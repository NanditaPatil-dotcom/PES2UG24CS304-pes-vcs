// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

static const char *object_type_name(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:
            return "blob";
        case OBJ_TREE:
            return "tree";
        case OBJ_COMMIT:
            return "commit";
        default:
            return NULL;
    }
}

static int object_type_from_name(const char *name, ObjectType *type_out) {
    if (strcmp(name, "blob") == 0) {
        *type_out = OBJ_BLOB;
        return 0;
    }
    if (strcmp(name, "tree") == 0) {
        *type_out = OBJ_TREE;
        return 0;
    }
    if (strcmp(name, "commit") == 0) {
        *type_out = OBJ_COMMIT;
        return 0;
    }
    return -1;
}

static int ensure_directory(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *ptr = (const unsigned char *)buf;

    while (len > 0) {
        ssize_t written = write(fd, ptr, len);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        ptr += (size_t)written;
        len -= (size_t)written;
    }

    return 0;
}

static int fsync_directory(const char *path) {
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) {
        return -1;
    }

    int rc = fsync(dir_fd);
    int saved_errno = errno;
    close(dir_fd);
    errno = saved_errno;
    return rc;
}

static int read_file_bytes(const char *path, unsigned char **buf_out, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    size_t len = (size_t)file_size;
    unsigned char *buf = malloc(len > 0 ? len : 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (len > 0 && fread(buf, 1, len, f) != len) {
        free(buf);
        fclose(f);
        return -1;
    }

    if (fclose(f) != 0) {
        free(buf);
        return -1;
    }

    *buf_out = buf;
    *len_out = len;
    return 0;
}

static int parse_object_header(const unsigned char *object_buf, size_t object_len,
                               ObjectType *type_out, size_t *data_offset_out,
                               size_t *data_len_out) {
    const unsigned char *null_byte = memchr(object_buf, '\0', object_len);
    if (!null_byte) {
        return -1;
    }

    char type_name[16];
    size_t declared_len;
    char extra;
    if (sscanf((const char *)object_buf, "%15s %zu %c", type_name, &declared_len, &extra) != 2) {
        return -1;
    }

    if (object_type_from_name(type_name, type_out) != 0) {
        return -1;
    }

    size_t data_offset = (size_t)(null_byte - object_buf) + 1;
    if (declared_len != object_len - data_offset) {
        return -1;
    }

    *data_offset_out = data_offset;
    *data_len_out = declared_len;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_name = object_type_name(type);
    if (!type_name || !id_out || (!data && len > 0)) {
        return -1;
    }

    int header_len = snprintf(NULL, 0, "%s %zu", type_name, len);
    if (header_len < 0) {
        return -1;
    }

    size_t object_len = (size_t)header_len + 1 + len;
    unsigned char *object_buf = malloc(object_len);
    if (!object_buf) {
        return -1;
    }

    snprintf((char *)object_buf, (size_t)header_len + 1, "%s %zu", type_name, len);
    if (len > 0) {
        memcpy(object_buf + header_len + 1, data, len);
    }

    compute_hash(object_buf, object_len, id_out);
    if (object_exists(id_out)) {
        free(object_buf);
        return 0;
    }

    char final_path[512];
    char shard_dir[512];
    char tmp_path[512];
    int fd = -1;
    int renamed = 0;

    object_path(id_out, final_path, sizeof(final_path));
    snprintf(shard_dir, sizeof(shard_dir), "%s", final_path);
    char *slash = strrchr(shard_dir, '/');
    if (!slash) {
        free(object_buf);
        return -1;
    }
    *slash = '\0';

    if (ensure_directory(PES_DIR) != 0 ||
        ensure_directory(OBJECTS_DIR) != 0 ||
        ensure_directory(shard_dir) != 0) {
        free(object_buf);
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s/.tmp-object-XXXXXX", shard_dir);
    fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(object_buf);
        return -1;
    }

    if (write_all(fd, object_buf, object_len) != 0 ||
        fsync(fd) != 0 ||
        close(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        unlink(tmp_path);
        free(object_buf);
        errno = saved_errno;
        return -1;
    }
    fd = -1;

    if (rename(tmp_path, final_path) != 0) {
        int saved_errno = errno;
        unlink(tmp_path);
        free(object_buf);
        errno = saved_errno;
        return -1;
    }
    renamed = 1;

    if (fsync_directory(shard_dir) != 0) {
        int saved_errno = errno;
        if (!renamed) {
            unlink(tmp_path);
        }
        free(object_buf);
        errno = saved_errno;
        return -1;
    }

    free(object_buf);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) {
        return -1;
    }

    char path[512];
    object_path(id, path, sizeof(path));

    unsigned char *object_buf = NULL;
    size_t object_len = 0;
    if (read_file_bytes(path, &object_buf, &object_len) != 0) {
        return -1;
    }

    ObjectID computed_id;
    compute_hash(object_buf, object_len, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(object_buf);
        return -1;
    }

    size_t data_offset = 0;
    size_t data_len = 0;
    if (parse_object_header(object_buf, object_len, type_out, &data_offset, &data_len) != 0) {
        free(object_buf);
        return -1;
    }

    void *data = malloc(data_len > 0 ? data_len : 1);
    if (!data) {
        free(object_buf);
        return -1;
    }

    if (data_len > 0) {
        memcpy(data, object_buf + data_offset, data_len);
    }

    free(object_buf);
    *data_out = data;
    *len_out = data_len;
    return 0;
}
