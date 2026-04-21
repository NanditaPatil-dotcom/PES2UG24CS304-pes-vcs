// tree.c — Tree object serialization and construction

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MODE_FILE  0100644
#define MODE_EXEC  0100755
#define MODE_DIR   0040000

// Forward declarations — defined in object.c and index.c
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// Inline struct definitions matching index.h exactly, so tree.c doesn't need
// to include index.h (which would break the test_tree link target in the Makefile)
#define MAX_INDEX_ENTRIES 10000
typedef struct {
    uint32_t mode;
    ObjectID hash;
    uint64_t mtime_sec;
    uint32_t size;
    char path[512];
} _IndexEntry;
typedef struct {
    _IndexEntry entries[MAX_INDEX_ENTRIES];
    int count;
} _Index;
// Weak stub: test_tree doesn't link index.o, so provide a fallback
__attribute__((weak)) int index_load(_Index *idx) { idx->count = 0; return 0; }

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';
        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size > 0 ? max_size : 1);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Recursive helper: build a tree from index entries sharing the same directory
// level. prefix_len = how many bytes of path to skip (the parent dir prefix).
static int write_tree_level(_IndexEntry *entries, int count,
                             size_t prefix_len, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        const char *rel = entries[i].path + prefix_len;
        const char *slash = strchr(rel, '/');

        if (!slash) {
            // Plain file at this level
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            snprintf(te->name, sizeof(te->name), "%s", rel);
            i++;
        } else {
            // Subdirectory — collect all entries with same dir prefix
            size_t dir_len = (size_t)(slash - rel);
            char dir_name[256];
            if (dir_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            int j = i;
            while (j < count) {
                const char *r2 = entries[j].path + prefix_len;
                if (strncmp(r2, dir_name, dir_len) == 0 && r2[dir_len] == '/') {
                    j++;
                } else {
                    break;
                }
            }

            // Recurse for this subdirectory's entries
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i,
                                 prefix_len + dir_len + 1, &sub_id) != 0)
                return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = sub_id;
            snprintf(te->name, sizeof(te->name), "%s", dir_name);

            i = j;
        }
    }

    void *serialized;
    size_t ser_len;
    if (tree_serialize(&tree, &serialized, &ser_len) != 0) return -1;
    int rc = object_write(OBJ_TREE, serialized, ser_len, id_out);
    free(serialized);
    return rc;
}

int tree_from_index(ObjectID *id_out) {
    _Index index;
    if (index_load(&index) != 0) return -1;

    if (index.count == 0) {
        Tree empty; empty.count = 0;
        void *serialized; size_t ser_len;
        if (tree_serialize(&empty, &serialized, &ser_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, serialized, ser_len, id_out);
        free(serialized);
        return rc;
    }

    return write_tree_level(index.entries, index.count, 0, id_out);
}