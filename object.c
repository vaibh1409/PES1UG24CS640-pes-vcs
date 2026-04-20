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
    const char *type_str;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    char header[64];
    int header_n = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_n < 0 || (size_t)header_n >= sizeof(header) - 1) return -1;
    size_t header_len = (size_t)header_n + 1; // include '\0'

    size_t obj_len = header_len + len;
    uint8_t *obj = malloc(obj_len);
    if (!obj) return -1;
    memcpy(obj, header, header_len);
    if (len > 0) memcpy(obj + header_len, data, len);

    ObjectID id;
    compute_hash(obj, obj_len, &id);
    *id_out = id;

    if (object_exists(&id)) {
        free(obj);
        return 0;
    }

    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));

    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", final_path);
    char *slash = strrchr(dir_path, '/');
    if (!slash) {
        free(obj);
        return -1;
    }
    *slash = '\0';

    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        free(obj);
        return -1;
    }

    char tmp_template[640];
    int tmp_n = snprintf(tmp_template, sizeof(tmp_template), "%s/.tmp_obj_XXXXXX", dir_path);
    if (tmp_n < 0 || (size_t)tmp_n >= sizeof(tmp_template)) {
        free(obj);
        return -1;
    }
    int fd = mkstemp(tmp_template);
    if (fd < 0) {
        free(obj);
        return -1;
    }

    size_t written = 0;
    while (written < obj_len) {
        ssize_t n = write(fd, obj + written, obj_len - written);
        if (n <= 0) {
            close(fd);
            unlink(tmp_template);
            free(obj);
            return -1;
        }
        written += (size_t)n;
    }

    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_template);
        free(obj);
        return -1;
    }

    if (close(fd) != 0) {
        unlink(tmp_template);
        free(obj);
        return -1;
    }

    if (rename(tmp_template, final_path) != 0) {
        unlink(tmp_template);
        free(obj);
        return -1;
    }

    int dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(obj);
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
    int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

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

    uint8_t *buf = malloc((size_t)file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(buf, 1, (size_t)file_size, f);
    fclose(f);
    if (nread != (size_t)file_size) {
        free(buf);
        return -1;
    }

    ObjectID actual;
    compute_hash(buf, (size_t)file_size, &actual);
    if (memcmp(actual.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    uint8_t *null_byte = memchr(buf, '\0', (size_t)file_size);
    if (!null_byte) {
        free(buf);
        return -1;
    }

    size_t header_len = (size_t)(null_byte - buf);
    if (header_len >= 64) {
        free(buf);
        return -1;
    }
    char header[64];
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    size_t declared_size = 0;
    if (sscanf(header, "%15s %zu", type_str, &declared_size) != 2) {
        free(buf);
        return -1;
    }

    
}
