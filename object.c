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
    char header[64];
    const char *type_str;

    // 1. Convert type enum to string
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // 2. Build header: "<type> <size>\0"
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // 3. Allocate full buffer (header + data)
    size_t total_len = header_len + len;
    char *full = malloc(total_len);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // 4. Compute hash
    compute_hash(full, total_len, id_out);

    // 5. Deduplication check
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // 6. Build paths
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    // Extract shard directory path
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", final_path);
    char *slash = strrchr(dir_path, '/');
    if (!slash) {
        free(full);
        return -1;
    }
    *slash = '\0';

    // 7. Create shard directory if needed
    mkdir(dir_path, 0755);  // OK if it already exists

    // 8. Create temp file path
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmpXXXXXX", dir_path);

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // 9. Write full object
    ssize_t written = write(fd, full, total_len);
    if (written != (ssize_t)total_len) {
        close(fd);
        unlink(temp_path);
        free(full);
        return -1;
    }

    // 10. fsync file
    if (fsync(fd) < 0) {
        close(fd);
        unlink(temp_path);
        free(full);
        return -1;
    }

    close(fd);

    // 11. Atomic rename
    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(full);
        return -1;
    }

    // 12. fsync directory
    int dir_fd = open(dir_path, O_DIRECTORY | O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full);
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
	    char path[512];
	    object_path(id, path, sizeof(path));
	
	    // 1. Open file
	    FILE *f = fopen(path, "rb");
	    if (!f) return -1;
	
	    // 2. Get file size
	    if (fseek(f, 0, SEEK_END) != 0) {
	        fclose(f);
	        return -1;
	    }
	    long fsize = ftell(f);
	    if (fsize < 0) {
	        fclose(f);
	        return -1;
	    }
	    rewind(f);
	
	    // 3. Read entire file
	    char *buf = malloc(fsize);
	    if (!buf) {
	        fclose(f);
	        return -1;
	    }
	
	    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
	        fclose(f);
	        free(buf);
	        return -1;
	    }
	    fclose(f);
	
	    // 4. Verify hash (integrity check)
	    ObjectID computed;
	    compute_hash(buf, fsize, &computed);
	    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
	        free(buf);
	        return -1;
	    }
	
	    // 5. Find header/data separator ('\0')
	    char *null_pos = memchr(buf, '\0', fsize);
	    if (!null_pos) {
	        free(buf);
	        return -1;
	    }
	
	    size_t header_len = null_pos - buf;
	    char *data_start = null_pos + 1;
	    size_t data_len = fsize - (header_len + 1);
	
	    // 6. Parse header: "<type> <size>"
	    char type_str[16];
	    size_t declared_size;
	
	    if (sscanf(buf, "%15s %zu", type_str, &declared_size) != 2) {
	        free(buf);
	        return -1;
	    }
	
	    // 7. Validate size
	    if (declared_size != data_len) {
	        free(buf);
	        return -1;
	    }
	
	    // 8. Convert type string to enum
	    if (strcmp(type_str, "blob") == 0) {
	        *type_out = OBJ_BLOB;
	    } else if (strcmp(type_str, "tree") == 0) {
	        *type_out = OBJ_TREE;
	    } else if (strcmp(type_str, "commit") == 0) {
	        *type_out = OBJ_COMMIT;
	    } else {
	        free(buf);
	        return -1;
	    }
	
	    // 9. Allocate and copy data
	    void *out = malloc(data_len);
	    if (!out) {
	        free(buf);
	        return -1;
	    }
	
	    memcpy(out, data_start, data_len);
	
	    *data_out = out;
	    *len_out = data_len;
	
	    free(buf);
	    return 0;
	}
