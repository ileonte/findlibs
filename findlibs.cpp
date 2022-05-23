#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define ERR(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define LOG(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define LOGN(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)

/*
 * REFs:
 *  - https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/generic/dl-cache.h;h=93d4bea9303136fc165417395cafdc30e4dee97f;hb=HEAD
 *  - https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/generic/ldconfig.h;h=7cc898db6156127cba5c9a6744fcad2fd043cc49;hb=HEAD
 *  - https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;h=9394ac6438f6fdcaf25c6924e8d1d749a364d782;hb=HEAD
 */
#define FLAG_ANY                        -1
#define FLAG_TYPE_MASK                  0x00ff
#define FLAG_LIBC4                      0x0000
#define FLAG_ELF                        0x0001
#define FLAG_ELF_LIBC5                  0x0002
#define FLAG_ELF_LIBC6                  0x0003
#define FLAG_REQUIRED_MASK              0xff00
#define FLAG_X86                        0x0000  /* made up */
#define FLAG_SPARC_LIB64                0x0100
#define FLAG_IA64_LIB64                 0x0200
#define FLAG_X8664_LIB64                0x0300
#define FLAG_S390_LIB64                 0x0400
#define FLAG_POWERPC_LIB64              0x0500
#define FLAG_MIPS64_LIBN32              0x0600
#define FLAG_MIPS64_LIBN64              0x0700
#define FLAG_X8664_LIBX32               0x0800
#define FLAG_ARM_LIBHF                  0x0900
#define FLAG_AARCH64_LIB64              0x0a00
#define FLAG_ARM_LIBSF                  0x0b00
#define FLAG_MIPS_LIB32_NAN2008         0x0c00
#define FLAG_MIPS64_LIBN32_NAN2008      0x0d00
#define FLAG_MIPS64_LIBN64_NAN2008      0x0e00
#define FLAG_RISCV_FLOAT_ABI_SOFT       0x0f00
#define FLAG_RISCV_FLOAT_ABI_DOUBLE     0x1000

static constexpr const char CACHEFILE_MAGIC_OLD[] = "ld.so-1.7.0";
struct CacheFileEntry_Old {
    int flags;
    unsigned int key;
    unsigned int value;
};
struct ChacheFileHeader_Old {
    char magic[sizeof(CACHEFILE_MAGIC_OLD) - 1];
    unsigned int nlibs;
    CacheFileEntry_Old dummy[0];
};

static constexpr const char CACHEFILE_MAGIC_NEW[] = "glibc-ld.so.cache1.1";
struct CacheFileEntry_New {
    int32_t flags = 0;
    uint32_t key = 0;
    uint32_t value = 0;
    uint32_t osversion = 0;
    uint64_t hwcap = 0;
};
struct CacheFileHeader_New {
    char magic[sizeof(CACHEFILE_MAGIC_NEW) - 1] = {};
    uint32_t nlibs = 0;
    uint32_t len_strings = 0;
    uint32_t unused[5] = {};
    CacheFileEntry_New dummy[0];
};
static_assert(sizeof(CacheFileHeader_New) == 48);

struct LinkerCacheFile {
    size_t entry_count = 0;
    CacheFileEntry_New *entries = NULL;
    size_t string_table_size = 0;
    char *string_table = NULL;
};

static void ldsocache_close(LinkerCacheFile* cache) {
    if (cache) {
        free(cache->entries);
        free(cache->string_table);
        free(cache);
    }
}

static LinkerCacheFile* ldsocache_open(char const* path = NULL) {
    ChacheFileHeader_Old header_old[1] = {};
    CacheFileHeader_New header[1] = {};
    LinkerCacheFile* ret = NULL;
    size_t expected_read = 0;
    bool mixed_format = false;
    long str_base = 0;

    auto f = fopen(path ? path : "/etc/ld.so.cache", "rb");
    if (!f) goto err_out;

    {
        // check for old format entries, skip if needed
        if (fread(header_old, 1, sizeof(header_old), f) < sizeof(header_old)) goto err_out;
        if (!memcmp(header_old->magic, CACHEFILE_MAGIC_OLD, sizeof(header_old->magic))) {
            // old-style header found, skip entries to reach new-style header
            fseek(f, header_old->nlibs * sizeof(CacheFileEntry_Old), SEEK_CUR);
            mixed_format = true;
            str_base = ftell(f);
        } else {
            // old-style header not found, jump back to the beginning of the file
            fseek(f, 0, SEEK_SET);
        }
    }

    if (fread(header, 1, sizeof(header), f) < sizeof(header)) goto err_out;
    if (memcmp(header->magic, CACHEFILE_MAGIC_NEW, sizeof(header->magic))) goto err_out;

    ret = (LinkerCacheFile*)calloc(1, sizeof(LinkerCacheFile));
    ret->entry_count = header->nlibs;
    ret->entries = (CacheFileEntry_New*)malloc(header->nlibs * sizeof(CacheFileEntry_New));
    ret->string_table_size = header->len_strings;
    ret->string_table = (char*)malloc(header->len_strings);

    expected_read = ret->entry_count * sizeof(CacheFileEntry_New);
    if (fread(ret->entries, 1, expected_read, f) < expected_read) goto err_out;

    // fixup: entry->key and entry->value are file offsets relative to the new-style header, adjust for in-memory string table
    if (mixed_format) str_base = ftell(f) - str_base;
    else str_base = ftell(f);
    for (size_t i = 0; i < ret->entry_count; i++) {
        auto* entry = ret->entries + i;
        entry->key = entry->key - str_base;
        entry->value = entry->value - str_base;
    }

    expected_read = ret->string_table_size;
    if (fread(ret->string_table, 1, expected_read, f) < expected_read) goto err_out;

    fclose(f);
    return ret;

err_out:
    if (f) fclose(f);
    ldsocache_close(ret);
    return NULL;
}

struct LibraryPaths {
    char *dynamic_linker;
    char *libc;
    char *libm;
    char *libpthread;
    char *librt;

    size_t search_dir_count;
    char **search_dirs;
};

static inline LibraryPaths* ldsocache_extract_paths(LinkerCacheFile const* cache, uint32_t arch_filter = FLAG_X8664_LIB64) {
    if (!cache) return NULL;
    if ((arch_filter & FLAG_REQUIRED_MASK) > FLAG_RISCV_FLOAT_ABI_DOUBLE) return NULL;

    auto* paths = (LibraryPaths*)calloc(1, sizeof(LibraryPaths));

    for (size_t i = 0; i < cache->entry_count; i++) {
        auto* entry = cache->entries + i;
        auto type = entry->flags & FLAG_TYPE_MASK;
        if ((type != FLAG_ELF_LIBC6) && (type != FLAG_ELF)) continue;
        if ((entry->flags & FLAG_REQUIRED_MASK) != arch_filter) continue;

        auto const* soname = cache->string_table + entry->key;
        auto const* path = cache->string_table + entry->value;

        if (!paths->dynamic_linker && !strncmp(soname, "ld-linux", 8)) {
            paths->dynamic_linker = strdup(path);
            continue;
        }
        if (!paths->libc && !strncmp(soname, "libc.so", 7)) {
            paths->libc = strdup(path);
            continue;
        }
        if (!paths->libm && !strncmp(soname, "libm.so", 7)) {
            paths->libm = strdup(path);
            continue;
        }
        if (!paths->libpthread && !strncmp(soname, "libpthread.so", 13)) {
            paths->libpthread = strdup(path);
            continue;
        }
        if (!paths->librt && !strncmp(soname, "librt.so", 8)) {
            paths->librt = strdup(path);
            continue;
        }

        char const* p = strrchr(path, '/');
        if (!p) continue;
        bool found = false;
        for (size_t j = 0; j < paths->search_dir_count; j++) {
            if ((strlen(paths->search_dirs[j]) == size_t(p - path)) && !strncmp(paths->search_dirs[j], path, p - path)) {
                found = true;
                break;
            }
        }
        if (found) continue;

        paths->search_dirs = (char**)realloc(paths->search_dirs, (paths->search_dir_count + 1) * sizeof(char*));
        paths->search_dirs[paths->search_dir_count++] = strndup(path, p - path);
    }

    return paths;
}

static inline void ldsocache_free_paths(LibraryPaths* paths) {
    if (paths) {
        free(paths->dynamic_linker);
        free(paths->libc);
        free(paths->libm);
        free(paths->libpthread);
        free(paths->librt);

        for (size_t i = 0; i < paths->search_dir_count; i++)
            free(paths->search_dirs[i]);
        free(paths->search_dirs);
    }
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        ERR("Usage: %s <path_to_linker_cache> [32/64]", argv[0]);
        return 1;
    }

    uint32_t arch_filter = FLAG_X8664_LIB64;
    if (argc == 3) {
        if (!strcmp(argv[2], "32")) arch_filter = FLAG_X86;
        else if (!strcmp(argv[2], "64")) { /* noop */ }
        else {
            ERR("Usage: %s <path_to_linker_cache> [32/64]", argv[0]);
            return 1;
        }
    }

    auto *cache = ldsocache_open(argv[1]);
    if (!cache) {
        ERR("Failed to open/read linker cache!");
        return 1;
    }
    auto* paths = ldsocache_extract_paths(cache, arch_filter);
    ldsocache_close(cache);

    LOGN("Library search paths: [");
    for (size_t i = 0; i < paths->search_dir_count; i++)
        LOGN("%s%s", paths->search_dirs[i], i < paths->search_dir_count - 1 ? ",": "");
    LOG("]");
    LOG("System libs:");
    LOG("  dynamic linker : %s", paths->dynamic_linker ? paths->dynamic_linker : "(none)");
    LOG("  libc.so        : %s", paths->libc ? paths->libc : "(none)");
    LOG("  libm.so        : %s", paths->libm ? paths->libm : "(none)");
    LOG("  libpthread.so  : %s", paths->libpthread ? paths->libpthread : "(none)");
    LOG("  librt.so       : %s", paths->librt ? paths->librt : "(none)");

    ldsocache_free_paths(paths);

    return 0;
}
