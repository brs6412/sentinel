#define _XOPEN_SOURCE 700
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char *name;
    int   is_dir;
} entry_t;

static const char *IGNORES[] = {
    ".git", ".DS_Store", "build", "__pycache__", ".idea", ".vscode",
    NULL
};

static int ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lt = strlen(suffix);
    return (ls >= lt) && (strcmp(s + (ls - lt), suffix) == 0);
}

static int should_skip(const char *name) {
    for (const char **p = IGNORES; *p; ++p) {
        if (strcmp(name, *p) == 0) return 1;
    }
    if (ends_with(name, ".o") || ends_with(name, ".obj")) return 1;
    return 0;
}

static int by_name(const void *a, const void *b) {
    const entry_t *ea = (const entry_t *)a;
    const entry_t *eb = (const entry_t *)b;
    return strcmp(ea->name, eb->name);
}

static void free_entries(entry_t *arr, size_t n) {
    for (size_t i = 0; i < n; ++i) free(arr[i].name);
    free(arr);
}

static void print_tree(const char *path, const char *prefix) {
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "warn: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    // Collect entries
    entry_t *entries = NULL;
    size_t cap = 0, len = 0;
    struct dirent *de;

    while ((de = readdir(dir)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (should_skip(name)) continue;

        // Build full path
        size_t full_len = strlen(path) + 1 + strlen(name) + 1;
        char *full = (char *)malloc(full_len);
        if (!full) { perror("malloc"); closedir(dir); free_entries(entries, len); return; }
        snprintf(full, full_len, "%s/%s", path, name);

        // lstat (don’t follow symlinks)
        struct stat st;
        if (lstat(full, &st) != 0) {
            // skip unreadable entries
            free(full);
            continue;
        }

        // Save entry
        if (len == cap) {
            size_t ncap = cap ? cap * 2 : 32;
            entry_t *tmp = (entry_t *)realloc(entries, ncap * sizeof(entry_t));
            if (!tmp) { perror("realloc"); free(full); closedir(dir); free_entries(entries, len); return; }
            entries = tmp;
            cap = ncap;
        }
        entries[len].name   = strdup(name);
        entries[len].is_dir = S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
        ++len;

        free(full);
    }
    closedir(dir);

    // Sort by name
    qsort(entries, len, sizeof(entry_t), by_name);

    // Print and recurse
    for (size_t i = 0; i < len; ++i) {
        int last = (i == len - 1);
        printf("%s%s %s\n", prefix, last ? "└──" : "├──", entries[i].name);

        if (entries[i].is_dir) {
            // Build next prefix
            char next_prefix[1024];
            snprintf(next_prefix, sizeof(next_prefix), "%s%s   ",
                     prefix, last ? "    " : "│");
            // Build next path
            char next_path[4096];
            snprintf(next_path, sizeof(next_path), "%s/%s", path, entries[i].name);
            print_tree(next_path, next_prefix);
        }
    }

    free_entries(entries, len);
}

static const char *basename_of(const char *p, char *buf, size_t n) {
    // Return last path component into buf, or "." if empty.
    const char *slash = strrchr(p, '/');
    const char *base = slash ? slash + 1 : p;
    if (*base == '\0') base = "/";
    snprintf(buf, n, "%s", base);
    return buf;
}

int main(int argc, char **argv) {
    char cwd[4096];
    const char *root = (argc > 1) ? argv[1] : ".";
    if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, ".");

    // Print top label as "<basename>/"
    char label[1024];
    if (strcmp(root, ".") == 0) {
        basename_of(cwd, label, sizeof(label));
    } else {
        basename_of(root, label, sizeof(label));
    }
    printf("%s/\n", label);
    print_tree(root, "");
    return 0;
}
