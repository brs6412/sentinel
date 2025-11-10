// repo_tree_ignore.c — print a directory tree respecting .gitignore patterns.
//
// -----------------------------------------------------------------------------
// HOW TO BUILD AND RUN
// -----------------------------------------------------------------------------
// 1. From the repo root, compile:
//      clang -std=c17 -Wall -Wextra -O2 tools/repo_tree_ignore.c -o tools/repo_tree_ignore
//
// 2. Run to print the repo tree (respecting .gitignore):
//      ./tools/repo_tree_ignore
//
// 3. Or print a specific subdirectory:
//      ./tools/repo_tree_ignore apps
//
// (Optional) Add to your Makefile:
//      tree-ignore: tools/repo_tree_ignore
//          ./tools/repo_tree_ignore
//
// -----------------------------------------------------------------------------
// Notes:
//  - Reads .gitignore patterns and skips matching files/directories.
//  - Shows directories even if all their contents are ignored (empty folders).
//  - Does not follow symlinks.
//  - Uses UTF-8 connectors (├──, └──, │).  Make sure your terminal is UTF-8.
// -----------------------------------------------------------------------------

#define _XOPEN_SOURCE 700
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>

typedef struct {
    char *name;
    int   is_dir;
} entry_t;

typedef struct {
    char **patterns;
    size_t count;
    size_t cap;
} ignore_list_t;

static ignore_list_t ignores = {NULL, 0, 0};

// Always ignore these common directories/files (even if not in .gitignore)
static const char *ALWAYS_IGNORE[] = {
    ".git", ".DS_Store", NULL
};

static void add_ignore_pattern(const char *pattern) {
    if (ignores.count == ignores.cap) {
        size_t ncap = ignores.cap ? ignores.cap * 2 : 32;
        char **tmp = (char **)realloc(ignores.patterns, ncap * sizeof(char *));
        if (!tmp) return;
        ignores.patterns = tmp;
        ignores.cap = ncap;
    }
    ignores.patterns[ignores.count++] = strdup(pattern);
}

static void free_ignores(void) {
    for (size_t i = 0; i < ignores.count; ++i) {
        free(ignores.patterns[i]);
    }
    free(ignores.patterns);
    ignores.patterns = NULL;
    ignores.count = ignores.cap = 0;
}

static void load_gitignore(const char *root_path) {
    char gitignore_path[4096];
    snprintf(gitignore_path, sizeof(gitignore_path), "%s/.gitignore", root_path);
    
    FILE *f = fopen(gitignore_path, "r");
    if (!f) return;
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        
        // Skip empty lines and comments
        if (len == 0 || line[0] == '#') continue;
        
        // Remove leading/trailing whitespace
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        char *end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t')) end--;
        end[1] = '\0';
        
        if (*start == '\0') continue;
        
        add_ignore_pattern(start);
    }
    
    fclose(f);
}

static int matches_ignore(const char *name, int is_dir) {
    // Check always-ignore list first
    for (const char **p = ALWAYS_IGNORE; *p; ++p) {
        if (strcmp(name, *p) == 0) return 1;
    }
    
    // Check .gitignore patterns
    for (size_t i = 0; i < ignores.count; ++i) {
        const char *pattern = ignores.patterns[i];
        int is_negated = (pattern[0] == '!');
        if (is_negated) pattern++; // Skip '!' for now
        
        // Handle absolute paths (starting with /)
        int is_absolute = (pattern[0] == '/');
        if (is_absolute) pattern++; // Skip leading /
        
        // Handle directory patterns (ending with /)
        int pattern_is_dir = (pattern[strlen(pattern) - 1] == '/');
        if (pattern_is_dir && !is_dir) continue;
        
        // Remove trailing / for matching
        char clean_pattern[1024];
        strncpy(clean_pattern, pattern, sizeof(clean_pattern) - 1);
        clean_pattern[sizeof(clean_pattern) - 1] = '\0';
        if (clean_pattern[strlen(clean_pattern) - 1] == '/') {
            clean_pattern[strlen(clean_pattern) - 1] = '\0';
        }
        
        // Pattern matching (supports *, ?, [])
        if (fnmatch(clean_pattern, name, FNM_PATHNAME | FNM_PERIOD) == 0) {
            return !is_negated; // Matches if not negated
        }
        
        // Exact match
        if (strcmp(name, clean_pattern) == 0) {
            return !is_negated;
        }
    }
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
        
        // Build full path
        size_t full_len = strlen(path) + 1 + strlen(name) + 1;
        char *full = (char *)malloc(full_len);
        if (!full) { perror("malloc"); closedir(dir); free_entries(entries, len); return; }
        snprintf(full, full_len, "%s/%s", path, name);

        // lstat (don't follow symlinks)
        struct stat st;
        if (lstat(full, &st) != 0) {
            free(full);
            continue;
        }

        int is_dir = S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
        
        // Check always-ignore list first (these are completely hidden)
        int always_ignore = 0;
        for (const char **p = ALWAYS_IGNORE; *p; ++p) {
            if (strcmp(name, *p) == 0) {
                always_ignore = 1;
                break;
            }
        }
        if (always_ignore) {
            free(full);
            continue;
        }
        
        // Check if this entry should be ignored
        // For directories: show them but mark as "skip contents"
        // For files: skip them entirely
        int should_ignore = matches_ignore(name, is_dir);
        if (should_ignore && !is_dir) {
            // Skip files that match ignore patterns
            free(full);
            continue;
        }

        // Save entry (directories are always shown, even if ignored)
        if (len == cap) {
            size_t ncap = cap ? cap * 2 : 32;
            entry_t *tmp = (entry_t *)realloc(entries, ncap * sizeof(entry_t));
            if (!tmp) { perror("realloc"); free(full); closedir(dir); free_entries(entries, len); return; }
            entries = tmp;
            cap = ncap;
        }
        entries[len].name   = strdup(name);
        entries[len].is_dir = is_dir;
        // If directory is ignored, we'll skip recursing into it
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
            // Only recurse if directory doesn't match ignore patterns
            if (!matches_ignore(entries[i].name, 1)) {
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

    // Load .gitignore patterns from root
    load_gitignore(root);

    // Print top label as "<basename>/"
    char label[1024];
    if (strcmp(root, ".") == 0) {
        basename_of(cwd, label, sizeof(label));
    } else {
        basename_of(root, label, sizeof(label));
    }
    printf("%s/\n", label);
    print_tree(root, "");
    
    free_ignores();
    return 0;
}

