#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* The caller verifies signature/hash before staging and after installation.
 * RENAME_EXCL is the macOS atomic no-replace operation; an existing installation
 * is never adopted, overwritten or removed by this executable. No elevation. */
int main(int argc, char **argv) {
    const char *prefix = "/Applications/.EnvaraRoutingStage-";
    const char *target = "/Applications/Mitmproxy Redirector.app";
    char canonical[PATH_MAX];
    struct stat status;
    if (argc != 2 || strncmp(argv[1], prefix, strlen(prefix)) != 0 ||
        strchr(argv[1] + strlen(prefix), '/') != NULL ||
        realpath(argv[1], canonical) == NULL || strcmp(canonical, argv[1]) != 0 ||
        lstat(argv[1], &status) != 0 || !S_ISDIR(status.st_mode)) return 2;
    if (renamex_np(argv[1], target, RENAME_EXCL) == 0) return 0;
    if (errno == EEXIST || errno == ENOTEMPTY) return 3;
    return 4;
}
