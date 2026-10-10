/* Local authorization carrier. No shell, arbitrary path or automatic rights.
 * The installer retains its independently reviewed compiled payload contract. */
#define _DARWIN_C_SOURCE
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static int refused(void) {
    fputs("{\"schema\":\"envara.local-pf-carrier/v1\",\"ready\":false,\"reason\":\"fixed-operation-or-resource-unavailable\"}\n", stderr);
    return 1;
}

int main(int argc, char **argv) {
    const char *operation = argc == 1 ? "--plan" : argc == 2 ? argv[1] : NULL;
    if (!operation || (strcmp(operation, "--plan") && strcmp(operation, "--request-install") &&
        strcmp(operation, "--request-controlled-experiment"))) return refused();
    char raw[PATH_MAX], executable[PATH_MAX]; uint32_t size = sizeof(raw);
    if (_NSGetExecutablePath(raw, &size) || !realpath(raw, executable)) return refused();
    const char suffix[] = "/Contents/MacOS/EnvaraPFAuthorization";
    size_t length = strlen(executable), tail = sizeof(suffix) - 1;
    if (length <= tail || strcmp(executable + length - tail, suffix)) return refused();
    executable[length - tail] = 0;
    char target[PATH_MAX], canonical[PATH_MAX];
    int written = snprintf(target, sizeof(target), "%s/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall", executable);
    if (written < 0 || (size_t)written >= sizeof(target) || !realpath(target, canonical) || strcmp(canonical, target)) return refused();
    int fd = open(target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat info;
    bool okay = fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 && (info.st_mode & 0111);
    if (fd >= 0) close(fd);
    if (!okay) return refused();
    char *arguments[] = { target, (char *)operation, NULL };
    execv(target, arguments);
    return refused();
}
