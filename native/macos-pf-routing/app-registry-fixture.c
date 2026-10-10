#include "app-registry.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Standalone caller-owned fixture driver. Never executes the copied app. */
struct fault_context { const char *stage; char marker[PATH_MAX]; int mutated, copied_files; };

static const char *error_name(int error) {
    switch (error) {
        case 0: return "OK";
        case EACCES: return "EACCES"; case EINVAL: return "EINVAL";
        case EALREADY: return "EALREADY"; case EEXIST: return "EEXIST";
        case ESTALE: return "ESTALE"; case EINPROGRESS: return "EINPROGRESS";
        case EAGAIN: return "EAGAIN"; case ENOENT: return "ENOENT";
        case EIO: return "EIO"; case ENOSPC: return "ENOSPC";
        case ENOTSUP: return "ENOTSUP"; default: return "OTHER";
    }
}
static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static int observation(const char *stage, void *context) {
    struct fault_context *fault = context;
    if (!strcmp(fault->stage, "mutate-after-copy-file") && !strcmp(stage, "after-copy-file") &&
        ++fault->copied_files == 3 && !fault->mutated) {
        int fd = open(fault->marker, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return 1;
        const char bytes[] = "-changed-during-copy";
        ssize_t count = write(fd, bytes, sizeof(bytes) - 1);
        int closed = close(fd); fault->mutated = 1;
        return count != (ssize_t)(sizeof(bytes) - 1) || closed != 0;
    }
    return !strcmp(fault->stage, stage);
}
static int output(int result, int error, const struct envara_app_registration *record) {
    printf("{\"ok\":%s,\"errno\":%d,\"error\":", result == 0 ? "true" : "false", error);
    json_string(error_name(error));
    printf(",\"fixtureOnly\":true,\"ready\":false,\"protected\":false,\"activatesSystem\":false");
    if (result == 0 && record) {
        printf(",\"sequence\":%u,\"registrationReady\":%s,\"registrationProtected\":%s,\"registrationFixtureOnly\":%s",
               record->sequence, record->ready ? "true" : "false", record->protected_ready ? "true" : "false", record->fixture_only ? "true" : "false");
        printf(",\"registrationId\":"); json_string(record->registration_id);
        printf(",\"versionId\":"); json_string(record->version_id);
        printf(",\"originalBundle\":"); json_string(record->original.bundle);
        printf(",\"snapshotBundle\":"); json_string(record->snapshot.bundle);
        printf(",\"originalContentSHA256\":"); json_string(record->original.content_digest);
        printf(",\"snapshotContentSHA256\":"); json_string(record->snapshot.content_digest);
        printf(",\"originalExecutableSHA256\":"); json_string(record->original.executable_digest);
        printf(",\"snapshotExecutableSHA256\":"); json_string(record->snapshot.executable_digest);
        printf(",\"originalCDHash\":"); json_string(record->original.cdhash);
        printf(",\"snapshotCDHash\":"); json_string(record->snapshot.cdhash);
    }
    puts("}"); return result == 0 ? 0 : 1;
}
static void parent_diagnostic(const char *root) {
    char parent[PATH_MAX]; if (strlen(root) >= sizeof(parent)) return; strcpy(parent, root);
    char *slash = strrchr(parent, '/'); if (!slash) return; *slash = 0;
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return;
    struct stat info; if (!fstat(fd, &info)) fprintf(stderr, "fixture parent owner=%u mode=%o\n", info.st_uid, info.st_mode & 07777);
    errno = 0; acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED); int error = errno;
    acl_entry_t item; int entries = acl ? acl_get_entry(acl, ACL_FIRST_ENTRY, &item) : -1;
    fprintf(stderr, "fixture parent acl=%d errno=%d\n", entries, error); if (acl) acl_free(acl);
    char names[4096]; ssize_t size = flistxattr(fd, names, sizeof(names), 0);
    fprintf(stderr, "fixture parent attrs=%zd errno=%d\n", size, errno);
    if (size > 0 && size <= (ssize_t)sizeof(names)) for (size_t offset = 0; offset < (size_t)size;) {
        size_t length = strnlen(names + offset, (size_t)size - offset); if (!length || length == (size_t)size - offset) break;
        errno = 0; ssize_t bytes = fgetxattr(fd, names + offset, NULL, 0, 0, 0);
        fprintf(stderr, "fixture parent attr=%s bytes=%zd errno=%d\n", names + offset, bytes, errno); offset += length + 1;
    }
    close(fd);
}
int main(int argc, char **argv) {
    if (getuid() == 0 || geteuid() != getuid() || argc < 3) return 90;
    struct envara_app_registry registry; memset(&registry, 0, sizeof(registry)); registry.fd = -1;
    struct envara_app_registration record; memset(&record, 0, sizeof(record));
    int create = !strcmp(argv[1], "open-create");
    if (!create && strcmp(argv[1], "open-read") && strcmp(argv[1], "register") && strcmp(argv[1], "resolve") && strcmp(argv[1], "retire")) return 91;
    int result = envara_app_registry_open(&registry, argv[2], 1, create);
    if (result != 0) { int error = errno; parent_diagnostic(argv[2]); return output(result, error, NULL); }
    int has_record = 0;
    if (!strcmp(argv[1], "register")) {
        if (argc != 8) { envara_app_registry_close(&registry); return 92; }
        const char *allowed[] = {"none", "after-intent", "after-copy-file", "after-object", "after-commit", "mutate-after-copy-file", "umask-077"};
        int valid = 0; for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) if (!strcmp(argv[7], allowed[i])) valid = 1;
        if (!valid) { envara_app_registry_close(&registry); return 93; }
        struct fault_context fault; memset(&fault, 0, sizeof(fault)); fault.stage = argv[7];
        if (snprintf(fault.marker, sizeof(fault.marker), "%s/Contents/Resources/marker", argv[5]) >= (int)sizeof(fault.marker)) {
            envara_app_registry_close(&registry); return 94;
        }
        struct envara_app_registry_fixture_hook hook = {observation, &fault};
        int restrictive = !strcmp(argv[7], "umask-077"); mode_t original_umask = restrictive ? umask(077) : 0;
        result = envara_app_registry_register(&registry, argv[3], argv[4], argv[5], !strcmp(argv[6], "-") ? NULL : argv[6],
                                             !strcmp(argv[7], "none") || restrictive ? NULL : &hook, &record);
        if (restrictive) umask(original_umask);
        has_record = result == 0;
    } else if (!strcmp(argv[1], "resolve")) {
        if (argc != 5) { envara_app_registry_close(&registry); return 95; }
        result = envara_app_registry_resolve(&registry, argv[3], argv[4], &record); has_record = result == 0;
    } else if (!strcmp(argv[1], "retire")) {
        if (argc != 4) { envara_app_registry_close(&registry); return 96; }
        result = envara_app_registry_retire(&registry, argv[3]);
    } else if (argc != 3) { envara_app_registry_close(&registry); return 97; }
    int error = result == 0 ? 0 : errno;
    envara_app_registry_close(&registry);
    return output(result, error, has_record ? &record : NULL);
}
