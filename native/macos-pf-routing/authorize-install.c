/* Fixed resource installer and separately approved, bounded helper relay.
 * Installation itself performs no PF, utun, groups or application operations. */
#define _DARWIN_C_SOURCE
#include <CommonCrypto/CommonDigest.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "installer-manifest.h"
typedef struct { const char *manifest_sha256; const EnvaraPFInstallFile *files; size_t count; } InstallSnapshot;
#include "installer-upgrade-f8.h"
#include "installer-upgrade-e940.h"
#include "installer-upgrade-518.h"
#include "installer-upgrade-2a7.h"
#include "installer-upgrade-832.h"
#include "installer-upgrade-ff9.h"
#include "installer-upgrade-6f8.h"
#include "installer-upgrade-199.h"
#include "installer-upgrade-46a.h"
#include "installer-upgrade-c37.h"
#include "installer-upgrade-f99.h"
#include "installer-upgrade-05d6.h"
#include "installer-upgrade-14b87.h"
#include "installer-upgrade-dbcf.h"
#include "installer-upgrade-43b.h"
#include "installer-upgrade-acfc.h"
#include "installer-upgrade-c34.h"
#include "installer-upgrade-4b9f85.h"
#include "installer-upgrade-43392e.h"
#include "installer-upgrade-f0b99f.h"
#include "installer-upgrade-f39101.h"
#include "installer-upgrade-a8bd00.h"
#include "installer-upgrade-da6e7c.h"
#include "installer-upgrade-03245359.h"
#include "installer-upgrade-2059a0.h"
#include "installer-upgrade-127e83.h"
#include "installer-upgrade-010117.h"
#include "installer-upgrade-9b51cf.h"
#include "installer-upgrade-91b62a.h"
#include "installer-upgrade-7c91a1.h"
#include "installer-upgrade-af79b1.h"
#include "installer-upgrade-dceba9.h"
#include "installer-upgrade-fa70a2.h"
#include "installer-upgrade-32811e.h"
#include "installer-upgrade-22a6f3.h"
#include "installer-upgrade-78c3.h"
#include "installer-upgrade-fb74.h"
#include "installer-upgrade-554c.h"
#include "installer-upgrade-2af8.h"
#include "installer-upgrade-005f.h"
#include "installer-upgrade-88f8.h"
#include "installer-upgrade-0b6d.h"
#include "installer-upgrade-0359.h"
#include "installer-upgrade-6e95.h"
#include "installer-upgrade-9ff6.h"
static const InstallSnapshot *const known_prior_snapshots[] = {
    &ENVARA_PF_UPGRADE_F8_SNAPSHOT, &ENVARA_PF_UPGRADE_E940_SNAPSHOT,
    &ENVARA_PF_UPGRADE_518_SNAPSHOT, &ENVARA_PF_UPGRADE_2A7_SNAPSHOT,
    &ENVARA_PF_UPGRADE_832_SNAPSHOT, &ENVARA_PF_UPGRADE_FF9_SNAPSHOT,
    &ENVARA_PF_UPGRADE_6F8_SNAPSHOT, &ENVARA_PF_UPGRADE_199_SNAPSHOT,
    &ENVARA_PF_UPGRADE_46A_SNAPSHOT, &ENVARA_PF_UPGRADE_C37_SNAPSHOT,
    &ENVARA_PF_UPGRADE_F99_SNAPSHOT, &ENVARA_PF_UPGRADE_05D6_SNAPSHOT,
    &ENVARA_PF_UPGRADE_14B87_SNAPSHOT, &ENVARA_PF_UPGRADE_DBCF_SNAPSHOT,
    &ENVARA_PF_UPGRADE_43B_SNAPSHOT, &ENVARA_PF_UPGRADE_ACFC_SNAPSHOT,
    &ENVARA_PF_UPGRADE_C34_SNAPSHOT, &ENVARA_PF_UPGRADE_4B9F85_SNAPSHOT,
    &ENVARA_PF_UPGRADE_43392E_SNAPSHOT, &ENVARA_PF_UPGRADE_F0B99F_SNAPSHOT,
    &ENVARA_PF_UPGRADE_F39101_SNAPSHOT, &ENVARA_PF_UPGRADE_A8BD00_SNAPSHOT,
    &ENVARA_PF_UPGRADE_DA6E7C_SNAPSHOT, &ENVARA_PF_UPGRADE_03245359_SNAPSHOT,
    &ENVARA_PF_UPGRADE_2059A0_SNAPSHOT, &ENVARA_PF_UPGRADE_127E83_SNAPSHOT,
    &ENVARA_PF_UPGRADE_010117_SNAPSHOT, &ENVARA_PF_UPGRADE_9B51CF_SNAPSHOT, &ENVARA_PF_UPGRADE_91B62A_SNAPSHOT,
    &ENVARA_PF_UPGRADE_7C91A1_SNAPSHOT, &ENVARA_PF_UPGRADE_AF79B1_SNAPSHOT,
    &ENVARA_PF_UPGRADE_DCEBA9_SNAPSHOT, &ENVARA_PF_UPGRADE_FA70A2_SNAPSHOT, &ENVARA_PF_UPGRADE_32811E_SNAPSHOT,
    &ENVARA_PF_UPGRADE_22A6F3_SNAPSHOT, &ENVARA_PF_UPGRADE_78C3_SNAPSHOT, &ENVARA_PF_UPGRADE_FB74_SNAPSHOT,
    &ENVARA_PF_UPGRADE_554C_SNAPSHOT, &ENVARA_PF_UPGRADE_2AF8_SNAPSHOT, &ENVARA_PF_UPGRADE_005F_SNAPSHOT, &ENVARA_PF_UPGRADE_88F8_SNAPSHOT, &ENVARA_PF_UPGRADE_0B6D_SNAPSHOT, &ENVARA_PF_UPGRADE_0359_SNAPSHOT, &ENVARA_PF_UPGRADE_6E95_SNAPSHOT, &ENVARA_PF_UPGRADE_9FF6_SNAPSHOT
};
#define KNOWN_PRIOR_COUNT (sizeof(known_prior_snapshots) / sizeof(known_prior_snapshots[0]))

#define INSTALL_NAME "io.envara.pf-routing"
#define INSTALL_PARENT "/Library/PrivilegedHelperTools"
#define INSTALL_TARGET INSTALL_PARENT "/" INSTALL_NAME
#define RUNTIME_NAME "io.envara.pf-runtime"
#define SCHEMA "envara.macos-pf-install/v1"
#define MAX_FILE_BYTES (512ULL * 1024ULL * 1024ULL)
#define MAX_TOTAL_BYTES (1024ULL * 1024ULL * 1024ULL)
#define ACTUAL_FILE_COUNT (sizeof(ENVARA_PF_INSTALL_FILES) / sizeof(ENVARA_PF_INSTALL_FILES[0]))
#define RELAY_BYTES 65536
/* Zero means: relay until Envara ends this session or the root controller
 * exits. The session is bounded by the heartbeat the controller sends and by
 * the native lease ceiling, never by a wall-clock deadline here. */
#define RELAY_SECONDS 0.0
#define STAGE_PREFIX "." INSTALL_NAME "-stage-"
static const InstallSnapshot current_snapshot = { ENVARA_PF_INSTALL_MANIFEST_SHA256, ENVARA_PF_INSTALL_FILES,
    sizeof(ENVARA_PF_INSTALL_FILES) / sizeof(ENVARA_PF_INSTALL_FILES[0]) };
static const char *failure = "installation-unconfirmed";
/* Fixed API names and numerical statuses are safe diagnostic evidence, never
 * authorization objects, credentials, caller input or private request data. */
static const char *authorization_stage;
static OSStatus authorization_status;
static const char *upgraded_from;
static bool needs_manual_review;
static uint64_t total_bytes;

static bool fail(const char *reason) { failure = reason; return false; }
static double clock_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}
static void json_string(const char *text) {
    if (!text) { printf("null"); return; }
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static void authorization_diagnostic(void) {
    if (!authorization_stage) return;
    printf(",\"nativeAuthorization\":{\"stage\":"); json_string(authorization_stage);
    printf(",\"status\":%d}", (int)authorization_status);
}
static bool hash_string(const char *hash) {
    if (!hash || strlen(hash) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!((hash[i] >= '0' && hash[i] <= '9') || (hash[i] >= 'a' && hash[i] <= 'f'))) return false;
    return true;
}
static bool relative_name(const char *name) {
    if (!name || !*name || strlen(name) >= 1024 || name[0] == '/') return false;
    const char *segment = name;
    for (const char *p = name; ; p++) {
        if (*p == '/' || !*p) {
            size_t size = (size_t)(p - segment);
            if (!size || (size == 1 && segment[0] == '.') || (size == 2 && segment[0] == '.' && segment[1] == '.')) return false;
            if (!*p) break;
            segment = p + 1;
        } else if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return false;
    }
    return true;
}
static bool valid_snapshot(const InstallSnapshot *snapshot) {
    size_t count = snapshot->count;
    if (!count || count > 1024 || !snapshot->files || !hash_string(snapshot->manifest_sha256)) return fail("fixed-manifest-invalid");
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        const EnvaraPFInstallFile *file = &snapshot->files[i];
        if (!relative_name(file->name) || !hash_string(file->sha256) || (file->mode != 0644 && file->mode != 0755)) return fail("fixed-manifest-invalid");
        if (!strcmp(file->name, "manifest.json")) found = !strcmp(file->sha256, snapshot->manifest_sha256);
        for (size_t j = 0; j < i; j++) {
            const char *other = snapshot->files[j].name;
            size_t a = strlen(file->name), b = strlen(other);
            if (!strcmp(file->name, other) || (a < b && !strncmp(file->name, other, a) && other[a] == '/') ||
                (b < a && !strncmp(file->name, other, b) && file->name[b] == '/')) return fail("fixed-manifest-invalid");
        }
    }
    return found || fail("fixed-manifest-invalid");
}
static bool valid_manifest(void) {
    return (ACTUAL_FILE_COUNT == ENVARA_PF_INSTALL_FILE_COUNT || fail("fixed-manifest-invalid")) && valid_snapshot(&current_snapshot);
}
static bool no_writable_acl_value(acl_t acl) {
    acl_entry_t entry;
    int cursor = ACL_FIRST_ENTRY, result;
    while ((result = acl_get_entry(acl, cursor, &entry)) == 0) {
        cursor = ACL_NEXT_ENTRY;
        acl_tag_t tag; acl_permset_t permissions;
        if (acl_get_tag_type(entry, &tag) || acl_get_permset(entry, &permissions)) { acl_free(acl); return false; }
        if (tag == ACL_EXTENDED_ALLOW && (acl_get_perm_np(permissions, ACL_WRITE_DATA) == 1 ||
            acl_get_perm_np(permissions, ACL_APPEND_DATA) == 1 || acl_get_perm_np(permissions, ACL_DELETE) == 1 ||
            acl_get_perm_np(permissions, ACL_DELETE_CHILD) == 1 || acl_get_perm_np(permissions, ACL_WRITE_ATTRIBUTES) == 1 ||
            acl_get_perm_np(permissions, ACL_WRITE_EXTATTRIBUTES) == 1 || acl_get_perm_np(permissions, ACL_WRITE_SECURITY) == 1 ||
            acl_get_perm_np(permissions, ACL_CHANGE_OWNER) == 1)) { acl_free(acl); return false; }
    }
    int error = errno; acl_free(acl);
    return result == -1 && error == EINVAL;
}
static bool no_writable_acl(int fd) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) {
        /* Darwin reports ENOENT for absent extended ACLs even on a live FD.
         * A bad FD, inaccessible ACL or unsupported filesystem stays refused. */
        int error = errno; struct stat info;
        return error == ENOENT && fstat(fd, &info) == 0;
    }
    return no_writable_acl_value(acl);
}
static bool no_writable_acl_at(int parent, const char *name, const struct stat *expected) {
    char base[PATH_MAX], target[PATH_MAX];
    if (!relative_name(name) || strchr(name, '/') || fcntl(parent, F_GETPATH, base)) return false;
    int length = snprintf(target, sizeof(target), "%s/%s", base, name);
    if (length < 0 || (size_t)length >= sizeof(target)) return false;
    errno = 0; acl_t acl = acl_get_link_np(target, ACL_TYPE_EXTENDED);
    bool okay = acl ? no_writable_acl_value(acl) : errno == ENOENT;
    struct stat after;
    return okay && fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(after.st_mode) &&
        expected->st_dev == after.st_dev && expected->st_ino == after.st_ino && expected->st_uid == after.st_uid &&
        expected->st_gid == after.st_gid && expected->st_mode == after.st_mode &&
        expected->st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && expected->st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
}
static bool secure_root_object(int fd, bool directory) {
    struct stat info;
    return fstat(fd, &info) == 0 && (directory ? S_ISDIR(info.st_mode) : S_ISREG(info.st_mode)) &&
        info.st_uid == 0 && !(info.st_mode & 0022) && no_writable_acl(fd);
}
static bool clear_acl(int fd) {
    acl_t empty = acl_init(0);
    if (!empty) return false;
    int result = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED);
    acl_free(empty); return result == 0;
}
/* Each path component is opened relative to an already held directory FD. */
static int directory_at(int fd, const char *component, bool root_owned, bool create) {
    int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0 && errno == ENOENT && create) {
        if (mkdirat(fd, component, 0755)) return -1;
        next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next >= 0 && (fchown(next, 0, 0) || !clear_acl(next) || fchmod(next, 0755))) { close(next); return -1; }
    }
    if (next >= 0 && root_owned && !secure_root_object(next, true)) { close(next); return -1; }
    return next;
}
static int absolute_directory(const char *name, bool root_owned) {
    if (!name || name[0] != '/' || strlen(name) >= PATH_MAX) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || (root_owned && !secure_root_object(fd, true))) { if (fd >= 0) close(fd); return -1; }
    char copy[PATH_MAX]; snprintf(copy, sizeof(copy), "%s", name);
    char *save = NULL;
    for (char *part = strtok_r(copy + 1, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return -1; }
        int next = directory_at(fd, part, root_owned, false); close(fd); fd = next;
        if (fd < 0) return -1;
    }
    return fd;
}
static int relative_parent(int base, const char *name, bool root_owned, bool create, char leaf[1024]) {
    char copy[1024]; snprintf(copy, sizeof(copy), "%s", name);
    int fd = dup(base); if (fd < 0) return -1;
    char *save = NULL, *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next_part = strtok_r(NULL, "/", &save);
        if (!next_part) { snprintf(leaf, 1024, "%s", part); return fd; }
        int next = directory_at(fd, part, root_owned, create); close(fd); fd = next;
        if (fd < 0) return -1;
        part = next_part;
    }
    close(fd); return -1;
}
static bool write_all(int fd, const unsigned char *bytes, size_t size) {
    while (size) {
        ssize_t written = write(fd, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        bytes += written; size -= (size_t)written;
    }
    return true;
}
static bool check_resource_file(int source, const EnvaraPFInstallFile *file, int output, bool root_owned, bool exact_mode) {
    char leaf[1024]; int parent = relative_parent(source, file->name, root_owned, false, leaf);
    if (parent < 0) return fail("resource-path-unsafe");
    int fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); close(parent);
    if (fd < 0) return fail("resource-path-unsafe");
    struct stat before, after;
    bool okay = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size >= 0 &&
        (uint64_t)before.st_size <= MAX_FILE_BYTES;
    if (root_owned) okay = okay && secure_root_object(fd, false);
    if (exact_mode) okay = okay && (before.st_mode & 07777) == file->mode;
    if (!okay) { close(fd); return fail("resource-file-unsafe"); }
    CC_SHA256_CTX digest;
    CC_SHA256_Init(&digest);
    unsigned char bytes[65536], result[CC_SHA256_DIGEST_LENGTH];
    uint64_t count = 0; double started = clock_seconds();
    while (okay) {
        if (clock_seconds() - started > 30.0) { okay = fail("resource-read-deadline"); break; }
        ssize_t size = read(fd, bytes, sizeof(bytes));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) { okay = fail("resource-read-failed"); break; }
        if (!size) break;
        count += (uint64_t)size;
        if (count > (uint64_t)before.st_size || count > MAX_FILE_BYTES) { okay = fail("resource-changed"); break; }
        CC_SHA256_Update(&digest, bytes, (CC_LONG)size);
        if (output >= 0 && !write_all(output, bytes, (size_t)size)) { okay = fail("resource-copy-failed"); break; }
    }
    if (okay && (fstat(fd, &after) || count != (uint64_t)before.st_size || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec || after.st_nlink != 1)) okay = fail("resource-changed");
    close(fd);
    CC_SHA256_Final(result, &digest);
    char hex[65]; for (size_t i = 0; i < sizeof(result); i++) snprintf(hex + i * 2, 3, "%02x", result[i]);
    if (okay && strcmp(hex, file->sha256)) okay = fail("resource-hash-mismatch");
    if (okay && (count > MAX_TOTAL_BYTES - total_bytes)) okay = fail("resource-total-too-large");
    if (okay) total_bytes += count;
    return okay;
}
static bool check_file(int source, const EnvaraPFInstallFile *file, int output, bool root_owned) {
    return check_resource_file(source, file, output, root_owned, root_owned);
}
static bool verify_files(int source, bool root_owned) {
    total_bytes = 0;
    if (!valid_manifest()) return false;
    for (size_t i = 0; i < ACTUAL_FILE_COUNT; i++) if (!check_file(source, &ENVARA_PF_INSTALL_FILES[i], -1, root_owned)) return false;
    return true;
}
static bool listed_snapshot_path(const char *name, bool directory, const InstallSnapshot *snapshot) {
    size_t length = strlen(name);
    for (size_t i = 0; i < snapshot->count; i++) {
        const char *listed = snapshot->files[i].name;
        if (directory ? strlen(listed) > length && !strncmp(listed, name, length) && listed[length] == '/' : !strcmp(listed, name)) return true;
    }
    return false;
}
static bool exact_snapshot_tree(int fd, const char *prefix, size_t depth, const InstallSnapshot *snapshot, bool root_owned) {
    if (depth > 64) return false;
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return false;
    DIR *directory = fdopendir(scan); if (!directory) { close(scan); return false; }
    bool okay = true; struct dirent *entry;
    while (okay) {
        errno = 0; entry = readdir(directory);
        if (!entry) { if (errno) okay = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char name[1024]; int size = snprintf(name, sizeof(name), "%s%s%s", prefix, *prefix ? "/" : "", entry->d_name);
        struct stat info;
        if (size < 0 || (size_t)size >= sizeof(name) || fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW)) { okay = false; break; }
        bool is_directory = S_ISDIR(info.st_mode);
        if (!listed_snapshot_path(name, is_directory, snapshot) || (!is_directory && !S_ISREG(info.st_mode))) { okay = false; break; }
        if (root_owned && is_directory && (info.st_mode & 07777) != 0755) { okay = false; break; }
        if (is_directory) {
            int next = directory_at(fd, entry->d_name, root_owned, false);
            okay = next >= 0 && exact_snapshot_tree(next, name, depth + 1, snapshot, root_owned); if (next >= 0) close(next);
        }
    }
    closedir(directory); return okay;
}
static bool exact_tree(int fd, const char *prefix, size_t depth) {
    return valid_manifest() && exact_snapshot_tree(fd, prefix, depth, &current_snapshot, true);
}
static bool snapshot_matches(int fd, const InstallSnapshot *snapshot, bool root_owned) {
    total_bytes = 0;
    struct stat directory;
    if (!valid_snapshot(snapshot) || (root_owned && !secure_root_object(fd, true)) ||
        fstat(fd, &directory) || !S_ISDIR(directory.st_mode) || (root_owned && (directory.st_mode & 07777) != 0755) ||
        !exact_snapshot_tree(fd, "", 0, snapshot, root_owned)) return false;
    for (size_t i = 0; i < snapshot->count; i++)
        if (!check_resource_file(fd, &snapshot->files[i], -1, root_owned, true)) return false;
    return true;
}
static bool same_directory_at(int parent, const char *name, int held);
typedef bool (*DirectorySync)(int fd, const char *relative, void *context);
static bool sync_directory_native(int fd, const char *relative, void *context) {
    (void)relative; (void)context;
    return fsync(fd) == 0;
}
/* Files are flushed while their copy FDs are held. Flush every fixed nested
 * directory bottom-up as well, so child names precede the staging root. */
static bool sync_snapshot_directories(int fd, const char *prefix, size_t depth,
    const InstallSnapshot *snapshot, bool root_owned, DirectorySync sync_directory, void *context) {
    if (depth > 64 || !valid_snapshot(snapshot) || (root_owned && !secure_root_object(fd, true))) return false;
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return false;
    DIR *directory = fdopendir(scan); if (!directory) { close(scan); return false; }
    bool okay = true;
    while (okay) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) okay = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char name[1024]; int size = snprintf(name, sizeof(name), "%s%s%s", prefix, *prefix ? "/" : "", entry->d_name);
        struct stat info;
        if (size < 0 || (size_t)size >= sizeof(name) || fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW)) { okay = false; break; }
        bool nested = S_ISDIR(info.st_mode);
        if (!listed_snapshot_path(name, nested, snapshot) || (!nested && !S_ISREG(info.st_mode))) { okay = false; break; }
        if (nested) {
            int child = directory_at(fd, entry->d_name, root_owned, false);
            okay = child >= 0 && same_directory_at(fd, entry->d_name, child) &&
                sync_snapshot_directories(child, name, depth + 1, snapshot, root_owned, sync_directory, context) &&
                same_directory_at(fd, entry->d_name, child);
            if (child >= 0) close(child);
        }
    }
    closedir(directory);
    return okay && sync_directory(fd, prefix, context);
}
static bool same_directory_at(int parent, const char *name, int held) {
    struct stat expected, actual;
    return fstat(held, &expected) == 0 && fstatat(parent, name, &actual, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(expected.st_mode) && S_ISDIR(actual.st_mode) && expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino;
}
static bool pending_stage(int parent) {
    int scan = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return true;
    DIR *directory = fdopendir(scan); if (!directory) { close(scan); return true; }
    bool present = false; struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(directory);
        if (!entry) { if (errno) present = true; break; }
        /* Unknown, corrupt and crash leftovers all require review, regardless
         * of file type. Never follow or automatically clean one of them. */
        if (!strncmp(entry->d_name, STAGE_PREFIX, strlen(STAGE_PREFIX))) { present = true; break; }
    }
    closedir(directory); return present;
}
static bool fixed_entry_absent(int parent, const char *name) {
    struct stat info;
    return fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}
static bool legacy_runtime_absent(void) {
    /* This is only a fixed legacy presence probe. Stock macOS /private/var/run
     * is root:daemon 0775; it is never used to write or load current resources.
     * Generic privileged-directory validation remains unchanged. Any legacy
     * entry, even an empty directory or dangling link, requires manual review. */
    char canonical[PATH_MAX];
    if (!realpath("/var/run", canonical) || strcmp(canonical, "/private/var/run")) return false;
    int parent = absolute_directory("/private/var", true); if (parent < 0) return false;
    int runtime = directory_at(parent, "run", false, false);
    struct stat info;
    bool standard_parent = runtime >= 0 && fstat(runtime, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == 0 &&
        info.st_gid == 1 && (info.st_mode & 07777) == 0775 && no_writable_acl(runtime);
    bool okay = runtime >= 0 && same_directory_at(parent, "run", runtime) &&
        (standard_parent || secure_root_object(runtime, true)) && fixed_entry_absent(runtime, "envara-pf-routing") &&
        same_directory_at(parent, "run", runtime);
    if (runtime >= 0) close(runtime); close(parent); return okay;
}
static bool directory_contents_empty(int fd) {
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *directory = scan >= 0 ? fdopendir(scan) : NULL;
    if (!directory) { if (scan >= 0) close(scan); return false; }
    bool okay = true;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) okay = false; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { okay = false; break; }
    }
    closedir(directory); return okay;
}
typedef enum { RUNTIME_REFUSED, RUNTIME_VERIFIED_ABSENT, RUNTIME_PRIVATE_INSPECTION } RuntimeInspection;
static RuntimeInspection runtime_directory_inspection(int parent, const char *name, bool root_owned) {
    if (fixed_entry_absent(parent, name)) return RUNTIME_VERIFIED_ABSENT;
    struct stat info;
    if (fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(info.st_mode) ||
        info.st_uid != (root_owned ? 0 : geteuid()) || (info.st_mode & 07777) != 0700 ||
        !no_writable_acl_at(parent, name, &info)) return RUNTIME_REFUSED;
    int runtime = directory_at(parent, name, root_owned, false);
    if (runtime < 0) return geteuid() != 0 && (errno == EACCES || errno == EPERM) ? RUNTIME_PRIVATE_INSPECTION : RUNTIME_REFUSED;
    bool stable = same_directory_at(parent, name, runtime);
    bool empty = stable && directory_contents_empty(runtime); int read_error = errno;
    stable = stable && same_directory_at(parent, name, runtime);
    close(runtime);
    if (stable && empty) return RUNTIME_VERIFIED_ABSENT;
    return stable && geteuid() != 0 && (read_error == EACCES || read_error == EPERM) ? RUNTIME_PRIVATE_INSPECTION : RUNTIME_REFUSED;
}
static RuntimeInspection runtime_inspection(void) {
    /* Inspection only. The current runtime lives under safe root ancestors,
     * separate from installed resources. Preserve any legacy or current
     * evidence, including unknown entries; never clean it during installation. */
    if (!legacy_runtime_absent()) return RUNTIME_REFUSED;
    int parent = absolute_directory(INSTALL_PARENT, true);
    if (parent < 0) {
        int library = absolute_directory("/Library", true);
        bool absent = library >= 0 && fixed_entry_absent(library, "PrivilegedHelperTools");
        if (library >= 0) close(library);
        return absent ? RUNTIME_VERIFIED_ABSENT : RUNTIME_REFUSED;
    }
    RuntimeInspection result = runtime_directory_inspection(parent, RUNTIME_NAME, true);
    close(parent); return result;
}
static bool runtime_registry_absent(void) {
    return runtime_inspection() == RUNTIME_VERIFIED_ABSENT;
}
typedef bool (*SnapshotValidator)(int fd, void *context);
typedef enum { EXCHANGE_REFUSED, EXCHANGE_COMMITTED, EXCHANGE_ROLLED_BACK, EXCHANGE_UNCONFIRMED } ExchangeResult;
/* No delete is performed here. The old directory is retained through complete
 * post-swap validation and any rollback; the caller owns the transaction lock.
 * Parameterized validators let the identical filesystem transaction be tested
 * against unprivileged owned temp data without relaxing production ownership. */
static ExchangeResult exchange_known_snapshot(int parent, const char *stage_name, const char *target_name,
    int old_fd, int new_fd, SnapshotValidator old_validator, void *old_context,
    SnapshotValidator new_validator, void *new_context) {
    if (!same_directory_at(parent, target_name, old_fd) || !same_directory_at(parent, stage_name, new_fd) ||
        !old_validator(old_fd, old_context) || !new_validator(new_fd, new_context)) return EXCHANGE_REFUSED;
    if (!same_directory_at(parent, target_name, old_fd) || !same_directory_at(parent, stage_name, new_fd)) return EXCHANGE_REFUSED;
    if (renameatx_np(parent, stage_name, parent, target_name, RENAME_SWAP)) return EXCHANGE_REFUSED;
    bool confirmed = fsync(parent) == 0 && same_directory_at(parent, target_name, new_fd) &&
        same_directory_at(parent, stage_name, old_fd) && old_validator(old_fd, old_context) && new_validator(new_fd, new_context) &&
        same_directory_at(parent, target_name, new_fd) && same_directory_at(parent, stage_name, old_fd);
    if (confirmed) return EXCHANGE_COMMITTED;
    /* Restore only our two proven directory identities and the still-exact
     * prior snapshot. Never swap an unknown replacement over a newer target. */
    if (same_directory_at(parent, target_name, new_fd) && same_directory_at(parent, stage_name, old_fd) &&
        old_validator(old_fd, old_context) && same_directory_at(parent, target_name, new_fd) &&
        same_directory_at(parent, stage_name, old_fd) && !renameatx_np(parent, stage_name, parent, target_name, RENAME_SWAP) &&
        !fsync(parent) && same_directory_at(parent, target_name, old_fd) &&
        same_directory_at(parent, stage_name, new_fd) && old_validator(old_fd, old_context)) return EXCHANGE_ROLLED_BACK;
    return EXCHANGE_UNCONFIRMED;
}
static bool production_snapshot_validator(int fd, void *context) {
    return snapshot_matches(fd, (const InstallSnapshot *)context, true);
}
static int install_parent(bool create) {
    int library = absolute_directory("/Library", true); if (library < 0) return -1;
    int parent = directory_at(library, "PrivilegedHelperTools", true, create); close(library); return parent;
}
static const InstallSnapshot *prior_snapshot(int classification) {
    return classification >= 2 && (size_t)(classification - 2) < KNOWN_PRIOR_COUNT ? known_prior_snapshots[classification - 2] : NULL;
}
static const char *known_prior_receipt(const char *output) {
    const char *found = NULL;
    for (size_t i = 0; i < KNOWN_PRIOR_COUNT; i++) {
        char field[128]; int size = snprintf(field, sizeof(field), "\"priorManifestSHA256\":\"%s\"", known_prior_snapshots[i]->manifest_sha256);
        if (size < 0 || (size_t)size >= sizeof(field)) return NULL;
        if (strstr(output, field)) {
            if (found) return NULL;
            found = known_prior_snapshots[i]->manifest_sha256;
        }
    }
    return found;
}
/* 0 absent, 1 exact current, 2+ fixed known-prior index, -1 unknown. */
static int existing_installation(int parent) {
    if (!valid_manifest()) return -1;
    struct stat info;
    if (fstatat(parent, INSTALL_NAME, &info, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT ? 0 : -1;
    int fd = directory_at(parent, INSTALL_NAME, true, false); if (fd < 0) return -1;
    int result = snapshot_matches(fd, &current_snapshot, true) ? 1 : -1;
    for (size_t i = 0; result < 0 && i < KNOWN_PRIOR_COUNT; i++)
        if (snapshot_matches(fd, known_prior_snapshots[i], true)) result = (int)i + 2;
    close(fd); return result;
}
static bool self_source(char executable[PATH_MAX], char source[PATH_MAX]) {
    char raw[PATH_MAX]; uint32_t count = sizeof(raw);
    if (_NSGetExecutablePath(raw, &count) || !realpath(raw, executable)) return fail("installer-location-unavailable");
    int fd = open(executable, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat info;
    bool okay = fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1;
    if (fd >= 0) close(fd);
    if (!okay) return fail("installer-location-unsafe");
    snprintf(source, PATH_MAX, "%s", executable);
    char *slash = strrchr(source, '/'); if (!slash || slash == source) return fail("installer-location-unsafe");
    *slash = 0; return true;
}
static void result_json(bool installed, bool changed, const char *reason) {
    printf("{\"schema\":\"%s\",\"action\":\"installedResourcesOnly\",\"installed\":%s,\"changed\":%s,\"ready\":false,\"productionReady\":false,\"manifestSHA256\":", SCHEMA, installed ? "true" : "false", changed ? "true" : "false");
    json_string(ENVARA_PF_INSTALL_MANIFEST_SHA256); printf(",\"reason\":");
    json_string(reason); printf(",\"needsManualReview\":%s", needs_manual_review ? "true" : "false");
    if (upgraded_from) { printf(",\"priorManifestSHA256\":"); json_string(upgraded_from); }
    authorization_diagnostic(); puts("}"); fflush(stdout);
}
static void remove_stage(int parent, const char *name) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *directory = scan >= 0 ? fdopendir(scan) : NULL;
    if (!directory && scan >= 0) close(scan);
    if (directory) {
        struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            struct stat info;
            if (!fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) && S_ISDIR(info.st_mode)) remove_stage(fd, entry->d_name);
            else (void)unlinkat(fd, entry->d_name, 0);
        }
        closedir(directory);
    }
    close(fd); (void)unlinkat(parent, name, AT_REMOVEDIR);
}
static bool cleanup_exact_snapshot(int parent, const char *name, int held, const InstallSnapshot *snapshot, bool root_owned) {
    if (!same_directory_at(parent, name, held) || !snapshot_matches(held, snapshot, root_owned)) return false;
    remove_stage(parent, name);
    struct stat info;
    return fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT && fsync(parent) == 0;
}
static bool install_resources(int source, bool *changed) {
    if (!valid_manifest()) return false;
    if (!runtime_registry_absent()) return fail("controlled-runtime-still-present");
    int parent = install_parent(true); if (parent < 0) return fail("destination-parent-unsafe");
    if (flock(parent, LOCK_EX | LOCK_NB)) { close(parent); return fail("installation-maintenance-busy"); }
    if (pending_stage(parent)) { needs_manual_review = true; close(parent); return fail("owned-staging-review-required"); }
    int existing = existing_installation(parent);
    if (existing == 1) { close(parent); return true; }
    if (existing < 0) { close(parent); return fail("existing-installation-conflict"); }
    if (!runtime_registry_absent()) { close(parent); return fail("controlled-runtime-still-present"); }
    const InstallSnapshot *prior = prior_snapshot(existing);
    int old = prior ? directory_at(parent, INSTALL_NAME, true, false) : -1;
    if (prior && (old < 0 || !snapshot_matches(old, prior, true))) {
        if (old >= 0) close(old); close(parent); return fail("existing-installation-conflict");
    }
    char name[128] = {0}; int stage = -1; bool stage_created = false;
    for (int attempt = 0; attempt < 16; attempt++) {
        unsigned char random[16]; arc4random_buf(random, sizeof(random));
        char suffix[33]; for (size_t i = 0; i < sizeof(random); i++) snprintf(suffix + i * 2, 3, "%02x", random[i]);
        snprintf(name, sizeof(name), ".%s-stage-%s", INSTALL_NAME, suffix);
        if (!mkdirat(parent, name, 0700)) { stage_created = true; stage = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); break; }
        if (errno != EEXIST) break;
    }
    bool okay = stage >= 0 && !fchown(stage, 0, 0) && clear_acl(stage) && !fchmod(stage, 0700) && secure_root_object(stage, true);
    total_bytes = 0;
    for (size_t i = 0; okay && i < ACTUAL_FILE_COUNT; i++) {
        const EnvaraPFInstallFile *file = &ENVARA_PF_INSTALL_FILES[i]; char leaf[1024];
        int directory = relative_parent(stage, file->name, true, true, leaf);
        int output = directory < 0 ? -1 : openat(directory, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (directory >= 0) close(directory);
        okay = output >= 0 && check_file(source, file, output, false) && !fchown(output, 0, 0) && clear_acl(output) && !fchmod(output, file->mode) && !fsync(output);
        if (output >= 0) close(output);
    }
    if (okay) okay = exact_tree(stage, "", 0) && verify_files(stage, true) && !fchmod(stage, 0755) &&
        sync_snapshot_directories(stage, "", 0, &current_snapshot, true, sync_directory_native, NULL) &&
        snapshot_matches(stage, &current_snapshot, true);
    ExchangeResult exchange = EXCHANGE_REFUSED;
    bool was_swapped = false;
    if (okay && !runtime_registry_absent()) okay = fail("controlled-runtime-still-present");
    if (okay && prior) {
        exchange = exchange_known_snapshot(parent, name, INSTALL_NAME, old, stage,
            production_snapshot_validator, (void *)prior,
            production_snapshot_validator, (void *)&current_snapshot);
        was_swapped = exchange != EXCHANGE_REFUSED;
        okay = exchange == EXCHANGE_COMMITTED;
        if (okay) {
            *changed = true; upgraded_from = prior->manifest_sha256;
            okay = cleanup_exact_snapshot(parent, name, old, prior, true);
            if (!okay) { needs_manual_review = true; failure = "upgrade-cleanup-required"; }
        } else {
            needs_manual_review = exchange == EXCHANGE_UNCONFIRMED;
            failure = exchange == EXCHANGE_UNCONFIRMED ? "upgrade-rollback-unconfirmed" :
                exchange == EXCHANGE_ROLLED_BACK ? "upgrade-rolled-back" : "upgrade-target-changed";
        }
    } else if (okay) {
        okay = renameatx_np(parent, name, parent, INSTALL_NAME, RENAME_EXCL) == 0;
        if (okay) { *changed = true; okay = fsync(parent) == 0; if (!okay) { needs_manual_review = true; failure = "installation-commit-unconfirmed"; } }
    }
    if (!okay && stage_created && stage >= 0 && (!was_swapped || exchange == EXCHANGE_ROLLED_BACK) &&
        same_directory_at(parent, name, stage)) {
        /* Before a swap (or after a confirmed rollback), only this invocation's
         * private new stage may be discarded. Crash/old/unknown backups stay. */
        if (exact_tree(stage, "", 0)) remove_stage(parent, name); else needs_manual_review = true;
    }
    if (!okay && !strcmp(failure, "installation-unconfirmed")) failure = "atomic-install-failed";
    if (stage >= 0) close(stage); if (old >= 0) close(old);
    close(parent); return okay;
}
static int plan(const char *source_path) {
    total_bytes = 0;
    bool manifest_valid = valid_manifest();
    int source = manifest_valid ? absolute_directory(source_path, false) : -1;
    if (manifest_valid && source < 0) failure = "resource-path-unsafe";
    bool verified = manifest_valid && source >= 0 && verify_files(source, false);
    const char *source_failure = failure;
    uint64_t bytes = total_bytes; if (source >= 0) close(source);
    int parent = manifest_valid ? install_parent(false) : -1;
    needs_manual_review = parent >= 0 && pending_stage(parent);
    int existing = parent >= 0 ? existing_installation(parent) : -1; if (parent >= 0) close(parent);
    const InstallSnapshot *prior = prior_snapshot(existing);
    if (manifest_valid && parent < 0) {
        int library = absolute_directory("/Library", true); struct stat info;
        if (library >= 0 && fstatat(library, "PrivilegedHelperTools", &info, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT) existing = 0;
        if (library >= 0) close(library);
    }
    RuntimeInspection inspection = manifest_valid ? runtime_inspection() : RUNTIME_REFUSED;
    bool idle = inspection == RUNTIME_VERIFIED_ABSENT, private_inspection = inspection == RUNTIME_PRIVATE_INSPECTION;
    bool can_request = verified && existing >= 0 && !needs_manual_review && inspection != RUNTIME_REFUSED;
    printf("{\"schema\":\"%s\",\"action\":\"installedResourcesOnly\",\"readOnly\":true,\"ready\":false,\"productionReady\":false,\"systemInstallation\":false,\"activation\":false,\"requiresAdministrator\":true,\"requiresAppleDeveloperIdentity\":false,\"deprecatedAuthorizationAPI\":true,\"bootstrapIdentityBound\":false,\"sourceVerified\":%s,\"canRequestInstall\":%s,\"canRequestAuthorizationForInspection\":%s,\"privateRuntimeInspectionRequired\":%s,\"source\":", SCHEMA, verified ? "true" : "false", can_request ? "true" : "false", can_request && private_inspection ? "true" : "false", private_inspection ? "true" : "false");
    json_string(source_path);
    printf(",\"target\":\"%s\",\"manifestSHA256\":", INSTALL_TARGET); json_string(ENVARA_PF_INSTALL_MANIFEST_SHA256);
    printf(",\"totalBytes\":%llu,\"existingInstallation\":\"%s\",\"needsManualReview\":%s,\"requiresUpgradeApproval\":%s,\"controlledRuntimeAbsent\":%s", (unsigned long long)bytes, existing == 1 ? "exact" : prior ? "known-prior" : existing == 0 ? "absent" : "unknown-or-conflict", needs_manual_review ? "true" : "false", prior ? "true" : "false", idle ? "true" : "false");
    if (prior) { printf(",\"priorManifestSHA256\":"); json_string(prior->manifest_sha256); }
    printf(",\"files\":[");
    for (size_t i = 0; i < ACTUAL_FILE_COUNT && i < 1024; i++) {
        if (i) putchar(','); printf("{\"name\":"); json_string(ENVARA_PF_INSTALL_FILES[i].name);
        printf(",\"sha256\":"); json_string(ENVARA_PF_INSTALL_FILES[i].sha256);
        printf(",\"mode\":%u}", ENVARA_PF_INSTALL_FILES[i].mode);
    }
    printf("],\"operations\":{\"copyFixedResources\":true,\"changePF\":false,\"createGroups\":false,\"createTunnel\":false,\"startDaemon\":false,\"launchApplication\":false},\"controlledExperiment\":{\"operation\":\"request-controlled-experiment\",\"separateApprovalRequired\":true,\"boundedSeconds\":180,\"maxGroups\":2,\"maxTunnels\":2,\"installedPayloadRequired\":true,\"privateCommunicationRequired\":true,\"productionReady\":false},\"reason\":");
    json_string(verified ? needs_manual_review ? "owned-staging-review-required" : inspection == RUNTIME_REFUSED ? "controlled-runtime-still-present" :
        private_inspection ? "privileged-runtime-inspection-required" :
        existing < 0 ? "destination-review-required" : prior ? "explicit-upgrade-approval-required" : "explicit-installation-approval-required" : source_failure); puts("}");
    return verified ? 0 : 1;
}
static void experiment_failure(const char *reason) {
    /* No private request, environment or raw Security/OS error reaches logs. */
    printf("{\"protocol\":\"envara.application-routing\",\"version\":1,\"id\":null,\"error\":{\"code\":\"APPLICATION_ROUTING_AUTHORIZATION_REQUIRED\",\"message\":");
    json_string(reason); printf("}"); authorization_diagnostic(); puts("}"); fflush(stdout);
}
static bool console_uid(uid_t *uid) {
    struct stat info;
    if (lstat("/dev/console", &info) || !S_ISCHR(info.st_mode) || info.st_uid == 0 || info.st_uid == (uid_t)-1)
        return fail("active-console-user-required");
    *uid = info.st_uid;
    return true;
}
static bool installed_helper_verified(void) {
    if (!valid_manifest()) return false;
    bool listed_helper = false;
    for (size_t i = 0; i < ACTUAL_FILE_COUNT; i++)
        if (!strcmp(ENVARA_PF_INSTALL_FILES[i].name, "EnvaraPFHelper") && ENVARA_PF_INSTALL_FILES[i].mode == 0755) listed_helper = true;
    if (!listed_helper) return fail("fixed-helper-missing");
    int parent = install_parent(false);
    if (parent >= 0 && pending_stage(parent)) { needs_manual_review = true; close(parent); return fail("owned-staging-review-required"); }
    int installed = parent < 0 ? -1 : existing_installation(parent);
    if (parent >= 0) close(parent);
    return installed == 1 || fail("reviewed-installed-payload-required");
}
static bool unix_stream(int fd) {
    int type = 0; socklen_t size = sizeof(type);
    struct sockaddr_storage address; socklen_t length = sizeof(address);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_STREAM &&
        getsockname(fd, (struct sockaddr *)&address, &length) == 0 && address.ss_family == AF_UNIX;
}
static bool private_stdio(int fd) {
    struct stat info;
    return fstat(fd, &info) == 0 && (S_ISFIFO(info.st_mode) || (S_ISSOCK(info.st_mode) && unix_stream(fd)));
}
typedef struct { unsigned char data[RELAY_BYTES]; size_t start, length; } RelayBuffer;
static void compact_buffer(RelayBuffer *buffer) {
    if (buffer->start) { memmove(buffer->data, buffer->data + buffer->start, buffer->length); buffer->start = 0; }
}
static bool relay_read(int fd, RelayBuffer *buffer, bool *ended) {
    compact_buffer(buffer);
    ssize_t size = read(fd, buffer->data + buffer->length, sizeof(buffer->data) - buffer->length);
    if (size < 0) return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK;
    if (!size) *ended = true; else buffer->length += (size_t)size;
    return true;
}
static bool relay_write(int fd, RelayBuffer *buffer) {
    ssize_t size = write(fd, buffer->data + buffer->start, buffer->length);
    if (size < 0) return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK;
    if (!size) return false;
    buffer->start += (size_t)size; buffer->length -= (size_t)size;
    return true;
}
/* The API documents a bidirectional FILE. Verify its actual Unix socket before
 * relaying; stdin EOF closes only our write half, retaining the cleanup reply. */
static bool relay_helper(int fd, double seconds) {
    if (!unix_stream(fd) || !private_stdio(STDIN_FILENO) || !private_stdio(STDOUT_FILENO))
        return fail("private-bidirectional-communication-required");
    int descriptors[] = { fd, STDIN_FILENO, STDOUT_FILENO }, flags[3] = { -1, -1, -1 };
    bool okay = true;
    for (size_t i = 0; i < 3; i++) {
        flags[i] = fcntl(descriptors[i], F_GETFL);
        if (flags[i] < 0 || fcntl(descriptors[i], F_SETFL, flags[i] | O_NONBLOCK)) { okay = false; break; }
    }
    struct sigaction previous, ignored; memset(&ignored, 0, sizeof(ignored)); ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask); bool signal_changed = sigaction(SIGPIPE, &ignored, &previous) == 0;
    if (!signal_changed) okay = false;
    RelayBuffer input = {0}, output = {0};
    bool input_ended = false, root_ended = false, write_ended = false;
    double deadline = seconds > 0.0 ? clock_seconds() + seconds : 0.0;
    while (okay && (!root_ended || output.length)) {
        if (deadline > 0.0 && clock_seconds() >= deadline) { okay = fail("controlled-session-deadline"); break; }
        if (input_ended && !input.length && !write_ended) {
            if (shutdown(fd, SHUT_WR) && errno != ENOTCONN) { okay = false; break; }
            write_ended = true;
        }
        short root_events = (short)((!root_ended && output.length < RELAY_BYTES ? POLLIN : 0) | (!root_ended && input.length ? POLLOUT : 0));
        bool read_input = !input_ended && !root_ended && input.length < RELAY_BYTES;
        struct pollfd waits[] = {
            { root_events ? fd : -1, root_events, 0 },
            { read_input ? STDIN_FILENO : -1, POLLIN, 0 },
            { output.length ? STDOUT_FILENO : -1, POLLOUT, 0 }
        };
        /* An unbounded session (deadline zero) still waits in poll. Computing
         * the remaining time from a zero deadline gave a zero timeout, and the
         * relay spun for as long as an attach session stayed open. */
        double remaining = deadline > 0.0 ? deadline - clock_seconds() : 0.250;
        int wait_ms = remaining >= 0.250 ? 250 : remaining > 0 ? (int)(remaining * 1000.0) + 1 : 0;
        int observed = poll(waits, 3, wait_ms);
        if (observed < 0 && errno == EINTR) continue;
        if (observed < 0) { okay = false; break; }
        if (waits[0].revents & POLLNVAL || waits[1].revents & POLLNVAL || waits[2].revents & (POLLNVAL | POLLERR | POLLHUP)) { okay = false; break; }
        if (!root_ended && output.length < RELAY_BYTES && waits[0].revents & (POLLIN | POLLHUP | POLLERR)) okay = relay_read(fd, &output, &root_ended);
        if (okay && !root_ended && input.length && waits[0].revents & POLLOUT) okay = relay_write(fd, &input);
        if (okay && !input_ended && !root_ended && input.length < RELAY_BYTES && waits[1].revents & (POLLIN | POLLHUP | POLLERR)) okay = relay_read(STDIN_FILENO, &input, &input_ended);
        if (okay && output.length && waits[2].revents & POLLOUT) okay = relay_write(STDOUT_FILENO, &output);
        if (root_ended && input.length) { okay = fail("controlled-session-input-unconfirmed"); break; }
    }
    for (size_t i = 0; i < 3; i++) if (flags[i] >= 0) (void)fcntl(descriptors[i], F_SETFL, flags[i]);
    if (signal_changed) (void)sigaction(SIGPIPE, &previous, NULL);
    if (!okay && !strcmp(failure, "installation-unconfirmed")) failure = "controlled-session-communication-unconfirmed";
    return okay;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool privileged_reference(void) {
    if (geteuid() != 0) return fail("privileged-reference-required");
    AuthorizationRef reference = NULL;
    OSStatus status = AuthorizationCopyPrivilegedReference(&reference, kAuthorizationFlagDefaults);
    authorization_stage = "AuthorizationCopyPrivilegedReference"; authorization_status = status;
    if (status != errAuthorizationSuccess || !reference) return fail("privileged-reference-required");
    AuthorizationItem item = { kAuthorizationRightExecute, 0, NULL, 0 };
    AuthorizationRights rights = { 1, &item };
    status = AuthorizationCopyRights(reference, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, NULL);
    authorization_stage = "AuthorizationCopyRights"; authorization_status = status;
    AuthorizationFree(reference, kAuthorizationFlagDefaults);
    return status == errAuthorizationSuccess || fail("privileged-reference-required");
}
static bool authorized_self(const char *executable, const char *mode, const char *prompt, AuthorizationRef *reference, FILE **communications) {
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, reference);
    authorization_stage = "AuthorizationCreate"; authorization_status = status;
    AuthorizationItem item = { kAuthorizationRightExecute, 0, NULL, 0 };
    AuthorizationRights rights = { 1, &item };
    AuthorizationItem prompt_item = { kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0 };
    AuthorizationEnvironment environment = { 1, &prompt_item };
    if (status == errAuthorizationSuccess) {
        status = AuthorizationCopyRights(*reference, &rights, &environment, kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
        authorization_stage = "AuthorizationCopyRights"; authorization_status = status;
    }
    char *arguments[] = { (char *)mode, NULL };
    if (status == errAuthorizationSuccess) {
        status = AuthorizationExecuteWithPrivileges(*reference, executable, kAuthorizationFlagDefaults, arguments, communications);
        authorization_stage = "AuthorizationExecuteWithPrivileges"; authorization_status = status;
    }
    if (status != errAuthorizationSuccess || !*communications) {
        if (*reference) { AuthorizationFree(*reference, kAuthorizationFlagDestroyRights); *reference = NULL; }
        return fail(status == errAuthorizationCanceled ? "administrator-authorization-canceled" : status == errAuthorizationDenied ? "administrator-authorization-denied" : "native-authorization-unavailable");
    }
    return true;
}
static int request_install(const char *executable, const char *source_path) {
    int source = absolute_directory(source_path, false);
    bool verified = valid_manifest() && source >= 0 && verify_files(source, false); if (source >= 0) close(source);
    if (!verified) { result_json(false, false, failure); return 1; }
    AuthorizationRef reference = NULL;
    int parent = install_parent(false);
    if (parent >= 0) {
        bool review = pending_stage(parent);
        int existing = existing_installation(parent); close(parent);
        if (review || existing < 0) { needs_manual_review = review; result_json(false, false, review ? "owned-staging-review-required" : "existing-installation-conflict"); return 1; }
    }
    if (runtime_inspection() == RUNTIME_REFUSED) { result_json(false, false, "controlled-runtime-still-present"); return 1; }
    const char prompt[] = "Envara: inspect private runtime evidence as administrator, then install reviewed PF helper files only if no runtime evidence remains. Replace only an exact previously reviewed f8, e940, 518, 2a7, 832, ff9, 6f8, 199, 46a, c37, f99, 05d6, 14b87, dbcf or 43b snapshot. No network rules, tunnels, groups, daemon or applications will be started.";
    FILE *communications = NULL;
    if (!authorized_self(executable, "--install-fixed-manifest", prompt, &reference, &communications)) { result_json(false, false, failure); return 1; }
    int fd = fileno(communications); char output[4096]; size_t size = 0; bool completed = false;
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    double deadline = clock_seconds() + 120.0;
    while (clock_seconds() < deadline && size < sizeof(output) - 1) {
        struct pollfd wait = { fd, POLLIN | POLLHUP, 0 };
        int observed = poll(&wait, 1, 1000);
        if (observed < 0 && errno == EINTR) continue;
        if (observed < 0) break;
        if (!observed) continue;
        ssize_t count = read(fd, output + size, sizeof(output) - 1 - size);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count < 0) break;
        if (!count) { completed = true; break; }
        size += (size_t)count;
    }
    output[size] = 0; fclose(communications); AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
    parent = install_parent(false); int installed = parent < 0 ? -1 : existing_installation(parent);
    bool review = parent >= 0 && pending_stage(parent); if (parent >= 0) close(parent);
    bool okay = completed && strstr(output, "\"installed\":true") && strstr(output, ENVARA_PF_INSTALL_MANIFEST_SHA256) && installed == 1;
    okay = okay && !review; needs_manual_review = review;
    if (completed) upgraded_from = known_prior_receipt(output);
    bool changed = completed && strstr(output, ENVARA_PF_INSTALL_MANIFEST_SHA256) && strstr(output, "\"changed\":true");
    result_json(okay, changed, okay ? "installed-resources-only" : "installation-completion-unconfirmed");
    return okay ? 0 : 1;
}
static int request_controlled_experiment(const char *executable) {
    uid_t uid;
    if (!private_stdio(STDIN_FILENO) || !private_stdio(STDOUT_FILENO)) { experiment_failure("private-bidirectional-communication-required"); return 1; }
    if (!console_uid(&uid)) { experiment_failure(failure); return 1; }
    if (getuid() != uid) { experiment_failure("active-console-user-required"); return 1; }
    int lease = install_parent(false);
    if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) { if (lease >= 0) close(lease); experiment_failure("installation-maintenance-busy"); return 1; }
    if (!installed_helper_verified()) { close(lease); experiment_failure(failure); return 1; }
    AuthorizationRef reference = NULL; FILE *communications = NULL;
    const char prompt[] = "Envara: route applications you attach to a selected network group through temporary, owned PF rules and one dedicated tunnel per application, until you stop them or quit Envara. Existing VPN settings stay unchanged. Quitting Envara removes every temporary rule; the administrator password is asked once per Envara launch and no permanent daemon is installed.";
    if (!authorized_self(executable, "--run-controlled-experiment", prompt, &reference, &communications)) { close(lease); experiment_failure(failure); return 1; }
    bool okay = relay_helper(fileno(communications), RELAY_SECONDS);
    fclose(communications); AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
    close(lease);
    /* The runner validates helper RPC identity and cleanup receipts. Relay EOF
     * is transport completion, never protection or native acceptance proof. */
    if (!okay) experiment_failure(failure);
    return okay ? 0 : 1;
}
typedef void (*OwnedHelperEntry)(void *context);
static void controlled_helper_terminal_failure(void) {
    /* The outer Security relay cannot observe the root child's exit status.
     * Its socket EOF may therefore be followed by outer exit zero. Send a
     * fixed refusal over that same private channel instead. No run ID, raw
     * child output or exit diagnostic is copied into this terminal frame.
     * Exit zero never emits a positive cleanup receipt: only the controller's
     * run-bound evidence can establish cleanup for the acceptance client. */
    fputs("{\"protocol\":\"envara.application-routing\",\"version\":1,\"id\":null,"
          "\"terminal\":true,\"cleanupUncertain\":true,\"error\":{"
          "\"code\":\"APPLICATION_ROUTING_CLEANUP_UNCONFIRMED\","
          "\"message\":\"Root helper cleanup could not be confirmed\"}}\n", stdout);
    (void)fflush(stdout);
}
/* The root wrapper holds its own CLOEXEC directory lease, independent of the
 * outer user relay. Only waitpid confirmation releases it. A transport EOF or
 * deadline cannot prove the child exited. An unrecoverable wait error therefore
 * reports uncertainty once and retains the lease rather than exiting. */
static int guard_owned_helper(int lease, OwnedHelperEntry entry, void *context) {
    const int ignored[] = { SIGHUP, SIGINT, SIGTERM, SIGPIPE };
    for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++)
        if (signal(ignored[i], SIG_IGN) == SIG_ERR) { close(lease); experiment_failure("controlled-guardian-unavailable"); return 1; }
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) { close(lease); experiment_failure("controlled-guardian-unavailable"); return 1; }
    pid_t child = fork();
    if (child < 0) { close(lease); experiment_failure("controlled-helper-fork-failed"); return 1; }
    if (!child) {
        /* Never leak the installation-directory descriptor into the helper's
         * launched applications. Whole guardian SIGKILL remains an explicit
         * acceptance boundary, not a claim of kernel-enforced persistence. */
        close(lease);
        for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) (void)signal(ignored[i], SIG_DFL);
        (void)signal(SIGCHLD, SIG_DFL);
        entry(context); _exit(1);
    }
    bool reported = false;
    for (;;) {
        int status = 0; pid_t waited = waitpid(child, &status, 0);
        if (waited == child) {
            close(lease);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
            if (!reported) controlled_helper_terminal_failure();
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
        if (waited < 0 && errno == EINTR) continue;
        if (!reported) { controlled_helper_terminal_failure(); reported = true; }
        struct timespec retry = { 1, 0 }; (void)nanosleep(&retry, NULL);
    }
}
static void exec_fixed_controlled_helper(void *context) {
    uid_t uid = *(uid_t *)context;
    char user[32]; snprintf(user, sizeof(user), "%u", uid);
    char *arguments[] = { INSTALL_TARGET "/EnvaraPFHelper", "--controlled-experiment", "--caller-uid", user, NULL };
    char *environment[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
    execve(INSTALL_TARGET "/EnvaraPFHelper", arguments, environment);
    experiment_failure("fixed-installed-helper-exec-failed");
}
static int run_controlled_experiment(void) {
    uid_t uid;
    if (!privileged_reference() || !console_uid(&uid)) {
        experiment_failure(failure); return 1;
    }
    if (getuid() != 0 && getuid() != uid) { experiment_failure("active-console-user-required"); return 1; }
    if (!unix_stream(STDIN_FILENO) || !unix_stream(STDOUT_FILENO)) { experiment_failure("private-bidirectional-communication-required"); return 1; }
    gid_t root_group = 0;
    if (setgroups(1, &root_group) || setgid(0) || setuid(0) || getuid() || geteuid()) { experiment_failure("privileged-identity-unconfirmed"); return 1; }
    umask(0077);
    int lease = install_parent(false);
    if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) { if (lease >= 0) close(lease); experiment_failure("installation-maintenance-busy"); return 1; }
    if (!installed_helper_verified()) { close(lease); experiment_failure(failure); return 1; }
    return guard_owned_helper(lease, exec_fixed_controlled_helper, &uid);
}
#pragma clang diagnostic pop
int main(int argc, char **argv) {
    char executable[PATH_MAX], source_path[PATH_MAX];
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--plan") && strcmp(argv[1], "--request-install") && strcmp(argv[1], "--install-fixed-manifest") && strcmp(argv[1], "--request-controlled-experiment") && strcmp(argv[1], "--run-controlled-experiment"))) { result_json(false, false, "invalid-fixed-operation"); return 1; }
    if (!self_source(executable, source_path)) { result_json(false, false, failure); return 1; }
    if (argc == 1 || !strcmp(argv[1], "--plan")) return plan(source_path);
    if (!strcmp(argv[1], "--request-install")) return request_install(executable, source_path);
    if (!strcmp(argv[1], "--request-controlled-experiment")) return request_controlled_experiment(executable);
    if (!strcmp(argv[1], "--run-controlled-experiment")) return run_controlled_experiment();
    if (!privileged_reference() || !valid_manifest()) { result_json(false, false, failure); return 1; }
    umask(0077);
    int source = absolute_directory(source_path, false);
    bool changed = false;
    bool okay = source >= 0 && install_resources(source, &changed); if (source >= 0) close(source);
    result_json(okay, changed, okay ? "installed-resources-only" : failure); return okay ? 0 : 1;
}
