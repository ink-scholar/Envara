#include "gui-launch.h"
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <Security/Security.h>
#include <Security/AuthSession.h>
#include <CommonCrypto/CommonDigest.h>
#include <bsm/audit.h>
#include <fts.h>
#include <libproc.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/acl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static int denied(int error) { errno = error; return -1; }
static int bounded(const char *value, size_t capacity) {
    if (!value || !memchr(value, 0, capacity)) return 0;
    size_t length = strnlen(value, capacity);
    if (!length) return 0;
    for (size_t i = 0; i < length; i++) if ((unsigned char)value[i] < 32 || value[i] == 127) return 0;
    return 1;
}
static int uuid(const char *value) {
    if (!bounded(value, 37) || strlen(value) != 36) return 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return 0; }
        else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return value[14] >= '1' && value[14] <= '5' && strchr("89ab", value[19]);
}
static int inside(const char *root, const char *candidate) {
    size_t length = strlen(root);
    return !strncmp(root, candidate, length) && (candidate[length] == 0 || candidate[length] == '/');
}
static struct envara_gui_file_identity identity(const struct stat *info) {
    return (struct envara_gui_file_identity){info->st_dev, info->st_ino, info->st_size,
        info->st_mtimespec.tv_sec, info->st_mtimespec.tv_nsec, info->st_ctimespec.tv_sec,
        info->st_ctimespec.tv_nsec, info->st_uid, info->st_gid, info->st_mode};
}
static int identical(const struct envara_gui_file_identity *a, const struct envara_gui_file_identity *b) {
    return a->device == b->device && a->inode == b->inode && a->size == b->size &&
        a->modified_seconds == b->modified_seconds && a->modified_nanoseconds == b->modified_nanoseconds &&
        a->changed_seconds == b->changed_seconds && a->changed_nanoseconds == b->changed_nanoseconds &&
        a->owner == b->owner && a->group == b->group && a->mode == b->mode;
}
static void hex(const unsigned char *bytes, size_t length, char *out) {
    for (size_t i = 0; i < length; i++) snprintf(out + i * 2, 3, "%02x", bytes[i]);
    out[length * 2] = 0;
}
static void hash_bytes(CC_SHA256_CTX *context, const void *bytes, size_t length) {
    while (length) {
        size_t part = length > UINT32_MAX ? UINT32_MAX : length;
        CC_SHA256_Update(context, bytes, (CC_LONG)part);
        bytes = (const char *)bytes + part; length -= part;
    }
}
static int file_hash(const char *path, char out[65]) {
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    struct stat before, after;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode)) { close(fd); return denied(EINVAL); }
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) != 0) {
        if (count < 0) { if (errno == EINTR) continue; int error = errno; close(fd); return denied(error); }
        hash_bytes(&context, buffer, (size_t)count);
    }
    if (fstat(fd, &after)) { int error = errno; close(fd); return denied(error); }
    close(fd);
    struct envara_gui_file_identity a = identity(&before), b = identity(&after);
    if (!identical(&a, &b)) return denied(ESTALE);
    CC_SHA256_Final(digest, &context); hex(digest, sizeof(digest), out); return 0;
}
static int fts_order(const FTSENT **a, const FTSENT **b) { return strcmp((*a)->fts_name, (*b)->fts_name); }
static int tree_hash(const char *bundle, int fixture, char out[65], char content_out[65]) {
    char *roots[] = {(char *)bundle, NULL};
    FTS *tree = fts_open(roots, FTS_PHYSICAL | FTS_NOCHDIR, fts_order);
    if (!tree) return -1;
    CC_SHA256_CTX context, contents; CC_SHA256_Init(&context); CC_SHA256_Init(&contents);
    FTSENT *entry; size_t count = 0; int error = 0;
    errno = 0;
    while ((entry = fts_read(tree))) {
        if (entry->fts_info == FTS_DP) continue;
        if (++count > 200000 || entry->fts_info == FTS_ERR || entry->fts_info == FTS_DNR ||
            entry->fts_info == FTS_NS || entry->fts_info == FTS_DC || !entry->fts_statp) { error = EIO; break; }
        struct stat *info = entry->fts_statp;
        if (fixture && info->st_uid != getuid()) { error = EACCES; break; }
        if ((!S_ISLNK(info->st_mode) && (info->st_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH))) ||
            !(S_ISDIR(info->st_mode) || S_ISREG(info->st_mode) || S_ISLNK(info->st_mode))) { error = EACCES; break; }
        const char *relative = entry->fts_path + strlen(bundle);
        uint64_t length = strlen(relative);
        hash_bytes(&context, &length, sizeof(length)); hash_bytes(&context, relative, (size_t)length);
        hash_bytes(&contents, &length, sizeof(length)); hash_bytes(&contents, relative, (size_t)length);
        uint64_t content_mode = info->st_mode & (S_IFMT | 0111);
        hash_bytes(&contents, &content_mode, sizeof(content_mode));
        struct envara_gui_file_identity record = identity(info);
        /* Hash explicit fields, not padding bytes in a compiler-dependent struct. */
        uint64_t values[] = {record.device, record.inode, record.size, (uint64_t)record.modified_seconds,
            (uint64_t)record.modified_nanoseconds, (uint64_t)record.changed_seconds,
            (uint64_t)record.changed_nanoseconds, record.owner, record.group, record.mode};
        hash_bytes(&context, values, sizeof(values));
        if (S_ISREG(info->st_mode)) {
            char digest[65]; struct stat now;
            if (file_hash(entry->fts_path, digest) || lstat(entry->fts_path, &now)) { error = errno; break; }
            struct envara_gui_file_identity actual = identity(&now);
            if (!identical(&record, &actual)) { error = ESTALE; break; }
            hash_bytes(&context, digest, 64);
            hash_bytes(&contents, digest, 64);
        } else if (S_ISLNK(info->st_mode)) {
            char target[PATH_MAX], resolved[PATH_MAX];
            ssize_t length = readlink(entry->fts_path, target, sizeof(target) - 1);
            if (length <= 0 || length >= (ssize_t)sizeof(target) - 1 ||
                !realpath(entry->fts_path, resolved) || !inside(bundle, resolved)) { error = EACCES; break; }
            target[length] = 0;
            hash_bytes(&context, target, (size_t)length + 1);
            hash_bytes(&contents, target, (size_t)length + 1);
        }
        errno = 0;
    }
    if (!error && errno) error = errno;
    if (fts_close(tree) && !error) error = errno;
    if (error) return denied(error);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(digest, &context);
    hex(digest, sizeof(digest), out);
    CC_SHA256_Final(digest, &contents); hex(digest, sizeof(digest), content_out); return 0;
}
static int copy_string(NSString *value, char *out, size_t capacity) {
    if (![value isKindOfClass:[NSString class]] || ![value length] ||
        ![value getCString:out maxLength:capacity encoding:NSUTF8StringEncoding] || !bounded(out, capacity) ||
        [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] != strlen(out)) return 0;
    return 1;
}
static int sign_info(const char *bundle, struct envara_gui_manifest *out) {
    SecStaticCodeRef code = NULL; CFDictionaryRef information = NULL;
    SecRequirementRef requirement = NULL; CFStringRef description = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)bundle, strlen(bundle), true);
    int error = EACCES;
    if (!url || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, NULL) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) != errSecSuccess ||
        SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &requirement) != errSecSuccess ||
        SecRequirementCopyString(requirement, kSecCSDefaultFlags, &description) != errSecSuccess) goto done;
    CFTypeRef cdhash = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (!cdhash || CFGetTypeID(cdhash) != CFDataGetTypeID() || CFDataGetLength(cdhash) < 20 || CFDataGetLength(cdhash) > 32 ||
        !CFStringGetCString(description, out->requirement, sizeof(out->requirement), kCFStringEncodingUTF8)) goto done;
    hex(CFDataGetBytePtr(cdhash), (size_t)CFDataGetLength(cdhash), out->cdhash); error = 0;
done:
    if (description) CFRelease(description); if (requirement) CFRelease(requirement);
    if (information) CFRelease(information); if (code) CFRelease(code); if (url) CFRelease(url);
    return error ? denied(error) : 0;
}
static int manifest_valid(const struct envara_gui_manifest *manifest) {
    if (!manifest || manifest->schema != ENVARA_GUI_SCHEMA || (manifest->fixture_only != 0 && manifest->fixture_only != 1) ||
        !bounded(manifest->bundle, sizeof(manifest->bundle)) || manifest->bundle[0] != '/' ||
        !bounded(manifest->executable, sizeof(manifest->executable)) || manifest->executable[0] != '/' ||
        !inside(manifest->bundle, manifest->executable) || !bounded(manifest->identifier, sizeof(manifest->identifier)) ||
        !bounded(manifest->bundle_digest, sizeof(manifest->bundle_digest)) || strlen(manifest->bundle_digest) != 64 ||
        !bounded(manifest->content_digest, sizeof(manifest->content_digest)) || strlen(manifest->content_digest) != 64 ||
        !bounded(manifest->executable_digest, sizeof(manifest->executable_digest)) || strlen(manifest->executable_digest) != 64 ||
        !memchr(manifest->cdhash, 0, sizeof(manifest->cdhash)) || !memchr(manifest->requirement, 0, sizeof(manifest->requirement))) return 0;
    for (int i = 0; i < 64; i++) if (!strchr("0123456789abcdef", manifest->bundle_digest[i]) ||
                                     !strchr("0123456789abcdef", manifest->content_digest[i]) ||
                                     !strchr("0123456789abcdef", manifest->executable_digest[i])) return 0;
    if (!manifest->fixture_only && (!bounded(manifest->cdhash, sizeof(manifest->cdhash)) ||
        !bounded(manifest->requirement, sizeof(manifest->requirement)))) return 0;
    return 1;
}
int envara_gui_manifest_inspect(const char *bundle, int fixture, struct envara_gui_manifest *out) {
    @autoreleasepool {
        char canonical[PATH_MAX], plist[PATH_MAX], executable[PATH_MAX], second_digest[65], second_content[65]; struct stat b, e;
        if (!out || (fixture != 0 && fixture != 1) || !bounded(bundle, PATH_MAX) || bundle[0] != '/' ||
            !realpath(bundle, canonical) || strcmp(bundle, canonical) || strlen(bundle) < 5 ||
            strcmp(bundle + strlen(bundle) - 4, ".app") || lstat(bundle, &b) || !S_ISDIR(b.st_mode) ||
            (fixture && (getuid() == 0 || geteuid() != getuid() || b.st_uid != getuid()))) return denied(EINVAL);
        if (snprintf(plist, sizeof(plist), "%s/Contents/Info.plist", bundle) >= (int)sizeof(plist)) return denied(EINVAL);
        int fd = open(plist, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); struct stat p;
        if (fd < 0) return -1;
        if (fstat(fd, &p) || !S_ISREG(p.st_mode) || p.st_size < 1 || p.st_size > 1048576) { close(fd); return denied(EINVAL); }
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)p.st_size];
        size_t offset = 0;
        while (offset < (size_t)p.st_size) {
            ssize_t count = read(fd, (char *)[data mutableBytes] + offset, (size_t)p.st_size - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { close(fd); return denied(EIO); } offset += (size_t)count;
        }
        struct stat plist_after, plist_named;
        if (fstat(fd, &plist_after) || lstat(plist, &plist_named)) { int error = errno; close(fd); return denied(error); }
        struct envara_gui_file_identity plist_identity = identity(&p), read_identity = identity(&plist_after), named_identity = identity(&plist_named);
        close(fd);
        if (!identical(&plist_identity, &read_identity) || !identical(&read_identity, &named_identity)) return denied(ESTALE);
        NSDictionary *info = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
        char name[256]; struct envara_gui_manifest result; memset(&result, 0, sizeof(result));
        if (![info isKindOfClass:[NSDictionary class]] || ![info[@"CFBundlePackageType"] isEqual:@"APPL"] ||
            !copy_string(info[@"CFBundleExecutable"], name, sizeof(name)) || strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..") ||
            !copy_string(info[@"CFBundleIdentifier"], result.identifier, sizeof(result.identifier)) ||
            snprintf(executable, sizeof(executable), "%s/Contents/MacOS/%s", bundle, name) >= (int)sizeof(executable) ||
            !realpath(executable, canonical) || strcmp(executable, canonical) || lstat(executable, &e) ||
            !S_ISREG(e.st_mode) || !(e.st_mode & 0111) || (e.st_mode & (S_ISUID | S_ISGID))) return denied(EINVAL);
        /* Only Mach-O app executables, never a caller-selected script/shell. */
        uint32_t magic = 0; fd = open(executable, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) return -1;
        ssize_t count = read(fd, &magic, sizeof(magic)); close(fd);
        if (count != sizeof(magic) || !(magic == 0xfeedface || magic == 0xcefaedfe || magic == 0xfeedfacf ||
            magic == 0xcffaedfe || magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca)) return denied(ENOEXEC);
        result.schema = ENVARA_GUI_SCHEMA; result.fixture_only = fixture;
        strcpy(result.bundle, bundle); strcpy(result.executable, executable);
        result.bundle_identity = identity(&b); result.executable_identity = identity(&e);
        if (tree_hash(bundle, fixture, result.bundle_digest, result.content_digest) || file_hash(executable, result.executable_digest) ||
            (!fixture && sign_info(bundle, &result)) || tree_hash(bundle, fixture, second_digest, second_content) ||
            strcmp(second_digest, result.bundle_digest) || strcmp(second_content, result.content_digest)) return denied(errno ? errno : ESTALE);
        struct stat after_b, after_e, after_plist;
        if (lstat(bundle, &after_b) || lstat(executable, &after_e) || lstat(plist, &after_plist)) return -1;
        struct envara_gui_file_identity actual_b = identity(&after_b), actual_e = identity(&after_e);
        struct envara_gui_file_identity actual_plist = identity(&after_plist);
        if (!identical(&result.bundle_identity, &actual_b) || !identical(&result.executable_identity, &actual_e) ||
            !identical(&plist_identity, &actual_plist)) return denied(ESTALE);
        *out = result; return 0;
    }
}
int envara_gui_manifest_unchanged(const struct envara_gui_manifest *expected) {
    struct envara_gui_manifest now;
    if (!manifest_valid(expected)) return denied(EINVAL);
    if (
        envara_gui_manifest_inspect(expected->bundle, expected->fixture_only, &now)) return -1;
    if (strcmp(expected->executable, now.executable) || strcmp(expected->identifier, now.identifier) ||
        strcmp(expected->bundle_digest, now.bundle_digest) || strcmp(expected->executable_digest, now.executable_digest) ||
        strcmp(expected->content_digest, now.content_digest) ||
        strcmp(expected->cdhash, now.cdhash) || strcmp(expected->requirement, now.requirement) ||
        !identical(&expected->bundle_identity, &now.bundle_identity) ||
        !identical(&expected->executable_identity, &now.executable_identity)) return denied(ESTALE);
    return 0;
}
static int locale_valid(const char *value) {
    if (!bounded(value, 64)) return 0;
    size_t segment = 0, segments = 0;
    for (const char *p = value;; p++) {
        if (!*p || *p == '-') {
            if (!segment || segment > 8 || (!segments && (segment < 2 || segment > 8))) return 0;
            segments++; segment = 0; if (!*p) return segments <= 8;
        } else { if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (segments && *p >= '0' && *p <= '9'))) return 0; segment++; }
    }
}
int envara_gui_request_validate(const struct envara_gui_manifest *manifest, const struct envara_gui_request *request, int fixture) {
    char canonical[PATH_MAX], zone[PATH_MAX], zone_root[PATH_MAX]; struct stat info; uid_t console_uid;
    if (!manifest_valid(manifest) || !request || request->schema != ENVARA_GUI_SCHEMA ||
        manifest->fixture_only != fixture || (fixture != 0 && fixture != 1) || !uuid(request->lease_id) || !uuid(request->environment_id) ||
        !request->console_uid || !request->realm_gid || !bounded(request->cwd, sizeof(request->cwd)) || request->cwd[0] != '/' ||
        !realpath(request->cwd, canonical) || strcmp(request->cwd, canonical) || lstat(request->cwd, &info) || !S_ISDIR(info.st_mode) ||
        !bounded(request->timezone, sizeof(request->timezone)) || !locale_valid(request->browser_locale)) return denied(EINVAL);
    const char *p = request->timezone;
    for (; *p; p++) if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr("/_+-", *p))) return denied(EINVAL);
    if (request->timezone[0] == '/' || strstr(request->timezone, "//") || strstr(request->timezone, "..") ||
        snprintf(zone, sizeof(zone), "/usr/share/zoneinfo/%s", request->timezone) >= (int)sizeof(zone) ||
        !realpath("/usr/share/zoneinfo", zone_root) || !realpath(zone, canonical) || !inside(zone_root, canonical) ||
        stat(canonical, &info) || !S_ISREG(info.st_mode)) return denied(EINVAL);
    if (fixture) {
        if (getuid() == 0 || geteuid() != getuid() || request->console_uid != getuid() ||
            request->realm_gid != getgid() || getegid() != getgid()) return denied(EACCES);
    } else if (request->realm_gid < ENVARA_REALM_GID_MIN || request->realm_gid > ENVARA_REALM_GID_MAX ||
               envara_console_uid(&console_uid) || request->console_uid != console_uid) return denied(EACCES);
    return 0;
}
/* csops(2) is the kernel code-signing query (xnu bsd/kern/kern_proc.c).
 * CS_OPS_IDENTITY / CS_OPS_TEAMID return an 8-byte header holding the
 * big-endian total length, then the NUL-ended value, and only while the
 * process signature is still valid: its executable file need not exist. */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
/* Tests substitute the original-running path lookup to model a live process
 * whose executable was unlinked; production always uses proc_pidpath. */
#ifdef ENVARA_GUI_PIDPATH
int ENVARA_GUI_PIDPATH(int pid, void *buffer, uint32_t size);
#else
#define ENVARA_GUI_PIDPATH proc_pidpath
#endif
#define ENVARA_CS_OPS_IDENTITY 11
#define ENVARA_CS_OPS_TEAMID 14
static int kernel_signing_value(pid_t pid, unsigned int op, char *out, size_t capacity) {
    unsigned char blob[8 + 1024]; uint32_t length;
    memset(blob, 0, sizeof(blob));
    if (csops(pid, op, blob, sizeof(blob))) return -1;
    memcpy(&length, blob + 4, sizeof(length)); length = ntohl(length);
    size_t value = length > 9 && length <= sizeof(blob) ? strnlen((const char *)blob + 8, length - 8) : 0;
    if (!value || value + 9 != length || value >= capacity) { errno = EPROTO; return -1; }
    memcpy(out, blob + 8, value + 1); return 0;
}
/* A Developer ID designated requirement names its team as
 * certificate leaf[subject.OU]; ad-hoc and platform requirements have none. */
int envara_gui_requirement_team(const char *requirement, char team[11]) {
    static const char key[] = "certificate leaf[subject.OU] = ";
    const char *at = requirement ? strstr(requirement, key) : NULL;
    if (!at) return 0;
    at += sizeof(key) - 1; int quoted = *at == '"'; at += quoted;
    size_t n = 0; while (n < 11 && ((at[n] >= 'A' && at[n] <= 'Z') || (at[n] >= '0' && at[n] <= '9'))) n++;
    if (n != 10 || (quoted && at[n] != '"')) return 0;
    memcpy(team, at, 10); team[10] = 0; return 1;
}
/* A live process without a path, because an updater unlinked its executable,
 * still has its kernel signing identity. Only that decides: the registered
 * identifier, its helpers or its team count as running; another signed program
 * does not; anything unverifiable stays unknown and refuses. Never a name. */
static int unresolved_is_target(pid_t pid, const struct envara_gui_manifest *manifest) {
    char identity[1024], team[64], expected[11];
    if (kernel_signing_value(pid, ENVARA_CS_OPS_IDENTITY, identity, sizeof(identity))) return -1;
    size_t length = strlen(manifest->identifier);
    if (length && (!strcmp(identity, manifest->identifier) || (!strncmp(identity, manifest->identifier, length) && identity[length] == '.'))) return 1;
    if (!envara_gui_requirement_team(manifest->requirement, expected)) return 0;
    if (!kernel_signing_value(pid, ENVARA_CS_OPS_TEAMID, team, sizeof(team))) return !strcmp(team, expected);
    return errno == ENOENT ? 0 : -1;
}
int envara_gui_original_running(const struct envara_gui_manifest *manifest, uid_t uid, pid_t *found) {
    @autoreleasepool {
        if (!manifest_valid(manifest) || !uid || !found) return denied(EINVAL);
        *found = 0;
        NSString *identifier = [NSString stringWithUTF8String:manifest->identifier];
        if (!identifier) return denied(EINVAL);
        /* Conservative: refuse all registered copies with the same bundle ID. */
        NSArray<NSRunningApplication *> *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:identifier];
        for (NSRunningApplication *app in apps) if (![app isTerminated]) { *found = [app processIdentifier]; return 1; }
        int required = proc_listpids(PROC_UID_ONLY, uid, NULL, 0);
        if (required <= 0 || required > 1048576) return denied(EIO);
        size_t capacity = (size_t)required + 1024 * sizeof(pid_t);
        pid_t *pids = calloc(1, capacity); if (!pids) return -1;
        int count = proc_listpids(PROC_UID_ONLY, uid, pids, (int)capacity), result = 0;
        if (count <= 0 || count >= (int)capacity) { free(pids); return denied(EIO); }
        for (size_t i = 0; i < (size_t)count / sizeof(pid_t); i++) {
            if (pids[i] < 2) continue;
            struct envara_identity before, after; char executable[PROC_PIDPATHINFO_MAXSIZE];
            errno = 0;
            if (envara_identity_read(pids[i], &before)) { if (errno == ESRCH) continue; result = -1; break; }
            /* Fixture inventory is self-owned direct children only. This is
             * deliberately narrower than the production UID-wide refusal. */
            if (manifest->fixture_only && before.parent_pid != getpid()) continue;
            if (ENVARA_GUI_PIDPATH(pids[i], executable, sizeof(executable)) <= 0) {
                if (!envara_same_process(&before)) continue;
                int target = unresolved_is_target(pids[i], manifest);
                /* Bind the signing answer to this process, never a reused PID. */
                if (!envara_same_process(&before)) continue;
                if (target < 0) { result = -1; break; }
                if (target) { *found = pids[i]; result = 1; break; }
                continue;
            }
            if (envara_identity_read(pids[i], &after) || !envara_same_process(&before)) {
                if (errno == ESRCH) continue; result = -1; break;
            }
            if (inside(manifest->bundle, executable)) { *found = pids[i]; result = 1; break; }
        }
        free(pids); return result;
    }
}
int envara_gui_session_read(struct envara_gui_session *out) {
    struct auditinfo_addr current;
    if (!out) return denied(EINVAL);
    memset(out, 0, sizeof(*out)); memset(&current, 0, sizeof(current));
    if (envara_console_uid(&out->console_uid) || getaudit_addr(&current, sizeof(current))) return -1;
    out->audit_session = (uint32_t)current.ai_asid; out->audit_flags = (uint32_t)current.ai_flags;
    uint64_t required = AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS | AU_SESSION_FLAG_HAS_CONSOLE_ACCESS | AU_SESSION_FLAG_HAS_AUTHENTICATED;
    out->audit_has_console_graphics = current.ai_auid == out->console_uid && current.ai_asid > 0 &&
        (current.ai_flags & required) == required && !(current.ai_flags & (AU_SESSION_FLAG_IS_INITIAL | AU_SESSION_FLAG_IS_REMOTE));
    SecuritySessionId session = 0; SessionAttributeBits attributes = 0;
    if (SessionGetInfo(callerSecuritySession, &session, &attributes) != errSecSuccess) return denied(EACCES);
    out->security_session = session; out->security_flags = attributes;
    out->security_has_graphics = (attributes & sessionHasGraphicAccess) && !(attributes & sessionIsRoot);
    out->bootstrap_verified = 0; return 0;
}
int envara_gui_acl_free(const char *path) {
    if (!bounded(path, PATH_MAX) || path[0] != '/') return denied(EINVAL);
    char parent[PATH_MAX], canonical[PATH_MAX], held_path[PATH_MAX]; strcpy(parent, path);
    char *separator = strrchr(parent, '/');
    if (!separator) return denied(EINVAL);
    if (separator == parent) parent[1] = 0; else *separator = 0;
    if (!realpath(parent, canonical) || strcmp(parent, canonical)) return denied(EACCES);
    struct stat before, held = {0}, after, named;
    if (lstat(path, &before) || !(S_ISREG(before.st_mode) || S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode))) return denied(EACCES);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | (S_ISLNK(before.st_mode) ? O_SYMLINK : O_NOFOLLOW));
    if (fd < 0) return -1;
    int valid = !fstat(fd, &held) && !fcntl(fd, F_GETPATH, held_path) && !strcmp(path, held_path);
    struct envara_gui_file_identity expected = identity(&before), opened = identity(&held);
    valid = valid && identical(&expected, &opened);
    errno = 0; acl_t acl = valid ? (S_ISLNK(before.st_mode) ? acl_get_link_np(path, ACL_TYPE_EXTENDED) : acl_get_fd_np(fd, ACL_TYPE_EXTENDED)) : NULL;
    if (!acl) valid = valid && errno == ENOENT;
    else {
        if (acl_valid(acl)) valid = 0;
        else {
            acl_entry_t entry; errno = 0;
            /* Darwin returns zero when an entry exists, -1/EINVAL at end. */
            int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
            valid = valid && result == -1 && errno == EINVAL;
        }
        acl_free(acl);
    }
    if (fstat(fd, &after) || lstat(path, &named)) valid = 0;
    else {
        struct envara_gui_file_identity final = identity(&after), current = identity(&named);
        valid = valid && identical(&expected, &final) && identical(&final, &current);
    }
    if (close(fd)) valid = 0;
    return valid ? 0 : denied(EACCES);
}
static int root_object(const char *path, int file) {
    struct stat info;
    if (lstat(path, &info) || info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) ||
        (file ? (!S_ISREG(info.st_mode) || !(info.st_mode & 0111)) : !S_ISDIR(info.st_mode))) return 0;
    return envara_gui_acl_free(path) == 0;
}
static int root_executable_chain(const char *path) {
    char canonical[PATH_MAX], ancestor[PATH_MAX];
    if (!realpath(path, canonical) || strcmp(path, canonical) || !root_object(path, 1)) return 0;
    strcpy(ancestor, path); char *separator;
    while ((separator = strrchr(ancestor, '/')) && separator != ancestor) { *separator = 0; if (!root_object(ancestor, 0)) return 0; }
    return root_object("/", 0);
}
int envara_gui_bootstrap_plan(const struct envara_gui_request *request, const char *pinned_hash, struct envara_gui_bootstrap_plan *out) {
    char canonical[PATH_MAX], digest[65], ancestor[PATH_MAX]; uid_t uid;
    if (!request || !out || request->schema != ENVARA_GUI_SCHEMA || !uuid(request->lease_id) ||
        !bounded(pinned_hash, 65) || strlen(pinned_hash) != 64 || envara_console_uid(&uid) || uid != request->console_uid) return denied(EINVAL);
    for (const char *p = pinned_hash; *p; p++) if (!strchr("0123456789abcdef", *p)) return denied(EINVAL);
    if (!realpath(ENVARA_GUI_NATIVE_PATH, canonical) || strcmp(canonical, ENVARA_GUI_NATIVE_PATH) ||
        !root_object(ENVARA_GUI_NATIVE_PATH, 1) || file_hash(ENVARA_GUI_NATIVE_PATH, digest) || strcmp(digest, pinned_hash)) return denied(EACCES);
    strcpy(ancestor, ENVARA_GUI_NATIVE_PATH);
    char *separator;
    while ((separator = strrchr(ancestor, '/')) && separator != ancestor) { *separator = 0; if (!root_object(ancestor, 0)) return denied(EACCES); }
    if (!root_object("/", 0) || !root_object("/bin/launchctl", 1)) return denied(EACCES);
    memset(out, 0, sizeof(*out)); strcpy(out->executable, "/bin/launchctl");
    snprintf(out->uid_decimal, sizeof(out->uid_decimal), "%u", request->console_uid); strcpy(out->lease_id, request->lease_id);
    strcpy(out->arguments[0], "/bin/launchctl"); strcpy(out->arguments[1], "asuser"); strcpy(out->arguments[2], out->uid_decimal);
    strcpy(out->arguments[3], ENVARA_GUI_NATIVE_PATH); strcpy(out->arguments[4], "gui-launch-lease"); strcpy(out->arguments[5], out->lease_id);
    out->ready = 0; out->activates_system = 0; return 0;
}
int envara_gui_bootstrap_argv(const struct envara_gui_bootstrap_plan *plan, const char *argv[7]) {
    if (!plan || !argv || !bounded(plan->executable, sizeof(plan->executable)) || !bounded(plan->uid_decimal, sizeof(plan->uid_decimal))) return denied(EINVAL);
    for (int i = 0; i < 6; i++) if (!bounded(plan->arguments[i], sizeof(plan->arguments[i]))) return denied(EINVAL);
    for (const char *p = plan->uid_decimal; *p; p++) if (*p < '0' || *p > '9') return denied(EINVAL);
    if (strcmp(plan->executable, "/bin/launchctl") || strcmp(plan->arguments[0], "/bin/launchctl") ||
        strcmp(plan->arguments[1], "asuser") || strcmp(plan->arguments[3], ENVARA_GUI_NATIVE_PATH) ||
        strcmp(plan->arguments[4], "gui-launch-lease") || !uuid(plan->arguments[5]) ||
        !bounded(plan->arguments[2], sizeof(plan->arguments[2])) || strcmp(plan->arguments[2], plan->uid_decimal)) return denied(EINVAL);
    for (int i = 0; i < 6; i++) argv[i] = plan->arguments[i]; argv[6] = NULL; return 0;
}
static int sole_group(const struct envara_child *child, gid_t gid) {
    int names[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, child->identity.pid}; struct kinfo_proc info;
    size_t size = sizeof(info); memset(&info, 0, sizeof(info));
    if (sysctl(names, 4, &info, &size, NULL, 0) || size != sizeof(info) || !envara_same_process(&child->identity)) return 0;
    return info.kp_eproc.e_ucred.cr_ngroups == 1 && info.kp_eproc.e_ucred.cr_groups[0] == gid;
}
void envara_gui_lifecycle_init(struct envara_gui_lifecycle *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out)); out->child.error_fd = -1;
}
const char *envara_gui_precondition_name(enum envara_gui_precondition reason) {
    switch (reason) {
        case ENVARA_GUI_PRECONDITION_NONE: return "NONE";
        case ENVARA_GUI_ROOT_HELPER_REQUIRED: return "ROOT_HELPER_REQUIRED";
        case ENVARA_GUI_SEALED_SNAPSHOT_REQUIRED: return "ROOT_SEALED_SIGNED_SNAPSHOT_REQUIRED";
        case ENVARA_GUI_FIXED_NATIVE_ENTRY_REQUIRED: return "FIXED_ROOT_NATIVE_ENTRY_REQUIRED";
        case ENVARA_GUI_CONSOLE_SESSION_REQUIRED: return "AUTHENTICATED_CONSOLE_GUI_SESSION_REQUIRED";
        case ENVARA_GUI_INVALID_REQUEST: return "INVALID_GUI_REQUEST";
        case ENVARA_GUI_ORIGINAL_IDENTITY_CHANGED: return "ORIGINAL_APP_IDENTITY_CHANGED";
        case ENVARA_GUI_ORIGINAL_ALREADY_RUNNING: return "ORIGINAL_APP_ALREADY_RUNNING";
        case ENVARA_GUI_PROCESS_INVENTORY_UNAVAILABLE: return "PROCESS_INVENTORY_UNAVAILABLE";
        case ENVARA_GUI_PRIVATE_PIPES_REQUIRED: return "OWNED_ANONYMOUS_PIPES_REQUIRED";
        case ENVARA_GUI_COMMITTED_DENY_REQUIRED: return "VERIFIED_COMMITTED_REALM_DENY_REQUIRED";
    }
    return "UNKNOWN_PRECONDITION";
}
static int stage_denied(struct envara_gui_lifecycle *out, enum envara_gui_precondition reason, int error) {
    out->blocked_reason = reason; return denied(error);
}
static int private_pipe(int fd, int writing) {
    if (fd == -1) return 1;
    struct stat info; int flags;
    if (fd < 3 || fstat(fd, &info) || !S_ISFIFO(info.st_mode) || info.st_nlink != 0 || info.st_uid != getuid() ||
        (flags = fcntl(fd, F_GETFL)) < 0) return 0;
    int access = flags & O_ACCMODE;
    return writing ? access == O_WRONLY : access == O_RDONLY;
}
static int sealed_snapshot(const struct envara_gui_manifest *manifest) {
    if (!manifest_valid(manifest) || manifest->fixture_only || !inside(ENVARA_GUI_SEALED_ROOT, manifest->bundle) ||
        !strcmp(manifest->bundle, ENVARA_GUI_SEALED_ROOT)) return 0;
    char ancestors[PATH_MAX]; strcpy(ancestors, manifest->bundle); char *separator;
    do {
        if (!root_object(ancestors, 0)) return 0;
        separator = strrchr(ancestors, '/'); if (!separator || separator == ancestors) break; *separator = 0;
    } while (1);
    if (!root_object("/", 0)) return 0;
    char *roots[] = {(char *)manifest->bundle, NULL}; FTS *tree = fts_open(roots, FTS_PHYSICAL | FTS_NOCHDIR, fts_order);
    if (!tree) return 0;
    FTSENT *entry; int valid = 1; errno = 0;
    while ((entry = fts_read(tree))) {
        if (entry->fts_info == FTS_DP) continue;
        if (!entry->fts_statp || entry->fts_info == FTS_ERR || entry->fts_info == FTS_NS || entry->fts_info == FTS_DNR ||
            entry->fts_statp->st_uid != 0 ||
            (!S_ISLNK(entry->fts_statp->st_mode) && (entry->fts_statp->st_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH))) ||
            (S_ISREG(entry->fts_statp->st_mode) && entry->fts_statp->st_nlink != 1)) { valid = 0; break; }
        if (envara_gui_acl_free(entry->fts_path)) { valid = 0; break; }
        if (S_ISLNK(entry->fts_statp->st_mode)) {
            char resolved[PATH_MAX];
            if (!realpath(entry->fts_path, resolved) || !inside(manifest->bundle, resolved)) { valid = 0; break; }
        }
        errno = 0;
    }
    if (errno) valid = 0;
    if (fts_close(tree)) valid = 0;
    return valid;
}
int envara_gui_sealed_snapshot_validate(const struct envara_gui_manifest *manifest) {
    if (!sealed_snapshot(manifest)) return denied(EACCES);
    return envara_gui_manifest_unchanged(manifest);
}
int envara_gui_stage(const struct envara_gui_manifest *original, const struct envara_gui_manifest *manifest,
                     const struct envara_gui_request *request, int fixture,
                     const struct envara_gui_stage_authority *authority,
                     int input, int output, struct envara_gui_lifecycle *out) {
    if (!out) return denied(EINVAL);
    /* A lifecycle cannot discard an unresolved prior scope after leader exit. */
    if (out->phase != ENVARA_GUI_EMPTY) return denied(EALREADY);
    if (fixture != 0 && fixture != 1) return stage_denied(out, ENVARA_GUI_INVALID_REQUEST, EINVAL);
    if (!fixture && (getuid() != 0 || geteuid() != 0)) return stage_denied(out, ENVARA_GUI_ROOT_HELPER_REQUIRED, EACCES);
    if (!private_pipe(input, 0) || !private_pipe(output, 1) || (!fixture && (input != -1 || output != -1)))
        return stage_denied(out, ENVARA_GUI_PRIVATE_PIPES_REQUIRED, EACCES);
    pid_t running;
    if (envara_gui_request_validate(manifest, request, fixture) || !manifest_valid(original) || original->fixture_only != fixture)
        return stage_denied(out, ENVARA_GUI_INVALID_REQUEST, EINVAL);
    if (strcmp(original->identifier, manifest->identifier) || strcmp(original->content_digest, manifest->content_digest) ||
        strcmp(original->executable_digest, manifest->executable_digest) || strcmp(original->cdhash, manifest->cdhash) ||
        strcmp(original->requirement, manifest->requirement) || envara_gui_manifest_unchanged(original) || envara_gui_manifest_unchanged(manifest))
        return stage_denied(out, ENVARA_GUI_ORIGINAL_IDENTITY_CHANGED, ESTALE);
    struct envara_gui_session session; memset(&session, 0, sizeof(session));
    if (!fixture) {
        if (envara_gui_sealed_snapshot_validate(manifest)) return stage_denied(out, ENVARA_GUI_SEALED_SNAPSHOT_REQUIRED, EACCES);
        char executing[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(getpid(), executing, sizeof(executing)) <= 0 || strcmp(executing, ENVARA_GUI_NATIVE_PATH) ||
            !root_executable_chain(executing)) return stage_denied(out, ENVARA_GUI_FIXED_NATIVE_ENTRY_REQUIRED, EACCES);
        if (!request->gui_audit_session || envara_gui_session_read(&session) || session.console_uid != request->console_uid ||
            session.audit_session != request->gui_audit_session || !session.audit_has_console_graphics || !session.security_has_graphics)
            return stage_denied(out, ENVARA_GUI_CONSOLE_SESSION_REQUIRED, EACCES);
    }
    int scan = envara_gui_original_running(original, request->console_uid, &running);
    if (scan == 0 && strcmp(original->bundle, manifest->bundle)) scan = envara_gui_original_running(manifest, request->console_uid, &running);
    if (scan != 0) return stage_denied(out, scan > 0 ? ENVARA_GUI_ORIGINAL_ALREADY_RUNNING : ENVARA_GUI_PROCESS_INVENTORY_UNAVAILABLE,
                                     scan > 0 ? EALREADY : EACCES);
    struct passwd *account = getpwuid(request->console_uid);
    if (!account || !account->pw_name || !account->pw_dir) return denied(EACCES);
    char home[PATH_MAX + 6], user[256], login[256], timezone[132], browser_locale[96];
    if (snprintf(home, sizeof(home), "HOME=%s", account->pw_dir) >= (int)sizeof(home) ||
        snprintf(user, sizeof(user), "USER=%s", account->pw_name) >= (int)sizeof(user) ||
        snprintf(login, sizeof(login), "LOGNAME=%s", account->pw_name) >= (int)sizeof(login)) return denied(EINVAL);
    snprintf(timezone, sizeof(timezone), "TZ=%s", request->timezone);
    snprintf(browser_locale, sizeof(browser_locale), "ENVARA_BROWSER_LOCALE=%s", request->browser_locale);
    /* Generic apps may ignore this locale hint; no claim of browser-locale control. */
    char *environment[] = {home, user, login, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", timezone, browser_locale, NULL};
    char *argv[] = {(char *)manifest->executable, NULL};
    /* Console UID can continue its own stopped process. Live deny ownership
     * must therefore precede fork/credential transition, never wait for resume. */
    if (!fixture && (!authority || !authority->verify_committed_deny || authority->verify_committed_deny(request, authority->context) != 0))
        return stage_denied(out, ENVARA_GUI_COMMITTED_DENY_REQUIRED, EAGAIN);
    envara_gui_lifecycle_init(out);
    if (envara_spawn_suspended_io(request->console_uid, request->realm_gid, request->cwd,
                                  manifest->executable, argv, environment, fixture, input, output, &out->child)) return -1;
    out->fixture_only = fixture; out->original = *original; out->manifest = *manifest; out->request = *request; out->session = session;
    out->phase = ENVARA_GUI_SUSPENDED;
    /* Production integration additionally verifies actual sole supplementary GID.
     * Fixtures deliberately retain the caller's ordinary groups, as native.h says. */
    if ((!fixture && !sole_group(&out->child, request->realm_gid)) || envara_gui_manifest_unchanged(original) || envara_gui_manifest_unchanged(manifest)) {
        envara_gui_cancel(out); return denied(ESTALE);
    }
    return 0;
}
static int executable_matches(struct envara_gui_lifecycle *lifecycle) {
    char path[PROC_PIDPATHINFO_MAXSIZE]; struct stat info;
    if (!envara_same_process(&lifecycle->child.identity) || proc_pidpath(lifecycle->child.identity.pid, path, sizeof(path)) <= 0 ||
        strcmp(path, lifecycle->manifest.executable) || lstat(path, &info)) return 0;
    struct envara_gui_file_identity actual = identity(&info);
    return identical(&actual, &lifecycle->manifest.executable_identity) && envara_same_process(&lifecycle->child.identity);
}
int envara_gui_resume_fixture(struct envara_gui_lifecycle *lifecycle, unsigned timeout_ms) {
    if (!lifecycle || !lifecycle->fixture_only || getuid() == 0 || lifecycle->phase != ENVARA_GUI_SUSPENDED ||
        !timeout_ms || timeout_ms > 5000) return denied(EINVAL);
    if (envara_gui_request_validate(&lifecycle->manifest, &lifecycle->request, 1) ||
        envara_gui_manifest_unchanged(&lifecycle->original) || envara_gui_manifest_unchanged(&lifecycle->manifest)) {
        envara_gui_cancel(lifecycle); return denied(ESTALE);
    }
    pid_t running;
    int scan = envara_gui_original_running(&lifecycle->original, lifecycle->request.console_uid, &running);
    if (scan == 0 && strcmp(lifecycle->original.bundle, lifecycle->manifest.bundle))
        scan = envara_gui_original_running(&lifecycle->manifest, lifecycle->request.console_uid, &running);
    if (scan != 0 ||
        !envara_same_process(&lifecycle->child.identity) || envara_child_resume(&lifecycle->child)) {
        envara_gui_cancel(lifecycle); return denied(EACCES);
    }
    struct pollfd descriptor = {lifecycle->child.error_fd, POLLIN | POLLHUP, 0}; int result;
    struct timespec now; if (clock_gettime(CLOCK_MONOTONIC, &now)) { envara_gui_cancel(lifecycle); return -1; }
    uint64_t deadline = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 + timeout_ms;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) { result = -1; break; }
        uint64_t current = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
        if (current >= deadline) { result = 0; break; }
        result = poll(&descriptor, 1, (int)(deadline - current));
        if (result >= 0 || errno != EINTR) break;
    }
    if (result <= 0) { envara_gui_cancel(lifecycle); return denied(result == 0 ? ETIMEDOUT : EIO); }
    int exec_error = 0; ssize_t count = read(lifecycle->child.error_fd, &exec_error, sizeof(exec_error));
    if (count != 0 || !executable_matches(lifecycle)) {
        envara_gui_cancel(lifecycle); return denied(count == sizeof(exec_error) && exec_error ? exec_error : ESTALE);
    }
    close(lifecycle->child.error_fd); lifecycle->child.error_fd = -1;
    lifecycle->phase = ENVARA_GUI_EXECUTING; lifecycle->protected_ready = 0; return 0;
}
int envara_gui_poll(struct envara_gui_lifecycle *lifecycle, int *status) {
    if (!lifecycle || !status || lifecycle->phase == ENVARA_GUI_EMPTY) return denied(EINVAL);
    if (lifecycle->leader_reaped) { *status = lifecycle->wait_status; return 1; }
    pid_t result;
    do { result = waitpid(lifecycle->child.identity.pid, status, WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == 0) return 0;
    if (result != lifecycle->child.identity.pid) { lifecycle->phase = ENVARA_GUI_UNCERTAIN; return -1; }
    lifecycle->leader_reaped = 1; lifecycle->scope_quiescent = 0;
    lifecycle->wait_status = *status;
    if (lifecycle->phase != ENVARA_GUI_CANCELLED) lifecycle->phase = ENVARA_GUI_EXITED;
    if (lifecycle->child.error_fd >= 0) { close(lifecycle->child.error_fd); lifecycle->child.error_fd = -1; }
    return 1;
}
int envara_gui_cancel(struct envara_gui_lifecycle *lifecycle) {
    if (!lifecycle || lifecycle->phase == ENVARA_GUI_EMPTY) return denied(EINVAL);
    if (lifecycle->leader_reaped) return 0;
    int status = 0, polled = envara_gui_poll(lifecycle, &status);
    if (polled != 0) return polled < 0 ? -1 : 0;
    if (!envara_same_process(&lifecycle->child.identity) || envara_child_cancel(&lifecycle->child)) {
        lifecycle->phase = ENVARA_GUI_UNCERTAIN; return denied(ESRCH);
    }
    lifecycle->phase = ENVARA_GUI_CANCELLED; lifecycle->scope_quiescent = 0;
    for (int i = 0; i < 200; i++) {
        int result = envara_gui_poll(lifecycle, &status); if (result != 0) return result < 0 ? -1 : 0;
        usleep(10000);
    }
    lifecycle->phase = ENVARA_GUI_UNCERTAIN; return denied(ETIMEDOUT);
}
