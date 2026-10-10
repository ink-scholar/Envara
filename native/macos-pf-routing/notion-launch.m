#import <Foundation/Foundation.h>
#include "notion-launch.h"
#include <Security/Security.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <libproc.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>

static int reject(int error) { errno = error; return -1; }
static int uuid(const char *s) {
    if (!s || !memchr(s, 0, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0; return 1;
}
/* DNS-SD IPC paths are defined by Apple's dnssd_ipc.h and its installed
 * mDNSResponder.sb. com.apple.dnssd.service is the actual resolver XPC name.
 * This is process-local denial, inherited by ordinary descendants. It cannot
 * constrain an already existing broker or prove every future macOS DNS API. */
static const char dns_profile[] =
    "(version 1)(allow default)"
    "(deny mach-lookup (global-name \"com.apple.dnssd.service\"))"
    "(deny file-read* file-write* (literal \"/private/var/run/mDNSResponder\")"
    " (literal \"/var/run/mDNSResponder\") (literal \"/private/var/tmp/mDNSResponder\") (literal \"/var/tmp/mDNSResponder\"))"
    "(deny network-outbound (remote unix-socket (literal \"/private/var/run/mDNSResponder\"))"
    " (remote unix-socket (literal \"/var/run/mDNSResponder\")) (remote unix-socket (literal \"/private/var/tmp/mDNSResponder\"))"
    " (remote unix-socket (literal \"/var/tmp/mDNSResponder\")))"
    "(deny network-outbound (remote tcp \"*:53\") (remote udp \"*:53\")"
    " (remote tcp \"*:853\") (remote udp \"*:853\") (remote udp \"*:5353\"))";
const char *envara_notion_dns_profile(void) { return dns_profile; }
int envara_notion_scoped_profile(uint16_t port, char *out, size_t capacity) {
    if (!out || !capacity || port < 1024) return reject(EINVAL);
    int n = snprintf(out, capacity, "%s(deny network-outbound)"
        "(allow network-outbound (remote tcp4 \"localhost:%u\"))", dns_profile, port);
    if (n < 0 || (size_t)n >= capacity) { out[0] = 0; return reject(EOVERFLOW); }
    return 0;
}

static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static NSString *plist_string(const char *bundle, NSString *relative, NSString *key) {
    NSString *base = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:bundle length:strlen(bundle)];
    const char *path = [[base stringByAppendingPathComponent:relative] fileSystemRepresentation];
    char canonical[PATH_MAX], held[PATH_MAX]; struct stat before, after, named;
    size_t prefix = strlen(bundle);
    if (!path || !realpath(path, canonical) || strncmp(canonical, bundle, prefix) || canonical[prefix] != '/') return nil;
    int fd = open(canonical, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); if (fd < 0) return nil;
    int valid = !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size > 0 && before.st_size <= 1024 * 1024 &&
        !fcntl(fd, F_GETPATH, held) && !strcmp(held, canonical) && !envara_gui_acl_free(canonical);
    NSMutableData *bytes = valid ? [NSMutableData dataWithLength:(NSUInteger)before.st_size] : nil;
    size_t offset = 0;
    while (valid && offset < [bytes length]) {
        ssize_t n = read(fd, (char *)[bytes mutableBytes] + offset, [bytes length] - offset);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { valid = 0; break; } offset += (size_t)n;
    }
    valid = valid && !fstat(fd, &after) && !lstat(canonical, &named) && same_file(&before, &after) && same_file(&after, &named) &&
        !fcntl(fd, F_GETPATH, held) && !strcmp(held, canonical);
    close(fd); if (!valid) return nil;
    id info = [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:NULL error:NULL];
    id value = [info isKindOfClass:[NSDictionary class]] ? info[key] : nil;
    return [value isKindOfClass:[NSString class]] && ![value containsString:@"\0"] ? value : nil;
}
static int supported_versions(NSString *version, NSString *electron) {
    return ([version isEqualToString:@ENVARA_NOTION_SUPPORTED_VERSION] ||
            [version isEqualToString:@ENVARA_NOTION_SUPPORTED_VERSION_ADDITIONAL]) &&
        [electron isEqualToString:@ENVARA_NOTION_ELECTRON_VERSION];
}
int envara_notion_supported(const struct envara_gui_manifest *manifest) {
    if (!manifest || manifest->schema != ENVARA_GUI_SCHEMA || manifest->fixture_only ||
        !memchr(manifest->bundle, 0, sizeof(manifest->bundle)) || !memchr(manifest->identifier, 0, sizeof(manifest->identifier)) ||
        strcmp(manifest->identifier, "notion.id") || envara_gui_manifest_unchanged(manifest)) return reject(EACCES);
    int valid = 0;
    @autoreleasepool {
        NSString *version = plist_string(manifest->bundle, @"Contents/Info.plist", @"CFBundleShortVersionString");
        NSString *executable = plist_string(manifest->bundle, @"Contents/Info.plist", @"CFBundleExecutable");
        NSString *electron = plist_string(manifest->bundle,
            @"Contents/Frameworks/Electron Framework.framework/Resources/Info.plist", @"CFBundleVersion");
        if (!supported_versions(version, electron) ||
            ![executable isEqualToString:@"Notion"]) return reject(ENOTSUP);
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)manifest->bundle, (CFIndex)strlen(manifest->bundle), true);
        SecStaticCodeRef code = NULL; SecRequirementRef requirement = NULL;
        OSStatus status = url ? SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) : errSecParam;
        if (!status) status = SecRequirementCreateWithString(CFSTR("anchor apple generic and identifier \"notion.id\" and certificate leaf[subject.OU] = \"LBQJ96FQ8D\""), kSecCSDefaultFlags, &requirement);
        if (!status) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures, requirement);
        valid = status == errSecSuccess;
        if (requirement) CFRelease(requirement); if (code) CFRelease(code); if (url) CFRelease(url);
    }
    return valid && !envara_gui_manifest_unchanged(manifest) ? 0 : reject(EACCES);
}
static int data_open(const char *path, uid_t console, struct stat *identity) {
    char canonical[PATH_MAX], ancestors[PATH_MAX]; struct stat info;
    if (!realpath(path, canonical) || strcmp(path, canonical)) return reject(EACCES);
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, identity) || !S_ISDIR(identity->st_mode) || identity->st_uid != console ||
        (identity->st_mode & 07777) != 0700 || envara_gui_acl_free(path)) goto refuse;
    strcpy(ancestors, path); char *slash = strrchr(ancestors, '/'); if (!slash) goto refuse; *slash = 0;
    for (;;) {
        if (lstat(ancestors, &info) || !S_ISDIR(info.st_mode) || info.st_uid ||
            (info.st_mode & (S_ISUID | S_ISGID | 0022)) || envara_gui_acl_free(ancestors)) goto refuse;
        slash = strrchr(ancestors, '/'); if (!slash || slash == ancestors) break; *slash = 0;
    }
    if (envara_gui_acl_free("/") || lstat(path, &info) || info.st_dev != identity->st_dev || info.st_ino != identity->st_ino ||
        info.st_uid != identity->st_uid || info.st_mode != identity->st_mode) goto refuse;
    return fd;
refuse: close(fd); return reject(EACCES);
}
static int sole_group(const struct envara_child *child, gid_t gid) {
    int names[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, child->identity.pid}; struct kinfo_proc info;
    size_t size = sizeof(info); memset(&info, 0, sizeof(info));
    return !sysctl(names, 4, &info, &size, NULL, 0) && size == sizeof(info) && envara_same_process(&child->identity) &&
        info.kp_eproc.e_ucred.cr_ngroups == 1 && info.kp_eproc.e_ucred.cr_groups[0] == gid;
}
static int root_chain(const char *path) {
    char canonical[PATH_MAX], parent[PATH_MAX]; struct stat info;
    if (!realpath(path, canonical) || strcmp(path, canonical)) return 0;
    strcpy(parent, path);
    for (;;) {
        if (lstat(parent, &info) || info.st_uid || (info.st_mode & (S_ISUID | S_ISGID | 0022)) || envara_gui_acl_free(parent) ||
            (!strcmp(parent, path) ? (!S_ISREG(info.st_mode) || info.st_nlink != 1 || !(info.st_mode & 0111)) : !S_ISDIR(info.st_mode))) return 0;
        char *slash = strrchr(parent, '/'); if (!slash || slash == parent) break; *slash = 0;
    }
    return envara_gui_acl_free("/") == 0;
}
static int bounded_children(int fd, unsigned *out) {
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (copy < 0) return -1;
    DIR *directory = fdopendir(copy); if (!directory) { close(copy); return -1; }
    unsigned count = 0; struct dirent *entry; int error = 0;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++count > 64) { error = ENOSPC; break; }
    }
    if (!error) error = errno; closedir(directory); *out = count; return error ? reject(error) : 0;
}
static int data_child(int parent, const char *name, uid_t uid, gid_t gid, int leaf, int bounded) {
    int created = 0;
    unsigned count = 0; struct stat existing;
    if (bounded && bounded_children(parent, &count)) return -1;
    if (count >= 64 && fstatat(parent, name, &existing, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) return reject(ENOSPC);
    if (!mkdirat(parent, name, leaf ? 0700 : 0755)) created = 1;
    else if (errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat held, named; char path[PATH_MAX];
    if (created && ((leaf && fchown(fd, uid, gid)) || fchmod(fd, leaf ? 0700 : 0755))) goto refuse;
    if (fstat(fd, &held) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino || !S_ISDIR(held.st_mode) ||
        held.st_uid != (leaf ? uid : 0) || (held.st_mode & 07777) != (leaf ? 0700 : 0755) ||
        fcntl(fd, F_GETPATH, path) || envara_gui_acl_free(path) || (created && (fsync(fd) || fsync(parent)))) goto refuse;
    return fd;
refuse:
    { int error = errno ? errno : EACCES; close(fd); return reject(error); }
}
int envara_notion_data_prepare(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority) {
    char executing[PROC_PIDPATHINFO_MAXSIZE];
    if (getuid() || geteuid() || !app || !request || !context || !authority || !authority->verify_committed_deny ||
        !uuid(app->registration_id) || !uuid(request->environment_id) || strcmp(context->registration_id, app->registration_id) ||
        proc_pidpath(getpid(), executing, sizeof(executing)) <= 0 || strcmp(executing, ENVARA_GUI_NATIVE_PATH) || !root_chain(executing) ||
        envara_gui_request_validate(&app->snapshot, request, 0) || envara_gui_sealed_snapshot_validate(&app->snapshot) ||
        envara_notion_supported(&app->original) || envara_notion_supported(&app->snapshot) ||
        strcmp(app->original.content_digest, app->snapshot.content_digest) || strcmp(app->original.cdhash, app->snapshot.cdhash) ||
        authority->verify_committed_deny(request, authority->context)) return reject(EACCES);
    const char *parent_path = "/Library/PrivilegedHelperTools";
    struct stat held, named; char canonical[PATH_MAX];
    if (!realpath(parent_path, canonical) || strcmp(parent_path, canonical)) return reject(EACCES);
    int fd = open(parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &held) || lstat(parent_path, &named) || held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        held.st_uid || (held.st_mode & 0022) || envara_gui_acl_free(parent_path) || envara_gui_acl_free("/Library") || envara_gui_acl_free("/")) {
        int error = errno ? errno : EACCES; close(fd); return reject(error);
    }
    const char *parts[] = {"io.envara.pf-app-data", request->environment_id, app->registration_id, "UserData"};
    for (int i = 0; i < 4; i++) {
        int child = data_child(fd, parts[i], request->console_uid, request->realm_gid, i == 3, i > 0);
        int error = errno; close(fd); if (child < 0) return reject(error); fd = child;
    }
    char path[PATH_MAX]; int result = fcntl(fd, F_GETPATH, path); close(fd);
    if (result) return -1;
    struct stat identity; fd = data_open(path, request->console_uid, &identity);
    if (fd < 0) return -1; close(fd);
    return authority->verify_committed_deny(request, authority->context);
}
int envara_notion_plan(const struct envara_app_registration *app, const struct envara_gui_request *request,
                      const struct envara_notion_context *context, struct envara_notion_plan *out) {
    if (!out) return reject(EINVAL); memset(out, 0, sizeof(*out));
    if (!app || !request || !context || app->schema != ENVARA_APP_REGISTRY_SCHEMA || app->fixture_only || app->ready || app->protected_ready ||
        !uuid(app->registration_id) || !uuid(app->version_id) || !uuid(context->registration_id) || strcmp(context->registration_id, app->registration_id) ||
        context->front_port < 1024 || envara_gui_request_validate(&app->snapshot, request, 0) ||
        envara_gui_sealed_snapshot_validate(&app->snapshot) || envara_notion_supported(&app->original) || envara_notion_supported(&app->snapshot) ||
        strcmp(app->original.content_digest, app->snapshot.content_digest) || strcmp(app->original.cdhash, app->snapshot.cdhash) ||
        strcmp(app->original.requirement, app->snapshot.requirement)) return reject(EACCES);
    if (snprintf(out->user_data, sizeof(out->user_data), "%s/%s/%s/UserData", ENVARA_NOTION_DATA_ROOT,
        request->environment_id, app->registration_id) >= (int)sizeof(out->user_data)) return reject(EOVERFLOW);
    struct stat data; int fd = data_open(out->user_data, request->console_uid, &data); if (fd < 0) return -1; close(fd);
    strcpy(out->arguments[0], "/usr/bin/sandbox-exec"); strcpy(out->arguments[1], "-p");
    if (envara_notion_scoped_profile(context->front_port, out->arguments[2], sizeof(out->arguments[2]))) return -1;
    strcpy(out->arguments[3], app->snapshot.executable);
    snprintf(out->arguments[4], sizeof(out->arguments[4]), "--proxy-server=socks5://127.0.0.1:%u", context->front_port);
    strcpy(out->arguments[5], "--proxy-bypass-list=<-loopback>");
    strcpy(out->arguments[6], "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1");
    if (snprintf(out->arguments[7], sizeof(out->arguments[7]), "--user-data-dir=%s", out->user_data) >= (int)sizeof(out->arguments[7]) ||
        snprintf(out->arguments[8], sizeof(out->arguments[8]), "--lang=%s", request->browser_locale) >= (int)sizeof(out->arguments[8])) return reject(EOVERFLOW);
    return 0;
}
static int finish_stopped_stage(const struct envara_app_registration *app, const struct envara_gui_request *request,
                               const char *user_data, int data_fd, struct envara_gui_lifecycle *out) {
    struct stat before, after;
    int result = !sole_group(&out->child, request->realm_gid) || lstat(user_data, &after) || fstat(data_fd, &before) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_uid != request->console_uid || (before.st_mode & 07777) != 0700 || envara_gui_acl_free(user_data) ||
        envara_gui_manifest_unchanged(&app->original) || envara_gui_manifest_unchanged(&app->snapshot);
    close(data_fd);
    /* The supervisor must first independently establish direct-child custody.
     * Pre-reaping here would leave a spent PID that cannot pass that check.
     * Preserve the real stopped child/error reader on every post-fork refusal;
     * its supervisor performs exact cancel/reap plus deny/scope recovery. */
    if (result) return reject(ESTALE);
    return 0;
}
int envara_notion_stage(const struct envara_app_registration *app, const struct envara_gui_request *request,
                       const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority,
                       struct envara_gui_lifecycle *out) {
    if (!out || out->phase != ENVARA_GUI_EMPTY) return reject(EALREADY);
    if (getuid() || geteuid() || !authority || !authority->verify_committed_deny) return reject(EACCES);
    char executing[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), executing, sizeof(executing)) <= 0 || strcmp(executing, ENVARA_GUI_NATIVE_PATH) ||
        !root_chain(executing) || !root_chain("/usr/bin/sandbox-exec")) return reject(EACCES);
    struct envara_notion_plan plan; if (envara_notion_plan(app, request, context, &plan)) return -1;
    struct envara_gui_session session;
    if (!request->gui_audit_session || envara_gui_session_read(&session) || session.console_uid != request->console_uid ||
        session.audit_session != request->gui_audit_session || !session.audit_has_console_graphics || !session.security_has_graphics) return reject(EACCES);
    pid_t running; int scan = envara_gui_original_running(&app->original, request->console_uid, &running);
    if (scan == 0) scan = envara_gui_original_running(&app->snapshot, request->console_uid, &running);
    if (scan) return reject(scan > 0 ? EALREADY : EACCES);
    struct passwd *account = getpwuid(request->console_uid);
    if (!account || !account->pw_name || !account->pw_dir) return reject(EACCES);
    char home[PATH_MAX + 6], user[256], login[256], timezone[132], locale[96];
    if (snprintf(home, sizeof(home), "HOME=%s", account->pw_dir) >= (int)sizeof(home) ||
        snprintf(user, sizeof(user), "USER=%s", account->pw_name) >= (int)sizeof(user) ||
        snprintf(login, sizeof(login), "LOGNAME=%s", account->pw_name) >= (int)sizeof(login)) return reject(EINVAL);
    snprintf(timezone, sizeof(timezone), "TZ=%s", request->timezone); snprintf(locale, sizeof(locale), "ENVARA_BROWSER_LOCALE=%s", request->browser_locale);
    char *environment[] = {home, user, login, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", timezone, locale, NULL};
    char *arguments[10]; for (int i = 0; i < 9; i++) arguments[i] = plan.arguments[i]; arguments[9] = NULL;
    struct stat before; int data_fd = data_open(plan.user_data, request->console_uid, &before); if (data_fd < 0) return -1;
    if (envara_gui_manifest_unchanged(&app->original) || envara_gui_manifest_unchanged(&app->snapshot) ||
        authority->verify_committed_deny(request, authority->context)) { close(data_fd); return reject(EAGAIN); }
    envara_gui_lifecycle_init(out);
    int result = envara_spawn_suspended_io(request->console_uid, request->realm_gid, request->cwd,
        "/usr/bin/sandbox-exec", arguments, environment, 0, -1, -1, &out->child);
    if (result) { int error = errno; close(data_fd); return reject(error); }
    out->phase = ENVARA_GUI_SUSPENDED; out->request = *request; out->original = app->original; out->manifest = app->snapshot; out->session = session;
    if (finish_stopped_stage(app, request, plan.user_data, data_fd, out)) return -1;
    return 0; /* Stopped, no sandbox/flag/native traffic acceptance claim. */
}
