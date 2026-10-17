#import <Foundation/Foundation.h>
#include "notion-launch.h"
#include "app-keychain.h"
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
#include <locale.h>
#include <xlocale.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <libkern/OSByteOrder.h>

/* Fixed diagnostic sub-operation. Thread-local so a refused call in one worker
 * cannot be attributed to another; reset per instrumented invocation. First
 * write wins, mirroring the outer native-failure latch: a later secondary
 * cleanup error must never replace the sub-operation that actually refused. */
static _Thread_local EnvaraNotionSuboperation notion_suboperation = ENVARA_NOTION_SUBOP_NONE;
void envara_notion_suboperation_begin(void) { notion_suboperation = ENVARA_NOTION_SUBOP_NONE; }
void envara_notion_suboperation_set(EnvaraNotionSuboperation sub) {
    if (notion_suboperation == ENVARA_NOTION_SUBOP_NONE && sub != ENVARA_NOTION_SUBOP_NONE) notion_suboperation = sub;
}
EnvaraNotionSuboperation envara_notion_suboperation(void) { return notion_suboperation; }
const char *envara_notion_suboperation_name(EnvaraNotionSuboperation sub) {
    switch (sub) {
        case ENVARA_NOTION_SUBOP_SUPPORTED_ARGUMENT: return "SUPPORTED_ARGUMENT";
        case ENVARA_NOTION_SUBOP_SUPPORTED_PLIST: return "SUPPORTED_PLIST";
        case ENVARA_NOTION_SUBOP_SUPPORTED_VERSION: return "SUPPORTED_VERSION";
        case ENVARA_NOTION_SUBOP_SUPPORTED_SIGNATURE: return "SUPPORTED_SIGNATURE";
        case ENVARA_NOTION_SUBOP_PLAN_ARGUMENT: return "PLAN_ARGUMENT";
        case ENVARA_NOTION_SUBOP_PLAN_REGISTRY: return "PLAN_REGISTRY";
        case ENVARA_NOTION_SUBOP_PLAN_CONTEXT: return "PLAN_CONTEXT";
        case ENVARA_NOTION_SUBOP_PLAN_REQUEST: return "PLAN_REQUEST";
        case ENVARA_NOTION_SUBOP_PLAN_SEALED: return "PLAN_SEALED";
        case ENVARA_NOTION_SUBOP_PLAN_SUPPORTED: return "PLAN_SUPPORTED";
        case ENVARA_NOTION_SUBOP_PLAN_DIGEST: return "PLAN_DIGEST";
        case ENVARA_NOTION_SUBOP_PLAN_CDHASH: return "PLAN_CDHASH";
        case ENVARA_NOTION_SUBOP_PLAN_REQUIREMENT: return "PLAN_REQUIREMENT";
        case ENVARA_NOTION_SUBOP_PLAN_DATA: return "PLAN_DATA";
        case ENVARA_NOTION_SUBOP_PLAN_ALLOCATION: return "PLAN_ALLOCATION";
        case ENVARA_NOTION_SUBOP_DATA_ARGUMENT: return "DATA_ARGUMENT";
        case ENVARA_NOTION_SUBOP_DATA_ENTRY: return "DATA_ENTRY";
        case ENVARA_NOTION_SUBOP_DATA_ANCESTOR: return "DATA_ANCESTOR";
        case ENVARA_NOTION_SUBOP_DATA_LEAF: return "DATA_LEAF";
        case ENVARA_NOTION_SUBOP_DATA_DENY: return "DATA_DENY";
        case ENVARA_NOTION_SUBOP_STAGE_ARGUMENT: return "STAGE_ARGUMENT";
        case ENVARA_NOTION_SUBOP_STAGE_AUTHORITY: return "STAGE_AUTHORITY";
        case ENVARA_NOTION_SUBOP_STAGE_ENTRY: return "STAGE_ENTRY";
        case ENVARA_NOTION_SUBOP_STAGE_SESSION: return "STAGE_SESSION";
        case ENVARA_NOTION_SUBOP_STAGE_ORIGINAL_RUNNING: return "STAGE_ORIGINAL_RUNNING";
        case ENVARA_NOTION_SUBOP_STAGE_ACCOUNT: return "STAGE_ACCOUNT";
        case ENVARA_NOTION_SUBOP_STAGE_ENVIRONMENT: return "STAGE_ENVIRONMENT";
        case ENVARA_NOTION_SUBOP_STAGE_DATA: return "STAGE_DATA";
        case ENVARA_NOTION_SUBOP_STAGE_KEYCHAIN: return "STAGE_KEYCHAIN";
        case ENVARA_NOTION_SUBOP_STAGE_RECHECK: return "STAGE_RECHECK";
        case ENVARA_NOTION_SUBOP_STAGE_SPAWN: return "STAGE_SPAWN";
        case ENVARA_NOTION_SUBOP_STAGE_STOPPED: return "STAGE_STOPPED";
        default: return "NONE";
    }
}
/* Attach the exact sub-operation to a refusal without disturbing its errno. */
static int reject_at(int error, EnvaraNotionSuboperation sub) {
    envara_notion_suboperation_set(sub);
    errno = error; return -1;
}
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
    "(deny mach-lookup (global-name \"com.apple.dnssd.service\")"
    " (global-name \"com.apple.nsurlsessiond\") (global-name \"com.apple.nsurlsessiond-launchondemand\"))"
    "(deny file-read* file-write* (literal \"/private/var/run/mDNSResponder\")"
    " (literal \"/var/run/mDNSResponder\") (literal \"/private/var/tmp/mDNSResponder\") (literal \"/var/tmp/mDNSResponder\"))"
    "(deny network-outbound (remote unix-socket (literal \"/private/var/run/mDNSResponder\"))"
    " (remote unix-socket (literal \"/var/run/mDNSResponder\")) (remote unix-socket (literal \"/private/var/tmp/mDNSResponder\"))"
    " (remote unix-socket (literal \"/var/tmp/mDNSResponder\")))"
    "(deny network-outbound (remote tcp \"*:53\") (remote udp \"*:53\")"
    " (remote tcp \"*:853\") (remote udp \"*:853\") (remote udp \"*:5353\"))";
const char *envara_notion_dns_profile(void) { return dns_profile; }
/* ENVARA_NOTION_DATA_ROOT/<environment>/<registration>, exactly. */
static int socket_root_valid(const char *root) {
    size_t prefix = strlen(ENVARA_NOTION_DATA_ROOT); char environment[37], registration[37];
    if (strncmp(root, ENVARA_NOTION_DATA_ROOT "/", prefix + 1) || strlen(root) != prefix + 74 || root[prefix + 37] != '/') return 0;
    memcpy(environment, root + prefix + 1, 36); environment[36] = 0;
    memcpy(registration, root + prefix + 38, 36); registration[36] = 0;
    return uuid(environment) && uuid(registration);
}
/* An application's own local sockets (VS Code's single-instance socket, git
 * askpass, MCP) live in its scoped data directory, and only those are reachable.
 * Refused, a socket left by a stopped run failed with EPERM, not ECONNREFUSED,
 * which VS Code reports as another instance running as administrator. The
 * sandbox resolves the root-owned aliases to this directory. */
int envara_notion_scoped_profile(uint16_t port, const char *socket_root, char *out, size_t capacity) {
    if (!out || !capacity || port < 1024 || (socket_root && !socket_root_valid(socket_root))) return reject(EINVAL);
    int n = snprintf(out, capacity, "%s(deny network-outbound)"
        "(allow network-outbound (remote tcp4 \"localhost:%u\"))%s%s%s", dns_profile, port,
        socket_root ? "(allow network-outbound (remote unix-socket (subpath \"" : "", socket_root ? socket_root : "",
        socket_root ? "\")))" : "");
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
static int metadata_match(NSString *value, NSString *pattern) {
    return [value isKindOfClass:NSString.class] && value.length <= 256 &&
        [value rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound;
}
static int read_at(int fd, void *bytes, size_t size, uint64_t offset, uint64_t length) {
    if (offset > length || size > length - offset || offset > INT64_MAX) return 0;
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, (char *)bytes + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue; if (n <= 0) return 0; done += (size_t)n;
    }
    return 1;
}
/* Inspect, never dlopen, the signed engine's defined public entry symbol.
 * Thin/fat 64-bit native slices only; bounded load commands/symbol offsets.
 * Stripped or unusual layouts refuse rather than guessing engine support. */
static int engine_entry(const char *bundle, NSString *relative, const char *symbol) {
    NSString *base = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:bundle length:strlen(bundle)];
    const char *input = [[base stringByAppendingPathComponent:relative] fileSystemRepresentation];
    char canonical[PATH_MAX]; size_t prefix = strlen(bundle); struct stat before, after, named;
    if (!input || !realpath(input, canonical) || strncmp(canonical, bundle, prefix) || canonical[prefix] != '/') return 0;
    int fd = open(canonical, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); if (fd < 0) return 0;
    int okay = !fstat(fd,&before) && S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size > 0 &&
        before.st_size <= INT64_C(1024)*1024*1024 && !envara_gui_acl_free(canonical);
    uint64_t length = okay ? (uint64_t)before.st_size : 0, slice = 0, slice_size = length; uint32_t magic = 0;
    okay = okay && read_at(fd,&magic,sizeof(magic),0,length);
#if defined(__arm64__)
    const cpu_type_t native_cpu = CPU_TYPE_ARM64;
#else
    const cpu_type_t native_cpu = CPU_TYPE_X86_64;
#endif
    if (okay && (magic == FAT_CIGAM || magic == FAT_CIGAM_64)) {
        struct fat_header fat = {0}; okay = read_at(fd,&fat,sizeof(fat),0,length);
        uint32_t count = OSSwapBigToHostInt32(fat.nfat_arch); int found = 0;
        if (!count || count > 32) okay = 0;
        for (uint32_t i = 0; okay && i < count; i++) {
            uint64_t at = sizeof(fat) + (uint64_t)i * (magic == FAT_CIGAM_64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch));
            uint32_t cpu; uint64_t offset, size;
            if (magic == FAT_CIGAM_64) {
                struct fat_arch_64 a; okay = read_at(fd,&a,sizeof(a),at,length); if (!okay) break;
                cpu=OSSwapBigToHostInt32(a.cputype); offset=OSSwapBigToHostInt64(a.offset); size=OSSwapBigToHostInt64(a.size);
            } else {
                struct fat_arch a; okay = read_at(fd,&a,sizeof(a),at,length); if (!okay) break;
                cpu=OSSwapBigToHostInt32(a.cputype); offset=OSSwapBigToHostInt32(a.offset); size=OSSwapBigToHostInt32(a.size);
            }
            if (offset > length || size > length-offset || size < sizeof(struct mach_header_64)) { okay=0; break; }
            if (cpu == (uint32_t)native_cpu) { if (found++) { okay=0; break; } slice=offset; slice_size=size; }
        }
        okay = okay && found == 1;
    }
    struct mach_header_64 header = {0};
    okay = okay && read_at(fd,&header,sizeof(header),slice,length) && header.magic == MH_MAGIC_64 &&
        header.cputype == native_cpu && header.filetype == MH_DYLIB && header.ncmds > 0 && header.ncmds <= 4096 &&
        header.sizeofcmds <= 4*1024*1024 && sizeof(header) + (uint64_t)header.sizeofcmds <= slice_size;
    struct symtab_command symbols = {0}; uint64_t at = sizeof(header); int symbol_tables = 0, entry = 0;
    for (uint32_t i = 0; okay && i < header.ncmds; i++) {
        struct load_command command;
        okay = at + sizeof(command) <= sizeof(header) + (uint64_t)header.sizeofcmds &&
            read_at(fd,&command,sizeof(command),slice+at,length) && command.cmdsize >= sizeof(command) &&
            command.cmdsize <= sizeof(header) + (uint64_t)header.sizeofcmds-at;
        if (!okay) break;
        if (command.cmd == LC_SYMTAB) {
            if (symbol_tables++ || command.cmdsize != sizeof(symbols)) { okay=0; break; }
            okay=read_at(fd,&symbols,sizeof(symbols),slice+at,length);
        }
        at += command.cmdsize;
    }
    okay = okay && at == sizeof(header)+(uint64_t)header.sizeofcmds && symbol_tables == 1 && symbols.nsyms <= 2000000 &&
        symbols.symoff <= slice_size && (uint64_t)symbols.nsyms*sizeof(struct nlist_64) <= slice_size-symbols.symoff &&
        symbols.stroff <= slice_size && symbols.strsize <= slice_size-symbols.stroff;
    size_t wanted = strlen(symbol)+1;
    for (uint32_t i = 0; okay && !entry && i < symbols.nsyms; i++) {
        struct nlist_64 row;
        okay=read_at(fd,&row,sizeof(row),slice+symbols.symoff+(uint64_t)i*sizeof(row),length);
        if (!okay || (row.n_type & N_STAB) || !(row.n_type & N_EXT) || (row.n_type & N_TYPE) != N_SECT ||
            row.n_un.n_strx >= symbols.strsize || wanted > symbols.strsize-row.n_un.n_strx) continue;
        char name[32]; if (wanted > sizeof(name)) { okay=0; break; }
        okay=read_at(fd,name,wanted,slice+symbols.stroff+row.n_un.n_strx,length);
        entry=okay && !memcmp(name,symbol,wanted);
    }
    okay = okay && entry && !fstat(fd,&after) && !lstat(canonical,&named) && same_file(&before,&after) && same_file(&after,&named);
    close(fd); return okay;
}
static enum envara_notion_engine engine_metadata(const struct envara_gui_manifest *manifest, NSString **framework_out) {
    NSString *package=plist_string(manifest->bundle,@"Contents/Info.plist",@"CFBundlePackageType");
    NSString *identifier=plist_string(manifest->bundle,@"Contents/Info.plist",@"CFBundleIdentifier");
    NSString *executable=plist_string(manifest->bundle,@"Contents/Info.plist",@"CFBundleExecutable");
    NSString *principal=plist_string(manifest->bundle,@"Contents/Info.plist",@"NSPrincipalClass");
    NSString *expected=[[NSString stringWithUTF8String:manifest->executable] lastPathComponent];
    if (![package isEqual:@"APPL"] || ![identifier isEqual:[NSString stringWithUTF8String:manifest->identifier]] ||
        !metadata_match(identifier,@"^[A-Za-z0-9.-]+$") || ![executable isEqual:expected]) return ENVARA_NOTION_ENGINE_NONE;
    BOOL electron=[principal isEqual:@"AtomApplication"], chromium=[principal isEqual:@"BrowserCrApplication"];
    if (!electron && !chromium) return ENVARA_NOTION_ENGINE_NONE;
    NSString *base=[NSString stringWithUTF8String:manifest->bundle];
    NSString *root=[base stringByAppendingPathComponent:@"Contents/Frameworks"];
    NSArray *entries=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:root error:NULL];
    if (!entries || entries.count > 64) return ENVARA_NOTION_ENGINE_NONE;
    enum envara_notion_engine result=ENVARA_NOTION_ENGINE_NONE; NSString *selected=nil;
    for (NSString *name in entries) {
        if (![name hasSuffix:@".framework"] || !metadata_match(name,@"^[A-Za-z0-9 ._-]+\\.framework$")) continue;
        if (electron && ![name isEqual:@"Electron Framework.framework"]) continue;
        NSString *relative=[@"Contents/Frameworks" stringByAppendingPathComponent:name];
        NSString *info=[relative stringByAppendingPathComponent:@"Resources/Info.plist"];
        NSString *framework_id=plist_string(manifest->bundle,info,@"CFBundleIdentifier");
        NSString *binary=plist_string(manifest->bundle,info,@"CFBundleExecutable");
        NSString *version=plist_string(manifest->bundle,info,@"CFBundleVersion");
        NSString *kind=plist_string(manifest->bundle,info,@"CFBundlePackageType");
        NSString *required_id=electron?@"com.github.Electron.framework":[identifier stringByAppendingString:@".framework"];
        NSString *required_binary=[name substringToIndex:name.length-@".framework".length];
        if (![framework_id isEqual:required_id] || ![kind isEqual:@"FMWK"] || ![binary isEqual:required_binary] ||
            version.length > 64 || !metadata_match(version,@"^[0-9]+(\\.[0-9]+){1,3}$") ||
            !engine_entry(manifest->bundle,[relative stringByAppendingPathComponent:binary],electron?"_ElectronMain":"_ChromeMain")) continue;
        if (result != ENVARA_NOTION_ENGINE_NONE) return ENVARA_NOTION_ENGINE_NONE;
        selected=relative; result=electron?ENVARA_NOTION_ENGINE_ELECTRON:ENVARA_NOTION_ENGINE_CHROMIUM;
    }
    if (result == ENVARA_NOTION_ENGINE_ELECTRON && ([identifier isEqual:@"com.microsoft.VSCode"] || [identifier isEqual:@"com.microsoft.VSCodeInsiders"])) {
        NSString *path=[base stringByAppendingPathComponent:@"Contents/Resources/app/product.json"];
        char actual[PATH_MAX]; struct stat st;
        if (!realpath(path.fileSystemRepresentation,actual) || strncmp(actual,manifest->bundle,strlen(manifest->bundle)) ||
            actual[strlen(manifest->bundle)] != '/') return ENVARA_NOTION_ENGINE_NONE;
        int fd=open(actual,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); struct stat after, named;
        BOOL okay=fd>=0 && !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_nlink==1 && st.st_size>0 && st.st_size<=1024*1024 && !envara_gui_acl_free(actual);
        NSMutableData *bytes=okay?[NSMutableData dataWithLength:(NSUInteger)st.st_size]:nil;
        okay=okay && read_at(fd,bytes.mutableBytes,bytes.length,0,(uint64_t)st.st_size) && !fstat(fd,&after) && !lstat(actual,&named) && same_file(&st,&after) && same_file(&after,&named);
        if(fd>=0) close(fd);
        id product=okay?[NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL]:nil;
        BOOL stable=[identifier isEqual:@"com.microsoft.VSCode"];
        if (![product isKindOfClass:NSDictionary.class] || ![product[@"darwinBundleIdentifier"] isEqual:identifier] ||
            ![product[@"applicationName"] isEqual:stable?@"code":@"code-insiders"] || ![product[@"quality"] isEqual:stable?@"stable":@"insider"]) return ENVARA_NOTION_ENGINE_NONE;
        result=ENVARA_NOTION_ENGINE_VSCODE;
    }
    if (framework_out) *framework_out=selected; return result;
}
static _Thread_local struct {uint64_t generation;pid_t owner;unsigned count;
    struct {struct envara_gui_manifest manifest;enum envara_notion_engine engine;} entries[4];} engine_scope;
static int notion_engine_in_scope(const struct envara_gui_manifest *manifest, enum envara_notion_engine *engine) {
    if (engine) *engine=ENVARA_NOTION_ENGINE_NONE;
    if (!manifest || manifest->schema != ENVARA_GUI_SCHEMA || manifest->fixture_only ||
        !memchr(manifest->bundle, 0, sizeof(manifest->bundle)) || !memchr(manifest->identifier, 0, sizeof(manifest->identifier)) ||
        !memchr(manifest->requirement,0,sizeof(manifest->requirement)) || envara_gui_manifest_unchanged(manifest))
        return reject_at(EACCES, ENVARA_NOTION_SUBOP_SUPPORTED_ARGUMENT);
    uint64_t generation=envara_gui_validation_scope_current();
    if(engine_scope.generation!=generation || engine_scope.owner!=getpid()) {
        memset(&engine_scope,0,sizeof(engine_scope));engine_scope.generation=generation;engine_scope.owner=getpid();
    }
    for(unsigned i=0;generation && i<engine_scope.count;i++)
        if(!memcmp(manifest,&engine_scope.entries[i].manifest,sizeof(*manifest))) {if(engine)*engine=engine_scope.entries[i].engine;return 0;}
    int valid = 0; enum envara_notion_engine detected=ENVARA_NOTION_ENGINE_NONE;
    @autoreleasepool {
        NSString *framework=nil; detected=engine_metadata(manifest,&framework);
        if (detected == ENVARA_NOTION_ENGINE_NONE || !framework)
            return reject_at(ENOTSUP, ENVARA_NOTION_SUBOP_SUPPORTED_VERSION);
        char team[11];
        if (!envara_gui_requirement_team(manifest->requirement,team)) return reject_at(EACCES,ENVARA_NOTION_SUBOP_SUPPORTED_SIGNATURE);
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)manifest->bundle, (CFIndex)strlen(manifest->bundle), true);
        SecStaticCodeRef code = NULL; SecRequirementRef requirement = NULL;
        NSString *expected=[NSString stringWithFormat:@"anchor apple generic and (%s)",manifest->requirement];
        OSStatus status = url ? SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) : errSecParam;
        if (!status) status = SecRequirementCreateWithString((__bridge CFStringRef)expected, kSecCSDefaultFlags, &requirement);
        if (!status) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures, requirement);
        if (requirement) { CFRelease(requirement); requirement=NULL; } if (code) { CFRelease(code); code=NULL; } if (url) { CFRelease(url); url=NULL; }
        NSString *frameworkPath=[[NSString stringWithUTF8String:manifest->bundle] stringByAppendingPathComponent:framework];
        url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8 *)frameworkPath.fileSystemRepresentation,(CFIndex)strlen(frameworkPath.fileSystemRepresentation),true);
        expected=[NSString stringWithFormat:@"anchor apple generic and certificate leaf[subject.OU] = \"%s\"",team];
        if (!status) status=url?SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&code):errSecParam;
        if (!status) status=SecRequirementCreateWithString((__bridge CFStringRef)expected,kSecCSDefaultFlags,&requirement);
        if (!status) status=SecStaticCodeCheckValidity(code,kSecCSStrictValidate|kSecCSCheckNestedCode|kSecCSCheckAllArchitectures,requirement);
        valid = status == errSecSuccess;
        if (requirement) CFRelease(requirement); if (code) CFRelease(code); if (url) CFRelease(url);
    }
    if (!valid) return reject_at(EACCES, ENVARA_NOTION_SUBOP_SUPPORTED_SIGNATURE);
    if (envara_gui_manifest_unchanged(manifest)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_SUPPORTED_ARGUMENT);
    if(generation && engine_scope.count<4) {unsigned at=engine_scope.count++;engine_scope.entries[at].manifest=*manifest;engine_scope.entries[at].engine=detected;}
    if (engine) *engine=detected; return 0;
}
int envara_notion_engine(const struct envara_gui_manifest *manifest, enum envara_notion_engine *engine) {
    if(!envara_gui_validation_scope_begin()) return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_SUPPORTED_ARGUMENT);
    int result=notion_engine_in_scope(manifest,engine),error=errno;
    envara_gui_validation_scope_end();errno=error;return result;
}
int envara_notion_supported(const struct envara_gui_manifest *manifest) { return envara_notion_engine(manifest,NULL); }
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
static int plan_paths(const char *environment, const char *registration, struct envara_notion_plan *out) {
    if (!uuid(environment) || !uuid(registration) || !out) return reject(EINVAL);
    char *destinations[]={out->user_data,out->home,out->cache,out->temp,out->extensions};
    const char *names[]={"UserData","Home","Cache","Temp","Extensions"};
    for (unsigned i=0;i<5;i++) if (snprintf(destinations[i],PATH_MAX,"%s/%s/%s/%s",ENVARA_NOTION_DATA_ROOT,environment,registration,names[i]) >= PATH_MAX) return reject(EOVERFLOW);
    char alias[17]; if (envara_gui_scoped_alias_id(environment,registration,alias)) return -1;
    if (snprintf(out->user_data_alias,sizeof(out->user_data_alias),"%s/%su",ENVARA_GUI_ALIAS_ROOT,alias) >= (int)sizeof(out->user_data_alias) ||
        snprintf(out->temp_alias,sizeof(out->temp_alias),"%s/%st",ENVARA_GUI_ALIAS_ROOT,alias) >= (int)sizeof(out->temp_alias)) return reject(EOVERFLOW);
    return snprintf(out->shared_data,sizeof(out->shared_data),"%s/.vscode-shared",out->home) >= (int)sizeof(out->shared_data) ? reject(EOVERFLOW) : 0;
}
/* The alias directory is root-owned 0755 without ACLs beneath root-owned,
 * non-writable ancestors, and the alias is a root-owned symlink naming exactly
 * the scoped directory, which itself resolves canonically to that directory.
 * Only root can change either, and data_open still checks the target itself. */
static int alias_directory(void) {
    struct stat info; char parent[PATH_MAX]; strcpy(parent, ENVARA_GUI_ALIAS_ROOT);
    if (lstat(parent, &info) || !S_ISDIR(info.st_mode) || info.st_uid || (info.st_mode & 07777) != 0755) return reject(EACCES);
    for (;;) {
        if (lstat(parent, &info) || !S_ISDIR(info.st_mode) || info.st_uid ||
            (info.st_mode & (S_ISUID | S_ISGID | 0022)) || envara_gui_acl_free(parent)) return reject(EACCES);
        char *slash = strrchr(parent, '/'); if (!slash || slash == parent) break; *slash = 0;
    }
    return envara_gui_acl_free("/") ? reject(EACCES) : 0;
}
static int alias_current(const char *alias, const char *target) {
    char text[PATH_MAX], resolved[PATH_MAX]; struct stat info;
    /* Darwin checks a symlink's own mode for readlink(): the console-owned
     * application resolves these links (SQLite and file watching do), so they
     * must be readable, while only root can still change them. */
    if (alias_directory() || lstat(alias, &info) || !S_ISLNK(info.st_mode) || info.st_uid || (info.st_mode & 07777) != 0755 ||
        envara_gui_acl_free(alias)) return reject(EACCES);
    ssize_t length = readlink(alias, text, sizeof(text) - 1);
    if (length <= 0 || length >= (ssize_t)sizeof(text) - 1) return reject(EACCES);
    text[length] = 0;
    return strcmp(text, target) || !realpath(alias, resolved) || strcmp(resolved, target) ? reject(EACCES) : 0;
}
/* No process-global setlocale and no host environment inheritance. Availability
 * is tested against the installed libc locale; fallback is explicit in plan. */
static int plan_locale(const char *requested, struct envara_notion_plan *out) {
    if (!requested || !out) return reject(EINVAL);
    const char *language="en_US.UTF-8";
    const struct {const char *prefix,*locale;} choices[]={
        {"zh-TW","zh_TW.UTF-8"},{"zh-HK","zh_HK.UTF-8"},{"zh","zh_CN.UTF-8"},
        {"ja","ja_JP.UTF-8"},{"ko","ko_KR.UTF-8"},{"es","es_ES.UTF-8"},{"fr","fr_FR.UTF-8"},
        {"de","de_DE.UTF-8"},{"pt","pt_BR.UTF-8"},{"en","en_US.UTF-8"}};
    int recognized=0;
    for (unsigned i=0;i<sizeof(choices)/sizeof(choices[0]);i++) {
        size_t n=strlen(choices[i].prefix);
        if (!strncmp(requested,choices[i].prefix,n) && (!requested[n] || requested[n]=='-')) { language=choices[i].locale; recognized=1; break; }
    }
    locale_t locale=newlocale(LC_CTYPE_MASK,language,NULL); out->locale_fallback=!recognized;
    if (!locale) { language="en_US.UTF-8"; locale=newlocale(LC_CTYPE_MASK,language,NULL); out->locale_fallback=1; }
    if (!locale) return reject(ENOTSUP); freelocale(locale); strcpy(out->posix_locale,language); return 0;
}
static int shared_data_open(int home, uid_t console, struct stat *identity) {
    int fd=openat(home,".vscode-shared",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); struct stat named; char path[PATH_MAX];
    if (fd<0) return -1;
    if (fstat(fd,identity) || fstatat(home,".vscode-shared",&named,AT_SYMLINK_NOFOLLOW) || !same_file(identity,&named) ||
        !S_ISDIR(identity->st_mode) || identity->st_uid!=console || (identity->st_mode&07777)!=0700 ||
        fcntl(fd,F_GETPATH,path) || envara_gui_acl_free(path)) { close(fd); return reject(EACCES); }
    return fd;
}
static int plan_arguments(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, enum envara_notion_engine snapshot_engine, struct envara_notion_plan *out) {
    strcpy(out->arguments[0], "/usr/bin/sandbox-exec"); strcpy(out->arguments[1], "-p");
    char socket_root[PATH_MAX]; size_t length = strlen(out->user_data);
    if (length <= 9 || strcmp(out->user_data + length - 9, "/UserData")) return reject(EINVAL);
    memcpy(socket_root, out->user_data, length - 9); socket_root[length - 9] = 0;
    if (envara_notion_scoped_profile(context->front_port, socket_root, out->arguments[2], sizeof(out->arguments[2]))) return -1;
    strcpy(out->arguments[3], app->snapshot.executable);
    snprintf(out->arguments[4], sizeof(out->arguments[4]), "--proxy-server=socks5://127.0.0.1:%u", context->front_port);
    strcpy(out->arguments[5], "--proxy-bypass-list=<-loopback>");
    strcpy(out->arguments[6], "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1");
    /* VS Code binds its main IPC socket inside --user-data-dir, so its path must
     * fit the 103-character socket limit; other engines keep the original path. */
    const char *user_data = snapshot_engine == ENVARA_NOTION_ENGINE_VSCODE ? out->user_data_alias : out->user_data;
    if (snprintf(out->arguments[7], sizeof(out->arguments[7]), "--user-data-dir=%s", user_data) >= (int)sizeof(out->arguments[7]) ||
        snprintf(out->arguments[8], sizeof(out->arguments[8]), "--lang=%s", request->browser_locale) >= (int)sizeof(out->arguments[8]))
        return reject_at(EOVERFLOW, ENVARA_NOTION_SUBOP_PLAN_ALLOCATION);
    /* Chromium helpers initialize their own seatbelt profile at startup, and
     * macOS refuses a second sandbox inside the one sandbox-exec applied above
     * ("Failed to initialize sandbox ... Operation not permitted"): every
     * helper died and the app exited before drawing a window. The helpers
     * therefore run without their own sandbox, inside the outer profile, which
     * still denies every network path except the front. Decided with the user
     * on 2026-10-12; the trade-off is the app's internal process isolation. */
    strcpy(out->arguments[9], "--no-sandbox");
    if(snprintf(out->arguments[10],sizeof(out->arguments[10]),"--disk-cache-dir=%s",out->cache)>=(int)sizeof(out->arguments[10]))
        return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_PLAN_ALLOCATION);
    out->argument_count=11;
    if(snapshot_engine==ENVARA_NOTION_ENGINE_VSCODE) {
        if(snprintf(out->arguments[11],sizeof(out->arguments[11]),"--extensions-dir=%s",out->extensions)>=(int)sizeof(out->arguments[11]) ||
           snprintf(out->arguments[12],sizeof(out->arguments[12]),"--shared-data-dir=%s",out->shared_data)>=(int)sizeof(out->arguments[12]))
            return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_PLAN_ALLOCATION);
        out->argument_count=13;
    }
    return 0;
}
static int envara_notion_data_prepare_in_scope(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority) {
    char executing[PROC_PIDPATHINFO_MAXSIZE];
    if (getuid() || geteuid() || !app || !request || !context || !authority || !authority->verify_committed_deny ||
        !uuid(app->registration_id) || !uuid(request->environment_id) || strcmp(context->registration_id, app->registration_id) ||
        proc_pidpath(getpid(), executing, sizeof(executing)) <= 0 || strcmp(executing, ENVARA_GUI_NATIVE_PATH) || !root_chain(executing) ||
        envara_gui_request_validate(&app->snapshot, request, 0) || envara_gui_sealed_snapshot_validate(&app->snapshot) ||
        envara_notion_supported(&app->original) || envara_notion_supported(&app->snapshot) ||
        strcmp(app->original.content_digest, app->snapshot.content_digest) || strcmp(app->original.cdhash, app->snapshot.cdhash) ||
        authority->verify_committed_deny(request, authority->context)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_DATA_ENTRY);
    const char *parent_path = "/Library/PrivilegedHelperTools";
    struct stat held, named; char canonical[PATH_MAX];
    if (!realpath(parent_path, canonical) || strcmp(parent_path, canonical)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_DATA_ANCESTOR);
    int fd = open(parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &held) || lstat(parent_path, &named) || held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        held.st_uid || (held.st_mode & 0022) || envara_gui_acl_free(parent_path) || envara_gui_acl_free("/Library") || envara_gui_acl_free("/")) {
        int error = errno ? errno : EACCES; close(fd); return reject_at(error, ENVARA_NOTION_SUBOP_DATA_ANCESTOR);
    }
    const char *parts[] = {"io.envara.pf-app-data", request->environment_id, app->registration_id};
    for (int i = 0; i < 3; i++) {
        int child = data_child(fd, parts[i], request->console_uid, request->realm_gid, 0, i > 0);
        int error = errno; close(fd); if (child < 0) return reject_at(error, ENVARA_NOTION_SUBOP_DATA_ANCESTOR); fd = child;
    }
    const char *leaves[]={"UserData","Home","Cache","Temp","Extensions"};
    for (unsigned i=0;i<5;i++) {
        int child=data_child(fd,leaves[i],request->console_uid,request->realm_gid,1,1); struct stat identity; char path[PATH_MAX];
        if(child<0) { int error=errno; close(fd); return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF); }
        if(i==1) { int shared=data_child(child,".vscode-shared",request->console_uid,request->realm_gid,1,0);
            if(shared<0) {int error=errno; close(child);close(fd);return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF);} close(shared); }
        int result=fcntl(child,F_GETPATH,path); close(child);
        int checked=result ? -1 : data_open(path,request->console_uid,&identity);
        if(checked<0) {int error=errno?errno:EACCES;close(fd);return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF);} close(checked);
    }
    close(fd);
    /* Short root-owned aliases for socket paths; an existing alias must already
     * name exactly this directory, otherwise preparation refuses. */
    struct envara_notion_plan names; memset(&names,0,sizeof(names));
    if (plan_paths(request->environment_id,app->registration_id,&names)) return reject_at(errno?errno:EINVAL,ENVARA_NOTION_SUBOP_DATA_LEAF);
    int tools = open(parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (tools < 0) return reject_at(errno?errno:EACCES,ENVARA_NOTION_SUBOP_DATA_ANCESTOR);
    int aliases = data_child(tools, strrchr(ENVARA_GUI_ALIAS_ROOT,'/')+1, request->console_uid, request->realm_gid, 0, 0);
    { int error=errno; close(tools); if (aliases < 0) return reject_at(error,ENVARA_NOTION_SUBOP_DATA_ANCESTOR); }
    const char *alias_paths[]={names.user_data_alias,names.temp_alias}, *targets[]={names.user_data,names.temp};
    for (unsigned i=0;i<2;i++) {
        const char *name=strrchr(alias_paths[i],'/')+1;
        int created=!symlinkat(targets[i],aliases,name);
        if (!created && errno!=EEXIST) { int error=errno; close(aliases); return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF); }
        /* The link mode follows umask; set it only on a root-owned link that
         * already names exactly this directory. */
        char text[PATH_MAX]; struct stat link; ssize_t length=readlinkat(aliases,name,text,sizeof(text)-1);
        if (length<=0 || length>=(ssize_t)sizeof(text)-1 || (text[length]=0, strcmp(text,targets[i])) ||
            fstatat(aliases,name,&link,AT_SYMLINK_NOFOLLOW) || !S_ISLNK(link.st_mode) || link.st_uid ||
            ((link.st_mode&07777)!=0755 && fchmodat(aliases,name,0755,AT_SYMLINK_NOFOLLOW))) {
            int error=errno?errno:EACCES; close(aliases); return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF); }
        if ((created || (link.st_mode&07777)!=0755) && fsync(aliases)) { int error=errno; close(aliases); return reject_at(error,ENVARA_NOTION_SUBOP_DATA_LEAF); }
        if (alias_current(alias_paths[i],targets[i])) { close(aliases); return reject_at(EACCES,ENVARA_NOTION_SUBOP_DATA_LEAF); }
    }
    close(aliases);
    return authority->verify_committed_deny(request, authority->context) ? reject_at(EAGAIN, ENVARA_NOTION_SUBOP_DATA_DENY) : 0;
}
static int envara_notion_plan_in_scope(const struct envara_app_registration *app, const struct envara_gui_request *request,
                      const struct envara_notion_context *context, struct envara_notion_plan *out) {
    if (!out) return reject_at(EINVAL, ENVARA_NOTION_SUBOP_PLAN_ARGUMENT); memset(out, 0, sizeof(*out));
    /* Ordered so the FIRST failing sub-operation is the one recorded. The
     * evaluations and short-circuit order are identical to the single
     * conjunction this replaces; only the diagnostic attribution is new. */
    if (!app || !request || !context || app->schema != ENVARA_APP_REGISTRY_SCHEMA || app->fixture_only)
        return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_ARGUMENT);
    if (app->ready || app->protected_ready) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_REGISTRY);
    if (!uuid(app->registration_id) || !uuid(app->version_id) || !uuid(context->registration_id) || strcmp(context->registration_id, app->registration_id))
        return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_CONTEXT);
    if (context->front_port < 1024) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_CONTEXT);
    if (envara_gui_request_validate(&app->snapshot, request, 0)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_REQUEST);
    if (envara_gui_sealed_snapshot_validate(&app->snapshot)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_SEALED);
    enum envara_notion_engine original_engine, snapshot_engine;
    if (envara_notion_engine(&app->original,&original_engine) || envara_notion_engine(&app->snapshot,&snapshot_engine) || original_engine!=snapshot_engine)
        return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_SUPPORTED);
    if (strcmp(app->original.content_digest, app->snapshot.content_digest)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_DIGEST);
    if (strcmp(app->original.cdhash, app->snapshot.cdhash)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_CDHASH);
    if (strcmp(app->original.requirement, app->snapshot.requirement)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_PLAN_REQUIREMENT);
    if (plan_paths(request->environment_id,app->registration_id,out) || plan_locale(request->browser_locale,out))
        return reject_at(errno?errno:EOVERFLOW,ENVARA_NOTION_SUBOP_PLAN_ALLOCATION);
    const char *paths[]={out->user_data,out->home,out->cache,out->temp,out->extensions};
    for(unsigned i=0;i<5;i++) { struct stat data; int fd=data_open(paths[i],request->console_uid,&data);
        if(fd<0) return reject_at(errno?errno:EACCES,ENVARA_NOTION_SUBOP_PLAN_DATA);
        if(i==1) {int shared=shared_data_open(fd,request->console_uid,&data);if(shared<0){close(fd);return reject_at(errno?errno:EACCES,ENVARA_NOTION_SUBOP_PLAN_DATA);}close(shared);} close(fd); }
    if (alias_current(out->user_data_alias,out->user_data) || alias_current(out->temp_alias,out->temp))
        return reject_at(EACCES,ENVARA_NOTION_SUBOP_PLAN_DATA);
    return plan_arguments(app,request,context,snapshot_engine,out);
}
struct notion_data_holds { int fds[6]; struct stat identities[6]; };
static void close_data_holds(struct notion_data_holds *holds) { for(unsigned i=0;i<6;i++) if(holds->fds[i]>=0) {close(holds->fds[i]);holds->fds[i]=-1;} }
static int open_data_holds(const struct envara_notion_plan *plan, uid_t uid, struct notion_data_holds *holds) {
    for(unsigned i=0;i<6;i++) holds->fds[i]=-1;
    const char *paths[]={plan->user_data,plan->home,plan->cache,plan->temp,plan->extensions};
    for(unsigned i=0;i<5;i++) if((holds->fds[i]=data_open(paths[i],uid,&holds->identities[i]))<0) {close_data_holds(holds);return -1;}
    holds->fds[5]=shared_data_open(holds->fds[1],uid,&holds->identities[5]);
    if(holds->fds[5]<0) {close_data_holds(holds);return -1;} return 0;
}
static int data_holds_unchanged(const struct envara_notion_plan *plan, uid_t uid, struct notion_data_holds *holds) {
    const char *paths[]={plan->user_data,plan->home,plan->cache,plan->temp,plan->extensions,plan->shared_data};
    for(unsigned i=0;i<6;i++) {struct stat held,named;char actual[PATH_MAX]; const struct stat *before=&holds->identities[i];
        if(fstat(holds->fds[i],&held) || lstat(paths[i],&named) || held.st_dev!=before->st_dev || held.st_ino!=before->st_ino ||
            held.st_dev!=named.st_dev || held.st_ino!=named.st_ino || !S_ISDIR(named.st_mode) || named.st_uid!=uid ||
            (named.st_mode&07777)!=0700 || held.st_mode!=named.st_mode || held.st_uid!=named.st_uid ||
            fcntl(holds->fds[i],F_GETPATH,actual) || strcmp(actual,paths[i]) || envara_gui_acl_free(paths[i])) return reject(ESTALE);
    }
    return alias_current(plan->user_data_alias,plan->user_data) || alias_current(plan->temp_alias,plan->temp) ? reject(ESTALE) : 0;
}
struct notion_child_environment {char home[PATH_MAX+32],user[256],login[256],timezone[132],browser_locale[96],
    lang[96],ctype[96],all[96],tempdir[PATH_MAX+32],tmp[PATH_MAX+32],temp[PATH_MAX+32],cache[PATH_MAX+32],config[PATH_MAX+32];
    char proxies[6][64]; char *values[24];};
static int child_environment(const struct envara_notion_plan *plan, const struct envara_gui_request *request,
                             const struct envara_notion_context *context, const char *account, struct notion_child_environment *out) {
    if(!plan || !request || !context || !account || !out || context->front_port<1024 ||
        !plan->home[0] || !plan->posix_locale[0]) return reject(EINVAL);
    memset(out,0,sizeof(*out));
#define ENV_FIELD(field,format,value) if(snprintf(out->field,sizeof(out->field),format,value)>=(int)sizeof(out->field)) return reject(EOVERFLOW)
    ENV_FIELD(home,"HOME=%s",plan->home); ENV_FIELD(user,"USER=%s",account); ENV_FIELD(login,"LOGNAME=%s",account);
    ENV_FIELD(timezone,"TZ=%s",request->timezone); ENV_FIELD(browser_locale,"ENVARA_BROWSER_LOCALE=%s",request->browser_locale);
    ENV_FIELD(lang,"LANG=%s",plan->posix_locale); ENV_FIELD(ctype,"LC_CTYPE=%s",plan->posix_locale); ENV_FIELD(all,"LC_ALL=%s",plan->posix_locale);
    ENV_FIELD(tempdir,"TMPDIR=%s/",plan->temp_alias); ENV_FIELD(tmp,"TMP=%s",plan->temp_alias); ENV_FIELD(temp,"TEMP=%s",plan->temp_alias);
    ENV_FIELD(cache,"XDG_CACHE_HOME=%s",plan->cache); ENV_FIELD(config,"XDG_CONFIG_HOME=%s",plan->user_data);
#undef ENV_FIELD
    /* Cooperative CLI clients resolve destination names through the same
     * already-attested front as the engine. These secretless settings grant
     * no routing authority: clients that ignore them remain fenced. */
    const char *proxy_keys[]={"ALL_PROXY","all_proxy","HTTP_PROXY","http_proxy","HTTPS_PROXY","https_proxy"};
    for(unsigned i=0;i<sizeof(proxy_keys)/sizeof(proxy_keys[0]);i++) {
        int n=snprintf(out->proxies[i],sizeof(out->proxies[i]),"%s=socks5h://127.0.0.1:%u",proxy_keys[i],(unsigned)context->front_port);
        if(n<0||n>=(int)sizeof(out->proxies[i]))return reject(EOVERFLOW);
    }
    char *values[]={out->home,out->user,out->login,"PATH=/usr/bin:/bin:/usr/sbin:/sbin",out->lang,out->ctype,out->all,
        out->timezone,out->browser_locale,out->tempdir,out->tmp,out->temp,out->cache,out->config,
        out->proxies[0],out->proxies[1],out->proxies[2],out->proxies[3],out->proxies[4],out->proxies[5],
        "NO_PROXY=","no_proxy=",NULL};
    memcpy(out->values,values,sizeof(values)); return 0;
}
static int finish_stopped_stage(const struct envara_app_registration *app, const struct envara_gui_request *request,
                               const struct envara_notion_plan *plan, struct notion_data_holds *holds, struct envara_gui_lifecycle *out) {
    int result = !sole_group(&out->child, request->realm_gid) || data_holds_unchanged(plan,request->console_uid,holds) ||
        envara_gui_manifest_unchanged(&app->original) || envara_gui_manifest_unchanged(&app->snapshot);
    close_data_holds(holds);
    /* The supervisor must first independently establish direct-child custody.
     * Pre-reaping here would leave a spent PID that cannot pass that check.
     * Preserve the real stopped child/error reader on every post-fork refusal;
     * its supervisor performs exact cancel/reap plus deny/scope recovery. */
    if (result) return reject(ESTALE);
    return 0;
}
static int envara_notion_stage_in_scope(const struct envara_app_registration *app, const struct envara_gui_request *request,
                       const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority,
                       struct envara_gui_lifecycle *out) {
    envara_notion_suboperation_begin();
    if (!out || out->phase != ENVARA_GUI_EMPTY) return reject_at(EALREADY, ENVARA_NOTION_SUBOP_STAGE_ARGUMENT);
    if (getuid() || geteuid() || !authority || !authority->verify_committed_deny) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_AUTHORITY);
    char executing[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), executing, sizeof(executing)) <= 0 || strcmp(executing, ENVARA_GUI_NATIVE_PATH) ||
        !root_chain(executing)) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_ENTRY);
    /* sandbox-exec is the fixed interpreter this profile is built around. Its
     * own root chain is a separate predicate from the native entry's chain, so
     * it gets its own attribution. */
    if (!root_chain("/usr/bin/sandbox-exec")) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_ENTRY);
    struct envara_notion_plan plan; if (envara_notion_plan(app, request, context, &plan)) return -1;
    envara_gui_step(ENVARA_GUI_STEP_STAGE_PLAN);
    struct envara_gui_session session;
    if (!request->gui_audit_session) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_SESSION);
    if (envara_gui_session_read(&session)) return reject_at(errno ? errno : EACCES, ENVARA_NOTION_SUBOP_STAGE_SESSION);
    if (session.console_uid != request->console_uid || session.audit_session != request->gui_audit_session)
        return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_SESSION);
    if (!session.audit_has_console_graphics) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_SESSION);
    if (!session.security_has_graphics) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_SESSION);
    pid_t running; int scan = envara_gui_original_running(&app->original, request->console_uid, &running);
    if (scan == 0) scan = envara_gui_original_running(&app->snapshot, request->console_uid, &running);
    if (scan) return reject_at(scan > 0 ? EALREADY : EACCES, ENVARA_NOTION_SUBOP_STAGE_ORIGINAL_RUNNING);
    struct passwd *account = getpwuid(request->console_uid);
    if (!account || !account->pw_name || !account->pw_dir) return reject_at(EACCES, ENVARA_NOTION_SUBOP_STAGE_ACCOUNT);
    struct notion_child_environment environment;
    if(child_environment(&plan,request,context,account->pw_name,&environment)) return reject_at(errno?errno:EINVAL,ENVARA_NOTION_SUBOP_STAGE_ENVIRONMENT);
    if(plan.argument_count<10 || plan.argument_count>13) return reject_at(EINVAL,ENVARA_NOTION_SUBOP_STAGE_ARGUMENT);
    char *arguments[14]; for (int i = 0; i < plan.argument_count; i++) arguments[i] = plan.arguments[i]; arguments[plan.argument_count] = NULL;
    struct notion_data_holds holds;
    if (open_data_holds(&plan,request->console_uid,&holds)) return reject_at(errno ? errno : EACCES, ENVARA_NOTION_SUBOP_STAGE_DATA);
    if (envara_gui_manifest_unchanged(&app->original) || envara_gui_manifest_unchanged(&app->snapshot) ||
        data_holds_unchanged(&plan,request->console_uid,&holds) ||
        authority->verify_committed_deny(request, authority->context)) { close_data_holds(&holds); return reject_at(EAGAIN, ENVARA_NOTION_SUBOP_STAGE_RECHECK); }
    enum envara_notion_engine engine;
    if(envara_notion_engine(&app->snapshot,&engine)){close_data_holds(&holds);return reject_at(EACCES,ENVARA_NOTION_SUBOP_STAGE_RECHECK);}
    if(engine==ENVARA_NOTION_ENGINE_VSCODE){
        if(envara_app_keychain_prepare(context->preparation,app,request,plan.home,authority)){
            int error=errno;close_data_holds(&holds);return reject_at(error?error:EACCES,ENVARA_NOTION_SUBOP_STAGE_KEYCHAIN);
        }
        /* Preparation has its own exact process custody. The application has
         * not been forked, and every stage predicate must still hold now. */
        struct envara_gui_session current;
        scan=envara_gui_original_running(&app->original,request->console_uid,&running);
        if(!scan)scan=envara_gui_original_running(&app->snapshot,request->console_uid,&running);
        if(scan||envara_gui_session_read(&current)||current.console_uid!=request->console_uid||
            current.audit_session!=request->gui_audit_session||!current.audit_has_console_graphics||!current.security_has_graphics||
            envara_gui_manifest_unchanged(&app->original)||envara_gui_manifest_unchanged(&app->snapshot)||
            data_holds_unchanged(&plan,request->console_uid,&holds)||authority->verify_committed_deny(request,authority->context)){
            close_data_holds(&holds);return reject_at(EAGAIN,ENVARA_NOTION_SUBOP_STAGE_RECHECK);
        }
    }
    envara_gui_step(ENVARA_GUI_STEP_STAGE_RECHECK);
    envara_gui_lifecycle_init(out);
    int result = envara_spawn_suspended_io(request->console_uid, request->realm_gid, request->cwd,
        "/usr/bin/sandbox-exec", arguments, environment.values, 0, -1, -1, &out->child);
    if (result) { int error = errno; close_data_holds(&holds); return reject_at(error, ENVARA_NOTION_SUBOP_STAGE_SPAWN); }
    envara_gui_step(ENVARA_GUI_STEP_STAGE_SPAWN);
    out->phase = ENVARA_GUI_SUSPENDED; out->request = *request; out->original = app->original; out->manifest = app->snapshot; out->session = session;
    if (finish_stopped_stage(app, request, &plan, &holds, out))
        return reject_at(errno ? errno : ESTALE, ENVARA_NOTION_SUBOP_STAGE_STOPPED);
    envara_gui_step(ENVARA_GUI_STEP_STAGE_STOPPED);
    return 0; /* Stopped, no sandbox/flag/native traffic acceptance claim. */
}

int envara_notion_data_prepare(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority) {
    if(!envara_gui_validation_scope_begin()) return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_DATA_ARGUMENT);
    int result=envara_notion_data_prepare_in_scope(app,request,context,authority),error=errno;
    envara_gui_validation_scope_end();errno=error;return result;
}

int envara_notion_plan(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, struct envara_notion_plan *out) {
    if(!envara_gui_validation_scope_begin()) return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_PLAN_ARGUMENT);
    int result=envara_notion_plan_in_scope(app,request,context,out),error=errno;
    envara_gui_validation_scope_end();errno=error;return result;
}

int envara_notion_stage(const struct envara_app_registration *app, const struct envara_gui_request *request,
    const struct envara_notion_context *context, const struct envara_gui_stage_authority *authority, struct envara_gui_lifecycle *out) {
    if(!envara_gui_validation_scope_begin()) return reject_at(EOVERFLOW,ENVARA_NOTION_SUBOP_STAGE_ARGUMENT);
    int result=envara_notion_stage_in_scope(app,request,context,authority,out),error=errno;
    envara_gui_validation_scope_end();errno=error;return result;
}
