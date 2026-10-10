#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "recovery-app-46ae-inventory.h"
#include "app-scope-proof.h"
#include "pf-hook-abi.h"
#define INSTALL_PARENT "/Library/PrivilegedHelperTools"
#define INSTALL INSTALL_PARENT "/io.envara.pf-routing"
#define NATIVE INSTALL "/envara-pf-native"
#define MF CANARY_MANIFEST_SHA
#define ROOT_RULE @"7f79342e7409a1d3569220b8e143c1f261574ae1ae7de6a07b915a2364316bb5"
#define ROOT_TEXT @"5e803c2e459d5417da5d61aba888d1da25ad56cb0bff4f22e69d36078eb7f575"
#define CANARY_SCHEMA @"envara.macos-pf-empty-run-canary/v2"
#define NATIVE_SCHEMA @"envara.macos-pf-owned-root-hook/v2"
#define OUTPUT_LIMIT (128U * 1024U)
static const char *failure = "CANARY_PREFLIGHT_REFUSED";
static volatile sig_atomic_t interrupted;
/* Starts inside the authorized root entry. Authorization UI time is separate.
 * Reserve five seconds for final reporting outside this 175-second budget. */
static double rootDeadline;
#define INSERT_REQUIRED_SECONDS 145.0
static void onSignal(int signal) { interrupted = signal; }
static bool refuse(const char *why) { failure = why; return false; }
static double seconds(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0; return t.tv_sec + t.tv_nsec / 1e9; }
static bool sameStat(const struct stat *a, const struct stat *b) {
 return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size && a->st_mode == b->st_mode &&
  a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
  a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
  a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static bool noWriteACL(int fd) {
 errno = 0; acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
 if (!acl) return errno == ENOENT;
 acl_entry_t entry; int cursor = ACL_FIRST_ENTRY, result; bool okay = true;
 while ((result = acl_get_entry(acl, cursor, &entry)) == 0) {
  cursor = ACL_NEXT_ENTRY; acl_tag_t tag; acl_permset_t perms;
  if (acl_get_tag_type(entry, &tag) || acl_get_permset(entry, &perms)) { okay = false; break; }
  if (tag != ACL_EXTENDED_ALLOW) continue;
  const acl_perm_t forbidden[] = {ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES,
   ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER};
  for (size_t i = 0; i < sizeof(forbidden)/sizeof(forbidden[0]); i++) if (acl_get_perm_np(perms, forbidden[i]) != 0) { okay = false; break; }
  if (!okay) break;
 }
 if (okay) okay = result == -1 && errno == EINVAL;
 acl_free(acl); return okay;
}
static bool secureFD(int fd, bool directory, mode_t exact) {
 struct stat st; return fd >= 0 && !fstat(fd, &st) && st.st_uid == 0 && st.st_gid == 0 && !(st.st_mode & 0022) &&
  (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode) && st.st_nlink == 1) &&
  (!exact || (st.st_mode & 07777) == exact) && noWriteACL(fd);
}
static int directory(const char *absolute) {
 int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
 if (!secureFD(fd, true, 0)) { if (fd >= 0) close(fd); return -1; }
 char copy[PATH_MAX]; if (strlen(absolute) >= sizeof(copy)) { close(fd); return -1; }
 strcpy(copy, absolute); char *save = NULL;
 for (char *part = strtok_r(copy + 1, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
  if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return -1; }
  int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); close(fd); fd = next;
  if (!secureFD(fd, true, 0)) { if (fd >= 0) close(fd); return -1; }
 }
 return fd;
}
static int relativeFile(int base, const char *name) {
 if (!strcmp(name, "fixtures/EnvaraRoutingAcceptanceFixture")) {
  int parent = openat(base, "fixtures", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!secureFD(parent, true, 0755)) { if (parent >= 0) close(parent); return -1; }
  int fd = openat(parent, "EnvaraRoutingAcceptanceFixture", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); close(parent); return fd;
 }
 return openat(base, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool hashFD(int fd, const char *expected, double deadline) {
 struct stat before, after; if (fstat(fd, &before) || before.st_size < 0 || before.st_size > 512LL*1024*1024 || lseek(fd, 0, SEEK_SET) < 0) return false;
 CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx); unsigned char bytes[65536], digest[CC_SHA256_DIGEST_LENGTH]; off_t count = 0;
 for (;;) { if (seconds() >= deadline) return false; ssize_t size = read(fd, bytes, sizeof(bytes));
  if (size < 0 && errno == EINTR) continue; if (size < 0) return false; if (!size) break;
  count += size; if (count > before.st_size) return false; CC_SHA256_Update(&ctx, bytes, (CC_LONG)size);
 }
 CC_SHA256_Final(digest, &ctx); char hex[65]; for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + 2*i, 3, "%02x", digest[i]);
 return count == before.st_size && !fstat(fd, &after) && sameStat(&before, &after) && !strcmp(hex, expected);
}
static NSString *hashText(NSString *value) {
 NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding]; unsigned char digest[32]; CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
 char hex[65]; for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + 2*i, 3, "%02x", digest[i]); return @(hex);
}
#pragma clang diagnostic pop
static bool exactTree(int fd, bool fixtures) {
 int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (scan < 0) return false;
 DIR *entries = fdopendir(scan); if (!entries) { close(scan); return false; } struct dirent *entry; unsigned count = 0; bool okay = true;
 errno = 0;
 while ((entry = readdir(entries))) {
  if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue; bool known = false; struct stat st;
  if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) { okay = false; break; }
  if (!fixtures && !strcmp(entry->d_name, "fixtures") && S_ISDIR(st.st_mode)) {
   int nested = openat(fd, "fixtures", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
   known = secureFD(nested, true, 0755) && exactTree(nested, true); if (nested >= 0) close(nested);
  } else if (S_ISREG(st.st_mode)) {
   for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
    const char *name = files[i].name; if (fixtures && strchr(name, '/')) name = strchr(name, '/') + 1;
    else if (fixtures || strchr(name, '/')) continue;
    if (!strcmp(name, entry->d_name)) { known = true; break; }
   }
  }
  if (!known) { okay = false; break; } count++; errno = 0;
 }
 if (okay) okay = errno == 0 && count == (fixtures ? 1 : sizeof(files)/sizeof(files[0])); closedir(entries); return okay;
}
static int verifiedInstallation(double deadline) {
 int base = directory(INSTALL); if (!secureFD(base, true, 0755) || !exactTree(base, false)) { if (base >= 0) close(base); refuse("INSTALLED_TREE_REFUSED"); return -1; }
 for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
  int fd = relativeFile(base, files[i].name); bool okay = secureFD(fd, false, files[i].mode) && hashFD(fd, files[i].sha, deadline);
  if (fd >= 0) close(fd); if (!okay) { close(base); refuse("INSTALLED_PIN_OR_MODE_REFUSED"); return -1; }
 }
 return base;
}

/* Reject duplicate JSON keys before Foundation can collapse them. Canonical
 * sealed registries use ASCII keys/string values without escapes. Unknown or
 * noncanonical syntax is refused, never normalized into a private lease. */
typedef struct { const unsigned char *bytes; size_t size, at; } JSONCursor;
static void skipSpace(JSONCursor *c) { while (c->at < c->size && strchr(" \t\r\n", c->bytes[c->at])) c->at++; }
static NSString *jsonString(JSONCursor *c) {
 skipSpace(c); if (c->at >= c->size || c->bytes[c->at++] != '"') return nil; size_t start = c->at;
 while (c->at < c->size && c->bytes[c->at] != '"') { unsigned char ch = c->bytes[c->at++]; if (ch < 32 || ch > 126 || ch == '\\') return nil; }
 if (c->at == c->size || c->at - start > 4096) return nil;
 NSString *value = [[NSString alloc] initWithBytes:c->bytes + start length:c->at - start encoding:NSASCIIStringEncoding]; c->at++; return value;
}
static bool jsonValue(JSONCursor *c, unsigned depth) {
 if (depth > 16) return false; skipSpace(c); if (c->at >= c->size) return false; unsigned char ch = c->bytes[c->at];
 if (ch == '"') return jsonString(c) != nil;
 if (ch == '{' || ch == '[') {
  bool object = ch == '{'; unsigned char end = object ? '}' : ']'; c->at++; skipSpace(c);
  if (c->at < c->size && c->bytes[c->at] == end) { c->at++; return true; }
  NSMutableSet *seen = [NSMutableSet set]; unsigned items = 0;
  for (;;) { if (++items > 128) return false;
   if (object) { NSString *key = jsonString(c); if (!key || [seen containsObject:key]) return false; [seen addObject:key];
    skipSpace(c); if (c->at >= c->size || c->bytes[c->at++] != ':') return false; }
   if (!jsonValue(c, depth + 1)) return false; skipSpace(c); if (c->at >= c->size) return false;
   ch = c->bytes[c->at++]; if (ch == end) return true; if (ch != ',') return false;
  }
 }
 size_t start = c->at; while (c->at < c->size && !strchr(" \t\r\n,}]", c->bytes[c->at])) c->at++;
 return c->at > start && c->at - start <= 64;
}
static NSDictionary *strictJSON(NSData *data, size_t limit) {
 if (!data.length || data.length > limit) return nil; JSONCursor c = {data.bytes, data.length, 0};
 if (!jsonValue(&c, 0)) return nil; skipSpace(&c); if (c.at != c.size) return nil;
 id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]; return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
static bool keys(NSDictionary *value, NSArray *allowed) {
 return [value isKindOfClass:NSDictionary.class] && value.count == allowed.count && [[NSSet setWithArray:value.allKeys] isEqualToSet:[NSSet setWithArray:allowed]];
}
static bool regex(id value, NSString *expression) {
 return [value isKindOfClass:NSString.class] && [(NSString *)value rangeOfString:expression options:NSRegularExpressionSearch].location != NSNotFound;
}
static bool isBool(id value) { return value && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID(); }
static bool validLease(NSDictionary *lease) {
 NSArray *names = @[@"schema", @"runId", @"leaseId", @"anchor", @"owner", @"label", @"ticket", @"rootBeforeSHA256", @"rootBeforeTextSHA256"];
 if (!keys(lease, names)) return false; for (NSString *name in names) if (![lease[name] isKindOfClass:NSString.class]) return false;
 if (![lease[@"schema"] isEqual:@"envara.macos-pf-owned-root-hook-lease/v2"] || ![lease[@"runId"] isEqual:CANARY_RUN] ||
  !regex(lease[@"leaseId"], @"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$") ||
  ![lease[@"anchor"] isEqual:CANARY_ANCHOR] || ![lease[@"owner"] isEqual:CANARY_ANCHOR] ||
  ![lease[@"rootBeforeSHA256"] isEqual:ROOT_RULE] || ![lease[@"rootBeforeTextSHA256"] isEqual:ROOT_TEXT] ||
  !regex(lease[@"ticket"], @"^[1-9][0-9]{0,19}$")) return false;
 NSString *ticket = lease[@"ticket"]; if (ticket.length == 20 && [ticket compare:@"18446744073709551615" options:NSLiteralSearch] == NSOrderedDescending) return false;
 NSString *label = [@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@", CANARY_RUN, lease[@"leaseId"]]) substringToIndex:32]];
 return [lease[@"label"] isEqual:label];
}

static NSArray *proofKeys(void) {
 return @[@"schema", @"ok", @"operation", @"reason", @"anchor", @"namespaceScheme", @"readOnly", @"productionReady", @"ready", @"protected", @"fixtureOnly",
  @"pfDisabled", @"pinsVerified", @"originalRootCompatible", @"canCreateOwnedHook", @"ownedRootHookCanCreate", @"ownedRootHookVerified", @"hookInstalled",
  @"ownedRootHookRemoved", @"originalRootRestored", @"cleanupPending", @"namespaceState", @"namespaceReclaimed", @"namespaceExists", @"receiptRetired",
  @"runLedgerState", @"inactiveQueuesVerified", @"namespaceReferencesVerified", @"originalRootTextSHA256", @"originalRootSHA256", @"ticketSource",
  @"nativeCanaryProof", @"namespaceCanaryVerified", @"gates", @"lease", @"priorAnchorsCompatible", @"priorRootDerivedAnchorCount", @"priorRulesetCountsSHA256"];
}
static NSArray *nativeReasons(void) {
 return @[@"READ_ONLY_OWNED_HOOK_PROOF", @"INVALID_FIXED_OPERATION", @"AUTHENTICATED_ROOT_CONTROLLER_REQUIRED", @"SIGNAL_BOUNDARY_UNAVAILABLE",
  @"INVALID_PRIVATE_HOOK_INPUT", @"PINNED_HOST_MISMATCH", @"READ_DEVICE_UNAVAILABLE", @"OWNED_RUN_LEDGER_UNVERIFIED", @"OWNED_RUN_NAMESPACE_CONSUMED",
  @"OWNED_HOOK_PREFLIGHT_REQUIRED", @"EXACT_LEASE_AND_EMPTY_OWNED_ANCHOR_REQUIRED", @"OWNED_RUN_ALLOCATION_REQUIRED", @"EXACT_ISSUED_LEASE_REQUIRED",
  @"WRITE_DEVICE_UNAVAILABLE", @"OWNED_HOOK_DELETE_INTENT_REQUIRED", @"EXACT_OWNED_HOOK_REMOVED", @"EXACT_OWNED_HOOK_DEACTIVATED_NAMESPACE_RETAINED",
  @"OWNED_RUN_RETIREMENT_UNCONFIRMED", @"EXACT_CLEANUP_UNCONFIRMED", @"PF_CHANGED_OR_PARENT_ENDED_BEFORE_INSERT", @"OWNED_EMPTY_HOOK_VERIFIED",
  @"INSERT_UNCONFIRMED_OWN_ROLLBACK_ATTEMPTED", @"INSERT_UNCONFIRMED_OWN_ROLLBACK_REFUSED"];
}
static const char *nativeOperation(unsigned operation) {
 static const char *const operations[] = {"hook-status", "REFUSED_INSERT", "delete-owned-root-hook"};
 return operation < 3 && operation != 1 ? operations[operation] : NULL;
}
/* Decode only this exact pinned executable's known v2 envelope. Neither a
 * successful exit nor an ok flag alone proves kernel or ledger restoration. */
static NSDictionary *nativeProof(NSData *data, unsigned operation, bool baseline, int exitStatus) {
 NSDictionary *proof = strictJSON(data, OUTPUT_LIMIT);
 if (!nativeOperation(operation) || !keys(proof, proofKeys()) || ![proof[@"schema"] isEqual:NATIVE_SCHEMA] ||
  ![proof[@"operation"] isEqual:@(nativeOperation(operation))] || ![nativeReasons() containsObject:proof[@"reason"]] ||
  ![proof[@"namespaceScheme"] isEqual:@"full-run-uuid/v2"] || ![proof[@"ticketSource"] isEqual:@"this-INSERT-return-only"] ||
  ![proof[@"nativeCanaryProof"] isEqual:@"root-canary-native-20261008-fixed-v1-only"]) return nil;
 for (NSString *key in @[@"ok", @"readOnly", @"productionReady", @"ready", @"protected", @"fixtureOnly", @"pfDisabled", @"pinsVerified",
   @"originalRootCompatible", @"canCreateOwnedHook", @"ownedRootHookCanCreate", @"ownedRootHookVerified", @"hookInstalled", @"ownedRootHookRemoved",
   @"originalRootRestored", @"cleanupPending", @"namespaceReclaimed", @"namespaceExists", @"receiptRetired", @"inactiveQueuesVerified",
   @"namespaceReferencesVerified", @"namespaceCanaryVerified", @"priorAnchorsCompatible"]) if (!isBool(proof[key])) return nil;
 if ([proof[@"ok"] boolValue] && exitStatus != 0) return nil;
 if ([proof[@"readOnly"] boolValue] != (operation == 0) || ![proof[@"fixtureOnly"] boolValue] || [proof[@"productionReady"] boolValue] ||
  [proof[@"ready"] boolValue] || [proof[@"protected"] boolValue] || [proof[@"inactiveQueuesVerified"] boolValue] ||
  [proof[@"namespaceReferencesVerified"] boolValue] || [proof[@"namespaceCanaryVerified"] boolValue]) return nil;
 NSString *expected = baseline ? @"" : CANARY_ANCHOR;
 if (![proof[@"anchor"] isEqual:expected] && !(![proof[@"ok"] boolValue] && [proof[@"anchor"] isEqual:@""])) return nil;
 if (![@[@"unselected", @"absent", @"present", @"unknown"] containsObject:proof[@"namespaceState"]] ||
  ![@[@"unselected", @"unused", @"allocation-only", @"issued", @"delete-intent", @"retired", @"capacity-exhausted", @"unknown"] containsObject:proof[@"runLedgerState"]]) return nil;
 for (NSString *key in @[@"originalRootTextSHA256", @"originalRootSHA256", @"priorRulesetCountsSHA256"])
  if (!regex(proof[key], @"^([0-9a-f]{64})?$")) return nil;
 id count = proof[@"priorRootDerivedAnchorCount"];
 if (![count isKindOfClass:NSNumber.class] || isBool(count) || [count doubleValue] != 7.0) return nil;
 NSDictionary *gates = proof[@"gates"];
 if (!keys(gates, @[@"productionHook", @"fullKernelLayout", @"fullFixtureAcceptance", @"wholeGuardCrash", @"allStatePreservation"])) return nil;
 for (NSString *key in gates) if (!isBool(gates[key]) || [gates[key] boolValue]) return nil;
 if (proof[@"lease"] != NSNull.null && !validLease(proof[@"lease"])) return nil;
 return proof;
}
/* Only static argv below are reachable. Fixed input <=4094 bytes fits the
 * pipe atomically; stdout is private, bounded and never forwarded to users. */
typedef struct { pid_t pid, parent; uint64_t seconds, microseconds; bool known; } CanaryChildIdentity;
static CanaryChildIdentity childIdentity(pid_t child) {
 struct proc_bsdinfo info = {0}; CanaryChildIdentity identity = {.pid=child,.parent=getpid()};
 if (child > 1 && proc_pidinfo(child,PROC_PIDTBSDINFO,0,&info,sizeof(info)) == (int)sizeof(info) &&
  info.pbi_pid == (uint32_t)child && info.pbi_ppid == (uint32_t)identity.parent) {
  identity.seconds = info.pbi_start_tvsec; identity.microseconds = info.pbi_start_tvusec; identity.known = true;
 }
 return identity;
}
static bool sameChildBirth(const CanaryChildIdentity *identity) {
 if (!identity->known) return false; struct proc_bsdinfo info = {0};
 return proc_pidinfo(identity->pid,PROC_PIDTBSDINFO,0,&info,sizeof(info)) == (int)sizeof(info) &&
  info.pbi_pid == (uint32_t)identity->pid && info.pbi_ppid == (uint32_t)identity->parent &&
  info.pbi_start_tvsec == identity->seconds && info.pbi_start_tvusec == identity->microseconds;
}
/* The unreaped-child ownership check and exact birth check both apply. A
 * zombie keeps its PID reserved until waitpid; any reaped/unknown child must
 * never be signalled merely because a pipe still has an inherited writer. */
static bool signalOwnedChild(const CanaryChildIdentity *identity, int signal, bool *ended, bool *owned, int *status) {
 if (*ended || !*owned) return false;
 pid_t result = waitpid(identity->pid,status,WNOHANG);
 if (result == identity->pid) { *ended = true; *owned = false; return false; }
 if (result < 0) { if (errno != EINTR) *owned = false; return false; }
 return result == 0 && sameChildBirth(identity) && kill(identity->pid,signal) == 0;
}
static NSData *fixedProcess(const char *executable, char *const argv[], NSData *input, int *exitStatus, bool mutation) {
 int in[2], out[2]; if (rootDeadline <= seconds() || input.length > 4094 || pipe(in)) return nil;
 if (pipe(out)) { close(in[0]); close(in[1]); return nil; }
 posix_spawnattr_t attr; posix_spawn_file_actions_t actions; pid_t child = -1;
 int error = posix_spawnattr_init(&attr); bool attrReady = !error, actionsReady = false;
 if (!error) { error = posix_spawn_file_actions_init(&actions); actionsReady = !error; }
 if (!error) error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
 if (!error) error = posix_spawn_file_actions_adddup2(&actions, in[0], STDIN_FILENO);
 if (!error) error = posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO);
 if (!error) error = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
 char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", NULL};
 if (!error) error = posix_spawn(&child, executable, &actions, &attr, argv, env);
 if (actionsReady) posix_spawn_file_actions_destroy(&actions); if (attrReady) posix_spawnattr_destroy(&attr);
 close(in[0]); close(out[1]);
 if (error || child < 0) { close(in[1]); close(out[0]); return nil; }
 CanaryChildIdentity identity = childIdentity(child);
 bool okay = !input.length || write(in[1], input.bytes, input.length) == (ssize_t)input.length; close(in[1]);
 NSMutableData *data = [NSMutableData data]; bool ended = false, owned = true, eof = false, terminated = false; int status = 0;
 double deadline = MIN(rootDeadline,seconds() + (mutation ? 20 : 10));
 double killDeadline = MIN(rootDeadline,deadline + 5);
 while (!ended || !eof) {
  double now = seconds();
  if (now >= deadline && !terminated) { (void)signalOwnedChild(&identity,SIGTERM,&ended,&owned,&status); terminated = true; okay = false; }
  if (now >= killDeadline) { okay = false; break; }
  if (!ended) { pid_t found = waitpid(child, &status, WNOHANG);
   if (found == child) { ended = true; owned = false; } else if (found < 0 && errno != EINTR) { owned = false; okay = false; break; } }
  if (!eof) { struct pollfd p = {out[0], POLLIN|POLLHUP, 0}; int ready = poll(&p, 1, 50);
   if (ready < 0 && errno != EINTR) { okay = false; break; }
   if (ready > 0) { unsigned char bytes[4096]; ssize_t size = read(out[0], bytes, sizeof(bytes));
    if (size > 0 && data.length + (size_t)size <= OUTPUT_LIMIT) [data appendBytes:bytes length:(NSUInteger)size];
    else if (!size) eof = true; else if (size < 0 && errno == EINTR) continue;
    else { okay = false; (void)signalOwnedChild(&identity,SIGTERM,&ended,&owned,&status); terminated = true; break; } }
  } else { struct timespec pause = {0,1000000}; nanosleep(&pause, NULL); }
 }
 close(out[0]); if (!ended && owned) {
  (void)signalOwnedChild(&identity,SIGKILL,&ended,&owned,&status);
  while (!ended && owned && seconds() < rootDeadline) {
   pid_t result = waitpid(child,&status,WNOHANG);
   if (result == child) { ended = true; owned = false; }
   else if (result < 0 && errno != EINTR) owned = false;
   else { struct timespec pause = {0,1000000}; nanosleep(&pause,NULL); }
  }
 }
 if (!okay || !ended || !eof || !WIFEXITED(status)) return nil;
 *exitStatus = WEXITSTATUS(status); return data;
}
static NSDictionary *nativeCall(unsigned operation, NSDictionary *input, int *exitStatus, int installed) {
 if (!nativeOperation(operation) || !(keys(input, @[]) || keys(input, @[@"runId"]) || keys(input, @[@"lease"]))) return nil;
 if (operation == 1 && (!keys(input, @[@"runId"]) || ![input[@"runId"] isEqual:CANARY_RUN])) return nil;
 if (operation == 2 && (!keys(input, @[@"lease"]) || !validLease(input[@"lease"]))) return nil;
 if (input[@"runId"] && ![input[@"runId"] isEqual:CANARY_RUN]) return nil;
 if (input[@"lease"] && !validLease(input[@"lease"])) return nil;
 int held = relativeFile(installed, "envara-pf-native"); struct stat expected, current;
 bool stable = secureFD(held, false, 0755) && !fstat(held, &expected) && !lstat(NATIVE, &current) && sameStat(&expected, &current);
 if (held >= 0) close(held); if (!stable) return nil;
 NSData *payload = [NSJSONSerialization dataWithJSONObject:input options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 if (!payload || payload.length > 4094) return nil;
 char *argv[] = {NATIVE, (char *)nativeOperation(operation), NULL};
 NSData *data = fixedProcess(NATIVE, argv, payload, exitStatus, operation != 0);
 return data ? nativeProof(data, operation, !input.count, *exitStatus) : nil;
}

static NSString *normalizedRoutes(NSString *text) {
 if (![text isKindOfClass:NSString.class] || text.length > OUTPUT_LIMIT) return nil;
 NSMutableArray *entries = [NSMutableArray array]; NSString *family = nil; NSArray *header = nil;
 NSCharacterSet *space = NSCharacterSet.whitespaceCharacterSet;
 for (NSString *raw in [text componentsSeparatedByString:@"\n"]) {
  NSString *line = [raw stringByTrimmingCharactersInSet:space]; if (!line.length || [line isEqual:@"Routing tables"]) continue;
  if ([line isEqual:@"Internet:"] || [line isEqual:@"Internet6:"]) { family = [line substringToIndex:line.length-1]; header = nil; continue; }
  NSArray *fields = [[line componentsSeparatedByCharactersInSet:space] filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if ([line hasPrefix:@"Destination "]) {
   header = fields; for (NSString *key in @[@"Destination", @"Gateway", @"Flags", @"Netif"]) if (![header containsObject:key]) return nil; continue;
  }
  if (!family || !header) return nil; NSMutableArray *values = [NSMutableArray arrayWithObject:family];
  for (NSString *key in @[@"Destination", @"Gateway", @"Flags", @"Netif"]) { NSUInteger index = [header indexOfObject:key];
   if (index >= fields.count || ![fields[index] length]) return nil; [values addObject:fields[index]]; }
  [entries addObject:[values componentsJoinedByString:@"|"]];
 }
 return entries.count ? [[entries sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"\n"] : nil;
}
static NSDictionary *hostSnapshot(void) {
 char *routes[] = {"/usr/sbin/netstat", "-rn", NULL}, *dns[] = {"/usr/sbin/scutil", "--dns", NULL}, *nat[] = {"/sbin/pfctl", "-sn", NULL};
 char *const *commands[] = {routes, dns, nat}; NSMutableDictionary *hashes = [NSMutableDictionary dictionary];
 NSArray *names = @[@"routes", @"dns", @"nat"];
 for (unsigned i = 0; i < 3; i++) {
  const char *parentPath = i < 2 ? "/usr/sbin" : "/sbin";
  const char *leaf = i == 0 ? "netstat" : i == 1 ? "scutil" : "pfctl";
  int parent = directory(parentPath), executable = parent < 0 ? -1 : openat(parent, leaf, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  bool secure = secureFD(executable, false, 0); if (executable >= 0) close(executable); if (parent >= 0) close(parent);
  if (!secure) return nil;
  int status = -1; NSData *data = fixedProcess(commands[i][0], (char *const *)commands[i], nil, &status, false);
  if (!data || status != 0) return nil; NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (i == 0) text = normalizedRoutes(text); if (!text) return nil; hashes[names[i]] = hashText(text); }
 int configParent = directory("/private/etc");
 int fd = configParent < 0 ? -1 : openat(configParent, "pf.conf", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
 if (configParent >= 0) close(configParent);
 if (!secureFD(fd, false, 0)) { if (fd >= 0) close(fd); return nil; }
 struct stat before, after; if (fstat(fd, &before) || before.st_size < 0 || before.st_size > 1024*1024) { close(fd); return nil; }
 NSMutableData *data = [NSMutableData data]; unsigned char bytes[4096]; ssize_t count;
 while ((count = read(fd, bytes, sizeof(bytes))) > 0 && data.length + (size_t)count <= 1024*1024) [data appendBytes:bytes length:(NSUInteger)count];
 bool stable = count == 0 && !fstat(fd, &after) && sameStat(&before, &after) && data.length == (NSUInteger)before.st_size;
 close(fd); NSString *text = stable ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
 if (!text) return nil; hashes[@"pfconf"] = hashText(text); return hashes;
}


#define RUNTIME INSTALL_PARENT "/io.envara.pf-runtime"
#define FIXED_ENV @"f285429a-61e4-4023-8749-ec9073ce6a39"
#define CAPSULE "io.envara.pf-retired-46ae-90401ced"
#define RECOVERY_SCHEMA @"envara.macos-pf-application-recovery/v1"
static bool integer(id v,uint64_t *out){if(![v isKindOfClass:NSNumber.class]||isBool(v))return false;double x=[v doubleValue];if(!isfinite(x)||x<0||x!=floor(x)||x>9007199254740991.)return false;*out=[v unsignedLongLongValue];return true;}
static NSData *privateRead(int parent,const char *name,size_t max,struct stat *identity){int fd=openat(parent,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(!secureFD(fd,false,0600)){if(fd>=0)close(fd);return nil;}struct stat before,after,named;NSMutableData *d=[NSMutableData data];unsigned char b[4096];ssize_t n=0;bool ok=!fstat(fd,&before)&&before.st_size>0&&(uint64_t)before.st_size<=max;while(ok&&(n=read(fd,b,sizeof(b)))>0){if(d.length+(size_t)n>max){ok=false;break;}[d appendBytes:b length:(NSUInteger)n];}if(ok)ok=n==0&&!fstat(fd,&after)&&!fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)&&sameStat(&before,&after)&&sameStat(&after,&named)&&d.length==(NSUInteger)before.st_size;close(fd);if(!ok)return nil;if(identity)*identity=after;return d;}
static bool unchanged(int parent,const char *name,struct stat *original,NSData *bytes){struct stat after;return [privateRead(parent,name,65536,&after) isEqual:bytes]&&sameStat(original,&after);}
static bool absent(int parent,const char *name){struct stat s;return fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;}
static bool names(int fd,NSArray *allowed){int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(scan<0)return false;DIR*d=fdopendir(scan);if(!d){close(scan);return false;}NSMutableSet*s=[NSMutableSet set];struct dirent*e;errno=0;bool ok=true;while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;NSString*n=@(e->d_name);if(![allowed containsObject:n]){ok=false;break;}[s addObject:n];errno=0;}if(errno)ok=false;closedir(d);return ok&&s.count==allowed.count;}
static NSString *command(char *const argv[],bool mutation,int *code){NSData*d=fixedProcess(argv[0],argv,nil,code,mutation);return d?[[NSString alloc]initWithData:d encoding:NSUTF8StringEncoding]:nil;}
/* Read-only six active rule classes. Unknown/inactive internals remain unclaimed.
 * Native exact DELETE independently repeats its pinned six-class proof. */
static bool pfEmpty(void) {
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC);if(fd<0)return false;
 const uint8_t actions[]={0,2,4,6,8,11};bool ok=true;
 for(size_t i=0;i<sizeof(actions);i++){
  EnvaraPFHookRequest a={0},b={0};strcpy(a.anchor,CANARY_ANCHOR.UTF8String);a.rule.action=actions[i];b=a;
  if(ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&a)||a.nr||ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&b)||b.nr||a.ticket!=b.ticket){ok=false;break;}
 }
 close(fd);if(!ok)return false;
 int c=0;char*t[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)"Tables",NULL};
 char*a[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)"Anchors",NULL};
 for(int i=0;i<2;i++){NSString*v=command(i?t:a,false,&c);if(!v||c||[v stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length)return false;}
 return true;
}
static bool stillGone(pid_t pid){struct proc_bsdinfo p={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&p,sizeof(p));return n==0&&errno==ESRCH;}
/* The failed ACK did not persist keeper/core/front births. Complete process
 * snapshots still refuse every installed runtime or owned Snapshot component.
 * Only the original Notion family may be unrelated: its complete credentials
 * must belong to the sealed console UID and exclude the sealed realm GID in
 * both stable scans. This never replaces the independent global GID proof. */
#define ROOT_PROCESS_CAPACITY 16384
_Static_assert(sizeof(((struct kinfo_proc *)0)->kp_eproc.e_ucred.cr_groups)==NGROUPS*sizeof(gid_t),"complete supplementary group vector");
typedef struct {
 struct proc_bsdinfo bsd;
 unsigned groupCount;
 gid_t groups[NGROUPS];
 unsigned char pathHash[CC_SHA256_DIGEST_LENGTH];
 bool original;
} ComponentCredentials;
/* Private compiled callbacks are used by inert tests only. The production
 * entry always supplies the native readers and requires real/effective root. */
typedef struct {
 void *context;
 int (*list)(void *,pid_t *);
 int (*bsd)(void *,pid_t,struct proc_bsdinfo *);
 int (*path)(void *,pid_t,char *,uint32_t);
 int (*supplementary)(void *,pid_t,struct kinfo_proc *,size_t *);
 int (*capacity)(void *,unsigned *);
} ComponentReaders;
static int pidOrder(const void*a,const void*b){pid_t x=*(const pid_t*)a,y=*(const pid_t*)b;return (x>y)-(x<y);}
static int processList(pid_t*list){
 int estimate=proc_listallpids(NULL,0);if(estimate<=0||estimate>=ROOT_PROCESS_CAPACITY)return -1;
 int n=proc_listallpids(list,ROOT_PROCESS_CAPACITY*(int)sizeof(pid_t));if(n<=0||n>=ROOT_PROCESS_CAPACITY||proc_listallpids(NULL,0)>=ROOT_PROCESS_CAPACITY)return -1;
 int count=0;for(int i=0;i<n;i++){if(list[i]<0)return -1;if(list[i])list[count++]=list[i];}
 qsort(list,(size_t)count,sizeof(pid_t),pidOrder);for(int i=1;i<count;i++)if(list[i]==list[i-1])return -1;return count;
}
static bool componentBSDValid(const struct proc_bsdinfo*p,pid_t pid,int bytes){
 return p&&bytes==sizeof(*p)&&pid>0&&p->pbi_pid==(uint32_t)pid&&p->pbi_start_tvsec&&p->pbi_start_tvusec<1000000&&p->pbi_status>=SIDL&&p->pbi_status<=SZOMB;
}
static bool componentSameBSD(const struct proc_bsdinfo*a,const struct proc_bsdinfo*b){
 return a->pbi_pid==b->pbi_pid&&a->pbi_start_tvsec==b->pbi_start_tvsec&&a->pbi_start_tvusec==b->pbi_start_tvusec&&a->pbi_status==b->pbi_status&&
  a->pbi_uid==b->pbi_uid&&a->pbi_ruid==b->pbi_ruid&&a->pbi_svuid==b->pbi_svuid&&a->pbi_gid==b->pbi_gid&&a->pbi_rgid==b->pbi_rgid&&a->pbi_svgid==b->pbi_svgid;
}
static bool componentDecodeGroups(const struct kinfo_proc*p,int status,size_t bytes,const struct proc_bsdinfo*bsd,ComponentCredentials*out){
 if(!p||!bsd||!out||status||bytes!=sizeof(*p)||p->kp_proc.p_pid!=(pid_t)bsd->pbi_pid||p->kp_proc.p_starttime.tv_sec<=0||p->kp_proc.p_starttime.tv_usec<0||p->kp_proc.p_starttime.tv_usec>=1000000||
  (uint64_t)p->kp_proc.p_starttime.tv_sec!=bsd->pbi_start_tvsec||(uint64_t)p->kp_proc.p_starttime.tv_usec!=bsd->pbi_start_tvusec||(unsigned char)p->kp_proc.p_stat!=bsd->pbi_status||
  p->kp_eproc.e_ucred.cr_uid!=bsd->pbi_uid||p->kp_eproc.e_pcred.p_ruid!=bsd->pbi_ruid||p->kp_eproc.e_pcred.p_svuid!=bsd->pbi_svuid||
  p->kp_eproc.e_pcred.p_rgid!=bsd->pbi_rgid||p->kp_eproc.e_pcred.p_svgid!=bsd->pbi_svgid)return false;
 int count=p->kp_eproc.e_ucred.cr_ngroups;if(count<1||count>NGROUPS||p->kp_eproc.e_ucred.cr_groups[0]!=bsd->pbi_gid)return false;
 for(int i=0;i<count;i++)for(int j=0;j<i;j++)if(p->kp_eproc.e_ucred.cr_groups[i]==p->kp_eproc.e_ucred.cr_groups[j])return false;
 out->bsd=*bsd;out->groupCount=(unsigned)count;memcpy(out->groups,p->kp_eproc.e_ucred.cr_groups,(size_t)count*sizeof(gid_t));return true;
}
static bool originalNotionUnrelated(const ComponentCredentials*p,uid_t consoleUID,gid_t realmGID){
 if(!p||!consoleUID||realmGID<7100||realmGID>7999||!componentBSDValid(&p->bsd,(pid_t)p->bsd.pbi_pid,sizeof(p->bsd))||p->bsd.pbi_status==SZOMB||
  p->bsd.pbi_uid!=consoleUID||p->bsd.pbi_ruid!=consoleUID||p->bsd.pbi_svuid!=consoleUID||p->groupCount<1||p->groupCount>NGROUPS||p->groups[0]!=p->bsd.pbi_gid||
  p->bsd.pbi_gid==realmGID||p->bsd.pbi_rgid==realmGID||p->bsd.pbi_svgid==realmGID)return false;
 for(unsigned i=0;i<p->groupCount;i++){if(p->groups[i]==realmGID)return false;for(unsigned j=0;j<i;j++)if(p->groups[i]==p->groups[j])return false;}
 return true;
}
static bool componentSameOriginal(const ComponentCredentials*a,const ComponentCredentials*b){
 return a->original&&b->original&&componentSameBSD(&a->bsd,&b->bsd)&&a->groupCount==b->groupCount&&
  !memcmp(a->groups,b->groups,a->groupCount*sizeof(gid_t))&&!memcmp(a->pathHash,b->pathHash,sizeof(a->pathHash));
}
static int componentPathClass(const char*p){
 if(!strcmp(p,NATIVE)||!strcmp(p,INSTALL "/node")||!strcmp(p,INSTALL "/mihomo")||!strncmp(p,"/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/",sizeof("/Library/PrivilegedHelperTools/io.envara.pf-apps/objects/")-1))return 2;
 return !strncmp(p,"/Applications/Notion.app/",sizeof("/Applications/Notion.app/")-1)?1:0;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void componentPathHash(const char*path,unsigned char*out){CC_SHA256(path,(CC_LONG)strlen(path),out);}
#pragma clang diagnostic pop
static NSString *componentFailureReason=@"component-lease";
static uint32_t componentFailurePid=0;
static bool componentsAbsentWithReaders(NSDictionary*sealedLease,const ComponentReaders*readers){
 uint64_t uid,gid;unsigned capacity=0;componentFailureReason=@"component-lease";componentFailurePid=0;
 if(!integer(sealedLease[@"consoleUID"],&uid)||!uid||uid>UINT32_MAX||!integer(sealedLease[@"gid"],&gid)||gid<7100||gid>7999||!readers||!readers->list||!readers->bsd||!readers->path||!readers->supplementary||!readers->capacity)return false;
 if(readers->capacity(readers->context,&capacity)||capacity!=NGROUPS){componentFailureReason=@"component-capacity";return false;}
 pid_t*first=calloc(ROOT_PROCESS_CAPACITY,sizeof(pid_t)),*second=calloc(ROOT_PROCESS_CAPACITY,sizeof(pid_t));
 ComponentCredentials*baseline=calloc(ROOT_PROCESS_CAPACITY,sizeof(ComponentCredentials));bool ok=false;int count;
 if(!first||!second||!baseline){componentFailureReason=@"component-memory";goto done;}
 if((count=readers->list(readers->context,first))<=0||count>=ROOT_PROCESS_CAPACITY){componentFailureReason=@"component-list-first";goto done;}
 for(int pass=0;pass<2;pass++){
  pid_t*list=pass?second:first;componentFailurePid=0;if(pass){int secondCount=readers->list(readers->context,second);if(secondCount!=count||memcmp(first,second,(size_t)count*sizeof(pid_t))){componentFailureReason=secondCount<=0?@"component-list-second":@"component-inventory-change";goto done;}}
  for(int i=0;i<count;i++){
   componentFailurePid=list[i]>0?(uint32_t)list[i]:0;
   if(interrupted||seconds()+2>=rootDeadline){componentFailureReason=@"component-deadline";goto done;}
   if(list[i]<=0||(i&&list[i]<=list[i-1])){componentFailureReason=@"component-inventory-change";goto done;}
   struct proc_bsdinfo before={0},after={0};ComponentCredentials observed={0};
   if(!componentBSDValid(&before,list[i],readers->bsd(readers->context,list[i],&before))){componentFailureReason=@"component-bsd-before";goto done;}
   if(before.pbi_status!=SZOMB){
    char executable[PROC_PIDPATHINFO_MAXSIZE]={0};int n=readers->path(readers->context,list[i],executable,sizeof(executable));
    if(n<=0||n>=(int)sizeof(executable)||!memchr(executable,0,sizeof(executable))){componentFailureReason=@"component-path-read";goto done;}
    int kind=componentPathClass(executable);if(kind==2){componentFailureReason=@"component-owned-runtime-live";goto done;}
    if(kind==1){struct kinfo_proc info={0};size_t bytes=sizeof(info);int status=readers->supplementary(readers->context,list[i],&info,&bytes);
     if(!componentDecodeGroups(&info,status,bytes,&before,&observed)||!originalNotionUnrelated(&observed,(uid_t)uid,(gid_t)gid)){componentFailureReason=@"component-notion-groups";goto done;}
     observed.original=true;componentPathHash(executable,observed.pathHash);
    }
   }
   if(!componentBSDValid(&after,list[i],readers->bsd(readers->context,list[i],&after))){componentFailureReason=@"component-bsd-after";goto done;}
   if(!componentSameBSD(&before,&after)){componentFailureReason=@"component-identity-change";goto done;}
   observed.bsd=after;
   if(pass&&(!componentSameBSD(&baseline[i].bsd,&after)||baseline[i].original!=observed.original||(observed.original&&!componentSameOriginal(&baseline[i],&observed)))){componentFailureReason=@"component-baseline-change";goto done;}
   if(!pass)baseline[i]=observed;
  }
 }
 componentFailurePid=0;capacity=0;if(readers->capacity(readers->context,&capacity)||capacity!=NGROUPS){componentFailureReason=@"component-capacity";goto done;}
 if(interrupted||seconds()+2>=rootDeadline){componentFailureReason=@"component-deadline";goto done;}
 ok=true;componentFailureReason=nil;componentFailurePid=0;
 done:free(first);free(second);free(baseline);return ok;
}
static int componentNativeList(void*context,pid_t*pids){(void)context;return processList(pids);}
static int componentNativeBSD(void*context,pid_t pid,struct proc_bsdinfo*out){(void)context;return proc_pidinfo(pid,PROC_PIDTBSDINFO,1,out,sizeof(*out));}
static int componentNativePath(void*context,pid_t pid,char*out,uint32_t size){(void)context;return proc_pidpath(pid,out,size);}
static int componentNativeSupplementary(void*context,pid_t pid,struct kinfo_proc*out,size_t*bytes){(void)context;int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,pid};return sysctl(mib,4,out,bytes,NULL,0);}
static int componentNativeCapacity(void*context,unsigned*out){(void)context;int capacity=0;size_t bytes=sizeof(capacity);if(sysctlbyname("kern.ngroups",&capacity,&bytes,NULL,0)||bytes!=sizeof(capacity)||capacity!=NGROUPS)return -1;*out=(unsigned)capacity;return 0;}
static bool componentsAbsent(NSDictionary*sealedLease){
 if(getuid()||geteuid()){componentFailureReason=@"component-lease";componentFailurePid=0;return false;}
 const ComponentReaders readers={NULL,componentNativeList,componentNativeBSD,componentNativePath,componentNativeSupplementary,componentNativeCapacity};
 return componentsAbsentWithReaders(sealedLease,&readers);
}
static bool rootProof(NSDictionary*p){return p&&isBool(p[@"ok"])&&[p[@"ok"]boolValue]&&[p[@"pinsVerified"]boolValue]&&[p[@"originalRootCompatible"]boolValue]&&[p[@"priorAnchorsCompatible"]boolValue]&&[p[@"originalRootSHA256"]isEqual:ROOT_RULE]&&[p[@"originalRootTextSHA256"]isEqual:ROOT_TEXT];}
static bool contextShape(NSDictionary*r,NSDictionary*l,NSData*leaseBytes,uint64_t *gid,uint64_t *pid,NSString **realmOut,NSDictionary **hookOut,NSString **groupOut,NSString **tokenOut){
 NSArray*lk=@[@"schema",@"runId",@"environmentId",@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId",@"consoleUID",@"gid",@"cwd",@"timezone",@"locale",@"issuedMonotonicMs",@"expiresMonotonicMs",@"bootTimeSeconds",@"controllerPid",@"controllerBirth",@"ipv4Address",@"rootHookLease"];
 if(!keys(l,lk)||![l[@"schema"]isEqual:@"envara.macos-pf-app-bound-lease/v1"]||![l[@"runId"]isEqual:CANARY_RUN]||![l[@"environmentId"]isEqual:FIXED_ENV]||![r[@"schema"]isEqual:@"envara.macos-pf-owned-registry/v1"]||![r[@"runId"]isEqual:CANARY_RUN]||![r[@"anchor"]isEqual:CANARY_ANCHOR]||![r[@"phase"]isEqual:@"cleanup-required"]||!isBool(r[@"cleanupUncertain"])||![r[@"cleanupUncertain"]boolValue]||!integer(l[@"gid"],gid)||*gid<7100||*gid>7999||!integer(l[@"controllerPid"],pid)||*pid<2||*pid>INT32_MAX||![r[@"supervisorPid"]isEqual:l[@"controllerPid"]])return false;
 uint64_t uid,issued,expires,boot;NSString*uuidPattern=@"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
 if(!keys(r,@[@"schema",@"runId",@"supervisorPid",@"anchor",@"phase",@"cleanupUncertain",@"rootHook",@"ownedPFReference",@"filterReplacement",@"filterReceipt",@"application",@"incompleteGroupAllocations",@"realms",@"guardians"])||!integer(l[@"consoleUID"],&uid)||!uid||uid>UINT32_MAX||!integer(l[@"issuedMonotonicMs"],&issued)||!integer(l[@"expiresMonotonicMs"],&expires)||expires<=issued||expires-issued>180000||!integer(l[@"bootTimeSeconds"],&boot)||!boot||!regex(l[@"controllerBirth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$")||!regex(l[@"cwd"],@"^/[^\n]{1,4094}$")||!regex(l[@"timezone"],@"^[A-Za-z0-9_+/-]{1,128}$")||!regex(l[@"locale"],@"^[A-Za-z0-9_-]{1,64}$")||![l[@"ipv4Address"]isEqual:@"198.18.1.1"])return false;
 for(NSString*k in @[@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId"])if(!regex(l[k],uuidPattern))return false;
 NSDictionary*app=r[@"application"],*root=r[@"rootHook"],*pfe=r[@"ownedPFReference"];NSArray*realms=r[@"realms"];
 if(!keys(root,@[@"mutationAttempted",@"verified",@"removed",@"receiptRetired",@"namespaceState",@"namespaceReclaimed",@"lease"])||!isBool(root[@"mutationAttempted"])||![root[@"mutationAttempted"]boolValue]||!isBool(root[@"namespaceReclaimed"])||[root[@"namespaceReclaimed"]boolValue]||![@[@"unknown",@"present"]containsObject:root[@"namespaceState"]]||!keys(pfe,@[@"attempted",@"acquired",@"released",@"token"])||!isBool(pfe[@"attempted"])||![pfe[@"attempted"]boolValue])return false;
 if(!keys(app,@[@"environmentId",@"routeId",@"registrationId",@"versionId",@"ticketId",@"leaseSHA256",@"transport",@"child",@"resumed"])||![app[@"environmentId"]isEqual:FIXED_ENV]||![app[@"registrationId"]isEqual:l[@"registrationId"]]||![app[@"versionId"]isEqual:l[@"versionId"]]||![app[@"leaseSHA256"]isEqual:hashText([[NSString alloc]initWithData:leaseBytes encoding:NSUTF8StringEncoding])]||!isBool(app[@"resumed"])||[app[@"resumed"]boolValue]||app[@"transport"]!=NSNull.null||app[@"child"]!=NSNull.null||![realms isKindOfClass:NSArray.class]||realms.count!=1||![r[@"guardians"]isEqual:@[]]||![r[@"incompleteGroupAllocations"]isEqual:@[]]||r[@"filterReplacement"]!=NSNull.null||r[@"filterReceipt"]!=NSNull.null)return false;
 NSDictionary*realm=realms[0];if(!keys(realm,@[@"environmentId",@"realmId",@"gid",@"groupPath",@"mode",@"tunnel",@"fixtures"])||!regex(app[@"ticketId"],uuidPattern)||!regex(app[@"routeId"],@"^pf_[0-9a-f]{32}$"))return false;NSString*group=[NSString stringWithFormat:@"/Groups/_envara_pf_%llu",(unsigned long long)*gid];
 if(![realm[@"environmentId"]isEqual:FIXED_ENV]||![realm[@"realmId"]isEqual:l[@"realmId"]]||![realm[@"gid"]isEqual:l[@"gid"]]||![realm[@"groupPath"]isEqual:group]||![realm[@"mode"]isEqual:@"blocked"]||realm[@"tunnel"]!=NSNull.null||![realm[@"fixtures"]isEqual:@[]]||!validLease(root[@"lease"])||![root[@"lease"]isEqual:l[@"rootHookLease"]]||!isBool(root[@"verified"])||![root[@"verified"]boolValue]||!isBool(root[@"removed"])||[root[@"removed"]boolValue]||!isBool(root[@"receiptRetired"])||[root[@"receiptRetired"]boolValue]||!isBool(pfe[@"acquired"])||![pfe[@"acquired"]boolValue]||!isBool(pfe[@"released"])||[pfe[@"released"]boolValue]||!regex(pfe[@"token"],@"^[1-9][0-9]{0,19}$")||!regex(l[@"realmId"],@"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))return false;
 *realmOut=l[@"realmId"];*hookOut=root[@"lease"];*groupOut=group;*tokenOut=pfe[@"token"];return true;
}
static int emit(NSDictionary*v){NSData*d=[NSJSONSerialization dataWithJSONObject:v options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!d||fwrite(d.bytes,1,d.length,stdout)!=d.length||fputc('\n',stdout)==EOF)return 1;fflush(stdout);return [v[@"ok"]boolValue]?0:1;}
static NSMutableDictionary *outcome(bool cleanup){return [@{@"schema":RECOVERY_SCHEMA,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"readOnly":@((BOOL)!cleanup),@"ok":@NO,@"cleanupUncertain":@YES,@"rootHookRemoved":@NO,@"namespaceReclaimed":@NO,@"receiptRetired":@NO,@"ownedPFReferenceReleased":@NO,@"ownedGroupRemoved":@NO,@"runtimeArchived":@NO,@"cleanupConfirmed":@NO,@"originalHostBaselineVerified":@NO,@"interactiveAuthorizationAllowed":@NO,@"bootstrapIdentityBound":@NO,@"reason":@"RECOVERY_PREFLIGHT_REFUSED",@"preflightGate":@"not-started",@"componentPid":@0}mutableCopy];}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool rights(void){AuthorizationRef r=NULL;if(geteuid()||AuthorizationCopyPrivilegedReference(&r,0)!=errAuthorizationSuccess||!r)return false;AuthorizationItem item={kAuthorizationRightExecute,0,NULL,0};AuthorizationRights rs={1,&item};bool ok=AuthorizationCopyRights(r,&rs,kAuthorizationEmptyEnvironment,0,NULL)==errAuthorizationSuccess;AuthorizationFree(r,0);return ok;}
#pragma clang diagnostic pop
static int recover(bool mutate){NSMutableDictionary*out=outcome(mutate);rootDeadline=seconds()+175;out[@"preflightGate"]=@"rights";if(!rights())return emit(out);out[@"preflightGate"]=@"root-credentials";gid_t zero=0;if(setgroups(1,&zero)||setgid(0)||setuid(0)||getuid()||geteuid())return emit(out);umask(077);struct sigaction sa={0};sa.sa_handler=onSignal;sigemptyset(&sa.sa_mask);for(int i=0;i<4;i++){int signals[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};if(sigaction(signals[i],&sa,NULL))return emit(out);}sa.sa_handler=SIG_DFL;if(sigaction(SIGCHLD,&sa,NULL))return emit(out);
 int parent=-1,installed=-1,runtime=-1,lock=-1,run=-1,state=-1,cap=-1;NSData*rb=nil,*lb=nil,*lockBytes=nil;struct stat ri,li,rooti,locki,parenti,runi,statei,capi;NSDictionary*record=nil,*lease=nil,*hook=nil,*proof=nil,*hostBefore=nil,*hostAfter=nil;NSString*realm=nil,*group=nil,*token=nil;uint64_t gid=0,pid=0;int code=0;
 do{out[@"preflightGate"]=@"root-parent";parent=directory(INSTALL_PARENT);if(parent<0||flock(parent,LOCK_EX|LOCK_NB)||fstat(parent,&parenti))break;out[@"preflightGate"]=@"installed-inventory";installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(installed<0)break;out[@"preflightGate"]=@"private-runtime";runtime=directory(RUNTIME);if(!secureFD(runtime,true,0700)||fstat(runtime,&rooti))break;out[@"preflightGate"]=@"registry-lock";lock=openat(runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(lock,false,0600)||flock(lock,LOCK_EX|LOCK_NB)||fstat(lock,&locki))break;out[@"preflightGate"]=@"registry-shape";rb=privateRead(runtime,"registry.json",65536,&ri);record=strictJSON(rb,65536);lockBytes=privateRead(runtime,"registry.lock",4096,NULL);NSDictionary*lockValue=strictJSON(lockBytes,4096);if(!keys(lockValue,@[@"runId",@"pid",@"anchor"])||![lockValue[@"runId"]isEqual:CANARY_RUN]||![lockValue[@"anchor"]isEqual:CANARY_ANCHOR]||![lockValue[@"pid"]isEqual:record[@"supervisorPid"]])break;out[@"preflightGate"]=@"run-directory";run=openat(runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(run,true,0700)||fstat(run,&runi))break;out[@"preflightGate"]=@"lease-shape";lb=privateRead(run,"app-bound-lease.json",16384,&li);lease=strictJSON(lb,16384);if(!contextShape(record,lease,lb,&gid,&pid,&realm,&hook,&group,&token))break;
 out[@"preflightGate"]=@"state-directory";state=openat(run,realm.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(state,true,0700)||fstat(state,&statei))break;
 out[@"preflightGate"]=@"empty-state-shape";if(!names(state,@[])||!names(run,@[@"app-bound-lease.json",realm])||!names(runtime,@[@"registry.json",@"registry.lock",CANARY_RUN]))break;
 out[@"preflightGate"]=@"filter-journal-absent";if(!absent(run,"app-filter-events"))break;
 out[@"preflightGate"]=@"controller-gone";if(!stillGone((pid_t)pid))break;
 out[@"preflightGate"]=@"gid-scope-absent";if(envara_app_scope_gid_absent((gid_t)gid)!=1)break;
 out[@"preflightGate"]=@"components-absent";if(!componentsAbsent(lease)){out[@"preflightGate"]=componentFailureReason;out[@"componentPid"]=@(componentFailurePid);break;}
 out[@"preflightGate"]=@"pf-empty";if(!pfEmpty())break;
 out[@"preflightGate"]=@"dedicated-group";struct group*g=getgrgid((gid_t)gid);NSString*name=[group lastPathComponent];if(!g||g->gr_gid!=gid||strcmp(g->gr_name,name.UTF8String)||(g->gr_mem&&g->gr_mem[0]))break;
 out[@"preflightGate"]=@"root-hook-readback";proof=nativeCall(0,@{@"lease":hook},&code,installed);if(!rootProof(proof)||code||![proof[@"hookInstalled"]boolValue]||![proof[@"ownedRootHookVerified"]boolValue]||![proof[@"runLedgerState"]isEqual:@"issued"])break;
 out[@"preflightGate"]=@"preflight-complete";out[@"preflightVerified"]=@YES;out[@"ownedGIDScopeAbsent"]=@YES;out[@"ownedFilterEmpty"]=@YES;out[@"rootRuntimeComponentsAbsent"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_PREFLIGHT_VERIFIED";if(!mutate)break;out[@"ok"]=@NO;out[@"reason"]=@"CLEANUP_UNCONFIRMED";hostBefore=hostSnapshot();if(!hostBefore)break;
 if(seconds()+60>=rootDeadline||interrupted||!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&locki,lockBytes)||!unchanged(run,"app-bound-lease.json",&li,lb)||envara_app_scope_gid_absent((gid_t)gid)!=1||!componentsAbsent(lease)||!pfEmpty())break;
 int intent=openat(run,"recovery-46ae.intent",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);const char marker[]="fixed46ae/run904 cleanup attempted; never replay token or DELETE\n";if(!secureFD(intent,false,0600)||write(intent,marker,sizeof(marker)-1)!=sizeof(marker)-1||fsync(intent)||fsync(run)){if(intent>=0)close(intent);break;}close(intent);
 char*x[]={(char*)"/sbin/pfctl",(char*)"-X",(char*)token.UTF8String,NULL};NSString*xout=command(x,true,&code);if(!xout||code)break;out[@"ownedPFReferenceReleased"]=@YES;proof=nativeCall(0,@{@"lease":hook},&code,installed);if(!rootProof(proof)||code||![proof[@"pfDisabled"]boolValue]||![proof[@"runLedgerState"]isEqual:@"issued"]||!pfEmpty()||envara_app_scope_gid_absent((gid_t)gid)!=1||!componentsAbsent(lease))break;
 out[@"deleteAttempted"]=@YES;NSDictionary*deleted=nativeCall(2,@{@"lease":hook},&code,installed);NSDictionary*after=nativeCall(0,@{@"lease":hook},&code,installed);(void)deleted;if(!rootProof(after)||code||![after[@"pfDisabled"]boolValue]||![after[@"ownedRootHookRemoved"]boolValue]||![after[@"originalRootRestored"]boolValue]||![after[@"receiptRetired"]boolValue]||![after[@"namespaceReclaimed"]boolValue]||![after[@"namespaceState"]isEqual:@"absent"]||![after[@"runLedgerState"]isEqual:@"retired"])break;
 out[@"rootHookRemoved"]=@YES;out[@"namespaceReclaimed"]=@YES;out[@"receiptRetired"]=@YES;if(envara_app_scope_gid_absent((gid_t)gid)!=1||!componentsAbsent(lease))break;g=getgrgid((gid_t)gid);if(!g||strcmp(g->gr_name,name.UTF8String)||(g->gr_mem&&g->gr_mem[0]))break;char*delgroup[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-delete",(char*)group.UTF8String,NULL};if(!command(delgroup,true,&code)||code)break;errno=0;if(getgrgid((gid_t)gid)!=NULL||errno)break;out[@"ownedGroupRemoved"]=@YES;
 if(!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&locki,lockBytes)||!unchanged(run,"app-bound-lease.json",&li,lb)||!names(state,@[])||!names(run,@[@"app-bound-lease.json",realm,@"recovery-46ae.intent"])||!names(runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!absent(parent,CAPSULE)||envara_app_scope_gid_absent((gid_t)gid)!=1||!componentsAbsent(lease))break;
 hostAfter=hostSnapshot();if(!hostAfter||![hostBefore isEqual:hostAfter])break;out[@"recoveryHostNetworkUnchanged"]=@YES;
 if(mkdirat(parent,CAPSULE,0700))break;cap=openat(parent,CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(cap,true,0700)||fstat(cap,&capi)||!names(cap,@[]))break;NSData*receipt=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];int receiptfd=openat(cap,"recovery-proof.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(!secureFD(receiptfd,false,0600)||write(receiptfd,receipt.bytes,receipt.length)!=(ssize_t)receipt.length||fsync(receiptfd)||fsync(cap)||fsync(parent)){if(receiptfd>=0)close(receiptfd);break;}close(receiptfd);struct stat receipti;NSData*readReceipt=privateRead(cap,"recovery-proof.json",16384,&receipti);if(![readReceipt isEqual:receipt])break;struct stat current,parentNow,runNow,stateNow,capNow;if(fstat(parent,&parentNow)||parentNow.st_dev!=parenti.st_dev||parentNow.st_ino!=parenti.st_ino||!secureFD(parent,true,0)||fstatat(parent,CAPSULE,&capNow,AT_SYMLINK_NOFOLLOW)||capNow.st_dev!=capi.st_dev||capNow.st_ino!=capi.st_ino||fstatat(runtime,CANARY_RUN.UTF8String,&runNow,AT_SYMLINK_NOFOLLOW)||runNow.st_dev!=runi.st_dev||runNow.st_ino!=runi.st_ino||fstatat(run,realm.UTF8String,&stateNow,AT_SYMLINK_NOFOLLOW)||stateNow.st_dev!=statei.st_dev||stateNow.st_ino!=statei.st_ino||!names(state,@[])||!unchanged(cap,"recovery-proof.json",&receipti,receipt)||fstatat(parent,"io.envara.pf-runtime",&current,AT_SYMLINK_NOFOLLOW)||current.st_dev!=rooti.st_dev||current.st_ino!=rooti.st_ino||!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&locki,lockBytes)||!unchanged(run,"app-bound-lease.json",&li,lb)||!names(cap,@[@"recovery-proof.json"])||interrupted||seconds()+5>=rootDeadline)break;
 if(renameatx_np(parent,"io.envara.pf-runtime",cap,"runtime",RENAME_EXCL)||fsync(cap)||fsync(parent)||!absent(parent,"io.envara.pf-runtime")||fstatat(cap,"runtime",&current,AT_SYMLINK_NOFOLLOW)||current.st_dev!=rooti.st_dev||current.st_ino!=rooti.st_ino||!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&locki,lockBytes)||!unchanged(run,"app-bound-lease.json",&li,lb)||!names(state,@[])||!names(run,@[@"app-bound-lease.json",realm,@"recovery-46ae.intent"])||!names(runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!unchanged(cap,"recovery-proof.json",&receipti,receipt)||!names(cap,@[@"runtime",@"recovery-proof.json"]))break;out[@"runtimeArchived"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"cleanupConfirmed"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"EXACT_RECOVERY_COMPLETED";
 }while(0);if(cap>=0)close(cap);if(state>=0)close(state);if(run>=0)close(run);if(lock>=0)close(lock);if(runtime>=0)close(runtime);if(installed>=0)close(installed);if(parent>=0)close(parent);return emit(out);}
/* AEXWP may interact even after noninteractive CopyRights. No launch path is
 * advertised as noninteractive. These request modes never call Authorization,
 * sudo, a daemon, or a privileged child; user must return before a reviewed
 * interactive carrier can be added. Root internal modes retain strict rights. */
static int requestRecovery(bool cleanup) {
 NSMutableDictionary *v=outcome(cleanup);v[@"readOnly"]=@YES;
 v[@"reason"]=@"NONINTERACTIVE_PRIVILEGED_EXECUTION_UNAVAILABLE";return emit(v);
}
#ifndef RECOVERY_INERT
int main(int argc,char**argv){@autoreleasepool{if(argc>2)return emit(outcome(false));const char*m=argc==1?"--plan":argv[1];if(!strcmp(m,"--plan")){NSMutableDictionary*p=outcome(false);p[@"ok"]=@YES;p[@"cleanupUncertain"]=@YES;p[@"reason"]=@"INERT_PLAN";p[@"runtimeLeafCount"]=@(sizeof(files)/sizeof(files[0]));return emit(p);}if(!strcmp(m,"--request-readonly-existing-rights"))return requestRecovery(false);if(!strcmp(m,"--request-cleanup-existing-rights"))return requestRecovery(true);if(!strcmp(m,"--inspect-fixed-root"))return recover(false);if(!strcmp(m,"--cleanup-fixed-root"))return recover(true);return emit(outcome(false));}}
#endif
