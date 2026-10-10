/* A standalone pinned-2a7 empty-hook experiment. Default --plan is inert.
 * The only mutating child operations are the installed v2 primitive's fixed
 * INSERT and once-only DELETE. No source RPC, PF enable/reference, rules,
 * groups, utun, DNS/route changes, application or arbitrary command input.
 * AuthorizationExecuteWithPrivileges has a user-writable bootstrap path
 * race; installed payload pinning does not attest this independent launcher.
 * SIGKILL/power loss/output loss may leave an issued lease in the root ledger.
 * Never rerun this compiled UUID; independent recovery requires review.
 */
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
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
#include "pf-run-canary-inventory-2a7.h"
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
 static const char *const operations[] = {"hook-status", "insert-owned-root-hook", "delete-owned-root-hook"};
 return operation < 3 ? operations[operation] : NULL;
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

static bool rootBaseline(NSDictionary *proof) {
 return proof && [proof[@"ok"] boolValue] && [proof[@"pfDisabled"] boolValue] && [proof[@"pinsVerified"] boolValue] &&
  [proof[@"originalRootCompatible"] boolValue] && [proof[@"priorAnchorsCompatible"] boolValue] && ![proof[@"hookInstalled"] boolValue] &&
  [proof[@"originalRootSHA256"] isEqual:ROOT_RULE] && [proof[@"originalRootTextSHA256"] isEqual:ROOT_TEXT] &&
  regex(proof[@"priorRulesetCountsSHA256"], @"^[0-9a-f]{64}$");
}
typedef NSDictionary *(^CanaryCall)(unsigned, NSDictionary *, int *);
typedef NSDictionary *(^CanarySnapshot)(void);
typedef bool (^CanaryPeerClosed)(void);
static bool stdoutPeerClosed(void) {
 struct pollfd p = {STDOUT_FILENO,0,0}; int result = poll(&p,1,0);
 return result < 0 || (result > 0 && (p.revents & (POLLHUP|POLLERR|POLLNVAL)));
}
static NSMutableDictionary *exchangeCanary(CanaryCall call, CanarySnapshot snapshot, CanaryPeerClosed peerClosed) {
 NSMutableDictionary *out = [@{@"reason": @"CANARY_PREFLIGHT_REFUSED", @"insertAttempted": @NO, @"insertReadbackVerified": @NO,
  @"deleteAttempted": @NO, @"deleteReceiptVerified": @NO, @"originalRootRestored": @NO, @"receiptRetired": @NO,
  @"namespaceReclaimed": @NO, @"namespaceState": @"unknown", @"hostNetworkRestored": @NO, @"emptyHookCycleVerified": @NO,
  @"cleanupUncertain": @NO, @"cleanupPending": @NO, @"ok": @NO} mutableCopy];
 int status = -1; NSDictionary *before = call(0, @{}, &status);
 out[@"diagnosticStage"] = @"BASELINE";
 if ([nativeReasons() containsObject:before[@"reason"]]) out[@"nativeReason"] = before[@"reason"];
 if (!rootBaseline(before)) return out;
 NSDictionary *selected = call(0, @{@"runId": CANARY_RUN}, &status);
 out[@"diagnosticStage"] = @"FRESH_RUN_PREFLIGHT";
 if ([nativeReasons() containsObject:selected[@"reason"]]) out[@"nativeReason"] = selected[@"reason"];
 if (!rootBaseline(selected) || ![selected[@"runLedgerState"] isEqual:@"unused"] || ![selected[@"namespaceState"] isEqual:@"absent"] ||
  ![selected[@"ownedRootHookCanCreate"] boolValue] || ![selected[@"canCreateOwnedHook"] boolValue] ||
  ![selected[@"priorRulesetCountsSHA256"] isEqual:before[@"priorRulesetCountsSHA256"]]) return out;
 NSDictionary *hostBefore = snapshot(); if (!hostBefore || interrupted || peerClosed() || rootDeadline - seconds() < INSERT_REQUIRED_SECONDS) return out;
 out[@"insertAttempted"] = @YES; out[@"cleanupUncertain"] = @YES; out[@"cleanupPending"] = @YES;
 out[@"diagnosticStage"] = @"INSERT";
 NSDictionary *insert = call(1, @{@"runId": CANARY_RUN}, &status);
 if ([nativeReasons() containsObject:insert[@"reason"]]) out[@"nativeReason"] = insert[@"reason"];
 NSDictionary *lease = validLease(insert[@"lease"]) ? insert[@"lease"] : nil;
 NSDictionary *readback = lease ? call(0, @{@"lease": lease}, &status) : nil;
 bool issued = readback && [readback[@"ok"] boolValue] && [readback[@"runLedgerState"] isEqual:@"issued"] &&
  [readback[@"ownedRootHookVerified"] boolValue] && [readback[@"hookInstalled"] boolValue] &&
  [readback[@"pfDisabled"] boolValue] && [readback[@"originalRootCompatible"] boolValue] && [readback[@"priorAnchorsCompatible"] boolValue] &&
  [readback[@"originalRootSHA256"] isEqual:ROOT_RULE] && [readback[@"originalRootTextSHA256"] isEqual:ROOT_TEXT] &&
  [readback[@"priorRulesetCountsSHA256"] isEqual:before[@"priorRulesetCountsSHA256"]];
 out[@"insertReadbackVerified"] = @((BOOL)(issued && [insert[@"ok"] boolValue]));
 /* Even interruption/readback failure does not skip known owned cleanup.
  * Only an exact persisted ISSUED receipt can open this one DELETE epoch;
  * native failed INSERT may already have consumed its own rollback intent. */
 bool deleteEligible = readback && [readback[@"ok"] boolValue] && [readback[@"runLedgerState"] isEqual:@"issued"] && [readback[@"pfDisabled"] boolValue];
 if (deleteEligible) {
  out[@"deleteAttempted"] = @YES;
  out[@"diagnosticStage"] = @"DELETE_ONCE";
  NSDictionary *deleted = call(2, @{@"lease": lease}, &status);
  if ([nativeReasons() containsObject:deleted[@"reason"]]) out[@"nativeReason"] = deleted[@"reason"];
  out[@"deleteReceiptVerified"] = @((BOOL)(deleted && [deleted[@"ok"] boolValue] && [deleted[@"ownedRootHookRemoved"] boolValue] &&
   [deleted[@"originalRootRestored"] boolValue] && [deleted[@"receiptRetired"] boolValue]));
 }
 /* A lost DELETE response is never retried. The sole next operation is a
  * read-only exact historical receipt check. No observed ticket is adopted. */
 NSDictionary *after = lease ? call(0, @{@"lease": lease}, &status) : call(0, @{@"runId": CANARY_RUN}, &status);
 NSDictionary *fresh = call(0, @{}, &status); NSDictionary *hostAfter = snapshot();
 bool restored = rootBaseline(fresh) && [fresh[@"priorRulesetCountsSHA256"] isEqual:before[@"priorRulesetCountsSHA256"]];
 bool retired = after && [after[@"ok"] boolValue] && [after[@"receiptRetired"] boolValue] && [after[@"runLedgerState"] isEqual:@"retired"] &&
  [after[@"ownedRootHookRemoved"] boolValue] && [after[@"originalRootRestored"] boolValue] && ![after[@"hookInstalled"] boolValue];
 bool hostRestored = hostAfter && [hostBefore isEqual:hostAfter];
 bool reclaimed = retired && [after[@"namespaceReclaimed"] boolValue] && [after[@"namespaceState"] isEqual:@"absent"];
 bool cycle = [out[@"insertReadbackVerified"] boolValue] && [out[@"deleteAttempted"] boolValue] && retired && restored && hostRestored;
 out[@"originalRootRestored"] = @((BOOL)restored); out[@"receiptRetired"] = @((BOOL)retired);
 out[@"hostNetworkRestored"] = @((BOOL)hostRestored); out[@"namespaceReclaimed"] = @((BOOL)reclaimed);
 out[@"namespaceState"] = after ? after[@"namespaceState"] : @"unknown";
 out[@"emptyHookCycleVerified"] = @((BOOL)cycle);
 out[@"cleanupUncertain"] = @((BOOL)(!retired || !restored || !hostRestored));
 out[@"cleanupPending"] = @((BOOL)(!retired || !restored || !hostRestored || !reclaimed));
 bool peerEnded = peerClosed();
 out[@"diagnosticStage"] = @"READ_ONLY_RESTORE";
 out[@"ok"] = @((BOOL)(cycle && reclaimed && !interrupted && !peerEnded));
 out[@"reason"] = !retired ? @"EXACT_RECEIPT_CLEANUP_UNCONFIRMED" : !restored || !hostRestored ? @"BASELINE_RESTORATION_UNCONFIRMED" :
  !reclaimed ? @"ROOT_RESTORED_NAMESPACE_RETAINED" : interrupted || peerEnded ? @"INTERRUPTED_AFTER_OWNED_CLEANUP" : cycle ? @"BOUNDED_EMPTY_V2_HOOK_CYCLE_RESTORED" : @"INSERT_READBACK_UNCONFIRMED";
 out[@"hostComponentHashes"] = @{@"before": hostBefore, @"after": hostAfter ?: @{}};
 return out;
}

static NSArray *canaryReasons(void) {
 return @[@"CANARY_PREFLIGHT_REFUSED", @"EXACT_RECEIPT_CLEANUP_UNCONFIRMED", @"BASELINE_RESTORATION_UNCONFIRMED", @"ROOT_RESTORED_NAMESPACE_RETAINED",
  @"INTERRUPTED_AFTER_OWNED_CLEANUP", @"BOUNDED_EMPTY_V2_HOOK_CYCLE_RESTORED", @"INSERT_READBACK_UNCONFIRMED", @"PRIVILEGED_REFERENCE_REQUIRED",
  @"SIGNAL_BOUNDARY_UNAVAILABLE", @"PRIVILEGED_IDENTITY_UNCONFIRMED", @"INSTALLATION_LEASE_REFUSED", @"INSTALLED_TREE_REFUSED", @"INSTALLED_PIN_OR_MODE_REFUSED",
  @"UNPRIVILEGED_REQUEST_REQUIRED", @"AUTHORIZATION_CANCELLED", @"AUTHORIZATION_UNAVAILABLE", @"ROOT_COMPLETION_UNCONFIRMED_READ_ONLY_RECOVERY_REQUIRED",
  @"INVALID_FIXED_OPERATION", @"INERT_FIXED_2A7_CANDIDATE"];
}
static NSDictionary *publicHashes(id value) {
 if (!keys(value, @[@"before", @"after"])) return nil;
 for (NSString *phase in @[@"before", @"after"]) {
  NSDictionary *hashes = value[phase]; if (phase && [phase isEqual:@"after"] && keys(hashes,@[])) continue;
  if (!keys(hashes, @[@"routes", @"dns", @"nat", @"pfconf"])) return nil;
  for (NSString *key in hashes) if (!regex(hashes[key],@"^[0-9a-f]{64}$")) return nil;
 }
 return value;
}
static NSDictionary *report(NSString *action, NSDictionary *out, bool requested) {
 NSMutableDictionary *result = [@{@"schema": CANARY_SCHEMA, @"action": action, @"runId": CANARY_RUN, @"anchor": CANARY_ANCHOR,
  @"manifestSHA256": @MF, @"nativeSHA256": @CANARY_NATIVE_SHA, @"experimentOnly": @YES, @"productionReady": @NO, @"ready": @NO,
  @"protected": @NO, @"fullCleanupVerified": @NO, @"bootstrapIdentityBound": @NO, @"wholeCanaryCrashCleanupVerified": @NO,
  @"requiresSeparateApproval": @YES, @"authorizationRequested": @((BOOL)requested), @"requiresPFAlreadyDisabled": @YES,
  @"priority": @4294967295ULL, @"keepState": @0, @"installedLeafCount": @(sizeof(files)/sizeof(files[0])),
  @"fixedRunMayNeverBeReused": @YES, @"readOnly": @((BOOL)(isBool(out[@"insertAttempted"]) && ![out[@"insertAttempted"] boolValue] &&
   isBool(out[@"cleanupUncertain"]) && ![out[@"cleanupUncertain"] boolValue])), @"interrupted": @((BOOL)(interrupted != 0)),
  @"rootPhaseDeadlineSeconds": @175, @"outerCompletionWaitSeconds": @180, @"authorizationWaitExcluded": @YES,
  @"operations": @{@"burnFixedUUIDLedger": @YES, @"emptyRootHookInsert": @YES, @"exactReceiptDeleteOnce": @YES,
   @"PFEnable": @NO, @"PFReference": @NO, @"groups": @NO, @"tunnels": @NO, @"childRules": @NO, @"applications": @NO,
   @"hostDNSChanges": @NO, @"hostRouteChanges": @NO, @"stateControl": @NO, @"globalReload": @NO},
  @"gates": @{@"productionRouting": @NO, @"allStatePreservation": @NO, @"inactiveQueues": @NO, @"namespaceReferences": @NO,
   @"SIGKILLCleanup": @NO, @"PFEnableRaceExcluded": @NO}} mutableCopy];
 for (NSString *key in @[@"ok", @"insertAttempted", @"insertReadbackVerified", @"deleteAttempted", @"deleteReceiptVerified",
   @"originalRootRestored", @"receiptRetired", @"namespaceState", @"namespaceReclaimed", @"hostNetworkRestored", @"emptyHookCycleVerified",
   @"cleanupUncertain", @"cleanupPending"]) {
  if ([key isEqual:@"namespaceState"]) result[key] = [@[@"unselected",@"absent",@"present",@"unknown"] containsObject:out[key]] ? out[key] : @"unknown";
  else result[key] = isBool(out[key]) ? out[key] : @((BOOL)[key hasPrefix:@"cleanup"]);
 }
 bool recognized = [canaryReasons() containsObject:out[@"reason"]];
 result[@"reason"] = recognized ? out[@"reason"] : @"UNRECOGNIZED_COMPLETION_REASON";
 if (!recognized) { result[@"ok"] = @NO; result[@"cleanupUncertain"] = @YES; result[@"cleanupPending"] = @YES; }
 if (!isBool(out[@"insertAttempted"])) { result[@"ok"] = @NO; result[@"cleanupUncertain"] = @YES; result[@"cleanupPending"] = @YES; }
 if (out[@"hostComponentHashes"] && publicHashes(out[@"hostComponentHashes"])) result[@"hostComponentHashes"] = out[@"hostComponentHashes"];
 if ([@[@"BASELINE", @"FRESH_RUN_PREFLIGHT", @"INSERT", @"DELETE_ONCE", @"READ_ONLY_RESTORE"] containsObject:out[@"diagnosticStage"]]) result[@"diagnosticStage"] = out[@"diagnosticStage"];
 if ([nativeReasons() containsObject:out[@"nativeReason"]]) result[@"nativeReason"] = out[@"nativeReason"];
 if ([action isEqual:@"canary"] && [result[@"ok"] boolValue] && (![result[@"emptyHookCycleVerified"] boolValue] ||
  ![result[@"originalRootRestored"] boolValue] || ![result[@"receiptRetired"] boolValue] || ![result[@"hostNetworkRestored"] boolValue] ||
  ![result[@"namespaceReclaimed"] boolValue] || [result[@"cleanupUncertain"] boolValue] || [result[@"cleanupPending"] boolValue])) {
  result[@"ok"] = @NO; result[@"cleanupUncertain"] = @YES; result[@"cleanupPending"] = @YES;
 }
 if ([result[@"cleanupUncertain"] boolValue]) result[@"readOnly"] = @NO;
 return result;
}
static int emitReport(NSDictionary *value) {
 NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 if (!data || fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF || fflush(stdout)) return 1;
 return [value[@"ok"] boolValue] ? 0 : 1;
}
static NSDictionary *emptyOutcome(NSString *reason, bool okay, bool uncertain) {
 return @{@"reason": reason, @"ok": @((BOOL)okay), @"insertAttempted": @NO, @"insertReadbackVerified": @NO, @"deleteAttempted": @NO,
  @"deleteReceiptVerified": @NO, @"originalRootRestored": @NO, @"receiptRetired": @NO, @"namespaceState": @"unselected",
  @"namespaceReclaimed": @NO, @"hostNetworkRestored": @NO, @"emptyHookCycleVerified": @NO,
  @"cleanupUncertain": @((BOOL)uncertain), @"cleanupPending": @((BOOL)uncertain)};
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool rootAuthorization(void) {
 AuthorizationRef reference = NULL;
 if (geteuid() || AuthorizationCopyPrivilegedReference(&reference, kAuthorizationFlagDefaults) != errAuthorizationSuccess || !reference) return false;
 AuthorizationItem item = {kAuthorizationRightExecute,0,NULL,0}; AuthorizationRights rights = {1,&item};
 bool verified = AuthorizationCopyRights(reference,&rights,kAuthorizationEmptyEnvironment,kAuthorizationFlagDefaults,NULL) == errAuthorizationSuccess;
 AuthorizationFree(reference, kAuthorizationFlagDefaults); return verified;
}
#pragma clang diagnostic pop
static int runCanary(void) {
 rootDeadline = seconds() + 175;
 if (!rootAuthorization()) return emitReport(report(@"canary", emptyOutcome(@"PRIVILEGED_REFERENCE_REQUIRED", false, false), true));
 /* Security may retain the requesting real UID. Only after the fixed execute
  * right is verified do we normalize this child, never the caller's identity.
  * This creates no OS group; installed native requires real/effective root. */
 gid_t rootGroup = 0;
 if (setgroups(1,&rootGroup) || setgid(0) || setuid(0) || getuid() || geteuid())
  return emitReport(report(@"canary", emptyOutcome(@"PRIVILEGED_IDENTITY_UNCONFIRMED", false, false), true));
 struct sigaction action = {0}; action.sa_handler = onSignal; sigemptyset(&action.sa_mask);
 for (unsigned i = 0; i < 4; i++) { const int signals[] = {SIGTERM,SIGINT,SIGHUP,SIGPIPE};
  if (sigaction(signals[i], &action, NULL)) return emitReport(report(@"canary", emptyOutcome(@"SIGNAL_BOUNDARY_UNAVAILABLE", false, false), true)); }
 /* Explicitly disable inherited automatic child reaping. Until our waitpid
  * consumes an exit, this root parent's child PID cannot be recycled between
  * the ownership/birth checks and signal delivery. No external reaper exists. */
 struct sigaction childAction = {0}; childAction.sa_handler = SIG_DFL; sigemptyset(&childAction.sa_mask);
 if (sigaction(SIGCHLD,&childAction,NULL)) return emitReport(report(@"canary", emptyOutcome(@"SIGNAL_BOUNDARY_UNAVAILABLE", false, false), true));
 int parent = directory(INSTALL_PARENT);
 if (parent < 0 || flock(parent, LOCK_SH|LOCK_NB)) { if (parent >= 0) close(parent);
  return emitReport(report(@"canary", emptyOutcome(@"INSTALLATION_LEASE_REFUSED", false, false), true)); }
 int installed = verifiedInstallation(MIN(rootDeadline,seconds() + 30));
 if (installed < 0) { close(parent); return emitReport(report(@"canary", emptyOutcome(@(failure), false, false), true)); }
 NSDictionary *out = exchangeCanary(^NSDictionary *(unsigned operation, NSDictionary *input, int *status) {
  return nativeCall(operation, input, status, installed);
 }, ^NSDictionary * { return hostSnapshot(); }, ^bool { return stdoutPeerClosed(); });
 close(installed); close(parent); return emitReport(report(@"canary", out, true));
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int requestCanary(void) {
 if (getuid() == 0 || geteuid() == 0) return emitReport(report(@"requestCanary", emptyOutcome(@"UNPRIVILEGED_REQUEST_REQUIRED", false, false), true));
 char unresolved[PATH_MAX], executable[PATH_MAX]; uint32_t size = sizeof(unresolved);
 if (_NSGetExecutablePath(unresolved, &size) || !realpath(unresolved, executable)) return 1;
 AuthorizationRef reference = NULL; AuthorizationItem item = {kAuthorizationRightExecute,0,NULL,0}; AuthorizationRights rights = {1,&item};
 const char prompt[] = "Envara independent 2a7 V2 EMPTY namespace canary: permanently burn ONE fixed run UUID in the root ledger, insert ONE EMPTY root hook, read its exact lease and attempt ONE exact DELETE. PF must already be Disabled. No PF enable, groups, tunnels, rules, software, DNS or route changes. SIGKILL or missing receipt can leave cleanup uncertain. Separate approval required.";
 AuthorizationItem promptItem = {kAuthorizationEnvironmentPrompt,sizeof(prompt)-1,(void *)prompt,0}; AuthorizationEnvironment environment = {1,&promptItem};
 OSStatus status = AuthorizationCreate(NULL,kAuthorizationEmptyEnvironment,kAuthorizationFlagDefaults,&reference);
 if (status == errAuthorizationSuccess) status = AuthorizationCopyRights(reference,&rights,&environment,kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights,NULL);
 FILE *communications = NULL; char *arguments[] = {"--canary",NULL};
 if (status == errAuthorizationSuccess) status = AuthorizationExecuteWithPrivileges(reference,executable,kAuthorizationFlagDefaults,arguments,&communications);
 if (status != errAuthorizationSuccess || !communications) { if (reference) AuthorizationFree(reference,kAuthorizationFlagDestroyRights);
  return emitReport(report(@"requestCanary", emptyOutcome(status == errAuthorizationCanceled ? @"AUTHORIZATION_CANCELLED" : @"AUTHORIZATION_UNAVAILABLE", false, false), true)); }
 int fd = fileno(communications); fcntl(fd,F_SETFL,O_NONBLOCK); NSMutableData *data = [NSMutableData data]; bool eof = false, okay = true;
 double deadline = seconds() + 180;
 while (seconds() < deadline && !eof) { struct pollfd p = {fd,POLLIN|POLLHUP,0}; int ready = poll(&p,1,100);
  if (ready < 0 && errno == EINTR) continue; if (ready < 0) { okay = false; break; } if (!ready) continue;
  unsigned char bytes[4096]; ssize_t count = read(fd,bytes,sizeof(bytes));
  if (count > 0 && data.length + (size_t)count <= OUTPUT_LIMIT) [data appendBytes:bytes length:(NSUInteger)count];
  else if (!count) eof = true; else if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue; else { okay = false; break; }
 }
 fclose(communications); AuthorizationFree(reference,kAuthorizationFlagDestroyRights);
 NSDictionary *value = okay && eof ? strictJSON(data,OUTPUT_LIMIT) : nil;
 if (!value || ![value[@"schema"] isEqual:CANARY_SCHEMA] || ![value[@"action"] isEqual:@"canary"] || ![value[@"runId"] isEqual:CANARY_RUN] ||
  ![value[@"anchor"] isEqual:CANARY_ANCHOR] ||
  ![value[@"manifestSHA256"] isEqual:@MF] || ![value[@"nativeSHA256"] isEqual:@CANARY_NATIVE_SHA] ||
  !isBool(value[@"ok"]) || !isBool(value[@"cleanupUncertain"]) || !isBool(value[@"cleanupPending"]))
  return emitReport(report(@"requestCanary", emptyOutcome(@"ROOT_COMPLETION_UNCONFIRMED_READ_ONLY_RECOVERY_REQUIRED", false, true), true));
 /* Reconstruct the public report from a closed whitelist, never forward a
  * raw privileged payload/private lease after decoding. */
 return emitReport(report(@"canary", value, true));
}
#pragma clang diagnostic pop
#ifdef CANARY_INERT_MAIN
#define main CANARY_INERT_MAIN
#endif
int main(int argc, char **argv) {
 @autoreleasepool {
  if (argc > 2) return emitReport(report(@"plan", emptyOutcome(@"INVALID_FIXED_OPERATION", false, false), false));
  const char *mode = argc == 1 ? "--plan" : argv[1];
  if (!strcmp(mode,"--request-canary")) return requestCanary();
  if (!strcmp(mode,"--canary")) return runCanary();
  bool okay = !strcmp(mode,"--plan");
  return emitReport(report(@"plan", emptyOutcome(okay ? @"INERT_FIXED_2A7_CANDIDATE" : @"INVALID_FIXED_OPERATION", okay, false), false));
 }
}
