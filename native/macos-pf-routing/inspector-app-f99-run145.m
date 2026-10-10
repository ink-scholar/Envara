/* Dedicated c37/run02b source-only recovery; archived904 is never selected. */
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
#include "inspector-app-f99-inventory.h"
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
typedef struct { const unsigned char *bytes; size_t size, at; bool allowEscapedSlash; } JSONCursor;
static void skipSpace(JSONCursor *c) { while (c->at < c->size && strchr(" \t\r\n", c->bytes[c->at])) c->at++; }
static NSString *jsonString(JSONCursor *c) {
 skipSpace(c); if (c->at >= c->size || c->bytes[c->at++] != '"') return nil;
 unsigned char decoded[4096]; size_t length = 0;
 while (c->at < c->size) {
  unsigned char ch = c->bytes[c->at++];
  if (ch == '"') return [[NSString alloc] initWithBytes:decoded length:length encoding:NSASCIIStringEncoding];
  if (ch == '\\') {
   if (!c->allowEscapedSlash || c->at >= c->size || c->bytes[c->at++] != '/') return nil;
   ch = '/';
  }
  if (ch < 32 || ch > 126 || length >= sizeof(decoded)) return nil; decoded[length++] = ch;
 }
 return nil;
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
static NSDictionary *strictJSONMode(NSData *data, size_t limit, bool allowEscapedSlash) {
 if (!data.length || data.length > limit) return nil; JSONCursor c = {data.bytes, data.length, 0, allowEscapedSlash};
 if (!jsonValue(&c, 0)) return nil; skipSpace(&c); if (c.at != c.size) return nil;
 id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]; return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
static NSDictionary *strictJSON(NSData *data, size_t limit) { return strictJSONMode(data, limit, false); }
/* Only Foundation-written filter journals may encode '/' as '\/'. Decode
 * that one escape before duplicate-key comparison; every other escape stays
 * refused. Sealed leases, registries and native proofs retain strictJSON. */
static NSDictionary *strictJournalJSON(NSData *data, size_t limit) { return strictJSONMode(data, limit, true); }
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
 return operation == 0 ? "hook-status" : NULL;
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
 if(operation!=0)return nil;
 if (!nativeOperation(operation) || !(keys(input, @[]) || keys(input, @[@"runId"]) || keys(input, @[@"lease"]))) return nil;
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
#define FIXED_ENV @"9b5fb67d-7d8e-492b-a1f5-cccd893b0567"
#define CAPSULE "io.envara.pf-inspector-f99-no-capsule"
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

/* Separate observational entry: no recovery, PF reference, rule replacement,
 * DELETE, group operation, keeper command, or archive function is linked here.
 * A live keeper owns the ledger EX handle; STATUS may legitimately be unknown. */
#define INSPECTION_SCHEMA @"envara.macos-pf-application-inspection/v1"
#define PUBLIC_FAILURE_SHA @"bbb4a94a2ece4a5fd388adaba5a54e59acbcaa695dff411a15b53db9a02d7133"
static bool nonBoolInteger(id value,uint64_t minimum,uint64_t maximum){uint64_t n=0;return integer(value,&n)&&n>=minimum&&n<=maximum;}
static bool boolValue(id value,bool expected){return isBool(value)&&[value boolValue]==expected;}
static bool uuidString(id value){return regex(value,@"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");}
static NSDictionary *directorySnapshot(int fd){
 if(!secureFD(fd,true,0700))return nil;int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(scan<0)return nil;
 DIR*d=fdopendir(scan);if(!d){close(scan);return nil;}NSMutableArray*entries=[NSMutableArray array];struct dirent*e;bool okay=true;errno=0;
 while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
  struct stat s;NSString*name=@(e->d_name);if(entries.count>=64||!regex(name,@"^[A-Za-z0-9_.-]{1,255}$")||fstatat(fd,e->d_name,&s,AT_SYMLINK_NOFOLLOW)||s.st_uid||S_ISLNK(s.st_mode)||(!S_ISREG(s.st_mode)&&!S_ISDIR(s.st_mode))||(s.st_mode&0077)){okay=false;break;}
  [entries addObject:[NSString stringWithFormat:@"%@|%llu|%llu|%u|%llu",name,(unsigned long long)s.st_dev,(unsigned long long)s.st_ino,(unsigned)(s.st_mode&07777),(unsigned long long)s.st_size]];errno=0;
 }
 if(errno)okay=false;if(closedir(d))okay=false;if(!okay)return nil;
 return @{@"entryCount":@(entries.count),@"inventorySHA256":hashText([[entries sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"])};
}
static NSDictionary *processObservation(NSString*role,id pidValue,id birthValue,const char*path,pid_t parent){
 if(!nonBoolInteger(pidValue,2,INT32_MAX)||!regex(birthValue,@"^[1-9][0-9]{0,19}:[0-9]{6}$"))return nil;
 pid_t pid=(pid_t)[pidValue unsignedIntValue];struct proc_bsdinfo a={0},b={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&a,sizeof(a));
 if(!n&&errno==ESRCH)return @{@"role":role,@"pid":pidValue,@"recordedBirth":birthValue,@"state":@"absent"};
 if(n!=sizeof(a)||a.pbi_pid!=(uint32_t)pid||a.pbi_start_tvusec>=1000000)return nil;
 NSString*actual=[NSString stringWithFormat:@"%llu:%06llu",a.pbi_start_tvsec,a.pbi_start_tvusec];
 if(![actual isEqual:birthValue])return @{@"role":role,@"pid":pidValue,@"recordedBirth":birthValue,@"state":@"recorded-birth-absent-pid-reused"};
 char image[PROC_PIDPATHINFO_MAXSIZE]={0};if(proc_pidpath(pid,image,sizeof(image))<=0||strcmp(image,path)||a.pbi_uid||a.pbi_ruid||a.pbi_svuid||
   (parent>0&&a.pbi_ppid!=(uint32_t)parent)||proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&b,sizeof(b))!=sizeof(b)||
   a.pbi_pid!=b.pbi_pid||a.pbi_ppid!=b.pbi_ppid||a.pbi_start_tvsec!=b.pbi_start_tvsec||a.pbi_start_tvusec!=b.pbi_start_tvusec||
   a.pbi_uid!=b.pbi_uid||a.pbi_ruid!=b.pbi_ruid||a.pbi_svuid!=b.pbi_svuid||a.pbi_gid!=b.pbi_gid||a.pbi_rgid!=b.pbi_rgid||a.pbi_svgid!=b.pbi_svgid)return nil;
 return @{@"role":role,@"pid":pidValue,@"recordedBirth":birthValue,@"parentPid":@(b.pbi_ppid),@"state":@"live-exact-recorded-identity",@"uid":@(b.pbi_uid),@"gid":@(b.pbi_gid)};
}
static NSDictionary *activeClassObservation(void){
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat a,b;
 if(fd<0||fstat(fd,&a)||lstat("/dev/pf",&b)||!S_ISCHR(a.st_mode)||a.st_uid||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_rdev!=b.st_rdev){if(fd>=0)close(fd);return nil;}
 uint8_t actions[]={0,2,4,6,8,11};NSMutableArray*classes=[NSMutableArray array];bool okay=true;
 for(unsigned i=0;i<sizeof(actions);i++){
  EnvaraPFHookRequest first={0},last={0};strcpy(first.anchor,CANARY_ANCHOR.UTF8String);first.rule.action=actions[i];last=first;
  if(ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)||first.nr>64){okay=false;break;}
  NSMutableData*semantics=[NSMutableData data];bool noState=true;for(uint32_t j=0;j<first.nr;j++){
   EnvaraPFHookRequest row={0};strcpy(row.anchor,CANARY_ANCHOR.UTF8String);row.rule.action=actions[i];row.ticket=first.ticket;row.nr=j;
   if(ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&row)||row.ticket!=first.ticket||row.nr!=j){okay=false;break;}
   noState=noState&&row.rule.keep_state==0;[semantics appendBytes:&row.rule length:sizeof(row.rule)];
  }
  if(!okay||ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)||last.nr!=first.nr||last.ticket!=first.ticket){okay=false;break;}
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(semantics.bytes,(CC_LONG)semantics.length,digest);char hex[65];for(unsigned j=0;j<32;j++)snprintf(hex+j*2,3,"%02x",digest[j]);hex[64]=0;
  [classes addObject:@{@"action":@(actions[i]),@"activeRuleCount":@(first.nr),@"revision":@(first.ticket),@"observedRuleBytesSHA256":@(hex),@"keepStateZeroObserved":@(noState)}];
 }
 close(fd);return okay?@{@"classes":classes,@"inactiveQueuesVerified":@NO,@"fullRuleSemanticsVerified":@NO}:nil;
}
static NSDictionary *readJournal(int run,NSDictionary*lease,id keeperPID){
 struct stat exists;if(fstatat(run,"app-filter-events",&exists,AT_SYMLINK_NOFOLLOW)){return errno==ENOENT?@{@"present":@NO,@"eventCount":@0,@"pendingIntent":@NO,@"nativeRulesVerified":@NO}:nil;}
 int fd=openat(run,"app-filter-events",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);NSDictionary*before=directorySnapshot(fd);if(!before){if(fd>=0)close(fd);return nil;}
 NSMutableArray*digests=[NSMutableArray array];NSDictionary*latest=nil;unsigned sequence=0;bool pending=false,okay=true;
 for(;sequence<16;sequence++){
  NSString*intentName=[NSString stringWithFormat:@"%03u.intent",sequence],*receiptName=[NSString stringWithFormat:@"%03u.receipt",sequence];
  if(absent(fd,intentName.UTF8String)){if(!absent(fd,receiptName.UTF8String))okay=false;break;}
  NSData*ib=privateRead(fd,intentName.UTF8String,4096,NULL);NSDictionary*intent=strictJournalJSON(ib,4096);
  if(!keys(intent,@[@"schema",@"runId",@"leaseId",@"generation",@"sequence",@"previous",@"next",@"writerPid"])||![intent[@"schema"]isEqual:@"envara.macos-pf-app-filter-event/v1"]||
    ![intent[@"runId"]isEqual:CANARY_RUN]||![intent[@"leaseId"]isEqual:lease[@"leaseId"]]||![intent[@"generation"]isEqual:lease[@"generation"]]||
    !nonBoolInteger(intent[@"sequence"],sequence,sequence)||!nonBoolInteger(intent[@"previous"],0,3)||!nonBoolInteger(intent[@"next"],0,3)||
    ![@[@0,@1,@3]containsObject:intent[@"previous"]]||![@[@0,@1,@3]containsObject:intent[@"next"]]||
    ![intent[@"previous"]isEqual:latest?latest[@"mode"]:@0]||![intent[@"writerPid"]isEqual:keeperPID]){okay=false;break;}
  [digests addObject:hashText([[NSString alloc]initWithData:ib encoding:NSUTF8StringEncoding])];
  if(absent(fd,receiptName.UTF8String)){pending=true;sequence++;break;}
  NSData*rb=privateRead(fd,receiptName.UTF8String,4096,NULL);NSDictionary*receipt=strictJournalJSON(rb,4096);
  if(!keys(receipt,@[@"schema",@"runId",@"leaseId",@"generation",@"sequence",@"mode",@"writerPid",@"revision",@"ruleCount"])||![receipt[@"schema"]isEqual:@"envara.macos-pf-app-filter-receipt/v1"]||
    ![receipt[@"runId"]isEqual:CANARY_RUN]||![receipt[@"leaseId"]isEqual:lease[@"leaseId"]]||![receipt[@"generation"]isEqual:lease[@"generation"]]||
    !nonBoolInteger(receipt[@"sequence"],sequence,sequence)||!nonBoolInteger(receipt[@"mode"],0,3)||![receipt[@"mode"]isEqual:intent[@"next"]]||![receipt[@"writerPid"]isEqual:keeperPID]||
    !nonBoolInteger(receipt[@"revision"],0,UINT32_MAX)||!nonBoolInteger(receipt[@"ruleCount"],0,16)){okay=false;break;}
  latest=receipt;[digests addObject:hashText([[NSString alloc]initWithData:rb encoding:NSUTF8StringEncoding])];
 }
 NSDictionary*after=directorySnapshot(fd);if(!after||![before isEqual:after]||[before[@"entryCount"]unsignedIntegerValue]!=digests.count)okay=false;close(fd);
 if(!okay)return nil;NSMutableDictionary*out=[@{@"present":@YES,@"eventCount":@(digests.count),@"pendingIntent":@(pending),@"inventorySHA256":before[@"inventorySHA256"],@"eventBytesSHA256":hashText([digests componentsJoinedByString:@"|"]),@"nativeRulesVerified":@NO}mutableCopy];
 if(latest)out[@"lastReceipt"]=@{@"sequence":latest[@"sequence"],@"mode":latest[@"mode"],@"writerPid":latest[@"writerPid"],@"revision":latest[@"revision"],@"ruleCount":latest[@"ruleCount"]};return out;
}
static bool journalMatchesActiveFilter(NSDictionary*journal,NSDictionary*observation){
 NSArray*rows=observation[@"classes"];if(![rows isKindOfClass:NSArray.class]||rows.count!=6)return false;
 NSSet*actions=[NSSet setWithArray:@[@0,@2,@4,@6,@8,@11]];NSMutableSet*seen=[NSMutableSet set];NSDictionary*filter=nil;
 for(NSDictionary*row in rows){if(![row isKindOfClass:NSDictionary.class]||!nonBoolInteger(row[@"action"],0,11)||![actions containsObject:row[@"action"]]||[seen containsObject:row[@"action"]])return false;
  [seen addObject:row[@"action"]];if([row[@"action"]isEqual:@0])filter=row;}
 NSDictionary*receipt=journal[@"lastReceipt"];
 return filter&&[receipt isKindOfClass:NSDictionary.class]&&boolValue(journal[@"pendingIntent"],false)&&
  nonBoolInteger(filter[@"revision"],0,UINT32_MAX)&&nonBoolInteger(filter[@"activeRuleCount"],0,64)&&
  nonBoolInteger(receipt[@"revision"],0,UINT32_MAX)&&nonBoolInteger(receipt[@"ruleCount"],0,16)&&
  [receipt[@"revision"]isEqual:filter[@"revision"]]&&[receipt[@"ruleCount"]isEqual:filter[@"activeRuleCount"]];
}
static bool liveShape(NSDictionary*r,NSDictionary*l,NSData*bytes,NSDictionary**transport,uint64_t*gid){
 NSArray*leaseKeys=@[@"schema",@"runId",@"environmentId",@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId",@"consoleUID",@"gid",@"cwd",@"timezone",@"locale",@"issuedMonotonicMs",@"expiresMonotonicMs",@"bootTimeSeconds",@"controllerPid",@"controllerBirth",@"ipv4Address",@"rootHookLease"];
 if(!keys(l,leaseKeys)||![l[@"schema"]isEqual:@"envara.macos-pf-app-bound-lease/v1"]||![l[@"runId"]isEqual:CANARY_RUN]||![l[@"environmentId"]isEqual:FIXED_ENV]||
  !integer(l[@"gid"],gid)||*gid<7100||*gid>7999||!nonBoolInteger(l[@"consoleUID"],1,UINT32_MAX)||!nonBoolInteger(l[@"controllerPid"],2,INT32_MAX)||
  !regex(l[@"controllerBirth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$")||!nonBoolInteger(l[@"issuedMonotonicMs"],1,UINT64_MAX)||!nonBoolInteger(l[@"expiresMonotonicMs"],1,UINT64_MAX)||
  [l[@"expiresMonotonicMs"]unsignedLongLongValue]<=[l[@"issuedMonotonicMs"]unsignedLongLongValue]||[l[@"expiresMonotonicMs"]unsignedLongLongValue]-[l[@"issuedMonotonicMs"]unsignedLongLongValue]>180000||
  !nonBoolInteger(l[@"bootTimeSeconds"],1,UINT64_MAX)||!regex(l[@"cwd"],@"^/[^\n]{1,4094}$")||!regex(l[@"timezone"],@"^[A-Za-z0-9_+/-]{1,128}$")||!regex(l[@"locale"],@"^[A-Za-z0-9_-]{1,64}$")||![l[@"ipv4Address"]isEqual:@"198.18.1.1"]||!validLease(l[@"rootHookLease"]))return false;
 for(NSString*k in @[@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId"])if(!uuidString(l[k]))return false;
 if(!keys(r,@[@"schema",@"runId",@"supervisorPid",@"anchor",@"phase",@"cleanupUncertain",@"rootHook",@"ownedPFReference",@"filterReplacement",@"filterReceipt",@"application",@"incompleteGroupAllocations",@"realms",@"guardians"])||
  ![r[@"schema"]isEqual:@"envara.macos-pf-owned-registry/v1"]||![r[@"runId"]isEqual:CANARY_RUN]||![r[@"anchor"]isEqual:CANARY_ANCHOR]||![r[@"supervisorPid"]isEqual:l[@"controllerPid"]]||
  ![r[@"phase"]isEqual:@"cleanup-required"]||!boolValue(r[@"cleanupUncertain"],true)||r[@"filterReplacement"]!=NSNull.null||r[@"filterReceipt"]!=NSNull.null||![r[@"guardians"]isEqual:@[]]||![r[@"incompleteGroupAllocations"]isEqual:@[]])return false;
 NSDictionary*app=r[@"application"],*root=r[@"rootHook"],*reference=r[@"ownedPFReference"];
 if(!keys(app,@[@"environmentId",@"routeId",@"registrationId",@"versionId",@"ticketId",@"leaseSHA256",@"transport",@"child",@"resumed"])||![app[@"environmentId"]isEqual:FIXED_ENV]||
   ![app[@"registrationId"]isEqual:l[@"registrationId"]]||![app[@"versionId"]isEqual:l[@"versionId"]]||!uuidString(app[@"ticketId"])||!regex(app[@"routeId"],@"^pf_[0-9a-f]{32}$")||
   ![app[@"leaseSHA256"]isEqual:hashText([[NSString alloc]initWithData:bytes encoding:NSUTF8StringEncoding])]||!boolValue(app[@"resumed"],false)||app[@"child"]!=NSNull.null)return false;
 if(!keys(root,@[@"mutationAttempted",@"verified",@"removed",@"receiptRetired",@"namespaceState",@"namespaceReclaimed",@"lease"])||!boolValue(root[@"mutationAttempted"],true)||!boolValue(root[@"verified"],true)||
   !boolValue(root[@"removed"],false)||!boolValue(root[@"receiptRetired"],false)||!boolValue(root[@"namespaceReclaimed"],false)||![@[@"unknown",@"present"]containsObject:root[@"namespaceState"]]||![root[@"lease"]isEqual:l[@"rootHookLease"]]||
   !keys(reference,@[@"attempted",@"acquired",@"released",@"token"])||!boolValue(reference[@"attempted"],true)||!boolValue(reference[@"acquired"],true)||!boolValue(reference[@"released"],false)||!regex(reference[@"token"],@"^[1-9][0-9]{0,19}$"))return false;
 NSArray*realms=r[@"realms"];if(![realms isKindOfClass:NSArray.class]||realms.count!=1)return false;NSDictionary*realm=realms[0];
 if(!keys(realm,@[@"environmentId",@"realmId",@"gid",@"groupPath",@"mode",@"tunnel",@"fixtures"])||![realm[@"environmentId"]isEqual:FIXED_ENV]||![realm[@"realmId"]isEqual:l[@"realmId"]]||
   ![realm[@"gid"]isEqual:l[@"gid"]]||![realm[@"groupPath"]isEqual:[NSString stringWithFormat:@"/Groups/_envara_pf_%llu",(unsigned long long)*gid]]||![realm[@"mode"]isEqual:@"blocked"]||realm[@"tunnel"]!=NSNull.null||![realm[@"fixtures"]isEqual:@[]])return false;
 NSDictionary*t=app[@"transport"];NSArray*tk=@[@"schema",@"event",@"runId",@"environmentId",@"interfaceName",@"corePID",@"coreBirth",@"frontPID",@"frontBirth",@"frontPort",@"keeperPID",@"ownsOriginalUTunFD",@"ownsOriginalListenerFD",@"keeperBirth",@"ready",@"protected",@"productionReady",@"profile",@"genericApplicationRouting",@"udpSupported"];
 if(!keys(t,tk)||![t[@"schema"]isEqual:@"envara.macos-pf-app-transport/v1"]||![t[@"event"]isEqual:@"transport-started"]||![t[@"runId"]isEqual:CANARY_RUN]||![t[@"environmentId"]isEqual:FIXED_ENV]||
   !regex(t[@"interfaceName"],@"^utun[0-9]{1,7}$")||!nonBoolInteger(t[@"frontPort"],1,65535)||!boolValue(t[@"ownsOriginalUTunFD"],true)||!boolValue(t[@"ownsOriginalListenerFD"],true)||
   ![t[@"profile"]isEqual:@"seatbelt-front-only"]||!boolValue(t[@"ready"],false)||!boolValue(t[@"protected"],false)||!boolValue(t[@"productionReady"],false)||!boolValue(t[@"genericApplicationRouting"],false)||!boolValue(t[@"udpSupported"],false))return false;
 for(NSString*k in @[@"corePID",@"frontPID",@"keeperPID"])if(!nonBoolInteger(t[k],2,INT32_MAX))return false;
 for(NSString*k in @[@"coreBirth",@"frontBirth",@"keeperBirth"])if(!regex(t[k],@"^[1-9][0-9]{0,19}:[0-9]{6}$"))return false;*transport=t;return true;
}
static int emitInspection(NSDictionary*out){NSData*d=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!d||fwrite(d.bytes,1,d.length,stdout)!=d.length||fputc('\n',stdout)==EOF)return 1;fflush(stdout);return [out[@"ok"]boolValue]?0:1;}
static NSMutableDictionary *inspectionOutcome(void){return [@{@"schema":INSPECTION_SCHEMA,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"publicFailureReceiptSHA256":PUBLIC_FAILURE_SHA,@"readOnly":@YES,@"ok":@NO,@"reason":@"INSPECTION_UNCONFIRMED",@"gate":@"not-started",@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"cleanupPermitted":@NO,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"runtimeChanged":@NO}mutableCopy];}
/* Shared by the actual observational entry and inert producer fixtures. These
 * formatters do not execute commands or make cleanup/readiness assertions. */
static void formatOwnedNamespaceObservation(NSMutableDictionary*out,bool children,NSString*text){
 NSString*trim=[text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
 out[children?@"ownedChildrenEmptyObserved":@"ownedTablesEmptyObserved"]=@((BOOL)(trim.length==0));
 out[children?@"ownedChildrenSHA256":@"ownedTablesSHA256"]=hashText(text);
}
static void formatNativeHookObservation(NSMutableDictionary*out,NSDictionary*proof){
 out[@"nativeHookStatusAvailable"]=@((BOOL)(proof!=nil));
 if(proof)out[@"nativeRootStatus"]=@{@"ok":proof[@"ok"],@"reason":proof[@"reason"],@"pfDisabled":proof[@"pfDisabled"],@"hookInstalled":proof[@"hookInstalled"],@"ownedRootHookVerified":proof[@"ownedRootHookVerified"],@"namespaceState":proof[@"namespaceState"],@"runLedgerState":proof[@"runLedgerState"],@"receiptRetired":proof[@"receiptRetired"],@"originalRootCompatible":proof[@"originalRootCompatible"],@"originalRootSHA256":proof[@"originalRootSHA256"],@"originalRootTextSHA256":proof[@"originalRootTextSHA256"]};
}
/* Security may provide genuine EUID 0 while retaining the console RUID/GID.
 * Normalize only this authorized child, never an unprivileged request. */
#ifndef INSPECTOR_CREDENTIAL_FIXTURE
/* _DARWIN_C_SOURCE aliases getgroups to a default-directory-groups extension.
 * Bind the documented legacy process getter, not that memberd lookup. */
extern int inspectorKernelGroups(int,gid_t[]) __asm("_getgroups");
#endif
typedef struct {const char*stage;int error,count;uid_t real_uid,effective_uid;gid_t real_gid,effective_gid;} InspectorCredentialObservation;
static InspectorCredentialObservation credentialObservation;
static void credentialSnapshot(void){
 credentialObservation.real_uid=getuid();credentialObservation.effective_uid=geteuid();
 credentialObservation.real_gid=getgid();credentialObservation.effective_gid=getegid();
}
static bool credentialRefused(const char*stage,int error){
 credentialObservation.stage=stage;credentialObservation.error=error>=0&&error<=1024?error:0;credentialSnapshot();return false;
}
static NSDictionary *credentialDiagnostic(void){
 return @{@"stage":@(credentialObservation.stage),@"errno":@(credentialObservation.error),@"realUID":@(credentialObservation.real_uid),
  @"effectiveUID":@(credentialObservation.effective_uid),@"realGID":@(credentialObservation.real_gid),@"effectiveGID":@(credentialObservation.effective_gid),@"groupCount":@(credentialObservation.count)};
}
static bool inspectorRootCredentials(void){
 credentialObservation=(InspectorCredentialObservation){.stage="effective-root",.count=-1};
 if(geteuid()!=0)return credentialRefused("effective-root",0);
 gid_t root=0,groups[2]={UINT32_MAX,UINT32_MAX};
 errno=0;if(setgroups(1,&root))return credentialRefused("setgroups",errno);
 errno=0;if(setgid(0))return credentialRefused("setgid",errno);
 errno=0;if(setuid(0))return credentialRefused("setuid",errno);
 errno=0;int count=inspectorKernelGroups(2,groups);int error=errno;credentialObservation.count=count;
 if(count<0)return credentialRefused("kernel-groups",error);
 credentialSnapshot();if(credentialObservation.real_uid||credentialObservation.effective_uid||credentialObservation.real_gid||credentialObservation.effective_gid)return credentialRefused("identity-check",0);
 if(count!=1||groups[0]!=0)return credentialRefused("group-check",0);
 return true;
}
/* AEXWP may inherit ignored child exits. Only this inspector's disposition is
 * reset; zero flags clear SA_NOCLDWAIT before readonly command children exist. */
static bool inspectorChildWaitBoundary(void){
 struct sigaction action={0};action.sa_handler=SIG_DFL;
 return !sigemptyset(&action.sa_mask)&&!sigaction(SIGCHLD,&action,NULL);
}
static int inspectFixedRun(void){
 NSMutableDictionary*out=inspectionOutcome();rootDeadline=seconds()+175;bool credentials=inspectorRootCredentials();
 if(credentials){errno=0;if(!inspectorChildWaitBoundary())credentials=credentialRefused("child-wait-boundary",errno);}
 if(!credentials){out[@"gate"]=@"root-credentials";out[@"rootCredentialObservation"]=credentialDiagnostic();return emitInspection(out);}
 int installed=-1,runtime=-1,run=-1,state=-1;NSData*rb=nil,*lb=nil,*lockBytes=nil;struct stat ri,li,ki,rooti,runi,statei;NSDictionary*record=nil,*lease=nil,*transport=nil;uint64_t gid=0;int code=-1;
 do{
  out[@"gate"]=@"installed-inventory";installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(installed<0)break;
  out[@"gate"]=@"private-runtime";runtime=directory(RUNTIME);if(!secureFD(runtime,true,0700)||fstat(runtime,&rooti))break;
  /* No flock: the live controller owns this EX lock. Atomic bytes and named
   * inode identities are reread; any concurrent update refuses the snapshot. */
  out[@"gate"]=@"registry-shape";rb=privateRead(runtime,"registry.json",65536,&ri);record=strictJSON(rb,65536);lockBytes=privateRead(runtime,"registry.lock",4096,&ki);NSDictionary*lock=strictJSON(lockBytes,4096);
  if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"anchor"]isEqual:CANARY_ANCHOR]||![lock[@"pid"]isEqual:record[@"supervisorPid"]])break;
  out[@"gate"]=@"run-directory";run=openat(runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(run,true,0700)||fstat(run,&runi))break;
  out[@"gate"]=@"lease-and-transport-shape";lb=privateRead(run,"app-bound-lease.json",16384,&li);lease=strictJSON(lb,16384);if(!liveShape(record,lease,lb,&transport,&gid))break;
  state=openat(run,[lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(state,true,0700)||fstat(state,&statei))break;
  out[@"ownedReferenceRecordedUnreleased"]=@YES;out[@"realmGID"]=@(gid);out[@"privateFileIdentities"]=@{@"runtimeDevice":@(rooti.st_dev),@"runtimeInode":@(rooti.st_ino),@"runDevice":@(runi.st_dev),@"runInode":@(runi.st_ino),@"leaseDevice":@(li.st_dev),@"leaseInode":@(li.st_ino),@"registryDevice":@(ri.st_dev),@"registryInode":@(ri.st_ino)};
  out[@"gate"]=@"recorded-processes";NSMutableArray*processes=[NSMutableArray array];NSDictionary*p=processObservation(@"controller",lease[@"controllerPid"],lease[@"controllerBirth"],INSTALL "/node",0);if(!p)break;[processes addObject:p];
  p=processObservation(@"keeper",transport[@"keeperPID"],transport[@"keeperBirth"],NATIVE,0);if(!p)break;[processes addObject:p];
  p=processObservation(@"core",transport[@"corePID"],transport[@"coreBirth"],INSTALL "/mihomo",[transport[@"keeperPID"]intValue]);if(!p)break;[processes addObject:p];
  p=processObservation(@"front",transport[@"frontPID"],transport[@"frontBirth"],INSTALL "/node",[transport[@"keeperPID"]intValue]);if(!p)break;[processes addObject:p];out[@"recordedProcesses"]=processes;
  out[@"gidScopeObservation"]=@(envara_app_scope_gid_absent((gid_t)gid));
  out[@"gate"]=@"native-journal";NSDictionary*j=readJournal(run,lease,transport[@"keeperPID"]);if(!j)break;out[@"journal"]=j;
  out[@"gate"]=@"owned-active-classes";NSDictionary*classes=activeClassObservation();if(!classes)break;out[@"activeClasses"]=classes;
  out[@"lastJournalRevisionAndCountMatchActiveFilter"]=@(journalMatchesActiveFilter(j,classes));
  out[@"gate"]=@"owned-tables-and-children";for(unsigned i=0;i<2;i++){
   char*argv[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",i?(char*)"Anchors":(char*)"Tables",NULL};NSString*text=command(argv,false,&code);if(!text||code)break;
   formatOwnedNamespaceObservation(out,i!=0,text);
  }if(!out[@"ownedTablesSHA256"]||!out[@"ownedChildrenSHA256"])break;
  out[@"gate"]=@"native-root-hook-status";NSDictionary*proof=nativeCall(0,@{@"lease":lease[@"rootHookLease"]},&code,installed);
  formatNativeHookObservation(out,proof);
  out[@"gate"]=@"stable-private-snapshot";struct stat a,b,c;
  if(!unchanged(runtime,"registry.json",&ri,rb)||!unchanged(runtime,"registry.lock",&ki,lockBytes)||!unchanged(run,"app-bound-lease.json",&li,lb)||
   fstatat(runtime,CANARY_RUN.UTF8String,&a,AT_SYMLINK_NOFOLLOW)||a.st_dev!=runi.st_dev||a.st_ino!=runi.st_ino||
   fstatat(run,[lease[@"realmId"]UTF8String],&b,AT_SYMLINK_NOFOLLOW)||b.st_dev!=statei.st_dev||b.st_ino!=statei.st_ino||lstat(RUNTIME,&c)||c.st_dev!=rooti.st_dev||c.st_ino!=rooti.st_ino||
   ![j isEqual:readJournal(run,lease,transport[@"keeperPID"])])break;
  out[@"stablePrivateSnapshotVerified"]=@YES;out[@"originalDescriptorCustodyVerified"]=@NO;out[@"liveGuardianFailureAccepted"]=@NO;
  NSDictionary*stateInventory=directorySnapshot(state);if(!stateInventory)break;out[@"stateDirectoryInventory"]=stateInventory;
  out[@"gate"]=@"inspection-complete";out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_FIXED_RUN_OBSERVED";
 }while(0);
 if(state>=0)close(state);if(run>=0)close(run);if(runtime>=0)close(runtime);if(installed>=0)close(installed);return emitInspection(out);
}
#ifndef INSPECTOR_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return emitInspection(inspectionOutcome());const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=inspectionOutcome();out[@"ok"]=@YES;out[@"reason"]=@"INERT_READ_ONLY_PLAN";out[@"runtimeLeafCount"]=@(sizeof(files)/sizeof(files[0]));return emitInspection(out);}
 if(!strcmp(mode,"--inspect-fixed-root"))return inspectFixedRun();return emitInspection(inspectionOutcome());
}}
#endif
