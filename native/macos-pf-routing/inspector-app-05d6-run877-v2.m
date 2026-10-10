/* Fixed 05d6/run877 v2 independent READONLY progress inspection. No recovery entry.
 * Prior actual partial receipt SHA256: 6d89719207655152de65c951e684785b6840fd8ae20573f94fba4ee7b322d12c. */
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
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/kern_control.h>
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
#include "inspector-app-05d6-inventory.h"
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
#define FIXED_ENV @"72826f65-99c0-446c-a9c3-b825b36ad1a5"
#define CAPSULE "io.envara.pf-inspector-05d6-no-capsule"
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
#define SOURCE_OBSERVATION_SHA @"e77fae421722e7a5b61ed07ea1262178ea14cb0d33e6c017f6e04b9b566eaf05"
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
/* A zombie has no inspectable current executable image. This separate metadata
 * never substitutes for processObservation or any launch/cleanup identity gate. */
static NSDictionary *zombieFrontFromBSD(const struct proc_bsdinfo*a,const struct proc_bsdinfo*b,pid_t pid,NSString*birth,pid_t parent){
 if(!a||!b||pid<2||parent<2||a->pbi_pid!=(uint32_t)pid||b->pbi_pid!=(uint32_t)pid||a->pbi_ppid!=(uint32_t)parent||b->pbi_ppid!=(uint32_t)parent||
  a->pbi_status!=SZOMB||b->pbi_status!=SZOMB||!a->pbi_start_tvsec||a->pbi_start_tvusec>=1000000||b->pbi_start_tvusec>=1000000||
  a->pbi_start_tvsec!=b->pbi_start_tvsec||a->pbi_start_tvusec!=b->pbi_start_tvusec||a->pbi_xstatus!=b->pbi_xstatus||
  a->pbi_uid||a->pbi_ruid||a->pbi_svuid||a->pbi_gid||a->pbi_rgid||a->pbi_svgid||b->pbi_uid||b->pbi_ruid||b->pbi_svuid||b->pbi_gid||b->pbi_rgid||b->pbi_svgid||
  ![[NSString stringWithFormat:@"%llu:%06llu",a->pbi_start_tvsec,a->pbi_start_tvusec]isEqual:birth])return nil;
 bool available=false;int exitCode=-1,signalNumber=-1;
 if(a->pbi_xstatus<=UINT16_MAX){int status=(int)a->pbi_xstatus;if(WIFEXITED(status)){available=true;exitCode=WEXITSTATUS(status);signalNumber=0;}
  else if(WIFSIGNALED(status)){available=true;signalNumber=WTERMSIG(status);}}
 return @{@"state":@"exact-recorded-zombie",@"exitStatusAvailable":@((BOOL)available),@"exitCode":@(exitCode),@"signal":@(signalNumber),@"causeVerified":@NO};
}
static NSDictionary *zombieFrontObservation(NSDictionary*t){
 if(!nonBoolInteger(t[@"frontPID"],2,INT32_MAX)||!nonBoolInteger(t[@"keeperPID"],2,INT32_MAX)||!regex(t[@"frontBirth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$"))return nil;
 struct proc_bsdinfo a={0},b={0};pid_t pid=[t[@"frontPID"]intValue];
 if(proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&a,sizeof(a))!=sizeof(a)||proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&b,sizeof(b))!=sizeof(b))return nil;
 return zombieFrontFromBSD(&a,&b,pid,t[@"frontBirth"],[t[@"keeperPID"]intValue]);
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
  ![@[@"preparing",@"staged",@"running",@"stopping",@"cleanup-required"]containsObject:r[@"phase"]]||!isBool(r[@"cleanupUncertain"])||r[@"filterReplacement"]!=NSNull.null||r[@"filterReceipt"]!=NSNull.null||![r[@"guardians"]isEqual:@[]]||![r[@"incompleteGroupAllocations"]isEqual:@[]])return false;
 NSDictionary*app=r[@"application"],*root=r[@"rootHook"],*reference=r[@"ownedPFReference"];
 if(!keys(app,@[@"environmentId",@"routeId",@"registrationId",@"versionId",@"ticketId",@"leaseSHA256",@"transport",@"child",@"resumed"])||![app[@"environmentId"]isEqual:FIXED_ENV]||
   ![app[@"registrationId"]isEqual:l[@"registrationId"]]||![app[@"versionId"]isEqual:l[@"versionId"]]||!uuidString(app[@"ticketId"])||!regex(app[@"routeId"],@"^pf_[0-9a-f]{32}$")||
   ![app[@"leaseSHA256"]isEqual:hashText([[NSString alloc]initWithData:bytes encoding:NSUTF8StringEncoding])]||!isBool(app[@"resumed"])||(app[@"child"]!=NSNull.null&&(!keys(app[@"child"],@[@"pid",@"birth"])||!nonBoolInteger(app[@"child"][@"pid"],2,INT32_MAX)||!regex(app[@"child"][@"birth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$"))))return false;
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
typedef struct {NSDictionary *transport;gid_t gid;} InspectionFDContext;
typedef struct {uint32_t fd,kind,family,type,protocol,dev,uid,gid;uint64_t socket,pcb,inode;uint32_t tcp_state,local_address,foreign_address;uint16_t local_port,foreign_port;uint32_t ctl_id,ctl_unit;char ctl_name[MAX_KCTL_NAME];} InspectionSocketIdentity;
typedef struct {struct proc_fdinfo*list;InspectionSocketIdentity*sockets;int bytes,count,capacity;unsigned socket_count,listener_count,utun_count;int listener_fd,utun_fd;struct stat listener;} InspectionFDPass;
static bool inspectionFDBytes(int capacity,int buffer,int bytes){return capacity>0&&capacity<=65536&&capacity%(int)sizeof(struct proc_fdinfo)==0&&buffer>capacity&&bytes>0&&bytes<=capacity&&bytes<buffer&&bytes%(int)sizeof(struct proc_fdinfo)==0;}
static void inspectionFreeFDPass(InspectionFDPass*p){free(p->list);free(p->sockets);memset(p,0,sizeof(*p));}
/* PROC_PIDFDSOCKETINFO is not fstat. Pinned public Apple XNU f6217:
 * proc_info.c:2692-2702 zeros socket_fdinfo; socket_info.c:74-261 never
 * fills soi_stat. Its UID/GID/dev/inode therefore remain placeholders,
 * unlike sys_socket.c:382-395 fstat's actual so_cred. The current exact
 * inspection/run145 root diagnostic 20261009T051555Z independently observed 0/0
 * in two complete stable passes. Public xnu-12377 source is not the live
 * host's xnu-13432 source attestation. This strict 0/0 placeholder check
 * proves no creator credential or historical original FD. Realm7100,
 * root-process credentials/birth, opaque socket/PCB, tuple, unit and all
 * existing cleanup gates remain separate and mandatory. */
static bool inspectionSocketInfoStatPlaceholder(uid_t uid,gid_t gid,gid_t expectedRealm){return expectedRealm>=7100&&expectedRealm<=7999&&uid==0&&gid==0;}
static bool inspectionReadFDPass(pid_t pid,InspectionFDContext*c,InspectionFDPass*out){
 memset(out,0,sizeof(*out));out->capacity=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
 if(out->capacity<=0||out->capacity>65536||out->capacity%(int)sizeof(struct proc_fdinfo))return false;
 /* NULL returns allocation capacity, not populated bytes. Extra slack makes
  * an exact-filled buffer distinguishable from a complete actual short list. */
 int buffer=out->capacity+32*(int)sizeof(struct proc_fdinfo);out->list=calloc(1,(size_t)buffer);if(!out->list)return false;
 out->bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,out->list,buffer);if(!inspectionFDBytes(out->capacity,buffer,out->bytes)){inspectionFreeFDPass(out);return false;}
 out->count=out->bytes/(int)sizeof(*out->list);out->sockets=calloc((size_t)out->count,sizeof(*out->sockets));if(!out->sockets){inspectionFreeFDPass(out);return false;}
 unsigned expectedUnit=0;if(c&&(sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&expectedUnit)!=1||expectedUnit==UINT_MAX)){inspectionFreeFDPass(out);return false;}
 for(int i=0;i<out->count;i++){
  if((i&&out->list[i].proc_fd<=out->list[i-1].proc_fd)||out->list[i].proc_fd<0){inspectionFreeFDPass(out);return false;}
  if(out->list[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;struct socket_fdinfo s={0};
  if(proc_pidfdinfo(pid,out->list[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s))!=sizeof(s)){inspectionFreeFDPass(out);return false;}
  InspectionSocketIdentity*w=&out->sockets[out->socket_count++];w->fd=out->list[i].proc_fd;w->kind=s.psi.soi_kind;w->family=s.psi.soi_family;w->type=s.psi.soi_type;w->protocol=s.psi.soi_protocol;
  w->socket=s.psi.soi_so;w->pcb=s.psi.soi_pcb;w->dev=s.psi.soi_stat.vst_dev;w->inode=s.psi.soi_stat.vst_ino;w->uid=s.psi.soi_stat.vst_uid;w->gid=s.psi.soi_stat.vst_gid;
  if(s.psi.soi_kind==SOCKINFO_TCP){struct in_sockinfo*in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;w->tcp_state=s.psi.soi_proto.pri_tcp.tcpsi_state;
   w->local_port=(uint16_t)in->insi_lport;w->foreign_port=(uint16_t)in->insi_fport;w->local_address=in->insi_laddr.ina_46.i46a_addr4.s_addr;w->foreign_address=in->insi_faddr.ina_46.i46a_addr4.s_addr;
   if(c&&s.psi.soi_family==AF_INET&&s.psi.soi_type==SOCK_STREAM&&w->tcp_state==TSI_S_LISTEN&&in->insi_lport==htons([c->transport[@"frontPort"]unsignedShortValue])&&w->local_address==htonl(INADDR_LOOPBACK)){
    if(!inspectionSocketInfoStatPlaceholder(w->uid,w->gid,(gid_t)c->gid)){inspectionFreeFDPass(out);return false;}out->listener_count++;out->listener_fd=out->list[i].proc_fd;out->listener.st_dev=(dev_t)w->dev;out->listener.st_ino=(ino_t)w->inode;
   }
  }
  if(s.psi.soi_family==AF_SYSTEM&&s.psi.soi_kind==SOCKINFO_KERN_CTL){struct kern_ctl_info*k=&s.psi.soi_proto.pri_kern_ctl;
   if(!memchr(k->kcsi_name,0,sizeof(k->kcsi_name))){inspectionFreeFDPass(out);return false;}w->ctl_id=k->kcsi_id;w->ctl_unit=k->kcsi_unit;memcpy(w->ctl_name,k->kcsi_name,sizeof(w->ctl_name));
   if(c&&!strcmp(k->kcsi_name,"com.apple.net.utun_control")&&k->kcsi_unit==expectedUnit+1){out->utun_count++;out->utun_fd=out->list[i].proc_fd;}
  }
 }return true;
}
static bool inspectionFDPassesSame(const InspectionFDPass*a,const InspectionFDPass*b){return a->count>0&&a->bytes==b->bytes&&a->socket_count==b->socket_count&&
 !memcmp(a->list,b->list,(size_t)a->bytes)&&!memcmp(a->sockets,b->sockets,a->socket_count*sizeof(*a->sockets))&&a->listener_count==b->listener_count&&a->utun_count==b->utun_count&&
 a->listener_fd==b->listener_fd&&a->utun_fd==b->utun_fd;}

/* Count matching nonzero kernel socket identities in RAM only. Two descriptor
 * aliases are not two tunnels; neither this census nor zero stat placeholders
 * proves historical original FD custody or actual creator credentials. */
static unsigned inspectionUTunObjects(const InspectionFDPass*p,unsigned unit,bool*aliases){
 *aliases=false;if(!p||unit==UINT_MAX||p->socket_count>8192)return 0;unsigned matches=0,objects=0;const InspectionSocketIdentity*first=NULL;bool same=true;
 for(unsigned i=0;i<p->socket_count;i++){const InspectionSocketIdentity*w=&p->sockets[i];
  if(w->family!=AF_SYSTEM||w->kind!=SOCKINFO_KERN_CTL||w->ctl_unit!=unit+1||strcmp(w->ctl_name,"com.apple.net.utun_control"))continue;
  if(!w->socket)return 0;matches++;if(!first)first=w;else if(w->socket!=first->socket||w->pcb!=first->pcb||w->ctl_id!=first->ctl_id||w->ctl_unit!=first->ctl_unit)same=false;
  bool seen=false;for(unsigned j=0;j<i;j++){const InspectionSocketIdentity*v=&p->sockets[j];if(v->family==AF_SYSTEM&&v->kind==SOCKINFO_KERN_CTL&&v->ctl_unit==unit+1&&!strcmp(v->ctl_name,"com.apple.net.utun_control")&&v->socket==w->socket){seen=true;break;}}
  if(!seen)objects++;
 }if(matches!=p->utun_count)return 0;*aliases=matches>1&&objects==1&&same;return objects;
}
static NSDictionary *kernelCustodyObservation(NSDictionary*lease,NSDictionary*t,uint64_t gid){
 InspectionFDContext c={.transport=t,.gid=(gid_t)gid};InspectionFDPass a={0},b={0};
 pid_t pid=[t[@"keeperPID"]intValue];pid_t parent=[lease[@"controllerPid"]intValue];
 NSDictionary*before=processObservation(@"keeper",t[@"keeperPID"],t[@"keeperBirth"],NATIVE,parent);
 bool first=[before[@"state"]isEqual:@"live-exact-recorded-identity"]&&inspectionReadFDPass(pid,&c,&a);
 NSDictionary*middle=processObservation(@"keeper",t[@"keeperPID"],t[@"keeperBirth"],NATIVE,parent);
 bool second=first&&[middle[@"state"]isEqual:@"live-exact-recorded-identity"]&&inspectionReadFDPass(pid,&c,&b);
 NSDictionary*after=processObservation(@"keeper",t[@"keeperPID"],t[@"keeperBirth"],NATIVE,parent);
 bool identities=before&&middle&&after&&[before isEqual:middle]&&[middle isEqual:after]&&[after[@"state"]isEqual:@"live-exact-recorded-identity"];
 bool stable=first&&second&&inspectionFDPassesSame(&a,&b);unsigned idx=if_nametoindex([t[@"interfaceName"]UTF8String]);
 unsigned unit=UINT_MAX;bool firstAliases=false,secondAliases=false;sscanf([t[@"interfaceName"]UTF8String],"utun%u",&unit);
 unsigned firstObjects=first?inspectionUTunObjects(&a,unit,&firstAliases):0,secondObjects=second?inspectionUTunObjects(&b,unit,&secondAliases):0;
 NSDictionary*out=@{@"firstComplete":@((BOOL)first),@"secondComplete":@((BOOL)second),@"firstQueryBytes":@(MAX(0,a.capacity)),@"firstReadBytes":@(MAX(0,a.bytes)),@"secondQueryBytes":@(MAX(0,b.capacity)),@"secondReadBytes":@(MAX(0,b.bytes)),@"firstFDCount":@(MAX(0,a.count)),@"secondFDCount":@(MAX(0,b.count)),@"firstSocketCount":@(a.socket_count),@"secondSocketCount":@(b.socket_count),@"firstListenerCount":@(a.listener_count),@"secondListenerCount":@(b.listener_count),@"firstUTunCount":@(a.utun_count),@"secondUTunCount":@(b.utun_count),@"interfaceIndex":@(idx),@"metadataStable":@((BOOL)stable),@"keeperIdentityStable":@((BOOL)identities),@"uniqueCurrentCustodyObserved":@((BOOL)(stable&&identities&&idx&&a.listener_count==1&&b.listener_count==1&&a.utun_count==1&&b.utun_count==1)),@"firstUTunObjectCount":@(firstObjects),@"secondUTunObjectCount":@(secondObjects),@"firstUTunDescriptorsAliasSameObject":@((BOOL)firstAliases),@"secondUTunDescriptorsAliasSameObject":@((BOOL)secondAliases),@"creatorCredentialVerified":@NO,@"originalDescriptorCustodyVerified":@NO};
 inspectionFreeFDPass(&a);inspectionFreeFDPass(&b);return out;
}
static NSDictionary *ticketStoreObservation(NSDictionary*record){
 NSString*id=record[@"application"][@"ticketId"];if(!uuidString(id))return nil;
 const char*storePath="/Library/PrivilegedHelperTools/io.envara.pf-app-tickets";
 int store=directory(storePath);if(store<0){if(errno!=ENOENT)return nil;return @{@"storePresent":@NO,@"ticketDirectoryPresent":@NO,@"reservedPresent":@NO,@"issuedPresent":@NO,@"claimedPresent":@NO,@"entryCount":@0,@"inventorySHA256":hashText(@""),@"stablePrivateInventoryVerified":@YES,@"contentBindingsVerified":@NO};}
 if(!secureFD(store,true,0700)){close(store);return nil;}
 int ticket=openat(store,id.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(ticket<0){int error=errno;close(store);if(error!=ENOENT)return nil;return @{@"storePresent":@YES,@"ticketDirectoryPresent":@NO,@"reservedPresent":@NO,@"issuedPresent":@NO,@"claimedPresent":@NO,@"entryCount":@0,@"inventorySHA256":hashText(@""),@"stablePrivateInventoryVerified":@YES,@"contentBindingsVerified":@NO};}
 if(!secureFD(ticket,true,0700)){close(ticket);close(store);return nil;}struct stat held,named;if(fstat(ticket,&held)){close(ticket);close(store);return nil;}
 NSDictionary*before=directorySnapshot(ticket);if(!before){close(ticket);close(store);return nil;}
 NSMutableDictionary*out=[@{@"storePresent":@YES,@"ticketDirectoryPresent":@YES,@"entryCount":before[@"entryCount"],@"inventorySHA256":before[@"inventorySHA256"],@"stablePrivateInventoryVerified":@NO,@"contentBindingsVerified":@NO}mutableCopy];
 NSArray*names=@[@"reserved",@"ticket",@"claimed"],*fields=@[@"reservedPresent",@"issuedPresent",@"claimedPresent"];unsigned count=0;bool okay=true;
 for(unsigned i=0;i<3;i++){struct stat st;int found=fstatat(ticket,[names[i]UTF8String],&st,AT_SYMLINK_NOFOLLOW);if(!found){int file=openat(ticket,[names[i]UTF8String],O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(file<0||!secureFD(file,false,0600)||st.st_size<=0||st.st_size>1048576){if(file>=0)close(file);okay=false;break;}close(file);count++;out[fields[i]]=@YES;}else if(errno==ENOENT)out[fields[i]]=@NO;else {okay=false;break;}}
 NSDictionary*after=directorySnapshot(ticket);okay=okay&&after&&[before isEqual:after]&&[before[@"entryCount"]unsignedIntValue]==count&&fstatat(store,id.UTF8String,&named,AT_SYMLINK_NOFOLLOW)==0&&sameStat(&held,&named);
 close(ticket);close(store);if(!okay)return nil;out[@"stablePrivateInventoryVerified"]=@YES;return out;
}

static int emitInspection(NSDictionary*out){NSData*d=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!d||fwrite(d.bytes,1,d.length,stdout)!=d.length||fputc('\n',stdout)==EOF)return 1;fflush(stdout);return [out[@"ok"]boolValue]?0:1;}
static NSMutableDictionary *inspectionOutcome(void){return [@{@"schema":INSPECTION_SCHEMA,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"sourceObservationSHA256":SOURCE_OBSERVATION_SHA,@"readOnly":@YES,@"ok":@NO,@"reason":@"INSPECTION_UNCONFIRMED",@"gate":@"not-started",@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"cleanupPermitted":@NO,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"ownedAppOrKeeperSignalExecuted":@NO,@"runtimeChanged":@NO}mutableCopy];}
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
  out[@"registryObservation"]=@{@"phase":record[@"phase"],@"cleanupUncertain":record[@"cleanupUncertain"],@"childRecorded":@((BOOL)(record[@"application"][@"child"]!=NSNull.null)),@"resumed":record[@"application"][@"resumed"]};
  out[@"ticketStoreObservation"]=ticketStoreObservation(record);if(!out[@"ticketStoreObservation"])break;
  out[@"kernelCustodyObservation"]=kernelCustodyObservation(lease,transport,gid);
  out[@"ownedReferenceRecordedUnreleased"]=@YES;out[@"realmGID"]=@(gid);out[@"privateFileIdentities"]=@{@"runtimeDevice":@(rooti.st_dev),@"runtimeInode":@(rooti.st_ino),@"runDevice":@(runi.st_dev),@"runInode":@(runi.st_ino),@"leaseDevice":@(li.st_dev),@"leaseInode":@(li.st_ino),@"registryDevice":@(ri.st_dev),@"registryInode":@(ri.st_ino)};
  out[@"gate"]=@"recorded-processes";NSMutableArray*processes=[NSMutableArray array];NSDictionary*p=processObservation(@"controller",lease[@"controllerPid"],lease[@"controllerBirth"],INSTALL "/node",0);if(!p)break;[processes addObject:p];
  p=processObservation(@"keeper",transport[@"keeperPID"],transport[@"keeperBirth"],NATIVE,[lease[@"controllerPid"]intValue]);if(!p||![p[@"state"]isEqual:@"live-exact-recorded-identity"])break;[processes addObject:p];out[@"recordedProcesses"]=processes;
  /* Safe private progress is observed only after exact live keeper identity,
   * before front-image availability. Original role gates remain below. */
  out[@"gidScopeObservation"]=@(envara_app_scope_gid_absent((gid_t)gid));
  out[@"gate"]=@"native-journal";NSDictionary*j=readJournal(run,lease,transport[@"keeperPID"]);if(!j)break;out[@"journal"]=j;
  out[@"gate"]=@"owned-active-classes";NSDictionary*classes=activeClassObservation();if(!classes)break;out[@"activeClasses"]=classes;
  out[@"lastJournalRevisionAndCountMatchActiveFilter"]=@(journalMatchesActiveFilter(j,classes));
  NSDictionary*zombie=zombieFrontObservation(transport);if(zombie)out[@"zombieFrontObservation"]=zombie;
  out[@"gate"]=@"recorded-processes";p=processObservation(@"core",transport[@"corePID"],transport[@"coreBirth"],INSTALL "/mihomo",[transport[@"keeperPID"]intValue]);if(!p)break;[processes addObject:p];
  p=processObservation(@"front",transport[@"frontPID"],transport[@"frontBirth"],INSTALL "/node",[transport[@"keeperPID"]intValue]);if(!p)break;[processes addObject:p];out[@"recordedProcesses"]=processes;
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
   ![j isEqual:readJournal(run,lease,transport[@"keeperPID"])]||![out[@"ticketStoreObservation"]isEqual:ticketStoreObservation(record)])break;
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
