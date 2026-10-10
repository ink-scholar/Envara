/* Isolated, fixed-run READ-ONLY recovery inspector. Not a manifest input.
 * No installation, PF writes, deletion, group/tunnel operations or app launch.
 * Root registry/lease stays private; only literal diagnostic fields leave.
 * Build/review and separate native administrator approval are required. */
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libproc.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#include "pf-hook-abi.h"
#include "recovery-runtime-inventory-832-run95c92.h"
#include "recovery-gid-proof-832-run95c92.h"
#include <ifaddrs.h>

#define FIXED_RUN @"95c92c49-063e-4595-b28f-232f558d6f6e"
#define FIXED_ANCHOR @"io.envara.pf.run.95c92c49-063e-4595-b28f-232f558d6f6e"
#define INSTALL_PARENT "/Library/PrivilegedHelperTools"
#define INSTALL INSTALL_PARENT "/io.envara.pf-routing"
#define RUNTIME "/Library/PrivilegedHelperTools/io.envara.pf-runtime"
#define NATIVE INSTALL "/envara-pf-native"
#define MF "83256899dc6db90bb6a21dcd18d17cb08a46d3ba4e79177098629475cc107f78"
#define ROOT_RULE @"7f79342e7409a1d3569220b8e143c1f261574ae1ae7de6a07b915a2364316bb5"
#define ROOT_TEXT @"5e803c2e459d5417da5d61aba888d1da25ad56cb0bff4f22e69d36078eb7f575"
#define PFCTL "/sbin/pfctl"
#define PFCTL_SHA "ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef"
#define PFCTL_MODE 0555
#define SCHEMA @"envara.macos-pf-readonly-recovery/v1"
typedef struct { const char *name, *sha; mode_t mode; } FixedFile;
static const FixedFile files[] = {
 {"manifest.json", MF, 0644},
 {"node", "ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a", 0755},
 {"node-LICENSE", "148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5", 0644},
 {"mihomo", "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66", 0755},
 {"mihomo-LICENSE", "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986", 0644},
 {"mihomo-SOURCE.md", "abba5783d51be50d72260f6dea97e3df7b4e6e0cc32a46339cfe357c719e66a0", 0644},
 {"mihomo-corresponding-source.tar.gz", "6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb", 0644},
 {"envara-pf-native", "8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8", 0755},
 {"helper.mjs", "6e6ad1aff6f21d0ecdc2908201757f83ba9128f8dcd9338debbef8e41861ba5c", 0644},
 {"controller.mjs", "3a340f269a289c631ee46b0fe5d869988801da5d5694f717867be380041026fb", 0644},
 {"policy.mjs", "02deb8c99596939034e3d1338c42daa5b1cbda66f8ba4d412bb5c7147ea89cde", 0644},
 {"stateless-verifier.mjs", "13f09ec1c42d8dfe5541b692fb10a3667d10469450c3717ec18584a2cb26b9a6", 0644},
 {"EnvaraPFHelper", "89b32f784003031c3b005898ac2b2e601edeff5ef91e9a4e60dcf5e0d59ff345", 0755},
 {"LICENSE", "c5c17ea1c06b26cb4a04e72bef9072dbb6ef52cb36b721a9ee2b98b29e66bc28", 0644},
 {"fixtures/EnvaraRoutingAcceptanceFixture", "4944df4dbd5032b756149e1ffb4156e5d25874e3c10e9e5d33ce87b3deddc763", 0755},
};
static const char *failure = "INSPECTION_REFUSED";
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
 if (![lease[@"schema"] isEqual:@"envara.macos-pf-owned-root-hook-lease/v2"] || ![lease[@"runId"] isEqual:FIXED_RUN] ||
  !regex(lease[@"leaseId"], @"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$") ||
  ![lease[@"anchor"] isEqual:FIXED_ANCHOR] || ![lease[@"owner"] isEqual:FIXED_ANCHOR] ||
  ![lease[@"rootBeforeSHA256"] isEqual:ROOT_RULE] || ![lease[@"rootBeforeTextSHA256"] isEqual:ROOT_TEXT] ||
  !regex(lease[@"ticket"], @"^[1-9][0-9]{0,19}$")) return false;
 NSString *ticket = lease[@"ticket"]; if (ticket.length == 20 && [ticket compare:@"18446744073709551615" options:NSLiteralSearch] == NSOrderedDescending) return false;
 NSString *label = [@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@", FIXED_RUN, lease[@"leaseId"]]) substringToIndex:32]];
 return [lease[@"label"] isEqual:label];
}
static bool positivePID(id value) { return [value isKindOfClass:NSNumber.class] && !isBool(value) &&
 [value doubleValue] == [value longLongValue] && [value longLongValue] > 1 && [value longLongValue] <= INT32_MAX; }
static NSDictionary *validRegistry(NSData *data) {
 NSDictionary *record = strictJSON(data, 65536);
 if (!keys(record, @[@"schema", @"runId", @"supervisorPid", @"anchor", @"phase", @"cleanupUncertain", @"rootHook", @"ownedPFReference", @"incompleteGroupAllocations", @"realms", @"guardians"]) ||
  ![record[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"] || ![record[@"runId"] isEqual:FIXED_RUN] ||
  ![record[@"anchor"] isEqual:FIXED_ANCHOR] || !positivePID(record[@"supervisorPid"]) || !isBool(record[@"cleanupUncertain"]) ||
  ![@[@"preparing", @"fixtures-running", @"fault", @"transport-fault", @"cleaning", @"cleaned", @"cleanup-required"] containsObject:record[@"phase"]]) return nil;
 NSDictionary *hook = record[@"rootHook"], *reference = record[@"ownedPFReference"];
 if (!keys(hook, @[@"mutationAttempted", @"verified", @"removed", @"receiptRetired", @"namespaceState", @"namespaceReclaimed", @"lease"]) || !isBool(hook[@"mutationAttempted"]) ||
  !isBool(hook[@"receiptRetired"]) || !isBool(hook[@"namespaceReclaimed"]) ||
  ![@[@"present",@"absent",@"unknown",@"unselected"] containsObject:hook[@"namespaceState"]] ||
  !isBool(hook[@"verified"]) || !isBool(hook[@"removed"]) || !validLease(hook[@"lease"]) ||
  !keys(reference, @[@"attempted", @"acquired", @"released", @"token"]) ||
  !isBool(reference[@"attempted"]) || !isBool(reference[@"acquired"]) || !isBool(reference[@"released"])) return nil;
 for (NSString *name in @[@"incompleteGroupAllocations", @"realms", @"guardians"])
  if (![record[name] isKindOfClass:NSArray.class] || [record[name] count] > ([name isEqual:@"realms"] ? 2 : 16)) return nil;
 for (id realm in record[@"realms"]) {
  if (![realm isKindOfClass:NSDictionary.class] || ![realm[@"fixtures"] isKindOfClass:NSArray.class] || [realm[@"fixtures"] count] > 6) return nil;
  for (id fixture in realm[@"fixtures"]) if (![fixture isKindOfClass:NSDictionary.class] || !positivePID(fixture[@"pid"]) ||
   !regex(fixture[@"birth"], @"^[1-9][0-9]{0,19}:[0-9]{6}$")) return nil;
 }
 for (id guard in record[@"guardians"]) if (![guard isKindOfClass:NSDictionary.class] || !positivePID(guard[@"guardianPid"]) ||
  (guard[@"pid"] != NSNull.null && !positivePID(guard[@"pid"]))) return nil;
 if (![record[@"phase"] isEqual:@"cleanup-required"] || ![record[@"cleanupUncertain"] boolValue] ||
  [record[@"realms"] count]!=2 || [record[@"guardians"] count]!=4) return nil;
 gid_t gids[2]; if (!EG832Record(record,gids)) return nil;
 NSMutableSet *identities=[NSMutableSet setWithObject:record[@"supervisorPid"]];
 for (NSDictionary *realm in record[@"realms"]) {
  if ([realm[@"fixtures"] count]!=2 || ![realm[@"tunnel"] isKindOfClass:NSDictionary.class]) return nil;
  NSMutableSet *roles=[NSMutableSet set];
  for (NSDictionary *fixture in realm[@"fixtures"]) {
   if (![@[@"parent",@"child"] containsObject:fixture[@"role"]] || [roles containsObject:fixture[@"role"]]) return nil;
   [roles addObject:fixture[@"role"]]; [identities addObject:fixture[@"pid"]];
  }
  NSDictionary *t=realm[@"tunnel"];
  if (!regex(t[@"interfaceName"],@"^utun[0-9]{1,5}$") || !positivePID(t[@"pid"]) || !positivePID(t[@"guardianPid"]) ||
   !regex(t[@"coreBirth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$") || !isBool(t[@"fdRetained"])) return nil;
  [identities addObject:t[@"pid"]]; [identities addObject:t[@"guardianPid"]];
 }
 for (NSDictionary *guard in record[@"guardians"]) {
  if (![@[@"fixture",@"tunnel"] containsObject:guard[@"kind"]] || !isBool(guard[@"exited"])) return nil;
  [identities addObject:guard[@"guardianPid"]]; if (positivePID(guard[@"pid"])) [identities addObject:guard[@"pid"]];
 }
 if (identities.count!=11) return nil;
 return record;
}
static NSData *readHeld(int fd, struct stat *before) {
 if (!secureFD(fd, false, 0600) || fstat(fd, before) || before->st_size < 1 || before->st_size > 65536) return nil;
 NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before->st_size]; size_t at = 0;
 while (at < data.length) { ssize_t size = pread(fd, (unsigned char *)data.mutableBytes + at, data.length - at, (off_t)at);
  if (size < 0 && errno == EINTR) continue; if (size <= 0) return nil; at += (size_t)size; }
 struct stat after; return !fstat(fd, &after) && sameStat(before, &after) ? data : nil;
}
static bool heldRegistryUnchanged(int runtime, int registry, const struct stat *before) {
 struct stat held, current; return !fstat(registry, &held) && !fstatat(runtime, "registry.json", &current, AT_SYMLINK_NOFOLLOW) &&
  secureFD(registry, false, 0600) && sameStat(before, &held) && sameStat(before, &current);
}
#define NATIVE_SCHEMA @"envara.macos-pf-owned-root-hook/v2"
#define OUTPUT_LIMIT (128U*1024U)
static double rootDeadline;
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
static const char *nativeOperation(unsigned operation) { return operation==0 ? "hook-status" : NULL; }
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
 NSString *expected = baseline ? @"" : FIXED_ANCHOR;
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
static NSData *fixedProcess(const char *executable, char *const argv[], NSData *input, int *exitStatus) {
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
 double deadline = MIN(rootDeadline,seconds() + 10);
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

static NSDictionary *safeHook(NSDictionary *proof) {
 if (![proof isKindOfClass:NSDictionary.class]) return nil;
 NSMutableDictionary *value=[NSMutableDictionary dictionary];
 for (NSString *key in @[@"ok",@"pfDisabled",@"pinsVerified",@"originalRootCompatible",@"ownedRootHookVerified",@"hookInstalled",
  @"canCreateOwnedHook",@"ownedRootHookCanCreate",@"priorAnchorsCompatible",@"ownedRootHookRemoved",@"originalRootRestored",
  @"receiptRetired",@"namespaceReclaimed",@"namespaceExists",@"cleanupPending",@"inactiveQueuesVerified",@"namespaceReferencesVerified"]) {
  if (!isBool(proof[key])) return nil; value[key]=proof[key]; }
 value[@"namespaceState"]=proof[@"namespaceState"]; value[@"runLedgerState"]=proof[@"runLedgerState"];
 value[@"rootRulesMatchOriginalFingerprint"]=@([proof[@"originalRootSHA256"] isEqual:ROOT_RULE]);
 value[@"rootTextMatchesOriginalFingerprint"]=@([proof[@"originalRootTextSHA256"] isEqual:ROOT_TEXT]);
 value[@"rootRuleCountAvailable"]=@NO; value[@"ownedChildRuleCountsAvailable"]=@NO;
 value[@"nativeReason"]=[nativeReasons() containsObject:proof[@"reason"]]?proof[@"reason"]:@"UNRECOGNIZED_NATIVE_REASON";
 return value;
}
static NSDictionary *nativeHook(int installed, NSDictionary *lease, double deadline) {
 if(seconds()>=deadline || (lease && !validLease(lease))) { refuse("PRIVATE_INPUT_REFUSED"); return nil; }
 int fd=relativeFile(installed,"envara-pf-native"); struct stat held,current;
 bool stable=secureFD(fd,false,0755) && !fstat(fd,&held) && !lstat(NATIVE,&current) && sameStat(&held,&current);
 if(fd>=0) close(fd); if(!stable) { refuse("FIXED_NATIVE_IDENTITY_REFUSED"); return nil; }
 NSData *input=[NSJSONSerialization dataWithJSONObject:lease?@{@"lease":lease}:@{} options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 char *argv[]={NATIVE,"hook-status",NULL}; int exitStatus=-1;
 NSData *data=fixedProcess(NATIVE,argv,input,&exitStatus);
 NSDictionary *decoded=data?nativeProof(data,0,!lease,exitStatus):nil;
 NSMutableDictionary *safe=[safeHook(decoded) mutableCopy];
 if(!safe) refuse("READ_ONLY_NATIVE_SCHEMA_REFUSED"); else safe[@"nativeExitStatus"]=@(exitStatus);
 return safe;
}
static NSDictionary *processProof(NSDictionary *record) {
 NSMutableSet *pids = [NSMutableSet setWithObject:record[@"supervisorPid"]]; NSMutableDictionary *births = [NSMutableDictionary dictionary];
 for (NSDictionary *realm in record[@"realms"]) for (NSDictionary *fixture in realm[@"fixtures"]) {
  [pids addObject:fixture[@"pid"]]; births[fixture[@"pid"]] = fixture[@"birth"];
 }
 for (NSDictionary *guard in record[@"guardians"]) {
  [pids addObject:guard[@"guardianPid"]]; if (positivePID(guard[@"pid"])) { [pids addObject:guard[@"pid"]];
   if (regex(guard[@"birth"], @"^[1-9][0-9]{0,19}:[0-9]{6}$")) births[guard[@"pid"]] = guard[@"birth"]; }
 }
 NSUInteger absent = 0, live = 0, unknown = 0, changed = 0;
 for (NSNumber *value in pids) {
  struct proc_bsdinfo a = {0}, b = {0}; errno = 0; int ra = proc_pidinfo(value.intValue, PROC_PIDTBSDINFO, 0, &a, sizeof(a)); int ea = errno;
  errno = 0; int rb = proc_pidinfo(value.intValue, PROC_PIDTBSDINFO, 0, &b, sizeof(b)); int eb = errno;
  if (!ra && !rb && ea == ESRCH && eb == ESRCH) { absent++; continue; }
  if (ra != (int)sizeof(a) || rb != (int)sizeof(b) || a.pbi_pid != value.unsignedIntValue || b.pbi_pid != a.pbi_pid ||
   a.pbi_start_tvsec != b.pbi_start_tvsec || a.pbi_start_tvusec != b.pbi_start_tvusec) { unknown++; continue; }
  NSString *birth = [NSString stringWithFormat:@"%llu:%06llu", (unsigned long long)b.pbi_start_tvsec, (unsigned long long)b.pbi_start_tvusec];
  if (births[value] && ![births[value] isEqual:birth]) { changed++; continue; }
  live++;
 }
 // Missing births for supervisor/guardian mean a live PID remains uncertain;
 // never infer extinction from an identity mismatch or registry exited flags.
 return @{@"recordedProcessCount": @(pids.count), @"absentPIDsDoubleChecked": @(absent), @"liveRecordedPIDs": @(live),
  @"unreadableOrUnstablePIDs": @(unknown), @"birthMismatches": @(changed), @"controlledProcessesGone": @((BOOL)(absent == pids.count))};
}
typedef int (*RuleReader)(int, unsigned long, EnvaraPFHookRequest *, void *);
static const unsigned char ruleActions[] = {0,2,4,6,8,11};
static NSArray *ruleNames(void) { return @[@"filter",@"scrub",@"nat",@"binat",@"rdr",@"dummynet"]; }
static int nativeRuleReader(int fd, unsigned long operation, EnvaraPFHookRequest *request, void *context) {
 (void)context; return ioctl(fd, operation, request);
}
static NSDictionary *readRuleClass(int fd, unsigned char action, RuleReader reader, void *context) {
 size_t index = 0; while (index < sizeof(ruleActions) && ruleActions[index] != action) index++;
 if (index == sizeof(ruleActions) || !reader) return nil;
 EnvaraPFHookRequest first = {0}, second = {0}; first.rule.action = second.rule.action = action;
 // Outer action remains literal PF_GET_NONE=0. Never reset counters, inspect
 // inactive queues, or invoke a mutation. No receipt/ticket leaves this scope.
 strcpy(first.anchor,"io.envara.pf.run.95c92c49-063e-4595-b28f-232f558d6f6e"); strcpy(second.anchor,"io.envara.pf.run.95c92c49-063e-4595-b28f-232f558d6f6e");
 errno = 0; int a = reader(fd, ENVARA_PF_HOOK_GET_RULES, &first, context), ea = errno;
 errno = 0; int b = reader(fd, ENVARA_PF_HOOK_GET_RULES, &second, context), eb = errno;
 NSString *outcome = @"unreadable", *error = @"NON_EINVAL"; NSNumber *count = nil; BOOL stable = NO;
 if (a == -1 && b == -1 && ea == EINVAL && eb == EINVAL) { outcome = @"absent"; error = @"EINVAL"; stable = YES; }
 else if (a == 0 && b == 0 && first.nr <= 8192 && second.nr <= 8192) {
  error = @"NONE"; stable = first.nr == second.nr && first.ticket == second.ticket;
  outcome = stable ? @"present" : @"unstable"; if (stable) count = @(first.nr);
 } else if ((a == 0 && b == -1 && eb == EINVAL) || (b == 0 && a == -1 && ea == EINVAL)) { outcome = @"unstable"; error = @"MIXED_RESULT"; }
 return @{@"ruleset":ruleNames()[index], @"action":@(action), @"outcome":outcome, @"errnoClass":error,
  @"count":count ?: NSNull.null, @"stable":@(stable)};
}
static NSDictionary *safeActiveCounts(NSDictionary *raw) {
 if (![raw isKindOfClass:NSDictionary.class] || ![raw[@"classes"] isKindOfClass:NSArray.class] ||
  ([raw[@"classes"] count] != 0 && [raw[@"classes"] count] != 6)) return nil;
 NSMutableArray *rows = [NSMutableArray array]; BOOL readable = [raw[@"classes"] count] == 6, empty = readable;
 for (NSUInteger i = 0; i < [raw[@"classes"] count]; i++) {
  NSDictionary *value = raw[@"classes"][i]; if (![value isKindOfClass:NSDictionary.class] ||
   ![value[@"ruleset"] isEqual:ruleNames()[i]] || ![value[@"action"] isKindOfClass:NSNumber.class] || isBool(value[@"action"]) ||
   [value[@"action"] doubleValue] != ruleActions[i] || !isBool(value[@"stable"]) ||
   ![@[@"present",@"absent",@"unstable",@"unreadable"] containsObject:value[@"outcome"]] ||
   ![@[@"NONE",@"EINVAL",@"MIXED_RESULT",@"NON_EINVAL"] containsObject:value[@"errnoClass"]]) return nil;
  BOOL present = [value[@"outcome"] isEqual:@"present"], absent = [value[@"outcome"] isEqual:@"absent"];
  id count = value[@"count"];
  if (present) { if (![count isKindOfClass:NSNumber.class] || isBool(count) || [count doubleValue] != [count integerValue] ||
   [count integerValue] < 0 || [count integerValue] > 8192 || ![value[@"stable"] boolValue] || ![value[@"errnoClass"] isEqual:@"NONE"]) return nil; }
  else if (count != NSNull.null || (absent && (![value[@"stable"] boolValue] || ![value[@"errnoClass"] isEqual:@"EINVAL"])) ||
   (!absent && [value[@"stable"] boolValue])) return nil;
  readable = readable && (present || absent); empty = empty && (absent || (present && [count integerValue] == 0));
  [rows addObject:@{@"ruleset":ruleNames()[i],@"action":@(ruleActions[i]),@"outcome":value[@"outcome"],
   @"errnoClass":value[@"errnoClass"],@"count":count,@"stable":value[@"stable"]}];
 }
 return @{@"inspectionAttempted":@YES,@"readable":@(readable),@"allActiveRulesEmptyOrAbsent":@(empty),@"classes":rows};
}
static NSDictionary *activeOwnedCounts(void) {
 int fd = open("/dev/pf",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat st; NSMutableArray *rows = [NSMutableArray array];
 if (fd >= 0 && !fstat(fd,&st) && S_ISCHR(st.st_mode) && (fcntl(fd,F_GETFL)&O_ACCMODE) == O_RDONLY)
  for (size_t i = 0; i < sizeof(ruleActions); i++) [rows addObject:readRuleClass(fd,ruleActions[i],nativeRuleReader,NULL)];
 if (fd >= 0) close(fd); return safeActiveCounts(@{@"classes":rows});
}
static BOOL freshRootAllowsReadback(NSDictionary *proof) {
 if (![proof isKindOfClass:NSDictionary.class]) return NO;
 for (NSString *key in @[@"ok",@"pinsVerified",@"pfDisabled",@"originalRootCompatible",@"priorAnchorsCompatible",@"rootRulesMatchOriginalFingerprint",@"rootTextMatchesOriginalFingerprint"])
  if (!isBool(proof[key]) || ![proof[key] boolValue]) return NO;
 return isBool(proof[@"hookInstalled"]) && ![proof[@"hookInstalled"] boolValue];
}
/* Fixed read-only pfctl argument sets only. Raw listings remain in memory. */
static NSData *fixedPFListing(bool tables, int trusted, const struct stat *expected, double deadline) {
 struct stat held,path;
 if(seconds()>=deadline || !secureFD(trusted,false,PFCTL_MODE) || fstat(trusted,&held) || lstat(PFCTL,&path) ||
  !sameStat(expected,&held) || !sameStat(expected,&path)) return nil;
 char *anchors[]={PFCTL,"-a","io.envara.pf.run.95c92c49-063e-4595-b28f-232f558d6f6e","-s","Anchors",NULL};
 char *ghosts[]={PFCTL,"-g","-a","io.envara.pf.run.95c92c49-063e-4595-b28f-232f558d6f6e","-v","-s","Tables",NULL};
 int status=-1; NSData *data=fixedProcess(PFCTL,tables?ghosts:anchors,nil,&status);
 if(!data || status || fstat(trusted,&held) || lstat(PFCTL,&path) || !sameStat(expected,&held) || !sameStat(expected,&path)) return nil;
 return data;
}
static NSDictionary *parseListing(NSData *data, bool tables) {
 BOOL read = data != nil, format = read, present = NO; NSUInteger count = 0;
 NSMutableArray *flags = [NSMutableArray array]; NSMutableSet *names = [NSMutableSet set];
 NSString *text = read ? [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] : nil;
 if (!text || text.length>65536 || [text rangeOfString:@"[\\x00-\\x08\\x0b-\\x1f\\x7f]" options:NSRegularExpressionSearch].location!=NSNotFound) format = NO;
 for (NSString *row in [text componentsSeparatedByString:@"\n"]) {
  NSString *line = [row stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]; if (!line.length) continue;
  present = YES; NSString *name = line;
  if (tables) { NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:@"^([c-][p-][a-][i-][r-][h-])[ \\t]+([A-Za-z0-9_.-]{1,1024})$" options:0 error:NULL];
   NSTextCheckingResult *match = [expression firstMatchInString:line options:0 range:NSMakeRange(0,line.length)];
   if (!match) { format=NO; continue; } [flags addObject:[line substringWithRange:[match rangeAtIndex:1]]]; name=[line substringWithRange:[match rangeAtIndex:2]];
  } else if (!regex(name,@"^[A-Za-z0-9_./-]{1,1024}$") || [name containsString:@".."]) { format=NO; continue; }
  if ([names containsObject:name]) { format=NO; continue; } [names addObject:name]; count++;
 }
 return @{@"operation":tables?@"tables-with-ghosts":@"anchors",@"readSucceeded":@(read),@"formatVerified":@(format),
  @"entriesPresent":@(present),@"count":format?@(count):NSNull.null,
  @"flagsSHA256":tables && format?hashText([flags componentsJoinedByString:@"\n"]):NSNull.null};
}
static NSDictionary *listingObservation(NSData *first, NSData *second, bool tables) {
 NSDictionary *a=parseListing(first,tables), *b=parseListing(second,tables);
 BOOL read=[a[@"readSucceeded"] boolValue] && [b[@"readSucceeded"] boolValue], stable=read && [first isEqual:second];
 BOOL format=[a[@"formatVerified"] boolValue] && [b[@"formatVerified"] boolValue], present=[a[@"entriesPresent"] boolValue] || [b[@"entriesPresent"] boolValue];
 return @{@"operation":tables?@"tables-with-ghosts":@"anchors",@"readSucceeded":@(read),@"stable":@(stable),@"formatVerified":@(format),
  @"entriesPresent":@(present),@"count":stable && format?a[@"count"]:NSNull.null,
  @"emptyVerified":@((BOOL)(read && stable && format && !present)),@"flagsSHA256":tables && stable && format?a[@"flagsSHA256"]:NSNull.null};
}
static NSDictionary *safeListing(NSDictionary *raw, bool tables) {
 if (![raw isKindOfClass:NSDictionary.class] || ![raw[@"operation"] isEqual:(tables?@"tables-with-ghosts":@"anchors")]) return nil;
 NSMutableDictionary *out=[NSMutableDictionary dictionaryWithObject:raw[@"operation"] forKey:@"operation"];
 for (NSString *key in @[@"readSucceeded",@"stable",@"formatVerified",@"entriesPresent",@"emptyVerified"]) { if (!isBool(raw[key])) return nil; out[key]=raw[key]; }
 id count=raw[@"count"]; if (count!=NSNull.null && (![count isKindOfClass:NSNumber.class] || isBool(count) ||
  [count doubleValue]!=[count integerValue] || [count integerValue]<0 || [count integerValue]>65536)) return nil;
 out[@"count"]=count;
 id digest=raw[@"flagsSHA256"]; if (digest!=NSNull.null && (!tables || !regex(digest,@"^[a-f0-9]{64}$"))) return nil; out[@"flagsSHA256"]=digest;
 if ([raw[@"emptyVerified"] boolValue] && (![raw[@"readSucceeded"] boolValue] || ![raw[@"stable"] boolValue] ||
  ![raw[@"formatVerified"] boolValue] || [raw[@"entriesPresent"] boolValue] || count==NSNull.null || [count integerValue]!=0)) return nil;
 return out;
}
static NSDictionary *ownedNamespaceListings(double deadline) {
 int parent=directory("/sbin"), trusted=parent<0?-1:openat(parent,"pfctl",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); if(parent>=0) close(parent);
 struct stat expected; BOOL pinned=secureFD(trusted,false,PFCTL_MODE) && hashFD(trusted,PFCTL_SHA,deadline) && !fstat(trusted,&expected);
 NSData *a=nil,*b=nil,*c=nil,*d=nil;
 if(pinned) { a=fixedPFListing(false,trusted,&expected,deadline); b=fixedPFListing(false,trusted,&expected,deadline);
  c=fixedPFListing(true,trusted,&expected,deadline); d=fixedPFListing(true,trusted,&expected,deadline); }
 if(trusted>=0) close(trusted);
 return @{@"pfctlPinVerified":@(pinned),@"anchors":listingObservation(a,b,false),@"tablesIncludingGhosts":listingObservation(c,d,true)};
}
static NSDictionary *safeNamespaceListings(NSDictionary *raw) {
 if (![raw isKindOfClass:NSDictionary.class] || !isBool(raw[@"pfctlPinVerified"])) return nil;
 NSDictionary *anchors=safeListing(raw[@"anchors"],false), *tables=safeListing(raw[@"tablesIncludingGhosts"],true);
 if(!anchors || !tables) return nil;
 return @{@"pfctlPinVerified":raw[@"pfctlPinVerified"],@"anchors":anchors,@"tablesIncludingGhosts":tables};
}
static NSDictionary *safeRuntimeInventory(NSDictionary *raw) {
 if (![raw isKindOfClass:NSDictionary.class] || ![raw[@"schema"] isEqual:@"envara.macos-pf-runtime-inventory/v1"] ||
  !isBool(raw[@"readOnly"]) || ![raw[@"readOnly"] boolValue]) return nil;
 NSMutableDictionary *out=[@{@"schema":@"envara.macos-pf-runtime-inventory/v1",@"readOnly":@YES,@"cleanupConfirmed":@NO,@"productionReady":@NO} mutableCopy];
 for (NSString *key in @[@"recordIdentityVerified",@"runtimeDirectoryVerified",@"registryFileVerified",@"lockFileVerified",@"lockRecordVerified",
  @"runDirectoryVerified",@"realmDirectoriesVerified",@"identitiesStable",@"inventoryComplete",@"exactInventoryVerified",@"unknownEntriesObserved",
  @"tamperingObserved",@"runtimeEmpty",@"runEmpty",@"realmContentsEmpty"]) if(isBool(raw[key])) out[key]=raw[key];
 for (NSString *key in @[@"expectedRealmCount",@"runtimeEntryCount",@"runEntryCount",@"realmEntryCount",@"unknownEntryCount",@"missingEntryCount"])
  if ([raw[key] isKindOfClass:NSNumber.class] && !isBool(raw[key]) && [raw[key] doubleValue]==[raw[key] integerValue] &&
   [raw[key] integerValue]>=0 && [raw[key] integerValue]<=65536) out[key]=raw[key];
 out[@"inventorySHA256"]=regex(raw[@"inventorySHA256"],@"^[a-f0-9]{64}$")?raw[@"inventorySHA256"]:NSNull.null;
 out[@"reason"]=[raw[@"reason"] isEqual:@"READ_ONLY_FIXED_RUNTIME_INVENTORY"]?@"READ_ONLY_FIXED_RUNTIME_INVENTORY":@"FIXED_RUNTIME_INVENTORY_REFUSED";
 return out;
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
  int status = -1; NSData *data = fixedProcess(commands[i][0], (char *const *)commands[i], nil, &status);
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

static NSDictionary *safeGIDProof(NSDictionary *raw) {
 if (![raw[@"schema"] isEqual:@"envara.macos-pf-gid-proof/v1"] || !isBool(raw[@"readOnly"]) || ![raw[@"readOnly"] boolValue]) return nil;
 NSMutableDictionary *out=[@{@"schema":@"envara.macos-pf-gid-proof/v1",@"readOnly":@YES,@"cleanupConfirmed":@NO,@"productionReady":@NO} mutableCopy];
 for(NSString *key in @[@"recordIdentityVerified",@"rootCallerVerified",@"groupLookupComplete",@"groupsAbsent",@"processEnumerationComplete",
  @"processIdentitiesStable",@"supplementaryGroupsCovered",@"groupCapacityVerified",@"snapshotStable",@"allOwnedGIDProcessesAbsent"])
  if(isBool(raw[key])) out[key]=raw[key];
 for(NSString *key in @[@"runtimeGroupCapacity",@"realmCount",@"groupLookups",@"snapshotPIDCount",@"inspectedProcessCount",@"matchingProcessCount",
  @"unreadableProcessCount",@"unstableProcessCount",@"attemptCount",@"zombieCredentialChecks",@"scanRound",@"sdkGroupCapacity",
  @"readerExpectedByteCount",@"readerReturnedByteCount",@"observedGroupCount"])
  if([raw[key] isKindOfClass:NSNumber.class] && !isBool(raw[key]) && [raw[key] doubleValue]==[raw[key] integerValue] &&
   [raw[key] integerValue]>=0 && [raw[key] integerValue]<=65536) out[key]=raw[key];
 NSDictionary *enums=@{@"diagnosticStage":EG832StageNames(),@"readerFailure":EG832FailureNames(),@"errnoClass":EG832ErrnoNames()};
 for(NSString *key in enums) out[key]=[enums[key] containsObject:raw[key]]?raw[key]:@"UNRECOGNIZED";
 return out;
}
static NSDictionary *tunnelInterfaceProof(NSDictionary *record) {
 struct ifaddrs *list=NULL; if(getifaddrs(&list)) return @{@"readSucceeded":@NO,@"recordedInterfaceCount":@2,@"recordedNamesAbsent":@NO,@"ownershipInferredFromName":@NO};
 NSMutableSet *names=[NSMutableSet set]; for(struct ifaddrs *entry=list;entry;entry=entry->ifa_next) if(entry->ifa_name) [names addObject:@(entry->ifa_name)];
 BOOL absent=YES; for(NSDictionary *realm in record[@"realms"]) if([names containsObject:realm[@"tunnel"][@"interfaceName"]]) absent=NO;
 freeifaddrs(list); return @{@"readSucceeded":@YES,@"recordedInterfaceCount":@2,@"recordedNamesAbsent":@(absent),@"ownershipInferredFromName":@NO};
}
/* Observed metadata preconditions only. This carrier has no archive operation,
 * and this snapshot cannot authorize a later writer or reclaim kernel state. */
static BOOL archivePreconditions(NSDictionary *result) {
 for(NSString *key in @[@"installed832SnapshotVerified",@"sealedFixedRegistryVerified",@"sealedRegistryStableThroughInspection",@"originalRootStableThroughInspection",@"currentOriginalRootRestored",@"ownedPFReferenceReleasedInRegistry"]) if(!isBool(result[key]) || ![result[key] boolValue]) return NO;
 NSDictionary *hook=result[@"privateLeaseRootProof"], *p=result[@"controlledProcessProof"], *g=result[@"ownedGIDProof"], *rules=result[@"ownedAnchorActiveRules"], *listing=result[@"ownedNamespaceListings"], *inventory=result[@"runtimeInventory"];
 for(NSString *key in @[@"ok",@"pfDisabled",@"pinsVerified",@"originalRootCompatible",@"ownedRootHookRemoved",@"originalRootRestored",@"receiptRetired"]) if(!isBool(hook[key]) || ![hook[key] boolValue]) return NO;
 if(![hook[@"runLedgerState"] isEqual:@"retired"] || !isBool(hook[@"hookInstalled"]) || [hook[@"hookInstalled"] boolValue]) return NO;
 if(!isBool(p[@"controlledProcessesGone"]) || ![p[@"controlledProcessesGone"] boolValue] || [p[@"recordedProcessCount"] integerValue]!=11 || [p[@"absentPIDsDoubleChecked"] integerValue]!=11) return NO;
 for(NSString *key in @[@"recordIdentityVerified",@"rootCallerVerified",@"groupLookupComplete",@"groupsAbsent",@"processEnumerationComplete",@"processIdentitiesStable",@"supplementaryGroupsCovered",@"groupCapacityVerified",@"snapshotStable",@"allOwnedGIDProcessesAbsent"]) if(!isBool(g[key]) || ![g[key] boolValue]) return NO;
 if(![rules[@"readable"] boolValue] || ![rules[@"allActiveRulesEmptyOrAbsent"] boolValue] || ![listing[@"pfctlPinVerified"] boolValue] || ![listing[@"anchors"][@"emptyVerified"] boolValue] || ![listing[@"tablesIncludingGhosts"][@"emptyVerified"] boolValue]) return NO;
 return (BOOL)([inventory[@"exactInventoryVerified"] boolValue] && [inventory[@"realmContentsEmpty"] boolValue] && [inventory[@"expectedRealmCount"] integerValue]==2);
}
static NSMutableDictionary *baseResult(void) {
 return [@{@"schema": SCHEMA, @"runId": FIXED_RUN, @"readOnly": @YES, @"ready": @NO, @"productionReady": @NO,
  @"changesSystem": @NO, @"deletesRules": @NO, @"changesPF": @NO, @"changesDNS": @NO,
  @"ownedChildRuleCountsAvailable": @NO, @"inactiveRulesAvailable":@NO,@"inactiveQueuesAvailable":@NO,@"openTransactionsAvailable":@NO,
  @"topenAvailable":@NO,@"referenceCountsAvailable":@NO,@"cleanupConfirmed": @NO,@"privateRunBaselinePersisted":@NO,@"failedRunHostBaselineMatched":@NO,@"deletesAttempted":@NO,@"runtimeArchiveAuthorized":@NO,@"snapshotAtomic":@NO} mutableCopy];
}
static NSDictionary *safeReport(NSDictionary *raw) {
 if (![raw[@"schema"] isEqual:SCHEMA] || ![raw[@"runId"] isEqual:FIXED_RUN] || ![raw[@"readOnly"] isEqual:@YES] ||
  ![raw[@"changesSystem"] isEqual:@NO]) return nil;
 NSMutableDictionary *out = baseResult();
 NSArray *reasons = @[@"NATIVE_AUTHORIZATION_REQUIRED", @"INSTALLATION_MAINTENANCE_BUSY", @"INSTALLED_TREE_REFUSED", @"INSTALLED_PIN_OR_MODE_REFUSED", @"SEALED_RUNTIME_REFUSED",
  @"SEALED_FIXED_REGISTRY_REFUSED", @"FIXED_NATIVE_IDENTITY_REFUSED", @"PRIVATE_INPUT_REFUSED", @"READ_ONLY_NATIVE_PROOF_UNCONFIRMED",
  @"READ_ONLY_NATIVE_SCHEMA_REFUSED", @"SEALED_REGISTRY_CHANGED", @"READ_ONLY_FIXED_RUN_INSPECTED", @"INSPECTION_REFUSED", @"READ_ONLY_INSPECTION_EXCEPTION"];
 out[@"reason"] = [reasons containsObject:raw[@"reason"]] ? raw[@"reason"] : @"UNRECOGNIZED_READ_ONLY_REASON";
 for (NSString *key in @[@"recordedReceiptRetired",@"hostSnapshotComplete",@"hostNetworkStableDuringInspection",@"inspectionCompleted", @"installed832SnapshotVerified", @"sealedFixedRegistryVerified", @"registryCleanupUncertain",
  @"recordedRootHookMutationAttempted", @"recordedRootHookRemoved", @"ownedPFReferenceReleasedInRegistry",
  @"sealedRegistryStableThroughInspection", @"currentOriginalRootRestored", @"originalRootStableThroughInspection"]) if (isBool(raw[key])) out[key] = raw[key];
 if ([@[@"preparing", @"fixtures-running", @"fault", @"transport-fault", @"cleaning", @"cleaned", @"cleanup-required"] containsObject:raw[@"registryPhase"]])
  out[@"registryPhase"] = raw[@"registryPhase"];
 for (NSString *proofKey in @[@"privateLeaseRootProof", @"freshNoLeaseRootProof", @"finalNoLeaseRootProof"]) {
  NSDictionary *proof = raw[proofKey]; if (![proof isKindOfClass:NSDictionary.class]) continue;
  NSMutableDictionary *safe = [NSMutableDictionary dictionary];
  for (NSString *key in @[@"ok", @"pfDisabled", @"pinsVerified", @"originalRootCompatible", @"ownedRootHookVerified", @"hookInstalled", @"canCreateOwnedHook", @"ownedRootHookCanCreate",
   @"priorAnchorsCompatible", @"ownedRootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"namespaceExists",@"cleanupPending",@"inactiveQueuesVerified",@"namespaceReferencesVerified", @"rootRulesMatchOriginalFingerprint", @"rootTextMatchesOriginalFingerprint", @"rootRuleCountAvailable", @"ownedChildRuleCountsAvailable"])
   if (isBool(proof[key])) safe[key] = proof[key];
  if ([proof[@"nativeExitStatus"] isKindOfClass:NSNumber.class] && !isBool(proof[@"nativeExitStatus"]) &&
   [proof[@"nativeExitStatus"] doubleValue] == [proof[@"nativeExitStatus"] integerValue] &&
   [proof[@"nativeExitStatus"] integerValue] >= 0 && [proof[@"nativeExitStatus"] integerValue] <= 255) safe[@"nativeExitStatus"] = proof[@"nativeExitStatus"];
  NSArray *why = @[@"READ_ONLY_OWNED_HOOK_PROOF", @"PINNED_HOST_MISMATCH", @"READ_DEVICE_UNAVAILABLE", @"AUTHENTICATED_ROOT_CONTROLLER_REQUIRED",
   @"SIGNAL_BOUNDARY_UNAVAILABLE", @"INVALID_PRIVATE_HOOK_INPUT", @"UNRECOGNIZED_NATIVE_REASON"];
  safe[@"nativeReason"] = [why containsObject:proof[@"nativeReason"]] ? proof[@"nativeReason"] : @"UNRECOGNIZED_NATIVE_REASON";
  for(NSString *key in @[@"namespaceState",@"runLedgerState"]) if([@[@"unselected",@"absent",@"present",@"unknown",@"unused",@"allocation-only",@"issued",@"delete-intent",@"retired",@"capacity-exhausted"] containsObject:proof[key]]) safe[key]=proof[key];
  out[proofKey] = safe;
 }
 NSDictionary *p = raw[@"controlledProcessProof"]; if ([p isKindOfClass:NSDictionary.class]) {
  NSMutableDictionary *safe = [NSMutableDictionary dictionary];
  for (NSString *key in @[@"recordedProcessCount", @"absentPIDsDoubleChecked", @"liveRecordedPIDs", @"unreadableOrUnstablePIDs", @"birthMismatches"])
   if ([p[key] isKindOfClass:NSNumber.class] && !isBool(p[key]) && [p[key] doubleValue] == [p[key] integerValue] &&
    [p[key] integerValue] >= 0 && [p[key] integerValue] <= 64) safe[key] = p[key];
  if (isBool(p[@"controlledProcessesGone"])) safe[@"controlledProcessesGone"] = p[@"controlledProcessesGone"]; out[@"controlledProcessProof"] = safe;
 }
 NSDictionary *counts=safeActiveCounts(raw[@"ownedAnchorActiveRules"]), *listings=safeNamespaceListings(raw[@"ownedNamespaceListings"]),
  *inventory=safeRuntimeInventory(raw[@"runtimeInventory"]);
 if(counts) out[@"ownedAnchorActiveRules"]=counts; if(listings) out[@"ownedNamespaceListings"]=listings; if(inventory) out[@"runtimeInventory"]=inventory;
 NSDictionary *gids=safeGIDProof(raw[@"ownedGIDProof"]); if(gids) out[@"ownedGIDProof"]=gids;
 NSDictionary *interfaces=raw[@"tunnelInterfaceProof"];
 if([interfaces isKindOfClass:NSDictionary.class]) { NSMutableDictionary *v=[@{@"recordedInterfaceCount":@2,@"ownershipInferredFromName":@NO} mutableCopy];
  for(NSString *key in @[@"readSucceeded",@"recordedNamesAbsent"]) if(isBool(interfaces[key])) v[key]=interfaces[key]; out[@"tunnelInterfaceProof"]=v; }
 for(NSString *key in @[@"hostBeforeSHA256",@"hostAfterSHA256"]) {
  NSDictionary *hashes=raw[key]; if(![hashes isKindOfClass:NSDictionary.class]) continue;
  NSMutableDictionary *v=[NSMutableDictionary dictionary]; for(NSString *name in @[@"routes",@"dns",@"nat",@"pfconf"]) if(regex(hashes[name],@"^[0-9a-f]{64}$")) v[name]=hashes[name]; out[key]=v;
 }
 out[@"runtimeArchivePreconditionsObserved"]=@(archivePreconditions(out));
 return out;
}
static int emit(NSDictionary *value) {
 NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingWithoutEscapingSlashes error:NULL]; if (!data || data.length > 16384) return 1;
 if (fwrite(data.bytes, 1, data.length, stdout) != data.length || fputc('\n', stdout) == EOF || fflush(stdout)) return 1;
 return [value[@"inspectionCompleted"] boolValue] ? 0 : 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool privilegedReference(void) {
 if (geteuid() != 0) return false; AuthorizationRef ref = NULL;
 OSStatus status = AuthorizationCopyPrivilegedReference(&ref, kAuthorizationFlagDefaults); if (status != errAuthorizationSuccess || !ref) return false;
 AuthorizationItem item = {kAuthorizationRightExecute,0,NULL,0}; AuthorizationRights rights = {1,&item};
 status = AuthorizationCopyRights(ref, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, NULL);
 AuthorizationFree(ref, kAuthorizationFlagDefaults); return status == errAuthorizationSuccess;
}
static int inspectRoot(void) {
 NSMutableDictionary *result = baseResult(); double deadline = seconds()+90.0; rootDeadline=deadline;
 if (!privilegedReference() || setgroups(1,(gid_t[]){0}) || setgid(0) || setuid(0) || getuid() || geteuid()) { result[@"reason"] = @"NATIVE_AUTHORIZATION_REQUIRED"; return emit(result); }
 struct sigaction ignore = {0}; ignore.sa_handler = SIG_IGN; sigemptyset(&ignore.sa_mask);
 struct sigaction reap={0}; reap.sa_handler=SIG_DFL; sigemptyset(&reap.sa_mask);
 if (sigaction(SIGCHLD,&reap,NULL) || sigaction(SIGPIPE, &ignore, NULL)) { result[@"reason"] = @"INSPECTION_REFUSED"; return emit(result); }
 int maintenance = -1, installed = -1, runtime = -1, registry = -1; struct stat before; NSDictionary *record = nil;
 // Same verified parent and SH/EX flock convention as the fixed installer.
 // Hold the process-scoped shared lease through hashing and both status reads.
 maintenance = directory(INSTALL_PARENT);
 if (maintenance < 0 || flock(maintenance, LOCK_SH | LOCK_NB)) { refuse("INSTALLATION_MAINTENANCE_BUSY"); goto finished; }
 installed = verifiedInstallation(deadline);
 if (installed < 0) goto finished;
 result[@"installed832SnapshotVerified"] = @YES;
 runtime = directory(RUNTIME); if (!secureFD(runtime, true, 0700)) { refuse("SEALED_RUNTIME_REFUSED"); goto finished; }
 registry = openat(runtime, "registry.json", O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 record = validRegistry(readHeld(registry, &before));
 if (!record || !heldRegistryUnchanged(runtime, registry, &before)) { refuse("SEALED_FIXED_REGISTRY_REFUSED"); goto finished; }
 result[@"sealedFixedRegistryVerified"] = @YES; result[@"registryPhase"] = record[@"phase"];
 result[@"registryCleanupUncertain"] = record[@"cleanupUncertain"];
 result[@"recordedRootHookMutationAttempted"] = record[@"rootHook"][@"mutationAttempted"];
 result[@"recordedRootHookRemoved"] = record[@"rootHook"][@"removed"];
 result[@"ownedPFReferenceReleasedInRegistry"] = record[@"ownedPFReference"][@"released"];
 result[@"recordedReceiptRetired"]=record[@"rootHook"][@"receiptRetired"];
 result[@"controlledProcessProof"] = processProof(record);
 result[@"ownedGIDProof"]=EnvaraInspectGIDProof832(record);
 result[@"tunnelInterfaceProof"]=tunnelInterfaceProof(record);
 { NSDictionary *host=hostSnapshot(); if(host) result[@"hostBeforeSHA256"]=host; }
 { NSDictionary *inventory=safeRuntimeInventory(EnvaraInspectRuntimeInventory832(runtime,record)); if(inventory) result[@"runtimeInventory"]=inventory; }
 { NSDictionary *fresh = nativeHook(installed, nil, deadline); if (fresh) result[@"freshNoLeaseRootProof"] = fresh; else goto finished;
   NSDictionary *leased = nativeHook(installed, record[@"rootHook"][@"lease"], deadline);
   if (leased) result[@"privateLeaseRootProof"] = leased; else goto finished;
   if (!heldRegistryUnchanged(runtime, registry, &before)) { refuse("SEALED_REGISTRY_CHANGED"); goto finished; }
   result[@"sealedRegistryStableThroughInspection"] = @YES; result[@"inspectionCompleted"] = @YES;
   result[@"currentOriginalRootRestored"] = @((BOOL)([fresh[@"ok"] boolValue] && [fresh[@"pinsVerified"] boolValue] &&
    [fresh[@"originalRootCompatible"] boolValue] && [fresh[@"priorAnchorsCompatible"] boolValue] && ![fresh[@"hookInstalled"] boolValue]));
   if(freshRootAllowsReadback(fresh)) { result[@"ownedAnchorActiveRules"]=activeOwnedCounts();
    result[@"ownedNamespaceListings"]=ownedNamespaceListings(deadline); }
   NSDictionary *final = nativeHook(installed,nil,deadline); if(!final) { [result removeObjectForKey:@"inspectionCompleted"]; goto finished; }
   result[@"finalNoLeaseRootProof"]=final;
   result[@"originalRootStableThroughInspection"]=@((BOOL)(freshRootAllowsReadback(fresh) && freshRootAllowsReadback(final)));
   result[@"currentOriginalRootRestored"]=@((BOOL)freshRootAllowsReadback(final));
   if (!heldRegistryUnchanged(runtime,registry,&before)) { [result removeObjectForKey:@"inspectionCompleted"]; refuse("SEALED_REGISTRY_CHANGED"); goto finished; }
   NSDictionary *host=hostSnapshot(); if(host) result[@"hostAfterSHA256"]=host;
   result[@"hostSnapshotComplete"]=@((BOOL)([result[@"hostBeforeSHA256"] isKindOfClass:NSDictionary.class] && host!=nil));
   result[@"hostNetworkStableDuringInspection"]=@((BOOL)([result[@"hostSnapshotComplete"] boolValue] && [result[@"hostBeforeSHA256"] isEqual:host]));
   result[@"runtimeArchivePreconditionsObserved"]=@(archivePreconditions(result));
   result[@"reason"] = @"READ_ONLY_FIXED_RUN_INSPECTED"; }
finished:
 if (!result[@"inspectionCompleted"]) result[@"reason"] = @(failure);
 if (registry >= 0) close(registry); if (runtime >= 0) close(runtime); if (installed >= 0) close(installed);
 if (maintenance >= 0) { (void)flock(maintenance, LOCK_UN); close(maintenance); } return emit(safeReport(result));
}
static int requestInspection(const char *self) {
 AuthorizationRef ref = NULL; FILE *communication = NULL; OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref);
 const char prompt[] = "Envara: read only the private record for the failed 832 run95c92 fixture run and inspect its exact owned PF hook. No cleanup, rule deletion, PF enable/disable, DNS changes, applications, groups or tunnels.";
 AuthorizationItem item = {kAuthorizationRightExecute,0,NULL,0}, promptItem = {kAuthorizationEnvironmentPrompt,sizeof(prompt)-1,(void *)prompt,0};
 AuthorizationRights rights = {1,&item}; AuthorizationEnvironment env = {1,&promptItem};
 if (status == errAuthorizationSuccess) status = AuthorizationCopyRights(ref,&rights,&env,kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights,NULL);
 char *argv[] = {"--inspect-fixed-root",NULL}; if (status == errAuthorizationSuccess) status = AuthorizationExecuteWithPrivileges(ref,self,kAuthorizationFlagDefaults,argv,&communication);
 if (status != errAuthorizationSuccess || !communication) { if (ref) AuthorizationFree(ref,kAuthorizationFlagDestroyRights);
  NSMutableDictionary *value = baseResult(); value[@"reason"] = status == errAuthorizationCanceled ? @"NATIVE_AUTHORIZATION_CANCELED" : @"NATIVE_AUTHORIZATION_REFUSED"; return emit(value); }
 // No stdin is relayed; root command accepts no caller-supplied data or paths.
 NSMutableData *data = [NSMutableData data]; int fd = fileno(communication); double deadline = seconds()+100.0; bool eof = false;
 while (seconds() < deadline && data.length <= 16384) { struct pollfd p = {fd,POLLIN|POLLHUP,0}; int observed = poll(&p,1,100);
  if (observed < 0 && errno == EINTR) continue; if (observed < 0) break; if (!observed) continue;
  unsigned char bytes[1024]; ssize_t size = read(fd,bytes,sizeof(bytes)); if (!size) { eof = true; break; }
  if (size < 0 && errno == EINTR) continue; if (size < 0 || data.length+(size_t)size > 16384) break; [data appendBytes:bytes length:(NSUInteger)size]; }
 fclose(communication); AuthorizationFree(ref,kAuthorizationFlagDestroyRights);
 NSDictionary *value = eof ? safeReport(strictJSON(data,16384)) : nil;
 if (!value) { NSMutableDictionary *bad = baseResult(); bad[@"reason"] = @"NATIVE_READ_ONLY_REPORT_UNCONFIRMED"; return emit(bad); }
 // Reconstruct even the fixed root response from a public-field whitelist.
 return emit(value);
}
#pragma clang diagnostic pop
#ifndef ENVARA_RECOVERY_INERT_TEST
int main(int argc, char **argv) { @autoreleasepool { @try {
 if (argc != 2 || (strcmp(argv[1],"--plan") && strcmp(argv[1],"--request-readonly-inspection") && strcmp(argv[1],"--inspect-fixed-root"))) {
  NSMutableDictionary *bad = baseResult(); bad[@"reason"] = @"FIXED_OPERATION_REQUIRED"; return emit(bad); }
 if (!strcmp(argv[1],"--plan")) { NSMutableDictionary *plan = baseResult(); plan[@"inspectionCompleted"] = @NO;
  plan[@"requiresSeparateNativeAuthorization"] = @YES; plan[@"installedManifestSHA256"] = @MF; plan[@"nativeSHA256"]=@"8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8";
  plan[@"authorizationRequested"]=@NO; plan[@"rootDeadlineSeconds"]=@90; plan[@"relayDeadlineSeconds"]=@100; plan[@"bootstrapSelfPathAttested"]=@NO;
  plan[@"operations"] = @[@"verify-fixed-installed-832-snapshot", @"read-held-private-fixed-run-registry", @"read-only-hook-status-without-lease", @"read-only-hook-status-with-private-lease", @"read-recorded-process-identities", @"read-owned-active-rules-six-classes", @"read-owned-anchors-and-ghost-tables", @"read-fixed-runtime-inventory",@"read-real-saved-supplementary-owned-gid-processes",@"read-host-network-hashes-before-and-after"];
  plan[@"reason"] = @"READ_ONLY_PLAN_ONLY"; emit(plan); return 0; }
 if (!strcmp(argv[1],"--inspect-fixed-root")) return inspectRoot();
 if (getuid() == 0 || geteuid() == 0) { NSMutableDictionary *bad = baseResult(); bad[@"reason"] = @"UNPRIVILEGED_REQUEST_REQUIRED"; return emit(bad); }
 char raw[PATH_MAX], self[PATH_MAX]; uint32_t size = sizeof(raw);
 if (_NSGetExecutablePath(raw,&size) || !realpath(raw,self)) return 1;
 const char suffix[] = "/Contents/MacOS/EnvaraPFReadOnlyRecovery832Run95c92"; size_t length = strlen(self), tail = sizeof(suffix)-1;
 if (length <= tail || strcmp(self+length-tail,suffix)) { NSMutableDictionary *bad = baseResult(); bad[@"reason"] = @"FIXED_APP_CARRIER_REQUIRED"; return emit(bad); }
 return requestInspection(self);
 } @catch (NSException *exception) { (void)exception; NSMutableDictionary *bad = baseResult(); bad[@"reason"] = @"READ_ONLY_INSPECTION_EXCEPTION"; return emit(bad); } } }
#endif
