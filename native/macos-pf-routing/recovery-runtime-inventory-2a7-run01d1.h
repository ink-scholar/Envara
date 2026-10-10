/* Standalone, inert READ-ONLY inventory for one sealed 2A7 runtime record.
 * Input: an already verified/held root-0700 runtime FD and strict fixed record.
 * No path from the caller, content reads except registry.lock, mutations,
 * recursive unknown-directory traversal, processes or native authorization.
 * Exact inventory is not proof of process extinction or kernel reclamation.
 */
#ifndef ENVARA_RECOVERY_RUNTIME_INVENTORY_2A7_H
#define ENVARA_RECOVERY_RUNTIME_INVENTORY_2A7_H
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ER2A7_RUN @"01d1e669-bc58-4a10-ae2d-709e7fedd7f6"
#define ER2A7_ANCHOR @"io.envara.pf.run.01d1e669-bc58-4a10-ae2d-709e7fedd7f6"
#define ER2A7_ENTRY_LIMIT 256U

static bool ER2A7SameStat(const struct stat *a, const struct stat *b) {
 return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
  a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
  a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
  a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static bool ER2A7NoWriteACL(int fd) {
 errno = 0; acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
 if (!acl) return errno == ENOENT;
 acl_entry_t entry; int cursor = ACL_FIRST_ENTRY, result; bool okay = true;
 while ((result = acl_get_entry(acl, cursor, &entry)) == 0) {
  cursor = ACL_NEXT_ENTRY; acl_tag_t tag; acl_permset_t perms;
  if (acl_get_tag_type(entry, &tag) || acl_get_permset(entry, &perms)) { okay = false; break; }
  if (tag != ACL_EXTENDED_ALLOW) continue;
  const acl_perm_t forbidden[] = {ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
   ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER};
  for (size_t i = 0; i < sizeof(forbidden)/sizeof(forbidden[0]); i++)
   if (acl_get_perm_np(perms, forbidden[i]) != 0) { okay = false; break; }
  if (!okay) break;
 }
 if (okay) okay = result == -1 && errno == EINVAL;
 acl_free(acl); return okay;
}
static bool ER2A7SecureFD(int fd, bool directory, uid_t owner, gid_t group, struct stat *identity) {
 struct stat st;
 if (fd < 0 || fstat(fd, &st) || st.st_uid != owner || st.st_gid != group ||
  (st.st_mode & 07777) != (directory ? 0700 : 0600) ||
  (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode) || st.st_nlink != 1) || !ER2A7NoWriteACL(fd)) return false;
 if (identity) *identity = st; return true;
}
static bool ER2A7PathStable(int parent, const char *leaf, int held, const struct stat *before,
 bool directory, uid_t owner, gid_t group) {
 struct stat current, after;
 return ER2A7SecureFD(held, directory, owner, group, &after) &&
  !fstatat(parent, leaf, &current, AT_SYMLINK_NOFOLLOW) && ER2A7SameStat(before, &after) && ER2A7SameStat(before, &current);
}
static bool ER2A7UUID(id value) {
 return [value isKindOfClass:NSString.class] && [(NSString *)value length] == 36 &&
  [(NSString *)value rangeOfString:@"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
   options:NSRegularExpressionSearch].location != NSNotFound;
}
static bool ER2A7PID(id value) {
 return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() &&
  [value doubleValue] == [value longLongValue] && [value longLongValue] > 1 && [value longLongValue] <= INT32_MAX;
}
static NSArray<NSString *> *ER2A7RecordRealms(NSDictionary *record) {
 if (![record isKindOfClass:NSDictionary.class] || ![record[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"] ||
  ![record[@"runId"] isEqual:ER2A7_RUN] || ![record[@"anchor"] isEqual:ER2A7_ANCHOR] || !ER2A7PID(record[@"supervisorPid"]) ||
  ![record[@"realms"] isKindOfClass:NSArray.class] || [record[@"realms"] count] > 2) return nil;
 NSMutableArray<NSString *> *ids = [NSMutableArray array]; NSMutableSet<NSString *> *seen = [NSMutableSet set];
 for (id realm in record[@"realms"]) {
  if (![realm isKindOfClass:NSDictionary.class] || !ER2A7UUID(realm[@"realmId"]) || [seen containsObject:realm[@"realmId"]]) return nil;
  [ids addObject:realm[@"realmId"]]; [seen addObject:realm[@"realmId"]];
 }
 return ids;
}

/* Only a tiny ASCII JSON object is accepted. No escapes, duplicate/extra keys,
 * booleans, exponent notation or decimal PID normalization into an identity. */
typedef struct { const unsigned char *bytes; size_t size, at; } ER2A7LockCursor;
static void ER2A7LockSpace(ER2A7LockCursor *c) {
 while (c->at < c->size && c->bytes[c->at] && strchr(" \t\r\n", c->bytes[c->at])) c->at++;
}
static bool ER2A7LockChar(ER2A7LockCursor *c, unsigned char expected) {
 ER2A7LockSpace(c); if (c->at >= c->size || c->bytes[c->at] != expected) return false; c->at++; return true;
}
static bool ER2A7LockString(ER2A7LockCursor *c, char *out, size_t capacity) {
 if (!ER2A7LockChar(c, '"')) return false; size_t size = 0;
 while (c->at < c->size && c->bytes[c->at] != '"') {
  unsigned char byte = c->bytes[c->at++];
  if (byte < 32 || byte > 126 || byte == '\\' || size + 1 >= capacity) return false;
  out[size++] = (char)byte;
 }
 if (c->at >= c->size) return false; c->at++; out[size] = 0; return true;
}
static bool ER2A7LockMatches(NSData *data, pid_t supervisor) {
 if (!data.length || data.length > 1024) return false;
 ER2A7LockCursor c = {data.bytes, data.length, 0}; unsigned fields = 0;
 if (!ER2A7LockChar(&c, '{')) return false;
 for (unsigned i = 0; i < 3; i++) {
  char key[16], value[80];
  if ((i && !ER2A7LockChar(&c, ',')) || !ER2A7LockString(&c, key, sizeof(key)) || !ER2A7LockChar(&c, ':')) return false;
  if (!strcmp(key, "pid")) {
   if (fields & 2) return false; fields |= 2; ER2A7LockSpace(&c); uint64_t pid = 0; size_t digits = 0;
   if (c.at >= c.size || c.bytes[c.at] < '1' || c.bytes[c.at] > '9') return false;
   while (c.at < c.size && c.bytes[c.at] >= '0' && c.bytes[c.at] <= '9') {
    if (++digits > 10) return false; pid = pid * 10 + c.bytes[c.at++] - '0';
   }
   if (pid > INT32_MAX || pid != (uint64_t)supervisor) return false;
  } else {
   unsigned bit = !strcmp(key, "runId") ? 1 : !strcmp(key, "anchor") ? 4 : 0;
   if (!bit || (fields & bit) || !ER2A7LockString(&c, value, sizeof(value))) return false; fields |= bit;
   if (strcmp(value, bit == 1 ? ER2A7_RUN.UTF8String : ER2A7_ANCHOR.UTF8String)) return false;
  }
 }
 if (fields != 7 || !ER2A7LockChar(&c, '}')) return false; ER2A7LockSpace(&c); return c.at == c.size;
}
static NSData *ER2A7ReadLock(int fd, const struct stat *identity) {
 if (identity->st_size < 1 || identity->st_size > 1024) return nil;
 NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)identity->st_size]; size_t at = 0;
 while (at < data.length) {
  ssize_t count = pread(fd, (unsigned char *)data.mutableBytes + at, data.length - at, (off_t)at);
  if (count < 0 && errno == EINTR) continue; if (count <= 0) return nil; at += (size_t)count;
 }
 struct stat after; return !fstat(fd, &after) && ER2A7SameStat(identity, &after) ? data : nil;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSString *ER2A7Digest(CC_SHA256_CTX *ctx) {
 unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(digest, ctx); char hex[65];
 for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + i * 2, 3, "%02x", digest[i]); return @(hex);
}
static NSString *ER2A7EntryDigest(NSString *scope, const char *name, size_t length, const struct stat *st, bool available) {
 CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx); NSData *zone = [scope dataUsingEncoding:NSUTF8StringEncoding];
 CC_SHA256_Update(&ctx, zone.bytes, (CC_LONG)zone.length); const unsigned char separator = 0;
 CC_SHA256_Update(&ctx, &separator, 1); CC_SHA256_Update(&ctx, name, (CC_LONG)length); CC_SHA256_Update(&ctx, &separator, 1);
 char metadata[512]; int count = available ? snprintf(metadata, sizeof(metadata), "%llu:%llu:%llu:%llu:%llu:%llu:%lld:%lld:%lld:%lld:%lld",
  (unsigned long long)st->st_dev, (unsigned long long)st->st_ino, (unsigned long long)st->st_mode,
  (unsigned long long)st->st_uid, (unsigned long long)st->st_gid, (unsigned long long)st->st_nlink,
  (long long)st->st_size, (long long)st->st_mtimespec.tv_sec, (long long)st->st_mtimespec.tv_nsec,
  (long long)st->st_ctimespec.tv_sec, (long long)st->st_ctimespec.tv_nsec) : snprintf(metadata, sizeof(metadata), "unavailable");
 if (count > 0 && (size_t)count < sizeof(metadata)) CC_SHA256_Update(&ctx, metadata, (CC_LONG)count);
 return ER2A7Digest(&ctx);
}
static NSString *ER2A7InventoryDigest(NSArray<NSString *> *entries) {
 CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx); const char domain[] = "envara-readonly-runtime-inventory-2A7/v1";
 CC_SHA256_Update(&ctx, domain, (CC_LONG)sizeof(domain));
 for (NSString *entry in [entries sortedArrayUsingSelector:@selector(compare:)]) {
  NSData *data = [entry dataUsingEncoding:NSASCIIStringEncoding]; CC_SHA256_Update(&ctx, data.bytes, (CC_LONG)data.length);
 }
 return ER2A7Digest(&ctx);
}
#pragma clang diagnostic pop

typedef struct { NSUInteger count, unknown, missing; bool complete, stable, tampering; } ER2A7Scan;
static ER2A7Scan ER2A7ScanDirectory(int fd, NSString *scope, NSArray<NSString *> *expected,
 NSMutableArray<NSString *> *hashes, uid_t owner, gid_t group) {
 ER2A7Scan result = {0}; struct stat before, after, scanIdentity;
 if (!ER2A7SecureFD(fd, true, owner, group, &before)) { result.tampering = true; return result; }
 int scanFD = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
 if (!ER2A7SecureFD(scanFD, true, owner, group, &scanIdentity) || !ER2A7SameStat(&before, &scanIdentity)) {
  if (scanFD >= 0) close(scanFD); result.tampering = true; return result;
 }
 DIR *directory = fdopendir(scanFD); if (!directory) { close(scanFD); return result; }
 NSMutableSet<NSString *> *seen = [NSMutableSet set]; bool complete = true;
 for (;;) {
  errno = 0; struct dirent *entry = readdir(directory);
  if (!entry) { complete = errno == 0; break; }
  if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
  if (result.count >= ER2A7_ENTRY_LIMIT) { complete = false; break; } result.count++;
  size_t length = strnlen(entry->d_name, sizeof(entry->d_name)); struct stat st = {0};
  bool available = length > 0 && length < sizeof(entry->d_name) && !strchr(entry->d_name, '/') &&
   !fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
  [hashes addObject:ER2A7EntryDigest(scope, entry->d_name, length, &st, available)];
  NSString *name = available ? [[NSString alloc] initWithBytes:entry->d_name length:length encoding:NSUTF8StringEncoding] : nil;
  if (name && [expected containsObject:name]) [seen addObject:name]; else result.unknown++;
  if (!available || S_ISLNK(st.st_mode)) result.tampering = true;
 }
 closedir(directory);
 result.missing = expected.count - seen.count; result.complete = complete;
 result.stable = ER2A7SecureFD(fd, true, owner, group, &after) && ER2A7SameStat(&before, &after);
 if (!result.stable) result.tampering = true; return result;
}
static NSMutableDictionary *ER2A7BaseReport(void) {
 NSMutableDictionary *out = [@{@"schema": @"envara.macos-pf-runtime-inventory/v1", @"readOnly": @YES,
  @"cleanupConfirmed": @NO, @"productionReady": @NO, @"inventorySHA256": ER2A7InventoryDigest(@[]),
  @"reason": @"FIXED_RUNTIME_INVENTORY_REFUSED"} mutableCopy];
 for (NSString *key in @[@"recordIdentityVerified", @"runtimeDirectoryVerified", @"registryFileVerified", @"lockFileVerified",
  @"lockRecordVerified", @"runDirectoryVerified", @"realmDirectoriesVerified", @"identitiesStable", @"inventoryComplete",
  @"exactInventoryVerified", @"unknownEntriesObserved", @"tamperingObserved", @"runtimeEmpty", @"runEmpty", @"realmContentsEmpty"]) out[key] = @NO;
 for (NSString *key in @[@"expectedRealmCount", @"runtimeEntryCount", @"runEntryCount", @"realmEntryCount", @"unknownEntryCount", @"missingEntryCount"]) out[key] = @0;
 return out;
}
static NSDictionary *ER2A7InspectInventory(int runtime, NSDictionary *record, uid_t owner, gid_t group) {
 NSMutableDictionary *out = ER2A7BaseReport(); NSMutableArray<NSString *> *hashes = [NSMutableArray array];
 NSArray<NSString *> *realms = ER2A7RecordRealms(record); struct stat rootBefore = {0}, rootAfter = {0};
 bool rootVerified = ER2A7SecureFD(runtime, true, owner, group, &rootBefore);
 out[@"recordIdentityVerified"] = @((BOOL)(realms != nil)); out[@"runtimeDirectoryVerified"] = @((BOOL)rootVerified);
 if (!realms || !rootVerified) { out[@"tamperingObserved"] = @YES; return out; }
 out[@"expectedRealmCount"] = @(realms.count);
 ER2A7Scan rootScan = ER2A7ScanDirectory(runtime, @"runtime", @[@"registry.json", @"registry.lock", ER2A7_RUN], hashes, owner, group);
 out[@"runtimeEntryCount"] = @(rootScan.count); out[@"runtimeEmpty"] = @((BOOL)(rootScan.complete && rootScan.stable && rootScan.count == 0));
 NSUInteger unknown = rootScan.unknown, missing = rootScan.missing, realmEntries = 0;
 bool complete = rootScan.complete, stable = rootScan.stable, tampering = rootScan.tampering;
 int registry = openat(runtime, "registry.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
 int lock = openat(runtime, "registry.lock", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
 int run = openat(runtime, ER2A7_RUN.UTF8String, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
 struct stat registryBefore = {0}, lockBefore = {0}, runBefore = {0};
 bool registryVerified = ER2A7SecureFD(registry, false, owner, group, &registryBefore) && registryBefore.st_size > 0 && registryBefore.st_size <= 65536;
 bool lockVerified = ER2A7SecureFD(lock, false, owner, group, &lockBefore);
 bool lockMatches = lockVerified && ER2A7LockMatches(ER2A7ReadLock(lock, &lockBefore), [record[@"supervisorPid"] intValue]);
 bool runVerified = ER2A7SecureFD(run, true, owner, group, &runBefore), allRealmsVerified = runVerified;
 out[@"lockRecordVerified"] = @((BOOL)lockMatches); out[@"runDirectoryVerified"] = @((BOOL)runVerified);
 bool realmsEmpty = runVerified, allRealmScansComplete = runVerified;
 if (runVerified) {
  ER2A7Scan runScan = ER2A7ScanDirectory(run, @"run", realms, hashes, owner, group);
  out[@"runEntryCount"] = @(runScan.count); out[@"runEmpty"] = @((BOOL)(runScan.complete && runScan.stable && runScan.count == 0));
  unknown += runScan.unknown; missing += runScan.missing; complete &= runScan.complete; stable &= runScan.stable; tampering |= runScan.tampering;
  for (NSString *realm in realms) {
   int realmFD = openat(run, realm.UTF8String, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat realmBefore = {0};
   bool verified = ER2A7SecureFD(realmFD, true, owner, group, &realmBefore);
   allRealmsVerified &= verified;
   if (verified) {
    ER2A7Scan scan = ER2A7ScanDirectory(realmFD, [@"realm:" stringByAppendingString:realm], @[], hashes, owner, group);
    realmEntries += scan.count; unknown += scan.unknown; missing += scan.missing; allRealmScansComplete &= scan.complete;
    bool pathStable = ER2A7PathStable(run, realm.UTF8String, realmFD, &realmBefore, true, owner, group);
    allRealmsVerified &= pathStable;
    stable &= scan.stable && pathStable; tampering |= scan.tampering || !pathStable;
    realmsEmpty &= scan.complete && scan.stable && pathStable && scan.count == 0;
   } else { allRealmScansComplete = false; realmsEmpty = false; stable = false; tampering = true; }
   if (realmFD >= 0) close(realmFD);
  }
 } else { complete = false; stable = false; tampering = true; }
 bool registryStable = registryVerified && ER2A7PathStable(runtime, "registry.json", registry, &registryBefore, false, owner, group);
 bool lockStable = lockVerified && ER2A7PathStable(runtime, "registry.lock", lock, &lockBefore, false, owner, group);
 bool runStable = runVerified && ER2A7PathStable(runtime, ER2A7_RUN.UTF8String, run, &runBefore, true, owner, group);
 bool rootStable = ER2A7SecureFD(runtime, true, owner, group, &rootAfter) && ER2A7SameStat(&rootBefore, &rootAfter);
 stable &= registryStable && lockStable && runStable && rootStable;
 tampering |= !registryVerified || !lockVerified || !lockMatches || !stable;
 complete &= allRealmScansComplete;
 out[@"registryFileVerified"] = @((BOOL)registryStable); out[@"lockFileVerified"] = @((BOOL)lockStable);
 out[@"runtimeDirectoryVerified"] = @((BOOL)(rootVerified && rootStable)); out[@"runDirectoryVerified"] = @((BOOL)(runVerified && runStable));
 out[@"realmDirectoriesVerified"] = @((BOOL)allRealmsVerified); out[@"identitiesStable"] = @((BOOL)stable);
 out[@"inventoryComplete"] = @((BOOL)complete); out[@"unknownEntryCount"] = @(unknown); out[@"missingEntryCount"] = @(missing);
 out[@"realmEntryCount"] = @(realmEntries); out[@"realmContentsEmpty"] = @((BOOL)(realmsEmpty && allRealmsVerified && stable));
 out[@"unknownEntriesObserved"] = @((BOOL)(unknown > 0)); out[@"tamperingObserved"] = @((BOOL)tampering);
 out[@"inventorySHA256"] = ER2A7InventoryDigest(hashes);
 bool exact = complete && stable && registryStable && lockStable && lockMatches && runVerified && allRealmsVerified && !unknown && !missing && !tampering;
 out[@"exactInventoryVerified"] = @((BOOL)exact); if (exact) out[@"reason"] = @"READ_ONLY_FIXED_RUNTIME_INVENTORY";
 if (registry >= 0) close(registry); if (lock >= 0) close(lock); if (run >= 0) close(run);
 return out;
}
/* Production entry cannot accept an alternate owner or group. The caller must
 * retain its registry FD and independently recheck its original sealed bytes. */
static NSDictionary *EnvaraInspectRuntimeInventory2A7(int runtimeFD, NSDictionary *protectedRecord) {
 return ER2A7InspectInventory(runtimeFD, protectedRecord, 0, 0);
}
#ifdef ENVARA_RECOVERY_INVENTORY_INERT_TEST
/* Local test-only fixtures; never built into the authorized inspector. */
static NSDictionary *EnvaraInspectRuntimeInventory2A7ForTest(int runtimeFD, NSDictionary *protectedRecord, uid_t owner, gid_t group) {
 return ER2A7InspectInventory(runtimeFD, protectedRecord, owner, group);
}
#endif
#endif
