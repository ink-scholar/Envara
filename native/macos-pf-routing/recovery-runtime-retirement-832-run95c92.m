/* Isolated fixed-832/run95c92 filesystem ARCHIVE source, never a PF cleanup tool.
 * No installed payload modification, DELETE/old-lease replay, PF/group/route/
 * DNS mutation, application launch, active runtime recreation or resume.
 * Separate review and native authorization are required for an actual move.
 */
#define ENVARA_RECOVERY_INERT_TEST 1
#include "recovery-readonly-832-run95c92.m"
#include "recovery-gid-proof-832-run95c92.h"

#define RR832_SOURCE "io.envara.pf-runtime"
#define RR832_CAPSULE "io.envara.pf-retired-832-95c92c49"
#define RR832_RECEIPT "retirement-proof.json"
#define RR832_SCHEMA @"envara.macos-pf-runtime-retirement/v1"
#define RR832_PROOF_SCHEMA @"envara.macos-pf-runtime-retirement-preflight/v1"

static bool RR832CarrierPathValid(const char *self) {
 const char suffix[] = "/Contents/MacOS/EnvaraPFRuntimeRetirement832Run95c92";
 if (!self || self[0] != '/' || strnlen(self, PATH_MAX) == PATH_MAX || strstr(self, "/../") || strstr(self, "/./") || strstr(self, "//")) return false;
 size_t length = strlen(self), tail = sizeof(suffix)-1; return length > tail && !strcmp(self + length-tail, suffix);
}

static NSMutableDictionary *RR832Report(bool readOnly) {
 NSMutableDictionary *out = [@{@"schema": RR832_SCHEMA,@"runId":FIXED_RUN,@"manifestSHA256":@MF,@"anchor":FIXED_ANCHOR, @"readOnly": @((BOOL)readOnly),
  @"cleanupUncertain": @YES, @"archiveSHA256": NSNull.null, @"reason": @"ARCHIVE_PREFLIGHT_REFUSED",
  @"diagnosticStage": @"NOT_STARTED", @"preflightSummary": @{}} mutableCopy];
 for (NSString *key in @[@"retirementAttempted", @"archiveCreated", @"runtimeMoved", @"archiveVerified", @"runtimeRetired",
  @"changesFilesystem", @"changesPF", @"changesDNS", @"changesRoutes", @"changesGroups", @"namespaceReclaimed",
  @"cleanupConfirmed", @"productionReady", @"issuedLeaseRetiredNoDelete", @"sourceAbsentVerified", @"canRequestArchive"]) out[key] = @NO;
 out[@"archivedFileCount"] = @0; out[@"archivedEmptyRealmCount"] = @0; return out;
}
static NSArray *RR832RequiredProofBools(void) {
 return @[@"readOnly", @"rootPFDisabled", @"rootOriginalFingerprintsMatch", @"activeRulesAllEmpty", @"anchorsEmpty",
  @"ghostTablesEmpty", @"pfReferenceReleased", @"recordedProcessesGone", @"ownedGIDProcessesGone", @"inventoryExact",@"receiptRetired",@"ownedRootHookRemoved",@"originalRootRestored",@"exactOwnedNamespaceRetained"];
}
static bool RR832IntegerEqual(id value, long long expected) {
 return [value isKindOfClass:NSNumber.class] && !isBool(value) &&
  !CFNumberIsFloatType((__bridge CFNumberRef)value) && [value longLongValue] == expected;
}
static NSArray *RR832DiagnosticStages(void) {
 return @[@"NOT_STARTED", @"AUTHORIZATION_REFERENCE", @"SIGNAL_BOUNDARY", @"INSTALLATION_PARENT", @"MAINTENANCE_LEASE",
  @"INSTALLED_SNAPSHOT", @"RUNTIME_DIRECTORY", @"REGISTRY_READ", @"REGISTRY_SCHEMA", @"FIXED_PROCESS_INVENTORY", @"REGISTRY_IDENTITY",
  @"FRESH_PREFLIGHT", @"FINAL_REGISTRY_IDENTITY", @"READONLY_READY", @"ARCHIVE_OPERATION", @"REQUEST_RELAY", @"STATIC_PLAN"];
}
static NSDictionary *RR832SummarySpec(void) {
 NSArray *native = @[@"ok", @"pfDisabled", @"pinsVerified", @"originalRootCompatible", @"hookInstalled", @"priorAnchorsCompatible",
  @"rootRulesMatchOriginalFingerprint", @"rootTextMatchesOriginalFingerprint",@"receiptRetired",@"ownedRootHookRemoved",@"originalRootRestored",@"namespaceExists",@"namespaceReclaimed",@"cleanupPending"];
 NSDictionary *listing = @{@"bools": @[@"readSucceeded", @"stable", @"formatVerified", @"entriesPresent", @"emptyVerified"], @"counts": @{@"count": @65536}};
 return @{@"checks": @{@"bools": RR832RequiredProofBools(), @"counts": @{}},
  @"registryInventory": @{@"bools": @[@"schemaVerified", @"fixedProcessInventoryVerified"],
   @"counts": @{@"realmCount": @2, @"guardianCount": @16, @"fixtureCount": @12, @"recordedIdentityCount": @64}},
  @"firstNative": @{@"bools": native, @"counts": @{@"nativeExitStatus": @255}},
  @"privateLeaseNative": @{@"bools":native,@"counts":@{@"nativeExitStatus":@255}},
  @"lastNative": @{@"bools": native, @"counts": @{@"nativeExitStatus": @255}},
  @"activeRules": @{@"bools": @[@"inspectionAttempted", @"readable", @"allActiveRulesEmptyOrAbsent"], @"counts": @{}},
  @"namespacePin": @{@"bools": @[@"pfctlPinVerified"], @"counts": @{}}, @"anchors": listing, @"tables": listing,
  @"recordedProcesses": @{@"bools": @[@"controlledProcessesGone"], @"counts": @{@"recordedProcessCount": @64,
   @"absentPIDsDoubleChecked": @64, @"liveRecordedPIDs": @64, @"unreadableOrUnstablePIDs": @64, @"birthMismatches": @64}},
  @"ownedGIDProof": @{@"bools": @[@"readOnly", @"recordIdentityVerified", @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent",
   @"processEnumerationComplete", @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"allOwnedGIDProcessesAbsent", @"groupCapacityVerified"],
   @"counts": @{@"realmCount": @2, @"groupLookups": @8, @"snapshotPIDCount": @16384, @"inspectedProcessCount": @32768,
    @"matchingProcessCount": @32768, @"unreadableProcessCount": @32768, @"unstableProcessCount": @32768, @"zombieCredentialChecks": @32768, @"attemptCount": @3,
    @"scanRound": @2, @"sdkGroupCapacity": @65536, @"runtimeGroupCapacity": @65536, @"observedGroupCount": @65536, @"readerExpectedByteCount": @16384, @"readerReturnedByteCount": @16384},
   @"enums": @{@"diagnosticStage": EG832StageNames(), @"readerFailure": EG832FailureNames(), @"errnoClass": EG832ErrnoNames()}},
  @"runtimeInventory": @{@"bools": @[@"recordIdentityVerified", @"runtimeDirectoryVerified", @"registryFileVerified", @"lockFileVerified",
   @"lockRecordVerified", @"runDirectoryVerified", @"realmDirectoriesVerified", @"identitiesStable", @"inventoryComplete", @"exactInventoryVerified",
   @"unknownEntriesObserved", @"tamperingObserved", @"realmContentsEmpty"], @"counts": @{@"expectedRealmCount": @2,
    @"runtimeEntryCount": @256, @"runEntryCount": @256, @"realmEntryCount": @512, @"unknownEntryCount": @1024, @"missingEntryCount": @8}}};
}
static NSDictionary *RR832SanitizeSummary(NSDictionary *raw) {
 if (![raw isKindOfClass:NSDictionary.class]) return @{};
 NSMutableDictionary *out = [NSMutableDictionary dictionary]; NSDictionary *spec = RR832SummarySpec();
 for (NSString *section in spec) {
  NSDictionary *values = raw[section]; if (![values isKindOfClass:NSDictionary.class]) continue;
  NSMutableDictionary *safe = [NSMutableDictionary dictionary];
  for (NSString *key in [spec[section][@"bools"] arrayByAddingObject:@"received"])
   if (isBool(values[key])) safe[key] = values[key];
  NSDictionary *limits = spec[section][@"counts"];
  for (NSString *key in limits) { id number = values[key];
   if ([number isKindOfClass:NSNumber.class] && !isBool(number) && !CFNumberIsFloatType((__bridge CFNumberRef)number) &&
    [number longLongValue] >= 0 && [number longLongValue] <= [limits[key] longLongValue]) safe[key] = number;
  }
  NSDictionary *enums = spec[section][@"enums"];
  for (NSString *key in enums) if ([enums[key] containsObject:values[key]]) safe[key] = values[key];
  out[section] = safe;
 }
 return out;
}
static NSDictionary *RR832SummaryFromProof(NSDictionary *proof) {
 if (![proof isKindOfClass:NSDictionary.class]) return @{};
 NSDictionary *namespace = [proof[@"namespaceListings"] isKindOfClass:NSDictionary.class] ? proof[@"namespaceListings"] : @{};
 NSDictionary *sources = @{@"checks": proof, @"firstNative": proof[@"firstRootProof"] ?: NSNull.null,
  @"privateLeaseNative":proof[@"privateLeaseRootProof"]?:NSNull.null,
  @"lastNative": proof[@"freshRootProof"] ?: NSNull.null, @"activeRules": proof[@"activeRules"] ?: NSNull.null,
  @"namespacePin": proof[@"namespaceListings"] ?: NSNull.null, @"anchors": namespace[@"anchors"] ?: NSNull.null, @"tables": namespace[@"tablesIncludingGhosts"] ?: NSNull.null,
  @"recordedProcesses": proof[@"recordedProcesses"] ?: NSNull.null, @"ownedGIDProof": proof[@"ownedGIDProof"] ?: NSNull.null,
  @"runtimeInventory": proof[@"runtimeInventory"] ?: NSNull.null};
 NSMutableDictionary *summary = [NSMutableDictionary dictionary];
 for (NSString *key in sources) { BOOL received = [sources[key] isKindOfClass:NSDictionary.class];
  NSMutableDictionary *section = received ? [sources[key] mutableCopy] : [NSMutableDictionary dictionary];
  section[@"received"] = @(received); summary[key] = section;
 }
 return RR832SanitizeSummary(summary);
}
static bool RR832RecordedProcessesValid(NSDictionary *proof) {
 if (![proof isKindOfClass:NSDictionary.class] || !isBool(proof[@"controlledProcessesGone"]) ||
  ![proof[@"controlledProcessesGone"] boolValue]) return false;
 if (!RR832IntegerEqual(proof[@"recordedProcessCount"], 11) || !RR832IntegerEqual(proof[@"absentPIDsDoubleChecked"], 11)) return false;
 for (NSString *key in @[@"liveRecordedPIDs", @"unreadableOrUnstablePIDs", @"birthMismatches"])
  if (!RR832IntegerEqual(proof[key], 0)) return false;
 return true;
}
static bool RR832FixedRecordProcessesValid(NSDictionary *record) {
 if (![record isKindOfClass:NSDictionary.class] || !positivePID(record[@"supervisorPid"]) ||
  ![record[@"realms"] isKindOfClass:NSArray.class] || [record[@"realms"] count] != 2 ||
  ![record[@"guardians"] isKindOfClass:NSArray.class] || ![record[@"guardians"] count]) return false;
 NSMutableSet *pids = [NSMutableSet setWithObject:record[@"supervisorPid"]];
 for (id realm in record[@"realms"]) {
  if (![realm isKindOfClass:NSDictionary.class] || ![realm[@"fixtures"] isKindOfClass:NSArray.class] || ![realm[@"fixtures"] count]) return false;
  for (id fixture in realm[@"fixtures"]) {
   if (![fixture isKindOfClass:NSDictionary.class] || !positivePID(fixture[@"pid"])) return false;
   [pids addObject:fixture[@"pid"]];
  }
 }
 for (id guard in record[@"guardians"]) {
  if (![guard isKindOfClass:NSDictionary.class] || !positivePID(guard[@"guardianPid"])) return false;
  [pids addObject:guard[@"guardianPid"]];
  if (guard[@"pid"] != NSNull.null) { if (!positivePID(guard[@"pid"])) return false; [pids addObject:guard[@"pid"]]; }
 }
 return pids.count == 11;
}
static NSDictionary *RR832FixedRegistry(NSData *bytes) {
 NSDictionary *record = validRegistry(bytes); return RR832FixedRecordProcessesValid(record) ? record : nil;
}
static NSDictionary *RR832RegistrySummary(NSDictionary *validatedRecord) {
 if (![validatedRecord isKindOfClass:NSDictionary.class]) return @{};
 NSMutableSet *pids = [NSMutableSet setWithObject:validatedRecord[@"supervisorPid"]]; NSUInteger fixtures = 0;
 for (NSDictionary *realm in validatedRecord[@"realms"]) for (NSDictionary *fixture in realm[@"fixtures"]) { fixtures++; [pids addObject:fixture[@"pid"]]; }
 for (NSDictionary *guard in validatedRecord[@"guardians"]) { [pids addObject:guard[@"guardianPid"]]; if (positivePID(guard[@"pid"])) [pids addObject:guard[@"pid"]]; }
 return RR832SanitizeSummary(@{@"registryInventory": @{@"received": @YES, @"schemaVerified": @YES,
  @"fixedProcessInventoryVerified": @((BOOL)RR832FixedRecordProcessesValid(validatedRecord)),
  @"realmCount": @([validatedRecord[@"realms"] count]), @"guardianCount": @([validatedRecord[@"guardians"] count]),
  @"fixtureCount": @(fixtures), @"recordedIdentityCount": @(pids.count)}});
}
static bool RR832ProofValid(NSDictionary *proof) {
 if (![proof isKindOfClass:NSDictionary.class] || ![proof[@"schema"] isEqual:RR832_PROOF_SCHEMA] ||
  ![proof[@"runId"] isEqual:FIXED_RUN] || ![proof[@"manifestSHA256"] isEqual:@MF]) return false;
 for (NSString *key in RR832RequiredProofBools()) if (!isBool(proof[key]) || ![proof[key] boolValue]) return false;
 return RR832RecordedProcessesValid(proof[@"recordedProcesses"]);
}
static bool RR832GIDProofValid(NSDictionary *proof) {
 if (![proof[@"schema"] isEqual:@"envara.macos-pf-gid-proof/v1"]) return false;
 for (NSString *key in @[@"readOnly", @"recordIdentityVerified", @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent",
  @"processEnumerationComplete", @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"allOwnedGIDProcessesAbsent", @"groupCapacityVerified"])
  if (!isBool(proof[key]) || ![proof[key] boolValue]) return false;
 for (NSString *key in @[@"matchingProcessCount", @"unreadableProcessCount", @"unstableProcessCount"])
  if (![proof[key] isKindOfClass:NSNumber.class] || isBool(proof[key]) || [proof[key] doubleValue] != 0) return false;
 return [proof[@"realmCount"] isKindOfClass:NSNumber.class] && !isBool(proof[@"realmCount"]) && [proof[@"realmCount"] doubleValue] == 2 &&
  RR832IntegerEqual(proof[@"sdkGroupCapacity"], NGROUPS) && RR832IntegerEqual(proof[@"runtimeGroupCapacity"], NGROUPS);
}
static NSDictionary *RR832FreshProof(int installed, int runtime, NSDictionary *record, double deadline) {
 if (seconds()+EG832_DEADLINE_SECONDS+2>=deadline) return nil;
 NSDictionary *first = nativeHook(installed, nil, deadline);
 // STATUS only: bind the exact sealed receipt to its permanently retired
 // ledger epoch. Neither INSERT nor DELETE is reachable from this carrier.
 NSDictionary *retired=nativeHook(installed,record[@"rootHook"][@"lease"],deadline);
 NSDictionary *counts = activeOwnedCounts(), *listings = ownedNamespaceListings(deadline);
 if (seconds()+EG832_DEADLINE_SECONDS+2>=deadline) return nil;
 NSDictionary *pids = processProof(record), *gids = EnvaraInspectGIDProof832(record);
 NSDictionary *inventory = EnvaraInspectRuntimeInventory832(runtime, record);
 NSDictionary *last = nativeHook(installed, nil, deadline);
 BOOL roots = freshRootAllowsReadback(first) && freshRootAllowsReadback(last) &&
  [first[@"nativeExitStatus"] integerValue] == 0 && [last[@"nativeExitStatus"] integerValue] == 0;
 BOOL rules = isBool(counts[@"readable"]) && [counts[@"readable"] boolValue] &&
  isBool(counts[@"allActiveRulesEmptyOrAbsent"]) && [counts[@"allActiveRulesEmptyOrAbsent"] boolValue];
 NSDictionary *safeListings = safeNamespaceListings(listings);
 BOOL pinned = isBool(safeListings[@"pfctlPinVerified"]) && [safeListings[@"pfctlPinVerified"] boolValue];
 BOOL anchors = pinned && [safeListings[@"anchors"][@"emptyVerified"] boolValue];
 BOOL tables = pinned && [safeListings[@"tablesIncludingGhosts"][@"emptyVerified"] boolValue];
 BOOL released = isBool(record[@"ownedPFReference"][@"released"]) && [record[@"ownedPFReference"][@"released"] boolValue];
 BOOL gone = RR832FixedRecordProcessesValid(record) && RR832RecordedProcessesValid(pids);
 BOOL exact = isBool(inventory[@"exactInventoryVerified"]) && [inventory[@"exactInventoryVerified"] boolValue] &&
  [inventory[@"realmContentsEmpty"] boolValue] && [inventory[@"expectedRealmCount"] integerValue] == 2;
 return @{@"schema": RR832_PROOF_SCHEMA, @"runId": FIXED_RUN, @"manifestSHA256": @MF, @"readOnly": @YES,
  @"rootPFDisabled": @(roots), @"rootOriginalFingerprintsMatch": @(roots), @"activeRulesAllEmpty": @(rules),
  @"anchorsEmpty": @(anchors), @"ghostTablesEmpty": @(tables), @"pfReferenceReleased": @(released),
  @"receiptRetired":@((BOOL)(retired && [retired[@"nativeExitStatus"] integerValue]==0 && [retired[@"receiptRetired"] boolValue] && [retired[@"runLedgerState"] isEqual:@"retired"])),
  @"ownedRootHookRemoved":@((BOOL)(retired && [retired[@"ownedRootHookRemoved"] boolValue] && ![retired[@"hookInstalled"] boolValue])),
  @"originalRootRestored":@((BOOL)(retired && freshRootAllowsReadback(retired) && [retired[@"originalRootRestored"] boolValue])),
  @"exactOwnedNamespaceRetained":@((BOOL)(retired && [retired[@"namespaceState"] isEqual:@"present"] && [retired[@"namespaceExists"] boolValue] && ![retired[@"namespaceReclaimed"] boolValue])),
  @"privateLeaseRootProof":retired?:NSNull.null,
  @"recordedProcessesGone": @(gone), @"ownedGIDProcessesGone": @((BOOL)RR832GIDProofValid(gids)), @"inventoryExact": @(exact),
  @"firstRootProof": first ?: NSNull.null, @"freshRootProof": last ?: NSNull.null, @"activeRules": counts ?: NSNull.null, @"namespaceListings": safeListings ?: NSNull.null,
  @"recordedProcesses": pids ?: NSNull.null, @"ownedGIDProof": gids ?: NSNull.null, @"runtimeInventory": inventory ?: NSNull.null};
}
static bool RR832ParentSecure(int fd, uid_t owner, gid_t group, struct stat *identity) {
 struct stat st; if (fd < 0 || fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != owner || st.st_gid != group ||
  (st.st_mode & 0022) || !ER832NoWriteACL(fd)) return false; if (identity) *identity = st; return true;
}
static bool RR832ParentHeld(int fd, const struct stat *identity, uid_t owner, gid_t group) {
 struct stat after; return RR832ParentSecure(fd, owner, group, &after) && identity->st_dev == after.st_dev &&
  identity->st_ino == after.st_ino && identity->st_mode == after.st_mode && identity->st_uid == after.st_uid && identity->st_gid == after.st_gid;
}
static NSData *RR832Read(int fd, uid_t owner, gid_t group, struct stat *identity, size_t maximum) {
 if (!ER832SecureFD(fd, false, owner, group, identity) || identity->st_size < 1 || (uint64_t)identity->st_size > maximum) return nil;
 NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)identity->st_size]; size_t at = 0;
 while (at < data.length) { ssize_t size = pread(fd, (unsigned char *)data.mutableBytes + at, data.length - at, (off_t)at);
  if (size < 0 && errno == EINTR) continue; if (size <= 0) return nil; at += (size_t)size; }
 struct stat after; return !fstat(fd, &after) && ER832SameStat(identity, &after) ? data : nil;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSString *RR832Hash(NSData *data) {
 unsigned char digest[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data.bytes, (CC_LONG)data.length, digest); char hex[65];
 for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + 2*i, 3, "%02x", digest[i]); return @(hex);
}
#pragma clang diagnostic pop
static NSDictionary *RR832FileIdentity(const struct stat *st, NSData *bytes) {
 return @{@"device": @((unsigned long long)st->st_dev), @"inode": @((unsigned long long)st->st_ino),
  @"size": @((unsigned long long)st->st_size), @"sha256": RR832Hash(bytes)};
}
static bool RR832Absent(int parent, const char *leaf) {
 struct stat st; errno = 0; return fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT;
}
static bool RR832ExactCapsule(int fd, bool moved) {
 int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (scan < 0) return false;
 DIR *directory = fdopendir(scan); if (!directory) { close(scan); return false; }
 unsigned mask = 0; bool okay = true;
 for (;;) { errno = 0; struct dirent *entry = readdir(directory); if (!entry) { okay &= errno == 0; break; }
  if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
  unsigned bit = !strcmp(entry->d_name, RR832_RECEIPT) ? 1 : moved && !strcmp(entry->d_name, "runtime") ? 2 : 0;
  if (!bit || (mask & bit)) { okay = false; break; } mask |= bit; }
 closedir(directory); return okay && mask == (moved ? 3U : 1U);
}
typedef NSDictionary *(^RR832Refresh)(int runtime, NSDictionary *record);
typedef struct {
#ifdef ENVARA_RUNTIME_RETIREMENT_INERT_TEST
 int fault; void (^beforeRename)(int runtime);
#else
 int unused;
#endif
} RR832Options;
static NSDictionary *RR832Archive(int parent, const char *source, NSDictionary *record, RR832Refresh refresh,
 uid_t owner, gid_t group, RR832Options options) {
 NSMutableDictionary *out = RR832Report(false); int runtime = -1, registry = -1, lock = -1, capsule = -1, receipt = -1;
 struct stat parentBefore = {0}, rootBefore = {0}, registryBefore = {0}, lockBefore = {0}, capsuleBefore = {0}, receiptBefore = {0};
 bool maintenance = false, created = false, moved = false;
 do {
  if (!source || strcmp(source, RR832_SOURCE) || !refresh || !RR832ParentSecure(parent, owner, group, &parentBefore) || flock(parent, LOCK_EX | LOCK_NB)) break;
  maintenance = true;
  if (rootDeadline && seconds()>=rootDeadline) break;
  if (!RR832Absent(parent, RR832_CAPSULE)) { out[@"reason"] = @"ARCHIVE_CAPSULE_EXISTS"; break; }
  runtime = openat(parent, source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!ER832SecureFD(runtime, true, owner, group, &rootBefore) || !ER832PathStable(parent, source, runtime, &rootBefore, true, owner, group)) break;
  registry = openat(runtime, "registry.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  lock = openat(runtime, "registry.lock", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  NSData *registryBytes = RR832Read(registry, owner, group, &registryBefore, 65536);
  NSData *lockBytes = RR832Read(lock, owner, group, &lockBefore, 1024);
  NSDictionary *sealed = registryBytes ? RR832FixedRegistry(registryBytes) : nil;
  if (!sealed || ![sealed isEqualToDictionary:record] || !lockBytes || !ER832LockMatches(lockBytes, [record[@"supervisorPid"] intValue])) break;
  NSDictionary *inventory = ER832InspectInventory(runtime, record, owner, group), *proof = refresh(runtime, record);
  if (![inventory[@"exactInventoryVerified"] boolValue] || ![inventory[@"realmContentsEmpty"] boolValue] ||
   [inventory[@"expectedRealmCount"] integerValue] != 2 || !RR832ProofValid(proof)) break;
  out[@"canRequestArchive"] = @YES;
  NSDictionary *recordReceipt = @{@"schema": @"envara.macos-pf-runtime-retirement-capsule/v1", @"runId": FIXED_RUN,
   @"installedManifestSHA256": @MF, @"issuedLeaseDisposition": @"retired-no-delete", @"leaseReusePermitted": @NO,
   @"namespaceReclaimed": @NO, @"cleanupConfirmed": @NO, @"productionReady": @NO,
   @"registry": RR832FileIdentity(&registryBefore, registryBytes), @"lock": RR832FileIdentity(&lockBefore, lockBytes),
   @"runtimeDevice": @((unsigned long long)rootBefore.st_dev), @"runtimeInode": @((unsigned long long)rootBefore.st_ino),
   @"preflight": proof};
  NSData *receiptBytes = [NSJSONSerialization dataWithJSONObject:recordReceipt options:NSJSONWritingWithoutEscapingSlashes error:NULL];
  if (!receiptBytes || !receiptBytes.length || receiptBytes.length > 65536 || !RR832ParentHeld(parent, &parentBefore, owner, group)) break;
  out[@"canRequestArchive"] = @NO; // A mutation attempt can never inherit read-only readiness as success.
  if (rootDeadline && seconds()+30>=rootDeadline) break;
  if (mkdirat(parent, RR832_CAPSULE, 0700)) { out[@"reason"] = @"ARCHIVE_CAPSULE_EXISTS"; break; }
  created = true; out[@"retirementAttempted"] = @YES; out[@"archiveCreated"] = @YES; out[@"changesFilesystem"] = @YES;
  capsule = openat(parent, RR832_CAPSULE, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!ER832SecureFD(capsule, true, owner, group, &capsuleBefore)) { out[@"reason"] = @"ARCHIVE_RECEIPT_UNCONFIRMED"; break; }
  receipt = openat(capsule, RR832_RECEIPT, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (!ER832SecureFD(receipt, false, owner, group, NULL)) { out[@"reason"] = @"ARCHIVE_RECEIPT_UNCONFIRMED"; break; }
  size_t written = 0, wanted = receiptBytes.length;
#ifdef ENVARA_RUNTIME_RETIREMENT_INERT_TEST
  if (options.fault == 1) wanted = 1;
#else
  (void)options;
#endif
  while (written < wanted) { ssize_t size = write(receipt, (const unsigned char *)receiptBytes.bytes + written, wanted - written);
   if (size < 0 && errno == EINTR) continue; if (size <= 0) break; written += (size_t)size; }
  bool flushed = written == receiptBytes.length && !fsync(receipt) && !fsync(capsule) && !fsync(parent);
  close(receipt); receipt = openat(capsule, RR832_RECEIPT, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  NSData *reread = RR832Read(receipt, owner, group, &receiptBefore, 65536);
  if (!flushed || ![reread isEqual:receiptBytes] || !RR832ExactCapsule(capsule, false) ||
   !ER832SecureFD(capsule, true, owner, group, &capsuleBefore) ||
   !ER832PathStable(parent, RR832_CAPSULE, capsule, &capsuleBefore, true, owner, group)) { out[@"reason"] = @"ARCHIVE_RECEIPT_UNCONFIRMED"; break; }
  out[@"archiveSHA256"] = RR832Hash(receiptBytes);
#ifdef ENVARA_RUNTIME_RETIREMENT_INERT_TEST
  if (options.beforeRename) options.beforeRename(runtime);
#endif
  proof = refresh(runtime, record); inventory = ER832InspectInventory(runtime, record, owner, group);
  if (!RR832ProofValid(proof) || ![inventory[@"exactInventoryVerified"] boolValue] || ![inventory[@"realmContentsEmpty"] boolValue] ||
   !RR832ParentHeld(parent, &parentBefore, owner, group) || !ER832PathStable(parent, source, runtime, &rootBefore, true, owner, group) ||
   !ER832PathStable(runtime, "registry.json", registry, &registryBefore, false, owner, group) ||
   !ER832PathStable(runtime, "registry.lock", lock, &lockBefore, false, owner, group) ||
   !ER832PathStable(parent, RR832_CAPSULE, capsule, &capsuleBefore, true, owner, group) ||
   !ER832PathStable(capsule, RR832_RECEIPT, receipt, &receiptBefore, false, owner, group) || !RR832ExactCapsule(capsule, false) ||
   !RR832Absent(capsule, "runtime")) { out[@"reason"] = @"ARCHIVE_IDENTITY_CHANGED"; break; }
  if (rootDeadline && seconds()+5>=rootDeadline) { out[@"reason"]=@"ARCHIVE_IDENTITY_CHANGED"; break; }
  if (renameatx_np(parent, source, capsule, "runtime", RENAME_EXCL)) { out[@"reason"] = @"ARCHIVE_IDENTITY_CHANGED"; break; }
  moved = true; out[@"runtimeMoved"] = @YES;
  struct stat after, path, capsuleAfter, capsulePath, rereadIdentity;
  bool pathIdentity = !fstat(runtime, &after) && !fstatat(capsule, "runtime", &path, AT_SYMLINK_NOFOLLOW) &&
   rootBefore.st_dev == after.st_dev && rootBefore.st_ino == after.st_ino && ER832SameStat(&after, &path) &&
   after.st_mode == rootBefore.st_mode && after.st_uid == rootBefore.st_uid && after.st_gid == rootBefore.st_gid;
  inventory = ER832InspectInventory(runtime, record, owner, group);
  BOOL bytesPreserved = [RR832Read(registry, owner, group, &rereadIdentity, 65536) isEqual:registryBytes] &&
   [RR832Read(lock, owner, group, &rereadIdentity, 1024) isEqual:lockBytes] &&
   [RR832Read(receipt, owner, group, &rereadIdentity, 65536) isEqual:receiptBytes];
  bool capsuleHeld = ER832SecureFD(capsule, true, owner, group, &capsuleAfter) &&
   !fstatat(parent, RR832_CAPSULE, &capsulePath, AT_SYMLINK_NOFOLLOW) && ER832SameStat(&capsuleAfter, &capsulePath) &&
   capsuleBefore.st_dev == capsuleAfter.st_dev && capsuleBefore.st_ino == capsuleAfter.st_ino;
  bool verified = !fsync(capsule) && !fsync(parent) && pathIdentity && capsuleHeld && bytesPreserved && RR832Absent(parent, source) &&
   RR832ExactCapsule(capsule, true) && [inventory[@"exactInventoryVerified"] boolValue] && [inventory[@"realmContentsEmpty"] boolValue] &&
   ER832PathStable(runtime, "registry.json", registry, &registryBefore, false, owner, group) &&
   ER832PathStable(runtime, "registry.lock", lock, &lockBefore, false, owner, group) &&
   ER832PathStable(capsule, RR832_RECEIPT, receipt, &receiptBefore, false, owner, group);
#ifdef ENVARA_RUNTIME_RETIREMENT_INERT_TEST
  if (options.fault == 2) verified = false;
#endif
  if (!verified) { out[@"reason"] = @"ARCHIVE_POSTMOVE_UNCONFIRMED"; break; }
  out[@"archiveVerified"] = @YES; out[@"runtimeRetired"] = @YES; out[@"sourceAbsentVerified"] = @YES;
  out[@"issuedLeaseRetiredNoDelete"] = @YES; out[@"archivedFileCount"] = @2; out[@"archivedEmptyRealmCount"] = @2;
  out[@"reason"] = @"FIXED_RUNTIME_ARCHIVED";
 } while (false);
 // Preserve a partial capsule or moved tree on every fault. Never try a
 // name-only rollback, overwrite, recursive cleanup, or subsequent resume.
 if (moved && ![out[@"archiveVerified"] boolValue]) out[@"reason"] = @"ARCHIVE_POSTMOVE_UNCONFIRMED";
 if (created) out[@"changesFilesystem"] = @YES;
 if (receipt >= 0) close(receipt); if (capsule >= 0) close(capsule); if (lock >= 0) close(lock);
 if (registry >= 0) close(registry); if (runtime >= 0) close(runtime); if (maintenance) (void)flock(parent, LOCK_UN);
 return out;
}
static bool RR832ExitSuccess(NSDictionary *result) {
 if (![result[@"schema"] isEqual:RR832_SCHEMA] || ![result[@"runId"] isEqual:FIXED_RUN] || ![result[@"manifestSHA256"] isEqual:@MF] || ![result[@"anchor"] isEqual:FIXED_ANCHOR] || !isBool(result[@"readOnly"])) return false;
 if ([result[@"readOnly"] boolValue]) return [result[@"reason"] isEqual:@"STATIC_ARCHIVE_PLAN_ONLY"] ||
  (isBool(result[@"canRequestArchive"]) && [result[@"canRequestArchive"] boolValue]);
 for (NSString *key in @[@"retirementAttempted", @"archiveCreated", @"runtimeMoved", @"archiveVerified", @"runtimeRetired",
  @"changesFilesystem", @"issuedLeaseRetiredNoDelete", @"sourceAbsentVerified"])
  if (!isBool(result[key]) || ![result[key] boolValue]) return false;
 for (NSString *key in @[@"changesPF", @"changesDNS", @"changesRoutes", @"changesGroups", @"namespaceReclaimed", @"cleanupConfirmed", @"productionReady", @"canRequestArchive"])
  if (!isBool(result[key]) || [result[key] boolValue]) return false;
 return RR832IntegerEqual(result[@"archivedFileCount"], 2) && RR832IntegerEqual(result[@"archivedEmptyRealmCount"], 2) &&
  [result[@"archiveSHA256"] isKindOfClass:NSString.class] && [result[@"archiveSHA256"] length] == 64 &&
  regex(result[@"archiveSHA256"], @"^[a-f0-9]{64}$") && [result[@"reason"] isEqual:@"FIXED_RUNTIME_ARCHIVED"];
}

#ifdef ENVARA_RUNTIME_RETIREMENT_INERT_TEST
static NSDictionary *RR832ArchiveRuntimeForTestWithFault(int parentFD, const char *sourceLeaf, NSDictionary *record,
 NSDictionary *proof, uid_t owner, gid_t group, int fault, void (^beforeRename)(int)) {
 RR832Options options = {fault, beforeRename};
 return RR832Archive(parentFD, sourceLeaf, record, ^NSDictionary *(int runtime, NSDictionary *sealed) {
  (void)runtime; (void)sealed; return proof; }, owner, group, options);
}
static NSDictionary *RR832ArchiveRuntimeForTest(int parentFD, const char *sourceLeaf, NSDictionary *record,
 NSDictionary *proof, uid_t owner, gid_t group) {
 return RR832ArchiveRuntimeForTestWithFault(parentFD, sourceLeaf, record, proof, owner, group, 0, nil);
}
#else
static NSDictionary *RR832RootOperation(bool archive) {
 NSMutableDictionary *out = RR832Report(!archive); int parent = -1, installed = -1, runtime = -1, registry = -1; struct stat before;
 NSDictionary *record = nil, *proof = nil; NSData *registryBytes = nil; NSMutableDictionary *summary = nil;
 double deadline = seconds() + 175.0; rootDeadline=deadline;
 out[@"diagnosticStage"] = @"AUTHORIZATION_REFERENCE";
 if (!privilegedReference() || setgroups(1,(gid_t[]){0}) || setgid(0) || setuid(0) || getuid() || geteuid()) { out[@"reason"] = @"NATIVE_AUTHORIZATION_REQUIRED"; return out; }
 struct sigaction ignore = {0}; ignore.sa_handler = SIG_IGN; sigemptyset(&ignore.sa_mask);
 out[@"diagnosticStage"] = @"SIGNAL_BOUNDARY";
 struct sigaction reap={0}; reap.sa_handler=SIG_DFL; sigemptyset(&reap.sa_mask);
 if (sigaction(SIGCHLD,&reap,NULL) || sigaction(SIGPIPE, &ignore, NULL)) return out;
 out[@"diagnosticStage"] = @"INSTALLATION_PARENT";
 parent = directory(INSTALL_PARENT); if (parent < 0) goto done;
 out[@"diagnosticStage"] = @"MAINTENANCE_LEASE";
 if (flock(parent, LOCK_EX | LOCK_NB)) goto done;
 out[@"diagnosticStage"] = @"INSTALLED_SNAPSHOT";
 installed = verifiedInstallation(deadline); if (installed < 0) goto done;
 out[@"diagnosticStage"] = @"RUNTIME_DIRECTORY";
 runtime = directory(RUNTIME); if (!secureFD(runtime, true, 0700)) goto done;
 out[@"diagnosticStage"] = @"REGISTRY_READ";
 registry = openat(runtime, "registry.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
 registryBytes = readHeld(registry, &before); if (!registryBytes) goto done;
 out[@"diagnosticStage"] = @"REGISTRY_SCHEMA";
 record = validRegistry(registryBytes); if (!record) goto done;
 out[@"preflightSummary"] = RR832RegistrySummary(record);
 out[@"diagnosticStage"] = @"FIXED_PROCESS_INVENTORY";
 if (!RR832FixedRecordProcessesValid(record)) goto done;
 out[@"diagnosticStage"] = @"REGISTRY_IDENTITY";
 if (!heldRegistryUnchanged(runtime, registry, &before)) goto done;
 out[@"diagnosticStage"] = @"FRESH_PREFLIGHT";
 proof = RR832FreshProof(installed, runtime, record, deadline);
 summary = [RR832SummaryFromProof(proof) mutableCopy]; summary[@"registryInventory"] = out[@"preflightSummary"][@"registryInventory"];
 out[@"preflightSummary"] = summary;
 if (!RR832ProofValid(proof)) goto done;
 out[@"diagnosticStage"] = @"FINAL_REGISTRY_IDENTITY";
 if (!heldRegistryUnchanged(runtime, registry, &before)) goto done;
 if (archive) {
  RR832Options options = {0};
  out = [RR832Archive(parent, RR832_SOURCE, record, ^NSDictionary *(int fd, NSDictionary *sealed) {
   return RR832FreshProof(installed, fd, sealed, deadline); }, 0, 0, options) mutableCopy];
  out[@"diagnosticStage"] = @"ARCHIVE_OPERATION"; out[@"preflightSummary"] = summary;
 } else { out[@"canRequestArchive"] = @YES; out[@"reason"] = @"ARCHIVE_READY_READONLY"; out[@"diagnosticStage"] = @"READONLY_READY"; }
done:
 if (registry >= 0) close(registry); if (runtime >= 0) close(runtime); if (installed >= 0) close(installed);
 if (parent >= 0) { (void)flock(parent, LOCK_UN); close(parent); } return out;
}
static int RR832Emit(NSDictionary *result) {
 NSData *bytes = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 if (!bytes || bytes.length > 8192 || fwrite(bytes.bytes, 1, bytes.length, stdout) != bytes.length || fputc('\n', stdout) == EOF || fflush(stdout)) return 1;
 return RR832ExitSuccess(result) ? 0 : 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int RR832Request(const char *self, bool archive) {
 if (!RR832CarrierPathValid(self)) return RR832Emit(RR832Report(true));
 AuthorizationRef ref = NULL; FILE *communication = NULL; OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &ref);
 const char *prompt = archive ? "Envara: archive only the exact failed 832 run95c92 runtime into a private quarantine capsule. Preserve all original files and the retired lease. No PF, DNS, routes, groups, apps or installation changes."
  : "Envara: read only the exact failed 832 run95c92 runtime and fresh network/process proofs for a possible archive. Do not write or retire anything.";
 AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0}, item = {kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt, 0};
 AuthorizationRights rights = {1, &right}; AuthorizationEnvironment environment = {1, &item};
 if (status == errAuthorizationSuccess) status = AuthorizationCopyRights(ref, &rights, &environment,
  kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
 char *arguments[] = {archive ? "--archive-fixed-runtime" : "--inspect-fixed-runtime", NULL};
 if (status == errAuthorizationSuccess) status = AuthorizationExecuteWithPrivileges(ref, self, kAuthorizationFlagDefaults, arguments, &communication);
 NSMutableDictionary *out = RR832Report(!archive);
 out[@"diagnosticStage"] = @"REQUEST_RELAY";
 if (status == errAuthorizationSuccess && communication) {
  NSMutableData *bytes = [NSMutableData data]; int fd = fileno(communication); double until = seconds() + 185; bool eof = false;
  while (seconds() < until && bytes.length <= 8192) { struct pollfd p = {fd, POLLIN | POLLHUP, 0}; int ready = poll(&p, 1, 100);
   if (ready < 0 && errno == EINTR) continue; if (ready < 0) break; if (!ready) continue;
   unsigned char block[1024]; ssize_t size = read(fd, block, sizeof(block)); if (!size) { eof = true; break; }
   if (size < 0 && errno == EINTR) continue; if (size < 0 || bytes.length + (size_t)size > 8192) break; [bytes appendBytes:block length:(NSUInteger)size]; }
  NSDictionary *result = eof ? strictJSON(bytes, 8192) : nil;
  if ([result[@"schema"] isEqual:RR832_SCHEMA] && [result[@"runId"] isEqual:FIXED_RUN] && [result[@"manifestSHA256"] isEqual:@MF] && [result[@"anchor"] isEqual:FIXED_ANCHOR]) for (NSString *key in out.allKeys) {
   id value = result[key], base = out[key];
   if (isBool(base) && isBool(value) && ![@[@"cleanupUncertain", @"changesPF", @"changesDNS", @"changesRoutes", @"changesGroups", @"namespaceReclaimed", @"cleanupConfirmed", @"productionReady"] containsObject:key]) out[key] = value;
   else if ([@[@"archivedFileCount", @"archivedEmptyRealmCount"] containsObject:key] && [value isKindOfClass:NSNumber.class] && !isBool(value) && [value doubleValue] == 2) out[key] = value;
   else if ([key isEqual:@"archiveSHA256"] && regex(value, @"^[a-f0-9]{64}$")) out[key] = value;
   else if ([key isEqual:@"diagnosticStage"] && [RR832DiagnosticStages() containsObject:value]) out[key] = value;
   else if ([key isEqual:@"preflightSummary"]) out[key] = RR832SanitizeSummary(value);
   else if ([key isEqual:@"reason"] && [@[@"ARCHIVE_READY_READONLY", @"FIXED_RUNTIME_ARCHIVED", @"ARCHIVE_PREFLIGHT_REFUSED", @"ARCHIVE_CAPSULE_EXISTS", @"ARCHIVE_RECEIPT_UNCONFIRMED", @"ARCHIVE_IDENTITY_CHANGED", @"ARCHIVE_POSTMOVE_UNCONFIRMED"] containsObject:value]) out[key] = value;
  }
 } else out[@"reason"] = status == errAuthorizationCanceled ? @"NATIVE_AUTHORIZATION_CANCELED" : @"NATIVE_AUTHORIZATION_REFUSED";
 if (communication) fclose(communication); if (ref) AuthorizationFree(ref, kAuthorizationFlagDestroyRights); return RR832Emit(out);
}
#pragma clang diagnostic pop
int main(int argc, char **argv) { @autoreleasepool { @try {
 if (argc != 2) return RR832Emit(RR832Report(true));
 if (!strcmp(argv[1], "--plan")) { NSMutableDictionary *plan = RR832Report(true);
  plan[@"reason"] = @"STATIC_ARCHIVE_PLAN_ONLY"; plan[@"installedManifestSHA256"] = @MF;
  plan[@"fixedSource"] = @RUNTIME; plan[@"fixedCapsule"] = @INSTALL_PARENT "/" RR832_CAPSULE;
  plan[@"scope"] = @"atomic-filesystem-archive-only"; plan[@"requiresSeparateNativeAuthorization"] = @YES;
  plan[@"diagnosticStage"] = @"STATIC_PLAN";
  plan[@"recreatesActiveRuntime"] = @NO; plan[@"rootDeadlineSeconds"]=@175; plan[@"relayDeadlineSeconds"]=@185;
  plan[@"authorizationRequested"]=@NO; plan[@"bootstrapSelfPathAttested"]=@NO;
  plan[@"failedRunHostBaselineMatched"]=@NO; plan[@"snapshotAtomic"]=@NO;
  plan[@"operations"] = @[@"verify-fixed-installed-832-snapshot", @"fresh-read-only-network-and-process-preflight",
   @"seal-exclusive-private-proof-receipt", @"atomic-no-replace-runtime-directory-archive", @"verify-preserved-inodes-and-bytes"];
  return RR832Emit(plan); }
 if (!strcmp(argv[1], "--inspect-fixed-runtime")) return RR832Emit(RR832RootOperation(false));
 if (!strcmp(argv[1], "--archive-fixed-runtime")) return RR832Emit(RR832RootOperation(true));
 bool inspect = !strcmp(argv[1], "--request-readonly-archive-inspection"), archive = !strcmp(argv[1], "--request-archive-fixed-runtime");
 if ((!inspect && !archive) || getuid() == 0 || geteuid() == 0) return RR832Emit(RR832Report(true));
 char raw[PATH_MAX], self[PATH_MAX]; uint32_t capacity = sizeof(raw);
 if (_NSGetExecutablePath(raw, &capacity) || !realpath(raw, self)) return 1;
 if (!RR832CarrierPathValid(self)) return RR832Emit(RR832Report(true));
 return RR832Request(self, archive);
 } @catch (NSException *exception) { (void)exception; NSMutableDictionary *uncertain = RR832Report(false);
  uncertain[@"retirementAttempted"] = @YES; uncertain[@"changesFilesystem"] = @YES;
  uncertain[@"reason"] = @"ARCHIVE_POSTMOVE_UNCONFIRMED"; return RR832Emit(uncertain); } } }
#endif
