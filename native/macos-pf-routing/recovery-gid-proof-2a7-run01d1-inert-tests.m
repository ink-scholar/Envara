#define ENVARA_GID_PROOF_2A7_INERT_TEST 1
#import "recovery-gid-proof-2a7-run01d1.h"
#include <assert.h>
#include <stdio.h>

/* All callbacks are injected. This executable never invokes the production
 * inspector, proc_listallpids, proc_pidinfo, sysctl, getgrgid or getgrnam. */
typedef enum {
 Stable, NonRoot, GroupPresentGID, GroupPresentName, GroupUnknown, GroupUnknownOnce,
 GroupRecreated, EffectiveMatch, RealMatch, SavedMatch, SupplementaryMatch,
 BSDUnreadable, SupplementaryUnreadable, BindingPID, BindingBirth, BindingUID,
 BindingGID, BindingRealGID, BindingSavedGID, EmptyGroups, TruncatedGroups,
 WrongPrimaryGroup, DuplicateGroups, ListUnreadable, ListCapacity, ListNegative,
 ListDuplicate, ListEmpty, ListChurn, ListChurnOnce, BirthMutation, CredentialMutation,
 GroupMutation, Deadline, BadClock, ZeroBirth, BadMicroseconds, BSDErrorGone, BSDErrorDenied,
 SupplementaryZeroSize, SupplementaryShortSize, SupplementaryCapacity, SupplementaryErrorDenied, BSDFinalError, DeadlineAfterName,
 SupplementaryCapacityOwnedLast, SupplementaryCapacityVectorChanged, RuntimeCapacityUnknown, RuntimeCapacityMismatch,
 RuntimeCapacityError, RuntimeCapacityShort, ZombieComplete, ZombieOwnedLast, ZombiePIDReuse, ZombieUnknown, ZombieSupplementaryUnknown
} EG2A7TestMode;

typedef struct {
 EG2A7TestMode mode;
 unsigned rootCalls, listCalls, bsdCalls, supplementaryCalls, lookupCalls, clockCalls, capacityCalls;
 EG2A7ReaderDiagnostic diagnostic;
} EG2A7Fixture;

static NSDictionary *Record(void) {
 return @{@"schema": @"envara.macos-pf-owned-registry/v1",
  @"runId": @"01d1e669-bc58-4a10-ae2d-709e7fedd7f6", @"anchor": @"io.envara.pf.run.01d1e669-bc58-4a10-ae2d-709e7fedd7f6",
  @"incompleteGroupAllocations": @[], @"realms": @[
   @{@"realmId": @"aaaabbbb-cccc-4ddd-8eee-111122223333", @"gid": @7171, @"groupPath": @"/Groups/_envara_pf_7171"},
   @{@"realmId": @"ddddaaaa-bbbb-4ccc-8ddd-444455556666", @"gid": @7172, @"groupPath": @"/Groups/_envara_pf_7172"}]};
}
static BOOL TestRoot(void *context) {
 EG2A7Fixture *f = context; f->rootCalls++; return (BOOL)(f->mode != NonRoot);
}
static int TestList(void *context, pid_t *pids, size_t capacity) {
 EG2A7Fixture *f = context; f->listCalls++; assert(capacity == EG2A7_PID_LIMIT);
 if (f->mode == ListUnreadable) return -1;
 if (f->mode == ListCapacity) return (int)capacity;
 if (f->mode == ListEmpty) { pids[0] = 0; return 1; }
 /* Deliberately unordered, with PID zero (the kernel task) excluded. */
 pids[0] = 1002; pids[1] = 0; pids[2] = 1001;
 if (f->mode == ListNegative) pids[0] = -4;
 if (f->mode == ListDuplicate) pids[0] = 1001;
 if (f->mode == ListChurn && f->listCalls % 2 == 0) pids[0] = 1003;
 if (f->mode == ListChurnOnce && f->listCalls == 2) pids[0] = 1003;
 return 3;
}
static EG2A7Credentials Credential(pid_t pid) {
 return (EG2A7Credentials){.pid = pid, .seconds = 1234567 + (uint64_t)pid,
  .microseconds = 456, .effectiveUID = 501, .realUID = 501, .savedUID = 501,
  .effectiveGID = 20, .realGID = 20, .savedGID = 20};
}
static EG2A7Fixture *nativeShimFixture;
static int TestNativeBSDCall(int pid, int flavor, uint64_t argument, void *buffer, int bytes) {
 assert(nativeShimFixture && flavor == PROC_PIDTBSDINFO && argument == 1 && bytes == sizeof(struct proc_bsdinfo));
 assert(pid == 1001 || pid == 1002);
 if (nativeShimFixture->mode == ZombieUnknown) { errno = ESRCH; return 0; }
 struct proc_bsdinfo info = {.pbi_pid = (uint32_t)pid, .pbi_status = SZOMB, .pbi_start_tvsec = 1234567 + (uint64_t)pid,
  .pbi_start_tvusec = 456, .pbi_uid = 501, .pbi_ruid = 501, .pbi_svuid = 501, .pbi_gid = 20, .pbi_rgid = 20, .pbi_svgid = 20};
 if (nativeShimFixture->mode == ZombiePIDReuse && nativeShimFixture->bsdCalls % 2 == 0) info.pbi_start_tvsec++;
 memcpy(buffer, &info, sizeof(info)); return sizeof(info);
}
static int TestBSD(void *context, pid_t pid, EG2A7Credentials *out) {
 EG2A7Fixture *f = context; f->bsdCalls++;
 f->diagnostic = (EG2A7ReaderDiagnostic){0};
 if (f->mode == ZombieComplete || f->mode == ZombieOwnedLast || f->mode == ZombiePIDReuse || f->mode == ZombieUnknown || f->mode == ZombieSupplementaryUnknown) {
  nativeShimFixture = f; int result = EG2A7ReadBSDIncludingZombies(pid, out, &f->diagnostic, TestNativeBSDCall); nativeShimFixture = NULL; return result;
 }
 if (f->mode == BSDErrorGone || f->mode == BSDErrorDenied || (f->mode == BSDFinalError && f->bsdCalls % 2 == 0)) {
  struct proc_bsdinfo info = {0}; return EG2A7DecodeBSD(&info, 0, f->mode == BSDErrorDenied ? EACCES : ESRCH, out, &f->diagnostic);
 }
 if (f->mode == BSDUnreadable) return -1;
 *out = Credential(pid);
 if (f->mode == EffectiveMatch) out->effectiveGID = 7171;
 if (f->mode == RealMatch) out->realGID = 7172;
 if (f->mode == SavedMatch) out->savedGID = 7171;
 if (f->mode == BirthMutation && f->bsdCalls % 2 == 0) out->seconds++;
 if (f->mode == CredentialMutation && f->bsdCalls % 2 == 0) out->savedUID++;
 if (f->mode == ZeroBirth) out->seconds = 0;
 if (f->mode == BadMicroseconds) out->microseconds = 1000000;
 return 0;
}
static int TestSupplementary(void *context, pid_t pid, EG2A7Credentials *out) {
 EG2A7Fixture *f = context; f->supplementaryCalls++;
 f->diagnostic = (EG2A7ReaderDiagnostic){0};
 if (f->mode == SupplementaryZeroSize || f->mode == SupplementaryShortSize || f->mode == SupplementaryCapacity ||
  f->mode == SupplementaryCapacityOwnedLast || f->mode == SupplementaryCapacityVectorChanged || f->mode == SupplementaryErrorDenied ||
  f->mode == ZombieComplete || f->mode == ZombieOwnedLast || f->mode == ZombiePIDReuse || f->mode == ZombieSupplementaryUnknown) {
  struct kinfo_proc info = {0}; info.kp_proc.p_pid = pid; info.kp_proc.p_starttime.tv_sec = 1234567 + pid; info.kp_proc.p_starttime.tv_usec = 456;
  info.kp_eproc.e_ucred.cr_uid = 501; info.kp_eproc.e_pcred.p_ruid = 501; info.kp_eproc.e_pcred.p_svuid = 501;
  info.kp_eproc.e_pcred.p_rgid = 20; info.kp_eproc.e_pcred.p_svgid = 20;
  BOOL zombie = (BOOL)(f->mode == ZombieComplete || f->mode == ZombieOwnedLast || f->mode == ZombiePIDReuse || f->mode == ZombieSupplementaryUnknown);
  info.kp_proc.p_stat = zombie ? SZOMB : SRUN;
  BOOL full = (BOOL)(zombie || f->mode == SupplementaryCapacity || f->mode == SupplementaryCapacityOwnedLast || f->mode == SupplementaryCapacityVectorChanged);
  info.kp_eproc.e_ucred.cr_ngroups = full ? NGROUPS : 2;
  info.kp_eproc.e_ucred.cr_groups[0] = 20; info.kp_eproc.e_ucred.cr_groups[1] = 80;
  if (full) for (unsigned i = 1; i < NGROUPS; i++) info.kp_eproc.e_ucred.cr_groups[i] = 80 + i;
  if (f->mode == SupplementaryCapacityOwnedLast || f->mode == ZombieOwnedLast) info.kp_eproc.e_ucred.cr_groups[NGROUPS-1] = 7172;
  if (f->mode == SupplementaryCapacityVectorChanged && f->supplementaryCalls % 4 >= 3) info.kp_eproc.e_ucred.cr_groups[NGROUPS-1]++;
  size_t size = f->mode == SupplementaryZeroSize ? 0 : f->mode == SupplementaryShortSize ? sizeof(info)-1 : sizeof(info);
  BOOL denied = (BOOL)(f->mode == SupplementaryErrorDenied || f->mode == ZombieSupplementaryUnknown);
  return EG2A7DecodeSupplementary(&info, denied ? -1 : 0, size, denied ? EPERM : 0, out, &f->diagnostic);
 }
 if (f->mode == SupplementaryUnreadable) return -1;
 *out = Credential(pid); out->groupCount = 2; out->groups[0] = 20; out->groups[1] = 80;
 if (f->mode == SupplementaryMatch) out->groups[1] = 7172;
 if (f->mode == BindingPID) out->pid++;
 if (f->mode == BindingBirth) out->microseconds++;
 if (f->mode == BindingUID) out->effectiveUID++;
 if (f->mode == BindingGID) { out->effectiveGID++; out->groups[0]++; }
 if (f->mode == BindingRealGID) out->realGID++;
 if (f->mode == BindingSavedGID) out->savedGID++;
 if (f->mode == EmptyGroups) out->groupCount = 0;
 if (f->mode == TruncatedGroups) out->groupCount = NGROUPS + 1;
 if (f->mode == WrongPrimaryGroup) out->groups[0]++;
 if (f->mode == DuplicateGroups) out->groups[1] = 20;
 if (f->mode == GroupMutation && f->supplementaryCalls % 4 >= 3) out->groups[1]++;
 return 0;
}
static int Lookup(EG2A7Fixture *f, BOOL name) {
 f->lookupCalls++;
 if (f->mode == GroupPresentGID && !name) return 1;
 if (f->mode == GroupPresentName && name) return 1;
 if (f->mode == GroupUnknown || (f->mode == GroupUnknownOnce && f->lookupCalls == 1)) return -1;
 if (f->mode == GroupRecreated && f->lookupCalls > 4) return 1;
 return 0;
}
static int TestGID(void *context, gid_t gid) {
 assert(gid == 7171 || gid == 7172); return Lookup(context, NO);
}
static int TestName(void *context, const char *name) {
 assert(!strcmp(name, "_envara_pf_7171") || !strcmp(name, "_envara_pf_7172")); return Lookup(context, YES);
}
static double TestClock(void *context) {
 EG2A7Fixture *f = context; f->clockCalls++;
 if (f->mode == BadClock) return NAN;
 if (f->mode == Deadline) return (double)f->clockCalls * 5.0;
 if (f->mode == DeadlineAfterName && f->lookupCalls >= 4) return 20.0;
 return 1.0;
}
static void TestDiagnostic(void *context, EG2A7ReaderDiagnostic *out) { *out = ((EG2A7Fixture *)context)->diagnostic; }
static int TestCapacity(void *context, unsigned *out) {
 EG2A7Fixture *f = context; f->capacityCalls++;
 int capacity = f->mode == RuntimeCapacityUnknown ? 0 : f->mode == RuntimeCapacityMismatch ? NGROUPS + 1 : NGROUPS;
 return EG2A7DecodeCapacity(f->mode == RuntimeCapacityError ? -1 : 0,
  f->mode == RuntimeCapacityShort ? sizeof(int)-1 : sizeof(int), capacity,
  f->mode == RuntimeCapacityError ? EPERM : 0, out, &f->diagnostic);
}
static EG2A7Readers Readers(EG2A7Fixture *f) {
 return (EG2A7Readers){.context = f, .root = TestRoot, .list = TestList, .bsd = TestBSD,
  .supplementary = TestSupplementary, .groupByGID = TestGID, .groupByName = TestName, .clock = TestClock,
  .capacity = TestCapacity, .diagnostic = TestDiagnostic};
}

static unsigned tests;
static void Safe(NSDictionary *report) {
 NSArray *booleans = @[@"readOnly", @"cleanupConfirmed", @"productionReady", @"recordIdentityVerified",
  @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent", @"processEnumerationComplete",
  @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"allOwnedGIDProcessesAbsent", @"groupCapacityVerified"];
 NSArray *counts = @[@"realmCount", @"groupLookups", @"snapshotPIDCount", @"inspectedProcessCount",
  @"matchingProcessCount", @"unreadableProcessCount", @"unstableProcessCount", @"zombieCredentialChecks", @"attemptCount", @"scanRound", @"sdkGroupCapacity", @"runtimeGroupCapacity", @"readerExpectedByteCount"];
 NSArray *nullableCounts = @[@"readerReturnedByteCount", @"observedGroupCount"];
 NSMutableSet *keys = [NSMutableSet setWithArray:booleans]; [keys addObjectsFromArray:counts];
 [keys addObjectsFromArray:nullableCounts]; [keys addObjectsFromArray:@[@"schema", @"reason", @"diagnosticStage", @"readerFailure", @"errnoClass"]]; assert(report.count == keys.count);
 for (NSString *key in report) assert([keys containsObject:key]);
 for (NSString *key in booleans) assert(CFGetTypeID((__bridge CFTypeRef)report[key]) == CFBooleanGetTypeID());
 for (NSString *key in counts) {
  NSNumber *value = report[key]; assert([value isKindOfClass:NSNumber.class]);
  assert(CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID());
  assert(value.longLongValue >= 0 && value.longLongValue <= 32768);
 }
 for (NSString *key in nullableCounts) if (report[key] != NSNull.null) {
  assert([report[key] isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)report[key]) != CFBooleanGetTypeID());
  assert(!CFNumberIsFloatType((__bridge CFNumberRef)report[key]) && [report[key] longLongValue] >= 0 && [report[key] longLongValue] <= 65536);
 }
 assert([EG2A7StageNames() containsObject:report[@"diagnosticStage"]]); assert([EG2A7FailureNames() containsObject:report[@"readerFailure"]]);
 assert([EG2A7ErrnoNames() containsObject:report[@"errnoClass"]]);
 assert([report[@"readOnly"] boolValue]); assert(![report[@"cleanupConfirmed"] boolValue]);
 assert(![report[@"productionReady"] boolValue]);
 assert([report[@"schema"] isEqual:@"envara.macos-pf-gid-proof/v1"]);
 assert(([@[@"READ_ONLY_FIXED_GID_PROOF", @"FIXED_GID_PROOF_REFUSED"] containsObject:report[@"reason"]]));
 NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingWithoutEscapingSlashes error:NULL];
 NSString *text = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]; assert(text);
 for (NSString *private in @[@"1001", @"1002", @"7171", @"7172", @"_envara_pf_", @"/Groups/",
  @"0a00377a", @"aaaabbbb", @"ddddaaaa", @"1234567"]) assert(![text containsString:private]);
}
static NSDictionary *Check(NSString *label, EG2A7TestMode mode, BOOL expected) {
 EG2A7Fixture fixture = {.mode = mode}; EG2A7Readers readers = Readers(&fixture);
 NSDictionary *report = EnvaraInspectGIDProof2A7ForTest(Record(), &readers); Safe(report);
 assert([report[@"allOwnedGIDProcessesAbsent"] boolValue] == expected);
 assert([report[@"attemptCount"] unsignedIntValue] <= EG2A7_ATTEMPTS);
 if (expected) {
  for (NSString *key in @[@"recordIdentityVerified", @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent",
   @"processEnumerationComplete", @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"groupCapacityVerified"])
   assert([report[key] boolValue]);
  assert([report[@"snapshotPIDCount"] intValue] == 2 && [report[@"inspectedProcessCount"] intValue] == 4);
  assert([report[@"groupLookups"] intValue] == 8);
 }
 if (mode == NonRoot) assert(fixture.listCalls == 0 && fixture.lookupCalls == 0 && fixture.bsdCalls == 0 && fixture.capacityCalls == 0);
 if (mode == RuntimeCapacityUnknown || mode == RuntimeCapacityMismatch || mode == RuntimeCapacityError || mode == RuntimeCapacityShort)
  assert(fixture.listCalls == 0 && fixture.lookupCalls == 0 && fixture.bsdCalls == 0 && ![report[@"groupCapacityVerified"] boolValue]);
 if (mode == EffectiveMatch || mode == RealMatch || mode == SavedMatch || mode == SupplementaryMatch) {
  assert([report[@"matchingProcessCount"] intValue] == 1 && [report[@"attemptCount"] intValue] == 1);
 }
 if (mode == GroupPresentGID || mode == GroupPresentName) assert(fixture.listCalls == 0);
 printf("PASS %s\n", label.UTF8String); tests++; return report;
}
static void Invalid(NSString *label, NSDictionary *record) {
 EG2A7Fixture fixture = {.mode = Stable}; EG2A7Readers readers = Readers(&fixture);
 NSDictionary *report = EnvaraInspectGIDProof2A7ForTest(record, &readers); Safe(report);
 assert(![report[@"recordIdentityVerified"] boolValue]); assert(![report[@"allOwnedGIDProcessesAbsent"] boolValue]);
 assert(fixture.rootCalls == 0 && fixture.listCalls == 0 && fixture.lookupCalls == 0 && fixture.bsdCalls == 0);
 printf("PASS %s\n", label.UTF8String); tests++;
}
static NSMutableDictionary *AlterRealm(id gid, id path) {
 NSMutableDictionary *record = [Record() mutableCopy], *realm = [record[@"realms"][1] mutableCopy];
 if (gid) realm[@"gid"] = gid; if (path) realm[@"groupPath"] = path;
 record[@"realms"] = @[record[@"realms"][0], realm]; return record;
}

int main(void) {
 @autoreleasepool {
  Check(@"stable two-realm complete credential snapshots", Stable, YES);
  Check(@"non-root stops before enumeration and directory lookup", NonRoot, NO);
  Check(@"existing numeric group refuses", GroupPresentGID, NO);
  Check(@"existing named group refuses", GroupPresentName, NO);
  Check(@"unknown group result refuses", GroupUnknown, NO);
  NSDictionary *retry = Check(@"finite retry after an unknown lookup", GroupUnknownOnce, YES);
  assert([retry[@"attemptCount"] intValue] == 2);
  Check(@"group recreation after process snapshots refuses", GroupRecreated, NO);
  Check(@"effective group member refuses", EffectiveMatch, NO);
  Check(@"real group member refuses", RealMatch, NO);
  Check(@"saved group member refuses", SavedMatch, NO);
  Check(@"supplementary-only group member refuses", SupplementaryMatch, NO);
  Check(@"unreadable BSD snapshot refuses", BSDUnreadable, NO);
  Check(@"unreadable supplementary snapshot refuses", SupplementaryUnreadable, NO);
  Check(@"cross-interface PID mismatch refuses", BindingPID, NO);
  Check(@"cross-interface birth mismatch refuses", BindingBirth, NO);
  Check(@"cross-interface UID mismatch refuses", BindingUID, NO);
  Check(@"cross-interface effective GID mismatch refuses", BindingGID, NO);
  Check(@"cross-interface real GID mismatch refuses", BindingRealGID, NO);
  Check(@"cross-interface saved GID mismatch refuses", BindingSavedGID, NO);
  Check(@"empty supplementary group vector refuses", EmptyGroups, NO);
  Check(@"overflow seventeen supplementary groups refuses", TruncatedGroups, NO);
  Check(@"primary supplementary entry mismatch refuses", WrongPrimaryGroup, NO);
  Check(@"duplicate supplementary vector refuses", DuplicateGroups, NO);
  Check(@"unreadable enumeration refuses", ListUnreadable, NO);
  Check(@"full enumeration capacity refuses", ListCapacity, NO);
  Check(@"negative PID refuses", ListNegative, NO);
  Check(@"duplicate PID refuses", ListDuplicate, NO);
  Check(@"positive PID coverage cannot be empty", ListEmpty, NO);
  Check(@"persistent process-set churn refuses", ListChurn, NO);
  retry = Check(@"finite retry after process-set churn", ListChurnOnce, YES);
  assert([retry[@"attemptCount"] intValue] == 2);
  Check(@"birth change inside bracket refuses", BirthMutation, NO);
  Check(@"credential change inside bracket refuses", CredentialMutation, NO);
  Check(@"supplementary membership changes between enumerations refuse", GroupMutation, NO);
  Check(@"deadline closes observation window", Deadline, NO);
  Check(@"invalid monotonic clock refuses", BadClock, NO);
  Check(@"zero process birth refuses", ZeroBirth, NO);
  Check(@"out-of-range birth microseconds refuses", BadMicroseconds, NO);
  NSDictionary *diagnostic = Check(@"first BSD ESRCH remains unknown and reports only fixed class", BSDErrorGone, NO);
  assert([diagnostic[@"diagnosticStage"] isEqual:@"BSD_FIRST"] && [diagnostic[@"readerFailure"] isEqual:@"PROC_PIDINFO_ERROR"] && [diagnostic[@"errnoClass"] isEqual:@"ESRCH"]);
  assert([diagnostic[@"scanRound"] intValue] == 1 && [diagnostic[@"readerReturnedByteCount"] intValue] == 0);
  diagnostic = Check(@"first BSD access denial remains refused", BSDErrorDenied, NO);
  assert([diagnostic[@"errnoClass"] isEqual:@"EACCES"]);
  diagnostic = Check(@"sysctl successful zero-size result remains unknown", SupplementaryZeroSize, NO);
  assert([diagnostic[@"diagnosticStage"] isEqual:@"SYSCTL_SUPPLEMENTARY"] && [diagnostic[@"readerFailure"] isEqual:@"SYSCTL_SIZE_MISMATCH"]);
  assert([diagnostic[@"readerReturnedByteCount"] intValue] == 0 && [diagnostic[@"errnoClass"] isEqual:@"NONE"]);
  diagnostic = Check(@"sysctl short ABI result remains refused", SupplementaryShortSize, NO);
  assert([diagnostic[@"readerReturnedByteCount"] unsignedLongLongValue] + 1 == sizeof(struct kinfo_proc));
  diagnostic = Check(@"exact sixteen-slot system-attested vector passes both complete snapshots", SupplementaryCapacity, YES);
  assert([diagnostic[@"groupCapacityVerified"] boolValue] && [diagnostic[@"runtimeGroupCapacity"] intValue] == NGROUPS);
  diagnostic = Check(@"owned group only in sixteenth slot refuses", SupplementaryCapacityOwnedLast, NO);
  assert([diagnostic[@"matchingProcessCount"] intValue] == 1 && [diagnostic[@"readerFailure"] isEqual:@"OWNED_GID_OBSERVED"]);
  diagnostic = Check(@"sixteenth-slot mutation between snapshots refuses", SupplementaryCapacityVectorChanged, NO);
  assert([diagnostic[@"unstableProcessCount"] intValue] > 0 && [diagnostic[@"readerFailure"] isEqual:@"GROUPS_CHANGED"]);
  struct kinfo_proc overflowing = {0}; overflowing.kp_proc.p_starttime.tv_sec = 1234567;
  overflowing.kp_eproc.e_ucred.cr_ngroups = NGROUPS + 1;
  EG2A7Credentials untouched = {.pid = 1001}, beforeOverflow = untouched; EG2A7ReaderDiagnostic overflowDiagnostic = {0};
  assert(EG2A7DecodeSupplementary(&overflowing, 0, sizeof(overflowing), 0, &untouched, &overflowDiagnostic) == -1);
  assert(overflowDiagnostic.failure == EG2A7_FAILURE_GROUP_CAPACITY && overflowDiagnostic.observedGroups == NGROUPS + 1);
  assert(!memcmp(&untouched, &beforeOverflow, sizeof(untouched)));
  printf("PASS production native decoder refuses seventeen slots before copying any credentials\n"); tests++;
  diagnostic = Check(@"unknown runtime group capacity stops before process enumeration", RuntimeCapacityUnknown, NO);
  assert([diagnostic[@"diagnosticStage"] isEqual:@"GROUP_CAPACITY_ATTESTATION"]);
  diagnostic = Check(@"runtime SDK capacity mismatch stops before process enumeration", RuntimeCapacityMismatch, NO);
  assert([diagnostic[@"readerFailure"] isEqual:@"SYSTEM_GROUP_CAPACITY_MISMATCH"]);
  Check(@"native capacity permission failure stops before process enumeration", RuntimeCapacityError, NO);
  Check(@"native capacity short result stops before process enumeration", RuntimeCapacityShort, NO);
  diagnostic = Check(@"fixed native arg1 reads complete stable zombie credentials in both snapshots", ZombieComplete, YES);
  assert([diagnostic[@"zombieCredentialChecks"] intValue] == 4 && [diagnostic[@"unreadableProcessCount"] intValue] == 0);
  diagnostic = Check(@"zombie owned supplementary GID in last slot still refuses", ZombieOwnedLast, NO);
  assert([diagnostic[@"matchingProcessCount"] intValue] == 1 && ![diagnostic[@"allOwnedGIDProcessesAbsent"] boolValue]);
  diagnostic = Check(@"zombie birth mismatch across APIs refuses PID reuse", ZombiePIDReuse, NO);
  assert([diagnostic[@"unstableProcessCount"] intValue] > 0 && [diagnostic[@"readerFailure"] isEqual:@"IDENTITY_CHANGED"]);
  diagnostic = Check(@"arg1 ESRCH remains unknown and restarts bounded full scan", ZombieUnknown, NO);
  assert([diagnostic[@"attemptCount"] intValue] == EG2A7_ATTEMPTS && [diagnostic[@"unreadableProcessCount"] intValue] == 1 && [diagnostic[@"errnoClass"] isEqual:@"ESRCH"]);
  diagnostic = Check(@"zombie sysctl permission error remains unknown without skipping", ZombieSupplementaryUnknown, NO);
  assert([diagnostic[@"unreadableProcessCount"] intValue] == 1 && [diagnostic[@"errnoClass"] isEqual:@"EPERM"]);
  EG2A7Fixture missingCapacityFixture = {.mode = Stable}; EG2A7Readers missingCapacityReaders = Readers(&missingCapacityFixture); missingCapacityReaders.capacity = NULL;
  diagnostic = EnvaraInspectGIDProof2A7ForTest(Record(), &missingCapacityReaders); Safe(diagnostic);
  assert(![diagnostic[@"groupCapacityVerified"] boolValue] && ![diagnostic[@"allOwnedGIDProcessesAbsent"] boolValue] && missingCapacityFixture.listCalls == 0);
  printf("PASS missing capacity reader cannot open complete-credential proof\n"); tests++;
  diagnostic = Check(@"sysctl permission denial remains refused without asserting bytes", SupplementaryErrorDenied, NO);
  assert([diagnostic[@"readerFailure"] isEqual:@"SYSCTL_ERROR"] && [diagnostic[@"errnoClass"] isEqual:@"EPERM"] && diagnostic[@"readerReturnedByteCount"] == NSNull.null);
  diagnostic = Check(@"final BSD disappearance is separately classified and refused", BSDFinalError, NO);
  assert([diagnostic[@"diagnosticStage"] isEqual:@"BSD_FINAL"] && [diagnostic[@"errnoClass"] isEqual:@"ESRCH"]);
  diagnostic = Check(@"deadline after successful final group-name lookup is explicit", DeadlineAfterName, NO);
  assert([diagnostic[@"diagnosticStage"] isEqual:@"GROUP_LOOKUPS"] && [diagnostic[@"readerFailure"] isEqual:@"DEADLINE"]);
  EG2A7Fixture oldFixture = {.mode = BSDUnreadable}; EG2A7Readers oldReaders = Readers(&oldFixture); oldReaders.diagnostic = NULL;
  diagnostic = EnvaraInspectGIDProof2A7ForTest(Record(), &oldReaders); Safe(diagnostic);
  assert(![diagnostic[@"allOwnedGIDProcessesAbsent"] boolValue] && [diagnostic[@"readerFailure"] isEqual:@"READER_UNSPECIFIED"]);
  printf("PASS absent diagnostic callback cannot turn unreadable credentials into proof\n"); tests++;
  Invalid(@"duplicate realm group identity refuses", AlterRealm(@7171, @"/Groups/_envara_pf_7171"));
  Invalid(@"lower group bound refuses", AlterRealm(@7099, @"/Groups/_envara_pf_7099"));
  Invalid(@"upper group bound refuses", AlterRealm(@8000, @"/Groups/_envara_pf_8000"));
  Invalid(@"fractional group identity refuses", AlterRealm(@7172.5, nil));
  Invalid(@"boolean group identity refuses", AlterRealm(@YES, nil));
  Invalid(@"string group identity refuses", AlterRealm(@"7172", nil));
  Invalid(@"group path must exactly match its numeric identity", AlterRealm(nil, @"/Groups/_envara_pf_7173"));
  NSMutableDictionary *record = [Record() mutableCopy]; record[@"incompleteGroupAllocations"] = @[@{}];
  Invalid(@"incomplete allocations refuse", record);
  record = [Record() mutableCopy]; record[@"runId"] = @"11111111-2222-4333-8444-555555555555";
  Invalid(@"foreign run refuses", record);
  record = [Record() mutableCopy]; record[@"anchor"] = @"foreign.anchor"; Invalid(@"foreign anchor refuses", record);
  record = [Record() mutableCopy]; record[@"realms"] = @[record[@"realms"][0]]; Invalid(@"exactly two realms required", record);
  record = [Record() mutableCopy];
  NSMutableDictionary *realm = [record[@"realms"][1] mutableCopy]; realm[@"realmId"] = record[@"realms"][0][@"realmId"];
  record[@"realms"] = @[record[@"realms"][0], realm]; Invalid(@"distinct sealed realm IDs required", record);
  Invalid(@"wrong top-level type refuses", (id)@[]);
  printf("PASS %u inert GID-proof tests; no native process/group scans executed\n", tests);
 }
 return 0;
}
