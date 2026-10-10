#ifndef ENVARA_RECOVERY_GID_PROOF_832_H
#define ENVARA_RECOVERY_GID_PROOF_832_H

/* Fixed-run, read-only snapshot proof. This is not an atomic credential barrier:
 * the caller must retain its verified installation/runtime exclusion and recheck
 * its independent recorded-PID proof. No PF, directory-service or filesystem
 * mutation is performed here. The injected entry point exists only in inert tests.
 */
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#define EG832_PID_LIMIT 16384
#define EG832_ATTEMPTS 3
#define EG832_DEADLINE_SECONDS 15.0

typedef struct {
 pid_t pid;
 unsigned status;
 uint64_t seconds, microseconds;
 uid_t effectiveUID, realUID, savedUID;
 gid_t effectiveGID, realGID, savedGID;
 unsigned groupCount;
 gid_t groups[NGROUPS];
} EG832Credentials;

typedef enum { EG832_STAGE_NOT_STARTED, EG832_STAGE_RECORD, EG832_STAGE_READERS, EG832_STAGE_ROOT,
 EG832_STAGE_CLOCK, EG832_STAGE_ALLOCATION, EG832_STAGE_GROUPS, EG832_STAGE_LIST_FIRST,
 EG832_STAGE_BSD_FIRST, EG832_STAGE_SUPPLEMENTARY, EG832_STAGE_BSD_FINAL, EG832_STAGE_BINDING,
 EG832_STAGE_LIST_SECOND, EG832_STAGE_SECOND_IDENTITY, EG832_STAGE_SECOND_GROUPS,
 EG832_STAGE_GROUPS_FINAL, EG832_STAGE_COMPLETE, EG832_STAGE_CAPACITY } EG832Stage;
typedef enum { EG832_FAILURE_NONE, EG832_FAILURE_RECORD, EG832_FAILURE_READERS, EG832_FAILURE_NOT_ROOT,
 EG832_FAILURE_CLOCK, EG832_FAILURE_ALLOCATION, EG832_FAILURE_DEADLINE, EG832_FAILURE_GROUP_UNKNOWN,
 EG832_FAILURE_GROUP_PRESENT, EG832_FAILURE_LIST_UNREADABLE, EG832_FAILURE_LIST_CAPACITY,
 EG832_FAILURE_LIST_INVALID, EG832_FAILURE_LIST_EMPTY, EG832_FAILURE_LIST_DUPLICATE, EG832_FAILURE_LIST_CHANGED,
 EG832_FAILURE_BSD_ERROR, EG832_FAILURE_BSD_SIZE, EG832_FAILURE_SYSCTL_ERROR, EG832_FAILURE_SYSCTL_SIZE,
 EG832_FAILURE_PID, EG832_FAILURE_BIRTH, EG832_FAILURE_GROUP_EMPTY, EG832_FAILURE_GROUP_CAPACITY,
 EG832_FAILURE_GROUP_PRIMARY, EG832_FAILURE_GROUP_DUPLICATE, EG832_FAILURE_IDENTITY,
 EG832_FAILURE_GROUPS_CHANGED, EG832_FAILURE_OWNED, EG832_FAILURE_UNSPECIFIED, EG832_FAILURE_GROUP_COUNT,
 EG832_FAILURE_CAPACITY_UNAVAILABLE, EG832_FAILURE_CAPACITY_MISMATCH } EG832Failure;
typedef struct {
 EG832Failure failure; int error;
 size_t expectedBytes, returnedBytes; BOOL bytesAvailable;
 unsigned observedGroups; BOOL groupsAvailable;
} EG832ReaderDiagnostic;

typedef struct {
 void *context;
 BOOL (*root)(void *);
 int (*list)(void *, pid_t *, size_t);
 int (*bsd)(void *, pid_t, EG832Credentials *);
 int (*supplementary)(void *, pid_t, EG832Credentials *);
 /* 0 absent, 1 present, -1 unknown. Presence in either namespace refuses. */
 int (*groupByGID)(void *, gid_t);
 int (*groupByName)(void *, const char *);
 double (*clock)(void *);
 /* Mandatory system/SDK capacity attestation before any process snapshot. */
 int (*capacity)(void *, unsigned *);
 /* Optional metadata only; absence never changes a failed reader into proof. */
 void (*diagnostic)(void *, EG832ReaderDiagnostic *);
} EG832Readers;

typedef struct {
 BOOL record, root, lookupsComplete, groupsAbsent, enumerationComplete;
 BOOL identitiesStable, supplementaryCovered, snapshotStable, absent;
 BOOL capacityVerified;
 NSUInteger runtimeCapacity;
 NSUInteger realmCount, groupLookups, snapshotPIDCount, inspected;
 NSUInteger matching, unreadable, unstable, attempts;
 NSUInteger zombieChecks;
 NSUInteger scanRound;
 EG832Stage stage; EG832ReaderDiagnostic diagnostic;
} EG832Result;

static NSArray *EG832StageNames(void) {
 return @[@"NOT_STARTED", @"RECORD", @"READER_CONTRACT", @"ROOT_CALLER", @"CLOCK", @"ALLOCATION", @"GROUP_LOOKUPS",
  @"PID_LIST_FIRST", @"BSD_FIRST", @"SYSCTL_SUPPLEMENTARY", @"BSD_FINAL", @"CROSS_INTERFACE_IDENTITY",
  @"PID_LIST_SECOND", @"SECOND_SNAPSHOT_IDENTITY", @"SECOND_SNAPSHOT_GROUPS", @"FINAL_GROUP_LOOKUPS", @"COMPLETE", @"GROUP_CAPACITY_ATTESTATION"];
}
static NSArray *EG832FailureNames(void) {
 return @[@"NONE", @"INVALID_RECORD", @"READER_CONTRACT", @"NOT_ROOT", @"CLOCK_INVALID", @"ALLOCATION_FAILED", @"DEADLINE",
  @"GROUP_LOOKUP_UNKNOWN", @"GROUP_PRESENT", @"PID_LIST_UNREADABLE", @"PID_LIST_CAPACITY", @"PID_LIST_INVALID",
  @"PID_LIST_EMPTY", @"PID_LIST_DUPLICATE", @"PID_LIST_CHANGED", @"PROC_PIDINFO_ERROR", @"PROC_PIDINFO_SIZE_MISMATCH",
  @"SYSCTL_ERROR", @"SYSCTL_SIZE_MISMATCH", @"CREDENTIAL_PID_INVALID", @"BIRTH_INVALID", @"GROUP_EMPTY", @"GROUP_CAPACITY",
  @"GROUP_PRIMARY_MISMATCH", @"GROUP_DUPLICATE", @"IDENTITY_CHANGED", @"GROUPS_CHANGED", @"OWNED_GID_OBSERVED", @"READER_UNSPECIFIED", @"GROUP_COUNT_INVALID",
  @"SYSTEM_GROUP_CAPACITY_UNAVAILABLE", @"SYSTEM_GROUP_CAPACITY_MISMATCH"];
}
static NSArray *EG832ErrnoNames(void) { return @[@"NONE", @"ESRCH", @"ENOENT", @"EPERM", @"EACCES", @"EINVAL", @"ENOMEM", @"EIO", @"OTHER"]; }
static NSString *EG832ErrnoClass(int value) {
 switch (value) { case 0: return @"NONE"; case ESRCH: return @"ESRCH"; case ENOENT: return @"ENOENT";
  case EPERM: return @"EPERM"; case EACCES: return @"EACCES"; case EINVAL: return @"EINVAL";
  case ENOMEM: return @"ENOMEM"; case EIO: return @"EIO"; default: return @"OTHER"; }
}
static void EG832FailureSet(EG832Result *r, EG832Failure failure) { r->diagnostic.failure = failure; }
static void EG832ReaderFailure(const EG832Readers *readers, EG832Result *r, EG832Failure fallback) {
 EG832ReaderDiagnostic diagnostic = {0}; if (readers->diagnostic) readers->diagnostic(readers->context, &diagnostic);
 if (diagnostic.failure < EG832_FAILURE_NONE || diagnostic.failure > EG832_FAILURE_CAPACITY_MISMATCH) diagnostic.failure = EG832_FAILURE_UNSPECIFIED;
 if (diagnostic.failure == EG832_FAILURE_NONE) diagnostic.failure = fallback;
 r->diagnostic = diagnostic;
}

static NSDictionary *EG832Report(EG832Result r) {
 return @{@"schema": @"envara.macos-pf-gid-proof/v1", @"readOnly": @YES,
  @"cleanupConfirmed": @NO, @"productionReady": @NO,
  @"recordIdentityVerified": @((BOOL)r.record), @"rootCallerVerified": @((BOOL)r.root),
  @"groupLookupComplete": @((BOOL)r.lookupsComplete), @"groupsAbsent": @((BOOL)r.groupsAbsent),
  @"processEnumerationComplete": @((BOOL)r.enumerationComplete),
  @"processIdentitiesStable": @((BOOL)r.identitiesStable),
  @"supplementaryGroupsCovered": @((BOOL)r.supplementaryCovered),
  @"groupCapacityVerified": @((BOOL)r.capacityVerified), @"runtimeGroupCapacity": @(r.runtimeCapacity),
  @"snapshotStable": @((BOOL)r.snapshotStable), @"allOwnedGIDProcessesAbsent": @((BOOL)r.absent),
  @"realmCount": @(r.realmCount), @"groupLookups": @(r.groupLookups),
  @"snapshotPIDCount": @(r.snapshotPIDCount), @"inspectedProcessCount": @(r.inspected),
  @"matchingProcessCount": @(r.matching), @"unreadableProcessCount": @(r.unreadable),
  @"unstableProcessCount": @(r.unstable), @"attemptCount": @(r.attempts),
  @"zombieCredentialChecks": @(r.zombieChecks),
  @"scanRound": @(r.scanRound),
  @"diagnosticStage": (unsigned)r.stage < EG832StageNames().count ? EG832StageNames()[r.stage] : @"NOT_STARTED",
  @"readerFailure": (unsigned)r.diagnostic.failure < EG832FailureNames().count ? EG832FailureNames()[r.diagnostic.failure] : @"READER_UNSPECIFIED",
  @"errnoClass": EG832ErrnoClass(r.diagnostic.error), @"sdkGroupCapacity": @(NGROUPS),
  @"readerExpectedByteCount": r.diagnostic.expectedBytes <= 16384 ? @(r.diagnostic.expectedBytes) : NSNull.null,
  @"readerReturnedByteCount": r.diagnostic.bytesAvailable && r.diagnostic.returnedBytes <= 16384 ? @(r.diagnostic.returnedBytes) : NSNull.null,
  @"observedGroupCount": r.diagnostic.groupsAvailable && r.diagnostic.observedGroups <= 65536 ? @(r.diagnostic.observedGroups) : NSNull.null,
  @"reason": r.absent ? @"READ_ONLY_FIXED_GID_PROOF" : @"FIXED_GID_PROOF_REFUSED"};
}

static BOOL EG832UUID(id value) {
 if (![value isKindOfClass:NSString.class] || [value length] != 36) return NO;
 NSString *pattern = @"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
 return (BOOL)([value rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound);
}

static BOOL EG832Record(NSDictionary *record, gid_t owned[2]) {
 if (![record isKindOfClass:NSDictionary.class] ||
  ![record[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"] ||
  ![record[@"runId"] isEqual:@"3f419119-19e1-46d5-847e-fcd2d1ec1ed1"] ||
  ![record[@"anchor"] isEqual:@"io.envara.pf.run.3f419119-19e1-46d5-847e-fcd2d1ec1ed1"] ||
  ![record[@"incompleteGroupAllocations"] isKindOfClass:NSArray.class] ||
  [record[@"incompleteGroupAllocations"] count] != 0 ||
  ![record[@"realms"] isKindOfClass:NSArray.class] || [record[@"realms"] count] != 2) return NO;
 NSMutableSet *ids = [NSMutableSet set];
 for (NSUInteger i = 0; i < 2; i++) {
  NSDictionary *realm = record[@"realms"][i];
  if (![realm isKindOfClass:NSDictionary.class] || !EG832UUID(realm[@"realmId"]) ||
   [ids containsObject:realm[@"realmId"]]) return NO;
  [ids addObject:realm[@"realmId"]];
  id value = realm[@"gid"];
  if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
   [value doubleValue] != [value longLongValue] || [value longLongValue] < 7100 || [value longLongValue] > 7999) return NO;
  owned[i] = (gid_t)[value unsignedIntValue];
  if ((i && owned[0] == owned[1]) ||
   ![realm[@"groupPath"] isEqual:[NSString stringWithFormat:@"/Groups/_envara_pf_%u", owned[i]]]) return NO;
 }
 return YES;
}

static BOOL EG832CredentialShape(const EG832Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0 || !c->seconds || c->microseconds >= 1000000) return NO;
 if (!groups) return YES;
 /* The fixed SDK array is complete only with the separately required
  * kern.ngroups == NGROUPS attestation. All NGROUPS slots are inspected. */
 if (c->groupCount < 1 || c->groupCount > NGROUPS || c->groups[0] != c->effectiveGID) return NO;
 for (unsigned i = 0; i < c->groupCount; i++)
  for (unsigned j = 0; j < i; j++) if (c->groups[i] == c->groups[j]) return NO;
 return YES;
}

static BOOL EG832SameIdentity(const EG832Credentials *a, const EG832Credentials *b) {
 return (BOOL)(a->pid == b->pid && a->seconds == b->seconds && a->microseconds == b->microseconds &&
  a->effectiveUID == b->effectiveUID && a->realUID == b->realUID && a->savedUID == b->savedUID &&
  a->effectiveGID == b->effectiveGID && a->realGID == b->realGID && a->savedGID == b->savedGID);
}

static BOOL EG832SameGroups(const EG832Credentials *a, const EG832Credentials *b) {
 return (BOOL)(a->groupCount == b->groupCount &&
  !memcmp(a->groups, b->groups, a->groupCount * sizeof(gid_t)));
}

static BOOL EG832OwnedCredentials(const EG832Credentials *c, const gid_t owned[2]) {
 for (unsigned n = 0; n < 2; n++) {
  if (c->effectiveGID == owned[n] || c->realGID == owned[n] || c->savedGID == owned[n]) return YES;
  for (unsigned i = 0; i < c->groupCount; i++) if (c->groups[i] == owned[n]) return YES;
 }
 return NO;
}

static int EG832PIDCompare(const void *a, const void *b) {
 pid_t pa = *(const pid_t *)a, pb = *(const pid_t *)b;
 return pa < pb ? -1 : pa > pb ? 1 : 0;
}

static BOOL EG832BeforeDeadline(const EG832Readers *readers, double deadline) {
 double now = readers->clock(readers->context);
 return (BOOL)(isfinite(now) && now >= 0 && now < deadline);
}

static int EG832ReadList(const EG832Readers *readers, pid_t *pids, double deadline, EG832Result *r) {
 if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); return -1; }
 int size = readers->list(readers->context, pids, EG832_PID_LIMIT);
 if (size <= 0) { EG832ReaderFailure(readers, r, EG832_FAILURE_LIST_UNREADABLE); return -1; }
 if (size >= EG832_PID_LIMIT) { EG832FailureSet(r, EG832_FAILURE_LIST_CAPACITY); return -1; }
 if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); return -1; }
 size_t positive = 0;
 for (int i = 0; i < size; i++) {
  if (pids[i] < 0) { EG832FailureSet(r, EG832_FAILURE_LIST_INVALID); return -1; }
  if (pids[i] > 0) pids[positive++] = pids[i];
 }
 if (!positive) { EG832FailureSet(r, EG832_FAILURE_LIST_EMPTY); return -1; }
 qsort(pids, positive, sizeof(pid_t), EG832PIDCompare);
 for (size_t i = 1; i < positive; i++) if (pids[i] == pids[i - 1]) { EG832FailureSet(r, EG832_FAILURE_LIST_DUPLICATE); return -1; }
 return (int)positive;
}

static int EG832CheckGroups(const EG832Readers *readers, const gid_t owned[2],
 double deadline, EG832Result *r) {
 BOOL absent = YES, complete = YES;
 for (unsigned i = 0; i < 2; i++) {
  if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); complete = NO; break; }
  int byGID = readers->groupByGID(readers->context, owned[i]); r->groupLookups++;
  if (byGID < 0 || byGID > 1) EG832ReaderFailure(readers, r, EG832_FAILURE_GROUP_UNKNOWN);
  NSString *name = [NSString stringWithFormat:@"_envara_pf_%u", owned[i]];
  if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); complete = NO; break; }
  int byName = readers->groupByName(readers->context, name.UTF8String); r->groupLookups++;
  if (byName < 0 || byName > 1) EG832ReaderFailure(readers, r, EG832_FAILURE_GROUP_UNKNOWN);
  BOOL beforeDeadline = EG832BeforeDeadline(readers, deadline);
  if (!beforeDeadline) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); complete = NO; }
  if (byGID < 0 || byGID > 1 || byName < 0 || byName > 1) complete = NO;
  if (byGID != 0 || byName != 0) absent = NO;
 }
 r->lookupsComplete = complete; r->groupsAbsent = (BOOL)(complete && absent);
 if (complete && !absent) EG832FailureSet(r, EG832_FAILURE_GROUP_PRESENT);
 return !complete ? -1 : absent ? 0 : 1;
}

/* A libproc/sysctl pair is bracketed by another libproc read. Both credentials
 * and birth must agree; this rejects PID reuse or credential mutation between
 * the two public SDK interfaces rather than treating a matching PID as proof.
 * Zombies receive the same complete checks; they are never skipped. */
static EG832Failure EG832ShapeFailure(const EG832Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0) return EG832_FAILURE_PID;
 if (!c->seconds || c->microseconds >= 1000000) return EG832_FAILURE_BIRTH;
 if (groups) {
  if (!c->groupCount) return EG832_FAILURE_GROUP_EMPTY;
  if (c->groupCount > NGROUPS) return EG832_FAILURE_GROUP_CAPACITY;
  if (c->groups[0] != c->effectiveGID) return EG832_FAILURE_GROUP_PRIMARY;
  return EG832_FAILURE_GROUP_DUPLICATE;
 }
 return EG832_FAILURE_UNSPECIFIED;
}
static int EG832ReadCredentials(const EG832Readers *readers, pid_t pid,
 const gid_t owned[2], double deadline, EG832Credentials *out, EG832Result *r) {
 EG832Credentials a = {0}, supplemental = {0}, b = {0};
 r->stage = EG832_STAGE_BSD_FIRST;
 if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); r->unreadable++; return -1; }
 int status = readers->bsd(readers->context, pid, &a); EG832ReaderFailure(readers, r, status ? EG832_FAILURE_UNSPECIFIED : EG832_FAILURE_NONE);
 if (status || !EG832CredentialShape(&a, pid, NO)) { if (!status) EG832FailureSet(r, EG832ShapeFailure(&a, pid, NO)); r->unreadable++; return -1; }
 if (EG832OwnedCredentials(&a, owned)) { EG832FailureSet(r, EG832_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG832_STAGE_SUPPLEMENTARY;
 if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 status = readers->supplementary(readers->context, pid, &supplemental); EG832ReaderFailure(readers, r, status ? EG832_FAILURE_UNSPECIFIED : EG832_FAILURE_NONE);
 if (status || !EG832CredentialShape(&supplemental, pid, YES)) { if (!status) EG832FailureSet(r, EG832ShapeFailure(&supplemental, pid, YES)); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 if (EG832OwnedCredentials(&supplemental, owned)) { EG832FailureSet(r, EG832_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG832_STAGE_BSD_FINAL;
 if (!EG832BeforeDeadline(readers, deadline)) { EG832FailureSet(r, EG832_FAILURE_DEADLINE); r->unreadable++; return -1; }
 status = readers->bsd(readers->context, pid, &b); EG832ReaderFailure(readers, r, status ? EG832_FAILURE_UNSPECIFIED : EG832_FAILURE_NONE);
 if (status || !EG832CredentialShape(&b, pid, NO) || !EG832BeforeDeadline(readers, deadline)) {
  if (!status) EG832FailureSet(r, !EG832CredentialShape(&b, pid, NO) ? EG832ShapeFailure(&b, pid, NO) : EG832_FAILURE_DEADLINE);
  r->unreadable++; return -1;
 }
 if (EG832OwnedCredentials(&b, owned)) { EG832FailureSet(r, EG832_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG832_STAGE_BINDING;
 if (!EG832SameIdentity(&a, &supplemental) || !EG832SameIdentity(&supplemental, &b)) {
  EG832FailureSet(r, EG832_FAILURE_IDENTITY); r->unstable++; r->supplementaryCovered = NO; return -1;
 }
 if (a.status == SZOMB && supplemental.status == SZOMB && b.status == SZOMB) r->zombieChecks++;
 *out = supplemental; r->inspected++; return 0;
}

static NSDictionary *EG832Inspect(NSDictionary *record, const EG832Readers *readers) {
 EG832Result result = {0}; gid_t owned[2] = {0};
 result.stage = EG832_STAGE_RECORD; EG832FailureSet(&result, EG832_FAILURE_RECORD);
 result.record = EG832Record(record, owned); result.realmCount = result.record ? 2 : 0;
 if (!result.record) return EG832Report(result);
 result.stage = EG832_STAGE_READERS; EG832FailureSet(&result, EG832_FAILURE_READERS);
 if (!readers || !readers->root || !readers->list || !readers->bsd ||
  !readers->supplementary || !readers->groupByGID || !readers->groupByName || !readers->clock) return EG832Report(result);
 result.stage = EG832_STAGE_ROOT; EG832FailureSet(&result, EG832_FAILURE_NOT_ROOT);
 result.root = readers->root(readers->context); if (!result.root) return EG832Report(result);
 result.stage = EG832_STAGE_CAPACITY; EG832FailureSet(&result, EG832_FAILURE_CAPACITY_UNAVAILABLE);
 if (!readers->capacity) return EG832Report(result);
 unsigned runtimeCapacity = 0; int capacityStatus = readers->capacity(readers->context, &runtimeCapacity);
 result.runtimeCapacity = runtimeCapacity <= 65536 ? runtimeCapacity : 0;
 if (capacityStatus) { EG832ReaderFailure(readers, &result, EG832_FAILURE_CAPACITY_UNAVAILABLE); return EG832Report(result); }
 if (runtimeCapacity != NGROUPS) { EG832ReaderFailure(readers, &result, EG832_FAILURE_CAPACITY_MISMATCH); return EG832Report(result); }
 result.capacityVerified = YES;
 result.stage = EG832_STAGE_CLOCK; EG832FailureSet(&result, EG832_FAILURE_CLOCK);
 double now = readers->clock(readers->context);
 if (!isfinite(now) || now < 0) return EG832Report(result);
 double deadline = now + EG832_DEADLINE_SECONDS;
 result.stage = EG832_STAGE_ALLOCATION; EG832FailureSet(&result, EG832_FAILURE_ALLOCATION);
 pid_t *first = calloc(EG832_PID_LIMIT, sizeof(pid_t)), *second = calloc(EG832_PID_LIMIT, sizeof(pid_t));
 EG832Credentials *baseline = calloc(EG832_PID_LIMIT, sizeof(EG832Credentials));
 if (!first || !second || !baseline) { free(first); free(second); free(baseline); return EG832Report(result); }
 for (unsigned attempt = 1; attempt <= EG832_ATTEMPTS && EG832BeforeDeadline(readers, deadline); attempt++) {
  EG832Result r = {0}; r.record = YES; r.root = YES; r.realmCount = 2; r.attempts = attempt; r.stage = EG832_STAGE_GROUPS;
  r.capacityVerified = result.capacityVerified; r.runtimeCapacity = result.runtimeCapacity;
  int groupStatus = EG832CheckGroups(readers, owned, deadline, &r);
  if (groupStatus != 0) { result = r; if (groupStatus > 0) break; continue; }
  r.stage = EG832_STAGE_LIST_FIRST;
  int n = EG832ReadList(readers, first, deadline, &r);
  if (n < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.snapshotPIDCount = (NSUInteger)n;
  BOOL failed = NO, found = NO; r.scanRound = 1;
  for (int i = 0; i < n; i++) {
   int status = EG832ReadCredentials(readers, first[i], owned, deadline, &baseline[i], &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.stage = EG832_STAGE_LIST_SECOND;
  int m = EG832ReadList(readers, second, deadline, &r);
  if (m < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.enumerationComplete = YES;
  if (m != n || memcmp(first, second, (size_t)n * sizeof(pid_t))) { EG832FailureSet(&r, EG832_FAILURE_LIST_CHANGED); r.unstable++; result = r; continue; }
  r.scanRound = 2;
  for (int i = 0; i < n; i++) {
   EG832Credentials observed = {0};
   int status = EG832ReadCredentials(readers, second[i], owned, deadline, &observed, &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
   if (!EG832SameIdentity(&baseline[i], &observed) || !EG832SameGroups(&baseline[i], &observed)) {
    r.stage = !EG832SameIdentity(&baseline[i], &observed) ? EG832_STAGE_SECOND_IDENTITY : EG832_STAGE_SECOND_GROUPS;
    EG832FailureSet(&r, r.stage == EG832_STAGE_SECOND_IDENTITY ? EG832_FAILURE_IDENTITY : EG832_FAILURE_GROUPS_CHANGED);
    r.unstable++; failed = YES; break;
   }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.identitiesStable = YES; r.supplementaryCovered = YES; r.snapshotStable = YES;
  r.stage = EG832_STAGE_GROUPS_FINAL;
  groupStatus = EG832CheckGroups(readers, owned, deadline, &r);
  r.absent = (BOOL)(groupStatus == 0 && r.record && r.root && r.capacityVerified && r.runtimeCapacity == NGROUPS && r.lookupsComplete && r.groupsAbsent &&
   r.enumerationComplete && r.identitiesStable && r.supplementaryCovered && r.snapshotStable &&
   !r.matching && !r.unreadable && !r.unstable && EG832BeforeDeadline(readers, deadline));
  if (r.absent) { r.stage = EG832_STAGE_COMPLETE; EG832FailureSet(&r, EG832_FAILURE_NONE); }
  else if (r.diagnostic.failure == EG832_FAILURE_NONE) EG832FailureSet(&r, EG832_FAILURE_DEADLINE);
  result = r; if (r.absent || groupStatus > 0) break;
 }
 free(first); free(second); free(baseline); return EG832Report(result);
}

static BOOL EG832NativeRoot(void *context) { (void)context; return (BOOL)(getuid() == 0 && geteuid() == 0); }
static double EG832NativeClock(void *context) {
 (void)context; struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
 return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static int EG832DecodeCapacity(int status, size_t bytes, int capacity, int nativeError,
 unsigned *out, EG832ReaderDiagnostic *diagnostic) {
 EG832ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG832ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(int); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status || bytes != sizeof(int) || capacity < 1 || capacity > 65536) {
  diagnostic->failure = EG832_FAILURE_CAPACITY_UNAVAILABLE; diagnostic->error = status ? nativeError : 0; return -1;
 }
 *out = (unsigned)capacity;
 if (capacity != NGROUPS) { diagnostic->failure = EG832_FAILURE_CAPACITY_MISMATCH; return -1; }
 return 0;
}
static int EG832NativeCapacity(void *context, unsigned *out) {
 int capacity = 0; size_t bytes = sizeof(capacity); errno = 0;
 int status = sysctlbyname("kern.ngroups", &capacity, &bytes, NULL, 0); int error = errno;
 return EG832DecodeCapacity(status, bytes, capacity, error, out, context);
}
/* Production conversion logic is pure so inert fixtures can exercise real
 * SDK sizes/boundaries without running either public native reader. */
static int EG832DecodeBSD(const struct proc_bsdinfo *info, int bytes, int nativeError,
 EG832Credentials *out, EG832ReaderDiagnostic *diagnostic) {
 EG832ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG832ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(bytes >= 0);
 diagnostic->returnedBytes = bytes >= 0 ? (size_t)bytes : 0;
 if (bytes != sizeof(*info)) { diagnostic->failure = bytes < 0 || (!bytes && nativeError) ? EG832_FAILURE_BSD_ERROR : EG832_FAILURE_BSD_SIZE;
  diagnostic->error = nativeError; return -1; }
 *out = (EG832Credentials){.pid = (pid_t)info->pbi_pid, .status = info->pbi_status, .seconds = info->pbi_start_tvsec,
  .microseconds = info->pbi_start_tvusec, .effectiveUID = info->pbi_uid, .realUID = info->pbi_ruid,
  .savedUID = info->pbi_svuid, .effectiveGID = info->pbi_gid, .realGID = info->pbi_rgid, .savedGID = info->pbi_svgid};
 return 0;
}
static int EG832DecodeSupplementary(const struct kinfo_proc *info, int status, size_t bytes, int nativeError,
 EG832Credentials *out, EG832ReaderDiagnostic *diagnostic) {
 EG832ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG832ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status) { diagnostic->failure = EG832_FAILURE_SYSCTL_ERROR; diagnostic->error = nativeError; return -1; }
 if (bytes != sizeof(*info)) { diagnostic->failure = EG832_FAILURE_SYSCTL_SIZE; return -1; }
 int groups = info->kp_eproc.e_ucred.cr_ngroups;
 diagnostic->groupsAvailable = (BOOL)(groups >= 0); diagnostic->observedGroups = groups >= 0 ? (unsigned)groups : 0;
 if (info->kp_proc.p_starttime.tv_sec <= 0 || info->kp_proc.p_starttime.tv_usec < 0 || info->kp_proc.p_starttime.tv_usec >= 1000000) {
  diagnostic->failure = EG832_FAILURE_BIRTH; return -1; }
 if (groups < 1 || groups > NGROUPS) { diagnostic->failure = groups < 0 ? EG832_FAILURE_GROUP_COUNT : !groups ? EG832_FAILURE_GROUP_EMPTY : EG832_FAILURE_GROUP_CAPACITY; return -1; }
 *out = (EG832Credentials){.pid = info->kp_proc.p_pid, .status = (unsigned char)info->kp_proc.p_stat, .seconds = (uint64_t)info->kp_proc.p_starttime.tv_sec,
  .microseconds = (uint64_t)info->kp_proc.p_starttime.tv_usec, .effectiveUID = info->kp_eproc.e_ucred.cr_uid,
  .realUID = info->kp_eproc.e_pcred.p_ruid, .savedUID = info->kp_eproc.e_pcred.p_svuid,
  .effectiveGID = info->kp_eproc.e_ucred.cr_groups[0], .realGID = info->kp_eproc.e_pcred.p_rgid,
  .savedGID = info->kp_eproc.e_pcred.p_svgid, .groupCount = (unsigned)groups};
 memcpy(out->groups, info->kp_eproc.e_ucred.cr_groups, out->groupCount * sizeof(gid_t)); return 0;
}
static void EG832NativeDiagnostic(void *context, EG832ReaderDiagnostic *out) {
 *out = context ? *(EG832ReaderDiagnostic *)context : (EG832ReaderDiagnostic){.failure = EG832_FAILURE_UNSPECIFIED};
}
static int EG832NativeList(void *context, pid_t *pids, size_t capacity) {
 EG832ReaderDiagnostic *diagnostic = context; if (diagnostic) *diagnostic = (EG832ReaderDiagnostic){0};
 if (capacity != EG832_PID_LIMIT || capacity * sizeof(pid_t) > INT_MAX) { if (diagnostic) diagnostic->failure = EG832_FAILURE_LIST_CAPACITY; return -1; }
 errno = 0;
 int estimate = proc_listallpids(NULL, 0);
 int error = errno;
 if (estimate <= 0 || estimate >= (int)capacity) { if (diagnostic) *diagnostic = (EG832ReaderDiagnostic){.failure = estimate >= (int)capacity ? EG832_FAILURE_LIST_CAPACITY : EG832_FAILURE_LIST_UNREADABLE, .error = error}; return -1; }
 errno = 0;
 int count = proc_listallpids(pids, (int)(capacity * sizeof(pid_t)));
 error = errno;
 if (diagnostic && (count <= 0 || count >= (int)capacity)) *diagnostic = (EG832ReaderDiagnostic){.failure = count >= (int)capacity ? EG832_FAILURE_LIST_CAPACITY : EG832_FAILURE_LIST_UNREADABLE, .error = error};
 return count > 0 && count < (int)capacity ? count : -1;
}
typedef int (*EG832BSDSystemCall)(int, int, uint64_t, void *, int);
static int EG832ReadBSDIncludingZombies(pid_t pid, EG832Credentials *out,
 EG832ReaderDiagnostic *diagnostic, EG832BSDSystemCall reader) {
 if (!reader) { if (diagnostic) *diagnostic = (EG832ReaderDiagnostic){.failure = EG832_FAILURE_UNSPECIFIED}; return -1; }
 struct proc_bsdinfo info = {0}; errno = 0;
 /* Apple XNU proc_info.c: PROC_PIDTBSDINFO arg != 0 enables proc_find_zombref.
  * Full UID/GID/birth data still comes from proc_pidbsdinfo. An ESRCH response
  * remains unknown and refuses the scan; neither dead nor zombie PIDs skip it.
  * Pinned evidence: f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, lines 2046-2061. */
 int bytes = reader(pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)); int error = errno;
 return EG832DecodeBSD(&info, bytes, error, out, diagnostic);
}
static int EG832NativeBSD(void *context, pid_t pid, EG832Credentials *out) {
 return EG832ReadBSDIncludingZombies(pid, out, context, proc_pidinfo);
}
static int EG832NativeSupplementary(void *context, pid_t pid, EG832Credentials *out) {
 int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
 struct kinfo_proc info = {0}; size_t size = sizeof(info);
 errno = 0; int status = sysctl(mib, 4, &info, &size, NULL, 0); int error = errno;
 return EG832DecodeSupplementary(&info, status, size, error, out, context);
}
static int EG832NativeGroupByGID(void *context, gid_t gid) {
 errno = 0; struct group *entry = getgrgid(gid); int error = errno;
 if (context) *(EG832ReaderDiagnostic *)context = (EG832ReaderDiagnostic){.failure = !entry && error ? EG832_FAILURE_GROUP_UNKNOWN : EG832_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}
static int EG832NativeGroupByName(void *context, const char *name) {
 errno = 0; struct group *entry = getgrnam(name); int error = errno;
 if (context) *(EG832ReaderDiagnostic *)context = (EG832ReaderDiagnostic){.failure = !entry && error ? EG832_FAILURE_GROUP_UNKNOWN : EG832_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}

static NSDictionary *EnvaraInspectGIDProof832(NSDictionary *sealedRecord) {
 EG832ReaderDiagnostic diagnostic = {0};
 const EG832Readers readers = {.context = &diagnostic, .root = EG832NativeRoot, .list = EG832NativeList,
  .bsd = EG832NativeBSD, .supplementary = EG832NativeSupplementary,
  .groupByGID = EG832NativeGroupByGID, .groupByName = EG832NativeGroupByName, .clock = EG832NativeClock,
  .capacity = EG832NativeCapacity, .diagnostic = EG832NativeDiagnostic};
 return EG832Inspect(sealedRecord, &readers);
}

#ifdef ENVARA_GID_PROOF_832_INERT_TEST
static NSDictionary *EnvaraInspectGIDProof832ForTest(NSDictionary *record, const EG832Readers *readers) {
 return EG832Inspect(record, readers);
}
#endif
#endif
