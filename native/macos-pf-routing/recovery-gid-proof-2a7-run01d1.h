#ifndef ENVARA_RECOVERY_GID_PROOF_2A7_H
#define ENVARA_RECOVERY_GID_PROOF_2A7_H

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

#define EG2A7_PID_LIMIT 16384
#define EG2A7_ATTEMPTS 3
#define EG2A7_DEADLINE_SECONDS 15.0

typedef struct {
 pid_t pid;
 unsigned status;
 uint64_t seconds, microseconds;
 uid_t effectiveUID, realUID, savedUID;
 gid_t effectiveGID, realGID, savedGID;
 unsigned groupCount;
 gid_t groups[NGROUPS];
} EG2A7Credentials;

typedef enum { EG2A7_STAGE_NOT_STARTED, EG2A7_STAGE_RECORD, EG2A7_STAGE_READERS, EG2A7_STAGE_ROOT,
 EG2A7_STAGE_CLOCK, EG2A7_STAGE_ALLOCATION, EG2A7_STAGE_GROUPS, EG2A7_STAGE_LIST_FIRST,
 EG2A7_STAGE_BSD_FIRST, EG2A7_STAGE_SUPPLEMENTARY, EG2A7_STAGE_BSD_FINAL, EG2A7_STAGE_BINDING,
 EG2A7_STAGE_LIST_SECOND, EG2A7_STAGE_SECOND_IDENTITY, EG2A7_STAGE_SECOND_GROUPS,
 EG2A7_STAGE_GROUPS_FINAL, EG2A7_STAGE_COMPLETE, EG2A7_STAGE_CAPACITY } EG2A7Stage;
typedef enum { EG2A7_FAILURE_NONE, EG2A7_FAILURE_RECORD, EG2A7_FAILURE_READERS, EG2A7_FAILURE_NOT_ROOT,
 EG2A7_FAILURE_CLOCK, EG2A7_FAILURE_ALLOCATION, EG2A7_FAILURE_DEADLINE, EG2A7_FAILURE_GROUP_UNKNOWN,
 EG2A7_FAILURE_GROUP_PRESENT, EG2A7_FAILURE_LIST_UNREADABLE, EG2A7_FAILURE_LIST_CAPACITY,
 EG2A7_FAILURE_LIST_INVALID, EG2A7_FAILURE_LIST_EMPTY, EG2A7_FAILURE_LIST_DUPLICATE, EG2A7_FAILURE_LIST_CHANGED,
 EG2A7_FAILURE_BSD_ERROR, EG2A7_FAILURE_BSD_SIZE, EG2A7_FAILURE_SYSCTL_ERROR, EG2A7_FAILURE_SYSCTL_SIZE,
 EG2A7_FAILURE_PID, EG2A7_FAILURE_BIRTH, EG2A7_FAILURE_GROUP_EMPTY, EG2A7_FAILURE_GROUP_CAPACITY,
 EG2A7_FAILURE_GROUP_PRIMARY, EG2A7_FAILURE_GROUP_DUPLICATE, EG2A7_FAILURE_IDENTITY,
 EG2A7_FAILURE_GROUPS_CHANGED, EG2A7_FAILURE_OWNED, EG2A7_FAILURE_UNSPECIFIED, EG2A7_FAILURE_GROUP_COUNT,
 EG2A7_FAILURE_CAPACITY_UNAVAILABLE, EG2A7_FAILURE_CAPACITY_MISMATCH } EG2A7Failure;
typedef struct {
 EG2A7Failure failure; int error;
 size_t expectedBytes, returnedBytes; BOOL bytesAvailable;
 unsigned observedGroups; BOOL groupsAvailable;
} EG2A7ReaderDiagnostic;

typedef struct {
 void *context;
 BOOL (*root)(void *);
 int (*list)(void *, pid_t *, size_t);
 int (*bsd)(void *, pid_t, EG2A7Credentials *);
 int (*supplementary)(void *, pid_t, EG2A7Credentials *);
 /* 0 absent, 1 present, -1 unknown. Presence in either namespace refuses. */
 int (*groupByGID)(void *, gid_t);
 int (*groupByName)(void *, const char *);
 double (*clock)(void *);
 /* Mandatory system/SDK capacity attestation before any process snapshot. */
 int (*capacity)(void *, unsigned *);
 /* Optional metadata only; absence never changes a failed reader into proof. */
 void (*diagnostic)(void *, EG2A7ReaderDiagnostic *);
} EG2A7Readers;

typedef struct {
 BOOL record, root, lookupsComplete, groupsAbsent, enumerationComplete;
 BOOL identitiesStable, supplementaryCovered, snapshotStable, absent;
 BOOL capacityVerified;
 NSUInteger runtimeCapacity;
 NSUInteger realmCount, groupLookups, snapshotPIDCount, inspected;
 NSUInteger matching, unreadable, unstable, attempts;
 NSUInteger zombieChecks;
 NSUInteger scanRound;
 EG2A7Stage stage; EG2A7ReaderDiagnostic diagnostic;
} EG2A7Result;

static NSArray *EG2A7StageNames(void) {
 return @[@"NOT_STARTED", @"RECORD", @"READER_CONTRACT", @"ROOT_CALLER", @"CLOCK", @"ALLOCATION", @"GROUP_LOOKUPS",
  @"PID_LIST_FIRST", @"BSD_FIRST", @"SYSCTL_SUPPLEMENTARY", @"BSD_FINAL", @"CROSS_INTERFACE_IDENTITY",
  @"PID_LIST_SECOND", @"SECOND_SNAPSHOT_IDENTITY", @"SECOND_SNAPSHOT_GROUPS", @"FINAL_GROUP_LOOKUPS", @"COMPLETE", @"GROUP_CAPACITY_ATTESTATION"];
}
static NSArray *EG2A7FailureNames(void) {
 return @[@"NONE", @"INVALID_RECORD", @"READER_CONTRACT", @"NOT_ROOT", @"CLOCK_INVALID", @"ALLOCATION_FAILED", @"DEADLINE",
  @"GROUP_LOOKUP_UNKNOWN", @"GROUP_PRESENT", @"PID_LIST_UNREADABLE", @"PID_LIST_CAPACITY", @"PID_LIST_INVALID",
  @"PID_LIST_EMPTY", @"PID_LIST_DUPLICATE", @"PID_LIST_CHANGED", @"PROC_PIDINFO_ERROR", @"PROC_PIDINFO_SIZE_MISMATCH",
  @"SYSCTL_ERROR", @"SYSCTL_SIZE_MISMATCH", @"CREDENTIAL_PID_INVALID", @"BIRTH_INVALID", @"GROUP_EMPTY", @"GROUP_CAPACITY",
  @"GROUP_PRIMARY_MISMATCH", @"GROUP_DUPLICATE", @"IDENTITY_CHANGED", @"GROUPS_CHANGED", @"OWNED_GID_OBSERVED", @"READER_UNSPECIFIED", @"GROUP_COUNT_INVALID",
  @"SYSTEM_GROUP_CAPACITY_UNAVAILABLE", @"SYSTEM_GROUP_CAPACITY_MISMATCH"];
}
static NSArray *EG2A7ErrnoNames(void) { return @[@"NONE", @"ESRCH", @"ENOENT", @"EPERM", @"EACCES", @"EINVAL", @"ENOMEM", @"EIO", @"OTHER"]; }
static NSString *EG2A7ErrnoClass(int value) {
 switch (value) { case 0: return @"NONE"; case ESRCH: return @"ESRCH"; case ENOENT: return @"ENOENT";
  case EPERM: return @"EPERM"; case EACCES: return @"EACCES"; case EINVAL: return @"EINVAL";
  case ENOMEM: return @"ENOMEM"; case EIO: return @"EIO"; default: return @"OTHER"; }
}
static void EG2A7FailureSet(EG2A7Result *r, EG2A7Failure failure) { r->diagnostic.failure = failure; }
static void EG2A7ReaderFailure(const EG2A7Readers *readers, EG2A7Result *r, EG2A7Failure fallback) {
 EG2A7ReaderDiagnostic diagnostic = {0}; if (readers->diagnostic) readers->diagnostic(readers->context, &diagnostic);
 if (diagnostic.failure < EG2A7_FAILURE_NONE || diagnostic.failure > EG2A7_FAILURE_CAPACITY_MISMATCH) diagnostic.failure = EG2A7_FAILURE_UNSPECIFIED;
 if (diagnostic.failure == EG2A7_FAILURE_NONE) diagnostic.failure = fallback;
 r->diagnostic = diagnostic;
}

static NSDictionary *EG2A7Report(EG2A7Result r) {
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
  @"diagnosticStage": (unsigned)r.stage < EG2A7StageNames().count ? EG2A7StageNames()[r.stage] : @"NOT_STARTED",
  @"readerFailure": (unsigned)r.diagnostic.failure < EG2A7FailureNames().count ? EG2A7FailureNames()[r.diagnostic.failure] : @"READER_UNSPECIFIED",
  @"errnoClass": EG2A7ErrnoClass(r.diagnostic.error), @"sdkGroupCapacity": @(NGROUPS),
  @"readerExpectedByteCount": r.diagnostic.expectedBytes <= 16384 ? @(r.diagnostic.expectedBytes) : NSNull.null,
  @"readerReturnedByteCount": r.diagnostic.bytesAvailable && r.diagnostic.returnedBytes <= 16384 ? @(r.diagnostic.returnedBytes) : NSNull.null,
  @"observedGroupCount": r.diagnostic.groupsAvailable && r.diagnostic.observedGroups <= 65536 ? @(r.diagnostic.observedGroups) : NSNull.null,
  @"reason": r.absent ? @"READ_ONLY_FIXED_GID_PROOF" : @"FIXED_GID_PROOF_REFUSED"};
}

static BOOL EG2A7UUID(id value) {
 if (![value isKindOfClass:NSString.class] || [value length] != 36) return NO;
 NSString *pattern = @"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
 return (BOOL)([value rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound);
}

static BOOL EG2A7Record(NSDictionary *record, gid_t owned[2]) {
 if (![record isKindOfClass:NSDictionary.class] ||
  ![record[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"] ||
  ![record[@"runId"] isEqual:@"01d1e669-bc58-4a10-ae2d-709e7fedd7f6"] ||
  ![record[@"anchor"] isEqual:@"io.envara.pf.run.01d1e669-bc58-4a10-ae2d-709e7fedd7f6"] ||
  ![record[@"incompleteGroupAllocations"] isKindOfClass:NSArray.class] ||
  [record[@"incompleteGroupAllocations"] count] != 0 ||
  ![record[@"realms"] isKindOfClass:NSArray.class] || [record[@"realms"] count] != 2) return NO;
 NSMutableSet *ids = [NSMutableSet set];
 for (NSUInteger i = 0; i < 2; i++) {
  NSDictionary *realm = record[@"realms"][i];
  if (![realm isKindOfClass:NSDictionary.class] || !EG2A7UUID(realm[@"realmId"]) ||
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

static BOOL EG2A7CredentialShape(const EG2A7Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0 || !c->seconds || c->microseconds >= 1000000) return NO;
 if (!groups) return YES;
 /* The fixed SDK array is complete only with the separately required
  * kern.ngroups == NGROUPS attestation. All NGROUPS slots are inspected. */
 if (c->groupCount < 1 || c->groupCount > NGROUPS || c->groups[0] != c->effectiveGID) return NO;
 for (unsigned i = 0; i < c->groupCount; i++)
  for (unsigned j = 0; j < i; j++) if (c->groups[i] == c->groups[j]) return NO;
 return YES;
}

static BOOL EG2A7SameIdentity(const EG2A7Credentials *a, const EG2A7Credentials *b) {
 return (BOOL)(a->pid == b->pid && a->seconds == b->seconds && a->microseconds == b->microseconds &&
  a->effectiveUID == b->effectiveUID && a->realUID == b->realUID && a->savedUID == b->savedUID &&
  a->effectiveGID == b->effectiveGID && a->realGID == b->realGID && a->savedGID == b->savedGID);
}

static BOOL EG2A7SameGroups(const EG2A7Credentials *a, const EG2A7Credentials *b) {
 return (BOOL)(a->groupCount == b->groupCount &&
  !memcmp(a->groups, b->groups, a->groupCount * sizeof(gid_t)));
}

static BOOL EG2A7OwnedCredentials(const EG2A7Credentials *c, const gid_t owned[2]) {
 for (unsigned n = 0; n < 2; n++) {
  if (c->effectiveGID == owned[n] || c->realGID == owned[n] || c->savedGID == owned[n]) return YES;
  for (unsigned i = 0; i < c->groupCount; i++) if (c->groups[i] == owned[n]) return YES;
 }
 return NO;
}

static int EG2A7PIDCompare(const void *a, const void *b) {
 pid_t pa = *(const pid_t *)a, pb = *(const pid_t *)b;
 return pa < pb ? -1 : pa > pb ? 1 : 0;
}

static BOOL EG2A7BeforeDeadline(const EG2A7Readers *readers, double deadline) {
 double now = readers->clock(readers->context);
 return (BOOL)(isfinite(now) && now >= 0 && now < deadline);
}

static int EG2A7ReadList(const EG2A7Readers *readers, pid_t *pids, double deadline, EG2A7Result *r) {
 if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); return -1; }
 int size = readers->list(readers->context, pids, EG2A7_PID_LIMIT);
 if (size <= 0) { EG2A7ReaderFailure(readers, r, EG2A7_FAILURE_LIST_UNREADABLE); return -1; }
 if (size >= EG2A7_PID_LIMIT) { EG2A7FailureSet(r, EG2A7_FAILURE_LIST_CAPACITY); return -1; }
 if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); return -1; }
 size_t positive = 0;
 for (int i = 0; i < size; i++) {
  if (pids[i] < 0) { EG2A7FailureSet(r, EG2A7_FAILURE_LIST_INVALID); return -1; }
  if (pids[i] > 0) pids[positive++] = pids[i];
 }
 if (!positive) { EG2A7FailureSet(r, EG2A7_FAILURE_LIST_EMPTY); return -1; }
 qsort(pids, positive, sizeof(pid_t), EG2A7PIDCompare);
 for (size_t i = 1; i < positive; i++) if (pids[i] == pids[i - 1]) { EG2A7FailureSet(r, EG2A7_FAILURE_LIST_DUPLICATE); return -1; }
 return (int)positive;
}

static int EG2A7CheckGroups(const EG2A7Readers *readers, const gid_t owned[2],
 double deadline, EG2A7Result *r) {
 BOOL absent = YES, complete = YES;
 for (unsigned i = 0; i < 2; i++) {
  if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); complete = NO; break; }
  int byGID = readers->groupByGID(readers->context, owned[i]); r->groupLookups++;
  if (byGID < 0 || byGID > 1) EG2A7ReaderFailure(readers, r, EG2A7_FAILURE_GROUP_UNKNOWN);
  NSString *name = [NSString stringWithFormat:@"_envara_pf_%u", owned[i]];
  if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); complete = NO; break; }
  int byName = readers->groupByName(readers->context, name.UTF8String); r->groupLookups++;
  if (byName < 0 || byName > 1) EG2A7ReaderFailure(readers, r, EG2A7_FAILURE_GROUP_UNKNOWN);
  BOOL beforeDeadline = EG2A7BeforeDeadline(readers, deadline);
  if (!beforeDeadline) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); complete = NO; }
  if (byGID < 0 || byGID > 1 || byName < 0 || byName > 1) complete = NO;
  if (byGID != 0 || byName != 0) absent = NO;
 }
 r->lookupsComplete = complete; r->groupsAbsent = (BOOL)(complete && absent);
 if (complete && !absent) EG2A7FailureSet(r, EG2A7_FAILURE_GROUP_PRESENT);
 return !complete ? -1 : absent ? 0 : 1;
}

/* A libproc/sysctl pair is bracketed by another libproc read. Both credentials
 * and birth must agree; this rejects PID reuse or credential mutation between
 * the two public SDK interfaces rather than treating a matching PID as proof.
 * Zombies receive the same complete checks; they are never skipped. */
static EG2A7Failure EG2A7ShapeFailure(const EG2A7Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0) return EG2A7_FAILURE_PID;
 if (!c->seconds || c->microseconds >= 1000000) return EG2A7_FAILURE_BIRTH;
 if (groups) {
  if (!c->groupCount) return EG2A7_FAILURE_GROUP_EMPTY;
  if (c->groupCount > NGROUPS) return EG2A7_FAILURE_GROUP_CAPACITY;
  if (c->groups[0] != c->effectiveGID) return EG2A7_FAILURE_GROUP_PRIMARY;
  return EG2A7_FAILURE_GROUP_DUPLICATE;
 }
 return EG2A7_FAILURE_UNSPECIFIED;
}
static int EG2A7ReadCredentials(const EG2A7Readers *readers, pid_t pid,
 const gid_t owned[2], double deadline, EG2A7Credentials *out, EG2A7Result *r) {
 EG2A7Credentials a = {0}, supplemental = {0}, b = {0};
 r->stage = EG2A7_STAGE_BSD_FIRST;
 if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); r->unreadable++; return -1; }
 int status = readers->bsd(readers->context, pid, &a); EG2A7ReaderFailure(readers, r, status ? EG2A7_FAILURE_UNSPECIFIED : EG2A7_FAILURE_NONE);
 if (status || !EG2A7CredentialShape(&a, pid, NO)) { if (!status) EG2A7FailureSet(r, EG2A7ShapeFailure(&a, pid, NO)); r->unreadable++; return -1; }
 if (EG2A7OwnedCredentials(&a, owned)) { EG2A7FailureSet(r, EG2A7_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG2A7_STAGE_SUPPLEMENTARY;
 if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 status = readers->supplementary(readers->context, pid, &supplemental); EG2A7ReaderFailure(readers, r, status ? EG2A7_FAILURE_UNSPECIFIED : EG2A7_FAILURE_NONE);
 if (status || !EG2A7CredentialShape(&supplemental, pid, YES)) { if (!status) EG2A7FailureSet(r, EG2A7ShapeFailure(&supplemental, pid, YES)); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 if (EG2A7OwnedCredentials(&supplemental, owned)) { EG2A7FailureSet(r, EG2A7_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG2A7_STAGE_BSD_FINAL;
 if (!EG2A7BeforeDeadline(readers, deadline)) { EG2A7FailureSet(r, EG2A7_FAILURE_DEADLINE); r->unreadable++; return -1; }
 status = readers->bsd(readers->context, pid, &b); EG2A7ReaderFailure(readers, r, status ? EG2A7_FAILURE_UNSPECIFIED : EG2A7_FAILURE_NONE);
 if (status || !EG2A7CredentialShape(&b, pid, NO) || !EG2A7BeforeDeadline(readers, deadline)) {
  if (!status) EG2A7FailureSet(r, !EG2A7CredentialShape(&b, pid, NO) ? EG2A7ShapeFailure(&b, pid, NO) : EG2A7_FAILURE_DEADLINE);
  r->unreadable++; return -1;
 }
 if (EG2A7OwnedCredentials(&b, owned)) { EG2A7FailureSet(r, EG2A7_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EG2A7_STAGE_BINDING;
 if (!EG2A7SameIdentity(&a, &supplemental) || !EG2A7SameIdentity(&supplemental, &b)) {
  EG2A7FailureSet(r, EG2A7_FAILURE_IDENTITY); r->unstable++; r->supplementaryCovered = NO; return -1;
 }
 if (a.status == SZOMB && supplemental.status == SZOMB && b.status == SZOMB) r->zombieChecks++;
 *out = supplemental; r->inspected++; return 0;
}

static NSDictionary *EG2A7Inspect(NSDictionary *record, const EG2A7Readers *readers) {
 EG2A7Result result = {0}; gid_t owned[2] = {0};
 result.stage = EG2A7_STAGE_RECORD; EG2A7FailureSet(&result, EG2A7_FAILURE_RECORD);
 result.record = EG2A7Record(record, owned); result.realmCount = result.record ? 2 : 0;
 if (!result.record) return EG2A7Report(result);
 result.stage = EG2A7_STAGE_READERS; EG2A7FailureSet(&result, EG2A7_FAILURE_READERS);
 if (!readers || !readers->root || !readers->list || !readers->bsd ||
  !readers->supplementary || !readers->groupByGID || !readers->groupByName || !readers->clock) return EG2A7Report(result);
 result.stage = EG2A7_STAGE_ROOT; EG2A7FailureSet(&result, EG2A7_FAILURE_NOT_ROOT);
 result.root = readers->root(readers->context); if (!result.root) return EG2A7Report(result);
 result.stage = EG2A7_STAGE_CAPACITY; EG2A7FailureSet(&result, EG2A7_FAILURE_CAPACITY_UNAVAILABLE);
 if (!readers->capacity) return EG2A7Report(result);
 unsigned runtimeCapacity = 0; int capacityStatus = readers->capacity(readers->context, &runtimeCapacity);
 result.runtimeCapacity = runtimeCapacity <= 65536 ? runtimeCapacity : 0;
 if (capacityStatus) { EG2A7ReaderFailure(readers, &result, EG2A7_FAILURE_CAPACITY_UNAVAILABLE); return EG2A7Report(result); }
 if (runtimeCapacity != NGROUPS) { EG2A7ReaderFailure(readers, &result, EG2A7_FAILURE_CAPACITY_MISMATCH); return EG2A7Report(result); }
 result.capacityVerified = YES;
 result.stage = EG2A7_STAGE_CLOCK; EG2A7FailureSet(&result, EG2A7_FAILURE_CLOCK);
 double now = readers->clock(readers->context);
 if (!isfinite(now) || now < 0) return EG2A7Report(result);
 double deadline = now + EG2A7_DEADLINE_SECONDS;
 result.stage = EG2A7_STAGE_ALLOCATION; EG2A7FailureSet(&result, EG2A7_FAILURE_ALLOCATION);
 pid_t *first = calloc(EG2A7_PID_LIMIT, sizeof(pid_t)), *second = calloc(EG2A7_PID_LIMIT, sizeof(pid_t));
 EG2A7Credentials *baseline = calloc(EG2A7_PID_LIMIT, sizeof(EG2A7Credentials));
 if (!first || !second || !baseline) { free(first); free(second); free(baseline); return EG2A7Report(result); }
 for (unsigned attempt = 1; attempt <= EG2A7_ATTEMPTS && EG2A7BeforeDeadline(readers, deadline); attempt++) {
  EG2A7Result r = {0}; r.record = YES; r.root = YES; r.realmCount = 2; r.attempts = attempt; r.stage = EG2A7_STAGE_GROUPS;
  r.capacityVerified = result.capacityVerified; r.runtimeCapacity = result.runtimeCapacity;
  int groupStatus = EG2A7CheckGroups(readers, owned, deadline, &r);
  if (groupStatus != 0) { result = r; if (groupStatus > 0) break; continue; }
  r.stage = EG2A7_STAGE_LIST_FIRST;
  int n = EG2A7ReadList(readers, first, deadline, &r);
  if (n < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.snapshotPIDCount = (NSUInteger)n;
  BOOL failed = NO, found = NO; r.scanRound = 1;
  for (int i = 0; i < n; i++) {
   int status = EG2A7ReadCredentials(readers, first[i], owned, deadline, &baseline[i], &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.stage = EG2A7_STAGE_LIST_SECOND;
  int m = EG2A7ReadList(readers, second, deadline, &r);
  if (m < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.enumerationComplete = YES;
  if (m != n || memcmp(first, second, (size_t)n * sizeof(pid_t))) { EG2A7FailureSet(&r, EG2A7_FAILURE_LIST_CHANGED); r.unstable++; result = r; continue; }
  r.scanRound = 2;
  for (int i = 0; i < n; i++) {
   EG2A7Credentials observed = {0};
   int status = EG2A7ReadCredentials(readers, second[i], owned, deadline, &observed, &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
   if (!EG2A7SameIdentity(&baseline[i], &observed) || !EG2A7SameGroups(&baseline[i], &observed)) {
    r.stage = !EG2A7SameIdentity(&baseline[i], &observed) ? EG2A7_STAGE_SECOND_IDENTITY : EG2A7_STAGE_SECOND_GROUPS;
    EG2A7FailureSet(&r, r.stage == EG2A7_STAGE_SECOND_IDENTITY ? EG2A7_FAILURE_IDENTITY : EG2A7_FAILURE_GROUPS_CHANGED);
    r.unstable++; failed = YES; break;
   }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.identitiesStable = YES; r.supplementaryCovered = YES; r.snapshotStable = YES;
  r.stage = EG2A7_STAGE_GROUPS_FINAL;
  groupStatus = EG2A7CheckGroups(readers, owned, deadline, &r);
  r.absent = (BOOL)(groupStatus == 0 && r.record && r.root && r.capacityVerified && r.runtimeCapacity == NGROUPS && r.lookupsComplete && r.groupsAbsent &&
   r.enumerationComplete && r.identitiesStable && r.supplementaryCovered && r.snapshotStable &&
   !r.matching && !r.unreadable && !r.unstable && EG2A7BeforeDeadline(readers, deadline));
  if (r.absent) { r.stage = EG2A7_STAGE_COMPLETE; EG2A7FailureSet(&r, EG2A7_FAILURE_NONE); }
  else if (r.diagnostic.failure == EG2A7_FAILURE_NONE) EG2A7FailureSet(&r, EG2A7_FAILURE_DEADLINE);
  result = r; if (r.absent || groupStatus > 0) break;
 }
 free(first); free(second); free(baseline); return EG2A7Report(result);
}

static BOOL EG2A7NativeRoot(void *context) { (void)context; return (BOOL)(getuid() == 0 && geteuid() == 0); }
static double EG2A7NativeClock(void *context) {
 (void)context; struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
 return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static int EG2A7DecodeCapacity(int status, size_t bytes, int capacity, int nativeError,
 unsigned *out, EG2A7ReaderDiagnostic *diagnostic) {
 EG2A7ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG2A7ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(int); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status || bytes != sizeof(int) || capacity < 1 || capacity > 65536) {
  diagnostic->failure = EG2A7_FAILURE_CAPACITY_UNAVAILABLE; diagnostic->error = status ? nativeError : 0; return -1;
 }
 *out = (unsigned)capacity;
 if (capacity != NGROUPS) { diagnostic->failure = EG2A7_FAILURE_CAPACITY_MISMATCH; return -1; }
 return 0;
}
static int EG2A7NativeCapacity(void *context, unsigned *out) {
 int capacity = 0; size_t bytes = sizeof(capacity); errno = 0;
 int status = sysctlbyname("kern.ngroups", &capacity, &bytes, NULL, 0); int error = errno;
 return EG2A7DecodeCapacity(status, bytes, capacity, error, out, context);
}
/* Production conversion logic is pure so inert fixtures can exercise real
 * SDK sizes/boundaries without running either public native reader. */
static int EG2A7DecodeBSD(const struct proc_bsdinfo *info, int bytes, int nativeError,
 EG2A7Credentials *out, EG2A7ReaderDiagnostic *diagnostic) {
 EG2A7ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG2A7ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(bytes >= 0);
 diagnostic->returnedBytes = bytes >= 0 ? (size_t)bytes : 0;
 if (bytes != sizeof(*info)) { diagnostic->failure = bytes < 0 || (!bytes && nativeError) ? EG2A7_FAILURE_BSD_ERROR : EG2A7_FAILURE_BSD_SIZE;
  diagnostic->error = nativeError; return -1; }
 *out = (EG2A7Credentials){.pid = (pid_t)info->pbi_pid, .status = info->pbi_status, .seconds = info->pbi_start_tvsec,
  .microseconds = info->pbi_start_tvusec, .effectiveUID = info->pbi_uid, .realUID = info->pbi_ruid,
  .savedUID = info->pbi_svuid, .effectiveGID = info->pbi_gid, .realGID = info->pbi_rgid, .savedGID = info->pbi_svgid};
 return 0;
}
static int EG2A7DecodeSupplementary(const struct kinfo_proc *info, int status, size_t bytes, int nativeError,
 EG2A7Credentials *out, EG2A7ReaderDiagnostic *diagnostic) {
 EG2A7ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EG2A7ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status) { diagnostic->failure = EG2A7_FAILURE_SYSCTL_ERROR; diagnostic->error = nativeError; return -1; }
 if (bytes != sizeof(*info)) { diagnostic->failure = EG2A7_FAILURE_SYSCTL_SIZE; return -1; }
 int groups = info->kp_eproc.e_ucred.cr_ngroups;
 diagnostic->groupsAvailable = (BOOL)(groups >= 0); diagnostic->observedGroups = groups >= 0 ? (unsigned)groups : 0;
 if (info->kp_proc.p_starttime.tv_sec <= 0 || info->kp_proc.p_starttime.tv_usec < 0 || info->kp_proc.p_starttime.tv_usec >= 1000000) {
  diagnostic->failure = EG2A7_FAILURE_BIRTH; return -1; }
 if (groups < 1 || groups > NGROUPS) { diagnostic->failure = groups < 0 ? EG2A7_FAILURE_GROUP_COUNT : !groups ? EG2A7_FAILURE_GROUP_EMPTY : EG2A7_FAILURE_GROUP_CAPACITY; return -1; }
 *out = (EG2A7Credentials){.pid = info->kp_proc.p_pid, .status = (unsigned char)info->kp_proc.p_stat, .seconds = (uint64_t)info->kp_proc.p_starttime.tv_sec,
  .microseconds = (uint64_t)info->kp_proc.p_starttime.tv_usec, .effectiveUID = info->kp_eproc.e_ucred.cr_uid,
  .realUID = info->kp_eproc.e_pcred.p_ruid, .savedUID = info->kp_eproc.e_pcred.p_svuid,
  .effectiveGID = info->kp_eproc.e_ucred.cr_groups[0], .realGID = info->kp_eproc.e_pcred.p_rgid,
  .savedGID = info->kp_eproc.e_pcred.p_svgid, .groupCount = (unsigned)groups};
 memcpy(out->groups, info->kp_eproc.e_ucred.cr_groups, out->groupCount * sizeof(gid_t)); return 0;
}
static void EG2A7NativeDiagnostic(void *context, EG2A7ReaderDiagnostic *out) {
 *out = context ? *(EG2A7ReaderDiagnostic *)context : (EG2A7ReaderDiagnostic){.failure = EG2A7_FAILURE_UNSPECIFIED};
}
static int EG2A7NativeList(void *context, pid_t *pids, size_t capacity) {
 EG2A7ReaderDiagnostic *diagnostic = context; if (diagnostic) *diagnostic = (EG2A7ReaderDiagnostic){0};
 if (capacity != EG2A7_PID_LIMIT || capacity * sizeof(pid_t) > INT_MAX) { if (diagnostic) diagnostic->failure = EG2A7_FAILURE_LIST_CAPACITY; return -1; }
 errno = 0;
 int estimate = proc_listallpids(NULL, 0);
 int error = errno;
 if (estimate <= 0 || estimate >= (int)capacity) { if (diagnostic) *diagnostic = (EG2A7ReaderDiagnostic){.failure = estimate >= (int)capacity ? EG2A7_FAILURE_LIST_CAPACITY : EG2A7_FAILURE_LIST_UNREADABLE, .error = error}; return -1; }
 errno = 0;
 int count = proc_listallpids(pids, (int)(capacity * sizeof(pid_t)));
 error = errno;
 if (diagnostic && (count <= 0 || count >= (int)capacity)) *diagnostic = (EG2A7ReaderDiagnostic){.failure = count >= (int)capacity ? EG2A7_FAILURE_LIST_CAPACITY : EG2A7_FAILURE_LIST_UNREADABLE, .error = error};
 return count > 0 && count < (int)capacity ? count : -1;
}
typedef int (*EG2A7BSDSystemCall)(int, int, uint64_t, void *, int);
static int EG2A7ReadBSDIncludingZombies(pid_t pid, EG2A7Credentials *out,
 EG2A7ReaderDiagnostic *diagnostic, EG2A7BSDSystemCall reader) {
 if (!reader) { if (diagnostic) *diagnostic = (EG2A7ReaderDiagnostic){.failure = EG2A7_FAILURE_UNSPECIFIED}; return -1; }
 struct proc_bsdinfo info = {0}; errno = 0;
 /* Apple XNU proc_info.c: PROC_PIDTBSDINFO arg != 0 enables proc_find_zombref.
  * Full UID/GID/birth data still comes from proc_pidbsdinfo. An ESRCH response
  * remains unknown and refuses the scan; neither dead nor zombie PIDs skip it.
  * Pinned evidence: f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, lines 2046-2061. */
 int bytes = reader(pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)); int error = errno;
 return EG2A7DecodeBSD(&info, bytes, error, out, diagnostic);
}
static int EG2A7NativeBSD(void *context, pid_t pid, EG2A7Credentials *out) {
 return EG2A7ReadBSDIncludingZombies(pid, out, context, proc_pidinfo);
}
static int EG2A7NativeSupplementary(void *context, pid_t pid, EG2A7Credentials *out) {
 int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
 struct kinfo_proc info = {0}; size_t size = sizeof(info);
 errno = 0; int status = sysctl(mib, 4, &info, &size, NULL, 0); int error = errno;
 return EG2A7DecodeSupplementary(&info, status, size, error, out, context);
}
static int EG2A7NativeGroupByGID(void *context, gid_t gid) {
 errno = 0; struct group *entry = getgrgid(gid); int error = errno;
 if (context) *(EG2A7ReaderDiagnostic *)context = (EG2A7ReaderDiagnostic){.failure = !entry && error ? EG2A7_FAILURE_GROUP_UNKNOWN : EG2A7_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}
static int EG2A7NativeGroupByName(void *context, const char *name) {
 errno = 0; struct group *entry = getgrnam(name); int error = errno;
 if (context) *(EG2A7ReaderDiagnostic *)context = (EG2A7ReaderDiagnostic){.failure = !entry && error ? EG2A7_FAILURE_GROUP_UNKNOWN : EG2A7_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}

static NSDictionary *EnvaraInspectGIDProof2A7(NSDictionary *sealedRecord) {
 EG2A7ReaderDiagnostic diagnostic = {0};
 const EG2A7Readers readers = {.context = &diagnostic, .root = EG2A7NativeRoot, .list = EG2A7NativeList,
  .bsd = EG2A7NativeBSD, .supplementary = EG2A7NativeSupplementary,
  .groupByGID = EG2A7NativeGroupByGID, .groupByName = EG2A7NativeGroupByName, .clock = EG2A7NativeClock,
  .capacity = EG2A7NativeCapacity, .diagnostic = EG2A7NativeDiagnostic};
 return EG2A7Inspect(sealedRecord, &readers);
}

#ifdef ENVARA_GID_PROOF_2A7_INERT_TEST
static NSDictionary *EnvaraInspectGIDProof2A7ForTest(NSDictionary *record, const EG2A7Readers *readers) {
 return EG2A7Inspect(record, readers);
}
#endif
#endif
