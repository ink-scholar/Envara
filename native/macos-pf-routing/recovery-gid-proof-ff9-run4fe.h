#ifndef ENVARA_RECOVERY_GID_PROOF_FF9_H
#define ENVARA_RECOVERY_GID_PROOF_FF9_H

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

#define EGFF9_PID_LIMIT 16384
#define EGFF9_ATTEMPTS 3
#define EGFF9_DEADLINE_SECONDS 15.0

typedef struct {
 pid_t pid;
 unsigned status;
 uint64_t seconds, microseconds;
 uid_t effectiveUID, realUID, savedUID;
 gid_t effectiveGID, realGID, savedGID;
 unsigned groupCount;
 gid_t groups[NGROUPS];
} EGFF9Credentials;

typedef enum { EGFF9_STAGE_NOT_STARTED, EGFF9_STAGE_RECORD, EGFF9_STAGE_READERS, EGFF9_STAGE_ROOT,
 EGFF9_STAGE_CLOCK, EGFF9_STAGE_ALLOCATION, EGFF9_STAGE_GROUPS, EGFF9_STAGE_LIST_FIRST,
 EGFF9_STAGE_BSD_FIRST, EGFF9_STAGE_SUPPLEMENTARY, EGFF9_STAGE_BSD_FINAL, EGFF9_STAGE_BINDING,
 EGFF9_STAGE_LIST_SECOND, EGFF9_STAGE_SECOND_IDENTITY, EGFF9_STAGE_SECOND_GROUPS,
 EGFF9_STAGE_GROUPS_FINAL, EGFF9_STAGE_COMPLETE, EGFF9_STAGE_CAPACITY } EGFF9Stage;
typedef enum { EGFF9_FAILURE_NONE, EGFF9_FAILURE_RECORD, EGFF9_FAILURE_READERS, EGFF9_FAILURE_NOT_ROOT,
 EGFF9_FAILURE_CLOCK, EGFF9_FAILURE_ALLOCATION, EGFF9_FAILURE_DEADLINE, EGFF9_FAILURE_GROUP_UNKNOWN,
 EGFF9_FAILURE_GROUP_PRESENT, EGFF9_FAILURE_LIST_UNREADABLE, EGFF9_FAILURE_LIST_CAPACITY,
 EGFF9_FAILURE_LIST_INVALID, EGFF9_FAILURE_LIST_EMPTY, EGFF9_FAILURE_LIST_DUPLICATE, EGFF9_FAILURE_LIST_CHANGED,
 EGFF9_FAILURE_BSD_ERROR, EGFF9_FAILURE_BSD_SIZE, EGFF9_FAILURE_SYSCTL_ERROR, EGFF9_FAILURE_SYSCTL_SIZE,
 EGFF9_FAILURE_PID, EGFF9_FAILURE_BIRTH, EGFF9_FAILURE_GROUP_EMPTY, EGFF9_FAILURE_GROUP_CAPACITY,
 EGFF9_FAILURE_GROUP_PRIMARY, EGFF9_FAILURE_GROUP_DUPLICATE, EGFF9_FAILURE_IDENTITY,
 EGFF9_FAILURE_GROUPS_CHANGED, EGFF9_FAILURE_OWNED, EGFF9_FAILURE_UNSPECIFIED, EGFF9_FAILURE_GROUP_COUNT,
 EGFF9_FAILURE_CAPACITY_UNAVAILABLE, EGFF9_FAILURE_CAPACITY_MISMATCH } EGFF9Failure;
typedef struct {
 EGFF9Failure failure; int error;
 size_t expectedBytes, returnedBytes; BOOL bytesAvailable;
 unsigned observedGroups; BOOL groupsAvailable;
} EGFF9ReaderDiagnostic;

typedef struct {
 void *context;
 BOOL (*root)(void *);
 int (*list)(void *, pid_t *, size_t);
 int (*bsd)(void *, pid_t, EGFF9Credentials *);
 int (*supplementary)(void *, pid_t, EGFF9Credentials *);
 /* 0 absent, 1 present, -1 unknown. Presence in either namespace refuses. */
 int (*groupByGID)(void *, gid_t);
 int (*groupByName)(void *, const char *);
 double (*clock)(void *);
 /* Mandatory system/SDK capacity attestation before any process snapshot. */
 int (*capacity)(void *, unsigned *);
 /* Optional metadata only; absence never changes a failed reader into proof. */
 void (*diagnostic)(void *, EGFF9ReaderDiagnostic *);
} EGFF9Readers;

typedef struct {
 BOOL record, root, lookupsComplete, groupsAbsent, enumerationComplete;
 BOOL identitiesStable, supplementaryCovered, snapshotStable, absent;
 BOOL capacityVerified;
 NSUInteger runtimeCapacity;
 NSUInteger realmCount, groupLookups, snapshotPIDCount, inspected;
 NSUInteger matching, unreadable, unstable, attempts;
 NSUInteger zombieChecks;
 NSUInteger scanRound;
 EGFF9Stage stage; EGFF9ReaderDiagnostic diagnostic;
} EGFF9Result;

static NSArray *EGFF9StageNames(void) {
 return @[@"NOT_STARTED", @"RECORD", @"READER_CONTRACT", @"ROOT_CALLER", @"CLOCK", @"ALLOCATION", @"GROUP_LOOKUPS",
  @"PID_LIST_FIRST", @"BSD_FIRST", @"SYSCTL_SUPPLEMENTARY", @"BSD_FINAL", @"CROSS_INTERFACE_IDENTITY",
  @"PID_LIST_SECOND", @"SECOND_SNAPSHOT_IDENTITY", @"SECOND_SNAPSHOT_GROUPS", @"FINAL_GROUP_LOOKUPS", @"COMPLETE", @"GROUP_CAPACITY_ATTESTATION"];
}
static NSArray *EGFF9FailureNames(void) {
 return @[@"NONE", @"INVALID_RECORD", @"READER_CONTRACT", @"NOT_ROOT", @"CLOCK_INVALID", @"ALLOCATION_FAILED", @"DEADLINE",
  @"GROUP_LOOKUP_UNKNOWN", @"GROUP_PRESENT", @"PID_LIST_UNREADABLE", @"PID_LIST_CAPACITY", @"PID_LIST_INVALID",
  @"PID_LIST_EMPTY", @"PID_LIST_DUPLICATE", @"PID_LIST_CHANGED", @"PROC_PIDINFO_ERROR", @"PROC_PIDINFO_SIZE_MISMATCH",
  @"SYSCTL_ERROR", @"SYSCTL_SIZE_MISMATCH", @"CREDENTIAL_PID_INVALID", @"BIRTH_INVALID", @"GROUP_EMPTY", @"GROUP_CAPACITY",
  @"GROUP_PRIMARY_MISMATCH", @"GROUP_DUPLICATE", @"IDENTITY_CHANGED", @"GROUPS_CHANGED", @"OWNED_GID_OBSERVED", @"READER_UNSPECIFIED", @"GROUP_COUNT_INVALID",
  @"SYSTEM_GROUP_CAPACITY_UNAVAILABLE", @"SYSTEM_GROUP_CAPACITY_MISMATCH"];
}
static NSArray *EGFF9ErrnoNames(void) { return @[@"NONE", @"ESRCH", @"ENOENT", @"EPERM", @"EACCES", @"EINVAL", @"ENOMEM", @"EIO", @"OTHER"]; }
static NSString *EGFF9ErrnoClass(int value) {
 switch (value) { case 0: return @"NONE"; case ESRCH: return @"ESRCH"; case ENOENT: return @"ENOENT";
  case EPERM: return @"EPERM"; case EACCES: return @"EACCES"; case EINVAL: return @"EINVAL";
  case ENOMEM: return @"ENOMEM"; case EIO: return @"EIO"; default: return @"OTHER"; }
}
static void EGFF9FailureSet(EGFF9Result *r, EGFF9Failure failure) { r->diagnostic.failure = failure; }
static void EGFF9ReaderFailure(const EGFF9Readers *readers, EGFF9Result *r, EGFF9Failure fallback) {
 EGFF9ReaderDiagnostic diagnostic = {0}; if (readers->diagnostic) readers->diagnostic(readers->context, &diagnostic);
 if (diagnostic.failure < EGFF9_FAILURE_NONE || diagnostic.failure > EGFF9_FAILURE_CAPACITY_MISMATCH) diagnostic.failure = EGFF9_FAILURE_UNSPECIFIED;
 if (diagnostic.failure == EGFF9_FAILURE_NONE) diagnostic.failure = fallback;
 r->diagnostic = diagnostic;
}

static NSDictionary *EGFF9Report(EGFF9Result r) {
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
  @"diagnosticStage": (unsigned)r.stage < EGFF9StageNames().count ? EGFF9StageNames()[r.stage] : @"NOT_STARTED",
  @"readerFailure": (unsigned)r.diagnostic.failure < EGFF9FailureNames().count ? EGFF9FailureNames()[r.diagnostic.failure] : @"READER_UNSPECIFIED",
  @"errnoClass": EGFF9ErrnoClass(r.diagnostic.error), @"sdkGroupCapacity": @(NGROUPS),
  @"readerExpectedByteCount": r.diagnostic.expectedBytes <= 16384 ? @(r.diagnostic.expectedBytes) : NSNull.null,
  @"readerReturnedByteCount": r.diagnostic.bytesAvailable && r.diagnostic.returnedBytes <= 16384 ? @(r.diagnostic.returnedBytes) : NSNull.null,
  @"observedGroupCount": r.diagnostic.groupsAvailable && r.diagnostic.observedGroups <= 65536 ? @(r.diagnostic.observedGroups) : NSNull.null,
  @"reason": r.absent ? @"READ_ONLY_FIXED_GID_PROOF" : @"FIXED_GID_PROOF_REFUSED"};
}

static BOOL EGFF9UUID(id value) {
 if (![value isKindOfClass:NSString.class] || [value length] != 36) return NO;
 NSString *pattern = @"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
 return (BOOL)([value rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound);
}

static BOOL EGFF9Record(NSDictionary *record, gid_t owned[2]) {
 if (![record isKindOfClass:NSDictionary.class] ||
  ![record[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"] ||
  ![record[@"runId"] isEqual:@"4fe07677-cbdb-4273-9b45-a1ecae8e6444"] ||
  ![record[@"anchor"] isEqual:@"io.envara.pf.run.4fe07677-cbdb-4273-9b45-a1ecae8e6444"] ||
  ![record[@"incompleteGroupAllocations"] isKindOfClass:NSArray.class] ||
  [record[@"incompleteGroupAllocations"] count] != 0 ||
  ![record[@"realms"] isKindOfClass:NSArray.class] || [record[@"realms"] count] != 2) return NO;
 NSMutableSet *ids = [NSMutableSet set];
 for (NSUInteger i = 0; i < 2; i++) {
  NSDictionary *realm = record[@"realms"][i];
  if (![realm isKindOfClass:NSDictionary.class] || !EGFF9UUID(realm[@"realmId"]) ||
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

static BOOL EGFF9CredentialShape(const EGFF9Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0 || !c->seconds || c->microseconds >= 1000000) return NO;
 if (!groups) return YES;
 /* The fixed SDK array is complete only with the separately required
  * kern.ngroups == NGROUPS attestation. All NGROUPS slots are inspected. */
 if (c->groupCount < 1 || c->groupCount > NGROUPS || c->groups[0] != c->effectiveGID) return NO;
 for (unsigned i = 0; i < c->groupCount; i++)
  for (unsigned j = 0; j < i; j++) if (c->groups[i] == c->groups[j]) return NO;
 return YES;
}

static BOOL EGFF9SameIdentity(const EGFF9Credentials *a, const EGFF9Credentials *b) {
 return (BOOL)(a->pid == b->pid && a->seconds == b->seconds && a->microseconds == b->microseconds &&
  a->effectiveUID == b->effectiveUID && a->realUID == b->realUID && a->savedUID == b->savedUID &&
  a->effectiveGID == b->effectiveGID && a->realGID == b->realGID && a->savedGID == b->savedGID);
}

static BOOL EGFF9SameGroups(const EGFF9Credentials *a, const EGFF9Credentials *b) {
 return (BOOL)(a->groupCount == b->groupCount &&
  !memcmp(a->groups, b->groups, a->groupCount * sizeof(gid_t)));
}

static BOOL EGFF9OwnedCredentials(const EGFF9Credentials *c, const gid_t owned[2]) {
 for (unsigned n = 0; n < 2; n++) {
  if (c->effectiveGID == owned[n] || c->realGID == owned[n] || c->savedGID == owned[n]) return YES;
  for (unsigned i = 0; i < c->groupCount; i++) if (c->groups[i] == owned[n]) return YES;
 }
 return NO;
}

static int EGFF9PIDCompare(const void *a, const void *b) {
 pid_t pa = *(const pid_t *)a, pb = *(const pid_t *)b;
 return pa < pb ? -1 : pa > pb ? 1 : 0;
}

static BOOL EGFF9BeforeDeadline(const EGFF9Readers *readers, double deadline) {
 double now = readers->clock(readers->context);
 return (BOOL)(isfinite(now) && now >= 0 && now < deadline);
}

static int EGFF9ReadList(const EGFF9Readers *readers, pid_t *pids, double deadline, EGFF9Result *r) {
 if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); return -1; }
 int size = readers->list(readers->context, pids, EGFF9_PID_LIMIT);
 if (size <= 0) { EGFF9ReaderFailure(readers, r, EGFF9_FAILURE_LIST_UNREADABLE); return -1; }
 if (size >= EGFF9_PID_LIMIT) { EGFF9FailureSet(r, EGFF9_FAILURE_LIST_CAPACITY); return -1; }
 if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); return -1; }
 size_t positive = 0;
 for (int i = 0; i < size; i++) {
  if (pids[i] < 0) { EGFF9FailureSet(r, EGFF9_FAILURE_LIST_INVALID); return -1; }
  if (pids[i] > 0) pids[positive++] = pids[i];
 }
 if (!positive) { EGFF9FailureSet(r, EGFF9_FAILURE_LIST_EMPTY); return -1; }
 qsort(pids, positive, sizeof(pid_t), EGFF9PIDCompare);
 for (size_t i = 1; i < positive; i++) if (pids[i] == pids[i - 1]) { EGFF9FailureSet(r, EGFF9_FAILURE_LIST_DUPLICATE); return -1; }
 return (int)positive;
}

static int EGFF9CheckGroups(const EGFF9Readers *readers, const gid_t owned[2],
 double deadline, EGFF9Result *r) {
 BOOL absent = YES, complete = YES;
 for (unsigned i = 0; i < 2; i++) {
  if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); complete = NO; break; }
  int byGID = readers->groupByGID(readers->context, owned[i]); r->groupLookups++;
  if (byGID < 0 || byGID > 1) EGFF9ReaderFailure(readers, r, EGFF9_FAILURE_GROUP_UNKNOWN);
  NSString *name = [NSString stringWithFormat:@"_envara_pf_%u", owned[i]];
  if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); complete = NO; break; }
  int byName = readers->groupByName(readers->context, name.UTF8String); r->groupLookups++;
  if (byName < 0 || byName > 1) EGFF9ReaderFailure(readers, r, EGFF9_FAILURE_GROUP_UNKNOWN);
  BOOL beforeDeadline = EGFF9BeforeDeadline(readers, deadline);
  if (!beforeDeadline) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); complete = NO; }
  if (byGID < 0 || byGID > 1 || byName < 0 || byName > 1) complete = NO;
  if (byGID != 0 || byName != 0) absent = NO;
 }
 r->lookupsComplete = complete; r->groupsAbsent = (BOOL)(complete && absent);
 if (complete && !absent) EGFF9FailureSet(r, EGFF9_FAILURE_GROUP_PRESENT);
 return !complete ? -1 : absent ? 0 : 1;
}

/* A libproc/sysctl pair is bracketed by another libproc read. Both credentials
 * and birth must agree; this rejects PID reuse or credential mutation between
 * the two public SDK interfaces rather than treating a matching PID as proof.
 * Zombies receive the same complete checks; they are never skipped. */
static EGFF9Failure EGFF9ShapeFailure(const EGFF9Credentials *c, pid_t pid, BOOL groups) {
 if (c->pid != pid || pid <= 0) return EGFF9_FAILURE_PID;
 if (!c->seconds || c->microseconds >= 1000000) return EGFF9_FAILURE_BIRTH;
 if (groups) {
  if (!c->groupCount) return EGFF9_FAILURE_GROUP_EMPTY;
  if (c->groupCount > NGROUPS) return EGFF9_FAILURE_GROUP_CAPACITY;
  if (c->groups[0] != c->effectiveGID) return EGFF9_FAILURE_GROUP_PRIMARY;
  return EGFF9_FAILURE_GROUP_DUPLICATE;
 }
 return EGFF9_FAILURE_UNSPECIFIED;
}
static int EGFF9ReadCredentials(const EGFF9Readers *readers, pid_t pid,
 const gid_t owned[2], double deadline, EGFF9Credentials *out, EGFF9Result *r) {
 EGFF9Credentials a = {0}, supplemental = {0}, b = {0};
 r->stage = EGFF9_STAGE_BSD_FIRST;
 if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); r->unreadable++; return -1; }
 int status = readers->bsd(readers->context, pid, &a); EGFF9ReaderFailure(readers, r, status ? EGFF9_FAILURE_UNSPECIFIED : EGFF9_FAILURE_NONE);
 if (status || !EGFF9CredentialShape(&a, pid, NO)) { if (!status) EGFF9FailureSet(r, EGFF9ShapeFailure(&a, pid, NO)); r->unreadable++; return -1; }
 if (EGFF9OwnedCredentials(&a, owned)) { EGFF9FailureSet(r, EGFF9_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EGFF9_STAGE_SUPPLEMENTARY;
 if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 status = readers->supplementary(readers->context, pid, &supplemental); EGFF9ReaderFailure(readers, r, status ? EGFF9_FAILURE_UNSPECIFIED : EGFF9_FAILURE_NONE);
 if (status || !EGFF9CredentialShape(&supplemental, pid, YES)) { if (!status) EGFF9FailureSet(r, EGFF9ShapeFailure(&supplemental, pid, YES)); r->unreadable++; r->supplementaryCovered = NO; return -1; }
 if (EGFF9OwnedCredentials(&supplemental, owned)) { EGFF9FailureSet(r, EGFF9_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EGFF9_STAGE_BSD_FINAL;
 if (!EGFF9BeforeDeadline(readers, deadline)) { EGFF9FailureSet(r, EGFF9_FAILURE_DEADLINE); r->unreadable++; return -1; }
 status = readers->bsd(readers->context, pid, &b); EGFF9ReaderFailure(readers, r, status ? EGFF9_FAILURE_UNSPECIFIED : EGFF9_FAILURE_NONE);
 if (status || !EGFF9CredentialShape(&b, pid, NO) || !EGFF9BeforeDeadline(readers, deadline)) {
  if (!status) EGFF9FailureSet(r, !EGFF9CredentialShape(&b, pid, NO) ? EGFF9ShapeFailure(&b, pid, NO) : EGFF9_FAILURE_DEADLINE);
  r->unreadable++; return -1;
 }
 if (EGFF9OwnedCredentials(&b, owned)) { EGFF9FailureSet(r, EGFF9_FAILURE_OWNED); r->matching++; return 1; }
 r->stage = EGFF9_STAGE_BINDING;
 if (!EGFF9SameIdentity(&a, &supplemental) || !EGFF9SameIdentity(&supplemental, &b)) {
  EGFF9FailureSet(r, EGFF9_FAILURE_IDENTITY); r->unstable++; r->supplementaryCovered = NO; return -1;
 }
 if (a.status == SZOMB && supplemental.status == SZOMB && b.status == SZOMB) r->zombieChecks++;
 *out = supplemental; r->inspected++; return 0;
}

static NSDictionary *EGFF9Inspect(NSDictionary *record, const EGFF9Readers *readers) {
 EGFF9Result result = {0}; gid_t owned[2] = {0};
 result.stage = EGFF9_STAGE_RECORD; EGFF9FailureSet(&result, EGFF9_FAILURE_RECORD);
 result.record = EGFF9Record(record, owned); result.realmCount = result.record ? 2 : 0;
 if (!result.record) return EGFF9Report(result);
 result.stage = EGFF9_STAGE_READERS; EGFF9FailureSet(&result, EGFF9_FAILURE_READERS);
 if (!readers || !readers->root || !readers->list || !readers->bsd ||
  !readers->supplementary || !readers->groupByGID || !readers->groupByName || !readers->clock) return EGFF9Report(result);
 result.stage = EGFF9_STAGE_ROOT; EGFF9FailureSet(&result, EGFF9_FAILURE_NOT_ROOT);
 result.root = readers->root(readers->context); if (!result.root) return EGFF9Report(result);
 result.stage = EGFF9_STAGE_CAPACITY; EGFF9FailureSet(&result, EGFF9_FAILURE_CAPACITY_UNAVAILABLE);
 if (!readers->capacity) return EGFF9Report(result);
 unsigned runtimeCapacity = 0; int capacityStatus = readers->capacity(readers->context, &runtimeCapacity);
 result.runtimeCapacity = runtimeCapacity <= 65536 ? runtimeCapacity : 0;
 if (capacityStatus) { EGFF9ReaderFailure(readers, &result, EGFF9_FAILURE_CAPACITY_UNAVAILABLE); return EGFF9Report(result); }
 if (runtimeCapacity != NGROUPS) { EGFF9ReaderFailure(readers, &result, EGFF9_FAILURE_CAPACITY_MISMATCH); return EGFF9Report(result); }
 result.capacityVerified = YES;
 result.stage = EGFF9_STAGE_CLOCK; EGFF9FailureSet(&result, EGFF9_FAILURE_CLOCK);
 double now = readers->clock(readers->context);
 if (!isfinite(now) || now < 0) return EGFF9Report(result);
 double deadline = now + EGFF9_DEADLINE_SECONDS;
 result.stage = EGFF9_STAGE_ALLOCATION; EGFF9FailureSet(&result, EGFF9_FAILURE_ALLOCATION);
 pid_t *first = calloc(EGFF9_PID_LIMIT, sizeof(pid_t)), *second = calloc(EGFF9_PID_LIMIT, sizeof(pid_t));
 EGFF9Credentials *baseline = calloc(EGFF9_PID_LIMIT, sizeof(EGFF9Credentials));
 if (!first || !second || !baseline) { free(first); free(second); free(baseline); return EGFF9Report(result); }
 for (unsigned attempt = 1; attempt <= EGFF9_ATTEMPTS && EGFF9BeforeDeadline(readers, deadline); attempt++) {
  EGFF9Result r = {0}; r.record = YES; r.root = YES; r.realmCount = 2; r.attempts = attempt; r.stage = EGFF9_STAGE_GROUPS;
  r.capacityVerified = result.capacityVerified; r.runtimeCapacity = result.runtimeCapacity;
  int groupStatus = EGFF9CheckGroups(readers, owned, deadline, &r);
  if (groupStatus != 0) { result = r; if (groupStatus > 0) break; continue; }
  r.stage = EGFF9_STAGE_LIST_FIRST;
  int n = EGFF9ReadList(readers, first, deadline, &r);
  if (n < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.snapshotPIDCount = (NSUInteger)n;
  BOOL failed = NO, found = NO; r.scanRound = 1;
  for (int i = 0; i < n; i++) {
   int status = EGFF9ReadCredentials(readers, first[i], owned, deadline, &baseline[i], &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.stage = EGFF9_STAGE_LIST_SECOND;
  int m = EGFF9ReadList(readers, second, deadline, &r);
  if (m < 0) { r.unreadable++; r.supplementaryCovered = NO; result = r; continue; }
  r.enumerationComplete = YES;
  if (m != n || memcmp(first, second, (size_t)n * sizeof(pid_t))) { EGFF9FailureSet(&r, EGFF9_FAILURE_LIST_CHANGED); r.unstable++; result = r; continue; }
  r.scanRound = 2;
  for (int i = 0; i < n; i++) {
   EGFF9Credentials observed = {0};
   int status = EGFF9ReadCredentials(readers, second[i], owned, deadline, &observed, &r);
   if (status != 0) { failed = YES; found = (BOOL)(status == 1); break; }
   if (!EGFF9SameIdentity(&baseline[i], &observed) || !EGFF9SameGroups(&baseline[i], &observed)) {
    r.stage = !EGFF9SameIdentity(&baseline[i], &observed) ? EGFF9_STAGE_SECOND_IDENTITY : EGFF9_STAGE_SECOND_GROUPS;
    EGFF9FailureSet(&r, r.stage == EGFF9_STAGE_SECOND_IDENTITY ? EGFF9_FAILURE_IDENTITY : EGFF9_FAILURE_GROUPS_CHANGED);
    r.unstable++; failed = YES; break;
   }
  }
  if (failed) { result = r; if (found) break; continue; }
  r.identitiesStable = YES; r.supplementaryCovered = YES; r.snapshotStable = YES;
  r.stage = EGFF9_STAGE_GROUPS_FINAL;
  groupStatus = EGFF9CheckGroups(readers, owned, deadline, &r);
  r.absent = (BOOL)(groupStatus == 0 && r.record && r.root && r.capacityVerified && r.runtimeCapacity == NGROUPS && r.lookupsComplete && r.groupsAbsent &&
   r.enumerationComplete && r.identitiesStable && r.supplementaryCovered && r.snapshotStable &&
   !r.matching && !r.unreadable && !r.unstable && EGFF9BeforeDeadline(readers, deadline));
  if (r.absent) { r.stage = EGFF9_STAGE_COMPLETE; EGFF9FailureSet(&r, EGFF9_FAILURE_NONE); }
  else if (r.diagnostic.failure == EGFF9_FAILURE_NONE) EGFF9FailureSet(&r, EGFF9_FAILURE_DEADLINE);
  result = r; if (r.absent || groupStatus > 0) break;
 }
 free(first); free(second); free(baseline); return EGFF9Report(result);
}

static BOOL EGFF9NativeRoot(void *context) { (void)context; return (BOOL)(getuid() == 0 && geteuid() == 0); }
static double EGFF9NativeClock(void *context) {
 (void)context; struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
 return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static int EGFF9DecodeCapacity(int status, size_t bytes, int capacity, int nativeError,
 unsigned *out, EGFF9ReaderDiagnostic *diagnostic) {
 EGFF9ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EGFF9ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(int); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status || bytes != sizeof(int) || capacity < 1 || capacity > 65536) {
  diagnostic->failure = EGFF9_FAILURE_CAPACITY_UNAVAILABLE; diagnostic->error = status ? nativeError : 0; return -1;
 }
 *out = (unsigned)capacity;
 if (capacity != NGROUPS) { diagnostic->failure = EGFF9_FAILURE_CAPACITY_MISMATCH; return -1; }
 return 0;
}
static int EGFF9NativeCapacity(void *context, unsigned *out) {
 int capacity = 0; size_t bytes = sizeof(capacity); errno = 0;
 int status = sysctlbyname("kern.ngroups", &capacity, &bytes, NULL, 0); int error = errno;
 return EGFF9DecodeCapacity(status, bytes, capacity, error, out, context);
}
/* Production conversion logic is pure so inert fixtures can exercise real
 * SDK sizes/boundaries without running either public native reader. */
static int EGFF9DecodeBSD(const struct proc_bsdinfo *info, int bytes, int nativeError,
 EGFF9Credentials *out, EGFF9ReaderDiagnostic *diagnostic) {
 EGFF9ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EGFF9ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(bytes >= 0);
 diagnostic->returnedBytes = bytes >= 0 ? (size_t)bytes : 0;
 if (bytes != sizeof(*info)) { diagnostic->failure = bytes < 0 || (!bytes && nativeError) ? EGFF9_FAILURE_BSD_ERROR : EGFF9_FAILURE_BSD_SIZE;
  diagnostic->error = nativeError; return -1; }
 *out = (EGFF9Credentials){.pid = (pid_t)info->pbi_pid, .status = info->pbi_status, .seconds = info->pbi_start_tvsec,
  .microseconds = info->pbi_start_tvusec, .effectiveUID = info->pbi_uid, .realUID = info->pbi_ruid,
  .savedUID = info->pbi_svuid, .effectiveGID = info->pbi_gid, .realGID = info->pbi_rgid, .savedGID = info->pbi_svgid};
 return 0;
}
static int EGFF9DecodeSupplementary(const struct kinfo_proc *info, int status, size_t bytes, int nativeError,
 EGFF9Credentials *out, EGFF9ReaderDiagnostic *diagnostic) {
 EGFF9ReaderDiagnostic local = {0}; if (!diagnostic) diagnostic = &local; *diagnostic = (EGFF9ReaderDiagnostic){0};
 diagnostic->expectedBytes = sizeof(*info); diagnostic->bytesAvailable = (BOOL)(status == 0); diagnostic->returnedBytes = bytes;
 if (status) { diagnostic->failure = EGFF9_FAILURE_SYSCTL_ERROR; diagnostic->error = nativeError; return -1; }
 if (bytes != sizeof(*info)) { diagnostic->failure = EGFF9_FAILURE_SYSCTL_SIZE; return -1; }
 int groups = info->kp_eproc.e_ucred.cr_ngroups;
 diagnostic->groupsAvailable = (BOOL)(groups >= 0); diagnostic->observedGroups = groups >= 0 ? (unsigned)groups : 0;
 if (info->kp_proc.p_starttime.tv_sec <= 0 || info->kp_proc.p_starttime.tv_usec < 0 || info->kp_proc.p_starttime.tv_usec >= 1000000) {
  diagnostic->failure = EGFF9_FAILURE_BIRTH; return -1; }
 if (groups < 1 || groups > NGROUPS) { diagnostic->failure = groups < 0 ? EGFF9_FAILURE_GROUP_COUNT : !groups ? EGFF9_FAILURE_GROUP_EMPTY : EGFF9_FAILURE_GROUP_CAPACITY; return -1; }
 *out = (EGFF9Credentials){.pid = info->kp_proc.p_pid, .status = (unsigned char)info->kp_proc.p_stat, .seconds = (uint64_t)info->kp_proc.p_starttime.tv_sec,
  .microseconds = (uint64_t)info->kp_proc.p_starttime.tv_usec, .effectiveUID = info->kp_eproc.e_ucred.cr_uid,
  .realUID = info->kp_eproc.e_pcred.p_ruid, .savedUID = info->kp_eproc.e_pcred.p_svuid,
  .effectiveGID = info->kp_eproc.e_ucred.cr_groups[0], .realGID = info->kp_eproc.e_pcred.p_rgid,
  .savedGID = info->kp_eproc.e_pcred.p_svgid, .groupCount = (unsigned)groups};
 memcpy(out->groups, info->kp_eproc.e_ucred.cr_groups, out->groupCount * sizeof(gid_t)); return 0;
}
static void EGFF9NativeDiagnostic(void *context, EGFF9ReaderDiagnostic *out) {
 *out = context ? *(EGFF9ReaderDiagnostic *)context : (EGFF9ReaderDiagnostic){.failure = EGFF9_FAILURE_UNSPECIFIED};
}
static int EGFF9NativeList(void *context, pid_t *pids, size_t capacity) {
 EGFF9ReaderDiagnostic *diagnostic = context; if (diagnostic) *diagnostic = (EGFF9ReaderDiagnostic){0};
 if (capacity != EGFF9_PID_LIMIT || capacity * sizeof(pid_t) > INT_MAX) { if (diagnostic) diagnostic->failure = EGFF9_FAILURE_LIST_CAPACITY; return -1; }
 errno = 0;
 int estimate = proc_listallpids(NULL, 0);
 int error = errno;
 if (estimate <= 0 || estimate >= (int)capacity) { if (diagnostic) *diagnostic = (EGFF9ReaderDiagnostic){.failure = estimate >= (int)capacity ? EGFF9_FAILURE_LIST_CAPACITY : EGFF9_FAILURE_LIST_UNREADABLE, .error = error}; return -1; }
 errno = 0;
 int count = proc_listallpids(pids, (int)(capacity * sizeof(pid_t)));
 error = errno;
 if (diagnostic && (count <= 0 || count >= (int)capacity)) *diagnostic = (EGFF9ReaderDiagnostic){.failure = count >= (int)capacity ? EGFF9_FAILURE_LIST_CAPACITY : EGFF9_FAILURE_LIST_UNREADABLE, .error = error};
 return count > 0 && count < (int)capacity ? count : -1;
}
typedef int (*EGFF9BSDSystemCall)(int, int, uint64_t, void *, int);
static int EGFF9ReadBSDIncludingZombies(pid_t pid, EGFF9Credentials *out,
 EGFF9ReaderDiagnostic *diagnostic, EGFF9BSDSystemCall reader) {
 if (!reader) { if (diagnostic) *diagnostic = (EGFF9ReaderDiagnostic){.failure = EGFF9_FAILURE_UNSPECIFIED}; return -1; }
 struct proc_bsdinfo info = {0}; errno = 0;
 /* Apple XNU proc_info.c: PROC_PIDTBSDINFO arg != 0 enables proc_find_zombref.
  * Full UID/GID/birth data still comes from proc_pidbsdinfo. An ESRCH response
  * remains unknown and refuses the scan; neither dead nor zombie PIDs skip it.
  * Pinned evidence: f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, lines 2046-2061. */
 int bytes = reader(pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)); int error = errno;
 return EGFF9DecodeBSD(&info, bytes, error, out, diagnostic);
}
static int EGFF9NativeBSD(void *context, pid_t pid, EGFF9Credentials *out) {
 return EGFF9ReadBSDIncludingZombies(pid, out, context, proc_pidinfo);
}
static int EGFF9NativeSupplementary(void *context, pid_t pid, EGFF9Credentials *out) {
 int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
 struct kinfo_proc info = {0}; size_t size = sizeof(info);
 errno = 0; int status = sysctl(mib, 4, &info, &size, NULL, 0); int error = errno;
 return EGFF9DecodeSupplementary(&info, status, size, error, out, context);
}
static int EGFF9NativeGroupByGID(void *context, gid_t gid) {
 errno = 0; struct group *entry = getgrgid(gid); int error = errno;
 if (context) *(EGFF9ReaderDiagnostic *)context = (EGFF9ReaderDiagnostic){.failure = !entry && error ? EGFF9_FAILURE_GROUP_UNKNOWN : EGFF9_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}
static int EGFF9NativeGroupByName(void *context, const char *name) {
 errno = 0; struct group *entry = getgrnam(name); int error = errno;
 if (context) *(EGFF9ReaderDiagnostic *)context = (EGFF9ReaderDiagnostic){.failure = !entry && error ? EGFF9_FAILURE_GROUP_UNKNOWN : EGFF9_FAILURE_NONE, .error = !entry ? error : 0};
 return entry ? 1 : errno ? -1 : 0;
}

static NSDictionary *EnvaraInspectGIDProofFF9(NSDictionary *sealedRecord) {
 EGFF9ReaderDiagnostic diagnostic = {0};
 const EGFF9Readers readers = {.context = &diagnostic, .root = EGFF9NativeRoot, .list = EGFF9NativeList,
  .bsd = EGFF9NativeBSD, .supplementary = EGFF9NativeSupplementary,
  .groupByGID = EGFF9NativeGroupByGID, .groupByName = EGFF9NativeGroupByName, .clock = EGFF9NativeClock,
  .capacity = EGFF9NativeCapacity, .diagnostic = EGFF9NativeDiagnostic};
 return EGFF9Inspect(sealedRecord, &readers);
}

#ifdef ENVARA_GID_PROOF_FF9_INERT_TEST
static NSDictionary *EnvaraInspectGIDProofFF9ForTest(NSDictionary *record, const EGFF9Readers *readers) {
 return EGFF9Inspect(record, readers);
}
#endif
#endif
