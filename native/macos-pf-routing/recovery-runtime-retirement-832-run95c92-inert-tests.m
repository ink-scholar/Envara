/* SOURCE-ONLY inert archive tests. Compile/run only when root authorizes it.
 * A future run writes, renames and removes only this harness's own mkdtemp
 * fixture. No root paths, authorization, process/GID probes or PF operations.
 * The archive function must preserve source bytes/inodes, including failures. */
#define ENVARA_RUNTIME_RETIREMENT_INERT_TEST 1
#include "recovery-runtime-retirement-832-run95c92.m"
#include <assert.h>

static const char *RR832TSourceLeaf = "io.envara.pf-runtime";
static NSString *const RR832TCapsuleLeaf = @"io.envara.pf-retired-832-95c92c49";
static NSString *const RR832TRealmA = @"aaaabbbb-cccc-4ddd-8eee-111122223333";
static NSString *const RR832TRealmB = @"ddddaaaa-bbbb-4ccc-8ddd-444455556666";
static NSData *RR832TJSON(id object) {
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingWithoutEscapingSlashes error:NULL]; assert(bytes); return bytes;
}
static NSDictionary *RR832TLease(void) {
 NSString *id = @"aaaabbbb-cccc-4ddd-8eee-111122223333";
 NSString *label = [@"envara.hook.v2." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@",FIXED_RUN,id]) substringToIndex:32]];
 return @{@"schema": @"envara.macos-pf-owned-root-hook-lease/v2", @"runId": FIXED_RUN, @"leaseId": id,
  @"anchor": FIXED_ANCHOR, @"owner": FIXED_ANCHOR, @"label": label, @"ticket": @"12345", @"rootBeforeSHA256": ROOT_RULE, @"rootBeforeTextSHA256": ROOT_TEXT};
}
static NSDictionary *RR832TRecord(void) {
 NSMutableArray *realms=[NSMutableArray array], *guards=[NSMutableArray array];
 for(unsigned i=0;i<2;i++) {
  NSNumber *parent=@(11+10*i), *child=@(12+10*i), *core=@(31+i), *fixtureGuard=@(41+i), *tunnelGuard=@(51+i), *gid=@(7171+i);
  NSString *realm=i?@"ddddaaaa-bbbb-4ccc-8ddd-444455556666":@"aaaabbbb-cccc-4ddd-8eee-111122223333";
  NSString *birth=@"1234567:000456", *utun=[NSString stringWithFormat:@"utun%u",123+i];
  [realms addObject:@{@"environmentId":realm,@"realmId":realm,@"gid":gid,@"groupPath":[NSString stringWithFormat:@"/Groups/_envara_pf_%u",7171+i],@"mode":@"blocked",
   @"tunnel":@{@"interfaceName":utun,@"pid":core,@"guardianPid":tunnelGuard,@"coreBirth":birth,@"instanceId":realm,@"ipv4Address":@"198.18.0.1",@"fdRetained":@YES},
   @"fixtures":@[@{@"pid":parent,@"birth":birth,@"role":@"parent",@"guardianKey":realm},@{@"pid":child,@"birth":birth,@"role":@"child",@"guardianKey":realm}]}];
  [guards addObject:@{@"key":realm,@"kind":@"fixture",@"guardianPid":fixtureGuard,@"pid":parent,@"birth":birth,@"interfaceName":NSNull.null,@"exited":@YES}];
  [guards addObject:@{@"key":realm,@"kind":@"tunnel",@"guardianPid":tunnelGuard,@"pid":core,@"birth":birth,@"interfaceName":utun,@"exited":@YES}];
 }
 return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": FIXED_RUN, @"supervisorPid": @999,
  @"anchor": FIXED_ANCHOR, @"phase": @"cleanup-required", @"cleanupUncertain": @YES,
  @"rootHook": @{@"mutationAttempted": @YES, @"verified": @YES, @"removed": @YES, @"receiptRetired":@YES,@"namespaceState":@"present",@"namespaceReclaimed":@NO,@"lease": RR832TLease()},
  @"ownedPFReference": @{@"attempted": @YES, @"acquired": @YES, @"released": @YES, @"token": @"private-token"},
  @"incompleteGroupAllocations": @[], @"realms":realms, @"guardians":guards};
}
static NSDictionary *RR832TPIDProof(void) {
    return @{@"recordedProcessCount": @11, @"absentPIDsDoubleChecked": @11, @"liveRecordedPIDs": @0,
        @"unreadableOrUnstablePIDs": @0, @"birthMismatches": @0, @"controlledProcessesGone": @YES};
}
static NSDictionary *RR832TProof(void) {
    return @{@"schema": @"envara.macos-pf-runtime-retirement-preflight/v1", @"runId": FIXED_RUN, @"manifestSHA256": @MF,
        @"readOnly": @YES, @"rootPFDisabled": @YES, @"rootOriginalFingerprintsMatch": @YES, @"activeRulesAllEmpty": @YES,
        @"anchorsEmpty": @YES, @"ghostTablesEmpty": @YES, @"pfReferenceReleased": @YES, @"recordedProcessesGone": @YES,
        @"ownedGIDProcessesGone": @YES, @"inventoryExact": @YES,@"receiptRetired":@YES,@"ownedRootHookRemoved":@YES,@"originalRootRestored":@YES,@"exactOwnedNamespaceRetained":@YES, @"recordedProcesses": RR832TPIDProof()};
}
static void RR832TWriteFD(int fd, NSData *bytes) {
    assert(fd >= 0); assert(fchmod(fd, 0600) == 0); size_t written = 0;
    while (written < bytes.length) {
        ssize_t count = write(fd, (const unsigned char *)bytes.bytes + written, bytes.length - written);
        assert(count > 0); written += (size_t)count;
    }
    assert(close(fd) == 0);
}
static void RR832TWrite(NSString *filename, NSData *bytes) {
    RR832TWriteFD(open(filename.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), bytes);
}
static void RR832TWriteAt(int parentFD, const char *leaf, NSData *bytes) {
    RR832TWriteFD(openat(parentFD, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), bytes);
}
static void RR832TMkdir(NSString *directory) {
    assert(mkdir(directory.fileSystemRepresentation, 0700) == 0); assert(chmod(directory.fileSystemRepresentation, 0700) == 0);
}
static NSDictionary *RR832TFixture(void) {
    char temporary[PATH_MAX];
    NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"envara-runtime-retirement-832-inert-XXXXXX"];
    int length = snprintf(temporary, sizeof(temporary), "%s", pattern.fileSystemRepresentation);
    assert(length > 0 && (size_t)length < sizeof(temporary)); assert(mkdtemp(temporary)); assert(chmod(temporary, 0700) == 0);
    NSString *parent = [NSString stringWithUTF8String:temporary];
    NSString *source = [parent stringByAppendingPathComponent:@"io.envara.pf-runtime"];
    NSString *run = [source stringByAppendingPathComponent:FIXED_RUN];
    NSArray *realms = @[[run stringByAppendingPathComponent:RR832TRealmA], [run stringByAppendingPathComponent:RR832TRealmB]];
    RR832TMkdir(source); RR832TMkdir(run); for (NSString *realm in realms) RR832TMkdir(realm);
    NSDictionary *record = RR832TRecord(); NSData *recordBytes = RR832TJSON(record);
    assert(RR832FixedRegistry(recordBytes));
    RR832TWrite([source stringByAppendingPathComponent:@"registry.json"], recordBytes);
    RR832TWrite([source stringByAppendingPathComponent:@"registry.lock"], RR832TJSON(@{@"runId": FIXED_RUN, @"pid": @999, @"anchor": FIXED_ANCHOR}));
    int parentFD = open(parent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); assert(parentFD >= 0);
    return @{@"parent": parent, @"source": source, @"run": run, @"realms": realms, @"fd": @(parentFD), @"record": record,
        @"recordBytes": recordBytes, @"capsule": [parent stringByAppendingPathComponent:RR832TCapsuleLeaf]};
}
static void RR832TDestroy(NSDictionary *fixture) {
    assert(close([fixture[@"fd"] intValue]) == 0);
    assert([[NSFileManager defaultManager] removeItemAtPath:fixture[@"parent"] error:NULL]);
}
static void RR832TSnapshotVisit(NSString *filename, NSString *relative, NSMutableDictionary *snapshot) {
    struct stat info; assert(lstat(filename.fileSystemRepresentation, &info) == 0);
    // Rename changes directory ctime. Inodes, modes and bytes must be retained.
    NSMutableDictionary *row = [@{@"device": @((unsigned long long)info.st_dev), @"inode": @((unsigned long long)info.st_ino),
        @"mode": @((unsigned int)info.st_mode), @"uid": @((unsigned int)info.st_uid), @"gid": @((unsigned int)info.st_gid),
        @"links": @((unsigned long long)info.st_nlink), @"size": @((long long)info.st_size)} mutableCopy];
    if (S_ISREG(info.st_mode)) {
        int fd = open(filename.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW); assert(fd >= 0);
        NSMutableData *contents = [NSMutableData data]; unsigned char bytes[4096]; ssize_t count;
        while ((count = read(fd, bytes, sizeof(bytes))) > 0) [contents appendBytes:bytes length:(NSUInteger)count];
        assert(count == 0); assert(close(fd) == 0); row[@"bytes"] = contents;
    } else if (S_ISLNK(info.st_mode)) {
        char target[PATH_MAX]; ssize_t length = readlink(filename.fileSystemRepresentation, target, sizeof(target));
        assert(length >= 0 && (size_t)length < sizeof(target)); row[@"target"] = [NSData dataWithBytes:target length:(NSUInteger)length];
    }
    snapshot[relative] = row;
    if (S_ISDIR(info.st_mode)) {
        DIR *directory = opendir(filename.fileSystemRepresentation); assert(directory); struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            NSString *name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:entry->d_name length:strlen(entry->d_name)]; assert(name);
            RR832TSnapshotVisit([filename stringByAppendingPathComponent:name], [relative stringByAppendingPathComponent:name], snapshot);
        }
        assert(closedir(directory) == 0);
    }
}
static NSDictionary *RR832TSnapshot(NSString *root) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary]; RR832TSnapshotVisit(root, @"", snapshot); return snapshot;
}
static BOOL RR832TExists(NSString *filename) {
    struct stat info; if (lstat(filename.fileSystemRepresentation, &info) == 0) return YES;
    assert(errno == ENOENT); return NO;
}
static void RR832TReport(NSDictionary *report) {
    assert([report[@"schema"] isEqual:@"envara.macos-pf-runtime-retirement/v1"]);
    for (NSString *key in @[@"readOnly", @"retirementAttempted", @"archiveCreated", @"runtimeMoved", @"archiveVerified", @"runtimeRetired",
        @"cleanupUncertain", @"changesFilesystem", @"changesPF", @"changesDNS", @"changesRoutes", @"changesGroups", @"namespaceReclaimed",
        @"cleanupConfirmed", @"productionReady", @"issuedLeaseRetiredNoDelete", @"sourceAbsentVerified", @"canRequestArchive"])
        assert(isBool(report[key]));
    for (NSString *key in @[@"archivedFileCount", @"archivedEmptyRealmCount"]) {
        assert([report[key] isKindOfClass:NSNumber.class] && !isBool(report[key])); assert([report[key] longLongValue] >= 0);
    }
    for (NSString *key in @[@"changesPF", @"changesDNS", @"changesRoutes", @"changesGroups", @"namespaceReclaimed", @"cleanupConfirmed", @"productionReady"])
        assert(![report[key] boolValue]);
    id digest = report[@"archiveSHA256"];
    assert(digest == NSNull.null || ([digest isKindOfClass:NSString.class] && [digest length] == 64 &&
        [digest rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location == NSNotFound));
    assert([report[@"reason"] isKindOfClass:NSString.class]);
    assert([RR832DiagnosticStages() containsObject:report[@"diagnosticStage"]]);
    assert([report[@"preflightSummary"] isKindOfClass:NSDictionary.class]);
    assert([RR832SanitizeSummary(report[@"preflightSummary"]) isEqual:report[@"preflightSummary"]]);
    NSString *output = [[NSString alloc] initWithData:RR832TJSON(report) encoding:NSUTF8StringEncoding];
    for (NSString *secret in @[@"PRIVATE_OWNED_FIXTURE_TOKEN", @"PRIVATE_UNKNOWN_ENTRY", @"PRIVATE_CAPSULE_CONTENT", @"\"ticket\"", @"\"lease\"", @"envara.hook.v2."])
        assert([output rangeOfString:secret].location == NSNotFound);
}
static NSDictionary *RR832TArchive(NSDictionary *fixture, NSDictionary *proof) {
    NSDictionary *report = RR832ArchiveRuntimeForTest([fixture[@"fd"] intValue], RR832TSourceLeaf, fixture[@"record"], proof, getuid(), getgid());
    RR832TReport(report); return report;
}
static void RR832TPreflightRefused(NSDictionary *fixture, NSDictionary *before, NSDictionary *report, BOOL capsuleExisted) {
    assert(![report[@"changesFilesystem"] boolValue]); assert(![report[@"runtimeRetired"] boolValue]); assert(![report[@"runtimeMoved"] boolValue]);
    assert(!RR832ExitSuccess(report));
    assert(RR832TExists(fixture[@"source"])); assert(RR832TExists(fixture[@"capsule"]) == capsuleExisted);
    assert([before isEqualToDictionary:RR832TSnapshot(fixture[@"parent"])]);
}
static void RR832TSuccess(void) {
    NSDictionary *fixture = RR832TFixture(), *sourceBefore = RR832TSnapshot(fixture[@"source"]);
    NSDictionary *report = RR832TArchive(fixture, RR832TProof());
    for (NSString *key in @[@"retirementAttempted", @"archiveCreated", @"runtimeMoved", @"archiveVerified", @"runtimeRetired",
        @"changesFilesystem", @"issuedLeaseRetiredNoDelete", @"sourceAbsentVerified"]) assert([report[key] boolValue]);
    assert([report[@"cleanupUncertain"] boolValue]); /* Archive confirms only filesystem sealing; overall cleanup remains uncertain. */ assert(!RR832TExists(fixture[@"source"]));
    NSString *archived = [fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"];
    assert([sourceBefore isEqualToDictionary:RR832TSnapshot(archived)]);
    NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fixture[@"capsule"] error:NULL];
    assert(([[NSSet setWithArray:names] isEqualToSet:[NSSet setWithArray:@[@"runtime", @"retirement-proof.json"]]]));
    struct stat receipt; assert(lstat([[fixture[@"capsule"] stringByAppendingPathComponent:@"retirement-proof.json"] fileSystemRepresentation], &receipt) == 0);
    assert(S_ISREG(receipt.st_mode) && (receipt.st_mode & 07777) == 0600 && receipt.st_nlink == 1 && receipt.st_size > 0);
    assert([report[@"archivedEmptyRealmCount"] unsignedIntegerValue] == 2); assert([report[@"archivedFileCount"] unsignedIntegerValue] >= 2);
    assert(report[@"archiveSHA256"] != NSNull.null); assert(![report[@"canRequestArchive"] boolValue]); assert(RR832ExitSuccess(report));
    NSMutableDictionary *badDigest = [report mutableCopy]; badDigest[@"archiveSHA256"] = [report[@"archiveSHA256"] stringByAppendingString:@"\n"];
    assert(!RR832ExitSuccess(badDigest)); RR832TDestroy(fixture);
}
static void RR832TBadProof(void) {
    for (NSString *key in [RR832RequiredProofBools() arrayByAddingObjectsFromArray:@[@"manifestSHA256", @"runId"]]) {
        NSDictionary *fixture = RR832TFixture(); NSMutableDictionary *proof = [RR832TProof() mutableCopy];
        proof[key] = [key isEqual:@"manifestSHA256"] ? @"wrong-manifest" : [key isEqual:@"runId"] ? @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" : @NO;
        NSDictionary *before = RR832TSnapshot(fixture[@"parent"]);
        RR832TPreflightRefused(fixture, before, RR832TArchive(fixture, proof), NO); RR832TDestroy(fixture);
    }
    NSDictionary *fixture = RR832TFixture(); NSMutableDictionary *proof = [RR832TProof() mutableCopy]; proof[@"rootPFDisabled"] = @1;
    NSDictionary *before = RR832TSnapshot(fixture[@"parent"]);
    RR832TPreflightRefused(fixture, before, RR832TArchive(fixture, proof), NO); RR832TDestroy(fixture);
}
static void RR832TBadSource(void) {
    for (NSUInteger kind = 0; kind < 5; kind++) {
        NSDictionary *fixture = RR832TFixture(); NSString *registry = [fixture[@"source"] stringByAppendingPathComponent:@"registry.json"];
        if (kind < 3) {
            NSString *directory = kind == 0 ? fixture[@"source"] : kind == 1 ? fixture[@"run"] : fixture[@"realms"][0];
            RR832TWrite([directory stringByAppendingPathComponent:@"PRIVATE_UNKNOWN_ENTRY"], [@"PRIVATE_UNKNOWN_ENTRY_CONTENT" dataUsingEncoding:NSUTF8StringEncoding]);
        } else if (kind == 3) {
            NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-symlink-target"];
            assert(rename(registry.fileSystemRepresentation, saved.fileSystemRepresentation) == 0); assert(symlink(saved.fileSystemRepresentation, registry.fileSystemRepresentation) == 0);
        } else {
            NSString *other = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-hardlink-copy"];
            assert(link(registry.fileSystemRepresentation, other.fileSystemRepresentation) == 0);
        }
        NSDictionary *before = RR832TSnapshot(fixture[@"parent"]);
        RR832TPreflightRefused(fixture, before, RR832TArchive(fixture, RR832TProof()), NO); RR832TDestroy(fixture);
    }
}
static void RR832TExistingCapsule(void) {
    for (NSUInteger partial = 0; partial < 2; partial++) {
        NSDictionary *fixture = RR832TFixture(); RR832TMkdir(fixture[@"capsule"]);
        RR832TWrite([fixture[@"capsule"] stringByAppendingPathComponent:@"retirement-proof.json"], [@"PRIVATE_CAPSULE_CONTENT" dataUsingEncoding:NSUTF8StringEncoding]);
        if (!partial) RR832TMkdir([fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"]);
        NSDictionary *before = RR832TSnapshot(fixture[@"parent"]);
        RR832TPreflightRefused(fixture, before, RR832TArchive(fixture, RR832TProof()), YES); RR832TDestroy(fixture);
    }
}
static void RR832TFaults(void) {
    for (int fault = 1; fault <= 2; fault++) {
        NSDictionary *fixture = RR832TFixture(), *sourceBefore = RR832TSnapshot(fixture[@"source"]);
        NSDictionary *report = RR832ArchiveRuntimeForTestWithFault([fixture[@"fd"] intValue], RR832TSourceLeaf, fixture[@"record"], RR832TProof(), getuid(), getgid(), fault, nil);
        RR832TReport(report); assert([report[@"changesFilesystem"] boolValue]); assert([report[@"cleanupUncertain"] boolValue]);
        assert(![report[@"canRequestArchive"] boolValue]); assert(!RR832ExitSuccess(report));
        assert(![report[@"runtimeRetired"] boolValue]); assert(RR832TExists(fixture[@"capsule"]));
        if (fault == 1) {
            assert(![report[@"runtimeMoved"] boolValue]); assert([sourceBefore isEqualToDictionary:RR832TSnapshot(fixture[@"source"])]);
        } else {
            assert([report[@"runtimeMoved"] boolValue]); assert(!RR832TExists(fixture[@"source"]));
            assert([sourceBefore isEqualToDictionary:RR832TSnapshot([fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"])]);
        }
        RR832TDestroy(fixture);
    }
}
static void RR832TBeforeRename(void) {
    for (NSUInteger kind = 0; kind < 2; kind++) {
        NSDictionary *fixture = RR832TFixture(); int parentFD = [fixture[@"fd"] intValue];
        __block NSDictionary *afterInjection = nil;
        void (^inject)(int) = ^(int runtimeFD) {
            if (kind == 0) {
                assert(renameat(runtimeFD, "registry.json", parentFD, "owned-original-registry") == 0);
                RR832TWriteAt(runtimeFD, "registry.json", fixture[@"recordBytes"]);
            } else {
                NSString *relative = [[FIXED_RUN stringByAppendingPathComponent:RR832TRealmA] stringByAppendingPathComponent:@"PRIVATE_UNKNOWN_ENTRY"];
                RR832TWriteAt(runtimeFD, relative.fileSystemRepresentation, [@"private" dataUsingEncoding:NSUTF8StringEncoding]);
            }
            afterInjection = RR832TSnapshot(fixture[@"parent"]);
        };
        NSDictionary *report = RR832ArchiveRuntimeForTestWithFault(parentFD, RR832TSourceLeaf, fixture[@"record"], RR832TProof(), getuid(), getgid(), 0, inject);
        RR832TReport(report); assert(afterInjection); assert([report[@"cleanupUncertain"] boolValue]); assert([report[@"changesFilesystem"] boolValue]);
        assert(![report[@"canRequestArchive"] boolValue]); assert(!RR832ExitSuccess(report));
        assert(![report[@"runtimeMoved"] boolValue]); assert(![report[@"runtimeRetired"] boolValue]);
        assert(RR832TExists(fixture[@"source"]) && RR832TExists(fixture[@"capsule"]));
        assert([afterInjection isEqualToDictionary:RR832TSnapshot(fixture[@"parent"])]); RR832TDestroy(fixture);
    }
}
static void RR832TRefreshFailureAndTargetRace(void) {
 for(unsigned mode=0;mode<2;mode++) {
  NSDictionary *fixture=RR832TFixture(), *original=RR832TSnapshot(fixture[@"source"]); __block unsigned calls=0;
  RR832Options options={0};
  if(mode==1) options.beforeRename=^(int ignored) { (void)ignored;
   RR832TMkdir([fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"]);
  };
  NSDictionary *report=RR832Archive([fixture[@"fd"] intValue],RR832TSourceLeaf,fixture[@"record"],^NSDictionary *(int fd,NSDictionary *record) {
   (void)fd;(void)record; calls++;
   if(mode==0 && calls==2) { NSMutableDictionary *failed=[RR832TProof() mutableCopy]; failed[@"receiptRetired"]=@NO; return failed; }
   return RR832TProof();
  },getuid(),getgid(),options);
  RR832TReport(report); assert(calls==2); assert([report[@"archiveCreated"] boolValue]);
  assert(![report[@"runtimeMoved"] boolValue] && ![report[@"runtimeRetired"] boolValue]);
  assert([original isEqual:RR832TSnapshot(fixture[@"source"])]);
  assert(RR832TExists(fixture[@"capsule"]) && !RR832ExitSuccess(report));
  RR832TDestroy(fixture);
 }
}
static void RR832TStrictProcessesAndExit(void) {
    assert(RR832RecordedProcessesValid(RR832TPIDProof()));
    assert(RR832FixedRecordProcessesValid(RR832TRecord()));
    for (NSString *key in @[@"recordedProcessCount", @"absentPIDsDoubleChecked", @"liveRecordedPIDs", @"unreadableOrUnstablePIDs", @"birthMismatches", @"controlledProcessesGone"]) {
        NSMutableDictionary *proof = [RR832TPIDProof() mutableCopy]; [proof removeObjectForKey:key]; assert(!RR832RecordedProcessesValid(proof));
        proof = [RR832TPIDProof() mutableCopy]; proof[key] = @YES; assert(!RR832RecordedProcessesValid(proof) || [key isEqual:@"controlledProcessesGone"]);
        proof = [RR832TPIDProof() mutableCopy]; proof[key] = @1; assert(!RR832RecordedProcessesValid(proof));
    }
    for (NSNumber *count in @[@10, @0, @11.0, @10.5]) {
        NSMutableDictionary *proof = [RR832TPIDProof() mutableCopy]; proof[@"recordedProcessCount"] = count; assert(!RR832RecordedProcessesValid(proof));
    }
    NSMutableDictionary *record = [RR832TRecord() mutableCopy]; record[@"guardians"] = @[];
    assert(!validRegistry(RR832TJSON(record))); assert(!RR832FixedRegistry(RR832TJSON(record)));
    record = [RR832TRecord() mutableCopy]; record[@"realms"] = @[@{@"realmId": RR832TRealmA, @"fixtures": @[]}, @{@"realmId": RR832TRealmB, @"fixtures": @[]}];
    assert(!validRegistry(RR832TJSON(record))); assert(!RR832FixedRegistry(RR832TJSON(record)));
    record = [RR832TRecord() mutableCopy]; record[@"guardians"] = @[@{@"guardianPid": @1201, @"pid": @1301}, @{@"guardianPid": @1202, @"pid": @1302}, @{@"guardianPid": @1203, @"pid": NSNull.null}];
    assert(!RR832FixedRegistry(RR832TJSON(record))); // Ten identities cannot pass the fixed eleven-PID gate.
    NSMutableDictionary *report = RR832Report(true); report[@"canRequestArchive"] = @YES; assert(RR832ExitSuccess(report));
    report[@"readOnly"] = @NO; assert(!RR832ExitSuccess(report)); report[@"runtimeRetired"] = @YES; assert(!RR832ExitSuccess(report));
    report = RR832Report(false); report[@"reason"] = @"STATIC_ARCHIVE_PLAN_ONLY"; assert(!RR832ExitSuccess(report));
    NSDictionary *fixture = RR832TFixture(); NSMutableDictionary *proof = [RR832TProof() mutableCopy];
    NSMutableDictionary *pids = [RR832TPIDProof() mutableCopy]; pids[@"recordedProcessCount"] = @10; proof[@"recordedProcesses"] = pids;
    NSDictionary *before = RR832TSnapshot(fixture[@"parent"]); RR832TPreflightRefused(fixture, before, RR832TArchive(fixture, proof), NO); RR832TDestroy(fixture);
}
static void RR832TCarrierPaths(void) {
    // The production path predicate is pure; no Authorization API is invoked.
    assert(RR832CarrierPathValid("/owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement832Run95c92"));
    assert(!RR832CarrierPathValid(NULL));
    assert(!RR832CarrierPathValid("owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement832Run95c92"));
    assert(!RR832CarrierPathValid("/owned/Review.app/Contents/MacOS/OtherExecutable"));
    assert(!RR832CarrierPathValid("/owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement832Run95c92/extra"));
    assert(!RR832CarrierPathValid("/owned/../Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement832Run95c92"));
}
static void RR832TDiagnosticSummary(void) {
    NSDictionary *registry = RR832RegistrySummary(RR832TRecord());
    assert(RR832IntegerEqual(registry[@"registryInventory"][@"recordedIdentityCount"], 11));
    assert(isBool(registry[@"registryInventory"][@"fixedProcessInventoryVerified"]));
    assert([registry[@"registryInventory"][@"fixedProcessInventoryVerified"] boolValue]);
    NSMutableDictionary *proof = [RR832TProof() mutableCopy];
    proof[@"firstRootProof"] = @{@"ok": @YES, @"pfDisabled": @NO, @"nativeExitStatus": @3,
        @"lease": @"PRIVATE_UNKNOWN_ENTRY", @"pid": @999, @"gid": @7101};
    proof[@"freshRootProof"] = NSNull.null;
    proof[@"ownedGIDProof"] = @{@"snapshotStable": @NO, @"matchingProcessCount": @0,
        @"unreadableProcessCount": @1, @"attemptCount": @3, @"gid": @7101, @"diagnosticStage": @"SYSCTL_SUPPLEMENTARY",
        @"readerFailure": @"GROUP_CAPACITY", @"errnoClass": @"NONE", @"observedGroupCount": @17, @"sdkGroupCapacity": @16,
        @"runtimeGroupCapacity": @16, @"groupCapacityVerified": @YES, @"zombieCredentialChecks": @2};
    proof[@"ownedGIDProcessesGone"] = @NO;
    proof[@"runtimeInventory"] = @{@"exactInventoryVerified": @NO, @"unknownEntryCount": @1,
        @"rawName": @"PRIVATE_UNKNOWN_ENTRY", @"inventorySHA256": @"PRIVATE_UNKNOWN_ENTRY"};
    NSDictionary *summary = RR832SummaryFromProof(proof);
    assert([summary[@"firstNative"][@"received"] boolValue]);
    assert(![summary[@"lastNative"][@"received"] boolValue]);
    assert(![summary[@"firstNative"][@"pfDisabled"] boolValue]);
    assert(RR832IntegerEqual(summary[@"firstNative"][@"nativeExitStatus"], 3));
    assert(RR832IntegerEqual(summary[@"ownedGIDProof"][@"matchingProcessCount"], 0));
    assert(RR832IntegerEqual(summary[@"ownedGIDProof"][@"unreadableProcessCount"], 1));
    assert([summary[@"ownedGIDProof"][@"diagnosticStage"] isEqual:@"SYSCTL_SUPPLEMENTARY"]);
    assert([summary[@"ownedGIDProof"][@"readerFailure"] isEqual:@"GROUP_CAPACITY"] && RR832IntegerEqual(summary[@"ownedGIDProof"][@"observedGroupCount"], 17));
    assert(isBool(summary[@"ownedGIDProof"][@"groupCapacityVerified"]) && [summary[@"ownedGIDProof"][@"groupCapacityVerified"] boolValue]);
    assert(RR832IntegerEqual(summary[@"ownedGIDProof"][@"runtimeGroupCapacity"], NGROUPS));
    assert(RR832IntegerEqual(summary[@"ownedGIDProof"][@"zombieCredentialChecks"], 2));
    NSMutableDictionary *report = RR832Report(true); report[@"diagnosticStage"] = @"FRESH_PREFLIGHT"; report[@"preflightSummary"] = summary;
    RR832TReport(report); assert(!RR832ExitSuccess(report)); assert(!RR832ProofValid(proof));
    NSDictionary *spec = RR832SummarySpec();
    for (NSString *section in summary) {
        for (NSString *key in [spec[section][@"bools"] arrayByAddingObject:@"received"]) if (summary[section][key]) assert(isBool(summary[section][key]));
        for (NSString *key in spec[section][@"counts"]) if (summary[section][key]) assert(!isBool(summary[section][key]) && !CFNumberIsFloatType((__bridge CFNumberRef)summary[section][key]));
    }
    NSDictionary *malformed = RR832SanitizeSummary(@{@"PRIVATE_UNKNOWN_ENTRY": @{@"ok": @YES},
        @"firstNative": @{@"ok": @1, @"pfDisabled": @"true", @"nativeExitStatus": @256, @"pid": @999},
        @"recordedProcesses": @{@"controlledProcessesGone": @1, @"recordedProcessCount": @YES,
            @"absentPIDsDoubleChecked": @11.0, @"liveRecordedPIDs": @(-1), @"birthMismatches": @65},
        @"ownedGIDProof": @{@"attemptCount": @4, @"unreadableProcessCount": @32769,
            @"diagnosticStage": @"PRIVATE_UNKNOWN_ENTRY", @"readerFailure": @999, @"errnoClass": @"PRIVATE_UNKNOWN_ENTRY"}});
    assert([malformed[@"firstNative"] count] == 0 && [malformed[@"recordedProcesses"] count] == 0 && [malformed[@"ownedGIDProof"] count] == 0);
    assert(!malformed[@"PRIVATE_UNKNOWN_ENTRY"]);
    assert([RR832SummaryFromProof(nil) count] == 0);
    assert(!RR832SummaryFromProof(@{})[@"checks"][@"rootPFDisabled"]); // Missing evidence is never synthesized as success.
    NSMutableDictionary *gid = [@{@"schema": @"envara.macos-pf-gid-proof/v1", @"realmCount": @2,
        @"matchingProcessCount": @0, @"unreadableProcessCount": @0, @"unstableProcessCount": @0,
        @"sdkGroupCapacity": @(NGROUPS), @"runtimeGroupCapacity": @(NGROUPS)} mutableCopy];
    for (NSString *key in @[@"readOnly", @"recordIdentityVerified", @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent",
        @"processEnumerationComplete", @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"allOwnedGIDProcessesAbsent", @"groupCapacityVerified"]) gid[key] = @YES;
    assert(RR832GIDProofValid(gid)); gid[@"groupCapacityVerified"] = @1; assert(!RR832GIDProofValid(gid));
    gid[@"groupCapacityVerified"] = @YES; gid[@"runtimeGroupCapacity"] = @YES; assert(!RR832GIDProofValid(gid));
    gid[@"runtimeGroupCapacity"] = @(NGROUPS-1); assert(!RR832GIDProofValid(gid));
    [gid removeObjectForKey:@"runtimeGroupCapacity"]; assert(!RR832GIDProofValid(gid));
}
int main(void) { @autoreleasepool {
    RR832TCarrierPaths(); RR832TStrictProcessesAndExit(); RR832TDiagnosticSummary();
    RR832TSuccess(); RR832TBadProof(); RR832TBadSource(); RR832TExistingCapsule(); RR832TFaults(); RR832TBeforeRename(); RR832TRefreshFailureAndTargetRace();
    puts("Runtime retirement inert fixture tests passed; only owned temporary fixtures were archived, without root/system activation.");
    return 0;
} }
