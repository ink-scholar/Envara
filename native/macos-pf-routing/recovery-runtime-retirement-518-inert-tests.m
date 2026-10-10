/* SOURCE-ONLY inert archive tests. Compile/run only when root authorizes it.
 * A future run writes, renames and removes only this harness's own mkdtemp
 * fixture. No root paths, authorization, process/GID probes or PF operations.
 * The archive function must preserve source bytes/inodes, including failures. */
#define ENVARA_RUNTIME_RETIREMENT_INERT_TEST 1
#include "recovery-runtime-retirement-518.m"
#include <assert.h>

static const char *RR518TSourceLeaf = "io.envara.pf-runtime";
static NSString *const RR518TCapsuleLeaf = @"io.envara.pf-retired-518-0a00377a";
static NSString *const RR518TRealmA = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
static NSString *const RR518TRealmB = @"cccccccc-cccc-4ccc-8ccc-cccccccccccc";
static NSData *RR518TJSON(id object) {
    NSData *bytes = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingWithoutEscapingSlashes error:NULL]; assert(bytes); return bytes;
}
static NSDictionary *RR518TRecord(void) {
    NSString *leaseId = @"dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    NSString *label = [@"envara.hook.v1." stringByAppendingString:[hashText([NSString stringWithFormat:@"%@|%@", FIXED_RUN, leaseId]) substringToIndex:32]];
    NSDictionary *lease = @{@"schema": @"envara.macos-pf-owned-root-hook-lease/v1", @"runId": FIXED_RUN,
        @"leaseId": leaseId, @"anchor": FIXED_ANCHOR, @"owner": FIXED_ANCHOR, @"label": label, @"ticket": @"12345",
        @"rootBeforeSHA256": ROOT_RULE, @"rootBeforeTextSHA256": ROOT_TEXT};
    return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": FIXED_RUN, @"supervisorPid": @999,
        @"anchor": FIXED_ANCHOR, @"phase": @"cleanup-required", @"cleanupUncertain": @YES,
        @"rootHook": @{@"mutationAttempted": @YES, @"verified": @YES, @"removed": @NO, @"lease": lease},
        @"ownedPFReference": @{@"attempted": @YES, @"acquired": @YES, @"released": @YES, @"token": @"PRIVATE_OWNED_FIXTURE_TOKEN"},
        @"incompleteGroupAllocations": @[], @"realms": @[
            @{@"realmId": RR518TRealmA, @"fixtures": @[@{@"pid": @1001, @"birth": @"123:000001"}, @{@"pid": @1002, @"birth": @"123:000002"}]},
            @{@"realmId": RR518TRealmB, @"fixtures": @[@{@"pid": @1003, @"birth": @"123:000003"}, @{@"pid": @1004, @"birth": @"123:000004"}]}],
        @"guardians": @[@{@"guardianPid": @1201, @"pid": @1301}, @{@"guardianPid": @1202, @"pid": @1302}, @{@"guardianPid": @1203, @"pid": @1303}]};
}
static NSDictionary *RR518TPIDProof(void) {
    return @{@"recordedProcessCount": @11, @"absentPIDsDoubleChecked": @11, @"liveRecordedPIDs": @0,
        @"unreadableOrUnstablePIDs": @0, @"birthMismatches": @0, @"controlledProcessesGone": @YES};
}
static NSDictionary *RR518TProof(void) {
    return @{@"schema": @"envara.macos-pf-runtime-retirement-preflight/v1", @"runId": FIXED_RUN, @"manifestSHA256": @MF,
        @"readOnly": @YES, @"rootPFDisabled": @YES, @"rootOriginalFingerprintsMatch": @YES, @"activeRulesAllEmpty": @YES,
        @"anchorsEmpty": @YES, @"ghostTablesEmpty": @YES, @"pfReferenceReleased": @YES, @"recordedProcessesGone": @YES,
        @"ownedGIDProcessesGone": @YES, @"inventoryExact": @YES, @"recordedProcesses": RR518TPIDProof()};
}
static void RR518TWriteFD(int fd, NSData *bytes) {
    assert(fd >= 0); assert(fchmod(fd, 0600) == 0); size_t written = 0;
    while (written < bytes.length) {
        ssize_t count = write(fd, (const unsigned char *)bytes.bytes + written, bytes.length - written);
        assert(count > 0); written += (size_t)count;
    }
    assert(close(fd) == 0);
}
static void RR518TWrite(NSString *filename, NSData *bytes) {
    RR518TWriteFD(open(filename.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), bytes);
}
static void RR518TWriteAt(int parentFD, const char *leaf, NSData *bytes) {
    RR518TWriteFD(openat(parentFD, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), bytes);
}
static void RR518TMkdir(NSString *directory) {
    assert(mkdir(directory.fileSystemRepresentation, 0700) == 0); assert(chmod(directory.fileSystemRepresentation, 0700) == 0);
}
static NSDictionary *RR518TFixture(void) {
    char temporary[PATH_MAX];
    NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"envara-runtime-retirement-518-inert-XXXXXX"];
    int length = snprintf(temporary, sizeof(temporary), "%s", pattern.fileSystemRepresentation);
    assert(length > 0 && (size_t)length < sizeof(temporary)); assert(mkdtemp(temporary)); assert(chmod(temporary, 0700) == 0);
    NSString *parent = [NSString stringWithUTF8String:temporary];
    NSString *source = [parent stringByAppendingPathComponent:@"io.envara.pf-runtime"];
    NSString *run = [source stringByAppendingPathComponent:FIXED_RUN];
    NSArray *realms = @[[run stringByAppendingPathComponent:RR518TRealmA], [run stringByAppendingPathComponent:RR518TRealmB]];
    RR518TMkdir(source); RR518TMkdir(run); for (NSString *realm in realms) RR518TMkdir(realm);
    NSDictionary *record = RR518TRecord(); NSData *recordBytes = RR518TJSON(record);
    assert(RR518FixedRegistry(recordBytes));
    RR518TWrite([source stringByAppendingPathComponent:@"registry.json"], recordBytes);
    RR518TWrite([source stringByAppendingPathComponent:@"registry.lock"], RR518TJSON(@{@"runId": FIXED_RUN, @"pid": @999, @"anchor": FIXED_ANCHOR}));
    int parentFD = open(parent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW); assert(parentFD >= 0);
    return @{@"parent": parent, @"source": source, @"run": run, @"realms": realms, @"fd": @(parentFD), @"record": record,
        @"recordBytes": recordBytes, @"capsule": [parent stringByAppendingPathComponent:RR518TCapsuleLeaf]};
}
static void RR518TDestroy(NSDictionary *fixture) {
    assert(close([fixture[@"fd"] intValue]) == 0);
    assert([[NSFileManager defaultManager] removeItemAtPath:fixture[@"parent"] error:NULL]);
}
static void RR518TSnapshotVisit(NSString *filename, NSString *relative, NSMutableDictionary *snapshot) {
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
            RR518TSnapshotVisit([filename stringByAppendingPathComponent:name], [relative stringByAppendingPathComponent:name], snapshot);
        }
        assert(closedir(directory) == 0);
    }
}
static NSDictionary *RR518TSnapshot(NSString *root) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary]; RR518TSnapshotVisit(root, @"", snapshot); return snapshot;
}
static BOOL RR518TExists(NSString *filename) {
    struct stat info; if (lstat(filename.fileSystemRepresentation, &info) == 0) return YES;
    assert(errno == ENOENT); return NO;
}
static void RR518TReport(NSDictionary *report) {
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
    assert([RR518DiagnosticStages() containsObject:report[@"diagnosticStage"]]);
    assert([report[@"preflightSummary"] isKindOfClass:NSDictionary.class]);
    assert([RR518SanitizeSummary(report[@"preflightSummary"]) isEqual:report[@"preflightSummary"]]);
    NSString *output = [[NSString alloc] initWithData:RR518TJSON(report) encoding:NSUTF8StringEncoding];
    for (NSString *secret in @[@"PRIVATE_OWNED_FIXTURE_TOKEN", @"PRIVATE_UNKNOWN_ENTRY", @"PRIVATE_CAPSULE_CONTENT", @"\"ticket\"", @"\"lease\"", @"envara.hook.v1."])
        assert([output rangeOfString:secret].location == NSNotFound);
}
static NSDictionary *RR518TArchive(NSDictionary *fixture, NSDictionary *proof) {
    NSDictionary *report = RR518ArchiveRuntimeForTest([fixture[@"fd"] intValue], RR518TSourceLeaf, fixture[@"record"], proof, getuid(), getgid());
    RR518TReport(report); return report;
}
static void RR518TPreflightRefused(NSDictionary *fixture, NSDictionary *before, NSDictionary *report, BOOL capsuleExisted) {
    assert(![report[@"changesFilesystem"] boolValue]); assert(![report[@"runtimeRetired"] boolValue]); assert(![report[@"runtimeMoved"] boolValue]);
    assert(!RR518ExitSuccess(report));
    assert(RR518TExists(fixture[@"source"])); assert(RR518TExists(fixture[@"capsule"]) == capsuleExisted);
    assert([before isEqualToDictionary:RR518TSnapshot(fixture[@"parent"])]);
}
static void RR518TSuccess(void) {
    NSDictionary *fixture = RR518TFixture(), *sourceBefore = RR518TSnapshot(fixture[@"source"]);
    NSDictionary *report = RR518TArchive(fixture, RR518TProof());
    for (NSString *key in @[@"retirementAttempted", @"archiveCreated", @"runtimeMoved", @"archiveVerified", @"runtimeRetired",
        @"changesFilesystem", @"issuedLeaseRetiredNoDelete", @"sourceAbsentVerified"]) assert([report[key] boolValue]);
    assert([report[@"cleanupUncertain"] boolValue]); /* Archive confirms only filesystem sealing; overall cleanup remains uncertain. */ assert(!RR518TExists(fixture[@"source"]));
    NSString *archived = [fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"];
    assert([sourceBefore isEqualToDictionary:RR518TSnapshot(archived)]);
    NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fixture[@"capsule"] error:NULL];
    assert(([[NSSet setWithArray:names] isEqualToSet:[NSSet setWithArray:@[@"runtime", @"retirement-proof.json"]]]));
    struct stat receipt; assert(lstat([[fixture[@"capsule"] stringByAppendingPathComponent:@"retirement-proof.json"] fileSystemRepresentation], &receipt) == 0);
    assert(S_ISREG(receipt.st_mode) && (receipt.st_mode & 07777) == 0600 && receipt.st_nlink == 1 && receipt.st_size > 0);
    assert([report[@"archivedEmptyRealmCount"] unsignedIntegerValue] == 2); assert([report[@"archivedFileCount"] unsignedIntegerValue] >= 2);
    assert(report[@"archiveSHA256"] != NSNull.null); assert(![report[@"canRequestArchive"] boolValue]); assert(RR518ExitSuccess(report));
    NSMutableDictionary *badDigest = [report mutableCopy]; badDigest[@"archiveSHA256"] = [report[@"archiveSHA256"] stringByAppendingString:@"\n"];
    assert(!RR518ExitSuccess(badDigest)); RR518TDestroy(fixture);
}
static void RR518TBadProof(void) {
    for (NSString *key in @[@"rootPFDisabled", @"ownedGIDProcessesGone", @"inventoryExact", @"manifestSHA256", @"runId"]) {
        NSDictionary *fixture = RR518TFixture(); NSMutableDictionary *proof = [RR518TProof() mutableCopy];
        proof[key] = [key isEqual:@"manifestSHA256"] ? @"wrong-manifest" : [key isEqual:@"runId"] ? @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" : @NO;
        NSDictionary *before = RR518TSnapshot(fixture[@"parent"]);
        RR518TPreflightRefused(fixture, before, RR518TArchive(fixture, proof), NO); RR518TDestroy(fixture);
    }
    NSDictionary *fixture = RR518TFixture(); NSMutableDictionary *proof = [RR518TProof() mutableCopy]; proof[@"rootPFDisabled"] = @1;
    NSDictionary *before = RR518TSnapshot(fixture[@"parent"]);
    RR518TPreflightRefused(fixture, before, RR518TArchive(fixture, proof), NO); RR518TDestroy(fixture);
}
static void RR518TBadSource(void) {
    for (NSUInteger kind = 0; kind < 5; kind++) {
        NSDictionary *fixture = RR518TFixture(); NSString *registry = [fixture[@"source"] stringByAppendingPathComponent:@"registry.json"];
        if (kind < 3) {
            NSString *directory = kind == 0 ? fixture[@"source"] : kind == 1 ? fixture[@"run"] : fixture[@"realms"][0];
            RR518TWrite([directory stringByAppendingPathComponent:@"PRIVATE_UNKNOWN_ENTRY"], [@"PRIVATE_UNKNOWN_ENTRY_CONTENT" dataUsingEncoding:NSUTF8StringEncoding]);
        } else if (kind == 3) {
            NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-symlink-target"];
            assert(rename(registry.fileSystemRepresentation, saved.fileSystemRepresentation) == 0); assert(symlink(saved.fileSystemRepresentation, registry.fileSystemRepresentation) == 0);
        } else {
            NSString *other = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-hardlink-copy"];
            assert(link(registry.fileSystemRepresentation, other.fileSystemRepresentation) == 0);
        }
        NSDictionary *before = RR518TSnapshot(fixture[@"parent"]);
        RR518TPreflightRefused(fixture, before, RR518TArchive(fixture, RR518TProof()), NO); RR518TDestroy(fixture);
    }
}
static void RR518TExistingCapsule(void) {
    for (NSUInteger partial = 0; partial < 2; partial++) {
        NSDictionary *fixture = RR518TFixture(); RR518TMkdir(fixture[@"capsule"]);
        RR518TWrite([fixture[@"capsule"] stringByAppendingPathComponent:@"retirement-proof.json"], [@"PRIVATE_CAPSULE_CONTENT" dataUsingEncoding:NSUTF8StringEncoding]);
        if (!partial) RR518TMkdir([fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"]);
        NSDictionary *before = RR518TSnapshot(fixture[@"parent"]);
        RR518TPreflightRefused(fixture, before, RR518TArchive(fixture, RR518TProof()), YES); RR518TDestroy(fixture);
    }
}
static void RR518TFaults(void) {
    for (int fault = 1; fault <= 2; fault++) {
        NSDictionary *fixture = RR518TFixture(), *sourceBefore = RR518TSnapshot(fixture[@"source"]);
        NSDictionary *report = RR518ArchiveRuntimeForTestWithFault([fixture[@"fd"] intValue], RR518TSourceLeaf, fixture[@"record"], RR518TProof(), getuid(), getgid(), fault, nil);
        RR518TReport(report); assert([report[@"changesFilesystem"] boolValue]); assert([report[@"cleanupUncertain"] boolValue]);
        assert(![report[@"canRequestArchive"] boolValue]); assert(!RR518ExitSuccess(report));
        assert(![report[@"runtimeRetired"] boolValue]); assert(RR518TExists(fixture[@"capsule"]));
        if (fault == 1) {
            assert(![report[@"runtimeMoved"] boolValue]); assert([sourceBefore isEqualToDictionary:RR518TSnapshot(fixture[@"source"])]);
        } else {
            assert([report[@"runtimeMoved"] boolValue]); assert(!RR518TExists(fixture[@"source"]));
            assert([sourceBefore isEqualToDictionary:RR518TSnapshot([fixture[@"capsule"] stringByAppendingPathComponent:@"runtime"])]);
        }
        RR518TDestroy(fixture);
    }
}
static void RR518TBeforeRename(void) {
    for (NSUInteger kind = 0; kind < 2; kind++) {
        NSDictionary *fixture = RR518TFixture(); int parentFD = [fixture[@"fd"] intValue];
        __block NSDictionary *afterInjection = nil;
        void (^inject)(int) = ^(int runtimeFD) {
            if (kind == 0) {
                assert(renameat(runtimeFD, "registry.json", parentFD, "owned-original-registry") == 0);
                RR518TWriteAt(runtimeFD, "registry.json", fixture[@"recordBytes"]);
            } else {
                NSString *relative = [[FIXED_RUN stringByAppendingPathComponent:RR518TRealmA] stringByAppendingPathComponent:@"PRIVATE_UNKNOWN_ENTRY"];
                RR518TWriteAt(runtimeFD, relative.fileSystemRepresentation, [@"private" dataUsingEncoding:NSUTF8StringEncoding]);
            }
            afterInjection = RR518TSnapshot(fixture[@"parent"]);
        };
        NSDictionary *report = RR518ArchiveRuntimeForTestWithFault(parentFD, RR518TSourceLeaf, fixture[@"record"], RR518TProof(), getuid(), getgid(), 0, inject);
        RR518TReport(report); assert(afterInjection); assert([report[@"cleanupUncertain"] boolValue]); assert([report[@"changesFilesystem"] boolValue]);
        assert(![report[@"canRequestArchive"] boolValue]); assert(!RR518ExitSuccess(report));
        assert(![report[@"runtimeMoved"] boolValue]); assert(![report[@"runtimeRetired"] boolValue]);
        assert(RR518TExists(fixture[@"source"]) && RR518TExists(fixture[@"capsule"]));
        assert([afterInjection isEqualToDictionary:RR518TSnapshot(fixture[@"parent"])]); RR518TDestroy(fixture);
    }
}
static void RR518TStrictProcessesAndExit(void) {
    assert(RR518RecordedProcessesValid(RR518TPIDProof()));
    assert(RR518FixedRecordProcessesValid(RR518TRecord()));
    for (NSString *key in @[@"recordedProcessCount", @"absentPIDsDoubleChecked", @"liveRecordedPIDs", @"unreadableOrUnstablePIDs", @"birthMismatches", @"controlledProcessesGone"]) {
        NSMutableDictionary *proof = [RR518TPIDProof() mutableCopy]; [proof removeObjectForKey:key]; assert(!RR518RecordedProcessesValid(proof));
        proof = [RR518TPIDProof() mutableCopy]; proof[key] = @YES; assert(!RR518RecordedProcessesValid(proof) || [key isEqual:@"controlledProcessesGone"]);
        proof = [RR518TPIDProof() mutableCopy]; proof[key] = @1; assert(!RR518RecordedProcessesValid(proof));
    }
    for (NSNumber *count in @[@10, @0, @11.0, @10.5]) {
        NSMutableDictionary *proof = [RR518TPIDProof() mutableCopy]; proof[@"recordedProcessCount"] = count; assert(!RR518RecordedProcessesValid(proof));
    }
    NSMutableDictionary *record = [RR518TRecord() mutableCopy]; record[@"guardians"] = @[];
    assert(validRegistry(RR518TJSON(record))); assert(!RR518FixedRegistry(RR518TJSON(record)));
    record = [RR518TRecord() mutableCopy]; record[@"realms"] = @[@{@"realmId": RR518TRealmA, @"fixtures": @[]}, @{@"realmId": RR518TRealmB, @"fixtures": @[]}];
    assert(validRegistry(RR518TJSON(record))); assert(!RR518FixedRegistry(RR518TJSON(record)));
    record = [RR518TRecord() mutableCopy]; record[@"guardians"] = @[@{@"guardianPid": @1201, @"pid": @1301}, @{@"guardianPid": @1202, @"pid": @1302}, @{@"guardianPid": @1203, @"pid": NSNull.null}];
    assert(!RR518FixedRegistry(RR518TJSON(record))); // Ten identities cannot pass the fixed eleven-PID gate.
    NSMutableDictionary *report = RR518Report(true); report[@"canRequestArchive"] = @YES; assert(RR518ExitSuccess(report));
    report[@"readOnly"] = @NO; assert(!RR518ExitSuccess(report)); report[@"runtimeRetired"] = @YES; assert(!RR518ExitSuccess(report));
    report = RR518Report(false); report[@"reason"] = @"STATIC_ARCHIVE_PLAN_ONLY"; assert(!RR518ExitSuccess(report));
    NSDictionary *fixture = RR518TFixture(); NSMutableDictionary *proof = [RR518TProof() mutableCopy];
    NSMutableDictionary *pids = [RR518TPIDProof() mutableCopy]; pids[@"recordedProcessCount"] = @10; proof[@"recordedProcesses"] = pids;
    NSDictionary *before = RR518TSnapshot(fixture[@"parent"]); RR518TPreflightRefused(fixture, before, RR518TArchive(fixture, proof), NO); RR518TDestroy(fixture);
}
static void RR518TCarrierPaths(void) {
    // The production path predicate is pure; no Authorization API is invoked.
    assert(RR518CarrierPathValid("/owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement518"));
    assert(!RR518CarrierPathValid(NULL));
    assert(!RR518CarrierPathValid("owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement518"));
    assert(!RR518CarrierPathValid("/owned/Review.app/Contents/MacOS/OtherExecutable"));
    assert(!RR518CarrierPathValid("/owned/Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement518/extra"));
    assert(!RR518CarrierPathValid("/owned/../Review.app/Contents/MacOS/EnvaraPFRuntimeRetirement518"));
}
static void RR518TDiagnosticSummary(void) {
    NSDictionary *registry = RR518RegistrySummary(RR518TRecord());
    assert(RR518IntegerEqual(registry[@"registryInventory"][@"recordedIdentityCount"], 11));
    assert(isBool(registry[@"registryInventory"][@"fixedProcessInventoryVerified"]));
    assert([registry[@"registryInventory"][@"fixedProcessInventoryVerified"] boolValue]);
    NSMutableDictionary *proof = [RR518TProof() mutableCopy];
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
    NSDictionary *summary = RR518SummaryFromProof(proof);
    assert([summary[@"firstNative"][@"received"] boolValue]);
    assert(![summary[@"lastNative"][@"received"] boolValue]);
    assert(![summary[@"firstNative"][@"pfDisabled"] boolValue]);
    assert(RR518IntegerEqual(summary[@"firstNative"][@"nativeExitStatus"], 3));
    assert(RR518IntegerEqual(summary[@"ownedGIDProof"][@"matchingProcessCount"], 0));
    assert(RR518IntegerEqual(summary[@"ownedGIDProof"][@"unreadableProcessCount"], 1));
    assert([summary[@"ownedGIDProof"][@"diagnosticStage"] isEqual:@"SYSCTL_SUPPLEMENTARY"]);
    assert([summary[@"ownedGIDProof"][@"readerFailure"] isEqual:@"GROUP_CAPACITY"] && RR518IntegerEqual(summary[@"ownedGIDProof"][@"observedGroupCount"], 17));
    assert(isBool(summary[@"ownedGIDProof"][@"groupCapacityVerified"]) && [summary[@"ownedGIDProof"][@"groupCapacityVerified"] boolValue]);
    assert(RR518IntegerEqual(summary[@"ownedGIDProof"][@"runtimeGroupCapacity"], NGROUPS));
    assert(RR518IntegerEqual(summary[@"ownedGIDProof"][@"zombieCredentialChecks"], 2));
    NSMutableDictionary *report = RR518Report(true); report[@"diagnosticStage"] = @"FRESH_PREFLIGHT"; report[@"preflightSummary"] = summary;
    RR518TReport(report); assert(!RR518ExitSuccess(report)); assert(!RR518ProofValid(proof));
    NSDictionary *spec = RR518SummarySpec();
    for (NSString *section in summary) {
        for (NSString *key in [spec[section][@"bools"] arrayByAddingObject:@"received"]) if (summary[section][key]) assert(isBool(summary[section][key]));
        for (NSString *key in spec[section][@"counts"]) if (summary[section][key]) assert(!isBool(summary[section][key]) && !CFNumberIsFloatType((__bridge CFNumberRef)summary[section][key]));
    }
    NSDictionary *malformed = RR518SanitizeSummary(@{@"PRIVATE_UNKNOWN_ENTRY": @{@"ok": @YES},
        @"firstNative": @{@"ok": @1, @"pfDisabled": @"true", @"nativeExitStatus": @256, @"pid": @999},
        @"recordedProcesses": @{@"controlledProcessesGone": @1, @"recordedProcessCount": @YES,
            @"absentPIDsDoubleChecked": @11.0, @"liveRecordedPIDs": @(-1), @"birthMismatches": @65},
        @"ownedGIDProof": @{@"attemptCount": @4, @"unreadableProcessCount": @32769,
            @"diagnosticStage": @"PRIVATE_UNKNOWN_ENTRY", @"readerFailure": @999, @"errnoClass": @"PRIVATE_UNKNOWN_ENTRY"}});
    assert([malformed[@"firstNative"] count] == 0 && [malformed[@"recordedProcesses"] count] == 0 && [malformed[@"ownedGIDProof"] count] == 0);
    assert(!malformed[@"PRIVATE_UNKNOWN_ENTRY"]);
    assert([RR518SummaryFromProof(nil) count] == 0);
    assert(!RR518SummaryFromProof(@{})[@"checks"][@"rootPFDisabled"]); // Missing evidence is never synthesized as success.
    NSMutableDictionary *gid = [@{@"schema": @"envara.macos-pf-gid-proof/v1", @"realmCount": @2,
        @"matchingProcessCount": @0, @"unreadableProcessCount": @0, @"unstableProcessCount": @0,
        @"sdkGroupCapacity": @(NGROUPS), @"runtimeGroupCapacity": @(NGROUPS)} mutableCopy];
    for (NSString *key in @[@"readOnly", @"recordIdentityVerified", @"rootCallerVerified", @"groupLookupComplete", @"groupsAbsent",
        @"processEnumerationComplete", @"processIdentitiesStable", @"supplementaryGroupsCovered", @"snapshotStable", @"allOwnedGIDProcessesAbsent", @"groupCapacityVerified"]) gid[key] = @YES;
    assert(RR518GIDProofValid(gid)); gid[@"groupCapacityVerified"] = @1; assert(!RR518GIDProofValid(gid));
    gid[@"groupCapacityVerified"] = @YES; gid[@"runtimeGroupCapacity"] = @YES; assert(!RR518GIDProofValid(gid));
    gid[@"runtimeGroupCapacity"] = @(NGROUPS-1); assert(!RR518GIDProofValid(gid));
    [gid removeObjectForKey:@"runtimeGroupCapacity"]; assert(!RR518GIDProofValid(gid));
}
int main(void) { @autoreleasepool {
    RR518TCarrierPaths(); RR518TStrictProcessesAndExit(); RR518TDiagnosticSummary();
    RR518TSuccess(); RR518TBadProof(); RR518TBadSource(); RR518TExistingCapsule(); RR518TFaults(); RR518TBeforeRename();
    puts("Runtime retirement inert fixture tests passed; only owned temporary fixtures were archived, without root/system activation.");
    return 0;
} }
