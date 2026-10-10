/* INERT fixture tests. Source only until root explicitly compiles/runs them.
 * The future harness creates and removes only its own mkdtemp tree. It never
 * installs, authorizes, activates PF, probes a process, or uses a system path.
 * The inspector is included as a standalone header, without its CLI source. */
#define ENVARA_RECOVERY_INVENTORY_INERT_TEST 1
#include "recovery-runtime-inventory-ff9-run4fe.h"
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const EFF9Run = @"4fe07677-cbdb-4273-9b45-a1ecae8e6444";
static NSString *const EFF9Anchor = @"io.envara.pf.run.4fe07677-cbdb-4273-9b45-a1ecae8e6444";
static NSString *const EFF9RealmA = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
static NSString *const EFF9RealmB = @"cccccccc-cccc-4ccc-8ccc-cccccccccccc";

static NSData *EFF9JSON(id object) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:NULL];
    assert(data); return data;
}
static NSDictionary *EFF9Record(void) {
    return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": EFF9Run,
        @"anchor": EFF9Anchor, @"supervisorPid": @999,
        @"realms": @[@{@"realmId": EFF9RealmA}, @{@"realmId": EFF9RealmB}]};
}
static NSDictionary *EFF9Lock(void) {
    return @{@"runId": EFF9Run, @"pid": @999, @"anchor": EFF9Anchor};
}
static void EFF9Write(NSString *filename, NSData *data, BOOL replace) {
    int fd = open(filename.fileSystemRepresentation,
        O_WRONLY | O_NOFOLLOW | (replace ? O_TRUNC : O_CREAT | O_EXCL), 0600);
    assert(fd >= 0);
    const unsigned char *bytes = data.bytes; size_t written = 0;
    while (written < data.length) {
        ssize_t count = write(fd, bytes + written, data.length - written);
        assert(count > 0); written += (size_t)count;
    }
    assert(close(fd) == 0);
}
static NSData *EFF9Text(NSString *text) { return [text dataUsingEncoding:NSUTF8StringEncoding]; }
static void EFF9Directory(NSString *directory) {
    assert(mkdir(directory.fileSystemRepresentation, 0700) == 0);
    assert(chmod(directory.fileSystemRepresentation, 0700) == 0);
}
static NSDictionary *EFF9Fixture(void) {
    char temporary[PATH_MAX];
    NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"envara-runtime-inventory-FF9-inert-XXXXXX"];
    int length = snprintf(temporary, sizeof(temporary), "%s", pattern.fileSystemRepresentation);
    assert(length > 0 && (size_t)length < sizeof(temporary));
    assert(mkdtemp(temporary));
    NSString *parent = [NSString stringWithUTF8String:temporary];
    assert(chmod(temporary, 0700) == 0);
    NSString *runtime = [parent stringByAppendingPathComponent:@"runtime"];
    NSString *run = [runtime stringByAppendingPathComponent:EFF9Run];
    NSArray *realms = @[[run stringByAppendingPathComponent:EFF9RealmA], [run stringByAppendingPathComponent:EFF9RealmB]];
    EFF9Directory(runtime); EFF9Directory(run);
    for (NSString *realm in realms) EFF9Directory(realm);
    // Deliberately invalid JSON: registry content is not part of this inspection.
    EFF9Write([runtime stringByAppendingPathComponent:@"registry.json"], EFF9Text(@"UNPARSED_REGISTRY_PRIVATE_SENTINEL\n"), NO);
    EFF9Write([runtime stringByAppendingPathComponent:@"registry.lock"], EFF9JSON(EFF9Lock()), NO);
    int fd = open(runtime.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    assert(fd >= 0);
    return @{@"parent": parent, @"runtime": runtime, @"run": run, @"realms": realms, @"fd": @(fd)};
}
static void EFF9Destroy(NSDictionary *fixture) {
    assert(close([fixture[@"fd"] intValue]) == 0);
    assert([[NSFileManager defaultManager] removeItemAtPath:fixture[@"parent"] error:NULL]);
}

// Snapshot the owned fixture, including unknown entries. This test helper reads
// only its fixture files; it does not grant the inspector permission to do so.
static void EFF9SnapshotVisit(NSString *filename, NSString *relative, NSMutableDictionary *snapshot) {
    struct stat info; assert(lstat(filename.fileSystemRepresentation, &info) == 0);
    NSMutableDictionary *row = [@{@"mode": @((unsigned int)info.st_mode), @"uid": @((unsigned int)info.st_uid),
        @"gid": @((unsigned int)info.st_gid), @"links": @((unsigned long long)info.st_nlink),
        @"device": @((unsigned long long)info.st_dev), @"inode": @((unsigned long long)info.st_ino),
        @"size": @((long long)info.st_size)} mutableCopy];
    if (S_ISREG(info.st_mode)) {
        int fd = open(filename.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW); assert(fd >= 0);
        NSMutableData *contents = [NSMutableData data]; unsigned char buffer[4096]; ssize_t count;
        while ((count = read(fd, buffer, sizeof(buffer))) > 0) [contents appendBytes:buffer length:(NSUInteger)count];
        assert(count == 0); assert(close(fd) == 0); row[@"contents"] = contents;
    } else if (S_ISLNK(info.st_mode)) {
        char target[PATH_MAX]; ssize_t length = readlink(filename.fileSystemRepresentation, target, sizeof(target));
        assert(length >= 0 && (size_t)length < sizeof(target));
        row[@"link"] = [NSData dataWithBytes:target length:(NSUInteger)length];
    }
    snapshot[relative] = row;
    if (S_ISDIR(info.st_mode)) {
        DIR *directory = opendir(filename.fileSystemRepresentation); assert(directory);
        struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            NSString *name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:entry->d_name length:strlen(entry->d_name)];
            assert(name);
            EFF9SnapshotVisit([filename stringByAppendingPathComponent:name], [relative stringByAppendingPathComponent:name], snapshot);
        }
        assert(closedir(directory) == 0);
    }
}
static NSDictionary *EFF9Snapshot(NSDictionary *fixture) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    EFF9SnapshotVisit(fixture[@"parent"], @"", snapshot); return snapshot;
}
static void EFF9Contract(NSDictionary *report) {
    assert([report isKindOfClass:[NSDictionary class]]);
    NSArray *booleanKeys = @[@"readOnly", @"cleanupConfirmed", @"productionReady", @"recordIdentityVerified",
        @"runtimeDirectoryVerified", @"registryFileVerified", @"lockFileVerified", @"lockRecordVerified",
        @"runDirectoryVerified", @"realmDirectoriesVerified", @"identitiesStable", @"inventoryComplete",
        @"exactInventoryVerified", @"unknownEntriesObserved", @"tamperingObserved", @"runtimeEmpty", @"runEmpty", @"realmContentsEmpty"];
    NSArray *countKeys = @[@"expectedRealmCount", @"runtimeEntryCount", @"runEntryCount", @"realmEntryCount", @"unknownEntryCount", @"missingEntryCount"];
    NSMutableSet *allowed = [NSMutableSet setWithArray:booleanKeys];
    [allowed addObjectsFromArray:countKeys]; [allowed addObjectsFromArray:@[@"schema", @"inventorySHA256", @"reason"]];
    assert([[NSSet setWithArray:report.allKeys] isEqualToSet:allowed]);
    assert([report[@"schema"] isEqual:@"envara.macos-pf-runtime-inventory/v1"]);
    for (NSString *key in booleanKeys) {
        id value = report[key]; assert(value);
        assert(CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID());
    }
    for (NSString *key in countKeys) {
        id value = report[key]; assert([value isKindOfClass:[NSNumber class]]);
        assert(CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID());
        assert([value longLongValue] >= 0);
    }
    assert([report[@"readOnly"] boolValue]);
    assert(![report[@"cleanupConfirmed"] boolValue]); assert(![report[@"productionReady"] boolValue]);
    NSString *digest = report[@"inventorySHA256"];
    assert([digest isKindOfClass:[NSString class]] && digest.length == 64);
    assert([digest rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location == NSNotFound);
    assert([report[@"reason"] isEqual:@"READ_ONLY_FIXED_RUNTIME_INVENTORY"] || [report[@"reason"] isEqual:@"FIXED_RUNTIME_INVENTORY_REFUSED"]);
    NSString *output = [[NSString alloc] initWithData:EFF9JSON(report) encoding:NSUTF8StringEncoding];
    for (NSString *privateText in @[@"UNPARSED_REGISTRY_PRIVATE_SENTINEL", @"PRIVATE_ROOT_ENTRY", @"PRIVATE_RUN_ENTRY",
        @"PRIVATE_REALM_ENTRY", @"PRIVATE_NESTED_ENTRY", @"transport-config.json", EFF9Run, EFF9Anchor, EFF9RealmA, EFF9RealmB]) {
        assert([output rangeOfString:privateText].location == NSNotFound);
    }
}
static NSDictionary *EFF9Inspect(NSDictionary *fixture, NSDictionary *record) {
    NSDictionary *before = EFF9Snapshot(fixture);
    NSDictionary *report = EnvaraInspectRuntimeInventoryFF9ForTest([fixture[@"fd"] intValue], record, getuid(), getgid());
    EFF9Contract(report); assert([before isEqualToDictionary:EFF9Snapshot(fixture)]); return report;
}
static void EFF9Refused(NSDictionary *report) {
    assert(![report[@"exactInventoryVerified"] boolValue]);
    assert([report[@"reason"] isEqual:@"FIXED_RUNTIME_INVENTORY_REFUSED"]);
}
static void EFF9Unknown(NSDictionary *report, NSUInteger root, NSUInteger run, NSUInteger realm, NSUInteger unknown) {
    EFF9Refused(report); assert([report[@"unknownEntriesObserved"] boolValue]);
    assert([report[@"inventoryComplete"] boolValue]);
    assert([report[@"runtimeEntryCount"] unsignedIntegerValue] == root);
    assert([report[@"runEntryCount"] unsignedIntegerValue] == run);
    assert([report[@"realmEntryCount"] unsignedIntegerValue] == realm);
    assert([report[@"unknownEntryCount"] unsignedIntegerValue] == unknown);
    assert([report[@"missingEntryCount"] unsignedIntegerValue] == 0);
}
static void EFF9TestValid(void) {
    NSDictionary *fixture = EFF9Fixture(), *report = EFF9Inspect(fixture, EFF9Record());
    for (NSString *key in @[@"recordIdentityVerified", @"runtimeDirectoryVerified", @"registryFileVerified", @"lockFileVerified",
        @"lockRecordVerified", @"runDirectoryVerified", @"realmDirectoriesVerified", @"identitiesStable", @"inventoryComplete", @"exactInventoryVerified", @"realmContentsEmpty"])
        assert([report[key] boolValue]);
    for (NSString *key in @[@"unknownEntriesObserved", @"tamperingObserved", @"runtimeEmpty", @"runEmpty"])
        assert(![report[key] boolValue]);
    assert([report[@"reason"] isEqual:@"READ_ONLY_FIXED_RUNTIME_INVENTORY"]);
    assert([report[@"expectedRealmCount"] unsignedIntegerValue] == 2);
    assert([report[@"runtimeEntryCount"] unsignedIntegerValue] == 3);
    assert([report[@"runEntryCount"] unsignedIntegerValue] == 2);
    assert([report[@"realmEntryCount"] unsignedIntegerValue] == 0);
    assert([report[@"unknownEntryCount"] unsignedIntegerValue] == 0);
    assert([report[@"missingEntryCount"] unsignedIntegerValue] == 0);
    EFF9Destroy(fixture);
}
static void EFF9TestLock(void) {
    NSDictionary *fixture = EFF9Fixture();
    NSMutableDictionary *wrongRun = [EFF9Lock() mutableCopy]; wrongRun[@"runId"] = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    NSMutableDictionary *wrongPID = [EFF9Lock() mutableCopy]; wrongPID[@"pid"] = @1000;
    NSMutableDictionary *wrongAnchor = [EFF9Lock() mutableCopy]; wrongAnchor[@"anchor"] = @"io.envara.pf.private-wrong-anchor";
    NSMutableDictionary *extra = [EFF9Lock() mutableCopy]; extra[@"extra"] = @"PRIVATE_LOCK_EXTRA";
    NSMutableData *nulWhitespace = [EFF9JSON(EFF9Lock()) mutableCopy];
    const unsigned char zero = 0; [nulWhitespace appendBytes:&zero length:1];
    NSArray *invalid = @[EFF9Text(@"{"), EFF9JSON(wrongRun), EFF9JSON(wrongPID), EFF9JSON(wrongAnchor), EFF9JSON(extra),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\"}", EFF9Run, EFF9Run, EFF9Anchor]),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"pid\":999,\"anchor\":\"%@\"}", EFF9Run, EFF9Anchor]),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\",\"anchor\":\"%@\"}", EFF9Run, EFF9Anchor, EFF9Anchor]),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":true,\"anchor\":\"%@\"}", EFF9Run, EFF9Anchor]),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.5,\"anchor\":\"%@\"}", EFF9Run, EFF9Anchor]),
        EFF9Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.0,\"anchor\":\"%@\"}", EFF9Run, EFF9Anchor]),
        nulWhitespace, EFF9JSON(@[])];
    for (NSData *bytes in invalid) {
        EFF9Write([fixture[@"runtime"] stringByAppendingPathComponent:@"registry.lock"], bytes, YES);
        NSDictionary *report = EFF9Inspect(fixture, EFF9Record());
        EFF9Refused(report); assert(![report[@"lockRecordVerified"] boolValue]);
    }
    EFF9Destroy(fixture);
}
static void EFF9TestUnknown(void) {
    for (NSUInteger level = 0; level < 3; level++) {
        NSDictionary *fixture = EFF9Fixture();
        NSString *directory = level == 0 ? fixture[@"runtime"] : level == 1 ? fixture[@"run"] : fixture[@"realms"][0];
        NSString *name = level == 0 ? @"PRIVATE_ROOT_ENTRY" : level == 1 ? @"PRIVATE_RUN_ENTRY" : @"transport-config.json";
        EFF9Write([directory stringByAppendingPathComponent:name], EFF9Text(@"PRIVATE_REALM_ENTRY_CONTENT"), NO);
        EFF9Unknown(EFF9Inspect(fixture, EFF9Record()), level == 0 ? 4 : 3, level == 1 ? 3 : 2, level == 2 ? 1 : 0, 1);
        EFF9Destroy(fixture);
    }
    NSDictionary *fixture = EFF9Fixture();
    EFF9Write([fixture[@"runtime"] stringByAppendingPathComponent:@"PRIVATE_ROOT_ENTRY"], EFF9Text(@"private"), NO);
    EFF9Write([fixture[@"run"] stringByAppendingPathComponent:@"PRIVATE_RUN_ENTRY"], EFF9Text(@"private"), NO);
    EFF9Write([fixture[@"realms"][0] stringByAppendingPathComponent:@"PRIVATE_REALM_ENTRY"], EFF9Text(@"private"), NO);
    EFF9Write([fixture[@"realms"][1] stringByAppendingPathComponent:@"transport-config.json"], EFF9Text(@"private"), NO);
    NSString *unknownDirectory = [fixture[@"realms"][1] stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY"];
    EFF9Directory(unknownDirectory);
    EFF9Write([unknownDirectory stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY_CHILD"], EFF9Text(@"private"), NO);
    EFF9Unknown(EFF9Inspect(fixture, EFF9Record()), 4, 3, 3, 5);
    EFF9Destroy(fixture);
}
static void EFF9TestMetadata(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", EFF9Run, [EFF9Run stringByAppendingPathComponent:EFF9RealmA], @""]) {
        NSDictionary *fixture = EFF9Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        assert(chmod(filename.fileSystemRepresentation, [relative hasSuffix:@".json"] || [relative hasSuffix:@".lock"] ? 0644 : 0755) == 0);
        EFF9Refused(EFF9Inspect(fixture, EFF9Record())); EFF9Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = EFF9Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        NSString *otherLink = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-hardlink-copy"];
        assert(link(filename.fileSystemRepresentation, otherLink.fileSystemRepresentation) == 0);
        EFF9Refused(EFF9Inspect(fixture, EFF9Record())); EFF9Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = EFF9Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        assert(unlink(filename.fileSystemRepresentation) == 0); assert(mkfifo(filename.fileSystemRepresentation, 0600) == 0);
        EFF9Refused(EFF9Inspect(fixture, EFF9Record())); EFF9Destroy(fixture);
    }
}
static void EFF9TestSymlinksAndMissing(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", EFF9Run, [EFF9Run stringByAppendingPathComponent:EFF9RealmA]]) {
        NSDictionary *fixture = EFF9Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-symlink-target"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        assert(symlink(saved.fileSystemRepresentation, filename.fileSystemRepresentation) == 0);
        EFF9Refused(EFF9Inspect(fixture, EFF9Record())); EFF9Destroy(fixture);
    }
    for (NSString *relative in @[@"registry.json", @"registry.lock", EFF9Run, [EFF9Run stringByAppendingPathComponent:EFF9RealmA]]) {
        NSDictionary *fixture = EFF9Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-missing-entry-backup"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        NSDictionary *report = EFF9Inspect(fixture, EFF9Record());
        EFF9Refused(report); assert([report[@"missingEntryCount"] unsignedIntegerValue] > 0);
        EFF9Destroy(fixture);
    }
}
static void EFF9TestRecord(void) {
    NSDictionary *fixture = EFF9Fixture();
    for (NSArray *change in @[@[@"schema", @"wrong-schema"], @[@"runId", @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        @[@"anchor", @"wrong-anchor"], @[@"supervisorPid", @YES], @[@"supervisorPid", @999.5], @[@"supervisorPid", @(-1)],
        @[@"realms", @[@{@"realmId": EFF9RealmA}, @{@"realmId": EFF9RealmA}]],
        @[@"realms", @[@{@"realmId": @"not-a-uuid"}]],
        @[@"realms", @[@{@"realmId": [EFF9RealmA stringByAppendingString:@"\n"]}]],
        @[@"realms", @[@{@"realmId": EFF9RealmA}, @{@"realmId": EFF9RealmB}, @{@"realmId": @"dddddddd-dddd-4ddd-8ddd-dddddddddddd"}]],
        @[@"realms", @[@{@"realmId": @999}]], @[@"realms", @"not-an-array"]]) {
        NSMutableDictionary *record = [EFF9Record() mutableCopy]; record[change[0]] = change[1];
        NSDictionary *report = EFF9Inspect(fixture, record);
        EFF9Refused(report); assert(![report[@"recordIdentityVerified"] boolValue]);
    }
    EFF9Destroy(fixture);
}
int main(void) { @autoreleasepool {
    // Check the production entry signature without invoking its root-only path.
    NSDictionary *(*productionEntry)(int, NSDictionary *) = EnvaraInspectRuntimeInventoryFF9; (void)productionEntry;
    EFF9TestValid(); EFF9TestLock(); EFF9TestUnknown(); EFF9TestMetadata(); EFF9TestSymlinksAndMissing(); EFF9TestRecord();
    puts("Runtime inventory inert fixture tests passed; no installation, authorization, PF activation, or process inspection performed.");
    return 0;
} }
