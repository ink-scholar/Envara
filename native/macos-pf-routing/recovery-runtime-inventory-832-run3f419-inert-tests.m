/* INERT fixture tests. Source only until root explicitly compiles/runs them.
 * The future harness creates and removes only its own mkdtemp tree. It never
 * installs, authorizes, activates PF, probes a process, or uses a system path.
 * The inspector is included as a standalone header, without its CLI source. */
#define ENVARA_RECOVERY_INVENTORY_INERT_TEST 1
#include "recovery-runtime-inventory-832-run3f419.h"
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

static NSString *const E832Run = @"3f419119-19e1-46d5-847e-fcd2d1ec1ed1";
static NSString *const E832Anchor = @"io.envara.pf.run.3f419119-19e1-46d5-847e-fcd2d1ec1ed1";
static NSString *const E832RealmA = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
static NSString *const E832RealmB = @"cccccccc-cccc-4ccc-8ccc-cccccccccccc";

static NSData *E832JSON(id object) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:NULL];
    assert(data); return data;
}
static NSDictionary *E832Record(void) {
    return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": E832Run,
        @"anchor": E832Anchor, @"supervisorPid": @999,
        @"realms": @[@{@"realmId": E832RealmA}, @{@"realmId": E832RealmB}]};
}
static NSDictionary *E832Lock(void) {
    return @{@"runId": E832Run, @"pid": @999, @"anchor": E832Anchor};
}
static void E832Write(NSString *filename, NSData *data, BOOL replace) {
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
static NSData *E832Text(NSString *text) { return [text dataUsingEncoding:NSUTF8StringEncoding]; }
static void E832Directory(NSString *directory) {
    assert(mkdir(directory.fileSystemRepresentation, 0700) == 0);
    assert(chmod(directory.fileSystemRepresentation, 0700) == 0);
}
static NSDictionary *E832Fixture(void) {
    char temporary[PATH_MAX];
    NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"envara-runtime-inventory-832-inert-XXXXXX"];
    int length = snprintf(temporary, sizeof(temporary), "%s", pattern.fileSystemRepresentation);
    assert(length > 0 && (size_t)length < sizeof(temporary));
    assert(mkdtemp(temporary));
    NSString *parent = [NSString stringWithUTF8String:temporary];
    assert(chmod(temporary, 0700) == 0);
    NSString *runtime = [parent stringByAppendingPathComponent:@"runtime"];
    NSString *run = [runtime stringByAppendingPathComponent:E832Run];
    NSArray *realms = @[[run stringByAppendingPathComponent:E832RealmA], [run stringByAppendingPathComponent:E832RealmB]];
    E832Directory(runtime); E832Directory(run);
    for (NSString *realm in realms) E832Directory(realm);
    // Deliberately invalid JSON: registry content is not part of this inspection.
    E832Write([runtime stringByAppendingPathComponent:@"registry.json"], E832Text(@"UNPARSED_REGISTRY_PRIVATE_SENTINEL\n"), NO);
    E832Write([runtime stringByAppendingPathComponent:@"registry.lock"], E832JSON(E832Lock()), NO);
    int fd = open(runtime.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    assert(fd >= 0);
    return @{@"parent": parent, @"runtime": runtime, @"run": run, @"realms": realms, @"fd": @(fd)};
}
static void E832Destroy(NSDictionary *fixture) {
    assert(close([fixture[@"fd"] intValue]) == 0);
    assert([[NSFileManager defaultManager] removeItemAtPath:fixture[@"parent"] error:NULL]);
}

// Snapshot the owned fixture, including unknown entries. This test helper reads
// only its fixture files; it does not grant the inspector permission to do so.
static void E832SnapshotVisit(NSString *filename, NSString *relative, NSMutableDictionary *snapshot) {
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
            E832SnapshotVisit([filename stringByAppendingPathComponent:name], [relative stringByAppendingPathComponent:name], snapshot);
        }
        assert(closedir(directory) == 0);
    }
}
static NSDictionary *E832Snapshot(NSDictionary *fixture) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    E832SnapshotVisit(fixture[@"parent"], @"", snapshot); return snapshot;
}
static void E832Contract(NSDictionary *report) {
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
    NSString *output = [[NSString alloc] initWithData:E832JSON(report) encoding:NSUTF8StringEncoding];
    for (NSString *privateText in @[@"UNPARSED_REGISTRY_PRIVATE_SENTINEL", @"PRIVATE_ROOT_ENTRY", @"PRIVATE_RUN_ENTRY",
        @"PRIVATE_REALM_ENTRY", @"PRIVATE_NESTED_ENTRY", @"transport-config.json", E832Run, E832Anchor, E832RealmA, E832RealmB]) {
        assert([output rangeOfString:privateText].location == NSNotFound);
    }
}
static NSDictionary *E832Inspect(NSDictionary *fixture, NSDictionary *record) {
    NSDictionary *before = E832Snapshot(fixture);
    NSDictionary *report = EnvaraInspectRuntimeInventory832ForTest([fixture[@"fd"] intValue], record, getuid(), getgid());
    E832Contract(report); assert([before isEqualToDictionary:E832Snapshot(fixture)]); return report;
}
static void E832Refused(NSDictionary *report) {
    assert(![report[@"exactInventoryVerified"] boolValue]);
    assert([report[@"reason"] isEqual:@"FIXED_RUNTIME_INVENTORY_REFUSED"]);
}
static void E832Unknown(NSDictionary *report, NSUInteger root, NSUInteger run, NSUInteger realm, NSUInteger unknown) {
    E832Refused(report); assert([report[@"unknownEntriesObserved"] boolValue]);
    assert([report[@"inventoryComplete"] boolValue]);
    assert([report[@"runtimeEntryCount"] unsignedIntegerValue] == root);
    assert([report[@"runEntryCount"] unsignedIntegerValue] == run);
    assert([report[@"realmEntryCount"] unsignedIntegerValue] == realm);
    assert([report[@"unknownEntryCount"] unsignedIntegerValue] == unknown);
    assert([report[@"missingEntryCount"] unsignedIntegerValue] == 0);
}
static void E832TestValid(void) {
    NSDictionary *fixture = E832Fixture(), *report = E832Inspect(fixture, E832Record());
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
    E832Destroy(fixture);
}
static void E832TestLock(void) {
    NSDictionary *fixture = E832Fixture();
    NSMutableDictionary *wrongRun = [E832Lock() mutableCopy]; wrongRun[@"runId"] = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    NSMutableDictionary *wrongPID = [E832Lock() mutableCopy]; wrongPID[@"pid"] = @1000;
    NSMutableDictionary *wrongAnchor = [E832Lock() mutableCopy]; wrongAnchor[@"anchor"] = @"io.envara.pf.private-wrong-anchor";
    NSMutableDictionary *extra = [E832Lock() mutableCopy]; extra[@"extra"] = @"PRIVATE_LOCK_EXTRA";
    NSMutableData *nulWhitespace = [E832JSON(E832Lock()) mutableCopy];
    const unsigned char zero = 0; [nulWhitespace appendBytes:&zero length:1];
    NSArray *invalid = @[E832Text(@"{"), E832JSON(wrongRun), E832JSON(wrongPID), E832JSON(wrongAnchor), E832JSON(extra),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\"}", E832Run, E832Run, E832Anchor]),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"pid\":999,\"anchor\":\"%@\"}", E832Run, E832Anchor]),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\",\"anchor\":\"%@\"}", E832Run, E832Anchor, E832Anchor]),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":true,\"anchor\":\"%@\"}", E832Run, E832Anchor]),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.5,\"anchor\":\"%@\"}", E832Run, E832Anchor]),
        E832Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.0,\"anchor\":\"%@\"}", E832Run, E832Anchor]),
        nulWhitespace, E832JSON(@[])];
    for (NSData *bytes in invalid) {
        E832Write([fixture[@"runtime"] stringByAppendingPathComponent:@"registry.lock"], bytes, YES);
        NSDictionary *report = E832Inspect(fixture, E832Record());
        E832Refused(report); assert(![report[@"lockRecordVerified"] boolValue]);
    }
    E832Destroy(fixture);
}
static void E832TestUnknown(void) {
    for (NSUInteger level = 0; level < 3; level++) {
        NSDictionary *fixture = E832Fixture();
        NSString *directory = level == 0 ? fixture[@"runtime"] : level == 1 ? fixture[@"run"] : fixture[@"realms"][0];
        NSString *name = level == 0 ? @"PRIVATE_ROOT_ENTRY" : level == 1 ? @"PRIVATE_RUN_ENTRY" : @"transport-config.json";
        E832Write([directory stringByAppendingPathComponent:name], E832Text(@"PRIVATE_REALM_ENTRY_CONTENT"), NO);
        E832Unknown(E832Inspect(fixture, E832Record()), level == 0 ? 4 : 3, level == 1 ? 3 : 2, level == 2 ? 1 : 0, 1);
        E832Destroy(fixture);
    }
    NSDictionary *fixture = E832Fixture();
    E832Write([fixture[@"runtime"] stringByAppendingPathComponent:@"PRIVATE_ROOT_ENTRY"], E832Text(@"private"), NO);
    E832Write([fixture[@"run"] stringByAppendingPathComponent:@"PRIVATE_RUN_ENTRY"], E832Text(@"private"), NO);
    E832Write([fixture[@"realms"][0] stringByAppendingPathComponent:@"PRIVATE_REALM_ENTRY"], E832Text(@"private"), NO);
    E832Write([fixture[@"realms"][1] stringByAppendingPathComponent:@"transport-config.json"], E832Text(@"private"), NO);
    NSString *unknownDirectory = [fixture[@"realms"][1] stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY"];
    E832Directory(unknownDirectory);
    E832Write([unknownDirectory stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY_CHILD"], E832Text(@"private"), NO);
    E832Unknown(E832Inspect(fixture, E832Record()), 4, 3, 3, 5);
    E832Destroy(fixture);
}
static void E832TestMetadata(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", E832Run, [E832Run stringByAppendingPathComponent:E832RealmA], @""]) {
        NSDictionary *fixture = E832Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        assert(chmod(filename.fileSystemRepresentation, [relative hasSuffix:@".json"] || [relative hasSuffix:@".lock"] ? 0644 : 0755) == 0);
        E832Refused(E832Inspect(fixture, E832Record())); E832Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = E832Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        NSString *otherLink = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-hardlink-copy"];
        assert(link(filename.fileSystemRepresentation, otherLink.fileSystemRepresentation) == 0);
        E832Refused(E832Inspect(fixture, E832Record())); E832Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = E832Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        assert(unlink(filename.fileSystemRepresentation) == 0); assert(mkfifo(filename.fileSystemRepresentation, 0600) == 0);
        E832Refused(E832Inspect(fixture, E832Record())); E832Destroy(fixture);
    }
}
static void E832TestSymlinksAndMissing(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", E832Run, [E832Run stringByAppendingPathComponent:E832RealmA]]) {
        NSDictionary *fixture = E832Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-symlink-target"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        assert(symlink(saved.fileSystemRepresentation, filename.fileSystemRepresentation) == 0);
        E832Refused(E832Inspect(fixture, E832Record())); E832Destroy(fixture);
    }
    for (NSString *relative in @[@"registry.json", @"registry.lock", E832Run, [E832Run stringByAppendingPathComponent:E832RealmA]]) {
        NSDictionary *fixture = E832Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-missing-entry-backup"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        NSDictionary *report = E832Inspect(fixture, E832Record());
        E832Refused(report); assert([report[@"missingEntryCount"] unsignedIntegerValue] > 0);
        E832Destroy(fixture);
    }
}
static void E832TestRecord(void) {
    NSDictionary *fixture = E832Fixture();
    for (NSArray *change in @[@[@"schema", @"wrong-schema"], @[@"runId", @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        @[@"anchor", @"wrong-anchor"], @[@"supervisorPid", @YES], @[@"supervisorPid", @999.5], @[@"supervisorPid", @(-1)],
        @[@"realms", @[@{@"realmId": E832RealmA}, @{@"realmId": E832RealmA}]],
        @[@"realms", @[@{@"realmId": @"not-a-uuid"}]],
        @[@"realms", @[@{@"realmId": [E832RealmA stringByAppendingString:@"\n"]}]],
        @[@"realms", @[@{@"realmId": E832RealmA}, @{@"realmId": E832RealmB}, @{@"realmId": @"dddddddd-dddd-4ddd-8ddd-dddddddddddd"}]],
        @[@"realms", @[@{@"realmId": @999}]], @[@"realms", @"not-an-array"]]) {
        NSMutableDictionary *record = [E832Record() mutableCopy]; record[change[0]] = change[1];
        NSDictionary *report = E832Inspect(fixture, record);
        E832Refused(report); assert(![report[@"recordIdentityVerified"] boolValue]);
    }
    E832Destroy(fixture);
}
int main(void) { @autoreleasepool {
    // Check the production entry signature without invoking its root-only path.
    NSDictionary *(*productionEntry)(int, NSDictionary *) = EnvaraInspectRuntimeInventory832; (void)productionEntry;
    E832TestValid(); E832TestLock(); E832TestUnknown(); E832TestMetadata(); E832TestSymlinksAndMissing(); E832TestRecord();
    puts("Runtime inventory inert fixture tests passed; no installation, authorization, PF activation, or process inspection performed.");
    return 0;
} }
