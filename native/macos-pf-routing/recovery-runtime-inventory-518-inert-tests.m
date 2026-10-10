/* INERT fixture tests. Source only until root explicitly compiles/runs them.
 * The future harness creates and removes only its own mkdtemp tree. It never
 * installs, authorizes, activates PF, probes a process, or uses a system path.
 * The inspector is included as a standalone header, without its CLI source. */
#define ENVARA_RECOVERY_INVENTORY_INERT_TEST 1
#include "recovery-runtime-inventory-518.h"
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

static NSString *const E518Run = @"0a00377a-0829-49f4-93d6-29a665e5c06b";
static NSString *const E518Anchor = @"io.envara.pf.root.v1";
static NSString *const E518RealmA = @"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
static NSString *const E518RealmB = @"cccccccc-cccc-4ccc-8ccc-cccccccccccc";

static NSData *E518JSON(id object) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:NULL];
    assert(data); return data;
}
static NSDictionary *E518Record(void) {
    return @{@"schema": @"envara.macos-pf-owned-registry/v1", @"runId": E518Run,
        @"anchor": E518Anchor, @"supervisorPid": @999,
        @"realms": @[@{@"realmId": E518RealmA}, @{@"realmId": E518RealmB}]};
}
static NSDictionary *E518Lock(void) {
    return @{@"runId": E518Run, @"pid": @999, @"anchor": E518Anchor};
}
static void E518Write(NSString *filename, NSData *data, BOOL replace) {
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
static NSData *E518Text(NSString *text) { return [text dataUsingEncoding:NSUTF8StringEncoding]; }
static void E518Directory(NSString *directory) {
    assert(mkdir(directory.fileSystemRepresentation, 0700) == 0);
    assert(chmod(directory.fileSystemRepresentation, 0700) == 0);
}
static NSDictionary *E518Fixture(void) {
    char temporary[PATH_MAX];
    NSString *pattern = [NSTemporaryDirectory() stringByAppendingPathComponent:@"envara-runtime-inventory-518-inert-XXXXXX"];
    int length = snprintf(temporary, sizeof(temporary), "%s", pattern.fileSystemRepresentation);
    assert(length > 0 && (size_t)length < sizeof(temporary));
    assert(mkdtemp(temporary));
    NSString *parent = [NSString stringWithUTF8String:temporary];
    assert(chmod(temporary, 0700) == 0);
    NSString *runtime = [parent stringByAppendingPathComponent:@"runtime"];
    NSString *run = [runtime stringByAppendingPathComponent:E518Run];
    NSArray *realms = @[[run stringByAppendingPathComponent:E518RealmA], [run stringByAppendingPathComponent:E518RealmB]];
    E518Directory(runtime); E518Directory(run);
    for (NSString *realm in realms) E518Directory(realm);
    // Deliberately invalid JSON: registry content is not part of this inspection.
    E518Write([runtime stringByAppendingPathComponent:@"registry.json"], E518Text(@"UNPARSED_REGISTRY_PRIVATE_SENTINEL\n"), NO);
    E518Write([runtime stringByAppendingPathComponent:@"registry.lock"], E518JSON(E518Lock()), NO);
    int fd = open(runtime.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    assert(fd >= 0);
    return @{@"parent": parent, @"runtime": runtime, @"run": run, @"realms": realms, @"fd": @(fd)};
}
static void E518Destroy(NSDictionary *fixture) {
    assert(close([fixture[@"fd"] intValue]) == 0);
    assert([[NSFileManager defaultManager] removeItemAtPath:fixture[@"parent"] error:NULL]);
}

// Snapshot the owned fixture, including unknown entries. This test helper reads
// only its fixture files; it does not grant the inspector permission to do so.
static void E518SnapshotVisit(NSString *filename, NSString *relative, NSMutableDictionary *snapshot) {
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
            E518SnapshotVisit([filename stringByAppendingPathComponent:name], [relative stringByAppendingPathComponent:name], snapshot);
        }
        assert(closedir(directory) == 0);
    }
}
static NSDictionary *E518Snapshot(NSDictionary *fixture) {
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionary];
    E518SnapshotVisit(fixture[@"parent"], @"", snapshot); return snapshot;
}
static void E518Contract(NSDictionary *report) {
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
    NSString *output = [[NSString alloc] initWithData:E518JSON(report) encoding:NSUTF8StringEncoding];
    for (NSString *privateText in @[@"UNPARSED_REGISTRY_PRIVATE_SENTINEL", @"PRIVATE_ROOT_ENTRY", @"PRIVATE_RUN_ENTRY",
        @"PRIVATE_REALM_ENTRY", @"PRIVATE_NESTED_ENTRY", @"transport-config.json", E518Run, E518Anchor, E518RealmA, E518RealmB]) {
        assert([output rangeOfString:privateText].location == NSNotFound);
    }
}
static NSDictionary *E518Inspect(NSDictionary *fixture, NSDictionary *record) {
    NSDictionary *before = E518Snapshot(fixture);
    NSDictionary *report = EnvaraInspectRuntimeInventory518ForTest([fixture[@"fd"] intValue], record, getuid(), getgid());
    E518Contract(report); assert([before isEqualToDictionary:E518Snapshot(fixture)]); return report;
}
static void E518Refused(NSDictionary *report) {
    assert(![report[@"exactInventoryVerified"] boolValue]);
    assert([report[@"reason"] isEqual:@"FIXED_RUNTIME_INVENTORY_REFUSED"]);
}
static void E518Unknown(NSDictionary *report, NSUInteger root, NSUInteger run, NSUInteger realm, NSUInteger unknown) {
    E518Refused(report); assert([report[@"unknownEntriesObserved"] boolValue]);
    assert([report[@"inventoryComplete"] boolValue]);
    assert([report[@"runtimeEntryCount"] unsignedIntegerValue] == root);
    assert([report[@"runEntryCount"] unsignedIntegerValue] == run);
    assert([report[@"realmEntryCount"] unsignedIntegerValue] == realm);
    assert([report[@"unknownEntryCount"] unsignedIntegerValue] == unknown);
    assert([report[@"missingEntryCount"] unsignedIntegerValue] == 0);
}
static void E518TestValid(void) {
    NSDictionary *fixture = E518Fixture(), *report = E518Inspect(fixture, E518Record());
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
    E518Destroy(fixture);
}
static void E518TestLock(void) {
    NSDictionary *fixture = E518Fixture();
    NSMutableDictionary *wrongRun = [E518Lock() mutableCopy]; wrongRun[@"runId"] = @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    NSMutableDictionary *wrongPID = [E518Lock() mutableCopy]; wrongPID[@"pid"] = @1000;
    NSMutableDictionary *wrongAnchor = [E518Lock() mutableCopy]; wrongAnchor[@"anchor"] = @"io.envara.pf.private-wrong-anchor";
    NSMutableDictionary *extra = [E518Lock() mutableCopy]; extra[@"extra"] = @"PRIVATE_LOCK_EXTRA";
    NSMutableData *nulWhitespace = [E518JSON(E518Lock()) mutableCopy];
    const unsigned char zero = 0; [nulWhitespace appendBytes:&zero length:1];
    NSArray *invalid = @[E518Text(@"{"), E518JSON(wrongRun), E518JSON(wrongPID), E518JSON(wrongAnchor), E518JSON(extra),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\"}", E518Run, E518Run, E518Anchor]),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"pid\":999,\"anchor\":\"%@\"}", E518Run, E518Anchor]),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999,\"anchor\":\"%@\",\"anchor\":\"%@\"}", E518Run, E518Anchor, E518Anchor]),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":true,\"anchor\":\"%@\"}", E518Run, E518Anchor]),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.5,\"anchor\":\"%@\"}", E518Run, E518Anchor]),
        E518Text([NSString stringWithFormat:@"{\"runId\":\"%@\",\"pid\":999.0,\"anchor\":\"%@\"}", E518Run, E518Anchor]),
        nulWhitespace, E518JSON(@[])];
    for (NSData *bytes in invalid) {
        E518Write([fixture[@"runtime"] stringByAppendingPathComponent:@"registry.lock"], bytes, YES);
        NSDictionary *report = E518Inspect(fixture, E518Record());
        E518Refused(report); assert(![report[@"lockRecordVerified"] boolValue]);
    }
    E518Destroy(fixture);
}
static void E518TestUnknown(void) {
    for (NSUInteger level = 0; level < 3; level++) {
        NSDictionary *fixture = E518Fixture();
        NSString *directory = level == 0 ? fixture[@"runtime"] : level == 1 ? fixture[@"run"] : fixture[@"realms"][0];
        NSString *name = level == 0 ? @"PRIVATE_ROOT_ENTRY" : level == 1 ? @"PRIVATE_RUN_ENTRY" : @"transport-config.json";
        E518Write([directory stringByAppendingPathComponent:name], E518Text(@"PRIVATE_REALM_ENTRY_CONTENT"), NO);
        E518Unknown(E518Inspect(fixture, E518Record()), level == 0 ? 4 : 3, level == 1 ? 3 : 2, level == 2 ? 1 : 0, 1);
        E518Destroy(fixture);
    }
    NSDictionary *fixture = E518Fixture();
    E518Write([fixture[@"runtime"] stringByAppendingPathComponent:@"PRIVATE_ROOT_ENTRY"], E518Text(@"private"), NO);
    E518Write([fixture[@"run"] stringByAppendingPathComponent:@"PRIVATE_RUN_ENTRY"], E518Text(@"private"), NO);
    E518Write([fixture[@"realms"][0] stringByAppendingPathComponent:@"PRIVATE_REALM_ENTRY"], E518Text(@"private"), NO);
    E518Write([fixture[@"realms"][1] stringByAppendingPathComponent:@"transport-config.json"], E518Text(@"private"), NO);
    NSString *unknownDirectory = [fixture[@"realms"][1] stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY"];
    E518Directory(unknownDirectory);
    E518Write([unknownDirectory stringByAppendingPathComponent:@"PRIVATE_NESTED_ENTRY_CHILD"], E518Text(@"private"), NO);
    E518Unknown(E518Inspect(fixture, E518Record()), 4, 3, 3, 5);
    E518Destroy(fixture);
}
static void E518TestMetadata(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", E518Run, [E518Run stringByAppendingPathComponent:E518RealmA], @""]) {
        NSDictionary *fixture = E518Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        assert(chmod(filename.fileSystemRepresentation, [relative hasSuffix:@".json"] || [relative hasSuffix:@".lock"] ? 0644 : 0755) == 0);
        E518Refused(E518Inspect(fixture, E518Record())); E518Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = E518Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        NSString *otherLink = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-hardlink-copy"];
        assert(link(filename.fileSystemRepresentation, otherLink.fileSystemRepresentation) == 0);
        E518Refused(E518Inspect(fixture, E518Record())); E518Destroy(fixture);
    }
    for (NSString *name in @[@"registry.json", @"registry.lock"]) {
        NSDictionary *fixture = E518Fixture(); NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:name];
        assert(unlink(filename.fileSystemRepresentation) == 0); assert(mkfifo(filename.fileSystemRepresentation, 0600) == 0);
        E518Refused(E518Inspect(fixture, E518Record())); E518Destroy(fixture);
    }
}
static void E518TestSymlinksAndMissing(void) {
    for (NSString *relative in @[@"registry.json", @"registry.lock", E518Run, [E518Run stringByAppendingPathComponent:E518RealmA]]) {
        NSDictionary *fixture = E518Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-symlink-target"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        assert(symlink(saved.fileSystemRepresentation, filename.fileSystemRepresentation) == 0);
        E518Refused(E518Inspect(fixture, E518Record())); E518Destroy(fixture);
    }
    for (NSString *relative in @[@"registry.json", @"registry.lock", E518Run, [E518Run stringByAppendingPathComponent:E518RealmA]]) {
        NSDictionary *fixture = E518Fixture();
        NSString *filename = [fixture[@"runtime"] stringByAppendingPathComponent:relative];
        NSString *saved = [fixture[@"parent"] stringByAppendingPathComponent:@"owned-missing-entry-backup"];
        assert(rename(filename.fileSystemRepresentation, saved.fileSystemRepresentation) == 0);
        NSDictionary *report = E518Inspect(fixture, E518Record());
        E518Refused(report); assert([report[@"missingEntryCount"] unsignedIntegerValue] > 0);
        E518Destroy(fixture);
    }
}
static void E518TestRecord(void) {
    NSDictionary *fixture = E518Fixture();
    for (NSArray *change in @[@[@"schema", @"wrong-schema"], @[@"runId", @"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        @[@"anchor", @"wrong-anchor"], @[@"supervisorPid", @YES], @[@"supervisorPid", @999.5], @[@"supervisorPid", @(-1)],
        @[@"realms", @[@{@"realmId": E518RealmA}, @{@"realmId": E518RealmA}]],
        @[@"realms", @[@{@"realmId": @"not-a-uuid"}]],
        @[@"realms", @[@{@"realmId": [E518RealmA stringByAppendingString:@"\n"]}]],
        @[@"realms", @[@{@"realmId": E518RealmA}, @{@"realmId": E518RealmB}, @{@"realmId": @"dddddddd-dddd-4ddd-8ddd-dddddddddddd"}]],
        @[@"realms", @[@{@"realmId": @999}]], @[@"realms", @"not-an-array"]]) {
        NSMutableDictionary *record = [E518Record() mutableCopy]; record[change[0]] = change[1];
        NSDictionary *report = E518Inspect(fixture, record);
        E518Refused(report); assert(![report[@"recordIdentityVerified"] boolValue]);
    }
    E518Destroy(fixture);
}
int main(void) { @autoreleasepool {
    // Check the production entry signature without invoking its root-only path.
    NSDictionary *(*productionEntry)(int, NSDictionary *) = EnvaraInspectRuntimeInventory518; (void)productionEntry;
    E518TestValid(); E518TestLock(); E518TestUnknown(); E518TestMetadata(); E518TestSymlinksAndMissing(); E518TestRecord();
    puts("Runtime inventory inert fixture tests passed; no installation, authorization, PF activation, or process inspection performed.");
    return 0;
} }
