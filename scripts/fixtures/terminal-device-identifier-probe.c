// Local feasibility probe. Hardware values stay in memory and are never formatted.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOReturn.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <gethostuuid.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static const char *b(bool value) { return value ? "true" : "false"; }
static void wipe(void *pointer, size_t length) { volatile unsigned char *bytes = pointer; while (length--) *bytes++ = 0; }
static bool denied_errno(int result) { return result != 0 && (errno == EPERM || errno == EACCES); }
static bool denied_iokit(kern_return_t result) { return result == kIOReturnNotPermitted || result == kIOReturnNotPrivileged; }

static void single(io_registry_entry_t entry, CFStringRef key, const char *label) {
    CFTypeRef value = entry ? IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0) : NULL;
    printf("\"%s\":{\"present\":%s}", label, b(value != NULL));
    if (value) CFRelease(value);
}

static void search(io_registry_entry_t entry, CFStringRef key, const char *label, IOOptionBits options) {
    CFTypeRef value = entry ? IORegistryEntrySearchCFProperty(entry, kIOServicePlane, key, kCFAllocatorDefault, options) : NULL;
    printf("\"%s\":{\"present\":%s}", label, b(value != NULL));
    if (value) CFRelease(value);
}

static void bytes(io_registry_entry_t entry, const char *key, const char *label) {
    unsigned char value[4096] = {0}; uint32_t size = sizeof(value);
    kern_return_t result = entry ? IORegistryEntryGetProperty(entry, key, (char *)value, &size) : kIOReturnNoDevice;
    printf("\"%s\":{\"present\":%s,\"denied\":%s}", label, b(result == KERN_SUCCESS && size > 0), b(denied_iokit(result)));
    wipe(value, sizeof(value));
}

static void sysctl_probe(const char *name, bool numeric) {
    unsigned char value[4096] = {0}; size_t size = sizeof(value); int mib[CTL_MAXNAME]; size_t mibsize = CTL_MAXNAME;
    int result;
    errno = 0;
    if (numeric) {
        result = sysctlnametomib(name, mib, &mibsize);
        if (result == 0) result = sysctl(mib, (u_int)mibsize, value, &size, NULL, 0);
    } else result = sysctlbyname(name, value, &size, NULL, 0);
    bool denied = denied_errno(result), absent = result != 0 && errno == ENOENT;
    printf("{\"present\":%s,\"denied\":%s,\"absent\":%s}", b(result == 0 && size > 0), b(denied), b(absent));
    wipe(value, sizeof(value)); wipe(mib, sizeof(mib));
}

int main(void) {
    io_registry_entry_t entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    io_registry_entry_t root = IORegistryGetRootEntry(kIOMainPortDefault);
    printf("{\"platformEntryPresent\":%s,\"registryRootPresent\":%s,\"single\":{", b(entry != IO_OBJECT_NULL), b(root != IO_OBJECT_NULL));
    single(entry, CFSTR(kIOPlatformSerialNumberKey), "serial"); printf(",");
    single(entry, CFSTR(kIOPlatformUUIDKey), "uuid"); printf(",");
    single(entry, CFSTR("model"), "model"); printf("},\"batch\":{");
    CFMutableDictionaryRef properties = NULL;
    kern_return_t result = entry ? IORegistryEntryCreateCFProperties(entry, &properties, kCFAllocatorDefault, 0) : kIOReturnNoDevice;
    printf("\"present\":%s,\"denied\":%s,\"serialPresent\":%s,\"uuidPresent\":%s,\"modelPresent\":%s},\"searchDirect\":{",
      b(result == KERN_SUCCESS && properties), b(denied_iokit(result)),
      b(properties && CFDictionaryContainsKey(properties, CFSTR(kIOPlatformSerialNumberKey))),
      b(properties && CFDictionaryContainsKey(properties, CFSTR(kIOPlatformUUIDKey))),
      b(properties && CFDictionaryContainsKey(properties, CFSTR("model"))));
    if (properties) CFRelease(properties);
    search(entry, CFSTR(kIOPlatformSerialNumberKey), "serial", 0); printf(",");
    search(entry, CFSTR(kIOPlatformUUIDKey), "uuid", 0); printf("},\"searchRecursive\":{");
    search(root, CFSTR(kIOPlatformSerialNumberKey), "serial", kIORegistryIterateRecursively); printf(",");
    search(root, CFSTR(kIOPlatformUUIDKey), "uuid", kIORegistryIterateRecursively); printf("},\"bytes\":{");
    bytes(entry, kIOPlatformSerialNumberKey, "serial"); printf(",");
    bytes(entry, kIOPlatformUUIDKey, "uuid"); printf("},\"hostUuid\":{");
    uuid_t uuid = {0}; struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    errno = 0; int hostResult = gethostuuid(uuid, &timeout); bool hostDenied = denied_errno(hostResult);
    printf("\"library\":{\"present\":%s,\"denied\":%s},", b(hostResult == 0), b(hostDenied));
    wipe(uuid, sizeof(uuid)); errno = 0;
    int syscallResult = (int)syscall(SYS_gethostuuid, uuid, &timeout); bool syscallDenied = denied_errno(syscallResult);
    printf("\"syscall\":{\"present\":%s,\"denied\":%s}},\"sysctl\":{", b(syscallResult == 0), b(syscallDenied));
    wipe(uuid, sizeof(uuid));
    const char *keys[] = {"kern.uuid", "kern.bootsessionuuid", "kern.hostname", "hw.uuid", "hw.serialnumber", "hw.serialno", "hw.model", "hw.memsize", "hw.logicalcpu"};
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
        if (index) printf(","); printf("\"%s\":{\"byName\":", keys[index]); sysctl_probe(keys[index], false);
        printf(",\"numericMib\":"); sysctl_probe(keys[index], true); printf("}");
    }
    if (entry) IOObjectRelease(entry); if (root) IOObjectRelease(root);
    printf("}}\n"); return 0;
}
