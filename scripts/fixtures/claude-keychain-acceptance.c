/* Synthetic Keychain fixture. Every mutation uses an explicit owned keychain.
 * No authentication entry from the user's Keychain is ever requested. */
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const char service[] = "Envara-Claude-Keychain-Synthetic-Acceptance";
static char vault[PATH_MAX], fixture_root[PATH_MAX], fixture_home[PATH_MAX];
static struct stat root_identity, home_identity;
static char password[129], value[257];

static void clear_bytes(void *bytes, size_t size) {
    volatile unsigned char *cursor = bytes;
    while (size--) *cursor++ = 0;
}

static int fail(const char *stage, OSStatus status) {
    printf("{\"ok\":false,\"stage\":\"%s\",\"osStatus\":%d}\n", stage, (int)status);
    return 1;
}

static bool owned_directory(const char *name, struct stat *identity) {
    char canonical[PATH_MAX]; struct stat entry;
    if (!realpath(name, canonical) || strcmp(name, canonical) || lstat(name, &entry) ||
        !S_ISDIR(entry.st_mode) || entry.st_uid != getuid() || (entry.st_mode & 077) != 0) return false;
    if (identity) *identity = entry;
    return true;
}

static bool unchanged(void) {
    struct stat root_now, home_now;
    return owned_directory(fixture_root, &root_now) && owned_directory(fixture_home, &home_now) &&
        root_now.st_dev == root_identity.st_dev && root_now.st_ino == root_identity.st_ino &&
        home_now.st_dev == home_identity.st_dev && home_now.st_ino == home_identity.st_ino;
}

static bool owned_context(const char *root, const char *home) {
    if (!root || !home || !getenv("HOME") || strcmp(home, getenv("HOME")) ||
        strlen(root) >= sizeof(fixture_root) || strlen(home) >= sizeof(fixture_home) ||
        strncmp(home, root, strlen(root)) || home[strlen(root)] != '/' ||
        (strcmp(home + strlen(root), "/source-home") && strcmp(home + strlen(root), "/target-home"))) return false;
    strcpy(fixture_root, root); strcpy(fixture_home, home);
    char directory[PATH_MAX];
    if (snprintf(directory, sizeof(directory), "%s/vault", root) >= (int)sizeof(directory) ||
        snprintf(vault, sizeof(vault), "%s/acceptance.keychain-db", directory) >= (int)sizeof(vault)) return false;
    return owned_directory(root, &root_identity) && owned_directory(home, &home_identity) &&
        owned_directory(directory, NULL);
}

static bool owned_vault(void) {
    char canonical[PATH_MAX]; struct stat entry;
    return unchanged() && !lstat(vault, &entry) && S_ISREG(entry.st_mode) && entry.st_uid == getuid() &&
        (entry.st_mode & 022) == 0 && entry.st_nlink == 1 && realpath(vault, canonical) && !strcmp(vault, canonical);
}

static bool secure_created_vault(void) {
    struct stat before, opened;
    if (!owned_vault() || lstat(vault, &before)) return false;
    int descriptor = open(vault, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return false;
    bool safe = !fstat(descriptor, &opened) && opened.st_dev == before.st_dev && opened.st_ino == before.st_ino &&
        !fchmod(descriptor, 0600);
    close(descriptor); return safe && owned_vault();
}

static bool key_matches(SecKeychainRef key) {
    UInt32 size = PATH_MAX; char name[PATH_MAX] = "";
    return key && SecKeychainGetPath(key, &size, name) == errSecSuccess && size < sizeof(name) &&
        !strcmp(name, vault) && owned_vault();
}

static bool line(char *buffer, size_t size) {
    if (!fgets(buffer, (int)size, stdin)) return false;
    size_t length = strlen(buffer);
    if (!length || buffer[length - 1] != '\n') return false;
    buffer[--length] = '\0';
    if (length < 16) return false;
    for (size_t i = 0; i < length; ++i) if (!((buffer[i] >= 'a' && buffer[i] <= 'f') ||
        (buffer[i] >= '0' && buffer[i] <= '9'))) return false;
    return true;
}

static void digest(const void *bytes, size_t length, char output[CC_SHA256_DIGEST_LENGTH * 2 + 1]) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(bytes, (CC_LONG)length, hash);
    for (size_t i = 0; i < sizeof(hash); ++i) snprintf(output + i * 2, 3, "%02x", hash[i]);
}

/* This mode reads selection metadata only. Paths are hashed before stdout. */
static int snapshot(void) {
    SecKeychainRef current = NULL; CFArrayRef search = NULL;
    OSStatus current_status = SecKeychainCopyDefault(&current), search_status = SecKeychainCopySearchList(&search);
    char selected[PATH_MAX] = "", default_hash[65], search_hash[65]; UInt32 length = sizeof(selected);
    if (current && SecKeychainGetPath(current, &length, selected) != errSecSuccess) current_status = errSecInternalError;
    selected[sizeof(selected) - 1] = '\0';
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    if (search) for (CFIndex i = 0; i < CFArrayGetCount(search); ++i) {
        char name[PATH_MAX] = ""; UInt32 size = sizeof(name);
        OSStatus result = SecKeychainGetPath((SecKeychainRef)CFArrayGetValueAtIndex(search, i), &size, name);
        if (result || size >= sizeof(name)) { search_status = result ? result : errSecInternalError; break; }
        CC_SHA256_Update(&context, name, (CC_LONG)strlen(name) + 1);
    }
    unsigned char hash[32]; CC_SHA256_Final(hash, &context);
    for (size_t i = 0; i < sizeof(hash); ++i) snprintf(search_hash + i * 2, 3, "%02x", hash[i]);
    digest(selected, strlen(selected), default_hash);
    printf("{\"defaultStatus\":%d,\"searchStatus\":%d,\"defaultDigest\":\"%s\",\"searchDigest\":\"%s\",\"defaultPresent\":%s,\"searchCount\":%ld}\n",
        (int)current_status, (int)search_status, default_hash, search_hash, current ? "true" : "false", search ? (long)CFArrayGetCount(search) : 0L);
    if (current) CFRelease(current); if (search) CFRelease(search);
    return 0;
}

static int default_metadata(void) {
    SecKeychainRef current = NULL; OSStatus status = SecKeychainCopyDefault(&current);
    bool matches = status == errSecSuccess && key_matches(current);
    printf("{\"ok\":true,\"osStatus\":%d,\"present\":%s,\"matchesOwnedKeychain\":%s}\n",
        (int)status, current ? "true" : "false", matches ? "true" : "false");
    if (current) CFRelease(current); return 0;
}

static int create_vault(void) {
    struct stat entry; SecKeychainRef key = NULL;
    if (!line(password, sizeof(password)) || lstat(vault, &entry) == 0 || errno != ENOENT) return fail("create-precondition", errSecParam);
    OSStatus status = SecKeychainCreate(vault, (UInt32)strlen(password), password, false, NULL, &key);
    if (status) return fail("create", status);
    if (!key_matches(key) || !secure_created_vault()) { CFRelease(key); return fail("create-identity", errSecParam); }
    status = SecKeychainUnlock(key, (UInt32)strlen(password), password, true);
    if (!status && unchanged()) status = SecKeychainSetDefault(key);
    else if (!status) status = errSecParam;
    CFRelease(key); clear_bytes(password, sizeof(password));
    if (status) return fail("create-select", status);
    return default_metadata();
}

static bool account_ok(const char *account) {
    if (!account || strncmp(account, "synthetic-config-", 17) || strlen(account) > 128) return false;
    for (const char *p = account; *p; ++p) if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-')) return false;
    return true;
}

static int credential(const char *mode, const char *account) {
    SecKeychainRef selected = NULL, key = NULL; SecKeychainItemRef item = NULL;
    OSStatus status; UInt32 size = 0; void *bytes = NULL;
    if (!account_ok(account) || !line(password, sizeof(password)) ||
        ((!strcmp(mode, "write") || !strcmp(mode, "read")) && !line(value, sizeof(value)))) return fail("credential-input", errSecParam);
    status = SecKeychainCopyDefault(&selected);
    if (status || !key_matches(selected)) { if (selected) CFRelease(selected); return fail("credential-default", status ? status : errSecParam); }
    CFRelease(selected);
    status = SecKeychainOpen(vault, &key);
    if (status || !key_matches(key)) { if (key) CFRelease(key); return fail("credential-open", status ? status : errSecParam); }
    status = SecKeychainUnlock(key, (UInt32)strlen(password), password, true);
    clear_bytes(password, sizeof(password));
    if (status) { CFRelease(key); return fail("credential-unlock", status); }
    bool found = false, matches = false;
    if (!strcmp(mode, "write")) {
        status = SecKeychainAddGenericPassword(key, sizeof(service) - 1, service, (UInt32)strlen(account), account,
            (UInt32)strlen(value), value, NULL);
    } else {
        status = SecKeychainFindGenericPassword(key, sizeof(service) - 1, service, (UInt32)strlen(account), account,
            &size, &bytes, &item);
        found = status == errSecSuccess;
        matches = found && size == strlen(value) && !memcmp(bytes, value, size);
        if (bytes) SecKeychainItemFreeContent(NULL, bytes);
        if (!strcmp(mode, "delete-item") && found) status = SecKeychainItemDelete(item);
    }
    if (item) CFRelease(item); CFRelease(key); clear_bytes(value, sizeof(value));
    if (!unchanged()) return fail("credential-context-changed", errSecParam);
    printf("{\"ok\":%s,\"osStatus\":%d,\"found\":%s,\"matchesSyntheticValue\":%s}\n",
        status == errSecSuccess || status == errSecItemNotFound ? "true" : "false", (int)status,
        found ? "true" : "false", matches ? "true" : "false");
    return status == errSecSuccess || status == errSecItemNotFound ? 0 : 1;
}

static int delete_vault(void) {
    struct stat entry; SecKeychainRef key = NULL;
    if (lstat(vault, &entry) != 0) {
        if (errno == ENOENT) { puts("{\"ok\":true,\"osStatus\":0,\"absent\":true}"); return 0; }
        return fail("cleanup-stat", errSecParam);
    }
    if (!owned_vault()) return fail("cleanup-identity", errSecParam);
    OSStatus status = SecKeychainOpen(vault, &key);
    if (status || !key_matches(key)) { if (key) CFRelease(key); return fail("cleanup-open", status ? status : errSecParam); }
    status = SecKeychainDelete(key); CFRelease(key);
    bool absent = lstat(vault, &entry) != 0 && errno == ENOENT;
    printf("{\"ok\":%s,\"osStatus\":%d,\"absent\":%s}\n", !status && absent ? "true" : "false", (int)status, absent ? "true" : "false");
    return !status && absent ? 0 : 1;
}

static int connection(const char *port) {
    char *end = NULL; long number = strtol(port, &end, 10);
    if (!end || *end || number < 1 || number > 65535) return EINVAL;
    int descriptor = socket(AF_INET, SOCK_STREAM, 0); if (descriptor < 0) return errno;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((uint16_t)number) };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0 ? 0 : errno;
    close(descriptor); return result;
}

int main(int argc, char **argv) {
    if (getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return fail("identity", errSecParam);
    umask(077);
    if (SecKeychainSetUserInteractionAllowed(false)) return fail("disable-ui", errSecInteractionNotAllowed);
    if (argc == 2 && !strcmp(argv[1], "snapshot")) return snapshot();
    if (argc < 4 || !owned_context(argv[2], argv[3])) return fail("owned-context", errSecParam);
    if (argc == 4 && !strcmp(argv[1], "default")) return default_metadata();
    if (argc == 4 && !strcmp(argv[1], "create")) return create_vault();
    if (argc == 4 && !strcmp(argv[1], "delete-keychain")) return delete_vault();
    if (argc == 5 && (!strcmp(argv[1], "write") || !strcmp(argv[1], "read") || !strcmp(argv[1], "delete-item"))) return credential(argv[1], argv[4]);
    if (argc == 6 && !strcmp(argv[1], "network")) {
        int allowed = connection(argv[4]), denied = connection(argv[5]);
        printf("{\"ok\":true,\"allowedErrno\":%d,\"deniedErrno\":%d}\n", allowed, denied); return 0;
    }
    return fail("arguments", errSecParam);
}
