#include "app-registry.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/acl.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* No CLI or installed caller exists yet. Fixed compiled callers must resolve
 * records here instead of trusting wire manifests. No launch/resume/GC API. */
enum { DESCRIPTOR = 1, INTENT = 2, COMMIT = 3, RETIRED = 4 };
struct disk_record {
    char magic[8];
    uint32_t schema, size, kind, fixture_only, owner, sequence;
    char registration_id[37], version_id[37], previous_version_id[37];
    struct envara_gui_manifest original, snapshot;
    char checksum[65];
};
struct names { char **items; size_t count; };
struct copy_limits { uint64_t bytes; size_t entries; char bundle[PATH_MAX]; };
static int refuse(int error) { errno = error; return -1; }
static int string_ok(const char *s, size_t size) { return s && memchr(s, 0, size) && strnlen(s, size) > 0; }
static int uuid(const char *s) {
    if (!string_ok(s, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0;
    }
    return 1;
}
static int same_stat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int acl_value_empty(acl_t acl) {
    acl_entry_t entry;
    if (!acl) return errno == ENOENT;
    if (acl_valid(acl)) { acl_free(acl); return 0; }
    errno = 0; int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); int error = errno;
    acl_free(acl); return result == -1 && error == EINVAL;
}
static int acl_empty(int fd) { return acl_value_empty(acl_get_fd_np(fd, ACL_TYPE_EXTENDED)); }
static int attrs_supported(int fd) {
    char names[4096]; ssize_t size = flistxattr(fd, names, sizeof(names), 0);
    if (size < 0 || size > (ssize_t)sizeof(names)) return 0;
    size_t offset = 0;
    while (offset < (size_t)size) {
        size_t length = strnlen(names + offset, (size_t)size - offset);
        if (!length || length == (size_t)size - offset || strcmp(names + offset, "com.apple.provenance")) return 0;
        ssize_t bytes = fgetxattr(fd, names + offset, NULL, 0, 0, 0);
        if (bytes < 0 || bytes > 256) return 0; offset += length + 1;
    }
    return 1;
}
static int metadata(int fd, uid_t owner, int directory, mode_t exact_mode, int no_xattrs) {
    struct stat info;
    if (fstat(fd, &info) || (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) ||
        (owner != (uid_t)-1 && info.st_uid != owner) || (info.st_mode & (S_ISUID | S_ISGID | 0022)) ||
        (!directory && info.st_nlink != 1) || (exact_mode && (info.st_mode & 0777) != exact_mode) || !acl_empty(fd) ||
        (no_xattrs && !attrs_supported(fd))) return refuse(EACCES);
    return 0;
}
/* macOS may automatically reattach provenance even after removal. This one
 * bounded OS attribute is explicitly outside the app-content copy manifest.
 * Never remove/rewrite it or source metadata; every other xattr refuses. */
static int clear_created_xattrs(int fd) {
    return attrs_supported(fd) ? 0 : refuse(EACCES);
}
static int name_order(const void *a, const void *b) { return strcmp(*(const char * const *)a, *(const char * const *)b); }
static void free_names(struct names *names) { for (size_t i = 0; i < names->count; i++) free(names->items[i]); free(names->items); memset(names, 0, sizeof(*names)); }
static int list(int fd, struct names *names, size_t bound) {
    memset(names, 0, sizeof(*names));
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return -1;
    DIR *dir = fdopendir(scan); if (!dir) { close(scan); return -1; }
    struct dirent *entry; int error = 0; errno = 0;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (names->count >= bound) { error = ENOSPC; break; }
        size_t length = strlen(entry->d_name);
        if (!length || length > 255 || strchr(entry->d_name, '/')) { error = EINVAL; break; }
        for (size_t i = 0; i < length; i++) if ((unsigned char)entry->d_name[i] < 32 || entry->d_name[i] == 127) error = EINVAL;
        if (error) break;
        char **items = realloc(names->items, (names->count + 1) * sizeof(char *));
        if (!items) { error = ENOMEM; break; } names->items = items;
        names->items[names->count] = strdup(entry->d_name);
        if (!names->items[names->count]) { error = ENOMEM; break; } names->count++; errno = 0;
    }
    if (!error && errno) error = errno;
    if (closedir(dir) && !error) error = errno;
    if (error) { free_names(names); return refuse(error); }
    qsort(names->items, names->count, sizeof(char *), name_order); return 0;
}
static int open_dir(int parent, const char *name, uid_t owner, mode_t mode) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (metadata(fd, owner, 1, mode, 1)) { int error = errno; close(fd); return refuse(error); }
    return fd;
}
static int absolute_dir(const char *path, int production) {
    if (!string_ok(path, PATH_MAX) || path[0] != '/') return refuse(EINVAL);
    char parts[PATH_MAX]; strcpy(parts, path); int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (production && metadata(fd, 0, 1, 0, 0)) { close(fd); return -1; }
    char *save = NULL;
    for (char *part = strtok_r(parts, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return refuse(EINVAL); }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { int error = errno; close(fd); return refuse(error); }
        close(fd); fd = next;
        if (production && metadata(fd, 0, 1, 0, 0)) { close(fd); return -1; }
    }
    return fd;
}
static int make_dir(int parent, const char *name, mode_t mode, uid_t owner) {
    int created = mkdirat(parent, name, mode) == 0;
    if (!created && errno != EEXIST) return -1;
    int fd;
    if (created) {
        fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0 && (fchmod(fd, mode) || clear_created_xattrs(fd))) { int error = errno; close(fd); return refuse(error); }
    } else fd = open_dir(parent, name, owner, mode);
    if (fd < 0 || metadata(fd, owner, 1, mode, 1)) { if (fd >= 0) close(fd); return -1; }
    if (fsync(parent)) { int error = errno; close(fd); return refuse(error); } return fd;
}
static int handle_valid(struct envara_app_registry *registry) {
    if (!registry || registry->fd < 0 || (registry->fixture_only != 0 && registry->fixture_only != 1) ||
        (registry->fixture_only ? getuid() == 0 || geteuid() != getuid() || registry->owner != getuid() :
         getuid() != 0 || geteuid() != 0 || registry->owner != 0 || strcmp(registry->root, ENVARA_APP_REGISTRY_ROOT))) return refuse(EACCES);
    struct stat held, current; char canonical[PATH_MAX];
    if (!realpath(registry->root, canonical) || strcmp(canonical, registry->root)) return refuse(ESTALE);
    int chain = absolute_dir(registry->root, !registry->fixture_only); if (chain < 0) return -1;
    int chain_valid = !fstat(chain, &current); close(chain);
    if (!chain_valid || metadata(registry->fd, registry->owner, 1, 0755, 1) || fstat(registry->fd, &held) || lstat(registry->root, &current) ||
        held.st_dev != current.st_dev || held.st_ino != current.st_ino || !S_ISDIR(current.st_mode)) return refuse(ESTALE);
    return 0;
}
int envara_app_registry_open(struct envara_app_registry *registry, const char *fixture_root, int fixture_only, int create) {
    if (!registry || (fixture_only != 0 && fixture_only != 1) || (create != 0 && create != 1)) return refuse(EINVAL);
    memset(registry, 0, sizeof(*registry)); registry->fd = -1;
    const char *root = fixture_only ? fixture_root : ENVARA_APP_REGISTRY_ROOT;
    if (!string_ok(root, PATH_MAX) || root[0] != '/' || (fixture_only ? getuid() == 0 || geteuid() != getuid() : getuid() != 0 || geteuid() != 0)) return refuse(EACCES);
    if (fixture_only && !strncmp(root, "/Library/", 9)) return refuse(EACCES);
    char parent[PATH_MAX], canonical[PATH_MAX]; strcpy(parent, root);
    char *slash = strrchr(parent, '/'); if (!slash || slash == parent || !slash[1]) return refuse(EINVAL);
    char leaf[256]; if (strlen(slash + 1) >= sizeof(leaf)) return refuse(EINVAL); strcpy(leaf, slash + 1); *slash = 0;
    if (!realpath(parent, canonical) || strcmp(parent, canonical)) return refuse(EINVAL);
    int parent_fd = absolute_dir(parent, !fixture_only); if (parent_fd < 0) return -1;
    uid_t owner = fixture_only ? getuid() : 0;
    if (fixture_only && metadata(parent_fd, owner, 1, 0700, 1)) { close(parent_fd); return -1; }
    int fd = create ? make_dir(parent_fd, leaf, 0755, owner) : open_dir(parent_fd, leaf, owner, 0755);
    close(parent_fd); if (fd < 0) return -1;
    if (create) {
        if (flock(fd, LOCK_EX | LOCK_NB)) { close(fd); return -1; }
        int records = make_dir(fd, "registrations", 0700, owner), objects = make_dir(fd, "objects", 0755, owner);
        int error = records < 0 || objects < 0 ? errno : 0;
        if (records >= 0) close(records); if (objects >= 0) close(objects); flock(fd, LOCK_UN);
        if (error) { close(fd); return refuse(error); }
    }
    registry->fd = fd; registry->fixture_only = fixture_only; registry->owner = owner; strcpy(registry->root, root);
    return handle_valid(registry);
}
void envara_app_registry_close(struct envara_app_registry *registry) {
    if (registry && registry->fd >= 0) close(registry->fd);
    if (registry) { memset(registry, 0, sizeof(*registry)); registry->fd = -1; }
}
static void record_hash(struct disk_record *record, char out[65]) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; char saved[65]; memcpy(saved, record->checksum, sizeof(saved));
    memset(record->checksum, 0, sizeof(record->checksum)); CC_SHA256(record, (CC_LONG)sizeof(*record), hash);
    memcpy(record->checksum, saved, sizeof(saved));
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(out + 2 * i, 3, "%02x", hash[i]); out[64] = 0;
}
static void record_init(struct disk_record *record, struct envara_app_registry *registry, unsigned kind, const char *id) {
    memset(record, 0, sizeof(*record)); memcpy(record->magic, "EVAPP01", 8);
    record->schema = ENVARA_APP_REGISTRY_SCHEMA; record->size = sizeof(*record); record->kind = kind;
    record->fixture_only = registry->fixture_only; record->owner = registry->owner; strcpy(record->registration_id, id);
}
static int manifest_shape(const struct envara_gui_manifest *m, int fixture) {
    if (m->schema != ENVARA_GUI_SCHEMA || m->fixture_only != fixture || !string_ok(m->bundle, PATH_MAX) || m->bundle[0] != '/' ||
        !string_ok(m->executable, PATH_MAX) || m->executable[0] != '/' || !string_ok(m->identifier, sizeof(m->identifier)) ||
        !memchr(m->cdhash, 0, sizeof(m->cdhash)) || !memchr(m->requirement, 0, sizeof(m->requirement)) ||
        (!fixture && (!m->cdhash[0] || !m->requirement[0]))) return 0;
    const char *hashes[] = {m->bundle_digest, m->content_digest, m->executable_digest};
    for (size_t i = 0; i < 3; i++) {
        if (!memchr(hashes[i], 0, 65) || strlen(hashes[i]) != 64) return 0;
        for (int j = 0; j < 64; j++) if (!strchr("0123456789abcdef", hashes[i][j])) return 0;
    }
    return 1;
}
static int write_record(int parent, const char *name, struct disk_record *record) {
    record_hash(record, record->checksum);
    int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t offset = 0; int error = 0;
    while (offset < sizeof(*record)) {
        ssize_t count = write(fd, (char *)record + offset, sizeof(*record) - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { error = errno ? errno : EIO; break; } offset += (size_t)count;
    }
    if (!error && (fchmod(fd, 0600) || clear_created_xattrs(fd) || fsync(fd))) error = errno;
    if (close(fd) && !error) error = errno;
    if (!error && fsync(parent)) error = errno;
    return error ? refuse(error) : 0; // Partial/uncertain records are never removed.
}
static int read_record(int parent, const char *name, struct envara_app_registry *registry, unsigned kind, const char *id, struct disk_record *record) {
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); if (fd < 0) return -1;
    struct stat before, after, named; int error = 0; size_t offset = 0;
    if (metadata(fd, registry->owner, 0, 0600, 1) || fstat(fd, &before) || before.st_size != sizeof(*record)) error = EILSEQ;
    while (!error && offset < sizeof(*record)) {
        ssize_t count = read(fd, (char *)record + offset, sizeof(*record) - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { error = EIO; break; } offset += (size_t)count;
    }
    if (!error && (fstat(fd, &after) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) || !same_stat(&before, &after) || !same_stat(&after, &named))) error = ESTALE;
    close(fd); if (error) return refuse(error);
    char hash[65]; record_hash(record, hash);
    if (memcmp(record->magic, "EVAPP01", 8) || record->schema != ENVARA_APP_REGISTRY_SCHEMA || record->size != sizeof(*record) ||
        record->kind != kind || record->fixture_only != (unsigned)registry->fixture_only || record->owner != registry->owner ||
        !uuid(record->registration_id) || strcmp(record->registration_id, id) || !memchr(record->checksum, 0, 65) || strcmp(hash, record->checksum) ||
        !manifest_shape(&record->original, registry->fixture_only) ||
        ((kind == INTENT || kind == COMMIT) && !uuid(record->version_id)) ||
        (record->previous_version_id[0] && !uuid(record->previous_version_id)) ||
        (kind == COMMIT && !manifest_shape(&record->snapshot, registry->fixture_only))) return refuse(EILSEQ);
    return 0;
}
static int root_inventory(struct envara_app_registry *registry, int *records, int *objects, size_t *count) {
    struct names roots, ids; *records = -1; *objects = -1;
    if (list(registry->fd, &roots, 3)) return -1;
    int valid = roots.count == 2 && !strcmp(roots.items[0], "objects") && !strcmp(roots.items[1], "registrations"); free_names(&roots);
    if (!valid) return refuse(EILSEQ);
    *records = open_dir(registry->fd, "registrations", registry->owner, 0700);
    *objects = open_dir(registry->fd, "objects", registry->owner, 0755);
    if (*records < 0 || *objects < 0) return -1;
    if (list(*records, &ids, ENVARA_APP_REGISTRY_MAX_APPS + 1)) return -1;
    *count = ids.count; valid = ids.count <= ENVARA_APP_REGISTRY_MAX_APPS;
    for (size_t i = 0; valid && i < ids.count; i++) { int fd;
        if (!uuid(ids.items[i]) || (fd = open_dir(*records, ids.items[i], registry->owner, 0700)) < 0) valid = 0;
        else close(fd);
    }
    free_names(&ids); if (!valid) return refuse(ENOSPC);
    if (list(*objects, &ids, ENVARA_APP_REGISTRY_MAX_APPS + 1)) return -1;
    for (size_t i = 0; valid && i < ids.count; i++) { int fd, paired;
        if (!uuid(ids.items[i]) || (fd = open_dir(*objects, ids.items[i], registry->owner, 0755)) < 0) { valid = 0; break; }
        close(fd); paired = open_dir(*records, ids.items[i], registry->owner, 0700);
        if (paired < 0) valid = 0; else close(paired);
    }
    free_names(&ids); return valid ? 0 : refuse(EILSEQ);
}
static int version_inventory(int fd, struct envara_app_registry *registry, const char *id, unsigned *highest, struct disk_record *latest) {
    struct names names; if (list(fd, &names, 2 * ENVARA_APP_REGISTRY_MAX_VERSIONS + 2)) return -1;
    unsigned intents = 0, commits = 0; int descriptor = 0, retired = 0, error = 0;
    for (size_t i = 0; i < names.count && !error; i++) {
        const char *name = names.items[i]; unsigned sequence = 0; char suffix[16], expected[32];
        if (!strcmp(name, "descriptor")) { descriptor++; continue; }
        if (!strcmp(name, "retired")) { retired++; continue; }
        if (sscanf(name, "%8u.%15s", &sequence, suffix) != 2 || sequence < 1 || sequence > ENVARA_APP_REGISTRY_MAX_VERSIONS ||
            (strcmp(suffix, "intent") && strcmp(suffix, "commit"))) { error = EILSEQ; break; }
        snprintf(expected, sizeof(expected), "%08u.%s", sequence, suffix); if (strcmp(name, expected)) { error = EILSEQ; break; }
        if (!strcmp(suffix, "intent")) intents |= 1u << (sequence - 1); else commits |= 1u << (sequence - 1);
    }
    free_names(&names);
    if (error || descriptor != 1 || (commits & ~intents)) return refuse(error ? error : EILSEQ);
    struct disk_record desc; if (read_record(fd, "descriptor", registry, DESCRIPTOR, id, &desc)) return -1;
    if (retired) { struct disk_record dead; if (read_record(fd, "retired", registry, RETIRED, id, &dead)) return -1; return refuse(ENOENT); }
    *highest = 0;
    while (intents & (1u << *highest)) (*highest)++;
    if (intents != (*highest ? (1u << *highest) - 1 : 0)) return refuse(EILSEQ);
    char previous[37] = {0};
    for (unsigned i = 1; i <= *highest; i++) {
        char name[32]; struct disk_record intent, committed;
        snprintf(name, sizeof(name), "%08u.intent", i);
        if (read_record(fd, name, registry, INTENT, id, &intent) || intent.sequence != i || !uuid(intent.version_id) ||
            strcmp(intent.original.bundle, desc.original.bundle) || strcmp(intent.original.identifier, desc.original.identifier) ||
            strcmp(intent.original.requirement, desc.original.requirement) || strcmp(intent.previous_version_id, previous)) return refuse(EILSEQ);
        if (!(commits & (1u << (i - 1)))) return refuse(EINPROGRESS);
        snprintf(name, sizeof(name), "%08u.commit", i);
        if (read_record(fd, name, registry, COMMIT, id, &committed) || committed.sequence != i ||
            strcmp(committed.version_id, intent.version_id) || strcmp(committed.previous_version_id, intent.previous_version_id) ||
            memcmp(&committed.original, &intent.original, sizeof(intent.original))) return refuse(EILSEQ);
        strcpy(previous, committed.version_id);
        if (latest) *latest = committed;
    }
    return 0;
}
static int object_inventory(int object_reg, int reg, struct envara_app_registry *registry, const char *id, unsigned highest) {
    struct names versions; if (list(object_reg, &versions, ENVARA_APP_REGISTRY_MAX_VERSIONS + 1)) return -1;
    int error = versions.count != highest ? EILSEQ : 0;
    for (size_t i = 0; !error && i < versions.count; i++) {
        if (!uuid(versions.items[i])) { error = EILSEQ; break; }
        int found = 0;
        for (unsigned sequence = 1; sequence <= highest; sequence++) {
            char name[32]; struct disk_record intent; snprintf(name, sizeof(name), "%08u.intent", sequence);
            if (read_record(reg, name, registry, INTENT, id, &intent)) { error = errno; break; }
            if (!strcmp(intent.version_id, versions.items[i])) found++;
        }
        if (found != 1) error = EILSEQ;
        if (!error) { int fd = open_dir(object_reg, versions.items[i], registry->owner, 0755);
            if (fd < 0) error = errno; else close(fd); }
    }
    free_names(&versions); return error ? refuse(error) : 0;
}
static int named_dir(int parent, const char *name, int fd, struct envara_app_registry *registry, mode_t mode) {
    struct stat held, named;
    if (fd < 0 || metadata(fd, registry->owner, 1, mode, 1) || fstat(fd, &held) ||
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) || !same_stat(&held, &named)) return refuse(ESTALE);
    return 0;
}
static int exact_version(int fd) {
    struct names files; if (list(fd, &files, 2)) return -1;
    int exact = files.count == 1 && !strcmp(files.items[0], "Snapshot.app"); free_names(&files);
    return exact ? 0 : refuse(EILSEQ);
}
static int pin_record(int parent, const char *name, struct envara_app_registry *registry, struct stat *info) {
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (metadata(fd, registry->owner, 0, 0600, 1) || fstat(fd, info)) { int error = errno; close(fd); return refuse(error); }
    return fd;
}
static int pinned_record_unchanged(int parent, const char *name, int fd, const struct stat *before) {
    struct stat held, named;
    if (fstat(fd, &held) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_stat(before, &held) || !same_stat(&held, &named)) return refuse(ESTALE);
    return 0;
}
static int named_chain(struct envara_app_registry *registry, int records, int objects, int reg, int object_reg,
                       int object_version, int snapshot, const char *id, const char *version) {
    return handle_valid(registry) || named_dir(registry->fd, "registrations", records, registry, 0700) ||
        named_dir(registry->fd, "objects", objects, registry, 0755) || named_dir(records, id, reg, registry, 0700) ||
        named_dir(objects, id, object_reg, registry, 0755) || named_dir(object_reg, version, object_version, registry, 0755) ||
        named_dir(object_version, "Snapshot.app", snapshot, registry, 0555) ? refuse(ESTALE) : 0;
}
static int hook_call(const struct envara_app_registry_fixture_hook *hook, const char *stage) {
    return hook && hook->observe && hook->observe(stage, hook->context) ? refuse(EIO) : 0;
}
static int internal_link(int parent, const char *name, const char *bundle, char text[PATH_MAX]) {
    struct stat before, after; char parent_path[PATH_MAX], path[PATH_MAX], resolved[PATH_MAX];
    if (fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) || !S_ISLNK(before.st_mode) ||
        fcntl(parent, F_GETPATH, parent_path) || snprintf(path, sizeof(path), "%s/%s", parent_path, name) >= (int)sizeof(path)) return refuse(EACCES);
    ssize_t length = readlinkat(parent, name, text, PATH_MAX - 1);
    if (length < 1 || length >= PATH_MAX - 1) return refuse(EACCES); text[length] = 0;
    if (!acl_value_empty(acl_get_link_np(path, ACL_TYPE_EXTENDED))) return refuse(EACCES);
    size_t root_length = strlen(bundle);
    char attrs[4096]; ssize_t attr_size = listxattr(path, attrs, sizeof(attrs), XATTR_NOFOLLOW);
    if (attr_size < 0 || attr_size > (ssize_t)sizeof(attrs)) return refuse(EACCES);
    size_t offset = 0;
    while (offset < (size_t)attr_size) {
        size_t size = strnlen(attrs + offset, (size_t)attr_size - offset);
        if (!size || size == (size_t)attr_size - offset || strcmp(attrs + offset, "com.apple.provenance")) return refuse(EACCES);
        ssize_t bytes = getxattr(path, attrs + offset, NULL, 0, 0, XATTR_NOFOLLOW); if (bytes < 0 || bytes > 256) return refuse(EACCES);
        offset += size + 1;
    }
    if (text[0] == '/' || !realpath(path, resolved) || strncmp(bundle, resolved, root_length) ||
        (resolved[root_length] != '/' && resolved[root_length] != 0) ||
        fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) || !same_stat(&before, &after)) return refuse(EACCES);
    return 0;
}
static int copy_tree(int source, int destination, struct envara_app_registry *registry, struct copy_limits *limits, unsigned depth,
                     const struct envara_app_registry_fixture_hook *hook) {
    if (depth > 32 || metadata(source, registry->fixture_only ? registry->owner : (uid_t)-1, 1, 0, 1)) return refuse(EACCES);
    struct stat before, after; if (fstat(source, &before) || (before.st_mode & 0111) != 0111) return refuse(EACCES);
    if (++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES) return refuse(ENOSPC);
    struct names names; if (list(source, &names, ENVARA_APP_REGISTRY_MAX_ENTRIES)) return -1;
    int error = 0;
    for (size_t i = 0; i < names.count && !error; i++) {
        const char *name = names.items[i]; struct stat named, held, final, current;
        if (fstatat(source, name, &named, AT_SYMLINK_NOFOLLOW)) { error = errno; break; }
        if (S_ISLNK(named.st_mode)) {
            char text[PATH_MAX]; struct stat created, sealed;
            if (++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES || (registry->fixture_only && named.st_uid != registry->owner) ||
                internal_link(source, name, limits->bundle, text) || symlinkat(text, destination, name) ||
                fstatat(destination, name, &created, AT_SYMLINK_NOFOLLOW) || !S_ISLNK(created.st_mode) || created.st_uid != registry->owner ||
                /* Darwin symlink permissions follow umask and affect access.
                 * Restore only this new link, never its possibly not-yet-copied target. */
                fchmodat(destination, name, named.st_mode & 0777, AT_SYMLINK_NOFOLLOW) ||
                fstatat(destination, name, &sealed, AT_SYMLINK_NOFOLLOW) || !S_ISLNK(sealed.st_mode) ||
                created.st_dev != sealed.st_dev || created.st_ino != sealed.st_ino || created.st_uid != sealed.st_uid ||
                created.st_size != sealed.st_size || (sealed.st_mode & 0777) != (named.st_mode & 0777) ||
                fstatat(source, name, &current, AT_SYMLINK_NOFOLLOW) || !same_stat(&named, &current)) error = errno ? errno : ESTALE;
            continue;
        }
        if (!(S_ISDIR(named.st_mode) || S_ISREG(named.st_mode))) { error = EACCES; break; }
        int input = openat(source, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (S_ISDIR(named.st_mode) ? O_DIRECTORY : 0));
        if (input < 0) { error = errno; break; }
        if (fstat(input, &held) || !same_stat(&named, &held) || metadata(input, registry->fixture_only ? registry->owner : (uid_t)-1, S_ISDIR(named.st_mode), 0, 1)) error = EACCES;
        int output = -1;
        if (!error && S_ISDIR(named.st_mode)) {
            if (mkdirat(destination, name, 0700)) error = errno;
            else output = openat(destination, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (!error && (output < 0 || copy_tree(input, output, registry, limits, depth + 1, hook))) error = errno;
        } else if (!error) {
            if (++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES || named.st_size < 0 ||
                (uint64_t)named.st_size > ENVARA_APP_REGISTRY_MAX_BYTES - limits->bytes ||
                ((named.st_mode & 0111) && (named.st_mode & 0111) != 0111)) error = ENOSPC;
            if (!error) { limits->bytes += (uint64_t)named.st_size; output = openat(destination, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); if (output < 0) error = errno; }
            unsigned char bytes[65536]; uint64_t copied = 0;
            while (!error) {
                ssize_t count = read(input, bytes, sizeof(bytes)); if (count < 0 && errno == EINTR) continue;
                if (count < 0) { error = errno; break; } if (!count) break;
                if ((uint64_t)count > (uint64_t)named.st_size - copied) { error = ESTALE; break; }
                copied += (uint64_t)count; size_t offset = 0;
                while (offset < (size_t)count) { ssize_t written = write(output, bytes + offset, (size_t)count - offset);
                    if (written < 0 && errno == EINTR) continue; if (written <= 0) { error = EIO; break; } offset += (size_t)written; }
            }
            if (!error && (copied != (uint64_t)named.st_size || clear_created_xattrs(output) || fchmod(output, 0444 | (named.st_mode & 0111)) || fsync(output) || hook_call(hook, "after-copy-file"))) error = errno ? errno : ESTALE;
        }
        if (!error && (fstat(input, &final) || fstatat(source, name, &current, AT_SYMLINK_NOFOLLOW) || !same_stat(&held, &final) || !same_stat(&held, &current))) error = ESTALE;
        if (output >= 0 && close(output) && !error) error = errno; close(input);
    }
    free_names(&names);
    if (!error && (fstat(source, &after) || !same_stat(&before, &after))) error = ESTALE;
    if (!error && (clear_created_xattrs(destination) || fchmod(destination, 0555) || fsync(destination))) error = errno;
    return error ? refuse(error) : 0;
}
static int validate_tree(int fd, struct envara_app_registry *registry, struct copy_limits *limits, unsigned depth) {
    if (depth > 32 || metadata(fd, registry->owner, 1, 0555, 1) || ++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES) return refuse(EACCES);
    struct names names; if (list(fd, &names, ENVARA_APP_REGISTRY_MAX_ENTRIES)) return -1;
    int error = 0; struct stat before, after; if (fstat(fd, &before)) error = errno;
    for (size_t i = 0; i < names.count && !error; i++) {
        struct stat info, held, final; if (fstatat(fd, names.items[i], &info, AT_SYMLINK_NOFOLLOW)) { error = errno; break; }
        if (S_ISLNK(info.st_mode)) {
            char text[PATH_MAX];
            if (++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES || info.st_uid != registry->owner || internal_link(fd, names.items[i], limits->bundle, text)) error = EACCES;
            continue;
        }
        if (!(S_ISDIR(info.st_mode) || S_ISREG(info.st_mode))) { error = EACCES; break; }
        int child = openat(fd, names.items[i], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (S_ISDIR(info.st_mode) ? O_DIRECTORY : 0));
        if (child < 0) { error = errno; break; }
        if (fstat(child, &held) || !same_stat(&info, &held)) error = ESTALE;
        if (!error && S_ISDIR(info.st_mode)) { if (validate_tree(child, registry, limits, depth + 1)) error = errno; }
        else if (!error && (metadata(child, registry->owner, 0, 0444 | (info.st_mode & 0111), 1) ||
            ++limits->entries > ENVARA_APP_REGISTRY_MAX_ENTRIES || info.st_size < 0 || (uint64_t)info.st_size > ENVARA_APP_REGISTRY_MAX_BYTES - limits->bytes)) error = EACCES;
        else if (!error) limits->bytes += (uint64_t)info.st_size;
        if (!error && (fstatat(fd, names.items[i], &final, AT_SYMLINK_NOFOLLOW) || !same_stat(&held, &final))) error = ESTALE;
        close(child);
    }
    free_names(&names); if (!error && (fstat(fd, &after) || !same_stat(&before, &after))) error = ESTALE;
    return error ? refuse(error) : 0;
}
static int content_matches(const struct envara_gui_manifest *a, const struct envara_gui_manifest *b) {
    return !strcmp(a->identifier, b->identifier) && !strcmp(a->content_digest, b->content_digest) &&
        !strcmp(a->executable_digest, b->executable_digest) && !strcmp(a->cdhash, b->cdhash) && !strcmp(a->requirement, b->requirement);
}
static int result_of(struct disk_record *record, struct envara_app_registration *out) {
    if (!out) return refuse(EINVAL); memset(out, 0, sizeof(*out)); out->schema = ENVARA_APP_REGISTRY_SCHEMA;
    out->sequence = record->sequence; out->fixture_only = record->fixture_only;
    strcpy(out->registration_id, record->registration_id); strcpy(out->version_id, record->version_id);
    out->original = record->original; out->snapshot = record->snapshot; return 0;
}
int envara_app_registry_register(struct envara_app_registry *registry, const char *id, const char *version, const char *original,
                                const char *previous, const struct envara_app_registry_fixture_hook *hook, struct envara_app_registration *out) {
    if (handle_valid(registry) || !uuid(id) || !uuid(version) || !out || (previous && !uuid(previous)) || (hook && !registry->fixture_only)) return refuse(EINVAL);
    if (flock(registry->fd, LOCK_EX | LOCK_NB)) return -1;
    int records = -1, objects = -1, reg = -1, object_reg = -1, object_version = -1, source = -1, snapshot = -1, committed_fd = -1, error = 0;
    size_t count = 0; unsigned highest = 0; struct disk_record descriptor, latest, intent;
    struct envara_gui_manifest inspected;
    if (root_inventory(registry, &records, &objects, &count) || envara_gui_manifest_inspect(original, registry->fixture_only, &inspected)) { error = errno; goto done; }
    reg = open_dir(records, id, registry->owner, 0700);
    if (reg < 0 && errno == ENOENT) {
        if (previous || count >= ENVARA_APP_REGISTRY_MAX_APPS) { error = previous ? ESTALE : ENOSPC; goto done; }
        reg = make_dir(records, id, 0700, registry->owner); if (reg < 0) { error = errno; goto done; }
        record_init(&descriptor, registry, DESCRIPTOR, id); descriptor.original = inspected;
        if (write_record(reg, "descriptor", &descriptor)) { error = errno; goto done; }
    } else if (reg < 0) { error = errno; goto done; }
    if (version_inventory(reg, registry, id, &highest, &latest) || read_record(reg, "descriptor", registry, DESCRIPTOR, id, &descriptor)) { error = errno; goto done; }
    if (strcmp(descriptor.original.bundle, inspected.bundle) || strcmp(descriptor.original.identifier, inspected.identifier) ||
        strcmp(descriptor.original.requirement, inspected.requirement) || (highest ? !previous || strcmp(previous, latest.version_id) : previous != NULL)) { error = ESTALE; goto done; }
    if (highest >= ENVARA_APP_REGISTRY_MAX_VERSIONS || (highest && !strcmp(version, latest.version_id))) { error = ENOSPC; goto done; }
    object_reg = make_dir(objects, id, 0755, registry->owner); if (object_reg < 0) { error = errno; goto done; }
    if (object_inventory(object_reg, reg, registry, id, highest)) { error = errno; goto done; }
    struct stat existing; if (!fstatat(object_reg, version, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) { error = EEXIST; goto done; }
    record_init(&intent, registry, INTENT, id); intent.sequence = highest + 1; strcpy(intent.version_id, version);
    if (previous) strcpy(intent.previous_version_id, previous); intent.original = inspected;
    char name[32]; snprintf(name, sizeof(name), "%08u.intent", intent.sequence);
    if (write_record(reg, name, &intent) || hook_call(hook, "after-intent")) { error = errno; goto done; }
    // This durable intent invalidates the old version before any snapshot bytes.
    if (mkdirat(object_reg, version, 0755)) { error = errno; goto done; }
    object_version = openat(object_reg, version, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (object_version < 0 || fchmod(object_version, 0755) || clear_created_xattrs(object_version) ||
        metadata(object_version, registry->owner, 1, 0755, 1) || fsync(object_reg) || mkdirat(object_version, "Snapshot.app", 0700)) { error = errno; goto done; }
    snapshot = openat(object_version, "Snapshot.app", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    source = absolute_dir(inspected.bundle, 0); if (snapshot < 0 || source < 0) { error = errno; goto done; }
    struct copy_limits limits = {0}; strcpy(limits.bundle, inspected.bundle);
    if (copy_tree(source, snapshot, registry, &limits, 0, hook) || fsync(object_version) || fsync(object_reg) || hook_call(hook, "after-object") ||
        envara_gui_manifest_unchanged(&inspected)) { error = errno; goto done; }
    char path[PATH_MAX]; if (snprintf(path, sizeof(path), "%s/objects/%s/%s/Snapshot.app", registry->root, id, version) >= (int)sizeof(path)) { error = ENAMETOOLONG; goto done; }
    if (envara_gui_manifest_inspect(path, registry->fixture_only, &intent.snapshot) || !content_matches(&intent.original, &intent.snapshot)) { error = ESTALE; goto done; }
    struct copy_limits sealed = {0}; strcpy(sealed.bundle, path);
    if (validate_tree(snapshot, registry, &sealed, 0) || envara_gui_manifest_unchanged(&inspected) || exact_version(object_version) ||
        object_inventory(object_reg, reg, registry, id, intent.sequence) ||
        named_chain(registry, records, objects, reg, object_reg, object_version, snapshot, id, version)) { error = errno ? errno : ESTALE; goto done; }
    intent.kind = COMMIT; snprintf(name, sizeof(name), "%08u.commit", intent.sequence);
    struct stat commit_identity; struct disk_record reread; unsigned final_highest;
    if (write_record(reg, name, &intent) || (committed_fd = pin_record(reg, name, registry, &commit_identity)) < 0 ||
        hook_call(hook, "after-commit") || pinned_record_unchanged(reg, name, committed_fd, &commit_identity) ||
        version_inventory(reg, registry, id, &final_highest, &reread) || final_highest != intent.sequence || memcmp(&reread, &intent, sizeof(intent)) ||
        exact_version(object_version) || object_inventory(object_reg, reg, registry, id, intent.sequence) ||
        named_chain(registry, records, objects, reg, object_reg, object_version, snapshot, id, version)) { error = errno ? errno : ESTALE; goto done; }
    if (result_of(&intent, out)) error = errno;
done:
    if (committed_fd >= 0) close(committed_fd);
    if (snapshot >= 0) close(snapshot); if (source >= 0) close(source); if (object_version >= 0) close(object_version);
    if (object_reg >= 0) close(object_reg); if (reg >= 0) close(reg); if (objects >= 0) close(objects); if (records >= 0) close(records);
    flock(registry->fd, LOCK_UN); return error ? refuse(error) : 0;
}
int envara_app_registry_resolve(struct envara_app_registry *registry, const char *id, const char *version, struct envara_app_registration *out) {
    if (handle_valid(registry) || !uuid(id) || !uuid(version) || !out) return refuse(EINVAL);
    if (flock(registry->fd, LOCK_SH | LOCK_NB)) return -1;
    int records = -1, objects = -1, reg = -1, object_reg = -1, object_version = -1, snapshot = -1, committed_fd = -1, error = 0;
    size_t count; unsigned highest = 0, final_highest = 0; struct disk_record current, final;
    if (root_inventory(registry, &records, &objects, &count) || (reg = open_dir(records, id, registry->owner, 0700)) < 0 ||
        version_inventory(reg, registry, id, &highest, &current) || !highest) { error = errno ? errno : ENOENT; goto done; }
    if (strcmp(current.version_id, version) || !string_ok(current.snapshot.bundle, PATH_MAX)) { error = ESTALE; goto done; }
    char expected[PATH_MAX]; if (snprintf(expected, sizeof(expected), "%s/objects/%s/%s/Snapshot.app", registry->root, id, version) >= (int)sizeof(expected) ||
        strcmp(expected, current.snapshot.bundle)) { error = EILSEQ; goto done; }
    char commit_name[32]; struct stat commit_identity; snprintf(commit_name, sizeof(commit_name), "%08u.commit", highest);
    committed_fd = pin_record(reg, commit_name, registry, &commit_identity); if (committed_fd < 0) { error = errno; goto done; }
    object_reg = open_dir(objects, id, registry->owner, 0755); if (object_reg < 0) { error = errno; goto done; }
    if (object_inventory(object_reg, reg, registry, id, highest)) { error = errno; goto done; }
    object_version = open_dir(object_reg, version, registry->owner, 0755); if (object_version < 0) { error = errno; goto done; }
    if (exact_version(object_version)) { error = errno; goto done; }
    snapshot = open_dir(object_version, "Snapshot.app", registry->owner, 0555); if (snapshot < 0) { error = errno; goto done; }
    struct copy_limits limits = {0}; strcpy(limits.bundle, expected);
    if (validate_tree(snapshot, registry, &limits, 0) || envara_gui_manifest_unchanged(&current.original) ||
        envara_gui_manifest_unchanged(&current.snapshot) || !content_matches(&current.original, &current.snapshot) ||
        version_inventory(reg, registry, id, &final_highest, &final) || highest != final_highest || memcmp(&current, &final, sizeof(current)) ||
        object_inventory(object_reg, reg, registry, id, highest) || exact_version(object_version) ||
        pinned_record_unchanged(reg, commit_name, committed_fd, &commit_identity) ||
        named_chain(registry, records, objects, reg, object_reg, object_version, snapshot, id, version)) { error = errno ? errno : ESTALE; goto done; }
    struct stat held, named;
    if (fstat(snapshot, &held) || lstat(expected, &named) || !same_stat(&held, &named)) { error = ESTALE; goto done; }
    if (result_of(&current, out)) error = errno;
done:
    if (committed_fd >= 0) close(committed_fd);
    if (snapshot >= 0) close(snapshot); if (object_version >= 0) close(object_version); if (object_reg >= 0) close(object_reg);
    if (reg >= 0) close(reg); if (objects >= 0) close(objects); if (records >= 0) close(records);
    flock(registry->fd, LOCK_UN); return error ? refuse(error) : 0;
}
int envara_app_registry_retire(struct envara_app_registry *registry, const char *id) {
    if (handle_valid(registry) || !uuid(id)) return refuse(EINVAL);
    if (flock(registry->fd, LOCK_EX | LOCK_NB)) return -1;
    int records = -1, objects = -1, reg = -1, error = 0; size_t count; struct disk_record descriptor, dead;
    if (root_inventory(registry, &records, &objects, &count) || (reg = open_dir(records, id, registry->owner, 0700)) < 0 ||
        read_record(reg, "descriptor", registry, DESCRIPTOR, id, &descriptor)) error = errno;
    else { record_init(&dead, registry, RETIRED, id); dead.original = descriptor.original;
        if (handle_valid(registry) || named_dir(registry->fd, "registrations", records, registry, 0700) ||
            named_dir(records, id, reg, registry, 0700) || write_record(reg, "retired", &dead) ||
            handle_valid(registry) || named_dir(registry->fd, "registrations", records, registry, 0700) ||
            named_dir(records, id, reg, registry, 0700)) error = errno; }
    if (reg >= 0) close(reg); if (objects >= 0) close(objects); if (records >= 0) close(records);
    flock(registry->fd, LOCK_UN); return error ? refuse(error) : 0;
}
