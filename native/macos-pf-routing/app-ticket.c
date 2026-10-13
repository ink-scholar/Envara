#include "app-ticket.h"
#include <CommonCrypto/CommonDigest.h>
#include <mach/mach_time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

enum { RESERVED = 1, ISSUED = 2, CLAIMED = 3 };
struct ticket_record { char magic[8]; uint32_t size, kind, owner; struct envara_app_ticket ticket; char checksum[65]; };
static int reject(int error) { errno = error; return -1; }
static int bounded(const char *s, size_t n) { return s && memchr(s, 0, n) && strnlen(s, n) > 0; }
static int uuid(const char *s) {
    if (!bounded(s, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i = 0; i < 36; i++) if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!strchr("0123456789abcdef", s[i])) return 0;
    return 1;
}
static int digest(const char *s) {
    if (!bounded(s, 65) || strlen(s) != 64) return 0;
    for (int i = 0; i < 64; i++) if (!strchr("0123456789abcdef", s[i])) return 0;
    return 1;
}
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int object(int fd, uid_t owner, int directory, mode_t mode) {
    struct stat info; char path[PATH_MAX];
    if (fstat(fd, &info) || (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) || info.st_uid != owner ||
        (info.st_mode & 07777) != mode || (!directory && info.st_nlink != 1) || fcntl(fd, F_GETPATH, path) ||
        envara_gui_acl_free(path)) return reject(EACCES);
    return 0;
}
static int absolute_dir(const char *path, int production) {
    char parts[PATH_MAX]; if (!bounded(path, PATH_MAX) || path[0] != '/') return reject(EINVAL); strcpy(parts, path);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return -1;
    char *save = NULL;
    for (char *part = strtok_r(parts, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return reject(EINVAL); }
        if (production) { struct stat info; char held[PATH_MAX];
            if (fstat(fd, &info) || info.st_uid || (info.st_mode & (S_ISUID | S_ISGID | 0022)) ||
                fcntl(fd, F_GETPATH, held) || envara_gui_acl_free(held)) { close(fd); return reject(EACCES); } }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { int error = errno; close(fd); return reject(error); } close(fd); fd = next;
    }
    return fd;
}
static int valid_store(struct envara_app_ticket_store *store) {
    if (!store || store->fd < 0 || (store->fixture_only != 0 && store->fixture_only != 1) ||
        (store->fixture_only ? !getuid() || geteuid() != getuid() || store->owner != getuid() :
         getuid() || geteuid() || store->owner || strcmp(store->root, ENVARA_APP_TICKET_ROOT))) return reject(EACCES);
    char canonical[PATH_MAX]; struct stat held, named;
    if (!realpath(store->root, canonical) || strcmp(canonical, store->root)) return reject(ESTALE);
    int chain = absolute_dir(store->root, !store->fixture_only); if (chain < 0) return -1;
    int ok = !fstat(store->fd, &held) && !fstat(chain, &named) && held.st_dev == named.st_dev && held.st_ino == named.st_ino;
    close(chain); if (!ok || object(store->fd, store->owner, 1, 0700)) return reject(ESTALE); return 0;
}
int envara_app_ticket_store_open(struct envara_app_ticket_store *store, const char *fixture_root, int fixture, int create) {
    if (!store || (fixture != 0 && fixture != 1) || (create != 0 && create != 1)) return reject(EINVAL);
    memset(store, 0, sizeof(*store)); store->fd = -1;
    const char *root = fixture ? fixture_root : ENVARA_APP_TICKET_ROOT;
    if (!bounded(root, PATH_MAX) || root[0] != '/' || (fixture ? !getuid() || geteuid() != getuid() || !strncmp(root, "/Library/", 9) : getuid() || geteuid())) return reject(EACCES);
    char parent[PATH_MAX], canonical[PATH_MAX]; strcpy(parent, root); char *slash = strrchr(parent, '/');
    if (!slash || slash == parent || !slash[1]) return reject(EINVAL);
    char leaf[256]; if (strlen(slash + 1) >= sizeof(leaf)) return reject(EINVAL); strcpy(leaf, slash + 1); *slash = 0;
    if (!realpath(parent, canonical) || strcmp(parent, canonical)) return reject(EINVAL);
    int fd = absolute_dir(parent, !fixture); if (fd < 0) return -1;
    uid_t owner = fixture ? getuid() : 0;
    if (fixture && object(fd, owner, 1, 0700)) { close(fd); return -1; }
    if (create && mkdirat(fd, leaf, 0700) && errno != EEXIST) { int error = errno; close(fd); return reject(error); }
    int child = openat(fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0 || object(child, owner, 1, 0700) || (create && fsync(fd))) { int error = errno; if (child >= 0) close(child); close(fd); return reject(error); }
    close(fd); store->fd = child; store->owner = owner; store->fixture_only = fixture; strcpy(store->root, root);
    return valid_store(store);
}
void envara_app_ticket_store_close(struct envara_app_ticket_store *store) { if (store && store->fd >= 0) close(store->fd); if (store) { memset(store, 0, sizeof(*store)); store->fd = -1; } }
static int clock_read(uint64_t *now, char boot[64]) {
    mach_timebase_info_data_t base; if (mach_timebase_info(&base) != KERN_SUCCESS || !base.denom) return reject(EIO);
    uint64_t ticks = mach_continuous_time(); __uint128_t nanos = (__uint128_t)ticks * base.numer / base.denom;
    if (nanos > UINT64_MAX) return reject(EOVERFLOW); *now = (uint64_t)nanos;
    size_t size = 64; memset(boot, 0, 64);
    if (sysctlbyname("kern.bootsessionuuid", boot, &size, NULL, 0) || !bounded(boot, 64)) return reject(EIO); return 0;
}
static void checksum(struct ticket_record *record, char out[65]) {
    char saved[65]; unsigned char hash[CC_SHA256_DIGEST_LENGTH]; memcpy(saved, record->checksum, 65); memset(record->checksum, 0, 65);
    CC_SHA256(record, sizeof(*record), hash); memcpy(record->checksum, saved, 65);
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(out + i * 2, 3, "%02x", hash[i]); out[64] = 0;
}
static int write_record(int fd, const char *name, struct ticket_record *record) {
    checksum(record, record->checksum); int file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0) return -1; size_t offset = 0; int error = 0;
    while (offset < sizeof(*record)) { ssize_t n = write(file, (char *)record + offset, sizeof(*record) - offset);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { error = errno ? errno : EIO; break; } offset += n; }
    if (!error && (fchmod(file, 0600) || fsync(file))) error = errno;
    if (close(file) && !error) error = errno; if (!error && fsync(fd)) error = errno;
    return error ? reject(error) : 0; /* Never unlink an uncertain record. */
}
static int read_record(int fd, const char *name, unsigned kind, struct envara_app_ticket_store *store, const char *id, struct ticket_record *record) {
    int file = openat(fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC); if (file < 0) return -1;
    struct stat before, after, named; int error = 0; size_t offset = 0;
    if (object(file, store->owner, 0, 0600) || fstat(file, &before) || before.st_size != sizeof(*record)) error = EILSEQ;
    while (!error && offset < sizeof(*record)) { ssize_t n = read(file, (char *)record + offset, sizeof(*record) - offset);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { error = EIO; break; } offset += n; }
    if (!error && (fstat(file, &after) || fstatat(fd, name, &named, AT_SYMLINK_NOFOLLOW) || !same(&before, &after) || !same(&after, &named))) error = ESTALE;
    close(file); if (error) return reject(error); char hash[65]; checksum(record, hash);
    struct envara_app_ticket *t = &record->ticket;
    if (memcmp(record->magic, "EVTKT01", 8) || record->size != sizeof(*record) || record->kind != kind || record->owner != store->owner ||
        !digest(record->checksum) || strcmp(hash, record->checksum) || t->schema != ENVARA_APP_TICKET_SCHEMA || t->fixture_only != store->fixture_only ||
        t->ready || t->protected_ready || !uuid(t->ticket_id) || (id && strcmp(t->ticket_id, id)) || !uuid(t->environment_id) || !uuid(t->run_id) ||
        !uuid(t->request.lease_id) || !uuid(t->request.environment_id) ||
        !uuid(t->app.registration_id) || !uuid(t->app.version_id) || !bounded(t->boot_id, 64) || !digest(t->environment_lease_sha256) ||
        t->app.fixture_only != store->fixture_only || t->app.ready || t->app.protected_ready || t->issued_ns > UINT64_MAX - ENVARA_APP_TICKET_LIFETIME_NS ||
        t->expires_ns != t->issued_ns + ENVARA_APP_TICKET_LIFETIME_NS) return reject(EILSEQ);
    return 0;
}
static int directory_named(struct envara_app_ticket_store *store, const char *id, int fd) {
    struct stat held, named;
    if (valid_store(store) || object(fd, store->owner, 1, 0700) || fstat(fd, &held) ||
        fstatat(store->fd, id, &named, AT_SYMLINK_NOFOLLOW) || !same(&held, &named)) return reject(ESTALE); return 0;
}
static int inventory(struct envara_app_ticket_store *store, size_t *count) {
    int scan = openat(store->fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (scan < 0) return -1;
    DIR *dir = fdopendir(scan); if (!dir) { close(scan); return -1; } struct dirent *entry; int error = 0; *count = 0; errno = 0;
    size_t bindings = 0, leases = 0, runs = 0;
    while ((entry = readdir(dir))) { if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        const char *binding_id = !strncmp(entry->d_name, "lease.", 6) ? entry->d_name + 6 : !strncmp(entry->d_name, "run.", 4) ? entry->d_name + 4 : NULL;
        if (binding_id) {
            if (++bindings > 2 * ENVARA_APP_TICKET_MAX || !uuid(binding_id)) { error = ENOSPC; break; }
            if (!strncmp(entry->d_name, "lease.", 6)) leases++; else runs++;
            if (leases > ENVARA_APP_TICKET_MAX || runs > ENVARA_APP_TICKET_MAX) { error = ENOSPC; break; }
            struct ticket_record record;
            if (read_record(store->fd, entry->d_name, RESERVED, store, NULL, &record) ||
                strcmp(binding_id, !strncmp(entry->d_name, "lease.", 6) ? record.ticket.request.lease_id : record.ticket.run_id)) error = EILSEQ;
            if (error) break; errno = 0; continue;
        }
        if (++*count > ENVARA_APP_TICKET_MAX || !uuid(entry->d_name)) { error = ENOSPC; break; }
        int child = openat(store->fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 || object(child, store->owner, 1, 0700)) error = EILSEQ; if (child >= 0) close(child); if (error) break; errno = 0; }
    if (!error && errno) error = errno; if (closedir(dir) && !error) error = errno;
    if (*count < leases) *count = leases; if (*count < runs) *count = runs;
    return error ? reject(error) : 0;
}
static int files_exact(int fd, int allow_claimed) {
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (scan < 0) return -1;
    DIR *dir = fdopendir(scan); if (!dir) { close(scan); return -1; } int mask = 0, error = 0; struct dirent *entry; errno = 0;
    while ((entry = readdir(dir))) { if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, "reserved")) mask |= 1; else if (!strcmp(entry->d_name, "ticket")) mask |= 2;
        else if (!strcmp(entry->d_name, "claimed")) mask |= 4; else { error = EILSEQ; break; } errno = 0; }
    if (!error && errno) error = errno; if (closedir(dir) && !error) error = errno;
    if (!error && (mask & 4) && !allow_claimed) error = EALREADY;
    if (!error && mask != (allow_claimed ? 7 : 3)) error = EAGAIN; return error ? reject(error) : 0;
}
static int live_time(const struct envara_app_ticket *t) {
    uint64_t now; char boot[64];
    if (clock_read(&now, boot) || strcmp(boot, t->boot_id) || now < t->issued_ns || now >= t->expires_ns) return reject(ESTALE);
    return 0;
}
static int fresh(struct envara_app_ticket *t, struct envara_app_registry *registry) {
    struct envara_app_registration current;
    if (live_time(t)) return -1;
    if (envara_app_registry_resolve(registry, t->app.registration_id, t->app.version_id, &current) ||
        memcmp(&current, &t->app, sizeof(current)) || envara_gui_request_validate(&current.snapshot, &t->request, registry->fixture_only) ||
        strcmp(t->request.environment_id, t->environment_id)) return reject(ESTALE);
    return live_time(t);
}
static int authority_fresh(struct envara_app_ticket *t, const struct envara_app_ticket_authority *authority) {
    if (!authority || !authority->inspect || !authority->verify || !authority->adopt) return reject(ENOTSUP);
    struct envara_gui_request request; char hash[65]; memset(&request, 0, sizeof(request)); memset(hash, 0, sizeof(hash));
    if (authority->inspect(t->environment_id, t->run_id, &t->app, &request, hash, authority->context) || !digest(hash) ||
        memcmp(&request, &t->request, sizeof(request)) || strcmp(hash, t->environment_lease_sha256) ||
        authority->verify(&t->app, &request, t->run_id, hash, authority->context)) return reject(ESTALE); return live_time(t);
}
static int read_ticket(int fd, struct envara_app_ticket_store *store, struct envara_app_registry *registry, const char *id, struct ticket_record *out) {
    struct ticket_record reserved, lease_binding, run_binding; char lease_name[64], run_name[64];
    if (files_exact(fd, 0) || read_record(fd, "reserved", RESERVED, store, id, &reserved) ||
        read_record(fd, "ticket", ISSUED, store, id, out) || memcmp(&reserved.ticket, &out->ticket, sizeof(out->ticket)) ||
        fresh(&out->ticket, registry) || directory_named(store, id, fd)) return reject(errno ? errno : ESTALE);
    snprintf(lease_name, sizeof(lease_name), "lease.%s", out->ticket.request.lease_id); snprintf(run_name, sizeof(run_name), "run.%s", out->ticket.run_id);
    if (read_record(store->fd, lease_name, RESERVED, store, id, &lease_binding) || read_record(store->fd, run_name, RESERVED, store, id, &run_binding) ||
        memcmp(&lease_binding.ticket, &out->ticket, sizeof(out->ticket)) || memcmp(&run_binding.ticket, &out->ticket, sizeof(out->ticket))) return reject(ESTALE);
    return 0;
}
/* Expired tickets and their lease/run bindings are moved, never deleted, into
 * a sibling archive, and a ticket, lease or run named there is still refused
 * exactly as in the live store. Archiving frees the bounded live store without
 * weakening the replay refusal: every attach used to leave one ticket and two
 * bindings behind, and after 64 attaches the store refused every further one.
 * The archive is never pruned, so no burned identity is ever forgotten. */
static int archive_open(struct envara_app_ticket_store *store) {
    char parent[PATH_MAX], leaf[300]; strcpy(parent, store->root); char *slash = strrchr(parent, '/');
    if (!slash || slash == parent || !slash[1]) return reject(EINVAL);
    if (snprintf(leaf, sizeof(leaf), "%s-archive", slash + 1) >= (int)sizeof(leaf)) return reject(ENAMETOOLONG);
    *slash = 0;
    int fd = absolute_dir(parent, !store->fixture_only); if (fd < 0) return -1;
    int created = !mkdirat(fd, leaf, 0700);
    if (!created && errno != EEXIST) { int error = errno; close(fd); return reject(error); }
    int archive = openat(fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (archive < 0 || object(archive, store->owner, 1, 0700) || (created && fsync(fd))) {
        int error = errno ? errno : EACCES; if (archive >= 0) close(archive); close(fd); return reject(error); }
    close(fd); return archive;
}
static int archived(int archive, const char *name) {
    struct stat existing; return !fstatat(archive, name, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT;
}
static int record_expired(int fd, const char *name, struct envara_app_ticket_store *store, uint64_t now, const char *boot) {
    struct ticket_record record;
    if (read_record(fd, name, RESERVED, store, NULL, &record)) return 0; /* Unreadable: left exactly where it is. */
    return strcmp(record.ticket.boot_id, boot) || now >= record.ticket.expires_ns;
}
static void archive_expired(struct envara_app_ticket_store *store, int archive) {
    uint64_t now; char boot[64]; if (clock_read(&now, boot)) return;
    int scan = openat(store->fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (scan < 0) return;
    DIR *dir = fdopendir(scan); if (!dir) { close(scan); return; }
    /* Names are collected first and moved after, so a listing in progress is
     * never mutated. Anything beyond this bound is handled by the next attach. */
    char *names[3 * ENVARA_APP_TICKET_MAX + 8]; size_t count = 0; struct dirent *entry;
    while (count < sizeof(names) / sizeof(names[0]) && (entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!(names[count] = strdup(entry->d_name))) break;
        count++;
    }
    closedir(dir);
    for (size_t i = 0; i < count; i++) {
        const char *name = names[i]; int expired = 0;
        if (!strncmp(name, "lease.", 6) || !strncmp(name, "run.", 4)) expired = record_expired(store->fd, name, store, now, boot);
        else if (uuid(name)) {
            int child = openat(store->fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child >= 0) { expired = !object(child, store->owner, 1, 0700) && record_expired(child, "reserved", store, now, boot); close(child); }
        }
        if (expired) (void)renameatx_np(store->fd, name, archive, name, RENAME_EXCL);
        free(names[i]);
    }
    (void)fsync(archive); (void)fsync(store->fd);
}
int envara_app_ticket_prepare(struct envara_app_ticket_store *store, struct envara_app_registry *registry,
    const char *id, const char *registration, const char *version, const char *environment, const char *run,
    const struct envara_app_ticket_authority *authority, struct envara_app_ticket *out) {
    if (!out || valid_store(store) || !registry || registry->fixture_only != store->fixture_only ||
        !uuid(id) || !uuid(registration) || !uuid(version) || !uuid(environment) || !uuid(run)) return reject(EINVAL);
    memset(out, 0, sizeof(*out)); if (!authority || !authority->inspect || !authority->verify || !authority->adopt) return reject(ENOTSUP);
    if (flock(store->fd, LOCK_EX | LOCK_NB)) return -1; int fd = -1, error = 0; size_t count; struct ticket_record record; memset(&record, 0, sizeof(record));
    /* Without the archive a replay of an archived identity could not be
     * refused, so no ticket is prepared when it cannot be opened. */
    int archive = archive_open(store);
    if (archive < 0) { error = errno ? errno : EACCES; flock(store->fd, LOCK_UN); return reject(error); }
    archive_expired(store, archive);
    memcpy(record.magic, "EVTKT01", 8); record.size = sizeof(record); record.kind = RESERVED; record.owner = store->owner;
    struct envara_app_ticket *t = &record.ticket; t->schema = ENVARA_APP_TICKET_SCHEMA; t->fixture_only = store->fixture_only;
    strcpy(t->ticket_id, id); strcpy(t->environment_id, environment); strcpy(t->run_id, run);
    if (inventory(store, &count) || count >= ENVARA_APP_TICKET_MAX) { error = errno ? errno : ENOSPC; goto done; }
    if (envara_app_registry_resolve(registry, registration, version, &t->app) ||
        authority->inspect(environment, run, &t->app, &t->request, t->environment_lease_sha256, authority->context) || !digest(t->environment_lease_sha256) ||
        envara_gui_request_validate(&t->app.snapshot, &t->request, store->fixture_only) || strcmp(t->request.environment_id, environment) ||
        authority->verify(&t->app, &t->request, run, t->environment_lease_sha256, authority->context) || clock_read(&t->issued_ns, t->boot_id)) { error = errno ? errno : EACCES; goto done; }
    if (t->issued_ns > UINT64_MAX - ENVARA_APP_TICKET_LIFETIME_NS) { error = EOVERFLOW; goto done; } t->expires_ns = t->issued_ns + ENVARA_APP_TICKET_LIFETIME_NS;
    char lease_name[64], run_name[64]; snprintf(lease_name, sizeof(lease_name), "lease.%s", t->request.lease_id); snprintf(run_name, sizeof(run_name), "run.%s", run);
    struct stat existing;
    if (!fstatat(store->fd, id, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
        !fstatat(store->fd, lease_name, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
        !fstatat(store->fd, run_name, &existing, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
        archived(archive, id) || archived(archive, lease_name) || archived(archive, run_name)) { error = EALREADY; goto done; }
    /* Independently burn the underlying native lease and run, not merely a
     * caller-selected ticket UUID. Partial indices are retained, never reused. */
    if (write_record(store->fd, lease_name, &record) || write_record(store->fd, run_name, &record) ||
        mkdirat(store->fd, id, 0700)) { error = errno; goto done; }
    fd = openat(store->fd, id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || object(fd, store->owner, 1, 0700) || fsync(store->fd) || directory_named(store, id, fd) ||
        write_record(fd, "reserved", &record)) { error = errno; goto done; }
    record.kind = ISSUED;
    if (fresh(t, registry) || authority_fresh(t, authority) || write_record(fd, "ticket", &record) || directory_named(store, id, fd)) { error = errno; goto done; }
    struct ticket_record check;
    if (read_ticket(fd, store, registry, id, &check) || memcmp(&check.ticket, t, sizeof(*t))) { error = errno ? errno : ESTALE; goto done; } *out = *t;
done: if (fd >= 0) close(fd); close(archive); flock(store->fd, LOCK_UN); return error ? reject(error) : 0;
}
int envara_app_ticket_inspect(struct envara_app_ticket_store *store, struct envara_app_registry *registry, const char *id, struct envara_app_ticket *out) {
    if (!out || valid_store(store) || !uuid(id) || !registry || registry->fixture_only != store->fixture_only) return reject(EINVAL);
    memset(out, 0, sizeof(*out)); if (flock(store->fd, LOCK_SH | LOCK_NB)) return -1; size_t count; int error = 0, fd = -1;
    struct ticket_record record;
    if (inventory(store, &count) || (fd = openat(store->fd, id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0 ||
        read_ticket(fd, store, registry, id, &record)) error = errno; else *out = record.ticket;
    if (fd >= 0) close(fd); flock(store->fd, LOCK_UN); return error ? reject(error) : 0;
}
int envara_app_ticket_claim(struct envara_app_ticket_store *store, struct envara_app_registry *registry, const char *id,
    const struct envara_app_ticket_authority *authority, struct envara_app_ticket *out) {
    if (!out || valid_store(store) || !uuid(id) || !registry || registry->fixture_only != store->fixture_only) return reject(EINVAL);
    memset(out, 0, sizeof(*out)); if (!authority || !authority->inspect || !authority->verify || !authority->adopt) return reject(ENOTSUP);
    if (flock(store->fd, LOCK_EX | LOCK_NB)) return -1; size_t count; int fd = -1, error = 0; struct ticket_record record;
    if (inventory(store, &count) || (fd = openat(store->fd, id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0 ||
        read_ticket(fd, store, registry, id, &record) || authority_fresh(&record.ticket, authority) ||
        fresh(&record.ticket, registry) || directory_named(store, id, fd)) { error = errno; goto done; }
    record.kind = CLAIMED;
    if (write_record(fd, "claimed", &record) || directory_named(store, id, fd) || files_exact(fd, 1)) { error = errno; goto done; }
    *out = record.ticket;
done: if (fd >= 0) close(fd); flock(store->fd, LOCK_UN); return error ? reject(error) : 0;
}
struct stage_context { struct envara_app_ticket ticket; const struct envara_app_ticket_authority *authority; struct envara_app_registry *registry; };
static int stage_verify(const struct envara_gui_request *request, void *context) {
    struct stage_context *ctx = context;
    return memcmp(request, &ctx->ticket.request, sizeof(*request)) || fresh(&ctx->ticket, ctx->registry) || authority_fresh(&ctx->ticket, ctx->authority) ? -1 : 0;
}
int envara_app_ticket_stage(struct envara_app_ticket_store *store, struct envara_app_registry *registry, const char *id,
    const struct envara_app_ticket_authority *authority, struct envara_gui_lifecycle *out) {
    if (!out || out->phase != ENVARA_GUI_EMPTY) return reject(EALREADY);
    struct stage_context context; memset(&context, 0, sizeof(context)); context.authority = authority; context.registry = registry;
    if (envara_app_ticket_claim(store, registry, id, authority, &context.ticket)) return -1;
    struct envara_gui_stage_authority committed = {stage_verify, &context};
    if (envara_gui_stage(&context.ticket.app.original, &context.ticket.app.snapshot, &context.ticket.request,
        store->fixture_only, &committed, -1, -1, out)) return -1;
    if (authority->adopt(&context.ticket, out, authority->context)) {
        int error = errno ? errno : EIO; envara_gui_cancel(out); out->phase = ENVARA_GUI_UNCERTAIN; out->protected_ready = 0;
        return reject(error); /* Claim and deny remain retained; no family cleanup claim. */
    }
    return 0;
}
