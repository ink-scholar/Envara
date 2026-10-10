#include "journal-retirement.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ENVARA_JOURNAL_RETIREMENT_INERT
enum {
    ENVARA_JR_INTENT_CREATE = 1, ENVARA_JR_INTENT_WRITE,
    ENVARA_JR_INTENT_FILE_FSYNC, ENVARA_JR_INTENT_PARENT_FSYNC,
    ENVARA_JR_FILE_UNLINK, ENVARA_JR_FILE_DIRECTORY_FSYNC,
    ENVARA_JR_DIRECTORY_UNLINK, ENVARA_JR_DIRECTORY_PARENT_FSYNC,
    ENVARA_JR_INTENT_UNLINK, ENVARA_JR_FINAL_PARENT_FSYNC
};
#endif

static int jr_refuse(int error) { errno = error; return 0; }

#ifdef ENVARA_JOURNAL_RETIREMENT_INERT
static struct { pid_t owner; int event, after; unsigned remaining; } jr_fault;
int envara_journal_retirement_test_fault(int event, unsigned occurrence, int after) {
    if (event < ENVARA_JR_INTENT_CREATE || event > ENVARA_JR_FINAL_PARENT_FSYNC ||
        !occurrence || (after != 0 && after != 1)) return jr_refuse(EINVAL);
    jr_fault.owner = getpid(); jr_fault.event = event;
    jr_fault.after = after; jr_fault.remaining = occurrence;
    return 1;
}
static int jr_checkpoint(int event, int after) {
    if (jr_fault.owner == getpid() && jr_fault.event == event &&
        jr_fault.after == after && jr_fault.remaining && !--jr_fault.remaining) {
        jr_fault.event = 0; return jr_refuse(EIO);
    }
    return 1;
}
#else
static int jr_checkpoint(int event, int after) { (void)event; (void)after; return 1; }
#endif

static int jr_name(const char *name) {
    if (!name || !*name || strnlen(name, ENVARA_JOURNAL_RETIREMENT_NAME_BYTES) >=
        ENVARA_JOURNAL_RETIREMENT_NAME_BYTES || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}
static int jr_object(const struct stat *a, const struct stat *b) {
    if (a->st_dev != b->st_dev || a->st_ino != b->st_ino || a->st_mode != b->st_mode ||
        a->st_uid != b->st_uid || a->st_gid != b->st_gid) return 0;
#ifdef __APPLE__
    if (a->st_flags != b->st_flags || a->st_gen != b->st_gen) return 0;
#endif
    return 1;
}
static int jr_times(const struct stat *a, const struct stat *b, int ctime) {
#ifdef __APPLE__
    return a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && (!ctime ||
        (a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
         a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec));
#else
    return a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        (!ctime || (a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec));
#endif
}
static int jr_same(const struct stat *a, const struct stat *b) {
    return jr_object(a, b) && a->st_nlink == b->st_nlink && a->st_size == b->st_size && jr_times(a, b, 1);
}
static int jr_secure(const struct stat *s, int directory, uid_t uid, gid_t gid) {
    return (directory ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode)) &&
        s->st_uid == uid && s->st_gid == gid && (s->st_mode & 07777) == (directory ? 0700 : 0600);
}
static int jr_read_exact(int fd, const unsigned char *bytes, size_t length) {
    unsigned char buffer[1024]; size_t offset = 0;
    while (offset < length) {
        size_t want = length - offset; if (want > sizeof(buffer)) want = sizeof(buffer);
        ssize_t n = pread(fd, buffer, want, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || memcmp(buffer, bytes + offset, (size_t)n)) return jr_refuse(ESTALE);
        offset += (size_t)n;
    }
    unsigned char extra; ssize_t n;
    do { n = pread(fd, &extra, 1, (off_t)length); } while (n < 0 && errno == EINTR);
    return n == 0 ? 1 : jr_refuse(ESTALE);
}
static int jr_file_verify(struct envara_journal_retirement *s, size_t i) {
    struct envara_journal_retirement_file *f = &s->files[i]; struct stat held, after, named;
    if (fstat(f->fd, &held) || !jr_secure(&held, 0, s->uid, s->gid) ||
        !jr_object(&held, &f->identity) || held.st_size != (off_t)f->length ||
        !jr_times(&held, &f->identity, !f->unlinked) ||
        !jr_read_exact(f->fd, f->bytes, f->length) || fstat(f->fd, &after) ||
        !jr_same(&held, &after)) return jr_refuse(ESTALE);
    if (!f->unlinked) {
        if (held.st_nlink != 1 || fstatat(s->directory_fd, f->name, &named, AT_SYMLINK_NOFOLLOW) ||
            !jr_same(&held, &named) || !jr_same(&held, &f->identity)) return jr_refuse(ESTALE);
    } else {
        /* Missing names are accepted only for successful unlinks recorded by
         * this live object, while the original held inode remains unlinked. */
        if (held.st_nlink != 0 || !fstatat(s->directory_fd, f->name, &named, AT_SYMLINK_NOFOLLOW) ||
            errno != ENOENT || (f->unlinked_identity_set && !jr_same(&held, &f->unlinked_identity))) return jr_refuse(ESTALE);
        if (!f->unlinked_identity_set) { f->unlinked_identity = held; f->unlinked_identity_set = 1; }
    }
    return 1;
}
static int jr_intent_verify(struct envara_journal_retirement *s) {
    struct stat held, after, named;
    if (!s->intent_created) {
        if (!fstatat(s->parent_fd, s->intent_name, &named, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)
            return jr_refuse(EEXIST);
        return 1;
    }
    if (s->intent_fd < 0 || fstat(s->intent_fd, &held) ||
        !jr_secure(&held, 0, s->uid, s->gid) || !jr_object(&held, &s->intent_identity) ||
        held.st_size != (off_t)s->intent_written ||
        !jr_times(&held, &s->intent_identity, !s->intent_unlinked) ||
        !jr_read_exact(s->intent_fd, s->intent_bytes, s->intent_written) ||
        fstat(s->intent_fd, &after) || !jr_same(&held, &after)) return jr_refuse(ESTALE);
    if (s->intent_unlinked) {
        if (held.st_nlink != 0 || !fstatat(s->parent_fd, s->intent_name, &named, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
            (s->intent_unlinked_identity_set && !jr_same(&held, &s->intent_unlinked_identity)))
            return jr_refuse(ESTALE);
        if (!s->intent_unlinked_identity_set) { s->intent_unlinked_identity = held; s->intent_unlinked_identity_set = 1; }
    } else if (held.st_nlink != 1 || fstatat(s->parent_fd, s->intent_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !jr_same(&held, &named) || !jr_same(&held, &s->intent_identity)) return jr_refuse(ESTALE);
    return 1;
}
static int jr_verify(struct envara_journal_retirement *s) {
    struct stat parent, held, named;
    if (!s || !s->initialized || s->owner != getpid() || !s->guard ||
        fstat(s->parent_fd, &parent) || !jr_secure(&parent, 1, s->uid, s->gid) ||
        !jr_object(&parent, &s->parent_identity) || fstat(s->directory_fd, &held) ||
        !jr_secure(&held, 1, s->uid, s->gid) || !jr_object(&held, &s->directory_identity)) return jr_refuse(ESTALE);
    if (s->directory_unlinked) {
        if (!fstatat(s->parent_fd, s->directory_name, &named, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
            (s->directory_unlinked_identity_set && !jr_same(&held, &s->directory_unlinked_identity)))
            return jr_refuse(ESTALE);
#ifdef __APPLE__
        /* APFS retains nlink=2 on a held removed directory. Require our own
         * successful rmdir, exact absent parent name, immutable held identity,
         * the original held-FD path, and an empty inventory below. A renamed
         * still-live directory changes F_GETPATH and cannot be adopted. */
        char current_path[4096];
        if (held.st_nlink > 2 || fcntl(s->directory_fd, F_GETPATH, current_path) ||
            strcmp(current_path, s->directory_path)) return jr_refuse(ESTALE);
#else
        if (held.st_nlink != 0) return jr_refuse(ESTALE);
#endif
        if (!s->directory_unlinked_identity_set) {
            s->directory_unlinked_identity = held; s->directory_unlinked_identity_set = 1;
        }
    } else if (held.st_nlink < 2 || fstatat(s->parent_fd, s->directory_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !jr_object(&held, &named)) return jr_refuse(ESTALE);
    for (size_t i = 0; i < s->count; i++) if (!jr_file_verify(s, i)) return 0;
    if (!jr_intent_verify(s)) return 0;
    int scan = openat(s->directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan < 0) return s->directory_unlinked && held.st_nlink == 0 && errno == ENOENT ? 1 : 0;
    DIR *directory = fdopendir(scan); if (!directory) { int e = errno; close(scan); return jr_refuse(e); }
    size_t count = 0; int ok = 1; struct dirent *entry; errno = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size_t i = 0; while (i < s->count && strcmp(entry->d_name, s->files[i].name)) i++;
        if (i == s->count || s->files[i].unlinked || !jr_file_verify(s, i)) { ok = 0; break; }
        count++; errno = 0;
    }
    if (errno) ok = 0;
    size_t expected = 0; for (size_t i = 0; i < s->count; i++) if (!s->files[i].unlinked) expected++;
    if (count != expected) ok = 0;
    if (closedir(directory)) ok = 0;
    return ok ? 1 : jr_refuse(ESTALE);
}
static int jr_before(struct envara_journal_retirement *s, int event) {
    if (!jr_verify(s)) return 0;
    errno = 0; if (s->guard(s->opaque) != 1) return jr_refuse(errno ? errno : EACCES);
    return jr_verify(s) && jr_checkpoint(event, 0);
}
int envara_journal_retirement_verify(struct envara_journal_retirement *s) { return jr_verify(s); }
static void jr_put_u64(unsigned char **p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) { *(*p)++ = (unsigned char)value; value >>= 8; }
}
static void jr_put_stat(unsigned char **p, const struct stat *s) {
    jr_put_u64(p, (uint64_t)s->st_dev); jr_put_u64(p, (uint64_t)s->st_ino);
    jr_put_u64(p, (uint64_t)s->st_mode); jr_put_u64(p, (uint64_t)s->st_uid);
    jr_put_u64(p, (uint64_t)s->st_gid); jr_put_u64(p, (uint64_t)s->st_nlink);
    jr_put_u64(p, (uint64_t)s->st_size);
#ifdef __APPLE__
    jr_put_u64(p, (uint64_t)s->st_mtimespec.tv_sec); jr_put_u64(p, (uint64_t)s->st_mtimespec.tv_nsec);
    jr_put_u64(p, (uint64_t)s->st_ctimespec.tv_sec); jr_put_u64(p, (uint64_t)s->st_ctimespec.tv_nsec);
#else
    jr_put_u64(p, (uint64_t)s->st_mtim.tv_sec); jr_put_u64(p, (uint64_t)s->st_mtim.tv_nsec);
    jr_put_u64(p, (uint64_t)s->st_ctim.tv_sec); jr_put_u64(p, (uint64_t)s->st_ctim.tv_nsec);
#endif
}
void envara_journal_retirement_close(struct envara_journal_retirement *s) {
    if (!s || !s->initialized || s->owner != getpid()) return;
    if (s->parent_fd >= 0) close(s->parent_fd);
    if (s->directory_fd >= 0) close(s->directory_fd);
    if (s->intent_fd >= 0) close(s->intent_fd);
    for (size_t i = 0; i < s->count; i++) if (s->files[i].fd >= 0) close(s->files[i].fd);
    free(s->intent_bytes); memset(s, 0, sizeof(*s));
}
int envara_journal_retirement_init(struct envara_journal_retirement *s,
    int parent_fd, int directory_fd, const char *directory_name, const struct stat *identity,
    const struct envara_journal_retirement_entry *entries, size_t count,
    uid_t uid, gid_t gid, envara_journal_retirement_guard guard, void *opaque) {
    if (!s || s->initialized || parent_fd < 3 || directory_fd < 3 || !jr_name(directory_name) ||
        !identity || count > ENVARA_JOURNAL_RETIREMENT_MAX_FILES || (count && !entries) || !guard)
        return jr_refuse(EINVAL);
    errno = 0;
    memset(s, 0, sizeof(*s)); s->initialized = 1; s->owner = getpid(); s->uid = uid; s->gid = gid;
    s->parent_fd = s->directory_fd = s->intent_fd = -1;
    for (size_t i = 0; i < ENVARA_JOURNAL_RETIREMENT_MAX_FILES; i++) s->files[i].fd = -1;
    s->guard = guard; s->opaque = opaque; s->directory_identity = *identity;
    memcpy(s->directory_name, directory_name, strlen(directory_name) + 1);
    int n = snprintf(s->intent_name, sizeof(s->intent_name), "%s.retirement-intent", directory_name);
    if (n < 0 || (size_t)n >= sizeof(s->intent_name)) goto invalid;
    s->parent_fd = fcntl(parent_fd, F_DUPFD_CLOEXEC, 3);
    s->directory_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (s->parent_fd < 0 || s->directory_fd < 0 || fstat(s->parent_fd, &s->parent_identity)) goto invalid;
#ifdef __APPLE__
    if (fcntl(s->directory_fd, F_GETPATH, s->directory_path)) goto invalid;
#endif
    size_t capacity = 512;
    for (size_t i = 0; i < count; i++) {
        const struct envara_journal_retirement_entry *entry = &entries[i];
        if (!jr_name(entry->name) || entry->fd < 3 || entry->length > ENVARA_JOURNAL_RETIREMENT_MAX_BYTES ||
            (entry->length && !entry->bytes) || entry->identity.st_size != (off_t)entry->length ||
            entry->identity.st_nlink != 1 || !jr_secure(&entry->identity, 0, uid, gid)) goto invalid;
        for (size_t j = 0; j < i; j++) if (!strcmp(entry->name, s->files[j].name)) goto invalid;
        int flags = fcntl(entry->fd, F_GETFL); if (flags < 0 || (flags & O_ACCMODE) == O_WRONLY) goto invalid;
        struct envara_journal_retirement_file *file = &s->files[i];
        file->fd = fcntl(entry->fd, F_DUPFD_CLOEXEC, 3); if (file->fd < 0) goto invalid;
        s->count = i + 1; file->identity = entry->identity; file->length = entry->length;
        memcpy(file->name, entry->name, strlen(entry->name) + 1);
        if (entry->length) memcpy(file->bytes, entry->bytes, entry->length);
        capacity += strlen(entry->name) + entry->length + 128;
    }
    s->intent_bytes = calloc(capacity, 1); if (!s->intent_bytes) goto invalid;
    unsigned char *p = s->intent_bytes;
    static const unsigned char magic[] = "envara.journal-retirement/v1";
    memcpy(p, magic, sizeof(magic)); p += sizeof(magic);
    jr_put_stat(&p, &s->parent_identity); jr_put_stat(&p, &s->directory_identity);
    jr_put_u64(&p, strlen(s->directory_name)); memcpy(p, s->directory_name, strlen(s->directory_name)); p += strlen(s->directory_name);
    jr_put_u64(&p, s->count);
    for (size_t i = 0; i < s->count; i++) {
        struct envara_journal_retirement_file *f = &s->files[i];
        jr_put_u64(&p, strlen(f->name)); memcpy(p, f->name, strlen(f->name)); p += strlen(f->name);
        jr_put_stat(&p, &f->identity); jr_put_u64(&p, f->length);
        if (f->length) memcpy(p, f->bytes, f->length); p += f->length;
    }
    s->intent_length = (size_t)(p - s->intent_bytes);
    if (s->intent_length > capacity || !jr_verify(s)) goto invalid;
    return 1;
invalid: {
    int error = errno ? errno : EINVAL; envara_journal_retirement_close(s); return jr_refuse(error);
    }
}
int envara_journal_retirement_step(struct envara_journal_retirement *s) {
    if (!jr_verify(s)) return 0;
    if (s->complete) return 1;
    if (!s->intent_created) {
        if (!jr_before(s, ENVARA_JR_INTENT_CREATE)) return 0;
        int fd = openat(s->parent_fd, s->intent_name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return 0;
        s->intent_fd = fd; s->intent_created = 1;
        if (fstat(fd, &s->intent_identity) || !jr_secure(&s->intent_identity, 0, s->uid, s->gid) ||
            s->intent_identity.st_nlink != 1 || s->intent_identity.st_size != 0) return jr_refuse(ESTALE);
        if (!jr_checkpoint(ENVARA_JR_INTENT_CREATE, 1)) return 0;
    }
    while (s->intent_written < s->intent_length) {
        if (!jr_before(s, ENVARA_JR_INTENT_WRITE)) return 0;
        ssize_t n = pwrite(s->intent_fd, s->intent_bytes + s->intent_written,
            s->intent_length - s->intent_written, (off_t)s->intent_written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        s->intent_written += (size_t)n;
        if (fstat(s->intent_fd, &s->intent_identity)) return 0;
        if (!jr_checkpoint(ENVARA_JR_INTENT_WRITE, 1)) return 0;
    }
    if (!s->intent_file_synced) {
        if (!jr_before(s, ENVARA_JR_INTENT_FILE_FSYNC) || fsync(s->intent_fd)) return 0;
        s->intent_file_synced = 1;
        if (!jr_checkpoint(ENVARA_JR_INTENT_FILE_FSYNC, 1)) return 0;
    }
    if (!s->intent_durable) {
        if (!jr_before(s, ENVARA_JR_INTENT_PARENT_FSYNC) || fsync(s->parent_fd)) return 0;
        s->intent_durable = 1;
        if (!jr_checkpoint(ENVARA_JR_INTENT_PARENT_FSYNC, 1)) return 0;
    }
    for (size_t i = 0; i < s->count; i++) {
        struct envara_journal_retirement_file *f = &s->files[i];
        if (!f->unlinked) {
            if (!jr_before(s, ENVARA_JR_FILE_UNLINK) || unlinkat(s->directory_fd, f->name, 0)) return 0;
            f->unlinked = 1;
            if (!jr_checkpoint(ENVARA_JR_FILE_UNLINK, 1)) return 0;
            if (!jr_file_verify(s, i)) return 0;
        }
        if (!f->directory_synced) {
            if (!jr_before(s, ENVARA_JR_FILE_DIRECTORY_FSYNC) || fsync(s->directory_fd)) return 0;
            f->directory_synced = 1;
            if (!jr_checkpoint(ENVARA_JR_FILE_DIRECTORY_FSYNC, 1)) return 0;
        }
    }
    if (!s->directory_unlinked) {
        if (!jr_before(s, ENVARA_JR_DIRECTORY_UNLINK) || unlinkat(s->parent_fd, s->directory_name, AT_REMOVEDIR)) return 0;
        s->directory_unlinked = 1;
        if (!jr_checkpoint(ENVARA_JR_DIRECTORY_UNLINK, 1)) return 0;
    }
    if (!s->directory_parent_synced) {
        if (!jr_before(s, ENVARA_JR_DIRECTORY_PARENT_FSYNC) || fsync(s->parent_fd)) return 0;
        s->directory_parent_synced = 1;
        if (!jr_checkpoint(ENVARA_JR_DIRECTORY_PARENT_FSYNC, 1)) return 0;
    }
    if (!s->intent_unlinked) {
        if (!jr_before(s, ENVARA_JR_INTENT_UNLINK) || unlinkat(s->parent_fd, s->intent_name, 0)) return 0;
        s->intent_unlinked = 1;
        if (!jr_checkpoint(ENVARA_JR_INTENT_UNLINK, 1)) return 0;
    }
    if (!s->final_parent_synced) {
        if (!jr_before(s, ENVARA_JR_FINAL_PARENT_FSYNC) || fsync(s->parent_fd)) return 0;
        s->final_parent_synced = 1;
        if (!jr_checkpoint(ENVARA_JR_FINAL_PARENT_FSYNC, 1)) return 0;
    }
    if (!jr_verify(s)) return 0;
    s->complete = 1; return 1;
}
