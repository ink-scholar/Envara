#ifndef ENVARA_JOURNAL_RETIREMENT_H
#define ENVARA_JOURNAL_RETIREMENT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* This is filesystem retirement, never PF authority. Its caller supplies
 * already-owned held descriptors and an immutable record of its own writes.
 * A fresh invocation cannot adopt an existing retirement intent or journal.
 * The guard must prove PF EMPTY, complete scope absence, and owned custody.
 * It is called afresh immediately before every filesystem mutation. */
#define ENVARA_JOURNAL_RETIREMENT_MAX_FILES 32U
#define ENVARA_JOURNAL_RETIREMENT_MAX_BYTES 4096U
#define ENVARA_JOURNAL_RETIREMENT_NAME_BYTES 64U

struct envara_journal_retirement_entry {
    const char *name;
    int fd;                       /* Held readable FD; the module duplicates it. */
    struct stat identity;
    const void *bytes;             /* Frozen exact bytes, including a partial write. */
    size_t length;                 /* A known, owned zero-byte prefix is valid. */
};

typedef int (*envara_journal_retirement_guard)(void *opaque);

struct envara_journal_retirement_file {
    char name[ENVARA_JOURNAL_RETIREMENT_NAME_BYTES];
    int fd;
    struct stat identity, unlinked_identity;
    unsigned char bytes[ENVARA_JOURNAL_RETIREMENT_MAX_BYTES];
    size_t length;
    int unlinked, unlinked_identity_set, directory_synced;
};

struct envara_journal_retirement {
    pid_t owner;
    uid_t uid;
    gid_t gid;
    int initialized, parent_fd, directory_fd, intent_fd;
    struct stat parent_identity, directory_identity, directory_unlinked_identity;
    struct stat intent_identity, intent_unlinked_identity;
    char directory_name[ENVARA_JOURNAL_RETIREMENT_NAME_BYTES];
    char intent_name[ENVARA_JOURNAL_RETIREMENT_NAME_BYTES + 24U];
    char directory_path[4096];     /* Darwin held-FD path, never used for a mutation. */
    struct envara_journal_retirement_file files[ENVARA_JOURNAL_RETIREMENT_MAX_FILES];
    size_t count, intent_length, intent_written;
    unsigned char *intent_bytes;
    int intent_created, intent_file_synced, intent_durable;
    int directory_unlinked, directory_unlinked_identity_set, directory_parent_synced;
    int intent_unlinked, intent_unlinked_identity_set, final_parent_synced, complete;
    envara_journal_retirement_guard guard;
    void *opaque;
};

/* Both APIs return 1 on success, 0 with errno on refusal or an incomplete
 * operation. Call step again only on this SAME live state. A retry accepts an
 * absent name solely after this state recorded its successful authorized
 * unlink and its retained descriptor still names the same nlink-zero inode.
 * No ENOENT, identity replacement, extra entry, or missing pre-intent record
 * is accepted as cleanup proof. init and close perform no filesystem mutation. */
int envara_journal_retirement_init(struct envara_journal_retirement *state,
    int parent_fd, int directory_fd, const char *directory_name,
    const struct stat *directory_identity,
    const struct envara_journal_retirement_entry *entries, size_t count,
    uid_t uid, gid_t gid, envara_journal_retirement_guard guard, void *opaque);
int envara_journal_retirement_step(struct envara_journal_retirement *state);
/* Held descriptor/name/content verification only; no guard call, adoption,
 * directory creation, signals, PF access, or filesystem mutation. */
int envara_journal_retirement_verify(struct envara_journal_retirement *state);
void envara_journal_retirement_close(struct envara_journal_retirement *state);

#ifdef ENVARA_JOURNAL_RETIREMENT_INERT
enum envara_journal_retirement_test_event {
    ENVARA_JR_INTENT_CREATE = 1,
    ENVARA_JR_INTENT_WRITE,
    ENVARA_JR_INTENT_FILE_FSYNC,
    ENVARA_JR_INTENT_PARENT_FSYNC,
    ENVARA_JR_FILE_UNLINK,
    ENVARA_JR_FILE_DIRECTORY_FSYNC,
    ENVARA_JR_DIRECTORY_UNLINK,
    ENVARA_JR_DIRECTORY_PARENT_FSYNC,
    ENVARA_JR_INTENT_UNLINK,
    ENVARA_JR_FINAL_PARENT_FSYNC
};
/* A one-shot test-only EIO immediately before or after the selected actual
 * syscall, never an alternate production filesystem or privilege path. */
int envara_journal_retirement_test_fault(int event, unsigned occurrence, int after);
#endif

#endif
