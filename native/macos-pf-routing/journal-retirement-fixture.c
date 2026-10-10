#include "journal-retirement.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ENVARA_JOURNAL_RETIREMENT_INERT
#error This filesystem-only fixture must never be linked into production.
#endif

struct fixture {
    int root, parent, journal, files[3];
    char name[32];
    struct envara_journal_retirement state;
    struct envara_journal_retirement_entry entries[3];
    int pf_empty, scope_absent, owned_custody;
    unsigned guards;
};
static unsigned cases, faults, refusals, guard_calls;
static const char *names[] = { "000.intent", "000.receipt", "001.intent" };
static const char *contents[] = { "", "a", "{\"schema\":\"owned-test\",\"sequence\":1}" };

static int check(int condition, const char *label) {
    if (!condition) { fprintf(stderr, "fixture refused: %s (errno %d)\n", label, errno); return 0; }
    return 1;
}
static int guard(void *opaque) {
    struct fixture *f = opaque; f->guards++;
    if (f->pf_empty && f->scope_absent && f->owned_custody) return 1;
    errno = EACCES; return 0;
}
static int absent(int fd, const char *name) {
    struct stat s; return fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT;
}
static int put(int fd, const char *name, const char *bytes) {
    int out = openat(fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0) return -1;
    size_t n = strlen(bytes);
    if (write(out, bytes, n) != (ssize_t)n || fsync(out)) { int e = errno; close(out); errno = e; return -1; }
    return out;
}
static struct fixture *create_fixture(int root) {
    struct fixture *f = calloc(1, sizeof(*f)); if (!f) return NULL;
    f->root = root; f->parent = f->journal = -1;
    for (size_t i = 0; i < 3; i++) f->files[i] = -1;
    snprintf(f->name, sizeof(f->name), "case-%03u", cases++);
    if (mkdirat(root, f->name, 0700)) return NULL;
    f->parent = openat(root, f->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (f->parent < 0 || mkdirat(f->parent, "app-filter-events", 0700)) return NULL;
    f->journal = openat(f->parent, "app-filter-events", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (f->journal < 0) return NULL;
    for (size_t i = 0; i < 3; i++) {
        f->files[i] = put(f->journal, names[i], contents[i]);
        if (f->files[i] < 0 || fstat(f->files[i], &f->entries[i].identity)) return NULL;
        f->entries[i].name = names[i]; f->entries[i].fd = f->files[i];
        f->entries[i].bytes = contents[i]; f->entries[i].length = strlen(contents[i]);
    }
    if (fsync(f->journal) || fsync(f->parent)) return NULL;
    f->pf_empty = f->scope_absent = f->owned_custody = 1; return f;
}
static int initialize(struct fixture *f) {
    struct stat directory; if (fstat(f->journal, &directory)) return 0;
    return envara_journal_retirement_init(&f->state, f->parent, f->journal, "app-filter-events",
        &directory, f->entries, 3, getuid(), directory.st_gid, guard, f);
}
static void empty_owned_fixture_directory(int parent, const char *name) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return;
    for (size_t i = 0; i < 3; i++) unlinkat(fd, names[i], 0);
    unlinkat(fd, "foreign", 0); close(fd); unlinkat(parent, name, AT_REMOVEDIR);
}
static void destroy_fixture(struct fixture *f) {
    if (!f) return;
    guard_calls += f->guards; envara_journal_retirement_close(&f->state);
    for (size_t i = 0; i < 3; i++) if (f->files[i] >= 0) close(f->files[i]);
    if (f->journal >= 0) close(f->journal);
    if (f->parent >= 0) {
        empty_owned_fixture_directory(f->parent, "app-filter-events");
        empty_owned_fixture_directory(f->parent, "saved-journal");
        unlinkat(f->parent, "app-filter-events.retirement-intent", 0);
        unlinkat(f->parent, "other-link", 0); close(f->parent);
    }
    unlinkat(f->root, f->name, AT_REMOVEDIR); free(f);
}
static int completed(struct fixture *f) {
    struct stat held;
    return check(f->state.complete && f->state.intent_durable && f->state.directory_unlinked &&
        f->state.directory_parent_synced && f->state.intent_unlinked && f->state.final_parent_synced,
        "all durable completion bits") && check(absent(f->parent, "app-filter-events") &&
        absent(f->parent, "app-filter-events.retirement-intent"), "exact names absent") &&
        check(!fstat(f->journal, &held) && held.st_nlink <= 2, "held removed directory remains exact") &&
        check(envara_journal_retirement_step(&f->state) == 1, "same-state idempotent completion");
}
static void phase_error(const struct fixture *f) {
    fprintf(stderr, "phase: intent %d/%zu/%d/%d dir %d/%d end %d/%d files %d/%d %d/%d %d/%d\n",
        f->state.intent_created, f->state.intent_written, f->state.intent_file_synced, f->state.intent_durable,
        f->state.directory_unlinked, f->state.directory_parent_synced, f->state.intent_unlinked,
        f->state.final_parent_synced, f->state.files[0].unlinked, f->state.files[0].directory_synced,
        f->state.files[1].unlinked, f->state.files[1].directory_synced,
        f->state.files[2].unlinked, f->state.files[2].directory_synced);
}
static int fault_case(int root, int event, unsigned occurrence, int after) {
    struct fixture *f = create_fixture(root); if (!check(f != NULL, "fault setup")) return 0;
    int ok = check(initialize(f) == 1, "fault init") &&
        check(envara_journal_retirement_test_fault(event, occurrence, after) == 1, "fault arm") &&
        check(envara_journal_retirement_step(&f->state) == 0 && errno == EIO, "actual syscall fault") &&
        check(envara_journal_retirement_step(&f->state) == 1, "same-state retry") && completed(f);
    if (ok) faults++; destroy_fixture(f); return ok;
}
static int refusal_case(int root, unsigned mode) {
    struct fixture *f = create_fixture(root); if (!check(f != NULL, "refusal setup")) return 0;
    int ok = check(initialize(f) == 1, "refusal init"); if (!ok) { destroy_fixture(f); return 0; }
    if (mode == 0) ok = check(!unlinkat(f->journal, names[1], 0), "foreign missing");
    else if (mode == 1) { int fd = put(f->journal, "foreign", "foreign"); ok = check(fd >= 0, "foreign extra"); if (fd >= 0) close(fd); }
    else if (mode == 2) {
        ok = check(!unlinkat(f->journal, names[1], 0), "replacement unlink");
        int fd = put(f->journal, names[1], contents[1]); ok = ok && check(fd >= 0, "replacement create"); if (fd >= 0) close(fd);
    } else if (mode == 3) {
        ok = check(!renameat(f->parent, "app-filter-events", f->parent, "saved-journal") &&
            !mkdirat(f->parent, "app-filter-events", 0700), "directory replacement");
    } else if (mode == 4) {
        int fd = put(f->parent, "app-filter-events.retirement-intent", "foreign intent");
        ok = check(fd >= 0, "foreign intent setup"); if (fd >= 0) close(fd);
    } else if (mode == 5) ok = check(pwrite(f->files[1], "x", 1, 0) == 1, "same inode byte mutation");
    else if (mode == 6) ok = check(!linkat(f->journal, names[1], f->parent, "other-link", 0), "foreign hard link");
    else if (mode == 7) {
        ok = check(envara_journal_retirement_test_fault(ENVARA_JR_FILE_UNLINK, 1, 1) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && f->state.files[0].unlinked,
            "owned first unlink recorded") && check(!unlinkat(f->journal, names[1], 0), "foreign second absence");
    } else if (mode == 8) {
        ok = check(envara_journal_retirement_test_fault(ENVARA_JR_FILE_UNLINK, 1, 1) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && f->state.files[0].unlinked,
            "owned first unlink before replacement");
        int fd = put(f->journal, names[0], contents[0]); ok = ok && check(fd >= 0, "own-unlinked name replaced"); if (fd >= 0) close(fd);
    } else if (mode == 9) {
        ok = check(envara_journal_retirement_test_fault(ENVARA_JR_INTENT_PARENT_FSYNC, 1, 1) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && f->state.intent_durable,
            "own durable intent before foreign removal") &&
            check(!unlinkat(f->parent, f->state.intent_name, 0), "foreign intent removal");
    } else if (mode == 10) {
        ok = check(envara_journal_retirement_test_fault(ENVARA_JR_DIRECTORY_UNLINK, 1, 0) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && !f->state.directory_unlinked,
            "all files removed before directory intent") &&
            check(!unlinkat(f->parent, "app-filter-events", AT_REMOVEDIR), "foreign directory removal");
    } else if (mode == 11) ok = check(!fchmod(f->parent, 0755), "changed parent mode");
    if (ok) ok = check(envara_journal_retirement_step(&f->state) == 0, "foreign evidence refused") &&
        check(!f->state.complete, "foreign evidence never completion");
    if (mode == 11) fchmod(f->parent, 0700);
    if (ok) refusals++; destroy_fixture(f); return ok;
}
static int guard_case(int root) {
    struct fixture *f = create_fixture(root); if (!check(f != NULL, "guard setup")) return 0;
    int ok = check(initialize(f) == 1, "guard init") &&
        check(envara_journal_retirement_test_fault(ENVARA_JR_FILE_UNLINK, 1, 1) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && f->state.files[0].unlinked,
            "guard owns prior unlink");
    for (unsigned gate = 0; gate < 3 && ok; gate++) {
        f->pf_empty = gate != 0; f->scope_absent = gate != 1; f->owned_custody = gate != 2;
        ok = check(envara_journal_retirement_step(&f->state) == 0 && errno == EACCES,
            "fresh fixed guard refused mutation") && check(!f->state.files[1].unlinked &&
            !f->state.directory_unlinked, "no later mutation across failed guard");
    }
    f->pf_empty = f->scope_absent = f->owned_custody = 1;
    ok = ok && check(envara_journal_retirement_step(&f->state) == 1, "guard reproof permits own retry") && completed(f);
    destroy_fixture(f); return ok;
}
static int no_adoption_case(int root) {
    struct fixture *f = create_fixture(root); if (!check(f != NULL, "no adoption setup")) return 0;
    int ok = check(initialize(f) == 1, "first state init") &&
        check(envara_journal_retirement_test_fault(ENVARA_JR_INTENT_PARENT_FSYNC, 1, 1) == 1 &&
            envara_journal_retirement_step(&f->state) == 0 && f->state.intent_durable, "persisted own roster");
    envara_journal_retirement_close(&f->state);
    ok = ok && check(initialize(f) == 0 && errno == EEXIST, "new object refuses previous intent");
    destroy_fixture(f); return ok;
}
int main(int argc, char **argv) {
    if (argc != 2 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 2;
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat st;
    if (root < 3 || fstat(root, &st) || !S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & 07777) != 0700) return 2;
    struct fixture *normal = create_fixture(root);
    if (!check(normal != NULL, "normal setup") || !check(initialize(normal) == 1, "normal init")) return 1;
    if (!check(envara_journal_retirement_verify(&normal->state) == 1 && !normal->guards &&
        absent(normal->parent, "app-filter-events.retirement-intent"), "readonly held verification")) return 1;
    if (!check(envara_journal_retirement_step(&normal->state) == 1, "normal completion")) { phase_error(normal); return 1; }
    if (!completed(normal)) return 1;
    destroy_fixture(normal);
    for (int event = ENVARA_JR_INTENT_CREATE; event <= ENVARA_JR_FINAL_PARENT_FSYNC; event++)
        for (int after = 0; after <= 1; after++) if (!fault_case(root, event, 1, after)) return 1;
    for (int event = ENVARA_JR_FILE_UNLINK; event <= ENVARA_JR_FILE_DIRECTORY_FSYNC; event++)
        for (unsigned occurrence = 2; occurrence <= 3; occurrence++)
            for (int after = 0; after <= 1; after++) if (!fault_case(root, event, occurrence, after)) return 1;
    for (unsigned mode = 0; mode < 12; mode++) if (!refusal_case(root, mode)) return 1;
    if (!guard_case(root) || !no_adoption_case(root)) return 1;
    close(root);
    printf("{\"ok\":true,\"actualFilesystemCases\":%u,\"injectedFaultCases\":%u,\"foreignRefusals\":%u,"
        "\"freshGuardCalls\":%u,\"ownedZeroBytePrefix\":true,\"partialUnlinkRetry\":true,"
        "\"directoryAndIntentFsyncRetry\":true,\"missingBeforeIntentRefused\":true,"
        "\"replacementsAndUnknownEntriesRefused\":true,\"newInvocationCannotAdopt\":true,"
        "\"root\":false,\"pf\":false,\"ready\":false,\"protected\":false}\n",
        cases, faults, refusals, guard_calls);
    return 0;
}
