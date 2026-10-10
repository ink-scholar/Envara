/* Standalone INERT fixtures. Build only with the inert library variant.
 * No PF device/ioctl, authorization, privileged helper, process launch, or
 * production ledger path is used. All writes and cleanup stay inside a
 * nonroot caller's own mkdtemp tree; source checks do not prove PF readiness.
 */
#ifndef ENVARA_PF_RUN_LEDGER_INERT
#error "Build this fixture only with ENVARA_PF_RUN_LEDGER_INERT"
#endif
#include "pf-run-ledger.h"
#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIXTURE_LIMIT 128
#define SNAPSHOT_LIMIT (1024U * 1024U)
#define LEASE_SCHEMA "envara.macos-pf-owned-root-hook-lease/v2"
static const char Run[] = "01234567-89ab-4cde-8fab-0123456789ab";
static const char OtherRun[] = "89abcdef-0123-4567-9abc-def012345678";
static const char LeaseID[] = "fedcba98-7654-4321-abcd-0123456789ab";
static unsigned checks;

typedef struct {
    char top[PATH_MAX], root[PATH_MAX];
    dev_t device;
    ino_t inode;
    int active;
} Fixture;
static Fixture fixtures[FIXTURE_LIMIT];
static size_t fixture_count;

static void cleanup_all(void);
static void failed(const char *expression, const char *file, int line) {
    fprintf(stderr, "ledger inert fixture failed at %s:%d: %s (errno=%d)\n",
            file, line, expression, errno);
    exit(1);
}
#define CHECK(expression) do { checks++; if (!(expression)) failed(#expression, __FILE__, __LINE__); } while (0)
#define REFUSED(expression) do { errno = 0; CHECK((expression) == 0); CHECK(errno != 0); } while (0)

static void joined(char output[PATH_MAX], const char *parent, const char *name) {
    int length = snprintf(output, PATH_MAX, "%s/%s", parent, name);
    CHECK(length > 0 && length < PATH_MAX);
}
static void owned_file(const char *path, const void *data, size_t length, int replace) {
    int descriptor = open(path, O_WRONLY | O_NOFOLLOW | (replace ? O_TRUNC : O_CREAT | O_EXCL), 0600);
    CHECK(descriptor >= 0);
    size_t done = 0;
    while (done < length) {
        ssize_t result = write(descriptor, (const unsigned char *)data + done, length - done);
        CHECK(result > 0); done += (size_t)result;
    }
    CHECK(close(descriptor) == 0);
}

/* Cleanup follows only directory descriptors rooted in the exact owned
 * mkdtemp inode. It unlinks fixture symlinks instead of traversing them. */
static int remove_children(int descriptor, dev_t device) {
    int copy = dup(descriptor);
    if (copy < 0) return 0;
    DIR *directory = fdopendir(copy);
    if (!directory) { close(copy); return 0; }
    int okay = 1;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat info;
        if (fstatat(descriptor, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0 ||
            info.st_uid != getuid() || info.st_dev != device) { okay = 0; break; }
        if (S_ISDIR(info.st_mode)) {
            int child = openat(descriptor, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (child < 0 || !remove_children(child, device)) { if (child >= 0) close(child); okay = 0; break; }
            struct stat after;
            int stable = fstat(child, &after) == 0 && after.st_dev == info.st_dev && after.st_ino == info.st_ino;
            close(child);
            if (!stable || unlinkat(descriptor, entry->d_name, AT_REMOVEDIR) != 0) { okay = 0; break; }
        } else if (unlinkat(descriptor, entry->d_name, 0) != 0) { okay = 0; break; }
    }
    if (closedir(directory) != 0) okay = 0;
    return okay;
}
static int destroy_fixture(Fixture *fixture) {
    if (!fixture->active) return 1;
    struct stat path_info, held;
    if (lstat(fixture->top, &path_info) != 0 || !S_ISDIR(path_info.st_mode) ||
        path_info.st_uid != getuid() || path_info.st_dev != fixture->device || path_info.st_ino != fixture->inode) return 0;
    int descriptor = open(fixture->top, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) return 0;
    int okay = fstat(descriptor, &held) == 0 && held.st_dev == fixture->device && held.st_ino == fixture->inode &&
        remove_children(descriptor, fixture->device);
    close(descriptor);
    if (okay) okay = rmdir(fixture->top) == 0;
    if (okay) fixture->active = 0;
    return okay;
}
static void cleanup_all(void) {
    for (size_t i = fixture_count; i > 0; i--)
        if (!destroy_fixture(&fixtures[i - 1])) fprintf(stderr, "owned ledger fixture cleanup refused\n");
}
static Fixture *fixture(void) {
    CHECK(fixture_count < FIXTURE_LIMIT);
    Fixture *result = &fixtures[fixture_count++];
    int length = snprintf(result->top, sizeof(result->top), "/private/tmp/envara-pf-run-ledger-inert-XXXXXX");
    CHECK(length > 0 && (size_t)length < sizeof(result->top));
    CHECK(mkdtemp(result->top) != NULL);
    CHECK(chmod(result->top, 0700) == 0);
    struct stat info;
    CHECK(lstat(result->top, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == getuid());
    result->device = info.st_dev; result->inode = info.st_ino; result->active = 1;
    joined(result->root, result->top, "ledger");
    CHECK(mkdir(result->root, 0700) == 0 && chmod(result->root, 0700) == 0);
    CHECK(envara_pf_run_ledger_test_root(result->root) == 1);
    return result;
}

typedef struct { unsigned char *bytes; size_t length; } Snapshot;
static void snapshot_append(Snapshot *snapshot, const void *bytes, size_t length) {
    CHECK(length <= SNAPSHOT_LIMIT - snapshot->length);
    memcpy(snapshot->bytes + snapshot->length, bytes, length); snapshot->length += length;
}
static int name_order(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }
static void snapshot_visit(Snapshot *snapshot, const char *path, const char *relative, unsigned depth) {
    CHECK(depth < 8);
    struct stat info; CHECK(lstat(path, &info) == 0);
    size_t name_length = strlen(relative);
    snapshot_append(snapshot, &name_length, sizeof(name_length)); snapshot_append(snapshot, relative, name_length);
    /* Exclude access time, which a read-only content check may update. */
    snapshot_append(snapshot, &info.st_dev, sizeof(info.st_dev));
    snapshot_append(snapshot, &info.st_ino, sizeof(info.st_ino));
    snapshot_append(snapshot, &info.st_mode, sizeof(info.st_mode));
    snapshot_append(snapshot, &info.st_uid, sizeof(info.st_uid));
    snapshot_append(snapshot, &info.st_gid, sizeof(info.st_gid));
    snapshot_append(snapshot, &info.st_nlink, sizeof(info.st_nlink));
    snapshot_append(snapshot, &info.st_size, sizeof(info.st_size));
    snapshot_append(snapshot, &info.st_mtimespec, sizeof(info.st_mtimespec));
    snapshot_append(snapshot, &info.st_ctimespec, sizeof(info.st_ctimespec));
    if (S_ISREG(info.st_mode)) {
        CHECK(info.st_size >= 0 && (uint64_t)info.st_size <= SNAPSHOT_LIMIT / 2);
        int descriptor = open(path, O_RDONLY | O_NOFOLLOW); CHECK(descriptor >= 0);
        unsigned char buffer[4096]; ssize_t count;
        while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) snapshot_append(snapshot, buffer, (size_t)count);
        CHECK(count == 0 && close(descriptor) == 0);
    } else if (S_ISLNK(info.st_mode)) {
        char target[PATH_MAX]; ssize_t count = readlink(path, target, sizeof(target));
        CHECK(count >= 0 && (size_t)count < sizeof(target)); snapshot_append(snapshot, target, (size_t)count);
    } else if (S_ISDIR(info.st_mode)) {
        DIR *directory = opendir(path); CHECK(directory != NULL);
        char names[256][NAME_MAX + 1]; size_t count = 0; struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            CHECK(count < 256 && strlen(entry->d_name) <= NAME_MAX);
            strcpy(names[count++], entry->d_name);
        }
        CHECK(closedir(directory) == 0); qsort(names, count, sizeof(names[0]), name_order);
        for (size_t i = 0; i < count; i++) {
            char child[PATH_MAX], child_relative[PATH_MAX];
            joined(child, path, names[i]); joined(child_relative, relative, names[i]);
            snapshot_visit(snapshot, child, child_relative, depth + 1);
        }
    }
}
static Snapshot snapshot(Fixture *fixture) {
    Snapshot result = { .bytes = malloc(SNAPSHOT_LIMIT), .length = 0 }; CHECK(result.bytes != NULL);
    snapshot_visit(&result, fixture->top, "", 0); return result;
}
static void unchanged(Fixture *fixture, Snapshot *before) {
    Snapshot after = snapshot(fixture);
    CHECK(before->length == after.length && memcmp(before->bytes, after.bytes, after.length) == 0);
    free(before->bytes); free(after.bytes); before->bytes = NULL;
}
static void observed(Fixture *fixture, const char *run, EnvaraPFRunLedgerState expected) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedgerState state = ENVARA_PF_RUN_UNKNOWN;
    CHECK(envara_pf_run_ledger_inspect(run, &state) == 1 && state == expected); unchanged(fixture, &before);
}
static void unknown(Fixture *fixture, const char *run) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedgerState state = ENVARA_PF_RUN_UNUSED;
    REFUSED(envara_pf_run_ledger_inspect(run, &state)); CHECK(state == ENVARA_PF_RUN_UNKNOWN);
    unchanged(fixture, &before);
}
static void allocation_refused(Fixture *fixture, const char *run) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedger *ledger = NULL;
    REFUSED(envara_pf_run_ledger_allocate(run, &ledger)); CHECK(ledger == NULL); unchanged(fixture, &before);
}
static void open_refused(Fixture *fixture, const char *run, const char *lease, size_t length) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedger *ledger = NULL;
    REFUSED(envara_pf_run_ledger_open_issued(run, lease, length, &ledger)); CHECK(ledger == NULL);
    unchanged(fixture, &before);
}
static void receipt(Fixture *fixture, const char *lease, EnvaraPFRunLedgerState expected) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedgerState state = ENVARA_PF_RUN_UNKNOWN;
    CHECK(envara_pf_run_ledger_inspect_lease(Run, lease, strlen(lease), &state) == 1 && state == expected);
    unchanged(fixture, &before);
}
static void receipt_refused(Fixture *fixture, const char *lease, size_t length) {
    Snapshot before = snapshot(fixture); EnvaraPFRunLedgerState state = ENVARA_PF_RUN_UNUSED;
    REFUSED(envara_pf_run_ledger_inspect_lease(Run, lease, length, &state));
    CHECK(state == ENVARA_PF_RUN_UNKNOWN); unchanged(fixture, &before);
}
static EnvaraPFRunLedger *allocated(const char *run) {
    EnvaraPFRunLedger *ledger = NULL;
    CHECK(envara_pf_run_ledger_allocate(run, &ledger) == 1 && ledger != NULL); return ledger;
}

static void canonical_lease(char output[ENVARA_PF_RUN_LEASE_LIMIT + 1], const char *run, const char *ticket) {
    char anchor[64], input[74], label[64], digest_text[65]; unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CHECK(envara_pf_run_anchor(run, anchor) == 1);
    int length = snprintf(input, sizeof(input), "%s|%s", run, LeaseID);
    CHECK(length == 73);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CHECK(CC_SHA256(input, (CC_LONG)length, digest) != NULL);
#pragma clang diagnostic pop
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(digest_text + i * 2, 3, "%02x", digest[i]);
    CHECK(snprintf(label, sizeof(label), "envara.hook.v2.%.32s", digest_text) == 47);
    length = snprintf(output, ENVARA_PF_RUN_LEASE_LIMIT + 1,
        "{\"schema\":\"%s\",\"runId\":\"%s\",\"leaseId\":\"%s\",\"anchor\":\"%s\",\"owner\":\"%s\",\"label\":\"%s\",\"ticket\":\"%s\","
        "\"rootBeforeSHA256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"rootBeforeTextSHA256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}",
        LEASE_SCHEMA, run, LeaseID, anchor, anchor, label, ticket);
    CHECK(length > 0 && length <= ENVARA_PF_RUN_LEASE_LIMIT);
}
static void replaced(char output[ENVARA_PF_RUN_LEASE_LIMIT + 2], const char *input, const char *needle, const char *replacement) {
    const char *found = strstr(input, needle); CHECK(found != NULL);
    size_t prefix = (size_t)(found - input), suffix = strlen(found + strlen(needle)), replacement_length = strlen(replacement);
    CHECK(prefix + replacement_length + suffix < ENVARA_PF_RUN_LEASE_LIMIT + 2);
    memcpy(output, input, prefix); memcpy(output + prefix, replacement, replacement_length);
    memcpy(output + prefix + replacement_length, found + strlen(needle), suffix + 1);
}
static void bad_issue(Fixture *fixture, EnvaraPFRunLedger *ledger, const char *lease, size_t length) {
    Snapshot before = snapshot(fixture);
    REFUSED(envara_pf_run_ledger_issue(ledger, lease, length)); unchanged(fixture, &before);
}
static void run_file(char output[PATH_MAX], Fixture *fixture, const char *name) {
    char directory[PATH_MAX]; joined(directory, fixture->root, Run); joined(output, directory, name);
}

static void test_uuid(void) {
    CHECK(ENVARA_PF_RUN_LEDGER_MAX_RUNS == 64);
    CHECK(ENVARA_PF_RUN_UUID_BYTES == 37 && ENVARA_PF_RUN_ANCHOR_BYTES == 54);
    const char *valid[] = { Run, OtherRun, LeaseID, "00000000-0000-4000-b000-000000000000" };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        char anchor[64], expected[64]; CHECK(envara_pf_run_uuid_valid(valid[i]) == 1);
        CHECK(envara_pf_run_anchor(valid[i], anchor) == 1 && strlen(anchor) == 53);
        CHECK(snprintf(expected, sizeof(expected), "io.envara.pf.run.%s", valid[i]) == 53);
        CHECK(!strcmp(anchor, expected));
    }
    const char *invalid[] = { "", "01234567-89AB-4cde-8fab-0123456789ab", "01234567-89ab-3cde-8fab-0123456789ab",
        "01234567-89ab-5cde-8fab-0123456789ab", "01234567-89ab-4cde-7fab-0123456789ab",
        "01234567-89ab-4cde-cfab-0123456789ab", "0123456789ab4cde8fab0123456789ab",
        "01234567-89ab-4cde-8fab-0123456789ab/", "01234567-89ab-4cde-8fab-0123456789ab\n",
        "../01234567-89ab-4cde-8fab-0123456789ab" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        char anchor[64]; CHECK(envara_pf_run_uuid_valid(invalid[i]) == 0); CHECK(envara_pf_run_anchor(invalid[i], anchor) == 0);
    }
    CHECK(envara_pf_run_uuid_valid(NULL) == 0);
    CHECK(envara_pf_run_ledger_state_name(ENVARA_PF_RUN_UNUSED) != NULL);
    CHECK(envara_pf_run_ledger_state_name(ENVARA_PF_RUN_UNKNOWN) != NULL);
    CHECK(strcmp(envara_pf_run_ledger_state_name(ENVARA_PF_RUN_UNUSED),
                 envara_pf_run_ledger_state_name(ENVARA_PF_RUN_UNKNOWN)) != 0);
}
static void test_readonly_and_consumption(void) {
    Fixture *root = fixture(); char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "1");
    observed(root, Run, ENVARA_PF_RUN_UNUSED);
    open_refused(root, Run, lease, strlen(lease)); receipt_refused(root, lease, strlen(lease));
    EnvaraPFRunLedger *ledger = allocated(Run);
    /* A second independently opened lock must refuse without a child process. */
    allocation_refused(root, OtherRun);
    bad_issue(root, ledger, "{}", 2);
    envara_pf_run_ledger_close(ledger);
    CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
    observed(root, Run, ENVARA_PF_RUN_ALLOCATION_ONLY);
    allocation_refused(root, Run); open_refused(root, Run, lease, strlen(lease)); receipt_refused(root, lease, strlen(lease));
    CHECK(destroy_fixture(root));
}
static void test_strict_lease(void) {
    Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
    char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1], bad[ENVARA_PF_RUN_LEASE_LIMIT + 2];
    canonical_lease(lease, Run, "18446744073709551615");
    const char *needles[] = { LEASE_SCHEMA, Run, LeaseID, "\"owner\":\"io.envara.pf.run.", "envara.hook.v2.",
        "\"ticket\":\"18446744073709551615\"", "\"ticket\":\"18446744073709551615\"", "\"ticket\":\"18446744073709551615\"",
        "\"ticket\":\"18446744073709551615\"", "\"ticket\":\"18446744073709551615\"", "\"ticket\":\"18446744073709551615\"",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "\"schema\":", "}" };
    const char *replacements[] = { "envara.macos-pf-owned-root-hook-lease/v1", OtherRun, "fedcba98-7654-3321-abcd-0123456789ab",
        "\"owner\":\"io.envara.pf.other.", "envara.hook.v1.", "\"ticket\":\"0\"", "\"ticket\":\"01\"",
        "\"ticket\":\"18446744073709551616\"", "\"ticket\":1", "\"ticket\":\"+1\"", "\"ticket\":\"1.0\"",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "bbbb", "\"schema\" :", ",\"extra\":\"fixture\"}" };
    CHECK(sizeof(needles) / sizeof(needles[0]) == sizeof(replacements) / sizeof(replacements[0]));
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
        replaced(bad, lease, needles[i], replacements[i]); bad_issue(root, ledger, bad, strlen(bad));
    }
    replaced(bad, lease, "\"anchor\":\"io.envara.pf.run.", "\"anchor\":\"io.envara.pf.wrong."); bad_issue(root, ledger, bad, strlen(bad));
    replaced(bad, lease, ",\"ticket\":\"18446744073709551615\"", ""); bad_issue(root, ledger, bad, strlen(bad));
    replaced(bad, lease, LeaseID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"); bad_issue(root, ledger, bad, strlen(bad));
    strcpy(bad, lease); char *label = strstr(bad, "envara.hook.v2."); CHECK(label != NULL);
    label[15] = label[15] == '0' ? '1' : '0'; bad_issue(root, ledger, bad, strlen(bad));
    replaced(bad, lease, "\"schema\":", "\"schema\":\"duplicate\",\"schema\":"); bad_issue(root, ledger, bad, strlen(bad));
    replaced(bad, lease, "{", "{ "); bad_issue(root, ledger, bad, strlen(bad));
    replaced(bad, lease, "\"schema\":\"" LEASE_SCHEMA "\",\"runId\":\"01234567-89ab-4cde-8fab-0123456789ab\"",
        "\"runId\":\"01234567-89ab-4cde-8fab-0123456789ab\",\"schema\":\"" LEASE_SCHEMA "\"");
    bad_issue(root, ledger, bad, strlen(bad));
    size_t length = strlen(lease); memcpy(bad, lease, length); bad[length] = '\n'; bad[length + 1] = 0;
    bad_issue(root, ledger, bad, length + 1);
    bad_issue(root, ledger, lease, length + 1); /* Explicit trailing NUL. */
    memcpy(bad, lease, length + 1); bad[length / 2] = 0; bad_issue(root, ledger, bad, length);
    memset(bad, 'x', sizeof(bad)); bad_issue(root, ledger, bad, sizeof(bad));
    CHECK(envara_pf_run_ledger_issue(ledger, lease, length) == 1);
    bad_issue(root, ledger, lease, length); /* One durable issue only. */
    envara_pf_run_ledger_close(ledger); observed(root, Run, ENVARA_PF_RUN_ISSUED); receipt(root, lease, ENVARA_PF_RUN_ISSUED);
    replaced(bad, lease, "18446744073709551615", "1"); open_refused(root, Run, bad, strlen(bad)); receipt_refused(root, bad, strlen(bad));
    char other_lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(other_lease, OtherRun, "1");
    open_refused(root, Run, other_lease, strlen(other_lease));
    replaced(bad, lease, LEASE_SCHEMA, "envara.macos-pf-owned-root-hook-lease/v1");
    open_refused(root, Run, bad, strlen(bad)); receipt_refused(root, bad, strlen(bad));
    CHECK(destroy_fixture(root));
}
static void test_delete_and_retirement(void) {
    for (int disposition = ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT;
         disposition <= ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN; disposition++) {
        Fixture *root = fixture(); char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "42");
        EnvaraPFRunLedger *ledger = allocated(Run); CHECK(envara_pf_run_ledger_issue(ledger, lease, strlen(lease)) == 1);
        envara_pf_run_ledger_close(ledger); ledger = NULL;
        Snapshot before = snapshot(root);
        CHECK(envara_pf_run_ledger_open_issued(Run, lease, strlen(lease), &ledger) == 1 && ledger != NULL); unchanged(root, &before);
        before = snapshot(root); REFUSED(envara_pf_run_ledger_retire(ledger, (EnvaraPFRunLedgerRetirement)disposition)); unchanged(root, &before);
        CHECK(envara_pf_run_ledger_begin_delete(ledger) == 1);
        before = snapshot(root); REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
        envara_pf_run_ledger_close(ledger);
        CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
        observed(root, Run, ENVARA_PF_RUN_DELETE_INTENT); receipt(root, lease, ENVARA_PF_RUN_DELETE_INTENT);
        allocation_refused(root, Run); open_refused(root, Run, lease, strlen(lease));
        /* A lost-reply/reopen case cannot obtain another DELETE handle. */
        CHECK(destroy_fixture(root));

        root = fixture(); ledger = allocated(Run); CHECK(envara_pf_run_ledger_issue(ledger, lease, strlen(lease)) == 1);
        envara_pf_run_ledger_close(ledger); ledger = NULL;
        CHECK(envara_pf_run_ledger_open_issued(Run, lease, strlen(lease), &ledger) == 1);
        CHECK(envara_pf_run_ledger_begin_delete(ledger) == 1);
        CHECK(envara_pf_run_ledger_retire(ledger, (EnvaraPFRunLedgerRetirement)disposition) == 1);
        before = snapshot(root); REFUSED(envara_pf_run_ledger_retire(ledger, (EnvaraPFRunLedgerRetirement)disposition)); unchanged(root, &before);
        bad_issue(root, ledger, lease, strlen(lease));
        before = snapshot(root); REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
        envara_pf_run_ledger_close(ledger); CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
        observed(root, Run, ENVARA_PF_RUN_RETIRED); receipt(root, lease, ENVARA_PF_RUN_RETIRED);
        allocation_refused(root, Run); open_refused(root, Run, lease, strlen(lease));
        char stale[ENVARA_PF_RUN_LEASE_LIMIT + 2]; replaced(stale, lease, "\"ticket\":\"42\"", "\"ticket\":\"43\"");
        receipt_refused(root, stale, strlen(stale)); CHECK(destroy_fixture(root));
    }
}
static void test_insert_rollback_retirement(void) {
    for (int issued = 0; issued < 2; issued++) {
        for (int disposition = ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT;
             disposition <= ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN; disposition++) {
            Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
            char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "7");
            if (issued) CHECK(envara_pf_run_ledger_issue(ledger, lease, strlen(lease)) == 1);
            Snapshot before = snapshot(root);
            REFUSED(envara_pf_run_ledger_retire(ledger, ENVARA_PF_RUN_RETIRE_NONE)); unchanged(root, &before);
            before = snapshot(root);
            REFUSED(envara_pf_run_ledger_retire(ledger, (EnvaraPFRunLedgerRetirement)disposition)); unchanged(root, &before);
            CHECK(envara_pf_run_ledger_begin_delete(ledger) == 1);
            before = snapshot(root); REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
            /* Independent readers cannot establish a state while this EX
             * handle is held; refusal must report UNKNOWN without writes. */
            unknown(root, Run); receipt_refused(root, lease, strlen(lease));
            CHECK(envara_pf_run_ledger_retire(ledger, (EnvaraPFRunLedgerRetirement)disposition) == 1);
            envara_pf_run_ledger_close(ledger);
            observed(root, Run, ENVARA_PF_RUN_RETIRED); allocation_refused(root, Run); open_refused(root, Run, lease, strlen(lease));
            if (issued) receipt(root, lease, ENVARA_PF_RUN_RETIRED); else receipt_refused(root, lease, strlen(lease));
            CHECK(destroy_fixture(root));
        }
    }
}
static void test_allocation_delete_intent_readonly(void) {
    Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
    char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "7");
    CHECK(envara_pf_run_ledger_begin_delete(ledger) == 1);
    envara_pf_run_ledger_close(ledger);
    CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
    observed(root, Run, ENVARA_PF_RUN_DELETE_INTENT);
    receipt_refused(root, lease, strlen(lease));
    open_refused(root, Run, lease, strlen(lease)); allocation_refused(root, Run);
    /* No issued receipt exists, and a lost rollback reply grants no handle. */
    CHECK(destroy_fixture(root));
}
static void test_uncertain_issue(void) {
    REFUSED(envara_pf_run_ledger_test_fail_issue(-1));
    REFUSED(envara_pf_run_ledger_test_fail_issue(3));
    CHECK(envara_pf_run_ledger_test_fail_issue(0) == 1);
    for (int mode = 1; mode <= 2; mode++) {
        Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
        char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "17");
        CHECK(envara_pf_run_ledger_test_fail_issue(mode) == 1);
        /* This refusal intentionally leaves partial or complete issued bytes;
         * it is not an unchanged-tree parser refusal. No PF DELETE occurred. */
        REFUSED(envara_pf_run_ledger_issue(ledger, lease, strlen(lease)));
        CHECK(envara_pf_run_ledger_test_fail_issue(0) == 1);
        Snapshot before = snapshot(root);
        REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
        before = snapshot(root);
        REFUSED(envara_pf_run_ledger_retire(ledger, ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN)); unchanged(root, &before);
        bad_issue(root, ledger, lease, strlen(lease));
        envara_pf_run_ledger_close(ledger); CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
        if (mode == 1) {
            unknown(root, Run); receipt_refused(root, lease, strlen(lease));
            open_refused(root, Run, lease, strlen(lease)); allocation_refused(root, OtherRun);
        } else {
            observed(root, Run, ENVARA_PF_RUN_ISSUED); receipt(root, lease, ENVARA_PF_RUN_ISSUED);
            allocation_refused(root, Run); ledger = NULL; before = snapshot(root);
            CHECK(envara_pf_run_ledger_open_issued(Run, lease, strlen(lease), &ledger) == 1 && ledger != NULL);
            unchanged(root, &before);
            before = snapshot(root);
            REFUSED(envara_pf_run_ledger_retire(ledger, ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN)); unchanged(root, &before);
            CHECK(envara_pf_run_ledger_begin_delete(ledger) == 1);
            before = snapshot(root); REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
            envara_pf_run_ledger_close(ledger);
            observed(root, Run, ENVARA_PF_RUN_DELETE_INTENT); receipt(root, lease, ENVARA_PF_RUN_DELETE_INTENT);
            open_refused(root, Run, lease, strlen(lease)); allocation_refused(root, Run);
        }
        CHECK(destroy_fixture(root));
    }
}
static void test_unknown_inventory(void) {
    for (int kind = 0; kind < 8; kind++) {
        Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run); envara_pf_run_ledger_close(ledger);
        char path[PATH_MAX], other[PATH_MAX], directory[PATH_MAX]; run_file(path, root, "allocation.json");
        joined(directory, root->root, Run); joined(other, root->top, "owned-extra");
        if (kind == 0) { joined(path, root->root, "unknown-entry"); owned_file(path, "fixture", 7, 0); }
        if (kind == 1) { run_file(path, root, "unknown-entry"); owned_file(path, "fixture", 7, 0); }
        if (kind == 2) CHECK(chmod(root->root, 0755) == 0);
        if (kind == 3) CHECK(chmod(directory, 0755) == 0);
        if (kind == 4) CHECK(chmod(path, 0644) == 0);
        if (kind == 5) CHECK(link(path, other) == 0);
        if (kind == 6) owned_file(path, "{}", 2, 1);
        if (kind == 7) { CHECK(rename(root->root, other) == 0); CHECK(symlink(other, root->root) == 0); }
        unknown(root, Run); allocation_refused(root, OtherRun);
        CHECK(destroy_fixture(root));
    }
    Fixture *root = fixture(); char run_directory[PATH_MAX]; joined(run_directory, root->root, Run);
    CHECK(mkdir(run_directory, 0700) == 0); unknown(root, Run); allocation_refused(root, Run); CHECK(destroy_fixture(root));
}
static void test_held_identity_replacement(void) {
    Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
    char run_directory[PATH_MAX], moved[PATH_MAX], lease[ENVARA_PF_RUN_LEASE_LIMIT + 1];
    joined(run_directory, root->root, Run); joined(moved, root->top, "owned-moved-run");
    CHECK(rename(run_directory, moved) == 0 && mkdir(run_directory, 0700) == 0);
    canonical_lease(lease, Run, "19");
    bad_issue(root, ledger, lease, strlen(lease));
    Snapshot before = snapshot(root); REFUSED(envara_pf_run_ledger_begin_delete(ledger)); unchanged(root, &before);
    before = snapshot(root);
    REFUSED(envara_pf_run_ledger_retire(ledger, ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN)); unchanged(root, &before);
    envara_pf_run_ledger_close(ledger); unknown(root, Run); CHECK(destroy_fixture(root));
}
static void test_issued_tampering(void) {
    for (int kind = 0; kind < 7; kind++) {
        Fixture *root = fixture(); EnvaraPFRunLedger *ledger = allocated(Run);
        char lease[ENVARA_PF_RUN_LEASE_LIMIT + 1]; canonical_lease(lease, Run, "9");
        CHECK(envara_pf_run_ledger_issue(ledger, lease, strlen(lease)) == 1); envara_pf_run_ledger_close(ledger);
        char path[PATH_MAX], other[PATH_MAX]; run_file(path, root, "issued.json"); joined(other, root->top, "owned-other");
        if (kind == 0) owned_file(path, "{", 1, 1);
        if (kind == 1) CHECK(chmod(path, 0644) == 0);
        if (kind == 2) CHECK(link(path, other) == 0);
        if (kind == 3) { CHECK(unlink(path) == 0); owned_file(other, lease, strlen(lease), 0); CHECK(symlink(other, path) == 0); }
        if (kind == 4) { CHECK(unlink(path) == 0); CHECK(mkdir(path, 0700) == 0); }
        if (kind == 5) { CHECK(unlink(path) == 0); CHECK(mkfifo(path, 0600) == 0); }
        if (kind == 6) { char oversized[ENVARA_PF_RUN_LEASE_LIMIT + 1]; memset(oversized, 'x', sizeof(oversized)); owned_file(path, oversized, sizeof(oversized), 1); }
        unknown(root, Run); receipt_refused(root, lease, strlen(lease)); open_refused(root, Run, lease, strlen(lease));
        allocation_refused(root, OtherRun); CHECK(destroy_fixture(root));
    }
}
static void test_root_selection_refusals(void) {
    Fixture *root = fixture(); char other[PATH_MAX]; Snapshot before;
    joined(other, root->top, "missing"); before = snapshot(root);
    REFUSED(envara_pf_run_ledger_test_root(other)); unchanged(root, &before);
    joined(other, root->top, "owned-root-link"); CHECK(symlink(root->root, other) == 0); before = snapshot(root);
    REFUSED(envara_pf_run_ledger_test_root(other)); unchanged(root, &before);
    CHECK(unlink(other) == 0); owned_file(other, "fixture", 7, 0); before = snapshot(root);
    REFUSED(envara_pf_run_ledger_test_root(other)); unchanged(root, &before);
    CHECK(chmod(root->root, 0755) == 0); before = snapshot(root);
    REFUSED(envara_pf_run_ledger_test_root(root->root)); unchanged(root, &before);
    CHECK(chmod(root->root, 0700) == 0 && envara_pf_run_ledger_test_root(root->root) == 1);
    observed(root, Run, ENVARA_PF_RUN_UNUSED); CHECK(destroy_fixture(root));
}
static void test_hard_cap(void) {
    Fixture *root = fixture(); char run[37];
    for (unsigned i = 0; i < ENVARA_PF_RUN_LEDGER_MAX_RUNS; i++) {
        CHECK(snprintf(run, sizeof(run), "%08x-0000-4000-8000-000000000001", i) == 36);
        EnvaraPFRunLedger *ledger = allocated(run); envara_pf_run_ledger_close(ledger);
    }
    CHECK(envara_pf_run_ledger_test_root(root->root) == 1);
    CHECK(snprintf(run, sizeof(run), "%08x-0000-4000-8000-000000000001", ENVARA_PF_RUN_LEDGER_MAX_RUNS) == 36);
    observed(root, run, ENVARA_PF_RUN_CAPACITY_EXHAUSTED);
    allocation_refused(root, run);
    observed(root, "00000000-0000-4000-8000-000000000001", ENVARA_PF_RUN_ALLOCATION_ONLY);
    allocation_refused(root, "00000000-0000-4000-8000-000000000001");
    /* An externally introduced 65th directory is unknown, never eviction. */
    char directory[PATH_MAX]; joined(directory, root->root, run); CHECK(mkdir(directory, 0700) == 0);
    unknown(root, "00000000-0000-4000-8000-000000000001"); allocation_refused(root, OtherRun);
    CHECK(destroy_fixture(root));
}

int main(void) {
    if (getuid() == 0 || geteuid() == 0 || getuid() != geteuid()) {
        fputs("ledger inert fixtures refuse root or changed effective identity\n", stderr); return 77;
    }
    CHECK(atexit(cleanup_all) == 0);
    test_uuid(); test_readonly_and_consumption(); test_strict_lease(); test_delete_and_retirement();
    test_insert_rollback_retirement(); test_allocation_delete_intent_readonly();
    test_uncertain_issue(); test_unknown_inventory(); test_held_identity_replacement(); test_issued_tampering();
    test_root_selection_refusals(); test_hard_cap();
    printf("ledger inert fixtures passed (%u checks); no PF or privileged operation\n", checks);
    return 0;
}
