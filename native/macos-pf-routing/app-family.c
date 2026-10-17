#include "app-family.h"
#include <mach/mach.h>
#include <mach/task_info.h>
#include <libproc.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#ifndef proc_signal_with_audittoken
extern int proc_signal_with_audittoken(audit_token_t *, int) __attribute__((weak_import));
#endif
static int (*family_signal_api)(audit_token_t *, int) = proc_signal_with_audittoken;
int envara_app_family_available(void) { return family_signal_api != NULL; }

#define ENVARA_APP_FAMILY_LIMIT 256U
struct family_member { struct envara_identity identity; audit_token_t token; };
struct envara_app_family {
    pid_t owner;
    int uncertain, stopped, retry_pending, retry_error;
    struct envara_app_family_failure failure;
    size_t count;
    uint64_t membership_revision;
    struct family_member members[ENVARA_APP_FAMILY_LIMIT];
};
const char *envara_app_family_failure_name(enum envara_app_family_failure_reason reason) {
    static const char *names[] = {"none", "identity", "token", "inventory", "churn", "capacity", "signal", "stop-timeout", "unavailable"};
    return reason >= ENVARA_APP_FAMILY_FAILURE_NONE && reason <= ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE ? names[reason] : NULL;
}
void envara_app_family_first_failure(const envara_app_family *family, struct envara_app_family_failure *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (family && family->owner == getpid()) *out = family->failure;
}
static int family_refuse_reason(envara_app_family *family, enum envara_app_family_failure_reason reason, int error, int mach_error) {
    if (family) {
        family->uncertain = 1;
        if (family->failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE)
            family->failure = (struct envara_app_family_failure){.reason = reason, .os_error = error, .mach_error = mach_error};
    }
    errno = error; return 0;
}
static int family_defer(envara_app_family *family, enum envara_app_family_failure_reason reason, int error) {
    if (!family || family->uncertain) return family_refuse_reason(family, reason, error, 0);
    family->retry_pending = 1; family->retry_error = error;
    if (family->failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE)
        family->failure = (struct envara_app_family_failure){.reason = reason, .os_error = error};
    errno = error; return 0;
}
static int family_refuse(envara_app_family *family, int error) {
    return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, error, 0);
}
static int family_refresh_refuse(envara_app_family *family, enum envara_app_family_failure_reason reason, int error, int mach_error) {
    (void)family_refuse_reason(family, reason, error, mach_error); return -1;
}
/* 1 live, 2 zombie, 0 exact native absence, -1 unknown. Zombies are inspected
 * before reap, unlike a PID-only kill/absence guess. */
static int family_identity(pid_t pid, struct envara_identity *out, unsigned *state) {
    struct proc_bsdinfo info = {0}; errno = 0;
    int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info));
    if (!bytes && errno == ESRCH) return 0;
    if (bytes != sizeof(info) || info.pbi_pid != (uint32_t)pid || !info.pbi_start_tvsec ||
        info.pbi_start_tvusec >= 1000000 || info.pbi_status < SIDL || info.pbi_status > SZOMB) return -1;
    *out = (struct envara_identity){.pid = pid, .parent_pid = (pid_t)info.pbi_ppid,
        .uid = info.pbi_uid, .ruid = info.pbi_ruid, .saved_uid = info.pbi_svuid,
        .gid = info.pbi_gid, .rgid = info.pbi_rgid, .saved_gid = info.pbi_svgid,
        .birth_seconds = info.pbi_start_tvsec, .birth_microseconds = info.pbi_start_tvusec};
    if (state) *state = info.pbi_status;
    return info.pbi_status == SZOMB ? 2 : 1;
}
static int family_same(const struct envara_identity *a, const struct envara_identity *b) {
    return a->pid == b->pid && a->birth_seconds == b->birth_seconds && a->birth_microseconds == b->birth_microseconds &&
        a->uid == b->uid && a->ruid == b->ruid && a->saved_uid == b->saved_uid &&
        a->gid == b->gid && a->rgid == b->rgid && a->saved_gid == b->saved_gid;
}
static int family_membership_changed(envara_app_family *family) {
    if (family->membership_revision == UINT64_MAX)
        return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_CAPACITY, EOVERFLOW, 0);
    family->membership_revision++; return 1;
}
/* Compact only between complete observation rounds, before any parent pointer
 * is held. A registered descendant keeps its own generation and token when its
 * parent leaves. Only positive native ESRCH retires a nonleader; a zombie,
 * changed generation/credentials or unavailable inspection is not absence. */
static int family_retire_absent(envara_app_family *family) {
    for (size_t i = 1; i < family->count;) {
        struct envara_identity actual;
        int state = family_identity(family->members[i].identity.pid, &actual, NULL);
        if (state < 0 || (state > 0 && !family_same(&actual, &family->members[i].identity)))
            return family_refuse(family, ESTALE);
        if (state != 0) { i++; continue; }
        if (!family_membership_changed(family)) return 0;
        memmove(&family->members[i], &family->members[i + 1],
            (family->count - i - 1) * sizeof(family->members[0]));
        memset(&family->members[--family->count], 0, sizeof(family->members[0]));
    }
    return 1;
}
static int family_confirm_zombie(const struct envara_identity *seen, int bind_parent) {
    struct envara_identity confirmed; int state = family_identity(seen->pid, &confirmed, NULL);
    if (state == 0) return 0;
    return state == 2 && family_same(seen, &confirmed) &&
        (!bind_parent || seen->parent_pid == confirmed.parent_pid) ? 2 : -1;
}
static int family_refresh_pause(void) {
    /* One scheduling opportunity for the observed task-gone/BSD-live exit
     * window. Interrupted sleep is never restarted or promoted to success. */
    const struct timespec pause = {0, 1000000};
    return nanosleep(&pause, NULL) == 0;
}
static int family_member_refresh_attempt(envara_app_family *family, struct family_member *member,
    const audit_token_t *reparent_token, pid_t prior_parent, unsigned bracket, int candidate) {
    struct envara_identity before, after; int state = family_identity(member->identity.pid, &before, NULL);
    if (state == 0) return 0;
    if (state < 0 || !family_same(&before, &member->identity))
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (candidate && before.parent_pid != member->identity.parent_pid)
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (bracket && before.parent_pid != prior_parent)
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (state == 2) {
        if (!bracket && !candidate) return state;
        state = family_confirm_zombie(&before, 1);
        return state >= 0 ? state : family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    }
    mach_port_t name = MACH_PORT_NULL; pid_t actual = 0;
    audit_token_t token; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t error = task_name_for_pid(mach_task_self(), before.pid, &name);
    if (error != KERN_SUCCESS) {
        /* A known generation may exit between BSD inspection and task lookup.
         * Only positive absence or two complete same-generation zombie reads
         * reconcile that race; unavailable or changed evidence stays permanent. */
        state = family_identity(before.pid, &after, NULL);
        if (state == 0) return 0;
        if (candidate && state > 0 && (!family_same(&before, &after) || after.parent_pid != member->identity.parent_pid))
            return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
        if (state == 2 && family_same(&before, &after) && (!bracket || before.parent_pid == after.parent_pid)) {
            state = family_confirm_zombie(&after, bracket != 0 || candidate);
            if (state >= 0) return state;
        }
        else if (!bracket && error == KERN_FAILURE && state == 1 && family_same(&before, &after) &&
            before.parent_pid == after.parent_pid && family_refresh_pause())
            return family_member_refresh_attempt(family, member, NULL, after.parent_pid, 1, candidate);
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_TOKEN, EACCES, error);
    }
    error = pid_for_task(name, &actual);
    int info_called = error == KERN_SUCCESS && actual == before.pid;
    if (info_called)
        error = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    (void)mach_port_deallocate(mach_task_self(), name);
    /* A new candidate has no retained membership authority. Explicit successful
     * API contradictions cannot be erased by a later native absence. */
    if (candidate && error == KERN_SUCCESS && actual != before.pid)
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (candidate && info_called && error == KERN_SUCCESS && count != TASK_AUDIT_TOKEN_COUNT)
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_TOKEN, EIO, 0);
    state = family_identity(before.pid, &after, NULL);
    if (state == 0) return state;
    if (candidate && state > 0 && (!family_same(&before, &after) || after.parent_pid != member->identity.parent_pid))
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (state == 2 && family_same(&before, &after) && (!bracket || before.parent_pid == after.parent_pid)) {
        if (!bracket && !candidate) return state;
        state = family_confirm_zombie(&after, 1);
        return state >= 0 ? state : family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    }
    if (state != 1 || !family_same(&before, &after))
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (error != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) {
        if (!bracket && info_called && error == KERN_INVALID_ARGUMENT && count == TASK_AUDIT_TOKEN_COUNT &&
            before.parent_pid == after.parent_pid && family_refresh_pause())
            return family_member_refresh_attempt(family, member, NULL, after.parent_pid, 1, candidate);
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_TOKEN, error == KERN_SUCCESS ? EIO : EACCES, error);
    }
    if (actual != before.pid) return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (reparent_token && memcmp(reparent_token, &token, sizeof(token)))
        return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
    if (before.parent_pid != after.parent_pid) {
        /* Retain an already observed member, never admit a new parent chain.
         * The saved audit token must still match, including its exec epoch.
         * One fresh stable bracket is required; a second drift stays unknown. */
        int registered = 0;
        for (size_t i = 1; i < family->count; i++)
            if (member == &family->members[i]) { registered = 1; break; }
        if (bracket || !registered || memcmp(&member->token, &token, sizeof(token)))
            return family_refresh_refuse(family, ENVARA_APP_FAMILY_FAILURE_IDENTITY, ESTALE, 0);
        return family_member_refresh_attempt(family, member, &token, after.parent_pid, 1, candidate);
    }
    member->token = token; return 1;
}
static int family_member_refresh(envara_app_family *family, struct family_member *member) {
    /* A reparent and a transient Mach failure share this two-bracket budget. */
    return family_member_refresh_attempt(family, member, NULL, 0, 0, 0);
}
static int family_pid_compare(const void *a, const void *b) {
    pid_t x = *(const pid_t *)a, y = *(const pid_t *)b; return x < y ? -1 : x > y ? 1 : 0;
}
static int family_children(pid_t parent, pid_t *children) {
    errno = 0; int count = proc_listchildpids(parent, children, (int)(ENVARA_APP_FAMILY_LIMIT * sizeof(pid_t)));
    if (count < 0 || count >= (int)ENVARA_APP_FAMILY_LIMIT || (!count && errno)) return -1;
    qsort(children, (size_t)count, sizeof(pid_t), family_pid_compare);
    for (int i = 0; i < count; i++) if (children[i] <= 1 || (i && children[i] == children[i - 1])) return -1;
    return count;
}
static int family_find(const envara_app_family *family, pid_t pid) {
    for (size_t i = 0; i < family->count; i++) if (family->members[i].identity.pid == pid) return (int)i;
    return -1;
}
/* A positively identified zombie cannot fork or receive a signal. Recheck its
 * exact identity and observed parent before excluding it from the live family;
 * a fully attributed child may instead be exactly absent after reap, provided
 * its registered parent is freshly live. Keep both original child
 * vectors: unknown/changed identity is a gap, and their differences are churn. */
static int family_stable_zombie(envara_app_family *family, struct family_member *parent,
    const struct envara_identity *seen) {
    if (seen->parent_pid != parent->identity.pid) return -1;
    struct envara_identity after; int state = family_identity(seen->pid, &after, NULL);
    if (state == 0) return family_member_refresh(family, parent) == 1 ? 0 : -1;
    if (state != 2 || !family_same(seen, &after) || seen->parent_pid != parent->identity.pid ||
        after.parent_pid != seen->parent_pid || family_member_refresh(family, parent) != 1) return -1;
    return 1;
}
static int family_observe_child(envara_app_family *family, struct family_member *parent, pid_t pid) {
    struct envara_identity actual; int state = family_identity(pid, &actual, NULL);
    /* A listed PID without a complete identity is an attribution gap, not
     * retryable vector churn, even when the syscall happened to say EAGAIN. */
    if ((state != 1 && state != 2) || actual.parent_pid != parent->identity.pid ||
        !envara_identity_matches(&actual, family->members[0].identity.uid, family->members[0].identity.gid))
        return family_refuse(family, ESTALE);
    int existing = family_find(family, actual.pid);
    if (existing >= 0 && !family_same(&family->members[existing].identity, &actual)) return family_refuse(family, ESTALE);
    if (state == 2) {
        return family_stable_zombie(family, parent, &actual) >= 0 ? 1 : family_refuse(family, ESTALE);
    }
    if (existing >= 0) return 1;
    if (family->count >= ENVARA_APP_FAMILY_LIMIT)
        return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_CAPACITY, EOVERFLOW, 0);
    struct family_member member = {.identity = actual};
    state = family_member_refresh_attempt(family, &member, NULL, 0, 0, 1);
    if (state == 0) return family_member_refresh(family, parent) == 1 ? 1 : family_refuse(family, ESTALE);
    if (state == 2) return family_stable_zombie(family, parent, &member.identity) >= 0 ? 1 : family_refuse(family, ESTALE);
    if (state != 1 || family_member_refresh(family, parent) != 1) return family_refuse(family, ESTALE);
    if (!family_membership_changed(family)) return 0;
    family->members[family->count++] = member; return 1;
}
int envara_app_family_observe(envara_app_family *family) {
    if (!family || family->owner != getpid() || family->uncertain) return family_refuse(family, EACCES);
    if (family->retry_pending) { errno = family->retry_error; return 0; }
    for (unsigned round = 0; round < 3; round++) {
        if (!family_retire_absent(family)) return 0;
        int changed = 0;
        for (size_t i = 0; i < family->count; i++) {
            struct family_member *parent = &family->members[i];
            int live = family_member_refresh(family, parent);
            if (live < 0) return family_refuse(family, ESTALE);
            if (live != 1) continue;
            pid_t first[ENVARA_APP_FAMILY_LIMIT], second[ENVARA_APP_FAMILY_LIMIT];
            int count = family_children(parent->identity.pid, first);
            if (count < 0) return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_INVENTORY, EACCES, 0);
            for (int j = 0; j < count; j++) if (!family_observe_child(family, parent, first[j])) return 0;
            int other = family_children(parent->identity.pid, second);
            if (other < 0) return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_INVENTORY, EACCES, 0);
            /* Every PID in both vectors must have complete native attribution
             * before a vector-only difference can be classified as retryable. */
            for (int j = 0; j < other; j++) if (!family_observe_child(family, parent, second[j])) return 0;
            if (family_member_refresh(family, parent) != 1) return family_refuse(family, ESTALE);
            if (other != count || memcmp(first, second, (size_t)count * sizeof(pid_t))) changed = 1;
        }
        if (!changed) return 1;
    }
    return family_defer(family, ENVARA_APP_FAMILY_FAILURE_CHURN, EAGAIN);
}
envara_app_family *envara_app_family_create_diagnosed(const struct envara_identity *leader,
    struct envara_app_family_failure *failure) {
    if (failure) memset(failure, 0, sizeof(*failure));
    struct envara_identity actual;
    enum envara_app_family_failure_reason reason = ENVARA_APP_FAMILY_FAILURE_IDENTITY; int error = EACCES;
    if (!envara_app_family_available()) { reason = ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE; error = ENOTSUP; goto refused; }
    if (!leader || leader->pid <= 1 || leader->parent_pid != getpid() || !leader->birth_seconds ||
        family_identity(leader->pid, &actual, NULL) != 1 || actual.parent_pid != getpid() || !family_same(leader, &actual)) goto refused;
    envara_app_family *family = calloc(1, sizeof(*family));
    if (!family) { reason = ENVARA_APP_FAMILY_FAILURE_CAPACITY; error = ENOMEM; goto refused; }
    family->owner = getpid(); family->count = 1; family->membership_revision = 1; family->members[0].identity = *leader;
    if (!envara_app_family_observe(family)) {
        int observed_error = errno; if (failure) *failure = family->failure;
        if (!family->uncertain && family->retry_pending) { errno = observed_error; return family; }
        free(family); errno = observed_error; return NULL;
    }
    return family;
refused:
    if (failure) *failure = (struct envara_app_family_failure){.reason = reason, .os_error = error};
    errno = error; return NULL;
}
envara_app_family *envara_app_family_create(const struct envara_identity *leader) {
    return envara_app_family_create_diagnosed(leader, NULL);
}
static int family_signal(envara_app_family *family, size_t index, int signal_number, int *sent) {
    struct family_member *member = &family->members[index]; int state = family_member_refresh(family, member);
    if (state == 0 || state == 2) return 1;
    if (state != 1) return family_refuse(family, ESTALE);
    if (!envara_app_family_available()) return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE, ENOTSUP, 0);
    int error = family_signal_api(&member->token, signal_number);
    if (error) {
        struct envara_identity actual; state = family_identity(member->identity.pid, &actual, NULL);
        if (error == ESRCH && (state == 0 || (state == 2 && family_same(&member->identity, &actual)))) return 1;
        return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_SIGNAL, error, 0);
    }
    if (sent) *sent = 1;
    return 1;
}
int envara_app_family_stop(envara_app_family *family, int *leader_signal_sent) {
    if (leader_signal_sent) *leader_signal_sent = 0;
    if (!family || family->owner != getpid() || family->uncertain) return family_refuse(family, EACCES);
    if (family->retry_pending) { errno = family->retry_error; return 0; }
    if (family->stopped) return 1;
    for (unsigned round = 0; round < 4; round++) {
        if (!envara_app_family_observe(family)) return 0;
        size_t count = family->count;
        uint64_t revision = family->membership_revision;
        for (size_t i = count; i > 0; i--) if (!family_signal(family, i - 1, SIGSTOP, NULL)) return 0;
        int frozen = 0;
        for (unsigned wait = 0; wait < 25; wait++) {
            frozen = 1;
            for (size_t i = 0; i < family->count; i++) {
                struct envara_identity actual; unsigned state = 0; int live = family_identity(family->members[i].identity.pid, &actual, &state);
                if (live < 0 || (live > 0 && !family_same(&actual, &family->members[i].identity))) return family_refuse(family, ESTALE);
                if (live == 1 && state != SSTOP) frozen = 0;
            }
            if (frozen) break;
            struct timespec pause = {0, 10000000}; (void)nanosleep(&pause, NULL);
        }
        if (!frozen) return family_defer(family, ENVARA_APP_FAMILY_FAILURE_STOP_TIMEOUT, ETIMEDOUT);
        if (!envara_app_family_observe(family)) return 0;
        /* Retirement and admission can leave the same count. Every changed
         * membership must receive another STOP and complete frozen readback. */
        if (revision != family->membership_revision) continue;
        for (size_t i = family->count; i > 0; i--) {
            int sent = 0;
            if (!family_signal(family, i - 1, SIGKILL, &sent)) return 0;
            if (i == 1 && sent && leader_signal_sent) *leader_signal_sent = 1;
        }
        family->stopped = 1; return 1;
    }
    return family_refuse_reason(family, ENVARA_APP_FAMILY_FAILURE_CAPACITY, EOVERFLOW, 0);
}
int envara_app_family_retry_stop(envara_app_family *family, int *leader_signal_sent) {
    if (leader_signal_sent) *leader_signal_sent = 0;
    if (!family || family->owner != getpid() || family->uncertain) return family_refuse(family, EACCES);
    /* This entry is used only by the fixed guardian after a fresh explicit S
     * has verified DENY plus original frontend shutdown. No R/automatic retry. */
    family->retry_pending = 0; family->retry_error = 0;
    return envara_app_family_stop(family, leader_signal_sent);
}
int envara_app_family_quiescent(envara_app_family *family) {
    if (!family || family->owner != getpid() || family->uncertain || family->retry_pending) return 0;
    for (size_t i = 0; i < family->count; i++) {
        struct envara_identity actual; int state = family_identity(family->members[i].identity.pid, &actual, NULL);
        if (state < 0 || (state > 0 && !family_same(&actual, &family->members[i].identity))) return family_refuse(family, ESTALE);
        if (state == 1) return 0;
    }
    return 1;
}
size_t envara_app_family_count(const envara_app_family *family) { return family && family->owner == getpid() ? family->count : 0; }
void envara_app_family_destroy(envara_app_family *family) {
    if (family) { memset(family, 0, sizeof(*family)); free(family); }
}
