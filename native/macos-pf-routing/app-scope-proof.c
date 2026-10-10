#include "app-scope-proof.h"
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

/* Reader extracted from the corrected ff9 recovery proof. SDK field sizes and
 * native returned byte counts stay strict; kern.ngroups must equal NGROUPS.
 * Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea proc_info.c 2046-2061:
 * PROC_PIDTBSDINFO with arg1 includes zombies and returns full BSD credentials.
 * KERN_PROC_PID supplies the supplementary credential vector. No fixed run,
 * group-directory claim, native mutation, PF operation or runtime override. */
#define SCOPE_PID_LIMIT 16384U
#define SCOPE_DEADLINE_SECONDS 15.0
#define SCOPE_MAX_ROUNDS 3U
_Static_assert(sizeof(((struct kinfo_proc *)0)->kp_eproc.e_ucred.cr_groups) ==
    NGROUPS * sizeof(gid_t), "complete SDK credential group vector");
_Static_assert(sizeof(((struct proc_bsdinfo *)0)->pbi_gid) == sizeof(gid_t) &&
    sizeof(((struct proc_bsdinfo *)0)->pbi_rgid) == sizeof(gid_t) &&
    sizeof(((struct proc_bsdinfo *)0)->pbi_svgid) == sizeof(gid_t), "BSD GID widths");

typedef struct {
    pid_t pid;
    unsigned status;
    uint64_t seconds, microseconds;
    uid_t effective_uid, real_uid, saved_uid;
    gid_t effective_gid, real_gid, saved_gid;
    unsigned group_count;
    gid_t groups[NGROUPS];
} ScopeCredentials;
/* Private compiled callbacks allow inert tests to exercise the reader core.
 * The exported absence function always selects the native readers below.
 * Result 1 from a credential reader means exact zero-byte ESRCH only. */
typedef struct {
    void *context;
    int (*root)(void *);
    int (*capacity)(void *, unsigned *);
    int (*list)(void *, pid_t *, size_t);
    int (*bsd)(void *, pid_t, ScopeCredentials *);
    int (*supplementary)(void *, pid_t, ScopeCredentials *);
    double (*clock)(void *);
} ScopeReaders;

static _Thread_local EnvaraScopeDiagnostic scope_diagnostic;
static _Thread_local int scope_transient;
const EnvaraScopeDiagnostic *envara_app_scope_last_diagnostic(void) { return &scope_diagnostic; }
static void scope_diag_fail(uint32_t reason) {
    if (scope_diagnostic.reason == ENVARA_SCOPE_NOT_RUN) scope_diagnostic.reason = reason;
}
static int scope_diag_predicate(int result, uint32_t reason) {
    if (!result) scope_diag_fail(reason); return result;
}
static void scope_diag_native(uint32_t query, int status, int error, size_t bytes) {
    if (scope_diagnostic.reason != ENVARA_SCOPE_NOT_RUN) return;
    scope_diagnostic.native_query = query;
    scope_diagnostic.native_errno = status && error > 0 ? (uint32_t)error : 0;
    scope_diagnostic.native_bytes = bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}
static int scope_diag_root(const ScopeReaders *readers) {
    int result = readers->root(readers->context);
    if (result != 1) scope_diag_fail(ENVARA_SCOPE_ROOT_REFUSED); return result;
}
static int scope_diag_capacity(const ScopeReaders *readers, unsigned *capacity) {
    int result = readers->capacity(readers->context, capacity);
    if (result) scope_diag_fail(ENVARA_SCOPE_CAPACITY_READER_REFUSED); return result;
}
static int scope_diag_bsd(const ScopeReaders *readers, pid_t pid, ScopeCredentials *out) {
    scope_diagnostic.bsd_reads++;
    int result = readers->bsd(readers->context, pid, out);
    if (result) {scope_diag_fail(ENVARA_SCOPE_BSD_READER_REFUSED);scope_transient=result==1;} return result;
}
static int scope_diag_supplementary(const ScopeReaders *readers, pid_t pid, ScopeCredentials *out) {
    scope_diagnostic.supplementary_reads++;
    int result = readers->supplementary(readers->context, pid, out);
    if (result) {scope_diag_fail(ENVARA_SCOPE_SUPPLEMENTARY_READER_REFUSED);scope_transient=result==1;} return result;
}
static int scope_credential_shape(const ScopeCredentials *value, pid_t pid, int groups) {
    if (value->pid != pid || pid <= 0 || !value->seconds || value->microseconds >= 1000000 ||
        value->status < SIDL || value->status > SZOMB) { scope_diag_fail(groups ? ENVARA_SCOPE_SUPPLEMENTARY_SHAPE_REFUSED : ENVARA_SCOPE_BSD_SHAPE_REFUSED); return 0; }
    if (!groups) return scope_diag_predicate(value->group_count == 0, ENVARA_SCOPE_BSD_SHAPE_REFUSED);
    if (value->group_count < 1 || value->group_count > NGROUPS || value->groups[0] != value->effective_gid) { scope_diag_fail(ENVARA_SCOPE_SUPPLEMENTARY_SHAPE_REFUSED); return 0; }
    for (unsigned i = 0; i < value->group_count; i++)
        for (unsigned j = 0; j < i; j++) if (value->groups[i] == value->groups[j]) { scope_diag_fail(ENVARA_SCOPE_SUPPLEMENTARY_SHAPE_REFUSED); return 0; }
    return 1;
}
static int scope_same_identity(const ScopeCredentials *a, const ScopeCredentials *b) {
    return scope_diag_predicate(a->pid == b->pid && a->seconds == b->seconds && a->microseconds == b->microseconds &&
        (a->status == SZOMB) == (b->status == SZOMB) &&
        a->effective_uid == b->effective_uid && a->real_uid == b->real_uid && a->saved_uid == b->saved_uid &&
        a->effective_gid == b->effective_gid && a->real_gid == b->real_gid && a->saved_gid == b->saved_gid, ENVARA_SCOPE_IDENTITY_MISMATCH);
}
static int scope_same_groups(const ScopeCredentials *a, const ScopeCredentials *b) {
    return scope_diag_predicate(a->group_count == b->group_count && !memcmp(a->groups, b->groups, a->group_count * sizeof(gid_t)), ENVARA_SCOPE_GROUP_VECTOR_CHANGED);
}
static int scope_has_gid(const ScopeCredentials *value, gid_t gid) {
    if (value->effective_gid == gid || value->real_gid == gid || value->saved_gid == gid) { scope_diag_fail(ENVARA_SCOPE_GID_PRESENT); return 1; }
    for (unsigned i = 0; i < value->group_count; i++) if (value->groups[i] == gid) { scope_diag_fail(ENVARA_SCOPE_GID_PRESENT); return 1; }
    return 0;
}
static int scope_pid_compare(const void *a, const void *b) {
    pid_t left = *(const pid_t *)a, right = *(const pid_t *)b;
    return left < right ? -1 : left > right ? 1 : 0;
}
static int scope_before_deadline(const ScopeReaders *readers, double deadline) {
    double now = readers->clock(readers->context);
    return scope_diag_predicate(isfinite(now) && now >= 0 && now < deadline && scope_diag_root(readers) == 1, ENVARA_SCOPE_DEADLINE_REFUSED);
}
static int scope_read_list(const ScopeReaders *readers, pid_t *pids, double deadline) {
    if (!scope_before_deadline(readers, deadline)) return -1;
    int count = readers->list(readers->context, pids, SCOPE_PID_LIMIT);
    if (count <= 0 || count >= (int)SCOPE_PID_LIMIT || !scope_before_deadline(readers, deadline)) { scope_diag_fail(count < 0 ? ENVARA_SCOPE_LIST_READER_REFUSED : ENVARA_SCOPE_LIST_BOUND_REFUSED); return -1; }
    size_t positive = 0;
    for (int i = 0; i < count; i++) {
        if (pids[i] < 0) { scope_diag_fail(ENVARA_SCOPE_NEGATIVE_PID); return -1; }
        if (pids[i] > 0) pids[positive++] = pids[i];
    }
    /* PID zero is the kernel task, not a user credential-bearing process. */
    if (!positive) { scope_diag_fail(ENVARA_SCOPE_EMPTY_POSITIVE_LIST); return -1; }
    qsort(pids, positive, sizeof(pid_t), scope_pid_compare);
    for (size_t i = 1; i < positive; i++) if (pids[i] == pids[i - 1]) { scope_diag_fail(ENVARA_SCOPE_DUPLICATE_PID); return -1; }
    return (int)positive;
}
static int scope_read_credentials(const ScopeReaders *readers, pid_t pid, gid_t gid,
    double deadline, ScopeCredentials *out) {
    ScopeCredentials first = {0}, supplementary = {0}, last = {0};
    if (!scope_before_deadline(readers, deadline) || scope_diag_bsd(readers, pid, &first) ||
        !scope_credential_shape(&first, pid, 0) || scope_has_gid(&first, gid)) return 0;
    if (!scope_before_deadline(readers, deadline) || scope_diag_supplementary(readers, pid, &supplementary) ||
        !scope_credential_shape(&supplementary, pid, 1) || scope_has_gid(&supplementary, gid)) return 0;
    if (!scope_before_deadline(readers, deadline) || scope_diag_bsd(readers, pid, &last) ||
        !scope_credential_shape(&last, pid, 0) || scope_has_gid(&last, gid) ||
        !scope_before_deadline(readers, deadline)) return 0;
    if(!scope_same_identity(&first,&supplementary)||!scope_same_identity(&supplementary,&last)){scope_transient=1;return 0;}
    *out = supplementary; return 1;
}
static void scope_retain_first_reason(void) {
    if(!scope_diagnostic.first_reason&&scope_diagnostic.reason){
        scope_diagnostic.first_reason=scope_diagnostic.reason;
        scope_diagnostic.first_native_errno=scope_diagnostic.native_errno;
        scope_diagnostic.first_native_bytes=scope_diagnostic.native_bytes;
        scope_diagnostic.first_native_query=scope_diagnostic.native_query;
    }
}
static int scope_gid_absent(gid_t gid,const ScopeReaders *readers) {
    scope_diagnostic=(EnvaraScopeDiagnostic){0};scope_transient=0;
    if(gid<7100||gid>7999||!readers||!readers->root||!readers->capacity||!readers->list||!readers->bsd||!readers->supplementary||!readers->clock){
        scope_diag_fail(ENVARA_SCOPE_REQUEST_OR_READERS_INVALID);scope_retain_first_reason();return 0;}
    if(scope_diag_root(readers)!=1){scope_retain_first_reason();return 0;}
    double start=readers->clock(readers->context),deadline=start+SCOPE_DEADLINE_SECONDS;
    if(!isfinite(start)||start<0||!isfinite(deadline)||deadline<=start){scope_diag_fail(ENVARA_SCOPE_CLOCK_REFUSED);scope_retain_first_reason();return 0;}
    pid_t *first=calloc(SCOPE_PID_LIMIT,sizeof(pid_t)),*second=calloc(SCOPE_PID_LIMIT,sizeof(pid_t));
    ScopeCredentials *baseline=calloc(SCOPE_PID_LIMIT,sizeof(*baseline));int absent=0;
    if(!first||!second||!baseline){scope_diag_fail(ENVARA_SCOPE_ALLOCATION_REFUSED);goto done;}
    /* At most three COMPLETE reacquisitions share this one original deadline.
     * No failed PID is skipped or reread in isolation, and no credentials from
     * a rejected round enter a later proof. Unknown/permission/shape/GID fails
     * stop immediately; only the explicit native zero-byte ESRCH result or a
     * fully decoded inventory/identity/group change invalidates a whole round. */
    for(unsigned round=1;round<=SCOPE_MAX_ROUNDS;round++){
        scope_diagnostic.rounds=round;scope_diagnostic.reason=ENVARA_SCOPE_NOT_RUN;scope_transient=0;
        scope_diagnostic.first_count=scope_diagnostic.second_count=0;
        memset(first,0,SCOPE_PID_LIMIT*sizeof(*first));memset(second,0,SCOPE_PID_LIMIT*sizeof(*second));memset(baseline,0,SCOPE_PID_LIMIT*sizeof(*baseline));
        if(!scope_before_deadline(readers,deadline))goto done;
        unsigned capacity=0;
        if(scope_diag_capacity(readers,&capacity)||capacity!=NGROUPS){scope_diag_fail(ENVARA_SCOPE_CAPACITY_MISMATCH);goto done;}
        int count=scope_read_list(readers,first,deadline);if(count>0)scope_diagnostic.first_count=(uint32_t)count;if(count<0)goto done;
        for(int i=0;i<count;i++)if(!scope_read_credentials(readers,first[i],gid,deadline,&baseline[i]))goto round_failed;
        int count_second=scope_read_list(readers,second,deadline);if(count_second>0)scope_diagnostic.second_count=(uint32_t)count_second;if(count_second<0)goto done;
        if(count_second!=count||memcmp(first,second,(size_t)count*sizeof(pid_t))){scope_diag_fail(ENVARA_SCOPE_PID_INVENTORY_CHANGED);scope_transient=1;goto round_failed;}
        for(int i=0;i<count;i++){
            ScopeCredentials observed={0};if(!scope_read_credentials(readers,second[i],gid,deadline,&observed))goto round_failed;
            if(!scope_same_identity(&baseline[i],&observed)||!scope_same_groups(&baseline[i],&observed)){scope_transient=1;goto round_failed;}
        }
        capacity=0;
        if(scope_diag_capacity(readers,&capacity)||capacity!=NGROUPS||!scope_before_deadline(readers,deadline)){scope_diag_fail(ENVARA_SCOPE_CAPACITY_MISMATCH);goto done;}
        absent=1;scope_diagnostic.reason=ENVARA_SCOPE_ABSENCE_VERIFIED;goto done;
round_failed:
        scope_retain_first_reason();
        if(!scope_transient)goto done;
        if(round==SCOPE_MAX_ROUNDS){scope_diagnostic.retry_exhausted=1;goto done;}
        scope_diagnostic.retry_count++;
    }
done:
    scope_retain_first_reason();free(first);free(second);free(baseline);return absent;
}

static int scope_decode_bsd(const struct proc_bsdinfo *info, int bytes, ScopeCredentials *out) {
    if (!info || !out || bytes != sizeof(*info)) return -1;
    *out = (ScopeCredentials){.pid = (pid_t)info->pbi_pid, .status = info->pbi_status,
        .seconds = info->pbi_start_tvsec, .microseconds = info->pbi_start_tvusec,
        .effective_uid = info->pbi_uid, .real_uid = info->pbi_ruid, .saved_uid = info->pbi_svuid,
        .effective_gid = info->pbi_gid, .real_gid = info->pbi_rgid, .saved_gid = info->pbi_svgid};
    return 0;
}
static int scope_decode_supplementary(const struct kinfo_proc *info, int status, size_t bytes, ScopeCredentials *out) {
    if (!info || !out || status || bytes != sizeof(*info) || info->kp_proc.p_starttime.tv_sec <= 0 ||
        info->kp_proc.p_starttime.tv_usec < 0 || info->kp_proc.p_starttime.tv_usec >= 1000000) return -1;
    int count = info->kp_eproc.e_ucred.cr_ngroups;
    if (count < 1 || count > NGROUPS) return -1;
    ScopeCredentials value = {.pid = info->kp_proc.p_pid, .status = (unsigned char)info->kp_proc.p_stat,
        .seconds = (uint64_t)info->kp_proc.p_starttime.tv_sec, .microseconds = (uint64_t)info->kp_proc.p_starttime.tv_usec,
        .effective_uid = info->kp_eproc.e_ucred.cr_uid, .real_uid = info->kp_eproc.e_pcred.p_ruid,
        .saved_uid = info->kp_eproc.e_pcred.p_svuid, .effective_gid = info->kp_eproc.e_ucred.cr_groups[0],
        .real_gid = info->kp_eproc.e_pcred.p_rgid, .saved_gid = info->kp_eproc.e_pcred.p_svgid, .group_count = (unsigned)count};
    memcpy(value.groups, info->kp_eproc.e_ucred.cr_groups, value.group_count * sizeof(gid_t));
    *out = value; return 0;
}
static int scope_native_root(void *context) { (void)context; return getuid() == 0 && geteuid() == 0; }
static double scope_native_clock(void *context) {
    (void)context; struct timespec value;
    errno = 0; int status = clock_gettime(CLOCK_MONOTONIC, &value); int error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_CLOCK, status, error, status ? 0 : sizeof(value));
    if (status) return -1;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static int scope_native_capacity(void *context, unsigned *out) {
    (void)context; int capacity = 0; size_t bytes = sizeof(capacity);
    errno = 0; int status = sysctlbyname("kern.ngroups", &capacity, &bytes, NULL, 0); int error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_GROUP_CAPACITY, status, error, bytes);
    if (status || bytes != sizeof(capacity) ||
        capacity < 1 || capacity > 65536 || capacity != NGROUPS) return -1;
    *out = (unsigned)capacity; return 0;
}
static int scope_native_list(void *context, pid_t *pids, size_t capacity) {
    (void)context;
    if (capacity != SCOPE_PID_LIMIT || capacity * sizeof(pid_t) > INT_MAX) return -1;
    errno = 0; int estimate = proc_listallpids(NULL, 0); int estimate_error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_PID_ESTIMATE, estimate <= 0, estimate_error, estimate > 0 ? (size_t)estimate * sizeof(pid_t) : 0);
    if (estimate <= 0 || estimate >= (int)capacity) return -1;
    errno = 0; int count = proc_listallpids(pids, (int)(capacity * sizeof(pid_t))); int count_error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_PID_LIST, count <= 0, count_error, count > 0 ? (size_t)count * sizeof(pid_t) : 0);
    return count > 0 && count < (int)capacity ? count : -1;
}
static int scope_native_bsd(void *context, pid_t pid, ScopeCredentials *out) {
    (void)context; struct proc_bsdinfo info = {0};
    /* Nonzero argument requests complete credentials for live OR zombie PID.
     * Only exact zero bytes with freshly captured ESRCH invalidates the
     * entire round. Partial/unknown/permission results are never retried. */
    errno=0;int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info)); int error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_BSD, bytes <= 0, error, bytes > 0 ? (size_t)bytes : 0);
    if(bytes==0&&error==ESRCH)return 1;
    return scope_decode_bsd(&info, bytes, out);
}
static int scope_native_supplementary(void *context, pid_t pid, ScopeCredentials *out) {
    (void)context; int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info = {0}; size_t bytes = sizeof(info);
    errno=0;int status = sysctl(mib, 4, &info, &bytes, NULL, 0); int error = errno;
    scope_diag_native(ENVARA_SCOPE_QUERY_SUPPLEMENTARY, status, error, bytes);
    if(status==-1&&bytes==0&&error==ESRCH)return 1;
    return scope_decode_supplementary(&info, status, bytes, out);
}
int envara_app_scope_gid_absent(gid_t gid) {
    const ScopeReaders readers = {.context = NULL, .root = scope_native_root, .capacity = scope_native_capacity,
        .list = scope_native_list, .bsd = scope_native_bsd, .supplementary = scope_native_supplementary, .clock = scope_native_clock};
    return scope_gid_absent(gid, &readers);
}
