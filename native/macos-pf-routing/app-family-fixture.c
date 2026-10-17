#include "app-family.h"
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* A separately compiled failure fixture includes the unchanged implementation
 * after the real SDK declarations. These wrappers never enter a product build. */
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
#include <mach/mach.h>
#include <mach/task_info.h>
#include <bsm/libbsm.h>
static int fixture_deny_token, fixture_deny_signal, fixture_wrong_generation;
static int fixture_signal_calls, fixture_wrong_generation_refused;
static pid_t fixture_zombie_pid, fixture_inventory_parent;
static int fixture_zombie_token_calls, fixture_zombie_signal_calls, fixture_pidinfo_mode, fixture_churn;
static unsigned fixture_inventory_calls;
static int fixture_signal_error,fixture_metadata_error,fixture_force_running,fixture_stop_signals,fixture_esrch_mismatch;
static pid_t fixture_metadata_pid,fixture_esrch_pid;
enum { NAME_EXIT_ZOMBIE, NAME_EXIT_ABSENT, NAME_EXIT_BIRTH, NAME_EXIT_CREDENTIALS,
    NAME_EXIT_UNKNOWN, NAME_EXIT_SECOND_BIRTH, NAME_EXIT_SECOND_CREDENTIALS,
    NAME_EXIT_SECOND_UNKNOWN, NAME_EXIT_SECOND_LIVE, NAME_EXIT_LIVE };
static pid_t fixture_name_pid;
static int fixture_name_control=-1,fixture_name_mode,fixture_name_finished;
static int fixture_name_calls,fixture_name_reads;
static int *fixture_name_leader_reaped;
static struct envara_identity fixture_name_identity;
enum { REPARENT_STABLE, REPARENT_UNREGISTERED, REPARENT_LEADER, REPARENT_STORED_TOKEN,
    REPARENT_FIRST_TOKEN_FAILED, REPARENT_FIRST_TOKEN_SHORT, REPARENT_SECOND_TOKEN,
    REPARENT_SECOND_TOKEN_FAILED, REPARENT_SECOND_TOKEN_SHORT, REPARENT_SECOND_BIRTH,
    REPARENT_SECOND_CREDENTIALS, REPARENT_AFTER_BIRTH, REPARENT_AFTER_CREDENTIALS,
    REPARENT_SECOND_PPID, REPARENT_SECOND_UNKNOWN, REPARENT_AFTER_UNKNOWN, REPARENT_LINK_PPID,
    REPARENT_SECOND_NAME_FAILED, REPARENT_SECOND_INFO_INVALID };
static int fixture_reparent_mode,fixture_reparent_control=-1,fixture_reparent_done;
static int fixture_reparent_calls,fixture_reparent_reads,fixture_reparent_names;
static pid_t fixture_reparent_pid;
static struct envara_identity fixture_reparent_identity,fixture_reparent_parent;
enum { RECHECK_NAME_EXIT, RECHECK_INFO_EXIT, RECHECK_NAME_SUCCESS, RECHECK_INFO_SUCCESS,
    RECHECK_NAME_PERSISTENT, RECHECK_INFO_PERSISTENT, RECHECK_NAME_OTHER, RECHECK_INFO_OTHER,
    RECHECK_PID_INVALID, RECHECK_PID_FAILURE, RECHECK_SHORT, RECHECK_INVALID_SHORT,
    RECHECK_FIRST_PARENT, RECHECK_SECOND_BIRTH, RECHECK_SECOND_CREDENTIALS, RECHECK_SECOND_PARENT,
    RECHECK_SECOND_UNKNOWN, RECHECK_AFTER_BIRTH, RECHECK_AFTER_CREDENTIALS, RECHECK_AFTER_PARENT,
    RECHECK_SECOND_SHORT, RECHECK_NAME_THEN_INFO, RECHECK_INFO_THEN_NAME, RECHECK_INTERRUPTED,
    RECHECK_ZOMBIE_PARENT };
static pid_t fixture_recheck_pid;
static int fixture_recheck_mode, fixture_recheck_names, fixture_recheck_infos, fixture_recheck_reads;
static int fixture_recheck_sleeps, fixture_recheck_control, fixture_recheck_triggered;
static struct proc_bsdinfo fixture_recheck_original;
static pid_t fixture_terminal_pid;
static int fixture_terminal_parent_control, fixture_terminal_exit_control, fixture_terminal_changed;
static int fixture_terminal_info_exit;
enum { CAND_LIVE_ABSENT, CAND_ZOMBIE_ABSENT, CAND_NAME_ABSENT, CAND_SECOND_LIST_GAP,
    CAND_FIRST_ABSENT, CAND_FIRST_UNKNOWN, CAND_FIRST_SHORT, CAND_SECOND_BIRTH,
    CAND_SECOND_CREDENTIALS, CAND_SECOND_PARENT, CAND_POST_PARENT, CAND_PID_MISMATCH,
    CAND_SHORT_TOKEN, CAND_PARENT_ABSENT, CAND_PARENT_CHANGED, CAND_ZOMBIE_PARENT, CAND_CHURN };
static pid_t fixture_candidate_pid, fixture_candidate_parent;
static int fixture_candidate_mode, fixture_candidate_reads, fixture_candidate_lists, fixture_candidate_names;
static int fixture_candidate_infos, fixture_candidate_reaped, fixture_candidate_control, fixture_candidate_events;
enum { REAP_ABSENT, REAP_STRESS, REAP_FIRST_ABSENT, REAP_FIRST_UNKNOWN, REAP_FIRST_SHORT,
    REAP_FIRST_BIRTH, REAP_FIRST_CREDENTIALS, REAP_FIRST_PARENT, REAP_SECOND_UNKNOWN,
    REAP_SECOND_SHORT, REAP_SECOND_BIRTH, REAP_SECOND_CREDENTIALS, REAP_SECOND_PARENT,
    REAP_SECOND_LIVE, REAP_PARENT_ABSENT, REAP_PARENT_ZOMBIE, REAP_PARENT_BIRTH,
    REAP_PARENT_CREDENTIALS, REAP_PARENT_UNKNOWN, REAP_PARENT_SHORT, REAP_PARENT_TOKEN,
    REAP_PARENT_AFTER_BIRTH, REAP_PARENT_AFTER_CREDENTIALS, REAP_PRIOR_UNCERTAIN };
static pid_t fixture_reap_pid, fixture_reap_parent;
static int fixture_reap_mode, fixture_reap_reads, fixture_reap_parent_reads, fixture_reap_reaped, fixture_reap_lists;
static int fixture_reap_control, fixture_reap_events;
enum { RETIRE_UNKNOWN, RETIRE_NO_ERRNO, RETIRE_EAGAIN, RETIRE_SHORT, RETIRE_BIRTH, RETIRE_CREDENTIALS };
static pid_t fixture_retire_pid, fixture_alias_pid, fixture_alias_actual;
static int fixture_retire_mode;
struct fixture;
static struct fixture *fixture_swap_tree;
static pid_t fixture_swap_old, fixture_swap_new;
static int fixture_swap_triggered, fixture_swap_frozen, fixture_swap_kill_early;
static int fixture_swap_member(void);
static int fixture_known_reap_pidinfo(int pid,int flavor,uint64_t arg,void *buffer,int size);
static int fixture_candidate_reap(void);
static int fixture_terminal_reparent(void);
static int fixture_terminal_exit(void);
static kern_return_t fixture_recheck_info(task_t task, task_flavor_t flavor,
    task_info_t information, mach_msg_type_number_t *count);
static kern_return_t fixture_pid_for_task(mach_port_name_t task, int *pid);
static int fixture_refresh_nanosleep(const struct timespec *requested, struct timespec *remaining);
static kern_return_t fixture_reparent_after_token(task_info_t information,mach_msg_type_number_t *count,kern_return_t result);
static kern_return_t fixture_task_name_for_pid(mach_port_name_t task,pid_t pid,mach_port_name_t *name);
static kern_return_t fixture_task_info(task_name_t task, task_flavor_t flavor,
    task_info_t information, mach_msg_type_number_t *count);
static int fixture_signal_with_audittoken(audit_token_t *token, int signal_number);
static int fixture_proc_pidinfo(int pid,int flavor,uint64_t arg,void *buffer,int size);
static int fixture_proc_listchildpids(pid_t parent,void *buffer,int size);
#define task_name_for_pid fixture_task_name_for_pid
#define task_info fixture_task_info
#define pid_for_task fixture_pid_for_task
#define nanosleep fixture_refresh_nanosleep
#define proc_signal_with_audittoken fixture_signal_with_audittoken
#define proc_pidinfo fixture_proc_pidinfo
#define proc_listchildpids fixture_proc_listchildpids
#include "app-family.c"
#undef task_name_for_pid
#undef task_info
#undef pid_for_task
#undef nanosleep
#undef proc_signal_with_audittoken
#undef proc_pidinfo
#undef proc_listchildpids
static kern_return_t fixture_task_info(task_name_t task, task_flavor_t flavor,
    task_info_t information, mach_msg_type_number_t *count) {
    pid_t actual=0;
    if (flavor==TASK_AUDIT_TOKEN && fixture_reap_reaped && fixture_reap_mode==REAP_PARENT_TOKEN &&
        pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_reap_parent) return KERN_PROTECTION_FAILURE;
    if (flavor==TASK_AUDIT_TOKEN && fixture_candidate_pid>1 &&
        pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_candidate_pid) {
        fixture_candidate_infos++;
        kern_return_t result=task_info(task,flavor,information,count);
        if (fixture_candidate_mode==CAND_SHORT_TOKEN && result==KERN_SUCCESS) {
            *count=TASK_AUDIT_TOKEN_COUNT-1;
            if (!fixture_candidate_reap()) return KERN_FAILURE;
        }
        return result;
    }
    if (flavor==TASK_AUDIT_TOKEN && fixture_recheck_pid>1 &&
        pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_recheck_pid)
        return fixture_recheck_info(task,flavor,information,count);
    if (flavor==TASK_AUDIT_TOKEN && fixture_zombie_pid>1 && pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_zombie_pid)
        fixture_zombie_token_calls++;
    if (fixture_deny_token && flavor == TASK_AUDIT_TOKEN) return KERN_PROTECTION_FAILURE;
    kern_return_t result=task_info(task, flavor, information, count);
    if (flavor==TASK_AUDIT_TOKEN && fixture_terminal_info_exit && result==KERN_SUCCESS &&
        pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_terminal_pid)
        if (!fixture_terminal_exit()) return KERN_FAILURE;
    if (flavor==TASK_AUDIT_TOKEN && fixture_reparent_pid>1 &&
        pid_for_task(task,&actual)==KERN_SUCCESS && actual==fixture_reparent_pid)
        return fixture_reparent_after_token(information,count,result);
    return result;
}
static kern_return_t fixture_pid_for_task(mach_port_name_t task, int *pid) {
    kern_return_t result=pid_for_task(task,pid);
    if (result==KERN_SUCCESS && fixture_alias_pid>1 && *pid==fixture_alias_actual) *pid=fixture_alias_pid;
    if (result==KERN_SUCCESS && *pid==fixture_candidate_pid && fixture_candidate_mode==CAND_PID_MISMATCH) {
        if (!fixture_candidate_reap()) return KERN_FAILURE;
        (*pid)++;
    }
    if (result==KERN_SUCCESS && *pid==fixture_recheck_pid) {
        if (fixture_recheck_mode==RECHECK_PID_INVALID) return KERN_INVALID_ARGUMENT;
        if (fixture_recheck_mode==RECHECK_PID_FAILURE) return KERN_FAILURE;
    }
    return result;
}
static int fixture_refresh_nanosleep(const struct timespec *requested, struct timespec *remaining) {
    if (fixture_recheck_pid>1 && requested->tv_sec==0 && requested->tv_nsec==1000000) {
        fixture_recheck_sleeps++;
        if (fixture_recheck_mode==RECHECK_INTERRUPTED) {errno=EINTR;return -1;}
    }
    return nanosleep(requested,remaining);
}
static int fixture_signal_with_audittoken(audit_token_t *token, int signal_number) {
    fixture_signal_calls++;
    if (fixture_swap_tree && signal_number==SIGSTOP && audit_token_to_pid(*token)==fixture_swap_old && !fixture_swap_triggered) {
        if (!fixture_swap_member()) return EIO;
        return ESRCH; /* The real old generation has been reaped. */
    }
    if (fixture_swap_new>1 && audit_token_to_pid(*token)==fixture_swap_new) {
        if (signal_number==SIGKILL && !fixture_swap_frozen) {fixture_swap_kill_early=1;return EPERM;}
        if (signal_number==SIGSTOP) fixture_swap_frozen=1;
    }
    if (fixture_zombie_pid>1 && audit_token_to_pid(*token)==fixture_zombie_pid) fixture_zombie_signal_calls++;
    if (fixture_deny_signal) return EPERM;
    if (fixture_signal_error) return fixture_signal_error;
    if (fixture_esrch_mismatch) {fixture_esrch_pid=audit_token_to_pid(*token);return ESRCH;}
    if (fixture_wrong_generation) {
        audit_token_t incorrect = *token;
        incorrect.val[7] ^= 1;
        int result = proc_signal_with_audittoken(&incorrect, signal_number);
        fixture_wrong_generation_refused = result == ESRCH;
        return result;
    }
    int result=proc_signal_with_audittoken(token, signal_number);
    if (!result && signal_number==SIGSTOP) fixture_stop_signals++;
    return result;
}
static int fixture_proc_pidinfo(int pid,int flavor,uint64_t arg,void *buffer,int size) {
    if (flavor==PROC_PIDTBSDINFO && pid==fixture_retire_pid) {
        if (fixture_retire_mode<=RETIRE_EAGAIN) {
            errno=fixture_retire_mode==RETIRE_UNKNOWN?EACCES:fixture_retire_mode==RETIRE_EAGAIN?EAGAIN:0;return 0;
        }
        int count=proc_pidinfo(pid,flavor,arg,buffer,size);
        if (count==sizeof(struct proc_bsdinfo)) {
            struct proc_bsdinfo *info=buffer;
            if (fixture_retire_mode==RETIRE_SHORT) return count-1;
            if (fixture_retire_mode==RETIRE_BIRTH) info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
            if (fixture_retire_mode==RETIRE_CREDENTIALS) info->pbi_svuid++;
        }
        return count;
    }
    if (flavor==PROC_PIDTBSDINFO && fixture_alias_pid>1 && pid==fixture_alias_pid) {
        int count=proc_pidinfo(fixture_alias_actual,flavor,arg,buffer,size);
        if (count==sizeof(struct proc_bsdinfo)) ((struct proc_bsdinfo *)buffer)->pbi_pid=(uint32_t)pid;
        return count;
    }
    if (flavor==PROC_PIDTBSDINFO && fixture_reap_pid>1 &&
        fixture_reap_lists>0 &&
        (pid==fixture_reap_pid || (fixture_reap_reaped && pid==fixture_reap_parent)))
        return fixture_known_reap_pidinfo(pid,flavor,arg,buffer,size);
    int candidate_read=pid==fixture_candidate_pid && flavor==PROC_PIDTBSDINFO;
    if (candidate_read) {
        fixture_candidate_reads++;
        if (fixture_candidate_reads==1 && (fixture_candidate_mode==CAND_FIRST_ABSENT || fixture_candidate_mode==CAND_FIRST_UNKNOWN)) {
            errno=fixture_candidate_mode==CAND_FIRST_ABSENT?ESRCH:EACCES;return 0;
        }
        if (fixture_candidate_reads==2 && (fixture_candidate_mode==CAND_LIVE_ABSENT || fixture_candidate_mode==CAND_ZOMBIE_ABSENT ||
            fixture_candidate_mode==CAND_SECOND_LIST_GAP || fixture_candidate_mode==CAND_PARENT_ABSENT ||
            fixture_candidate_mode==CAND_PARENT_CHANGED || fixture_candidate_mode==CAND_CHURN))
            if (!fixture_candidate_reap()) {errno=EIO;return 0;}
    }
    if (pid==fixture_candidate_parent && flavor==PROC_PIDTBSDINFO && fixture_candidate_reaped && fixture_candidate_mode==CAND_PARENT_ABSENT) {
        errno=ESRCH;return 0;
    }
    int recheck_read=pid==fixture_recheck_pid && flavor==PROC_PIDTBSDINFO;
    if (recheck_read && ++fixture_recheck_reads==3 && fixture_recheck_mode==RECHECK_SECOND_UNKNOWN) {errno=EACCES;return 0;}
    int name_read=pid==fixture_name_pid && fixture_name_finished && flavor==PROC_PIDTBSDINFO;
    if (name_read) {
        fixture_name_reads++;
        if (fixture_name_mode==NAME_EXIT_UNKNOWN ||
            (fixture_name_mode==NAME_EXIT_SECOND_UNKNOWN && fixture_name_reads==2)) {errno=EACCES;return 0;}
    }
    int reparent_read=pid==fixture_reparent_pid && fixture_reparent_done && flavor==PROC_PIDTBSDINFO;
    if (reparent_read) {
        fixture_reparent_reads++;
        if ((fixture_reparent_mode==REPARENT_SECOND_UNKNOWN && fixture_reparent_reads==2) ||
            (fixture_reparent_mode==REPARENT_AFTER_UNKNOWN && fixture_reparent_reads==3)) {errno=EACCES;return 0;}
    }
    if (pid==fixture_metadata_pid && flavor==PROC_PIDTBSDINFO && fixture_metadata_error) {errno=fixture_metadata_error;return 0;}
    if (pid==fixture_zombie_pid && flavor==PROC_PIDTBSDINFO && fixture_pidinfo_mode==3) {errno=EACCES;return 0;}
    if (pid==fixture_zombie_pid && flavor==PROC_PIDTBSDINFO && fixture_pidinfo_mode==4) {errno=ESRCH;return 0;}
    int count=proc_pidinfo(pid,flavor,arg,buffer,size);
    if (pid==fixture_candidate_parent && flavor==PROC_PIDTBSDINFO && fixture_candidate_reaped &&
        fixture_candidate_mode==CAND_PARENT_CHANGED && count==sizeof(struct proc_bsdinfo))
        ((struct proc_bsdinfo *)buffer)->pbi_start_tvusec=(((struct proc_bsdinfo *)buffer)->pbi_start_tvusec+1)%1000000;
    if (candidate_read && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;int read=fixture_candidate_reads;
        if (read==1 && fixture_candidate_mode==CAND_FIRST_SHORT) return count-1;
        if (read==2 && fixture_candidate_mode==CAND_SECOND_BIRTH) info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
        if (read==2 && fixture_candidate_mode==CAND_SECOND_CREDENTIALS) info->pbi_svgid++;
        if ((read>=2 && fixture_candidate_mode==CAND_SECOND_PARENT) ||
            (read==3 && fixture_candidate_mode==CAND_POST_PARENT) ||
            (read==2 && fixture_candidate_mode==CAND_ZOMBIE_PARENT)) info->pbi_ppid=1;
    }
    if (pid==fixture_terminal_pid && flavor==PROC_PIDTBSDINFO && count==sizeof(struct proc_bsdinfo) &&
        ((struct proc_bsdinfo *)buffer)->pbi_status==SZOMB && !fixture_terminal_changed)
        if (!fixture_terminal_reparent()) {errno=EACCES;return 0;}
    if (recheck_read && fixture_recheck_reads==2 && fixture_recheck_triggered) {
        /* The task-gone/BSD-live window was measured against the real kernel.
         * Hold that first live observation deterministically; the next bracket
         * must inspect the fixture's real same-generation zombie twice. */
        memcpy(buffer,&fixture_recheck_original,sizeof(fixture_recheck_original));
        ((struct proc_bsdinfo *)buffer)->pbi_status=SRUN;
        count=sizeof(fixture_recheck_original);errno=0;
    }
    if (recheck_read && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;int read=fixture_recheck_reads;
        if ((read==3 && fixture_recheck_mode==RECHECK_SECOND_BIRTH) ||
            (read==4 && fixture_recheck_mode==RECHECK_AFTER_BIRTH)) info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
        if ((read==3 && fixture_recheck_mode==RECHECK_SECOND_CREDENTIALS) ||
            (read==4 && fixture_recheck_mode==RECHECK_AFTER_CREDENTIALS)) info->pbi_svuid++;
        if ((read==2 && fixture_recheck_mode==RECHECK_FIRST_PARENT) ||
            (read>=3 && (fixture_recheck_mode==RECHECK_SECOND_PARENT || fixture_recheck_mode==RECHECK_ZOMBIE_PARENT)) ||
            (read==4 && fixture_recheck_mode==RECHECK_AFTER_PARENT)) info->pbi_ppid=1;
    }
    if (reparent_read && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;
        if (fixture_reparent_mode==REPARENT_LEADER) info->pbi_ppid=1;
        if ((fixture_reparent_mode==REPARENT_SECOND_BIRTH && fixture_reparent_reads==2) ||
            (fixture_reparent_mode==REPARENT_AFTER_BIRTH && fixture_reparent_reads==3))
            info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
        if ((fixture_reparent_mode==REPARENT_SECOND_CREDENTIALS && fixture_reparent_reads==2) ||
            (fixture_reparent_mode==REPARENT_AFTER_CREDENTIALS && fixture_reparent_reads==3)) info->pbi_svuid++;
        if ((fixture_reparent_mode==REPARENT_SECOND_PPID && fixture_reparent_reads==3) ||
            (fixture_reparent_mode==REPARENT_LINK_PPID && fixture_reparent_reads==2))
            info->pbi_ppid=(uint32_t)fixture_reparent_parent.pid;
    }
    if (name_read && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;
        if (fixture_name_mode==NAME_EXIT_BIRTH ||
            (fixture_name_mode==NAME_EXIT_SECOND_BIRTH && fixture_name_reads==2))
            info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
        if (fixture_name_mode==NAME_EXIT_CREDENTIALS ||
            (fixture_name_mode==NAME_EXIT_SECOND_CREDENTIALS && fixture_name_reads==2)) info->pbi_uid++;
        if (fixture_name_mode==NAME_EXIT_SECOND_LIVE && fixture_name_reads==2) info->pbi_status=SRUN;
    }
    if (pid==fixture_zombie_pid && flavor==PROC_PIDTBSDINFO && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;
        if (fixture_pidinfo_mode==1) info->pbi_ppid=(uint32_t)getpid();
        else if (fixture_pidinfo_mode==2) info->pbi_uid++;
    }
    if (flavor==PROC_PIDTBSDINFO && count==sizeof(struct proc_bsdinfo)) {
        struct proc_bsdinfo *info=buffer;
        if (fixture_force_running && fixture_stop_signals>=3 && info->pbi_status==SSTOP) info->pbi_status=SRUN;
        if (fixture_esrch_pid>1 && pid==fixture_esrch_pid) {info->pbi_status=SZOMB;info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;}
    }
    return count;
}
static int fixture_proc_listchildpids(pid_t parent,void *buffer,int size) {
    int count=proc_listchildpids(parent,buffer,size);
    if (parent==fixture_reap_parent) fixture_reap_lists++;
    if (fixture_alias_pid>1 && count>0 && count<size/(int)sizeof(pid_t))
        for (int i=0;i<count;i++) if (((pid_t *)buffer)[i]==fixture_alias_actual) ((pid_t *)buffer)[i]=fixture_alias_pid;
    if (parent==fixture_candidate_parent) {
        fixture_candidate_lists++;
        if (fixture_candidate_mode==CAND_SECOND_LIST_GAP && fixture_candidate_lists==2 && count>=0 && count<size/(int)sizeof(pid_t))
            ((pid_t *)buffer)[count++]=fixture_candidate_pid;
        if (fixture_candidate_mode==CAND_CHURN && fixture_candidate_reaped && fixture_candidate_lists%2==0) return 0;
    }
    if (fixture_churn && parent==fixture_inventory_parent && count>0 && (++fixture_inventory_calls%2)==0) return 0;
    return count;
}
#endif

/* Unprivileged, disposable process trees only. The lifeline writer belongs to
 * this fixture alone, so an assertion failure or timeout also makes every
 * surviving fixture process exit. No installed application or PF is used. */
enum { EVENT_CHILD = 1, EVENT_GRANDCHILD, EVENT_DETACHED, EVENT_ZOMBIE, EVENT_ZOMBIE_REAPED, EVENT_CANDIDATE,
    EVENT_BULK, EVENT_BULK_REAPED, EVENT_CHILD_REAPED };
struct fixture_event {
    unsigned kind;
    struct envara_identity identity;
    int detached, verified;
};
struct fixture {
    int lifeline[2], events[2], control[2], detach[2], sibling[2], orphan[2];
    pid_t leader_pid, sibling_pid;
    int leader_reaped, sibling_reaped;
    struct envara_identity leader, child, grandchild, unrelated, zombie;
    struct envara_identity bulk[256];
    unsigned bulk_count;
};

static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static void pause_briefly(void) {
    struct timespec duration = { .tv_nsec = 10000000 };
    while (nanosleep(&duration, &duration) && errno == EINTR) {}
}
static int exact_io(int fd, void *bytes, size_t length, int writing, int timeout) {
    size_t offset = 0;
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    while (offset < length) {
        uint64_t now = milliseconds();
        if (now >= deadline) return 0;
        struct pollfd waiting = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
        int ready = poll(&waiting, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (waiting.revents & (POLLERR | POLLNVAL))) return 0;
        ssize_t count = writing ? write(fd, (char *)bytes + offset, length - offset) :
            read(fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}
static int command(int fd, char byte) { return exact_io(fd, &byte, 1, 1, 1000); }
static int identity_state(const struct envara_identity *identity) {
    struct proc_bsdinfo now;
    memset(&now, 0, sizeof(now));
    errno = 0;
    int count = proc_pidinfo(identity->pid, PROC_PIDTBSDINFO, 1, &now, sizeof(now));
    if (!count && errno == ESRCH) return 0;
    if (count != sizeof(now) || now.pbi_pid != (uint32_t)identity->pid ||
        !now.pbi_start_tvsec || now.pbi_status < SIDL || now.pbi_status > SZOMB) return -1;
    if (now.pbi_start_tvsec != identity->birth_seconds || now.pbi_start_tvusec != identity->birth_microseconds) return 0;
    return now.pbi_status == SZOMB ? 2 : 1;
}
static int live_identity(const struct envara_identity *identity) { return identity_state(identity) == 1; }
static int wait_exited(const struct envara_identity *identity, int timeout) {
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    int state;
    while ((state = identity_state(identity)) == 1 && milliseconds() < deadline) pause_briefly();
    return state == 0 || state == 2;
}
static int reap_direct(pid_t pid, int *reaped, int timeout, int *signal_number) {
    if (*reaped) return 1;
    uint64_t deadline = milliseconds() + (unsigned)timeout;
    do {
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            *reaped = 1;
            if (signal_number) *signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
            return 1;
        }
        if (result < 0 && errno != EINTR) return 0;
        pause_briefly();
    } while (milliseconds() < deadline);
    return 0;
}
static void announce(int fd, unsigned kind, int detached) {
    struct fixture_event event = { .kind = kind, .detached = detached };
    if (envara_identity_read(getpid(), &event.identity) ||
        !exact_io(fd, &event, sizeof(event), 1, 1000)) _exit(71);
}
static int persistent_loop(int lifeline, int control, int event_fd, int is_grandchild) {
    /* Deadline is a last resort for a broken fixture, never its exit evidence. */
    uint64_t deadline = milliseconds() + 12000;
    while (milliseconds() < deadline) {
        struct pollfd descriptors[2] = {
            { .fd = lifeline, .events = POLLIN }, { .fd = control, .events = POLLIN }
        };
        int ready = poll(descriptors, 2, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || descriptors[0].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (descriptors[0].revents & POLLIN) {
            char byte;
            if (read(lifeline, &byte, 1) <= 0) break;
        }
        if (control >= 0 && descriptors[1].revents & POLLIN) {
            char byte;
            if (read(control, &byte, 1) != 1) continue;
            if (is_grandchild && byte == 'D') {
                int detached = setsid() == getpid();
                announce(event_fd, EVENT_DETACHED, detached);
            } else if (byte == 'X') return 1;
            else if (!is_grandchild && byte == 'P') {
                if (!command(control, 'P')) break;
            }
        }
    }
    return 0;
}
static int read_zombie(pid_t pid,struct envara_identity *identity) {
    struct proc_bsdinfo info={0};
    if (proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&info,sizeof(info))!=sizeof(info) || info.pbi_status!=SZOMB ||
        info.pbi_pid!=(uint32_t)pid || !info.pbi_start_tvsec) return 0;
    *identity=(struct envara_identity){.pid=pid,.parent_pid=(pid_t)info.pbi_ppid,
        .uid=info.pbi_uid,.ruid=info.pbi_ruid,.saved_uid=info.pbi_svuid,.gid=info.pbi_gid,.rgid=info.pbi_rgid,
        .saved_gid=info.pbi_svgid,.birth_seconds=info.pbi_start_tvsec,.birth_microseconds=info.pbi_start_tvusec};
    return 1;
}
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
/* The real intermediate parent exits only after the first token was read.
 * The known grandchild survives and is observed reparented to launchd. */
static kern_return_t fixture_reparent_after_token(task_info_t information,mach_msg_type_number_t *count,kern_return_t result) {
    fixture_reparent_calls++;
    if (result!=KERN_SUCCESS || *count!=TASK_AUDIT_TOKEN_COUNT) return result;
    if (fixture_reparent_calls==1) {
        if (fixture_reparent_mode==REPARENT_LEADER) fixture_reparent_done=1;
        else {
            if (!command(fixture_reparent_control,'X')) return KERN_FAILURE;
            uint64_t until=milliseconds()+1000;
            do {
                struct envara_identity child,parent;
                if (!envara_identity_read(fixture_reparent_pid,&child) && child.parent_pid==1 &&
                    family_same(&child,&fixture_reparent_identity) &&
                    read_zombie(fixture_reparent_parent.pid,&parent) && family_same(&parent,&fixture_reparent_parent)) {
                    fixture_reparent_done=1;break;
                }
                pause_briefly();
            } while (milliseconds()<until);
        }
        if (!fixture_reparent_done || fixture_reparent_mode==REPARENT_FIRST_TOKEN_FAILED) return KERN_PROTECTION_FAILURE;
        if (fixture_reparent_mode==REPARENT_FIRST_TOKEN_SHORT) *count=TASK_AUDIT_TOKEN_COUNT-1;
    } else if (fixture_reparent_calls==2) {
        if (fixture_reparent_mode==REPARENT_SECOND_INFO_INVALID) return KERN_INVALID_ARGUMENT;
        if (fixture_reparent_mode==REPARENT_SECOND_TOKEN_FAILED) return KERN_PROTECTION_FAILURE;
        if (fixture_reparent_mode==REPARENT_SECOND_TOKEN_SHORT) *count=TASK_AUDIT_TOKEN_COUNT-1;
        if (fixture_reparent_mode==REPARENT_SECOND_TOKEN) ((audit_token_t *)information)->val[7]^=1;
    }
    return result;
}
static int fixture_recheck_exit(void) {
    if (!command(fixture_recheck_control,'X')) return 0;
    uint64_t until=milliseconds()+1000;
    do {
        struct envara_identity actual;
        if (read_zombie(fixture_recheck_pid,&actual) && actual.parent_pid==(pid_t)fixture_recheck_original.pbi_ppid &&
            actual.birth_seconds==fixture_recheck_original.pbi_start_tvsec &&
            actual.birth_microseconds==fixture_recheck_original.pbi_start_tvusec) {
            fixture_recheck_triggered=1;return 1;
        }
        pause_briefly();
    } while (milliseconds()<until);
    return 0;
}
static int fixture_terminal_exit(void) {
    if (!command(fixture_terminal_exit_control,'X')) return 0;
    uint64_t until=milliseconds()+1000;
    do {
        struct envara_identity actual;
        if (read_zombie(fixture_terminal_pid,&actual)) return 1;
        pause_briefly();
    } while (milliseconds()<until);
    return 0;
}
static int fixture_terminal_reparent(void) {
    if (!command(fixture_terminal_parent_control,'X')) return 0;
    uint64_t until=milliseconds()+1000;
    do {
        struct proc_bsdinfo actual;errno=0;
        int count=proc_pidinfo(fixture_terminal_pid,PROC_PIDTBSDINFO,1,&actual,sizeof(actual));
        if ((!count && errno==ESRCH) || (count==sizeof(actual) && actual.pbi_ppid==1)) {
            fixture_terminal_changed=1;return 1;
        }
        pause_briefly();
    } while (milliseconds()<until);
    return 0;
}
static int fixture_candidate_reap(void) {
    if (fixture_candidate_reaped) return 1;
    struct fixture_event event;
    if (!command(fixture_candidate_control,'R') ||
        !exact_io(fixture_candidate_events,&event,sizeof(event),0,1000) ||
        event.kind!=EVENT_ZOMBIE_REAPED || !event.verified) return 0;
    struct proc_bsdinfo actual;errno=0;
    if (proc_pidinfo(fixture_candidate_pid,PROC_PIDTBSDINFO,1,&actual,sizeof(actual))!=0 || errno!=ESRCH) return 0;
    fixture_candidate_reaped=1;return 1;
}
/* Order a real reap between the known child's first zombie read and its
 * confirmation. The positive/stress cases never forge native identity data. */
static int fixture_known_reap_pidinfo(int pid,int flavor,uint64_t arg,void *buffer,int size) {
    int mode=fixture_reap_mode, child=pid==fixture_reap_pid;
    int read=child?++fixture_reap_reads:++fixture_reap_parent_reads;
    int reap=child && ((read==1 && mode==REAP_FIRST_ABSENT) ||
        (read==2 && (mode==REAP_ABSENT || mode==REAP_STRESS || mode>=REAP_PARENT_ABSENT)));
    if (reap) {
        struct fixture_event event;
        if (!command(fixture_reap_control,'R') || !exact_io(fixture_reap_events,&event,sizeof(event),0,1000) ||
            event.kind!=EVENT_ZOMBIE_REAPED || !event.verified) {errno=EIO;return 0;}
        struct proc_bsdinfo actual;errno=0;
        if (proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&actual,sizeof(actual))!=0 || errno!=ESRCH) {errno=EIO;return 0;}
        fixture_reap_reaped=1;
    }
    if ((child && ((read==1 && mode==REAP_FIRST_UNKNOWN) || (read==2 && mode==REAP_SECOND_UNKNOWN))) ||
        (!child && mode==REAP_PARENT_UNKNOWN)) {errno=EACCES;return 0;}
    if (!child && mode==REAP_PARENT_ABSENT) {errno=ESRCH;return 0;}
    int count=proc_pidinfo(pid,flavor,arg,buffer,size);
    if (count!=sizeof(struct proc_bsdinfo)) return count;
    struct proc_bsdinfo *info=buffer;
    if ((child && ((read==1 && mode==REAP_FIRST_SHORT) || (read==2 && mode==REAP_SECOND_SHORT))) ||
        (!child && mode==REAP_PARENT_SHORT)) return count-1;
    if ((child && ((read==1 && mode==REAP_FIRST_BIRTH) || (read==2 && mode==REAP_SECOND_BIRTH))) ||
        (!child && (mode==REAP_PARENT_BIRTH || (read==2 && mode==REAP_PARENT_AFTER_BIRTH))))
        info->pbi_start_tvusec=(info->pbi_start_tvusec+1)%1000000;
    if ((child && ((read==1 && mode==REAP_FIRST_CREDENTIALS) || (read==2 && mode==REAP_SECOND_CREDENTIALS))) ||
        (!child && (mode==REAP_PARENT_CREDENTIALS || (read==2 && mode==REAP_PARENT_AFTER_CREDENTIALS)))) info->pbi_svuid++;
    if (child && ((read==1 && mode==REAP_FIRST_PARENT) || (read==2 && mode==REAP_SECOND_PARENT))) info->pbi_ppid=1;
    if (child && read==2 && mode==REAP_SECOND_LIVE) info->pbi_status=SRUN;
    if (!child && mode==REAP_PARENT_ZOMBIE) info->pbi_status=SZOMB;
    return count;
}
static kern_return_t fixture_recheck_info(task_t task, task_flavor_t flavor,
    task_info_t information, mach_msg_type_number_t *count) {
    fixture_recheck_infos++;
    kern_return_t result=task_info(task,flavor,information,count);
    if (result!=KERN_SUCCESS) return result;
    int mode=fixture_recheck_mode;
    if (mode==RECHECK_INFO_EXIT && fixture_recheck_infos==1) {
        (void)fixture_recheck_exit();return KERN_INVALID_ARGUMENT;
    }
    if (mode==RECHECK_SHORT || mode==RECHECK_INVALID_SHORT || mode==RECHECK_SECOND_SHORT) {
        *count=TASK_AUDIT_TOKEN_COUNT-1;
        return mode==RECHECK_INVALID_SHORT?KERN_INVALID_ARGUMENT:result;
    }
    if (mode==RECHECK_INFO_OTHER) return KERN_PROTECTION_FAILURE;
    if (mode==RECHECK_INFO_PERSISTENT || mode==RECHECK_NAME_THEN_INFO ||
        ((mode==RECHECK_INFO_SUCCESS || mode==RECHECK_INFO_THEN_NAME) && fixture_recheck_infos==1))
        return KERN_INVALID_ARGUMENT;
    return result;
}
/* Exit occurs inside the failed task lookup, after product BSD inspection.
 * These commands affect only this fixture's already-recorded process tree. */
static kern_return_t fixture_task_name_for_pid(mach_port_name_t task,pid_t pid,mach_port_name_t *name) {
    if (fixture_alias_pid>1 && pid==fixture_alias_pid) return task_name_for_pid(task,fixture_alias_actual,name);
    if (pid==fixture_candidate_pid) {
        fixture_candidate_names++;
        if (fixture_candidate_mode==CAND_NAME_ABSENT) {
            *name=MACH_PORT_NULL;(void)fixture_candidate_reap();return KERN_FAILURE;
        }
        if (fixture_candidate_mode==CAND_POST_PARENT) {*name=MACH_PORT_NULL;return KERN_FAILURE;}
    }
    if (pid==fixture_reparent_pid) {
        fixture_reparent_names++;
        if (fixture_reparent_done && fixture_reparent_mode==REPARENT_SECOND_NAME_FAILED) return KERN_FAILURE;
    }
    if (pid==fixture_recheck_pid) {
        fixture_recheck_names++;int mode=fixture_recheck_mode;
        if (mode==RECHECK_NAME_OTHER) return KERN_PROTECTION_FAILURE;
        int info_first=mode==RECHECK_INFO_EXIT || mode==RECHECK_INFO_SUCCESS || mode==RECHECK_INFO_PERSISTENT ||
            mode==RECHECK_INFO_OTHER || mode==RECHECK_PID_INVALID || mode==RECHECK_PID_FAILURE ||
            mode==RECHECK_SHORT || mode==RECHECK_INVALID_SHORT || mode==RECHECK_INFO_THEN_NAME;
        if ((!info_first && fixture_recheck_names==1) || mode==RECHECK_NAME_PERSISTENT ||
            (mode==RECHECK_INFO_THEN_NAME && fixture_recheck_names==2)) {
            *name=MACH_PORT_NULL;
            if (mode==RECHECK_NAME_EXIT || mode==RECHECK_ZOMBIE_PARENT) (void)fixture_recheck_exit();
            return KERN_FAILURE;
        }
        return task_name_for_pid(task,pid,name);
    }
    if (pid!=fixture_name_pid) return task_name_for_pid(task,pid,name);
    fixture_name_calls++;
    *name=MACH_PORT_NULL;
    if (fixture_name_mode==NAME_EXIT_LIVE) {fixture_name_finished=1;return KERN_FAILURE;}
    if (fixture_name_calls!=1 || !command(fixture_name_control,'X')) return KERN_FAILURE;
    if (fixture_name_mode==NAME_EXIT_ABSENT) {
        int signal_number=0;
        if (fixture_name_leader_reaped && reap_direct(pid,fixture_name_leader_reaped,1000,&signal_number) && !signal_number)
            fixture_name_finished=1;
    } else {
        uint64_t until=milliseconds()+1000;
        do {
            struct envara_identity actual;
            if (read_zombie(pid,&actual) && actual.parent_pid==fixture_name_identity.parent_pid &&
                family_same(&actual,&fixture_name_identity)) {fixture_name_finished=1;break;}
            pause_briefly();
        } while (milliseconds()<until);
    }
    return KERN_FAILURE;
}
#endif
static void leader_loop(int lifeline,int control,int events,pid_t child) {
    pid_t zombie=-1; int orphan_children=0, candidate_release=-1;
    pid_t bulk[256];unsigned bulk_count=0;
    uint64_t deadline=milliseconds()+12000;
    while (milliseconds()<deadline) {
        struct pollfd items[]={{.fd=lifeline,.events=POLLIN},{.fd=control,.events=POLLIN}};
        if (poll(items,2,100)<=0) continue;
        if ((items[0].revents|items[1].revents)&(POLLHUP|POLLERR|POLLNVAL)) break;
        if (!(items[1].revents&POLLIN)) continue;
        char byte; if (read(control,&byte,1)!=1) break;
        if (byte=='X') {orphan_children=1;break;}
        if (byte=='M') {
            if (bulk_count>=256) break;
            pid_t added=fork();if (added<0) break;
            if (!added) {announce(events,EVENT_BULK,0);persistent_loop(lifeline,-1,-1,0);_exit(0);}
            bulk[bulk_count++]=added;
        } else if (byte=='Q') {
            struct fixture_event event={.kind=EVENT_BULK_REAPED,.verified=1};
            for (unsigned i=0;i<bulk_count;i++) {
                int status=0;pid_t got;
                if (kill(bulk[i],SIGTERM)) event.verified=0;
                do {got=waitpid(bulk[i],&status,0);} while (got<0 && errno==EINTR);
                if (got!=bulk[i] || !WIFSIGNALED(status) || WTERMSIG(status)!=SIGTERM) event.verified=0;
            }
            bulk_count=0;
            if (!exact_io(events,&event,sizeof(event),1,1000)) break;
        } else if (byte=='C') {
            int status=0;pid_t got;
            do {got=waitpid(child,&status,0);} while (got<0 && errno==EINTR);
            struct fixture_event event={.kind=EVENT_CHILD_REAPED,
                .verified=got==child && WIFEXITED(status) && !WEXITSTATUS(status)};
            if (got==child) child=-1;
            if (!exact_io(events,&event,sizeof(event),1,1000)) break;
        } else if (byte=='Z' || byte=='N') {
            int holding[2]={-1,-1};
            if (byte=='N' && pipe(holding)) _exit(74);
            zombie=fork(); if (zombie<0) _exit(74);
            if (!zombie) {
                if (byte=='N') {
                    close(holding[1]);char release;
                    while (read(holding[0],&release,1)<0 && errno==EINTR) {}
                    close(holding[0]);
                }
                _exit(23);
            }
            if (byte=='N') {close(holding[0]);candidate_release=holding[1];}
            struct fixture_event event={.kind=byte=='N'?EVENT_CANDIDATE:EVENT_ZOMBIE};
            uint64_t until=milliseconds()+1000;
            do {
                if (byte=='N'?!envara_identity_read(zombie,&event.identity):read_zombie(zombie,&event.identity)) {event.verified=1;break;}
                pause_briefly();
            } while (milliseconds()<until);
            if (!exact_io(events,&event,sizeof(event),1,1000)) break;
        } else if (byte=='E') {
            if (candidate_release>=0) {(void)write(candidate_release,"E",1);close(candidate_release);candidate_release=-1;}
            struct fixture_event event={.kind=EVENT_ZOMBIE};
            uint64_t until=milliseconds()+1000;
            do {
                if (read_zombie(zombie,&event.identity)) {event.verified=1;break;}
                pause_briefly();
            } while (milliseconds()<until);
            if (!exact_io(events,&event,sizeof(event),1,1000)) break;
        } else if (byte=='R') {
            if (candidate_release>=0) {(void)write(candidate_release,"R",1);close(candidate_release);candidate_release=-1;}
            int status=0;pid_t result;
            do {result=waitpid(zombie,&status,0);} while (result<0 && errno==EINTR);
            struct fixture_event event={.kind=EVENT_ZOMBIE_REAPED,
                .verified=result==zombie && WIFEXITED(status) && WEXITSTATUS(status)==23};
            if (result==zombie) zombie=-1;
            if (!exact_io(events,&event,sizeof(event),1,1000)) break;
        }
    }
    if (candidate_release>=0) close(candidate_release);
    if (!orphan_children && child>1) while (waitpid(child,NULL,0)<0 && errno==EINTR) {}
    if (zombie>1) while (waitpid(zombie,NULL,0)<0 && errno==EINTR) {}
    for (unsigned i=0;i<bulk_count;i++) while (waitpid(bulk[i],NULL,0)<0 && errno==EINTR) {}
}
static int create_tree(struct fixture *f) {
    memset(f, 0, sizeof(*f));
    int *descriptors[] = { f->lifeline, f->events, f->control, f->detach, f->sibling, f->orphan };
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); i++)
        descriptors[i][0] = descriptors[i][1] = -1;
    if (pipe(f->lifeline) || pipe(f->events) || pipe(f->detach) || pipe(f->orphan) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, f->control) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, f->sibling)) return 0;
    f->leader_pid = fork();
    if (f->leader_pid < 0) return 0;
    if (!f->leader_pid) {
        close(f->lifeline[1]); close(f->events[0]); close(f->detach[1]); close(f->orphan[1]);
        close(f->control[0]); close(f->sibling[0]); close(f->sibling[1]);
        pid_t child = fork();
        if (child < 0) _exit(72);
        if (!child) {
            close(f->control[1]);
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(73);
            if (!grandchild) {
                close(f->orphan[0]);
                announce(f->events[1], EVENT_GRANDCHILD, 0);
                persistent_loop(f->lifeline[0], f->detach[0], f->events[1], 1);
                _exit(0);
            }
            close(f->detach[0]);
            announce(f->events[1], EVENT_CHILD, 0);
            /* Only the private X command requests an actual orphan transition. */
            int orphan=persistent_loop(f->lifeline[0], f->orphan[0], -1, 0);
            if (!orphan) while (waitpid(grandchild, NULL, 0) < 0 && errno == EINTR) {}
            _exit(0);
        }
        close(f->detach[0]); close(f->orphan[0]);
        leader_loop(f->lifeline[0],f->control[1],f->events[1],child);
        _exit(0);
    }
    f->sibling_pid = fork();
    if (f->sibling_pid < 0) return 0;
    if (!f->sibling_pid) {
        close(f->lifeline[1]); close(f->events[0]); close(f->events[1]);
        close(f->detach[0]); close(f->detach[1]); close(f->control[0]); close(f->control[1]);
        close(f->sibling[0]); close(f->orphan[0]); close(f->orphan[1]);
        persistent_loop(f->lifeline[0], f->sibling[1], -1, 0);
        _exit(0);
    }
    close(f->lifeline[0]); f->lifeline[0] = -1;
    close(f->events[1]); f->events[1] = -1;
    close(f->detach[0]); f->detach[0] = -1;
    close(f->orphan[0]); f->orphan[0] = -1;
    close(f->control[1]); f->control[1] = -1;
    close(f->sibling[1]); f->sibling[1] = -1;
    for (unsigned i = 0; i < 2; i++) {
        struct fixture_event event;
        if (!exact_io(f->events[0], &event, sizeof(event), 0, 1500)) return 0;
        if (event.kind == EVENT_CHILD) f->child = event.identity;
        else if (event.kind == EVENT_GRANDCHILD) f->grandchild = event.identity;
        else return 0;
    }
    return f->child.pid > 1 && f->grandchild.pid > 1 &&
        !envara_identity_read(f->leader_pid, &f->leader) &&
        !envara_identity_read(f->sibling_pid, &f->unrelated) &&
        f->leader.parent_pid == getpid() && f->child.parent_pid == f->leader_pid &&
        f->grandchild.parent_pid == f->child.pid &&
        envara_identity_matches(&f->leader, getuid(), getgid()) &&
        envara_identity_matches(&f->unrelated, getuid(), getgid());
}
static int sibling_alive(struct fixture *f) {
    char response = 0;
    return live_identity(&f->unrelated) && command(f->sibling[0], 'P') &&
        exact_io(f->sibling[0], &response, 1, 0, 1000) && response == 'P';
}
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
static int stable_children(struct fixture *f,int has_zombie) {
    pid_t first[4]={0},second[4]={0};
    int count=has_zombie?2:1;
    if (proc_listchildpids(f->leader_pid,first,sizeof(first))!=count ||
        proc_listchildpids(f->leader_pid,second,sizeof(second))!=count) return 0;
    if (count==2) {
        if (first[0]>first[1]) {pid_t value=first[0];first[0]=first[1];first[1]=value;}
        if (second[0]>second[1]) {pid_t value=second[0];second[0]=second[1];second[1]=value;}
        return !memcmp(first,second,2*sizeof(pid_t)) &&
            ((first[0]==f->child.pid && first[1]==f->zombie.pid) || (first[1]==f->child.pid && first[0]==f->zombie.pid));
    }
    return first[0]==f->child.pid && second[0]==f->child.pid;
}
static int make_zombie(struct fixture *f) {
    struct fixture_event event;struct envara_identity actual;
    if (!command(f->control[0],'Z') || !exact_io(f->events[0],&event,sizeof(event),0,1500) ||
        event.kind!=EVENT_ZOMBIE || !event.verified || !read_zombie(event.identity.pid,&actual) ||
        actual.parent_pid!=f->leader_pid || actual.birth_seconds!=event.identity.birth_seconds ||
        actual.birth_microseconds!=event.identity.birth_microseconds || !envara_identity_matches(&actual,getuid(),getgid())) return 0;
    f->zombie=actual;
    fixture_zombie_pid=actual.pid;
    return stable_children(f,1);
}
static int make_live_candidate(struct fixture *f) {
    struct fixture_event event;struct envara_identity actual;
    if (!command(f->control[0],'N') || !exact_io(f->events[0],&event,sizeof(event),0,1500) ||
        event.kind!=EVENT_CANDIDATE || !event.verified || envara_identity_read(event.identity.pid,&actual) ||
        actual.parent_pid!=f->leader_pid || !family_same(&actual,&event.identity) ||
        !envara_identity_matches(&actual,getuid(),getgid())) return 0;
    f->zombie=actual;return stable_children(f,1);
}
static int reap_candidate(struct fixture *f) {
    struct fixture_event event;struct proc_bsdinfo actual;errno=0;
    return command(f->control[0],'R') && exact_io(f->events[0],&event,sizeof(event),0,1500) &&
        event.kind==EVENT_ZOMBIE_REAPED && event.verified &&
        proc_pidinfo(f->zombie.pid,PROC_PIDTBSDINFO,1,&actual,sizeof(actual))==0 && errno==ESRCH;
}
static int make_bulk_child(struct fixture *f) {
    struct fixture_event event;
    if (f->bulk_count>=256 || !command(f->control[0],'M') ||
        !exact_io(f->events[0],&event,sizeof(event),0,1500) || event.kind!=EVENT_BULK ||
        event.identity.parent_pid!=f->leader.pid || !live_identity(&event.identity)) return 0;
    f->bulk[f->bulk_count++]=event.identity;return 1;
}
static int fixture_swap_member(void) {
    if (!fixture_swap_tree || !reap_candidate(fixture_swap_tree) || !make_live_candidate(fixture_swap_tree)) return 0;
    fixture_swap_new=fixture_swap_tree->zombie.pid;fixture_swap_triggered=1;return 1;
}
#endif
static int cleanup(struct fixture *f) {
    int okay = 1;
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
    /* A timeout case deliberately leaves owned members stopped. Resume only
     * these recorded exact generations before the shared lifeline cleanup. */
    const struct envara_identity *members[]={&f->leader,&f->child,&f->grandchild};
    if (fixture_stop_signals) for (unsigned i=0;i<3;i++) {
        struct proc_bsdinfo info={0};const struct envara_identity *member=members[i];
        if (member->pid<=1 || proc_pidinfo(member->pid,PROC_PIDTBSDINFO,1,&info,sizeof(info))!=sizeof(info) || info.pbi_status!=SSTOP) continue;
        mach_port_t name=MACH_PORT_NULL;audit_token_t token;mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
        int verified=envara_same_process(member) && task_name_for_pid(mach_task_self(),member->pid,&name)==KERN_SUCCESS;
        if (verified) verified=task_info(name,TASK_AUDIT_TOKEN,(task_info_t)&token,&count)==KERN_SUCCESS &&
            count==TASK_AUDIT_TOKEN_COUNT && audit_token_to_pid(token)==member->pid && envara_same_process(member);
        if (name!=MACH_PORT_NULL) mach_port_deallocate(mach_task_self(),name);
        if (!verified || proc_signal_with_audittoken(&token,SIGCONT)) okay=0;
    }
#endif
    if (f->lifeline[1] >= 0) { close(f->lifeline[1]); f->lifeline[1] = -1; }
    if (f->leader_pid > 1) okay &= reap_direct(f->leader_pid, &f->leader_reaped, 2000, NULL);
    if (f->sibling_pid > 1) okay &= reap_direct(f->sibling_pid, &f->sibling_reaped, 2000, NULL);
    if (f->child.pid > 1) okay &= wait_exited(&f->child, 2000);
    if (f->grandchild.pid > 1) okay &= wait_exited(&f->grandchild, 2000);
    if (f->zombie.pid > 1) okay &= wait_exited(&f->zombie, 2000);
    for (unsigned i=0;i<f->bulk_count;i++) okay &= wait_exited(&f->bulk[i],2000);
    int *descriptors[] = { f->lifeline, f->events, f->control, f->detach, f->sibling, f->orphan };
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); i++)
        for (unsigned j = 0; j < 2; j++) if (descriptors[i][j] >= 0) close(descriptors[i][j]);
    return okay;
}
#define REQUIRE(condition) do { if (!(condition)) { \
    fprintf(stderr, "fixture check failed at line %d\n", __LINE__); okay = 0; goto finished; \
} } while (0)

int main(int argc, char **argv) {
    if (getuid() == 0 || getuid() != geteuid() || getgid() != getegid() || argc != 2) return 64;
    signal(SIGPIPE, SIG_IGN);
    struct fixture f;
    envara_app_family *family = NULL;
    int okay = 1, leader_signal_sent = 0, signal_number = 0;
    int detached = 0, natural_exit = 0, refused = 0, repeat_stop = 0;
    int failure_closed = 0, wrong_generation_refused = 0;
    int family_stopped=0,stable_zombie=0,zombie_reaped=0,zombie_untouched=0,true_churn_retained=0;
    int typed_retry_succeeded=0,first_failure_preserved=0;
    unsigned known_reap_transitions=0;
    REQUIRE(create_tree(&f));
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
    if (!strncmp(argv[1],"retire-",7)) {
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        if (!strcmp(argv[1],"retire-sequential")) {
            for (unsigned i=0;i<320;i++) {
                REQUIRE(make_live_candidate(&f) && envara_app_family_observe(family) && family->count==4);
                REQUIRE(reap_candidate(&f) && envara_app_family_observe(family) && family->count==3);
                REQUIRE(family_find(family,f.zombie.pid)<0 && !family->uncertain);
                known_reap_transitions++;
            }
        } else if (!strcmp(argv[1],"retire-capacity")) {
            for (unsigned i=0;i<253;i++) REQUIRE(make_bulk_child(&f));
            REQUIRE(envara_app_family_observe(family) && family->count==ENVARA_APP_FAMILY_LIMIT);
            REQUIRE(make_bulk_child(&f) && !envara_app_family_observe(family));
            REQUIRE(family->failure.reason==ENVARA_APP_FAMILY_FAILURE_CAPACITY && family->failure.os_error==EOVERFLOW);
            goto retirement_refused;
        } else if (!strcmp(argv[1],"retire-adjacent")) {
            for (unsigned i=0;i<3;i++) REQUIRE(make_bulk_child(&f));
            REQUIRE(envara_app_family_observe(family) && family->count==6);
            struct fixture_event event;
            REQUIRE(command(f.control[0],'Q') && exact_io(f.events[0],&event,sizeof(event),0,1500) &&
                event.kind==EVENT_BULK_REAPED && event.verified);
            REQUIRE(envara_app_family_observe(family) && family->count==3);
            for (unsigned i=0;i<3;i++) REQUIRE(family_find(family,f.bulk[i].pid)<0);
        } else if (!strcmp(argv[1],"retire-parent")) {
            int index=family_find(family,f.grandchild.pid);REQUIRE(index>0);
            audit_token_t saved=family->members[index].token;
            REQUIRE(command(f.orphan[1],'X') && wait_exited(&f.child,1000));
            struct fixture_event event;struct proc_bsdinfo absent;errno=0;
            REQUIRE(command(f.control[0],'C') && exact_io(f.events[0],&event,sizeof(event),0,1500) &&
                event.kind==EVENT_CHILD_REAPED && event.verified &&
                proc_pidinfo(f.child.pid,PROC_PIDTBSDINFO,1,&absent,sizeof(absent))==0 && errno==ESRCH);
            REQUIRE(envara_app_family_observe(family) && family->count==2 && family_find(family,f.child.pid)<0);
            index=family_find(family,f.grandchild.pid);REQUIRE(index>0 && live_identity(&f.grandchild));
            REQUIRE(!memcmp(&saved,&family->members[index].token,sizeof(saved)));
        } else if (!strcmp(argv[1],"retire-leader")) {
            REQUIRE(command(f.control[0],'X') && reap_direct(f.leader_pid,&f.leader_reaped,1000,&signal_number) && !signal_number);
            REQUIRE(envara_app_family_observe(family) && family->count==3 && family_same(&family->members[0].identity,&f.leader));
            natural_exit=1;
        } else if (!strcmp(argv[1],"retire-zombie")) {
            REQUIRE(make_live_candidate(&f) && envara_app_family_observe(family) && family->count==4);
            fixture_zombie_pid=f.zombie.pid;struct fixture_event event;
            REQUIRE(command(f.control[0],'E') && exact_io(f.events[0],&event,sizeof(event),0,1500) &&
                event.kind==EVENT_ZOMBIE && event.verified);
            REQUIRE(envara_app_family_observe(family) && family->count==4 && family_find(family,f.zombie.pid)>=0 &&
                !fixture_zombie_token_calls && !fixture_zombie_signal_calls);
            REQUIRE(reap_candidate(&f) && envara_app_family_observe(family) && family->count==3);
        } else if (!strcmp(argv[1],"retire-reuse-confirmed") || !strcmp(argv[1],"retire-reuse-unconfirmed")) {
            REQUIRE(make_live_candidate(&f) && envara_app_family_observe(family) && family->count==4);
            struct envara_identity old=f.zombie;REQUIRE(reap_candidate(&f));
            int confirmed=!strcmp(argv[1],"retire-reuse-confirmed");
            if (confirmed) REQUIRE(envara_app_family_observe(family) && family->count==3 && family_find(family,old.pid)<0);
            REQUIRE(make_live_candidate(&f) && f.zombie.pid!=old.pid);
            /* Model PID recycling consistently across BSD/list/Mach reads,
             * using a different real owned process and its real audit token. */
            fixture_alias_pid=old.pid;fixture_alias_actual=f.zombie.pid;
            int observed=envara_app_family_observe(family);
            if (!confirmed) {REQUIRE(!observed);goto retirement_refused;}
            int index=family_find(family,old.pid);
            REQUIRE(observed && family->count==4 && index>0 && !family_same(&old,&family->members[index].identity));
            REQUIRE(audit_token_to_pid(family->members[index].token)==f.zombie.pid);
        } else if (!strcmp(argv[1],"retire-freeze-replacement")) {
            REQUIRE(make_live_candidate(&f) && envara_app_family_observe(family) && family->count==4);
            fixture_swap_tree=&f;fixture_swap_old=f.zombie.pid;
        } else if (!strcmp(argv[1],"retire-revision-admit") || !strcmp(argv[1],"retire-revision-remove")) {
            REQUIRE(make_live_candidate(&f));
            if (!strcmp(argv[1],"retire-revision-remove")) REQUIRE(envara_app_family_observe(family) && reap_candidate(&f));
            size_t before=family->count;family->membership_revision=UINT64_MAX;
            REQUIRE(!envara_app_family_observe(family) && family->membership_revision==UINT64_MAX && family->count==before &&
                family->failure.reason==ENVARA_APP_FAMILY_FAILURE_CAPACITY);
            goto retirement_refused;
        } else {
            const char *names[]={"retire-unknown","retire-zero-errno","retire-eagain","retire-short","retire-birth","retire-credentials"};
            fixture_retire_mode=-1;
            for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_retire_mode=(int)i;
            REQUIRE(fixture_retire_mode>=0);fixture_retire_pid=f.child.pid;
            REQUIRE(!envara_app_family_observe(family) && family->count==3);
            fixture_retire_pid=0;
            goto retirement_refused;
        }
        REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && (natural_exit || leader_signal_sent));
        if (fixture_swap_tree) REQUIRE(fixture_swap_triggered && fixture_swap_frozen && !fixture_swap_kill_early &&
            family->count==4 && family_find(family,fixture_swap_old)<0 && family_find(family,fixture_swap_new)>0);
        REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
        REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && (natural_exit || signal_number==SIGKILL));
        REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        goto finished;
retirement_refused:;
        struct envara_app_family_failure first,after;envara_app_family_first_failure(family,&first);
        REQUIRE(family->uncertain && !fixture_signal_calls && !envara_app_family_stop(family,&leader_signal_sent) &&
            !envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent &&
            !envara_app_family_observe(family) && !envara_app_family_quiescent(family));
        envara_app_family_first_failure(family,&after);
        REQUIRE(!memcmp(&first,&after,sizeof(first)) && !fixture_signal_calls && live_identity(&f.leader) && sibling_alive(&f));
        failure_closed=1;first_failure_preserved=1;
        goto finished;
    }
    if (!strncmp(argv[1],"candidate-",10)) {
        const char *names[]={"candidate-live-absent","candidate-zombie-absent","candidate-name-absent",
            "candidate-second-list-gap","candidate-first-absent","candidate-first-unknown","candidate-first-short",
            "candidate-second-birth","candidate-second-credentials","candidate-second-parent","candidate-post-parent",
            "candidate-pid-mismatch","candidate-short-token","candidate-parent-absent","candidate-parent-changed",
            "candidate-zombie-parent","candidate-churn"};
        fixture_candidate_mode=-1;
        for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_candidate_mode=(int)i;
        REQUIRE(fixture_candidate_mode>=0);
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int mode=fixture_candidate_mode,zombie=mode==CAND_ZOMBIE_ABSENT || mode==CAND_ZOMBIE_PARENT;
        REQUIRE(zombie?make_zombie(&f):make_live_candidate(&f));
        fixture_candidate_pid=f.zombie.pid;fixture_candidate_parent=f.leader.pid;
        fixture_candidate_control=f.control[0];fixture_candidate_events=f.events[0];
        int observed=envara_app_family_observe(family);
        int positive=mode==CAND_LIVE_ABSENT || mode==CAND_ZOMBIE_ABSENT || mode==CAND_NAME_ABSENT;
        REQUIRE(family->count==3 && !fixture_signal_calls);
        audit_token_t empty={{0}};
        REQUIRE(!memcmp(&family->members[3].token,&empty,sizeof(empty)));
        if (positive) REQUIRE(observed && !family->uncertain && fixture_candidate_reaped &&
            fixture_candidate_lists>=4 && !fixture_candidate_infos);
        if (mode==CAND_SECOND_LIST_GAP) REQUIRE(fixture_candidate_reaped && fixture_candidate_reads==3);
        if (mode==CAND_PID_MISMATCH || mode==CAND_SHORT_TOKEN) REQUIRE(fixture_candidate_reaped && fixture_candidate_reads==2);
        if (mode==CAND_SECOND_PARENT || mode==CAND_SECOND_BIRTH || mode==CAND_SECOND_CREDENTIALS)
            REQUIRE(fixture_candidate_reads==2 && !fixture_candidate_names);
        fixture_candidate_pid=0;fixture_candidate_parent=0;
        if (positive) {
            struct envara_app_family_failure failure;envara_app_family_first_failure(family,&failure);
            REQUIRE(failure.reason==ENVARA_APP_FAMILY_FAILURE_NONE);
            REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        } else {
            struct envara_app_family_failure first,again;envara_app_family_first_failure(family,&first);
            REQUIRE(!observed && (family->uncertain || family->retry_pending));
            if (mode==CAND_CHURN) REQUIRE(!family->uncertain && family->retry_pending && first.reason==ENVARA_APP_FAMILY_FAILURE_CHURN && first.os_error==EAGAIN);
            else REQUIRE(family->uncertain && !envara_app_family_retry_stop(family,&leader_signal_sent));
            REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && !leader_signal_sent &&
                !envara_app_family_observe(family) && !envara_app_family_quiescent(family) && !fixture_signal_calls);
            envara_app_family_first_failure(family,&again);
            REQUIRE(first.reason==again.reason && first.os_error==again.os_error && first.mach_error==again.mach_error);
            REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && sibling_alive(&f));
            failure_closed=1;first_failure_preserved=1;
        }
        goto finished;
    }
    if (!strncmp(argv[1],"known-reap-",11)) {
        const char *names[]={"known-reap-absent","known-reap-stress","known-reap-first-absent",
            "known-reap-first-unknown","known-reap-first-short","known-reap-first-birth",
            "known-reap-first-credentials","known-reap-first-parent","known-reap-second-unknown",
            "known-reap-second-short","known-reap-second-birth","known-reap-second-credentials",
            "known-reap-second-parent","known-reap-second-live","known-reap-parent-absent",
            "known-reap-parent-zombie","known-reap-parent-birth","known-reap-parent-credentials",
            "known-reap-parent-unknown","known-reap-parent-short","known-reap-parent-token",
            "known-reap-parent-after-birth","known-reap-parent-after-credentials","known-reap-prior-uncertain"};
        fixture_reap_mode=-1;
        for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_reap_mode=(int)i;
        REQUIRE(fixture_reap_mode>=0);
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int positive=fixture_reap_mode==REAP_ABSENT || fixture_reap_mode==REAP_STRESS;
        unsigned rounds=fixture_reap_mode==REAP_STRESS?64:1;
        for (unsigned round=0;round<rounds;round++) {
            REQUIRE(make_live_candidate(&f) && envara_app_family_observe(family));
            REQUIRE(family->count==4 && family_find(family,f.zombie.pid)>=0);
            struct fixture_event event;struct envara_identity actual;
            REQUIRE(command(f.control[0],'E') && exact_io(f.events[0],&event,sizeof(event),0,1500) &&
                event.kind==EVENT_ZOMBIE && event.verified && read_zombie(f.zombie.pid,&actual) &&
                family_same(&actual,&f.zombie) && actual.parent_pid==f.leader.pid);
            fixture_reap_pid=f.zombie.pid;fixture_reap_parent=f.leader.pid;
            fixture_reap_control=f.control[0];fixture_reap_events=f.events[0];
            fixture_reap_reads=0;fixture_reap_parent_reads=0;fixture_reap_reaped=0;fixture_reap_lists=0;
            if (fixture_reap_mode==REAP_PRIOR_UNCERTAIN)
                (void)family_refuse_reason(family,ENVARA_APP_FAMILY_FAILURE_TOKEN,EACCES,KERN_PROTECTION_FAILURE);
            int observed=envara_app_family_observe(family);
            REQUIRE(!fixture_signal_calls && (family->count==4 || (positive && family->count==3)));
            if (positive) {
                if (!observed) {
                    struct envara_app_family_failure failure;envara_app_family_first_failure(family,&failure);
                    fprintf(stderr,"known reap refused: uncertain=%d reaped=%d childReads=%d parentReads=%d reason=%s osError=%d\n",
                        family->uncertain,fixture_reap_reaped,fixture_reap_reads,fixture_reap_parent_reads,
                        envara_app_family_failure_name(failure.reason),failure.os_error);
                }
                REQUIRE(observed && !family->uncertain && fixture_reap_reaped && fixture_reap_reads>=3 &&
                    fixture_reap_parent_reads>=2 && stable_children(&f,0));
                struct envara_app_family_failure failure;envara_app_family_first_failure(family,&failure);
                REQUIRE(failure.reason==ENVARA_APP_FAMILY_FAILURE_NONE);known_reap_transitions++;
            } else {
                REQUIRE(!observed && family->uncertain);
                struct envara_app_family_failure first,again;envara_app_family_first_failure(family,&first);
                if (fixture_reap_mode==REAP_PRIOR_UNCERTAIN) REQUIRE(!fixture_reap_reads &&
                    first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN && first.os_error==EACCES && first.mach_error==KERN_PROTECTION_FAILURE);
                fixture_reap_pid=0;fixture_reap_parent=0;
                REQUIRE(!envara_app_family_observe(family) && !envara_app_family_stop(family,&leader_signal_sent) &&
                    !envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent &&
                    !envara_app_family_quiescent(family) && !fixture_signal_calls);
                envara_app_family_first_failure(family,&again);
                REQUIRE(!memcmp(&first,&again,sizeof(first)) && live_identity(&f.leader) &&
                    live_identity(&f.child) && sibling_alive(&f));
                failure_closed=1;first_failure_preserved=1;
            }
            fixture_reap_pid=0;fixture_reap_parent=0;
        }
        if (positive) {
            REQUIRE(known_reap_transitions==rounds && envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        }
        goto finished;
    }
    if (!strncmp(argv[1],"known-",6)) {
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int index=family_find(family,f.grandchild.pid);REQUIRE(index>=0);
        fixture_terminal_pid=f.grandchild.pid;fixture_terminal_parent_control=f.orphan[1];
        fixture_terminal_exit_control=f.detach[1];
        if (!strcmp(argv[1],"known-zombie-reparent")) REQUIRE(fixture_terminal_exit());
        else if (!strcmp(argv[1],"known-name-zombie-reparent")) {
            fixture_name_pid=f.grandchild.pid;fixture_name_mode=NAME_EXIT_ZOMBIE;
            fixture_name_identity=f.grandchild;fixture_name_control=f.detach[1];
        } else {REQUIRE(!strcmp(argv[1],"known-info-zombie-reparent"));fixture_terminal_info_exit=1;}
        int refreshed=family_member_refresh(family,&family->members[index]);
        REQUIRE(refreshed>=0 && refreshed!=1 && fixture_terminal_changed && !family->uncertain && !fixture_signal_calls);
        struct envara_app_family_failure failure;envara_app_family_first_failure(family,&failure);
        REQUIRE(failure.reason==ENVARA_APP_FAMILY_FAILURE_NONE);
        fixture_terminal_pid=0;fixture_terminal_info_exit=0;fixture_name_pid=0;
        REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
        REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
        REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
        REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        goto finished;
    }
    if (!strncmp(argv[1],"refresh-recheck-",16)) {
        const char *names[]={"refresh-recheck-name-exit","refresh-recheck-info-exit",
            "refresh-recheck-name-success","refresh-recheck-info-success","refresh-recheck-name-persistent",
            "refresh-recheck-info-persistent","refresh-recheck-name-other","refresh-recheck-info-other",
            "refresh-recheck-pid-invalid","refresh-recheck-pid-failure","refresh-recheck-short",
            "refresh-recheck-invalid-short","refresh-recheck-first-parent","refresh-recheck-second-birth",
            "refresh-recheck-second-credentials","refresh-recheck-second-parent","refresh-recheck-second-unknown",
            "refresh-recheck-after-birth","refresh-recheck-after-credentials","refresh-recheck-after-parent",
            "refresh-recheck-second-short","refresh-recheck-name-then-info","refresh-recheck-info-then-name",
            "refresh-recheck-interrupted","refresh-recheck-zombie-parent"};
        fixture_recheck_mode=-1;
        for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_recheck_mode=(int)i;
        REQUIRE(fixture_recheck_mode>=0);
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int index=family_find(family,f.grandchild.pid);REQUIRE(index>=0);
        REQUIRE(proc_pidinfo(f.grandchild.pid,PROC_PIDTBSDINFO,1,&fixture_recheck_original,sizeof(fixture_recheck_original))==sizeof(fixture_recheck_original));
        fixture_recheck_pid=f.grandchild.pid;fixture_recheck_control=f.detach[1];
        struct family_member *target=&family->members[index];target->token.val[7]^=1;
        audit_token_t saved=target->token;
        int refreshed=family_member_refresh(family,target),mode=fixture_recheck_mode;
        REQUIRE(fixture_recheck_names>=1 && fixture_recheck_names<=2 && fixture_recheck_sleeps<=1 &&
            fixture_recheck_reads<=4 && !fixture_signal_calls && family->count==3);
        int terminal=mode==RECHECK_NAME_EXIT || mode==RECHECK_INFO_EXIT;
        int live_success=mode==RECHECK_NAME_SUCCESS || mode==RECHECK_INFO_SUCCESS;
        int positive=terminal || live_success;
        if (terminal || mode==RECHECK_ZOMBIE_PARENT) REQUIRE(fixture_recheck_triggered);
        if (live_success) REQUIRE(fixture_recheck_names==2 && fixture_recheck_sleeps==1 &&
            fixture_recheck_infos==(mode==RECHECK_NAME_SUCCESS?1:2) && memcmp(&saved,&target->token,sizeof(saved)));
        if (mode==RECHECK_NAME_PERSISTENT || mode==RECHECK_INFO_PERSISTENT ||
            mode==RECHECK_NAME_THEN_INFO || mode==RECHECK_INFO_THEN_NAME) REQUIRE(fixture_recheck_names==2 && fixture_recheck_sleeps==1);
        if (mode==RECHECK_NAME_OTHER || mode==RECHECK_INFO_OTHER || mode==RECHECK_PID_INVALID ||
            mode==RECHECK_PID_FAILURE || mode==RECHECK_SHORT || mode==RECHECK_INVALID_SHORT ||
            mode==RECHECK_FIRST_PARENT) REQUIRE(fixture_recheck_names==1 && !fixture_recheck_sleeps);
        if (mode==RECHECK_INTERRUPTED) REQUIRE(fixture_recheck_names==1 && fixture_recheck_sleeps==1);
        fixture_recheck_pid=0;fixture_recheck_triggered=0;
        if (positive) {
            struct envara_app_family_failure diagnosis;envara_app_family_first_failure(family,&diagnosis);
            REQUIRE(refreshed==(terminal?2:1) && !family->uncertain && diagnosis.reason==ENVARA_APP_FAMILY_FAILURE_NONE);
            REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        } else {
            struct envara_app_family_failure first,again;envara_app_family_first_failure(family,&first);
            REQUIRE(refreshed==-1 && family->uncertain && !memcmp(&saved,&target->token,sizeof(saved)));
            REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_IDENTITY || first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN);
            if (mode==RECHECK_INTERRUPTED) REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN && first.os_error==EACCES && first.mach_error==KERN_FAILURE);
            REQUIRE(!envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent);
            REQUIRE(!envara_app_family_observe(family) && !envara_app_family_quiescent(family) && !fixture_signal_calls);
            envara_app_family_first_failure(family,&again);
            REQUIRE(first.reason==again.reason && first.os_error==again.os_error && first.mach_error==again.mach_error);
            REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && sibling_alive(&f));
            failure_closed=1;first_failure_preserved=1;
        }
        goto finished;
    }
    if (!strncmp(argv[1],"reparent-",9)) {
        const char *names[]={"reparent-stable","reparent-unregistered","reparent-leader","reparent-stored-token",
            "reparent-first-token-failed","reparent-first-token-short","reparent-second-token",
            "reparent-second-token-failed","reparent-second-token-short","reparent-second-birth",
            "reparent-second-credentials","reparent-after-birth","reparent-after-credentials",
            "reparent-second-ppid","reparent-second-unknown","reparent-after-unknown","reparent-link-ppid",
            "reparent-second-name-failed","reparent-second-info-invalid"};
        fixture_reparent_mode=-1;
        for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_reparent_mode=(int)i;
        REQUIRE(fixture_reparent_mode>=0);
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int leader=fixture_reparent_mode==REPARENT_LEADER;
        fixture_reparent_identity=leader?f.leader:f.grandchild;
        fixture_reparent_parent=f.child;fixture_reparent_pid=fixture_reparent_identity.pid;
        fixture_reparent_control=f.orphan[1];
        int index=family_find(family,fixture_reparent_pid);REQUIRE(index>=0);
        struct family_member detached_member=family->members[index];
        struct family_member *target=fixture_reparent_mode==REPARENT_UNREGISTERED?&detached_member:&family->members[index];
        if (fixture_reparent_mode==REPARENT_STORED_TOKEN) target->token.val[7]^=1;
        audit_token_t saved=target->token;
        int refreshed=family_member_refresh(family,target);
        REQUIRE(fixture_reparent_done && !fixture_signal_calls && family->count==3 &&
            family->members[index].identity.parent_pid==fixture_reparent_identity.parent_pid);
        int early=fixture_reparent_mode==REPARENT_UNREGISTERED || leader || fixture_reparent_mode==REPARENT_STORED_TOKEN ||
            fixture_reparent_mode==REPARENT_FIRST_TOKEN_FAILED || fixture_reparent_mode==REPARENT_FIRST_TOKEN_SHORT;
        int before_second_token=fixture_reparent_mode==REPARENT_SECOND_BIRTH || fixture_reparent_mode==REPARENT_SECOND_CREDENTIALS ||
            fixture_reparent_mode==REPARENT_SECOND_UNKNOWN || fixture_reparent_mode==REPARENT_LINK_PPID;
        REQUIRE(fixture_reparent_calls==(early || before_second_token || fixture_reparent_mode==REPARENT_SECOND_NAME_FAILED?1:2));
        REQUIRE(fixture_reparent_reads==(early?1:before_second_token?2:3));
        REQUIRE(fixture_reparent_names<=2);
        fixture_reparent_pid=0;fixture_reparent_done=0;
        REQUIRE(live_identity(&f.leader) && live_identity(&f.grandchild) && sibling_alive(&f));
        REQUIRE(identity_state(&f.child)==(leader?1:2));
        if (fixture_reparent_mode==REPARENT_STABLE) {
            REQUIRE(refreshed==1 && !family->uncertain && !memcmp(&saved,&target->token,sizeof(saved)));
            struct envara_identity current;REQUIRE(!envara_identity_read(f.grandchild.pid,&current) && current.parent_pid==1);
            REQUIRE(envara_app_family_observe(family) && family->count==3);
            REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        } else {
            struct envara_app_family_failure first,again;envara_app_family_first_failure(family,&first);
            REQUIRE(refreshed==-1 && family->uncertain && !memcmp(&saved,&target->token,sizeof(saved)));
            REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_IDENTITY || first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN);
            REQUIRE(!envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent);
            REQUIRE(!envara_app_family_observe(family) && !envara_app_family_quiescent(family) && !fixture_signal_calls);
            envara_app_family_first_failure(family,&again);
            REQUIRE(first.reason==again.reason && first.os_error==again.os_error && first.mach_error==again.mach_error);
            failure_closed=1;first_failure_preserved=1;
        }
        goto finished;
    }
    if (!strncmp(argv[1],"name-exit-",10)) {
        const char *names[]={"name-exit-zombie","name-exit-absent","name-exit-birth","name-exit-credentials",
            "name-exit-unknown","name-exit-second-birth","name-exit-second-credentials",
            "name-exit-second-unknown","name-exit-second-live","name-exit-live"};
        fixture_name_mode=-1;
        for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) if (!strcmp(argv[1],names[i])) fixture_name_mode=(int)i;
        REQUIRE(fixture_name_mode>=0);
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int absent=fixture_name_mode==NAME_EXIT_ABSENT;
        int positive=absent || fixture_name_mode==NAME_EXIT_ZOMBIE;
        fixture_name_identity=absent?f.leader:f.grandchild;
        fixture_name_pid=fixture_name_identity.pid;
        fixture_name_control=absent?f.control[0]:f.detach[1];
        fixture_name_leader_reaped=absent?&f.leader_reaped:NULL;
        int index=family_find(family,fixture_name_pid);REQUIRE(index>=0);
        int refreshed=family_member_refresh(family,&family->members[index]);
        REQUIRE(fixture_name_calls==(fixture_name_mode==NAME_EXIT_LIVE?2:1) && fixture_name_finished && !fixture_signal_calls);
        int second=fixture_name_mode==NAME_EXIT_ZOMBIE ||
            (fixture_name_mode>=NAME_EXIT_SECOND_BIRTH && fixture_name_mode<=NAME_EXIT_SECOND_LIVE);
        REQUIRE(fixture_name_reads==(fixture_name_mode==NAME_EXIT_LIVE?3:second?2:1));
        fixture_name_pid=0;fixture_name_finished=0;fixture_name_leader_reaped=NULL;
        if (positive) {
            REQUIRE(refreshed==(absent?0:2) && !family->uncertain);
            struct envara_app_family_failure diagnosis;envara_app_family_first_failure(family,&diagnosis);
            REQUIRE(diagnosis.reason==ENVARA_APP_FAMILY_FAILURE_NONE);
            REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent==!absent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number));
            REQUIRE(absent || signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        } else {
            struct envara_app_family_failure first,again;envara_app_family_first_failure(family,&first);
            REQUIRE(refreshed==-1 && family->uncertain && first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN &&
                first.os_error==EACCES && first.mach_error==KERN_FAILURE);
            REQUIRE(!envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent);
            REQUIRE(!envara_app_family_observe(family) && !envara_app_family_quiescent(family) && !fixture_signal_calls);
            envara_app_family_first_failure(family,&again);
            REQUIRE(first.reason==again.reason && first.os_error==again.os_error && first.mach_error==again.mach_error);
            REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && sibling_alive(&f));
            REQUIRE(identity_state(&f.grandchild)==(fixture_name_mode==NAME_EXIT_LIVE?1:2));
            failure_closed=1;first_failure_preserved=1;
        }
        goto finished;
    }
    if (!strcmp(argv[1],"true-inventory-churn") || !strcmp(argv[1],"stop-timeout-retry")) {
        family=envara_app_family_create(&f.leader);
        REQUIRE(family && family->count==3);
        int timeout=!strcmp(argv[1],"stop-timeout-retry");
        fixture_inventory_parent=f.leader_pid;fixture_churn=!timeout;fixture_force_running=timeout;
        errno=0;
        REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && errno==(timeout?ETIMEDOUT:EAGAIN) && !leader_signal_sent);
        REQUIRE(timeout ? fixture_stop_signals==3 : fixture_inventory_calls>=6 && !fixture_signal_calls);
        struct envara_app_family_failure first,after;
        envara_app_family_first_failure(family,&first);
        REQUIRE(first.reason==(timeout?ENVARA_APP_FAMILY_FAILURE_STOP_TIMEOUT:ENVARA_APP_FAMILY_FAILURE_CHURN));
        fixture_churn=0;fixture_force_running=0;
        REQUIRE(!envara_app_family_observe(family));
        REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && !leader_signal_sent);
        REQUIRE(!envara_app_family_quiescent(family));
        REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && !leader_signal_sent);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild) && sibling_alive(&f));
        REQUIRE(envara_app_family_retry_stop(family,&leader_signal_sent) && leader_signal_sent);
        REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000));
        REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
        REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));
        envara_app_family_first_failure(family,&after);
        REQUIRE(first.reason==after.reason && first.os_error==after.os_error && first.mach_error==after.mach_error);
        family_stopped=1;typed_retry_succeeded=1;first_failure_preserved=1;true_churn_retained=!timeout;goto finished;
    }
    if (!strcmp(argv[1],"metadata-eagain-permanent") || !strcmp(argv[1],"metadata-timeout-permanent") ||
        !strcmp(argv[1],"signal-eagain-permanent") || !strcmp(argv[1],"signal-timeout-permanent") ||
        !strcmp(argv[1],"gap-eagain-permanent") || !strcmp(argv[1],"esrch-mismatched-zombie")) {
        family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);
        int metadata=!strncmp(argv[1],"metadata-",9),signal_case=!strncmp(argv[1],"signal-",7);
        int gap=!strcmp(argv[1],"gap-eagain-permanent");
        int error=strstr(argv[1],"timeout")?ETIMEDOUT:EAGAIN;
        if (metadata) {fixture_metadata_pid=f.leader_pid;fixture_metadata_error=error;}
        if (signal_case) fixture_signal_error=error;
        if (gap) {REQUIRE(make_zombie(&f));stable_zombie=1;fixture_pidinfo_mode=4;}
        fixture_esrch_mismatch=!strcmp(argv[1],"esrch-mismatched-zombie");
        REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && !leader_signal_sent && family->uncertain);
        struct envara_app_family_failure first,after;envara_app_family_first_failure(family,&first);
        REQUIRE(first.reason!=ENVARA_APP_FAMILY_FAILURE_NONE && first.reason!=ENVARA_APP_FAMILY_FAILURE_STOP_TIMEOUT);
        if (signal_case) REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_SIGNAL && first.os_error==error);
        fixture_metadata_error=0;fixture_signal_error=0;fixture_pidinfo_mode=0;fixture_esrch_mismatch=0;fixture_esrch_pid=0;
        if (gap) {REQUIRE(identity_state(&f.zombie)==2 && stable_children(&f,1) && !fixture_zombie_token_calls && !fixture_zombie_signal_calls);zombie_untouched=1;}
        REQUIRE(!envara_app_family_retry_stop(family,&leader_signal_sent) && !leader_signal_sent);
        REQUIRE(!envara_app_family_observe(family) && !envara_app_family_quiescent(family));
        envara_app_family_first_failure(family,&after);
        REQUIRE(first.reason==after.reason && first.os_error==after.os_error && first.mach_error==after.mach_error);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild) && sibling_alive(&f));
        failure_closed=1;first_failure_preserved=1;goto finished;
    }
    int zombie_positive=!strncmp(argv[1],"stable-zombie-",14);
    int zombie_negative=!strcmp(argv[1],"zombie-parent-mismatch") || !strcmp(argv[1],"zombie-credential-mismatch") ||
        !strcmp(argv[1],"zombie-inspection-denied");
    if (zombie_positive || zombie_negative) {
        int zombie_before=!strcmp(argv[1],"stable-zombie-create");
        if (!zombie_before) {family=envara_app_family_create(&f.leader);REQUIRE(family && family->count==3);}
        REQUIRE(make_zombie(&f));stable_zombie=1;
        if (zombie_negative) {
            fixture_pidinfo_mode=!strcmp(argv[1],"zombie-parent-mismatch")?1:!strcmp(argv[1],"zombie-credential-mismatch")?2:3;
            errno=0;REQUIRE(!envara_app_family_observe(family) && errno==ESTALE && family->uncertain);
            fixture_pidinfo_mode=0;
            REQUIRE(identity_state(&f.zombie)==2 && stable_children(&f,1));
            errno=0;REQUIRE(!envara_app_family_observe(family) && errno==EACCES && family->uncertain);
            REQUIRE(!envara_app_family_stop(family,&leader_signal_sent) && !leader_signal_sent && !fixture_signal_calls);
            REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild) && sibling_alive(&f));
            REQUIRE(!fixture_zombie_token_calls && !fixture_zombie_signal_calls);zombie_untouched=1;
            failure_closed=1;goto finished;
        }
        if (zombie_before) family=envara_app_family_create(&f.leader);
        REQUIRE(family && family->count==3 && !family->uncertain && envara_app_family_observe(family));
        REQUIRE(identity_state(&f.zombie)==2 && stable_children(&f,1) && sibling_alive(&f));
        if (!strcmp(argv[1],"stable-zombie-observe")) {
            struct fixture_event event;
            REQUIRE(command(f.control[0],'R') && exact_io(f.events[0],&event,sizeof(event),0,1000));
            REQUIRE(event.kind==EVENT_ZOMBIE_REAPED && event.verified && stable_children(&f,0));
            REQUIRE(envara_app_family_observe(family) && !family->uncertain);zombie_reaped=1;
        } else if (!strcmp(argv[1],"stable-zombie-stop")) {
            REQUIRE(envara_app_family_stop(family,&leader_signal_sent) && leader_signal_sent);
            REQUIRE(wait_exited(&f.child,2000) && wait_exited(&f.grandchild,2000) && wait_exited(&f.zombie,2000));
            REQUIRE(reap_direct(f.leader_pid,&f.leader_reaped,2000,&signal_number) && signal_number==SIGKILL);
            REQUIRE(envara_app_family_quiescent(family) && sibling_alive(&f));family_stopped=1;
        } else REQUIRE(zombie_before);
        REQUIRE(!fixture_zombie_token_calls && !fixture_zombie_signal_calls);zombie_untouched=1;
        goto finished;
    }
    if (!strcmp(argv[1], "api-unavailable-create")) {
        family_signal_api = NULL;
        REQUIRE(!envara_app_family_available());
        struct envara_app_family_failure diagnosis;
        errno = 0;
        REQUIRE(envara_app_family_create_diagnosed(&f.leader,&diagnosis) == NULL && errno == ENOTSUP);
        REQUIRE(diagnosis.reason==ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE && diagnosis.os_error==ENOTSUP && !diagnosis.mach_error);
        REQUIRE(!fixture_signal_calls);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild));
        REQUIRE(sibling_alive(&f)); failure_closed = 1;
        goto finished;
    }
    if (!strcmp(argv[1], "token-denied-create")) {
        fixture_deny_token = 1;
        struct envara_app_family_failure diagnosis;
        REQUIRE(envara_app_family_create_diagnosed(&f.leader,&diagnosis) == NULL);
        REQUIRE(diagnosis.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN && diagnosis.os_error==EACCES && diagnosis.mach_error==KERN_PROTECTION_FAILURE);
        REQUIRE(!fixture_signal_calls);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild));
        REQUIRE(sibling_alive(&f)); failure_closed = 1;
        goto finished;
    }
    if (!strcmp(argv[1], "token-denied-stop") || !strcmp(argv[1], "signal-denied-stop") ||
        !strcmp(argv[1], "wrong-generation-stop") || !strcmp(argv[1], "api-unavailable-stop")) {
        family = envara_app_family_create(&f.leader);
        REQUIRE(family && envara_app_family_count(family) == 3);
        fixture_deny_token = !strcmp(argv[1], "token-denied-stop");
        fixture_deny_signal = !strcmp(argv[1], "signal-denied-stop");
        fixture_wrong_generation = !strcmp(argv[1], "wrong-generation-stop");
        int unavailable = !strcmp(argv[1], "api-unavailable-stop");
        if (unavailable) { family_signal_api = NULL; REQUIRE(!envara_app_family_available()); }
        REQUIRE(!envara_app_family_stop(family, &leader_signal_sent));
        struct envara_app_family_failure first,after;envara_app_family_first_failure(family,&first);
        if (fixture_deny_token) REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_TOKEN && first.os_error==EACCES && first.mach_error==KERN_PROTECTION_FAILURE);
        else if (unavailable) REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_UNAVAILABLE && first.os_error==ENOTSUP && !first.mach_error);
        else REQUIRE(first.reason==ENVARA_APP_FAMILY_FAILURE_SIGNAL && first.os_error==(fixture_deny_signal?EPERM:ESRCH) && !first.mach_error);
        REQUIRE(!leader_signal_sent && !envara_app_family_quiescent(family));
        REQUIRE(!envara_app_family_observe(family));
        REQUIRE(!envara_app_family_stop(family, &leader_signal_sent) && !leader_signal_sent);
        envara_app_family_first_failure(family,&after);
        REQUIRE(first.reason==after.reason && first.os_error==after.os_error && first.mach_error==after.mach_error);
        first_failure_preserved=1;
        REQUIRE(fixture_deny_token || unavailable ? !fixture_signal_calls : fixture_signal_calls == 1);
        REQUIRE(!fixture_wrong_generation || fixture_wrong_generation_refused);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild));
        REQUIRE(sibling_alive(&f)); failure_closed = 1;
        wrong_generation_refused = fixture_wrong_generation_refused;
        goto finished;
    }
#endif
    if (!strcmp(argv[1], "refusal")) {
        struct envara_identity wrong = f.leader;
        wrong.birth_microseconds = (wrong.birth_microseconds + 1) % 1000000;
        REQUIRE(envara_app_family_create(NULL) == NULL);
        REQUIRE(envara_app_family_create(&wrong) == NULL);
        REQUIRE(envara_app_family_create(&f.grandchild) == NULL);
        wrong = f.grandchild; wrong.parent_pid = getpid();
        REQUIRE(envara_app_family_create(&wrong) == NULL);
        struct envara_identity self;
        REQUIRE(!envara_identity_read(getpid(), &self));
        REQUIRE(envara_app_family_create(&self) == NULL);
        REQUIRE(live_identity(&f.leader) && live_identity(&f.child) && live_identity(&f.grandchild));
        REQUIRE(sibling_alive(&f)); refused = 1;
        goto finished;
    }
    REQUIRE(!strcmp(argv[1], "tree") || !strcmp(argv[1], "detached") ||
        !strcmp(argv[1], "natural") || !strcmp(argv[1], "repeat"));
    family = envara_app_family_create(&f.leader);
    REQUIRE(family != NULL);
    REQUIRE(envara_app_family_count(family) == 3);
    REQUIRE(envara_app_family_observe(family));
    REQUIRE(!envara_app_family_quiescent(family));
    REQUIRE(sibling_alive(&f));
    if (!strcmp(argv[1], "detached")) {
        struct fixture_event event;
        REQUIRE(command(f.detach[1], 'D'));
        REQUIRE(exact_io(f.events[0], &event, sizeof(event), 0, 1000));
        REQUIRE(event.kind == EVENT_DETACHED && event.detached &&
            event.identity.pid == f.grandchild.pid && event.identity.birth_seconds == f.grandchild.birth_seconds &&
            event.identity.birth_microseconds == f.grandchild.birth_microseconds);
        REQUIRE(getsid(f.grandchild.pid) == f.grandchild.pid);
        REQUIRE(envara_app_family_observe(family));
        REQUIRE(envara_app_family_count(family) == 3); detached = 1;
    } else if (!strcmp(argv[1], "natural")) {
        REQUIRE(command(f.control[0], 'X'));
        REQUIRE(reap_direct(f.leader_pid, &f.leader_reaped, 1000, &signal_number));
        REQUIRE(signal_number == 0);
        REQUIRE(live_identity(&f.child) && live_identity(&f.grandchild));
        REQUIRE(envara_app_family_observe(family));
        REQUIRE(!envara_app_family_quiescent(family)); natural_exit = 1;
    }
    REQUIRE(envara_app_family_stop(family, &leader_signal_sent));
    family_stopped=1;
    REQUIRE(natural_exit || leader_signal_sent);
    REQUIRE(wait_exited(&f.child, 2000) && wait_exited(&f.grandchild, 2000));
    REQUIRE(reap_direct(f.leader_pid, &f.leader_reaped, 2000, &signal_number));
    REQUIRE(natural_exit || signal_number == SIGKILL);
    REQUIRE(envara_app_family_quiescent(family));
    REQUIRE(sibling_alive(&f));
    if (!strcmp(argv[1], "repeat")) {
        int signal_again = 0;
        REQUIRE(envara_app_family_stop(family, &signal_again));
        REQUIRE(!signal_again && envara_app_family_quiescent(family));
        REQUIRE(sibling_alive(&f)); repeat_stop = 1;
    }
finished:
#ifdef ENVARA_APP_FAMILY_FAILURE_FIXTURE
    fixture_pidinfo_mode=0;fixture_churn=0;
    fixture_name_pid=0;fixture_name_finished=0;fixture_name_leader_reaped=NULL;
    fixture_reparent_pid=0;fixture_reparent_done=0;
    fixture_recheck_pid=0;fixture_recheck_triggered=0;
    fixture_terminal_pid=0;fixture_terminal_info_exit=0;
    fixture_candidate_pid=0;fixture_candidate_parent=0;
    fixture_reap_pid=0;fixture_reap_parent=0;
    fixture_retire_pid=0;fixture_alias_pid=0;fixture_alias_actual=0;fixture_swap_tree=NULL;
    fixture_swap_old=0;fixture_swap_new=0;
    fixture_metadata_error=0;fixture_force_running=0;fixture_esrch_pid=0;
#endif
    if (family) envara_app_family_destroy(family);
    int sibling_untouched=f.unrelated.pid>1 && sibling_alive(&f);
    if (!sibling_untouched) okay=0;
    int cleaned = cleanup(&f);
    if (!cleaned) { fprintf(stderr, "fixture owned cleanup incomplete\n"); okay = 0; }
    printf("{\"ok\":%s,\"fixtureOnly\":true,\"ready\":false,\"protected\":false,"
        "\"activatesSystem\":false,\"sameIdentitySiblingUnaffected\":%s,\"ownedCleanupComplete\":%s,"
        "\"refusedUnownedOrStaleIdentity\":%s,\"detachedMemberStopped\":%s,"
        "\"naturalLeaderExitRetainedMembers\":%s,\"repeatedStopSafe\":%s,"
        "\"familyStopped\":%s,\"failureRetainedCustody\":%s,\"wrongGenerationSignalRefused\":%s,"
        "\"stableZombieVerified\":%s,\"stableZombieReaped\":%s,\"zombieTokenAndSignalUntouched\":%s,\"trueChurnRetained\":%s,"
        "\"typedRetrySucceeded\":%s,\"firstFailurePreserved\":%s,\"knownReapTransitions\":%u}\n",
        okay?"true":"false",sibling_untouched?"true":"false",cleaned?"true":"false",refused ? "true" : "false", detached ? "true" : "false", natural_exit ? "true" : "false",
        repeat_stop ? "true" : "false",family_stopped?"true":"false",
        failure_closed ? "true" : "false", wrong_generation_refused ? "true" : "false",
        stable_zombie?"true":"false",zombie_reaped?"true":"false",zombie_untouched?"true":"false",true_churn_retained?"true":"false",
        typed_retry_succeeded?"true":"false",first_failure_preserved?"true":"false",known_reap_transitions);
    return okay?0:1;
}
