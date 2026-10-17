/* Unprivileged source fixture. Every Security entry point and every root
 * authority below is replaced at compile time. The fake worker only handles
 * synthetic frames and creates an empty selector inside its disposable root.
 * Actual filesystem/pipes/own-child waits exercise the production code;
 * neither this binary nor its children use a real Keychain API. */
#include "app-keychain.h"
#include "notion-launch.h"
#include "app-scope-proof.h"
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/acl.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <libproc.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

static char fixture_root[PATH_MAX];
enum fixture_command_fault { COMMAND_NONE, COMMAND_OK, COMMAND_ENTRY, COMMAND_IDENTITY, COMMAND_HOME,
    COMMAND_HOLDS, COMMAND_SANDBOX, COMMAND_METADATA, COMMAND_SET_DEFAULT, COMMAND_PARENT_IDENTITY };
static _Thread_local enum fixture_command_fault fixture_command_fault;
static _Thread_local int fixture_command_active;
static uid_t fixture_module_uid(void);
static pid_t fixture_getppid(void);
static int fixture_getgroups(int size,gid_t *groups);
static int fixture_proc_pidpath(int pid, void *buffer, uint32_t size);
static pid_t fixture_waitpid(pid_t pid, int *status, int options);
static int fixture_kill(pid_t pid,int signal_number);
static int fixture_sigaction(int signal_number,const struct sigaction *action,struct sigaction *previous);
static int fixture_openat(int directory,const char *name,int flags,...);
static int fixture_fstat(int fd,struct stat *info);
static int fixture_lstat(const char *path,struct stat *info);
static int fixture_fstatat(int directory,const char *name,struct stat *info,int flags);
static int fixture_fchown(int fd,uid_t uid,gid_t gid);
static int fixture_fchmod(int fd,mode_t mode);
static int fixture_fchflags(int fd,unsigned int flags);
static int fixture_sysctlbyname(const char *name,void *value,size_t *size,const void *replacement,size_t replacement_size);
static int fixture_sysctl(int *name,u_int count,void *value,size_t *size,void *replacement,size_t replacement_size);
static int fixture_fsync(int fd);
static int fixture_renameatx_np(int from,const char *source,int to,const char *destination,unsigned flags);
static int fixture_sandbox_init(const char *profile, uint64_t flags, char **error);
static void fixture_sandbox_free_error(char *error);
static OSStatus fixture_SecKeychainCopyDefault(SecKeychainRef *key);
static OSStatus fixture_SecKeychainGetPath(SecKeychainRef key, UInt32 *size, char *path);
static OSStatus fixture_SecKeychainGetStatus(SecKeychainRef key, SecKeychainStatus *status);
static OSStatus fixture_SecKeychainCopySearchList(CFArrayRef *list);
static OSStatus fixture_SecKeychainCopyDomainSearchList(SecPreferencesDomain domain, CFArrayRef *list);
static CFTypeID fixture_SecKeychainGetTypeID(void);
static OSStatus fixture_SecKeychainSetUserInteractionAllowed(Boolean allowed);
static OSStatus fixture_SecKeychainGetUserInteractionAllowed(Boolean *allowed);
static OSStatus fixture_SecKeychainOpen(const char *path, SecKeychainRef *key);
static OSStatus fixture_SecKeychainSetDefault(SecKeychainRef key);

#undef ENVARA_NOTION_DATA_ROOT
#define ENVARA_NOTION_DATA_ROOT fixture_root
#define getuid fixture_module_uid
#define geteuid fixture_module_uid
#define getppid fixture_getppid
#define getgroups fixture_getgroups
#define proc_pidpath fixture_proc_pidpath
#define waitpid fixture_waitpid
#define kill fixture_kill
#define sigaction(...) fixture_sigaction(__VA_ARGS__)
#define openat(...) fixture_openat(__VA_ARGS__)
#define fstat(...) fixture_fstat(__VA_ARGS__)
#define lstat(...) fixture_lstat(__VA_ARGS__)
#define fstatat(...) fixture_fstatat(__VA_ARGS__)
#define fchown(...) fixture_fchown(__VA_ARGS__)
#define fchmod(...) fixture_fchmod(__VA_ARGS__)
#define fchflags(...) fixture_fchflags(__VA_ARGS__)
#define sysctlbyname(...) fixture_sysctlbyname(__VA_ARGS__)
#define sysctl(...) fixture_sysctl(__VA_ARGS__)
#define fsync(...) fixture_fsync(__VA_ARGS__)
#define renameatx_np(...) fixture_renameatx_np(__VA_ARGS__)
#define sandbox_init fixture_sandbox_init
#define sandbox_free_error fixture_sandbox_free_error
#define SecKeychainCopyDefault fixture_SecKeychainCopyDefault
#define SecKeychainGetPath fixture_SecKeychainGetPath
#define SecKeychainGetStatus fixture_SecKeychainGetStatus
#define SecKeychainCopySearchList fixture_SecKeychainCopySearchList
#define SecKeychainCopyDomainSearchList fixture_SecKeychainCopyDomainSearchList
#define SecKeychainGetTypeID fixture_SecKeychainGetTypeID
#define SecKeychainSetUserInteractionAllowed fixture_SecKeychainSetUserInteractionAllowed
#define SecKeychainGetUserInteractionAllowed fixture_SecKeychainGetUserInteractionAllowed
#define SecKeychainOpen fixture_SecKeychainOpen
#define SecKeychainSetDefault fixture_SecKeychainSetDefault
#include "app-keychain.m"
#undef getuid
#undef geteuid
#undef getppid
#undef getgroups
#undef proc_pidpath
#undef waitpid
#undef kill
#undef sigaction
#undef openat
#undef fstat
#undef lstat
#undef fstatat
#undef fchown
#undef fchmod
#undef fchflags
#undef sysctlbyname
#undef sysctl
#undef fsync
#undef renameatx_np
#undef sandbox_init
#undef sandbox_free_error
#undef SecKeychainCopyDefault
#undef SecKeychainGetPath
#undef SecKeychainGetStatus
#undef SecKeychainCopySearchList
#undef SecKeychainCopyDomainSearchList
#undef SecKeychainGetTypeID
#undef SecKeychainSetUserInteractionAllowed
#undef SecKeychainGetUserInteractionAllowed
#undef SecKeychainOpen
#undef SecKeychainSetDefault

static unsigned checks, security_reads, security_setters, unexpected_worker_calls;
static unsigned wait_calls, forbidden_waits, scope_calls, spawn_calls, selector_writes;
static int scope_absent=1, owner_live=1, last_error_fd=-1;
static int expect_birth_missing_wait;
static unsigned module_signal_calls, module_signal_policy_writes;
static pid_t last_wait_zero_pid;
static int policy_read_refused, saved_sigchld_active;
static struct sigaction saved_sigchld;
static char fixture_registration[PATH_MAX];
static int publish_hardlink_race, stage_library_open_refused, scope_unknown_at_select;
static unsigned publish_race_injected;
static char last_stage_root[PATH_MAX];
static int stage_fail_mode_readback, stage_fail_owner_readback, stage_fail_first_identity, fail_next_fd_fstat=-1;
static int publish_fsync_failure;static unsigned published_fsync_failures;
struct fixture_stage_file { dev_t device; ino_t inode; int transferred; };
static struct fixture_stage_file fixture_stage_files[8];
static unsigned fixture_stage_file_count;
struct fixture_stage_home { dev_t device; ino_t inode; uid_t owner; unsigned int flags; };
static struct fixture_stage_home fixture_stage_homes[8];
static unsigned fixture_stage_home_count, home_owner_changes, home_seals, home_unseals, home_reclaims, securelevel_reads;
static int securelevel_value=-1, securelevel_error, securelevel_short;
static int seal_owner_fail,seal_owner_readback,seal_mode_fail,seal_mode_readback,seal_flags_fail,seal_flags_readback;
static int clear_flags_fail,clear_flags_readback,reclaim_owner_fail,reclaim_owner_readback,reclaim_mode_fail,reclaim_mode_readback;
static int seal_swap,reclaim_swap,seal_acl,reclaim_acl,home_acl_refused;
static char swapped_library[PATH_MAX];
struct fixture_child { struct envara_identity identity; int reaped; };
static struct fixture_child fixture_children[16];
static unsigned fixture_child_count;
static struct envara_app_registration test_app;
static struct envara_gui_request test_request;
static const char test_run[]="77777777-7777-4777-8777-777777777777";
static char test_home[PATH_MAX], selector_path[PATH_MAX], key_a_path[PATH_MAX], key_b_path[PATH_MAX];
static CFStringRef key_a, key_b;
static CFArrayRef metadata_merged, metadata_user;
static OSStatus metadata_default_status, metadata_status_error, metadata_search_error;
static SecKeychainStatus metadata_flags;
static enum envara_gui_step collected_steps[64];
static unsigned collected_step_count, diagnostic_gate_checks;
static int fixture_wait_stays_pending;
static int parent_fixture_active,parent_sysctl_error,parent_getppid_before,parent_getppid_after;
static size_t parent_reply_size;
static pid_t parent_fixture_pid;
static struct kinfo_proc parent_fixture_record;
static unsigned parent_sysctl_calls,parent_tbsd_calls;
static unsigned real_kernel_snapshot_reads;
static int root_snapshot_readable,root_bsd_denied;

static uid_t fixture_module_uid(void) { return fixture_command_active?getuid():0; }
static pid_t fixture_getppid(void) {
    if(!parent_fixture_active)return getppid();
    return parent_fixture_pid+(parent_getppid_before||(!parent_getppid_before&&parent_sysctl_calls&&parent_getppid_after)?1:0);
}
static int fixture_getgroups(int size,gid_t *groups) {
    if(!fixture_command_active)return getgroups(size,groups);
    if(size<1||!groups){errno=EINVAL;return -1;}groups[0]=test_request.realm_gid;return 1;
}
void envara_gui_step(enum envara_gui_step step) {
    if(collected_step_count>=sizeof(collected_steps)/sizeof(collected_steps[0]))abort();
    if(step>=ENVARA_GUI_STEP_KEYCHAIN_HELPER_ENTRY&&step<=ENVARA_GUI_STEP_KEYCHAIN_HELPER_TIMEOUT){
        if(!owned_slot||owned_slot->wait_proof!=KC_OWNED_TERMINAL_WAIT||!owned_slot->scope_confirmed||
            !fixture_child_count||!fixture_children[fixture_child_count-1].reaped)abort();
        diagnostic_gate_checks++;
    }
    collected_steps[collected_step_count++]=step;
}

static int actual_identity(pid_t pid,struct envara_identity *out) {
    struct proc_bsdinfo info={0};
    if(pid<2||proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&info,sizeof(info))!=sizeof(info)||info.pbi_pid!=(uint32_t)pid||!info.pbi_start_tvsec)return -1;
    *out=(struct envara_identity){pid,(pid_t)info.pbi_ppid,info.pbi_uid,info.pbi_ruid,info.pbi_svuid,
        info.pbi_gid,info.pbi_rgid,info.pbi_svgid,info.pbi_start_tvsec,info.pbi_start_tvusec};return 0;
}
static int generation_equal(const struct envara_identity *a,const struct envara_identity *b) {
    return a->pid==b->pid&&a->birth_seconds==b->birth_seconds&&a->birth_microseconds==b->birth_microseconds;
}
static struct fixture_child *find_child(pid_t pid) {
    for(unsigned i=0;i<fixture_child_count;i++)if(fixture_children[i].identity.pid==pid)return &fixture_children[i];
    return NULL;
}
static pid_t wait_owned_event(pid_t pid,int *status,int stopped,unsigned timeout_ms) {
    int64_t started=now_ms(),deadline=started+timeout_ms;
    if(started<0)return -1;
    for(;;){
        pid_t got=waitpid(pid,status,WNOHANG|(stopped?WUNTRACED:0));
        if(got==pid){
            if(WIFEXITED(*status)||WIFSIGNALED(*status))find_child(pid)->reaped=1;
            return got;
        }
        if(got<0&&errno!=EINTR)return -1;
        int64_t now=now_ms();if(now<0||now>=deadline){errno=ETIMEDOUT;return -1;}
        struct timespec delay={0,1000000};(void)nanosleep(&delay,NULL);
    }
}
static void fixture_cleanup(void) {
    int unknown=0;
    if(saved_sigchld_active){if(sigaction(SIGCHLD,&saved_sigchld,NULL))unknown=1;saved_sigchld_active=0;}
    for(unsigned i=0;i<fixture_child_count;i++)if(!fixture_children[i].reaped){
        /* These are only this fixture's direct fork results. Until our exact
         * wait consumes termination the PID cannot be reused, even when a
         * process-inventory query is unavailable. Never infer a reap. */
        (void)kill(fixture_children[i].identity.pid,SIGKILL);
        int status=0;
        if(wait_owned_event(fixture_children[i].identity.pid,&status,0,1000)!=fixture_children[i].identity.pid||
            !(WIFEXITED(status)||WIFSIGNALED(status)))unknown=1;
    }
    /* Private test memory is discarded only after all actual children were
     * reaped. This is not a public cleanup or release proof. */
    if(owned_slot){
        if(owned_slot->child.error_fd>=0)close(owned_slot->child.error_fd);
        /* Only fixture-owned actual permissions are restored for the JS
         * disposable-root removal after process exit. Flags and root owners
         * are virtual, and this is never a production cleanup proof. */
        struct stat actual;
        if(owned_slot->stage.fds[0]>=0&&!fstat(owned_slot->stage.fds[0],&actual)&&S_ISDIR(actual.st_mode)&&actual.st_uid==getuid())
            if(fchmod(owned_slot->stage.fds[0],0700))unknown=1;
        /* No removal or inferred identity: any deliberately unprovable stage
         * remains in the disposable test root until the JS harness removes
         * that root after process exit. This is not successful slot cleanup. */
        stage_release_fds(&owned_slot->stage);free(owned_slot);owned_slot=NULL;
    }
    if(metadata_merged)CFRelease(metadata_merged);if(metadata_user)CFRelease(metadata_user);
    if(key_a)CFRelease(key_a);if(key_b)CFRelease(key_b);
    if(unknown){fputs("keychain fixture retained unknown child cleanup\n",stderr);_Exit(1);}
}
static void failure(int line) { fprintf(stderr,"keychain fixture failed at line %d (errno %d)\n",line,errno);exit(1); }
#define CHECK(condition) do { checks++; if(!(condition))failure(__LINE__); } while(0)

/* Only exact synthetic registration/stage directories receive a root-owner
 * interpretation. All modes, inodes, links, file contents and filesystem
 * operations remain real. This does not validate actual root permissions. */
static int stage_path_kind(const char *path) {
    size_t size=strlen(fixture_registration);if(!size||strncmp(path,fixture_registration,size))return 0;
    if(!path[size])return 1;
    const char *prefix="/.keychain-selection-";size_t prefix_size=strlen(prefix);
    if(strncmp(path+size,prefix,prefix_size))return 0;
    const char *name=path+size+prefix_size;
    for(unsigned i=0;i<32;i++)if(!name[i]||!strchr("0123456789abcdef",name[i]))return 0;
    const char *tail=name+32;
    if(!*tail||!strcmp(tail,"/Library")||!strcmp(tail,"/Library/Preferences"))return 2;
    return !strcmp(tail,"/Library/Preferences/com.apple.security.plist")?3:0;
}
static void remember_stage_root(const char *path) {
    if(stage_path_kind(path)<2)return;
    size_t size=strlen(fixture_registration)+strlen("/.keychain-selection-")+32;
    CHECK(size<sizeof(last_stage_root));memcpy(last_stage_root,path,size);last_stage_root[size]=0;
}
static struct fixture_stage_file *stage_file_record(const struct stat *info) {
    for(unsigned i=0;i<fixture_stage_file_count;i++)if(fixture_stage_files[i].device==info->st_dev&&fixture_stage_files[i].inode==info->st_ino)return &fixture_stage_files[i];
    return NULL;
}
static int stage_home_path(const char *path) {
    return stage_path_kind(path)==2&&strlen(path)==strlen(fixture_registration)+strlen("/.keychain-selection-")+32;
}
static struct fixture_stage_home *stage_home_record(const struct stat *info) {
    for(unsigned i=0;i<fixture_stage_home_count;i++)if(fixture_stage_homes[i].device==info->st_dev&&fixture_stage_homes[i].inode==info->st_ino)return &fixture_stage_homes[i];
    return NULL;
}
static void map_stage_owner(const char *path,struct stat *info) {
    if(info->st_uid!=getuid())return;
    struct fixture_stage_home *home=stage_home_record(info);
    if(home){info->st_uid=home->owner;info->st_flags=home->flags;}
    else if(S_ISDIR(info->st_mode)&&stage_path_kind(path))info->st_uid=0;
    else if(S_ISREG(info->st_mode)){
        struct fixture_stage_file *record=stage_file_record(info);if(record&&!record->transferred)info->st_uid=0;
    }
}
static int path_at(int directory,const char *name,char out[PATH_MAX]) {
    if(name[0]=='/')return snprintf(out,PATH_MAX,"%s",name)>=PATH_MAX?-1:0;
    char parent[PATH_MAX];return fcntl(directory,F_GETPATH,parent)||snprintf(out,PATH_MAX,"%s/%s",parent,name)>=PATH_MAX?-1:0;
}
static int fixture_openat(int directory,const char *name,int flags,...) {
    mode_t mode=0;if(flags&O_CREAT){va_list args;va_start(args,flags);mode=(mode_t)va_arg(args,int);va_end(args);}
    char path[PATH_MAX];int kind=!path_at(directory,name,path)?stage_path_kind(path):0;
    if(kind>=2)remember_stage_root(path);
    if(stage_library_open_refused&&kind==2&&!strcmp(name,"Library")){stage_library_open_refused=0;errno=EACCES;return -1;}
    int fd=(flags&O_CREAT)?openat(directory,name,flags,mode):openat(directory,name,flags);
    if(fd>=0&&kind==2&&stage_home_path(path)){
        struct stat info;CHECK(fstat(fd,&info)==0&&S_ISDIR(info.st_mode)&&info.st_uid==getuid()&&!info.st_flags);
        if(!stage_home_record(&info)){
            CHECK(fixture_stage_home_count<8);fixture_stage_homes[fixture_stage_home_count++]=(struct fixture_stage_home){info.st_dev,info.st_ino,0,0};
        }
    }
    if(fd>=0&&kind==3&&(flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)){
        struct stat info;CHECK(fstat(fd,&info)==0&&info.st_uid==getuid()&&S_ISREG(info.st_mode)&&info.st_nlink==1);
        CHECK(fixture_stage_file_count<8);fixture_stage_files[fixture_stage_file_count++]=(struct fixture_stage_file){info.st_dev,info.st_ino,0};
    }
    return fd;
}
static int fixture_fstat(int fd,struct stat *info) {
    if(fd==fail_next_fd_fstat){fail_next_fd_fstat=-1;errno=EIO;return -1;}
    int result=fstat(fd,info);char path[PATH_MAX];if(!result&&!fcntl(fd,F_GETPATH,path)){
        if(fixture_command_active&&fixture_command_fault==COMMAND_HOLDS&&!strcmp(path,test_home)){errno=EIO;return -1;}
        if(stage_fail_first_identity&&S_ISDIR(info->st_mode)&&stage_path_kind(path)==2){stage_fail_first_identity=0;errno=EIO;return -1;}
        map_stage_owner(path,info);
    }return result;
}
static int fixture_lstat(const char *path,struct stat *info) {
    int result=lstat(path,info);if(!result)map_stage_owner(path,info);return result;
}
static int fixture_fstatat(int directory,const char *name,struct stat *info,int flags) {
    int result=fstatat(directory,name,info,flags);char path[PATH_MAX];if(!result&&!path_at(directory,name,path))map_stage_owner(path,info);return result;
}
static void swap_stage_library(int fd) {
    char root[PATH_MAX],library[PATH_MAX];struct stat actual;CHECK(!swapped_library[0]&&fstat(fd,&actual)==0&&actual.st_uid==getuid());
    CHECK(fcntl(fd,F_GETPATH,root)==0&&stage_home_path(root));
    snprintf(library,sizeof(library),"%s/Library",root);snprintf(swapped_library,sizeof(swapped_library),"%s/Library-fixture-raced",root);
    /* Inject the ownership-transition race using only our actual UID and
     * unflagged fixture directories, then restore the observed mode. */
    CHECK(fchmod(fd,0700)==0&&rename(library,swapped_library)==0&&mkdir(library,0755)==0&&fchmod(fd,actual.st_mode&07777)==0);
}
static int fixture_fchown(int fd,uid_t uid,gid_t gid) {
    struct stat info;if(fstat(fd,&info))return -1;CHECK(info.st_uid==getuid()&&!info.st_flags&&gid==(gid_t)-1);
    struct fixture_stage_home *home=stage_home_record(&info);
    if(home){
        CHECK(uid==0||uid==getuid());if(home->flags){errno=EPERM;return -1;}
        if(uid==getuid()){
            if(seal_owner_fail){errno=EPERM;return -1;}
            home->owner=uid;home_owner_changes++;
            if(seal_owner_readback){seal_owner_readback=0;fail_next_fd_fstat=fd;}
        }else {
            if(reclaim_owner_fail){errno=EPERM;return -1;}
            if(reclaim_swap){reclaim_swap=0;swap_stage_library(fd);}
            home->owner=0;home_reclaims++;
            if(reclaim_acl){reclaim_acl=0;home_acl_refused=1;}
            if(reclaim_owner_readback){reclaim_owner_readback=0;fail_next_fd_fstat=fd;}
        }
        return 0;
    }
    struct fixture_stage_file *record=stage_file_record(&info);
    CHECK(record&&uid==getuid()&&!record->transferred);record->transferred=1;
    {
        if(stage_fail_owner_readback){stage_fail_owner_readback=0;fail_next_fd_fstat=fd;}
    }
    return 0;
}
static int fixture_sysctl(int *name,u_int count,void *value,size_t *size,void *replacement,size_t replacement_size) {
    if(!name||count!=4||name[0]!=CTL_KERN||name[1]!=KERN_PROC||name[2]!=KERN_PROC_PID||
        !value||!size||*size!=sizeof(struct kinfo_proc)||replacement||replacement_size)abort();
    parent_sysctl_calls++;
    if(parent_fixture_active){
        if(name[3]!=parent_fixture_pid)abort();
        if(parent_sysctl_error){errno=parent_sysctl_error;return -1;}
        memcpy(value,&parent_fixture_record,sizeof(parent_fixture_record));*size=parent_reply_size;return 0;
    }
    if(!fixture_command_active||name[3]!=getppid())abort();
    if(fixture_command_fault==COMMAND_PARENT_IDENTITY){errno=EPERM;return -1;}
    /* The fixture parent is our ordinary-UID process. Only its birth is real;
     * root credentials are synthetic, with no cross-UID identity access. */
    struct envara_identity actual;if(actual_identity(getppid(),&actual))abort();
    struct kinfo_proc synthetic={0};synthetic.kp_proc.p_pid=actual.pid;
    synthetic.kp_proc.p_starttime.tv_sec=(time_t)actual.birth_seconds;
    synthetic.kp_proc.p_starttime.tv_usec=(suseconds_t)actual.birth_microseconds;
    memcpy(value,&synthetic,sizeof(synthetic));*size=sizeof(synthetic);return 0;
}
static int fixture_fchmod(int fd,mode_t mode) {
    struct stat info;CHECK(fstat(fd,&info)==0);struct fixture_stage_home *home=stage_home_record(&info);
    if(home){
        if(home->flags){errno=EPERM;return -1;}
        if(mode==0500&&seal_mode_fail){errno=EPERM;return -1;}
        if(mode==0700&&reclaim_mode_fail){errno=EPERM;return -1;}
    }
    int result=fchmod(fd,mode);char path[PATH_MAX];
    if(!result&&home){
        if(mode==0500&&seal_mode_readback){seal_mode_readback=0;fail_next_fd_fstat=fd;}
        if(mode==0700&&reclaim_mode_readback){reclaim_mode_readback=0;fail_next_fd_fstat=fd;}
    }
    if(!result&&stage_fail_mode_readback&&!fcntl(fd,F_GETPATH,path)&&stage_path_kind(path)==2){
        stage_fail_mode_readback=0;fail_next_fd_fstat=fd;
    }return result;
}
static int fixture_fchflags(int fd,unsigned int flags) {
    struct stat actual;CHECK(fstat(fd,&actual)==0&&actual.st_uid==getuid()&&!actual.st_flags);
    struct fixture_stage_home *home=stage_home_record(&actual);CHECK(home&&(flags==0||flags==SF_IMMUTABLE));
    if(flags){
        CHECK(home->owner==getuid()&&!home->flags&&(actual.st_mode&07777)==0500);
        if(seal_flags_fail){errno=EPERM;return -1;}
        if(seal_swap){seal_swap=0;swap_stage_library(fd);}
        home->flags=flags;home_seals++;
        if(seal_acl){seal_acl=0;home_acl_refused=1;}
        if(seal_flags_readback){seal_flags_readback=0;fail_next_fd_fstat=fd;}
    }else {
        CHECK(home->flags==SF_IMMUTABLE);
        if(clear_flags_fail){errno=EPERM;return -1;}
        home->flags=0;home_unseals++;
        if(clear_flags_readback){clear_flags_readback=0;fail_next_fd_fstat=fd;}
    }
    return 0;
}
static int fixture_sysctlbyname(const char *name,void *value,size_t *size,const void *replacement,size_t replacement_size) {
    CHECK(!strcmp(name,"kern.securelevel")&&value&&size&&*size==sizeof(int)&&!replacement&&!replacement_size);
    securelevel_reads++;if(securelevel_error){errno=EACCES;return -1;}
    memcpy(value,&securelevel_value,sizeof(securelevel_value));*size=securelevel_short?sizeof(int)-1:sizeof(int);return 0;
}
static int fixture_fsync(int fd) {
    char path[PATH_MAX],expected[PATH_MAX];snprintf(expected,sizeof(expected),"%s/Library/Preferences",test_home);
    if(publish_fsync_failure&&!fcntl(fd,F_GETPATH,path)&&!strcmp(path,expected)&&access(selector_path,F_OK)==0){
        publish_fsync_failure=0;published_fsync_failures++;errno=EIO;return -1;
    }return fsync(fd);
}
static int fixture_renameatx_np(int from,const char *source,int to,const char *destination,unsigned flags) {
    if(publish_hardlink_race){
        char path[PATH_MAX],target[PATH_MAX];CHECK(!path_at(from,source,path)&&stage_path_kind(path)==3&&
            !path_at(to,destination,target)&&!strcmp(target,selector_path)&&flags==RENAME_EXCL);
        CHECK(link(key_b_path,target)==0);publish_hardlink_race=0;publish_race_injected++;
    }
    return renameatx_np(from,source,to,destination,flags);
}

static OSStatus fixture_SecKeychainCopyDefault(SecKeychainRef *key) {
    security_reads++;*key=NULL;if(metadata_default_status)return metadata_default_status;
    *key=(SecKeychainRef)CFRetain(key_a);return errSecSuccess;
}
static OSStatus fixture_SecKeychainGetPath(SecKeychainRef key,UInt32 *size,char *path) {
    security_reads++;if(!key||CFGetTypeID((CFTypeRef)key)!=CFStringGetTypeID())return errSecParam;
    char value[PATH_MAX];if(!CFStringGetCString((CFStringRef)key,value,sizeof(value),kCFStringEncodingUTF8))return errSecParam;
    size_t length=strlen(value);if(*size<=length)return errSecBufferTooSmall;
    memcpy(path,value,length+1);*size=(UInt32)length;return errSecSuccess;
}
static OSStatus fixture_SecKeychainGetStatus(SecKeychainRef key,SecKeychainStatus *status) {
    (void)key;security_reads++;*status=metadata_flags;return metadata_status_error;
}
static OSStatus fixture_SecKeychainCopySearchList(CFArrayRef *list) {
    security_reads++;*list=NULL;if(metadata_search_error)return metadata_search_error;
    *list=(CFArrayRef)CFRetain(metadata_merged);return errSecSuccess;
}
static OSStatus fixture_SecKeychainCopyDomainSearchList(SecPreferencesDomain domain,CFArrayRef *list) {
    security_reads++;*list=NULL;if(domain!=kSecPreferencesDomainUser)return errSecParam;
    *list=(CFArrayRef)CFRetain(metadata_user);return errSecSuccess;
}
static CFTypeID fixture_SecKeychainGetTypeID(void) { return CFStringGetTypeID(); }
static OSStatus fixture_SecKeychainSetUserInteractionAllowed(Boolean allowed) {
    if(fixture_command_active)return allowed?errSecParam:errSecSuccess;
    unexpected_worker_calls++;return errSecParam;
}
static OSStatus fixture_SecKeychainGetUserInteractionAllowed(Boolean *allowed) {
    *allowed=!fixture_command_active;if(fixture_command_active)return errSecSuccess;
    unexpected_worker_calls++;return errSecParam;
}
static OSStatus fixture_SecKeychainOpen(const char *path,SecKeychainRef *key) {
    *key=NULL;if(fixture_command_active&&!strcmp(path,key_a_path)){*key=(SecKeychainRef)CFRetain(key_a);return errSecSuccess;}
    unexpected_worker_calls++;return errSecParam;
}
static OSStatus fixture_SecKeychainSetDefault(SecKeychainRef key) {
    security_setters++;return fixture_command_active&&key==(SecKeychainRef)key_a&&fixture_command_fault!=COMMAND_SET_DEFAULT?errSecSuccess:errSecParam;
}
static int fixture_sandbox_init(const char *profile,uint64_t flags,char **error) {
    *error=NULL;if(fixture_command_active)return !profile||flags||fixture_command_fault==COMMAND_SANDBOX?-1:0;
    unexpected_worker_calls++;return -1;
}
static void fixture_sandbox_free_error(char *error) { (void)error;unexpected_worker_calls++; }

int envara_identity_read(pid_t pid,struct envara_identity *out) {
    if(fixture_command_active&&pid==getppid()){parent_tbsd_calls++;errno=EPERM;return -1;}
    if(fixture_command_active&&fixture_command_fault==COMMAND_IDENTITY&&pid==getpid()){errno=EACCES;return -1;}
    if(pid==getpid()&&!owner_live){errno=EACCES;return -1;}
    if(actual_identity(pid,out))return -1;
    if(fixture_command_active&&pid==getpid())out->gid=out->rgid=out->saved_gid=test_request.realm_gid;
    else if(pid==getpid())out->uid=out->ruid=out->saved_uid=0;
    return 0;
}
int envara_identity_matches(const struct envara_identity *id,uid_t uid,gid_t gid) {
    return id&&id->uid==uid&&id->ruid==uid&&id->saved_uid==uid&&id->gid==gid&&id->rgid==gid&&id->saved_gid==gid;
}
int envara_same_process(const struct envara_identity *expected) {
    struct envara_identity actual;return expected&&!envara_identity_read(expected->pid,&actual)&&generation_equal(expected,&actual)&&
        expected->uid==actual.uid&&expected->ruid==actual.ruid&&expected->saved_uid==actual.saved_uid&&
        expected->gid==actual.gid&&expected->rgid==actual.rgid&&expected->saved_gid==actual.saved_gid;
}
int envara_root_owned_executable(const char *path) { return !strcmp(path,ENVARA_GUI_NATIVE_PATH); }
static int fixture_proc_pidpath(int pid,void *buffer,uint32_t size) {
    if(pid!=getpid()&&!(fixture_command_active&&pid==getppid())&&!find_child(pid))return 0;
    size_t length=strlen(ENVARA_GUI_NATIVE_PATH);if(length>=size)return 0;
    memcpy(buffer,ENVARA_GUI_NATIVE_PATH,length+1);return (int)length;
}
int envara_gui_session_read(struct envara_gui_session *out) {
    memset(out,0,sizeof(*out));out->console_uid=getuid();out->audit_session=test_request.gui_audit_session;
    out->audit_has_console_graphics=out->security_has_graphics=1;return 0;
}
int envara_gui_acl_free(const char *path) {
    if(home_acl_refused&&stage_home_path(path)){errno=EACCES;return -1;}
    acl_t acl=acl_get_file(path,ACL_TYPE_EXTENDED);if(!acl)return errno==ENOENT?0:-1;
    acl_entry_t entry;errno=0;int got=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);int result=got==-1&&errno==EINVAL?0:-1;
    acl_free(acl);return result;
}
int envara_app_scope_gid_absent(gid_t gid) { scope_calls++;CHECK(gid==test_request.realm_gid);return scope_absent; }
static pid_t fixture_waitpid(pid_t pid,int *status,int options) {
    wait_calls++;if(pid<2||!find_child(pid)){forbidden_waits++;errno=ECHILD;return -1;}
    if(fixture_wait_stays_pending){last_wait_zero_pid=pid;return 0;}
    if(expect_birth_missing_wait)CHECK(owned_slot&&owned_slot->active&&owned_slot->wait_proof==KC_OWNED_UNREAPED&&
        owned_slot->child.identity.pid==pid&&!owned_slot->child.identity.birth_seconds&&!find_child(pid)->reaped);
    pid_t got=waitpid(pid,status,options);last_wait_zero_pid=got==0?pid:0;
    if(got==pid&&(WIFEXITED(*status)||WIFSIGNALED(*status)))find_child(pid)->reaped=1;
    return got;
}
static int fixture_kill(pid_t pid,int signal_number) {
    struct fixture_child *known=find_child(pid);
    CHECK(pid>1&&known&&!known->reaped&&owned_slot&&owned_slot->active&&owned_slot->child.identity.pid==pid&&
        owned_slot->wait_proof==KC_OWNED_UNREAPED&&last_wait_zero_pid==pid&&signal_number==SIGKILL);
    module_signal_calls++;return kill(pid,signal_number);
}
static int fixture_sigaction(int signal_number,const struct sigaction *action,struct sigaction *previous) {
    if(action){module_signal_policy_writes++;errno=EACCES;return -1;}
    CHECK(signal_number==SIGCHLD);
    if(policy_read_refused){errno=EACCES;return -1;}
    return sigaction(signal_number,NULL,previous);
}
int envara_child_cancel(struct envara_child *child) {
    struct fixture_child *known=child?find_child(child->identity.pid):NULL;struct envara_identity now;
    if(!known||known->reaped||actual_identity(child->identity.pid,&now)||now.parent_pid!=getpid()||!generation_equal(&now,&known->identity))return -1;
    return kill(child->identity.pid,SIGKILL);
}

enum fixture_reply_fault { FRAME_OK, FRAME_TRAILING, FRAME_NONCE, FRAME_SCHEMA, FRAME_RESULT, FRAME_UNTERMINATED, FRAME_ECHILD, FRAME_NO_CHILD, FRAME_BIRTH_MISSING, FRAME_STOPPED_BIRTH_MISSING };
struct fixture_step {
    enum kc_mode mode; enum kc_result result; enum fixture_reply_fault fault; int host_changed;
    int exit_status; enum fixture_command_fault command_fault;
};
static struct fixture_step steps[8];static unsigned step_count, step_index;
static void add_step(enum kc_mode mode,enum kc_result result,enum fixture_reply_fault fault,int host_changed) {
    CHECK(step_count<8);steps[step_count++]=(struct fixture_step){.mode=mode,.result=result,.fault=fault,.host_changed=host_changed};
}
static int deny_verified(const struct envara_gui_request *request,void *context) {
    (void)context;return memcmp(request,&test_request,sizeof(test_request))? -1:0;
}
static const struct envara_gui_stage_authority authority={deny_verified,NULL};
static void close_child_fds(int input,int output) {
    int bytes=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,NULL,0);if(bytes<=0||bytes>1024*1024)_exit(81);
    size_t capacity=(size_t)bytes+32*sizeof(struct proc_fdinfo);struct proc_fdinfo *entries=calloc(1,capacity);if(!entries)_exit(82);
    bytes=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,entries,(int)capacity);if(bytes<=0||(size_t)bytes>=capacity)_exit(83);
    for(size_t i=0;i<(size_t)bytes/sizeof(*entries);i++){int fd=entries[i].proc_fd;if(fd>=3&&fd!=input&&fd!=output)close(fd);}
    free(entries);
}
static void fake_worker(int input,int output,struct fixture_step step,const char *home) {
    close_child_fds(input,output);if(raise(SIGSTOP))_exit(84);
    if(step.command_fault!=COMMAND_NONE){
        fixture_command_active=1;fixture_command_fault=step.command_fault;
        if(dup2(input,STDIN_FILENO)<0||dup2(output,STDOUT_FILENO)<0||
            setenv("HOME",step.command_fault==COMMAND_HOME?fixture_root:home,1))_exit(92);
        if(input>STDOUT_FILENO)close(input);if(output>STDOUT_FILENO)close(output);
        if(step.command_fault==COMMAND_METADATA)metadata_default_status=errSecParam;
        char *arguments[]={"fixture",step.command_fault==COMMAND_ENTRY?"invalid-entry":"app-keychain-helper",NULL};
        int status=envara_app_keychain_command(2,arguments);
        unsigned expected_parent_reads=step.command_fault==COMMAND_ENTRY||step.command_fault==COMMAND_IDENTITY?0:1;
        if(unexpected_worker_calls||parent_tbsd_calls||parent_sysctl_calls!=expected_parent_reads||
            (step.command_fault==COMMAND_SET_DEFAULT?security_setters!=1:security_setters!=0))_exit(93);
        _exit(status);
    }
    struct kc_request request;int64_t deadline=now_ms()+3000;
    if(transfer(input,&request,sizeof(request),0,deadline)||!no_more_input(input,deadline)||request.mode!=(uint32_t)step.mode||
        strcmp(request.home,test_home)||request.schema!=KC_SCHEMA||request.generation!=step_index)_exit(85);
    if(step.exit_status)_exit(step.exit_status);
    if(step.mode==KC_SELECT){
        if(strcmp(request.selected,key_a_path))_exit(86);
        struct kc_holds holds;struct kc_stage stage;stage_init(&stage);
        if(holds_open(request.home,request.uid,0,&holds)||stage_load(&stage,&holds,&request)||stage_check(&stage,request.uid))_exit(87);
        if(!strcmp(request.selector_home,request.home)||access(selector_path,F_OK)==0)_exit(90);
        int fd=openat(stage.fds[2],"com.apple.security.plist",O_WRONLY|O_TRUNC|O_NOFOLLOW);struct stat before,after;
        const char payload[]="synthetic-selector-v1\n";
        if(fd<0||fstat(fd,&before)||!file_matches(&before,&request.selector_file)||
            write(fd,payload,sizeof(payload)-1)!=(ssize_t)sizeof(payload)-1||fstat(fd,&after)||
            !file_matches(&after,&request.selector_file)||stage_check(&stage,request.uid))_exit(91);
        close(fd);stage_release_fds(&stage);holds_close(&holds);
    }
    struct kc_reply reply={0};reply.schema=KC_SCHEMA;reply.result=step.result;memcpy(reply.nonce,request.nonce,sizeof(reply.nonce));
    if(step.result==KC_OK&&step.mode!=KC_SELECT){
        strcpy(reply.selected,key_a_path);reply.merged_count=2;reply.user_count=1;
        memset(reply.merged_digest,step.host_changed?22:11,sizeof(reply.merged_digest));memset(reply.user_digest,33,sizeof(reply.user_digest));
    }
    if(step.fault==FRAME_NONCE)reply.nonce[0]^=1;
    if(step.fault==FRAME_SCHEMA)reply.schema++;
    if(step.fault==FRAME_RESULT)reply.result=99;
    if(step.fault==FRAME_UNTERMINATED)memset(reply.selected,'x',sizeof(reply.selected));
    if(transfer(output,&reply,sizeof(reply),1,deadline))_exit(88);
    if(step.fault==FRAME_TRAILING){unsigned char extra=1;if(transfer(output,&extra,1,1,deadline))_exit(89);}
    close(output);close(input);_exit(0);
}
int envara_spawn_suspended_io(uid_t uid,gid_t gid,const char *cwd,const char *executable,char *const argv[],char *const environment[],
    int fixture_mode,int input,int output,struct envara_child *out) {
    CHECK(uid==getuid()&&gid==test_request.realm_gid&&!strcmp(cwd,test_home)&&!strcmp(executable,ENVARA_GUI_NATIVE_PATH));
    CHECK(!strcmp(argv[1],"app-keychain-helper")&&environment&&!fixture_mode&&step_index<step_count);
    struct fixture_step step=steps[step_index++];spawn_calls++;if(step.mode==KC_SELECT)selector_writes++;
    if(step.mode==KC_SELECT){
        CHECK(owned_slot&&owned_slot->stage.parent_fd>=0&&!strncmp(environment[0],"HOME=",5)&&
            !strcmp(environment[0]+5,owned_slot->stage.paths[0]));
        if(scope_unknown_at_select)scope_absent=0;
    }
    if(step.fault==FRAME_NO_CHILD){errno=EACCES;return -1;}
    CHECK(fixture_child_count<16);int errors[2];CHECK(pipe(errors)==0);
    pid_t pid=fork();CHECK(pid>=0);if(!pid){
        if(step.fault==FRAME_BIRTH_MISSING)_exit(0);
        if(step.fault==FRAME_STOPPED_BIRTH_MISSING){close_child_fds(input,output);if(raise(SIGSTOP))_exit(84);for(;;)pause();}
        fake_worker(input,output,step,environment[0]+5);
    }
    /* Register custody before assertions about stop state, so a failed test
     * still reaps precisely the child it just created. */
    struct fixture_child *known=&fixture_children[fixture_child_count++];known->identity.pid=pid;
    CHECK(actual_identity(pid,&known->identity)==0);out->identity=known->identity;
    if(step.fault==FRAME_BIRTH_MISSING){
        close(errors[1]);out->error_fd=errors[0];last_error_fd=errors[0];
        /* Observe the fixture child's actual zombie state without any wait.
         * Only production cleanup may consume its terminal status. The full
         * identity remains fixture-private; launcher output has no birth. */
        int zombie=0;int64_t deadline=now_ms()+2000;
        while(now_ms()<deadline){struct proc_bsdinfo info={0};
            if(proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&info,sizeof(info))==sizeof(info)&&info.pbi_status==SZOMB){zombie=1;break;}
            struct timespec delay={0,1000000};(void)nanosleep(&delay,NULL);
        }
        CHECK(zombie&&!known->reaped&&wait_calls==0);
        memset(&out->identity,0,sizeof(out->identity));out->identity.pid=pid;out->identity.parent_pid=getpid();
        expect_birth_missing_wait=1;errno=EACCES;return -1;
    }
    close(errors[1]);int status;CHECK(wait_owned_event(pid,&status,1,2000)==pid&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP);
    if(step.fault==FRAME_STOPPED_BIRTH_MISSING){
        memset(&out->identity,0,sizeof(out->identity));out->identity.pid=pid;out->identity.parent_pid=getpid();
        out->error_fd=errors[0];last_error_fd=errors[0];expect_birth_missing_wait=1;errno=EACCES;return -1;
    }
    out->error_fd=errors[0];last_error_fd=errors[0];return 0;
}
int envara_child_resume(struct envara_child *child) {
    CHECK(child&&find_child(child->identity.pid));CHECK(kill(child->identity.pid,SIGCONT)==0);
    if(steps[step_index-1].fault==FRAME_ECHILD){int status;CHECK(wait_owned_event(child->identity.pid,&status,0,2000)==child->identity.pid&&WIFEXITED(status));}
    return 0;
}

static void make_file(const char *path) { int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);CHECK(fd>=0);CHECK(close(fd)==0); }
static void setup(const char *root) {
    struct stat s;char canonical[PATH_MAX];CHECK(getuid()!=0&&getuid()==geteuid());
    CHECK(realpath(root,canonical)&&!strcmp(canonical,root)&&lstat(root,&s)==0&&S_ISDIR(s.st_mode)&&s.st_uid==getuid()&&(s.st_mode&07777)==0700);
    CHECK(strlen(root)+160<PATH_MAX);strcpy(fixture_root,root);
    memset(&test_app,0,sizeof(test_app));memset(&test_request,0,sizeof(test_request));
    strcpy(test_app.registration_id,"22222222-2222-4222-8222-222222222222");strcpy(test_app.version_id,"33333333-3333-4333-8333-333333333333");
    strcpy(test_request.environment_id,"44444444-4444-4444-8444-444444444444");strcpy(test_request.lease_id,"55555555-5555-4555-8555-555555555555");
    test_request.console_uid=getuid();test_request.realm_gid=ENVARA_REALM_GID_MIN;test_request.gui_audit_session=1;
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/%s",root,test_request.environment_id);CHECK(mkdir(path,0700)==0);
    snprintf(path,sizeof(path),"%s/%s/%s",root,test_request.environment_id,test_app.registration_id);CHECK(mkdir(path,0755)==0);strcpy(fixture_registration,path);
    CHECK(expected_home(test_request.environment_id,test_app.registration_id,test_home)==0);CHECK(mkdir(test_home,0700)==0);
    /* The real root-owned sibling staging path is deliberately outside this
     * unprivileged fixture. Exercise existing owned directories instead. */
    snprintf(path,sizeof(path),"%s/Library",test_home);CHECK(mkdir(path,0700)==0);
    snprintf(path,sizeof(path),"%s/Library/Preferences",test_home);CHECK(mkdir(path,0700)==0);
    snprintf(selector_path,sizeof(selector_path),"%s/Library/Preferences/com.apple.security.plist",test_home);
    snprintf(key_a_path,sizeof(key_a_path),"%s/synthetic-key-a",root);snprintf(key_b_path,sizeof(key_b_path),"%s/synthetic-key-b",root);
    make_file(key_a_path);make_file(key_b_path);
    key_a=CFStringCreateWithCString(NULL,key_a_path,kCFStringEncodingUTF8);key_b=CFStringCreateWithCString(NULL,key_b_path,kCFStringEncodingUTF8);CHECK(key_a&&key_b);
    const void *keys[]={key_a,key_b};metadata_merged=CFArrayCreate(NULL,keys,2,&kCFTypeArrayCallBacks);metadata_user=CFArrayCreate(NULL,keys,1,&kCFTypeArrayCallBacks);
}
static envara_app_keychain_custody *new_slot(void) {
    envara_app_keychain_custody *slot=NULL;CHECK(envara_app_keychain_custody_create(&test_app,&test_request,test_run,&slot)==0&&slot);
    return slot;
}
static void prepare_holds(struct kc_holds *holds) { CHECK(holds_open(test_home,getuid(),1,holds)==0); }
static int run_one(envara_app_keychain_custody *slot,struct kc_reply *reply) {
    struct kc_holds holds;prepare_holds(&holds);int result=run_helper(slot,&holds,KC_SCOPED,NULL,&authority,now_ms()+5000,reply);holds_close(&holds);return result;
}
static int cleanup_public(envara_app_keychain_custody *slot) { return envara_app_keychain_custody_cleanup(slot,&test_app,&test_request,test_run); }
static struct envara_app_keychain_snapshot snapshot(envara_app_keychain_custody *slot) {
    struct envara_app_keychain_snapshot out;CHECK(envara_app_keychain_custody_snapshot(slot,&test_app,&test_request,test_run,&out)==0);return out;
}
static int actual_child_state(pid_t pid) {
    struct proc_bsdinfo info={0};
    return proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&info,sizeof(info))==sizeof(info)?(int)info.pbi_status:-1;
}
static void observe_zombie(pid_t pid) {
    int64_t deadline=now_ms()+2000;
    while(now_ms()<deadline){if(actual_child_state(pid)==SZOMB)return;struct timespec delay={0,1000000};(void)nanosleep(&delay,NULL);}
    CHECK(0);
}
static void pipe_identity_case(void) {
    int channel[2],other[2];CHECK(pipe(channel)==0&&pipe(other)==0);
    struct stat observed;CHECK(fstat(channel[0],&observed)==0&&S_ISFIFO(observed.st_mode)&&observed.st_nlink==0&&observed.st_uid==getuid());
    struct kc_file captured=file_identity(&observed);captured.owner=0;
    /* Darwin reports the observing UID for an anonymous pipe. This models
     * the root parent's metadata, using the real inherited-endpoint fields;
     * no credential transition or root-parent authority is claimed here. */
    CHECK(pipe_identity(channel[0],O_RDONLY,NULL));
    CHECK(pipe_identity(channel[0],O_RDONLY,&captured));
    CHECK(!pipe_identity(channel[0],O_WRONLY,&captured));
    CHECK(!pipe_identity(other[0],O_RDONLY,&captured));
    CHECK(!pipe_identity(channel[1],O_WRONLY,&captured));
    struct kc_file changed=captured;changed.inode^=1;CHECK(!pipe_identity(channel[0],O_RDONLY,&changed));
    changed=captured;changed.mode^=S_IRUSR;CHECK(!pipe_identity(channel[0],O_RDONLY,&changed));
    CHECK(fstat(channel[1],&observed)==0&&observed.st_uid==getuid());captured=file_identity(&observed);captured.owner=0;
    CHECK(pipe_identity(channel[1],O_WRONLY,&captured));
    int regular=open(key_a_path,O_RDONLY|O_NOFOLLOW);CHECK(regular>=0&&fstat(regular,&observed)==0);
    captured=file_identity(&observed);CHECK(file_matches(&observed,&captured));
    CHECK(!pipe_identity(regular,O_RDONLY,&captured));
    captured.owner=0;CHECK(!file_matches(&observed,&captured));
    CHECK(close(regular)==0);
    for(int i=0;i<2;i++)CHECK(close(channel[i])==0&&close(other[i])==0);
    CHECK(!security_reads&&!security_setters&&!spawn_calls);
}
static void metadata_case(void) {
    struct kc_reply reply={0};metadata_default_status=errSecNoDefaultKeychain;unsigned before=security_reads;
    CHECK(metadata(&reply,getuid())==0&&reply.result==KC_ABSENT&&security_reads==before+1);
    metadata_default_status=0;memset(&reply,0,sizeof(reply));CHECK(metadata(&reply,getuid())==0&&reply.result==KC_OK&&!reply.unlocked&&reply.merged_count==2&&reply.user_count==1);
    metadata_flags=kSecUnlockStateStatus;memset(&reply,0,sizeof(reply));CHECK(metadata(&reply,getuid())==0&&reply.unlocked==1);
    metadata_status_error=errSecInteractionNotAllowed;CHECK(metadata(&reply,getuid())==-1);metadata_status_error=0;
    metadata_search_error=errSecNotAvailable;CHECK(metadata(&reply,getuid())==-1);metadata_search_error=0;
    CFRelease(metadata_merged);const void *only_b[]={key_b};metadata_merged=CFArrayCreate(NULL,only_b,1,&kCFTypeArrayCallBacks);CHECK(metadata(&reply,getuid())==-1);
    const void *ab[]={key_a,key_b},*ba[]={key_b,key_a};CFArrayRef first=CFArrayCreate(NULL,ab,2,&kCFTypeArrayCallBacks),second=CFArrayCreate(NULL,ba,2,&kCFTypeArrayCallBacks);
    unsigned char digest_a[CC_SHA256_DIGEST_LENGTH],digest_b[CC_SHA256_DIGEST_LENGTH];uint32_t count;int contains;
    CHECK(search_digest(first,key_a_path,digest_a,&count,&contains)==0&&count==2&&contains);
    CHECK(search_digest(second,key_a_path,digest_b,&count,&contains)==0&&count==2&&contains&&memcmp(digest_a,digest_b,sizeof(digest_a)));
    CFMutableArrayRef too_many=CFArrayCreateMutable(NULL,65,&kCFTypeArrayCallBacks);for(int i=0;i<65;i++)CFArrayAppendValue(too_many,key_a);
    CHECK(search_digest(too_many,key_a_path,digest_a,&count,&contains)==-1);
    int number=7;CFNumberRef wrong=CFNumberCreate(NULL,kCFNumberIntType,&number);const void *bad[]={wrong};CFArrayRef bad_array=CFArrayCreate(NULL,bad,1,&kCFTypeArrayCallBacks);
    CHECK(search_digest(bad_array,key_a_path,digest_a,&count,&contains)==-1);
    CFRelease(bad_array);CFRelease(wrong);CFRelease(too_many);CFRelease(first);CFRelease(second);
}
static void paths_case(void) {
    struct kc_holds holds;prepare_holds(&holds);CHECK(holds_check(&holds,getuid())==0&&selector_state(&holds,getuid())==0);
    make_file(selector_path);CHECK(selector_state(&holds,getuid())==1);CHECK(chmod(selector_path,0660)==0&&selector_state(&holds,getuid())==-1);CHECK(chmod(selector_path,0600)==0);
    char link_path[PATH_MAX];snprintf(link_path,sizeof(link_path),"%s/second-link",fixture_root);CHECK(link(selector_path,link_path)==0&&selector_state(&holds,getuid())==-1);
    CHECK(unlink(link_path)==0&&unlink(selector_path)==0&&symlink(key_a_path,selector_path)==0&&selector_state(&holds,getuid())==-1);CHECK(unlink(selector_path)==0);
    CHECK(chmod(holds.paths[2],0720)==0&&holds_check(&holds,getuid())==-1);CHECK(chmod(holds.paths[2],0700)==0);
    char saved[PATH_MAX];snprintf(saved,sizeof(saved),"%s/Library/SavedPreferences",test_home);CHECK(rename(holds.paths[2],saved)==0&&mkdir(holds.paths[2],0700)==0);
    CHECK(holds_check(&holds,getuid())==-1);CHECK(rmdir(holds.paths[2])==0&&rename(saved,holds.paths[2])==0);holds_close(&holds);
    char library[PATH_MAX];snprintf(library,sizeof(library),"%s/Library",test_home);snprintf(saved,sizeof(saved),"%s/SavedLibrary",test_home);
    CHECK(rename(library,saved)==0&&symlink(saved,library)==0);CHECK(holds_open(test_home,getuid(),0,&holds)==-1);
    CHECK(unlink(library)==0&&rename(saved,library)==0);CHECK(chmod(test_home,0770)==0&&holds_open(test_home,getuid(),0,&holds)==-1);CHECK(chmod(test_home,0700)==0);
}
static void protocol_case(enum fixture_reply_fault fault) {
    envara_app_keychain_custody *slot=new_slot();struct kc_reply reply={0};add_step(KC_SCOPED,KC_OK,fault,0);
    int result=run_one(slot,&reply);CHECK((result==0)==(fault==FRAME_OK));CHECK(step_index==1);
    CHECK(cleanup_public(slot)==1);CHECK(!envara_app_keychain_custody_pending(slot,&test_app,&test_request,test_run));
    CHECK(envara_app_keychain_custody_destroy(slot)==0);CHECK(forbidden_waits==0);
}
static void custody_case(const char *mode) {
    envara_app_keychain_custody *slot=new_slot();struct kc_reply reply={0};
    if(!strcmp(mode,"inactive-scope")){
        add_step(KC_SCOPED,KC_OK,FRAME_OK,0);CHECK(run_one(slot,&reply)==0&&snapshot(slot).pending==0);
        unsigned queried=scope_calls,waited=wait_calls;scope_absent=0;CHECK(cleanup_public(slot)==0&&scope_calls==queried+1);
        scope_absent=1;CHECK(cleanup_public(slot)==1&&scope_calls==queried+2&&wait_calls==waited);
        CHECK(envara_app_keychain_custody_destroy(slot)==0);return;
    }
    scope_absent=0;
    enum fixture_reply_fault fault=!strcmp(mode,"launcher-clear")?FRAME_NO_CHILD:!strcmp(mode,"birth-missing")?FRAME_BIRTH_MISSING:!strcmp(mode,"echild")?FRAME_ECHILD:FRAME_OK;
    add_step(KC_SCOPED,KC_OK,fault,0);CHECK(run_one(slot,&reply)==-1);CHECK(envara_app_keychain_custody_pending(slot,&test_app,&test_request,test_run)==1);
    unsigned waited=wait_calls;struct envara_app_keychain_snapshot state=snapshot(slot);CHECK(state.pending&&state.generation==1);
    if(fault==FRAME_NO_CHILD){CHECK(state.child_state==ENVARA_APP_KEYCHAIN_LAUNCHER_CLEAR&&waited==0&&last_error_fd==-1);}
    else if(fault==FRAME_ECHILD)CHECK(state.child_state==ENVARA_APP_KEYCHAIN_UNKNOWN);
    else CHECK(state.child_state==ENVARA_APP_KEYCHAIN_REAPED);
    if(fault==FRAME_BIRTH_MISSING)CHECK(waited==1&&fixture_children[0].reaped&&!slot->child.identity.birth_seconds&&!slot->scope_confirmed);
    if(last_error_fd>=0)CHECK(fcntl(last_error_fd,F_GETFD)>=0);
    CHECK(envara_app_keychain_custody_destroy(slot)==-1&&errno==EBUSY);
    if(!strcmp(mode,"active-refusal")){
        unsigned spawned=spawn_calls;
        CHECK(run_one(slot,&reply)==-1&&spawn_calls==spawned);
        CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&spawn_calls==spawned);
        CHECK(snapshot(slot).pending==1&&wait_calls==waited);
    }
    if(!strcmp(mode,"binding")){
        struct envara_app_registration changed_app=test_app;changed_app.sequence++;
        struct envara_gui_request changed_request=test_request;changed_request.realm_gid++;
        const char *changed_run="88888888-8888-4888-8888-888888888888";unsigned queried=scope_calls;
        CHECK(envara_app_keychain_custody_pending(slot,&changed_app,&test_request,test_run)==-1);
        CHECK(envara_app_keychain_custody_cleanup(slot,&test_app,&changed_request,test_run)==-1);
        CHECK(envara_app_keychain_custody_snapshot(slot,&test_app,&test_request,changed_run,&state)==-1);
        CHECK(wait_calls==waited&&scope_calls==queried);
    }
    if(!strcmp(mode,"owner-unknown")){
        owner_live=0;unsigned queried=scope_calls;CHECK(snapshot(slot).pending==1);
        CHECK(envara_app_keychain_custody_pending(slot,&test_app,&test_request,test_run)==1);
        CHECK(cleanup_public(slot)==-1&&scope_calls==queried&&wait_calls==waited);CHECK(envara_app_keychain_custody_destroy(slot)==-1);owner_live=1;
    }
    scope_absent=1;
    if(fault==FRAME_ECHILD){CHECK(cleanup_public(slot)==0&&snapshot(slot).child_state==ENVARA_APP_KEYCHAIN_UNKNOWN&&wait_calls==waited);CHECK(envara_app_keychain_custody_destroy(slot)==-1);}
    else {CHECK(cleanup_public(slot)==1&&wait_calls==waited);if(last_error_fd>=0)CHECK(fcntl(last_error_fd,F_GETFD)==-1&&errno==EBADF);CHECK(envara_app_keychain_custody_destroy(slot)==0);}
    CHECK(forbidden_waits==0);
}
static void stopped_birth_case(int unknown_policy) {
    envara_app_keychain_custody *slot=new_slot();struct kc_reply reply={0};scope_absent=0;
    add_step(KC_SCOPED,KC_OK,FRAME_STOPPED_BIRTH_MISSING,0);CHECK(run_one(slot,&reply)==-1);
    pid_t pid=slot->child.identity.pid;struct envara_app_keychain_snapshot state=snapshot(slot);
    CHECK(state.pending&&state.child_state==ENVARA_APP_KEYCHAIN_UNWAITED&&pid>1&&!slot->child.identity.birth_seconds&&
        !fixture_children[0].reaped&&actual_child_state(pid)==SSTOP&&module_signal_calls==0);
    CHECK(envara_app_keychain_custody_destroy(slot)==-1&&fcntl(last_error_fd,F_GETFD)>=0);
    if(unknown_policy){
        policy_read_refused=1;unsigned waited=wait_calls;
        CHECK(cleanup_public(slot)==0&&wait_calls==waited+1&&module_signal_calls==0&&actual_child_state(pid)==SSTOP);
        CHECK(snapshot(slot).child_state==ENVARA_APP_KEYCHAIN_UNWAITED&&!fixture_children[0].reaped);
        policy_read_refused=0;
    }
    CHECK(cleanup_public(slot)==0&&module_signal_calls==1);
    observe_zombie(pid);CHECK(!fixture_children[0].reaped);
    CHECK(cleanup_public(slot)==0&&module_signal_calls==1&&fixture_children[0].reaped);
    state=snapshot(slot);CHECK(state.pending&&state.child_state==ENVARA_APP_KEYCHAIN_REAPED&&!slot->scope_confirmed&&fcntl(last_error_fd,F_GETFD)>=0);
    unsigned waited=wait_calls;scope_absent=1;CHECK(cleanup_public(slot)==1&&wait_calls==waited&&module_signal_calls==1);
    CHECK(fcntl(last_error_fd,F_GETFD)==-1&&errno==EBADF);CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void launch_policy_case(int no_child_wait) {
    envara_app_keychain_custody *slot=new_slot();struct kc_reply reply={0};struct sigaction replacement={0},installed={0},current={0};
    CHECK(sigaction(SIGCHLD,NULL,&saved_sigchld)==0);saved_sigchld_active=1;
    replacement.sa_handler=no_child_wait?SIG_DFL:SIG_IGN;replacement.sa_flags=no_child_wait?SA_NOCLDWAIT:0;sigemptyset(&replacement.sa_mask);
    CHECK(sigaction(SIGCHLD,&replacement,NULL)==0);
    /* Compare with the OS's installed representation: Darwin may normalize
     * SIG_IGN into an additional SA_NOCLDWAIT flag. */
    CHECK(sigaction(SIGCHLD,NULL,&installed)==0&&installed.sa_handler==replacement.sa_handler&&
        (!no_child_wait||(installed.sa_flags&SA_NOCLDWAIT)));
    add_step(KC_SCOPED,KC_OK,FRAME_OK,0);
    CHECK(run_one(slot,&reply)==-1&&spawn_calls==0&&fixture_child_count==0&&wait_calls==0);
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&spawn_calls==0);
    CHECK(sigaction(SIGCHLD,NULL,&current)==0&&current.sa_handler==installed.sa_handler&&current.sa_flags==installed.sa_flags&&
        !memcmp(&current.sa_mask,&installed.sa_mask,sizeof(current.sa_mask))&&module_signal_policy_writes==0);
    CHECK(snapshot(slot).pending==0&&snapshot(slot).generation==0&&module_signal_calls==0);
    CHECK(sigaction(SIGCHLD,&saved_sigchld,NULL)==0);saved_sigchld_active=0;
    CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static const char staged_payload[]="synthetic-staged-selector\n";
static const char protected_payload[]="fixture-content-must-survive\n";
static void write_text(int fd,const char *text) {
    size_t size=strlen(text);CHECK(ftruncate(fd,0)==0&&pwrite(fd,text,size,0)==(ssize_t)size);
}
static void write_path_text(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_NOFOLLOW);CHECK(fd>=0);write_text(fd,text);CHECK(close(fd)==0);
}
static void check_text(const char *path,const char *text) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW);CHECK(fd>=0);char buffer[256];ssize_t size=read(fd,buffer,sizeof(buffer));
    CHECK(size==(ssize_t)strlen(text)&&!memcmp(buffer,text,(size_t)size));CHECK(close(fd)==0);
}
static void check_absent(const char *path) { struct stat info;CHECK(lstat(path,&info)==-1&&errno==ENOENT); }
static void same_inode(const struct stat *expected,const char *path) {
    struct stat actual;CHECK(lstat(path,&actual)==0&&actual.st_dev==expected->st_dev&&actual.st_ino==expected->st_ino);
}
static envara_app_keychain_custody *open_direct_stage(struct kc_holds *holds) {
    envara_app_keychain_custody *slot=new_slot();prepare_holds(holds);CHECK(stage_open(slot,holds,getuid())==0);
    CHECK(stage_check(&slot->stage,getuid())==0&&slot->stage.file_present&&slot->stage.file_fd>=0);
    struct stat actual;CHECK(fstat(slot->stage.file_fd,&actual)==0&&actual.st_uid==getuid()&&actual.st_nlink==1&&
        (actual.st_mode&07777)==0600&&actual.st_size==0);
    CHECK(fixture_fstat(slot->stage.fds[0],&actual)==0&&actual.st_uid==getuid()&&(actual.st_mode&07777)==0500&&actual.st_flags==SF_IMMUTABLE);
    CHECK(home_seals==1&&!home_unseals&&securelevel_reads==1);
    CHECK(envara_app_keychain_custody_destroy(slot)==-1);write_text(slot->stage.file_fd,staged_payload);return slot;
}
static void direct_stage_case(const char *mode) {
    struct kc_holds holds;envara_app_keychain_custody *slot=open_direct_stage(&holds);struct kc_stage *stage=&slot->stage;
    char root[PATH_MAX],file[PATH_MAX],extra[PATH_MAX];strcpy(root,stage->paths[0]);
    snprintf(file,sizeof(file),"%s/com.apple.security.plist",stage->paths[2]);
    struct stat original;CHECK(fstat(stage->file_fd,&original)==0);
    if(!strcmp(mode,"stage-publish-inode")){
        CHECK(stage_publish(stage,&holds,getuid())==0&&!stage->file_present);same_inode(&original,selector_path);check_text(selector_path,staged_payload);
        CHECK(stage_close(stage,getuid())==0);check_absent(root);same_inode(&original,selector_path);check_text(selector_path,staged_payload);
    }else if(!strcmp(mode,"stage-existing-destination")){
        make_file(selector_path);write_path_text(selector_path,protected_payload);struct stat destination;CHECK(lstat(selector_path,&destination)==0);
        CHECK(stage_publish(stage,&holds,getuid())==-1);same_inode(&original,file);same_inode(&destination,selector_path);check_text(selector_path,protected_payload);
        CHECK(stage_close(stage,getuid())==0);check_absent(root);same_inode(&destination,selector_path);check_text(selector_path,protected_payload);
    }else if(!strcmp(mode,"stage-hardlink-race")){
        write_path_text(key_b_path,protected_payload);struct stat victim;CHECK(lstat(key_b_path,&victim)==0);
        publish_hardlink_race=1;CHECK(stage_publish(stage,&holds,getuid())==-1&&publish_race_injected==1);
        same_inode(&victim,key_b_path);same_inode(&victim,selector_path);check_text(key_b_path,protected_payload);check_text(selector_path,protected_payload);
        same_inode(&original,file);check_text(file,staged_payload);CHECK(stage_close(stage,getuid())==0);check_absent(root);
        same_inode(&victim,selector_path);check_text(key_b_path,protected_payload);
    }else if(!strcmp(mode,"stage-replaced-inode")){
        snprintf(extra,sizeof(extra),"%s/original-held-file",stage->paths[2]);CHECK(rename(file,extra)==0);make_file(file);write_path_text(file,protected_payload);
        CHECK(stage_check(stage,getuid())==-1&&stage_publish(stage,&holds,getuid())==-1&&stage_close(stage,getuid())==-1);
        same_inode(&original,extra);check_text(file,protected_payload);check_text(extra,staged_payload);check_absent(selector_path);
        CHECK(unlink(file)==0&&rename(extra,file)==0&&stage_cleanup_check(stage,getuid())==0&&stage_close(stage,getuid())==0);check_absent(root);
    }else if(!strcmp(mode,"stage-extra-entry")){
        snprintf(extra,sizeof(extra),"%s/unrelated-fixture-entry",stage->paths[2]);make_file(extra);write_path_text(extra,protected_payload);
        CHECK(stage_close(stage,getuid())==-1&&stage->parent_fd>=0);check_text(extra,protected_payload);check_absent(file);
        CHECK(unlink(extra)==0&&stage_close(stage,getuid())==0);check_absent(root);
    }else if(!strcmp(mode,"stage-source-hardlink")){
        snprintf(extra,sizeof(extra),"%s/staged-file-alias",fixture_root);CHECK(link(file,extra)==0);
        CHECK(stage_check(stage,getuid())==-1&&stage_publish(stage,&holds,getuid())==-1);check_absent(selector_path);
        CHECK(stage_close(stage,getuid())==-1);same_inode(&original,extra);check_text(extra,staged_payload);check_text(file,staged_payload);
        CHECK(unlink(extra)==0&&stage_close(stage,getuid())==0);check_absent(root);
    }else CHECK(0);
    holds_close(&holds);CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void stage_pending_case(int stopped) {
    envara_app_keychain_custody *slot=new_slot();scope_unknown_at_select=1;
    add_step(KC_SCOPED,KC_ABSENT,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,0);
    add_step(KC_SELECT,KC_OK,stopped?FRAME_STOPPED_BIRTH_MISSING:FRAME_OK,0);
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&step_index==3);
    char root[PATH_MAX],file[PATH_MAX];strcpy(root,slot->stage.paths[0]);snprintf(file,sizeof(file),"%s/com.apple.security.plist",slot->stage.paths[2]);
    int held=slot->stage.file_fd;CHECK(held>=0&&fcntl(held,F_GETFD)>=0&&stage_check(&slot->stage,getuid())==0);
    CHECK(home_seals==1&&!home_unseals&&!home_reclaims);
    struct envara_app_keychain_snapshot state=snapshot(slot);CHECK(state.pending&&state.child_state==(stopped?ENVARA_APP_KEYCHAIN_UNWAITED:ENVARA_APP_KEYCHAIN_REAPED));
    CHECK(envara_app_keychain_custody_destroy(slot)==-1);check_absent(selector_path);
    if(stopped){
        pid_t pid=slot->child.identity.pid;CHECK(module_signal_calls==0&&actual_child_state(pid)==SSTOP);
        CHECK(cleanup_public(slot)==0&&module_signal_calls==1);observe_zombie(pid);
        CHECK(cleanup_public(slot)==0&&snapshot(slot).child_state==ENVARA_APP_KEYCHAIN_REAPED);
    }else CHECK(cleanup_public(slot)==0);
    CHECK(slot->stage.file_fd==held&&fcntl(held,F_GETFD)>=0&&stage_check(&slot->stage,getuid())==0);
    CHECK(!home_unseals&&!home_reclaims);
    check_text(file,stopped?"":"synthetic-selector-v1\n");
    unsigned waited=wait_calls;scope_absent=1;CHECK(cleanup_public(slot)==1&&wait_calls==waited&&slot->stage.parent_fd==-1);
    CHECK(home_unseals==1&&home_reclaims==1);
    CHECK(fcntl(held,F_GETFD)==-1&&errno==EBADF);check_absent(root);check_absent(selector_path);
    CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void restore_library(struct kc_stage *stage) {
    if(!swapped_library[0])return;
    char library[PATH_MAX];snprintf(library,sizeof(library),"%s/Library",stage->paths[0]);
    struct stat actual;CHECK(fixture_fstat(stage->fds[0],&actual)==0&&!actual.st_uid&&!actual.st_flags&&(actual.st_mode&07777)==0700);
    CHECK(rmdir(library)==0&&rename(swapped_library,library)==0);swapped_library[0]=0;
}
static void home_seal_case(const char *mode) {
    struct {const char *name;int *fault;} faults[]={
        {"home-seal-owner-failure",&seal_owner_fail},{"home-seal-owner-readback",&seal_owner_readback},
        {"home-seal-mode-failure",&seal_mode_fail},{"home-seal-mode-readback",&seal_mode_readback},
        {"home-seal-flags-failure",&seal_flags_fail},{"home-seal-flags-readback",&seal_flags_readback},
        {"home-seal-swap",&seal_swap},{"home-seal-acl",&seal_acl}};
    int configured=0;
    for(unsigned i=0;i<sizeof(faults)/sizeof(faults[0]);i++)if(!strcmp(mode,faults[i].name)){*faults[i].fault=1;configured=1;}
    int preflight=!strcmp(mode,"home-securelevel-positive")||!strcmp(mode,"home-securelevel-error")||!strcmp(mode,"home-securelevel-short");
    if(!strcmp(mode,"home-securelevel-positive"))securelevel_value=1;
    if(!strcmp(mode,"home-securelevel-error"))securelevel_error=1;
    if(!strcmp(mode,"home-securelevel-short"))securelevel_short=1;
    CHECK(configured||preflight);
    envara_app_keychain_custody *slot=new_slot();struct kc_holds holds;prepare_holds(&holds);
    CHECK(stage_open(slot,&holds,getuid())==-1&&slot->stage.parent_fd>=0&&slot->stage.file_present&&!spawn_calls&&!selector_writes);
    CHECK(securelevel_reads==1&&fail_next_fd_fstat==-1);
    if(preflight)CHECK(!home_owner_changes&&!home_seals&&!home_unseals);
    struct stat observed;CHECK(fixture_fstat(slot->stage.fds[0],&observed)==0&&file_matches(&observed,&slot->stage.directories[0]));
    char root[PATH_MAX];strcpy(root,slot->stage.paths[0]);write_text(slot->stage.file_fd,protected_payload);
    if(swapped_library[0]||home_acl_refused){
        CHECK(stage_close(&slot->stage,getuid())==-1&&slot->stage.file_present&&fstat(slot->stage.file_fd,&observed)==0&&observed.st_nlink==1);
        home_acl_refused=0;restore_library(&slot->stage);
    }
    CHECK(stage_close(&slot->stage,getuid())==0);check_absent(root);check_absent(selector_path);
    holds_close(&holds);CHECK(!security_reads&&!security_setters&&envara_app_keychain_custody_destroy(slot)==0);
}
static void home_reclaim_case(const char *mode) {
    struct kc_holds holds;envara_app_keychain_custody *slot=open_direct_stage(&holds);struct kc_stage *stage=&slot->stage;
    struct {const char *name;int *fault;} faults[]={
        {"home-clear-failure",&clear_flags_fail},{"home-clear-readback",&clear_flags_readback},
        {"home-reclaim-owner-failure",&reclaim_owner_fail},{"home-reclaim-owner-readback",&reclaim_owner_readback},
        {"home-reclaim-mode-failure",&reclaim_mode_fail},{"home-reclaim-mode-readback",&reclaim_mode_readback},
        {"home-reclaim-swap",&reclaim_swap},{"home-reclaim-acl",&reclaim_acl}};
    int *selected=NULL;for(unsigned i=0;i<sizeof(faults)/sizeof(faults[0]);i++)if(!strcmp(mode,faults[i].name)){selected=faults[i].fault;*selected=1;}
    struct stat actual;CHECK(fstat(stage->fds[0],&actual)==0);struct fixture_stage_home *home=stage_home_record(&actual);CHECK(home);
    int damaged=!strcmp(mode,"home-unexpected-flags");CHECK(selected||damaged);if(damaged)home->flags=UF_IMMUTABLE;
    char root[PATH_MAX];strcpy(root,stage->paths[0]);
    CHECK(stage_close(stage,getuid())==-1&&stage->parent_fd>=0&&stage->file_present&&fstat(stage->file_fd,&actual)==0&&actual.st_nlink==1);
    CHECK(fail_next_fd_fstat==-1&&!spawn_calls&&!selector_writes&&!security_reads&&!security_setters);
    CHECK(fixture_fstat(stage->fds[0],&actual)==0);
    if(damaged){CHECK(!home_unseals&&!home_reclaims);home->flags=SF_IMMUTABLE;}
    else CHECK(file_matches(&actual,&stage->directories[0]));
    if(selected)*selected=0;home_acl_refused=0;restore_library(stage);
    CHECK(stage_close(stage,getuid())==0);check_absent(root);check_absent(selector_path);
    holds_close(&holds);CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void stage_creation_fault_case(const char *mode) {
    envara_app_keychain_custody *slot=new_slot();int unknown=!strcmp(mode,"stage-unknown-identity");
    stage_fail_first_identity=unknown;stage_fail_mode_readback=!strcmp(mode,"stage-mode-readback");stage_fail_owner_readback=!strcmp(mode,"stage-owner-readback");
    add_step(KC_SCOPED,KC_ABSENT,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,0);
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&step_index==2&&selector_writes==0);
    CHECK(!stage_fail_first_identity&&!stage_fail_mode_readback&&!stage_fail_owner_readback&&fail_next_fd_fstat==-1);check_absent(selector_path);
    unsigned waited=wait_calls;
    if(unknown){
        struct stat info;CHECK(snapshot(slot).pending&&slot->stage.parent_fd>=0&&slot->stage.directories_present[0]&&
            !slot->stage.directories[0].inode&&lstat(last_stage_root,&info)==0);
        CHECK(cleanup_public(slot)==0&&wait_calls==waited&&slot->stage.parent_fd>=0&&lstat(last_stage_root,&info)==0);
        CHECK(envara_app_keychain_custody_destroy(slot)==-1);
    }else {
        CHECK(!snapshot(slot).pending&&slot->stage.parent_fd==-1&&cleanup_public(slot)==1&&wait_calls==waited);
        check_absent(last_stage_root);CHECK(envara_app_keychain_custody_destroy(slot)==0);
    }
}
static void stage_publish_fsync_case(void) {
    envara_app_keychain_custody *slot=new_slot();publish_fsync_failure=1;
    add_step(KC_SCOPED,KC_ABSENT,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,0);add_step(KC_SELECT,KC_OK,FRAME_OK,0);
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&published_fsync_failures==1&&step_index==3);
    CHECK(!snapshot(slot).pending&&slot->stage.parent_fd==-1);check_absent(last_stage_root);check_text(selector_path,"synthetic-selector-v1\n");
    struct stat published;CHECK(lstat(selector_path,&published)==0&&envara_app_keychain_custody_destroy(slot)==0);
    /* The refused attempt preserves the published selector. The approved
     * next attempt may reuse a usable scoped default without selecting again. */
    step_count=step_index=0;slot=new_slot();add_step(KC_SCOPED,KC_OK,FRAME_OK,0);
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==0&&step_index==1&&spawn_calls==4&&selector_writes==1);
    same_inode(&published,selector_path);check_text(selector_path,"synthetic-selector-v1\n");CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void check_diagnostics(int expected);
static void flow_case(const char *mode) {
    envara_app_keychain_custody *slot=new_slot();struct kc_holds holds;prepare_holds(&holds);holds_close(&holds);
    int existing=!strcmp(mode,"reuse")||!strcmp(mode,"invalid-existing"),implicit=!strcmp(mode,"implicit-reuse"),changed=!strcmp(mode,"host-changed");
    if(existing)make_file(selector_path);
    if(existing||implicit)add_step(KC_SCOPED,!strcmp(mode,"invalid-existing")?KC_ABSENT:KC_OK,FRAME_OK,0);
    else {add_step(KC_SCOPED,KC_ABSENT,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,0);add_step(KC_SELECT,KC_OK,FRAME_OK,0);add_step(KC_SCOPED,KC_OK,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,changed);}
    int result=envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority);
    CHECK((result==0)==(!changed&&strcmp(mode,"invalid-existing")));
    if(result)check_diagnostics(-1);
    else if(existing||implicit){
        CHECK(collected_step_count==3&&collected_steps[0]==ENVARA_GUI_STEP_KEYCHAIN_BEGIN&&
            collected_steps[1]==ENVARA_GUI_STEP_KEYCHAIN_SCOPED&&collected_steps[2]==ENVARA_GUI_STEP_KEYCHAIN_COMPLETE);
    }else {
        const enum envara_gui_step expected[]={ENVARA_GUI_STEP_KEYCHAIN_BEGIN,ENVARA_GUI_STEP_KEYCHAIN_SCOPED,
            ENVARA_GUI_STEP_KEYCHAIN_NORMAL,ENVARA_GUI_STEP_KEYCHAIN_STAGE_READY,ENVARA_GUI_STEP_KEYCHAIN_SELECT,
            ENVARA_GUI_STEP_KEYCHAIN_PUBLISHED,ENVARA_GUI_STEP_KEYCHAIN_STAGE_CLEANED,ENVARA_GUI_STEP_KEYCHAIN_VERIFY,
            ENVARA_GUI_STEP_KEYCHAIN_HOST_VERIFY,ENVARA_GUI_STEP_KEYCHAIN_COMPLETE};
        CHECK(collected_step_count==sizeof(expected)/sizeof(expected[0])&&!memcmp(collected_steps,expected,sizeof(expected)));
    }
    CHECK(step_index==step_count&&spawn_calls==step_count&&selector_writes==(unsigned)(existing||implicit?0:1));
    CHECK(cleanup_public(slot)==1&&!envara_app_keychain_custody_pending(slot,&test_app,&test_request,test_run));
    prepare_holds(&holds);CHECK(selector_state(&holds,getuid())==(implicit?0:1));holds_close(&holds);
    CHECK(envara_app_keychain_custody_destroy(slot)==0);
}
static void check_diagnostics(int expected) {
    unsigned phases=0,failures=0;
    for(unsigned i=0;i<collected_step_count;i++){
        enum envara_gui_step step=collected_steps[i];
        if(step>=ENVARA_GUI_STEP_KEYCHAIN_BEGIN&&step<=ENVARA_GUI_STEP_KEYCHAIN_COMPLETE)phases++;
        else {
            CHECK(step>=ENVARA_GUI_STEP_KEYCHAIN_PARENT_CONTEXT&&step<=ENVARA_GUI_STEP_KEYCHAIN_HELPER_TIMEOUT);
            if(expected>=0)CHECK(step==(enum envara_gui_step)expected);
            else CHECK(step>=ENVARA_GUI_STEP_KEYCHAIN_PARENT_CONTEXT&&step<=ENVARA_GUI_STEP_KEYCHAIN_PARENT_FINAL);
            failures++;
        }
    }
    CHECK(phases<=10&&failures==1&&collected_step_count<=11);
    unsigned before=collected_step_count;diagnostic_emit(owned_slot);CHECK(collected_step_count==before);
}
static void command_case(const char *name) {
    struct {const char *name;enum fixture_command_fault fault;int status;enum envara_gui_step step;} cases[]={
        {"command-entry",COMMAND_ENTRY,ENVARA_KEYCHAIN_EXIT_ENTRY,ENVARA_GUI_STEP_KEYCHAIN_HELPER_ENTRY},
        {"command-identity",COMMAND_IDENTITY,ENVARA_KEYCHAIN_EXIT_SELF_IDENTITY,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SELF_IDENTITY},
        {"command-parent-identity",COMMAND_PARENT_IDENTITY,ENVARA_KEYCHAIN_EXIT_PARENT_IDENTITY,ENVARA_GUI_STEP_KEYCHAIN_HELPER_PARENT_IDENTITY},
        {"command-home",COMMAND_HOME,ENVARA_KEYCHAIN_EXIT_HOME,ENVARA_GUI_STEP_KEYCHAIN_HELPER_HOME},
        {"command-holds",COMMAND_HOLDS,ENVARA_KEYCHAIN_EXIT_HOLDS_OPEN,ENVARA_GUI_STEP_KEYCHAIN_HELPER_HOLDS_OPEN},
        {"command-sandbox",COMMAND_SANDBOX,ENVARA_KEYCHAIN_EXIT_SANDBOX,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SANDBOX},
        {"command-metadata",COMMAND_METADATA,ENVARA_KEYCHAIN_EXIT_COPY_DEFAULT,ENVARA_GUI_STEP_KEYCHAIN_HELPER_COPY_DEFAULT},
        {"command-set-default",COMMAND_SET_DEFAULT,ENVARA_KEYCHAIN_EXIT_SET_DEFAULT,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SET_DEFAULT}};
    unsigned selected=sizeof(cases)/sizeof(cases[0]);
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(name,cases[i].name))selected=i;
    int success=!strcmp(name,"command-ok");CHECK(success||selected<sizeof(cases)/sizeof(cases[0]));
    envara_app_keychain_custody *slot=new_slot();
    int selecting=!success&&cases[selected].fault==COMMAND_SET_DEFAULT;
    if(selecting){add_step(KC_SCOPED,KC_ABSENT,FRAME_OK,0);add_step(KC_NORMAL,KC_OK,FRAME_OK,0);}
    add_step(selecting?KC_SELECT:KC_SCOPED,KC_OK,FRAME_OK,0);
    steps[step_count-1].command_fault=success?COMMAND_OK:cases[selected].fault;
    int result=envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority);
    CHECK((result==0)==success&&step_index==step_count&&slot->wait_proof==KC_OWNED_TERMINAL_WAIT&&slot->scope_confirmed);
    CHECK(WIFEXITED(slot->wait_status)&&WEXITSTATUS(slot->wait_status)==(success?0:cases[selected].status));
    if(success){CHECK(collected_step_count>0&&collected_step_count<=10&&!diagnostic_gate_checks);
        for(unsigned i=0;i<collected_step_count;i++)CHECK(collected_steps[i]>=ENVARA_GUI_STEP_KEYCHAIN_BEGIN&&collected_steps[i]<=ENVARA_GUI_STEP_KEYCHAIN_COMPLETE);
    }else {check_diagnostics(cases[selected].step);CHECK(diagnostic_gate_checks==1);}
    CHECK(!snapshot(slot).pending&&cleanup_public(slot)==1&&envara_app_keychain_custody_destroy(slot)==0);
}
static void exit_diagnostic_case(const char *name) {
    struct {const char *name;int status;enum envara_gui_step step;} cases[]={
        {"exit-entry",ENVARA_KEYCHAIN_EXIT_ENTRY,ENVARA_GUI_STEP_KEYCHAIN_HELPER_ENTRY},
        {"exit-identity",ENVARA_KEYCHAIN_EXIT_SELF_IDENTITY,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SELF_IDENTITY},
        {"exit-home",ENVARA_KEYCHAIN_EXIT_HOME,ENVARA_GUI_STEP_KEYCHAIN_HELPER_HOME},
        {"exit-holds",ENVARA_KEYCHAIN_EXIT_HOLDS_OPEN,ENVARA_GUI_STEP_KEYCHAIN_HELPER_HOLDS_OPEN},
        {"exit-sandbox",ENVARA_KEYCHAIN_EXIT_SANDBOX,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SANDBOX},
        {"exit-metadata",ENVARA_KEYCHAIN_EXIT_COPY_DEFAULT,ENVARA_GUI_STEP_KEYCHAIN_HELPER_COPY_DEFAULT},
        {"exit-set-default",ENVARA_KEYCHAIN_EXIT_SET_DEFAULT,ENVARA_GUI_STEP_KEYCHAIN_HELPER_SET_DEFAULT},
        {"exit-timeout",ENVARA_KEYCHAIN_EXIT_TIMEOUT,ENVARA_GUI_STEP_KEYCHAIN_HELPER_TIMEOUT}};
    int status=ENVARA_KEYCHAIN_EXIT_HOME,expected=-1,configured=0;
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(name,cases[i].name)){status=cases[i].status;expected=cases[i].step;configured=1;}
    int echild=!strcmp(name,"exit-echild"),unreaped=!strcmp(name,"exit-unreaped"),unknown=!strcmp(name,"exit-scope-unknown"),unrecognized=!strcmp(name,"exit-unrecognized");
    CHECK(configured||echild||unreaped||unknown||unrecognized);if(unrecognized)status=63;
    envara_app_keychain_custody *slot=new_slot();add_step(KC_SCOPED,KC_OK,echild?FRAME_ECHILD:FRAME_OK,0);steps[0].exit_status=status;
    if(unknown)scope_absent=0;if(unreaped)fixture_wait_stays_pending=1;
    CHECK(envara_app_keychain_prepare(slot,&test_app,&test_request,test_home,&authority)==-1&&step_index==1);
    check_diagnostics(expected);CHECK(diagnostic_gate_checks==(unsigned)(expected>=0));
    if(echild)CHECK(slot->wait_proof==KC_UNKNOWN_WAIT&&snapshot(slot).pending&&fixture_children[0].reaped);
    else if(unreaped)CHECK(slot->wait_proof==KC_OWNED_UNREAPED&&snapshot(slot).pending&&!fixture_children[0].reaped);
    else CHECK(slot->wait_proof==KC_OWNED_TERMINAL_WAIT&&fixture_children[0].reaped&&slot->scope_confirmed==!unknown);
    unsigned emitted=collected_step_count;fixture_wait_stays_pending=0;scope_absent=1;
    if(echild)CHECK(cleanup_public(slot)==0&&envara_app_keychain_custody_destroy(slot)==-1);
    else {CHECK(cleanup_public(slot)==1);diagnostic_emit(slot);CHECK(envara_app_keychain_custody_destroy(slot)==0);}
    CHECK(collected_step_count==emitted);
}
static void parent_identity_case(const char *name) {
    struct envara_identity expected={.pid=42,.birth_seconds=123456,.birth_microseconds=654321};
    parent_fixture_active=1;parent_fixture_pid=expected.pid;parent_reply_size=sizeof(parent_fixture_record);
    memset(&parent_fixture_record,0,sizeof(parent_fixture_record));
    parent_fixture_record.kp_proc.p_pid=expected.pid;
    parent_fixture_record.kp_proc.p_starttime.tv_sec=(time_t)expected.birth_seconds;
    parent_fixture_record.kp_proc.p_starttime.tv_usec=(suseconds_t)expected.birth_microseconds;
    int early=0,known=1,success=!strcmp(name,"parent-ok"),null_expected=!strcmp(name,"parent-null");
    if(success){}
    else if(null_expected)early=1;
    else if(!strcmp(name,"parent-pid-minimum")){expected.pid=1;early=1;}
    else if(!strcmp(name,"parent-pid-negative")){expected.pid=-2;early=1;}
    else if(!strcmp(name,"parent-expected-uid")){expected.uid=getuid();early=1;}
    else if(!strcmp(name,"parent-expected-ruid")){expected.ruid=getuid();early=1;}
    else if(!strcmp(name,"parent-expected-saved-uid")){expected.saved_uid=getuid();early=1;}
    else if(!strcmp(name,"parent-expected-birth-zero")){expected.birth_seconds=0;early=1;}
    else if(!strcmp(name,"parent-expected-usec-invalid")){expected.birth_microseconds=1000000;early=1;}
    else if(!strcmp(name,"parent-before-change")){parent_getppid_before=1;early=1;}
    else if(!strcmp(name,"parent-sysctl-error"))parent_sysctl_error=EPERM;
    else if(!strcmp(name,"parent-empty-length"))parent_reply_size=0;
    else if(!strcmp(name,"parent-short-length"))parent_reply_size--;
    else if(!strcmp(name,"parent-long-length"))parent_reply_size++;
    else if(!strcmp(name,"parent-wrong-pid"))parent_fixture_record.kp_proc.p_pid++;
    else if(!strcmp(name,"parent-actual-uid"))parent_fixture_record.kp_eproc.e_ucred.cr_uid=getuid();
    else if(!strcmp(name,"parent-actual-ruid"))parent_fixture_record.kp_eproc.e_pcred.p_ruid=getuid();
    else if(!strcmp(name,"parent-actual-saved-uid"))parent_fixture_record.kp_eproc.e_pcred.p_svuid=getuid();
    else if(!strcmp(name,"parent-birth-seconds"))parent_fixture_record.kp_proc.p_starttime.tv_sec++;
    else if(!strcmp(name,"parent-birth-microseconds"))parent_fixture_record.kp_proc.p_starttime.tv_usec++;
    else if(!strcmp(name,"parent-birth-zero"))parent_fixture_record.kp_proc.p_starttime.tv_sec=0;
    else if(!strcmp(name,"parent-birth-negative"))parent_fixture_record.kp_proc.p_starttime.tv_sec=-1;
    else if(!strcmp(name,"parent-usec-negative"))parent_fixture_record.kp_proc.p_starttime.tv_usec=-1;
    else if(!strcmp(name,"parent-usec-invalid"))parent_fixture_record.kp_proc.p_starttime.tv_usec=1000000;
    else if(!strcmp(name,"parent-after-change"))parent_getppid_after=1;
    else known=0;
    CHECK(known&&parent_matches(null_expected?NULL:&expected)==success);
    CHECK(parent_sysctl_calls==(unsigned)!early&&!parent_tbsd_calls&&!security_reads&&!security_setters&&!spawn_calls);
    parent_fixture_active=0;
}
static void kernel_snapshot_case(void) {
    /* These two public reads observe only ourselves and the fixed system
     * process. They neither establish helper custody nor authorize a launch. */
    CHECK(getuid()!=0&&getuid()==geteuid()&&!fixture_command_active&&!parent_fixture_active);
    struct envara_identity self;CHECK(actual_identity(getpid(),&self)==0);
    int name[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()};struct kinfo_proc info={0};size_t size=sizeof(info);
    real_kernel_snapshot_reads++;CHECK(sysctl(name,4,&info,&size,NULL,0)==0&&size==sizeof(info));
    CHECK(info.kp_proc.p_pid==getpid()&&info.kp_eproc.e_ucred.cr_uid==self.uid&&
        info.kp_eproc.e_pcred.p_ruid==self.ruid&&info.kp_eproc.e_pcred.p_svuid==self.saved_uid&&
        (uint64_t)info.kp_proc.p_starttime.tv_sec==self.birth_seconds&&
        (uint64_t)info.kp_proc.p_starttime.tv_usec==self.birth_microseconds);
    name[3]=1;memset(&info,0,sizeof(info));size=sizeof(info);errno=0;real_kernel_snapshot_reads++;
    int result=sysctl(name,4,&info,&size,NULL,0);
    if(!result){CHECK(size==sizeof(info)&&info.kp_proc.p_pid==1&&!info.kp_eproc.e_ucred.cr_uid&&
        !info.kp_eproc.e_pcred.p_ruid&&!info.kp_eproc.e_pcred.p_svuid&&info.kp_proc.p_starttime.tv_sec>0&&
        info.kp_proc.p_starttime.tv_usec>=0&&info.kp_proc.p_starttime.tv_usec<1000000);root_snapshot_readable=1;}
    else CHECK(errno==EPERM||errno==EACCES);
    struct proc_bsdinfo restricted={0};errno=0;
    int bytes=proc_pidinfo(1,PROC_PIDTBSDINFO,0,&restricted,sizeof(restricted));
    if(!bytes){CHECK(errno==EPERM||errno==EACCES);root_bsd_denied=1;}
    else CHECK(bytes==(int)sizeof(restricted)&&restricted.pbi_pid==1&&!restricted.pbi_uid);
    CHECK(!parent_sysctl_calls&&!parent_tbsd_calls&&!security_reads&&!security_setters&&!spawn_calls);
}
int main(int argc,char **argv) {
    if(argc!=3||!getuid()||getuid()!=geteuid())return 2;
    CHECK(atexit(fixture_cleanup)==0);setup(argv[2]);
    if(!strcmp(argv[1],"pipe-identity"))pipe_identity_case();
    else if(!strcmp(argv[1],"metadata"))metadata_case();
    else if(!strcmp(argv[1],"paths"))paths_case();
    else if(!strcmp(argv[1],"frame-ok"))protocol_case(FRAME_OK);
    else if(!strcmp(argv[1],"frame-trailing"))protocol_case(FRAME_TRAILING);
    else if(!strcmp(argv[1],"frame-nonce"))protocol_case(FRAME_NONCE);
    else if(!strcmp(argv[1],"frame-schema"))protocol_case(FRAME_SCHEMA);
    else if(!strcmp(argv[1],"frame-result"))protocol_case(FRAME_RESULT);
    else if(!strcmp(argv[1],"frame-unterminated"))protocol_case(FRAME_UNTERMINATED);
    else if(!strcmp(argv[1],"stopped-birth-missing"))stopped_birth_case(0);
    else if(!strcmp(argv[1],"cleanup-policy-unknown"))stopped_birth_case(1);
    else if(!strcmp(argv[1],"launch-sigchld-ignore"))launch_policy_case(0);
    else if(!strcmp(argv[1],"launch-no-child-wait"))launch_policy_case(1);
    else if(!strcmp(argv[1],"stage-publish-inode")||!strcmp(argv[1],"stage-existing-destination")||!strcmp(argv[1],"stage-hardlink-race")||
        !strcmp(argv[1],"stage-replaced-inode")||!strcmp(argv[1],"stage-extra-entry")||!strcmp(argv[1],"stage-source-hardlink"))direct_stage_case(argv[1]);
    else if(!strcmp(argv[1],"stage-pending-retention"))stage_pending_case(0);
    else if(!strcmp(argv[1],"stage-stopped-retention"))stage_pending_case(1);
    else if(!strncmp(argv[1],"home-seal-",10)||!strncmp(argv[1],"home-securelevel-",17))home_seal_case(argv[1]);
    else if(!strncmp(argv[1],"home-clear-",11)||!strncmp(argv[1],"home-reclaim-",13)||!strcmp(argv[1],"home-unexpected-flags"))home_reclaim_case(argv[1]);
    else if(!strcmp(argv[1],"stage-mode-readback")||!strcmp(argv[1],"stage-owner-readback")||!strcmp(argv[1],"stage-unknown-identity"))stage_creation_fault_case(argv[1]);
    else if(!strcmp(argv[1],"stage-publish-fsync"))stage_publish_fsync_case();
    else if(!strcmp(argv[1],"reap-scope-unknown")||!strcmp(argv[1],"launcher-clear")||!strcmp(argv[1],"birth-missing")||!strcmp(argv[1],"echild")||!strcmp(argv[1],"binding")||!strcmp(argv[1],"owner-unknown")||!strcmp(argv[1],"active-refusal")||!strcmp(argv[1],"inactive-scope"))custody_case(argv[1]);
    else if(!strcmp(argv[1],"create")||!strcmp(argv[1],"reuse")||!strcmp(argv[1],"implicit-reuse")||!strcmp(argv[1],"invalid-existing")||!strcmp(argv[1],"host-changed"))flow_case(argv[1]);
    else if(!strncmp(argv[1],"command-",8))command_case(argv[1]);
    else if(!strncmp(argv[1],"exit-",5))exit_diagnostic_case(argv[1]);
    else if(!strncmp(argv[1],"parent-",7))parent_identity_case(argv[1]);
    else if(!strcmp(argv[1],"kernel-snapshot-readonly"))kernel_snapshot_case();
    else return 2;
    CHECK(!security_setters&&!unexpected_worker_calls&&!forbidden_waits&&!module_signal_policy_writes);
    for(unsigned i=0;i<fixture_child_count;i++)CHECK(fixture_children[i].reaped);
    printf("{\"ok\":true,\"fixtureOnly\":true,\"rootAuthorityVerified\":false,\"realKeychainAPICalls\":0,\"ready\":false,\"protected\":false,\"activatesSystem\":false,\"ownedChildrenReaped\":true,\"checks\":%u,\"syntheticWorkers\":%u,\"syntheticSelectorAttempts\":%u,\"forbiddenWaits\":%u,\"readOnlyKernelSnapshots\":%u,\"rootSnapshotReadable\":%s,\"restrictedRootBsdDenied\":%s}\n",checks,spawn_calls,selector_writes,forbidden_waits,real_kernel_snapshot_reads,root_snapshot_readable?"true":"false",root_bsd_denied?"true":"false");
    return 0;
}
