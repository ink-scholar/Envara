#include "app-keychain.h"
#include "notion-launch.h"
#include "app-scope-proof.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sandbox.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <libproc.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* One private, bounded protocol between the fixed controller and its own
 * fresh console-UID child. Never serialized to the keeper/renderer/journal. */
#define KC_SCHEMA 1u
#define KC_TIMEOUT_MS 12000
#define KC_PREPARE_TIMEOUT_MS 20000
enum kc_mode { KC_SCOPED = 1, KC_NORMAL, KC_SELECT };
enum kc_result { KC_OK = 0, KC_ABSENT, KC_REFUSED };
struct kc_file { uint64_t device, inode; uint32_t owner, mode, flags, reserved; };
struct kc_request {
    uint32_t schema, mode, audit; uid_t uid; gid_t gid;
    uint64_t generation;
    unsigned char nonce[32]; struct envara_identity parent;
    struct kc_file input, output, directories[3];
    struct kc_file selector_directories[3], selector_file;
    char environment[37], registration[37], version[37], run[37], home[PATH_MAX], selected[PATH_MAX], selector_home[PATH_MAX];
};
struct kc_reply {
    uint32_t schema, result, unlocked, merged_count, user_count;
    unsigned char nonce[32], merged_digest[CC_SHA256_DIGEST_LENGTH], user_digest[CC_SHA256_DIGEST_LENGTH];
    char selected[PATH_MAX];
};
struct kc_holds { int fds[3]; struct kc_file identities[3]; char paths[3][PATH_MAX]; };
struct kc_stage {
    int parent_fd, fds[3], file_fd, file_present, directories_present[3];
    char name[64], paths[3][PATH_MAX];
    struct kc_file directories[3], file;
};
enum kc_wait_proof { KC_NO_PENDING_FROM_LAUNCHER, KC_OWNED_UNREAPED, KC_OWNED_TERMINAL_WAIT, KC_UNKNOWN_WAIT };
struct envara_app_keychain_custody {
    struct envara_identity owner;
    struct envara_app_registration app;
    struct envara_gui_request request;
    char run_id[37], slot_id[37]; uint64_t generation;
    int active, wait_status, scope_confirmed;
    int diagnostic_step, helper_step, diagnostic_emitted;
    enum kc_wait_proof wait_proof;
    struct envara_child child;
    struct kc_stage stage;
};
static _Thread_local envara_app_keychain_custody *owned_slot;
static _Thread_local enum envara_app_keychain_helper_exit helper_failure;

static int helper_fail(enum envara_app_keychain_helper_exit failure) {
    if(!helper_failure)helper_failure=failure;return -1;
}
static int parent_fail(envara_app_keychain_custody *slot,enum envara_gui_step step,int error) {
    if(slot->diagnostic_step<0)slot->diagnostic_step=step;errno=error;return -1;
}
static void diagnostic_emit(envara_app_keychain_custody *slot) {
    if(slot->diagnostic_emitted)return;
    int step=slot->helper_step>=0?slot->helper_step:slot->diagnostic_step;
    if(step>=0){slot->diagnostic_emitted=1;envara_gui_step((enum envara_gui_step)step);}
}
static int helper_step(int exit_code) {
#define HELPER_EXIT(name) case ENVARA_KEYCHAIN_EXIT_##name:return ENVARA_GUI_STEP_KEYCHAIN_HELPER_##name
    switch(exit_code){
        HELPER_EXIT(ENTRY);HELPER_EXIT(PIPES);HELPER_EXIT(REQUEST_READ);HELPER_EXIT(REQUEST_SHAPE);
        HELPER_EXIT(SELF_IDENTITY);HELPER_EXIT(PARENT_IDENTITY);HELPER_EXIT(EXECUTABLE);HELPER_EXIT(PIPE_BINDING);
        HELPER_EXIT(SESSION);HELPER_EXIT(HOME);HELPER_EXIT(HOLDS_OPEN);HELPER_EXIT(HOLDS_BINDING);
        HELPER_EXIT(SELECTOR);HELPER_EXIT(STAGE_LOAD);HELPER_EXIT(SANDBOX);HELPER_EXIT(INTERACTION);
        HELPER_EXIT(SELECT_RECHECK);HELPER_EXIT(KEYCHAIN_OPEN);HELPER_EXIT(SET_DEFAULT);HELPER_EXIT(SELECT_POSTCHECK);
        HELPER_EXIT(COPY_DEFAULT);HELPER_EXIT(DEFAULT_PATH);HELPER_EXIT(DEFAULT_OWNER);HELPER_EXIT(DEFAULT_STATUS);
        HELPER_EXIT(SEARCH_LIST);HELPER_EXIT(DOMAIN_SEARCH);HELPER_EXIT(SEARCH_DIGEST);HELPER_EXIT(SEARCH_MISSING);
        HELPER_EXIT(METADATA_POSTCHECK);HELPER_EXIT(REPLY_WRITE);HELPER_EXIT(TIMEOUT);
        default:return -1;
    }
#undef HELPER_EXIT
}

static int refuse(int error) { errno = error; return -1; }
static int64_t now_ms(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int private_wait_policy(void) {
    struct sigaction action;
    return !sigaction(SIGCHLD,NULL,&action)&&action.sa_handler==SIG_DFL&&!(action.sa_flags&SA_NOCLDWAIT);
}
static int parent_matches(const struct envara_identity *expected) {
    /* PROC_PIDTBSDINFO requires matching UIDs. This console-UID helper must
     * inspect its root parent through the public, read-only KERN_PROC_PID
     * record instead. Its birth tuple has the same kernel source, and all
     * three root UIDs, the direct parent PID and exact generation stay bound. */
    if(!expected||expected->pid<=1||expected->uid||expected->ruid||expected->saved_uid||
        !expected->birth_seconds||expected->birth_microseconds>=1000000||getppid()!=expected->pid)return 0;
    struct kinfo_proc parent;memset(&parent,0,sizeof(parent));size_t size=sizeof(parent);
    int name[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,expected->pid};
    if(sysctl(name,4,&parent,&size,NULL,0)||size!=sizeof(parent)||parent.kp_proc.p_pid!=expected->pid||
        parent.kp_eproc.e_ucred.cr_uid||parent.kp_eproc.e_pcred.p_ruid||parent.kp_eproc.e_pcred.p_svuid||
        parent.kp_proc.p_starttime.tv_sec<=0||parent.kp_proc.p_starttime.tv_usec<0||parent.kp_proc.p_starttime.tv_usec>=1000000||
        (uint64_t)parent.kp_proc.p_starttime.tv_sec!=expected->birth_seconds||
        (uint64_t)parent.kp_proc.p_starttime.tv_usec!=expected->birth_microseconds)return 0;
    return getppid()==expected->pid;
}
static int uuid(const char *s) {
    if (!memchr(s, 0, 37) || strlen(s) != 36 || s[14] != '4' || !strchr("89ab", s[19])) return 0;
    for (int i=0;i<36;i++) if(i==8||i==13||i==18||i==23) { if(s[i]!='-') return 0; }
        else if(!strchr("0123456789abcdef",s[i])) return 0;
    return 1;
}
static struct kc_file file_identity(const struct stat *s) {
    struct kc_file identity;memset(&identity,0,sizeof(identity));
    identity.device=s->st_dev;identity.inode=s->st_ino;identity.owner=s->st_uid;
    identity.mode=(uint32_t)s->st_mode;identity.flags=s->st_flags;return identity;
}
static int file_matches(const struct stat *s, const struct kc_file *f) {
    return (uint64_t)s->st_dev==f->device && (uint64_t)s->st_ino==f->inode && s->st_uid==f->owner &&
        (uint32_t)s->st_mode==f->mode && s->st_flags==f->flags;
}
static int canonical_owned(const char *path, uid_t uid, int directory, struct stat *out) {
    char real[PATH_MAX]; struct stat s;
    if (!path || path[0]!='/' || !realpath(path,real) || strcmp(path,real) || lstat(path,&s) || s.st_uid!=uid ||
        (directory ? !S_ISDIR(s.st_mode) : !S_ISREG(s.st_mode))) return -1;
    if(out) *out=s; return 0;
}
static int expected_home(const char *environment,const char *registration,char out[PATH_MAX]) {
    if(!uuid(environment)||!uuid(registration)) return -1;
    int n=snprintf(out,PATH_MAX,"%s/%s/%s/Home",ENVARA_NOTION_DATA_ROOT,environment,registration);
    return n<0||n>=PATH_MAX ? -1 : 0;
}
static void holds_close(struct kc_holds *h) { for(int i=0;i<3;i++) if(h->fds[i]>=0){close(h->fds[i]);h->fds[i]=-1;} }
static int create_owned_directory(const struct kc_holds *h,int parent,const char *name,uid_t uid) {
    /* Never chown a pathname inside a user-writable parent. Construct and hold
     * the new directory under the existing root-owned registration directory,
     * then publish it with an exclusive rename. Existing data is untouched. */
    char root_path[PATH_MAX],actual[PATH_MAX],stage[64];strcpy(root_path,h->paths[0]);
    char *slash=strrchr(root_path,'/');if(!slash||strcmp(slash,"/Home"))return -1;*slash=0;
    int root=openat(h->fds[0],"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),created=-1,result=-1,exists=0;
    struct stat s;
    if(root<0||fstat(root,&s)||!S_ISDIR(s.st_mode)||s.st_uid||(s.st_mode&022)||
        fcntl(root,F_GETPATH,actual)||strcmp(actual,root_path)||envara_gui_acl_free(root_path))goto done;
    unsigned char nonce[16];arc4random_buf(nonce,sizeof(nonce));
    snprintf(stage,sizeof(stage),".keychain-directory-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        nonce[0],nonce[1],nonce[2],nonce[3],nonce[4],nonce[5],nonce[6],nonce[7],nonce[8],nonce[9],nonce[10],nonce[11],nonce[12],nonce[13],nonce[14],nonce[15]);
    if(mkdirat(root,stage,0700))goto done;exists=1;
    created=openat(root,stage,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(created<0||fstat(created,&s)||s.st_uid||!S_ISDIR(s.st_mode)||(s.st_mode&07777)!=0700||
        fchown(created,uid,(gid_t)-1)||renameatx_np(root,stage,h->fds[parent],name,RENAME_EXCL))goto done;
    exists=0;result=0;
done:
    if(created>=0)close(created);
    if(exists)(void)unlinkat(root,stage,AT_REMOVEDIR); /* Empty owned entry only. */
    if(root>=0)close(root);return result;
}
static int holds_check(const struct kc_holds *h,uid_t uid) {
    for(int i=0;i<3;i++) {struct stat held,named;char path[PATH_MAX];
        if(fstat(h->fds[i],&held)||lstat(h->paths[i],&named)||!file_matches(&held,&h->identities[i])||
            !file_matches(&named,&h->identities[i])||!S_ISDIR(named.st_mode)||named.st_uid!=uid||(named.st_mode&022)||
            (i==0&&(named.st_mode&07777)!=0700)||fcntl(h->fds[i],F_GETPATH,path)||strcmp(path,h->paths[i])||
            envara_gui_acl_free(h->paths[i])) return -1;
    } return 0;
}
static int holds_open(const char *home,uid_t uid,int create,struct kc_holds *h) {
    memset(h,0,sizeof(*h));for(int i=0;i<3;i++)h->fds[i]=-1;
    const char *names[]={NULL,"Library","Preferences"};
    if(snprintf(h->paths[0],PATH_MAX,"%s",home)>=PATH_MAX) return -1;
    for(int i=0;i<3;i++) {
        if(i && snprintf(h->paths[i],PATH_MAX,"%s/%s",h->paths[i-1],names[i])>=PATH_MAX) goto bad;
        if(i && create) {struct stat existing;
            if(fstatat(h->fds[i-1],names[i],&existing,AT_SYMLINK_NOFOLLOW)) {
                if(errno!=ENOENT||create_owned_directory(h,i-1,names[i],uid))goto bad;
            }
        }
        h->fds[i]= i ? openat(h->fds[i-1],names[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) : open(home,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        struct stat s;char resolved[PATH_MAX];
        if(h->fds[i]<0||fstat(h->fds[i],&s)||canonical_owned(h->paths[i],uid,1,NULL)||
            (s.st_mode&022)||(i==0&&(s.st_mode&07777)!=0700)||fcntl(h->fds[i],F_GETPATH,resolved)||strcmp(resolved,h->paths[i])||
            envara_gui_acl_free(h->paths[i]))goto bad;
        h->identities[i]=file_identity(&s);
    }
    if(!holds_check(h,uid))return 0;
bad: holds_close(h);return -1;
}
static int selector_state(const struct kc_holds *h,uid_t uid) {
    struct stat s;
    if(fstatat(h->fds[2],"com.apple.security.plist",&s,AT_SYMLINK_NOFOLLOW))return errno==ENOENT?0:-1;
    char path[PATH_MAX]; if(snprintf(path,sizeof(path),"%s/com.apple.security.plist",h->paths[2])>=PATH_MAX)return -1;
    return S_ISREG(s.st_mode)&&s.st_uid==uid&&s.st_nlink==1&&!(s.st_mode&022)&&!envara_gui_acl_free(path)?1:-1;
}
static void stage_init(struct kc_stage *stage) {
    memset(stage,0,sizeof(*stage));stage->parent_fd=stage->file_fd=-1;
    for(int i=0;i<3;i++)stage->fds[i]=-1;
}
static void stage_release_fds(struct kc_stage *stage) {
    if(stage->file_fd>=0)close(stage->file_fd);
    for(int i=2;i>=0;i--)if(stage->fds[i]>=0)close(stage->fds[i]);
    if(stage->parent_fd>=0)close(stage->parent_fd);stage_init(stage);
}
static int stage_parent(struct kc_stage *stage,const struct kc_holds *holds) {
    char expected[PATH_MAX],actual[PATH_MAX];strcpy(expected,holds->paths[0]);
    char *slash=strrchr(expected,'/');if(!slash||strcmp(slash,"/Home"))return -1;*slash=0;
    stage->parent_fd=openat(holds->fds[0],"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat s;
    return stage->parent_fd<0||fstat(stage->parent_fd,&s)||!S_ISDIR(s.st_mode)||s.st_uid||
        (s.st_mode&07777)!=0755||fcntl(stage->parent_fd,F_GETPATH,actual)||strcmp(actual,expected)||envara_gui_acl_free(actual)?-1:0;
}
static int stage_check(const struct kc_stage *stage,uid_t uid) {
    const char *names[]={stage->name,"Library","Preferences"};struct stat held,named;char actual[PATH_MAX];
    for(int i=0;i<3;i++)if(stage->fds[i]<0||fstat(stage->fds[i],&held)||
        fstatat(i?stage->fds[i-1]:stage->parent_fd,names[i],&named,AT_SYMLINK_NOFOLLOW)||
        !file_matches(&held,&stage->directories[i])||!file_matches(&named,&stage->directories[i])||
        !S_ISDIR(held.st_mode)||held.st_uid!=(i?0:uid)||(held.st_mode&07777)!=(i?0755:0500)||
        held.st_flags!=(i?0:SF_IMMUTABLE)||
        fcntl(stage->fds[i],F_GETPATH,actual)||strcmp(actual,stage->paths[i])||envara_gui_acl_free(actual))return -1;
    return !stage->file_present||stage->file_fd<0||fstat(stage->file_fd,&held)||
        fstatat(stage->fds[2],"com.apple.security.plist",&named,AT_SYMLINK_NOFOLLOW)||
        !file_matches(&held,&stage->file)||!file_matches(&named,&stage->file)||!S_ISREG(held.st_mode)||
        held.st_uid!=uid||held.st_nlink!=1||(held.st_mode&07777)!=0600||held.st_flags||
        snprintf(actual,sizeof(actual),"%s/com.apple.security.plist",stage->paths[2])>=(int)sizeof(actual)||
        envara_gui_acl_free(actual)?-1:0;
}
static int stage_home_seal(struct kc_stage *stage,uid_t uid) {
    int level=1;size_t size=sizeof(level);struct stat s;
    if(sysctlbyname("kern.securelevel",&level,&size,NULL,0)||size!=sizeof(level)||level>0||
        stage->fds[0]<0||fstat(stage->fds[0],&s)||!file_matches(&s,&stage->directories[0])||s.st_flags||
        fchown(stage->fds[0],uid,(gid_t)-1))return -1;
    stage->directories[0].owner=uid;
    if(fstat(stage->fds[0],&s)||!file_matches(&s,&stage->directories[0])||fchmod(stage->fds[0],0500))return -1;
    stage->directories[0].mode=(stage->directories[0].mode&S_IFMT)|0500;
    if(fstat(stage->fds[0],&s)||!file_matches(&s,&stage->directories[0])||fchflags(stage->fds[0],SF_IMMUTABLE))return -1;
    stage->directories[0].flags=SF_IMMUTABLE;
    /* A console-UID process can race the ownership-to-seal window. Only a
     * successful system seal followed by the complete held/named validation
     * closes it; no selection helper may run before that validation. */
    return stage_check(stage,uid);
}
static int stage_home_reclaim(struct kc_stage *stage,uid_t uid) {
    struct stat held,named;char actual[PATH_MAX];
    if(!stage->directories_present[0])return 0;
    if(stage->fds[0]<0||fstat(stage->fds[0],&held)||
        fstatat(stage->parent_fd,stage->name,&named,AT_SYMLINK_NOFOLLOW)||
        !file_matches(&held,&stage->directories[0])||!file_matches(&named,&stage->directories[0])||
        !S_ISDIR(held.st_mode)||(held.st_uid!=0&&held.st_uid!=uid)||
        (held.st_flags!=0&&held.st_flags!=SF_IMMUTABLE)||
        fcntl(stage->fds[0],F_GETPATH,actual)||strcmp(actual,stage->paths[0])||envara_gui_acl_free(actual))return -1;
    if(held.st_flags){
        if(fchflags(stage->fds[0],0))return -1;
        stage->directories[0].flags=0;
    }
    /* Reclaim through the held FD before removing any entry. An unrelated
     * same-UID process can still hold this directory open during unsealing.
     * Its race is detected by the complete validation below, after ownership
     * and permissions are again root-controlled. Never recursively delete. */
    if(fchown(stage->fds[0],0,(gid_t)-1))return -1;
    stage->directories[0].owner=0;
    if(fchmod(stage->fds[0],0700))return -1;
    stage->directories[0].mode=(stage->directories[0].mode&S_IFMT)|0700;
    return 0;
}
static int stage_cleanup_check(const struct kc_stage *stage,uid_t uid) {
    struct stat held,named;char actual[PATH_MAX];const char *names[]={stage->name,"Library","Preferences"};
    for(int i=0;i<3;i++)if(stage->directories_present[i]){
        if(stage->fds[i]<0||fstat(stage->fds[i],&held)||
            fstatat(i?stage->fds[i-1]:stage->parent_fd,names[i],&named,AT_SYMLINK_NOFOLLOW)||
            !file_matches(&held,&stage->directories[i])||!file_matches(&named,&stage->directories[i])||
            !S_ISDIR(held.st_mode)||held.st_uid||held.st_flags||(held.st_mode&022)||
            (i==0&&(held.st_mode&07777)!=0700)||
            fcntl(stage->fds[i],F_GETPATH,actual)||strcmp(actual,stage->paths[i])||envara_gui_acl_free(actual))return -1;
    }
    if(stage->file_present){
        char path[PATH_MAX];
        if(stage->file_fd<0||fstat(stage->file_fd,&held)||
            fstatat(stage->fds[2],"com.apple.security.plist",&named,AT_SYMLINK_NOFOLLOW)||
            !file_matches(&held,&stage->file)||!file_matches(&named,&stage->file)||!S_ISREG(held.st_mode)||
            (held.st_uid!=0&&held.st_uid!=uid)||held.st_nlink!=1||held.st_flags||(held.st_mode&022)||
            snprintf(path,sizeof(path),"%s/com.apple.security.plist",stage->paths[2])>=(int)sizeof(path)||
            envara_gui_acl_free(path))return -1;
    }
    return 0;
}
/* The caller must hold actual terminal-wait and scope-absence proof. An
 * uncertain helper keeps the sealed HOME, descriptors and names in custody. */
static int stage_close(struct kc_stage *stage,uid_t uid) {
    if(stage->parent_fd<0)return 0;
    if(stage_home_reclaim(stage,uid)||stage_cleanup_check(stage,uid))return -1;
    struct stat held,named;const char *names[]={stage->name,"Library","Preferences"};
    if(stage->file_present){
        if(stage->file_fd<0||fstat(stage->file_fd,&held)||
            fstatat(stage->fds[2],"com.apple.security.plist",&named,AT_SYMLINK_NOFOLLOW)||
            !file_matches(&held,&stage->file)||!file_matches(&named,&stage->file)||
            unlinkat(stage->fds[2],"com.apple.security.plist",0))return -1;
        stage->file_present=0;
    }
    if(stage->file_fd>=0){close(stage->file_fd);stage->file_fd=-1;}
    for(int i=2;i>=0;i--)if(stage->directories_present[i]){int parent=i?stage->fds[i-1]:stage->parent_fd;
        if(stage->fds[i]<0||fstat(stage->fds[i],&held)||fstatat(parent,names[i],&named,AT_SYMLINK_NOFOLLOW)||
            !file_matches(&held,&stage->directories[i])||!file_matches(&named,&stage->directories[i])||
            unlinkat(parent,names[i],AT_REMOVEDIR))return -1;
        close(stage->fds[i]);stage->fds[i]=-1;stage->directories_present[i]=0;
    }
    close(stage->parent_fd);stage_init(stage);return 0;
}
static int stage_open(envara_app_keychain_custody *slot,const struct kc_holds *holds,uid_t uid) {
    struct kc_stage *stage=&slot->stage;if(stage->parent_fd>=0)return -1;
    if(stage_parent(stage,holds))return -1;
    unsigned char nonce[16];arc4random_buf(nonce,sizeof(nonce));
    snprintf(stage->name,sizeof(stage->name),".keychain-selection-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        nonce[0],nonce[1],nonce[2],nonce[3],nonce[4],nonce[5],nonce[6],nonce[7],nonce[8],nonce[9],nonce[10],nonce[11],nonce[12],nonce[13],nonce[14],nonce[15]);
    const char *names[]={stage->name,"Library","Preferences"};
    for(int i=0;i<3;i++){int parent=i?stage->fds[i-1]:stage->parent_fd;char parent_path[PATH_MAX];struct stat s;
        if(fcntl(parent,F_GETPATH,parent_path)||snprintf(stage->paths[i],PATH_MAX,"%s/%s",parent_path,names[i])>=PATH_MAX||
            mkdirat(parent,names[i],0700))return -1;
        stage->directories_present[i]=1;
        stage->fds[i]=openat(parent,names[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(stage->fds[i]<0||fstat(stage->fds[i],&s))return -1;
        stage->directories[i]=file_identity(&s);
        if(!S_ISDIR(s.st_mode)||s.st_uid||s.st_flags||(s.st_mode&07777)!=0700||fchmod(stage->fds[i],0755))return -1;
        /* Record only this exact held FD's successful mutation. A transient
         * readback failure must not leave a known old mode in custody. */
        stage->directories[i].mode=(stage->directories[i].mode&S_IFMT)|0755;
        if(fstat(stage->fds[i],&s))return -1;
        stage->directories[i]=file_identity(&s);
    }
    stage->file_fd=openat(stage->fds[2],"com.apple.security.plist",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat s;
    if(stage->file_fd<0)return -1;stage->file_present=1;
    if(fstat(stage->file_fd,&s))return -1;stage->file=file_identity(&s);
    if(!S_ISREG(s.st_mode)||s.st_uid||s.st_flags||s.st_nlink!=1||fchown(stage->file_fd,uid,(gid_t)-1))return -1;
    stage->file.owner=uid;
    if(fstat(stage->file_fd,&s))return -1;
    stage->file=file_identity(&s);
    if(fchmod(stage->file_fd,0600))return -1;
    stage->file.mode=(stage->file.mode&S_IFMT)|0600;
    if(fstat(stage->file_fd,&s))return -1;
    stage->file=file_identity(&s);stage->file_present=1;return stage_home_seal(stage,uid);
}
static int stage_load(struct kc_stage *stage,const struct kc_holds *holds,const struct kc_request *request) {
    stage_init(stage);char parent_path[PATH_MAX],expected[PATH_MAX];
    if(stage_parent(stage,holds)||fcntl(stage->parent_fd,F_GETPATH,parent_path))return -1;
    const char *name=strrchr(request->selector_home,'/');if(!name)return -1;name++;
    const char *prefix=".keychain-selection-";size_t prefix_size=strlen(prefix);
    if(strncmp(name,prefix,prefix_size)||strlen(name)!=prefix_size+32)return -1;
    for(size_t i=prefix_size;i<prefix_size+32;i++)if(!strchr("0123456789abcdef",name[i]))return -1;
    if(snprintf(expected,PATH_MAX,"%s/%s",parent_path,name)>=PATH_MAX||strcmp(expected,request->selector_home))return -1;
    strcpy(stage->name,name);const char *names[]={stage->name,"Library","Preferences"};
    for(int i=0;i<3;i++){int parent=i?stage->fds[i-1]:stage->parent_fd;
        if(snprintf(stage->paths[i],PATH_MAX,"%s/%s",i?stage->paths[i-1]:parent_path,names[i])>=PATH_MAX)return -1;
        stage->fds[i]=openat(parent,names[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        stage->directories[i]=request->selector_directories[i];
        stage->directories_present[i]=1;
    }
    stage->file_fd=openat(stage->fds[2],"com.apple.security.plist",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    stage->file=request->selector_file;stage->file_present=1;return stage_check(stage,request->uid);
}
static int stage_publish(struct kc_stage *stage,const struct kc_holds *holds,uid_t uid) {
    if(stage_check(stage,uid)||holds_check(holds,uid)||selector_state(holds,uid)!=0||fsync(stage->file_fd)||
        renameatx_np(stage->fds[2],"com.apple.security.plist",holds->fds[2],"com.apple.security.plist",RENAME_EXCL))return -1;
    stage->file_present=0;
    struct stat named,held;
    return fstat(stage->file_fd,&held)||fstatat(holds->fds[2],"com.apple.security.plist",&named,AT_SYMLINK_NOFOLLOW)||
        !file_matches(&held,&stage->file)||!file_matches(&named,&stage->file)||held.st_nlink!=1||fsync(holds->fds[2])?-1:0;
}
static int pipe_identity(int fd, int direction, const struct kc_file *expected) {
    struct stat s;int flags=fcntl(fd,F_GETFL);
    /* Darwin synthesizes anonymous-pipe st_uid/st_gid from the observer's
     * credentials. They change after the console-UID drop, unlike the held
     * endpoint identity. Authority comes from the fixed root parent and the
     * inherited endpoint binding, never from these synthetic owner fields. */
    return flags>=0&&(flags&O_ACCMODE)==direction&&!fstat(fd,&s)&&S_ISFIFO(s.st_mode)&&s.st_nlink==0&&
        (!expected||((uint64_t)s.st_dev==expected->device&&(uint64_t)s.st_ino==expected->inode&&(uint32_t)s.st_mode==expected->mode));
}
static int transfer(int fd,void *bytes,size_t size,int writing,int64_t deadline) {
    unsigned char *p=bytes;
    while(size) {int64_t now=now_ms();if(now<0||now>=deadline)return -1;
        struct pollfd event={fd,writing?POLLOUT:POLLIN,0};int n=poll(&event,1,(int)(deadline-now));
        if(n<0&&errno==EINTR)continue;if(n<=0||(event.revents&(POLLERR|POLLNVAL)))return -1;
        ssize_t got=writing?write(fd,p,size):read(fd,p,size);
        if(got<0&&(errno==EINTR||errno==EAGAIN))continue;if(got<=0)return -1;
        p+=got;size-=(size_t)got;
    }return 0;
}
static int no_more_input(int fd,int64_t deadline) {
    for(;;){int64_t now=now_ms();if(now<0||now>=deadline)return 0;
        struct pollfd event={fd,POLLIN|POLLHUP,0};int n=poll(&event,1,(int)(deadline-now));
        if(n<0&&errno==EINTR)continue;if(n<=0||(event.revents&(POLLERR|POLLNVAL)))return 0;
        unsigned char extra;ssize_t got=read(fd,&extra,1);
        if(got<0&&(errno==EINTR||errno==EAGAIN))continue;return got==0;
    }
}
static int fixed_process(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE]={0};int size=proc_pidpath(pid,path,sizeof(path));
    return size>0&&size<(int)sizeof(path)&&memchr(path,0,(size_t)size+1)&&
        !strcmp(path,ENVARA_GUI_NATIVE_PATH)&&envara_root_owned_executable(path);
}
static int session_matches(uid_t uid,uint32_t audit) {
    struct envara_gui_session s;return !envara_gui_session_read(&s)&&s.console_uid==uid&&s.audit_session==audit&&
        s.audit_has_console_graphics&&s.security_has_graphics;
}
static int key_path(SecKeychainRef key,char out[PATH_MAX]) {
    UInt32 size=PATH_MAX;memset(out,0,PATH_MAX);
    return SecKeychainGetPath(key,&size,out)||!memchr(out,0,PATH_MAX)||!out[0] ? -1 : 0;
}
static int search_digest(CFArrayRef list,const char *selected,unsigned char digest[CC_SHA256_DIGEST_LENGTH],uint32_t *count,int *contains) {
    if(!list||CFGetTypeID(list)!=CFArrayGetTypeID()||CFArrayGetCount(list)>64)return -1;
    CC_SHA256_CTX hash;CC_SHA256_Init(&hash);*count=(uint32_t)CFArrayGetCount(list);*contains=0;
    CC_SHA256_Update(&hash,count,sizeof(*count));
    for(CFIndex i=0;i<CFArrayGetCount(list);i++){CFTypeRef key=CFArrayGetValueAtIndex(list,i);char path[PATH_MAX];
        if(!key||CFGetTypeID(key)!=SecKeychainGetTypeID()||key_path((SecKeychainRef)key,path))return -1;
        uint32_t length=(uint32_t)strlen(path);CC_SHA256_Update(&hash,&length,sizeof(length));CC_SHA256_Update(&hash,path,length);
        if(!strcmp(path,selected))*contains=1;
    }CC_SHA256_Final(digest,&hash);return 0;
}
static int metadata(struct kc_reply *reply,uid_t uid) {
    helper_failure=0;
    SecKeychainRef key=NULL;OSStatus status=SecKeychainCopyDefault(&key);
    if(status==errSecNoDefaultKeychain&&!key){reply->result=KC_ABSENT;return 0;}
    if(status||!key){if(key)CFRelease(key);return helper_fail(ENVARA_KEYCHAIN_EXIT_COPY_DEFAULT);}
    SecKeychainStatus flags=0;
    int fail=0;
    if(key_path(key,reply->selected))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_DEFAULT_PATH);
    else if(canonical_owned(reply->selected,uid,0,NULL))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_DEFAULT_OWNER);
    else if(SecKeychainGetStatus(key,&flags))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_DEFAULT_STATUS);
    CFRelease(key);if(fail)return -1;reply->unlocked=(flags&kSecUnlockStateStatus)!=0;
    CFArrayRef merged=NULL,user=NULL;int contains=0,ignored=0;
    status=SecKeychainCopySearchList(&merged);
    if(status)fail=helper_fail(ENVARA_KEYCHAIN_EXIT_SEARCH_LIST);
    else if(SecKeychainCopyDomainSearchList(kSecPreferencesDomainUser,&user))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_DOMAIN_SEARCH);
    else if(search_digest(merged,reply->selected,reply->merged_digest,&reply->merged_count,&contains))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_SEARCH_DIGEST);
    else if(!contains)fail=helper_fail(ENVARA_KEYCHAIN_EXIT_SEARCH_MISSING);
    else if(search_digest(user,reply->selected,reply->user_digest,&reply->user_count,&ignored))fail=helper_fail(ENVARA_KEYCHAIN_EXIT_SEARCH_DIGEST);
    if(merged)CFRelease(merged);if(user)CFRelease(user);return fail?-1:0;
}
static void alarm_exit(int sig) {(void)sig;_exit(ENVARA_KEYCHAIN_EXIT_TIMEOUT);}

int envara_app_keychain_command(int argc,char **argv) {
    helper_failure=0;
    if(argc!=2||strcmp(argv[1],"app-keychain-helper")||!getuid()||getuid()!=geteuid())return ENVARA_KEYCHAIN_EXIT_ENTRY;
    if(!pipe_identity(0,O_RDONLY,NULL)||!pipe_identity(1,O_WRONLY,NULL))return ENVARA_KEYCHAIN_EXIT_PIPES;
    signal(SIGALRM,alarm_exit);alarm(10);
    struct kc_request r;struct kc_reply reply;memset(&reply,0,sizeof(reply));
    int64_t deadline=now_ms()+KC_TIMEOUT_MS;
    if(transfer(0,&r,sizeof(r),0,deadline)||!no_more_input(0,deadline))return ENVARA_KEYCHAIN_EXIT_REQUEST_READ;
    struct envara_identity self;gid_t group=0;char expected[PATH_MAX];
    if(r.schema!=KC_SCHEMA||r.mode<KC_SCOPED||r.mode>KC_SELECT||!r.uid||!r.audit||!r.generation||!uuid(r.version)||!uuid(r.run)||
        r.gid<ENVARA_REALM_GID_MIN||r.gid>ENVARA_REALM_GID_MAX||
        !memchr(r.home,0,sizeof(r.home))||!memchr(r.selected,0,sizeof(r.selected))||!memchr(r.selector_home,0,sizeof(r.selector_home))||
        expected_home(r.environment,r.registration,expected)||strcmp(expected,r.home))return ENVARA_KEYCHAIN_EXIT_REQUEST_SHAPE;
    if(envara_identity_read(getpid(),&self)||!envara_identity_matches(&self,r.uid,r.gid)||
        getgroups(1,&group)!=1||group!=r.gid)return ENVARA_KEYCHAIN_EXIT_SELF_IDENTITY;
    if(self.parent_pid!=getppid()||!parent_matches(&r.parent))return ENVARA_KEYCHAIN_EXIT_PARENT_IDENTITY;
    if(!fixed_process(getppid())||!fixed_process(getpid()))return ENVARA_KEYCHAIN_EXIT_EXECUTABLE;
    if(!pipe_identity(0,O_RDONLY,&r.input)||!pipe_identity(1,O_WRONLY,&r.output))return ENVARA_KEYCHAIN_EXIT_PIPE_BINDING;
    if(!session_matches(r.uid,r.audit))return ENVARA_KEYCHAIN_EXIT_SESSION;
    struct passwd *account=getpwuid(r.uid);const char *home=getenv("HOME");
    if(!account||!account->pw_dir||!home||!strcmp(r.home,account->pw_dir)||
        strcmp(home,r.mode==KC_NORMAL?account->pw_dir:r.mode==KC_SELECT?r.selector_home:r.home))return ENVARA_KEYCHAIN_EXIT_HOME;
    struct kc_holds holds;if(holds_open(r.home,r.uid,0,&holds))return ENVARA_KEYCHAIN_EXIT_HOLDS_OPEN;
    for(int i=0;i<3;i++)if(memcmp(&holds.identities[i],&r.directories[i],sizeof(r.directories[i]))){holds_close(&holds);return ENVARA_KEYCHAIN_EXIT_HOLDS_BINDING;}
    int state=selector_state(&holds,r.uid);
    if(state<0||(r.mode==KC_SELECT&&(state!=0||canonical_owned(r.selected,r.uid,0,NULL)))){holds_close(&holds);return ENVARA_KEYCHAIN_EXIT_SELECTOR;}
    struct kc_stage stage;stage_init(&stage);
    if(r.mode==KC_SELECT&&stage_load(&stage,&holds,&r)){stage_release_fds(&stage);holds_close(&holds);return ENVARA_KEYCHAIN_EXIT_STAGE_LOAD;}
    char profile[PATH_MAX+256];int n=snprintf(profile,sizeof(profile),"(version 1)(allow default)(deny network*)(deny file-write*)");
    if(r.mode==KC_SELECT)n=snprintf(profile,sizeof(profile),
        "(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (literal \"%s/Library/Preferences/com.apple.security.plist\"))",r.selector_home);
    char *sandbox_error=NULL;
    if(n<0||n>=(int)sizeof(profile)||sandbox_init(profile,0,&sandbox_error)) {if(sandbox_error)sandbox_free_error(sandbox_error);stage_release_fds(&stage);holds_close(&holds);return ENVARA_KEYCHAIN_EXIT_SANDBOX;}
    if(sandbox_error)sandbox_free_error(sandbox_error);
    Boolean interactive=true;
    if(SecKeychainSetUserInteractionAllowed(false)||SecKeychainGetUserInteractionAllowed(&interactive)||interactive){stage_release_fds(&stage);holds_close(&holds);return ENVARA_KEYCHAIN_EXIT_INTERACTION;}
    int failed=0;
    if(r.mode==KC_SELECT){SecKeychainRef key=NULL;
        if(holds_check(&holds,r.uid)||selector_state(&holds,r.uid)!=0||stage_check(&stage,r.uid))failed=helper_fail(ENVARA_KEYCHAIN_EXIT_SELECT_RECHECK);
        else if(SecKeychainOpen(r.selected,&key)||!key)failed=helper_fail(ENVARA_KEYCHAIN_EXIT_KEYCHAIN_OPEN);
        if(!failed&&SecKeychainSetDefault(key)!=errSecSuccess)failed=helper_fail(ENVARA_KEYCHAIN_EXIT_SET_DEFAULT);
        if(key)CFRelease(key);
        if(!failed&&(holds_check(&holds,r.uid)||selector_state(&holds,r.uid)!=0||stage_check(&stage,r.uid)))failed=helper_fail(ENVARA_KEYCHAIN_EXIT_SELECT_POSTCHECK);
    }else {failed=metadata(&reply,r.uid);if(!failed&&holds_check(&holds,r.uid))failed=helper_fail(ENVARA_KEYCHAIN_EXIT_METADATA_POSTCHECK);}
    stage_release_fds(&stage);holds_close(&holds);reply.schema=KC_SCHEMA;memcpy(reply.nonce,r.nonce,sizeof(reply.nonce));if(failed)reply.result=KC_REFUSED;
    int sent=transfer(1,&reply,sizeof(reply),1,deadline);memset(&r,0,sizeof(r));memset(&reply,0,sizeof(reply));alarm(0);
    if(sent&&!helper_failure)helper_failure=ENVARA_KEYCHAIN_EXIT_REPLY_WRITE;
    return sent||failed?(int)helper_failure:0;
}

/* Only this module owns these proof transitions. Public consumers receive an
 * opaque slot, not writable child/reaped flags or a PID adoption interface. */
static int slot_metadata_binding(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run) {
    return slot&&slot==owned_slot&&app&&request&&run&&uuid(run)&&getpid()==slot->owner.pid&&
        !memcmp(app,&slot->app,sizeof(*app))&&
        !memcmp(request,&slot->request,sizeof(*request))&&!strcmp(run,slot->run_id);
}
static int slot_binding(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run) {
    return slot_metadata_binding(slot,app,request,run)&&envara_same_process(&slot->owner);
}
int envara_app_keychain_custody_create(const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *run,envara_app_keychain_custody **out) {
    if(!out)return refuse(EINVAL);*out=NULL;
    if(owned_slot||getuid()||geteuid()||!fixed_process(getpid())||!app||!request||!run||
        !uuid(run)||!uuid(app->registration_id)||!uuid(app->version_id)||!uuid(request->environment_id)||!uuid(request->lease_id)||
        !request->console_uid||request->realm_gid<ENVARA_REALM_GID_MIN||request->realm_gid>ENVARA_REALM_GID_MAX)return refuse(EACCES);
    envara_app_keychain_custody *slot=calloc(1,sizeof(*slot));if(!slot)return -1;
    if(envara_identity_read(getpid(),&slot->owner)||slot->owner.uid||slot->owner.ruid||slot->owner.saved_uid){free(slot);return refuse(EACCES);}
    slot->app=*app;slot->request=*request;strcpy(slot->run_id,run);slot->child.error_fd=-1;
    slot->diagnostic_step=slot->helper_step=-1;stage_init(&slot->stage);
    unsigned char id[16];arc4random_buf(id,sizeof(id));id[6]=(id[6]&15)|64;id[8]=(id[8]&63)|128;
    snprintf(slot->slot_id,sizeof(slot->slot_id),"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        id[0],id[1],id[2],id[3],id[4],id[5],id[6],id[7],id[8],id[9],id[10],id[11],id[12],id[13],id[14],id[15]);
    owned_slot=slot;*out=slot;return 0;
}
int envara_app_keychain_custody_pending(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run) {
    /* This is a read of our own latch, not a release proof. An unavailable
     * BSD query cannot turn a never-used (generation zero) slot into a helper. */
    if(!slot)return 0;if(!slot_metadata_binding(slot,app,request,run))return refuse(EACCES);return slot->active!=0;
}
int envara_app_keychain_custody_snapshot(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run,
    struct envara_app_keychain_snapshot *out) {
    /* Diagnostics remain available if a later process-inventory query is
     * unavailable. The registered pointer, same process and immutable binding
     * are enough to read; cleanup still independently requires live identity. */
    if(!out||!slot_metadata_binding(slot,app,request,run))return refuse(EACCES);memset(out,0,sizeof(*out));
    strcpy(out->slot_id,slot->slot_id);out->generation=slot->generation;out->pending=slot->active;
    switch(slot->wait_proof){
        case KC_NO_PENDING_FROM_LAUNCHER:out->child_state=ENVARA_APP_KEYCHAIN_LAUNCHER_CLEAR;break;
        case KC_OWNED_UNREAPED:out->child_state=ENVARA_APP_KEYCHAIN_UNWAITED;break;
        case KC_OWNED_TERMINAL_WAIT:out->child_state=ENVARA_APP_KEYCHAIN_REAPED;break;
        case KC_UNKNOWN_WAIT:out->child_state=ENVARA_APP_KEYCHAIN_UNKNOWN;break;
    }return 0;
}
static int cleanup_slot(envara_app_keychain_custody *slot,int cancel,unsigned wait_ms,int preserve_stage) {
    if(!slot||slot!=owned_slot||getpid()!=slot->owner.pid||!envara_same_process(&slot->owner))return -1;
    if(!slot->active)return envara_app_scope_gid_absent(slot->request.realm_gid)==1?1:0;
    if(slot->wait_proof==KC_OWNED_UNREAPED){
        if(slot->child.identity.pid<2){slot->wait_proof=KC_UNKNOWN_WAIT;return 0;}
        int64_t start=now_ms(),deadline=start+wait_ms;int signalled=0;
        for(;;){int status=0;pid_t got=waitpid(slot->child.identity.pid,&status,WNOHANG);
            if(got==slot->child.identity.pid&&(WIFEXITED(status)||WIFSIGNALED(status))){
                slot->wait_proof=KC_OWNED_TERMINAL_WAIT;slot->wait_status=status;break;
            }
            if(got<0&&errno!=EINTR){slot->wait_proof=KC_UNKNOWN_WAIT;return 0;}
            /* This PID comes only from this module's fresh launcher. A zero
             * exact wait proves our direct child is still unreaped, even if
             * initial BSD birth inspection failed. This synchronous keeper
             * has no other reaper for the private helper PID; without a reap
             * the kernel cannot reuse it. Never apply this rule to observed,
             * adopted, terminal, ECHILD or unknown application identities. */
            if(got==0&&cancel&&!signalled){
                if(!private_wait_policy())return 0;
                if(kill(slot->child.identity.pid,SIGKILL)&&errno!=ESRCH)return 0;
                signalled=1;
            }
            int64_t now=now_ms();if(start<0||now<0||now>=deadline)return 0;
            struct timespec pause={0,10000000};(void)nanosleep(&pause,NULL);
        }
    }
    if(slot->wait_proof!=KC_OWNED_TERMINAL_WAIT&&slot->wait_proof!=KC_NO_PENDING_FROM_LAUNCHER)return 0;
    /* No-PID comes only from this module's fresh launcher output: that
     * function clears it solely before fork or after its own terminal wait. */
    slot->scope_confirmed=envara_app_scope_gid_absent(slot->request.realm_gid)==1;
    if(!slot->scope_confirmed)return 0;
    /* A diagnostic observes our existing proof; it cannot produce one. No
     * helper exit is trusted after ECHILD, an unknown wait, or unknown scope. */
    if(slot->wait_proof==KC_OWNED_TERMINAL_WAIT&&WIFEXITED(slot->wait_status))
        slot->helper_step=helper_step(WEXITSTATUS(slot->wait_status));
    if(!preserve_stage&&stage_close(&slot->stage,slot->request.console_uid))return 0;
    if(slot->child.error_fd>=0)close(slot->child.error_fd);
    memset(&slot->child,0,sizeof(slot->child));slot->child.error_fd=-1;slot->active=0;return 1;
}
int envara_app_keychain_custody_cleanup(envara_app_keychain_custody *slot,
    const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run) {
    if(!slot_binding(slot,app,request,run))return refuse(EACCES);return cleanup_slot(slot,1,0,0);
}
int envara_app_keychain_custody_destroy(envara_app_keychain_custody *slot) {
    if(!slot)return 0;
    if(slot!=owned_slot||getpid()!=slot->owner.pid||!envara_same_process(&slot->owner)||slot->active||slot->stage.parent_fd>=0)return refuse(EBUSY);
    memset(slot,0,sizeof(*slot));free(slot);owned_slot=NULL;return 0;
}
static int run_helper(envara_app_keychain_custody *slot,const struct kc_holds *holds,
    enum kc_mode mode,const char *selected,const struct envara_gui_stage_authority *authority,int64_t operation_deadline,struct kc_reply *reply) {
    const struct envara_gui_request *request=&slot->request;
    int64_t started=now_ms(),deadline=started+KC_TIMEOUT_MS;
    if(started<0||started>=operation_deadline)return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_DEADLINE,ETIMEDOUT);
    if(deadline>operation_deadline)deadline=operation_deadline;
    if(slot->active||slot->generation>=5)return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_CONTEXT,EACCES);
    if(!private_wait_policy())return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_WAIT_POLICY,EACCES);
    slot->helper_step=-1;
    struct kc_request r;memset(&r,0,sizeof(r));r.schema=KC_SCHEMA;r.mode=mode;r.uid=request->console_uid;r.gid=request->realm_gid;r.audit=request->gui_audit_session;
    memcpy(r.environment,request->environment_id,sizeof(r.environment));memcpy(r.registration,slot->app.registration_id,sizeof(r.registration));
    memcpy(r.version,slot->app.version_id,sizeof(r.version));memcpy(r.run,slot->run_id,sizeof(r.run));r.generation=slot->generation+1;
    strcpy(r.home,holds->paths[0]);if(selected)strcpy(r.selected,selected);memcpy(r.directories,holds->identities,sizeof(r.directories));
    if(mode==KC_SELECT){if(stage_check(&slot->stage,r.uid))return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_STAGE,EACCES);
        strcpy(r.selector_home,slot->stage.paths[0]);memcpy(r.selector_directories,slot->stage.directories,sizeof(r.selector_directories));r.selector_file=slot->stage.file;
    }
    arc4random_buf(r.nonce,sizeof(r.nonce));
    struct passwd *account=getpwuid(r.uid);char home[PATH_MAX+8],user[256],login[256];
    if(!account||!account->pw_dir||!account->pw_name)return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_ACCOUNT,EACCES);
    if(envara_identity_read(getpid(),&r.parent))return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_IDENTITY,EACCES);
    if(snprintf(home,sizeof(home),"HOME=%s",mode==KC_NORMAL?account->pw_dir:mode==KC_SELECT?r.selector_home:r.home)>=(int)sizeof(home)||
        snprintf(user,sizeof(user),"USER=%s",account->pw_name)>=(int)sizeof(user)||
        snprintf(login,sizeof(login),"LOGNAME=%s",account->pw_name)>=(int)sizeof(login))return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_ENVIRONMENT,EACCES);
    if(holds_check(holds,r.uid))return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_HOLDS,EACCES);
    if(authority->verify_committed_deny(request,authority->context))return parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_DENY,EACCES);
    char *environment[]={home,user,login,"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LANG=C","LC_ALL=C",NULL};
    char *arguments[]={ENVARA_GUI_NATIVE_PATH,"app-keychain-helper",NULL};
    int input[2]={-1,-1},output[2]={-1,-1},result=-1;
#define RUN_FAIL(condition,gate) do {if(condition){(void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_##gate,EACCES);goto done;}}while(0)
#define CHILD_FAIL(condition,gate) do {if(condition){(void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_##gate,EACCES);(void)cleanup_slot(slot,0,2000,1);goto done;}}while(0)
    RUN_FAIL(pipe(input)||pipe(output),PIPES);
    int all[]={input[0],input[1],output[0],output[1]};
    for(unsigned i=0;i<4;i++)RUN_FAIL(fcntl(all[i],F_SETFD,FD_CLOEXEC)||fcntl(all[i],F_SETFL,O_NONBLOCK),PIPES);
    RUN_FAIL(fcntl(input[1],F_SETNOSIGPIPE,1),PIPES);
    struct stat in,out;RUN_FAIL(fstat(input[0],&in)||fstat(output[1],&out),PIPES);r.input=file_identity(&in);r.output=file_identity(&out);
    RUN_FAIL(!private_wait_policy(),WAIT_POLICY);
    slot->active=1;slot->generation=r.generation;slot->scope_confirmed=0;slot->wait_proof=KC_NO_PENDING_FROM_LAUNCHER;slot->wait_status=0;
    memset(&slot->child,0,sizeof(slot->child));slot->child.error_fd=-1;
    int spawned=envara_spawn_suspended_io(r.uid,r.gid,r.home,ENVARA_GUI_NATIVE_PATH,arguments,environment,0,input[0],output[1],&slot->child);
    if(slot->child.identity.pid>1)slot->wait_proof=KC_OWNED_UNREAPED;
    close(input[0]);input[0]=-1;close(output[1]);output[1]=-1;
    CHILD_FAIL(spawned,SPAWN);
    CHILD_FAIL(!fixed_process(slot->child.identity.pid),CHILD);
    CHILD_FAIL(holds_check(holds,r.uid),HOLDS);
    CHILD_FAIL(transfer(input[1],&r,sizeof(r),1,deadline),WRITE);
    close(input[1]);input[1]=-1;
    CHILD_FAIL(envara_child_resume(&slot->child),RESUME);
    CHILD_FAIL(transfer(output[0],reply,sizeof(*reply),0,deadline),READ);
    CHILD_FAIL(reply->schema!=KC_SCHEMA||memcmp(reply->nonce,r.nonce,sizeof(r.nonce))||reply->result>KC_REFUSED||
        !memchr(reply->selected,0,sizeof(reply->selected)),REPLY);
    RUN_FAIL(cleanup_slot(slot,0,2000,1)!=1,WAIT_SCOPE);
    RUN_FAIL(!WIFEXITED(slot->wait_status)||WEXITSTATUS(slot->wait_status),EXIT);
    RUN_FAIL(reply->result==KC_REFUSED,REPLY);
    RUN_FAIL(!no_more_input(output[0],deadline),TRAILING);
    RUN_FAIL(holds_check(holds,r.uid),HOLDS);
    result=0;
done:
    for(int i=0;i<2;i++){if(input[i]>=0)close(input[i]);if(output[i]>=0)close(output[i]);}
    memset(&r,0,sizeof(r));return result?refuse(EACCES):0;
#undef CHILD_FAIL
#undef RUN_FAIL
}
static int same_selection(const struct kc_reply *a,const struct kc_reply *b) {
    return a->result==KC_OK&&b->result==KC_OK&&!strcmp(a->selected,b->selected)&&a->merged_count==b->merged_count&&a->user_count==b->user_count&&
        !memcmp(a->merged_digest,b->merged_digest,sizeof(a->merged_digest))&&!memcmp(a->user_digest,b->user_digest,sizeof(a->user_digest));
}
int envara_app_keychain_prepare(envara_app_keychain_custody *slot,const struct envara_app_registration *app,
    const struct envara_gui_request *request,const char *home,const struct envara_gui_stage_authority *authority) {
    char expected[PATH_MAX];int64_t started=now_ms(),deadline=started+KC_PREPARE_TIMEOUT_MS;
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_BEGIN);
    if(getuid()||geteuid()||!slot||slot!=owned_slot||!slot_binding(slot,app,request,slot->run_id)||slot->active||!home||
        !authority||!authority->verify_committed_deny||!fixed_process(getpid())||
        expected_home(request->environment_id,app->registration_id,expected)||strcmp(home,expected)){
        envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_PARENT_CONTEXT);return refuse(EACCES);
    }
    slot->diagnostic_step=slot->helper_step=-1;slot->diagnostic_emitted=0;
#define EARLY_FAIL(condition,gate) do {if(condition){(void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_##gate,EACCES);diagnostic_emit(slot);return refuse(EACCES);}}while(0)
    EARLY_FAIL(started<0,DEADLINE);
    EARLY_FAIL(!session_matches(request->console_uid,request->gui_audit_session),SESSION);
    EARLY_FAIL(authority->verify_committed_deny(request,authority->context),DENY);
    struct kc_holds holds;EARLY_FAIL(holds_open(home,request->console_uid,1,&holds),HOLDS);
#undef EARLY_FAIL
    int result=-1,state=selector_state(&holds,request->console_uid),final_state=1;struct kc_reply scoped,before,selected,verified,after;
    memset(&scoped,0,sizeof(scoped));memset(&before,0,sizeof(before));memset(&selected,0,sizeof(selected));memset(&verified,0,sizeof(verified));memset(&after,0,sizeof(after));
#define PREP_FAIL(condition,gate) do {if(condition){(void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_##gate,EACCES);goto done;}}while(0)
    PREP_FAIL(state<0,SELECTOR);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_SCOPED);
    if(run_helper(slot,&holds,KC_SCOPED,NULL,authority,deadline,&scoped))goto done;
    /* Security can derive a valid scoped login keychain without storing a
     * plist default entry. Preserve that identity too; plist absence alone
     * never authorizes rebinding an existing usable scoped default. */
    if(scoped.result==KC_OK){result=0;final_state=state;goto done;}
    PREP_FAIL(state==1||scoped.result!=KC_ABSENT,SELECTOR);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_NORMAL);
    if(run_helper(slot,&holds,KC_NORMAL,NULL,authority,deadline,&before))goto done;
    PREP_FAIL(before.result!=KC_OK,VERIFY);
    PREP_FAIL(selector_state(&holds,request->console_uid)!=0,SELECTOR);
    PREP_FAIL(stage_open(slot,&holds,request->console_uid),STAGE_OPEN);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_STAGE_READY);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_SELECT);
    if(run_helper(slot,&holds,KC_SELECT,before.selected,authority,deadline,&selected))goto done;
    PREP_FAIL(selected.result!=KC_OK,VERIFY);
    PREP_FAIL(stage_publish(&slot->stage,&holds,request->console_uid),PUBLISH);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_PUBLISHED);
    PREP_FAIL(stage_close(&slot->stage,request->console_uid),STAGE_CLOSE);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_STAGE_CLEANED);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_VERIFY);
    if(run_helper(slot,&holds,KC_SCOPED,NULL,authority,deadline,&verified))goto done;
    PREP_FAIL(verified.result!=KC_OK||strcmp(verified.selected,before.selected),VERIFY);
    envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_HOST_VERIFY);
    if(run_helper(slot,&holds,KC_NORMAL,NULL,authority,deadline,&after))goto done;
    PREP_FAIL(!same_selection(&before,&after),HOST_CHANGED);
    result=0;
done:
    if(slot->stage.parent_fd>=0){
        /* This also covers a partial staging failure after the preceding
         * metadata helper was reaped. Obtain a fresh scope proof before any
         * removal; unknown custody keeps the private staging resources. */
        slot->active=1;result=-1;
        (void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_STAGE_CLOSE,EACCES);
        (void)cleanup_slot(slot,0,0,0);
    }
    if(holds_check(&holds,request->console_uid)||selector_state(&holds,request->console_uid)!=final_state){
        result=-1;(void)parent_fail(slot,ENVARA_GUI_STEP_KEYCHAIN_PARENT_FINAL,EACCES);
    }
    holds_close(&holds);memset(&scoped,0,sizeof(scoped));memset(&before,0,sizeof(before));memset(&selected,0,sizeof(selected));memset(&verified,0,sizeof(verified));memset(&after,0,sizeof(after));
    if(result)diagnostic_emit(slot);else envara_gui_step(ENVARA_GUI_STEP_KEYCHAIN_COMPLETE);
    return result?refuse(EACCES):0;
#undef PREP_FAIL
}
