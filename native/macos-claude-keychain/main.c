#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <sandbox.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

/* This non-privileged helper prepares only a default-keychain selector. It
 * never queries, copies, creates, updates or deletes credential entries. Each
 * Security operation executes in a fresh process because Security caches HOME.
 * The source HOME is supplied by the application main process; a disposable
 * same-user source HOME exercises this identical binary during acceptance. */
#define SCHEMA 1
#define MAX_KEYS 64
#define SELECTOR "com.apple.security.plist"
#define LOCK_NAME ".envara-keychain.lock"
enum mode { QUERY = 1, SELECT = 2 };
struct request { uint32_t schema, mode; char home[PATH_MAX], selected[PATH_MAX]; };
struct reply {
    uint32_t schema; int32_t status; uint32_t present, unlocked, readable, writable;
    uint32_t merged_count, user_count;
    unsigned char merged_digest[CC_SHA256_DIGEST_LENGTH], user_digest[CC_SHA256_DIGEST_LENGTH];
    char selected[PATH_MAX];
};
struct held { int fd, enforce_acl; struct stat identity; char path[PATH_MAX]; };
struct tree { struct held dirs[3]; int selector; struct stat selector_identity; int selector_present; };
static uid_t owner;
static int64_t deadline;
static const char *error_code = "CLAUDE_KEYCHAIN_PREPARATION_FAILED", *error_stage = "arguments";
static OSStatus error_status;
static int has_status;
static int cleanup_failed;
static const char *host_check_code;

static int failure(const char *code, const char *stage, OSStatus status, int known) {
    error_code=code; error_stage=stage; error_status=status; has_status=known; return -1;
}
static int64_t milliseconds(void) {
    struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static int safe_path(const char *path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||!strcmp(path,"/"))return 0;
    for(const unsigned char *p=(const unsigned char *)path;*p;p++)if(*p<32||*p==127||*p=='"'||*p=='\\')return 0;
    return 1;
}
static int nested(const char *parent,const char *path) {
    size_t n=strlen(parent);return !strncmp(parent,path,n)&&(path[n]==0||path[n]=='/');
}
static int identity_matches(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_uid==b->st_uid&&
        a->st_mode==b->st_mode&&a->st_flags==b->st_flags;
}
static int no_acl(const char *path) {
    acl_t acl=acl_get_file(path,ACL_TYPE_EXTENDED);if(!acl)return errno==ENOENT?0:-1;
    acl_entry_t entry;errno=0;int n=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);
    int result=n==-1&&errno==EINVAL?0:-1;acl_free(acl);return result;
}
static int canonical_directory(const char *path,int private_mode,struct held *held) {
    char real[PATH_MAX],actual[PATH_MAX];struct stat s;
    if(!safe_path(path)||!realpath(path,real)||strcmp(path,real)||lstat(path,&s)||!S_ISDIR(s.st_mode)||
        s.st_uid!=owner||(s.st_mode&022)||(private_mode&&(s.st_mode&0777)!=0700)||
        (private_mode&&no_acl(path)))return -1;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    struct stat opened;
    if(fstat(fd,&opened)||!identity_matches(&s,&opened)||fcntl(fd,F_GETPATH,actual)||strcmp(actual,path)){close(fd);return -1;}
    held->fd=fd;held->enforce_acl=private_mode;held->identity=opened;strcpy(held->path,path);return 0;
}
static int held_matches(const struct held *held) {
    struct stat named,opened;char actual[PATH_MAX];
    return held->fd>=0&&!fstat(held->fd,&opened)&&!lstat(held->path,&named)&&
        identity_matches(&opened,&held->identity)&&identity_matches(&named,&held->identity)&&
        !fcntl(held->fd,F_GETPATH,actual)&&!strcmp(actual,held->path)&&(!held->enforce_acl||!no_acl(held->path));
}
static void tree_init(struct tree *tree) {
    memset(tree,0,sizeof(*tree));for(int i=0;i<3;i++)tree->dirs[i].fd=-1;tree->selector=-1;
}
static void tree_release(struct tree *tree) {
    if(tree->selector>=0)close(tree->selector);
    for(int i=2;i>=0;i--)if(tree->dirs[i].fd>=0)close(tree->dirs[i].fd);
    tree_init(tree);
}
static int tree_matches(const struct tree *tree) {
    for(int i=0;i<3;i++)if(!held_matches(&tree->dirs[i]))return 0;
    return 1;
}
static int child_directory(struct held *parent,const char *name,int create,struct held *out) {
    if(!held_matches(parent))return -1;
    char path[PATH_MAX];if(snprintf(path,sizeof(path),"%s/%s",parent->path,name)>=(int)sizeof(path))return -1;
    struct stat s;
    if(fstatat(parent->fd,name,&s,AT_SYMLINK_NOFOLLOW)){
        if(errno!=ENOENT||!create||mkdirat(parent->fd,name,0700))return -1;
    }
    if(canonical_directory(path,0,out)||no_acl(path)||!held_matches(parent))return -1;
    out->enforce_acl=1;
    return 0;
}
static int tree_open(const char *home,int create,struct tree *tree) {
    tree_init(tree);
    if(canonical_directory(home,1,&tree->dirs[0])||
        child_directory(&tree->dirs[0],"Library",create,&tree->dirs[1])||
        child_directory(&tree->dirs[1],"Preferences",create,&tree->dirs[2]))return -1;
    return tree_matches(tree)?0:-1;
}
/* 0 absent, 1 safe existing file, -1 unsafe or unreadable. Never interpret an
 * invalid/locked/unreadable existing selection as permission to replace it. */
static int selector_state(const struct tree *tree) {
    struct stat s;char path[PATH_MAX];
    if(!tree_matches(tree))return -1;
    if(fstatat(tree->dirs[2].fd,SELECTOR,&s,AT_SYMLINK_NOFOLLOW))return errno==ENOENT?0:-1;
    if(snprintf(path,sizeof(path),"%s/%s",tree->dirs[2].path,SELECTOR)>=(int)sizeof(path))return -1;
    return S_ISREG(s.st_mode)&&s.st_uid==owner&&s.st_nlink==1&&!(s.st_mode&022)&&!s.st_flags&&!no_acl(path)?1:-1;
}
static int prior_stage_present(const struct held *home) {
    int fd=dup(home->fd);if(fd<0)return -1;DIR *dir=fdopendir(fd);if(!dir){close(fd);return -1;}
    int found=0;struct dirent *entry;errno=0;
    while((entry=readdir(dir)))if(!strncmp(entry->d_name,".envara-keychain-",17)){found=1;break;}
    if(errno)found=-1;closedir(dir);return found;
}
/* Inspect existing directory/selector identities without creating or replacing
 * anything, including when Security can already derive a usable default. */
static int existing_tree_safe(const char *home) {
    struct tree tree;tree_init(&tree);int result=-1;
    if(canonical_directory(home,1,&tree.dirs[0]))goto done;
    const char *names[]={"Library","Preferences"};
    for(int i=0;i<2;i++){struct stat s;
        if(fstatat(tree.dirs[i].fd,names[i],&s,AT_SYMLINK_NOFOLLOW)){if(errno==ENOENT)result=0;goto done;}
        if(child_directory(&tree.dirs[i],names[i],0,&tree.dirs[i+1]))goto done;
    }
    result=selector_state(&tree)>=0?0:-1;
done:tree_release(&tree);return result;
}
static int key_path(SecKeychainRef key,char path[PATH_MAX]) {
    UInt32 length=PATH_MAX;memset(path,0,PATH_MAX);
    return SecKeychainGetPath(key,&length,path)||!memchr(path,0,PATH_MAX)||!safe_path(path)?-1:0;
}
static int key_file(const char *path) {
    char real[PATH_MAX];struct stat s;
    return safe_path(path)&&realpath(path,real)&&!strcmp(path,real)&&!lstat(path,&s)&&
        S_ISREG(s.st_mode)&&s.st_uid==owner&&s.st_nlink==1&&!(s.st_mode&022);
}
static int digest_list(CFArrayRef list,const char *selected,unsigned char digest[CC_SHA256_DIGEST_LENGTH],uint32_t *count,int *contains) {
    if(!list||CFGetTypeID(list)!=CFArrayGetTypeID()||CFArrayGetCount(list)>MAX_KEYS)return -1;
    CC_SHA256_CTX hash;CC_SHA256_Init(&hash);*count=(uint32_t)CFArrayGetCount(list);*contains=0;
    CC_SHA256_Update(&hash,count,sizeof(*count));
    for(CFIndex i=0;i<CFArrayGetCount(list);i++){
        CFTypeRef key=CFArrayGetValueAtIndex(list,i);char path[PATH_MAX];
        if(!key||CFGetTypeID(key)!=SecKeychainGetTypeID()||key_path((SecKeychainRef)key,path))return -1;
        uint32_t length=(uint32_t)strlen(path);CC_SHA256_Update(&hash,&length,sizeof(length));CC_SHA256_Update(&hash,path,length);
        if(!strcmp(path,selected))*contains=1;
    }
    CC_SHA256_Final(digest,&hash);return 0;
}
static void metadata(struct reply *reply) {
    SecKeychainRef key=NULL;reply->status=SecKeychainCopyDefault(&key);
    if(reply->status||!key){if(key){reply->present=1;CFRelease(key);}if(!reply->status)reply->status=errSecInternalComponent;return;}
    reply->present=1;SecKeychainStatus flags=0;
    if(key_path(key,reply->selected)||!key_file(reply->selected))reply->status=errSecParam;
    else reply->status=SecKeychainGetStatus(key,&flags);
    CFRelease(key);if(reply->status)return;
    reply->unlocked=(flags&kSecUnlockStateStatus)!=0;reply->readable=(flags&kSecReadPermStatus)!=0;reply->writable=(flags&kSecWritePermStatus)!=0;
    CFArrayRef merged=NULL,user=NULL;int contains=0,ignored=0;
    reply->status=SecKeychainCopySearchList(&merged);
    if(!reply->status)reply->status=SecKeychainCopyDomainSearchList(kSecPreferencesDomainUser,&user);
    if(!reply->status&&(digest_list(merged,reply->selected,reply->merged_digest,&reply->merged_count,&contains)||
        digest_list(user,reply->selected,reply->user_digest,&reply->user_count,&ignored)||!contains))reply->status=errSecParam;
    if(merged)CFRelease(merged);if(user)CFRelease(user);
}
static int transfer(int fd,void *data,size_t length,int writing,int64_t until) {
    unsigned char *p=data;
    while(length){int64_t remaining=until-milliseconds();if(remaining<=0)return -1;
        struct pollfd event={fd,writing?POLLOUT:POLLIN,0};int n=poll(&event,1,(int)remaining);
        if(n<0&&errno==EINTR)continue;if(n<=0||(event.revents&(POLLERR|POLLNVAL)))return -1;
        ssize_t got=writing?write(fd,p,length):read(fd,p,length);
        if(got<0&&errno==EINTR)continue;if(got<=0)return -1;p+=got;length-=(size_t)got;
    }return 0;
}
static void worker_alarm(int sig){(void)sig;_exit(124);}
static int worker_context(void) {
    char self[PROC_PIDPATHINFO_MAXSIZE]={0},parent[PROC_PIDPATHINFO_MAXSIZE]={0};struct stat input,output;
    return getppid()>1&&proc_pidpath(getpid(),self,sizeof(self))>0&&proc_pidpath(getppid(),parent,sizeof(parent))>0&&
        !strcmp(self,parent)&&!fstat(0,&input)&&!fstat(1,&output)&&S_ISFIFO(input.st_mode)&&S_ISFIFO(output.st_mode)&&
        input.st_nlink==0&&output.st_nlink==0&&(fcntl(0,F_GETFL)&O_ACCMODE)==O_RDONLY&&(fcntl(1,F_GETFL)&O_ACCMODE)==O_WRONLY;
}
static int worker(void) {
    if(!worker_context())return 2;
    signal(SIGALRM,worker_alarm);alarm(10);struct request request;struct reply reply;memset(&reply,0,sizeof(reply));reply.schema=SCHEMA;
    int64_t until=milliseconds()+9000;
    if(transfer(0,&request,sizeof(request),0,until))return 2;
    unsigned char extra;if(read(0,&extra,1)!=0)return 2;
    const char *home=getenv("HOME");
    if(request.schema!=SCHEMA||(request.mode!=QUERY&&request.mode!=SELECT)||!memchr(request.home,0,PATH_MAX)||
        !memchr(request.selected,0,PATH_MAX)||!home||strcmp(home,request.home)||!safe_path(home))return 2;
    if(request.mode==SELECT){const char *name=strrchr(home,'/');if(!name)return 2;name++;
        if(strncmp(name,".envara-keychain-",17)||strlen(name)!=49)return 2;
        for(size_t i=17;i<49;i++)if(!strchr("0123456789abcdef",name[i]))return 2;
    }
    struct held held={.fd=-1};if(canonical_directory(home,request.mode==SELECT,&held))return 2;
    char profile[PATH_MAX+256];int n=snprintf(profile,sizeof(profile),"(version 1)(allow default)(deny network*)(deny file-write*)");
    if(request.mode==SELECT)n=snprintf(profile,sizeof(profile),"(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (literal \"%s/Library/Preferences/" SELECTOR "\"))",home);
    char *sandbox_error=NULL;
    if(n<0||n>=(int)sizeof(profile)||sandbox_init(profile,0,&sandbox_error)){if(sandbox_error)sandbox_free_error(sandbox_error);close(held.fd);return 2;}
    if(sandbox_error)sandbox_free_error(sandbox_error);
    reply.status=SecKeychainSetUserInteractionAllowed(false);
    if(!reply.status&&request.mode==SELECT){
        if(!key_file(request.selected))reply.status=errSecParam;
        else {SecKeychainRef key=NULL;reply.status=SecKeychainOpen(request.selected,&key);
            if(!reply.status&&key)reply.status=SecKeychainSetDefault(key);
            else if(!reply.status)reply.status=errSecInternalComponent;
            if(key)CFRelease(key);}
    }else if(!reply.status)metadata(&reply);
    if(!held_matches(&held))reply.status=errSecParam;
    close(held.fd);int result=transfer(1,&reply,sizeof(reply),1,until);memset(&request,0,sizeof(request));memset(&reply,0,sizeof(reply));return result?2:0;
}
static int run_worker(const char *self,enum mode mode,const char *home,const char *selected,struct reply *reply) {
    struct request request;memset(&request,0,sizeof(request));request.schema=SCHEMA;request.mode=mode;
    strcpy(request.home,home);if(selected)strcpy(request.selected,selected);
    int input[2]={-1,-1},output[2]={-1,-1};pid_t pid=-1;int status=0,result=-1;
    if(pipe(input)||pipe(output))goto done;
    for(int i=0;i<2;i++){fcntl(input[i],F_SETFD,FD_CLOEXEC);fcntl(output[i],F_SETFD,FD_CLOEXEC);}
    posix_spawn_file_actions_t actions;if(posix_spawn_file_actions_init(&actions))goto done;
    if(posix_spawn_file_actions_adddup2(&actions,input[0],0)||posix_spawn_file_actions_adddup2(&actions,output[1],1)||
        posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)){posix_spawn_file_actions_destroy(&actions);goto done;}
    char home_env[PATH_MAX+6];snprintf(home_env,sizeof(home_env),"HOME=%s",home);
    char *environment[]={home_env,"PATH=/usr/bin:/bin:/usr/sbin:/sbin",NULL};char *arguments[]={(char *)self,"--worker",NULL};
    int spawned=posix_spawn(&pid,self,&actions,NULL,arguments,environment);posix_spawn_file_actions_destroy(&actions);if(spawned){pid=-1;goto done;}
    close(input[0]);input[0]=-1;close(output[1]);output[1]=-1;
    int64_t until=milliseconds()+10000;if(until>deadline)until=deadline;
    if(transfer(input[1],&request,sizeof(request),1,until))goto done;
    close(input[1]);input[1]=-1;
    if(transfer(output[0],reply,sizeof(*reply),0,until))goto done;
    for(;;){pid_t waited=waitpid(pid,&status,WNOHANG);if(waited==pid){pid=-1;break;}
        if(waited<0&&errno!=EINTR)goto done;if(milliseconds()>=until)goto done;
        struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    unsigned char extra;ssize_t n=read(output[0],&extra,1);
    if(n!=0||!WIFEXITED(status)||WEXITSTATUS(status)||reply->schema!=SCHEMA||!memchr(reply->selected,0,PATH_MAX))goto done;
    result=0;
done:
    if(pid>0){kill(pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}}
    for(int i=0;i<2;i++){if(input[i]>=0)close(input[i]);if(output[i]>=0)close(output[i]);}
    memset(&request,0,sizeof(request));return result;
}
static int usable(const struct reply *reply,const char *stage) {
    if(reply->status==errSecNoDefaultKeychain&&!reply->present)return 0;
    if(reply->status||!reply->present)return failure("CLAUDE_KEYCHAIN_UNAVAILABLE",stage,reply->status,1);
    if(!reply->unlocked)return failure("CLAUDE_KEYCHAIN_LOCKED",stage,errSecInteractionNotAllowed,1);
    if(!reply->readable||!reply->writable)return failure("CLAUDE_KEYCHAIN_UNAVAILABLE",stage,errSecReadOnly,1);
    return 1;
}
static int same_selection(const struct reply *a,const struct reply *b) {
    return !a->status&&!b->status&&a->present==b->present&&!strcmp(a->selected,b->selected)&&
        a->merged_count==b->merged_count&&a->user_count==b->user_count&&
        !memcmp(a->merged_digest,b->merged_digest,sizeof(a->merged_digest))&&
        !memcmp(a->user_digest,b->user_digest,sizeof(a->user_digest));
}
static int stage_cleanup(struct tree *stage,struct held *target,const char *name) {
    if(!name[0])return 0;
    if(!tree_matches(stage)||!held_matches(target))return -1;
    if(stage->selector_present){struct stat s;if(stage->selector<0||fstatat(stage->dirs[2].fd,SELECTOR,&s,AT_SYMLINK_NOFOLLOW)||
        !identity_matches(&s,&stage->selector_identity)||s.st_nlink!=1||unlinkat(stage->dirs[2].fd,SELECTOR,0))return -1;stage->selector_present=0;}
    if(unlinkat(stage->dirs[1].fd,"Preferences",AT_REMOVEDIR)||unlinkat(stage->dirs[0].fd,"Library",AT_REMOVEDIR)||
        unlinkat(target->fd,name,AT_REMOVEDIR))return -1;
    return 0;
}
static int prepare(const char *self,const char *home,const char *source,int *changed) {
    struct held target={.fd=-1},origin={.fd=-1};struct tree destination,stage;tree_init(&destination);tree_init(&stage);
    struct reply scoped,before,selected,verified,after;memset(&scoped,0,sizeof(scoped));memset(&before,0,sizeof(before));
    int result=-1,lock=-1,selection_started=0;struct stat lock_identity;char stage_name[64]={0};
    if(!safe_path(home)||!safe_path(source)||nested(home,source)||canonical_directory(home,1,&target)||
        canonical_directory(source,0,&origin)){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","arguments",0,0);goto done;}
    const char lock_marker[]="envara-claude-keychain-lock-v1\n";
    int created=0;lock=openat(target.fd,LOCK_NAME,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock>=0)created=1;else if(errno==EEXIST)lock=openat(target.fd,LOCK_NAME,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    struct stat named;
    if(lock<0||fstat(lock,&lock_identity)||!S_ISREG(lock_identity.st_mode)||lock_identity.st_uid!=owner||
        lock_identity.st_nlink!=1||(lock_identity.st_mode&0777)!=0600||lock_identity.st_flags||
        fstatat(target.fd,LOCK_NAME,&named,AT_SYMLINK_NOFOLLOW)||!identity_matches(&named,&lock_identity)){
        failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","lock",0,0);goto done;}
    if(flock(lock,LOCK_EX|LOCK_NB)){failure("CLAUDE_KEYCHAIN_BUSY","lock",0,0);goto done;}
    if(created){if(write(lock,lock_marker,sizeof(lock_marker)-1)!=(ssize_t)sizeof(lock_marker)-1||fsync(lock)){
        failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","lock",0,0);goto done;}}
    else {char marker[sizeof(lock_marker)]={0};ssize_t length=pread(lock,marker,sizeof(marker),0);
        if(length!=(ssize_t)sizeof(lock_marker)-1||memcmp(marker,lock_marker,sizeof(lock_marker)-1)){
            failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","lock",0,0);goto done;}}
    if(prior_stage_present(&target)!=0){failure("CLAUDE_KEYCHAIN_CLEANUP_FAILED","cleanup",0,0);goto done;}
    if(existing_tree_safe(home)){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","scoped-query",0,0);goto done;}
    if(run_worker(self,QUERY,home,NULL,&scoped)){failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","scoped-query",0,0);goto done;}
    int available=usable(&scoped,"scoped-query");if(available<0)goto done;
    if(available){
        if(!held_matches(&target)||existing_tree_safe(home)||fstatat(target.fd,LOCK_NAME,&named,AT_SYMLINK_NOFOLLOW)||
            !identity_matches(&named,&lock_identity)||named.st_nlink!=1){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","verify",0,0);goto done;}
        result=0;goto done;
    }
    if(tree_open(home,1,&destination)||!held_matches(&target)){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","stage",0,0);goto done;}
    int state=selector_state(&destination);
    if(state!=0){failure(state>0?"CLAUDE_KEYCHAIN_EXISTING_SELECTION":"CLAUDE_KEYCHAIN_UNSAFE_PATH","scoped-query",0,0);goto done;}
    if(run_worker(self,QUERY,source,NULL,&before)){failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","host-query",0,0);goto done;}
    available=usable(&before,"host-query");if(available<0)goto done;
    if(!available){failure("CLAUDE_KEYCHAIN_MISSING","host-query",errSecNoDefaultKeychain,1);goto done;}
    unsigned char nonce[16];arc4random_buf(nonce,sizeof(nonce));
    snprintf(stage_name,sizeof(stage_name),".envara-keychain-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        nonce[0],nonce[1],nonce[2],nonce[3],nonce[4],nonce[5],nonce[6],nonce[7],nonce[8],nonce[9],nonce[10],nonce[11],nonce[12],nonce[13],nonce[14],nonce[15]);
    if(mkdirat(target.fd,stage_name,0700)){stage_name[0]=0;failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","stage",0,0);goto done;}
    if(child_directory(&target,stage_name,0,&stage.dirs[0])||child_directory(&stage.dirs[0],"Library",1,&stage.dirs[1])||
        child_directory(&stage.dirs[1],"Preferences",1,&stage.dirs[2])){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","stage",0,0);goto done;}
    stage.selector=openat(stage.dirs[2].fd,SELECTOR,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(stage.selector<0||fstat(stage.selector,&stage.selector_identity)){failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","stage",0,0);goto done;}
    stage.selector_present=1;
    selection_started=1;
    if(run_worker(self,SELECT,stage.dirs[0].path,before.selected,&selected)){failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","select",0,0);goto done;}
    if(selected.status){failure("CLAUDE_KEYCHAIN_UNAVAILABLE","select",selected.status,1);goto done;}
    if(!tree_matches(&stage)||fstatat(stage.dirs[2].fd,SELECTOR,&named,AT_SYMLINK_NOFOLLOW)||
        !identity_matches(&named,&stage.selector_identity)||named.st_nlink!=1||named.st_size<=0||named.st_size>65536||
        !held_matches(&target)||!held_matches(&origin)||selector_state(&destination)!=0||
        fstatat(target.fd,LOCK_NAME,&named,AT_SYMLINK_NOFOLLOW)||!identity_matches(&named,&lock_identity)){
        failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","publish",0,0);goto done;}
    /* Verify the generated selector in a separate process before publication. */
    if(run_worker(self,QUERY,stage.dirs[0].path,NULL,&verified)){
        failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","verify",0,0);goto done;}
    available=usable(&verified,"verify");if(available<0)goto done;
    if(!available||strcmp(verified.selected,before.selected)){failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","verify",0,0);goto done;}
    if(fsync(stage.selector)||!tree_matches(&stage)||selector_state(&destination)!=0||
        renameatx_np(stage.dirs[2].fd,SELECTOR,destination.dirs[2].fd,SELECTOR,RENAME_EXCL)){
        failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","publish",0,0);goto done;}
    stage.selector_present=0;*changed=1;
    if(fsync(destination.dirs[2].fd)||!tree_matches(&destination)||
        fstatat(destination.dirs[2].fd,SELECTOR,&named,AT_SYMLINK_NOFOLLOW)||!identity_matches(&named,&stage.selector_identity)||named.st_nlink!=1){
        failure("CLAUDE_KEYCHAIN_UNSAFE_PATH","publish",0,0);goto done;}
    if(run_worker(self,QUERY,home,NULL,&verified)){
        failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","verify",0,0);goto done;}
    available=usable(&verified,"verify");if(available<0)goto done;
    if(!available||strcmp(verified.selected,before.selected)){failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","verify",0,0);goto done;}
    result=0;
done:
    if(selection_started){
        if(run_worker(self,QUERY,source,NULL,&after)||after.status||!held_matches(&origin))host_check_code="CLAUDE_KEYCHAIN_HOST_CHECK_FAILED";
        else if(!same_selection(&before,&after))host_check_code="CLAUDE_KEYCHAIN_HOST_CHANGED";
        if(host_check_code){if(!result)failure(host_check_code,"host-verify",0,0);result=-1;}
    }
    /* A published selector is not accepted as a completed preparation merely
     * because the next invocation can read it. Retain the owned staging name
     * when final verification failed or source state could not be confirmed;
     * the next invocation refuses that marker before consulting the selector.
     * Never roll back a selector or restore the source user's preferences. */
    if(stage_name[0]&&result&&(*changed||host_check_code))cleanup_failed=1;
    else if(stage_name[0]&&stage_cleanup(&stage,&target,stage_name)){cleanup_failed=1;if(result==0)failure("CLAUDE_KEYCHAIN_CLEANUP_FAILED","cleanup",0,0);result=-1;}
    tree_release(&stage);tree_release(&destination);if(lock>=0)close(lock);if(target.fd>=0)close(target.fd);if(origin.fd>=0)close(origin.fd);
    return result;
}
int main(int argc,char **argv) {
    owner=getuid();if(!owner||owner!=geteuid()||getgid()!=getegid())return 2;
    signal(SIGPIPE,SIG_IGN);deadline=milliseconds()+25000;
    if(argc==2&&!strcmp(argv[1],"--worker"))return worker();
    int changed=0,result=-1;char self[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(argc!=6||strcmp(argv[1],"prepare")||strcmp(argv[2],"--home")||strcmp(argv[4],"--host-home"))
        failure("CLAUDE_KEYCHAIN_INVALID_ARGUMENT","arguments",0,0);
    else if(proc_pidpath(getpid(),self,sizeof(self))<=0)failure("CLAUDE_KEYCHAIN_PREPARATION_FAILED","arguments",0,0);
    else result=prepare(self,argv[3],argv[5],&changed);
    if(!result)printf("{\"schemaVersion\":1,\"status\":\"ready\",\"changed\":%s}\n",changed?"true":"false");
    else {printf("{\"schemaVersion\":1,\"status\":\"error\",\"code\":\"%s\",\"stage\":\"%s\",\"osStatus\":",error_code,error_stage);
        if(has_status)printf("%d",(int)error_status);else printf("null");
        if(host_check_code)printf(",\"hostCheckCode\":\"%s\"",host_check_code);
        if(cleanup_failed)printf(",\"cleanupCode\":\"CLAUDE_KEYCHAIN_CLEANUP_FAILED\"");printf("}\n");}
    return result?1:0;
}
