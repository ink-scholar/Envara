#define _DARWIN_C_SOURCE
#include "pf-filter-command.h"
#include "pf-filter-transaction.h"
#include "pf-hook.h"
#include "pf-run-ledger.h"
#include "native.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/acl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#define FILTER_SCHEMA "envara.macos-pf-filter-replacement/v1"
#define FILTER_RUNTIME "/Library/PrivilegedHelperTools/io.envara.pf-runtime"
#define FILTER_NATIVE "/Library/PrivilegedHelperTools/io.envara.pf-routing/envara-pf-native"
#define FILTER_CORE "/Library/PrivilegedHelperTools/io.envara.pf-routing/mihomo"
#define FILTER_LIMIT 65536U
#define FILTER_TOKENS 4096U
enum JSONKind { J_OBJECT, J_ARRAY, J_STRING, J_NUMBER, J_BOOL, J_NULL };
typedef struct { enum JSONKind kind; size_t begin,end,next,count; } JSONToken;
typedef struct { const char *text;size_t size,at,used;JSONToken tokens[FILTER_TOKENS]; } JSONDocument;
typedef struct {
    EnvaraPFFilterConfig config;EnvaraPFFilterMode mode;
    pid_t core[2],guardian[2];char birth[2][32],instance[2][128];
} FilterSpec;
typedef struct {
    JSONDocument input,record;char input_text[FILTER_LIMIT+1],record_text[FILTER_LIMIT+1];
    char run[37],generation[37];FilterSpec previous,next;
    int lease_token,registry_fd,runtime_fd;struct stat registry_identity,runtime_identity;
    EnvaraPFHookFilterLease *lease;double deadline;pid_t supervisor;
} FilterCommand;
static volatile sig_atomic_t filter_interrupted;
static void filter_signal(int sig) { filter_interrupted=sig; }
static double filter_now(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec+t.tv_nsec/1e9; }
static void json_space(JSONDocument *d) { while(d->at<d->size && (d->text[d->at]==' '||d->text[d->at]=='\t'||d->text[d->at]=='\r'||d->text[d->at]=='\n'))d->at++; }
static int json_value(JSONDocument *d,unsigned depth);
static int json_string(JSONDocument *d) {
    if(d->used>=FILTER_TOKENS || d->at>=d->size || d->text[d->at++]!='"')return -1;
    int index=(int)d->used++;JSONToken *t=&d->tokens[index];t->kind=J_STRING;t->begin=d->at;
    while(d->at<d->size && d->text[d->at]!='"') { unsigned char c=(unsigned char)d->text[d->at++];if(c<32||c>126||c=='\\')return -1; }
    if(d->at>=d->size)return -1;t->end=d->at++;t->next=d->used;return index;
}
static int json_equal(const JSONDocument *d,int token,const char *value) {
    return token>=0 && (size_t)token<d->used && d->tokens[token].kind==J_STRING &&
        d->tokens[token].end-d->tokens[token].begin==strlen(value) && !memcmp(d->text+d->tokens[token].begin,value,strlen(value));
}
static int json_same_string(const JSONDocument *d,int a,int b) {
    if(a<0||b<0)return 0;JSONToken x=d->tokens[a],y=d->tokens[b];
    return x.kind==J_STRING&&y.kind==J_STRING&&x.end-x.begin==y.end-y.begin&&!memcmp(d->text+x.begin,d->text+y.begin,x.end-x.begin);
}
static int json_value(JSONDocument *d,unsigned depth) {
    json_space(d);if(depth>20||d->at>=d->size||d->used>=FILTER_TOKENS)return -1;
    char c=d->text[d->at];if(c=='"')return json_string(d);
    int index=(int)d->used++;JSONToken *t=&d->tokens[index];t->begin=d->at;
    if(c=='{'||c=='[') {
        t->kind=c=='{'?J_OBJECT:J_ARRAY;d->at++;json_space(d);char stop=c=='{'?'}':']';
        if(d->at<d->size&&d->text[d->at]==stop)d->at++;
        else for(;;) {
            if(t->count>=512)return -1;
            if(c=='{') {
                json_space(d);int key=json_string(d);if(key<0)return -1;
                for(size_t k=(size_t)index+1;k<(size_t)key;) { if(json_same_string(d,(int)k,key))return -1;k=d->tokens[k+1].next; }
                json_space(d);if(d->at>=d->size||d->text[d->at++]!=':')return -1;
            }
            if(json_value(d,depth+1)<0)return -1;t->count++;json_space(d);
            if(d->at>=d->size)return -1;char separator=d->text[d->at++];if(separator==stop)break;if(separator!=',')return -1;
        }
    } else if(c>='0'&&c<='9') {
        t->kind=J_NUMBER;d->at++;if(c=='0'&&d->at<d->size&&d->text[d->at]>='0'&&d->text[d->at]<='9')return -1;
        while(d->at<d->size&&d->text[d->at]>='0'&&d->text[d->at]<='9')d->at++;
        if(d->at-t->begin>20)return -1;
    } else {
        const char *word=c=='t'?"true":c=='f'?"false":c=='n'?"null":NULL;
        if(!word||d->size-d->at<strlen(word)||memcmp(d->text+d->at,word,strlen(word)))return -1;
        d->at+=strlen(word);t->kind=c=='n'?J_NULL:J_BOOL;
    }
    t->end=d->at;t->next=d->used;return index;
}
static int json_parse(JSONDocument *d,const char *text,size_t size) {
    memset(d,0,sizeof(*d));if(!size||size>FILTER_LIMIT||memchr(text,0,size))return 0;d->text=text;d->size=size;
    int root=json_value(d,0);json_space(d);return root==0&&d->at==size&&d->tokens[0].kind==J_OBJECT;
}
static int json_field(const JSONDocument *d,int object,const char *key) {
    if(object<0||d->tokens[object].kind!=J_OBJECT)return -1;
    for(size_t at=(size_t)object+1;at<d->tokens[object].next;) { int value=(int)at+1;if(json_equal(d,(int)at,key))return value;at=d->tokens[value].next; }return -1;
}
static int json_keys(const JSONDocument *d,int object,const char *const *names,size_t count) {
    if(object<0||d->tokens[object].kind!=J_OBJECT||d->tokens[object].count!=count)return 0;
    for(size_t i=0;i<count;i++)if(json_field(d,object,names[i])<0)return 0;return 1;
}
static int json_copy(const JSONDocument *d,int token,char *out,size_t capacity) {
    if(token<0||d->tokens[token].kind!=J_STRING)return 0;JSONToken t=d->tokens[token];size_t n=t.end-t.begin;
    if(n>=capacity)return 0;memcpy(out,d->text+t.begin,n);out[n]=0;return 1;
}
static int json_unsigned(const JSONDocument *d,int token,uint32_t *out,int string) {
    if(token<0||d->tokens[token].kind!=(string?J_STRING:J_NUMBER))return 0;JSONToken t=d->tokens[token];size_t n=t.end-t.begin;
    if(!n||n>10||(n>1&&d->text[t.begin]=='0'))return 0;uint64_t value=0;
    for(size_t i=t.begin;i<t.end;i++) { char c=d->text[i];if(c<'0'||c>'9')return 0;value=value*10+(unsigned)(c-'0');if(value>UINT32_MAX)return 0; }
    *out=(uint32_t)value;return 1;
}
static int json_true(const JSONDocument *d,int token) { return token>=0&&d->tokens[token].kind==J_BOOL&&d->tokens[token].end-d->tokens[token].begin==4&&!memcmp(d->text+d->tokens[token].begin,"true",4); }
static int json_false(const JSONDocument *d,int token) { return token>=0&&d->tokens[token].kind==J_BOOL&&d->tokens[token].end-d->tokens[token].begin==5&&!memcmp(d->text+d->tokens[token].begin,"false",5); }
static int json_null(const JSONDocument *d,int token) { return token>=0&&d->tokens[token].kind==J_NULL; }
static int valid_utun(const char *name) {
    size_t n=strlen(name);if(n<5||n>10||strncmp(name,"utun",4)||(n>5&&name[4]=='0'))return 0;
    for(size_t i=4;i<n;i++)if(name[i]<'0'||name[i]>'9')return 0;return 1;
}
static int parse_spec(const JSONDocument *d,int token,const char *run,FilterSpec *spec,int previous) {
    static const char *const before[]={"mode","realms","writerPid","filterRevision"},*const after[]={"mode","realms"};
    memset(spec,0,sizeof(*spec));strcpy(spec->config.run_id,run);
    if(!json_keys(d,token,previous?before:after,previous?4:2))return 0;
    int mode=json_field(d,token,"mode"),array=json_field(d,token,"realms");
    if(json_equal(d,mode,"empty"))spec->mode=ENVARA_PF_FILTER_EMPTY;
    else if(json_equal(d,mode,"deny"))spec->mode=ENVARA_PF_FILTER_DENY;
    else if(json_equal(d,mode,"routed"))spec->mode=ENVARA_PF_FILTER_ROUTED;else return 0;
    if(array<0||d->tokens[array].kind!=J_ARRAY||d->tokens[array].count>2||
        (spec->mode==ENVARA_PF_FILTER_EMPTY?d->tokens[array].count!=0:d->tokens[array].count==0))return 0;
    spec->config.realm_count=(uint32_t)d->tokens[array].count;
    if(previous) {
        if(!json_unsigned(d,json_field(d,token,"writerPid"),&spec->config.expected_writer_pid,0))return 0;
        int revision=json_field(d,token,"filterRevision");
        spec->config.has_previous_revision=!json_null(d,revision);
        if(spec->config.has_previous_revision&&!json_unsigned(d,revision,&spec->config.expected_revision,1))return 0;
        if(!spec->config.has_previous_revision&&(spec->mode!=ENVARA_PF_FILTER_EMPTY||spec->config.expected_writer_pid))return 0;
        if(spec->config.has_previous_revision&&spec->config.expected_writer_pid<2)return 0;
    }
    size_t at=(size_t)array+1;
    for(uint32_t i=0;i<spec->config.realm_count;i++) {
        static const char *const names[]={"environmentId","gid","udpPolicy","tunnel"};int realm=(int)at;at=d->tokens[at].next;
        EnvaraPFFilterRealm *r=&spec->config.realms[i];
        if(!json_keys(d,realm,names,4)||!json_copy(d,json_field(d,realm,"environmentId"),r->realm_id,sizeof(r->realm_id))||!envara_pf_run_uuid_valid(r->realm_id)||
            !json_unsigned(d,json_field(d,realm,"gid"),&r->gid,0)||r->gid<7100||r->gid>7999)return 0;
        int udp=json_field(d,realm,"udpPolicy");if(json_equal(d,udp,"proxy"))r->udp_proxy=1;else if(!json_equal(d,udp,"block"))return 0;
        int tunnel=json_field(d,realm,"tunnel");
        if(!json_null(d,tunnel)) {
            static const char *const fields[]={"interfaceName","ipv4Address","pid","coreBirth","guardianPid","instanceId","fdRetained"};char ip[16];uint32_t core,guardian;
            if(!json_keys(d,tunnel,fields,7)||!json_copy(d,json_field(d,tunnel,"interfaceName"),r->utun,sizeof(r->utun))||!valid_utun(r->utun)||
                !json_copy(d,json_field(d,tunnel,"ipv4Address"),ip,sizeof(ip))||inet_pton(AF_INET,ip,r->route_ipv4)!=1||
                memcmp(r->route_ipv4,"\xc6\x12",2)||(r->route_ipv4[2]!=1&&r->route_ipv4[2]!=2)||r->route_ipv4[3]!=1||
                !json_unsigned(d,json_field(d,tunnel,"pid"),&core,0)||core<2||core>INT32_MAX||
                !json_unsigned(d,json_field(d,tunnel,"guardianPid"),&guardian,0)||guardian<2||guardian>INT32_MAX||
                !json_copy(d,json_field(d,tunnel,"coreBirth"),spec->birth[i],sizeof(spec->birth[i]))||
                !json_copy(d,json_field(d,tunnel,"instanceId"),spec->instance[i],sizeof(spec->instance[i]))||!json_true(d,json_field(d,tunnel,"fdRetained")))return 0;
            spec->core[i]=(pid_t)core;spec->guardian[i]=(pid_t)guardian;
        }
        r->routed=spec->mode==ENVARA_PF_FILTER_ROUTED;if(r->routed&&!r->utun[0])return 0;
        if(i&& (strcmp(spec->config.realms[i-1].realm_id,r->realm_id)>=0||spec->config.realms[i-1].gid==r->gid||
            (r->utun[0]&&!strcmp(spec->config.realms[i-1].utun,r->utun))))return 0;
    }
    return 1;
}
static int json_equivalent(const JSONDocument *a,int x,const JSONDocument *b,int y,unsigned depth) {
    if(x<0||y<0||depth>20)return 0;JSONToken p=a->tokens[x],q=b->tokens[y];
    if(p.kind!=q.kind||p.count!=q.count)return 0;
    if(p.kind==J_OBJECT) {
        for(size_t at=(size_t)x+1;at<p.next;) { char key[128];if(!json_copy(a,(int)at,key,sizeof(key)))return 0;
            int match=json_field(b,y,key);if(!json_equivalent(a,(int)at+1,b,match,depth+1))return 0;at=a->tokens[at+1].next; }return 1;
    }
    if(p.kind==J_ARRAY) { size_t i=(size_t)x+1,j=(size_t)y+1;while(i<p.next&&j<q.next) {
        if(!json_equivalent(a,(int)i,b,(int)j,depth+1))return 0;i=a->tokens[i].next;j=b->tokens[j].next; }return i==p.next&&j==q.next;
    }
    return p.end-p.begin==q.end-q.begin&&!memcmp(a->text+p.begin,b->text+q.begin,p.end-p.begin);
}
static int parse_request(FilterCommand *c,size_t length) {
    static const char *const names[]={"schema","runId","generation","lease","previous","next"};
    JSONDocument *d=&c->input;
    if(!json_parse(d,c->input_text,length)||!json_keys(d,0,names,6)||!json_equal(d,json_field(d,0,"schema"),FILTER_SCHEMA)||
        !json_copy(d,json_field(d,0,"runId"),c->run,sizeof(c->run))||!envara_pf_run_uuid_valid(c->run)||
        !json_copy(d,json_field(d,0,"generation"),c->generation,sizeof(c->generation))||!envara_pf_run_uuid_valid(c->generation))return 0;
    c->lease_token=json_field(d,0,"lease");
    if(c->lease_token<0||d->tokens[c->lease_token].kind!=J_OBJECT||
        !parse_spec(d,json_field(d,0,"previous"),c->run,&c->previous,1)||!parse_spec(d,json_field(d,0,"next"),c->run,&c->next,0))return 0;
    if(c->previous.config.expected_writer_pid>INT32_MAX)return 0;
    // Empty is only the initial/cleared shape; every nonempty replacement is
    // generated from the same sealed group identities. No group can vanish
    // while the desired policy still contains rules.
    if(c->previous.mode!=ENVARA_PF_FILTER_EMPTY&&c->next.mode!=ENVARA_PF_FILTER_EMPTY) {
        if(c->previous.config.realm_count!=c->next.config.realm_count)return 0;
        for(uint32_t i=0;i<c->next.config.realm_count;i++) if(strcmp(c->previous.config.realms[i].realm_id,c->next.config.realms[i].realm_id)||
            c->previous.config.realms[i].gid!=c->next.config.realms[i].gid||c->previous.config.realms[i].udp_proxy!=c->next.config.realms[i].udp_proxy)return 0;
    }
    return 1;
}
static int no_write_acl(int fd) {
    errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl)return errno==ENOENT;acl_entry_t e;int entry=ACL_FIRST_ENTRY,result,okay=1;
    for(;;) { errno=0;result=acl_get_entry(acl,entry,&e);if(result!=0)break;entry=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t perms;
        if(acl_get_tag_type(e,&tag)||acl_get_permset(e,&perms)) { okay=0;break; }
        if(tag==ACL_EXTENDED_ALLOW) {
            const acl_perm_t write[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_DELETE,ACL_DELETE_CHILD,ACL_CHANGE_OWNER};
            for(size_t i=0;i<sizeof(write)/sizeof(write[0]);i++) { int allowed=acl_get_perm_np(perms,write[i]);if(allowed<0||allowed==1)okay=0; }
        }
    }
    if(result<0&&errno!=0&&errno!=EINVAL)okay=0;acl_free(acl);return okay;
}
static int safe_directory(const char *path,int private_directory) {
    char selected[1024];if(!path||path[0]!='/'||strlen(path)>=sizeof(selected))return -1;strcpy(selected,path);
    int current=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(current<0)return -1;
    char *save=NULL,*component=strtok_r(selected+1,"/",&save);struct stat st;
    if(fstat(current,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0022)||!no_write_acl(current))goto refused;
    while(component) {
        if(!strcmp(component,".")||!strcmp(component,".."))goto refused;
        int next=openat(current,component,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);char *following=strtok_r(NULL,"/",&save);
        if(next<0||fstat(next,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&(following||!private_directory?0022:0077))||!no_write_acl(next)) { if(next>=0)close(next);goto refused; }
        close(current);current=next;component=following;
    }
    return current;
refused:close(current);return -1;
}
static int same_file(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&
        a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec&&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static int registry_stable(FilterCommand *c) {
    struct stat held,path;char bytes[FILTER_LIMIT+1];ssize_t n;
    if(c->runtime_fd<0||fstat(c->runtime_fd,&held)||lstat(FILTER_RUNTIME,&path)||
        !same_file(&held,&c->runtime_identity)||!same_file(&held,&path)||!no_write_acl(c->runtime_fd))return 0;
    if(c->registry_fd<0||fstat(c->registry_fd,&held)||fstatat(c->runtime_fd,"registry.json",&path,AT_SYMLINK_NOFOLLOW)||
        !same_file(&held,&c->registry_identity)||!same_file(&held,&path)||!no_write_acl(c->registry_fd))return 0;
    n=pread(c->registry_fd,bytes,FILTER_LIMIT+1,0);
    return n==(ssize_t)c->record.size&&!memcmp(bytes,c->record_text,c->record.size)&&!fstat(c->registry_fd,&held)&&same_file(&held,&c->registry_identity);
}
static int pending_record_matches(FilterCommand *c) {
    JSONDocument *r=&c->record;uint32_t supervisor;char anchor[64];envara_pf_run_anchor(c->run,anchor);
    if(!json_equal(r,json_field(r,0,"schema"),"envara.macos-pf-owned-registry/v1")||!json_equal(r,json_field(r,0,"runId"),c->run)||
        !json_equal(r,json_field(r,0,"anchor"),anchor)||!json_unsigned(r,json_field(r,0,"supervisorPid"),&supervisor,0)||supervisor!=(uint32_t)getppid())return 0;
    int hook=json_field(r,0,"rootHook"),record_lease=json_field(r,hook,"lease"),intent=json_field(r,0,"filterReplacement");
    if(!json_true(r,json_field(r,hook,"verified"))||!json_true(r,json_field(r,hook,"mutationAttempted"))||
        !json_false(r,json_field(r,hook,"removed"))||!json_false(r,json_field(r,hook,"receiptRetired"))||record_lease<0)return 0;
    JSONToken lease=r->tokens[record_lease];
    static const char *const intent_keys[]={"schema","generation","state","previous","next"};
    return envara_pf_hook_filter_matches(c->lease,r->text+lease.begin,(unsigned long)(lease.end-lease.begin))&&
        json_keys(r,intent,intent_keys,5)&&json_equal(r,json_field(r,intent,"schema"),FILTER_SCHEMA)&&
        json_equal(r,json_field(r,intent,"generation"),c->generation)&&json_equal(r,json_field(r,intent,"state"),"pending")&&
        json_equivalent(&c->input,json_field(&c->input,0,"previous"),r,json_field(r,intent,"previous"),0)&&
        json_equivalent(&c->input,json_field(&c->input,0,"next"),r,json_field(r,intent,"next"),0);
}
static int open_registry(FilterCommand *c) {
    int directory=safe_directory(FILTER_RUNTIME,1);if(directory<0)return 0;
    c->runtime_fd=directory;if(fstat(directory,&c->runtime_identity))return 0;
    int lock=openat(directory,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    char lock_text[1024];ssize_t lock_size;JSONDocument *lock_doc=calloc(1,sizeof(*lock_doc));uint32_t lock_pid=0;
    int okay=lock>=0&&!fstat(lock,&st)&&S_ISREG(st.st_mode)&&!st.st_uid&&(st.st_mode&07777)==0600&&st.st_nlink==1&&no_write_acl(lock)&&
        (lock_size=pread(lock,lock_text,sizeof(lock_text),0))>0&&lock_size<(ssize_t)sizeof(lock_text)&&lock_doc&&json_parse(lock_doc,lock_text,(size_t)lock_size);
    char anchor[64];envara_pf_run_anchor(c->run,anchor);
    static const char *const lock_keys[]={"runId","pid","anchor"};
    okay=okay&&json_keys(lock_doc,0,lock_keys,3)&&json_equal(lock_doc,json_field(lock_doc,0,"runId"),c->run)&&
        json_equal(lock_doc,json_field(lock_doc,0,"anchor"),anchor)&&json_unsigned(lock_doc,json_field(lock_doc,0,"pid"),&lock_pid,0)&&lock_pid==(uint32_t)getppid();
    free(lock_doc);if(lock>=0)close(lock);
    if(!okay)return 0;
    c->registry_fd=openat(directory,"registry.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(c->registry_fd<0||fstat(c->registry_fd,&c->registry_identity)||!S_ISREG(c->registry_identity.st_mode)||c->registry_identity.st_uid||
        (c->registry_identity.st_mode&07777)!=0600||c->registry_identity.st_nlink!=1||!no_write_acl(c->registry_fd)||
        c->registry_identity.st_size<1||c->registry_identity.st_size>FILTER_LIMIT)return 0;
    ssize_t length=pread(c->registry_fd,c->record_text,FILTER_LIMIT+1,0);
    if(length!=c->registry_identity.st_size||!json_parse(&c->record,c->record_text,(size_t)length))return 0;
    return pending_record_matches(c)&&registry_stable(c);
}
static int group_matches(uint32_t gid) {
    char name[32];snprintf(name,sizeof(name),"_envara_pf_%u",gid);
    errno=0;struct group *numeric=getgrgid((gid_t)gid);if(!numeric||numeric->gr_gid!=(gid_t)gid||strcmp(numeric->gr_name,name))return 0;
    errno=0;struct group *named=getgrnam(name);return named&&named->gr_gid==(gid_t)gid&&!strcmp(named->gr_name,name);
}
static int process_root_path(pid_t pid,pid_t parent,const char *birth,const char *path) {
    struct envara_identity a,b;char actual[PROC_PIDPATHINFO_MAXSIZE],stamp[32];
    if(envara_identity_read(pid,&a)||a.uid||a.ruid||a.saved_uid||a.gid||a.rgid||a.saved_gid||a.parent_pid!=parent||
        proc_pidpath(pid,actual,sizeof(actual))<=0||strcmp(actual,path))return 0;
    snprintf(stamp,sizeof(stamp),"%llu:%06llu",(unsigned long long)a.birth_seconds,(unsigned long long)a.birth_microseconds);
    return (!birth||!strcmp(stamp,birth))&&!envara_identity_read(pid,&b)&&b.pid==a.pid&&b.parent_pid==a.parent_pid&&
        b.birth_seconds==a.birth_seconds&&b.birth_microseconds==a.birth_microseconds&&!b.uid&&!b.ruid&&!b.saved_uid&&!b.gid&&!b.rgid&&!b.saved_gid;
}
static int tunnel_matches(const FilterSpec *spec,uint32_t index) {
    const EnvaraPFFilterRealm *realm=&spec->config.realms[index];
    if(!realm->utun[0]||!spec->core[index]||!spec->guardian[index]||!if_nametoindex(realm->utun)||
        !process_root_path(spec->guardian[index],getppid(),NULL,FILTER_NATIVE)||
        !process_root_path(spec->core[index],spec->guardian[index],spec->birth[index],FILTER_CORE))return 0;
    struct ifaddrs *addresses=NULL;if(getifaddrs(&addresses))return 0;unsigned matched=0;
    for(struct ifaddrs *i=addresses;i;i=i->ifa_next) if(!strcmp(i->ifa_name,realm->utun)&&i->ifa_addr&&i->ifa_addr->sa_family==AF_INET&&
        !memcmp(&((struct sockaddr_in *)i->ifa_addr)->sin_addr,realm->route_ipv4,4)&&i->ifa_netmask&&
        ((struct sockaddr_in *)i->ifa_netmask)->sin_addr.s_addr==htonl(UINT32_MAX))matched++;
    freeifaddrs(addresses);return matched==1;
}
static int record_realm(const JSONDocument *d,const char *environment) {
    int realms=json_field(d,0,"realms");if(realms<0||d->tokens[realms].kind!=J_ARRAY||d->tokens[realms].count>2)return -1;
    int found=-1;for(size_t at=(size_t)realms+1;at<d->tokens[realms].next;at=d->tokens[at].next)
        if(json_equal(d,json_field(d,(int)at,"environmentId"),environment)) { if(found>=0)return -1;found=(int)at; }return found;
}
static int recorded_scope_matches(FilterCommand *c,const FilterSpec *spec,int require_live_tunnel) {
    const JSONDocument *r=&c->record;
    for(uint32_t i=0;i<spec->config.realm_count;i++) {
        const EnvaraPFFilterRealm *realm=&spec->config.realms[i];int entry=record_realm(r,realm->realm_id);uint32_t gid;
        if(entry<0||!json_unsigned(r,json_field(r,entry,"gid"),&gid,0)||gid!=realm->gid||!group_matches(gid))return 0;
        char group[64];snprintf(group,sizeof(group),"/Groups/_envara_pf_%u",gid);if(!json_equal(r,json_field(r,entry,"groupPath"),group))return 0;
        if(spec->mode==ENVARA_PF_FILTER_ROUTED) {
            int tunnel=json_field(r,entry,"tunnel");char ip[16];inet_ntop(AF_INET,realm->route_ipv4,ip,sizeof(ip));uint32_t core,guardian;
            if(tunnel<0||!json_equal(r,json_field(r,tunnel,"interfaceName"),realm->utun)||!json_equal(r,json_field(r,tunnel,"ipv4Address"),ip)||
                !json_equal(r,json_field(r,tunnel,"coreBirth"),spec->birth[i])||!json_equal(r,json_field(r,tunnel,"instanceId"),spec->instance[i])||
                !json_unsigned(r,json_field(r,tunnel,"pid"),&core,0)||core!=(uint32_t)spec->core[i]||
                !json_unsigned(r,json_field(r,tunnel,"guardianPid"),&guardian,0)||guardian!=(uint32_t)spec->guardian[i]||
                !json_true(r,json_field(r,tunnel,"fdRetained"))||(require_live_tunnel&&!tunnel_matches(spec,i)))return 0;
        }
    }
    return 1;
}
static int recorded_fixtures_absent(const JSONDocument *d) {
    int realms=json_field(d,0,"realms");if(realms<0||d->tokens[realms].kind!=J_ARRAY||d->tokens[realms].count>2)return 0;
    for(size_t at=(size_t)realms+1;at<d->tokens[realms].next;at=d->tokens[at].next) {
        int fixtures=json_field(d,(int)at,"fixtures");if(fixtures<0||d->tokens[fixtures].kind!=J_ARRAY||d->tokens[fixtures].count>2)return 0;
        for(size_t f=(size_t)fixtures+1;f<d->tokens[fixtures].next;f=d->tokens[f].next) {
            uint32_t pid;if(!json_unsigned(d,json_field(d,(int)f,"pid"),&pid,0)||pid<2||pid>INT32_MAX)return 0;
            struct envara_identity identity;errno=0;int first=envara_identity_read((pid_t)pid,&identity),a=errno;
            errno=0;int second=envara_identity_read((pid_t)pid,&identity),b=errno;
            if(!first||!second||a!=ESRCH||b!=ESRCH)return 0;
        }
    }
    return 1;
}
static int filter_guard(void *opaque,int fd,EnvaraPFFilterStage stage,uint32_t index) {
    (void)stage;(void)index;FilterCommand *c=opaque;double now=filter_now();
    struct pollfd output={STDOUT_FILENO,0,0};int peer=poll(&output,1,0);
    if(filter_interrupted||c->supervisor<2||getppid()!=c->supervisor||peer<0||
        (peer>0&&(output.revents&(POLLHUP|POLLERR|POLLNVAL)))||now<0||now>=c->deadline||!registry_stable(c)||!envara_pf_hook_filter_guard(c->lease,fd)||
        !recorded_scope_matches(c,&c->next,c->next.mode==ENVARA_PF_FILTER_ROUTED))return 0;
    return c->next.mode!=ENVARA_PF_FILTER_EMPTY||recorded_fixtures_absent(&c->record);
}
static int read_request(char *text,size_t *size) {
    size_t n=0;double end=filter_now()+3;
    while(filter_now()<end&&n<FILTER_LIMIT) {
        struct pollfd input={STDIN_FILENO,POLLIN|POLLHUP,0};int ready=poll(&input,1,100);
        if(filter_interrupted)return 0;if(ready<0&&errno==EINTR)continue;if(ready<0)return 0;if(!ready)continue;
        ssize_t got=read(STDIN_FILENO,text+n,FILTER_LIMIT-n);if(got<0&&errno==EINTR)continue;if(got<0)return 0;
        if(!got) { *size=n;return n>0; }if(memchr(text+n,0,(size_t)got))return 0;n+=(size_t)got;
    }
    return 0;
}
static int emit_filter(const FilterCommand *c,int okay,const char *reason,const EnvaraPFFilterResult *r) {
    const char *mode=!c?"unknown":c->next.mode==ENVARA_PF_FILTER_EMPTY?"empty":c->next.mode==ENVARA_PF_FILTER_DENY?"deny":"routed";
    const char *run=c&&envara_pf_run_uuid_valid(c->run)?c->run:"",*generation=c&&envara_pf_run_uuid_valid(c->generation)?c->generation:"";
    int attempted=r&&(r->begun||r->pool_attempted||r->commit_attempted),uncertain=r&&r->uncertain;
    printf("{\"schema\":\"%s\",\"operation\":\"replace-owned-filter\",\"ok\":%s,\"runId\":\"%s\",\"generation\":\"%s\",\"mode\":\"%s\",\"reason\":\"%s\","
        "\"readOnly\":%s,\"fixtureOnly\":true,\"productionReady\":false,\"protected\":false,\"nativeAcceptance\":false,"
        "\"replacementAttempted\":%s,\"replacementUncertain\":%s,\"rulesVerified\":%s,\"poolsVerified\":%s,\"ruleCount\":%u,\"writerPid\":%u,\"filterRevision\":",
        FILTER_SCHEMA,okay?"true":"false",run,generation,mode,reason,attempted?"false":"true",attempted?"true":"false",uncertain?"true":"false",
        okay?"true":"false",okay?"true":"false",r?r->actual_count:0,r?r->writer_pid:0);
    if(r&&r->ticket_known)printf("\"%u\"",r->ticket);else fputs("null",stdout);
    printf(",\"globalTemporaryPoolBufferReset\":%s,\"foreignPoolConcurrencyExcluded\":false,\"kernelIoctlHardDeadline\":false,\"changesOtherRuleClasses\":false,\"PFEnable\":false,\"statesCleared\":false}\n",r&&r->pool_attempted?"true":"false");
    return fflush(stdout)==0&&!ferror(stdout);
}
int envara_pf_filter_command(int argc,char **argv) {
    if(argc!=2||strcmp(argv[1],"replace-owned-filter")) { emit_filter(NULL,0,"INVALID_FIXED_OPERATION",NULL);return 1; }
    if(getuid()||geteuid()) { emit_filter(NULL,0,"AUTHENTICATED_ROOT_CONTROLLER_REQUIRED",NULL);return 1; }
    struct sigaction action={0};action.sa_handler=filter_signal;sigemptyset(&action.sa_mask);
    const int signals[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};for(size_t i=0;i<4;i++)if(sigaction(signals[i],&action,NULL)) { emit_filter(NULL,0,"SIGNAL_BOUNDARY_UNAVAILABLE",NULL);return 1; }
    FilterCommand *c=calloc(1,sizeof(*c));if(!c) { emit_filter(NULL,0,"BOUNDED_PRIVATE_INPUT_REQUIRED",NULL);return 1; }
    c->registry_fd=-1;c->runtime_fd=-1;c->supervisor=getppid();c->deadline=filter_now()+30;size_t input_length=0;int fd=-1,okay=0;const char *reason="INVALID_PRIVATE_FILTER_INPUT";EnvaraPFFilterResult result={0},prior={0};
    if(!read_request(c->input_text,&input_length)||!parse_request(c,input_length))goto finished;
    JSONToken lease=c->input.tokens[c->lease_token];
    reason="EXACT_ISSUED_LEASE_REQUIRED";
    if(!envara_pf_hook_filter_open(c->run,c->input.text+lease.begin,(unsigned long)(lease.end-lease.begin),&c->lease))goto finished;
    reason="SEALED_PENDING_FILTER_INTENT_REQUIRED";
    if(!open_registry(c)||!recorded_scope_matches(c,&c->previous,0)||!recorded_scope_matches(c,&c->next,c->next.mode==ENVARA_PF_FILTER_ROUTED))goto finished;
    fd=open("/dev/pf",O_RDWR|O_NOFOLLOW|O_CLOEXEC);reason="OWNED_FILTER_DEVICE_REFUSED";if(fd<0||!filter_guard(c,fd,ENVARA_PF_FILTER_GUARD_INITIAL,UINT32_MAX))goto finished;
    EnvaraPFFilterContext before={0},next={0};reason="PRIOR_FILTER_READBACK_REFUSED";
    if(!EnvaraPFFilterInit(&before,fd,c,NULL,filter_guard,&c->previous.config)||
        !EnvaraPFFilterVerify(&before,c->previous.mode,&prior)||!prior.verified)goto finished;
    reason="GENERATED_FILTER_REPLACEMENT_REFUSED";
    if(!EnvaraPFFilterInit(&next,fd,c,NULL,filter_guard,&c->next.config))goto finished;
    okay=EnvaraPFFilterApply(&next,c->next.mode,&result)==1&&result.verified==1&&!result.uncertain;
    reason=okay?"GENERATED_SINGLE_FILTER_VERIFIED":EnvaraPFFilterReasonName(result.reason);
finished:
    if(fd>=0)close(fd);if(c->registry_fd>=0)close(c->registry_fd);if(c->runtime_fd>=0)close(c->runtime_fd);envara_pf_hook_filter_close(c->lease);
    int emitted=emit_filter(c,okay,reason,&result);memset(c,0,sizeof(*c));free(c);return okay&&emitted?0:1;
}
