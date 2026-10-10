#define _DARWIN_C_SOURCE
#include "app-native-factory.h"
#include "app-scope-proof.h"
#include "pf-hook.h"
#include "app-transport.h"
#include "notion-launch.h"
#include "journal-retirement.h"
/* Linked through this sole factory translation unit; no recovery API accepts
 * caller-selected paths or grants PF authority. */
#include "journal-retirement.c"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/proc.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INSTALL "/Library/PrivilegedHelperTools/io.envara.pf-routing"
#define RUNTIME "/Library/PrivilegedHelperTools/io.envara.pf-runtime"
#define LEASE_LIMIT 16384U
#define RECORD_LIMIT 65536U
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2
/* Only this compiled factory constructs authority. No root daemon invokes
 * user-writable code, accepts a descriptor/proof object, adopts a PID, changes
 * host DNS/routes, or resumes an application here. FRONT admission is separate
 * from protection: scoped Seatbelt/helper/native acceptance remains required. */
struct envara_app_native_factory {
    pid_t owner;
    int lease_fd, lock_fd, run_fd, runtime_fd, pf_fd, journal_fd, poisoned;
    unsigned sequence;
    int staged, journal_removed, guard_live;
    int journal_created;
    struct envara_journal_retirement retirement;
    int cleanup_only, cleanup_reconciled, cleanup_reconciling, pending_intent, pending_write_attempted;
    EnvaraPFProductionMode pending_mode;
    EnvaraPFProductionResult pending_result;
    struct stat journal_identity, journal_files[32];
    char journal_names[32][32];
    int journal_file_fds[32];
    char *journal_file_bytes[32];
    size_t journal_file_sizes[32];
    int journal_entries_trusted;
    size_t journal_count;
    struct stat lease_identity, lock_identity, run_identity, runtime_identity, utun_identity, listener_identity, lease_pipe_identity, recovery_pipe_identity;
    struct envara_app_native_preflight plan;
    struct envara_app_native_owned_context owned;
    struct envara_gui_request request;
    struct envara_app_registration app;
    struct envara_child stage_child;
    char *lease_bytes, *hook_bytes;
    size_t lease_size, hook_size;
    uint64_t issued, expires, boot;
    EnvaraPFHookFilterLease *hook;
    EnvaraPFProductionMode mode;
    EnvaraPFProductionConfig config;
    EnvaraPFProductionResult receipt;
    struct envara_app_supervisor_provider provider;
};
static int refuse(int error) { errno=error; return -1; }
static const char *native_failure_reason="NATIVE_OPERATION_REFUSED";
static int native_failure_error;
const char *envara_app_native_failure_reason(void) { return native_failure_reason; }
void envara_app_native_failure_begin(void) {native_failure_reason="NATIVE_OPERATION_REFUSED";native_failure_error=0;}
int envara_app_native_failure_error(int fallback) {return native_failure_error?native_failure_error:fallback;}
static int operation_refuse(const char *reason,int error) {
    error=error>0&&error<=1024?error:EIO;
    if(!native_failure_error){native_failure_reason=reason;native_failure_error=error;}return refuse(error);
}
static int uuid(const char *s) {
    if (!s || strnlen(s,37)!=36 || s[14]!='4' || !strchr("89ab",s[19])) return 0;
    for(int i=0;i<36;i++) if(i==8||i==13||i==18||i==23) {if(s[i]!='-')return 0;}
        else if(!strchr("0123456789abcdef",s[i]))return 0;
    return 1;
}
static int digest_valid(const char *s) {
    if(!s||strnlen(s,65)!=64)return 0;
    for(int i=0;i<64;i++)if(!strchr("0123456789abcdef",s[i]))return 0;return 1;
}
static int clock_values(uint64_t *now,uint64_t *boot) {
    struct timespec t;struct timeval b;size_t n=sizeof(b);
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||sysctlbyname("kern.boottime",&b,&n,NULL,0)||n!=sizeof(b)||b.tv_sec<=0)return refuse(EIO);
    *now=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;*boot=(uint64_t)b.tv_sec;return 0;
}
int envara_app_native_context_clock(int argc,char **argv) {
    if(argc!=2||!argv||strcmp(argv[1],"app-context-clock"))return 1;
    uint64_t now,boot;if(clock_values(&now,&boot)){puts("{\"schema\":\"" ENVARA_APP_BOUND_CLOCK_SCHEMA "\",\"ok\":false,\"reason\":\"CLOCK_UNAVAILABLE\"}");return 1;}
    printf("{\"schema\":\"" ENVARA_APP_BOUND_CLOCK_SCHEMA "\",\"ok\":true,\"bootTimeSeconds\":%llu,\"nowMonotonicMilliseconds\":%llu}\n",(unsigned long long)boot,(unsigned long long)now);return 0;
}
static int same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec&&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static int secure_object(int fd,int directory,mode_t exact) {
    struct stat s;char path[PATH_MAX];
    if(fstat(fd,&s)||(directory?!S_ISDIR(s.st_mode):!S_ISREG(s.st_mode))||s.st_uid||s.st_gid||(s.st_mode&07777)!=exact||(!directory&&s.st_nlink!=1)||fcntl(fd,F_GETPATH,path)||envara_gui_acl_free(path))return refuse(EACCES);return 0;
}
static int safe_directory(const char *path,mode_t final_mode) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX)return refuse(EINVAL);
    char components[PATH_MAX];strcpy(components,path);
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    char *save=NULL;for(char *c=strtok_r(components,"/",&save);c;c=strtok_r(NULL,"/",&save)) {
        struct stat s;char held[PATH_MAX];
        if(!strcmp(c,".")||!strcmp(c,"..")||fstat(fd,&s)||s.st_uid||(s.st_mode&0022)||fcntl(fd,F_GETPATH,held)||envara_gui_acl_free(held)){close(fd);return refuse(EACCES);}
        int next=openat(fd,c,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(next<0){int e=errno;close(fd);return refuse(e);}close(fd);fd=next;
    }
    if(secure_object(fd,1,final_mode)){close(fd);return -1;}return fd;
}
static int read_private(int parent,const char *name,size_t limit,mode_t mode,int *held,struct stat *identity,char **bytes,size_t *length) {
    int fd=openat(parent,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    struct stat before,after,named;char *buffer=NULL;int e=0;
    if(secure_object(fd,0,mode)||fstat(fd,&before)||before.st_size<1||(uint64_t)before.st_size>limit)e=EACCES;
    if(!e&&!(buffer=calloc((size_t)before.st_size+1,1)))e=ENOMEM;
    size_t offset=0;while(!e&&offset<(size_t)before.st_size){ssize_t n=read(fd,buffer+offset,(size_t)before.st_size-offset);if(n<0&&errno==EINTR)continue;if(n<=0){e=EIO;break;}offset+=(size_t)n;}
    if(!e&&(fstat(fd,&after)||fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)||!same_stat(&before,&after)||!same_stat(&after,&named)||memchr(buffer,0,offset)))e=ESTALE;
    if(e){free(buffer);close(fd);return refuse(e);}*held=fd;*identity=after;*bytes=buffer;*length=offset;return 0;
}
static void sha(const void *bytes,size_t length,char out[65]) {
    unsigned char h[CC_SHA256_DIGEST_LENGTH];CC_SHA256(bytes,(CC_LONG)length,h);for(size_t i=0;i<sizeof(h);i++)snprintf(out+i*2,3,"%02x",h[i]);out[64]=0;
}
/* Detect duplicate keys BEFORE Foundation collapses them. Object keys must be
 * literal ASCII; values may use JSON escapes and UTF8 (e.g. a Chinese cwd).
 * Foundation performs the final UTF8/escape/typed syntax validation. */
typedef struct {const unsigned char *s;size_t n,p,nodes,object_limit;} Scan;
static void ws(Scan *d){while(d->p<d->n&&strchr(" \n\r\t",d->s[d->p]))d->p++;}
static int scan_value(Scan *d,unsigned depth);
static int scan_string(Scan *d,int key,size_t *begin,size_t *end) {
    if(d->p>=d->n||d->s[d->p++]!='"')return 0;*begin=d->p;
    while(d->p<d->n){unsigned char c=d->s[d->p++];if(c=='"'){*end=d->p-1;return 1;}if(c<32||(key&&(c>126||c=='\\')))return 0;
        if(c=='\\'){if(d->p>=d->n)return 0;d->p++;}}
    return 0;
}
static int scan_value(Scan *d,unsigned depth) {
    ws(d);if(depth>20||d->p>=d->n||++d->nodes>4096)return 0;unsigned char c=d->s[d->p];size_t b,e;
    if(c=='"')return scan_string(d,0,&b,&e);
    if(c=='{'||c=='['){d->p++;ws(d);unsigned char stop=c=='{'?'}':']';size_t starts[128],ends[128],count=0,limit=c=='{'?d->object_limit:64;
        if(d->p<d->n&&d->s[d->p]==stop){d->p++;return 1;}
        for(;;){if(count>=limit)return 0;if(c=='{'){ws(d);if(!scan_string(d,1,&b,&e))return 0;
            for(size_t i=0;i<count;i++)if(e-b==ends[i]-starts[i]&&!memcmp(d->s+b,d->s+starts[i],e-b))return 0;
            starts[count]=b;ends[count]=e;ws(d);if(d->p>=d->n||d->s[d->p++]!=':')return 0;}
            count++;if(!scan_value(d,depth+1))return 0;ws(d);if(d->p>=d->n)return 0;
            unsigned char sep=d->s[d->p++];if(sep==stop)return 1;if(sep!=',')return 0;}
    }
    b=d->p;while(d->p<d->n&&!strchr(" \t\r\n,]}",d->s[d->p]))d->p++;return d->p>b;
}
static NSDictionary *decode_bounded(const char *bytes,size_t length,size_t object_limit) {
    if(!bytes||!length||length>RECORD_LIMIT||memchr(bytes,0,length)||(object_limit!=64&&object_limit!=128))return nil;
    Scan d={(const unsigned char *)bytes,length,0,0,object_limit};if(!scan_value(&d,0))return nil;ws(&d);if(d.p!=length)return nil;
    id value=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:length] options:0 error:NULL];return [value isKindOfClass:[NSDictionary class]]?value:nil;
}
static NSDictionary *decode(const char *bytes,size_t length) {return decode_bounded(bytes,length,64);}
/* Only the public installation manifest has a larger bounded source inventory.
 * Lease/registry parsing, array size, total nodes/depth and byte limits stay fixed. */
static NSDictionary *decode_manifest(const char *bytes,size_t length) {return decode_bounded(bytes,length,128);}
static int number(id value,uint64_t *out) {
    if(![value isKindOfClass:[NSNumber class]]||CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID())return 0;
    double x=[value doubleValue];uint64_t u=[value unsignedLongLongValue];if(x<0||x>9007199254740991.0||x!=(double)u)return 0;*out=u;return 1;
}
static const char *string(id value,size_t limit) {
    if(![value isKindOfClass:[NSString class]])return NULL;const char *s=[value UTF8String];
    if(!s||!strlen(s)||strlen(s)>=limit||[(NSString *)value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]!=strlen(s))return NULL;return s;
}
static int boolean(id value,int expected) {return value&&CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID()&&[value boolValue]==expected;}
static int equal_uuid(id value,const char *expected) {const char *s=string(value,37);return uuid(s)&&(!expected||!strcmp(s,expected));}
static int lease_shape(NSDictionary *l) {
    NSArray *keys=@[@"schema",@"runId",@"environmentId",@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId",@"consoleUID",@"gid",@"cwd",@"timezone",@"locale",@"issuedMonotonicMs",@"expiresMonotonicMs",@"bootTimeSeconds",@"controllerPid",@"controllerBirth",@"ipv4Address",@"rootHookLease"];
    if(!l||l.count!=keys.count||![[NSSet setWithArray:l.allKeys] isEqual:[NSSet setWithArray:keys]]||![l[@"schema"] isEqual:@ENVARA_APP_BOUND_LEASE_SCHEMA])return 0;
    for(NSString *key in @[@"runId",@"environmentId",@"realmId",@"leaseId",@"generation",@"registrationId",@"versionId"])if(!equal_uuid(l[key],NULL))return 0;
    uint64_t uid,gid,pid,issued,expires,boot;
    if(!number(l[@"consoleUID"],&uid)||!uid||uid>UINT32_MAX||!number(l[@"gid"],&gid)||gid<7100||gid>7999||!number(l[@"controllerPid"],&pid)||pid<2||pid>INT32_MAX||
        !number(l[@"issuedMonotonicMs"],&issued)||!number(l[@"expiresMonotonicMs"],&expires)||!number(l[@"bootTimeSeconds"],&boot)||!boot||expires<=issued||expires-issued>ENVARA_APP_BOUND_MAX_LEASE_MS)return 0;
    const char *cwd=string(l[@"cwd"],PATH_MAX),*tz=string(l[@"timezone"],128),*locale=string(l[@"locale"],64),*ip=string(l[@"ipv4Address"],16);
    NSDictionary *hook=l[@"rootHookLease"];
    return cwd&&cwd[0]=='/'&&tz&&locale&&string(l[@"controllerBirth"],40)&&ip&&(!strcmp(ip,"198.18.1.1")||!strcmp(ip,"198.18.2.1"))&&[hook isKindOfClass:[NSDictionary class]]&&equal_uuid(hook[@"runId"],string(l[@"runId"],37));
}
static int birth_parse(id value,struct envara_identity *idn) {
    const char *s=string(value,40);unsigned long long seconds,micro;int end=0;
    if(!s||sscanf(s,"%llu:%6llu%n",&seconds,&micro,&end)!=2||s[end]||micro>999999)return 0;
    char canonical[40];snprintf(canonical,sizeof(canonical),"%llu:%06llu",seconds,micro);if(strcmp(s,canonical))return 0;
    idn->birth_seconds=seconds;idn->birth_microseconds=micro;return 1;
}
static int root_process(const struct envara_identity *expected,const char *path,pid_t parent) {
    struct envara_identity now;char actual[PROC_PIDPATHINFO_MAXSIZE];
    if(expected->pid<2||envara_identity_read(expected->pid,&now)||now.birth_seconds!=expected->birth_seconds||now.birth_microseconds!=expected->birth_microseconds||
        !envara_identity_matches(&now,0,0)||(parent&&now.parent_pid!=parent)||proc_pidpath(now.pid,actual,sizeof(actual))<=0||strcmp(path,actual)||!envara_root_owned_executable(path)||envara_gui_acl_free(path))return 0;return 1;
}
static int registered_app(struct envara_app_native_factory *f) {
    struct envara_app_registry store;struct envara_app_registration actual;
    if(envara_app_registry_open(&store,NULL,0,0))return 0;
    int ok=!envara_app_registry_resolve(&store,f->plan.registration_id,f->plan.version_id,&actual);
    envara_app_registry_close(&store);if(!ok)return 0;
    if(f->app.schema&&memcmp(&f->app,&actual,sizeof(actual)))return 0;f->app=actual;return 1;
}
static int native_hash(char out[65]) {
    int dir=safe_directory(INSTALL,0755);if(dir<0)return 0;
    int fd=-1;struct stat identity;char *text=NULL;size_t n=0;int ok=0;
    if(read_private(dir,"manifest.json",RECORD_LIMIT,0644,&fd,&identity,&text,&n))goto done;
    NSDictionary *manifest=decode_manifest(text,n);NSDictionary *files=manifest[@"files"];
    if(![manifest[@"schema"] isEqual:@"envara.macos-pf-installation/v1"]||![manifest[@"component"] isEqual:@"envara-pf-routing"]||![manifest[@"backend"] isEqual:@"pf-utun"]||![manifest[@"version"] isEqual:@"1"]||![files isKindOfClass:[NSDictionary class]])goto done;
    const char *expected=string(files[@"envara-pf-native"],65);if(!digest_valid(expected))goto done;
    int binary=openat(dir,"envara-pf-native",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(binary<0)goto done;
    struct stat first,last,named;CC_SHA256_CTX ctx;unsigned char bytes[65536],hash[32];
    if(secure_object(binary,0,0755)||fstat(binary,&first)){close(binary);goto done;}CC_SHA256_Init(&ctx);
    for(;;){ssize_t count=read(binary,bytes,sizeof(bytes));if(count<0&&errno==EINTR)continue;if(count<0){close(binary);goto done;}if(!count)break;CC_SHA256_Update(&ctx,bytes,(CC_LONG)count);}
    CC_SHA256_Final(hash,&ctx);if(fstat(binary,&last)||fstatat(dir,"envara-pf-native",&named,AT_SYMLINK_NOFOLLOW)||!same_stat(&first,&last)||!same_stat(&last,&named)){close(binary);goto done;}close(binary);
    for(size_t i=0;i<32;i++)snprintf(out+i*2,3,"%02x",hash[i]);out[64]=0;ok=!strcmp(out,expected);
done:free(text);if(fd>=0)close(fd);close(dir);return ok;
}
static int registry_matches(struct envara_app_native_factory *f,NSDictionary *lease) {
    int fd=-1;struct stat s;char *bytes=NULL;size_t n=0;if(read_private(f->runtime_fd,"registry.json",RECORD_LIMIT,0600,&fd,&s,&bytes,&n))return 0;
    NSDictionary *r=decode(bytes,n);uint64_t pid=0;
    int ok=[r[@"schema"] isEqual:@"envara.macos-pf-owned-registry/v1"]&&equal_uuid(r[@"runId"],f->plan.run_id)&&number(r[@"supervisorPid"],&pid)&&pid==(uint64_t)f->plan.controller.pid&&boolean(r[@"cleanupUncertain"],0);
    NSDictionary *hook=r[@"rootHook"];ok=ok&&[hook isKindOfClass:[NSDictionary class]]&&boolean(hook[@"verified"],1)&&boolean(hook[@"removed"],0)&&boolean(hook[@"receiptRetired"],0)&&[hook[@"lease"] isEqual:lease[@"rootHookLease"]];
    NSArray *realms=r[@"realms"];NSUInteger matches=0;if(![realms isKindOfClass:[NSArray class]]||realms.count>2){free(bytes);close(fd);return 0;}
    for(NSDictionary *realm in realms){uint64_t gid=0;if(![realm isKindOfClass:[NSDictionary class]]){ok=0;break;}
        if(equal_uuid(realm[@"environmentId"],f->plan.environment_id)&&equal_uuid(realm[@"realmId"],f->plan.realm_id)&&number(realm[@"gid"],&gid)&&gid==f->plan.realm_gid)matches++;}
    ok=ok&&matches==1;free(bytes);close(fd);return ok;
}
static NSData *serialize_hook(NSDictionary *hook) {
    /* The exact native scalar lease parser intentionally refuses JSON escapes. */
    return [NSJSONSerialization dataWithJSONObject:hook options:NSJSONWritingWithoutEscapingSlashes error:NULL];
}
static int application_prepared(struct envara_app_native_factory *f) {
    /* Both checks use the POSIX 0-success/-1-refusal convention. */
    return envara_gui_request_validate(&f->app.snapshot,&f->request,0)==0&&envara_notion_supported(&f->app.snapshot)==0;
}
static int load_bound(struct envara_app_native_factory *f,const char *run,const char *env) {
    if(getuid()||geteuid()||!uuid(run)||!uuid(env))return refuse(EACCES);
    f->runtime_fd=safe_directory(RUNTIME,0700);if(f->runtime_fd<0)return -1;
    f->lock_fd=openat(f->runtime_fd,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(f->lock_fd<0||secure_object(f->lock_fd,0,0600)||fstat(f->lock_fd,&f->lock_identity))return refuse(EACCES);
    f->run_fd=openat(f->runtime_fd,run,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(f->run_fd<0||secure_object(f->run_fd,1,0700)||fstat(f->runtime_fd,&f->runtime_identity)||fstat(f->run_fd,&f->run_identity))return refuse(EACCES);
    if(read_private(f->run_fd,"app-bound-lease.json",LEASE_LIMIT,0600,&f->lease_fd,&f->lease_identity,&f->lease_bytes,&f->lease_size))return -1;
    NSDictionary *l=decode(f->lease_bytes,f->lease_size);
    if(!lease_shape(l)||!equal_uuid(l[@"runId"],run)||!equal_uuid(l[@"environmentId"],env))return refuse(EILSEQ);
    strcpy(f->plan.run_id,run);strcpy(f->plan.environment_id,env);
    const char *fields[]={"realmId","leaseId","generation","registrationId","versionId"};char *outputs[]={f->plan.realm_id,f->plan.lease_id,f->plan.generation,f->plan.registration_id,f->plan.version_id};
    for(size_t i=0;i<5;i++){NSString *key=[NSString stringWithUTF8String:fields[i]];if(!equal_uuid(l[key],NULL))return refuse(EILSEQ);strcpy(outputs[i],string(l[key],37));}
    uint64_t uid,gid,pid,now,boot;
    if(!number(l[@"consoleUID"],&uid)||uid<1||uid>UINT32_MAX||!number(l[@"gid"],&gid)||gid<7100||gid>7999||!number(l[@"controllerPid"],&pid)||pid<2||pid>INT32_MAX||
        !number(l[@"issuedMonotonicMs"],&f->issued)||!number(l[@"expiresMonotonicMs"],&f->expires)||!number(l[@"bootTimeSeconds"],&f->boot)||clock_values(&now,&boot)||
        f->boot!=boot||now<f->issued||now>=f->expires||f->expires-f->issued>ENVARA_APP_BOUND_MAX_LEASE_MS)return refuse(ETIMEDOUT);
    f->plan.console_uid=(uid_t)uid;f->plan.realm_gid=(gid_t)gid;f->plan.remaining_milliseconds=(unsigned)(f->expires-now);f->plan.controller.pid=(pid_t)pid;
    if(!birth_parse(l[@"controllerBirth"],&f->plan.controller)||!root_process(&f->plan.controller,INSTALL "/node",0)||envara_identity_read((pid_t)pid,&f->plan.controller))return refuse(ESTALE);
    uid_t console;char group[40];snprintf(group,sizeof(group),"_envara_pf_%u",(unsigned)gid);struct group *g=getgrgid((gid_t)gid);
    if(envara_console_uid(&console)||console!=uid||!g||strcmp(g->gr_name,group)||g->gr_gid!=gid)return refuse(EACCES);
    const char *cwd=string(l[@"cwd"],PATH_MAX),*tz=string(l[@"timezone"],128),*locale=string(l[@"locale"],64),*ip=string(l[@"ipv4Address"],16);
    if(!cwd||cwd[0]!='/'||!tz||!locale||!ip||(strcmp(ip,"198.18.1.1")&&strcmp(ip,"198.18.2.1")))return refuse(EILSEQ);
    f->request.schema=1;strcpy(f->request.lease_id,f->plan.lease_id);strcpy(f->request.environment_id,env);f->request.console_uid=(uid_t)uid;f->request.realm_gid=(gid_t)gid;
    strcpy(f->request.cwd,cwd);strcpy(f->request.timezone,tz);strcpy(f->request.browser_locale,locale);strcpy(f->plan.ipv4,ip);
    snprintf(f->plan.state_directory,sizeof(f->plan.state_directory),RUNTIME "/%s/%s",run,f->plan.realm_id);
    int state=safe_directory(f->plan.state_directory,0700);if(state<0)return -1;close(state);
    NSDictionary *hook=l[@"rootHookLease"];if(![hook isKindOfClass:[NSDictionary class]]||!equal_uuid(hook[@"runId"],run))return refuse(EILSEQ);
    NSData *hook_data=serialize_hook(hook);if(!hook_data||hook_data.length>LEASE_LIMIT)return refuse(EILSEQ);
    f->hook_size=hook_data.length;f->hook_bytes=calloc(f->hook_size+1,1);if(!f->hook_bytes)return -1;memcpy(f->hook_bytes,hook_data.bytes,f->hook_size);
    sha(f->lease_bytes,f->lease_size,f->plan.lease_sha256);
    if(!registry_matches(f,l))return refuse(EACCES);return 0;
}
static int load(struct envara_app_native_factory *f,const char *run,const char *env) {
    if(load_bound(f,run,env))return -1;
    if(!registered_app(f)||!native_hash(f->plan.native_sha256))return refuse(EACCES);return 0;
}
static void dispose(struct envara_app_native_factory *f) {
    if(!f)return;envara_journal_retirement_close(&f->retirement);envara_pf_hook_filter_close(f->hook);if(f->pf_fd>=0)close(f->pf_fd);if(f->journal_fd>=0)close(f->journal_fd);for(size_t i=0;i<f->journal_count;i++){if(f->journal_file_fds[i]>=0)close(f->journal_file_fds[i]);free(f->journal_file_bytes[i]);}if(f->lease_fd>=0)close(f->lease_fd);if(f->lock_fd>=0)close(f->lock_fd);if(f->run_fd>=0)close(f->run_fd);if(f->runtime_fd>=0)close(f->runtime_fd);free(f->lease_bytes);free(f->hook_bytes);free(f);
}
static struct envara_app_native_factory *allocate(void) {
    struct envara_app_native_factory *f=calloc(1,sizeof(*f));if(f){f->owner=getpid();f->lease_fd=f->lock_fd=f->run_fd=f->runtime_fd=f->pf_fd=f->journal_fd=-1;for(size_t i=0;i<32;i++)f->journal_file_fds[i]=-1;f->journal_entries_trusted=1;}return f;
}
int envara_app_native_preflight(const char *run,const char *env,struct envara_app_native_preflight *out) {
    envara_app_native_failure_begin();
    native_failure_reason="NATIVE_CONTEXT_LOAD_REFUSED";
    if(!out)return refuse(EINVAL);@autoreleasepool {struct envara_app_native_factory *f=allocate();if(!f)return -1;int status=load(f,run,env),error=errno;if(!status)*out=f->plan;dispose(f);errno=error;return status;}
}
int envara_app_native_abort_plan(const char *run,const char *env,struct envara_app_native_preflight *out,
                                char *hook,size_t capacity,size_t *length) {
    if(out)memset(out,0,sizeof(*out));if(length)*length=0;if(hook&&capacity&&capacity<=LEASE_LIMIT)memset(hook,0,capacity);
    if(!out||!hook||!capacity||capacity>LEASE_LIMIT||!length)return refuse(EINVAL);
    @autoreleasepool {
        struct envara_app_native_factory *f=allocate();if(!f)return -1;
        int status=load_bound(f,run,env);
        if(!status&&(!f->hook_size||f->hook_size>=capacity))status=refuse(EOVERFLOW);
        if(!status){*out=f->plan;memcpy(hook,f->hook_bytes,f->hook_size);*length=f->hook_size;}
        int error=errno;dispose(f);errno=error;return status;
    }
}
static int immutable_lease(struct envara_app_native_factory *f,int active) {
    struct stat held,named,runtime,run;uint64_t now,boot;uid_t console;
    if(!f||f->owner!=getpid()||getuid()||geteuid()||secure_object(f->lease_fd,0,0600)||secure_object(f->runtime_fd,1,0700)||secure_object(f->run_fd,1,0700)||
        fstat(f->lease_fd,&held)||fstatat(f->run_fd,"app-bound-lease.json",&named,AT_SYMLINK_NOFOLLOW)||
        !same_stat(&held,&f->lease_identity)||!same_stat(&held,&named)||fstat(f->runtime_fd,&runtime)||fstat(f->run_fd,&run)||
        runtime.st_dev!=f->runtime_identity.st_dev||runtime.st_ino!=f->runtime_identity.st_ino||run.st_dev!=f->run_identity.st_dev||run.st_ino!=f->run_identity.st_ino||
        clock_values(&now,&boot)||boot!=f->boot||(active==1&&(now<f->issued||now>=f->expires))||
        (active>=0&&(envara_console_uid(&console)||console!=f->plan.console_uid)))return 0;
    char *bytes=malloc(f->lease_size);if(!bytes)return 0;ssize_t n=pread(f->lease_fd,bytes,f->lease_size,0);int ok=n==(ssize_t)f->lease_size&&!memcmp(bytes,f->lease_bytes,f->lease_size);free(bytes);
    struct stat lock,named_lock;if(secure_object(f->lock_fd,0,0600)||fstat(f->lock_fd,&lock)||fstatat(f->runtime_fd,"registry.lock",&named_lock,AT_SYMLINK_NOFOLLOW)||!same_stat(&lock,&f->lock_identity)||!same_stat(&lock,&named_lock))return 0;
    int directory=safe_directory(RUNTIME,0700);if(directory<0)return 0;struct stat current;ok=ok&&!fstat(directory,&current)&&current.st_dev==runtime.st_dev&&current.st_ino==runtime.st_ino;close(directory);
    struct stat current_run;ok=ok&&!fstatat(f->runtime_fd,f->plan.run_id,&current_run,AT_SYMLINK_NOFOLLOW)&&current_run.st_dev==run.st_dev&&current_run.st_ino==run.st_ino;
    char group[40];snprintf(group,sizeof(group),"_envara_pf_%u",f->plan.realm_gid);struct group *g=getgrgid(f->plan.realm_gid);return ok&&g&&g->gr_gid==f->plan.realm_gid&&!strcmp(g->gr_name,group);
}
static int utun_original(struct envara_app_native_factory *f) {
    struct stat s;struct ctl_info control={0};struct sockaddr_ctl peer={0};socklen_t size=sizeof(peer),n=16;char name[16]={0};int type=0;socklen_t integer=sizeof(type);
    strlcpy(control.ctl_name,UTUN_CONTROL_NAME,sizeof(control.ctl_name));
    int flags=fcntl(f->owned.original_utun_fd,F_GETFD);
    return flags>=0&&(flags&FD_CLOEXEC)&&!fstat(f->owned.original_utun_fd,&s)&&S_ISSOCK(s.st_mode)&&s.st_dev==f->utun_identity.st_dev&&s.st_ino==f->utun_identity.st_ino&&
        !getsockopt(f->owned.original_utun_fd,SOL_SOCKET,SO_TYPE,&type,&integer)&&integer==sizeof(type)&&type==SOCK_DGRAM&&
        !ioctl(f->owned.original_utun_fd,CTLIOCGINFO,&control)&&!getpeername(f->owned.original_utun_fd,(struct sockaddr *)&peer,&size)&&size==sizeof(peer)&&peer.sc_family==AF_SYSTEM&&peer.ss_sysaddr==AF_SYS_CONTROL&&peer.sc_id==control.ctl_id&&peer.sc_unit&&
        !getsockopt(f->owned.original_utun_fd,SYSPROTO_CONTROL,UTUN_OPT_IFNAME,name,&n)&&memchr(name,0,sizeof(name))&&!strcmp(name,f->owned.tunnel_name);
}
static int listener_original(struct envara_app_native_factory *f) {
    struct stat s;struct envara_app_listener held={.fd=f->owned.original_listener_fd,.owner=getpid(),.port=f->config.tcp_front_port,
        .credential_uid=0,.credential_gid=f->plan.realm_gid};
    /* fstat(socket) reads so_cred, including after SCM_RIGHTS transfer. The
     * keeper/front process GID is not the listening socket's identity. */
    return !fstat(held.fd,&s)&&s.st_uid==0&&s.st_gid==f->plan.realm_gid&&
        s.st_dev==f->listener_identity.st_dev&&s.st_ino==f->listener_identity.st_ino&&!envara_app_listener_verify(&held);
}
static int pipe_reader(int fd,struct stat *s) {
    int flags=fcntl(fd,F_GETFL),cloexec=fcntl(fd,F_GETFD);
    return fd>=3&&flags>=0&&(flags&O_ACCMODE)==O_RDONLY&&cloexec>=0&&(cloexec&FD_CLOEXEC)&&!fstat(fd,s)&&S_ISFIFO(s->st_mode)&&!s->st_uid&&!s->st_nlink;
}
static int pipes_original(struct envara_app_native_factory *f) {
    struct stat one,two;return pipe_reader(f->owned.lease_read_fd,&one)&&pipe_reader(f->owned.recovery_read_fd,&two)&&
        one.st_dev==f->lease_pipe_identity.st_dev&&one.st_ino==f->lease_pipe_identity.st_ino&&two.st_dev==f->recovery_pipe_identity.st_dev&&two.st_ino==f->recovery_pipe_identity.st_ino&&
        (one.st_dev!=two.st_dev||one.st_ino!=two.st_ino);
}
/* Fixed read-only command. No shell/user args, no stdout in diagnostics. Keep
 * the original unreaped direct PID until signalling so PID reuse cannot occur.
 * Unknown exit/output/timeout refuses without modifying skip flags or PF. */
static int pf_read(int info,char output[16385]) {
    int channel[2];if(pipe(channel))return 0;if(fcntl(channel[0],F_SETFD,FD_CLOEXEC)||fcntl(channel[1],F_SETFD,FD_CLOEXEC)){close(channel[0]);close(channel[1]);return 0;}
    posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;
    if(posix_spawn_file_actions_init(&actions)){close(channel[0]);close(channel[1]);return 0;}
    if(posix_spawnattr_init(&attributes)){posix_spawn_file_actions_destroy(&actions);close(channel[0]);close(channel[1]);return 0;}
    int setup=posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT)||
        posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0)||posix_spawn_file_actions_adddup2(&actions,channel[1],1)||
        posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)||posix_spawn_file_actions_addclose(&actions,channel[0]);
    char *interfaces[]={"/sbin/pfctl","-v","-s","Interfaces",NULL},*status_args[]={"/sbin/pfctl","-s","info",NULL};char **args=info?status_args:interfaces;
    char *env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin",NULL};pid_t child;
    int spawn=setup?EINVAL:posix_spawn(&child,args[0],&actions,&attributes,args,env);posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attributes);close(channel[1]);if(spawn){close(channel[0]);return 0;}
    size_t used=0;int ended=0,status=0,failed=0,eof=0;uint64_t now,boot;if(clock_values(&now,&boot)){close(channel[0]);kill(child,SIGKILL);for(int i=0;i<100;i++){if(waitpid(child,NULL,WNOHANG)==child)break;poll(NULL,0,10);}return 0;}uint64_t deadline=now+2000;
    while(!eof||!ended){if(clock_values(&now,&boot)||now>=deadline){failed=1;break;}
        if(!ended){pid_t done=waitpid(child,&status,WNOHANG);if(done==child)ended=1;else if(done<0){failed=1;ended=1;break;}}
        struct pollfd p={channel[0],POLLIN|POLLHUP,0};int r=poll(&p,1,25);if(r<0&&errno==EINTR)continue;if(r<0){failed=1;break;}
        if(r>0&&(p.revents&(POLLIN|POLLHUP))){ssize_t count=read(channel[0],output+used,16384-used);if(count==0)eof=1;else if(count<0){if(errno!=EINTR){failed=1;break;}}else used+=(size_t)count;if(used==16384){failed=1;break;}}
    }
    close(channel[0]);if(!ended){(void)kill(child,SIGKILL);for(int i=0;i<100;i++){pid_t r=waitpid(child,&status,WNOHANG);if(r==child){ended=1;break;}if(r<0)break;poll(NULL,0,10);}}
    if(failed||!ended||!WIFEXITED(status)||WEXITSTATUS(status)||!used||memchr(output,0,used))return 0;output[used]=0;return 1;
}
static int loopback_filtering(void) {
    char output[16385];if(!pf_read(0,output))return 0;
    int found=0;char names[256][33];size_t entries=0;char *save=NULL;
    for(char *line=strtok_r(output,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        size_t n=strlen(line);int skip=n>7&&!strcmp(line+n-7," (skip)");if(skip){line[n-7]=0;n-=7;}
        if(!n||n>32||entries>=256)return 0;for(size_t i=0;i<n;i++)if(!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-",line[i]))return 0;
        for(size_t i=0;i<entries;i++)if(!strcmp(names[i],line))return 0;strcpy(names[entries++],line);
        if(!strcmp(line,"lo0")){if(skip)return 0;found=1;}if(skip&&(!strcmp(line,"all")||!strcmp(line,"lo")))return 0;
    }
    return found;
}
static int pf_enabled_text(char *output) {
    size_t found=0;char *save=NULL;
    for(char *line=strtok_r(output,"\n",&save);line;line=strtok_r(NULL,"\n",&save))if(!strncmp(line,"Status:",7)){
        if(strncmp(line,"Status: Enabled",15)||(line[15]&&line[15]!=' '))return 0;found++;}
    return found==1;
}
static int pf_running(struct envara_app_native_factory *f) {
    char output[16385];if(!pf_read(1,output)||!pf_enabled_text(output))return 0;
    int fd=-1;struct stat s;char *bytes=NULL;size_t n=0;if(read_private(f->runtime_fd,"registry.json",RECORD_LIMIT,0600,&fd,&s,&bytes,&n))return 0;
    NSDictionary *r=decode(bytes,n),*reference=r[@"ownedPFReference"];
    if(![reference isKindOfClass:[NSDictionary class]]){free(bytes);close(fd);return 0;}
    const char *token=string(reference[@"token"],32);
    int ok=equal_uuid(r[@"runId"],f->plan.run_id)&&boolean(reference[@"acquired"],1)&&boolean(reference[@"released"],0)&&token&&token[0]!='0';
    if(token)for(const char *p=token;*p;p++)if(*p<'0'||*p>'9')ok=0;
    free(bytes);close(fd);return ok;
}
static int dependencies(struct envara_app_native_factory *f) {
    return root_process(&f->owned.controller,INSTALL "/node",0)&&root_process(&f->owned.core,INSTALL "/mihomo",getpid())&&root_process(&f->owned.frontend,INSTALL "/node",getpid());
}
static int basic(struct envara_app_native_factory *f,int live) {
    return (!f->poisoned||(f->cleanup_only&&f->cleanup_reconciled))&&immutable_lease(f,f->cleanup_only&&!live?-1:live)&&utun_original(f)&&listener_original(f)&&pipes_original(f)&&(!live||(dependencies(f)&&pf_running(f)))&&f->hook&&envara_pf_hook_filter_guard(f->hook,f->pf_fd)&&(f->cleanup_only||loopback_filtering());
}
static int cleanup_owned(struct envara_app_native_factory *f) {
    return f&&f->owner==getpid()&&immutable_lease(f,-1)&&utun_original(f)&&listener_original(f)&&pipes_original(f)&&
        root_process(&f->owned.controller,INSTALL "/node",0)&&f->hook&&envara_pf_hook_filter_guard(f->hook,f->pf_fd);
}
static int pf_guard(void *opaque,int fd,EnvaraPFProductionStage stage,uint32_t index) {
    (void)stage;(void)index;struct envara_app_native_factory *f=opaque;
    /* Recovery DENY/EMPTY remains possible after dependency exit/lease expiry;
     * immutable ownership/original descriptors/exact native hook never relax. */
    if(f->cleanup_reconciling)return fd==f->pf_fd&&stage==ENVARA_PF_PRODUCTION_GUARD_VERIFY&&cleanup_owned(f);
    return fd==f->pf_fd&&basic(f,f->guard_live);
}
static int context(struct envara_app_native_factory *f,EnvaraPFProductionContext *ctx) {
    memset(ctx,0,sizeof(*ctx));
    EnvaraPFProductionConfig c=f->config;
    c.has_previous_revision=f->receipt.verified;c.expected_revision=f->receipt.ticket;c.expected_writer_pid=f->receipt.writer_pid;
    return EnvaraPFProductionInit(ctx,f->pf_fd,f,NULL,pf_guard,&c)==1;
}
static int verify_mode(struct envara_app_native_factory *f,EnvaraPFProductionMode mode,int live) {
    if(!basic(f,live)||f->mode!=mode)return 0;EnvaraPFProductionContext c;EnvaraPFProductionResult r;
    int previous=f->guard_live;f->guard_live=live;int ok=context(f,&c)&&EnvaraPFProductionVerify(&c,mode,&r)==1&&r.verified&&!r.uncertain;f->guard_live=previous;return ok;
}
static int journal_write(struct envara_app_native_factory *f,NSString *suffix,NSDictionary *record) {
    if(f->journal_count>=32||!f->journal_entries_trusted){errno=EOVERFLOW;return 0;}
    if(f->journal_fd<0){
        if(mkdirat(f->run_fd,"app-filter-events",0700))return 0;
        f->journal_created=1;
        f->journal_fd=openat(f->run_fd,"app-filter-events",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(f->journal_fd<0||secure_object(f->journal_fd,1,0700)||fstat(f->journal_fd,&f->journal_identity)||fsync(f->run_fd))return 0;
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    if(!data||data.length>4096){errno=EINVAL;return 0;}
    NSString *name=[NSString stringWithFormat:@"%03u.%@",f->sequence,suffix];
    int fd=openat(f->journal_fd,name.UTF8String,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return 0;
    /* Retain this original EXCL-created file, including a known partial write.
     * Recovery never adopts a pathname or treats an untracked file as ours. */
    size_t index=f->journal_count++;f->journal_file_fds[index]=fd;strlcpy(f->journal_names[index],name.UTF8String,32);
    size_t offset=0;int ok=1,error=0;
    while(offset<data.length){ssize_t n=write(fd,(const char *)data.bytes+offset,data.length-offset);if(n<0&&errno==EINTR)continue;
        if(n<=0){ok=0;error=n<0?errno:EIO;break;}offset+=(size_t)n;}
    if(ok&&fsync(fd)){ok=0;error=errno;}
    struct stat first,last;char *bytes=calloc(offset+1,1);
    if(!bytes||secure_object(fd,0,0600)||fstat(fd,&first)||first.st_size!=(off_t)offset||
        pread(fd,bytes,offset,0)!=(ssize_t)offset||memcmp(bytes,data.bytes,offset)||fstat(fd,&last)||!same_stat(&first,&last)){
        if(!error)error=errno?errno:EIO;f->journal_entries_trusted=0;free(bytes);ok=0;
    } else {f->journal_files[index]=last;f->journal_file_bytes[index]=bytes;f->journal_file_sizes[index]=offset;}
    if(ok&&fsync(f->journal_fd)){ok=0;error=errno;}
    if(!ok)errno=error?error:EIO;return ok;
}
int envara_app_native_factory_apply(envara_app_native_factory *f,EnvaraPFProductionMode mode,EnvaraPFProductionResult *out) {
    envara_app_native_failure_begin();
    native_failure_reason="NATIVE_PF_GUARD_REFUSED";
    if(!f||!out)return refuse(EINVAL);memset(out,0,sizeof(*out));
    if(mode!=ENVARA_PF_PRODUCTION_DENY&&mode!=ENVARA_PF_PRODUCTION_EMPTY&&mode!=ENVARA_PF_PRODUCTION_FRONT)return refuse(ENOTSUP);
    if(f->cleanup_only&&mode==ENVARA_PF_PRODUCTION_FRONT)return refuse(ECANCELED);
    @autoreleasepool {
        if(f->sequence>=16||!basic(f,mode==ENVARA_PF_PRODUCTION_FRONT)||
            (mode==ENVARA_PF_PRODUCTION_FRONT&&!f->staged&&envara_app_scope_gid_absent(f->plan.realm_gid)!=1))return refuse(EACCES);
        if(!verify_mode(f,f->mode,0))return operation_refuse("NATIVE_FILTER_READBACK_REFUSED",EACCES);
        NSDictionary *intent=@{@"schema":@"envara.macos-pf-app-filter-event/v1",@"runId":@(f->plan.run_id),@"leaseId":@(f->plan.lease_id),@"generation":@(f->plan.generation),@"sequence":@(f->sequence),@"previous":@(f->mode),@"next":@(mode),@"writerPid":@(getpid())};
        f->pending_intent=1;f->pending_mode=mode;f->pending_write_attempted=0;memset(&f->pending_result,0,sizeof(f->pending_result));
        if(!journal_write(f,@"intent",intent)){int error=errno;f->poisoned=1;f->cleanup_reconciled=0;return operation_refuse("NATIVE_JOURNAL_REFUSED",error);}
        f->guard_live=mode==ENVARA_PF_PRODUCTION_FRONT;
        EnvaraPFProductionContext c;int initialized=context(f,&c),ok=0;
        if(initialized){f->pending_write_attempted=1;ok=EnvaraPFProductionApply(&c,mode,out)==1&&out->verified&&!out->uncertain;}
        int apply_error=out->os_error?out->os_error:(errno?errno:EIO);f->pending_result=*out;f->guard_live=0;
        if(!ok){f->poisoned=1;f->cleanup_reconciled=0;return operation_refuse("NATIVE_FILTER_TRANSACTION_REFUSED",apply_error);}
        NSDictionary *ack=@{@"schema":@"envara.macos-pf-app-filter-receipt/v1",@"runId":@(f->plan.run_id),@"leaseId":@(f->plan.lease_id),@"generation":@(f->plan.generation),@"sequence":@(f->sequence),@"mode":@(mode),@"writerPid":@(out->writer_pid),@"revision":@(out->ticket),@"ruleCount":@(out->actual_count)};
        if(!journal_write(f,@"receipt",ack)){int error=errno;f->poisoned=1;f->cleanup_reconciled=0;return operation_refuse("NATIVE_JOURNAL_REFUSED",error);}
        if(!basic(f,mode==ENVARA_PF_PRODUCTION_FRONT)){f->poisoned=1;f->cleanup_reconciled=0;return operation_refuse("NATIVE_PF_GUARD_REFUSED",EACCES);}
        f->receipt=*out;f->mode=mode;f->sequence++;f->pending_intent=0;return 0;
    }
}
static int inventory_guard(void *opaque) {return cleanup_owned(opaque);}
static int journal_inventory_bound(struct envara_app_native_factory *f) {
    if(!f->journal_entries_trusted)return 0;
    if(f->retirement.initialized)return envara_journal_retirement_verify(&f->retirement);
    if(f->journal_fd<0)return !f->journal_created;
    struct envara_journal_retirement *bound=calloc(1,sizeof(*bound));if(!bound)return 0;
    struct envara_journal_retirement_entry entries[32];memset(entries,0,sizeof(entries));
    for(size_t i=0;i<f->journal_count;i++)entries[i]=(struct envara_journal_retirement_entry){
        .name=f->journal_names[i],.fd=f->journal_file_fds[i],.identity=f->journal_files[i],.bytes=f->journal_file_bytes[i],.length=f->journal_file_sizes[i]};
    int ok=envara_journal_retirement_init(bound,f->run_fd,f->journal_fd,"app-filter-events",&f->journal_identity,
        entries,f->journal_count,0,0,inventory_guard,f);
    envara_journal_retirement_close(bound);free(bound);return ok;
}
/* A failed syscall reply is not repaired by a later matching readback. Only
 * this same keeper's no-write outcome or fully verified apply can reconcile
 * into irreversible cleanup authority; the original poison latch stays set. */
static int cleanup_outcome(const struct envara_app_native_factory *f) {
    if(!f||f->owner!=getpid()||!f->pending_intent)return 0;
    if(!f->pending_write_attempted||(!f->pending_result.begun&&!f->pending_result.uncertain))return 1;
    return f->pending_result.verified&&!f->pending_result.uncertain&&f->pending_result.committed&&
        f->pending_result.ticket_known&&f->pending_result.writer_pid==(uint32_t)getpid()?2:0;
}
static int cleanup_reconcile(struct envara_app_native_factory *f) {
    if(!cleanup_owned(f)||!journal_inventory_bound(f))return 0;
    f->cleanup_only=1;
    if(!f->poisoned){f->cleanup_reconciled=1;return 1;}
    if(f->cleanup_reconciled)return 1;
    int outcome=cleanup_outcome(f);if(!outcome)return 0;int no_write=outcome==1;
    EnvaraPFProductionConfig config=f->config;EnvaraPFProductionResult candidate=no_write?f->receipt:f->pending_result;
    EnvaraPFProductionMode mode=no_write?f->mode:f->pending_mode;
    config.has_previous_revision=candidate.verified;config.expected_revision=candidate.ticket;config.expected_writer_pid=candidate.writer_pid;
    EnvaraPFProductionContext c={0};EnvaraPFProductionResult observed;f->cleanup_reconciling=1;
    int ok=EnvaraPFProductionInit(&c,f->pf_fd,f,NULL,pf_guard,&config)==1&&EnvaraPFProductionVerify(&c,mode,&observed)==1&&observed.verified&&!observed.uncertain;
    f->cleanup_reconciling=0;if(!ok)return 0;
    f->receipt=candidate;f->mode=mode;f->sequence++;f->pending_intent=0;f->cleanup_reconciled=1;return 1;
}
int envara_app_native_factory_cleanup_binding(envara_app_native_factory *f) { return cleanup_owned(f); }
int envara_app_native_factory_cleanup_deny(envara_app_native_factory *f) {
    if(!cleanup_reconcile(f))return 0;
    if(verify_mode(f,ENVARA_PF_PRODUCTION_DENY,0))return 1;
    EnvaraPFProductionResult r;return !envara_app_native_factory_apply(f,ENVARA_PF_PRODUCTION_DENY,&r)&&verify_mode(f,ENVARA_PF_PRODUCTION_DENY,0);
}
static int persistent_deny(void *opaque) {
    struct envara_app_native_factory *f=opaque;
    if(verify_mode(f,ENVARA_PF_PRODUCTION_DENY,0))return 1;
    /* FRONT is a scoped exception under the fixed child Seatbelt boundary,
     * not broad network protection. This callback never revokes admission
     * during guard's pre-fork checks. Final release must remove the exception. */
    return verify_mode(f,ENVARA_PF_PRODUCTION_FRONT,0);
}
static int scope_absent(void *opaque){struct envara_app_native_factory *f=opaque;return immutable_lease(f,f->cleanup_only?-1:0)&&envara_app_scope_gid_absent(f->plan.realm_gid)==1;}
static int ticket_verify(const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run,const char *hash,void *opaque) {
    struct envara_app_native_factory *f=opaque;
    if(!app||!request||strcmp(run,f->plan.run_id)||strcmp(hash,f->plan.lease_sha256)||memcmp(request,&f->request,sizeof(*request))||memcmp(app,&f->app,sizeof(*app)))return operation_refuse("NATIVE_TICKET_BINDING_REFUSED",EACCES);
#ifdef ENVARA_APP_FACTORY_TICKET_INERT
    /* Only the private source-including fixture replaces these two boundary
     * calls. Production has no configurable provider or cached proof. */
#define TICKET_REGISTERED_APP envara_factory_fixture_registered_app
#define TICKET_VERIFY_MODE envara_factory_fixture_verify_mode
#else
#define TICKET_REGISTERED_APP registered_app
#define TICKET_VERIFY_MODE verify_mode
#endif
    /* The staged app/request were copied by this root-owned factory and are
     * still exactly bound above. Persistent denial audits fresh kernel/lease
     * custody each time; full bundle inspection remains before stage and in
     * verify_resume immediately before SIGCONT. */
    @autoreleasepool {
        if(!f->staged&&!TICKET_REGISTERED_APP(f))return operation_refuse("NATIVE_APP_IDENTITY_REFUSED",EACCES);
        int ok=!f->staged?TICKET_VERIFY_MODE(f,ENVARA_PF_PRODUCTION_FRONT,1):
            (TICKET_VERIFY_MODE(f,ENVARA_PF_PRODUCTION_FRONT,0)||TICKET_VERIFY_MODE(f,ENVARA_PF_PRODUCTION_DENY,0));
        return ok?0:operation_refuse("NATIVE_TICKET_FILTER_REFUSED",EACCES);
    }
#undef TICKET_REGISTERED_APP
#undef TICKET_VERIFY_MODE
}
static int ticket_inspect(const char *env,const char *run,const struct envara_app_registration *app,struct envara_gui_request *request,char hash[65],void *opaque) {
    struct envara_app_native_factory *f=opaque;if(!request||!hash||strcmp(env,f->plan.environment_id)||strcmp(run,f->plan.run_id)||memcmp(app,&f->app,sizeof(*app)))return -1;
    *request=f->request;strcpy(hash,f->plan.lease_sha256);return ticket_verify(app,request,run,hash,opaque);
}
static int exact_staged_child(struct envara_app_native_factory *f,const struct envara_child *child,int stopped) {
    if(!f->staged||!child||memcmp(&child->identity,&f->stage_child.identity,sizeof(child->identity))||child->identity.parent_pid!=getpid()||child->identity.pid<2||!envara_same_process(&child->identity))return 0;
    struct proc_bsdinfo b={0};struct kinfo_proc p={0};size_t n=sizeof(p);int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,child->identity.pid};
    if(proc_pidinfo(child->identity.pid,PROC_PIDTBSDINFO,1,&b,sizeof(b))!=sizeof(b)||
        b.pbi_start_tvsec!=child->identity.birth_seconds||b.pbi_start_tvusec!=child->identity.birth_microseconds||b.pbi_ppid!=(uint32_t)getpid()||
        b.pbi_uid!=f->plan.console_uid||b.pbi_ruid!=f->plan.console_uid||b.pbi_svuid!=f->plan.console_uid||b.pbi_gid!=f->plan.realm_gid||b.pbi_rgid!=f->plan.realm_gid||b.pbi_svgid!=f->plan.realm_gid||
        (stopped&&b.pbi_status!=SSTOP)||sysctl(mib,4,&p,&n,NULL,0)||n!=sizeof(p)||p.kp_proc.p_pid!=child->identity.pid||
        (uint64_t)p.kp_proc.p_starttime.tv_sec!=child->identity.birth_seconds||(uint64_t)p.kp_proc.p_starttime.tv_usec!=child->identity.birth_microseconds||
        p.kp_eproc.e_ucred.cr_ngroups!=1||p.kp_eproc.e_ucred.cr_groups[0]!=f->plan.realm_gid||!envara_same_process(&child->identity))return 0;return 1;
}
static int verify_resume(const struct envara_child *child,void *opaque) {
    struct envara_app_native_factory *f=opaque;@autoreleasepool {
        struct envara_gui_session graphics;char path[PROC_PIDPATHINFO_MAXSIZE];struct envara_notion_context c={.front_port=f->config.tcp_front_port};struct envara_notion_plan plan;strcpy(c.registration_id,f->plan.registration_id);
        return exact_staged_child(f,child,1)&&verify_mode(f,ENVARA_PF_PRODUCTION_FRONT,1)&&registered_app(f)&&
            !envara_gui_request_validate(&f->app.snapshot,&f->request,0)&&!envara_gui_session_read(&graphics)&&graphics.console_uid==f->plan.console_uid&&graphics.audit_session==f->request.gui_audit_session&&graphics.audit_has_console_graphics&&graphics.security_has_graphics&&
            !envara_notion_plan(&f->app,&f->request,&c,&plan)&&proc_pidpath(child->identity.pid,path,sizeof(path))>0&&!strcmp(path,ENVARA_GUI_NATIVE_PATH)&&exact_staged_child(f,child,1);
    }
}
static int running_signature(pid_t pid,const struct envara_gui_manifest *manifest) {
    SecCodeRef code=NULL;CFDictionaryRef info=NULL;SecRequirementRef requirement=NULL;int ok=0;
    NSDictionary *guest=@{(__bridge NSString *)kSecGuestAttributePid:@(pid)};
    if(SecCodeCopyGuestWithAttributes(NULL,(__bridge CFDictionaryRef)guest,kSecCSDefaultFlags,&code)!=errSecSuccess||
        SecRequirementCreateWithString((__bridge CFStringRef)[NSString stringWithUTF8String:manifest->requirement],kSecCSDefaultFlags,&requirement)!=errSecSuccess||
        SecCodeCheckValidity(code,kSecCSStrictValidate,requirement)!=errSecSuccess||SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info)!=errSecSuccess)goto done;
    CFDataRef data=(CFDataRef)CFDictionaryGetValue(info,kSecCodeInfoUnique);if(!data||CFGetTypeID(data)!=CFDataGetTypeID()||CFDataGetLength(data)<20||CFDataGetLength(data)>32)goto done;
    char hash[65]={0};const UInt8 *bytes=CFDataGetBytePtr(data);for(CFIndex i=0;i<CFDataGetLength(data);i++)snprintf(hash+i*2,3,"%02x",bytes[i]);ok=!strcmp(hash,manifest->cdhash);
done:if(requirement)CFRelease(requirement);if(info)CFRelease(info);if(code)CFRelease(code);return ok;
}
static int verify_executed(const struct envara_child *child,void *opaque) {
    struct envara_app_native_factory *f=opaque;@autoreleasepool {
        char path[PROC_PIDPATHINFO_MAXSIZE];if(!exact_staged_child(f,child,0)||!verify_mode(f,ENVARA_PF_PRODUCTION_FRONT,1)||proc_pidpath(child->identity.pid,path,sizeof(path))<=0)return -1;
        if(!strcmp(path,ENVARA_GUI_NATIVE_PATH)||!strcmp(path,"/usr/bin/sandbox-exec"))return 0;
        /* Fixed root-owned sandbox-exec receives only the native constructed
         * profile and exact signed snapshot argv. Its successful exec chain
         * plus actual target identity is observable; this is NOT a private
         * sandbox policy reader or a claim that all external delegates obey. */
        return !strcmp(path,f->app.snapshot.executable)&&running_signature(child->identity.pid,&f->app.snapshot)&&exact_staged_child(f,child,0)?1:-1;
    }
}
static int prepare_guard(const struct envara_app_registration *app,const struct envara_gui_request *request,const char *run,const char *hash,struct envara_launch_guard_request *guard,struct envara_launch_guard_authority *authority,void *opaque) {
    struct envara_app_native_factory *f=opaque;if(ticket_verify(app,request,run,hash,f))return -1;if(!scope_absent(f))return operation_refuse("NATIVE_SCOPE_CHECK_REFUSED",EACCES);
    /* The supervisor demands persistent DENY before fork. For first-app scope,
     * exact FRONT admits only sandbox-permitted SOCKS requests; its denial is
     * checked here without revoking before the cold stage. Faults use DENY. */
    int a=fcntl(f->owned.original_utun_fd,F_DUPFD_CLOEXEC,3),b=fcntl(f->owned.lease_read_fd,F_DUPFD_CLOEXEC,3),c=fcntl(f->owned.recovery_read_fd,F_DUPFD_CLOEXEC,3);
    struct stat copied_one,copied_two;
    if(a<0||b<0||c<0||!pipe_reader(b,&copied_one)||!pipe_reader(c,&copied_two)||
        copied_one.st_dev!=f->lease_pipe_identity.st_dev||copied_one.st_ino!=f->lease_pipe_identity.st_ino||copied_two.st_dev!=f->recovery_pipe_identity.st_dev||copied_two.st_ino!=f->recovery_pipe_identity.st_ino||!pipes_original(f)){
        int error=(a<0||b<0||c<0)?errno:EACCES;if(a>=0)close(a);if(b>=0)close(b);if(c>=0)close(c);return operation_refuse("NATIVE_GUARD_DESCRIPTOR_REFUSED",error);}
    uint64_t now,boot;if(clock_values(&now,&boot)||now>=f->expires){int error=errno?errno:ETIMEDOUT;close(a);close(b);close(c);return operation_refuse("NATIVE_LEASE_EXPIRED_REFUSED",error);}
    memset(guard,0,sizeof(*guard));guard->retained_fd=a;guard->lease_fd=b;guard->recovery_fd=c;strcpy(guard->tunnel_name,f->owned.tunnel_name);guard->lease_milliseconds=(unsigned)(f->expires-now);
    guard->dependencies[0]=f->owned.controller;guard->dependencies[1]=f->owned.core;guard->dependencies[2]=f->owned.frontend;guard->dependency_count=3;
    guard->verify_resume=verify_resume;guard->verify_executed=verify_executed;guard->resume_context=f;
    memset(authority,0,sizeof(*authority));authority->verify_persistent_deny=persistent_deny;authority->verify_scope_quiescent=scope_absent;authority->context=f;return 0;
}
static int notion_stage(const struct envara_app_registration *app,const struct envara_gui_request *request,const struct envara_gui_stage_authority *authority,struct envara_gui_lifecycle *out,void *opaque) {
    struct envara_app_native_factory *f=opaque;struct envara_notion_context c={.front_port=f->config.tcp_front_port};strcpy(c.registration_id,f->plan.registration_id);
    if(envara_notion_data_prepare(app,request,&c,authority)){int error=errno;return operation_refuse("NATIVE_NOTION_DATA_PREPARE_REFUSED",error);}
    int result=envara_notion_stage(app,request,&c,authority,out),error=errno;
    if(out&&out->child.identity.pid>1){f->stage_child=out->child;f->staged=1;}
    return result?operation_refuse("NATIVE_NOTION_STAGE_REFUSED",error):0;
}
static int ticket_never_adopt(const struct envara_app_ticket *ticket,struct envara_gui_lifecycle *child,void *opaque) {
    (void)ticket;(void)child;(void)opaque;
    /* Preparation requires a complete authority, but child custody belongs
     * only to the supervisor's wrapped authority after its fresh checks. */
    return refuse(ENOTSUP);
}
static void provider_initialize(struct envara_app_native_factory *f) {
    f->provider.ticket.inspect=ticket_inspect;f->provider.ticket.verify=ticket_verify;
    f->provider.ticket.adopt=ticket_never_adopt;f->provider.ticket.context=f;
    f->provider.prepare_guard=prepare_guard;f->provider.context=f;f->provider.stage=notion_stage;f->provider.execution_profile=ENVARA_APP_EXECUTION_NOTION_FRONT_ONLY;
}
int envara_app_native_factory_open(const struct envara_app_native_owned_context *owned,envara_app_native_factory **out) {
    envara_app_native_failure_begin();
    if(!owned||!out)return refuse(EINVAL);*out=NULL;@autoreleasepool {
        struct envara_app_native_factory *f=allocate();if(!f)return -1;int error=EACCES;
#define OPEN_SYSCALL(reason,condition) do { if(condition){error=errno?errno:EIO;native_failure_reason=reason;goto failed;} } while(0)
#define OPEN_REQUIRE(reason,condition) do { if(!(condition)){error=EACCES;native_failure_reason=reason;goto failed;} } while(0)
        OPEN_SYSCALL("NATIVE_CONTEXT_LOAD_REFUSED",load(f,owned->run_id,owned->environment_id));f->owned=*owned;
        OPEN_REQUIRE("NATIVE_CONTROLLER_BINDING_REFUSED",!memcmp(&owned->controller,&f->plan.controller,sizeof(owned->controller)));
        OPEN_SYSCALL("NATIVE_ORIGINAL_SOCKET_REFUSED",fstat(owned->original_utun_fd,&f->utun_identity)||fstat(owned->original_listener_fd,&f->listener_identity));
        OPEN_REQUIRE("NATIVE_LISTENER_CREDENTIAL_REFUSED",f->listener_identity.st_uid==0&&f->listener_identity.st_gid==f->plan.realm_gid);
        struct stat one,two;
        OPEN_REQUIRE("NATIVE_PIPE_BINDING_REFUSED",pipe_reader(owned->lease_read_fd,&one)&&pipe_reader(owned->recovery_read_fd,&two)&&(one.st_dev!=two.st_dev||one.st_ino!=two.st_ino));
        f->lease_pipe_identity=one;f->recovery_pipe_identity=two;
        struct sockaddr_in address;socklen_t n=sizeof(address);
        OPEN_SYSCALL("NATIVE_ORIGINAL_SOCKET_REFUSED",getsockname(owned->original_listener_fd,(struct sockaddr *)&address,&n));
        OPEN_REQUIRE("NATIVE_ORIGINAL_SOCKET_REFUSED",n==sizeof(address));
        strcpy(f->config.run_id,f->plan.run_id);strcpy(f->config.realm_id,f->plan.realm_id);f->config.gid=f->plan.realm_gid;
        OPEN_REQUIRE("NATIVE_ORIGINAL_SOCKET_REFUSED",strnlen(owned->tunnel_name,16)<16);strcpy(f->config.utun,owned->tunnel_name);
        OPEN_REQUIRE("NATIVE_CONTEXT_LOAD_REFUSED",inet_pton(AF_INET,f->plan.ipv4,f->config.route_ipv4)==1);
        f->config.listener_fd=owned->original_listener_fd;f->config.tcp_front_port=ntohs(address.sin_port);
        struct envara_gui_session graphics;
        OPEN_SYSCALL("NATIVE_GUI_SESSION_REFUSED",envara_gui_session_read(&graphics));
        OPEN_REQUIRE("NATIVE_GUI_SESSION_REFUSED",graphics.console_uid==f->plan.console_uid&&graphics.audit_has_console_graphics&&graphics.security_has_graphics);
        f->request.gui_audit_session=graphics.audit_session;
        OPEN_REQUIRE("NATIVE_APP_IDENTITY_REFUSED",application_prepared(f));
        OPEN_REQUIRE("NATIVE_HOOK_LEASE_REFUSED",envara_pf_hook_filter_open(f->plan.run_id,f->hook_bytes,(unsigned long)f->hook_size,&f->hook));
        f->pf_fd=open("/dev/pf",O_RDWR|O_NOFOLLOW|O_CLOEXEC);
        OPEN_SYSCALL("NATIVE_PF_OPEN_REFUSED",f->pf_fd<0);
        OPEN_REQUIRE("NATIVE_PF_GUARD_REFUSED",basic(f,1));
        OPEN_REQUIRE("NATIVE_FILTER_READBACK_REFUSED",verify_mode(f,ENVARA_PF_PRODUCTION_EMPTY,1));
        /* A new factory never adopts an old or partial uncertain journal. */
        struct stat existing;int found=fstatat(f->run_fd,"app-filter-events",&existing,AT_SYMLINK_NOFOLLOW),lookup_error=errno;
        if(!found){error=EEXIST;native_failure_reason="NATIVE_JOURNAL_REFUSED";goto failed;}
        if(lookup_error!=ENOENT){error=lookup_error;native_failure_reason="NATIVE_JOURNAL_REFUSED";goto failed;}
        provider_initialize(f);*out=f;return 0;
failed:dispose(f);return refuse(error);
#undef OPEN_SYSCALL
#undef OPEN_REQUIRE
    }
}
const struct envara_app_supervisor_provider *envara_app_native_factory_provider(envara_app_native_factory *f){return f&&f->owner==getpid()&&!f->poisoned&&!f->cleanup_only?&f->provider:NULL;}
int envara_app_native_factory_admission(envara_app_native_factory *f,struct envara_app_native_admission *out) {
    if(!out)return refuse(EINVAL);memset(out,0,sizeof(*out));
    if(!f||f->cleanup_only||!verify_mode(f,ENVARA_PF_PRODUCTION_FRONT,1)||(!f->staged&&!scope_absent(f)))return refuse(EACCES);
    struct envara_identity keeper;if(envara_identity_read(getpid(),&keeper)||!envara_identity_matches(&keeper,0,0))return refuse(ESTALE);
    out->keeper=keeper;strcpy(out->run_id,f->plan.run_id);strcpy(out->environment_id,f->plan.environment_id);strcpy(out->lease_id,f->plan.lease_id);strcpy(out->generation,f->plan.generation);strcpy(out->lease_sha256,f->plan.lease_sha256);
    out->frontend=f->owned.frontend;out->front_port=f->config.tcp_front_port;out->gid=f->plan.realm_gid;out->filter_revision=f->receipt.ticket;out->writer_pid=f->receipt.writer_pid;out->expires_monotonic_ms=f->expires;out->boot_time_seconds=f->boot;return 0;
}
static int retirement_guard(void *opaque) {
    struct envara_app_native_factory *f=opaque;
    return cleanup_owned(f)&&basic(f,0)&&scope_absent(f)&&verify_mode(f,ENVARA_PF_PRODUCTION_EMPTY,0);
}
int envara_app_native_factory_release_safe(envara_app_native_factory *f) {
    if(!f||!cleanup_reconcile(f)||!scope_absent(f)||!basic(f,0))return 0;
    if(f->mode==ENVARA_PF_PRODUCTION_FRONT){EnvaraPFProductionResult r;if(envara_app_native_factory_apply(f,ENVARA_PF_PRODUCTION_DENY,&r))return 0;}
    if(f->mode==ENVARA_PF_PRODUCTION_DENY){EnvaraPFProductionResult r;if(envara_app_native_factory_apply(f,ENVARA_PF_PRODUCTION_EMPTY,&r))return 0;}
    if(!verify_mode(f,ENVARA_PF_PRODUCTION_EMPTY,0)||!scope_absent(f))return 0;
    if(f->journal_removed)return f->retirement.complete&&retirement_guard(f);
    if(f->journal_fd<0)return !f->journal_created;
    if(!f->journal_entries_trusted)return 0;
    if(!f->retirement.initialized){
        struct envara_journal_retirement_entry entries[32];memset(entries,0,sizeof(entries));
        for(size_t i=0;i<f->journal_count;i++)entries[i]=(struct envara_journal_retirement_entry){
            .name=f->journal_names[i],.fd=f->journal_file_fds[i],.identity=f->journal_files[i],
            .bytes=f->journal_file_bytes[i],.length=f->journal_file_sizes[i]};
        if(!envara_journal_retirement_init(&f->retirement,f->run_fd,f->journal_fd,"app-filter-events",&f->journal_identity,
            entries,f->journal_count,0,0,retirement_guard,f))return 0;
    }
    if(envara_journal_retirement_step(&f->retirement)!=1)return 0;
    f->journal_removed=1;return retirement_guard(f);
}
void envara_app_native_factory_close(envara_app_native_factory *f){dispose(f);}
