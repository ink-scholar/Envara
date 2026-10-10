/* Independent fixed socket-metadata revision; frozen f68/5990 untouched. */
/* Fixed recovery of the one failed f99 Notion experiment. This is a separate
 * source candidate, never an installed-runtime replacement. No INSERT, PFE,
 * pool reset, application launch, arbitrary PID/path/command or replay entry.
 * Mutation is reachable only from --cleanup-fixed-root after fresh evidence.
 * The original application's host baseline was not retained and stays false.
 * This tool is not authorized/deployed by its source or inert tests. */
#define INSPECTOR_INERT 1
#include "inspector-app-f99-run145.m"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/proc_info.h>

#define F99_RECOVERY_SCHEMA @"envara.macos-pf-live-application-recovery/v1"
#define F99_CAPSULE "io.envara.pf-recovery-f99-14514ea6"
#define F99_INTENT "recovery-f99.intent"
#define F99_CONTROLLER_PID 76008
#define F99_KEEPER_PID 76082
#define F99_CONTROLLER_BIRTH @"1791513842:631989"
#define F99_KEEPER_BIRTH @"1791513848:727886"
#define F99_CORE_BIRTH @"1791513850:540374"
#define F99_FRONT_BIRTH @"1791513851:467772"

typedef struct { int32_t rs_num; char anchor[1024]; uint32_t ticket; } F99Entry;
typedef struct { int32_t size, esize; F99Entry *array; } F99Transaction;
typedef struct {uint8_t bytes[1136];} F99PoolRead;
_Static_assert(sizeof(F99Entry)==1032&&offsetof(F99Entry,ticket)==1028,"one FILTER entry ABI");
_Static_assert(sizeof(F99Transaction)==16&&offsetof(F99Transaction,array)==8,"one FILTER transaction ABI");
#define F99_BEGIN _IOWR('D',81,F99Transaction)
#define F99_COMMIT _IOWR('D',82,F99Transaction)
#define F99_ROLLBACK _IOWR('D',83,F99Transaction)
#define F99_GET_ADDRS _IOWR('D',53,F99PoolRead)
_Static_assert(F99_BEGIN==0xc0104451UL&&F99_COMMIT==0xc0104452UL&&F99_ROLLBACK==0xc0104453UL,"fixed one FILTER ioctl ABI");
_Static_assert(F99_GET_ADDRS==0xc4704435UL,"readonly empty pool ABI");

typedef struct {struct proc_bsdinfo controller,keeper;struct stat listener;int listener_fd,utun_fd;uint32_t interface_index;} F99Custody;
typedef struct {int installed,parent,runtime,run,state,lock;struct stat registry_i,lease_i,lock_i,runtime_i,run_i,state_i;
 NSData *registry_bytes,*lease_bytes,*lock_bytes;NSDictionary *record,*lease,*transport,*journal;uint64_t gid;bool root_retired,clear_attempted,delete_attempted;F99Custody custody;} F99Context;

static NSMutableDictionary *f99Outcome(bool mutation){
 return [@{@"schema":F99_RECOVERY_SCHEMA,@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
 @"readOnly":@((BOOL)!mutation),@"ok":@NO,@"reason":@"FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED",@"gate":@"not-started",
 @"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"originalApplicationHostBaselineVerified":@NO,
 @"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"fullGuardFailureAccepted":@NO,
 @"ownedGIDScopeAbsent":@NO,@"ownedDenialVerified":@NO,@"originalDescriptorCustodyVerified":@NO,@"uniqueCurrentKeeperCustodyVerified":@NO,
 @"controllerStopped":@NO,@"keeperStopped":@NO,@"ownedFilterClearAttempted":@NO,@"ownedFilterEmptyVerified":@NO,
 @"keeperExitObserved":@NO,@"controllerExitObserved":@NO,@"ownedInterfaceAbsent":@NO,@"ownedListenerAbsent":@NO,
 @"ownedPFReferenceReleaseAttempted":@NO,@"ownedPFReferenceReleased":@NO,@"rootHookDeleteAttempted":@NO,
 @"rootHookRemoved":@NO,@"originalRootRestored":@NO,@"receiptRetired":@NO,@"namespaceReclaimed":@NO,
 @"ownedGroupDeleteAttempted":@NO,@"ownedGroupRemoved":@NO,@"runtimeArchived":@NO,@"recoveryScopeHostNetworkRestored":@NO,
 @"globalFlushExecuted":@NO,@"PFEnableExecuted":@NO,@"globalPoolResetExecuted":@NO,@"applicationLaunchExecuted":@NO}mutableCopy];
}
static int f99Emit(NSDictionary *out){return emitInspection(out);}
static bool f99NamedDirectory(int parent,const char*name,int held,struct stat*expected){
 struct stat actual,current;return secureFD(held,true,0700)&&!fstat(held,&current)&&!fstatat(parent,name,&actual,AT_SYMLINK_NOFOLLOW)&&
  current.st_dev==expected->st_dev&&current.st_ino==expected->st_ino&&actual.st_dev==current.st_dev&&actual.st_ino==current.st_ino;
}
static bool f99PrivateStable(F99Context*c){
 return unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)&&unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)&&
 unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)&&f99NamedDirectory(c->parent,"io.envara.pf-runtime",c->runtime,&c->runtime_i)&&
 f99NamedDirectory(c->runtime,CANARY_RUN.UTF8String,c->run,&c->run_i)&&f99NamedDirectory(c->run,[c->lease[@"realmId"]UTF8String],c->state,&c->state_i)&&
 [c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"])];
}
static bool f99BSDIdentity(pid_t pid,NSString*birth,const char*path,pid_t parent,struct proc_bsdinfo*out){
 struct proc_bsdinfo a={0},b={0};char executable[PROC_PIDPATHINFO_MAXSIZE]={0};
 if(proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&a,sizeof(a))!=sizeof(a)||a.pbi_pid!=(uint32_t)pid||a.pbi_ppid!=(uint32_t)parent||a.pbi_uid||a.pbi_ruid||a.pbi_svuid||
 a.pbi_gid||a.pbi_rgid||a.pbi_svgid||a.pbi_start_tvusec>=1000000||![[NSString stringWithFormat:@"%llu:%06llu",a.pbi_start_tvsec,a.pbi_start_tvusec]isEqual:birth]||
 proc_pidpath(pid,executable,sizeof(executable))<=0||strcmp(executable,path)||proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&b,sizeof(b))!=sizeof(b))return false;
 if(a.pbi_pid!=b.pbi_pid||a.pbi_ppid!=b.pbi_ppid||a.pbi_uid!=b.pbi_uid||a.pbi_ruid!=b.pbi_ruid||a.pbi_svuid!=b.pbi_svuid||a.pbi_gid!=b.pbi_gid||
 a.pbi_rgid!=b.pbi_rgid||a.pbi_svgid!=b.pbi_svgid||a.pbi_start_tvsec!=b.pbi_start_tvsec||a.pbi_start_tvusec!=b.pbi_start_tvusec)return false;
 if(out)*out=b;return true;
}
/* A snapshot comparison does not create a kernel PID handle. Immediately
 * repeat birth/parent/image/credentials at each fixed signal boundary. The
 * tool never signals a reused/unknown PID and never claims whole-guard proof. */
static bool f99Signal(F99Context*c,bool keeper,int signal){
 if(interrupted||seconds()+5>=rootDeadline||!f99PrivateStable(c)||envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;
 struct proc_bsdinfo p;pid_t pid=keeper?F99_KEEPER_PID:F99_CONTROLLER_PID;NSString*birth=keeper?F99_KEEPER_BIRTH:F99_CONTROLLER_BIRTH;
 if(!f99BSDIdentity(pid,birth,keeper?NATIVE:INSTALL "/node",keeper?F99_CONTROLLER_PID:76007,&p))return false;
 return kill(pid,signal)==0;
}
static bool f99WaitState(bool keeper,bool exited,double duration){
 double until=MIN(rootDeadline,seconds()+duration);pid_t pid=keeper?F99_KEEPER_PID:F99_CONTROLLER_PID;
 while(seconds()<until){struct proc_bsdinfo p={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&p,sizeof(p));
  if(exited&&n==0&&errno==ESRCH)return true;if(n!=sizeof(p))return false;
  NSString*birth=[NSString stringWithFormat:@"%llu:%06llu",p.pbi_start_tvsec,p.pbi_start_tvusec];
  if(![birth isEqual:keeper?F99_KEEPER_BIRTH:F99_CONTROLLER_BIRTH])return false;
  if(exited&&p.pbi_status==SZOMB)return true;
  if(!exited&&p.pbi_status==SSTOP)return true;struct timespec pause={0,10000000};nanosleep(&pause,NULL);
 }return false;
}
static bool f99FixedBindings(F99Context*c){
 NSDictionary*l=c->lease,*t=c->transport;if(![l[@"controllerPid"]isEqual:@F99_CONTROLLER_PID]||![l[@"controllerBirth"]isEqual:F99_CONTROLLER_BIRTH]||
 ![t[@"keeperPID"]isEqual:@F99_KEEPER_PID]||![t[@"keeperBirth"]isEqual:F99_KEEPER_BIRTH]||![t[@"corePID"]isEqual:@76086]||
 ![t[@"coreBirth"]isEqual:F99_CORE_BIRTH]||![t[@"frontPID"]isEqual:@76088]||![t[@"frontBirth"]isEqual:F99_FRONT_BIRTH]||c->gid!=7100)return false;
 NSDictionary*core=processObservation(@"core",t[@"corePID"],t[@"coreBirth"],INSTALL "/mihomo",F99_KEEPER_PID);
 NSDictionary*front=processObservation(@"front",t[@"frontPID"],t[@"frontBirth"],INSTALL "/node",F99_KEEPER_PID);
 return [core[@"state"]isEqual:@"absent"]&&[front[@"state"]isEqual:@"absent"]&&f99BSDIdentity(F99_CONTROLLER_PID,F99_CONTROLLER_BIRTH,INSTALL "/node",76007,&c->custody.controller)&&
 f99BSDIdentity(F99_KEEPER_PID,F99_KEEPER_BIRTH,NATIVE,F99_CONTROLLER_PID,&c->custody.keeper);
}
/* Actual descriptor metadata, not transport-started boolean assertions. A
 * unique AF_INET TCP LISTEN socket and unique utun control must still be held
 * by this exact keeper. Original FD inode seals are not persisted by f99;
 * this proves current unique custody, not historical original-FD uniqueness. */
typedef struct {uint32_t fd,kind,family,type,protocol,dev,uid,gid;uint64_t socket,pcb,inode;uint32_t tcp_state,local_address,foreign_address;uint16_t local_port,foreign_port;uint32_t ctl_id,ctl_unit;char ctl_name[MAX_KCTL_NAME];} F99SocketIdentity;
typedef struct {struct proc_fdinfo*list;F99SocketIdentity*sockets;int bytes,count,capacity;unsigned socket_count,listener_count,utun_count;int listener_fd,utun_fd;struct stat listener;} F99FDPass;
static bool f99FDBytes(int capacity,int buffer,int bytes){return capacity>0&&capacity<=65536&&capacity%(int)sizeof(struct proc_fdinfo)==0&&buffer>capacity&&bytes>0&&bytes<=capacity&&bytes<buffer&&bytes%(int)sizeof(struct proc_fdinfo)==0;}
static void f99FreeFDPass(F99FDPass*p){free(p->list);free(p->sockets);memset(p,0,sizeof(*p));}
/* PROC_PIDFDSOCKETINFO is not fstat. Pinned public Apple XNU f6217:
 * proc_info.c:2692-2702 zeros socket_fdinfo; socket_info.c:74-261 never
 * fills soi_stat. Its UID/GID/dev/inode therefore remain placeholders,
 * unlike sys_socket.c:382-395 fstat's actual so_cred. The current exact
 * f99/run145 root diagnostic 20261009T051555Z independently observed 0/0
 * in two complete stable passes. Public xnu-12377 source is not the live
 * host's xnu-13432 source attestation. This strict 0/0 placeholder check
 * proves no creator credential or historical original FD. Realm7100,
 * root-process credentials/birth, opaque socket/PCB, tuple, unit and all
 * existing cleanup gates remain separate and mandatory. */
static bool f99SocketInfoStatPlaceholder(uid_t uid,gid_t gid,gid_t expectedRealm){return expectedRealm==7100&&uid==0&&gid==0;}
static bool f99ReadFDPass(pid_t pid,F99Context*c,F99FDPass*out){
 memset(out,0,sizeof(*out));out->capacity=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
 if(out->capacity<=0||out->capacity>65536||out->capacity%(int)sizeof(struct proc_fdinfo))return false;
 /* NULL returns allocation capacity, not populated bytes. Extra slack makes
  * an exact-filled buffer distinguishable from a complete actual short list. */
 int buffer=out->capacity+32*(int)sizeof(struct proc_fdinfo);out->list=calloc(1,(size_t)buffer);if(!out->list)return false;
 out->bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,out->list,buffer);if(!f99FDBytes(out->capacity,buffer,out->bytes)){f99FreeFDPass(out);return false;}
 out->count=out->bytes/(int)sizeof(*out->list);out->sockets=calloc((size_t)out->count,sizeof(*out->sockets));if(!out->sockets){f99FreeFDPass(out);return false;}
 unsigned expectedUnit=0;if(c&&(sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&expectedUnit)!=1||expectedUnit==UINT_MAX)){f99FreeFDPass(out);return false;}
 for(int i=0;i<out->count;i++){
  if((i&&out->list[i].proc_fd<=out->list[i-1].proc_fd)||out->list[i].proc_fd<0){f99FreeFDPass(out);return false;}
  if(out->list[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;struct socket_fdinfo s={0};
  if(proc_pidfdinfo(pid,out->list[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s))!=sizeof(s)){f99FreeFDPass(out);return false;}
  F99SocketIdentity*w=&out->sockets[out->socket_count++];w->fd=out->list[i].proc_fd;w->kind=s.psi.soi_kind;w->family=s.psi.soi_family;w->type=s.psi.soi_type;w->protocol=s.psi.soi_protocol;
  w->socket=s.psi.soi_so;w->pcb=s.psi.soi_pcb;w->dev=s.psi.soi_stat.vst_dev;w->inode=s.psi.soi_stat.vst_ino;w->uid=s.psi.soi_stat.vst_uid;w->gid=s.psi.soi_stat.vst_gid;
  if(s.psi.soi_kind==SOCKINFO_TCP){struct in_sockinfo*in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;w->tcp_state=s.psi.soi_proto.pri_tcp.tcpsi_state;
   w->local_port=(uint16_t)in->insi_lport;w->foreign_port=(uint16_t)in->insi_fport;w->local_address=in->insi_laddr.ina_46.i46a_addr4.s_addr;w->foreign_address=in->insi_faddr.ina_46.i46a_addr4.s_addr;
   if(c&&s.psi.soi_family==AF_INET&&s.psi.soi_type==SOCK_STREAM&&w->tcp_state==TSI_S_LISTEN&&in->insi_lport==htons([c->transport[@"frontPort"]unsignedShortValue])&&w->local_address==htonl(INADDR_LOOPBACK)){
    if(!f99SocketInfoStatPlaceholder(w->uid,w->gid,(gid_t)c->gid)){f99FreeFDPass(out);return false;}out->listener_count++;out->listener_fd=out->list[i].proc_fd;out->listener.st_dev=(dev_t)w->dev;out->listener.st_ino=(ino_t)w->inode;
   }
  }
  if(s.psi.soi_family==AF_SYSTEM&&s.psi.soi_kind==SOCKINFO_KERN_CTL){struct kern_ctl_info*k=&s.psi.soi_proto.pri_kern_ctl;
   if(!memchr(k->kcsi_name,0,sizeof(k->kcsi_name))){f99FreeFDPass(out);return false;}w->ctl_id=k->kcsi_id;w->ctl_unit=k->kcsi_unit;memcpy(w->ctl_name,k->kcsi_name,sizeof(w->ctl_name));
   if(c&&!strcmp(k->kcsi_name,"com.apple.net.utun_control")&&k->kcsi_unit==expectedUnit+1){out->utun_count++;out->utun_fd=out->list[i].proc_fd;}
  }
 }return true;
}
static bool f99FDPassesSame(const F99FDPass*a,const F99FDPass*b){return a->count>0&&a->bytes==b->bytes&&a->socket_count==b->socket_count&&
 !memcmp(a->list,b->list,(size_t)a->bytes)&&!memcmp(a->sockets,b->sockets,a->socket_count*sizeof(*a->sockets))&&a->listener_count==b->listener_count&&a->utun_count==b->utun_count&&
 a->listener_fd==b->listener_fd&&a->utun_fd==b->utun_fd;}
static bool f99ObserveCustody(F99Context*c){
 if(!f99FixedBindings(c))return false;F99FDPass first={0},second={0};
 bool okay=f99ReadFDPass(F99_KEEPER_PID,c,&first)&&f99FixedBindings(c)&&f99ReadFDPass(F99_KEEPER_PID,c,&second)&&f99FDPassesSame(&first,&second)&&
 second.listener_count==1&&second.utun_count==1&&f99FixedBindings(c);unsigned idx=okay?if_nametoindex([c->transport[@"interfaceName"]UTF8String]):0;
 if(okay&&idx){c->custody.listener_fd=second.listener_fd;c->custody.utun_fd=second.utun_fd;c->custody.listener=second.listener;c->custody.interface_index=idx;}
 f99FreeFDPass(&first);f99FreeFDPass(&second);return okay&&idx;
}

static NSData *f99HashData(NSData*d){unsigned char digest[32];CC_SHA256(d.bytes,(CC_LONG)d.length,digest);return [NSData dataWithBytes:digest length:32];}
static NSString *f99HexData(NSData*d){NSData*h=f99HashData(d);char hex[65];for(NSUInteger i=0;i<h.length;i++)snprintf(hex+2*i,3,"%02x",((const unsigned char*)h.bytes)[i]);return @(hex);}
static bool f99HostPins(void){
 char os[128]={0},kernel[1024]={0};size_t a=sizeof(os),b=sizeof(kernel);
 if(sysctlbyname("kern.osrelease",os,&a,NULL,0)||sysctlbyname("kern.version",kernel,&b,NULL,0)||a>sizeof(os)||b>sizeof(kernel)||
 !memchr(os,0,sizeof(os))||!memchr(kernel,0,sizeof(kernel))||strcmp(os,"27.0.0")||!strstr(kernel,"xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020"))return false;
 const char*parents[]={"/sbin","/usr/libexec"},*leaves[]={"pfctl","pfd"};const char*hashes[]={"ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef","ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"};
 for(unsigned i=0;i<2;i++){int parent=directory(parents[i]);int fd=parent<0?-1:openat(parent,leaves[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);bool ok=secureFD(fd,false,0)&&hashFD(fd,hashes[i],rootDeadline);if(fd>=0)close(fd);if(parent>=0)close(parent);if(!ok)return false;}return true;
}
static bool f99Zero(const void*bytes,size_t n){const unsigned char*p=bytes;for(size_t i=0;i<n;i++)if(p[i])return false;return true;}
static bool f99OwnedHook(EnvaraPFHookRequest*q,NSDictionary*lease){
 uint64_t ticket=strtoull([lease[@"ticket"]UTF8String],NULL,10);EnvaraPFHookRule*r=&q->rule;
 return !q->anchor[0]&&strnlen(q->anchor_call,1024)<1024&&strnlen(r->owner,64)<64&&strnlen(r->label,64)<64&&
 !strcmp(q->anchor_call,CANARY_ANCHOR.UTF8String)&&!strcmp(r->owner,[lease[@"owner"]UTF8String])&&!strcmp(r->label,[lease[@"label"]UTF8String])&&r->ticket==ticket&&
 r->priority==UINT32_MAX&&r->nr==7&&!r->action&&!r->direction&&!r->quick&&!r->keep_state&&!r->af&&!r->proto&&!r->uid_op&&!r->gid_op&&
 f99Zero(r->uid,sizeof(r->uid))&&f99Zero(r->gid,sizeof(r->gid))&&f99Zero(r->ifname,sizeof(r->ifname))&&!r->ifnot&&!r->rule_flag&&!r->log&&!r->logif&&!r->match_tag_not&&!r->natpass&&
 !r->type&&!r->code&&!r->flags&&!r->flagset&&!r->min_ttl&&!r->allow_opts&&!r->rt&&!r->return_ttl&&!r->tos&&r->anchor_relative==1&&!r->anchor_wildcard&&!r->flush&&
 !r->proto_variant&&!r->extfilter&&!r->extmap&&!r->dnpipe&&!r->dntype&&f99Zero(r->src,64)&&f99Zero(r->dst,64);
}
static bool f99RootAttached(F99Context*c){
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;EnvaraPFHookRequest first={0},last={0},rows[8]={{0}};bool ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==8;
 for(uint32_t i=0;ok&&i<8;i++){rows[i].ticket=first.ticket;rows[i].nr=i;ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&rows[i])&&rows[i].rule.nr==i;}
 if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&first.nr==last.nr&&first.ticket==last.ticket&&f99OwnedHook(&rows[7],c->lease[@"rootHookLease"]);close(fd);if(!ok)return false;
 for(unsigned i=0;i<7;i++){rows[i].ticket=0;memset(rows[i].rule.skip,0,sizeof(rows[i].rule.skip));rows[i].rule.evaluations=0;memset(rows[i].rule.packets,0,sizeof(rows[i].rule.packets));memset(rows[i].rule.bytes,0,sizeof(rows[i].rule.bytes));}
 if(![f99HexData([NSData dataWithBytes:rows length:7*sizeof(*rows)])isEqual:ROOT_RULE])return false;
 char*argv[]={(char*)"/sbin/pfctl",(char*)"-sr",NULL};int code=-1;NSString*text=command(argv,false,&code);if(!text||code)return false;
 /* Like the native root-hook proof, text comparison covers the original
  * seven rows only. The eighth row's label formatting is not a semantic
  * witness; its complete typed kernel identity/predicates were checked above. */
 NSArray*lines=[text componentsSeparatedByString:@"\n"];if(lines.count<8)return false;
 NSString*firstSeven=[[[lines subarrayWithRange:NSMakeRange(0,7)]componentsJoinedByString:@"\n"]stringByAppendingString:@"\n"];
 return [hashText(firstSeven)isEqual:ROOT_TEXT];
}
/* Exact f99 mode DENY six-row constructor. It is copied narrowly from the
 * f99 manifest-pinned source 9ac5f645..., not the future FRONT profile. All
 * opaque readback bytes remain strict except the documented 40 counters. */
static EnvaraPFHookRule f99DenyRule(F99Context*c,uint32_t i){
 EnvaraPFHookRule r={0};const char*suffix=i<2?"loopback":i<4?"ipv6":"blocked";NSString*digest=hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,c->lease[@"realmId"]]);
 snprintf(r.label,64,"envara_prod_v1_%.24s_%s",digest.UTF8String,suffix);strcpy(r.owner,CANARY_ANCHOR.UTF8String);r.priority=UINT32_MAX;r.action=1;r.direction=2;r.quick=1;
 r.proto=(i%2)?17:6;r.af=i>=2&&i<4?30:0;if(i<2)strcpy(r.ifname,"lo0");r.gid[0]=r.gid[1]=(uint32_t)c->gid;r.gid_op=2;
 uint16_t high=htons(UINT16_MAX);memcpy(r.src+50,&high,2);r.src[52]=9;r.rule_flag=8;uint16_t icmp=0x0303,icmp6=0x0104;memcpy((uint8_t*)&r+964,&icmp,2);memcpy((uint8_t*)&r+966,&icmp6,2);
 r.nr=i;((uint8_t*)&r)[642]=r.af;uint32_t writer=F99_KEEPER_PID;memcpy((uint8_t*)&r+960,&writer,4);
 for(unsigned key=0;key<8;key++){uint32_t next=UINT32_MAX;for(uint32_t j=i+1;j<6;j++){
  EnvaraPFHookRule x={0};x.direction=2;x.proto=(j%2)?17:6;x.af=j>=2&&j<4?30:0;if(j<2)strcpy(x.ifname,"lo0");
  bool differs=key==0?strcmp(r.ifname,x.ifname)!=0:key==1?false:key==2?r.af!=x.af:key==3?r.proto!=x.proto:false;
  if(differs){next=j;break;}}
  memcpy(r.skip+key*8,&next,4);
 }return r;
}
static bool f99DenyVerified(F99Context*c){
 NSDictionary*receipt=c->journal[@"lastReceipt"];if(!boolValue(c->journal[@"present"],true)||!boolValue(c->journal[@"pendingIntent"],false)||![receipt[@"mode"]isEqual:@1]||
 ![receipt[@"writerPid"]isEqual:@F99_KEEPER_PID]||![receipt[@"ruleCount"]isEqual:@6]||!nonBoolInteger(receipt[@"revision"],1,UINT32_MAX))return false;
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;uint32_t ticket=[receipt[@"revision"]unsignedIntValue];bool ok=true;
 const uint8_t actions[]={0,2,4,6,8,11};for(unsigned a=0;ok&&a<6;a++){
  EnvaraPFHookRequest first={0},last={0};strcpy(first.anchor,CANARY_ANCHOR.UTF8String);first.rule.action=actions[a];last=first;
  ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==(a?0U:6U)&&(!a?first.ticket==ticket:true);
  for(uint32_t i=0;ok&&!a&&i<6;i++){EnvaraPFHookRequest got={0},wanted={0};strcpy(got.anchor,CANARY_ANCHOR.UTF8String);got.ticket=ticket;got.nr=i;wanted=got;wanted.rule=f99DenyRule(c,i);
   ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&got);memset((uint8_t*)&got.rule+648,0,40);if(ok)ok=!memcmp(&got,&wanted,sizeof(got));
   F99PoolRead pool={0},expected={0};memcpy(pool.bytes+4,&ticket,4);memcpy(pool.bytes+12,&i,4);pool.bytes[18]=AF_INET;strcpy((char*)pool.bytes+19,CANARY_ANCHOR.UTF8String);expected=pool;
   if(ok)ok=!ioctl(fd,F99_GET_ADDRS,&pool)&&!memcmp(&pool,&expected,sizeof(pool));}
  if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&last.nr==first.nr&&last.ticket==first.ticket;
 }close(fd);return ok&&f99RootAttached(c);
}
static bool f99OwnedTextEmpty(const char*kind){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)kind,NULL};NSString*text=command(argv,false,&code);return text&&code==0&&![text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool f99PortObservation(F99Context*c,bool listener);
static bool f99GroupInventory(gid_t gid,bool present);
static bool f99Load(F99Context*c,NSMutableDictionary*out){
 *c=(F99Context){.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};
 out[@"gate"]=@"fixed-host-abi-pins";if(!f99HostPins())return false;
 out[@"gate"]=@"installed-inventory";c->installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c->installed<0)return false;
 out[@"gate"]=@"fixed-private-context";c->parent=directory(INSTALL_PARENT);c->runtime=directory(RUNTIME);if(c->parent<0||!secureFD(c->runtime,true,0700)||fstat(c->runtime,&c->runtime_i))return false;
 c->registry_bytes=privateRead(c->runtime,"registry.json",65536,&c->registry_i);c->record=strictJSON(c->registry_bytes,65536);c->lock_bytes=privateRead(c->runtime,"registry.lock",4096,&c->lock_i);NSDictionary*lock=strictJSON(c->lock_bytes,4096);
 if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"pid"]isEqual:@F99_CONTROLLER_PID]||![lock[@"anchor"]isEqual:CANARY_ANCHOR])return false;
 c->run=openat(c->runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->run,true,0700)||fstat(c->run,&c->run_i))return false;
 c->lease_bytes=privateRead(c->run,"app-bound-lease.json",16384,&c->lease_i);c->lease=strictJSON(c->lease_bytes,16384);
 NSDictionary*transport=nil;if(!liveShape(c->record,c->lease,c->lease_bytes,&transport,&c->gid))return false;c->transport=transport;
 c->state=openat(c->run,[c->lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->state,true,0700)||fstat(c->state,&c->state_i)||!names(c->state,@[])||
 !names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events"])||!absent(c->run,F99_INTENT)||!absent(c->parent,F99_CAPSULE))return false;
 out[@"gate"]=@"current-process-and-custody";if(!f99ObserveCustody(c)||!f99PortObservation(c,true))return false;out[@"uniqueCurrentKeeperCustodyVerified"]=@YES;
 out[@"gate"]=@"complete-gid-absence";if(envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;out[@"ownedGIDScopeAbsent"]=@YES;
 out[@"gate"]=@"dedicated-group-identity";struct group*g=getgrgid((gid_t)c->gid);NSString*group=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c->gid];if(!g||g->gr_gid!=c->gid||strcmp(g->gr_name,group.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!f99GroupInventory((gid_t)c->gid,true))return false;
 out[@"gate"]=@"journal-and-native-denial";c->journal=readJournal(c->run,c->lease,c->transport[@"keeperPID"]);if(!c->journal||!f99DenyVerified(c)||!f99OwnedTextEmpty("Tables")||!f99OwnedTextEmpty("Anchors")||!f99PrivateStable(c))return false;
 out[@"ownedDenialVerified"]=@YES;return true;
}
static void f99Close(F99Context*c){int fds[]={c->lock,c->state,c->run,c->runtime,c->parent,c->installed};for(unsigned i=0;i<sizeof(fds)/sizeof(fds[0]);i++)if(fds[i]>=0)close(fds[i]);}

/* One transaction only, zero rules: no DIOCBEGINADDRS and no table/state/global
 * action. A commit attempt, failed/lost reply or rollback never permits retry.
 * All callers must already have stopped both exact writers and held custody. */
#ifdef F99_RECOVERY_INERT
/* Compile-only fault seams. They are absent from every production binary;
 * no command, environment, wire object or installed helper can select them. */
static bool(*f99_test_clear_guard)(F99Context*,unsigned);
static int(*f99_test_write_open)(void);
static int(*f99_test_transaction_ioctl)(int,unsigned long,void*);
static bool(*f99_test_empty_readback)(F99Context*);
#endif
static bool f99ClearGuard(F99Context*c,unsigned phase){
#ifdef F99_RECOVERY_INERT
 if(f99_test_clear_guard)return f99_test_clear_guard(c,phase);
#else
 (void)phase;
#endif
 return !interrupted&&seconds()+10<rootDeadline&&f99HostPins()&&f99WaitState(false,false,.2)&&f99WaitState(true,false,.2)&&f99PrivateStable(c)&&
  envara_app_scope_gid_absent((gid_t)c->gid)==1&&f99DenyVerified(c);
}
static int f99WriteDevice(void){
#ifdef F99_RECOVERY_INERT
 return f99_test_write_open?f99_test_write_open():-1;
#else
 int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat h,n;
 if(fstat(fd,&h)||lstat("/dev/pf",&n)||!S_ISCHR(h.st_mode)||h.st_uid||h.st_dev!=n.st_dev||h.st_ino!=n.st_ino||h.st_rdev!=n.st_rdev){close(fd);return -1;}return fd;
#endif
}
static int f99TransactionIoctl(int fd,unsigned long op,void*argument){
 if(op!=F99_BEGIN&&op!=F99_COMMIT&&op!=F99_ROLLBACK){errno=EINVAL;return -1;}
#ifdef F99_RECOVERY_INERT
 return f99_test_transaction_ioctl?f99_test_transaction_ioctl(fd,op,argument):-1;
#else
 return ioctl(fd,op,argument);
#endif
}
static bool f99EmptyReadback(F99Context*c){
#ifdef F99_RECOVERY_INERT
 if(f99_test_empty_readback)return f99_test_empty_readback(c);
#endif
 return pfEmpty()&&f99RootAttached(c);
}
static bool f99ClearOnce(F99Context*c,NSMutableDictionary*out){
 if(c->clear_attempted||!f99ClearGuard(c,0))return false;c->clear_attempted=true;
 int fd=f99WriteDevice();if(fd<0)return false;
 F99Entry e={0};e.rs_num=1;strcpy(e.anchor,CANARY_ANCHOR.UTF8String);F99Transaction t={1,sizeof(e),&e};out[@"ownedFilterClearAttempted"]=@YES;
 bool began=!f99TransactionIoctl(fd,F99_BEGIN,&t);uint32_t ticket=e.ticket;F99Entry expected={0};expected.rs_num=1;strcpy(expected.anchor,CANARY_ANCHOR.UTF8String);expected.ticket=ticket;
 bool known=began&&ticket&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));bool okay=known&&f99ClearGuard(c,1);
 if(okay)okay=!f99TransactionIoctl(fd,F99_COMMIT,&t)&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));
 /* Exact single rollback is permitted only before COMMIT was attempted.
  * This guard deliberately retains uncertain inactive state after commit. */
 else if(known){e=expected;t=(F99Transaction){1,sizeof(e),&e};(void)f99TransactionIoctl(fd,F99_ROLLBACK,&t);}
 close(fd);return okay&&f99EmptyReadback(c);
}
static bool f99InterfaceAbsent(F99Context*c){errno=0;unsigned idx=if_nametoindex([c->transport[@"interfaceName"]UTF8String]);return idx==0&&(errno==ENXIO||errno==ENODEV||errno==0);}
static bool f99NumericIPv4Endpoint(NSString*text){
 if(![text isKindOfClass:NSString.class]||text.length>32)return false;NSRange dot=[text rangeOfString:@"."options:NSBackwardsSearch];if(dot.location==NSNotFound)return false;
 NSString*address=[text substringToIndex:dot.location],*service=[text substringFromIndex:dot.location+1];
 if(![service isEqual:@"*"]){if(!regex(service,@"^(0|[1-9][0-9]{0,4})$")||service.longLongValue>UINT16_MAX)return false;}
 struct in_addr ip;return [address isEqual:@"*"]||inet_pton(AF_INET,address.UTF8String,&ip)==1;
}
static bool f99PortRows(NSString*text,uint16_t port,bool expectListener){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return false;
 bool header=false;unsigned matches=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  if([line hasPrefix:@"Active Internet connections"])continue;
  if(regex(line,@"^Proto[ \\t]+Recv-Q[ \\t]+Send-Q[ \\t]+Local Address[ \\t]+Foreign Address[ \\t]+[(]state[)]([ \\t].*)?$")){if(header)return false;header=true;continue;}
  if(!header)return false;NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count<6||f.count>32||![@[@"tcp4",@"tcp46"]containsObject:f[0]]||!regex(f[1],@"^[0-9]+$")||!regex(f[2],@"^[0-9]+$")||
   !f99NumericIPv4Endpoint(f[3])||!f99NumericIPv4Endpoint(f[4])||
   ![@[@"CLOSED",@"LISTEN",@"SYN_SENT",@"SYN_RECEIVED",@"SYN_RCVD",@"ESTABLISHED",@"CLOSE_WAIT",@"FIN_WAIT_1",@"CLOSING",@"LAST_ACK",@"FIN_WAIT_2",@"TIME_WAIT"]containsObject:f[5]])return false;
  NSString*suffix=[NSString stringWithFormat:@".%u",port];if([f[5]isEqual:@"LISTEN"]&&([f[3]isEqual:[@"127.0.0.1"stringByAppendingString:suffix]]||[f[3]isEqual:[@"*"stringByAppendingString:suffix]]))matches++;
 }
 return header&&matches==(expectListener?1U:0U);
}
static bool f99PortObservation(F99Context*c,bool listener){
 /* Numeric kernel TCP inventory only, no bind/connect or unrelated process FD
  * inspection. Two bounded reads must agree on this exact IPv4 front port. */
 char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-an",(char*)"-p",(char*)"tcp",(char*)"-f",(char*)"inet",NULL};int code=-1;
 NSString*one=command(argv,false,&code);if(!one||code||!f99PortRows(one,[c->transport[@"frontPort"]unsignedShortValue],listener))return false;
 NSString*two=command(argv,false,&code);return two&&!code&&f99PortRows(two,[c->transport[@"frontPort"]unsignedShortValue],listener);
}
static bool f99NamespaceEmpty(F99Context*c){
 if(!c->root_retired)return pfEmpty();int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
 const uint8_t actions[]={0,2,4,6,8,11};bool absentAll=true;
 for(unsigned i=0;i<6;i++){EnvaraPFHookRequest q={0};strcpy(q.anchor,CANARY_ANCHOR.UTF8String);q.rule.action=actions[i];errno=0;if(ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&q)!=-1||errno!=EINVAL){absentAll=false;break;}}
 close(fd);return absentAll;
}
static bool f99WritePrivate(int parent,const char*name,NSData*bytes,struct stat*identity){
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);bool ok=secureFD(fd,false,0600)&&bytes.length>0&&bytes.length<=65536&&write(fd,bytes.bytes,bytes.length)==(ssize_t)bytes.length&&!fsync(fd)&&!fsync(parent);if(fd>=0)close(fd);
 return ok&&[privateRead(parent,name,65536,identity)isEqual:bytes];
}
static NSDictionary *f99HostWithoutOwnedRoute(F99Context*c){
 NSDictionary*base=hostSnapshot();if(!base)return nil;char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-rn",NULL};int code=-1;NSString*routes=normalizedRoutes(command(argv,false,&code));if(!routes||code)return nil;
 NSMutableArray*keep=[NSMutableArray array];for(NSString*row in [routes componentsSeparatedByString:@"\n"]){NSArray*p=[row componentsSeparatedByString:@"|"];if(p.count!=5)return nil;
  if([p[4]isEqual:c->transport[@"interfaceName"]])continue;[keep addObject:row];}
 NSMutableDictionary*out=[base mutableCopy];out[@"routes"]=hashText([keep componentsJoinedByString:@"\n"]);return out;
}
static bool f99StatesEmpty(void){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-ss",NULL};NSString*s=command(argv,false,&code);return s&&code==0&&![s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool f99RootProof(NSDictionary*p){return p&&boolValue(p[@"ok"],true)&&boolValue(p[@"pinsVerified"],true)&&boolValue(p[@"originalRootCompatible"],true)&&boolValue(p[@"priorAnchorsCompatible"],true)&&[p[@"originalRootSHA256"]isEqual:ROOT_RULE]&&[p[@"originalRootTextSHA256"]isEqual:ROOT_TEXT];}
static NSDictionary *f99RootRequest(F99Context*c,bool delete){
 if(delete){if(c->delete_attempted)return nil;c->delete_attempted=true;}
 if(!validLease(c->lease[@"rootHookLease"])||seconds()+20>=rootDeadline)return nil;
 int held=relativeFile(c->installed,"envara-pf-native");struct stat h,n;bool stable=secureFD(held,false,0755)&&!fstat(held,&h)&&!lstat(NATIVE,&n)&&sameStat(&h,&n);if(held>=0)close(held);if(!stable)return nil;
 NSData*input=[NSJSONSerialization dataWithJSONObject:@{@"lease":c->lease[@"rootHookLease"]} options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!input||input.length>4094)return nil;
 char*argv[]={NATIVE,delete?(char*)"delete-owned-root-hook":(char*)"hook-status",NULL};int code=-1;NSData*d=fixedProcess(NATIVE,argv,input,&code,delete);if(!d)return nil;
 if(!delete)return nativeProof(d,0,false,code);
 /* The DELETE output is never treated as cleanup proof. Only its exact known
  * envelope may be retained internally; a separate readonly STATUS supplies
  * all final facts, even when this one-shot reply is lost/refused. */
 NSDictionary*p=strictJSON(d,OUTPUT_LIMIT);if(!keys(p,proofKeys())||![p[@"schema"]isEqual:NATIVE_SCHEMA]||![p[@"operation"]isEqual:@"delete-owned-root-hook"]||
 !boolValue(p[@"readOnly"],false)||![nativeReasons()containsObject:p[@"reason"]]||(![p[@"anchor"]isEqual:CANARY_ANCHOR]&&![p[@"anchor"]isEqual:@""]))return nil;return p;
}
static NSString *f99GroupRows(NSString*text,gid_t gid,bool present){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return nil;NSMutableSet*seen=[NSMutableSet set];NSMutableArray*normalized=[NSMutableArray array];NSString*owned=[NSString stringWithFormat:@"_envara_pf_%u",gid];unsigned ownedRows=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count!=2||!regex(f[0],@"^[A-Za-z0-9_.-]{1,255}$")||!regex(f[1],@"^(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})$")||[seen containsObject:f[0]])return nil;
  errno=0;long long value=strtoll([f[1]UTF8String],NULL,10);if(errno||value<INT32_MIN||value>UINT32_MAX)return nil;if([f[0]isEqual:owned]||(uint32_t)value==gid){if(!present||![f[0]isEqual:owned]||(uint32_t)value!=gid)return nil;ownedRows++;}
  [seen addObject:f[0]];[normalized addObject:[NSString stringWithFormat:@"%@|%u",f[0],(uint32_t)value]];
 }return normalized.count&&ownedRows==(present?1U:0U)?[[normalized sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]:nil;
}
static NSString *f99NegativeGroups(NSString*text,gid_t gid){return f99GroupRows(text,gid,false);}
static bool f99GroupInventory(gid_t gid,bool present){char*argv[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-list",(char*)"/Groups",(char*)"PrimaryGroupID",NULL};int code=-1;
 NSString*one=f99GroupRows(command(argv,false,&code),gid,present);if(!one||code)return false;NSString*two=f99GroupRows(command(argv,false,&code),gid,present);return !code&&two&&[one isEqual:two];}
static bool f99GroupAbsent(gid_t gid){return f99GroupInventory(gid,false);}
static bool f99AfterCustodianScope(F99Context*c){
 return !interrupted&&seconds()+5<rootDeadline&&f99WaitState(true,true,.1)&&f99WaitState(false,true,.1)&&envara_app_scope_gid_absent((gid_t)c->gid)==1&&f99InterfaceAbsent(c)&&f99PortObservation(c,false)&&f99NamespaceEmpty(c)&&f99StatesEmpty();
}
static bool f99Archive(F99Context*c,int cap,struct stat*capi,struct stat*beforei,NSData*beforeBytes,struct stat*intenti,NSData*intentBytes,NSMutableDictionary*out){
 if(seconds()+10>=rootDeadline||!f99AfterCustodianScope(c)||!f99GroupAbsent((gid_t)c->gid)||!f99PrivateStable(c)||!unchanged(c->run,F99_INTENT,intenti,intentBytes)||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!names(cap,@[@"recovery-before.json"])||!names(c->state,@[])||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@F99_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN]))return false;
 /* This durable pre-rename receipt cannot claim the rename already occurred.
  * Public success is emitted only after held-identity postflight completes. */
 NSMutableDictionary*archiveReceipt=[out mutableCopy];archiveReceipt[@"gate"]=@"durable-pre-archive-proof";NSData*bytes=[NSJSONSerialization dataWithJSONObject:archiveReceipt options:NSJSONWritingWithoutEscapingSlashes error:NULL];struct stat ri;
 if(!f99WritePrivate(cap,"recovery-proof.json",bytes,&ri))return false;struct stat named,parentBefore;if(fstat(c->parent,&parentBefore)||fstatat(c->parent,F99_CAPSULE,&named,AT_SYMLINK_NOFOLLOW)||named.st_dev!=capi->st_dev||named.st_ino!=capi->st_ino||
 !f99PrivateStable(c)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(c->run,F99_INTENT,intenti,intentBytes)||!secureFD(c->parent,true,0)||!secureFD(cap,true,0700)||
 !names(cap,@[@"recovery-before.json",@"recovery-proof.json"])||!f99AfterCustodianScope(c)||!f99GroupAbsent((gid_t)c->gid)||interrupted)return false;
 if(renameatx_np(c->parent,"io.envara.pf-runtime",cap,"runtime",RENAME_EXCL)||fsync(cap)||fsync(c->parent))return false;
 struct stat parentAfter,archived;if(!absent(c->parent,"io.envara.pf-runtime")||fstat(c->parent,&parentAfter)||parentAfter.st_dev!=parentBefore.st_dev||parentAfter.st_ino!=parentBefore.st_ino||
 fstatat(cap,"runtime",&archived,AT_SYMLINK_NOFOLLOW)||archived.st_dev!=c->runtime_i.st_dev||archived.st_ino!=c->runtime_i.st_ino||
 !unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)||!unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)||!unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)||
 !unchanged(c->run,F99_INTENT,intenti,intentBytes)||![c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"]) ]||!names(c->state,@[])||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@F99_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!names(cap,@[@"runtime",@"recovery-before.json",@"recovery-proof.json"]))return false;
 return true;
}
static int f99Recover(bool mutation){
 NSMutableDictionary*out=f99Outcome(mutation);rootDeadline=seconds()+175;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary())return f99Emit(out);umask(077);struct sigaction sa={0};sa.sa_handler=onSignal;if(sigemptyset(&sa.sa_mask))return f99Emit(out);int sigs[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};for(unsigned i=0;i<4;i++)if(sigaction(sigs[i],&sa,NULL))return f99Emit(out);
 F99Context c={.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};int cap=-1;struct stat capi,beforei,intenti;NSData*beforeBytes=nil,*intentBytes=nil;NSDictionary*hostBefore=nil;bool loaded=false;
 do{if(!f99Load(&c,out))break;loaded=true;out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_LIVE_RECOVERY_PREFLIGHT_VERIFIED";out[@"gate"]=@"preflight-complete";if(!mutation)break;
  out[@"ok"]=@NO;out[@"reason"]=@"FIXED_LIVE_RECOVERY_UNCONFIRMED";out[@"gate"]=@"durable-scope-and-single-use-intent";
  if(seconds()+100>=rootDeadline||!f99PrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!f99DenyVerified(&c)||!f99StatesEmpty())break;
  hostBefore=f99HostWithoutOwnedRoute(&c);if(!hostBefore||mkdirat(c.parent,F99_CAPSULE,0700))break;cap=openat(c.parent,F99_CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(cap,true,0700)||fstat(cap,&capi)||!names(cap,@[]))break;
  NSDictionary*b=@{@"schema":@"envara.macos-pf-live-recovery-baseline/v1",@"scope":@"fixed-f99-run145-recovery-only",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,
   @"originalApplicationHostBaselineVerified":@NO,@"hostExcludingOnlyRecordedUTunRoutes":hostBefore,@"registrySHA256":f99HexData(c.registry_bytes),@"leaseSHA256":f99HexData(c.lease_bytes),@"lockSHA256":f99HexData(c.lock_bytes),@"journalObservation":c.journal};
  beforeBytes=[NSJSONSerialization dataWithJSONObject:b options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!f99WritePrivate(cap,"recovery-before.json",beforeBytes,&beforei)||fsync(c.parent))break;
  intentBytes=[NSJSONSerialization dataWithJSONObject:@{@"schema":@"envara.macos-pf-live-recovery-intent/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"scope":@"one-empty-filter-one-pf-token-one-issued-delete-no-retry"} options:NSJSONWritingWithoutEscapingSlashes error:NULL];
  if(!f99WritePrivate(c.run,F99_INTENT,intentBytes,&intenti))break;
  out[@"gate"]=@"stop-exact-controllers-preserving-custody";if(!f99Signal(&c,false,SIGSTOP)||!f99WaitState(false,false,2))break;out[@"controllerStopped"]=@YES;
  if(!f99Signal(&c,true,SIGSTOP)||!f99WaitState(true,false,2))break;out[@"keeperStopped"]=@YES;
  if(!f99ObserveCustody(&c)||!f99PrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1)break;
  out[@"gate"]=@"single-owned-empty-filter";if(!f99ClearOnce(&c,out))break;out[@"ownedFilterEmptyVerified"]=@YES;
  out[@"gate"]=@"close-exact-owned-custodians-after-empty";
  if(!pfEmpty()||!f99RootAttached(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!f99Signal(&c,true,SIGKILL)||!f99WaitState(true,true,5))break;out[@"keeperExitObserved"]=@YES;
  if(!pfEmpty()||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!f99Signal(&c,false,SIGKILL)||!f99WaitState(false,true,5))break;out[@"controllerExitObserved"]=@YES;
  if(!f99InterfaceAbsent(&c)||!f99PortObservation(&c,false)||!pfEmpty())break;out[@"ownedInterfaceAbsent"]=@YES;out[@"ownedListenerAbsent"]=@YES;
  out[@"gate"]=@"exclusive-registry-after-custodian-exit";if(flock(c.parent,LOCK_EX|LOCK_NB))break;c.lock=openat(c.runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  if(!secureFD(c.lock,false,0600)||flock(c.lock,LOCK_EX|LOCK_NB)||!f99PrivateStable(&c)||!f99AfterCustodianScope(&c))break;
  out[@"gate"]=@"exact-issued-native-retirement-proof";NSDictionary*proof=f99RootRequest(&c,false);
  if(!f99RootProof(proof)||!boolValue(proof[@"hookInstalled"],true)||!boolValue(proof[@"ownedRootHookVerified"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!pfEmpty())break;
  out[@"gate"]=@"release-only-recorded-pf-reference";out[@"ownedPFReferenceReleaseAttempted"]=@YES;int code=-1;char*release[]={(char*)"/sbin/pfctl",(char*)"-X",(char*)[c.record[@"ownedPFReference"][@"token"]UTF8String],NULL};
  if(!f99AfterCustodianScope(&c)||!command(release,true,&code)||code)break;out[@"ownedPFReferenceReleased"]=@YES;
  proof=f99RootRequest(&c,false);if(!f99RootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!f99AfterCustodianScope(&c))break;
  out[@"gate"]=@"one-exact-issued-root-hook-delete";out[@"rootHookDeleteAttempted"]=@YES;(void)f99RootRequest(&c,true);proof=f99RootRequest(&c,false);
  if(!f99RootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||!boolValue(proof[@"ownedRootHookRemoved"],true)||!boolValue(proof[@"originalRootRestored"],true)||!boolValue(proof[@"receiptRetired"],true)||
   !boolValue(proof[@"namespaceReclaimed"],true)||![proof[@"namespaceState"]isEqual:@"absent"]||![proof[@"runLedgerState"]isEqual:@"retired"])break;c.root_retired=true;if(!f99AfterCustodianScope(&c))break;
  out[@"rootHookRemoved"]=out[@"originalRootRestored"]=out[@"receiptRetired"]=out[@"namespaceReclaimed"]=@YES;
  out[@"gate"]=@"one-dedicated-group-removal";struct group*g=getgrgid((gid_t)c.gid);NSString*name=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c.gid];
  if(!g||g->gr_gid!=c.gid||strcmp(g->gr_name,name.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!f99GroupInventory((gid_t)c.gid,true)||!f99AfterCustodianScope(&c))break;
  NSString*path=[@"/Groups/"stringByAppendingString:name];char*deleteGroup[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-delete",(char*)path.UTF8String,NULL};out[@"ownedGroupDeleteAttempted"]=@YES;
  if(!command(deleteGroup,true,&code)||code||!f99GroupAbsent((gid_t)c.gid))break;out[@"ownedGroupRemoved"]=@YES;
  out[@"gate"]=@"recovery-scope-host-network-postflight";NSDictionary*after=f99HostWithoutOwnedRoute(&c);if(!after||![after isEqual:hostBefore]||!f99AfterCustodianScope(&c))break;out[@"recoveryScopeHostNetworkRestored"]=@YES;
  out[@"gate"]=@"held-inode-atomic-private-runtime-archive";if(!f99Archive(&c,cap,&capi,&beforei,beforeBytes,&intenti,intentBytes,out))break;
  out[@"runtimeArchived"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"cleanupConfirmed"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"FIXED_LIVE_RECOVERY_COMPLETED";out[@"gate"]=@"recovery-complete";
 }while(0);
 if(loaded)f99Close(&c);else if(c.installed>=0)f99Close(&c);if(cap>=0)close(cap);return f99Emit(out);
}
#ifndef F99_RECOVERY_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return f99Emit(f99Outcome(false));const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=f99Outcome(false);out[@"ok"]=@YES;out[@"reason"]=@"INERT_FIXED_LIVE_RECOVERY_PLAN";out[@"mutationEntryLinked"]=@YES;out[@"nativeStatusRequiredAfterCustodianExit"]=@YES;return f99Emit(out);}
 if(!strcmp(mode,"--inspect-fixed-root"))return f99Recover(false);
 if(!strcmp(mode,"--cleanup-fixed-root"))return f99Recover(true);
 return f99Emit(f99Outcome(false));
}}
#endif
