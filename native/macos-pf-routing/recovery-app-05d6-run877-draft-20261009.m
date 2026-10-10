/* INCOMPLETE fixed 05d6/run877 recovery draft, 2026-10-09.
 * Reuses the successfully exercised run145 single FILTER retirement shape.
 * This source is deliberately impossible to build as a privileged executable.
 * Fresh actual run877 readonly evidence and a separately reviewed child
 * lifecycle branch are required before freezing a final uniquely named file.
 * Never remove this guard or substitute guessed process births/GID merely
 * to compile. Inert predicate fixtures may define R877_RECOVERY_INERT only.
 */
#ifndef R877_RECOVERY_INERT
#error RUN877_RECOVERY_DRAFT_REQUIRES_ACTUAL_READONLY_FACTS_AND_CHILD_SCOPE_REVIEW
#endif
/* Fixed recovery of the one failed 05d6/run877 Notion experiment. This is a separate
 * source candidate, never an installed-runtime replacement. No INSERT, PFE,
 * pool reset, application launch, arbitrary PID/path/command or replay entry.
 * Mutation is reachable only from --cleanup-fixed-root after fresh evidence.
 * The original application's host baseline was not retained and stays false.
 * This tool is not authorized/deployed by its source or inert tests. */
#define INSPECTOR_INERT 1
#include "inspector-app-05d6-run877.m"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/proc_info.h>

#define R877_RECOVERY_SCHEMA @"envara.macos-pf-live-application-recovery/v1"
#define R877_CAPSULE "io.envara.pf-recovery-05d6-877ab9cc"
#define R877_INTENT "recovery-05d6-run877.intent"
#define R877_CONTROLLER_PID 15418
#define R877_KEEPER_PID 15492
#define R877_CONTROLLER_BIRTH @"RO_REQUIRED_CONTROLLER_BIRTH"
#define R877_KEEPER_BIRTH @"RO_REQUIRED_KEEPER_BIRTH"
#define R877_CORE_BIRTH @"RO_REQUIRED_CORE_BIRTH"
#define R877_FRONT_BIRTH @"RO_REQUIRED_FRONT_BIRTH"
#define R877_FIXED_GID 0 /* RO_REQUIRED_EXACT_GID; zero never passes liveShape. */

typedef struct { int32_t rs_num; char anchor[1024]; uint32_t ticket; } R877Entry;
typedef struct { int32_t size, esize; R877Entry *array; } R877Transaction;
typedef struct {uint8_t bytes[1136];} R877PoolRead;
_Static_assert(sizeof(R877Entry)==1032&&offsetof(R877Entry,ticket)==1028,"one FILTER entry ABI");
_Static_assert(sizeof(R877Transaction)==16&&offsetof(R877Transaction,array)==8,"one FILTER transaction ABI");
#define R877_BEGIN _IOWR('D',81,R877Transaction)
#define R877_COMMIT _IOWR('D',82,R877Transaction)
#define R877_ROLLBACK _IOWR('D',83,R877Transaction)
#define R877_GET_ADDRS _IOWR('D',53,R877PoolRead)
_Static_assert(R877_BEGIN==0xc0104451UL&&R877_COMMIT==0xc0104452UL&&R877_ROLLBACK==0xc0104453UL,"fixed one FILTER ioctl ABI");
_Static_assert(R877_GET_ADDRS==0xc4704435UL,"readonly empty pool ABI");

typedef struct {struct proc_bsdinfo controller,keeper;struct stat listener;int listener_fd,utun_fd;uint32_t interface_index;} R877Custody;
typedef struct {int installed,parent,runtime,run,state,lock;struct stat registry_i,lease_i,lock_i,runtime_i,run_i,state_i;
 NSData *registry_bytes,*lease_bytes,*lock_bytes;NSDictionary *record,*lease,*transport,*journal;uint64_t gid;bool root_retired,clear_attempted,delete_attempted;R877Custody custody;} R877Context;

static NSMutableDictionary *r877Outcome(bool mutation){
 return [@{@"schema":R877_RECOVERY_SCHEMA,@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
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
static int r877Emit(NSDictionary *out){return emitInspection(out);}
static bool r877NamedDirectory(int parent,const char*name,int held,struct stat*expected){
 struct stat actual,current;return secureFD(held,true,0700)&&!fstat(held,&current)&&!fstatat(parent,name,&actual,AT_SYMLINK_NOFOLLOW)&&
  current.st_dev==expected->st_dev&&current.st_ino==expected->st_ino&&actual.st_dev==current.st_dev&&actual.st_ino==current.st_ino;
}
static bool r877PrivateStable(R877Context*c){
 return unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)&&unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)&&
 unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)&&r877NamedDirectory(c->parent,"io.envara.pf-runtime",c->runtime,&c->runtime_i)&&
 r877NamedDirectory(c->runtime,CANARY_RUN.UTF8String,c->run,&c->run_i)&&r877NamedDirectory(c->run,[c->lease[@"realmId"]UTF8String],c->state,&c->state_i)&&
 [c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"])];
}
static bool r877BSDIdentity(pid_t pid,NSString*birth,const char*path,pid_t parent,struct proc_bsdinfo*out){
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
static bool r877Signal(R877Context*c,bool keeper,int signal){
 if(interrupted||seconds()+5>=rootDeadline||!r877PrivateStable(c)||envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;
 struct proc_bsdinfo p;pid_t pid=keeper?R877_KEEPER_PID:R877_CONTROLLER_PID;NSString*birth=keeper?R877_KEEPER_BIRTH:R877_CONTROLLER_BIRTH;
 if(!r877BSDIdentity(pid,birth,keeper?NATIVE:INSTALL "/node",keeper?R877_CONTROLLER_PID:15417,&p))return false;
 return kill(pid,signal)==0;
}
static bool r877WaitState(bool keeper,bool exited,double duration){
 double until=MIN(rootDeadline,seconds()+duration);pid_t pid=keeper?R877_KEEPER_PID:R877_CONTROLLER_PID;
 while(seconds()<until){struct proc_bsdinfo p={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&p,sizeof(p));
  if(exited&&n==0&&errno==ESRCH)return true;if(n!=sizeof(p))return false;
  NSString*birth=[NSString stringWithFormat:@"%llu:%06llu",p.pbi_start_tvsec,p.pbi_start_tvusec];
  if(![birth isEqual:keeper?R877_KEEPER_BIRTH:R877_CONTROLLER_BIRTH])return false;
  if(exited&&p.pbi_status==SZOMB)return true;
  if(!exited&&p.pbi_status==SSTOP)return true;struct timespec pause={0,10000000};nanosleep(&pause,NULL);
 }return false;
}
static bool r877FixedBindings(R877Context*c){
 NSDictionary*l=c->lease,*t=c->transport;if(![l[@"controllerPid"]isEqual:@R877_CONTROLLER_PID]||![l[@"controllerBirth"]isEqual:R877_CONTROLLER_BIRTH]||
 ![t[@"keeperPID"]isEqual:@R877_KEEPER_PID]||![t[@"keeperBirth"]isEqual:R877_KEEPER_BIRTH]||![t[@"corePID"]isEqual:@15525]||
 ![t[@"coreBirth"]isEqual:R877_CORE_BIRTH]||![t[@"frontPID"]isEqual:@15545]||![t[@"frontBirth"]isEqual:R877_FRONT_BIRTH]||c->gid!=R877_FIXED_GID)return false;
 NSDictionary*core=processObservation(@"core",t[@"corePID"],t[@"coreBirth"],INSTALL "/mihomo",R877_KEEPER_PID);
 NSDictionary*front=processObservation(@"front",t[@"frontPID"],t[@"frontBirth"],INSTALL "/node",R877_KEEPER_PID);
 return [core[@"state"]isEqual:@"absent"]&&[front[@"state"]isEqual:@"absent"]&&r877BSDIdentity(R877_CONTROLLER_PID,R877_CONTROLLER_BIRTH,INSTALL "/node",15417,&c->custody.controller)&&
 r877BSDIdentity(R877_KEEPER_PID,R877_KEEPER_BIRTH,NATIVE,R877_CONTROLLER_PID,&c->custody.keeper);
}
/* Actual descriptor metadata, not transport-started boolean assertions. A
 * unique AF_INET TCP LISTEN socket and unique utun control must still be held
 * by this exact keeper. Original FD inode seals are not persisted by r877;
 * this proves current unique custody, not historical original-FD uniqueness. */
typedef struct {uint32_t fd,kind,family,type,protocol,dev,uid,gid;uint64_t socket,pcb,inode;uint32_t tcp_state,local_address,foreign_address;uint16_t local_port,foreign_port;uint32_t ctl_id,ctl_unit;char ctl_name[MAX_KCTL_NAME];} R877SocketIdentity;
typedef struct {struct proc_fdinfo*list;R877SocketIdentity*sockets;int bytes,count,capacity;unsigned socket_count,listener_count,utun_count;int listener_fd,utun_fd;struct stat listener;} R877FDPass;
static bool r877FDBytes(int capacity,int buffer,int bytes){return capacity>0&&capacity<=65536&&capacity%(int)sizeof(struct proc_fdinfo)==0&&buffer>capacity&&bytes>0&&bytes<=capacity&&bytes<buffer&&bytes%(int)sizeof(struct proc_fdinfo)==0;}
static void r877FreeFDPass(R877FDPass*p){free(p->list);free(p->sockets);memset(p,0,sizeof(*p));}
/* PROC_PIDFDSOCKETINFO is not fstat. Pinned public Apple XNU f6217:
 * proc_info.c:2692-2702 zeros socket_fdinfo; socket_info.c:74-261 never
 * fills soi_stat. Its UID/GID/dev/inode therefore remain placeholders,
 * unlike sys_socket.c:382-395 fstat's actual so_cred. The historical exact
 * f99/run145 root diagnostic 20261009T051555Z independently observed 0/0
 * in two complete stable passes. Public xnu-12377 source is not the live
 * host's xnu-13432 source attestation. This strict 0/0 placeholder check
 * proves no creator credential or historical original FD. The exact run877 realm must be observed before finalization;
 * root-process credentials/birth, opaque socket/PCB, tuple, unit and all
 * existing cleanup gates remain separate and mandatory. */
static bool r877SocketInfoStatPlaceholder(uid_t uid,gid_t gid,gid_t expectedRealm){return expectedRealm>=7100&&expectedRealm<=7999&&expectedRealm==R877_FIXED_GID&&uid==0&&gid==0;}
static bool r877ReadFDPass(pid_t pid,R877Context*c,R877FDPass*out){
 memset(out,0,sizeof(*out));out->capacity=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
 if(out->capacity<=0||out->capacity>65536||out->capacity%(int)sizeof(struct proc_fdinfo))return false;
 /* NULL returns allocation capacity, not populated bytes. Extra slack makes
  * an exact-filled buffer distinguishable from a complete actual short list. */
 int buffer=out->capacity+32*(int)sizeof(struct proc_fdinfo);out->list=calloc(1,(size_t)buffer);if(!out->list)return false;
 out->bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,out->list,buffer);if(!r877FDBytes(out->capacity,buffer,out->bytes)){r877FreeFDPass(out);return false;}
 out->count=out->bytes/(int)sizeof(*out->list);out->sockets=calloc((size_t)out->count,sizeof(*out->sockets));if(!out->sockets){r877FreeFDPass(out);return false;}
 unsigned expectedUnit=0;if(c&&(sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&expectedUnit)!=1||expectedUnit==UINT_MAX)){r877FreeFDPass(out);return false;}
 for(int i=0;i<out->count;i++){
  if((i&&out->list[i].proc_fd<=out->list[i-1].proc_fd)||out->list[i].proc_fd<0){r877FreeFDPass(out);return false;}
  if(out->list[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;struct socket_fdinfo s={0};
  if(proc_pidfdinfo(pid,out->list[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s))!=sizeof(s)){r877FreeFDPass(out);return false;}
  R877SocketIdentity*w=&out->sockets[out->socket_count++];w->fd=out->list[i].proc_fd;w->kind=s.psi.soi_kind;w->family=s.psi.soi_family;w->type=s.psi.soi_type;w->protocol=s.psi.soi_protocol;
  w->socket=s.psi.soi_so;w->pcb=s.psi.soi_pcb;w->dev=s.psi.soi_stat.vst_dev;w->inode=s.psi.soi_stat.vst_ino;w->uid=s.psi.soi_stat.vst_uid;w->gid=s.psi.soi_stat.vst_gid;
  if(s.psi.soi_kind==SOCKINFO_TCP){struct in_sockinfo*in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;w->tcp_state=s.psi.soi_proto.pri_tcp.tcpsi_state;
   w->local_port=(uint16_t)in->insi_lport;w->foreign_port=(uint16_t)in->insi_fport;w->local_address=in->insi_laddr.ina_46.i46a_addr4.s_addr;w->foreign_address=in->insi_faddr.ina_46.i46a_addr4.s_addr;
   if(c&&s.psi.soi_family==AF_INET&&s.psi.soi_type==SOCK_STREAM&&w->tcp_state==TSI_S_LISTEN&&in->insi_lport==htons([c->transport[@"frontPort"]unsignedShortValue])&&w->local_address==htonl(INADDR_LOOPBACK)){
    if(!r877SocketInfoStatPlaceholder(w->uid,w->gid,(gid_t)c->gid)){r877FreeFDPass(out);return false;}out->listener_count++;out->listener_fd=out->list[i].proc_fd;out->listener.st_dev=(dev_t)w->dev;out->listener.st_ino=(ino_t)w->inode;
   }
  }
  if(s.psi.soi_family==AF_SYSTEM&&s.psi.soi_kind==SOCKINFO_KERN_CTL){struct kern_ctl_info*k=&s.psi.soi_proto.pri_kern_ctl;
   if(!memchr(k->kcsi_name,0,sizeof(k->kcsi_name))){r877FreeFDPass(out);return false;}w->ctl_id=k->kcsi_id;w->ctl_unit=k->kcsi_unit;memcpy(w->ctl_name,k->kcsi_name,sizeof(w->ctl_name));
   if(c&&!strcmp(k->kcsi_name,"com.apple.net.utun_control")&&k->kcsi_unit==expectedUnit+1){out->utun_count++;out->utun_fd=out->list[i].proc_fd;}
  }
 }return true;
}
static bool r877FDPassesSame(const R877FDPass*a,const R877FDPass*b){return a->count>0&&a->bytes==b->bytes&&a->socket_count==b->socket_count&&
 !memcmp(a->list,b->list,(size_t)a->bytes)&&!memcmp(a->sockets,b->sockets,a->socket_count*sizeof(*a->sockets))&&a->listener_count==b->listener_count&&a->utun_count==b->utun_count&&
 a->listener_fd==b->listener_fd&&a->utun_fd==b->utun_fd;}
static bool r877ObserveCustody(R877Context*c){
 if(!r877FixedBindings(c))return false;R877FDPass first={0},second={0};
 bool okay=r877ReadFDPass(R877_KEEPER_PID,c,&first)&&r877FixedBindings(c)&&r877ReadFDPass(R877_KEEPER_PID,c,&second)&&r877FDPassesSame(&first,&second)&&
 second.listener_count==1&&second.utun_count==1&&r877FixedBindings(c);unsigned idx=okay?if_nametoindex([c->transport[@"interfaceName"]UTF8String]):0;
 if(okay&&idx){c->custody.listener_fd=second.listener_fd;c->custody.utun_fd=second.utun_fd;c->custody.listener=second.listener;c->custody.interface_index=idx;}
 r877FreeFDPass(&first);r877FreeFDPass(&second);return okay&&idx;
}

static NSData *r877HashData(NSData*d){unsigned char digest[32];CC_SHA256(d.bytes,(CC_LONG)d.length,digest);return [NSData dataWithBytes:digest length:32];}
static NSString *r877HexData(NSData*d){NSData*h=r877HashData(d);char hex[65];for(NSUInteger i=0;i<h.length;i++)snprintf(hex+2*i,3,"%02x",((const unsigned char*)h.bytes)[i]);return @(hex);}
static bool r877HostPins(void){
 char os[128]={0},kernel[1024]={0};size_t a=sizeof(os),b=sizeof(kernel);
 if(sysctlbyname("kern.osrelease",os,&a,NULL,0)||sysctlbyname("kern.version",kernel,&b,NULL,0)||a>sizeof(os)||b>sizeof(kernel)||
 !memchr(os,0,sizeof(os))||!memchr(kernel,0,sizeof(kernel))||strcmp(os,"27.0.0")||!strstr(kernel,"xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020"))return false;
 const char*parents[]={"/sbin","/usr/libexec"},*leaves[]={"pfctl","pfd"};const char*hashes[]={"ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef","ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"};
 for(unsigned i=0;i<2;i++){int parent=directory(parents[i]);int fd=parent<0?-1:openat(parent,leaves[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);bool ok=secureFD(fd,false,0)&&hashFD(fd,hashes[i],rootDeadline);if(fd>=0)close(fd);if(parent>=0)close(parent);if(!ok)return false;}return true;
}
static bool r877Zero(const void*bytes,size_t n){const unsigned char*p=bytes;for(size_t i=0;i<n;i++)if(p[i])return false;return true;}
static bool r877OwnedHook(EnvaraPFHookRequest*q,NSDictionary*lease){
 uint64_t ticket=strtoull([lease[@"ticket"]UTF8String],NULL,10);EnvaraPFHookRule*r=&q->rule;
 return !q->anchor[0]&&strnlen(q->anchor_call,1024)<1024&&strnlen(r->owner,64)<64&&strnlen(r->label,64)<64&&
 !strcmp(q->anchor_call,CANARY_ANCHOR.UTF8String)&&!strcmp(r->owner,[lease[@"owner"]UTF8String])&&!strcmp(r->label,[lease[@"label"]UTF8String])&&r->ticket==ticket&&
 r->priority==UINT32_MAX&&r->nr==7&&!r->action&&!r->direction&&!r->quick&&!r->keep_state&&!r->af&&!r->proto&&!r->uid_op&&!r->gid_op&&
 r877Zero(r->uid,sizeof(r->uid))&&r877Zero(r->gid,sizeof(r->gid))&&r877Zero(r->ifname,sizeof(r->ifname))&&!r->ifnot&&!r->rule_flag&&!r->log&&!r->logif&&!r->match_tag_not&&!r->natpass&&
 !r->type&&!r->code&&!r->flags&&!r->flagset&&!r->min_ttl&&!r->allow_opts&&!r->rt&&!r->return_ttl&&!r->tos&&r->anchor_relative==1&&!r->anchor_wildcard&&!r->flush&&
 !r->proto_variant&&!r->extfilter&&!r->extmap&&!r->dnpipe&&!r->dntype&&r877Zero(r->src,64)&&r877Zero(r->dst,64);
}
static bool r877RootAttached(R877Context*c){
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;EnvaraPFHookRequest first={0},last={0},rows[8]={{0}};bool ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==8;
 for(uint32_t i=0;ok&&i<8;i++){rows[i].ticket=first.ticket;rows[i].nr=i;ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&rows[i])&&rows[i].rule.nr==i;}
 if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&first.nr==last.nr&&first.ticket==last.ticket&&r877OwnedHook(&rows[7],c->lease[@"rootHookLease"]);close(fd);if(!ok)return false;
 for(unsigned i=0;i<7;i++){rows[i].ticket=0;memset(rows[i].rule.skip,0,sizeof(rows[i].rule.skip));rows[i].rule.evaluations=0;memset(rows[i].rule.packets,0,sizeof(rows[i].rule.packets));memset(rows[i].rule.bytes,0,sizeof(rows[i].rule.bytes));}
 if(![r877HexData([NSData dataWithBytes:rows length:7*sizeof(*rows)])isEqual:ROOT_RULE])return false;
 char*argv[]={(char*)"/sbin/pfctl",(char*)"-sr",NULL};int code=-1;NSString*text=command(argv,false,&code);if(!text||code)return false;
 /* Like the native root-hook proof, text comparison covers the original
  * seven rows only. The eighth row's label formatting is not a semantic
  * witness; its complete typed kernel identity/predicates were checked above. */
 NSArray*lines=[text componentsSeparatedByString:@"\n"];if(lines.count<8)return false;
 NSString*firstSeven=[[[lines subarrayWithRange:NSMakeRange(0,7)]componentsJoinedByString:@"\n"]stringByAppendingString:@"\n"];
 return [hashText(firstSeven)isEqual:ROOT_TEXT];
}
/* Exact r877 mode DENY six-row constructor. It is copied narrowly from the
 * 05d6 manifest-pinned production filter (unchanged from f99), not the future FRONT profile. All
 * opaque readback bytes remain strict except the documented 40 counters. */
static EnvaraPFHookRule r877DenyRule(R877Context*c,uint32_t i){
 EnvaraPFHookRule r={0};const char*suffix=i<2?"loopback":i<4?"ipv6":"blocked";NSString*digest=hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,c->lease[@"realmId"]]);
 snprintf(r.label,64,"envara_prod_v1_%.24s_%s",digest.UTF8String,suffix);strcpy(r.owner,CANARY_ANCHOR.UTF8String);r.priority=UINT32_MAX;r.action=1;r.direction=2;r.quick=1;
 r.proto=(i%2)?17:6;r.af=i>=2&&i<4?30:0;if(i<2)strcpy(r.ifname,"lo0");r.gid[0]=r.gid[1]=(uint32_t)c->gid;r.gid_op=2;
 uint16_t high=htons(UINT16_MAX);memcpy(r.src+50,&high,2);r.src[52]=9;r.rule_flag=8;uint16_t icmp=0x0303,icmp6=0x0104;memcpy((uint8_t*)&r+964,&icmp,2);memcpy((uint8_t*)&r+966,&icmp6,2);
 r.nr=i;((uint8_t*)&r)[642]=r.af;uint32_t writer=R877_KEEPER_PID;memcpy((uint8_t*)&r+960,&writer,4);
 for(unsigned key=0;key<8;key++){uint32_t next=UINT32_MAX;for(uint32_t j=i+1;j<6;j++){
  EnvaraPFHookRule x={0};x.direction=2;x.proto=(j%2)?17:6;x.af=j>=2&&j<4?30:0;if(j<2)strcpy(x.ifname,"lo0");
  bool differs=key==0?strcmp(r.ifname,x.ifname)!=0:key==1?false:key==2?r.af!=x.af:key==3?r.proto!=x.proto:false;
  if(differs){next=j;break;}}
  memcpy(r.skip+key*8,&next,4);
 }return r;
}
static bool r877DenyVerified(R877Context*c){
 NSDictionary*receipt=c->journal[@"lastReceipt"];if(!boolValue(c->journal[@"present"],true)||!boolValue(c->journal[@"pendingIntent"],false)||![receipt[@"mode"]isEqual:@1]||
 ![receipt[@"writerPid"]isEqual:@R877_KEEPER_PID]||![receipt[@"ruleCount"]isEqual:@6]||!nonBoolInteger(receipt[@"revision"],1,UINT32_MAX))return false;
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;uint32_t ticket=[receipt[@"revision"]unsignedIntValue];bool ok=true;
 const uint8_t actions[]={0,2,4,6,8,11};for(unsigned a=0;ok&&a<6;a++){
  EnvaraPFHookRequest first={0},last={0};strcpy(first.anchor,CANARY_ANCHOR.UTF8String);first.rule.action=actions[a];last=first;
  ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==(a?0U:6U)&&(!a?first.ticket==ticket:true);
  for(uint32_t i=0;ok&&!a&&i<6;i++){EnvaraPFHookRequest got={0},wanted={0};strcpy(got.anchor,CANARY_ANCHOR.UTF8String);got.ticket=ticket;got.nr=i;wanted=got;wanted.rule=r877DenyRule(c,i);
   ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&got);memset((uint8_t*)&got.rule+648,0,40);if(ok)ok=!memcmp(&got,&wanted,sizeof(got));
   R877PoolRead pool={0},expected={0};memcpy(pool.bytes+4,&ticket,4);memcpy(pool.bytes+12,&i,4);pool.bytes[18]=AF_INET;strcpy((char*)pool.bytes+19,CANARY_ANCHOR.UTF8String);expected=pool;
   if(ok)ok=!ioctl(fd,R877_GET_ADDRS,&pool)&&!memcmp(&pool,&expected,sizeof(pool));}
  if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&last.nr==first.nr&&last.ticket==first.ticket;
 }close(fd);return ok&&r877RootAttached(c);
}
static bool r877OwnedTextEmpty(const char*kind){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)kind,NULL};NSString*text=command(argv,false,&code);return text&&code==0&&![text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool r877PortObservation(R877Context*c,bool listener);
static bool r877GroupInventory(gid_t gid,bool present);
static bool r877Load(R877Context*c,NSMutableDictionary*out){
 *c=(R877Context){.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};
 out[@"gate"]=@"fixed-host-abi-pins";if(!r877HostPins())return false;
 out[@"gate"]=@"installed-inventory";c->installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c->installed<0)return false;
 out[@"gate"]=@"fixed-private-context";c->parent=directory(INSTALL_PARENT);c->runtime=directory(RUNTIME);if(c->parent<0||!secureFD(c->runtime,true,0700)||fstat(c->runtime,&c->runtime_i))return false;
 c->registry_bytes=privateRead(c->runtime,"registry.json",65536,&c->registry_i);c->record=strictJSON(c->registry_bytes,65536);c->lock_bytes=privateRead(c->runtime,"registry.lock",4096,&c->lock_i);NSDictionary*lock=strictJSON(c->lock_bytes,4096);
 if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"pid"]isEqual:@R877_CONTROLLER_PID]||![lock[@"anchor"]isEqual:CANARY_ANCHOR])return false;
 c->run=openat(c->runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->run,true,0700)||fstat(c->run,&c->run_i))return false;
 c->lease_bytes=privateRead(c->run,"app-bound-lease.json",16384,&c->lease_i);c->lease=strictJSON(c->lease_bytes,16384);
 NSDictionary*transport=nil;if(!liveShape(c->record,c->lease,c->lease_bytes,&transport,&c->gid))return false;c->transport=transport;
 c->state=openat(c->run,[c->lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->state,true,0700)||fstat(c->state,&c->state_i)||!names(c->state,@[])||
 !names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events"])||!absent(c->run,R877_INTENT)||!absent(c->parent,R877_CAPSULE))return false;
 out[@"gate"]=@"current-process-and-custody";if(!r877ObserveCustody(c)||!r877PortObservation(c,true))return false;out[@"uniqueCurrentKeeperCustodyVerified"]=@YES;
 out[@"gate"]=@"complete-gid-absence";if(envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;out[@"ownedGIDScopeAbsent"]=@YES;
 out[@"gate"]=@"dedicated-group-identity";struct group*g=getgrgid((gid_t)c->gid);NSString*group=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c->gid];if(!g||g->gr_gid!=c->gid||strcmp(g->gr_name,group.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!r877GroupInventory((gid_t)c->gid,true))return false;
 out[@"gate"]=@"journal-and-native-denial";c->journal=readJournal(c->run,c->lease,c->transport[@"keeperPID"]);if(!c->journal||!r877DenyVerified(c)||!r877OwnedTextEmpty("Tables")||!r877OwnedTextEmpty("Anchors")||!r877PrivateStable(c))return false;
 out[@"ownedDenialVerified"]=@YES;return true;
}
static void r877Close(R877Context*c){int fds[]={c->lock,c->state,c->run,c->runtime,c->parent,c->installed};for(unsigned i=0;i<sizeof(fds)/sizeof(fds[0]);i++)if(fds[i]>=0)close(fds[i]);}

/* One transaction only, zero rules: no DIOCBEGINADDRS and no table/state/global
 * action. A commit attempt, failed/lost reply or rollback never permits retry.
 * All callers must already have stopped both exact writers and held custody. */
#ifdef R877_RECOVERY_INERT
/* Compile-only fault seams. They are absent from every production binary;
 * no command, environment, wire object or installed helper can select them. */
static bool(*r877_test_clear_guard)(R877Context*,unsigned);
static int(*r877_test_write_open)(void);
static int(*r877_test_transaction_ioctl)(int,unsigned long,void*);
static bool(*r877_test_empty_readback)(R877Context*);
#endif
static bool r877ClearGuard(R877Context*c,unsigned phase){
#ifdef R877_RECOVERY_INERT
 if(r877_test_clear_guard)return r877_test_clear_guard(c,phase);
#else
 (void)phase;
#endif
 return !interrupted&&seconds()+10<rootDeadline&&r877HostPins()&&r877WaitState(false,false,.2)&&r877WaitState(true,false,.2)&&r877PrivateStable(c)&&
  envara_app_scope_gid_absent((gid_t)c->gid)==1&&r877DenyVerified(c);
}
static int r877WriteDevice(void){
#ifdef R877_RECOVERY_INERT
 return r877_test_write_open?r877_test_write_open():-1;
#else
 int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat h,n;
 if(fstat(fd,&h)||lstat("/dev/pf",&n)||!S_ISCHR(h.st_mode)||h.st_uid||h.st_dev!=n.st_dev||h.st_ino!=n.st_ino||h.st_rdev!=n.st_rdev){close(fd);return -1;}return fd;
#endif
}
static int r877TransactionIoctl(int fd,unsigned long op,void*argument){
 if(op!=R877_BEGIN&&op!=R877_COMMIT&&op!=R877_ROLLBACK){errno=EINVAL;return -1;}
#ifdef R877_RECOVERY_INERT
 return r877_test_transaction_ioctl?r877_test_transaction_ioctl(fd,op,argument):-1;
#else
 return ioctl(fd,op,argument);
#endif
}
static bool r877EmptyReadback(R877Context*c){
#ifdef R877_RECOVERY_INERT
 if(r877_test_empty_readback)return r877_test_empty_readback(c);
#endif
 return pfEmpty()&&r877RootAttached(c);
}
static bool r877ClearOnce(R877Context*c,NSMutableDictionary*out){
 if(c->clear_attempted||!r877ClearGuard(c,0))return false;c->clear_attempted=true;
 int fd=r877WriteDevice();if(fd<0)return false;
 R877Entry e={0};e.rs_num=1;strcpy(e.anchor,CANARY_ANCHOR.UTF8String);R877Transaction t={1,sizeof(e),&e};out[@"ownedFilterClearAttempted"]=@YES;
 bool began=!r877TransactionIoctl(fd,R877_BEGIN,&t);uint32_t ticket=e.ticket;R877Entry expected={0};expected.rs_num=1;strcpy(expected.anchor,CANARY_ANCHOR.UTF8String);expected.ticket=ticket;
 bool known=began&&ticket&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));bool okay=known&&r877ClearGuard(c,1);
 if(okay)okay=!r877TransactionIoctl(fd,R877_COMMIT,&t)&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));
 /* Exact single rollback is permitted only before COMMIT was attempted.
  * This guard deliberately retains uncertain inactive state after commit. */
 else if(known){e=expected;t=(R877Transaction){1,sizeof(e),&e};(void)r877TransactionIoctl(fd,R877_ROLLBACK,&t);}
 close(fd);return okay&&r877EmptyReadback(c);
}
static bool r877InterfaceAbsent(R877Context*c){errno=0;unsigned idx=if_nametoindex([c->transport[@"interfaceName"]UTF8String]);return idx==0&&(errno==ENXIO||errno==ENODEV||errno==0);}
static bool r877NumericIPv4Endpoint(NSString*text){
 if(![text isKindOfClass:NSString.class]||text.length>32)return false;NSRange dot=[text rangeOfString:@"."options:NSBackwardsSearch];if(dot.location==NSNotFound)return false;
 NSString*address=[text substringToIndex:dot.location],*service=[text substringFromIndex:dot.location+1];
 if(![service isEqual:@"*"]){if(!regex(service,@"^(0|[1-9][0-9]{0,4})$")||service.longLongValue>UINT16_MAX)return false;}
 struct in_addr ip;return [address isEqual:@"*"]||inet_pton(AF_INET,address.UTF8String,&ip)==1;
}
static bool r877PortRows(NSString*text,uint16_t port,bool expectListener){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return false;
 bool header=false;unsigned matches=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  if([line hasPrefix:@"Active Internet connections"])continue;
  if(regex(line,@"^Proto[ \\t]+Recv-Q[ \\t]+Send-Q[ \\t]+Local Address[ \\t]+Foreign Address[ \\t]+[(]state[)]([ \\t].*)?$")){if(header)return false;header=true;continue;}
  if(!header)return false;NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count<6||f.count>32||![@[@"tcp4",@"tcp46"]containsObject:f[0]]||!regex(f[1],@"^[0-9]+$")||!regex(f[2],@"^[0-9]+$")||
   !r877NumericIPv4Endpoint(f[3])||!r877NumericIPv4Endpoint(f[4])||
   ![@[@"CLOSED",@"LISTEN",@"SYN_SENT",@"SYN_RECEIVED",@"SYN_RCVD",@"ESTABLISHED",@"CLOSE_WAIT",@"FIN_WAIT_1",@"CLOSING",@"LAST_ACK",@"FIN_WAIT_2",@"TIME_WAIT"]containsObject:f[5]])return false;
  NSString*suffix=[NSString stringWithFormat:@".%u",port];if([f[5]isEqual:@"LISTEN"]&&([f[3]isEqual:[@"127.0.0.1"stringByAppendingString:suffix]]||[f[3]isEqual:[@"*"stringByAppendingString:suffix]]))matches++;
 }
 return header&&matches==(expectListener?1U:0U);
}
static bool r877PortObservation(R877Context*c,bool listener){
 /* Numeric kernel TCP inventory only, no bind/connect or unrelated process FD
  * inspection. Two bounded reads must agree on this exact IPv4 front port. */
 char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-an",(char*)"-p",(char*)"tcp",(char*)"-f",(char*)"inet",NULL};int code=-1;
 NSString*one=command(argv,false,&code);if(!one||code||!r877PortRows(one,[c->transport[@"frontPort"]unsignedShortValue],listener))return false;
 NSString*two=command(argv,false,&code);return two&&!code&&r877PortRows(two,[c->transport[@"frontPort"]unsignedShortValue],listener);
}
static bool r877NamespaceEmpty(R877Context*c){
 if(!c->root_retired)return pfEmpty();int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
 const uint8_t actions[]={0,2,4,6,8,11};bool absentAll=true;
 for(unsigned i=0;i<6;i++){EnvaraPFHookRequest q={0};strcpy(q.anchor,CANARY_ANCHOR.UTF8String);q.rule.action=actions[i];errno=0;if(ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&q)!=-1||errno!=EINVAL){absentAll=false;break;}}
 close(fd);return absentAll;
}
static bool r877WritePrivate(int parent,const char*name,NSData*bytes,struct stat*identity){
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);bool ok=secureFD(fd,false,0600)&&bytes.length>0&&bytes.length<=65536&&write(fd,bytes.bytes,bytes.length)==(ssize_t)bytes.length&&!fsync(fd)&&!fsync(parent);if(fd>=0)close(fd);
 return ok&&[privateRead(parent,name,65536,identity)isEqual:bytes];
}
static NSDictionary *r877HostWithoutOwnedRoute(R877Context*c){
 NSDictionary*base=hostSnapshot();if(!base)return nil;char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-rn",NULL};int code=-1;NSString*routes=normalizedRoutes(command(argv,false,&code));if(!routes||code)return nil;
 NSMutableArray*keep=[NSMutableArray array];for(NSString*row in [routes componentsSeparatedByString:@"\n"]){NSArray*p=[row componentsSeparatedByString:@"|"];if(p.count!=5)return nil;
  if([p[4]isEqual:c->transport[@"interfaceName"]])continue;[keep addObject:row];}
 NSMutableDictionary*out=[base mutableCopy];out[@"routes"]=hashText([keep componentsJoinedByString:@"\n"]);return out;
}
static bool r877StatesEmpty(void){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-ss",NULL};NSString*s=command(argv,false,&code);return s&&code==0&&![s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool r877RootProof(NSDictionary*p){return p&&boolValue(p[@"ok"],true)&&boolValue(p[@"pinsVerified"],true)&&boolValue(p[@"originalRootCompatible"],true)&&boolValue(p[@"priorAnchorsCompatible"],true)&&[p[@"originalRootSHA256"]isEqual:ROOT_RULE]&&[p[@"originalRootTextSHA256"]isEqual:ROOT_TEXT];}
static NSDictionary *r877RootRequest(R877Context*c,bool delete){
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
static NSString *r877GroupRows(NSString*text,gid_t gid,bool present){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return nil;NSMutableSet*seen=[NSMutableSet set];NSMutableArray*normalized=[NSMutableArray array];NSString*owned=[NSString stringWithFormat:@"_envara_pf_%u",gid];unsigned ownedRows=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count!=2||!regex(f[0],@"^[A-Za-z0-9_.-]{1,255}$")||!regex(f[1],@"^(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})$")||[seen containsObject:f[0]])return nil;
  errno=0;long long value=strtoll([f[1]UTF8String],NULL,10);if(errno||value<INT32_MIN||value>UINT32_MAX)return nil;if([f[0]isEqual:owned]||(uint32_t)value==gid){if(!present||![f[0]isEqual:owned]||(uint32_t)value!=gid)return nil;ownedRows++;}
  [seen addObject:f[0]];[normalized addObject:[NSString stringWithFormat:@"%@|%u",f[0],(uint32_t)value]];
 }return normalized.count&&ownedRows==(present?1U:0U)?[[normalized sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]:nil;
}
static NSString *r877NegativeGroups(NSString*text,gid_t gid){return r877GroupRows(text,gid,false);}
static bool r877GroupInventory(gid_t gid,bool present){char*argv[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-list",(char*)"/Groups",(char*)"PrimaryGroupID",NULL};int code=-1;
 NSString*one=r877GroupRows(command(argv,false,&code),gid,present);if(!one||code)return false;NSString*two=r877GroupRows(command(argv,false,&code),gid,present);return !code&&two&&[one isEqual:two];}
static bool r877GroupAbsent(gid_t gid){return r877GroupInventory(gid,false);}
static bool r877AfterCustodianScope(R877Context*c){
 return !interrupted&&seconds()+5<rootDeadline&&r877WaitState(true,true,.1)&&r877WaitState(false,true,.1)&&envara_app_scope_gid_absent((gid_t)c->gid)==1&&r877InterfaceAbsent(c)&&r877PortObservation(c,false)&&r877NamespaceEmpty(c)&&r877StatesEmpty();
}
static bool r877Archive(R877Context*c,int cap,struct stat*capi,struct stat*beforei,NSData*beforeBytes,struct stat*intenti,NSData*intentBytes,NSMutableDictionary*out){
 if(seconds()+10>=rootDeadline||!r877AfterCustodianScope(c)||!r877GroupAbsent((gid_t)c->gid)||!r877PrivateStable(c)||!unchanged(c->run,R877_INTENT,intenti,intentBytes)||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!names(cap,@[@"recovery-before.json"])||!names(c->state,@[])||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@R877_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN]))return false;
 /* This durable pre-rename receipt cannot claim the rename already occurred.
  * Public success is emitted only after held-identity postflight completes. */
 NSMutableDictionary*archiveReceipt=[out mutableCopy];archiveReceipt[@"gate"]=@"durable-pre-archive-proof";NSData*bytes=[NSJSONSerialization dataWithJSONObject:archiveReceipt options:NSJSONWritingWithoutEscapingSlashes error:NULL];struct stat ri;
 if(!r877WritePrivate(cap,"recovery-proof.json",bytes,&ri))return false;struct stat named,parentBefore;if(fstat(c->parent,&parentBefore)||fstatat(c->parent,R877_CAPSULE,&named,AT_SYMLINK_NOFOLLOW)||named.st_dev!=capi->st_dev||named.st_ino!=capi->st_ino||
 !r877PrivateStable(c)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(c->run,R877_INTENT,intenti,intentBytes)||!secureFD(c->parent,true,0)||!secureFD(cap,true,0700)||
 !names(cap,@[@"recovery-before.json",@"recovery-proof.json"])||!r877AfterCustodianScope(c)||!r877GroupAbsent((gid_t)c->gid)||interrupted)return false;
 if(renameatx_np(c->parent,"io.envara.pf-runtime",cap,"runtime",RENAME_EXCL)||fsync(cap)||fsync(c->parent))return false;
 struct stat parentAfter,archived;if(!absent(c->parent,"io.envara.pf-runtime")||fstat(c->parent,&parentAfter)||parentAfter.st_dev!=parentBefore.st_dev||parentAfter.st_ino!=parentBefore.st_ino||
 fstatat(cap,"runtime",&archived,AT_SYMLINK_NOFOLLOW)||archived.st_dev!=c->runtime_i.st_dev||archived.st_ino!=c->runtime_i.st_ino||
 !unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)||!unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)||!unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)||
 !unchanged(c->run,R877_INTENT,intenti,intentBytes)||![c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"]) ]||!names(c->state,@[])||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@R877_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!names(cap,@[@"runtime",@"recovery-before.json",@"recovery-proof.json"]))return false;
 return true;
}
static int r877Recover(bool mutation){
 NSMutableDictionary*out=r877Outcome(mutation);rootDeadline=seconds()+175;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary())return r877Emit(out);umask(077);struct sigaction sa={0};sa.sa_handler=onSignal;if(sigemptyset(&sa.sa_mask))return r877Emit(out);int sigs[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};for(unsigned i=0;i<4;i++)if(sigaction(sigs[i],&sa,NULL))return r877Emit(out);
 R877Context c={.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};int cap=-1;struct stat capi,beforei,intenti;NSData*beforeBytes=nil,*intentBytes=nil;NSDictionary*hostBefore=nil;bool loaded=false;
 do{if(!r877Load(&c,out))break;loaded=true;out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_LIVE_RECOVERY_PREFLIGHT_VERIFIED";out[@"gate"]=@"preflight-complete";if(!mutation)break;
  out[@"ok"]=@NO;out[@"reason"]=@"FIXED_LIVE_RECOVERY_UNCONFIRMED";out[@"gate"]=@"durable-scope-and-single-use-intent";
  if(seconds()+100>=rootDeadline||!r877PrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r877DenyVerified(&c)||!r877StatesEmpty())break;
  hostBefore=r877HostWithoutOwnedRoute(&c);if(!hostBefore||mkdirat(c.parent,R877_CAPSULE,0700))break;cap=openat(c.parent,R877_CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(cap,true,0700)||fstat(cap,&capi)||!names(cap,@[]))break;
  NSDictionary*b=@{@"schema":@"envara.macos-pf-live-recovery-baseline/v1",@"scope":@"fixed-05d6-run877-recovery-only",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,
   @"originalApplicationHostBaselineVerified":@NO,@"hostExcludingOnlyRecordedUTunRoutes":hostBefore,@"registrySHA256":r877HexData(c.registry_bytes),@"leaseSHA256":r877HexData(c.lease_bytes),@"lockSHA256":r877HexData(c.lock_bytes),@"journalObservation":c.journal};
  beforeBytes=[NSJSONSerialization dataWithJSONObject:b options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!r877WritePrivate(cap,"recovery-before.json",beforeBytes,&beforei)||fsync(c.parent))break;
  intentBytes=[NSJSONSerialization dataWithJSONObject:@{@"schema":@"envara.macos-pf-live-recovery-intent/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"scope":@"one-empty-filter-one-pf-token-one-issued-delete-no-retry"} options:NSJSONWritingWithoutEscapingSlashes error:NULL];
  if(!r877WritePrivate(c.run,R877_INTENT,intentBytes,&intenti))break;
  out[@"gate"]=@"stop-exact-controllers-preserving-custody";if(!r877Signal(&c,false,SIGSTOP)||!r877WaitState(false,false,2))break;out[@"controllerStopped"]=@YES;
  if(!r877Signal(&c,true,SIGSTOP)||!r877WaitState(true,false,2))break;out[@"keeperStopped"]=@YES;
  if(!r877ObserveCustody(&c)||!r877PrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1)break;
  out[@"gate"]=@"single-owned-empty-filter";if(!r877ClearOnce(&c,out))break;out[@"ownedFilterEmptyVerified"]=@YES;
  out[@"gate"]=@"close-exact-owned-custodians-after-empty";
  if(!pfEmpty()||!r877RootAttached(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r877Signal(&c,true,SIGKILL)||!r877WaitState(true,true,5))break;out[@"keeperExitObserved"]=@YES;
  if(!pfEmpty()||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r877Signal(&c,false,SIGKILL)||!r877WaitState(false,true,5))break;out[@"controllerExitObserved"]=@YES;
  if(!r877InterfaceAbsent(&c)||!r877PortObservation(&c,false)||!pfEmpty())break;out[@"ownedInterfaceAbsent"]=@YES;out[@"ownedListenerAbsent"]=@YES;
  out[@"gate"]=@"exclusive-registry-after-custodian-exit";if(flock(c.parent,LOCK_EX|LOCK_NB))break;c.lock=openat(c.runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  if(!secureFD(c.lock,false,0600)||flock(c.lock,LOCK_EX|LOCK_NB)||!r877PrivateStable(&c)||!r877AfterCustodianScope(&c))break;
  out[@"gate"]=@"exact-issued-native-retirement-proof";NSDictionary*proof=r877RootRequest(&c,false);
  if(!r877RootProof(proof)||!boolValue(proof[@"hookInstalled"],true)||!boolValue(proof[@"ownedRootHookVerified"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!pfEmpty())break;
  out[@"gate"]=@"release-only-recorded-pf-reference";out[@"ownedPFReferenceReleaseAttempted"]=@YES;int code=-1;char*release[]={(char*)"/sbin/pfctl",(char*)"-X",(char*)[c.record[@"ownedPFReference"][@"token"]UTF8String],NULL};
  if(!r877AfterCustodianScope(&c)||!command(release,true,&code)||code)break;out[@"ownedPFReferenceReleased"]=@YES;
  proof=r877RootRequest(&c,false);if(!r877RootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!r877AfterCustodianScope(&c))break;
  out[@"gate"]=@"one-exact-issued-root-hook-delete";out[@"rootHookDeleteAttempted"]=@YES;(void)r877RootRequest(&c,true);proof=r877RootRequest(&c,false);
  if(!r877RootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||!boolValue(proof[@"ownedRootHookRemoved"],true)||!boolValue(proof[@"originalRootRestored"],true)||!boolValue(proof[@"receiptRetired"],true)||
   !boolValue(proof[@"namespaceReclaimed"],true)||![proof[@"namespaceState"]isEqual:@"absent"]||![proof[@"runLedgerState"]isEqual:@"retired"])break;c.root_retired=true;if(!r877AfterCustodianScope(&c))break;
  out[@"rootHookRemoved"]=out[@"originalRootRestored"]=out[@"receiptRetired"]=out[@"namespaceReclaimed"]=@YES;
  out[@"gate"]=@"one-dedicated-group-removal";struct group*g=getgrgid((gid_t)c.gid);NSString*name=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c.gid];
  if(!g||g->gr_gid!=c.gid||strcmp(g->gr_name,name.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!r877GroupInventory((gid_t)c.gid,true)||!r877AfterCustodianScope(&c))break;
  NSString*path=[@"/Groups/"stringByAppendingString:name];char*deleteGroup[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-delete",(char*)path.UTF8String,NULL};out[@"ownedGroupDeleteAttempted"]=@YES;
  if(!command(deleteGroup,true,&code)||code||!r877GroupAbsent((gid_t)c.gid))break;out[@"ownedGroupRemoved"]=@YES;
  out[@"gate"]=@"recovery-scope-host-network-postflight";NSDictionary*after=r877HostWithoutOwnedRoute(&c);if(!after||![after isEqual:hostBefore]||!r877AfterCustodianScope(&c))break;out[@"recoveryScopeHostNetworkRestored"]=@YES;
  out[@"gate"]=@"held-inode-atomic-private-runtime-archive";if(!r877Archive(&c,cap,&capi,&beforei,beforeBytes,&intenti,intentBytes,out))break;
  out[@"runtimeArchived"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"cleanupConfirmed"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"FIXED_LIVE_RECOVERY_COMPLETED";out[@"gate"]=@"recovery-complete";
 }while(0);
 if(loaded)r877Close(&c);else if(c.installed>=0)r877Close(&c);if(cap>=0)close(cap);return r877Emit(out);
}
#ifndef R877_RECOVERY_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return r877Emit(r877Outcome(false));const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=r877Outcome(false);out[@"ok"]=@YES;out[@"reason"]=@"INERT_FIXED_LIVE_RECOVERY_PLAN";out[@"mutationEntryLinked"]=@YES;out[@"nativeStatusRequiredAfterCustodianExit"]=@YES;return r877Emit(out);}
 if(!strcmp(mode,"--inspect-fixed-root"))return r877Recover(false);
 if(!strcmp(mode,"--cleanup-fixed-root"))return r877Recover(true);
 return r877Emit(r877Outcome(false));
}}
#endif
