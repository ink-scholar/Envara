/* Fixed 43b/run6c6 owned-session recovery candidate, 2026-10-09.
 * Grounded in actual readonly receipt 20261009T105331Z: exact controller,
 * keeper/core and zombie front; FRONT5 revision2, recorded child and no confirmed resume,
 * same-object three-FD utun, recorded cold child. Count-only observations never authorize mutation.
 * Private configuration-only inventory remains UNOBSERVED until this tool's
 * fresh exact metadata/held-inode/bytes preflight succeeds; no run6c6 evidence
 * is reused as a claim about current state. All prior sources stay unchanged.
 * One explicit cleanup entry retires only this fixed current session, then
 * archives the entire private runtime under the held identities. Historical
 * whole-host equality is observation only; it does not authorize replay or
 * waive fresh owned resource absence, namespace/root/group or archive proof.
 * This source and inert tests perform no authorization or deployment.
 */
#define INSPECTOR_INERT 1
#include "inspector-app-43b-run6c6.m"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/proc_info.h>

#define R5BES_RECOVERY_SCHEMA @"envara.macos-pf-owned-session-recovery/v1"
#define R5BES_CAPSULE "io.envara.pf-recovery-43b-6c6fc98d-owned-scope"
#define R5BES_INTENT "recovery-dbcf-run6c6-state-files.intent"
#define R5BES_CONTROLLER_PID 88253
#define R5BES_KEEPER_PID 88325
#define R5BES_CONTROLLER_BIRTH @"1791545513:232668"
#define R5BES_KEEPER_BIRTH @"1791545516:021589"
#define R5BES_CORE_BIRTH @"1791545517:855052"
#define R5BES_FRONT_BIRTH(c) ((c)->transport[@"frontBirth"]) /* private sealed run6c6 transport; never signalled */
#define R5BES_FIXED_GID 7100

typedef struct { int32_t rs_num; char anchor[1024]; uint32_t ticket; } R5BESEntry;
typedef struct { int32_t size, esize; R5BESEntry *array; } R5BESTransaction;
typedef struct {uint8_t bytes[1136];} R5BESPoolRead;
_Static_assert(sizeof(R5BESEntry)==1032&&offsetof(R5BESEntry,ticket)==1028,"one FILTER entry ABI");
_Static_assert(sizeof(R5BESTransaction)==16&&offsetof(R5BESTransaction,array)==8,"one FILTER transaction ABI");
#define R5BES_BEGIN _IOWR('D',81,R5BESTransaction)
#define R5BES_COMMIT _IOWR('D',82,R5BESTransaction)
#define R5BES_ROLLBACK _IOWR('D',83,R5BESTransaction)
#define R5BES_GET_ADDRS _IOWR('D',53,R5BESPoolRead)
_Static_assert(R5BES_BEGIN==0xc0104451UL&&R5BES_COMMIT==0xc0104452UL&&R5BES_ROLLBACK==0xc0104453UL,"fixed one FILTER ioctl ABI");
_Static_assert(R5BES_GET_ADDRS==0xc4704435UL,"readonly empty pool ABI");

typedef struct {struct proc_bsdinfo controller,keeper;struct stat listener;int listener_fd,utun_fd;uint32_t interface_index;} R5BESCustody;
typedef struct {int installed,parent,runtime,run,state,lock;struct stat registry_i,lease_i,lock_i,runtime_i,run_i,state_i;
 NSData *registry_bytes,*lease_bytes,*lock_bytes,*state_config_bytes;struct stat state_config_i;NSDictionary *record,*lease,*transport,*journal,*host_before,*host_after,*host_comparison;uint64_t gid;bool root_retired,clear_attempted,delete_attempted,core_terminated;R5BESCustody custody;} R5BESContext;

static NSMutableDictionary *r5besOutcome(bool mutation){
 return [@{@"schema":R5BES_RECOVERY_SCHEMA,@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
 @"readOnly":@((BOOL)!mutation),@"ok":@NO,@"reason":@"FIXED_LIVE_RECOVERY_PREFLIGHT_REFUSED",@"gate":@"not-started",
 @"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"originalApplicationHostBaselineVerified":@NO,
 @"cleanupScope":@"owned-current-session",@"hostComparisonAvailable":@NO,@"hostSnapshotsMatched":@NO,
 @"ready":@NO,@"protected":@NO,@"productionReady":@NO,@"fullGuardFailureAccepted":@NO,
 @"ownedGIDScopeAbsent":@NO,@"ownedDenialVerified":@NO,@"ownedFrontVerified":@NO,@"originalDescriptorCustodyVerified":@NO,@"uniqueCurrentKeeperCustodyVerified":@NO,
 @"controllerStopped":@NO,@"keeperStopped":@NO,@"ownedFilterClearAttempted":@NO,@"ownedFilterEmptyVerified":@NO,
 @"keeperExitObserved":@NO,@"controllerExitObserved":@NO,@"ownedInterfaceAbsent":@NO,@"ownedListenerAbsent":@NO,
 @"ownedPFReferenceReleaseAttempted":@NO,@"ownedPFReferenceReleased":@NO,@"rootHookDeleteAttempted":@NO,
 @"rootHookRemoved":@NO,@"originalRootRestored":@NO,@"receiptRetired":@NO,@"namespaceReclaimed":@NO,
 @"ownedGroupDeleteAttempted":@NO,@"ownedGroupRemoved":@NO,@"runtimeArchived":@NO,@"recoveryScopeHostNetworkRestored":@NO,
 @"coreStopped":@NO,@"coreTerminateAttempted":@NO,@"coreTerminatedObserved":@NO,@"coreReapedByRecovery":@NO,
 @"frontZombieBound":@NO,@"coreFinalAbsent":@NO,@"frontFinalAbsent":@NO,@"currentUTunAliasCustodyVerified":@NO,
 @"globalFlushExecuted":@NO,@"PFEnableExecuted":@NO,@"globalPoolResetExecuted":@NO,@"applicationLaunchExecuted":@NO}mutableCopy];
}
static int r5besEmit(NSDictionary *out){return emitInspection(out);}
static bool r5besNamedDirectory(int parent,const char*name,int held,struct stat*expected){
 struct stat actual,current;return secureFD(held,true,0700)&&!fstat(held,&current)&&!fstatat(parent,name,&actual,AT_SYMLINK_NOFOLLOW)&&
  current.st_dev==expected->st_dev&&current.st_ino==expected->st_ino&&actual.st_dev==current.st_dev&&actual.st_ino==current.st_ino;
}
/* The fixed production transport retains a credential-bearing configuration
 * until its own session_stop. This candidate accepts exactly one root0600/
 * single-link configuration only after fresh held-inode/bytes inspection;
 * no actual private-state observation is asserted by this source. Recovery
 * preserves its held inode and bytes in the whole private runtime archive;
 * no leaf is deleted or reclassified as public data. */
static bool r5besStateMetadata(const struct stat*s,size_t bound){
 return s&&S_ISREG(s->st_mode)&&!s->st_uid&&!s->st_gid&&(s->st_mode&07777)==0600&&s->st_nlink==1&&s->st_size>0&&(uint64_t)s->st_size<=bound;
}
static bool r5besStateStable(R5BESContext*c){
 return secureFD(c->state,true,0700)&&c->state_config_bytes&&r5besStateMetadata(&c->state_config_i,65536)&&
  names(c->state,@[@"transport-config.json"])&&unchanged(c->state,"transport-config.json",&c->state_config_i,c->state_config_bytes)&&absent(c->state,"cache.db");
}
static bool r5besStateLoad(R5BESContext*c){
 if(!secureFD(c->state,true,0700)||!names(c->state,@[@"transport-config.json"]))return false;
 c->state_config_bytes=privateRead(c->state,"transport-config.json",65536,&c->state_config_i);
 return r5besStateStable(c);
}

/* The sealed controller recorded the exact cold-stage child before B. A false
 * resumed flag is not an absence proof. This recovery never signals that child.
 * Only current double ESRCH or two exact root-credential SZOMB observations
 * permit retirement, and final ESRCH is separately required after keeper exit. */
static NSDictionary *r5besApplicationChildFromBSD(NSDictionary *recorded,const struct proc_bsdinfo*a,const struct proc_bsdinfo*b,bool absentBoth){
 if(!keys(recorded,@[@"pid",@"birth"])||!nonBoolInteger(recorded[@"pid"],2,INT32_MAX)||!regex(recorded[@"birth"],@"^[1-9][0-9]{0,19}:[0-9]{6}$"))return nil;
 NSString*state=@"unknown";int exitCode=-1,signal=0;
 if(absentBoth)state=@"absent";
 else if(a&&b&&a->pbi_pid==[recorded[@"pid"]unsignedIntValue]&&b->pbi_pid==a->pbi_pid&&a->pbi_ppid==R5BES_KEEPER_PID&&b->pbi_ppid==a->pbi_ppid&&
  !a->pbi_uid&&!a->pbi_ruid&&!a->pbi_svuid&&!a->pbi_gid&&!a->pbi_rgid&&!a->pbi_svgid&&
  !b->pbi_uid&&!b->pbi_ruid&&!b->pbi_svuid&&!b->pbi_gid&&!b->pbi_rgid&&!b->pbi_svgid&&
  a->pbi_status==SZOMB&&b->pbi_status==SZOMB&&a->pbi_start_tvusec<1000000&&
  a->pbi_start_tvsec==b->pbi_start_tvsec&&a->pbi_start_tvusec==b->pbi_start_tvusec&&a->pbi_xstatus==b->pbi_xstatus&&
  [[NSString stringWithFormat:@"%llu:%06llu",a->pbi_start_tvsec,a->pbi_start_tvusec]isEqual:recorded[@"birth"]]){
  int status=(int)a->pbi_xstatus;if(WIFEXITED(status)){exitCode=WEXITSTATUS(status);state=@"exact-recorded-zombie";}
  else if(WIFSIGNALED(status)&&WTERMSIG(status)>0&&WTERMSIG(status)<=31){signal=WTERMSIG(status);state=@"exact-recorded-zombie";}
 }
 return @{@"pid":recorded[@"pid"],@"recordedBirth":recorded[@"birth"],@"state":state,@"exitCode":@(exitCode),@"signal":@(signal),@"causeVerified":@NO};
}
static NSDictionary *r5besApplicationChildObservation(R5BESContext*c){
 NSDictionary*child=c->record[@"application"][@"child"];struct proc_bsdinfo a={0},b={0};
 if(!keys(child,@[@"pid",@"birth"])||!nonBoolInteger(child[@"pid"],2,INT32_MAX))return nil;
 pid_t pid=[child[@"pid"]intValue];errno=0;int first=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&a,sizeof(a)),ea=errno;
 errno=0;int second=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&b,sizeof(b)),eb=errno;
 return r5besApplicationChildFromBSD(child,first==sizeof(a)?&a:NULL,second==sizeof(b)?&b:NULL,first==0&&ea==ESRCH&&second==0&&eb==ESRCH);
}
static bool r5besApplicationChildTerminated(R5BESContext*c){NSDictionary*p=r5besApplicationChildObservation(c);return p&&[@[@"absent",@"exact-recorded-zombie"]containsObject:p[@"state"]];}
static bool r5besApplicationChildAbsent(R5BESContext*c){NSDictionary*p=r5besApplicationChildObservation(c);return p&&[p[@"state"]isEqual:@"absent"];}
static bool r5besPrivateStable(R5BESContext*c){
 return r5besApplicationChildTerminated(c)&&r5besStateStable(c)&&unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)&&unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)&&
 unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)&&r5besNamedDirectory(c->parent,"io.envara.pf-runtime",c->runtime,&c->runtime_i)&&
 r5besNamedDirectory(c->runtime,CANARY_RUN.UTF8String,c->run,&c->run_i)&&r5besNamedDirectory(c->run,[c->lease[@"realmId"]UTF8String],c->state,&c->state_i)&&
 [c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"])];
}
static bool r5besBSDIdentity(pid_t pid,NSString*birth,const char*path,pid_t parent,struct proc_bsdinfo*out){
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
static bool r5besSignal(R5BESContext*c,bool keeper,int signal){
 if(interrupted||seconds()+5>=rootDeadline||!r5besPrivateStable(c)||envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;
 struct proc_bsdinfo p;pid_t pid=keeper?R5BES_KEEPER_PID:R5BES_CONTROLLER_PID;NSString*birth=keeper?R5BES_KEEPER_BIRTH:R5BES_CONTROLLER_BIRTH;
 if(!r5besBSDIdentity(pid,birth,keeper?NATIVE:INSTALL "/node",keeper?R5BES_CONTROLLER_PID:88252,&p))return false;
 return kill(pid,signal)==0;
}
static bool r5besWaitState(bool keeper,bool exited,double duration){
 double until=MIN(rootDeadline,seconds()+duration);pid_t pid=keeper?R5BES_KEEPER_PID:R5BES_CONTROLLER_PID;
 while(seconds()<until){struct proc_bsdinfo p={0};errno=0;int n=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&p,sizeof(p));
  if(exited&&n==0&&errno==ESRCH)return true;if(n!=sizeof(p))return false;
  NSString*birth=[NSString stringWithFormat:@"%llu:%06llu",p.pbi_start_tvsec,p.pbi_start_tvusec];
  if(![birth isEqual:keeper?R5BES_KEEPER_BIRTH:R5BES_CONTROLLER_BIRTH])return false;
  if(exited&&p.pbi_status==SZOMB)return true;
  if(!exited&&p.pbi_status==SSTOP)return true;struct timespec pause={0,10000000};nanosleep(&pause,NULL);
 }return false;
}
/* This external recovery is not either child's parent and never claims reap.
 * Exact stable SZOMB/SIGKILL is termination; ESRCH is required separately after
 * the keeper has exited. A current zombie executable-image proof is impossible.
 * The core's executable was verified while alive at each exact signal boundary.
 * No FD query failure is interpreted as an empty descriptor inventory. */
static bool r5besZombie(pid_t pid,NSString*birth,pid_t parent,bool killed){
 struct proc_bsdinfo a={0},b={0};
 if(proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&a,sizeof(a))!=sizeof(a)||proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&b,sizeof(b))!=sizeof(b))return false;
 NSDictionary*proof=zombieFrontFromBSD(&a,&b,pid,birth,parent);
 return proof&&[proof[@"exitStatusAvailable"]boolValue]&&(killed?
   [proof[@"signal"]intValue]==SIGKILL&&[proof[@"exitCode"]intValue]==-1:
   [proof[@"signal"]intValue]==0&&[proof[@"exitCode"]intValue]==1);
}
static bool r5besFixedBindings(R5BESContext*c){
 NSDictionary*l=c->lease,*t=c->transport;if(![l[@"controllerPid"]isEqual:@R5BES_CONTROLLER_PID]||![l[@"controllerBirth"]isEqual:R5BES_CONTROLLER_BIRTH]||
 ![t[@"keeperPID"]isEqual:@R5BES_KEEPER_PID]||![t[@"keeperBirth"]isEqual:R5BES_KEEPER_BIRTH]||![t[@"corePID"]isEqual:@88328]||
 ![t[@"coreBirth"]isEqual:R5BES_CORE_BIRTH]||![t[@"frontPID"]isEqual:@88331]||c->gid!=R5BES_FIXED_GID)return false;
 struct proc_bsdinfo core;
 bool coreBound=c->core_terminated?r5besZombie(88328,R5BES_CORE_BIRTH,R5BES_KEEPER_PID,true):
   r5besBSDIdentity(88328,R5BES_CORE_BIRTH,INSTALL "/mihomo",R5BES_KEEPER_PID,&core);
 return coreBound&&r5besZombie(88331,R5BES_FRONT_BIRTH(c),R5BES_KEEPER_PID,false)&&
 r5besBSDIdentity(R5BES_CONTROLLER_PID,R5BES_CONTROLLER_BIRTH,INSTALL "/node",88252,&c->custody.controller)&&
 r5besBSDIdentity(R5BES_KEEPER_PID,R5BES_KEEPER_BIRTH,NATIVE,R5BES_CONTROLLER_PID,&c->custody.keeper);
}
/* Actual descriptor metadata, not transport-started boolean assertions. A
 * unique AF_INET TCP LISTEN socket and unique utun control must still be held
 * by this exact keeper. Original FD inode seals are not persisted by r5bes;
 * this proves current unique custody, not historical original-FD uniqueness. */
typedef struct {uint32_t fd,kind,family,type,protocol,dev,uid,gid;uint64_t socket,pcb,inode;uint32_t tcp_state,local_address,foreign_address;uint16_t local_port,foreign_port;uint32_t ctl_id,ctl_unit;char ctl_name[MAX_KCTL_NAME];} R5BESSocketIdentity;
typedef struct {struct proc_fdinfo*list;R5BESSocketIdentity*sockets;int bytes,count,capacity;unsigned socket_count,listener_count,utun_count;int listener_fd,utun_fd;struct stat listener;} R5BESFDPass;
static bool r5besFDBytes(int capacity,int buffer,int bytes){return capacity>0&&capacity<=65536&&capacity%(int)sizeof(struct proc_fdinfo)==0&&buffer>capacity&&bytes>0&&bytes<=capacity&&bytes<buffer&&bytes%(int)sizeof(struct proc_fdinfo)==0;}
static void r5besFreeFDPass(R5BESFDPass*p){free(p->list);free(p->sockets);memset(p,0,sizeof(*p));}
/* PROC_PIDFDSOCKETINFO is not fstat. Pinned public Apple XNU f6217:
 * proc_info.c:2692-2702 zeros socket_fdinfo; socket_info.c:74-261 never
 * fills soi_stat. Its UID/GID/dev/inode therefore remain placeholders,
 * unlike sys_socket.c:382-395 fstat's actual so_cred. The historical exact
 * f99/run145 root diagnostic 20261009T051555Z independently observed 0/0
 * in two complete stable passes; this is historical ABI evidence only. Public xnu-12377 source is not the live
 * host's xnu-13432 source attestation. This strict 0/0 placeholder check
 * proves no creator credential or historical original FD. The exact run6c6 realm must be observed before finalization;
 * root-process credentials/birth, opaque socket/PCB, tuple, unit and all
 * existing cleanup gates remain separate and mandatory. */
static bool r5besSocketInfoStatPlaceholder(uid_t uid,gid_t gid,gid_t expectedRealm){return expectedRealm>=7100&&expectedRealm<=7999&&expectedRealm==R5BES_FIXED_GID&&uid==0&&gid==0;}
static bool r5besReadFDPass(pid_t pid,R5BESContext*c,R5BESFDPass*out){
 memset(out,0,sizeof(*out));out->capacity=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
 if(out->capacity<=0||out->capacity>65536||out->capacity%(int)sizeof(struct proc_fdinfo))return false;
 /* NULL returns allocation capacity, not populated bytes. Extra slack makes
  * an exact-filled buffer distinguishable from a complete actual short list. */
 int buffer=out->capacity+32*(int)sizeof(struct proc_fdinfo);out->list=calloc(1,(size_t)buffer);if(!out->list)return false;
 out->bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,out->list,buffer);if(!r5besFDBytes(out->capacity,buffer,out->bytes)){r5besFreeFDPass(out);return false;}
 out->count=out->bytes/(int)sizeof(*out->list);out->sockets=calloc((size_t)out->count,sizeof(*out->sockets));if(!out->sockets){r5besFreeFDPass(out);return false;}
 unsigned expectedUnit=0;if(c&&(sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&expectedUnit)!=1||expectedUnit==UINT_MAX)){r5besFreeFDPass(out);return false;}
 for(int i=0;i<out->count;i++){
  if((i&&out->list[i].proc_fd<=out->list[i-1].proc_fd)||out->list[i].proc_fd<0){r5besFreeFDPass(out);return false;}
  if(out->list[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;struct socket_fdinfo s={0};
  if(proc_pidfdinfo(pid,out->list[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s))!=sizeof(s)){r5besFreeFDPass(out);return false;}
  R5BESSocketIdentity*w=&out->sockets[out->socket_count++];w->fd=out->list[i].proc_fd;w->kind=s.psi.soi_kind;w->family=s.psi.soi_family;w->type=s.psi.soi_type;w->protocol=s.psi.soi_protocol;
  w->socket=s.psi.soi_so;w->pcb=s.psi.soi_pcb;w->dev=s.psi.soi_stat.vst_dev;w->inode=s.psi.soi_stat.vst_ino;w->uid=s.psi.soi_stat.vst_uid;w->gid=s.psi.soi_stat.vst_gid;
  if(s.psi.soi_kind==SOCKINFO_TCP){struct in_sockinfo*in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;w->tcp_state=s.psi.soi_proto.pri_tcp.tcpsi_state;
   w->local_port=(uint16_t)in->insi_lport;w->foreign_port=(uint16_t)in->insi_fport;w->local_address=in->insi_laddr.ina_46.i46a_addr4.s_addr;w->foreign_address=in->insi_faddr.ina_46.i46a_addr4.s_addr;
   if(c&&s.psi.soi_family==AF_INET&&s.psi.soi_type==SOCK_STREAM&&w->tcp_state==TSI_S_LISTEN&&in->insi_lport==htons([c->transport[@"frontPort"]unsignedShortValue])&&w->local_address==htonl(INADDR_LOOPBACK)){
    if(!r5besSocketInfoStatPlaceholder(w->uid,w->gid,(gid_t)c->gid)){r5besFreeFDPass(out);return false;}out->listener_count++;out->listener_fd=out->list[i].proc_fd;out->listener.st_dev=(dev_t)w->dev;out->listener.st_ino=(ino_t)w->inode;
   }
  }
  if(s.psi.soi_family==AF_SYSTEM&&s.psi.soi_kind==SOCKINFO_KERN_CTL){struct kern_ctl_info*k=&s.psi.soi_proto.pri_kern_ctl;
   if(!memchr(k->kcsi_name,0,sizeof(k->kcsi_name))){r5besFreeFDPass(out);return false;}w->ctl_id=k->kcsi_id;w->ctl_unit=k->kcsi_unit;memcpy(w->ctl_name,k->kcsi_name,sizeof(w->ctl_name));
   if(c&&!strcmp(k->kcsi_name,"com.apple.net.utun_control")&&k->kcsi_unit==expectedUnit+1){out->utun_count++;out->utun_fd=out->list[i].proc_fd;}
  }
 }return true;
}
static bool r5besFDPassesSame(const R5BESFDPass*a,const R5BESFDPass*b){return a->count>0&&a->bytes==b->bytes&&a->socket_count==b->socket_count&&
 !memcmp(a->list,b->list,(size_t)a->bytes)&&!memcmp(a->sockets,b->sockets,a->socket_count*sizeof(*a->sockets))&&a->listener_count==b->listener_count&&a->utun_count==b->utun_count&&
 a->listener_fd==b->listener_fd&&a->utun_fd==b->utun_fd;}
/* Exactly three stable descriptors alias one nonzero utun socket object.
 * The two complete per-FD vectors are compared above; opaque identifiers stay
 * in RAM only. This is current scoped custody, never historical original FD
 * custody or a claim that a second tunnel was opened by these descriptors. */
static bool r5besSameUTunObject(const R5BESFDPass*p,R5BESContext*c){
 unsigned unit=UINT_MAX;if(!p||p->utun_count!=3||p->socket_count>8192||sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&unit)!=1||unit==UINT_MAX)return false;
 unsigned matches=0;R5BESSocketIdentity first={0};
 for(unsigned i=0;i<p->socket_count;i++){
  R5BESSocketIdentity value=p->sockets[i];if(value.family!=AF_SYSTEM||value.kind!=SOCKINFO_KERN_CTL||value.ctl_unit!=unit+1||strcmp(value.ctl_name,"com.apple.net.utun_control"))continue;
  if(!value.socket)return false;value.fd=0;if(!matches)first=value;else if(memcmp(&value,&first,sizeof(value)))return false;matches++;
 }return matches==3;
}
static bool r5besObserveCustody(R5BESContext*c){
 if(!r5besFixedBindings(c))return false;R5BESFDPass first={0},second={0};
 bool okay=r5besReadFDPass(R5BES_KEEPER_PID,c,&first)&&r5besFixedBindings(c)&&r5besReadFDPass(R5BES_KEEPER_PID,c,&second)&&r5besFDPassesSame(&first,&second)&&
 second.listener_count==1&&second.utun_count==3&&r5besSameUTunObject(&first,c)&&r5besSameUTunObject(&second,c)&&r5besFixedBindings(c);unsigned idx=okay?if_nametoindex([c->transport[@"interfaceName"]UTF8String]):0;
 if(okay&&idx){c->custody.listener_fd=second.listener_fd;c->custody.utun_fd=second.utun_fd;c->custody.listener=second.listener;c->custody.interface_index=idx;}
 r5besFreeFDPass(&first);r5besFreeFDPass(&second);return okay&&idx;
}

static NSData *r5besHashData(NSData*d){unsigned char digest[32];CC_SHA256(d.bytes,(CC_LONG)d.length,digest);return [NSData dataWithBytes:digest length:32];}
static NSString *r5besHexData(NSData*d){NSData*h=r5besHashData(d);char hex[65];for(NSUInteger i=0;i<h.length;i++)snprintf(hex+2*i,3,"%02x",((const unsigned char*)h.bytes)[i]);return @(hex);}
static bool r5besHostPins(void){
 char os[128]={0},kernel[1024]={0};size_t a=sizeof(os),b=sizeof(kernel);
 if(sysctlbyname("kern.osrelease",os,&a,NULL,0)||sysctlbyname("kern.version",kernel,&b,NULL,0)||a>sizeof(os)||b>sizeof(kernel)||
 !memchr(os,0,sizeof(os))||!memchr(kernel,0,sizeof(kernel))||strcmp(os,"27.0.0")||!strstr(kernel,"xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020"))return false;
 const char*parents[]={"/sbin","/usr/libexec"},*leaves[]={"pfctl","pfd"};const char*hashes[]={"ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef","ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"};
 for(unsigned i=0;i<2;i++){int parent=directory(parents[i]);int fd=parent<0?-1:openat(parent,leaves[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);bool ok=secureFD(fd,false,0)&&hashFD(fd,hashes[i],rootDeadline);if(fd>=0)close(fd);if(parent>=0)close(parent);if(!ok)return false;}return true;
}
static bool r5besZero(const void*bytes,size_t n){const unsigned char*p=bytes;for(size_t i=0;i<n;i++)if(p[i])return false;return true;}
static bool r5besOwnedHook(EnvaraPFHookRequest*q,NSDictionary*lease){
 uint64_t ticket=strtoull([lease[@"ticket"]UTF8String],NULL,10);EnvaraPFHookRule*r=&q->rule;
 return !q->anchor[0]&&strnlen(q->anchor_call,1024)<1024&&strnlen(r->owner,64)<64&&strnlen(r->label,64)<64&&
 !strcmp(q->anchor_call,CANARY_ANCHOR.UTF8String)&&!strcmp(r->owner,[lease[@"owner"]UTF8String])&&!strcmp(r->label,[lease[@"label"]UTF8String])&&r->ticket==ticket&&
 r->priority==UINT32_MAX&&r->nr==7&&!r->action&&!r->direction&&!r->quick&&!r->keep_state&&!r->af&&!r->proto&&!r->uid_op&&!r->gid_op&&
 r5besZero(r->uid,sizeof(r->uid))&&r5besZero(r->gid,sizeof(r->gid))&&r5besZero(r->ifname,sizeof(r->ifname))&&!r->ifnot&&!r->rule_flag&&!r->log&&!r->logif&&!r->match_tag_not&&!r->natpass&&
 !r->type&&!r->code&&!r->flags&&!r->flagset&&!r->min_ttl&&!r->allow_opts&&!r->rt&&!r->return_ttl&&!r->tos&&r->anchor_relative==1&&!r->anchor_wildcard&&!r->flush&&
 !r->proto_variant&&!r->extfilter&&!r->extmap&&!r->dnpipe&&!r->dntype&&r5besZero(r->src,64)&&r5besZero(r->dst,64);
}
static bool r5besRootAttached(R5BESContext*c){
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;EnvaraPFHookRequest first={0},last={0},rows[8]={{0}};bool ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==8;
 for(uint32_t i=0;ok&&i<8;i++){rows[i].ticket=first.ticket;rows[i].nr=i;ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&rows[i])&&rows[i].rule.nr==i;}
 if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&first.nr==last.nr&&first.ticket==last.ticket&&r5besOwnedHook(&rows[7],c->lease[@"rootHookLease"]);close(fd);if(!ok)return false;
 for(unsigned i=0;i<7;i++){rows[i].ticket=0;memset(rows[i].rule.skip,0,sizeof(rows[i].rule.skip));rows[i].rule.evaluations=0;memset(rows[i].rule.packets,0,sizeof(rows[i].rule.packets));memset(rows[i].rule.bytes,0,sizeof(rows[i].rule.bytes));}
 if(![r5besHexData([NSData dataWithBytes:rows length:7*sizeof(*rows)])isEqual:ROOT_RULE])return false;
 char*argv[]={(char*)"/sbin/pfctl",(char*)"-sr",NULL};int code=-1;NSString*text=command(argv,false,&code);if(!text||code)return false;
 /* Like the native root-hook proof, text comparison covers the original
  * seven rows only. The eighth row's label formatting is not a semantic
  * witness; its complete typed kernel identity/predicates were checked above. */
 NSArray*lines=[text componentsSeparatedByString:@"\n"];if(lines.count<8)return false;
 NSString*firstSeven=[[[lines subarrayWithRange:NSMakeRange(0,7)]componentsJoinedByString:@"\n"]stringByAppendingString:@"\n"];
 return [hashText(firstSeven)isEqual:ROOT_TEXT];
}
/* Exact installed dbcf FRONT5 readback constructor. The five rows permit
 * the original scoped SOCKS listener; this is never described as DENY6 or
 * general application protection. Retirement requires empty complete scope. */
static EnvaraPFHookRule r5besFrontBase(R5BESContext*c,uint32_t i){
 EnvaraPFHookRule r={0};if(i>=5)return r;
 const char*labels[]={"front_scoped","front_foreign","front_ipv6","front_listener","front_listener_other"};
 NSString*digest=hashText([NSString stringWithFormat:@"%@|%@",CANARY_RUN,c->lease[@"realmId"]]);
 snprintf(r.label,64,"envara_prod_v1_%.24s_%s",digest.UTF8String,labels[i]);strcpy(r.owner,CANARY_ANCHOR.UTF8String);r.priority=UINT32_MAX;
 r.action=(i==0||i==3)?0:1;r.direction=i<3?2:1;r.quick=1;r.af=i==2?30:2;r.proto=6;strcpy(r.ifname,"lo0");
 if(i==0||i==2||i==3){r.gid[0]=r.gid[1]=(uint32_t)c->gid;r.gid_op=2;uint16_t high=htons(UINT16_MAX);memcpy(r.src+50,&high,2);r.src[52]=9;}
 if(i==3)r.uid_op=2;
 if(i==2){r.dst[15]=1;memset(r.dst+16,255,16);}else{const uint8_t ip[]={127,0,0,1};memcpy(r.dst,ip,4);memset(r.dst+16,255,4);}
 uint16_t port=htons([c->transport[@"frontPort"]unsignedShortValue]);memcpy(r.dst+48,&port,2);memcpy(r.dst+50,&port,2);r.dst[52]=2;
 if(r.action==1){r.rule_flag=8;uint16_t icmp=0x0303,icmp6=0x0104;memcpy((uint8_t*)&r+964,&icmp,2);memcpy((uint8_t*)&r+966,&icmp6,2);}return r;
}
static bool r5besFrontDiff(const EnvaraPFHookRule*a,const EnvaraPFHookRule*b,unsigned key){
 if(key==0)return strcmp(a->ifname,b->ifname)||a->ifnot!=b->ifnot;if(key==1)return a->direction!=b->direction;if(key==2)return a->af!=b->af;if(key==3)return a->proto!=b->proto;
 const uint8_t*x=key<6?a->src:a->dst,*y=key<6?b->src:b->dst;
 return key==4||key==6?x[56]!=y[56]||x[40]!=y[40]||memcmp(x,y,32):x[52]!=y[52]||memcmp(x+48,y+48,4);
}
static EnvaraPFHookRule r5besFrontRule(R5BESContext*c,uint32_t i){
 EnvaraPFHookRule r=r5besFrontBase(c,i);r.nr=i;((uint8_t*)&r)[642]=r.af;uint32_t writer=R5BES_KEEPER_PID;memcpy((uint8_t*)&r+960,&writer,4);
 for(unsigned key=0;key<8;key++){uint32_t next=UINT32_MAX;for(uint32_t j=i+1;j<5;j++){EnvaraPFHookRule later=r5besFrontBase(c,j);if(r5besFrontDiff(&r,&later,key)){next=j;break;}}memcpy(r.skip+key*8,&next,4);}return r;
}
static bool r5besFrontRowMatches(R5BESContext*c,uint32_t ticket,uint32_t i,const EnvaraPFHookRequest*row){
 if(!c||!row||c->gid!=R5BES_FIXED_GID||ticket!=2||i>=5)return false;
 EnvaraPFHookRequest got=*row,wanted={0};strcpy(wanted.anchor,CANARY_ANCHOR.UTF8String);wanted.ticket=ticket;wanted.nr=i;wanted.rule=r5besFrontRule(c,i);
 /* Only these documented evaluation/packet/byte counters are volatile. */
 memset((uint8_t*)&got.rule+648,0,40);return !memcmp(&got,&wanted,sizeof(got));
}
static bool r5besFrontVerified(R5BESContext*c){
 NSDictionary*receipt=c->journal[@"lastReceipt"];if(!boolValue(c->journal[@"present"],true)||!boolValue(c->journal[@"pendingIntent"],false)||![receipt[@"mode"]isEqual:@3]||
 ![receipt[@"writerPid"]isEqual:@R5BES_KEEPER_PID]||![receipt[@"ruleCount"]isEqual:@5]||!nonBoolInteger(receipt[@"revision"],2,2)||![receipt[@"sequence"]isEqual:@1]||![c->journal[@"eventCount"]isEqual:@4]||
 ![c->journal[@"inventorySHA256"]isEqual:@"18679bd7e9d2082eb76194e5d51f4d52a215545cb9d68a0d1198078d1da536c0"]||
 ![c->journal[@"eventBytesSHA256"]isEqual:@"517ea49b873cf01ccc26a7971797b139828c2e1193102683325ac7cc023be799"])return false;
 int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;uint32_t ticket=[receipt[@"revision"]unsignedIntValue];bool ok=true;
 const uint8_t actions[]={0,2,4,6,8,11};for(unsigned a=0;ok&&a<6;a++){
  EnvaraPFHookRequest first={0},last={0};strcpy(first.anchor,CANARY_ANCHOR.UTF8String);first.rule.action=actions[a];last=first;
  ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first)&&first.nr==(a?0U:5U)&&(!a?first.ticket==ticket:true);
  for(uint32_t i=0;ok&&!a&&i<5;i++){EnvaraPFHookRequest got={0};strcpy(got.anchor,CANARY_ANCHOR.UTF8String);got.ticket=ticket;got.nr=i;
   ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULE,&got)&&r5besFrontRowMatches(c,ticket,i,&got);
   R5BESPoolRead pool={0},expected={0};memcpy(pool.bytes+4,&ticket,4);memcpy(pool.bytes+12,&i,4);pool.bytes[18]=AF_INET;strcpy((char*)pool.bytes+19,CANARY_ANCHOR.UTF8String);expected=pool;
   if(ok)ok=!ioctl(fd,R5BES_GET_ADDRS,&pool)&&!memcmp(&pool,&expected,sizeof(pool));}
  if(ok)ok=!ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&last)&&last.nr==first.nr&&last.ticket==first.ticket;
 }close(fd);return ok&&r5besRootAttached(c);
}
static bool r5besOwnedTextEmpty(const char*kind){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-a",(char*)CANARY_ANCHOR.UTF8String,(char*)"-s",(char*)kind,NULL};NSString*text=command(argv,false,&code);return text&&code==0&&![text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool r5besPortObservation(R5BESContext*c,bool listener);
static bool r5besGroupInventory(gid_t gid,bool present);
static bool r5besLoad(R5BESContext*c,NSMutableDictionary*out){
 *c=(R5BESContext){.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};
 out[@"gate"]=@"fixed-host-abi-pins";if(!r5besHostPins())return false;
 out[@"gate"]=@"installed-inventory";c->installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c->installed<0)return false;
 out[@"gate"]=@"fixed-private-context";c->parent=directory(INSTALL_PARENT);c->runtime=directory(RUNTIME);if(c->parent<0||!secureFD(c->runtime,true,0700)||fstat(c->runtime,&c->runtime_i))return false;
 c->registry_bytes=privateRead(c->runtime,"registry.json",65536,&c->registry_i);c->record=strictJSON(c->registry_bytes,65536);c->lock_bytes=privateRead(c->runtime,"registry.lock",4096,&c->lock_i);NSDictionary*lock=strictJSON(c->lock_bytes,4096);
 if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"pid"]isEqual:@R5BES_CONTROLLER_PID]||![lock[@"anchor"]isEqual:CANARY_ANCHOR])return false;
 c->run=openat(c->runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->run,true,0700)||fstat(c->run,&c->run_i))return false;
 c->lease_bytes=privateRead(c->run,"app-bound-lease.json",16384,&c->lease_i);c->lease=strictJSON(c->lease_bytes,16384);
 NSDictionary*transport=nil;if(!liveShape(c->record,c->lease,c->lease_bytes,&transport,&c->gid))return false;c->transport=transport;if(c->gid!=R5BES_FIXED_GID||c->record[@"application"][@"child"]==NSNull.null||!boolValue(c->record[@"application"][@"resumed"],false)||![c->record[@"phase"]isEqual:@"cleanup-required"]||!boolValue(c->record[@"cleanupUncertain"],true))return false;
 out[@"gate"]=@"recorded-application-child-termination";NSDictionary*childObservation=r5besApplicationChildObservation(c);if(childObservation)out[@"applicationChildObservation"]=childObservation;if(!r5besApplicationChildTerminated(c))return false;
 c->state=openat(c->run,[c->lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->state,true,0700)||fstat(c->state,&c->state_i)||!r5besStateLoad(c)||
 !names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||!names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events"])||!absent(c->run,R5BES_INTENT)||!absent(c->parent,R5BES_CAPSULE))return false;
 out[@"gate"]=@"current-process-and-custody";if(!r5besObserveCustody(c)||!r5besPortObservation(c,true))return false;out[@"uniqueCurrentKeeperCustodyVerified"]=@YES;out[@"currentUTunAliasCustodyVerified"]=@YES;out[@"frontZombieBound"]=@YES;
 out[@"gate"]=@"complete-gid-absence";if(envara_app_scope_gid_absent((gid_t)c->gid)!=1)return false;out[@"ownedGIDScopeAbsent"]=@YES;
 out[@"gate"]=@"dedicated-group-identity";struct group*g=getgrgid((gid_t)c->gid);NSString*group=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c->gid];if(!g||g->gr_gid!=c->gid||strcmp(g->gr_name,group.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!r5besGroupInventory((gid_t)c->gid,true))return false;
 out[@"gate"]=@"journal-and-native-front";c->journal=readJournal(c->run,c->lease,c->transport[@"keeperPID"]);if(!c->journal||!r5besFrontVerified(c)||!r5besOwnedTextEmpty("Tables")||!r5besOwnedTextEmpty("Anchors")||!r5besPrivateStable(c))return false;
 out[@"ownedFrontVerified"]=@YES;return true;
}
static void r5besClose(R5BESContext*c){int fds[]={c->lock,c->state,c->run,c->runtime,c->parent,c->installed};for(unsigned i=0;i<sizeof(fds)/sizeof(fds[0]);i++)if(fds[i]>=0)close(fds[i]);}

/* One transaction only, zero rules: no DIOCBEGINADDRS and no table/state/global
 * action. A commit attempt, failed/lost reply or rollback never permits retry.
 * All callers must already have stopped both exact writers and held custody. */
#ifdef R5BES_RECOVERY_INERT
/* Compile-only fault seams. They are absent from every production binary;
 * no command, environment, wire object or installed helper can select them. */
static bool(*r5bes_test_clear_guard)(R5BESContext*,unsigned);
static int(*r5bes_test_write_open)(void);
static int(*r5bes_test_transaction_ioctl)(int,unsigned long,void*);
static bool(*r5bes_test_empty_readback)(R5BESContext*);
#endif
static bool r5besClearGuard(R5BESContext*c,unsigned phase){
#ifdef R5BES_RECOVERY_INERT
 if(r5bes_test_clear_guard)return r5bes_test_clear_guard(c,phase);
#else
 (void)phase;
#endif
 return !interrupted&&seconds()+10<rootDeadline&&r5besHostPins()&&r5besWaitState(false,false,.2)&&r5besWaitState(true,false,.2)&&r5besPrivateStable(c)&&
  envara_app_scope_gid_absent((gid_t)c->gid)==1&&r5besFrontVerified(c);
}
static int r5besWriteDevice(void){
#ifdef R5BES_RECOVERY_INERT
 return r5bes_test_write_open?r5bes_test_write_open():-1;
#else
 int fd=open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;struct stat h,n;
 if(fstat(fd,&h)||lstat("/dev/pf",&n)||!S_ISCHR(h.st_mode)||h.st_uid||h.st_dev!=n.st_dev||h.st_ino!=n.st_ino||h.st_rdev!=n.st_rdev){close(fd);return -1;}return fd;
#endif
}
static int r5besTransactionIoctl(int fd,unsigned long op,void*argument){
 if(op!=R5BES_BEGIN&&op!=R5BES_COMMIT&&op!=R5BES_ROLLBACK){errno=EINVAL;return -1;}
#ifdef R5BES_RECOVERY_INERT
 return r5bes_test_transaction_ioctl?r5bes_test_transaction_ioctl(fd,op,argument):-1;
#else
 return ioctl(fd,op,argument);
#endif
}
static bool r5besEmptyReadback(R5BESContext*c){
#ifdef R5BES_RECOVERY_INERT
 if(r5bes_test_empty_readback)return r5bes_test_empty_readback(c);
#endif
 return pfEmpty()&&r5besRootAttached(c);
}
static bool r5besClearOnce(R5BESContext*c,NSMutableDictionary*out){
 if(c->clear_attempted||!r5besClearGuard(c,0))return false;c->clear_attempted=true;
 int fd=r5besWriteDevice();if(fd<0)return false;
 R5BESEntry e={0};e.rs_num=1;strcpy(e.anchor,CANARY_ANCHOR.UTF8String);R5BESTransaction t={1,sizeof(e),&e};out[@"ownedFilterClearAttempted"]=@YES;
 bool began=!r5besTransactionIoctl(fd,R5BES_BEGIN,&t);uint32_t ticket=e.ticket;R5BESEntry expected={0};expected.rs_num=1;strcpy(expected.anchor,CANARY_ANCHOR.UTF8String);expected.ticket=ticket;
 bool known=began&&ticket&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));bool okay=known&&r5besClearGuard(c,1);
 if(okay)okay=!r5besTransactionIoctl(fd,R5BES_COMMIT,&t)&&t.size==1&&t.esize==sizeof(e)&&t.array==&e&&!memcmp(&e,&expected,sizeof(e));
 /* Exact single rollback is permitted only before COMMIT was attempted.
  * This guard deliberately retains uncertain inactive state after commit. */
 else if(known){e=expected;t=(R5BESTransaction){1,sizeof(e),&e};(void)r5besTransactionIoctl(fd,R5BES_ROLLBACK,&t);}
 close(fd);return okay&&r5besEmptyReadback(c);
}
static bool r5besCoreSignal(R5BESContext*c,int signal){
 if((signal!=SIGSTOP&&signal!=SIGKILL)||c->core_terminated||interrupted||seconds()+10>=rootDeadline||
 !r5besWaitState(false,false,.2)||!r5besWaitState(true,false,.2)||!r5besPrivateStable(c)||envara_app_scope_gid_absent((gid_t)c->gid)!=1||!r5besFrontVerified(c)||!r5besObserveCustody(c))return false;
 struct proc_bsdinfo core;if(!r5besBSDIdentity(88328,R5BES_CORE_BIRTH,INSTALL "/mihomo",R5BES_KEEPER_PID,&core))return false;
 if(signal==SIGKILL&&core.pbi_status!=SSTOP)return false;
 return kill(88328,signal)==0;
}
static bool r5besCoreWait(bool terminated,double duration){
 double until=MIN(rootDeadline,seconds()+duration);
 while(seconds()<until){
  if(terminated){if(r5besZombie(88328,R5BES_CORE_BIRTH,R5BES_KEEPER_PID,true))return true;}
  else {struct proc_bsdinfo core;if(!r5besBSDIdentity(88328,R5BES_CORE_BIRTH,INSTALL "/mihomo",R5BES_KEEPER_PID,&core))return false;if(core.pbi_status==SSTOP)return true;}
  struct timespec pause={0,10000000};nanosleep(&pause,NULL);
 }return false;
}
static bool r5besChildFinalAbsent(pid_t pid){
 errno=0;struct proc_bsdinfo info={0};int size=proc_pidinfo(pid,PROC_PIDTBSDINFO,1,&info,sizeof(info));return size==0&&errno==ESRCH;
}
static bool r5besChildrenFinalAbsent(R5BESContext*c,double duration){
 double until=MIN(rootDeadline,seconds()+duration);
 while(seconds()<until){if(r5besApplicationChildAbsent(c)&&r5besChildFinalAbsent(88328)&&r5besChildFinalAbsent(88331))return true;struct timespec pause={0,10000000};nanosleep(&pause,NULL);}return false;
}
static bool r5besInterfaceAbsent(R5BESContext*c){errno=0;unsigned idx=if_nametoindex([c->transport[@"interfaceName"]UTF8String]);return idx==0&&(errno==ENXIO||errno==ENODEV||errno==0);}
static bool r5besNumericIPv4Endpoint(NSString*text){
 if(![text isKindOfClass:NSString.class]||text.length>32)return false;NSRange dot=[text rangeOfString:@"."options:NSBackwardsSearch];if(dot.location==NSNotFound)return false;
 NSString*address=[text substringToIndex:dot.location],*service=[text substringFromIndex:dot.location+1];
 if(![service isEqual:@"*"]){if(!regex(service,@"^(0|[1-9][0-9]{0,4})$")||service.longLongValue>UINT16_MAX)return false;}
 struct in_addr ip;return [address isEqual:@"*"]||inet_pton(AF_INET,address.UTF8String,&ip)==1;
}
static bool r5besPortRows(NSString*text,uint16_t port,bool expectListener){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return false;
 bool header=false;unsigned matches=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  if([line hasPrefix:@"Active Internet connections"])continue;
  if(regex(line,@"^Proto[ \\t]+Recv-Q[ \\t]+Send-Q[ \\t]+Local Address[ \\t]+Foreign Address[ \\t]+[(]state[)]([ \\t].*)?$")){if(header)return false;header=true;continue;}
  if(!header)return false;NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count<6||f.count>32||![@[@"tcp4",@"tcp46"]containsObject:f[0]]||!regex(f[1],@"^[0-9]+$")||!regex(f[2],@"^[0-9]+$")||
   !r5besNumericIPv4Endpoint(f[3])||!r5besNumericIPv4Endpoint(f[4])||
   ![@[@"CLOSED",@"LISTEN",@"SYN_SENT",@"SYN_RECEIVED",@"SYN_RCVD",@"ESTABLISHED",@"CLOSE_WAIT",@"FIN_WAIT_1",@"CLOSING",@"LAST_ACK",@"FIN_WAIT_2",@"TIME_WAIT"]containsObject:f[5]])return false;
  NSString*suffix=[NSString stringWithFormat:@".%u",port];if([f[5]isEqual:@"LISTEN"]&&([f[3]isEqual:[@"127.0.0.1"stringByAppendingString:suffix]]||[f[3]isEqual:[@"*"stringByAppendingString:suffix]]))matches++;
 }
 return header&&matches==(expectListener?1U:0U);
}
static bool r5besPortObservation(R5BESContext*c,bool listener){
 /* Numeric kernel TCP inventory only, no bind/connect or unrelated process FD
  * inspection. Two bounded reads must agree on this exact IPv4 front port. */
 char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-an",(char*)"-p",(char*)"tcp",(char*)"-f",(char*)"inet",NULL};int code=-1;
 NSString*one=command(argv,false,&code);if(!one||code||!r5besPortRows(one,[c->transport[@"frontPort"]unsignedShortValue],listener))return false;
 NSString*two=command(argv,false,&code);return two&&!code&&r5besPortRows(two,[c->transport[@"frontPort"]unsignedShortValue],listener);
}
static bool r5besNamespaceEmpty(R5BESContext*c){
 if(!c->root_retired)return pfEmpty();int fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
 const uint8_t actions[]={0,2,4,6,8,11};bool absentAll=true;
 for(unsigned i=0;i<6;i++){EnvaraPFHookRequest q={0};strcpy(q.anchor,CANARY_ANCHOR.UTF8String);q.rule.action=actions[i];errno=0;if(ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&q)!=-1||errno!=EINVAL){absentAll=false;break;}}
 close(fd);return absentAll;
}
static bool r5besWritePrivate(int parent,const char*name,NSData*bytes,struct stat*identity){
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);bool ok=secureFD(fd,false,0600)&&bytes.length>0&&bytes.length<=65536&&write(fd,bytes.bytes,bytes.length)==(ssize_t)bytes.length&&!fsync(fd)&&!fsync(parent);if(fd>=0)close(fd);
 return ok&&[privateRead(parent,name,65536,identity)isEqual:bytes];
}
static NSDictionary *r5besHostWithoutOwnedRoute(R5BESContext*c){
 NSDictionary*base=hostSnapshot();if(!base)return nil;char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-rn",NULL};int code=-1;NSString*routes=normalizedRoutes(command(argv,false,&code));if(!routes||code)return nil;
 NSMutableArray*keep=[NSMutableArray array];for(NSString*row in [routes componentsSeparatedByString:@"\n"]){NSArray*p=[row componentsSeparatedByString:@"|"];if(p.count!=5)return nil;
  if([p[4]isEqual:c->transport[@"interfaceName"]])continue;[keep addObject:row];}
 NSMutableDictionary*out=[base mutableCopy];out[@"routes"]=hashText([keep componentsJoinedByString:@"\n"]);return out;
}
/* Host snapshots contain only fixed, normalized hashes. Equality is an
 * observation over the cleanup interval, never the missing application-start
 * baseline. Unknown hashes refuse; a genuine volatile difference is preserved
 * privately and cannot erase any mandatory owned-retirement proof. */
static NSDictionary *r5besCompareHost(NSDictionary *before,NSDictionary *after){
 NSArray *fields=@[@"routes",@"dns",@"nat",@"pfconf"];
 if(!keys(before,fields)||!keys(after,fields))return nil;
 NSMutableDictionary *comparison=[NSMutableDictionary dictionary];
 for(NSString *key in fields){if(!regex(before[key],@"^[0-9a-f]{64}$")||!regex(after[key],@"^[0-9a-f]{64}$"))return nil;
  comparison[key]=@((BOOL)[before[key]isEqual:after[key]]);}
 return comparison;
}
/* Typed public outcome facts are separate from the fresh kernel/FD checks in
 * r5besArchive. This gate prevents any partial retirement from being promoted
 * to owned-session success, regardless of host-snapshot equality. */
static bool r5besOwnedRetirementFacts(NSDictionary *out){
 if(![out[@"schema"]isEqual:R5BES_RECOVERY_SCHEMA]||![out[@"cleanupScope"]isEqual:@"owned-current-session"]||
  !boolValue(out[@"hostComparisonAvailable"],true)||
  !boolValue(out[@"originalApplicationHostBaselineVerified"],false))return false;
 const BOOL hostMatch=[out[@"hostSnapshotsMatched"]boolValue];
 if(!boolValue(out[@"hostSnapshotsMatched"],hostMatch)||!boolValue(out[@"recoveryScopeHostNetworkRestored"],hostMatch))return false;
 for(NSString *key in @[@"ownedGIDScopeAbsent",@"ownedFilterEmptyVerified",@"keeperExitObserved",@"controllerExitObserved",@"ownedInterfaceAbsent",@"ownedListenerAbsent",@"ownedPFReferenceReleased",@"rootHookRemoved",@"originalRootRestored",@"receiptRetired",@"namespaceReclaimed",@"ownedGroupRemoved",@"coreFinalAbsent",@"frontFinalAbsent"])
  if(!boolValue(out[key],true))return false;
 for(NSString *key in @[@"ready",@"protected",@"productionReady",@"fullGuardFailureAccepted",@"ownedDenialVerified",@"originalDescriptorCustodyVerified",@"coreReapedByRecovery",@"globalFlushExecuted",@"PFEnableExecuted",@"globalPoolResetExecuted",@"applicationLaunchExecuted"])
  if(!boolValue(out[key],false))return false;
 return true;
}
static bool r5besStatesEmpty(void){int code=-1;char*argv[]={(char*)"/sbin/pfctl",(char*)"-ss",NULL};NSString*s=command(argv,false,&code);return s&&code==0&&![s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length;}
static bool r5besRootProof(NSDictionary*p){return p&&boolValue(p[@"ok"],true)&&boolValue(p[@"pinsVerified"],true)&&boolValue(p[@"originalRootCompatible"],true)&&boolValue(p[@"priorAnchorsCompatible"],true)&&[p[@"originalRootSHA256"]isEqual:ROOT_RULE]&&[p[@"originalRootTextSHA256"]isEqual:ROOT_TEXT];}
static bool r5besRetiredNativeFacts(NSDictionary *proof){
 return r5besRootProof(proof)&&boolValue(proof[@"pfDisabled"],true)&&boolValue(proof[@"ownedRootHookRemoved"],true)&&
  boolValue(proof[@"originalRootRestored"],true)&&boolValue(proof[@"receiptRetired"],true)&&boolValue(proof[@"namespaceReclaimed"],true)&&
  [proof[@"namespaceState"]isEqual:@"absent"]&&[proof[@"runLedgerState"]isEqual:@"retired"];
}
static NSDictionary *r5besRootRequest(R5BESContext*c,bool delete){
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
static NSString *r5besGroupRows(NSString*text,gid_t gid,bool present){
 if(![text isKindOfClass:NSString.class]||!text.length||text.length>OUTPUT_LIMIT)return nil;NSMutableSet*seen=[NSMutableSet set];NSMutableArray*normalized=[NSMutableArray array];NSString*owned=[NSString stringWithFormat:@"_envara_pf_%u",gid];unsigned ownedRows=0;
 for(NSString*raw in [text componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length)continue;
  NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
  if(f.count!=2||!regex(f[0],@"^[A-Za-z0-9_.-]{1,255}$")||!regex(f[1],@"^(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})$")||[seen containsObject:f[0]])return nil;
  errno=0;long long value=strtoll([f[1]UTF8String],NULL,10);if(errno||value<INT32_MIN||value>UINT32_MAX)return nil;if([f[0]isEqual:owned]||(uint32_t)value==gid){if(!present||![f[0]isEqual:owned]||(uint32_t)value!=gid)return nil;ownedRows++;}
  [seen addObject:f[0]];[normalized addObject:[NSString stringWithFormat:@"%@|%u",f[0],(uint32_t)value]];
 }return normalized.count&&ownedRows==(present?1U:0U)?[[normalized sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]:nil;
}
static NSString *r5besNegativeGroups(NSString*text,gid_t gid){return r5besGroupRows(text,gid,false);}
static bool r5besGroupInventory(gid_t gid,bool present){char*argv[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-list",(char*)"/Groups",(char*)"PrimaryGroupID",NULL};int code=-1;
 NSString*one=r5besGroupRows(command(argv,false,&code),gid,present);if(!one||code)return false;NSString*two=r5besGroupRows(command(argv,false,&code),gid,present);return !code&&two&&[one isEqual:two];}
static bool r5besGroupAbsent(gid_t gid){return r5besGroupInventory(gid,false);}
static bool r5besAfterCustodianScope(R5BESContext*c){
 return !interrupted&&seconds()+5<rootDeadline&&r5besWaitState(true,true,.1)&&r5besWaitState(false,true,.1)&&r5besApplicationChildAbsent(c)&&r5besChildFinalAbsent(88328)&&r5besChildFinalAbsent(88331)&&envara_app_scope_gid_absent((gid_t)c->gid)==1&&r5besInterfaceAbsent(c)&&r5besPortObservation(c,false)&&r5besNamespaceEmpty(c)&&r5besStatesEmpty();
}
static bool r5besArchive(R5BESContext*c,int cap,struct stat*capi,struct stat*beforei,NSData*beforeBytes,struct stat*intenti,NSData*intentBytes,NSMutableDictionary*out){
 if(!r5besOwnedRetirementFacts(out)||!c->host_before||!c->host_after||!c->host_comparison||
 ![c->host_comparison isEqual:r5besCompareHost(c->host_before,c->host_after)]||seconds()+45>=rootDeadline||!r5besAfterCustodianScope(c)||!r5besGroupAbsent((gid_t)c->gid)||!r5besPrivateStable(c)||!unchanged(c->run,R5BES_INTENT,intenti,intentBytes)||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!names(cap,@[@"recovery-before.json"])||!r5besStateStable(c)||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@R5BES_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN]))return false;
 /* This durable pre-rename receipt cannot claim the rename already occurred.
  * Public success is emitted only after held-identity postflight completes. */
 NSMutableDictionary*archiveReceipt=[out mutableCopy];archiveReceipt[@"gate"]=@"durable-pre-archive-proof";
 archiveReceipt[@"observedHostBeforeSHA256"]=c->host_before;archiveReceipt[@"observedHostAfterSHA256"]=c->host_after;archiveReceipt[@"observedHostComparison"]=c->host_comparison;NSData*bytes=[NSJSONSerialization dataWithJSONObject:archiveReceipt options:NSJSONWritingWithoutEscapingSlashes error:NULL];struct stat ri;
 if(!r5besWritePrivate(cap,"recovery-proof.json",bytes,&ri))return false;struct stat named,parentBefore;if(fstat(c->parent,&parentBefore)||fstatat(c->parent,R5BES_CAPSULE,&named,AT_SYMLINK_NOFOLLOW)||named.st_dev!=capi->st_dev||named.st_ino!=capi->st_ino||
 !r5besPrivateStable(c)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(c->run,R5BES_INTENT,intenti,intentBytes)||!secureFD(c->parent,true,0)||!secureFD(cap,true,0700)||
 !names(cap,@[@"recovery-before.json",@"recovery-proof.json"])||!r5besAfterCustodianScope(c)||!r5besGroupAbsent((gid_t)c->gid)||interrupted||seconds()+35>=rootDeadline)return false;
 if(renameatx_np(c->parent,"io.envara.pf-runtime",cap,"runtime",RENAME_EXCL)||fsync(cap)||fsync(c->parent))return false;
 struct stat parentAfter,archived;if(!absent(c->parent,"io.envara.pf-runtime")||fstat(c->parent,&parentAfter)||parentAfter.st_dev!=parentBefore.st_dev||parentAfter.st_ino!=parentBefore.st_ino||
 fstatat(cap,"runtime",&archived,AT_SYMLINK_NOFOLLOW)||archived.st_dev!=c->runtime_i.st_dev||archived.st_ino!=c->runtime_i.st_ino||
 !unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)||!unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)||!unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)||
 !unchanged(c->run,R5BES_INTENT,intenti,intentBytes)||![c->journal isEqual:readJournal(c->run,c->lease,c->transport[@"keeperPID"]) ]||!r5besStateStable(c)||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events",@R5BES_INTENT])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||
 !unchanged(cap,"recovery-before.json",beforei,beforeBytes)||!unchanged(cap,"recovery-proof.json",&ri,bytes)||!names(cap,@[@"runtime",@"recovery-before.json",@"recovery-proof.json"])||
 !r5besOwnedRetirementFacts(out)||!r5besAfterCustodianScope(c)||!r5besGroupAbsent((gid_t)c->gid))return false;
 NSDictionary *proof=r5besRootRequest(c,false);
 if(!r5besRetiredNativeFacts(proof)||!r5besAfterCustodianScope(c))return false;
 return true;
}
static int r5besRecover(bool mutation){
 NSMutableDictionary*out=r5besOutcome(mutation);rootDeadline=seconds()+175;
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary())return r5besEmit(out);umask(077);struct sigaction sa={0};sa.sa_handler=onSignal;if(sigemptyset(&sa.sa_mask))return r5besEmit(out);int sigs[]={SIGTERM,SIGINT,SIGHUP,SIGPIPE};for(unsigned i=0;i<4;i++)if(sigaction(sigs[i],&sa,NULL))return r5besEmit(out);
 R5BESContext c={.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};int cap=-1;struct stat capi,beforei,intenti;NSData*beforeBytes=nil,*intentBytes=nil;NSDictionary*hostBefore=nil;bool loaded=false;
 do{if(!r5besLoad(&c,out))break;loaded=true;out[@"ok"]=@YES;out[@"reason"]=@"READ_ONLY_LIVE_RECOVERY_PREFLIGHT_VERIFIED";out[@"gate"]=@"preflight-complete";if(!mutation)break;
  out[@"ok"]=@NO;out[@"reason"]=@"FIXED_LIVE_RECOVERY_UNCONFIRMED";out[@"gate"]=@"durable-scope-and-single-use-intent";
  if(seconds()+100>=rootDeadline||!r5besPrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r5besFrontVerified(&c)||!r5besStatesEmpty())break;
  hostBefore=r5besHostWithoutOwnedRoute(&c);if(!hostBefore||mkdirat(c.parent,R5BES_CAPSULE,0700))break;cap=openat(c.parent,R5BES_CAPSULE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(cap,true,0700)||fstat(cap,&capi)||!names(cap,@[]))break;
  NSDictionary*b=@{@"schema":@"envara.macos-pf-live-recovery-baseline/v1",@"scope":@"fixed-43b-run6c6-recovery-only",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,
   @"originalApplicationHostBaselineVerified":@NO,@"hostExcludingOnlyRecordedUTunRoutes":hostBefore,@"registrySHA256":r5besHexData(c.registry_bytes),@"leaseSHA256":r5besHexData(c.lease_bytes),@"lockSHA256":r5besHexData(c.lock_bytes),@"journalObservation":c.journal,@"stateConfigSHA256":r5besHexData(c.state_config_bytes)};
  beforeBytes=[NSJSONSerialization dataWithJSONObject:b options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!r5besWritePrivate(cap,"recovery-before.json",beforeBytes,&beforei)||fsync(c.parent))break;
  intentBytes=[NSJSONSerialization dataWithJSONObject:@{@"schema":@"envara.macos-pf-live-recovery-intent/v1",@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,@"manifestSHA256":@MF,@"scope":@"one-empty-filter-one-pf-token-one-issued-delete-no-retry"} options:NSJSONWritingWithoutEscapingSlashes error:NULL];
  if(!r5besWritePrivate(c.run,R5BES_INTENT,intentBytes,&intenti))break;
  out[@"gate"]=@"stop-exact-controllers-preserving-custody";if(!r5besSignal(&c,false,SIGSTOP)||!r5besWaitState(false,false,2))break;out[@"controllerStopped"]=@YES;
  if(!r5besSignal(&c,true,SIGSTOP)||!r5besWaitState(true,false,2))break;out[@"keeperStopped"]=@YES;
  if(!r5besObserveCustody(&c)||!r5besPrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1)break;
  out[@"gate"]=@"terminate-exact-core-preserving-keeper-custody";
  if(!r5besCoreSignal(&c,SIGSTOP)||!r5besCoreWait(false,2))break;out[@"coreStopped"]=@YES;
  out[@"coreTerminateAttempted"]=@YES;if(!r5besCoreSignal(&c,SIGKILL)||!r5besCoreWait(true,5))break;
  c.core_terminated=true;out[@"coreTerminatedObserved"]=@YES;
  if(!r5besObserveCustody(&c)||!r5besPrivateStable(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r5besFrontVerified(&c))break;
  /* Denial rows clear only after complete owned-GID absence, exact writers STOP, exact core termination and repeated custody; keeper exit follows. */
  out[@"gate"]=@"single-owned-empty-filter";if(!r5besClearOnce(&c,out))break;out[@"ownedFilterEmptyVerified"]=@YES;
  out[@"gate"]=@"close-exact-owned-custodians-after-empty";
  if(!pfEmpty()||!r5besRootAttached(&c)||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r5besSignal(&c,true,SIGKILL)||!r5besWaitState(true,true,5))break;out[@"keeperExitObserved"]=@YES;
  if(!pfEmpty()||envara_app_scope_gid_absent((gid_t)c.gid)!=1||!r5besSignal(&c,false,SIGKILL)||!r5besWaitState(false,true,5))break;out[@"controllerExitObserved"]=@YES;
  out[@"gate"]=@"actual-core-and-front-absence-after-parent-exit";
  if(!r5besChildrenFinalAbsent(&c,10))break;NSDictionary*finalChild=r5besApplicationChildObservation(&c);if(!finalChild||![finalChild[@"state"]isEqual:@"absent"])break;out[@"applicationChildObservation"]=finalChild;out[@"coreFinalAbsent"]=out[@"frontFinalAbsent"]=@YES;
  if(!r5besInterfaceAbsent(&c)||!r5besPortObservation(&c,false)||!pfEmpty())break;out[@"ownedInterfaceAbsent"]=@YES;out[@"ownedListenerAbsent"]=@YES;
  out[@"gate"]=@"exclusive-registry-after-custodian-exit";if(flock(c.parent,LOCK_EX|LOCK_NB))break;c.lock=openat(c.runtime,"registry.lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  if(!secureFD(c.lock,false,0600)||flock(c.lock,LOCK_EX|LOCK_NB)||!r5besPrivateStable(&c)||!r5besAfterCustodianScope(&c))break;
  out[@"gate"]=@"exact-issued-native-retirement-proof";NSDictionary*proof=r5besRootRequest(&c,false);
  if(!r5besRootProof(proof)||!boolValue(proof[@"hookInstalled"],true)||!boolValue(proof[@"ownedRootHookVerified"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!pfEmpty())break;
  out[@"gate"]=@"release-only-recorded-pf-reference";out[@"ownedPFReferenceReleaseAttempted"]=@YES;int code=-1;char*release[]={(char*)"/sbin/pfctl",(char*)"-X",(char*)[c.record[@"ownedPFReference"][@"token"]UTF8String],NULL};
  if(!r5besAfterCustodianScope(&c)||!command(release,true,&code)||code)break;out[@"ownedPFReferenceReleased"]=@YES;
  proof=r5besRootRequest(&c,false);if(!r5besRootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||![proof[@"runLedgerState"]isEqual:@"issued"]||!r5besAfterCustodianScope(&c))break;
  out[@"gate"]=@"one-exact-issued-root-hook-delete";out[@"rootHookDeleteAttempted"]=@YES;(void)r5besRootRequest(&c,true);proof=r5besRootRequest(&c,false);
  if(!r5besRootProof(proof)||!boolValue(proof[@"pfDisabled"],true)||!boolValue(proof[@"ownedRootHookRemoved"],true)||!boolValue(proof[@"originalRootRestored"],true)||!boolValue(proof[@"receiptRetired"],true)||
   !boolValue(proof[@"namespaceReclaimed"],true)||![proof[@"namespaceState"]isEqual:@"absent"]||![proof[@"runLedgerState"]isEqual:@"retired"])break;c.root_retired=true;if(!r5besAfterCustodianScope(&c))break;
  out[@"rootHookRemoved"]=out[@"originalRootRestored"]=out[@"receiptRetired"]=out[@"namespaceReclaimed"]=@YES;
  out[@"gate"]=@"one-dedicated-group-removal";struct group*g=getgrgid((gid_t)c.gid);NSString*name=[NSString stringWithFormat:@"_envara_pf_%llu",(unsigned long long)c.gid];
  if(!g||g->gr_gid!=c.gid||strcmp(g->gr_name,name.UTF8String)||(g->gr_mem&&g->gr_mem[0])||!r5besGroupInventory((gid_t)c.gid,true)||!r5besAfterCustodianScope(&c))break;
  NSString*path=[@"/Groups/"stringByAppendingString:name];char*deleteGroup[]={(char*)"/usr/bin/dscl",(char*)".",(char*)"-delete",(char*)path.UTF8String,NULL};out[@"ownedGroupDeleteAttempted"]=@YES;
  if(!command(deleteGroup,true,&code)||code||!r5besGroupAbsent((gid_t)c.gid))break;out[@"ownedGroupRemoved"]=@YES;
  out[@"gate"]=@"owned-scope-host-observation";NSDictionary*after=r5besHostWithoutOwnedRoute(&c),*comparison=r5besCompareHost(hostBefore,after);
  if(!comparison||!r5besAfterCustodianScope(&c))break;c.host_before=hostBefore;c.host_after=after;c.host_comparison=comparison;
  out[@"hostComparisonAvailable"]=@YES;const BOOL matched=[after isEqual:hostBefore];out[@"hostSnapshotsMatched"]=@((BOOL)matched);out[@"recoveryScopeHostNetworkRestored"]=@((BOOL)matched);
  if(!r5besOwnedRetirementFacts(out))break;
  out[@"gate"]=@"held-inode-atomic-private-runtime-archive";if(!r5besArchive(&c,cap,&capi,&beforei,beforeBytes,&intenti,intentBytes,out))break;
  out[@"runtimeArchived"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"cleanupConfirmed"]=@YES;out[@"ok"]=@YES;out[@"reason"]=@"OWNED_SESSION_RECOVERY_COMPLETED";out[@"gate"]=@"owned-session-recovery-complete";
 }while(0);
 if(loaded)r5besClose(&c);else if(c.installed>=0)r5besClose(&c);if(cap>=0)close(cap);return r5besEmit(out);
}
#ifndef R5BES_RECOVERY_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return r5besEmit(r5besOutcome(false));const char*mode=argc==1?"--plan":argv[1];
 if(!strcmp(mode,"--plan")){NSMutableDictionary*out=r5besOutcome(false);out[@"ok"]=@YES;out[@"reason"]=@"INERT_FIXED_LIVE_RECOVERY_PLAN";out[@"mutationEntryLinked"]=@YES;out[@"nativeStatusRequiredAfterCustodianExit"]=@YES;return r5besEmit(out);}
 if(!strcmp(mode,"--inspect-fixed-root"))return r5besRecover(false);
 if(!strcmp(mode,"--cleanup-fixed-root"))return r5besRecover(true);
 return r5besEmit(r5besOutcome(false));
}}
#endif
