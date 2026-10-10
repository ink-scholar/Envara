/* One fixed f99/run145 READONLY observation. Imported frozen definitions are
 * parsing/read helpers only; optimizer/link verification excludes recovery.
 * No cleanup, PF IOCTL, recorded-process signal or authorization entry. */
#define F99_RECOVERY_INERT 1
#include "recovery-app-f99-run145-fd-capacity.m"
#define CUSTODY_SCHEMA @"envara.macos-pf-live-custody-diagnostic/v1"
static NSMutableDictionary *custodyFDOutcome(void){return [@{
 @"stage":@"not-started",@"queryBytes":@0,@"readBytes":@0,@"bufferBytes":@0,@"queryErrno":@0,@"readErrno":@0,@"metadataErrno":@0,
 @"completeList":@NO,@"metadataComplete":@NO,@"fdCount":@0,@"socketCount":@0,@"ipv4TCPListenCount":@0,@"exactListenerTupleCount":@0,
 @"expectedListenerCredentialCount":@0,@"listenerUID":@0,@"listenerGID":@0,@"utunControlCount":@0,@"exactUTunUnitCount":@0}mutableCopy];}
static NSMutableDictionary *custodyNetstatOutcome(void){return [@{
 @"firstExit":@-1,@"secondExit":@-1,@"firstBytes":@0,@"secondBytes":@0,@"firstTextAvailable":@NO,@"secondTextAvailable":@NO,
 @"firstEmpty":@NO,@"secondEmpty":@NO,@"firstGrammarMatched":@NO,@"secondGrammarMatched":@NO}mutableCopy];}
static NSMutableDictionary *custodyOutcome(void){return [@{
 @"schema":CUSTODY_SCHEMA,@"manifestSHA256":@MF,@"runId":CANARY_RUN,@"environmentId":FIXED_ENV,
 @"readOnly":@YES,@"ok":@NO,@"reason":@"FIXED_CUSTODY_DIAGNOSTIC_UNCONFIRMED",@"gate":@"not-started",
 @"cleanupConfirmed":@NO,@"cleanupPermitted":@NO,@"cleanupUncertain":@YES,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,
 @"recordedProcessSignalExecuted":@NO,@"PFWriteExecuted":@NO,@"runtimeWriteExecuted":@NO,@"authorizationRequested":@NO,
 @"sealedContextVerified":@NO,@"fixedRecordBindingMatched":@NO,@"coreAbsent":@NO,@"frontAbsent":@NO,
 @"controllerExactIdentity":@NO,@"keeperExactIdentity":@NO,@"identityStableBeforeFDRead":@NO,@"identityStableBetweenFDReads":@NO,
 @"identityStableAfterFDRead":@NO,@"interfaceIndex":@0,@"fdListsStable":@NO,@"socketMetadataStable":@NO,@"uniqueCurrentCustodyObserved":@NO,
 @"privateContextStable":@NO,@"firstFD":custodyFDOutcome(),@"secondFD":custodyFDOutcome(),@"netstat":custodyNetstatOutcome()}mutableCopy];}
static bool custodyListSize(int capacity,int buffer,int returned){return f99FDBytes(capacity,buffer,returned);}
static int custodyErrno(int n){return MIN(1024,MAX(0,n));}
static bool custodyContextStable(F99Context*c){return
 unchanged(c->runtime,"registry.json",&c->registry_i,c->registry_bytes)&&unchanged(c->runtime,"registry.lock",&c->lock_i,c->lock_bytes)&&
 unchanged(c->run,"app-bound-lease.json",&c->lease_i,c->lease_bytes)&&f99NamedDirectory(c->parent,"io.envara.pf-runtime",c->runtime,&c->runtime_i)&&
 f99NamedDirectory(c->runtime,CANARY_RUN.UTF8String,c->run,&c->run_i)&&f99NamedDirectory(c->run,[c->lease[@"realmId"]UTF8String],c->state,&c->state_i);
}
/* This deliberately stops before the recovery custody/GID/PF/journal gates.
 * It only reads the same strict typed private context and inventory. */
static bool custodyLoad(F99Context*c,NSMutableDictionary*out){
 *c=(F99Context){.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};
 out[@"gate"]=@"fixed-host-abi-pins";if(!f99HostPins())return false;
 out[@"gate"]=@"installed-inventory";c->installed=verifiedInstallation(MIN(rootDeadline,seconds()+30));if(c->installed<0)return false;
 out[@"gate"]=@"fixed-private-context";c->parent=directory(INSTALL_PARENT);c->runtime=directory(RUNTIME);if(c->parent<0||!secureFD(c->runtime,true,0700)||fstat(c->runtime,&c->runtime_i))return false;
 c->registry_bytes=privateRead(c->runtime,"registry.json",65536,&c->registry_i);c->record=strictJSON(c->registry_bytes,65536);c->lock_bytes=privateRead(c->runtime,"registry.lock",4096,&c->lock_i);NSDictionary*lock=strictJSON(c->lock_bytes,4096);
 if(!keys(lock,@[@"runId",@"pid",@"anchor"])||![lock[@"runId"]isEqual:CANARY_RUN]||![lock[@"pid"]isEqual:@F99_CONTROLLER_PID]||![lock[@"anchor"]isEqual:CANARY_ANCHOR])return false;
 c->run=openat(c->runtime,CANARY_RUN.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(!secureFD(c->run,true,0700)||fstat(c->run,&c->run_i))return false;
 c->lease_bytes=privateRead(c->run,"app-bound-lease.json",16384,&c->lease_i);c->lease=strictJSON(c->lease_bytes,16384);NSDictionary*transport=nil;
 if(!liveShape(c->record,c->lease,c->lease_bytes,&transport,&c->gid))return false;c->transport=transport;
 c->state=openat(c->run,[c->lease[@"realmId"]UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(!secureFD(c->state,true,0700)||fstat(c->state,&c->state_i)||!names(c->state,@[])||!names(c->runtime,@[@"registry.json",@"registry.lock",CANARY_RUN])||
 !names(c->run,@[@"app-bound-lease.json",c->lease[@"realmId"],@"app-filter-events"])||!absent(c->run,F99_INTENT)||!absent(c->parent,F99_CAPSULE)||!custodyContextStable(c))return false;
 out[@"sealedContextVerified"]=@YES;return true;
}
static bool custodyBindings(F99Context*c,NSMutableDictionary*out){
 out[@"fixedRecordBindingMatched"]=@((BOOL)([c->lease[@"controllerPid"]isEqual:@F99_CONTROLLER_PID]&&[c->lease[@"controllerBirth"]isEqual:F99_CONTROLLER_BIRTH]&&
 [c->transport[@"keeperPID"]isEqual:@F99_KEEPER_PID]&&[c->transport[@"keeperBirth"]isEqual:F99_KEEPER_BIRTH]&&[c->transport[@"corePID"]isEqual:@76086]&&
 [c->transport[@"coreBirth"]isEqual:F99_CORE_BIRTH]&&[c->transport[@"frontPID"]isEqual:@76088]&&[c->transport[@"frontBirth"]isEqual:F99_FRONT_BIRTH]&&c->gid==7100));
 NSDictionary*core=processObservation(@"core",@76086,F99_CORE_BIRTH,INSTALL "/mihomo",F99_KEEPER_PID),*front=processObservation(@"front",@76088,F99_FRONT_BIRTH,INSTALL "/node",F99_KEEPER_PID);
 out[@"coreAbsent"]=@((BOOL)[core[@"state"]isEqual:@"absent"]);out[@"frontAbsent"]=@((BOOL)[front[@"state"]isEqual:@"absent"]);
 out[@"controllerExactIdentity"]=@((BOOL)f99BSDIdentity(F99_CONTROLLER_PID,F99_CONTROLLER_BIRTH,INSTALL "/node",76007,NULL));
 out[@"keeperExactIdentity"]=@((BOOL)f99BSDIdentity(F99_KEEPER_PID,F99_KEEPER_BIRTH,NATIVE,F99_CONTROLLER_PID,NULL));
 for(NSString*k in @[@"fixedRecordBindingMatched",@"coreAbsent",@"frontAbsent",@"controllerExactIdentity",@"keeperExactIdentity"]){if(![out[k]boolValue]){out[@"gate"]=k;return false;}}
 return true;
}
/* Independent observer: mismatch credentials/tuple/unit are reported, never
 * discarded by recovery's admission predicates. Raw identity words remain
 * private memory solely for two-pass equality. No socket is opened here. */
static bool custodyReadPass(pid_t pid,F99Context*c,F99FDPass*p,NSMutableDictionary*out){
 memset(p,0,sizeof(*p));out[@"stage"]=@"fd-query";errno=0;p->capacity=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
 out[@"queryBytes"]=@(MAX(0,p->capacity));out[@"queryErrno"]=@(custodyErrno(errno));
 if(p->capacity<=0||p->capacity>65536||p->capacity%(int)sizeof(struct proc_fdinfo))return false;
 int buffer=p->capacity+32*(int)sizeof(struct proc_fdinfo);out[@"bufferBytes"]=@(buffer);out[@"stage"]=@"fd-memory";
 p->list=calloc(1,(size_t)buffer);if(!p->list)return false;errno=0;out[@"stage"]=@"fd-read";p->bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,p->list,buffer);
 out[@"readBytes"]=@(MAX(0,p->bytes));out[@"readErrno"]=@(custodyErrno(errno));bool complete=custodyListSize(p->capacity,buffer,p->bytes);out[@"completeList"]=@((BOOL)complete);if(!complete)return false;
 p->count=p->bytes/(int)sizeof(*p->list);out[@"fdCount"]=@(p->count);p->sockets=calloc((size_t)p->count,sizeof(*p->sockets));out[@"stage"]=@"socket-memory";if(!p->sockets)return false;
 unsigned expectedUnit=0;if(c&&(sscanf([c->transport[@"interfaceName"]UTF8String],"utun%u",&expectedUnit)!=1||expectedUnit==UINT_MAX)){out[@"stage"]=@"interface-name";return false;}
 unsigned listen=0,tuples=0,credentials=0,utuns=0,units=0;uint32_t observedUID=0,observedGID=0;out[@"stage"]=@"socket-metadata";
 for(int i=0;i<p->count;i++){
  if(i&&p->list[i].proc_fd<=p->list[i-1].proc_fd){out[@"stage"]=@"fd-order";return false;}if(p->list[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;
  struct socket_fdinfo s={0};errno=0;int got=proc_pidfdinfo(pid,p->list[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s));out[@"metadataErrno"]=@(custodyErrno(errno));if(got!=sizeof(s))return false;
  F99SocketIdentity*w=&p->sockets[p->socket_count++];w->fd=p->list[i].proc_fd;w->kind=s.psi.soi_kind;w->family=s.psi.soi_family;w->type=s.psi.soi_type;w->protocol=s.psi.soi_protocol;
  w->socket=s.psi.soi_so;w->pcb=s.psi.soi_pcb;w->dev=s.psi.soi_stat.vst_dev;w->inode=s.psi.soi_stat.vst_ino;w->uid=s.psi.soi_stat.vst_uid;w->gid=s.psi.soi_stat.vst_gid;
  if(s.psi.soi_kind==SOCKINFO_TCP){struct in_sockinfo*in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;w->tcp_state=s.psi.soi_proto.pri_tcp.tcpsi_state;w->local_port=(uint16_t)in->insi_lport;w->foreign_port=(uint16_t)in->insi_fport;
   w->local_address=in->insi_laddr.ina_46.i46a_addr4.s_addr;w->foreign_address=in->insi_faddr.ina_46.i46a_addr4.s_addr;
   if(w->family==AF_INET&&w->type==SOCK_STREAM&&w->tcp_state==TSI_S_LISTEN){listen++;
    if(c&&w->local_port==htons([c->transport[@"frontPort"]unsignedShortValue])&&w->local_address==htonl(INADDR_LOOPBACK)){tuples++;observedUID=w->uid;observedGID=w->gid;if(f99ListenerCredentials(w->uid,w->gid,(gid_t)c->gid))credentials++;}}
  }
  if(w->family==AF_SYSTEM&&w->kind==SOCKINFO_KERN_CTL){struct kern_ctl_info*k=&s.psi.soi_proto.pri_kern_ctl;if(!memchr(k->kcsi_name,0,sizeof(k->kcsi_name)))return false;
   w->ctl_id=k->kcsi_id;w->ctl_unit=k->kcsi_unit;memcpy(w->ctl_name,k->kcsi_name,sizeof(w->ctl_name));if(!strcmp(k->kcsi_name,"com.apple.net.utun_control")){utuns++;if(c&&k->kcsi_unit==expectedUnit+1)units++;}}
  out[@"socketCount"]=@(p->socket_count);out[@"ipv4TCPListenCount"]=@(listen);out[@"exactListenerTupleCount"]=@(tuples);out[@"expectedListenerCredentialCount"]=@(credentials);
  out[@"listenerUID"]=@(tuples==1?observedUID:0);out[@"listenerGID"]=@(tuples==1?observedGID:0);out[@"utunControlCount"]=@(utuns);out[@"exactUTunUnitCount"]=@(units);
 }
 out[@"metadataComplete"]=@YES;out[@"stage"]=@"complete";return true;
}
static bool custodyListSame(F99FDPass*a,F99FDPass*b){return a->count>0&&a->bytes==b->bytes&&!memcmp(a->list,b->list,(size_t)a->bytes);}
static bool custodyMetadataSame(F99FDPass*a,F99FDPass*b){return a->socket_count==b->socket_count&&(!a->socket_count||!memcmp(a->sockets,b->sockets,a->socket_count*sizeof(*a->sockets)));}
static void custodyFDObservation(F99Context*c,NSMutableDictionary*out){
 F99FDPass first={0},second={0};out[@"identityStableBeforeFDRead"]=@((BOOL)f99FixedBindings(c));
 bool a=custodyReadPass(F99_KEEPER_PID,c,&first,out[@"firstFD"]);out[@"identityStableBetweenFDReads"]=@((BOOL)f99FixedBindings(c));
 bool b=custodyReadPass(F99_KEEPER_PID,c,&second,out[@"secondFD"]);out[@"identityStableAfterFDRead"]=@((BOOL)f99FixedBindings(c));
 out[@"fdListsStable"]=@((BOOL)(a&&b&&custodyListSame(&first,&second)));out[@"socketMetadataStable"]=@((BOOL)(a&&b&&custodyMetadataSame(&first,&second)));
 out[@"interfaceIndex"]=@(if_nametoindex([c->transport[@"interfaceName"]UTF8String]));NSDictionary*x=out[@"firstFD"],*y=out[@"secondFD"];
 out[@"uniqueCurrentCustodyObserved"]=@((BOOL)([out[@"fdListsStable"]boolValue]&&[out[@"socketMetadataStable"]boolValue]&&
 [out[@"identityStableBeforeFDRead"]boolValue]&&[out[@"identityStableBetweenFDReads"]boolValue]&&[out[@"identityStableAfterFDRead"]boolValue]&&[out[@"interfaceIndex"]unsignedIntValue]>0&&
 [x[@"exactListenerTupleCount"]isEqual:@1]&&[y[@"exactListenerTupleCount"]isEqual:@1]&&[x[@"expectedListenerCredentialCount"]isEqual:@1]&&[y[@"expectedListenerCredentialCount"]isEqual:@1]&&
 [x[@"exactUTunUnitCount"]isEqual:@1]&&[y[@"exactUTunUnitCount"]isEqual:@1]));f99FreeFDPass(&first);f99FreeFDPass(&second);
}
static void custodyNetstat(F99Context*c,NSMutableDictionary*out){
 char*argv[]={(char*)"/usr/sbin/netstat",(char*)"-an",(char*)"-p",(char*)"tcp",(char*)"-f",(char*)"inet",NULL};NSMutableDictionary*n=out[@"netstat"];
 for(unsigned i=0;i<2;i++){int code=-1;NSString*text=command(argv,false,&code);NSString*prefix=i?@"second":@"first";
  n[[prefix stringByAppendingString:@"Exit"]]=@(code);n[[prefix stringByAppendingString:@"Bytes"]]=@([text lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);n[[prefix stringByAppendingString:@"TextAvailable"]]=@((BOOL)(text!=nil));
  n[[prefix stringByAppendingString:@"Empty"]]=@((BOOL)(text!=nil&&text.length==0));n[[prefix stringByAppendingString:@"GrammarMatched"]]=@((BOOL)(text&&code==0&&f99PortRows(text,[c->transport[@"frontPort"]unsignedShortValue],true)));
 }
}
static int custodyInspect(void){
 NSMutableDictionary*out=custodyOutcome();rootDeadline=seconds()+175;out[@"gate"]=@"root-credentials";
 if(!inspectorRootCredentials()||!inspectorChildWaitBoundary())return emitInspection(out);F99Context c={.installed=-1,.parent=-1,.runtime=-1,.run=-1,.state=-1,.lock=-1};
 do{if(!custodyLoad(&c,out))break;if(!custodyBindings(&c,out))break;custodyFDObservation(&c,out);custodyNetstat(&c,out);
  bool stable=custodyContextStable(&c);out[@"privateContextStable"]=@((BOOL)stable);if(!stable){out[@"gate"]=@"private-context-change";break;}
  out[@"ok"]=@YES;out[@"reason"]=@"FIXED_CUSTODY_DIAGNOSTIC_OBSERVED";out[@"gate"]=@"diagnostic-complete";
 }while(0);f99Close(&c);return emitInspection(out);
}
#ifndef CUSTODY_DIAGNOSTIC_INERT
int main(int argc,char**argv){@autoreleasepool{
 if(argc>2)return emitInspection(custodyOutcome());const char*operation=argc==1?"--plan":argv[1];
 if(!strcmp(operation,"--plan")){NSMutableDictionary*out=custodyOutcome();out[@"ok"]=@YES;out[@"reason"]=@"INERT_FIXED_CUSTODY_DIAGNOSTIC_PLAN";return emitInspection(out);}
 if(!strcmp(operation,"--inspect-fixed-root"))return custodyInspect();return emitInspection(custodyOutcome());
}}
#endif
