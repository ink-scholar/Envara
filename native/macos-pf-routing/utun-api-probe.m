/* Fixed local experiment: one unconfigured sc_unit=0 UTUN and one duplicate.
 * No PF/device write, network configuration, app, group, or route mutation.
 * --plan and nonroot refusals never construct the socket. */
#define _DARWIN_C_SOURCE
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <spawn.h>
#include <grp.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "native.h"
extern int probeKernelGroups(int,gid_t[]) __asm("_getgroups");
#define PROBE_SCHEMA @"envara.macos-utun-api-probe/v1"
static double seconds(void){struct timespec t;return clock_gettime(CLOCK_MONOTONIC,&t)?-1:t.tv_sec+t.tv_nsec/1e9;}
static NSMutableDictionary *probeOutcome(bool plan){return [@{
 @"schema":PROBE_SCHEMA,@"ok":@((BOOL)plan),@"reason":plan?@"INERT_FIXED_UTUN_API_PLAN":@"FIXED_UTUN_API_PROBE_UNCONFIRMED",@"gate":@"not-started",
 @"readOnly":@((BOOL)plan),@"cleanupConfirmed":@NO,@"cleanupUncertain":@YES,@"ready":@NO,@"protected":@NO,@"productionReady":@NO,
 @"socketCreated":@NO,@"soleKernelRootCredentialsVerified":@NO,
 @"getsocknameReturn":@(-1),@"getsocknameErrno":@0,@"ctlInfoReturn":@(-1),@"ctlInfoErrno":@0,
 @"getpeernameReturn":@(-1),@"getpeernameErrno":@0,@"ifnameReturn":@(-1),@"ifnameErrno":@0,
 @"typeVerified":@NO,@"ctlIDMatched":@NO,@"peerAddressVerified":@NO,@"unitMatched":@NO,@"nameVerified":@NO,
 @"duplicateCreated":@NO,@"duplicateIdentityVerified":@NO,@"duplicateClosed":@NO,@"duplicateEBADF":@NO,
 @"originalHeldAfterDuplicateClose":@NO,@"interfacePresentAfterDuplicateClose":@NO,@"originalClosed":@NO,@"originalEBADF":@NO,@"interfaceAbsent":@NO,
 @"hostComparisonAvailable":@NO,@"routesMatched":@NO,@"dnsMatched":@NO,@"natMatched":@NO,@"rootPFMatched":@NO,@"pfConfigMatched":@NO,@"currentHostNetworkUnchanged":@NO,
 @"originalHostBaselineVerified":@NO,@"PFWriteExecuted":@NO,@"routeWriteExecuted":@NO,@"DNSWriteExecuted":@NO,@"MTUWriteExecuted":@NO,
 @"IPConfigurationExecuted":@NO,@"coreLaunched":@NO,@"groupChanged":@NO,@"applicationLaunchExecuted":@NO
 } mutableCopy];}
static int emit(NSDictionary*out){NSData*d=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingWithoutEscapingSlashes error:NULL];if(!d||d.length>16384)return 1;const char*p=d.bytes;size_t used=0;while(used<d.length){ssize_t n=write(1,p+used,d.length-used);if(n<0&&errno==EINTR)continue;if(n<=0)return 1;used+=(size_t)n;}return write(1,"\n",1)==1?0:1;}
static bool credentials(void){gid_t g[16];if(geteuid()!=0||setgroups(1,(gid_t[]){0})||setgid(0)||setuid(0))return false;return getuid()==0&&geteuid()==0&&getgid()==0&&getegid()==0&&probeKernelGroups(16,g)==1&&g[0]==0;}
static bool sameSocket(const struct stat*a,const struct stat*b){return S_ISSOCK(a->st_mode)&&S_ISSOCK(b->st_mode)&&a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_mode==b->st_mode;}
static bool closedFD(int fd){errno=0;return fcntl(fd,F_GETFD)==-1&&errno==EBADF;}
static int interfacePresence(const char*name){struct ifaddrs*list=NULL;if(!name||!name[0]||getifaddrs(&list))return -1;bool present=false;for(struct ifaddrs*p=list;p;p=p->ifa_next)if(p->ifa_name&&!strcmp(p->ifa_name,name))present=true;freeifaddrs(list);return present?1:0;}
static void observation(NSMutableDictionary*out,NSString*name,int result,int error){out[[name stringByAppendingString:@"Return"]]=@(result);out[[name stringByAppendingString:@"Errno"]]=@(result==0?0:error);}
static bool inspectSocket(int fd,const char*expected,NSMutableDictionary*out){
 struct sockaddr_ctl local={0},peer={0};socklen_t n=sizeof(local);errno=0;int r=getsockname(fd,(struct sockaddr*)&local,&n);observation(out,@"getsockname",r,errno);
 struct ctl_info ctl={0};strlcpy(ctl.ctl_name,UTUN_CONTROL_NAME,sizeof(ctl.ctl_name));errno=0;r=ioctl(fd,CTLIOCGINFO,&ctl);observation(out,@"ctlInfo",r,errno);bool info=r==0&&ctl.ctl_id!=0;
 n=sizeof(peer);errno=0;r=getpeername(fd,(struct sockaddr*)&peer,&n);observation(out,@"getpeername",r,errno);
 bool address=r==0&&n==sizeof(peer)&&peer.sc_len==sizeof(peer)&&peer.sc_family==AF_SYSTEM&&peer.ss_sysaddr==AF_SYS_CONTROL&&peer.sc_id&&peer.sc_unit;
 out[@"peerAddressVerified"]=@((BOOL)address);out[@"ctlIDMatched"]=@((BOOL)(info&&address&&peer.sc_id==ctl.ctl_id));
 char name[IFNAMSIZ]={0};n=sizeof(name);errno=0;r=getsockopt(fd,SYSPROTO_CONTROL,UTUN_OPT_IFNAME,name,&n);observation(out,@"ifname",r,errno);
 bool named=r==0&&n>1&&n<=sizeof(name)&&memchr(name,0,n)&&!strcmp(name,expected)&&!strncmp(name,"utun",4)&&name[4];
 unsigned index=0;if(named){char*end=NULL;errno=0;unsigned long x=strtoul(name+4,&end,10);named=!errno&&end&&!*end&&x<UINT32_MAX;index=(unsigned)x;}
 out[@"nameVerified"]=@((BOOL)named);out[@"unitMatched"]=@((BOOL)(named&&address&&peer.sc_unit==index+1));
 int type=0;n=sizeof(type);out[@"typeVerified"]=@((BOOL)(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)==0&&n==sizeof(type)&&type==SOCK_DGRAM));
 return [out[@"typeVerified"]boolValue]&&[out[@"ctlIDMatched"]boolValue]&&[out[@"peerAddressVerified"]boolValue]&&[out[@"unitMatched"]boolValue]&&named;
}
static NSData *fixedRead(unsigned command){
 static char *const commands[][4]={{"/usr/sbin/netstat","-rn",NULL},{"/usr/sbin/scutil","--dns",NULL},{"/sbin/pfctl","-sn",NULL},{"/sbin/pfctl","-sr",NULL}};
 if(command>=4)return nil;struct stat executable;if(lstat(commands[command][0],&executable)||!S_ISREG(executable.st_mode)||executable.st_uid||(executable.st_mode&0022))return nil;
 int p[2];if(pipe(p))return nil;if(fcntl(p[0],F_SETFD,FD_CLOEXEC)||fcntl(p[1],F_SETFD,FD_CLOEXEC)||fcntl(p[0],F_SETFL,O_NONBLOCK)){close(p[0]);close(p[1]);return nil;}
 posix_spawn_file_actions_t a;posix_spawnattr_t s;bool ai=false,si=false;int error=posix_spawn_file_actions_init(&a);if(!error)ai=true;if(!error){error=posix_spawnattr_init(&s);if(!error)si=true;}
 if(!error)error=posix_spawnattr_setflags(&s,POSIX_SPAWN_CLOEXEC_DEFAULT);
 if(!error)error=posix_spawn_file_actions_adddup2(&a,p[1],1);
 if(!error)error=posix_spawn_file_actions_addopen(&a,0,"/dev/null",O_RDONLY,0);
 if(!error)error=posix_spawn_file_actions_addopen(&a,2,"/dev/null",O_WRONLY,0);
 for(int fd=0;fd<3&&!error;fd++)error=posix_spawn_file_actions_addinherit_np(&a,fd);
 char*env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C","LANG=C",NULL};pid_t child=-1;
 if(!error)error=posix_spawn(&child,commands[command][0],&a,&s,commands[command],env);
 if(si)posix_spawnattr_destroy(&s);if(ai)posix_spawn_file_actions_destroy(&a);close(p[1]);if(error){close(p[0]);return nil;}
 NSMutableData*d=[NSMutableData data];bool eof=false,ended=false,valid=true;int status=0;double deadline=seconds()+3;
 while(seconds()>=0&&seconds()<deadline&&(!eof||!ended)){
  if(!ended){pid_t got=waitpid(child,&status,WNOHANG);if(got==child)ended=true;else if(got<0&&errno!=EINTR){valid=false;break;}}
  if(eof){poll(NULL,0,5);continue;}struct pollfd item={p[0],POLLIN|POLLHUP,0};int ready=poll(&item,1,25);if(ready<0&&errno==EINTR)continue;if(ready<0){valid=false;break;}
  if(ready){char b[4096];ssize_t count=read(p[0],b,sizeof(b));if(count>0&&d.length+(NSUInteger)count<=131072)[d appendBytes:b length:(NSUInteger)count];else if(!count)eof=true;else if(count<0&&(errno==EINTR||errno==EAGAIN))continue;else{valid=false;break;}}
 }
 close(p[0]);if(!ended){(void)kill(child,SIGKILL);for(int i=0;i<100;i++){pid_t got=waitpid(child,&status,WNOHANG);if(got==child){ended=true;break;}if(got<0&&errno!=EINTR)break;poll(NULL,0,10);}}
 return valid&&ended&&eof&&WIFEXITED(status)&&WEXITSTATUS(status)==0?d:nil;
}
static NSString *routes(NSData*d){NSString*t=[[NSString alloc]initWithData:d encoding:NSUTF8StringEncoding];if(!t)return nil;NSMutableArray*rows=[NSMutableArray array];NSString*family=nil;NSArray*header=nil;
 for(NSString*raw in [t componentsSeparatedByString:@"\n"]){NSString*line=[raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if(!line.length||[line isEqual:@"Routing tables"])continue;
  if([line isEqual:@"Internet:"]||[line isEqual:@"Internet6:"]){family=line;header=nil;continue;}
  NSArray*f=[[line componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet]filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];if([line hasPrefix:@"Destination "]){header=f;continue;}if(!family||!header)return nil;
  NSMutableArray*v=[NSMutableArray arrayWithObject:family];for(NSString*k in @[@"Destination",@"Gateway",@"Flags",@"Netif"]){NSUInteger i=[header indexOfObject:k];if(i==NSNotFound||i>=f.count)return nil;[v addObject:f[i]];}[rows addObject:[v componentsJoinedByString:@"|"]];
 }return rows.count?[[rows sortedArrayUsingSelector:@selector(compare:)]componentsJoinedByString:@"\n"]:nil;}
static NSDictionary *snapshot(void){NSMutableDictionary*out=[NSMutableDictionary dictionary];NSArray*keys=@[@"routes",@"dns",@"nat",@"rootPF"];
 for(unsigned i=0;i<4;i++){NSData*d=fixedRead(i);if(!d)return nil;if(i==0){NSString*t=routes(d);if(!t)return nil;d=[t dataUsingEncoding:NSUTF8StringEncoding];}out[keys[i]]=d;}
 int fd=open("/private/etc/pf.conf",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);struct stat a,b;if(fd<0||fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_uid||(a.st_mode&0022)||a.st_nlink!=1||a.st_size<0||a.st_size>1048576){if(fd>=0)close(fd);return nil;}
 NSMutableData*d=[NSMutableData data];char bytes[4096];ssize_t count;while((count=read(fd,bytes,sizeof(bytes)))>0&&d.length+(NSUInteger)count<=1048576)[d appendBytes:bytes length:(NSUInteger)count];bool stable=count==0&&!fstat(fd,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec&&d.length==(NSUInteger)a.st_size;close(fd);if(!stable)return nil;out[@"pfConfig"]=d;return out;}
static void comparison(NSMutableDictionary*out,NSDictionary*before,NSDictionary*after){if(!before||!after)return;out[@"hostComparisonAvailable"]=@YES;bool matched=true;for(NSString*k in @[@"routes",@"dns",@"nat",@"rootPF",@"pfConfig"]){BOOL equal=[before[k]isEqual:after[k]];out[[k stringByAppendingString:@"Matched"]]=@(equal);matched=matched&&equal;}out[@"currentHostNetworkUnchanged"]=@((BOOL)matched);}
static bool finishProbe(NSMutableDictionary*out){NSArray*required=@[@"socketCreated",@"soleKernelRootCredentialsVerified",@"typeVerified",@"ctlIDMatched",@"peerAddressVerified",@"unitMatched",@"nameVerified",@"duplicateCreated",@"duplicateIdentityVerified",@"duplicateClosed",@"duplicateEBADF",@"originalHeldAfterDuplicateClose",@"interfacePresentAfterDuplicateClose",@"originalClosed",@"originalEBADF",@"interfaceAbsent",@"hostComparisonAvailable",@"routesMatched",@"dnsMatched",@"natMatched",@"rootPFMatched",@"pfConfigMatched",@"currentHostNetworkUnchanged"];
 for(NSString*k in required)if(![out[k]isEqual:@YES]||CFGetTypeID((__bridge CFTypeRef)out[k])!=CFBooleanGetTypeID())return false;
 for(NSString*k in @[@"ctlInfo",@"getpeername",@"ifname"]){NSNumber*r=out[[k stringByAppendingString:@"Return"]],*e=out[[k stringByAppendingString:@"Errno"]];if(r.intValue||e.intValue)return false;}
 int named=[out[@"getsocknameReturn"]intValue],error=[out[@"getsocknameErrno"]intValue];if((named!=0&&named!=-1)||(named==0&&error!=0)||(named==-1&&(error<1||error>1024)))return false;
 out[@"ok"]=@YES;out[@"cleanupConfirmed"]=@YES;out[@"cleanupUncertain"]=@NO;out[@"reason"]=@"FIXED_UTUN_API_PROBE_COMPLETED";out[@"gate"]=@"probe-complete";return true;}
static NSDictionary *probe(void){NSMutableDictionary*out=probeOutcome(false);out[@"gate"]=@"root-credentials";if(!credentials())return out;out[@"soleKernelRootCredentialsVerified"]=@YES;
 struct sigaction chld={0};chld.sa_handler=SIG_DFL;sigemptyset(&chld.sa_mask);if(sigaction(SIGCHLD,&chld,NULL))return out;
 out[@"gate"]=@"host-before";NSDictionary*before=snapshot();if(!before)return out;
 int original=-1,duplicate=-1;char name[IFNAMSIZ]={0};struct stat identity,copy,current;out[@"gate"]=@"utun-open";original=envara_utun_open(name,sizeof(name));if(original<0)return out;out[@"socketCreated"]=@YES;
 out[@"gate"]=@"socket-observation";bool safe=!fstat(original,&identity)&&inspectSocket(original,name,out)&&if_nametoindex(name)>0&&interfacePresence(name)==1;
 if(safe){out[@"gate"]=@"duplicate";duplicate=fcntl(original,F_DUPFD_CLOEXEC,3);if(duplicate>=0){out[@"duplicateCreated"]=@YES;out[@"duplicateIdentityVerified"]=@((BOOL)(!fstat(duplicate,&copy)&&sameSocket(&identity,&copy)));}safe=duplicate>=0&&[out[@"duplicateIdentityVerified"]boolValue];}
 if(duplicate>=0){out[@"gate"]=@"duplicate-close";out[@"duplicateClosed"]=@((BOOL)(close(duplicate)==0));out[@"duplicateEBADF"]=@((BOOL)closedFD(duplicate));duplicate=-1;
  out[@"originalHeldAfterDuplicateClose"]=@((BOOL)(fcntl(original,F_GETFD)>=0&&!fstat(original,&current)&&sameSocket(&identity,&current)));out[@"interfacePresentAfterDuplicateClose"]=@((BOOL)(if_nametoindex(name)>0&&interfacePresence(name)==1));}
 out[@"gate"]=@"original-close";out[@"originalClosed"]=@((BOOL)(close(original)==0));out[@"originalEBADF"]=@((BOOL)closedFD(original));original=-1;
 out[@"gate"]=@"interface-absence";for(int i=0;i<200;i++){errno=0;unsigned index=if_nametoindex(name);int error=errno;if(!index&&error==ENXIO&&interfacePresence(name)==0){errno=0;if(if_nametoindex(name)==0&&errno==ENXIO&&interfacePresence(name)==0){out[@"interfaceAbsent"]=@YES;break;}}poll(NULL,0,10);}
 out[@"gate"]=@"host-after";NSDictionary*after=snapshot();comparison(out,before,after);if(safe)(void)finishProbe(out);return out;}
#ifndef UTUN_PROBE_INERT
int main(int argc,char**argv){@autoreleasepool{if(argc==2&&!strcmp(argv[1],"--plan"))return emit(probeOutcome(true));if(argc!=2||strcmp(argv[1],"--probe-fixed-root")){emit(probeOutcome(false));return 1;}NSDictionary*out=probe();int result=emit(out);return result||![out[@"ok"]boolValue]?1:0;}}
#endif
