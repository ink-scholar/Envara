/* Read-only, unprivileged owned-fixture TCP witness. No PF/DNS, signals, or
 * privilege operations. Tuple snapshots are NOT a race-free authorization.
 * ABI: Apple xnu f6217f891ac0bb64f3d375211650a4c1ff8ca1ea bsd/sys/proc_info.h. */
#include <sys/socket.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int refuse(const char *reason){printf("{\"verified\":false,\"raceFree\":false,\"reason\":\"%s\"}\n",reason);return 0;}
static int info(pid_t pid,struct proc_bsdinfo *p){return proc_pidinfo(pid,PROC_PIDTBSDINFO,0,p,sizeof(*p))==(int)sizeof(*p) && p->pbi_pid==(uint32_t)pid && p->pbi_start_tvsec && p->pbi_uid==getuid() && p->pbi_ruid==getuid();}
static int same(const struct proc_bsdinfo *a,const struct proc_bsdinfo *b){return a->pbi_pid==b->pbi_pid && a->pbi_uid==b->pbi_uid && a->pbi_gid==b->pbi_gid && a->pbi_rgid==b->pbi_rgid && a->pbi_start_tvsec==b->pbi_start_tvsec && a->pbi_start_tvusec==b->pbi_start_tvusec;}
static void identity(const struct proc_bsdinfo *p){printf("{\"pid\":%u,\"uid\":%u,\"gid\":%u,\"birthSec\":%llu,\"birthUsec\":%llu}",p->pbi_pid,p->pbi_uid,p->pbi_gid,(unsigned long long)p->pbi_start_tvsec,(unsigned long long)p->pbi_start_tvusec);}
typedef struct {int fd,matches;uint64_t generation;} Match;
static int scan(pid_t pid,unsigned local,unsigned remote,Match *out){
    int length=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);if(length<=0 || length>16384)return 0;
    struct proc_fdinfo *fds=calloc(1,(size_t)length+sizeof(*fds)*16);if(!fds)return 0;
    int count=proc_pidinfo(pid,PROC_PIDLISTFDS,0,fds,length+(int)sizeof(*fds)*16);if(count<=0 || count%sizeof(*fds)){free(fds);return 0;}
    out->matches=0;
    for(size_t i=0;i<(size_t)count/sizeof(*fds);i++)if(fds[i].proc_fdtype==PROX_FDTYPE_SOCKET){
      struct socket_fdinfo s;if(proc_pidfdinfo(pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s))!=(int)sizeof(s)){free(fds);return 0;}
      if(s.psi.soi_kind!=SOCKINFO_TCP || s.psi.soi_family!=AF_INET || s.psi.soi_protocol!=IPPROTO_TCP)continue;
      struct in_sockinfo *in=&s.psi.soi_proto.pri_tcp.tcpsi_ini;
      if(ntohs((uint16_t)in->insi_lport)==local && ntohs((uint16_t)in->insi_fport)==remote &&
        in->insi_laddr.ina_46.i46a_addr4.s_addr==htonl(INADDR_LOOPBACK) && in->insi_faddr.ina_46.i46a_addr4.s_addr==htonl(INADDR_LOOPBACK)){
        out->matches++;out->fd=fds[i].proc_fd;out->generation=in->insi_gencnt;
      }
    }free(fds);return 1;
}
static int number(const char *raw,unsigned long long *out){char *end=NULL;errno=0;*out=strtoull(raw,&end,10);return !errno && end && *raw && !*end && raw[0]!='-';}
int main(int argc,char **argv){
    if(getuid()==0 || geteuid()!=getuid() || argc<3)return 2;
    unsigned long long values[7];for(int i=2;i<argc;i++)if(i-2>=7 || !number(argv[i],&values[i-2]))return 2;
    if(values[0]<2 || values[0]>INT32_MAX)return 2;pid_t pid=(pid_t)values[0];struct proc_bsdinfo before,after;
    if(!info(pid,&before))return refuse("IDENTITY_UNREADABLE");
    if(argc==3 && !strcmp(argv[1],"identity")){if(!info(pid,&after) || !same(&before,&after))return refuse("IDENTITY_UNSTABLE");
      printf("{\"verified\":true,\"identity\":");identity(&after);puts("}");return 0;}
    if(argc!=9 || strcmp(argv[1],"witness") || values[5]<1 || values[5]>65535 || values[6]<1 || values[6]>65535)return 2;
    if(before.pbi_start_tvsec!=values[1] || before.pbi_start_tvusec!=values[2] || before.pbi_uid!=values[3] ||
      before.pbi_gid!=values[4] || before.pbi_rgid!=values[4])return refuse("REGISTERED_IDENTITY_MISMATCH");
    Match first={0},second={0};
    if(!scan(pid,(unsigned)values[5],(unsigned)values[6],&first) || !scan(pid,(unsigned)values[5],(unsigned)values[6],&second))return refuse("DESCRIPTORS_UNREADABLE");
    if(first.matches!=1 || second.matches!=1)return refuse(first.matches>1 || second.matches>1?"AMBIGUOUS_TUPLE":"TUPLE_UNMATCHED");
    if(!first.generation || first.fd!=second.fd || first.generation!=second.generation || !info(pid,&after) || !same(&before,&after))return refuse("TUPLE_OR_IDENTITY_UNSTABLE");
    printf("{\"verified\":true,\"identity\":");identity(&after);
    printf(",\"witness\":{\"nativeVerified\":true,\"stable\":true,\"raceFree\":false,\"matchCount\":1,\"fd\":%d,\"pcbGeneration\":\"%llx\",\"clientHost\":\"127.0.0.1\",\"clientPort\":%llu,\"frontHost\":\"127.0.0.1\",\"frontPort\":%llu}}\n",first.fd,(unsigned long long)first.generation,values[5],values[6]);return 0;
}
