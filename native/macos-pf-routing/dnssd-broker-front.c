/* Prototype-only DNS-SD Unix front. No system DNS, PF, privilege, or resolver calls.
 * Independent implementation of Apple's 28-byte DNS-SD IPC framing. See
 * dnssd-broker-protocol.mjs for the pinned upstream protocol provenance.
 * All DNS frames remain on a private pipe to the owning resolver broker. */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define CLIENTS 16
#define PEERS 32
#define BODY_MAX 4096
#define FRAME_MAX (28 + BODY_MAX)
#define COMMAND_MAX (2 * FRAME_MAX * 4 + 256)
typedef struct {pid_t pid;uint64_t sec,usec;} Peer;
typedef struct {int fd,errfd,shared,pending;unsigned id,seq,requests;size_t used,needed;uint8_t frame[FRAME_MAX];double deadline;Peer peer;} Client;
static volatile sig_atomic_t stopped=0;
static Peer peers[PEERS];static unsigned peer_count=0,next_id=0;
static Client clients[CLIENTS];
static char fixture_path[PATH_MAX],route[65];
static pid_t owner_pid;static uid_t owner_uid;
static unsigned rejected=0,requests=0;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void stop_signal(int sig){(void)sig;stopped=1;}
static uint32_t u32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return ntohl(v);}
static void event_close(Client *c,const char *reason){
    if(c->errfd>=0)close(c->errfd);if(c->fd>=0)close(c->fd);
    printf("{\"kind\":\"closed\",\"connectionId\":%u,\"reason\":\"%s\"}\n",c->id,reason);fflush(stdout);
    memset(c,0,sizeof(*c));c->fd=-1;c->errfd=-1;
}
static int identity(Peer p){
    struct proc_bsdinfo before,after;char path[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(p.pid<2 || proc_pidinfo(p.pid,PROC_PIDTBSDINFO,0,&before,sizeof(before))!=(int)sizeof(before))return 0;
    if(before.pbi_uid!=owner_uid || before.pbi_ruid!=owner_uid || before.pbi_ppid!=(uint32_t)owner_pid ||
       before.pbi_start_tvsec!=p.sec || before.pbi_start_tvusec!=p.usec)return 0;
    if(proc_pidpath(p.pid,path,sizeof(path))<=0 || strcmp(path,fixture_path))return 0;
    if(proc_pidinfo(p.pid,PROC_PIDTBSDINFO,0,&after,sizeof(after))!=(int)sizeof(after))return 0;
    return after.pbi_uid==before.pbi_uid && after.pbi_ppid==before.pbi_ppid &&
           after.pbi_start_tvsec==before.pbi_start_tvsec && after.pbi_start_tvusec==before.pbi_start_tvusec;
}
static int inspect_peer(int fd,Peer *p){
    pid_t pid=0;uid_t uid;gid_t gid;socklen_t len=sizeof(pid);
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&len)!=0 || len!=sizeof(pid) ||
       getpeereid(fd,&uid,&gid)!=0 || uid!=owner_uid)return 0;
    for(unsigned i=0;i<peer_count;i++)if(peers[i].pid==pid && identity(peers[i])){*p=peers[i];return 1;}
    return 0;
}
static int write_bounded(int fd,const uint8_t *bytes,size_t len){
    double until=now()+0.5;
    while(len){ssize_t n=send(fd,bytes,len,0);if(n>0){bytes+=n;len-=(size_t)n;continue;}
        if(n<0 && errno==EINTR)continue;
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) && now()<until){struct pollfd p={fd,POLLOUT,0};poll(&p,1,10);continue;}
        return 0;}
    return 1;
}
static int error_socket(int fd){struct sockaddr_un addr;socklen_t len=sizeof(addr);int type=0;socklen_t tlen=sizeof(type);
    return getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&tlen)==0 && type==SOCK_STREAM &&
      getsockname(fd,(struct sockaddr*)&addr,&len)==0 && addr.sun_family==AF_UNIX;
}
static void dispatch(Client *c){
    uint32_t op=u32(c->frame+12),flags=u32(c->frame+8),body=u32(c->frame+4);
    if(!identity(c->peer) || ++c->requests>32){event_close(c,"PEER_OR_REQUEST_LIMIT");return;}
    if((flags&~3U) || ((op==1 || op==63) && flags) || (op==63 && (body || c->errfd>=0)) ||
      (op==1 && (body || c->shared || c->errfd>=0)) ||
      (op!=1 && op!=63 && ((c->shared && (c->errfd<0 || !body || c->frame[28]!=0)) || (!c->shared && c->errfd>=0)))){
      event_close(c,"INVALID_ERROR_CHANNEL");return;}
    c->pending=1;c->seq++;c->deadline=now()+4.0;requests++;
    printf("{\"kind\":\"request\",\"connectionId\":%u,\"sequence\":%u,\"shared\":%s,\"errorSocket\":%s,\"peer\":{\"pid\":%d,\"uid\":%u,\"birthSec\":%llu,\"birthUsec\":%llu},\"frameHex\":\"",
      c->id,c->seq,c->shared?"true":"false",c->errfd>=0?"true":"false",c->peer.pid,owner_uid,
      (unsigned long long)c->peer.sec,(unsigned long long)c->peer.usec);
    for(size_t i=0;i<c->used;i++)printf("%02x",c->frame[i]);puts("\"}");fflush(stdout);
}
static void receive_frame(Client *c){
    uint8_t data[FRAME_MAX];char ancillary[CMSG_SPACE(sizeof(int)*4)];
    struct iovec vec={data,c->needed-c->used};struct msghdr msg={0};
    msg.msg_iov=&vec;msg.msg_iovlen=1;msg.msg_control=ancillary;msg.msg_controllen=sizeof(ancillary);
    ssize_t n=recvmsg(c->fd,&msg,0);
    if(n==0){event_close(c,"CLIENT_EOF");return;}
    if(n<0){if(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)event_close(c,"READ_FAILED");return;}
    int invalid=(msg.msg_flags&(MSG_CTRUNC|MSG_TRUNC))!=0;
    for(struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h;h=CMSG_NXTHDR(&msg,h)){
      if(h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS || h->cmsg_len<CMSG_LEN(0)){invalid=1;continue;}
      size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);int *fds=(int*)CMSG_DATA(h);
      for(size_t i=0;i<count;i++){if(c->errfd>=0 || count!=1 || !error_socket(fds[i])){close(fds[i]);invalid=1;}
        else {c->errfd=fds[i];fcntl(c->errfd,F_SETFD,FD_CLOEXEC);fcntl(c->errfd,F_SETFL,O_NONBLOCK);}}
    }
    if(invalid){event_close(c,"INVALID_ANCILLARY");return;}
    memcpy(c->frame+c->used,data,(size_t)n);c->used+=(size_t)n;
    if(c->used==28 && c->needed==28){uint32_t size=u32(c->frame+4);
      if(u32(c->frame)!=1 || size>BODY_MAX){event_close(c,"INVALID_HEADER");return;}c->needed=28+size;}
    if(c->used==c->needed)dispatch(c);
}
static int nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static void command(char *line){
    if(!strncmp(line,"ADD ",4)){
      int pid=0;unsigned long long sec=0,usec=0;char token[65],tail;
      int parsed=sscanf(line,"ADD %d %llu %llu %64s %c",&pid,&sec,&usec,token,&tail);Peer p={pid,sec,usec};
      int ok=parsed==4 && peer_count<PEERS && !strcmp(token,route) && identity(p);
      if(ok){for(unsigned i=0;i<peer_count;i++)if(peers[i].pid==pid)ok=0;}
      if(ok)peers[peer_count++]=p;
      printf("{\"kind\":\"registered\",\"pid\":%d,\"verified\":%s}\n",pid,ok?"true":"false");fflush(stdout);return;
    }
    unsigned id,seq;long error;char hex[COMMAND_MAX],tail;
    if(sscanf(line,"REPLY %u %u %ld %33023s %c",&id,&seq,&error,hex,&tail)!=4 || error>0 || error<INT32_MIN){stopped=1;return;}
    Client *c=NULL;for(int i=0;i<CLIENTS;i++)if(clients[i].fd>=0 && clients[i].id==id)c=&clients[i];
    if(!c || !c->pending || c->seq!=seq)return; /* Late completion of a closed request is inert. */
    if(!identity(c->peer)){event_close(c,"PEER_CHANGED");return;}
    uint8_t bytes[FRAME_MAX*4];size_t count=0;
    if(strcmp(hex,"-")){size_t len=strlen(hex);if(len%2 || len/2>sizeof(bytes)){stopped=1;return;}
      for(size_t i=0;i<len;i+=2){int a=nibble(hex[i]),b=nibble(hex[i+1]);if(a<0||b<0){stopped=1;return;}bytes[count++]=(uint8_t)((a<<4)|b);}}
    uint32_t op=u32(c->frame+12),flags=u32(c->frame+8);int ok=1;
    if(op!=63){uint32_t wire=htonl((uint32_t)(int32_t)error);ok=write_bounded(c->errfd>=0?c->errfd:c->fd,(uint8_t*)&wire,4);}
    if(c->errfd>=0){close(c->errfd);c->errfd=-1;}
    if(ok && count && !(flags&1))ok=write_bounded(c->fd,bytes,count);
    if(!ok || error){event_close(c,ok?"REQUEST_REFUSED":"WRITE_FAILED");return;}
    if(op==1)c->shared=1;
    c->pending=0;c->used=0;c->needed=28;c->deadline=now()+5.0;
}
int main(int argc,char **argv){
    if(argc!=4 || geteuid()!=getuid() || getuid()==0 || strlen(argv[1])>=sizeof(((struct sockaddr_un*)0)->sun_path) ||
      strlen(argv[3])!=36 || strspn(argv[3],"0123456789abcdef-")!=36 || !realpath(argv[2],fixture_path))return 2;
    strcpy(route,argv[3]);owner_pid=getppid();owner_uid=getuid();
    char parent[PATH_MAX];if(strlen(argv[1])>=sizeof(parent))return 2;strcpy(parent,argv[1]);char *last=strrchr(parent,'/');if(!last)return 2;*last=0;
    struct stat dir,entry;if(lstat(parent,&dir)!=0 || !S_ISDIR(dir.st_mode) || dir.st_uid!=owner_uid || (dir.st_mode&077)!=0 ||
      lstat(argv[1],&entry)==0 || errno!=ENOENT)return 2;
    signal(SIGPIPE,stop_signal);signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);
    for(int i=0;i<CLIENTS;i++){clients[i].fd=-1;clients[i].errfd=-1;}
    int listener=socket(AF_UNIX,SOCK_STREAM,0);if(listener<0)return 2;
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;address.sun_len=sizeof(address);strcpy(address.sun_path,argv[1]);
    mode_t previous=umask(077);int bound=bind(listener,(struct sockaddr*)&address,sizeof(address));umask(previous);
    if(bound || listen(listener,CLIENTS) || lstat(argv[1],&entry)!=0){close(listener);return 2;}
    dev_t socket_dev=entry.st_dev;ino_t socket_ino=entry.st_ino;
    fcntl(listener,F_SETFL,O_NONBLOCK);fcntl(listener,F_SETFD,FD_CLOEXEC);fcntl(0,F_SETFL,O_NONBLOCK);
    puts("{\"kind\":\"listening\",\"ready\":false,\"nativePeerVerification\":true}");fflush(stdout);
    char input[COMMAND_MAX];size_t input_used=0;double lifetime=now()+45.0;
    while(!stopped && now()<lifetime){
      struct pollfd items[CLIENTS+2];items[0]=(struct pollfd){0,POLLIN,0};items[1]=(struct pollfd){listener,POLLIN,0};
      for(int i=0;i<CLIENTS;i++)items[i+2]=(struct pollfd){clients[i].fd,clients[i].pending?0:POLLIN,0};
      if(poll(items,CLIENTS+2,50)<0 && errno!=EINTR)break;
      if(items[0].revents&(POLLIN|POLLHUP)){
        ssize_t n=read(0,input+input_used,sizeof(input)-1-input_used);
        if(n==0){stopped=1;break;}if(n>0){input_used+=(size_t)n;input[input_used]=0;char *start=input,*end;
          while((end=strchr(start,'\n'))){*end=0;command(start);start=end+1;}size_t left=input+input_used-start;memmove(input,start,left);input_used=left;
          if(input_used==sizeof(input)-1)stopped=1;}
      }
      if(items[1].revents&POLLIN){int fd=accept(listener,NULL,NULL);if(fd>=0){Peer p;int slot=-1;
        for(int i=0;i<CLIENTS;i++)if(clients[i].fd<0){slot=i;break;}
        if(slot<0 || !inspect_peer(fd,&p)){close(fd);rejected++;puts("{\"kind\":\"peerRejected\"}");fflush(stdout);}
        else {fcntl(fd,F_SETFL,O_NONBLOCK);fcntl(fd,F_SETFD,FD_CLOEXEC);clients[slot]=(Client){.fd=fd,.errfd=-1,.id=++next_id,.needed=28,.deadline=now()+5.0,.peer=p};}}
      }
      for(int i=0;i<CLIENTS;i++)if(clients[i].fd>=0){
        if(now()>clients[i].deadline){event_close(&clients[i],"REQUEST_TIMEOUT");continue;}
        if(items[i+2].revents&(POLLIN|POLLHUP|POLLERR))receive_frame(&clients[i]);
      }
    }
    for(int i=0;i<CLIENTS;i++)if(clients[i].fd>=0)event_close(&clients[i],"BROKER_STOP");close(listener);
    if(lstat(argv[1],&entry)==0 && entry.st_dev==socket_dev && entry.st_ino==socket_ino)unlink(argv[1]);
    printf("{\"kind\":\"stopped\",\"peerRejected\":%u,\"requests\":%u,\"activeConnections\":0}\n",rejected,requests);return 0;
}
