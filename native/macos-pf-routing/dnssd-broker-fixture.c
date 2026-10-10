/* Owned, synthetic-name DNS-SD client. Does not connect to returned addresses. */
#include <dns_sd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int answers=0,callback_error=0,owned_endpoint=-1;static char addresses[8][INET6_ADDRSTRLEN];
static void add_address(int family,const void *raw){
    if(answers<8 && inet_ntop(family,raw,addresses[answers],sizeof(addresses[answers])))answers++;
}
static void query_reply(DNSServiceRef ref,DNSServiceFlags flags,uint32_t index,DNSServiceErrorType error,
 const char *name,uint16_t type,uint16_t rrclass,uint16_t length,const void *data,uint32_t ttl,void *context){
    (void)ref;(void)flags;(void)index;(void)name;(void)rrclass;(void)ttl;(void)context;
    if(error){callback_error=error;return;}if(type==1 && length==4)add_address(AF_INET,data);
    if(type==28 && length==16)add_address(AF_INET6,data);
}
static void addr_reply(DNSServiceRef ref,DNSServiceFlags flags,uint32_t index,DNSServiceErrorType error,
 const char *name,const struct sockaddr *address,uint32_t ttl,void *context){
    (void)ref;(void)flags;(void)index;(void)name;(void)ttl;(void)context;
    if(error){callback_error=error;return;}if(!address)return;
    if(address->sa_family==AF_INET)add_address(AF_INET,&((const struct sockaddr_in*)address)->sin_addr);
    if(address->sa_family==AF_INET6)add_address(AF_INET6,&((const struct sockaddr_in6*)address)->sin6_addr);
}
static void result(int status){
    printf("{\"kind\":\"result\",\"status\":%d,\"callbackError\":%d,\"ownedEndpoint\":%d,\"addresses\":[",status,callback_error,owned_endpoint);
    for(int i=0;i<answers;i++)printf("%s\"%s\"",i?",":"",addresses[i]);puts("]}");fflush(stdout);
}
static int write_all(int fd,const void *raw,size_t length){const unsigned char *bytes=raw;while(length){ssize_t n=write(fd,bytes,length);if(n<=0)return -1;bytes+=n;length-=(size_t)n;}return 0;}
static int read_all(int fd,void *raw,size_t length){unsigned char *bytes=raw;while(length){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,1500)<=0)return -1;
    ssize_t n=read(fd,bytes,length);if(n<=0)return -1;bytes+=n;length-=(size_t)n;}return 0;}
static uint32_t get32(const unsigned char *p){uint32_t v;memcpy(&v,p,4);return ntohl(v);}
static void put32(unsigned char *p,uint32_t v){v=htonl(v);memcpy(p,&v,4);}
static void put16(unsigned char *p,uint16_t v){v=htons(v);memcpy(p,&v,2);}
static int wire_request(int fd,unsigned op,const unsigned char *body,size_t length,int shared){
    unsigned char frame[512]={0};if(length>sizeof(frame)-28)return -65540;
    put32(frame,1);put32(frame+4,(uint32_t)length);put32(frame+12,op);memcpy(frame+16,"CTXtest1",8);if(length)memcpy(frame+28,body,length);
    int pair[2]={-1,-1},errorfd=fd;
    if(shared){if(!length || socketpair(AF_UNIX,SOCK_STREAM,0,pair))return -65540;errorfd=pair[0];}
    size_t main_length=28+length-(shared?1:0);
    if(write_all(fd,frame,main_length)){if(shared){close(pair[0]);close(pair[1]);}return -65568;}
    if(shared){char ancillary[CMSG_SPACE(sizeof(int))]={0};struct iovec vec={frame+main_length,1};struct msghdr msg={0};
      msg.msg_iov=&vec;msg.msg_iovlen=1;msg.msg_control=ancillary;msg.msg_controllen=sizeof(ancillary);
      struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(h),&pair[1],sizeof(int));
      if(sendmsg(fd,&msg,0)!=1){close(pair[0]);close(pair[1]);return -65568;}close(pair[1]);}
    unsigned char error[4];int status=read_all(errorfd,error,sizeof(error))?-65568:(int32_t)get32(error);
    if(shared)close(pair[0]);return status;
}
/* Independent protocol fixtures. These are deliberately not called getaddrinfo
 * or libdns_sd: they test framing/SCM_RIGHTS, not system-library routing. */
static int wire_query(const char *mode,const char *name){
    if(strcmp(mode,"wire-query") && strcmp(mode,"wire-query6") && strcmp(mode,"wire-shared-query") && strcmp(mode,"wire-addrinfo") &&
       strcmp(mode,"wire-unsupported") && strcmp(mode,"wire-multicast-flags") && strcmp(mode,"wire-invalid-header"))return -65544;
    const char *socket_path=getenv("DNSSD_UDS_PATH");if(!socket_path || strlen(socket_path)>=sizeof(((struct sockaddr_un*)0)->sun_path))return -65540;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -65540;
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;addr.sun_len=sizeof(addr);strcpy(addr.sun_path,socket_path);
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))){close(fd);return -65568;}owned_endpoint=1;
    if(!strcmp(mode,"wire-invalid-header")){unsigned char invalid[28]={0};put32(invalid,1);put32(invalid+4,4097);put32(invalid+12,8);
      (void)write_all(fd,invalid,sizeof(invalid));unsigned char reply[4];int status=read_all(fd,reply,sizeof(reply))?-65540:0;close(fd);return status;}
    int shared=!strcmp(mode,"wire-shared-query"),address=!strcmp(mode,"wire-addrinfo");
    int status=shared?wire_request(fd,1,NULL,0,0):0;
    unsigned char body[512]={0};size_t offset=shared?1:0;
    put32(body+offset,shared?0x4000:!strcmp(mode,"wire-multicast-flags")?0x400:0);offset+=4;put32(body+offset,0);offset+=4;
    if(address){put32(body+offset,3);offset+=4;}
    size_t name_length=strlen(name)+1;if(offset+name_length+4>sizeof(body)){close(fd);return -65540;}
    memcpy(body+offset,name,name_length);offset+=name_length;
    if(!address){put16(body+offset,!strcmp(mode,"wire-query6")?28:!strcmp(mode,"wire-unsupported")?16:1);put16(body+offset+2,1);offset+=4;}
    if(!status)status=wire_request(fd,address?15:8,body,offset,shared);
    int target=address?2:1;
    while(!status && !callback_error && answers<target){
      unsigned char header[28],response[4096];if(read_all(fd,header,sizeof(header))){status=-65568;break;}
      uint32_t length=get32(header+4);
      if(get32(header)!=1 || length>sizeof(response) || get32(header+12)!=(unsigned)(address?72:68) || memcmp(header+16,"CTXtest1",8) || read_all(fd,response,length)){status=-65540;break;}
      if(length<12){status=-65540;break;}callback_error=(int32_t)get32(response+8);size_t end=12;
      while(end<length && response[end])end++;
      if(end>=length || end+11>length){status=-65540;break;}uint16_t type,rdlength;memcpy(&type,response+end+1,2);type=ntohs(type);memcpy(&rdlength,response+end+5,2);rdlength=ntohs(rdlength);
      if(end+7+(size_t)rdlength+4!=length){status=-65540;break;}
      if(!callback_error){if(type==1 && rdlength==4)add_address(AF_INET,response+end+7);else if(type==28 && rdlength==16)add_address(AF_INET6,response+end+7);else {status=-65540;break;}}
    }
    if(shared && !status){unsigned char cancel[28]={0};put32(cancel,1);put32(cancel+12,63);memcpy(cancel+16,"CTXtest1",8);(void)write_all(fd,cancel,sizeof(cancel));}
    close(fd);return status;
}
int main(int argc,char **argv){
    if(argc!=3 || getuid()==0)return 2;
    size_t name_length=strlen(argv[2]);
    if(name_length<9 || name_length>253 || strcmp(argv[2]+name_length-8,".invalid") || strspn(argv[2],"abcdefghijklmnopqrstuvwxyz0123456789-.")!=name_length)return 2;
    alarm(9);signal(SIGPIPE,SIG_IGN);struct proc_bsdinfo info;
    if(proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&info,sizeof(info))!=(int)sizeof(info))return 2;
    printf("{\"kind\":\"ready\",\"pid\":%d,\"uid\":%u,\"birthSec\":%llu,\"birthUsec\":%llu}\n",getpid(),getuid(),
      (unsigned long long)info.pbi_start_tvsec,(unsigned long long)info.pbi_start_tvusec);fflush(stdout);
    char command[16];if(!fgets(command,sizeof(command),stdin) || strcmp(command,"GO\n"))return 2;
    if(!strncmp(argv[1],"wire-",5)){result(wire_query(argv[1],argv[2]));return 0;}
    if(!strcmp(argv[1],"connection")){
      DNSServiceRef ref=NULL;int status=DNSServiceCreateConnection(&ref);
      if(!status){struct sockaddr_un peer={0};socklen_t length=sizeof(peer);const char *expected=getenv("DNSSD_UDS_PATH");
        owned_endpoint=expected && getpeername(DNSServiceRefSockFD(ref),(struct sockaddr*)&peer,&length)==0 && peer.sun_family==AF_UNIX && !strcmp(peer.sun_path,expected);
        DNSServiceRefDeallocate(ref);}
      result(status);return 0;
    }
    if(!strcmp(argv[1],"getaddrinfo4") || !strcmp(argv[1],"getaddrinfo")){
      struct addrinfo hints={0},*list=NULL;hints.ai_socktype=SOCK_STREAM;
      hints.ai_family=!strcmp(argv[1],"getaddrinfo4")?AF_INET:AF_UNSPEC;
      int status=getaddrinfo(argv[2],"443",&hints,&list);
      for(struct addrinfo *p=list;p;p=p->ai_next){if(p->ai_family==AF_INET)add_address(AF_INET,&((struct sockaddr_in*)p->ai_addr)->sin_addr);
        if(p->ai_family==AF_INET6)add_address(AF_INET6,&((struct sockaddr_in6*)p->ai_addr)->sin6_addr);}
      if(list)freeaddrinfo(list);result(status);return 0;
    }
    DNSServiceRef ref=NULL,child=NULL;int status=0,target=1;
    if(!strcmp(argv[1],"addrinfo")){target=2;status=DNSServiceGetAddrInfo(&ref,0,0,3,argv[2],addr_reply,NULL);}
    else if(!strcmp(argv[1],"shared-query")){
      status=DNSServiceCreateConnection(&ref);if(!status){child=ref;status=DNSServiceQueryRecord(&child,kDNSServiceFlagsShareConnection,0,argv[2],1,1,query_reply,NULL);}
    }else if(!strcmp(argv[1],"query") || !strcmp(argv[1],"query6")){
      status=DNSServiceQueryRecord(&ref,0,0,argv[2],!strcmp(argv[1],"query6")?28:1,1,query_reply,NULL);
    }else if(!strcmp(argv[1],"unsupported")){
      status=DNSServiceQueryRecord(&ref,0,0,argv[2],16,1,query_reply,NULL);
    }else if(!strcmp(argv[1],"privacy-flags")){
      status=DNSServiceQueryRecord(&ref,kDNSServiceFlagsForceMulticast,0,argv[2],1,1,query_reply,NULL);
    }else return 2;
    while(!status && !callback_error && answers<target){
      struct pollfd p={DNSServiceRefSockFD(ref),POLLIN,0};int ready=poll(&p,1,2000);
      if(ready<=0){status=kDNSServiceErr_Timeout;break;}status=DNSServiceProcessResult(ref);
    }
    if(child)DNSServiceRefDeallocate(child);if(ref)DNSServiceRefDeallocate(ref);result(status);return 0;
}
