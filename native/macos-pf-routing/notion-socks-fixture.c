/* Owned loopback-only byte client. Commands stay on private stdio; no resolver. */
#include <sys/socket.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int nibble(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static void response(int ok){printf("{\"ok\":%s}\n",ok?"true":"false");fflush(stdout);}
int main(void){
    if(getuid()==0 || geteuid()!=getuid())return 2;alarm(30);signal(SIGPIPE,SIG_IGN);
    struct proc_bsdinfo info;if(proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&info,sizeof(info))!=(int)sizeof(info))return 2;
    printf("{\"ready\":true,\"identity\":{\"pid\":%d,\"uid\":%u,\"gid\":%u,\"birthSec\":%llu,\"birthUsec\":%llu}}\n",getpid(),getuid(),getgid(),(unsigned long long)info.pbi_start_tvsec,(unsigned long long)info.pbi_start_tvusec);fflush(stdout);
    int fd=-1,extra=-1;char command[65540];
    while(fgets(command,sizeof(command),stdin)){
      if(!strncmp(command,"CONNECT ",8)){
        char *end;long port=strtol(command+8,&end,10);if(fd>=0 || port<1 || port>65535 || strcmp(end,"\n")){response(0);continue;}
        fd=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_len=sizeof(addr);addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons((uint16_t)port);
        if(fd<0 || connect(fd,(struct sockaddr*)&addr,sizeof(addr))){if(fd>=0)close(fd);fd=-1;response(0);continue;}
        struct sockaddr_in local;socklen_t length=sizeof(local);if(getsockname(fd,(struct sockaddr*)&local,&length)){response(0);continue;}
        printf("{\"ok\":true,\"clientPort\":%u,\"frontPort\":%ld}\n",ntohs(local.sin_port),port);fflush(stdout);
      }else if(!strncmp(command,"WRITE ",6) && fd>=0){
        size_t length=strcspn(command+6,"\n");int ok=!(length%2) && length<=65536;unsigned char bytes[32768];
        for(size_t i=0;ok && i<length;i+=2){int a=nibble(command[6+i]),b=nibble(command[7+i]);if(a<0||b<0)ok=0;else bytes[i/2]=(unsigned char)((a<<4)|b);}
        size_t sent=0;while(ok && sent<length/2){struct pollfd p={fd,POLLOUT,0};if(poll(&p,1,1500)<=0){ok=0;break;}ssize_t n=write(fd,bytes+sent,length/2-sent);if(n<=0){ok=0;break;}sent+=(size_t)n;}response(ok);
      }else if(!strncmp(command,"READ ",5) && fd>=0){
        char *end;long length=strtol(command+5,&end,10);if(length<1 || length>32768 || strcmp(end,"\n")){response(0);continue;}
        unsigned char bytes[32768];size_t received=0;int ok=1;
        while(received<(size_t)length){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,2000)<=0){ok=0;break;}ssize_t n=read(fd,bytes+received,(size_t)length-received);if(n<=0){ok=0;break;}received+=(size_t)n;}
        printf("{\"ok\":%s,\"bytes\":%zu,\"hex\":\"",ok?"true":"false",received);for(size_t i=0;i<received;i++)printf("%02x",bytes[i]);puts("\"}");fflush(stdout);
      }else if(!strcmp(command,"END\n"))response(fd>=0 && shutdown(fd,SHUT_WR)==0);
      else if(!strcmp(command,"DUP\n")){if(extra>=0 || fd<0)response(0);else {extra=dup(fd);response(extra>=0);}}
      else if(!strcmp(command,"CLOSE_DUP\n")){if(extra>=0){close(extra);extra=-1;response(1);}else response(0);}
      else if(!strcmp(command,"CLOSE\n")){if(extra>=0){close(extra);extra=-1;}if(fd>=0){close(fd);fd=-1;}response(1);}
      else if(!strcmp(command,"QUIT\n"))break;
      else response(0);
    }
    if(extra>=0)close(extra);if(fd>=0)close(fd);return 0;
}
