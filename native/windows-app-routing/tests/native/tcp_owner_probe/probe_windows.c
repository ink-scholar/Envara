#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "observation.h"

/* Driver-free instrumentation only. It never loads WinDivert, enables a
 * service, changes routing/DNS, or releases a captured packet. All traffic
 * belongs to this process's temporary IPv4 loopback sockets. */
typedef struct {
    DWORD result, count;
    int found;
    MIB_TCPROW_OWNER_MODULE row;
    uint64_t before_qpc, after_qpc, wall_filetime;
} Observation;
typedef struct {
    DWORD result, set_result;
    TCP_ESTATS_DATA_RW_v0 rw;
    TCP_ESTATS_DATA_ROD_v0 rod;
    int usable;
} Stats;

static uint64_t filetime_value(FILETIME time) {return ((uint64_t)time.dwHighDateTime<<32)|time.dwLowDateTime;}
static uint64_t qpc_now(void) {LARGE_INTEGER time;QueryPerformanceCounter(&time);return (uint64_t)time.QuadPart;}
static Observation observe(const struct sockaddr_in *local,const struct sockaddr_in *remote) {
    Observation result;DWORD bytes=0,rc,i;uint32_t count=0;void *buffer=NULL;FILETIME wall;
    memset(&result,0,sizeof(result));result.before_qpc=qpc_now();GetSystemTimePreciseAsFileTime(&wall);result.wall_filetime=filetime_value(wall);
    rc=GetExtendedTcpTable(NULL,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_MODULE_ALL,0);
    if(rc!=ERROR_INSUFFICIENT_BUFFER || bytes<4 || bytes>4*1024*1024){result.result=rc?rc:ERROR_INVALID_DATA;goto done;}
    buffer=malloc(bytes);if(!buffer){result.result=ERROR_NOT_ENOUGH_MEMORY;goto done;}
    rc=GetExtendedTcpTable(buffer,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_MODULE_ALL,0);result.result=rc;
    if(rc!=NO_ERROR)goto done;
    if(!envara_probe_table_count(buffer,bytes,offsetof(MIB_TCPTABLE_OWNER_MODULE,table),sizeof(MIB_TCPROW_OWNER_MODULE),&count)){result.result=ERROR_INVALID_DATA;goto done;}
    for(i=0;i<count;i++) {
        MIB_TCPROW_OWNER_MODULE *row=&((MIB_TCPTABLE_OWNER_MODULE*)buffer)->table[i];
        if(row->dwLocalAddr==local->sin_addr.s_addr && row->dwRemoteAddr==remote->sin_addr.s_addr &&
           (UINT16)row->dwLocalPort==local->sin_port && (UINT16)row->dwRemotePort==remote->sin_port) {
            result.count++;result.row=*row;
        }
    }
    result.found=result.count==1 && result.row.dwOwningPid==GetCurrentProcessId();
done:
    free(buffer);result.after_qpc=qpc_now();return result;
}
static Stats stats(const Observation *observation,int enable) {
    Stats result;MIB_TCPROW row;TCP_ESTATS_DATA_RW_v0 setting;
    memset(&result,0,sizeof(result));result.result=ERROR_NOT_FOUND;result.set_result=ERROR_NOT_SUPPORTED;
    if(!observation->found)return result;
    memset(&row,0,sizeof(row));row.dwState=observation->row.dwState;row.dwLocalAddr=observation->row.dwLocalAddr;
    row.dwLocalPort=observation->row.dwLocalPort;row.dwRemoteAddr=observation->row.dwRemoteAddr;row.dwRemotePort=observation->row.dwRemotePort;
    if(enable) {
        setting.EnableCollection=TRUE;
        result.set_result=SetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&setting,0,sizeof(setting),0);
    }
    result.result=GetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&result.rw,0,sizeof(result.rw),NULL,0,0,(PUCHAR)&result.rod,0,sizeof(result.rod));
    result.usable=envara_probe_estats_usable(result.result,result.rw.EnableCollection);
    if(!result.usable)memset(&result.rod,0,sizeof(result.rod));
    return result;
}
static void print_observation(const Observation *result) {
    printf("{\"error\":%lu,\"matching_rows\":%lu,\"self_owner_observed\":%s,\"pid\":%lu,\"bind_filetime\":%llu,\"tcp_state\":%lu,\"before_qpc\":%llu,\"after_qpc\":%llu,\"wall_filetime\":%llu}",
        (unsigned long)result->result,(unsigned long)result->count,result->found?"true":"false",(unsigned long)result->row.dwOwningPid,
        (unsigned long long)result->row.liCreateTimestamp.QuadPart,(unsigned long)result->row.dwState,
        (unsigned long long)result->before_qpc,(unsigned long long)result->after_qpc,(unsigned long long)result->wall_filetime);
}
static void print_stats(const Stats *result) {
    printf("{\"error\":%lu,\"set_error\":%lu,\"collection_enabled\":%s,\"dynamic_values_usable\":%s,\"snd_una\":",
        (unsigned long)result->result,(unsigned long)result->set_result,result->rw.EnableCollection?"true":"false",result->usable?"true":"false");
    if(result->usable)printf("%lu,\"snd_nxt\":%lu,\"snd_max\":%lu,\"rcv_nxt\":%lu}",(unsigned long)result->rod.SndUna,(unsigned long)result->rod.SndNxt,(unsigned long)result->rod.SndMax,(unsigned long)result->rod.RcvNxt);
    else printf("null,\"snd_nxt\":null,\"snd_max\":null,\"rcv_nxt\":null}");
}
static SOCKET client_connect(const struct sockaddr_in *server,const struct sockaddr_in *fixed,struct sockaddr_in *local,DWORD *error) {
    SOCKET client=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);int bytes=sizeof(*local);DWORD timeout=2000;BOOL reuse=TRUE;
    if(client==INVALID_SOCKET){*error=WSAGetLastError();return client;}
    setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
    setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
    if(fixed) {
        setsockopt(client,SOL_SOCKET,SO_REUSEADDR,(const char*)&reuse,sizeof(reuse));
        if(bind(client,(const struct sockaddr*)fixed,sizeof(*fixed))==SOCKET_ERROR)goto failed;
    }
    if(connect(client,(const struct sockaddr*)server,sizeof(*server))==SOCKET_ERROR)goto failed;
    if(getsockname(client,(struct sockaddr*)local,&bytes)==SOCKET_ERROR)goto failed;
    return client;
failed:
    *error=WSAGetLastError();closesocket(client);return INVALID_SOCKET;
}
static void close_reset(SOCKET socket_value) {
    struct linger option={1,0};if(socket_value==INVALID_SOCKET)return;
    setsockopt(socket_value,SOL_SOCKET,SO_LINGER,(const char*)&option,sizeof(option));closesocket(socket_value);
}
static int transfer_marker(SOCKET source,SOCKET destination,const char *payload,int bytes) {
    char received[32];int written=0,read_bytes=0,count;
    if(bytes<1 || bytes>(int)sizeof(received))return 0;
    while(written<bytes) {
        count=send(source,payload+written,bytes-written,0);if(count<=0)return 0;written+=count;
    }
    while(read_bytes<bytes) {
        count=recv(destination,received+read_bytes,bytes-read_bytes,0);if(count<=0)return 0;read_bytes+=count;
    }
    return memcmp(payload,received,(size_t)bytes)==0;
}

int main(int argc,char **argv) {
    SOCKET listener=INVALID_SOCKET,client=INVALID_SOCKET,accepted=INVALID_SOCKET,replacement=INVALID_SOCKET,reaccepted=INVALID_SOCKET;
    WSADATA wsa;struct sockaddr_in server,local,new_local;int size=sizeof(server),enable=0;
    DWORD error=0,reuse_error=0;Observation before,after,reused;Stats baseline,dynamic;FILETIME created,exited,kernel,user;LARGE_INTEGER frequency;
    uint64_t marker;const char payload[]="fixture";
    if(argc==1) {
        puts("{\"schema\":1,\"probe\":\"tcp-owner-observation\",\"mode\":\"read-only\",\"traffic_created\":false,\"driver_loaded\":false,\"ready\":false,\"dns\":false,\"fail_closed\":false,\"packet_generation_proved\":false}");return 0;
    }
    if(strcmp(argv[1],"--run-local") || argc>3 || (argc==3 && strcmp(argv[2],"--enable-own-estats"))) {fputs("Use --run-local [--enable-own-estats]; no driver or routing changes.\n",stderr);return 2;}
    enable=argc==3;
    memset(&before,0,sizeof(before));memset(&after,0,sizeof(after));memset(&reused,0,sizeof(reused));
    memset(&baseline,0,sizeof(baseline));memset(&dynamic,0,sizeof(dynamic));memset(&server,0,sizeof(server));memset(&local,0,sizeof(local));
    memset(&created,0,sizeof(created));memset(&exited,0,sizeof(exited));memset(&kernel,0,sizeof(kernel));memset(&user,0,sizeof(user));frequency.QuadPart=0;
    if(WSAStartup(MAKEWORD(2,2),&wsa)){return 3;}
    listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(listener==INVALID_SOCKET){error=WSAGetLastError();goto done;}
    server.sin_family=AF_INET;server.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(listener,(struct sockaddr*)&server,sizeof(server))==SOCKET_ERROR || getsockname(listener,(struct sockaddr*)&server,&size)==SOCKET_ERROR || listen(listener,2)==SOCKET_ERROR){error=WSAGetLastError();goto done;}
    client=client_connect(&server,NULL,&local,&error);if(client==INVALID_SOCKET)goto done;
    accepted=accept(listener,NULL,NULL);if(accepted==INVALID_SOCKET){error=WSAGetLastError();goto done;}
    {DWORD timeout=2000;setsockopt(accepted,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));}
    before=observe(&local,&server);baseline=stats(&before,enable);
    /* This is a userspace observation marker, NOT a captured packet timestamp. */
    marker=qpc_now();if(!transfer_marker(client,accepted,payload,sizeof(payload)))error=ERROR_INVALID_DATA;
    after=observe(&local,&server);dynamic=stats(&after,0);
    close_reset(client);client=INVALID_SOCKET;close_reset(accepted);accepted=INVALID_SOCKET;
    replacement=client_connect(&server,&local,&new_local,&reuse_error);
    if(replacement!=INVALID_SOCKET) {
        reaccepted=accept(listener,NULL,NULL);if(reaccepted!=INVALID_SOCKET)reused=observe(&new_local,&server);else reuse_error=WSAGetLastError();
    }
    if(!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user) || !QueryPerformanceFrequency(&frequency))error=GetLastError();
    printf("{\"schema\":1,\"probe\":\"tcp-owner-observation\",\"mode\":\"controlled-loopback\",\"error\":%lu,\"pid\":%lu,\"process_filetime\":%llu,\"qpc_frequency\":%llu,\"marker_qpc\":%llu,\"before\":",
        (unsigned long)error,(unsigned long)GetCurrentProcessId(),(unsigned long long)filetime_value(created),(unsigned long long)frequency.QuadPart,(unsigned long long)marker);
    print_observation(&before);printf(",\"after\":");print_observation(&after);printf(",\"baseline_estats\":");print_stats(&baseline);printf(",\"after_estats\":");print_stats(&dynamic);
    printf(",\"tuple_reuse_error\":%lu,\"replacement\":",(unsigned long)reuse_error);print_observation(&reused);
    printf(",\"same_bind_timestamp_after_reuse\":%s,\"driver_loaded\":false,\"packet_generation_proved\":false,\"ready\":false,\"dns\":false,\"fail_closed\":false}\n",
        reused.found && before.found && reused.row.liCreateTimestamp.QuadPart==before.row.liCreateTimestamp.QuadPart?"true":"false");
done:
    close_reset(client);close_reset(accepted);close_reset(replacement);close_reset(reaccepted);if(listener!=INVALID_SOCKET)closesocket(listener);WSACleanup();
    if(error && !before.before_qpc)printf("{\"schema\":1,\"probe\":\"tcp-owner-observation\",\"error\":%lu,\"driver_loaded\":false,\"ready\":false,\"fail_closed\":false}\n",(unsigned long)error);
    return error?1:0;
}
