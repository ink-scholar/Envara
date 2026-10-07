/* See PROVENANCE.md. Requires the unchanged official signed WinDivert 2.2.2
 * driver. This user-mode capture does NOT retain filtering after service death. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include "vendor/windivert.h"
#include "capture_core.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static SRWLOCK core_lock=SRWLOCK_INIT, lifecycle_lock=SRWLOCK_INIT;
static EnvaraCore core;
static EnvaraCaptureConfig config;
static EnvaraCaptureStatus counters;
static HANDLE socket_handle=INVALID_HANDLE_VALUE, network_handle=INVALID_HANDLE_VALUE;
static HANDLE socket_thread=NULL, network_thread=NULL;
static volatile LONG running=0;
static int initialized=0;
static LARGE_INTEGER qpc_frequency;
static uint32_t resolve_tuple_current(const EnvaraTuple *,INT64 timestamp,uint32_t *identity_index,uint32_t *pid,uint64_t *birth);

static void fail(DWORD error) {
    AcquireSRWLockExclusive(&core_lock);
    counters.last_error=error?error:ERROR_INVALID_DATA;
    counters.socket_ready=0;counters.network_ready=0;
    ReleaseSRWLockExclusive(&core_lock);
    InterlockedExchange(&running,0);
    if(network_handle!=INVALID_HANDLE_VALUE)WinDivertShutdown(network_handle,WINDIVERT_SHUTDOWN_RECV);
    if(socket_handle!=INVALID_HANDLE_VALUE)WinDivertShutdown(socket_handle,WINDIVERT_SHUTDOWN_RECV);
}
static void count(uint64_t *field) {
    AcquireSRWLockExclusive(&core_lock); (*field)++; ReleaseSRWLockExclusive(&core_lock);
}
static uint64_t filetime_value(FILETIME f) {return ((uint64_t)f.dwHighDateTime<<32)|f.dwLowDateTime;}
static void expire_processes_locked(void) {
    uint32_t i;
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++) {
        EnvaraCoreIdentity *id=&core.identities[i];
        if(id->used && id->process_handle && WaitForSingleObject((HANDLE)(uintptr_t)id->process_handle,0)==WAIT_OBJECT_0) {
            CloseHandle((HANDLE)(uintptr_t)id->process_handle);envara_core_remove_identity(&core,i,GetTickCount64());
        }
    }
    envara_core_expire(&core,GetTickCount64());
}
static uint32_t resolve_pid(DWORD pid,INT64 event_timestamp,uint32_t *identity_index,uint64_t *birth) {
    HANDLE process;FILETIME created,exited,kernel,user;
    EnvaraIdentityRequest request;EnvaraIdentityResult result;uint32_t rc;int retained=0;
    if(!pid)return ENVARA_ERR_IDENTITY;
    process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if(!process)return ENVARA_ERR_IDENTITY;
    memset(&request,0,sizeof(request)); memset(&result,0,sizeof(result));
    request.size=sizeof(request);request.version=ENVARA_CAPTURE_ABI;request.pid=pid;
    request.process_handle=(uint64_t)(uintptr_t)process;
    result.size=sizeof(result);result.version=ENVARA_CAPTURE_ABI;
    if(!GetProcessTimes(process,&created,&exited,&kernel,&user) || WaitForSingleObject(process,0)!=WAIT_TIMEOUT) {
        CloseHandle(process);return ENVARA_ERR_IDENTITY;
    }
    request.creation_time=filetime_value(created);
    if(event_timestamp) {
        LARGE_INTEGER now; FILETIME wall; uint64_t elapsed,event_wall;
        QueryPerformanceCounter(&now);GetSystemTimePreciseAsFileTime(&wall);
        if(event_timestamp>now.QuadPart || event_timestamp<0) {CloseHandle(process);return ENVARA_ERR_IDENTITY;}
        elapsed=(uint64_t)(((long double)(now.QuadPart-event_timestamp)*10000000.0L)/(long double)qpc_frequency.QuadPart);
        if(elapsed>filetime_value(wall)) {CloseHandle(process);return ENVARA_ERR_IDENTITY;}
        event_wall=filetime_value(wall)-elapsed;
        /* Reject a PID whose currently opened process was born after this socket
         * event. A two-ms ambiguity band also rejects near-birth attribution.
         * Wall-clock adjustments and OS PID/event races remain acceptance gaps. */
        if(request.creation_time+20000>event_wall) {CloseHandle(process);return ENVARA_ERR_IDENTITY;}
    }
    rc=((EnvaraResolveIdentity)(uintptr_t)config.resolve_identity)(config.callback_context,&request,&result);
    if(rc!=ENVARA_OK || result.reserved || result.decision==ENVARA_ID_UNKNOWN) {CloseHandle(process);return ENVARA_ERR_IDENTITY;}
    AcquireSRWLockExclusive(&core_lock);
    expire_processes_locked();
    rc=envara_core_identity(&core,&request,&result,identity_index);
    if(rc==ENVARA_OK && birth)*birth=request.creation_time;
    if(rc==ENVARA_OK && core.identities[*identity_index].process_handle==(uint64_t)(uintptr_t)process)retained=1;
    ReleaseSRWLockExclusive(&core_lock);
    if(!retained)CloseHandle(process);
    return rc;
}
static void event_endpoint(EnvaraEndpoint *ep,const UINT32 address[4],UINT16 port,BOOL ipv6) {
    uint32_t converted[4]; memset(ep,0,sizeof(*ep));ep->family=ipv6?6:4;ep->port=port;
    if(ipv6) {WinDivertHelperHtonIpv6Address(address,converted);memcpy(ep->address,converted,16);}
    else {UINT32 v=htonl(address[0]);memcpy(ep->address,&v,4);}
}
static DWORD WINAPI socket_worker(void *unused) {
    WINDIVERT_ADDRESS address;UINT ignored;
    (void)unused;
    while(InterlockedCompareExchange(&running,0,0)) {
        EnvaraTuple tuple;uint32_t id,rc;uint64_t birth=0;
        memset(&address,0,sizeof(address));
        if(!WinDivertRecv(socket_handle,NULL,0,&ignored,&address)) {
            if(InterlockedCompareExchange(&running,0,0))fail(GetLastError());
            break;
        }
        if(address.Layer!=WINDIVERT_LAYER_SOCKET || address.Timestamp<=0 || !address.Socket.EndpointId ||
           (address.Socket.Protocol!=6 && address.Socket.Protocol!=17)) {count(&counters.unsupported_dropped);continue;}
        if(address.Event==WINDIVERT_EVENT_SOCKET_CLOSE) {
            AcquireSRWLockExclusive(&core_lock);envara_core_close_owner(&core,address.Socket.EndpointId);
            expire_processes_locked();ReleaseSRWLockExclusive(&core_lock);continue;
        }
        if(address.Event!=WINDIVERT_EVENT_SOCKET_BIND && address.Event!=WINDIVERT_EVENT_SOCKET_CONNECT &&
           address.Event!=WINDIVERT_EVENT_SOCKET_ACCEPT && address.Event!=WINDIVERT_EVENT_SOCKET_LISTEN)continue;
        rc=resolve_pid(address.Socket.ProcessId,address.Timestamp,&id,&birth);
        if(rc!=ENVARA_OK) {count(&counters.unknown_dropped);continue;}
        memset(&tuple,0,sizeof(tuple));tuple.protocol=address.Socket.Protocol;
        event_endpoint(&tuple.source,address.Socket.LocalAddr,address.Socket.LocalPort,address.IPv6);
        event_endpoint(&tuple.destination,address.Socket.RemoteAddr,address.Socket.RemotePort,address.IPv6);
        AcquireSRWLockExclusive(&core_lock);
        if(core.identities[id].used && core.identities[id].pid==address.Socket.ProcessId &&
            core.identities[id].creation_time==birth && WaitForSingleObject((HANDLE)(uintptr_t)core.identities[id].process_handle,0)==WAIT_TIMEOUT)
            rc=envara_core_owner_event(&core,address.Socket.EndpointId,&tuple,id,(uint64_t)address.Timestamp);
        else rc=ENVARA_ERR_IDENTITY;
        ReleaseSRWLockExclusive(&core_lock);
        if(rc==ENVARA_ERR_CAPACITY)fail(ERROR_NOT_ENOUGH_MEMORY);
    }
    return 0;
}
static int packet_fragment(const uint8_t *packet,UINT length) {
    uint8_t next;UINT offset;uint16_t bits;
    if(!length)return 1;
    if((packet[0]>>4)==4) {
        if(length<20)return 1;
        bits=(uint16_t)(((uint16_t)packet[6]<<8)|packet[7]);return (bits&0x3fff)!=0;
    }
    if((packet[0]>>4)!=6 || length<40)return 1;
    next=packet[6];offset=40;
    while(next==0 || next==43 || next==60 || next==51 || next==44) {
        UINT span;
        if(next==44)return 1;
        if(offset+2>length)return 1;
        span=next==51?((UINT)packet[offset+1]+2)*4:((UINT)packet[offset+1]+1)*8;
        next=packet[offset];if(span<8 || span>length-offset)return 1;offset+=span;
    }
    return 0;
}
static int packet_tuple(const uint8_t *packet,UINT length,EnvaraTuple *t,
    PWINDIVERT_IPHDR *v4,PWINDIVERT_IPV6HDR *v6,PWINDIVERT_TCPHDR *tcp,PWINDIVERT_UDPHDR *udp) {
    memset(t,0,sizeof(*t));*v4=NULL;*v6=NULL;*tcp=NULL;*udp=NULL;
    if(!WinDivertHelperParsePacket(packet,length,v4,v6,NULL,NULL,NULL,tcp,udp,NULL,NULL,NULL,NULL))return 0;
    if((*v4==NULL)==(*v6==NULL) || (*tcp==NULL)==(*udp==NULL))return 0;
    t->source.family=t->destination.family=*v4?4:6;
    if(*v4) {memcpy(t->source.address,&(*v4)->SrcAddr,4);memcpy(t->destination.address,&(*v4)->DstAddr,4);}
    else {memcpy(t->source.address,(*v6)->SrcAddr,16);memcpy(t->destination.address,(*v6)->DstAddr,16);}
    if(*tcp) {t->protocol=6;t->source.port=ntohs((*tcp)->SrcPort);t->destination.port=ntohs((*tcp)->DstPort);}
    else {t->protocol=17;t->source.port=ntohs((*udp)->SrcPort);t->destination.port=ntohs((*udp)->DstPort);}
    return envara_tuple_valid(t);
}
static void rewrite_packet(const EnvaraTuple *t,PWINDIVERT_IPHDR v4,PWINDIVERT_IPV6HDR v6,PWINDIVERT_TCPHDR tcp) {
    if(v4) {memcpy(&v4->SrcAddr,t->source.address,4);memcpy(&v4->DstAddr,t->destination.address,4);}
    else {memcpy(v6->SrcAddr,t->source.address,16);memcpy(v6->DstAddr,t->destination.address,16);}
    tcp->SrcPort=htons(t->source.port);tcp->DstPort=htons(t->destination.port);
}
static int unsupported_target(const EnvaraTuple *t) {
    const uint8_t *s=t->source.address,*d=t->destination.address;
    if(t->source.family==4)return d[0]>=224 || (d[0]==255 && d[1]==255 && d[2]==255 && d[3]==255);
    return d[0]==255 || (d[0]==0xfe && (d[1]&0xc0)==0x80) || (s[0]==0xfe && (s[1]&0xc0)==0x80);
}
static int send_packet(uint8_t *packet,UINT len,WINDIVERT_ADDRESS *a,int changed) {
    UINT sent=0;
    if(changed && !WinDivertHelperCalcChecksums(packet,len,a,0))return 0;
    if(!WinDivertSend(network_handle,packet,len,&sent,a) || sent!=len)return 0;
    return 1;
}
static DWORD WINAPI network_worker(void *unused) {
    uint8_t *packet=(uint8_t *)malloc(65535);UINT length;
    (void)unused;if(!packet){fail(ERROR_NOT_ENOUGH_MEMORY);return 0;}
    while(InterlockedCompareExchange(&running,0,0)) {
        WINDIVERT_ADDRESS address;EnvaraTuple tuple,out;uint32_t id=UINT32_MAX,decision=ENVARA_ID_UNKNOWN,rc;
        PWINDIVERT_IPHDR v4;PWINDIVERT_IPV6HDR v6;PWINDIVERT_TCPHDR tcp;PWINDIVERT_UDPHDR udp;
        uint64_t now,deadline,flow_id=0,decided_birth=0;uint32_t decided_pid=0;int known_original=0;
        memset(&address,0,sizeof(address));
        if(!WinDivertRecv(network_handle,packet,65535,&length,&address)) {
            if(InterlockedCompareExchange(&running,0,0))fail(GetLastError());
            break;
        }
        if(address.Layer!=WINDIVERT_LAYER_NETWORK || address.Timestamp<=0 || packet_fragment(packet,length) ||
           !packet_tuple(packet,length,&tuple,&v4,&v6,&tcp,&udp)) {
            /* Unsupported outbound fragments cannot be safely attributed. Drop,
             * record the limitation, never label them protected. Incoming
             * non-attributable fragments retain the original system path. */
            if(!address.Outbound && address.Layer==WINDIVERT_LAYER_NETWORK) {
                if(!send_packet(packet,length,&address,0))fail(GetLastError());else count(&counters.reinjected);
            } else count(&counters.unsupported_dropped);
            continue;
        }
        now=GetTickCount64();
        /* A real process must never reach the wildcard listener directly.
         * Our rewritten packets are injected past this handle's priority. */
        if(tcp && tuple.destination.port==config.relay_port && (!address.Outbound || address.Loopback)) {
            count(&counters.blocked);continue;
        }
        if(tcp && tuple.source.port==config.relay_port && address.Outbound) {
            AcquireSRWLockExclusive(&core_lock);rc=envara_core_reverse(&core,&tuple,now,&out);
            if(rc==ENVARA_OK)envara_core_note_tcp(&core,&tuple,1,tcp->Fin,tcp->Rst,now);
            ReleaseSRWLockExclusive(&core_lock);
            if(rc==ENVARA_OK) {
                rewrite_packet(&out,v4,v6,tcp);address.Outbound=address.Loopback?TRUE:FALSE;
                if(!send_packet(packet,length,&address,1))fail(GetLastError());else count(&counters.intercepted);
            } else count(&counters.blocked);
            continue;
        }
        if(!address.Outbound) {
            /* Refuse unsolicited external sockets to our wildcard relay. */
            if(tcp && tuple.destination.port==config.relay_port)count(&counters.blocked);
            else if(!send_packet(packet,length,&address,0))fail(GetLastError());else count(&counters.reinjected);
            continue;
        }
        deadline=now+config.hold_milliseconds;
        do {
            AcquireSRWLockExclusive(&core_lock);
            expire_processes_locked();
            known_original=envara_core_has_original(&core,&tuple,&id);
            if(known_original)decision=(id<ENVARA_CAPTURE_MAX_IDENTITIES && core.identities[id].used)?core.identities[id].decision:ENVARA_ID_BLOCKED;
            else decision=envara_core_decision_at(&core,&tuple,(uint64_t)address.Timestamp,&id);
            if(id<ENVARA_CAPTURE_MAX_IDENTITIES && core.identities[id].used) {
                decided_pid=core.identities[id].pid;decided_birth=core.identities[id].creation_time;
            }
            ReleaseSRWLockExclusive(&core_lock);
            if((tcp && tcp->Syn && !tcp->Ack) || decision==ENVARA_ID_UNOWNED) {
                uint32_t current_id=UINT32_MAX,event_id=UINT32_MAX,current_pid=0;uint64_t current_birth=0;
                uint32_t current=resolve_tuple_current(&tuple,address.Timestamp,&current_id,&current_pid,&current_birth),event_decision;
                AcquireSRWLockExclusive(&core_lock);
                event_decision=envara_core_decision_at(&core,&tuple,(uint64_t)address.Timestamp,&event_id);
                decision=current!=ENVARA_ID_UNKNOWN && event_decision!=ENVARA_ID_UNKNOWN &&
                    current_id==event_id && current_id<ENVARA_CAPTURE_MAX_IDENTITIES && core.identities[current_id].used &&
                    core.identities[current_id].pid==current_pid && core.identities[current_id].creation_time==current_birth?
                    core.identities[current_id].decision:ENVARA_ID_UNKNOWN;
                if(decision!=ENVARA_ID_UNKNOWN && tcp && tcp->Syn && !tcp->Ack) {
                    uint32_t f;
                    for(f=0;f<ENVARA_CAPTURE_MAX_FLOWS;f++) {
                        EnvaraCoreFlow *existing=&core.flows[f];
                        if(existing->used && !existing->reserved && envara_tuple_equal(&existing->original,&tuple) &&
                            (existing->identity_index!=current_id || existing->closed_at ||
                             existing->initial_sequence!=ntohl(tcp->SeqNum))) {
                            envara_core_retire_original(&core,&tuple,now);known_original=0;break;
                        }
                    }
                }
                id=current_id;
                decided_pid=current_pid;decided_birth=current_birth;
                ReleaseSRWLockExclusive(&core_lock);
            }
            if(decision!=ENVARA_ID_UNKNOWN || !InterlockedCompareExchange(&running,0,0))break;
            Sleep(5);now=GetTickCount64();
        }while(now<deadline);
        if(!InterlockedCompareExchange(&running,0,0))break;
        if(decision==ENVARA_ID_UNOWNED) {
            if(!send_packet(packet,length,&address,0))fail(GetLastError());else count(&counters.reinjected);continue;
        }
        if(decision==ENVARA_ID_UNKNOWN) {count(&counters.unknown_dropped);continue;}
        if(decision!=ENVARA_ID_OWNED || udp || tuple.destination.port==53) {count(&counters.blocked);continue;}
        if(unsupported_target(&tuple) || (!known_original && (!tcp->Syn || tcp->Ack))) {
            count(&counters.unsupported_dropped);continue;
        }
        AcquireSRWLockExclusive(&core_lock);
        rc=id<ENVARA_CAPTURE_MAX_IDENTITIES && core.identities[id].used && core.identities[id].pid==decided_pid &&
            core.identities[id].creation_time==decided_birth &&
            WaitForSingleObject((HANDLE)(uintptr_t)core.identities[id].process_handle,0)==WAIT_TIMEOUT?
            envara_core_forward(&core,&tuple,id,now,&out,&flow_id):ENVARA_ERR_IDENTITY;
        if(rc==ENVARA_OK && !known_original && tcp->Syn && !tcp->Ack) {
            uint32_t f;for(f=0;f<ENVARA_CAPTURE_MAX_FLOWS;f++)
                if(core.flows[f].used && core.flows[f].flow_id==flow_id)core.flows[f].initial_sequence=ntohl(tcp->SeqNum);
        }
        if(rc==ENVARA_OK)envara_core_note_tcp(&core,&tuple,0,tcp->Fin,tcp->Rst,now);
        ReleaseSRWLockExclusive(&core_lock);
        if(rc!=ENVARA_OK) {count(&counters.blocked);continue;}
        rewrite_packet(&out,v4,v6,tcp);address.Outbound=address.Loopback?TRUE:FALSE;
        if(!send_packet(packet,length,&address,1))fail(GetLastError());else count(&counters.intercepted);
    }
    free(packet);return 0;
}

/* Packet-triggered socket owner verification, not process/child polling. A
 * current owner-table row alone never grants direct access: network_worker also
 * requires a matching SOCKET event at/before the captured packet timestamp.
 * This deliberately drops pre-capture sockets without such evidence. */
static uint32_t resolve_tuple_current(const EnvaraTuple *packet,INT64 timestamp,uint32_t *identity_index,uint32_t *pid_out,uint64_t *birth_out) {
        int family=packet->source.family==6,kind=packet->protocol==17;
        DWORD bytes=0,error,i,owner_pid=0;uint8_t *data;DWORD af=family?AF_INET6:AF_INET;
        uint32_t rc,id,decision;size_t row_size;
        if(timestamp<=0)return ENVARA_ID_UNKNOWN;
        if(kind)error=GetExtendedUdpTable(NULL,&bytes,FALSE,af,UDP_TABLE_OWNER_PID,0);
        else error=GetExtendedTcpTable(NULL,&bytes,FALSE,af,TCP_TABLE_OWNER_PID_ALL,0);
        if(error!=ERROR_INSUFFICIENT_BUFFER || bytes<sizeof(DWORD) || bytes>4*1024*1024)return ENVARA_ID_UNKNOWN;
        data=(uint8_t*)malloc(bytes);if(!data)return ENVARA_ID_UNKNOWN;
        if(kind)error=GetExtendedUdpTable(data,&bytes,FALSE,af,UDP_TABLE_OWNER_PID,0);
        else error=GetExtendedTcpTable(data,&bytes,FALSE,af,TCP_TABLE_OWNER_PID_ALL,0);
        if(error!=NO_ERROR){free(data);return ENVARA_ID_UNKNOWN;}
        row_size=kind?(family?sizeof(MIB_UDP6ROW_OWNER_PID):sizeof(MIB_UDPROW_OWNER_PID)):
            (family?sizeof(MIB_TCP6ROW_OWNER_PID):sizeof(MIB_TCPROW_OWNER_PID));
        if(*(DWORD*)data>(bytes-sizeof(DWORD))/row_size){free(data);return ENVARA_ID_UNKNOWN;}
        for(i=0;i<*(DWORD*)data;i++) {
            EnvaraTuple t;DWORD pid;static const uint8_t zero[16]={0};memset(&t,0,sizeof(t));
            t.protocol=kind?17:6;t.source.family=t.destination.family=family?6:4;
            if(!family && !kind) {
                MIB_TCPROW_OWNER_PID *r=&((MIB_TCPTABLE_OWNER_PID*)data)->table[i];pid=r->dwOwningPid;
                memcpy(t.source.address,&r->dwLocalAddr,4);memcpy(t.destination.address,&r->dwRemoteAddr,4);
                t.source.port=ntohs((UINT16)r->dwLocalPort);t.destination.port=ntohs((UINT16)r->dwRemotePort);
            }else if(family && !kind) {
                MIB_TCP6ROW_OWNER_PID *r=&((MIB_TCP6TABLE_OWNER_PID*)data)->table[i];pid=r->dwOwningPid;
                memcpy(t.source.address,r->ucLocalAddr,16);memcpy(t.destination.address,r->ucRemoteAddr,16);
                t.source.port=ntohs((UINT16)r->dwLocalPort);t.destination.port=ntohs((UINT16)r->dwRemotePort);
            }else if(!family) {
                MIB_UDPROW_OWNER_PID *r=&((MIB_UDPTABLE_OWNER_PID*)data)->table[i];pid=r->dwOwningPid;
                memcpy(t.source.address,&r->dwLocalAddr,4);t.source.port=ntohs((UINT16)r->dwLocalPort);
            }else {
                MIB_UDP6ROW_OWNER_PID *r=&((MIB_UDP6TABLE_OWNER_PID*)data)->table[i];pid=r->dwOwningPid;
                memcpy(t.source.address,r->ucLocalAddr,16);t.source.port=ntohs((UINT16)r->dwLocalPort);
            }
            if(t.source.port!=packet->source.port ||
                (memcmp(t.source.address,zero,family?16:4) && !envara_endpoint_equal(&t.source,&packet->source)) ||
                (!kind && !envara_endpoint_equal(&t.destination,&packet->destination)))continue;
            if(!pid || (owner_pid && owner_pid!=pid)){free(data);return ENVARA_ID_UNKNOWN;}
            owner_pid=pid;
        }
        free(data);
        if(!owner_pid)return ENVARA_ID_UNKNOWN;
        rc=resolve_pid(owner_pid,timestamp,&id,birth_out);
        if(rc!=ENVARA_OK)return ENVARA_ID_UNKNOWN;
        AcquireSRWLockShared(&core_lock);
        decision=core.identities[id].used && core.identities[id].pid==owner_pid && core.identities[id].creation_time==*birth_out?
            core.identities[id].decision:ENVARA_ID_UNKNOWN;
        ReleaseSRWLockShared(&core_lock);
        *identity_index=id;*pid_out=owner_pid;return decision;
}
static void stop_locked(void) {
    uint32_t i;InterlockedExchange(&running,0);
    if(network_handle!=INVALID_HANDLE_VALUE)WinDivertShutdown(network_handle,WINDIVERT_SHUTDOWN_RECV);
    if(socket_handle!=INVALID_HANDLE_VALUE)WinDivertShutdown(socket_handle,WINDIVERT_SHUTDOWN_RECV);
    if(network_thread){WaitForSingleObject(network_thread,INFINITE);CloseHandle(network_thread);network_thread=NULL;}
    if(socket_thread){WaitForSingleObject(socket_thread,INFINITE);CloseHandle(socket_thread);socket_thread=NULL;}
    /* Explicitly discard already queued packets; never restore unknown packets
     * from user space. Shutdown disables further capture. This is cleanup only,
     * NOT a persistent block: caller must terminate/wait its Jobs first. Stock
     * WinDivert crash/cleanup semantics still forbid a fail-closed claim. */
    if(network_handle!=INVALID_HANDLE_VALUE) {
        uint8_t discard[65535];UINT discard_len;WINDIVERT_ADDRESS discard_addr;
        while(WinDivertRecv(network_handle,discard,sizeof(discard),&discard_len,&discard_addr)) {}
    }
    if(network_handle!=INVALID_HANDLE_VALUE){WinDivertClose(network_handle);network_handle=INVALID_HANDLE_VALUE;}
    if(socket_handle!=INVALID_HANDLE_VALUE){WinDivertClose(socket_handle);socket_handle=INVALID_HANDLE_VALUE;}
    AcquireSRWLockExclusive(&core_lock);
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++)if(core.identities[i].used && core.identities[i].process_handle)
        CloseHandle((HANDLE)(uintptr_t)core.identities[i].process_handle);
    memset(&core,0,sizeof(core));memset(&config,0,sizeof(config));
    counters.running=0;counters.socket_ready=0;counters.network_ready=0;
    counters.tcp_capture=0;counters.udp_blocking=0;counters.identity_callback=0;
    ReleaseSRWLockExclusive(&core_lock);initialized=0;
}
uint32_t ENVARA_CALL EnvaraCaptureStart(const EnvaraCaptureConfig *requested) {
    uint32_t rc=ENVARA_OK;DWORD error=0;UINT64 version=0;
    if(!requested || requested->size!=sizeof(*requested) || requested->version!=ENVARA_CAPTURE_ABI ||
       !requested->resolve_identity || requested->relay_port==0 || requested->relay_port>65535 ||
       requested->hold_milliseconds<10 || requested->hold_milliseconds>250)return ENVARA_ERR_ARGUMENT;
    AcquireSRWLockExclusive(&lifecycle_lock);
    if(initialized){ReleaseSRWLockExclusive(&lifecycle_lock);return ENVARA_ERR_STATE;}
    AcquireSRWLockExclusive(&core_lock);
    config=*requested;envara_core_init(&core,(uint16_t)config.relay_port);memset(&counters,0,sizeof(counters));
    counters.size=sizeof(counters);counters.version=ENVARA_CAPTURE_ABI;initialized=1;
    ReleaseSRWLockExclusive(&core_lock);
    if(!QueryPerformanceFrequency(&qpc_frequency) || qpc_frequency.QuadPart<=0){rc=ENVARA_ERR_STATE;goto failed;}
    socket_handle=WinDivertOpen("tcp or udp",WINDIVERT_LAYER_SOCKET,2111,WINDIVERT_FLAG_SNIFF|WINDIVERT_FLAG_RECV_ONLY);
    if(socket_handle==INVALID_HANDLE_VALUE){rc=ENVARA_ERR_DRIVER;goto failed;}
    if(!WinDivertGetParam(socket_handle,WINDIVERT_PARAM_VERSION_MAJOR,&version) || version!=2){rc=ENVARA_ERR_DRIVER;goto failed;}
    InterlockedExchange(&running,1);
    socket_thread=CreateThread(NULL,0,socket_worker,NULL,0,NULL);if(!socket_thread){rc=ENVARA_ERR_STATE;goto failed;}
    if(!InterlockedCompareExchange(&running,0,0)){rc=ENVARA_ERR_STATE;goto failed;}
    /* fragment catches IPv4/IPv6 extension-header fragments as well. Other IP
     * protocols are outside this experimental TCP/UDP capture capability. */
    network_handle=WinDivertOpen("tcp or udp or fragment",WINDIVERT_LAYER_NETWORK,2110,0);
    if(network_handle==INVALID_HANDLE_VALUE){rc=ENVARA_ERR_DRIVER;goto failed;}
    if(!WinDivertSetParam(network_handle,WINDIVERT_PARAM_QUEUE_LENGTH,2048) ||
       !WinDivertSetParam(network_handle,WINDIVERT_PARAM_QUEUE_SIZE,4*1024*1024) ||
       !WinDivertSetParam(network_handle,WINDIVERT_PARAM_QUEUE_TIME,1000)){rc=ENVARA_ERR_DRIVER;goto failed;}
    AcquireSRWLockExclusive(&core_lock);
    counters.running=1;counters.socket_ready=1;counters.network_ready=1;
    counters.tcp_capture=1;counters.udp_blocking=1;counters.identity_callback=1;
    ReleaseSRWLockExclusive(&core_lock);
    network_thread=CreateThread(NULL,0,network_worker,NULL,0,NULL);if(!network_thread){rc=ENVARA_ERR_STATE;goto failed;}
    if(!InterlockedCompareExchange(&running,0,0)){rc=ENVARA_ERR_STATE;goto failed;}
    ReleaseSRWLockExclusive(&lifecycle_lock);return ENVARA_OK;
failed:
    error=GetLastError();stop_locked();
    AcquireSRWLockExclusive(&core_lock);counters.last_error=error?error:ERROR_INVALID_DATA;ReleaseSRWLockExclusive(&core_lock);
    ReleaseSRWLockExclusive(&lifecycle_lock);return rc;
}
uint32_t ENVARA_CALL EnvaraCaptureStop(void) {
    AcquireSRWLockExclusive(&lifecycle_lock);if(initialized)stop_locked();ReleaseSRWLockExclusive(&lifecycle_lock);return ENVARA_OK;
}
uint32_t ENVARA_CALL EnvaraCaptureRevokeSession(const EnvaraRevokeRequest *r) {
    uint32_t rc;
    if(!r || r->size!=sizeof(*r) || r->version!=ENVARA_CAPTURE_ABI)return ENVARA_ERR_ARGUMENT;
    AcquireSRWLockExclusive(&core_lock);
    rc=InterlockedCompareExchange(&running,0,0)?envara_core_revoke(&core,r->session_tag,r->generation):ENVARA_ERR_STATE;
    ReleaseSRWLockExclusive(&core_lock);
    if(rc==ENVARA_ERR_CAPACITY)fail(ERROR_NOT_ENOUGH_MEMORY);
    return rc;
}
uint32_t ENVARA_CALL EnvaraCaptureLookupRelay(const EnvaraRelayQuery *query,EnvaraRelayResult *result) {
    uint32_t rc;
    if(!query || !result || query->size!=sizeof(*query) || query->version!=ENVARA_CAPTURE_ABI ||
       result->size!=sizeof(*result) || result->version!=ENVARA_CAPTURE_ABI || !envara_tuple_valid(&query->accepted))return ENVARA_ERR_ARGUMENT;
    AcquireSRWLockExclusive(&core_lock);expire_processes_locked();
    rc=InterlockedCompareExchange(&running,0,0)?envara_core_lookup(&core,&query->accepted,result):ENVARA_ERR_STATE;
    ReleaseSRWLockExclusive(&core_lock);return rc;
}
uint32_t ENVARA_CALL EnvaraCaptureStatusRead(EnvaraCaptureStatus *out) {
    uint32_t i;
    if(!out || out->size!=sizeof(*out) || out->version!=ENVARA_CAPTURE_ABI)return ENVARA_ERR_ARGUMENT;
    AcquireSRWLockShared(&core_lock);*out=counters;out->size=sizeof(*out);out->version=ENVARA_CAPTURE_ABI;
    out->running=(uint32_t)InterlockedCompareExchange(&running,0,0);out->active_flows=0;out->active_identities=0;
    for(i=0;i<ENVARA_CAPTURE_MAX_FLOWS;i++)if(core.flows[i].used)out->active_flows++;
    for(i=0;i<ENVARA_CAPTURE_MAX_IDENTITIES;i++)if(core.identities[i].used)out->active_identities++;
    /* Immutable acceptance boundary; no config flag, registry value or RPC
     * overrides DNS isolation, persistent fail-closed or real-Windows QA. */
    out->ready=0;out->dns=0;out->fail_closed=0;out->verification_passed=0;
    ReleaseSRWLockShared(&core_lock);return ENVARA_OK;
}
