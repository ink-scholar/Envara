/*
 * Envara process-owned WFP callout driver. MIT.
 *
 * TCP is redirected to the managed local SOCKS relay. UDP and non-TCP protocols
 * are blocked for owned processes (never silently sent directly). Shared DNS
 * Client service attribution is intentionally NOT advertised by this driver.
 * Public launch stays disabled until the service can also isolate that path.
 *
 * This driver does not map executable names. A suspended root is registered by
 * process object and creation time; kernel process-create callbacks inherit its
 * route before child user-mode code starts. Process-exit callbacks remove the
 * object before PID reuse. Revoke keeps living process entries as blocked
 * tombstones, and an expired service heartbeat blocks all owned connections.
 */
#include <ntifs.h>
#include <wdmsec.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ntintsafe.h>
#include "envara_wire.h"
#include "envara_lifecycle.h"

#define ENVARA_TAG 'rvnE'
#define ENVARA_HEARTBEAT_TICKS (10ull * 10000000ull)

static const GUID providerKey = {0x8c6a4421,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID sublayerKey = {0x8c6a4422,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID redirect4Key = {0x8c6a4423,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID redirect6Key = {0x8c6a4424,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID auth4Key = {0x8c6a4425,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID auth6Key = {0x8c6a4426,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID deviceClass = {0x8c6a4427,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID receive4Key = {0x8c6a4428,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};
static const GUID receive6Key = {0x8c6a4429,0x1fb0,0x40cb,{0xb4,0x94,0xfa,0x8d,0x67,0xa9,0x27,0x11}};

typedef struct OWNED_ROUTE {
    UINT64 id;
    UINT64 ownerPid;
    UINT64 heartbeat;
    UINT16 proxyPort;
    BOOLEAN active;
    UINT64 generation;
} OWNED_ROUTE;

typedef struct OWNED_PROCESS {
    UINT64 pid;
    PEPROCESS object;
    UINT64 routeId;
} OWNED_PROCESS;

static PDEVICE_OBJECT deviceObject;
static HANDLE engineHandle;
static HANDLE redirectHandle;
static UINT32 calloutIds[6];
static OWNED_ROUTE routes[ENVARA_MAX_ROUTES];
static OWNED_PROCESS processes[ENVARA_MAX_PROCESSES];
static KSPIN_LOCK tableLock;
static BOOLEAN processNotifyRegistered;
static HANDLE bfeSubscription;
static KMUTEX lifecycleMutex;
static ENVARA_LIFECYCLE lifecycle;
static FWPM_SERVICE_STATE observedBfeState=FWPM_SERVICE_STOPPED;
static UINT64 filterIds[6];
static NTSTATUS lastFilteringFailure=STATUS_DEVICE_NOT_READY;
static BOOLEAN shuttingDown;
static PEPROCESS terminationSnapshot[ENVARA_MAX_PROCESSES];

static VOID BfeStateChanged(VOID* context,FWPM_SERVICE_STATE state);
static BOOLEAN VerifyFilteringLocked(VOID);
static VOID InvalidateAndDrainLocked(VOID);

static OWNED_ROUTE* FindRouteLocked(UINT64 id) {
    UINT32 i;
    if(id==0) return NULL;
    for (i=0;i<ENVARA_MAX_ROUTES;i++) if (routes[i].id==id) return &routes[i];
    return NULL;
}

static OWNED_PROCESS* FindProcessLocked(UINT64 pid) {
    UINT32 i;
    if(pid==0) return NULL;
    for (i=0;i<ENVARA_MAX_PROCESSES;i++) if (processes[i].pid==pid) return &processes[i];
    return NULL;
}

static BOOLEAN Snapshot(UINT64 pid, OWNED_ROUTE* route) {
    KIRQL irql;
    OWNED_PROCESS* process;
    OWNED_ROUTE* found;
    BOOLEAN owned=FALSE;
    KeAcquireSpinLock(&tableLock,&irql);
    process=FindProcessLocked(pid);
    if (process!=NULL) {
        owned=TRUE;
        found=FindRouteLocked(process->routeId);
        RtlZeroMemory(route,sizeof(*route));
        if (found!=NULL) {
            *route=*found;
            if(!EnvaraLifecycleAllows(&lifecycle,route->generation,route->active)) route->active=FALSE;
        }
    }
    KeReleaseSpinLock(&tableLock,irql);
    return owned;
}

static BOOLEAN Alive(const OWNED_ROUTE* route) {
    UINT64 now=KeQueryInterruptTime();
    return route->active && FwpmBfeStateGet0()==FWPM_SERVICE_RUNNING &&
        route->heartbeat<=now && now-route->heartbeat<=ENVARA_HEARTBEAT_TICKS;
}

static VOID ProcessNotify(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO info) {
    KIRQL irql;
    UINT32 i;
    PEPROCESS release=NULL;
    OWNED_PROCESS* parent;
    UINT64 parentRoute=0;
    KeAcquireSpinLock(&tableLock,&irql);
    if (info==NULL) {
        OWNED_PROCESS* entry=FindProcessLocked((UINT64)(ULONG_PTR)processId);
        if (entry!=NULL && entry->object==process) {
            UINT64 oldRoute=entry->routeId;
            BOOLEAN hasLivingProcess=FALSE;
            release=entry->object;
            RtlZeroMemory(entry,sizeof(*entry));
            for(i=0;i<ENVARA_MAX_PROCESSES;i++) if(processes[i].routeId==oldRoute) {hasLivingProcess=TRUE;break;}
            if(!hasLivingProcess) {
                OWNED_ROUTE* unused=FindRouteLocked(oldRoute);
                if(unused!=NULL) RtlZeroMemory(unused,sizeof(*unused));
            }
        }
    } else {
        /* Use the creating process, not a user-selected spoofable parent PID. */
        parent=FindProcessLocked((UINT64)(ULONG_PTR)info->CreatingThreadId.UniqueProcess);
        if (parent!=NULL) parentRoute=parent->routeId;
        if (parentRoute!=0) {
            OWNED_ROUTE* inherited=FindRouteLocked(parentRoute);
            if(inherited==NULL || !EnvaraLifecycleAllows(&lifecycle,inherited->generation,inherited->active) || !Alive(inherited)) {
                info->CreationStatus=STATUS_NETWORK_UNREACHABLE;
                KeReleaseSpinLock(&tableLock,irql);
                return;
            }
            for (i=0;i<ENVARA_MAX_PROCESSES;i++) if (processes[i].pid==0) break;
            if (i==ENVARA_MAX_PROCESSES) {
                /* An untracked owned child must not get an opportunity to run. */
                info->CreationStatus=STATUS_INSUFFICIENT_RESOURCES;
            } else {
                ObReferenceObject(process);
                processes[i].pid=(UINT64)(ULONG_PTR)processId;
                processes[i].object=process;
                processes[i].routeId=parentRoute;
            }
        }
    }
    KeReleaseSpinLock(&tableLock,irql);
    if (release!=NULL) ObDereferenceObject(release);
}

static VOID Block(FWPS_CLASSIFY_OUT0* out) {
    out->actionType=FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static VOID NTAPI ClassifyRedirect(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layerData,
    const VOID* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    OWNED_ROUTE route;
    UINT8 protocol;
    UINT64 handle=0;
    FWPS_CONNECT_REQUEST0* request=NULL;
    ENVARA_REDIRECT_CONTEXT* context=NULL;
    NTSTATUS status;
    BOOLEAN ipv6=(values->layerId==FWPS_LAYER_ALE_CONNECT_REDIRECT_V6);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);
    out->actionType=FWP_ACTION_CONTINUE;
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
        !Snapshot(metadata->processId,&route)) return;
    if (!Alive(&route) || !(out->rights & FWPS_RIGHT_ACTION_WRITE)) { Block(out);return; }
    protocol=values->incomingValue[ipv6 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL :
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    if (protocol!=IPPROTO_TCP) { Block(out);return; }
    if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) {
        FWPS_CONNECTION_REDIRECT_STATE state=FwpsQueryConnectionRedirectState0(
            metadata->redirectRecords,redirectHandle,NULL);
        if (state==FWPS_CONNECTION_REDIRECTED_BY_SELF || state==FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) return;
        /* Do not chain to another app proxy and lose our ownership guarantees. */
        if (state!=FWPS_CONNECTION_NOT_REDIRECTED) { Block(out);return; }
    }
    status=FwpsAcquireClassifyHandle0((VOID*)classifyContext,0,&handle);
    if (!NT_SUCCESS(status)) { Block(out);return; }
    status=FwpsAcquireWritableLayerDataPointer0(handle,filter->filterId,0,(VOID**)&request,out);
    if (!NT_SUCCESS(status)) { FwpsReleaseClassifyHandle0(handle);Block(out);return; }
    context=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*context),ENVARA_TAG);
    if (context!=NULL) {
        RtlZeroMemory(context,sizeof(*context));
        context->magic=ENVARA_CONTEXT_MAGIC;
        context->version=ENVARA_ABI_VERSION;
        context->routeId=route.id;
        context->sourcePid=metadata->processId;
        if (!ipv6) {
            SOCKADDR_IN* remote=(SOCKADDR_IN*)&request->remoteAddressAndPort;
            SOCKADDR_IN* local=(SOCKADDR_IN*)&request->localAddressAndPort;
            context->family=AF_INET;
            context->port=RtlUshortByteSwap(remote->sin_port);
            RtlCopyMemory(context->address,&remote->sin_addr,4);
            /* Binding to a physical source cannot safely redirect to loopback. */
            if (local->sin_addr.S_un.S_addr!=0 && local->sin_addr.S_un.S_addr!=RtlUlongByteSwap(0x7f000001)) {
                ExFreePoolWithTag(context,ENVARA_TAG);context=NULL;
            } else {
                RtlZeroMemory(remote,sizeof(*remote));
                remote->sin_family=AF_INET;
                remote->sin_addr.S_un.S_addr=RtlUlongByteSwap(0x7f000001);
                remote->sin_port=RtlUshortByteSwap(route.proxyPort);
            }
        } else {
            SOCKADDR_IN6* remote=(SOCKADDR_IN6*)&request->remoteAddressAndPort;
            SOCKADDR_IN6* local=(SOCKADDR_IN6*)&request->localAddressAndPort;
            static const UCHAR any[16]={0};
            static const UCHAR loopback[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
            context->family=AF_INET6;
            context->port=RtlUshortByteSwap(remote->sin6_port);
            RtlCopyMemory(context->address,&remote->sin6_addr,16);
            if (RtlCompareMemory(&local->sin6_addr,any,16)!=16 &&
                RtlCompareMemory(&local->sin6_addr,loopback,16)!=16) {
                ExFreePoolWithTag(context,ENVARA_TAG);context=NULL;
            } else {
                RtlZeroMemory(remote,sizeof(*remote));
                remote->sin6_family=AF_INET6;
                remote->sin6_addr.u.Byte[15]=1;
                remote->sin6_port=RtlUshortByteSwap(route.proxyPort);
            }
        }
        if (context!=NULL) {
            request->localRedirectContext=context;
            request->localRedirectContextSize=sizeof(*context);
            request->localRedirectHandle=redirectHandle;
            request->localRedirectTargetPID=route.ownerPid;
            /* WFP owns the nonpaged context after apply. Do not free it here. */
        }
    }
    /* Matching apply is mandatory even when no modification could be made. */
    FwpsApplyModifiedLayerData0(handle,request,FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
    FwpsReleaseClassifyHandle0(handle);
    if (context==NULL) Block(out); else out->actionType=FWP_ACTION_PERMIT;
}

static VOID NTAPI ClassifyAuthorize(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layerData,
    const VOID* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    OWNED_ROUTE route;
    UINT8 protocol;
    UINT32 flags;
    BOOLEAN loopback;
    BOOLEAN ipv6=(values->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V6);
    UNREFERENCED_PARAMETER(layerData);UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);UNREFERENCED_PARAMETER(flowContext);
    out->actionType=FWP_ACTION_CONTINUE;
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
        !Snapshot(metadata->processId,&route)) return;
    protocol=values->incomingValue[ipv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL :
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    flags=values->incomingValue[ipv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS :
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS].value.uint32;
    if(ipv6) {
        static const UCHAR address[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        loopback=(RtlCompareMemory(values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16,address,16)==16);
    } else loopback=(values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32==0x7f000001);
    /* No unconditional localhost exception; unowned localhost relays are bypasses. */
    if (!Alive(&route) || protocol!=IPPROTO_TCP || !loopback || !(flags & FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED) ||
        !(metadata->currentMetadataValues & FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID) ||
        metadata->localRedirectTargetPID!=route.ownerPid ||
        values->incomingValue[ipv6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT :
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16!=route.proxyPort) {
        Block(out);
    }
}

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER1* filter) {
    UNREFERENCED_PARAMETER(type);UNREFERENCED_PARAMETER(key);UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI ClassifyReceive(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layerData,
    const VOID* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    OWNED_ROUTE route;
    BOOLEAN loopback;
    UINT8 protocol;
    BOOLEAN ipv6=(values->layerId==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    UNREFERENCED_PARAMETER(layerData);UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);UNREFERENCED_PARAMETER(flowContext);
    out->actionType=FWP_ACTION_CONTINUE;
    if(!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
        !Snapshot(metadata->processId,&route)) return;
    protocol=values->incomingValue[ipv6 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL :
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
    if(ipv6) {
        static const UCHAR address[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        loopback=(RtlCompareMemory(values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16,address,16)==16);
    } else loopback=((values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32 & 0xff000000)==0x7f000000);
    /* Outbound-only application attachment: no physical-interface accepted flow
     * may create a direct response path that bypasses connect redirection. */
    if(!Alive(&route) || protocol!=IPPROTO_TCP || !loopback) Block(out);
}

static NTSTATUS RegisterCallout(const GUID* key,const GUID* layer,FWPS_CALLOUT_CLASSIFY_FN1 classify,UINT32 index) {
    FWPS_CALLOUT1 kernel={0};
    FWPM_CALLOUT0 management={0};
    FWPM_FILTER0 filter={0};
    NTSTATUS status;
    kernel.calloutKey=*key;kernel.classifyFn=classify;kernel.notifyFn=Notify;
    /* Kernel registrations survive BFE restart. Never register the same GUID
     * a second time; only the FWPM management objects are reconstructed. */
    if(calloutIds[index]==0) {
        status=FwpsCalloutRegister1(deviceObject,&kernel,&calloutIds[index]);
        if (!NT_SUCCESS(status)) return status;
    }
    management.calloutKey=*key;management.providerKey=(GUID*)&providerKey;
    management.applicableLayer=*layer;management.displayData.name=L"Envara owned process routing";
    status=FwpmCalloutAdd0(engineHandle,&management,NULL,NULL);
    if (!NT_SUCCESS(status)) return status;
    filter.displayData.name=L"Envara owned process routing";
    filter.providerKey=(GUID*)&providerKey;filter.layerKey=*layer;filter.subLayerKey=sublayerKey;
    filter.weight.type=FWP_UINT8;filter.weight.uint8=15;
    filter.action.type=FWP_ACTION_CALLOUT_UNKNOWN;filter.action.calloutKey=*key;
    return FwpmFilterAdd0(engineHandle,&filter,NULL,&filterIds[index]);
}

static NTSTATUS RegisterFiltering(VOID) {
    FWPM_SESSION0 session={0};
    FWPM_PROVIDER0 provider={0};
    FWPM_SUBLAYER0 sublayer={0};
    NTSTATUS status;
    if(FwpmBfeStateGet0()!=FWPM_SERVICE_RUNNING) return STATUS_DEVICE_NOT_READY;
    session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    status=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&engineHandle);
    if (!NT_SUCCESS(status)) return status;
    status=FwpmTransactionBegin0(engineHandle,0);
    if (!NT_SUCCESS(status)) return status;
    provider.providerKey=providerKey;provider.displayData.name=L"Envara";
    status=FwpmProviderAdd0(engineHandle,&provider,NULL);
    if (!NT_SUCCESS(status)) goto failure;
    sublayer.subLayerKey=sublayerKey;sublayer.providerKey=(GUID*)&providerKey;
    sublayer.displayData.name=L"Envara process routing";sublayer.weight=0x8000;
    status=FwpmSubLayerAdd0(engineHandle,&sublayer,NULL);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&redirect4Key,&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,ClassifyRedirect,0);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&redirect6Key,&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,ClassifyRedirect,1);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&auth4Key,&FWPM_LAYER_ALE_AUTH_CONNECT_V4,ClassifyAuthorize,2);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&auth6Key,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,ClassifyAuthorize,3);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&receive4Key,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,ClassifyReceive,4);
    if (!NT_SUCCESS(status)) goto failure;
    status=RegisterCallout(&receive6Key,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,ClassifyReceive,5);
    if (!NT_SUCCESS(status)) goto failure;
    return FwpmTransactionCommit0(engineHandle);
failure:
    FwpmTransactionAbort0(engineHandle);
    return status;
}

/* All functions below run at PASSIVE_LEVEL with lifecycleMutex held. Do not
 * acquire a FAST_MUTEX here: it would raise IRQL above WFP management's limit. */
static VOID CloseFilteringLocked(VOID) {
    if(engineHandle!=NULL) {FwpmEngineClose0(engineHandle);engineHandle=NULL;}
    RtlZeroMemory(filterIds,sizeof(filterIds));
}

static BOOLEAN FiltersPresentLocked(VOID) {
    UINT32 i;
    static const GUID* keys[6]={&redirect4Key,&redirect6Key,&auth4Key,&auth6Key,&receive4Key,&receive6Key};
    static const GUID* layers[6]={&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    if(engineHandle==NULL || FwpmBfeStateGet0()!=FWPM_SERVICE_RUNNING) return FALSE;
    for(i=0;i<6;i++) {
        FWPM_FILTER0* filter=NULL;
        BOOLEAN valid;
        NTSTATUS status;
        if(filterIds[i]==0) return FALSE;
        status=FwpmFilterGetById0(engineHandle,filterIds[i],&filter);
        if(!NT_SUCCESS(status) || filter==NULL) return FALSE;
        valid=(filter->providerKey!=NULL && RtlEqualMemory(filter->providerKey,&providerKey,sizeof(GUID)) &&
            RtlEqualMemory(&filter->subLayerKey,&sublayerKey,sizeof(GUID)) &&
            RtlEqualMemory(&filter->layerKey,layers[i],sizeof(GUID)) &&
            filter->numFilterConditions==0 &&
            filter->action.type==FWP_ACTION_CALLOUT_UNKNOWN &&
            RtlEqualMemory(&filter->action.calloutKey,keys[i],sizeof(GUID)));
        FwpmFreeMemory0((VOID**)&filter);
        if(!valid) return FALSE;
    }
    return TRUE;
}

static BOOLEAN DrainOwnedProcessesLocked(VOID) {
    KIRQL irql;
    UINT32 count=0,i;
    BOOLEAN drained=TRUE;
    UINT64 deadline=KeQueryInterruptTime()+5ull*10000000ull;
    /* Objects, not PIDs, are retained through termination and wait; PID reuse
     * cannot cause termination of a replacement process. tableLock is released
     * before any blocking API or process-exit notification can run. */
    KeAcquireSpinLock(&tableLock,&irql);
    for(i=0;i<ENVARA_MAX_PROCESSES;i++) if(processes[i].object!=NULL) {
        ObReferenceObject(processes[i].object);
        terminationSnapshot[count++]=processes[i].object;
    }
    KeReleaseSpinLock(&tableLock,irql);
    for(i=0;i<count;i++) {
        HANDLE handle=NULL;
        PEPROCESS process=terminationSnapshot[i];
        if(PsGetProcessExitStatus(process)==STATUS_PENDING) {
            NTSTATUS status=ObOpenObjectByPointer(process,OBJ_KERNEL_HANDLE,NULL,
                PROCESS_TERMINATE|SYNCHRONIZE,NULL,KernelMode,&handle);
            if(NT_SUCCESS(status)) {status=ZwTerminateProcess(handle,STATUS_NETWORK_UNREACHABLE);ZwClose(handle);}
            if(!NT_SUCCESS(status) && PsGetProcessExitStatus(process)==STATUS_PENDING) drained=FALSE;
        }
    }
    for(i=0;i<count;i++) {
        PEPROCESS process=terminationSnapshot[i];
        if(PsGetProcessExitStatus(process)==STATUS_PENDING) {
            UINT64 now=KeQueryInterruptTime();
            LARGE_INTEGER timeout;
            if(now>=deadline) drained=FALSE;
            else {
                timeout.QuadPart=-(LONGLONG)(deadline-now);
                /* STATUS_TIMEOUT is nonnegative; NT_SUCCESS would wrongly
                 * report it as a successful complete process-tree drain. */
                if(KeWaitForSingleObject(process,Executive,KernelMode,FALSE,&timeout)!=STATUS_SUCCESS) drained=FALSE;
            }
        }
        ObDereferenceObject(process);terminationSnapshot[i]=NULL;
    }
    return drained;
}

static VOID InvalidateAndDrainLocked(VOID) {
    KIRQL irql;
    UINT32 i;
    BOOLEAN drained;
    KeAcquireSpinLock(&tableLock,&irql);
    EnvaraLifecycleInvalidate(&lifecycle);
    for(i=0;i<ENVARA_MAX_ROUTES;i++) routes[i].active=FALSE;
    KeReleaseSpinLock(&tableLock,irql);
    /* New inherited children have already been denied by ProcessNotify. */
    drained=DrainOwnedProcessesLocked();
    KeAcquireSpinLock(&tableLock,&irql);
    lifecycle.drained=drained ? 1u : 0u;
    KeReleaseSpinLock(&tableLock,irql);
    if(!drained) lastFilteringFailure=STATUS_TIMEOUT;
}

static NTSTATUS RebuildFilteringLocked(VOID) {
    KIRQL irql;
    UINT32 i;
    BOOLEAN drained=TRUE;
    NTSTATUS status;
    CloseFilteringLocked();
    if(shuttingDown || FwpmBfeStateGet0()!=FWPM_SERVICE_RUNNING) return STATUS_DEVICE_NOT_READY;
    KeAcquireSpinLock(&tableLock,&irql);
    for(i=0;i<ENVARA_MAX_PROCESSES;i++) if(processes[i].object!=NULL) {drained=FALSE;break;}
    KeReleaseSpinLock(&tableLock,irql);
    /* Do not restore availability while an old owner survived termination. */
    if(!drained) return STATUS_DEVICE_BUSY;
    status=RegisterFiltering();
    if(!NT_SUCCESS(status) || !FiltersPresentLocked()) {
        CloseFilteringLocked();return NT_SUCCESS(status) ? STATUS_DEVICE_NOT_READY : status;
    }
    KeAcquireSpinLock(&tableLock,&irql);
    drained=EnvaraLifecycleRebuilt(&lifecycle,FwpmBfeStateGet0()==FWPM_SERVICE_RUNNING,TRUE,drained);
    KeReleaseSpinLock(&tableLock,irql);
    return drained ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
}

static VOID NTAPI BfeStateChanged(VOID* context,FWPM_SERVICE_STATE state) {
    UNREFERENCED_PARAMETER(context);
    KeWaitForSingleObject(&lifecycleMutex,Executive,KernelMode,FALSE,NULL);
    observedBfeState=state;
    if(!shuttingDown) {
        /* STOP_PENDING cleanup happens before orderly BFE stop, as required by
         * Microsoft's lifecycle API. Abrupt-crash timing remains a native test
         * requirement; this source does not assert an instantaneous guarantee. */
        InvalidateAndDrainLocked();
        if(state==FWPM_SERVICE_RUNNING) lastFilteringFailure=RebuildFilteringLocked();
        else {CloseFilteringLocked();lastFilteringFailure=STATUS_DEVICE_NOT_READY;}
    }
    KeReleaseMutex(&lifecycleMutex,FALSE);
}

static BOOLEAN VerifyFilteringLocked(VOID) {
    KIRQL irql;
    BOOLEAN enforcing;
    KeAcquireSpinLock(&tableLock,&irql);enforcing=lifecycle.enforcing!=0;KeReleaseSpinLock(&tableLock,irql);
    if(enforcing && FwpmBfeStateGet0()==FWPM_SERVICE_RUNNING && FiltersPresentLocked()) return TRUE;
    InvalidateAndDrainLocked();
    observedBfeState=FwpmBfeStateGet0();
    if(observedBfeState==FWPM_SERVICE_RUNNING) lastFilteringFailure=RebuildFilteringLocked();
    else {CloseFilteringLocked();lastFilteringFailure=STATUS_DEVICE_NOT_READY;}
    return lastFilteringFailure==STATUS_SUCCESS;
}

static NTSTATUS Complete(PIRP irp,NTSTATUS status,ULONG_PTR bytes) {
    irp->IoStatus.Status=status;irp->IoStatus.Information=bytes;
    IoCompleteRequest(irp,IO_NO_INCREMENT);return status;
}

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT device,PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    return Complete(irp,STATUS_SUCCESS,0);
}

static NTSTATUS AddRoute(PIRP irp,ENVARA_ROUTE_REQUEST* request) {
    PEPROCESS root=NULL;
    NTSTATUS status;
    KIRQL irql;
    UINT32 slot,processSlot;
    if (request->version!=ENVARA_ABI_VERSION || request->routeId==0 || request->rootPid==0 || request->ownerPid==0 || request->proxyPort==0 ||
        request->flags!=ENVARA_ROUTE_UDP_BLOCK || request->reserved16!=0 || request->reserved32!=0 ||
        request->ownerPid!=(UINT64)(ULONG_PTR)IoGetRequestorProcessId(irp)) return STATUS_INVALID_PARAMETER;
    status=PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->rootPid,&root);
    if (!NT_SUCCESS(status)) return status;
    if ((UINT64)PsGetProcessCreateTimeQuadPart(root)!=request->rootCreationTime ||
        PsGetProcessExitStatus(root)!=STATUS_PENDING) { ObDereferenceObject(root);return STATUS_INVALID_PARAMETER; }
    KeAcquireSpinLock(&tableLock,&irql);
    if (FindProcessLocked(request->rootPid)!=NULL || FindRouteLocked(request->routeId)!=NULL) {
        status=STATUS_OBJECT_NAME_COLLISION;goto done;
    }
    for(slot=0;slot<ENVARA_MAX_ROUTES;slot++) if(routes[slot].id==0) break;
    for(processSlot=0;processSlot<ENVARA_MAX_PROCESSES;processSlot++) if(processes[processSlot].pid==0) break;
    if(slot==ENVARA_MAX_ROUTES || processSlot==ENVARA_MAX_PROCESSES) {status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
    routes[slot].id=request->routeId;routes[slot].ownerPid=request->ownerPid;
    routes[slot].proxyPort=request->proxyPort;routes[slot].active=TRUE;
    routes[slot].heartbeat=KeQueryInterruptTime();
    routes[slot].generation=lifecycle.generation;
    processes[processSlot].pid=request->rootPid;processes[processSlot].object=root;
    processes[processSlot].routeId=request->routeId;root=NULL;
    status=STATUS_SUCCESS;
done:
    KeReleaseSpinLock(&tableLock,irql);
    if(root!=NULL) ObDereferenceObject(root);
    return status;
}

static NTSTATUS DispatchControl(PDEVICE_OBJECT device,PIRP irp) {
    PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);
    ULONG code=stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG input=stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG output=stack->Parameters.DeviceIoControl.OutputBufferLength;
    KIRQL irql;
    NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes=0;
    UINT32 i;
    UNREFERENCED_PARAMETER(device);
    /* WFP management verification may wait on BFE; it is never executed from a
     * DISPATCH-level classify callback or while holding tableLock. */
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL) return Complete(irp,STATUS_INVALID_DEVICE_STATE,0);
    KeWaitForSingleObject(&lifecycleMutex,Executive,KernelMode,FALSE,NULL);
    if(code==IOCTL_ENVARA_STATUS && output>=sizeof(ENVARA_STATUS)) {
        ENVARA_STATUS* result=irp->AssociatedIrp.SystemBuffer;
        BOOLEAN healthy=VerifyFilteringLocked();
        RtlZeroMemory(result,sizeof(*result));result->version=ENVARA_ABI_VERSION;
        result->capabilities=ENVARA_CAP_TCP|ENVARA_CAP_UDP_BLOCK|ENVARA_CAP_CHILD_PROCESSES|ENVARA_CAP_FAIL_CLOSED;
        result->bfeState=FwpmBfeStateGet0();result->filteringReady=healthy ? 1u : 0u;
        result->lastFailure=(UINT32)lastFilteringFailure;
        KeAcquireSpinLock(&tableLock,&irql);
        result->generation=lifecycle.generation;
        for(i=0;i<ENVARA_MAX_ROUTES;i++) if(routes[i].active) result->routes++;
        for(i=0;i<ENVARA_MAX_PROCESSES;i++) if(processes[i].pid!=0) result->processes++;
        KeReleaseSpinLock(&tableLock,irql);
        status=STATUS_SUCCESS;bytes=sizeof(*result);
    } else if(code==IOCTL_ENVARA_ADD_ROUTE && input==sizeof(ENVARA_ROUTE_REQUEST)) {
        status=VerifyFilteringLocked() ? AddRoute(irp,irp->AssociatedIrp.SystemBuffer) : STATUS_DEVICE_NOT_READY;
    } else if(code==IOCTL_ENVARA_PROCESS_ROUTE && input==sizeof(ENVARA_PROCESS_QUERY) && output>=sizeof(ENVARA_PROCESS_ROUTE)) {
        ENVARA_PROCESS_QUERY request=*(ENVARA_PROCESS_QUERY*)irp->AssociatedIrp.SystemBuffer;
        ENVARA_PROCESS_ROUTE* result=irp->AssociatedIrp.SystemBuffer;
        OWNED_PROCESS* process;
        OWNED_ROUTE* route;
        RtlZeroMemory(result,sizeof(*result));
        status=STATUS_NOT_FOUND;
        if(request.version==ENVARA_ABI_VERSION && request.reserved==0 && request.pid!=0 && VerifyFilteringLocked()) {
            KeAcquireSpinLock(&tableLock,&irql);
            process=FindProcessLocked(request.pid);
            route=process==NULL ? NULL : FindRouteLocked(process->routeId);
            if(process!=NULL && (UINT64)PsGetProcessCreateTimeQuadPart(process->object)==request.creationTime &&
                route!=NULL && route->ownerPid==(UINT64)(ULONG_PTR)IoGetRequestorProcessId(irp) &&
                EnvaraLifecycleAllows(&lifecycle,route->generation,route->active) && Alive(route)) {
                result->version=ENVARA_ABI_VERSION;result->active=1;result->routeId=route->id;result->generation=route->generation;
                status=STATUS_SUCCESS;bytes=sizeof(*result);
            }
            KeReleaseSpinLock(&tableLock,irql);
        }
    } else if((code==IOCTL_ENVARA_REVOKE_ROUTE || code==IOCTL_ENVARA_HEARTBEAT) && input==sizeof(ENVARA_ROUTE_ID)) {
        ENVARA_ROUTE_ID* request=irp->AssociatedIrp.SystemBuffer;
        OWNED_ROUTE* route;
        if(request->version!=ENVARA_ABI_VERSION || request->reserved!=0) {status=STATUS_INVALID_PARAMETER;goto complete;}
        if(code==IOCTL_ENVARA_HEARTBEAT && !VerifyFilteringLocked()) {status=STATUS_DEVICE_NOT_READY;goto complete;}
        KeAcquireSpinLock(&tableLock,&irql);
        route=FindRouteLocked(request->routeId);
        status=STATUS_NOT_FOUND;
        if(route!=NULL && route->ownerPid==(UINT64)(ULONG_PTR)IoGetRequestorProcessId(irp)) {
            if(code==IOCTL_ENVARA_REVOKE_ROUTE) route->active=FALSE;
            else if(EnvaraLifecycleAllows(&lifecycle,route->generation,route->active)) route->heartbeat=KeQueryInterruptTime();
            else {status=STATUS_NETWORK_UNREACHABLE;goto unlockTable;}
            status=STATUS_SUCCESS;
        }
unlockTable:
        KeReleaseSpinLock(&tableLock,irql);
    }
complete:
    KeReleaseMutex(&lifecycleMutex,FALSE);
    return Complete(irp,status,bytes);
}

/* Cleanup is used only on failed load, before a registered root can execute.
 * A running production driver is deliberately not unloadable: removing its
 * filters while an owned process lives would create a direct-traffic window.
 * Driver replacement/removal requires a reboot after all managed jobs stop. */
static VOID CleanupFailedLoad(VOID) {
    UINT32 i;
    UNICODE_STRING name=RTL_CONSTANT_STRING(ENVARA_DOS_DEVICE_NAME);
    /* Never unsubscribe while holding lifecycleMutex or inside its callback. */
    shuttingDown=TRUE;
    if(bfeSubscription!=NULL) {FwpmBfeStateUnsubscribeChanges0(bfeSubscription);bfeSubscription=NULL;}
    if(processNotifyRegistered) PsSetCreateProcessNotifyRoutineEx(ProcessNotify,TRUE);
    if(engineHandle!=NULL) FwpmEngineClose0(engineHandle);
    for(i=0;i<6;i++) if(calloutIds[i]!=0) FwpsCalloutUnregisterById0(calloutIds[i]);
    if(redirectHandle!=NULL) FwpsRedirectHandleDestroy0(redirectHandle);
    IoDeleteSymbolicLink(&name);
    if(deviceObject!=NULL) IoDeleteDevice(deviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registryPath) {
    UNICODE_STRING name=RTL_CONSTANT_STRING(ENVARA_DEVICE_NAME);
    UNICODE_STRING dosName=RTL_CONSTANT_STRING(ENVARA_DOS_DEVICE_NAME);
    /* Only local SYSTEM and administrators can alter kernel route state. */
    UNICODE_STRING security=RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&tableLock);
    KeInitializeMutex(&lifecycleMutex,0);
    status=IoCreateDeviceSecure(driver,0,&name,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,
        &security,&deviceClass,&deviceObject);
    if(!NT_SUCCESS(status)) return status;
    status=IoCreateSymbolicLink(&dosName,&name);
    if(!NT_SUCCESS(status)) goto failure;
    driver->MajorFunction[IRP_MJ_CREATE]=DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE]=DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DispatchControl;
    status=FwpsRedirectHandleCreate0(&providerKey,0,&redirectHandle);
    if(!NT_SUCCESS(status)) goto failure;
    status=PsSetCreateProcessNotifyRoutineEx(ProcessNotify,FALSE);
    if(!NT_SUCCESS(status)) goto failure;
    processNotifyRegistered=TRUE;
    /* Subscribe before Get, so a stop/restart cannot hide between initialization
     * and the first observed BFE state. The callback may also initialize FWPM. */
    status=FwpmBfeStateSubscribeChanges0(deviceObject,BfeStateChanged,NULL,&bfeSubscription);
    if(!NT_SUCCESS(status)) goto failure;
    BfeStateChanged(NULL,FwpmBfeStateGet0());
    /* Loading while BFE is stopped is safe: the control plane remains gated and
     * the subsequent RUNNING callback reconstructs the management objects. */
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
failure:
    CleanupFailedLoad();return status;
}
