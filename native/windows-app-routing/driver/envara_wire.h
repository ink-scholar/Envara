/* Private ABI shared by the Windows service and the callout driver. MIT. */
#pragma once

#define ENVARA_ABI_VERSION 2u
#define ENVARA_CONTEXT_MAGIC 0x45565231u
#define ENVARA_DEVICE_NAME L"\\Device\\EnvaraAppRouting"
#define ENVARA_DOS_DEVICE_NAME L"\\DosDevices\\EnvaraAppRouting"
#define ENVARA_MAX_ROUTES 64u
#define ENVARA_MAX_PROCESSES 4096u
#define ENVARA_CAP_TCP 1u
#define ENVARA_CAP_UDP_BLOCK 2u
#define ENVARA_CAP_CHILD_PROCESSES 4u
#define ENVARA_CAP_FAIL_CLOSED 8u
#define ENVARA_CAP_DNS 16u
#define ENVARA_ROUTE_UDP_BLOCK 1u

#define IOCTL_ENVARA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_ENVARA_ADD_ROUTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ENVARA_REVOKE_ROUTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ENVARA_HEARTBEAT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ENVARA_PROCESS_ROUTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(push, 8)
typedef struct ENVARA_ROUTE_REQUEST {
    UINT32 version;
    UINT32 flags;
    UINT64 routeId;
    UINT64 ownerPid;
    UINT64 rootPid;
    UINT64 rootCreationTime;
    UINT16 proxyPort;
    UINT16 reserved16;
    UINT32 reserved32;
} ENVARA_ROUTE_REQUEST;

typedef struct ENVARA_ROUTE_ID {
    UINT32 version;
    UINT32 reserved;
    UINT64 routeId;
} ENVARA_ROUTE_ID;

typedef struct ENVARA_STATUS {
    UINT32 version;
    UINT32 capabilities;
    UINT32 routes;
    UINT32 processes;
    UINT32 bfeState;
    UINT32 filteringReady;
    UINT64 generation;
    UINT32 lastFailure;
    UINT32 reserved;
} ENVARA_STATUS;

typedef struct ENVARA_PROCESS_QUERY {
    UINT32 version;
    UINT32 reserved;
    UINT64 pid;
    UINT64 creationTime;
} ENVARA_PROCESS_QUERY;

typedef struct ENVARA_PROCESS_ROUTE {
    UINT32 version;
    UINT32 active;
    UINT64 routeId;
    UINT64 generation;
} ENVARA_PROCESS_ROUTE;

typedef struct ENVARA_REDIRECT_CONTEXT {
    UINT32 magic;
    UINT32 version;
    UINT64 routeId;
    UINT64 sourcePid;
    UINT16 family;
    UINT16 port;
    UCHAR address[16];
} ENVARA_REDIRECT_CONTEXT;
#pragma pack(pop)
