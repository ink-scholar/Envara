#pragma once

// The Windows SDK declarations are reproduced as probe-local ABI layouts,
// because MinGW's windns.h does not yet declare these application settings APIs.
// Contract: microsoft/win32metadata 75ec935a4f1ac56345daa9f7f0bc21db3e68ac68
// WinDNS.h:851-908; shared/windnsdef.h:1624-1673. See README.md.
// No packed structs: the official x64 ABI uses natural 8-byte alignment.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <cstddef>

#if !defined(_WIN64) || !defined(__x86_64__)
#error This probe currently supports only MinGW Windows x64.
#endif

namespace probe {
constexpr ULONG kSettingsVersion = 1;
constexpr ULONG64 kExclusiveServers = 1;
constexpr DWORD kServerUdp = 1;

struct ApplicationSettings {
    ULONG Version;
    ULONG64 Flags;
};

struct CustomServer {
    DWORD dwServerType;
    ULONG64 ullFlags;
    union {
        PWSTR pwszTemplate;
        PWSTR pwszHostname;
    };
    union {
        SOCKADDR_INET ServerAddr;
        CHAR MaxSa[32];
    };
};

struct QueryRequest {
    ULONG Version;
    PCWSTR QueryName;
    WORD QueryType;
    ULONG64 QueryOptions;
    PVOID pDnsServerList; // DNS_ADDR_ARRAY*: always NULL in this probe.
    ULONG InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE pQueryCompletionCallback;
    PVOID pQueryContext;
};
struct alignas(8) QueryCancel {
    CHAR Reserved[32];
};

// The three application-settings declarations have no WINAPI in the SDK.
// QueryEx has WINAPI. Restricting to x64 also avoids x86 convention ambiguity.
using GetSettings = DWORD (*)(DWORD*, CustomServer**, ApplicationSettings*);
using SetSettings = DWORD (*)(DWORD, const CustomServer*, const ApplicationSettings*);
using FreeServers = VOID (*)(DWORD*, CustomServer**);
using QueryEx = DNS_STATUS (WINAPI*)(QueryRequest*, DNS_QUERY_RESULT*, QueryCancel*);

static_assert(sizeof(ApplicationSettings) == 16);
static_assert(offsetof(ApplicationSettings, Flags) == 8);
static_assert(sizeof(CustomServer) == 56);
static_assert(offsetof(CustomServer, ullFlags) == 8);
static_assert(offsetof(CustomServer, pwszTemplate) == 16);
static_assert(offsetof(CustomServer, ServerAddr) == 24);
static_assert(sizeof(QueryRequest) == 64);
static_assert(offsetof(QueryRequest, QueryOptions) == 24);
static_assert(offsetof(QueryRequest, pQueryCompletionCallback) == 48);
static_assert(sizeof(QueryCancel) == 32 && alignof(QueryCancel) == 8);
static_assert(sizeof(DNS_QUERY_RESULT) == 32);
static_assert(offsetof(DNS_QUERY_RESULT, pQueryRecords) == 16);
} // namespace probe
