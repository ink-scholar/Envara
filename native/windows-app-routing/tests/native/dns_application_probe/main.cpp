#include "dns_api_abi.h"
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {
std::string json(const std::string& s) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
        else out << c;
    }
    out << '"';
    return out.str();
}
const char* boolean(bool value) { return value ? "true" : "false"; }
std::wstring wide(const std::string& s) { return {s.begin(), s.end()}; }
template<typename T> T symbol(HMODULE module, const char* name) {
    FARPROC raw = module ? GetProcAddress(module, name) : nullptr;
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(raw));
    std::memcpy(&result, &raw, sizeof(result));
    return result;
}
struct Api {
    HMODULE dll = LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    probe::GetSettings get = symbol<probe::GetSettings>(dll, "DnsGetApplicationSettings");
    probe::SetSettings set = symbol<probe::SetSettings>(dll, "DnsSetApplicationSettings");
    probe::FreeServers freeServers = symbol<probe::FreeServers>(dll, "DnsFreeCustomServers");
    probe::QueryEx queryEx = symbol<probe::QueryEx>(dll, "DnsQueryEx");
    decltype(&DnsQuery_A) queryA = symbol<decltype(&DnsQuery_A)>(dll, "DnsQuery_A");
    decltype(&DnsQuery_W) queryW = symbol<decltype(&DnsQuery_W)>(dll, "DnsQuery_W");
    decltype(&DnsFree) freeRecords = symbol<decltype(&DnsFree)>(dll, "DnsFree");
    bool settingsAvailable() const { return get && set && freeServers; }
    ~Api() { if (dll) FreeLibrary(dll); }
};
DWORD buildNumber() {
    using Version = LONG (WINAPI*)(OSVERSIONINFOW*);
    auto version = symbol<Version>(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    return version && version(&info) == 0 ? info.dwBuildNumber : 0;
}
bool sameServer(const probe::CustomServer& a, const probe::CustomServer& b) {
    if (a.dwServerType != b.dwServerType || a.ullFlags != b.ullFlags) return false;
    if (a.dwServerType == 2 || a.dwServerType == 3) {
        if (bool(a.pwszTemplate) != bool(b.pwszTemplate)) return false;
        if (a.pwszTemplate && std::wcscmp(a.pwszTemplate, b.pwszTemplate)) return false;
    }
    if (a.ServerAddr.si_family != b.ServerAddr.si_family) return false;
    if (a.ServerAddr.si_family == AF_INET)
        return a.ServerAddr.Ipv4.sin_port == b.ServerAddr.Ipv4.sin_port &&
               a.ServerAddr.Ipv4.sin_addr.s_addr == b.ServerAddr.Ipv4.sin_addr.s_addr;
    if (a.ServerAddr.si_family == AF_INET6)
        return a.ServerAddr.Ipv6.sin6_port == b.ServerAddr.Ipv6.sin6_port &&
               a.ServerAddr.Ipv6.sin6_scope_id == b.ServerAddr.Ipv6.sin6_scope_id &&
               !std::memcmp(&a.ServerAddr.Ipv6.sin6_addr, &b.ServerAddr.Ipv6.sin6_addr, 16);
    return !std::memcmp(a.MaxSa, b.MaxSa, sizeof(a.MaxSa));
}
struct Snapshot {
    Api& api;
    DWORD count = 0;
    probe::CustomServer* servers = nullptr;
    probe::ApplicationSettings settings{probe::kSettingsVersion, 0};
    DWORD status = ERROR_PROC_NOT_FOUND;
    bool setAttempted = false;
    bool restored = false;
    bool restoreVerified = false;
    DWORD restoreStatus = ERROR_SUCCESS;
    explicit Snapshot(Api& a) : api(a) {
        if (api.settingsAvailable()) status = api.get(&count, &servers, &settings);
    }
    bool valid() const {
        return status == ERROR_SUCCESS && settings.Version == probe::kSettingsVersion &&
               (count == 0 || servers != nullptr);
    }
    DWORD apply(const probe::CustomServer& server) {
        probe::ApplicationSettings exclusive{probe::kSettingsVersion, probe::kExclusiveServers};
        setAttempted = true; // Restore even if Set returns an error.
        return api.set(1, &server, &exclusive);
    }
    void restore() {
        if (!setAttempted || restored) return;
        restored = true;
        restoreStatus = api.set(count, count ? servers : nullptr, &settings);
        DWORD readCount = 0;
        probe::CustomServer* readServers = nullptr;
        probe::ApplicationSettings readSettings{probe::kSettingsVersion, 0};
        DWORD readStatus = api.get(&readCount, &readServers, &readSettings);
        restoreVerified = restoreStatus == ERROR_SUCCESS && readStatus == ERROR_SUCCESS &&
            readCount == count && readSettings.Version == settings.Version && readSettings.Flags == settings.Flags &&
            (readCount == 0 || readServers != nullptr);
        if (restoreVerified)
            for (DWORD i = 0; i < count; ++i)
                if (!sameServer(servers[i], readServers[i])) restoreVerified = false;
        if (readServers) api.freeServers(&readCount, &readServers);
    }
    ~Snapshot() {
        restore();
        if (servers && api.freeServers) api.freeServers(&count, &servers);
    }
};

struct Winsock {
    WSADATA data{};
    int status = WSAStartup(MAKEWORD(2, 2), &data);
    ~Winsock() { if (!status) WSACleanup(); }
};
std::string canonical(std::string name) {
    while (!name.empty() && name.back() == '.') name.pop_back();
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return name;
}
struct Responder {
    SOCKET socket = INVALID_SOCKET;
    std::atomic<bool> stopping{false};
    std::thread worker;
    std::mutex mutex;
    std::map<std::string, unsigned> seen;
    std::string suffix;
    DWORD error = 0;
    explicit Responder(const std::string& address, const std::string& token) : suffix(token + ".invalid") {
        socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket == INVALID_SOCKET) { error = WSAGetLastError(); return; }
        BOOL exclusive = TRUE;
        if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) {
            error = WSAGetLastError(); closesocket(socket); socket = INVALID_SOCKET; return;
        }
        sockaddr_in bindAddress{};
        bindAddress.sin_family = AF_INET;
        bindAddress.sin_port = htons(53);
        if (inet_pton(AF_INET, address.c_str(), &bindAddress.sin_addr) != 1 ||
            bind(socket, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress))) {
            error = WSAGetLastError(); closesocket(socket); socket = INVALID_SOCKET; return;
        }
        worker = std::thread([this] { serve(); });
    }
    unsigned hits(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex);
        return seen[canonical(name)];
    }
    void serve() {
        while (!stopping) {
            fd_set readers;
            FD_ZERO(&readers); FD_SET(socket, &readers);
            timeval timeout{0, 100000};
            if (select(0, &readers, nullptr, nullptr, &timeout) <= 0) continue;
            unsigned char packet[4096];
            sockaddr_in peer{};
            int peerSize = sizeof(peer);
            int length = recvfrom(socket, reinterpret_cast<char*>(packet), sizeof(packet), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peerSize);
            if (length < 17 || (ntohl(peer.sin_addr.s_addr) >> 24) != 127 ||
                (packet[2] & 0xf8) || packet[4] || packet[5] != 1) continue;
            size_t cursor = 12;
            std::string name;
            bool valid = true;
            while (cursor < size_t(length) && packet[cursor]) {
                unsigned labelSize = packet[cursor++];
                if (labelSize > 63 || cursor + labelSize >= size_t(length) || name.size() + labelSize > 253) { valid = false; break; }
                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<char*>(packet + cursor), labelSize);
                cursor += labelSize;
            }
            if (!valid || cursor + 5 > size_t(length)) continue;
            ++cursor;
            WORD type = WORD((packet[cursor] << 8) | packet[cursor + 1]);
            WORD klass = WORD((packet[cursor + 2] << 8) | packet[cursor + 3]);
            cursor += 4;
            name = canonical(name);
            if (klass != 1 || name.size() <= suffix.size() ||
                name.compare(name.size() - suffix.size(), suffix.size(), suffix) ||
                name[name.size() - suffix.size() - 1] != '.') continue;
            { std::lock_guard<std::mutex> lock(mutex); ++seen[name]; }
            std::vector<unsigned char> reply(packet, packet + cursor);
            reply[2] = static_cast<unsigned char>(0x80 | (packet[2] & 1));
            reply[3] = 0x80; // NOERROR, recursion available; no forwarding exists.
            reply[6] = 0; reply[7] = type == DNS_TYPE_A ? 1 : 0;
            reply[8] = reply[9] = reply[10] = reply[11] = 0;
            if (type == DNS_TYPE_A) {
                // TTL=0; the reserved benchmark address is never connected to.
                const unsigned char answer[]{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 198, 18, 0, 42};
                reply.insert(reply.end(), std::begin(answer), std::end(answer));
            }
            sendto(socket, reinterpret_cast<const char*>(reply.data()), int(reply.size()), 0,
                   reinterpret_cast<sockaddr*>(&peer), peerSize);
        }
    }
    ~Responder() {
        stopping = true;
        if (worker.joinable()) worker.join();
        if (socket != INVALID_SOCKET) closesocket(socket);
    }
};

struct QueryResult { long status; bool expected; };
bool expectedRecords(PDNS_RECORD records) {
    for (auto* r = records; r; r = r->pNext)
        if (r->wType == DNS_TYPE_A && r->Data.A.IpAddress == inet_addr("198.18.0.42")) return true;
    return false;
}
constexpr DWORD kOptions = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE;
QueryResult legacy(Api& api, const std::string& name, bool unicode) {
    PDNS_RECORD records = nullptr;
    DWORD status = ERROR_PROC_NOT_FOUND;
    if (unicode && api.queryW) status = api.queryW(wide(name).c_str(), DNS_TYPE_A, kOptions, nullptr, &records, nullptr);
    if (!unicode && api.queryA) status = api.queryA(name.c_str(), DNS_TYPE_A, kOptions, nullptr, &records, nullptr);
    bool expected = status == ERROR_SUCCESS && expectedRecords(records);
    if (records && api.freeRecords) api.freeRecords(records, DnsFreeRecordList);
    return {long(status), expected};
}
QueryResult extended(Api& api, const std::string& name) {
    if (!api.queryEx) return {ERROR_PROC_NOT_FOUND, false};
    auto queryName = wide(name);
    probe::QueryRequest request{};
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.QueryName = queryName.c_str();
    request.QueryType = DNS_TYPE_A;
    request.QueryOptions = kOptions;
    DNS_QUERY_RESULT result{};
    result.Version = DNS_QUERY_RESULTS_VERSION1;
    auto status = api.queryEx(&request, &result, nullptr); // Synchronous; callback=NULL.
    bool expected = status == ERROR_SUCCESS && result.QueryStatus == ERROR_SUCCESS && expectedRecords(result.pQueryRecords);
    if (result.pQueryRecords && api.freeRecords) api.freeRecords(result.pQueryRecords, DnsFreeRecordList);
    return {long(status == ERROR_SUCCESS ? result.QueryStatus : status), expected};
}
QueryResult addresses(const std::string& name) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    int status = getaddrinfo(name.c_str(), nullptr, &hints, &result);
    bool expected = false;
    for (auto* r = result; r; r = r->ai_next)
        if (r->ai_family == AF_INET && r->ai_addrlen >= sizeof(sockaddr_in) &&
            reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr.s_addr == inet_addr("198.18.0.42")) expected = true;
    if (result) freeaddrinfo(result);
    return {status, status == 0 && expected};
}
std::string queryJson(const char* api, const std::string& name, const QueryResult& result, unsigned hits, bool bypass) {
    std::ostringstream out;
    out << "{\"case\":" << json(api) << ",\"qname\":" << json(name)
        << ",\"server_seen\":" << boolean(hits != 0) << ",\"server_requests\":" << hits
        << ",\"result\":{\"status\":" << result.status << ",\"expected_answer\":" << boolean(result.expected) << "}"
        << ",\"cache_bypass\":" << boolean(bypass)
        << ",\"query_options\":" << (bypass ? std::to_string(kOptions) : "null")
        << ",\"fail_closed\":false,\"coverage\":false,\"ready\":false}";
    return out.str();
}
bool childNameValid(const std::string& name) {
    return name.size() < 200 && name.find("child.envara-probe-") == 0 &&
        name.size() > 9 && name.compare(name.size() - 9, 9, ".invalid.") == 0 &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
        });
}
bool privateAddressValid(const std::string& address) {
    if (address.size() > 15 || address.find("127.77.") != 0) return false;
    IN_ADDR parsed{};
    if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) return false;
    DWORD host = ntohl(parsed.s_addr);
    unsigned third = (host >> 8) & 255, fourth = host & 255;
    return third > 0 && third < 255 && fourth > 0 && fourth < 255;
}
std::string runChild(const std::string& name, const std::string& address) {
    std::vector<wchar_t> path(32768);
    DWORD size = GetModuleFileNameW(nullptr, path.data(), DWORD(path.size()));
    if (!size || size >= path.size()) return "{\"error\":\"self_path_unavailable\"}";
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE reader = nullptr, writer = nullptr;
    if (!CreatePipe(&reader, &writer, &security, 0)) return "{\"error\":\"pipe_unavailable\"}";
    if (!SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(reader); CloseHandle(writer); return "{\"error\":\"pipe_handle_unavailable\"}";
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writer;
    startup.hStdError = writer;
    startup.hStdInput = nullptr;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + std::wstring(path.data(), size) + L"\" --inherit-child " + wide(name) + L" " + wide(address);
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(0);
    BOOL started = CreateProcessW(path.data(), mutableCommand.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(writer);
    if (!started) { CloseHandle(reader); return "{\"error\":\"child_start_failed\"}"; }
    DWORD waited = WaitForSingleObject(process.hProcess, 20000);
    bool timedOut = waited != WAIT_OBJECT_0;
    if (timedOut) {
        BOOL terminated = TerminateProcess(process.hProcess, 3);
        DWORD finished = WaitForSingleObject(process.hProcess, 5000);
        if (!terminated || finished != WAIT_OBJECT_0) {
            CloseHandle(reader); CloseHandle(process.hThread); CloseHandle(process.hProcess);
            return "{\"timed_out\":true,\"error\":\"child_exit_unconfirmed\"}";
        }
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(process.hProcess, &exitCode);
    std::string output;
    char buffer[1024]; DWORD read = 0, available = 0;
    // The controlled child has exited. Peek avoids an unbounded pipe wait.
    while (PeekNamedPipe(reader, nullptr, 0, nullptr, &available, nullptr) && available &&
           ReadFile(reader, buffer, std::min<DWORD>(sizeof(buffer), available), &read, nullptr) && read) {
        if (output.size() + read > 4096) { output = "child output exceeded limit"; break; }
        output.append(buffer, read);
    }
    CloseHandle(reader); CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return "{\"exit_code\":" + std::to_string(exitCode) + ",\"timed_out\":" + boolean(timedOut) +
        ",\"child_json_text\":" + json(output) + "}";
}

int execute(int argc, char** argv) {
    bool local = argc == 2 && std::string(argv[1]) == "--run-local";
    bool child = argc == 4 && std::string(argv[1]) == "--inherit-child" && childNameValid(argv[2]) && privateAddressValid(argv[3]);
    if (argc != 1 && !local && !child) {
        std::cout << "{\"error\":\"use no arguments or --run-local; child mode is internal\",\"ready\":false,\"coverage\":false}\n";
        return 2;
    }
    Api api;
    DWORD build = buildNumber();
    Snapshot snapshot(api);
    std::ostringstream report;
    report << "{\"probe\":\"dns-application-settings-x64-v1\",\"mode\":" << json(child ? "inherit-child-read-only" : local ? "run-local" : "read-only")
        << ",\"pid\":" << GetCurrentProcessId() << ",\"windows_build\":" << build
        << ",\"api_available\":{\"get\":" << boolean(api.get) << ",\"set\":" << boolean(api.set)
        << ",\"free\":" << boolean(api.freeServers) << ",\"query_ex\":" << boolean(api.queryEx) << "}"
        << ",\"initial_settings\":{\"get_status\":" << snapshot.status << ",\"version\":" << snapshot.settings.Version
        << ",\"flags\":" << snapshot.settings.Flags << ",\"server_count\":" << snapshot.count << "}"
        << ",\"ready\":false,\"coverage\":false,\"fail_closed\":false";
    if (!local && !child) { std::cout << report.str() << ",\"set_attempted\":false,\"cases\":[]}\n"; return 0; }
    Winsock winsock;
    if (winsock.status) { std::cout << report.str() << ",\"error\":\"winsock_startup_failed\",\"set_attempted\":false,\"cases\":[]}\n"; return 2; }
    if (child) {
        // No Set call in this branch: observe, rather than assume, inheritance.
        probe::CustomServer parentServer{};
        parentServer.dwServerType = probe::kServerUdp;
        parentServer.ServerAddr.Ipv4.sin_family = AF_INET;
        parentServer.ServerAddr.Ipv4.sin_port = htons(53);
        inet_pton(AF_INET, argv[3], &parentServer.ServerAddr.Ipv4.sin_addr);
        bool matchesParent = snapshot.valid() && snapshot.count == 1 &&
            snapshot.settings.Flags == probe::kExclusiveServers && sameServer(parentServer, snapshot.servers[0]);
        auto result = legacy(api, argv[2], false);
        report << ",\"set_attempted\":false,\"settings_match_parent_exclusive\":" << boolean(matchesParent) << ",\"cases\":["
            << queryJson("DnsQuery_A_child", argv[2], result, 0, true)
            << "],\"server_seen_note\":\"child has no responder; parent reports actual receive count\"}";
        std::cout << report.str() << '\n'; return 0;
    }
    if (build < 22000 || !snapshot.valid() || !api.queryA || !api.queryW || !api.freeRecords) {
        std::cout << report.str() << ",\"error\":\"required_api_build_or_snapshot_unavailable\",\"set_attempted\":false,\"cases\":[]}\n"; return 2;
    }
    unsigned char random[12];
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        std::cout << report.str() << ",\"error\":\"random_unavailable\",\"set_attempted\":false,\"cases\":[]}\n"; return 2;
    }
    std::ostringstream tokenStream;
    tokenStream << "envara-probe-" << std::hex << std::setfill('0');
    for (size_t i = 0; i < 10; ++i) tokenStream << std::setw(2) << unsigned(random[i]);
    std::string token = tokenStream.str();
    std::string address = "127.77." + std::to_string(1 + random[10] % 254) + "." + std::to_string(1 + random[11] % 254);
    Responder responder(address, token);
    if (responder.error || responder.socket == INVALID_SOCKET) {
        std::cout << report.str() << ",\"error\":\"private_udp_bind_failed\",\"socket_error\":" << responder.error
            << ",\"set_attempted\":false,\"cases\":[]}\n"; return 2;
    }
    probe::CustomServer server{};
    server.dwServerType = probe::kServerUdp;
    server.ServerAddr.Ipv4.sin_family = AF_INET;
    server.ServerAddr.Ipv4.sin_port = htons(53);
    inet_pton(AF_INET, address.c_str(), &server.ServerAddr.Ipv4.sin_addr);
    DWORD setStatus = snapshot.apply(server);
    Snapshot readback(api);
    bool exclusiveReadback = readback.valid() && readback.count == 1 &&
        readback.settings.Flags == probe::kExclusiveServers && sameServer(server, readback.servers[0]);
    report << ",\"set_attempted\":true,\"set_status\":" << setStatus
        << ",\"exclusive_readback\":" << boolean(exclusiveReadback)
        << ",\"responder\":{\"owner_pid\":" << GetCurrentProcessId() << ",\"address\":" << json(address)
        << ",\"port\":53,\"protocol\":\"udp\",\"forwarding\":false},\"cases\":[";
    if (setStatus == ERROR_SUCCESS && exclusiveReadback) {
        auto name = [&](const char* label) { return std::string(label) + "." + token + ".invalid."; };
        std::string a = name("ansi"), w = name("wide"), ex = name("ex"), gai = name("gai"), childQuery = name("child");
        auto ra = legacy(api, a, false);
        report << queryJson("DnsQuery_A", a, ra, responder.hits(a), true);
        auto rw = legacy(api, w, true);
        report << ',' << queryJson("DnsQuery_W", w, rw, responder.hits(w), true);
        auto re = extended(api, ex);
        report << ',' << queryJson("DnsQueryEx_v1_sync", ex, re, responder.hits(ex), true);
        auto rg = addresses(gai);
        report << ',' << queryJson("getaddrinfo_AF_INET", gai, rg, responder.hits(gai), false);
        auto childResult = runChild(childQuery, address);
        report << ",{\"case\":\"inherit_child\",\"qname\":" << json(childQuery)
            << ",\"server_seen\":" << boolean(responder.hits(childQuery) != 0)
            << ",\"server_requests\":" << responder.hits(childQuery) << ",\"result\":" << childResult
            << ",\"cache_bypass\":true,\"query_options\":" << kOptions
            << ",\"fail_closed\":false,\"coverage\":false,\"ready\":false}";
    }
    snapshot.restore();
    report << "],\"restore\":{\"attempted\":" << boolean(snapshot.restored) << ",\"status\":" << snapshot.restoreStatus
        << ",\"readback_matches_original\":" << boolean(snapshot.restoreVerified) << "}"
        << ",\"not_tested\":[\"NRPT\",\"fail-closed outbound enforcement\",\"shared Dnscache isolation\",\"thread scope\",\"warm cache\",\"UDP/TCP retry\",\"DnsQueryEx v3/async/explicit servers\",\"DnsQueryRaw\",\"GetAddrInfoW/Ex\",\"third-party target/children\",\"PPL\",\"x86\",\"single-instance handoff\"]}";
    std::cout << report.str() << '\n';
    return setStatus != ERROR_SUCCESS || !exclusiveReadback || !snapshot.restoreVerified ? 2 : 0;
}
} // namespace

int main(int argc, char** argv) {
    try { return execute(argc, argv); }
    catch (...) {
        // Stack unwinding restores and frees a successful snapshot first.
        std::cout << "{\"error\":\"probe_exception\",\"ready\":false,\"coverage\":false,\"fail_closed\":false}\n";
        return 2;
    }
}
