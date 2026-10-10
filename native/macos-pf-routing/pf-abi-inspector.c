/* Standalone diagnostic: never installs, starts PF, changes rules or clears
 * counters. Layout provenance is pinned in the report; it is not a claim that
 * the unpublished Darwin 27 kernel's complete write ABI has been verified. */
#define _DARWIN_C_SOURCE
#include <CommonCrypto/CommonDigest.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <mach-o/dyld.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SCHEMA "envara.macos-pf-abi-inspection/v1"
#define PINNED_PFCTL "ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef"
#define MAX_RULES 1024
#define MAX_OUTPUT (1024 * 1024)

/* Only the fields inspected here are named. Opaque ranges reproduce the fixed
 * generated layout, not inferred private SDK declarations. Source:
 * mullvad/pfctl-rs 0.7.0, 273e96bec0f5b983f16cfd43b6512f4c97a3f848,
 * src/ffi/pfvar.rs SHA256 e09ade2fe4be76579bd8185eeccd561deb9f89f84db69dc5ae50a386425b78d6.
 * Its sizeof/offsetof assertions are independently asserted below. */
typedef struct __attribute__((aligned(8))) {
    uint8_t src[64], dst[64], skip[64];
    char label[64], ifname[16];
    uint8_t opaque272[376];
    uint64_t evaluations, packets[2], bytes[2], ticket;
    char owner[64];
    uint32_t priority;
    uint8_t opaque764[184];
    uint32_t nr;
    uint8_t opaque952[24];
    uint32_t uid[2]; uint8_t uid_op, uid_pad[3];
    uint32_t gid[2]; uint8_t gid_op, gid_pad[3];
    uint32_t rule_flag;
    uint8_t action, direction, log, logif, quick, ifnot, match_tag_not,
        natpass, keep_state, af, proto, type, code, flags, flagset, min_ttl,
        allow_opts, rt, return_ttl, tos, anchor_relative, anchor_wildcard,
        flush, proto_variant, extfilter, extmap, pad1030[2];
    uint32_t dnpipe, dntype;
} InspectorRule;
typedef struct {
    uint32_t action, ticket, pool_ticket, nr;
    char anchor[1024], anchor_call[1024];
    InspectorRule rule;
} InspectorRequest;
#define ASSERT_OFFSET(type, field, value) _Static_assert(offsetof(type, field) == value, #field " layout mismatch")
_Static_assert(sizeof(InspectorRule) == 1040, "rule size mismatch");
_Static_assert(_Alignof(InspectorRule) == 8, "rule alignment mismatch");
_Static_assert(sizeof(InspectorRequest) == 3104, "request size mismatch");
ASSERT_OFFSET(InspectorRequest, action, 0); ASSERT_OFFSET(InspectorRequest, ticket, 4);
ASSERT_OFFSET(InspectorRequest, nr, 12); ASSERT_OFFSET(InspectorRequest, anchor, 16);
ASSERT_OFFSET(InspectorRequest, anchor_call, 1040); ASSERT_OFFSET(InspectorRequest, rule, 2064);
ASSERT_OFFSET(InspectorRule, label, 192); ASSERT_OFFSET(InspectorRule, ifname, 256);
ASSERT_OFFSET(InspectorRule, ticket, 688); ASSERT_OFFSET(InspectorRule, owner, 696);
ASSERT_OFFSET(InspectorRule, priority, 760); ASSERT_OFFSET(InspectorRule, nr, 948);
ASSERT_OFFSET(InspectorRule, uid, 976); ASSERT_OFFSET(InspectorRule, gid, 988);
ASSERT_OFFSET(InspectorRule, gid_op, 996); ASSERT_OFFSET(InspectorRule, rule_flag, 1000);
ASSERT_OFFSET(InspectorRule, action, 1004); ASSERT_OFFSET(InspectorRule, direction, 1005);
ASSERT_OFFSET(InspectorRule, quick, 1008); ASSERT_OFFSET(InspectorRule, keep_state, 1012);
ASSERT_OFFSET(InspectorRule, af, 1013); ASSERT_OFFSET(InspectorRule, proto, 1014);
#define INSPECT_GET_RULES _IOWR('D', 6, InspectorRequest)
#define INSPECT_GET_RULE _IOWR('D', 7, InspectorRequest)
_Static_assert(INSPECT_GET_RULES == 0xcc204406UL, "GETRULES encoding mismatch");
_Static_assert(INSPECT_GET_RULE == 0xcc204407UL, "GETRULE encoding mismatch");

static const char *reason = "inspection-unconfirmed";
static const char *authorization_stage;
static OSStatus authorization_status;
static double seconds(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void digest(const void *bytes, size_t size, char output[65]) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(bytes, (CC_LONG)size, hash);
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(output + i * 2, 3, "%02x", hash[i]);
}
static int file_digest(const char *filename, char output[65]) {
    int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return 0;
    struct stat info; if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0022)) { close(fd); return 0; }
    CC_SHA256_CTX context; CC_SHA256_Init(&context); unsigned char bytes[65536], hash[CC_SHA256_DIGEST_LENGTH];
    ssize_t size; while ((size = read(fd, bytes, sizeof(bytes))) > 0) CC_SHA256_Update(&context, bytes, (CC_LONG)size);
    close(fd); if (size < 0) return 0; CC_SHA256_Final(hash, &context);
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(output + i * 2, 3, "%02x", hash[i]); return 1;
}
static int authorized_root(void) {
    if (geteuid() != 0) { reason = "privileged-reference-required"; return 0; }
    AuthorizationRef reference = NULL;
    authorization_status = AuthorizationCopyPrivilegedReference(&reference, kAuthorizationFlagDefaults);
    authorization_stage = "AuthorizationCopyPrivilegedReference";
    if (authorization_status != errAuthorizationSuccess || !reference) { reason = "privileged-reference-required"; return 0; }
    AuthorizationItem item = { kAuthorizationRightExecute, 0, NULL, 0 }; AuthorizationRights rights = { 1, &item };
    authorization_status = AuthorizationCopyRights(reference, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, NULL);
    authorization_stage = "AuthorizationCopyRights"; AuthorizationFree(reference, kAuthorizationFlagDefaults);
    if (authorization_status != errAuthorizationSuccess) { reason = "privileged-reference-required"; return 0; } return 1;
}
#pragma clang diagnostic pop
static int host_matches(void) {
    char release[128], version[1024], hash[65]; size_t r = sizeof(release), v = sizeof(version);
    if (sysctlbyname("kern.osrelease", release, &r, NULL, 0) || sysctlbyname("kern.version", version, &v, NULL, 0)) return 0;
    release[sizeof(release)-1] = 0; version[sizeof(version)-1] = 0;
    return !strcmp(release, "27.0.0") && strstr(version, "xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020") &&
        file_digest("/sbin/pfctl", hash) && !strcmp(hash, PINNED_PFCTL);
}
static void header(const char *mode, int okay) {
    printf("{\"schema\":\"%s\",\"action\":\"%s\",\"ok\":%s,\"readOnly\":true,\"ready\":false,\"productionReady\":false,\"activation\":false,\"systemInstallation\":false,", SCHEMA, mode, okay ? "true" : "false");
    printf("\"pinnedHost\":{\"darwin\":\"27.0.0\",\"xnu\":\"13432.0.94.501.4~1\",\"pfctlSHA256\":\"%s\"},", PINNED_PFCTL);
    printf("\"layout\":{\"requestSize\":3104,\"ruleSize\":1040,\"ruleOffset\":2064,\"actionOffset\":1004,\"sourceCommit\":\"273e96bec0f5b983f16cfd43b6512f4c97a3f848\",\"sourceSHA256\":\"e09ade2fe4be76579bd8185eeccd561deb9f89f84db69dc5ae50a386425b78d6\"},");
    printf("\"gates\":{\"completeKernelLayoutVerified\":false,\"insertDeleteABIVerified\":false,\"ticketOwnerWriteSemanticsVerified\":false,\"nonzeroLabelOffsetVerified\":false,\"nonzeroOwnerOffsetVerified\":false,\"priorityOffsetVerified\":false,\"counterOffsetsVerified\":false,\"nonzeroGIDOffsetVerified\":false,\"nonzeroAddressOffsetsVerified\":false,\"rootHookInstalled\":false},");
    if (authorization_stage) printf("\"nativeAuthorization\":{\"stage\":\"%s\",\"status\":%d},", authorization_stage, (int)authorization_status);
}
static int refused(const char *mode, const char *why) { header(mode, 0); printf("\"reason\":\"%s\",\"rulesCompared\":0,\"rootRulesMatch\":false}\n", why); return 1; }
/* Defense in depth: O_RDONLY alone is not an all-ioctl write barrier on Darwin.
 * The only two requests this program is able to issue are these read calls.
 * Outer action always PF_GET_NONE=0: never PF_GET_CLR_CNTR=1. */
static int read_request(int fd, unsigned long operation, InspectorRequest *request) {
    if ((operation != INSPECT_GET_RULES && operation != INSPECT_GET_RULE) || request->action != 0 || request->anchor[0] != 0 || request->rule.action != 0 || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) { errno = EINVAL; return -1; }
    return ioctl(fd, operation, request);
}
static int original_rules(char output[MAX_OUTPUT + 1]) {
    int channel[2]; if (pipe(channel)) return 0; pid_t child = fork();
    if (child < 0) { close(channel[0]); close(channel[1]); return 0; }
    if (!child) {
        close(channel[0]); dup2(channel[1], STDOUT_FILENO); close(channel[1]);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC); if (null >= 0) { dup2(null, STDERR_FILENO); close(null); }
        char *args[] = { "/sbin/pfctl", "-sr", NULL }; char *env[] = { "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        execve(args[0], args, env); _exit(127);
    }
    close(channel[1]); fcntl(channel[0], F_SETFL, O_NONBLOCK); size_t length = 0; int complete = 0; double deadline = seconds() + 10;
    while (seconds() < deadline && length < MAX_OUTPUT) {
        struct pollfd wait = { channel[0], POLLIN | POLLHUP, 0 }; int found = poll(&wait, 1, 200);
        if (found < 0 && errno == EINTR) continue; if (found < 0) break; if (!found) continue;
        ssize_t count = read(channel[0], output + length, MAX_OUTPUT - length);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue; if (count < 0) break;
        if (!count) { complete = 1; break; } length += (size_t)count;
    }
    output[length] = 0; close(channel[0]); int status = 0;
    if (!complete) kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return complete && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int zero(const void *data, size_t size) { const uint8_t *bytes = data; for (size_t i = 0; i < size; i++) if (bytes[i]) return 0; return 1; }
/* Deliberately bounded grammar. Unknown rules remain unverified. This does not
 * normalize an unfamiliar live rule to an assumed harmless 'anchor all'. */
static int matches_anchor_line(const char *line, const InspectorRequest *request) {
    if (strncmp(line, "anchor \"", 8)) return 0; const char *end = strchr(line + 8, '"'); if (!end) return 0;
    size_t size = (size_t)(end - (line + 8)); if (!size || size >= sizeof(request->anchor_call) || memchr(line + 8, '\\', size)) return 0;
    if (strnlen(request->anchor_call, sizeof(request->anchor_call)) != size || memcmp(line + 8, request->anchor_call, size)) return 0;
    const char *tail = end + 1; while (*tail == ' ') tail++;
    if (strcmp(tail, "all")) return 0;
    const InspectorRule *rule = &request->rule;
    return rule->action == 0 && rule->direction == 0 && rule->quick == 0 && rule->af == 0 && rule->proto == 0 &&
        rule->keep_state == 0 && rule->ifnot == 0 && rule->uid_op == 0 && rule->gid_op == 0 &&
        zero(rule->src, sizeof(rule->src)) && zero(rule->dst, sizeof(rule->dst)) &&
        zero(rule->label, sizeof(rule->label)) && zero(rule->ifname, sizeof(rule->ifname));
}
static int inspect(void) {
    if (!authorized_root()) return refused("inspect", reason);
    if (!host_matches()) return refused("inspect", "pinned-host-mismatch");
    int fd = open("/dev/pf", O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return refused("inspect", "read-device-unavailable");
    InspectorRequest first = {0}; if (read_request(fd, INSPECT_GET_RULES, &first)) { close(fd); return refused("inspect", "GETRULES-ABI-unconfirmed"); }
    if (first.nr > MAX_RULES) { close(fd); return refused("inspect", "bounded-rule-limit"); }
    InspectorRequest *rules = calloc(first.nr ? first.nr : 1, sizeof(*rules)); char *original = malloc(MAX_OUTPUT + 1);
    if (!rules || !original) { free(rules); free(original); close(fd); return refused("inspect", "allocation-failed"); }
    int okay = original_rules(original);
    for (uint32_t index = 0; okay && index < first.nr; index++) {
        rules[index].ticket = first.ticket; rules[index].nr = index;
        okay = read_request(fd, INSPECT_GET_RULE, &rules[index]) == 0 && rules[index].rule.nr == index &&
            strnlen(rules[index].anchor_call, sizeof(rules[index].anchor_call)) < sizeof(rules[index].anchor_call);
    }
    InspectorRequest last = {0}; if (okay) okay = read_request(fd, INSPECT_GET_RULES, &last) == 0 && first.ticket == last.ticket && first.nr == last.nr;
    close(fd); if (!okay) { free(rules); free(original); return refused("inspect", "root-read-unconfirmed-or-rules-changed"); }
    char text_hash[65], decoded_hash[65]; digest(original, strlen(original), text_hash); digest(rules, first.nr * sizeof(*rules), decoded_hash);
    char *save = NULL, *line = strtok_r(original, "\n", &save); uint32_t compared = 0; int match = 1;
    for (uint32_t index = 0; index < first.nr; index++) {
        int row_match = line && matches_anchor_line(line, &rules[index]); if (!row_match) match = 0;
        if (row_match) compared++; if (line) line = strtok_r(NULL, "\n", &save);
    }
    if (line) match = 0;
    header("inspect", match);
    printf("\"reason\":\"%s\",\"pinnedHostMatch\":true,\"deviceOpenMode\":\"O_RDONLY\",\"counterReadAction\":\"PF_GET_NONE\",\"rulesetRevisionStable\":true,\"rootRuleCount\":%u,\"rulesCompared\":%u,\"rootRulesMatch\":%s,\"originalPFCTLSHA256\":\"%s\",\"decodedReadSHA256\":\"%s\",\"ruleEvidence\":[", match ? "bounded-anchor-fields-match" : "unknown-or-mismatched-rule-fields", first.nr, compared, match ? "true" : "false", text_hash, decoded_hash);
    for (uint32_t index = 0; index < first.nr; index++) {
        char call_hash[65], owner_hash[65], label_hash[65], ticket_hash[65]; InspectorRequest *r = &rules[index];
        digest(r->anchor_call, strnlen(r->anchor_call, sizeof(r->anchor_call)), call_hash);
        digest(r->rule.owner, sizeof(r->rule.owner), owner_hash); digest(r->rule.label, sizeof(r->rule.label), label_hash); digest(&r->rule.ticket, sizeof(r->rule.ticket), ticket_hash);
        printf("%s{\"index\":%u,\"anchorCallSHA256\":\"%s\",\"ownerSHA256\":\"%s\",\"labelSHA256\":\"%s\",\"ticketSHA256\":\"%s\",\"action\":%u,\"direction\":%u,\"quick\":%u,\"af\":%u,\"proto\":%u,\"keepState\":%u,\"priority\":%u}", index ? "," : "", index, call_hash, owner_hash, label_hash, ticket_hash, r->rule.action, r->rule.direction, r->rule.quick, r->rule.af, r->rule.proto, r->rule.keep_state, r->rule.priority);
    }
    printf("]}\n"); free(rules); free(original); return match ? 0 : 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int request_inspect(void) {
    if (geteuid() == 0) return refused("requestInspect", "unprivileged-request-required");
    if (!host_matches()) return refused("requestInspect", "pinned-host-mismatch");
    char unresolved[PATH_MAX], executable[PATH_MAX]; uint32_t capacity = sizeof(unresolved);
    if (_NSGetExecutablePath(unresolved, &capacity) || !realpath(unresolved, executable)) return refused("requestInspect", "self-path-unconfirmed");
    AuthorizationRef reference = NULL; AuthorizationItem item = { kAuthorizationRightExecute, 0, NULL, 0 }; AuthorizationRights rights = { 1, &item };
    const char prompt[] = "Envara: read PF ABI and compare current root rules. No PF rules, counters, states, groups, tunnels or files will be changed; nothing will be installed.";
    AuthorizationItem prompt_item = { kAuthorizationEnvironmentPrompt, sizeof(prompt)-1, (void *)prompt, 0 }; AuthorizationEnvironment environment = { 1, &prompt_item };
    authorization_status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &reference); authorization_stage = "AuthorizationCreate";
    if (authorization_status == errAuthorizationSuccess) { authorization_status = AuthorizationCopyRights(reference, &rights, &environment, kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL); authorization_stage = "AuthorizationCopyRights"; }
    FILE *communications = NULL; char *arguments[] = { "--inspect", NULL };
    if (authorization_status == errAuthorizationSuccess) { authorization_status = AuthorizationExecuteWithPrivileges(reference, executable, kAuthorizationFlagDefaults, arguments, &communications); authorization_stage = "AuthorizationExecuteWithPrivileges"; }
    if (authorization_status != errAuthorizationSuccess || !communications) {
        if (reference) AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
        return refused("requestInspect", authorization_status == errAuthorizationCanceled ? "authorization-canceled" : "authorization-unavailable");
    }
    int fd = fileno(communications); fcntl(fd, F_SETFL, O_NONBLOCK); char *output = malloc(MAX_OUTPUT + 1); size_t length = 0; int complete = 0; double deadline = seconds() + 30;
    while (output && seconds() < deadline && length < MAX_OUTPUT) {
        struct pollfd wait = { fd, POLLIN | POLLHUP, 0 }; int observed = poll(&wait, 1, 200);
        if (observed < 0 && errno == EINTR) continue; if (observed < 0) break; if (!observed) continue;
        ssize_t count = read(fd, output + length, MAX_OUTPUT - length);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue; if (count < 0) break;
        if (!count) { complete = 1; break; } length += (size_t)count;
    }
    fclose(communications); AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
    if (!output || !complete || !length) { free(output); return refused("requestInspect", "inspection-completion-unconfirmed"); }
    output[length] = 0; int okay = strstr(output, "\"schema\":\"" SCHEMA "\"") && strstr(output, "\"action\":\"inspect\"") && strstr(output, "\"ok\":true");
    fwrite(output, 1, length, stdout); free(output); return okay ? 0 : 1;
}
#pragma clang diagnostic pop
int main(int argc, char **argv) {
    if (argc > 2) return refused("plan", "invalid-fixed-operation");
    const char *mode = argc == 1 ? "--plan" : argv[1];
    if (!strcmp(mode, "--inspect")) return inspect();
    if (!strcmp(mode, "--request-inspect")) return request_inspect();
    if (strcmp(mode, "--plan")) return refused("plan", "invalid-fixed-operation");
    header("plan", 1); printf("\"reason\":\"no-authorization-or-PF-open\",\"pinnedHostMatch\":%s,\"authorizationRequested\":false,\"deviceOpened\":false,\"operations\":[\"O_RDONLY\",\"DIOCGETRULES\",\"DIOCGETRULE\",\"pfctl -sr\"],\"rootRulesMatch\":false}\n", host_matches() ? "true" : "false"); return 0;
}
