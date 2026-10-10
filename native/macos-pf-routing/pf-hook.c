#define _DARWIN_C_SOURCE
#include "pf-hook.h"
#include "pf-hook-abi.h"
#include "pf-run-ledger.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* A private installed-root-controller primitive. This file never requests
 * authorization, enables PF, loads rules, starts software or changes a state.
 * The historical fixed-v1 empty-call canary does not verify these fresh-v2
 * namespaces. The five-case fixture and every production readiness gate
 * remain unverified. */
#define HOOK_SCHEMA "envara.macos-pf-owned-root-hook/v2"
#define LEASE_SCHEMA "envara.macos-pf-owned-root-hook-lease/v2"
#define LABEL_PREFIX "envara.hook.v2."
#define PFCTL_HASH "ceae69b705ccb481c9bce4fc4a3b9fb8cb4e9775b09677901bac6f4c44398bef"
#define PFD_HASH "ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"
#define ROOT_TEXT_HASH "5e803c2e459d5417da5d61aba888d1da25ad56cb0bff4f22e69d36078eb7f575"
#define ROOT_RULE_HASH "7f79342e7409a1d3569220b8e143c1f261574ae1ae7de6a07b915a2364316bb5"
#define INPUT_LIMIT 4096
#define TEXT_LIMIT 65536
#define RULE_LIMIT 64

typedef struct {
    char schema[64], runId[37], leaseId[37], anchor[64], owner[64], label[64], ticket[21];
    char rootBeforeSHA256[65], rootBeforeTextSHA256[65];
} HookLease;
typedef struct { HookLease lease; char runId[37]; int has_lease, has_run; } HookInput;
typedef struct { uint32_t count; EnvaraPFHookRequest rows[RULE_LIMIT]; char canonical[65], text[65]; } HookRoot;
typedef struct {
    int pins, readable, disabled, compatible, prior_compatible, leaf_absent, hook_verified, hook_present;
    int namespace_state, receipt_retired, ledger_verified;
    char anchor[64], prior_counts[65]; EnvaraPFRunLedgerState ledger_state; HookRoot root;
} HookProof;
static volatile sig_atomic_t hook_interrupted;
static void hook_signal(int value) { hook_interrupted = value; }
static double hook_seconds(void) { struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now); return now.tv_sec + now.tv_nsec / 1e9; }
static int zero_bytes(const void *data, size_t length) { const unsigned char *p = data; for (size_t i = 0; i < length; i++) if (p[i]) return 0; return 1; }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void hook_hash(const void *data, size_t length, char output[65]) {
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(data, (CC_LONG)length, bytes);
    for (size_t i = 0; i < sizeof(bytes); i++) snprintf(output + i * 2, 3, "%02x", bytes[i]);
}
static int hash_root_file(const char *filename, char output[65]) {
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return 0;
    struct stat info; if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid || (info.st_mode & 0022)) { close(fd); return 0; }
    CC_SHA256_CTX context; CC_SHA256_Init(&context); unsigned char bytes[65536], hash[CC_SHA256_DIGEST_LENGTH]; ssize_t count;
    while ((count = read(fd, bytes, sizeof(bytes))) > 0) CC_SHA256_Update(&context, bytes, (CC_LONG)count);
    close(fd); if (count < 0) return 0; CC_SHA256_Final(hash, &context);
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(output + i * 2, 3, "%02x", hash[i]); return 1;
}
#pragma clang diagnostic pop
static int pins_verified(void) {
    char os[128], kernel[1024], hash[65]; size_t a = sizeof(os), b = sizeof(kernel);
    if (sysctlbyname("kern.osrelease", os, &a, NULL, 0) || sysctlbyname("kern.version", kernel, &b, NULL, 0)) return 0;
    os[sizeof(os)-1] = 0; kernel[sizeof(kernel)-1] = 0;
    return !strcmp(os, "27.0.0") && strstr(kernel, "xnu-13432.0.94.501.4~1/RELEASE_ARM64_T6020") &&
        hash_root_file("/sbin/pfctl", hash) && !strcmp(hash, PFCTL_HASH) && hash_root_file("/usr/libexec/pfd", hash) && !strcmp(hash, PFD_HASH);
}
static int fixed_pfctl(unsigned mode, char output[TEXT_LIMIT + 1]) {
    if (mode > 1) return 0;
    int channel[2]; if (pipe(channel)) return 0; pid_t child = fork();
    if (child < 0) { close(channel[0]); close(channel[1]); return 0; }
    if (!child) {
        close(channel[0]); dup2(channel[1], STDOUT_FILENO); close(channel[1]);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC); if (null >= 0) { dup2(null, STDERR_FILENO); close(null); }
        char *info[] = {"/sbin/pfctl", "-s", "info", NULL}, *rules[] = {"/sbin/pfctl", "-sr", NULL};
        char *env[] = {"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL}; execve("/sbin/pfctl", mode ? rules : info, env); _exit(127);
    }
    close(channel[1]); fcntl(channel[0], F_SETFL, O_NONBLOCK); size_t size = 0; int complete = 0; double deadline = hook_seconds() + 5;
    while (hook_seconds() < deadline && size < TEXT_LIMIT) {
        struct pollfd wait = {channel[0], POLLIN | POLLHUP, 0}; int ready = poll(&wait, 1, 100);
        if (ready < 0 && errno == EINTR) continue; if (ready < 0) break; if (!ready) continue;
        ssize_t count = read(channel[0], output + size, TEXT_LIMIT - size);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue; if (count < 0) break;
        if (!count) { complete = 1; break; } size += (size_t)count;
    }
    output[size] = 0; close(channel[0]); int status = 0; if (!complete) kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return complete && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int pf_disabled(void) { char *text = malloc(TEXT_LIMIT + 1); if (!text) return 0; int okay = fixed_pfctl(0, text) && strstr(text, "Status: Disabled"); free(text); return okay; }
static int uuid_valid(const char *text) {
    if (strlen(text) != 36) return 0;
    for (size_t i = 0; i < 36; i++) { if (i == 8 || i == 13 || i == 18 || i == 23) { if (text[i] != '-') return 0; }
        else if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return 0; }
    return text[14] == '4' && (text[19] == '8' || text[19] == '9' || text[19] == 'a' || text[19] == 'b');
}
static void random_uuid(char out[37]) {
    unsigned char bytes[16]; arc4random_buf(bytes, sizeof(bytes)); bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]);
}
static void lease_label(const HookLease *lease, char label[64]) {
    char input[74], hash[65]; snprintf(input, sizeof(input), "%s|%s", lease->runId, lease->leaseId);
    hook_hash(input, strlen(input), hash); snprintf(label, 64, LABEL_PREFIX "%.32s", hash);
}
static int ticket_value(const char *text, uint64_t *ticket) {
    if (!*text || *text == '0' || strlen(text) > 20) return 0;
    for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0; char *end; unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || !value) return 0; *ticket = (uint64_t)value; return 1;
}
static int lease_identity_valid(const HookLease *lease) {
    char label[64], anchor[64]; lease_label(lease, label);
    return !strcmp(lease->schema, LEASE_SCHEMA) && uuid_valid(lease->runId) && uuid_valid(lease->leaseId) &&
        envara_pf_run_anchor(lease->runId, anchor) && !strcmp(lease->anchor, anchor) && !strcmp(lease->owner, anchor) && !strcmp(lease->label, label) &&
        !strcmp(lease->rootBeforeSHA256, ROOT_RULE_HASH) && !strcmp(lease->rootBeforeTextSHA256, ROOT_TEXT_HASH);
}
static int lease_valid(const HookLease *lease) {
    uint64_t ticket; return lease_identity_valid(lease) && ticket_value(lease->ticket,&ticket);
}
/* JSON is deliberately limited to these private scalar fields and one lease
 * object. Reject escapes, extra/duplicate fields, arrays, numeric tickets,
 * unterminated input, trailing payloads and any arbitrary anchor/operation. */
static void space(const char **p) { while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') (*p)++; }
static int consume(const char **p, char c) { space(p); if (**p != c) return 0; (*p)++; return 1; }
static int string_value(const char **p, char *output, size_t capacity) {
    if (!consume(p, '"')) return 0; size_t length = 0;
    while (**p && **p != '"') { unsigned char c = (unsigned char)*(*p)++; if (c < 32 || c > 126 || c == '\\' || length + 1 >= capacity) return 0; output[length++] = (char)c; }
    if (**p != '"') return 0; (*p)++; output[length] = 0; return 1;
}
static int parse_lease(const char **p, HookLease *lease) {
    static const char *const keys[] = {"schema","runId","leaseId","anchor","owner","label","ticket","rootBeforeSHA256","rootBeforeTextSHA256"};
    char *values[] = {lease->schema,lease->runId,lease->leaseId,lease->anchor,lease->owner,lease->label,lease->ticket,lease->rootBeforeSHA256,lease->rootBeforeTextSHA256};
    const size_t capacities[] = {64,37,37,64,64,64,21,65,65}; unsigned seen = 0;
    if (!consume(p, '{')) return 0;
    for (;;) {
        char key[64]; if (!string_value(p, key, sizeof(key)) || !consume(p, ':')) return 0;
        size_t i; for (i = 0; i < 9 && strcmp(key, keys[i]); i++) {}
        if (i == 9 || (seen & (1U << i)) || !string_value(p, values[i], capacities[i])) return 0; seen |= 1U << i;
        space(p); if (**p == '}') { (*p)++; break; } if (!consume(p, ',')) return 0;
    }
    return seen == 511 && lease_valid(lease);
}
static int parse_input(const char *text, const char *operation, HookInput *input) {
    memset(input, 0, sizeof(*input)); const char *p = text; if (!consume(&p, '{')) return 0; space(&p);
    if (*p != '}') {
        char key[64]; if (!string_value(&p, key, sizeof(key)) || !consume(&p, ':')) return 0;
        if (!strcmp(key, "runId") && strcmp(operation, "delete-owned-root-hook")) { input->has_run = string_value(&p, input->runId, sizeof(input->runId)) && uuid_valid(input->runId); if (!input->has_run) return 0; }
        else if (!strcmp(key, "lease") && strcmp(operation, "insert-owned-root-hook")) { input->has_lease = parse_lease(&p, &input->lease); if (!input->has_lease) return 0; }
        else return 0;
    }
    if (!consume(&p, '}')) return 0; space(&p); if (*p) return 0;
    return !strcmp(operation, "insert-owned-root-hook") ? input->has_run : !strcmp(operation, "delete-owned-root-hook") ? input->has_lease : 1;
}
static int read_input(char text[INPUT_LIMIT + 1], int status) {
    size_t length = 0; double deadline = hook_seconds() + 2;
    while (hook_seconds() < deadline && length < INPUT_LIMIT) {
        struct pollfd wait = {STDIN_FILENO, POLLIN | POLLHUP, 0}; int ready = poll(&wait, 1, 100);
        if (hook_interrupted) return 0; if (ready < 0 && errno == EINTR) continue; if (ready < 0) return 0; if (!ready) continue;
        ssize_t count = read(STDIN_FILENO, text + length, INPUT_LIMIT - length);
        if (count < 0 && errno == EINTR) continue; if (count < 0) return 0;
        if (!count) { text[length] = 0; if (!length && status) strcpy(text, "{}"); return status || length > 0; }
        if (memchr(text + length, 0, (size_t)count)) return 0; length += (size_t)count;
    }
    return 0;
}
static int anchor_valid(const char *anchor) {
    char expected[64]; const char *prefix = "io.envara.pf.run.";
    return anchor && !strncmp(anchor,prefix,strlen(prefix)) &&
        envara_pf_run_anchor(anchor + strlen(prefix),expected) && !strcmp(anchor,expected);
}
static int read_rule(int fd, unsigned long op, EnvaraPFHookRequest *request, const char *anchor) {
    if ((op != ENVARA_PF_HOOK_GET_RULES && op != ENVARA_PF_HOOK_GET_RULE) || request->action || request->rule.action ||
        (request->anchor[0] && (!anchor_valid(anchor) || strcmp(request->anchor, anchor))) || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) { errno = EINVAL; return -1; }
    return ioctl(fd, op, request);
}
static int owned_identity(const EnvaraPFHookRequest *request, const HookLease *lease) {
    const EnvaraPFHookRule *rule = &request->rule;
    if (strnlen(request->anchor, sizeof(request->anchor)) == sizeof(request->anchor) || strnlen(request->anchor_call, sizeof(request->anchor_call)) == sizeof(request->anchor_call) ||
        strnlen(rule->label, sizeof(rule->label)) == sizeof(rule->label) || strnlen(rule->owner, sizeof(rule->owner)) == sizeof(rule->owner)) return 0;
    return !request->anchor[0] && !strcmp(request->anchor_call, lease->anchor) && !strcmp(rule->owner, lease->owner) && !strcmp(rule->label, lease->label);
}
static int owned_semantics(const EnvaraPFHookRequest *request, const HookLease *lease) {
    const EnvaraPFHookRule *rule = &request->rule;
    return owned_identity(request,lease) &&
        rule->priority == UINT32_MAX && !rule->action && !rule->direction && !rule->quick && !rule->keep_state && !rule->af && !rule->proto &&
        zero_bytes(rule->ifname,sizeof(rule->ifname)) && !rule->ifnot && !rule->uid_op && !rule->gid_op &&
        zero_bytes(rule->uid,sizeof(rule->uid)) && zero_bytes(rule->gid,sizeof(rule->gid)) &&
        !rule->rule_flag && !rule->log && !rule->logif && !rule->match_tag_not && !rule->natpass &&
        !rule->type && !rule->code && !rule->flags && !rule->flagset && !rule->min_ttl && !rule->allow_opts && !rule->rt &&
        !rule->return_ttl && !rule->tos && !rule->anchor_wildcard && !rule->flush &&
        !rule->proto_variant && !rule->extfilter && !rule->extmap && !rule->dnpipe && !rule->dntype &&
        zero_bytes(rule->src,64) && zero_bytes(rule->dst,64);
}
/* Fixed XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea
 * bsd/net/pf_ruleset.c pf_anchor_setup/copyout: our no-leading-slash
 * single-component call is normalized to relative=1 at the root. Input
 * remains zeroed. These are separate contracts, never a 0-or-1 allowance;
 * exact identity above excludes '/', '../', wildcard and foreign paths. */
static int owned_write_template(const EnvaraPFHookRequest *request, const HookLease *lease) {
    return owned_semantics(request,lease) && request->rule.anchor_relative == 0;
}
static int owned_readback(const EnvaraPFHookRequest *request, const HookLease *lease) {
    return owned_semantics(request,lease) && request->rule.anchor_relative == 1;
}
static EnvaraPFHookRequest new_rule(const HookLease *lease) {
    EnvaraPFHookRequest request = {0}; strcpy(request.anchor_call, lease->anchor); strcpy(request.rule.owner, lease->owner);
    strcpy(request.rule.label, lease->label); request.rule.priority = UINT32_MAX; return request;
}
static int write_rule(int fd, unsigned long op, EnvaraPFHookRequest *request, const HookLease *lease) {
    uint64_t ticket = 0;
    if ((op != ENVARA_PF_HOOK_INSERT && op != ENVARA_PF_HOOK_DELETE) || !lease_identity_valid(lease) || request->action || !owned_write_template(request, lease) ||
        (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDWR || (op == ENVARA_PF_HOOK_INSERT && request->rule.ticket) ||
        (op == ENVARA_PF_HOOK_DELETE && (!lease_valid(lease) || !ticket_value(lease->ticket, &ticket) || request->rule.ticket != ticket))) { errno = EINVAL; return -1; }
    return ioctl(fd, op, request);
}
/* Same fixed-source normalization as the native-verified canary: XNU
 * f6217f891ac0bb64f3d375211650a4c1ff8ca1ea pf_rule_copyout/calc_skip_steps.
 * Preserve inner ticket/owner/label/matches/opaque semantics and rule order. */
static EnvaraPFHookRule semantic(EnvaraPFHookRule rule) {
    memset(rule.skip, 0, sizeof(rule.skip)); rule.evaluations = 0; memset(rule.packets, 0, sizeof(rule.packets)); memset(rule.bytes, 0, sizeof(rule.bytes)); return rule;
}
static void root_hash(HookRoot *root, uint32_t count) {
    EnvaraPFHookRequest normalized[RULE_LIMIT]; memcpy(normalized, root->rows, count * sizeof(*normalized));
    for (uint32_t i = 0; i < count; i++) { normalized[i].ticket = 0; normalized[i].rule = semantic(normalized[i].rule); }
    hook_hash(normalized, count * sizeof(*normalized), root->canonical);
}
static int read_root(int fd, HookRoot *root) {
    memset(root, 0, sizeof(*root)); EnvaraPFHookRequest request = {0}; if (read_rule(fd, ENVARA_PF_HOOK_GET_RULES, &request, NULL) || request.nr > RULE_LIMIT) return 0;
    root->count = request.nr; uint32_t revision = request.ticket;
    for (uint32_t i = 0; i < root->count; i++) {
        EnvaraPFHookRequest *row = &root->rows[i]; row->ticket = revision; row->nr = i;
        if (read_rule(fd, ENVARA_PF_HOOK_GET_RULE, row, NULL) || row->rule.nr != i ||
            strnlen(row->anchor_call, sizeof(row->anchor_call)) == sizeof(row->anchor_call) ||
            strnlen(row->rule.owner, sizeof(row->rule.owner)) == sizeof(row->rule.owner) ||
            strnlen(row->rule.label, sizeof(row->rule.label)) == sizeof(row->rule.label)) return 0;
    }
    memset(&request, 0, sizeof(request)); return !read_rule(fd, ENVARA_PF_HOOK_GET_RULES, &request, NULL) && request.nr == root->count && request.ticket == revision;
}
/* Presence only. GET exposes active rules, never inactive queues/refcounts. */
static int leaf_state(int fd, const char *anchor) {
    if (!anchor_valid(anchor)) return -1;
    EnvaraPFHookRequest request = {0}; strcpy(request.anchor,anchor);
    if (!read_rule(fd,ENVARA_PF_HOOK_GET_RULES,&request,anchor)) return 1;
    return errno == EINVAL ? 0 : -1;
}
static int leaf_absent(int fd, const char *anchor) { return leaf_state(fd,anchor) == 0; }
static int leaf_empty(int fd, const char *anchor) {
    const unsigned char actions[] = {0,2,4,6,8,11};
    if (!anchor_valid(anchor) || (fcntl(fd,F_GETFL)&O_ACCMODE) != O_RDONLY) return 0;
    for (size_t i = 0; i < sizeof(actions); i++) {
        EnvaraPFHookRequest first = {0}, second = {0};
        strcpy(first.anchor,anchor); first.rule.action = actions[i]; second = first;
        if (ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&first) || first.nr ||
            ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&second) || second.nr || first.ticket != second.ticket) return 0;
    }
    return 1;
}
static int find_identity(const HookRoot *root, const HookLease *lease, EnvaraPFHookRequest *out) {
    uint64_t ticket; if (!lease_valid(lease) || !ticket_value(lease->ticket, &ticket)) return 0; int found = 0;
    for (uint32_t i = 0; i < root->count; i++) if (root->rows[i].rule.ticket == ticket) {
        if (found || !owned_identity(&root->rows[i], lease)) return 0; *out = root->rows[i]; found = 1;
    }
    return found;
}
static int find_lease(const HookRoot *root, const HookLease *lease, EnvaraPFHookRequest *out) {
    return find_identity(root,lease,out) && owned_readback(out,lease);
}
static int old_text_matches(const char *line, const EnvaraPFHookRequest *request) {
    char expected[1200]; const EnvaraPFHookRule *rule = &request->rule;
    if (strchr(request->anchor_call, '"') || strchr(request->anchor_call, '\\')) return 0;
    snprintf(expected, sizeof(expected), "anchor \"%s\" all", request->anchor_call);
    return !strcmp(line, expected) && !rule->action && !rule->direction && !rule->quick && !rule->keep_state && !rule->af && !rule->proto &&
        !rule->ifnot && !rule->uid_op && !rule->gid_op && zero_bytes(rule->label, 64) && zero_bytes(rule->ifname, 16) && zero_bytes(rule->src, 64) && zero_bytes(rule->dst, 64);
}
static int original_compatible(HookRoot *root, const HookLease *lease) {
    EnvaraPFHookRequest owned; if (root->count != (lease ? 8U : 7U) || (lease && (!find_lease(root, lease, &owned) || owned.rule.nr != 7))) return 0;
    root_hash(root, 7); if (strcmp(root->canonical, ROOT_RULE_HASH)) return 0;
    char *text = malloc(TEXT_LIMIT + 1); if (!text) return 0; int okay = fixed_pfctl(1, text); char *cursor = text;
    for (uint32_t i = 0; okay && i < 7; i++) { char *end = strchr(cursor, '\n'); if (!end) { okay = 0; break; }
        *end = 0; okay = old_text_matches(cursor, &root->rows[i]); *end = '\n'; cursor = end + 1; }
    if (okay && !lease && *cursor) okay = 0;
    if (okay) { hook_hash(text, (size_t)(cursor - text), root->text); okay = !strcmp(root->text, ROOT_TEXT_HASH); }
    free(text); return okay;
}
/* Enabling PF can activate latent third-party rules. Root shape alone cannot
 * authorize it. Fixed XNU pf_ruleset.c pf_get_ruleset_number maps the following
 * actions to filter/scrub/NAT/BINAT/RDR/dummynet. Each exact root-derived
 * foreign call must have zero rules in all six classes; root non-filter
 * classes must also be empty. Missing/unsupported/ambiguous reads fail closed.
 * Paths come only from the native-verified original root, never JSON input. */
static int prior_count(int fd, const HookRoot *root, int index, unsigned char action, uint32_t *count) {
    if ((action != 0 && action != 2 && action != 4 && action != 6 && action != 8 && action != 11) ||
        index < -1 || index > 6 || strcmp(root->canonical, ROOT_RULE_HASH) ||
        (fcntl(fd,F_GETFL) & O_ACCMODE) != O_RDONLY) return 0;
    EnvaraPFHookRequest request = {0}; request.rule.action = action; char selected[1024] = {0};
    if (index >= 0) {
        const char *path = root->rows[index].anchor_call; size_t length = strnlen(path,1024);
        if (!length || length > 128 || path[0] == '/' || path[length-1] == '/' || strstr(path,"..")) return 0;
        for (size_t i = 0; i < length; i++) if (!((path[i] >= 'a' && path[i] <= 'z') || (path[i] >= 'A' && path[i] <= 'Z') ||
            (path[i] >= '0' && path[i] <= '9') || path[i] == '.' || path[i] == '_' || path[i] == '-' || path[i] == '/')) return 0;
        strcpy(selected,path); strcpy(request.anchor,selected);
    }
    /* Both calls have literal outer PF_GET_NONE=0, including scrub action2:
     * rule.action chooses a ruleset; outer action never clears counters. */
    if (ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&request)) return 0;
    uint32_t revision = request.ticket, amount = request.nr;
    EnvaraPFHookRequest again = {0}; again.rule.action = action; strcpy(again.anchor,selected);
    if (ioctl(fd,ENVARA_PF_HOOK_GET_RULES,&again) || again.nr != amount || again.ticket != revision) return 0;
    *count = amount; return 1;
}
static int prior_anchors_empty(int fd, const HookRoot *root, char digest[65]) {
    const unsigned char actions[] = {0,2,4,6,8,11}; uint32_t counts[8][6] = {{0}};
    for (int index = -1; index < 7; index++) for (size_t type = index < 0 ? 1 : 0; type < 6; type++)
        if (!prior_count(fd,root,index,actions[type],&counts[index+1][type]) || counts[index+1][type]) return 0;
    hook_hash(counts,sizeof(counts),digest); return 1;
}
static size_t lease_json(const HookLease *lease, char output[ENVARA_PF_RUN_LEASE_LIMIT + 1]) {
    int length = snprintf(output,ENVARA_PF_RUN_LEASE_LIMIT + 1,
        "{\"schema\":\"%s\",\"runId\":\"%s\",\"leaseId\":\"%s\",\"anchor\":\"%s\",\"owner\":\"%s\",\"label\":\"%s\",\"ticket\":\"%s\",\"rootBeforeSHA256\":\"%s\",\"rootBeforeTextSHA256\":\"%s\"}",
        lease->schema,lease->runId,lease->leaseId,lease->anchor,lease->owner,lease->label,lease->ticket,lease->rootBeforeSHA256,lease->rootBeforeTextSHA256);
    return length > 0 && length <= ENVARA_PF_RUN_LEASE_LIMIT ? (size_t)length : 0;
}
static HookProof prove(int fd, const char *run_id, const HookLease *lease, int inspect_ledger) {
    HookProof proof = {0}; proof.namespace_state = -1; proof.ledger_state = ENVARA_PF_RUN_UNKNOWN;
    if (run_id && !envara_pf_run_anchor(run_id,proof.anchor)) return proof;
    if (run_id && inspect_ledger) {
        if (lease) {
            char canonical[ENVARA_PF_RUN_LEASE_LIMIT + 1]; size_t length = lease_json(lease,canonical);
            proof.ledger_verified = length && envara_pf_run_ledger_inspect_lease(run_id,canonical,length,&proof.ledger_state);
        } else proof.ledger_verified = envara_pf_run_ledger_inspect(run_id,&proof.ledger_state);
        proof.receipt_retired = proof.ledger_verified && proof.ledger_state == ENVARA_PF_RUN_RETIRED;
    }
    proof.pins = pins_verified(); if (!proof.pins) return proof;
    proof.disabled = pf_disabled(); proof.readable = read_root(fd, &proof.root); if (!proof.readable) return proof;
    for (uint32_t i = 0; proof.anchor[0] && i < proof.root.count; i++) if (!strcmp(proof.root.rows[i].anchor_call, proof.anchor)) proof.hook_present = 1;
    EnvaraPFHookRequest owned; proof.hook_verified = lease && find_lease(&proof.root, lease, &owned);
    proof.compatible = original_compatible(&proof.root,proof.hook_present ? lease : NULL);
    proof.prior_compatible = proof.compatible && prior_anchors_empty(fd,&proof.root,proof.prior_counts);
    if (proof.anchor[0]) proof.namespace_state = leaf_state(fd,proof.anchor);
    proof.leaf_absent = proof.anchor[0] && proof.namespace_state == 0; return proof;
}
struct EnvaraPFHookFilterLease {
    HookLease lease;
    EnvaraPFRunLedger *ledger;
    int read_fd;
    pid_t creator;
    struct stat device;
};
static int filter_lease_parse(const char *json, unsigned long length, HookLease *lease) {
    if (!json || !length || length > ENVARA_PF_RUN_LEASE_LIMIT || memchr(json,0,length)) return 0;
    char text[ENVARA_PF_RUN_LEASE_LIMIT + 1]; memcpy(text,json,length);text[length]=0;
    const char *p=text;memset(lease,0,sizeof(*lease));
    int okay=parse_lease(&p,lease);space(&p);okay=okay && !*p;
    memset(text,0,sizeof(text));return okay;
}
static int filter_device_matches(const EnvaraPFHookFilterLease *held,int fd,int access) {
    struct stat current,path;
    return held && fd>=0 && !fstat(fd,&current) && !lstat("/dev/pf",&path) &&
        S_ISCHR(current.st_mode) && !current.st_uid && S_ISCHR(path.st_mode) && !path.st_uid &&
        current.st_dev==held->device.st_dev && current.st_ino==held->device.st_ino && current.st_rdev==held->device.st_rdev &&
        path.st_dev==current.st_dev && path.st_ino==current.st_ino && path.st_rdev==current.st_rdev &&
        (fcntl(fd,F_GETFL)&O_ACCMODE)==access;
}
int envara_pf_hook_filter_matches(const EnvaraPFHookFilterLease *held,const char *json,unsigned long length) {
    HookLease selected;
    return held && held->creator==getpid() && !getuid() && !geteuid() &&
        filter_lease_parse(json,length,&selected) && !memcmp(&held->lease,&selected,sizeof(selected));
}
int envara_pf_hook_filter_guard(EnvaraPFHookFilterLease *held,int write_fd) {
    if (!held || held->creator!=getpid() || getuid() || geteuid() || !held->ledger ||
        !filter_device_matches(held,held->read_fd,O_RDONLY) || (write_fd>=0 && !filter_device_matches(held,write_fd,O_RDWR))) return 0;
    /* The issued ledger EX handle excludes a concurrent DELETE. Do not reopen
     * its lock recursively. Kernel/root proof is independently reread. */
    HookProof proof=prove(held->read_fd,held->lease.runId,&held->lease,0);
    return proof.pins && proof.readable && proof.compatible && proof.prior_compatible &&
        proof.hook_present && proof.hook_verified && proof.namespace_state==1;
}
int envara_pf_hook_filter_open(const char *run_id,const char *json,unsigned long length,EnvaraPFHookFilterLease **out) {
    if (!out) return 0;*out=NULL;
    if (getuid() || geteuid() || !run_id || !uuid_valid(run_id)) return 0;
    EnvaraPFHookFilterLease *held=calloc(1,sizeof(*held));if(!held)return 0;
    held->read_fd=-1;held->creator=getpid();
    if (!filter_lease_parse(json,length,&held->lease) || strcmp(run_id,held->lease.runId)) goto refused;
    char canonical[ENVARA_PF_RUN_LEASE_LIMIT+1];size_t canonical_length=lease_json(&held->lease,canonical);
    if (!canonical_length || !envara_pf_run_ledger_open_issued(run_id,canonical,canonical_length,&held->ledger)) { memset(canonical,0,sizeof(canonical));goto refused; }
    memset(canonical,0,sizeof(canonical));
    held->read_fd=open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (held->read_fd<0 || fstat(held->read_fd,&held->device) || !S_ISCHR(held->device.st_mode) || held->device.st_uid ||
        !envara_pf_hook_filter_guard(held,-1)) goto refused;
    *out=held;return 1;
refused:
    envara_pf_hook_filter_close(held);return 0;
}
void envara_pf_hook_filter_close(EnvaraPFHookFilterLease *held) {
    if(!held)return;
    if(held->read_fd>=0)close(held->read_fd);envara_pf_run_ledger_close(held->ledger);
    memset(held,0,sizeof(*held));free(held);
}
static void lease_output(const HookLease *lease) {
    char canonical[ENVARA_PF_RUN_LEASE_LIMIT + 1]; size_t length = lease_json(lease,canonical);
    if (length) fwrite(canonical,1,length,stdout); else printf("null");
}
static int emit(const char *operation, int okay, const char *why, const HookProof *proof, const HookLease *lease, int removed, int restored, int pending) {
    int can_create = proof && proof->anchor[0] && proof->ledger_verified && proof->ledger_state == ENVARA_PF_RUN_UNUSED && proof->pins && proof->readable && proof->disabled && proof->compatible && proof->prior_compatible && proof->leaf_absent && !proof->hook_present;
    printf("{\"schema\":\"%s\",\"ok\":%s,\"operation\":\"%s\",\"reason\":\"%s\",\"anchor\":\"%s\",\"namespaceScheme\":\"full-run-uuid/v2\",\"readOnly\":%s,\"productionReady\":false,\"ready\":false,\"protected\":false,\"fixtureOnly\":true,", HOOK_SCHEMA,okay?"true":"false",operation,why,proof?proof->anchor:"",!strcmp(operation,"hook-status")?"true":"false");
    printf("\"pfDisabled\":%s,\"pinsVerified\":%s,\"originalRootCompatible\":%s,\"canCreateOwnedHook\":%s,\"ownedRootHookCanCreate\":%s,\"ownedRootHookVerified\":%s,\"hookInstalled\":%s,\"ownedRootHookRemoved\":%s,\"originalRootRestored\":%s,\"cleanupPending\":%s,",
        proof&&proof->disabled?"true":"false",proof&&proof->pins?"true":"false",proof&&proof->compatible?"true":"false",can_create?"true":"false",can_create?"true":"false",proof&&proof->hook_verified?"true":"false",proof&&proof->hook_present?"true":"false",removed?"true":"false",restored?"true":"false",pending?"true":"false");
    printf("\"namespaceState\":\"%s\",\"namespaceReclaimed\":%s,\"namespaceExists\":%s,\"receiptRetired\":%s,\"runLedgerState\":\"%s\",\"inactiveQueuesVerified\":false,\"namespaceReferencesVerified\":false,",
        !proof||!proof->anchor[0]?"unselected":proof->namespace_state==0?"absent":proof->namespace_state==1?"present":"unknown",
        proof&&proof->anchor[0]&&proof->namespace_state==0?"true":"false",proof&&proof->anchor[0]&&proof->namespace_state==1?"true":"false",
        proof&&proof->receipt_retired?"true":"false",proof&&proof->anchor[0]?envara_pf_run_ledger_state_name(proof->ledger_state):"unselected");
    printf("\"originalRootTextSHA256\":\"%s\",\"originalRootSHA256\":\"%s\",\"ticketSource\":\"this-INSERT-return-only\",\"nativeCanaryProof\":\"root-canary-native-20261008-fixed-v1-only\",\"namespaceCanaryVerified\":false,\"gates\":{\"productionHook\":false,\"fullKernelLayout\":false,\"fullFixtureAcceptance\":false,\"wholeGuardCrash\":false,\"allStatePreservation\":false},\"lease\":",proof?proof->root.text:"",proof?proof->root.canonical:"");
    if (lease) lease_output(lease); else printf("null");
    printf(",\"priorAnchorsCompatible\":%s,\"priorRootDerivedAnchorCount\":7,\"priorRulesetCountsSHA256\":\"%s\"}\n",proof&&proof->prior_compatible?"true":"false",proof?proof->prior_counts:"");
    return fflush(stdout) == 0 && !ferror(stdout);
}
static int exact_remove(int read_fd, int write_fd, const HookLease *lease) {
    HookRoot current; EnvaraPFHookRequest owned;
    if (!lease_valid(lease) || !read_root(read_fd,&current) || !find_identity(&current,lease,&owned) || !leaf_empty(read_fd,lease->anchor)) return 0;
    /* Remove only the issued receipt's current identity, even if an unknown
     * semantic readback prevented successful insertion proof. Never copy
     * unknown readback fields into a write: DELETE receives a fixed template. */
    EnvaraPFHookRequest deletion = new_rule(lease); deletion.rule.ticket = owned.rule.ticket;
    return write_rule(write_fd,ENVARA_PF_HOOK_DELETE,&deletion,lease) == 0;
}
static int peer_closed(void) { struct pollfd wait = {STDOUT_FILENO, 0, 0}; return poll(&wait, 1, 0) > 0 && (wait.revents & (POLLHUP|POLLERR|POLLNVAL)); }
static EnvaraPFRunLedgerRetirement retirement_for(const HookProof *proof) {
    return proof->namespace_state == 0 ? ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_ABSENT :
        proof->namespace_state == 1 ? ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_PRESENT : ENVARA_PF_RUN_ROOT_RESTORED_NAMESPACE_UNKNOWN;
}
int envara_pf_hook_main(int argc, char **argv) {
    const char *operation = argc == 2 ? argv[1] : "invalid";
    int is_status = !strcmp(operation,"hook-status"), is_insert = !strcmp(operation,"insert-owned-root-hook"), is_delete = !strcmp(operation,"delete-owned-root-hook");
    if ((!is_status && !is_insert && !is_delete) || argc != 2) { emit("invalid",0,"INVALID_FIXED_OPERATION",NULL,NULL,0,0,0); return 1; }
    if (getuid() || geteuid()) { emit(operation,is_status,"AUTHENTICATED_ROOT_CONTROLLER_REQUIRED",NULL,NULL,0,0,0); return is_status?0:1; }
    struct sigaction handler = {0}; handler.sa_handler = hook_signal; sigemptyset(&handler.sa_mask);
    const int signals[] = {SIGTERM,SIGINT,SIGHUP,SIGPIPE};
    for (size_t i = 0; i < 4; i++) if (sigaction(signals[i],&handler,NULL)) { emit(operation,0,"SIGNAL_BOUNDARY_UNAVAILABLE",NULL,NULL,0,0,0); return 1; }
    char payload[INPUT_LIMIT+1]; HookInput input;
    if (!read_input(payload,is_status) || !parse_input(payload,operation,&input)) { emit(operation,0,"INVALID_PRIVATE_HOOK_INPUT",NULL,NULL,0,0,0); return 1; }
    if (!pins_verified()) { emit(operation,0,"PINNED_HOST_MISMATCH",NULL,NULL,0,0,0); return 1; }
    int read_fd = open("/dev/pf",O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if (read_fd < 0) { emit(operation,0,"READ_DEVICE_UNAVAILABLE",NULL,NULL,0,0,0); return 1; }
    const char *run_id = input.has_lease ? input.lease.runId : input.has_run ? input.runId : NULL;
    HookProof proof = prove(read_fd,run_id,input.has_lease?&input.lease:NULL,1);
    if (is_status) {
        int verified = proof.readable && (!run_id || proof.ledger_verified);
        int restored = proof.receipt_retired && proof.compatible && !proof.hook_present;
        int okay = emit(operation,verified,"READ_ONLY_OWNED_HOOK_PROOF",&proof,NULL,restored,restored,restored&&!proof.leaf_absent);
        close(read_fd); return okay&&verified?0:1;
    }
    if (!proof.ledger_verified) { emit(operation,0,"OWNED_RUN_LEDGER_UNVERIFIED",&proof,NULL,0,0,is_delete); close(read_fd); return 1; }
    if (is_insert && proof.ledger_state != ENVARA_PF_RUN_UNUSED) { emit(operation,0,"OWNED_RUN_NAMESPACE_CONSUMED",&proof,NULL,0,0,0); close(read_fd); return 1; }
    if (is_insert && (!proof.pins || !proof.readable || !proof.disabled || !proof.compatible || !proof.prior_compatible || !proof.leaf_absent || proof.hook_present || hook_interrupted || peer_closed())) {
        emit(operation,0,"OWNED_HOOK_PREFLIGHT_REQUIRED",&proof,NULL,0,0,0); close(read_fd); return 1;
    }
    EnvaraPFHookRequest known;
    if (is_delete && (!proof.readable || !proof.disabled || !find_identity(&proof.root,&input.lease,&known) || !leaf_empty(read_fd,input.lease.anchor))) { emit(operation,0,"EXACT_LEASE_AND_EMPTY_OWNED_ANCHOR_REQUIRED",&proof,NULL,0,0,1); close(read_fd); return 1; }
    EnvaraPFRunLedger *ledger = NULL;
    if (is_insert && !envara_pf_run_ledger_allocate(run_id,&ledger)) { emit(operation,0,"OWNED_RUN_ALLOCATION_REQUIRED",&proof,NULL,0,0,0); close(read_fd); return 1; }
    if (is_insert) proof.ledger_state = ENVARA_PF_RUN_ALLOCATION_ONLY;
    if (is_delete) {
        char canonical[ENVARA_PF_RUN_LEASE_LIMIT + 1]; size_t length = lease_json(&input.lease,canonical);
        if (!length || !envara_pf_run_ledger_open_issued(run_id,canonical,length,&ledger)) { emit(operation,0,"EXACT_ISSUED_LEASE_REQUIRED",&proof,NULL,0,0,1); close(read_fd); return 1; }
    }
    int write_fd = open("/dev/pf",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (write_fd < 0) { emit(operation,0,"WRITE_DEVICE_UNAVAILABLE",&proof,NULL,0,0,is_delete); envara_pf_run_ledger_close(ledger); close(read_fd); return 1; }
    if (is_delete) {
        if (!envara_pf_run_ledger_begin_delete(ledger)) {
            emit(operation,0,"OWNED_HOOK_DELETE_INTENT_REQUIRED",&proof,NULL,0,0,1);
            close(write_fd); envara_pf_run_ledger_close(ledger); close(read_fd); return 1;
        }
        /* The durable intent consumes the one DELETE attempt even when a
         * subsequent read/refusal, ioctl failure or lost reply is ambiguous. */
        (void)exact_remove(read_fd,write_fd,&input.lease);
        /* PF proof remains independent. Reopening the ledger here would
         * conflict with this invocation's held exclusive descriptor lock. */
        HookProof after = prove(read_fd,run_id,&input.lease,0);
        int restored = after.readable && after.compatible && !after.hook_present;
        int retired = restored && envara_pf_run_ledger_retire(ledger,retirement_for(&after));
        after.ledger_verified = retired; after.ledger_state = retired ? ENVARA_PF_RUN_RETIRED : ENVARA_PF_RUN_UNKNOWN; after.receipt_retired = retired;
        int okay = restored && retired;
        emit(operation,okay,okay?(after.leaf_absent?"EXACT_OWNED_HOOK_REMOVED":"EXACT_OWNED_HOOK_DEACTIVATED_NAMESPACE_RETAINED"):
            restored?"OWNED_RUN_RETIREMENT_UNCONFIRMED":"EXACT_CLEANUP_UNCONFIRMED",&after,NULL,restored,restored,!okay||!after.leaf_absent);
        close(write_fd); envara_pf_run_ledger_close(ledger); close(read_fd); return okay?0:1;
    }
    HookLease lease = {0}; strcpy(lease.schema,LEASE_SCHEMA); strcpy(lease.runId,input.runId); random_uuid(lease.leaseId);
    envara_pf_run_anchor(run_id,lease.anchor); strcpy(lease.owner,lease.anchor); lease_label(&lease,lease.label);
    strcpy(lease.rootBeforeSHA256,proof.root.canonical); strcpy(lease.rootBeforeTextSHA256,proof.root.text);
    /* Last Disabled check occurs after slow proof/readback and immediately
     * before INSERT. Cross-process enable races remain an explicit gate. */
    HookRoot immediate;
    if (hook_interrupted || peer_closed() || !read_root(read_fd,&immediate) || !original_compatible(&immediate,NULL) ||
        !prior_anchors_empty(read_fd,&immediate,proof.prior_counts) || !pf_disabled() || !leaf_absent(read_fd,lease.anchor)) {
        emit(operation,0,"PF_CHANGED_OR_PARENT_ENDED_BEFORE_INSERT",&proof,NULL,0,0,0); close(write_fd); envara_pf_run_ledger_close(ledger); close(read_fd); return 1;
    }
    EnvaraPFHookRequest request = new_rule(&lease); int inserted = write_rule(write_fd,ENVARA_PF_HOOK_INSERT,&request,&lease);
    if (owned_identity(&request,&lease) && request.rule.ticket) snprintf(lease.ticket,sizeof(lease.ticket),"%llu",(unsigned long long)request.rule.ticket);
    HookProof after = prove(read_fd,run_id,lease_valid(&lease)?&lease:NULL,0);
    int verified = inserted == 0 && lease_valid(&lease) && after.hook_verified && after.compatible && after.prior_compatible && leaf_empty(read_fd,lease.anchor) && after.disabled && !hook_interrupted && !peer_closed();
    char canonical[ENVARA_PF_RUN_LEASE_LIMIT + 1]; size_t length = lease_json(&lease,canonical);
    int issued = verified && length && envara_pf_run_ledger_issue(ledger,canonical,length);
    after.ledger_verified = issued; after.ledger_state = issued ? ENVARA_PF_RUN_ISSUED : ENVARA_PF_RUN_UNKNOWN;
    if (issued && emit(operation,1,"OWNED_EMPTY_HOOK_VERIFIED",&after,&lease,0,0,0)) { close(write_fd); envara_pf_run_ledger_close(ledger); close(read_fd); return 0; }
    /* Never acquire ownership from an observed rule. Receiptless INSERT or a
     * mismatching readback must not delete a same-name foreign ticket. */
    /* Even a failed issue() may have left an issued file before a durability
     * error. Every rollback DELETE therefore requires durable intent; a
     * partial/unknown ledger refuses rather than permitting a second epoch. */
    int rollback_intent = envara_pf_run_ledger_begin_delete(ledger);
    int removed = rollback_intent && lease_valid(&lease) && exact_remove(read_fd,write_fd,&lease);
    HookProof restored = prove(read_fd,run_id,NULL,0);
    int root_restored = restored.readable && restored.compatible && !restored.hook_present;
    int retired = root_restored && envara_pf_run_ledger_retire(ledger,retirement_for(&restored));
    restored.ledger_verified = retired; restored.ledger_state = retired ? ENVARA_PF_RUN_RETIRED : ENVARA_PF_RUN_UNKNOWN; restored.receipt_retired = retired;
    emit(operation,0,rollback_intent?"INSERT_UNCONFIRMED_OWN_ROLLBACK_ATTEMPTED":"INSERT_UNCONFIRMED_OWN_ROLLBACK_REFUSED",&restored,issued?&lease:NULL,removed,root_restored,!root_restored||!retired||!restored.leaf_absent);
    close(write_fd); envara_pf_run_ledger_close(ledger); close(read_fd); return 1;
}
#ifdef ENVARA_PF_HOOK_STANDALONE
int main(int argc,char **argv) { return envara_pf_hook_main(argc,argv); }
#endif
