/* REVIEW CANDIDATE ONLY. The default plan never asks for rights or opens PF.
 * --request-canary is a separate native authorization for one empty root call.
 * No result from this program enables production application routing. */
#define main envara_readonly_inspector_entry
#include "pf-abi-inspector.c"
#undef main
#include <Security/SecRandom.h>

#define CANARY_SCHEMA "envara.macos-pf-root-canary/v1"
#define CANARY_ANCHOR "io.envara.pf.root.v1"
#define CANARY_OWNER "io.envara.pf.root.v1"
#define CANARY_LABEL_PREFIX "envara.empty.v1."
#define CANARY_LABEL_TEMPLATE CANARY_LABEL_PREFIX "<32-random-hex>"
#define CANARY_RULE_LIMIT 64
static char active_label[64];
static uint64_t issued_ticket;
static int pf_device_opened;
#define PINNED_ROOT_TEXT "5e803c2e459d5417da5d61aba888d1da25ad56cb0bff4f22e69d36078eb7f575"
#define PINNED_PFD "ce0e2352db81ea01fdc592c56447c5f89a3ee1a923122ef6ba5f78259bc47049"
#define CANARY_INSERT _IOWR('D', 27, InspectorRequest)
#define CANARY_DELETE _IOWR('D', 28, InspectorRequest)
_Static_assert(CANARY_INSERT == 0xcc20441bUL, "INSERT encoding mismatch");
_Static_assert(CANARY_DELETE == 0xcc20441cUL, "DELETE encoding mismatch");

/* Nonzero ticket support is an experiment, not proved by these layout asserts.
 * Additional observed Apple userland evidence: current pfd loads/stores a u64
 * at request+0xac0 for INSERT/DELETE, owner at +0xac8, priority at +0xb08.
 * Current pfctl prints label from rule+192, owner+696 and priority+760. */
static volatile sig_atomic_t interrupted;
static void interruption(int value) { interrupted = value; }
static int peer_ended(void) {
    struct pollfd wait = { STDOUT_FILENO, 0, 0 };
    return poll(&wait, 1, 0) > 0 && (wait.revents & (POLLHUP | POLLERR | POLLNVAL));
}
static int pinned_host(void) {
    char hash[65]; return host_matches() && file_digest("/usr/libexec/pfd", hash) && !strcmp(hash, PINNED_PFD);
}
static int fixed_read(int fd, unsigned long operation, InspectorRequest *request) {
    if ((operation != INSPECT_GET_RULES && operation != INSPECT_GET_RULE) || request->action || request->rule.action ||
        (request->anchor[0] && strcmp(request->anchor, CANARY_ANCHOR)) || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) { errno = EINVAL; return -1; }
    return ioctl(fd, operation, request);
}
static int valid_label(const char *label) {
    size_t prefix = strlen(CANARY_LABEL_PREFIX);
    if (!label || strlen(label) != prefix + 32 || strncmp(label, CANARY_LABEL_PREFIX, prefix)) return 0;
    for (size_t i = prefix; i < prefix + 32; i++) if (!((label[i] >= '0' && label[i] <= '9') || (label[i] >= 'a' && label[i] <= 'f'))) return 0;
    return 1;
}
static int generate_label(char label[64]) {
    uint8_t nonce[16]; if (SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce) != errSecSuccess) return 0;
    strcpy(label, CANARY_LABEL_PREFIX); size_t prefix = strlen(label);
    for (size_t i = 0; i < sizeof(nonce); i++) snprintf(label + prefix + i * 2, 3, "%02x", nonce[i]);
    return valid_label(label);
}
static int own_call(const InspectorRequest *request, const char *label) {
    const InspectorRule *rule = &request->rule;
    if (strnlen(request->anchor, sizeof(request->anchor)) == sizeof(request->anchor) ||
        strnlen(request->anchor_call, sizeof(request->anchor_call)) == sizeof(request->anchor_call) ||
        strnlen(rule->owner, sizeof(rule->owner)) == sizeof(rule->owner) ||
        strnlen(rule->label, sizeof(rule->label)) == sizeof(rule->label)) return 0;
    return !request->anchor[0] && !strcmp(request->anchor_call, CANARY_ANCHOR) &&
        !strcmp(rule->owner, CANARY_OWNER) && valid_label(label) && !strcmp(rule->label, label) &&
        rule->priority == UINT32_MAX && rule->action == 0 && rule->keep_state == 0 &&
        rule->direction == 0 && rule->quick == 0 && rule->af == 0 && rule->proto == 0 &&
        rule->ifname[0] == 0 && rule->gid_op == 0 && rule->uid_op == 0 &&
        zero(rule->src, sizeof(rule->src)) && zero(rule->dst, sizeof(rule->dst));
}
static InspectorRequest new_call(const char *label) {
    InspectorRequest request = {0}; if (!valid_label(label)) return request;
    strcpy(request.anchor_call, CANARY_ANCHOR);
    strcpy(request.rule.owner, CANARY_OWNER); strcpy(request.rule.label, label);
    request.rule.priority = UINT32_MAX; return request;
}
static int fixed_write(int fd, unsigned long operation, InspectorRequest *request, const char *label) {
    if ((operation != CANARY_INSERT && operation != CANARY_DELETE) || request->action || !own_call(request, label) ||
        (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDWR || (operation == CANARY_DELETE && request->rule.ticket == 0) ||
        (operation == CANARY_INSERT && request->rule.ticket != 0)) { errno = EINVAL; return -1; }
    return ioctl(fd, operation, request);
}
typedef struct { uint32_t count; InspectorRequest rows[CANARY_RULE_LIMIT]; char canonical[65], text[65]; } RootSnapshot;
/* Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea (12377.121.6),
 * bsd/net/pf_ioctl.c pf_rule_copyout and pf_calc_skip_steps: skip pointers/indices and
 * evaluation/packet/byte counters are derived. Do not exclude match/action,
 * opaque semantics, owner, label, priority, rule number or inner u64 ticket. */
static InspectorRule semantic_rule(InspectorRule rule) {
    memset(rule.skip, 0, sizeof(rule.skip)); rule.evaluations = 0;
    memset(rule.packets, 0, sizeof(rule.packets)); memset(rule.bytes, 0, sizeof(rule.bytes)); return rule;
}
static void snapshot_digest(RootSnapshot *snapshot) {
    InspectorRequest canonical[CANARY_RULE_LIMIT]; memcpy(canonical, snapshot->rows, snapshot->count * sizeof(*canonical));
    for (uint32_t i = 0; i < snapshot->count; i++) { canonical[i].ticket = 0; canonical[i].rule = semantic_rule(canonical[i].rule); }
    digest(canonical, snapshot->count * sizeof(*canonical), snapshot->canonical);
}
static int root_snapshot(int fd, RootSnapshot *snapshot, int compare_text) {
    InspectorRequest request = {0}; if (fixed_read(fd, INSPECT_GET_RULES, &request) || request.nr > CANARY_RULE_LIMIT) return 0;
    snapshot->count = request.nr; uint32_t revision = request.ticket;
    for (uint32_t index = 0; index < request.nr; index++) {
        InspectorRequest *row = &snapshot->rows[index]; memset(row, 0, sizeof(*row)); row->ticket = revision; row->nr = index;
        if (fixed_read(fd, INSPECT_GET_RULE, row) || row->rule.nr != index ||
            strnlen(row->anchor_call, sizeof(row->anchor_call)) == sizeof(row->anchor_call) ||
            strnlen(row->rule.owner, sizeof(row->rule.owner)) == sizeof(row->rule.owner) ||
            strnlen(row->rule.label, sizeof(row->rule.label)) == sizeof(row->rule.label)) return 0;
    }
    memset(&request, 0, sizeof(request)); if (fixed_read(fd, INSPECT_GET_RULES, &request) || request.nr != snapshot->count || request.ticket != revision) return 0;
    snapshot_digest(snapshot);
    if (!compare_text) return 1;
    char *text = malloc(MAX_OUTPUT + 1); if (!text) return 0;
    int okay = original_rules(text); if (okay) {
        digest(text, strlen(text), snapshot->text); char *save = NULL, *line = strtok_r(text, "\n", &save);
        for (uint32_t index = 0; okay && index < snapshot->count; index++) { okay = line && matches_anchor_line(line, &snapshot->rows[index]); if (line) line = strtok_r(NULL, "\n", &save); }
        if (line) okay = 0;
    }
    free(text); return okay;
}
static int absent_leaf(int fd) {
    InspectorRequest request = {0}; strcpy(request.anchor, CANARY_ANCHOR);
    /* Exact absent single-component leaf: pinned GET/PASS/root-read ABI plus
     * valid fixed name rules out the other public EINVAL branch (bad action).
     * GET does not create an anchor. Existing even-empty leaves are refused. */
    return fixed_read(fd, INSPECT_GET_RULES, &request) == -1 && errno == EINVAL;
}
static int empty_leaf(int fd) {
    InspectorRequest request = {0}; strcpy(request.anchor, CANARY_ANCHOR);
    return fixed_read(fd, INSPECT_GET_RULES, &request) == 0 && request.nr == 0;
}
/* No caller-controlled executable or arguments can enter this read helper. */
static int readonly_command(unsigned int operation, char output[MAX_OUTPUT + 1]) {
    static const char *const programs[] = { "/sbin/pfctl", "/sbin/pfctl", "/usr/sbin/netstat", "/usr/sbin/scutil" };
    static const char *const arguments[][4] = { {"/sbin/pfctl", "-s", "info", NULL}, {"/sbin/pfctl", "-sn", NULL, NULL},
        {"/usr/sbin/netstat", "-rn", NULL, NULL}, {"/usr/sbin/scutil", "--dns", NULL, NULL} };
    if (operation >= 4) return 0;
    int pipefd[2]; if (pipe(pipefd)) return 0; pid_t child = fork();
    if (child < 0) { close(pipefd[0]); close(pipefd[1]); return 0; }
    if (!child) { close(pipefd[0]); dup2(pipefd[1], STDOUT_FILENO); close(pipefd[1]); int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null >= 0) { dup2(null, STDERR_FILENO); close(null); }
        char *environment[] = { "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        execve(programs[operation], (char *const *)arguments[operation], environment); _exit(127); }
    close(pipefd[1]); fcntl(pipefd[0], F_SETFL, O_NONBLOCK); size_t length = 0; int complete = 0; double deadline = seconds() + 10;
    while (seconds() < deadline && length < MAX_OUTPUT) { struct pollfd wait = { pipefd[0], POLLIN | POLLHUP, 0 }; int observed = poll(&wait, 1, 100);
        if (observed < 0 && errno == EINTR) continue; if (observed < 0) break; if (!observed) continue;
        ssize_t count = read(pipefd[0], output + length, MAX_OUTPUT - length);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue; if (count < 0) break; if (!count) { complete = 1; break; } length += (size_t)count; }
    output[length] = 0; close(pipefd[0]); int status = 0; if (!complete) kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return complete && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int disabled(void) { char *text = malloc(MAX_OUTPUT + 1); if (!text) return 0;
    int okay = readonly_command(0, text) && strstr(text, "Status: Disabled") != NULL; free(text); return okay; }
typedef struct { char network[65], pfconf[65], nat[65], routes[65], dns[65]; } HostSnapshot;
static int host_snapshot(HostSnapshot *snapshot) {
    char *text = malloc(MAX_OUTPUT + 1); char pieces[3][65]; if (!text) return 0;
    int okay = file_digest("/etc/pf.conf", snapshot->pfconf);
    for (unsigned int index = 0; okay && index < 3; index++) { okay = readonly_command(index + 1, text); if (okay) digest(text, strlen(text), pieces[index]); }
    free(text); if (okay) { digest(pieces, sizeof(pieces), snapshot->network); strcpy(snapshot->nat, pieces[0]); strcpy(snapshot->routes, pieces[1]); strcpy(snapshot->dns, pieces[2]); } return okay;
}
static int originals_preserved(const RootSnapshot *before, const RootSnapshot *during) {
    if (before->count != 7 || during->count != 8) return 0;
    for (uint32_t index = 0; index < 7; index++) {
        const InspectorRequest *a = &before->rows[index], *b = &during->rows[index];
        InspectorRule first = semantic_rule(a->rule), second = semantic_rule(b->rule);
        if (memcmp(a->anchor_call, b->anchor_call, sizeof(a->anchor_call)) || memcmp(&first, &second, sizeof(first))) return 0;
    }
    return 1;
}
static int original_text_preserved(const RootSnapshot *before) {
    char *text = malloc(MAX_OUTPUT + 1); if (!text) return 0;
    int okay = original_rules(text); char *cursor = text;
    for (uint32_t i = 0; okay && i < 7; i++) {
        char *end = strchr(cursor, '\n'); if (!end) { okay = 0; break; }
        char saved = *end; *end = 0; okay = matches_anchor_line(cursor, &before->rows[i]); *end = saved; cursor = end + 1;
    }
    char hash[65]; if (okay) { digest(text, (size_t)(cursor - text), hash); okay = !strcmp(hash, before->text); }
    free(text); return okay;
}
static int find_issued(const RootSnapshot *snapshot, const InspectorRequest *issued, const char *label, InspectorRequest *output) {
    if (!issued->rule.ticket || !own_call(issued, label)) return 0;
    int found = 0; for (uint32_t i = 0; i < snapshot->count; i++) {
        const InspectorRequest *row = &snapshot->rows[i];
        if (row->rule.ticket == issued->rule.ticket) {
            if (found || !own_call(row, label)) return 0; *output = *row; found = 1;
        }
    }
    return found;
}
typedef struct {
    int (*write)(int, unsigned long, InspectorRequest *, const char *);
    int (*snapshot)(int, RootSnapshot *, int);
    int (*empty)(int); int (*absent)(int);
    int (*text_preserved)(const RootSnapshot *);
    double (*clock)(void);
} CanaryIO;
typedef struct { int attempted, inserted, removed, restored, pending, deadline_exceeded; } CanaryOutcome;
static CanaryOutcome exchange_canary(int read_fd, int write_fd, const RootSnapshot *before, RootSnapshot *after, const char *label, const CanaryIO *io) {
    CanaryOutcome result = {0}; RootSnapshot during = {0}; InspectorRequest issued = new_call(label), owned = {0};
    double started = io->clock(); result.attempted = 1;
    int inserted_result = io->write(write_fd, CANARY_INSERT, &issued, label);
    /* Receipt comes only from this INSERT. Never adopt an observed foreign
     * rule's ticket if the syscall failed without returning a usable receipt. */
    issued_ticket = own_call(&issued, label) ? issued.rule.ticket : 0;
    int root_read = 0, found = 0;
    for (unsigned int attempt = 0; attempt < 2; attempt++) {
        root_read = io->snapshot(read_fd, &during, 0);
        found = root_read && find_issued(&during, &issued, label, &owned);
        if (found || root_read) break;
    }
    result.inserted = inserted_result == 0 && found && originals_preserved(before, &during) && io->empty(read_fd) && io->text_preserved(before);
    result.deadline_exceeded = io->clock() - started > 15;
    /* Every post-INSERT path reaches cleanup. Signals/EOF/deadline prevent
     * success, but never prevent a known exact owned ticket from deletion. */
    if (found) {
        int deleted = io->write(write_fd, CANARY_DELETE, &owned, label);
        int after_read = io->snapshot(read_fd, after, 1), absent = io->absent(read_fd);
        result.removed = deleted == 0 && after_read && absent;
        result.restored = after_read && after->count == 7 && !strcmp(after->canonical, before->canonical) && !strcmp(after->text, before->text);
        result.pending = !result.removed;
    } else {
        int absent = root_read && io->absent(read_fd);
        result.pending = !absent;
        if (absent && io->snapshot(read_fd, after, 1)) result.restored = after->count == 7 && !strcmp(after->canonical, before->canonical) && !strcmp(after->text, before->text);
    }
    return result;
}
static const CanaryIO native_io = { fixed_write, root_snapshot, empty_leaf, absent_leaf, original_text_preserved, seconds };
static void canary_report(const char *action, int okay, const char *why, int attempted, int inserted, int removed,
    int restored, int host_restored, int cleanup_pending, const RootSnapshot *before, const RootSnapshot *after,
    const HostSnapshot *host_before, const HostSnapshot *host_after) {
    printf("{\"schema\":\"%s\",\"action\":\"%s\",\"ok\":%s,\"reason\":\"%s\",\"experimentOnly\":true,\"productionReady\":false,\"mutationSupportVerified\":false,\"activation\":false,\"systemInstallation\":false,\"requiresSeparateApproval\":true,", CANARY_SCHEMA, action, okay ? "true" : "false", why);
    printf("\"anchor\":\"%s\",\"owner\":\"%s\",\"label\":\"%s\",\"priority\":4294967295,\"keepState\":0,\"requiresPFAlreadyDisabled\":true,\"originalRuleCount\":7,", CANARY_ANCHOR, CANARY_OWNER, active_label[0] ? active_label : CANARY_LABEL_TEMPLATE);
    printf("\"pinnedHost\":{\"darwin\":\"27.0.0\",\"xnu\":\"13432.0.94.501.4~1\",\"pfctlSHA256\":\"%s\",\"pfdSHA256\":\"%s\",\"originalRootTextSHA256\":\"%s\"},", PINNED_PFCTL, PINNED_PFD, PINNED_ROOT_TEXT);
    printf("\"insertAttempted\":%s,\"insertReadbackVerified\":%s,\"exactTicketDeleteVerified\":%s,\"originalRootRestored\":%s,\"hostNetworkRestored\":%s,\"cleanupPending\":%s,\"interrupted\":%s,", attempted ? "true" : "false", inserted ? "true" : "false", removed ? "true" : "false", restored ? "true" : "false", host_restored ? "true" : "false", cleanup_pending ? "true" : "false", interrupted ? "true" : "false");
    printf("\"issuedTicket\":\"%llu\",\"ticketSource\":\"this-INSERT-return-only\",", (unsigned long long)issued_ticket);
    printf("\"deviceOpened\":%s,\"callSequence\":[\"readonly-preflight\",\"one-empty-call-INSERT\",\"GET-exact-receipt\",\"DELETE-exact-nonzero-ticket-owner-label\",\"readonly-restore-check\"],", pf_device_opened ? "true" : "false");
    printf("\"gates\":{\"completeKernelLayoutVerified\":false,\"productionHookVerified\":false,\"PFEnabledTrafficVerified\":false,\"wholeProcessCrashCleanupVerified\":false,\"SIGKILLCleanupGuaranteed\":false,\"allStatePreservationVerified\":false},");
    printf("\"operations\":{\"requestPFStart\":false,\"stateControl\":false,\"globalReload\":false,\"groups\":false,\"tunnels\":false,\"applications\":false,\"fillChildAnchor\":false},");
    if (before && after && host_before && host_after) {
    printf("\"hashes\":{\"rootBefore\":\"%s\",\"rootAfter\":\"%s\",\"networkBefore\":\"%s\",\"networkAfter\":\"%s\",\"pfconfBefore\":\"%s\",\"pfconfAfter\":\"%s\"},", before->canonical, after->canonical, host_before->network, host_after->network, host_before->pfconf, host_after->pfconf);
    printf("\"hostComponentHashes\":{\"routesBefore\":\"%s\",\"routesAfter\":\"%s\",\"DNSBefore\":\"%s\",\"DNSAfter\":\"%s\",\"NATBefore\":\"%s\",\"NATAfter\":\"%s\"},", host_before->routes, host_after->routes, host_before->dns, host_after->dns, host_before->nat, host_after->nat);
    }
    printf("\"authorizationRequested\":%s,\"readOnly\":%s}\n", !strcmp(action, "plan") ? "false" : "true", attempted ? "false" : "true");
}
static int run_canary(void) {
    RootSnapshot before = {0}, after = {0}; HostSnapshot host_before = {0}, host_after = {0};
    int read_fd = -1, write_fd = -1, attempted = 0, inserted = 0, removed = 0, restored = 0, host_restored = 0, pending = 0;
    const char *failure_reason = "canary-preflight-unconfirmed";
    if (!authorized_root()) { canary_report("canary", 0, "privileged-reference-required", 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); return 1; }
    struct sigaction action = {0}; action.sa_handler = interruption; sigemptyset(&action.sa_mask);
    for (size_t index = 0; index < 4; index++) { const int signals[] = { SIGTERM, SIGINT, SIGHUP, SIGPIPE }; if (sigaction(signals[index], &action, NULL)) goto finish; }
    if (!generate_label(active_label)) { failure_reason = "nonce-generation-failed"; goto finish; }
    if (!pinned_host()) { failure_reason = "pinned-host-mismatch"; goto finish; }
    read_fd = open("/dev/pf", O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (read_fd < 0) goto finish; pf_device_opened = 1;
    if (!disabled() || !root_snapshot(read_fd, &before, 1) || before.count != 7 || strcmp(before.text, PINNED_ROOT_TEXT) || !absent_leaf(read_fd) || !host_snapshot(&host_before)) goto finish;
    for (uint32_t index = 0; index < before.count; index++) if (!strcmp(before.rows[index].anchor_call, CANARY_ANCHOR) || !strcmp(before.rows[index].rule.owner, CANARY_OWNER) || !strncmp(before.rows[index].rule.label, CANARY_LABEL_PREFIX, strlen(CANARY_LABEL_PREFIX))) goto finish;
    if (interrupted || peer_ended() || !disabled()) { failure_reason = "interrupted-before-insert"; goto finish; }
    RootSnapshot immediate = {0}; if (!root_snapshot(read_fd, &immediate, 1) || strcmp(immediate.canonical, before.canonical) || strcmp(immediate.text, before.text)) { failure_reason = "root-changed-before-insert"; goto finish; }
    write_fd = open("/dev/pf", O_RDWR | O_CLOEXEC | O_NOFOLLOW); if (write_fd < 0) { failure_reason = "write-device-unavailable"; goto finish; }
    /* Recheck after the potentially slow pfctl comparison. An external PF
     * start racing the actual ioctl cannot be atomically excluded here. */
    if (interrupted || peer_ended() || !disabled()) { failure_reason = "interrupted-or-PF-enabled-before-insert"; goto finish; }
    CanaryOutcome result = exchange_canary(read_fd, write_fd, &before, &after, active_label, &native_io);
    attempted = result.attempted; inserted = result.inserted; removed = result.removed;
    restored = result.restored; pending = result.pending;
    failure_reason = inserted ? "owned-empty-call-readback" : "insert-readback-unconfirmed";
    /* All post-insert paths reach this point after exact cleanup was attempted.
     * Signals only set a flag. SIGKILL/power loss cannot promise cleanup. */
    if (host_snapshot(&host_after)) host_restored = !strcmp(host_before.network, host_after.network) && !strcmp(host_before.pfconf, host_after.pfconf);
    if (!disabled()) failure_reason = "PF-state-changed-externally";
    else if (pending) failure_reason = "exact-cleanup-unconfirmed-empty-call-may-remain";
    else if (result.deadline_exceeded) failure_reason = "deadline-exceeded-after-exact-cleanup";
    else if (interrupted || peer_ended()) failure_reason = "interrupted-after-exact-cleanup";
    else if (inserted && removed && restored && host_restored) failure_reason = "empty-root-canary-restored";
finish:
    if (write_fd >= 0) close(write_fd); if (read_fd >= 0) close(read_fd);
    int okay = attempted && inserted && removed && restored && host_restored && !pending && !interrupted && !strcmp(failure_reason, "empty-root-canary-restored");
    canary_report("canary", okay, failure_reason, attempted, inserted, removed, restored, host_restored, pending, &before, &after, &host_before, &host_after); return okay ? 0 : 1;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int request_canary(void) {
    if (geteuid() == 0 || !pinned_host()) { canary_report("requestCanary", 0, "unprivileged-pinned-request-required", 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); return 1; }
    char unresolved[PATH_MAX], executable[PATH_MAX]; uint32_t size = sizeof(unresolved);
    if (_NSGetExecutablePath(unresolved, &size) || !realpath(unresolved, executable)) return 1;
    AuthorizationRef reference = NULL; AuthorizationItem item = { kAuthorizationRightExecute, 0, NULL, 0 }; AuthorizationRights rights = {1, &item};
    const char prompt[] = "Envara EXPERIMENT: append ONE EMPTY owned PF root-anchor call while PF is already disabled, read it back and delete its exact ticket. No PF start, application, tunnel or group. Unverified write ABI: an empty owned entry may remain if cleanup fails. This requires separate explicit approval.";
    AuthorizationItem prompt_item = { kAuthorizationEnvironmentPrompt, sizeof(prompt)-1, (void *)prompt, 0 }; AuthorizationEnvironment environment = {1, &prompt_item};
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &reference);
    if (status == errAuthorizationSuccess) status = AuthorizationCopyRights(reference, &rights, &environment, kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    FILE *communications = NULL; char *arguments[] = { "--canary", NULL };
    if (status == errAuthorizationSuccess) status = AuthorizationExecuteWithPrivileges(reference, executable, kAuthorizationFlagDefaults, arguments, &communications);
    if (status != errAuthorizationSuccess || !communications) { if (reference) AuthorizationFree(reference, kAuthorizationFlagDestroyRights);
        canary_report("requestCanary", 0, status == errAuthorizationCanceled ? "authorization-canceled" : "authorization-unavailable", 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); return 1; }
    int fd = fileno(communications); fcntl(fd, F_SETFL, O_NONBLOCK); char output[32768]; size_t length = 0; int complete = 0; double deadline = seconds() + 120;
    while (seconds() < deadline && length < sizeof(output)-1) { struct pollfd wait = {fd, POLLIN | POLLHUP, 0}; int observed = poll(&wait, 1, 200);
        if (observed < 0 && errno == EINTR) continue; if (observed < 0) break; if (!observed) continue;
        ssize_t count = read(fd, output + length, sizeof(output)-1-length); if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count < 0) break; if (!count) { complete = 1; break; } length += (size_t)count; }
    fclose(communications); AuthorizationFree(reference, kAuthorizationFlagDestroyRights); output[length] = 0;
    if (!complete || !length) { canary_report("requestCanary", 0, "root-completion-unconfirmed-check-empty-owned-entry", 1, 0, 0, 0, 0, 1, NULL, NULL, NULL, NULL); return 1; }
    fwrite(output, 1, length, stdout); return strstr(output, "\"schema\":\"" CANARY_SCHEMA "\"") && strstr(output, "\"ok\":true") ? 0 : 1;
}
#pragma clang diagnostic pop
#ifdef CANARY_TEST_MAIN
#define main CANARY_TEST_MAIN
#endif
int main(int argc, char **argv) {
    if (argc > 2) { canary_report("plan", 0, "invalid-fixed-operation", 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); return 1; }
    const char *mode = argc == 1 ? "--plan" : argv[1];
    if (!strcmp(mode, "--request-canary")) return request_canary();
    if (!strcmp(mode, "--canary")) return run_canary();
    int okay = !strcmp(mode, "--plan");
    canary_report("plan", okay, okay ? "candidate-only-no-authorization-or-PF-open" : "invalid-fixed-operation", 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL); return okay ? 0 : 1;
}
