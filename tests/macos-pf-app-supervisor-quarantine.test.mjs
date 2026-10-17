import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

const exec = promisify(execFile), root = path.resolve(import.meta.dirname, '..');
const native = path.join(root, 'native/macos-pf-routing');
const fixedOldSHA = 'c29c1636eba730cca09f6bc596659a04818e98a8a9b4708d6fcc48cfea6cedf5';
const helper = `static void quarantine_refusal_delay(void) {
    struct timespec delay = {0, 50000000};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
}
`;
/* The later staging validation scope and diagnostic step marks are removed
 * first, so the reconstruction is still exactly the frozen 14b87 source. */
const stagingScope = [
  ['    int output, prepared, output_failed, stopped_before_exec, validation_scope_open;\n', '    int output, prepared, output_failed, stopped_before_exec;\n'],
  [`/* Staging, from claim to the exact stopped child, is one native operation.
 * Custody is not: the guardian holds the child for the run's whole lifetime,
 * and resume re-verifies in its own operation. */
static void staging_scope_end(struct keeper *k) {
    if (k->validation_scope_open) { envara_gui_validation_scope_end(); k->validation_scope_open = 0; }
}
`, ''],
  ['    struct keeper *k = context; staging_scope_end(k);\n    k->ticket = *ticket;', '    struct keeper *k = context; k->ticket = *ticket;'],
  ['    envara_gui_step(ENVARA_GUI_STEP_TICKET_CLAIM);\n', ''],
  ['    envara_gui_step(ENVARA_GUI_STEP_STAGE_FRESH);\n', ''],
  ['    envara_gui_step(ENVARA_GUI_STEP_STAGE_ADOPT);\n', ''],
  [`    /* Its first check of each bundle is a full signed inspection; later
     * staging boundaries re-prove that exact state's identity. adopt ends it. */
    if (!envara_gui_validation_scope_begin()) { result = -1; errno = EOVERFLOW; goto done; }
    k.validation_scope_open = 1;
`, ''],
  ['done:\n    { int saved = errno; staging_scope_end(&k); errno = saved; }\n', 'done:\n'],
];
function withoutStagingScope(current) {
  let source = current;
  for (const [added, original] of stagingScope) {
    assert.equal(source.split(added).length, 2, 'each later staging edit appears exactly once');
    source = source.replace(added, original);
  }
  return source;
}
const networkPatches = [
  [
    "#include \"app-family.h\"\n",
    ""
  ],
  [
    "    envara_app_family *family;\n",
    ""
  ],
  [
    "!k->authority.verify_scope_quiescent || !k->authority.revoke_owned_network ||",
    "!k->authority.verify_scope_quiescent ||"
  ],
  [
    "static int revoke_network(void *context) {\n    struct keeper *k = context;\n    return k->authority.revoke_owned_network && k->authority.revoke_owned_network(k->authority.context) == 1;\n}\n",
    ""
  ],
  [
    "static int emit_cleanup_pending(struct keeper *k, const struct envara_launch_guard_report *report) {\n    const struct envara_app_ticket *t = &k->ticket; struct envara_identity own;\n    if (envara_identity_read(getpid(), &own)) return reject(ESTALE);\n    const char *profile = t->app.fixture_only ? \"fixture\" :\n        k->provider->execution_profile == ENVARA_APP_EXECUTION_NOTION_FRONT_ONLY ? \"seatbelt-front-only\" : \"cold\";\n    int stopped = report->child_reaped && scope(k);\n    const char *family_failure = envara_app_family_failure_name(report->family_failure.reason);\n    if (!family_failure || report->family_failure.os_error < 0 || report->family_failure.os_error > 1024 ||\n        (report->family_failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE ?\n            report->family_failure.os_error != 0 || report->family_failure.mach_error != 0 : report->family_failure.os_error == 0))\n        return reject(EINVAL);\n    char bytes[1536]; int length = snprintf(bytes, sizeof(bytes),\n        \"{\\\"schema\\\":\\\"%s\\\",\\\"event\\\":\\\"cleanup-pending\\\",\\\"ticketId\\\":\\\"%s\\\",\\\"registrationId\\\":\\\"%s\\\",\\\"versionId\\\":\\\"%s\\\",\"\n        \"\\\"environmentId\\\":\\\"%s\\\",\\\"runId\\\":\\\"%s\\\",\\\"pid\\\":%d,\\\"birth\\\":\\\"%llu:%06llu\\\",\\\"keeperPID\\\":%d,\"\n        \"\\\"keeperBirth\\\":\\\"%llu:%06llu\\\",\\\"profile\\\":\\\"%s\\\",\\\"cleanupAttempt\\\":%u,\\\"launchAuthorityBurned\\\":true,\\\"custodyHeld\\\":true,\"\n        \"\\\"denyVerified\\\":%s,\\\"frontClosedVerified\\\":%s,\\\"familyStoppedVerified\\\":%s,\\\"familyFailureReason\\\":\\\"%s\\\",\\\"familyFailureErrno\\\":%d,\\\"familyFailureMach\\\":%d,\\\"ready\\\":false,\\\"protected\\\":false}\\n\",\n        ENVARA_APP_KEEPER_PROTOCOL, t->ticket_id, t->app.registration_id, t->app.version_id,\n        t->environment_id, t->run_id, k->child->child.identity.pid,\n        (unsigned long long)k->child->child.identity.birth_seconds, (unsigned long long)k->child->child.identity.birth_microseconds,\n        getpid(), (unsigned long long)own.birth_seconds, (unsigned long long)own.birth_microseconds, profile, report->cleanup_attempt,\n        report->network_revoked && report->persistent_deny_observed ? \"true\" : \"false\", report->network_revoked ? \"true\" : \"false\", stopped ? \"true\" : \"false\", family_failure,\n        report->family_failure.os_error, report->family_failure.mach_error);\n    if (length <= 0 || length >= (int)sizeof(bytes)) return reject(EOVERFLOW);\n    ssize_t count; do { count = write(k->output, bytes, (size_t)length); } while (count < 0 && errno == EINTR);\n    return count == length ? 0 : reject(count < 0 ? errno : EIO);\n}\n",
    ""
  ],
  [
    "    } else if (event == ENVARA_GUARD_CLEANUP_PENDING) {\n        k->stopped_before_exec = 0;\n        if (emit_cleanup_pending(k, report)) k->output_failed = 1;\n",
    ""
  ],
  [
    "static int quarantine(struct keeper *k) {\n    /* Arming can fail after fork. Never exit and drop the original utun socket\n     * merely because a dependent birth/FD changed. Exact child cancel is once;\n     * fixed native denial and complete scope proof are still required. */\n    k->report->recovery_required = 1;\n    /* Only the guardian's positive direct-child wait result permits this\n     * already-terminal entry. ECHILD/unavailable identity is never promoted. */\n    int prior_reaped = k->report->guardian.child_reaped && k->child->leader_reaped;\n    /* Pre-arm refusal obeys the same order as a running guardian. Never cancel\n     * the application before fresh DENY plus original frontend shutdown. */\n    k->report->guardian.network_revoked = revoke_network(k);\n    if (!k->family && !prior_reaped) {\n        struct envara_app_family_failure failure;\n        k->family = envara_app_family_create_diagnosed(&k->child->child.identity, &failure);\n        if (k->report->guardian.family_failure.reason == ENVARA_APP_FAMILY_FAILURE_NONE)\n            k->report->guardian.family_failure = failure;\n    }\n    if (prior_reaped) k->report->guardian.family_stop_confirmed = 1;\n    if (k->report->guardian.network_revoked && k->family) {\n        int sent = 0;\n        k->report->guardian.family_stop_confirmed = envara_app_family_stop(k->family, &sent);\n        k->report->guardian.child_signal_sent |= sent;\n    }\n    for (;;) {\n        if (!k->child->leader_reaped) { int status; (void)envara_gui_poll(k->child, &status); }\n        struct pollfd item = {k->guard.recovery_fd, POLLIN, 0};\n        int result = poll(&item, 1, 50); (void)quarantine_signal;\n        if (result <= 0 || !(item.revents & POLLIN)) {\n            if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { quarantine_refusal_delay(); }\n            continue;\n        }\n        char command[32]; ssize_t amount = read(item.fd, command, sizeof(command));\n        if (amount <= 0) { quarantine_refusal_delay(); continue; }\n        for (ssize_t i = 0; i < amount; i++) if (command[i] == 'R') {\n            if (!k->report->guardian.network_revoked) k->report->guardian.network_revoked = revoke_network(k);\n            if (k->report->guardian.network_revoked && k->family && !k->report->guardian.family_stop_confirmed) {\n                int sent = 0; k->report->guardian.family_stop_confirmed = envara_app_family_stop(k->family, &sent);\n                k->report->guardian.child_signal_sent |= sent;\n            }\n            if (!k->report->guardian.network_revoked || !k->report->guardian.family_stop_confirmed ||\n                (!prior_reaped && (!k->family || !envara_app_family_quiescent(k->family))) ||\n                !k->child->leader_reaped || !deny(k) || !scope(k)) continue;\n            struct envara_launch_guard_report report = k->report->guardian;\n            report.child_reaped = report.persistent_deny_observed = report.scope_quiescent_observed = 1;\n            report.owns_retained_fd = 0;\n            k->child->scope_quiescent = 1;\n            observe(ENVARA_GUARD_RELEASED, &report, k);\n            k->report->recovery_required = 0; return 0;\n        }\n        quarantine_refusal_delay();\n    }\n}\n",
    "static int quarantine(struct keeper *k) {\n    /* Arming can fail after fork. Never exit and drop the original utun socket\n     * merely because a dependent birth/FD changed. Exact child cancel is once;\n     * fixed native denial and complete scope proof are still required. */\n    k->report->recovery_required = 1;\n    (void)envara_gui_cancel(k->child);\n    for (;;) {\n        if (!k->child->leader_reaped) { int status; (void)envara_gui_poll(k->child, &status); }\n        struct pollfd item = {k->guard.recovery_fd, POLLIN, 0};\n        int result = poll(&item, 1, 50); (void)quarantine_signal;\n        if (result <= 0 || !(item.revents & POLLIN)) {\n            if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { quarantine_refusal_delay(); }\n            continue;\n        }\n        char command[32]; ssize_t amount = read(item.fd, command, sizeof(command));\n        if (amount <= 0) { quarantine_refusal_delay(); continue; }\n        for (ssize_t i = 0; i < amount; i++) if (command[i] == 'R' && k->child->leader_reaped && deny(k) && scope(k)) {\n            struct envara_launch_guard_report report = k->report->guardian;\n            report.child_reaped = report.persistent_deny_observed = report.scope_quiescent_observed = 1;\n            report.owns_retained_fd = 0;\n            k->child->scope_quiescent = 1;\n            observe(ENVARA_GUARD_RELEASED, &report, k);\n            k->report->recovery_required = 0; return 0;\n        }\n        quarantine_refusal_delay();\n    }\n}\n"
  ],
  [
    "    struct envara_launch_guard_authority authority = {.verify_persistent_deny = deny, .verify_scope_quiescent = scope,\n        .observe = observe, .context = k, .revoke_owned_network = revoke_network};",
    "    struct envara_launch_guard_authority authority = {deny, scope, observe, k};"
  ],
  [
    "    envara_app_family_destroy(k.family);\n",
    ""
  ]
];
function withoutNetworkRevocation(current) {
  let source = current;
  for (const [added, original] of networkPatches) {
    assert.equal(source.split(added).length, 2, "each network revocation edit appears once");
    source = source.replace(added, original);
  }
  return source;
}
function frozenOldSource(current) {
  // Strip this later, separate preparation path before reconstructing the
  // same immutable application-quarantine baseline. Never update its hash.
  const begin = current.indexOf('/* Preparation quarantine is deliberately separate from application custody.');
  const end = current.indexOf('static int adopt(', begin);
  assert.ok(begin > 0 && end > begin);
  let original = current.slice(0, begin) + current.slice(end);
  for (const addition of [
    '#include <limits.h>\n',
    '    struct envara_identity own;\n',
    '    if (k->provider->preparation && envara_identity_read(getpid(),&k->own)) return reject(ESTALE);\n',
    '    if (envara_app_keychain_custody_pending(k->provider->preparation,&k->ticket.app,&k->ticket.request,k->ticket.run_id) != 0)\n        return preparation_quarantine(k,error);\n',
  ]) {
    assert.equal(original.split(addition).length, 2, 'each later preparation edit appears once');
    original = original.replace(addition, '');
  }
  return withoutStagingScope(withoutNetworkRevocation(original)).replace(helper, '').replace('if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { quarantine_refusal_delay(); }',
    'if (result < 0 || (item.revents & (POLLHUP | POLLERR | POLLNVAL))) { struct timespec delay = {0, 50000000}; nanosleep(&delay, NULL); }')
    .replace('if (amount <= 0) { quarantine_refusal_delay(); continue; }', 'if (amount <= 0) continue;')
    .replace('        quarantine_refusal_delay();\n    }\n}\nstatic int adopt', '    }\n}\nstatic int adopt');
}

test('actual quarantine EOF/error paths stay alive with custody and bounded CPU; fixed 14b87 path reproduces the spin',
  { skip: process.platform !== 'darwin' }, async () => {
    assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid());
    const directory = await mkdtemp(path.join(tmpdir(), 'envara-quarantine-refusal-fixture-'));
    try {
      const current = await readFile(path.join(native, 'app-supervisor.c'), 'utf8');
      const old = frozenOldSource(current);
      assert.equal(createHash('sha256').update(old).digest('hex'), fixedOldSHA,
        'baseline is the actual immutable 14b87 supervisor, not a mirrored implementation');
      const baseline = path.join(directory, 'frozen-14b87-app-supervisor.c'); await writeFile(baseline, old, { mode: 0o600 });
      const common = ['app-control.c', 'app-ticket.c', 'app-registry.c', 'gui-launch.m', 'launcher.c', 'launch-guardian.c', 'app-keychain.m', 'app-scope-proof.c'];
      const inputs = ['app-supervisor.c', 'app-supervisor.h', 'app-supervisor-quarantine-fixture.c', 'app-family.h', 'app-family.c', ...common];
      const hashes = async () => Promise.all(inputs.map(async name => [name,
        createHash('sha256').update(await readFile(path.join(native, name))).digest('hex')]));
      const before = await hashes();
      for (const [name, source] of [['old', baseline], ['fixed', path.join(native, 'app-supervisor.c')]]) {
        const binary = path.join(directory, name);
        await exec('/usr/bin/clang', ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', ...(name === 'old' ? ['-Wno-missing-field-initializers'] : []),
          '-I', native, ...(name === 'old' ? ['-DENVARA_QUARANTINE_LEGACY=1'] : []), `-DENVARA_QUARANTINE_SOURCE=${JSON.stringify(source)}`,
          path.join(native, 'app-supervisor-quarantine-fixture.c'), ...common.map(n => path.join(native, n)),
          '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-o', binary],
        { timeout: 30000, maxBuffer: 1024 * 1024 });
        const reports = [];
        for (const mode of name === 'old' ? [1] : [1, 2, 3, 4, 5, 6, 7]) {
          const reply = await exec(binary, [String(mode)], { timeout: 5000 });
          const report = JSON.parse(reply.stdout); reports.push(report);
          assert.equal(report.ready, false); assert.equal(report.protected, false);
          if (mode >= 6) {
            assert.equal(report.positivePriorReapReleased, mode === 6);
            assert.equal(report.unknownPriorReapHeld, mode === 7);
          } else if (mode === 4) {
            assert.equal(report.heldUntilAuthorizedR, true); assert.equal(report.actualChildReaped, true);
          } else {
            assert.equal(report.heldBeforeOwnFixtureCancellation, true); assert.equal(report.released, false);
            assert.ok(report.elapsedSeconds >= 0.6);
            if (name === 'old') {
              assert.equal(report.actualEOFEvents, 17, 'actual Darwin pipe emits POLLIN | POLLHUP');
              assert.ok(report.reads > 1000, JSON.stringify(report));
              assert.ok(report.cpuSeconds > 0.15, JSON.stringify(report));
            } else {
              assert.ok(report.reads > 0 && report.reads <= 20, JSON.stringify(report));
              assert.ok(report.polls <= 20, JSON.stringify(report));
              assert.ok(report.cpuSeconds < 0.12, JSON.stringify(report));
            }
          }
        }
        console.log(`${name} quarantine observations: ${JSON.stringify(reports)}`);
      }
      assert.deepEqual(await hashes(), before, 'all actual compiled inputs remain unchanged');
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
