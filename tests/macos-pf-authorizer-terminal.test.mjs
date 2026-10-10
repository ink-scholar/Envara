import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { createPersistentPFHelperClient } from '../scripts/accept-macos-pf-routing.mjs';

const exec = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/authorize-install.c', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
const runId = 'ad2354a0-6d8e-458a-b09e-d175bfc585c3';
const terminalFrame = {
  protocol: 'envara.application-routing', version: 1, id: null,
  terminal: true, cleanupUncertain: true,
  error: { code: 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', message: 'Root helper cleanup could not be confirmed' },
};
let directory, binary;

// This harness invokes only the real guardian and byte relay on ordinary-user
// children, temporary directory locks and anonymous Unix sockets. It never
// invokes Security authorization, the installer, root operations or PF.
const harness = String.raw`
#define _DARWIN_C_SOURCE
#include <sys/wait.h>
#include <sys/types.h>
static pid_t fixture_waitpid(pid_t, int *, int);
#define waitpid fixture_waitpid
#define main envara_installer_entry
#include AUTHORIZE_SOURCE
#undef main
#undef waitpid
static int inject_wait_error;
static pid_t fixture_waitpid(pid_t child, int *status, int flags) {
    if (inject_wait_error) { inject_wait_error = 0; errno = ECHILD; return -1; }
    return waitpid(child, status, flags);
}
typedef struct { const char *mode; } ChildFixture;
static void fixture_reply(const char *id, bool complete) {
    printf("{\"protocol\":\"envara.application-routing\",\"version\":1,\"id\":\"%s\",\"result\":{"
           "\"runId\":\"ad2354a0-6d8e-458a-b09e-d175bfc585c3\",\"acceptanceProtocol\":\"envara-pf-acceptance/v1\","
           "\"acceptanceOnly\":true,\"ready\":false,\"productionReceiptAllowed\":false,\"cleanupUncertain\":false,"
           "\"evidence\":{\"source\":\"native-pf\",\"platform\":\"darwin\",\"complete\":true,\"cleanupUncertain\":false,"
           "\"ownedProcessesExited\":true,\"ownedTunnelsRemoved\":true,\"ownedAnchorRemoved\":true,"
           "\"unrelatedPFUnchanged\":true,\"unrelatedRoutesUnchanged\":true,\"hostDNSUnchanged\":%s,"
           "\"noOwnedStatesCreatedVerified\":true,\"noOwnedStatesRemainVerified\":true,\"ownedRootHookRemoved\":true,"
           "\"originalRootRestored\":true,\"ownedPFReferenceReleased\":true}}}\n", id, complete ? "true" : "false");
    fflush(stdout);
}
static void fixture_helper(void *value) {
    const char *mode = ((ChildFixture *)value)->mode;
    if (!strcmp(mode, "exit-one")) _exit(1);
    if (!strcmp(mode, "exit-seven")) _exit(7);
    if (!strcmp(mode, "signal-term")) { raise(SIGTERM); _exit(91); }
    if (!strcmp(mode, "signal-kill")) { raise(SIGKILL); _exit(91); }
    if (!strcmp(mode, "entry-return")) return;
    if (!strcmp(mode, "zero") || !strcmp(mode, "wait-error")) _exit(0);
    char *line = NULL; size_t capacity = 0;
    while (getline(&line, &capacity, stdin) >= 0) {
        const char *start = strstr(line, "\"id\":\""); if (!start) _exit(92);
        start += 6; const char *end = strchr(start, '"');
        if (!end || end == start || end - start >= 129) _exit(93);
        char id[129]; memcpy(id, start, (size_t)(end - start)); id[end - start] = 0;
        for (const char *p = id; *p; p++) if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) _exit(94);
        fixture_reply(id, strcmp(mode, "rpc-missing-evidence") != 0);
    }
    free(line);
    if (!strcmp(mode, "rpc-signal-term")) { raise(SIGTERM); _exit(95); }
    if (!strcmp(mode, "rpc-partial-exit-one")) { fputs("{\"incomplete\":", stdout); fflush(stdout); }
    _exit(!strcmp(mode, "rpc-zero") || !strcmp(mode, "rpc-missing-evidence") ? 0 : 1);
}
static int fixture_guard(const char *mode, const char *lease_path) {
    int lease = open(lease_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) return 96;
    inject_wait_error = !strcmp(mode, "wait-error");
    ChildFixture context = { mode };
    int result = guard_owned_helper(lease, fixture_helper, &context);
    int check = open(lease_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (check < 0 || flock(check, LOCK_EX | LOCK_NB)) { if (check >= 0) close(check); return 97; }
    close(check); return result;
}
int main(int argc, char **argv) {
    if (argc != 3 || getuid() == 0 || geteuid() == 0) return 98;
    if (strncmp(argv[1], "relay-", 6)) return fixture_guard(argv[1], argv[2]);
    int channel[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel)) return 99;
    pid_t root_fixture = fork(); if (root_fixture < 0) return 100;
    if (!root_fixture) {
        close(channel[0]);
        if (dup2(channel[1], STDIN_FILENO) < 0 || dup2(channel[1], STDOUT_FILENO) < 0) _exit(101);
        close(channel[1]); _exit(fixture_guard(argv[1] + 6, argv[2]));
    }
    close(channel[1]);
    bool okay = relay_helper(channel[0], 8.0); close(channel[0]);
    int child_status; if (waitpid(root_fixture, &child_status, 0) != root_fixture) return 102;
    // As with Security's outer relay, socket EOF can be transport success
    // even when the guardian's child failed. No cleanup claim is made here.
    return okay ? 0 : 1;
}
`;

before(async () => {
  if (process.platform !== 'darwin') return;
  directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-terminal-inert-')));
  await writeFile(path.join(directory, 'installer-manifest.h'),
    `#define ENVARA_PF_INSTALL_SOURCE ${JSON.stringify(directory)}\n` +
    '#define ENVARA_PF_INSTALL_MANIFEST_SHA256 "' + '0'.repeat(64) + '"\n' +
    'typedef struct {const char *name;const char *sha256;unsigned int mode;} EnvaraPFInstallFile;\n' +
    'static const EnvaraPFInstallFile ENVARA_PF_INSTALL_FILES[]={{"EnvaraPFHelper","' + '0'.repeat(64) + '",0755}};\n' +
    '#define ENVARA_PF_INSTALL_FILE_COUNT 1\n');
  const fixture = path.join(directory, 'terminal-fixture.c');
  await writeFile(fixture, harness.replace('AUTHORIZE_SOURCE', JSON.stringify(source)));
  binary = path.join(directory, 'terminal-fixture');
  const compiled = await exec('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', directory,
    fixture, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
  assert.equal(compiled.stderr, '');
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

async function run(mode) {
  try { return { code: 0, ...await exec(binary, [mode, directory], { timeout: 12000, maxBuffer: 65536 }) }; }
  catch (error) {
    assert.equal(typeof error.code, 'number', 'inert guardian must exit normally');
    assert.equal(error.signal ?? null, null);
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

test('nonzero root child exits emit a single fixed terminal refusal with no raw exit data', onlyMac, async () => {
  for (const [mode, code] of [['exit-one', 1], ['exit-seven', 7], ['entry-return', 1]]) {
    const result = await run(mode);
    assert.equal(result.code, code); assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), terminalFrame);
    assert.equal(result.stdout.split('\n').filter(Boolean).length, 1);
    assert.equal(Object.hasOwn(JSON.parse(result.stdout), 'result'), false);
  }
});

test('signaled children and unknown wait results explicitly remain unconfirmed', onlyMac, async () => {
  for (const mode of ['signal-term', 'signal-kill', 'wait-error']) {
    const result = await run(mode);
    assert.equal(result.code, mode === 'wait-error' ? 0 : 1);
    assert.equal(result.stderr, ''); assert.deepEqual(JSON.parse(result.stdout), terminalFrame);
    assert.equal(result.stdout.split('\n').filter(Boolean).length, 1, 'unknown wait emits once, even after later successful wait');
  }
});

test('zero child exit produces no independent positive cleanup assertion', onlyMac, async () => {
  const result = await run('zero');
  assert.equal(result.code, 0); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});

test('the real byte relay preserves terminal refusal even while its outer EOF exits zero', onlyMac, async () => {
  const result = await run('relay-exit-one');
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), terminalFrame);
});

async function cleanedClient(mode) {
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(binary, [`relay-${mode}`, directory], {
    stdio: ['pipe', 'pipe', 'pipe'],
  }) });
  try {
    await call('prepareOwnedFixtures', { runId, privateFixtureMarker: 'must-not-appear-in-terminal-frame' });
    await call('cleanupOwnedFixtures', { runId });
    return { beforeClose: call.snapshot(), afterClose: await call.close({ timeoutMs: 5000 }), snapshot: call.snapshot() };
  } finally { await call.close({ timeoutMs: 5000 }); }
}

test('terminal child faults latch uncertainty after complete run-bound inert cleanup receipts', onlyMac, async () => {
  for (const mode of ['rpc-exit-one', 'rpc-signal-term', 'rpc-partial-exit-one']) {
    const result = await cleanedClient(mode);
    assert.equal(result.beforeClose.cleanupUncertain, false, 'the inert receipt satisfies all 11 cleanup evidence gates');
    assert.equal(result.afterClose.closed, true); assert.equal(result.afterClose.cleanupUncertain, true);
    assert.equal(result.snapshot.cleanupUncertain, true);
  }
});

test('normal zero close requires complete evidence; one missing gate remains uncertain', onlyMac, async () => {
  const clean = await cleanedClient('rpc-zero');
  assert.equal(clean.afterClose.closed, true); assert.equal(clean.afterClose.cleanupUncertain, false);
  const missing = await cleanedClient('rpc-missing-evidence');
  assert.equal(missing.beforeClose.cleanupUncertain, true);
  assert.equal(missing.afterClose.closed, true); assert.equal(missing.afterClose.cleanupUncertain, true);
});
