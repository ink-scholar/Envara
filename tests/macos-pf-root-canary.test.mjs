import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-root-canary.c', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
async function fixture(callback, harness) {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-canary-test-')));
  try {
    const input = harness ? path.join(directory, 'fixture.c') : source;
    if (harness) await writeFile(input, harness.replace('CANARY_SOURCE', JSON.stringify(source)));
    const binary = path.join(directory, 'canary');
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', input, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return await callback(binary);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
async function result(binary, args) {
  try { return { code: 0, value: JSON.parse((await execute(binary, args, { timeout: 15000 })).stdout) }; }
  catch (error) { assert.equal(typeof error.code, 'number'); return { code: error.code, value: JSON.parse(error.stdout) }; }
}
test('native plan is an inert, explicitly unverified one-empty-entry candidate', onlyMac, async () => {
  await fixture(async binary => {
    for (const args of [[], ['--plan']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 0); assert.equal(value.readOnly, true); assert.equal(value.authorizationRequested, false);
      assert.equal(value.deviceOpened, false);
      assert.equal(value.requiresSeparateApproval, true); assert.equal(value.insertAttempted, false);
      assert.equal(value.anchor, 'io.envara.pf.root.v1'); assert.equal(value.owner, value.anchor);
      assert.equal(value.label, 'envara.empty.v1.<32-random-hex>'); assert.equal(value.issuedTicket, '0');
      assert.equal(value.requiresPFAlreadyDisabled, true); assert.equal(value.priority, 4294967295); assert.equal(value.keepState, 0);
      assert.equal(value.productionReady, false); assert.equal(value.mutationSupportVerified, false);
      assert.ok(Object.values(value.gates).every(gate => gate === false));
      assert.ok(Object.values(value.operations).every(operation => operation === false));
    }
  });
});
test('native parser rejects arbitrary operations and unauthorized canary without prompting', onlyMac, async () => {
  await fixture(async binary => {
    for (const args of [['--activate'], ['--request-canary', '/untrusted'], ['--canary', 'write']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 1); assert.equal(value.reason, 'invalid-fixed-operation'); assert.equal(value.insertAttempted, false);
    }
    if (process.getuid() !== 0) {
      const { code, value } = await result(binary, ['--canary']);
      assert.equal(code, 1); assert.equal(value.reason, 'privileged-reference-required'); assert.equal(value.insertAttempted, false);
    }
  });
});
test('native mutation allowlist refuses owner bulk deletion, foreign ownership, state and unknown operations', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
static unsigned int observed;
static int inert_ioctl(int descriptor, unsigned long operation, ...) {
    (void)descriptor; (void)operation; observed++; return 0;
}
#define ioctl inert_ioctl
#define CANARY_TEST_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
#undef ioctl
int main(void) {
    const char *label = CANARY_LABEL_PREFIX "00112233445566778899aabbccddeeff";
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC); if (fd < 0) return 1;
    InspectorRequest request = new_call(label);
    if (fixed_write(fd, CANARY_INSERT, &request, label) || observed != 1) return 2;
    if (fixed_write(fd, CANARY_DELETE, &request, label) != -1 || observed != 1) return 3;
    request.rule.ticket = UINT64_C(0x1122334455667788);
    if (fixed_write(fd, CANARY_DELETE, &request, label) || observed != 2) return 4;
    if (fixed_write(fd, CANARY_INSERT, &request, label) != -1 || observed != 2) return 5;
    if (fixed_write(fd, 1234, &request, label) != -1 || observed != 2) return 6;
    strcpy(request.rule.owner, "foreign");
    if (fixed_write(fd, CANARY_DELETE, &request, label) != -1 || observed != 2) return 7;
    strcpy(request.rule.owner, CANARY_OWNER); request.rule.keep_state = 1;
    if (fixed_write(fd, CANARY_DELETE, &request, label) != -1 || observed != 2) return 8;
    request.rule.keep_state = 0; request.rule.label[20] = 'f';
    if (fixed_write(fd, CANARY_DELETE, &request, label) != -1 || observed != 2) return 9;
    request = new_call(label); request.rule.ticket = 1; memset(request.rule.owner, 'x', sizeof(request.rule.owner));
    if (fixed_write(fd, CANARY_DELETE, &request, label) != -1 || observed != 2) return 11;
    close(fd); char first[64], second[64];
    if (!generate_label(first) || !generate_label(second) || !strcmp(first, second)) return 10;
    return 0;
}`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native preservation normalizes only documented derived fields and ruleset revision', onlyMac, async () => {
  const harness = `
#define CANARY_TEST_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
int main(void) {
    RootSnapshot before = {0}, during = {0}; before.count = 7;
    for (uint32_t i = 0; i < 7; i++) { snprintf(before.rows[i].anchor_call, 1024, "original-%u", i); before.rows[i].rule.nr = i; before.rows[i].nr = i; before.rows[i].rule.ticket = i + 10; }
    snapshot_digest(&before); during = before; during.count = 8;
    during.rows[0].rule.skip[0] = 1; during.rows[0].rule.evaluations = 7; during.rows[0].rule.packets[1] = 8; during.rows[0].rule.bytes[0] = 9;
    during.rows[0].ticket = 10;
    if (!originals_preserved(&before, &during)) return 1;
    RootSnapshot normalized = during; normalized.count = 7; snapshot_digest(&normalized);
    if (strcmp(before.canonical, normalized.canonical)) return 2;
    during.rows[0].rule.ticket++;
    if (originals_preserved(&before, &during)) return 3;
    during = before; during.count = 8; during.rows[0].rule.owner[0] = 'x'; if (originals_preserved(&before, &during)) return 4;
    during = before; during.count = 8; during.rows[0].rule.label[0] = 'x'; if (originals_preserved(&before, &during)) return 5;
    during = before; during.count = 8; during.rows[0].rule.priority = 1; if (originals_preserved(&before, &during)) return 6;
    during = before; during.count = 8; during.rows[0].rule.src[0] = 1; if (originals_preserved(&before, &during)) return 7;
    during = before; during.count = 8; during.rows[0].rule.opaque272[0] = 1; if (originals_preserved(&before, &during)) return 8;
    during = before; during.count = 8; during.rows[0].rule.nr = 1; if (originals_preserved(&before, &during)) return 9;
    return 0;
}`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('native exchange fault harness never adopts a foreign ticket and always attempts exact known cleanup', onlyMac, async () => {
  const harness = `
#define CANARY_TEST_MAIN canary_program_main
#include CANARY_SOURCE
#undef main
static unsigned int scenario, deleted;
static int removed, snapshots;
static RootSnapshot baseline;
static InspectorRequest actual;
static int stub_write(int fd, unsigned long op, InspectorRequest *r, const char *label) {
    (void)fd;
    if (op == CANARY_INSERT) {
        actual = *r; actual.rule.ticket = UINT64_C(0x1122334455667788);
        if (scenario != 1) r->rule.ticket = actual.rule.ticket;
        if (scenario == 2) actual.rule.ticket++;
        if (scenario == 3) interruption(SIGTERM);
        if (scenario == 6) strcpy(actual.rule.label, CANARY_LABEL_PREFIX "ffeeddccbbaa99887766554433221100");
        return scenario == 1 || scenario == 7 ? -1 : 0;
    }
    if (op != CANARY_DELETE || !own_call(r, label) || !r->rule.ticket || r->rule.ticket != issued_ticket) return -1;
    deleted++; if (scenario == 4) return -1; removed = 1; return 0;
}
static int stub_snapshot(int fd, RootSnapshot *s, int compare) {
    (void)fd; (void)compare; snapshots++;
    if (scenario == 9) return 0;
    if (scenario == 8 && !removed && snapshots < 2) return 0;
    *s = baseline;
    if (!removed) { s->count = scenario == 5 ? 9 : 8; s->rows[7] = actual; s->rows[7].nr = s->rows[7].rule.nr = 7; if (scenario == 5) strcpy(s->rows[8].anchor_call, "foreign-extra"); }
    else if (scenario == 5) { s->count = 8; strcpy(s->rows[7].anchor_call, "foreign-extra"); s->rows[7].nr = s->rows[7].rule.nr = 7; }
    snapshot_digest(s); return 1;
}
static int stub_empty(int fd) { (void)fd; return 1; }
static int stub_absent(int fd) { (void)fd; return removed; }
static int stub_text(const RootSnapshot *s) { (void)s; return 1; }
static double stub_clock(void) { return scenario == 10 && snapshots ? 17 : 0; }
int main(void) {
    const char *label = CANARY_LABEL_PREFIX "00112233445566778899aabbccddeeff";
    baseline.count = 7; strcpy(baseline.text, "bounded-original-text");
    for (uint32_t i = 0; i < 7; i++) { snprintf(baseline.rows[i].anchor_call, 1024, "original-%u", i); baseline.rows[i].nr = baseline.rows[i].rule.nr = i; }
    snapshot_digest(&baseline); const CanaryIO io = { stub_write, stub_snapshot, stub_empty, stub_absent, stub_text, stub_clock };
    for (scenario = 0; scenario < 11; scenario++) {
        deleted = 0; removed = 0; snapshots = 0; interrupted = 0; issued_ticket = 0; RootSnapshot after = {0};
        CanaryOutcome r = exchange_canary(-1, -1, &baseline, &after, label, &io);
        if (scenario == 1 || scenario == 2 || scenario == 6 || scenario == 9) { if (deleted || !r.pending || r.inserted) return 10 + scenario; }
        else if (scenario == 4) { if (deleted != 1 || !r.pending || r.removed) return 20 + scenario; }
        else if (scenario == 5) { if (deleted != 1 || r.pending || !r.removed || r.restored) return 25; }
        else { if (deleted != 1 || r.pending || !r.removed || !r.restored) return 30 + scenario; }
        if (scenario == 3 && interrupted != SIGTERM) return 43;
        if ((scenario == 5 || scenario == 7) && r.inserted) return 50 + scenario;
        if (scenario == 10 && !r.deadline_exceeded) return 60;
    }
    return 0;
}`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('source keeps the experiment separate from installed routing and other PF operations', async () => {
  const text = await readFile(source, 'utf8');
  assert.match(text, /SecRandomCopyBytes/); assert.match(text, /issued_ticket = own_call\(&issued, label\) \? issued\.rule\.ticket : 0/);
  assert.match(text, /CANARY_DELETE && request->rule.ticket == 0/);
  assert.match(text, /O_RDONLY \| O_CLOEXEC \| O_NOFOLLOW/); assert.match(text, /O_RDWR \| O_CLOEXEC \| O_NOFOLLOW/);
  assert.doesNotMatch(text, /DIOCSTART|DIOCSTOP|DIOCCLRSTATES|DIOCCHANGERULE|pfctl[^\n]*["']-f["']/);
  const build = await readFile(new URL('../scripts/build-macos-pf-root-canary.mjs', import.meta.url), 'utf8');
  assert.match(build, /inspectorSHA256/); assert.match(build, /source changed while compiling/);
  assert.match(build, /exec\(binary, \['--plan'\]/); assert.doesNotMatch(build, /exec\([^\n]*--request-canary/);
});
