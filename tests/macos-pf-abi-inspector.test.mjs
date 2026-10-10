import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, realpath, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const source = fileURLToPath(new URL('../native/macos-pf-routing/pf-abi-inspector.c', import.meta.url));
const onlyMac = { skip: process.platform !== 'darwin' };
async function fixture(callback, harness) {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-pf-abi-test-')));
  try {
    const input = harness ? path.join(directory, 'fixture.c') : source;
    if (harness) await writeFile(input, harness.replace('INSPECTOR_SOURCE', JSON.stringify(source)));
    const binary = path.join(directory, 'inspector');
    await execute('/usr/bin/clang', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', input, '-framework', 'Security', '-o', binary], { timeout: 30000, maxBuffer: 1024 * 1024 });
    return await callback(binary);
  } finally { await rm(directory, { recursive: true, force: true }); }
}
async function result(binary, args) {
  try { return { code: 0, value: JSON.parse((await execute(binary, args, { timeout: 15000 })).stdout) }; }
  catch (error) { assert.equal(typeof error.code, 'number'); return { code: error.code, value: JSON.parse(error.stdout) }; }
}
test('native default and plan do not request authorization or open PF', onlyMac, async () => {
  await fixture(async binary => {
    for (const args of [[], ['--plan']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 0); assert.equal(value.readOnly, true);
      assert.equal(value.authorizationRequested, false); assert.equal(value.deviceOpened, false);
      assert.equal(value.activation, false); assert.equal(value.systemInstallation, false);
      assert.equal(value.layout.requestSize, 3104); assert.equal(value.layout.ruleSize, 1040);
      assert.equal(value.layout.actionOffset, 1004);
      assert.ok(Object.values(value.gates).every(gate => gate === false));
    }
  });
});
test('native parser rejects arbitrary commands and unauthorized inspect without prompting', onlyMac, async () => {
  await fixture(async binary => {
    for (const args of [['--activate'], ['--request-inspect', '/untrusted'], ['--inspect', 'write']]) {
      const { code, value } = await result(binary, args);
      assert.equal(code, 1); assert.equal(value.reason, 'invalid-fixed-operation');
    }
    if (process.getuid() !== 0) {
      const { code, value } = await result(binary, ['--inspect']);
      assert.equal(code, 1); assert.equal(value.reason, 'privileged-reference-required');
      assert.equal(value.rootRulesMatch, false);
    }
  });
});
test('actual native anchor comparison refuses unknown syntax, shifted semantics and private labels', onlyMac, async () => {
  const harness = `
#define main inspector_program_main
#include INSPECTOR_SOURCE
#undef main
int main(void) {
    InspectorRequest r = {0}; strcpy(r.anchor_call, "owned-fixture");
    if (!matches_anchor_line("anchor \\\"owned-fixture\\\" all", &r)) return 1;
    if (matches_anchor_line("pass out quick all", &r)) return 2;
    if (matches_anchor_line("anchor \\\"another-fixture\\\" all", &r)) return 3;
    if (matches_anchor_line("anchor \\\"owned-fixture\\\" all label \\\"private\\\"", &r)) return 4;
    r.rule.quick = 1; if (matches_anchor_line("anchor \\\"owned-fixture\\\" all", &r)) return 5;
    r.rule.quick = 0; r.rule.gid_op = 4; if (matches_anchor_line("anchor \\\"owned-fixture\\\" all", &r)) return 6;
    r.rule.gid_op = 0; r.rule.src[0] = 1; if (matches_anchor_line("anchor \\\"owned-fixture\\\" all", &r)) return 7;
    return 0;
}`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});
test('source contains only allowlisted read ioctls and a read-only PF descriptor', async () => {
  const text = await readFile(source, 'utf8');
  assert.match(text, /open\("\/dev\/pf", O_RDONLY \| O_CLOEXEC \| O_NOFOLLOW\)/);
  assert.equal((text.match(/\bioctl\(/g) ?? []).length, 1);
  assert.match(text, /operation != INSPECT_GET_RULES && operation != INSPECT_GET_RULE/);
  assert.match(text, /request->action != 0/);
  assert.match(text, /AuthorizationCopyPrivilegedReference/);
  assert.doesNotMatch(text, /DIOCINSERTRULE|DIOCDELETERULE|DIOCCHANGERULE|DIOCCLRSTATES|DIOCSTART|DIOCSTOP/);
});

test('native ioctl boundary rejects counter-clear action, other requests and writable descriptors', onlyMac, async () => {
  const harness = `
#include <stdarg.h>
#include <sys/ioctl.h>
static unsigned int observed;
static int inert_ioctl(int descriptor, unsigned long operation, ...) {
    (void)descriptor; (void)operation; observed++; return 0;
}
#define ioctl inert_ioctl
#define main inspector_program_main
#include INSPECTOR_SOURCE
#undef main
#undef ioctl
int main(void) {
    int fds[2]; if (pipe(fds)) return 1;
    InspectorRequest request = {0};
    if (read_request(fds[0], INSPECT_GET_RULES, &request) || observed != 1) return 2;
    if (read_request(fds[0], INSPECT_GET_RULE, &request) || observed != 2) return 3;
    if (read_request(fds[0], 1234, &request) != -1 || observed != 2) return 4;
    request.action = 1;
    if (read_request(fds[0], INSPECT_GET_RULE, &request) != -1 || observed != 2) return 5;
    request.action = 0; request.anchor[0] = 'x';
    if (read_request(fds[0], INSPECT_GET_RULE, &request) != -1 || observed != 2) return 6;
    request.anchor[0] = 0;
    if (read_request(fds[1], INSPECT_GET_RULE, &request) != -1 || observed != 2) return 7;
    close(fds[0]); close(fds[1]); return 0;
}`;
  await fixture(binary => execute(binary, [], { timeout: 15000 }), harness);
});
