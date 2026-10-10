import test from 'node:test';
import assert from 'node:assert/strict';
import { createStatelessFixturePFRoutingPolicy } from '../native/macos-pf-routing/policy.mjs';
import { expectedStatelessFixtureRuleSemantics, verifyStatelessFixtureRuleReadback } from '../native/macos-pf-routing/stateless-verifier.mjs';
import { statelessFixtureRoutes as routes, statelessFixtureDestinations as fixtureDestinations, printedStatelessFixtureReadback } from './fixtures/macos-pf-stateless-readback.mjs';

const policy = createStatelessFixturePFRoutingPolicy(routes, { fixtureDestinations, runId: 'e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5' });
const readback = printedStatelessFixtureReadback();
const refused = (text, code) => assert.throws(() => verifyStatelessFixtureRuleReadback(policy, text), error => error.code === code);

test('four-port source lists become 40 pass rules, while all block expansions are also checked', () => {
  assert.equal(policy.rules.split('\n').filter(line => line.startsWith('pass ')).length, 16);
  assert.equal(readback.split('\n').filter(line => line.startsWith('pass ')).length, 40);
  assert.equal(expectedStatelessFixtureRuleSemantics(policy).length, 56);
  const result = verifyStatelessFixtureRuleReadback(policy, readback);
  assert.equal(result.sourceRuleCount, 24);
  assert.equal(result.expandedRuleCount, 56);
  assert.equal(result.passRuleCount, 40);
  assert.equal(result.blockRuleCount, 16);
  assert.equal(result.rulesMatch, true);
  assert.equal(result.noStateRulesVerified, true);
  assert.equal(result.nativeAcceptance, false);
  assert.equal(result.productionReady, false);
});

test('unexpanded source text cannot stand in for native singleton readback', () => {
  refused(policy.rules, 'PF_STATELESS_RULES_UNEXPANDED');
});

test('label presence alone cannot replace multiplicity and full scope', () => {
  const rows = readback.trim().split('\n');
  const index = rows.findIndex(line => line.includes('port = 44442'));
  rows.splice(index, 1); refused(`${rows.join('\n')}\n`, 'PF_STATELESS_RULES_MISMATCH');
  const duplicated = readback.replace('port = 44442', 'port = 44441');
  refused(duplicated, 'PF_STATELESS_RULES_MISMATCH');
});

for (const [name, original, replacement] of [
  ['destination port', 'port = 44443', 'port = 44444'],
  ['destination address', 'to 198.51.100.42/32', 'to 203.0.113.42/32'],
  ['source address', 'from 198.51.100.42/32', 'from 203.0.113.42/32'],
  ['source port', 'from 198.51.100.42/32 port = 44441', 'from 198.51.100.42/32 port = 44442'],
  ['group', 'group = 7100', 'group = 7101'],
  ['interface', 'on utun42', 'on utun43'],
  ['route interface', 'route-to (utun42', 'route-to (utun43'],
  ['route address', 'route-to (utun42 198.18.1.1)', 'route-to (utun42 198.18.2.1)'],
  ['negation', 'on ! lo0', 'on lo0'],
  ['family', 'on utun42 inet proto', 'on utun42 inet6 proto'],
  ['protocol', 'on utun42 inet proto tcp', 'on utun42 inet proto udp'],
  ['direction', 'pass in quick', 'pass out quick'],
  ['label', '_in_3c18c53a44df', '_in_d14c171bc7e7'],
]) {
  test(`rejects same-count rule change: ${name}`, () => refused(readback.replace(original, replacement), 'PF_STATELESS_RULES_MISMATCH'));
}

test('impactful rule reordering is refused even with every label and count intact', () => {
  const rows = readback.trim().split('\n'); [rows[4], rows[5]] = [rows[5], rows[4]];
  refused(`${rows.join('\n')}\n`, 'PF_STATELESS_RULES_MISMATCH');
});

test('extra valid-looking owned rule is refused', () => {
  refused(`${readback}${readback.split('\n')[4]}\n`, 'PF_STATELESS_RULES_MISMATCH');
});

test('stateful pass, omitted no-state, alternate flags and unknown options are refused', () => {
  refused(readback.replace('no state', 'keep state'), 'PF_STATELESS_STATE_REQUIRED');
  refused(readback.replace('no state', 'modulate state'), 'PF_STATELESS_STATE_REQUIRED');
  refused(readback.replace('no state ', ''), 'PF_STATELESS_STATE_REQUIRED');
  refused(readback.replace('no state', 'flags S/SA no state'), 'PF_STATELESS_RULES_UNSUPPORTED');
  refused(readback.replace('pass in quick', 'pass in log quick'), 'PF_STATELESS_RULES_UNSUPPORTED');
  refused(readback.replace('no state', 'no state tag FOREIGN'), 'PF_STATELESS_RULES_UNSUPPORTED');
  refused(readback.replace('block return out', 'block return out quick quick'), 'PF_STATELESS_RULES_UNSUPPORTED');
});

test('explicit zero flags and their native printed omission have identical stateless meaning', () => {
  assert.equal(verifyStatelessFixtureRuleReadback(policy, readback.replaceAll('no state', 'flags any no state')).rulesMatch, true);
});

test('printed group names require explicit verified numeric binding, never a guessed suffix', () => {
  const names = readback.replaceAll('group = 7100', 'group = _envara_pf_7100').replaceAll('group = 7101', 'group = _envara_pf_7101');
  refused(names, 'PF_STATELESS_GROUP_BINDING_REQUIRED');
  assert.equal(verifyStatelessFixtureRuleReadback(policy, names, { groupNameToGID: { _envara_pf_7100: 7100, _envara_pf_7101: 7101 } }).rulesMatch, true);
  assert.throws(() => verifyStatelessFixtureRuleReadback(policy, names, { groupNameToGID: { _envara_pf_7100: 7101, _envara_pf_7101: 7101 } }), { code: 'PF_STATELESS_RULES_MISMATCH' });
});

test('arbitrary policies cannot expand verifier scope or borrow a production stateful policy', () => {
  assert.throws(() => verifyStatelessFixtureRuleReadback({ ...policy, anchor: 'com.apple/envara' }, readback), { code: 'PF_STATELESS_POLICY_REQUIRED' });
  assert.throws(() => verifyStatelessFixtureRuleReadback({ ...policy, fixtureOnly: false }, readback), { code: 'PF_STATELESS_POLICY_REQUIRED' });
  assert.throws(() => verifyStatelessFixtureRuleReadback({ ...policy, rules: policy.rules.replace('no state', 'keep state') }, readback), { code: 'PF_STATELESS_POLICY_REQUIRED' });
  assert.throws(() => verifyStatelessFixtureRuleReadback({ ...policy, fixtureDestinations: [{ host: '8.8.8.8', ports: [443] }] }, readback), { code: 'PF_STATELESS_POLICY_REQUIRED' });
});

test('malformed, control-bearing, overly large or foreign lines fail without exposing readback', () => {
  for (const value of [null, 42, `${readback}\0`, `${readback}\r`, 'x'.repeat(1024 * 1024 + 1)]) refused(value, 'PF_STATELESS_RULES_INVALID');
  refused(`${readback}anchor "FOREIGN"\n`, 'PF_STATELESS_RULES_UNSUPPORTED');
  assert.throws(() => verifyStatelessFixtureRuleReadback(policy, `${readback}password=secret\n`), error => !error.message.includes('secret'));
});

test('readback from a different run cannot be borrowed even for identical routes and fixture targets', () => {
  const next = createStatelessFixturePFRoutingPolicy(routes, { fixtureDestinations, runId: '66d5514e-771f-4c09-8da7-3f869c3c5166' });
  assert.notEqual(next.anchor, policy.anchor); assert.notEqual(next.rules, policy.rules);
  assert.throws(() => verifyStatelessFixtureRuleReadback(next, readback), { code: 'PF_STATELESS_RULES_MISMATCH' });
  for (const change of [{ runId: policy.runId.toUpperCase() }, { anchor: 'io.envara.pf.root.v1' }, { runId: next.runId }, { anchor: next.anchor }]) {
    assert.throws(() => verifyStatelessFixtureRuleReadback({ ...policy, ...change }, readback), { code: 'PF_STATELESS_POLICY_REQUIRED' });
  }
});
