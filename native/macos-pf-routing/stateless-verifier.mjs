import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { createStatelessFixturePFRoutingPolicy, isPFRoutingRunId, pfRoutingAnchor } from './policy.mjs';

const fail = code => Object.assign(new Error('Owned stateless fixture rules do not match'), { code });
const MAX_BYTES = 1024 * 1024, MAX_RULES = 8192;
const integer = value => /^(?:0|[1-9][0-9]*)$/.test(value) && Number.isSafeInteger(Number(value));
const object = value => value && typeof value === 'object' && !Array.isArray(value);

function lines(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES || /[\0\r\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) throw fail('PF_STATELESS_RULES_INVALID');
  const result = text.split('\n').filter(line => line.trim().length);
  if (result.length > MAX_RULES) throw fail('PF_STATELESS_RULES_INVALID');
  return result;
}

function tokens(line) {
  // Deliberately not a general PF parser. Unknown syntax must require review.
  const result = []; let offset = 0;
  const expression = /[ \t]*("[A-Za-z0-9_]+"|[{}(),!=]|[A-Za-z0-9_.\/-]+)/y;
  while (offset < line.length) {
    if (/^[ \t]*$/.test(line.slice(offset))) break;
    expression.lastIndex = offset; const match = expression.exec(line);
    if (!match) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
    result.push(match[1]); offset = expression.lastIndex;
  }
  return result;
}

function address(value) {
  if (value === 'any') return value;
  const selected = value.endsWith('/32') ? value.slice(0, -3) : value;
  if (isIP(selected) !== 4 || selected.split('.').some(part => String(Number(part)) !== part)) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  return selected;
}

function parseRule(line, { source, groupNameToGID }) {
  const input = tokens(line); let position = 0;
  const peek = () => input[position];
  const take = expected => {
    const selected = input[position++];
    if (selected === undefined || expected !== undefined && selected !== expected) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
    return selected;
  };
  const alternatives = kind => {
    const values = [];
    if (peek() === '{') {
      if (!source) throw fail('PF_STATELESS_RULES_UNEXPANDED');
      take('{');
      while (peek() !== '}') {
        if (values.length && peek() === ',') take(',');
        const selected = take();
        if (selected === ',' || selected === '{' || selected === '}') throw fail('PF_STATELESS_RULES_UNSUPPORTED');
        values.push(selected);
        if (values.length > 8) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
      }
      take('}');
    } else { if (peek() === '=') take('='); values.push(take()); }
    if (!values.length || new Set(values).size !== values.length || values.some(value => kind === 'protocol'
      ? !['tcp', 'udp'].includes(value) : !integer(value) || Number(value) < 1 || Number(value) > 65535)) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
    return kind === 'port' ? values.map(Number) : values;
  };
  const result = { action: take(), direction: '', quick: true, interface: null, interfaceNegated: false,
    routeTo: null, family: null, protocols: [], source: 'any', sourcePorts: [null], destination: 'any', destinationPorts: [null], gid: null, state: null, label: '' };
  if (result.action === 'block') take('return');
  else if (result.action !== 'pass') throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  result.direction = take(); if (!['in', 'out'].includes(result.direction)) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  take('quick');
  if (peek() === 'on') {
    take('on'); if (peek() === '!') { take('!'); result.interfaceNegated = true; }
    result.interface = take();
    if (!/^(?:lo0|utun(?:0|[1-9][0-9]{0,5}))$/.test(result.interface)) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  }
  if (peek() === 'route-to') {
    take('route-to'); take('('); const interfaceName = take(), ipv4Address = address(take()); take(')');
    if (!/^utun(?:0|[1-9][0-9]{0,5})$/.test(interfaceName) || ipv4Address === 'any') throw fail('PF_STATELESS_RULES_UNSUPPORTED');
    result.routeTo = { interfaceName, ipv4Address };
  }
  if (['inet', 'inet6'].includes(peek())) result.family = take();
  take('proto'); result.protocols = alternatives('protocol');
  if (peek() === 'all') take('all');
  else {
    take('from'); result.source = address(take());
    if (peek() === 'port') { take('port'); result.sourcePorts = alternatives('port'); }
    take('to'); result.destination = address(take());
    if (peek() === 'port') { take('port'); result.destinationPorts = alternatives('port'); }
  }
  if (peek() === 'group') {
    take('group'); if (peek() === '=') take('='); const selected = take();
    if (integer(selected)) result.gid = Number(selected);
    else if (!source && object(groupNameToGID) && Object.hasOwn(groupNameToGID, selected) && Number.isSafeInteger(groupNameToGID[selected])) result.gid = groupNameToGID[selected];
    else throw fail('PF_STATELESS_GROUP_BINDING_REQUIRED');
  }
  // The fixed installed Darwin pfctl -n -v printer omits zero flags for
  // both TCP and UDP. Explicit "flags any" is the same zero-mask semantics.
  // No alternative mask is accepted. State omission on a pass is NOT accepted.
  if (peek() === 'flags') { take('flags'); take('any'); }
  if (peek() === 'no') { take('no'); take('state'); result.state = 'none'; }
  if (result.action === 'pass' && result.state !== 'none') throw fail('PF_STATELESS_STATE_REQUIRED');
  if (result.action === 'block') result.state = 'none';
  take('label'); const label = take();
  if (!/^"envara_[a-f0-9]{24}_(?:loopback|ipv6|udp|fixture_in_block|blocked|(?:in|out)_[a-f0-9]{12})"$/.test(label)) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  result.label = label.slice(1, -1);
  if (position !== input.length) throw fail('PF_STATELESS_RULES_UNSUPPORTED');
  return result;
}

function expand(rule) {
  const { protocols, sourcePorts, destinationPorts, ...base } = rule, result = [];
  // PF list expansion is a Cartesian product, not one kernel rule per line.
  // Installed Apple pf.conf(5): protocol/port list grammar and parse-time
  // expansion example. Preserve source order; every rule has a label barrier.
  for (const protocol of protocols) for (const sourcePort of sourcePorts) for (const destinationPort of destinationPorts) {
    result.push({ ...base, protocol, sourcePort, destinationPort });
  }
  return result;
}

function expectedPolicy(policy) {
  if (!object(policy) || policy.schema !== 'envara.macos-pf-stateless-fixture' || policy.version !== 1 ||
      !isPFRoutingRunId(policy.runId) || policy.anchor !== pfRoutingAnchor(policy.runId) || policy.fixtureOnly !== true || policy.statePolicy !== 'stateless-fixture') throw fail('PF_STATELESS_POLICY_REQUIRED');
  let regenerated;
  try { regenerated = createStatelessFixturePFRoutingPolicy(policy.routes, { fixtureDestinations: policy.fixtureDestinations, runId: policy.runId }); }
  catch { throw fail('PF_STATELESS_POLICY_REQUIRED'); }
  // An arbitrary caller-authored policy may not widen the accepted readback.
  if (regenerated.rules !== policy.rules) throw fail('PF_STATELESS_POLICY_REQUIRED');
  return regenerated;
}

export function expectedStatelessFixtureRuleSemantics(policy) {
  const regenerated = expectedPolicy(policy);
  return lines(regenerated.rules).flatMap(line => expand(parseRule(line, { source: true })));
}

/** Pure comparison only; the caller must obtain an authenticated native readback.
 * This never reads PF, changes a rule, or proves lifecycle/routing acceptance.
 * groupNameToGID, if supplied, must come from the caller's verified OS registry.
 */
export function verifyStatelessFixtureRuleReadback(policy, readback, { groupNameToGID } = {}) {
  const expected = expectedStatelessFixtureRuleSemantics(policy);
  const actual = lines(readback).flatMap(line => expand(parseRule(line, { source: false, groupNameToGID })));
  if (actual.length !== expected.length || expected.some((rule, index) => JSON.stringify(rule) !== JSON.stringify(actual[index]))) throw fail('PF_STATELESS_RULES_MISMATCH');
  const count = action => expected.filter(rule => rule.action === action).length;
  return { schema: 'envara.macos-pf-stateless-rule-comparison/v1', rulesMatch: true, noStateRulesVerified: true,
    sourceRuleCount: lines(policy.rules).length, expandedRuleCount: expected.length, passRuleCount: count('pass'), blockRuleCount: count('block'),
    installedRulesDigest: createHash('sha256').update(readback).digest('hex'), nativeAcceptance: false, productionReady: false };
}
