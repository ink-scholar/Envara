export const statelessFixtureRoutes = [
  { environmentId: 'realm-one', gid: 7100, mode: 'routed', udpPolicy: 'proxy', tunnel: { interfaceName: 'utun42', pid: 1001, instanceId: 'owned-one', ipv4Address: '198.18.1.1' } },
  { environmentId: 'realm-two', gid: 7101, mode: 'routed', udpPolicy: 'proxy', tunnel: { interfaceName: 'utun43', pid: 1002, instanceId: 'owned-two', ipv4Address: '198.18.2.1' } },
];
export const statelessFixtureDestinations = [{ host: '198.51.100.42', ports: [44441, 44442, 44443, 44444] }, { host: '1.1.1.1', ports: [53] }];

// Fixed run: e152b0ec-3e0c-4b6a-a4ec-18cf1f3435b5.
// Independent singleton fixture, not generated from policy.rules or verifier
// expectations. Format follows the installed Darwin pfctl -n -v printer:
// numeric group/port equality, "all", and zero TCP flags omitted. The four
// port alternatives retain the same source label across distinct rules.
export function printedStatelessFixtureReadback() {
  const lines = [];
  for (const realm of [
    { gid: 7100, iface: 'utun42', address: '198.18.1.1', label: 'envara_fb984084c1dd77701ea9626b', dns: ['3c18c53a44df', 'd14c171bc7e7'], echo: ['ca7a8ab9978e', '5168d96310ab'] },
    { gid: 7101, iface: 'utun43', address: '198.18.2.1', label: 'envara_9cd74c8768f5f1c7e1560110', dns: ['c050582307f7', 'd7d7b4f8fbe8'], echo: ['2043c1de6295', '3b04047e63d3'] },
  ]) {
    for (const protocol of ['tcp', 'udp']) lines.push(`block return out quick on lo0 proto ${protocol} all group = ${realm.gid} label "${realm.label}_loopback"`);
    for (const protocol of ['tcp', 'udp']) lines.push(`block return out quick inet6 proto ${protocol} all group = ${realm.gid} label "${realm.label}_ipv6"`);
    for (const target of [{ host: '1.1.1.1', ports: [53], suffix: realm.dns }, { host: '198.51.100.42', ports: [44441, 44442, 44443, 44444], suffix: realm.echo }]) {
      for (const [index, protocol] of ['tcp', 'udp'].entries()) {
        for (const port of target.ports) lines.push(`pass in quick on ${realm.iface} inet proto ${protocol} from ${target.host}/32 port = ${port} to any no state label "${realm.label}_in_${target.suffix[index]}"`);
        for (const port of target.ports) lines.push(`pass out quick on ! lo0 route-to (${realm.iface} ${realm.address}) inet proto ${protocol} from any to ${target.host}/32 port = ${port} group = ${realm.gid} no state label "${realm.label}_out_${target.suffix[index]}"`);
      }
    }
    for (const protocol of ['tcp', 'udp']) lines.push(`block return in quick on ${realm.iface} proto ${protocol} all label "${realm.label}_fixture_in_block"`);
    for (const protocol of ['tcp', 'udp']) lines.push(`block return out quick proto ${protocol} all group = ${realm.gid} label "${realm.label}_blocked"`);
  }
  return `${lines.join('\n')}\n`;
}
