#!/bin/sh
# Runs under channel-agent.py: bring up the environment namespace, then hold it.
NS=${NS:-envpty}; CONF=/etc/envara/$NS; RUN=/run/envara
pkill -f "mihomo -d $CONF" 2>/dev/null; ip netns del $NS 2>/dev/null
mkdir -p $CONF /etc/netns/$NS
ip netns add $NS && ip -n $NS link set lo up
echo 'nameserver 198.18.0.2' > /etc/netns/$NS/resolv.conf
ip netns exec $NS socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:$RUN/route.sock 2>/dev/null &
cat > $CONF/config.yaml <<'YAML'
log-level: warning
ipv6: false
mode: rule
find-process-mode: off
tun: { enable: true, stack: system, device: envtun0, auto-route: true, auto-detect-interface: false, dns-hijack: ["any:53", "tcp://any:53"] }
dns: { enable: true, ipv6: false, listen: 127.0.0.1:1053, enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16, respect-rules: true, nameserver: ["https://1.1.1.1/dns-query"], proxy-server-nameserver: ["https://1.1.1.1/dns-query"] }
proxies: [ { name: route, type: http, server: 127.0.0.1, port: 1080 } ]
rules: [ "NETWORK,udp,REJECT", "MATCH,route" ]
YAML
ip netns exec $NS /opt/envara/mihomo -d $CONF > /tmp/mihomo-$NS.log 2>&1 &
sleep 3
[ "$CONTAINERENV" = 1 ] && touch /run/.containerenv || rm -f /run/.containerenv
echo NS-READY
sleep 3600
