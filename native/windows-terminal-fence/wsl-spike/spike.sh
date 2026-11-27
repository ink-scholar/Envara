#!/bin/sh
# Envara WSL fence spike: one environment = one network namespace whose only
# exit is a TUN device owned by Mihomo, which forwards everything to the route.
NS=envspike; RUN=/run/envara; CONF=/etc/envara/$NS
TOKEN=envara-leak-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')
cleanup() { pkill -f "mihomo -d $CONF" 2>/dev/null; pkill -f "socat" 2>/dev/null; kill $DUMP 2>/dev/null; ip netns del $NS 2>/dev/null; rm -rf $RUN; }
trap cleanup EXIT
cleanup; mkdir -p $RUN $CONF /etc/netns/$NS
say() { printf '\n== %s\n' "$1"; }

# Host side: the route. In the product this is the environment's authenticated route; here, yyb's Clash.
socat UNIX-LISTEN:$RUN/route.sock,fork,mode=600 TCP:127.0.0.1:7897 & sleep 0.5

ip netns add $NS && ip -n $NS link set lo up
echo 'nameserver 198.18.0.2' > /etc/netns/$NS/resolv.conf
# Inside: loopback relay to the route socket (unix sockets cross network namespaces).
ip netns exec $NS socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:$RUN/route.sock & sleep 0.5
cat > $CONF/config.yaml <<'YAML'
log-level: info
ipv6: false
allow-lan: false
mode: rule
find-process-mode: off
tun:
  enable: true
  stack: system
  device: envtun0
  auto-route: true
  auto-detect-interface: false
  dns-hijack: ["any:53", "tcp://any:53"]
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  respect-rules: true
  nameserver: ["https://1.1.1.1/dns-query"]
  proxy-server-nameserver: ["https://1.1.1.1/dns-query"]
proxies:
  - { name: route, type: http, server: 127.0.0.1, port: 1080 }
rules:
  - NETWORK,udp,REJECT
  - MATCH,route
YAML
ip netns exec $NS /opt/envara/mihomo -d $CONF > $RUN/mihomo.log 2>&1 &
sleep 3

# Leak watch outside the namespace: any packet carrying the test domain in clear.
tcpdump -i any -n -l -vv 'not port 1080' > $RUN/dump.txt 2>/dev/null & DUMP=$!
sleep 1

say "proxy variables WSL injects into this shell"; env | grep -i '_proxy=' | sed 's/=.*/=<set>/' | sort | tr '\n' ' '; echo
# Envara controls the environment: no inherited proxy variables inside.
N="ip netns exec $NS env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY"
say "interfaces and routes inside the namespace"; $N ip -br addr; $N ip route
say "exit IP inside (no proxy variables)"; $N curl -s -m 15 https://api.ipify.org; echo
say "exit IP of the host side via the route (expected to match)"; curl -s -m 15 -x http://127.0.0.1:7897 https://api.ipify.org; echo
say "raw IP connection (still forced through the route)"; $N curl -s -m 10 -o /dev/null -w 'http=%{http_code}\n' http://1.1.1.1/
say "DNS straight to 8.8.8.8 (UDP) for a unique name"; $N dig +short +time=5 +tries=1 "$TOKEN.example.com" @8.8.8.8 A
say "DNS over TCP to 8.8.8.8"; $N dig +short +tcp +time=5 +tries=1 "$TOKEN-tcp.example.com" @8.8.8.8 A
say "system resolver"; $N getent hosts example.com
say "UDP to a STUN server (WebRTC style)"; $N python3 -c "
import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5)
try:
  s.sendto(bytes.fromhex('000100002112a442')+os.urandom(12),('74.125.250.129',19302)); d,a=s.recvfrom(2048); print('STUN reply from',a,len(d),'bytes')
except Exception as e: print('no STUN reply:',type(e).__name__)
"
say "IPv6"; $N curl -6 -s -m 8 -o /dev/null -w 'http=%{http_code}\n' 'https://[2606:4700:4700::1111]/' || echo "ipv6 failed (exit $?)"
say "Windows interop"; $N /mnt/c/Windows/System32/cmd.exe /c ver > $RUN/interop.txt 2>&1; echo "exit $?; Windows banner printed: $(grep -c Microsoft $RUN/interop.txt)"
say "git over the route"; rm -rf /tmp/hw; $N git clone -q --depth 1 https://github.com/octocat/Hello-World /tmp/hw && echo "git clone ok: $(ls /tmp/hw)"
say "Claude Code reaches its API"; $N /root/.local/bin/claude --version >/dev/null; $N curl -s -m 15 -o /dev/null -w 'api.anthropic.com http=%{http_code}\n' https://api.anthropic.com/
say "claude version"; $N /root/.local/bin/claude --version 2>&1 | head -2
sleep 2
kill $DUMP 2>/dev/null; sleep 1
say "leak watch: captured lines outside the namespace carrying $TOKEN"; grep -c "$TOKEN" $RUN/dump.txt
say "leak watch: DNS packets (port 53) seen outside the namespace"; grep -c '\.53: \|\.53 >' $RUN/dump.txt
say "names in those DNS packets (queries only)"; grep -oE '(A|AAAA|HTTPS)\? [A-Za-z0-9.-]+' $RUN/dump.txt | sort | uniq -c | sort -rn | head -15
say "did any name the namespace used appear there?"; for n in api.ipify.org github.com claude.ai downloads.claude.ai api.anthropic.com; do printf '%s: %s\n' $n "$(grep -cE "(A|AAAA|HTTPS)\? $n\." $RUN/dump.txt)"; done
say "mihomo connections (last lines)"; grep -E 'match|DNS|error|warn' $RUN/mihomo.log | sed 's/time="[^"]*" //' | tail -12
