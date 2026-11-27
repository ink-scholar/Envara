#!/bin/sh
# Runs under channel-agent.py. The namespace's only exit is Mihomo TUN ->
# 127.0.0.1:1080 -> route.sock -> agent -> wsl.exe stdio -> Windows host.
NS=envch; CONF=/etc/envara/$NS; RUN=/run/envara
say() { printf '\n== %s\n' "$1"; }
cleanup() { pkill -f "mihomo -d $CONF" 2>/dev/null; pkill -f "TCP-LISTEN:1080" 2>/dev/null; ip netns del $NS 2>/dev/null; }
cleanup; mkdir -p $CONF /etc/netns/$NS
ip netns add $NS && ip -n $NS link set lo up
echo 'nameserver 198.18.0.2' > /etc/netns/$NS/resolv.conf
ip netns exec $NS socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:$RUN/route.sock 2>/dev/null & sleep 0.5
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
ip netns exec $NS /opt/envara/mihomo -d $CONF > /tmp/mihomo-ch.log 2>&1 &
sleep 3
N="ip netns exec $NS env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY"

say "distro has no TCP path to Windows in this test: route proxy is"; grep -o 'server: 127.0.0.1, port: 1080' $CONF/config.yaml
say "exit IP inside the namespace"; $N curl -s -m 15 https://api.ipify.org; echo
say "latency: 10 sequential HTTPS requests (time_total, s)"
for i in 1 2 3 4 5 6 7 8 9 10; do $N curl -s -m 15 -o /dev/null -w '%{time_total} ' https://www.gstatic.com/generate_204; done; echo
say "8 parallel HTTPS requests"
P=''; for i in 1 2 3 4 5 6 7 8; do $N curl -s -m 20 -o /dev/null -w '%{http_code} ' https://api.github.com/ & P="$P $!"; done; wait $P; echo
say "download 20 MB through the channel"
$N curl -s -m 120 -o /dev/null -w 'size=%{size_download} speed=%{speed_download}B/s time=%{time_total}s\n' 'https://speed.cloudflare.com/__down?bytes=20000000'
say "upload 5 MB through the channel"
head -c 5000000 /dev/urandom > /tmp/up.bin
$N curl -s -m 120 -o /dev/null -X POST --data-binary @/tmp/up.bin -w 'size=%{size_upload} speed=%{speed_upload}B/s http=%{http_code}\n' 'https://speed.cloudflare.com/__up'
say "git clone through the channel"; rm -rf /tmp/hw; $N git clone -q --depth 1 https://github.com/octocat/Hello-World /tmp/hw && echo "ok: $(ls /tmp/hw)"
say "raw stdio channel throughput (Windows host sends 200 MB)"
python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_UNIX); s.connect('/run/envara/bench.sock')
t = time.perf_counter(); n = 0
while (b := s.recv(1 << 20)): n += len(b)
dt = time.perf_counter() - t
print(f'{n} bytes in {dt:.2f}s = {n / dt / 1e6:.0f} MB/s')
PY
say "mihomo warnings"; grep -iE 'warn|error' /tmp/mihomo-ch.log | sed 's/time="[^"]*" //' | tail -5
cleanup
