#!/bin/sh
set -e
export http_proxy=http://127.0.0.1:7897 https_proxy=http://127.0.0.1:7897
apk update -q
apk add -q iproute2 socat curl git bash libgcc libstdc++ ripgrep bind-tools ca-certificates python3 iptables nftables tcpdump
mkdir -p /opt/envara
gunzip -c /mnt/c/Users/Admin/envara-test/wsl-spike/mihomo.gz > /opt/envara/mihomo
chmod 755 /opt/envara/mihomo
/opt/envara/mihomo -v | head -1
cat > /etc/wsl.conf <<'CONF'
[interop]
enabled = false
appendWindowsPath = false
[user]
default = root
CONF
echo setup-done
