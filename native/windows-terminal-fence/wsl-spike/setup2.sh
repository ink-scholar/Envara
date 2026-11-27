#!/bin/sh
# Second spike distro: files (drvfs into a mount namespace) and the stdio channel.
# Runs once as root inside the freshly imported Alpine, while automount is still on.
set -e
export http_proxy=http://127.0.0.1:7897 https_proxy=http://127.0.0.1:7897
SRC=/mnt/c/Users/Admin/envara-test/wsl-spike2
apk update -q
apk add -q iproute2 socat curl git python3 inotify-tools util-linux-misc su-exec ca-certificates
mkdir -p /opt/envara /opt/spike
gunzip -c /mnt/c/Users/Admin/envara-test/wsl-spike/mihomo.gz > /opt/envara/mihomo
chmod 755 /opt/envara/mihomo
cp "$SRC"/files-spike.sh "$SRC"/files-inner.sh "$SRC"/bench_fs.py "$SRC"/channel-agent.py "$SRC"/channel-spike.sh /opt/spike/
adduser -D -u 1000 env
cat > /etc/wsl.conf <<'CONF'
[automount]
enabled = false
mountFsTab = false
[interop]
enabled = false
appendWindowsPath = false
[user]
default = root
CONF
echo setup2-done
