#!/bin/sh
# Third spike distro: interactive terminal (node-pty/ConPTY -> wsl.exe -> namespace
# -> unprivileged shell) and Claude Code's first run / login inside it.
set -e
export http_proxy=http://127.0.0.1:7897 https_proxy=http://127.0.0.1:7897
SRC=/mnt/c/Users/Admin/envara-test/wsl-spike2
apk update -q
apk add -q iproute2 socat curl git bash ncurses python3 util-linux-misc su-exec ca-certificates libgcc libstdc++ ripgrep iproute2-ss
mkdir -p /opt/envara /opt/spike/bin
gunzip -c /mnt/c/Users/Admin/envara-test/wsl-spike/mihomo.gz > /opt/envara/mihomo
chmod 755 /opt/envara/mihomo
cp "$SRC"/channel-agent.py "$SRC"/ns-up.sh "$SRC"/enter.sh /opt/spike/
# Stand-ins for the terminal link channel: record what would open in the Envara browser.
for b in xdg-open open-url; do printf '#!/bin/sh\necho "$(date +%%T) $0 $*" >> /home/env/opened-urls.txt\n' > /opt/spike/bin/$b; chmod 755 /opt/spike/bin/$b; done
adduser -D -s /bin/bash -u 1000 env
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
echo setup3-done
