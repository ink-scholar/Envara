#!/bin/sh
# Distro root side: automount and interop are off; one environment gets a
# network namespace plus a private mount namespace holding only its folder.
WIN="$1"
say() { printf '\n== %s\n' "$1"; }
say "root namespace: /mnt contents (automount off)"; ls -A /mnt
say "root namespace: 9p/drvfs mounts before"; grep -E ' (9p|drvfs) ' /proc/mounts | awk '{print $2, $3}'
say "interop binfmt"; ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -i -e wsl -e interop || echo "no WSL interop handler"
ip netns add envfs 2>/dev/null; ip -n envfs link set lo up
ip netns exec envfs unshare -m --propagation private sh /opt/spike/files-inner.sh "$WIN"
say "root namespace: 9p/drvfs mounts after (the folder must not leak out)"; grep -E ' (9p|drvfs) ' /proc/mounts | awk '{print $2, $3}'
ip netns del envfs
