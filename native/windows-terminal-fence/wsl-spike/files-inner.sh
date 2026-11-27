#!/bin/sh
# Root inside the environment's network + mount namespace. The shell the user
# gets runs as the unprivileged "env" account (uid 1000).
WIN="$1"
say() { printf '\n== %s\n' "$1"; }
U="su-exec env"
OPTS=metadata,uid=1000,gid=1000,umask=022
mkdir -p /work
say "mount the chosen Windows folder: $WIN"
mount -t drvfs "$WIN" /work -o $OPTS && echo mounted || { echo "MOUNT FAILED"; exit 1; }
grep ' /work ' /proc/mounts | awk '{print $2, $3, $4}'

say "read a file Windows wrote"; $U cat /work/from-windows.txt
say "write a UTF-8 file"; $U sh -c 'echo "from linux 中文" > /work/from-linux.txt' && echo ok
say "exec bit with metadata"; $U sh -c 'printf "#!/bin/sh\necho script-ran\n" > /work/run.sh && chmod 755 /work/run.sh && stat -c %a /work/run.sh && /work/run.sh'
say "symlink"; $U sh -c 'ln -sf from-linux.txt /work/link.txt && readlink /work/link.txt && cat /work/link.txt'
say "case: Case.txt and case.txt in a Windows-created folder"; $U sh -c 'echo upper > /work/Case.txt; echo lower > /work/case.txt; ls /work | grep -i "^case.txt$"; cat /work/Case.txt'
say "case: in a folder created from Linux"; $U sh -c 'mkdir -p /work/linuxdir && echo upper > /work/linuxdir/Case.txt && echo lower > /work/linuxdir/case.txt; ls /work/linuxdir'

say "inotify: watching /work for 25 s (a Linux write now, a Windows write from outside)"
$U sh -c 'timeout 25 inotifywait -m -q -e create,modify,close_write --format "%e %f" /work > /tmp/inotify.txt 2>&1 &'
sleep 2
$U sh -c 'echo linux-write > /work/linux-event.txt'
$U sh -c 'echo ready > /work/inotify-ready.txt'
sleep 24
cat /tmp/inotify.txt | sort | uniq

say "small files and git: drvfs vs ext4 (1000 files)"
$U python3 /opt/spike/bench_fs.py /work/bench
$U python3 /opt/spike/bench_fs.py /home/env/bench

say "remount: does the exec bit persist"
umount /work && mount -t drvfs "$WIN" /work -o $OPTS && stat -c '%a %n' /work/run.sh

say "escape: env mounts the whole C: drive"
$U sh -c 'mkdir -p /tmp/c; mount -t drvfs "C:\\" /tmp/c 2>&1; echo "exit $?"'
say "escape: env in a new user namespace mounts C:"
$U sh -c 'unshare -Urm sh -c "mkdir -p /tmp/c2; mount -t drvfs \"C:\\\\\" /tmp/c2 2>&1; echo exit \$?; ls /tmp/c2 | head -3"'
say "escape: env reads the distro root via /proc/1/root"
$U sh -c 'ls /proc/1/root/ 2>&1 | head -2'
say "escape: WSL paths visible to env"; $U sh -c 'ls -A /mnt /usr/lib/wsl 2>&1 | head -10'
say "network inside (expected none)"; $U sh -c 'curl -s -m 5 -o /dev/null -w "http=%{http_code}\n" https://example.com || echo "no network (exit $?)"'
