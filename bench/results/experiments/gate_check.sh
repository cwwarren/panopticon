#!/usr/bin/env bash
set -euo pipefail
cd /home/colin/work/panopticon
docker run -d --name pano-fs docker.io/library/redis:7-alpine sleep 60 >/dev/null
cpid=$(docker inspect -f '{{.State.Pid}}' pano-fs)
host_ino=$(stat -c %i /etc/shadow)
ctr_ino=$(sudo stat -c %i "/proc/$cpid/root/etc/shadow")
echo "host /etc/shadow ino=$host_ino container /etc/shadow ino=$ctr_ino"
sudo python3 /tmp/pano-exp/inotify_hold.py 20 /etc/shadow "/proc/$cpid/root/etc/shadow" >/tmp/pano-exp/hold.log 2>&1 &
hold=$!
sudo bpftrace -e "fentry:vmlinux:inotify_handle_inode_event /args.inode->i_ino == $host_ino || args.inode->i_ino == $ctr_ino/ {
  printf(\"%-12s pid=%-8d cgroup=%-6llu pidfs=%-9llu ino=%llu mask=0x%x\n\", comm, pid, cgroup, curtask->group_leader->thread_pid->ino, args.inode->i_ino, args.mask);
}" >/tmp/pano-exp/gate.log 2>&1 &
bt=$!
for _ in $(seq 100); do grep -q Attached /tmp/pano-exp/gate.log && break; sleep 0.1; done
sleep 1
echo "--- host cat"; sudo cat /etc/shadow >/dev/null
echo "--- host io_uring"; sudo target/release/loadgen act uring-open-shadow
echo "--- container cat"; docker exec pano-fs cat /etc/shadow >/dev/null
echo "--- fresh container (unmarked)"; docker run --rm docker.io/library/redis:7-alpine cat /etc/shadow >/dev/null
sleep 1
sudo pkill -INT -x bpftrace
wait "$bt" || true
docker rm -f pano-fs >/dev/null
wait "$hold" || true
cat /tmp/pano-exp/gate.log
