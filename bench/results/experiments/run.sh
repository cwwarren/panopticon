#!/usr/bin/env bash
set -euo pipefail
cd /home/colin/work/panopticon
LG=target/release/loadgen
RB=target/release/ringbench
OUT=${OUT:-/tmp/pano-exp/results.jsonl}
SECS=5
NAT_EMPTY='fexit:nf_nat:nf_nat_setup_info {}'
NAT_FILTER='fexit:nf_nat:nf_nat_setup_info {
  if (args.ct->tuplehash[0].tuple.src.u3.ip != args.ct->tuplehash[1].tuple.dst.u3.ip ||
      args.ct->tuplehash[0].tuple.src.u.all != args.ct->tuplehash[1].tuple.dst.u.all) { @translated = count(); }
  @calls = count();
}'
BG_PID=""

record() {
  local exp=$1 rep=$2 res=$3
  jq -c --arg exp "$exp" --argjson rep "$rep" '{exp: $exp, rep: $rep} + (if .result then .result + {consumed, drops} else . end)' <<<"$res" >>"$OUT"
}

start_bg() {
  local ready=$1 log=$2
  shift 2
  "$@" >"$log" 2>&1 &
  BG_PID=$!
  for _ in $(seq 100); do
    grep -q "$ready" "$log" && return
    sleep 0.1
  done
  echo "timeout waiting for $ready in $log" >&2
  exit 1
}

files() {
  local rep=$1 file=/usr/lib/os-release
  record f0-none "$rep" "$(sudo taskset -c 2 $LG bench open 1 $SECS $file)"
  record f1-empty-hook "$rep" "$(sudo PRODUCER_CPUS=2 $RB empty security_file_open open 1 $SECS $file)"
  record f1-inode-filter "$rep" "$(sudo PRODUCER_CPUS=2 $RB file_filter security_file_open open 1 $SECS $file)"
  start_bg ready /tmp/pano-exp/hold.log sudo python3 /tmp/pano-exp/inotify_hold.py $((SECS + 3)) /etc/shadow /etc/gshadow /etc/sudoers
  record f2-inotify-marks "$rep" "$(sudo taskset -c 2 $LG bench open 1 $SECS $file)"
  wait "$BG_PID"
  start_bg ready /tmp/pano-exp/hold.log sudo python3 /tmp/pano-exp/inotify_hold.py $((SECS + 3)) /etc/shadow /etc/gshadow /etc/sudoers
  record f3-gated-hook "$rep" "$(sudo PRODUCER_CPUS=2 $RB spsc_out inotify_handle_inode_event open 1 $SECS $file)"
  wait "$BG_PID"
}

nat() {
  local rep=$1 threads=$2 p=$3
  record "n0-none-$threads" "$rep" "$(sudo $p $LG bench connect "$threads" $SECS)"
  start_bg ready /tmp/pano-exp/ctnl.log sudo python3 /tmp/pano-exp/ctnl_listen.py $((SECS + 3))
  record "n1-ctnetlink-$threads" "$rep" "$(sudo $p $LG bench connect "$threads" $SECS)"
  wait "$BG_PID"
  echo "ctnetlink $threads rep $rep: $(tail -n1 /tmp/pano-exp/ctnl.log)" >>/tmp/pano-exp/ctnl-summary.txt
  start_bg Attached /tmp/pano-exp/bt.log sudo bpftrace -e "$NAT_EMPTY"
  record "n2-nat-empty-$threads" "$rep" "$(sudo $p $LG bench connect "$threads" $SECS)"
  sudo pkill -INT -x bpftrace
  wait "$BG_PID" || true
  start_bg Attached /tmp/pano-exp/bt.log sudo bpftrace -e "$NAT_FILTER"
  record "n3-nat-filter-$threads" "$rep" "$(sudo $p $LG bench connect "$threads" $SECS)"
  sudo pkill -INT -x bpftrace
  wait "$BG_PID" || true
  echo "natfilter $threads rep $rep: $(grep -E '^@' /tmp/pano-exp/bt.log | tr '\n' ' ')" >>/tmp/pano-exp/nat-summary.txt
}

for rep in 1 2 3 4 5; do
  files "$rep"
  nat "$rep" 1 "taskset -c 2"
  nat "$rep" 16 ""
done
