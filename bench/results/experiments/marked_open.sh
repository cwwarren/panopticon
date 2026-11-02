#!/usr/bin/env bash
set -euo pipefail
cd /home/colin/work/panopticon
LG=target/release/loadgen
EXP=bench/results/experiments
OUT=${OUT:-$EXP/marked-open.jsonl}
SECS=5
FILE=/etc/shadow
BG_PID=""

record() {
  jq -c --arg exp "$1" --argjson rep "$2" '{exp: $exp, rep: $rep} + .' <<<"$3" >>"$OUT"
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

bench() {
  sudo taskset -c 2 $LG bench open 1 $SECS $FILE
}

for rep in 1 2 3 4 5; do
  record m0-none "$rep" "$(bench)"
  start_bg ready /tmp/pano-exp/hold.log sudo python3 $EXP/inotify_mark.py 1 $((SECS + 3)) $FILE
  record m1-mark-drain "$rep" "$(bench)"
  wait "$BG_PID"
  start_bg ready /tmp/pano-exp/hold.log sudo python3 $EXP/inotify_mark.py 0 $((SECS + 3)) $FILE
  record m2-mark-nodrain "$rep" "$(bench)"
  wait "$BG_PID"
  start_bg ready /tmp/pano-exp/pano.log sudo target/release/panopticon run /tmp/pano-exp/marked.pano
  record m3-pano "$rep" "$(bench)"
  sudo pkill -INT -x panopticon
  wait "$BG_PID"
  rm -f /tmp/pano-exp/marked.pano
done
