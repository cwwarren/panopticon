#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
EXP=bench/results/experiments
mkdir -p /tmp/pano-exp
gcc -O2 -pthread -Wno-unused-result -o /tmp/pano-exp/sysctl_race "$EXP/sysctl_race.c"
sudo rm -f /tmp/pano-exp/sysctl.pano
sudo target/release/panopticon run /tmp/pano-exp/sysctl.pano >/tmp/pano-exp/sysctl-agent.log 2>&1 &
for _ in $(seq 100); do grep -q ready /tmp/pano-exp/sysctl-agent.log && break; sleep 0.1; done
sudo unshare -n /tmp/pano-exp/sysctl_race 5000
sleep 1.5
sudo pkill -INT -x panopticon
while pgrep -x panopticon >/dev/null; do sleep 0.1; done
echo "agent:"
target/release/panopticon decode /tmp/pano-exp/sysctl.pano |
  jq -r 'select(.type == "admin" and (.exe | endswith("/sysctl_race"))) | .value' | sort | uniq -c
