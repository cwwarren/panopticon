#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
EXP=bench/results/experiments
mkdir -p /tmp/pano-exp
gcc -O2 -pthread -o /tmp/pano-exp/dns_race "$EXP/dns_race.c"
sudo rm -f /tmp/pano-exp/dns.pano
sudo target/release/panopticon run /tmp/pano-exp/dns.pano >/tmp/pano-exp/dns-agent.log 2>&1 &
for _ in $(seq 100); do grep -q ready /tmp/pano-exp/dns-agent.log && break; sleep 0.1; done
sudo python3 "$EXP/dns_listen.py" >/tmp/pano-exp/dns-wire.txt 2>&1 &
listener=$!
for _ in $(seq 100); do grep -q listening /tmp/pano-exp/dns-wire.txt && break; sleep 0.1; done
/tmp/pano-exp/dns_race 20000
wait "$listener"
sudo pkill -INT -x panopticon
while pgrep -x panopticon >/dev/null; do sleep 0.1; done
grep wire /tmp/pano-exp/dns-wire.txt
echo "agent:"
target/release/panopticon decode /tmp/pano-exp/dns.pano |
  jq -r 'select(.type == "dns_query" and (.exe | endswith("/dns_race"))) | .qname' | sort | uniq -c
