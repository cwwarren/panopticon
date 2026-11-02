#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

REPS=${REPS:-3}
SECS=${SECS:-5}
OUT=${OUT:-$PWD/bench/results/ringbench-$(date +%Y%m%dT%H%M%S).jsonl}
VARIANTS=(${VARIANTS:-none empty filter context_nots context context_jiffies rb_shared_default rb_shared_out rb_percpu_out perf_out perf_out_batched spsc_out spsc_nots})
CASES=("__do_sys_getppid getppid 1 2" "udp_sendmsg udp 1 2" "udp_sendmsg udp 16 -")

mkdir -p "$(dirname "$OUT")"
for rep in $(seq "$REPS"); do
  for case in "${CASES[@]}"; do
    read -r target workload threads cpus <<<"$case"
    for variant in "${VARIANTS[@]}"; do
      pin=()
      [[ $cpus != - ]] && pin=(PRODUCER_CPUS="$cpus" CONSUMER_CPU=4)
      sudo "${pin[@]}" target/release/ringbench "$variant" "$target" "$workload" "$threads" "$SECS" |
        jq -c --argjson rep "$rep" '. + {rep: $rep}' >>"$OUT"
    done
  done
done

jq -rs '
  def median: sort | .[length / 2 | floor];
  group_by([.target, .result.workload, .result.threads]) | map(
    (map(select(.variant == "none") | .result.threads / .result.ops_per_sec * 1e9) | median) as $base
    | group_by(.variant) | map(
      (map(.result.threads / .result.ops_per_sec * 1e9) | median) as $ns
      | [
          "\(.[0].result.workload)-\(.[0].result.threads)", .[0].variant,
          ($ns * 10 | round / 10), (($ns - $base) * 10 | round / 10),
          (map(if .consumed + .drops > 0 then 100 * .drops / (.consumed + .drops) else 0 end) | median * 100 | round / 100),
          (map(.consumer_cpu_s / .result.secs) | median * 1000 | round / 1000)
        ]
    ) | sort_by(.[3])
  ) | flatten(1) | (["case", "variant", "ns/op", "added ns/op", "drop %", "consumer cores"] | @tsv), (.[] | @tsv)
' "$OUT" | column -t
echo "$OUT"
