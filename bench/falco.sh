#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

LOADGEN=$PWD/target/release/loadgen
RULES=$PWD/bench/falco
OUT=${OUT:-$PWD/bench/results/$(date +%Y%m%dT%H%M%S)}
REPS=${REPS:-3}
SECS=${SECS:-10}
KSRC=${KSRC:-/tmp/kbuild/linux-7.0}
CONDITIONS=(${CONDITIONS:-none noop-syscall-tp noop-precise falco-default falco-telemetry})
HZ=$(getconf CLK_TCK)

FALCO_ARGS=(
  -o syslog_output.enabled=false -o log_syslog=false -o webserver.enabled=false
  -o json_output=true -o stdout_output.enabled=true
  -o metrics.enabled=true -o metrics.interval=2s -o metrics.output_rule=false
)
NOOP_SYSCALL_TP='rawtracepoint:vmlinux:sys_exit {}'
NOOP_PRECISE='rawtracepoint:vmlinux:sched_process_exec {} rawtracepoint:vmlinux:sched_process_fork {}
rawtracepoint:vmlinux:sched_process_exit {} fentry:vmlinux:security_file_open {}
fentry:vmlinux:security_socket_connect {} fentry:vmlinux:security_socket_accept {} fentry:vmlinux:udp_sendmsg {}'

WORKLOADS=(
  "idle"
  "getppid-1 getppid 1"
  "exec-1 exec 1 /tmp/pano-true"
  "exec-16 exec 16 /tmp/pano-true"
  "connect-1 connect 1"
  "connect-16 connect 16"
  "udp-1 udp 1"
  "udp-16 udp 16"
  "open-1 open 1 /usr/lib/os-release"
  "open-shadow-1 open 1 /etc/shadow"
  "unix-1 unix 1"
  "signal-1 signal 1"
)

ACTIONS=(
  exec memfd-exec reparent-exec setuid-exec
  tcp4-connect tcp6-connect udp4-sendto tcp-listen packet-socket unix-connect-docker
  open-shadow file-create file-chmod-suid file-chown file-rename file-hardlink file-symlink
  file-timestomp file-truncate file-setxattr file-unlink
  uring-open-shadow uring-file-create uring-connect
  module-load sysctl-write bpf-prog-load mount-tmpfs unshare-ns setns setuid capset
  ptrace-attach proc-mem-write process-vm-writev pidfd-getfd kill mprotect-exec mmap-exec-file
  kexec-attempt settime-attempt
)

agent_job=""
agent_pid=""

now() { date +%s.%N; }

wait_for() {
  for _ in $(seq 600); do
    grep -q "$2" "$1" 2>/dev/null && return
    sleep 0.1
  done
  echo "timeout waiting for '$2' in $1" >&2
  exit 1
}

start_falco() {
  local tag=$1
  shift
  sudo falco "${FALCO_ARGS[@]}" -o metrics.output_file="$OUT/$tag.metrics.jsonl" "$@" \
    >"$OUT/$tag.alerts.jsonl" 2>"$OUT/$tag.log" &
  agent_job=$!
  wait_for "$OUT/$tag.log" "Opening 'syscall' source"
  sleep 5
  agent_pid=$(pgrep -nx falco)
}

start_bpftrace() {
  local tag=$1
  sudo bpftrace -e "$2" >"$OUT/$tag.log" 2>&1 &
  agent_job=$!
  wait_for "$OUT/$tag.log" "Attached"
  agent_pid=$(pgrep -nx bpftrace)
}

start_pano() {
  local tag=$1
  sudo "$PWD/target/release/panopticon" run "$OUT/$tag.pano" 2>"$OUT/$tag.log" &
  agent_job=$!
  wait_for "$OUT/$tag.log" "ready"
  agent_pid=$(pgrep -nx panopticon)
}

start_agent() {
  local cond=$1 tag=$2
  case $cond in
    none) ;;
    noop-syscall-tp) start_bpftrace "$tag" "$NOOP_SYSCALL_TP" ;;
    noop-precise) start_bpftrace "$tag" "$NOOP_PRECISE" ;;
    falco-default) start_falco "$tag" ;;
    falco-telemetry) start_falco "$tag" -r "$RULES/telemetry_rules.yaml" ;;
    pano) start_pano "$tag" ;;
    *) echo "unknown condition $cond" >&2; exit 1 ;;
  esac
}

stop_agent() {
  [[ -n $agent_pid ]] && sudo kill -INT "$agent_pid"
  [[ -n $agent_job ]] && wait "$agent_job" || true
  agent_job=""
  agent_pid=""
}
trap stop_agent EXIT

agent_ticks() { if [[ -n $agent_pid ]]; then awk '{print $14 + $15}' "/proc/$agent_pid/stat"; else echo 0; fi; }
agent_rss_kb() { if [[ -n $agent_pid ]]; then awk '/^VmRSS/ {print $2}' "/proc/$agent_pid/status"; else echo 0; fi; }

record() {
  local file=$1 cond=$2 rep=$3 name=$4 t0=$5 t1=$6 c0=$7 c1=$8 result=$9
  jq -c --arg cond "$cond" --argjson rep "$rep" --arg name "$name" --argjson t0 "$t0" --argjson t1 "$t1" \
    --argjson agent_cpu_s "$(awk -v a="$c0" -v b="$c1" -v hz="$HZ" 'BEGIN {printf "%.2f", (b - a) / hz}')" \
    --argjson agent_rss_kb "$(agent_rss_kb)" \
    '. + {cond: $cond, rep: $rep, name: $name, t0: $t0, t1: $t1, agent_cpu_s: $agent_cpu_s, agent_rss_kb: $agent_rss_kb}' \
    <<<"$result" >>"$file"
}

overhead() {
  cp /usr/bin/true /tmp/pano-true
  for rep in $(seq "$REPS"); do
    for cond in "${CONDITIONS[@]}"; do
      start_agent "$cond" "overhead-$cond-$rep"
      for w in "${WORKLOADS[@]}"; do
        read -r name workload threads path <<<"$w"
        local t0 c0 result
        t0=$(now)
        c0=$(agent_ticks)
        if [[ $name == idle ]]; then
          sleep "$SECS"
          result='{"workload":"idle","threads":0,"secs":'"$SECS"',"ops":0,"ops_per_sec":0}'
        else
          result=$(sudo "$LOADGEN" bench "$workload" "$threads" "$SECS" ${path:+"$path"})
        fi
        record "$OUT/overhead.jsonl" "$cond" "$rep" "$name" "$t0" "$(now)" "$c0" "$(agent_ticks)" "$result"
        [[ $cond == pano ]] && sudo truncate -s 0 "$OUT/overhead-$cond-$rep.pano"
        sleep 3
      done
      stop_agent
    done
  done
}

kbuild() {
  if [[ ! -f $KSRC/.config ]]; then
    mkdir -p "$(dirname "$KSRC")"
    curl -sSL "https://cdn.kernel.org/pub/linux/kernel/v7.x/$(basename "$KSRC").tar.xz" | tar xJ -C "$(dirname "$KSRC")"
    make -C "$KSRC" -s defconfig
  fi
  for rep in $(seq "$REPS"); do
    for cond in "${CONDITIONS[@]}"; do
      make -C "$KSRC" -s clean
      start_agent "$cond" "kbuild-$cond-$rep"
      local t0 c0 t1
      t0=$(now)
      c0=$(agent_ticks)
      make -C "$KSRC" -s -j"$(nproc)" vmlinux >/dev/null
      t1=$(now)
      record "$OUT/kbuild.jsonl" "$cond" "$rep" kbuild "$t0" "$t1" "$c0" "$(agent_ticks)" \
        "{\"workload\":\"kbuild\",\"secs\":$(awk -v a="$t0" -v b="$t1" 'BEGIN {print b - a}')}"
      stop_agent
    done
  done
}

probe_container() {
  local tag=$1 runtime=$2 uplink
  uplink=$(ip route show default | awk '{print $5; exit}')
  sudo timeout 30 tcpdump -i "$uplink" -nn -c 1 'tcp[tcpflags] & tcp-syn != 0 and dst host 1.1.1.1 and dst port 80' \
    >"$OUT/$tag.wire-$runtime.txt" 2>/dev/null &
  local dump=$!
  sleep 1
  local script='cat /etc/shadow >/dev/null; wget -q -T 3 -O /dev/null http://1.1.1.1/; echo pano-ctr'
  case $runtime in
    docker) docker run --rm docker.io/library/redis:7-alpine sh -c "$script" || true ;;
    k3s)
      sudo k3s kubectl run pano-probe --image=docker.io/library/redis:7-alpine --image-pull-policy=IfNotPresent \
        --restart=Never --command -- sh -c "$script" >/dev/null
      sudo k3s kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/pano-probe --timeout=60s >/dev/null || true
      sudo k3s kubectl delete pod pano-probe --wait=false >/dev/null
      ;;
  esac
  wait "$dump" || true
}

coverage() {
  for pass in ${COVERAGE_PASSES:-capability default-rules pano}; do
    local tag=coverage-$pass
    case $pass in
      capability) start_falco "$tag" -r "$RULES/coverage_rules.yaml" -o base_syscalls.all=true ;;
      default-rules) start_falco "$tag" ;;
      pano) start_pano "$tag" ;;
    esac
    for action in "${ACTIONS[@]}"; do
      local t0 result
      t0=$(now)
      if [[ $action == setuid-exec ]]; then
        result=$("$LOADGEN" act "$action")
      else
        result=$(sudo "$LOADGEN" act "$action")
      fi
      jq -nc --arg action "$action" --arg result "$result" --argjson t0 "$t0" --argjson t1 "$(now)" \
        '{action: $action, result: $result, t0: $t0, t1: $t1}' >>"$OUT/$tag.actions.jsonl"
      sleep 0.5
    done
    for runtime in docker k3s; do
      local t0
      t0=$(now)
      probe_container "$tag" "$runtime"
      jq -nc --arg action "container-$runtime" --argjson t0 "$t0" --argjson t1 "$(now)" \
        '{action: $action, t0: $t0, t1: $t1}' >>"$OUT/$tag.actions.jsonl"
      sleep 1
    done
    sleep 3
    stop_agent
  done
}

bpfstats() {
  cp /usr/bin/true /tmp/pano-true
  sudo sysctl -q kernel.bpf_stats_enabled=1
  for cond in "${CONDITIONS[@]}"; do
    [[ $cond == none ]] && continue
    local base_ids
    base_ids=$(sudo bpftool prog show -j | jq -c '[.[].id]')
    start_agent "$cond" "bpfstats-$cond"
    for w in "${WORKLOADS[@]}"; do
      read -r name workload threads path <<<"$w"
      local before result
      before=$(sudo bpftool prog show -j)
      if [[ $name == idle ]]; then
        sleep "$SECS"
        result='{"workload":"idle","threads":0,"secs":'"$SECS"',"ops":0,"ops_per_sec":0}'
      else
        result=$(sudo "$LOADGEN" bench "$workload" "$threads" "$SECS" ${path:+"$path"})
      fi
      sudo bpftool prog show -j | jq -c --arg cond "$cond" --arg name "$name" --argjson base "$base_ids" \
        --argjson before "$before" --argjson result "$result" '
        ($before | map({key: (.id | tostring), value: .}) | from_entries) as $b
        | {cond: $cond, name: $name, result: $result,
           progs: [.[] | select(.id as $id | $base | index($id) | not)
                   | {id, name, type,
                      run_cnt: ((.run_cnt // 0) - ($b[.id | tostring].run_cnt // 0)),
                      run_time_ns: ((.run_time_ns // 0) - ($b[.id | tostring].run_time_ns // 0))}
                   | select(.run_cnt > 0)]}' >>"$OUT/bpfstats.jsonl"
      sleep 2
    done
    stop_agent
  done
  sudo sysctl -q kernel.bpf_stats_enabled=0
}

mkdir -p "$OUT"
echo "results: $OUT"
for cmd in "$@"; do
  "$cmd"
done
