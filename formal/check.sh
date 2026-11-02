#!/usr/bin/env bash
# Runs every TLC model and the TLAPS proof in formal/.  Safe configurations
# must pass; unsafe ones must fail with their expected property.  Exits
# non-zero on any other outcome.
#
#   formal/check.sh               run everything
#   formal/check.sh Ring Udp      run only the named configurations (or
#                                 TLAPS for the RingProof proof)
#
# TLC runs pinned to FORMAL_CPUS (default 24-31) with FORMAL_WORKERS
# (default 8) workers; benchmarks use the other CPUs.  Logs and the summary
# table go to formal/out/.
set -euo pipefail
cd "$(dirname "$0")"

CPUS=${FORMAL_CPUS:-24-31}
WORKERS=${FORMAL_WORKERS:-8}
JAVA_HEAP=${FORMAL_JAVA_HEAP:-16g}

TLA_URL=https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
TLA_SHA256=011267fca25d0752cf18894dd585cd28b96960c112ea8a20b823ea770e7e10cd
TLAPM_URL=https://github.com/tlaplus/tlapm/releases/download/1.6.0-pre/tlapm-1.6.0-pre-x86_64-linux-gnu.tar.gz
TLAPM_SHA256=39620b869ed939d991f5e2c4d604d84d16c05c5dd95787a1e5f47da296746b7b

# spec config expected (pass, or the property TLC must report violated)
MODELS=(
    "Ring Ring pass"
    "Ring RingProducerOnly pass"
    "Ring RingLarge pass"
    "Ring RingRelaxHead NoPartialRead"
    "Ring RingRelaxTail NoOverwrite"
    "Ring RingSmallSlack MemSafe"
    "Ring RingOverrun NoOverwrite"
    "MultiCtx MultiPlain Exclusive"
    "MultiCtx MultiBusy pass"
    "MultiCtx MultiBusyNMI pass"
    "MultiCtx MultiBusyAnyNest pass"
    "MultiCtx MultiBusyFree pass"
    "MultiCtx MultiBusyPlainFlagFree BusyMirrorsHolder"
    "MultiCtx MultiBusyPlainFlag pass"
    "MultiCtx MultiBusyPlainDrops Accounting"
    "MultiCtx MultiBusyWitness NoContentionDrop"
    "MultiCtx MultiSplit pass"
    "MultiCtx MultiSplitWitness NoNestedAccept"
    "MultiCtx MultiGuard pass"
    "MultiCtx MultiGuardWitness NoMiss"
    "MultiCtx MultiTasks pass"
    "MultiCtx MultiTasksNoPreemptOff Exclusive"
    "MultiCtx MultiTasksGuardWitness NoMiss"
    "MultiCtx MultiTasksBusy pass"
    "MultiCtx MultiGuardBusy pass"
    "FileCoalesce FileNoReuse pass"
    "FileCoalesce FileLag pass"
    "FileCoalesce FileOverflow pass"
    "FileCoalesce FileDelFail pass"
    "FileCoalesce FileTable pass"
    "FileCoalesce FileReuse AttributionCorrect"
    "FileCoalesce FileReuseLoss NoLoss"
    "FileCoalesce FileOverflowWitness NoSaturated"
    "FileCoalesce FileLateWitness NoLateRepeat"
    "FileCoalesce FileGoneWitness RecordsPerWindow"
    "FileCoalesce FileLostWitness RecordsPerWindow"
    "FileCoalesce FileStaleWitness RecordsPerWindow"
    "FileCoalesce FileTableWitness DeletedWithinWP"
    "FileCoalesceLRU FileLRUNoEvict pass"
    "FileCoalesceLRU FileLRUEvict pass"
    "FileCoalesceLRU FileLRUAny LossOnlyByEviction"
    "FileCoalesceLRU FileLRUEvictWitness AttributionCorrect"
    "HostSafety HostSafety pass"
    "HostSafety HostSafetyWait HostProgress"
    "UdpDedup Udp pass"
    "UdpDedup UdpRace RecordBound"
    "UdpDedup UdpWrap pass"
    "UdpDedup UdpWrapPreFix RecordBound"
)

fetch() {
    local url=$1 sha=$2 out=$3
    curl -fsSL -o "$out.tmp" "$url"
    echo "$sha  $out.tmp" | sha256sum -c --quiet -
    mv "$out.tmp" "$out"
}

mkdir -p tools out
if [[ ! -f tools/tla2tools.jar ]]; then
    fetch "$TLA_URL" "$TLA_SHA256" tools/tla2tools.jar
fi
if [[ ! -x tools/tlapm/bin/tlapm ]]; then
    fetch "$TLAPM_URL" "$TLAPM_SHA256" tools/tlapm.tar.gz
    tar -xzf tools/tlapm.tar.gz -C tools
    rm tools/tlapm.tar.gz
fi

ONLY=("$@")
selected() {
    [[ ${#ONLY[@]} -eq 0 ]] && return 0
    local o
    for o in "${ONLY[@]}"; do
        [[ $o == "$1" ]] && return 0
    done
    return 1
}

elapsed() {
    local ms=$(( ($(date +%s%N) - $1) / 1000000 ))
    printf '%d.%d' $((ms / 1000)) $(((ms % 1000) / 100))
}

summary=out/summary.md
{
    echo "| Config | Spec | Expected | Result | Distinct states | Depth | Trace | Time (s) |"
    echo "|---|---|---|---|---|---|---|---|"
} > "$summary"

fail=0
for m in "${MODELS[@]}"; do
    read -r spec cfg expected <<< "$m"
    selected "$cfg" || continue
    log=out/$cfg.log
    start=$(date +%s%N)
    taskset -c "$CPUS" java -XX:+UseParallelGC -Xmx"$JAVA_HEAP" -cp tools/tla2tools.jar tlc2.TLC \
        -workers "$WORKERS" -noGenerateSpecTE -cleanup -metadir "out/states/$cfg" \
        -config "cfg/$cfg.cfg" "$spec.tla" > "$log" 2>&1 || true
    secs=$(elapsed "$start")
    rm -rf "out/states/$cfg"

    if grep -q "^Model checking completed. No error has been found." "$log"; then
        result=pass
    elif v=$(grep -oP '^Error: Invariant \K\w+(?= is violated)' "$log"); then
        result=$v
    elif v=$(grep -oP '^Error: Temporal property \K\w+(?= was violated)' "$log"); then
        result=$v
    elif grep -q "^Error: Deadlock reached" "$log"; then
        result=deadlock
    else
        result=error
    fi
    distinct=$(grep -oP '\d+ states generated, \K\d+(?= distinct states found)' "$log" | tail -1 || true)
    depth=$(grep -oP 'The depth of the complete state graph search is \K\d+' "$log" | tail -1 || true)
    trace=$(grep -cE '^State [0-9]+:' "$log" || true)
    [[ $result == pass ]] && trace=-

    status=ok
    if [[ $result != "$expected" ]]; then
        status=UNEXPECTED
        fail=1
    fi
    printf '%-26s %-13s expected %-19s got %-19s %12s states %8ss  %s\n' \
        "$cfg" "$spec" "$expected" "$result" "${distinct:-?}" "$secs" "$status"
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
        "$cfg" "$spec" "$expected" "$result" "${distinct:-?}" "${depth:-?}" "$trace" "$secs" >> "$summary"
done

if selected RingProof; then
    log=out/RingProof.log
    start=$(date +%s%N)
    taskset -c "$CPUS" tools/tlapm/bin/tlapm --cleanfp --threads "$WORKERS" \
        -I tools/tlapm/lib/tlapm/stdlib RingProof.tla > "$log" 2>&1 || true
    secs=$(elapsed "$start")
    if n=$(grep -oP 'All \K\d+(?= obligations proved)' "$log"); then
        printf '%-26s %-13s %s obligations proved %22ss  ok\n' RingProof TLAPS "$n" "$secs"
        echo >> "$summary"
        printf 'TLAPS RingProof.tla: all %s obligations proved in %s s.\n' "$n" "$secs" >> "$summary"
    else
        printf '%-26s %-13s proof failed, see %s  UNEXPECTED\n' RingProof TLAPS "$log"
        fail=1
    fi
fi

echo "summary: formal/$summary"
exit $fail
