#!/usr/bin/env python3
import bisect
import functools
import json
import os
import pathlib
import statistics
import subprocess
import sys
from collections import defaultdict

CONDS = ["none", "noop-syscall-tp", "noop-precise", "falco-default", "falco-telemetry", "pano"]
LOADGEN = str(pathlib.Path(__file__).resolve().parent.parent / "target/release/loadgen")
ALERTS = {
    "exec": ('"rule":"tel_exec"', '"proc.exepath":"/tmp/pano-true"'),
    "net": ('"rule":"tel_net"', f'"proc.exepath":"{LOADGEN}"'),
    "shadow_tel": ('"rule":"tel_file_open"', '"fd.name":"/etc/shadow"'),
    "shadow_default": ('"rule":"Read sensitive file untrusted"', f'"proc.exepath":"{LOADGEN}"'),
}
HEADER = (
    "| workload | condition | ops/s or build s | slowdown % | added ns/op | agent cores "
    "| agent RSS MB | kernel drops % | alerts delivered % |"
)


def jsonl(path):
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("{"):
            yield json.loads(line)


def scap_series(path):
    if not path.exists():
        return []
    fields = (m["output_fields"] for m in jsonl(path))
    return sorted((f["evt.time"] / 1e9, f["scap.n_evts"], f["scap.n_drops"]) for f in fields)


def scap_drop_pct(series, t0, t1):
    before = [s for s in series if s[0] <= t0]
    after = [s for s in series if s[0] >= t1] or [s for s in series if s[0] <= t1][-1:]
    if not before or not after:
        return None
    events, drops = after[0][1] - before[-1][1], after[0][2] - before[-1][2]
    return 100 * drops / (events + drops) if events + drops else 0.0


@functools.cache
def alert_times(path, category):
    rule, field = ALERTS[category]
    cmd = f"grep -F '{rule}' '{path}' | grep -F '{field}' | grep -oE '\"evt.time\":[0-9]+' | cut -d: -f2"
    env = {**os.environ, "LC_ALL": "C"}
    found = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env).stdout
    return sorted(int(t) / 1e9 for t in found.split())


def expected_alerts(row):
    cond, name, ops = row["cond"], row["name"], row.get("ops")
    if cond == "falco-telemetry":
        if name.startswith("exec"):
            return ops, "exec"
        if name.startswith("connect"):
            return 2 * ops, "net"
        if name.startswith("open-shadow"):
            return ops, "shadow_tel"
    if cond == "falco-default" and name.startswith("open-shadow"):
        return ops, "shadow_default"
    return None, None


def pano_series(path):
    if not path.exists():
        return []
    rows = (line.split() for line in path.read_text().splitlines() if line.startswith("stats "))
    return sorted((int(r[1]) / 1000, *map(int, r[2:])) for r in rows)


def pano_window(series, t0, t1):
    before = [s for s in series if s[0] <= t0]
    after = [s for s in series if s[0] >= t1]
    if not before or not after:
        return None
    return [a - b for a, b in zip(after[0][1:], before[-1][1:])]


def annotate_pano(r, log):
    delta = pano_window(pano_series(log), r["t0"], r["t1"])
    if delta is None:
        return
    proc, net, file, drops, coalesced = delta
    r["drop_pct"] = 100 * drops / (proc + net + file + drops) if proc + net + file + drops else 0.0
    name, ops = r["name"], r.get("ops")
    if name.startswith("exec"):
        r["delivered_pct"] = 100 * proc / ops
    elif name.startswith("connect"):
        r["delivered_pct"] = 100 * net / (2 * ops)
    elif name.startswith("open-shadow"):
        r["delivered_pct"] = 100 * (file + coalesced) / ops


def annotate(out, prefix, rows):
    for r in rows:
        tag = out / f"{prefix}-{r['cond']}-{r['rep']}"
        if r["cond"] == "pano":
            annotate_pano(r, tag.with_name(tag.name + ".log"))
            continue
        if not r["cond"].startswith("falco"):
            continue
        r["drop_pct"] = scap_drop_pct(scap_series(tag.with_name(tag.name + ".metrics.jsonl")), r["t0"], r["t1"])
        want, category = expected_alerts(r)
        if want:
            times = alert_times(tag.with_name(tag.name + ".alerts.jsonl"), category)
            got = bisect.bisect_right(times, r["t1"]) - bisect.bisect_left(times, r["t0"])
            r["delivered_pct"] = 100 * got / want


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def fmt(value, spec):
    return "" if value is None else format(value, spec)


def print_table(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["name"], r["cond"])].append(r)
    print(HEADER)
    print("|" + "---|" * (HEADER.count("|") - 1))
    for name in dict.fromkeys(r["name"] for r in rows):
        base = median(r["per_op_s"] for r in groups.get((name, "none"), []))
        for cond in CONDS:
            rs = groups.get((name, cond))
            if not rs:
                continue
            per_op = median(r["per_op_s"] for r in rs)
            shown = median(r["secs"] if name == "kbuild" else r["ops_per_sec"] for r in rs)
            slowdown = 100 * (per_op / base - 1) if per_op and base else None
            added = 1e9 * (per_op - base) if per_op and base and name != "kbuild" else None
            print(
                f"| {name} | {cond} | {fmt(shown, ',.2f' if name == 'kbuild' else ',.0f')} | {fmt(slowdown, '+.1f')} "
                f"| {fmt(added, '+.0f')} | {median(r['agent_cpu_s'] / r['secs'] for r in rs):.2f} "
                f"| {max(r['agent_rss_kb'] for r in rs) / 1024:.0f} | {fmt(median(r.get('drop_pct') for r in rs), '.1f')} "
                f"| {fmt(median(r.get('delivered_pct') for r in rs), '.1f')} |"
            )


def main():
    out = pathlib.Path(sys.argv[1])
    for prefix in ("overhead", "kbuild"):
        path = out / f"{prefix}.jsonl"
        if not path.exists():
            continue
        rows = list(jsonl(path))
        for r in rows:
            if prefix == "kbuild":
                r["per_op_s"] = r["secs"]
            else:
                r["per_op_s"] = r["threads"] / r["ops_per_sec"] if r["ops"] else None
        annotate(out, prefix, rows)
        print_table(rows)
        print()


main()
