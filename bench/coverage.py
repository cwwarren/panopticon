#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PANO = ROOT / "target/release/panopticon"
LOADGEN = str(ROOT / "target/release/loadgen")
CONTAINER = ("docker-", "kubepods", "cri-containerd")


def records(path):
    out = subprocess.run([PANO, "decode", path], capture_output=True, text=True, check=True).stdout
    return [json.loads(line) for line in out.splitlines()]


def from_probe(r):
    if r["type"] == "exec" and r["path"] == LOADGEN:
        return False
    return LOADGEN in (r.get("exe"), r.get("prev_exe"))


def label(r):
    t = r["type"]
    if t == "admin":
        return f"admin:{r['op']}"
    if t in ("file", "file_repeat"):
        target = r["path"] + ("/" + r["name"] if r.get("name") else "")
        return f"{t}:{'+'.join(r['mask'])}:{target}"
    if t == "exec":
        return f"exec:{r['path']}"
    if t in ("connect", "accept", "listen", "udp_send", "dns_query", "dns_answer"):
        return f"{t}:{r['dst']}"
    return t


def main():
    out = pathlib.Path(sys.argv[1])
    actions = [json.loads(line) for line in (out / "coverage-pano.actions.jsonl").read_text().splitlines()]
    recs = records(out / "coverage-pano.pano")
    cgroups = {r["id"]: r["path"] for r in recs if r["type"] == "cgroup"}

    def in_container(r):
        return any(c in cgroups.get(r.get("cgroup"), "") for c in CONTAINER)

    print("| action | panopticon records |")
    print("|---|---|")
    for a in actions:
        lo, hi = a["t0"] * 1000 - 50, a["t1"] * 1000 + 300
        match = in_container if a["action"].startswith("container-") else from_probe
        hits = sorted({label(r) for r in recs if lo <= r["ts"] <= hi and r["type"] != "exit" and match(r)})
        print(f"| {a['action']} | {', '.join(hits) or '—'} |")


if __name__ == "__main__":
    main()
