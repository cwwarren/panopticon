# Panopticon design

Working document. Each decision cites a measurement in this repo or is marked as a hypothesis.

Reference host: Ryzen 9 9950X (16 cores, 32 threads), Ubuntu 26.04, kernel 7.0, `PREEMPT` full (lazy), `HZ=1000`.
The host runs vLLM, k3s with Cilium, ClickHouse and Docker, so it is not quiet; benchmarks interleave
conditions and report medians.

## Goal

Collect host security telemetry at the lowest possible cost to the host.

Collected:

- Process starts, which carry most of the security value, with attribution: spawner, binary, user and
  session, container.
- Network attribution: the process and container behind a connection, keyed so it joins against network
  flow logs, including the post-NAT tuple.
- DNS queries and answers on the standard resolver paths.
- Access to a fixed list of sensitive files and directories.
- Privileged kernel and admin operations: module load, BPF load, sysctl writes, mounts and namespaces,
  cross-process memory access, credential changes, kexec, clock changes.
- Sensor health: losses per event class.

Not collected: payloads, flow volume (the network side has it), on-host detection rules, prevention.
Kernels without the features listed under [Transport](#transport) are not supported.

## Principles

The target is two orders of magnitude less impact than existing agents. It comes from not doing work,
not from optimizing work that should not happen.

1. **Pay nothing for unrelated activity.** Hook semantic kernel points, never syscall entry or exit.
   Where the kernel already indexes what matters (fsnotify marks, NAT setup, exec), let that index
   decide whether our code runs at all.
2. **Never mirror kernel state.** Read the kernel object when the event happens instead of rebuilding
   it from a stream of state-tracking syscalls.
3. **Self-contained records keyed by kernel identities.** No global ordering, no userspace process
   table, no `/proc` lookups on the event path.
4. **Decide in the kernel.** Filter and deduplicate where the data lives; userspace copies bytes.
5. **Fixed-cost transport.** Per-CPU, per-class lock-free rings. No locks, no consumer wakeups, no
   nanosecond timestamps.
6. **Loss is data.** Every ring counts its drops and the stream reports them.
7. **Every decision has a benchmark.** If a choice cannot be measured here, it is a hypothesis.

## Evidence

### Falco 0.45.2 baseline

`bench/falco.sh`, results in `bench/results/falco-0.45.2/` (raw logs and metrics are not committed).
Medians of 3 interleaved 10-second runs. "Telemetry" is Falco with
`bench/falco/telemetry_rules.yaml`, which approximates our requirements.

| Workload (rate without agent) | Falco default: slowdown, added/op | Falco CPU | Kernel drops | Telemetry records delivered |
|---|---|---|---|---|
| getppid, 1 thread (24.5M/s) | +56%, +23 ns | 0.01 | 0% | n/a |
| exec, 1 thread (7.4k/s) | +6.1%, +8.2 µs | 9.3 µs/exec (25 µs with telemetry output) | 0% | 100% |
| exec, 16 threads (58k/s) | +3.3% | 0.60 cores | 0% (8.7% telemetry) | 69% |
| connect+accept, 1 thread (88k/s) | +8.4%, +0.96 µs | 1.9 µs/conn | 0% (31% telemetry) | 53% |
| connect+accept, 16 threads (937k/s) | +5.9% | 1.00 (saturated) | 39% | 6% |
| UDP sendto, 1 thread (579k/s) | +12%, +206 ns | 0.14 | 0% | n/a |
| open+close, 1 thread (2.2M/s) | +70%, +316 ns | 1.00 (saturated) | 25% | n/a |
| kernel build, `-j32` (50.3 s) | +2.3% | 0.48 cores | 0% | n/a |

Memory: 355 MB RSS idle, ~450 MB under telemetry load, plus 128 MB of kernel ring buffers.

Coverage, from 43 probe actions (`loadgen act`, `bench/falco.sh coverage`):

- Stock rules alerted on 6 of 43.
- Operations submitted through io_uring (file open/read/write/unlink, socket, connect) are invisible to
  Falco's syscall hooks.
- 272 of the 434 syscalls in Falco's schema are captured without arguments (utimensat, truncate,
  setxattr, kexec_file_load, clock_settime, the new mount API, ...).
- Container connections are reported pre-NAT: `172.17.0.2:39686→1.1.1.1:80` in Falco,
  `192.168.1.18:39686` on the wire.
- After reparenting, an orphan's parent is reported as the reaper (`systemd`); the spawner is lost.

What causes the cost, by measurement:

- One BPF dispatcher on `sys_exit` runs for every syscall on the host: 17–20 ns of BPF per call plus
  14 ns for the raw tracepoint itself. vLLM's engine issues 1.3–2.7M `sched_yield`/s on this host, which
  puts ~0.03–0.06 cores of Falco's cost on vLLM while Falco reports 0.01 cores for itself (computed).
- Every open/close/socket/dup is captured to maintain fd tables in userspace: +316 ns per open of an
  uninteresting file.
- One userspace thread does all parsing, state, rule evaluation and JSON output. At one core it drops
  events of every class; a single thread looping `open()` causes 25% drops. Output tops out at
  40–110k alerts/s.
- Each exec copies argv, the full environment and cgroup path strings in the kernel (1.6–2.2 µs of BPF).

### Hook placement floor

Empty BPF programs, measured with the same workloads (`noop-*` conditions above):

| Hook | getppid | open+close | kernel build |
|---|---|---|---|
| `sys_exit` raw tracepoint (Falco's attach point) | +14 ns (+35%) | +36 ns | +0.3% |
| Semantic hooks (sched exec/fork/exit, `security_file_open`, `security_socket_connect`, `security_socket_accept`, `udp_sendmsg`) | 0 | +14 ns | −0.1% (noise) |

### Transport

`bench/ringbench.sh` (`crates/ringbench`), results in `bench/results/ringbench/`. A program on
`__do_sys_getppid` (42 ns per call), producer and consumer pinned to separate cores, medians of 5×5 s.
Each row adds to the ones above it unless noted.

| Per event | Added vs no hook |
|---|---|
| Empty fentry | +3.6 ns |
| Read pid/tgid, pidfs inode, cgroup id | +8.2 ns |
| Plus jiffies timestamp | +8.6 ns |
| Plus `bpf_ktime_get_boot_ns` instead | +16.2 ns |
| **Emit to per-CPU lock-free ring, no kernel timestamp** | **+11.0 ns** |
| Same, with `bpf_ktime_get_boot_ns` | +21.8 ns |
| Shared `BPF_MAP_TYPE_RINGBUF` | +26.3 ns |
| One `RINGBUF` per CPU | +30.4 ns |
| Perf buffer, wakeup every 1024 events | +49.6 ns |
| Perf buffer, libbpf default (wakeup every event) | +541 ns |

With 16 producers at 8M events/s total (UDP sendto), the shared ring buffer costs +1,353 ns per event
(lock contention); the per-CPU variants stay within +23 to +85 ns, inside the run-to-run noise of a
2 µs operation. The lock-free consumer used 0.013 cores at 15M events/s.

### Gating with kernel indexes

Results in `bench/results/experiments/` (scripts alongside the data).

Sensitive files, open+close of a file not on the list (460 ns base, medians of 5):

| Mechanism | Added per unrelated open |
|---|---|
| Any BPF program on `security_file_open` | +12 ns (+2.7%) |
| Plus an inode-set hash lookup | no further measurable cost |
| inotify marks on the listed files | +1.5 ns (noise) |
| inotify marks plus BPF on `inotify_handle_inode_event` | −0.4 ns (noise) |

The gated hook runs synchronously in the opener's context and captured command, pid, cgroup and pidfs
inode for a host read, an io_uring read, and a read inside a container whose file was marked through
`/proc/<pid>/root`. A container whose copy was not marked was not seen: marks are per inode.
`inotify_handle_inode_event` runs for every inotify group on the host (omp, systemd, containerd and
systemd-networkd showed up), so the program must filter by group.

NAT, loopback connect+accept (87k connections/s on one thread, 949k/s on 16):

| Mechanism | 1 thread | 16 threads |
|---|---|---|
| ctnetlink NEW+DESTROY events | +1.53 µs/conn (+13%), listener ~0.2 cores | +1.87 µs/conn (+11%), listener saturated |
| `fexit/nf_nat_setup_info`, empty | +46 ns/conn (+0.4%), 2 calls per connection | noise |
| Same, comparing tuples (bpftrace) | +114 ns/conn (+1.0%) | noise |

One hook on `nf_nat_setup_info` captured Docker and k3s pod translations for TCP and UDP
(`172.17.0.2:41008→1.1.1.1:80` became `192.168.1.18:41008`; pod `10.42.0.99:52042` became
`192.168.1.18:52042`). This cluster's Cilium masquerades through iptables
(`enable-ipv4-masquerade=true`, no BPF masquerade, no kube-proxy replacement), so kernel NAT covers it.

### Identity

`struct pid` carries a 64-bit pidfs inode. BPF `task->group_leader->thread_pid->ino` equals userspace
`fstat(pidfd_open(pid)).st_ino` (verified 3/3). On 64-bit kernels it comes from a cookie allocator:
unique per boot, never reused, not monotonic across CPUs.

## Architecture

### Event classes

A class groups events that share a record family, a rate profile and an execution context. Each class
has its own ring on every CPU.

| Class | Hooks | Context | Records |
|---|---|---|---|
| proc | `tp_btf/sched_process_fork` (state only), `lsm.s/bprm_committed_creds`, `tp_btf/cgroup_mkdir` | process | exec, cgroup |
| net | `fexit/tcp_v4_connect`, `fexit/tcp_v6_connect`, `fexit/inet_csk_accept`, `fexit/inet_listen`, `fexit/udp_sendmsg`, `fentry/skb_consume_udp` | process | connect, accept, listen, UDP first send, DNS query, DNS answer |
| file | `fentry/inotify_handle_inode_event` (our group only), `iter/bpf_map_elem` on the coalescing map | process | sensitive file access, repeat count |
| nat | `fexit/nf_nat_setup_info` | process or softirq | NAT translation (planned) |
| admin | LSM hooks for module, bpf, mount, ptrace attach, setuid/capset, settime, kexec; `cgroup/sysctl` | process | admin operation (planned) |

Fork and exit produce no records. Exits are not observed at all.

### Identity and process records

- **Process key**: pidfs inode of the thread-group leader. Combined with the boot id it is unique
  forever, so pid reuse does not exist for consumers.
- **Image key**: (process key, `self_exec_id`) of the exec that loaded the code currently running.
  `self_exec_id` increments on every exec.
- **Spawner**: the process key of the parent at fork time, kept in task-local storage. Reparenting
  does not change it.
- At fork, the child's storage gets the spawner and inherits the parent's image key. At exec, the
  image key becomes the process's own. Network, file and admin records carry both the process key and
  the image key, so a child that forks without exec'ing joins back to the program it is running.
- One exec record per successful exec, emitted after the point of no return: process key, exec
  sequence, spawner, current parent, previous image key (the program that called exec), cgroup id,
  uid/euid/gid/egid, loginuid, sessionid, effective capabilities, executable dev/inode/ctime,
  executable path, argv (bounded, never the environment). The previous image key attributes an exec
  by a fork-only child (a subshell, a double-forked daemon) to the program it was running, without
  fork records.
- Processes that exist when the agent starts are emitted once by a BPF task iterator, in the same
  record format. The verifier rejects `bpf_d_path` on `mm->exe_file` (a walked, untrusted pointer)
  and the kfuncs that return a trusted file are LSM-only, so the agent fills these executable paths
  from `/proc/<pid>/exe` at startup.

Volume is one record per exec plus the one-time snapshot.

### Records

Records are packed binary, 8-byte aligned, with a 16-byte header (`u16 len`, `u8 type`, `u8 flags`,
`u32 reserved`, `u64 jiffies`). Kernel structs in `crates/agent/src/bpf/agent.bpf.c` are the schema;
the Rust types are generated from them through the BPF skeleton so the layouts cannot diverge. The
agent writes records as-is; decoding to JSON is a separate tool (`panopticon decode`).

Records reference each other only through kernel identities (process key, image key, socket cookie,
cgroup id, inode). The consumer drains rings one after another, so stream order is not time order;
the decoder indexes identities in a first pass and emits in a second.

Time is jiffies (1 ms at `HZ=1000`). Userspace emits a clock record (jiffies, `CLOCK_REALTIME`) every
second, and the decoder converts.

### Transport

Each class has, per CPU, a byte ring in a `BPF_F_MMAPABLE` array element of `size + slack` bytes. The
control block per (class, CPU) holds `head`, `tail` and `drops` on separate cache lines.

Producer:

1. `bpf_preempt_disable()`.
2. Load `tail` with acquire; if `head + max_record - tail > size`, count a drop.
3. Write the record at `head & (size - 1)`. A record that runs past the end continues into the slack
   bytes, so records are always contiguous and never split or padded.
4. Store `head + len` with release; `bpf_preempt_enable()`.

Consumer: one thread polls every ring every 10 ms, copies whole records to the output buffer, stores
`tail` with release. No syscalls per record, no wakeups.

Safety comes from the same structure that makes it fast:

- One ring per CPU means one producer per ring unless the producer is interrupted.
- Preemption is disabled for the few nanoseconds of the write.
- Each class's hooks run in a single kind of context, so an interrupt never re-enters the same ring.
  The nat class can run in softirq as well as process context and needs a per-ring busy flag (to be
  measured).

Kernel requirements: `bpf_preempt_disable` (6.10), BPF load-acquire/store-release (6.15), BPF LSM,
task and socket local storage.

All classes use the same mechanism. Sharing one ring between low-rate classes would save a few MB and
add a second code path.

Ring sizes are compile-time per class and sized from expected rate × poll interval × headroom. The
prototype uses 256 KiB per CPU for proc and net and 64 KiB for file (about 18 MiB on 32 CPUs).

### Userspace

One thread:

- Poll all rings; append whole records to an output buffer.
- Drain the inotify fd. Its events are not used (the BPF hook is the event source); draining keeps
  their kernel memory near zero and does not change the producer's cost (+87.4 ns per marked open
  drained, +89.2 ns never read).
- Once per second and at shutdown: clock record, a loss record for any ring whose drop counter
  moved, and the repeat records from the file coalescing iterator.
- Write the buffer to the sink.

No parsing on the hot path. Container metadata (image, pod) is resolved once per new cgroup, not per
record (planned).

### Containers

Records carry the cgroup id (`bpf_get_current_cgroup_id`, 8 bytes, ~2 ns). The proc class emits a
cgroup record with the path from `cgroup_mkdir`, and the agent emits records for cgroups that already
exist at start, so short-lived containers resolve even after their cgroup is gone. Container id comes
from the cgroup path (`docker-<id>.scope`, `cri-containerd-<id>.scope`); image and pod come from the
runtime API once per container (planned).

### Network attribution

The goal is a join key against network flows: socket cookie, protocol, the socket's own tuple, network
namespace, process key, image key, cgroup, time.

- TCP out: `fexit/tcp_v4_connect` and `tcp_v6_connect`, after the source port is assigned.
- TCP in: `fexit/inet_csk_accept`, in the accepting process.
- Listen: `fexit/inet_listen`.
- UDP, IPv4 only (`udpv6_sendmsg` is not hooked yet): `fexit/udp_sendmsg`. Each destination is
  checked against the socket's last 4 in socket-local storage, and a new one emits a record. After 16
  records the socket is flagged saturated and reports nothing more; its own tuple joins the rest of
  its flows. `connect()` on UDP without traffic is not recorded because no flow follows it.
- DNS, IPv4 only: every query payload from `udp_sendmsg` when the destination port is 53; the socket
  is tagged, and answers are copied from `skb_consume_udp` for tagged sockets only. Covers glibc and
  musl stub resolvers, systemd-resolved's stub, Docker's resolver paths and CoreDNS. Not covered: DoH,
  DoT, DoQ, TCP port 53, systemd-resolved's varlink clients.
- NAT (planned): `fexit/nf_nat_setup_info`, emitted only when the tuple was translated. Cilium with BPF
  masquerade keeps NAT state in its own map (`cilium_snat_v4_external`) and needs a version-pinned
  reader; not testable on this host.

### Sensitive files

A fixed list of files and directories, each with an event mask. Credential files (`/etc/shadow`,
`/etc/gshadow`, `/etc/sudoers`, SSH host keys): open, close after write, attribute change, move and
delete. Credential directories (`/etc/sudoers.d`, `~/.ssh`): the same plus entry create, delete and
move. Public but integrity-sensitive files (`/etc/passwd`, `/etc/group`, `/etc/ld.so.preload`): close
after write, attribute change, move and delete.

- The agent owns one inotify group with marks on the listed inodes, and learns the kernel address of
  that group from `fentry/inotify_update_watch`.
- `fentry/inotify_handle_inode_event` compares the mark's group with ours. The marked object is `dir`
  when the kernel passes one (an event on a child or on a directory entry), otherwise `inode`. The
  record carries the marked inode, the child inode and the entry name.
- Coalescing: the first event per (process key, `self_exec_id`, marked inode, child inode, mask) in a
  one-second window emits a record; later ones increment a counter in an LRU hash of 4096 keys. A
  `bpf_map_elem` iterator, read once per second and at shutdown, swaps each counter with zero and
  emits a repeat record. With `self_exec_id` in the key, a program exec'd by the process gets its own
  record instead of disappearing into the previous program's count.
- Containers: mark each container's copy through `/proc/<pid>/root/<path>` when the container starts
  (planned).
- Replacement by rename (e.g. `passwd` rewriting `/etc/shadow`): directory marks on the parents for
  create and move, then re-mark (planned).

Cost of an access to a listed file, open+close of `/etc/shadow` (`bench/results/experiments/marked_open.sh`,
medians of 5, 488 ns base):

| Condition | Added per open |
|---|---|
| inotify mark, no BPF, fd drained | +87.4 ns |
| inotify mark, no BPF, fd never read | +89.2 ns |
| pano | +118.3 ns |

Three quarters of it is the kernel allocating an inotify event that nobody reads. On 7.0, BPF cannot
skip that allocation: `inotify_handle_inode_event` is not error-injectable, so `fmod_ret` cannot
attach, and fanotify has no BPF hooks. Unlisted files pay nothing.

Limit: with more than 4096 keys active within one second, LRU eviction drops the pending counts of
evicted keys without a loss record. Every access after an eviction still emits a full record.

### Admin operations (planned)

LSM hooks fire only on the operation itself: `kernel_read_file`/`kernel_load_data` (modules, kexec),
`bpf_prog_load` (excluding the agent), `sb_mount`/`move_mount`/`sb_pivotroot`, `ptrace_access_check`
in attach mode only (covers ptrace, `/proc/<pid>/mem`, `process_vm_*`, `pidfd_getfd`), `task_fix_setuid`,
`capset`, `settime`. Sysctl writes come from a `cgroup/sysctl` program on the root cgroup. Namespace
creation is visible at fork by comparing `nsproxy`.

## Decision log

| Date | Decision | Evidence |
|---|---|---|
| 2026-10-31 | Hook semantic points, never syscall entry/exit | Floor table: +14 ns on every syscall vs 0 |
| 2026-10-31 | pidfs inode as process identity | BPF value equals `fstat(pidfd).st_ino`; 64-bit, never reused |
| 2026-11-02 | No fork or exit records; spawner and image key in task storage | Exec carries the value; fork/exit would multiply volume |
| 2026-11-02 | Per-CPU, per-class lock-free rings for every class | +11 ns per event vs +26 (shared RINGBUF, 1 thread) and +1,353 (shared, 16 threads) |
| 2026-11-02 | No rare-class ring sharing | Saves a few MB, adds a second code path |
| 2026-11-02 | Jiffies, not nanosecond timestamps | ktime costs ~8 ns of an 11 ns event; 1 ms is enough to join flows |
| 2026-11-02 | Sensitive files gated by fsnotify marks | 0 ns per unrelated open vs +12 ns for any `file_open` hook; catches io_uring |
| 2026-11-02 | NAT from `nf_nat_setup_info`, not ctnetlink | +46 ns/conn vs +1.53 µs/conn |
| 2026-11-02 | Kernel ≥ 6.15 only | Needed for preempt kfuncs and acquire/release; no fallback paths |
| 2026-11-02 | libbpf (C programs) with libbpf-rs userspace | Most mature CO-RE; skeleton generates Rust record types |
| 2026-11-02 | Exec record carries the previous image key | Attributes execs by fork-only children without fork records |
| 2026-11-02 | Keep fork-time task storage | 246 ns per fork (604 ns with 16 forkers), about 0.2% of a fork+exec; deriving the spawner at exec from `real_parent` loses it on reparenting, the double-fork case |
| 2026-11-02 | Coalesce sensitive-file events per (process, image, file, mask) per second in the kernel; flush counts with a map iterator | 3.3M-open flood: 3 records and exact counts, 0 drops; Falco: 49% drops, 4% of alerts delivered |
| 2026-11-02 | Snapshot executable paths from `/proc/<pid>/exe` | Verifier rejects `bpf_d_path` on `mm->exe_file`; trusted-file kfuncs are LSM-only |

## Open questions

- Cost of the remaining fexit trampolines. `udp_sendmsg` uses its return value only to skip failed
  sends and size the DNS payload; `fentry` would avoid the call-through. Measure before switching.
- Whether the per-ring busy flag for multi-context classes costs more than splitting rings by context.
- Output path: batch size, compression, transport to the collector.
- Container mark management for sensitive files at container start.

## Prototype status

`crates/agent`, binary `panopticon`. `panopticon run <file> [poll-ms]` loads the programs and appends
the record stream to a file; `panopticon decode <file>` prints one JSON object per record.

Implemented: the proc, net and file classes above, the startup snapshot, clock, loss and repeat
records, the decoder. Not implemented: nat and admin classes, container metadata and container file
marks, UDP over IPv6, shipping the stream off the host.

### Against Falco

`bench/falco.sh overhead` with the `pano` condition, results in `bench/results/prototype-2026-11-02/`
(run 2; run 1, taken before the file-class fixes below, agrees within noise). Medians of 3
interleaved 10-second runs. "Noop" is empty programs on the semantic hooks: the noise floor plus the
cost of attaching anything. Agent CPU below 0.001 cores is under the measurement's resolution.
Delivered is the share of the workload's operations present in the output; for the `/etc/shadow`
flood that is records plus repeat counts.

| Workload | Falco default | pano | Noop | Agent CPU, Falco / pano | Drops, Falco / pano | Delivered, pano |
|---|---|---|---|---|---|---|
| getppid, 1 thread | +57.8%, +23 ns | −0.5%, 0 ns | −0.5% | 0.005 / 0.001 | 0% / 0% | n/a |
| exec, 1 thread | +7.2%, +9.8 µs | +1.1%, +1.5 µs | +0.9%, +1.2 µs | 0.064 / 0.001 | 0% / 0% | 100% |
| exec, 16 threads | +4.5%, +12.5 µs | +1.2%, +3.2 µs | +1.0%, +2.7 µs | 0.600 / 0.005 | 0% / 0% | 100% |
| connect+accept, 1 thread | +8.5%, +964 ns | +1.0%, +110 ns | +0.5%, +55 ns | 0.154 / 0.005 | 0% / 0% | 100% |
| connect+accept, 16 threads | +8.3%, +1,403 ns | +1.1%, +179 ns | +0.4%, +74 ns | 1.00 / 0.048 | 30% / 0% | 100% |
| UDP sendto, 1 thread | +11.4%, +198 ns | +1.6%, +29 ns | +0.7%, +12 ns | 0.146 / <0.001 | 0% / 0% | n/a |
| UDP sendto, 16 threads | +17.2%, +347 ns | +1.8%, +37 ns | +0.4%, +9 ns | 1.00 / <0.001 | 36% / 0% | n/a |
| open+close, unlisted file | +70.3%, +320 ns | −0.2%, −1 ns | +2.4%, +11 ns | 1.00 / <0.001 | 25% / 0% | n/a |
| open+close of `/etc/shadow` | +54.7%, +264 ns | +23.0%, +111 ns | +2.7%, +13 ns | 1.11 / 0.001 | 49% / 0% | 100% (Falco 4.4%) |
| kernel build, `-j32` (run 1) | +2.5% | +0.1% | +0.1% | 0.481 / 0.002 | 0% / 0% | n/a |

Memory: 22–25 MB RSS, of which 18 MiB are the mapped rings, against Falco's 347 MB.

### Per-program cost

`bench/falco.sh bpfstats` (run 2): mean run time per invocation from `kernel.bpf_stats_enabled`,
which includes part of its own clock reads and excludes the trampoline.

| Program | 1 thread | 16 threads |
|---|---|---|
| `on_fork` (task storage allocation) | 245 ns | 596 ns |
| `on_exec` (record with path and argv) | 450 ns | 571 ns |
| `on_tcp4_connect` | 20 ns | 26 ns |
| `on_accept` | 20 ns | 24 ns |
| `on_udp_send` | 17 ns | 18 ns |
| `on_inotify_event` | 23 ns | n/a |
| `file_flush`, per map entry once per second | 20–30 ns | n/a |

A fork+exec costs 0.7 µs of our BPF on one thread, against 1.6–2.2 µs for Falco's exec programs alone.

### Against the target

- Unrelated activity costs nothing measurable (getppid, unlisted opens, the kernel build). Falco adds
  23 ns to every syscall and 320 ns to every open.
- Recorded events cost 4–9× less added time per operation than Falco (exec 3.9–6.7×, connect
  7.8–8.8×, UDP 6.8–9.4×), with no drops where Falco drops 25–49%. What remains is mostly the price
  of attaching anything: pano is 0.2–1.4 points above the noop floor.
- Agent CPU is 21× lower on connect+accept with 16 threads, the only workload where every operation
  becomes a record, 120× lower on exec with 16 threads, 200× on the kernel build, and more than
  1,000× on the UDP and open floods.
- Memory is 14× lower.

The 100× holds for unrelated activity and for agent CPU. Per recorded event it is 4–9×, and the
floor there is the trampoline plus the record write.

### Found by the functional runs

- In a double fork, the grandchild's spawner is a process that never exec'd, so no record named the
  program behind the grandchild's exec. The exec record now carries the previous image key; in the
  orphan test it names `loadgen`.
- The decoder assumed exec records precede the records that reference them. Rings are drained in
  sequence, so they do not; the decoder now indexes first.
- File coalescing keyed without the image: a program exec'd right after its process read a listed
  file vanished into the previous program's record (`sh -c 'exec 3</etc/shadow; exec cat /etc/shadow'`
  showed only `dash`). The key now includes `self_exec_id`.
- Directory-entry events (create and delete in `~/.ssh`) carried the child inode, so the path was
  lost. The marked object now comes from `dir`.
- Coalesced counts were reported only when the key fired again, so the last window's count was lost
  (424 of 3.4M opens). With the flush iterator, a 2-second flood of 3,276,638 opens produced 3
  records and 3,276,635 repeat counts.

### Next

1. nat class, and with it the open question of a busy flag versus split rings for softirq producers.
2. admin class: the LSM hooks and `cgroup/sysctl` listed above.
3. Container metadata from the runtime API, and file marks inside containers.
4. UDP over IPv6.
5. Shipping the stream off the host.
