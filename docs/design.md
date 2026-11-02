# Panopticon design

Working document. Each decision cites a measurement in this repo or is marked as a hypothesis.

Reference host: Ryzen 9 9950X (16 cores, 32 threads), Ubuntu 26.04, kernel 7.0, `PREEMPT` full (lazy), `HZ=1000`.
The host runs vLLM, k3s with Cilium, ClickHouse and Docker, so it is not quiet; benchmarks interleave
conditions and report medians.

## Goal

Collect host security telemetry at the lowest possible cost to the host.

Collected:

- Process starts and ends, which carry most of the security value, with attribution: spawner, binary
  (path, SHA-256, file mode, link count, filesystem), user and session, terminal, container.
- Network attribution: the process and container behind a connection, keyed so it joins against network
  flow logs, including the post-NAT tuple. TCP and UDP over IPv4 and IPv6, raw and packet sockets,
  connections to container runtime sockets.
- DNS queries and answers on the standard resolver paths.
- Reads of credentials, and changes to persistence and integrity locations.
- Privileged kernel and admin operations: module and kexec loads, BPF loads, sysctl writes, mounts and
  namespaces, cross-process memory access, credential changes, clock changes; logins.
- Container identity: runtime, image, name, pod and namespace, privileged and host-namespace flags.
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
| proc | `tp_btf/sched_process_fork` (state only), `lsm.s/bprm_committed_creds`, `tp_btf/sched_process_exit`, `fexit/audit_set_loginuid`, `tp_btf/cgroup_mkdir` | process | exec, exit, login, cgroup |
| net | `fexit/tcp_v4_connect`, `fexit/tcp_v6_connect`, `fexit/inet_csk_accept`, `fexit/inet_listen`, `fexit/inet_bind` and `inet6_bind` (datagram sockets), `fentry/udp_send_skb`, `fentry/udp_v6_send_skb`, `fentry/skb_consume_udp`, `fexit/packet_create`, `fexit/raw_sk_init`, `fexit/rawv6_init_sk`, `lsm/unix_stream_connect` | process | connect, accept, listen, UDP bind, UDP first send, DNS query, DNS answer, raw socket, unix connect |
| file | `fentry/inotify_handle_inode_event` (our group only), `iter/bpf_map_elem` on the coalescing map | process | file access or change, repeat count |
| admin | LSM hooks for module and kexec loads, BPF loads, ptrace access in attach mode, traceme, uid/gid/capability changes, mount/move_mount/umount/pivot_root, settime, user namespaces, signals (`task_kill`), secure anonymous inodes, access to the agent's own BPF objects (`bpf_map`, `bpf_prog`); `fentry/proc_sys_write`; `fexit/create_new_namespaces` and the eight `*ns_install` callbacks | process | admin operation |
| nat | `fexit/nf_nat_setup_info` (`nf_nat` module), in its own BPF object | process or softirq | NAT translation |

Fork produces no records. Process exit produces one record when the last thread exits.

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
  uid/euid/gid/egid, loginuid, sessionid, effective capabilities, controlling terminal, working
  directory (dev, inode), executable dev/inode/ctime, mode, link count and filesystem magic, whether
  the executable sits on an overlayfs upper layer, whether stdin, stdout and stderr are sockets,
  executable path, argv (bounded, never the environment). The previous image key attributes an exec
  by a fork-only child (a subshell, a double-forked daemon) to the program it was running, without
  fork records. Mode, link count and filesystem make setuid binaries, deleted executables and memfd
  execution (`nlink` 0 on tmpfs) visible without extra hooks; the upper-layer flag marks a container
  running a binary it wrote or modified (drift, read through CO-RE on `ovl_inode` and skipped when
  the overlay module's BTF is absent); socket stdio marks reverse shells.
- Working directory: the exec record carries the directory's (dev, inode). The first exec in a
  directory not seen recently (LRU set of 4096) also emits a path record from a bounded dentry walk
  that crosses mounts up to the namespace root, so the path is container-relative inside containers.
  `bpf_d_path` cannot be used on `current->fs->pwd` (a walked pointer). Snapshot processes get their
  directory from `/proc/<pid>/cwd`.
- One exit record when a process's last thread exits (`sched_process_exit` with `group_dead`): wait
  status, total CPU time, start time (`start_boottime`, converted with the boottime reference in the
  clock record). 70 ns per process exit.
- One login record when `/proc/self/loginuid` is set (PAM `pam_loginuid`): new loginuid and session.
- Processes that exist when the agent starts are emitted once by a BPF task iterator, in the same
  record format. The verifier rejects `bpf_d_path` on `mm->exe_file` (a walked, untrusted pointer)
  and the kfuncs that return a trusted file are LSM-only, so the agent fills these executable paths
  from `/proc/<pid>/exe` at startup.
- Executable hashes: userspace queues each distinct (dev, inode, ctime) once to a worker thread
  running `SCHED_IDLE` with idle I/O priority. It hashes `/proc/<pid>/exe` (the exact inode even if the
  path was replaced or deleted), falling back to the recorded path with the key verified, and drops the
  pages it read (`POSIX_FADV_DONTNEED`: a 200 MB binary left 0 bytes resident, 190.8 MB without). The
  startup snapshot's executables go to a second idle thread that exits when done, so live execs and
  file changes never wait behind it: this host's 91 running binaries (4.07 GB) take about 25 s, and a
  file changed 3 s after start was hashed in the same run. The set of keys already queued holds at most
  65,536 entries and is cleared when full, which costs a repeated hash, not memory growth.

Volume is one record per exec and per process exit, plus the one-time snapshot.

### Records

Records are packed binary, 8-byte aligned, with a 16-byte header (`u16 len`, `u8 type`, `u8 flags`,
`u32 reserved`, `u64 jiffies`). Kernel structs in `crates/agent/src/bpf/agent.bpf.c` are the schema;
the Rust types are generated from them through the BPF skeleton so the layouts cannot diverge. The
agent writes records as-is; decoding to JSON is a separate tool (`panopticon decode`).

Records reference each other only through kernel identities (process key, image key, socket cookie,
cgroup id, inode). The consumer drains rings one after another, so stream order is not time order;
the decoder indexes identities in a first pass and emits in a second.

Userspace adds its own record types to the same stream: meta (host, boot id, CPU count, HZ), clock,
loss, miss (a program's recursion misses), watch (each marked path or watched socket with its dev and
inode), container and hash.

Time is jiffies (1 ms at `HZ=1000`). Userspace emits a clock record (jiffies, `CLOCK_REALTIME`,
`CLOCK_BOOTTIME`) every second, and the decoder converts; the boottime reference converts kernel start
times.

### Transport

Each class has, per CPU, a byte ring in a `BPF_F_MMAPABLE` array element of `size + slack` bytes. The
control block per (class, CPU) holds `head`, `tail` and `drops` on separate cache lines.

Producer:

1. `bpf_preempt_disable()`.
2. Take the ring's busy flag with an atomic exchange; if it was already set, count a drop.
3. Load `tail` with acquire; if `head + max_record - tail > size`, count a drop and release the flag.
4. Write the record at `head & (size - 1)`. A record that runs past the end continues into the slack
   bytes, so records are always contiguous and never split or padded.
5. Store `head + len` with release, release the busy flag with release, `bpf_preempt_enable()`.

Consumer: one thread polls every ring every 10 ms, copies whole records to the output buffer, stores
`tail` with release. No syscalls per record, no wakeups.

Safety comes from the same structure that makes it fast:

- One ring per CPU means one producer per ring unless the producer is interrupted.
- Preemption is disabled for the few nanoseconds of the write.
- The busy flag turns a nested producer of the same ring on the same CPU into a counted drop instead
  of a corrupted ring: a different program in an interrupting context, an NMI, a future hook in an
  unexpected context. No class depends on its hooks running in one kind of context. Uncontended it
  costs nothing measurable: 52.10 ns against 52.29 ns per `getppid` with an emitting program (41.23 ns
  without one), medians of 11 interleaved pinned runs of `crates/ringbench` variants `spsc_busy` and
  `spsc_nots`.
- A nested invocation of the same fentry, fexit or tp_btf program never reaches the flag: the
  kernel's per-program, per-CPU recursion guard skips it and counts it in the program's
  `recursion_misses` (LSM programs have no guard). That covers a softirq `on_nat` under a task-context
  `on_nat`, and also a task preempted inside a tracing program, which makes the same program skip in
  every other task on that CPU until it resumes. The agent reads every program's counter once per
  second and writes a `miss` record with the program name and the new count, so this loss is reported
  like ring drops. None appeared with 32 UDP or connect threads on 2 CPUs.
- Drop counters are incremented atomically, because a nested producer can race the holder.
- Every writer stays within the `max_record` bytes it reserved. The verifier only checks that writes
  stay inside the map value, so this is a code invariant, not a verifier guarantee; the formal model
  shows that one byte past `max` overwrites the oldest unread record.

Kernel requirements: `bpf_preempt_disable` (6.10), BPF load-acquire/store-release (6.15), BPF LSM,
task and socket local storage.

All classes use the same mechanism. Sharing one ring between low-rate classes would save a few MB and
add a second code path.

Ring sizes are compile-time per class and sized from expected rate × poll interval × headroom. The
prototype uses 256 KiB per CPU for proc and net and 64 KiB for file, admin and nat (22 MiB on 32 CPUs).

### Userspace

One thread:

- Poll all rings; append whole records to an output buffer. The only record bytes it reads are the
  header and two record types: a cgroup record triggers container resolution, an exec record queues a
  hash.
- Drain the inotify fd. Its events are not used (the BPF hook is the event source); draining keeps
  their kernel memory near zero and does not change the producer's cost (+87.4 ns per marked open
  drained, +89.2 ns never read).
- Once per second and at shutdown: clock record, a loss record for any ring whose drop counter
  moved, a miss record for any program whose recursion counter moved, and the repeat records from the
  file coalescing iterator.
- At shutdown the agent first detaches every program, waits one poll interval for invocations in
  flight, and only then drains the rings and reads the iterator, so nothing committed is left behind.
- Collect finished hashes from the hashing worker.
- Write the buffer to the sink.

### Containers

Records carry the cgroup id (`bpf_get_current_cgroup_id`, 8 bytes, ~2 ns). The proc class emits a
cgroup record with the path from `cgroup_mkdir`, and the agent emits records for cgroups that already
exist at start, so short-lived containers resolve even after their cgroup is gone.

For a cgroup whose name holds a container id (`docker-<id>.scope`, `cri-containerd-<id>.scope`,
`crio-<id>.scope`, `libpod-<id>.scope`, or a 64-hex leaf under `/docker/` or `kubepods`), the agent reads
the runtime's own state files once and emits a container record: docker's `config.v2.json` and
`hostconfig.json`; for containerd, CRI-O and podman, the OCI `config.json` of the bundle, whose CRI
annotations give container name, pod, namespace and image. Flags: privileged (docker `Privileged`, or
`CAP_SYS_ADMIN` in the OCI bounding set), host PID and host network namespaces, pod sandbox. No runtime
API calls and no per-record work. The decoder attaches the container to every record whose cgroup
belongs to one.

A cgroup's name proves nothing: a user can create cgroups in the subtree systemd delegates to them
(`user@UID.service`) and move their processes in, and container ids are readable in any process's
`/proc/<pid>/cgroup`. The container record is emitted only when the bundle's OCI `linux.cgroupsPath`
names this exact cgroup (the systemd form `slice:prefix:id` expanded as systemd does, or the cgroupfs
path). The runtime writes the bundle before it creates the cgroup. The previous build attributed a
cgroup that an unprivileged user created as `app.slice/cri-containerd-<id>.scope` to the k3s pod with
that id; this build emits only the cgroup record, whose path shows where it really is. Rootless and
nested runtimes, whose bundles are outside the paths the agent reads, get no container record.

### Network attribution

The goal is a join key against network flows: socket cookie, protocol, the socket's own tuple, network
namespace, process key, image key, cgroup, time.

- TCP out: `fexit/tcp_v4_connect` and `tcp_v6_connect`, after the source port is assigned.
- TCP in: `fexit/inet_csk_accept`, in the accepting process.
- Listen: `fexit/inet_listen`.
- UDP over IPv4 and IPv6: `fentry/udp_send_skb` and `fentry/udp_v6_send_skb` share one path. Both
  the plain and the corked send path build the datagram and call them, out of line (bpftrace on this
  host: 530,721 calls for 530,722 `udp_sendmsg` returns; the one missing send failed before building
  an skb). Addresses come from the route's flow, so an unconnected socket records its real source
  address instead of `0.0.0.0`. A datagram is recorded when it is handed to IP; one a local firewall
  then drops is still recorded. Each destination (16-byte address and port) is checked against the
  socket's last 4 in socket-local storage, and a new one emits a record. After 16 records the socket
  is flagged saturated and reports nothing more (DNS queries are always recorded and do not move the
  count past 16). The table is updated without a lock, so two threads sending on one socket can
  exceed 16 by a few records. Its own tuple joins the rest of its flows. A send to an IPv4-mapped
  address goes through the IPv4 function and is recorded once. `connect()` on UDP without traffic
  is not recorded because no flow follows it.
- DNS over IPv4 and IPv6: every query payload when the destination port is 53, copied from the
  datagram's linear data in the skb, which the sender can no longer change. The first version read
  the sender's buffer after `udp_sendmsg` returned: a thread that rewrote the name 0–3 µs into each
  send (`bench/results/experiments/dns_race.sh`, 20,000 queries) put `evil.com` on the wire 1,429
  times and in the records 15,498 times. Reading the skb, the counts are equal (1,413 and 1,413). The
  socket is tagged, and answers are copied from `skb_consume_udp` for tagged sockets only. Covers
  glibc and musl stub resolvers, systemd-resolved's stub, Docker's resolver paths and CoreDNS. Not
  covered: DoH, DoT, DoQ, TCP port 53, systemd-resolved's varlink clients.
- Raw and packet sockets: `fexit/packet_create`, `fexit/raw_sk_init` and `fexit/rawv6_init_sk`, the
  family constructors, so no other socket creation pays. Kernel control sockets are excluded.
- Unix stream connects to container runtime sockets (docker, containerd, k3s containerd, CRI-O,
  podman): `lsm/unix_stream_connect`, filtered by the target socket's inode. This hook runs for every
  unix stream connect, 19 ns each; nothing in the kernel indexes unix connects by target, so this is the
  one new cost on unrelated activity.
- NAT: `fexit/nf_nat_setup_info` in the `nf_nat` module; one record per call whose own manipulation
  changed the tuple (SNAT compares the original source with the reply destination, DNAT the original
  destination with the reply source): original and reply tuples, protocol, network namespace. No
  actor: the hook also runs in softirq context, where the current task is unrelated; the original tuple
  joins the record to the container's connect record. Docker egress `172.17.0.2:54560 -> 1.1.1.1:80`
  is recorded with reply `1.1.1.1:80 -> 192.168.1.18:54560`. Agents start at boot, often before docker
  or k3s loads `nf_nat`, and an fexit target is fixed when the program loads. So the program lives in
  its own BPF object (`nat.bpf.c`) that reuses the main object's nat ring and control maps; the agent
  loads it at start if `/sys/kernel/btf/nf_nat` exists and otherwise checks once per second.
  Verified by hiding that file in a private mount namespace and creating it 3 s after start: the
  program attached on the next check and docker egress was recorded. A failed load (module BTF
  appears before the module's init finishes) is logged and retried on the next check. A program
  loaded after start is not in the frozen set of the agent's own program ids. While attached it
  holds a reference that keeps `nf_nat` from being unloaded. Cilium with BPF masquerade keeps NAT state
  in its own map (`cilium_snat_v4_external`) and needs a version-pinned reader; not testable on this
  host.
- UDP binds: `fexit/inet_bind` and `inet6_bind` for datagram sockets, on success. TCP servers are
  covered by listen.

### Credentials, persistence and integrity

Two kinds of inotify marks:

- Reads of credentials: `IN_OPEN` marks on `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd` and
  the SSH host private keys; `IN_OPEN` plus change events on the credential directories of every home
  (`.ssh`, `.aws`, `.kube`, `.docker`, `.config/gcloud`, `.gnupg`).
- Changes to persistence and integrity locations: directory marks with close-after-write, modify,
  attribute, create, delete and move events on `/etc` (top level), cron and at spools, systemd unit
  directories (system and user, and each existing subdirectory of `/etc/systemd/system`), `init.d`,
  `profile.d`, `ld.so.conf.d`, PAM configuration and module directories, `sudoers.d`, sshd
  configuration, udev rules, module-loading configuration, `update-motd.d`, APT hooks, XDG autostart,
  `/boot`, the system binary and multiarch library directories, and each home directory with its
  autostart and systemd user directories. A directory mark sees files created after startup (a new
  `/etc/ld.so.preload`) and replacement by rename, which per-file marks miss. Reads in these
  directories are not marked: every process start reads `/etc/ld.so.cache`.

- The agent owns one inotify group with marks on the listed inodes, and learns the kernel address of
  that group from `fentry/inotify_update_watch`.
- `fentry/inotify_handle_inode_event` compares the mark's group with ours. The marked object is `dir`
  when the kernel passes one (an event on a child or on a directory entry), otherwise `inode`. The
  record carries the marked inode, the child inode, the entry name (up to 255 bytes, the kernel's
  `NAME_MAX`, so long names are never cut) and the watch descriptor read from the mark. Events caused
  by the agent itself (the hash worker opening a changed credential file) are skipped.
- When the kernel destroys a mark (the directory was deleted, a container's filesystem unmounted), it
  calls the same function with `IN_IGNORED`. The program then emits an internal record with the watch
  descriptor, and userspace drops that descriptor's path and growth entry. These maps are keyed by
  watch descriptor, which the kernel allocates cyclically, so a reused inode number cannot remove a
  newer entry. A container start and exit leaves both maps at their previous size.
- Coalescing: the first event per (process key, `self_exec_id`, marked inode, child inode, mask) in a
  one-second window emits a record; later ones increment a counter in an LRU hash of 4096 keys. A
  `bpf_map_elem` iterator, read once per second and at shutdown, swaps each counter with zero and
  emits a repeat record. With `self_exec_id` in the key, a program exec'd by the process gets its own
  record instead of disappearing into the previous program's count.
- Containers: when a container's cgroup appears, the agent locates its OCI bundle (containerd,
  docker through containerd's `moby` namespace, CRI-O, podman) and marks `etc/shadow` and
  `etc/gshadow` for reads, `etc` for changes and `root/.ssh` for both under the bundle's root, which is
  the container's own overlay mount, so the container's opens hit the marks. Failures are logged, not
  fatal. The marks are made while the container starts, so its first milliseconds can go unseen.
- Paths below a home directory or a container root are controlled by the user or the image. The agent
  resolves them with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS` to an
  `O_PATH` descriptor, marks the inode through `/proc/self/fd/N` and takes its key from `fstat` of the
  same descriptor. A symlink that leaves the root or a path that crosses into another mount fails
  with `EXDEV` and is logged; a link loop fails with `ELOOP`; symlinks inside the root are followed.
  The previous build resolved these paths in the host namespace and asserted that every failure was
  `ENOENT`. Reproduced against it: `~/.aws -> /tmp/x` marked `/tmp/x` and recorded its files as
  `~/.aws`, so a link to `/usr/lib/x86_64-linux-gnu` would put an open mark on every library load
  on the host; `~/.aws -> .aws` made the agent panic at startup; a FUSE mount at `~/.aws` whose server
  never answers hung startup with no output. The current build logs all three and starts.
- New subdirectories: when a watched system directory (not a home directory) reports a created or
  moved-in subdirectory, the agent marks it with the parent's mask, up to 4096 such directories at a
  time. This catches `systemctl enable` creating a new `.wants` directory. Files created in the 10 ms
  before the mark lands are missed. Home directories do not grow: users create directories constantly.
- Hashes of changed files: a close-after-write or moved-in file in a watched directory is queued to
  the idle-priority hash worker. The worker opens the path with `O_PATH | O_NOFOLLOW`, which does not
  call the file's `open` method, and reopens it through `/proc/self/fd/N` with `O_NONBLOCK` only if
  `fstat` shows a regular file with the event's (dev, inode). A device node moved into a container's
  `etc` (a container with the default `CAP_MKNOD` can create one; the device cgroup does not apply to
  the agent) is never opened, and a FIFO or lease cannot stall the worker. Executable hashes use the
  same open, so replacing an exited program's path with a FIFO no longer stops all later hashing.

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
evicted keys without a loss record, and because an evicted element is reused at once while another
CPU may still hold a pointer to it, a count can land on a different key. Every access after an
eviction still emits a full record. The window test is a signed difference, so an invocation that
read the clock just before another CPU advanced the key's window counts as inside it.

### Admin operations

Hooks that fire only on the operation itself:

| Operation | Hook | Recorded |
|---|---|---|
| Module load from a file, including compressed modules | `lsm.s/kernel_read_file` (`READING_MODULE`, `READING_MODULE_COMPRESSED`) | path, dev, inode |
| Module load from memory | `lsm/kernel_load_data` | operation only |
| kexec | the same two hooks with the kexec ids | path, or memory |
| BPF program load | `lsm/bpf_prog_load`, user loads only | name, program and attach type, instruction count, attach BTF id |
| ptrace attach, `/proc/<pid>/mem`, `process_vm_*`, `pidfd_getfd` | `lsm/ptrace_access_check`, attach mode only | target process key and pid, mode |
| `PTRACE_TRACEME` | `lsm/ptrace_traceme` | tracer |
| uid and gid changes | `lsm/task_fix_setuid`, `lsm/task_fix_setgid` | old and new real/effective/saved/fs ids, when the real id changes or any id becomes 0 |
| Capability changes | `lsm/capset` | old and new effective, permitted, inheritable |
| mount, move_mount, pivot_root | `lsm.s/sb_mount` (`bpf_d_path`); `lsm/move_mount` and `lsm/sb_pivotroot` (`bpf_path_d_path` kfunc: these hooks are not sleepable) | target, source, filesystem type, flags |
| umount | `lsm/sb_umount` | filesystem type, dev, flags |
| Clock set | `lsm/settime` | new time |
| sysctl write | `fexit/proc_sys_write` | name (bounded dentry walk), return value, `maxlen`, and the value the kernel holds afterwards (up to 256 bytes of the table's data) when the table's handler is one whose data is the value: the generic int, uint, u8, ulong, bool and string handlers and the security and forwarding handlers of `core_pattern`, `kptr_restrict`/`dmesg_restrict`, Yama, BPF, `mmap_min_addr`, `ip_forward`, `conf/*` and IPv6 `forwarding`/`disable_ipv6`. Other handlers' data can be a kernel pointer (`tcp_congestion_control`), so they get the name only. The first version read the value from the writer's buffer before the kernel copied it: under a flip race (`bench/results/experiments/sysctl_race.sh`) 129 of 315 writes that set 99 were recorded as 64; the kernel's value matches exactly |
| Namespace creation | `fexit/create_new_namespaces` | types, unshare or clone, new net and mount namespace inodes |
| setns | `fexit` on the eight `*ns_install` callbacks, which serve both the fd and the pidfd path | type, target namespace inode |
| User namespace creation | `lsm/userns_create` | euid |
| Signals | `lsm/task_kill`: user-originated HUP, INT, QUIT, KILL, TERM, STOP to another process | target process key and pid, signal |
| Secure anonymous inodes (`[userfaultfd]`, `[io_uring]`) | `lsm/inode_init_security_anon` | name |
| Another process obtaining an fd to one of the agent's maps or programs | `lsm/bpf_map`, `lsm/bpf_prog`, against id sets frozen at startup | object, id, mode |

All LSM programs return 0 on every path: none of them can deny an operation. A `cgroup/sysctl` program
was rejected because cgroup programs cannot call `bpf_get_current_task_btf` and so cannot fill the actor.

Volume: a container start on this host (k3s, runc, Cilium CNI) produces about 50-80 admin records
(mounts, setns, privilege drops, pivot_root, device-cgroup and CNI BPF loads).

Not observable at these hooks, by design: attempts that fail before the security check
(`kexec_file_load` with a bad fd, `clock_settime` on a clock that cannot be set), and operations on hot
paths that are deliberately not hooked: `mprotect`, `mmap` with `PROT_EXEC`.

Tampering: the agent's configuration maps (its own object ids, the watched unix sockets) are frozen
after startup, so `bpf()` cannot change them (`bpftool map update` fails with `EPERM`), and read-only
settings such as the coalescing window live in `.rodata`, which libbpf freezes. Taking an fd to any of
the agent's maps or programs, the first step of map-tampering attacks, is recorded, as is a signal
sent to the agent. Prevention is out of scope; an agent that is killed stops emitting clock records,
which the collector sees within a second.

## Formal model

`formal/` holds TLA+ models of the concurrency the agent depends on, model-checked with TLC, and a
TLAPS proof of the ring for every size. `formal/check.sh` runs all of it and fails unless every safe
configuration passes and every unsafe variant fails with its expected property; `formal/README.md`
lists the kernel and BPF guarantees each model relies on, with sources.

| Model | Holds as written | What the unsafe variants show |
|---|---|---|
| Ring (614,228 states) | No overwrite, no partial read, records contiguous within size + slack, every record consumed, dropped or still in the ring; the producer finishes within `max + 2` steps even if the consumer never runs | Head store without release: partial read. Tail store without release: overwrite. One byte written past `max`: overwrite with every store inside the map value |
| Nested producers (up to 3,950,593 states) | Busy flag with exchange and atomic drop counters, under task, softirq, hardirq and NMI nesting in any order: no overlapping writes, one commit per reservation, the flag never leaks, exact accounting | No flag: overlap. Non-atomic drop counter: a lost count. A plain load/store flag is safe only for last-in first-out nesting |
| File coalescing (1,988,080 states with eviction) | Every event is counted once, as a record, a flushed repeat or a pending count; only eviction loses counts | `BPF_ANY` insert loses a pending count without eviction; eviction can move a count to another key |
| Host safety (1,246,989 states) | Every hook invocation finishes in a bounded number of steps; host threads keep making progress whether the agent runs, stalls or dies; all state stays bounded | A producer that waited for ring space would block the host |
| UDP dedup (16,693,624 states) | With one sender, records ≤ 16 + DNS queries; a send to a destination outside the last 4 always emits | Two senders on one socket exceed the cap |

TLAPS proves the ring invariant inductive and that it implies no overwrite and containment for every
ring size (83 obligations). TLC bounds are small: rings of 4–8 cells, 2 CPUs, 1–2 invocations per
context.

Found by the models and fixed in the code: recursion misses were not reported; the final drain ran
before the programs were detached; the UDP destination count wrapped; the coalescing window test
underflowed when an invocation spanned a jiffy. Found and documented: the two-sender UDP overshoot,
eviction moving a count to another key, a one-jiffy lag that can add a record to a window or move
its start back by a jiffy, and that the shutdown wait is one poll interval, so a program preempted
before `reserve()` for longer than that could still commit after the final drain. The busy flag
costs nothing measurable (52.10 against 52.29 ns per emitting `getppid`).

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
| 2026-11-02 | Record process exits after all (reverses the exit half of the fork/exit row) | Falco, Tetragon, Tracee, Datadog and 8 commercial sensors export exits (`docs/research/`); one record per process, 70 ns |
| 2026-11-02 | One per-ring busy flag in every class's reserve/commit, instead of split rings for multi-context classes | 52.10 vs 52.29 ns per emitting `getppid` (medians of 11 interleaved pinned runs); safe under any nesting, one code path |
| 2026-11-02 | Admin operations from LSM hooks and single-purpose kernel functions that fire only on the operation | Coverage pass: 36 of 43 probe actions observed across all classes, before signals and truncation were added; the misses fail before the security check, are unhooked hot paths, or sit outside watched paths |
| 2026-11-02 | Container metadata from the runtimes' state files, not their APIs | Read once per container; no runtime API calls, no per-record work; docker, containerd, CRI-O, podman |
| 2026-11-02 | Hash executables and changed files in a `SCHED_IDLE` worker that drops the pages it read | 200 MB binary: 0 bytes left resident (190.8 MB without); 4.07 GB of running binaries in ~25 s of idle time |
| 2026-11-02 | Persistence and integrity as directory change marks; read marks only on credentials | Catches files created after startup and rename-replacement; `/etc` reads stay unmarked |
| 2026-11-02 | Unix connects filtered in BPF by target inode | 19 ns per unix connect, the only parity hook that runs for unrelated activity; nothing in the kernel indexes unix connects by target |
| 2026-11-02 | Do not collect library loads or environment variables | Rule demand 0% and 1.1% (`docs/parity.md`); estimated +0.6% on exec-heavy loads and 1–1.5 µs per exec |
| 2026-11-02 | Resolve paths under homes and container roots with `openat2(RESOLVE_BENEATH \| RESOLVE_NO_XDEV)`; mark through `/proc/self/fd` | Previous build: a user symlink redirected a mark anywhere on the host, a link loop stopped the agent from starting, a stalled FUSE mount hung it (all reproduced) |
| 2026-11-02 | Open files to hash with `O_PATH` first and reopen only regular files | `open` on a device node runs its driver (a watchdog arms on open); a container with default `CAP_MKNOD` can place one in its watched `etc` |
| 2026-11-02 | Key watch state by watch descriptor and drop it on `IN_IGNORED` from the BPF hook | Path and growth maps grew with every container start; the inotify queue can overflow during a flood, the BPF hook sees every removal |
| 2026-11-02 | Emit a container record only when the bundle's `linux.cgroupsPath` names the cgroup | Previous build: a cgroup an unprivileged user created in `user@1000.service` with a k3s container's id was attributed to that pod |
| 2026-11-02 | UDP sends and DNS query payloads from `fentry/udp_send_skb` and `udp_v6_send_skb`, never from the sender's buffer | Reading the buffer after `udp_sendmsg`: 15,498 `evil.com` records for 1,429 on the wire under a 0–3 µs rewrite race; from the skb: 1,451 and 1,451 |

## Open questions

- Output path: batch size, compression, transport to the collector.
- NAT module pinning: whether holding `nf_nat` loaded is acceptable on hosts that unload it.
- Environment variables: whether an idle-priority read of `/proc/<pid>/environ` for long-lived
  processes is worth its blind spot for short-lived ones.

## Prototype status

`crates/agent`, binary `panopticon`. `panopticon run <file> [poll-ms]` loads the programs and appends
the record stream to a file; `panopticon decode <file>` prints one JSON object per record.

Implemented: every class above, the startup snapshot, container metadata and container file marks,
executable and changed-file hashes, clock, loss and repeat records, the decoder. Not implemented:
shipping the stream off the host.

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

1. Shipping the stream off the host.
2. Counting repeat counts lost to coalescing-map evictions, which are now silent.
