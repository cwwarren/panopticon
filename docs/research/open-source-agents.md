# Open-source Linux runtime-security and telemetry agents (survey, November 2026)

What the open-source agents hook, what they collect, where they filter, how they move events, what they cost, and what they miss. Written for panopticon; the principles referred to are those in [design.md](../design.md#principles).

## Scope and method

- Agents: Falco, Cilium Tetragon, Aqua Tracee, Datadog Workload Protection (CWS), KubeArmor, Inspektor Gadget, Elastic's open-source eBPF pieces (elastic/ebpf, quark, Auditbeat), Kunai, Exein Pulsar, osquery, auditd with Laurel or go-audit, Sysmon for Linux, Wazuh, and newer or less-known entrants: Jibril (binary-only, included for its design), ByteDance Elkeid, StackRox/Red Hat ACS Collector with `fact`, Kubescape node-agent. Candidates checked and excluded are listed [below](#checked-and-excluded).
- Sources: release pages, documentation, maintainers' talks and blogs, papers, and source code from shallow clones read on 2026-11-02. Source citations are GitHub permalinks with the full commit hash; each agent section names the commit. No agent was built or run on this host.
- Kernel-mechanism claims cite the Linux source (v6.12 or v7.0 tags).
- `[INFERENCE]` marks conclusions drawn from reading code or from the mechanism, not stated by the project or measured.
- Overhead numbers are quoted with their setup. Vendor and maintainer numbers are labeled as such; few independent measurements exist, and none on kernel 7.0.

## Findings

1. **Most agents still make every syscall pay.** A BPF program on raw `sys_enter`/`sys_exit` runs for every syscall on the host in Falco, Tracee, Sysmon for Linux, Kunai, ACS Collector (Falco's libs), Kubescape node-agent (via `advise_seccomp`, when runtime detection is on) and Elkeid (≥ 5.5). The kernel audit path does the same for auditd, Laurel, go-audit, osquery's audit tables and Wazuh's who-data in its default audit mode. Attaching even one per-syscall tracepoint (`syscalls:sys_enter_<name>`) sets `SYSCALL_WORK_SYSCALL_TRACEPOINT` on every task, so every syscall takes the tracepoint slow path and a bitmap test ([tracepoint.c#L800-L814](https://github.com/torvalds/linux/blob/v6.12/kernel/tracepoint.c#L800-L814), [trace_syscalls.c#L575-L591](https://github.com/torvalds/linux/blob/v6.12/kernel/trace/trace_syscalls.c#L575-L591)); KubeArmor, Inspektor Gadget, elastic/ebpf, quark and Pulsar do this. Only Tetragon's base sensor, Datadog's default configuration, Wazuh's eBPF provider and ACS `fact` avoid both.
2. **Filtered syscall hooks still cost.** Tetragon's maintainers measured +6.42% on a kernel build with kprobes on 190 syscalls and a filter that matched nothing ([LSFMM 2023](https://bpfconf.ebpf.io/bpfconf2023/bpfconf2023_material/LSFMM_Tetragon.pdf)). Falco's dispatchers cost 62-66 ns per run with no syscall selected ([libs proposal](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/proposals/20240901-disable-support-for-syscall-enter-events.md#L16-L316)). Elkeid's authors estimate 3-5% for a no-op `sys_exit` hook ([smith_hook.c#L2646-L2651](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L2646-L2651)). Audit adds 38 → 791 ns to `getpid` as unrelated rules go from 0 to 256 ([LKML 2026](https://lists.openwall.net/linux-kernel/2026/08/07/58)). Panopticon's own floor table agrees: +14 ns per syscall for an empty raw tracepoint program ([design.md](../design.md#hook-placement-floor)).
3. **In-kernel decision-making ranges from a syscall-id bitmap to learned deny-lists.** Falco filters only by syscall id. Tetragon compiles selectors to maps and evaluates cheap cgroup and process filters before reading arguments. Datadog derives approvers from the ruleset and learns inode discarders at runtime, invalidated by revision counters. In-kernel dedup exists in Datadog (first-seen samplers), Kunai (first read/write per thread and inode), quark (mprotect transitions per process image), Tracee (one `file_modification` per open), Sysmon (UDP 4-tuple per 30 minutes) and Tetragon (`rateLimit`). These drop repeats or send heartbeats. Aggregates kept in maps and read periodically appear in Inspektor Gadget's `top_*` gadgets, the `advise_seccomp` per-namespace syscall bitmap, and Datadog's opt-in per-flow packet and byte counters, which perf-event programs walk with `bpf_for_each_map_elem` ([all.go#L195-L200](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/all.go#L195-L200)) [INFERENCE: the flow counters are the map those programs walk].
4. **Transport is mostly a shared ring or perf buffers with a wakeup per record.** A single BPF ringbuf shared by all CPUs with default wakeups: Tetragon, Datadog, KubeArmor's LSM enforcer, elastic/ebpf, Wazuh, Inspektor Gadget, `fact`. Per-CPU perf buffers with a wakeup per record: Tracee, Sysmon, osquery, KubeArmor's monitor. Only Falco submits with `BPF_RB_NO_WAKEUP` and polls with backoff; Kunai polls its perf buffers and sleeps 10 ms when idle. Most consume with one thread or goroutine. Panopticon measured these options at +11 ns (its per-CPU rings), +26 ns (shared ringbuf, one producer), +1,353 ns (shared ringbuf, 16 producers) and +541 ns (perf buffer, wakeup per event) ([design.md](../design.md#transport)).
5. **Enrichment mirrors kernel state in userspace.** Nearly every agent keeps a process table seeded from `/proc`; Falco and osquery's BPF tables also mirror fd tables. Hashes are computed after the fact by reopening `/proc/<pid>/root/<path>` (Tracee, Datadog, Kunai, Laurel). Self-contained records with kernel identities are the exception: elastic/ebpf and quark, `fact`, and partly Tetragon (`exec_id` from ktime and pid).
6. **NAT is a gap everywhere.** No agent exports the post-translation tuple. Datadog hooks `nf_nat_manip_pkt`/`nf_nat_packet` but only to attribute packets to processes internally ([flow.h#L159-L199](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/flow.h#L159-L199)). The other agents' connection records carry the socket's own, pre-NAT tuple [INFERENCE for most of them: no netfilter or conntrack hook in their code]; panopticon measured this for Falco ([design.md](../design.md#falco-0452-baseline)).
7. **Shared blind spots:** io_uring for syscall-hooking agents ([ARMO Curing](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)); TOCTOU on user-memory syscall arguments ([Phantom attack](https://av.tib.eu/media/54228)); drops under load, often uncounted or reported only in logs; map tampering by anyone with `CAP_BPF` ([SunnyMapBPF](https://github.com/azqzazq1/SunnyMapBPF/blob/ceacd5f2b9e8424e462af0a66ce735efbd285831/README.md)).

## Overview

"Every syscall" means the cost lands on syscalls unrelated to what the agent records, in its default configuration.

| Agent (version) | Kernel mechanism | Every syscall pays? | In-kernel filtering and dedup | Transport | Published overhead |
|---|---|---|---|---|---|
| [Falco](#falco) 0.45.2 | `tp_btf/sys_exit` dispatcher, tail calls per syscall; sched tracepoints; kmod alternative | Yes: BPF on `sys_exit`; `sys_enter_<name>` tracepoints for 5 syscalls | Syscall-id bitmap only | BPF ringbuf per 2 CPUs, 8 MB, no wakeups, polled | Maintainer; independent papers |
| [Tetragon](#cilium-tetragon) 1.8.0 | Base: `sched_process_exec` raw tp, kprobes `wake_up_new_task`, `acct_process`; policies: kprobe, fentry, tracepoint, LSM, uprobe | No for the base sensor; depends on policies | Selectors compiled to maps; cgroup/process filters first; LPM tries; `rateLimit` LRU; per-cgroup throttle | One shared ringbuf, 64 KiB × CPUs, default wakeups | Vendor; maintainer slides |
| [Tracee](#aqua-tracee) 0.24.1 | Raw `sys_enter`/`sys_exit` + tail calls; kprobes on `security_*`; `cgroup_skb` | Yes once any syscall event is selected (default set has 25) | 64-policy bitmap scopes; path filters on 3 events; once-per-open file modification | Per-CPU perf buffers, 4 MiB, wakeup per record | Independent only |
| [Datadog](#datadog-workload-protection-formerly-cloud-workload-security) 7.85 | kprobe/kretprobe (fentry opt-in) on ~150 kernel functions and per-syscall wrappers; TC; `cgroup/sysctl` | No raw hook by default; kprobe pairs on exec, cred and file syscalls | Approvers; inode discarders with revisions; first-seen samplers; rate limiters | Shared ringbuf 8/16 MiB, default wakeups | Vendor statements |
| [KubeArmor](#kubearmor) 1.7.6 | kprobe/kretprobe on 18 `sys_*`; syscall tracepoints; BPF-LSM enforcer | Tracepoint slow path; kprobe pairs on 18 syscalls | Per-container visibility maps; per-container alert throttle | Perf 4 MiB/CPU (monitor); shared ringbuf 16 MiB (enforcer) | Vendor; independent paper |
| [Inspektor Gadget](#inspektor-gadget) 0.57.0 | Per gadget: syscall tracepoints, kprobes, LSM, socket filters, iterators | Depends on gadgets; container hook uses syscall tracepoints | mntns filter map; load-time constants; `top_*` aggregation | Per-gadget shared ringbuf 256 KiB | Vendor |
| [Elastic](#elastic-open-source-elasticebpf-quark-auditbeat) ebpf/quark/Auditbeat | fentry/kprobe twins, `tp_btf`; a few per-syscall tracepoints; audit; tracefs kprobes | Tracepoint slow path only [INFERENCE] | Structural filters; quark mprotect dedup | Shared ringbuf 4 MiB (quark 512 KiB × CPUs) | None |
| [Kunai](#kunai) 0.6.2 | kprobes; 6 raw `sys_enter` + 2-3 raw `sys_exit` programs | Yes | First read/write per (thread, inode); per-task file-event throttle | Per-CPU perf, polled every 10 ms | Independent blog |
| [Pulsar](#exein-pulsar) 0.10.1 | LSM (kprobe fallback); sched tracepoints including `sched_switch` | Every context switch; tracepoint slow path | Interest map inherited at fork | Perf 16 MiB/CPU per module | None |
| [osquery](#osquery) 5.24.0 | Audit netlink; ebpfpub syscall tracepoints; inotify | Yes (audit or syscall tracepoints) | None in kernel | Netlink; perf ~4 MiB/CPU, wakeup per record | None |
| [auditd +Laurel/go-audit](#auditd-with-laurel-or-go-audit) | Kernel audit subsystem | Yes: entry/exit hooks, rule-list walk | Audit rule fields at syscall exit | Netlink with backpressure on the workload | Kernel list; vendor tables; academic |
| [Sysmon for Linux](#sysmon-for-linux) 1.5.3 | Raw `sys_enter` + up to 11 raw `sys_exit` programs; `consume_skb` | Yes | Per-syscall active array; file-create heuristic; UDP 4-tuple dedup | Perf 64 MiB/CPU, wakeup per record | Vendor |
| [Wazuh](#wazuh-agent) 4.14.9 | Scheduled scans; inotify; audit; eBPF LSM or kprobes on `vfs_*` | Who-data in audit mode yes; scans, inotify and eBPF mode no | Type and flag filters only | Shared ringbuf 8 MiB | None |
| [Jibril](#jibril-garnet-labs--binary-only) 2.17.0 | Unpublished; state kept in maps | Unknown | Per-(task, object) state in maps | No ring; maps polled every 6-9 s | Vendor claims |
| [Elkeid](#bytedance-elkeid) 1.7.0.24 | Kernel module: kprobes; `sys_exit` tracepoint for DNS | Yes on ≥ 5.5 | Exe/argv allowlist fed by userspace rate counting; DNS load shedding | Private per-CPU ring, overwrite mode | Vendor handler latency |
| [ACS Collector + fact](#stackrox--red-hat-acs-collector-with-fact) 3.26.2 / 0.4.2 | Collector: Falco libs, reduced set + `sched_switch`; fact: BPF LSM only | Collector yes; fact no | Collector: syscall bitmap; fact: inode, parent-inode and prefix maps | Per-CPU ringbufs; fact shared 8 MiB | Resource settings only |
| [Kubescape node-agent](#kubescape-node-agent) 0.3.299 | Inspektor Gadget gadgets incl. `advise_seccomp` on raw `sys_enter` | Yes when runtime detection is on | mntns filter; per-mntns syscall bitmap | Per-gadget rings | Project benchmark |

## Cross-cutting evidence

### Kernel mechanisms that tax unrelated syscalls

- **Syscall tracepoints.** The first registration on the `sys_enter`/`sys_exit` tracepoints runs `syscall_regfunc()`, which sets `SYSCALL_WORK_SYSCALL_TRACEPOINT` on every thread ([tracepoint.c#L800-L814](https://github.com/torvalds/linux/blob/v6.12/kernel/tracepoint.c#L800-L814); the regfunc is attached to `sys_enter`/`sys_exit` in [syscalls.h#L18-L63](https://github.com/torvalds/linux/blob/v6.12/include/trace/events/syscalls.h#L18-L63)). From then on every syscall enters the tracing slow path; BPF programs attached to `syscalls:sys_enter_<name>` are reached through `perf_syscall_enter`, which returns after testing the syscall's bit in `enabled_perf_enter_syscalls` ([trace_syscalls.c#L575-L591](https://github.com/torvalds/linux/blob/v6.12/kernel/trace/trace_syscalls.c#L575-L591)). A raw tracepoint program on `sys_enter`/`sys_exit` additionally runs BPF on every syscall. [INFERENCE] The cost of the slow path alone, without any BPF running, is not published by any project surveyed.
- **Audit.** Once audit is enabled, new tasks get `SYSCALL_WORK_SYSCALL_AUDIT`; with any rule loaded, `__audit_syscall_exit` walks the whole exit rule list for every syscall ([auditsc.c#L1057-L1083](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L1057), [#L1986-L2058](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L1986)). When the backlog is full the generating task sleeps up to 60 s by default ([audit.c#L1926-L1955](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/audit.c#L1926)).
- **fsnotify is skipped when no mark exists.** Auditbeat's kprobe file monitor has to add inotify watches on monitored mountpoints because kernels 5.15+ skip `fsnotify()` entirely for superblocks without marks ([path_inotify.go#L55-L62](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/kprobes/path_inotify.go#L55-L62)). This is the property panopticon's sensitive-file gating relies on ([design.md](../design.md#gating-with-kernel-indexes)).

### Independent comparisons

| Study | Setup | Results | Caveats |
|---|---|---|---|
| Aquila, Sensors 25(21):6511, Oct 2025 ([paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12608121/)) | 1 node, Xeon Gold 5220R, kernel 5.15, K8s 1.29; Falco, Tracee, Tetragon set to monitor every supported syscall, scoped to the benchmark pod, logging to local files; Phoronix OSBench, wrk, iperf3 | Per-event processing time lowest for Falco (63.1 µs create files, 41.0 µs threads); events lost relative to the authors' system: Falco 5.8-74.5%, Tracee 2.3-32%, Tetragon 58.6-85.1%; Falco CPU pinned at 100% (one thread), Tracee and Tetragon above 300% (389.5% and 414.9% launching programs); iperf3 21.70 Gbps Falco, 13.98 Tracee, 12.40 Tetragon | Authors' own system is the comparator; tool versions not stated; non-default configurations; the paper's claim that Falco has no loss awareness conflicts with Falco's per-class drop counters ([struct_definitions.h#L71-L95](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/shared_definitions/struct_definitions.h#L71-L95)) |
| Her et al., IEEE Access 13:155588, Sep 2025 ([PDF](https://cclab.info/papers/2025_her_access.pdf)) | Single-node K8s; KubeArmor, Falco, Tetragon, Tracee; `/usr/bin/ls` × 10,000; 100,000 UDP packets; exec-rate ramp for log loss | Exec loop without/with a process policy: Tetragon +6.88/+9.79%, Falco +8.49/+9.96%, Tracee +9.97/+37.59%, KubeArmor +18.29/+18.04%. UDP without/with a network policy: Tracee +1.48/+71.50%, Tetragon +3.14/+72.92%, Falco +19.93/+24.77%, KubeArmor +87.74/+88.59%. Zero log loss up to 1,874 execs/s for Falco and 486 for Tracee; KubeArmor highest loss | Versions in a table not extractable from the PDF; policies differ per tool |
| Syairozi & Arizal, RITECH 2025 ([PDF](https://www.scitepress.org/Papers/2025/142727/142727.pdf)) | DigitalOcean K8s, 3 × 2 vCPU/4 GB nodes, Helm defaults; container escape, DoS, cryptomining | Agent CPU idle: Falco 431.5 mcores, Tracee 91.6, Tetragon 6.5; memory 397 / 573 / 635 MB; all detected the three attacks | Measures the agents' own containers, not kernel time charged to workloads |
| MERLIN, ASPLOS'24 ([PDF](https://people.cs.umass.edu/~juanzhai/papers/asplos24.pdf), Table 4) | Tracee default settings, kernel 5.15, Ryzen 6800H, lmbench | Null syscall 0.06 → 0.10 µs; open/close 0.79 → 0.94 µs; exec 321.5 → 337.4 µs | Tracee version not stated |
| scrpt.ru blog, Sep 2026 ([post](https://scrpt.ru/blog/auditd-vs-ebpf-linux-audit/)) | Debian 12, kernel 6.1, VM; six scenarios | Kunai ~31% CPU, 395 MB; Falco ~32%, 180 MB; auditd 7% average | Single source; load generator and sampling not described |

### Evasion and tampering

- **io_uring.** ARMO's Curing PoC performs its file and network operations through io_uring. ARMO reports Falco "completely blind to io_uring-based operations" and that Tetragon's sample policies miss it unless users hook kernel functions or LSM hooks; Tetragon's maintainers' position is that hooking anywhere is supported ([ARMO, 2025-04-24](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)). Falco answered with the opt-in `krsi` plugin; Datadog and Kunai hook io_uring internals; Tracee's issue is open since 2020 ([#309](https://github.com/aquasecurity/tracee/issues/309)); Inspektor Gadget documents it as unobservable. In the kernel audit path, 33 io_uring operations, including READ, WRITE, SEND, RECV and SOCKET, are marked `audit_skip` ([io_uring.c#L1381-L1387](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/io_uring/io_uring.c#L1381), [opdef.c](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/io_uring/opdef.c#L54)).
- **TOCTOU.** Phantom attack (DEF CON 29) evaded Falco and Tracee by changing syscall arguments in user memory between the monitor's read and the kernel's use ([talk](https://av.tib.eu/media/54228)). Falco now adds enter-time copies for five syscalls; Tracee and Tetragon document the issue and recommend LSM hooks.
- **Flooding.** Brendan Gregg: tools that drop under load can be evaded "by overwhelming them with events" ([blog](https://www.brendangregg.com/blog/2023-04-28/ebpf-security-issues.html)). Inspektor Gadget reported its ringbuf losses as zero until v0.50.1, letting a container flood the ring to hide events ([CVE-2026-31890](https://github.com/inspektor-gadget/inspektor-gadget/security/advisories/GHSA-wv52-frfv-mfh4)).
- **Map tampering.** SunnyMapBPF shows that a process with `CAP_BPF` can edit Tracee's `config_map`, Tetragon's `execve_map` or Falco's syscall table and drop detections to zero without stopping the agent; none of the three freezes its maps ([README](https://github.com/azqzazq1/SunnyMapBPF/blob/ceacd5f2b9e8424e462af0a66ce735efbd285831/README.md)). quark freezes its maps and makes the trusted-pid map read-only to programs ([CHANGES#L204-L209](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L204-L209)).

## Agents

The four agents with the largest user bases and the most relevant designs get full sections; the rest are shorter.

### Falco

Surveyed: Falco [0.45.2](https://github.com/falcosecurity/falco/releases/tag/0.45.2) (2026-10-29; libs 0.26.1, driver 11.0.1, falco-rules 5.2.0 via [0.45.0](https://falco.org/blog/falco-0-45-0/)). Source read at libs [`f13bc24`](https://github.com/falcosecurity/libs/tree/f13bc241815d463be433e947b90f42713df1abf9), falco [`6e13dff`](https://github.com/falcosecurity/falco/tree/6e13dff8fe017b5dfbb98708e20275ea2feba41f), rules [`e7b066b`](https://github.com/falcosecurity/rules/tree/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428), plugins [`9064e9d`](https://github.com/falcosecurity/plugins/tree/9064e9d620538aebf32912fa00f6b9ef95d46a37). Apache-2.0 userspace in C++, drivers GPL-2.0-only OR MIT ([syscall_exit.bpf.c#L1-L7](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/dispatchers/syscall_exit.bpf.c#L1-L7)). One process per node, packaged or as a Helm DaemonSet. This is the agent panopticon benchmarks against in [design.md](../design.md#falco-0452-baseline).

**Drivers.** `modern_ebpf` (default, CO-RE, kernel ≥ 5.8 or backported BTF and ringbuf) and `kmod` (≥ 3.10) ([libs README#L44-L50](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/README.md#L44-L50)). 0.44.0 removed the legacy eBPF probe, the gVisor engine and gRPC output ([CHANGELOG#L87-L89](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/CHANGELOG.md#L87-L89), [0.44 blog](https://falco.org/blog/falco-0-44-0/)).

#### Kernel mechanism and attach points

- **One `tp_btf/sys_exit` dispatcher for every syscall** ([syscall_exit.bpf.c#L181-L259](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/dispatchers/syscall_exit.bpf.c#L181-L259)). It reads the syscall id, maps ia32 ids and `socketcall`, checks a per-syscall `bool` array `interesting_syscalls_table_64bit` ([maps.h#L142-L151](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/maps/maps.h#L142-L151)), runs optional sampling and `drop_failed` checks, then `bpf_tail_call`s into one of about 160 per-syscall filler programs.
- **The generic `sys_enter` program is gone.** libs implemented the proposal ["Disable support for syscall enter events"](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/proposals/20240901-disable-support-for-syscall-enter-events.md#L1-L12), moving parameters into exit events. Enter events survive only as TOCTOU mitigation for `connect`, `creat`, `open`, `openat`, `openat2`, via `tracepoint/syscalls/sys_enter_<name>` plus ia32 kprobes ([toctou_mitigation/README.md](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/events/toctou_mitigation/README.md)), attached only if the syscall is selected ([sc_set.c#L92-L101](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libpman/src/sc_set.c#L92-L101)). Each of those opens/connects therefore produces two ring events.
- **Unrelated syscalls pay.** The exit dispatcher is attached whenever any syscall is selected ([sc_set.c#L67-L81](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libpman/src/sc_set.c#L67-L81)), so every syscall on the host runs BPF up to the bitmap check. [INFERENCE] The per-syscall `sys_enter_<name>` tracepoints are dispatched through the kernel's raw `sys_enter` tracepoint, so selecting `openat`/`connect` adds a raw tracepoint call on every syscall entry too.
- **Other `tp_btf` hooks:** `sched_process_exec` (emits the successful execve/execveat exit event, because `sys_exit` is unreliable for successful exec on some arches; [sched_process_exec.bpf.c#L45-L69](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/events/sched_process_exec.bpf.c#L45-L69)), `sched_process_fork`, `sched_process_exit` (status, signal, core, reaper tid; [sched_process_exit.bpf.c#L140-L175](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/events/sched_process_exit.bpf.c#L140-L175)), and optionally `sched_switch`, `page_fault_user/kernel`, `signal_deliver`.
- **BPF iterators** (0.44+): `iter.s/task` and `iter/task_file` dump tasks and fds at startup and "heal the state upon event drops", replacing `/proc` scans ([iterators/README.md](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/iterators/README.md), [falco.yaml#L429-L440](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L429-L440)).
- **Event construction.** Fixed-size events are reserved in place in the ring ([ringbuf_store_params.h#L119-L121](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/ringbuf_store_params.h#L119-L121)). Variable-size events are built in a 128 KiB per-CPU scratch slot and copied with `bpf_ringbuf_output` ([auxmap_store_params.h#L347-L392](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/auxmap_store_params.h#L347-L392)). Driver 11.0.0 added two scratch slots per CPU claimed by `cmpxchg` on `pid_tgid`, because a tracepoint program can be preempted mid-build on preemptible kernels; it counts reentrancy, pool-full and migration events ([auxmap_store_params.h#L62-L129](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/auxmap_store_params.h#L62-L129), [0.45 blog](https://falco.org/blog/falco-0-45-0/)). Each header carries `boot_time + bpf_ktime_get_boot_ns()` ([ppm_events_public.h#L2262-L2270](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/ppm_events_public.h#L2262-L2270)).
- **kmod** hooks the `sys_enter`, `sys_exit`, `sched_process_*`, `sched_switch`, page-fault and `signal_deliver` tracepoints; its `sys_enter` probe runs on every syscall and returns early except for the five TOCTOU syscalls ([main.c#L1990-L2035](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/main.c#L1990-L2035)).
- **`krsi` plugin** (opt-in, v0.2.0, Rust/aya) is Falco's answer to io_uring: fentry/fexit on functions shared by the syscall and io_uring paths (`fd_install`, `io_fixed_fd_install`, `do_sys_openat2`, `security_file_open`, `io_openat2`, `__sys_connect`, `io_connect`, `do_unlinkat`, `io_unlinkat`, and bind/socket/link/mkdir/rename/symlink equivalents), one shared 256 KiB ringbuf, events `krsi_open`, `krsi_connect`, ... ([main.rs#L41-L61](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/krsi/krsi-ebpf/src/main.rs#L41-L61), [shared_state.rs#L39-L40](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/krsi/krsi-ebpf/src/shared_state.rs#L39-L40), [README#L5-L9](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/krsi/README.md#L5-L9)). Despite the name it has no `lsm/` programs (grep of `krsi-ebpf/src`).

#### Event inventory

Events are syscall names (`evt.type`) with parameters defined in [event_table.c](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c); [docs/report.md](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md) lists which syscalls have argument fillers.

- Process: `execve`/`execveat` exit with exe, args, env, cwd, tty, loginuid, caps, cgroups, exe inode/ctime/mtime and flags `EXE_WRITABLE`, `EXE_UPPER_LAYER`, `EXE_FROM_MEMFD`, `EXE_LOWER_LAYER` ([event_table.c#L1993-L2027](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L1993-L2027)); clone family; `procexit`; set*id/capset/prctl; `ptrace`; `process_vm_readv/writev`; `memfd_create`; signals.
- File: open family (fd, dirfd, relative name, flags incl. created bit and overlay layer, dev, ino), unlink/rmdir/rename/mkdir/link/symlink/chmod/chown, mmap/mprotect, read/write family (data capped at an 80-byte snaplen, [falco.yaml#L1434](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1434)). xattr, `truncate` and `fchmodat2` are generic events with no arguments.
- Network: socket/bind/listen/connect/accept/send*/recv* with IPv4, IPv6 and unix tuples.
- Kernel/admin: module syscalls, `bpf` (cmd, fd), `mount`, `umount2`, `setns`, `unshare`, `userfaultfd`, `keyctl` (args since 0.44), `io_uring_setup/enter/register`. Without arguments: `kexec_*`, `perf_event_open`, `settimeofday`/`clock_settime`/`adjtimex`, `add_key`, `request_key`, `pivot_root`, the new mount API.
- Container/K8s: `container` and `container_removed` async events from the container plugin ([macros.h.in#L20-L36](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/src/macros.h.in#L20-L36)); a separate `k8s_audit` source from the k8saudit plugin.
- Sensor: `drop_e/drop_x`, internal "syscall event drop" and "metrics snapshot" alerts ([falco.yaml#L1100-L1152](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1100-L1152)).

**Rules.** falcosecurity/rules has four maturity levels; only `maturity_stable` ships in the package as `falco_rules.yaml`, and rules that need high-volume syscalls cannot go beyond sandbox ([CONTRIBUTING.md#L20-L53](https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/CONTRIBUTING.md#L20-L53)). At `e7b066b`: 25 stable, 32 incubating, 39 sandbox (14 disabled), 4 deprecated (count of `- rule:` entries). The stable set ([falco_rules.yaml#L318-L1266](https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L318-L1266)) covers untrusted shells, interactive system users, terminal shells in containers, netcat RCE, credential searches, bulk deletion, execution from `/dev/shm`, drop-and-execute in containers (`proc.is_exe_upper_layer`), memfd execution, ptrace attach and anti-debug, sensitive file reads, directory traversal, log clearing, symlink/hardlink over sensitive files, `release_agent` escapes, K8s API contact from containers, packet sockets, stdio redirected to a socket, SSH on non-standard ports, and kernel module injection. Incubating adds persistence writes (shell rc, cron, `authorized_keys`), namespace changes, privileged container launch, cloud metadata access, non-sudo setuid and "BPF Program Not Profiled" ([falco-incubating_rules.yaml](https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L258-L1368)). The k8saudit plugin ships 48 rules on API-server audit events ([k8s_audit_rules.yaml](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/k8saudit/rules/k8s_audit_rules.yaml)).

#### Enrichment

All state lives in userspace (libsinsp) and is rebuilt from the event stream plus the startup snapshot.

- A thread table keyed by tid (262,144 entries by default, purged every 300 s; [falco.yaml#L1397-L1431](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1397-L1431)) provides lineage (`proc.aname[N]`, `proc.apid[N]`). Drops lose ancestors; the docs say "Falco logs can never be perfect, and null values can occur" ([missing-fields](https://falco.org/docs/troubleshooting/missing-fields/)).
- A per-process fd table, capped at 4096 entries ([fdtable.cpp#L140-L159](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/fdtable.cpp#L140-L159)), supplies `fd.name` for later reads, writes and connects. Maintaining it is why `close`, `dup`, `fcntl`, `pipe`, `socket` and the send/recv family are always captured: 63 events carry `EF_MODIFIES_STATE` and are added to the kernel selection regardless of rules ([configure_interesting_sets.cpp#L121-L165](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/userspace/falco/app/actions/configure_interesting_sets.cpp#L121-L165), [sinsp_events_ppm_sc.cpp#L29-L44](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/events/sinsp_events_ppm_sc.cpp#L29-L44)). `base_syscalls.repair` shrinks this to a minimal state set ([sinsp_events_ppm_sc.cpp#L307-L356](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/events/sinsp_events_ppm_sc.cpp#L307-L356)).
- Container: the container plugin, loaded by default, derives `container.id` from the kernel-supplied cgroup paths and queries Docker, Podman, containerd and CRI sockets for image, labels, privileged flag, mounts and `k8s.pod.*`/`k8s.ns.name`; lookups are asynchronous, so early events can lack image fields ([container README#L17-L91](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/README.md#L17-L91)). Deployment/service labels need the k8smeta plugin plus a cluster-level collector ([k8smeta README#L5-L30](https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/k8smeta/README.md#L5-L30)).
- No executable hashes, package ownership or signatures; user names come from host `/etc` in userspace. `fd.sip.name` does not observe DNS: Falco resolves the domains named in rules itself and compares IPs ([fd-sip-name](https://falco.org/docs/concepts/rules/fd-sip-name/)).

#### In-kernel filtering

- The only kernel filter is the syscall id (the bool array and which tracepoints are attached), plus optional `drop_failed_exit` ([falco.yaml#L345-L352](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L345-L352)). There is no path, process, cgroup or dedup filter in the driver; every selected syscall becomes a ring event.
- A kernel sampling mode exists (`dropping_mode`, `sampling_ratio`, per-syscall never/always-drop flags; [syscall_exit.bpf.c#L125-L173](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/dispatchers/syscall_exit.bpf.c#L125-L173)), but no code in falco calls it (grep of `userspace/`).
- Kernel-side conditional filtering has been an open request since 2023 ([libs#1557](https://github.com/falcosecurity/libs/issues/1557)). The maintainer's reasoning there: "anything you do in the kernel driver happens in the application context", and "Typically file opens are the biggest problem". The docs: "in the kernel, you only have raw syscall arguments and can't easily correlate them with other events" ([dropping](https://falco.org/docs/troubleshooting/dropping/)).
- The userspace rule engine indexes rules by event type ([indexable_ruleset.h#L229-L246](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/userspace/engine/indexable_ruleset.h#L229-L246)).

#### Transport

- BPF ringbufs in a `BPF_MAP_TYPE_ARRAY_OF_MAPS` indexed by CPU id ([maps.h#L226-L246](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/maps/maps.h#L226-L246)). Default `buf_size_preset` 4 = 8 MB per buffer, `cpus_for_each_buffer` 2 ([falco.yaml#L296-L428](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L296-L428)). The 2022 modern-probe proposal chose per-CPU rings because shared-ringbuf throughput fell about 2× with 2 contended producers and about 5× with 20+ ([20220329-modern-bpf-probe.md#L49-L80](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/proposals/20220329-modern-bpf-probe.md#L49-L80)); the 2-CPU default was justified by the kernel double-accounting ringbuf memory ([libs#1557](https://github.com/falcosecurity/libs/issues/1557)).
- Every submit uses `BPF_RB_NO_WAKEUP` ([ringbuf_store_params.h#L173-L179](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/ringbuf_store_params.h#L173-L179)). The consumer polls; when all rings are empty it sleeps 500 µs, doubling to 30 ms ([scap_modern_bpf.c#L54-L71](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libscap/engine/modern_bpf/scap_modern_bpf.c#L54-L71)).
- Each `next()` peeks every ring head and returns the event with the lowest timestamp, a k-way merge costing O(buffers) per event ([ringbuffer.c#L253-L336](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libpman/src/ringbuffer.c#L253-L336)); a maintainer called this "almost certain[ly]" the bottleneck on 128-CPU hosts ([libs#1557](https://github.com/falcosecurity/libs/issues/1557)).
- Per-CPU kernel counters include `n_drops_buffer` and per-class `n_drops_buffer_{clone_fork_exit, execve_exit, connect_enter, connect_exit, open_enter, open_exit, dir_file_exit, other_interest_exit, close_exit, proc_exit}` ([struct_definitions.h#L71-L95](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/shared_definitions/struct_definitions.h#L71-L95)), exported as `scap.n_drops_*` metrics ([falco.yaml#L1253-L1278](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1253-L1278)).
- Userspace: one event loop per source does read, parse, state update and rule evaluation on one thread ([process_events.cpp#L609-L660](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/userspace/falco/app/actions/process_events.cpp#L609-L660)); outputs go through a queue to an output thread. "Falco's hot path is single-threaded" ([performance](https://falco.org/docs/troubleshooting/performance/)). A multi-threaded design that partitions ringbufs by TGID is a December 2025 proposal, not shipped ([20251205-multi-thread-falco-design.md#L37-L80](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/proposals/20251205-multi-thread-falco-design.md#L37-L80)).

#### Published overhead

| Source | Setup | Result |
|---|---|---|
| libs proposal, 2024 ([doc](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/proposals/20240901-disable-support-for-syscall-enter-events.md#L16-L316)) | EC2 t2.2xlarge, kernel 6.5, modern_ebpf, `scap-open` consumer, `redis-benchmark -n 1000000` | Dispatchers attached, no syscall selected: 66 ns (`sys_enter`) and 62 ns (`sys_exit`) per run; Redis 64-65K → 56-57.7K req/s. 15 busy syscalls selected: 343/354 ns per run, 1.59M events/s, Redis about 42K req/s. |
| Falco docs ([dropping](https://falco.org/docs/troubleshooting/dropping/)) | 96-CPU production snapshot, not a benchmark | `sys_enter` 194 ns, `sys_exit` 205 ns, `sched_process_exit` 2,041 ns average; adopters report < 1K events/s per CPU as usually fine and 1-2% drops as acceptable. |
| Maintainer ([libs#1557](https://github.com/falcosecurity/libs/issues/1557), 2023) | Estimate | Up to ~100K events/s with acceptable drops; below 60-70K "likely no problem"; one adopter's 128-CPU hosts produced 21M events/s. |
| Maintainer slides ([Terzolo, Dellaluce](https://sessionize.com/download/ighaxmef~hvzKR4pwBLbqeoJBqtX9Cw.pdf~Terzolo_Dellaluce_-_Falcos_Discovery_of_the_Modern_eBPF_World.pdf), slides 11-12) | redis-benchmark, sys_enter→sys_exit timing | Modern probe ~40% less syscall overhead than the old probe, ~20% more than kmod. |
| Red Hat ACS, 2022 ([PDF](https://github.com/falcosecurity/libs/files/8334709/Falco.eBPF.Kernel.Module.Performance.pdf)) | Legacy probe vs kmod, Phoronix, ~320M syscalls | `close` median 1,317 ns base, 2,641 eBPF, 1,451 kmod; benchmark 47.2 s base, 60.3 s eBPF, 51.7 s kmod, 47.9 s with eBPF on 17 targeted tracepoints only. |
| Panopticon ([design.md](../design.md#falco-0452-baseline)) | 9950X, kernel 7.0, Falco 0.45.2 | +23 ns per getppid (14 ns tracepoint + 17-20 ns BPF), +316 ns per open, 25% drops from one thread looping `open()`. |

Independent comparisons that include Falco are summarized under [Cross-cutting evidence](#cross-cutting-evidence).

#### Documented blind spots

- **io_uring**: ARMO's Curing PoC found Falco "completely blind to io_uring-based operations" ([ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)). Core Falco sees only `io_uring_setup/enter/register`; ring operations need the opt-in `krsi` plugin.
- **TOCTOU**: fillers on `sys_exit` copy user-memory pointers after the syscall, e.g. the `openat` and `unlinkat` paths ([openat.bpf.c#L43-L44](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/tail_called/events/syscall_dispatched_events/openat.bpf.c#L43-L44)). Only the five syscalls above have enter-time mitigation, and `sys_enter_creat` does not exist on arm64 ([sc_set.c#L24-L36](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libpman/src/sc_set.c#L24-L36)). Phantom attack demonstrated this class against Falco in 2021 ([DEF CON 29](https://av.tib.eu/media/54228)).
- **Missing arguments** for the generic events listed above; I/O payloads truncated at 80 bytes.
- **Drops** from the single consumer thread; dropped clone/exec events lose lineage and container fields ([dropping](https://falco.org/docs/troubleshooting/dropping/), [missing-fields](https://falco.org/docs/troubleshooting/missing-fields/)).
- **fd table cap** of 4096 per process; shell built-ins are invisible ([missing-fields](https://falco.org/docs/troubleshooting/missing-fields/)).
- **NAT**: [INFERENCE] tuples are the socket's own view; the driver has no netfilter hook. Panopticon measured pre-NAT tuples for container connections ([design.md](../design.md#falco-0452-baseline)).
- No DNS, TLS/SNI, hashing, login or tamper visibility; Falco only detects ([README](https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/README.md)); response is the separate [falco-talon](https://github.com/falcosecurity/falco-talon) project.

#### Relevance to panopticon

The 2024 enter-event removal is Falco's own evidence for principle 1: deleting the generic enter program was their largest recent cost cut. What remains (an exit dispatcher on every syscall, the fd mirror that forces `close`/`dup`/send/recv capture, userspace `*at` resolution, a single consumer doing a k-way timestamp merge) is what panopticon's design rejects. Worth keeping: `BPF_RB_NO_WAKEUP` with a backoff poller, per-class kernel drop counters, BPF task iterators instead of `/proc`, and the 2-slot scratch pool with explicit reentrancy counters if records are ever built in scratch memory on preemptible kernels.

### Cilium Tetragon

Surveyed: [v1.8.0](https://github.com/cilium/tetragon/releases/tag/v1.8.0) (2026-10-30); source at main [`31e646a`](https://github.com/cilium/tetragon/tree/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5), two commits after the tag. BPF C dual GPL-2.0/BSD-2-Clause, Go agent Apache-2.0 ([bpf_execve_event.c#L1-L19](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_event.c#L1-L19)). Helm DaemonSet or host package; minimum kernel 4.19 with BTF ([faq.md#L8-L27](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/installation/faq.md#L8-L27)). Policies are `TracingPolicy`/`TracingPolicyNamespaced` CRDs, YAML files or gRPC.

Tetragon is two things: an always-on process sensor with no syscall hooks, and a policy engine that can attach to almost any kernel or user function. Its cost depends on which functions the loaded policies hook.

#### Kernel mechanism and attach points

Base sensor, always loaded ([base.go#L32-L97](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/base/base.go#L32-L97)):

- **exec**: raw tracepoint `sched_process_exec`. v1.8.0 moved it to a raw tracepoint and removed its tail calls (#5346, #5353 in the [release notes](https://github.com/cilium/tetragon/releases/tag/v1.8.0); [bpf_execve_event_notc.c#L21-L36](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_event_notc.c#L21-L36)).
- **exec privilege**: kprobe `security_bprm_committing_creds` compares old and new euid/egid/permitted caps and the exe's link count, and stores a record only if the exec is setuid/setgid, gains file caps, or runs an unlinked file ([bpf_execve_bprm_commit_creds.c#L47-L162](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_bprm_commit_creds.c#L47-L162)).
- **fork**: kprobe `wake_up_new_task` creates the child's entry in the kernel process table and emits one clone message per new thread group; new threads enter and return early ([bpf_fork.c#L76-L149](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_fork.c#L76-L149)).
- **exit**: kprobe `acct_process` (fallback `disassociate_ctty`), once per thread group, reads `exit_code` and deletes the table entry ([bpf_exit.c#L18-L161](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_exit.c#L18-L161)).
- **cgroups**: raw tracepoints `cgroup_mkdir`, `cgroup_rmdir`, `cgroup_release` feed a cgroup-id to container tracker ([bpf_cgtracker.c#L49-L69](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/cgroup/bpf_cgtracker.c#L49-L69)).
- Startup walks `/proc` and emits synthetic execs flagged `procFS` ([proc_reader_linux.go#L92-L136](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/exec/procevents/proc_reader_linux.go#L92-L136)).

[INFERENCE from the attach list] The base sensor costs nothing per syscall: it runs per exec, per new task (including threads, which return early), per thread-group exit and per cgroup operation.

Policy-driven sensors ([hooks.md#L7-L20](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L7-L20)): `kprobes` (single or `kprobe.multi`, kretprobe with `return: true`), `fentries` (fentry/fexit, ≥ 6.1), `tracepoints` (perf or raw), `uprobes`, `usdts`, `lsmhooks` (BPF LSM). Syscalls can be hooked as `sys_*` kprobes or via `raw_syscalls/sys_enter` ([hooks.md#L46-L55](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L46-L55), [#L218-L236](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L218-L236)), in which case every caller of that syscall pays. A loader sensor reports mapped executables and libraries with build ids through a `PERF_COUNT_SW_BPF_OUTPUT` perf event plus a kprobe on `perf_event_mmap_output`, deduplicated in userspace ([loader_linux.go#L123-L207](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/tracing/loader_linux.go#L123-L207), [bpf_loader.c#L66-L140](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_loader.c#L66-L140)).

#### Event inventory

Exported types: `process_exec`, `process_exit`, `process_kprobe`, `process_tracepoint`, `process_loader`, `process_uprobe`, `process_throttle`, `process_lsm`, `process_usdt` ([events.proto#L204-L224](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/events.proto#L204-L224)). There is no exported fork event. Every event carries a `Process` object ([tetragon.proto#L195-L308](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L195-L308)): `exec_id` (base64 of `node:ktime:pid`), pid, tid, uid, cwd, binary, arguments, flags, start time, `auid`, pod, container id, `parent_exec_id`, caps, namespaces, full credentials, `binary_properties` (setuid/setgid, privilege change, inode and link count for memfd/deleted executables), optional environment, plus `parent` and optional `ancestors`.

Everything beyond exec/exit comes from `process_kprobe`/`process_lsm` events defined by policies. The shipped examples and policy library cover:

- Process: credential changes via `__sys_set*id`, `security_capset`, `create_user_ns`, `commit_creds`, `cap_capable` ([privileges-raise.yaml#L67-L207](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/privileges/privileges-raise.yaml#L67-L207)); `sys_ptrace` example.
- File: `security_file_permission`, `security_mmap_file`, `security_path_truncate` with path prefix filters ([file_monitoring.yaml#L7-L148](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/quickstart/file_monitoring.yaml#L7-L148)); `sys_linkat`, `sys_symlinkat` examples; LSM `file_open`.
- Network: `sock` arguments carry family, type, protocol, addresses, ports, socket cookie and state ([tetragon.proto#L338-L350](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L338-L350)); examples hook `tcp_connect`/`tcp_close`/`tcp_sendmsg` ([tcp-connect.yaml#L7-L23](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/tcp-connect.yaml#L7-L23)), `inet_csk_listen_start`, `__cgroup_bpf_run_filter_skb` for datagrams.
- Kernel/admin: `bpf_check`, `security_perf_event_alloc`, `security_bpf_map_create` ([bpf.yaml#L7-L80](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/bpf.yaml#L7-L80)); `security_kernel_module_request`, `security_kernel_read_file` ([modules.yaml#L10-L32](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/modules.yaml#L10-L32)); `sys_mount`, `sys_pivot_root`, `sys_clock_settime`, `sys_setns`.
- Container/K8s: `pod` with namespace, name, labels, workload, annotations, container id/name/image and `security_context.privileged` ([tetragon.proto#L15-L68](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L15-L68)).
- Sensor: `process_throttle` start/stop per cgroup ([cgroup-rate.md#L63-L91](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/cgroup-rate.md#L63-L91)).

#### Enrichment

- **In-kernel process table.** `execve_map` is a hash keyed by tgid holding `{pid, ktime}`, parent key, flags, namespace pid, namespaces, caps, binary path, a matchBinaries bitset and args ([process.h#L357-L398](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/process.h#L357-L398)); 32,768 entries by default ([base.go#L27-L30](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/base/base.go#L27-L30)). Every policy hook looks up the current tgid to stamp the process key and evaluate process filters in the kernel.
- **Kernel-side exec record.** argv from the new mm, optional env, `bprm->filename`, cwd and the absolute exe path resolved with an in-BPF `d_path` (first 255 and last 127 bytes), creds, namespaces, auid, cgroup id and name ([bpf_execve_event.h#L209-L274](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_event.h#L209-L274), [process.h#L708-L753](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/process.h#L708-L753)).
- **Userspace mirror.** An LRU process cache of 65,536 entries with refcounts and a 30 s GC ([cache.go#L25-L201](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/process/cache.go#L25-L201)); events whose process or pod is not yet known are retried 15 times every 2 s ([defaults.go#L66-L70](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/defaults/defaults.go#L66-L70)). v1.8.0 can disable the cache (`--disable-process-cache`, [flags.go#L543](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/option/flags.go#L543)).
- **Containers and pods.** Container id from the BPF-captured cgroup name, or a cgroup-id map filled by an OCI/NRI runtime hook or CRI ([exec_linux.go#L39-L80](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/exec/exec_linux.go#L39-L80), [runtime-hooks.md#L7-L30](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/runtime-hooks.md#L7-L30)); pod metadata from a node-scoped pod informer indexed by container id ([pod.go#L102-L125](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/watcher/pod.go#L102-L125)).
- **Hashes**: IMA hashes only, from LSM hooks with `imaHash: true` (IMA plus BPF LSM, ≥ 5.11; [selectors.md#L1554-L1603](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1554-L1603)); loader events carry ELF build ids. User names only for host-namespace processes ([userinfo.go#L18-L47](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/exec/userinfo/userinfo.go#L18-L47)).

#### In-kernel filtering, dedup, rate limiting

- **Selectors compiled to bytes.** Up to 5 selectors per hook; userspace encodes each into a byte program (sections for PIDs, namespaces, capabilities, namespace/capability changes, states, args, actions) stored in `filter_map` and interpreted by BPF ([kernel.go#L2034-L2076](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/selectors/kernel.go#L2034-L2076), [generic_calls.h#L1438-L1459](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/generic_calls.h#L1438-L1459)).
- **Cheap filters first.** The tail-call chain runs the per-policy cgroup filter, then process filters, and only then reads arguments (`d_path` and friends) and evaluates `matchArgs` ([bpf_generic_kprobe.c#L19-L139](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_generic_kprobe.c#L19-L139), [generic_calls.h#L42-L99](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/generic_calls.h#L42-L99)). K8s scoping uses a hash-of-maps from policy id to allowed cgroup ids ([policy_filter.h#L10-L114](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/policy_filter.h#L10-L114)).
- **Precompute at exec.** `matchBinaries` paths are resolved at exec into a bitset stored in the process entry (inherited by children for `followChildren`), so a hook tests one bit ([bpf_mbset.h#L9-L46](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_mbset.h#L9-L46)). Namespace and capability changes are detected against the exec-time snapshot.
- **String and address maps.** Exact strings go in 11 hash maps bucketed by padded length (25 to 4,098 bytes) to bound hashing cost; prefixes in an LPM trie; suffixes in an LPM trie over the reversed string; CIDRs in LPM tries ([string_maps.h#L9-L237](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/string_maps.h#L9-L237), [addr_lpm_maps.h#L15-L40](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/addr_lpm_maps.h#L15-L40)).
- **`rateLimit` dedup.** An LRU hash keyed by (hook, action, thread/process/global scope, first 40 bytes of each argument) holds the last emit time and suppresses repeats inside the window ([basic.h#L2529-L2604](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/types/basic.h#L2529-L2604)).
- **Per-cgroup throttle** (`--cgroup-rate`, off by default): a per-CPU hash per cgroup with a two-window sliding rate; at the threshold it emits one throttle record and stops exec/clone events from that cgroup on that CPU; userspace decides when to stop throttling ([bpf_rate.h#L28-L148](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_rate.h#L28-L148), [cgrouprate.go#L125-L270](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/cgrouprate/cgrouprate.go#L125-L270)).
- **Actions** in BPF: `Sigkill`, `Signal`, `Override` (error injection on allow-listed functions and `security_*` hooks), `NotifyEnforcer`, `Post`/`NoPost`, `UpdateState` ([selectors.md#L1019-L1188](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1019-L1188)). The old userspace fd→name tracking (`FollowFD`) is "Deprecated and no more supported"; `fd` arguments are resolved in BPF ([api README#L1559-L1561](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/README.md#L1559-L1561), [basic.h#L2734-L2763](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/types/basic.h#L2734-L2763)).
- **Still paid by unrelated activity.** Selectors cut work only after the probe fires. The quickstart file-monitoring policy puts a kprobe and kretprobe on `security_file_permission` ([file_monitoring.yaml#L7-L17](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/quickstart/file_monitoring.yaml#L7-L17)), which Isovalent describes as "called on every file access in the system" ([file monitoring part 1](https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/)).

#### Transport

- **Kernel ≥ 5.11: one BPF ringbuf shared by all CPUs** (`tg_rb_events`, [bpf_event.h#L19-L25](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/bpf_event.h#L19-L25)), 64 KiB × possible CPUs by default ([config_linux.go#L213-L231](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/config/config_linux.go#L213-L231)), written with `bpf_ringbuf_output(..., 0)`, i.e. default wakeups ([process.h#L658-L693](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/process.h#L658-L693)). Older kernels or `--use-perf-ring-buffer`: a per-CPU perf event array of 64 KiB per CPU ([observer_linux.go#L25-L52](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/observer/observer_linux.go#L25-L52)).
- **Loss accounting at the producer.** Each failed write increments a per-CPU `sent_failed[opcode][errno]` counter ([process.h#L590-L656](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/process.h#L590-L656)), exported as `tetragon_bpf_missed_events_total{error,opcode}`; probe misses from kprobe link and program recursion counters ([collector.go#L49-L68](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/metrics/kprobemetrics/collector.go#L49-L68)); userspace queue drops separately ([metrics.go#L29-L61](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/observer/metrics.go#L29-L61)).
- **Userspace**: a reader goroutine feeds a 65,535-entry channel; one goroutine drains it and runs the handlers and exporters synchronously ([observer_linux.go#L105-L201](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/observer/observer_linux.go#L105-L201)). Large payloads travel as separate data records joined in userspace. Export via gRPC or a JSON file; the Helm default JSON deny list drops host and `kube-system` events ([values.yaml#L114-L125](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/install/kubernetes/tetragon/values.yaml#L114-L125)). The open-source export aggregator forwards every event unchanged ([aggregator.go#L72-L79](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/aggregator/aggregator.go#L72-L79)).

#### Published overhead

| Source | Setup | Result |
|---|---|---|
| Isovalent, Tetragon 1.0 blog, 2023 ([post](https://isovalent.com/blog/post/tetragon-release-10/)), vendor | Linux 6.1.13 kernel build, ~1.5M exec events at 2.6K/s; host not stated | 549.3 s → 558.5 s (+1.68%); 562.8 s (+2.46%) writing JSON. |
| same | 32 threads doing 1K sequential reads; FIM policy matching nothing | CPU 23.83% → 24.03%; an unnamed "traditional solution" without in-kernel filtering 27.44%. |
| same | netperf TCP_CRR | All events filtered: −5.88% conn/s; logging every connection: −17.49%. Policies not published. |
| Maintainers, LSFMM/BPF 2023 ([slides](https://bpfconf.ebpf.io/bpfconf2023/bpfconf2023_material/LSFMM_Tetragon.pdf), slide 17) | `perf stat` over `make -j16 && make clean` | Loader sensor +2.79%; kprobes on 190 syscalls with a filter that matched nothing +6.42% time, +5.26% cycles; exporting every open/close +23% time with 48.8M events lost against 27.5M delivered. |
| Syairozi & Arizal, RITECH 2025 ([paper](https://www.scitepress.org/Papers/2025/142727/142727.pdf)), independent | DOKS, 2 vCPU nodes, Helm defaults | 6.5 mcores idle, 6.9 under attack scenarios; 635-642 MB. Measures the agent's own container only. |

The repo has a `perf stat` harness with no committed results ([bench.sh](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/contrib/bench/bench.sh#L1-L100)) and exposes per-program run counts and time with `kernel.bpf_stats_enabled` ([bpf-progs-stats.md](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/troubleshooting/bpf-progs-stats.md#L12-L174)). The LSFMM row is the clearest published number for principle 1 in any agent: hooking syscalls costs about 6% even when nothing matches.

#### Documented blind spots

- **Credentials only at exec**, for the main thread; later setuid/capset are not reflected ([threat model#L319-L327](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/threat-model/_index.md#L319-L327)).
- **Exit status** missing from output, open since 2023 ([#902](https://github.com/cilium/tetragon/issues/902)).
- **Path-based file matching** misses hard links and bind mounts ([filename-access.md#L291-L295](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/use-cases/filename-access.md#L291-L295)); inode-based FIM is in the commercial edition ([Isovalent](https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/)).
- **TOCTOU** on syscall hooks with user pointers; the docs recommend `security_*` hooks ([hooks.md#L13-L20](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L13-L20)).
- **io_uring**: syscall-based sample policies miss it; maintainers' position is that users must hook kernel functions or LSM ([ARMO](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)).
- **Kprobe portability**: renamed functions (`security_bpf_map_alloc` → `security_bpf_map_create` in 6.9, `security_path_truncate` → `security_file_truncate` in 6.2) need `ignore.callNotFound` ([observability/_index.md#L406-L410](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/policy-library/observability/_index.md#L406-L410)).
- **Floods**: the threat model says a workload can flood events and cause loss, and points to the loss metrics and cgroup throttling ([threat model#L144-L181](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/threat-model/_index.md#L144-L181)).
- **Root on the node** can unload programs; no tamper protection ([threat model#L307-L318](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/threat-model/_index.md#L307-L318)).
- No DNS parsing or HTTP/TLS metadata in the open-source edition; TLS visibility is in [Isovalent Enterprise 1.13](https://isovalent.com/blog/post/isovalent-enterprise-for-tetragon-1-13/). [INFERENCE] No post-NAT tuple: socket hooks see the socket's own addresses.

#### Relevance to panopticon

Tetragon's base sensor already follows principle 1 (exec, fork, exit and cgroup hooks only), and the LSFMM measurement quantifies what syscall hooks cost even when filtered. Techniques worth copying: gating expensive argument extraction behind cheap cgroup and process checks; precomputing per-process predicates at exec into the task's record; length-bucketed hash maps and LPM tries for path matching; an argument-keyed LRU for dedup; per-opcode, per-errno producer loss counters. Differences: Tetragon mirrors process state twice (`execve_map` in the kernel and an LRU cache in userspace), keys processes by `(pid, ktime)` rather than a kernel-unique id, and uses one shared ringbuf with default wakeups drained by one goroutine. Panopticon's task-local storage and pidfs inode replace the tgid hash.

### Aqua Tracee

Surveyed: latest release v0.24.1 (2025-11-19, [releases](https://github.com/aquasecurity/tracee/releases)); source at main [`2f9dc40`](https://github.com/aquasecurity/tracee/tree/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62) (2026-09-29), whose eBPF hook set matches v0.24.1. Main moved the Go signatures into `detectors/` and added YAML/CEL detectors ([detectors/README.md](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/README.md)). Apache-2.0 Go userspace on libbpfgo; one CO-RE C file of 7,768 lines, GPL ([tracee.bpf.c#L1-L41](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L1-L41)). Single binary or Helm DaemonSet; up to 64 `Policy` CRs ([policies/index.md#L5](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/policies/index.md#L5)). Detection only ([lsm-support.md#L84](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/install/lsm-support.md#L84)). Kernel 5.4+ (or RHEL 8 4.18), BTF or embedded BTFHub types ([prerequisites.md#L17-L57](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/install/prerequisites.md#L17-L57)).

#### Kernel mechanism and attach points

Program sections in `tracee.bpf.c`: 33 `raw_tracepoint`, 80 `kprobe`, 24 `kretprobe`, 17 `uprobe` (on Tracee's own Go functions, used to trigger in-kernel scans), 2 `cgroup_skb`, 1 `lsm` (test only). No fentry/fexit, no `tp_btf`, no production BPF LSM ([probe_group.go#L199-L341](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/probes/probe_group.go#L199-L341)).

- **Syscalls: global raw tracepoints plus tail calls.** `raw_syscalls:sys_enter` does compat translation and tail-calls `sys_enter_init`, which saves the six arguments and a timestamp in the per-thread `task_info_map` entry, then tail-calls the per-syscall program ([tracee.bpf.c#L45-L133](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L45-L133)); `sys_exit` mirrors it and most syscall events are emitted at exit with string arguments read then ([tracee.bpf.c#L186-L300](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L186-L300)). Tail-call slots exist only for selected syscalls ([core.go#L314-L341](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L314-L341)).
- **Unrelated syscalls pay.** [INFERENCE from code] Once any syscall event is selected, every syscall on the host runs both raw tracepoint programs (task lookup, compat check, a failed tail call). The `default` event set includes 25 syscall events (chmod, chown, the setuid family, ptrace, init_module, setns, memfd_create, ...), so a run with no arguments pays it ([policy.go#L386-L398](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/cmd/flags/policy.go#L386-L398)).
- **"LSM" events are kprobes on `security_*` functions**: `security_bprm_check`, `security_file_open`, `security_file_permission`, `security_socket_{create,listen,connect,accept,bind,setsockopt,sendmsg,recvmsg}`, `security_sb_mount/umount`, `security_bpf*`, `security_kernel_read_file`, `security_inode_{mknod,symlink,unlink,rename}`, `security_mmap_file`, `security_file_mprotect`, `security_settime64`, `security_task_prctl` and more ([probe_group.go#L226-L340](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/probes/probe_group.go#L226-L340)). Some still pull in the global syscall dispatcher to recover syscall arguments: `security_bprm_check` gets argv/envp that way ([core.go#L12983-L13001](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L12983-L13001)).
- **Other kprobes**: `commit_creds`, `switch_task_namespaces`, `cap_capable`, `vfs_write/read` (+ret), `do_mmap`, `fd_install`, `filp_close`, `file_modified`, `file_update_time`, `chmod_common`, `load_elf_phdrs`, `register_kprobe`, `do_init_module`, `bpf_check`, `call_usermodehelper`, `sock_alloc_file`, `__cgroup_bpf_run_filter_skb`. `ptrace`, `process_vm_writev`, `arch_prctl` and `dup*` use per-syscall kprobes on `__x64_sys_<name>` rather than the global tracepoint ([probe_group.go#L326-L337](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/probes/probe_group.go#L326-L337)).
- **Raw tracepoints**: `sched_process_fork/exec/exit/free`, `sched_switch`, `cgroup_attach_task/mkdir/rmdir`, `module_load/free`, `task_rename`; fork/exec/exit and cgroup mkdir/rmdir are always attached ([policy_manager.go#L173-L184](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/policy/policy_manager.go#L173-L184)).
- **Network**: `cgroup_skb/ingress` and `egress` on the cgroup v2 root, fed by the `__cgroup_bpf_run_filter_skb` kprobe, which resolves socket inode → task through `inodemap` and stashes context in an LRU keyed by L3 header fields for the skb program ([tracee.bpf.c#L6476-L6563](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L6476-L6563)). IPv4/IPv6 only; DNS and HTTP are parsed in userspace. Not loaded unless a network event is selected ([probe_group.go#L376-L384](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/probes/probe_group.go#L376-L384)).

#### Event inventory

About 589 event definitions in [core.go](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go): about 447 syscall events, about 140 kprobe/tracepoint/derived events, plus 31 detectors.

- Process: `sched_process_exec` (cmdpath, pathname, dev, inode, ctime, interpreter path/inode, argv from the new mm, `stdin_type`/`stdin_path`, optional env, pwd, optional `sha256`; [core.go#L12662](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L12662)); `sched_process_fork`; `sched_process_exit` (exit_code, signal_code); `process_execute_failed`; `commit_creds` (old/new cred, emitted only if an id or cap changed, [tracee.bpf.c#L2493-L2509](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2493-L2509)); `cap_capable`; `mem_prot_alert`; `suspicious_syscall_source`; `stack_pivot`.
- File: `security_file_open` (pathname, flags, dev, inode, ctime; [core.go#L13014](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13014)), `magic_write` (first ≤ 20 bytes written at offset 0), `file_modification`, `security_inode_unlink/rename/symlink/mknod`, `chmod_common`, `do_truncate`, `security_mmap_file`, `shared_object_loaded`, `symbols_loaded`.
- Network: `security_socket_*` with addresses including `sockaddr_un`; derived `net_tcp_connect`; `net_packet_{ipv4,ipv6,tcp,udp,icmp,dns,dns_request,dns_response,http,http_request,http_response}`; `net_flow_tcp_begin/end`.
- Kernel/admin: `module_load`, `do_init_module`, `security_kernel_read_file`, `security_bpf_prog` (type, name, helpers), `bpf_attach`, `kprobe_attach`, `security_sb_mount/umount`, `switch_task_ns`, `security_settime64`, `call_usermodehelper`, and rootkit checks (`hooked_syscall`, `hidden_kernel_module`, `hooked_proc_fops`, `ftrace_hook`, ...).
- Container/K8s: `container_create`, `container_remove`, `existing_container` with runtime, id, image, digest, name, pod name/namespace/uid ([core.go#L13558-L13598](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13558-L13598)).
- Detectors TRC-101..1031 ([security-events.md#L54-L87](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/events/builtin/security-events.md#L54-L87)): stdio over socket, anti-debugging, ptrace code injection, fileless execution, LD_PRELOAD, K8s service account token, cgroup release_agent, core_pattern modification, kernel module loading, dropped executable, `/proc/<pid>/mem` access and injection, `process_vm_writev` injection, rc.d/cron/sudoers modification, syscall hooking, and others.

#### Enrichment

- **Kernel**: each event carries host and namespace pid/tid/ppid, uid, mount/pid namespace ids, comm, uts name, cgroup id and start times, gathered by walking `task_struct` on every submit ([context.h#L27-L70](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/context.h#L27-L70), [buffer.h#L705-L710](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/buffer.h#L705-L710)). No loginuid or session id.
- **Containers**: startup walk of cgroupfs, container id parsed from the cgroup path, then image, digest and pod name/namespace/uid fetched once per container from Docker/containerd/CRI-O/Podman sockets ([containers.go#L193-L330](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/container/containers.go#L193-L330)). Pod labels and the privileged flag are not exported. The kernel tracks per-cgroup container state (existed/created/started) in `containers_map` for the `container=new|started` scopes ([maps.h#L20-L26](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/maps.h#L20-L26)).
- **Process tree** in userspace: LRU of 10,000 processes keyed by (host tid, start time), seeded by a full `/proc` scan and on-demand procfs reads ([proctree.go#L38-L95](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/process/proctree.go#L38-L95)). It is fed by both pipeline events and control-plane signals on a separate perf buffer, so fork/exec/exit are submitted twice ([policy_manager.go#L186-L208](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/policy/policy_manager.go#L186-L208)).
- **Executable hash** (`--enrichment executable-hash`): sha256 computed in userspace by opening `/proc/<pid>/root/<path>`, cached by (dev, inode) or (digest, inode) with ctime revalidation; memfd files are not hashed ([processor_funcs.go#L120-L219](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/processor_funcs.go#L120-L219)).
- **Artifacts**: forensic capture of written/read files, executables, kernel modules, BPF programs, W+X memory regions and pcaps ([artifacts.1.md#L20-L50](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/flags/artifacts.1.md#L20-L50)).

#### In-kernel filtering and dedup

- **Scope filters as 64-bit policy bitmaps.** Each filter map value is `{equals_in_policies, key_used_in_policies}`, so one hash lookup answers all 64 policies as `equals | (match_if_missing & ~key_used)` ([filtering.h#L99-L156](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/filtering.h#L99-L156)). In-kernel scopes: pid/tid, uid, mount/pid/uts namespace, comm, cgroup id, container state, process tree (inherited at fork), executable path, and `follow` for children ([scopes.md#L15-L45](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/policies/scopes.md#L15-L45)). Container image/name and pod scopes are evaluated in userspace.
- **Atomic policy updates**: every filter map is an inner map of a hash-of-maps keyed by a 16-bit policy version ([maps.h#L402-L660](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/maps.h#L402-L660)).
- **Argument filters in the kernel only for paths** (exact match in a hash, prefix and suffix in LPM tries, 1,024 entries each) and only on `security_file_open`, `magic_write` and `security_mmap_file` ([data.go#L280-L284](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/filters/data.go#L280-L284), [filtering.h#L356-L455](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/filtering.h#L356-L455)); `security_file_open` still walks the dentry path and builds every argument before that filter runs ([tracee.bpf.c#L2329-L2363](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2329-L2363)). All other argument and return-value filters run in userspace ([events_pipeline.go#L293-L307](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/events_pipeline.go#L293-L307)).
- **Dedup**: `file_modification` emits at most one event per (pid, dev, inode) per open: `fd_install` arms an LRU entry for files opened for write, and the first modification marks it done ([tracee.bpf.c#L4910-L5069](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L4910-L5069)). `suspicious_syscall_source` inserts with `BPF_NOEXIST` into a 4,096-entry LRU to emit once per (syscall, process, VMA) ([tracee.bpf.c#L5704-L5715](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L5704-L5715)). `switch_task_ns` fires only when a namespace changed; `cap_capable` skips no-audit checks.
- **Kernel state mirrors**: `proc_info_map` (LRU 30,720 per tgid) and `task_info_map` (LRU 10,240 per tid, including saved syscall arguments) ([maps.h#L50-L66](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/maps.h#L50-L66)); `inodemap` (LRU 65,535, socket inode → task context) is rewritten on every in-scope `sendmsg`/`recvmsg` ([tracee.bpf.c#L6391-L6470](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L6391-L6470)). Each kprobe runs about seven map lookups in `init_program_data` before scope checks ([context.h#L117-L212](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/context.h#L117-L212)).

#### Transport

- Per-CPU perf buffers only; BPF ringbuf support is an open issue since 2020 ([#476](https://github.com/aquasecurity/tracee/issues/476)). Buffers: `events`, `file_writes`, `signals`, `logs`, `net_cap_events` ([maps.h#L688-L724](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/maps.h#L688-L724)), 4 MiB per CPU each by default ([buffers.go#L117-L122](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/cmd/flags/buffers.go#L117-L122)). Records are an event context plus TLV arguments built in a 32,000-byte per-CPU scratch ([buffer.h#L705-L734](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/buffer.h#L705-L734)); timestamps from `bpf_ktime_get_boot_ns` ([common.h#L91-L96](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/common.h#L91-L96)).
- Wakeups: libbpfgo calls `perf_buffer__new` with default options ([libbpfgo.c#L92-L109](https://github.com/aquasecurity/libbpfgo/blob/96cbab36fb96ce52522352809a335b7ff3fef8ef/libbpfgo.c#L92-L109)) and libbpf sets `wakeup_events = 1` ([libbpf.c#L14982-L15013](https://github.com/libbpf/libbpf/blob/85c0d575a447651bbeb8e2376eacd64c30dce9a6/src/libbpf.c#L14982-L15013)), so every record wakes the reader. Panopticon measured this configuration at +541 ns per event against +11 ns for its own rings ([design.md](../design.md#transport)).
- Loss: perf lost-sample callbacks feed Prometheus `tracee_lostevents_total`, `tracee_write_lostevents_total`, `tracee_network_capture_lostevents_total` ([stats.go#L94-L256](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/metrics/stats.go#L94-L256)); not per event class.
- Userspace: a goroutine per stage (decode, optional sort, process, enrich, derive, detect, sink) connected by 1,000-event channels ([events_pipeline.go#L35-L109](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/events_pipeline.go#L35-L109)).

#### Published overhead

Aqua publishes no overhead figures; the repo has tooling only ([tracee-bench](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/cmd/tracee-bench/readme.md#L1-L18), [network bench.sh](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/performance/benchmark/network/bench.sh)).

| Source | Setup | Result |
|---|---|---|
| MERLIN, ASPLOS'24 ([PDF](https://people.cs.umass.edu/~juanzhai/papers/asplos24.pdf), Table 4) | Tracee default settings, output to /dev/null; kernel 5.15, Ryzen 6800H; lmbench | null syscall 0.06 → 0.10 µs, open/close 0.79 → 0.94 µs, fork 72.9 → 76.1 µs, exec 321.5 → 337.4 µs, file create 4.78 → 7.31 µs, pipe 5.24 → 9.48 µs. |
| Her et al., IEEE Access 2025 ([PDF](https://cclab.info/papers/2025_her_access.pdf)) | single-node K8s; `/usr/bin/ls` × 10,000; 100,000 UDP packets | exec loop +9.97% without a user policy, +37.59% with a process policy (attributed to tail-call chains re-running policy matching); UDP +1.48% without, +71.50% with a network policy; 0% loss up to 486 execs/s. |
| Aquila, Sensors 2025 ([paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12608121/)) | all supported syscalls traced, OSBench, kernel 5.15 | CPU above 300% on most workloads (389.5% launching programs); 2-32% fewer events than Aquila; iperf3 13.98 Gbps vs 21.70 for Falco. |
| Syairozi & Arizal, RITECH 2025 ([paper](https://www.scitepress.org/Papers/2025/142727/142727.pdf)) | DOKS 2 vCPU nodes, Helm defaults | 91.6 mcores idle, 93.7 under attack; ~573 MB. |

The MERLIN null-syscall result (+40 ns) is consistent with the always-attached dispatcher [INFERENCE].

#### Documented blind spots

- **TOCTOU** on syscall arguments; the docs recommend cross-checking syscall events against LSM-hook events ([security-model.md#L116-L165](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/security-model.md#L116-L165)). `security_bprm_check` argv/envp come from saved syscall arguments and are flagged as TOCTOU-prone in its own page ([security_bprm_check.md#L79-L84](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/events/builtin/man/lsm/security_bprm_check.md#L79-L84)). Phantom attack demonstrated this class against Tracee in 2021 ([DEF CON 29](https://av.tib.eu/media/54228)). A 5-entry path cache can be overwritten by another CPU mid-use ([#3804](https://github.com/aquasecurity/tracee/issues/3804)).
- **io_uring**: only `io_uring_setup/enter/register` syscall events; "Add io_uring tracepoints" open since 2020 ([#309](https://github.com/aquasecurity/tracee/issues/309)). [INFERENCE] Operations reaching the kprobed `security_*`/`vfs_*` functions are still seen.
- **Drops**: the troubleshooting guide says to enlarge buffers or filter ([troubleshooting.md#L137-L156](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/troubleshooting.md#L137-L156)); detectors miss events silently when base events are lost.
- **Network**: sockets need a task association made by an in-scope task, otherwise packets are skipped ([tracee.bpf.c#L6542-L6559](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L6542-L6559)); dual-stack IPv6 "unsupported for now" ([tracee.bpf.c#L6891-L6893](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L6891-L6893)); flow byte counters are commented out ([network.h#L59-L69](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/network.h#L59-L69)); HTTP is plaintext only. [INFERENCE] The root `cgroup_skb` programs see pre-SNAT egress addresses.
- **Self-defense**: root with CAP_BPF can detach programs or edit maps ([security-model.md#L13-L45](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/security-model.md#L13-L45)).
- [INFERENCE] Hashes are computed from `/proc/<pid>/root/<path>` after the event, so the file may have changed or the mount namespace may be gone ([processor_funcs.go#L139-L144](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/processor_funcs.go#L139-L144)).

#### Relevance to panopticon

Tracee shows both directions. Worth copying: one hash lookup answering many policies through bitmask values; versioned map-of-maps for atomic configuration swaps; the open→first-write state machine that reduces every write on a file to one record per open; `BPF_NOEXIST` inserts for once-per-key emission; exec argv read from the new mm at `sched_process_exec` instead of from syscall arguments. Counter-examples: the global syscall dispatcher kept alive by a default event set, a per-thread kernel copy of syscall arguments, a socket→task mirror rewritten on every send/receive, a full `task_struct` walk per event, perf buffers with a wakeup per record, and fork/exec/exit submitted twice.

### Datadog Workload Protection (formerly Cloud Workload Security)

Surveyed: datadog-agent release 7.85.0 (2026-10-29, [releases API](https://api.github.com/repos/DataDog/datadog-agent/releases?per_page=5)); source at main [`7619c1d`](https://github.com/DataDog/datadog-agent/tree/7619c1de291765f5553bb5911af3e1386522a4b9) (sparse clone of `pkg/security`, `pkg/config/setup`, `docs/cloud-workload-security`). The runtime security module runs inside `system-probe`; the separate `security-agent` runtime has been unused since 7.77 ([agent config docs](https://docs.datadoghq.com/security/workload_protection/setup/advanced_configuration/)). Agent Apache-2.0, eBPF C GPL-2.0 ([COPYING](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/COPYING)). The default agent ruleset is public in `DataDog/security-agent-policies` v0.86.0 [`d66bad4`](https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy) (5,313 lines). Backend detection rules, signals and storage are closed SaaS; the docs list "over 350 agent rules and 200 detection rules" ([docs](https://docs.datadoghq.com/security/workload_protection/)). Agent events are emitted only when an agent rule matches; they are re-evaluated in the backend.

#### Kernel mechanism and attach points

- **kprobe/kretprobe by default.** `HOOK_ENTRY`/`HOOK_EXIT` compile to kprobe/kretprobe or to fentry/fexit in a second object ([fentry_macro.h#L8-L64](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/constants/fentry_macro.h#L8-L64)). fentry is opt-in (`event_stream.use_fentry: false`, [settings#L447](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L447)) and refused below 6.1 ([probe_ebpf.go#L342-L369](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L342-L369)). No `lsm/` programs exist in `pkg/security/ebpf`; `security_*` functions are hooked with kprobes for observation.
- **Not CO-RE.** Struct offsets are injected as load-time constants from, in order, kernel BTF, an embedded BTFHub-derived table, a runtime offset-guessing eBPF program, then hardcoded fallbacks ([available.go#L24-L45](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/constantfetch/available.go#L24-L45)); dead-code elimination on constants picks map types and code paths at load ([perf_ring.h#L34-L66](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/perf_ring.h#L34-L66)). Kernel ≥ 4.14, RHEL 7 in degraded mode ([setup docs](https://docs.datadoghq.com/security/workload_protection/setup/)).
- **About 150 kernel functions** ([event_types.go#L272-L504](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L272-L504)). Process: fork (tracepoint or `get_task_pid`), `do_exit`, `bprm_execve`/`security_bprm_check`, `setup_new_exec`, `setup_arg_pages`, `commit_creds`, `switch_task_namespaces`, `audit_set_loginuid`, cgroup writes. File: `vfs_open`, `terminate_walk`, `security_inode_setattr`, `vfs_rename`, `vfs_unlink`, `security_inode_rmdir`, `vfs_mkdir`, `vfs_setxattr`, mount internals. Kernel/admin: `security_bpf_map/prog`, `check_helper_call`, `ptrace_check_attach`, `security_mmap_file`, `security_kernel_read_file`, `proc_sys_call_handler` plus a `cgroup/sysctl` program ([event_types.go#L602-L771](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L602-L771)). Network: `security_socket_bind/connect`, `inet_csk_accept`, `security_sk_classify_flow`, NAT `nf_nat_manip_pkt`/`nf_nat_packet` (only if `nf_nat` is loaded), TC `classifier/ingress` and `egress` ([tc.h#L9-L28](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/tc.h#L9-L28)), `cgroup/sock_create`, `cgroup/connect4/6`. io_uring: `io_openat`, `io_openat2`, `io_connect`, `io_bind`, `io_socket`, `io_issue_sqe` and others ([event_types.go#L374-L393](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L374-L393)).
- **Syscall entry/exit kprobes per syscall.** File and credential syscalls are also hooked at their arch wrappers (`__x64_sys_openat`, ia32 variants) with entry and return probes ([syscall_helpers.go#L94-L147](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/syscall_helpers.go#L94-L147)). The entry stores a `syscall_cache_t` per task (task-local storage when available), the VFS/LSM hook fills in the dentry and runs approvers, and the return probe emits the event ([open.h#L16-L313](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/open.h#L16-L313)). The always-attached set covers execve/execveat, all set*id, capset, setsid, open/creat/truncate/openat/openat2, the mount family, unshare, pivot_root, rename*, unlink*, rmdir, link* ([event_types.go#L336-L495](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L336-L495)). Other event types (chmod, bpf, ptrace, mmap, modules, signal, connect, sysctl, ...) attach only when a loaded rule, activity dump, profile or sampler needs them ([probe_ebpf.go#L2709-L2721](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L2709-L2721)).
- **No hook on every syscall by default.** `raw_syscalls/sys_exit` attaches only on kernels < 4.12 or RHEL 7 ([syscall_helpers.go#L78-L85](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/syscall_helpers.go#L78-L85)); `raw_syscalls/sys_enter` only for syscall-drift profiling or raw-syscall kill enforcement, both off by default ([probe_ebpf.go#L2740-L2745](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L2740-L2745)). What unrelated activity does pay by default: a kprobe+kretprobe pair on every call in the always-attached syscall set even with zero rules, the open handler on every `vfs_open`, and with `network.enabled: true` (default) the TC classifiers on every packet of tracked interfaces. Datadog's own engineering blog says `raw_syscalls` tracepoints hurt production "from slowing connection acceptance to consuming host resources" ([lessons blog](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)).
- **eBPF-less mode** for Fargate runs the workload under ptrace with a seccomp filter that traps only the monitored syscalls, and mirrors the fd table in userspace ([ptracer.go#L44-L505](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ptracer/ptracer.go#L44-L505), [Fargate docs](https://docs.datadoghq.com/security/workload_protection/setup/fargate/)).

#### Event inventory

From the SECL reference ([linux_expressions.md](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md), [rendered](https://docs.datadoghq.com/security/workload_protection/linux_expressions/)):

- Process: `exec` (file path/hashes/package, argv, envs with values only for an allow-list such as `LD_PRELOAD`, `PATH`, `SSH_CLIENT`, interpreter, tty, uid/euid/auid/caps, user session, mnt/net ns; no cwd field), `exit` (code, cause), `setuid`, `setgid`, `capset`, `signal`, `ptrace`, `prctl`, `setrlimit`, `capabilities` (experimental). Fork is an internal event that maintains the process cache.
- File: `open`, `chmod`, `chown`, `link` (hard links only), `rename`, `unlink`, `rmdir`, `mkdir`, `utimes`, `setxattr`, `removexattr`, `splice`, `chdir`, `mount`, each with path, inode, mount id, filesystem, overlay upper-layer flag, mode, owner, optional hashes and package; `fim.write.file.*` groups the write-like events.
- Kernel/admin: `bpf` (cmd, prog name/tag/type/helpers), `load_module`/`unload_module` (incl. `loaded_from_memory`), `mmap`, `mprotect`, `selinux`, `sysctl` (action, name, value, old value), `cgroup_write`, `unshare`.
- Network: `connect`, `accept`, `bind`, `socket`, `setsockopt` (including BPF filter hash), `dns` (question, response code, IPs, CNAMEs), `imds` (cloud metadata requests), `packet`, `network_flow_monitor` (per-flow packet and byte counts, opt-in).
- Identity and containers as fields: `process.auid`, `process.user_session.*` (SSH client, auth method, K8s user), `process.container.*`, `process.cgroup.*`.
- Custom `ondemand` hooks on arbitrary kernel functions or `syscall:<name>`, compiled from the rule and rate limited; not in the public docs ([ruleset.go#L169-L240](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/secl/rules/ruleset.go#L169-L240)).
- Sensor: `ruleset_loaded`, `heartbeat`, `self_test`, `abnormal_path`, `broken_process_lineage`, ... ([custom.go#L24-L84](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/events/custom.go#L24-L84)).

#### Enrichment

- **Events carry kernel keys, not strings.** The header has `bpf_ktime_get_ns`; the process context is pid, tid, netns, mntns, ppid, sid, exe inode and user session id; the cgroup is a (inode, mount id) key; files are `{ino, mount_id, path_id}` plus inode metadata ([events_context.h#L7-L73](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/structs/events_context.h#L7-L73), [filesystem.h#L95-L167](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/filesystem.h#L95-L167)). Paths are resolved later by the dentry resolver.
- **Kernel process cache.** At exec the kernel stores `{cgroup, executable, exec timestamp, tty, comm}` under a random 64-bit cookie in LRU `proc_cache` and points `pid_cache[tgid]` (fork/exit timestamps, credentials, auid, caps) at it ([exec.h#L802-L929](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/exec.h#L802-L929)); argv/envp are streamed as separate `args_envs` events. The userspace resolver tries its cache, then the kernel maps, then a rate-limited `/proc` scan, and checks entries against the exe inode in every event ([resolver_ebpf.go#L1076-L1305](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/process/resolver_ebpf.go#L1076-L1305)). The startup `/proc` snapshot is written back into the kernel maps ([resolver_ebpf.go#L1879-L1934](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/process/resolver_ebpf.go#L1879-L1934)).
- **Containers and K8s**: container id, pod UID and ECS task id parsed from the resolved cgroup path ([cgroup/resolver.go#L188-L261](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/cgroup/resolver.go#L188-L261)); image and pod tags from the core agent's tagger ([tags/resolver.go#L87-L110](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/tags/resolver.go#L87-L110)).
- **Users and sessions**: names from the container's `/etc/passwd` via `/proc/<pid>/root`; SSH sessions by tailing `auth.log`/`secure` (journald-only hosts unsupported, [usersessions/resolver_linux.go#L496-L535](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/usersessions/resolver_linux.go#L496-L535)); `kubectl exec` identity injected by a Cluster Agent webhook and pushed into a kernel map so descendants inherit it ([blog](https://www.datadoghq.com/blog/workload-protection-kubernetes-remote-access/)).
- **Hashes**: computed lazily in userspace when a rule needs them, by reopening `/proc/<pid>/root/<path>`; sha1/sha256/ssdeep, max 5 MiB, 500 hashes/s ([hash/resolver_linux.go#L330-L550](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/hash/resolver_linux.go#L330-L550)). **Package ownership** from an in-agent dpkg/rpm/apk scanner, off by default ([sbom/resolver.go#L440](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/sbom/resolver.go#L440), [settings#L313-L317](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L313-L317)).

#### In-kernel filtering: approvers, discarders, samplers

The model, described in the SSTIC 2021 paper ([slides 13-17](https://www.sstic.org/media/SSTIC2021/SSTIC-actes/runtime_security_with_ebpf/SSTIC2021-Slides-runtime_security_with_ebpf-fournier_afchain_baubeau.pdf)) and the 2025 FIM blog ([post](https://www.datadoghq.com/blog/engineering/workload-protection-ebpf-fim/)): approvers are static allow-lists derived from the ruleset, discarders are deny-lists learned at runtime from userspace evaluation, and full SECL evaluation runs in userspace. Both are on by default ([config.go#L308-L318](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/config/config.go#L308-L318)).

- **Hook gating.** Only probes for event types referenced by loaded rules, dumps, profiles or samplers are attached; a kernel `enabled_events` bitmask lets always-attached hooks skip unwanted types ([probe_ebpf.go#L2679-L2721](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L2679-L2721), [maps.h#L20](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/maps.h#L20)).
- **Per-type policy.** `filter_policy[event_type]` is NoFilter, Accept or Deny; with kernel filters on, types default to Deny (approvers required) and fall back to Accept if any approver cannot be installed ([probe_ebpf.go#L2999-L3085](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L2999-L3085), [approvers.h#L844-L887](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L844-L887)).
- **Approvers.** A field becomes an approver for an event type only if every rule of that type constrains it ([secl/rules/approvers.go#L216-L239](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/secl/rules/approvers.go#L216-L239)). Basename approvers in a hash keyed by `{type, char[32]}`: exact leaf name, the first 3 bytes of a wildcard leaf, or the exact parent directory name, checked inside the dentry walk ([kfilters/approvers.go#L40-L120](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/kfilters/approvers.go#L40-L120), [approvers.h#L278-L317](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L278-L317)). Flag approvers are bitmasks for open flags, mmap/mprotect protections, bpf cmd, sysctl action, address family, prctl option, socket fields, unshare flags ([maps.h#L26-L42](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/maps.h#L26-L42)). AUID approvers and an overlay upper-layer approver (container-written files only) complete the chain ([approvers.h#L243-L327](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L243-L327)).
- **Discarders.** When an event matches no rule, userspace partially evaluates each rule with only one field known; if no rule can match that value, it becomes a discarder ([ruleset.go#L1040-L1266](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/secl/rules/ruleset.go#L1040-L1266)). Inode discarders live in an LRU of 4,096 keyed by `{ino, mount_id, is_leaf}`; userspace prefers discarding a parent directory up to 3 levels up ([discarders_linux.go#L39-L449](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/discarders_linux.go#L39-L449)). The kernel checks the leaf and up to 3 ancestors during the path walk and drops the syscall before any event is built ([dentry_resolver.h#L88-L99](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/dentry_resolver.h#L88-L99)).
- **Discarder invalidation without scans**: a global revision bumped on every ruleset reload; a per-mount revision array bumped on umount, directory rename and rmdir; and a 5-second retention on renamed or unlinked inodes so an in-flight discarder cannot resurrect a stale inode ([discarders.h#L54-L293](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/discarders.h#L54-L293)). PID discarders are deprecated ([erpc.go#L28-L30](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/erpc/erpc.go#L28-L30)).
- **First-seen samplers** (profiles v2, on by default): `open_samples` is an LRU of 20,000 keyed by (ppid, exe key, file key, comm); the first occurrence emits a full event with a random cookie, repeats emit nothing except an `EVENT_SAMPLE_REFRESH {cookie}` every 30 s. Same for bind and connect. With dynamic sampling (off by default), admission depends on `bpf_ringbuf_query` fill level ([approvers.h#L75-L123](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L75-L123), [#L497-L587](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L497-L587)).
- **Rate limiters**: fixed one-second windows, global and per pid, in the kernel ([rate_limiter.h#L8-L80](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/rate_limiter.h#L8-L80)); per-rule token buckets in userspace.
- **What a rejected open still costs.** `handle_open` always tail-calls the in-kernel dentry walk because the parent-basename approver and the inode discarders are evaluated inside it, and the walk writes every component into the `pathnames` LRU; the verdict is applied at syscall return ([open.h#L81-L129](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/open.h#L81-L129)). chmod/chown/utimes reject before the walk ([setattr.h#L63-L82](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/setattr.h#L63-L82)).

#### Dentry resolver and eRPC

- The kernel walk follows `d_parent` and writes `pathnames[{ino, mount_id, path_id}] = {parent, name[256]}` for every component, 40 components per program and up to 29 tail calls, into an LRU of at least 64,000 entries ("~27 MB") ([dentry_resolver.h#L42-L159](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/dentry_resolver.h#L42-L159), [all.go#L26-L27](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/all.go#L26-L27)). `path_id` generation counters per mount, bumped on unlink and rename, keep stale cached names from being reused ([filesystem.h#L14-L86](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/filesystem.h#L14-L86)).
- Userspace resolves a key through its own LRU (8,000), then eRPC, then direct map lookups ([dentry/resolver.go#L609-L631](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/dentry/resolver.go#L609-L631)). eRPC is an `ioctl(fd, 0xdeadc001, req)` caught by a kprobe on `security_file_ioctl`: for path resolution a tail-called program walks `pathnames` and copies the whole path into an mmapable array map, one syscall instead of N lookups ([erpc.h#L61-L146](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/erpc.h#L61-L146), [dentry_resolver.h#L232-L388](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/dentry_resolver.h#L232-L388)). eRPC also inserts discarders and bumps revisions. The cost side: a kprobe on `security_file_ioctl` runs for every ioctl on the host.

#### Transport

- One `events` map: a shared BPF ringbuf (≥ 5.8, default) of 8 MiB on ≤ 16 CPUs and 16 MiB above, or a 1 MiB per-CPU perf buffer ([all.go#L44-L91](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/all.go#L44-L91), [probe_ebpf.go#L249-L262](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L249-L262)). Events are built in per-CPU scratch and copied with `bpf_ringbuf_output(..., 0)`, i.e. default wakeups ([perf_ring.h#L34-L67](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/perf_ring.h#L34-L67)).
- Loss: per-CPU `events_stats[event_type] = {bytes, count, lost}` updated at every output ([perf_ring.h#L52-L63](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/perf_ring.h#L52-L63)), exported per event type ([metrics.go#L138-L178](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/metrics/metrics.go#L138-L178)). Stats maps are double-buffered per CPU and swapped by a selector so userspace reads a quiescent copy ([buffer_selector.h](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/buffer_selector.h)).
- Userspace: in perf mode a min-heap reorderer by timestamp ([reorderer.go#L162-L234](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/eventstream/reorderer/reorderer.go#L162-L234)); in ringbuf mode one goroutine decodes, resolves and evaluates rules synchronously ([probe_ebpf.go#L1246-L1265](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/probe/probe_ebpf.go#L1246-L1265)). The lessons blog: "only a single CPU core can read from them in user space. Under high system load, this can lead to dropped or out-of-order events" ([post](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)).

#### Published overhead

All vendor statements without hardware or kernel methodology; no independent measurement found.

- FIM blog, 2025-11-18 ([post](https://www.datadoghq.com/blog/engineering/workload-protection-ebpf-fim/)): more than 10 billion file events per minute across Datadog's fleet; approvers and discarders "pre-filter up to 94% of events directly in the kernel"; a figure shows ~5,000 kernel events/s → ~300/s reaching the agent → < 1/s sent to the backend on one workload.
- Lessons blog, 2026-01-07 ([post](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)): the default ruleset drops "up to 95% of captured events before they reach user space".
- eBPF-less mode: "around 3% for PostgreSQL workloads and negligible impacts for Redis" ([docs](https://docs.datadoghq.com/security/cloud_security_management/guide/ebpf-free-agent/)).

#### Documented blind spots

- **kretprobe `maxactive` and missed probes**: events are sent from the return hook; under pressure kretprobe instances run out and probes interrupted by hardware IRQs are missed ([LPC 2023 slides p.11](https://lpc.events/event/17/contributions/1582/attachments/1328/2673/Troubles%20and%20Tidbits%20from%20Datadog%E2%80%99s%20eBPF%20Journey%20v2.pdf)). Default `kretprobe_max_active` is 512.
- **Module hooks** (NAT) are lost on module reload (LPC p.12).
- **TOCTOU** on syscall arguments (LPC p.13); paths come from kernel dentries, but `*.syscall.path` fields are user-pointer reads and hashes are computed later from `/proc/<pid>/root`.
- **Lost and reordered events** under load from the single reader ([lessons blog](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)).
- **io_uring**: a subset of operations is hooked (open, truncate, xattr, bind, connect, socket, splice, and link/unlink/mkdir/rename/rmdir through shared functions), with the issuing pid recovered from the request ([open.h#L213-L234](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/open.h#L213-L234)).
- **CNI conflicts**: if a CNI uses TC priority 1, network detections inside containers do not work ([troubleshooting](https://docs.datadoghq.com/security/workload_protection/troubleshooting/threats/)).
- **Kill is after the fact**: no LSM deny; the signal is sent from userspace and at the next hooked syscall entry via `bpf_send_signal` ([process.h#L11-L22](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/process.h#L11-L22)).
- **No events** for symlink creation, `setns`, kexec, clock changes, keyring, `userfaultfd`, `perf_event_open`, `process_vm_writev` except through `ondemand` hooks; `AF_UNIX` connects record only the family ([connect.h#L124-L135](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/connect.h#L124-L135)).

#### Relevance to panopticon

Datadog has gone furthest of the open-source agents in deciding in the kernel, and its approver/discarder split is the main prior art for principle 4. Directly reusable ideas: discarder invalidation by revision counters (global, per mount) and short retention windows instead of map scans; first-seen samplers that emit one full record per (process, file) tuple and then only a cookie heartbeat, which is close to panopticon's coalescing map; per-type `{bytes, count, lost}` counters at the output site; double-buffered per-CPU stats. Where it differs: records are not self-contained (paths, processes and containers are resolved later from kernel LRUs, userspace caches and `/proc`), it mirrors the dentry tree into a ~27 MB kernel LRU, it still pays kprobe+kretprobe pairs on hot file syscalls and a full path walk on rejected opens, and a single goroutine resolves and evaluates everything.

### KubeArmor

Surveyed: [v1.7.6](https://github.com/kubearmor/KubeArmor/releases) (2026-10-23); source at main [`3b5c8f7`](https://github.com/kubearmor/KubeArmor/tree/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72) (v1.7.7-rc1). Apache-2.0 Go (cilium/ebpf), BPF C dual BSD/GPL; CNCF Sandbox. DaemonSet or systemd service. An init container compiles the system monitor on the node with clang; the BPF-LSM enforcer is a prebuilt CO-RE object ([Dockerfile.init#L1-L15](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/Dockerfile.init#L1-L15), [bpflsm/enforcer.go#L207-L283](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/enforcer/bpflsm/enforcer.go#L207-L283)). KubeArmor is primarily an enforcement engine (KubeArmorPolicy, HostPolicy, ClusterPolicy, NetworkPolicy CRDs) with a syscall-level visibility stream alongside; the enforcer backend is chosen per node in the order `bpf,apparmor,selinux` ([config.go#L190](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/config/config.go#L190)).

**Mechanism.**

- **System monitor (telemetry):** kprobe + kretprobe on 18 syscall entry functions (`open`, `openat`, `execve`, `execveat`, `socket`, `connect`, `bind`, `listen`, `unlink`, `unlinkat`, `rmdir`, `ptrace`, `chown`, `setuid`, `setgid`, `fchownat`, `mount`, `umount`); tracepoints `sys_exit_openat`, `sys_enter_setns`, `sys_exit_setns`, `sched_process_fork`; kprobes on `security_bprm_check`, `security_file_open`, `security_path_*` and `do_exit`; network kprobes `tcp_connect`, kretprobe `inet_csk_accept`, kprobe `udp_send_skb` (DNS queries on port 53) ([systemMonitor.go#L599-L614](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L599-L614)). Kernel ≥ 4.14.
- **BPF-LSM enforcer:** `lsm/bprm_check_security`, `file_open`, `file_permission` (write mask), `socket_create/connect/accept/sendmsg`, `capable`, and `path_*` hooks when `CONFIG_SECURITY_PATH=y` ([enforcer.bpf.c#L718-L760](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L718-L760), [enforcer_path.bpf.c#L8-L73](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer_path.bpf.c#L8-L73)). Presets on LSM hooks detect fileless exec (`memfd:`, `/dev/shm`), anonymous executable mappings, and `/proc/<pid>` or `environ` access ([filelessexec.bpf.c#L42-L123](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/filelessexec.bpf.c#L42-L123), [anonmapexec.bpf.c#L92-L191](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/anonmapexec.bpf.c#L92-L191)). Network policy is enforced with nftables, not BPF ([networkPolicyEnforcer.go#L23-L39](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/networkPolicyEnforcer/networkPolicyEnforcer.go#L23-L39)).
- **Who pays.** No global syscall hook, but every listed syscall on the host pays a kprobe and a kretprobe. The entry probe copies arguments into `args_map` for every task; per-container visibility is checked only in the return probe ([system_monitor.c#L409-L431](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L409-L431), [#L1624-L1731](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1624-L1731)). `openat` entry additionally reads 256 bytes of the path to drop `/proc/` and `/sys/` ([system_monitor.c#L1823-L1846](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1823-L1846)). Attaching `syscalls:*` tracepoints sets `SYSCALL_WORK_SYSCALL_TRACEPOINT` on every task, so every syscall on the node takes the tracepoint path and a bitmap test ([tracepoint.c#L800-L814](https://github.com/torvalds/linux/blob/v6.12/kernel/tracepoint.c#L800-L814), [trace_syscalls.c#L575-L591](https://github.com/torvalds/linux/blob/v6.12/kernel/trace/trace_syscalls.c#L575-L591)).

**Events.** A `Log`/`Alert` protobuf with container, pod, labels, pids, process and parent names, cwd, tty, operation, resource, result, optional hashes ([kubearmor.proto#L41-L96](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/protobuf/kubearmor.proto#L41-L96)). Operations: `Process` (execve with ≤ 20 argv), `File` (open with flags, unlink, rmdir, chown), `Network` (socket, connect, accept, bind, listen with sockaddr including `sun_path`; `tcp_connect`/`tcp_accept` tuples; DNS query name and type), `Syscall` (mount, umount, setuid, setgid), `Capabilities` (BPF-LSM alerts only), `AlertThreshold` ([logUpdate.go#L145-L561](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L145-L561)). No exit or fork records.

**Enrichment.** Kernel: timestamps, host and namespace pids, pid/mnt namespace inodes, uid, comm, tty, an 80-byte cwd ([system_monitor.c#L1087-L1161](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1087-L1161)). The container key in the kernel is the (pidns, mntns) inode pair. `kubectl exec` sessions are tagged in the kernel: `sys_exit_setns` stores an exec id when a task enters a known container's namespaces and `sched_process_fork` copies it to children ([system_monitor.c#L1177-L1265](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1177-L1265)). Userspace subscribes to containerd/CRI-O/Docker/NRI events and reads `/proc/<pid>/ns/*` to map namespaces to containers; process paths come from a userspace pid map with `/proc/<pid>/exe` fallback ([processTree.go#L166-L302](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/processTree.go#L166-L302)). Optional IMA executable hash from sleepable `lsm.s/bprm_check_security`; hashing on `file_open` is commented out as "a high latency operation" ([ima_hash.bpf.c#L14-L57](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/ima_hash.bpf.c#L14-L57)).

**In-kernel filtering.** Per-container visibility in a hash-of-maps keyed by (pidns, mntns) with per-class switches; successful events of invisible classes are dropped, failed ones always emitted ([visibility.h#L10-L75](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/visibility.h#L10-L75)). BPF-LSM policy lives in per-container inner hashes keyed by (path, source) with bitmask values; non-container tasks exit after one outer-map miss ([shared.h#L210-L260](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/shared.h#L210-L260)). Per-container alert throttling in the kernel: 10 alerts/s by default, then one threshold record and silence for 30 s while enforcement continues ([shared.h#L602-L672](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/shared.h#L602-L672)). No dedup of repeated events.

**Transport.** Monitor: per-CPU perf buffer, 4 MiB per CPU, default wakeups; lost samples are only logged at debug level ([systemMonitor.go#L665](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L665), [#L792-L795](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L792-L795)). Enforcer: a shared 16 MiB ringbuf; on reserve failure the decision is still enforced and the alert is lost without a counter ([enforcer.bpf.c#L444-L463](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L444-L463)). Output over gRPC to a cluster relay; full client queues drop logs ([feeder.go#L905-L940](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/feeder/feeder.go#L905-L940)).

**Published overhead.** Vendor ([benchmark wiki](https://github.com/kubearmor/KubeArmor/wiki/KubeArmor-Performance-Benchmarking-Data), method in the [guide](https://github.com/kubearmor/KubeArmor/wiki/Kubearmor-Performance-Benchmarking-Guide)): GKE, 2-vCPU nodes, microservices-demo under Locust at 2,000 users, metric front-end throughput. BPF-LSM throughput drop 1.3% with no policy up to 4.4% with process+network+file policies; visibility modes cost 2.7% (process), 7.9% (process+network), 11.6% (process+file), 18% (process+network+file); agent 44-69 mCPU, ~240 MB. The wiki states file visibility is off by default because of "huge overhead". Independent ([Her et al., IEEE Access 2025](https://cclab.info/papers/2025_her_access.pdf)): +18.29% on an exec loop without policy, +87.74% on a 100,000-packet UDP send loop (highest of four tools), highest log loss, fastest policy apply (map writes).

**Blind spots.** Syscall arguments read at entry (TOCTOU), relative paths joined with an 80-byte cwd in userspace ([logUpdate.go#L574-L580](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L574-L580)); a fixed list of 18 syscalls, so `openat2`, `renameat*`, `linkat`, `setresuid`, `capset`, `unshare` and io_uring have no monitor events; `/proc` and `/sys` opens unreported; syscall policies are audit-only ([security_policy_specification.md#L323](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/getting-started/security_policy_specification.md#L323)); DNS queries only, IPv4 only; `kube-system` and `kubearmor` namespaces untracked by default ([config.go#L188](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/config/config.go#L188)); AppArmor-backend limitations in the [feature parity](https://github.com/kubearmor/KubeArmor/wiki/Enforcer-Feature-Parity) page.

**Relevance.** Two ideas carry over: enforcement that never depends on telemetry delivery (decide, then try to report), and per-container policy as inner maps keyed by a kernel identity so unrelated tasks exit after one lookup. The monitor itself is a counter-example: entry/return kprobe pairs that copy arguments before checking visibility.

### Inspektor Gadget

Surveyed: [v0.57.0](https://github.com/inspektor-gadget/inspektor-gadget/releases) (2026-10-05); source at main [`df1a627`](https://github.com/inspektor-gadget/inspektor-gadget/tree/df1a6277355119a17201a9aea0f531d9553a62ec). Apache-2.0 Go, GPL-2.0 BPF. A framework for running eBPF "gadgets" packaged as OCI images, as a DaemonSet driven by `kubectl gadget` or as the `ig` binary ([architecture.md#L19-L33](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/reference/architecture.md#L19-L33)). Built-in gadgets were replaced by image-based ones in 2025 ([year in review](https://inspektor-gadget.io/blog/2025/12/2025-year-in-review/)). Nothing is traced unless a gadget instance runs; there are no detection rules. Kubescape node-agent embeds it as a library ([go.mod](https://raw.githubusercontent.com/kubescape/node-agent/main/go.mod)); adopters include Microsoft Defender for Containers ([ADOPTERS.md#L11-L19](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/ADOPTERS.md#L11-L19)). Kernel 5.10+ with BTF, or BTFHub-derived BTF shipped in the image ([requirements.md#L13-L15](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/reference/requirements.md#L13-L15)).

**Mechanism, per gadget.** `trace_exec`: `syscalls/sys_enter_execve*`, `sys_exit_execve*`, `sched_process_exec`, kprobe `security_bprm_check` ([trace_exec/program.bpf.c#L195-L451](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L195-L451)). `trace_open`: `sys_enter/exit_open(at)` tracepoints. `trace_tcp`: kprobes on `tcp_v4/v6_connect`, `tcp_set_state`, `tcp_close`, `inet_csk_accept`. `trace_bind`: `inet_bind`, `inet6_bind`. `trace_capabilities`: `cap_capable` plus raw `sys_enter`/`sys_exit` on every syscall. `trace_mount`, `trace_signal`, `trace_init_module`: syscall tracepoints. `trace_link`, `trace_rename`: `security_path_*` kprobes. `trace_lsm`: 147 `lsm/<hook>` programs that report only the hook id. `trace_sni`, `trace_dns`: socket filters on an `AF_PACKET` socket opened in each selected container's netns ([networktracer/tracer.go#L121-L126](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/networktracer/tracer.go#L121-L126)). `trace_ssl`: uprobes on OpenSSL/GnuTLS/NSS. `snapshot_*`: BPF iterators. `top_file`, `top_tcp`: kprobes on `vfs_read/write`, `tcp_sendmsg`, `tcp_cleanup_rbuf` with in-kernel aggregation. Container discovery puts fanotify `FAN_OPEN_EXEC_PERM` marks on runtime binaries, so the kernel blocks runc until the agent has read the container's `config.json` ([container-hook/tracer.go#L15-L31](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/container-hook/tracer.go#L15-L31)), plus syscall tracepoints to read runc's argv.

**Who pays.** Depends on running gadgets. Syscall-tracepoint gadgets and the default container hook set `SYSCALL_WORK_SYSCALL_TRACEPOINT` host-wide (same kernel mechanism as above); `trace_capabilities`, `traceloop` and `advise_seccomp` run BPF on every syscall; packet gadgets run a filter on every packet of each attached netns.

**Events.** Every event embeds `gadget_process` (comm, pid, tid, mntns, uid, gid, parent) filled in the kernel ([common.h#L13-L36](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/include/gadget/common.h#L13-L36)). `exec` adds loginuid, sessionid, args (≤ 20 × 256 B), tty, cwd, exe path, parent exe path, dev/inode/ctime and an overlayfs upper-layer flag ([trace_exec/program.bpf.c#L36-L70](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L36-L70)). Others: `open`, `rename`, `link`, `tcp`, `bind`, `dns` (queries and responses, rcode, latency, parsed by a WASM module), `sni`, `ssl`, `capabilities` (cap, verdict, syscall, stacks), `mount`, `init_module`, `signal`, `oomkill`, `lsm`, `selinux`, `seccomp`, `bpfstats`.

**Enrichment.** Kernel: the socket enricher keeps a socket→process map keyed by `{netns, family, proto, port}` filled at bind/connect/sendmsg and removed at release, so packet programs get process identity without userspace fd tables ([socket-enricher.bpf.c#L250-L304](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/socketenricher/bpf/socket-enricher.bpf.c#L250-L304)). Userspace: mntns/netns → node, namespace, pod, container, labels, owner, image name and digest ([kubemanager.md#L17-L33](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/spec/operators/kubemanager.md#L17-L33)); uid/gid names from host files. No hashes, no lineage beyond the parent.

**In-kernel filtering.** A mount-namespace hash (1,024 entries) gated by a load-time constant ([mntns_filter.h#L12-L28](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/include/gadget/mntns_filter.h#L12-L28)); pid/uid/comm filters as `const volatile` rodata that the verifier can prune when unused ([filter.h#L21-L125](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/include/gadget/filter.h#L21-L125)); first-seen dedup of (cap, mntns) in `trace_capabilities` ([program.bpf.c#L120-L213](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_capabilities/program.bpf.c#L120-L213)); `top_*` aggregate in hash maps read by iteration.

**Transport.** Each gadget declares a 256 KiB shared ringbuf with a per-CPU lost counter next to it, or falls back to perf buffers; default wakeups ([buffer.h#L14-L100](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/include/gadget/buffer.h#L14-L100)). Userspace sums the lost counter every second ([ebpf/tracer.go#L136-L216](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/operators/ebpf/tracer.go#L136-L216)). Before v0.50.1 that count was hard-coded to zero and a container could flood the ring to hide events ([GHSA-wv52-frfv-mfh4 / CVE-2026-31890](https://github.com/inspektor-gadget/inspektor-gadget/security/advisories/GHSA-wv52-frfv-mfh4)).

**Published overhead.** Vendor ([PR #4730](https://github.com/inspektor-gadget/inspektor-gadget/pull/4730), [report](https://github.com/user-attachments/files/22010557/benchmarks_analysis.pdf)), Azure D8as_v5 (8 vCPU EPYC 7763), kernel 6.11, one gadget at a time, 5 × 20 s: host CPU 53.96% → 72.36% for `trace_exec` at 8,192 execs/s; 59.07% → 89.93% for `trace_open` at 524,288 opens/s; `trace_dns` loses 400 events/s at 1,024 queries/s and 7,362/s at 16,384. The PR warns that an event-generation issue may have skewed earlier results. No independent measurement found.

**Blind spots.** No coverage unless a gadget runs; each gadget loads its own programs, ring and enrichment. io_uring is documented as unobservable ([gadget_limitations.mdx#L15-L20](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/gadgets/gadget_limitations.mdx#L15-L20)); `trace_open` reads the filename pointer at syscall exit and misses `openat2` ([trace_open/program.bpf.c#L135](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_open/program.bpf.c#L135)); DNS over TCP is best effort; the fanotify hook needs `CAP_SYS_ADMIN` and does not cover rootless or kata containers ([requirements.md#L27-L60](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/reference/requirements.md#L27-L60)).

**Relevance.** Several techniques match panopticon's direction: argv read once from the new mm at `sched_process_exec` ([trace_exec/program.bpf.c#L251-L276](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L251-L276)); drift detection by checking whether the exe lives on an overlayfs upper layer ([#L229-L249](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L229-L249)); a kernel socket→process table instead of userspace fd tables; fanotify permission events to register containers before they start; BPF iterators instead of `/proc`; load-time constants for filters. The CVE is a reminder that loss counters must be real.

### Elastic open source: elastic/ebpf, quark, Auditbeat

One matrix column for three components that differ a lot. Surveyed: elastic/ebpf main [`51b6ec7`](https://github.com/elastic/ebpf/tree/51b6ec73e00b9bb0d8612ae237576b9af410dac6) (last tagged release 2022, main active in 2026 with Linux 7.0 renames; [File/Probe.bpf.c#L57-L69](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L57-L69)); quark v0.10 (2026-10-06), source at [`c1042f7`](https://github.com/elastic/quark/tree/c1042f70797e1b72b584a8c4ea69408d8ce91acc); Auditbeat 9.5.5 (beats [`6966d44`](https://github.com/elastic/beats/tree/6966d4422ef249fb3d48bbe27f32994bb5537dd3)). elastic/ebpf BPF code is GPL-2.0/BSD-2 and its userspace library Elastic License 2.0; it is the event source of the closed Elastic Defend ([README#L5-L22](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/README.md#L5-L22)). quark is an Apache-2.0 C library with no threads, driven by `quark_queue_get_event` ([quark.7#L381-L383](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.7#L381-L383)). Auditbeat's `system` module is under the Elastic License; `auditd` and `file_integrity` are Apache-2.0 ([beats LICENSE.txt](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/LICENSE.txt#L1-L8)).

**elastic/ebpf mechanism.** Every function hook exists as an fentry/fexit and a kprobe twin; the loader uses fentry when a test trampoline attaches ([EbpfEvents.c#L313-L551](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/non-GPL/Events/Lib/EbpfEvents.c#L313-L551)). Process: `tp_btf/sched_process_fork`, `tp_btf/sched_process_exec`, exit at `disassociate_ctty` (because `sched_process_exit` runs before `exit_files()`), `commit_creds`, `ptrace_attach`, `tty_write`, `tp_btf/module_load`, and per-syscall tracepoints for `setsid`, `shmget`, `memfd_create` ([Process/Probe.bpf.c#L73-L712](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L73-L712)). File: `vfs_unlink`, `do_filp_open` exit (create when `FMODE_CREATED`, memfd, `/dev/shm`), `vfs_rename`, `chmod_common`, `chown_common`, `do_truncate`, `vfs_write`/`vfs_writev` exit ([File/Probe.bpf.c#L45-L872](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L45-L872)). Network: `inet_csk_accept`, `tcp_v4/v6_connect`, `tcp_close` ([Network/Probe.bpf.c#L58-L199](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Probe.bpf.c#L58-L199)). No raw syscall hook, but every program is attached regardless of what the consumer subscribed to, and the event mask is applied in userspace ([EbpfEvents.c#L45-L62](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/non-GPL/Events/Lib/EbpfEvents.c#L45-L62)). Every successful regular-file `vfs_write` emits a full `FILE_MODIFY` event with a resolved path; there is no dedup ([File/Probe.bpf.c#L594-L648](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L594-L648)). Kernel ≥ 5.10.16 with BTF.

**Records.** Self-contained: pid/tgid/ppid/pgid/sid with start time, creds, controlling tty, comm, all namespace inode numbers and the resolved cgroup path are written per event; paths are resolved to strings in BPF ([Process/Probe.bpf.c#L139-L206](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L139-L206)). Exec carries argv (≤ 20 KiB), env (≤ 40 KiB), cwd, filename, setuid/setgid/memfd flags and `inode_nlink` (0 for deleted executables). Exit carries only the status byte; the terminating signal is dropped ([#L258-L260](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L258-L260)). `NETWORK_CONNECTION_CLOSED` carries bytes sent and received from `tcp_sock` ([Network/Probe.bpf.c#L156-L187](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Probe.bpf.c#L156-L187)). Event list: [EbpfEventProto.h#L22-L42](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/EbpfEventProto.h#L22-L42).

**quark.** Three exclusive backends: a vendored, extended copy of the elastic/ebpf probes that autoloads only the programs for the requested features ([bpf_queue.c#L1284-L1515](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/bpf_queue.c#L1284-L1515)) and adds DNS via `cgroup_skb` and an mprotect hook; a tracefs kprobe backend with BTFHub offsets for kernels without BTF ([kprobe_defs.h#L109-L131](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/kprobe_defs.h#L109-L131)); and an experimental "nova" backend that evaluates the rule set in BPF at `lsm/bprm_check_security` using an LPM trie for path prefixes and suffixes, though its LSM programs always pass ([nova.bpf.c#L202-L320](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/nova.bpf.c#L202-L320), [#L516-L518](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/nova.bpf.c#L516-L518)). quark reads `/proc` once at startup after opening the rings and then lives on kernel records ([quark.c#L4796-L4805](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.c#L4796-L4805)). It merges fork+exec+exit of a process into one event in userspace, holding raw events up to 1 s, less as the queue fills ([quark.7#L52-L105](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.7#L52-L105)). Its mprotect dedup is an LRU keyed by (tgid, dev, inode) holding {start time, `self_exec_id`, bitmap of reported transitions}, and the bit is set only after the ring write succeeded, so a dropped event is retried ([Process/Probe.bpf.c#L102-L155](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/elastic-ebpf/GPL/Events/Process/Probe.bpf.c#L102-L155)). Pod and image metadata come from a separate Go `quark-kube-talker` running pod informers ([quark-kube-talker.go#L160-L195](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/go/quark-kube-talker/quark-kube-talker.go#L160-L195)). Trusted-pid and config maps are frozen or `BPF_F_RDONLY_PROG` after load ([CHANGES#L204-L209](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L204-L209)).

**Auditbeat.** `auditd` module over audit netlink, defaulting to kernel `backlog_wait_time` 0 so the kernel drops instead of blocking tasks ([auditd docs#L120-L186](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/auditd/_meta/docs.md#L120-L186)); `file_integrity` with fsnotify (default), tracefs-kprobe or eBPF backends. The kprobe backend has to add an inotify watch on each monitored mountpoint because kernels 5.15+ skip `fsnotify()` entirely when a superblock has no marks ([path_inotify.go#L55-L62](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/kprobes/path_inotify.go#L55-L62)); the eBPF backend subscribes to all file events host-wide and filters paths in Go ([eventreader_ebpf.go#L128-L152](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/eventreader_ebpf.go#L128-L152)). `system/socket` puts tracefs kprobes on per-packet functions (`tcp_sendmsg`, `udp_sendmsg`, `udp_queue_rcv_skb`, ...) to build flows with byte counts ([kprobes.go#L144-L506](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/socket/kprobes.go#L144-L506)); `system/login`, `user`, `package` poll files.

**Transport.** elastic/ebpf: one shared 4 MiB ringbuf, variable-length events built in a scratch array and copied, default wakeups; per-CPU `{sent, lost}` counters, not per class ([EventProbe.bpf.c#L16-L19](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/EventProbe.bpf.c#L16-L19), [Helpers.h#L330-L349](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Helpers.h#L330-L349)). quark sizes the ring at 512 KiB per CPU (4-64 MiB) because 4 MiB on 8 CPUs was "the point at which bursty large execs did not drop" ([bpf_queue.c#L36-L79](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/bpf_queue.c#L36-L79)).

**Overhead.** None published with a methodology for any of the three (docs, man pages, CHANGES, Auditbeat docs checked). Third-party exec-loop tables that include Auditbeat 7.x are in the [auditd section](#auditd-with-laurel-or-go-audit).

**Blind spots.** quark may present a process as one aggregated or several events depending on load ([quark.7#L127-L138](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.7#L127-L138)); its container detection recognizes only the systemd cgroup driver ([CHANGES#L241-L250](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L241-L250)); Auditbeat `system/socket` sees no raw sockets and is x86-only ([socket docs#L15](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/socket/_meta/docs.md#L15)); process exe hashes are skipped for other mount namespaces ([quark_provider_linux.go#L256-L273](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/process/quark_provider_linux.go#L256-L273)). [INFERENCE] Connect tuples are pre-NAT; no io_uring hooks, though the VFS file hooks see io_uring-issued opens and writes.

**Relevance.** quark is the closest open-source relative of panopticon's record model: self-contained records, `/proc` only at startup, and a process view that collapses fork, exec and exit. The difference is where the merge happens (userspace, with a hold time, versus panopticon's exec record that already carries spawner and previous image). Its "set the dedup bit only after a successful write" rule and the `self_exec_id` in the dedup key are directly reusable; panopticon already uses `self_exec_id` in its file coalescing key ([design.md](../design.md#credentials-persistence-and-integrity)).

### Kunai

Surveyed: v0.6.2 (2025-11-12) and v0.7.0-rc.1 (2026-03-11); source at [`9358284`](https://github.com/kunai-project/kunai/tree/93582844db929860138a87d69f48a2af11eae43a). GPL-3.0, Rust with Aya for both BPF and userspace, one static binary; developed at CIRCL as "the Linux counterpart to Sysmon" ([README#L16-L30](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/README.md#L16-L30), [PTS 2024 slides](https://archives.pass-the-salt.org/Pass%20the%20SALT/2024/slides/PTS2024-TALK-08-Kunai.pdf)).

**Mechanism.** kprobes, kretprobes and raw tracepoints, CO-RE: `security_bprm_check` + `bprm_execve` return for exec, `security_task_alloc` + `wake_up_new_task` for clone, `commit_creds`, `security_task_kill`, `security_ptrace_access_check`, `mod_sysfs_setup`, `security_bpf_prog` + `bpf_prog_load`, `__sk_attach_prog` (socket filters), `io_issue_sqe`, `vfs_read/write(v)`, `security_path_rename/unlink`, `fput`, `security_file_open`, `__sys_connect`, `security_socket_sendmsg` ([execve.rs](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/execve.rs#L32), [fs.rs#L181-L681](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L181-L681), [io_uring.rs#L17-L72](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/io_uring.rs#L17-L72)). Six programs sit on raw `sys_enter` (exit, init_module, finit_module, mmap, mprotect, prctl) and two on raw `sys_exit` (init_module, prctl; plus execve below 5.9), so every syscall runs eight programs that compare the syscall number and return ([exit.rs#L17-L29](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/exit.rs#L17-L29), [mmap.rs#L10-L19](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/mmap.rs#L10-L19), [prctl.rs#L14-L57](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/prctl.rs#L14-L57)). All probes load regardless of which events are enabled; enablement is a per-event bool in a config map ([lib.rs#L187-L228](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/lib.rs#L187-L228)). With `harden: true`, `lsm/task_kill` and `lsm/ptrace_access_check` protect the agent ([lsm.rs#L22-L89](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/lsm.rs#L22-L89)).

**Events** (fixed numeric ids, [bpf_events.rs#L60-L179](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events.rs#L60-L179)): execve and execve_script (exe with md5/sha1/sha256/sha512, 512-byte command line, ancestors, interpreter), clone, exit/exit_group, prctl, kill, ptrace, commit_creds (old/new creds with caps), creds_tampered (userspace comparison against the last commit_creds), init_module, bpf_prog_load (with instruction hashes), bpf_socket_filter, mprotect_exec, mmap_exec, connect, dns_query, send_data (size and byte-entropy histogram), read/read_config, write/write_config, write_close, file_create, file_rename, file_unlink, io_uring_sqe (opcode), plus `error` and `event_loss` sensor events ([events docs](https://why.kunai.rocks/docs/events/)).

**Enrichment.** A userspace process table keyed by (tgid, leader start time), seeded once from `/proc` ([main.rs#L1521-L1626](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/bin/main.rs#L1521-L1626)); hashes computed in userspace by entering the event's mount namespace and re-opening the path ([cache.rs#L153-L213](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/cache.rs#L153-L213)); container type (docker, lxc, podman, firejail) by string matching on cgroup names and ancestor executables, no image or pod ([containers.rs#L68-L114](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/containers.rs#L68-L114)); IoC set lookups and gene-rs rules in userspace.

**In-kernel filtering.** First-touch dedup: an LRU keyed by (pid_tgid, inode number) with read/write/close-after-write flags, so only the first read and first write per thread and file reach the ring ([fs.rs#L13-L90](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L13-L90)). A per-CPU LRU keyed by (task, second) counts file events; above a per-task and a global limit it emits one `error` event and drops file events for the rest of the second ([fs.rs#L92-L177](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L92-L177)).

**Transport.** Per-CPU perf buffers; one task per CPU polls every 10 ms without wakeups, and all CPU tasks meet at a barrier each round to release events in timestamp order ([main.rs#L2755-L2931](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/bin/main.rs#L2755-L2931)). Lost records become an `event_loss` event with read, lost and events-per-second counts ([main.rs#L2781-L2857](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/bin/main.rs#L2781-L2857)).

**Overhead.** None published by the project. One independent blog test (Debian 12, kernel 6.1, VM, six scenarios, method details not given) reports Kunai with adapted rules at ~31% CPU and 395 MB RSS, Falco ~32% and 180 MB, auditd 7% average ([scrpt.ru](https://scrpt.ru/blog/auditd-vs-ebpf-linux-audit/)).

**Blind spots.** Losses under frequent file events are documented as "inevitable" ([events docs](https://why.kunai.rocks/docs/events/)); container identification is string matching ([generalities](https://kunai.rocks/docs/events/generalities)); `write_close` from async `fput` can arrive after the task ended ([fs.rs#L520-L527](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L520-L527)). [INFERENCE] Exit is taken at the `exit`/`exit_group` syscall, so signal deaths produce no exit event; the dedup key lacks the device and the exec generation.

### Exein Pulsar

Surveyed: v0.10.1 (2026-09-30) after a gap since v0.9.0 (2024-11-15); source at [`f6d27fa`](https://github.com/exein-io/pulsar/tree/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1); maintained (79 commits by 6 authors in 2026 per the GitHub API). Apache-2.0 userspace, GPL-2.0 BPF in C loaded by Rust/Aya; host agent aimed at IoT/edge ([pulsar.sh](https://pulsar.sh/)). The syscall-monitor module existed only in v0.2.0-v0.4.0 and its last event type was removed in 0.10.0 ([CHANGELOG#L119-L125](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/CHANGELOG.md#L119-L125)).

**Mechanism.** `PULSAR_LSM_HOOK(hook)` compiles to `lsm/<hook>` when BPF LSM is available and to `kprobe/security_<hook>` otherwise; the LSM programs return the previous verdict unchanged ([common.bpf.h#L33-L90](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/common.bpf.h#L33-L90)). process-monitor: raw tracepoints `sched_process_fork/exec/exit`, `sched_switch` (to emit re-parenting events), LSM `task_fix_setuid/setgid`, kprobe `commit_creds` ([probes.bpf.c#L279-L630](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L279-L630)). file-system-monitor: LSM `path_mknod`, `path_unlink`, `file_open`, `path_link`, `path_symlink`, `path_mkdir`, `path_rmdir`, `path_rename`. network-monitor: LSM `socket_bind/listen/connect/accept`, kprobe `tcp_set_state`, `sys_exit_accept*` tracepoints, and `cgroup_skb` on the root cgroup ([network-monitor lib.rs#L49-L80](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/src/lib.rs#L49-L80)). Kernel 5.5+ with BTF.

**Events and enrichment.** Fork, Exec (argv from the new mm), Exit, ChangeParent, CredentialsChange, FileCreated/Deleted/Opened/Link/Rename, DirCreated/Deleted, ElfOpened, Bind, Listen, Connect, Accept, Close, Send/Receive per packet with payload, DnsQuery/DnsResponse parsed in userspace ([event.rs#L181](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/pulsar-core/src/event.rs#L181)). Container engine and id are parsed in BPF from the memory-cgroup name for Docker and Podman only ([probes.bpf.c#L160-L275](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L160-L275)). A userspace PID-keyed process tracker supplies image and parent for every event and waits up to 100 ms for a missing fork ([process_tracker.rs#L139-L244](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/pulsar-core/src/pdk/process_tracker.rs#L139-L244)).

**In-kernel filtering.** An interest map of 16,384 tgids with track-self and track-children bits, inherited at fork and recomputed at exec from the image path, gates most hooks ([interest_tracking.bpf.h#L19-L193](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/interest_tracking.bpf.h#L19-L193)); all processes are tracked by default. No dedup or rate limit.

**Transport.** One perf event array per module, 4,096 pages (16 MiB) per CPU by default; events are built in a per-CPU array with three slots chosen by a nesting counter so a preempting program cannot clobber a slot ([output.bpf.h#L10-L167](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/output.bpf.h#L10-L167), [program.rs#L39-L57](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-common/src/program.rs#L39-L57)). Lost samples are only logged ([program.rs#L536-L538](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-common/src/program.rs#L536-L538)).

**Overhead.** None published; the site says "blazing fast" ([pulsar.sh](https://pulsar.sh/)).

**Blind spots.** The homepage advertises blocking file access by path, but every LSM program passes the previous verdict through ([common.bpf.h#L72-L80](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/common.bpf.h#L72-L80)); orphan handling is bounded at 45 children ([probes.bpf.c#L23-L26](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L23-L26)). [INFERENCE] containerd and CRI-O cgroup layouts match none of the container patterns; exit drops the signal; per-packet events make network volume proportional to packets.

**Relevance.** Pulsar shows the LSM-first shape with a kprobe twin from one macro, and kernel-side interest inherited at fork. Its costs are where it leaves that shape: a program on every context switch and per-packet records with payload copies.

### osquery

Surveyed: 5.24.0 (2026-10-09, [releases API](https://api.github.com/repos/osquery/osquery/releases)); source at master [`99ea204`](https://github.com/osquery/osquery/tree/99ea20493a2614eab939cbc02ebfaa114a3caecb). Apache-2.0 OR GPL-2.0, C++. A SQL engine: evented tables buffer rows in RocksDB until a scheduled query drains them; a watchdog restarts the worker above 200 MB or 10% CPU for 12 s by default ([cli-flags.md#L85-L128](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/installation/cli-flags.md#L85-L128)).

**Mechanism.** Four opt-in Linux sources:

- **Audit netlink** for `process_events`, `socket_events`, `process_file_events`, `user_events` and SELinux/AppArmor/seccomp tables. osquery installs one exit rule for the union of needed syscalls with no field filters ([auditdnetlink.cpp#L431-L450](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/auditdnetlink.cpp#L431-L450)), and cannot coexist with auditd ([process-auditing.md#L83](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L83)). `process_file_events` audits every `read`, `write` and `close` on the host and filters paths in userspace ([process_file_events.h#L16-L55](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/process_file_events.h#L16-L55)).
- **eBPF via Trail of Bits ebpfpub** for `bpf_process_events` and `bpf_socket_events`: enter/exit programs on 26 per-syscall tracepoints (fork, clone, close, dup*, open*, socket, fcntl, connect, accept*, bind, listen, chdir, ...) plus kprobes on `execve`/`execveat`, with bytecode generated at runtime from LLVM IR and no CO-RE ([bpfeventpublisher.cpp#L68-L100](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/bpfeventpublisher.cpp#L68-L100)). Most of those hooks exist to rebuild per-process fd tables and cwd in userspace from a `/proc` snapshot re-taken every 10 minutes ([isystemstatetracker.h#L22-L25](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/isystemstatetracker.h#L22-L25), [bpfeventpublisher.cpp#L322-L335](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/bpfeventpublisher.cpp#L322-L335)). The docs say it will be removed in 6.0 ([process-auditing.md#L224](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L224)). An experimental `bpf_process_events_v2` uses a single `sched_process_exec` tracepoint with BTF and the cgroup path ([linuxevents README](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/experimental/experiments/linuxevents/README.md)).
- **inotify** for `file_events` (create, modify, delete, move, attrib, optional access/open), so only watched inodes cost anything ([inotify.cpp#L39-L54](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/inotify.cpp#L39-L54)).
- **udev netlink** for `hardware_events`.

**Events and enrichment.** `process_events`: cmdline, env, cwd, auid, uids/gids, parent pid; optional fork and kill syscalls ([process_events.table](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/process_events.table)). `socket_events`: bind/connect/accept with IPv4/IPv6/unix addresses. `process_file_events`: open/read/write/link/symlink/rename/unlink with pid and executable. `file_events`: path, action and md5/sha1/sha256 computed in userspace after the event ([file_events.cpp#L117-L122](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/file_events.cpp#L117-L122)). `user_events`: PAM/sshd audit messages. No exit event in any Linux table. Modules, mounts, sysctls, keys, namespaces, packages and Docker containers are snapshot tables only; lineage, hashes and package ownership are query-time SQL joins.

**Transport.** Audit: one reader and one parser thread; the reader stops reading netlink above 4,096 unprocessed records, and loss appears only in the kernel `lost` counter ([auditdnetlink.cpp#L74](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/auditdnetlink.cpp#L74), [process-auditing.md#L191-L216](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L191-L216)). BPF: per-CPU perf buffers of ~4 MiB with `wakeup_events = 1` ([ebpf_utils.cpp#L299-L306](https://github.com/trailofbits/ebpf-common/blob/1f454b453390134dc850f93068e045d8e1725ec5/ebpf/src/ebpf_utils.cpp#L299-L306)); events are held 5 s in a sorted map to reorder across CPUs ([bpfeventpublisher.cpp#L337-L388](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/bpfeventpublisher.cpp#L337-L388)); lost records are counted as one per `PERF_RECORD_LOST` and logged only in verbose mode ([perfeventarray.cpp#L127-L130](https://github.com/trailofbits/ebpf-common/blob/1f454b453390134dc850f93068e045d8e1725ec5/ebpf/src/perfeventarray.cpp#L127-L130)).

**Overhead.** No numbers published. The docs are qualitative: socket auditing "can introduce considerable load" ([process-auditing.md#L124](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L124)); a maintainer talk calls the audit tables high-CPU and high-memory and inotify "prone to losing events" with "no way to know if events were lost" ([QueryCon 2019 slides](https://querycon.io/static/Alessandro%20Gario%20-%20Linux%20security%20event%20monitoring%20with%20osquery.279cddb4.pdf), pp. 6, 9, 14).

**Blind spots.** Audit and auditd are mutually exclusive; events expire only when queried; inotify cannot watch paths that do not exist yet, stops on delete, does not recurse into moved-in directories ([file-integrity-monitoring.md#L179-L188](https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/file-integrity-monitoring.md#L179-L188)); `bpf_*` tables carry a raw cgroup id with no container mapping. [INFERENCE] io_uring is invisible to both the audit rule and the BPF syscall hooks.

### auditd with Laurel or go-audit

Surveyed: audit-userspace v4.2.1 ([`280cb8c`](https://github.com/linux-audit/audit-userspace/tree/280cb8c07c431439ff85771988b9656780b8ef2b)), Laurel v0.8.2 (2026-07-17, [`8d3d83c`](https://github.com/threathunters-io/laurel/tree/8d3d83cac896e6d63b5f927e415f6d7d7ad89270)), go-audit v1.2.2 (2026-06-22, [`4739171`](https://github.com/slackhq/go-audit/tree/4739171bc7d5dea93f863c361eec2ce30b5daa5e)). Kernel references are to Linux v7.0 ([`028ef9c`](https://github.com/torvalds/linux/tree/028ef9c96e96197026887c0f092424679298aae8)).

**Mechanism.** The kernel audit subsystem. Once audit is enabled, each new task gets an audit context and `SYSCALL_WORK_SYSCALL_AUDIT` unless a task rule disables it ([auditsc.c#L1057-L1083](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L1057)). Every syscall then runs `__audit_syscall_entry` and `__audit_syscall_exit`; with at least one rule loaded, the exit path walks the whole exit rule list, testing each rule's syscall bitmap ([auditsc.c#L1986-L2058](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L1986), [#L827-L840](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L827)). auditctl(8): "If you have 10 syscall rules, every program on your system will delay during a syscall while the audit system evaluates each rule" ([auditctl.8#L281-L303](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/docs/auditctl.8#L281-L303)). Some records need no syscall rule: BPF program load/unload ([bpf/syscall.c#L2309-L2326](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/bpf/syscall.c#L2309)), core dumps, and userspace USER_* records from PAM, sudo and shadow-utils.

**Events.** SYSCALL (pid, ppid, auid, uids, tty, ses, comm, exe, key, a0-a3), EXECVE, CWD, PATH, PROCTITLE, SOCKADDR, OBJ_PID, CAPSET, KERN_MODULE, BPF, TIME_*, URINGOP, and identity records USER_LOGIN, USER_AUTH, USER_CMD, ADD_USER, LOGIN ([uapi audit.h#L93-L158](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/audit.h#L93)). Shipped rule files cover namespaces (clone flags, unshare, setns), ptrace injection, module load, STIG time/identity/perm-mod/mount/delete rules and PCI setuid rules ([rules/](https://github.com/linux-audit/audit-userspace/tree/280cb8c07c431439ff85771988b9656780b8ef2b/rules)).

**Enrichment.** Laurel, an auditd plugin, coalesces records per event id into one JSON object and adds, in userspace and after the fact: a shadow process table seeded from `/proc` and persisted across restarts (`SPAWNED_BY` lineage), container id from `/proc/<pid>/cgroup`, selected env vars from `/proc/<pid>/environ`, the interpreter script path, optional exe SHA-256, and propagated labels ([laurel-about.7.md#L46-L104](https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-about.7.md#L46-L104), [proc.rs#L167-L262](https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/src/proc.rs#L167-L262)). The script lookup "may fail for very short-lived processes" ([coalesce.rs#L326-L343](https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/src/coalesce.rs#L326-L343)). Lineage requires auditing every fork, clone and exec in the kernel even if Laurel drops them later ([laurel-audit-rules.7.md#L153-L174](https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-audit-rules.7.md#L153-L174)). go-audit replaces auditd, reads netlink directly and can add container image and pod labels from the Docker/containerd API ([extras_containers.go#L119-L175](https://github.com/slackhq/go-audit/blob/4739171bc7d5dea93f863c361eec2ce30b5daa5e/extras_containers.go#L119-L175)).

**Filtering and transport.** Kernel rule fields filter at syscall exit, after the hooks have run; no dedup. When the kernel backlog fills, the task generating the record sleeps up to `backlog_wait_time` (default 60 s) before the record is dropped and `lost` incremented; with failure mode 2 a lost record panics the machine ([audit.c#L1926-L1955](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/audit.c#L1926), [#L392-L422](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/audit.c#L392)). auditd's own docs warn this "will likely be noticed as slowing down various processes on the machine" ([auditd-plugins.5#L59-L79](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/docs/auditd-plugins.5#L59-L79)). go-audit detects loss from gaps in audit sequence numbers ([marshaller.go#L155-L177](https://github.com/slackhq/go-audit/blob/4739171bc7d5dea93f863c361eec2ce30b5daa5e/marshaller.go#L155-L177)).

**Overhead.**

| Source | Setup | Result |
|---|---|---|
| Ankur Arora (Oracle), 2022 ([linux-audit list](https://lists.linux-audit.osci.io/archives/list/linux-audit%40lists.linux-audit.osci.io/message/RL7XJNIDJ6G7ATBKLKPFM7I2TUWZXOLT/)) | Skylake-X, v6.0-rc5, `getpid()` × 10^7, `perf stat` | 283 cycles per call with audit off; 836 with a production set of 42 exit rules that getpid does not match. |
| Stanislav Kinsburskii, 2026 ([LKML](https://lists.openwall.net/linux-kernel/2026/08/07/58)) | VM, median `getpid` latency | 38 ns with no rules; 55 / 71 / 428 / 791 ns with 1 / 32 / 128 / 256 unrelated exit rules; 55 ns flat with a proposed per-syscall aggregate mask. [INFERENCE] Not in the v7.0 tree surveyed. |
| Laurel authors, 2021 ([performance.md](https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/performance.md)) | AWS t2.small, `/bin/true` exec loop, userspace CPU only | At 1,000 exec/s: auditd RAW 5.96%, ENRICHED 10.33%, Laurel+auditd 20.98%, go-audit 7.42%, auditbeat 54.53%. |
| Microsoft, 2021 ([perftest README](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/perftest/README.md), [perf2.csv](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/perftest/perf2.csv)) | Azure B2s, exec loop, execve rule only | At 1,600 exec/s: auditd RAW 8.53%, go-audit 8.3%, Laurel 24.9%, auditbeat 42.1%, Sysmon 24.71%. |
| eAudit, Stony Brook ([paper](https://par.nsf.gov/servlets/purl/10554458)) | i7-6500U, auditd logging ~80 provenance syscalls incl. read/write | auditd reaches zero loss by slowing benchmarks about 5× (shbm) and 8× (postmark); 850 bytes per record. |

**Blind spots.** Syscall rules do not see io_uring operations; io_uring rules exist, but 33 operations including READ, WRITE, SEND, RECV and SOCKET are marked `audit_skip` in v7.0 ([io_uring.c#L1381-L1387](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/io_uring/io_uring.c#L1381), [opdef.c](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/io_uring/opdef.c#L54)). No container id in kernel records. Watches on non-existent paths cannot be loaded. Only one process can own the audit netlink socket.

### Sysmon for Linux

Surveyed: SysmonForLinux 1.5.3 and SysinternalsEBPF 2.2.2 (2026-09-10); source at [`62523fd`](https://github.com/microsoft/SysmonForLinux/tree/62523fd44d9f7cad51dc21d0e465829a29eab6e2) and [`a43369a`](https://github.com/microsoft/SysinternalsEBPF/tree/a43369a5e0b9421c02ee8715c31557744ac1c9f4). MIT userland, GPL-2.0 eBPF; systemd service writing XML events to syslog.

**Mechanism.** On kernels ≥ 4.17, raw tracepoints `sys_enter` and `sys_exit` ([sysmonforlinux.c#L1511-L1580](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L1511-L1580)). One generic `sys_enter` program runs on every syscall, checks `config->active[syscall]` and saves the arguments in a hash keyed by pid_tgid ([sysmonGenericEntry_rawtp.c#L53-L80](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonGenericEntry_rawtp.c#L53-L80)); up to 11 exit programs are each attached to `sys_exit` and each runs on every syscall exit ([sysmonforlinux.c#L132-L160](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L132-L160)). Other hooks: `sched_process_exit`, `sock/inet_sock_set_state` for TCP, and `skb/consume_skb` for UDP sends, which runs on every freed skb ([sysmonUDPsend.c#L42-L132](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonUDPsend.c#L42-L132)). Enabling NetworkConnect activates `read()` and the recv family host-wide ([sysmonforlinux.c#L901-L952](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L901-L952)).

**Events.** IDs 1 ProcessCreate (image, command line, cwd, user, logon id, parent image and command line, GUIDs), 3 NetworkConnect, 4/16 service and config state, 5 ProcessTerminate (no exit code), 9 RawAccessRead (block devices), 10 ProcessAccess (ptrace), 11 FileCreate, 23 FileDelete, 100 eBPFEvent (BPF program loads) ([manifest.xml](https://github.com/microsoft/SysmonCommon/blob/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml#L51)). FileDelete hashes are always blank on Linux ([sysmonforlinux.c#L701](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L701)). No container context anywhere in the sources.

**In-kernel filtering.** A per-syscall `active[]` array; a FileCreate heuristic that emits only O_CREAT opens of regular files whose three timestamps are equal and within 100 ms, "to reduce load on the ring buffer" ([sysmonFileOpen.c#L191-L216](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonFileOpen.c#L191-L216)); UDP dedup in a 128K-entry hash keyed by 4-tuple, reporting each tuple again only after 30 minutes ([sysmonUDPsend.c#L173-L192](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonUDPsend.c#L173-L192)). All XML rule filtering runs in userspace.

**Transport.** Perf buffers of 16,384 pages (64 MiB) per CPU with libbpf's default wakeup per record ([telemetryLoader.c#L1438](https://github.com/microsoft/SysinternalsEBPF/blob/a43369a5e0b9421c02ee8715c31557744ac1c9f4/telemetryLoader.c#L1438)); lost samples are printed to stdout and never become events ([sysmonforlinux.c#L788-L793](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L788-L793)).

**Overhead.** Microsoft ([perftest README](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/perftest/README.md)): Azure B2s, ProcessCreate only, `/bin/true` at 100-1,600 exec/s; 4.43% CPU at 100/s to 24.71% at 1,600/s for all involved processes, plus BPF time of 0.48-0.98% from `perf top`. Their comparison of raw vs per-syscall tracepoints found no significant difference at exec rates, but did not measure unrelated syscalls ([TracepointComparisons.md](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/perftest/TracepointComparisons.md)). No published cost of the raw sys_enter/sys_exit programs on unrelated syscalls.

**Blind spots.** "Does not … attempt to protect or hide itself" ([sysmon man page#L20-L21](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/package/usr/share/man/man8/sysmon_template.8#L20-L21)); deep paths truncated with a `+` prefix; syslog may truncate large events; [INFERENCE] no openat2, rename, mmap or io_uring coverage, and FileCreate misses creates that fail the timestamp heuristic.

### Wazuh agent

Surveyed: v4.14.9 (2026-10-15) and v5.0.0-rc2 (2026-10-30); source at main [`bbd1cea`](https://github.com/wazuh/wazuh/tree/bbd1cea999dd661483c3e5f51345385caa853319) (5.1.0-alpha0). GPL-2.0. Host agent; detection rules run on the manager.

**Mechanism.** File integrity monitoring (`syscheckd`) has three modes: a scheduled scan (default every 12 h over `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot`; [ossec-agent.conf#L43-L97](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L43-L97)); realtime via inotify ([run_realtime.c#L34](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/run_realtime.c#L34)); and who-data. Who-data defaults to an audit directory watch per monitored directory ([audit_op.c#L278-L332](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/shared/src/audit_op.c#L278-L332), [syscheck-config.c#L93](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/config/src/syscheck-config.c#L93)); a proposal to make eBPF the default was reverted ([#31467](https://github.com/wazuh/wazuh/issues/31467)). The eBPF provider (since [4.12.0](https://documentation.wazuh.com/current/release-notes/release-4-12-0.html)) uses `lsm/file_open`, `lsm/path_unlink`, `lsm/path_rename` when BPF LSM is active, otherwise kprobes on `vfs_open`, `vfs_unlink`, `vfs_rename`, plus kprobes on `security_inode_setattr` and `mnt_want_write` (to recover the mount for path reconstruction) ([modern.bpf.c#L422-L843](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L422-L843)). A startup self-test creates, modifies, chmods and deletes a file and falls back to audit, then inotify, on failure ([ebpf_whodata.cpp#L852-L927](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/ebpf_whodata.cpp#L852-L927)). Process, network and identity data come from log collection (`auth.log`, `syslog`, optionally audit logs) and an hourly inventory ([ossec-agent.conf#L26-L117](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L26-L117)).

**Events.** FIM added/modified/deleted with path, mode, size, owner, inode, mtime, md5/sha1/sha256, changed fields, diffs, and who-data (uid, user, process name, pid, ppid, cwd, parent name/cwd, login uid) ([events.c](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/file/events.c), [modern.bpf.c#L38-L52](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L38-L52)).

**Filtering and transport.** The eBPF provider filters in the kernel only by file type and write/create flags; there is no path filter, so every write-open, unlink or rename of any regular file emits a ~12 KB record with three path walks, and the monitored-directory check runs in userspace ([modern.bpf.c#L345-L412](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L345-L412), [ebpf_whodata.cpp#L211-L251](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/ebpf_whodata.cpp#L211-L251)). One shared 8 MiB ringbuf, default wakeups; reserve failures return silently ([modern.bpf.c#L66-L69](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L66-L69), [#L349-L351](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L349-L351)). Userspace caps FIM at 50 events/s by default ([syscheck-config.c#L80-L125](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/config/src/syscheck-config.c#L80-L125)). inotify overflow defers recovery to the next scan ([run_realtime.c#L221-L226](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/run_realtime.c#L221-L226)).

**Overhead.** None published for the agent; the "Measuring Wazuh performance" post covers server components only ([blog](https://wazuh.com/blog/measuring-wazuh-performance-and-operational-efficiency/)).

**Blind spots.** Default FIM is a 12-hourly scan; realtime and who-data must be enabled per directory; no read monitoring in eBPF mode; no exec telemetry without auditd rules; no container context.

### Jibril (Garnet Labs) — binary-only

Surveyed: v2.17.0 binary release (2026-09-09; [releases API](https://api.github.com/repos/garnet-org/jibril-releases/releases)). **Not open source.** The license is "MIT-Binary-Restricted": binary distribution only, internal use, no reverse engineering; the embedded eBPF objects are GPLv2 ([license](https://jibril.garnet.ai/intro/license.html), [jibril-releases README#L3-L4](https://github.com/garnet-org/jibril-releases/blob/82bedcb1ff4a716361edde624939dcde68941da4/README.md#L3-L4)). Public parts: Apache-2.0 output types ([jibril-ashkaal `0bac0ee`](https://github.com/garnet-org/jibril-ashkaal/tree/0bac0ee73ab319973a40d6d1a62fdc9397fc2695)), GPL-2.0 detection recipes ([jibril-recipes `8d06e36`](https://github.com/garnet-org/jibril-recipes/tree/8d06e36b320f3f58184fa07294e9363741a05dea)) and a GitHub Action. Included because its claimed architecture is the main alternative to ring-buffer streaming. Lead developer was previously a Tracee core developer ([HN](https://news.ycombinator.com/item?id=43475522)).

**Mechanism (as documented; hook names unpublished).** "eBPF programs attach to kernel functions and store data in eBPF maps"; userspace "retrieves security events on demand from kernel memory rather than streaming them through ring buffers" and a query engine polls the maps at a configured interval ([architecture](https://jibril.garnet.ai/intro/arch.html)). The state is relational: caches for tasks, recently ended tasks, command lines, task references, files, directories, flows, and the task↔file, task↔flow and flow↔flow edges ([cache categories](https://jibril.garnet.ai/config/caches/categories.html)). Per (process, file) pair the record holds a 15-bit action set (open, read, write, mmap, rename, truncate, unlink, create, link, execve, ...) ([files.go#L29-L47](https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L29-L47)). Detection recipes run in userspace every 6-9 s by default, serialized on one core ([cadences](https://jibril.garnet.ai/config/cadences/perf.html)); network egress blocking is synchronous in the kernel, with DNS answers pushed into the policy map ([policy](https://jibril.garnet.ai/config/policy.html)). Kernel 5.10+, 6.2 recommended ([requirements](https://jibril.garnet.ai/install/requirements.html)).

**Events.** No raw stream: `flow`, `profile`, `dropip`, and one detection event per recipe (≈70), each carrying container info, files, flows and full process ancestry ([kind.go#L31-L39](https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/kind/kind.go#L31-L39), [types.go#L401-L407](https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L401-L407)). Process arguments and environment are "never collected" ([cache categories](https://jibril.garnet.ai/config/caches/categories.html)). Flows have no byte counters ([types.go#L1809-L2016](https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1809-L2016)). Container metadata (image, privileged flag, labels) from the Docker and containerd sockets ([containers](https://jibril.garnet.ai/config/containers.html)).

**Overhead.** Vendor claims only: "Handles 100,000+ events/second; No event loss under load" ([docs home](https://jibril.garnet.ai/)), "≤2% CPU" ([garnet.ai](https://www.garnet.ai/)); no workload, hardware or kernel stated.

**Blind spots.** The docs contradict "no event loss": "If your workload is bigger, or you make the detection cadence longer, you'll probably need to make caches bigger to avoid missing events" ([caches](https://jibril.garnet.ai/config/caches/)); no eviction counter is documented. Detection latency equals the cadence. The CI action states the record "does not declare that every connection was captured" ([action README#L189](https://github.com/garnet-org/action/blob/96e9f81ec0f59f2322e8c67b43c4d4017d932ad3/README.md#L189)).

**Relevance.** Jibril takes "decide and deduplicate in the kernel" to its limit: memory scales with distinct (task, object) pairs, not event rate. The price is the loss of per-event time and order, and silent LRU eviction in place of counted drops, which conflicts with panopticon's principle 6.

### ByteDance Elkeid

Surveyed: driver 1.7.0.24 (2025-12-15; last tag v1.7.0.22, 2024-12-24); sparse source at [`c906c51`](https://github.com/bytedance/Elkeid/tree/c906c512d20c0d56f2b779b8558ed69abae718c8). GPLv2 kernel module, Apache-2.0 Rust plugin, Go agent; described as "deployed massively for HIDS usage in world-class production environments" ([driver README#L13](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L13)). There is no eBPF HIDS driver; the sensor is a loadable kernel module.

**Mechanism.** kprobes and kretprobes on syscall wrappers (`execve`, `connect`, `accept`, `bind`, `ptrace`, `open`, `kill`, `exit`, ...) and on LSM and kernel functions (`security_sb_mount`, `security_inode_rename/link/create`, `security_file_mprotect`, `commit_creds`, `do_init_module`, `call_usermodehelper_exec`, `vfs_write`, `tcp_v4/v6_connect`) ([smith_hook.c#L3920-L4120](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L3920-L4120)). A `sys_exit` tracepoint parses DNS replies on kernels ≥ 5.5; the source comment says "sys_enter or sys_exit will affect all syscalls, and could lead performance drop of about 3 - 5%, even with noop-processing in the hookpoint callback" ([smith_hook.c#L2646-L2651](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L2646-L2651)). Write, open, accept, mprotect, kill, unlink and exit hooks are off by default ([smith_hook.c#L32-L60](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L32-L60)).

**Events and enrichment.** Numbered data types: execve (argv, cwd, tty, stdin/stdout, socket tuple of the task tree, `pid_tree`, SSH and LD_PRELOAD env), connect, bind, DNS query, create_file, rename, link, mount, load_module, memfd_create, ptrace (POKE only), update_cred (non-root → root only), privilege_escalation, usermodehelper, and rootkit scans ([driver README#L82-L474](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L82-L474)). The kernel builds a 12-level `pid_tree` string per event ([smith_hook.c#L599-L675](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L599-L675)). The plugin's executable "hash" is XxHash64 over size and the first 32 KiB ([cache.rs#L141-L174](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/plugins/driver/src/transformer/cache.rs#L141-L174)).

**Filtering and transport.** Kernel allowlists of executables and argv (128 hashed entries) written through `/proc/elkeid-endpoint` ([filter.c#L40-L87](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/filter.c#L40-L87)); the plugin counts events per executable and pushes anything above 150 events/s (outside system paths) into that allowlist ([transformer.rs#L217-L235](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/plugins/driver/src/transformer.rs#L217-L235)); DNS parsing is disarmed above ~1,024 UDP receives/s ([smith_hook.c#L2258-L2325](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L2258-L2325)). Transport is a private copy of the ftrace per-CPU ring (128 KiB per CPU) in overwrite-oldest mode; records are formatted to text in the reader's `read()`, not in the hook ([trace.c#L280-L459](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/trace.c#L280-L459)).

**Overhead.** Vendor per-handler latency on kernel 4.14 under LTP syscall tests: e.g. `execve_handler` 15.21 µs average (36.09 TP99), `connect_syscall_handler` 0.745 µs, `security_inode_create_pre_handler` 1.55 µs; handler time only ([driver README#L574-L611](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L574-L611)).

**Blind spots.** "DO NOT insmod the ko in the production machines if you have not well tested it" ([driver README#L15-L16](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L15-L16)); per-kernel module builds; overwrite mode replaces the oldest records under bursts. [INFERENCE] A noisy attacker binary can get itself auto-allowlisted, and UDP receive load blinds DNS logging.

### StackRox / Red Hat ACS Collector, with `fact`

Surveyed: collector 3.26.2 (2026-10-26) at [`53f1ef8`](https://github.com/stackrox/collector/tree/53f1ef8af9be20adc1c646c805f3487e930a429b), using `stackrox/falcosecurity-libs` [`8d02979`](https://github.com/stackrox/falcosecurity-libs/tree/8d029795c5330842df2630a5c3023aba0abde46a); `fact` 0.4.2 at [`710d858`](https://github.com/stackrox/fact/tree/710d85818e150606d2b4ef062219ff8aefcf0394). Apache-2.0; shipped in Red Hat Advanced Cluster Security. Included as the main production consumer of the Falco libs outside Falco, and because `fact` is an LSM-only, inode-keyed file monitor.

**Collector.** Opens the modern_ebpf driver with a reduced syscall set (accept*, chdir, clone*, close, connect, execve, fchdir, fork, getsockopt, procexit, set*id, shutdown, socket, vfork; send/recv optional) plus `sched_process_exit` and `sched_switch` ("sched_switch makes conveying process information more reliable") ([KernelDriver.h#L47-L77](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/KernelDriver.h#L47-L77), [CollectorConfig.h#L35-L67](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/CollectorConfig.h#L35-L67)). Every syscall still pays the libs `sys_exit` dispatcher, and the `sched_switch` program reserves a ring record on every context switch ([sched_switch.bpf.c](https://github.com/stackrox/falcosecurity-libs/blob/8d029795c5330842df2630a5c3023aba0abde46a/driver/modern_bpf/programs/attached/events/sched_switch.bpf.c)). Host processes are filtered in userspace after transport ("Filter out host processes to avoid flooding Sensor", [Service.cpp#L61-L89](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/system-inspector/Service.cpp#L61-L89)). Outputs are process signals (args, exe, uid, container id, up to 10 ancestors within the container) and network connection/endpoint deltas, with server-side connections normalized by dropping the ephemeral port, a 5-minute "afterglow" that suppresses open/close churn, and 2,048 connections per container per minute ([ConnTracker.cpp#L167-L290](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ConnTracker.cpp#L167-L290), [NetworkStatusNotifier.cpp#L315-L360](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/NetworkStatusNotifier.cpp#L315-L360)). Listen endpoints come from a `/proc` scrape every 30 s ([CollectorConfig.h#L31-L33](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/CollectorConfig.h#L31-L33)). Ringbuf per CPU, 8 MiB each up to 512 MiB total; drop counters exported ([references.md#L59-L75](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/docs/references.md#L59-L75)). Red Hat documents resource settings (request 0.06 cores / 320 MiB, limit 0.9 cores / 1,000 MiB for the collector container), not measurements ([RHACS 4.11 requirements](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/installing/acs-default-requirements)).

**fact.** BPF LSM programs only: `file_open`, `path_link`, `path_unlink`, `path_chmod`, `path_chown`, `path_rename`, `path_mkdir`, `d_instantiate`, `inode_setxattr`, `inode_removexattr`, `inode_set_acl`, `path_rmdir`, `sb_mount`, `sb_umount`, `move_mount`, `path_symlink` ([main.c#L61-L683](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L61-L683)). `file_open` keeps only creates and write-opens, then checks the inode against a `(dev, ino)` hash of watched inodes, then the parent's inode (and adds newly created children, so the watch set grows with the tree), then an LPM trie of path prefixes ([main.c#L61-L124](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L61-L124), [maps.h#L30-L100](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/maps.h#L30-L100)). Process context (exe via `bpf_get_task_exe_file` + `d_path`, memory cgroup, loginuid, two-level lineage) is gathered in the kernel ([process.h#L14-L140](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/process.h#L14-L140)). Per-hook per-CPU counters for total, added, error, ignored and ringbuffer-full ([types.h#L175-L206](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/types.h#L175-L206)). [INFERENCE] Unwatched write-opens pay path resolution before the inode check, and the fixed-size event (several PATH_MAX buffers, ~29 KiB) leaves room for ~290 events in the 8 MiB ring. Technology Preview in RHACS 4.10/4.11 ([4.11 release notes](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.11/html/release_notes/release-notes-411)).

### Kubescape node-agent

Surveyed: v0.3.299 (2026-10-28) at [`c1519c3`](https://github.com/kubescape/node-agent/tree/c1519c3e183c38d74faed7b93a0b10ebfa680f6e). Apache-2.0 Go DaemonSet, part of Kubescape (CNCF incubating), built on a fork of Inspektor Gadget ([inspektor-gadget-fork.md](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/features/inspektor-gadget-fork.md)).

**Mechanism.** Upstream IG gadgets (`trace_exec`, `trace_open`, `trace_dns`, `trace_capabilities`, `advise_seccomp`) plus its own gadgets on syscall tracepoints (`sys_enter_bpf`, `link*`, `symlink*`, `init_module`, `ptrace`, `unshare`, `open*`), `sched_process_exit/fork`, io_uring submit tracepoints, socket filters, and an x86 FPU tracepoint for RandomX mining ([pkg/ebpf/gadgets](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets)). `advise_seccomp` puts a program on raw `sys_enter` and is enabled whenever runtime detection or seccomp is on; it aggregates a syscall bitmap per mount namespace in a map that userspace iterates ([syscall.go#L298-L303](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/syscall.go#L298-L303), [advise_seccomp#L65-L124](https://github.com/inspektor-gadget/inspektor-gadget/blob/2d313744c21e53d8f846b681d72add09688a2040/gadgets/advise_seccomp/program.bpf.c#L65-L124)). Host processes are not monitored by default ([CONFIGURATION.md#L146-L163](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L146-L163)). Detection uses CEL rules and learned per-workload application profiles.

**Overhead.** The project's own benchmark (kind cluster, ~1,100 events/s mixed load): 0.178 cores average and 339.5 MiB, 0.150 cores with a userspace dedup cache; "The eBPF ingestion and event enrichment cost (which dominates baseline CPU) is unchanged" ([benchmark-results.md](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/dedup-testing/benchmark-results.md)). [INFERENCE] That is on the order of 130 µs of agent CPU per event delivered to userspace. The README claims "~1-2% CPU overhead" without methodology ([README#L31](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/README.md#L31)).

### Checked and excluded

| Candidate | Reason | Source |
|---|---|---|
| Meta bpfjailer | BPF-LSM mandatory access control, enforcement rather than telemetry; Linux 6.16+, "completely experimental" | [README](https://github.com/facebookincubator/bpfjailer/blob/e6e9caf0df01c7528c9048fc09b35f66d480ea40/README.md) |
| SunnyMapBPF | Not an agent; a study showing that editing BPF maps of Falco, Tracee and Tetragon silences detections (see [cross-cutting evidence](#evasion-and-tampering)) | [README](https://github.com/azqzazq1/SunnyMapBPF/blob/ceacd5f2b9e8424e462af0a66ce735efbd285831/README.md) |
| chriskaliX/Hades | Single-maintainer eBPF port of Elkeid's hook set | [README](https://github.com/chriskaliX/Hades/blob/56f8fb84008f08fdd56c698c9426f876d2a3f471/README.md) |
| Deepfence ThreatMapper | CNAPP scanning and topology, not a continuous runtime sensor; low activity | [repo](https://github.com/deepfence/ThreatMapper/tree/657c7c11d4cc37a2052e27672f17ef7033757e9c) |
| bpfman | eBPF program manager, not telemetry | [repo](https://github.com/bpfman/bpfman/tree/38a68b5f9feab9b64145cf896b307f667df34dbe) |
| Velociraptor `watch_ebpf` | Query-time watcher inside a DFIR client | [docs](https://docs.velociraptor.app/vql_reference/linux/watch_ebpf/) |
| LimaCharlie sensor | Source not found | `api.github.com/repos/refractionPOINT/lc-sensor` returned 404 |
| Sekoia agent | Not checked | — |

## Coverage matrix

Values: ✓ = a shipped, documented event, table, rule or library policy delivers the item with its key fields (for rule- or policy-gated agents such as Falco, Tetragon, Datadog and KubeArmor this can mean enabling a rule or policy that uses only shipped event types); partial = only through user-written hooks or policies (Tetragon kprobes on unlisted functions, Datadog `ondemand` hooks, custom audit rules), or key fields are missing, or coverage is limited; ✗ = not available. Columns: ACS = StackRox/Red Hat ACS Collector with `fact`; auditd+ = auditd with Laurel or go-audit; IG = Inspektor Gadget. Every cell has a one-line basis and a citation in the per-agent evidence blocks below the tables, written by the researcher who read that agent's source.

### Process

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exec | ✓ | ✓ | ✓ | partial | partial | partial | ✓ | partial | partial | ✓ | ✓ | partial | partial | partial | ✓ | partial | ✓ |
| exit | ✓ | ✓ | ✓ | ✓ | ✗ | partial | partial | partial | partial | ✗ | partial | partial | ✗ | partial | partial | ✗ | ✓ |
| fork/clone | ✓ | partial | ✓ | partial | ✗ | partial | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | partial | ✗ | ✗ | ✓ |
| credential change | ✓ | ✓ | ✓ | ✓ | partial | partial | partial | ✓ | partial | ✗ | ✓ | ✗ | partial | ✗ | partial | ✗ | partial |
| process injection | ✓ | partial | ✓ | partial | partial | partial | partial | partial | ✗ | ✗ | partial | partial | partial | partial | partial | ✗ | partial |
| fileless exec | partial | ✓ | ✓ | ✓ | partial | partial | ✓ | partial | ✗ | partial | partial | ✗ | ✗ | partial | partial | ✗ | ✓ |
| script/interpreter content | ✗ | ✗ | partial | partial | ✗ | ✗ | ✗ | partial | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| TTY/interactive | ✓ | partial | partial | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | partial | ✗ | ✗ | ✓ | ✗ | ✓ |
| lineage | ✓ | ✓ | ✓ | ✓ | partial | partial | ✓ | ✓ | ✓ | partial | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ |
| executable hash | ✗ | partial | ✓ | ✓ | partial | ✗ | partial | ✓ | ✗ | partial | partial | partial | partial | ✗ | partial | ✗ | partial |
| package ownership/signature | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | partial | ✗ | ✗ | partial | ✗ | ✗ | ✗ | partial |

### File

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sensitive-file read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ | ✗ | partial | ✓ | ✗ | ✗ | ✓ |
| write/modify | partial | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✗ | ✓ | ✓ | partial | partial | partial |
| create | ✓ | partial | partial | ✓ | partial | partial | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ | partial |
| delete | ✓ | partial | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | partial | ✓ | ✗ |
| rename | ✓ | partial | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | partial | partial | ✓ | ✓ | ✗ |
| chmod/chown/xattr | partial | partial | ✓ | ✓ | partial | partial | partial | ✗ | ✗ | partial | ✓ | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ |
| link/symlink | ✓ | ✓ | ✓ | partial | partial | ✓ | partial | ✗ | ✓ | ✓ | partial | ✗ | partial | partial | partial | ✓ | ✓ |
| FIM hashing | ✗ | partial | ✗ | ✓ | ✗ | ✗ | ✓ | partial | ✗ | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | partial |
| persistence locations | partial | partial | partial | ✓ | partial | partial | partial | partial | ✓ | partial | ✓ | partial | partial | partial | partial | partial | partial |
| dropped-file exec | partial | partial | partial | ✓ | ✗ | ✓ | partial | partial | partial | ✗ | ✗ | ✗ | ✗ | partial | partial | ✗ | partial |
| library load / mmap exec | partial | ✓ | ✓ | ✓ | partial | partial | partial | ✓ | partial | partial | partial | ✗ | ✗ | partial | partial | ✗ | ✗ |

### Network

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| TCP connect/accept/listen | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | partial | ✓ | ✓ | ✓ | ✓ | partial | partial | partial | ✓ | partial |
| UDP flows | partial | partial | partial | partial | partial | partial | ✓ | partial | partial | partial | partial | ✓ | partial | ✓ | partial | partial | ✓ |
| DNS query/answer | ✗ | ✗ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | partial | ✓ | ✗ | ✓ |
| raw/packet sockets | ✓ | partial | partial | ✓ | ✓ | ✗ | ✗ | partial | ✗ | partial | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| unix sockets | ✓ | partial | ✓ | partial | ✓ | partial | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| IPv6 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | ✓ |
| NAT post-translation tuple | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| HTTP/TLS metadata (SNI) | ✗ | ✗ | partial | partial | ✗ | ✓ | ✗ | partial | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial |
| flow volume | partial | partial | ✗ | ✓ | partial | partial | ✓ | partial | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| bind | ✓ | partial | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | partial | ✗ | partial | ✗ | ✓ | partial | ✗ |

### Kernel/admin

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| module load | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ | partial | partial | ✓ | ✗ | partial | ✗ | ✓ | ✗ | ✓ |
| BPF load | ✓ | ✓ | ✓ | ✓ | ✗ | partial | partial | ✓ | ✗ | ✗ | ✓ | ✓ | ✗ | partial | ✗ | ✗ | ✓ |
| kprobe/perf_event_open | partial | ✓ | ✓ | partial | ✗ | ✗ | partial | partial | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| mount/umount | ✓ | partial | ✓ | partial | ✓ | ✓ | partial | ✗ | ✗ | partial | ✓ | ✗ | partial | ✗ | partial | ✓ | ✗ |
| namespaces | ✓ | ✓ | ✓ | partial | partial | partial | partial | partial | partial | partial | ✓ | ✗ | ✗ | partial | ✗ | ✗ | ✓ |
| kexec | partial | partial | ✓ | partial | ✗ | partial | partial | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| sysctl write | partial | partial | partial | ✓ | partial | partial | partial | ✗ | partial | partial | partial | ✗ | partial | partial | ✗ | ✗ | ✗ |
| time change | partial | partial | ✓ | partial | ✗ | partial | partial | ✗ | ✗ | ✗ | ✓ | ✗ | partial | ✗ | ✗ | ✗ | ✗ |
| keyring | partial | partial | ✓ | partial | ✗ | partial | partial | ✗ | ✗ | partial | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| io_uring | partial | partial | partial | partial | ✗ | ✗ | ✗ | partial | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| userfaultfd | ✓ | partial | ✓ | partial | ✗ | partial | partial | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| capability use | partial | ✓ | ✓ | partial | partial | ✓ | ✗ | partial | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |

### Identity

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| login/logout | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✓ | ✗ | partial | ✓ | ✓ | ✗ | ✓ | ✗ | partial | ✗ | partial |
| sudo/su | partial | ✓ | partial | ✓ | partial | partial | ✓ | partial | partial | partial | ✓ | ✗ | ✓ | partial | partial | ✗ | ✗ |
| user/group changes | partial | partial | partial | partial | partial | partial | ✓ | partial | partial | partial | ✓ | ✗ | ✓ | partial | ✗ | ✗ | ✗ |
| loginuid/session | ✓ | partial | ✗ | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | partial | partial | ✗ | partial | partial | ✗ |

### Container/K8s

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| container id | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | partial | partial | ✓ | ✗ | partial | ✓ | partial | ✓ | ✓ |
| image | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | partial | ✗ | partial | partial | partial | ✗ | partial | ✓ | ✗ | partial | ✓ |
| pod/namespace/labels | ✓ | ✓ | partial | ✓ | ✓ | ✓ | partial | ✗ | ✗ | partial | partial | ✗ | ✗ | partial | partial | partial | ✓ |
| privileged flag | ✓ | ✓ | ✗ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | partial |
| runtime events | ✓ | ✗ | ✓ | partial | ✗ | partial | ✗ | ✗ | ✗ | ✗ | partial | ✗ | ✓ | partial | ✗ | ✗ | ✓ |
| K8s audit | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |

### Sensor

| Item | Falco | Tetragon | Tracee | Datadog | KubeArmor | IG | Elastic | Kunai | Pulsar | osquery | auditd+ | Sysmon | Wazuh | Jibril | Elkeid | ACS | Kubescape |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| tamper protection | ✗ | ✗ | partial | partial | ✗ | ✗ | partial | ✓ | ✗ | ✗ | partial | ✗ | ✗ | ✗ | partial | ✗ | ✗ |
| loss/health reporting | ✓ | ✓ | ✓ | ✓ | partial | ✓ | ✓ | ✓ | partial | partial | ✓ | partial | partial | partial | partial | ✓ | partial |
| response actions | partial | ✓ | ✗ | ✓ | ✗ | partial | partial | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | partial | ✗ | ✗ | partial |
| prevention/enforcement | ✗ | ✓ | ✗ | partial | ✓ | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial | partial | ✗ | ✗ | ✗ |

Totals of ✓ cells (of 58): Falco 30, Tetragon 24, Tracee 34, Datadog 32, KubeArmor 13, IG 19, Elastic 21, Kunai 17, Pulsar 12, osquery 15, auditd+ 26, Sysmon 7, Wazuh 10, Jibril 8, Elkeid 10, ACS 11, Kubescape 20. Totals measure breadth of shipped telemetry, not quality or cost.

### Per-agent evidence

Each block lists the basis for every cell of one column. Click to expand.

<details>
<summary>Falco (section: <a href="#falco">Falco</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | `execve` exit: args, env, cwd, exe, tty, loginuid, caps ([event_table.c#L1993][fa1]) |
| exit | ✓ | `procexit` event: status, ret, sig, core; no shipped rule ([sched_process_exit.bpf.c#L140][fa2]) |
| fork/clone | ✓ | `clone`/`clone3`/`fork`/`vfork` events plus sched_process_fork child event ([event_table.c#L2285][fa3], [sched_process_fork.bpf.c#L49][fa4]) |
| credential change | ✓ | `setresuid`/`setuid`/`capset` events; incubating rule "Non sudo setuid" ([event_table.c#L1327][fa5], [falco-incubating_rules.yaml#L852][fa6]) |
| process injection | ✓ | stable rule "PTRACE attached to process"; `process_vm_writev` event, no rule ([falco_rules.yaml#L1123][fa7], [report.md#L248][fa8]) |
| fileless exec | partial | stable memfd rule; no deleted-executable check in field list ([falco_rules.yaml#L1266][fa9], [sinsp_filtercheck_thread.cpp#L31][fa10]) |
| script/interpreter content | ✗ | argv only; no script-content field in complete process field list ([sinsp_filtercheck_thread.cpp#L31][fa10]) |
| TTY/interactive | ✓ | `proc.tty`; stable rule "System user interactive" ([sinsp_filtercheck_thread.cpp#L231][fa11], [falco_rules.yaml#L702][fa12]) |
| lineage | ✓ | userspace thread table; `proc.aname[N]` ancestor fields ([sinsp_filtercheck_thread.cpp#L110][fa13]) |
| executable hash | ✗ | no hash field in complete process field list ([sinsp_filtercheck_thread.cpp#L31][fa10]) |
| package ownership/signature | ✗ | no package/signature field in complete process field list ([sinsp_filtercheck_thread.cpp#L31][fa10]) |
| sensitive-file read | ✓ | stable rule "Read sensitive file untrusted" (/etc/shadow, sudoers, pam) ([falco_rules.yaml#L397][fa14]) |
| write/modify | partial | open-with-write flags only; `write()` ignored by default ([falco_rules.yaml#L42][fa15], [app.cpp#L32][fa16]) |
| create | ✓ | `creat`, `mkdirat`, openat created flag; rule "Create files below dev" ([event_table.c#L2079][fa17], [falco-incubating_rules.yaml#L917][fa18]) |
| delete | ✓ | `unlinkat` event with path; rule "Delete or rename shell history" ([event_table.c#L2070][fa19], [falco-incubating_rules.yaml#L1085][fa20]) |
| rename | ✓ | `renameat2` event with old and new paths ([event_table.c#L2151][fa21]) |
| chmod/chown/xattr | partial | chmod/chown events with args; setxattr family generic, no args ([report.md#L20][fa22], [report.md#L341][fa23]) |
| link/symlink | ✓ | stable rules "Create Symlink/Hardlink Over Sensitive Files" ([falco_rules.yaml#L986][fa24]) |
| FIM hashing | ✗ | no content-hash field in complete fd field list ([sinsp_filtercheck_fd.cpp#L33][fa25]) |
| persistence locations | partial | incubating cron/shell-rc/authorized_keys rules; no ld.so.preload rule ([falco-incubating_rules.yaml#L355][fa26], [falco-incubating_rules.yaml#L1316][fa27]) |
| dropped-file exec | partial | stable rule covers only container overlay upper layer ([falco_rules.yaml#L1198][fa28]) |
| library load / mmap exec | partial | `mmap` event not selected by default; only sshd liblzma rule ([report.md#L184][fa29], [falco-incubating_rules.yaml#L1352][fa30]) |
| TCP connect/accept/listen | ✓ | `connect` exit with tuple; `accept4`, `listen` events ([event_table.c#L205][fa31], [event_table.c#L218][fa32]) |
| UDP flows | partial | per-syscall `sendto`/`recvfrom` tuples; no flow aggregation ([event_table.c#L260][fa33], [falco-incubating_rules.yaml#L810][fa34]) |
| DNS query/answer | ✗ | no DNS parsing; `fd.sip.name` resolves rule domains itself ([Resolving Domain Names][fa35]) |
| raw/packet sockets | ✓ | `socket` domain; stable rule "Packet socket created in container" ([falco_rules.yaml#L1013][fa36]) |
| unix sockets | ✓ | unix tuples/paths on connect/accept; `fd.type` unix ([sinsp_filtercheck_fd.cpp#L43][fa37]) |
| IPv6 | ✓ | socket tuples carry IPv6; `fd.sockfamily` field ([sinsp_filtercheck_fd.cpp#L119][fa38]) |
| NAT post-translation tuple | ✗ | socket-view tuples; no conntrack/netfilter program attached [INFERENCE] ([sc_set.c#L39][fa39]) |
| HTTP/TLS metadata (SNI) | ✗ | no L7 parsing; I/O data capped at 80-byte snaplen ([falco.yaml#L1434][fa40]) |
| flow volume | partial | per-call `evt.buflen`; read/write off by default; no aggregation ([sinsp_filtercheck_event.cpp#L169][fa41], [app.cpp#L32][fa16]) |
| bind | ✓ | `bind` exit event with address ([event_table.c#L193][fa42]) |
| module load | ✓ | `init_module`/`finit_module`; stable "Linux Kernel Module Injection Detected" ([falco_rules.yaml#L1063][fa43]) |
| BPF load | ✓ | `bpf` event (cmd); incubating rule "BPF Program Not Profiled" ([falco-incubating_rules.yaml#L1368][fa44]) |
| kprobe/perf_event_open | partial | `perf_event_open` generic event, syscall id only ([report.md#L227][fa45]) |
| mount/umount | ✓ | `mount` event: dev, dir, type, flags; `umount2` ([event_table.c#L1785][fa46]) |
| namespaces | ✓ | `setns`/`unshare` events; incubating rule "Change thread namespace" ([falco-incubating_rules.yaml#L493][fa47]) |
| kexec | partial | `kexec_load`/`kexec_file_load` generic events, no args ([report.md#L145][fa48]) |
| sysctl write | partial | only via custom open_write rule on /proc/sys; none shipped ([falco_rules.yaml#L42][fa15]) |
| time change | partial | `settimeofday`/`clock_settime` generic events, no args ([report.md#L339][fa49]) |
| keyring | partial | `keyctl` has args; `add_key`/`request_key` generic; no rule ([report.md#L146][fa50], [report.md#L9][fa51]) |
| io_uring | partial | setup/enter events only; ring ops invisible; krsi plugin opt-in ([io_uring rootkit blog][fa52], [krsi README#L5][fa53]) |
| userfaultfd | ✓ | `userfaultfd` event; sandbox rule "Unprivileged Delegation of Page Faults…" ([falco-sandbox_rules.yaml#L1636][fa54]) |
| capability use | partial | capset events, `thread.cap_*` snapshots; no capable() hook ([event_table.c#L2399][fa55], [sinsp_filtercheck_thread.cpp#L510][fa56]) |
| login/logout | ✗ | no login/PAM/utmp event in complete syscall report ([report.md#L1][fa57]) |
| sudo/su | partial | exec visibility; only CVE-specific sandbox sudo rule ([falco-sandbox_rules.yaml#L1618][fa58]) |
| user/group changes | partial | incubating "User mgmt binaries" detects useradd-style exec only ([falco-incubating_rules.yaml#L880][fa59]) |
| loginuid/session | ✓ | execve `loginuid` param; `user.loginuid`, `proc.sid` fields ([event_table.c#L2015][fa60], [sinsp_filtercheck_user.cpp#L38][fa61]) |
| container id | ✓ | kernel `cgroups` param mapped to `container.id` by container plugin ([container README#L50][fa62]) |
| image | ✓ | container plugin queries runtime sockets asynchronously ([container README#L53][fa63]) |
| pod/namespace/labels | ✓ | `k8s.pod.*`, `k8s.ns.name` from CRI sandbox; k8smeta for more ([container README#L82][fa64]) |
| privileged flag | ✓ | `container.privileged`; incubating rule "Launch Privileged Container" ([container README#L56][fa65], [falco-incubating_rules.yaml#L678][fa66]) |
| runtime events | ✓ | `container` and `container_removed` async events ([macros.h.in#L26][fa67]) |
| K8s audit | ✓ | k8saudit plugin, 48 rules on `k8s_audit` source ([k8s_audit_rules.yaml#L154][fa68]) |
| tamper protection | ✗ | no self-protection option in complete configuration file ([falco.yaml#L1][fa69]) |
| loss/health reporting | ✓ | per-class `scap.n_drops_*` counters, drop alerts, Prometheus metrics ([falco.yaml#L1253][fa70], [struct_definitions.h#L71][fa71]) |
| response actions | partial | separate falco-talon project; Falco itself only emits outputs ([falco-talon][fa72]) |
| prevention/enforcement | ✗ | detection only: "designed to detect and alert" ([README.md#L9][fa73]) |

[fa1]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L1993-L2027
[fa2]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/events/sched_process_exit.bpf.c#L140-L175
[fa3]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2285
[fa4]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/events/sched_process_fork.bpf.c#L49
[fa5]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L1327
[fa6]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L852
[fa7]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L1123
[fa8]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L248
[fa9]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L1266
[fa10]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_thread.cpp#L31-L715
[fa11]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_thread.cpp#L231
[fa12]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L702
[fa13]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_thread.cpp#L110
[fa14]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L397
[fa15]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L42-L43
[fa16]: https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/userspace/falco/app/app.cpp#L32-L39
[fa17]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2079
[fa18]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L917
[fa19]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2070
[fa20]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L1085
[fa21]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2151
[fa22]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L20
[fa23]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L341
[fa24]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L986-L998
[fa25]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_fd.cpp#L33-L295
[fa26]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L355
[fa27]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L1316
[fa28]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L1198-L1214
[fa29]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L184
[fa30]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L1352
[fa31]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L205-L208
[fa32]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L218
[fa33]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L260-L294
[fa34]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L810
[fa35]: https://falco.org/docs/concepts/rules/fd-sip-name/
[fa36]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L1013
[fa37]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_fd.cpp#L43
[fa38]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_fd.cpp#L119
[fa39]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libpman/src/sc_set.c#L39-L200
[fa40]: https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1434
[fa41]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_event.cpp#L169
[fa42]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L193-L196
[fa43]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco_rules.yaml#L1063
[fa44]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L1368
[fa45]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L227
[fa46]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L1785-L1788
[fa47]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L493-L519
[fa48]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L145
[fa49]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L339
[fa50]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L146
[fa51]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L9
[fa52]: https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/
[fa53]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/krsi/README.md#L5-L9
[fa54]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-sandbox_rules.yaml#L1636
[fa55]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2399-L2402
[fa56]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_thread.cpp#L510
[fa57]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/docs/report.md#L1-L424
[fa58]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-sandbox_rules.yaml#L1618
[fa59]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L880
[fa60]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L2015
[fa61]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libsinsp/sinsp_filtercheck_user.cpp#L38
[fa62]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/README.md#L50
[fa63]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/README.md#L53-L66
[fa64]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/README.md#L82-L91
[fa65]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/README.md#L56
[fa66]: https://github.com/falcosecurity/rules/blob/e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428/rules/falco-incubating_rules.yaml#L678
[fa67]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/container/src/macros.h.in#L26-L29
[fa68]: https://github.com/falcosecurity/plugins/blob/9064e9d620538aebf32912fa00f6b9ef95d46a37/plugins/k8saudit/rules/k8s_audit_rules.yaml#L154
[fa69]: https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1-L1434
[fa70]: https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/falco.yaml#L1253-L1278
[fa71]: https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/shared_definitions/struct_definitions.h#L71-L95
[fa72]: https://github.com/falcosecurity/falco-talon
[fa73]: https://github.com/falcosecurity/falco/blob/6e13dff8fe017b5dfbb98708e20275ea2feba41f/README.md#L9

</details>

<details>
<summary>Cilium Tetragon (section: <a href="#cilium-tetragon">Tetragon</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | `process_exec`: binary, args, cwd; env via opt-in flag ([bpf_execve_event.h#L209][te1]) |
| exit | ✓ | `process_exit` signal + status; status-missing bug #902 open ([tetragon.proto#L319][te2], [issue 902][te3]) |
| fork/clone | partial | `wake_up_new_task` tracked in kernel; no exported fork event ([bpf_fork.c#L76][te4], [events.proto#L204][te5]) |
| credential change | ✓ | library policy: `__sys_set*id`, `security_capset`, `create_user_ns` kprobes ([privileges-raise.yaml#L67][te6]) |
| process injection | partial | `sys_ptrace` example only; no process_vm_writev or /proc/pid/mem ([sys_ptrace.yaml#L8][te7]) |
| fileless exec | ✓ | exec `binary_properties.file.inode.links=0` for memfd/deleted exe ([observability/_index.md#L287][te8]) |
| script/interpreter content | ✗ | matchBinaries sees interpreter; script content never captured ([selectors.md#L479][te9]) |
| TTY/interactive | partial | `tty_write` kprobe example; no tty field on exec ([tty.yaml#L7][te10]) |
| lineage | ✓ | `parent`, `parent_exec_id`, opt-in `ancestors`, `in_init_tree` ([tetragon.proto#L195][te11]) |
| executable hash | partial | IMA hash only on LSM hooks with `imaHash`; needs IMA ([selectors.md#L1554][te12]) |
| package ownership/signature | ✗ | no package/signature field in Process message ([tetragon.proto#L195][te11]) |
| sensitive-file read | ✓ | quickstart FIM: `security_file_permission` MAY_READ on /etc/shadow, /root/.ssh ([file_monitoring.yaml#L7][te13]) |
| write/modify | ✓ | same policy MAY_WRITE prefixes /etc, /bin, /usr/lib; truncate hook ([file_monitoring.yaml#L55][te14]) |
| create | partial | only `sys_openat` O_CREAT on /etc/passwd example (syscall, TOCTOU) ([openat_write.yaml#L11][te15]) |
| delete | partial | custom kprobe/LSM only; no shipped unlink policy ([hooks.md#L24][te16]) |
| rename | partial | custom kprobe/LSM only; no shipped rename policy ([hooks.md#L24][te16]) |
| chmod/chown/xattr | partial | custom kprobe/LSM only; no shipped policy ([hooks.md#L24][te16]) |
| link/symlink | ✓ | `sys_linkat` and `sys_symlinkat` example policies ([hardlink-observe.yaml#L12][te17], [symlink-observe.yaml#L12][te18]) |
| FIM hashing | partial | IMA hash on file_open-type LSM hooks only; needs IMA ([selectors.md#L1554][te19]) |
| persistence locations | partial | FIM write prefixes /etc, /root/.ssh; misses ~/.ssh, user crontabs ([file_monitoring.yaml#L55][te20]) |
| dropped-file exec | partial | /tmp exec and deleted-exe flags; no write→exec correlation ([observability/_index.md#L339][te21]) |
| library load / mmap exec | ✓ | `process_loader` (path, build id) via library policy `loader: true` ([library.yaml#L9][te22], [bpf_loader.c#L66][te23]) |
| TCP connect/accept/listen | ✓ | `tcp_connect`/accept/`inet_csk_listen_start` example policies with sock tuple ([tcp-connect.yaml#L7][te24], [tcp-listen.yaml#L44][te25]) |
| UDP flows | partial | per-skb `__cgroup_bpf_run_filter_skb` example; no flow state ([datagram.yaml#L7][te26]) |
| DNS query/answer | ✗ | no DNS event in complete event list; no DNS parsing ([events.proto#L204][te5]) |
| raw/packet sockets | partial | custom `sock` family/type/protocol filters; none shipped ([argument_types.md#L119][te27]) |
| unix sockets | partial | `sockaddr_un` arg type exists; no shipped policy ([argument_types.md#L293][te28]) |
| IPv6 | ✓ | sock/skb parsing and SAddr/DAddr CIDR ops support IPv6 ([selectors.md#L2151][te29]) |
| NAT post-translation tuple | ✗ | socket's own tuple only; no conntrack fields [INFERENCE] ([tetragon.proto#L338][te30]) |
| HTTP/TLS metadata (SNI) | ✗ | not in OSS event list; HTTP/TLS visibility is Isovalent Enterprise ([events.proto#L204][te5], [Enterprise 1.13 blog][te31]) |
| flow volume | partial | `tcp_sendmsg` size per call; no byte counters ([tcp-connect.yaml#L17][te32]) |
| bind | partial | listen via `inet_csk_listen_start` example; bind() itself custom ([tcp-listen.yaml#L44][te25]) |
| module load | ✓ | library: `security_kernel_module_request`, `security_kernel_read_file` kprobes ([modules.yaml#L10][te33]) |
| BPF load | ✓ | library: `bpf_check` with `bpf_attr` ProgType/InsnCnt ([bpf.yaml#L7][te34]) |
| kprobe/perf_event_open | ✓ | library: `security_perf_event_alloc` with `perf_event` arg ([bpf.yaml#L12][te35]) |
| mount/umount | partial | `sys_mount`, `sys_pivot_root` examples; no umount ([sys_mount.yaml#L8][te36]) |
| namespaces | ✓ | library `create_user_ns`; `sys_setns` use-case; matchNamespaceChanges ([privileges-raise.yaml#L106][te37], [namespace-access.md#L51][te38]) |
| kexec | partial | custom kprobe/LSM only; none shipped ([hooks.md#L24][te16]) |
| sysctl write | partial | custom policy only; /proc/sys not in shipped FIM prefixes ([file_monitoring.yaml#L55][te20]) |
| time change | partial | `sys_clock_settime` example only; no settimeofday/adjtimex ([sys_clock_settime.yaml#L8][te39]) |
| keyring | partial | custom kprobe/LSM only; none shipped ([hooks.md#L24][te16]) |
| io_uring | partial | custom hooks (io_uring tracepoints available); none shipped ([hooks.md#L171][te40]) |
| userfaultfd | partial | custom kprobe/LSM only; none shipped ([hooks.md#L24][te16]) |
| capability use | ✓ | `cap_capable` kprobe example policy ([creds-capability-usage.yaml#L18][te41]) |
| login/logout | ✗ | no login/PAM event in complete event list ([events.proto#L204][te5]) |
| sudo/su | ✓ | `process_exec` of sudo/su with setuid `privileges_changed` ([observability/_index.md#L62][te42]) |
| user/group changes | partial | only as FIM writes under /etc prefix ([file_monitoring.yaml#L55][te20]) |
| loginuid/session | partial | `auid` on every process; no session id ([bpf_execve_event.h#L248][te43]) |
| container id | ✓ | `docker` / `pod.container.id` from cgroup name or cgidmap ([exec_linux.go#L39][te44]) |
| image | ✓ | `pod.container.image{id,name}` from pod informer ([events.md#L41][te45]) |
| pod/namespace/labels | ✓ | `pod.namespace`, name, `pod_labels`, workload; annotations opt-in ([tetragon.proto#L50][te46]) |
| privileged flag | ✓ | `pod.container.security_context.privileged` ([podinfo.go#L42][te47]) |
| runtime events | ✗ | no container lifecycle event in complete event list ([events.proto#L204][te5]) |
| K8s audit | ✗ | no K8s audit event in complete event list ([events.proto#L204][te5]) |
| tamper protection | ✗ | threat model: root can unload/replace programs ([threat-model/_index.md#L307][te48]) |
| loss/health reporting | ✓ | per-opcode/errno kernel send failures, ringbuf/queue lost metrics ([metrics.md#L24][te49]) |
| response actions | ✓ | in-kernel Sigkill/Signal/Override/NotifyEnforcer; userspace GetUrl/DnsLookup ([selectors.md#L1019][te50]) |
| prevention/enforcement | ✓ | Override on syscalls/`security_` hooks and LSM hooks ([selectors.md#L1138][te51]) |

[te1]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_event.h#L209-L274
[te2]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L319-L330
[te3]: https://github.com/cilium/tetragon/issues/902
[te4]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_fork.c#L76-L149
[te5]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/events.proto#L204-L224
[te6]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/privileges/privileges-raise.yaml#L67-L207
[te7]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/sys_ptrace.yaml#L8
[te8]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/policy-library/observability/_index.md#L287-L377
[te9]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L479-L504
[te10]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/tty.yaml#L7
[te11]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L195-L308
[te12]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1554-L1603
[te13]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/quickstart/file_monitoring.yaml#L7-L54
[te14]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/quickstart/file_monitoring.yaml#L55-L148
[te15]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/openat_write.yaml#L11-L36
[te16]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L24-L26
[te17]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/hardlink-observe.yaml#L12
[te18]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/symlink-observe.yaml#L12
[te19]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1554-L1570
[te20]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/quickstart/file_monitoring.yaml#L55-L75
[te21]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/policy-library/observability/_index.md#L339-L377
[te22]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/library.yaml#L9
[te23]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_loader.c#L66-L140
[te24]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/tcp-connect.yaml#L7-L23
[te25]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/tcp-listen.yaml#L44-L52
[te26]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/datagram.yaml#L7-L15
[te27]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/argument_types.md#L119-L126
[te28]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/argument_types.md#L293-L300
[te29]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L2151-L2154
[te30]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L338-L350
[te31]: https://isovalent.com/blog/post/isovalent-enterprise-for-tetragon-1-13/
[te32]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/tcp-connect.yaml#L17-L23
[te33]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/modules.yaml#L10-L32
[te34]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/bpf.yaml#L7-L11
[te35]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/bpf.yaml#L12-L16
[te36]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/sys_mount.yaml#L8
[te37]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/policylibrary/privileges/privileges-raise.yaml#L106-L116
[te38]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/use-cases/process-lifecycle/namespace-access.md#L51-L78
[te39]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/sys_clock_settime.yaml#L8
[te40]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/hooks.md#L171-L193
[te41]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml#L18
[te42]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/policy-library/observability/_index.md#L62-L124
[te43]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_execve_event.h#L248
[te44]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/exec/exec_linux.go#L39-L80
[te45]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/events.md#L41-L53
[te46]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/api/v1/tetragon/tetragon.proto#L50-L68
[te47]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/process/podinfo.go#L42
[te48]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/threat-model/_index.md#L307-L318
[te49]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/reference/metrics.md#L24-L32
[te50]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1019-L1041
[te51]: https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/tracing-policy/selectors.md#L1138-L1188

</details>

<details>
<summary>Aqua Tracee (section: <a href="#aqua-tracee">Tracee</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | `sched_process_exec`: argv read from new mm, env (opt), pwd ([tracee.bpf.c#L1492-L1541][tr1]) |
| exit | ✓ | `sched_process_exit`: exit_code, signal_code, process_group_exit ([tracee.bpf.c#L1544-L1602][tr2]) |
| fork/clone | ✓ | `sched_process_fork`: parent/child tids, pids, start times ([tracee.bpf.c#L622-L777][tr3]) |
| credential change | ✓ | `commit_creds` old/new uid/gid/caps, emitted only on change ([tracee.bpf.c#L2432-L2513][tr4]) |
| process injection | ✓ | `ptrace`/`process_vm_writev` events; TRC-1024 /proc/pid/mem injection ([proc_mem_code_injection.go#L28-L32][tr5]) |
| fileless exec | ✓ | TRC-105 `fileless_execution`: exec from memfd:, /dev/shm, /run/shm ([fileless_execution.go#L22][tr6]) |
| script/interpreter content | partial | only `interp`/`interpreter_pathname` fields on exec; no script content ([core.go#L12662][tr7]) |
| TTY/interactive | partial | `stdin_type`/`stdin_path` on exec; no tty/session field ([tracee.bpf.c#L1513-L1523][tr8]) |
| lineage | ✓ | userspace process tree (LRU, procfs-seeded) with ancestry ([proctree.go#L38-L95][tr9]) |
| executable hash | ✓ | `--enrichment executable-hash`: sha256 of executed file, cached ([processor_funcs.go#L191-L211][tr10]) |
| package ownership/signature | ✗ | no package/signature enrichment in the complete event definitions ([core.go#L310-L15822][tr11]) |
| sensitive-file read | ✓ | `security_file_open` with in-kernel pathname exact/prefix/suffix filters ([filtering.h#L356-L455][tr12]) |
| write/modify | ✓ | `file_modification` once per open; `magic_write`; `vfs_write` ([tracee.bpf.c#L4910-L5069][tr13]) |
| create | partial | no inode_create hook; only open flags, creat syscall, mknod ([probe_group.go#L226-L244][tr14]) |
| delete | ✓ | `security_inode_unlink` (default set): pathname, inode, dev ([core.go#L13036][tr15]) |
| rename | ✓ | `security_inode_rename`: old_path, new_path ([core.go#L14270][tr16]) |
| chmod/chown/xattr | ✓ | `chmod_common` kprobe; chown/xattr as syscall events only ([core.go#L14760][tr17]) |
| link/symlink | ✓ | `security_inode_symlink`; hard links via link/linkat syscall events ([core.go#L13327][tr18]) |
| FIM hashing | ✗ | no hashing of modified files; only written-data capture artifacts ([artifacts.1.md#L20-L33][tr19]) |
| persistence locations | partial | detectors for cron, rc.d, sudoers, ld.so.preload; no systemd/ssh/PAM ([security-events.md#L54-L87][tr20]) |
| dropped-file exec | partial | TRC-1022 flags ELF written in container; exec not correlated ([dropped_executable.go#L22-L37][tr21]) |
| library load / mmap exec | ✓ | `shared_object_loaded`, `security_mmap_file`, `symbols_loaded` ([core.go#L13857][tr22]) |
| TCP connect/accept/listen | ✓ | `security_socket_connect/accept/listen`, derived `net_tcp_connect` ([core.go#L13076-L13156][tr23]) |
| UDP flows | partial | per-packet `net_packet_udp`; no UDP flow aggregation ([core.go#L15214][tr24]) |
| DNS query/answer | ✓ | `net_packet_dns_request/response`, full packet parsed in userspace ([core.go#L15355-L15373][tr25]) |
| raw/packet sockets | partial | `security_socket_create` family/type only; packet events inet-only ([tracee.bpf.c#L5873-L5887][tr26]) |
| unix sockets | ✓ | `security_socket_connect` records `sockaddr_un`; TRC-1019 docker.sock ([tracee.bpf.c#L2763-L2769][tr27]) |
| IPv6 | ✓ | `net_packet_ipv6`; `sockaddr_in6` in socket events ([core.go#L15134][tr28]) |
| NAT post-translation tuple | ✗ | no conntrack/NAT lookup; root cgroup_skb sees pre-SNAT [INFERENCE] ([tracee.bpf.c#L6834-L6844][tr29]) |
| HTTP/TLS metadata (SNI) | partial | plaintext `net_packet_http_request/response` only; no TLS/SNI ([core.go#L15432][tr30]) |
| flow volume | ✗ | flow byte/packet counters commented out in `netflowvalue` ([network.h#L59-L69][tr31]) |
| bind | ✓ | `security_socket_bind`: sockfd, local_addr ([core.go#L13156][tr32]) |
| module load | ✓ | `module_load` tracepoint, `do_init_module`; TRC-1017 ([core.go#L14081][tr33]) |
| BPF load | ✓ | `security_bpf`, `security_bpf_prog` (type, name, helpers, id), `bpf_attach` ([core.go#L14534][tr34]) |
| kprobe/perf_event_open | ✓ | `kprobe_attach`, `bpf_attach`, `perf_event_open` syscall event ([core.go#L13635][tr35]) |
| mount/umount | ✓ | `security_sb_mount`, `security_sb_umount`; TRC-1014 ([core.go#L13194-L13214][tr36]) |
| namespaces | ✓ | `switch_task_ns` (changed ns ids); unshare/setns syscall events ([tracee.bpf.c#L2515-L2563][tr37]) |
| kexec | ✓ | `kexec_load`/`kexec_file_load` syscall events (TOCTOU-prone args) ([core.go#L7005][tr38]) |
| sysctl write | partial | no sysctl event; detectors match /proc/sys paths via file_open ([core_pattern_modification.go#L23-L30][tr39]) |
| time change | ✓ | `security_settime64`: tv_sec, tv_nsec ([core.go#L14741][tr40]) |
| keyring | ✓ | `add_key`, `request_key`, `keyctl` syscall events only ([core.go#L7123][tr41]) |
| io_uring | partial | only io_uring_setup/enter/register syscall events; op-level not covered ([core.go#L9575][tr42]) |
| userfaultfd | ✓ | `userfaultfd` syscall event ([core.go#L9200][tr43]) |
| capability use | ✓ | `cap_capable` (cap), skips CAP_OPT_NOAUDIT ([tracee.bpf.c#L2565-L2584][tr44]) |
| login/logout | ✗ | no PAM/utmp/sshd event in the complete event definitions ([core.go#L310-L15822][tr11]) |
| sudo/su | partial | only via `commit_creds` + exec; TRC-1028 covers sudoers edits ([sudoers_modification.go#L23-L33][tr45]) |
| user/group changes | partial | only user-written `security_file_open` data filters on /etc/passwd ([rules.md#L330-L348][tr46]) |
| loginuid/session | ✗ | task context carries uid only; no loginuid/sessionid ([types.h#L10-L27][tr47]) |
| container id | ✓ | parsed from cgroup path; `container_create` events ([containers.go#L327-L330][tr48]) |
| image | ✓ | image name and digest from runtime API ([runtime.go#L18-L28][tr49]) |
| pod/namespace/labels | partial | pod name/namespace/uid; labels not exported ([containerd.go#L94-L103][tr50]) |
| privileged flag | ✗ | container `EnrichResult` has no privileged field ([runtime.go#L18-L28][tr49]) |
| runtime events | ✓ | `container_create`, `container_remove`, `existing_container` ([core.go#L13558-L13598][tr51]) |
| K8s audit | ✗ | no K8s audit source in the complete event definitions ([core.go#L310-L15822][tr11]) |
| tamper protection | partial | detects bpf/kprobe/syscall-table hooks; root can detach Tracee ([security-model.md#L40-L45][tr52]) |
| loss/health reporting | ✓ | Prometheus lost-event counters, heartbeat, /healthz ([stats.go#L223-L248][tr53]) |
| response actions | ✗ | policy actions limited to `log`/`print` ([policy_file.go#L139-L150][tr54]) |
| prevention/enforcement | ✗ | detection only; BPF-LSM described as future enforcement groundwork ([lsm-support.md#L84][tr55]) |

[tr1]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L1492-L1541
[tr2]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L1544-L1602
[tr3]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L622-L777
[tr4]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2432-L2513
[tr5]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/proc_mem_code_injection.go#L28-L32
[tr6]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/fileless_execution.go#L22
[tr7]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L12662
[tr8]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L1513-L1523
[tr9]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/process/proctree.go#L38-L95
[tr10]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/processor_funcs.go#L191-L211
[tr11]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L310-L15822
[tr12]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/filtering.h#L356-L455
[tr13]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L4910-L5069
[tr14]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/probes/probe_group.go#L226-L244
[tr15]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13036
[tr16]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L14270
[tr17]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L14760
[tr18]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13327
[tr19]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/flags/artifacts.1.md#L20-L33
[tr20]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/events/builtin/security-events.md#L54-L87
[tr21]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/dropped_executable.go#L22-L37
[tr22]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13857
[tr23]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13076-L13156
[tr24]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L15214
[tr25]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L15355-L15373
[tr26]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L5873-L5887
[tr27]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2763-L2769
[tr28]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L15134
[tr29]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L6834-L6844
[tr30]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L15432
[tr31]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/network.h#L59-L69
[tr32]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13156
[tr33]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L14081
[tr34]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L14534
[tr35]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13635
[tr36]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13194-L13214
[tr37]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2515-L2563
[tr38]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L7005
[tr39]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/core_pattern_modification.go#L23-L30
[tr40]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L14741
[tr41]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L7123
[tr42]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L9575
[tr43]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L9200
[tr44]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L2565-L2584
[tr45]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/detectors/sudoers_modification.go#L23-L33
[tr46]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/policies/rules.md#L330-L348
[tr47]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/types.h#L10-L27
[tr48]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/container/containers.go#L327-L330
[tr49]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/container/runtime/runtime.go#L18-L28
[tr50]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/datastores/container/runtime/containerd.go#L94-L103
[tr51]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/events/core.go#L13558-L13598
[tr52]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/security-model.md#L40-L45
[tr53]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/metrics/stats.go#L223-L248
[tr54]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/policy/v1beta1/policy_file.go#L139-L150
[tr55]: https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/docs/docs/install/lsm-support.md#L84

</details>

<details>
<summary>Datadog Workload Protection (CWS) (section: <a href="#datadog-workload-protection-formerly-cloud-workload-security">Datadog</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | `exec` argv/envs (env values allow-listed); no cwd field ([linux_expressions.md#L814][dd1], [system_probe_settings.go#L427][dd2]) |
| exit | ✓ | `exit.code`, `exit.cause` EXITED/SIGNALED/COREDUMPED ([linux_expressions.md#L971][dd3]) |
| fork/clone | partial | fork tracked internally (`ForkEventType`), not a rule-able event ([events.go#L65][dd4], [linux_expressions.md#L32][dd5]) |
| credential change | ✓ | `setuid`, `setgid`, `capset` events from `commit_creds` ([linux_expressions.md#L2328][dd6], [event_types.go#L296][dd7]) |
| process injection | partial | `ptrace` event + `ptrace_injection` rule; no process_vm_writev, /proc/pid/mem ([linux_expressions.md#L1425][dd8], [default.policy#L3887][dd9]) |
| fileless exec | ✓ | `memfd_create_v2` default rule: exec of memfd, empty path ([default.policy#L2802][dd10]) |
| script/interpreter content | partial | `process.interpreter.file.*` path only; no script content ([linux_expressions.md#L401][dd11]) |
| TTY/interactive | ✓ | `process.tty_name`; `interactive_shell_in_container_v2` rule ([linux_expressions.md#L531][dd12], [default.policy#L2349][dd13]) |
| lineage | ✓ | `process.ancestors.*`, `process.parent.*` from userspace process tree ([linux_expressions.md#L248][dd14], [resolver_ebpf.go#L212][dd15]) |
| executable hash | ✓ | `process.file.hashes` sha1/sha256/ssdeep, lazy, ≤5 MiB, 500/s ([linux_expressions.md#L351][dd16], [system_probe_settings.go#L296][dd17]) |
| package ownership/signature | partial | `file.package.*` needs `sbom.enabled` (default false); no signature check ([system_probe_settings.go#L313][dd18], [linux_expressions.md#L362][dd19]) |
| sensitive-file read | ✓ | `open` + `credential_category_*` default rules ([default.policy#L798][dd20], [linux_expressions.md#L1339][dd21]) |
| write/modify | ✓ | `open.flags` write flags; `fim.write.file.*` meta-fields ([linux_expressions.md#L74][dd22]) |
| create | ✓ | `open` with O_CREAT, `mkdir` event ([linux_expressions.md#L1211][dd23], [linux_expressions.md#L1339][dd21]) |
| delete | ✓ | `unlink`, `rmdir` events ([linux_expressions.md#L2803][dd24], [linux_expressions.md#L1887][dd25]) |
| rename | ✓ | `rename.file.*` and `rename.file.destination.*` ([linux_expressions.md#L1823][dd26]) |
| chmod/chown/xattr | ✓ | `chmod`, `chown`, `setxattr`, `removexattr` events ([linux_expressions.md#L39][dd27]) |
| link/symlink | partial | `link` is hard link only; no symlink-creation event ([linux_expressions.md#L46][dd28]) |
| FIM hashing | ✓ | `hash` action and `*.file.hashes` fields ([variables_and_actions][dd29]) |
| persistence locations | ✓ | default rules: cron, systemd, profiles, ssh keys, PAM, ld.so.preload ([default.policy#L1810][dd30], [default.policy#L2081][dd31]) |
| dropped-file exec | ✓ | `exec_new_file` rule (recent ctime, upper layer; container-scoped) ([default.policy#L2123][dd32]) |
| library load / mmap exec | ✓ | `mmap.file.*` + `mmap.protection` PROT_EXEC; `ld_audit` rule ([linux_expressions.md#L1250][dd33], [default.policy#L2723][dd34]) |
| TCP connect/accept/listen | ✓ | `connect`, `accept`, `bind` events; no separate `listen` event ([linux_expressions.md#L32][dd35]) |
| UDP flows | partial | UDP `connect` + opt-in `network_flow_monitor`; unconnected sendto unseen [INFERENCE] ([linux_expressions.md#L1317][dd36], [system_probe_settings.go#L387][dd37]) |
| DNS query/answer | ✓ | `dns.question.*`, `dns.response.{code,ips,cnames}` from TC ([linux_expressions.md#L783][dd38]) |
| raw/packet sockets | ✓ | `socket.{domain,type,protocol}`; SO_ATTACH_FILTER default rule ([linux_expressions.md#L2740][dd39], [default.policy#L1220][dd40]) |
| unix sockets | partial | `connect.addr.family` only; AF_UNIX path not captured ([connect.h#L124][dd41]) |
| IPv6 | ✓ | connect/bind/accept parse AF_INET6 addresses ([connect.h#L132][dd42]) |
| NAT post-translation tuple | partial | conntrack map used for pid attribution, not exposed in events ([flow.h#L159][dd43]) |
| HTTP/TLS metadata (SNI) | partial | IMDS HTTP fields, `packet.tls.version`; no SNI ([linux_expressions.md#L1077][dd44], [linux_expressions.md#L1379][dd45]) |
| flow volume | ✓ | `network_flow_monitor` packets/bytes per flow (opt-in, default off) ([linux_expressions.md#L1317][dd36], [system_probe_settings.go#L387][dd37]) |
| bind | ✓ | `bind.addr.*`, `bind.protocol` ([linux_expressions.md#L562][dd46]) |
| module load | ✓ | `load_module` incl. `loaded_from_memory`; default rules ([linux_expressions.md#L1171][dd47], [default.policy#L2592][dd48]) |
| BPF load | ✓ | `bpf.cmd`, `bpf.prog.helpers`; probe_write_user default rule ([linux_expressions.md#L575][dd49], [default.policy#L1196][dd50]) |
| kprobe/perf_event_open | partial | only `bpf.prog.attach_type`; perf_event_open needs custom `ondemand` hook ([linux_expressions.md#L575][dd49], [ruleset.go#L169][dd51]) |
| mount/umount | partial | `mount` event (experimental); umount internal only ([linux_expressions.md#L1287][dd52]) |
| namespaces | partial | `unshare` event + mntns/netns fields; setns/clone flags not events ([linux_expressions.md#L2851][dd53]) |
| kexec | partial | no event; only via custom `ondemand` syscall hook ([ruleset.go#L169][dd51]) |
| sysctl write | ✓ | `sysctl.{action,name,value,old_value}` via cgroup/sysctl ([linux_expressions.md#L2788][dd54]) |
| time change | partial | no event; only via custom `ondemand` hook ([ruleset.go#L169][dd51]) |
| keyring | partial | no event; only via custom `ondemand` hook ([ruleset.go#L169][dd51]) |
| io_uring | partial | io_uring ops mapped to file/net events (`event.async`); no io_uring event ([event_types.go#L374][dd55]) |
| userfaultfd | partial | no event; only via custom `ondemand` hook ([ruleset.go#L169][dd51]) |
| capability use | partial | `capabilities` event experimental; monitoring off by default ([linux_expressions.md#L591][dd56], [system_probe_settings.go#L416][dd57]) |
| login/logout | partial | SSH session context from auth log; no logout/PAM event ([resolver_linux.go#L496][dd58], [linux_expressions.md#L542][dd59]) |
| sudo/su | ✓ | `exec` of sudo/su plus `setuid` event ([linux_expressions.md#L2328][dd6]) |
| user/group changes | partial | exec-based rules (usermod/useradd); no account-db event ([default.policy#L5170][dd60]) |
| loginuid/session | ✓ | `process.auid`, `process.sid`, `user_session.*` fields ([linux_expressions.md#L317][dd61], [linux_expressions.md#L529][dd62]) |
| container id | ✓ | `process.container.id` from cgroup path pattern ([linux_expressions.md#L335][dd63], [resolver.go#L188][dd64]) |
| image | ✓ | `container.tags` image_name/image_tag via tagger ([linux_expressions.md#L337][dd65], [resolver.go#L87][dd66]) |
| pod/namespace/labels | ✓ | `container.pod_uid`; orchestrator-cardinality tagger tags ([linux_expressions.md#L336][dd67], [resolver.go#L93][dd68]) |
| privileged flag | partial | no field; `deploy_priv_container` infers from CAP_SYS_ADMIN ([default.policy#L1969][dd69]) |
| runtime events | partial | `container.created_at`, cgroup tracking; no start/stop event ([linux_expressions.md#L333][dd70], [linux_expressions.md#L32][dd5]) |
| K8s audit | ✗ | not in agent; only `kubectl exec` identity via webhook ([k8s remote access blog][dd71]) |
| tamper protection | partial | detects BPF abuse; reads kprobe-disable knobs; no self-protection found ([default.policy#L1196][dd50], [LPC 2023 slides][dd72]) |
| loss/health reporting | ✓ | per-type lost counters, self-test, heartbeat, abnormal_path events ([metrics.go#L138][dd73], [custom.go#L24][dd74]) |
| response actions | ✓ | kill process/container/cgroup, network_filter drop, hash, coredump ([variables_and_actions][dd29]) |
| prevention/enforcement | partial | TC packet drop; kill is post-hoc, no LSM deny ([response actions blog][dd75], [process.h#L11][dd76]) |

[dd1]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L814-L948
[dd2]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L427-L439
[dd3]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L971-L977
[dd4]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/secl/model/events.go#L65
[dd5]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L32-L73
[dd6]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L2328-L2340
[dd7]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L296
[dd8]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1425
[dd9]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L3887
[dd10]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2802
[dd11]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L401
[dd12]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L531
[dd13]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2349
[dd14]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L248
[dd15]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/process/resolver_ebpf.go#L212-L418
[dd16]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L351
[dd17]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L296-L301
[dd18]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L313
[dd19]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L362
[dd20]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L798
[dd21]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1339
[dd22]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L74-L124
[dd23]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1211
[dd24]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L2803
[dd25]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1887
[dd26]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1823
[dd27]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L39-L65
[dd28]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L46
[dd29]: https://docs.datadoghq.com/security/workload_protection/detect_and_monitor/agent_rules/variables_and_actions/
[dd30]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L1810
[dd31]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2081
[dd32]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2123
[dd33]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1250
[dd34]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2723
[dd35]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L32-L41
[dd36]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1317
[dd37]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L387
[dd38]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L783-L813
[dd39]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L2740
[dd40]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L1220
[dd41]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/connect.h#L124-L136
[dd42]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/connect.h#L132-L136
[dd43]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/network/flow.h#L159-L199
[dd44]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1077
[dd45]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1379
[dd46]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L562
[dd47]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1171
[dd48]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L2592
[dd49]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L575-L590
[dd50]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L1196
[dd51]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/secl/rules/ruleset.go#L169-L240
[dd52]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L1287-L1306
[dd53]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L2851
[dd54]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L2788
[dd55]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L374-L393
[dd56]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L591
[dd57]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/config/setup/generatedsettings/system_probe_settings.go#L416
[dd58]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/usersessions/resolver_linux.go#L496-L535
[dd59]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L542
[dd60]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L5170
[dd61]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L317
[dd62]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L529
[dd63]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L335
[dd64]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/cgroup/resolver.go#L188-L216
[dd65]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L337
[dd66]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/tags/resolver.go#L87-L110
[dd67]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L336
[dd68]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/resolvers/tags/resolver.go#L93
[dd69]: https://github.com/DataDog/security-agent-policies/blob/d66bad47b7b11308074abdfac60c90e1a3e60d86/runtime/default.policy#L1969
[dd70]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/docs/cloud-workload-security/linux_expressions.md#L333
[dd71]: https://www.datadoghq.com/blog/workload-protection-kubernetes-remote-access/
[dd72]: https://lpc.events/event/17/contributions/1582/attachments/1328/2673/Troubles%20and%20Tidbits%20from%20Datadog%E2%80%99s%20eBPF%20Journey%20v2.pdf
[dd73]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/metrics/metrics.go#L138-L178
[dd74]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/events/custom.go#L24-L84
[dd75]: https://www.datadoghq.com/blog/stop-runtime-threats-with-workload-protection-response-actions/
[dd76]: https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/process.h#L11-L22

</details>

<details>
<summary>KubeArmor (section: <a href="#kubearmor">KubeArmor</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | `SYS_EXECVE` Resource=path+≤20 argv, Cwd; no env ([systemMonitor.go#L960-L996][ka1]) |
| exit | ✗ | `do_exit` kprobe only cleans pid tree, no log ([systemMonitor.go#L1143-L1145][ka2]) |
| fork/clone | ✗ | fork tracepoint only propagates exec_id ([system_monitor.c#L1250-L1265][ka3]) |
| credential change | partial | setuid/setgid syscall logs only; no setres*/capset ([logUpdate.go#L285-L294][ka4]) |
| process injection | partial | `SYS_PTRACE` log; protectProc preset for /proc/pid access; no process_vm_writev ([protectproc.bpf.c#L34-L112][ka5]) |
| fileless exec | partial | filelessExec preset (memfd:, /dev/shm), BPF-LSM only; no deleted-exe ([filelessexec.bpf.c#L42-L123][ka6]) |
| script/interpreter content | ✗ | no hook reads script bodies in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| TTY/interactive | ✓ | `TTY` field from `signal->tty->name` on every record ([system_monitor.c#L1127-L1138][ka9]) |
| lineage | partial | PPID/ParentProcessName + kubectl-exec ExecID; no ancestor chain ([processTree.go#L212-L279][ka10]) |
| executable hash | partial | ProcessHash via `bpf_ima_file_hash`, off by default, needs IMA ([ima_hash.bpf.c#L14-L36][ka11]) |
| package ownership/signature | ✗ | no such field in complete Alert proto ([kubearmor.proto#L41-L96][ka12]) |
| sensitive-file read | ✓ | `SYS_OPENAT` File log with flags (file visibility off in Helm default); policy audit via `lsm/file_open` ([enforcer.bpf.c#L740-L745][ka13]) |
| write/modify | partial | open flags only; per-write only for policy paths (`lsm/file_permission`) ([enforcer.bpf.c#L747-L759][ka14]) |
| create | partial | O_CREAT flag on openat; mknod/mkdir only as BPF-LSM policy alerts ([enforcer_path.bpf.c#L8-L21][ka15]) |
| delete | ✓ | `SYS_UNLINK/UNLINKAT/RMDIR` File logs ([logUpdate.go#L187-L230][ka16]) |
| rename | partial | `lsm/path_rename` policy alerts only; no monitor event ([enforcer_path.bpf.c#L41-L58][ka17]) |
| chmod/chown/xattr | partial | chown/fchownat logs; chmod policy-only; no xattr ([logUpdate.go#L234-L281][ka18]) |
| link/symlink | partial | `lsm/path_link`/`path_symlink` policy alerts only ([enforcer_path.bpf.c#L23-L39][ka19]) |
| FIM hashing | ✗ | file_open IMA hashing commented out for latency ([ima_hash.bpf.c#L38-L57][ka20]) |
| persistence locations | partial | library "detect-access-to-cronjob-files" policy; others user-written ([hardening_guide.md#L156-L160][ka21]) |
| dropped-file exec | ✗ | no write→exec correlation; only path-based exec rules ([security_policy_specification.md#L177][ka22]) |
| library load / mmap exec | partial | anonymousMapExec preset (anon PROT_EXEC); file-backed libs not reported ([anonmapexec.bpf.c#L92-L140][ka23]) |
| TCP connect/accept/listen | ✓ | `tcp_connect`/`inet_csk_accept` kprobes, `SYS_LISTEN` ([logUpdate.go#L403-L424][ka24]) |
| UDP flows | partial | socket/connect/bind syscalls only; no per-datagram/sendto ([systemMonitor.go#L599][ka25]) |
| DNS query/answer | partial | query name/qtype via `udp_send_skb`, IPv4/53 only; no answers ([system_monitor.c#L2384-L2446][ka26]) |
| raw/packet sockets | ✓ | `SYS_SOCKET` domain/type (AF_PACKET, SOCK_RAW decoded) ([syscallParser.go#L481][ka27]) |
| unix sockets | ✓ | connect/bind sockaddr decodes `sun_path` ([syscallParser.go#L159-L180][ka28]) |
| IPv6 | ✓ | `_TCP_CONNECT_v6`/`_TCP_ACCEPT_v6` ([system_monitor.c#L2176-L2182][ka29]) |
| NAT post-translation tuple | ✗ | socket-level tuple at `tcp_connect` only ([system_monitor.c#L2164-L2189][ka30]) |
| HTTP/TLS metadata (SNI) | ✗ | no L7 hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| flow volume | partial | nftables quota enforcement (KubeArmorNetworkPolicy), no per-flow byte telemetry ([network_bandwidth_quota.md#L1-L3][ka31]) |
| bind | ✓ | `SYS_BIND` with sockaddr ([logUpdate.go#L481-L496][ka32]) |
| module load | ✗ | no init_module hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| BPF load | ✗ | no bpf() hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| kprobe/perf_event_open | ✗ | no such hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| mount/umount | ✓ | `SYS_MOUNT`/`SYS_UMOUNT` Syscall logs ([logUpdate.go#L297-L337][ka33]) |
| namespaces | partial | setns used only to tag kubectl-exec ExecID; no ns events ([system_monitor.c#L1203-L1235][ka34]) |
| kexec | ✗ | no such hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| sysctl write | partial | only BPF-LSM file policy on /proc/sys; monitor skips /proc,/sys ([system_monitor.c#L1834-L1846][ka35]) |
| time change | ✗ | no such hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| keyring | ✗ | no such hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| io_uring | ✗ | no io_uring hook in attach lists; LSM enforcement still applies [INFERENCE] ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| userfaultfd | ✗ | no such hook in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| capability use | partial | `lsm/capable` alerts only for matchCapabilities policies ([enforcer.bpf.c#L760-L780][ka36]) |
| login/logout | ✗ | no PAM/sshd source in complete monitor/LSM attach lists ([systemMonitor.go#L599-L604][ka7], [bpflsm/enforcer.go#L150-L270][ka8]) |
| sudo/su | partial | exec + setuid/setgid logs; no PAM/auth context ([logUpdate.go#L285-L294][ka4]) |
| user/group changes | partial | only user-written file policies on /etc/passwd etc. ([security_policy_specification.md#L219-L246][ka37]) |
| loginuid/session | ✗ | UID only; UserName lookup host-only ([feeder.go#L763-L766][ka38]) |
| container id | ✓ | ContainerID/Name via (pidns,mntns) map ([processTree.go#L24-L35][ka39]) |
| image | ✓ | ContainerImage ([kubearmor.proto#L53-L55][ka40]) |
| pod/namespace/labels | ✓ | PodName, NamespaceName, Labels, Owner ([kubearmor.proto#L48-L51][ka41]) |
| privileged flag | ✗ | tracked internally only; absent from Log/Alert ([containerdHandler.go#L217-L219][ka42]) |
| runtime events | ✗ | containerd/CRI-O events consumed internally, not emitted ([containerdHandler.go#L106-L118][ka43]) |
| K8s audit | ✗ | no audit-log input; no such fields in Alert proto ([kubearmor.proto#L41-L96][ka12]) |
| tamper protection | ✗ | "tamper" absent from code/docs; own namespace untracked by default ([config.go#L188][ka44]) |
| loss/health reporting | partial | gRPC health check; AlertThreshold event; perf/ringbuf loss not exported ([systemMonitor.go#L792-L795][ka45]) |
| response actions | ✗ | no kill/isolate; only inline LSM denial ([enforcer.bpf.c#L429-L466][ka46]) |
| prevention/enforcement | ✓ | BPF-LSM/AppArmor/SELinux Allow/Audit/Block; nftables network policy ([enforcer.bpf.c#L429-L466][ka46]) |

[ka1]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L960-L996
[ka2]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L1143-L1145
[ka3]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1250-L1265
[ka4]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L285-L294
[ka5]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/protectproc.bpf.c#L34-L112
[ka6]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/filelessexec.bpf.c#L42-L123
[ka7]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L599-L604
[ka8]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/enforcer/bpflsm/enforcer.go#L150-L270
[ka9]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1127-L1138
[ka10]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/processTree.go#L212-L279
[ka11]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/ima_hash.bpf.c#L14-L36
[ka12]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/protobuf/kubearmor.proto#L41-L96
[ka13]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L740-L745
[ka14]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L747-L759
[ka15]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer_path.bpf.c#L8-L21
[ka16]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L187-L230
[ka17]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer_path.bpf.c#L41-L58
[ka18]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L234-L281
[ka19]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer_path.bpf.c#L23-L39
[ka20]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/ima_hash.bpf.c#L38-L57
[ka21]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/getting-started/hardening_guide.md#L156-L160
[ka22]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/getting-started/security_policy_specification.md#L177
[ka23]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/anonmapexec.bpf.c#L92-L140
[ka24]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L403-L424
[ka25]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L599
[ka26]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L2384-L2446
[ka27]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/syscallParser.go#L481
[ka28]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/syscallParser.go#L159-L180
[ka29]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L2176-L2182
[ka30]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L2164-L2189
[ka31]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/getting-started/network_bandwidth_quota.md#L1-L3
[ka32]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L481-L496
[ka33]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/logUpdate.go#L297-L337
[ka34]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1203-L1235
[ka35]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/system_monitor.c#L1834-L1846
[ka36]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L760-L780
[ka37]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/getting-started/security_policy_specification.md#L219-L246
[ka38]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/feeder/feeder.go#L763-L766
[ka39]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/processTree.go#L24-L35
[ka40]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/protobuf/kubearmor.proto#L53-L55
[ka41]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/protobuf/kubearmor.proto#L48-L51
[ka42]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/core/containerdHandler.go#L217-L219
[ka43]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/core/containerdHandler.go#L106-L118
[ka44]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/config/config.go#L188
[ka45]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/monitor/systemMonitor.go#L792-L795
[ka46]: https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L429-L466

</details>

<details>
<summary>Inspektor Gadget (section: <a href="#inspektor-gadget">IG</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | trace_exec args + cwd (`--paths`); no env ([trace_exec/program.bpf.c#L36-L64][ig1]) |
| exit | partial | no exit gadget; traceloop `exit_group` only; trace_oomkill for OOM kills ([trace_oomkill/program.bpf.c#L17-L30][ig2]) |
| fork/clone | partial | no fork gadget; trace_lsm `task_alloc` name only, traceloop `clone` ([trace_lsm/program.bpf.c#L190-L210][ig3], [traceloop/program.bpf.c#L278][ig4]) |
| credential change | partial | trace_capabilities CAP_SETUID/SETGID checks w/ syscall; trace_lsm `task_fix_setuid` name ([trace_capabilities/program.bpf.c#L79-L93][ig5]) |
| process injection | partial | trace_lsm `ptrace_access_check` name; traceloop ptrace/process_vm_writev ([trace_lsm/program.bpf.c#L190-L210][ig3], [traceloop/program.bpf.c#L278][ig4]) |
| fileless exec | partial | exepath (`--paths`) would show memfd/deleted path; no flag [INFERENCE] ([trace_exec/program.bpf.c#L313-L324][ig6]) |
| script/interpreter content | ✗ | script path (`file`) only, no content ([trace_exec/program.bpf.c#L485-L490][ig7]) |
| TTY/interactive | ✓ | trace_exec tty major/minor; ttysnoop captures tty_write data ([trace_exec/program.bpf.c#L130-L144][ig8]) |
| lineage | partial | parent comm/pid/tid and parent_exepath only ([gadget/common.h#L28-L35][ig9]) |
| executable hash | ✗ | inode/dev/ctime only, no hash ([trace_exec/program.bpf.c#L55-L60][ig10]) |
| package ownership/signature | ✗ | no such gadget in complete gadget list ([gadgets/Makefile#L117-L173][ig11]) |
| sensitive-file read | ✓ | trace_open fname/fpath, flags, error ([trace_open/program.bpf.c#L89-L148][ig12]) |
| write/modify | ✓ | trace_open write flags; top_file per-file write bytes ([top_file/program.bpf.c#L122][ig13]) |
| create | partial | O_CREAT via trace_open flags; no mkdir/mknod gadget ([trace_open/program.bpf.c#L32][ig14]) |
| delete | partial | trace_lsm `inode_unlink` name only; traceloop unlink ([trace_lsm/program.bpf.c#L190-L210][ig3], [traceloop/program.bpf.c#L278][ig4]) |
| rename | ✓ | trace_rename old/new path ([trace_rename/program.bpf.c#L40-L47][ig15]) |
| chmod/chown/xattr | partial | trace_lsm `inode_setxattr` name only; traceloop ([trace_lsm/program.bpf.c#L190-L210][ig3], [traceloop/program.bpf.c#L278][ig4]) |
| link/symlink | ✓ | trace_link target + linkpath ([trace_link/program.bpf.c#L27-L32][ig16]) |
| FIM hashing | ✗ | no such gadget in complete gadget list ([gadgets/Makefile#L117-L173][ig11]) |
| persistence locations | partial | trace_open with user filters; no shipped rules ([run.mdx#L70-L78][ig17]) |
| dropped-file exec | ✓ | `upper_layer`/`fupper_layer` = exe from container overlay upper layer ([trace_exec/program.bpf.c#L229-L249][ig18]) |
| library load / mmap exec | partial | trace_lsm `mmap_file`/`file_mprotect` names only ([trace_lsm/program.bpf.c#L190-L210][ig3]) |
| TCP connect/accept/listen | ✓ | trace_tcp connect/accept/close; listen only via snapshot_socket ([trace_tcp/program.bpf.c#L14-L93][ig19]) |
| UDP flows | partial | DNS only; snapshot_socket `iter/udp` snapshots ([snapshot_socket/program.bpf.c#L246][ig20]) |
| DNS query/answer | ✓ | trace_dns queries+responses, rcode, latency, v4/v6 ([trace_dns/program.bpf.c#L367-L423][ig21]) |
| raw/packet sockets | ✗ | no socket-create gadget; trace_lsm list lacks socket hooks ([gadgets/Makefile#L117-L173][ig11], [trace_lsm/program.bpf.c#L17-L164][ig22]) |
| unix sockets | partial | fdpass (SCM_RIGHTS) only ([fdpass/program.bpf.c#L81-L160][ig23]) |
| IPv6 | ✓ | tcp_v6_connect, inet6_bind, IPv6 DNS/SNI parsing ([trace_tcp/program.bpf.c#L26-L32][ig24]) |
| NAT post-translation tuple | ✗ | socket tuple / pod-netns packet view ([ebpf/common.h#L29-L41][ig25]) |
| HTTP/TLS metadata (SNI) | ✓ | trace_sni; trace_ssl plaintext via uprobes ([trace_sni/program.bpf.c#L166][ig26]) |
| flow volume | partial | top_tcp bytes per TCP connection; no UDP ([top_tcp/program.bpf.c#L30-L40][ig27]) |
| bind | ✓ | trace_bind addr, opts, iface ([trace_bind/program.bpf.c#L36-L43][ig28]) |
| module load | ✓ | trace_init_module (init/finit, params, filepath) ([trace_init_module/program.bpf.c#L21-L30][ig29]) |
| BPF load | partial | bpfstats lists loaded programs/CPU; no load event ([bpfstats.mdx#L11][ig30]) |
| kprobe/perf_event_open | ✗ | no such gadget; hook absent from trace_lsm list ([gadgets/Makefile#L117-L173][ig11], [trace_lsm/program.bpf.c#L17-L164][ig22]) |
| mount/umount | ✓ | trace_mount src/dest/fs/flags ([trace_mount/program.bpf.c#L67-L80][ig31]) |
| namespaces | partial | traceloop raw syscalls only ([traceloop/program.bpf.c#L278][ig4]) |
| kexec | partial | traceloop raw syscalls only ([traceloop/program.bpf.c#L278][ig4]) |
| sysctl write | partial | trace_open on /proc/sys with write flags; no value ([trace_open/program.bpf.c#L26-L37][ig32]) |
| time change | partial | trace_lsm `settime` name; traceloop ([trace_lsm/program.bpf.c#L190-L210][ig3], [traceloop/program.bpf.c#L278][ig4]) |
| keyring | partial | traceloop raw syscalls only ([traceloop/program.bpf.c#L278][ig4]) |
| io_uring | ✗ | documented unobservable ([gadget_limitations.mdx#L15-L20][ig33]) |
| userfaultfd | partial | traceloop raw syscalls only ([traceloop/program.bpf.c#L278][ig4]) |
| capability use | ✓ | trace_capabilities cap, verdict, syscall, stacks ([trace_capabilities/program.bpf.c#L170-L240][ig34]) |
| login/logout | ✗ | no such gadget in complete gadget list ([gadgets/Makefile#L117-L173][ig11]) |
| sudo/su | partial | exec + loginuid; CAP_SETUID checks ([trace_exec/program.bpf.c#L169-L177][ig35]) |
| user/group changes | partial | trace_open on /etc/passwd etc. ([trace_open/program.bpf.c#L89-L148][ig12]) |
| loginuid/session | ✓ | trace_exec loginuid + sessionid ([trace_exec/program.bpf.c#L169-L177][ig35]) |
| container id | ✓ | runtime.containerId via mntns ([kubemanager.md#L27-L33][ig36]) |
| image | ✓ | image name + digest ([kubemanager.md#L31-L32][ig37]) |
| pod/namespace/labels | ✓ | k8s namespace/pod/labels/owner ([kubemanager.md#L20-L26][ig38]) |
| privileged flag | ✗ | only `k8s.hostnetwork` ([gadget-ebpf-api.md#L69][ig39]) |
| runtime events | partial | `ig list-containers --watch` add/remove; not a gadget datasource ([containers.go#L138-L141][ig40]) |
| K8s audit | ✗ | no audit-log gadget in complete gadget list ([gadgets/Makefile#L117-L173][ig11]) |
| tamper protection | ✗ | not found; image signature verification only ([verify-gadgets.mdx#L10-L11][ig41]) |
| loss/health reporting | ✓ | per-CPU lost counters reported per second; bpfstats ([ebpf/tracer.go#L136-L216][ig42]) |
| response actions | partial | custom gadgets can SIGKILL (third-party runc-vuln-detector `--kill`) ([runc-vuln-detector blog][ig43]) |
| prevention/enforcement | partial | custom `lsm/*` gadgets possible; none shipped ([program-types.md#L167-L170][ig44]) |

[ig1]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L36-L64
[ig2]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_oomkill/program.bpf.c#L17-L30
[ig3]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_lsm/program.bpf.c#L190-L210
[ig4]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/traceloop/program.bpf.c#L278
[ig5]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_capabilities/program.bpf.c#L79-L93
[ig6]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L313-L324
[ig7]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L485-L490
[ig8]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L130-L144
[ig9]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/include/gadget/common.h#L28-L35
[ig10]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L55-L60
[ig11]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/Makefile#L117-L173
[ig12]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_open/program.bpf.c#L89-L148
[ig13]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/top_file/program.bpf.c#L122
[ig14]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_open/program.bpf.c#L32
[ig15]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_rename/program.bpf.c#L40-L47
[ig16]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_link/program.bpf.c#L27-L32
[ig17]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/reference/run.mdx#L70-L78
[ig18]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L229-L249
[ig19]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_tcp/program.bpf.c#L14-L93
[ig20]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/snapshot_socket/program.bpf.c#L246
[ig21]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_dns/program.bpf.c#L367-L423
[ig22]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_lsm/program.bpf.c#L17-L164
[ig23]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/fdpass/program.bpf.c#L81-L160
[ig24]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_tcp/program.bpf.c#L26-L32
[ig25]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_tcp/ebpf/common.h#L29-L41
[ig26]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_sni/program.bpf.c#L166
[ig27]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/top_tcp/program.bpf.c#L30-L40
[ig28]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_bind/program.bpf.c#L36-L43
[ig29]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_init_module/program.bpf.c#L21-L30
[ig30]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/gadgets/bpfstats.mdx#L11
[ig31]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_mount/program.bpf.c#L67-L80
[ig32]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_open/program.bpf.c#L26-L37
[ig33]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/gadgets/gadget_limitations.mdx#L15-L20
[ig34]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_capabilities/program.bpf.c#L170-L240
[ig35]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L169-L177
[ig36]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/spec/operators/kubemanager.md#L27-L33
[ig37]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/spec/operators/kubemanager.md#L31-L32
[ig38]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/spec/operators/kubemanager.md#L20-L26
[ig39]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/gadget-devel/gadget-ebpf-api.md#L69
[ig40]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/cmd/ig/containers/containers.go#L138-L141
[ig41]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/reference/verify-gadgets.mdx#L10-L11
[ig42]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/operators/ebpf/tracer.go#L136-L216
[ig43]: https://inspektor-gadget.io/blog/2025/12/detect-and-mitigate-runc-container-escape-vuln
[ig44]: https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/docs/gadget-devel/program-types.md#L167-L170

</details>

<details>
<summary>Elastic open source (elastic/ebpf, elastic/quark, Auditbeat) (section: <a href="#elastic-open-source-elasticebpf-quark-auditbeat">Elastic</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | ebpf `PROCESS_EXEC`: argv, env, cwd, filename ([Process/Probe.bpf.c#L183-L206][el1]) |
| exit | partial | `PROCESS_EXIT` keeps status byte only; terminating signal dropped ([Process/Probe.bpf.c#L258-L260][el2]) |
| fork/clone | ✓ | `PROCESS_FORK` at tp_btf/sched_process_fork; thread creations ignored ([Process/Probe.bpf.c#L73-L120][el3]) |
| credential change | partial | `PROCESS_SETUID`/`SETGID` from commit_creds; no capability-change event ([Process/Probe.bpf.c#L516-L576][el4]) |
| process injection | partial | `PROCESS_PTRACE` only; no process_vm_writev or /proc/pid/mem ([Process/Probe.bpf.c#L380-L422][el5]) |
| fileless exec | ✓ | exec flags MEMFD, inode_nlink=0; `MEMFD_CREATE`, `SHMEM_OPEN` events ([Process/Probe.bpf.c#L153-L176][el6]) |
| script/interpreter content | ✗ | no script-content event in the complete event enum ([EbpfEventProto.h#L22-L42][el7]) |
| TTY/interactive | ✓ | `PROCESS_TTY_WRITE` output bytes; ctty on process events ([Process/Probe.bpf.c#L590-L712][el8]) |
| lineage | ✓ | ppid/pgid/sid per event; quark process cache with entry leader ([quark.h#L640-L692][el9]) |
| executable hash | partial | Auditbeat process hashes exe; skipped outside its mount namespace ([quark_provider_linux.go#L256-L273][el10]) |
| package ownership/signature | ✗ | system/package is an installed-package inventory, no exe→package link ([system/_meta/docs.md][el11]) |
| sensitive-file read | partial | no read event; only user-written auditd `-w -p r` rules ([auditd docs.md#L225-L252][el12]) |
| write/modify | ✓ | `FILE_MODIFY` change_type CONTENT from vfs_write/writev, truncate ([File/Probe.bpf.c#L748-L829][el13]) |
| create | ✓ | `FILE_CREATE` when do_filp_open returns FMODE_CREATED ([File/Probe.bpf.c#L302-L305][el14]) |
| delete | ✓ | `FILE_DELETE` at vfs_unlink exit with path ([File/Probe.bpf.c#L115-L179][el15]) |
| rename | ✓ | `FILE_RENAME` old/new path via vfs_rename ([File/Probe.bpf.c#L462-L600][el16]) |
| chmod/chown/xattr | partial | `FILE_MODIFY` PERMISSIONS/OWNER; XATTRS enum exists but no xattr hook ([File/Probe.bpf.c#L650-L872][el17]) |
| link/symlink | partial | symlink target recorded on file events; no link()/symlink() hook ([File/Probe.bpf.c#L159-L163][el18]) |
| FIM hashing | ✓ | Auditbeat file_integrity hashes changed files (sha1 default, many algorithms) ([file_integrity docs.md#L116-L120][el19]) |
| persistence locations | partial | FIM defaults /etc and bin dirs, non-recursive; no ssh/profile paths ([file_integrity docs.md#L61-L79][el20]) |
| dropped-file exec | partial | quark `file.exec_change` rule predicate; no create→exec correlation shipped ([CHANGES#L117-L119][el21]) |
| library load / mmap exec | partial | quark `QUARK_EV_MPROTECT` exec-mprotect attempts; no mmap hook ([quark_queue_open.3#L121-L127][el22]) |
| TCP connect/accept/listen | partial | CONNECTION_ATTEMPTED/ACCEPTED/CLOSED; no listen event ([Network/Probe.bpf.c#L32-L154][el23]) |
| UDP flows | ✓ | Auditbeat system/socket `network_flow` for UDP v4/v6 with counters ([socket docs.md#L6-L13][el24]) |
| DNS query/answer | ✓ | quark `QQ_DNS` cgroup_skb DNS packets; Auditbeat socket AF_PACKET DNS ([quark Network/Probe.bpf.c#L443-L475][el25]) |
| raw/packet sockets | ✗ | socket dataset excludes raw sockets; ebpf network is TCP-only ([socket docs.md#L15][el26]) |
| unix sockets | ✗ | socket fill handles AF_INET/AF_INET6 only ([Network.h#L17-L84][el27]) |
| IPv6 | ✓ | tcp_v6_connect hook, AF_INET6 addresses in network events ([Network.h#L38-L52][el28]) |
| NAT post-translation tuple | ✗ | tuple read from sock at connect; no conntrack hook [INFERENCE] ([Network.h#L17-L63][el29]) |
| HTTP/TLS metadata (SNI) | ✗ | no HTTP/TLS event in the complete event enum ([EbpfEventProto.h#L22-L42][el7]) |
| flow volume | ✓ | `CONNECTION_CLOSED` bytes_sent/received; Auditbeat flows bytes+packets ([Network/Probe.bpf.c#L161-L180][el30]) |
| bind | ✗ | no bind event in the complete event enum ([EbpfEventProto.h#L22-L42][el7]) |
| module load | ✓ | `PROCESS_LOAD_MODULE` name/version/srcversion; skips pid/ppid 1,2 ([Process/Probe.bpf.c#L323-L378][el31]) |
| BPF load | partial | only via user-written auditd `-S bpf` syscall rule ([auditd docs.md#L168-L169][el32]) |
| kprobe/perf_event_open | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| mount/umount | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| namespaces | partial | ns inode numbers on events; unshare/setns only via auditd rule ([Helpers.h#L309-L328][el33]) |
| kexec | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| sysctl write | partial | only via user-written auditd watch rule ([auditd docs.md#L168-L169][el32]) |
| time change | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| keyring | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| io_uring | ✗ | no io_uring event in the complete event enum ([EbpfEventProto.h#L22-L42][el7]) |
| userfaultfd | partial | only via user-written auditd syscall rule ([auditd docs.md#L168-L169][el32]) |
| capability use | ✗ | cap_effective carried as a field; no capability-use event ([Helpers.h#L252-L302][el34]) |
| login/logout | ✓ | system/login from wtmp/btmp; auditd USER_LOGIN → logged-in ([login.go#L35-L41][el35]) |
| sudo/su | ✓ | auditd USER_CMD → `ran-command` ([sudo-asuser.log-expected.json#L156-L162][el36]) |
| user/group changes | ✓ | system/user user_added/removed/changed, password_changed ([user.go#L53-L76][el37]) |
| loginuid/session | ✓ | auditd LOGIN → `changed-login-id-to`; auid/ses fields ([auditlogin.log-expected.json#L24][el38]) |
| container id | ✓ | quark `container_id` parsed from cgroup path ([quark.h#L684-L689][el39]) |
| image | partial | quark image fields need quark-kube-talker or container API ([CHANGES#L251-L260][el40]) |
| pod/namespace/labels | partial | quark pod name/ns/labels only with separate quark-kube-talker ([quark.h#L768-L782][el41]) |
| privileged flag | ✗ | no privileged field in quark container struct ([quark.h#L743-L758][el42]) |
| runtime events | ✗ | no container lifecycle event in quark event list ([quark.h#L546-L579][el43]) |
| K8s audit | ✗ | no K8s audit source in quark event list ([quark.h#L546-L579][el43]) |
| tamper protection | partial | quark freezes maps, read-only trusted-pid map; no anti-kill ([CHANGES#L204-L209][el44]) |
| loss/health reporting | ✓ | per-CPU ringbuf_stats sent/lost; quark stats lost/stalls ([Helpers.h#L330-L349][el45]) |
| response actions | partial | host isolation only: TC filter plus connect allow-list ([hostisolation.md#L1-L8][el46]) |
| prevention/enforcement | ✗ | nova LSM hooks always pass ("Always pass for now") ([nova.bpf.c#L516-L518][el47]) |

[el1]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L183-L206
[el2]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L258-L260
[el3]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L73-L120
[el4]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L516-L576
[el5]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L380-L422
[el6]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L153-L176
[el7]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/EbpfEventProto.h#L22-L42
[el8]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L590-L712
[el9]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.h#L640-L692
[el10]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/process/quark_provider_linux.go#L256-L273
[el11]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/_meta/docs.md
[el12]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/auditd/_meta/docs.md#L225-L252
[el13]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L748-L829
[el14]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L302-L305
[el15]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L115-L179
[el16]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L462-L600
[el17]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L650-L872
[el18]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/File/Probe.bpf.c#L159-L163
[el19]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/_meta/docs.md#L116-L120
[el20]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/_meta/docs.md#L61-L79
[el21]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L117-L119
[el22]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark_queue_open.3#L121-L127
[el23]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Probe.bpf.c#L32-L154
[el24]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/socket/_meta/docs.md#L6-L13
[el25]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/elastic-ebpf/GPL/Events/Network/Probe.bpf.c#L443-L475
[el26]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/socket/_meta/docs.md#L15
[el27]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Network.h#L17-L84
[el28]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Network.h#L38-L52
[el29]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Network.h#L17-L63
[el30]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Network/Probe.bpf.c#L161-L180
[el31]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L323-L378
[el32]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/auditd/_meta/docs.md#L168-L169
[el33]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Helpers.h#L309-L328
[el34]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Helpers.h#L252-L302
[el35]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/login/login.go#L35-L41
[el36]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/auditd/testdata/sudo-asuser.log-expected.json#L156-L162
[el37]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/x-pack/auditbeat/module/system/user/user.go#L53-L76
[el38]: https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/auditd/testdata/auditlogin.log-expected.json#L24
[el39]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.h#L684-L689
[el40]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L251-L260
[el41]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.h#L768-L782
[el42]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.h#L743-L758
[el43]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.h#L546-L579
[el44]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L204-L209
[el45]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Helpers.h#L330-L349
[el46]: https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/docs/hostisolation.md#L1-L8
[el47]: https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/nova.bpf.c#L516-L518

</details>

<details>
<summary>Kunai (section: <a href="#kunai">Kunai</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | `execve` exe + argv (512 B cap); no env or cwd field ([execve.rs#L7-L20][ku1]) |
| exit | partial | `exit`/`exit_group` at syscall entry; signal deaths missed [INFERENCE] ([exit.rs#L17-L58][ku2]) |
| fork/clone | ✓ | `clone` {flags, exe, argv, cgroup} ([clone.rs#L13-L18][ku3]) |
| credential change | ✓ | `commit_creds` old/new creds incl. caps; `creds_tampered` ([creds.rs#L42-L54][ku4]) |
| process injection | partial | `ptrace` {mode, target}; no process_vm_writev or /proc/pid/mem ([ptrace.rs#L6-L8][ku5]) |
| fileless exec | partial | `mprotect_exec`/`mmap_exec`; no memfd or deleted-exe flag ([mprotect.rs#L6-L10][ku6]) |
| script/interpreter content | partial | `execve_script` gives interpreter and script path, not content ([execve.rs#L12-L20][ku7]) |
| TTY/interactive | ✗ | no tty event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| lineage | ✓ | `ancestors` chain, parent_exe, parent_command_line, guuid ([kunai.rocks execve docs][ku9]) |
| executable hash | ✓ | md5/sha1/sha256/sha512 + size computed in userspace, cached ([cache.rs#L153-L213][ku10]) |
| package ownership/signature | ✗ | no package field or event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| sensitive-file read | ✓ | `read_config` for /etc on by default; `read` off by default ([fs.rs#L237-L249][ku11]) |
| write/modify | ✓ | `write`/`write_config` first per task×inode; `write_close` ([fs.rs#L295-L341][ku12]) |
| create | ✓ | `file_create` at security_file_open with FMODE_CREATED ([fs.rs#L631-L681][ku13]) |
| delete | ✓ | `file_unlink` via security_path_unlink + vfs_unlink return ([fs.rs#L418-L468][ku14]) |
| rename | ✓ | `file_rename` via security_path_rename ([fs.rs#L343-L358][ku15]) |
| chmod/chown/xattr | ✗ | no chmod/chown/xattr event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| link/symlink | ✗ | no link/symlink event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| FIM hashing | partial | `scan-files` rule action hashes/YARA-scans paths on match ([rule_configuration][ku16]) |
| persistence locations | partial | `write_config` covers /etc only; no shipped rules ([fs.rs#L321-L323][ku17]) |
| dropped-file exec | partial | `write_close` + hashed `execve`; correlation needs user rules ([rule_configuration][ku16]) |
| library load / mmap exec | ✓ | `mmap_exec` for PROT_EXEC file mappings, with file hashes ([mmap.rs#L30-L60][ku18]) |
| TCP connect/accept/listen | partial | `connect` only; no accept or listen event ([connect.rs#L15-L28][ku19]) |
| UDP flows | partial | `connect` on UDP sockets, `send_data` per send; no flow records ([kunai.rocks connect docs][ku20]) |
| DNS query/answer | ✓ | `dns_query`: query, response, resolver, query_type ([dns.rs#L34-L86][ku21]) |
| raw/packet sockets | partial | `bpf_socket_filter` attach events only; no raw-socket event ([bpf_socket.rs#L11-L68][ku22]) |
| unix sockets | ✗ | network probes accept AF_INET/AF_INET6 only ([send_data.rs#L50-L53][ku23]) |
| IPv6 | ✓ | `is_v6` addresses on connect and dns_query ([kunai.rocks connect docs][ku20]) |
| NAT post-translation tuple | ✗ | tuple taken at __sys_connect; no conntrack hook [INFERENCE] ([connect.rs#L15-L28][ku19]) |
| HTTP/TLS metadata (SNI) | partial | `send_data` byte entropy only (flags encryption); no SNI ([send_data.rs#L1-L6][ku24]) |
| flow volume | partial | per-send `real_data_size`; no aggregated counters ([send_data.rs#L97-L109][ku25]) |
| bind | ✗ | no bind event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| module load | ✓ | `init_module` {name, args, loaded} ([init_module.rs#L57-L61][ku26]) |
| BPF load | ✓ | `bpf_prog_load` {name, prog_type, attach, insn hashes} ([bpf.rs#L13-L33][ku27]) |
| kprobe/perf_event_open | partial | kprobe-type programs visible via `bpf_prog_load`; no perf_event_open event ([bpf.rs#L22-L33][ku28]) |
| mount/umount | ✗ | mount event (id 80) removed from the event type enum ([bpf_events.rs#L112-L114][ku29]) |
| namespaces | partial | clone flags; user-ns maps tracked internally; no unshare/setns ([user_ns.rs#L11-L47][ku30]) |
| kexec | ✗ | no kexec event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| sysctl write | ✗ | no sysctl event; write_config covers /etc only ([bpf_events.rs#L60-L179][ku8]) |
| time change | ✗ | no time-change event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| keyring | ✗ | no keyring event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| io_uring | partial | `io_uring_sqe` carries opcode only ([io_uring.rs#L6-L8][ku31]) |
| userfaultfd | ✗ | no userfaultfd event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| capability use | partial | caps carried in commit_creds; no capable() event ([creds.rs#L42-L54][ku4]) |
| login/logout | ✗ | no login event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| sudo/su | partial | visible only as execve plus commit_creds ([creds.rs#L42-L54][ku4]) |
| user/group changes | partial | only `write_config` on /etc/passwd and similar ([fs.rs#L321-L323][ku17]) |
| loginuid/session | ✗ | no loginuid/session field in TaskInfo ([bpf_events.rs#L199-L216][ku32]) |
| container id | partial | container type + name only; no id field documented ([kunai.rocks generalities][ku33]) |
| image | ✗ | container enum is type only; no image ([containers.rs#L8-L17][ku34]) |
| pod/namespace/labels | ✗ | no K8s metadata; container detection by string match ([containers.rs#L68-L114][ku35]) |
| privileged flag | ✗ | not collected; container enum is type only ([containers.rs#L8-L17][ku34]) |
| runtime events | ✗ | no container lifecycle event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| K8s audit | ✗ | no K8s audit event in the complete event type enum ([bpf_events.rs#L60-L179][ku8]) |
| tamper protection | ✓ | harden mode: LSM blocks signals and ptrace to Kunai ([lsm.rs#L22-L89][ku36]) |
| loss/health reporting | ✓ | `event_loss` {read, lost, eps}, throttle `error`, per-type stats ([main.rs#L2781-L2857][ku37]) |
| response actions | ✓ | rule actions `kill` and `scan-files` ([rule_configuration][ku16]) |
| prevention/enforcement | ✗ | kill is after the fact; LSM only self-protects ([lsm.rs#L50-L56][ku38]) |

[ku1]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/execve.rs#L7-L20
[ku2]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/exit.rs#L17-L58
[ku3]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/clone.rs#L13-L18
[ku4]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/creds.rs#L42-L54
[ku5]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/ptrace.rs#L6-L8
[ku6]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/mprotect.rs#L6-L10
[ku7]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/execve.rs#L12-L20
[ku8]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events.rs#L60-L179
[ku9]: https://kunai.rocks/docs/events/execve
[ku10]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/cache.rs#L153-L213
[ku11]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L237-L249
[ku12]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L295-L341
[ku13]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L631-L681
[ku14]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L418-L468
[ku15]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L343-L358
[ku16]: https://why.kunai.rocks/docs/advanced/rule_configuration/
[ku17]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L321-L323
[ku18]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/mmap.rs#L30-L60
[ku19]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/connect.rs#L15-L28
[ku20]: https://kunai.rocks/docs/events/connect
[ku21]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/dns.rs#L34-L86
[ku22]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/bpf_socket.rs#L11-L68
[ku23]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/send_data.rs#L50-L53
[ku24]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/send_data.rs#L1-L6
[ku25]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/send_data.rs#L97-L109
[ku26]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/init_module.rs#L57-L61
[ku27]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/bpf.rs#L13-L33
[ku28]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/bpf.rs#L22-L33
[ku29]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events.rs#L112-L114
[ku30]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/user_ns.rs#L11-L47
[ku31]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events/events/io_uring.rs#L6-L8
[ku32]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-common/src/bpf_events.rs#L199-L216
[ku33]: https://kunai.rocks/docs/events/generalities
[ku34]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/containers.rs#L8-L17
[ku35]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/containers.rs#L68-L114
[ku36]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/lsm.rs#L22-L89
[ku37]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai/src/bin/main.rs#L2781-L2857
[ku38]: https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/lsm.rs#L50-L56

</details>

<details>
<summary>Exein Pulsar (section: <a href="#exein-pulsar">Pulsar</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | `Exec` filename + argv; no env or cwd ([probes.bpf.c#L67-L80][pu1]) |
| exit | partial | `Exit` exit_code>>8; terminating signal dropped ([probes.bpf.c#L524-L525][pu2]) |
| fork/clone | ✓ | `Fork` {ppid, uid, gid, namespaces, container id} ([probes.bpf.c#L279-L339][pu3]) |
| credential change | partial | `CredentialsChange` uid/gid only; no caps ([probes.bpf.c#L599-L630][pu4]) |
| process injection | ✗ | no ptrace/process_vm event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| fileless exec | ✗ | no memfd/deleted-exe event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| script/interpreter content | ✗ | no script-content event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| TTY/interactive | ✗ | no tty event; shipped rule matches Exec only ([interpreter_tty_upgrade.toml][pu6]) |
| lineage | ✓ | parent_pid header, `ChangeParent`, tracker is_descendant_of ([process_tracker.rs#L124-L136][pu7]) |
| executable hash | ✗ | no hash field in event header or Payload ([event.rs#L81-L95][pu8]) |
| package ownership/signature | ✗ | no package event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| sensitive-file read | ✓ | `FileOpened` + shipped "Open sensitive file" rule ([read_sensitive_file.toml][pu9]) |
| write/modify | partial | only open-with-write-flags via `FileOpened` f_flags ([fs probes.bpf.c#L91-L103][pu10]) |
| create | ✓ | `FileCreated` (path_mknod), `DirCreated` ([fs probes.bpf.c#L61-L75][pu11]) |
| delete | ✓ | `FileDeleted`, `DirDeleted` ([fs probes.bpf.c#L77-L89][pu12]) |
| rename | ✓ | `FileRename` source/destination ([fs probes.bpf.c#L173-L226][pu13]) |
| chmod/chown/xattr | ✗ | no attribute event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| link/symlink | ✓ | `FileLink` {source, destination, hard_link} ([fs probes.bpf.c#L105-L142][pu14]) |
| FIM hashing | ✗ | no hash field in event header or Payload ([event.rs#L81-L95][pu8]) |
| persistence locations | ✓ | shipped rules for cron, ld.so.preload, sshd_config, ssh binaries ([schedule_cron_job.toml#L7-L12][pu15]) |
| dropped-file exec | partial | opt-in `ElfOpened` plus Exec; no correlation rule found ([file-system-monitor lib.rs#L173-L222][pu16]) |
| library load / mmap exec | partial | opt-in `ElfOpened` when an ELF is opened; no mmap hook ([file-system-monitor lib.rs#L173-L222][pu16]) |
| TCP connect/accept/listen | ✓ | `Connect`, `Accept`, `Listen`, `Close` events ([network probes.bpf.c#L272-L462][pu17]) |
| UDP flows | partial | per-packet `Send`/`Receive` with proto; no flow aggregation ([network probes.bpf.c#L625-L661][pu18]) |
| DNS query/answer | ✓ | `DnsQuery`/`DnsResponse` parsed from packet payloads ([network-monitor lib.rs#L182-L209][pu19]) |
| raw/packet sockets | ✗ | no raw/packet socket event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| unix sockets | ✗ | sockaddr copy handles AF_INET/AF_INET6 only ([network probes.bpf.c#L95-L137][pu20]) |
| IPv6 | ✓ | v6 sockaddr and ipv6hdr parsing ([network probes.bpf.c#L538-L562][pu21]) |
| NAT post-translation tuple | ✗ | Connect taken at security_socket_connect, pre-NAT [INFERENCE] ([network probes.bpf.c#L305-L324][pu22]) |
| HTTP/TLS metadata (SNI) | partial | raw payload bytes in Send/Receive; no HTTP/TLS parser ([network probes.bpf.c#L675-L681][pu23]) |
| flow volume | partial | per-packet `data_len` only; no aggregated counters ([network probes.bpf.c#L675-L681][pu23]) |
| bind | ✓ | `Bind` {addr, proto} ([network probes.bpf.c#L272-L288][pu24]) |
| module load | partial | only shipped Exec rules on insmod/modprobe ([kernel_module_injection.toml][pu25]) |
| BPF load | ✗ | no BPF event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| kprobe/perf_event_open | ✗ | no perf_event_open event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| mount/umount | ✗ | no mount event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| namespaces | partial | ns inode numbers on Fork/Exec; no unshare/setns event ([probes.bpf.c#L40-L48][pu26]) |
| kexec | ✗ | no kexec event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| sysctl write | partial | only via user-written FileOpened rule on /proc/sys ([fs probes.bpf.c#L91-L103][pu10]) |
| time change | ✗ | no time-change event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| keyring | ✗ | no keyring event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| io_uring | ✗ | no io_uring event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| userfaultfd | ✗ | no userfaultfd event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| capability use | ✗ | no capability event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| login/logout | partial | shipped "SSH Brute-force attempt" rule on Exec only ([ssh_bruteforce.toml][pu27]) |
| sudo/su | partial | shipped Exec rule for su/sudo; CredentialsChange uid/gid ([management_binaries.toml][pu28]) |
| user/group changes | partial | only via user-written FileOpened rule on /etc/passwd ([fs probes.bpf.c#L91-L103][pu10]) |
| loginuid/session | ✗ | no loginuid/session field in event header ([event.rs#L81-L95][pu8]) |
| container id | partial | Docker and Podman cgroup layouts only ([probes.bpf.c#L221-L275][pu29]) |
| image | partial | image + digest for Docker/Podman from runtime state files ([containers/mod.rs#L166-L203][pu30]) |
| pod/namespace/labels | ✗ | ContainerInfo has no pod/namespace/labels ([containers/mod.rs#L166-L173][pu31]) |
| privileged flag | ✗ | ContainerInfo has no privileged field ([containers/mod.rs#L166-L173][pu31]) |
| runtime events | ✗ | no container lifecycle event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| K8s audit | ✗ | no K8s audit event in the complete Payload enum ([event.rs#L181-L280][pu5]) |
| tamper protection | ✗ | only `ignore_self` whitelist of its own process ([pulsar.toml.template#L37-L38][pu32]) |
| loss/health reporting | partial | perf lost and bus lag only as log warnings ([program.rs#L536-L538][pu33]) |
| response actions | ✗ | only threat logging, desktop and SMTP notification modules ([pulsar.toml.template#L58-L96][pu34]) |
| prevention/enforcement | ✗ | LSM programs return the previous verdict unchanged ([common.bpf.h#L72-L80][pu35]) |

[pu1]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L67-L80
[pu2]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L524-L525
[pu3]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L279-L339
[pu4]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L599-L630
[pu5]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/pulsar-core/src/event.rs#L181-L280
[pu6]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/execution/interpreter_tty_upgrade.toml
[pu7]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/pulsar-core/src/pdk/process_tracker.rs#L124-L136
[pu8]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/pulsar-core/src/event.rs#L81-L95
[pu9]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/execution/read_sensitive_file.toml
[pu10]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/probes.bpf.c#L91-L103
[pu11]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/probes.bpf.c#L61-L75
[pu12]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/probes.bpf.c#L77-L89
[pu13]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/probes.bpf.c#L173-L226
[pu14]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/probes.bpf.c#L105-L142
[pu15]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/persistence/schedule_cron_job.toml#L7-L12
[pu16]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/file-system-monitor/src/lib.rs#L173-L222
[pu17]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L272-L462
[pu18]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L625-L661
[pu19]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/src/lib.rs#L182-L209
[pu20]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L95-L137
[pu21]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L538-L562
[pu22]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L305-L324
[pu23]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L675-L681
[pu24]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/network-monitor/probes.bpf.c#L272-L288
[pu25]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/persistence/kernel_module_injection.toml
[pu26]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L40-L48
[pu27]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/credential_access/ssh_bruteforce.toml
[pu28]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/rules/privilege_escalation/management_binaries.toml
[pu29]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L221-L275
[pu30]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-common/src/containers/mod.rs#L166-L203
[pu31]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-common/src/containers/mod.rs#L166-L173
[pu32]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/src/pulsard/pulsar.toml.template#L37-L38
[pu33]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-common/src/program.rs#L536-L538
[pu34]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/src/pulsard/pulsar.toml.template#L58-L96
[pu35]: https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/common.bpf.h#L72-L80

</details>

<details>
<summary>osquery (section: <a href="#osquery">osquery</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | `process_events` cmdline, env, cwd via audit execve/execveat ([process_events.table#L4-L36][oq1]) |
| exit | ✗ | no exit/exit_group in any Linux audit or BPF syscall set ([process_events.h#L17-L28][oq2]) |
| fork/clone | ✓ | `process_events` syscall=fork/vfork/clone with audit_allow_fork_process_events ([audit_flags.cpp#L54-L58][oq3]) |
| credential change | ✗ | no setuid/setgid/capset rules; creds only at exec ([process_events.h#L17-L28][oq2]) |
| process injection | ✗ | no ptrace/process_vm_writev; only optional kill/tkill/tgkill ([process_events.h#L17-L28][oq2]) |
| fileless exec | partial | snapshot `processes.on_disk` only; not evented ([processes.table#L17-L18][oq4]) |
| script/interpreter content | ✗ | no interpreter/script column in evented tables ([process-auditing.md#L9-L15][oq5]) |
| TTY/interactive | ✗ | no tty column in process tables ([process_events.table#L4-L36][oq1]) |
| lineage | partial | `parent` pid only; ancestry needs query-time joins ([process_events.table#L33][oq6]) |
| executable hash | partial | only via query-time join with `hash` table (TOCTOU) ([hash.table][oq7]) |
| package ownership/signature | partial | snapshot deb/rpm_package_files joins only ([deb_package_files.table][oq8]) |
| sensitive-file read | ✓ | `process_file_events` operation=open/read with pid/executable ([process_file_events.cpp#L291-L299][oq9]) |
| write/modify | ✓ | `file_events` UPDATED (+hash); `process_file_events` write ([inotify.cpp#L39-L49][oq10]) |
| create | ✓ | `file_events` CREATED (inotify IN_CREATE) ([inotify.cpp#L43][oq11]) |
| delete | ✓ | `file_events` DELETED; `process_file_events` unlink ([inotify.cpp#L44][oq12]) |
| rename | ✓ | MOVED_FROM/MOVED_TO; `process_file_events` rename with dest_path ([process_file_events.cpp#L255-L270][oq13]) |
| chmod/chown/xattr | partial | inotify ATTRIBUTES_MODIFIED without actor or old/new values ([inotify.cpp#L41][oq14]) |
| link/symlink | ✓ | `process_file_events` operation=link/symlink ([process_file_events.cpp#L255-L264][oq15]) |
| FIM hashing | ✓ | `file_events` md5/sha1/sha256 after change ([file_events.table#L16-L19][oq16]) |
| persistence locations | partial | user-configured `file_paths`; snapshot crontab/systemd_units/authorized_keys ([file-integrity-monitoring.md#L40-L76][oq17]) |
| dropped-file exec | ✗ | no correlation of written file with later exec [INFERENCE] ([process-auditing.md#L9-L15][oq5]) |
| library load / mmap exec | partial | audit mmap tracked only for write/fd state ([process_file_events.cpp#L461-L464][oq18]) |
| TCP connect/accept/listen | ✓ | `socket_events` connect/accept; `bpf_socket_events` adds listen ([bpf_socket_events.cpp#L39-L52][oq19]) |
| UDP flows | partial | connect/bind on UDP only; no sendto/recvmsg ([socket_events.cpp#L24-L37][oq20]) |
| DNS query/answer | ✗ | `dns_lookup_events` is Windows-only ([dns_lookup_events.table][oq21]) |
| raw/packet sockets | partial | family/type/protocol only on bind/connect; no socket() row ([bpf_socket_events.table#L12-L21][oq22]) |
| unix sockets | ✓ | `socket_events.socket` path with `--audit_allow_unix` ([process-auditing.md#L153][oq23]) |
| IPv6 | ✓ | AF_INET6 saddr parsed in socket_events ([socket_events.cpp#L72-L75][oq24]) |
| NAT post-translation tuple | ✗ | syscall arguments only; no conntrack source [INFERENCE] ([socket_events.cpp#L24-L37][oq20]) |
| HTTP/TLS metadata (SNI) | ✗ | no HTTP/TLS table among evented tables ([process-auditing.md#L9-L15][oq5]) |
| flow volume | ✗ | no byte/packet counters in socket tables ([socket_events.table#L3-L25][oq25]) |
| bind | ✓ | `socket_events` action=bind ([socket_events.cpp#L154-L156][oq26]) |
| module load | partial | snapshot `kernel_modules` only ([kernel_modules.table][oq27]) |
| BPF load | ✗ | bpf() not in audit or BPF syscall sets ([bpfeventpublisher.cpp#L68-L100][oq28]) |
| kprobe/perf_event_open | ✗ | perf_event_open not in audit or BPF syscall sets ([bpfeventpublisher.cpp#L68-L100][oq28]) |
| mount/umount | partial | snapshot `mounts` only ([mounts.table][oq29]) |
| namespaces | partial | snapshot `process_namespaces`; clone flags not exported ([process_namespaces.table][oq30]) |
| kexec | ✗ | kexec_load not in any syscall set ([bpfeventpublisher.cpp#L68-L100][oq28]) |
| sysctl write | partial | snapshot `system_controls` only ([system_controls.table][oq31]) |
| time change | ✗ | no time-change event or rule ([process_events.h#L17-L28][oq2]) |
| keyring | partial | snapshot `kernel_keys` only ([kernel_keys.table][oq32]) |
| io_uring | ✗ | no io_uring audit rules; BPF hooks syscalls only ([auditdnetlink.cpp#L431-L450][oq33]) |
| userfaultfd | ✗ | userfaultfd not in any syscall set ([bpfeventpublisher.cpp#L68-L100][oq28]) |
| capability use | ✗ | no capability-use event among evented tables ([process-auditing.md#L9-L15][oq5]) |
| login/logout | ✓ | `user_events` PAM/sshd audit USER_* messages ([user_events.cpp#L66-L97][oq34]) |
| sudo/su | partial | only if sudo/su emit audit USER_* records; raw message [INFERENCE] ([user_events.cpp#L66-L97][oq34]) |
| user/group changes | partial | shadow-utils ADD_USER etc. as raw user_events messages [INFERENCE] ([auditdnetlink.cpp#L970-L974][oq35]) |
| loginuid/session | ✓ | `auid` on process/socket/file events; `ses` on seccomp_events ([process_events.table#L17][oq36]) |
| container id | partial | `bpf_process_events.cid` raw cgroup id only ([bpf_process_events.table#L9][oq37]) |
| image | partial | snapshot `docker_containers` via Docker API ([docker_containers.table][oq38]) |
| pod/namespace/labels | partial | docker labels snapshot; no k8s pod metadata ([docker_container_labels.table][oq39]) |
| privileged flag | partial | `docker_containers.privileged` snapshot ([docker_containers.table#L17][oq40]) |
| runtime events | ✗ | no evented container table ([process-auditing.md#L9-L15][oq5]) |
| K8s audit | ✗ | no Kubernetes audit table ([process-auditing.md#L9-L15][oq5]) |
| tamper protection | ✗ | `audit_persist` only re-acquires the netlink socket ([auditdnetlink.cpp#L35][oq41]) |
| loss/health reporting | partial | throttle warnings, `osquery_events` counts; BPF loss only in verbose log ([bpferrorstate.cpp#L49-L56][oq42]) |
| response actions | ✗ | read-only agent; carving is collection only ([file-carving.md][oq43]) |
| prevention/enforcement | ✗ | no enforcement mechanism in event publishers ([process-auditing.md#L9-L15][oq5]) |

[oq1]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/process_events.table#L4-L36
[oq2]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/process_events.h#L17-L28
[oq3]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/audit_flags.cpp#L54-L58
[oq4]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/processes.table#L17-L18
[oq5]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L9-L15
[oq6]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/process_events.table#L33
[oq7]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/hash.table#L1-L18
[oq8]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/deb_package_files.table#L1-L7
[oq9]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/process_file_events.cpp#L291-L299
[oq10]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/inotify.cpp#L39-L49
[oq11]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/inotify.cpp#L43
[oq12]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/inotify.cpp#L44
[oq13]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/process_file_events.cpp#L255-L270
[oq14]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/inotify.cpp#L41
[oq15]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/process_file_events.cpp#L255-L264
[oq16]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/file_events.table#L16-L19
[oq17]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/file-integrity-monitoring.md#L40-L76
[oq18]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/process_file_events.cpp#L461-L464
[oq19]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/bpf_socket_events.cpp#L39-L52
[oq20]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/socket_events.cpp#L24-L37
[oq21]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/windows/dns_lookup_events.table#L1-L5
[oq22]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/bpf_socket_events.table#L12-L21
[oq23]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/process-auditing.md#L153
[oq24]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/socket_events.cpp#L72-L75
[oq25]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/socket_events.table#L3-L25
[oq26]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/socket_events.cpp#L154-L156
[oq27]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/kernel_modules.table#L1-L10
[oq28]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/bpfeventpublisher.cpp#L68-L100
[oq29]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/mounts.table#L1-L10
[oq30]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/process_namespaces.table#L1-L10
[oq31]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/system_controls.table#L1-L10
[oq32]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/kernel_keys.table#L1-L10
[oq33]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/auditdnetlink.cpp#L431-L450
[oq34]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/tables/events/linux/user_events.cpp#L66-L97
[oq35]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/auditdnetlink.cpp#L970-L974
[oq36]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/process_events.table#L17
[oq37]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/linux/bpf_process_events.table#L9
[oq38]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/docker_containers.table#L1-L20
[oq39]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/docker_container_labels.table#L1-L10
[oq40]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/specs/posix/docker_containers.table#L17
[oq41]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/auditdnetlink.cpp#L35
[oq42]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/osquery/events/linux/bpf/bpferrorstate.cpp#L49-L56
[oq43]: https://github.com/osquery/osquery/blob/99ea20493a2614eab939cbc02ebfaa114a3caecb/docs/wiki/deployment/file-carving.md#L1-L10

</details>

<details>
<summary>auditd (+Laurel/go-audit) (section: <a href="#auditd-with-laurel-or-go-audit">auditd+</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | EXECVE+CWD+PROCTITLE records; env via Laurel `execve-env` (/proc, racy) ([laurel.8.md#L161-L163][au1]) |
| exit | partial | custom `-S exit_group` rule; ANOM_ABEND only on core dumps ([auditsc.c#L2914-L2930][au2]) |
| fork/clone | ✓ | Laurel-recommended fork/vfork/clone/clone3 rules (key fork) ([laurel-audit-rules.7.md#L158-L165][au3]) |
| credential change | ✓ | shipped PCI rules: setuid/setresuid, execve uid!=euid; CAPSET record ([30-pci-dss-v31.rules#L62-L67][au4]) |
| process injection | partial | shipped ptrace POKE* rules; process_vm_writev, /proc/pid/mem need custom rules ([42-injection.rules][au5]) |
| fileless exec | partial | exe/PATH show memfd/deleted names; no explicit flag [INFERENCE] ([audit.h#L93-L123][au6]) |
| script/interpreter content | partial | Laurel `SCRIPT` path only, not content ([laurel.8.md#L181-L184][au7]) |
| TTY/interactive | ✓ | SYSCALL `tty=` field; pam_tty_audit TTY keystroke records ([tty_audit.c#L73][au8]) |
| lineage | ✓ | Laurel `SPAWNED_BY`/`PPID` with event IDs, persisted state ([laurel-about.7.md#L86-L100][au9]) |
| executable hash | partial | Laurel `exe-hash` opt-in, post-hoc userspace SHA-256 ([laurel.8.md#L192-L199][au10]) |
| package ownership/signature | ✗ | no package enrichment in Laurel enrich options ([laurel.8.md#L157-L199][au11]) |
| sensitive-file read | ✓ | path rules with `perm=r`; STIG failed-access rules ([30-stig.rules#L121-L124][au12]) |
| write/modify | ✓ | `perm=wa` path rules on identity/sudoers files ([30-stig.rules#L37-L47][au13]) |
| create | ✓ | OSPP create-success rule file ([30-ospp-v42-1-create-success.rules][au14]) |
| delete | ✓ | STIG unlink/unlinkat/rename rule (auid≥1000 only) ([30-stig.rules#L138-L139][au15]) |
| rename | ✓ | same STIG rule; PATH records carry old/new names ([30-stig.rules#L138-L139][au15]) |
| chmod/chown/xattr | ✓ | STIG perm_mod rules incl. setxattr/removexattr ([30-stig.rules#L113-L118][au16]) |
| link/symlink | partial | custom link/symlink rules; ANOM_LINK for protected-link denials ([audit.h#L158][au17]) |
| FIM hashing | ✗ | no content hashing record type in audit ([audit.h#L93-L123][au6]) |
| persistence locations | ✓ | Laurel rule set watches cron, systemd, udev, ld.so, PAM, sshd ([laurel-audit-rules.7.md#L22-L72][au18]) |
| dropped-file exec | ✗ | no write-then-exec correlation in Laurel/go-audit [INFERENCE] ([laurel-about.7.md#L86-L104][au19]) |
| library load / mmap exec | partial | MMAP record needs custom mmap rule; none shipped ([audit.h#L108][au20]) |
| TCP connect/accept/listen | ✓ | shipped `-S accept,connect` rule with SOCKADDR; listen needs custom rule ([71-networking.rules][au21]) |
| UDP flows | partial | custom sendto/sendmsg rules; per-call, no flow state [INFERENCE] ([audit.h#L93-L123][au6]) |
| DNS query/answer | ✗ | no DNS record type in audit ([audit.h#L93-L123][au6]) |
| raw/packet sockets | partial | custom `-S socket -F a0=17`-style rule only [INFERENCE] ([audit.h#L93-L123][au6]) |
| unix sockets | ✓ | connect SOCKADDR carries unix path [INFERENCE] ([71-networking.rules][au21]) |
| IPv6 | ✓ | SOCKADDR AF_INET6 decoded by ENRICHED/Laurel ([auditd.conf.5#L28-L37][au22]) |
| NAT post-translation tuple | ✗ | syscall args only; no post-NAT record type ([audit.h#L93-L123][au6]) |
| HTTP/TLS metadata (SNI) | ✗ | no HTTP/TLS record type ([audit.h#L93-L123][au6]) |
| flow volume | ✗ | no byte/flow counters in audit records ([audit.h#L93-L123][au6]) |
| bind | partial | custom `-S bind` rule; none in shipped library ([71-networking.rules][au21]) |
| module load | ✓ | 43-module-load rules + KERN_MODULE record ([43-module-load.rules][au23]) |
| BPF load | ✓ | kernel emits AUDIT_BPF prog LOAD/UNLOAD records ([bpf/syscall.c#L2309-L2326][au24]) |
| kprobe/perf_event_open | partial | custom perf_event_open rule only; none shipped ([rules/README-rules][au25]) |
| mount/umount | ✓ | STIG mount/mount_setattr rule (auid≥1000 filter) ([30-stig.rules#L132-L133][au26]) |
| namespaces | ✓ | 41-containers: clone ns flags, unshare, setns ([41-containers.rules][au27]) |
| kexec | partial | custom kexec_load rule only; none shipped ([rules/README-rules][au25]) |
| sysctl write | partial | custom /proc/sys path rule only; none shipped ([rules/README-rules][au25]) |
| time change | ✓ | STIG time-change rules; TIME_* records ([30-stig.rules#L27-L35][au28]) |
| keyring | partial | custom add_key/keyctl rule only; none shipped ([rules/README-rules][au25]) |
| io_uring | partial | io_uring filter rules + URINGOP; 33 ops are audit_skip ([io_uring.c#L1381-L1387][au29]) |
| userfaultfd | partial | custom userfaultfd rule only; none shipped ([rules/README-rules][au25]) |
| capability use | partial | CAPSET/BPRM_FCAPS records; capable() checks not logged ([audit.h#L106-L107][au30]) |
| login/logout | ✓ | PAM USER_LOGIN/USER_START/USER_END without rules ([30-stig.rules#L100-L102][au31]) |
| sudo/su | ✓ | USER_CMD/USER_AUTH; PCI su/sudo setuid rules (go-audit drops 11xx default) ([30-pci-dss-v31.rules#L62-L65][au32]) |
| user/group changes | ✓ | shadow-utils ADD_USER/USER_MGMT; STIG identity watches ([30-stig.rules#L37-L47][au13]) |
| loginuid/session | ✓ | auid/ses on every record; `--loginuid-immutable` ([11-loginuid.rules][au33]) |
| container id | ✓ | Laurel/go-audit container id from /proc cgroup path ([proc.rs#L167-L180][au34]) |
| image | partial | go-audit Docker/containerd API extras only (opt-in) ([extras_containers.go#L148][au35]) |
| pod/namespace/labels | partial | go-audit pod_name/pod_namespace/pod_uid from CRI labels ([extras_containers.go#L149-L152][au36]) |
| privileged flag | ✗ | no privileged field in go-audit container extras ([extras_containers.go#L144-L176][au37]) |
| runtime events | partial | exec-watch keys on runc/containerd/dockerd binaries ([laurel-audit-rules.7.md#L133-L139][au38]) |
| K8s audit | ✗ | K8s API audit is outside kernel audit record types ([audit.h#L93-L123][au6]) |
| tamper protection | partial | `-e 2` immutable rules, loginuid-immutable, watches on audit config/tools ([laurel-audit-rules.7.md#L93-L108][au39]) |
| loss/health reporting | ✓ | kernel lost/backlog, auditd.state, go-audit sequence gaps ([auditd-plugins.5#L59-L79][au40]) |
| response actions | ✗ | no response mechanism; observe-only subsystem ([auditd.conf.5#L452-L470][au41]) |
| prevention/enforcement | ✗ | observe-only; failure-mode panic is not prevention ([audit.c#L392-L422][au42]) |

[au1]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel.8.md#L161-L163
[au2]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/auditsc.c#L2914-L2930
[au3]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-audit-rules.7.md#L158-L165
[au4]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-pci-dss-v31.rules#L62-L67
[au5]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/42-injection.rules#L1-L12
[au6]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/audit.h#L93-L123
[au7]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel.8.md#L181-L184
[au8]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/drivers/tty/tty_audit.c#L73
[au9]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-about.7.md#L86-L100
[au10]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel.8.md#L192-L199
[au11]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel.8.md#L157-L199
[au12]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L121-L124
[au13]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L37-L47
[au14]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-ospp-v42-1-create-success.rules#L1-L5
[au15]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L138-L139
[au16]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L113-L118
[au17]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/audit.h#L158
[au18]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-audit-rules.7.md#L22-L72
[au19]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-about.7.md#L86-L104
[au20]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/audit.h#L108
[au21]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/71-networking.rules#L1-L3
[au22]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/docs/auditd.conf.5#L28-L37
[au23]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/43-module-load.rules#L1-L6
[au24]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/bpf/syscall.c#L2309-L2326
[au25]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/README-rules#L1-L20
[au26]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L132-L133
[au27]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/41-containers.rules#L1-L8
[au28]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L27-L35
[au29]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/io_uring/io_uring.c#L1381-L1387
[au30]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/include/uapi/linux/audit.h#L106-L107
[au31]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-stig.rules#L100-L102
[au32]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/30-pci-dss-v31.rules#L62-L65
[au33]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/rules/11-loginuid.rules#L1-L2
[au34]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/src/proc.rs#L167-L180
[au35]: https://github.com/slackhq/go-audit/blob/4739171bc7d5dea93f863c361eec2ce30b5daa5e/extras_containers.go#L148
[au36]: https://github.com/slackhq/go-audit/blob/4739171bc7d5dea93f863c361eec2ce30b5daa5e/extras_containers.go#L149-L152
[au37]: https://github.com/slackhq/go-audit/blob/4739171bc7d5dea93f863c361eec2ce30b5daa5e/extras_containers.go#L144-L176
[au38]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-audit-rules.7.md#L133-L139
[au39]: https://github.com/threathunters-io/laurel/blob/8d3d83cac896e6d63b5f927e415f6d7d7ad89270/man/laurel-audit-rules.7.md#L93-L108
[au40]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/docs/auditd-plugins.5#L59-L79
[au41]: https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/docs/auditd.conf.5#L452-L470
[au42]: https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/audit.c#L392-L422

</details>

<details>
<summary>Sysmon for Linux (section: <a href="#sysmon-for-linux">Sysmon</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | ProcessCreate CommandLine + CurrentDirectory; no env ([manifest.xml#L51-L77][sy1]) |
| exit | partial | ProcessTerminate (sched_process_exit) without exit code/signal ([manifest.xml#L115-L122][sy2]) |
| fork/clone | ✗ | no fork/clone hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| credential change | ✗ | no setuid/setgid/capset in the active-syscall switch ([sysmonforlinux.c#L901-L952][sy4]) |
| process injection | partial | ProcessAccess via ptrace syscall only ([sysmonforlinux.c#L943-L945][sy5]) |
| fileless exec | ✗ | no memfd/deleted marker in ProcessCreate [INFERENCE] ([manifest.xml#L51-L77][sy1]) |
| script/interpreter content | ✗ | no script/interpreter field in the event list ([sysmonforlinux.c#L901-L952][sy4]) |
| TTY/interactive | partial | tty index only in LogonId/AuthenticationId ([sysmonProcCreate.c#L160-L166][sy6]) |
| lineage | ✓ | ProcessGuid + ParentProcessGuid/ParentImage/ParentCommandLine ([manifest.xml#L51-L77][sy1]) |
| executable hash | partial | `Hashes` field; HashAlgorithms passed, Linux computation unverified ([sysmonforlinux.c#L633-L639][sy7]) |
| package ownership/signature | ✗ | no package/signature field in Linux events ([sysmonforlinux.c#L901-L952][sy4]) |
| sensitive-file read | ✗ | only RawAccessRead for block devices ([sysmonFileOpen.c#L200-L201][sy8]) |
| write/modify | ✗ | no file-modify event in the active-syscall switch ([sysmonforlinux.c#L901-L952][sy4]) |
| create | ✓ | FileCreate: O_CREAT + equal-timestamp heuristic, creat ([sysmonFileOpen.c#L191-L216][sy9]) |
| delete | ✓ | FileDelete (unlink/unlinkat); hashes blank, no archiving ([sysmonforlinux.c#L693-L728][sy10]) |
| rename | ✗ | no rename syscall in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| chmod/chown/xattr | ✗ | no chmod/chown/xattr syscall in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| link/symlink | ✗ | no link/symlink syscall in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| FIM hashing | ✗ | no FIM hashing; FileDelete HashType forced to 0xFF ([sysmonforlinux.c#L701][sy11]) |
| persistence locations | partial | FileCreate/FileDelete path rules only; no modify events ([sysmonforlinux.c#L901-L952][sy4]) |
| dropped-file exec | ✗ | no create-then-exec correlation [INFERENCE] ([sysmonforlinux.c#L901-L952][sy4]) |
| library load / mmap exec | ✗ | ImageLoad (ID 7) not wired on Linux ([sysmonforlinux.c#L901-L952][sy4]) |
| TCP connect/accept/listen | ✓ | NetworkConnect via inet_sock_set_state + accept; no listen ([sysmonTCPconnection_5_6_.c#L62-L92][sy12]) |
| UDP flows | ✓ | consume_skb send + recv*/read; 30-min per-tuple dedup ([sysmonUDPsend.c#L173-L192][sy13]) |
| DNS query/answer | ✗ | DnsQuery (ID 22) not in the Linux active-syscall switch ([sysmonforlinux.c#L901-L952][sy4]) |
| raw/packet sockets | ✗ | no raw/packet socket event in the switch ([sysmonforlinux.c#L901-L952][sy4]) |
| unix sockets | ✗ | inet_sock_set_state handles AF_INET/AF_INET6 only ([sysmonTCPconnection_5_6_.c#L96][sy14]) |
| IPv6 | ✓ | AF_INET6 handled in TCP and UDP programs ([sysmonTCPconnection_5_6_.c#L96][sy14]) |
| NAT post-translation tuple | ✗ | socket tuple only, no conntrack [INFERENCE] ([sysmonTCPconnection_5_6_.c#L62-L92][sy12]) |
| HTTP/TLS metadata (SNI) | ✗ | no HTTP/TLS fields in NetworkConnect ([manifest.xml#L89-L108][sy15]) |
| flow volume | ✗ | no byte counters in NetworkConnect ([manifest.xml#L89-L108][sy15]) |
| bind | ✗ | no bind/listen hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| module load | ✗ | DriverLoad (ID 6) not wired on Linux ([sysmonforlinux.c#L901-L952][sy4]) |
| BPF load | ✓ | eBPFEvent (ID 100) on bpf() exit ([manifest.xml#L356-L380][sy16]) |
| kprobe/perf_event_open | ✗ | no perf_event_open hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| mount/umount | ✗ | no mount hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| namespaces | ✗ | no unshare/setns/clone hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| kexec | ✗ | no kexec hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| sysctl write | ✗ | no sysctl hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| time change | ✗ | no time-change hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| keyring | ✗ | no keyring hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| io_uring | ✗ | no io_uring hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| userfaultfd | ✗ | no userfaultfd hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| capability use | ✗ | no capability hook in the program tables ([sysmonforlinux.c#L97-L174][sy3]) |
| login/logout | ✗ | no login event in the Linux active-syscall switch ([sysmonforlinux.c#L901-L952][sy4]) |
| sudo/su | ✗ | no sudo/su event in the Linux active-syscall switch ([sysmonforlinux.c#L901-L952][sy4]) |
| user/group changes | ✗ | no user/group-change event in the switch ([sysmonforlinux.c#L901-L952][sy4]) |
| loginuid/session | partial | AuditUserId/SessionId copied into ProcessCreate ([sysmonProcCreate.c#L142-L143][sy17]) |
| container id | ✗ | no cgroup/container code in BPF or userland [INFERENCE from grep] ([sysmonforlinux.c#L97-L174][sy3]) |
| image | ✗ | no image field in Linux event schema ([manifest.xml#L51-L77][sy1]) |
| pod/namespace/labels | ✗ | no pod/namespace field in Linux event schema ([manifest.xml#L51-L77][sy1]) |
| privileged flag | ✗ | no privileged field in Linux event schema ([manifest.xml#L51-L77][sy1]) |
| runtime events | ✗ | no container runtime event in the switch ([sysmonforlinux.c#L901-L952][sy4]) |
| K8s audit | ✗ | no K8s audit source ([sysmonforlinux.c#L901-L952][sy4]) |
| tamper protection | ✗ | man page: does not protect or hide itself ([sysmon_template.8#L20-L21][sy18]) |
| loss/health reporting | partial | events 4/16; perf loss printed to stdout only ([sysmonforlinux.c#L788-L793][sy19]) |
| response actions | ✗ | observe-only; no response action in the event list ([sysmonforlinux.c#L901-L952][sy4]) |
| prevention/enforcement | ✗ | observe-only eBPF programs; no enforcement ([sysmonforlinux.c#L97-L174][sy3]) |

[sy1]: https://github.com/microsoft/SysmonCommon/blob/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml#L51-L77
[sy2]: https://github.com/microsoft/SysmonCommon/blob/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml#L115-L122
[sy3]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L97-L174
[sy4]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L901-L952
[sy5]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L943-L945
[sy6]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonProcCreate.c#L160-L166
[sy7]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L633-L639
[sy8]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonFileOpen.c#L200-L201
[sy9]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonFileOpen.c#L191-L216
[sy10]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L693-L728
[sy11]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L701
[sy12]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonTCPconnection_5_6_.c#L62-L92
[sy13]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonUDPsend.c#L173-L192
[sy14]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonTCPconnection_5_6_.c#L96
[sy15]: https://github.com/microsoft/SysmonCommon/blob/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml#L89-L108
[sy16]: https://github.com/microsoft/SysmonCommon/blob/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml#L356-L380
[sy17]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonProcCreate.c#L142-L143
[sy18]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/package/usr/share/man/man8/sysmon_template.8#L20-L21
[sy19]: https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/sysmonforlinux.c#L788-L793

</details>

<details>
<summary>Wazuh agent (section: <a href="#wazuh-agent">Wazuh</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | only via auditd rules + logcollector (audit-wazuh-c key) ([audit-configuration docs][wa1]) |
| exit | ✗ | no exit source in default agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| fork/clone | ✗ | no fork/clone source in default agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| credential change | partial | custom audit rules via logcollector only ([audit-configuration docs][wa1]) |
| process injection | partial | custom audit rules via logcollector only ([audit-configuration docs][wa1]) |
| fileless exec | ✗ | no fileless-exec detection in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| script/interpreter content | ✗ | no script/interpreter source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| TTY/interactive | ✗ | no TTY source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| lineage | partial | who-data ppid/parent_name/parent_cwd on FIM events only ([modern.bpf.c#L399-L409][wa3]) |
| executable hash | partial | FIM hashes of monitored binaries, not per-exec ([ossec-agent.conf#L50-L51][wa4]) |
| package ownership/signature | partial | syscollector package inventory (hourly), no file ownership ([syscollectorTablesDef.hpp#L77-L98][wa5]) |
| sensitive-file read | partial | custom audit `-p r` rules via logcollector; FIM ignores reads ([audit-configuration docs][wa1]) |
| write/modify | ✓ | FIM modified with who-data ([run_realtime.c#L34][wa6]) |
| create | ✓ | FIM added (vfs_open / lsm file_open create) ([modern.bpf.c#L422-L480][wa7]) |
| delete | ✓ | FIM deleted (vfs_unlink / lsm path_unlink) ([modern.bpf.c#L605-L653][wa8]) |
| rename | partial | appears as delete+add pairs [INFERENCE] ([modern.bpf.c#L738-L745][wa9]) |
| chmod/chown/xattr | ✓ | permissions/uid/gid changes via security_inode_setattr; no xattr ([modern.bpf.c#L534-L591][wa10]) |
| link/symlink | partial | FIM sees new link entries; no link-specific event ([modern.bpf.c#L422-L1080][wa11]) |
| FIM hashing | ✓ | md5/sha1/sha256 plus diffs ([syscheck-config.c#L80-L125][wa12]) |
| persistence locations | partial | default /etc,/usr/bin… every 12 h; home dirs not default ([ossec-agent.conf#L43-L51][wa13]) |
| dropped-file exec | ✗ | no create-then-exec correlation in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| library load / mmap exec | ✗ | no mmap/library hook in eBPF FIM ([modern.bpf.c#L422-L1080][wa11]) |
| TCP connect/accept/listen | partial | syscollector listening-ports snapshot (hourly) ([syscollectorTablesDef.hpp#L118-L137][wa14]) |
| UDP flows | partial | ports snapshot only ([syscollectorTablesDef.hpp#L118-L137][wa14]) |
| DNS query/answer | ✗ | no DNS source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| raw/packet sockets | ✗ | no raw/packet socket source ([ossec-agent.conf#L15-L122][wa2]) |
| unix sockets | ✗ | no unix socket source ([ossec-agent.conf#L15-L122][wa2]) |
| IPv6 | partial | inventory addresses/ports only ([syscollectorTablesDef.hpp#L175-L188][wa15]) |
| NAT post-translation tuple | ✗ | no NAT source ([ossec-agent.conf#L15-L122][wa2]) |
| HTTP/TLS metadata (SNI) | ✗ | no HTTP/TLS source ([ossec-agent.conf#L15-L122][wa2]) |
| flow volume | ✗ | no flow volume source ([ossec-agent.conf#L15-L122][wa2]) |
| bind | partial | listening ports inventory ([syscollectorTablesDef.hpp#L118-L137][wa14]) |
| module load | partial | audit logs (custom rules) via logcollector ([audit-configuration docs][wa1]) |
| BPF load | ✗ | no BPF-load source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| kprobe/perf_event_open | ✗ | no perf_event_open source ([ossec-agent.conf#L15-L122][wa2]) |
| mount/umount | partial | audit logs via logcollector only ([audit-configuration docs][wa1]) |
| namespaces | ✗ | no namespace source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| kexec | ✗ | no kexec source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| sysctl write | partial | FIM on /etc/sysctl*; no runtime sysctl events ([ossec-agent.conf#L50][wa16]) |
| time change | partial | audit logs via logcollector only ([audit-configuration docs][wa1]) |
| keyring | ✗ | no keyring source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| io_uring | ✗ | no io_uring source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| userfaultfd | ✗ | no userfaultfd source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| capability use | ✗ | no capability-use source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| login/logout | ✓ | auth.log collected by default; manager sshd/PAM rules ([ossec-agent.conf#L109-L112][wa17]) |
| sudo/su | ✓ | auth.log sudo/su lines collected by default ([ossec-agent.conf#L109-L112][wa17]) |
| user/group changes | ✓ | auth.log useradd/groupadd; syscollector users/groups diff ([syscollectorTablesDef.hpp#L189-L244][wa18]) |
| loginuid/session | partial | who-data login_uid on FIM events ([modern.bpf.c#L365-L374][wa19]) |
| container id | partial | docker-listener Docker events only ([monitoring-docker docs][wa20]) |
| image | partial | docker-listener event attributes only ([monitoring-docker docs][wa20]) |
| pod/namespace/labels | ✗ | no k8s metadata in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| privileged flag | ✗ | no privileged-flag source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| runtime events | ✓ | docker-listener wodle forwards Docker daemon events ([monitoring-docker docs][wa20]) |
| K8s audit | ✗ | no K8s audit source in agent modules ([ossec-agent.conf#L15-L122][wa2]) |
| tamper protection | ✗ | no Linux agent anti-tamper found in agent config ([ossec-agent.conf#L15-L122][wa2]) |
| loss/health reporting | partial | eBPF/audit healthchecks; inotify-overflow and queue-full warnings ([run_realtime.c#L221-L226][wa21]) |
| response actions | ✓ | active response block-ip, disable-account ([active_responses.c][wa22]) |
| prevention/enforcement | partial | post-detection active response only; no inline blocking ([ossec-agent.conf#L120-L122][wa23]) |

[wa1]: https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html
[wa2]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L15-L122
[wa3]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L399-L409
[wa4]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L50-L51
[wa5]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/wazuh_modules/syscollector/src/syscollectorTablesDef.hpp#L77-L98
[wa6]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/run_realtime.c#L34
[wa7]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L422-L480
[wa8]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L605-L653
[wa9]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L738-L745
[wa10]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L534-L591
[wa11]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L422-L1080
[wa12]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/config/src/syscheck-config.c#L80-L125
[wa13]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L43-L51
[wa14]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/wazuh_modules/syscollector/src/syscollectorTablesDef.hpp#L118-L137
[wa15]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/wazuh_modules/syscollector/src/syscollectorTablesDef.hpp#L175-L188
[wa16]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L50
[wa17]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L109-L112
[wa18]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/wazuh_modules/syscollector/src/syscollectorTablesDef.hpp#L189-L244
[wa19]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L365-L374
[wa20]: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html
[wa21]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/run_realtime.c#L221-L226
[wa22]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/active-response/src/active_responses.c#L1-L20
[wa23]: https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/etc/ossec-agent.conf#L120-L122

</details>

<details>
<summary>Jibril (Garnet Labs) (section: <a href="#jibril-garnet-labs--binary-only">Jibril</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | only via `execution` recipes; args/env never collected ([categories][ji1]) |
| exit | partial | `retcode`/`exit` in Process context; no exit event ([types.go#L1067][ji2]) |
| fork/clone | partial | `task-ref` cache tracks forks; no fork event ([categories][ji1]) |
| credential change | ✗ | Process has only `uid`; no setuid/capset event ([types.go#L1064][ji3]) |
| process injection | partial | `code_modification_through_procfs` (/proc/N/mem) only ([recipe#L30][ji4]) |
| fileless exec | partial | `binary_self_deletion` (open+mmap+unlink+execve); no memfd recipe ([recipe#L26][ji5]) |
| script/interpreter content | ✗ | no script-content field in Process schema ([types.go#L1064][ji3]) |
| TTY/interactive | ✗ | no tty field in Process schema ([types.go#L1064][ji3]) |
| lineage | ✓ | `background.ancestry` on every event ([types.go#L405][ji6]) |
| executable hash | ✗ | `exe_hash` is uint32, no content digest ([types.go#L1087][ji7]) |
| package ownership/signature | ✗ | no package field in event schema ([types.go#L1064][ji3]) |
| sensitive-file read | ✓ | `credentials_files_access`, `ssl_certificate_access` recipes ([builtin rules][ji8]) |
| write/modify | ✓ | `pam_config_modification`, `sudoers_modification` (modify_related) ([builtin rules][ji8]) |
| create | partial | `create` action bit only inside modify recipes ([files.go#L42][ji9]) |
| delete | partial | `unlink` bit; only self-deletion/log-tamper recipes ([files.go#L41][ji10]) |
| rename | partial | `rename` bit; no rename event or new path ([files.go#L39][ji11]) |
| chmod/chown/xattr | ✗ | no setattr/chmod/chown/xattr action in vocabulary ([files.go#L29][ji12]) |
| link/symlink | partial | `link` (hardlink) bit; no symlink action ([files.go#L44][ji13]) |
| FIM hashing | ✗ | File struct has no content-hash field ([types.go#L1275][ji14]) |
| persistence locations | partial | shell rc, PAM, sudoers, ld.so.preload, authorized_keys; no cron/systemd ([recipe#L35][ji15]) |
| dropped-file exec | partial | `exec_from_unusual_dir` path-based; no write→exec correlation ([builtin rules][ji8]) |
| library load / mmap exec | partial | `mmap` bit + java lib-load recipes; no PROT_EXEC ([files.go#L35][ji16]) |
| TCP connect/accept/listen | partial | `flow` event incoming/outgoing/started/ended; no listen ([types.go#L1960][ji17]) |
| UDP flows | ✓ | `flows` cache covers TCP/UDP connections ([categories][ji1]) |
| DNS query/answer | partial | DNS names attached to flow nodes; no query event ([types.go#L1919][ji18]) |
| raw/packet sockets | ✗ | Flow has ICMP type/code only; no socket type ([types.go#L1809][ji19]) |
| unix sockets | ✗ | Flow struct is IP-only ([types.go#L1809][ji19]) |
| IPv6 | ✓ | `ip_version` field in Flow ([types.go#L1811][ji20]) |
| NAT post-translation tuple | ✗ | no translated tuple in Flow ([types.go#L1809][ji19]) |
| HTTP/TLS metadata (SNI) | ✗ | no L7 fields in Flow ([types.go#L1809][ji19]) |
| flow volume | ✗ | Flow has no byte/packet counters ([types.go#L1809][ji19]) |
| bind | ✗ | no bind in Flow flags/phase ([types.go#L1960][ji21]) |
| module load | ✗ | no module recipe in built-in list ([builtin rules][ji8]) |
| BPF load | partial | only `unprivileged_bpf_config_access` sysctl recipe ([builtin rules][ji8]) |
| kprobe/perf_event_open | ✗ | model page claims perf/ftrace monitoring; no event documented ([security model][ji22]) |
| mount/umount | ✗ | no mount recipe in built-in list ([builtin rules][ji8]) |
| namespaces | partial | namespace inode ids in Process; no unshare/setns event ([types.go#L1233][ji23]) |
| kexec | ✗ | no kexec recipe in built-in list ([builtin rules][ji8]) |
| sysctl write | partial | `core_pattern_access`, `sysrq_access` path recipes ([builtin rules][ji8]) |
| time change | ✗ | no time-change recipe in built-in list ([builtin rules][ji8]) |
| keyring | ✗ | no keyring recipe in built-in list ([builtin rules][ji8]) |
| io_uring | ✗ | no io_uring action in vocabulary ([files.go#L29][ji12]) |
| userfaultfd | ✗ | no userfaultfd recipe in built-in list ([builtin rules][ji8]) |
| capability use | ✗ | no capability-use recipe in built-in list ([builtin rules][ji8]) |
| login/logout | ✗ | no login recipe in built-in list ([builtin rules][ji8]) |
| sudo/su | partial | `sudoers_modification` file recipe only ([builtin rules][ji8]) |
| user/group changes | partial | `passwd_usage` exec-of-tool recipe only ([builtin rules][ji8]) |
| loginuid/session | ✗ | no loginuid/session field in Process ([types.go#L1064][ji3]) |
| container id | ✓ | enricher via docker/containerd sockets ([containers][ji24]) |
| image | ✓ | image name/tag/id/digest from enricher ([containers][ji24]) |
| pod/namespace/labels | partial | pod/namespace from runtime labels "if applicable"; no K8s API ([containers][ji24]) |
| privileged flag | ✓ | `Privileged` in enricher metadata ([containers][ji24]) |
| runtime events | partial | `runc_suspicious_exec` recipe; no container lifecycle event ([builtin rules][ji8]) |
| K8s audit | ✗ | no audit source among event categories ([events][ji25]) |
| tamper protection | ✗ | only "cannot be bypassed" claim; no self-protection ([security model][ji22]) |
| loss/health reporting | partial | `/health` endpoint; no eviction/miss counters ([runtime][ji26]) |
| response actions | partial | JS reactions removed; network blocking only ([architecture][ji27]) |
| prevention/enforcement | partial | synchronous egress IP/CIDR/domain policy only ([policy][ji28]) |

[ji1]: https://jibril.garnet.ai/config/caches/categories.html
[ji2]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1067-L1068
[ji3]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1064-L1094
[ji4]: https://github.com/garnet-org/jibril-recipes/blob/8d06e36b320f3f58184fa07294e9363741a05dea/recipes/code_modification_through_procfs.yaml#L30
[ji5]: https://github.com/garnet-org/jibril-recipes/blob/8d06e36b320f3f58184fa07294e9363741a05dea/recipes/binary_self_deletion.yaml#L26-L31
[ji6]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L405
[ji7]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1087
[ji8]: https://jibril.garnet.ai/rules/builtin.html
[ji9]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L42
[ji10]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L41
[ji11]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L39
[ji12]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L29-L47
[ji13]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L44
[ji14]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1275-L1288
[ji15]: https://github.com/garnet-org/jibril-recipes/blob/8d06e36b320f3f58184fa07294e9363741a05dea/recipes/global_shlib_modification.yaml#L35-L43
[ji16]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/chemistry/files.go#L35
[ji17]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1960-L1969
[ji18]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1919-L1923
[ji19]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1809-L1820
[ji20]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1811
[ji21]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1960-L2016
[ji22]: https://jibril.garnet.ai/intro/model.html
[ji23]: https://github.com/garnet-org/jibril-ashkaal/blob/0bac0ee73ab319973a40d6d1a62fdc9397fc2695/pkg/ongoing/types.go#L1233-L1239
[ji24]: https://jibril.garnet.ai/config/containers.html
[ji25]: https://jibril.garnet.ai/config/events.html
[ji26]: https://jibril.garnet.ai/config/runtime.html
[ji27]: https://jibril.garnet.ai/intro/arch.html
[ji28]: https://jibril.garnet.ai/config/policy.html

</details>

<details>
<summary>ByteDance Elkeid (driver + driver plugin) (section: <a href="#bytedance-elkeid">Elkeid</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | `execve`(59) argv, run_path, tty; env only SSH/LD_PRELOAD ([README#L230][ek1]) |
| exit | partial | `process exit`(60) off by default; no exit code ([README#L247][ek2]) |
| fork/clone | ✗ | no fork/clone hook in hook list ([hook list][ek3]) |
| credential change | partial | `update_cred`(604) only non-root→root; `privilege_escalation`(611) ([README#L387][ek4]) |
| process injection | partial | `ptrace`(101) POKETEXT/POKEDATA only ([README#L98][ek5]) |
| fileless exec | partial | `memfd_create`(356); no exec-from-memfd flag ([README#L341][ek6]) |
| script/interpreter content | ✗ | no script-content hook in hook list ([hook list][ek3]) |
| TTY/interactive | ✓ | `tty` field in execve ([README#L236][ek7]) |
| lineage | ✓ | in-kernel `pid_tree` up to 12 ancestors ([smith_hook.c#L599][ek8]) |
| executable hash | partial | `exe_hash` = XxHash64(size + first 32 KiB) ([cache.rs#L141][ek9]) |
| package ownership/signature | ✗ | only package inventory in collector plugin ([README.md#L50][ek10]) |
| sensitive-file read | ✗ | `file_read`(609) documented, absent from LKM source ([README#L441][ek11]) |
| write/modify | partial | `write`(1) vfs_write kprobe, off by default ([smith_hook.c#L54][ek12]) |
| create | ✓ | `create_file`(602) via security_inode_create ([README#L364][ek13]) |
| delete | partial | `unlink`(605)/`rmdir`(606) off by default ([smith_hook.c#L59][ek14]) |
| rename | ✓ | `rename`(82) old_name/new_name ([README#L264][ek15]) |
| chmod/chown/xattr | ✗ | CHMOD switch declared; no hook registered ([smith_hook.c#L51][ek16]) |
| link/symlink | partial | `link`(86) hardlinks only ([README#L275][ek17]) |
| FIM hashing | ✗ | scanner plugin does YARA only ([README.md#L52][ek18]) |
| persistence locations | partial | create/rename events + rules; crontab inventory ([README.md#L50][ek10]) |
| dropped-file exec | partial | create_file + execve; correlation left to rule engine ([README#L364][ek13]) |
| library load / mmap exec | partial | `mprotect`(10) PROT_EXEC only, off by default ([README#L88][ek19]) |
| TCP connect/accept/listen | partial | `connect`(42) on, `accept`(43) off, no listen ([README#L90][ek20]) |
| UDP flows | partial | connected UDP only via ip4/ip6_datagram_connect ([smith_hook.c#L3979][ek21]) |
| DNS query/answer | ✓ | `dns query`(601) query, opcode, rcode; load-shed >1024/s ([README#L353][ek22]) |
| raw/packet sockets | ✗ | no raw/packet socket hook in hook list ([hook list][ek3]) |
| unix sockets | ✗ | no unix socket hook in hook list ([hook list][ek3]) |
| IPv6 | ✓ | tcp_v6_connect/ip6_datagram_connect hooks ([smith_hook.c#L3979][ek23]) |
| NAT post-translation tuple | ✗ | socket-level tuple only ([README#L198][ek24]) |
| HTTP/TLS metadata (SNI) | ✗ | no L7 hook in hook list ([hook list][ek3]) |
| flow volume | ✗ | no byte counters in hook list ([hook list][ek3]) |
| bind | ✓ | `bind`(49) sip/sport ([README#L218][ek25]) |
| module load | ✓ | `load_module`(603) + hidden-module scan(702) ([README#L375][ek26]) |
| BPF load | ✗ | no BPF hook in hook list ([hook list][ek3]) |
| kprobe/perf_event_open | ✗ | no perf/kprobe hook in hook list ([hook list][ek3]) |
| mount/umount | partial | `mount`(165) via security_sb_mount; no umount ([README#L315][ek27]) |
| namespaces | ✗ | no unshare/setns hook in hook list ([hook list][ek3]) |
| kexec | ✗ | no kexec hook in hook list ([hook list][ek3]) |
| sysctl write | ✗ | no sysctl hook in hook list ([hook list][ek3]) |
| time change | ✗ | no time hook in hook list ([hook list][ek3]) |
| keyring | ✗ | no keyring hook in hook list ([hook list][ek3]) |
| io_uring | ✗ | no io_uring hook in hook list ([hook list][ek3]) |
| userfaultfd | ✗ | no userfaultfd hook in hook list ([hook list][ek3]) |
| capability use | ✗ | no capability hook in hook list ([hook list][ek3]) |
| login/logout | partial | Journal Watcher parses sshd journal, not kernel ([README.md#L51][ek28]) |
| sudo/su | partial | [INFERENCE] execve + `update_cred` to root ([README#L387][ek4]) |
| user/group changes | ✗ | no event; collector plugin inventories users ([README.md#L50][ek10]) |
| loginuid/session | partial | `sessionid`, `sid` in common data ([README#L141][ek29]) |
| container id | partial | UTS nodename + pid-ns inode; no runtime id ([README#L74][ek30]) |
| image | ✗ | no image field in common data ([README#L141][ek29]) |
| pod/namespace/labels | partial | pod_name from /proc environ or nodename only ([cache.rs#L30][ek31]) |
| privileged flag | ✗ | no privileged field in common data ([README#L141][ek29]) |
| runtime events | ✗ | no container lifecycle hook in hook list ([hook list][ek3]) |
| K8s audit | ✓ | K8s Audit Log collection in community edition ([README.md#L74][ek32]) |
| tamper protection | partial | anti-rootkit scans (syscall table, IDT, modules, /proc) ([README#L120][ek33]) |
| loss/health reporting | partial | ring stats ioctl; overwrite-oldest ring ([trace.c#L398][ek34]) |
| response actions | ✗ | driver is collection-only (hook list) ([hook list][ek3]) |
| prevention/enforcement | ✗ | no blocking hook in hook list ([hook list][ek3]) |

[ek1]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L230-L245
[ek2]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L247-L249
[ek3]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L82-L116
[ek4]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L387-L395
[ek5]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L98
[ek6]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L341-L349
[ek7]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L236
[ek8]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L599-L675
[ek9]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/plugins/driver/src/transformer/cache.rs#L141-L174
[ek10]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/README.md#L50
[ek11]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L441-L450
[ek12]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L54
[ek13]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L364-L372
[ek14]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L59
[ek15]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L264-L272
[ek16]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L51
[ek17]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L275-L283
[ek18]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/README.md#L52
[ek19]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L88
[ek20]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L90-L92
[ek21]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L3979-L3998
[ek22]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L353-L361
[ek23]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/smith_hook.c#L3979-L3992
[ek24]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L198-L206
[ek25]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L218-L226
[ek26]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L375-L383
[ek27]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L315-L323
[ek28]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/README.md#L51
[ek29]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L141-L149
[ek30]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L74-L80
[ek31]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/plugins/driver/src/transformer/cache.rs#L30-L70
[ek32]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/README.md#L74
[ek33]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/README.md#L120-L127
[ek34]: https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/driver/LKM/src/trace.c#L398-L415

</details>

<details>
<summary>StackRox / Red Hat ACS Collector + fact (section: <a href="#stackrox--red-hat-acs-collector-with-fact">ACS</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | partial | process signal: args, exe path; no env/cwd; containers only ([ProcessSignalFormatter.cpp#L139][ac1]) |
| exit | ✗ | procexit used for thread state; no exit signal ([KernelDriver.h#L47][ac2]) |
| fork/clone | ✗ | clone/fork captured for state only ([syscall set][ac3]) |
| credential change | ✗ | setuid family captured for state only ([syscall set][ac3]) |
| process injection | ✗ | no ptrace/process_vm_writev in syscall set ([syscall set][ac3]) |
| fileless exec | ✗ | no memfd/exec-origin data in syscall set ([syscall set][ac3]) |
| script/interpreter content | ✗ | no script-content field in process signal ([ProcessSignalFormatter.cpp#L139][ac1]) |
| TTY/interactive | ✗ | no tty field in process signal ([ProcessSignalFormatter.cpp#L139][ac1]) |
| lineage | ✓ | `lineage_info` ≤10 ancestors within container ([ProcessSignalFormatter.cpp#L362][ac4]) |
| executable hash | ✗ | no hash field in process signal ([ProcessSignalFormatter.cpp#L139][ac1]) |
| package ownership/signature | ✗ | [INFERENCE] not in process signal ([ProcessSignalFormatter.cpp#L139][ac1]) |
| sensitive-file read | ✗ | fact ignores read-only opens ([main.c#L69][ac5]) |
| write/modify | partial | fact: write-opens on monitored paths, not each write ([main.c#L69][ac5]) |
| create | ✓ | fact: FMODE_CREATED in lsm/file_open, plus mkdir ([main.c#L69][ac6]) |
| delete | ✓ | fact: lsm/path_unlink, path_rmdir ([main.c#L162][ac7]) |
| rename | ✓ | fact: lsm/path_rename from/to ([main.c#L262][ac8]) |
| chmod/chown/xattr | ✓ | fact: path_chmod/path_chown/setxattr/removexattr/set_acl ([main.c#L196][ac9]) |
| link/symlink | ✓ | fact: lsm/path_link, path_symlink ([main.c#L126][ac10]) |
| FIM hashing | ✗ | fact event_t has no content hash ([types.h#L125][ac11]) |
| persistence locations | partial | fact: only configured paths (4.10: four node paths) ([RHACS 4.10 release notes][ac12]) |
| dropped-file exec | ✗ | no exec hook in fact ([fact hooks][ac13]) |
| library load / mmap exec | ✗ | no mmap hook in fact or syscall set ([fact hooks][ac13]) |
| TCP connect/accept/listen | ✓ | connect/accept/close + /proc listen-endpoint scrape ([CollectorConfig.h#L31][ac14]) |
| UDP flows | partial | UDP via connect/optional send-recv; server role guessed ([ConnTracker.cpp#L169][ac15]) |
| DNS query/answer | ✗ | no DNS parsing; not in syscall set ([syscall set][ac3]) |
| raw/packet sockets | ✗ | no raw/packet socket handling in syscall set ([syscall set][ac3]) |
| unix sockets | ✗ | [INFERENCE] connections are L4 TCP/UDP only ([ConnTracker.cpp#L167][ac16]) |
| IPv6 | ✓ | IPv6 handled (fe80::/10 default ignore) ([references.md#L17][ac17]) |
| NAT post-translation tuple | ✗ | socket tuple only ([ConnTracker.cpp#L167][ac16]) |
| HTTP/TLS metadata (SNI) | ✗ | no L7 parsing in syscall set ([syscall set][ac3]) |
| flow volume | ✗ | no byte counters; connection stats are counts ([references.md#L56][ac18]) |
| bind | partial | listen endpoints via 30 s /proc scrape, not bind ([CollectorConfig.h#L31][ac19]) |
| module load | ✗ | not in syscall set ([syscall set][ac3]) |
| BPF load | ✗ | not in syscall set ([syscall set][ac3]) |
| kprobe/perf_event_open | ✗ | not in syscall set ([syscall set][ac3]) |
| mount/umount | ✓ | fact: lsm/sb_mount, sb_umount, move_mount ([main.c#L564][ac20]) |
| namespaces | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| kexec | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| sysctl write | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| time change | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| keyring | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| io_uring | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| userfaultfd | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| capability use | ✗ | not in syscall set or fact hooks ([syscall set][ac3]) |
| login/logout | ✗ | no login source in syscall set ([syscall set][ac3]) |
| sudo/su | ✗ | not reported ([syscall set][ac3]) |
| user/group changes | ✗ | not reported ([syscall set][ac3]) |
| loginuid/session | partial | fact records `login_uid` ([types.h#L37][ac21]) |
| container id | ✓ | container_id from cgroup ([ProcessSignalFormatter.cpp#L178][ac22]) |
| image | partial | [INFERENCE] image resolved by Sensor, not collector ([ProcessSignalFormatter.cpp#L178][ac22]) |
| pod/namespace/labels | partial | namespace label lookup; pod mapping in Sensor ([ContainerMetadata.cpp#L18][ac23]) |
| privileged flag | ✗ | only process and network signal handlers ([Service.cpp#L95][ac24]) |
| runtime events | ✗ | only process and network signal handlers ([Service.cpp#L95][ac24]) |
| K8s audit | ✗ | only process and network signal handlers ([Service.cpp#L95][ac24]) |
| tamper protection | ✗ | only process and network signal handlers ([Service.cpp#L95][ac24]) |
| loss/health reporting | ✓ | drops, ringbufferDrops, threadCacheDrops counters ([troubleshooting.md#L255][ac25]) |
| response actions | ✗ | only process and network signal handlers ([Service.cpp#L95][ac24]) |
| prevention/enforcement | ✗ | [INFERENCE] fact LSM handlers return 0 (observe only) ([main.c#L38][ac26]) |

[ac1]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ProcessSignalFormatter.cpp#L139-L170
[ac2]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/KernelDriver.h#L47-L56
[ac3]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/CollectorConfig.h#L35-L67
[ac4]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ProcessSignalFormatter.cpp#L362-L373
[ac5]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L69-L76
[ac6]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L69-L71
[ac7]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L162
[ac8]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L262
[ac9]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L196-L510
[ac10]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L126
[ac11]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/types.h#L125-L160
[ac12]: https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.10/html/release_notes/release-notes-410
[ac13]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L61-L683
[ac14]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/CollectorConfig.h#L31-L59
[ac15]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ConnTracker.cpp#L169-L172
[ac16]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ConnTracker.cpp#L167-L189
[ac17]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/docs/references.md#L17-L20
[ac18]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/docs/references.md#L56-L57
[ac19]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/CollectorConfig.h#L31-L32
[ac20]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L564-L636
[ac21]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/types.h#L37
[ac22]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ProcessSignalFormatter.cpp#L178-L182
[ac23]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/ContainerMetadata.cpp#L18-L26
[ac24]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/system-inspector/Service.cpp#L95-L106
[ac25]: https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/docs/troubleshooting.md#L255-L257
[ac26]: https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L38-L52

</details>

<details>
<summary>Kubescape node-agent (section: <a href="#kubescape-node-agent">Kubescape</a>)</summary>

| Item | Value | Basis |
|---|---|---|
| exec | ✓ | IG `trace_exec` gadget; CWD paths enabled ([exec.go#L21][ks1]) |
| exit | ✓ | exit gadget on sched_process_exit ([exit program.bpf.c#L38][ks2]) |
| fork/clone | ✓ | fork gadget on sched_process_fork ([fork program.bpf.c#L37][ks3]) |
| credential change | partial | capabilities tracer only; no setuid tracer ([capabilities.go#L21][ks4]) |
| process injection | partial | ptrace gadget (sys_enter_ptrace) only ([ptrace program.bpf.c#L51][ks5]) |
| fileless exec | ✓ | README lists fileless malware detection ([README#L46][ks6]) |
| script/interpreter content | ✗ | no script-content tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| TTY/interactive | ✓ | exec `hasTty`/`ttyMajor`/`ttyMinor` fields ([exec-tty-field.md#L1][ks8]) |
| lineage | ✓ | userspace process tree manager ([process_tree_manager.go#L32][ks9]) |
| executable hash | partial | malware manager only (default off), not per exec ([CONFIGURATION.md#L150][ks10]) |
| package ownership/signature | partial | SBOM per image (default off) ([CONFIGURATION.md#L153][ks11]) |
| sensitive-file read | ✓ | open tracer + "Sensitive file access" rules ([README#L346][ks12]) |
| write/modify | partial | open flags only; no write event ([open.go#L22][ks13]) |
| create | partial | O_CREAT flag in open events only ([open.go#L22][ks13]) |
| delete | ✗ | no unlink tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| rename | ✗ | no rename tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| chmod/chown/xattr | ✗ | no chmod/chown/xattr tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| link/symlink | ✓ | hardlink + symlink gadgets ([hardlink#L38][ks14], [symlink#L33][ks15]) |
| FIM hashing | partial | `fimEnabled` FIM manager, default off ([CONFIGURATION.md#L157][ks16]) |
| persistence locations | partial | rules over open events ([README#L346][ks12]) |
| dropped-file exec | partial | rule-level correlation over exec/open ([README#L346][ks12]) |
| library load / mmap exec | ✗ | no mmap tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| TCP connect/accept/listen | partial | socket-filter network gadget gives peers, not syscalls ([network program.bpf.c#L48][ks17]) |
| UDP flows | ✓ | network gadget ([network.go#L24][ks18]) |
| DNS query/answer | ✓ | IG `trace_dns` gadget ([dns.go#L29][ks19]) |
| raw/packet sockets | ✗ | no raw-socket tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| unix sockets | ✗ | no unix-socket tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| IPv6 | ✓ | [INFERENCE] IG network/dns gadgets handle IPv6 ([network.go#L24][ks18]) |
| NAT post-translation tuple | ✗ | no NAT tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| HTTP/TLS metadata (SNI) | partial | HTTP parsing gadget (default off); no TLS/SNI ([http.go#L124][ks20]) |
| flow volume | ✗ | no flow-volume tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| bind | ✗ | no bind tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| module load | ✓ | kmod gadget (init_module/finit_module) ([kmod program.bpf.c#L40][ks21]) |
| BPF load | ✓ | bpf gadget (sys_enter_bpf) ([bpf program.bpf.c#L40][ks22]) |
| kprobe/perf_event_open | ✗ | no perf/kprobe tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| mount/umount | ✗ | no mount tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| namespaces | ✓ | unshare gadget; setns not found ([unshare program.bpf.c#L40][ks23]) |
| kexec | ✗ | no kexec tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| sysctl write | ✗ | no sysctl tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| time change | ✗ | no time tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| keyring | ✗ | no keyring tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| io_uring | ✓ | io_uring gadgets (new/old) ([iouring.go#L23][ks24]) |
| userfaultfd | ✗ | no userfaultfd tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| capability use | ✓ | IG `trace_capabilities` gadget ([capabilities.go#L21][ks4]) |
| login/logout | partial | SSH gadget detects SSH banner in traffic ([ssh README#L3][ks25]) |
| sudo/su | ✗ | no sudo/su tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| user/group changes | ✗ | no user/group tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| loginuid/session | ✗ | no loginuid tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| container id | ✓ | container lifecycle callbacks ([containercallback.go#L45][ks26]) |
| image | ✓ | [INFERENCE] container collection carries image ([containercallback.go#L45][ks26]) |
| pod/namespace/labels | ✓ | K8s namespace selectors in rule bindings ([README#L332][ks27]) |
| privileged flag | partial | [INFERENCE] pod spec via K8s API; no field verified ([containercallback.go#L45][ks26]) |
| runtime events | ✓ | container add/remove callbacks ([containercallback.go#L45][ks26]) |
| K8s audit | ✗ | no audit tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| tamper protection | ✗ | no self-protection tracer in tracer list ([tracer_factory.go#L96][ks7]) |
| loss/health reporting | partial | health manager; Prometheus metrics ([health_manager.go#L20][ks28]) |
| response actions | partial | seccomp profile generation (default off) ([CONFIGURATION.md#L155][ks29]) |
| prevention/enforcement | ✗ | no enforcement option in config ([CONFIGURATION.md#L146][ks30]) |

[ks1]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/exec.go#L21
[ks2]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/exit/program.bpf.c#L38
[ks3]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/fork/program.bpf.c#L37
[ks4]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/capabilities.go#L21
[ks5]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/ptrace/program.bpf.c#L51
[ks6]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/README.md#L46
[ks7]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/tracer_factory.go#L96-L310
[ks8]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/features/exec-tty-field.md#L1-L10
[ks9]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/processtree/process_tree_manager.go#L32
[ks10]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L150
[ks11]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L153
[ks12]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/README.md#L346
[ks13]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/open.go#L22
[ks14]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/hardlink/program.bpf.c#L38
[ks15]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/symlink/program.bpf.c#L33
[ks16]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L157
[ks17]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/network/program.bpf.c#L48
[ks18]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/network.go#L24
[ks19]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/dns.go#L29
[ks20]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/http.go#L124-L126
[ks21]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/kmod/program.bpf.c#L40
[ks22]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/bpf/program.bpf.c#L40
[ks23]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/unshare/program.bpf.c#L40
[ks24]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/tracers/iouring.go#L23
[ks25]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/ebpf/gadgets/ssh/README.md#L3
[ks26]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/containerwatcher/v2/containercallback.go#L45
[ks27]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/README.md#L332-L340
[ks28]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/pkg/healthmanager/health_manager.go#L20
[ks29]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L155
[ks30]: https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/CONFIGURATION.md#L146-L163

</details>

## In-kernel techniques worth copying

Each technique is tied to the panopticon principle it serves ([design.md](../design.md#principles)) and to what panopticon already does. "Already" means the design or prototype has it; "new" means it is not in the design.

### Hook placement and gating (principle 1)

1. **No per-syscall tracepoints at all, not just no raw ones.** One `syscalls:sys_enter_<name>` attachment puts every task on the syscall-tracepoint slow path ([tracepoint.c#L800-L814](https://github.com/torvalds/linux/blob/v6.12/kernel/tracepoint.c#L800-L814)). elastic/ebpf (`sys_exit_setsid`, `sys_enter_memfd_create`), quark (`sys_exit_getpid`), Pulsar (`sys_exit_accept*`) and KubeArmor (`sys_exit_openat`, `setns`) each pay this for one or two events that have semantic alternatives. Already: panopticon hooks no syscall tracepoint; its admin class covers module and kexec loads, mounts, setns, clock changes and credential changes with LSM hooks, `fentry/proc_sys_write`, `fexit/create_new_namespaces` and the `*ns_install` callbacks ([design.md](../design.md#admin-operations)). Keep it that way when adding rare events.
2. **LSM-first with a kprobe twin from one macro.** Pulsar's `PULSAR_LSM_HOOK` compiles each hook to `lsm/<hook>` or `kprobe/security_<hook>` ([common.bpf.h#L33-L90](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/common.bpf.h#L33-L90)); elastic/ebpf does the same for fentry/kprobe ([EbpfEvents.c#L313-L551](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/non-GPL/Events/Lib/EbpfEvents.c#L313-L551)). Fallbacks are not needed for panopticon (kernel ≥ 6.15), but these agents show LSM programs used purely as telemetry points: Pulsar and quark's nova backend pass the previous verdict through ([common.bpf.h#L72-L80](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/common.bpf.h#L72-L80), [nova.bpf.c#L516-L518](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/nova.bpf.c#L516-L518)) and `fact`'s handlers return 0 [INFERENCE from its handlers]. Panopticon's `lsm.s/bprm_committed_creds` is the same kind of use.
3. **Kernel indexes as the gate.** The Auditbeat comment that the kernel skips `fsnotify()` on superblocks without marks ([path_inotify.go#L55-L62](https://github.com/elastic/beats/blob/6966d4422ef249fb3d48bbe27f32994bb5537dd3/auditbeat/module/file_integrity/kprobes/path_inotify.go#L55-L62)) is independent confirmation of the mechanism behind panopticon's +1.5 ns unrelated-open cost. Already. Contrast: Wazuh's eBPF FIM and Auditbeat's eBPF backend hook `vfs_*`/LSM for every file write host-wide and filter paths in userspace ([ebpf_whodata.cpp#L211-L251](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/ebpf_whodata.cpp#L211-L251)).
4. **An inode set that grows with the tree** (ACS `fact`): watched `(dev, ino)` in a hash, plus "parent is watched" → add the new child ([main.c#L61-L124](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/main.c#L61-L124)). This is a BPF-map analogue of fsnotify marks that follows files and directories created under a watched directory. Panopticon's directory marks already see new files and replacement by rename, but not subdirectories created after startup ([design.md](../design.md#credentials-persistence-and-integrity)); a mark-on-create step (adding a mark when a watched directory reports a new subdirectory) would close that gap with the same kernel index instead of a map. New. A `fact`-style map costs a program on every `file_open` (+12 ns for any `security_file_open` program, [design.md](../design.md#gating-with-kernel-indexes)).
5. **Register containers before they start.** Inspektor Gadget marks runtime binaries with fanotify `FAN_OPEN_EXEC_PERM`, so the kernel blocks `runc` until the agent has read the container's `config.json` ([container-hook/tracer.go#L15-L31](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/container-hook/tracer.go#L15-L31)); Tetragon uses OCI/NRI hooks for the same reason ([runtime-hooks.md#L7-L30](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/docs/content/en/docs/concepts/runtime-hooks.md#L7-L30)). New; relevant to panopticon's open question on marking sensitive files inside containers at start.

### Deciding in the kernel (principle 4)

6. **Precompute per-process predicates at exec, test a bit at the event.** Tetragon resolves `matchBinaries` into a bitset in the process entry at exec ([bpf_mbset.h#L9-L46](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_mbset.h#L9-L46)); Pulsar inherits an interest bit at fork and recomputes it at exec ([interest_tracking.bpf.h#L69-L141](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/interest_tracking.bpf.h#L69-L141)); Tracee answers 64 policies with one lookup using bitmask values ([filtering.h#L99-L156](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/common/filtering.h#L99-L156)). Panopticon already keeps spawner and image key in task storage; per-process flags (for example "exclude this image from file coalescing") would fit the same storage. New if needed.
7. **Cheap filters before expensive extraction.** Tetragon runs cgroup and process filters before any `d_path` ([generic_calls.h#L42-L99](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/generic_calls.h#L42-L99)); Datadog rejects chmod/chown before its path walk but not opens ([setattr.h#L63-L82](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/setattr.h#L63-L82), [open.h#L81-L129](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/hooks/open.h#L81-L129)); `fact` resolves the path before its inode check. Panopticon: the coalescing lookup in the file class should precede name and path copies. Already partly (the hook only runs for marked inodes).
8. **First-seen dedup keyed by process image and object.** Kunai: first read and first write per (thread, inode) ([fs.rs#L13-L90](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L13-L90)). Datadog: one full record per (ppid, exe, file, comm), then an 8-byte cookie refresh every 30 s ([approvers.h#L497-L587](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/approvers.h#L497-L587)). quark: the dedup bit is set only after the ring write succeeded, and the key carries start time and `self_exec_id` so pid reuse and a new image never suppress ([Process/Probe.bpf.c#L102-L155](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/elastic-ebpf/GPL/Events/Process/Probe.bpf.c#L102-L155)). Tracee: one `file_modification` per open ([tracee.bpf.c#L4910-L5069](https://github.com/aquasecurity/tracee/blob/2f9dc40c20b17c2ba27f6d92b25e62790bd48a62/pkg/ebpf/c/tracee.bpf.c#L4910-L5069)). Sysmon: UDP 4-tuple once per 30 minutes ([sysmonUDPsend.c#L173-L192](https://github.com/microsoft/SysmonForLinux/blob/62523fd44d9f7cad51dc21d0e465829a29eab6e2/ebpfKern/sysmonUDPsend.c#L173-L192)). Panopticon already coalesces file events per (process key, `self_exec_id`, inode, mask) and flushes exact repeat counts with a map iterator ([design.md](../design.md#credentials-persistence-and-integrity)); none of these five report repeat counts. Two details are worth taking: quark's "mark seen only after a successful write", so a dropped first record is retried, and a time window like Sysmon's for the UDP destination set (which saturates permanently after 16 records, [design.md](../design.md#network-attribution)) and DNS queries.
9. **Summarize at the throttle point instead of dropping silently.** Kunai emits one `error` record when a task crosses its file-event rate and drops the rest of that second ([fs.rs#L92-L177](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/fs.rs#L92-L177)); KubeArmor emits one threshold record per container ([shared.h#L602-L672](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/shared.h#L602-L672)); Tetragon emits throttle start/stop per cgroup ([bpf_rate.h#L73-L148](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/process/bpf_rate.h#L73-L148)). Panopticon's open limit (LRU eviction above 4,096 active keys loses counts without a loss record, [design.md](../design.md#credentials-persistence-and-integrity)) could use the same pattern: count evictions per CPU and report them as loss. New.
10. **Invalidate by generation counters, not scans.** Datadog invalidates inode discarders with a global revision on ruleset reload, a per-mount revision on umount and directory rename, and a 5 s retention on renamed or unlinked inodes ([discarders.h#L54-L293](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/discarders.h#L54-L293)); `path_id` counters per mount keep cached names from outliving a rename ([filesystem.h#L14-L86](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/filesystem.h#L14-L86)). Panopticon's `self_exec_id` in keys is the same idea for process images. Already, for images.

### Records and identities (principles 2 and 3)

11. **Self-contained records.** elastic/ebpf and quark write pids with start time, creds, tty, namespace inodes, cgroup path and resolved paths into every record and read `/proc` only at startup ([Process/Probe.bpf.c#L139-L206](https://github.com/elastic/ebpf/blob/51b6ec73e00b9bb0d8612ae237576b9af410dac6/GPL/Events/Process/Probe.bpf.c#L139-L206), [quark.c#L4796-L4805](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/quark.c#L4796-L4805)). Counter-examples: Datadog ships kernel keys and resolves paths, processes and containers later from a ~27 MB kernel dentry LRU, userspace caches and `/proc`; Falco and osquery rebuild fd tables. Already: panopticon records carry kernel identities; its pidfs inode is stronger than the `(pid, ktime)` or `(tgid, start time)` keys used by Tetragon and Kunai because it is never reused.
12. **Exec arguments from the new mm, after the point of no return.** Tracee, Inspektor Gadget and Tetragon read argv from `mm->arg_start` at `sched_process_exec`, which avoids the TOCTOU of reading the user `argv` array at syscall entry ([trace_exec/program.bpf.c#L251-L276](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L251-L276)). Already: panopticon emits exec at `bprm_committed_creds`.
13. **Drift detection in the exec record.** Inspektor Gadget flags executables on an overlayfs upper layer by checking the superblock magic and `__upperdentry` ([trace_exec/program.bpf.c#L229-L249](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/gadgets/trace_exec/program.bpf.c#L229-L249)); Falco carries the same as an exec flag (`EXE_UPPER_LAYER`, [event_table.c#L1993-L2027](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/event_table.c#L1993-L2027)) and Tetragon records the link count of deleted executables. Panopticon's exec record already carries mode, link count and filesystem magic, which expose setuid binaries, deleted executables and memfd execution ([design.md](../design.md#identity-and-process-records)). New: an upper-layer bit would add dropped-file exec in containers, a row where most agents are partial.
14. **Kernel socket → process table instead of fd mirrors.** Inspektor Gadget's socket enricher keys `{netns, family, proto, port}` to the owning process at bind/connect/sendmsg and removes it at release ([socket-enricher.bpf.c#L250-L304](https://github.com/inspektor-gadget/inspektor-gadget/blob/df1a6277355119a17201a9aea0f531d9553a62ec/pkg/socketenricher/bpf/socket-enricher.bpf.c#L250-L304)). Panopticon keys flows by socket cookie in socket-local storage, which needs no table. Already, and simpler.

### Transport and loss (principles 5 and 6)

15. **No wakeups.** Falco submits every record with `BPF_RB_NO_WAKEUP` and polls with a 500 µs → 30 ms backoff ([ringbuf_store_params.h#L173-L179](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/ringbuf_store_params.h#L173-L179), [scap_modern_bpf.c#L54-L71](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/userspace/libscap/engine/modern_bpf/scap_modern_bpf.c#L54-L71)); Kunai polls perf buffers. Every other agent pays a wakeup per record or the ringbuf's default notification. Already: panopticon polls every 10 ms.
16. **Loss counted at the producer, per class.** Falco: per-CPU `n_drops_buffer_*` per event class ([struct_definitions.h#L71-L95](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/shared_definitions/struct_definitions.h#L71-L95)). Tetragon: `sent_failed[opcode][errno]` per CPU ([process.h#L590-L656](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/bpf/lib/process.h#L590-L656)). Datadog: `{bytes, count, lost}` per event type per CPU, read through double-buffered stats maps ([perf_ring.h#L52-L63](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/perf_ring.h#L52-L63), [buffer_selector.h](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/c/include/helpers/buffer_selector.h)). `fact`: total/added/error/ignored/ringbuffer-full per hook ([types.h#L175-L206](https://github.com/stackrox/fact/blob/710d85818e150606d2b4ef062219ff8aefcf0394/fact-ebpf/src/bpf/types.h#L175-L206)). Already: per-ring drop counters. New: counting filter decisions (ignored, coalesced) next to drops, as `fact` does, makes the coalescing ratio observable.
17. **No timestamp merge in the consumer.** Falco's k-way merge across rings is called "almost certain[ly]" the bottleneck on 128-CPU hosts ([libs#1557](https://github.com/falcosecurity/libs/issues/1557)); osquery holds events 5 s to reorder; Datadog reorders perf events; Kunai synchronizes all CPU readers at a barrier. Already: panopticon's decoder indexes identities in a first pass and does not order the stream.
18. **Preemption-safe scratch.** Falco claims one of two per-CPU scratch slots by `cmpxchg` because a tracepoint program can be preempted mid-build on preemptible kernels ([auxmap_store_params.h#L62-L129](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/helpers/store/auxmap_store_params.h#L62-L129)); Pulsar picks one of three slots with a per-CPU nesting counter ([output.bpf.h#L10-L122](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/bpf-builder/include/output.bpf.h#L10-L122)). Panopticon writes records directly into its ring under `bpf_preempt_disable()`; the nesting-counter pattern is a candidate for the nat class, which can run in softirq and process context (the busy-flag open question in [design.md](../design.md#transport-1)).
19. **Startup state from BPF iterators.** Falco (0.44+) and Inspektor Gadget dump tasks and fds with `iter/task` and `iter/task_file` instead of parsing `/proc` ([iterators/README.md](https://github.com/falcosecurity/libs/blob/f13bc241815d463be433e947b90f42713df1abf9/driver/modern_bpf/programs/attached/iterators/README.md)). Already for tasks; panopticon still reads `/proc/<pid>/exe` for executable paths because `bpf_d_path` on `mm->exe_file` is rejected ([design.md](../design.md#identity-and-process-records)).

### Tamper resistance (new)

20. **Freeze configuration maps.** quark freezes its maps after load and marks the trusted-pid map `BPF_F_RDONLY_PROG` ([CHANGES#L204-L209](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/CHANGES#L204-L209), [bpf_queue.c#L1193-L1232](https://github.com/elastic/quark/blob/c1042f70797e1b72b584a8c4ea69408d8ce91acc/bpf_queue.c#L1193-L1232)); SunnyMapBPF shows the cost of not doing so ([README](https://github.com/azqzazq1/SunnyMapBPF/blob/ceacd5f2b9e8424e462af0a66ce735efbd285831/README.md)). Kunai's optional `lsm/task_kill` and `lsm/ptrace_access_check` keep other processes from signalling or tracing the agent ([lsm.rs#L22-L89](https://github.com/kunai-project/kunai/blob/93582844db929860138a87d69f48a2af11eae43a/kunai-ebpf/src/probes/lsm.rs#L22-L89)). Panopticon's design has no tamper section; its rings are writable mmaps by design, but the inotify group address and other control values could be frozen.

### Counter-examples worth remembering

- A program on `sched_switch` (ACS Collector to refresh thread state, Pulsar to catch re-parenting): it runs on every context switch ([sched_switch.bpf.c](https://github.com/stackrox/falcosecurity-libs/blob/8d029795c5330842df2630a5c3023aba0abde46a/driver/modern_bpf/programs/attached/events/sched_switch.bpf.c), [probes.bpf.c#L563-L597](https://github.com/exein-io/pulsar/blob/f6d27fa00b7e1922d2d5bf1dcfef7c816bcc39c1/crates/modules/process-monitor/probes.bpf.c#L563-L597)). Panopticon's spawner in task storage replaces both uses.
- Filtering after transport: ACS Collector drops host processes in userspace ([Service.cpp#L61-L89](https://github.com/stackrox/collector/blob/53f1ef8af9be20adc1c646c805f3487e930a429b/collector/lib/system-inspector/Service.cpp#L61-L89)); Kubescape's benchmark shows ingestion and enrichment dominate its CPU, not rule evaluation ([benchmark-results.md](https://github.com/kubescape/node-agent/blob/c1519c3e183c38d74faed7b93a0b10ebfa680f6e/docs/dedup-testing/benchmark-results.md)).
- Userspace-driven suppression: Elkeid pushes any executable above 150 events/s into a kernel allowlist ([transformer.rs#L217-L235](https://github.com/bytedance/Elkeid/blob/c906c512d20c0d56f2b779b8558ed69abae718c8/plugins/driver/src/transformer.rs#L217-L235)), so a noisy binary silences itself [INFERENCE]. Suppression must be counted.
- Backpressure on the workload: audit sleeps the generating task when its backlog is full ([audit.c#L1926-L1955](https://github.com/torvalds/linux/blob/028ef9c96e96197026887c0f092424679298aae8/kernel/audit.c#L1926)). Panopticon drops and counts instead.
- Losing events silently: KubeArmor's enforcer and Wazuh's eBPF FIM return without counting when a ringbuf reservation fails ([enforcer.bpf.c#L444-L451](https://github.com/kubearmor/KubeArmor/blob/3b5c8f74476ec7bcbdb2bf451a96ab3318b2ef72/KubeArmor/BPF/enforcer.bpf.c#L444-L451), [modern.bpf.c#L349-L351](https://github.com/wazuh/wazuh/blob/bbd1cea999dd661483c3e5f51345385caa853319/src/syscheckd/src/ebpf/src/modern.bpf.c#L349-L351)); Jibril's map-polling design replaces drops with LRU evictions that are not counted ([caches](https://jibril.garnet.ai/config/caches/)).

## Open questions

1. **Cost of the syscall-tracepoint slow path alone on 7.0.** No project publishes the cost of `SYSCALL_WORK_SYSCALL_TRACEPOINT` without a BPF program running. Panopticon measured +14 ns with an empty raw tracepoint program; measuring a single unrelated `syscalls:sys_enter_<name>` attachment would show what elastic/ebpf, quark, Pulsar and KubeArmor pay for their one or two syscall tracepoints, and would quantify the cost of any future exception in panopticon.
2. **NAT hooks across module reloads.** Datadog reports losing hooks in kernel modules on reload and attaches NAT probes only if `nf_nat` is loaded at start ([LPC 2023 slides p.12](https://lpc.events/event/17/contributions/1582/attachments/1328/2673/Troubles%20and%20Tidbits%20from%20Datadog%E2%80%99s%20eBPF%20Journey%20v2.pdf), [event_types.go#L178-L183](https://github.com/DataDog/datadog-agent/blob/7619c1de291765f5553bb5911af3e1386522a4b9/pkg/security/ebpf/probes/event_types.go#L178-L183)). Panopticon's planned `fexit/nf_nat_setup_info` needs the same handling (attach when `nf_nat` loads, re-attach after unload/load) unless the module is built in on the target hosts. No surveyed agent exports the post-NAT tuple, so there is no prior art for the record itself.
3. **Container file marks at container start.** fanotify `FAN_OPEN_EXEC_PERM` on runtime binaries (Inspektor Gadget) blocks container start until the agent acts; marking through `/proc/<pid>/root` after `cgroup_mkdir` does not block but races the container's first opens. Which is acceptable, and what does each cost per container start?
4. **Directories created after startup.** Panopticon's directory marks do not cover subdirectories created later. Is marking a new subdirectory when its watched parent reports `IN_CREATE` enough, or does a race window (files created in the new directory before the mark lands) need a `fact`-style inode set as a backstop, at +12 ns per `file_open`?
5. **Counting coalescing evictions.** The file-class LRU can evict pending counts without a loss record. Kunai, KubeArmor and Tetragon emit a summary record at their throttle points; can the coalescing map count evictions per CPU cheaply (for example by checking whether an update replaced a live entry), and should the UDP destination set report its saturation the same way?
6. **io_uring coverage of panopticon's own hooks.** The design verified an io_uring read of a marked file. [INFERENCE] io_uring `IORING_OP_CONNECT` and `IORING_OP_SEND*` should reach `tcp_v4_connect` and `udp_sendmsg`, which panopticon hooks, but this has not been tested; the 43-action coverage run in `bench/` could add io_uring connect and sendmsg cases.
7. **Rows panopticon leaves empty.** By its goal and admin-hook choices panopticon does not collect library loads or `mmap` with `PROT_EXEC` (deliberately not hooked on hot paths), script content, package ownership, HTTP/TLS metadata or flow volume ([design.md](../design.md#goal), [#admin-operations](../design.md#admin-operations)). Library loads are the row other agents fill most often (Tetragon's loader sensor, Tracee's `shared_object_loaded`, Kunai's `mmap_exec`, Datadog's `mmap`). Tetragon's loader sensor gets them from perf mmap records filtered by a kprobe that acts only for its own perf event ([loader_linux.go#L123-L207](https://github.com/cilium/tetragon/blob/31e646a5ed0c965c49b7e6a21166d38eb17ff6c5/pkg/sensors/tracing/loader_linux.go#L123-L207)); what that costs per `mmap` on 7.0 is unmeasured.
8. **Tamper model.** Which control maps can be frozen after load, whether a BPF token or LSM self-protection (Kunai's harden mode) is in scope, and how loss of the agent itself is reported.
9. **An independent benchmark on 7.0.** The published numbers are on kernels 4.14-6.11 with inconsistent configurations. Running Tetragon's base sensor, Tracee's default set and Datadog's default configuration through `bench/falco.sh` would give the first comparable figures on one host.
