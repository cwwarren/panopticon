# Parity with current agents

Where panopticon stands against the agents surveyed in `docs/research/`, what it took to get there,
and what is left out on purpose. Status is the code at the commit that last changed this file.

Sources:

- `docs/research/open-source-agents.md`: 17 open-source agents, a 58-item coverage matrix with a
  cited basis per cell.
- `docs/research/commercial-sensors.md`: 23 commercial sensors, table stakes and differentiators.
- `docs/research/beyond.md` §3.3–§4: detection demand, i.e. the share of Sigma (249), Elastic (544)
  and Falco (96) Linux rules that need each capability.

## The 58-item matrix

✓ = recorded with its key fields; partial = recorded for a subset or with fields missing; ✗ = not
recorded. Other agents' cells are copied from the open-source survey.

### Process

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| exec | ✓ | `lsm.s/bprm_committed_creds`: path, argv, ids, caps, cwd, tty, exe metadata | ✓ | ✓ | ✓ | partial |
| exit | ✓ | `tp_btf/sched_process_exit` when the last thread exits: status, signal, CPU time | ✓ | ✓ | ✓ | ✓ |
| fork/clone | partial | No fork records by design; spawner and image keys carry lineage, including fork-only children | ✓ | partial | ✓ | partial |
| credential change | ✓ | `task_fix_setuid`, `task_fix_setgid`, `capset` | ✓ | ✓ | ✓ | ✓ |
| process injection | ✓ | `ptrace_access_check` in attach mode: ptrace, `/proc/<pid>/mem`, `process_vm_*`, `pidfd_getfd` | ✓ | partial | ✓ | partial |
| fileless exec | ✓ | Exec record: link count 0, tmpfs magic, `/memfd:` path; overlay upper-layer flag | partial | ✓ | ✓ | ✓ |
| script/interpreter content | ✗ | No kernel path except `AT_EXECVE_CHECK` (6.14) for interpreters that opt in | ✗ | ✗ | partial | partial |
| TTY/interactive | ✓ | Controlling terminal in the exec record | ✓ | partial | partial | ✓ |
| lineage | ✓ | Spawner, parent, previous image key, pidfs process keys | ✓ | ✓ | ✓ | ✓ |
| executable hash | ✓ | SHA-256 per distinct (dev, inode, ctime), idle-priority worker | ✗ | partial | ✓ | ✓ |
| package ownership/signature | ✗ | Not implemented; no rule demand found | ✗ | ✗ | ✗ | partial |

### File

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| sensitive-file read | ✓ | inotify marks on credentials, host and inside containers | ✓ | ✓ | ✓ | ✓ |
| write/modify | partial | Watched locations only (persistence, integrity, credential directories) | partial | ✓ | ✓ | ✓ |
| create | partial | Watched locations only | ✓ | partial | partial | ✓ |
| delete | partial | Watched locations only | ✓ | partial | ✓ | ✓ |
| rename | partial | Watched locations only | ✓ | partial | ✓ | ✓ |
| chmod/chown/xattr | partial | Attribute events in watched locations | partial | partial | ✓ | ✓ |
| link/symlink | partial | Creates in watched locations | ✓ | ✓ | ✓ | partial |
| FIM hashing | ✓ | Changed regular files in watched directories, idle-priority worker | ✗ | partial | ✗ | ✓ |
| persistence locations | ✓ | cron, at, systemd (incl. new `.wants` directories), init, profiles, PAM, sudoers, sshd, udev, modprobe, APT hooks, autostart, `ld.so`, `/boot`, binary and library directories | partial | partial | partial | ✓ |
| dropped-file exec | ✓ | Executable ctime in every exec record; overlay upper-layer flag in containers | partial | partial | partial | ✓ |
| library load / mmap exec | ✗ | Deferred: see below | partial | ✓ | ✓ | ✓ |

### Network

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| TCP connect/accept/listen | ✓ | `fexit` on `tcp_v{4,6}_connect`, `inet_csk_accept`, `inet_listen` | ✓ | ✓ | ✓ | ✓ |
| UDP flows | ✓ | First send per (socket, destination), IPv4 and IPv6, from `fentry/udp_send_skb`: real source address even on unconnected sockets | partial | partial | partial | partial |
| DNS query/answer | ✓ | Query payload from the skb (a sender cannot rewrite it after the send, unlike a buffer read), answers on tagged sockets, IPv4 and IPv6 | ✗ | ✗ | ✓ | ✓ |
| raw/packet sockets | ✓ | Family constructors `packet_create`, `raw_sk_init`, `rawv6_init_sk` | ✓ | partial | partial | ✓ |
| unix sockets | partial | Connects to container runtime sockets only | ✓ | partial | ✓ | partial |
| IPv6 | ✓ | All network records | ✓ | ✓ | ✓ | ✓ |
| NAT post-translation tuple | ✓ | `fexit/nf_nat_setup_info`; no other surveyed agent exports it | ✗ | ✗ | ✗ | partial |
| HTTP/TLS metadata | ✗ | Payload; out of scope | ✗ | ✗ | partial | partial |
| flow volume | ✗ | Out of scope: the network side has it | partial | partial | ✗ | ✓ |
| bind | ✓ | UDP binds (`fexit/inet{,6}_bind`); TCP through listen | ✓ | partial | ✓ | ✓ |

### Kernel and admin

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| module load | ✓ | `kernel_read_file` (incl. compressed modules), `kernel_load_data` | ✓ | ✓ | ✓ | ✓ |
| BPF load | ✓ | `bpf_prog_load` | ✓ | ✓ | ✓ | ✓ |
| kprobe/perf_event_open | partial | BPF kprobe programs through `bpf_prog_load`; perf events not hooked | partial | ✓ | ✓ | partial |
| mount/umount | ✓ | `sb_mount`, `move_mount`, `sb_pivotroot`, `sb_umount` | ✓ | partial | ✓ | partial |
| namespaces | ✓ | `create_new_namespaces`, eight `*ns_install` callbacks, `userns_create` | ✓ | ✓ | ✓ | partial |
| kexec | ✓ | Privileged loads through the kernel read hooks | partial | partial | ✓ | partial |
| sysctl write | ✓ | `fexit/proc_sys_write`: name, result, and the value the kernel holds afterwards for value-type handlers | partial | partial | partial | ✓ |
| time change | ✓ | `settime` | partial | partial | ✓ | partial |
| keyring | ✗ | Low demand | partial | partial | ✓ | partial |
| io_uring | ✓ | Semantic hooks see io_uring operations (open, connect verified); setup recorded as an anonymous inode | partial | partial | partial | partial |
| userfaultfd | ✓ | `inode_init_security_anon` | ✓ | partial | ✓ | partial |
| capability use | partial | Effective capabilities at exec, `capset`; `capable()` is a hot path | partial | ✓ | ✓ | partial |

### Identity

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| login/logout | partial | Login when PAM sets loginuid; logout is the session leader's exit, derived by the consumer | ✗ | ✗ | ✗ | partial |
| sudo/su | ✓ | Setuid exec plus uid changes; loginuid survives sudo | partial | ✓ | partial | ✓ |
| user/group changes | ✓ | `/etc` directory mark covers passwd, group, shadow, gshadow | partial | partial | partial | partial |
| loginuid/session | ✓ | Exec records | ✓ | partial | ✗ | ✓ |

### Container and Kubernetes

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| container id | ✓ | cgroup id on every record, container record per cgroup | ✓ | ✓ | ✓ | ✓ |
| image | ✓ | Runtime state files, once per container | ✓ | ✓ | ✓ | ✓ |
| pod/namespace/labels | partial | Pod and namespace from CRI annotations; labels need the kubelet or CRI API | ✓ | ✓ | partial | ✓ |
| privileged flag | ✓ | Docker `Privileged`, or `CAP_SYS_ADMIN` in the OCI bounding set; host PID and network flags | ✓ | ✓ | ✗ | partial |
| runtime events | partial | Container record at cgroup creation; runc's mounts, setns and BPF loads as admin records | ✓ | ✗ | ✓ | partial |
| K8s audit | ✗ | API server source, not host telemetry | ✓ | ✗ | ✗ | ✗ |

### Sensor

| Item | Panopticon | How, or why not | Falco | Tetragon | Tracee | Datadog |
|---|---|---|---|---|---|---|
| tamper protection | partial | Records other processes obtaining fds to the agent's maps and programs; configuration maps frozen; signals to the agent recorded; no prevention | ✗ | ✗ | partial | partial |
| loss/health reporting | ✓ | Drop counter per (class, CPU), loss records, coalescing counts | ✓ | ✓ | ✓ | ✓ |
| response actions | ✗ | Out of scope | partial | ✓ | ✗ | ✓ |
| prevention/enforcement | ✗ | Out of scope | ✗ | ✓ | ✗ | partial |

Totals of ✓ (of 58): panopticon 35, Tracee 34, Datadog 32, Falco 30, Tetragon 24. Partial: panopticon
14. Of panopticon's 9 ✗, five are out of scope by design (HTTP/TLS payloads, flow volume, K8s audit,
response, prevention).

## Commercial table stakes

The commercial survey's table stakes, and panopticon's status:

| Table stake | Status |
|---|---|
| Process exec with lineage and hash | ✓ |
| Process exit | ✓ |
| TCP connect/accept/listen per process | ✓ |
| File create/modify/delete | Watched locations (persistence, integrity, credentials, container credentials) |
| Container id | ✓, plus image, pod, namespace, privileged and host-namespace flags |
| Kill, network isolation, remote shell, prevention | Response and prevention: out of scope |

Of the differentiators only some commercial sensors have, panopticon records BPF, module, mount,
namespace, sysctl and clock operations, cross-process memory access, credential changes, the login
identity through sudo, and metadata-service access (connect records). It does not record terminal
output, TLS server names, flow volume or package ownership, and does not block. The commercial survey
found no sensor that documents the post-NAT tuple, and per-event drop counters only in Sysdig, Aqua
and Elastic's quark library.

## Detection demand

The ranking from `docs/research/beyond.md` §4, with panopticon's status now. Score is the mean share
of Sigma, Elastic and Falco Linux rules that need the capability.

| # | Capability | Score | Status |
|---|---|---|---|
| 1 | Process exec (image, argv) | 62.4% | ✓ |
| 2 | Lineage | 27.7% | ✓ (keys; joins are the consumer's) |
| 3 | Container context | 21.8% | ✓ id, image, pod, namespace, privileged |
| 4 | File create, modify, rename, delete, attributes | 20.1% | Watched locations; name- or extension-anywhere rules (38–44% of file rules) need a per-operation hook |
| 5 | Network connect, accept, listen | 7.9% | ✓ |
| 6 | File open of listed files | 6.3% | ✓, host and containers |
| 7 | Working directory | 3.8% | ✓ path record per new directory |
| 8 | UDP flows | 2.8% | ✓ IPv4 and IPv6 |
| 9 | TTY | 2.4% | ✓ |
| 10 | Namespaces, BPF load, userfaultfd, raw sockets, dup to socket | 2.2% | ✓; stdin/stdout/stderr socket flags in the exec record |
| 11 | DNS | 2.0% | ✓ IPv4 and IPv6 |
| 12 | Fileless exec | 1.7% | ✓ |
| 13 | Credential change | 1.2% | ✓ |
| 14 | Environment variables | 1.1% | ✗, see below |
| 15 | Process injection | 0.9% | ✓ |
| 16 | Fork / exit | 0.8% | Exit ✓; fork by design no |
| 17 | Kernel module load | 0.6% | ✓ |
| 18 | Login | 0.6% | ✓ login; logout derived |
| 19 | User and group account changes | 0.4% | ✓ |
| 20 | Mount | 0.0% | ✓ |
| 21 | Library load / mmap exec | 0.0% | ✗, see below |
| 22 | Script content | 0.0% | ✗ |

## Left out, with the cost that keeps it out

- **Environment variables** (rank 14; 6 Elastic and 2 Falco rules use about 11 fixed names such as
  `LD_PRELOAD` and `GLIBC_TUNABLES`). The environment sits in user memory after argv; finding names
  means reading every variable's prefix at each exec, about 1–1.5 µs for 50 variables at 20–30 ns per
  read [estimate], two to three times the 0.45 µs the exec program costs today. Copying the whole
  block would ship secrets. An idle-priority read of `/proc/<pid>/environ` would cost nothing on the
  exec path but misses processes that have exited.
- **File changes matched by name or extension anywhere** (38–44% of file rules). Marks cover fixed
  locations. Anything else needs a hook on every file operation; the cheapest measured is a BPF LSM
  program on `file_open` at +12 ns per open of any file.
- **Library loads** (rank 21, no rule in the three sets). `lsm/mmap_file` with `PROT_EXEC`,
  deduplicated per (executable, library), would add an estimated 0.6% to exec-heavy workloads (about
  25 mmaps per process start) [estimate].
- **Script content** (rank 22): no kernel path except `AT_EXECVE_CHECK` for interpreters that opt in.
- **Package ownership**: a userspace dpkg/rpm lookup per distinct executable; no rule demand found.
- **Keyring, perf events, capability use**: low demand; `capable()` runs on hot paths.
- **Pod labels**: need the kubelet or CRI API; the runtime's state files carry pod and namespace only.

## What parity cost

Most hooks added for parity fire only on the operation they record. Four also run for activity that
is usually unrelated; run 3 measured each:

| Hook | Fires on | Measured |
|---|---|---|
| `lsm/unix_stream_connect` | every unix stream connect | 19 ns of BPF; +9 ns end to end on a connect loop |
| `lsm/task_kill` | every signal a process sends | 7 ns of BPF; +7 ns end to end on a `tgkill` loop (103 → 110 ns) |
| `ptrace_access_check` | every ptrace-mode check, including `/proc/<pid>/stat` reads | 14–18 ns of BPF per check |
| `__nf_conntrack_confirm` | every new connection on a host with conntrack | 8–9 ns of BPF; emits only for NAT |
| `tp_btf/sched_process_exit` | every process exit (last thread) | 114 ns of BPF per exit |
| admin LSM hooks, `proc_sys_write`, namespace callbacks | the operation itself | not measurable on the workloads |
| `packet_create`, `raw_sk_init`, `rawv6_init_sk`, `inet{,6}_bind` (UDP) | socket creation of that family, UDP binds | not measurable on the workloads |

Container metadata, hashes and path resolution run in userspace, once per container, distinct binary
or directory, at idle priority where they read files. The end-to-end overhead table in
`docs/design.md` (Prototype status) is measured with all of them enabled.
