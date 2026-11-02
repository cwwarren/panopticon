# Beyond Linux agents: other operating systems, kernel facilities, research and detection demand

Research notes for Panopticon, written 2026-11-02. This document covers three things:

1. Designs from macOS and Windows that keep cost proportional to interest.
2. Linux kernel facilities from 6.x to 7.x that change what an agent can observe cheaply.
3. Research on low-overhead provenance, and what published detection content actually consumes.

It ends with a list of capabilities ranked by detection value, each with the cheapest known way to
collect it.

Conventions:

- Every claim links the source that was opened. Repository counts cite the commit hash.
- **[INFERENCE]** marks reasoning that no source states directly.
- Kernel versions are mainline releases. Mainline was at 7.4-rc1 when this was written
  ([Makefile](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Makefile?h=master)).
  The reference host runs 7.0. Features newer than 7.0 are marked **post-7.0**.
- Measurements from this repository are cited as `docs/design.md`.

## Summary

- **Exec records carry most of the detection value.** Rules that need nothing beyond exec records and
  their attributes make up:
  - 177 of 249 Sigma Linux rules (71%);
  - 321 of 544 Elastic Linux rules (59%);
  - 39 of 96 Falco rules (41%).

  In ATT&CK v20, 278 of the 355 Linux techniques and sub-techniques that have a Linux analytic name
  Process Creation or Command Execution as a data source (§3.3).
- **Lineage, container context and file changes come next.**
  - Parent or ancestor fields appear in 254 Elastic rules and 27 Falco rules.
  - Container fields appear in 89 Elastic rules and 47 Falco rules.
  - File create, modify, rename and delete appear in 31 Sigma, 113 Elastic and 26 Falco rules.
- **Roughly half of file rules name fixed paths, so kernel marks can gate them.** Rules that target
  exact paths or fixed directories account for:
  - 63 of 117 Elastic file rules;
  - 18 of 30 Sigma file rules;
  - 14 of 34 Falco file rules, plus 5 whose globs can be expanded when the marks are set.

  Most of the rest (44 Elastic, 12 Sigma, 15 Falco) match names, extensions or patterns anywhere on
  the filesystem. Those need a hook that runs for every file operation (§3.3).
- **Exec records lack attributes that rules use**, chiefly:
  - working directory (50 Elastic rules);
  - TTY or session type (20 Elastic rules, and every Falco rule's output);
  - a short, fixed list of environment variables (8 rules).
- **Other operating systems filter interest in the kernel, before building the event.**
  - macOS Endpoint Security keeps subscriptions, mute sets (including inverted, target-path mute
    sets) and a verdict cache in the kernel. The cache is keyed on (process executable, target file)
    and is invalidated when the file is written.
  - Windows ETW providers test keyword and level before building an event. Microsoft documents that
    payload filtering reduces volume, not CPU.
  - On Linux, fsnotify marks and fanotify ignore masks do this job today.
- **No BPF hook exists in fanotify as of 7.4-rc1.** Song Liu's fastpath/filter series (2024) is
  unmerged, and LWN's 2025 and 2026 LSFMM reports describe the design as open. The filesystem kfuncs
  (`bpf_get_task_exe_file`, `bpf_path_d_path`, xattr, fs-verity) remain callable only from LSM
  programs, plus `binfmt_misc` struct_ops (7.3).
- **Research collectors show that in-kernel deduplication and compact transport matter as much as
  hook choice** (§3.1).
  - KCAL suppresses redundant events in the kernel. It cut Linux Audit's overhead from 40+% to 15%
    or less, and log space by about 90%.
  - eAudit reached 4.5% overhead.
  - In eAudit's comparison, used as syscall loggers, sysdig dropped about 60% of postmark records
    and Tetragon and Tracee about 90%.
  - Several provenance IDSs (ATLAS, MAGIC, ShadeWatcher) are evaluated on graphs that keep only the
    first edge of each kind. All of them still need reads and writes of ordinary files, which
    sensitive-file gating does not provide.

---

## 1. Designs from other operating systems

### 1.1 macOS Endpoint Security (ES)

**Delivery.**

- Each `es_new_client` call opens one channel with its own subscriptions. ES enriches each message
  and enqueues it for every subscribed client at once
  ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)).
- The message is created and enqueued before the syscall returns. Delivery is asynchronous, even
  for AUTH events
  ([es_sync_client](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_sync_client(_:_:).json)).
- Per-client queues drop messages when they are full. `seq_num` (per client and event type) and
  `global_seq_num` (per client, macOS 11) make the gaps visible
  ([endpoint-sec-sys message.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/message.rs.html)).
  This is a third-party Rust binding that reproduces Apple's header comments.
- ES has no TCP, UDP or DNS events; those are left to NetworkExtension. UNIX domain sockets are
  covered ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)).

**AUTH vs NOTIFY.**

- An AUTH event holds the operation in the kernel until the client answers or the deadline passes.
  A NOTIFY event does not block
  ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)).
- When several clients answer, the most restrictive answer wins. If no client subscribes to the AUTH
  variant, the operation is allowed.
- No message at all is produced when the process that caused the event is muted, or, for AUTH
  only, when the cache already holds a result. Cache hits still produce the NOTIFY event
  ([client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html)).

**Deadlines.**

- Each message carries a deadline. A client that misses an AUTH deadline may be killed, and the
  operation gets an implicit ALLOW that is not cached
  ([deadline](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_message_t/deadline.json),
  [WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)).
- An AUTH message dropped because the queue is full is allowed by default.
- macOS 27 lets a client choose what a missed deadline does: kill (the default), fail open or fail
  closed. It can also set a shorter maximum deadline per event type
  ([es_set_deadline_miss_mode](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:).json),
  [es_set_deadline_max_milliseconds](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_set_deadline_max_milliseconds(_:_:_:_:).json)).

**AUTH cache.**

- There is one global, best-effort cache holding the combined result of all clients.
- ES invalidates entries when the file involved is written, truncated or deleted.
- `es_clear_cache` drops every entry and is rate-limited
  ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/),
  [client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html)).
- Cache keys per event ([message.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/message.rs.html)):
  - EXEC: (process executable, target executable).
  - OPEN: (process executable, file).
  - MMAP: (process executable, source file).
  - MOUNT: (process executable, mount point).
  - Attribute reads and changes: (process executable, target file).
- UNLINK, RENAME, CREATE, TRUNCATE, SETEXTATTR, KEXTLOAD, SETTIME and other mutations are not
  cacheable.
- Apple's guidance ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)):
  - Use the cache for performance, never for policy, because entries expire.
  - Consider not caching EXEC of interpreters, whose behaviour depends on their arguments.

**Muting** (the mute sets are evaluated in the kernel, following the flowchart in the header comment
in [client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html)):

- **Process muting:**
  - `es_mute_process` mutes by audit token (macOS 10.15). ES removes the entry when the process exits.
  - `es_mute_process_events` mutes only some event types (12.0).
  - ([es_mute_process](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_mute_process(_:_:).json),
    [es_mute_process_events](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_mute_process_events(_:_:_:_:).json))
- **Path muting:**
  - `es_mute_path` mutes by executable path, as a prefix or a literal, optionally per event type (12.0).
  - Target-path muting (13.0) mutes by the object of the event: the file executed or opened, both
    paths of a rename, or the target process.
  - When an event has several targets, it is suppressed only if all of them are muted.
  - ([es_mute_path](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_mute_path(_:_:_:).json),
    [client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html))
- **Inverted muting:**
  - `es_invert_muting` (13.0) turns a mute set into a selection set, separately for process,
    executable-path and target-path muting.
  - With inverted target muting, an event is selected if any target matches. Apple's example is
    file events limited to persistence locations
    ([es_invert_muting](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_invert_muting(_:_:).json),
    [WWDC22 110345](https://developer.apple.com/videos/play/wwdc2022/110345/)).
- **Hard links:** paths are matched as VFS sees them, with no special handling, so an inverted path
  watch misses access through a hard link from outside the watched paths
  ([client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html)).
- **Performance:**
  - Large path mute sets have a performance cost, and muting by audit token is cheaper.
  - Muting noisy indexers such as Spotlight "can greatly reduce the number of messages"
    ([WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/)).

**Where ES filters.**

| Mechanism | Evaluated | Saves |
|---|---|---|
| `es_subscribe` per event type | Kernel, first step of the mute flowchart | Unsubscribed events never reach a queue |
| Process, path and target-path muting, normal or inverted | Kernel | Event not delivered. Whether the message is built at all is not documented |
| AUTH cache | Kernel, global | No AUTH message, no wakeup, no blocking. The NOTIFY event still fires |
| Content decisions (signing ID, arguments, scripts) | Client, in user space | Nothing: every such event crosses the boundary |

([client.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/client.rs.html),
[WWDC20 10159](https://developer.apple.com/videos/play/wwdc2020/10159/))

**ES event types on the shared taxonomy.**

- Versions are the release that added the enum value, taken from
  [types.rs](https://docs.rs/endpoint-sec-sys/latest/src/endpoint_sec_sys/types.rs.html).
- Names were checked against
  [es_event_type_t](https://developer.apple.com/tutorials/data/documentation/endpointsecurity/es_event_type_t.json).
- A = AUTH, N = NOTIFY.

| Taxonomy | ES events | macOS |
|---|---|---|
| Process: exec, exit, fork | A/N EXEC, N EXIT, N FORK | 10.15 |
| Process: credential change | N SETUID, SETGID, SETEUID, SETEGID, SETREUID, SETREGID | 12.0 |
| Process: injection | A/N GET_TASK, A/N GET_TASK_READ, N TRACE, N REMOTE_THREAD_CREATE, A/N PROC_CHECK, A/N SIGNAL | 10.15–11.3 |
| Process: memory, fileless | A/N MMAP, A/N MPROTECT; N CS_INVALIDATED (11.0) | 10.15 |
| Process: executable hash | No event; `es_process_t` carries a kernel-validated CDHash | — |
| Process: TTY | N PTY_GRANT, N PTY_CLOSE | 10.15.4 |
| File: open, write, create, delete, rename | A/N OPEN, N CLOSE (has a `modified` flag), N WRITE, A/N CREATE, A/N UNLINK, A/N RENAME, A/N TRUNCATE | 10.15 |
| File: attributes, links | A/N SETMODE, SETOWNER, SETFLAGS, SETEXTATTR, SETACL, UTIMES, LINK | 10.15–10.15.1 |
| File: persistence | N BTM_LAUNCH_ITEM_ADD, N BTM_LAUNCH_ITEM_REMOVE | 13.0 |
| Network: unix sockets, IPC | A/N UIPC_BIND, A/N UIPC_CONNECT; N XPC_CONNECT (14.0) | 10.15.1 |
| Kernel/admin | A/N KEXTLOAD, A/N MOUNT, N UNMOUNT, A/N SETTIME, A/N IOKIT_OPEN, N PROFILE_ADD (14.0), N TCC_MODIFY (15.4) | 10.15+ |
| Identity | N AUTHENTICATION, LW_SESSION_*, OPENSSH_LOGIN/LOGOUT, LOGIN_* (13.0); N SU, N SUDO (14.0); N OD_* user and group changes (14.0) | 13.0–14.0 |

Ventura (13) added events produced in user space (authentication, login, XProtect), which removed
most remaining reasons to use the OpenBSM audit trail
([WWDC22 110345](https://developer.apple.com/videos/play/wwdc2022/110345/)).

### 1.2 Windows

**Kernel callbacks.**

| API | Fires on | Notes |
|---|---|---|
| `PsSetCreateProcessNotifyRoutineEx` / `Ex2` | Process create and exit | Can veto creation through `CreationStatus`. The payload has the inheritance parent and the real creating thread, image file and command line. At most 64 callbacks ([Ex](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), [PS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info), [Ex2](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex2)) |
| `PsSetCreateThreadNotifyRoutine(Ex)` | Thread create and delete | Notify only ([Ex](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutineex)) |
| `PsSetLoadImageNotifyRoutine(Ex)` | Image mapped, before its entry point runs | Not called for `SEC_IMAGE_NO_EXECUTE` sections ([Ex](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex)) |
| `ObRegisterCallbacks` | Create or duplicate of a process, thread or desktop handle | The pre-callback can remove access rights but never add them ([ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks), [OB_PRE_CREATE_HANDLE_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information)) |
| `CmRegisterCallbackEx` | Every registry operation | Can block or redirect. `CmSetCallbackObjectContext` attaches a per-key context ([CmRegisterCallbackEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex), [context](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-context-information)) |

The Ob and Cm callbacks take no per-target registration parameter. Within the object types and
operations they register for, every matching operation reaches the driver. **[INFERENCE from the
API shape]**

**Filesystem minifilters.**

- Filter Manager calls a minifilter only for the operations it registered
  ([concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)).
- Flags skip whole classes of I/O at registration: `SKIP_PAGING_IO`, `SKIP_CACHED_IO` (which also
  skips fast I/O) and `SKIP_NON_CACHED_NON_PAGING_IO`
  ([FLT_OPERATION_REGISTRATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_operation_registration)).
- A pre-operation callback that returns `FLT_PREOP_SUCCESS_NO_CALLBACK` skips the post-operation
  callback for that I/O
  ([doc](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/returning-flt-preop-success-no-callback)).
- `FLT_PREOP_SYNCHRONIZE` on asynchronous I/O "can severely degrade" performance
  ([pre-op callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_pre_operation_callback)).
- Opting out of whole volumes:
  - The instance setup callback can decline a volume with `STATUS_FLT_DO_NOT_ATTACH`.
  - Since the Windows 11 22H2 September update, flags tell the filter that a volume is a developer
    volume or one an administrator trusts. On such volumes anti-virus filters may skip attaching
    ([instance setup](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_setup_callback)).
- Microsoft's AvScan sample caches scan results per file:
  - It keeps the verdict in a stream context and in a per-volume table keyed by FileId, which
    exists only on NTFS, CSVFS and ReFS.
  - A revision counter invalidates the verdict on writes, zeroing and end-of-file changes.
  - The table has no upper bound, which the sample itself calls "not optimal"
    ([avscan.c](https://raw.githubusercontent.com/microsoft/Windows-driver-samples/main/filesys/miniFilter/avscan/filter/avscan.c)).

**ETW.**

- Microsoft states where ETW filtering happens and what it costs
  ([EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)):
  - Providers perform control GUID, level and keyword filtering "directly in the provider's code
    before the event is generated".
  - Events disabled by level or keyword "have almost no impact on system performance".
  - Payload and attribute filters run after the event is generated. They reduce trace volume and
    are "not as effective for reducing trace CPU overhead".
- `EventWrite` returns immediately when no session listens
  ([EventEnabled](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventenabled)).
- Filter types ([EVENT_FILTER_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor)):
  - PID scope: at most 8 processes, user-mode providers only, and only processes that exist when the
    filter is set.
  - Executable-name scope.
  - Event ID allow or deny lists of up to 64 IDs.
  - Payload filters.
  - Per-event stack-walk filters.

**ETW Threat-Intelligence provider.** Microsoft does not document it. A 2020 reverse-engineering
write-up lists the following ([undev.ninja](https://undev.ninja/introduction-to-threat-intelligence-etw/)):

- **Events:**
  - `ALLOCVM`, `PROTECTVM` and `MAPVIEW`, each local or remote;
  - `QUEUEUSERAPC_REMOTE` and `SETTHREADCONTEXT_REMOTE`;
  - `READVM` and `WRITEVM`, each local or remote;
  - suspend, resume, freeze and thaw of processes and threads;
  - driver object load.
- **Gating:** the one logging function the author analysed, `EtwTiLogReadWriteVm`, checks
  `EtwEventEnabled`, a test of the session keyword mask, before writing the event. That the others
  do the same is **[INFERENCE]**.

Consuming the provider requires an anti-malware protected process (PPL), which in turn requires an
ELAM driver that registers the service's certificate
([SealighterTI](https://raw.githubusercontent.com/pathtofile/SealighterTI/master/README.md),
[protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)).

**Sysmon.** Names come from [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
The taxonomy column is **[INFERENCE]**.

| ID | Event | Taxonomy |
|---|---|---|
| 1 | ProcessCreate (command line, parent command line, hash, ProcessGUID) | Process: exec, lineage, executable hash |
| 2 | FileCreateTime | File: chmod/chown/xattr (timestomping) |
| 3 | NetworkConnect (off by default) | Network: TCP connect/accept, UDP |
| 4, 16 | Sysmon state change, configuration change (cannot be filtered) | Sensor: health, tamper |
| 5 | ProcessTerminate | Process: exit |
| 6 | DriverLoad (signature computed asynchronously) | Kernel: module load |
| 7 | ImageLoad (off by default, "significant amount of logging") | File: library load |
| 8 | CreateRemoteThread | Process: injection |
| 9 | RawAccessRead | File: sensitive read (raw device) |
| 10 | ProcessAccess | Process: injection, credential access |
| 11 | FileCreate | File: create, persistence, dropped files |
| 12–14 | Registry create/delete, value set, rename | Persistence (no Linux equivalent) |
| 15 | FileCreateStreamHash | File: create, FIM hashing |
| 17–18 | Pipe created, connected | Network: unix sockets / IPC |
| 19–21 | WMI filter, consumer, binding | Persistence |
| 22 | DNSEvent | Network: DNS |
| 23, 26 | FileDelete (archived), FileDeleteDetected | File: delete |
| 24 | ClipboardChange | — |
| 25 | ProcessTampering (hollowing, herpaderping) | Process: fileless exec, injection |
| 27–29 | FileBlockExecutable, FileBlockShredding, FileExecutableDetected | Sensor: prevention; File: dropped-file exec |
| 255 | Error | Sensor: loss, health |

- **Filtering:**
  - Each event type has an include set and an exclude set; exclude wins.
  - Conditions on the same field are ORed; conditions on different fields are ANDed.
  - Microsoft does not document whether the driver or the service evaluates the rules
    ([Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
- **Sysmon for Linux:**
  - It replaces the driver with eBPF programs on `raw_syscalls/sys_enter` or per-syscall
    tracepoints, plus `sched_process_exit` and TCP/UDP tracepoints
    ([DEVELOP.md](https://raw.githubusercontent.com/microsoft/SysmonForLinux/main/DEVELOP.md)).
  - In the kernel it only enables the syscalls that configured events need. Field-level include and
    exclude filtering runs in user space
    ([sysmonforlinux.c](https://raw.githubusercontent.com/microsoft/SysmonForLinux/main/sysmonforlinux.c)).
  - Events with kernel wiring: 1, 3, 5, 9, 10, 11, 23, plus an eBPF-load event.
  - Its cost therefore scales with the syscall rate of the enabled syscalls. **[INFERENCE]**

### 1.3 Mechanisms worth copying

The ranking is by expected effect on Panopticon, whose principle is that a kernel index decides
whether our code runs. **[INFERENCE]**

| # | Mechanism (origin) | Linux analogue | For Panopticon |
|---|---|---|---|
| 1 | Select events by a kernel-held object index: ES inverted target-path muting; minifilters called only for registered operations | fsnotify inode, mount, filesystem and mount-namespace marks ([fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)). An inode-storage tag checked first in an LSM program | Already the file-class design. ES's hard-link caveat favours inode marks over path matching **[INFERENCE]** |
| 2 | Verdict cache keyed on (actor executable, target file), invalidated on modification: ES AUTH cache, AvScan FileId cache | A fanotify ignore mask set without `FAN_MARK_IGNORED_SURV_MODIFY` "is cleared when a modify event occurs" ([fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)). inotify has no ignore masks ([inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)) | The current per-second coalescing is a time-based version. An (image key, inode) cache cleared on write would also suppress repeats across windows **[INFERENCE]** |
| 3 | Test whether the event is enabled before building it: ETW keyword and level, ETW-TI `EtwEventEnabled` | Tracepoints and LSM slots use static keys ([static keys](https://docs.kernel.org/staging/static-keys.html), §2.1). Detach links for disabled classes | Rule: no path resolution or string copy before every reject test **[INFERENCE]** |
| 4 | Mute actors by process identity, with cleanup on exit (`es_mute_process`) | BPF task local storage | Per-class mute bit for trusted noisy actors, keyed by the process key **[INFERENCE]** |
| 5 | Skip a whole volume (`STATUS_FLT_DO_NOT_ATTACH`, Dev Drive) | Mount and filesystem scope of fanotify marks. A superblock check in BPF | Build and scratch filesystems **[INFERENCE]** |
| 6 | Filter cross-process access by requested rights (ObRegisterCallbacks) | `ptrace_access_check(child, mode)` receives the mode. It covers ptrace attach, `process_vm_readv/writev`, opening `/proc/<pid>/mem` and `pidfd_getfd` (§2.8) | Planned admin hook. Emit only in attach mode |
| 7 | Count drops per consumer and event type (`seq_num`) | Per-class drop counters | Already done (loss records) |
| 8 | Subscriptions drive attachment (`es_subscribe`; Sysmon for Linux enables only the syscalls it needs) | Attach BPF links per enabled class | Admin sub-classes **[INFERENCE]** |
| 9 | Asynchronous enrichment (Sysmon signs images off the hot path) | User-space hashing keyed by (dev, inode, ctime) with a cache | Executable hash, package ownership **[INFERENCE]** |

Anti-patterns documented by these vendors:

- ETW payload filtering costs CPU even when the event is dropped.
- Large ES path-mute sets have a performance cost.
- Caches used as policy fail when entries expire, as with the ES AUTH cache.
- Per-file caches without a bound grow without limit, as in AvScan. Contrast
  `FAN_MARK_EVICTABLE` (5.19), whose marks do not pin inodes
  ([fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)).

---

## 2. Linux kernel facilities (6.x–7.x)

### 2.1 BPF LSM

**The basic facility.**

- `BPF_PROG_TYPE_LSM` landed in 5.7 ([KN 5.7](https://kernelnewbies.org/Linux_5.7)).
- Sleepable programs (`lsm.s`) landed in 5.10, and the set of sleepable hooks widened in 5.11
  ([KN 5.10](https://kernelnewbies.org/Linux_5.10), [KN 5.11](https://kernelnewbies.org/Linux_5.11)).
  At v7.0, 87 hooks are sleepable, among them:
  - `bprm_committed_creds`, `bprm_check_security`;
  - `file_open`, `mmap_file`, `kernel_read_file`;
  - `sb_mount`, `capset`, `settime`;
  - `bpf_prog_load`, the `socket_*` hooks, the `path_*` hooks and `inode_setxattr`.

  These hooks are not sleepable, so they cannot call sleepable kfuncs:
  - `kernel_load_data`, `task_fix_setuid`, `ptrace_access_check`;
  - `move_mount`, `sb_pivotroot`.

  ([bpf_lsm.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/bpf_lsm.c?h=v7.0))
- Rules added in 6.12:
  - A deny-list of hooks a BPF program may not attach to.
  - Return values are enforced: 0 or a negative errno, or 0/1 for three boolean hooks.

  `file_alloc_security` was added to the deny-list in 6.19
  ([git log bpf_lsm.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/kernel/bpf/bpf_lsm.c)).
- Some helpers are available only to LSM programs: inode storage, `bpf_bprm_opts_set` and the IMA
  hash helpers
  ([bpf_lsm.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/bpf_lsm.c?h=v7.0)).

**LSM static calls (6.12).**

- KP Singh's series replaced the indirect calls in each hook with static calls guarded by static
  keys ([KN 6.12](https://kernelnewbies.org/Linux_6.12),
  [commit 417c5643](https://github.com/torvalds/linux/commit/417c5643cd67a55f424b203b492082035d0236c3.patch)).
- On Unixbench with BPF LSM and SELinux it measured +3.49% on the system index, +9.55% on pipe
  throughput and +2.78% on system call overhead. LWN summarizes this as "about 3%"
  ([LWN 979683](https://lwn.net/Articles/979683/)).
- The commit says a later patch would make the BPF LSM key default to off. v7.0 contains no such
  toggle. With `bpf` in `lsm=`, every hook therefore calls the empty `bpf_lsm_<hook>` stub even when
  no program is attached
  ([security.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/security/security.c?h=v7.0)).
  **[INFERENCE from the source]**

**cgroup-scoped LSM (`BPF_LSM_CGROUP`, 6.0).**

- A shared shim in the hook's trampoline selects the program by cgroup
  ([KN 6.0](https://kernelnewbies.org/Linux_6.0),
  [trampoline.c v7.0](https://raw.githubusercontent.com/torvalds/linux/v7.0/kernel/bpf/trampoline.c)).
- The shim still runs on every hook invocation; cgroup scoping saves only the program run.
  **[INFERENCE]**
- One 2026 study on Linux 6.1 measured this "pre" filtering as cheaper than checking
  `bpf_get_current_cgroup_id` inside the program: 0.45% vs 0.85% on its process workload
  ([Houssel et al., arXiv 2608.11418](https://arxiv.org/pdf/2608.11418)).

**Hooks for the planned admin class.** At v7.0 there are 274 hooks
([lsm_hook_defs.h v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/lsm_hook_defs.h?h=v7.0)).

| Area | Hooks | Version notes |
|---|---|---|
| Module load, kexec | `kernel_read_file` (ids `READING_MODULE`, `READING_KEXEC_IMAGE`, ...), `kernel_load_data`, `kernel_module_request` | No kexec-specific hook ([kernel_read_file.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/kernel_read_file.h?h=v7.0)) |
| BPF | `bpf`, `bpf_map_create`, `bpf_prog_load`, `bpf_token_*` | Token hooks 6.9 |
| perf | `perf_event_open` | 5.5 ([KN 5.5](https://kernelnewbies.org/Linux_5.5)) |
| Mount | `sb_mount`, `sb_umount`, `sb_remount`, `sb_pivotroot`, `move_mount`, `fs_context_*` | `move_mount` 5.2. No `mount_setattr` or `fsmount` hook |
| Credentials | `task_fix_setuid`, `task_fix_setgid` (5.8), `task_fix_setgroups` (6.0), `capset`, `capable` | [KN 5.8](https://kernelnewbies.org/Linux_5.8), [KN 6.0](https://kernelnewbies.org/Linux_6.0) |
| Namespaces | `userns_create` | 6.1 ([KN 6.1](https://kernelnewbies.org/Linux_6.1)). No hook for `setns` or for unsharing other namespace types |
| userfaultfd | `inode_init_security_anon` | 5.12 ([KN 5.12](https://kernelnewbies.org/Linux_5.12)). No userfaultfd-specific hook |
| Time, keys | `settime`; `key_alloc`, `key_permission`, `key_post_create_or_update` (6.9) | [KN 6.9](https://kernelnewbies.org/Linux_6.9) |
| io_uring | `uring_override_creds`, `uring_sqpoll` (5.16), `uring_cmd` (6.0), `io_uring_setup` hook (6.15) | [KN 5.16](https://kernelnewbies.org/Linux_5.16), [KN 6.15](https://kernelnewbies.org/Linux_6.15) |
| File post-ops | `file_post_open`, `file_release`, `inode_post_setattr`, `inode_post_setxattr` and others (6.9, from moving IMA/EVM onto the LSM framework); `file_truncate` 6.2 | [KN 6.9](https://kernelnewbies.org/Linux_6.9), [KN 6.2](https://kernelnewbies.org/Linux_6.2) |
| sysctl | none | `BPF_PROG_TYPE_CGROUP_SYSCTL` (5.2) runs before `proc_handler` ([KN 5.2](https://kernelnewbies.org/Linux_5.2)) |

LWN states the basic limit: "LSM hooks are global — the LSM must respond to accesses for all files,
even if it's only interested in a subset" ([LWN 1018493](https://lwn.net/Articles/1018493/)). No mark
or mask decides whether a BPF LSM program runs.

### 2.2 fanotify and fsnotify

| Feature | Version |
|---|---|
| `FAN_MARK_FILESYSTEM`, `FAN_REPORT_TID` | 4.20 |
| `FAN_OPEN_EXEC(_PERM)` | 5.0 |
| `FAN_REPORT_FID` and directory-entry events (create, delete, move, attrib) | 5.1 |
| `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME` | 5.9 |
| `FAN_REPORT_PIDFD` | 5.15 |
| `FAN_FS_ERROR` | 5.16 |
| `FAN_REPORT_TARGET_FID`, `FAN_RENAME` | 5.17 |
| `FAN_MARK_EVICTABLE` (mark does not pin the inode) | 5.19 |
| `FAN_MARK_IGNORE` | 6.0 |
| `FAN_REPORT_FID` on all filesystems | 6.7–6.8 |
| `FAN_REPORT_FD_ERROR` | 6.13 |
| `FAN_PRE_ACCESS` (pre-content, range information) | 6.14 |
| Mount events `FAN_MNT_ATTACH/DETACH`, `FAN_MARK_MNTNS`, `FAN_REPORT_MNT` | 6.15 by git tag and [LWN 1075829](https://lwn.net/Articles/1075829/); the man page says 6.14 |
| User-namespace-aware superblock and mount-namespace marks | 6.16 ([KN 6.16](https://kernelnewbies.org/Linux_6.16)) |
| Per-open-file `FMODE_NOTIFY_*` bits | 6.17 ([KN 6.17](https://kernelnewbies.org/Linux_6.17)) |
| pidfds for tasks already reaped | **post-7.0**, 7.2 ([KN 7.2](https://kernelnewbies.org/Linux_7.2)) |

Sources: [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html),
[fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html),
[fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html), kernelnewbies pages as listed.

**Cost model at v7.0.** An event passes three gates before anything is allocated
([fsnotify.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/linux/fsnotify.h?h=v7.0),
[fsnotify.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/notify/fsnotify.c?h=v7.0)):

1. If the superblock has no watchers, return.
2. If the superblock, mount, inode, parent and mount namespace all have no marks, return. This
   check comes before SRCU, which the source comments call expensive.
3. If the OR of their masks lacks the event bit, return.

Only then does the kernel walk the mark lists and call the backend. This matches the design's
measurement: unrelated opens pay nothing measurable, and an open of a marked inode pays +87 ns with
an inotify mark and no BPF, most of it the inotify event allocation (`docs/design.md`).

**BPF filtering for fanotify is not merged.**

| Date | Step | Source |
|---|---|---|
| 2024-10-29 | Song Liu's "fanotify fastpath handler" RFC. Handlers built-in, as modules or as BPF, plus "bpf: Make bpf inode storage available to tracing programs" | [LWN 996394](https://lwn.net/Articles/996394/) |
| 2024-11-14 | v2, 7 patches: BPF fastpath, fs kfuncs, dentry references held by maps | [lkml v2](https://lkml.indiana.edu/hypermail/linux/kernel/2411.1/07825.html) |
| 2024-11-22 | v3 "fanotify in-kernel filter", module-based filters only | [patchew v3](https://patchew.org/linux/20241122225958.1775625-1-song%40kernel.org/) |
| 2025-05 | LSFMM+BPF: "The specifics of the design, however, remain up in the air" | [LWN 1018493](https://lwn.net/Articles/1018493/) |
| 2026-06 | LSFMM+BPF status: a BPF program to suppress redundant pre-content events is "not yet implemented" | [LWN 1075829](https://lwn.net/Articles/1075829/) |
| 7.4-rc1 | No filter or fastpath source under `fs/notify/fanotify/`. uapi `fanotify.h` identical to v7.0. No inode-storage helper for tracing programs | [tree](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/notify/fanotify?h=master), [fanotify.h master](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/fanotify.h?h=master), [bpf_trace.c master](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/trace/bpf_trace.c?h=master) |

Also not merged as of LSFMM 2026 ([LWN 1075829](https://lwn.net/Articles/1075829/)):

- restartable permission events;
- namespace-tree watches;
- cgroup watches;
- inode marks that do not pin the inode and are keyed by an inode ID.

### 2.3 IMA, EVM, fs-verity, IPE

- **IMA and EVM:**
  - IMA measurement dates from 2.6.30, appraisal from 3.7 and EVM from 3.2
    ([linux-ima wiki](https://sourceforge.net/p/linux-ima/wiki/Home/)).
  - IMA policy can `audit` file hashes at hooks such as `BPRM_CHECK`, `MMAP_CHECK`, `FILE_CHECK`,
    `MODULE_CHECK` and `KEXEC_KERNEL_CHECK`. `digest_type=verity` reuses the fs-verity digest
    ([ima_policy ABI v7.0](https://raw.githubusercontent.com/torvalds/linux/v7.0/Documentation/ABI/testing/ima_policy)).
  - IMA and EVM became regular LSMs in 6.9 ([KN 6.9](https://kernelnewbies.org/Linux_6.9)).
- **BPF access to hashes:**
  - `bpf_ima_inode_hash` landed in 5.11 and `bpf_ima_file_hash` in 5.18. Both work only in sleepable
    LSM hooks
    ([bcc kernel-versions](https://raw.githubusercontent.com/iovisor/bcc/master/docs/kernel-versions.md),
    [bpf_lsm.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/bpf/bpf_lsm.c?h=v7.0)).
  - fs-verity landed in 5.4. The `bpf_get_fsverity_digest` kfunc (6.8) is LSM-only "to avoid
    recursion", and gives a constant-time content identity for files that have verity enabled
    ([commit 67814c00](https://github.com/torvalds/linux/commit/67814c00de3161181cddd06c77aeaf86ac4cc584.patch),
    [fs_kfuncs](https://docs.kernel.org/bpf/fs_kfuncs.html)).
- **IPE** (6.12):
  - It decides on exec, kernel module and kexec from dm-verity and fs-verity properties.
  - It writes audit records 1420 (`AUDIT_IPE_ACCESS`), 1421 and 1422.
  - Success auditing is off by default: "very noisy, as IPE will check every userspace binary"
    ([IPE](https://docs.kernel.org/admin-guide/LSM/ipe.html)).

### 2.4 Audit

- **Cost model** at v7.0 ([auditsc.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/auditsc.c?h=v7.0)):
  - Once audit has ever been enabled, each new task gets an `audit_context` and the
    `SYSCALL_AUDIT` work flag, unless a `never` task rule matches.
  - From then on every syscall goes through audit entry and exit, which walks the exit-rule lists
    when rules exist.
- **Measured** on an unpinned VM in 2026-08: `getpid` took 55, 71, 428 and 791 ns with 1, 32, 128
  and 256 unrelated exit rules
  ([lkml 0/3](https://lkml.iu.edu/hypermail/linux/kernel/2608.0/12354.html)).
- **Fixes:**
  - The rule-counting fix is in master; it is not in v7.0
    ([auditfilter.c master](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/auditfilter.c?h=master)).
  - The per-syscall interest mask from the same series is not in master. **[INFERENCE from string
    search]**
- **io_uring:** audit and LSM coverage landed in 5.16 ([KN 5.16](https://kernelnewbies.org/Linux_5.16)).
- **Landlock:** audit landed in 6.15 ([KN 6.15](https://kernelnewbies.org/Linux_6.15)) and Landlock
  tracepoints in 7.3 (post-7.0) ([KN 7.3](https://kernelnewbies.org/Linux_7.3)).

Audit is the opposite of Panopticon's principle 1: a per-syscall cost on every task. Records that
other subsystems produce anyway (IPE, Landlock, fanotify `FAN_INFO`) are still usable as inputs.

### 2.5 BPF features

**Filesystem kfuncs and why they are LSM-only.**

- `bpf_get_task_exe_file`, `bpf_put_file` and `bpf_path_d_path` landed in 6.12.
  - The commit calls walking `current->mm->exe_file` directly a bug.
  - It limits the kfuncs to BPF LSM programs, sleepable or not.

  ([KN 6.12](https://kernelnewbies.org/Linux_6.12),
  [commit d08e2045ebf0](https://github.com/torvalds/linux/commit/d08e2045ebf0.patch))
- At v7.0, `bpf_fs_kfuncs_filter` admits only `BPF_PROG_TYPE_LSM`. The stated reason for the xattr
  and verity kfuncs is to avoid calling into other LSM hooks recursively
  ([bpf_fs_kfuncs.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/bpf_fs_kfuncs.c?h=v7.0),
  [fs_kfuncs](https://docs.kernel.org/bpf/fs_kfuncs.html)).
- 7.3 (post-7.0) adds `binfmt_misc` struct_ops programs; master still rejects tracing and iterator
  programs ([commit 7bddf0e9f108](https://github.com/torvalds/linux/commit/7bddf0e9f108.patch)).
- The older `bpf_d_path` helper (5.10) is allowed in more places
  ([bpf_trace.c v7.0](https://raw.githubusercontent.com/torvalds/linux/v7.0/kernel/trace/bpf_trace.c)):
  - iterator programs;
  - sleepable LSM programs;
  - fentry and fexit on an allowlist that includes `security_file_open`, `vfs_getattr` and
    `filp_close`.

  The path argument must be trusted or RCU-protected.
- A possible way to get startup executable paths without `/proc/<pid>/exe` follows from reading the
  v7.0 verifier. **[INFERENCE, untested]**
  - The design notes that the verifier rejects `bpf_d_path` on `task->mm->exe_file`. That is
    because `task_struct.mm` is untrusted.
  - `vm_area_struct.vm_mm` and `vm_file` are trusted-or-null, and `mm_struct.exe_file` is
    RCU-or-null.
  - So a non-sleepable `iter/task_vma` program could pass `&vma->vm_mm->exe_file->f_path` to
    `bpf_d_path` ([verifier.c v7.0](https://raw.githubusercontent.com/torvalds/linux/v7.0/kernel/bpf/verifier.c)).
  - A 7.1 commit confirms that "The verifier only trusts vm_mm and vm_file pointers"
    ([commit 4cbee026db54](https://github.com/torvalds/linux/commit/4cbee026db54.patch)).
  - This needs a load test on 7.0.

**xattr kfuncs.**

- `bpf_get_file_xattr` landed in 6.8 and `bpf_get_dentry_xattr` in 6.12.
- In 6.15 came `bpf_set_dentry_xattr` and `bpf_remove_dentry_xattr`, together with the
  `security.bpf.*` prefix that programs may write.
- All of them are sleepable and LSM-only
  ([bpf_fs_kfuncs.c v7.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/bpf_fs_kfuncs.c?h=v7.0)).
- `bpf_cgroup_read_xattr` landed in 6.17 ([KN 6.17](https://kernelnewbies.org/Linux_6.17)).
- A `security.bpf.*` xattr is a persistent per-file tag, for example "sensitive" or "owned by a
  package". It survives reboots, unlike an inotify mark.

**Iterators and runtime features.**

| Feature | Version | Relevance |
|---|---|---|
| Task and task_file iterators | 5.8 | Startup snapshot |
| task_vma iterator | 5.12 | Startup executable paths (see above) |
| TCP/UDP socket iterators; unix socket iterator | 5.9; 5.15 | Socket snapshot at start |
| cgroup iterator; parameterized task iterators | 6.1 | Existing containers at start |
| Open-coded `bpf_iter_task`, `bpf_iter_css_task`, `bpf_iter_task_vma` | 6.7 | Iterate inside any program |
| Task local storage | 5.11 | Spawner, image key; per-task mute bits |
| Inlined local-storage lookup (+8% geomean in the local-storage benchmark) | 6.9 | ([commit 68bc61c26cac](https://github.com/torvalds/linux/commit/68bc61c26cac.patch)) |
| BPF arena, BPF token, `may_goto` | 6.9 | Token: delegated loading inside user namespaces |
| `bpf_wq`, `bpf_preempt_disable` | 6.10 | Deferred sleepable work; the per-CPU ring |
| Load-acquire / store-release | 6.15 | The per-CPU ring |
| Signed BPF programs; `bpf_task_work` | 6.18 | Signed loader; defer work to the task's return to user space |
| Ring buffer overwrite mode; indirect jumps | 6.19 | — |
| kfuncs from `raw_tp`; fsession (fentry and fexit in one session) | 7.0 | — |
| `tracing_multi` link (fentry/fexit/fsession multi) | post-7.0, 7.2 | One link for many functions |
| Sleepable tracepoint programs | post-7.0, 7.2 | — |
| `bpf_ksock` UDP send from LSM programs, "to emit telemetry over UDP independently of userspace" | post-7.0, 7.3 | Ship records without a user-space agent |

Sources: [KN 5.8](https://kernelnewbies.org/Linux_5.8) through [KN 7.3](https://kernelnewbies.org/Linux_7.3),
[bcc kernel-versions](https://raw.githubusercontent.com/iovisor/bcc/master/docs/kernel-versions.md).

### 2.6 pidfs

| Feature | Version | Source |
|---|---|---|
| pidfs; `PIDFD_THREAD` | 6.9 | [KN 6.9](https://kernelnewbies.org/Linux_6.9) |
| `PIDFD_GET_INFO` ioctl (credentials, cgroup id, pid/tgid/ppid) | 6.13 | [KN 6.13](https://kernelnewbies.org/Linux_6.13) |
| 64-bit pidfs inode numbers; file handles for pidfds | 6.14 | [commit 9698d5a48365](https://github.com/torvalds/linux/commit/9698d5a48365.patch), [commit b3caba8f7a34](https://github.com/torvalds/linux/commit/b3caba8f7a34.patch) |
| `PIDFD_INFO_EXIT`: exit code and cgroup available after reap | 6.15 | [KN 6.15](https://kernelnewbies.org/Linux_6.15) |
| Persistent exit and coredump info that no longer needs an open pidfd; trusted xattrs on pidfds | 6.17 | [KN 6.17](https://kernelnewbies.org/Linux_6.17) |
| Inode allocation without the pidmap lock | 7.0 | [KN 7.0](https://kernelnewbies.org/Linux_7.0) |

- "On 64-bit platforms, userspace can read the pidfd's inode in order to get a never-repeated PID
  identifier" ([commit b3caba8f7a34](https://github.com/torvalds/linux/commit/b3caba8f7a34.patch)).
  This is Panopticon's process key.
- Since 6.17, a process's exit code can be read after it is reaped. This would give exit status
  without an exit hook. It needs a pidfd or a file handle, and the handle might be built from the
  process key. **[INFERENCE, untested]**

### 2.7 Mount and namespace observation

- **Mount queries:**
  - `listmount()` and `statmount()` landed in 6.8.
  - `statmount()` gained fields over several releases: mount namespace id and options in 6.11,
    filesystem subtype and option arrays in 6.13, id maps in 6.15. Querying by fd landed in 7.0
    ([statmount(2)](https://man7.org/linux/man-pages/man2/statmount.2.html),
    [KN 6.8](https://kernelnewbies.org/Linux_6.8)).
- **Namespace identifiers:**
  - `NS_GET_MNTNS_ID` landed in 6.11; iterating mount namespaces in 6.12.
  - Namespace file handles and `NS_GET_ID` for every namespace type landed in 6.18.
  - `listns()` landed in 6.19.

  ([KN 6.12](https://kernelnewbies.org/Linux_6.12), [KN 6.18](https://kernelnewbies.org/Linux_6.18),
  [KN 6.19](https://kernelnewbies.org/Linux_6.19))
- **Mount events:** fanotify mount events (6.15) carry the unique mount id that `statmount()` takes
  ([KN 6.15](https://kernelnewbies.org/Linux_6.15)).
- **For container metadata:** a container's mounts (which Falco checks as `container.mount.dest`)
  can be read once per container with `statmount()` instead of parsing `mountinfo`. **[INFERENCE]**

### 2.8 Other facilities

- **`ptrace_access_check` covers the four cross-process access paths in the design's admin plan.**
  Verified in master source for this document:
  - `process_vm_readv/writev` call `mm_access(task, PTRACE_MODE_ATTACH_REALCREDS)`
    ([mm/process_vm_access.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/mm/process_vm_access.c)).
  - Opening `/proc/<pid>/mem` uses `PTRACE_MODE_ATTACH` through `proc_mem_open()` →
    `mm_access()`. `/proc/<pid>/environ` opens with `PTRACE_MODE_READ` and `auxv` with
    `PTRACE_MODE_READ_FSCREDS`, so the same hook in read mode also sees environment reads (Falco's
    "Read environment variable from /proc files")
    ([fs/proc/base.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/proc/base.c)).
  - Read-mode checks are frequent: every read of `/proc/<pid>/stat` calls
    `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_NOAUDIT)`
    ([fs/proc/array.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/proc/array.c)),
    so `ps` and `top` run the hook once per process. A program on this hook must reject non-attach
    modes first. **[INFERENCE]**
  - `pidfd_getfd` calls `ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)`
    ([kernel/pid.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/pid.c)).
  - `mm_access` returns early when the target mm is the caller's own; otherwise it calls
    `ptrace_may_access` ([kernel/fork.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/fork.c)).
  - `__ptrace_may_access` returns early for the same thread group, and denies uid mismatches without
    the capability before it calls `security_ptrace_access_check`
    ([kernel/ptrace.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/ptrace.c)).

  So the hook sees every permitted cross-process access, but not attempts denied by the uid check.
- **Exec of scripts:** `AT_EXECVE_CHECK` and `SECBIT_EXEC_RESTRICT_FILE` (6.14) let an enlightened
  interpreter ask the kernel whether a script may be executed. That runs the exec LSM hooks for
  script files ([check_exec](https://docs.kernel.org/userspace-api/check_exec.html),
  [KN 6.14](https://kernelnewbies.org/Linux_6.14)). It is the only kernel path to script-content
  telemetry that does not inspect the interpreter.
- **memfd:** `vm.memfd_noexec` and `MFD_NOEXEC_SEAL`/`MFD_EXEC` (6.3). With value 2, a
  `memfd_create()` without `MFD_NOEXEC_SEAL` is rejected
  ([mfd_noexec](https://docs.kernel.org/userspace-api/mfd_noexec.html)).
- **Network:**
  - `BPF_PROG_TYPE_NETFILTER` landed in 6.4, tcx in 6.6 and netkit in 6.7.
  - conntrack kfuncs: lookup in 5.18, insert and update in 6.0.

  ([KN 6.4](https://kernelnewbies.org/Linux_6.4), [KN 6.6](https://kernelnewbies.org/Linux_6.6),
  [KN 6.0](https://kernelnewbies.org/Linux_6.0))
- **Process events connector** (2.6.15): delivers fork, exec, credential and exit events for every
  process, with no filtering. Brauner calls it a "really terrible API" and points to fanotify and
  pidfd events as the replacement ([LWN 1075829](https://lwn.net/Articles/1075829/)).

### 2.9 Summary

| Facility | Version | Lets a low-overhead agent observe or skip | Limits |
|---|---|---|---|
| BPF LSM; sleepable LSM | 5.7; 5.10 | Semantic hooks for exec, files, mounts, credentials, BPF, modules, keys | Runs for every object. 87 sleepable hooks |
| LSM static calls | 6.12 | Direct calls instead of indirect calls per hook | The BPF slot is always on when `bpf` is in `lsm=` **[INFERENCE]** |
| `BPF_LSM_CGROUP` | 6.0 | Per-cgroup programs | Shim runs for all tasks **[INFERENCE]** |
| fs kfuncs (exe file, `path_d_path`, xattr, fs-verity digest) | 6.8–6.15 | Safe executable path, per-file tags, content identity | LSM only (plus `binfmt_misc` struct_ops in 7.3) |
| fsnotify marks | long-standing | Unmarked inodes pay nothing measurable | Inode marks pin inodes unless evictable |
| fanotify FID/NAME reporting; evictable marks; ignore marks | 5.1–6.0 | Create/delete/rename with names; bounded ignore sets | Delivered to user space, no BPF filter |
| fanotify mount events | 6.15 | Mount attach and detach with mount id | Cannot be combined with content classes |
| BPF fanotify filter | not merged (7.4-rc1) | Would drop uninteresting events in the kernel | Design open (LWN 2025, 2026) |
| IMA audit; fs-verity; IPE | 2.6.30+; 5.4; 6.12 | Kernel-computed file hashes; exec-integrity decisions | Policy-driven hashing cost |
| Audit | long-standing | Kernel records, io_uring since 5.16 | Per-task syscall slow path once enabled |
| Iterators | 5.8–6.7 | In-kernel startup snapshot | — |
| pidfs, `PIDFD_INFO_EXIT` | 6.9, 6.15 | Never-reused process identity; exit code after reap | Needs a pidfd or file handle |
| `listmount`/`statmount`, namespace ids | 6.8–6.19 | Mount and namespace state without `/proc` parsing | — |
| `AT_EXECVE_CHECK` | 6.14 | Script files through the exec hooks | Interpreter must opt in |
| `bpf_ksock` | 7.3 | Send records from BPF without a user-space reader | Not on 7.0 |

---

## 3. Research and detection demand

### 3.1 Low-overhead provenance and audit collection

Numbers are as each source reports them. Benchmarks, hardware and metrics differ, so the rows are
not comparable with each other.

**Collectors.**

| System | Venue | Mechanism | Reported cost or reduction | How |
|---|---|---|---|---|
| SPADE v2 | Middleware 2012 | Linux Audit reporter; /proc for process details | Apache build under 5% on Linux; BLAST 12% | Does not report `read()`/`write()`; infers direction from `open()` flags ([SPADE](https://www.csl.sri.com/users/gehani/papers/MW-2012.SPADE.pdf)) |
| Hi-Fi | ACSAC 2012 | LSM module, relay ring buffer | Most syscalls under 1%; read 6.2%; kernel build +2.8% | Hooks on kernel objects instead of syscalls ([Hi-Fi](https://cise.ufl.edu/~butler/pubs/acsac12b.pdf)) |
| LPM | USENIX Sec 2015 | Provenance hooks after LSM authorization | Kernel compile +2.7%, Postmark +7.5%; open/close +42%. 3.7 GB raw for one kernel compile | Proposes keeping state "about past events within the kernel" to block redundant records ([LPM](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-bates.pdf)) |
| CamFlow | SoCC 2017 | LSM plus Netfilter, per-CPU relayfs | Postmark 11% whole-system, 6% selective; open/close +80% whole, +18% selective; redis up to 22% | Capture policy by node and edge type, program, directory, and taint propagation ([CamFlow](https://arxiv.org/pdf/1711.05296)) |
| KCAL | USENIX ATC 2018 | Modified Linux Audit with in-kernel caches; shared memory instead of Netlink | Overhead from "40+%" to "15-%"; space −90% | Per-task, per-process and per-file caches drop redundant events; temporary files detected and dropped ([KCAL](https://www.usenix.org/system/files/conference/atc18/atc18-ma-shiqing.pdf)) |
| ProTracer | NDSS 2016 | Kernel tracepoints and a ring buffer | 13 MB/day; under 7% on servers. Linux Audit measured "as high as 43%" | Logs only writes and sends; turns reads into taint in user space ([ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)) |
| eAudit | IEEE S&P 2024 | eBPF on per-syscall tracepoints; per-CPU caches into one ring buffer | 4.5% average; 18.4× lower agent overhead from buffer design; logs 3.5–12× smaller than sysdig after gzip | 1-byte event codes, few consumer wakeups, priority flush for critical syscalls ([eAudit](https://www.seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf)) |

**Loss and hook cost.**

- **eAudit's comparison** ([eAudit](https://www.seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf)):
  - A 3-minute postmark run produced 9 GB of logs with sysdig, 26 GB with auditd and 41 GB with
    CamFlow.
  - Used as syscall loggers, Tetragon and Tracee dropped about 90% of postmark records and sysdig
    about 60%.
  - CamFlow drops records once its daemon reaches 100% CPU.
  - At under 10% loss, the existing systems cost 4–16× in collector CPU per benchmark CPU.
- **Houssel et al.** (Linux 6.1) measured CPU overhead on network, file and process workloads
  ([arXiv 2608.11418](https://arxiv.org/pdf/2608.11418)):
  - fentry: 0.76% / 8.12% / 1.15%.
  - kprobe: 1.66% / 9.10% / 1.30%.
  - Only LSM programs avoid a second attachment to discard denied operations.
- **Red Hat's measurement of falcosecurity/libs**
  ([PDF](https://github.com/falcosecurity/libs/files/8334709/Falco.eBPF.Kernel.Module.Performance.pdf)):
  - The benchmark took 47.19 s without an agent and 60.30 s with eBPF on `sys_enter`/`sys_exit`.
  - With only the 17 needed syscalls hooked it took 47.87 s.
  - `read` and `write` were about 99.6% of all events.

**Reduction techniques.**

| Technique | Venue | Reduction | Accuracy claim | Source |
|---|---|---|---|---|
| BEEP (execution units) | NDSS 2013 | Causal graphs 40.93× smaller | Minimal graphs in the studied attacks | [BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf) |
| LogGC | CCS 2013 | 14× (users), 37× (servers) | No forensic accuracy loss | [LogGC](https://www.cs.purdue.edu/homes/xyzhang/Comp/ccs13.pdf) |
| CPR / PCAR | CCS 2016 | −56% / −70% events | CPR lossless; PCAR 0.2% false positives | [CPR](https://jhrhee.github.io/pubs/CCS16.pdf) |
| NodeMerge (templates of read-only accesses at process start) | CCS 2018 | Up to 75.7× on raw data | "nearly zero information loss" | [NodeMerge](https://jhrhee.github.io/pubs/CCS18.pdf) |
| FD / SD dependence-preserving | USENIX Sec 2018 | 7× / 9.2× events; 35× on disk | Provably preserves backtracking | [Hossain](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-hossain.pdf) |
| Winnower | NDSS 2018 | More than three orders of magnitude for clusters | Five attacks remained visible | [Winnower](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_07B-1_Hassan_paper.pdf) |
| LogApprox | ACSAC 2020 | 1.72–2.87× | Keeps 100% of attack events; finds that earlier approximations often drop them | [LogApprox](https://adambates.org/documents/Michael_Acsac20.pdf) |
| SEAL | USENIX Sec 2021 | 9.81× events, 2.63× storage | Lossless | [SEAL](https://www.usenix.org/system/files/sec21-fei.pdf) |

**Industrial collectors.**

- **Tetragon** applies "policy and filtering directly in eBPF in the kernel" and claims "less than 2%
  overhead" for every process exec. That is a vendor statement
  ([Tetragon](https://tetragon.io/docs/overview/)).
- **Falco 0.35** monitors only the syscalls the rules need
  ([PDF](https://github.com/falcosecurity/libs/files/8334709/Falco.eBPF.Kernel.Module.Performance.pdf)).
- **Elastic Defend:**
  - It deduplicates repeated network tuples by default from 8.15
    ([advanced settings](https://www.elastic.co/docs/reference/security/defend-advanced-settings)).
  - Elastic's own fleet went from about 48k to about 12k events per host per hour after filtering
    ([Elastic infosec](https://www.elastic.co/security-labs/blog/how-elastic-infosec-optimizes-defend)).
- **Microsoft Defender for Endpoint on Linux** replaced auditd with eBPF, citing rule conflicts,
  noise and the overhead of file-open monitoring. It publishes no numbers
  ([MDE](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf)).
- **LAUREL** costs about twice auditd's CPU when enrichment runs in a plugin
  ([LAUREL](https://raw.githubusercontent.com/threathunters-io/laurel/master/performance.md)).

### 3.2 What provenance IDSs consume

| IDS | Venue | Nodes | Edges used | Attributes | Repeats needed? |
|---|---|---|---|---|---|
| StreamSpot | KDD 2016 | file, process, socket | read, write, fork, sock_wr, ... | types only | Shingle counts: yes **[INFERENCE]** ([paper](https://arxiv.org/pdf/1602.04844)) |
| UNICORN | NDSS 2020 | CamFlow / CDM types | all, with decay | types | Histogram over all edges; not evaluated on coalesced input ([paper](https://arxiv.org/pdf/2001.01525)) |
| ProvDetector | NDSS 2020 | process, file, socket | start, end, read, write, execute | executable path, file path, IP:port | Rarity per (src, rel, dst) per host and window; counts unused **[INFERENCE]** ([paper](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24167-paper.pdf)) |
| ATLAS | USENIX Sec 2021 | process, file, network, domain | read, write, delete, execute, fork, connect, resolve, ... | lemmatized classes | First occurrence only, by design ([paper](https://www.usenix.org/system/files/sec21-alsaheel.pdf)) |
| ShadeWatcher | IEEE S&P 2022 | process, file, socket | 32 audited syscalls | paths, IPs | CPR keep-first plus temp-file and library pruning: ~95% of TRACE edges removed ([paper](https://jun-zeng.github.io/file/shadewatcher_paper.pdf)) |
| Kairos | IEEE S&P 2024 | process, file, socket | WRITE, READ, CLOSE, OPEN, EXECUTE, SENDTO, RECVFROM | image path, file path, IP:port | Every included edge with timestamps; not evaluated on coalesced input ([paper](https://arxiv.org/pdf/2308.05034), [config](https://raw.githubusercontent.com/ubc-provenance/kairos/main/DARPA/CADETS_E3/config.py)) |
| Flash | IEEE S&P 2024 | process, file, socket, module | all CDM types | process name and command line, path, IP:port | Released code adds tokens for every event ([code](https://raw.githubusercontent.com/DART-Laboratory/Flash-IDS/main/Cadets.ipynb)) |
| MAGIC | USENIX Sec 2024 | CDM types | all CDM types | types | Released parser keeps the first edge per node pair; 79.6% of E3 Trace edges removed ([paper](https://arxiv.org/pdf/2310.09831), [parser](https://raw.githubusercontent.com/FDUDSDE/MAGIC/main/utils/trace_parser.py)) |
| NODLINK | NDSS 2024 | process, file, IP | read, write, create, chmod, rename, fork, clone, execve, send, recv | command line, path, IP:port | Not evaluated on coalesced input ([paper](https://arxiv.org/pdf/2311.02331)) |

On the shared taxonomy:

- **Edges every system builds:** exec, reads and writes of all files (not only sensitive ones), and
  socket send and receive or connect. Attributes differ: Kairos and ProvDetector use image path,
  file path and IP:port; Flash and NODLINK add the command line; MAGIC, UNICORN and StreamSpot use
  node and edge types only.
- **Process lifecycle:** fork/clone appears in Kairos, ProvDetector, ShadeWatcher and NODLINK.
  ProvDetector models process exit, and Kairos lists Close among process-to-process relations.
- **Not used by any reviewed IDS:**
  - credential change (CDM `CHANGE_PRINCIPAL`);
  - ptrace (`MODIFY_PROCESS`);
  - module load (`INIT_MODULE`);
  - mount.

  ([CDM20.avdl](https://raw.githubusercontent.com/tanishqjasoria/darpa-tc-en5/master/Schema/CDM20.avdl),
  [SPADE CDM mapping](https://github.com/ashish-gehani/SPADE/wiki/System-calls-underlying-CDM-events))

Consequences for Panopticon **[INFERENCE]**:

- **What it can feed:**
  - Provenance IDSs that tolerate first-occurrence edges (ATLAS, MAGIC, ShadeWatcher) could take a
    coalesced stream: exec, connect, and the first read and write per (process, file).
  - The sensitive-file stream cannot feed them, because it covers only marked files.
  - An all-files "first touch" mode would need a hook on every open: +12 ns per open for any program
    on `security_file_open` (`docs/design.md`).
- **What it lacks:** exit events, which ProvDetector and Kairos model.
- **Order-sensitive IDSs** (StreamSpot, UNICORN, Flash, Kairos) have not been evaluated on coalesced
  input.

### 3.3 Detection-content demand

#### Sources

| Source | Version | Selection | Rules / techniques |
|---|---|---|---|
| MITRE ATT&CK Enterprise | v20.0, `mitre-attack/attack-stix-data` commit `c2494b29dd268c46a5d0ea0990553e4327cd2253` (2026-10-13), `enterprise-attack/enterprise-attack.json` | Techniques and sub-techniques, not revoked or deprecated, with platform Linux or Containers | 356 Linux (355 with a Linux analytic); 48 Containers (37 with a Containers analytic) |
| Sigma | `SigmaHQ/sigma` commit `05d1031f537e830b76da53bae2400c5814c89165` (2026-10-21) | All six rule directories, `logsource.product: linux` | 249 Linux (211 `rules/`, 34 `rules-emerging-threats/`, 4 `rules-threat-hunting/`); plus 16 `product: kubernetes` counted separately |
| Elastic | `elastic/detection-rules` commit `56b642f340d49c896e4644ddc3b501a098856567` (2026-10-31), package 9.6.0-beta.1 | `rules/` and `rules_building_block/`, tag `OS: Linux`, maturity `production`, type not `machine_learning` | 544 (22 building blocks; 442 tagged Elastic Defend, 132 Auditd Manager) |
| Falco | `falcosecurity/rules` commit `e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428` (2026-10-22) | `falco_rules.yaml` (stable, the default), `falco-incubating_rules.yaml`, `falco-sandbox_rules.yaml` | 96 (25 stable, 32 incubating, 39 sandbox, of which 14 are `enabled: false`) |

#### Counting method

- **Tooling.** Shallow clones in `/tmp/pano-research/`, counted by a Python script
  (`/tmp/pano-research/count.py`, not committed, about 5 s of CPU). Classification is regex- and
  heuristic-based over rule text, as described below.
- **Per-rule counting.** A rule counts once in every category it needs; one rule can need several.
- **ATT&CK.** In this release, techniques reach data components through detection strategies and
  analytics, not through direct `detects` relationships from data components.
  - For each technique, take the detection strategies that `detects` it, then their
    `x_mitre_analytic_refs`.
  - Keep analytics whose `x_mitre_platforms` includes the platform.
  - Each `x_mitre_log_source_references` entry names a data component.
  - The count is the number of techniques with at least one such reference. The data component is
    then mapped onto the taxonomy, as shown in the table below.
- **Sigma** (rule type by log source):
  - `process_creation` → exec; adds lineage if `ParentImage` or `ParentCommandLine` is used, cwd if
    `CurrentDirectory` is used.
  - `file_event` → file create or write.
  - `network_connection` → connect; adds DNS if `DestinationHostname` is used.
  - `auditd` rules are classified by their `type` values:
    - `EXECVE` → exec.
    - `PATH` → file path access, which carries no operation.
    - `SYSCALL` with a syscall name → that syscall.
    - `SYSCALL` without one → exec attribution.
    - `TTY`, `ADD_USER`, `SERVICE_STOP` → their own categories.
  - Rules with keywords only, or with a service log source → log content.
  - Fields are the detection keys without their modifiers.
- **Elastic** (event category, actions, fields):
  - The event category comes from EQL `<category> where`, from `event.category` values, and from
    ES|QL index patterns (`logs-endpoint.events.<category>-*`).
  - Operations come from `event.action` and `event.type` values. For example, `exec`, `start`,
    `exec_event`, `ProcessRollup2` and `executed` mean exec; `creation`, `rename`, `deletion`,
    `open` and `uid_change` map to their categories.
  - ECS field names are matched by regex.
  - Lineage means any `process.parent.*`, `process.entry_leader.*`, `process.session_leader.*` or
    `process.group_leader.*` field.
  - Container means any `container.*` or `orchestrator.*` field, or the "Elastic Defend for
    Containers" tag.
  - Negated clauses count toward categories.
- **Falco** (syscalls and fields after expanding macros):
  - Conditions are expanded through all macros and lists of the three files. `evt.type` values give
    the syscalls.
  - `open`/`openat` is split into read and write by `evt.is_open_read`, `evt.is_open_write` and
    `evt.arg.flags`.
  - Condition fields and output fields are counted separately.
- **"Satisfiable from exec records"** means every category of the rule is one of:
  - exec, lineage, cwd, TTY;
  - user fields, environment variables;
  - real and saved uid/gid fields on the exec event (credential-change events do not count);
  - container fields;
  - for Falco, also the capability fields and the exec-time flags `proc.is_exe_from_memfd` and
    `proc.is_exe_upper_layer`.
- **Path scope of file rules:**
  - Each positive (non-negated) path pattern is classed as one of:
    - exact (wildcards only in a `/home/*/` segment);
    - fixed directory (wildcards only in the last component);
    - enumerable glob (a wildcard in a middle component, outside `/proc`);
    - anywhere (leading wildcard, or only a name or extension condition).

    A rule takes its widest pattern.
  - For Elastic, comments are stripped and patterns inside `not (...)` are skipped.
  - For Sigma, `startswith` is a directory, `endswith` or `contains` of an absolute path is exact,
    and other modifiers are anywhere.
  - The 34 Falco file rules were classed by hand from the expanded `fd.name`, `fd.directory` and
    `evt.arg.*` predicates.
- **Limitations:**
  - Regexes over query text miss some multi-line constructs.
  - Sigma `auditd` PATH rules are counted as both read and write, because PATH records carry no
    operation.
  - Falco counts include the 14 disabled sandbox rules unless stated otherwise.
  - The ATT&CK free-text `channel` field is not normalized. Only data components are counted.

#### ATT&CK data components (techniques with at least one analytic on the platform)

| Data component | Linux | Containers | Taxonomy |
|---|---|---|---|
| Process Creation | 222 | 13 | Process: exec |
| Command Execution | 82 | 6 | Process: exec (command line) |
| File Access | 69 | 3 | File: sensitive-file read |
| Network Traffic Content | 62 | 5 | Network: content (network sensors) |
| File Modification | 61 | 3 | File: write/modify |
| Network Traffic Flow | 51 | 3 | Network: flows (network sensors) |
| File Creation | 46 | — | File: create |
| Network Connection Creation | 45 | 4 | Network: connect/accept |
| Application Log Content | 33 | 6 | Logs |
| File Metadata | 30 | 1 | File: chmod/chown/xattr, hash |
| OS API Execution | 16 | — | Specific syscalls (ptrace, mmap, unshare, ...) |
| User Account Authentication | 15 | 5 | Identity: login |
| Process Access / Process Modification | 12 / 11 | — | Process: injection |
| Module Load | 11 | — | File: library load |
| Logon Session Creation / Metadata | 10 / 7 | 1 / 1 | Identity: login |
| Process Metadata | 10 | 1 | Process: credentials, environment |
| File Deletion | 9 | 2 | File: delete |
| Drive Creation / Access / Modification | 7 / 5 / 1 | — | Kernel: mount, devices |
| Host Status | 7 | 2 | Sensor: health |
| Script Execution | 6 | — | Process: script content |
| Service Metadata / Creation; Scheduled Job Creation / Metadata / Modification | 6 / 3; 4 / 3 / 1 | 1 / 1; 1 | File: persistence locations |
| User Account Creation / Modification / Metadata | 3 / 4 / 2 | 1 / 1 / 1 | Identity: user and group changes |
| Process Termination | 3 | — | Process: exit |
| Driver Load, Firmware Modification | 2, 2 | — | Kernel: module load, firmware |
| Container Creation / Start / Enumeration; Image Creation / Metadata / Modification; Pod Creation / Enumeration; Volume Modification | — | 7 / 3 / 2; 2 / 2 / 1; 2 / 1; 1 | Container: runtime events, K8s audit |

Unions across these data components, over Linux techniques:

- exec (Process Creation or Command Execution): 278;
- any file data component: 184;
- Network Connection Creation: 45, against 102 for Network Traffic Flow or Content, which come from
  network sensors.

The most frequent Linux log source is `auditd:SYSCALL` with channel `execve`: 119 techniques.

#### Demand by category

Counts are rules (Sigma, Elastic, Falco) or techniques (ATT&CK Linux). Falco counts are for all 96
rules, with the 82 enabled rules in parentheses where they differ.

| Category | ATT&CK | Sigma (249) | Elastic (544) | Falco (96) | Fields the rules use |
|---|---|---|---|---|---|
| Process: exec | 278 | 183 | 392 | 40 (38) | **Sigma** (145 `process_creation` rules): `CommandLine` 126, `Image` 125. **Elastic** (392): `process.name` 353, `process.args` 284, `process.command_line` 100, `process.executable` 76, `process.args_count` 32. **Falco** conditions: `proc.name` 65, `proc.cmdline` 29, `proc.args` 10, `proc.exe` 8 |
| Process: lineage | — | 21 | 254 | 27 (26) | **Sigma**: `ParentImage` 17, `ParentCommandLine` 9. **Elastic**: `process.parent.name` 159, `.executable` 126, `.args` 79, `.command_line` 73, `.entity_id` 35. **Falco**: `proc.pname` 26, `proc.aname` (ancestors) 11, `proc.pcmdline` 4 |
| Container context | (48 Containers techniques) | 0 (16 Kubernetes audit rules) | 89 | 47 (39) | `container.id` (Elastic 44 exec rules; Falco 43); `container.image.repository` 18, `container.privileged` 3, `container.mount.dest`, `k8s.ns.name` 5 |
| File: create / write / rename / delete / attributes | 130 | 31 | 113 | 26 (21) | **Elastic**: `file.path` 97 of 117 file rules, `file.name` 55, `file.extension` 50, `file.Ext.original.extension` / `.name` / `.path` (rename source) 15 / 9 / 4. **Sigma**: `TargetFilename`, auditd `name`. **Falco**: `fd.name` 28, `fd.directory` 12, `evt.arg.*` |
| Network: connect / accept / listen | 45 | 5 | 50 | 12 (7) | **Elastic** (57 network rules): `destination.ip` 37, `destination.port` 14, `source.ip` 7, `network.direction` 6. **Falco**: `fd.sip`, `fd.sport`, `fd.l4proto`, `fd.net` |
| File: open/read | 69 | 12 (auditd PATH) | 15 | 11 (9) | path plus process |
| Process: cwd | — | 3 | 50 | 1 | `CurrentDirectory`, `process.working_directory`, `proc.cwd` |
| Network: UDP send/receive | — | 0 | 0 | 8 (3) | `fd.l4proto`, `fd.sip` |
| TTY / interactive | — | 1 | 20 | 3 | `process.entry_leader.entry_meta.type` 13, `process.interactive`, `proc.tty`. `proc.tty` is also in all 96 Falco outputs |
| Namespaces, BPF load, userfaultfd, raw sockets, dup to socket | — | 1 (`socket(AF_ALG)`) | 0 | 6 | `evt.arg.cmd`, `thread.cap_permitted`, `evt.arg.domain`, `fd.type` |
| DNS | — | 3 | 9 | 3 (1) | `DestinationHostname`, `dns.question.name` 9, `fd.sip.name` |
| Fileless exec | — | 1 (`memfd_create`) | 8 | 3 (2) | `memfd`, `(deleted)`, `proc.is_exe_from_memfd`, `proc.is_exe_upper_layer` |
| Credential change | 10 (Process Metadata) | 0 | 14 | 1 | `event.action` `uid_change`, `gid_change`, `guid_change`, `session_id_change`; `setuid` `evt.arg.uid`. Another 4 Elastic rules compare `process.real_user` / `process.saved_user` on exec events; these count as exec attributes |
| Environment variables | — | 0 | 6 | 2 | Fixed names: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `GLIBC_TUNABLES`, `HISTFILE`, `HISTSIZE`, `HISTFILESIZE`, `HISTCONTROL`, `HTTPS_PROXY`, `ALL_PROXY`, `HTTP_PROXY`, `RUNNER_TRACKING_ID` |
| Process injection | 23 | 0 | 4 | 2 | ptrace `evt.arg.request`; `/proc/*/mem` |
| Fork / exit | 3 | 0 | 13 (8 fork, 5 exit) | 0 | — |
| Kernel module load | 2 | 0 | 4 | 1 | `finit_module`, `init_module` |
| Identity: login / auth | 28 | 0 | 9 | 0 | `ssh_login`, `user_login` actions |
| User / group changes | 7 | 1 | 4 | 0 | `ADD_USER`, `added-user-account` |
| Mount / devices | 13 | 0 | 0 | 0 | — |
| Library load / mmap exec | 11 | 0 | 0 | 0 | — |
| Script content | 6 | 0 | 0 | 0 | — |
| Log content (syslog, service logs) | 33 | 27 (16 keyword, 11 service log) | 9 | 0 | Keywords |

The most frequent fields in each record family: Elastic file rules use `process.name` 86 and
`process.executable` 66; Elastic network rules use `process.name` 47, `process.executable` 28 and
`process.entity_id` 25. All 96 Falco rules output `proc.cmdline`, `proc.pname`, `proc.tty`,
`user.loginuid`, `user.uid` and `proc.name`, and 94 output `proc.exepath`. Every event therefore
needs the process context, which Panopticon gets by joining on the image key rather than copying it
into each record.

#### Concentration

| | Sigma | Elastic | Falco |
|---|---|---|---|
| Rules satisfiable from exec records alone | 177 / 249 (71%) | 321 / 544 (59%) | 39 / 96 (41%); 37 / 82 enabled |

Elastic has 84 sequence rules, grouped by the record classes they join:

| Classes joined | Rules |
|---|---|
| Process only | 33 |
| Network and process | 26 |
| File and process | 12 |
| Network only | 4 |
| File and network | 4 |
| Identity | 3 |
| File, network and process | 1 |
| File only | 1 |

Joining a connection to the exec that preceded it in the same process is the most common
correlation. With Panopticon this is a join on the image key.

#### Can kernel marks gate the file rules?

| Path scope | Elastic (117) | Sigma (30) | Falco (34; 28 enabled) |
|---|---|---|---|
| Exact paths | 20 | 11 | — |
| Fixed directories, with or without exact files | 43 | 7 | 14 (13) |
| Enumerable globs | 10 | — | 5 (4) |
| Anywhere: name or extension, path pattern, or no path constraint | 44 (20 + 11 + 13) | 12 | 15 (11) |

Rules scoped to exact paths and fixed directories can be gated by inode and directory marks set when
the agent starts: 54% of Elastic, 60% of Sigma and 41% of Falco file rules. Adding enumerable globs
(per-user homes, `python*` versions, set at mark time) raises this to 62%, 60% and 56%. **[INFERENCE]**

Two caveats:

- An EQL `/dir/*` pattern (the wildcard also matches `/` **[INFERENCE]**) or a Falco
  `startswith /dir/` predicate also matches deeper levels. A directory mark reports only direct
  children ("Inotify monitoring of directories is not recursive",
  [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)), so subtree rules such as
  Falco's "Write below etc" need marks on each subdirectory or a mount or filesystem mark.
- Everything in the "anywhere" row needs a per-operation hook that runs for every file. Examples:
  hidden files, `.so` creation, executables written to `/tmp`, shell history deletion by name, and
  setuid `chmod`.

#### What Panopticon's exec record lacks against this demand

The record (`docs/design.md`) has executable path, argv, uid/gid, loginuid, sessionid, effective
capabilities, cgroup, spawner, parent and previous image key. Rules also use:

- working directory: 50 Elastic rules, 3 Sigma, 1 Falco;
- TTY or session type: 20 Elastic, 3 Falco conditions, and all Falco outputs;
- a fixed list of environment variable names: 6 Elastic, 2 Falco;
- the exec-time flags "exe is memfd" and "exe on the overlay upper layer": 3 Falco rules, plus 8
  Elastic fileless-exec rules;
- permitted capabilities, alongside effective: 4 Falco rules;
- real and saved uid/gid: 4 Elastic rules.

Parent argv (79 Elastic rules) is available by joining on the parent's exec record.

---

## 4. Capabilities ranked by detection value

**How the ranking is built:**

- The score is the mean, over Sigma (249), Elastic (544) and Falco (96), of the share of each
  source's Linux rules that need the capability, classified as in §3.3.
- Ties are broken by ATT&CK Linux technique count.
- ATT&CK technique counts (through mapped data components) are shown but not used in the score,
  because analytics list data components generously and do not separate attributes such as lineage
  or cwd.
- Log-only rules (syslog keywords, service logs) are excluded.
- "Cheapest known mechanism" cites a measurement from `docs/design.md` where one exists.
  Otherwise the mechanism is **[INFERENCE]**.

| # | Capability | Score | Sigma | Elastic | Falco | ATT&CK | Cheapest known mechanism | Panopticon |
|---|---|---|---|---|---|---|---|---|
| 1 | Process exec (image, argv) | 62.4% | 183 | 392 | 40 | 278 | One program at exec after the point of no return (`lsm.s/bprm_committed_creds`). 450–571 ns of BPF per exec; +1.1–1.2% on the exec workload vs +4.5–7.2% for Falco (`docs/design.md`) | Done |
| 2 | Lineage (parent and ancestor image and argv) | 27.7% | 21 | 254 | 27 | — | No extra events. Spawner and image key in task storage (246 ns per fork, `docs/design.md`); the consumer joins parent exec records, and the startup iterator covers older processes | Done (keys); joins are the consumer's job |
| 3 | Container context (id, image, privileged, mounts, pod) | 21.8% | 0 | 89 | 47 | — | cgroup id on every record (~2 ns) plus a `cgroup_mkdir` record (`docs/design.md`); image and pod from the runtime API once per container; mounts with `statmount()` (6.8) once per container **[INFERENCE]** | Id done; image and pod planned |
| 4 | File create, modify, rename, delete, attributes | 20.1% | 31 | 113 | 26 | 130 | Fixed paths and directories (41–60% of file rules; 56–62% with enumerable globs): fsnotify marks, 0 ns for unrelated operations and +118 ns per marked open on 7.0; the cost of other marked operations is unmeasured (`docs/design.md`). Name or extension anywhere: LSM `path_*` or `inode_*` hooks with in-kernel filtering, paying per operation on every file (+12 ns measured for `file_open`) | Credential files and directories done; persistence directories not listed yet |
| 5 | Network connect, accept, listen | 7.9% | 5 | 50 | 12 | 45 | `fexit/tcp_v4_connect`, `tcp_v6_connect`, `inet_csk_accept`, `inet_listen`: +110 ns per connection on one thread (`docs/design.md`) | Done |
| 6 | File open/read of listed files | 6.3% | 12 | 15 | 11 | 69 | inotify marks plus BPF on `inotify_handle_inode_event`, filtered by group and coalesced in the kernel: +118 ns per marked open, 0 for others (`docs/design.md`). Not possible on 7.0: skipping the event allocation (no BPF hook in fanotify, §2.2) | Done |
| 7 | Process working directory | 3.8% | 3 | 50 | 1 | — | Add to the exec record: `bpf_d_path` on `current->fs->pwd` in the sleepable exec hook. Cost unmeasured **[INFERENCE]** | Missing |
| 8 | UDP flows | 2.8% | 0 | 0 | 8 | — | `fexit/udp_sendmsg` with per-socket destination deduplication: +29 ns per send (`docs/design.md`) | IPv4 done, IPv6 missing |
| 9 | TTY / interactive session | 2.4% | 1 | 20 | 3 | — | Read the controlling TTY device from `task->signal->tty` in the exec hook **[INFERENCE]** | Missing (sessionid is recorded) |
| 10 | Namespaces, BPF load, userfaultfd, raw sockets, dup to socket | 2.2% | 1 | 0 | 6 | — | LSM `bpf_prog_load`, `userns_create` (6.1), `inode_init_security_anon` (5.12), `socket_create`; for other namespaces, compare `nsproxy` at fork. Each fires only on the operation. Dup to socket: test whether fds 0–2 are sockets at exec **[INFERENCE]** | Planned (admin class) |
| 11 | DNS query and answer | 2.0% | 3 | 9 | 3 | — | `udp_sendmsg` to port 53 plus `skb_consume_udp` on tagged sockets (`docs/design.md`) | IPv4 done |
| 12 | Fileless exec (memfd, deleted executable, overlay upper layer) | 1.7% | 1 | 8 | 3 | — | Flags derived from the executable file in the exec hook (memfd/shmem, `nlink == 0`, overlayfs upper) **[INFERENCE]**. Preventive alternative: `vm.memfd_noexec=2` (6.3) | Missing |
| 13 | Credential change (setuid, setgid, capset) | 1.2% | 0 | 14 | 1 | 10 | LSM `task_fix_setuid`, `task_fix_setgid` (5.8), `capset`; these fire only on credential-changing calls | Planned |
| 14 | Environment variables | 1.1% | 0 | 6 | 2 | — | Scan envp at exec for the fixed list of about 11 names (§3.3) and copy only matches **[INFERENCE]** | Missing (the environment is never copied) |
| 15 | Process injection | 0.9% | 0 | 4 | 2 | 23 | LSM `ptrace_access_check` in attach mode. Covers ptrace attach, `process_vm_*`, `/proc/<pid>/mem` and `pidfd_getfd`, but not attempts denied by the uid check (§2.8) | Planned |
| 16 | Fork / exit | 0.8% | 0 | 13 | 0 | 3 | Fork: not needed (exec carries the spawner). Exit: `PIDFD_INFO_EXIT` (6.15) and persistent exit info (6.17) read on demand, or `tp_btf/sched_process_exit` at one event per exit | Exit not observed |
| 17 | Kernel module load | 0.6% | 0 | 4 | 1 | 2 | LSM `kernel_read_file` (`READING_MODULE`) and `kernel_load_data` | Planned |
| 18 | Login / authentication | 0.6% | 0 | 9 | 0 | 28 | No kernel event. loginuid and sessionid on exec records mark new sessions; sshd and PAM results come from the journal **[INFERENCE]** | Partial (ids on exec) |
| 19 | User and group account changes | 0.4% | 1 | 4 | 0 | 7 | Marks on `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` plus exec of `useradd` and similar | Done (file marks) |
| 20 | Mount and devices | 0.0% | 0 | 0 | 0 | 13 | LSM `sb_mount`, `move_mount`; or fanotify `FAN_MNT_ATTACH/DETACH` (6.15) plus `statmount()` | Planned |
| 21 | Library load / mmap exec | 0.0% | 0 | 0 | 0 | 11 | LSM `mmap_file` with `PROT_EXEC`, deduplicated per (image key, inode). NodeMerge found startup library reads redundant | Not planned |
| 22 | Script content | 0.0% | 0 | 0 | 0 | 6 | `AT_EXECVE_CHECK` (6.14) for interpreters that opt in; no other kernel path | Not planned |

Reading the ranking:

1. **Ranks 1–3** account for most rule demand and need almost no extra collection: one record per
   exec, plus keys already in task storage and a cgroup id. Ranks 7, 9, 12 and 14 are attributes of
   that same record. Adding them would make 50 more Elastic rules evaluable for cwd, 20 for TTY, 8
   for fileless exec and 6 (plus 2 Falco) for environment variables, without a new hook.
   **[INFERENCE]**
2. **File demand (rank 4) splits by scope.** Exact-path and fixed-directory rules fit the existing
   mark design once the persistence locations join the list: cron, systemd units, shell profiles,
   `ld.so.preload`, sudoers, udev rules, PAM. Name- or extension-anywhere rules (38–44% of file
   rules) are the only demand that forces a hook running for every file.
3. **Network flows and content** come from network sensors in ATT&CK (102 techniques). They are out
   of scope for the host agent by design (`docs/design.md`, "Not collected").
