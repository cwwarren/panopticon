# Commercial Linux sensors: what the public documentation says

Research notes for Panopticon. This survey covers closed-source or commercially licensed Linux EDR and
CWPP sensors, using public documentation only. It records what each sensor hooks, what it emits
(using the vendor's own event names), how it enriches, blocks and throttles, and what each vendor
publishes about cost. The last four sections hold the comparison matrix, the table-stakes and
differentiating telemetry, and the published performance budgets.

## Method and conventions

- Every statement links to a page that was opened in full on 2026-11-02 or in the two days before.
  Search-result snippets were not used. Event names, table names, field names, config keys and
  numbers are copied verbatim.
- `[VENDOR CLAIM]` marks marketing or performance claims that come without a published method.
  `[INFERENCE]` marks our own reading, which no page states.
- Source quality: vendor-owned pages and repos unless marked. *(3P mirror)* is a third party
  republishing vendor text, such as release notes or copies of login-only docs pages: treat it as vendor
  text in an unverified copy. *(3P integration)* is a SIEM or integration vendor's documentation that
  lists the vendor's event names. *(community extract)* is an unofficial extract of a login-only
  vendor reference.
- Login-walled and therefore thin: CrowdStrike docs, SentinelOne KB, docs.wiz.io, docs.aquasec.com,
  the Uptycs KB, and Sweet Security (no public docs site). Kaspersky KESL's help PDFs failed to load and
  its HTML help redirected elsewhere, so Kaspersky is not covered.
- "Linux" means the vendor's Linux host or node sensor. The vendors' cloud-API, agentless and
  admission-controller products are mentioned only where they change what the node sensor does.

## Architecture at a glance

| Sensor | Kernel-side mechanism | Fallback or alternative modes | Documented kernel floor | How it blocks |
|---|---|---|---|---|
| CrowdStrike Falcon | Kernel module ("kernel mode") or eBPF ("user mode"); the default is moving to eBPF | Reduced functionality mode (RFM): no process events | User mode: 5.8 with BTF, or backports | User mode: "asynchronous kill" |
| SentinelOne | User-space agent; eBPF, perf and fanotify providers; kprobe, uprobe and `security_path_*` hooks named | none documented | 2.6.32-358; eBPF from 3.10 | Not documented beyond kill and quarantine |
| Microsoft Defender for Endpoint | eBPF "supplementary event provider"; fanotify for real-time AV | Netlink (process events only); AuditD removed | eBPF table starts at RHEL 7.6 `3.10.0-957.10` | fanotify blocking scans, behavior monitoring |
| Elastic Defend | eBPF (fentry/fexit, `tp_btf`, kprobes), the quark library, or kprobe/tracefs; fanotify for malware; TC for isolation | kprobe/tracefs | eBPF on 5.10.16+ | fanotify-based malware prevention [INFERENCE], kill. The separate containers product uses BPF LSM |
| Sysdig Secure | Falco drivers: universal eBPF, kernel module, legacy eBPF; syscall tracepoints | `pdig` userspace tracing on serverless | 3.10 (kmod); 5.8 with BTF and ring buffer (universal eBPF) | Drift and malware: block before exec on 5.0+, kill below |
| Cortex XDR | Kernel module ("Kernel Mode") or eBPF ("User Space") | "Asynchronous mode": no EDR events | User Space 5.0; Kernel Mode per exact kernel build | Synchronous anti-malware in either mode |
| Prisma Cloud Defender | Not documented; fanotify for file monitoring | ptrace-style App-Embedded Defender [INFERENCE] | File-system Prevent needs 4.20 | Prevent (process or file op), Block (container) |
| Wiz Runtime Sensor | eBPF (Rust, libbpf skeleton) | ptrace on serverless containers | 4.18 [INFERENCE from an error code] | Kill |
| Aqua Enforcer | eBPF "alongside other operating system and runtime mechanisms"; runc interception | MicroEnforcer for CaaS | Not public | Inline denial of the action |
| Lacework / FortiCNAPP | User-mode agent with eBPF, no kernel module; libpcap below 4.16 | `lite`, `ebpflite`, `scan` modes | 4.16 (eBPF); 5.10 for process and connection telemetry (agent 7.10+) | None on the agent |
| Datadog Workload Protection | eBPF kprobes (fentry opt-in), ring buffer, in-kernel approvers and discarders; TC classifiers | ptrace on Fargate | 4.14 (RHEL 7 3.10 degraded) | Signal-based kill; TC packet drop |
| Uptycs | osquery with eBPF using pre-CO-RE, cloud-updated offsets | Linux Audit | 3.10 [VENDOR CLAIM]; eBPF on Graviton 5.8 | Optional "Protect" add-on, mechanism not documented |
| Sophos Linux Sensor | kprobes read through perf; ftrace; inotify | none documented | ARM64 5.3; release notes up to kernel 7.3 | `SIGKILL` and `SIGSTOP` after detection |
| Trend Micro Vision One / DSA | Kernel modules `tmhook.ko` and `bmhook.ko`, built per exact kernel | "User mode": fanotify and eBPF basic functions | Per exact kernel build | Kernel-module anti-malware, application control |
| Upwind | eBPF (the standard build needs BTF), per-CPU ring buffers | BCC build without BTF; gVisor trace points | 4.14 (5.4 recommended) | Not documented |
| Sweet Security | eBPF (Rust) | none documented | 5.10 on VMs | Blocks a syscall (`clone()` example), mechanism not stated |

---

## CrowdStrike Falcon sensor for Linux

CrowdStrike's documentation is login-only. The mode and requirement text below comes from third-party
copies of the Falcon docs pages, last updated June 2024 [cs-modes] [cs-sysreq], and from third-party
copies of the 7.30 and 7.31 release notes [cs-rn730] [cs-rn731]. The Linux event list comes from an
unofficial extract of CrowdStrike's "Events Full Reference" (998 events, snapshot 2026-06-02)
[cs-dict] *(community extract)*. In that extract many Linux events have no description; those are
marked † here, and their meaning is inferred from the name.

### Architecture

- Two backends plus a safe mode. Kernel mode: "The sensor pins to the Linux kernel to observe and take
  action on all activity occurring on the kernel". User mode: "The sensor does not require a kernel
  module. Instead, it uses extended Berkley Packet Filter (eBPF) programs that are loaded from the user
  space". The sensor enters reduced functionality mode (RFM) "If the Linux kernel is unsupported and
  doesn't meet user mode requirements" [cs-modes] *(3P mirror)*.
- The process is named `falcon-sensor` in kernel mode and `falcon-sensor-bpf` in eBPF mode
  [cs-operator].
- Mode selection: `falconctl` `backend` accepts `'auto'|'bpf'|'kernel'` on sensors after 6.46.0
  [cs-falconctl], and the installer's `FALCON_BACKEND` defaults to `auto` [cs-install]. "By default,
  the sensor is enabled with mode auto-switching": it uses user mode when kernel mode is unsupported
  and returns to kernel mode when the kernel becomes supported [cs-modes].
- The default is moving to eBPF. From 7.30.18306, "the option to force the Linux sensor to run in
  Kernel Mode will no longer be available if the host distro and kernel support running in User Mode"
  [cs-rn730]. 7.31 does the same for DaemonSets and cites a Tech Alert titled "Falcon Sensor for Linux
  Will Default to Running in User Mode in Upcoming Releases" [cs-rn731]. The current Helm chart says of
  `node.backend`: "Deprecated: This field is ignored. The sensor uses eBPF by default, but falls back
  to kernel mode on unsupported kernel versions" [cs-helm-values].
- Kernel mode needs a certified kernel. New kernels arrive through "zero-touch Linux" (ZTL) channel
  files and a ZTL module that supports new kernels "via offset mapping without having to upgrade to a
  newer sensor version" [cs-sysreq] *(3P mirror)*.
- Hook types are not published. The user-mode kernel requirements (next subsection) include BTF,
  `CONFIG_BPF_EVENTS`, `CONFIG_SECURITY`, `CONFIG_KALLSYMS_ALL` and `CONFIG_BSD_PROCESS_ACCT`, but not
  `CONFIG_BPF_LSM` [cs-sysreq]. [INFERENCE] The programs are CO-RE programs on kprobe/tracepoint-class
  hooks; nothing suggests BPF LSM.
- CrowdStrike says it welcomes user-mode-only processing "as we have done on macOS with the Endpoint
  Security Framework and on Linux with BPF" [cs-blog-kernel].

### Kernels

- User mode on custom kernels needs a "version of 5.8 or later and these kernel config options:
  CONFIG_BPF=y CONFIG_BPF_SYSCALL=y CONFIG_DEBUG_INFO_BTF=y CONFIG_BPF_EVENTS=y CONFIG_BPF_JIT=y
  CONFIG_SECURITY=y CONFIG_KALLSYMS_ALL=y CONFIG_BSD_PROCESS_ACCT=y", "or equivalent eBPF backports".
  User mode is not certified per kernel. It needs sensor 6.47 or later on hosts and 6.49 or later as
  a DaemonSet, and "User mode is not supported for FUSE filesystems and IBM zSystems" [cs-sysreq].
- No public page names kernel 6.15 or later. The 7.30 and 7.31 kernel-mode lists include Ubuntu 6.8
  builds and Debian 12 `6.1.0-40-amd64`, and 7.31 adds "support for Debian 13 on x86_64 in User Mode
  for all kernels" [cs-rn730] [cs-rn731]. [INFERENCE] On a 6.15+ kernel with BTF, a current sensor
  runs in eBPF mode.

### Telemetry on Linux

Every event name below comes from [cs-dict] unless another source is cited.

- **Process**
  - Exec: `ProcessRollup2`. Each instance carries a sensor-generated `TargetProcessId`, and a child
    names its parent through `ParentProcessId`.
  - Processes that were already running when the sensor started: `SyntheticProcessRollup2`.
  - Exit: `TerminateProcess`. The completion event "is EndOfProcess for Windows and Mac and
    TerminateProcess for Linux". `EndOfProcess` carries per-process event counters.
  - Lineage: `ProcessAncestryInformation`, covering parent, grandparent and great-grandparent, and
    only for chains "that haven't been observed recently on the host"; marked "experimental".
  - Executable hash: `ImageHash`.
  - Process injection: `ProcessTrace`†, `RemoteProcessMemoryRead`† and `RemoteProcessMemoryWrite`†.
  - Memory: `MemoryProtectionUpdated` ("Triggers if a new executable memory region is mapped which is
    writable or mapped from a file") and `MemoryMapped`.
  - Deleted executable: `ProcessSelfDeleted`.
  - Environment: `CriticalEnvironmentVariableChanged`.
  - Scripts: `ScriptControlScanInfo`†, `ScriptControlDetectInfo` (malicious script content
    detected), and `PhpEvalString`†, `PhpExecuteScript`†, `PhpBase64Decode`†.
  - TTY: `ShellCommandLineInfo`†, `PtyAttached`†, `PtyDetached`†.
  - Other process events: `ProcessSignal`†, `ProcessSessionCreated`†, `ProcessControl`†,
    `ResourceLimit`†.
  - Packages: `InstalledApplication`.
  - The extract has no Linux fork, setuid, setgid or capset event.
- **File**
  - Reads and opens: `CriticalFileAccessed`, `FileOpenInfo`.
  - Modification: `CriticalFileModified`.
  - Creation and deletion: `FileCreateInfo`, `DirectoryCreate`, `FileDeleteInfo`, `ExecutableDeleted`.
  - Rename: `FileRenameInfo`, "Only sent as part of a detection".
  - chmod: `FileSetMode` ("via chmod/fchmod/fchmodat").
  - Dropped files: `NewExecutableWritten`, `ELFFileWritten` ("contains a real ELF image header"),
    `NewScriptWritten` (shebang or script extension), about fifty typed `*FileWritten` events,
    `FileWrittenAndExecutedInContainer` and `RecentlyModifiedFileExecutedInContainer`.
  - Library load: `SharedObjectLoaded`†, `LoadImage`.
  - Persistence: `SystemdServiceCreated`†, `SystemdTimerCreated`† and related events. From 7.31,
    `FileContentsChanged` captures content changes under a pre-configured set of cron paths, in user
    mode only [cs-rn731].
  - FIM: `FileIntegrityMonitorRuleMatched` (Falcon FileVantage).
  - The extract has no Linux chown, xattr or link event.
- **Network**
  - Connect: `NetworkConnectIP4`/`IP6`. The Linux text covers both `connect()` and the first
    `sendto()` of a connectionless socket.
  - Accept: `NetworkReceiveAcceptIP4`/`IP6`, covering `accept()` and the first datagram received.
  - Listen and close: `NetworkListenIP4`/`IP6` and `NetworkCloseIP4`/`IP6`. A close event is also
    "generated when a session is inactive for 2 minutes using UDP".
  - Raw and packet sockets: `RawBindIP4`/`IP6`, `CreateSocket`, `PacketFilterAttached`†.
  - DNS: `DnsRequest`. "The sensor waits for the response" and the event includes the answer. "On
    Win/Lin sensor the data is deduplicated based on DomainName, IP4, IP6 and CNAME", and the
    deduplication entries clear "every 24 hrs".
  - Application protocols: `HttpRequest`†, `HttpResponse`†, `TlsClientHello`†, `FtpCommand`†,
    `SmtpCommand`†.
  - Unix sockets: `DBusMessage`, which gives visibility into "D-Bus messages flowing over local Unix
    sockets".
  - Host state: `FirewallRuleIP4Matched`, `LocalIpAddressIP4`, `NeighborListIP4`.
  - There is no NAT tuple event. Per-flow byte counts appear only in a Forensics-only event.
- **Kernel/admin**
  - Module load: `KernelModeLoadImage`.
  - BPF: `BPFCommandIssued` ("Emitted when a process executes bpf syscall.").
  - Namespaces: `NamespaceChanged`†.
  - Mount: `FsVolumeMounted`, `FsVolumeUnmounted`.
  - `KernelModeExecImage` ("Indicates a kernel Image has been loaded into memory"; [INFERENCE] kexec).
  - `HostTimeModified`†, `HostnameChanged`.
  - The extract has no sysctl, perf_event_open, keyring, io_uring, userfaultfd or capability-use event.
- **Identity**
  - Logins: `UserLogon`, `UserIdentity`, `UserLogonFailed2`, `UserLogoff`, `SSHClientAuthenticated`†.
  - Accounts and groups: `UserAccountCreated`, `UserAccountDeleted`, `UserAccountAddedToGroup`,
    `UserGroupCreated`.
  - `SudoCommandAttempt` and `ProcessSubstituteUser` exist only on macOS.
- **Container/K8s**
  - Containers: `OciContainerInfo`, `OciContainerStarted`, `OciContainerStopped`,
    `OciContainerHeartbeat` (every 24 hours).
  - Images and pods: `OciImageInfo`, `PodInfo`.
  - `K8SAdmissionReviewResult` belongs to the "Kubernetes" platform, not to the node sensor.
- **Sensor**
  - Health: `SensorHeartbeat`. RFM shows up as `SensorStateBitMap=2` [cs-modes].
    `ResourceUtilization` is sent every 15 minutes, and `SensorEnteredSafemode` marks safe mode.
  - Tamper: `SensorTampering`.
  - Response results: `KillProcessError`, `QuarantinedFile`, `NetworkContainmentCompleted`,
    `ProcessBlocked`.

### Enrichment

- Process identity comes from sensor-generated IDs (`TargetProcessId`, `ContextProcessId`).
  Cloud metadata comes from `InstanceMetadata`, and containers and pods from the `Oci*` and `PodInfo`
  events [cs-dict].
- On managed Kubernetes, the cluster name "is resolved cloud-side" [cs-operator].

### Response and prevention

- In user mode, these features arrived in the following sensor versions: Network Containment 7.06,
  Real Time Response 6.47, Quarantine 7.02, IOA and ML prevention 6.47. "For prevention, asynchronous
  kill is used instead of process blocking" [cs-modes].
- From 7.31, a domain-name custom IOA can "detect domain name lookups and optionally terminate the
  requesting process" [cs-rn731]. Falcon Firewall Management covers Linux [cs-faq].

### Resource claims and limits

- [VENDOR CLAIM] "a single, lightweight sensor" [cs-techhub]. [VENDOR CLAIM] "scale seamlessly and with
  no performance impact across large environments" [cs-faq].
- DaemonSet resource settings: a "Minimum setting of 250m CPU and 500Mi memory"; the GKE Autopilot
  default is "750m CPU and 1.5Gi memory"; and "Resource limits are not recommended when running in
  kernel mode" [cs-helm-readme].
- The GKE guide shows an example `kubectl top` of `498m` CPU and `223Mi` memory, warns that
  "Incorrect resource settings can lead to sensor deployment failure or a loss of clouded events", and
  says the limits "are only enabled when `backend: bpf`" [cs-gke].
- A 7.30 fix: "The BPF ringbuffer size calculation ignored the assigned cgroup memory limit"
  [cs-rn730].
- The offline cache "holds a maximum of 20,000 events", and it is lost on reboot [cs-dict].
- No host-level CPU or memory figure is published.

### Gaps, aggregation and throttling

- Exec aggregation, Linux text: "Linux sensors send far more ProcessRollup2 events than Windows (roughly
  20x as many), so rather than send events for every process on those hosts, the sensor sends an
  initial ProcessRollup2 event, followed 60 minutes later by a ProcessRollup2Stats event with a SHA256
  hash and the count of how many times the hash executed in the last 60 minutes" [cs-dict].
- Other dedup windows: `DnsRequest` dedup is cleared every 24 hours; a UDP close is synthesized after
  2 minutes of inactivity; `FirewallRuleIP4Matched` reports `RuleMatchCountSinceLastReport` [cs-dict].
- In RFM, sensors "don't have detections or process events, but continue sending SensorHeartBeat
  events" [cs-modes] [cs-duke-rfm].
- User mode was historically partial. Sensors 7.03–7.14 sent file rename events only. Network events
  were TCP only before 7.06, and all event types arrived in 7.15. "Falcon FileVantage All features
  Unsupported" in user mode, as of June 2024 [cs-modes].
- Some newer Linux visibility exists in user mode only: cron `FileContentsChanged`, Environment
  Variable Visibility, SSH Visibility and podman `OciContainer*` events [cs-rn730] [cs-rn731].

[cs-modes]: https://www.scribd.com/document/742992720/Falcon-Sensor-for-Linux-Modes-Falcon-Sensor-for-Linux-Linux-Kubernetes-and-Cloud-Sensor-Deployment-and-Maintenance-Documentation-Support-a
[cs-sysreq]: https://www.scribd.com/document/759240855/Falcon-Sensor-for-Linux-System-Requirements-Falcon-Sensor-for-Linux-Linux-Kubernetes-and-Cloud-Sensor-Deployment-and-Maintenance-Documentati
[cs-rn730]: https://endpoint.vn/release-notes-falcon-sensor-for-linux-7-30-18306/
[cs-rn731]: https://endpoint.vn/release-notes-falcon-sensor-for-linux-7-31-18410/
[cs-dict]: https://raw.githubusercontent.com/erickatwork/CrowdStrike-Falcon-Events-Data-Dictionary/main/data/current/sensor_events.csv
[cs-operator]: https://github.com/CrowdStrike/falcon-operator/blob/main/docs/resources/node/README.md
[cs-falconctl]: https://developer.crowdstrike.com/falcon-sensor/ansible/modules/falconctl/
[cs-install]: https://developer.crowdstrike.com/falcon-sensor/scripts/bash/install/
[cs-helm-values]: https://raw.githubusercontent.com/CrowdStrike/falcon-helm/main/helm-charts/falcon-sensor/values.yaml
[cs-helm-readme]: https://raw.githubusercontent.com/CrowdStrike/falcon-helm/main/helm-charts/falcon-sensor/README.md
[cs-gke]: https://raw.githubusercontent.com/CrowdStrike/falcon-operator/main/docs/deployment/gke/README.md
[cs-blog-kernel]: https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/
[cs-faq]: https://www.crowdstrike.com/en-us/products/faq/
[cs-techhub]: https://www.crowdstrike.com/tech-hub/endpoint-security/installing-falcon-sensor-for-linux/
[cs-duke-rfm]: https://oit.duke.edu/help/articles/kb0038677/

---

## SentinelOne Singularity for Linux (Linux Sentinel agent, Cloud Workload Security)

SentinelOne's KB is login-only. Most mechanism detail comes from SentinelOne agent release notes as
republished by N-able *(3P mirror)* and from a reseller KB that restates SentinelOne's requirements
*(3P mirror)* [s1-guardz]. Event-type names come from Google SecOps' SentinelOne parser and Elastic's
Cloud Funnel integration *(3P integration)*. Those lists span all operating systems and do not say
which event types the Linux agent emits [s1-secops] [s1-elastic].

### Architecture

- [VENDOR CLAIM in part] "Our agents operate entirely in user space, making use of eBPF (Extended
  Berkeley Packet Filter) probes for visibility into the kernel without the hassles of kernel
  dependencies". The Kubernetes agent uses "no container sidecar or usage of kernel modules"
  [s1-ga223]. SentinelOne also describes pre-filtering in the kernel: "observe kernel behavior and
  perform analysis within the kernel before transferring a subset of results back to user space"
  [s1-ebpf-blog].
- The agent is not eBPF-only. In 22.1, the "*perf* provider [was] enhanced to use the eBPF framework to
  track file create, delete, and rename events" [s1-rn221]. 22.2 did the same "to track execv and chmod
  events" and added a "New eBPF-based file read sensor" [s1-rn222]. In 23.1, "The s1-perf and
  s1-fanotify processes are no longer running ... merged in to the s1-agent process" [s1-rn231].
- Hooks named in the 23.4 notes: "A new memory_dump event type ... uses the eBPF kprobe hook on the
  mem_read kernel function ... supported on all systems that support eBPF CORE"; "A new chroot event
  type ... supported only on systems that support security_path_* hooks"; "TCP connection events are
  now monitored with eBPF"; "The Agent now enforces type-based mount exclusions at the kernel level when
  using eBPF hooks" [s1-rn234]. SSH-origin enrichment is "available for uprobe-supported scenarios
  only" [s1-rn242].
- From 23.2, excluded processes are filtered "in the eBPF program" [s1-rn232]. SentinelOne maintains a
  fork of libbpf [s1-libbpf].
- How the agent chooses between eBPF, perf and fanotify is not documented beyond "where the OS supports
  it" [s1-rn221].

### Kernels

- "Kernels earlier than 2.6 (build 2.6.32-358) — not supported." Below 3.8, "File Modification and
  Network event types are not supported for telemetry collection". Below 3.10, "containers are not
  supported, and the Agent is not compatible with eBPF" [s1-guardz].
- Known problems: kernel bugs in `4.19.0-6-amd64` and `4.19.0-8-amd64` "can cause system freezes";
  RHEL 8.1's `4.18.0-147` "may experience a soft lockup when the Agent uses eBPF"; Kernel Lockdown set
  to Confidentiality is unsupported; the agent's hooks interfere with Ksplice [s1-guardz].
- Recent agents are matched to distro releases: RHEL 10.2 needs 25.4+, and Ubuntu 26.04 and Debian 13.6
  need 26.1 [s1-guardz]. No statement covers BTF or kernels 6.x.

### Telemetry

Event types are the verbatim `event.type` values from [s1-secops], unless a Linux-specific source is
cited.

- **Process**
  - Exec: `Process Creation`. execv has been collected through eBPF on Linux since 22.2 [s1-rn222].
  - Exit and modification: `Process Exit`, `Process Modification`.
  - Cross-process: `Open Remote Process Handle`, `Remote Thread Creation`, `Duplicate Process Handle`.
    The names are Windows-centric, and their Linux mapping is undocumented.
  - Linux `memory_dump` event, which flags reads of another process's memory through the kprobe on
    `mem_read` [s1-rn234].
  - Scripts: `Command Script` (`cmdScript.content`, `cmdScript.sha256`) [s1-elastic]. On Linux,
    "Active content for interactive bash and python sessions has an improved classification"
    [s1-rn234].
  - Linux rules: `execute_from_memfd` [s1-rn231] and `pkexec_pe` [s1-rn231].
  - Identity fields on processes: `src.process.eUserUid`, `src.process.rUserUid`,
    `src.process.lUserName` [s1-secops].
  - Lineage: Storyline, "automatic PID tree context creation and re-linking" [s1-datasheet].
    `src.process.storyline.id` and `src.process.uid` give "SentinelOne's stable process identity"
    [s1-fields].
  - Hashes: `src.process.image.sha256` [s1-secops]. From 24.2 the agent "reports the SHA-256 value
    for supported file types to Deep Visibility" [s1-rn242].
  - Module loads: `Module Load` (`module.path`, `module.sha256`) and `Driver Load` exist; Linux
    applicability is undocumented [s1-fields] [s1-secops].
  - From 23.4, Behavioral Indicator events for binary-integrity detections are enriched "with the
    corrupted package name" [s1-rn234].
- **File**
  - `File Creation`, `File Deletion`, `File Rename` (`tgt.file.oldPath`) and `File Modification`
    [s1-secops]. Create, delete and rename have come through eBPF on Linux since 22.1 [s1-rn221].
  - chmod comes through eBPF since 22.2 [s1-rn222].
  - Sensitive reads: "New eBPF-based file read sensor allows the Agent to detect any read access to
    specific sensitive system files. The list of files is not configurable". The indicators are
    `ReadShadow`, `ReadPasswdFile` and `ReadSSHKeys` [s1-rn222].
  - Cron: rule `suspicious_cron_activity` [s1-rn231].
- **Network**
  - `IP Connect` (direction `INCOMING`/`OUTGOING`) and `IP Listen`; `DNS Resolved`, `DNS Unresolved`;
    and HTTP method events `GET`, `POST`, `CONNECT` and others [s1-secops].
  - Linux TCP connections go through eBPF from 23.4 [s1-rn234]. IPv6 collection is stated for macOS
    only [s1-rn234].
- **Kernel/admin**
  - Linux `chroot` event [s1-rn234].
  - Rules: `disarm_all_kprobes` ("detects if kprobes are disabled") and `mount_host_container_escape`
    [s1-rn234].
  - No public module, BPF, namespace or sysctl event for Linux.
- **Identity**
  - `Login` and `Logout` (`event.login.loginIsSuccessful`, `event.login.sessionId`) [s1-fields]
    [s1-secops]. `Group Creation` also exists; the sample is from Windows [s1-secops].
  - Linux limits: in agent 25.3 and earlier, failed logins are not detected on AlmaLinux 10, CentOS
    Stream 9, Oracle Linux 10, RHEL 10, RHEL 9.8 and Rocky Linux 10; in 26.1 and earlier, logins and
    logouts are not detected on Debian 13 [s1-guardz].
  - From 24.2, a threat that came in over SSH is enriched with the source IP and target user [s1-rn242].
- **Container/K8s**
  - `k8sCluster.containerId`, `k8sCluster.containerImage`, `k8sCluster.podName`,
    `k8sCluster.podLabels`, `k8sCluster.namespaceLabels` [s1-secops]. ECS task metadata from 24.2
    [s1-rn242].
- **Sensor**
  - Linux 23.4: `systemctl stop sentinelone.service` "is refused and a suspicious alert is generated"
    [s1-rn234].
  - Ransomware decoy files `.aaa.pdf` and others under predefined paths [s1-rn217].

### Response and prevention

- Linux response: "Secure remote shell", "Firewall control", "Network isolation", "File fetch".
  Prevention: "On-agent Static AI blocks & quarantines malware in real time in ELF ... binaries" and
  "On-agent Behavioral AI stops previously unknown fileless threats" [s1-datasheet].
- Rollback: "Mac and Linux don't have the same native shadow copy technology, so rollback capabilities
  are limited on these systems" [s1-rollback].
- No in-kernel blocking mechanism is documented. [INFERENCE] Kill and quarantine are user-space actions
  taken after detection.

### Resource claims and limits

- Minimum: "1 CPU core / 2 threads, dedicated to the Agent", "800 MB RAM minimum, dedicated to the
  Agent", and 2 GB in `/opt/sentinelone` [s1-guardz].
- [VENDOR CLAIM] v22.1+: "40-50% improvement in memory usage, and 40-50% improvement in CPU usage"
  [s1-ga223]. [VENDOR CLAIM] "negligible impact on endpoint resources" [s1-dv].
- Caps: memory limits are "enabled by default for systems with less than 500GB of memory" [s1-rn221];
  `sentinelctl resource cpu limit set` sets a CPU cap [s1-rn234]; and SentinelOne recommends "the
  memory, CPU, and queue capping features" [s1-rn231]. What happens to events when a cap is hit is not
  documented.
- Network file systems are excluded from file events by default: "fuse.lxcfs, cifs, nfs, nfs4, ...,
  and hdfs" [s1-rn232].

### Gaps, aggregation and throttling

- Linux 23.4: "The interval for sending Deep Visibility™ packets changed from one to three minutes, or
  every 1000 Deep Visibility™ events. ... Behavioral Indicator events are aggregated into a single event
  and reported one time per minute. ... File events are aggregated into a single event and reported one
  time per minute." [s1-rn234]
- The sensitive-file list is fixed. No public table maps event types to Linux.

[s1-ga223]: https://www.sentinelone.com/blog/feature-spotlight-announcing-general-availability-ga-of-linux-and-k8s-agents-v22-3-for-cloud-workload-security/
[s1-ebpf-blog]: https://www.sentinelone.com/blog/the-advantages-of-ebpf-for-cwpp-applications/
[s1-rn217]: https://status.n-able.com/2021/09/30/advance-notice-edr-linux-agent-update-21-7-ga-21-7-3-6/
[s1-rn221]: https://status.n-able.com/2022/06/09/advance-notice-edr-mac-22-1-ga-and-linux-agent-update/
[s1-rn222]: https://status.n-able.com/2022/10/31/advance-notice-edr-linux-agent-update/
[s1-rn231]: https://status.n-able.com/2023/07/05/advance-notice-edr-mac-and-linux-agent-update-to-23-1-ga/
[s1-rn232]: https://status.n-able.com/2023/11/09/advance-notice-edr-w-sp5-release-agents-23-2/
[s1-rn234]: https://status.n-able.com/2024/05/10/advance-notice-edr-agents-release-23-4-ga-update-wednesday-may-15th/
[s1-rn242]: https://status.n-able.com/2024/09/27/advance-notice-edr-agents-release-24-2-ga-macos-linux-update-october-2nd/
[s1-guardz]: https://support.guardz.com/en/articles/16621096-sentinelone-agent-requirements-on-linux
[s1-libbpf]: https://github.com/Sentinel-One/s1-libbpf
[s1-secops]: https://cloud.google.com/chronicle/docs/ingestion/default-parsers/sentinelone-cf
[s1-elastic]: https://www.elastic.co/docs/reference/integrations/sentinel_one_cloud_funnel
[s1-fields]: https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/plugins/s1-secops-skills/skills/powerquery/references/fields-and-schema.md
[s1-datasheet]: https://go.sentinelone.com/rs/327-MNM-087/images/Linux.pdf
[s1-rollback]: https://www.sentinelone.com/cybersecurity-101/cybersecurity/what-is-ransomware-rollback/
[s1-dv]: https://www.insight.com/content/dam/insight-web/en_US/pdfs/sentinelone/SentinelOne-deep-visibility.pdf

---

## Microsoft Defender for Endpoint on Linux

### Architecture

- The EDR event source is an eBPF "supplementary event provider", on by default since `101.23082.0006`:
  "events previously obtained from the AuditD event provider now flow from the eBPF sensor", which
  "uses capabilities of the Linux kernel without requiring the use of a kernel module" [mde-ebpf].
- AuditD is gone: "Starting with Defender for Endpoint on Linux, version `101.2408.0000`, AuditD is no
  longer be supported as a supplementary event provider" [mde-ebpf].
- The fallback when eBPF is unavailable is Netlink: "While Netlink continues to capture process events
  (for example, `exec`, `exit`, `fork`, `gid`, or `tid`), it doesn't support file system-related events
  (for example, `rename`, `unlink`) or socket events" [mde-ebpf]. [INFERENCE] This is the proc
  connector.
- eBPF attach types are not documented. The `mdatp diagnostic ebpf-statistics` sample output lists "Top
  syscall ids" [mde-ebpf] [mde-perf]. [INFERENCE] The sensor keys work by syscall number.
- Real-time AV uses fanotify in blocking mode. "Running Defender for Endpoint on Linux alongside other
  Fanotify-based security solutions isn't supported and may lead to unpredictable behavior, including
  system hangs" [mde-prereq].

### Kernels

- The base agent needs "`3.10.0-327` or later" and is "kernel-version agnostic for all other supported
  distributions"; it requires systemd [mde-prereq].
- The eBPF table starts at Ubuntu 16.04 / `4.15.0`, RHEL 7.6 / `3.10.0-957.10`, Amazon Linux 2 /
  `5.4.261-174.360`, and so on. No BTF requirement is stated for the event sensor [mde-ebpf].
- Tamper protection on Linux (audit-mode preview) does need eBPF with BTF ("BTF provides the file and
  process context") [mde-tamper-audit].
- Known eBPF problems: a kernel panic on RHEL 8.1 with SAP, hangs on Oracle Linux 8.8 UEK `5.15.0-0.30.20`,
  and hangs with ksplice on Oracle Linux 7.9 [mde-ebpf].

### Telemetry (Advanced Hunting)

Microsoft does not publish ActionType values per OS. Each table page says to "use the built-in schema
reference available in the Defender portal", which is login-only [mde-dpe] [mde-dne]. The
ActionTypes below come from community queries against WSL2 devices [michalos], from community schema
examples that are not labelled by OS [xdri-file] [xdri-net], and from Microsoft's configuration pages.
Microsoft's WSL plug-in page says the timeline "is populated, similar to Defender for Endpoint on
Linux, with events from inside the subsystem (file, process, network)", and it queries
`DeviceProcessEvents` with `OSPlatform == "Linux"` [mde-wsl].

- **Process**
  - Exec: `DeviceProcessEvents` / `ProcessCreated`, used in a community query scoped to WSL2 devices
    running the MDE WSL plug-in, not the native Linux agent [michalos]. Columns include
    `ProcessCommandLine`, `SHA1` and `MD5`; `SHA256` is "usually not populated" [mde-dpe].
  - Lineage: `InitiatingProcessParentId`, `InitiatingProcessParentFileName`, `ProcessUniqueId`
    [mde-dpe].
  - Exit, fork and gid changes are sensor-level events under Netlink [mde-ebpf]; no Linux ActionType
    for them is published.
  - POSIX identity in `AdditionalFields`: `InitiatingProcessPosixEffectiveUser`,
    `InitiatingProcessPosixRealUser`, `InitiatingProcessPosixSessionId`,
    `InitiatingProcessCurrentWorkingDirectory` [xdri-net].
  - From 101.26042.0011, "file, process, and network security events now include the original login
    user's ID, even when actions are performed via sudo or under root" [mde-releases], stored as
    `LogonID` inside `InitiatingProcessPosixEffectiveUser` [mde-dpe].
  - ptrace monitoring exists but is off by default: `enableProcessCalls`, "ptrace events are monitored
    and scanned", requires behavior monitoring [mde-prefs].
- **File**
  - `DeviceFileEvents` / `FileCreated` in community queries on Linux persistence paths (`/etc/cron.d/`,
    `/etc/systemd/system/`) [michalos].
  - `FileModified`, `FileDeleted` and `FileRenamed` appear in community schema examples with
    `FilePosixPermissions` [xdri-file]. Rename and unlink need the eBPF provider [mde-ebpf].
  - chmod and chown are off by default: `enableFilePermissionEvents` ("monitors changes to the executed
    bits of files") and `enableFileOwnershipEvents` [mde-prefs].
  - Library load is off by default: `features.moduleLoad` ("file open events on shared libraries")
    [mde-prefs].
  - procfs opens: `enableOtherFsOpenEvents` [mde-prefs].
- **Network**
  - `DeviceNetworkEvents` with `ConnectionSuccess`, `ConnectionRequest` and others in community schema
    examples carrying Linux POSIX fields [xdri-net]. Socket events need eBPF [mde-ebpf].
  - Raw and packet sockets, and setsockopt, are off by default: `enableRawSocketEvent` [mde-prefs].
  - Network protection (preview, "not supported on the production channel") blocks outbound HTTP(S) by
    domain through "a virtual private network (VPN) tunnel" [mde-netprot].
  - No Linux DNS event is documented.
- **Kernel/admin**
  - `.ko` file "creation, rename, and deletion" visibility (101.26032.0000) [mde-releases].
  - Off by default: `enableEbpfModuleLoadEvents` ("module load events are monitored by eBPF") and
    `enableBootLoaderCalls` [mde-prefs].
- **Identity**
  - Release notes mention Linux login events ("Username information is now preserved for login
    events", "Improved login event accuracy") but give no table or ActionType [mde-releases].
- **Container/K8s**
  - Nothing is documented for MDE on Linux.
- **Sensor**
  - Tamper: `DeviceEvents` / `TamperingAttempt` [mde-tamper]; on Linux it is an audit-only preview
    [mde-tamper-audit].
  - Health: `mdatp health` (`supplementary_events_subsystem`, `conflicting_applications`) and
    `DeviceTvmInfoGathering` with `EBPF STATUS: true` [mde-ebpf].

### Response and prevention

- Real-time protection through fanotify; quarantine to `/var/opt/microsoft/mdatp/quarantine`
  [mde-prereq] [mde-resources]. Behavior monitoring "monitors process behavior in real time to detect
  and block malicious activity" [mde-overview].
- Device isolation needs `iptables` and `CONFIG_NETFILTER_XT_MATCH_OWNER` on 5.x kernels. Isolation is
  lifted "when an administrator modifies or adds a new `iptable` rule" [mde-respond].
- Live response on Linux supports `processes`, `getfile` (3 GB), `run` (Bash from the library), and
  `remediate` (delete a file; stop a process). It does not support `connections`, `persistence` or
  `isolate` [mde-live].
- No LSM enforcement is documented.

### Resource claims and limits

- Minimums: "One CPU core minimum", "1 GB of RAM minimum", "2 GB minimum" disk [mde-prereq]. The
  guidance for breach-and-attack-simulation hosts recommends "4 CPU cores" and "2 GB of RAM minimum"
  [mde-bas].
- [VENDOR CLAIM] eBPF gives "Reduced overhead for file event (file read/open) monitoring" and "Improved
  event rate throughput and reduced memory footprint" [mde-ebpf]. [VENDOR CLAIM] "lightweight eBPF-based
  sensor architecture ... minimal overhead and zero workload disruption" [mde-overview].
- Diagnostics: `mdatp diagnostic hot-event-sources files|executables` reports events per path, with a
  sample throughput of "75.3333 events/sec" [mde-perf].
- eBPF exclusions apply only through global exclusions or "Reach out to Microsoft to apply the exclusions
  from the backend" [mde-ebpf].

### Gaps, aggregation and throttling

- With Netlink only, there are no file-system or socket events [mde-ebpf].
- Defaults are narrow. AV is `passive`, behavior monitoring is `disabled`, and chmod, chown, raw socket,
  ptrace, module-load and boot-loader monitoring are all `disabled` [mde-prefs].
- Aggregated reporting (`ProcessCreatedAggregatedReport` and similar, hourly) [mde-agg] and custom data
  collection ("up to 75,000 events per device per 24-hour rolling window") [mde-custom-rules] list
  Windows only. No numeric cap on the default Linux stream is published.

[mde-ebpf]: https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf
[mde-prereq]: https://learn.microsoft.com/en-us/defender-endpoint/mde-linux-prerequisites
[mde-overview]: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux
[mde-perf]: https://learn.microsoft.com/en-us/defender-endpoint/linux-support-perf
[mde-resources]: https://learn.microsoft.com/en-us/defender-endpoint/linux-resources
[mde-prefs]: https://learn.microsoft.com/en-us/defender-endpoint/linux-preferences
[mde-netprot]: https://learn.microsoft.com/en-us/defender-endpoint/network-protection-linux
[mde-respond]: https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts
[mde-live]: https://learn.microsoft.com/en-us/defender-endpoint/live-response
[mde-bas]: https://learn.microsoft.com/en-us/defender-endpoint/guidance-pen-testing-bas-linux
[mde-tamper-audit]: https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-linux-audit-mode
[mde-tamper]: https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview
[mde-agg]: https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting
[mde-custom-rules]: https://learn.microsoft.com/en-us/defender-endpoint/create-custom-data-collection-rules
[mde-releases]: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases
[mde-dpe]: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
[mde-dne]: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table
[xdri-net]: https://xdrinternals.com/docs/microsoftxdr/devices/devicenetworkevents/
[xdri-file]: https://xdrinternals.com/docs/microsoftxdr/devices/devicefileevents/
[michalos]: https://www.michalos.net/2024/06/25/keeping-an-eye-on-wsl-through-microsoft-defender-for-endpoint/
[mde-wsl]: https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl

---

## Elastic Defend (Elastic Endpoint) on Linux

Elastic's kernel-side code is public (GPL BPF programs in `elastic/ebpf`, and the `quark` library); the
endpoint binary is not. Event documentation comes from the `endpoint-package` repo, which has one page
per Linux event.

### Architecture

- Three capture backends, chosen by `linux.advanced.kernel.capture_mode`: "Options are kprobe, ebpf,
  quark or auto. auto uses quark if possible (and supported), then tries legacy ebpf, and otherwise it
  uses kprobe. Quark is supported by Elastic Defend versions 9.3 and newer" [ela-adv].
- "On newer kernels (5.10.16+), Elastic endpoint uses eBPF to source the various security events ... On
  older kernels, this data is sourced via tracefs instead" [ela-ebpf]. (The events doc says 5.11+
  [ela-events-md].) Events reach userspace through a BPF ring buffer [ela-events-md].
- The hooks are on semantic kernel functions, with fentry/fexit variants and kprobe fallbacks
  [ela-proc-probe] [ela-file-probe] [ela-net-probe]:
  - Process: `tp_btf/sched_process_fork`, `tp_btf/sched_process_exec`, `commit_creds`, `tty_write`,
    `ptrace_attach`, `tp_btf/module_load`, the `memfd_create` and `shmget` syscall tracepoints, and
    `sys_exit_setsid`.
  - File: `do_filp_open`, `vfs_unlink`, `vfs_rename`, `chmod_common`, `chown_common`, `do_truncate`,
    `vfs_write`.
  - Network: `tcp_v4_connect`, `tcp_v6_connect`, `inet_csk_accept`, `tcp_close`. There is no UDP or
    DNS hook in that file.
- Kernel-to-user event enum (verbatim): `EBPF_EVENT_PROCESS_FORK`, `_EXEC`, `_EXIT`, `_SETSID`,
  `_SETUID`, `_SETGID`, `_TTY_WRITE`, `EBPF_EVENT_FILE_DELETE`, `_CREATE`, `_RENAME`, `_MODIFY`,
  `_MEMFD_OPEN`, `_SHMEM_OPEN`, `EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED`, `_ATTEMPTED`, `_CLOSED`,
  `EBPF_EVENT_PROCESS_MEMFD_CREATE`, `_SHMGET`, `_PTRACE`, `_LOAD_MODULE` [ela-proto].
- Quark: "Currently, EBPF and a kprobe-based backend are provided"; it reuses the elastic/ebpf programs
  [ela-quark]. From quark 0.8, "quark_queue_open() now requires exactly one backend flag ... The fallback
  that tried ebpf and fell back to kprobe is gone" [ela-quark-changes].
- Malware protection uses fanotify (`linux.advanced.fanotify.*`); `FAN_OPEN_PERM` is mentioned for
  kernels "older than 5.0" [ela-adv]. Host isolation uses eBPF: a connect kprobe allowlist plus a TC
  filter [ela-hostiso].

### Kernels

- eBPF event sourcing needs 5.10.16+ [ela-ebpf]. "On Linux, DNS events are only available with
  eBPF-based event collection", and terminal output capture also needs eBPF [ela-policy].
- Release notes: "Updates eBPF probes for Elastic Defend on Linux to support 7.0 kernels"; "support
  kernels with lazy preemption enabled"; "Improves `fanotify` event collection reliability in Elastic
  Defend on Ubuntu 26.04 and Linux 7.0" [ela-rn].
- "Linux ARM support is 7.16+ only and requires a 5.4+ kernel" [ela-matrix].

### Telemetry

Data streams: `logs-endpoint.events.process-*`, `.file-*`, `.network-*` (network includes DNS).
Policy event categories on Linux are DNS (since 9.3), File, Network and Process [ela-policy].

- **Process**
  - `event.action`: `fork`, `exec`, `end`, or an aggregate of them. Fields include `process.args`,
    `process.working_directory`, `process.env_vars`, `process.exit_code`, `process.interactive`, and
    `process.tty.char_device.*` [ela-pkg-exec].
  - `already_running` is a snapshot event for processes that predate the sensor [ela-pkg-already].
  - Credential changes: `uid_change` and `gid_change` [ela-pkg-uid] [ela-pkg-gid]. Session changes:
    `session_id_change` [ela-pkg-sid].
  - Injection: `ptrace`, with `process.Ext.ptrace.request` and `child_pid` [ela-pkg-ptrace].
    `process_vm_writev` and `/proc/pid/mem` are not documented.
  - Fileless: `memfd_create` (`process.Ext.memfd.flags`, `name`) [ela-pkg-memfd] and `shmget`
    [ela-pkg-shmget].
  - Memory: `mprotect`, "as observed at the kernel's security_file_mprotect check ... does not assert
    that the protection change was committed". It is reported "once per protection transition per
    process life" for anonymous memory, and per file for file-backed memory [ela-pkg-mprotect].
  - TTY output: `text_output` (`process.io.text`, `process.io.max_bytes_per_process_exceeded`)
    [ela-pkg-tty].
  - Lineage: `process.Ext.ancestry` (default length 5), `process.entry_leader.*`,
    `process.session_leader.*`, `process.group_leader.*` [ela-pkg-exec] [ela-adv].
  - Hashes: `process.hash.sha256` and others. From 8.18 they default to `false` [ela-adv].
  - Capabilities: `process.thread.capabilities.effective`, behind `linux.advanced.events.enable_caps`,
    which defaults to false [ela-adv].
- **File**
  - `creation` (with optional `file.Ext.entropy` and `file.Ext.header_bytes`) [ela-pkg-fcreate],
    `modification` [ela-pkg-fmod], `rename` [ela-pkg-frename] and `deletion` [ela-pkg-fdelete].
  - Hooks exist for chmod and chown, but there is no separate `event.action` [ela-file-probe].
  - FIM-style hashing: `advanced.events.file.max_hash_size_mb`, "asynchronous, best-effort", default
    `off` [ela-adv].
  - There is no file-open event on the host product.
  - Persistence paths are covered by generic file events plus rules, e.g. a cron rule on
    `event.action in ("rename", "creation")` for paths such as `/etc/cron.allow` [ela-cron-rule].
- **Network**
  - `connection_attempted`, `connection_accepted`, `disconnect_received` (`source.bytes`,
    `destination.bytes`) [ela-pkg-net].
  - DNS: `lookup_requested` and `lookup_result` (`dns.question.name`, `dns.resolved_ip`) [ela-pkg-dns].
  - IPv6 TCP connects are supported [ela-rn].
  - Not emitted: "Elastic Defend tracks TCP connections. If a port is created but no traffic flows, no
    events are generated" [ela-capture].
- **Kernel/admin**
  - `load_module` (`process.Ext.load_module.name`, `.taints`) [ela-pkg-module].
  - No mount, BPF, namespace, kexec, sysctl or io_uring event is documented.
- **Identity**
  - "doesn't include every user event such as logins and logouts, or every time a user account is
    created, deleted, or modified" [ela-capture].
  - `process.entry_leader.entry_meta.type` and `.source.ip` record whether a session came from a
    terminal, SSH or similar [ela-pkg-exec].
- **Container/K8s**
  - On process events: `container.id`, `container.image.name`, `orchestrator.namespace`,
    `orchestrator.resource.name` [ela-pkg-exec].
- **Sensor**
  - Linux alerts: `malicious_file`, `memory_signature`, `behavior`, `ransomware`
    [ela-pkg-alerts].
  - Tamper: Agent tamper protection (an uninstall token) is "supported for all operating systems" and
    is "defense-in-depth ... does not provide comprehensive protection against all administrative
    attacks" [ela-tamper].

### Enrichment

- The Linux event model (ECS RFC 0030) builds `entity_id` as "fn(process.pid, process.start,
  host.pid_ns_ino, host.boot.id)" and adds the entry, session and group leaders [ela-rfc30].
- Cloud fields (`cloud.instance.name`, `cloud.region`) and AI-agent attribution
  (`process.ai_agent.name`) [ela-pkg-exec].

### Response and prevention

- Response console on Linux: `isolate`, `release`, `kill-process`, `suspend-process`, `processes`,
  `get-file`, `execute`, `upload`, `scan`, `memory-dump` (since 9.4), `runscript` [ela-resp] [ela-rn].
- Malware: an ML model with Detect or Prevent, scanning on modification and on execute; quarantine to
  `.equarantine` at the mount root [ela-policy]. Memory threat and malicious-behavior protection:
  Prevent "forces the process to stop" [ela-policy].
- Elastic Defend for Containers (`cloud_defend`, a separate CWPP integration) "uses eBPF LSM and
  tracepoint probes"; a `block` action "happens *before* the execution of the event". It needs
  "Minimum kernel version: **5.10.16**" and `CONFIG_BPF_LSM=y`, with "`bpf` ... included in the LSM
  list". Its file hook points are `lsm__path_chmod`, `lsm__file_open`, `lsm__path_rename`,
  `lsm__path_link`, `lsm__path_unlink` and others [ela-cd].

### Resource claims and limits

- Requirements: CPU "Under 2%" [VENDOR CLAIM], RSS "500 MB", disk "1 GB" [ela-req].
- `[linux,windows].advanced.utilization_limits.cpu`: "Restrict Endpoint CPU usage to a percentage of
  the total system CPU. The range is `20`-`100%` ... Default: `50`" [ela-adv].
- Quark ring buffer: "512 KiB per CPU, rounded up to a power of two, floored at 4 MiB and capped at 64
  MiB" [ela-quark-changes]. Its hold time scales with queue fill: "from [0; 10%] -> 1000ms, from [90%;
  100%] -> 0ms" [ela-quark]. It counts `lost` events [ela-quark-stats].

### Gaps, aggregation and throttling

- "Elastic Defend isn't designed to provide a complete capture of all system events. The event data
  that Elastic Defend generates might be aggregated, truncated, or deduplicated" [ela-capture].
- Process aggregation merges "`fork`/`exec`/`end` events (macOS/Linux) when possible ...
  short-lived processes only generate a single event", producing `event.action=[fork, exec, end]`.
  Network events are merged too. `aggregate_process` and `aggregate_network` default to `true` from 8.18
  [ela-volume].
- Network dedup: "Elastic Endpoint doesn't emit network events for repeated connections based on the
  Src-IP/Dst-IP/Dst-Port/PID tuple grouping"; `deduplicate_network_events_below_bytes` is `1048576`
  [ela-adv].
- `event_filter.default` drops "system activity known to be noisy" based on rules Elastic maintains.
  Event filters "do not lower CPU usage on hosts" [ela-adv] [ela-filters].
- TTY output is capped at 512 KB per process, and password entry is not captured [ela-session].
- fanotify ignores unknown and network file systems by default, and "can only monitor the root of a
  Btrfs file system" [ela-fsmon].

[ela-adv]: https://www.elastic.co/docs/reference/security/defend-advanced-settings
[ela-rn]: https://www.elastic.co/docs/release-notes/security
[ela-ebpf]: https://github.com/elastic/ebpf
[ela-events-md]: https://raw.githubusercontent.com/elastic/ebpf/main/docs/events.md
[ela-proc-probe]: https://raw.githubusercontent.com/elastic/ebpf/main/GPL/Events/Process/Probe.bpf.c
[ela-file-probe]: https://raw.githubusercontent.com/elastic/ebpf/main/GPL/Events/File/Probe.bpf.c
[ela-net-probe]: https://raw.githubusercontent.com/elastic/ebpf/main/GPL/Events/Network/Probe.bpf.c
[ela-proto]: https://raw.githubusercontent.com/elastic/ebpf/main/GPL/Events/EbpfEventProto.h
[ela-hostiso]: https://raw.githubusercontent.com/elastic/ebpf/main/docs/hostisolation.md
[ela-quark]: https://github.com/elastic/quark
[ela-quark-changes]: https://raw.githubusercontent.com/elastic/quark/main/CHANGES
[ela-quark-stats]: https://elastic.github.io/quark/quark_queue_get_stats.3.html
[ela-policy]: https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend
[ela-capture]: https://www.elastic.co/docs/solutions/security/manage-elastic-defend/event-capture-elastic-defend
[ela-volume]: https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-data-volume-for-elastic-endpoint
[ela-req]: https://www.elastic.co/docs/solutions/security/configure-elastic-defend/elastic-defend-requirements
[ela-fsmon]: https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-linux-file-system-monitoring
[ela-resp]: https://www.elastic.co/docs/solutions/security/endpoint-response-actions
[ela-session]: https://www.elastic.co/docs/solutions/security/investigate/session-view
[ela-filters]: https://www.elastic.co/docs/solutions/security/manage-elastic-defend/event-filters
[ela-matrix]: https://www.elastic.co/support/matrix
[ela-rfc30]: https://raw.githubusercontent.com/elastic/ecs/main/rfcs/text/0030-linux-event-model.md
[ela-cd]: https://www.elastic.co/docs/reference/integrations/cloud_defend
[ela-pkg-exec]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_fork_exec_exit.md
[ela-pkg-already]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_already_running.md
[ela-pkg-uid]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_uid_change.md
[ela-pkg-gid]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_gid_change.md
[ela-pkg-sid]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_session_id_change.md
[ela-pkg-ptrace]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_ptrace.md
[ela-pkg-memfd]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_memfd_create.md
[ela-pkg-shmget]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_shmget.md
[ela-pkg-mprotect]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_mprotect.md
[ela-pkg-tty]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_text_output.md
[ela-pkg-module]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/process/linux/linux_process_load_module.md
[ela-pkg-fcreate]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/file/linux/linux_file_create.md
[ela-pkg-fmod]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/file/linux/linux_file_modification.md
[ela-pkg-frename]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/file/linux/linux_file_rename.md
[ela-pkg-fdelete]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/file/linux/linux_file_delete.md
[ela-pkg-net]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/network/linux/linux_network_attempted_accepted_and_disconnect.md
[ela-pkg-dns]: https://raw.githubusercontent.com/elastic/endpoint-package/main/custom_documentation/doc/endpoint/network/linux/linux_network_dns_lookup_result.md
[ela-pkg-alerts]: https://github.com/elastic/endpoint-package/tree/main/custom_documentation/doc/endpoint
[ela-cron-rule]: https://raw.githubusercontent.com/elastic/detection-rules/main/rules/linux/persistence_cron_job_creation.toml
[ela-tamper]: https://www.elastic.co/docs/solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation

---

## Sysdig Secure (Sysdig Agent / Host Shield; Falco-based)

### Architecture

- Three drivers. Universal eBPF (`universal_ebpf`) is "pre-built and embedded directly into the agent
  binary", uses ring buffers, and is "the preferred method". The kernel module (`kmod`) "must be built
  against the headers for the specific kernel". Legacy eBPF (`legacy_ebpf`) "will be retired on December
  4, 2026" [sd-drivers].
- "Agent drivers attach event handlers to functions within the Linux kernel, such as a system call
  entry point or exit point" [sd-drivers]. The engineering blog lists static tracepoints on "System call
  entry path", "System call exit path", "Process context switch", "Process termination", "Minor and
  major page faults" and "Process signal delivery", with "per-CPU ring buffers" and a userspace state
  machine for each syscall [sd-blog-ebpf].
- Selection: `SYSDIG_AGENT_DRIVER`. "Agent defaults to `kmod` if this environment variable is not set"
  [sd-config]. The Helm `shield` chart default is also `driver: kmod` [sd-chart].
- Detection uses the Falco rules engine; Linux workload rules have `source: syscall` [sd-policies]
  [sd-rules].
- Malware and drift prevention depend on fanotify capacity: "For kernel versions below v5.13, Malware
  can monitor up to 128 containers per node"; on 5.13+ raise `fs.fanotify.max_user_groups`
  [sd-secconf]. [INFERENCE] Prevention uses fanotify permission events, with one group per container.

### Kernels

- Universal eBPF needs kernel 5.8 and no headers. The practical requirements are "BPF ring buffer
  support" and "A kernel that exposes BTF". The kernel module needs 3.10 and headers; legacy eBPF needs
  4.14 [sd-drivers]. Overall support is "Linux Kernel 3.10 and later" [sd-req].
- Drift "Prevent Execution": kill on kernels below 5.0, block before the process runs on 5.0+
  [sd-drift]. FIM needs universal eBPF and agent 14.3+ [sd-fim].

### Telemetry

The "Reference Library for Linux workloads" lists every syscall and tracepoint event, each with a
`Default` column [sd-ref]. That page lists 431 syscall names. About 160 of them have typed parameters;
the rest record only `SYSCALLID ID, UINT16 nativeID`.

- **Process**
  - Exec: `execve` and `execveat`. The exit parameters include `args`, `cwd`, `env`, `tty`, `loginuid`,
    `cap_effective`, `exe_ino`, and `flags` (`EXE_WRITABLE`, `EXE_UPPER_LAYER`, `EXE_FROM_MEMFD`).
  - Exit: the `procexit` tracepoint (`status`, `sig`, `core`).
  - Fork: `clone`, `clone3`, `fork`, `vfork`.
  - Credentials: `setuid`, `setresuid`, `setgid`, `capset`.
  - Injection: `ptrace`, `process_vm_writev`, `process_vm_readv`.
  - Fileless: `memfd_create` and `proc.is_exe_from_memfd`.
  - Lineage: `proc.aname`, `proc.apid`, `proc.sid`.
  - TTY: `proc.tty` [sd-ref].
  - Hash: `proc.hash.sha256` from the security-hashing plugin [sd-ref].
  - Activity Audit `command`: "Processes executed in an interactive (`tty != 0`) shell" [sd-audit].
- **File**
  - Open and create: `open`, `openat`, `openat2`, `creat`, with `evt.is_open_read`,
    `evt.is_open_exec` and the `O_F_CREATED` flag.
  - `read`, `write` and `pread` are `Default = No`.
  - `unlink`, `unlinkat`, `rename`, `renameat2`, `link`, `symlink`, `chmod`, `fchmodat`, `chown`.
  - `setxattr` and `removexattr` record the syscall ID only.
  - `mmap` and `mprotect` (`PROT_EXEC`).
  - Overlay-layer flags `proc.is_exe_upper_layer` and `fd.is_upper_layer` [sd-ref].
  - FIM: `fim.path`, `fim.old_hash.sha256`, `fim.new_hash.sha256`, `fim.type` [sd-ref]. Modification
    "doesn't trigger upon file creation" [sd-fim].
- **Network**
  - `connect` (exit `tuple`), `accept`/`accept4` (`queuepct`), `listen`, `bind`.
  - `socket`, with domains including `AF_PACKET`, `AF_NETLINK`, `AF_UNIX` and `AF_INET6`.
  - `sendto`, `recvfrom`, `sendmsg` and `recvmsg` are `Default = Yes`.
  - DNS through the security-dns plugin: `dns.domain`, `dns.type` ("query" or "response"),
    `dns.response.ips`, and `connect.domains` [sd-ref].
  - No HTTP/TLS, flow volume or NAT fields.
- **Kernel/admin**
  - Typed: `init_module`, `finit_module`, `delete_module`, `bpf` (`cmd`), `mount`, `umount2`, `fsconfig`,
    `unshare`, `setns`, `chroot`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`,
    `userfaultfd`, `seccomp`, `prctl`.
  - ID only: `perf_event_open`, `kexec_load`, `kexec_file_load`, `keyctl`, `add_key`, `settimeofday`,
    `clock_settime`, `_sysctl`, `pivot_root` [sd-ref].
- **Identity**
  - No login or sudo event class. `user.loginuid` and `user.loginname`, plus syslog fields for writes
    to `/dev/log` [sd-ref].
- **Container/K8s**
  - `container.id` ("extracted from the Linux cgroups by Falco within the kernel"), `container.image`,
    `container.privileged`, and `k8s.pod.name` / `k8s.ns.name` / `k8s.pod.labels` (14.3.0+, "extracted
    from the container runtime socket") [sd-ref].
  - Kubernetes audit comes in through `validating_webhook` or `audit_backend` [sd-chart].
- **Sensor**
  - `sysdig_agent_analyzer_dropped_evts`, `sysdig_sampling_ratio`, `sysdig_agent_analyzer_num_evts`
    [sd-health]. Legacy metrics: `dragent.analyzer.n_drops_buffer` ("dropped due to the buffer being
    full") and `dragent.analyzer.sr`, "current sampling ratio (1=all events, 2= half of events
    analyzed...)" [sd-legacy].
  - No tamper protection documentation was found.

### Response and prevention

- Policy actions: Kill Process; container Kill, Stop and Pause; Capture [sd-lwpolicy].
- Manual response (agent 13.9+): Process Kill, File Quarantine, File Acquire. Network Isolate "relies on
  Kubernetes Network Policies" [sd-resp].
- Malware "Prevent" blocks execution. Prevention is off by default on hosts
  (`protections.malware_control.enable_prevention_on_host`) [sd-malware] [sd-secconf].

### Resource claims and limits

- Ring-buffer memory: universal eBPF "8MiB * Number of CPU cores / 2"; legacy eBPF "8MiB per CPU
  core". RSS "appears to double-account for the eBPF ring buffer maps ... 16MiB per ring buffer map".
  Since 5.11 the ring buffer is memcg-accounted [sd-drivers].
- Chart defaults: requests `cpu: 250m`, `memory: 384Mi`; limits `cpu: 1000m`, `memory: 1Gi` [sd-chart].
- Dynamic Syscall Filtering (on by default) monitors "only the system calls ... required by active
  components" [sd-shield]. [VENDOR CLAIM] It "reduces CPU and memory usage".
- Backend outage buffer: "internal buffer of 300 messages" [sd-downtime].

### Gaps

- Drift detection "does not cover cases where a script is executed leveraging binaries from the
  original image" [sd-drift].
- `container.ip`: "Only ipv4 addresses are tracked" [sd-ref].
- Activity Audit records commands only when `tty != 0` [sd-audit].

[sd-drivers]: https://docs.sysdig.com/en/sysdig-secure/classic-agent-drivers/
[sd-req]: https://docs.sysdig.com/en/sysdig-secure/classic-req-agent/
[sd-config]: https://docs.sysdig.com/en/sysdig-secure/configure-classic-agent/
[sd-shield]: https://docs.sysdig.com/en/sysdig-secure/install-shield-linux-kubernetes/
[sd-chart]: https://raw.githubusercontent.com/sysdiglabs/charts/main/charts/shield/values.yaml
[sd-ref]: https://docs.sysdig.com/en/sysdig-secure/falco-reference-library/linux-workload/
[sd-policies]: https://docs.sysdig.com/en/sysdig-secure/threat-detection-policies/
[sd-rules]: https://docs.sysdig.com/en/sysdig-secure/manage_threat_detection_rules/
[sd-lwpolicy]: https://docs.sysdig.com/en/sysdig-secure/linux-workload-policy/
[sd-audit]: https://docs.sysdig.com/en/sysdig-secure/activity-audit/
[sd-drift]: https://docs.sysdig.com/en/sysdig-secure/drift_policy/
[sd-malware]: https://docs.sysdig.com/en/sysdig-secure/malware_policy/
[sd-secconf]: https://docs.sysdig.com/en/sysdig-secure/classic-secure-agent-configuration/
[sd-fim]: https://docs.sysdig.com/en/sysdig-secure/fim-policy/
[sd-resp]: https://docs.sysdig.com/en/sysdig-secure/response-actions/
[sd-health]: https://docs.sysdig.com/en/sysdig-secure/classic-agent-health/
[sd-legacy]: https://docs.sysdig.com/en/sysdig-monitor/sysdig-legacy-format/agent/
[sd-downtime]: https://docs.sysdig.com/en/sysdig-secure/agent-downtime-behavior/
[sd-blog-ebpf]: https://www.sysdig.com/blog/sysdig-and-falco-now-powered-by-ebpf

---

## Palo Alto Networks Cortex XDR agent for Linux

### Architecture

- Kernel Mode "Loads a kernel module compatible with the endpoint kernel". User Space "Uses eBPF; no
  Cortex kernel module is loaded". Both modes provide "Exploit and malware protection, EDR data
  collection". Only Kernel Mode provides "Kernel integrity monitoring, kernel module examination, local
  privilege escalation protection" [cx-modes].
- The profile setting "When Kernel Mode is unavailable, use User Space Mode" applies when "a content
  update does not contain a kernel module for the kernel used by an endpoint". The recommendation is
  "We recommend using Kernel mode" [cx-profiles].
- "Asynchronous mode" covers an unsupported kernel, `--no-km`, or User Space mode below kernel 5.0: "the
  anti-malware protection is asynchronous, and there is no event collection, no BTP, no EDR and no
  anti-lpe" [cx-profiles].
- Each event records its source in `event_source_bitmask`: "Simulated - 0x01, Kernel-Module - 0x02, EBPF -
  0x04, Fanotify - 0x08, Path-Resolved - 0x10" [cx-xdrdata].
- On COS and some RHCOS versions, Kernel Mode is not supported, and the deployment "will enforce User
  Space Mode" [cx-k8s].

### Kernels

- User Space needs "Cortex XDR agent 7.7 or later and Linux kernel 5.0 or later" [cx-modes].
- Kernel Mode needs a kernel listed per exact build, together with a minimum agent and content version
  [cx-kver]. Ubuntu 26 lists `7.0.0-*` builds from agent 9.1.0 [cx-kver-u26]. Amazon Linux 2023 lists
  `6.18.*` builds [cx-kver-al2023].

### Telemetry

- `xdr_data` `event_type` enum (verbatim): "Process = 1, Network = 2, File = 3, Registry = 4, Injection
  = 5, LoadImage = 6, UserStatusChange = 7, TimeChange = 8, Thread = 9, Causality = 10,
  HostStatusChange = 11, AgentStatusChange = 12, InternalStatistics = 13, ProcessHandle = 14,
  WindowsEventLog = 15, EpmStatus = 16, MetadataChange = 17, SystemCall = 18, Device = 19,
  HostFirewall = 23". `event_sub_type` values are not published ("create an XQL query ... which
  autocompletes the values") [cx-xdrdata].
- The "EDR data collected for Linux endpoints" table, complete as shown [cx-edr]:
  - Process "Start" (PIDs, image path, command line, SHA256 and MD5) and "Stop".
  - Files: "Create", "Open", "Write", "Delete" ("*Requires XTH add-on"), "Copy", "Move (rename)",
    "Change owner (chown)", "Change mode (chmod)".
  - Network: "Listen", "Accept", "Connect", "Connect failure", "Disconnect", including "Source IP address
    and port for explicit binds" and "Protocol (TCP/UDP)".
  - Event log "Authentication" (XTH add-on): Linux system authentication logs.
  - The Windows rows with no Linux counterpart: Image (DLL) Load, Thread Injection, DNS, HTTP, Network
    statistics (volume), System calls.
- Container fields: `actor_process_container_id`, `actor_container_info`, `actor_process_ns_pid`
  [cx-actor]. The causality card shows the container "name, ID, image" [cx-k8s].
- Linux malware modules (detection and prevention): "ELF file examination" (including "On-write file
  examination"), "ELF file loading" ("intercept ELF files and Shared Objects at the moment they are
  loaded into a process"), "Reverse shell protection", "Container escaping protection", "Credential
  gathering protection", among others [cx-malware].

### Response and prevention

- Linux: Live Terminal (with process terminate, suspend and resume), Isolate (agent 7.7+, needs
  `iptables`/`ip6tables` and `CONFIG_IP_NF_MATCH_OWNER`; still allows DNS and root HTTPS), and Run
  Scripts. "Remediate Changes" is not supported on Linux [cx-resp] [cx-iso] [cx-lt].
- Custom prevention rules on Linux can use only `os_actor_process_image_path`, `command_line`, `md5`,
  `sha256` and `os_pid` [cx-bioc].

### Resource claims and limits

- "4 GB minimum (8 GB recommended)" RAM and "10 GB available for /opt/traps"; "These are prerequisites,
  not consumption figures". [VENDOR CLAIM] "It doesn't continuously sweep the disk, so I/O stays low
  during normal operation" [cx-res].
- "Agents with Cortex XDR Pro per Endpoint apply limits and filters on network, file, and registry
  logs. To expand these limits and filters requires the Extended Threat Hunting Data (XTH) add-on." The
  filters themselves are not published [cx-edr].
- BIOC rules are disabled once they "reach 5000 or more hits over a 24-hour period" [cx-bioc].

### Gaps

- No DNS, library-load, injection or volume telemetry on Linux; file events need the XTH add-on
  [cx-edr]. User Space mode lacks kernel integrity and anti-LPE [cx-modes].
- [VENDOR CLAIM, contradicting the docs] A Palo Alto blog says the cloud agent can "run in user-space
  mode ... or in kernel-space mode, powered by eBPF" [cx-blog].

[cx-modes]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/insights-and-tips-cortex-xdr/endpoint-and-cortex-xdr-agent-management/cortex-xdr-agent-linux-operation-modes.md
[cx-profiles]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/protect-your-endpoints/install-and-manage-endpoints/set-up-endpoint-protection/set-up-endpoint-profiles-and-exception-rules/set-up-agent-settings-profiles.md
[cx-xdrdata]: https://cortex-docs.paloaltonetworks.com/xql-schema-reference/xdr-data-fields.md
[cx-k8s]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-agent/9.3/cortex-xdr-agent-for-linux/install-the-cortex-xdr-agent-for-kubernetes-hosts.md
[cx-kver]: https://cortex-docs.paloaltonetworks.com/linux-kernel-versions/readme.md
[cx-kver-u26]: https://cortex-docs.paloaltonetworks.com/linux-kernel-versions/ubuntu/x86_64/26.md
[cx-kver-al2023]: https://cortex-docs.paloaltonetworks.com/linux-kernel-versions/amazon-linux-2023/x86_64/2023.md
[cx-edr]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/protect-your-endpoints/endpoint-protection/endpoint-data-collection/endpoint-data-collection-1.md
[cx-actor]: https://cortex-docs.paloaltonetworks.com/xql-schema-reference/xdr-data-fields-by-actor/actor-actor.md
[cx-malware]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/protect-your-endpoints/endpoint-protection/malware-protection.md
[cx-resp]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/response-actions.md
[cx-iso]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/response-actions/isolate-an-endpoint.md
[cx-lt]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/insights-and-tips-cortex-xdr/endpoint-and-cortex-xdr-agent-management/endpoint-isolation-and-live-terminal.md
[cx-bioc]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/detect-investigate-and-respond-to-threats/threat-management/detection-rules/whats-a-bioc/create-a-bioc-rule.md
[cx-res]: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/insights-and-tips-cortex-xdr/endpoint-and-cortex-xdr-agent-management/cortex-xdr-agent-resource-usage.md
[cx-blog]: https://www.paloaltonetworks.com/blog/cloud-security/ebpf-cloud-security-real-time-protection/

---

## Palo Alto Networks Prisma Cloud (Compute) Defender

### Architecture

- Defender types: Container Defender, Host Defender ("runs as a systemd service on Linux"), Orchestrator
  (DaemonSet), Serverless, and App-Embedded ("starts as the parent process in the container")
  [pc-types].
- "Prisma Cloud Compute has distinct sensors for the filesystem, network, and process activity" with
  learned per-image models [pc-rt-cont].
- The kernel mechanism is not documented. The file monitor depends on fanotify: an error reads "failed
  to find host config value of CONFIG_FANOTIFY_ACCESS_PERMISSIONS" [pc-kb-fanotify]. `fsmon_v2`
  exposes `FANOTIFY_SYSTEM_LIMITS` and `RESPONSE_TIMEOUT_MS` ("10") [pc-kb-fsmon]. "The Prisma Cloud
  App-Embedded Defender requires CAP_SYS_PTRACE only" [pc-sysreq34]; [INFERENCE] it traces with ptrace.

### Kernels

- No overall minimum. "The Prevent action for detection of file system events requires a Linux kernel
  version 4.20 or later" [pc-rt-cont]. Tested systems include Amazon Linux 2023 `6.1.23`, and
  Bottlerocket and Talos on `6.12` [pc-sysreq].

### Telemetry

- Forensics event types (raw events, verbatim): "Process spawned", "Container started", "Binary
  created", "Listening port", "Connection established", "DNS query", "Runtime profile", "Runtime audit".
  Host "Process spawned" carries an "interactive (true or false)" flag [pc-incident].
- Custom-rule fields: `proc.name`, `proc.pname`, `proc.cmdline`, `proc.interactive`, `file.path`,
  `file.md5` ("Supported only for ELF files"), `net.outgoing_ip`. "Any write operation to a disk fires a
  file system event", but "File creation and file location change operations do not generate a runtime
  audit event" [pc-custom].
- Host FIM covers writes, reads and attribute changes ("permissions, ownership, timestamps, and links"),
  as `FileIntegrityEventTypeWrite`, `FileIntegrityEventTypeRead` and `FileIntegrityEventTypeMetadata`
  [pc-rt-host] [pc-evtypes].
- Host activity types: `HostActivityTypeLogin`, `HostActivityTypeSudo`,
  `HostActivityTypeAccountsModified`, `HostActivityTypeCronModified`, `HostActivityTypeServiceInstall`,
  `HostActivityTypeIptablesChanged` and others [pc-evtypes]. Sources include "New sessions spawned by
  sshd" and "Commands run with sudo or su" [pc-hostact].
- Detections include Suid Binaries, Reverse Shell, Altered Binary, "Suspicious Network Activity" (raw
  sockets), and Execution Flow Hijack Attempt ("when a process writes to /etc/ld.so.preload")
  [pc-audits].
- Package ownership: binaries that did not come from a package are flagged; "the `apt`, `yum`, and `dnf`
  package managers are supported" [pc-rt-host].
- In Kubernetes, "Prisma Cloud considers the image, namespace, and cluster when creating models"
  [pc-rt-cont].
- "By default, DNS monitoring is disabled in new rules" [pc-rt-cont].
- HTTP: WAAS, either as an inline proxy or out-of-band [pc-waas]. Kubernetes audit ingestion
  [pc-k8saudit].
- No ptrace, memfd, module, BPF, mount or namespace event was found.

### Response and prevention

- Effects: Alert, Prevent ("the process (and just the process)", or a denied file-system write) and
  Block (stop the container). "Prevent effect is not supported for network activities". "Prisma Cloud
  cannot inspect command line arguments before a process starts to run" [pc-rt-cont] [pc-custom].

### Resource claims and limits

- "Each Defender requires 256MB of RAM, 8GB of host storage, and 256m CPU ... The limit in Defenders is
  set to 900m" [pc-sysreq].
- "The Defender uses `cgroups` v1 or v2 to cap resource usage at 512MB of RAM and 900 CPU shares where a
  typical load is ~1-5% CPU and 30-70MB RAM" [pc-sysreq34]. The typical-load figures are
  [VENDOR CLAIM].
- Event aggregation: once "5 qualifying events occur within the throttle period of 15 minutes", the
  Defender aggregates over 10-minute periods [pc-agg].
- Log inspection is capped at 100 bytes per second, "non-customizable" [pc-rt-host]. The forensics FIFO
  holds 100 MB for containers and 10 MB for hosts [pc-incident].

### Gaps

- "By default, Prisma Cloud ships with an empty container runtime policy. An empty policy disables
  runtime defense entirely" [pc-rt-cont].
- "Allow all activity in attached sessions" (`kubectl exec`) bypasses the process, network and file
  checks [pc-rt-cont].

[pc-types]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/install/deploy-defender/defender-types.adoc
[pc-rt-cont]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/runtime-defense-containers.adoc
[pc-rt-host]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/runtime-defense-hosts.adoc
[pc-audits]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/runtime-audits.adoc
[pc-incident]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/incident-explorer.adoc
[pc-custom]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/custom-runtime-rules.adoc
[pc-agg]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/runtime-defense-aggregation.adoc
[pc-evtypes]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/runtime-defense/event-aggregation-event-types-table.adoc
[pc-hostact]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/audit/host-activity.adoc
[pc-sysreq34]: https://raw.githubusercontent.com/hlxsites/prisma-cloud-docs/main/docs/en/compute-edition/34/admin-guide/install/system-requirements.adoc
[pc-sysreq]: https://docs.prismacloud.io/content-collections/runtime-security/install/system-requirements.md
[pc-waas]: https://docs.prismacloud.io/content-collections/runtime-security/waas.md
[pc-k8saudit]: https://docs.prismacloud.io/content-collections/runtime-security/audit/kubernetes-auditing.md
[pc-kb-fsmon]: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA1Ki000000TNFHKA4&lang=en_US
[pc-kb-fanotify]: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000PR14CAG&lang=en_US

---

## Wiz Runtime Sensor (Wiz Defend)

docs.wiz.io is login-only. What follows comes from the public Helm chart, Wiz blogs, and Wiz
documentation text copied into GitLab's public runbook *(3P mirror)* [wiz-runbook].

### Architecture

- An eBPF sensor, run as a DaemonSet or as a systemd daemon (`wiz-sensor`) on hosts. Loading fails with
  `failed loading ebpf skeleton ... EACCES` when SELinux denies `bpf` [wiz-runbook]. Log paths such as
  `engine/src/comm/auth.rs` show that it is written in Rust [wiz-runbook].
- Detection rules ("definitions") update separately from the binary and are "evaluated in real-time on
  the sensor" [wiz-runbook] [wiz-linux].
- The chart grants `SYS_ADMIN`, `SYS_RESOURCE # eBPF`, `NET_ADMIN # network events`, `DAC_READ_SEARCH #
  file hashing`, `SYSLOG # kernel symbol resolve` and `KILL # response` [wiz-ds].
- On serverless containers (Fargate, Azure Container Apps), "Our sensor achieves this by leveraging
  **ptrace**" [wiz-serverless].

### Kernels

- No public matrix. The copied Wiz text gives the error `kernel version smaller than minimum 266752`
  [wiz-runbook]. [INFERENCE] 266752 is `KERNEL_VERSION(4,18,0)`. The chart lists amd64, arm64, s390x
  and ppc64le [wiz-values].

### Telemetry

- Custom-rule event types: "Process execution", "Network connection", "Network listen", "DNS query"
  [wiz-rules-blog].
- "The sensor captures execution data and full process tree information for every protected host"
  [wiz-product].
- Runtime FIM, "identifying the actor responsible for modifying files" [wiz-fim].
- Detections named in blogs: reading `/etc/shadow`, a reverse shell (a "non-standard input socket to a
  remote network"), and a container escape through `nsenter` [wiz-ebpf-blog]; fileless execution with
  the memfd payload collected [wiz-forensics]; exec from `/tmp`, reverse shells, privilege escalation
  attempts and image drift [wiz-gke].
- No public event schema.

### Response, enrichment, limits

- Response: "block (to immediately terminate the malicious process)" [wiz-rules-blog]. It can be
  disabled with `disallowRuntimeResponse` [wiz-values]. On detection, the sensor collects a forensic
  package [wiz-forensics].
- Enrichment: pod, namespace, image and controller, resolved through the Kubernetes API [wiz-gke]
  [wiz-values].
- Helm defaults: `limits: cpu: "300m", memory: "300Mi"`; `requests: cpu: "10m", memory: "50Mi"`
  [wiz-values]. The sensor reads `POD_CPU_LIMITS` and `POD_MEM_LIMITS` [wiz-ds].
- [VENDOR CLAIM] "negligible performance impact" [wiz-product]. [VENDOR CLAIM] Windows sensor
  "typically capped at 0.5 cores and 500MiB" [wiz-windows].
- Health: a `wiz-sensor get-statistics` CLI [wiz-runbook] and optional Prometheus metrics
  (`exposeMetrics`, `metricsPort: 9100`) [wiz-values].
- No public throttling, rate limit or drop documentation.

[wiz-runbook]: https://gitlab.com/gitlab-com/runbooks/-/raw/270526ba4155c14c1d2dfa0d5a3a85da18fe3b6f/docs/wiz-runtime-sensor/README.md
[wiz-values]: https://raw.githubusercontent.com/wiz-sec/charts/master/wiz-sensor/values.yaml
[wiz-ds]: https://raw.githubusercontent.com/wiz-sec/charts/master/wiz-sensor/templates/daemonset.yaml
[wiz-linux]: https://www.wiz.io/blog/wiz-runtime-sensor-for-linux
[wiz-serverless]: https://www.wiz.io/blog/wiz-expands-runtime-protection-to-serverless-containers
[wiz-rules-blog]: https://www.wiz.io/blog/custom-runtime-rules-and-response-policies
[wiz-product]: https://www.wiz.io/solutions/runtime-sensor
[wiz-fim]: https://www.wiz.io/blog/a-hybrid-approach-to-file-integrity-monitoring-agentless-and-runtime-fim
[wiz-ebpf-blog]: https://www.wiz.io/blog/unveiling-ebpf-harnessing-its-power-to-solve-real-world-issues
[wiz-forensics]: https://www.wiz.io/blog/ai-powered-wiz-forensics
[wiz-gke]: https://www.wiz.io/blog/wiz-sensor-on-gke-1-click-runtime-protection-now-native
[wiz-windows]: https://www.wiz.io/blog/wiz-runtime-sensor-for-your-windows-environment

---

## Aqua Security Enforcer (Aqua Enforcer, VM Enforcer, KubeEnforcer)

docs.aquasec.com is login-only. The Enforcer's telemetry is described here through its runtime-policy
controls (Terraform provider docs) and its public manifests. Aqua's open-source Tracee "is the eBPF
engine behind" some Aqua Platform capabilities [aq-tracee]. Tracee's event list is the open-source
upper bound, not what the Enforcer ships.

### Architecture

- "Aquasec uses eBPF as one part of that architecture, alongside other operating system and runtime
  mechanisms" [aq-runtime]. The 2022 eBPF "Lightning Enforcer" claims "a 65% reduction in load as
  compared to a non-eBPF agent" [VENDOR CLAIM] [aq-lightning].
- The Enforcer DaemonSet requests `SYS_MODULE`, `AUDIT_CONTROL`, `SYS_ADMIN`, `SYS_PTRACE` and others
  [aq-ds]. [INFERENCE] Module- and audit-based paths are possible. No public page says which mechanism
  is used.
- runc interception: User Access Control requires `AQUA_RUNC_INTERCEPTION` set to `0` [aq-tf-groups].
- Policy decisions "are enforced locally by the Aquasec Enforcer" [aq-runtime].
- KubeEnforcer is an admission controller, not a kernel sensor: it "uses native Kubernetes Admission
  Controller APIs" [aq-kube], with `block_admission_control` as a group setting [aq-tf-groups].

### Telemetry (policy controls, verbatim Terraform field names)

- Process: `audit_all_processes`, `audit_process_cmdline`, `block_fileless_exec`,
  `drift_prevention.exec_lockdown`, `reverse_shell.block_reverse_shell`, `container_exec.block_container_exec`
  [aq-tf-cont]. Host policies add `enable_fork_guard` and `fork_guard_process_limit` [aq-tf-host].
  Detections "Combine runtime telemetry, memory evidence, process lineage and MITRE ATT&CK mapping"
  [aq-runtime].
- File: `file_integrity_monitoring` with `monitored_files_read`, `monitored_files_create`,
  `monitored_files_modify`, `monitored_files_delete`, `monitored_files_attributes`; `readonly_files`;
  `blocked_files`; `package_block.packages_black_list` [aq-tf-cont].
- Network: `audit_all_network`, `port_block`, `enable_crypto_mining_dns`, `block_low_port_binding`
  [aq-tf-cont]; firewall policies, including `block_metadata_service` [aq-tf-fw].
- Identity (host): `audit_success_login`, `audit_failed_login`, `audit_user_account_management`,
  `audit_brute_force_login` [aq-tf-host].
- Kernel/admin: `audit_systemtime_change`, `monitor_system_log_integrity`, `blocked_capabilities`,
  `no_new_privileges` [aq-tf-host] [aq-tf-cont].
- Container/K8s: `limit_container_privileges` (`privileged`, `netmode`, `pidmode`), and scopes such as
  `kubernetes.namespace` and `kubernetes.label` [aq-tf-cont].
- Tracee (open source, not the Enforcer): LSM-hook events such as `security_bpf_prog`,
  `security_sb_mount` and `security_settime64`; kprobe events such as `commit_creds`, `do_init_module`
  and `call_usermodehelper`; and cgroup_skb network events such as `net_packet_dns_request` and
  `net_packet_http_request` [aq-tr-lsm] [aq-tr-misc] [aq-tr-net].

### Response, limits

- Each policy runs in Audit or Enforce mode; `enforce_after_days` switches it to Enforce after that many
  days [aq-tf-cont].
- "Block the specific process, file, network or privilege action that violates policy, without making
  workload termination the default response" [aq-runtime].
- Manifest requests: `cpu: 350m`, `memory: 512Mi`. The limits are commented out (`1000m`, `1.5Gi`)
  [aq-ds]. The Helm chart comments read `1500m` and `1.5Gi` [aq-helm].
- The Prometheus exporter exposes counters for "dropped behavioral detection events" [aq-prom].
- No public kernel matrix or event schema.

[aq-runtime]: https://www.aquasec.com/products/runtime-security/
[aq-lightning]: https://www.aquasec.com/blog/combat-zero-day-threats-with-aquas-ebpf-lightning-enforcer/
[aq-tracee]: https://www.aquasec.com/products/tracee/
[aq-ds]: https://raw.githubusercontent.com/aquasecurity/deployments/main/enforcers/aqua_enforcer/kubernetes_and_openshift/manifests/004_aqua_enforcer_daemonset.yaml
[aq-helm]: https://raw.githubusercontent.com/aquasecurity/aqua-helm/master/enforcer/values.yaml
[aq-tf-groups]: https://raw.githubusercontent.com/aquasecurity/terraform-provider-aquasec/main/docs/resources/enforcer_groups.md
[aq-tf-cont]: https://raw.githubusercontent.com/aquasecurity/terraform-provider-aquasec/main/docs/resources/container_runtime_policy.md
[aq-tf-host]: https://raw.githubusercontent.com/aquasecurity/terraform-provider-aquasec/main/docs/resources/host_runtime_policy.md
[aq-tf-fw]: https://raw.githubusercontent.com/aquasecurity/terraform-provider-aquasec/main/docs/resources/firewall_policy.md
[aq-prom]: https://www.aquasec.com/blog/integrate-aquasec-and-prometheus-for-greater-visibility-into-runtime-security-operations/
[aq-tr-lsm]: https://github.com/aquasecurity/tracee/tree/main/docs/docs/events/builtin/man/lsm
[aq-tr-misc]: https://github.com/aquasecurity/tracee/tree/main/docs/docs/events/builtin/man/misc
[aq-tr-net]: https://raw.githubusercontent.com/aquasecurity/tracee/main/docs/docs/events/builtin/network-events.md
[aq-kube]: https://github.com/aquasecurity/deployments/tree/main/enforcers/kube_enforcer

---

## Lacework / Fortinet FortiCNAPP agent (datacollector)

### Architecture

- "Does the Linux agent install kernel modules? No. The Linux agent is an user mode program that runs
  verifiably safe eBPF programs"; "works in the user space in a passive mode" [lw-faq].
- eBPF attribution is on by default "to effectively monitor short-lived connections and processes".
  Modes: `lite` ("On hosts running Linux kernel v4.16 and later, lite mode uses eBPF to capture packets
  on interfaces ... older than v4.16, lite mode uses libpcap"), `ebpflite`, and `scan` (FIM and
  vulnerability scans only) [lw-config].
- The agent batches data: datasources carry `BATCH_START_TIME`/`BATCH_END_TIME` and a `COUNT` ("Number
  of repeated operations represented by this record") [lw-lql].

### Kernels

- "The FortiCNAPP agent supports eBPF on Linux kernel versions 4.16 and later" [lw-eb]. In the agent
  7.10+ matrix, Connection telemetry, Process telemetry and RiskWatch need kernel 5.10+. Below that,
  hosts get only Package/DNS telemetry, FIM and UserLookup [lw-support-pdf]. Ubuntu 26.04 is supported
  from 8.4.0 [lw-support-pdf].

### Telemetry (LQL datasources, verbatim) [lw-lql]

- Process: `LW_HA_SYSCALLS_EXEC` (`EXE_PATH`, `CMDLINE`, `PID_HASH`, `PPID_HASH`, `COUNT`),
  `LW_HE_PROCESSES` (`CWD`, `SID`, `USERNAME`), `LW_HE_PACKAGES` (`ACTIVE`). Default anomaly policies
  include `LW_PROCESS_80` New Privilege Escalation and `LW_PROCESS_81` New Child Launched
  [lw-policies].
- File: `LW_HA_SYSCALLS_FILE` (`TARGET_OP`, `TARGET_PATH`, `WATCH_PATH`), with events "create",
  "delete", "modify" and "move", plus attribute change events [lw-console]. Periodic FIM: `LW_HE_FILES`
  (`FILEDATA_HASH`, `IS_LINK`) and `LW_HA_FILE_CHANGES`. FIM also "monitors the binary associated with
  processes that make long-running network connections" and compares "the SHA256 file hash to a list of
  known, malicious file hashes" [lw-fimfaq].
- Network: `LW_HA_CONNECTION_SUMMARY` (`SRC_IN_BYTES`, `DST_OUT_BYTES`, `NUM_CONNS`) and
  `LW_HA_DNS_REQUESTS` (`HOSTNAME`, `HOST_IP_ADDR`, `TTL`). Connection telemetry "Tracks inbound and
  outbound TCP and UDP connections" [lw-support-pdf]. `LW_HE_CONTAINERS` carries `IPV6` and
  `LISTEN_PORT_MAP`.
- Identity: `LW_HA_USER_LOGINS` (`EVENT_TYPE` 'LOGIN'/'LOGOFF', `TTY`), `LW_HA_SSH_LOGINS`
  (`FINGERPRINT_OPENSSH_SHA256`), `LW_HE_USERS`.
- Container: `LW_HE_CONTAINERS` (`CONTAINER_ID`, `IMAGE_ID`, `PRIVILEGED`, `PROPS_LABEL`).
- No module, BPF, mount, namespace, ptrace or sysctl events. "The FortiCNAPP agent does not currently
  track file read events" [lw-console].
- RiskWatch "probes" fire "when a vulnerable function executes", in C, C++ and Java
  [lw-riskwatch] *(Fortinet staff blog)*.

### Response, limits

- No agent response. Isolation is done out of band through cloud APIs [lw-isolate].
- `cpulimit` and `memlimit`: "If the agent measures sustained CPU usage over the specified limit during a
  4-minute window, the agent restarts" [lw-config]. Kubernetes defaults: CPU request 200m, limit 500m;
  memory request 512Mi, limit 1450Mi [lw-k8s].
- [VENDOR CLAIM] "1-3% CPU usage", "average of 250-300 MB of memory", "1-2 Kilo Bytes/sec" network
  [lw-faq].
- "The agent can buffer up to 40MB of compressed data ... When the data in the buffer exceeds 40MB, the
  agent drops data on a first in, first out basis" [lw-faq].
- Gaps: lite modes lose UDP and local-traffic attribution [lw-config]. FIM runs daily by default
  [lw-fimfaq]. Processes in containers with no network activity get argv only if "long-lived (> 1
  minute)" [lw-faq].

[lw-faq]: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/792160/linux-agent-faqs
[lw-config]: https://docs.fortinet.com/document/lacework-forticnapp/25.2.0/administration-guide/628180/configure-linux-agent-using-agent-configuration-file
[lw-console]: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/748186
[lw-fimfaq]: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/777250/file-integrity-monitoring-fim-faqs
[lw-k8s]: https://docs.fortinet.com/document/forticnapp/26.1.0/administration-guide/663510/installing-linux-agent-on-kubernetes
[lw-eb]: https://docs.fortinet.com/document/forticnapp/25.4.0/administration-guide/566160/install-linux-agent-with-aws-elastic-beanstalk
[lw-support-pdf]: https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/67091e5a-8807-11f0-9bfd-6af4c3636dc7/FortiCNAPP-Agent_support.pdf
[lw-lql]: https://docs.fortinet.com/document/lacework-forticnapp/25.2.0/lql-reference/771173/datasource-metadata
[lw-isolate]: https://community.fortinet.com/forticnapp-63/technical-tip-lacework-forticnapp-isolating-infected-vm-200530
[lw-riskwatch]: https://community.fortinet.com/blogs-103/riskwatch-is-here-vulnerable-activity-detection-response-224468
[lw-policies]: https://docs.fortinet.com/document/forticnapp/latest/lacework-forticnapp-policies/382254/host-policies

---

## Datadog Workload Protection (formerly Cloud Workload Security)

The agent code, including `pkg/security`, is Apache-2.0 [dd-license]. The product is billed: "Collecting
events using Workload Protection will affect your billing" [dd-setup].

### Architecture

- On Linux, "the eBPF agent. It offers the best performance and feature support". On Fargate,
  "cws-instrumentation tracer. Fargate does not provide eBPF access, so this tracer uses ptrace instead"
  [dd-setup].
- Hook config defaults: `use_fentry` false, `use_kprobe_fallback` true, `use_ring_buffer` true,
  `kretprobe_max_active` 512, `enable_kernel_filters` true, and `enable_co_re` true with a
  runtime-compiled fallback [dd-schema].
- In-kernel filtering. Approvers are "static filters generated when we compile our detection rules ...
  pass it into the kernel using eBPF maps". Discarders are "created at runtime by the rule engine ...
  injected into the kernel via LRU eBPF maps" [dd-blog-fim].
- The engineering blog recommends `raw_tracepoints/sys_enter`/`sys_exit` over per-syscall tracepoints
  for 32-bit compatibility. It lists io_uring, `binfmt_misc` and `call_usermodehelper` as coverage
  pitfalls, and says "Workload Protection uses eBPF TC classifiers (BPF program type `SCHED_CLS`)"
  [dd-blog-lessons].
- Event ordering uses "a sliding window of a few milliseconds". A missed exec is detected through an inode
  mismatch and resynchronized from `/proc` [dd-blog-lessons].

### Kernels

- "Workload Protection requires Linux kernel version 4.14.0 or higher". CentOS/RHEL 7 (3.10) runs "in a
  degraded mode" with network monitoring disabled [dd-setup]. The blog: "we currently support all
  kernels down to version 4.15 (the latest version ... at the time of this writing is 6.18)"
  [dd-blog-lessons].

### Telemetry (SECL triggers, verbatim, with minimum agent version) [dd-expr]

- Process
  - `exec` (7.27; "does not trigger on fork syscalls"; `exec.argv`, `exec.envs`, `exec.tty_name`,
    `exec.auid`).
  - `exit` (`exit.cause` "EXITED, SIGNALED, COREDUMPED", `exit.code`).
  - `setuid`, `setgid`, `capset`, `ptrace`, `signal`, `prctl`, `setrlimit`.
- File
  - `open`, `chmod`, `chown`, `link`, `mkdir`, `rename`, `rmdir`, `unlink`, `setxattr`,
    `removexattr`, `utimes`, `splice`, `chdir`.
  - `mmap` and `mprotect`.
  - `fim.write.file.*` expands to the write-like events.
- Network
  - `connect` (7.60), `accept` (7.63), `bind`, `socket` (7.81).
  - `dns` (`dns.question.name`, `dns.response.ips`).
  - `imds` (`imds.aws.is_imds_v2`).
  - `packet` (raw packets; `packet.tls.version`).
  - `setsockopt` (for `SO_ATTACH_FILTER`: `filter_hash`).
  - `network_flow_monitor` (`flows.egress.data_size`, `packet_count`).
- Kernel/admin
  - `load_module` (`load_module.loaded_from_memory`), `unload_module`, `bpf` (`bpf.prog.tag`,
    `bpf.prog.helpers`).
  - `mount` (experimental), `unshare` (7.84), `sysctl` (7.65; `sysctl.value`, `sysctl.old_value`),
    `selinux`, `cgroup_write`.
  - `capabilities` (experimental; `capabilities.used`).
- Not in the trigger list: fork, setns, kexec, keyring, io_uring, userfaultfd, perf_event_open, time
  change, and login.
- Context on every event: `process.ancestors.*`, `process.interpreter.file.*`, `process.auid` ("Login
  UID"), `process.container.id`, `process.container.tags` ("Tags of the container"; the tag contents
  are not listed), `process.file.in_upper_layer`, `process.file.package.name` (experimental),
  `process.file.hashes` (experimental), and `process.user_session.ssh_client_ip` and `k8s_username`.
  Kubernetes identities come from a mutating webhook on `kubectl exec` [dd-trouble].
- "Workload Protection ships with over 350 agent rules and 200 detection rules" [dd-overview].

### Response, limits

- Actions: `kill` ("The Agent sends a POSIX signal to the target process, container, or cgroup") and
  `network_filter` ("drop packets matching a BPF filter expression ... network isolation at the host
  level") [dd-actions]. Kill disarmers default to `enforcement.disarmer.container.max_allowed` 5 and
  `enforcement.disarmer.executable.max_allowed` 5, each per `period` 1m [dd-cws-schema].
- [VENDOR CLAIM] "pre-filter up to 94% of events directly in the kernel"; the example diagram goes from
  ~5,000 events/s out of eBPF, to ~300 events/s at the agent, to under 1 event/s at the backend
  [dd-blog-fim]. [VENDOR CLAIM] "we carefully drop—based on the loaded rules—up to 95% of captured
  events before they reach user space". "We set strict memory and CPU limits", but no numbers are given
  [dd-blog-lessons].
- Sampling defaults: `event_sampling.open` rate 500 with threshold 80, `connect` rate 500 with threshold 40,
  `bind` rate 500 with threshold 60. Hashing `max_hash_rate` 500. `anomaly_detection.rate_limiter.num_events_allowed`
  2000 per second [dd-cws-schema] [dd-adv].
- Known gaps the blog itself lists: kretprobe `maxactive` drops under load, "dropped or out-of-order
  events" from single-reader perf buffers, and no faulting of paged-out user memory [dd-blog-lessons].

[dd-license]: https://raw.githubusercontent.com/DataDog/datadog-agent/main/LICENSE
[dd-setup]: https://docs.datadoghq.com/security/workload_protection/setup/
[dd-schema]: https://raw.githubusercontent.com/DataDog/datadog-agent/main/pkg/config/schema/yaml/system-probe_schema.yaml
[dd-cws-schema]: https://raw.githubusercontent.com/DataDog/datadog-agent/main/pkg/config/schema/yaml/system-probe-cws.yaml
[dd-blog-fim]: https://www.datadoghq.com/blog/engineering/workload-protection-ebpf-fim/
[dd-blog-lessons]: https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/
[dd-expr]: https://docs.datadoghq.com/security/workload_protection/linux_expressions/
[dd-trouble]: https://docs.datadoghq.com/security/workload_protection/troubleshooting/threats/
[dd-actions]: https://docs.datadoghq.com/security/workload_protection/detect_and_monitor/agent_rules/variables_and_actions/
[dd-adv]: https://docs.datadoghq.com/security/workload_protection/setup/advanced_configuration/
[dd-overview]: https://docs.datadoghq.com/security/workload_protection/

---

## Uptycs

### Architecture

- "a single high performance osquery-based agent". eBPF on Graviton needs 5.8, and "For earlier Kernels
  we automatically rely on the Audit framework" [up-graviton].
- "Pre-CORE Ready: Built before 'Compile Once Run Everywhere' was mainstream; doesn't require BTF". It
  receives "Cloud-based memory layout updates" [up-guide]. [INFERENCE] Kernel structure offsets are
  shipped from the cloud.
- Uptycs moved "much of the event exclusion logic into kernel space" [up-optimize].
- The core agent "runs in read-only mode"; enforcement ships separately as the optional "Uptycs Protect"
  add-on [up-protect].

### Kernels, telemetry, limits

- "Supports Linux kernel versions from 3.10 and above" [VENDOR CLAIM] [up-ebpf].
- Tables:
  - `process_events` (`ancestor_list`, `is_container_process`, `is_container_privileged`) [up-docker].
  - `process_file_events` (opening flags, inode) [up-docker].
  - `socket_events` (`remote_address`) and `dns_lookup_events` (`question`, `answer`) [up-threat].
  - `bpf_process_events`, whose syscalls include `setns`, `mount` and `pivot_root` [up-escape].
- Categories: process creation and termination; file creation, modification and deletion; "User logon,
  logoff, and failed logon attempts"; "network socket listen events, and DNS queries"; "MD5 and SHA
  hashes"; and, as optional data, "Driver/Module Activity: eBPF events" [up-edr-leader].
- FIM supports "exclude paths" [up-optimize]. [VENDOR CLAIM] "Map events to containers, images, and even
  the exact Dockerfile instruction" [up-guide].
- Detections: ptrace and `LD_PRELOAD` injection [up-edr-detect]; io_uring and malicious eBPF programs
  [up-guide].
- [VENDOR CLAIM] "reduces telemetry volume by up to 95% before data exits the kernel" [up-ebpf].
- The guide mentions configurable soft and hard CPU and memory limits but publishes no numbers [up-guide].
  The osquery watchdog "kills the process and denylists that query for the next 24 hours"
  [up-optimize].
- Response through Protect: "kill or pause malicious processes or delete malicious files ... quarantine
  or shutdown a host" [up-protect].

[up-graviton]: https://www.uptycs.com/blog/uptycs-now-supports-amazon-graviton
[up-guide]: https://www.uptycs.com/hubfs/eBFP_Capabilities_Guide.pdf
[up-optimize]: https://www.uptycs.com/blog/optimizing-osquery-for-resource-utilization-at-scale
[up-protect]: https://www.uptycs.com/blog/uptycs-protect-rethinking-response-for-modern-csirt-teams
[up-ebpf]: https://www.uptycs.com/linux-security-with-ebpf
[up-docker]: https://www.uptycs.com/blog/detecting-docker-escapes-using-osquery-and-uptycs
[up-threat]: https://www.uptycs.com/blog/threat-research-report-team/investigating-threat-alerts-with-osquery-understanding-threat-surface-risk
[up-escape]: https://www.uptycs.com/blog/container-escape-vulnerability-detection
[up-edr-leader]: https://www.uptycs.com/blog/uptycs-linux-edr-leader
[up-edr-detect]: https://www.uptycs.com/blog/uptycs-edr-for-linux-detection-and-visibility-all-the-way-through

---

## Sophos Linux Sensor (Capsule8 heritage) and Sophos Protection for Linux

### Architecture

- "SLS collects host telemetry through a kprobe event monitor. We use `perf` ... to extract kprobe
  events" [sls-arch]. "SLS utilizes user space APIs and doesn't directly inject code into the kernel or
  require a kernel module" [sls-kernels].
- It uses ftrace "for various capabilities". On kernels 5.10.133–5.10.142 runtime detection goes into a
  "dormant mode" [sls-rn].
- Events are reordered in userspace over `perf_event_reorder_window`, default `75ms` [sls-config].
- No page mentions eBPF. In SPL 2025.1, the "dependency on the audit netlink" was removed [spl-rn].

### Kernels

- ARM64 needs 5.3+, "due to a lack of support for user space access monitors in kernel probes (kprobes)
  before the 5.3 release" [sls-kernels]. The release notes add support for kernels "6.19 and 7.0"
  (5.17.3) and "kernel 7.3" (5.22.0) [sls-rn].

### Telemetry

- Collected by default: "Container lifecycle", "File opens", "Kernel function calls", "Network
  activity", "Process lifecycle", "Raw system calls" [sls-arch].
- Capsule8 API (2018) enums: `PROCESS_EVENT_TYPE_FORK`, `_EXEC`, `_EXIT`; `FILE_EVENT_TYPE_OPEN`;
  `NETWORK_EVENT_TYPE_CONNECT_ATTEMPT`, `_BIND_ATTEMPT`, `_LISTEN_ATTEMPT`, `_ACCEPT_ATTEMPT`,
  `_SENDTO_ATTEMPT`; `CONTAINER_EVENT_TYPE_CREATED`; `KERNEL_FUNCTION_CALL_EVENT_TYPE_ENTER`
  [capsule8-api].
- Snapshot tables with a Linux platform include `deb_packages`, `rpm_packages` and `linux_packages`
  [sophos-schema].
- Data-lake tables (Linux):
  - `running_processes_linux_events` (`cmdline`, `parent_sophos_pid`, `sha256`).
  - `authentication_activity_linux` (`auth_result`, `remote_ipaddress`, `logon_type`).
  - `user_events_linux` (audit message, `nlmsg_type`).
  - `runtime_activity` (`target_process_*` "for use in reporting process injection techniques").
  - `sophos_runtime_detections_linux` [sophos-schema].
- Release notes: "SNI details have been added to connection events"; `dns_query_events` behind a Helm
  switch (5.18.2); `account_activity_linux`, covering account creation, deletion and group changes
  (5.17.3) [sls-rn].
- Only `process_events` and `audit_usr_msg` reach the Sophos Data Lake through the event dispatcher
  [sls-export].
- Named detections include "Chmod of SSH Authorized Keys" and "Suspicious Interactive Shell"
  [sls-docker]. The "Process Activity" Smart Policy group covers "compiler usage, debugging, scheduled
  task changes" [sls-cat].
- Alerts carry a `location` with `container_id`, `image_name`, `kubernetes_pod` and
  `kubernetes_namespace` [sls-alerts].

### Response, limits

- Responses: `stop` (`SIGSTOP`), `kill`, `kill-tree`, `kill-container` (`SIGKILL` to the container's
  init), and file delete. "Only one response action per individual policy" [sls-resp].
- SPL real-time (on-access) scanning works "on read" and "on write" and is off by default [spl-rt].
  SPL 2026.3 adds "automatic detection and recovery for unauthorized changes to SPL Agent files"
  [spl-rn].
- Optional cgroup supervisor: `use_resource_limits` (default `false`), `cpu_limit` (default `5.0`
  percent of total CPU), `memory_limit` (default `1024M`). "Both of these will have effects on SLS's
  coverage of telemetry events". A circuit breaker "sheds security data collection to maintain host
  performance" [sls-resources].
- Helm: limits `2Gi` and `200m`; requests `1Gi` and `100m` [sls-helm].
- SPL lets you set cgroup limits per component; `memory_limit` cannot go below `2048` [spl-limits].
- [VENDOR CLAIM] "lightweight Linux sensor" [sls-overview].

[sls-arch]: https://docs.sophos.com/esg/sls/help/en-us/gettingStarted/overviews/KB0010064-Overview_of_SLS_architecture/index.html
[sls-kernels]: https://docs.sophos.com/esg/sls/help/en-us/gettingStarted/overviews/KB0010065-Which_Linux_distributions_and_Kernels_does_SLS_support/
[sls-rn]: https://docs.sophos.com/releasenotes/output/en-us/esg/linux_sensor_rn.html
[sls-config]: https://docs.sophos.com/esg/sls/help/en-us/configuration/configureSensor/KB0010080-Reference_SLS_configuration_options/
[spl-rn]: https://docs.sophos.com/releasenotes/output/en-us/esg/linux_protection_rn.html
[capsule8-api]: https://pkg.go.dev/github.com/capsule8/capsule8@v0.15.0-alpha/api/v0
[sophos-schema]: https://docs.sophos.com/central/References/schemas/schemas/xdr_schema_docs.json
[sls-export]: https://docs.sophos.com/esg/sls/help/en-us/managingAlerts/exportAlerts/Exporting_Alerts_to_Sophos_Central/index.html
[sls-resp]: https://docs.sophos.com/esg/sls/help/en-us/managingAlerts/configureResponse/KB0010052-Getting_Started_with_Automated_Response/
[sls-resources]: https://docs.sophos.com/esg/sls/help/en-us/configuration/manageSensor/KB0010081-Managing_SLS_resource_usage/
[sls-helm]: https://docs.sophos.com/esg/sls/help/en-us/gettingStarted/installSensor/Installing_SLS_with_Helm/
[spl-limits]: https://docs.sophos.com/esg/spl/en-us/help/ServerProtectionAgentResourceLimits/
[sls-overview]: https://docs.sophos.com/esg/sls/help/en-us/gettingStarted/overviews/KB0010062-Overview_of_SLS_and_its_components/index.html
[sls-docker]: https://docs.sophos.com/esg/sls/help/en-us/gettingStarted/installSensor/KB0010071-Installing_SLS_on_Docker/
[sls-cat]: https://docs.sophos.com/esg/sls/help/en-us/detectionKnowledge/overview/KB0010015-Categories_of_Detections/index.html
[sls-alerts]: https://docs.sophos.com/esg/sls/help/en-us/managingAlerts/workingWithAlerts/Overview_of_SLS_Alerts/
[spl-rt]: https://docs.sophos.com/esg/spl/en-us/help/ServerProtectionAgentRealtimeScanning/index.html

---

## Trend Micro Vision One (Endpoint Sensor, Server & Workload Protection, Deep Security Agent)

### Architecture

- The agent relies on `tmhook.ko` and `bmhook.ko`, "out-of-tree livepatch-style kernel modules that
  reference unexported static_call keys". These provide "real-time Anti-Malware, Activity / Integrity
  Monitoring, and Application Control" [tm-ka-rhel].
- Drivers ship as Kernel Support Packages built for each exact kernel. The list covers Debian
  `7.1.13+deb13` and Ubuntu `7.0.0-29-generic` [tm-ksp-list].
- When no driver exists, "User mode": "basic Anti-Malware functions through Fanotify and eBPF on systems
  that lack kernel support". The Auto mode prefers kernel mode [tm-usermode] [tm-dsa-rn].
- Example of breakage: the RHEL 10.2 kernels `6.12.0-211.7.1` through `211.22.1` blocked building the
  modules, so those hosts ran in "driverless (basic functions) mode" [tm-ka-rhel].

### Telemetry

- The Linux telemetry table (verbatim) [tm-linux-telemetry]:
  - Collected by standard settings: "Process Creation", "Process Termination", "File Creation",
    "Outbound Connection", "Inbound Connection", "Listening", "Modified Process Write Memory", "Modified
    Process Write Process", "Memory Read", "Memory Modify", "BM Invoke", "BM Invoke API".
  - "File Opened" "Requires enabling hypersensitive mode".
  - "File Deletion" and "File Set Security": "Default disabled. If you require monitoring of this event
    type, contact your support provider."
- Schema: `eventId` `1` TELEMETRY_PROCESS, `2` TELEMETRY_FILE, `3` TELEMETRY_CONNECTION, `4`
  TELEMETRY_DNS, `8` TELEMETRY_MODIFIED_PROCESS, `13` TELEMETRY_MEMORY, `14` TELEMETRY_BM; sub-types
  such as `702` TELEMETRY_MODIFIED_PROCESS_WRITE_MEMORY [tm-schema].
- Matching the Linux table rows to sub-type IDs by name is [INFERENCE]. Linux `objectBmData` examples
  include `Access /proc/<pid>/*` [tm-schema-es].
- Without a driver, there are no File Create, File Open or DNS Query events [tm-am-basic-mode].
- "User account activity (Windows and macOS only)" [tm-xdr].
- Sensor 3.0.0.11101: "Support .service file events". DSA 20.0.2.22850: "Fixed the memfd detection
  failed issue" [tm-ka-components].
- Schema fields include `processFileHashSha256`, `objectFileHashSha256`, `parentCmd`, `parentPid`,
  `proto` (`TELEMETRY_CONNECTION_TCP`, `TELEMETRY_CONNECTION_UDP`) and `trafficSize` [tm-schema-es].
- Server & Workload Protection Integrity Monitoring supports real-time file scans on Linux [tm-features].

### Response, limits

- Linux response: Isolate Endpoint, Collect File, Run osquery, Run Remote Custom Script, Run YARA,
  Remote Shell. Terminate Process is Windows only ("the remote shell `kill` command can be used")
  [tm-response].
- Requirements: RAM "2 GB minimum", "5 GB recommended"; "4 vCPU or greater recommended" [tm-es-req].
- CPU caps through cgroups, from 5% to 95%. The legacy "Extremely Low" level documents "Loss of activity
  logs of the busiest events ... if the CPU usage is higher than 10%"; "Low" documents the same above
  40% [tm-cpu].
- DSA 20.0.3-860: "During periods of high activity, Deep Security Agent can now discard non-critical
  background events to improve system stability without impacting security" [VENDOR CLAIM for "without
  impacting security"] [tm-dsa-rn].

[tm-ka-rhel]: https://success.trendmicro.com/en-US/solution/KA-0023605
[tm-ksp-list]: https://files.trendmicro.com/documentation/Linux%20Sensor/TMVisionOne_LinuxKernelSupport.html
[tm-usermode]: https://help.deepsecurity.trendmicro.com/20_0/on-premise/user-mode-solution.html
[tm-dsa-rn]: https://help.deepsecurity.trendmicro.com/aws/release-notes-dsa.html
[tm-linux-telemetry]: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-what-telemetry-collect-linux
[tm-schema]: https://github.com/trendmicro/tm-v1-schema
[tm-schema-es]: https://trendmicro.github.io/tm-v1-schema/pages/Endpoint/Endpoint%20Sensor
[tm-am-basic-mode]: https://servicecentral.powerappsportals.com/en-us/documentation/article/trend-vision-one-activity-monitoring-basic
[tm-xdr]: https://docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-workload-security-xdr
[tm-ka-components]: https://success.trendmicro.com/en-US/solution/KA-0011999
[tm-response]: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-response-actions-section
[tm-es-req]: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-es-agent-sys-reqs
[tm-cpu]: https://docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-workload-security-cpu-usage
[tm-features]: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-supported-features-linux-platform

---

## Upwind

- Architecture: "Upwind applies policy and filtering directly with eBPF in the kernel"; "The Upwind
  Sensor runs as a user mode process" [uw-sensors]. Kernels with BTF get the standard sensor; otherwise
  "the BCC variant for older kernels" is installed, which needs kernel headers [uw-host]. Its whitepaper
  describes "kprobes on syscalls like sendmsg and recvmsg" and "Per-CPU ring buffers"
  [uw-whitepaper]. Under gVisor, it consumes gVisor trace points such as `sentry/execve`
  [uw-gvisor].
- Kernels: "kernel version of **4.14** or above", with "5.4 or above" recommended; it needs debugfs or
  tracefs [uw-host].
- Coverage: "process execution, file access, and system-level activity ... privilege escalation, and
  changes to critical files or binaries" [uw-coverage]. Enrichment adds Kubernetes metadata and "image
  digests, process trees, entrypoint commands, and PID namespaces" [uw-whitepaper].
- Telemetry (report types, verbatim): `process` ("Process lifecycle events (start/exit)"),
  `process_events` ("Syscall-level process events"), `aggregated_network` ("Network flows aggregated
  across the cluster"), `apisec_catalog` (API discovery), and `function_events` ("In-use workload
  events") [uw-s3]. The whitepaper claims L7 reconstruction of HTTP/1.x and gRPC "including TLS
  traffic when accessible at the syscall level or in-memory" [uw-whitepaper].
- Response: "stopping compromised containers and blocking malicious processes"; the mechanism is not
  documented [uw-sensors].
- Limits: the host sensor needs "0.5 CPU cores and 512 MiB of memory". Its systemd defaults are
  `UPWIND_AGENT_CPUQUOTA` 50%, `UPWIND_AGENT_MEMORYHIGH` 800M and `UPWIND_AGENT_MEMORYMAX` 1024M
  [uw-host] [uw-hostconf]. [VENDOR CLAIM] "eBPF performs up to 10x better than kernel extensions"
  [uw-ebpf].

[uw-sensors]: https://docs.upwind.io/public/introduction/concepts/upwind-architecture/sensors
[uw-host]: https://docs.upwind.io/public/getting-started/install-sensor/host/overview
[uw-hostconf]: https://docs.upwind.io/public/getting-started/install-sensor/host/configuration
[uw-whitepaper]: https://www.upwind.io/wp-content/uploads/2025/07/Leveraging-eBPF-for-Runtime-Security_-Upwinds-Architecture-for-Kernel-Level-Observability-and-Threat-Detection-.pdf
[uw-gvisor]: https://docs.upwind.io/public/getting-started/install-sensor/kubernetes/advanced-features/gvisor-support
[uw-s3]: https://docs.upwind.io/public/getting-started/install-sensor/s3
[uw-ebpf]: https://docs.upwind.io/public/introduction/concepts/ebpf/overview
[uw-coverage]: https://docs.upwind.io/public/introduction/concepts/upwind-coverage-model

---

## Sweet Security

Public material is marketing PDFs and blogs only.

- Architecture: "On Linux, our eBPF sensors capture process execution and network activity through
  kernel hooks, while userspace instrumentation adds visibility into application behavior" [sw-context].
  It is written in Rust [sw-ds]. Its eBPF sensors "combine kernel-level visibility with
  application-aware stack tracing" [sw-vpatch].
- Kernels: "Linux-based (amd64/arm64) with kernel >= 5.10" for VMs [sw-brief].
- Telemetry: "Captures processes, file accesses, network traffic, and memory usage" [sw-brief];
  connection analysis "including details about the country of origin and DNS information" [sw-conn];
  and Layer 7 API analysis [sw-ds].
- Prevention: one rule matches the process (Node.js), a call-stack frame (`node:zlib._close()`) and the
  operation (`clone()`). It "blocks the clone() syscall before the malicious child process is created".
  The mechanism is not stated [sw-vpatch]. [VENDOR CLAIM] Actions complete "in under 100 milliseconds"
  [sw-context].
- Response: "Shut down attacks as they unfold by manually or automatically terminating malicious
  processes" [sw-brief]; "automatically isolating compromised workloads, terminating processes"
  [sw-ds]. A customer case study describes "tracking network connections, file system access, and
  system calls" [sw-kaltura].
- [VENDOR CLAIM] "typically between 80-120 MBs, with minimal CPU usage" [sw-buyers]. [VENDOR CLAIM]
  A customer case study reports "only 50 MB of RAM and 0.20% CPU per node" [sw-kaltura].

[sw-context]: https://www.sweet.security/blog/how-sweet-turns-runtime-context-into-cloud-and-ai-security-outcomes
[sw-ds]: https://hi.sweet.security/hubfs/Product%20Marketing/Sweet%2BCloud-Native%2BDR%2BPlatform_DS.pdf
[sw-vpatch]: https://www.sweet.security/blog/stopping-exploits-at-runtime-sweets-new-virtual-patching-in-action
[sw-brief]: https://hi.sweet.security/hubfs/Product%20Marketing/General%20Solution%20Brief.pdf
[sw-conn]: https://www.sweet.security/blog/introducing-connection-analysis-unveiling-hidden-network-insights
[sw-buyers]: https://hi.sweet.security/hubfs/Product%20Marketing/Sweet%20-%20Buyers%20Guide%20doc%20design%20%281%29.pdf
[sw-kaltura]: https://hi.sweet.security/hubfs/Product%20Marketing/Case%20Studies/Kaltura.pdf

---

## Others (brief)

- **Orca Sensor.** "a non-intrusive eBPF-based sensor" [orca-press] that "detects and makes decisions
  locally" [orca-blog]. It offers "more than 30 runtime detections that cover DNS, files, networks, and
  processes", such as "malware execution, malicious domains, malicious IPs, binary drift, webshell
  execution", and can detect and prevent "memory persistence and execution even for fileless attacks"
  [orca-blog]. Other named detections cover privilege escalation "via Polkit exploits" and "DNS lookups
  to known offensive security domains" [orca-detections]. It can "terminate processes"
  [orca-platform]. [VENDOR CLAIM] "minimal performance impact" [orca-platform]. No kernel matrix, event
  schema or limits are public.
- **Broadcom Carbon Black Cloud.** The Linux sensor "uses Berkeley Packet Filter 'eBPF' technology",
  needs kernel headers, and uses "our kernel module instead of BPF" on CentOS/RHEL 7 [cb-bpf]. Its
  event-type table for Linux (verbatim): `childproc` Yes, `crossproc` No, `filemod` Yes, `fork` Yes,
  `modload` No, `netconn IPV4/IPV6` "Yes (both)", `posix_exec` Yes, `tamper` No, `fileless scriptload`
  No, `blocked/terminated` Yes [cb-types].
- **Rapid7 Insight Agent.** Linux telemetry relies on auditd: "the `auditd` library must be **present**,
  but the service must be **disabled**" [r7-os]. A compatibility mode shares auditd through the `af_unix`
  audispd plugin with `-b 8192`, and "results in larger `audit.log` files" [r7-auditd]. Telemetry
  includes `Process Start` [r7-eet] and FIM through audit watches [r7-auditd]. Sample queries use
  `process.cmd_line`, `process.hash_reputation.*` and `parent_process.*` [r7-eet].
- **Tanium Client Recorder.** eBPF is the default event source, "a replacement for auditd" for process,
  file and network events; security events still come from auditd. It falls back from netlink to audispd
  [tn-overview]. It uses libbpf CO-RE on newer distros and BCC elsewhere, and "BPF and Live Kernel
  Patching can have interoperability problems prior to Linux kernel version 6.0" [tn-req].
  - Telemetry: all TCP connections and `bind`. Processes carry "path, hash, command line, user
    information, ancestry, and the signed status". File writes are recorded; file reads need custom
    auditd rules. Security events (authentication, privilege escalation, logon) come from auditd, and
    the original login user is recorded across su and sudo. DNS is available only on eBPF and only
    through the system resolver. Image loads are not supported on Linux [tn-overview] [tn-tr-config].
  - Limits: `CX.recorder.ResourceMonitorCPUPercent` (default 50) suspends subscriptions when exceeded,
    `DatabaseMaxSizeMB` defaults to 1024, and the Recorder "is not restricted by Client
    Extension CPU throttles" [tn-settings] [tn-req].
- **Qualys.** The EDR agent is audit-based (`AuditBacklogLimit` 8192), with `EDRCPULimit` defaulting to
  "5% of the total CPU" and `EDRMemoryLimit` to "5% of the total memory". The recommended host is 8
  cores and 8 GB, and the thresholds operate "effectively only on systems with 8 or more CPU cores"
  [qs-edr-prereq]. Linux events:
  "Process Events: Running, Terminated", "File Events: Create, Write, Rename, Delete, Change", "Network
  Event: Listening, Established, Closed". Responses: process kill and file quarantine [qs-compat]. Search
  tokens include `parent.name`, `parent.pid`, `file.hash.sha256` and the cross-platform
  `process.loadedmodule.*` [qs-tokens]. The separate Container Runtime Sensor is eBPF, needs kernel
  4.19, and on "Linux kernel 6.x require[s] CRS version 1.5.0 or later" [qs-crs].
- **Cisco Secure Endpoint.** Kernel modules up to 4.14; "Kernel versions between 4.14 and 4.19 are not
  compatible"; eBPF from 4.19. Missing modules raise faults ("Realtime filesystem monitor failed to
  start") and the connector reports "Mode: Degraded" [cis-modules]. From 1.25 it prefers eBPF CO-RE on
  kernels with BTF [cis-core]. Telemetry documentation was not obtained.
- **Trellix ENS for Linux.** On-access scanning through fanotify or a kernel module (`mfetpcli
  --usefanotify` / `--usekernelmodule`); "For Ubuntu and SUSE, Fanotify is enabled by default"
  [trl-fanotify]. Telemetry documentation was not obtained.

[orca-press]: https://orca.security/resources/press-releases/orca-security-unveils-orca-sensor/
[orca-blog]: https://orca.security/resources/blog/meet-orca-sensor/
[orca-platform]: https://orca.security/platform/runtime-sensor/
[orca-detections]: https://orca.security/resources/blog/orca-sensor-runtime-detections/
[cb-bpf]: https://knowledge.broadcom.com/external/article/287460
[cb-types]: https://knowledge.broadcom.com/external/article/285010/the-type-of-data-that-a-linux-sensor-can.html
[r7-os]: https://docs.rapid7.com/insight-agent/operating-system/
[r7-auditd]: https://docs.rapid7.com/insight-agent/auditd-compatibility-mode-for-linux-assets/
[r7-eet]: https://docs.rapid7.com/insightidr/leverage-enhanced-endpoint-telemetry-data/
[tn-overview]: https://help.tanium.com/bundle/ug_recorder_cloud/page/recorder/overview.html
[tn-req]: https://help.tanium.com/bundle/ug_recorder_cloud/page/recorder/requirements.html
[tn-settings]: https://help.tanium.com/bundle/ug_recorder_cloud/page/recorder/configuring_endpoint_settings.html
[tn-tr-config]: https://help.tanium.com/bundle/ug_threat_response_onprem/page/threat_response/create_configurations.html
[qs-edr-prereq]: https://docs.qualys.com/en/edr/latest/edr_onboarding_for_linux/linux_prerequisites-for-edr.htm
[qs-compat]: https://docs.qualys.com/en/edr/latest/malware_protection/feature_compatibility_for_linux.htm
[qs-crs]: https://docs.qualys.com/en/cs/latest/mergedProjects/container_runtime_sensor_help/get_started/crs_interoperability_matrix.htm
[qs-tokens]: https://docs.qualys.com/en/edr/latest/search_tips/tokens_for_event_type.htm
[cis-modules]: https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/217207-building-cisco-secure-endpoint-linux-con.html
[cis-core]: https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/215549-linux-kernel-devel-fault.html
[trl-fanotify]: https://docs.trellix.com/docs/enable-or-disable-fanotify-and-kernel-modules-3

---

## Cross-cutting observations

Each point summarizes the vendor sections above, where its sources are cited.

1. **Kernel modules are being retired in favour of eBPF loaded from userspace.**
   - CrowdStrike now runs eBPF by default and no longer lets you force kernel mode where eBPF works.
     Microsoft removed its AuditD provider.
   - Cisco and Carbon Black use kernel modules only on old kernels.
   - Trend still depends on modules built for each kernel, and falls back to fanotify/eBPF "basic
     functions" when none exists.
   - Cortex XDR still recommends its kernel module, and offers eBPF as a fallback.
2. **Hook placement varies a lot.**
   - Sysdig/Falco hooks syscall entry and exit and lists 431 syscalls.
   - Datadog hooks kernel functions with kprobes and filters in the kernel with approvers and
     discarders.
   - Elastic's open BPF code hooks semantic functions (`commit_creds`, `do_filp_open`, `vfs_rename`,
     `tcp_v4_connect`, `tp_btf/sched_process_exec`). It is the closest public design to Panopticon's
     hook choice.
   - SentinelOne names kprobes, uprobes and `security_path_*` hooks.
   - MDE's diagnostics count events by syscall ID.
3. **BPF LSM blocking is rare.** Only Elastic Defend for Containers documents BPF LSM for blocking
   before an action runs.
   - Synchronous file and exec blocking elsewhere goes through fanotify permission events. This is
     documented for MDE real-time protection, Trellix and Trend user mode. It is [INFERENCE] for Elastic
     malware protection, Prisma file-system Prevent, and Sysdig drift and malware Prevent.
   - Everything else is kill after detection. CrowdStrike says so explicitly for user mode
     ("asynchronous kill"), and Datadog, Sophos, Wiz and Orca use signals.
4. **Many sensors aggregate in time or rate-limit before sending.**

   | Vendor | Aggregation, sampling or throttling |
   |---|---|
   | CrowdStrike | `ProcessRollup2Stats` 60-minute exec rollup; `DnsRequest` 24-hour dedup; UDP close synthesized after 2 minutes |
   | SentinelOne | File and behavioral-indicator events aggregated per minute; Deep Visibility sent every 3 minutes or 1000 events |
   | Elastic | fork/exec/end merged into one event for short-lived processes; network dedup by Src-IP/Dst-IP/Dst-Port/PID tuple; process hashes and argv capture off by default |
   | Prisma | Aggregation mode after 5 events in 15 minutes, then 10-minute periods |
   | Lacework | Batch windows with a `COUNT` column; daily FIM |
   | Datadog | Per-event-type sampling (`event_sampling.open` rate 500) |
   | Sysdig | A sampling ratio when overloaded (`dragent.analyzer.sr`) |
   | Trend | Documented loss of "the busiest events" above a CPU threshold |
   | Sophos | Circuit breaker that "sheds security data collection" |

5. **Loss is rarely reported as data.**
   - Per-event drop counters are documented by Sysdig (`sysdig_agent_analyzer_dropped_evts`,
     `n_drops_buffer`), Aqua (a "dropped behavioral detection events" metric) and Elastic's quark
     library (`lost`).
   - Others report loss only as states (CrowdStrike RFM; Cortex Asynchronous mode) or in documentation
     prose (Trend CPU levels; Lacework's 40 MB FIFO drop).
6. **No sensor documents a NAT post-translation tuple.** Per-flow volume is documented only by
   Datadog's `network_flow_monitor`, Lacework's connection summaries and Upwind's `aggregated_network`,
   plus Elastic's byte counts on disconnect and CrowdStrike's Forensics-only event.
7. **Kernels 6.15 and later.**
   - Explicitly named: Sophos (7.0, 7.3), Elastic (7.0 and lazy preemption), Trend (Ubuntu `7.0.0-29`,
     Debian `7.1.13`) and Cortex (Ubuntu 26 `7.0.0-*` builds). Datadog's blog names 6.18 as the latest
     kernel at the time of writing, within a supported range that starts at 4.15.
   - Qualys CRS says only that 6.x kernels need CRS 1.5.0.
   - CrowdStrike, SentinelOne, MDE, Wiz, Aqua, Upwind and Sweet name no kernel at or above 6.15.

---

## 1. Matrix: taxonomy category × sensor

Legend:

- `Y`: the vendor documents Linux telemetry for this item; the vendor event name is in the section
  above. A requirement for a mode that is the default on 6.15+ kernels with BTF still counts as `Y`.
- `P`: partial. Only some of the operations are covered, or the item is off by default, needs an
  add-on, or depends on a distro or kernel.
- `D`: only a detection rule, policy control or block exists; no raw event is documented.
- `x`: the event type exists in the vendor's cross-platform schema, but Linux emission is not
  documented.
- `n`: not in the vendor's published Linux event list, where that list appears complete. This is
  absence from a list, not a vendor statement.
- `-`: the vendor states that the item is not available on Linux.
- `?`: no public evidence either way.
- `†`: the event name exists, but its meaning is inferred from the name.

Sensors: CS CrowdStrike, S1 SentinelOne, MDE Microsoft Defender for Endpoint, ELA Elastic Defend
(host), SYS Sysdig, CTX Cortex XDR, PRI Prisma Cloud Defender, WIZ Wiz, AQU Aqua Enforcer, LAC
Lacework/FortiCNAPP, DD Datadog, UPT Uptycs, SOP Sophos SLS/SPL, TRE Trend Micro, UPW Upwind, SWE
Sweet, ORC Orca, CB Carbon Black, R7 Rapid7, TAN Tanium, QUA Qualys EDR, CIS Cisco, TRL Trellix.

### Process

| Sensor | exec | exit | fork | cred change | injection | fileless | script | TTY | lineage | exe hash | pkg/sig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CS | Y | Y | n | n | Y† | P | Y† | Y† | Y | Y | P |
| S1 | Y | x | ? | D | P | D | P | ? | Y | Y | P |
| MDE | Y | P | P | P | P | ? | ? | ? | Y | Y | ? |
| ELA | Y | Y | Y | Y | P | Y | n | Y | Y | P | n |
| SYS | Y | Y | Y | Y | Y | Y | n | Y | Y | Y | n |
| CTX | Y | Y | n | n | n | n | n | n | Y | Y | n |
| PRI | Y | ? | ? | D | n | n | ? | Y | Y | Y | Y |
| WIZ | Y | ? | ? | D | ? | D | P | ? | Y | P | ? |
| AQU | Y | ? | D | ? | ? | D | ? | ? | P | ? | D |
| LAC | Y | n | n | D | n | n | n | P | Y | P | Y |
| DD | Y | Y | n | Y | P | n | P | Y | Y | Y | P |
| UPT | Y | P | ? | ? | D | ? | ? | ? | Y | Y | ? |
| SOP | Y | P | P | ? | P | ? | ? | ? | Y | Y | P |
| TRE | Y | Y | ? | ? | Y† | D | P | ? | Y | Y | ? |
| UPW | Y | Y | ? | D | ? | ? | ? | ? | Y | ? | ? |
| SWE | Y | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| ORC | D | ? | ? | D | ? | D | ? | ? | ? | ? | ? |
| CB | Y | ? | Y | ? | - | ? | - | ? | Y | ? | ? |
| R7 | Y | ? | ? | ? | ? | ? | ? | ? | Y | P | ? |
| TAN | Y | ? | ? | ? | ? | ? | ? | ? | Y | Y | P |
| QUA | Y | Y | ? | ? | ? | ? | ? | ? | P | ? | ? |
| CIS | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

### File

| Sensor | sensitive read | write/modify | create | delete | rename | chmod/chown/xattr | link | FIM (hash) | persistence | dropped-file exec | lib load/mmap exec |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CS | Y | Y | Y | Y | P | P | n | P | Y | Y | Y |
| S1 | P | Y | Y | Y | Y | P | ? | ? | D | ? | x |
| MDE | P | x | Y | Y | Y | P | ? | ? | P | ? | P |
| ELA | n | Y | Y | Y | Y | P | n | P | P | ? | P |
| SYS | Y | Y | Y | Y | Y | P | Y | Y | D | Y | Y |
| CTX | P | P | P | P | Y | Y | n | n | n | D | D |
| PRI | P | Y | P | ? | - | P | P | P | Y | D | n |
| WIZ | D | Y | ? | ? | ? | ? | ? | P | ? | D | ? |
| AQU | Y | Y | Y | Y | ? | Y | ? | P | ? | D | ? |
| LAC | - | Y | Y | Y | Y | P | P | Y | n | n | n |
| DD | Y | Y | Y | Y | Y | Y | Y | Y | D | P | Y |
| UPT | P | Y | Y | Y | ? | ? | ? | P | ? | ? | ? |
| SOP | Y | ? | ? | ? | ? | D | ? | ? | D | ? | ? |
| TRE | P | n | Y | P | n | P | n | P | P | ? | n |
| UPW | P | D | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| SWE | P | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| ORC | ? | ? | ? | ? | ? | ? | ? | ? | ? | D | ? |
| CB | ? | Y | ? | ? | ? | ? | ? | ? | ? | ? | - |
| R7 | ? | P | ? | ? | ? | ? | ? | P | ? | ? | ? |
| TAN | P | Y | ? | ? | ? | ? | ? | ? | ? | ? | - |
| QUA | ? | Y | Y | Y | Y | ? | ? | ? | ? | ? | x |
| CIS | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

### Network

| Sensor | TCP connect/accept/listen | UDP flows | DNS | raw/packet | unix | IPv6 | NAT tuple | HTTP/TLS meta | flow volume | bind |
|---|---|---|---|---|---|---|---|---|---|---|
| CS | Y | Y | Y | Y | P | Y | n | Y† | n | P |
| S1 | Y | ? | x | ? | ? | ? | ? | x | ? | ? |
| MDE | Y | ? | ? | P | ? | ? | ? | P | ? | ? |
| ELA | P | n | Y | n | n | Y | n | n | P | n |
| SYS | Y | Y | Y | Y | Y | Y | n | n | n | Y |
| CTX | Y | Y | n | n | n | ? | n | n | n | Y |
| PRI | Y | ? | P | D | ? | ? | ? | P | ? | ? |
| WIZ | Y | ? | Y | ? | ? | ? | ? | ? | ? | ? |
| AQU | P | ? | D | ? | ? | ? | ? | ? | ? | D |
| LAC | Y | Y | Y | n | n | P | n | n | Y | P |
| DD | Y | Y | Y | Y | P | ? | n | P | Y | Y |
| UPT | Y | ? | Y | ? | ? | ? | ? | ? | ? | ? |
| SOP | Y | P | P | ? | ? | ? | ? | Y | ? | P |
| TRE | Y | P | P | ? | ? | ? | ? | ? | P | n |
| UPW | P | ? | ? | ? | ? | ? | ? | Y | Y | ? |
| SWE | Y | ? | P | ? | ? | ? | ? | Y | ? | ? |
| ORC | ? | ? | D | ? | ? | ? | ? | ? | ? | ? |
| CB | Y | ? | ? | ? | ? | Y | ? | ? | ? | ? |
| R7 | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TAN | Y | ? | P | ? | ? | ? | ? | - | ? | Y |
| QUA | Y | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| CIS | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

### Kernel/admin

| Sensor | module load | BPF load | kprobe/perf_event_open | mount | namespaces | kexec | sysctl | time change | keyring | io_uring | userfaultfd | capability use |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CS | Y | Y | n | Y | Y† | Y† | n | Y† | n | n | n | n |
| S1 | x | ? | ? | D | ? | ? | ? | ? | ? | ? | ? | ? |
| MDE | P | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| ELA | Y | n | n | n | n | n | n | n | n | n | n | P |
| SYS | Y | Y | P | Y | Y | P | P | P | P | Y | Y | n |
| CTX | D | n | n | n | n | n | n | n | n | n | n | n |
| PRI | n | n | n | n | n | n | n | n | n | n | n | n |
| WIZ | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| AQU | ? | ? | ? | ? | ? | ? | ? | Y | ? | ? | ? | D |
| LAC | n | n | n | n | n | n | n | n | n | n | n | n |
| DD | Y | Y | n | Y | P | n | Y | n | n | n | n | Y |
| UPT | P | D | ? | P | P | ? | ? | ? | ? | D | ? | ? |
| SOP | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TRE | n | n | n | n | n | n | n | n | n | n | n | n |
| UPW | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| SWE | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| ORC | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| CB | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| R7 | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TAN | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| QUA | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| CIS | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |

Sophos collects "Kernel function calls" and "Raw system calls" by default, but no public page says
which ones, so its row is `?`. For Sysdig, `P` means the syscall is recorded by ID only, without
arguments.

### Identity

| Sensor | login/logout | sudo/su | user/group changes | loginuid/session |
|---|---|---|---|---|
| CS | Y | n | Y | P† |
| S1 | Y | ? | x | P |
| MDE | P | ? | ? | Y |
| ELA | - | P | - | Y |
| SYS | P | P | n | Y |
| CTX | P | n | n | n |
| PRI | Y | Y | Y | ? |
| WIZ | ? | ? | ? | ? |
| AQU | Y | ? | Y | ? |
| LAC | Y | n | P | P |
| DD | P | P | n | Y |
| UPT | Y | ? | ? | ? |
| SOP | Y | ? | Y | ? |
| TRE | - | ? | - | ? |
| UPW | ? | ? | ? | ? |
| SWE | ? | ? | ? | ? |
| ORC | ? | ? | ? | ? |
| CB | ? | ? | ? | ? |
| R7 | ? | ? | ? | ? |
| TAN | Y | P | ? | Y |
| QUA | ? | ? | ? | ? |
| CIS | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? |

For sudo/su, `P` means it can be reconstructed from exec plus credential-change events or from a
preserved login identity; no dedicated event exists.

### Container/K8s

| Sensor | container id | image | pod/ns/labels | privileged flag | runtime events | K8s audit |
|---|---|---|---|---|---|---|
| CS | Y | Y | Y | ? | Y | n |
| S1 | Y | Y | Y | ? | ? | ? |
| MDE | ? | ? | ? | ? | ? | ? |
| ELA | Y | Y | Y | ? | ? | n |
| SYS | Y | Y | Y | Y | Y | Y |
| CTX | Y | Y | ? | ? | ? | ? |
| PRI | Y | Y | Y | ? | Y | Y |
| WIZ | Y | Y | Y | ? | ? | ? |
| AQU | Y | Y | Y | D | P | ? |
| LAC | Y | Y | P | Y | n | n |
| DD | Y | P | P | ? | ? | ? |
| UPT | Y | P | ? | Y | ? | ? |
| SOP | Y | Y | Y | ? | Y | ? |
| TRE | ? | ? | ? | ? | ? | ? |
| UPW | Y | Y | Y | ? | ? | ? |
| SWE | ? | ? | ? | ? | ? | ? |
| ORC | ? | ? | ? | ? | ? | ? |
| CB | ? | ? | ? | ? | ? | ? |
| R7 | ? | ? | ? | ? | ? | ? |
| TAN | ? | ? | ? | ? | ? | ? |
| QUA | ? | ? | ? | ? | ? | ? |
| CIS | ? | ? | ? | ? | ? | ? |
| TRL | ? | ? | ? | ? | ? | ? |

Trend's container coverage is a separate product (Container Security); Qualys's is also separate (the
Container Runtime Sensor).

### Sensor

| Sensor | tamper protection | loss/health reporting | response actions | prevention |
|---|---|---|---|---|
| CS | Y | P | Y | Y |
| S1 | Y | ? | Y | Y |
| MDE | P | P | Y | Y |
| ELA | P | P | Y | Y |
| SYS | ? | Y | Y | Y |
| CTX | ? | P | Y | Y |
| PRI | ? | ? | Y | Y |
| WIZ | ? | P | Y | P |
| AQU | ? | Y | Y | Y |
| LAC | n | P | - | - |
| DD | ? | P | Y | P |
| UPT | ? | P | P | P |
| SOP | P | P | Y | P |
| TRE | ? | P | Y | Y |
| UPW | ? | ? | P | P |
| SWE | ? | ? | Y | Y |
| ORC | ? | ? | P | P |
| CB | - | ? | ? | Y |
| R7 | ? | ? | ? | ? |
| TAN | ? | P | ? | ? |
| QUA | ? | ? | Y | P |
| CIS | ? | P | ? | ? |
| TRL | ? | ? | ? | P |

In the loss/health column, `Y` means drop or loss counters are documented and `P` means health or
state only. In the prevention column, `P` means kill-after-detect only, an optional add-on, or an
undocumented mechanism.

## 2. Table-stakes telemetry

These appear as `Y` for nearly every sensor that publishes a telemetry list (CrowdStrike, SentinelOne,
MDE, Elastic, Sysdig, Cortex, Prisma, Lacework, Datadog, Uptycs, Sophos, Trend):

- **Process exec** with command line, parent or lineage, user and executable hash. Every sensor in the
  matrix that publishes telemetry has exec.
  - Lineage comes as sensor-assigned process IDs (CrowdStrike `TargetProcessId`, SentinelOne
    `src.process.uid`, Elastic `entity_id`, Lacework `PID_HASH`), never as raw PIDs alone.
  - Hashes are sometimes off by default (Elastic from 8.18).
- **Process exit.** Present in CrowdStrike, Elastic, Sysdig, Cortex, Datadog, Trend, Qualys and Upwind.
- **TCP connect, accept and listen attributed to a process**, with IPv4 and usually IPv6.
- **File create, modify and delete.** Usually gated: Cortex needs the XTH add-on, Trend disables
  delete by default, and Lacework has no reads.
- **Container ID on events**, usually with the image (all CWPP-origin sensors and CrowdStrike,
  SentinelOne, Elastic, Cortex; Datadog exposes container tags whose contents are not listed).
- **Response:** process kill, network isolation (iptables-based in MDE and Cortex, TC/eBPF in Elastic,
  Kubernetes NetworkPolicy in Sysdig), and a remote shell or file fetch.
- **Prevention** of known-bad executables. On Linux this is a fanotify permission check or a kill
  after detection.

Close to table stakes, but not universal:

- **DNS query and answer.** Present in CrowdStrike, Elastic (eBPF only), Sysdig, Datadog, Lacework,
  Uptycs and Wiz. Off by default or conditional in Prisma, Sophos, Trend and Tanium. Absent from Cortex's
  Linux table, and undocumented for MDE on Linux. SentinelOne has DNS event types, but their emission
  on Linux is not documented.
- **Login and logout.** Present in CrowdStrike, SentinelOne, Prisma, Lacework, Aqua, Uptycs, Sophos and
  Tanium. Elastic and Trend explicitly do not collect it.
- **Sensitive-file read.** The documented forms differ:
  - A fixed list: SentinelOne `ReadShadow`/`ReadSSHKeys`, CrowdStrike `CriticalFileAccessed`.
  - Configurable FIM read monitoring: Aqua, Prisma.
  - All opens: Sysdig, Datadog, Sophos.
  - None: Lacework, Elastic host.

## 3. Differentiating telemetry

Documented by only a few sensors:

- **Privileged kernel operations.**
  - BPF load: CrowdStrike `BPFCommandIssued`, Sysdig `bpf`, Datadog `bpf` with `bpf.prog.tag` and
    `bpf.prog.helpers`.
  - Module load: CrowdStrike, Elastic, Sysdig, Datadog (with `loaded_from_memory`).
  - Mount: CrowdStrike, Sysdig, Datadog.
  - Namespaces: Sysdig `unshare`/`setns`, Datadog `unshare`, CrowdStrike `NamespaceChanged`†.
  - Sysctl writes with old and new values: only Datadog `sysctl`.
  - Clock changes: CrowdStrike `HostTimeModified`†, Aqua `audit_systemtime_change`.
  - kexec: CrowdStrike `KernelModeExecImage`†. Sysdig records the syscall ID only.
  - io_uring and userfaultfd: only Sysdig records them as typed syscalls; Uptycs claims io_uring
    detection.
  - perf_event_open and keyring: no sensor records them with arguments.
- **Cross-process memory access.** Sysdig `process_vm_writev`; CrowdStrike `RemoteProcessMemoryWrite`†;
  SentinelOne `memory_dump` through `mem_read`; Trend "Modified Process Write Memory". Elastic and
  Datadog stop at `ptrace`.
- **Credential changes as events.** Elastic `uid_change`/`gid_change` (hook on `commit_creds`), Sysdig
  and Datadog `setuid`/`setgid`/`capset`. CrowdStrike, Cortex and Trend publish none.
- **Login identity carried through sudo.** Datadog `process.auid`, Sysdig `user.loginuid`, MDE
  `LogonID` (since 101.26042), Tanium "original login user", Elastic entry and session leaders.
- **Terminal I/O capture.** Only Elastic (`text_output`, eBPF only, 512 KB per process).
- **HTTP and TLS metadata from the host sensor.** Sophos SNI on connection events; CrowdStrike
  `TlsClientHello`† and `HttpRequest`†; Datadog `packet.tls.version`; Upwind and Sweet L7 API
  reconstruction; Prisma WAAS (proxy or out-of-band).
- **Flow volume.** Lacework `LW_HA_CONNECTION_SUMMARY`, Datadog `network_flow_monitor`, Upwind
  `aggregated_network`, and Elastic disconnect byte counts.
- **Cloud metadata service access.** Only Datadog's `imds` event, which records IMDSv1 or v2 and
  credential access.
- **Package ownership of executables.** Prisma (`apt`/`yum`/`dnf` origin check), Lacework
  `LW_HE_PACKAGES` `ACTIVE`, Datadog `process.file.package.*` (experimental).
- **Executed vulnerable function.** Lacework RiskWatch probes, Upwind `function_events`, Sweet
  call-stack rules.
- **D-Bus and unix sockets.** CrowdStrike `DBusMessage`; Sysdig `socket` with `AF_UNIX`.
- **Overlay-layer exec (container drift).** Sysdig `proc.is_exe_upper_layer`, Datadog
  `process.file.in_upper_layer`, CrowdStrike `FileWrittenAndExecutedInContainer`.
- **Pre-execution blocking in the kernel.** Elastic Defend for Containers (BPF LSM), Sysdig drift and
  malware Prevent on 5.0+, Aqua inline denial, Sweet `clone()` blocking, Prisma file-system Prevent.
- **NAT post-translation tuple.** No sensor documents it.

## 4. Published performance budgets

"Requirement" means a minimum host size or a reservation, not a measured cost. Vendor marketing
figures are marked [VENDOR CLAIM]. Sources are in the vendor sections.

| Sensor | CPU | Memory | Other published limits | Type |
|---|---|---|---|---|
| CrowdStrike | K8s minimum limit 250m; GKE Autopilot default 750m; example reading 498m | K8s minimum 500Mi; Autopilot 1.5Gi; example 223Mi | 20,000-event offline cache; "no performance impact" [VENDOR CLAIM] | Configured limits plus one example reading; no host figure |
| SentinelOne | "1 CPU core / 2 threads, dedicated" | "800 MB RAM minimum, dedicated" | Memory cap on by default on hosts under 500 GB; CPU cap through `sentinelctl`; "40-50% improvement" [VENDOR CLAIM] | Requirement plus caps |
| MDE | "One CPU core minimum"; 4 cores for BAS hosts | "1 GB of RAM minimum" | None for the Linux event stream | Requirement |
| Elastic Defend | "Under 2%" [VENDOR CLAIM]; `utilization_limits.cpu` default 50% (range 20–100%) | RSS "500 MB" | quark ring buffer 512 KiB per CPU, 4–64 MiB; TTY output 512 KB per process | Claim plus configurable cap |
| Sysdig | requests 250m, limits 1000m (chart) | requests 384Mi, limits 1Gi; ring buffer 8 MiB × CPUs / 2 (visible as 16 MiB per map) | 300-message outage buffer | Chart defaults plus a sizing formula |
| Cortex XDR | "2.3 GHz dual-core" | "4 GB minimum (8 GB recommended)" | 10 GB disk; "prerequisites, not consumption figures" | Requirement |
| Prisma Defender | request 256m, limit 900m; "~1-5% CPU" typical [VENDOR CLAIM] | request 256MB; cgroup cap 512MB; "30-70MB" typical [VENDOR CLAIM] | Log inspection 100 bytes/s; forensics 110 MB | Caps plus claim |
| Wiz | limit 300m, request 10m | limit 300Mi, request 50Mi | "negligible performance impact" [VENDOR CLAIM] | Chart defaults |
| Aqua Enforcer | request 350m; commented limits 1000m–1500m | request 512Mi; commented limit 1.5Gi | "65% reduction in load" vs non-eBPF [VENDOR CLAIM] | Manifest defaults |
| Lacework | K8s request 200m, limit 500m; "1-3% CPU" [VENDOR CLAIM] | K8s request 512Mi, limit 1450Mi; "250-300 MB" [VENDOR CLAIM] | Restart after a 4-minute sustained breach; 40 MB FIFO buffer; "1-2 Kilo Bytes/sec" network | Caps plus claim |
| Datadog | Not published | Not published | Up to 94–95% of events filtered in the kernel [VENDOR CLAIM]; sampling rate 500 for open, connect and bind | Claim plus sampling config |
| Uptycs | Not published | Not published | "up to 95%" reduction in the kernel [VENDOR CLAIM] | Claim only |
| Sophos SLS | `cpu_limit` 5% (when limits are enabled; off by default); Helm limit 200m | `memory_limit` 1024M; Helm limit 2Gi; SPL floor 2048 | Circuit breaker sheds telemetry | Optional caps |
| Trend | "4 vCPU or greater recommended"; cgroup cap 5–95% | "2 GB minimum", "5 GB recommended" | Activity-log loss above 10% or 40% CPU at the legacy levels | Requirement plus cap |
| Upwind | Requirement 0.5 core; `CPUQuota` 50% | 512 MiB requirement; `MemoryHigh` 800M, `MemoryMax` 1024M | "up to 10x better than kernel extensions" [VENDOR CLAIM] | systemd caps |
| Sweet | "minimal CPU usage" [VENDOR CLAIM]; 0.20% per node (customer) [VENDOR CLAIM] | "80-120 MBs" [VENDOR CLAIM]; 50 MB (customer) [VENDOR CLAIM] | — | Claim only |
| Qualys EDR | `EDRCPULimit` default 5% of total CPU | `EDRMemoryLimit` default 5% of total memory | Recommended host 8 cores / 8 GB | Default caps |
| Tanium Recorder | `ResourceMonitorCPUPercent` 50 suspends subscriptions | `DatabaseMaxSizeMB` 1024 | Not bound by Client Extension CPU throttles | Self-monitoring threshold |
| Orca, Carbon Black, Rapid7, Cisco, Trellix | Not published | Not published | Orca: "minimal performance impact" [VENDOR CLAIM] | — |

No vendor publishes a per-event cost, a per-hook cost, or an idle-versus-load CPU measurement with a
method. The published numbers are host requirements, cgroup or Kubernetes caps, and unqualified
percentages. Only Datadog and Uptycs give in-kernel filtering ratios, as marketing claims, and only
Datadog shows the event rates behind its ratio (about 5,000/s in the kernel to about 300/s in userspace,
in an example diagram).
