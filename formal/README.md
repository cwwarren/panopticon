# Formal models

TLA+ models of the parts of panopticon whose correctness depends on concurrency: the per-CPU rings
with their busy flag, nested producers on one CPU, sensitive-file coalescing, host safety when the
agent misbehaves, and per-socket UDP dedup. TLC checks each model exhaustively within the bounds of its
configuration; TLAPS proves the ring's safety argument for all sizes.

## Running

```
formal/check.sh               # every configuration and the TLAPS proof
formal/check.sh Ring UdpRace  # only the named configurations (RingProof = the TLAPS proof)
```

`check.sh` downloads `tla2tools.jar` v1.8.0 (TLC 2026.10.30) and tlapm 1.6.0-pre into `formal/tools/`,
pinned by SHA-256, on first use. It needs Java 11 or later (runs here used OpenJDK 25.0.4.1), curl,
sha256sum and taskset. TLC runs with `taskset -c 24-31` and 8 workers (`FORMAL_CPUS`,
`FORMAL_WORKERS` override). Logs, counterexample traces and the summary table go to `formal/out/`.
Safe configurations must pass and unsafe ones must fail with their expected property; any other
outcome makes the script exit non-zero.

## Code version

The models follow `crates/agent/src/bpf/ring.h` (`reserve()`, `commit()`, `struct ctl`),
`agent.bpf.c`, `nat.bpf.c` and `crates/agent/src/run.rs` at commit `0d3aadc` (2026-11-02), which
fixes several findings below. Code and `docs/design.md` line numbers below refer to that commit. The
code kept changing while this was written, and the modeled functions were re-read at each change:
busy flag and atomic drop counters in `reserve()`/`commit()`, the ring protocol moved to `ring.h`,
the NAT producer moved to its own BPF object that shares the main object's nat ring and control
maps, `udp_emit()` shared by IPv4 and IPv6, `file_window` as a load-time constant. Kernel references
are to Linux v7.0 (`github.com/torvalds/linux`, tag `v7.0`) unless marked as the host's Ubuntu
`7.0.0-42` headers or config.

Later commits change code next to the models without changing what they model. `2e64251` moves the
UDP hooks from `fexit/udp_sendmsg` and `fexit/udpv6_sendmsg` to `fentry/udp_send_skb` and
`fentry/udp_v6_send_skb` and reads DNS payloads from the skb; `udp_seen()` and the dedup and
saturation logic in `udp_emit()` are unchanged, and K13 still holds because the uncorked path reaches
`udp_send_skb` without the socket lock. `0e9a541` changes the sysctl hook, which no model covers. The
NAT commit after it moves `on_nat` from `fexit/nf_nat_setup_info` to `fentry/__nf_conntrack_confirm`;
it is still one tracing program that runs in task and softirq context and calls `reserve()` and
`commit()` the same way, so the producer models and the recursion-guard finding apply unchanged.

## Files

| File | Content |
|---|---|
| `Ring.tla` | One per-CPU ring with one producer at a time: `reserve()`, record writes, `commit()`, consumer (`Ring::drain`), memory visibility, writes past `max`, agent death |
| `RingProof.tla` | TLAPS proof: the ring invariant is inductive and implies no overwrite and containment for every size |
| `MultiCtx.tla` | Task, softirq, hardirq and NMI producers of one CPU on one ring: the busy flag as written, Linux, arbitrary and unordered nesting, the ring without a flag, split rings, the trampoline recursion guard |
| `FileCoalesce.tla` | `on_inotify_event` on several CPUs, the `file_seen` LRU hash with element recycling, the `file_flush` iterator |
| `HostSafety.tla` | Host threads running operations through the agent's hooks while the agent runs, stalls or dies |
| `UdpDedup.tla` | `udp_seen()`/`udp_emit()` on one socket with one or more concurrent senders |
| `cfg/*.cfg` | TLC configurations; the first line of each says what it checks |
| `check.sh` | Runs everything and compares each result with the expected one |

## Results

From `formal/check.sh` on the reference host (exit status 0). Distinct states for a violation are the
states TLC had found when it stopped; with 8 workers that number varies slightly between runs.
Depth is the BFS depth, Trace the length of the counterexample. Time is wall clock including JVM
start.

| Config | Spec | Expected | Result | Distinct states | Depth | Trace | Time (s) |
|---|---|---|---|---|---|---|---|
| Ring | Ring | pass | pass | 614228 | 67 | - | 23.5 |
| RingProducerOnly | Ring | pass | pass | 614228 | 67 | - | 11.3 |
| RingLarge | Ring | pass | pass | 11388458 | 94 | - | 34.7 |
| RingRelaxHead | Ring | NoPartialRead | NoPartialRead | 200 | 7 | 6 | 0.2 |
| RingRelaxTail | Ring | NoOverwrite | NoOverwrite | 2258 | 18 | 16 | 0.3 |
| RingSmallSlack | Ring | MemSafe | MemSafe | 1425 | 16 | 14 | 0.2 |
| RingOverrun | Ring | NoOverwrite | NoOverwrite | 6850 | 18 | 17 | 0.3 |
| MultiPlain | MultiCtx | Exclusive | Exclusive | 69 | 6 | 5 | 0.2 |
| MultiBusy | MultiCtx | pass | pass | 1323954 | 40 | - | 52.6 |
| MultiBusyNMI | MultiCtx | pass | pass | 63657 | 27 | - | 4.5 |
| MultiBusyAnyNest | MultiCtx | pass | pass | 3950593 | 40 | - | 202.3 |
| MultiBusyFree | MultiCtx | pass | pass | 22573 | 27 | - | 1.8 |
| MultiBusyPlainFlagFree | MultiCtx | BusyMirrorsHolder | BusyMirrorsHolder | 108 | 9 | 7 | 0.2 |
| MultiBusyPlainFlag | MultiCtx | pass | pass | 1624683 | 46 | - | 63.0 |
| MultiBusyPlainDrops | MultiCtx | Accounting | Accounting | 1414 | 13 | 12 | 0.3 |
| MultiBusyWitness | MultiCtx | NoContentionDrop | NoContentionDrop | 67 | 7 | 5 | 0.2 |
| MultiSplit | MultiCtx | pass | pass | 583632 | 28 | - | 31.6 |
| MultiSplitWitness | MultiCtx | NoNestedAccept | NoNestedAccept | 134 | 7 | 6 | 0.2 |
| MultiGuard | MultiCtx | pass | pass | 449481 | 30 | - | 15.8 |
| MultiGuardWitness | MultiCtx | NoMiss | NoMiss | 26 | 5 | 3 | 0.2 |
| MultiTasks | MultiCtx | pass | pass | 6129 | 20 | - | 0.7 |
| MultiTasksNoPreemptOff | MultiCtx | Exclusive | Exclusive | 84 | 7 | 5 | 0.2 |
| MultiTasksGuardWitness | MultiCtx | NoMiss | NoMiss | 33 | 8 | 3 | 0.2 |
| MultiTasksBusy | MultiCtx | pass | pass | 8123 | 27 | - | 0.8 |
| MultiGuardBusy | MultiCtx | pass | pass | 560998 | 40 | - | 21.7 |
| FileNoEvict | FileCoalesce | pass | pass | 1195299 | 40 | - | 4.5 |
| FileLag | FileCoalesce | pass | pass | 4819460 | 41 | - | 15.6 |
| FileLagWitness | FileCoalesce | RecordsPerWindow | RecordsPerWindow | 787306 | 29 | 26 | 2.4 |
| FileLagMovesBack | FileCoalesce | WindowNeverMovesBack | WindowNeverMovesBack | 97272 | 22 | 18 | 0.7 |
| FileLagPreFix | FileCoalesce | NoWrapExpiry | NoWrapExpiry | 2853 | 13 | 13 | 0.3 |
| FileAny | FileCoalesce | LossOnlyByEviction | LossOnlyByEviction | 13309 | 17 | 16 | 0.5 |
| FileEvict | FileCoalesce | pass | pass | 1988080 | 31 | - | 6.2 |
| FileEvictWitness | FileCoalesce | AttributionCorrect | AttributionCorrect | 341943 | 22 | 22 | 1.4 |
| HostSafety | HostSafety | pass | pass | 1246989 | 43 | - | 19.0 |
| HostSafetyWait | HostSafety | HostProgress | HostProgress | 334731 | 18 | 19 | 4.2 |
| Udp | UdpDedup | pass | pass | 16693624 | 109 | - | 24.6 |
| UdpRace | UdpDedup | RecordBound | RecordBound | 23208 | 19 | 19 | 0.4 |
| UdpWrap | UdpDedup | pass | pass | 6934 | 37 | - | 0.3 |
| UdpWrapPreFix | UdpDedup | RecordBound | RecordBound | 6666 | 31 | 31 | 0.3 |

TLAPS `RingProof.tla`: all 83 obligations proved in 0.7 s (`tlapm --cleanfp`). The whole
script took 9 min 10 s. After `0d3aadc` only the `FileCoalesce` and `UdpDedup` models changed (signed
window test, saturating counter); their rows come from re-running just those twelve configurations
(`check.sh FileNoEvict ... UdpWrapPreFix`, 58 s, exit status 0). The other models and the code they
follow did not change.

"Witness" configurations are not bugs: they state a predicate that is expected to be false so that
TLC prints an example of the interleaving in question.

## Kernel and BPF guarantees relied on

| # | Guarantee | Source |
|---|---|---|
| K1 | The verifier bounds every map-value access by the value size, so a program can only be loaded if every write at `base + (head & (size - 1)) + off` stays inside `size + slack` | `kernel/bpf/verifier.c` `check_map_access` (6235), `check_mem_region_access` (5890) |
| K2 | Verified programs terminate: bounded loops, at most 1M processed instructions, infinite loops rejected | `include/linux/bpf.h:2259`, `kernel/bpf/verifier.c:21271`, `:20611` |
| K3 | fentry/fexit/tp_btf programs run behind a per-program, per-CPU recursion guard; a nested invocation of the same program on that CPU, from any context, is skipped and counted in `prog->stats->misses` (`bpf_prog_info.recursion_misses`). LSM programs have no guard | `kernel/bpf/trampoline.c:1143-1157`, `:1303-1315`; `include/linux/bpf.h:2043-2061`; `include/linux/bpf_verifier.h:965-978`; `kernel/trace/bpf_trace.c:2080`; `kernel/bpf/syscall.c:2445-2457`, `:5069` |
| K4 | Tracing programs run with migration disabled but preemption enabled under `CONFIG_PREEMPT_RCU` (set on the host) | Ubuntu `7.0.0-42` `include/linux/rcupdate.h:987-993`; `/boot/config-7.0.0-42-generic` |
| K5 | `bpf_preempt_disable()` is `preempt_disable()` | `kernel/bpf/helpers.c:3214-3222` |
| K6 | BPF load-acquire / store-release exist since 6.15 and are verified as such; the x86 JIT emits plain `mov`, which x86-TSO orders as acquire/release | `include/uapi/linux/bpf.h:54-55`; `kernel/bpf/verifier.c:8175`; `arch/x86/net/bpf_jit_comp.c:1397-1414` |
| K7 | Hard interrupt handlers run with local interrupts disabled; softirqs run on interrupt exit only when the interrupted code was not in interrupt context | `kernel/irq/handle.c:214`; `kernel/softirq.c:722` |
| K8 | LRU hash maps are always preallocated; an element leaving the table (eviction or replacement) goes straight back to the free list and can be reused for another key while a program still holds a value pointer from lookup; the update path pops an element, copies key and value, then links it under the bucket lock; `BPF_NOEXIST` fails with `-EEXIST` if the key is present | `kernel/bpf/hashtab.c:437`, `298-311`, `859-889`, `1267-1272`, `1274-1338`, `1152-1165`, `788-800` |
| K9 | The map-element iterator walks buckets under RCU only and hands the program a pointer into the live element | `kernel/bpf/hashtab.c:2084-2130` |
| K10 | Hash bucket locks and local-storage locks are resilient spinlocks: acquisition fails with `-EDEADLK` (same-CPU re-entry, ABBA) or `-ETIMEDOUT` (0.25 s) instead of spinning forever; LRU list locks are raw spinlocks held for a bounded scan | `kernel/bpf/hashtab.c:149-159`; `include/asm-generic/rqspinlock.h:62`, `:166-167`; `kernel/bpf/bpf_local_storage.c:343`; `kernel/bpf/bpf_lru_list.c:10-14`, `134-150` |
| K11 | Socket local storage is freed when the socket is destroyed | `net/core/bpf_sk_storage.c:46-47` |
| K12 | A trampoline image is reference counted while invocations run through it, so detaching a link lets in-flight invocations finish | `kernel/bpf/trampoline.c:1293-1301` |
| K13 | `udp_sendmsg` on an uncorked socket takes no socket lock; `dport == 0` fails with `-EINVAL` | `net/ipv4/udp.c:1476`, `:1336` |

Code-generation check: the newest object embedded in `target/release/build/*/out/agent.skel.rs`
(built 09:28 UTC, before the protocol moved unchanged to `ring.h`) disassembles (`llvm-objdump`) in
`on_nat` (the other emitting programs inline the same `reserve()` and `commit()`) to `xchg32_32` on
`ctl + 0x8` (busy), `atomic_fetch_add` on `ctl + 0x80` (drops, on both drop paths), `load_acquire`
on `ctl + 0x40` (tail), `store_release` on `ctl + 0` (head) and then on `ctl + 0x8` (busy).
`file_flush` uses `xchg_64` and `on_inotify_event` `atomic_fetch_add` for `repeats`. Struct sizes
from its BTF give the largest record per class: proc `EXEC_MAX` 1704 B (slack 4096), net `SOCK_MAX`
624 B (2048), file `FILE_MAX` 168 B (512), admin `ADMIN_MAX` 608 B (1024), nat `sizeof(struct
nat_rec)` 96 B (256). At `0d3aadc` `NAME_MAX_REC` is 255, so `FILE_MAX` is 104 + 255 = 359 B, still
below the file slack of 512.

## 1. Per-CPU ring (`Ring.tla`, `RingProof.tla`)

### Model

Memory is counted in 8-byte cells: `commit()` rounds every length up to 8 (`ring.h:144`) and head
starts at 0, so every record starts on a cell. The array value has `Size + Slack` cells; a record
starting at logical position `h` occupies cells `h % Size + k`. Each cell holds the id of the record
that last wrote it and the cell index inside that record (ghost data; the code holds bytes). Cell 0
is the header, written last by `commit()`. A writer stores a nondeterministic number of cells between
the record's final length and `max` (helpers such as `bpf_d_path`, `bpf_probe_read_*_str` and failed
`bpf_probe_read_*` write past the final length but inside `max`), plus `Overrun` cells beyond `max`
in the unsafe variant. The consumer reads the length from the header, then copies the whole record,
header included.

This module has one producer at a time per ring, which is what the busy flag provides
(`MultiCtx.tla`); with a single producer the flag is always free, so it is left out here.

| Action | Code (`ring.h`, `run.rs` at `0d3aadc`) |
|---|---|
| `PReserve`: read own head, load-acquire tail, drop if `head + Max - tail > Size`, else own `[head, head + Max)` | `ring.h:130-139`; drop `:133` |
| `PWrite`: one cell per step, body first, header last | program body between `reserve()` and `commit()`, header stores `:145-149` |
| `PCommit`: store-release `head = slot + len` | `:150` |
| `Flush` (only with `RelaxHead`): a pending producer store becomes visible | memory system |
| `CLoad`: load-acquire head | `run.rs:114-115` |
| `CHdr`: read `len`, the drain assertion | `run.rs:117-125` |
| `CBody`: copy the record, `self.tail += len` | `run.rs:127`, `:158` |
| `CStore`: store-release tail after the loop | `run.rs:162-163` |
| `CEarly` (only with `RelaxTail`): the tail store becomes visible while the last record is still being copied | memory system |
| `Die`: the agent stops forever | — |

The consumer's modulus is computed the way `map_rings()` does it, as the largest power of two not
above the value size (`run.rs:297`); it equals `Size` when `Slack < Size`, which holds for every class.

Assumptions: one producer per ring at a time (`MultiCtx.tla`, from K3, K5, K7); release and acquire
on head and tail (K6); every writer stays within the `max` it passed to `reserve()` (a code
invariant, see `RingOverrun`); `Max <= Slack + 1` cells, i.e. `max <= slack + 8` bytes, which every
class meets (sizes above) and without which the verifier rejects the program (K1); `Size` a power
of two (all `*_RING` are); u64 head and tail do not wrap.

### Properties

| Name | Meaning |
|---|---|
| `NoOverwrite` | no store hits a cell of a committed record the consumer has not finished copying |
| `NoPartialRead` | every cell the consumer reads belongs to the record it expects at that position |
| `MemSafe` | every store lands inside `Size + Slack` |
| `DrainAssert` | the assertion in `drain()` never fires |
| `Contiguous` | every record starts below `Size` and ends within `Size + Slack` |
| `Accounting` | emitted = consumed + dropped + records in the ring + the record being written |
| `Bounds`, `CopyBeforeRelease` | occupancy `<= Size`; a reservation stays below `tail + Size`; the published tail never passes what was copied |
| `StepBound` | a producer event takes at most `Max + Overrun + 2` steps |
| `NeverBlocks` | the producer's next step is always enabled |
| `ProducerFinishes` | every started event completes; checked under `ProducerOnlySpec`, which gives the consumer no fairness |
| `ConsumerDrains` | every committed record is eventually copied unless the agent died (weak fairness for both sides) |

Bounds: `Ring` and `RingProducerOnly` use `Size = 4`, `Slack = 1`, `Max = 2`, lengths {1, 2}, 8 events
(four laps). `RingLarge` uses `Size = 8`, `Slack = 2`, `Max = 3`, lengths {1, 2, 3}, 9 events, safety
only, with a `VIEW` that maps cells of records that are neither live nor being written to zero (no
action or property reads them).

### Unsafe variants

- `RingRelaxHead` (head store not a release): the producer reserves a one-cell record, its header
  store is still pending when `commit()` publishes head = 1, the consumer loads head and reads a zero
  header. [INFERENCE] In the code the drain assertion would fire on a zero header; after the first
  lap an older record's header left in that place could pass the assertion and be copied as a record.
- `RingRelaxTail` (tail store not a release): the ring holds two 2-cell records; the consumer reads
  record 1's header, its tail store (value 2) becomes visible while it still copies record 1, the
  producer sees free space, reserves at logical 4 (cell 0) and overwrites record 1's header before the
  copy reaches it.
- `RingOverrun` (a writer stores one cell past `max`, `Slack = 2` so the store stays inside the value):
  with exactly `max` free the producer reserves, writes its `max` cells and one more, and the extra
  cell lands on the oldest record the consumer has not copied (`NoOverwrite`). `MemSafe` still holds:
  the verifier's bound does not catch this. With `Overrun = 0`, writes anywhere within `max` never
  overwrite (`Ring`, `RingLarge`, and `RingProof.tla` for all sizes).
- `RingSmallSlack` (`Slack = 0` with `Max = 2`): a 2-cell record reserved at cell 3 writes cell 4,
  outside the value. The verifier rejects such a program (K1); the condition the model needs is
  exactly `max <= slack + 8` bytes.

The acquire sides (consumer's load of head, producer's load of tail) are not modeled separately.
[INFERENCE] Without acquire on head the consumer's copies could be satisfied before its head load,
which produces the same stale read as `RingRelaxHead`; without acquire on tail the producer's record
stores could become visible before the tail value that freed the space, which produces the same
overwrite as `RingRelaxTail`.

### Proof for all sizes

`RingProof.tla` abstracts the ring to logical positions with release/acquire visibility (head, tail,
the consumer's copy position, the producer's reservation) and proves with TLAPS, for every `S > 0`,
`Slack` and `1 <= Max <= S`, `Max <= Slack + 1`:

- `Safety`: `Inv` (`tail <= ctail <= chead <= head`, `head - tail <= S`, a reservation starts at head
  and ends by `tail + S`) is inductive.
- `NoOverwrite`: a byte the producer may write (`slot <= p1 < slot + Max`) never has the same physical
  index `(s % S) + (p - s)` as an unread committed byte (`ctail <= s2 <= p2 < head`). The two
  positions differ by between 1 and `S - 1`, so their physical indices are not congruent mod `S`.
  Since the consumer only reads below its loaded head, this also rules out reading a byte that is
  being written.
- `Contained`: every byte the producer may write has a physical index in `0 .. S + Slack - 1`.

## 2. Nested producers on one CPU (`MultiCtx.tla`)

### Model

Contexts `T1`, `T2` (tasks), `S` (softirq), `H` (hardirq), `N` (NMI) of one CPU produce into one
class ring. Three nesting disciplines:

- `linux`: an NMI interrupts anything but an NMI; a hardirq anything but a hardirq or NMI; a softirq
  only a task, never another softirq; a task switches to another task only where preemption is
  enabled, i.e. outside `bpf_preempt_disable()` (K4, K5, K7). Nested invocations run to completion
  before the interrupted one resumes.
- `any`: any context may interrupt any other at any step, still last-in first-out.
- `free`: no discipline: every started invocation may take its next step at any time.

Ring memory is abstracted to reservations `[start, start + len)`; `Ring.tla` covers the byte level for
a single producer, and this model checks that the busy flag provides that single producer. The
consumer on another CPU may advance tail to any committed record end. Each context makes 2
invocations (1 in `MultiBusyNMI`); `Size = 4`, `Max = 2`, lengths {1, 2}.

| Step | Code (`ring.h`, `nat.bpf.c` at `0d3aadc`) |
|---|---|
| `Start`: the hook fires; with `SameProg`, the trampoline guard skips the program if another invocation of it is active on this CPU | K3 |
| `XChg`: `if (__sync_lock_test_and_set(&c->busy, 1))` contention drop, else hold the flag | `ring.h:126` |
| `BLoad` + `BStore`: alternative plain flag (not the code) | — |
| `Reserve`: head, load-acquire tail, space check | `:130-132`, `:139` |
| `Drop`: `__sync_fetch_and_add(&c->drops, 1)` on contention or full ring (load + store in the unsafe variant) | `:127`, `:133` |
| `Release`: `__atomic_store_n(&c->busy, 0, __ATOMIC_RELEASE)` on the full path and after the head store in `commit()` | `:134`, `:151` |
| `Commit`: store-release head | `:150` |
| `Exit`: `bpf_preempt_enable()`, return, guard released | e.g. `nat.bpf.c:53-55` |

Mode `plain` is the ring without the flag (the code before `5414e97`); mode `split` is the
alternative of one ring per context kind, which the code does not use.

| Property | Meaning |
|---|---|
| `Exclusive` | at most one producer per ring between reserve and commit (the premise of `Ring.tla`) |
| `NoOverlap` | live records and reservations of a ring never overlap |
| `HeadIsEnd` | head always ends the last committed record |
| `Accounting` | emitted = consumed + in ring + dropped (full ring and busy contention) + recursion misses + in progress |
| `Occupancy` | `head - tail <= Size` |
| `BusyMirrorsHolder` | the flag is set exactly when one producer holds the ring |
| `OneCommitPerReserve` | every successful reserve is followed by exactly one commit, and a reserve that failed commits nothing |
| `NoBusyLeak` | a producer holds the flag only between `reserve()` and the release; no path returns with it |
| `ContentionOnlyNested` | a contention drop happens only when the dropped producer interrupted the holder |
| `GuardSerializes` | with one program, at most one invocation runs on the CPU |
| `StepBound` | at most 8 steps per invocation |
| `NeverBlocks`, `InvocationsFinish` | the next step of a running invocation is always enabled; every invocation ends |

### Results

| Config | Setup | Result |
|---|---|---|
| `MultiBusy` | the code: busy flag with xchg, atomic drops; T, S, H, Linux nesting | all properties hold |
| `MultiBusyNMI` | the code; T, S, H and NMI, one invocation each | all properties hold |
| `MultiBusyAnyNest` | the code; T, S, H nest in any order at any step | all properties hold |
| `MultiBusyFree` | the code; two producers interleave without any nesting discipline | all properties hold (`ContentionOnlyNested` not applicable) |
| `MultiBusyWitness` | the code | example: T takes the flag, S interrupts it and drops and counts |
| `MultiGuardBusy` | the code on the nat class: one fexit program in T, S and H | all hold; the busy flag never drops (`NoContentionDrop` holds); nested invocations are recursion misses |
| `MultiTasksBusy` | the code on a task-only class: two tasks, different programs | all hold; the busy flag never drops |
| `MultiPlain` | no flag, T, S, H share the ring | violation: T reserves at 0, S interrupts before T commits and reserves the same position |
| `MultiBusyPlainDrops` | flag, but drops as load/add/store | violation of `Accounting` |
| `MultiBusyPlainFlag` | flag as plain load then store, Linux nesting | all properties hold |
| `MultiBusyPlainFlagFree` | plain flag, free interleaving | violation of `BusyMirrorsHolder`: both producers load 0 and both take the flag |
| `MultiGuard`, `MultiGuardWitness` | one fexit program in T, S, H, no flag | all hold; example of a recursion miss |
| `MultiTasks` | two tasks, different programs, no flag, preemption off in the window | all properties hold |
| `MultiTasksNoPreemptOff` | same without `bpf_preempt_disable` | violation of `Exclusive` |
| `MultiTasksGuardWitness` | two tasks, same program | example: a task preempted inside the program before `bpf_preempt_disable()` makes the other task's invocation a recursion miss |
| `MultiSplit`, `MultiSplitWitness` | one ring per context kind (unused alternative) | all hold, no contention drop; example of the nested event the flag drops being accepted |

The uniform busy-flag ring is safe under every nesting discipline checked, including unordered
interleaving: no overlap, one commit per successful reserve, no leaked flag, and every event is
accounted. Which events it drops: exactly those whose `reserve()` starts while a producer they
interrupted holds the flag, i.e. sits between its `xchg` and the release in `commit()` or on the
full-ring path (`BusyMirrorsHolder` and `ContentionOnlyNested` hold in every reachable state;
`MultiBusyWitness` shows T taking the flag and S interrupting it). Split rings would accept that event
(`MultiSplitWitness`).

`MultiBusyPlainDrops` shows why the drop counter must be atomic: T holds the flag, S fails to take it
and loads `drops` (0), H interrupts S, also fails, and stores 1; S resumes and stores 0 + 1. Two
drops, counter 1. [INFERENCE] A holder incrementing on the full path would race a nested contender
the same way. The code uses `__sync_fetch_and_add` on both paths.

`MultiBusyPlainFlag` passes because Linux nesting is last-in first-out: a producer that interrupts
between another's load and store of the flag runs to completion and leaves the flag as it found it.
Without that discipline (`MultiBusyPlainFlagFree`) a plain flag admits two holders; the `xchg` in the
code does not depend on the nesting order.

Measured cost of the flag, from `docs/design.md:264-269` (not measured here): 52.10 ns against
52.29 ns per `getppid` with an emitting program, 41.23 ns without one, medians of 11 interleaved
pinned runs of `crates/ringbench` variants `spsc_busy` and `spsc_nots`.

## 3. Sensitive-file coalescing (`FileCoalesce.tla`)

### Model

Two CPUs run `on_inotify_event`; the agent runs the `file_flush` iterator at any time. Time is a global
jiffies counter. The repeats counter of each LRU element is modeled as the set of event ids added to it,
so every event can be followed to its outcome. LRU elements have identity (`Nodes`, the
`max_entries` pool) because the kernel recycles them immediately (K8). The `IN_IGNORED` path
(`agent.bpf.c:1063-1073`, an unwatch record whose `max` equals the bytes written) and the filter on
the agent's own tgid (`:1074-1075`) return before the coalescing code and are not modeled.

| Step | Code |
|---|---|
| `Begin`: `now = bpf_jiffies64()`, build the key | `agent.bpf.c:1077-1083` |
| `Lookup`: value pointer for the key, or NULL | `:1084` (K8) |
| `ReadJ`: `(__s64)(now - seen->jiffies) < (__s64)file_window` (`SignedCmp`); the pre-fix u64 test with `SignedCmp = FALSE` | `:1085` |
| `Add`: `__sync_fetch_and_add(&seen->repeats, 1)` | `:1086` |
| `SetJ`: `seen->jiffies = now` | `:1090` |
| `Pop`, `CopyVal`, `Link`: `bpf_map_update_elem(..., BPF_NOEXIST)`; pop a free element or evict one, copy key, copy `{now, 0}`, link or fail under the bucket lock; the result is ignored | `:1093` (K8) |
| `Emit`: full record (the ring itself is `Ring.tla`) | `:1096-1114` |
| `FPick`, `FXchg`, `FKey`: iterator element, `if (!v->repeats)`, `xchg(repeats, 0)`, then `r.k = *k` | `:1125-1132` (K9) |
| `Tick`: jiffies advance; an invocation lags at most `MaxDelay` jiffies behind the `now` it read | K4 (tracing programs are preemptible), interrupts |

Properties: `ExactlyOnce` (every finished event is exactly one of: full record, flushed repeat count,
pending count in a linked element, count held in an unlinked element, destroyed count),
`LossOnlyByEviction` (counts leave the table only when an element was evicted), `AttributionCorrect`
(every count is reported under its own key), `TableBounded` (one element per key, at most
`max_entries`), `RecordsPerWindow` (full records per key in any window of `W` jiffies `<= RecBound`),
`WindowNeverMovesBack`, `NoWrapExpiry` (no CPU treats a window as expired because its `now` is
behind the stored jiffies), `NoEviction`.

### Results

All with 2 CPUs and the signed window test of `0d3aadc` unless marked pre-fix.

| Config | Bounds | Result |
|---|---|---|
| `FileNoEvict` | 1 key, 3 elements (no eviction possible), 3 events per CPU, `W = 2`, jiffies 0..4, `MaxDelay = 0` | exactly once, no loss, correct attribution, at most 2 records per key per window, windows never move back, no wrap expiry |
| `FileLag` | as above, `W = 3`, jiffies 0..5, `MaxDelay = 1` | exactly once, no loss, no wrap expiry, at most 3 records per key per window |
| `FileLagWitness` | same, bound 2 | violation: 3 records in one window |
| `FileLagMovesBack` | same | violation of `WindowNeverMovesBack` |
| `FileLagPreFix` | same with the pre-fix u64 test | violation of `NoWrapExpiry` |
| `FileAny` | `BPF_ANY` instead of `BPF_NOEXIST` | violation of `LossOnlyByEviction` |
| `FileEvict` | 2 keys, 2 elements, 2 events per CPU, `W = 2`, jiffies 0..3, `MaxDelay = 1` | exactly once; every lost count was lost through eviction |
| `FileEvictWitness` | same | violation of `AttributionCorrect` |

- `BPF_ANY` counterexample: CPU 1 inserts the key and emits; CPU 2 had looked the key up before that
  and is inserting too; CPU 1's next event adds a repeat to its element; CPU 2's `BPF_ANY` update
  links a fresh element and unlinks CPU 1's, and the pending repeat is unreachable. With
  `BPF_NOEXIST` CPU 2's update fails with `-EEXIST` and the count stays (`FileNoEvict`).
- Records per window: with every invocation finishing in the jiffy it read (`MaxDelay = 0`) the bound
  is the number of CPUs (several CPUs can miss at once: insert race, expiry race). With the pre-fix
  u64 test and an invocation spanning a jiffy, a CPU that read `now = t` and then finds the key
  inserted or reset at `t + 1` sees the subtraction wrap, treats the window as expired, moves its
  start back to `t` and emits (`FileLagPreFix`). The signed test of `0d3aadc` removes that path
  (`NoWrapExpiry` holds in `FileLag`). Two effects of a one-jiffy lag remain in the fixed code: an
  insert that loses the race but read the clock a jiffy later still emits, so `FileLagWitness`
  reaches 3 records in a window of 3 jiffies with 2 CPUs (the bound of 3 holds in `FileLag`); and
  when two CPUs both see an expired window, the one with the older `now` may store last and move
  the start back by a jiffy (`FileLagMovesBack`).
- Misattribution (`FileEvictWitness`): the iterator exchanges key 1's count to zero; before it copies
  the key, CPU 2 inserts key 2, the LRU evicts key 1's element and reuses it for key 2; the iterator
  reports key 1's count under key 2. The same reuse lets an `Add` that looked up the element before
  eviction land in another key's count.

## 4. Host safety (`HostSafety.tla`, and the liveness checks above)

Two host threads on two CPUs perform operations whose kernel paths carry the agent's hooks. The
programs are reduced to the steps that touch shared state or loop: `on_exec` (task storage, reserve,
argv loop, commit; `agent.bpf.c:625-716`, loop `:694`), `udp_emit` (socket storage, `udp_seen` loop,
table update, record; `:795-854`), `on_inotify_event` (lookup, add or insert, record; `:1045-1116`),
`emit_sock` (record; `:453-465`). Storage creation and map inserts may fail (K10, K11); a full ring
drops. The agent runs (drains rings), stalls forever, or dies at any point; death closes its links and
detaches the programs, invocations already running finish (K12). Host threads have weak fairness, the
agent none.

| Property | Meaning |
|---|---|
| `StepBound` | an invocation takes at most `4 + ARGV_MAX_ARGS` (exec), `5 + 2 * UDP_SEEN` (udp), 4 (file), 2 (connect) steps; one step per loop iteration and one for the exit test |
| `NeverBlocks` | a thread inside a program or the kernel always has its next step enabled |
| `HostProgress` | every host thread returns to idle infinitely often, whatever the agent does |
| `StateBounded` | ring occupancy `<= RingSize`, `file_seen` entries `<= max_entries`, socket storage only on open sockets |
| `DetachedRunsNothing` | a dead agent has no attached programs |

`HostSafety` (scaled: `ARGV_MAX_ARGS = 2`, argc up to 3, `UDP_SEEN = 2`, ring of 2 records,
`max_entries = 1`, 2 keys, 1 socket) passes, including deadlock freedom. `HostSafetyWait` is the
counterfactual of a producer that waits for ring space: a thread fills its ring, the agent dies, and
the thread's next invocation waits in `reserve()` forever; `HostProgress` fails. The ring,
multi-context and coalescing models show the same independence in more detail: `ProducerFinishes`
holds with no fairness for the consumer, `NeverBlocks` holds in `Ring` and `MultiCtx`, and no step
of any `on_inotify_event` model waits on the iterator.

What bounds a real invocation: the verifier's termination guarantee (K2) bounds every program; the
code's loops are `ARGV_MAX_ARGS = 32` (`:694`), `UDP_SEEN = 4` (`:797`) and the path walk
(`PATH_WALK`, `:519`); map and storage locks fail instead of spinning forever (K10). Memory is fixed:
rings are array maps sized at load, `file_seen` is preallocated with 4096 elements, task and socket
storage live and die with their kernel objects (K11).

## 5. UDP dedup (`UdpDedup.tla`)

One socket's `udp_meta` (`agent.bpf.c:334-340`) and the code of `udp_emit()` (`:803-854`): one
`udp_seen()` call (`:816`), the early return (`:817-818`), the table insert and `distinct += 1`
(`:819-827`; since `0d3aadc` the increment is `if (m->distinct < UDP_CAP && ++m->distinct ==
UDP_CAP)` at `:825`, `SatCounter` in the model), the record (`:831-853`). Each step that reads or
writes `udp_meta` is separate, so concurrent senders interleave between them. Ghost state keeps the
last `UDP_SEEN` inserted destinations independently of the table.

Properties: `RecordBound` (records `<= UDP_CAP + DNS queries`), `NewDestEmits` (before saturation, a
non-DNS send to a destination outside the last `UDP_SEEN` recorded ones emits), `DedupHolds` (a
non-DNS send to one of them does not), `TableIsFifo`, `StateBounded`.

| Config | Bounds | Result |
|---|---|---|
| `Udp` | 1 sender, `UDP_SEEN = 4`, `UDP_CAP = 16`, u8 counter, 5 destinations + 2 DNS destinations, 18 sends | all properties hold |
| `UdpRace` | 2 senders, `UDP_SEEN = 2`, `UDP_CAP = 2`, 3 destinations, 5 sends | violation of `RecordBound` |
| `UdpWrap` | 1 sender, `UDP_SEEN = 2`, `UDP_CAP = 2`, counter of 2 bits, 3 + 3 destinations, 6 sends | `RecordBound` holds |
| `UdpWrapPreFix` | same with the pre-fix `distinct += 1` | violation of `RecordBound` |

- `UdpRace`: after one record (`distinct = 1`), both threads send to a new destination `b`; both pass
  the check, both insert `b` (the table ends up holding `b` twice), both increment and both emit:
  3 records with a cap of 2. Interleavings that lose an increment exist as well.
- `UdpWrapPreFix`: before `0d3aadc` a DNS send to a new destination incremented `distinct` even past
  the cap, so after `2^bits - UDP_CAP` such sends the counter wrapped to 0 and non-DNS sends emitted
  again (with the u8 counter, 240 DNS destinations after saturation; arithmetic, not run at full
  width). With the saturating increment the counter stops at the cap and `UdpWrap` passes.

## Findings and status

Status refers to commit `0d3aadc`.

1. **The busy flag does not see nested nat invocations.** *Fixed in the design text.* The design said
   the flag turns "a softirq interrupting a task-context producer of the nat class" into a counted
   drop. It cannot: `on_nat` (`nat.bpf.c:9`) is one fexit program, and the trampoline's recursion
   guard (K3) skips any nested invocation of it on the same CPU before the program runs
   (`MultiGuardBusy`: the flag never drops; `MultiGuardWitness`: the miss). The flag does what the
   design says for nested producers of different programs, in any nesting order, including NMI and
   unordered interleaving (`MultiBusy`, `MultiBusyNMI`, `MultiBusyAnyNest`, `MultiBusyFree`).
   `docs/design.md:264-276` now states both. [INFERENCE] From the hook list, every hook other than
   `on_nat` runs in process context, so today no ring has two programs that can nest
   (`MultiTasksBusy`: task-only classes never drop on the flag either).
2. **Recursion misses were not reported.** *Fixed.* Nested invocations skipped by the guard are
   counted only in `bpf_prog_info.recursion_misses`. Besides the softirq case, a task preempted inside
   a tracing program outside `bpf_preempt_disable()` (K4) makes the same program skip in every other
   task on that CPU until it resumes (`MultiTasksGuardWitness`). The agent now reads the counter of
   every program once per second and writes a miss record (`run.rs:254`, `push_misses()` at `:685`);
   `docs/design.md:270-276`. Not modeled further: the models count misses as their own outcome in
   `Accounting`.
3. **UDP saturation was not a hard bound.** *Wrap fixed; concurrent overshoot remains and is
   documented.* Before `0d3aadc` DNS destinations kept incrementing the u8 `distinct` after
   saturation, which wrapped and re-enabled non-DNS records (`UdpWrapPreFix`); the saturating
   increment (`agent.bpf.c:825`) removes it (`UdpWrap`). Two threads sending on one socket still run
   `udp_emit` concurrently (K13) on plain loads and stores and can exceed the cap (`UdpRace`), as
   `docs/design.md:341-345` now says.
4. **Coalescing under eviction moves counts as well as dropping them.** *Documented.* Eviction is the
   only loss (`FileEvict`) and `BPF_NOEXIST` is required (`FileAny`). Element reuse (K8) also lets a
   count be reported under another key (`FileEvictWitness`) and lets a stale `seen->jiffies = now`
   reset another key's window. `docs/design.md:451-455` now describes the reuse.
5. **Records per window could exceed one per CPU through a u64 wrap.** *Wrap fixed; a smaller lag
   effect remains.* The window test is now signed (`agent.bpf.c:1085`), so a CPU whose `now` is behind
   the stored jiffies counts as inside the window (`FileLagPreFix` fails, `FileLag` passes
   `NoWrapExpiry`). With a one-jiffy lag the fixed code still allows 3 records per window of 3
   jiffies with 2 CPUs (`FileLagWitness`) and a window start that moves back by a jiffy after an
   expiry race (`FileLagMovesBack`). [INFERENCE] With `file_window` = HZ = 1000 jiffies and
   invocations far shorter than a jiffy both are rare and small.
6. **Writers must stay within `max`.** *Documented; a code invariant.* `RingOverrun` shows one cell
   past `max` overwrites the oldest unread record while every store is still inside the map value.
   The models assume each program's writes are bounded by the `max` it passes (true by the size
   arithmetic of each record type, not verified here per program); `docs/design.md:278-280` cites
   this.
7. **Shutdown lost records committed after the last drain.** *Fixed; not modeled.* At shutdown
   `run()` now drops all links, sleeps one poll interval, then does the final drain, miss, loss and
   iterator reads (`run.rs:237-258`). [INFERENCE] The sleep is a heuristic wait for in-flight
   invocations: an invocation that stays preempted before its `reserve()` for longer than the poll
   interval could still commit after the final drain. The shutdown order is not in the models.

## Limits

- Bounds are small (rings of 4 and 8 cells, 2-4 contexts with 1-2 invocations each, 2 CPUs with 2-3
  events, scaled UDP and argv constants); only `RingProof.tla` covers all sizes, and only for the
  logical ring with release/acquire.
- `MultiCtx.tla` abstracts ring memory to reservations; `MultiBusyNMI` runs one invocation per
  context to keep the state space small.
- `FileCoalesce.tla` replaces the LRU policy by "any element may be evicted" and abstracts the record
  ring; the iterator may visit any linked element at any time.
- `UdpDedup.tla` treats a table slot (address and port, three stores in the code) as one store.
- `HostSafety.tla` reduces programs to their shared-state and loop steps; it does not model the
  verifier, only the bounds the verifier enforces.
