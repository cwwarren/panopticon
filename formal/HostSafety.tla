----------------------------- MODULE HostSafety -----------------------------
(***************************************************************************)
(* Host safety: host threads run operations whose kernel paths carry the   *)
(* agent's hooks; the agent process may run, stall forever, or die at any  *)
(* point (its links close and the programs detach).  Checks that a hook    *)
(* invocation never waits, finishes within a fixed number of steps, that   *)
(* host operations complete whatever the agent does, and that all agent    *)
(* state stays bounded.                                                    *)
(*                                                                         *)
(* Each program is reduced to its steps that touch shared state or loop:   *)
(*   exec: on_exec (task storage, reserve, argv loop, commit)              *)
(*   udp:  on_udp_send (sk storage, udp_seen loops, table update, record)  *)
(*   file: on_inotify_event (LRU lookup/insert, record)                    *)
(*   conn: emit_sock (record)                                              *)
(* The ring is one per thread (per CPU): occupancy in records.             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Threads,    \* host threads, each on its own CPU
    ArgvMax,    \* ARGV_MAX_ARGS
    ArgcMax,    \* largest argc a host exec may have (> ArgvMax)
    Seen,       \* UDP_SEEN
    RingSize,   \* records that fit in one ring
    MapMax,     \* file_seen max_entries
    Keys,       \* file keys
    Socks,      \* sockets the host may open
    WaitOnFull  \* FALSE as in the code; TRUE: a producer that waits for space

ASSUME ArgcMax > ArgvMax /\ RingSize \in Nat \ {0} /\ MapMax \in Nat \ {0}
       /\ WaitOnFull \in BOOLEAN

Ops == {"exec", "udp", "file", "conn"}
\* Worst-case steps per invocation, read off the program text.  A bounded
\* loop costs one step per iteration plus one for the exit test.
MaxSteps(op) == CASE op = "exec" -> 4 + ArgvMax     \* storage, reserve, argv loop + exit, commit
                  [] op = "udp"  -> 5 + 2 * Seen    \* storage, 2 x udp_seen + exit, insert, reserve, commit
                  [] op = "file" -> 4               \* lookup, add or insert, reserve, commit
                  [] op = "conn" -> 2               \* reserve, commit

VARIABLES
    agent,      \* "running" | "stalled" | "dead"
    attached,   \* the agent's programs are attached
    hpc, op, ppc, steps, i, argc, sock, key,   \* per host thread
    used,       \* [Threads -> records in that CPU's ring]
    mapKeys,    \* keys present in file_seen
    live,       \* open sockets
    skStore     \* sockets that have udp_meta storage

DefSock == CHOOSE s \in Socks : TRUE
DefKey == CHOOSE k \in Keys : TRUE

tvars == <<hpc, op, ppc, steps, i, argc, sock, key>>
vars == <<agent, attached, tvars, used, mapKeys, live, skStore>>

Init ==
    /\ agent = "running" /\ attached = TRUE
    /\ hpc = [t \in Threads |-> "idle"] /\ op = [t \in Threads |-> "conn"]
    /\ ppc = [t \in Threads |-> "none"] /\ steps = [t \in Threads |-> 0]
    /\ i = [t \in Threads |-> 0] /\ argc = [t \in Threads |-> 0]
    /\ sock = [t \in Threads |-> DefSock]
    /\ key = [t \in Threads |-> DefKey]
    /\ used = [t \in Threads |-> 0]
    /\ mapKeys = {} /\ live = {} /\ skStore = {}

(***************************************************************************)
(* Host                                                                    *)
(***************************************************************************)
FirstPc(o) == CASE o = "exec" -> "storage"
                [] o = "udp"  -> "storage"
                [] o = "file" -> "lookup"
                [] o = "conn" -> "reserve"

\* A host operation reaches the hook.  The trampoline runs the program only
\* while the link exists.
HStart(t) ==
    /\ hpc[t] = "idle"
    /\ \E o \in Ops :
       \E a \in (IF o = "exec" THEN 0..ArgcMax ELSE {0}),
          s \in (IF o = "udp" THEN live ELSE {DefSock}),
          k \in (IF o = "file" THEN Keys ELSE {DefKey}) :
         /\ op' = [op EXCEPT ![t] = o]
         /\ argc' = [argc EXCEPT ![t] = a]
         /\ sock' = [sock EXCEPT ![t] = s]
         /\ key' = [key EXCEPT ![t] = k]
         /\ IF attached
              THEN /\ hpc' = [hpc EXCEPT ![t] = "prog"]
                   /\ ppc' = [ppc EXCEPT ![t] = FirstPc(o)]
              ELSE /\ hpc' = [hpc EXCEPT ![t] = "kernel"]
                   /\ UNCHANGED ppc
    /\ steps' = [steps EXCEPT ![t] = 0]
    /\ i' = [i EXCEPT ![t] = 0]
    /\ UNCHANGED <<agent, attached, used, mapKeys, live, skStore>>

\* The kernel finishes the operation after the program returned.  The
\* thread's per-operation state returns to its initial values.
HFinish(t) ==
    /\ hpc[t] = "kernel"
    /\ hpc' = [hpc EXCEPT ![t] = "idle"]
    /\ op' = [op EXCEPT ![t] = "conn"]
    /\ steps' = [steps EXCEPT ![t] = 0]
    /\ i' = [i EXCEPT ![t] = 0]
    /\ argc' = [argc EXCEPT ![t] = 0]
    /\ sock' = [sock EXCEPT ![t] = DefSock]
    /\ key' = [key EXCEPT ![t] = DefKey]
    /\ UNCHANGED <<agent, attached, ppc, used, mapKeys, live, skStore>>

\* socket()/close(): sk storage is freed with the socket (bpf_sk_storage_free).
SockOpen(s) ==
    /\ s \notin live
    /\ live' = live \cup {s}
    /\ UNCHANGED <<agent, attached, tvars, used, mapKeys, skStore>>

SockClose(s) ==
    /\ s \in live
    /\ \A t \in Threads : ~(hpc[t] = "prog" /\ op[t] = "udp" /\ sock[t] = s)
    /\ live' = live \ {s}
    /\ skStore' = skStore \ {s}
    /\ UNCHANGED <<agent, attached, tvars, used, mapKeys>>

(***************************************************************************)
(* Program steps.  None of them is conditioned on the agent's state.       *)
(***************************************************************************)
Go(t, p) ==
    /\ ppc' = [ppc EXCEPT ![t] = p]
    /\ steps' = [steps EXCEPT ![t] = steps[t] + 1]

Ret(t) ==
    /\ ppc' = [ppc EXCEPT ![t] = "none"]
    /\ hpc' = [hpc EXCEPT ![t] = "kernel"]
    /\ steps' = [steps EXCEPT ![t] = steps[t] + 1]

\* bpf_task_storage_get / bpf_sk_storage_get with F_CREATE: may fail (NULL)
Storage(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "storage"
    /\ \/ /\ Ret(t) /\ UNCHANGED skStore                   \* allocation failed: return 0
       \/ /\ Go(t, IF op[t] = "exec" THEN "reserve" ELSE "seen")
          /\ skStore' = IF op[t] = "udp" THEN skStore \cup {sock[t]} ELSE skStore
          /\ UNCHANGED hpc
    /\ UNCHANGED <<agent, attached, op, i, argc, sock, key, used, mapKeys, live>>

\* udp_seen(): for (i = 0; i < UDP_SEEN; i++), called twice in the worst case
SeenLoop(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "seen"
    /\ IF i[t] < 2 * Seen
         THEN /\ \/ /\ Go(t, "seen") /\ i' = [i EXCEPT ![t] = i[t] + 1]
                 \/ /\ Go(t, "insert") /\ UNCHANGED i       \* match found / done
         ELSE /\ Go(t, "insert") /\ UNCHANGED i
    /\ UNCHANGED <<agent, attached, hpc, op, argc, sock, key, used, mapKeys, live, skStore>>

\* table update, or the early return of a duplicate / saturated destination
Insert(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "insert"
    /\ \/ Go(t, "reserve") /\ UNCHANGED hpc
       \/ Ret(t)
    /\ UNCHANGED <<agent, attached, op, i, argc, sock, key, used, mapKeys, live, skStore>>

\* bpf_map_lookup_elem on file_seen: repeat (atomic add) or new window
Lookup(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "lookup"
    /\ IF key[t] \in mapKeys
         THEN \/ Ret(t)                                   \* atomic add, return
              \/ Go(t, "reserve") /\ UNCHANGED hpc        \* window expired
         ELSE Go(t, "mapins") /\ UNCHANGED hpc
    /\ UNCHANGED <<agent, attached, op, i, argc, sock, key, used, mapKeys, live, skStore>>

\* bpf_map_update_elem(BPF_NOEXIST): evicts when full; may fail (-EEXIST,
\* -ENOMEM, or a bucket-lock error from rqspinlock); the result is ignored.
MapIns(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "mapins"
    /\ Go(t, "reserve")
    /\ \/ mapKeys' = mapKeys
       \/ /\ Cardinality(mapKeys) < MapMax
          /\ mapKeys' = mapKeys \cup {key[t]}
       \/ /\ Cardinality(mapKeys) = MapMax
          /\ \E v \in mapKeys : mapKeys' = (mapKeys \ {v}) \cup {key[t]}
    /\ UNCHANGED <<agent, attached, hpc, op, i, argc, sock, key, used, live, skStore>>

\* reserve(): drop when full, never wait.  WaitOnFull is the counterfactual
\* of a producer that waits for the consumer.
Reserve(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "reserve"
    /\ WaitOnFull => used[t] + 1 <= RingSize
    /\ IF used[t] + 1 > RingSize
         THEN Ret(t)                                          \* drops += 1
         ELSE Go(t, IF op[t] = "exec" THEN "argv" ELSE "commit") /\ UNCHANGED hpc
    /\ UNCHANGED <<agent, attached, op, i, argc, sock, key, used, mapKeys, live, skStore>>

\* for (i = 0; i < ARGV_MAX_ARGS; i++) { if (i >= argc) break; ... }
Argv(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "argv"
    /\ IF i[t] < ArgvMax /\ i[t] < argc[t]
         THEN /\ Go(t, "argv") /\ i' = [i EXCEPT ![t] = i[t] + 1]
         ELSE /\ Go(t, "commit") /\ UNCHANGED i
    /\ UNCHANGED <<agent, attached, hpc, op, argc, sock, key, used, mapKeys, live, skStore>>

\* commit(): store-release head
Commit(t) ==
    /\ hpc[t] = "prog" /\ ppc[t] = "commit"
    /\ used' = [used EXCEPT ![t] = used[t] + 1]
    /\ Ret(t)
    /\ UNCHANGED <<agent, attached, op, i, argc, sock, key, mapKeys, live, skStore>>

HStep(t) == HStart(t) \/ HFinish(t) \/ Storage(t) \/ SeenLoop(t) \/ Insert(t)
            \/ Lookup(t) \/ MapIns(t) \/ Reserve(t) \/ Argv(t) \/ Commit(t)

\* Program steps only (for the step-bound and never-blocks checks).
PStep(t) == Storage(t) \/ SeenLoop(t) \/ Insert(t) \/ Lookup(t) \/ MapIns(t)
            \/ Reserve(t) \/ Argv(t) \/ Commit(t)

(***************************************************************************)
(* Agent                                                                   *)
(***************************************************************************)
Consume(t) ==
    /\ agent = "running" /\ used[t] > 0
    /\ used' = [used EXCEPT ![t] = 0]
    /\ UNCHANGED <<agent, attached, tvars, mapKeys, live, skStore>>

Stall ==
    /\ agent = "running"
    /\ agent' = "stalled"
    /\ UNCHANGED <<attached, tvars, used, mapKeys, live, skStore>>

\* Process exit closes the link fds: the programs detach.  Invocations
\* already running finish (the trampoline image is reference counted).
Die ==
    /\ agent # "dead"
    /\ agent' = "dead" /\ attached' = FALSE
    /\ UNCHANGED <<tvars, used, mapKeys, live, skStore>>

AgentStep == Stall \/ Die \/ \E t \in Threads : Consume(t)

Next == \/ AgentStep
        \/ \E t \in Threads : HStep(t)
        \/ \E s \in Socks : SockOpen(s) \/ SockClose(s)

\* Fairness for host threads only: the agent may stop at any point forever.
Spec == Init /\ [][Next]_vars /\ \A t \in Threads : WF_vars(HStep(t))

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
StepBound == \A t \in Threads : steps[t] <= MaxSteps(op[t])

NeverBlocks ==
    \A t \in Threads : hpc[t] # "idle" => ENABLED HStep(t)

StateBounded ==
    /\ \A t \in Threads : used[t] \in 0..RingSize
    /\ Cardinality(mapKeys) <= MapMax
    /\ skStore \subseteq live

DetachedRunsNothing ==
    agent = "dead" => ~attached

\* Every host operation completes, whatever the agent does.
HostProgress == \A t \in Threads : []<>(hpc[t] = "idle")
=============================================================================
