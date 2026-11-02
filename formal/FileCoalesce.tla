---------------------------- MODULE FileCoalesce ----------------------------
(***************************************************************************)
(* Sensitive-file coalescing: on_inotify_event on several CPUs, the        *)
(* file_seen LRU hash, and the file_flush map-element iterator run by the  *)
(* agent.  agent.bpf.c on_inotify_event / file_flush; hashtab.c LRU paths. *)
(*                                                                         *)
(* The repeats counter is modeled as the SET of event ids added to it, so  *)
(* the fate of every event can be followed; its value is the cardinality.  *)
(* LRU elements are modeled as nodes with identity because the kernel      *)
(* recycles an LRU element immediately (no RCU grace period): a value      *)
(* pointer returned by lookup may point to a node that has since been      *)
(* unlinked, freed, or reused for another key.                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    CPUs,       \* CPUs running on_inotify_event concurrently
    Keys,       \* file_key values (process, exec id, inode, child, mask)
    Nodes,      \* preallocated LRU elements (max_entries)
    W,          \* file_window in jiffies
    TMax,       \* last jiffy of the run
    E,          \* events per CPU
    Flag,       \* "NOEXIST" (code) or "ANY"
    MaxDelay,   \* ticks a CPU may lag between reading now and its last use of it
    SignedCmp,  \* TRUE: (__s64)(now - jiffies) < (__s64)file_window (0d3aadc); FALSE: u64 (pre-fix)
    RecBound    \* claimed bound on full records per key per window

ASSUME /\ CPUs # {} /\ Keys # {} /\ Nodes # {}
       /\ W \in Nat \ {0} /\ TMax \in Nat /\ E \in Nat
       /\ Flag \in {"NOEXIST", "ANY"} /\ MaxDelay \in Nat /\ RecBound \in Nat
       /\ SignedCmp \in BOOLEAN

None == "none"
Ids == CPUs \X (1..E)

VARIABLES
    now,        \* jiffies
    nkey, nj, nrep,   \* node memory: key, value.jiffies, value.repeats
    linked,     \* hash table: key -> node linked for it (or None)
    free,       \* LRU free list
    cause,      \* ghost: why each node last left the table ("evict" / "replace")
    pc, ev, k, t, id, sn, nn,   \* per-CPU program state
    fpc, fnode, fset,           \* flush iterator (agent)
    keyOf,      \* ghost: key of each event
    recs,       \* ghost: full records <<id, key, now>>
    flushed,    \* ghost: <<id, key reported by the repeat record>>
    destroyed,  \* ghost: <<id, cause>> counts wiped by a value copy
    done,       \* ghost: events whose program finished
    uflow       \* ghost: a CPU treated the window as expired because now - jiffies wrapped

cpuvars == <<pc, ev, k, t, id, sn, nn>>
fvars == <<fpc, fnode, fset>>
mvars == <<nkey, nj, nrep, linked, free, cause>>
gvars == <<keyOf, recs, flushed, destroyed, done, uflow>>
vars == <<now, mvars, cpuvars, fvars, gvars>>

Init ==
    /\ now = 0
    /\ nkey = [n \in Nodes |-> None] /\ nj = [n \in Nodes |-> 0]
    /\ nrep = [n \in Nodes |-> {}]
    /\ linked = [x \in Keys |-> None] /\ free = Nodes
    /\ cause = [n \in Nodes |-> "none"]
    /\ pc = [c \in CPUs |-> "idle"] /\ ev = [c \in CPUs |-> 0]
    /\ k = [c \in CPUs |-> None] /\ t = [c \in CPUs |-> 0]
    /\ id = [c \in CPUs |-> <<c, 0>>]
    /\ sn = [c \in CPUs |-> None] /\ nn = [c \in CPUs |-> None]
    /\ fpc = "idle" /\ fnode = None /\ fset = {}
    /\ keyOf = [i \in Ids |-> None]
    /\ recs = {} /\ flushed = {} /\ destroyed = {} /\ done = {} /\ uflow = FALSE

IsLinked(n) == \E x \in Keys : linked[x] = n

\* jiffies advance; a running invocation lags at most MaxDelay ticks behind
\* the now it read (a program may be interrupted or, outside
\* bpf_preempt_disable, preempted).
Tick ==
    /\ now < TMax
    /\ \A c \in CPUs : pc[c] # "idle" => now + 1 - t[c] <= MaxDelay
    /\ now' = now + 1
    /\ UNCHANGED <<mvars, cpuvars, fvars, gvars>>

Goto(c, p) == pc' = [pc EXCEPT ![c] = p]

(***************************************************************************)
(* on_inotify_event                                                        *)
(***************************************************************************)
\* now = bpf_jiffies64(); build k
Begin(c) ==
    /\ pc[c] = "idle" /\ ev[c] < E
    /\ \E x \in Keys :
         LET i == <<c, ev[c] + 1>> IN
         /\ k' = [k EXCEPT ![c] = x]
         /\ id' = [id EXCEPT ![c] = i]
         /\ keyOf' = [keyOf EXCEPT ![i] = x]
    /\ ev' = [ev EXCEPT ![c] = ev[c] + 1]
    /\ t' = [t EXCEPT ![c] = now]
    /\ Goto(c, "lookup")
    /\ UNCHANGED <<now, mvars, sn, nn, fvars, recs, flushed, destroyed, done, uflow>>

\* seen = bpf_map_lookup_elem(&file_seen, &k)
Lookup(c) ==
    /\ pc[c] = "lookup"
    /\ sn' = [sn EXCEPT ![c] = linked[k[c]]]
    /\ Goto(c, IF linked[k[c]] # None THEN "readj" ELSE "pop")
    /\ UNCHANGED <<now, mvars, ev, k, t, id, nn, fvars, gvars>>

\* Window test.  Signed: a stored jiffies ahead of this CPU's now counts as
\* inside the window.  Unsigned (pre-fix): now - jiffies wraps and counts as
\* expired.
InWindow(now0, j) == IF SignedCmp THEN now0 - j < W ELSE now0 >= j /\ now0 - j < W

ReadJ(c) ==
    /\ pc[c] = "readj"
    /\ LET j == nj[sn[c]] IN
       /\ Goto(c, IF InWindow(t[c], j) THEN "add" ELSE "setj")
       /\ uflow' = (uflow \/ (~InWindow(t[c], j) /\ t[c] < j))
    /\ UNCHANGED <<now, mvars, ev, k, t, id, sn, nn, fvars, keyOf, recs, flushed, destroyed, done>>

\* __sync_fetch_and_add(&seen->repeats, 1)
Add(c) ==
    /\ pc[c] = "add"
    /\ nrep' = [nrep EXCEPT ![sn[c]] = @ \cup {id[c]}]
    /\ done' = done \cup {id[c]}
    /\ Goto(c, "idle")
    /\ UNCHANGED <<now, nkey, nj, linked, free, cause, ev, k, t, id, sn, nn, fvars,
                   keyOf, recs, flushed, destroyed, uflow>>

\* seen->jiffies = now (window expired)
SetJ(c) ==
    /\ pc[c] = "setj"
    /\ nj' = [nj EXCEPT ![sn[c]] = t[c]]
    /\ Goto(c, "emit")
    /\ UNCHANGED <<now, nkey, nrep, linked, free, cause, ev, k, t, id, sn, nn, fvars, gvars>>

\* bpf_map_update_elem(..., flag): prealloc_lru_pop() takes a free element or
\* evicts one from the table (htab_lru_map_delete_node), then copies the key.
Pop(c) ==
    /\ pc[c] = "pop"
    /\ IF free # {}
         THEN \E n \in free :
                /\ free' = free \ {n}
                /\ nkey' = [nkey EXCEPT ![n] = k[c]]
                /\ nn' = [nn EXCEPT ![c] = n]
                /\ Goto(c, "copyval")
                /\ UNCHANGED <<linked, cause>>
         ELSE IF \E n \in Nodes : IsLinked(n)
           THEN \E n \in Nodes :
                  /\ IsLinked(n)
                  /\ linked' = [x \in Keys |-> IF linked[x] = n THEN None ELSE linked[x]]
                  /\ cause' = [cause EXCEPT ![n] = "evict"]
                  /\ nkey' = [nkey EXCEPT ![n] = k[c]]
                  /\ nn' = [nn EXCEPT ![c] = n]
                  /\ Goto(c, "copyval")
                  /\ UNCHANGED free
           ELSE \* every element is held by a concurrent insert: -ENOMEM
                /\ Goto(c, "emit")
                /\ UNCHANGED <<free, nkey, nn, linked, cause>>
    /\ UNCHANGED <<now, nj, nrep, ev, k, t, id, sn, fvars, gvars>>

\* copy_map_value(): fresh = {jiffies = now, repeats = 0}
CopyVal(c) ==
    /\ pc[c] = "copyval"
    /\ LET n == nn[c] IN
       /\ destroyed' = destroyed \cup {<<e, cause[n]>> : e \in nrep[n]}
       /\ nj' = [nj EXCEPT ![n] = t[c]]
       /\ nrep' = [nrep EXCEPT ![n] = {}]
    /\ Goto(c, "link")
    /\ UNCHANGED <<now, nkey, linked, free, cause, ev, k, t, id, sn, nn, fvars,
                   keyOf, recs, flushed, done, uflow>>

\* Under the bucket lock: check_flags(); link the new element; with BPF_ANY
\* unlink the old one; push the loser to the free list (htab_lru_push_free).
Link(c) ==
    /\ pc[c] = "link"
    /\ LET n == nn[c]
           old == linked[k[c]]
       IN IF old # None /\ Flag = "NOEXIST"
            THEN /\ free' = free \cup {n}                \* -EEXIST
                 /\ UNCHANGED <<linked, cause>>
            ELSE /\ linked' = [linked EXCEPT ![k[c]] = n]
                 /\ IF old # None
                      THEN /\ free' = free \cup {old}
                           /\ cause' = [cause EXCEPT ![old] = "replace"]
                      ELSE UNCHANGED <<free, cause>>
    /\ Goto(c, "emit")
    /\ UNCHANGED <<now, nkey, nj, nrep, ev, k, t, id, sn, nn, fvars, gvars>>

\* reserve()/commit() of the full record (the ring itself is Ring.tla)
Emit(c) ==
    /\ pc[c] = "emit"
    /\ recs' = recs \cup {<<id[c], k[c], t[c]>>}
    /\ done' = done \cup {id[c]}
    /\ Goto(c, "idle")
    /\ UNCHANGED <<now, mvars, ev, k, t, id, sn, nn, fvars, keyOf, flushed, destroyed, uflow>>

(***************************************************************************)
(* file_flush: bpf_map_elem iterator walking buckets under RCU only.       *)
(***************************************************************************)
FPick ==
    /\ fpc = "idle"
    /\ \E n \in Nodes : IsLinked(n) /\ fnode' = n
    /\ fpc' = "xchg"
    /\ UNCHANGED <<now, mvars, cpuvars, fset, gvars>>

\* if (!v->repeats) return; count = xchg(&v->repeats, 0)
FXchg ==
    /\ fpc = "xchg"
    /\ IF nrep[fnode] = {}
         THEN /\ fpc' = "idle" /\ UNCHANGED <<nrep, fset>>
         ELSE /\ fset' = nrep[fnode]
              /\ nrep' = [nrep EXCEPT ![fnode] = {}]
              /\ fpc' = "key"
    /\ UNCHANGED <<now, nkey, nj, linked, free, cause, cpuvars, fnode, gvars>>

\* r.k = *k (read after the xchg); bpf_seq_write
FKey ==
    /\ fpc = "key"
    /\ flushed' = flushed \cup {<<e, nkey[fnode]>> : e \in fset}
    /\ fpc' = "idle" /\ fset' = {}
    /\ UNCHANGED <<now, mvars, cpuvars, fnode, keyOf, recs, destroyed, done, uflow>>

CPUStep(c) == Begin(c) \/ Lookup(c) \/ ReadJ(c) \/ Add(c) \/ SetJ(c) \/ Pop(c) \/ CopyVal(c)
              \/ Link(c) \/ Emit(c)
Flusher == FPick \/ FXchg \/ FKey

Next == Tick \/ Flusher \/ \E c \in CPUs : CPUStep(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
RecIds == {r[1] : r \in recs}
FlushIds == {f[1] : f \in flushed}
PendIds == UNION {nrep[n] : n \in {m \in Nodes : IsLinked(m)}}
LimboIds == UNION {nrep[n] : n \in {m \in Nodes : ~IsLinked(m)}} \cup fset
DestIds == {d[1] : d \in destroyed}

\* Every finished event is exactly one of: full record, flushed repeat,
\* pending repeat, count held off-table, destroyed count.
ExactlyOnce ==
    /\ done = RecIds \cup FlushIds \cup PendIds \cup LimboIds \cup DestIds
    /\ Cardinality(recs) = Cardinality(RecIds)
    /\ Cardinality(flushed) = Cardinality(FlushIds)
    /\ RecIds \cap (FlushIds \cup PendIds \cup LimboIds \cup DestIds) = {}
    /\ FlushIds \cap (PendIds \cup LimboIds \cup DestIds) = {}
    /\ PendIds \cap (LimboIds \cup DestIds) = {}
    /\ LimboIds \cap DestIds = {}
    /\ \A n, m \in Nodes : n # m => nrep[n] \cap nrep[m] = {}

\* Counts leave the table only through LRU eviction.  (fset is the flusher's
\* private copy after xchg and is always reported.)
LossOnlyByEviction ==
    /\ \A d \in destroyed : d[2] = "evict"
    /\ \A n \in Nodes : (~IsLinked(n) /\ nrep[n] # {}) => cause[n] = "evict"

\* Every count is reported under the key of the event that produced it.
AttributionCorrect ==
    /\ \A f \in flushed : keyOf[f[1]] = f[2]
    /\ \A x \in Keys : linked[x] # None => \A e \in nrep[linked[x]] : keyOf[e] = x

\* Full records for one key within any window of W jiffies.
RecordsPerWindow ==
    \A x \in Keys, t0 \in 0..TMax :
        Cardinality({r \in recs : r[2] = x /\ t0 <= r[3] /\ r[3] < t0 + W}) <= RecBound

\* The table never exceeds max_entries; one element per key.
TableBounded ==
    /\ \A x, y \in Keys : (x # y /\ linked[x] # None) => linked[x] # linked[y]
    /\ Cardinality({x \in Keys : linked[x] # None}) <= Cardinality(Nodes)

\* A reset never moves a window start backwards (stale now or u64 underflow).
WindowNeverMovesBack == \A c \in CPUs : pc[c] = "setj" => t[c] >= nj[sn[c]]

\* No CPU ever treats a window as expired because its now is behind the stored
\* jiffies (the u64 wrap of the pre-fix test).
NoWrapExpiry == ~uflow

NoEviction == \A n \in Nodes : cause[n] # "evict"
=============================================================================
