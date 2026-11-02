---------------------------- MODULE FileCoalesce ----------------------------
(***************************************************************************)
(* Sensitive-file coalescing with explicit deletion (a812964):             *)
(* on_inotify_event on several CPUs, the file_seen hash (no prealloc, no   *)
(* LRU), and the file_flush iterator.  An element's jiffies is a window    *)
(* start (live), FILE_DEAD or FILE_GONE.  A visit that finds a live window  *)
(* expired marks it DEAD; a hook that finds DEAD revives it with a new      *)
(* window; a later visit that still finds DEAD marks it GONE, swaps out the *)
(* count and deletes the key; a hook that finds GONE emits a full record    *)
(* and changes nothing; a visit that finds GONE (a failed delete) deletes   *)
(* again.                                                                   *)
(*                                                                         *)
(* The repeats counter of each element is modeled as the SET of event ids  *)
(* added to it; its value is the cardinality.  Elements have identity      *)
(* because a deleted element may be reused for another insert while a hook *)
(* on another CPU still holds a pointer to it (Reuse).                     *)
(* A hook's map section runs with preemption disabled, so it interleaves   *)
(* only with other CPUs; the model lets every step interleave, which only  *)
(* adds behaviors.                                                         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    CPUs,       \* CPUs running on_inotify_event
    Keys,       \* file_key values
    Nodes,      \* element memory the allocator may hand out
    MaxEntries, \* max_entries of file_seen
    W,          \* file_window in jiffies
    P,          \* a complete iterator pass starts at least every P jiffies
    TMax,       \* last jiffy of the run
    E,          \* events per CPU
    MaxDelay,   \* jiffies an invocation may lag behind the now it read
    Reuse,      \* TRUE: a deleted element can be reused at once; FALSE: never during the run
    RingDrops,  \* TRUE: a ring reserve may fail (a counted drop)
    DelFails,   \* bpf_map_delete_elem may fail this many times during the run
    Exempt      \* kinds of full record that RecordsPerWindow does not count

Kinds == {"ins", "open", "race", "eexist", "sat", "lost", "gone", "stale"}

ASSUME /\ CPUs # {} /\ Keys # {} /\ Nodes # {}
       /\ MaxEntries \in Nat /\ W \in Nat \ {0} /\ P \in Nat \ {0}
       /\ TMax \in Nat /\ E \in Nat /\ MaxDelay \in Nat
       /\ Reuse \in BOOLEAN /\ RingDrops \in BOOLEAN /\ DelFails \in Nat
       /\ Exempt \subseteq Kinds

None == "none"
DEAD == -1                  \* FILE_DEAD = (u64)-1
GONE == -2                  \* FILE_GONE = (u64)-2
Live(j) == j >= 0           \* j < FILE_GONE, i.e. a window start
Ids == CPUs \X (1..E)
NoOpen == -1               \* ro: no other hook opened a window

VARIABLES
    now,
    nkey, nj, nrep,         \* element memory: key, value.jiffies, value.repeats
    wst,                    \* ghost: last window start an element held
    linked,                 \* hash table: key -> element (or None)
    fresh,                  \* elements never handed out
    freed,                  \* deleted elements the allocator may hand out again
    pc, ev, k, t, id, sn, jl,             \* per-CPU hook state
    kd, ro, near,                         \* per-CPU ghost: record kind, opener seen, window
    fpc, pass, fn, fkey, fnow, fj, fgone, passStart, lastDone, \* iterator
    keyOf, recs, iflush, late, dropped, drops, destroyed, done, \* ghost
    lastRef, kold, extra, nfail

cpuvars == <<pc, ev, k, t, id, sn, jl, kd, ro, near>>
fvars == <<fpc, pass, fn, fkey, fnow, fj, fgone, passStart, lastDone>>
mvars == <<nkey, nj, nrep, wst, linked, fresh, freed>>
gvars == <<keyOf, recs, iflush, late, dropped, drops, destroyed, done,
           lastRef, kold, extra, nfail>>
vars == <<now, mvars, cpuvars, fvars, gvars>>

Init ==
    /\ now = 0
    /\ nkey = [n \in Nodes |-> None] /\ nj = [n \in Nodes |-> 0]
    /\ nrep = [n \in Nodes |-> {}] /\ wst = [n \in Nodes |-> 0]
    /\ linked = [x \in Keys |-> None] /\ fresh = Nodes /\ freed = {}
    /\ pc = [c \in CPUs |-> "idle"] /\ ev = [c \in CPUs |-> 0]
    /\ k = [c \in CPUs |-> None] /\ t = [c \in CPUs |-> 0]
    /\ id = [c \in CPUs |-> <<c, 0>>] /\ sn = [c \in CPUs |-> None]
    /\ jl = [c \in CPUs |-> 0] /\ kd = [c \in CPUs |-> None]
    /\ ro = [c \in CPUs |-> NoOpen] /\ near = [c \in CPUs |-> FALSE]
    /\ fpc = "idle" /\ pass = {} /\ fn = None /\ fkey = None /\ fnow = 0
    /\ fj = 0 /\ fgone = FALSE /\ passStart = 0 /\ lastDone = 0
    /\ keyOf = [i \in Ids |-> None]
    /\ recs = {} /\ iflush = {} /\ late = {} /\ dropped = {} /\ drops = 0
    /\ destroyed = {} /\ done = {}
    /\ lastRef = [x \in Keys |-> -W] /\ kold = [x \in Keys |-> -W]
    /\ extra = {} /\ nfail = 0

IsLinked(n) == \E x \in Keys : linked[x] = n
Linked == {n \in Nodes : IsLinked(n)}
Goto(c, p) == pc' = [pc EXCEPT ![c] = p]

\* (s64)(now - j) < (s64)file_window
InWindow(t0, j) == t0 - j < W

\* The hook returns; its locals are cleared so that idle CPUs compare equal.
Finish(c) ==
    /\ pc' = [pc EXCEPT ![c] = "idle"]
    /\ k' = [k EXCEPT ![c] = None] /\ t' = [t EXCEPT ![c] = 0]
    /\ id' = [id EXCEPT ![c] = <<c, 0>>] /\ sn' = [sn EXCEPT ![c] = None]
    /\ jl' = [jl EXCEPT ![c] = 0] /\ kd' = [kd EXCEPT ![c] = None]
    /\ ro' = [ro EXCEPT ![c] = NoOpen] /\ near' = [near EXCEPT ![c] = FALSE]

\* Ghost: hook c opens a window for key x at t[c]; every other hook on x
\* that has read the state it will act on, and has not yet acted, notes it.
Opened(c, x) ==
    ro' = [d \in CPUs |-> IF d # c /\ pc[d] \in {"cas", "insert"} /\ k[d] = x
                                /\ ro[d] = NoOpen
                             THEN t[c] ELSE ro[d]]

\* jiffies advance while every running invocation lags at most MaxDelay and
\* a complete iterator pass has started within the last P jiffies.
Tick ==
    /\ now < TMax
    /\ \A c \in CPUs : pc[c] # "idle" => now + 1 - t[c] <= MaxDelay
    /\ now + 1 - lastDone <= P
    /\ now' = now + 1
    /\ UNCHANGED <<mvars, cpuvars, fvars, gvars>>

(***************************************************************************)
(* on_inotify_event                                                        *)
(***************************************************************************)
\* now = bpf_jiffies64(); build k.  Ghost: near says whether this event falls
\* within W of the window of an earlier counted full record of its key.
Begin(c) ==
    /\ pc[c] = "idle" /\ ev[c] < E
    /\ \E x \in Keys :
         LET i == <<c, ev[c] + 1>> IN
         /\ k' = [k EXCEPT ![c] = x]
         /\ id' = [id EXCEPT ![c] = i]
         /\ keyOf' = [keyOf EXCEPT ![i] = x]
         /\ near' = [near EXCEPT ![c] = now < lastRef[x] + W]
    /\ ev' = [ev EXCEPT ![c] = ev[c] + 1]
    /\ t' = [t EXCEPT ![c] = now]
    /\ Goto(c, "lookup")
    /\ UNCHANGED <<now, mvars, sn, jl, kd, ro, fvars, recs, iflush, late, dropped,
                   drops, destroyed, done, lastRef, kold, extra, nfail>>

\* seen = bpf_map_lookup_elem(&file_seen, &k).  Ghost: a hook that finds the
\* key absent notes whether its clock lies inside the last window of the
\* key's last deleted element (kd = "stale" until it acts).
Lookup(c) ==
    /\ pc[c] = "lookup"
    /\ sn' = [sn EXCEPT ![c] = linked[k[c]]]
    /\ IF linked[k[c]] # None
         THEN /\ Goto(c, "readj") /\ UNCHANGED kd
         ELSE /\ Goto(c, "insert")
              /\ kd' = [kd EXCEPT ![c] = IF t[c] < kold[k[c]] + W THEN "stale" ELSE None]
    /\ UNCHANGED <<now, mvars, ev, k, t, id, jl, ro, near, fvars, gvars>>

\* j = READ_ONCE(seen->jiffies); live and inside the window -> add;
\* FILE_GONE -> full record; otherwise (expired or FILE_DEAD) -> cas.
\* Ghost: a hook that reads FILE_DEAD notes whether its clock lies inside
\* the window the iterator expired (kd = "stale" until it acts).
ReadJ(c) ==
    /\ pc[c] = "readj"
    /\ LET j == nj[sn[c]] IN
       IF Live(j) /\ InWindow(t[c], j)
         THEN /\ Goto(c, "add") /\ UNCHANGED <<jl, kd>>
       ELSE IF j = GONE
         THEN /\ Goto(c, "emit") /\ kd' = [kd EXCEPT ![c] = "gone"] /\ UNCHANGED jl
       ELSE /\ Goto(c, "cas") /\ jl' = [jl EXCEPT ![c] = j]
            /\ kd' = [kd EXCEPT ![c] = IF j = DEAD /\ t[c] < wst[sn[c]] + W
                                       THEN "stale" ELSE None]
    /\ UNCHANGED <<now, mvars, ev, k, t, id, sn, ro, near, fvars, gvars>>

\* n = __sync_fetch_and_add(&seen->repeats, 1)
Add(c) ==
    /\ pc[c] = "add"
    /\ nrep' = [nrep EXCEPT ![sn[c]] = @ \cup {id[c]}]
    /\ done' = done \cup {id[c]}
    /\ Goto(c, "chk")
    /\ UNCHANGED <<now, nkey, nj, wst, linked, fresh, freed, ev, k, t, id, sn, jl, kd,
                   ro, near, fvars, keyOf, recs, iflush, late, dropped, drops, destroyed,
                   lastRef, kold, extra, nfail>>

\* if (READ_ONCE(seen->jiffies) >= FILE_GONE && ...)
Chk(c) ==
    /\ pc[c] = "chk"
    /\ IF nj[sn[c]] \in {DEAD, GONE}
         THEN /\ Goto(c, "lxchg")
              /\ UNCHANGED <<k, t, id, sn, jl, kd, ro, near>>
         ELSE Finish(c)
    /\ UNCHANGED <<now, mvars, ev, fvars, gvars>>

\* ... (n = xchg(&seen->repeats, 0))) a repeat record (key k, count n); the
\* ring reserve may fail, which counts a drop.
LXchg(c) ==
    /\ pc[c] = "lxchg"
    /\ LET cnt == nrep[sn[c]] IN
       /\ nrep' = [nrep EXCEPT ![sn[c]] = {}]
       /\ IF cnt = {}
            THEN UNCHANGED <<late, dropped, drops>>
            ELSE \/ /\ late' = late \cup {<<e, k[c]>> : e \in cnt}
                    /\ UNCHANGED <<dropped, drops>>
                 \/ /\ RingDrops
                    /\ dropped' = dropped \cup cnt /\ drops' = drops + 1
                    /\ UNCHANGED late
    /\ Finish(c)
    /\ UNCHANGED <<now, nkey, nj, wst, linked, fresh, freed, ev, fvars,
                   keyOf, recs, iflush, destroyed, done, lastRef, kold, extra, nfail>>

\* if (j != FILE_GONE) __sync_val_compare_and_swap(&seen->jiffies, j, now);
\* result ignored, then a full record.  Ghost kind: "open" if the CAS
\* succeeded; "race" if it failed and another hook opened a window for the
\* key since the read; "lost" if it failed and only the iterator wrote;
\* "stale" instead of "open" or "race" if ReadJ found the hook's clock
\* inside the window the iterator expired.
Cas(c) ==
    /\ pc[c] = "cas"
    /\ LET n == sn[c]
           st == kd[c] = "stale"
       IN
       IF nj[n] = jl[c]
         THEN /\ nj' = [nj EXCEPT ![n] = t[c]]
              /\ wst' = [wst EXCEPT ![n] = t[c]]
              /\ kd' = [kd EXCEPT ![c] = IF st THEN "stale" ELSE "open"]
              /\ Opened(c, k[c])
         ELSE /\ UNCHANGED <<nj, wst, ro>>
              /\ kd' = [kd EXCEPT ![c] = IF ro[c] = NoOpen THEN "lost"
                                         ELSE IF st THEN "stale" ELSE "race"]
    /\ Goto(c, "emit")
    /\ UNCHANGED <<now, nkey, nrep, linked, fresh, freed, ev, k, t, id, sn, jl, near,
                   fvars, gvars>>

\* bpf_map_update_elem(&file_seen, &k, &fresh, BPF_NOEXIST) under the bucket
\* lock: -EEXIST if present; -E2BIG if the map is full; -ENOMEM if the
\* allocator has nothing; else a new (possibly reused) element is filled and
\* linked.  Any failure but -EEXIST sets FLAG_SATURATED on the full record.
\* Never-used elements differ only in whether the current pass may still
\* reach them, so one of each kind is offered, and every freed element.
\* Ghost kind "stale" instead of "ins" or "eexist" if Lookup found the hook's
\* clock inside the last window of the key's last deleted element.
First(S) == IF S = {} THEN {} ELSE {CHOOSE n \in S : TRUE}
Alloc == First(fresh \cap pass) \cup First(fresh \ pass) \cup freed

Insert(c) ==
    /\ pc[c] = "insert"
    /\ Goto(c, "emit")
    /\ LET x == k[c]
           st == kd[c] = "stale"
       IN
       IF linked[x] # None
         THEN /\ kd' = [kd EXCEPT ![c] = IF st THEN "stale" ELSE "eexist"]
              /\ UNCHANGED <<mvars, ro, destroyed>>
       ELSE IF Cardinality(Linked) >= MaxEntries \/ fresh \cup freed = {}
         THEN /\ kd' = [kd EXCEPT ![c] = "sat"]
              /\ UNCHANGED <<mvars, ro, destroyed>>
       ELSE \E n \in Alloc :
              /\ fresh' = fresh \ {n} /\ freed' = freed \ {n}
              /\ destroyed' = destroyed \cup nrep[n]
              /\ nkey' = [nkey EXCEPT ![n] = x]
              /\ nj' = [nj EXCEPT ![n] = t[c]]
              /\ wst' = [wst EXCEPT ![n] = t[c]]
              /\ nrep' = [nrep EXCEPT ![n] = {}]
              /\ linked' = [linked EXCEPT ![x] = n]
              /\ kd' = [kd EXCEPT ![c] = IF st THEN "stale" ELSE "ins"]
              /\ Opened(c, x)
    /\ UNCHANGED <<now, ev, k, t, id, sn, jl, near, fvars, keyOf, recs, iflush, late,
                   dropped, drops, done, lastRef, kold, extra, nfail>>

\* full REC_FILE record (FLAG_SATURATED for kind "sat"); the ring reserve may
\* fail, which counts a drop.  Ghost: a counted record that falls within W
\* of the window of an earlier counted full record of its key, emitted
\* before this hook began, goes to extra; the window this record belongs to
\* (its own, or the one it raced with) becomes the key's latest.
Emit(c) ==
    /\ pc[c] = "emit"
    /\ LET x == k[c]
           counted == kd[c] \notin Exempt
           ref == IF kd[c] \in {"race", "eexist"} THEN ro[c] ELSE t[c]
       IN
       /\ \/ /\ recs' = recs \cup {<<id[c], x, t[c], kd[c]>>}
             /\ UNCHANGED <<dropped, drops>>
          \/ /\ RingDrops
             /\ dropped' = dropped \cup {id[c]} /\ drops' = drops + 1
             /\ UNCHANGED recs
       /\ extra' = IF counted /\ near[c] THEN extra \cup {id[c]} ELSE extra
       /\ lastRef' = IF counted /\ ref > lastRef[x]
                       THEN [lastRef EXCEPT ![x] = ref] ELSE lastRef
    /\ done' = done \cup {id[c]}
    /\ Finish(c)
    /\ UNCHANGED <<now, mvars, ev, fvars, keyOf, iflush, late, destroyed, kold, nfail>>

(***************************************************************************)
(* file_flush                                                              *)
(***************************************************************************)
FStart ==
    /\ fpc = "idle" /\ pass = {} /\ passStart = lastDone
    /\ pass' = Nodes /\ passStart' = now /\ fpc' = "pick"
    /\ UNCHANGED <<now, mvars, cpuvars, fn, fkey, fnow, fj, fgone, lastDone, gvars>>

\* The pass reaches an element: now = bpf_jiffies64(); r.k = *k.  An
\* element that is not linked is passed over, so an element linked during
\* the pass may or may not be visited by it.  Of the never-used elements only
\* one is offered (they are interchangeable); deleted elements that the
\* allocator never hands out again are left out.  The pass ends once no
\* linked or reusable element is left in it.
Reachable == (pass \cap (Linked \cup freed)) \cup First(pass \cap fresh)

FPick ==
    /\ fpc = "pick"
    /\ \E n \in Reachable :
         /\ pass' = pass \ {n}
         /\ IF IsLinked(n)
              THEN /\ fn' = n /\ fkey' = nkey[n] /\ fnow' = now /\ fpc' = "read"
              ELSE /\ UNCHANGED <<fn, fkey, fnow>> /\ fpc' = "pick"
    /\ UNCHANGED <<now, mvars, cpuvars, fj, fgone, passStart, lastDone, gvars>>

FDone ==
    /\ fpc = "pick" /\ pass \cap (Linked \cup freed) = {}
    /\ fpc' = "idle" /\ pass' = {} /\ lastDone' = passStart
    /\ UNCHANGED <<now, mvars, cpuvars, fn, fkey, fnow, fj, fgone, passStart, gvars>>

\* j = READ_ONCE(v->jiffies); FILE_GONE -> gone; FILE_DEAD -> cas to
\* FILE_GONE; live and expired (signed) -> cas to FILE_DEAD
FRead ==
    /\ fpc = "read"
    /\ LET j == nj[fn] IN
       IF j = GONE THEN /\ fgone' = TRUE /\ fpc' = "xchg" /\ UNCHANGED fj
       ELSE IF j = DEAD THEN /\ fpc' = "gcas" /\ UNCHANGED <<fj, fgone>>
       ELSE IF ~InWindow(fnow, j) THEN /\ fj' = j /\ fpc' = "cas" /\ UNCHANGED fgone
       ELSE /\ fpc' = "xchg" /\ UNCHANGED <<fj, fgone>>
    /\ UNCHANGED <<now, mvars, cpuvars, pass, fn, fkey, fnow, passStart, lastDone, gvars>>

\* gone = cas(&v->jiffies, FILE_DEAD, FILE_GONE) == FILE_DEAD
FGCas ==
    /\ fpc = "gcas"
    /\ IF nj[fn] = DEAD
         THEN /\ nj' = [nj EXCEPT ![fn] = GONE] /\ fgone' = TRUE
         ELSE UNCHANGED <<nj, fgone>>
    /\ fpc' = "xchg"
    /\ UNCHANGED <<now, nkey, nrep, wst, linked, fresh, freed, cpuvars, pass, fn, fkey,
                   fnow, fj, passStart, lastDone, gvars>>

\* cas(&v->jiffies, j, FILE_DEAD), result ignored
FCas ==
    /\ fpc = "cas"
    /\ nj' = IF nj[fn] = fj THEN [nj EXCEPT ![fn] = DEAD] ELSE nj
    /\ fpc' = "xchg"
    /\ UNCHANGED <<now, nkey, nrep, wst, linked, fresh, freed, cpuvars, pass, fn, fkey,
                   fnow, fj, fgone, passStart, lastDone, gvars>>

\* Back to the pass; the visit's locals are cleared.
FNext ==
    /\ fpc' = "pick" /\ fn' = None /\ fkey' = None /\ fnow' = 0 /\ fj' = 0
    /\ fgone' = FALSE

\* r.count = xchg(&v->repeats, 0); repeat record with the key copied at the start
FXchg ==
    /\ fpc = "xchg"
    /\ iflush' = iflush \cup {<<e, fkey>> : e \in nrep[fn]}
    /\ nrep' = [nrep EXCEPT ![fn] = {}]
    /\ IF fgone THEN /\ fpc' = "del" /\ UNCHANGED <<fn, fkey, fnow, fj, fgone>>
                ELSE FNext
    /\ UNCHANGED <<now, nkey, nj, wst, linked, fresh, freed, cpuvars, pass,
                   passStart, lastDone, keyOf, recs, late, dropped, drops, destroyed,
                   done, lastRef, kold, extra, nfail>>

\* if (gone) bpf_map_delete_elem(&file_seen, &r.k); with Reuse the element
\* goes back to the allocator.  The delete may fail (DelFails times), which
\* leaves the element linked with FILE_GONE for the next pass.
FDel ==
    /\ fpc = "del"
    /\ LET n == linked[fkey] IN
       \/ /\ linked' = [linked EXCEPT ![fkey] = None]
          /\ freed' = IF Reuse /\ n # None THEN freed \cup {n} ELSE freed
          /\ kold' = IF n # None THEN [kold EXCEPT ![fkey] = wst[n]] ELSE kold
          /\ UNCHANGED nfail
       \/ /\ nfail < DelFails /\ nfail' = nfail + 1
          /\ UNCHANGED <<linked, freed, kold>>
    /\ FNext
    /\ UNCHANGED <<now, nkey, nj, nrep, wst, fresh, cpuvars, pass, passStart, lastDone,
                   keyOf, recs, iflush, late, dropped, drops, destroyed, done, lastRef,
                   extra>>

CPUStep(c) == Begin(c) \/ Lookup(c) \/ ReadJ(c) \/ Add(c) \/ Chk(c) \/ LXchg(c)
              \/ Cas(c) \/ Insert(c) \/ Emit(c)
Flusher == FStart \/ FPick \/ FDone \/ FRead \/ FGCas \/ FCas \/ FXchg \/ FDel

Next == Tick \/ Flusher \/ \E c \in CPUs : CPUStep(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
RecIds == {r[1] : r \in recs}
FlushIds == {f[1] : f \in iflush}
LateIds == {f[1] : f \in late}
PendIds == UNION {nrep[n] : n \in Linked}
LimboIds == UNION {nrep[n] : n \in Nodes \ Linked}

\* Every finished event is exactly one of: full record, iterator repeat,
\* late repeat, in a dropped record (counted in drops), pending in a linked
\* element, held in an unlinked element, destroyed by an element's reuse.
ExactlyOnce ==
    /\ done = RecIds \cup FlushIds \cup LateIds \cup dropped \cup PendIds
              \cup LimboIds \cup destroyed
    /\ Cardinality(recs) = Cardinality(RecIds)
    /\ Cardinality(iflush) = Cardinality(FlushIds)
    /\ Cardinality(late) = Cardinality(LateIds)
    /\ RecIds \cap (FlushIds \cup LateIds \cup dropped \cup PendIds \cup LimboIds
                    \cup destroyed) = {}
    /\ FlushIds \cap (LateIds \cup dropped \cup PendIds \cup LimboIds \cup destroyed) = {}
    /\ LateIds \cap (dropped \cup PendIds \cup LimboIds \cup destroyed) = {}
    /\ dropped \cap (PendIds \cup LimboIds \cup destroyed) = {}
    /\ PendIds \cap (LimboIds \cup destroyed) = {}
    /\ LimboIds \cap destroyed = {}
    /\ \A n, m \in Nodes : n # m => nrep[n] \cap nrep[m] = {}
    /\ drops <= Cardinality(dropped) /\ (drops = 0) = (dropped = {})

\* No count is lost: nothing is destroyed, and a count sits in an unlinked
\* element only while the hook that added it has still to check jiffies.
NoLoss ==
    /\ destroyed = {}
    /\ \A e \in LimboIds : \E c \in CPUs : id[c] = e /\ pc[c] \in {"chk", "lxchg"}

\* Every count is reported, or pending, under the key of its event.
AttributionCorrect ==
    /\ \A f \in iflush \cup late : keyOf[f[1]] = f[2]
    /\ \A x \in Keys : linked[x] # None => \A e \in nrep[linked[x]] : keyOf[e] = x

\* The map holds at most max_entries elements, one per key; a live element's
\* window started within the last W + P jiffies, and an element marked DEAD or
\* GONE had its last window start within the last W + 2P jiffies (one more
\* period per failed delete).
TableBounded ==
    /\ Cardinality(Linked) <= MaxEntries
    /\ \A x, y \in Keys : (x # y /\ linked[x] # None) => linked[x] # linked[y]
    /\ \A n \in Linked :
         /\ Live(nj[n]) => now < nj[n] + W + P
         /\ nj[n] = DEAD => now < wst[n] + W + 2 * P
         /\ nj[n] = GONE => now < wst[n] + W + (2 + nfail) * P

\* No counted full record falls within W of the window of an earlier counted
\* full record of the same key whose record was emitted before its hook
\* began.  Records of hooks that overlap in time are not compared: CPUs that
\* find the same key absent or expired at once each emit one.
RecordsPerWindow == extra = {}

\* Witnesses
NoSaturated == \A r \in recs : r[4] # "sat"
NoLateRepeat == late = {}
\* The bound of the two-state lifecycle: every element is gone W + P jiffies
\* after its last window start.
DeletedWithinWP == \A n \in Linked : now < wst[n] + W + P
=============================================================================
