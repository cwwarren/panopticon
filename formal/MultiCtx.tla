------------------------------ MODULE MultiCtx ------------------------------
(***************************************************************************)
(* Several execution contexts of ONE CPU producing into the same class     *)
(* ring: tasks, softirq, hardirq and NMI.  The nat class                   *)
(* (fexit/nf_nat_setup_info) runs in task and softirq context; the busy    *)
(* flag in reserve() is meant to turn any nested producer into a counted   *)
(* drop.                                                                   *)
(*                                                                         *)
(* Ring memory is abstracted to reservations [start, start + len); the     *)
(* byte-level protocol for a single producer is Ring.tla.  This module     *)
(* checks when the single-producer premise of Ring.tla holds.              *)
(*                                                                         *)
(* Mode "plain": all contexts share one ring, reserve()/commit() without   *)
(*               a busy flag (the code before the flag was added).         *)
(* Mode "busy":  shared ring with the per-ring busy flag, as reserve() and *)
(*               commit() do now for every class.                          *)
(* Mode "split": one ring per context kind (alternative design, unused).   *)
(* Nesting "linux": Linux nesting rules; "any": LIFO nesting in any order  *)
(*               at any step; "free": no nesting discipline at all, every  *)
(*               started invocation may step at any time.                  *)
(* SameProg:     every context runs the same fentry/fexit program, so the  *)
(*               BPF trampoline's per-program recursion guard applies.     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Ctx,          \* subset of {"T1", "T2", "S", "H", "N"}
    Mode,         \* "plain" | "busy" | "split"
    Nesting,      \* "linux" | "any" | "free"
    SameProg,     \* TRUE: one program for all contexts (trampoline recursion guard)
    AtomicBusy,   \* busy flag taken with xchg (TRUE, the code) or plain load + store (FALSE)
    AtomicDrops,  \* drop counter: atomic add (TRUE, the code) or load/add/store (FALSE)
    PreemptOff,   \* bpf_preempt_disable() spans reserve..commit
    Size, Max, Lens,
    E             \* invocations per context

ASSUME /\ Ctx \subseteq {"T1", "T2", "S", "H", "N"} /\ Ctx # {}
       /\ Mode \in {"plain", "busy", "split"}
       /\ Nesting \in {"linux", "any", "free"}
       /\ SameProg \in BOOLEAN /\ AtomicBusy \in BOOLEAN
       /\ AtomicDrops \in BOOLEAN /\ PreemptOff \in BOOLEAN
       /\ Size \in Nat \ {0} /\ Max \in 1..Size /\ Lens \subseteq 1..Max /\ Lens # {}
       /\ E \in Nat

Kind(c) == CASE c \in {"T1", "T2"} -> "task"
             [] c = "S" -> "softirq"
             [] c = "H" -> "hardirq"
             [] c = "N" -> "nmi"
RingOf(c) == IF Mode = "split" THEN Kind(c) ELSE "shared"
Rings == {RingOf(c) : c \in Ctx}
Events == Ctx \X (1..E)

VARIABLES
    stack,      \* contexts currently inside a hook on this CPU, in start order
    pc, ev, slot, len, tmp, holds, acc, steps,
    rsv, cmt,   \* ghost: this invocation reserved space / number of its commits
    head, tail, drops, busy,
    misses,     \* recursion misses counted by the kernel (bpf_prog_info.recursion_misses)
    committed, rStart, rLen, rRing,     \* ghost: records
    cdrops,     \* ghost: contention drops <<victim, holder, holder interrupted by victim>>
    nested      \* ghost: records committed while a context below held the ring

cvars == <<pc, ev, slot, len, tmp, holds, acc, steps, rsv, cmt>>
rvars == <<head, tail, drops, busy>>
gvars == <<misses, committed, rStart, rLen, rRing, cdrops, nested>>
vars == <<stack, cvars, rvars, gvars>>

Init ==
    /\ stack = <<>>
    /\ pc = [c \in Ctx |-> "idle"] /\ ev = [c \in Ctx |-> 0]
    /\ slot = [c \in Ctx |-> 0] /\ len = [c \in Ctx |-> 0] /\ tmp = [c \in Ctx |-> 0]
    /\ holds = [c \in Ctx |-> FALSE] /\ acc = [c \in Ctx |-> FALSE]
    /\ steps = [c \in Ctx |-> 0]
    /\ rsv = [c \in Ctx |-> FALSE] /\ cmt = [c \in Ctx |-> 0]
    /\ head = [r \in Rings |-> 0] /\ tail = [r \in Rings |-> 0]
    /\ drops = [r \in Rings |-> 0] /\ busy = [r \in Rings |-> 0]
    /\ misses = 0 /\ committed = {}
    /\ rStart = [e \in Events |-> 0] /\ rLen = [e \in Events |-> 0]
    /\ rRing = [e \in Events |-> "none"]
    /\ cdrops = {} /\ nested = {}

InStack(c) == \E i \in 1..Len(stack) : stack[i] = c
Pos(c) == CHOOSE i \in 1..Len(stack) : stack[i] = c
Top == stack[Len(stack)]
Below(c) == {stack[i] : i \in 1..(Pos(c) - 1)}
Cur(c) == <<c, ev[c]>>
KindInStack(k) == \E i \in 1..Len(stack) : Kind(stack[i]) = k

\* Preemption is enabled before bpf_preempt_disable() and after
\* bpf_preempt_enable(); the trampoline only disables migration.
Preemptible(c) == ~PreemptOff \/ pc[c] \in {"pre", "post"}

\* Which context may start a hook invocation now.  Linux: NMIs interrupt
\* anything but an NMI; hard interrupt handlers run with interrupts off;
\* softirqs run on interrupt exit to a context outside interrupt; tasks
\* switch only where preemption is enabled.
LinuxCanInterrupt(c) ==
    CASE Kind(c) = "nmi"     -> ~KindInStack("nmi")
      [] Kind(c) = "hardirq" -> ~KindInStack("hardirq") /\ ~KindInStack("nmi")
      [] Kind(c) = "softirq" -> Kind(Top) = "task" /\ ~KindInStack("softirq")
      [] Kind(c) = "task"    -> Kind(Top) = "task" /\ Preemptible(Top)

CanStart(c) ==
    /\ pc[c] = "idle" /\ ev[c] < E /\ ~InStack(c)
    /\ \/ stack = <<>>
       \/ Nesting # "linux"
       \/ stack # <<>> /\ LinuxCanInterrupt(c)

Start(c) ==
    /\ CanStart(c)
    /\ stack' = Append(stack, c)
    /\ ev' = [ev EXCEPT ![c] = ev[c] + 1]
    /\ steps' = [steps EXCEPT ![c] = 1]
    /\ rsv' = [rsv EXCEPT ![c] = FALSE]
    /\ cmt' = [cmt EXCEPT ![c] = 0]
    /\ IF SameProg /\ stack # <<>>
         \* __bpf_prog_enter_recur: another invocation of this program is
         \* active on this CPU -> skip the program, count a miss.
         THEN /\ pc' = [pc EXCEPT ![c] = "miss"]
              /\ acc' = [acc EXCEPT ![c] = TRUE]
              /\ misses' = misses + 1
         ELSE /\ pc' = [pc EXCEPT ![c] = "pre"]
              /\ acc' = [acc EXCEPT ![c] = FALSE]
              /\ UNCHANGED misses
    /\ UNCHANGED <<slot, len, tmp, holds, rvars, committed, rStart, rLen, rRing, cdrops, nested>>

\* With nesting, only the innermost invocation executes; "free" lets every
\* started invocation step.
Running(c) == IF Nesting = "free" THEN InStack(c) ELSE stack # <<>> /\ Top = c

Step(c, p, q) ==
    /\ Running(c) /\ pc[c] = p
    /\ pc' = [pc EXCEPT ![c] = q]
    /\ steps' = [steps EXCEPT ![c] = steps[c] + 1]

Holder(r) == IF \E d \in Ctx : holds[d] /\ RingOf(d) = r
               THEN CHOOSE d \in Ctx : holds[d] /\ RingOf(d) = r ELSE "none"

ContentionDrop(c) ==
    LET h == Holder(RingOf(c))
    IN cdrops' = cdrops \cup {<<c, h, h # "none" /\ InStack(h) /\ Pos(h) < Pos(c)>>}

\* reserve(): if (__sync_lock_test_and_set(&c->busy, 1)) -> contention drop
XChg(c) ==
    /\ Mode = "busy" /\ AtomicBusy
    /\ LET r == RingOf(c) IN
       IF busy[r] = 1
         THEN /\ Step(c, "pre", "cdrop") /\ ContentionDrop(c)
              /\ UNCHANGED <<busy, holds>>
         ELSE /\ Step(c, "pre", "reserve")
              /\ busy' = [busy EXCEPT ![r] = 1]
              /\ holds' = [holds EXCEPT ![c] = TRUE]
              /\ UNCHANGED cdrops
    /\ UNCHANGED <<stack, ev, slot, len, tmp, acc, rsv, cmt, head, tail, drops, misses,
                   committed, rStart, rLen, rRing, nested>>

\* Alternative: a plain flag, load ...
BLoad(c) ==
    /\ Mode = "busy" /\ ~AtomicBusy
    /\ Step(c, "pre", "bstore")
    /\ tmp' = [tmp EXCEPT ![c] = busy[RingOf(c)]]
    /\ UNCHANGED <<stack, ev, slot, len, holds, acc, rsv, cmt, rvars, gvars>>

\* ... then store 1 if it was 0
BStore(c) ==
    /\ LET r == RingOf(c) IN
       IF tmp[c] = 1
         THEN /\ Step(c, "bstore", "cdrop") /\ ContentionDrop(c)
              /\ UNCHANGED <<busy, holds>>
         ELSE /\ Step(c, "bstore", "reserve")
              /\ busy' = [busy EXCEPT ![r] = 1]
              /\ holds' = [holds EXCEPT ![c] = TRUE]
              /\ UNCHANGED cdrops
    /\ UNCHANGED <<stack, ev, slot, len, tmp, acc, rsv, cmt, head, tail, drops, misses,
                   committed, rStart, rLen, rRing, nested>>

\* reserve(): head = c->head; tail = load_acquire(&c->tail); space check
Reserve(c) ==
    /\ \/ Mode = "busy" /\ pc[c] = "reserve"
       \/ Mode # "busy" /\ pc[c] = "pre"
    /\ LET r == RingOf(c)
           h == head[r]
       IN IF h + Max - tail[r] > Size
            THEN /\ Step(c, pc[c], "fdrop")
                 /\ UNCHANGED <<slot, len, rsv, rStart, rLen, rRing>>
            ELSE /\ Step(c, pc[c], "commit")
                 /\ \E l \in Lens :
                      /\ len' = [len EXCEPT ![c] = l]
                      /\ rLen' = [rLen EXCEPT ![Cur(c)] = l]
                 /\ slot' = [slot EXCEPT ![c] = h]
                 /\ rsv' = [rsv EXCEPT ![c] = TRUE]
                 /\ rStart' = [rStart EXCEPT ![Cur(c)] = h]
                 /\ rRing' = [rRing EXCEPT ![Cur(c)] = r]
    /\ UNCHANGED <<stack, ev, tmp, holds, acc, cmt, rvars, misses, committed, cdrops, nested>>

\* Some context below this one is inside its reserve..commit (or busy) section.
LowerInSection(c) == \E d \in Below(c) : holds[d] \/ pc[d] = "commit"

\* commit(): store-release head = slot + len (busy released in Release)
Commit(c) ==
    /\ Step(c, "commit", IF holds[c] THEN "release" ELSE "post")
    /\ head' = [head EXCEPT ![RingOf(c)] = slot[c] + len[c]]
    /\ committed' = committed \cup {Cur(c)}
    /\ acc' = [acc EXCEPT ![c] = TRUE]
    /\ cmt' = [cmt EXCEPT ![c] = cmt[c] + 1]
    /\ nested' = IF LowerInSection(c) THEN nested \cup {Cur(c)} ELSE nested
    /\ UNCHANGED <<stack, ev, slot, len, tmp, holds, rsv, tail, drops, busy, misses,
                   rStart, rLen, rRing, cdrops>>

AfterDrop(c) == IF holds[c] THEN "release" ELSE "post"

\* __sync_fetch_and_add(&c->drops, 1), or a load ...
Drop(c) ==
    /\ \E p \in {"fdrop", "cdrop"} :
         IF AtomicDrops
           THEN /\ Step(c, p, AfterDrop(c))
                /\ drops' = [drops EXCEPT ![RingOf(c)] = drops[RingOf(c)] + 1]
                /\ acc' = [acc EXCEPT ![c] = TRUE]
                /\ UNCHANGED tmp
           ELSE /\ Step(c, p, "dstore")
                /\ tmp' = [tmp EXCEPT ![c] = drops[RingOf(c)]]
                /\ UNCHANGED <<drops, acc>>
    /\ UNCHANGED <<stack, ev, slot, len, holds, rsv, cmt, head, tail, busy, gvars>>

\* ... followed by the store of the incremented value.
DStore(c) ==
    /\ Step(c, "dstore", AfterDrop(c))
    /\ drops' = [drops EXCEPT ![RingOf(c)] = tmp[c] + 1]
    /\ acc' = [acc EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<stack, ev, slot, len, tmp, holds, rsv, cmt, head, tail, busy, gvars>>

\* __atomic_store_n(&c->busy, 0, __ATOMIC_RELEASE), in commit() or on the full path
Release(c) ==
    /\ Step(c, "release", "post")
    /\ busy' = [busy EXCEPT ![RingOf(c)] = 0]
    /\ holds' = [holds EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<stack, ev, slot, len, tmp, acc, rsv, cmt, head, tail, drops, gvars>>

\* bpf_preempt_enable(), program return, trampoline exit (guard released).
Exit(c) ==
    /\ Running(c) /\ pc[c] \in {"post", "miss"}
    /\ pc' = [pc EXCEPT ![c] = "idle"]
    /\ stack' = SelectSeq(stack, LAMBDA x : x # c)
    /\ steps' = [steps EXCEPT ![c] = steps[c] + 1]
    /\ UNCHANGED <<ev, slot, len, tmp, holds, acc, rsv, cmt, rvars, gvars>>

\* Consumer (other CPU): store-release tail at any committed record end.
Drain(r) ==
    /\ \E t \in {rStart[e] + rLen[e] : e \in {x \in committed : rRing[x] = r}} :
         /\ t > tail[r]
         /\ tail' = [tail EXCEPT ![r] = t]
    /\ UNCHANGED <<stack, cvars, head, drops, busy, gvars>>

ProgStep(c) ==
    \/ XChg(c) \/ BLoad(c) \/ BStore(c) \/ Reserve(c) \/ Commit(c)
    \/ Drop(c) \/ DStore(c) \/ Release(c) \/ Exit(c)

Next == \/ \E c \in Ctx : Start(c) \/ ProgStep(c)
        \/ \E r \in Rings : Drain(r)

Spec == Init /\ [][Next]_vars /\ \A c \in Ctx : WF_vars(ProgStep(c))

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0
                 ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumOver(f, S \ {x})

InFlight == {Cur(c) : c \in {d \in Ctx : pc[d] = "commit"}}
Live == {e \in committed : rStart[e] >= tail[rRing[e]]} \cup InFlight
Consumed == {e \in committed : rStart[e] + rLen[e] <= tail[rRing[e]]}

\* At most one context per ring between reserve and commit: the premise of Ring.tla.
Exclusive ==
    \A c1, c2 \in Ctx :
        (c1 # c2 /\ pc[c1] = "commit" /\ pc[c2] = "commit") => RingOf(c1) # RingOf(c2)

\* Live records and reservations of a ring never overlap.
NoOverlap ==
    \A e1, e2 \in Live :
        (e1 # e2 /\ rRing[e1] = rRing[e2]) =>
            \/ rStart[e1] + rLen[e1] <= rStart[e2]
            \/ rStart[e2] + rLen[e2] <= rStart[e1]

\* head only moves forward and always ends the last committed record.
HeadIsEnd ==
    \A r \in Rings :
        head[r] = IF \E e \in committed : rRing[e] = r
                    THEN LET last == CHOOSE e \in committed :
                                        rRing[e] = r /\ \A f \in committed :
                                            rRing[f] = r => rStart[f] <= rStart[e]
                         IN rStart[last] + rLen[last]
                    ELSE 0

\* emitted = consumed + in ring + dropped (full or busy contention)
\*           + recursion misses + in progress
Accounting ==
    SumOver(ev, Ctx) = Cardinality(Consumed) + Cardinality(committed \ Consumed)
                       + SumOver(drops, Rings) + misses
                       + Cardinality({c \in Ctx : pc[c] # "idle" /\ ~acc[c]})

Occupancy == \A r \in Rings : head[r] - tail[r] <= Size

\* The busy flag is set exactly when one context of this CPU holds that ring.
BusyMirrorsHolder ==
    \A r \in Rings :
        /\ busy[r] \in {0, 1}
        /\ (busy[r] = 1) <=> (\E c \in Ctx : holds[c] /\ RingOf(c) = r)
        /\ \A c \in Ctx : holds[c] => InStack(c)
        /\ Cardinality({c \in Ctx : holds[c] /\ RingOf(c) = r}) <= 1

\* Every successful reserve is followed by exactly one commit, and no path
\* returns while still holding the flag.
OneCommitPerReserve ==
    \A c \in Ctx :
        /\ cmt[c] <= 1
        /\ cmt[c] = 1 => rsv[c]
        /\ pc[c] = "post" => cmt[c] = IF rsv[c] THEN 1 ELSE 0
NoBusyLeak ==
    \A c \in Ctx : holds[c] => pc[c] \in {"reserve", "commit", "fdrop", "dstore", "release"}

\* A contention drop happens only when the victim interrupted the holder.
ContentionOnlyNested == \A x \in cdrops : x[3]

\* With one program, the trampoline guard lets at most one invocation run.
GuardSerializes ==
    SameProg => Cardinality({c \in Ctx : pc[c] \notin {"idle", "miss"}}) <= 1

\* Per-invocation work: start, flag load+store, reserve, drop load+store, release, exit.
StepBound == \A c \in Ctx : steps[c] <= 8

\* Every invocation allowed to run can take its next step.
NeverBlocks == \A c \in Ctx : (Running(c) /\ pc[c] # "idle") => ENABLED ProgStep(c)

InvocationsFinish == \A c \in Ctx : (pc[c] # "idle") ~> (pc[c] = "idle")

\* Witness predicates: TLC reports a trace when they are violated.
NoContentionDrop == cdrops = {}
NoNestedAccept == nested = {}
NoMiss == misses = 0
=============================================================================
