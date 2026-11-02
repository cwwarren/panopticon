-------------------------------- MODULE Ring --------------------------------
(***************************************************************************)
(* One per-CPU, per-class byte ring: a single producer (a BPF program on   *)
(* one CPU, inside bpf_preempt_disable) and a single consumer (the         *)
(* userspace drain thread).  See formal/README.md for the mapping of every *)
(* action to agent.bpf.c / run.rs lines and kernel guarantees.             *)
(*                                                                         *)
(* Unit of memory is one 8-byte cell.  commit() rounds every length up to  *)
(* 8 bytes and head starts at 0, so record starts are cell boundaries.     *)
(* Cell 0 of a record is its header (len/type/flags/reserved; commit()     *)
(* writes it last), cells 1.. are the body.                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Size,       \* ring size in cells (power of two; reserve() masks head with size - 1)
    Slack,      \* cells past Size in the array value (PROC/NET/FILE/ADMIN_SLACK)
    Max,        \* the class's maximum record size in cells (reserve() argument max)
    Lens,       \* committed record lengths the producer may choose (cells)
    N,          \* number of producer events; bounds the state space
    Overrun,    \* cells a writer may store past max (0: every writer stays within max)
    RelaxHead,  \* TRUE: head store is not a release (data may become visible after it)
    RelaxTail   \* TRUE: tail store is not a release (copies may finish after it)

ASSUME /\ Size \in Nat \ {0}
       /\ \E e \in 0..Size : 2^e = Size
       /\ Slack \in Nat
       /\ Max \in 1..Size
       /\ Lens \subseteq 1..Max /\ Lens # {}
       /\ N \in Nat /\ Overrun \in Nat
       /\ RelaxHead \in BOOLEAN /\ RelaxTail \in BOOLEAN

Cells == 0 .. (Size + Slack - 1)
Ids == 1..N
NoPend == <<0, 0>>
Zero == <<0, 0>>                 \* a never-written cell (array maps start zeroed)

\* Producer offset: base + (head & (size - 1)) in reserve().
Off(h) == h % Size
\* Consumer modulus: run.rs map_rings() takes the largest power of two <= value_size.
ConsSize == CHOOSE p \in {2^e : e \in 0..(Size + Slack)} :
                p <= Size + Slack /\ 2 * p > Size + Slack
COff(t) == t % ConsSize

VARIABLES
    mem,        \* [Cells -> <<record id, cell index>>]: memory as the consumer sees it
    pend,       \* producer stores not yet visible to the consumer (RelaxHead only)
    head, tail, drops,                  \* struct ctl
    ppc, pslot, plen, pw, pk, nev, psteps,   \* producer
    cpc, chead, ctail, clen, ck, crid,  \* consumer (ctail = Ring.tail in run.rs)
    alive,      \* the agent process is alive
    start, rlen, committed, consumed,   \* ghost
    errs        \* ghost: detected safety violations

pvars == <<ppc, pslot, plen, pw, pk, nev, psteps>>
cvars == <<cpc, chead, ctail, clen, ck, crid>>
gvars == <<start, rlen, committed, consumed>>
vars == <<mem, pend, head, tail, drops, pvars, cvars, alive, gvars, errs>>

TypeOK ==
    /\ mem \in [Cells -> (0..N) \X (0..(Max + Overrun))]
    /\ pend \in [Cells -> (0..N) \X (0..(Max + Overrun))]
    /\ head \in Nat /\ tail \in Nat /\ drops \in Nat
    /\ ppc \in {"idle", "write", "commit"}
    /\ cpc \in {"load", "hdr", "body", "store", "halt"}
    /\ alive \in BOOLEAN
    /\ committed \subseteq Ids
    /\ errs \subseteq {"overwrite", "badread", "oob", "assert"}

Init ==
    /\ mem = [c \in Cells |-> Zero]
    /\ pend = [c \in Cells |-> NoPend]
    /\ head = 0 /\ tail = 0 /\ drops = 0
    /\ ppc = "idle" /\ pslot = 0 /\ plen = 0 /\ pw = 0 /\ pk = 0 /\ nev = 0 /\ psteps = 0
    /\ cpc = "load" /\ chead = 0 /\ ctail = 0 /\ clen = 0 /\ ck = 0 /\ crid = 0
    /\ alive = TRUE
    /\ start = [i \in Ids |-> 0] /\ rlen = [i \in Ids |-> 0]
    /\ committed = {} /\ consumed = 0
    /\ errs = {}

\* A record is live from commit until the consumer has copied all of it.
Live(r) == r \in committed /\ start[r] >= ctail

\* Cell content o is part of a live record (not scratch past its length).
LiveCell(o) == o[1] # 0 /\ Live(o[1]) /\ o[2] < rlen[o[1]]

\* A store to cell c becomes visible.  Flags an overwrite of a live record.
Visible(c, v) ==
    /\ mem' = [mem EXCEPT ![c] = v]
    /\ errs' = IF mem[c][1] # v[1] /\ LiveCell(mem[c])
                 THEN errs \cup {"overwrite"} ELSE errs

(***************************************************************************)
(* Producer: reserve(), the record writes, commit().  reserve() also takes *)
(* the ring's busy flag; with one context per ring it is never contended   *)
(* (MultiCtx.tla covers contention), so it is left out here.               *)
(***************************************************************************)
PReserve ==
    /\ ppc = "idle" /\ nev < N
    /\ nev' = nev + 1
    /\ psteps' = 1
    /\ IF head + Max - tail > Size          \* reserve(): load-acquire tail, space check
         THEN /\ drops' = drops + 1         \* __sync_fetch_and_add(&c->drops, 1)
              /\ UNCHANGED <<ppc, pslot, plen, pw, pk, start, rlen>>
         ELSE /\ \E l \in Lens, w \in 1..(Max + Overrun) :
                   /\ w >= l                \* stores may run past len, up to max (+ Overrun)
                   /\ plen' = l /\ pw' = w
                   /\ rlen' = [rlen EXCEPT ![nev + 1] = l]
              /\ ppc' = "write" /\ pslot' = head /\ pk' = 1
              /\ start' = [start EXCEPT ![nev + 1] = head]
              /\ UNCHANGED drops
    /\ UNCHANGED <<mem, pend, head, tail, cvars, alive, committed, consumed, errs>>

\* Body cells 1..pw-1 in program order, then the header (cell 0) in commit().
PWrite ==
    /\ ppc = "write"
    /\ LET k == IF pk < pw THEN pk ELSE 0
           c == Off(pslot) + k
           v == <<nev, k>>
       IN IF c \notin Cells
            THEN /\ errs' = errs \cup {"oob"}
                 /\ UNCHANGED <<mem, pend>>
            ELSE IF RelaxHead
                   THEN /\ pend' = [pend EXCEPT ![c] = v]
                        /\ UNCHANGED <<mem, errs>>
                   ELSE /\ Visible(c, v)
                        /\ UNCHANGED pend
    /\ pk' = pk + 1
    /\ ppc' = IF pk < pw THEN "write" ELSE "commit"
    /\ psteps' = psteps + 1
    /\ UNCHANGED <<head, tail, drops, pslot, plen, pw, nev, cvars, alive, gvars>>

\* commit(): store-release head = slot + len.  With release semantics every
\* earlier store is visible first; RelaxHead drops that requirement.
PCommit ==
    /\ ppc = "commit"
    /\ RelaxHead \/ \A c \in Cells : pend[c] = NoPend
    /\ head' = pslot + plen
    /\ committed' = committed \cup {nev}
    /\ ppc' = "idle"
    /\ psteps' = psteps + 1
    /\ UNCHANGED <<mem, pend, tail, drops, pslot, plen, pw, pk, nev, cvars, alive,
                   start, rlen, consumed, errs>>

\* Memory system: a pending producer store becomes visible (RelaxHead only).
Flush ==
    /\ \E c \in Cells :
         /\ pend[c] # NoPend
         /\ Visible(c, pend[c])
         /\ pend' = [pend EXCEPT ![c] = NoPend]
    /\ UNCHANGED <<head, tail, drops, pvars, cvars, alive, gvars>>

(***************************************************************************)
(* Consumer: Ring::drain called by the main loop every poll.               *)
(***************************************************************************)
\* let head = ctl.head.load(Acquire)
CLoad ==
    /\ alive /\ cpc = "load"
    /\ chead' = head
    /\ cpc' = IF ctail < head THEN "hdr" ELSE "store"
    /\ UNCHANGED <<mem, pend, head, tail, drops, pvars, ctail, clen, ck, crid, alive, gvars, errs>>

\* The record expected at logical position t.
Expected(t, v) == \E r \in committed : start[r] = t /\ v = <<r, 0>>

\* read len from the header; assert len >= HDR && len % 8 == 0 && tail + len <= head
CHdr ==
    /\ alive /\ cpc = "hdr"
    /\ LET c == COff(ctail)
           v == IF c \in Cells THEN mem[c] ELSE Zero
           len == IF v[1] = 0 THEN 0 ELSE rlen[v[1]]
       IN IF ~ Expected(ctail, v)
            THEN /\ errs' = errs \cup {"badread"} /\ cpc' = "halt"
                 /\ UNCHANGED <<ctail, clen, ck, crid, consumed>>
            ELSE IF ~ (len >= 1 /\ ctail + len <= chead)
              THEN /\ errs' = errs \cup {"assert"} /\ cpc' = "halt"
                   /\ UNCHANGED <<ctail, clen, ck, crid, consumed>>
              ELSE /\ crid' = v[1] /\ clen' = len /\ UNCHANGED errs
                   /\ cpc' = "body" /\ ck' = 0
                   /\ UNCHANGED <<ctail, consumed>>
    /\ UNCHANGED <<mem, pend, head, tail, drops, pvars, chead, alive, start, rlen, committed>>

\* out.extend_from_slice(rec[..len]) one cell at a time (header included),
\* then self.tail += len
CBody ==
    /\ alive /\ cpc = "body"
    /\ LET c == COff(ctail) + ck
           v == IF c \in Cells THEN mem[c] ELSE Zero
       IN IF v # <<crid, ck>>
            THEN /\ errs' = errs \cup {"badread"} /\ cpc' = "halt"
                 /\ UNCHANGED <<ctail, ck, consumed>>
            ELSE /\ UNCHANGED errs
                 /\ IF ck + 1 < clen
                      THEN /\ ck' = ck + 1 /\ cpc' = "body"
                           /\ UNCHANGED <<ctail, consumed>>
                      ELSE /\ ctail' = ctail + clen
                           /\ consumed' = consumed + 1
                           /\ cpc' = IF ctail + clen < chead THEN "hdr" ELSE "store"
                           /\ UNCHANGED ck
    /\ UNCHANGED <<mem, pend, head, tail, drops, pvars, chead, clen, crid, alive,
                   start, rlen, committed>>

\* ctl.tail.store(self.tail, Release) after the loop
CStore ==
    /\ alive /\ cpc = "store"
    /\ tail' = ctail
    /\ cpc' = "load"
    /\ UNCHANGED <<mem, pend, head, drops, pvars, chead, ctail, clen, ck, crid, alive, gvars, errs>>

\* RelaxTail: the tail store becomes visible while the last record's bytes
\* are still being copied (its value depends only on the headers already read).
CEarly ==
    /\ RelaxTail
    /\ alive /\ cpc = "body" /\ ctail + clen = chead /\ tail < chead
    /\ tail' = chead
    /\ UNCHANGED <<mem, pend, head, drops, pvars, cvars, alive, gvars, errs>>

\* The agent dies or stops forever at any point.
Die ==
    /\ alive
    /\ alive' = FALSE
    /\ UNCHANGED <<mem, pend, head, tail, drops, pvars, cvars, gvars, errs>>

PStep == PReserve \/ PWrite \/ PCommit
CStep == CLoad \/ CHdr \/ CBody \/ CStore \/ CEarly

Next == PStep \/ CStep \/ Flush \/ Die

\* Both sides scheduled fairly while they exist (the agent may still die).
Spec == Init /\ [][Next]_vars /\ WF_vars(PStep) /\ WF_vars(CStep) /\ WF_vars(Flush)
\* No fairness at all for the consumer: it may stop at any point forever.
ProducerOnlySpec == Init /\ [][Next]_vars /\ WF_vars(PStep) /\ WF_vars(Flush)

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
NoOverwrite   == "overwrite" \notin errs   \* no store hits an uncopied record
NoPartialRead == "badread" \notin errs     \* every copied cell is the expected record's
MemSafe       == "oob" \notin errs         \* every store lands inside size + slack
DrainAssert   == "assert" \notin errs      \* run.rs drain() assertion never fires

\* Records are contiguous inside the value: they start below Size and end
\* within Size + Slack, never wrapping.
Contiguous == \A r \in committed : Off(start[r]) + rlen[r] <= Size + Slack

\* emitted = consumed + dropped + in ring (+ the one being written)
Accounting ==
    nev = consumed + drops
          + Cardinality({r \in committed : start[r] >= ctail})
          + (IF ppc # "idle" THEN 1 ELSE 0)

\* Ring occupancy stays within Size; a reservation never passes tail + Size.
Bounds ==
    /\ ctail <= head
    /\ head - tail <= Size
    /\ ppc # "idle" => pslot + Max <= tail + Size

\* The published tail never runs ahead of what the consumer has copied.
CopyBeforeRelease == tail <= ctail

\* Per-event work: reserve + at most Max cell writes + commit.
StepBound == psteps <= Max + Overrun + 2

\* The producer never waits: its next step is always enabled.
NeverBlocks ==
    /\ ppc # "idle" => ENABLED PStep
    /\ (ppc = "idle" /\ nev < N) => ENABLED PReserve

\* State abstraction for large safety-only runs: cells of records that are
\* neither live nor being written read as Zero, and only live records keep
\* their ghost start/length.  Every action and property above reads cells
\* only through Live/LiveCell/Expected or the producer's own record, so
\* two states with the same View have the same safety-relevant futures.
Kept == {r \in committed : start[r] >= ctail} \cup (IF ppc # "idle" THEN {nev} ELSE {})
View == <<[c \in Cells |-> IF mem[c][1] \in Kept THEN mem[c] ELSE Zero],
          pend, head, tail, drops, pvars, cvars, alive,
          [r \in Kept |-> <<start[r], rlen[r]>>], consumed, errs>>

ProducerFinishes == (ppc # "idle") ~> (ppc = "idle")
ConsumerDrains == \A i \in Ids : (i \in committed) ~> (start[i] < ctail \/ ~alive)
=============================================================================
