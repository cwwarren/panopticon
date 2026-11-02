------------------------------ MODULE RingProof ------------------------------
(***************************************************************************)
(* TLAPS proof of the single-producer ring for all sizes.                  *)
(*                                                                         *)
(* Logical model of Ring.tla with release/acquire visibility (the producer *)
(* publishes head only after its stores, the consumer publishes tail only  *)
(* after its copies).  Positions are logical byte (cell) offsets; a byte   *)
(* at logical position p of a record starting at s sits at physical index  *)
(* Phys(s, p) = (s % S) + (p - s), as in reserve(): base + (head & (size -  *)
(* 1)) plus the offset written by the program.                             *)
(*                                                                         *)
(* Proved for every S > 0, Slack, Max with 1 <= Max <= S, Max <= Slack + 1: *)
(*   Inv is inductive (Safety);                                            *)
(*   a byte the producer may write never shares a physical index with an   *)
(*   unread committed byte (NoOverwrite), which also means the consumer    *)
(*   never reads a byte that is being written;                             *)
(*   every byte the producer may write lies inside size + slack            *)
(*   (Contained), so records never split.                                  *)
(***************************************************************************)
EXTENDS Integers, TLAPS

CONSTANTS S, Slack, Max

ASSUME Const == /\ S \in Nat /\ S > 0
                /\ Slack \in Nat
                /\ Max \in Nat /\ 1 <= Max /\ Max <= S /\ Max <= Slack + 1

Phys(s, p) == (s % S) + (p - s)

VARIABLES head, tail, ctail, chead, busy, slot, plen
vars == <<head, tail, ctail, chead, busy, slot, plen>>

TypeOK ==
    /\ head \in Nat /\ tail \in Nat /\ ctail \in Nat /\ chead \in Nat
    /\ busy \in BOOLEAN /\ slot \in Nat /\ plen \in 1..Max

Init ==
    /\ head = 0 /\ tail = 0 /\ ctail = 0 /\ chead = 0
    /\ busy = FALSE /\ slot = 0 /\ plen = 1

\* reserve(): space check against max, then the producer owns [head, head + Max)
Reserve ==
    /\ ~busy /\ head + Max - tail <= S
    /\ busy' = TRUE /\ slot' = head
    /\ \E l \in 1..Max : plen' = l
    /\ UNCHANGED <<head, tail, ctail, chead>>

\* reserve() full: drops += 1 (no ring state changes)
Drop ==
    /\ ~busy /\ head + Max - tail > S
    /\ UNCHANGED vars

\* commit(): store-release head = slot + len
Commit ==
    /\ busy
    /\ head' = slot + plen /\ busy' = FALSE
    /\ UNCHANGED <<tail, ctail, chead, slot, plen>>

\* drain(): load-acquire head
CLoad ==
    /\ chead' = head
    /\ UNCHANGED <<head, tail, ctail, busy, slot, plen>>

\* drain(): copy one whole record, self.tail += len
CCopy ==
    /\ ctail < chead
    /\ \E n \in 1..(chead - ctail) : ctail' = ctail + n
    /\ UNCHANGED <<head, tail, chead, busy, slot, plen>>

\* drain(): store-release tail
CStore ==
    /\ tail' = ctail
    /\ UNCHANGED <<head, ctail, chead, busy, slot, plen>>

Next == Reserve \/ Drop \/ Commit \/ CLoad \/ CCopy \/ CStore
Spec == Init /\ [][Next]_vars

Inv ==
    /\ TypeOK
    /\ tail <= ctail /\ ctail <= chead /\ chead <= head
    /\ head - tail <= S
    /\ busy => (slot = head /\ slot + Max <= tail + S)

THEOREM Safety == Spec => []Inv
<1>1. Init => Inv
  BY Const DEF Init, Inv, TypeOK
<1>2. Inv /\ [Next]_vars => Inv'
  <2> SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
    OBVIOUS
  <2>1. CASE Reserve
    BY <2>1, Const DEF Reserve, Inv, TypeOK
  <2>2. CASE Drop
    BY <2>2 DEF Drop, Inv, TypeOK, vars
  <2>3. CASE Commit
    BY <2>3, Const DEF Commit, Inv, TypeOK
  <2>4. CASE CLoad
    BY <2>4 DEF CLoad, Inv, TypeOK
  <2>5. CASE CCopy
    BY <2>5 DEF CCopy, Inv, TypeOK
  <2>6. CASE CStore
    BY <2>6, Const, SMT DEF CStore, Inv, TypeOK
  <2>7. CASE UNCHANGED vars
    BY <2>7 DEF vars, Inv, TypeOK
  <2> QED
    BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6, <2>7 DEF Next
<1> QED
  BY <1>1, <1>2, PTL DEF Spec

\* An integer strictly between 0 and S is not a multiple of S.
LEMMA NotMultiple ==
  ASSUME NEW k \in Int, NEW d \in Int, 0 < d, d < S
  PROVE  d # S * k
<1>1. CASE k <= 0
  BY <1>1, Const, SMT
<1>2. CASE k >= 1
  BY <1>2, Const, SMT
<1> QED
  BY <1>1, <1>2

LEMMA PhysDiv ==
  ASSUME NEW s \in Nat, NEW p \in Int
  PROVE  Phys(s, p) = p - S * (s \div S)
  BY Const, SMT DEF Phys

\* While the producer owns its reservation, each byte it may write
\* (slot <= p1 < slot + Max) differs physically from each unread committed
\* byte p2 of a record starting at s2 (ctail <= s2 <= p2 < head).
THEOREM NoOverwrite ==
  ASSUME Inv, busy,
         NEW p1 \in Int, slot <= p1, p1 < slot + Max,
         NEW s2 \in Nat, NEW p2 \in Int, ctail <= s2, s2 <= p2, p2 < head
  PROVE  Phys(slot, p1) # Phys(s2, p2)
<1>1. slot \in Nat /\ head \in Nat /\ tail \in Nat /\ ctail \in Nat
  BY DEF Inv, TypeOK
<1>2. 0 < p1 - p2 /\ p1 - p2 < S
  BY <1>1, Const DEF Inv, TypeOK
<1>3. Phys(slot, p1) = p1 - S * (slot \div S) /\ Phys(s2, p2) = p2 - S * (s2 \div S)
  BY <1>1, PhysDiv
<1>4. (slot \div S) - (s2 \div S) \in Int
  BY <1>1, Const
<1>5. p1 - p2 # S * ((slot \div S) - (s2 \div S))
  BY <1>2, <1>4, NotMultiple
<1> QED
  BY <1>3, <1>5, <1>1, Const, SMT

\* Every byte the producer may write lies inside the size + slack array value.
THEOREM Contained ==
  ASSUME Inv, busy, NEW p \in Int, slot <= p, p < slot + Max
  PROVE  Phys(slot, p) \in 0..(S + Slack - 1)
<1>1. slot \in Nat
  BY DEF Inv, TypeOK
<1>2. slot % S \in 0..(S - 1)
  BY <1>1, Const, SMT
<1>3. p - slot \in 0..(Max - 1)
  BY <1>1, Const, SMT
<1> HIDE DEF Phys
<1>4. Phys(slot, p) = (slot % S) + (p - slot)
  BY DEF Phys
<1> QED
  BY <1>2, <1>3, <1>4, Const, SMT
=============================================================================
