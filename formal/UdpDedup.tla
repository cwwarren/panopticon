------------------------------ MODULE UdpDedup ------------------------------
(***************************************************************************)
(* Per-socket UDP destination dedup: agent.bpf.c udp_seen() and udp_emit(),*)
(* reached from fexit/udp_sendmsg and fexit/udpv6_sendmsg.  One socket,    *)
(* its udp_meta in socket local storage, and one or more threads calling   *)
(* sendmsg on it.  udp_sendmsg on an uncorked socket does not take the     *)
(* socket lock, so several CPUs can run udp_emit on the same udp_meta      *)
(* concurrently; the table and counter updates are plain loads and stores. *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Senders,    \* threads sending on the socket
    Dests,      \* non-DNS destinations (daddr, dport)
    DnsDests,   \* destinations with dport 53
    Seen,       \* UDP_SEEN (power of two)
    Cap,        \* UDP_CAP
    Mod,        \* 2^bits of udp_meta.distinct (u8: 256)
    SatCounter, \* TRUE: increment only below UDP_CAP (0d3aadc); FALSE: plain += 1 (pre-fix)
    MaxSends    \* total sends; bounds the state space

ASSUME /\ Senders # {} /\ Dests \cap DnsDests = {}
       /\ Seen \in Nat \ {0} /\ \E e \in 0..Seen : 2^e = Seen
       /\ Cap \in Nat \ {0} /\ Mod \in Nat /\ Mod > Cap /\ MaxSends \in Nat
       /\ SatCounter \in BOOLEAN

None == "none"
AllDests == Dests \cup DnsDests
Slots == 0..(Seen - 1)

VARIABLES
    tbl, nxt, distinct,             \* struct udp_meta (dns flag irrelevant here)
    pc, d, sl, tmp, sat,            \* per sender
    sends, dnsSends, recs, dnsRecs, \* ghost counters
    ins, hist,                      \* ghost: insertions and the last Seen inserted
    errs

svars == <<pc, d, sl, tmp, sat>>
vars == <<tbl, nxt, distinct, svars, sends, dnsSends, recs, dnsRecs, ins, hist, errs>>

Init ==
    /\ tbl = [i \in Slots |-> None] /\ nxt = 0 /\ distinct = 0
    /\ pc = [s \in Senders |-> "idle"] /\ d = [s \in Senders |-> None]
    /\ sl = [s \in Senders |-> 0] /\ tmp = [s \in Senders |-> 0]
    /\ sat = [s \in Senders |-> FALSE]
    /\ sends = 0 /\ dnsSends = 0 /\ recs = 0 /\ dnsRecs = 0
    /\ ins = 0 /\ hist = <<>> /\ errs = {}

InTbl(x) == \E i \in Slots : tbl[i] = x      \* udp_seen()
IsDns(x) == x \in DnsDests
LastSeen == {hist[i] : i \in 1..Len(hist)}
Goto(s, p) == pc' = [pc EXCEPT ![s] = p]

\* A send reaches udp_emit(): seen = udp_seen(m, addr, port), then
\* "if (!dns && (seen || m->distinct >= UDP_CAP)) return".  The ghost checks
\* compare the decision with the specification:
\*   - before saturation a non-DNS send to a destination outside the last
\*     Seen recorded ones emits;
\*   - a non-DNS send to one of them does not.
Begin(s) ==
    /\ pc[s] = "idle" /\ sends < MaxSends
    /\ \E x \in AllDests :
         /\ d' = [d EXCEPT ![s] = x]
         /\ sends' = sends + 1
         /\ dnsSends' = dnsSends + (IF IsDns(x) THEN 1 ELSE 0)
         /\ LET seen == InTbl(x)
                skip == ~IsDns(x) /\ (seen \/ distinct >= Cap)
            IN /\ Goto(s, IF skip THEN "idle" ELSE IF seen THEN "emit" ELSE "slot")
               /\ errs' = errs
                    \cup (IF skip /\ x \notin LastSeen /\ ins < Cap THEN {"missed"} ELSE {})
                    \cup (IF ~skip /\ ~IsDns(x) /\ x \in LastSeen THEN {"dup"} ELSE {})
    /\ sat' = [sat EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<tbl, nxt, distinct, sl, tmp, recs, dnsRecs, ins, hist>>

\* slot = m->next & (UDP_SEEN - 1)
Slot(s) ==
    /\ pc[s] = "slot"
    /\ sl' = [sl EXCEPT ![s] = nxt % Seen]
    /\ Goto(s, "wtbl")
    /\ UNCHANGED <<tbl, nxt, distinct, d, tmp, sat, sends, dnsSends, recs, dnsRecs, ins, hist, errs>>

\* m->seen[slot] = {addr, port}; m->next = slot + 1
WTbl(s) ==
    /\ pc[s] = "wtbl"
    /\ tbl' = [tbl EXCEPT ![sl[s]] = d[s]]
    /\ nxt' = sl[s] + 1
    /\ ins' = ins + 1
    /\ hist' = IF Len(hist) < Seen THEN Append(hist, d[s]) ELSE Append(Tail(hist), d[s])
    /\ Goto(s, "rdist")
    /\ UNCHANGED <<distinct, d, sl, tmp, sat, sends, dnsSends, recs, dnsRecs, errs>>

\* the increment of distinct as a load ...
RDist(s) ==
    /\ pc[s] = "rdist"
    /\ tmp' = [tmp EXCEPT ![s] = distinct]
    /\ Goto(s, "wdist")
    /\ UNCHANGED <<tbl, nxt, distinct, d, sl, sat, sends, dnsSends, recs, dnsRecs, ins, hist, errs>>

\* ... and a store.  0d3aadc: if (m->distinct < UDP_CAP && ++m->distinct == UDP_CAP)
\* flags |= FLAG_SATURATED.  Pre-fix: m->distinct += 1 (u8 wraps), then the same test.
WDist(s) ==
    /\ pc[s] = "wdist"
    /\ IF SatCounter /\ tmp[s] >= Cap
         THEN /\ UNCHANGED distinct
              /\ sat' = [sat EXCEPT ![s] = FALSE]
         ELSE /\ distinct' = (tmp[s] + 1) % Mod
              /\ sat' = [sat EXCEPT ![s] = ((tmp[s] + 1) % Mod = Cap)]
    /\ Goto(s, "emit")
    /\ UNCHANGED <<tbl, nxt, d, sl, tmp, sends, dnsSends, recs, dnsRecs, ins, hist, errs>>

\* reserve()/commit(): one record (or a counted ring drop, Ring.tla)
Emit(s) ==
    /\ pc[s] = "emit"
    /\ recs' = recs + 1
    /\ dnsRecs' = dnsRecs + (IF IsDns(d[s]) THEN 1 ELSE 0)
    /\ Goto(s, "idle")
    /\ UNCHANGED <<tbl, nxt, distinct, d, sl, tmp, sat, sends, dnsSends, ins, hist, errs>>

SStep(s) == Begin(s) \/ Slot(s) \/ WTbl(s) \/ RDist(s) \/ WDist(s) \/ Emit(s)

Next == \E s \in Senders : SStep(s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
\* records per socket <= UDP_CAP + DNS queries
RecordBound == recs <= Cap + dnsSends

\* Before saturation, a destination not among the last UDP_SEEN recorded
\* always emits; one among them never does (non-DNS).
NewDestEmits == "missed" \notin errs
DedupHolds == "dup" \notin errs

\* The table holds exactly the last Seen inserted destinations.
TableIsFifo == {tbl[i] : i \in Slots} \ {None} = LastSeen

\* Per-socket state is fixed size: Seen slots and u8 counters.
StateBounded == nxt \in 0..Seen /\ distinct \in 0..(Mod - 1)
=============================================================================
