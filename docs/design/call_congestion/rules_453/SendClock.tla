----------------------------- MODULE SendClock -----------------------------
(* Row R24 SENDCLOCK (45.3 row DR): a leg's backlog is the oldest unproved
   Channel message's age FROM ITS SEND.

   Code (CIRISEdge work/45.3):
     alm.rs:491-532   SendClock: note(now, last_sent) pushes (now, seq) when
                      last_sent changed (at most MAX_MARKS = 240, a minute of
                      ticks); age_of(now, oldest) pops every mark before
                      `oldest` (keeping one) and ages from the front mark.
     alm.rs:496-498   seq_at_or_after: a - b < 0x8000 on the 16-bit sequence.
     av_call.rs:4196-4207  each watch tick: note, then age_of(oldest_unacked).
     av_call.rs:7071-7081  the G8 verdict's own age: from the first tick the
                      message was the OLDEST (Clock = "oldest_since" below).

   One step = one watch tick (250 ms). Messages sent between two watch ticks
   are stamped with the later tick (sentTick); proofs arrive between ticks,
   in any order, within a window of MaxOut. The wire sequence is seq % SeqMod
   (SeqMod = 16 here, so the wrap is exercised; the code's is 65536).                                  *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Clock,      \* "send" (45.3) | "oldest_since" (the G8 verdict's age)
    MaxMarks,   \* marks kept (the code: 240)
    SeqMod,     \* wire sequence modulus (the code: 65536)
    MaxOut,     \* most messages unproved at once (the Channel window)
    MaxSend,    \* messages sent per tick at most
    H           \* horizon, ticks

VARIABLES t, next, out, sentTick, marks, lastSent, oldSince, reading

vars == <<t, next, out, sentTick, marks, lastSent, oldSince, reading>>

Seqs == 0..(H * MaxSend)
W(s) == s % SeqMod
AtOrAfter(a, b) == ((a - b) + SeqMod) % SeqMod < SeqMod \div 2
Min(S) == CHOOSE x \in S : \A y \in S : x <= y

Init ==
    /\ t = 0 /\ next = 0 /\ out = {} /\ sentTick = [s \in Seqs |-> 0]
    /\ marks = <<>> /\ lastSent = -1 /\ oldSince = <<-1, 0>> /\ reading = -1

\* age_of: pop marks before `o` (keep one), age from the front.
RECURSIVE Pop(_, _)
Pop(m, o) == IF Len(m) > 1 /\ ~AtOrAfter(m[1][2], o) THEN Pop(Tail(m), o) ELSE m

Note(m, now, ls) ==
    IF ls < 0 \/ (m /= <<>> /\ m[Len(m)][2] = W(ls)) THEN m
    ELSE LET m2 == Append(m, <<now, W(ls)>>)
         IN IF Len(m2) > MaxMarks THEN Tail(m2) ELSE m2

Tick ==
    /\ t < H
    /\ \E k \in 0..MaxSend, proved \in SUBSET out :
        \* the Channel's window: every unproved message within MaxOut of the oldest
        /\ LET o2 == (out \ proved) \cup {next + i : i \in 0..(k - 1)}
           IN o2 = {} \/ (\A x \in o2 : x < Min(o2) + MaxOut)
        /\ LET now   == t + 1
               new   == {next + i : i \in 0..(k - 1)}
               out2  == (out \ proved) \cup new
               ls    == IF k > 0 THEN next + k - 1 ELSE lastSent
               m1    == Note(marks, now, ls)
               o     == IF out2 = {} THEN -1 ELSE Min(out2)
               m2    == IF o < 0 THEN m1 ELSE Pop(m1, W(o))
               since == IF o < 0 THEN <<-1, 0>>
                        ELSE IF oldSince[1] = o THEN oldSince ELSE <<o, now>>
           IN /\ t' = now /\ next' = next + k /\ out' = out2
              /\ sentTick' = [s \in Seqs |-> IF s \in new THEN now ELSE sentTick[s]]
              /\ lastSent' = ls /\ marks' = m2 /\ oldSince' = since
              /\ reading' = IF o < 0 THEN -1
                            ELSE IF Clock = "send" THEN now - m2[1][1]
                            ELSE now - since[2]

Spec == Init /\ [][Tick]_vars

Oldest == Min(out)
TrueAge == t - sentTick[Oldest]     \* ticks; the real age is within one tick above

\* The backlog is the oldest message's age from its send, to the tick.
SendClockExact == out /= {} => reading = TrueAge
\* Weaker: never under-read by more than the span the marks keep.
SendClockBounded == out /= {} => reading >= TrueAge \/ reading >= MaxMarks - 1
\* Never over-read (the drain and the budget never act on a queue not there).
NeverOverReads == out /= {} => reading <= TrueAge
TypeOK == reading \in -1..H
=============================================================================
