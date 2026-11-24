------------------------- MODULE MCCallCongestion -------------------------
(* Model values the .cfg cannot spell (sequences), and the outcome probe. *)
EXTENDS CallCongestion
Listeners2 == <<"A", "B">>
Listeners3 == <<"A", "B", "C">>
\* hash(stream, child key) order: deliberately NOT the join order (A, B, C)
Rank2 == <<"B", "A">>
Rank3 == <<"C", "A", "B">>
=============================================================================
