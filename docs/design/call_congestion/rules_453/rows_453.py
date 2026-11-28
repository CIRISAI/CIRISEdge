"""Scenarios for rows R24-R28 and R29's advertised-latency clause; imported by
run_rules.py (see its docstring)."""


def register(add, B, S):
    # ---------------------------------------------------------------- R24
    sc = dict(MaxMarks=240, SeqMod=16, MaxOut=3, MaxSend=2, H=8)
    add("R24-sendclock", "SendClock", dict(sc, Clock=S("send")),
        invs=["TypeOK", "SendClockExact", "NeverOverReads"])
    add("R24-sendclock-marks3", "SendClock", dict(sc, Clock=S("send"), MaxMarks=3),
        invs=["TypeOK", "SendClockExact", "SendClockBounded", "NeverOverReads"])
    add("R24-sendclock-seqmod8", "SendClock", dict(sc, Clock=S("send"), SeqMod=8),
        invs=["TypeOK", "SendClockExact", "NeverOverReads"])
    add("R24-oldest-since", "SendClock", dict(sc, Clock=S("oldest_since")),
        invs=["TypeOK", "SendClockExact"])
    # ---------------------------------------------------------------- R25
    ub = dict(QMax=4, PMax=2, Enter=2, Leave=1, Clear=4, Latch=8, StaleT=4,
              SlowOnly=S("any"))
    for n in (1, 2, 3):
        add(f"R25-backlog-n{n}", "UplinkBacklog", dict(ub, N=n),
            invs=["TypeOK", "OnePeerIsNotOwn", "OwnQueueSeen", "OwnStaleSeen",
                  "BackloggedStalled", "DrainStalled", "NoRelayOfferStalled"])
    add("R25-backlog-n3-slowkept", "UplinkBacklog", dict(ub, N=3, SlowOnly=S("kept")),
        invs=["TypeOK"], props=["DrainEnds"])
    # ---------------------------------------------------------------- R26
    st = dict(C=2, MMax=4, CtlMax=1, LMax=14, StaleT=3)
    for bound in (3, 5, 6, 7):
        add(f"R26-stale-bound{bound}", "StaleAtSender", dict(st, Rule=S("stale"), Bound=bound),
            invs=["TypeOK", "ArrivalBound"])
    add("R26-stale", "StaleAtSender", dict(st, Rule=S("stale"), Bound=99),
        invs=["TypeOK", "ControlNeverHeld"], props=["Drains"])
    add("R26-none", "StaleAtSender", dict(st, Rule=S("none"), Bound=99),
        invs=["TypeOK", "ControlNeverHeld"], props=["Drains"])
    # ---------------------------------------------------------------- R27
    af = dict(Budget=16, Near=1, Step=40, DMax=20, WMax=4, MaxSteps=1, Rolls=1,
              MaxReanchor=1, Shift=S("none"), SinceCap=2)
    for fl in ("current", "confirm", "confirm0"):
        add(f"R27-age-{fl}", "AgeFloor", dict(af, Floor=S(fl)),
            invs=["TypeOK", "NoFalseStale", "NoFalseStaleHandout", "StaleCaught",
                  "NeverForwardStale", "HandedFresh"])
        add(f"R27-age-{fl}-nostep", "AgeFloor", dict(af, Floor=S(fl), MaxSteps=0),
            invs=["TypeOK", "NoFalseStale", "StaleCaught", "HandedFresh"])
    # R27 clock steps that stay (no one-chunk step; re-anchor on any chunk)
    for fl in ("confirm", "current", "confirm0"):
        for sh in ("ahead", "back"):
            c = dict(af, Floor=S(fl), MaxSteps=0, Shift=S(sh), Rolls=0,
                     MaxReanchor=12, SinceCap=12, DMax=4, WMax=0)
            add(f"R27-shift-{sh}-{fl}", "AgeFloor", c,
                invs=["TypeOK", "LivesAtOnce", "LivesAfterShift"])
            add(f"R27-shift-{sh}-{fl}-roll", "AgeFloor",
                dict(c, Rolls=1, MaxReanchor=1, SinceCap=2),
                invs=["TypeOK", "LivesAfterRoll"])
    # ---------------------------------------------------------------- R28
    eb = dict(C=4, RMin=2, RMax=8, VMax=4, S=2, LMax=24, FastT=8, LiftT=12,
              WMax=3, KWire=3, DebtMax=8, FloorDebit=S("all"))
    for deb in ("all", "floor_only"):
        add(f"R28-budget-{deb}", "EgressBudget", dict(eb, Floor=B(True), FloorDebit=S(deb)),
            invs=["TypeOK", "FirstWireWait", "AudioBeforeVideo", "VideoBeforeBulk",
                  "BulkWaitBound", "FloorDebtBounded", "WithinRate", "QueueBounded"],
            props=["BulkServed"])
    for kw in (4, 5, 6):
        add(f"R28-firstwait-k{kw}", "EgressBudget", dict(eb, Floor=B(True), KWire=kw),
            invs=["TypeOK", "FirstWireWait"])
    add("R28-budget-nofloor", "EgressBudget", dict(eb, Floor=B(False)),
        invs=["TypeOK", "BulkWaitBound"], props=["BulkServed"])
    # ---------------------------------------------------- R29 (second clause)
    ra = dict(Life=10, AMax=10, StaleB=8, Parent=3, HalfRtt=1)
    for keep in ("last", "max"):
        add(f"R29b-advert-{keep}", "RelayAdvert", dict(ra, Keep=S(keep)),
            invs=["TypeOK", "AdvOverParent", "AdvOverDrops", "AdvStillLate"])
    # ---------------------------------------------------------------- R30
    pt = dict(Period=5, Cap=12, Contacts=B(False), Anon=B(True), SilentTier=B(False),
              DirectNotify=B(False), FailNotify=B(False), TierNotify=B(False))
    pinv = ["TypeOK", "GatesEqual", "GatesEqualAlways", "DirectBound",
            "NoEscalationWhileFalse", "NoProposalWhileAnonymous", "RetryStops",
            "EscalationSettled", "ProposalSettled", "RetrySettled", "DirectSettled"]
    for code in ("fixed", "asbuilt"):
        for acc in ("room", "identified"):
            add(f"R30-{code}-{acc}", "PunchTrust", dict(pt, Code=S(code), Accept=S(acc)),
                invs=pinv)
    add("R30-fixed-room-silent", "PunchTrust",
        dict(pt, Code=S("fixed"), Accept=S("room"), SilentTier=B(True)), invs=pinv)
    add("R30-fixed-room-contacts", "PunchTrust",
        dict(pt, Code=S("fixed"), Accept=S("room"), Contacts=B(True), Anon=B(False)),
        invs=pinv)
    add("R30-fixed-room-roomonly", "PunchTrust",
        dict(pt, Code=S("fixed"), Accept=S("room"), Anon=B(False)), invs=pinv)
    add("R30-fixed-room-directnotify", "PunchTrust",
        dict(pt, Code=S("fixed"), Accept=S("room"), DirectNotify=B(True)), invs=pinv)
    # the three fixes sent to nat-reach, separately and together (with the
    # silent tier and one-way contacts in play)
    allin = dict(pt, Code=S("fixed"), Accept=S("room"), SilentTier=B(True), Contacts=B(True))
    for tag, fx in (("failnotify", dict(FailNotify=B(True))),
                    ("tiernotify", dict(TierNotify=B(True))),
                    ("directnotify2", dict(DirectNotify=B(True))),
                    ("allfixes", dict(FailNotify=B(True), TierNotify=B(True),
                                      DirectNotify=B(True)))):
        add(f"R30-fix-{tag}", "PunchTrust", dict(allin, **fx), invs=pinv)
    # ---------------------------------------------------------------- R31
    for rule in ("e356", "c1545", "stale", "both"):
        for liar in (False, True):
            c = dict(Rule=S(rule), USet="{0, 1, 2, 3}", LSet="{0, 1, 2, 3, 4}", GSet="{1, 2}",
                     CapEnd=32, H=90, Liar=B(liar),
                     ChunkCap=24, NCSet="{4, 8, 14}", SelfStamp=B(False))
            add(f"R31-{rule}{'-liar' if liar else ''}", "RoomStamps", c,
                invs=["ChildKeepsRelay", "RelayKeepsP", "LiarBounded", "StandbyKept"])
    for rule in ("e356", "both"):
        c = dict(Rule=S(rule), USet="{0, 1, 2, 3}", LSet="{0, 1, 2, 3, 4}", GSet="{1, 2}",
                 CapEnd=32, H=90, Liar=B(False), ChunkCap=24, NCSet="{4, 8, 14}",
                 SelfStamp=B(True))
        add(f"R31-{rule}-selfstamp", "RoomStamps", c,
            invs=["ChildKeepsRelay", "RelayKeepsP", "StandbyKept"])
    # ---------------------------------------------------------------- R32
    rb = dict(CapEnd=32, H=80, USet="{0, 1, 2, 3}", LSet="{0, 1, 2, 3, 4}", GSet="{1, 2}",
              DSet="{1}", RunSet="{1}", PauseSet="{0}", LapseRestarts=B(True),
              SelfStamp=B(False))
    for thr in (2, 1):
        add(f"R32-honest-thr{thr}", "RoomBuilt", dict(rb, Liar=B(False), ThrS=thr),
            invs=["MovedKeepsRelay", "RelayKeepsP"])
    add("R32-liar-only", "RoomBuilt", dict(rb, Liar=B(True), ThrS=2, CapEnd=0, H=120,
        DSet="{1, 2}", RunSet="{4, 8, 12, 16, 20, 24, 40}", PauseSet="{0, 4, 8, 10, 11, 12, 14}",
        USet="{0}", LSet="{0}", GSet="{1}"), invs=["LiarOnlyBound", "LiarGone"])
    add("R32-liar-only-nolapse", "RoomBuilt", dict(rb, Liar=B(True), ThrS=2, CapEnd=0, H=120,
        DSet="{1, 2}", RunSet="{4, 8, 12, 16, 20, 24, 40}", PauseSet="{0, 4, 8, 10, 11, 12, 14}",
        USet="{0}", LSet="{0}", GSet="{1}", LapseRestarts=B(False)),
        invs=["LiarOnlyBound", "LiarGone"])
    add("R32-honest-thr2-nolapse", "RoomBuilt", dict(rb, Liar=B(False), ThrS=2,
        LapseRestarts=B(False)), invs=["MovedKeepsRelay", "RelayKeepsP"])
    # ---------------------------------------------------------------- R33
    for order in ("fifo", "chatfirst"):
        for bound in (120, 40):
            add(f"R33-{order}-b{bound}", "BulkPacers",
                dict(RSet="{32, 64, 128}", SSet="{20, 75, 150}", Chat=10, NEnv=10, Lanes=1,
                     Order=S(order), Bound=bound, Ann=0),
                invs=["ChatWithin"])
    add("R33-fifo-announce", "BulkPacers",
        dict(RSet="{32, 64, 128}", SSet="{75}", Chat=10, NEnv=10, Lanes=1,
             Order=S("fifo"), Bound=400, Ann=3), invs=["ChatArrives"])
    # R32 against squash/45.3 as built: A (no lapse restart) + B (SelfStamp)
    asb = dict(rb, LapseRestarts=B(False), SelfStamp=B(True))
    add("R32abc-honest", "RoomBuilt", dict(asb, Liar=B(False), ThrS=2),
        invs=["MovedKeepsRelay", "RelayKeepsP"])
    add("R32abc-honest-g4", "RoomBuilt", dict(asb, Liar=B(False), ThrS=2, GSet="{3, 4}"),
        invs=["MovedKeepsRelay", "RelayKeepsP"])
    add("R32abc-liar-only", "RoomBuilt", dict(asb, Liar=B(True), ThrS=2, CapEnd=0, H=120,
        DSet="{1, 2}", RunSet="{4, 8, 12, 16, 20, 24, 40}", PauseSet="{0, 4, 8, 10, 11, 12, 14}",
        USet="{0}", LSet="{0}", GSet="{1}"), invs=["LiarOnlyBound", "LiarGone"])
