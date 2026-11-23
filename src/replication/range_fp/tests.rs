//! Range fingerprints, step A: the construction's known answers, the wire,
//! and the receiver's state machine (design §9 witnesses owned by step A).

use super::*;

fn x(i: u32) -> [u8; 32] {
    Sha256::digest(format!("ciris-rf-vector-{i}").as_bytes()).into()
}

fn kat_salt() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    s
}

/// The sender's side, as the reference: filter FIRST, then salt and sum
/// (R1). Every receiver answer below is checked against this.
fn sender_fp(
    plane: &str,
    prefix: &str,
    salt: &[u8; 32],
    set: &[[u8; 32]],
    exclude: &HashSet<[u8; 32]>,
    pk: &[String],
) -> (u64, String) {
    let mut acc = Acc::default();
    for h in set {
        if in_prefix(h, prefix) && !exclude.contains(h) && !pk.iter().any(|p| in_prefix(h, p)) {
            acc.add(&elem(salt, h));
        }
    }
    (acc.count(), hex::encode(node_fp(plane, prefix, &acc)))
}

fn fp_of(plane: &str, prefix: &str, salt: &[u8; 32], set: &[[u8; 32]]) -> String {
    sender_fp(plane, prefix, salt, set, &HashSet::new(), &[]).1
}

// ─── Witness 18: the FSD §3.4.2 known-answer vectors, byte for byte ─────

#[test]
fn known_answer_vectors_reproduce_fsd_3_4_2() {
    let s = kat_salt();
    let xs: Vec<[u8; 32]> = (0..4).map(x).collect();
    assert_eq!(
        hex::encode(xs[0]),
        "eb508c89d15536335c7c2009f9166e6577f2f4155bdbe8bb6dad116ff3946d29"
    );
    assert_eq!(
        hex::encode(xs[3]),
        "d5d55d7ae7725dd2775b8c038b8697f4adc99bef7f1b060dc9d2a62ee59246ee"
    );
    let mut e0 = Acc::default();
    e0.add(&elem(&s, &xs[0]));
    assert_eq!(
        hex::encode(e0.sum_le()),
        "3ce04fd7d2d80d6f15a18e1345cc6688ab54f0ea3a201bca8c5d78673d0d4d51"
    );
    assert_eq!(
        fp_of("key", "", &s, &[]),
        "424536b38733e31120b522bb3d906fef",
        "V1"
    );
    assert_eq!(
        fp_of("key", "", &s, &xs),
        "6b0ceedb4be4d229f583ab2129e78b17",
        "V2"
    );
    let mut v2 = Acc::default();
    for h in &xs {
        v2.add(&elem(&s, h));
    }
    assert_eq!(
        hex::encode(v2.sum_le()),
        "126990de50d21e21f249526b14de9adfb5233783ad5a369ec08beb8cf1403e07",
        "V2 wraps"
    );
    assert_eq!(
        fp_of("key", "e", &s, &xs),
        "f42b8c0a2585fe2c1abfe267731bb4e4",
        "V3"
    );
    assert_eq!(
        fp_of("identity_occurrence", "", &s, &xs),
        "4219528fc526b10ff80c4c3419bd9baf",
        "V4"
    );
    let mut s2 = [0u8; 32];
    for (i, b) in s2.iter_mut().enumerate() {
        *b = u8::try_from(i + 32).unwrap();
    }
    assert_eq!(
        fp_of("key", "", &s2, &xs),
        "b4f22081a2fd177ea367cd2d1f43fec2",
        "V5"
    );
    assert_eq!(
        fp_of("key", "", &s, &xs[..3]),
        "5ab8ad56d241203063179fdf44176e59",
        "V6"
    );
    assert_eq!(
        fp_of("key", "eb5", &s, &xs),
        "54b68f91e5e75e11a19a0b51808ea1c4",
        "V7"
    );
    assert_eq!(
        fp_of("key", "0", &s, &xs),
        "b54121e4e71812a2a2640c382ab3eddd",
        "V8"
    );
    assert_eq!(
        fp_of("key", "eb508c89", &s, &xs),
        "e732ee33209b5da52ff7f3b57d5f1e5a",
        "V9"
    );
    assert_eq!(hex::encode(salt_tag(&s)), "5b816966", "T1");
}

#[test]
fn tag_lengths_are_the_fsds() {
    assert_eq!(ELEM_TAG.len(), 16);
    assert_eq!(NODE_TAG.len(), 16);
    assert_eq!(SALT_TAG_TAG.len(), 15);
}

#[test]
fn add_then_sub_is_identity_and_wraps() {
    let s = kat_salt();
    let mut a = Acc::default();
    for i in 0..50 {
        a.add(&elem(&s, &x(i)));
    }
    let before = a;
    let e = elem(&s, &x(999));
    a.add(&e);
    a.sub(&e);
    assert_eq!(a, before);
    let mut z = Acc::default();
    z.sub(&e);
    z.add(&e);
    assert_eq!(z, Acc::default());
}

#[test]
fn prefix_bounds_cover_exactly_the_prefix() {
    for p in ["", "0", "e", "f", "eb", "ff", "3f2", "fff", "eb508c89"] {
        let (lo, hi) = prefix_bounds(p);
        for i in 0..2000 {
            let h = x(i);
            let inside = h >= lo && hi.is_none_or(|hi| h < hi);
            assert_eq!(
                inside,
                in_prefix(&h, p),
                "prefix {p} hash {}",
                hex::encode(h)
            );
        }
    }
    assert_eq!(prefix_bounds("ff").1, None);
}

// ─── The wire (witness 4, the lenient member, the compact decode) ───────

#[test]
fn rf_summary_round_trips_and_marker_is_small() {
    let m = RfSummary::marker("AAAAAAAAAAA", true);
    let j = serde_json::to_string(&m).unwrap();
    assert_eq!(j, r#"{"v":1,"ep":"AAAAAAAAAAA","e":1}"#);
    let back: RfSummary = serde_json::from_str(&j).unwrap();
    assert_eq!(back, m);
    assert!(!back.is_fingerprinted());
}

#[test]
fn compact_hashes_and_bodies_round_trip() {
    let hs: Vec<[u8; 32]> = (0..5).map(x).collect();
    let enc = encode_compact_hashes(&hs);
    assert_eq!(enc.len(), (5usize * 32 * 4).div_ceil(3));
    assert_eq!(decode_compact_hashes(&enc), hs);
    let before = RF_COMPACT_DECODE_FAILED.load(Ordering::Relaxed);
    assert!(decode_compact_hashes("not base64!!").is_empty());
    // 31 bytes: not a whole number of hashes.
    assert!(decode_compact_hashes(&b64().encode([7u8; 31])).is_empty());
    assert!(RF_COMPACT_DECODE_FAILED.load(Ordering::Relaxed) >= before + 2);
    let body = br#"{"attestation":{"attestation_id":"a"}}"#;
    assert_eq!(
        decode_compact_body(&encode_compact_body(body)).unwrap(),
        body.to_vec()
    );
}

#[test]
fn process_epoch_is_stable_within_a_process() {
    assert_eq!(process_epoch(), process_epoch());
    assert_eq!(b64().decode(process_epoch()).unwrap().len(), 8);
}

// ─── The receiver ───────────────────────────────────────────────────────

const PEER: &str = "peer-a";

/// A reference SENDER: fingerprints over exactly its offer, filtered first
/// and salted second (R1), the head rows and parked ranges left out.
struct Sender {
    salt: [u8; 32],
    ep: String,
    sid: u32,
    plane: EnvelopeKind,
}

impl Sender {
    fn new(seed: u8, plane: EnvelopeKind) -> Self {
        Self {
            salt: [seed; 32],
            ep: format!("ep{seed}"),
            sid: 7,
            plane,
        }
    }

    /// An RF Summary over `set` with `nodes` (prefixes), carrying `head` as
    /// head rows and listing the `lc` ranges completely.
    fn summary(
        &mut self,
        set: &[[u8; 32]],
        nodes: &[&str],
        head: &[[u8; 32]],
        lc: &[&str],
    ) -> (RfSummary, Vec<EnvelopeRef>) {
        self.summary_pk(set, nodes, head, lc, &[])
    }

    fn summary_pk(
        &mut self,
        set: &[[u8; 32]],
        nodes: &[&str],
        head: &[[u8; 32]],
        lc: &[&str],
        pk: &[String],
    ) -> (RfSummary, Vec<EnvelopeRef>) {
        self.sid = self.sid.wrapping_add(1);
        let exclude: HashSet<[u8; 32]> = head.iter().copied().collect();
        let plane = self.plane.as_wire_str();
        let n = nodes
            .iter()
            .map(|p| {
                let (c, f) = sender_fp(plane, p, &self.salt, set, &exclude, pk);
                ((*p).to_owned(), c, f)
            })
            .collect();
        let mut refs: Vec<EnvelopeRef> = head
            .iter()
            .map(|h| EnvelopeRef {
                envelope_hash: *h,
                seq: 0,
            })
            .collect();
        for p in lc {
            refs.extend(set.iter().filter(|h| in_prefix(h, p)).map(|h| EnvelopeRef {
                envelope_hash: *h,
                seq: 0,
            }));
        }
        let rf = RfSummary {
            v: RF_VERSION,
            a: Some(ALG_SALTED_SUM),
            ep: Some(self.ep.clone()),
            salt: Some(encode_salt(&self.salt)),
            sid: Some(self.sid),
            n,
            lc: lc.iter().map(|p| (*p).to_owned()).collect(),
            pk: pk.to_vec(),
            ..RfSummary::default()
        };
        (rf, refs)
    }
}

/// B's view: which hashes it holds, refuses for now (`suppressed`), holds
/// only as equivalents, or knows by hash only; everything else it wants.
#[derive(Default)]
struct Bview {
    held: HashSet<[u8; 32]>,
    suppressed: HashSet<[u8; 32]>,
    equivalent: HashSet<[u8; 32]>,
    ready: bool,
    feed: bool,
}

impl Bview {
    fn holding(held: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            held: held.into_iter().collect(),
            ready: true,
            ..Self::default()
        }
    }

    fn wants(&self, refs: &[EnvelopeRef]) -> (HashSet<[u8; 32]>, HashSet<[u8; 32]>) {
        let raw: HashSet<[u8; 32]> = refs
            .iter()
            .map(|r| r.envelope_hash)
            .filter(|h| !self.held.contains(h) && !self.equivalent.contains(h))
            .collect();
        let fin: HashSet<[u8; 32]> = raw
            .iter()
            .filter(|h| !self.suppressed.contains(*h))
            .copied()
            .collect();
        (raw, fin)
    }
}

#[allow(clippy::too_many_arguments)] // one inbound Summary, as the bridge hands it
fn answer_as(
    rx: &mut RfReceiver,
    peer: &str,
    kind: EnvelopeKind,
    rf: &RfSummary,
    refs: &[EnvelopeRef],
    b: &Bview,
    seed: Option<&[[u8; 32]]>,
    now: Instant,
) -> RxAnswer {
    let (raw, fin) = b.wants(refs);
    rx.answer(&RxInput {
        peer,
        kind,
        rf,
        refs,
        raw_want: &raw,
        final_want: &fin,
        held_equivalent: &|h| b.equivalent.contains(h),
        still_settled: &|h| b.suppressed.contains(h) || b.equivalent.contains(h),
        ready: b.ready,
        seed,
        feed: b.feed,
        page: 1024,
        now,
    })
}

fn answer(
    rx: &mut RfReceiver,
    s: &Sender,
    rf: &RfSummary,
    refs: &[EnvelopeRef],
    b: &Bview,
    now: Instant,
) -> RxAnswer {
    answer_as(rx, PEER, s.plane, rf, refs, b, None, now)
}

fn ids(n: u32) -> Vec<[u8; 32]> {
    (0..n).map(x).collect()
}

fn root() -> Vec<String> {
    vec![String::new()]
}

/// Witness 19 (asymmetric sets, finding 1): A offers 50, B holds those 50 and
/// 30,000 more, on `Key` and on `Revocation`. After A lists the plane
/// completely once, the root matches and stays matched for 50 idle rounds
/// with zero listed refs; B's mirror is never larger than what A listed.
#[test]
fn asymmetric_sets_converge_and_the_mirror_holds_only_what_a_listed_19() {
    for plane in [EnvelopeKind::Key, EnvelopeKind::Revocation] {
        let mut rx = RfReceiver::new();
        let mut a = Sender::new(1, plane);
        let offer = ids(50);
        let b = Bview::holding((0..30_050).map(x));
        let now = Instant::now();
        // Round 1: an empty mirror; the root differs and, at 50 rows, is listed.
        let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert!(ans.diff.m.is_empty());
        assert_eq!(ans.diff.l, root(), "50 ≤ a page, none of it in M: list");
        // Round 2: A lists the root completely.
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert_eq!(ans.diff.m, root(), "the listed range matches once settled");
        assert_eq!(rx.mirror_stats(PEER, plane).ids, 50);
        for _ in 0..50 {
            let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
            assert!(refs.is_empty());
            assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
        }
        assert_eq!(rx.mirror_stats(PEER, plane).ids, 50, "{plane:?}");
    }
}

/// The reverse case: A offers 3,000, B holds 50 of them. The root differs and
/// is split (larger than a page), never listed (R14, witness 25).
#[test]
fn a_range_larger_than_a_page_is_split_never_listed_25() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(2, EnvelopeKind::Key);
    let offer = ids(3_000);
    let b = Bview::holding(offer.iter().take(50).copied());
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.s, root());
    assert!(ans.diff.l.is_empty());
    // Under a page, a range B holds more than half of is split; at most 16
    // rows, or at most half held, it is listed.
    let offer = ids(100);
    let mut rx = RfReceiver::new();
    let b = Bview::holding(offer.iter().copied());
    let (rf, refs) = a.summary(&offer[..60], &[""], &[], &[""]);
    let _ = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.s, root(), "B holds 60 of 100 in M: split");
    let (rf, refs) = a.summary(&offer[..61], &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.s, root(), "61 rows, 60 of them in M");
}

/// Finding 11 / N3 / witness 32: a head row B lacks does not make the root
/// differ; a listed range is NOT subtracted, so a listed range B lacks part
/// of (a lost Deliver) stays open in the Summary that lists it.
#[test]
fn head_rows_are_subtracted_and_listed_ranges_are_not_n3() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(3, EnvelopeKind::Key);
    let offer = ids(40);
    let b = Bview::holding(offer.iter().copied());
    let now = Instant::now();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
    let new = x(10_000);
    let mut offer2 = offer.clone();
    offer2.push(new);
    let (rf, refs) = a.summary(&offer2, &[""], &[new], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
    assert_eq!(ans.diff.m, root(), "the head row is compared by the Diff");
    // A head row B already holds is subtracted on both sides too.
    let held_head = offer[0];
    let (rf, refs) = a.summary(&offer, &[""], &[held_head], &[]);
    assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
    let mut rx2 = RfReceiver::new();
    let mut a2 = Sender::new(4, EnvelopeKind::Key);
    let b2 = Bview::holding(offer.iter().take(30).copied());
    let (rf, refs) = a2.summary(&offer, &[""], &[], &[""]);
    let ans = answer(&mut rx2, &a2, &rf, &refs, &b2, now);
    assert!(
        ans.diff.m.is_empty(),
        "a listed range with a lost Deliver stays open"
    );
    // The next Summary re-lists the remainder; once admitted, it matches.
    for h in &offer[30..] {
        rx2.note_settled(PEER, EnvelopeKind::Key, &[*h]);
    }
    let (rf, refs) = a2.summary(&offer, &[""], &[], &[]);
    assert_eq!(answer(&mut rx2, &a2, &rf, &refs, &b2, now).diff.m, root());
}

/// **Fake ids never fill the mirror** (R21 / N6 / witness 33). A hostile peer
/// lists 10^6 made-up ids; its mirror grows by zero, its pending ids stay
/// within their own budgets, and an honest pair's mirror can still take every
/// id it settles: the node-wide mirror cap is untouched.
///
/// Mutation that turns it red: count pending ids against the mirror's
/// node-wide cap, or insert a wanted id into the mirror.
#[test]
fn fake_ids_never_fill_the_mirror_33() {
    let mut rx = RfReceiver::new();
    let b = Bview::holding(std::iter::empty());
    let now = Instant::now();
    // Sybils: 40 peers × 25,000 fakes = 10^6 made-up ids.
    for s in 0..40u32 {
        let mut a = Sender::new(u8::try_from(s % 250).unwrap(), EnvelopeKind::Key);
        let fakes: Vec<[u8; 32]> = (0..25_000).map(|i| x(1_000_000 + s * 25_000 + i)).collect();
        let peer = format!("sybil-{s}");
        let (rf, refs) = a.summary(&fakes, &[""], &fakes, &[]);
        let ans = answer_as(&mut rx, &peer, a.plane, &rf, &refs, &b, None, now);
        assert!(ans.diff.u.is_none(), "{:?}", ans.diff.u);
        let st = rx.mirror_stats(&peer, EnvelopeKind::Key);
        assert_eq!(st.ids, 0, "no fake id takes a mirror slot");
        assert!(st.pending <= RF_PENDING_CAP_PAIR);
    }
    assert_eq!(rx.mirror_total(), 0);
    assert!(rx.pending_total() <= RF_PENDING_CAP_NODE);
    // An honest pair settles 20,000 real rows: every one enters, no `cap`.
    let mut honest = Sender::new(251, EnvelopeKind::Key);
    let real = ids(20_000);
    let hb = Bview::holding(real.iter().copied());
    let (rf, refs) = honest.summary(&real, &[""], &[], &[""]);
    let ans = answer_as(
        &mut rx,
        "honest",
        EnvelopeKind::Key,
        &rf,
        &refs,
        &hb,
        None,
        now,
    );
    assert!(ans.diff.u.is_none(), "{:?}", ans.diff.u);
    assert_eq!(ans.diff.m, root());
    assert_eq!(rx.mirror_stats("honest", EnvelopeKind::Key).ids, 20_000);
    // With the pending budget spent by the sybils, an honest wanted id is not
    // tracked; it costs a round, never a row: once held, its next listing
    // puts it in the mirror.
    let late = x(4_000_000);
    let mut lb = Bview::holding(real.iter().copied());
    let (rf, refs) = honest.summary(&[late], &["0"], &[late], &[]);
    let _ = answer_as(
        &mut rx,
        "honest",
        EnvelopeKind::Key,
        &rf,
        &refs,
        &lb,
        None,
        now,
    );
    assert!(!rx.note_settled("honest", EnvelopeKind::Key, &[late]));
    lb.held.insert(late);
    let (rf, refs) = honest.summary(&[late], &["0"], &[late], &[]);
    let _ = answer_as(
        &mut rx,
        "honest",
        EnvelopeKind::Key,
        &rf,
        &refs,
        &lb,
        None,
        now,
    );
    assert!(rx.mirror_contains("honest", EnvelopeKind::Key, &late));
    // A wanted id enters when admitted from the peer that listed it, never
    // from another, and pending ids are forgotten after their time.
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(252, EnvelopeKind::Key);
    let want = [x(5_000_000), x(5_000_001)];
    let (rf, refs) = a.summary(&want, &[""], &want, &[]);
    let _ = answer_as(
        &mut rx,
        "lister",
        EnvelopeKind::Key,
        &rf,
        &refs,
        &b,
        None,
        now,
    );
    assert!(!rx.note_settled("someone-else", EnvelopeKind::Key, &[want[0]]));
    assert!(rx.note_settled("lister", EnvelopeKind::Key, &[want[0]]));
    assert!(rx.mirror_contains("lister", EnvelopeKind::Key, &want[0]));
    let (rf, refs) = a.summary(&want, &[""], &[], &[]);
    let _ = answer_as(
        &mut rx,
        "lister",
        EnvelopeKind::Key,
        &rf,
        &refs,
        &b,
        None,
        now + RF_PENDING_TTL + Duration::from_secs(1),
    );
    assert_eq!(rx.mirror_stats("lister", EnvelopeKind::Key).pending, 0);
    assert!(!rx.note_settled("lister", EnvelopeKind::Key, &[want[1]]));
}

/// `lc` replaces the range, an older `lc` cannot undo a newer one, and a
/// restarted sender (a new `ep`, whose `sid`s start afresh) is not held to
/// the old process's order.
#[test]
fn lc_replaces_and_reordered_lc_is_ignored() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(6, EnvelopeKind::Key);
    let offer = ids(20);
    let b = Bview::holding((0..20).map(x));
    let now = Instant::now();
    let (old_rf, old_refs) = a.summary(&offer, &[""], &[], &[""]);
    let smaller: Vec<[u8; 32]> = offer[5..].to_vec();
    let (new_rf, new_refs) = a.summary(&smaller, &[""], &[], &[""]);
    assert_eq!(
        answer(&mut rx, &a, &new_rf, &new_refs, &b, now).diff.m,
        root()
    );
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).ids, 15);
    let ans = answer(&mut rx, &a, &old_rf, &old_refs, &b, now);
    assert!(
        ans.diff.m.is_empty(),
        "the old fingerprint is of the old set"
    );
    assert_eq!(
        rx.mirror_stats(PEER, EnvelopeKind::Key).ids,
        15,
        "it taught nothing"
    );
    let (rf, refs) = a.summary(&smaller, &[""], &[], &[]);
    assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
    // The sender restarts: new `ep` and salt, and its `sid`s start BELOW the
    // old ones. Its complete listing still replaces the range.
    a.ep = "restarted".into();
    a.salt = [60; 32];
    a.sid = 1;
    let (rf, refs) = a.summary(&offer[10..], &[""], &[], &[""]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, now + Duration::from_secs(1));
    assert_eq!(ans.diff.m, root(), "{:?}", ans.diff);
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).ids, 10);
}

/// R16 / witness 27, 30: a new salt under the same `ep` is refused within 10
/// min (`u:salt`), accepted after; a new `ep` (a restarted sender) is accepted
/// at once; the bucket bounds rebuilds (`u:busy`); a refusal teaches nothing.
#[test]
fn salt_changes_follow_the_rules_27_30() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(7, EnvelopeKind::Key);
    let offer = ids(10);
    let b = Bview::holding(offer.iter().copied());
    let t0 = Instant::now();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    assert!(answer(&mut rx, &a, &rf, &refs, &b, t0).diff.u.is_none());
    a.salt = [8; 32];
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(1));
    assert_eq!(ans.diff.u.as_deref(), Some("salt"));
    assert_eq!(ans.flags.unable, Some(Unable::Salt));
    assert!(ans.diff.m.is_empty() && ans.diff.s.is_empty() && ans.diff.l.is_empty());
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(11));
    assert!(ans.diff.u.is_none());
    assert!(ans.flags.salt_changed);
    assert_eq!(ans.diff.m, root(), "the mirror re-salted matches");
    // A restarted sender, unseen: new ep and salt one minute later, accepted.
    a.salt = [9; 32];
    a.ep = "restarted".into();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(12));
    assert!(ans.diff.u.is_none(), "{:?}", ans.diff.u);
    assert_eq!(ans.diff.m, root());
    // Churn: every Summary a new ep and salt. Three tokens spent, one more
    // refilled by now at most: at most one more is accepted.
    let mut busy = 0;
    for i in 0..10u8 {
        a.salt = [100 + i; 32];
        a.ep = format!("churn{i}");
        let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(13));
        if ans.diff.u.as_deref() == Some("busy") {
            busy += 1;
            assert_eq!(ans.flags.unable, Some(Unable::Busy));
        }
    }
    assert!(busy >= 9, "at most the refilled token is spent: {busy}");
    // Twenty minutes on, one token is back.
    a.salt = [200; 32];
    a.ep = "later".into();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(34));
    assert!(ans.diff.u.is_none(), "{:?}", ans.diff.u);
}

/// A rotation the sender rolls out plane by plane (design §6.4: "the old salt
/// stays in use until [the new sums] are ready"): a plane still under the
/// previous salt is answered under it, costing no token and no `u`; a plane
/// that already moved refuses an old-salt Summary.
#[test]
fn a_rotation_rolls_out_plane_by_plane_without_u() {
    let mut rx = RfReceiver::new();
    let offer = ids(10);
    let b = Bview::holding(offer.iter().copied());
    let t0 = Instant::now();
    let mut key = Sender::new(20, EnvelopeKind::Key);
    let mut rev = Sender::new(20, EnvelopeKind::Revocation);
    for s in [&mut key, &mut rev] {
        let (rf, refs) = s.summary(&offer, &[""], &[], &[""]);
        assert_eq!(answer(&mut rx, s, &rf, &refs, &b, t0).diff.m, root());
    }
    let later = t0 + Duration::from_mins(61);
    key.salt = [21; 32];
    let (rf, refs) = key.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &key, &rf, &refs, &b, later);
    assert!(ans.flags.salt_changed);
    assert_eq!(ans.diff.m, root());
    let (rf, refs) = rev.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &rev, &rf, &refs, &b, later);
    assert!(
        ans.diff.u.is_none(),
        "the previous salt still answers: {:?}",
        ans.diff.u
    );
    assert_eq!(ans.diff.m, root());
    let mut old_key = Sender::new(20, EnvelopeKind::Key);
    let (rf, refs) = old_key.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &old_key, &rf, &refs, &b, later);
    assert_eq!(ans.diff.u.as_deref(), Some("salt"), "Key already moved on");
}

/// N7 / witness 17: a salted Summary that arrived over a non-confidential
/// transport is refused and its salt never used: nothing is learned.
#[test]
fn a_salt_over_a_non_confidential_transport_is_never_used_17() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(10, EnvelopeKind::Key);
    let offer = ids(10);
    let b = Bview::holding(offer.iter().copied());
    let (mut rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    rf.transport_refused = true;
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.u.as_deref(), Some("transport"));
    assert_eq!(ans.diff.sid, rf.sid);
    assert_eq!(
        rx.mirror_stats(PEER, EnvelopeKind::Key).ids,
        0,
        "nothing learned"
    );
    assert_eq!(rx.peers(), 0, "no salt state either");
}

/// R8: a holdings index that is not `Ready` answers `u:"unbooted"` and
/// learns nothing.
#[test]
fn an_unready_index_answers_unbooted_and_learns_nothing() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(11, EnvelopeKind::Key);
    let offer = ids(10);
    let mut b = Bview::holding(offer.iter().copied());
    b.ready = false;
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.u.as_deref(), Some("unbooted"));
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).ids, 0);
}

/// N5 / witness 27: an honest 16-split Summary, 256 child fingerprints, is
/// never `u:cap`; more records, nodes, parked or listed ranges than the caps
/// are.
#[test]
fn the_node_cap_counts_split_children_only_against_the_split_cap_n5() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(12, EnvelopeKind::Key);
    let offer = ids(5_000);
    let b = Bview::holding(offer.iter().copied());
    let (mut rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let plane = a.plane.as_wire_str();
    rf.c = (0..16u32)
        .map(|top| {
            let parent = format!("{top:x}");
            let mut counts = Vec::new();
            let mut fps = String::new();
            for digit in 0..16u32 {
                let child = format!("{parent}{digit:x}");
                let (count, fp) = sender_fp(plane, &child, &a.salt, &offer, &HashSet::new(), &[]);
                counts.push(count);
                fps.push_str(&fp);
            }
            (parent, counts, fps)
        })
        .collect();
    let now = Instant::now();
    let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
    assert!(ans.diff.u.is_none(), "{:?}", ans.diff.u);
    assert_eq!(
        ans.diff.m.len() + ans.diff.s.len() + ans.diff.l.len(),
        1 + 256
    );
    let mut over = rf.clone();
    over.c.push(over.c[0].clone());
    assert_eq!(
        answer(&mut rx, &a, &over, &refs, &b, now).diff.u.as_deref(),
        Some("cap")
    );
    let mut over = rf.clone();
    over.n = (0..=RX_MAX_NODES)
        .map(|i| (format!("{i:x}"), 0, "00".repeat(16)))
        .collect();
    assert_eq!(
        answer(&mut rx, &a, &over, &refs, &b, now).diff.u.as_deref(),
        Some("cap")
    );
    let mut over = rf.clone();
    over.pk = (0..=RX_MAX_PARKED).map(|i| format!("{i:03x}")).collect();
    assert_eq!(
        answer(&mut rx, &a, &over, &refs, &b, now).diff.u.as_deref(),
        Some("cap")
    );
    let mut over = rf;
    over.lc = (0..=RX_MAX_NODES).map(|i| format!("{i:03x}")).collect();
    let ans = answer(&mut rx, &a, &over, &refs, &b, now);
    assert_eq!(ans.flags.unable, Some(Unable::Cap));
    assert!(!ans.flags.mirror_capped);
}

/// A member this build cannot read is no `rf` (design §2.5): an unknown `v`
/// or `a`, a missing `sid`, a bad salt or prefix. The answer carries no
/// `sid`, no `st` and no answers — the plain marker — and is counted.
#[test]
fn an_unreadable_member_is_answered_with_the_plain_marker() {
    let mut a = Sender::new(13, EnvelopeKind::Key);
    let offer = ids(4);
    let b = Bview::holding(offer.iter().copied());
    let (good, refs) = a.summary(&offer, &[""], &[], &[""]);
    let bad: Vec<RfSummary> = vec![
        RfSummary {
            v: 2,
            ..good.clone()
        },
        RfSummary {
            a: Some(2),
            ..good.clone()
        },
        RfSummary {
            sid: None,
            ..good.clone()
        },
        RfSummary {
            salt: Some("short".into()),
            ..good.clone()
        },
        RfSummary {
            n: vec![("XY".into(), 0, String::new())],
            ..good.clone()
        },
        RfSummary {
            lc: vec!["g".into()],
            ..good.clone()
        },
        RfSummary {
            c: vec![("0".into(), vec![0; 15], String::new())],
            ..good.clone()
        },
    ];
    for rf in &bad {
        let mut rx = RfReceiver::new();
        let before = RF_PARSE_FAILED.load(Ordering::Relaxed);
        let ans = answer(&mut rx, &a, rf, &refs, &b, Instant::now());
        assert!(ans.flags.not_understood, "{rf:?}");
        assert_eq!((ans.diff.sid, ans.diff.st.as_ref()), (None, None));
        assert!(ans.diff.m.is_empty() && ans.diff.u.is_none());
        assert!(RF_PARSE_FAILED.load(Ordering::Relaxed) > before);
        assert_eq!(rx.peers(), 0, "nothing learned");
    }
}

/// The answers echo `sid` and `st`, the salt tag (R10, R17).
#[test]
fn answers_echo_sid_and_salt_tag_17() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(14, EnvelopeKind::Key);
    let offer = ids(5);
    let b = Bview::holding(offer.iter().copied());
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, Instant::now());
    assert_eq!(ans.diff.sid, rf.sid);
    assert_eq!(
        ans.diff.st.as_deref(),
        Some(hex::encode(salt_tag(&a.salt)).as_str())
    );
    assert_eq!(ans.diff.ep.as_deref(), Some(process_epoch()));
    assert_eq!(ans.diff.e, Some(1), "this node decodes the compact form");
}

/// **A refusal whose backoff ends mid-window is wanted at the next compare**
/// (the exact `still_settled` re-check, design §3.2). While the refusal is in
/// backoff — even for half an hour — the row is in `T_B` and the range
/// matches; the moment the backoff ends, the next compare sees the range
/// differ, and the row, listed again, is wanted (pending), not a member.
///
/// Mutation that turns it red: drop the `still_settled` sweep (the row would
/// stay matched), or put a TTL on provisional members (the range would reopen
/// while still refused).
#[test]
fn a_refusal_whose_backoff_ends_mid_ttl_is_wanted_at_the_next_compare() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(17, EnvelopeKind::Key);
    let offer = ids(8);
    let refused = offer[0];
    let mut b = Bview::holding(offer[1..].iter().copied());
    b.suppressed.insert(refused);
    let t0 = Instant::now();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, t0).diff.m, root());
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).provisional, 1);
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(30));
    assert_eq!(
        ans.diff.m,
        root(),
        "still refused: still settled, still matched"
    );
    b.suppressed.clear();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(31));
    assert!(
        ans.diff.m.is_empty(),
        "the root differs at the next compare: {:?}",
        ans.diff
    );
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).provisional, 0);
    assert!(!rx.mirror_contains(PEER, EnvelopeKind::Key, &refused));
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let _ = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(31));
    assert!(!rx.mirror_contains(PEER, EnvelopeKind::Key, &refused));
    assert_eq!(rx.mirror_stats(PEER, EnvelopeKind::Key).pending, 1);
    // A held row that later becomes a held-equivalent only is re-judged the
    // same way: provisional while remembered, out when forgotten.
    let eq = offer[1];
    b.held.remove(&eq);
    b.equivalent.insert(eq);
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let _ = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(32));
    assert!(rx.mirror_contains(PEER, EnvelopeKind::Key, &eq));
    b.equivalent.clear();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
    let _ = answer(&mut rx, &a, &rf, &refs, &b, t0 + Duration::from_mins(33));
    assert!(!rx.mirror_contains(PEER, EnvelopeKind::Key, &eq));
}

/// R13: on the removal planes the settled set is the HOLDINGS only. A refused
/// (backed-off) revocation and a held-equivalent one never enter the mirror,
/// so the range that holds one never matches while B lacks it; a held one
/// does, and an admitted one enters.
#[test]
fn removal_planes_settle_holdings_only_r13() {
    for plane in [
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
    ] {
        let mut rx = RfReceiver::new();
        let mut a = Sender::new(30, plane);
        let offer = ids(6);
        let mut b = Bview::holding(offer[2..].iter().copied());
        b.suppressed.insert(offer[0]);
        b.equivalent.insert(offer[1]);
        let now = Instant::now();
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert!(ans.diff.m.is_empty(), "{plane:?}: B does not hold it");
        assert!(!rx.mirror_contains(PEER, plane, &offer[0]));
        assert!(!rx.mirror_contains(PEER, plane, &offer[1]));
        assert_eq!(rx.mirror_stats(PEER, plane).provisional, 0);
        assert_eq!(rx.mirror_stats(PEER, plane).ids, 4);
        for _ in 0..3 {
            let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
            assert!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m.is_empty());
        }
        // The refusal ends and B admits it; the equivalent becomes a holding.
        b.suppressed.clear();
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        let _ = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert!(rx.note_settled(PEER, plane, &[offer[0]]));
        b.equivalent.clear();
        b.held.extend([offer[0], offer[1]]);
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
    }
}

/// R24 / witness 34: the restart seed is holdings-only, public planes only,
/// once per sender `ep`, and only under the half rule. A seeded receiver
/// matches an offer equal to its holdings at once.
#[test]
fn the_restart_seed_is_holdings_only_and_public_planes_only_34() {
    let holdings = ids(1_000);
    let b = Bview::holding(holdings.iter().copied());
    let now = Instant::now();
    let mut rx = RfReceiver::new();
    assert!(!rx.wants_seed(PEER, EnvelopeKind::IdentityOccurrence));
    assert!(!rx.wants_seed(PEER, EnvelopeKind::TransportDestination));
    assert!(rx.wants_seed(PEER, EnvelopeKind::Key));
    // Not a public plane: offered holdings are ignored.
    let mut io = Sender::new(40, EnvelopeKind::IdentityOccurrence);
    let (rf, refs) = io.summary(&holdings, &[""], &[], &[]);
    let ans = answer_as(
        &mut rx,
        PEER,
        io.plane,
        &rf,
        &refs,
        &b,
        Some(&holdings),
        now,
    );
    assert_eq!(ans.flags.seeded, 0);
    // Half rule: the sender offers 100, B holds 1,000: no seed, and not again.
    let mut a = Sender::new(41, EnvelopeKind::Key);
    let (rf, refs) = a.summary(&holdings[..100], &[""], &[], &[]);
    let ans = answer_as(&mut rx, PEER, a.plane, &rf, &refs, &b, Some(&holdings), now);
    assert_eq!(ans.flags.seeded, 0);
    assert!(!rx.wants_seed(PEER, EnvelopeKind::Key), "once per ep");
    // A new receiver, a sender offering the whole plane: seeded, matched.
    let mut rx = RfReceiver::new();
    let (rf, refs) = a.summary(&holdings, &[""], &[], &[]);
    let ans = answer_as(&mut rx, PEER, a.plane, &rf, &refs, &b, Some(&holdings), now);
    assert_eq!(ans.flags.seeded, 1_000);
    assert_eq!(ans.diff.m, root(), "one round, no listing");
    assert!(
        !rx.wants_seed(PEER, EnvelopeKind::Key),
        "not into a full mirror"
    );
    // A seeded id the sender does not offer makes the root differ until its
    // `lc` prunes it.
    let (rf, refs) = a.summary(&holdings[1..], &[""], &[], &[]);
    assert!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m.is_empty());
    let (rf, refs) = a.summary(&holdings[1..], &[""], &[], &[""]);
    assert_eq!(answer(&mut rx, &a, &rf, &refs, &b, now).diff.m, root());
}

/// N2: parked ranges (`pk`) are left out of every ancestor's sum on both
/// sides; overlapping and duplicated parked ranges are left out once; a node
/// inside a parked range sums nothing.
#[test]
fn parked_ranges_are_left_out_of_ancestors_n2() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(15, EnvelopeKind::Key);
    let offer = ids(64);
    let hx = hex::encode(offer[0]);
    let parked = hx[..3].to_owned();
    let b = Bview::holding(offer.iter().filter(|h| !in_prefix(h, &parked)).copied());
    let now = Instant::now();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let _ = answer(&mut rx, &a, &rf, &refs, &b, now);
    for pk in [
        vec![parked.clone()],
        vec![parked.clone(), parked.clone()],
        vec![hx[..2].to_owned(), parked.clone(), hx[..4].to_owned()],
    ] {
        let first = &hx[..1];
        let (rf, refs) = a.summary_pk(&offer, &["", first, &hx[..3]], &[], &[], &pk);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert_eq!(ans.diff.m.len(), 3, "{pk:?}: {:?}", ans.diff);
    }
}

/// R1 receiver side, R7, witness 15: the receiver's fingerprint equals the
/// filter-first reference over `settled ∩ M − H` at every depth, with the
/// bucket sums (a large mirror) and without them (a small one).
#[test]
fn receiver_sums_equal_the_filter_first_reference_15() {
    for n in [2_000u32, 300] {
        let mut rx = RfReceiver::new();
        let mut a = Sender::new(16, EnvelopeKind::Key);
        let offer = ids(n);
        let held: HashSet<[u8; 32]> = offer
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 7 != 0)
            .map(|(_, h)| *h)
            .collect();
        let b = Bview::holding(held.iter().copied());
        let now = Instant::now();
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        let _ = answer(&mut rx, &a, &rf, &refs, &b, now);
        let b_set: Vec<[u8; 32]> = offer
            .iter()
            .filter(|h| held.contains(*h))
            .copied()
            .collect();
        for p in ["", "0", "a", "3f", "c7", "e21", "ffff"] {
            let head_rows = [b_set[3]];
            let (rf, refs) = a.summary(&b_set, &[p], &head_rows, &[]);
            let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
            assert_eq!(ans.diff.m, vec![p.to_owned()], "n {n} prefix {p}");
        }
    }
}

/// R3 / §5.7: the receiver's match feed carries the compared snapshot
/// `T_B ∩ p − H`, once per change of the matched set, never once per round.
#[test]
fn the_match_feed_fires_once_per_change() {
    let mut rx = RfReceiver::new();
    let mut a = Sender::new(18, EnvelopeKind::Key);
    let offer = ids(30);
    let mut b = Bview::holding(offer.iter().copied());
    b.feed = true;
    let now = Instant::now();
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
    assert_eq!(ans.matched.len(), 1);
    assert_eq!(ans.matched[0].1.len(), 30);
    for _ in 0..5 {
        let (rf, refs) = a.summary(&offer, &[""], &[], &[]);
        let ans = answer(&mut rx, &a, &rf, &refs, &b, now);
        assert_eq!(ans.diff.m, root());
        assert!(ans.matched.is_empty(), "nothing changed: nothing booked");
    }
    // The set changes: booked again, over the compared ids, head rows left out.
    let more = ids(31);
    let mut b2 = Bview::holding(more.iter().copied());
    b2.feed = true;
    let (rf, refs) = a.summary(&more, &[""], &[], &[""]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b2, now);
    assert_eq!(ans.matched[0].1.len(), 31);
    let (rf, refs) = a.summary(&more, &[""], &[more[0]], &[]);
    let ans = answer(&mut rx, &a, &rf, &refs, &b2, now);
    assert_eq!(ans.matched[0].1.len(), 30, "the head row is not booked");
    assert!(!ans.matched[0].1.contains(&more[0]));
    // No consumer: nothing materialised.
    let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
    assert!(
        answer(&mut rx, &a, &rf, &refs, &Bview::holding(offer.clone()), now)
            .matched
            .is_empty()
    );
}

/// The peer table is bounded: past [`RF_MAX_PEERS`] the least recently heard
/// peer is forgotten, with its mirror.
#[test]
fn the_peer_table_is_bounded() {
    let mut rx = RfReceiver::new();
    let offer = ids(2);
    let b = Bview::holding(offer.iter().copied());
    let t0 = Instant::now();
    let mut a = Sender::new(19, EnvelopeKind::Key);
    for i in 0..=RF_MAX_PEERS {
        let (rf, refs) = a.summary(&offer, &[""], &[], &[""]);
        let at = t0 + Duration::from_millis(u64::try_from(i).unwrap());
        let _ = answer_as(&mut rx, &format!("p{i}"), a.plane, &rf, &refs, &b, None, at);
    }
    assert_eq!(rx.peers(), RF_MAX_PEERS);
    assert_eq!(
        rx.mirror_stats("p0", EnvelopeKind::Key).ids,
        0,
        "the stalest went"
    );
    assert_eq!(rx.mirror_total(), 2 * RF_MAX_PEERS);
}
