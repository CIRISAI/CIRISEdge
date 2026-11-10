//! **CIRISEdge#971 — the differentials commits 3 and 4 ship on, and the
//! witness that a caller label reaches persist (commit 5).**
//!
//! Over random sqlite stores, built from a seeded generator so a failure
//! names its seed:
//!
//! - **commit 3 (the gate reorder)**: for every peer, the advertise with the
//!   reach half run first and the advertise in the pre-v45 order offer the
//!   same set, judge the same rows, and give every row the same verdict. The
//!   one allowed difference is the documented move: a row the reach refuses
//!   and an earlier store-reading gate also refuses (author quarantine, the
//!   accord relay, the serve capability, the producer's recipient
//!   capability) is booked `recipient_not_in_send_set` where the old order
//!   booked that gate's reason, or booked nothing (the serve capability books
//!   once per sweep).
//! - **commit 4 (the narrowed first-contact read)**: the offer with a
//!   first-contact peer's own rows read only in the shapes its reach carries
//!   equals the offer with all of them read, in both gate orders. The stores
//!   hold membership ceremony rows (proposals, relayed proposals, acceptances
//!   and declines authored by the peers' nodes), founded rooms, and peers'
//!   own consent grants with a recipient-capability restriction.
//! - **commit 5 (caller scopes)**: a bridge read arrives in persist's
//!   `observe::snapshot().callers` under its edge label.
//!
//! Per-row verdicts come from the bridge's test-only log
//! (`record_row_verdicts`): every withhold booked for a row, or `offered`,
//! `awaits_request`, `not_advertisable`.
//!
//! `cargo test --lib gate_differential_971`

use std::collections::{BTreeMap, BTreeSet};

use super::*;

const NOT_IN_SEND_SET: &str = "recipient_not_in_send_set";
const SEEDS: [u64; 6] = [0x971, 0x9710, 0x1971, 0x7_1971, 0xA971, 0x9_71A5];

const PERSONS: [&str; 4] = ["gd-p0", "gd-p1", "gd-p2", "gd-p3"];
const NODES: [&str; 6] = ["gd-n0", "gd-n1", "gd-n2", "gd-n3", "gd-n4", "gd-n5"];
/// This node; owned by `gd-p0`.
const LOCAL: &str = "gd-n0";
/// Always owned by `gd-p3` and never consented: a first-contact peer in
/// every store.
const STRANGER: &str = "gd-n5";
/// Always quarantined, and always the author of one federation row: with
/// [`STRANGER`] that makes the documented move occur in every store.
const QUARANTINED: &str = "gd-p1";
const MODERATOR: &str = "gd-moderator";
const COMMONS: &str = "gd-commons";

/// splitmix64: the same generator the holdings differential uses.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        let i = usize::try_from(self.next() % xs.len() as u64).expect("small");
        xs[i]
    }
}

/// One random store and the peers to ask about it.
struct Store {
    backend: Arc<SqliteBackend>,
    consented: Vec<String>,
    /// Membership ceremony rows the store admitted (proposals and replies).
    ceremony: usize,
}

#[allow(clippy::too_many_lines)] // one generator, read top to bottom
async fn random_store(seed: u64) -> Store {
    let mut rng = Rng(seed);
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let mut keys: Vec<(&str, &str)> = Vec::new();
    keys.extend(PERSONS.iter().map(|p| (*p, identity_type::USER)));
    keys.extend(NODES.iter().map(|n| (*n, identity_type::NODE)));
    keys.push(("room-authority", identity_type::USER));
    keys.push((MODERATOR, identity_type::USER));
    keys.push((COMMONS, identity_type::USER));
    register_fixture_keys(&backend, &keys).await;

    // Owners and devices. The local node is p0's laptop; the stranger is p3's.
    let mut owner_of: BTreeMap<&'static str, &'static str> = BTreeMap::new();
    owner_of.insert(LOCAL, "gd-p0");
    owner_of.insert(STRANGER, "gd-p3");
    for node in &NODES[1..5] {
        if rng.chance(75) {
            owner_of.insert(*node, rng.pick(&PERSONS));
        }
    }
    for (node, owner) in &owner_of {
        seed_owner_binding(&backend, owner, node).await;
        if *node == LOCAL || rng.chance(70) {
            let class = if *node == LOCAL || rng.chance(50) {
                device_class::LAPTOP
            } else {
                device_class::PHONE
            };
            seed_device_occurrence(&backend, owner, node, class).await;
        }
    }
    // Roots in common for a random subset of persons (p0 always, so a Rooted
    // peer exists whenever its owner is picked).
    let mut rooted: Vec<&str> = vec!["gd-p0"];
    for p in &PERSONS[1..] {
        if rng.chance(50) {
            rooted.push(*p);
        }
    }
    seed_common_root(&backend, &rooted).await;
    // Consent: the local node grants a random subset of the other nodes (never
    // the stranger), some of them without a root in common.
    let mut consented = Vec::new();
    for node in &NODES[1..5] {
        if rng.chance(40) {
            seed_consent_membership(&backend, LOCAL, node).await;
            consented.push((*node).to_owned());
        } else if rng.chance(20) {
            seed_consent_membership_unrooted(&backend, LOCAL, node).await;
            consented.push((*node).to_owned());
        }
    }
    // Peers' own consent grants, restricted to a capability nobody holds: the
    // producer's recipient-capability gate (#396 item 6), and peer-authored
    // grant rows for the first-contact read.
    for _ in 0..2 {
        let producer = rng.pick(&NODES[1..]);
        let recipient = rng.pick(&NODES);
        if producer != recipient && rng.chance(60) {
            seed_consent_grant(&backend, producer, recipient, "credits:", "infra:serve").await;
        }
    }

    // Author quarantine: the moderator's commons holds the slash duty.
    backend
        .put_community(sign_community_fixture(
            MODERATOR,
            Community {
                community_key_id: COMMONS.to_string(),
                community_name: "gate differential commons".to_string(),
                members: vec![CommunityMember {
                    key_id: MODERATOR.to_string(),
                    joined_at: Utc::now(),
                    role: Some("founder".to_string()),
                }],
                founded_at: Utc::now(),
                consensus_protocol: "majority".to_string(),
                policy_blob: None,
                persist_row_hash: String::new(),
                prev_head_digest: String::new(),
                charter_digest: String::new(),
            },
        ))
        .await
        .expect("seed moderation commons");
    let quarantined_row = uuid::Uuid::new_v4().to_string();
    seed_raw_attestation(
        &backend,
        &quarantined_row,
        QUARANTINED,
        QUARANTINED,
        "scores",
        serde_json::json!({
            "id": quarantined_row,
            "attesting_key_id": QUARANTINED,
            "attested_key_id": QUARANTINED,
            "attestation_type": "scores",
            "dimension": "credits:test:v1",
            "score": 1.0,
        }),
    )
    .await;
    let marker_id = uuid::Uuid::new_v4().to_string();
    seed_raw_attestation(
        &backend,
        &marker_id,
        MODERATOR,
        QUARANTINED,
        "scores",
        ciris_persist::federation::quarantine::withhold_envelope(
            QUARANTINED,
            COMMONS,
            "gate-differential-971",
            "test: withhold-from-serving",
        ),
    )
    .await;

    // Random rows: any author, any subject, three membership-free scopes, an
    // ordinary dimension or a trace (the serve-capability gate).
    let everyone: Vec<&str> = PERSONS.iter().chain(NODES.iter()).copied().collect();
    for _ in 0..24 {
        let id = uuid::Uuid::new_v4().to_string();
        let attester = rng.pick(&everyone);
        let subject = rng.pick(&everyone);
        let scope = rng.pick(&["federation", "self", "affiliations"]);
        let envelope = if rng.chance(30) {
            serde_json::json!({
                "id": id,
                "attesting_key_id": attester,
                "attested_key_id": subject,
                "attestation_type": "scores",
                "dimension": "trace:complete:v1",
                "trace_id": format!("t-{id}"),
                "agent_id_hash": "ah-gate-differential",
                "trace": { "steps": [] },
            })
        } else {
            serde_json::json!({
                "id": id,
                "attesting_key_id": attester,
                "attested_key_id": subject,
                "attestation_type": "scores",
                "dimension": rng.pick(&["credits:test:v1", "chat:message:v1"]),
                "score": 1.0,
            })
        };
        // A shape persist refuses is simply not in this store.
        let _ = try_seed_scoped_attestation(
            &backend, &id, attester, subject, "scores", scope, envelope,
        )
        .await;
    }

    // The membership ceremony (commit 4): rooms founded by a person, proposals
    // into them, a relayed proposal into a room not held here, and replies
    // authored by the invitee's node (or any node), accepting or declining.
    let expires = Utc::now() + chrono::Duration::days(7);
    let mut proposals = Vec::new();
    let mut ceremony = 0usize;
    for _ in 0..2 {
        let opener = rng.pick(&PERSONS);
        let other = rng.pick(&PERSONS);
        if opener == other {
            continue;
        }
        let room = crate::chat::pair_community(opener, other, Utc::now());
        let g = room.community_key_id.clone();
        if backend
            .put_community(sign_community_fixture("room-authority", room))
            .await
            .is_err()
        {
            continue;
        }
        let invitee = rng.pick(&PERSONS);
        if let Ok(p) = crate::membership::propose(
            &*backend,
            crate::membership::GroupScope::Community,
            &g,
            invitee,
            None,
            expires,
            &fixture_local_signer(opener),
        )
        .await
        {
            proposals.push((p, invitee));
            ceremony += 1;
        }
    }
    let invitee = rng.pick(&PERSONS);
    if let Ok(relayed) = crate::membership::proposal_attestation(
        crate::membership::GroupScope::Community,
        "gd-room-elsewhere",
        invitee,
        None,
        expires,
        &fixture_local_signer(rng.pick(&PERSONS)),
    )
    .await
    {
        if backend
            .put_attestation(ciris_persist::federation::types::SignedAttestation {
                attestation: relayed.clone(),
            })
            .await
            .is_ok()
        {
            proposals.push((relayed, invitee));
            ceremony += 1;
        }
    }
    for (proposal, invitee) in &proposals {
        let replier = owner_of
            .iter()
            .find(|(_, owner)| **owner == *invitee)
            .map_or_else(|| rng.pick(&NODES), |(node, _)| *node);
        let accept = rng.chance(60);
        if crate::membership::reply(
            &*backend,
            &proposal.attestation_id,
            accept,
            &fixture_local_signer(replier),
        )
        .await
        .is_ok()
        {
            ceremony += 1;
        }
    }

    Store {
        backend,
        consented,
        ceremony,
    }
}

/// The local node's bridge over `store`, in the given gate order and
/// first-contact read, recording verdicts.
fn local_bridge(store: &Store, early: bool, narrow: bool) -> FederationDirectoryReplicationBridge {
    let publish: Vec<String> = vec![LOCAL.to_owned(), "gd-p0".to_owned()];
    let selector: CohortProvider = Arc::new(move || publish.clone());
    let cohort: Vec<&str> = store.consented.iter().map(String::as_str).collect();
    let b = bridge_over(&store.backend, &cohort)
        .with_local_key_id(Some(LOCAL.to_owned()))
        .with_self_provider(Some(selector));
    b.set_early_reach_check(early);
    b.set_narrow_first_contact_read(narrow);
    b.record_row_verdicts();
    b
}

type Verdicts = BTreeMap<String, Vec<&'static str>>;

async fn offer_and_verdicts(
    store: &Store,
    peer: &str,
    early: bool,
    narrow: bool,
) -> (BTreeSet<[u8; 32]>, Verdicts) {
    let b = local_bridge(store, early, narrow);
    let offer = b
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect();
    (offer, b.take_row_verdicts())
}

/// A reason booked by a gate the reorder put after the reach half.
fn moved_from(reason: &str) -> bool {
    reason == "quarantined_author"
        || reason == "quarantine_read_error"
        || reason.starts_with("accord_relay_")
        || reason.starts_with("serve_capability_")
        || matches!(
            reason,
            "local_identity_missing"
                | "row_not_serializable"
                | "trust_root_walk_error"
                | "recipient_capability_restriction"
        )
}

/// Whether one row's v45 verdicts are its pre-v45 verdicts, or the
/// documented move to `recipient_not_in_send_set`.
fn same_or_moved(old: &[&str], new: &[&str]) -> bool {
    if old == new {
        return true;
    }
    if old.is_empty() {
        // A silent skip in the old order (the serve capability books once per
        // sweep) that the reach now books.
        return !new.is_empty() && new.iter().all(|v| *v == NOT_IN_SEND_SET);
    }
    old.len() == new.len()
        && old
            .iter()
            .zip(new)
            .all(|(o, n)| o == n || (*n == NOT_IN_SEND_SET && moved_from(o)))
}

/// Every node but this one, every person, and an id no store holds.
fn peers() -> Vec<String> {
    let mut peers: Vec<String> = NODES[1..].iter().map(|n| (*n).to_owned()).collect();
    peers.extend(PERSONS.iter().map(|p| (*p).to_owned()));
    peers.push("gd-never-seen".to_owned());
    peers
}

/// **Commit 3.** Random stores, every peer, both first-contact reads: the v45
/// gate order offers the same set, judges the same rows, and gives each row
/// the same verdict up to the documented move. Mutation: drop the early
/// reach check's `continue` (offer a row the reach refuses), and a row
/// offered in the v45 order is refused in the old; or book the early refusal
/// under another reason, and `same_or_moved` fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gate_order_gives_every_row_the_same_verdict_on_random_stores_971() {
    let (mut offered, mut refused, mut moved) = (0usize, 0usize, 0usize);
    for seed in SEEDS {
        let store = random_store(seed).await;
        for peer in peers() {
            for narrow in [false, true] {
                let (old_offer, old) = offer_and_verdicts(&store, &peer, false, narrow).await;
                let (new_offer, new) = offer_and_verdicts(&store, &peer, true, narrow).await;
                assert_eq!(
                    new_offer, old_offer,
                    "seed {seed:#x} peer {peer} narrow {narrow}: the offer differs"
                );
                assert_eq!(
                    new.keys().collect::<Vec<_>>(),
                    old.keys().collect::<Vec<_>>(),
                    "seed {seed:#x} peer {peer} narrow {narrow}: different rows judged"
                );
                for (id, o) in &old {
                    let n = &new[id];
                    assert!(
                        same_or_moved(o, n),
                        "seed {seed:#x} peer {peer} narrow {narrow} row {id}: \
                         old {o:?}, v45 {n:?}"
                    );
                    if o != n {
                        moved += 1;
                    }
                    if n.contains(&"offered") {
                        offered += 1;
                    }
                    if n.contains(&NOT_IN_SEND_SET) {
                        refused += 1;
                    }
                }
            }
        }
    }
    eprintln!("rows offered {offered}, refused at the send set {refused}, moved {moved}");
    assert!(offered > 0, "not vacuous: some row is offered");
    assert!(refused > 0, "not vacuous: some row is refused by the reach");
    assert!(
        moved > 0,
        "not vacuous: the quarantined author's row to the stranger moves its reason"
    );
}

/// **Commit 4.** Random stores with membership and group-plane rows, every
/// peer: the narrowed first-contact read offers what the full read offers,
/// in both gate orders, and the stranger (whose own replies and grants are in
/// the store) is never refused more rows. Mutation: drop one membership
/// dimension from the narrowed query (say `ACCEPTANCE_DIMENSION`), and a
/// peer's acceptance of a proposal is no longer offered back where the full
/// read offered it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_narrowed_first_contact_read_offers_the_same_on_random_stores_971() {
    let mut offered = 0usize;
    let mut ceremony_rows = 0usize;
    for seed in SEEDS {
        let store = random_store(seed).await;
        ceremony_rows += store.ceremony;
        for peer in peers() {
            for early in [false, true] {
                let (full, full_v) = offer_and_verdicts(&store, &peer, early, false).await;
                let (narrow, narrow_v) = offer_and_verdicts(&store, &peer, early, true).await;
                assert_eq!(
                    narrow, full,
                    "seed {seed:#x} peer {peer} early {early}: the narrowed read offers \
                     a different set"
                );
                let refusals = |v: &Verdicts| {
                    v.values()
                        .flatten()
                        .filter(|r| {
                            !matches!(**r, "offered" | "awaits_request" | "not_advertisable")
                        })
                        .count()
                };
                assert!(
                    refusals(&narrow_v) <= refusals(&full_v),
                    "seed {seed:#x} peer {peer} early {early}: more refusals narrowed \
                     ({} vs {})",
                    refusals(&narrow_v),
                    refusals(&full_v)
                );
                offered += narrow.len();
            }
        }
    }
    eprintln!("offers {offered}, membership rows held {ceremony_rows}");
    assert!(offered > 0, "not vacuous: some peer is offered rows");
    assert!(
        ceremony_rows > 0,
        "not vacuous: the stores hold membership ceremony rows"
    );
}

/// The reads persist credited to `label` on sqlite, summed over doors.
fn persist_reads_under(label: &str) -> u64 {
    ciris_persist::observe::snapshot()
        .callers
        .iter()
        .filter(|c| c.backend == "sqlite" && c.caller == label)
        .map(|c| c.reads)
        .sum()
}

/// **Commit 5.** A bridge read arrives in persist's `snapshot().callers`
/// under its edge label. The advertise's required read
/// (`edge.advertise.required`) runs over a counting directory: every
/// `execute_attestation_query` it sees runs under a scope, the required
/// read's label is among them, and persist's per-caller count for that label
/// grows by at least one.
///
/// persist's counters are process-wide, so a test running beside this one
/// can add to the label as well; the mutation proof (drop the `scoped` wrap
/// on `required_rows`, and the label is absent from the directory's callers
/// and persist's count for it does not move) holds when this test runs
/// alone: `cargo test --lib a_bridge_read_arrives_in_persists_callers_971`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridge_read_arrives_in_persists_callers_971() {
    use crate::read_caller::Site;
    use crate::replication::counting_directory_930::CountingDirectory;
    let store = random_store(SEEDS[0]).await;
    let counting = CountingDirectory::new(store.backend.clone() as Arc<dyn FederationDirectory>);
    let publish: Vec<String> = vec![LOCAL.to_owned(), "gd-p0".to_owned()];
    let selector: CohortProvider = Arc::new(move || publish.clone());
    let cohort: Vec<String> = store.consented.clone();
    let bridge = FederationDirectoryReplicationBridge::new(
        Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
        Arc::new(move || cohort.clone()),
    )
    .with_local_key_id(Some(LOCAL.to_owned()))
    .with_self_provider(Some(selector));
    let label = Site::AdvertiseRequired.label();
    let before = persist_reads_under(label);
    for peer in [STRANGER, "gd-n1", "gd-n2"] {
        let _ = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
    }
    let after = persist_reads_under(label);
    let callers = counting.callers_of("execute_attestation_query");
    eprintln!("attestation-query callers {callers:?}; persist {label}: {before} -> {after}");
    assert!(
        callers.contains(label),
        "the required read ran under {label}: {callers:?}"
    );
    assert!(
        after > before,
        "persist credited the required read to {label} ({before} -> {after})"
    );
}
