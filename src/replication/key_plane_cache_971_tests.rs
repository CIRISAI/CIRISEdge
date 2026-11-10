//! **CIRISEdge#971 — the key-plane listing cache, the per-listing read
//! budget, and stale-while-revalidate, over real sqlite directories and the
//! real bridge.**
//!
//! - **budget** — one listing reads at most the budget, the host's own keys
//!   outside it; a subject left unread is absent (the listing is a subset of
//!   the per-subject oracle) and counted on the plane's unread gauge; the
//!   listings that follow read the rest and converge on the oracle;
//! - **no wrong offer** — after the TTL path, a revocation the cursor has
//!   seen drops the stale answers it can change before anything serves them:
//!   with the budget spent, the subject is absent, never offered with its
//!   pre-revocation answer;
//! - **stale-while-revalidate** — past the TTL, a listing still equals the
//!   oracle while it re-reads within the budget, and the next complete
//!   listing is served whole from the cache;
//! - **the cache** — an idle listing is served whole; a write ends it;
//! - **the differential** — seeds × ops over the key-plane doors, every op
//!   followed by the four listings of a cache-on bridge, a cache-off bridge
//!   (the oracle) and a budget-one bridge, compared.
//!
//! `cargo test --lib key_plane_cache_971`

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciris_persist::federation::types::SignedRevocation;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;

use super::key_plane_memo::{KeyPlaneRead, MEMO_TTL};
use super::key_plane_memo_930_tests::{as_set, oracle};
use super::key_plane_v59_tests::{self_revocation, NodeA};
use super::park_fresh_858_tests::{hold, occurrence, Ident};
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory,
};

const PLANES: [EnvelopeKind; 4] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::Revocation,
    EnvelopeKind::IdentityOccurrenceRevocation,
];

/// The feed's probe spacing in the witnesses that report each write by a
/// door (longer than any test: "inside the spacing" is deterministic).
const NO_TEST_OUTLIVES: Duration = Duration::from_secs(3600);

/// A shared, mutable subject list: the host's set as the witness moves it.
type Subjects = Arc<Mutex<Vec<String>>>;

/// A bridge whose self set is `own` and whose cohort is `cohort` (both
/// read on every listing), with `config`.
fn bridge(
    dir: &Arc<SqliteBackend>,
    own: Subjects,
    cohort: Subjects,
    config: BridgeConfig,
    metrics: Option<obs::EdgeMetrics>,
) -> Arc<FederationDirectoryReplicationBridge> {
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(dir) as Arc<dyn FederationDirectory>,
            Arc::new(move || cohort.lock().expect("cohort").clone()),
            config,
        )
        .with_self_provider(Some(Arc::new(move || own.lock().expect("own").clone())))
        .with_metrics(metrics),
    )
}

fn shared(v: Vec<String>) -> Subjects {
    Arc::new(Mutex::new(v))
}

fn gauge(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.holdings_index_gauge().get(label).copied().unwrap_or(0)
}

fn sweep(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.key_plane_sweep().get(label).copied().unwrap_or(0)
}

/// `n` held keys with nothing on any plane, seeds from `seed`.
async fn held_keys(dir: &SqliteBackend, tag: &str, n: usize, seed: u8) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..n {
        let id = Ident::mint(
            &format!("held-{tag}-{i}"),
            "node",
            seed.wrapping_add(u8::try_from(i).expect("small")),
        )
        .await;
        hold(dir, &id).await;
        out.push(id.key_id().to_owned());
    }
    out
}

/// The Revocation plane's per-subject oracle over own ∪ cohort.
async fn revocation_oracle(
    dir: &SqliteBackend,
    own: &[String],
    cohort: &[String],
) -> BTreeSet<(Vec<u8>, u64)> {
    let all: Vec<String> = own.iter().chain(cohort.iter()).cloned().collect();
    oracle(EnvelopeKind::Revocation, dir, &all).await
}

/// **The budget.** Over 20 held keys and K (revoked) in the cohort and one
/// own key S, with a budget of 5: the first listing reads 5 cohort subjects
/// plus S, leaves the rest unread (gauge), and is a subset of the oracle;
/// the listings that follow read 5 more each and the last equals the oracle,
/// with the gauge at zero. With a budget of zero on a fresh bridge, S is read
/// and nothing else. Mutants: the budget ignored (the first listing reads
/// all), own keys counted inside the budget (budget zero reads nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_reads_at_most_the_budget_and_own_keys_are_outside_it_971() {
    let a = NodeA::build("bud971", 0x51).await;
    let s = Ident::mint("own-bud971", "node", 0x5f).await;
    hold(&a.dir, &s).await;
    let own = vec![s.key_id().to_owned()];
    let mut cohort = held_keys(&a.dir, "bud971", 20, 0x60).await;
    cohort.push(a.k.key_id().to_owned());
    let want = revocation_oracle(&a.dir, &own, &cohort).await;
    assert_eq!(want.len(), 1, "K's revocation");

    let metrics = obs::EdgeMetrics::new();
    let b = bridge(
        &a.dir,
        shared(own.clone()),
        shared(cohort.clone()),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            key_plane_read_budget: 5,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    let unread = obs::KEY_PLANE_GAUGE_UNREAD[KeyPlaneRead::Revocation.index()];
    let first = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert!(
        as_set(&first).is_subset(&want),
        "a missed offer, never a wrong one"
    );
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS),
        6,
        "five within the budget, and S outside it"
    );
    assert_eq!(gauge(&metrics, unread), 16, "21 cohort subjects, 5 read");
    let mut listings = 1;
    loop {
        let next = b.list_envelope_refs(EnvelopeKind::Revocation).await;
        listings += 1;
        assert!(as_set(&next).is_subset(&want));
        if gauge(&metrics, unread) == 0 {
            assert_eq!(as_set(&next), want, "every subject read: the oracle");
            break;
        }
        assert!(listings < 10, "the unread count falls every listing");
    }
    assert_eq!(listings, 5, "21 cohort subjects at 5 a listing");
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS),
        22,
        "each subject read exactly once"
    );

    let metrics = obs::EdgeMetrics::new();
    let zero = bridge(
        &a.dir,
        shared(own),
        shared(cohort),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            key_plane_read_budget: 0,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    assert!(zero
        .list_envelope_refs(EnvelopeKind::Revocation)
        .await
        .is_empty());
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS),
        1,
        "the own key is read with no budget at all"
    );
    assert_eq!(gauge(&metrics, unread), 21);
}

/// **A missed offer never becomes a wrong offer.** S (own) and a cohort of
/// K (revoked), E, and six more held keys; the Revocation plane is filled
/// and offers K's revocation. Then:
///
/// 1. past the TTL with a budget of zero, the stale answers are SERVED
///    (nothing the cursor saw has changed them): the listing still offers
///    K's revocation, and the stale gauge counts them;
/// 2. E is revoked locally and the door reports it; with the budget still
///    zero, the next listing drains the feed and the revocation's dirt drops
///    every STALE answer on the plane before anything serves one: K's
///    previously offered revocation and E's new one are both ABSENT (the
///    subjects are unread, the gauge says how many), never offered from the
///    answer the dirt dropped;
/// 3. with the budget restored the listing equals the oracle (both
///    revocations).
///
/// Mutants: dirt that skips stale answers (step 2 offers K's stale answer),
/// a TTL that clears (step 1 offers nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_the_cursor_saw_is_never_served_stale_971() {
    let a = NodeA::build("swr971", 0x71).await;
    let s = Ident::mint("own-swr971", "node", 0x7f).await;
    let e = Ident::mint("held-swr971-e", "node", 0x7e).await;
    hold(&a.dir, &s).await;
    hold(&a.dir, &e).await;
    let own = vec![s.key_id().to_owned()];
    let mut cohort = held_keys(&a.dir, "swr971", 6, 0x80).await;
    cohort.push(a.k.key_id().to_owned());
    cohort.push(e.key_id().to_owned());
    let metrics = obs::EdgeMetrics::new();
    let b = bridge(
        &a.dir,
        shared(own.clone()),
        shared(cohort.clone()),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    let before = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    let k_revocation = as_set(&before);
    assert_eq!(k_revocation.len(), 1, "K's revocation is offered");
    let stale = obs::KEY_PLANE_GAUGE_STALE[KeyPlaneRead::Revocation.index()];
    let unread = obs::KEY_PLANE_GAUGE_UNREAD[KeyPlaneRead::Revocation.index()];

    // 1. Past the TTL, nothing changed: stale answers are served.
    b.set_key_plane_read_budget(0);
    b.age_key_plane_memo(KeyPlaneRead::Revocation, MEMO_TTL)
        .await;
    let aged = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        as_set(&aged),
        k_revocation,
        "stale-while-revalidate: the stale answers are served"
    );
    assert_eq!(sweep(&metrics, obs::KEY_PLANE_REBUILDS_TTL), 1);
    assert_eq!(
        gauge(&metrics, stale),
        8,
        "the eight cohort subjects are stale"
    );
    assert_eq!(gauge(&metrics, unread), 0);

    // 2. A revocation the cursor sees: the stale answers are dropped first.
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    b.invalidate_send_set_memos("host_kick");
    let invalidated_before = sweep(&metrics, obs::KEY_PLANE_INVALIDATED);
    let after = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert!(
        after.is_empty(),
        "K's stale answer is NOT served after a row the cursor saw dropped it, \
         and E's revocation is not read yet: {:?}",
        as_set(&after)
    );
    assert!(
        sweep(&metrics, obs::KEY_PLANE_INVALIDATED) - invalidated_before >= 8,
        "the plane's stale answers were dropped by the dirt"
    );
    assert_eq!(gauge(&metrics, unread), 8, "every cohort subject is unread");
    assert_eq!(gauge(&metrics, stale), 0, "none served stale");
    let want = revocation_oracle(&a.dir, &own, &cohort).await;
    assert_eq!(want.len(), 2);
    assert!(as_set(&after).is_subset(&want));

    // 3. With the budget back, the oracle.
    b.set_key_plane_read_budget(usize::MAX);
    let healed = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(as_set(&healed), want);
    assert_eq!(gauge(&metrics, unread), 0);
}

/// **The TTL and the dirt in the same listing.** The memo is past the TTL
/// AND a reported revocation is pending when the listing runs: the feed is
/// drained and its dirt applied, then the epoch turns. With the budget at
/// zero the listing offers nothing it cannot vouch for: K's old answer is
/// gone, and the counters show both paths ran in that one listing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dirt_is_applied_before_the_ttl_path_in_one_listing_971() {
    let a = NodeA::build("ord971", 0x91).await;
    let s = Ident::mint("own-ord971", "node", 0x9f).await;
    let e = Ident::mint("held-ord971-e", "node", 0x9e).await;
    hold(&a.dir, &s).await;
    hold(&a.dir, &e).await;
    let own = vec![s.key_id().to_owned()];
    let cohort = vec![a.k.key_id().to_owned(), e.key_id().to_owned()];
    let metrics = obs::EdgeMetrics::new();
    let b = bridge(
        &a.dir,
        shared(own),
        shared(cohort),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    assert_eq!(
        b.list_envelope_refs(EnvelopeKind::Revocation).await.len(),
        1
    );
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    b.invalidate_send_set_memos("host_kick");
    b.age_key_plane_memo(KeyPlaneRead::Revocation, MEMO_TTL)
        .await;
    b.set_key_plane_read_budget(0);
    let invalidated_before = sweep(&metrics, obs::KEY_PLANE_INVALIDATED);
    let listing = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert!(listing.is_empty(), "{:?}", as_set(&listing));
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_REBUILDS_TTL),
        1,
        "the TTL path ran"
    );
    assert!(
        sweep(&metrics, obs::KEY_PLANE_INVALIDATED) > invalidated_before,
        "the dirt ran"
    );
    assert_eq!(
        gauge(
            &metrics,
            obs::KEY_PLANE_GAUGE_STALE[KeyPlaneRead::Revocation.index()]
        ),
        0,
        "nothing was left for the TTL path to serve"
    );
}

/// **Stale-while-revalidate converges.** Past the TTL with a budget of 2,
/// each listing equals the oracle (nothing changed, so the stale answers are
/// right) while it re-reads at most 2 cohort subjects; once every answer is
/// fresh again the next listing is served whole from the cache. Mutant: a
/// TTL that clears the memo (the first aged listing is short of the oracle).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_plane_is_revalidated_within_the_budget_971() {
    let a = NodeA::build("rev971", 0xa1).await;
    let s = Ident::mint("own-rev971", "node", 0xaf).await;
    hold(&a.dir, &s).await;
    let own = vec![s.key_id().to_owned()];
    let mut cohort = held_keys(&a.dir, "rev971", 5, 0xb0).await;
    cohort.push(a.k.key_id().to_owned());
    let want = revocation_oracle(&a.dir, &own, &cohort).await;
    let metrics = obs::EdgeMetrics::new();
    let b = bridge(
        &a.dir,
        shared(own),
        shared(cohort),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    assert_eq!(
        as_set(&b.list_envelope_refs(EnvelopeKind::Revocation).await),
        want
    );
    b.set_key_plane_read_budget(2);
    b.age_key_plane_memo(KeyPlaneRead::Revocation, MEMO_TTL)
        .await;
    let stale = obs::KEY_PLANE_GAUGE_STALE[KeyPlaneRead::Revocation.index()];
    let mut listings = 0;
    loop {
        let reads_before = sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS);
        let listing = b.list_envelope_refs(EnvelopeKind::Revocation).await;
        listings += 1;
        assert_eq!(
            as_set(&listing),
            want,
            "listing {listings} equals the oracle"
        );
        let reads = sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS) - reads_before;
        assert!(
            reads <= 3,
            "two within the budget, the own key outside: {reads}"
        );
        if gauge(&metrics, stale) == 0 {
            break;
        }
        assert!(listings < 6);
    }
    assert_eq!(listings, 3, "six cohort subjects, two a listing");
    assert_eq!(sweep(&metrics, obs::KEY_PLANE_REVALIDATED), 7, "six and S");
    let hits = sweep(&metrics, obs::KEY_PLANE_LISTING_CACHE_HITS);
    assert_eq!(
        as_set(&b.list_envelope_refs(EnvelopeKind::Revocation).await),
        want
    );
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_LISTING_CACHE_HITS),
        hits + 1,
        "revalidated: served whole"
    );
}

/// **The cache.** A second idle listing on each plane is served whole (one
/// cache hit, no store read); a reported write ends it and the next listing
/// carries the write; with the cache off the same listings are equal and
/// nothing is a hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_listing_is_served_whole_and_a_write_ends_it_971() {
    let a = NodeA::build("hit971", 0xc1).await;
    let e = Ident::mint("held-hit971", "node", 0xcf).await;
    hold(&a.dir, &e).await;
    let subjects: Vec<String> = [&a.p, &a.n, &a.k, &e]
        .into_iter()
        .map(|id| id.key_id().to_owned())
        .collect();
    for cache in [true, false] {
        let metrics = obs::EdgeMetrics::new();
        let b = bridge(
            &a.dir,
            shared(subjects.clone()),
            shared(subjects.clone()),
            BridgeConfig {
                feed_probe_spacing: NO_TEST_OUTLIVES,
                key_plane_listing_cache: cache,
                ..BridgeConfig::default()
            },
            Some(metrics.clone()),
        );
        for kind in PLANES {
            let fill = b.list_envelope_refs(kind).await;
            let reads = sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS);
            let again = b.list_envelope_refs(kind).await;
            assert_eq!(as_set(&fill), as_set(&again), "cache {cache} {kind:?}");
            assert_eq!(sweep(&metrics, obs::KEY_PLANE_SUBJECT_READS), reads);
        }
        assert_eq!(
            sweep(&metrics, obs::KEY_PLANE_LISTING_CACHE_HITS),
            if cache { 4 } else { 0 },
            "cache {cache}"
        );
    }
    let metrics = obs::EdgeMetrics::new();
    let b = bridge(
        &a.dir,
        shared(subjects.clone()),
        shared(subjects.clone()),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    let hits = sweep(&metrics, obs::KEY_PLANE_LISTING_CACHE_HITS);
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    b.invalidate_send_set_memos("host_kick");
    let after = b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        sweep(&metrics, obs::KEY_PLANE_LISTING_CACHE_HITS),
        hits,
        "not a hit"
    );
    assert_eq!(
        as_set(&after),
        oracle(EnvelopeKind::Revocation, &*a.dir, &subjects).await
    );
    assert_eq!(after.len(), 2, "E's revocation is offered");
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Seeds and ops of the key-plane differential.
const SEEDS: u64 = 16;
const OPS: usize = 60;

/// **The key-plane differential.** For each seed: a store with NodeA's
/// rows; three bridges over it with the same moving subject set and spacing
/// zero (every write is seen by the next listing): `on` (cache on, holdings
/// index on), `off` (cache off, index off: the oracle bridge) and `tight`
/// (cache on, budget one). Ops: hold a new key and add it to the set; drop
/// a subject from the set; revoke a held subject locally; author P's
/// occurrence of a subject; withdraw one; a carrier; age one plane past the
/// TTL on every bridge. After EVERY op, for each of the four planes: `on`
/// equals `off`; on the two Global planes `off` equals the per-subject
/// oracle; `tight` is a subset of the oracle (a missed offer, never a wrong
/// one). Every 15 ops `tight` is listed until its unread gauge is zero and
/// must then equal `off`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one op table
async fn the_cache_equals_the_walk_through_every_key_plane_door_971() {
    let started = std::time::Instant::now();
    for seed in 0..SEEDS {
        let base = u8::try_from(seed).expect("small") * 8;
        let a = NodeA::build(&format!("kpd971-{seed}"), base).await;
        let mut seeds = base.wrapping_add(3);
        let mut next_seed = || {
            seeds = seeds.wrapping_add(1);
            seeds
        };
        let initial: Vec<String> = [&a.p, &a.n, &a.k]
            .into_iter()
            .map(|id| id.key_id().to_owned())
            .collect();
        let set = shared(initial);
        let quiet = BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            holdings_audit_every: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        };
        let on = bridge(&a.dir, Arc::clone(&set), Arc::clone(&set), quiet, None);
        let off = bridge(
            &a.dir,
            Arc::clone(&set),
            Arc::clone(&set),
            BridgeConfig {
                holdings_index: false,
                key_plane_listing_cache: false,
                key_plane_read_budget: usize::MAX,
                ..quiet
            },
            None,
        );
        let tight_metrics = obs::EdgeMetrics::new();
        let tight = bridge(
            &a.dir,
            Arc::clone(&set),
            Arc::clone(&set),
            BridgeConfig {
                key_plane_read_budget: 1,
                ..quiet
            },
            Some(tight_metrics.clone()),
        );
        let mut held: Vec<Ident> = Vec::new();
        let mut occurrences: Vec<String> = Vec::new();
        // One occurrence and one carrier per key: a second of either is a
        // supersession or a duplicate, not a door this witness is about.
        let mut authored: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut carried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut rng = 0x0971_0000_u64 + seed;
        for step in 0..OPS {
            let op = splitmix(&mut rng) % 8;
            let pick = usize::try_from(splitmix(&mut rng)).unwrap_or(0);
            let label = format!("seed {seed} step {step} op {op}");
            match op {
                0 | 1 => {
                    let id = Ident::mint(&format!("kpd-{seed}-{step}"), "node", next_seed()).await;
                    hold(&a.dir, &id).await;
                    set.lock().expect("set").push(id.key_id().to_owned());
                    held.push(id);
                }
                2 => {
                    let mut s = set.lock().expect("set");
                    if s.len() > 1 {
                        let i = pick % s.len();
                        s.remove(i);
                    }
                }
                3 => {
                    if !held.is_empty() {
                        let id = held.swap_remove(pick % held.len());
                        let revocation = self_revocation(&a.dir, &id).await;
                        a.dir
                            .put_revocation(SignedRevocation { revocation })
                            .await
                            .unwrap_or_else(|e| panic!("{label}: revocation: {e}"));
                    }
                }
                4 => {
                    if let Some(id) = held
                        .get(pick % held.len().max(1))
                        .filter(|id| authored.insert(id.key_id().to_owned()))
                    {
                        a.dir
                            .put_identity_occurrence(
                                occurrence(a.p.key_id(), id.key_id(), &a.p).await,
                            )
                            .await
                            .unwrap_or_else(|e| panic!("{label}: occurrence: {e}"));
                        occurrences.push(id.key_id().to_owned());
                    }
                }
                5 => {
                    if !occurrences.is_empty() {
                        let target_key = occurrences.swap_remove(pick % occurrences.len());
                        withdraw(&a, &target_key, &label).await;
                    }
                }
                6 => {
                    let target = held
                        .get(pick % held.len().max(1))
                        .map_or_else(|| a.k.key_id().to_owned(), |id| id.key_id().to_owned());
                    if carried.insert(target.clone()) {
                        a.carrier_revoking_node_occurrence(&target).await;
                    }
                }
                _ => {
                    let read = [
                        KeyPlaneRead::KeyRecord,
                        KeyPlaneRead::OccurrenceBinding,
                        KeyPlaneRead::Revocation,
                        KeyPlaneRead::OccurrenceWithdrawal,
                    ][pick % 4];
                    for b in [&on, &off, &tight] {
                        b.age_key_plane_memo(read, MEMO_TTL).await;
                    }
                }
            }
            let subjects = set.lock().expect("set").clone();
            for kind in PLANES {
                let got_on = as_set(&on.list_envelope_refs(kind).await);
                let got_off = as_set(&off.list_envelope_refs(kind).await);
                assert_eq!(
                    got_on, got_off,
                    "{label} {kind:?}: cache on equals cache off"
                );
                let want = oracle(kind, &*a.dir, &subjects).await;
                if matches!(
                    kind,
                    EnvelopeKind::Revocation | EnvelopeKind::IdentityOccurrenceRevocation
                ) {
                    assert_eq!(got_off, want, "{label} {kind:?}: the oracle");
                }
                let got_tight = as_set(&tight.list_envelope_refs(kind).await);
                assert!(
                    got_tight.is_subset(&got_off),
                    "{label} {kind:?}: budget one offers nothing the walk does not: {:?}",
                    got_tight.difference(&got_off).collect::<Vec<_>>()
                );
            }
            if step % 15 == 14 {
                for (kind, read) in [
                    (EnvelopeKind::Key, KeyPlaneRead::KeyRecord),
                    (
                        EnvelopeKind::IdentityOccurrence,
                        KeyPlaneRead::OccurrenceBinding,
                    ),
                    (EnvelopeKind::Revocation, KeyPlaneRead::Revocation),
                    (
                        EnvelopeKind::IdentityOccurrenceRevocation,
                        KeyPlaneRead::OccurrenceWithdrawal,
                    ),
                ] {
                    let unread = obs::KEY_PLANE_GAUGE_UNREAD[read.index()];
                    let stale = obs::KEY_PLANE_GAUGE_STALE[read.index()];
                    let mut got = tight.list_envelope_refs(kind).await;
                    let mut rounds = 0usize;
                    while gauge(&tight_metrics, unread) + gauge(&tight_metrics, stale) > 0 {
                        rounds += 1;
                        assert!(
                            rounds <= subjects.len() + 2,
                            "{label} {kind:?}: one subject a listing converges"
                        );
                        got = tight.list_envelope_refs(kind).await;
                    }
                    assert_eq!(
                        as_set(&got),
                        as_set(&off.list_envelope_refs(kind).await),
                        "{label} {kind:?}: budget one converges on the walk"
                    );
                }
            }
        }
    }
    eprintln!(
        "the_cache_equals_the_walk_through_every_key_plane_door_971: {SEEDS} seeds x {OPS} ops in {:?}",
        started.elapsed()
    );
}

/// P's `withdraws` of its occurrence row binding `occurrence_key`, admitted
/// at A.
async fn withdraw(a: &NodeA, occurrence_key: &str, label: &str) {
    let Some(target) = super::key_plane_rows::occurrence_rows_about(&*a.dir, a.p.key_id())
        .await
        .expect("rows")
        .into_iter()
        .find(|r| super::key_plane_rows::occurrence_key_of(r).as_deref() == Some(occurrence_key))
    else {
        return;
    };
    let withdraws = crate::replication::attestation_bind::withdraws_attestation(
        &target,
        "device_retired",
        chrono::Utc::now(),
        &a.p.signer(),
    )
    .await
    .unwrap_or_else(|e| panic!("{label}: build the withdraws: {e}"));
    a.dir
        .apply_replicated_attestation(ciris_persist::federation::SignedAttestation {
            attestation: withdraws,
        })
        .await
        .unwrap_or_else(|e| panic!("{label}: admit the withdraws: {e}"));
}
