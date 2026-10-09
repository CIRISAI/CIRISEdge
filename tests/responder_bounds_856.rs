//! **CIRISEdge#856 — the responder bounds every peer by its observed
//! behaviour.** Real Reticulum on loopback; the misbehaving peers are the
//! reusable fixture in `tests/misbehaving_peer/`. Each case runs its own
//! responder with a HEALTHY peer beside the misbehaving ones, and asserts the
//! responder's counters, its inbound link count, the typed refusal, and that
//! the healthy peer's rounds all complete.
//!
//! - (a) one identity dialling at 2×N: refused past N, `rate_identity` counts;
//! - (b) three identities from one source, each under N, over the source
//!   aggregate: `rate_source` counts, `rate_identity` does not;
//! - (c) a peer that never completes rounds: backed off after K, recovers on
//!   one completion;
//! - (d) a peer below the wire floor: typed refusal, no multi-segment reply
//!   sent — while the v3 healthy peer gets the same reply multi-segment;
//! - (e) a rooted peer that never dials: reported silent after the bound;
//! - (f) a healthy peer under the production defaults: zero refusals, every
//!   round completes.
#![cfg(feature = "transport-reticulum")]

mod common;
mod misbehaving_peer;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ciris_edge::rate_limit::Backoff;
use ciris_edge::rate_limit::Quota;
use ciris_edge::replication::responder_bounds::NoProgressPolicy;
use ciris_edge::replication::wire_frame::SINGLE_SEGMENT_MAX_BYTES;
use ciris_edge::transport::link_up_bounds::LinkUpRatePolicy;
use misbehaving_peer::{wait_for, Harness, Knobs, ResponderConfig, RoundResult, Wire};

const N: u32 = 3;

/// The healthy peer's inbound links at the responder: a send that overlaps
/// the previous one on its lane takes a second lane from its pool.
const HEALTHY_LANES: usize = 2;

fn link_up(identity: u32, source: u32) -> LinkUpRatePolicy {
    LinkUpRatePolicy {
        identity: Quota::new(identity, 600),
        source: Quota::new(source, 600),
        ..LinkUpRatePolicy::default()
    }
}

/// The healthy peer's rounds: every one completes.
async fn healthy_rounds_complete(h: &Harness, group: usize, rounds: usize) {
    let peer = &h.groups[group][0];
    for i in 0..rounds {
        let r = peer.round(false).await;
        assert_eq!(r, RoundResult::Completed, "healthy round {i}: {r:?}");
    }
}

/// **(a)** One identity dials 2×N times, each round on a fresh link with the
/// old one left up. The responder closes every link-up past N right after
/// identification, so its inbound link count stays at N plus the healthy
/// peer's, and the healthy peer is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_identity_dialling_past_its_rate_is_refused_856() {
    let storm = Knobs {
        dial_interval: Some(Duration::from_millis(300)),
        complete_rounds: false,
        ..Knobs::misbehaving()
    };
    let h = Harness::start(
        "a",
        ResponderConfig {
            link_up: link_up(N, 100),
            ..ResponderConfig::default()
        },
        &[storm, Knobs::healthy()],
    )
    .await;
    let r = &h.responder;
    healthy_rounds_complete(&h, 1, 1).await;

    h.groups[0][0].storm(2 * N as usize).await;
    assert!(
        wait_for(Duration::from_secs(30), || async {
            r.refused("rate_identity") >= u64::from(N)
        })
        .await,
        "the identity's link-ups past N are refused: {:?}",
        r.metrics.link_ups_refused_total()
    );
    assert_eq!(
        r.refused("rate_source"),
        0,
        "one identity is not a source flood"
    );
    assert!(
        r.metrics.responder_link_up_total()["refused"] >= u64::from(N),
        "each refusal ends its link-up as `refused`: {:?}",
        r.metrics.responder_link_up_total()
    );
    // Flat: the refused links are gone; N stormer links and the healthy
    // peer's remain (2N + 2 without the bound).
    assert!(
        wait_for(Duration::from_secs(10), || async {
            r.inbound_links() <= N as usize + HEALTHY_LANES
        })
        .await,
        "inbound links stay at N + the healthy peer's: {}",
        r.link_report()
    );
    healthy_rounds_complete(&h, 1, 3).await;
}

/// **(b)** Three identities on one source address, each dialling N times —
/// each alone inside its own quota — against a source aggregate of 2N. The
/// third identity's link-ups are refused on the SOURCE axis; the healthy peer
/// on another address is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_identities_on_one_source_are_refused_on_the_source_axis_856() {
    let storm = Knobs {
        dial_interval: Some(Duration::from_millis(300)),
        complete_rounds: false,
        identities_per_source: 3,
        ..Knobs::misbehaving()
    };
    let h = Harness::start(
        "b",
        ResponderConfig {
            link_up: link_up(N + 1, 2 * N),
            ..ResponderConfig::default()
        },
        &[storm, Knobs::healthy()],
    )
    .await;
    let r = &h.responder;
    healthy_rounds_complete(&h, 1, 1).await;

    for peer in &h.groups[0] {
        peer.storm(N as usize).await;
    }
    assert!(
        wait_for(Duration::from_secs(30), || async {
            r.refused("rate_source") >= u64::from(N)
        })
        .await,
        "the source aggregate refuses the third identity's link-ups: {:?}",
        r.metrics.link_ups_refused_total()
    );
    assert_eq!(
        r.refused("rate_identity"),
        0,
        "no identity exceeded its own quota — each alone would have passed"
    );
    assert!(
        wait_for(Duration::from_secs(10), || async {
            r.inbound_links() <= 2 * N as usize + HEALTHY_LANES
        })
        .await,
        "inbound links stay at the source aggregate + the healthy peer's: {}",
        r.link_report()
    );
    healthy_rounds_complete(&h, 1, 3).await;
}

/// **(c)** A peer whose rounds are served and never completed is backed off
/// after K of them: its next round open inside the window is dropped unserved
/// (`backed_off`). The first round it completes ends the backoff, and its
/// rounds are served at once again. The healthy peer's rounds complete
/// throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_a_peer_that_never_completes_is_backed_off_and_recovers_856() {
    let stuck = Knobs {
        complete_rounds: false,
        ..Knobs::misbehaving()
    };
    let h = Harness::start(
        "c",
        ResponderConfig {
            no_progress: NoProgressPolicy {
                after_failed_rounds: 2,
                backoff: Backoff::new(3, 6),
            },
            ..ResponderConfig::default()
        },
        &[stuck, Knobs::healthy()],
    )
    .await;
    let r = &h.responder;
    let p = &h.groups[0][0];

    // K = 2 served rounds that never complete, then a third open right away.
    assert_eq!(p.round(false).await, RoundResult::Abandoned);
    assert_eq!(p.round(false).await, RoundResult::Abandoned);
    assert_eq!(r.rounds("backed_off"), 0, "nothing backed off before K");
    assert_eq!(
        p.round(false).await,
        RoundResult::NotServed,
        "the open after K failures, inside the window, is not served"
    );
    assert!(
        r.rounds("backed_off") >= 1,
        "backed_off counts: {:?}",
        r.metrics.responder_rounds_total()
    );
    healthy_rounds_complete(&h, 1, 2).await;

    // Recovery: the peer starts completing; once one of its rounds is served
    // and completes, its next rounds are served immediately.
    p.set_complete_rounds(true);
    let mut completed = false;
    for _ in 0..8 {
        if p.round(false).await == RoundResult::Completed {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "a served round completes once the peer completes"
    );
    assert!(
        wait_for(Duration::from_secs(5), || async {
            r.rounds("completed_responder_final") >= 3
        })
        .await,
        "the responder saw the completion: {:?}",
        r.metrics.responder_rounds_total()
    );
    let backed_off = r.rounds("backed_off");
    for i in 0..3 {
        assert_eq!(
            p.round(false).await,
            RoundResult::Completed,
            "round {i} after recovery is served at once"
        );
    }
    assert_eq!(
        r.rounds("backed_off"),
        backed_off,
        "no backoff after recovery"
    );
    healthy_rounds_complete(&h, 1, 2).await;
}

/// **(d)** The responder holds enough `Key` rows that a peer wanting them all
/// gets a Deliver past one Resource segment. A peer that opened its round with
/// LEGACY framing — below the multi-segment wire floor — gets a typed refusal
/// and NO multi-segment frame; the v3 healthy peer asking for the same rows
/// gets the multi-segment Deliver (the gate is the wire version, not the size).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d_a_peer_below_the_wire_floor_gets_a_typed_refusal_not_a_multi_segment_reply_856() {
    let old = Knobs {
        wire: Wire::Legacy,
        max_segments: Some(1),
        ..Knobs::misbehaving()
    };
    let h = Harness::start(
        "d",
        ResponderConfig {
            bulk_keys: 240,
            ..ResponderConfig::default()
        },
        &[old, Knobs::healthy()],
    )
    .await;
    let r = &h.responder;
    let p = &h.groups[0][0];
    let healthy = &h.groups[1][0];

    assert_eq!(
        healthy.round(true).await,
        RoundResult::Completed,
        "the v3 peer takes the whole Deliver"
    );
    let big = healthy.max_frame_seen.load(Ordering::Relaxed);
    assert!(
        big > SINGLE_SEGMENT_MAX_BYTES,
        "the fixture's Deliver must need more than one segment to test the floor: {big} B"
    );
    assert_eq!(r.rounds("refused_capability"), 0, "nothing refused to v3");

    assert_eq!(
        p.round(true).await,
        RoundResult::NoDeliver,
        "the legacy peer's Deliver is refused, not sent"
    );
    assert!(
        wait_for(Duration::from_secs(5), || async {
            r.rounds("refused_capability") >= 1
        })
        .await,
        "refused_capability counts: {:?}",
        r.metrics.responder_rounds_total()
    );
    assert!(
        p.max_frame_seen.load(Ordering::Relaxed) <= SINGLE_SEGMENT_MAX_BYTES,
        "no multi-segment frame reached the legacy peer"
    );
    assert_eq!(
        p.oversized_dropped.load(Ordering::Relaxed),
        0,
        "nothing was sent that the peer had to drop"
    );
    // Small replies still flow to it: a round wanting nothing completes.
    assert_eq!(p.round(false).await, RoundResult::Completed);
    healthy_rounds_complete(&h, 1, 2).await;
}

/// **(e)** A peer that roots and never dials is reported silent once the
/// bound passes; the healthy peer, completing rounds, is not. Evidence only:
/// nothing is refused or closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e_a_rooted_peer_that_never_dials_is_reported_silent_856() {
    let silent = Knobs {
        dial_at_all: false,
        ..Knobs::misbehaving()
    };
    let h = Harness::start(
        "e",
        ResponderConfig {
            silence_bounds: vec![Duration::from_secs(3)],
            ..ResponderConfig::default()
        },
        &[silent, Knobs::healthy()],
    )
    .await;
    let r = &h.responder;
    let silent_key = h.groups[0][0].key.key_id.clone();
    let healthy_key = h.groups[1][0].key.key_id.clone();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline {
        healthy_rounds_complete(&h, 1, 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        wait_for(Duration::from_secs(10), || async {
            r.metrics.rooted_peers_silent()["3s"] == 1
        })
        .await,
        "exactly the never-dialling peer is silent: {:?} {:?}",
        r.metrics.rooted_peers_silent(),
        r.metrics.rooted_peer_last_completed_unix()
    );
    let last = r.metrics.rooted_peer_last_completed_unix();
    assert_eq!(last.get(&silent_key), Some(&0), "never completed: {last:?}");
    assert!(
        last.get(&healthy_key).copied().unwrap_or(0) > 0,
        "the healthy peer's last completion is reported: {last:?}"
    );
    let flat = r.metrics.snapshot().flatten();
    assert_eq!(flat.gauges["rooted_peers_silent.3s"], 1.0);
    assert_eq!(r.refused("rate_identity") + r.refused("rate_source"), 0);
}

/// **(f)** A healthy peer under the PRODUCTION defaults: every round
/// completes, nothing is refused or backed off, one link carries it all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f_a_healthy_peer_is_untouched_by_every_bound_856() {
    let h = Harness::start("f", ResponderConfig::default(), &[Knobs::healthy()]).await;
    let r = &h.responder;
    healthy_rounds_complete(&h, 0, 8).await;
    assert_eq!(r.refused("rate_identity"), 0);
    assert_eq!(r.refused("rate_source"), 0);
    assert_eq!(r.rounds("backed_off"), 0);
    assert_eq!(r.rounds("refused_capability"), 0);
    assert!(
        wait_for(Duration::from_secs(5), || async {
            r.rounds("completed_responder_final") >= 8
        })
        .await,
        "the responder completed every round: {:?}",
        r.metrics.responder_rounds_total()
    );
    assert!(
        r.inbound_links() <= HEALTHY_LANES,
        "a healthy peer reuses its lanes: {}",
        r.link_report()
    );
}
