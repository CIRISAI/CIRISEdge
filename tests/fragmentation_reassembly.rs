//! v6.1.0 (CIRISEdge#175, FSD §3.1) — fragmentation / reassembly
//! end-to-end test.
//!
//! Large payloads chunk into [`ciris_edge::MAX_PAYLOAD_BYTES`]-sized
//! fragments and ride the emission scheduler as a fragment set;
//! reassembly is byte-for-byte over the dedup-on-receive + drop-
//! on-window-expiry contract (FSD §3.1).

use std::time::{Duration, Instant};

use ciris_edge::emission::envelope::EmissionScopeTag;
use ciris_edge::emission::fragment::fragment_payload;
use ciris_edge::{Reassembler, ReassemblyOutcome, MAX_PAYLOAD_BYTES};

#[test]
fn large_payload_round_trips_byte_for_byte() {
    // Build a deterministic 4-fragment payload (one MTU per fragment).
    // The `(i & 0xff) as u8` form makes the truncation intentional
    // and clippy-clean.
    let payload: Vec<u8> = (0..(MAX_PAYLOAD_BYTES * 3 + 91))
        .map(|i| {
            let lo = u8::try_from(i & 0xff).unwrap();
            lo.wrapping_mul(31).wrapping_add(7)
        })
        .collect();
    let set = fragment_payload(
        EmissionScopeTag::Community,
        [0x42; 32],
        9,
        1_700_000_000_000,
        &payload,
    )
    .expect("fragment");
    assert_eq!(set.fragments.len(), 4);

    let mut r = Reassembler::new();
    let now = Instant::now();
    // Feed in shuffled order — reassembler must reassemble by index.
    for i in [2, 0, 3, 1] {
        let outcome = r
            .accept(&set.fragments[i].header, &set.fragments[i].payload, now)
            .unwrap();
        if i == 1 {
            // 1 is the 4th fragment we feed; should complete.
            match outcome {
                ReassemblyOutcome::Complete { payload: got } => assert_eq!(got, payload),
                other => panic!("expected Complete on final fragment, got {other:?}"),
            }
        } else {
            assert!(matches!(outcome, ReassemblyOutcome::Partial { .. }));
        }
    }
}

#[test]
fn dedup_silently_drops_replays() {
    let payload = vec![0xCDu8; MAX_PAYLOAD_BYTES * 2 + 100];
    let set = fragment_payload(EmissionScopeTag::Family, [0x55; 32], 4, 0, &payload).unwrap();
    let mut r = Reassembler::new();
    let now = Instant::now();
    // First feed.
    let _ = r.accept(&set.fragments[0].header, &set.fragments[0].payload, now);
    // Replay same fragment — dedup.
    let outcome = r
        .accept(&set.fragments[0].header, &set.fragments[0].payload, now)
        .unwrap();
    assert_eq!(outcome, ReassemblyOutcome::Duplicate);
}

#[test]
fn window_expiry_drops_partial_state() {
    let payload = vec![0x11u8; MAX_PAYLOAD_BYTES * 5];
    let set = fragment_payload(EmissionScopeTag::Community, [0x66; 32], 0, 0, &payload).unwrap();
    let mut r = Reassembler::new();
    let t0 = Instant::now();
    let _ = r.accept(&set.fragments[0].header, &set.fragments[0].payload, t0);
    assert_eq!(r.in_progress_count(), 1);

    // Roll the clock past the window.
    let later = t0 + Duration::from_millis(ciris_edge::emission::REASSEMBLY_WINDOW_MS + 10);
    r.prune_expired(later);
    assert_eq!(r.in_progress_count(), 0);
}
