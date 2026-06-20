//! v6.1.0 (CIRISEdge#175, FSD §3.4) — witness chain split end-to-end test.
//!
//! Asserts the §3.4 split:
//!
//! - **Federation witness** commits to the constant-tick counter
//!   (`count mod target_rate`) with HMAC-SHA3 cover-leaf padding.
//! - **Per-community witness** carries the community's record_id
//!   leaf set with the MLS group epoch and community_id stamped on.
//!
//! The signing surface (federation-public ML-DSA-65 + Ed25519
//! hybrid for the federation witness; MLS PrivateMessage for the
//! community witness) lives at the transport layer — these tests
//! exercise the body shape + the cover-leaf-padding contract.

use ciris_edge::holonomic::wholeness_witness::{compute_merkle_root, WholenessWitness};
use ciris_edge::holonomic::witness_chain_split::{
    pad_to_target, CommunityWitness, FederationWitness, DEFAULT_FEDERATION_TARGET_RATE,
};

fn empty_witness(peer: &str, epoch: u64, leaf_count: u32, root: [u8; 32]) -> WholenessWitness {
    WholenessWitness {
        peer_id: peer.into(),
        epoch_id: epoch,
        merkle_root: root,
        leaf_count,
        claim_namespaces: vec![],
        observed_at_unix_ms: 0,
        witness_version: 1,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: String::new(),
    }
}

#[test]
fn federation_witness_commits_to_constant_tick_counter() {
    // Real leaves below target — cover padding brings the multiset
    // to target_rate. The federation witness's merkle root is over
    // the padded multiset; the rate-smoothed counter commits to
    // `count mod target_rate`.
    let key = [0xAAu8; 32];
    let real_leaves: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 32]).collect();
    let padded = pad_to_target(real_leaves.clone(), &key, 7, DEFAULT_FEDERATION_TARGET_RATE);
    assert_eq!(padded.real_committed, 10);
    assert_eq!(
        padded.cover_injected,
        DEFAULT_FEDERATION_TARGET_RATE - 10,
        "cover padding fills to target_rate"
    );
    assert_eq!(padded.leaves.len(), DEFAULT_FEDERATION_TARGET_RATE as usize);
    assert!(padded.backpressure.is_empty());

    let root = compute_merkle_root(&padded.leaves);
    let body = empty_witness(
        "federation-1",
        7,
        u32::try_from(padded.leaves.len()).unwrap(),
        root,
    );
    let fw = FederationWitness::new(body, padded.real_committed);
    assert_eq!(
        fw.rate_smoothed_counter(),
        10 % DEFAULT_FEDERATION_TARGET_RATE
    );
    assert_eq!(fw.cover_count(), padded.cover_injected);
}

#[test]
fn federation_witness_above_target_back_pressures() {
    // Above-target real leaves split: the first `target_rate`
    // commit, the remainder back-pressures.
    let key = [0xBBu8; 32];
    let target = 4;
    let real_leaves: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 32]).collect();
    let padded = pad_to_target(real_leaves, &key, 0, target);
    assert_eq!(padded.real_committed, 4);
    assert_eq!(padded.cover_injected, 0);
    assert_eq!(padded.backpressure.len(), 6);
    assert_eq!(padded.leaves.len(), 4);
}

#[test]
fn cover_leaves_deterministic_per_witness_key_and_epoch() {
    // Two federations at the same `(witness_key, epoch)` produce
    // the same cover-leaf sequence; different `(key, epoch)`
    // differ.
    let key1 = [0xCCu8; 32];
    let key2 = [0xDDu8; 32];
    let p_a = pad_to_target(vec![], &key1, 99, 8);
    let p_b = pad_to_target(vec![], &key1, 99, 8);
    let p_c = pad_to_target(vec![], &key2, 99, 8);
    let p_d = pad_to_target(vec![], &key1, 100, 8);
    assert_eq!(p_a.leaves, p_b.leaves, "same key+epoch ⇒ same cover");
    assert_ne!(p_a.leaves, p_c.leaves, "different key ⇒ different cover");
    assert_ne!(p_a.leaves, p_d.leaves, "different epoch ⇒ different cover");
}

#[test]
fn community_witness_stamps_in_mls_context() {
    // Per-community witness body carries the community_id +
    // MLS group epoch. The signed-inside-MLS-encryption discipline
    // is enforced at the transport layer (MLS PrivateMessage); this
    // test asserts the body shape.
    let leaves: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i; 32]).collect();
    let root = compute_merkle_root(&leaves);
    let body = WholenessWitness {
        peer_id: "alice".into(),
        epoch_id: 9,
        merkle_root: root,
        leaf_count: u32::try_from(leaves.len()).unwrap(),
        claim_namespaces: vec!["holding_claim".into()],
        observed_at_unix_ms: 0,
        witness_version: 1,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: String::new(),
    };
    let cw = CommunityWitness::new(body.clone(), "community-A", 42);
    assert_eq!(cw.community_id, "community-A");
    assert_eq!(cw.mls_group_epoch, 42);
    assert_eq!(cw.witness.merkle_root, body.merkle_root);
}
