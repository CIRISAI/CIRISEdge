//! v6.0.0 (CIRISEdge#175, FSD §2.4) — scope-privacy end-to-end.
//!
//! Two-peer setup: alice and bob share an MLS group exporter_secret;
//! charlie is outside the group. Alice "publishes" a record at
//! community scope (derives record_id + symbol_key); bob reproduces
//! the same `record_id`/`symbol_key` from the same exporter_secret;
//! charlie's distinct exporter_secret produces non-matching bytes.
//!
//! Scope: validates that v6.3.0's `ciris_crypto::scope_privacy`
//! derivations work end-to-end from edge's re-export path AND that
//! cross-impl conformance vectors reproduce.

use ciris_edge::{derive_record_id, derive_symbol_key, k_record_id, k_symbol, RecordType};

/// Alice and bob share `exporter_secret`; they derive the same
/// `record_id` and `symbol_key`. Charlie's distinct exporter_secret
/// produces different bytes — community-scope confidentiality.
#[test]
fn community_member_sees_matching_record_id_outsider_does_not() {
    // Alice + bob: shared MLS group exporter_secret.
    let group_exporter = [0x42u8; 32];
    let community_epoch = 7;
    let internal_id = b"record-0001";

    let alice_k_rec = k_record_id(&group_exporter);
    let bob_k_rec = k_record_id(&group_exporter);
    assert_eq!(
        alice_k_rec, bob_k_rec,
        "shared exporter_secret yields identical K_record_id"
    );

    let alice_rid = derive_record_id(
        &alice_k_rec,
        internal_id,
        RecordType::CommunityRecord,
        community_epoch,
    );
    let bob_rid = derive_record_id(
        &bob_k_rec,
        internal_id,
        RecordType::CommunityRecord,
        community_epoch,
    );
    assert_eq!(
        alice_rid, bob_rid,
        "community members produce identical record_id from shared state"
    );

    // Charlie: outside the group, distinct exporter_secret.
    let charlie_exporter = [0xCCu8; 32];
    let charlie_k_rec = k_record_id(&charlie_exporter);
    let charlie_rid = derive_record_id(
        &charlie_k_rec,
        internal_id,
        RecordType::CommunityRecord,
        community_epoch,
    );
    assert_ne!(
        alice_rid, charlie_rid,
        "outsider with distinct exporter_secret produces distinct record_id"
    );
}

/// §2.4 symbol_key — community members derive identical symbol keys
/// for each (record_id, symbol_index) pair; outsiders cannot.
#[test]
fn community_members_share_symbol_keys_outsider_does_not() {
    let group_exporter = [0x42u8; 32];
    let alice_k_sym = k_symbol(&group_exporter);
    let bob_k_sym = k_symbol(&group_exporter);
    assert_eq!(alice_k_sym, bob_k_sym);

    let alice_k_rec = k_record_id(&group_exporter);
    let rid = derive_record_id(&alice_k_rec, b"record-001", RecordType::CommunityRecord, 1);

    // 20 symbol fragments (the default RaptorQ N=20 from FSD §2.4).
    for idx in 0..20u16 {
        let alice_sym = derive_symbol_key(&alice_k_sym, &rid, idx);
        let bob_sym = derive_symbol_key(&bob_k_sym, &rid, idx);
        assert_eq!(alice_sym, bob_sym, "symbol {idx} matches across members");
    }

    // Outsider charlie — distinct exporter, can't reproduce.
    let charlie_exporter = [0xCCu8; 32];
    let charlie_k_sym = k_symbol(&charlie_exporter);
    let charlie_sym = derive_symbol_key(&charlie_k_sym, &rid, 0);
    let alice_sym = derive_symbol_key(&alice_k_sym, &rid, 0);
    assert_ne!(charlie_sym, alice_sym);
}

/// §2.4 — distinct record_types under the same key produce distinct
/// `record_id`s, even with identical internal_id + epoch.
#[test]
fn record_type_disambiguates_record_id() {
    let k = k_record_id(&[0x99u8; 32]);
    let rid_self = derive_record_id(&k, b"x", RecordType::SelfRecord, 1);
    let rid_fam = derive_record_id(&k, b"x", RecordType::FamilyRecord, 1);
    let rid_com = derive_record_id(&k, b"x", RecordType::CommunityRecord, 1);
    let rid_fed = derive_record_id(&k, b"x", RecordType::FederationRecord, 1);
    assert_ne!(rid_self, rid_fam);
    assert_ne!(rid_fam, rid_com);
    assert_ne!(rid_com, rid_fed);
    assert_ne!(rid_self, rid_fed);
}

/// §2.2 domain separation — k_record_id and k_symbol must NEVER
/// match for the same exporter_secret. If they did, a holder
/// observing one would compromise the other.
#[test]
fn record_id_and_symbol_subkeys_are_distinct() {
    let exporter = [0x42u8; 32];
    assert_ne!(k_record_id(&exporter), k_symbol(&exporter));
}

/// §2.4 — epoch advance produces non-matching record_id even with
/// the same internal_id + record_type. The MLS epoch-advance is the
/// rotation hook FSD §3.5 leans on.
#[test]
fn epoch_advance_rotates_record_id() {
    let k = k_record_id(&[0x11u8; 32]);
    let rid_e0 = derive_record_id(&k, b"x", RecordType::CommunityRecord, 0);
    let rid_e1 = derive_record_id(&k, b"x", RecordType::CommunityRecord, 1);
    assert_ne!(rid_e0, rid_e1);
}
