//! v6.0.0 (CIRISEdge#175, FSD §3.3) — directory cache end-to-end.
//!
//! Simulates the `federation_keys` anti-entropy stream populating
//! the cache. Per FSD §3.3, no per-invitation directory query is
//! emitted; the cache is the only lookup surface. Subpoena of the
//! directory yields the federation-public X-Wing keys (already
//! public per §9.5) but no `querier → invitee` edges.

#![allow(clippy::similar_names)]

use ciris_crypto::hpke::XWingRecipientPublic;
use ciris_crypto::{ml_kem, x25519, MlDsa65Signer, PqcSigner};
use ciris_edge::{
    unwrap_welcome, wrap_welcome, DirectoryCache, DirectoryRecord, IdentityType, Reachability,
    XWingPublic,
};

#[test]
fn anti_entropy_populated_cache_resolves_by_federation_id() {
    let cache = DirectoryCache::new();
    assert!(cache.is_empty());

    // Simulate two anti-entropy events.
    cache.insert(DirectoryRecord {
        federation_id: "alice@fed.example".into(),
        ml_dsa_pk: vec![0x11u8; 1952],
        x_wing_pk: Some(XWingPublic {
            x25519_pub: [0x11; 32],
            mlkem768_pub: vec![0x11; 1184],
        }),
        identity_type: IdentityType::agent(),
        reachability: Reachability::Direct,
    });
    cache.insert(DirectoryRecord {
        federation_id: "bob@fed.example".into(),
        ml_dsa_pk: vec![0x22u8; 1952],
        x_wing_pk: Some(XWingPublic {
            x25519_pub: [0x22; 32],
            mlkem768_pub: vec![0x22; 1184],
        }),
        identity_type: IdentityType::phone(),
        reachability: Reachability::Relay,
    });

    assert_eq!(cache.len(), 2);
    let alice = cache.get("alice@fed.example").unwrap();
    assert_eq!(alice.identity_type, IdentityType::agent());
    assert_eq!(alice.reachability, Reachability::Direct);
    let bob = cache.get("bob@fed.example").unwrap();
    assert_eq!(bob.identity_type, IdentityType::phone());
    assert_eq!(bob.reachability, Reachability::Relay);
}

#[test]
fn cache_drives_welcome_wrap_unwrap_directory_lookup() {
    let cache = DirectoryCache::new();

    let inviter = MlDsa65Signer::new().unwrap();
    let inviter_pk_bytes = inviter.public_key().unwrap();
    cache.insert(DirectoryRecord {
        federation_id: "inviter-X".into(),
        ml_dsa_pk: inviter_pk_bytes.clone(),
        x_wing_pk: None,
        identity_type: IdentityType::steward(),
        reachability: Reachability::Direct,
    });

    // Build an invitee X-Wing keypair (also added to cache).
    let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().unwrap();
    let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().unwrap();
    let invitee_pk = XWingRecipientPublic {
        x25519_pub: x_pk,
        mlkem768_pub: mlkem_pk.clone(),
    };
    let invitee_sk = ciris_crypto::hpke::XWingRecipientSecret {
        x25519_priv: x_sk,
        mlkem768_priv: mlkem_sk,
        mlkem768_pub: mlkem_pk,
    };

    let welcome = b"directory-driven Welcome unwrap";
    let wrapped = wrap_welcome(&inviter, "inviter-X", &invitee_pk, welcome, b"").unwrap();

    let opened = unwrap_welcome(&invitee_sk, &wrapped, b"", cache.welcome_wrap_lookup()).unwrap();
    assert_eq!(opened, welcome);
}

#[test]
fn revocation_via_remove_drops_directory_record() {
    let cache = DirectoryCache::new();
    cache.insert(DirectoryRecord {
        federation_id: "ephemeral".into(),
        ml_dsa_pk: vec![0; 1952],
        x_wing_pk: None,
        identity_type: IdentityType::agent(),
        reachability: Reachability::Direct,
    });
    assert!(cache.contains("ephemeral"));
    let removed = cache.remove("ephemeral").unwrap();
    assert_eq!(removed.federation_id, "ephemeral");
    assert!(!cache.contains("ephemeral"));
}
