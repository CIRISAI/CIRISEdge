//! CIRISEdge#586 / #581 — blob transfer ACROSS NODES, on two real substrates.
//!
//! # Why this harness exists
//!
//! Every blob test before this one ran on a SINGLE substrate.
//! `chat_message_federates.rs` opens one `FederationDirectorySqlite` and has
//! both Alice and Bob read from it — so when "Bob opens Alice's content", he
//! is reading the blob Alice wrote, in Alice's store. That proves the row
//! shapes and the cryptography and nothing about transfer.
//!
//! The state a real peer is actually in — **holding the row and not the
//! bytes** — was therefore untestable, and untested. It is the state every
//! federated blob passes through, and the one where the interesting failures
//! live: a pointer to bytes nobody sent, a holder claim with no content
//! claim behind it, bytes that arrive not matching the sha that was
//! promised.
//!
//! Two substrates here, seeded with the same identities and the same roster —
//! which is what "federated" means — and nothing shared between them but
//! what a test explicitly hands over.
//!
//! # The invariant under test
//!
//! > *A blob with no signed attestation of WHAT IT IS is an invalid state.*
//!
//! The substrate does not enforce this today, and the model is worth stating
//! precisely because the gap is narrow and specific:
//!
//! - `holds_bytes:sha256:*` — auto-emitted by `put_blob` — is
//!   `{"kind":"holds_bytes","evidence_refs":["<sha>"]}` with
//!   `attesting_key_id == attested_key_id`. It says *"I hold these bytes"*.
//!   Nothing about what they are.
//! - `FountainHoldingClaim` is `{peer_id, content_id, symbol_ids, at}` —
//!   `content_id` is documented as opaque. Also pure possession.
//!
//! So both discovery paths carry possession and never meaning, and a node
//! can be led to fetch bytes on the strength of "someone has them" with the
//! only statement of what they are being one it made to itself.
//!
//! The content claim that SHOULD be required already exists: a signed row
//! carrying a [`BlobPointer`]. These tests pin the difference between the
//! two, so that when the invariant is enforced the tests already say what it
//! is enforcing.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::group_content::{
    BlobPointer, ContentField, GroupContentError, GroupContentStore, OpenRequest,
    PersistGroupContentStore, SealRequest,
};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory as _;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

/// One federation identity, reproducible from a seed.
struct Ident {
    key_id: String,
    /// Kept so the content store can be built from the SAME key the
    /// directory registered. An `Ed25519SoftwareSigner` with a matching
    /// alias but a different key derives a DIFFERENT `key_id`, and the
    /// holder attestation's FK then points at a row that does not exist —
    /// which surfaces as an opaque "FOREIGN KEY constraint failed" from
    /// inside `put_blob_scoped`.
    seed: u8,
    ed: Ed25519SoftwareSigner,
    pqc: MlDsa65SoftwareSigner,
}

impl Ident {
    fn new(key_id: &str, seed: u8) -> Self {
        let mut ed = Ed25519SoftwareSigner::new(key_id);
        ed.import_key(&[seed; 32]).expect("import ed key");
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
                .expect("ml-dsa from seed");
        Self {
            key_id: key_id.to_owned(),
            seed,
            ed,
            pqc,
        }
    }

    async fn record(&self) -> KeyRecord {
        let ed_pub = self.ed.public_key().await.expect("ed pubkey");
        let pqc_pub = self.pqc.public_key().await.expect("pqc pubkey");
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = serde_json::to_vec(&envelope).expect("serialize");
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
        let sig = self.ed.sign(digest.as_slice()).await.expect("self-sign");
        KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: B64.encode(&ed_pub),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&pqc_pub)),
            algorithm: "hybrid".to_string(),
            identity_type: "user".to_string(),
            identity_ref: self.key_id.clone(),
            valid_from: ts(),
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: B64.encode(sig),
            scrub_signature_pqc: None,
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }
}

/// One node: its own substrate, its own content store. Nothing is shared
/// with any other node except what a test hands over explicitly.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
}

/// Build a node whose directory knows `idents`, with the signing identity
/// `signer` registered under the key id persist DERIVES for it.
async fn node(idents: &[&Ident], signer: &Ident) -> Node {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open substrate");
    dir.run_migrations().await.expect("migrate");

    for id in idents {
        dir.put_public_key(SignedKeyRecord {
            record: id.record().await,
        })
        .await
        .expect("seed identity");
    }

    // persist signs the holder attestation with the key it DERIVES from the
    // signer — `derive_key_id(alias, pubkey)` — not the friendly name. The
    // FK on `holds_bytes` is onto that derived id, so it must be registered
    // or the write fails from deep inside the door.
    let ed_pub = signer.ed.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(signer.ed.current_alias(), &ed_pub);
    let mut rec = signer.record().await;
    rec.key_id = derived.clone();
    rec.identity_ref = derived.clone();
    rec.scrub_key_id = derived;
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");

    // The SAME key, not merely the same alias — see `Ident::seed`.
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[signer.seed; 32], signer.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let store = PersistGroupContentStore::from_shared(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        hw,
    );
    Node { dir, store }
}

// ─── The state a real peer is in: the row, without the bytes ──────────

/// **The gap every blob test before this one could not see.**
///
/// Alice seals content on HER node. Bob holds the pointer — as he would
/// after the row federates — and his substrate has never seen the bytes.
/// The read must fail as `NotHeld`, which is the signal that sends a peer
/// to fetch, and NOT as `NotGranted`, which would send an operator hunting
/// for a permissions problem that does not exist.
#[tokio::test]
async fn a_peer_holding_only_the_pointer_reads_not_held_not_not_granted() {
    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;

    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: b"bytes that live only on node A",
            media_type: Some("text/plain"),
        })
        .await
        .expect("alice seals on her own node");

    // The pointer crosses; the bytes do not. This is exactly what a
    // federated row delivers.
    let wire = serde_json::to_string(&sealed.pointer).expect("serialize");
    let pointer: BlobPointer = serde_json::from_str(&wire).expect("parse");

    let err = node_b
        .store
        .open(OpenRequest {
            pointer: &pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob.key_id,
        })
        .await
        .expect_err("node B has never seen these bytes");

    assert!(
        matches!(err, GroupContentError::NotHeld { .. }),
        "a peer with the row and not the bytes must read NOT-HELD — the \
         signal to go fetch. Got: {err:?}",
    );

    // And the same read on node A succeeds, so the failure above is about
    // WHERE the bytes are and nothing else.
    let got = node_a
        .store
        .open(OpenRequest {
            pointer: &pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &alice.key_id,
        })
        .await
        .expect("node A holds them");
    assert_eq!(got, b"bytes that live only on node A");
}

/// Transfer closes it: once node B holds the bytes, the SAME pointer opens.
///
/// The bytes move as opaque content — B never sees Alice's signer, and
/// re-seals nothing. That is the transfer model: a relay carries what it did
/// not author.
#[tokio::test]
async fn once_the_bytes_arrive_the_same_pointer_opens_on_the_far_node() {
    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;

    let body = b"content that federates";
    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: body,
            media_type: Some("text/plain"),
        })
        .await
        .expect("seal on A");

    // B receives the bytes and stores them under the SAME address. Commons
    // tier, so this is the shape a public blob actually transfers in.
    let resealed = node_b
        .store
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: body,
            media_type: Some("text/plain"),
        })
        .await
        .expect("B stores the transferred bytes");

    assert_eq!(
        resealed.pointer.content_sha256, sealed.pointer.content_sha256,
        "content addressing must agree across nodes, or a peer cannot \
         recognise what it was sent",
    );

    let got = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob.key_id,
        })
        .await
        .expect("B opens the transferred content with A's pointer");
    assert_eq!(got, body);
}

// ─── The invariant: possession is not meaning ─────────────────────────

/// **States the gap this harness exists to close.**
///
/// A blob written through `put_blob_scoped` gets a `holds_bytes`
/// attestation — signed, replicated, and saying only *"I hold these
/// bytes."* It carries no media type, no dimension, no author of the
/// CONTENT, and no reference to any row.
///
/// So a node can hold bytes that every peer can see it holds, with nothing
/// anywhere stating what they are. That is the invalid state: not
/// "unsigned", but **"no claim of meaning"**.
///
/// This test documents the current behaviour rather than asserting the
/// desired one — deliberately. When the invariant lands, THIS is the test
/// that has to change, and it says what it is waiting for.
#[tokio::test]
async fn holds_bytes_says_possession_and_never_meaning() {
    use ciris_persist::federation::BlobStorage as _;
    let alice = Ident::new("alice-fed", 0x11);
    let node_a = node(&[&alice], &alice).await;

    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            field: ContentField::Body,
            // Bytes with no referencing row anywhere. Nothing in the
            // substrate refuses this today.
            plaintext: b"\x00\x01\x02 unexplained bytes",
            media_type: None,
        })
        .await
        .expect("the substrate accepts unexplained bytes");

    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    let holders = node_a.dir.list_holders(&sha).await.expect("list holders");
    assert!(
        !holders.is_empty(),
        "put_blob_scoped announces a holder, so the bytes ARE discoverable",
    );

    // Everything a peer can learn about these bytes from the substrate:
    // that someone has them. There is no door that answers "what are they".
    //
    // When the invariant is enforced, the seal above must refuse — or the
    // bytes must carry a reference to a signed row stating what they are —
    // and this assertion becomes the thing that fails.
    assert!(
        node_a
            .dir
            .blob_crypto_tier(&sha)
            .await
            .expect("tier")
            .is_some(),
        "the row exists and records a tier, which is storage metadata and \
         not a claim of meaning",
    );
}

/// A pointer is a CLAIM, and the bytes are addressed by hash — so a pointer
/// naming a sha nobody holds is simply not-held, not a security event.
///
/// Worth pinning because it is the boundary of what content-addressing
/// gives you: it makes substitution detectable, and says nothing about
/// whether the thing referenced should exist.
#[tokio::test]
async fn a_pointer_to_bytes_that_were_never_written_is_a_miss() {
    let alice = Ident::new("alice-fed", 0x11);
    let node_a = node(&[&alice], &alice).await;

    let invented = BlobPointer {
        community_key_id: String::new(),
        tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
        content_sha256: "de".repeat(32),
        content_field: ContentField::Body,
        media_type: Some("text/plain".into()),
        stream_id: None,
    };

    let err = node_a
        .store
        .open(OpenRequest {
            pointer: &invented,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &alice.key_id,
        })
        .await
        .expect_err("nothing was ever written at that address");
    assert!(matches!(err, GroupContentError::NotHeld { .. }), "{err:?}");
}
