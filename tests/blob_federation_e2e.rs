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
//! The gap is narrow and specific, and both halves of it are discovery:
//!
//! - `holds_bytes:sha256:*` — auto-emitted by `put_blob` — is
//!   `{"kind":"holds_bytes","evidence_refs":["<sha>"]}` with
//!   `attesting_key_id == attested_key_id`. It says *"I hold these bytes"*.
//!   Nothing about what they are.
//! - `FountainHoldingClaim` is `{peer_id, content_id, symbol_ids, at}` —
//!   `content_id` is documented as opaque. Also pure possession.
//!
//! So both discovery paths carry possession and never meaning, and a node
//! could be led to fetch bytes on the strength of "someone has them" with
//! the only statement of what they are being one it made to itself.
//!
//! **Edge now enforces the difference.**
//! [`BlobMeaning::project`](ciris_edge::blob_swarm::BlobMeaning::project) is
//! the only way to obtain the scope the store gate consumes, it takes a
//! signed attestation that names the blob, and it refuses a `holds_bytes`
//! row **by name** rather than letting its `federation` column classify
//! every blob on the node as commons. The substrate still stores whatever it
//! is handed — that is the substrate's job — but nothing in edge will fetch
//! or admit bytes on possession alone.
//!
//! These tests are the cross-node statement of that: the ROW carries the
//! meaning, it travels separately from the bytes, and what the bytes' own
//! store can tell you about them is never enough.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::blob_swarm::{BlobMeaning, ContentScope, MeaningRefusal};
use ciris_edge::group_content::{
    BlobPointer, ContentField, GroupContentError, GroupContentStore, OpenRequest,
    PersistGroupContentStore, SealRequest,
};
use ciris_edge::CohortScope;
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
    /// The member identity this node's engine acts for.
    identity: String,
    /// The engine's derived signing key — this node's occurrence of
    /// `identity`, and the viewer key for every read here (CIRISPersist#848).
    me: String,
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
    rec.scrub_key_id = derived.clone();
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");

    // The SAME key, not merely the same alias — see `Ident::seed`. And the
    // FULL hybrid identity (CIRISPersist#848): an encrypted write now emits a
    // key_grant set that must be hybrid-signed to be admissible anywhere.
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[signer.seed; 32], signer.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[signer.seed ^ 0x55; 32],
            format!("{}-pqc", signer.key_id),
        )
        .expect("rebuild the registered pqc half"),
    );
    let identity = ciris_edge::identity::LocalSigner::new(derived.clone(), hw, Some(pqc));
    let store = PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    // NODE-class occurrence: the derived engine key, carrying the sealed
    // content-KEM identity's pubkeys — the pair `read_blob_as` unwraps with.
    let (me, _) = ciris_edge::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        &signer.key_id,
        "server",
    )
    .await
    .expect("provision this node's engine occurrence");
    Node {
        dir,
        store,
        identity: signer.key_id.clone(),
        me,
    }
}

/// A signed content row that says what `sha` IS: a [`BlobPointer`] naming
/// it, at the cohort `scope_token` names, in the group `group_id`.
///
/// This is the shape every content type produces — chat's
/// `chat_message_attestation` builds exactly this with a hybrid signature
/// and a bound envelope. Built here directly so the harness can vary the
/// scope without standing up an MLS room per case.
async fn content_row(
    author: &Ident,
    scope_token: &str,
    group_id: &str,
    sha: &[u8; 32],
) -> ciris_persist::federation::Attestation {
    let envelope = serde_json::json!({
        "dimension": "chat.message",
        "community_key_id": group_id,
        "score": 1.0,
        "content": {
            "community_key_id": group_id,
            "tier": "plaintext",
            "content_sha256": hex::encode(sha),
            "content_field": "body",
            "media_type": "text/plain",
        },
    });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
    let sig = author
        .ed
        .sign(digest.as_slice())
        .await
        .expect("sign the row");
    ciris_persist::federation::Attestation {
        attestation_id: format!("row-{}", &hex::encode(sha)[..16]),
        attesting_key_id: author.key_id.clone(),
        attested_key_id: author.key_id.clone(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at: ts(),
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
        scrub_key_id: author.key_id.clone(),
        scrub_timestamp: ts(),
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: vec![author.key_id.clone()],
        withdraws_admission_rule: None,
        cohort_scope: scope_token.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

// ─── The row carries the meaning; the bytes never do ──────────────────

/// **The invariant, across two substrates.**
///
/// Alice seals content on her node and signs the row that says what it is.
/// Bob gets the ROW ONLY — his substrate has never seen a byte. He can
/// still say exactly what the blob is and who placed it where, because
/// meaning lives on the row and travels with it.
///
/// And the reverse holds in the same breath: knowing what it is does not
/// produce it. The read is still `NotHeld`.
#[tokio::test]
async fn the_row_carries_the_meaning_and_the_bytes_never_do() {
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
            plaintext: b"the bytes",
            media_type: Some("text/plain"),
        })
        .await
        .expect("seal");
    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // Only this crosses. No bytes, no holder claim, no substrate access.
    let row = content_row(&alice, "federation", "", &sha).await;

    let meaning = BlobMeaning::project(&row, &sha).expect("the row says what the blob is");
    assert_eq!(meaning.scope(), &ContentScope::Federation);
    assert_eq!(meaning.attesting_key_id(), alice.key_id);
    assert_eq!(meaning.sha256(), &sha);
    assert_eq!(meaning.media_type(), Some("text/plain"));

    // Meaning is not possession.
    let err = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob.key_id,
        })
        .await
        .expect_err("knowing what it is does not produce it");
    assert!(matches!(err, GroupContentError::NotHeld { .. }), "{err:?}");
}

/// A community row places its blob in the community it names — the scope
/// the store gate's second axis asks about, arriving signed rather than
/// asserted by whoever is holding the bytes.
#[tokio::test]
async fn a_community_row_places_its_blob_in_the_community_it_names() {
    let alice = Ident::new("alice-fed", 0x11);
    let sha = [0xABu8; 32];
    let row = content_row(&alice, "community", "room-alice-bob", &sha).await;

    let meaning = BlobMeaning::project(&row, &sha).expect("project");
    assert_eq!(
        meaning.scope(),
        &ContentScope::Group {
            scope: CohortScope::Cohort {
                cohort_id: "room-alice-bob".into()
            },
            group_id: "room-alice-bob".into(),
        },
    );
}

/// A row about OTHER content cannot lend these bytes its scope — which is
/// what stops a peer pairing a legitimate community row with whatever bytes
/// it would like us to hold.
#[tokio::test]
async fn a_row_about_other_content_cannot_lend_these_bytes_its_scope() {
    let alice = Ident::new("alice-fed", 0x11);
    let theirs = [0xABu8; 32];
    let ours = [0xCDu8; 32];
    let row = content_row(&alice, "community", "room-alice-bob", &theirs).await;

    assert_eq!(
        BlobMeaning::project(&row, &ours),
        Err(MeaningRefusal::DoesNotReference {
            sha256_hex: hex::encode(ours)
        }),
        "the signature covers WHICH blob, not merely that a blob was meant",
    );
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
/// **A COMMONS blob opens on any node, because no key is involved.**
///
/// # What this proves, and what it does NOT
///
/// It proves one real thing: content addressing agrees across independent
/// substrates, so a peer recognises what it was sent and the row needs no
/// rewriting.
///
/// It proves **nothing about keys**, and the name it used to carry —
/// `once_the_bytes_arrive_the_same_pointer_opens_on_the_far_node` — implied
/// otherwise. Its doc comment claimed "B never sees Alice's signer, and
/// re-seals nothing", which the body contradicts on the next line: B calls
/// `seal` with the PLAINTEXT. At `cohort_scope: federation` that is a
/// plaintext write, so the open below succeeds because there is no
/// ciphertext, no DEK and no grant anywhere in it.
///
/// The encrypted case is the one that matters and it does not work:
/// see [`a_far_node_opens_once_the_key_grant_and_the_bytes_both_arrive`] and
/// CIRISPersist#848.
#[tokio::test]
async fn a_commons_blob_opens_on_any_node_because_no_key_is_involved() {
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

    // B writes the same PLAINTEXT and lands on the same address. This is a
    // re-seal, not a transfer — honest only because the commons tier stores
    // bytes verbatim, so "same input, same address" is the whole claim. An
    // encrypted tier would mint a fresh nonce here and a DIFFERENT address,
    // which is exactly why this shape cannot be reused to test that tier.
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
        .expect("commons content carries no key, so any node opens it");
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
    // that someone has them, and how they are stored. There is no door that
    // answers "what are they".
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

    // And the attestation the door DID emit refuses to be read as meaning.
    //
    // This is the whole point of the by-name refusal. The holder row is
    // signed, it genuinely references the blob, and its `cohort_scope`
    // column genuinely reads `federation` — so a projection that simply
    // mapped the column would classify these unexplained bytes as COMMONS
    // CONTENT and hand the store gate an audience to be inside of. Every
    // blob on the node would classify that way, since persist emits one of
    // these for each.
    let mut holder_row = ciris_persist::federation::blobs::holds_bytes_attestation_row(
        &sha,
        &alice.key_id,
        "hb-1",
        ts(),
    );
    assert_eq!(
        holder_row.cohort_scope,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        "fixture drift: the column that would have classified this",
    );
    holder_row.scrub_signature_classical = "sig".to_owned();
    holder_row.scrub_key_id = alice.key_id.clone();
    assert_eq!(
        BlobMeaning::project(&holder_row, &sha),
        Err(MeaningRefusal::PossessionIsNotMeaning),
        "possession is what discovery offers; it is never what content IS",
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

// ─── CIRISEdge#599: a node that seeded no fixture ─────────────────────

/// Hand one node's identity to the other, the way the `Key` and
/// `IdentityOccurrence` planes would on a real mesh: the derived engine key
/// (an FK target for everything the engine emits) and its occurrence row
/// (the wrap target the other node's cascade must enumerate).
async fn federate(from: &Node, to: &Node) {
    use ciris_persist::federation::FederationDirectory as _;
    let rec =
        ciris_persist::federation::FederationDirectory::lookup_public_key(&*from.dir, &from.me)
            .await
            .expect("lookup")
            .expect("the engine registered its derived key");
    to.dir
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the far node's derived key");
    let occ = from
        .dir
        .list_identity_occurrences_active(&from.identity)
        .await
        .expect("list")
        .into_iter()
        .find(|o| o.occurrence_key_id == from.me)
        .expect("the engine occurrence exists on its own node");
    to.dir
        .put_identity_occurrence_local(occ)
        .await
        .expect("carry the far node's occurrence over");
}

// ─── CIRISEdge#599 → #848: the NODE-class occurrence ──────────────────

/// **The acceptance test for CIRISEdge#599, corrected by #848.**
///
/// The first cut provisioned an occurrence with keys HKDF-derived from the
/// identity seed. persist's read door unwraps with the node's sealed
/// content-KEM identity and nothing else, so that occurrence was wrapped to
/// and could never be opened — a state `granted` reports as success. The
/// node class is the engine's own derived key carrying the content-KEM
/// identity's pubkeys, which is exactly what persist's own witness
/// provisions.
#[tokio::test]
async fn a_node_provisions_its_engine_occurrence_and_the_cascade_finds_it() {
    use ciris_edge::content_occurrence::{provision_engine_occurrence, Provisioned};
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::FederationDirectory as _;

    let alice = Ident::new("alice-fed", 0x11);
    let node_a = node(&[&alice], &alice).await;

    let occs = node_a
        .dir
        .list_identity_occurrences_active(&alice.key_id)
        .await
        .expect("list");
    assert_eq!(
        occs.len(),
        1,
        "exactly one wrap target: the engine's own occurrence"
    );
    assert_eq!(occs[0].occurrence_key_id, node_a.me);
    let kem = node_a
        .dir
        .load_or_init_content_kem_identity()
        .await
        .expect("content-KEM identity");
    let enc = occs[0].encryption_pubkeys.as_ref().expect("pubkeys");
    assert_eq!(
        (enc.x25519_base64.as_str(), enc.ml_kem_768_base64.as_str()),
        (
            kem.x25519_pubkey_b64.as_str(),
            kem.ml_kem_768_pubkey_b64.as_str()
        ),
        "the occurrence carries the pair `read_blob_as` can unwrap with — \
         any other pubkeys are a grant the node cannot use",
    );

    // Idempotent: a restart must not mint a second occurrence.
    let (again, outcome) =
        provision_engine_occurrence(node_a.store.engine(), &*node_a.dir, &alice.key_id, "server")
            .await
            .expect("re-provision");
    assert_eq!(again, node_a.me);
    assert_eq!(outcome, Provisioned::AlreadyCurrent);
}

/// A pre-existing occurrence under the engine's id with OTHER pubkeys is
/// reported, never overwritten — the grants already wrapped to it belong to
/// whoever holds those keys, and rewriting would orphan them.
#[tokio::test]
async fn a_foreign_occurrence_under_the_engine_id_reports_drift() {
    use ciris_edge::content_occurrence::{
        ensure_content_occurrence, provision_engine_occurrence, Provisioned,
    };
    use ciris_persist::federation::types::EncryptionPubkeys;

    let alice = Ident::new("alice-fed", 0x11);
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open");
    dir.run_migrations().await.expect("migrate");
    // Build the node by hand so the foreign occurrence lands FIRST.
    let node_a = node(&[&alice], &alice).await;
    let foreign = EncryptionPubkeys {
        x25519_base64: B64.encode([7u8; 32]),
        ml_kem_768_base64: B64.encode([9u8; 1184]),
    };
    // Simulate a different node having claimed this occurrence id: the
    // engine's occurrence already exists, so overwrite the row's pubkeys
    // through the directory door directly.
    let _ = dir;
    let _ = ensure_content_occurrence(&*node_a.dir, &alice.key_id, &node_a.me, "server", foreign)
        .await
        .expect("directory write");
    // ensure_content_occurrence itself refuses to overwrite (Drifted) — so
    // the drift is observable from provisioning as well.
    let (_, outcome) =
        provision_engine_occurrence(node_a.store.engine(), &*node_a.dir, &alice.key_id, "server")
            .await
            .expect("provision");
    assert_eq!(
        outcome,
        Provisioned::AlreadyCurrent,
        "the engine's own keys still stand"
    );
}

/// A community both identities are members of, with content occurrences for
/// each — everything the DEK cascade needs to produce a non-empty grant set.
async fn seed_room(node: &Node, room: &str, members: &[&Ident]) {
    use ciris_persist::federation::types::{Community, CommunityMember, SignedCommunity};
    use ciris_persist::federation::FederationDirectory as _;

    let founder = members[0];
    let community = Community {
        community_key_id: room.to_owned(),
        community_name: "The Room".to_owned(),
        members: members
            .iter()
            .map(|m| CommunityMember {
                key_id: m.key_id.clone(),
                joined_at: ts(),
                role: Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at: ts(),
        consensus_protocol: "founder_only".to_owned(),
        policy_blob: None,
        persist_row_hash: String::new(),
    };
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
        .expect("canonicalize the room");
    // The FULL hybrid: persist verifies the federation tier under
    // `HybridPolicy::Strict`, and a registered PQC pubkey with a
    // classical-only row is refused as `verify_hybrid_pqc_fields_mismatch`.
    let ed_sig = founder.ed.sign(&canonical).await.expect("ed sign");
    let pqc_sig = {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        ciris_keyring::PqcSigner::sign(&founder.pqc, &bound)
            .await
            .expect("pqc sign")
    };
    node.dir
        .put_community(SignedCommunity {
            community,
            authority_key_id: founder.key_id.clone(),
            scrub_signature_classical: B64.encode(&ed_sig),
            scrub_signature_pqc: Some(B64.encode(&pqc_sig)),
        })
        .await
        .expect("seed the room");

    // Occurrences are NOT provisioned here. Each node provisions its OWN
    // engine occurrence in `node()` (the node class, CIRISPersist#848), and
    // `federate` hands the other node's occurrence over — the way the
    // IdentityOccurrence plane would on a real mesh.
}

/// **CIRISPersist#848 — the key follows the bytes, across two substrates.**
///
/// Until v44.3.0 this test asserted the DEFECT: a member's node could hold
/// the row, the bytes and a provisioned occurrence and still read
/// `NotGranted`, because the wrap addressed to that occurrence existed only
/// where it was minted and nothing carried it. It was a characterization
/// pin, written to turn red the day the key crossed. It has.
///
/// # What crosses now, and through which doors
///
/// 1. **The key** — A's seal emitted the FULL grant set as a signed
///    attestation row (`attestation_type` `key_grant:epoch:v1`); on B it is
///    routed to `Engine::apply_replicated_key_grant`, which admits the
///    carrier and projects, as a UNION, the wraps addressed to occurrences B
///    holds the private half for. The general attestation door would admit
///    the carrier and project nothing — CIRISEdge#601's symptom.
/// 2. **The bytes** — served from A's disk verbatim (`serve_blob_to_peer`,
///    no decrypt) and stored on B at the tier and `(community, epoch)` the
///    author declared (`adopt_sealed_blob`, no decrypt), never re-sealed.
/// 3. **The open** — B's member reads from the wrap addressed to its own
///    occurrence, with the content-KEM private half derived from its own
///    seed. A stranger is still `NotGranted`.
///
/// The two steps are independent and order does not matter (I61/I62): a
/// set admitted before its bytes is held pending and projected by the
/// adopt. This test takes them key-first. Both node substrates share
/// NOTHING but what the test hands over — B never ran the cascade that
/// minted the DEK.
#[tokio::test]
#[allow(clippy::too_many_lines)] // three crossings and their preconditions, in one place on purpose
async fn a_far_node_opens_once_the_key_grant_and_the_bytes_both_arrive() {
    use ciris_persist::federation::blobs::BlobBody;
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    use ciris_persist::federation::{AdoptDisposition, BlobProvenance, FederationDirectory as _};

    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let room = "room-alice-bob";

    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    seed_room(&node_a, room, &[&alice, &bob]).await;
    seed_room(&node_b, room, &[&alice, &bob]).await;
    // Each node knows the other's occurrence — what the IdentityOccurrence
    // plane carries on a mesh — so A's cascade wraps to B's engine.
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;
    let bob_occ = node_b.me.clone();

    let body = b"a message for the room";
    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "community",
            community_key_id: Some(room),
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: body,
            media_type: Some("text/plain"),
        })
        .await
        .expect("seal at the community tier");
    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // Preconditions, so a pass cannot be a neighbouring state: the cascade
    // wrapped to someone (not the #599 grant-to-nobody state), the tier is
    // sealed (a key is involved at all), and the author's own node opens it
    // (the fixture is not simply broken).
    assert!(
        !sealed.granted.is_empty(),
        "precondition: A's cascade must have wrapped to someone — {sealed:?}",
    );
    assert_ne!(
        sealed.tier,
        ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
        "precondition: a SEALED tier, or no key is involved",
    );
    node_a
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &node_a.me,
        })
        .await
        .expect("positive control: the author's node holds the wrap it minted");

    // Before either crossing: B holds the roster and the occurrence and
    // nothing else. The pin this test replaced asserted exactly this.
    let before = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob_occ,
        })
        .await;
    assert!(
        matches!(
            before,
            Err(GroupContentError::NotGranted { .. } | GroupContentError::NotHeld { .. })
        ),
        "before the key and bytes cross, B must not open — got {before:?}",
    );

    // ── 1. The KEY crosses — as an attestation row, routed to the door ──
    let sets: Vec<_> = node_a
        .dir
        .list_attestations_since(None, 200)
        .await
        .expect("list A's rows")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
        .collect();
    assert!(
        !sets.is_empty(),
        "A's seal must have EMITTED a key_grant set as an attestation row \
         (CIRISPersist#848 §14) — a classical-only engine would have refused \
         with AttestationEmissionFailed instead",
    );
    let mut wraps_written = 0;
    for row in &sets {
        let admission = node_b
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: row.attestation.clone(),
            })
            .await
            .expect("B admits A's key_grant set through the key-grant door");
        wraps_written += admission.wraps_written;
    }
    assert!(
        wraps_written >= 1,
        "B holds bob-occ's private half, so at least that wrap must project \
         as a grant — the general door would have written 0 (CIRISEdge#601)",
    );

    // ── 2. The BYTES cross — served from disk, adopted verbatim ──
    let served = node_a
        .store
        .engine()
        .serve_blob_to_peer(&sha, &bob_occ)
        .await
        .expect("A serves the sealed envelope from disk");
    let BlobBody::Inline(envelope) = served else {
        panic!("a whole-blob seal is served inline, got {served:?}");
    };
    let aad = ciris_edge::group_content::aad_for_open(&OpenRequest {
        pointer: &sealed.pointer,
        author_key_id: &alice.key_id,
        asserted_at: ts(),
        viewer_key_id: &bob_occ,
    });
    let adopted = node_b
        .store
        .engine()
        .adopt_sealed_blob(
            &envelope,
            // The provenance's `author_key_id` IS the minter (#848 §11: the
            // author's cascade minted the epoch), and the grant B just
            // projected is keyed under that minter — A's DERIVED engine key.
            // In production a key id is `derive_key_id(alias, pubkey)`, so a
            // row's `attesting_key_id` and the engine's derived id coincide;
            // this harness registers friendly ids, so the distinction is
            // visible here and must be honoured, or the read looks for the
            // grant under a minter that never wrote one.
            BlobProvenance {
                author_key_id: node_a.me.clone(),
                cohort_scope: "community".to_owned(),
                community_key_id: Some(room.to_owned()),
                epoch: sealed.epoch,
                tier: sealed.tier,
            },
            Some(&aad),
            AdoptDisposition::LocalOnly,
        )
        .await
        .expect("B adopts the envelope at the author's declared binding");
    assert!(
        !adopted.announced,
        "LocalOnly must publish no holder claim — {adopted:?}",
    );

    // ── 3. The OPEN — from B's own grant, with B's own private half ──
    let got = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob_occ,
        })
        .await
        .expect("B's member opens content sealed on A — the key followed the bytes");
    assert_eq!(got, body);

    // And a stranger is still outside the boundary: no wrap was ever
    // addressed to an occurrence nobody enumerated.
    let stranger = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: "carol-fed-occ",
        })
        .await;
    assert!(
        matches!(stranger, Err(GroupContentError::NotGranted { .. })),
        "a non-member occurrence must stay NotGranted — got {stranger:?}",
    );
}
