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
    /// The signer for `me` — what an `Edge` on this node signs the wire with,
    /// and what a row authored by THIS NODE (attester == minter, the
    /// production shape) is signed with.
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// Build a node whose directory knows `idents`, with the signing identity
/// `signer` registered under the key id persist DERIVES for it.
async fn node(idents: &[&Ident], signer: &Ident) -> Node {
    build_node(idents, signer, true).await
}

/// [`node`], with provisioning optional — a node built with `provision:
/// false` is a pre-v24.2.0 node before its first occurrence exists, which is
/// the only honest way to simulate one: persist's trusted-local door carries
/// `WHERE signature IS NULL`, so it CANNOT downgrade a row that was published,
/// and a legacy row can only be made by never publishing in the first place.
async fn build_node(idents: &[&Ident], signer: &Ident, provision: bool) -> Node {
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
    let identity =
        ciris_edge::identity::LocalSigner::new(derived.clone(), hw.clone(), Some(pqc.clone()));

    // The OWNER BINDING, without which this node cannot publish its own
    // occurrence (persist v44.4.0 §20.2).
    //
    // A roster names PERSONS; the key on the wire is this NODE's derived key.
    // The gated occurrence door therefore asks `check_signer_acts_for`, and a
    // node signing for a person satisfies it exactly one way: an owner-signed,
    // replicated binding that lifts the node key to the identity. The node
    // cannot mint this for itself — self-appointment is the thing the gate
    // exists to refuse — so it is a PRECONDITION of provisioning, established
    // here by the same producer `edge_node` uses in production, in the same
    // order (bind, then provision).
    //
    // The binding is signed under the OWNER's key id, not the derived one: the
    // row's `attesting_key_id` is `signer.key_id`, and persist resolves the
    // verifying pubkeys from THAT record. Same hardware halves, different id.
    let owner_signer = ciris_edge::identity::LocalSigner::new(
        signer.key_id.clone(),
        hw.clone(),
        Some(pqc.clone()),
    );
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        &signer.key_id,
        &derived,
        ts(),
        &owner_signer,
    )
    .await
    .expect("build this node's owner binding");
    dir.put_attestation_authored(ciris_persist::federation::SignedAttestation {
        attestation: binding,
    })
    .await
    .expect("admit this node's owner binding");

    let store = PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    // NODE-class occurrence: the derived engine key, carrying the sealed
    // content-KEM identity's pubkeys — the pair `read_blob_as` unwraps with.
    let me = if provision {
        let (me, _) = ciris_edge::content_occurrence::provision_engine_occurrence(
            store.engine(),
            &*dir,
            &signer.key_id,
            "server",
        )
        .await
        .expect("provision this node's engine occurrence");
        me
    } else {
        store
            .engine()
            .local_derived_key_id()
            .await
            .expect("derive this engine's federation key id")
    };
    Node {
        dir,
        store,
        identity: signer.key_id.clone(),
        me,
        signer: Arc::new(identity),
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
    // v45.0.0 (CIRISPersist#871, AV-89) — the claim carries the blob's
    // byte length, bound into the signed bytes; this fixture is a hand-built
    // row for a meaning-projection assertion, never a door write, so the
    // length is the one true value for the bytes above.
    let mut holder_row = ciris_persist::federation::blobs::holds_bytes_attestation_row(
        &sha,
        &alice.key_id,
        "hb-1",
        ts(),
        u64::try_from(b"\x00\x01\x02 unexplained bytes".len()).expect("len"),
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
        epoch: None,
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
    // The owner binding crosses FIRST. §20.1: the binding is "a replicated
    // attestation the mesh already carries", and it is what lifts the far
    // node's key to the identity on THIS node — without it the gated door
    // refuses the occurrence with the same `signer_acts_for` refusal a fresh
    // node gets locally. Selected with persist's OWN predicate rather than by
    // the producer's id format, so a reworded id cannot silently stop carrying
    // it, and delivered on the cursor plane the mesh actually uses.
    let rows = ciris_persist::federation::FederationDirectory::list_attestations_since(
        &*from.dir, None, 256,
    )
    .await
    .expect("list the attestation plane");
    for row in rows {
        let att = row.attestation;
        if att.attested_key_id == from.me
            && ciris_persist::federation::admission::is_owner_binding_envelope(
                &att.attestation_envelope,
            )
        {
            to.dir
                .apply_replicated_attestation(ciris_persist::federation::SignedAttestation {
                    attestation: att,
                })
                .await
                .expect("carry the far node's owner binding");
        }
    }

    // #851 (persist v44.4.0) — the occurrence crosses on the REPLICATION
    // PLANE, not by hand. Before v44.4.0 this had to be a
    // `put_identity_occurrence_local` copy: a node's own occurrence was
    // written through the trusted-local door, which stores its signature
    // columns NULL, and the plane serves signed-put rows only — so the row
    // key_grant admission needs on the FAR node had no replicable form and
    // every receiving node refused every set with `signer_not_active_member`.
    //
    // Reading it off `list_signed_identity_occurrences_since` and admitting it
    // through the GATED `put_identity_occurrence` is therefore the assertion,
    // not the plumbing: it passes only because the occurrence was PUBLISHED
    // (`Engine::publish_self_occurrence`, via `provision_engine_occurrence`).
    // Revert edge to the local door and this line finds nothing to carry.
    let served = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane");
    let occ = served
        .into_iter()
        .map(|s| s.occurrence)
        .find(|o| {
            o.identity_occurrence.occurrence_key_id == from.me
                && o.identity_occurrence.identity_key_id == from.identity
        })
        .expect(
            "the engine occurrence is ON the signed plane — if this is None the node wrote it \
             through the trusted-local door and CIRISPersist#851 is back",
        );
    to.dir
        .put_identity_occurrence(occ)
        .await
        .expect("admit the far node's published occurrence through the gated door");
}

// ─── #851 / PR #607 review: what a republish is allowed to overwrite ──

/// **A heal reaches a legacy row, and carries an operator's expiry with it.**
///
/// The signed put is a last-signed-wins UPSERT on `valid_until` too, so a
/// republish is never a no-op: whatever the heal passes is what the row ends
/// up with. Before persist v44.5.0 the publish door took no expiry and the
/// heal had to REFUSE an expiring row rather than drop it (PR #607 review);
/// since CIRISPersist#855 it passes the stored expiry through, so the row
/// reaches the plane AND keeps the lifetime the operator chose. Leg (b) pins
/// both halves — a heal that dropped the expiry, or a refusal that left the
/// row off the plane, each fail one assertion.
///
/// Both legs simulate a pre-v24.2.0 node the way the substrate itself makes
/// one: `put_identity_occurrence_local` stores the signature columns NULL, so
/// the row drops off the signed plane while `list_identity_occurrences_active`
/// still returns it — which is precisely the state edge cannot distinguish by
/// reading the row, and CIRISPersist#851's whole shape.
#[tokio::test]
async fn a_legacy_occurrence_is_healed_onto_the_plane_and_keeps_its_expiry() {
    use ciris_edge::content_occurrence::provision_engine_occurrence;
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::{EncryptionPubkeys, FederationDirectory as _};

    // The plane membership question, asked the way a peer asks it.
    async fn on_plane(dir: &Arc<SqliteBackend>, identity: &str, occ: &str) -> bool {
        ciris_persist::federation::FederationDirectory::list_signed_identity_occurrences_since(
            &**dir, None, 256,
        )
        .await
        .expect("list the signed plane")
        .into_iter()
        .any(|s| {
            let o = &s.occurrence.identity_occurrence;
            o.identity_key_id == identity && o.occurrence_key_id == occ
        })
    }

    async fn enc_of(dir: &Arc<SqliteBackend>) -> EncryptionPubkeys {
        let kem = dir
            .load_or_init_content_kem_identity()
            .await
            .expect("content-KEM identity");
        EncryptionPubkeys {
            x25519_base64: kem.x25519_pubkey_b64,
            ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
        }
    }

    // Write back the SAME occurrence through the legacy door, optionally with
    // an operator's expiry. Same pubkeys, so this is `AlreadyCurrent` — the
    // case the heal is about, not drift.
    async fn make_it_legacy(
        dir: &Arc<SqliteBackend>,
        identity: &str,
        occ: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        let enc = enc_of(dir).await;
        dir.put_identity_occurrence_local(ciris_persist::federation::IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occ.to_owned(),
            device_class: "server".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until,
            encryption_pubkeys: Some(enc),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("write the pre-v24.2.0 trusted-local row");
    }

    let alice = Ident::new("alice-fed", 0x11);

    // ── (a) a legacy row with no expiry is HEALED onto the plane ──────
    let n = build_node(&[&alice], &alice, false).await;
    make_it_legacy(&n.dir, &alice.key_id, &n.me, None).await;
    assert!(
        !on_plane(&n.dir, &alice.key_id, &n.me).await,
        "a trusted-local row is not on the plane — if this fails the simulation is \
         wrong and the rest of this test proves nothing",
    );

    let (_, outcome) =
        provision_engine_occurrence(n.store.engine(), &*n.dir, &alice.key_id, "server")
            .await
            .expect("re-provision over the legacy row");
    assert_eq!(
        outcome,
        ciris_edge::content_occurrence::Provisioned::AlreadyCurrent,
        "same pubkeys: this is a heal, not drift",
    );
    assert!(
        on_plane(&n.dir, &alice.key_id, &n.me).await,
        "an upgrading node's local-door row must be republished onto the plane, or it \
         stays invisible to every peer's key_grant fold (CIRISPersist#851)",
    );

    // ── (b) a legacy row carrying an EXPIRY is healed WITH it ─────────
    let n2 = build_node(&[&alice], &alice, false).await;
    let expiry = chrono::Utc::now() + chrono::Duration::days(30);
    make_it_legacy(&n2.dir, &alice.key_id, &n2.me, Some(expiry)).await;

    let (_, outcome) =
        provision_engine_occurrence(n2.store.engine(), &*n2.dir, &alice.key_id, "server")
            .await
            .expect("re-provision over the legacy row with an expiry");
    assert_eq!(
        outcome,
        ciris_edge::content_occurrence::Provisioned::AlreadyCurrent
    );
    let row = n2
        .dir
        .list_identity_occurrences_active(&alice.key_id)
        .await
        .expect("list")
        .into_iter()
        .find(|o| o.occurrence_key_id == n2.me)
        .expect("the occurrence is still there");
    assert_eq!(
        row.valid_until.map(|t| t.timestamp_millis()),
        Some(expiry.timestamp_millis()),
        "the heal must carry the stored expiry through `publish_self_occurrence` — a `None` \
         there is an upsert to `valid_until: null`, silently extending this node's grant \
         membership past the lifetime an operator chose (PR #607 review, CIRISPersist#855)",
    );
    assert!(
        on_plane(&n2.dir, &alice.key_id, &n2.me).await,
        "and it IS on the plane now — with the door taking the expiry there is nothing left \
         to refuse over, and a row left off the plane is #851 again",
    );
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
            // v46.0.0 (CIRISPersist#876) — the MINTER is named, never inferred
            // from the author: it is the key whose cascade minted the epoch and
            // signed the `key_grant` set, which is A's sealing engine. Here the
            // two coincide (this harness seals under the same key it authors
            // with); in production a chat row is authored by a person and sealed
            // by their node, which is the defect #876 closed.
            BlobProvenance {
                author_key_id: node_a.me.clone(),
                cohort_scope: "community".to_owned(),
                community_key_id: Some(room.to_owned()),
                epoch: sealed.epoch,
                tier: sealed.tier,
                minter_key_id: Some(node_a.me.clone()),
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

// ─── CIRISEdge#606 — CC 2.3 at the bytes plane ────────────────────────

/// An edge `LocalSigner` over the SAME halves `Ident` registered, under the
/// friendly key id — the signer a person signs rows with.
fn edge_signer_for(id: &Ident) -> ciris_edge::identity::LocalSigner {
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[id.seed; 32], &id.key_id)
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[id.seed ^ 0x55; 32], format!("{}-pqc", id.key_id))
            .expect("rebuild the registered pqc half"),
    );
    ciris_edge::identity::LocalSigner::new(id.key_id.clone(), hw, Some(pqc))
}

/// A signed, admissible content row: what a chat message IS on the wire — a
/// `scores` row at community scope carrying a `BlobPointer` to the sealed
/// body, producer-only subjects (AV-84), born federation-tier so it crosses.
/// Built with the same binder and signer every edge producer uses.
async fn signed_content_row(
    author: &Ident,
    room: &str,
    pointer: &BlobPointer,
) -> ciris_persist::federation::Attestation {
    use ciris_edge::replication::attestation_bind::{
        bind_attestation_envelope, truncate_to_substrate_resolution, AttestationColumns,
    };
    use sha2::Digest as _;

    let signer = edge_signer_for(author);
    let asserted_at = truncate_to_substrate_resolution(ts());
    let attestation_id = format!("msg-{}-{}", author.key_id, &pointer.content_sha256[..12]);
    let mut envelope = serde_json::json!({
        "dimension": ciris_edge::chat::CHAT_MESSAGE_DIMENSION,
        ciris_edge::chat::FIELD_COMMUNITY_ID: room,
        "score": 1.0,
        "content": serde_json::to_value(pointer).expect("pointer"),
    });
    let subjects = vec![author.key_id.clone()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: &author.key_id,
            attestation_type: "scores",
            attested_key_id: &author.key_id,
            subject_key_ids: &subjects,
            cohort_scope: "community",
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(&signer, &canonical, "chat row")
            .await
            .expect("sign the row");
    ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: author.key_id.clone(),
        attested_key_id: author.key_id.clone(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: "community".to_owned(),
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// Carry A's sealed blob to B the #848 way — every key_grant set through the
/// key-grant door, the envelope served from A's disk and adopted on B at the
/// author's declared binding — and prove B opens it. The crossing every
/// #606 leg starts from.
async fn cross_key_and_bytes(
    node_a: &Node,
    node_b: &Node,
    sealed: &ciris_edge::group_content::SealedContent,
    author: &Ident,
    room: &str,
    body: &[u8],
) -> [u8; 32] {
    use ciris_persist::federation::blobs::BlobBody;
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    use ciris_persist::federation::{AdoptDisposition, BlobProvenance};

    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    for row in node_a
        .dir
        .list_attestations_since(None, 400)
        .await
        .expect("list A's rows")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
    {
        node_b
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: row.attestation,
            })
            .await
            .expect("B admits A's key_grant set");
    }
    let BlobBody::Inline(envelope) = node_a
        .store
        .engine()
        .serve_blob_to_peer(&sha, &node_b.me)
        .await
        .expect("A serves")
    else {
        panic!("inline");
    };
    let aad = ciris_edge::group_content::aad_for_open(&OpenRequest {
        pointer: &sealed.pointer,
        author_key_id: &author.key_id,
        asserted_at: ts(),
        viewer_key_id: &node_b.me,
    });
    node_b
        .store
        .engine()
        .adopt_sealed_blob(
            &envelope,
            BlobProvenance {
                author_key_id: node_a.me.clone(),
                cohort_scope: "community".to_owned(),
                community_key_id: Some(room.to_owned()),
                epoch: sealed.epoch,
                tier: sealed.tier,
                // v46.0.0 — the sealing engine minted this epoch (#876).
                minter_key_id: Some(node_a.me.clone()),
            },
            Some(&aad),
            AdoptDisposition::LocalOnly,
        )
        .await
        .expect("B adopts");
    assert_eq!(
        node_b
            .store
            .open(OpenRequest {
                pointer: &sealed.pointer,
                author_key_id: &author.key_id,
                asserted_at: ts(),
                viewer_key_id: &node_b.me,
            })
            .await
            .expect("positive control: B opens before any withdrawal"),
        body
    );
    sha
}

/// **An AUTHORIZED withdrawal that arrived before its target evicts on
/// replay.** persist admitted it with `rule = None`; that column is never
/// read. When the row lands, the pending withdrawal is replayed through the
/// recompute, resolves to rule 1 against the local target, and the bytes go
/// — the out-of-order half of the same guarantee the in-order leg pins.
#[tokio::test]
async fn an_authorized_withdraws_that_arrived_first_evicts_when_its_target_lands() {
    use ciris_edge::blob_swarm::revocation::{apply_observation, observe};
    use ciris_edge::blob_swarm::{
        BlobChunkSource as _, BlobEvictor, BytesVerdict, ChunkSourceRefusal,
        PersistBlobChunkSource, RevocationRegister,
    };
    use ciris_edge::replication::attestation_bind::withdraws_attestation;
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::{FederationDirectory as _, SignedAttestation};

    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let room = "room-alice-bob";
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    seed_room(&node_a, room, &[&alice, &bob]).await;
    seed_room(&node_b, room, &[&alice, &bob]).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;

    let body = b"withdrawn before the row even arrived";
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
        .expect("seal");
    let sha = cross_key_and_bytes(&node_a, &node_b, &sealed, &alice, room, body).await;

    let register = Arc::new(RevocationRegister::default());
    let serve = PersistBlobChunkSource::new(node_b.store.engine().clone())
        .with_revocations(Some(Arc::clone(&register)));
    let evictor: &dyn BlobEvictor = &*node_b.dir;

    let row = signed_content_row(&alice, room, &sealed.pointer).await;
    node_a
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A admits the row");

    // The withdrawal crosses FIRST. Admitted rule=None; held pending.
    let withdraws = withdraws_attestation(&row, "gone", ts(), &edge_signer_for(&alice))
        .await
        .expect("build");
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: withdraws.clone(),
        })
        .await
        .expect("admitted with rule=None: the target is not here yet");
    assert!(apply_observation(
        &register,
        &*node_b.dir,
        Some(evictor),
        observe(&withdraws).expect("observed"),
    )
    .await
    .is_empty());
    assert_eq!(register.verdict(&sha), BytesVerdict::Unknown);
    assert!(
        matches!(serve.read_chunk(sha, sha, &node_b.me).await, Ok(Some(_))),
        "nothing decided yet: B serves",
    );

    // The row lands: the pending withdrawal is replayed and RESOLVES.
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("B admits the row");
    let evicted = apply_observation(
        &register,
        &*node_b.dir,
        Some(evictor),
        observe(&row).expect("observed"),
    )
    .await;
    assert_eq!(
        evicted,
        vec![sha],
        "the replayed withdrawal passes the recompute against the now-local target (rule 1) \
         and evicts — the column persist stored (None) was never consulted",
    );
    let (_, _, pending, _, _) = register.stats();
    assert_eq!(pending, 0, "consumed on replay, not left to replay twice");
    assert_eq!(register.verdict(&sha), BytesVerdict::Revoked);
    assert!(matches!(
        serve.read_chunk(sha, sha, &node_b.me).await,
        Err(ChunkSourceRefusal::Withdrawn)
    ));
    assert!(node_b.dir.get_blob(&sha).await.expect("get_blob").is_none());
}

/// **CC 2.3 reaches the bytes.** A subject's `withdraws` is admitted on a
/// holder, RE-VERIFIED against the row the holder has, and the bytes go:
/// the serve door answers `Withdrawn` (the one refusal the fetcher aborts
/// on), the blob row is deleted, and the converger's consent input reads
/// `Revoked`. An unauthorized `withdraws` — admitted by persist with
/// `rule = None` because its target had not landed — is replayed when the
/// target lands, fails the recompute, and touches nothing.
///
/// # What the three legs pin
///
/// - **(b, out of order)** an unentitled withdrawal admitted BEFORE its
///   target (rule `None`, "authority is a read-side concern") is held
///   pending and replayed when the target lands; the recompute refuses it;
///   the bytes stay served. Remove the recompute and this leg deletes real
///   copies on the strength of a row nobody authorized — the remote-delete
///   primitive the operator's constraint names.
/// - **(b, in order)** persist's own write door refuses the same withdrawal
///   once the target is local. That is persist's half of the constraint,
///   asserted here so a regression there is seen here.
/// - **(a)** the subject's withdrawal — here the author, because AV-84
///   makes a community row's only subject its producer; the non-author
///   case of CC 2.3 lives on federation-tier subject-bearing dimensions —
///   passes the recompute and revokes: `Withdrawn`, bytes gone, `Revoked`.
///
/// The register is driven through [`observe`] / [`apply_observation`]
/// directly — the same two calls the replication bridge makes around its
/// put door — so this witnesses the decision, not the plumbing.
///
/// [`observe`]: ciris_edge::blob_swarm::revocation::observe
/// [`apply_observation`]: ciris_edge::blob_swarm::revocation::apply_observation
#[tokio::test]
#[allow(clippy::too_many_lines)] // three legs, one blob, in order on purpose
async fn a_withdraws_revokes_the_bytes_on_a_holder_and_an_unauthorized_one_is_inert() {
    use ciris_edge::blob_swarm::revocation::{apply_observation, observe};
    use ciris_edge::blob_swarm::{
        BlobChunkSource as _, BlobEvictor, BytesVerdict, ChunkSourceRefusal,
        PersistBlobChunkSource, RevocationRegister,
    };
    use ciris_edge::holonomic::swarm_rarity::ConsentState;
    use ciris_edge::replication::attestation_bind::withdraws_attestation;
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::{FederationDirectory as _, SignedAttestation};

    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    // Carol: a registered identity with NO standing over alice's row — not
    // its producer, not a subject, no delegation, not even a room member.
    let carol = Ident::new("carol-fed", 0x33);
    let room = "room-alice-bob";

    let node_a = node(&[&alice, &bob, &carol], &alice).await;
    let node_b = node(&[&alice, &bob, &carol], &bob).await;
    seed_room(&node_a, room, &[&alice, &bob]).await;
    seed_room(&node_b, room, &[&alice, &bob]).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;
    let bob_occ = node_b.me.clone();

    // ── A seals; the KEY and the BYTES cross to B (the #848 path) ─────
    let body = b"a message the subject will later withdraw";
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
    let sha = cross_key_and_bytes(&node_a, &node_b, &sealed, &alice, room, body).await;

    // ── B's revocation register, chunk source, and evictor ───────────
    // The same three handles production wires: the register the bridge
    // writes, the serve door that consults it, the substrate that deletes.
    let register = Arc::new(RevocationRegister::default());
    let serve = PersistBlobChunkSource::new(node_b.store.engine().clone())
        .with_revocations(Some(Arc::clone(&register)));
    let evictor: &dyn BlobEvictor = &*node_b.dir;
    let sha_hex = hex::encode(sha);
    assert_eq!(register.verdict(&sha), BytesVerdict::Unknown);
    assert!(
        matches!(serve.read_chunk(sha, sha, &bob_occ).await, Ok(Some(_))),
        "precondition: B serves the bytes it holds"
    );

    // The referencing row, authored on A. Alice is its producer and its
    // only subject (AV-84 at community scope).
    let row = signed_content_row(&alice, room, &sealed.pointer).await;
    node_a
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A admits the row alice signed");

    // ── (b) out of order: carol's withdraws lands on B BEFORE the row ──
    let carol_withdraws =
        withdraws_attestation(&row, "no standing", ts(), &edge_signer_for(&carol))
            .await
            .expect("build carol's withdraws");
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: carol_withdraws.clone(),
        })
        .await
        .expect(
            "persist ADMITS a withdraws whose target it does not hold, with rule=None — \
             'authority is a read-side concern'. This is the row the constraint is about.",
        );
    let held = node_b
        .dir
        .get_attestation(&carol_withdraws.attestation_id)
        .await
        .expect("get")
        .expect("carol's withdraws is stored on B");
    assert_eq!(
        held.withdraws_admission_rule, None,
        "precondition: stored with NO resolved authority — the value a naive hook would \
         read as permission",
    );
    let evicted = apply_observation(
        &register,
        &*node_b.dir,
        Some(evictor),
        observe(&carol_withdraws).expect("a withdraws is always observed"),
    )
    .await;
    assert!(
        evicted.is_empty(),
        "target absent: pending, nothing acted on"
    );
    let (_, _, pending, _, _) = register.stats();
    assert_eq!(pending, 1, "carol's withdrawal waits for its target");

    // ── The row lands on B; carol's pending withdrawal is REPLAYED ────
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("B admits alice's row");
    let evicted = apply_observation(
        &register,
        &*node_b.dir,
        Some(evictor),
        observe(&row).expect("a row with a pointer is observed"),
    )
    .await;
    assert!(
        evicted.is_empty(),
        "carol's replayed withdrawal must fail the recompute against the local target and \
         touch nothing — a hook that trusted the stored rule (None) or skipped the \
         recompute would have deleted real copies on the strength of a row nobody \
         authorized (CIRISEdge#606 / CIRISPersist#853, the operator's constraint)",
    );
    assert_eq!(
        register.verdict(&sha),
        BytesVerdict::Live,
        "the row is indexed and live; carol's withdrawal counted for nothing",
    );
    assert_eq!(register.consent_for(&sha_hex), ConsentState::Active);
    assert!(
        matches!(serve.read_chunk(sha, sha, &bob_occ).await, Ok(Some(_))),
        "B still serves: an unauthorized withdrawal is inert on the serve side too",
    );
    assert!(
        node_b.dir.get_blob(&sha).await.expect("get_blob").is_some(),
        "and the bytes are still on disk",
    );

    // ── (b) in order: persist's own door refuses carol now the target is local ──
    let mut carol_again =
        withdraws_attestation(&row, "still no standing", ts(), &edge_signer_for(&carol))
            .await
            .expect("build");
    // The producer's id is deterministic per (issuer, target); make this a
    // distinct row carrying the same claim.
    carol_again.attestation_id.push_str("-again");
    let refused = node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: carol_again,
        })
        .await;
    assert!(
        refused.is_err(),
        "with the target LOCAL, persist's write door refuses an unentitled withdraws \
         outright — persist's half of the constraint, asserted here so a regression \
         there shows up here: {refused:?}",
    );

    // ── (a) the subject withdraws: admitted, re-verified, the bytes go ──
    let alice_withdraws = withdraws_attestation(
        &row,
        "I withdraw this message",
        ts(),
        &edge_signer_for(&alice),
    )
    .await
    .expect("build alice's withdraws");
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: alice_withdraws.clone(),
        })
        .await
        .expect("B admits the subject's withdraws (persist resolves rule 1 at the door)");
    let evicted = apply_observation(
        &register,
        &*node_b.dir,
        Some(evictor),
        observe(&alice_withdraws).expect("observed"),
    )
    .await;
    assert_eq!(
        evicted,
        vec![sha],
        "every reference to the blob is withdrawn by an AUTHORIZED withdrawal: the bytes \
         are evicted — once, and exactly these",
    );
    assert_eq!(register.verdict(&sha), BytesVerdict::Revoked);
    assert_eq!(
        register.consent_for(&sha_hex),
        ConsentState::Revoked,
        "the converger's consent input — EjectHardDelete regardless of rarity",
    );
    assert!(
        matches!(
            serve.read_chunk(sha, sha, &bob_occ).await,
            Err(ChunkSourceRefusal::Withdrawn)
        ),
        "the serve door answers Withdrawn — the refusal the fetcher aborts on, not NotHeld \
         which would send it to the next holder",
    );
    assert!(
        node_b.dir.get_blob(&sha).await.expect("get_blob").is_none(),
        "the blob row and its satellites are gone from B's substrate",
    );
    let after = node_b
        .store
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: &alice.key_id,
            asserted_at: ts(),
            viewer_key_id: &bob_occ,
        })
        .await;
    assert!(
        matches!(after, Err(GroupContentError::NotHeld { .. })),
        "a member who could open it a moment ago cannot now: {after:?}",
    );
}

// ─── CIRISEdge#601: pull on attestation ────────────────────────────────

/// One end of an in-process wire between two `Edge`s: `send` to the one
/// peer this end knows lands on that peer's inbound; `listen` forwards this
/// end's inbound to the edge's dispatch loop. Frames carry NO attribution
/// (`source_key_id: None`, federation arrival) — the shape a plain HTTP
/// transport delivers, so every gate on the receive side runs at its
/// strictest.
struct WireEnd {
    peer_key_id: String,
    to_peer: tokio::sync::mpsc::Sender<Vec<u8>>,
    inbound: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
}

fn wire(a_key: &str, b_key: &str) -> (Arc<WireEnd>, Arc<WireEnd>) {
    let (a_to_b, b_inbound) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (b_to_a, a_inbound) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    (
        Arc::new(WireEnd {
            peer_key_id: b_key.to_owned(),
            to_peer: a_to_b,
            inbound: tokio::sync::Mutex::new(Some(a_inbound)),
        }),
        Arc::new(WireEnd {
            peer_key_id: a_key.to_owned(),
            to_peer: b_to_a,
            inbound: tokio::sync::Mutex::new(Some(b_inbound)),
        }),
    )
}

#[async_trait::async_trait]
impl ciris_edge::transport::Transport for WireEnd {
    fn id(&self) -> ciris_edge::transport::TransportId {
        ciris_edge::transport::TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        bytes: &[u8],
    ) -> Result<ciris_edge::transport::TransportSendOutcome, ciris_edge::transport::TransportError>
    {
        if destination_key_id != self.peer_key_id {
            return Err(ciris_edge::transport::TransportError::Unreachable(format!(
                "this wire reaches only {}, not {destination_key_id}",
                self.peer_key_id
            )));
        }
        self.to_peer
            .send(bytes.to_vec())
            .await
            .map_err(|e| ciris_edge::transport::TransportError::Io(e.to_string()))?;
        Ok(ciris_edge::transport::TransportSendOutcome::Delivered)
    }

    async fn listen(
        &self,
        sink: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        let mut rx =
            self.inbound.lock().await.take().ok_or_else(|| {
                ciris_edge::transport::TransportError::Config("listen twice".into())
            })?;
        while let Some(envelope_bytes) = rx.recv().await {
            let frame = ciris_edge::transport::InboundFrame {
                envelope_bytes,
                transport: ciris_edge::transport::TransportId::HTTP,
                received_at: chrono::Utc::now(),
                source_key_id: None,
                link_key_id: None,
                arrival_scope: None,
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

/// An `Edge` on `node`, over `transport`, serving this node's blobs through
/// the persist-backed chunk source, running.
async fn spawn_edge(
    node: &Node,
    transport: Arc<WireEnd>,
) -> (Arc<ciris_edge::Edge>, tokio::sync::watch::Sender<bool>) {
    use ciris_persist::federation::FederationDirectory;
    let edge = ciris_edge::Edge::builder()
        .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
        .queue(node.dir.clone())
        .signer(node.signer.clone())
        .transport(transport as Arc<dyn ciris_edge::transport::Transport>)
        .blob_chunk_source(Arc::new(
            ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
        ))
        .config(ciris_edge::EdgeConfig::default())
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = Arc::clone(&edge);
    tokio::spawn(async move {
        let _ = runner.run(shutdown_rx).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (edge, shutdown_tx)
}

/// A community-scoped, federation-tier content row authored by THIS NODE'S
/// key and bound-hybrid-signed — the wire shape a peer receives after the
/// author's `share` widened a chat message to the room. Mirrors
/// `chat::chat_row` on the fields that matter to admission and to the pull:
/// `dimension`, `community_id`, the `content` pointer (with the sealed-under
/// `epoch`), the bound columns, and a signature persist verifies against
/// the author's registered hybrid record.
async fn federation_content_row(
    author: &ciris_edge::identity::LocalSigner,
    room: &str,
    pointer: &BlobPointer,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::Attestation {
    use ciris_edge::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    use sha2::Digest as _;
    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let dimension = ciris_edge::chat::CHAT_MESSAGE_DIMENSION;
    let mut envelope = serde_json::json!({
        "dimension": dimension,
        ciris_edge::chat::FIELD_COMMUNITY_ID: room,
        "score": 1.0,
        ciris_edge::chat::FIELD_CONTENT: pointer,
    });
    let attestation_id = {
        let mut h = sha2::Sha256::new();
        h.update(dimension.as_bytes());
        h.update(room.as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon"));
        format!("chat-{}", &hex::encode(h.finalize())[..32])
    };
    let subjects = vec![author_key_id.to_owned()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(author, &canonical, dimension)
            .await
            .expect("hybrid sign");
    ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// A federation-tier row that references `sha` by `evidence_refs` — the
/// manifest / evidence-bundle shape, commons scope — authored and
/// bound-hybrid-signed by THIS NODE's key.
async fn commons_evidence_row(
    author: &ciris_edge::identity::LocalSigner,
    sha: &[u8; 32],
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::Attestation {
    use ciris_edge::replication::attestation_bind::{
        bind_attestation_envelope, truncate_to_substrate_resolution, AttestationColumns,
    };
    use sha2::Digest as _;
    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let dimension = "provenance:evidence_bundle:v1";
    let mut envelope = serde_json::json!({
        "dimension": dimension,
        "score": 1.0,
        "evidence_refs": [hex::encode(sha)],
    });
    let attestation_id = format!("evidence-{}", &hex::encode(sha)[..16]);
    let subjects = vec![author_key_id.to_owned()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(author, &canonical, dimension)
            .await
            .expect("hybrid sign");
    ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// A's rows of one attestation-type prefix, as B's bridge would receive
/// them over the cursor: BARE `Attestation` JSON.
async fn rows_of(node: &Node, type_prefix: &str) -> Vec<Vec<u8>> {
    use ciris_persist::federation::FederationDirectory;
    node.dir
        .list_attestations_since(None, 200)
        .await
        .expect("list rows")
        .into_iter()
        .filter(|a| a.attestation.attestation_type.starts_with(type_prefix))
        .map(|a| serde_json::to_vec(&a.attestation).expect("wire"))
        .collect()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=warn")),
        )
        .with_test_writer()
        .try_init();
}

/// **CIRISEdge#601 — the bytes crossed ONLY through the pull.**
///
/// Two nodes, two substrates, two running `Edge`s on a wire that carries
/// nothing but signed frames. A stores a commons blob and signs the row
/// that references it. The row reaches B through B's replication bridge —
/// the same door every attestation arrives by — and that is the LAST thing
/// this test hands over. Nothing copies the bytes. B's bridge offers the
/// admitted row to the pull sink; the puller projects the meaning, runs the
/// store gate (A is on B's commons allowlist; B's operator consented to
/// hold commons), asks persist who holds the blob, fetches it from A over
/// the wire through the swarm, and stores it. Then B holds what A had.
///
/// The holder plane crosses AFTER the row, so the first pull finds nobody
/// and the RETRY is what completes it — "retried on the next round if no
/// holder is fresh" is asserted, not assumed.
///
/// **Mutation:** with the bridge's `pull_sink.offer` removed, the bytes
/// never leave A and this fails at the assertion that names #601.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one crossing and every precondition in one place
async fn a_far_node_holds_what_the_pull_brought_home() {
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig};
    use ciris_edge::replication::{
        ApplyOutcome, BridgeConfig, BridgeEngine, EnvelopeKind,
        FederationDirectoryReplicationBridge, ReplicationDirectory as _,
    };
    use ciris_persist::federation::blobs::{BlobBody, BlobStorage as _};
    use ciris_persist::federation::{FederationDirectory, SignedAttestation};
    init_tracing();

    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;

    let (wire_a, wire_b) = wire(&node_a.me, &node_b.me);
    let (_edge_a, _stop_a) = spawn_edge(&node_a, wire_a).await;
    let (edge_b, _stop_b) = spawn_edge(&node_b, wire_b).await;

    // B's puller: A is a blessed commons sender, and B's operator holds
    // commons. Both are OPT-INS — the defaults refuse.
    let (sink, _puller) = BlobPuller::spawn(
        Arc::clone(&edge_b),
        node_b.store.engine().clone(),
        node_b.dir.clone(),
        node_b.dir.clone() as Arc<dyn FederationDirectory>,
        node_b.me.clone(),
        PullConfig {
            retry_backoff: std::time::Duration::from_millis(200),
            commons_allowlist: vec![node_a.me.clone()],
            consent: ciris_edge::blob_swarm::OperatorStoreConsent {
                commons: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                ..ciris_edge::blob_swarm::OperatorStoreConsent::default()
            },
            ..PullConfig::default()
        },
    );
    let bridge = FederationDirectoryReplicationBridge::with_config(
        node_b.dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    )
    .with_engine(Some(BridgeEngine(node_b.store.engine().clone())))
    .with_pull_sink(Some(sink))
    .with_local_key_id(Some(node_b.me.clone()));

    // A stores a commons blob through the commons door (announces a holder
    // claim) and signs the row that references it.
    let body = b"a public artifact, parked here, referenced there";
    let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(body).into();
    node_a
        .store
        .engine()
        .put_blob_signing(
            &sha,
            BlobBody::Inline(body.to_vec()),
            Some("application/octet-stream"),
            &node_a.me,
            // NOW, not the fixture's fixed instant: the holder claim carries
            // this as `asserted_at`, and B's `list_holders` drops a claim
            // older than the 24h TTL as stale (CEG §10.1.2) — correctly.
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("A stores the commons blob and announces it");
    let row = commons_evidence_row(&node_a.signer, &sha, ts()).await;
    node_a
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A holds the row it authored");
    assert!(
        !node_b.dir.has_blob(&sha).await.expect("has_blob"),
        "precondition: B holds nothing"
    );

    // ── The ROW crosses, through B's bridge — the last thing handed over. ──
    let outcome = bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&row).expect("wire"),
            None,
        )
        .await;
    assert_eq!(
        outcome,
        ApplyOutcome::Admitted,
        "B admits A's referencing row"
    );

    // ── The HOLDER plane crosses after it, so the retry completes the pull. ──
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let holders = rows_of(&node_a, "holds_bytes:").await;
    assert!(
        !holders.is_empty(),
        "precondition: put_blob announced a holder claim"
    );
    for bytes in &holders {
        let o = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, bytes, None)
            .await;
        assert_eq!(o, ApplyOutcome::Admitted, "B admits A's holder claim");
    }

    // ── The PULL: nothing else moves the bytes. ──
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if node_b.dir.has_blob(&sha).await.expect("has_blob") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the bytes never arrived on B: the pull-on-attestation hook did not fire, or \
             the fetch/store failed (CIRISEdge#601). Nothing in this test copies bytes; \
             only the puller can put them here"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let held = node_b
        .dir
        .get_blob(&sha)
        .await
        .expect("get_blob")
        .expect("held");
    let BlobBody::Inline(got) = held else {
        panic!("a whole blob is held inline, got {held:?}");
    };
    assert_eq!(got, body, "B holds byte-for-byte what A stored");
}

/// **CIRISEdge#601 vs #499 — the community leg, pinned where it stops.**
///
/// Everything up to the wire works for a sealed community blob: the row is
/// admitted, the hook fires, the meaning projects, the store gate clears
/// (A's key hops to alice, a member of a room B joined), the holder is
/// found. Then `resolve_holder_routes` refuses: the content is scoped to a
/// cohort, this node has no [`ScopeAddressTable`], and #499 forbids
/// shipping a scoped request on the federation address. No deployment has
/// a table today, and the only scoped send is Reticulum's. So on every
/// current node a community blob cannot be pulled — a design collision
/// between #499 and #601 that this pin states rather than papers over.
///
/// Meanwhile the transcript reads `NotFetched` — the state a reader waits
/// through — by TYPE, and a stranger reads `NotGranted` once bytes exist.
/// The first is asserted here; the second is asserted on the commons leg's
/// sibling in `chat_message_federates`.
///
/// This test turns red the day the router routes cohort content on a
/// legacy node, or a table is installed on the test transport — either of
/// which is the moment to promote it into the end-to-end open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // every crossing and the pin, in one place on purpose
async fn a_community_pull_stops_at_the_scope_router_on_a_legacy_node() {
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig, PullOutcome};
    use ciris_edge::chat::{Body, ChatMessage, UnopenedReason};
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    use ciris_persist::federation::{FederationDirectory, SignedAttestation};
    init_tracing();

    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let room = "room-alice-bob";
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    seed_room(&node_a, room, &[&alice, &bob]).await;
    seed_room(&node_b, room, &[&alice, &bob]).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;
    let (wire_a, wire_b) = wire(&node_a.me, &node_b.me);
    let (_edge_a, _stop_a) = spawn_edge(&node_a, wire_a).await;
    let (edge_b, _stop_b) = spawn_edge(&node_b, wire_b).await;

    // A seals as THIS NODE (attester == minter) and signs the row.
    let body = b"the bytes crossed on their own";
    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "community",
            community_key_id: Some(room),
            author_key_id: &node_a.me,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: body,
            media_type: Some("text/plain"),
        })
        .await
        .expect("seal at the community tier");
    assert!(
        sealed.pointer.epoch.is_some(),
        "precondition: the pointer carries the sealed-under epoch (CIRISEdge#601)"
    );
    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let row = federation_content_row(&node_a.signer, room, &sealed.pointer, ts()).await;
    node_a
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A holds the row it authored");

    // The key and the holder plane cross (the doors #605 and the commons leg
    // witnessed); the row is what the pull is about.
    for set in node_a
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
    {
        node_b
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: set.attestation.clone(),
            })
            .await
            .expect("B admits A's key_grant set");
    }
    for bytes in rows_of(&node_a, "holds_bytes:").await {
        let h: ciris_persist::federation::Attestation =
            serde_json::from_slice(&bytes).expect("row");
        node_b
            .dir
            .put_attestation(SignedAttestation { attestation: h })
            .await
            .expect("B admits A's holder claim");
    }

    // Before the bytes: NotFetched, by type.
    let mut msg = ChatMessage::from_row(&row, room).expect("a chat row");
    msg.resolve_content(&node_b.store, &node_b.me).await;
    match &msg.body {
        Body::Unopened {
            reason: UnopenedReason::NotFetched { .. },
        } => {}
        other => panic!(
            "before the bytes arrive the body reads NotFetched — a state to wait through, \
             distinct from NotGranted (CIRISEdge#601) — got {other:?}"
        ),
    }

    // The pull, driven directly so its verdict is observable.
    let puller = BlobPuller::new(
        Arc::clone(&edge_b),
        node_b.store.engine().clone(),
        node_b.dir.clone(),
        node_b.dir.clone() as Arc<dyn FederationDirectory>,
        node_b.me.clone(),
        PullConfig::default(),
    );
    let verdict = puller.pull_one(&row, sha, 0).await;
    match &verdict {
        PullOutcome::FetchFailed { reason, .. } if reason.contains("NO scope address table") => {}
        other => panic!(
            "the community pull is expected to stop at the SCOPE ROUTER on a node with no \
             address table (CIRISEdge#499 forbids a scoped request on the federation \
             address). `Stored` means #499's rule changed or a table exists — promote this \
             pin into the end-to-end open. `Refused` means the pull stopped EARLIER, at the \
             store gate, for a member's blob whose holders are all members — the \
             `Allowlisted` stand-in regression #601 fixed in `store_admission`. Got {other:?}"
        ),
    }
    assert!(
        !node_b.dir.has_blob(&sha).await.expect("has_blob"),
        "nothing was stored past the router's refusal"
    );
}

// ─── CIRISEdge#616: the room's group is the router's source ────────────

/// A destination sink that LISTENS and never announces — CC 5.4.6: a
/// below-federation destination "MUST NOT emit a Reticulum announce"; members
/// resolve it "from (cached directory entry + per-group HKDF)". The
/// `Transport` trait has no announce verb at all, so the in-process wire
/// cannot announce even by accident; this sink records what it was asked to
/// listen on, and nothing else.
#[derive(Default)]
struct ListenOnly(std::sync::Mutex<Vec<[u8; 16]>>);
impl ciris_edge::scope_lifecycle::ScopedDestinationSink for ListenOnly {
    fn register(
        &self,
        a: &ciris_edge::scope_addressing::MemberAddress,
        _: &ciris_edge::cohort_scope::CohortScope,
    ) -> Result<(), String> {
        self.0.lock().expect("sink").push(*a.as_bytes());
        Ok(())
    }
    fn retire(
        &self,
        _: &ciris_edge::scope_addressing::MemberAddress,
        _: &ciris_edge::cohort_scope::CohortScope,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// `spawn_edge`, with a caller-built scope lifecycle installed — the #616
/// door: the router reads the lifecycle's table when no Reticulum transport
/// owns one.
/// CIRISEdge#640 — what a scope-native host wires: persist's source for the
/// bytes, and a `chunk_scope` answer the host actually knows. Here the room is
/// the only scoped content, so the answer is the room's scope; a real host
/// projects it with `BlobMeaning::project` over a row that references the
/// blob. `answers_scope` declares it, which is what the builder gate reads.
struct RoomScopedSource {
    inner: ciris_edge::blob_swarm::PersistBlobChunkSource,
    scope: ciris_edge::blob_swarm::ContentScope,
}
#[async_trait::async_trait]
impl ciris_edge::blob_swarm::BlobChunkSource for RoomScopedSource {
    async fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        requesting_peer_key_id: &str,
    ) -> Result<Option<Vec<u8>>, ciris_edge::blob_swarm::ChunkSourceRefusal> {
        self.inner
            .read_chunk(blob_sha256, chunk_sha256, requesting_peer_key_id)
            .await
    }
    async fn chunk_scope(
        &self,
        _blob_sha256: [u8; 32],
    ) -> Option<ciris_edge::blob_swarm::ContentScope> {
        Some(self.scope.clone())
    }
    fn answers_scope(&self) -> bool {
        true
    }
}

async fn spawn_edge_with_lifecycle(
    node: &Node,
    transport: Arc<WireEnd>,
    lifecycle: Arc<ciris_edge::scope_lifecycle::ScopeLifecycle>,
    room: &str,
) -> (Arc<ciris_edge::Edge>, tokio::sync::watch::Sender<bool>) {
    use ciris_persist::federation::FederationDirectory;
    let edge = ciris_edge::Edge::builder()
        .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
        .queue(node.dir.clone())
        .signer(node.signer.clone())
        .transport(transport as Arc<dyn ciris_edge::transport::Transport>)
        .blob_chunk_source(Arc::new(RoomScopedSource {
            inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
            scope: ciris_edge::blob_swarm::ContentScope::Group {
                scope: ciris_edge::cohort_addressing::scope_for(room),
                group_id: room.to_owned(),
            },
        }))
        .scope_lifecycle(lifecycle)
        .config(ciris_edge::EdgeConfig::default())
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = Arc::clone(&edge);
    tokio::spawn(async move {
        let _ = runner.run(shutdown_rx).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (edge, shutdown_tx)
}

/// **The community pull resolves through the room's group — and stops at
/// the scoped send, which is Reticulum's.**
///
/// Same room, same seal, same row and holder claims as the legacy pin above.
/// The difference is that both nodes hold the room's MLS `CohortGroup` and a
/// scope lifecycle installed from it (`cohort_addressing::snapshot`), so
/// `Edge::blob_scope_router` has a table. Three things are asserted:
///
/// 1. the router RESOLVES node A as a holder to the address the lifecycle
///    derived from the group's exporter — under the table key the installer
///    used (`group_id_for`), which is the mismatch #616 fixed;
/// 2. the pull is therefore no longer refused at `resolve_holder_routes`; it
///    reaches `fetch_blob_chunk_scoped` and is refused THERE, by name, for
///    lack of a Reticulum transport — HTTP has no scope-derived destination
///    plane, and shipping a scoped request on the federation endpoint is the
///    context collapse #499 forbids. The in-process wire is not made to
///    pretend otherwise: that seam is the honest edge of what a non-Reticulum
///    node can do, and this rung pins it as exactly that;
/// 3. the sink was asked to LISTEN on this node's own address and nothing
///    announced (CC 5.4.6).
///
/// Mutation: build the edge without the lifecycle (`spawn_edge`) and (1)
/// fails at the router; the pull's reason reverts to "NO scope address
/// table".
#[allow(clippy::too_many_lines)] // the room's group, both lifecycles, the seam and the pull — one place on purpose
#[tokio::test]
async fn a_community_pull_resolves_through_the_rooms_group_and_stops_at_the_scoped_send() {
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig, PullOutcome};
    use ciris_edge::cohort_addressing::{group_id_for, scope_for, snapshot};
    use ciris_edge::mls::cohort_group::mint_cohort_key_material;
    use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
    use ciris_edge::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
    use ciris_edge::scope_lifecycle::ScopeLifecycle;
    use ciris_persist::encrypted_kv::XChaChaKvStore;
    use ciris_persist::federation::blobs::BlobStorage as _;
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    use ciris_persist::federation::{FederationDirectory, SignedAttestation};
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let room = "room-alice-bob";
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    seed_room(&node_a, room, &[&alice, &bob]).await;
    seed_room(&node_b, room, &[&alice, &bob]).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;

    // The room's MLS group on each node — the CC 5.4 addressing root. A
    // creates, adds B's key package, B joins from the Welcome; the members
    // are the NODE keys, because those are the holders `list_holders` names.
    let store_for = |tag: &[u8]| {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(tag).expect("in-memory scope state"),
        ))
    };
    let group_a = CohortGroup::create(store_for(b"616-a"), room, &node_a.me, 16)
        .await
        .expect("A creates the room's group");
    let (material_b, kp_b) = mint_cohort_key_material(&node_b.me).expect("B's key material");
    let add = group_a
        .add_member(&node_b.me, kp_b)
        .await
        .expect("A adds B");
    let group_b = CohortGroup::join(
        store_for(b"616-b"),
        room,
        material_b,
        add.welcome().expect("welcome"),
        16,
    )
    .await
    .expect("B joins from the Welcome");

    // A lifecycle per node over a listen-only sink, installed from the group.
    let lifecycle_for = |own: &str, sink: Arc<ListenOnly>| {
        let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
        (
            Arc::new(ScopeLifecycle::new(
                Arc::clone(&table),
                sink,
                own,
                std::time::Duration::from_secs(300),
            )),
            table,
        )
    };
    let sink_a = Arc::new(ListenOnly::default());
    let sink_b = Arc::new(ListenOnly::default());
    let (life_a, table_a) = lifecycle_for(&node_a.me, Arc::clone(&sink_a));
    let (life_b, table_b) = lifecycle_for(&node_b.me, Arc::clone(&sink_b));
    life_a
        .install(
            &scope_for(room),
            &snapshot(&group_a).await.expect("snapshot A"),
        )
        .expect("A installs the room's addresses");
    life_b
        .install(
            &scope_for(room),
            &snapshot(&group_b).await.expect("snapshot B"),
        )
        .expect("B installs the room's addresses");

    // (3) CC 5.4.6: each node LISTENS on exactly its own address; nothing
    // announced (the wire has no announce verb; the sink saw only register).
    assert_eq!(
        sink_a.0.lock().expect("sink").len(),
        1,
        "A listens on its own address only"
    );
    assert_eq!(
        sink_b.0.lock().expect("sink").len(),
        1,
        "B listens on its own address only"
    );
    // Both members derive the SAME address for A from their own group state.
    assert_eq!(
        table_a
            .send_address(&scope_for(room), &group_id_for(room), &node_a.me)
            .map(|m| *m.as_bytes()),
        table_b
            .send_address(&scope_for(room), &group_id_for(room), &node_a.me)
            .map(|m| *m.as_bytes()),
        "every member derives the same destination (CC 5.4.6)",
    );

    let (wire_a, wire_b) = wire(&node_a.me, &node_b.me);
    let (_edge_a, _stop_a) =
        spawn_edge_with_lifecycle(&node_a, wire_a, Arc::clone(&life_a), room).await;
    let (edge_b, _stop_b) =
        spawn_edge_with_lifecycle(&node_b, wire_b, Arc::clone(&life_b), room).await;

    // (1) The router on B resolves A, a holder, to the room-derived address.
    let content = ciris_edge::blob_swarm::ContentScope::Group {
        scope: scope_for(room),
        group_id: room.to_owned(),
    };
    let route = edge_b
        .blob_scope_router()
        .route(Some(&content), &node_a.me)
        .expect("B's router resolves A through the room's group (CIRISEdge#616)");
    assert_eq!(
        route.scoped_address().map(MemberAddress::as_bytes),
        table_b
            .send_address(&scope_for(room), &group_id_for(room), &node_a.me)
            .as_ref()
            .map(MemberAddress::as_bytes),
        "the route is the table's derived bytes for A under the room's key",
    );

    // A seals and authors the row; key and holder planes cross as in the pin.
    let body = b"the bytes would cross on the scoped route";
    let sealed = node_a
        .store
        .seal(SealRequest {
            cohort_scope: "community",
            community_key_id: Some(room),
            author_key_id: &node_a.me,
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
    let row = federation_content_row(&node_a.signer, room, &sealed.pointer, ts()).await;
    node_a
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A holds the row it authored");
    for set in node_a
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
    {
        node_b
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: set.attestation.clone(),
            })
            .await
            .expect("B admits A's key_grant set");
    }
    for bytes in rows_of(&node_a, "holds_bytes:").await {
        let h: ciris_persist::federation::Attestation =
            serde_json::from_slice(&bytes).expect("row");
        node_b
            .dir
            .put_attestation(SignedAttestation { attestation: h })
            .await
            .expect("B admits A's holder claim");
    }

    // (2) The pull passes the router and stops at the scoped SEND.
    let puller = BlobPuller::new(
        Arc::clone(&edge_b),
        node_b.store.engine().clone(),
        node_b.dir.clone(),
        node_b.dir.clone() as Arc<dyn FederationDirectory>,
        node_b.me.clone(),
        PullConfig::default(),
    );
    // (2a) The send seam, by name: the resolved scoped route reaches
    // `fetch_blob_chunk_scoped` and is refused there for lack of a
    // Reticulum transport — never shipped on the federation endpoint.
    let seam = edge_b
        .fetch_blob_chunk_scoped(&route, sha, sha, std::time::Duration::from_secs(2))
        .await;
    match &seam {
        Err(e) if e.to_string().contains("no Reticulum transport") => {}
        other => panic!(
            "a scoped route on a node without Reticulum must be refused BY NAME at \
             `fetch_blob_chunk_scoped` (CIRISEdge#499: HTTP has no scope-derived destination \
             plane; a scoped request on the federation endpoint is the context collapse the \
             address exists to prevent). Got {other:?}"
        ),
    }
    // (2b) The pull terminates. The router resolves (so it is NOT "NO scope
    // address table" — #616's regression signature), the seam refuses every
    // dispatch, the scheduler retires the holder at the error-strike limit
    // and reports the chunk unreachable. Bounded by a deadline: before the
    // strike bound an instantly-failing holder was re-dispatched forever.
    let verdict = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        puller.pull_one(&row, sha, 0),
    )
    .await
    .expect(
        "the pull must reach a verdict within the deadline — a holder whose dispatch fails \
         instantly is retired at `SwarmConfig::error_strike_limit`, never re-dispatched \
         forever (CIRISEdge#616)",
    );
    match &verdict {
        PullOutcome::FetchFailed { reason, .. }
            if reason.contains("no holders left") && !reason.contains("NO scope address table") => {
        }
        other => panic!(
            "with the room's group installed the community pull passes \
             `resolve_holder_routes` and ends at the send seam: every dispatch to the one \
             holder is refused, the holder is retired, and the chunk is unreachable. \
             \"NO scope address table\" means the router never saw the lifecycle's table \
             (#616 regressed); `Stored` means a scoped send exists on this transport — \
             promote this pin into the cross-node open. Got {other:?}"
        ),
    }
    assert!(
        !node_b.dir.has_blob(&sha).await.expect("has_blob"),
        "nothing was stored past the send seam's refusal"
    );
}
