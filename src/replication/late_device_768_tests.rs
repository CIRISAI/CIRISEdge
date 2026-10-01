//! **CIRISEdge#768 — a member's node that arrives AFTER a room epoch was
//! minted gets that epoch's key, on the wire.**
//!
//! Two persons, P and Q, one node each (A for P, B for Q), and a room whose
//! roster is {P, Q}. A seals a body into the room while it knows NO device of
//! Q's, so the epoch it mints is wrapped to P's devices only. Only then does
//! B's node occurrence reach A — through A's replication runtime's own bridge
//! apply doors (the owner binding, then the signed occurrence), the path the
//! mesh uses.
//!
//! persist re-wraps A's own epochs to the late device on admission
//! (`rewrap_after_admission`, CIRISPersist#916) — but the receive door writes
//! GRANT ROWS ONLY and leaves the epoch dirty; persist's contract is that "the
//! pending-KeyGrant loop every host runs" signs and emits the updated set
//! (`FederationDirectory::rewrap_own_epochs_for_device`). Until something runs
//! that loop, A keeps re-offering the epoch's ORIGINAL set and B never holds a
//! wrap: every body of the room reads `NotGranted` on B for good. That is the
//! mesh's pair-room failure (runs 36798512838 / 36800354009: the publisher's
//! epoch-0 set carried 4 wraps, none to sub-1's node, and never grew).
//!
//! The witness asserts on what A EMITS and B ADMITS — B's
//! `community_dek_minters_granting(room, epoch, B)` — never on A's local
//! grant rows. A's sets are carried to B through B's runtime's bridge
//! `apply_envelope_bytes(Attestation, ..)`, the key_grant door.
//!
//! `cargo test --lib late_device_768`
//!
//! A lib-level test module, not a `tests/` binary: every integration test
//! binary is linked separately, and one more pushed the `pyo3-full` CI lane's
//! runner out of disk (run 36805316128, `ld` bus error at 13 MB free).

// P, Q (persons) and A, B, C (their nodes) are the issue's names; the
// scenario reads as one sequence on purpose.
#![allow(clippy::many_single_char_names, clippy::too_many_lines)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::group_content::{
    ContentField, GroupContentStore, PersistGroupContentStore, SealRequest,
};
use crate::replication::directory::ReplicationDirectory as _;
use crate::replication::key_grant_emitter::{emit_pass, EmitPass};
use crate::replication::{
    BridgeEngine, EnvelopeKind, ReplicationRuntime, ReplicationRuntimeConfig, SchedulerConfig,
    SealedContentWiring,
};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::key_grant::KEY_GRANT_ATTESTATION_TYPE_PREFIX;
use ciris_persist::federation::{FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

const ROOM: &str = "room-768";

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

/// No network: every row this file moves, it moves by hand through the
/// runtimes' own bridge doors. The runtime only needs a transport to exist.
struct NullTransport;

#[async_trait]
impl Transport for NullTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

struct Ident {
    key_id: String,
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
        let digest = sha2::Sha256::digest(&canonical);
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

    fn signer(&self) -> Arc<crate::identity::LocalSigner> {
        let hw: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&[self.seed; 32], self.ed.current_alias())
                .expect("rebuild the signer"),
        );
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(
                &[self.seed ^ 0x55; 32],
                format!("{}-pqc", self.key_id),
            )
            .expect("rebuild the pqc half"),
        );
        Arc::new(crate::identity::LocalSigner::new(
            self.key_id.clone(),
            hw,
            Some(pqc),
        ))
    }
}

/// One node: its substrate, content store, engine key (the node), its owner.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
    owner: String,
    me: String,
}

/// A device of `owner`, the `family_files_wire_736::device` shape: the node
/// key is `device`'s derived id, the owner binding is signed by `owner`, the
/// engine occurrence is provisioned (node-signed) under the owner.
async fn device(seed_idents: &[&Ident], owner: &Ident, device: &Ident) -> Node {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open substrate");
    dir.run_migrations().await.expect("migrate");
    for id in seed_idents {
        dir.put_public_key(SignedKeyRecord {
            record: id.record().await,
        })
        .await
        .expect("seed identity");
    }
    let ed_pub = device.ed.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(device.ed.current_alias(), &ed_pub);
    let mut rec = device.record().await;
    rec.key_id = derived.clone();
    rec.identity_ref = derived.clone();
    rec.scrub_key_id = derived.clone();
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[device.seed; 32], device.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[device.seed ^ 0x55; 32],
            format!("{}-pqc", device.key_id),
        )
        .expect("rebuild the registered pqc half"),
    );
    let identity = crate::identity::LocalSigner::new(derived.clone(), hw, Some(pqc));
    let binding = crate::replication::attestation_bind::owner_binding_attestation(
        &owner.key_id,
        &derived,
        ts(),
        &owner.signer(),
    )
    .await
    .expect("build this node's owner binding");
    dir.put_attestation_authored(SignedAttestation {
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
    let (me, _) = crate::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        &owner.key_id,
        "server",
    )
    .await
    .expect("provision this node's engine occurrence");
    Node {
        dir,
        store,
        owner: owner.key_id.clone(),
        me,
    }
}

/// The room {P, Q}, founded by P, on `node`.
async fn seed_room(node: &Node, founder: &Ident, members: &[&Ident]) {
    seed_room_named(node, ROOM, founder, members).await;
}

/// A room named `room`, founded by `founder`, on `node`.
async fn seed_room_named(node: &Node, room: &str, founder: &Ident, members: &[&Ident]) {
    use ciris_persist::federation::types::{Community, CommunityMember, SignedCommunity};
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
    let ed_sig = founder.ed.sign(&canonical).await.expect("ed sign");
    let pqc_sig = {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        PqcSigner::sign(&founder.pqc, &bound)
            .await
            .expect("pqc sign")
    };
    // persist v52.0.0 (CIRISPersist#955) — a founding record admits only the
    // members who signed it: every other listed member co-signs.
    let mut cosignatures = Vec::new();
    for m in members.iter().filter(|m| m.key_id != founder.key_id) {
        let ed = m.ed.sign(&canonical).await.expect("cosign ed");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed);
        let pqc = PqcSigner::sign(&m.pqc, &bound).await.expect("cosign pqc");
        cosignatures.push(ciris_persist::federation::types::RosterCosignature {
            authority_key_id: m.key_id.clone(),
            scrub_signature_classical: B64.encode(&ed),
            scrub_signature_pqc: Some(B64.encode(&pqc)),
        });
    }
    node.dir
        .put_community(SignedCommunity {
            community,
            authority_key_id: founder.key_id.clone(),
            scrub_signature_classical: B64.encode(&ed_sig),
            scrub_signature_pqc: Some(B64.encode(&pqc_sig)),
            supersede_proof: None,
            cosignatures,
            lineage: Vec::new(),
        })
        .await
        .expect("seed the room");
}

/// `from`'s node key, owner binding and signed engine occurrence, as wire
/// bytes for the Attestation / IdentityOccurrence apply doors.
async fn device_rows(from: &Node) -> (KeyRecord, Vec<u8>, Vec<u8>) {
    let rec = FederationDirectory::lookup_public_key(&*from.dir, &from.me)
        .await
        .expect("lookup")
        .expect("the engine's derived key is registered");
    let binding = FederationDirectory::list_attestations_since(&*from.dir, None, 256)
        .await
        .expect("list the attestation plane")
        .into_iter()
        .map(|r| r.attestation)
        .find(|a| {
            a.attested_key_id == from.me
                && ciris_persist::federation::admission::is_owner_binding_envelope(
                    &a.attestation_envelope,
                )
        })
        .expect("the node's owner binding");
    let occ = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane")
        .into_iter()
        .map(|s| s.occurrence)
        .find(|o| {
            o.identity_occurrence.occurrence_key_id == from.me
                && o.identity_occurrence.identity_key_id == from.owner
        })
        .expect("the engine occurrence is on the signed plane");
    (
        rec,
        serde_json::to_vec(&binding).expect("encode binding"),
        serde_json::to_vec(&occ).expect("encode occurrence"),
    )
}

/// The node's replication runtime, wired as a sealing host wires it
/// (`SealedContentWiring` over the node's content engine), with no peers and
/// no network: rows are moved by hand through `runtime.bridge()`.
async fn runtime(node: &Node) -> ReplicationRuntime {
    ReplicationRuntime::start(
        Arc::clone(&node.dir) as Arc<dyn FederationDirectory>,
        Arc::new(NullTransport) as Arc<dyn Transport>,
        Vec::new(),
        ReplicationRuntimeConfig {
            // An hour: the emitter's cadence backstop (and its first tick at
            // start, before anything is dirty) cannot be what emits within
            // this file's 20 s budget, so a pass witnesses the WAKE.
            scheduler: SchedulerConfig {
                cadence: Duration::from_secs(3600),
                round_timeout: Duration::from_secs(5),
                ..SchedulerConfig::default()
            },
            local_key_id: Some(node.me.clone()),
            sealed_content: Some(SealedContentWiring {
                engine: BridgeEngine(node.store.engine().clone()),
                pull_sink: None,
                revocations: None,
            }),
            ..ReplicationRuntimeConfig::default()
        },
        None,
    )
    .await
}

/// Every `key_grant:*` set `from` holds, offered to `to` through its bridge's
/// key_grant door — the way the Attestation plane carries them.
async fn carry_key_grants(from: &Node, to: &ReplicationRuntime) {
    for row in FederationDirectory::list_attestations_since(&*from.dir, None, 512)
        .await
        .expect("list the minter's rows")
        .into_iter()
        .map(|r| r.attestation)
        .filter(|a| {
            a.attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
    {
        let bytes = serde_json::to_vec(&row).expect("encode set");
        let _ = to
            .bridge()
            .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(&from.me))
            .await;
    }
}

/// Whether A's room has a minter pointer row before the late device arrives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RoomHistory {
    /// A never-rotated room: epoch 0 and nothing else — every pair room.
    /// persist's `community_dek_communities()` omits it until
    /// CIRISPersist#967, so the #916 re-wrap walk never visits it.
    NeverRotated,
    /// The same room after its minter recorded an epoch pointer (here an
    /// operator retention policy — TEST SETUP ONLY, to step around #967 so
    /// the edge half is witnessed on its own; edge itself never writes one).
    PointerRecorded,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_member_device_receives_the_epoch_key_on_the_wire_768() {
    late_device_scenario(RoomHistory::PointerRecorded).await;
}

/// The same, for the room shape the mesh actually has: never rotated. Live
/// since persist v52.0.1 (CIRISPersist#967: the re-wrap walk enumerates the
/// key-state table, so an epoch-0-only room is visited).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_member_device_receives_the_epoch_key_in_a_never_rotated_room_768() {
    late_device_scenario(RoomHistory::NeverRotated).await;
}

async fn late_device_scenario(history: RoomHistory) {
    let p = Ident::new("person-p-768", 0x31);
    let q = Ident::new("person-q-768", 0x32);
    let a_dev = Ident::new("node-a-768", 0x41);
    let b_dev = Ident::new("node-b-768", 0x42);
    let a = device(&[&p, &q], &p, &a_dev).await;
    let b = device(&[&p, &q], &q, &b_dev).await;
    let c_dev = Ident::new("node-c-768", 0x43);
    let c = device(&[&p, &q], &q, &c_dev).await;
    seed_room(&a, &p, &[&p, &q]).await;
    seed_room(&b, &p, &[&p, &q]).await;

    let mut rt_a = runtime(&a).await;
    let mut rt_b = runtime(&b).await;

    // B knows A as a member device BEFORE any set arrives (the order the mesh
    // delivers it in: the Key / Attestation / IdentityOccurrence planes are
    // not what this file is about), so B can admit A's sets.
    let (a_rec, a_binding, a_occ) = device_rows(&a).await;
    b.dir
        .put_public_key(SignedKeyRecord { record: a_rec })
        .await
        .expect("A's key at B");
    let _ = rt_b
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::Attestation, &a_binding, Some(&a.me))
        .await;
    let _ = rt_b
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &a_occ, None)
        .await;

    // Q's OTHER device (its agent, on the mesh) is known at A before the seal,
    // so the epoch A mints is wrapped to it: the member holds the epoch, and
    // persist's second-device rule (#916) is what owes the late device a wrap.
    let (c_rec, c_binding, c_occ) = device_rows(&c).await;
    a.dir
        .put_public_key(SignedKeyRecord { record: c_rec })
        .await
        .expect("C's key at A");
    let _ = rt_a
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::Attestation, &c_binding, Some(&c.me))
        .await;
    let _ = rt_a
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &c_occ, None)
        .await;

    // A seals into the room knowing only that device of Q's: the epoch it
    // mints is wrapped to P's device and Q's OTHER device, not to B.
    let sealed = a
        .store
        .seal(SealRequest {
            cohort_scope: "community",
            community_key_id: Some(ROOM),
            author_key_id: &a.me,
            asserted_at: ts(),
            field: ContentField::Body,
            plaintext: b"minted before the device arrived",
            description: None,
        })
        .await
        .expect("A seals at the community tier");
    let epoch = sealed.epoch.expect("a community-DEK epoch");
    assert!(
        !sealed.granted.iter().any(|g| g == &b.me),
        "precondition: A's epoch is not wrapped to B (A does not know B yet)"
    );
    assert!(
        sealed.granted.iter().any(|g| g == &c.me),
        "precondition: A's epoch IS wrapped to Q's other device C: {:?}",
        sealed.granted
    );
    carry_key_grants(&a, &rt_b).await;
    assert!(
        b.dir
            .community_dek_minters_granting(ROOM, epoch, &b.me)
            .await
            .expect("read B's grants")
            .is_empty(),
        "precondition: B holds no wrap at A's epoch"
    );

    if history == RoomHistory::PointerRecorded {
        a.dir
            .community_dek_set_retain_past_epochs(ROOM, &a.me, Some(8))
            .await
            .expect("test setup: record the minter's epoch pointer (#967)");
    }

    // B's node reaches A LATE, through A's runtime's own apply doors: the
    // owner binding (Q → B) then the node-signed occurrence. persist re-wraps
    // A's epoch to B on admission (#916) — as grant rows, epoch dirty.
    let (b_rec, b_binding, b_occ) = device_rows(&b).await;
    a.dir
        .put_public_key(SignedKeyRecord { record: b_rec })
        .await
        .expect("B's key at A");
    let bound = rt_a
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::Attestation, &b_binding, Some(&b.me))
        .await;
    let occurred = rt_a
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &b_occ, None)
        .await;
    eprintln!("late fold at A: binding={bound:?} occurrence={occurred:?}");

    // What A EMITS, as B ADMITS it: within a bounded wait, A's sets — carried
    // to B through B's key_grant door — grant B's node a wrap at the epoch.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        carry_key_grants(&a, &rt_b).await;
        let granting = b
            .dir
            .community_dek_minters_granting(ROOM, epoch, &b.me)
            .await
            .expect("read B's grants");
        if granting.iter().any(|m| m == &a.me) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "A never put a wrap for its late member device B on the wire: B's \
             minters_granting(room, {epoch}, B) = {granting:?} after 20 s. persist \
             re-wraps on admission as grant rows only and leaves the epoch dirty; \
             the pending-KeyGrant loop that emits it never ran (CIRISEdge#768)"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // The emitter is the runtime's: it stops with it.
    rt_a.shutdown().await;
    rt_b.shutdown().await;
}

/// What one emission costs when NOTHING is dirty, on a node that minted in
/// `ROOMS` rooms — the price of the emitter's cadence backstop. Measured, not
/// asserted (a timing assertion is a flake): run with `--ignored --nocapture`.
/// Both room histories: today's enumeration skips never-rotated rooms
/// (CIRISPersist#967), so the `PointerRecorded` figure is the post-#967 cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement: run with --ignored --nocapture"]
async fn measure_a_noop_emission_on_a_node_with_many_rooms_768() {
    const ROOMS: usize = 100;
    const RUNS: u32 = 20;
    let p = Ident::new("person-p-768m", 0x51);
    let q = Ident::new("person-q-768m", 0x52);
    let a_dev = Ident::new("node-a-768m", 0x61);
    let c_dev = Ident::new("node-c-768m", 0x63);
    let a = device(&[&p, &q], &p, &a_dev).await;
    let c = device(&[&p, &q], &q, &c_dev).await;
    let (c_rec, c_binding, c_occ) = device_rows(&c).await;
    a.dir
        .put_public_key(SignedKeyRecord { record: c_rec })
        .await
        .expect("C's key at A");
    a.dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: serde_json::from_slice(&c_binding).expect("binding"),
        })
        .await
        .expect("C's binding at A");
    a.dir
        .put_identity_occurrence(serde_json::from_slice(&c_occ).expect("occ"))
        .await
        .expect("C's occurrence at A");
    let mut rooms = Vec::with_capacity(ROOMS);
    for i in 0..ROOMS {
        let room = format!("{ROOM}-m{i:03}");
        seed_room_named(&a, &room, &p, &[&p, &q]).await;
        a.store
            .seal(SealRequest {
                cohort_scope: "community",
                community_key_id: Some(&room),
                author_key_id: &a.me,
                asserted_at: ts(),
                field: ContentField::Body,
                plaintext: b"one body per room",
                description: None,
            })
            .await
            .expect("seal");
        rooms.push(room);
    }
    let engine = a.store.engine().clone();
    // Settle anything the seals left dirty.
    let _ = engine.emit_pending_key_grants().await;
    let time = |label: &'static str| {
        let engine = engine.clone();
        async move {
            for pass in [EmitPass::Sweep, EmitPass::DirtyOnly] {
                let mut total = Duration::ZERO;
                let mut worst = Duration::ZERO;
                for _ in 0..RUNS {
                    let t = Instant::now();
                    let n = emit_pass(&engine, pass).await.expect("emit");
                    let e = t.elapsed();
                    assert_eq!(n, 0, "nothing is dirty");
                    total += e;
                    worst = worst.max(e);
                }
                eprintln!(
                    "MEASURE {label}: {ROOMS} rooms, no-op {pass:?} pass: mean {:?}, worst {:?} over {RUNS} runs",
                    total / RUNS,
                    worst
                );
            }
        }
    };
    time("never-rotated (today's enumeration)").await;
    for room in &rooms {
        a.dir
            .community_dek_set_retain_past_epochs(room, &a.me, Some(8))
            .await
            .expect("pointer row");
    }
    let _ = engine.emit_pending_key_grants().await;
    time("pointer-recorded (post-#967 enumeration)").await;
}
