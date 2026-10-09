//! **CIRISEdge#858 — a fresh node parks what it cannot verify, once, and the
//! host can release it after a claim.**
//!
//! The field (a fresh, unclaimed agent install against the canonical): every
//! `IdentityOccurrence` round refused the same rows, one WARN per row per
//! round, because the canonical offers occurrences whose attesters' Keys the
//! fresh node does not hold (the Key plane is `SelfOwn`). Some refusals parked
//! and were evicted again by the Attestation plane's churn; the "signer does
//! not act for the identity" refusals never parked; nothing counted the park
//! where a scrape could see it; and after the claim nothing released the
//! owner's rows, because the claim writes the owner Key and binding LOCALLY.
//!
//! The witness is the real bridge, its apply choke and the replication
//! `Session`, over two in-memory sqlite directories: a responder R holding
//!
//! - owner `P` (user), agent identity `A`, node `N`, and `U`, a node P owns
//!   (R holds P's binding of U), and the occurrences
//! - `O1 = (identity P, occurrence N, attested by P)`,
//! - `O2 = (A, N, attested by A)`,
//! - `O3 = (P, U, attested by U)` — the issue's "(P, N, att U)" cannot be held
//!   beside O1 (one occurrence per `(identity, occurrence)` pair), so U attests
//!   its own occurrence, the common real shape of a sibling node's row;
//!
//! and a fresh node F holding only its own Key and N's and U's (it has met
//! them), no owner. F applies exactly the bytes R serves. Two legacy rows R
//! cannot hold are hand-built from O1's bytes:
//!
//! - `O4` = O1 with its typed `asserted_at` diverging from the signed envelope
//!   (persist refuses it before it reads the attester's Key, but the park
//!   reads the DIRECTORY, not the reason, so it parks on P — never re-asked
//!   every round, which is what the field needs);
//! - `O5` = O1 naming no signer at all: a transient refusal with no
//!   dependency to wait on, the case fix 6 moves to the terminal schedule.
//!
//! | letter | fix | fails before the fix because |
//! |---|---|---|
//! | (a) | — | round 1: every row refused, four parked (O1, O4 on P; O2 on A; O3 indexed on U) |
//! | (b) | 4, 6 | O3's second refusal stayed on the transient ladder; O5 never left it |
//! | (c) | 2 | one WARN per row per Deliver |
//! | (d) | — | Key(A) through the choke releases O2, which admits |
//! | (e) | 3 | no host hook (O1 waits out the window), and the first window was 3600 s |
//! | (f) | 5 | Attestation churn evicted the occurrence parks from the shared ring |
//! | (g) | — | restart: each row refused once and re-parked, one park line per signer |
//! | (h) | 1 | the park counters were bridge accessors only |
//!
//! `cargo test --lib park_fresh_858`
//!
//! A lib test module, not a `tests/` binary (the `pyo3-full` CI lane is at its
//! runner's disk limit linking test binaries).

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::types::{
    EncryptionPubkeys, IdentityOccurrence, SignedIdentityOccurrence,
};
use ciris_persist::federation::{FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

use crate::replication::refusal_backoff::{
    DEFAULT_MAX_KEYS, DEFAULT_MAX_PARKED, TERMINAL_BASE, TRANSIENT_CAP,
};
use crate::replication::{
    BridgeConfig, DeliverMessage, DirectoryStateAdapter, EnvelopeKind, EnvelopeRef,
    FederationDirectoryReplicationBridge, MutableDirectoryStateAdapter, ReplicationDirectory,
    ReplicationMessage, ReplicationOutcome, Session, SessionRole, SummaryMessage,
};

const KIND: EnvelopeKind = EnvelopeKind::IdentityOccurrence;
const R_PEER: &str = "responder-r-858";

fn sha(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// One identity: a persist-minted, self-scrubbed hybrid Key record (so the
/// Key plane admits it through the choke) and the signer it was minted from.
struct Ident {
    alias: String,
    seed: u8,
    record: KeyRecord,
}

impl Ident {
    async fn mint(alias: &str, identity_type: &str, seed: u8) -> Self {
        let record =
            crate::replication::bridge::tests::minted_key_record(alias, identity_type, seed).await;
        Self {
            alias: alias.to_owned(),
            seed,
            record,
        }
    }

    fn key_id(&self) -> &str {
        &self.record.key_id
    }

    fn signer(&self) -> Arc<crate::identity::LocalSigner> {
        let hw: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&[self.seed; 32], &self.alias)
                .expect("rebuild the ed25519 half"),
        );
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(
                &[self.seed ^ 0x55; 32],
                format!("{}-pqc", self.alias),
            )
            .expect("rebuild the ml-dsa half"),
        );
        Arc::new(crate::identity::LocalSigner::new(
            self.key_id().to_owned(),
            hw,
            Some(pqc),
        ))
    }

    fn signed_key_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&SignedKeyRecord {
            record: self.record.clone(),
        })
        .expect("encode key")
    }
}

/// A content-only signed occurrence of `identity` through `occurrence`,
/// attested by `attester` (persist's CIRISPersist#851 form).
async fn occurrence(
    identity: &str,
    occurrence: &str,
    attester: &Ident,
) -> SignedIdentityOccurrence {
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .expect("millis");
    let (x25519, ml_kem) = (B64.encode([0x07; 32]), B64.encode([0x09; 1184]));
    let env = serde_json::json!({
        "attesting_key_id": attester.key_id(),
        "identity_key_id": identity,
        "occurrence_key_id": occurrence,
        "device_class": "server",
        "encryption_pubkeys": { "x25519_base64": x25519, "ml_kem_768_base64": ml_kem },
        "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": serde_json::Value::Null,
        "hardware_attestation": serde_json::Value::Null,
    });
    let bytes = ciris_verify_core::jcs::canonicalize(&env).expect("jcs");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&attester.signer(), &bytes, "occurrence")
        .await
        .expect("hybrid sign");
    SignedIdentityOccurrence {
        identity_occurrence: IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: "server".to_owned(),
            hardware_attestation: None,
            asserted_at: at,
            valid_until: None,
            encryption_pubkeys: Some(EncryptionPubkeys {
                x25519_base64: x25519,
                ml_kem_768_base64: ml_kem,
            }),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: attester.key_id().to_owned(),
        signed_envelope: env,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    }
}

async fn substrate() -> Arc<SqliteBackend> {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open substrate");
    dir.run_migrations().await.expect("migrate");
    dir
}

async fn hold(dir: &SqliteBackend, id: &Ident) {
    dir.put_public_key(SignedKeyRecord {
        record: id.record.clone(),
    })
    .await
    .expect("hold key");
}

struct World {
    p: Ident,
    a: Ident,
    n: Ident,
    u: Ident,
    f: Ident,
    f_dir: Arc<SqliteBackend>,
    /// O1..O5, in order, as wire bytes.
    rows: Vec<Vec<u8>>,
}

impl World {
    /// R seeded, F fresh. `tag` keeps this test's key ids (and so the
    /// process-global refusal-log keys) apart from every other test's.
    async fn build(tag: &str, seed: u8) -> Self {
        let owner = Ident::mint(&format!("person-p-{tag}"), "user", seed).await;
        let agent = Ident::mint(&format!("agent-a-{tag}"), "agent", seed + 1).await;
        let node_n = Ident::mint(&format!("node-n-{tag}"), "node", seed + 2).await;
        let node_u = Ident::mint(&format!("node-u-{tag}"), "node", seed + 3).await;
        let fresh = Ident::mint(&format!("node-f-{tag}"), "node", seed + 4).await;

        // R: the seeded responder.
        let r_dir = substrate().await;
        for id in [&owner, &agent, &node_n, &node_u] {
            hold(&r_dir, id).await;
        }
        let binding = crate::replication::attestation_bind::owner_binding_attestation(
            owner.key_id(),
            node_u.key_id(),
            chrono::Utc::now(),
            &owner.signer(),
        )
        .await
        .expect("build P's binding of U");
        r_dir
            .put_attestation_authored(SignedAttestation {
                attestation: binding,
            })
            .await
            .expect("R admits P's binding of U");
        let o1 = occurrence(owner.key_id(), node_n.key_id(), &owner).await;
        let o2 = occurrence(agent.key_id(), node_n.key_id(), &agent).await;
        let o3 = occurrence(owner.key_id(), node_u.key_id(), &node_u).await;
        for o in [&o1, &o2, &o3] {
            r_dir
                .put_identity_occurrence(o.clone())
                .await
                .expect("R admits the occurrence");
        }
        // What R SERVES: its own serialization of each stored row, read back
        // through R's bridge fetch (the serve path's point-read).
        let r_bridge = Arc::new(FederationDirectoryReplicationBridge::with_config(
            Arc::clone(&r_dir) as Arc<dyn FederationDirectory>,
            Arc::new(Vec::new),
            BridgeConfig::default(),
        ));
        let stored = r_dir
            .list_signed_identity_occurrences_since(None, 64)
            .await
            .expect("list R's occurrences");
        let mut served = Vec::new();
        for o in [&o1, &o2, &o3] {
            let row = stored
                .iter()
                .map(|s| &s.occurrence)
                .find(|s| {
                    s.attesting_key_id == o.attesting_key_id
                        && s.identity_occurrence.identity_key_id
                            == o.identity_occurrence.identity_key_id
                        && s.identity_occurrence.occurrence_key_id
                            == o.identity_occurrence.occurrence_key_id
                })
                .expect("R holds the occurrence");
            let bytes = serde_json::to_vec(row).expect("encode");
            assert_eq!(
                r_bridge.fetch_envelope_bytes(KIND, &sha(&bytes)).await,
                Some(bytes.clone()),
                "R serves these exact bytes for this hash"
            );
            served.push(bytes);
        }
        // O4: O1 with a typed asserted_at that diverges from the envelope.
        let mut o4: serde_json::Value = serde_json::from_slice(&served[0]).expect("O1 json");
        let shifted = o1.identity_occurrence.asserted_at + chrono::Duration::seconds(1);
        o4["identity_occurrence"]["asserted_at"] = serde_json::to_value(shifted).expect("ts");
        // O5: O1 naming no signer.
        let mut o5: serde_json::Value = serde_json::from_slice(&served[0]).expect("O1 json");
        o5["attesting_key_id"] = serde_json::json!("");
        o5["signed_envelope"]["attesting_key_id"] = serde_json::json!("");
        served.push(serde_json::to_vec(&o4).expect("encode O4"));
        served.push(serde_json::to_vec(&o5).expect("encode O5"));

        // F: fresh, unclaimed; holds its own Key and N's and U's.
        let f_dir = substrate().await;
        for id in [&fresh, &node_n, &node_u] {
            hold(&f_dir, id).await;
        }
        Self {
            p: owner,
            a: agent,
            n: node_n,
            u: node_u,
            f: fresh,
            f_dir,
            rows: served,
        }
    }

    fn bridge(
        &self,
        metrics: Option<crate::observability::EdgeMetrics>,
    ) -> Arc<FederationDirectoryReplicationBridge> {
        Arc::new(
            FederationDirectoryReplicationBridge::with_config(
                Arc::clone(&self.f_dir) as Arc<dyn FederationDirectory>,
                Arc::new(Vec::new),
                BridgeConfig::default(),
            )
            .with_local_key_id(Some(self.f.key_id().to_owned()))
            .with_metrics(metrics),
        )
    }

    fn hashes(&self) -> Vec<[u8; 32]> {
        self.rows.iter().map(|b| sha(b)).collect()
    }
}

/// One SOLICITED round of F against R: F's Summary, R's Summary of every
/// row, F's Diff (the `want` this returns), R's Deliver of exactly what F
/// wanted, applied by F through the choke.
async fn round(
    bridge: &Arc<FederationDirectoryReplicationBridge>,
    rows: &[Vec<u8>],
) -> Vec<[u8; 32]> {
    let dir: Arc<dyn ReplicationDirectory> = Arc::clone(bridge) as _;
    let provider = DirectoryStateAdapter::new(Arc::clone(&dir)).with_peer(R_PEER);
    let applier = MutableDirectoryStateAdapter::new(dir);
    let mut sess = Session::new(SessionRole::Initiator, KIND);
    let _ = sess.start_round(&provider).await;
    let summary = SummaryMessage {
        kind: KIND,
        refs: rows
            .iter()
            .zip(0u64..)
            .map(|(b, seq)| EnvelopeRef {
                envelope_hash: sha(b),
                seq,
            })
            .collect(),
    };
    let ReplicationOutcome::Send(msgs) = sess
        .on_message(
            ReplicationMessage::Summary(summary),
            &provider,
            &applier,
            Some(R_PEER),
        )
        .await
    else {
        panic!("F answers R's Summary with a Diff");
    };
    let want = msgs
        .iter()
        .find_map(|m| match m {
            ReplicationMessage::Diff(d) => Some(d.want.clone()),
            _ => None,
        })
        .expect("a Diff");
    let envelopes: Vec<Vec<u8>> = rows
        .iter()
        .filter(|b| want.contains(&sha(b)))
        .cloned()
        .collect();
    if !envelopes.is_empty() {
        let _ = sess
            .on_message(
                ReplicationMessage::Deliver(DeliverMessage {
                    kind: KIND,
                    envelopes,
                }),
                &provider,
                &applier,
                Some(R_PEER),
            )
            .await;
    }
    want
}

/// R's UNSOLICITED push of `rows` (the #927 proactive publish — the defeater
/// the issue names): applied on its merits whatever the memory says.
async fn push(bridge: &Arc<FederationDirectoryReplicationBridge>, rows: &[Vec<u8>]) {
    let dir: Arc<dyn ReplicationDirectory> = Arc::clone(bridge) as _;
    let provider = DirectoryStateAdapter::new(Arc::clone(&dir)).with_peer(R_PEER);
    let applier = MutableDirectoryStateAdapter::new(dir);
    let mut sess = Session::new(SessionRole::Responder, KIND);
    let _ = sess
        .on_message(
            ReplicationMessage::Deliver(DeliverMessage {
                kind: KIND,
                envelopes: rows.to_vec(),
            }),
            &provider,
            &applier,
            Some(R_PEER),
        )
        .await;
}

/// A `tracing` writer into a shared buffer, for the witness that counts lines.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Captured {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish()
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture").clone()).expect("utf8")
    }

    /// Lines at `level` containing `needle` whose `signer` FIELD is `signer`
    /// (a reason's prose may name other keys; the field is the throttle key).
    fn lines(&self, level: &str, needle: &str, signer: &str) -> usize {
        let quoted = format!("signer=\"{signer}\"");
        let bare = format!("signer={signer}");
        self.text()
            .lines()
            .filter(|l| l.contains(level) && l.contains(needle))
            .filter(|l| l.contains(&quoted) || l.contains(&bare))
            .count()
    }
}

/// (a) round 1 and (b) the escalations — fixes 4 and 6.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_node_parks_round_one_and_escalates_what_cannot_move_858() {
    let w = World::build("858ab", 0x11).await;
    let bridge = w.bridge(None);
    assert!(
        bridge.retention(KIND) == crate::replication::retention::Retention::Bodies,
        "precondition: F applies bodies on this plane"
    );
    let h = w.hashes();

    // (a) Round 1: F wants all five, every one is refused.
    let want = round(&bridge, &w.rows).await;
    assert_eq!(want.len(), 5, "round 1 asks for every row");
    assert_eq!(bridge.refusal_memory_len(), 5, "all five refused");
    assert_eq!(
        bridge.rows_parked_on_signer(),
        4,
        "O1 and O4 park on P, O2 on A (absent Keys), O3 is indexed on U (held)"
    );
    let backoff = bridge.refusal_backoff_for_test();
    assert_eq!(backoff.parked_on(w.p.key_id()), 2);
    assert_eq!(backoff.parked_on(w.a.key_id()), 1);
    assert_eq!(backoff.parked_on(w.u.key_id()), 1);
    assert_eq!(
        bridge.parked_on_signer_len(),
        4,
        "O5 names no signer: not parked"
    );

    // (b) O3 again (a push, as the canonical's proactive publish does): its
    // signer is held and does not act for P here — terminal from attempt 2.
    push(&bridge, std::slice::from_ref(&w.rows[2])).await;
    let past_transient_cap = Instant::now() + TRANSIENT_CAP + Duration::from_secs(60);
    assert!(
        backoff.suppressed_at(KIND, &h[2], past_transient_cap),
        "O3's second refusal must put it on the TERMINAL schedule: on the transient \
         ladder it is re-asked (and WARNed) ~12 times an hour forever (CIRISEdge#858 fix 4)"
    );
    assert_eq!(backoff.parked_on(w.u.key_id()), 1, "still indexed on U");

    // (b) O5 names no dependency: three windows at the transient cap, then the
    // terminal schedule (FSD §2 S1 → S2). Round 1 was refusal 1; seven more.
    for refusal in 2..=8 {
        push(&bridge, std::slice::from_ref(&w.rows[4])).await;
        let quiet_past_cap = backoff.suppressed_at(
            KIND,
            &h[4],
            Instant::now() + TRANSIENT_CAP + Duration::from_secs(60),
        );
        assert_eq!(
            quiet_past_cap,
            refusal == 8,
            "refusal {refusal} of a row with no named dependency: only the 8th (after \
             three windows at the transient cap) moves it to the terminal schedule \
             (CIRISEdge#858 fix 6)"
        );
    }
    assert_eq!(bridge.parked_on_signer_len(), 4, "O5 is still not a park");
}

/// (c) rounds 3–10: no re-ask of a parked row, and ONE refusal WARN and ONE
/// park line per signer however many times the bytes are pushed — fix 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_refusal_warn_and_one_park_line_per_signer_858() {
    let w = World::build("858c", 0x21).await;
    let bridge = w.bridge(None);
    let h = w.hashes();
    let captured = Captured::default();
    {
        let _guard = tracing::subscriber::set_default(captured.subscriber());
        round(&bridge, &w.rows).await;
        for _ in 3..=10 {
            let want = round(&bridge, &w.rows).await;
            for (i, row) in ["O1", "O2", "O3", "O4"].iter().enumerate() {
                assert!(
                    !want.contains(&h[i]),
                    "{row} is parked: no round re-asks for it"
                );
            }
            // The canonical's proactive push re-delivers every row anyway.
            push(&bridge, &w.rows).await;
        }
    }
    let warn = "delivered envelope REFUSED";
    for (who, signer) in [
        ("P", w.p.key_id()),
        ("A", w.a.key_id()),
        ("U", w.u.key_id()),
    ] {
        assert_eq!(
            captured.lines("WARN", warn, signer),
            1,
            "exactly one refusal WARN for signer {who} over ten rounds and eight pushes \
             (CIRISEdge#858 fix 2):\n{}",
            captured.text()
        );
        assert_eq!(
            captured.lines("INFO", "parked", signer),
            1,
            "exactly one park line for signer {who}:\n{}",
            captured.text()
        );
    }
    // The row naming no signer is keyed on (plane, disposition) — a key every
    // test in this process shares, so at most one line here.
    assert!(captured.lines("WARN", warn, "<none>") <= 1);
    let text = captured.text();
    let p_park = text
        .lines()
        .find(|l| l.contains("parked") && l.contains(w.p.key_id()) && l.contains("absent Key"))
        .expect("P's park line");
    assert!(
        p_park.contains("UNCLAIMED"),
        "an unclaimed node says so, and why its owner's rows wait: {p_park}"
    );
}

/// (d) the Key through the choke releases its rows; (e) a LOCAL claim
/// releases nothing until the host calls the hook, and the first park window
/// is 1800 s — fix 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_key_releases_its_rows_and_the_host_hook_releases_a_local_claim_858() {
    let w = World::build("858de", 0x31).await;
    let bridge = w.bridge(None);
    let h = w.hashes();
    let parked_at = Instant::now();
    round(&bridge, &w.rows).await;
    let backoff = bridge.refusal_backoff_for_test();

    // (e, first half) The first park window is TERMINAL_BASE, not twice it.
    assert!(backoff.suppressed_at(
        KIND,
        &h[0],
        parked_at + TERMINAL_BASE.saturating_sub(Duration::from_secs(5))
    ));
    assert!(
        !backoff.suppressed_at(
            KIND,
            &h[0],
            parked_at + TERMINAL_BASE + Duration::from_secs(5)
        ),
        "the first park window must be TERMINAL_BASE (1800 s): the park counted the \
         choke's one refusal twice and installed 3600 s (CIRISEdge#858 fix 3)"
    );

    // (d) Key(A) through the choke: O2 released, re-asked, admitted.
    let key = bridge
        .apply_envelope_bytes(EnvelopeKind::Key, &w.a.signed_key_bytes(), Some(R_PEER))
        .await;
    assert!(
        key.is_admitted(),
        "A's Key admits on the Key plane: {key:?}"
    );
    assert_eq!(bridge.signer_releases(), 1, "O2 released");
    assert!(!bridge.retry_suppressed(KIND, &h[1]));
    let want = round(&bridge, &w.rows).await;
    assert!(want.contains(&h[1]), "the next round asks for O2");
    assert!(
        w.f_dir
            .list_identity_occurrences_active(w.a.key_id())
            .await
            .expect("read")
            .iter()
            .any(|o| o.occurrence_key_id == w.n.key_id()),
        "O2 admitted at F"
    );

    // (e) The claim writes P's Key LOCALLY — no choke, no release.
    hold(&w.f_dir, &w.p).await;
    assert!(
        bridge.retry_suppressed(KIND, &h[0]),
        "a local write releases nothing by itself"
    );
    let released = bridge.release_signer(w.p.key_id());
    assert_eq!(
        released, 2,
        "the host hook releases O1 and O4, parked on P (CIRISEdge#858 fix 3)"
    );
    assert!(!bridge.retry_suppressed(KIND, &h[0]));
    let want = round(&bridge, &w.rows).await;
    assert!(want.contains(&h[0]), "the next round asks for O1");
    assert!(
        w.f_dir
            .list_identity_occurrences_active(w.p.key_id())
            .await
            .expect("read")
            .iter()
            .any(|o| o.occurrence_key_id == w.n.key_id()),
        "O1, the owner's occurrence, admitted after the claim"
    );
    assert_eq!(
        bridge.release_signer(w.a.key_id()),
        0,
        "a signer with nothing parked releases nothing"
    );
}

/// (f) the Attestation plane's ordinary refusals cannot evict occurrence
/// parks; the park ring's own evictions are counted — fix 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_refusals_cannot_evict_the_occurrence_parks_858() {
    let w = World::build("858f", 0x41).await;
    let metrics = crate::observability::EdgeMetrics::new();
    let bridge = Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(&w.f_dir) as Arc<dyn FederationDirectory>,
            Arc::new(Vec::new),
            BridgeConfig::default(),
        )
        .with_local_key_id(Some(w.f.key_id().to_owned()))
        .with_metrics(Some(metrics.clone()))
        .with_refusal_capacities(8, DEFAULT_MAX_PARKED),
    );
    let h = w.hashes();
    round(&bridge, &w.rows).await;
    assert_eq!(bridge.parked_on_signer_len(), 4);
    for i in 0..20u32 {
        let junk = format!("{{\"not_an_attestation\":{i}}}").into_bytes();
        let out = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &junk, Some(R_PEER))
            .await;
        assert!(!out.is_admitted());
    }
    assert_eq!(
        bridge.parked_on_signer_len(),
        4,
        "20 Attestation refusals into an 8-row ordinary ring left the parks alone"
    );
    for (i, row) in ["O1", "O2", "O3", "O4"].iter().enumerate() {
        assert!(
            bridge.retry_suppressed(KIND, &h[i]),
            "{row} is still parked: the Attestation churn must not evict it \
             (CIRISEdge#858 fix 5)"
        );
    }

    // The park ring has its own bound, and its evictions are counted.
    let tight = Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(&w.f_dir) as Arc<dyn FederationDirectory>,
            Arc::new(Vec::new),
            BridgeConfig::default(),
        )
        .with_metrics(Some(metrics.clone()))
        .with_refusal_capacities(DEFAULT_MAX_KEYS, 2),
    );
    round(&tight, &w.rows).await;
    assert_eq!(tight.parked_on_signer_len(), 2);
    assert_eq!(metrics.snapshot().signer_park_evictions, 2);
}

/// (g) a restart forgets the memory by design: each still-absent row is
/// refused once and re-parked, with one park line per signer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_refuses_each_row_once_and_re_parks_it_858() {
    let w = World::build("858g", 0x51).await;
    round(&w.bridge(None), &w.rows).await;
    // The restart: a new bridge over the same directory.
    let restarted = w.bridge(None);
    let captured = Captured::default();
    {
        let _guard = tracing::subscriber::set_default(captured.subscriber());
        for _ in 0..3 {
            round(&restarted, &w.rows).await;
        }
    }
    assert_eq!(restarted.refusal_memory_len(), 5, "each row refused once");
    assert_eq!(restarted.rows_parked_on_signer(), 4, "and re-parked once");
    for signer in [w.p.key_id(), w.a.key_id(), w.u.key_id()] {
        assert_eq!(
            captured.lines("INFO", "parked", signer),
            1,
            "one park line per signer after a restart:\n{}",
            captured.text()
        );
        // The refusal WARN throttle is process-global: in-process the restart
        // keeps it (0 lines); a real restart resets it (1). Never more.
        assert!(captured.lines("WARN", "delivered envelope REFUSED", signer) <= 1);
    }
}

/// (h) the park ledger is in the metrics snapshot — fix 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_park_ledger_is_in_the_metrics_snapshot_858() {
    let w = World::build("858h", 0x61).await;
    let metrics = crate::observability::EdgeMetrics::new();
    let bridge = w.bridge(Some(metrics.clone()));
    round(&bridge, &w.rows).await;
    round(&bridge, &w.rows).await;
    let key = bridge
        .apply_envelope_bytes(EnvelopeKind::Key, &w.a.signed_key_bytes(), Some(R_PEER))
        .await;
    assert!(key.is_admitted());
    let snap = metrics.snapshot();
    assert_eq!(
        snap.rows_parked_on_signer.get(&KIND).copied(),
        Some(4),
        "rows parked on a signer, per plane, in the snapshot (CIRISEdge#858 fix 1)"
    );
    assert_eq!(snap.signer_releases, 1, "Key(A) released O2");
    assert!(
        snap.retry_suppressions >= 5,
        "round 2 dropped every refused row from its want: {}",
        snap.retry_suppressions
    );
    let as_u64 = |n: usize| u64::try_from(n).expect("fits");
    assert_eq!(
        snap.refusal_memory,
        crate::observability::RefusalMemoryGauges {
            len: 4,
            capacity: as_u64(DEFAULT_MAX_KEYS + DEFAULT_MAX_PARKED),
            parked_on_signer_len: 3,
            parked_on_signer_capacity: as_u64(DEFAULT_MAX_PARKED),
        },
        "the memory's size against its bounds, current after the release"
    );
    assert_eq!(snap.signer_park_evictions, 0);
}
