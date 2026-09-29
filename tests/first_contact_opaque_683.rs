//! CIRISEdge#683 — first contact on the opaque plane (`FSD/FIRST_CONTACT.md`
//! §2.2, invariants I15–I18).
//!
//! Two real `Edge`s over two separate persist directories, joined by a
//! recording transport so every frame is in the test's hands: what the new
//! device sends, what its owner's first device answers, and which path the
//! answer took. Keys are minted the way production mints them
//! (`register_self_federation_key`), so the proof-of-possession gate the door
//! runs is the real one.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciris_edge::handler::{Delivery, Message};
use ciris_edge::identity::LocalSigner;
use ciris_edge::messages::MessageType;
use ciris_edge::transport::{
    InboundFrame, ReplyPath, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OpaqueAnswer, OpaqueRequestContext, OpaqueResponse};
use ciris_persist::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::store::sqlite::SqliteBackend;

const TID: TransportId = TransportId("test-683");
const JOIN: u32 = 0x0000_0002;
const LINK: [u8; 16] = [0x68; 16];

/// One frame the recording transport was handed.
#[derive(Clone, Debug)]
struct Sent {
    dest: String,
    bytes: Vec<u8>,
    path: Option<ReplyPath>,
}

#[derive(Default)]
struct Recording {
    sent: Mutex<Vec<Sent>>,
}

impl Recording {
    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

#[async_trait::async_trait]
impl Transport for Recording {
    fn id(&self) -> TransportId {
        TID
    }
    async fn send(&self, dest: &str, bytes: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        self.sent.lock().unwrap().push(Sent {
            dest: dest.to_owned(),
            bytes: bytes.to_vec(),
            path: None,
        });
        Ok(TransportSendOutcome::Delivered)
    }
    async fn send_on_reply_path(
        &self,
        dest: &str,
        path: &ReplyPath,
        bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.sent.lock().unwrap().push(Sent {
            dest: dest.to_owned(),
            bytes: bytes.to_vec(),
            path: Some(*path),
        });
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

/// A node identity minted the production way: its self-signed, subject-bound
/// key record (PoP-valid) and the edge signer over the same keys.
struct Minted {
    key_id: String,
    record: KeyRecord,
    signer: Arc<LocalSigner>,
}

async fn mint(alias: &str, seed: u8) -> Minted {
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], alias).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{alias}-pqc"))
            .expect("ml-dsa-65"),
    );
    let persist_signer = ciris_persist::prelude::LocalSigner::from_hardware_parts(
        Arc::clone(&classical),
        alias.to_owned(),
        Some(Arc::clone(&pqc)),
        Some(format!("{alias}-pqc")),
    )
    .await
    .expect("persist signer");
    let engine = ciris_persist::Engine::with_signer(Arc::new(persist_signer), "sqlite::memory:")
        .await
        .expect("throwaway engine");
    let key_id = engine
        .register_self_federation_key("node", alias, None, serde_json::json!({}), Vec::new())
        .await
        .expect("mint");
    let record = engine
        .federation_directory()
        .lookup_public_key(&key_id)
        .await
        .expect("read back")
        .expect("minted record exists");
    Minted {
        signer: Arc::new(LocalSigner::new(key_id.clone(), classical, Some(pqc))),
        key_id,
        record,
    }
}

async fn directory_with(records: &[&KeyRecord]) -> Arc<SqliteBackend> {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open directory");
    for r in records {
        dir.put_public_key(SignedKeyRecord {
            record: (*r).clone(),
        })
        .await
        .expect("seed key");
    }
    dir
}

fn edge(me: &Minted, dir: &Arc<SqliteBackend>, transport: &Arc<Recording>) -> Arc<Edge> {
    Arc::new(
        Edge::builder()
            .directory(dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .federation_directory(dir.clone() as Arc<dyn FederationDirectory>)
            .queue(dir.clone())
            .signer(Arc::clone(&me.signer))
            .transport(transport.clone() as Arc<dyn Transport>)
            .config(EdgeConfig {
                hybrid_policy: HybridPolicy::Strict,
                cohort_scope_enforcement: ciris_edge::CohortScopeEnforcement::Off,
                ..EdgeConfig::default()
            })
            .build()
            .expect("build edge"),
    )
}

fn frame(bytes: Vec<u8>, path: Option<ReplyPath>) -> InboundFrame {
    InboundFrame {
        envelope_bytes: bytes,
        transport: TID,
        received_at: chrono::Utc::now(),
        source_key_id: None,
        link_key_id: None,
        arrival_scope: None,
        reply_path: path,
    }
}

async fn wait_sent(t: &Recording) -> Sent {
    for _ in 0..200 {
        if let Some(s) = t.take().into_iter().next() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing was sent");
}

async fn holds(dir: &SqliteBackend, key_id: &str) -> bool {
    dir.lookup_public_key(key_id)
        .await
        .expect("lookup")
        .is_some()
}

fn outcome(edge: &Edge, label: &str) -> u64 {
    edge.metrics()
        .snapshot()
        .first_contact_outcomes
        .get(label)
        .copied()
        .unwrap_or(0)
}

type Seen = Arc<Mutex<Vec<OpaqueRequestContext>>>;

/// The first device's device-join answerer: records what it was told, and
/// hands back whatever records the test asks it to introduce.
fn answer_joins(edge: &Edge, introduce: Vec<SignedKeyRecord>) -> Seen {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    edge.register_opaque_answerer(JOIN, move |ctx| {
        log.lock().unwrap().push(ctx);
        let mut answer = OpaqueAnswer::from(OpaqueResponse {
            kind: JOIN,
            status: 200,
            payload: b"welcome".to_vec(),
        });
        answer.introductions.keys.clone_from(&introduce);
        answer
    });
    seen
}

/// Everything a pair needs: the first device A (knows only itself), the new
/// device B (knows itself and, unless `b_knows_a` is false, A).
struct Pair {
    a: Minted,
    b: Minted,
    dir_a: Arc<SqliteBackend>,
    dir_b: Arc<SqliteBackend>,
    t_a: Arc<Recording>,
    t_b: Arc<Recording>,
    edge_a: Arc<Edge>,
    edge_b: Arc<Edge>,
}

async fn pair(b_knows_a: bool) -> Pair {
    let a = mint("first-device", 0x2a).await;
    let b = mint("new-device", 0x2b).await;
    let dir_a = directory_with(&[&a.record]).await;
    let dir_b = if b_knows_a {
        directory_with(&[&b.record, &a.record]).await
    } else {
        directory_with(&[&b.record]).await
    };
    let (t_a, t_b) = (
        Arc::new(Recording::default()),
        Arc::new(Recording::default()),
    );
    let edge_a = edge(&a, &dir_a, &t_a);
    let edge_b = edge(&b, &dir_b, &t_b);
    Pair {
        a,
        b,
        dir_a,
        dir_b,
        t_a,
        t_b,
        edge_a,
        edge_b,
    }
}

/// I15 + I17 — the whole first contact: the never-peered device's request is
/// admitted by its own record, verified, handed to the host as a first
/// contact, and answered on the path it arrived on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_never_peered_device_with_its_key_record_is_verified_handled_and_answered_on_its_path_683(
) {
    let p = pair(true).await;
    let seen = answer_joins(&p.edge_a, Vec::new());
    assert!(!holds(&p.dir_a, &p.b.key_id).await, "A has never seen B");

    let (edge_b, a_id) = (Arc::clone(&p.edge_b), p.a.key_id.clone());
    let ask = tokio::spawn(async move {
        edge_b
            .send_opaque_request_introducing(&a_id, JOIN, b"join please".to_vec(), 10_000)
            .await
    });
    let request = wait_sent(&p.t_b).await;
    assert_eq!(request.dest, p.a.key_id);

    let path = ReplyPath::new(TID, LINK);
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(path)))
        .await;

    assert!(holds(&p.dir_a, &p.b.key_id).await, "B's key was admitted");
    let ctx = seen.lock().unwrap().clone();
    assert_eq!(ctx.len(), 1, "the host handler ran once");
    assert_eq!(ctx[0].sender_key_id, p.b.key_id);
    assert!(ctx[0].first_contact, "and was told it is a first contact");
    assert_eq!(ctx[0].payload, b"join please");
    assert_eq!(outcome(&p.edge_a, "first_contact_admitted"), 1);

    let answer = wait_sent(&p.t_a).await;
    assert_eq!(answer.dest, p.b.key_id);
    assert_eq!(
        answer.path,
        Some(path),
        "the answer rides the path the request arrived on (#353), never a by-key dial"
    );

    p.edge_b
        .dispatch_inbound_for_test(frame(answer.bytes, None))
        .await;
    let exchange = ask.await.expect("join task").expect("answered");
    assert_eq!(exchange.response.status, 200);
    assert_eq!(exchange.response.payload, b"welcome");
    assert_eq!(
        exchange.introductions.keys_held,
        vec![p.a.key_id.clone()],
        "edge added A's own key; B already held it"
    );
}

/// I16 — an unknown key without a record is dropped exactly as before: no
/// admission, no handler, no answer, and the verify says `unknown_key`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_key_without_a_record_is_dropped_as_before_683() {
    let p = pair(true).await;
    let seen = answer_joins(&p.edge_a, Vec::new());
    let (edge_b, a_id) = (Arc::clone(&p.edge_b), p.a.key_id.clone());
    let ask = tokio::spawn(async move {
        edge_b
            .send_opaque_request(&a_id, JOIN, b"join?".to_vec(), 2_000)
            .await
    });
    let request = wait_sent(&p.t_b).await;
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
        .await;

    assert!(!holds(&p.dir_a, &p.b.key_id).await);
    assert!(seen.lock().unwrap().is_empty(), "the host never saw it");
    assert!(p.t_a.take().is_empty(), "no answer");
    let snap = p.edge_a.metrics().snapshot();
    assert_eq!(
        snap.verify_failures_total
            .get(&ciris_edge::observability::VerifyErrorClass::UnknownKey)
            .copied(),
        Some(1)
    );
    assert!(
        snap.first_contact_outcomes.is_empty(),
        "the door never looked at it"
    );
    ask.abort();
}

/// A hand-built request body, so a test can carry a record the sender's own
/// directory would never hand it.
#[derive(serde::Serialize, serde::Deserialize)]
struct CarriedReq {
    kind: u32,
    payload: Vec<u8>,
    key_record: SignedKeyRecord,
}

impl Message for CarriedReq {
    const TYPE: MessageType = MessageType::OpaqueRequest;
    const DELIVERY: Delivery = Delivery::Ephemeral;
    type Response = OpaqueResponse;
}

async fn carry(p: &Pair, record: KeyRecord) -> Sent {
    let (edge_b, a_id) = (Arc::clone(&p.edge_b), p.a.key_id.clone());
    tokio::spawn(async move {
        let _ = edge_b
            .send(
                &a_id,
                CarriedReq {
                    kind: JOIN,
                    payload: b"join".to_vec(),
                    key_record: SignedKeyRecord { record },
                },
            )
            .await;
    });
    wait_sent(&p.t_b).await
}

fn forged(mut record: KeyRecord) -> KeyRecord {
    // Same key, same pubkeys, a signature over nothing it names.
    let mut sig = record.scrub_signature_classical.into_bytes();
    sig[4] = if sig[4] == b'A' { b'B' } else { b'A' };
    record.scrub_signature_classical = String::from_utf8(sig).unwrap();
    record
}

/// I15 — a record that fails proof of possession is refused by name and
/// leaves nothing behind: no key row, no handler, no answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_record_is_refused_and_nothing_is_admitted_683() {
    let p = pair(true).await;
    let seen = answer_joins(&p.edge_a, Vec::new());
    let request = carry(&p, forged(p.b.record.clone())).await;
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
        .await;

    assert!(!holds(&p.dir_a, &p.b.key_id).await, "nothing admitted");
    assert!(seen.lock().unwrap().is_empty());
    assert!(p.t_a.take().is_empty(), "a refusal gets no answer");
    assert_eq!(
        outcome(&p.edge_a, "first_contact_proof_of_possession_failed"),
        1
    );
}

/// I15 — a request may introduce only its own signer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_naming_another_key_is_refused_683() {
    let p = pair(true).await;
    let seen = answer_joins(&p.edge_a, Vec::new());
    let other = mint("someone-else", 0x3c).await;
    let request = carry(&p, other.record.clone()).await;
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
        .await;

    assert!(!holds(&p.dir_a, &p.b.key_id).await);
    assert!(
        !holds(&p.dir_a, &other.key_id).await,
        "the named key is not admitted either"
    );
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        outcome(&p.edge_a, "first_contact_record_names_other_key"),
        1
    );
}

/// I15 — the budget runs BEFORE the proof of possession: three failed
/// attempts cost a PoP each, the fourth is refused by the sender budget and
/// costs nothing. (Admitted attempts cannot trip it: once admitted the key is
/// known, and a known key is never charged.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_contact_budget_trips_by_name_683() {
    let p = pair(true).await;
    let _seen = answer_joins(&p.edge_a, Vec::new());
    for _ in 0..4 {
        let request = carry(&p, forged(p.b.record.clone())).await;
        p.edge_a
            .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
            .await;
    }
    assert_eq!(
        outcome(&p.edge_a, "first_contact_proof_of_possession_failed"),
        3
    );
    assert_eq!(outcome(&p.edge_a, "first_contact_sender_budget_spent"), 1);
    assert!(!holds(&p.dir_a, &p.b.key_id).await);
}

/// I18 — the answer's introductions land at the requester before the call
/// returns: here B has never seen A either, so A's own key (added by edge) is
/// admitted before B verifies the answer, and the owner's key the host
/// introduced is admitted with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_introductions_land_at_the_requester_683() {
    let p = pair(false).await;
    let owner = mint("owner", 0x4d).await;
    let _seen = answer_joins(
        &p.edge_a,
        vec![SignedKeyRecord {
            record: owner.record.clone(),
        }],
    );
    assert!(!holds(&p.dir_b, &p.a.key_id).await, "B has never seen A");

    let (edge_b, a_id) = (Arc::clone(&p.edge_b), p.a.key_id.clone());
    let ask = tokio::spawn(async move {
        edge_b
            .send_opaque_request_introducing(&a_id, JOIN, b"join".to_vec(), 10_000)
            .await
    });
    let request = wait_sent(&p.t_b).await;
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
        .await;
    let answer = wait_sent(&p.t_a).await;
    p.edge_b
        .dispatch_inbound_for_test(frame(answer.bytes, None))
        .await;

    let exchange = ask.await.expect("task").expect("answered");
    assert_eq!(exchange.response.status, 200);
    let mut admitted = exchange.introductions.keys_admitted.clone();
    admitted.sort();
    let mut want = vec![p.a.key_id.clone(), owner.key_id.clone()];
    want.sort();
    assert_eq!(admitted, want, "report: {:?}", exchange.introductions);
    assert!(holds(&p.dir_b, &p.a.key_id).await);
    assert!(holds(&p.dir_b, &owner.key_id).await);
}

/// I18 — an answer to a request this node never sent introduces nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsolicited_answer_introduces_nothing_683() {
    let p = pair(true).await;
    let _seen = answer_joins(&p.edge_a, Vec::new());
    let (edge_b, a_id) = (Arc::clone(&p.edge_b), p.a.key_id.clone());
    let ask = tokio::spawn(async move {
        edge_b
            .send_opaque_request_introducing(&a_id, JOIN, b"join".to_vec(), 10_000)
            .await
    });
    let request = wait_sent(&p.t_b).await;
    p.edge_a
        .dispatch_inbound_for_test(frame(request.bytes, Some(ReplyPath::new(TID, LINK))))
        .await;
    let answer = wait_sent(&p.t_a).await;
    ask.abort();

    // A third node that asked A nothing receives A's answer.
    let c = mint("bystander", 0x5e).await;
    let dir_c = directory_with(&[&c.record]).await;
    let edge_c = edge(&c, &dir_c, &Arc::new(Recording::default()));
    edge_c
        .dispatch_inbound_for_test(frame(answer.bytes, None))
        .await;
    assert!(
        !holds(&dir_c, &p.a.key_id).await,
        "an unsolicited answer's keys are never admitted"
    );
    assert_eq!(
        outcome(&edge_c, "first_contact_unsolicited_introductions"),
        1
    );
}
