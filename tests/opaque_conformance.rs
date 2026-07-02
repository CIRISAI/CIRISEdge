//! CC 0.7 opaque-wire-vocabulary conformance suite (CIRISEdge v8.0.0).
//!
//! INDEPENDENT / CLEANROOM: these tests are authored from the CC 0.7
//! contract (CIRISRegistry `manifests/WIRE_VOCABULARY.md` v1.0.1 §3.3,
//! reflected in this repo's `FSD/CIRIS_EDGE.md` §3.2–§3.3 + §4 and
//! `MISSION.md` §2/§6). They assert the mission-load-bearing behaviors
//! of the Tier-2 opaque RPC surface:
//!
//!   OpaqueRequest  { kind: u32, payload: Vec<u8> }             Delivery::Ephemeral (Response = OpaqueResponse)
//!   OpaqueResponse { kind: u32, status: u16, payload: Vec<u8> } Delivery::Ephemeral (no Response)
//!   OpaqueEvent    { kind: u32, payload: Vec<u8> }             Delivery::Durable   (no Response)
//!
//! Edge carries `payload` as OPAQUE bytes: NO typed struct, NO
//! canonical_bytes, NO Message-semantic knowledge for any migrant. It
//! carries reach, not meaning (FSD §1.3). The app owns inner
//! canonicalization + any inner signature; the outer `EdgeEnvelope`
//! signature stays transport-tier.
//!
//! `MessageType` is a FIELDLESS discriminator; the `{kind, payload}`
//! fields live on the body structs (`OpaqueRequest`, `OpaqueResponse`,
//! `OpaqueEvent`), each of which implements [`ciris_edge::handler::Message`]
//! declaring its wire discriminator + compile-time `DELIVERY` class.
//!
//! The `WIRE_VOCABULARY_HASH` build-gate pins the crate to the registry
//! spec; `SchemaVersion::V2_0_0` is the coordinated strict-flip wire
//! break that carries this vocabulary.
//!
//! Two layers of test live here:
//!   * The `messages`-layer anchors run under default features — they
//!     touch only the wire vocabulary, no transport.
//!   * The two-node behavioral round-trips are gated behind
//!     `transport-reticulum` and reuse the loopback harness from
//!     `tests/common` (identical to `tests/reticulum_loopback.rs`).

// ─────────────────────────────────────────────────────────────────────
// Anchor 1 — the registry-spec hash pin (FSD §3 `MessageType`, build-gate)
// ─────────────────────────────────────────────────────────────────────

/// The crate MUST pin the exact sha256 of the authoritative
/// `WIRE_VOCABULARY.md` (v1.0.1 §3.3). Crate-vs-registry drift fails the
/// build; this test is the assertion side of that gate.
#[test]
fn wire_vocabulary_hash_pinned() {
    // sha256 of the registry-owned WIRE_VOCABULARY.md v1.0.1 §3.3.
    const HEX: &str = "c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c";
    let expected: [u8; 32] = hex::decode(HEX)
        .expect("hex-decode wire-vocabulary hash")
        .as_slice()
        .try_into()
        .expect("32-byte digest");
    assert_eq!(
        ciris_edge::WIRE_VOCABULARY_HASH,
        expected,
        "crate WIRE_VOCABULARY_HASH drifted from registry spec v1.0.1"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Anchor 2 — SchemaVersion::V2_0_0 is the new strict-flip default
// ─────────────────────────────────────────────────────────────────────

/// CC 0.7 IS the coordinated wire break: `V2_0_0` is the sole
/// allowlisted schema version and the default a fresh envelope stamps
/// (FSD §3 "the new strict-flip default").
#[test]
fn schema_version_default_is_v2_0_0() {
    use ciris_edge::messages::SchemaVersion;
    assert_eq!(
        SchemaVersion::default(),
        SchemaVersion::V2_0_0,
        "V2_0_0 must be the default SchemaVersion after the CC 0.7 flip"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Anchor 3 — the opaque vocabulary exists; the migrants are gone
// ─────────────────────────────────────────────────────────────────────

/// The three Tier-2 bodies exist as typed structs with the contract
/// fields. Constructing them is a compile-level assertion of the shape
/// `{ kind: u32, payload: Vec<u8> }` (+ `status: u16` on the response).
#[test]
fn opaque_vocabulary_exists() {
    use ciris_edge::messages::{OpaqueEvent, OpaqueRequest, OpaqueResponse};

    let req = OpaqueRequest {
        kind: 0x0000_0001_u32,
        payload: b"ping".to_vec(),
    };
    let resp = OpaqueResponse {
        kind: 0x0000_0001_u32,
        status: 200_u16,
        payload: b"pong".to_vec(),
    };
    let ev = OpaqueEvent {
        kind: 0x0000_0001_u32,
        payload: b"tick".to_vec(),
    };

    assert_eq!(req.kind, 0x0000_0001);
    assert_eq!(req.payload, b"ping");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.payload, b"pong");
    assert_eq!(ev.kind, 0x0000_0001);
    assert_eq!(ev.payload, b"tick");
}

/// The pre-CC-0.7 migrant bodies (`InlineText`, `AccordEventsBatch`,
/// `FederationKeyDirectoryQuery`) are gone from the wire vocabulary. A
/// removed enum variant cannot be *referenced* from a passing test, so
/// the negative is expressed positively: the opaque discriminators are
/// the wire vocabulary now, and — the CC 0.7 shape correction —
/// `MessageType` is FIELDLESS. The `{kind, payload}` fields live on the
/// body structs, never on the enum variants.
#[test]
fn migrants_are_gone_replacements_present() {
    use ciris_edge::messages::MessageType;

    // Fieldless discriminators — the wire vocabulary after CC 0.7. The
    // enum carries NO `{kind, payload}` fields (those live on the body
    // structs); it is a bare, equality-comparable discriminator that
    // dispatch keys on.
    assert_eq!(MessageType::OpaqueRequest, MessageType::OpaqueRequest);
    assert_eq!(MessageType::OpaqueResponse, MessageType::OpaqueResponse);
    assert_eq!(MessageType::OpaqueEvent, MessageType::OpaqueEvent);
    assert_ne!(MessageType::OpaqueRequest, MessageType::OpaqueEvent);
    assert_ne!(MessageType::OpaqueRequest, MessageType::OpaqueResponse);
}

// ─────────────────────────────────────────────────────────────────────
// Anchor 4 — Delivery class lives on the TYPE (OQ-09), not the call site
// ─────────────────────────────────────────────────────────────────────
//
// The delivery class is a compile-time `const DELIVERY` on the `Message`
// impl for each body struct — a caller cannot pick the wrong class. It
// is NOT a runtime method on the fieldless `MessageType` enum.

/// `OpaqueRequest` / `OpaqueResponse` ride `Delivery::Ephemeral`
/// (point-to-point, caller-retry).
#[test]
fn opaque_request_response_are_ephemeral_delivery() {
    use ciris_edge::handler::{Delivery, Message};
    use ciris_edge::messages::{MessageType, OpaqueRequest, OpaqueResponse};

    assert_eq!(<OpaqueRequest as Message>::DELIVERY, Delivery::Ephemeral);
    assert_eq!(<OpaqueResponse as Message>::DELIVERY, Delivery::Ephemeral);
    assert_eq!(<OpaqueRequest as Message>::TYPE, MessageType::OpaqueRequest);
    assert_eq!(
        <OpaqueResponse as Message>::TYPE,
        MessageType::OpaqueResponse
    );
}

/// `OpaqueEvent` rides the durable (persistent) delivery class,
/// fire-and-forget fan-out to subscribers. The spec word
/// "persistent"/"durable" maps to `Delivery::Durable { requires_ack:
/// false, .. }` — there is no `Delivery::Persistent`.
#[test]
fn opaque_event_is_durable_delivery() {
    use ciris_edge::handler::{Delivery, Message};
    use ciris_edge::messages::OpaqueEvent;

    assert!(
        matches!(
            <OpaqueEvent as Message>::DELIVERY,
            Delivery::Durable {
                requires_ack: false,
                ..
            }
        ),
        "OpaqueEvent must ride Delivery::Durable {{ requires_ack: false, .. }}"
    );
}

// ═════════════════════════════════════════════════════════════════════
// Two-node behavioral round-trips (Reticulum loopback).
//
// These reuse the `tests/common` harness: a real persist
// `federation_keys` directory (steward → {A, B}), two `ReticulumTransport`
// instances over loopback, cross-primed via `prime_v7_peer_pair` (the
// v7.0.0 explicit-hash rooting the announce path forbids). Each transport
// is wrapped in an `Edge`; the edge-owned inbound dispatch loop is driven
// via `Edge::spawn_background_listeners` — the exact production surface
// `init_edge_runtime` uses (mirrors `tests/reticulum_loopback.rs`).
// ═════════════════════════════════════════════════════════════════════

#[cfg(feature = "transport-reticulum")]
mod common;

#[cfg(feature = "transport-reticulum")]
mod loopback {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use ciris_edge::identity::LocalSigner;
    use ciris_edge::transport::reticulum::{
        ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
    };
    use ciris_edge::transport::Transport;
    use ciris_edge::verify::{HybridPolicy, RootingDirectory, VerifyDirectory};
    use ciris_edge::{CohortScopeEnforcement, Edge, EdgeConfig};
    use ciris_persist::store::sqlite::SqliteBackend;

    use super::common::{directory_with, prime_v7_peer_pair, signed_record, TestFedKey};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local addr")
            .port()
    }

    /// Edge `LocalSigner` (Ed25519-only) loaded from a test seed dir.
    async fn signer_for(key: &TestFedKey, base: &Path) -> Arc<LocalSigner> {
        let seed_dir = key.write_seed_dir(base);
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: key.key_id.clone(),
            key_path: seed_dir.join("ed25519.seed"),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load_local_seed");
        Arc::new(LocalSigner::new(key.key_id.clone(), classical, None))
    }

    /// `ReticulumAuth` for `key`, rooted against the shared directory.
    async fn auth_for(key: &TestFedKey, dir: Arc<SqliteBackend>, base: &Path) -> ReticulumAuth {
        ReticulumAuth {
            signer: Some(signer_for(key, base).await),
            rooting: Some(dir as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            ..ReticulumAuth::default()
        }
    }

    /// Build one primed loopback transport with mutual bootstrap (each
    /// node dials the other, so both A→B and B→A have a dialable path —
    /// the opaque round-trips need both directions).
    async fn build_sym(
        key: &TestFedKey,
        dir: Arc<SqliteBackend>,
        base: &Path,
        listen: u16,
        boot: u16,
    ) -> Arc<ReticulumTransport> {
        let mut c = ReticulumTransportConfig::new(base.join(&key.key_id).join("t.id"), &key.key_id);
        c.listen_addr = format!("127.0.0.1:{listen}").parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{boot}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(2);
        let auth = auth_for(key, dir, base).await;
        Arc::new(
            ReticulumTransport::new(c, auth)
                .await
                .expect("build transport"),
        )
    }

    /// Stand up two primed transports each wrapped in an `Edge`. Returns
    /// the two edges plus their `key_id`s. The tempdir is leaked to keep
    /// the seed files alive for the life of the edges.
    async fn two_node() -> (Arc<Edge>, Arc<Edge>, String, String) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().to_path_buf();

        let steward = TestFedKey::new("steward-opaque", 0x01);
        let a = TestFedKey::new("edge-a-opaque", 0x2a);
        let b = TestFedKey::new("edge-b-opaque", 0x2b);

        let dir = directory_with(vec![
            signed_record(&steward, &steward, "steward"),
            signed_record(&a, &steward, "agent"),
            signed_record(&b, &steward, "agent"),
        ])
        .await;

        // SYMMETRIC reachability: pre-pick both ports so EACH node
        // bootstraps the other. The opaque request/response round-trip
        // needs A→B (the response) as well as B→A (the request); a
        // one-way bootstrap (only B dials A) leaves A with no route to
        // B. Mutual bootstrap gives both directions a dialable path.
        let port_a = free_port();
        let port_b = free_port();
        let ta = build_sym(&a, dir.clone(), &base, port_a, port_b).await;
        let tb = build_sym(&b, dir.clone(), &base, port_b, port_a).await;
        prime_v7_peer_pair(&ta, &a.key_id, &tb, &b.key_id).await;

        let signer_a = signer_for(&a, &base).await;
        let signer_b = signer_for(&b, &base).await;
        let queue = dir.clone();

        let edge_a = Arc::new(
            Edge::builder()
                .directory(dir.clone() as Arc<dyn VerifyDirectory>)
                .queue(queue.clone())
                .signer(signer_a)
                .transport(ta.clone() as Arc<dyn Transport>)
                .reticulum_transport(ta)
                .config(EdgeConfig {
                    hybrid_policy: HybridPolicy::Ed25519Fallback,
                    cohort_scope_enforcement: CohortScopeEnforcement::Off,
                    ..EdgeConfig::default()
                })
                .build()
                .expect("build edge A"),
        );
        let edge_b = Arc::new(
            Edge::builder()
                .directory(dir.clone() as Arc<dyn VerifyDirectory>)
                .queue(queue)
                .signer(signer_b)
                .transport(tb.clone() as Arc<dyn Transport>)
                .reticulum_transport(tb)
                .config(EdgeConfig {
                    hybrid_policy: HybridPolicy::Ed25519Fallback,
                    cohort_scope_enforcement: CohortScopeEnforcement::Off,
                    ..EdgeConfig::default()
                })
                .build()
                .expect("build edge B"),
        );

        // Keep the tempdir (seed files) alive for the life of the edges.
        std::mem::forget(tmp);
        (edge_a, edge_b, a.key_id, b.key_id)
    }

    /// Build a dedicated multi-thread runtime for driving one edge's
    /// background listeners (Reticulum's link drive needs real threads).
    fn edge_runtime(name: &str) -> Arc<tokio::runtime::Runtime> {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .thread_name(name)
                .build()
                .expect("build edge runtime"),
        )
    }

    /// 1. Request/response round-trip: B → A, A's handler answers 200.
    ///    The response is SENDER-VISIBLE: `send_opaque_request` awaits
    ///    the correlated `OpaqueResponse` (correlation rides the request
    ///    envelope's `body_sha256` → response `in_reply_to`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opaque_request_response_round_trip() {
        let (edge_a, edge_b, a_id, _b_id) = two_node().await;

        // A answers kind 0x0000_0001 with a 200.
        edge_a.register_opaque_handler(0x0000_0001, |_sender_key_id, payload| {
            assert_eq!(payload, b"ping");
            ciris_edge::messages::OpaqueResponse {
                kind: 0x0000_0001,
                status: 200,
                payload: b"pong".to_vec(),
            }
        });

        let rt_a = edge_runtime("opaque-rt-a-1");
        let rt_b = edge_runtime("opaque-rt-b-1");
        let _ha = edge_a.spawn_background_listeners(rt_a.handle());
        let _hb = edge_b.spawn_background_listeners(rt_b.handle());

        let resp = edge_b
            .send_opaque_request(&a_id, 0x0000_0001, b"ping".to_vec(), 45_000)
            .await
            .expect("opaque request round-trip");

        assert_eq!(resp.kind, 0x0000_0001);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.payload, b"pong");

        std::mem::forget(rt_a);
        std::mem::forget(rt_b);
    }

    /// 2. Unknown `kind` → a sender-visible `status: 501`, never a silent
    ///    drop and never a timeout (MISSION §6 anti-pattern 7). A
    ///    registers a handler for a DIFFERENT kind, so 0x9999_9999 is
    ///    unknown at dispatch; the edge synthesizes the 501 reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opaque_unknown_kind_returns_501() {
        let (edge_a, edge_b, a_id, _b_id) = two_node().await;

        // Only 0x0000_0001 is known on A; 0x9999_9999 has no handler.
        edge_a.register_opaque_handler(0x0000_0001, |_sender_key_id, _payload| {
            ciris_edge::messages::OpaqueResponse {
                kind: 0x0000_0001,
                status: 200,
                payload: b"ok".to_vec(),
            }
        });

        let rt_a = edge_runtime("opaque-rt-a-2");
        let rt_b = edge_runtime("opaque-rt-b-2");
        let _ha = edge_a.spawn_background_listeners(rt_a.handle());
        let _hb = edge_b.spawn_background_listeners(rt_b.handle());

        let resp = edge_b
            .send_opaque_request(&a_id, 0x9999_9999, b"who?".to_vec(), 30_000)
            .await
            .expect("send resolves to a typed response, not a timeout/drop");

        assert_eq!(
            resp.status, 501,
            "unknown kind must reply 501, sender-visible"
        );
        assert_eq!(resp.kind, 0x9999_9999, "501 echoes the requested kind");

        std::mem::forget(rt_a);
        std::mem::forget(rt_b);
    }

    /// 3. `OpaqueEvent` fan-out: B subscribes to a kind; A publishes it
    ///    on the durable class; B's subscriber channel fires with
    ///    `(sender_key_id, kind, payload)`.
    ///
    /// Unlike the ephemeral request/response tests, `OpaqueEvent` rides
    /// `Delivery::Durable`, so `send_opaque_event` only *enqueues* — the
    /// outbound dispatcher (spawned by `Edge::run`, NOT by
    /// `spawn_background_listeners`) is what drains the queue + transmits.
    /// So A is driven via `Edge::run` (full stack incl. dispatcher) and B
    /// via `spawn_background_listeners` (listen + inbound fan-out).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opaque_event_delivers_to_subscriber() {
        use ciris_edge::EdgeError;
        use tokio::sync::watch;

        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().to_path_buf();
        let steward = TestFedKey::new("steward-opaque-ev", 0x01);
        let a = TestFedKey::new("edge-a-opaque-ev", 0x3a);
        let b = TestFedKey::new("edge-b-opaque-ev", 0x3b);
        let dir = directory_with(vec![
            signed_record(&steward, &steward, "steward"),
            signed_record(&a, &steward, "agent"),
            signed_record(&b, &steward, "agent"),
        ])
        .await;

        let port_a = free_port();
        let port_b = free_port();
        let ta = build_sym(&a, dir.clone(), &base, port_a, port_b).await;
        let tb = build_sym(&b, dir.clone(), &base, port_b, port_a).await;
        prime_v7_peer_pair(&ta, &a.key_id, &tb, &b.key_id).await;

        let signer_a = signer_for(&a, &base).await;
        let signer_b = signer_for(&b, &base).await;

        let cfg = || EdgeConfig {
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            cohort_scope_enforcement: CohortScopeEnforcement::Off,
            ..EdgeConfig::default()
        };
        // A: OWNED Edge — `run()` drives the outbound dispatcher that
        // transmits the durable event.
        let edge_a = Edge::builder()
            .directory(dir.clone() as Arc<dyn VerifyDirectory>)
            .queue(dir.clone())
            .signer(signer_a)
            .transport(ta.clone() as Arc<dyn Transport>)
            .reticulum_transport(ta)
            .config(cfg())
            .build()
            .expect("build edge A");
        // B: Arc — subscribe before spawning its inbound fan-out.
        let edge_b = Arc::new(
            Edge::builder()
                .directory(dir.clone() as Arc<dyn VerifyDirectory>)
                .queue(dir.clone())
                .signer(signer_b)
                .transport(tb.clone() as Arc<dyn Transport>)
                .reticulum_transport(tb)
                .config(cfg())
                .build()
                .expect("build edge B"),
        );
        std::mem::forget(tmp);

        let (_sub_id, mut rx) = edge_b.register_opaque_subscriber(0x0000_0001);
        let rt_b = edge_runtime("opaque-rt-b-3");
        let _hb = edge_b.spawn_background_listeners(rt_b.handle());

        // Enqueue the durable event, then drive A's full stack.
        edge_a
            .send_opaque_event(&b.key_id, 0x0000_0001, b"event-bytes".to_vec())
            .await
            .expect("enqueue opaque event");
        let (_sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(async move {
            // v8.2.0 (CIRISEdge#249) — `run` takes `self: Arc<Self>`.
            let _: Result<(), EdgeError> = std::sync::Arc::new(edge_a).run(sd_rx).await;
        });

        let (_sender, kind, payload) = tokio::time::timeout(Duration::from_secs(45), rx.recv())
            .await
            .expect("subscriber callback fired within timeout")
            .expect("subscriber channel delivered a payload");
        assert_eq!(kind, 0x0000_0001);
        assert_eq!(payload, b"event-bytes");

        std::mem::forget(rt_b);
    }

    /// 4. CIRISEdge#249 — the mesh control-plane INITIATOR leg works on a
    ///    `run()`-lifecycle node. Before #249, `Edge::run(self)` consumed
    ///    the edge, so a node that booted via `run()` had no handle left to
    ///    issue `send_opaque_request`. Now `run(self: Arc<Self>)` lets A
    ///    spawn the FULL run lifecycle on one `Arc` clone AND keep another
    ///    to initiate a request from a separate task. B answers 200 via its
    ///    own listeners. This is the `run()`-path counterpart to the
    ///    `spawn_background_listeners`-path round-trip in test 1, and the
    ///    exact acceptance criterion for CIRISServer#128 Phase E.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opaque_request_initiator_works_on_run_lifecycle() {
        use ciris_edge::EdgeError;
        use tokio::sync::watch;

        let (edge_a, edge_b, _a_id, b_id) = two_node().await;

        // B answers kind 0x0000_0002 with a 200.
        edge_b.register_opaque_handler(0x0000_0002, |_sender_key_id, payload| {
            assert_eq!(payload, b"seed?");
            ciris_edge::messages::OpaqueResponse {
                kind: 0x0000_0002,
                status: 200,
                payload: b"seeded".to_vec(),
            }
        });

        let rt_a = edge_runtime("opaque-rt-a-249");
        let rt_b = edge_runtime("opaque-rt-b-249");

        // A boots on the FULL `run()` lifecycle via an `Arc` clone; the
        // original `edge_a` handle survives for the initiator send below.
        let (_sd_tx, sd_rx) = watch::channel(false);
        let edge_a_run = Arc::clone(&edge_a);
        rt_a.spawn(async move {
            let _: Result<(), EdgeError> = edge_a_run.run(sd_rx).await;
        });
        let _hb = edge_b.spawn_background_listeners(rt_b.handle());

        // Let A's run() lifecycle claim its listeners before initiating.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Initiator leg: issue the request from the STILL-HELD `edge_a`,
        // proving a run()-lifecycle node can drive `send_opaque_request`.
        let resp = edge_a
            .send_opaque_request(&b_id, 0x0000_0002, b"seed?".to_vec(), 45_000)
            .await
            .expect("initiator send on a run()-lifecycle node");

        assert_eq!(resp.kind, 0x0000_0002);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.payload, b"seeded");

        std::mem::forget(rt_a);
        std::mem::forget(rt_b);
    }

    /// 5. CIRISEdge#243 — a DURABLE send (`send_opaque_event`) transmits
    ///    from the PRODUCTION `init_edge_runtime` posture:
    ///    `spawn_background_listeners` + `spawn_outbound_dispatcher`, with
    ///    NO `Edge::run` fallback. Test 3 above proves the fan-out works
    ///    when `run()` drives the dispatcher; this proves it works when the
    ///    dispatcher is spawned the way `init_edge_runtime` now wires it.
    ///    On `main` (before #243) the sender never transmitted (only
    ///    listeners ran under `spawn_background_listeners`), so the
    ///    subscriber timed out; here it must fire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opaque_event_delivers_via_spawn_background_dispatcher() {
        use tokio::sync::watch;

        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().to_path_buf();
        let steward = TestFedKey::new("steward-opaque-243", 0x01);
        let a = TestFedKey::new("edge-a-opaque-243", 0x4a);
        let b = TestFedKey::new("edge-b-opaque-243", 0x4b);
        let dir = directory_with(vec![
            signed_record(&steward, &steward, "steward"),
            signed_record(&a, &steward, "agent"),
            signed_record(&b, &steward, "agent"),
        ])
        .await;

        let port_a = free_port();
        let port_b = free_port();
        let ta = build_sym(&a, dir.clone(), &base, port_a, port_b).await;
        let tb = build_sym(&b, dir.clone(), &base, port_b, port_a).await;
        prime_v7_peer_pair(&ta, &a.key_id, &tb, &b.key_id).await;

        let signer_a = signer_for(&a, &base).await;
        let signer_b = signer_for(&b, &base).await;

        let cfg = || EdgeConfig {
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            cohort_scope_enforcement: CohortScopeEnforcement::Off,
            ..EdgeConfig::default()
        };
        // A: sender on the PRODUCTION posture (Arc, no `run()`).
        let edge_a = Arc::new(
            Edge::builder()
                .directory(dir.clone() as Arc<dyn VerifyDirectory>)
                .queue(dir.clone())
                .signer(signer_a)
                .transport(ta.clone() as Arc<dyn Transport>)
                .reticulum_transport(ta)
                .config(cfg())
                .build()
                .expect("build edge A"),
        );
        let edge_b = Arc::new(
            Edge::builder()
                .directory(dir.clone() as Arc<dyn VerifyDirectory>)
                .queue(dir.clone())
                .signer(signer_b)
                .transport(tb.clone() as Arc<dyn Transport>)
                .reticulum_transport(tb)
                .config(cfg())
                .build()
                .expect("build edge B"),
        );
        std::mem::forget(tmp);

        let (_sub_id, mut rx) = edge_b.register_opaque_subscriber(0x0000_0001);
        let rt_a = edge_runtime("opaque-rt-a-243");
        let rt_b = edge_runtime("opaque-rt-b-243");
        let _hb = edge_b.spawn_background_listeners(rt_b.handle());

        // SENDER exactly as `init_edge_runtime` now wires it: listeners
        // AND the outbound dispatcher, on the edge-side runtime. `_sd_tx`
        // is held for the test's duration (busy-loop guard, per the
        // `spawn_outbound_dispatcher` contract).
        let _ha = edge_a.spawn_background_listeners(rt_a.handle());
        let (_sd_tx, sd_rx) = watch::channel(false);
        let _hd = edge_a.spawn_outbound_dispatcher(rt_a.handle(), &sd_rx);

        edge_a
            .send_opaque_event(&b.key_id, 0x0000_0001, b"event-bytes".to_vec())
            .await
            .expect("enqueue opaque event");

        let (_sender, kind, payload) = tokio::time::timeout(Duration::from_secs(45), rx.recv())
            .await
            .expect("durable event delivered under spawn_background_dispatcher posture")
            .expect("subscriber channel delivered a payload");
        assert_eq!(kind, 0x0000_0001);
        assert_eq!(payload, b"event-bytes");

        std::mem::forget(rt_a);
        std::mem::forget(rt_b);
    }
}
