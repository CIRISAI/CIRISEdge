//! End-to-end acceptance for the realtime A/V mesh integrating runtime —
//! "the spine" (CIRISEdge#155, Gap 3).
//!
//! Runs ONE stream glass-to-glass through the full role stack:
//!
//! ```text
//!   AvPublisher ──(pub→relay link)──► AvRelay::spawn_pump ──(relay→sub link)──► AvSubscriber
//!        │  MLS epoch DEK                  no DEK (ciphertext-only)                 MLS epoch DEK
//!        └── seal_av_inner                 open outer + re-seal per sub            open both AEAD layers
//! ```
//!
//! What is REAL here:
//! - **MLS keys** — the publisher derives the epoch DEK from a live
//!   openmls (X-Wing 0x004D) group; the subscriber derives the SAME 32
//!   bytes by processing the Welcome the publisher's `admit_joiner` emits
//!   (RFC 9420 §8.5 epoch-deterministic exporter). No shared-secret
//!   shortcut.
//! - **The whole Layer-2 wire path** — publisher outer-seal → relay
//!   outer-open + re-seal → subscriber double-open, exactly as
//!   `AvDispatcher` drives it.
//! - **ALM parent selection** — `AvSubscriber::plan_parent` runs the real
//!   `AlmJoinPlanner` over a signed-capacity pool and the chosen parent
//!   is what the subscriber wires its inbound link to.
//!
//! What is the TRAIT SEAM (not real RNS) here:
//! - The links are in-memory `mpsc` channels implementing the dispatcher's
//!   `AvLinkSender` / `AvLinkReceiver` seam — the same seam the real-RNS
//!   `LeviculumAvSender` / `LinkDataPump` implement. Standing up two live
//!   leviculum nodes with an established RNS link is deferred (stretch);
//!   this test proves the spine byte-path over the transport-blind seam.

use tokio::sync::{mpsc, Mutex};

use ciris_edge::transport::federation_session::PeerKexPubkeys;
use ciris_edge::transport::realtime_av::Epoch;
use ciris_edge::transport::realtime_av::{ReceiverLayerPolicy, StreamId};
use ciris_edge::transport::realtime_av_alm::{ParentCandidate, RelayCapacity, SignedRelayCapacity};
use ciris_edge::transport::realtime_av_dispatcher::{
    AvDispatcherError, AvInboundLink, AvLinkReceiver, AvLinkSender, AvSubscriberLink,
};
use ciris_edge::transport::realtime_av_mls::{mint_joiner_key_material, Member};
use ciris_edge::transport::realtime_av_runtime::{AvPublisher, AvRelay, AvSubscriber};
use ciris_edge::transport::realtime_av_session::AvSession;

// ─── in-memory transport stubs (the dispatcher's trait seam) ────────

struct MpscSender {
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl AvLinkSender for MpscSender {
    async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
        self.tx
            .send(bytes.to_vec())
            .await
            .map_err(|e| AvDispatcherError::SendFailed(e.to_string()))
    }
}

struct MpscReceiver {
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

#[async_trait::async_trait]
impl AvLinkReceiver for MpscReceiver {
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| AvDispatcherError::RecvFailed("closed".into()))
    }
}

// ─── helpers ────────────────────────────────────────────────────────

fn stream(seed: u8) -> StreamId {
    StreamId([seed; 32])
}

fn hybrid_member(key_id: &str) -> Member {
    Member {
        key_id: key_id.to_string(),
        kex_pubkeys: PeerKexPubkeys {
            x25519_pub: [1u8; 32],
            mlkem768_pub: Some(vec![0xAB; 1184]),
        },
    }
}

/// An outbound subscriber link + a matching inbound link sharing the
/// same transit key + link_id, so one hop's send feeds straight into the
/// next hop's receive. `link_id` is the downstream peer's key_id bytes —
/// the substrate-wide outer-nonce convention.
fn linked_pair(peer: &str, transit: [u8; 32]) -> (AvSubscriberLink, AvInboundLink) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    let link_id = peer.as_bytes().to_vec();
    (
        AvSubscriberLink {
            subscriber: peer.to_string(),
            transit_key: transit,
            link_id: link_id.clone(),
            outbound_send: Box::new(MpscSender { tx }),
        },
        AvInboundLink {
            transit_key: transit,
            link_id,
            inbound_recv: Box::new(MpscReceiver { rx: Mutex::new(rx) }),
        },
    )
}

/// Build a verified-shaped `ParentCandidate` for the ALM planner. ALM-B
/// is signature-blind, so the signature fields are placeholders.
fn candidate(peer: &str, uplink_mbps: f32, measured_at_ms: u64) -> ParentCandidate {
    let capacity = RelayCapacity::new(
        uplink_mbps,
        4,
        16,
        ReceiverLayerPolicy::UNCAPPED,
        measured_at_ms,
    );
    ParentCandidate {
        signed_capacity: SignedRelayCapacity {
            advertiser_key_id: peer.to_string(),
            capacity,
            stream_id: stream(0xAB),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        },
        reachability_ratio: Some(0.95),
        rtt_ms_estimate: Some(50),
    }
}

// ─── the spine acceptance test ──────────────────────────────────────

/// Publisher → relay → subscriber, one parent, MLS-keyed both ends, ALM
/// selecting the relay as parent. Asserts a chunk arrives at the
/// subscriber byte-intact (glass-to-glass) and that the relay never
/// needed the epoch DEK.
#[tokio::test]
async fn spine_publisher_relay_subscriber_glass_to_glass() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();

    let s = stream(0xA1);
    let relay_key_id = "relay-sfu";
    let sub_key_id = "sub-carol";

    // ── MLS: publisher creates the group; the subscriber joins and
    //    derives the SAME epoch DEK from the Welcome. ──────────────────
    let (mut publisher_session, _dek0) =
        AvSession::create(s, "publisher", vec![hybrid_member("seed")])
            .expect("publisher AvSession create");

    // The subscriber mints + "publishes" its KeyPackage (federation-
    // directory step, out of scope) and retains the private material.
    let (joiner_material, joiner_kp) =
        mint_joiner_key_material(sub_key_id).expect("mint joiner key material");

    // Publisher admits the joiner → Commit + Welcome + rotated DEK.
    let artifacts = publisher_session
        .admit_published_joiner(sub_key_id, joiner_kp)
        .expect("publisher admit joiner");
    assert_eq!(
        artifacts.welcome_bytes.len(),
        1,
        "one Welcome for the joiner"
    );
    let pub_dek =
        ciris_edge::transport::realtime_av::EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
    let pub_epoch = artifacts.new_epoch;

    // Subscriber bootstraps from the Welcome → derives its epoch DEK.
    let mut sub_session = AvSession::new_joiner(s, joiner_material);
    let sub_dek = sub_session
        .process_welcome(&artifacts.welcome_bytes[0])
        .expect("subscriber process_welcome");
    assert_eq!(
        sub_dek.as_bytes(),
        pub_dek.as_bytes(),
        "publisher + subscriber MUST derive the same epoch DEK"
    );

    // ── Wire topology (trait seam): publisher→relay, relay→subscriber ─
    let up_key = [0x11u8; 32]; // publisher→relay transit key
    let down_key = [0x22u8; 32]; // relay→subscriber transit key
    let (pub_to_relay_out, relay_inbound) = linked_pair(relay_key_id, up_key);
    let (relay_to_sub_out, sub_inbound) = linked_pair(sub_key_id, down_key);

    // ── Publisher role: from the post-join session at the new epoch,
    //    fanning out to the relay. ─────────────────────────────────────
    let mut publisher =
        AvPublisher::from_session(s, publisher_session, pub_dek, vec![pub_to_relay_out])
            .expect("build publisher");
    assert_eq!(publisher.epoch(), pub_epoch);
    assert_eq!(publisher.subscriber_count(), 1);

    // ── Relay role: forwards ciphertext-only to the subscriber. ───────
    let relay = AvRelay::new(s, vec![relay_to_sub_out]).expect("build relay");
    assert_eq!(relay.subscriber_count(), 1);
    let _relay_pump = relay.spawn_pump(relay_inbound, up_key, relay_key_id.as_bytes().to_vec());

    // ── ALM parent selection: the subscriber plans over a capacity pool
    //    and the relay is the chosen primary parent. ──────────────────
    let candidates = vec![
        candidate(relay_key_id, 100.0, 1_000),
        candidate("relay-far", 100.0, 1_000),
    ];
    let plan = AvSubscriber::plan_parent(&candidates, 2.5, ReceiverLayerPolicy::UNCAPPED, 5_000)
        .expect("ALM parent plan");
    assert_eq!(
        plan.primary_parent, relay_key_id,
        "lowest-RTT feasible parent (both equal → first) must be the relay we wired"
    );

    // ── Subscriber role: subscribe to the chosen parent, start delivery.
    let mut rx = AvSubscriber::subscribe(s, &sub_dek, &plan.primary_parent, sub_inbound)
        .expect("subscribe to parent");

    // ── Glass-to-glass: publish one opaque chunk; it must arrive intact.
    let frame = b"glass-to-glass realtime av frame body";
    let seq = publisher
        .publish_opaque(frame)
        .await
        .expect("publish chunk");

    let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
        .await
        .expect("timed out waiting for reconstructed chunk")
        .expect("subscriber channel closed before delivery");

    assert_eq!(chunk.plaintext, frame, "chunk must arrive byte-intact");
    assert_eq!(chunk.stream_id, s, "stream id must survive the mesh");
    assert_eq!(chunk.chunk_seq, seq, "chunk seq must survive the mesh");
    assert_eq!(chunk.epoch, pub_epoch, "epoch must survive the mesh");
}

/// A second chunk also round-trips — proves the per-link `link_seq`
/// counters at the relay and subscriber stay aligned across chunks (a
/// desync would fail the second open).
#[tokio::test]
async fn spine_two_chunks_keep_counters_aligned() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,ciris_edge=info")
        .try_init();

    let s = stream(0xB2);
    let relay_key_id = "relay-2";
    let sub_key_id = "sub-2";

    // Shortest MLS path: publisher session + joiner handshake for the DEK.
    let (mut publisher_session, _dek0) =
        AvSession::create(s, "publisher", vec![hybrid_member("seed")]).expect("create");
    let (joiner_material, joiner_kp) = mint_joiner_key_material(sub_key_id).expect("mint");
    let artifacts = publisher_session
        .admit_published_joiner(sub_key_id, joiner_kp)
        .expect("admit");
    let pub_dek =
        ciris_edge::transport::realtime_av::EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
    let mut sub_session = AvSession::new_joiner(s, joiner_material);
    let sub_dek = sub_session
        .process_welcome(&artifacts.welcome_bytes[0])
        .expect("welcome");

    let up_key = [0x33u8; 32];
    let down_key = [0x44u8; 32];
    let (pub_to_relay_out, relay_inbound) = linked_pair(relay_key_id, up_key);
    let (relay_to_sub_out, sub_inbound) = linked_pair(sub_key_id, down_key);

    let mut publisher =
        AvPublisher::from_session(s, publisher_session, pub_dek, vec![pub_to_relay_out])
            .expect("publisher");
    let relay = AvRelay::new(s, vec![relay_to_sub_out]).expect("relay");
    let _pump = relay.spawn_pump(relay_inbound, up_key, relay_key_id.as_bytes().to_vec());
    let mut rx = AvSubscriber::subscribe(s, &sub_dek, &sub_key_id.to_string(), sub_inbound)
        .expect("subscribe");

    for i in 0..2u8 {
        let body = format!("chunk-{i}");
        let seq = publisher
            .publish_opaque(body.as_bytes())
            .await
            .expect("publish");
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(chunk.plaintext, body.as_bytes(), "chunk {i} intact");
        assert_eq!(chunk.chunk_seq, seq);
    }
}
