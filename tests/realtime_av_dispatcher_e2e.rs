//! E2E acceptance for the Layer-2 A/V wire dispatcher (CIRISEdge#155).
//!
//! In-memory mpsc channels stand in for the caller's Reticulum Links —
//! the dispatcher talks to them through the
//! [`AvLinkSender`] / [`AvLinkReceiver`] traits, exactly as a fabric
//! node would over a real transport. The tests prove the full
//! publisher → (relay) → subscriber wire path round-trips plaintext
//! byte-identically and that the relay never sees the epoch DEK.

use tokio::sync::{mpsc, Mutex};

use ciris_edge::transport::realtime_av::{
    seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, SealedAvChunk, StreamId, CODEC_OPAQUE,
};
use ciris_edge::transport::realtime_av_dispatcher::{
    AvDispatcher, AvDispatcherConfig, AvDispatcherError, AvInboundLink, AvLinkReceiver,
    AvLinkSender, AvRole, AvSubscriberLink,
};

// ─── in-memory transport stubs ──────────────────────────────────────

/// mpsc-backed outbound link.
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

/// mpsc-backed inbound link.
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

/// Inbound link that yields one malformed frame before each good frame —
/// drives the subscriber loop's per-frame skip resilience.
struct OneBadThenGood {
    inner: MpscReceiver,
    emitted_bad: Mutex<bool>,
}

#[async_trait::async_trait]
impl AvLinkReceiver for OneBadThenGood {
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
        {
            let mut g = self.emitted_bad.lock().await;
            if !*g {
                *g = true;
                return Ok(vec![0u8; 4]); // < CHUNK_HEADER_LEN → from_bytes errors → skipped
            }
        }
        self.inner.recv().await
    }
}

// ─── helpers ────────────────────────────────────────────────────────

fn stream(seed: u8) -> StreamId {
    StreamId([seed; 32])
}

fn transit_key(idx: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = idx
            .wrapping_add(u8::try_from(i % 256).unwrap())
            .wrapping_mul(13)
            .wrapping_add(7);
    }
    k
}

fn dek_bytes() -> [u8; 32] {
    [0x77u8; 32]
}

fn inner_for(
    stream_id: StreamId,
    chunk_seq: u64,
    plaintext: &[u8],
) -> ciris_edge::transport::realtime_av::InnerSealed {
    let dek = EpochDek::from_bytes(dek_bytes());
    seal_av_inner(
        plaintext,
        &dek,
        stream_id,
        Epoch(1),
        ChunkSeq(chunk_seq),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("inner seal")
}

/// An outbound subscriber link + a matching inbound link sharing the
/// same transit key + link_id, so a publisher's send feeds straight
/// into a subscriber loop.
fn linked_pair(sub: &str, transit: [u8; 32]) -> (AvSubscriberLink, AvInboundLink) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    let link_id = sub.as_bytes().to_vec();
    (
        AvSubscriberLink {
            subscriber: sub.to_string(),
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

/// A bare outbound link whose sent bytes are captured on a channel the
/// caller drains directly (used for the relay→relay hop where the
/// downstream consumer is another dispatcher fed manually).
fn capture_link(sub: &str, transit: [u8; 32]) -> (AvSubscriberLink, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    (
        AvSubscriberLink {
            subscriber: sub.to_string(),
            transit_key: transit,
            link_id: sub.as_bytes().to_vec(),
            outbound_send: Box::new(MpscSender { tx }),
        },
        rx,
    )
}

// ─── tests ──────────────────────────────────────────────────────────

/// Single hop: publisher inner-seals, dispatcher outer-seals + sends,
/// subscriber loop opens both layers. Plaintext is byte-identical.
#[tokio::test]
async fn publisher_to_subscriber_via_dispatcher() {
    let s = stream(0xA1);
    let key = transit_key(1);
    let (out, inb) = linked_pair("sub-0", key);

    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Publisher,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![out],
        inbound_links: vec![],
    })
    .expect("publisher ctor");

    let mut subscriber = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Subscriber,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![],
        inbound_links: vec![inb],
    })
    .expect("subscriber ctor");

    let mut rx = subscriber.spawn_subscriber_loop();

    let plaintext = b"realtime av frame body";
    publisher
        .publish_inner(inner_for(s, 0, plaintext))
        .await
        .expect("publish");

    let chunk = rx.recv().await.expect("recv reconstructed");
    assert_eq!(chunk.plaintext, plaintext);
    assert_eq!(chunk.stream_id, s);
    assert_eq!(chunk.chunk_seq, ChunkSeq(0));
}

/// Three chained dispatchers: publisher → relay → subscriber. The relay
/// holds NO epoch DEK; the inner ciphertext is preserved byte-identical
/// across the relay hop and the subscriber recovers the original
/// plaintext.
#[tokio::test]
async fn publisher_relay_subscriber_via_dispatchers() {
    let s = stream(0xB2);
    // publisher→relay link (upstream transit key)
    let up_key = transit_key(2);
    // relay→subscriber link (downstream transit key — independent)
    let down_key = transit_key(9);

    // Publisher fans out to the relay. We capture the publisher→relay
    // wire bytes directly so we can hand them to the relay's
    // relay_chunk (modelling the relay's inbound link).
    let (pub_out, mut pub_to_relay_rx) = capture_link("relay", up_key);
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Publisher,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![pub_out],
        inbound_links: vec![],
    })
    .expect("publisher ctor");

    // Relay: no DEK. Downstream link feeds the subscriber loop.
    let (relay_out, sub_inb) = linked_pair("sub-0", down_key);
    let mut relay = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Relay,
        epoch_dek: None,
        initial_subscribers: vec![relay_out],
        inbound_links: vec![],
    })
    .expect("relay ctor");
    assert_eq!(relay.role(), AvRole::Relay);

    let mut subscriber = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Subscriber,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![],
        inbound_links: vec![sub_inb],
    })
    .expect("subscriber ctor");
    let mut rx = subscriber.spawn_subscriber_loop();

    let plaintext = b"three-hop frame";
    // 1. Publisher seals + sends to the relay's inbound (link_seq 0 on
    //    the publisher→relay link; link_id is the relay's key_id bytes).
    publisher
        .publish_inner(inner_for(s, 0, plaintext))
        .await
        .expect("publish");
    let upstream_bytes = pub_to_relay_rx.recv().await.expect("pub→relay bytes");
    let sealed_upstream = SealedAvChunk::from_bytes(&upstream_bytes).expect("decode upstream");

    // 2. Relay opens the inbound outer AEAD (up_key, link_id = "relay",
    //    link_seq 0) and re-seals per downstream subscriber.
    relay
        .relay_chunk(sealed_upstream, &up_key, b"relay", 0)
        .await
        .expect("relay forward");

    // 3. Subscriber recovers plaintext.
    let chunk = rx.recv().await.expect("recv reconstructed");
    assert_eq!(chunk.plaintext, plaintext);
}

/// Roster mutation mid-stream: start with 2 subs, add a 3rd, drop the
/// 1st. The new sub receives the subsequent chunk; the dropped sub does
/// not.
#[tokio::test]
async fn add_remove_subscriber_mid_stream() {
    let s = stream(0xC3);

    let (out0, inb0) = linked_pair("sub-0", transit_key(10));
    let (out1, inb1) = linked_pair("sub-1", transit_key(11));

    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Publisher,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![out0, out1],
        inbound_links: vec![],
    })
    .expect("publisher ctor");
    assert_eq!(publisher.subscriber_count(), 2);

    // Subscriber loops for the three receivers.
    let mut sub0 = subscriber_for(s, inb0);
    let mut sub1 = subscriber_for(s, inb1);

    // Chunk #0: subs 0 + 1 only.
    publisher
        .publish_inner(inner_for(s, 0, b"chunk-0"))
        .await
        .expect("publish 0");
    assert_eq!(sub0.recv().await.expect("sub0 c0").plaintext, b"chunk-0");
    assert_eq!(sub1.recv().await.expect("sub1 c0").plaintext, b"chunk-0");

    // Add sub-2, drop sub-0.
    let (out2, inb2) = linked_pair("sub-2", transit_key(12));
    publisher.add_subscriber(out2).expect("add sub-2");
    publisher.remove_subscriber(&"sub-0".to_string());
    assert_eq!(publisher.subscriber_count(), 2); // sub-1 + sub-2
    let mut sub2 = subscriber_for(s, inb2);

    // Chunk #1: subs 1 + 2. sub-0's link should receive nothing more.
    publisher
        .publish_inner(inner_for(s, 1, b"chunk-1"))
        .await
        .expect("publish 1");

    // sub-2 (new) gets it. sub-2's link_seq starts at 0 — its first
    // (and only) received chunk opens at link_seq 0.
    assert_eq!(sub2.recv().await.expect("sub2 c1").plaintext, b"chunk-1");
    // sub-1 keeps receiving; this is its 2nd chunk → link_seq 1.
    assert_eq!(sub1.recv().await.expect("sub1 c1").plaintext, b"chunk-1");

    // sub-0 was dropped → no further frames. The publisher closed sub-0's
    // sender by dropping its OutboundState, so the loop's recv returns
    // an error and the task exits; the channel yields None.
    assert!(
        sub0.recv().await.is_none(),
        "dropped sub must get no more chunks"
    );
}

/// Relay opening the inbound outer AEAD with the WRONG transit key
/// returns an OpenFailed error — the relay cannot forward what it cannot
/// authenticate.
#[tokio::test]
async fn relay_open_outer_with_wrong_transit_key_returns_error() {
    let s = stream(0xD4);
    let right_key = transit_key(20);
    let wrong_key = transit_key(21);

    // Build a real upstream sealed chunk under right_key, link_id="relay".
    let (pub_out, mut pub_rx) = capture_link("relay", right_key);
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Publisher,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![pub_out],
        inbound_links: vec![],
    })
    .expect("publisher ctor");
    publisher
        .publish_inner(inner_for(s, 0, b"payload"))
        .await
        .expect("publish");
    let bytes = pub_rx.recv().await.expect("bytes");
    let sealed = SealedAvChunk::from_bytes(&bytes).expect("decode");

    let (relay_out, _sub_inb) = linked_pair("sub-0", transit_key(22));
    let mut relay = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Relay,
        epoch_dek: None,
        initial_subscribers: vec![relay_out],
        inbound_links: vec![],
    })
    .expect("relay ctor");

    // Wrong inbound transit key → outer open fails.
    let r = relay.relay_chunk(sealed, &wrong_key, b"relay", 0).await;
    assert!(matches!(r, Err(AvDispatcherError::OpenFailed(_))));
}

/// The subscriber loop skips a malformed inbound frame and still
/// surfaces the subsequent good chunk — per-frame resilience.
#[tokio::test]
async fn subscriber_loop_recovers_from_link_recv_error() {
    let s = stream(0xE5);
    let key = transit_key(30);

    // Outbound side feeds an mpsc; the subscriber's inbound link is a
    // OneBadThenGood wrapper over that mpsc's receiver.
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    let out = AvSubscriberLink {
        subscriber: "sub-0".to_string(),
        transit_key: key,
        link_id: b"sub-0".to_vec(),
        outbound_send: Box::new(MpscSender { tx }),
    };
    let inb = AvInboundLink {
        transit_key: key,
        link_id: b"sub-0".to_vec(),
        inbound_recv: Box::new(OneBadThenGood {
            inner: MpscReceiver { rx: Mutex::new(rx) },
            emitted_bad: Mutex::new(false),
        }),
    };

    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Publisher,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![out],
        inbound_links: vec![],
    })
    .expect("publisher ctor");

    let mut subscriber = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Subscriber,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![],
        inbound_links: vec![inb],
    })
    .expect("subscriber ctor");
    let mut out_rx = subscriber.spawn_subscriber_loop();

    // Publisher sends one good chunk. The loop first pulls the injected
    // malformed frame (skipped), then the good one.
    publisher
        .publish_inner(inner_for(s, 0, b"survives"))
        .await
        .expect("publish");

    let chunk = out_rx.recv().await.expect("recv after skip");
    assert_eq!(chunk.plaintext, b"survives");
}

// ─── local helper that needs the test-only types ───────────────────

/// Spin up a subscriber-role dispatcher over one inbound link and start
/// its receive loop.
fn subscriber_for(
    s: StreamId,
    inb: AvInboundLink,
) -> mpsc::Receiver<ciris_edge::transport::realtime_av_dispatcher::ReconstructedChunk> {
    let mut sub = AvDispatcher::new(AvDispatcherConfig {
        stream_id: s,
        local_role: AvRole::Subscriber,
        epoch_dek: Some(dek_bytes()),
        initial_subscribers: vec![],
        inbound_links: vec![inb],
    })
    .expect("subscriber ctor");
    sub.spawn_subscriber_loop()
}
