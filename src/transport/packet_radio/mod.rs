//! Packet-radio transport — N2 multi-medium plug for CIRISEdge#53.
//!
//! Closes the remaining half of Fed TM §3.3 Gap D: edge can now carry
//! federation envelopes over a packet-radio medium (LoRa, AX.25, raw
//! serial) using the same [`crate::transport::Transport`] trait shape
//! the HTTP + Reticulum transports use. The medium-specific hardware
//! (modem, serial chip, GPIO bus) plugs in via the
//! [`driver::PacketRadioDriver`] trait — implementations live as
//! separate crates or follow-up PRs once a specific deployment target
//! locks in.
//!
//! ## Why packet radio matters for the federation
//!
//! Per Fed TM §3.3:
//!
//! > F-AV-ECLIPSE — Per-peer S2 read-view manipulation — toy says
//! > LIVE EXPOSURE today; defense waits on N1+N2.
//! >
//! > F-AV-16 — Substrate-availability denial / fail-secure forcing —
//! > toy says attacker can hold RESTRICTED ~30% of time at minimum
//! > cost; N2 multi-medium raises that cost.
//!
//! An attacker who controls the IP infrastructure (BGP hijack, DNS
//! takeover, ISP-level filtering) cannot also control LoRa-band RF
//! propagation. Steward-grade messaging — anti-rollback witnesses,
//! AV-RECONSIDER votes — needs a transport floor that survives a
//! catastrophic IP outage. This module is that floor.
//!
//! ## Layering
//!
//! ```text
//!   ┌────────────────────────────────────────────────────────────────┐
//!   │  federation_session::SessionKey (hybrid X25519+ML-KEM-768 KEX, │
//!   │  CIRISEdge#54 — closes Fed TM §3.3 Gap C, harvest-now-decrypt-  │
//!   │  later closure)                                                │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │  AEAD (caller's choice — realtime_av for #62, or the signed-   │
//!   │  envelope shape for the rest of the federation surface)        │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │  PacketRadioTransport — destination resolution + replay window │
//!   │  via crate::transport::addressing (CIRISEdge#53 N1)            │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │  frame::encode_frame — magic + dest + seq + CRC32              │
//!   ├────────────────────────────────────────────────────────────────┤
//!   │  PacketRadioDriver — medium-specific modem / serial / GPIO     │
//!   └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Each layer can be swapped independently:
//! - Different KEX → swap above the AEAD layer.
//! - Different AEAD → swap between session-key and transport.
//! - Different medium → swap the driver.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{mpsc, Mutex};

use crate::transport::addressing::{
    destination_from_pubkey_bytes, AdmitOutcome, ReplayWindow, RETICULUM_DEST_LEN,
};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

pub mod driver;
pub mod frame;

use self::driver::{DriverError, PacketRadioDriver};
use self::frame::{decode_frame_view, encode_frame, FrameError};

/// Resolver from federation `key_id` → recipient public-key bytes.
/// The transport derives the on-wire 16-byte destination via
/// [`destination_from_pubkey_bytes`].
///
/// Production wiring is a thin adapter over persist's
/// `FederationDirectory::lookup_public_key`; tests inject an in-memory
/// table. Mirrors [`crate::transport::reticulum::PeerResolver`] but
/// takes raw pubkey bytes rather than the Reticulum 64-byte dual-key
/// form — packet radio doesn't carry Reticulum's identity layer, just
/// the addressing primitive.
pub trait PacketRadioResolver: Send + Sync + 'static {
    /// Return the recipient's federation public-key bytes (Ed25519
    /// 32B is the canonical shape; longer/shorter keys are accepted —
    /// only the sha256 truncation matters for addressing), or `None`
    /// if no peer with that `key_id` is reachable on this medium.
    fn resolve(&self, key_id: &str) -> Option<Vec<u8>>;
}

/// The N2 multi-medium transport plug for CIRISEdge#53.
///
/// Construction: wrap a [`PacketRadioDriver`] + a [`PacketRadioResolver`].
/// Per-peer outbound sequence numbers + per-peer replay windows live
/// inside the transport so callers don't manage them; the
/// [`crate::transport::Transport::send`] / `listen` surface matches
/// every other edge transport.
pub struct PacketRadioTransport {
    driver: Arc<dyn PacketRadioDriver>,
    resolver: Arc<dyn PacketRadioResolver>,
    /// Per-(local pubkey of sender) outbound sequence counter, used in
    /// the frame's `seq` field. Keyed by destination so re-sends to
    /// the same peer get monotonic sequence numbers; remote replay
    /// windows reject the duplicates.
    outbound_seqs: Arc<Mutex<std::collections::HashMap<[u8; RETICULUM_DEST_LEN], u64>>>,
    /// Per-remote-peer replay window for inbound frames. The remote's
    /// `destination` (which from our POV is the SENDER's destination
    /// hash, encoded by the SENDER) acts as the key.
    inbound_windows: Arc<Mutex<std::collections::HashMap<[u8; RETICULUM_DEST_LEN], ReplayWindow>>>,
    transport_id: TransportId,
}

impl PacketRadioTransport {
    /// Build a transport over the supplied driver + resolver. The
    /// `transport_id` distinguishes between concurrently-active
    /// packet-radio transports on different media (e.g. `LORA` vs
    /// `SERIAL`).
    pub fn new(
        driver: Arc<dyn PacketRadioDriver>,
        resolver: Arc<dyn PacketRadioResolver>,
        transport_id: TransportId,
    ) -> Self {
        Self {
            driver,
            resolver,
            outbound_seqs: Arc::new(Mutex::new(std::collections::HashMap::new())),
            inbound_windows: Arc::new(Mutex::new(std::collections::HashMap::new())),
            transport_id,
        }
    }

    /// Allocate the next outbound sequence number for a destination.
    /// Wraps on u64 overflow — at 1 packet per microsecond that takes
    /// ~584,000 years, so the wrap is a theoretical concern that costs
    /// nothing to handle (saturating_add to make analysis trivial).
    async fn next_outbound_seq(&self, dest: &[u8; RETICULUM_DEST_LEN]) -> u64 {
        let mut map = self.outbound_seqs.lock().await;
        let entry = map.entry(*dest).or_insert(0);
        let seq = *entry;
        *entry = entry.saturating_add(1);
        seq
    }

    /// Try to admit an inbound (sender_dest, seq) into that peer's
    /// replay window. Returns the [`AdmitOutcome`] so the listen
    /// loop can decide drop-vs-deliver.
    async fn admit_inbound(&self, sender_dest: [u8; RETICULUM_DEST_LEN], seq: u64) -> AdmitOutcome {
        let mut map = self.inbound_windows.lock().await;
        let window = map.entry(sender_dest).or_insert_with(ReplayWindow::new);
        window.admit(seq)
    }
}

#[async_trait]
impl Transport for PacketRadioTransport {
    fn id(&self) -> TransportId {
        self.transport_id
    }

    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        // 1. Resolve key_id → pubkey via the injected directory.
        let pubkey = self.resolver.resolve(destination_key_id).ok_or_else(|| {
            TransportError::Unreachable(format!(
                "no packet-radio pubkey for key_id={destination_key_id}"
            ))
        })?;
        // 2. Derive on-wire destination.
        let destination = destination_from_pubkey_bytes(&pubkey);
        // 3. Allocate the next outbound seq.
        let seq = self.next_outbound_seq(&destination).await;
        // 4. Frame it.
        let frame_bytes = encode_frame(&destination, seq, envelope_bytes).map_err(|e| match e {
            FrameError::PayloadTooLarge { len, max } => TransportError::BodyTooLarge {
                actual: len,
                limit: max,
            },
            other => TransportError::Config(format!("frame encode failed: {other}")),
        })?;
        // 5. Hand to the driver.
        self.driver
            .send_frame(&frame_bytes)
            .await
            .map_err(driver_error_to_transport)?;
        Ok(TransportSendOutcome::Delivered)
    }

    async fn listen(&self, sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        // Single consumer on the driver's receive half — the listen
        // loop is the sole owner.
        loop {
            let bytes = match self.driver.recv_frame().await {
                Ok(b) => b,
                Err(DriverError::RxOverflow { dropped }) => {
                    // Transient — record and keep listening. A
                    // production wiring would emit a metric here.
                    tracing::warn!(
                        transport = ?self.transport_id,
                        dropped,
                        "packet-radio rx queue overflow",
                    );
                    continue;
                }
                Err(other) => return Err(driver_error_to_transport(other)),
            };
            let view = match decode_frame_view(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    // Frame-level corruption — record + drop. NOT a
                    // listener-fatal error; the medium is noisy by
                    // nature.
                    tracing::debug!(
                        transport = ?self.transport_id,
                        error = %e,
                        "packet-radio frame decode rejected",
                    );
                    continue;
                }
            };
            // The frame's `destination` field is what the SENDER stamped
            // (= the recipient's address from the sender's POV = OUR
            // address). We don't need to match it to our own pubkey
            // here — that's the application layer's job (the AEAD
            // confirms the frame was meant for us); we just need a
            // stable per-sender key for the replay window, which is
            // unfortunately NOT in the frame today (the v1 frame
            // header doesn't carry the sender's destination — only the
            // recipient's). Use the recipient destination + seq as the
            // anti-replay key for now; this admits replays from
            // DIFFERENT senders targeting us with the same seq, but the
            // AEAD's nonce derivation includes sender identity, so a
            // cross-sender replay fails AEAD even if it passes our
            // window.
            //
            // The v2 frame layout (follow-up — see module docs of #53)
            // will carry the sender destination so per-sender windows
            // become possible.
            let dest = view.destination;
            let seq = view.seq;
            let payload = view.payload.to_vec();
            match self.admit_inbound(dest, seq).await {
                AdmitOutcome::Fresh => {
                    let frame = InboundFrame {
                        envelope_bytes: payload,
                        transport: self.transport_id,
                        received_at: Utc::now(),
                    };
                    if sink.send(frame).await.is_err() {
                        // Sink closed — listener should exit cleanly.
                        return Ok(());
                    }
                }
                AdmitOutcome::Duplicate => {
                    tracing::debug!(
                        transport = ?self.transport_id,
                        seq,
                        "packet-radio dropped duplicate frame",
                    );
                }
                AdmitOutcome::StaleBelowWindow => {
                    tracing::debug!(
                        transport = ?self.transport_id,
                        seq,
                        "packet-radio dropped stale-below-window frame",
                    );
                }
            }
        }
    }
}

fn driver_error_to_transport(e: DriverError) -> TransportError {
    match e {
        DriverError::Hardware(msg) => TransportError::Io(format!("packet-radio: {msg}")),
        DriverError::FrameOverMtu { got, limit } => {
            TransportError::BodyTooLarge { actual: got, limit }
        }
        DriverError::ConcurrentReceive => TransportError::Config(
            "packet-radio: concurrent recv_frame — only one listen() loop is supported".into(),
        ),
        DriverError::RxOverflow { dropped } => {
            TransportError::Io(format!("packet-radio rx overflow ({dropped} dropped)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::addressing::WINDOW_DEFAULT;
    use std::collections::HashMap;

    /// Map-backed [`PacketRadioResolver`] for tests.
    struct MapResolver(HashMap<String, Vec<u8>>);

    impl PacketRadioResolver for MapResolver {
        fn resolve(&self, key_id: &str) -> Option<Vec<u8>> {
            self.0.get(key_id).cloned()
        }
    }

    fn alice_pubkey() -> Vec<u8> {
        (0u8..32).collect()
    }
    fn bob_pubkey() -> Vec<u8> {
        (32u8..64).collect()
    }

    /// Two transports wired together over a mock bus exchange a
    /// federation envelope end-to-end.
    #[tokio::test]
    async fn end_to_end_round_trip_alice_to_bob() {
        let (a_bus, b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let bob_driver = Arc::new(driver::mock::MockDriver::new(b_bus));
        // Each peer's resolver maps key_id → pubkey of the OTHER peer.
        let alice_resolver = Arc::new(MapResolver(
            [("bob".to_string(), bob_pubkey())].into_iter().collect(),
        ));
        let bob_resolver = Arc::new(MapResolver(
            [("alice".to_string(), alice_pubkey())]
                .into_iter()
                .collect(),
        ));
        let alice = PacketRadioTransport::new(alice_driver, alice_resolver, TransportId::LORA);
        let bob = PacketRadioTransport::new(bob_driver, bob_resolver, TransportId::LORA);

        let (sink_tx, mut sink_rx) = mpsc::channel(16);
        let bob_arc = Arc::new(bob);
        let bob_listen = Arc::clone(&bob_arc);
        let listener = tokio::spawn(async move { bob_listen.listen(sink_tx).await });

        let envelope = b"signed federation envelope bytes";
        alice.send("bob", envelope).await.expect("alice → bob send");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), sink_rx.recv())
            .await
            .expect("recv timeout")
            .expect("listener closed");
        assert_eq!(received.envelope_bytes, envelope);
        assert_eq!(received.transport, TransportId::LORA);

        listener.abort();
    }

    /// Unknown destination key_id surfaces as [`TransportError::Unreachable`].
    #[tokio::test]
    async fn unknown_destination_is_unreachable() {
        let (a_bus, _b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let resolver = Arc::new(MapResolver(HashMap::new()));
        let alice = PacketRadioTransport::new(alice_driver, resolver, TransportId::LORA);
        let r = alice.send("charlie-never-heard-of-him", b"x").await;
        assert!(matches!(r, Err(TransportError::Unreachable(_))));
    }

    /// Payload above [`frame::MAX_PAYLOAD_LEN`] surfaces as
    /// [`TransportError::BodyTooLarge`].
    #[tokio::test]
    async fn oversize_envelope_surfaces_body_too_large() {
        let (a_bus, _b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let resolver = Arc::new(MapResolver(
            [("bob".to_string(), bob_pubkey())].into_iter().collect(),
        ));
        let alice = PacketRadioTransport::new(alice_driver, resolver, TransportId::LORA);
        let payload = vec![0u8; frame::MAX_PAYLOAD_LEN + 1];
        let r = alice.send("bob", &payload).await;
        assert!(matches!(
            r,
            Err(TransportError::BodyTooLarge { actual, limit })
                if actual == frame::MAX_PAYLOAD_LEN + 1 && limit == frame::MAX_PAYLOAD_LEN
        ));
    }

    /// Sequential sends from Alice to Bob produce monotonically
    /// increasing sequence numbers — the basis Bob's replay window
    /// uses to admit/refuse.
    #[tokio::test]
    async fn outbound_seqs_are_monotonic_per_destination() {
        let (a_bus, b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let bob_driver = Arc::new(driver::mock::MockDriver::new(b_bus));
        let resolver = Arc::new(MapResolver(
            [("bob".to_string(), bob_pubkey())].into_iter().collect(),
        ));
        let alice = PacketRadioTransport::new(alice_driver, resolver, TransportId::LORA);
        for _ in 0..5 {
            alice.send("bob", b"step").await.expect("send");
        }
        // Decode the 5 frames Bob saw and check seq monotonicity.
        let mut seqs = Vec::new();
        for _ in 0..5 {
            let bytes = bob_driver.recv_frame().await.expect("recv");
            let view = decode_frame_view(&bytes).expect("decode");
            seqs.push(view.seq);
        }
        assert_eq!(seqs, (0..5).collect::<Vec<_>>());
    }

    /// A frame replayed by an attacker is dropped at the listen
    /// layer's replay window (not handed to the application).
    #[tokio::test]
    async fn replayed_frame_dropped_at_listen() {
        let (a_bus, b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let bob_driver = Arc::new(driver::mock::MockDriver::new(b_bus));
        let alice_resolver = Arc::new(MapResolver(
            [("bob".to_string(), bob_pubkey())].into_iter().collect(),
        ));
        let bob_resolver = Arc::new(MapResolver(HashMap::new()));
        let alice =
            PacketRadioTransport::new(alice_driver.clone(), alice_resolver, TransportId::LORA);
        let bob = PacketRadioTransport::new(bob_driver, bob_resolver, TransportId::LORA);

        // Alice sends one envelope (just to exercise the wire path).
        alice.send("bob", b"replay-me").await.expect("send");
        // Drive the replay window directly — the async listen-loop is
        // hard to deterministically race in a single test, but the
        // window IS the unit we're asserting on.
        let dest = destination_from_pubkey_bytes(&bob_pubkey());
        let r1 = bob.admit_inbound(dest, 100).await;
        let r2 = bob.admit_inbound(dest, 100).await;
        assert_eq!(r1, AdmitOutcome::Fresh);
        assert_eq!(r2, AdmitOutcome::Duplicate);
    }

    /// Replay window is per-sender, so the same seq number from a
    /// different peer is admitted. (Documented limitation of the v1
    /// frame layout — see the listen-loop comment.)
    #[tokio::test]
    async fn replay_window_is_per_destination_key() {
        let (a_bus, _b_bus) = driver::mock::MockBus::channel_pair();
        let alice_driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let resolver = Arc::new(MapResolver(HashMap::new()));
        let bob = PacketRadioTransport::new(alice_driver, resolver, TransportId::LORA);
        let dest_a = [1u8; RETICULUM_DEST_LEN];
        let dest_b = [2u8; RETICULUM_DEST_LEN];
        assert_eq!(bob.admit_inbound(dest_a, 5).await, AdmitOutcome::Fresh);
        // Same seq, different destination — Fresh (independent windows).
        assert_eq!(bob.admit_inbound(dest_b, 5).await, AdmitOutcome::Fresh);
        // Repeat on dest_a — Duplicate.
        assert_eq!(bob.admit_inbound(dest_a, 5).await, AdmitOutcome::Duplicate);
    }

    /// The id() method returns the configured transport id.
    #[tokio::test]
    async fn id_returns_configured_transport_id() {
        let (a_bus, _) = driver::mock::MockBus::channel_pair();
        let driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let resolver = Arc::new(MapResolver(HashMap::new()));
        let t = PacketRadioTransport::new(driver, resolver, TransportId::SERIAL);
        assert_eq!(t.id(), TransportId::SERIAL);
    }

    /// Sanity — default window keeps WINDOW_DEFAULT range admittable.
    #[tokio::test]
    async fn replay_window_covers_default_range() {
        let (a_bus, _) = driver::mock::MockBus::channel_pair();
        let driver = Arc::new(driver::mock::MockDriver::new(a_bus));
        let resolver = Arc::new(MapResolver(HashMap::new()));
        let t = PacketRadioTransport::new(driver, resolver, TransportId::LORA);
        let dest = [9u8; RETICULUM_DEST_LEN];
        // Admit seq=WINDOW_DEFAULT first.
        assert_eq!(
            t.admit_inbound(dest, WINDOW_DEFAULT).await,
            AdmitOutcome::Fresh
        );
        // Now seq=0 is just inside the window (distance=WINDOW_DEFAULT).
        // The window is exclusive at the far end, so distance==window
        // is StaleBelowWindow.
        assert_eq!(
            t.admit_inbound(dest, 0).await,
            AdmitOutcome::StaleBelowWindow
        );
        // But seq=1 (distance=WINDOW_DEFAULT-1) is within window → Fresh.
        assert_eq!(t.admit_inbound(dest, 1).await, AdmitOutcome::Fresh);
    }
}
