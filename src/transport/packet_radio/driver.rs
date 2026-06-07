//! Medium-agnostic driver trait for the packet-radio transport.
//!
//! Packet radios divide into two operational shapes:
//!
//! - **Datagram-shape modems** (Semtech SX127x / SX126x LoRa, RAK4630,
//!   commodity 433/868/915 MHz LoRa modules). The modem delivers
//!   complete packets (max ~255 bytes payload, hardware CRC on the
//!   air-frame). The driver's `send_frame` / `recv_frame` map 1:1
//!   onto modem transactions.
//! - **Stream-shape modems** (AX.25 over serial KISS, half-duplex VHF
//!   data via PTT-keyed audio modems). The modem delivers a raw byte
//!   stream; the driver implementation adds COBS / SLIP / HDLC stuffing
//!   to recover frame boundaries before exposing the `send_frame` /
//!   `recv_frame` semantic.
//!
//! Either shape implements the same trait. The transport doesn't care
//! which medium is behind the driver.
//!
//! ## Concurrency / interior mutability
//!
//! Most radio modems serialize transmissions internally and present a
//! single TX queue. We model this with `&self` send (the driver
//! handles locking internally — typically a `Mutex<RawHardware>`),
//! letting [`crate::transport::Transport::send`] dispatch concurrently
//! without the caller threading a `Mutex` through.
//!
//! `recv_frame` is `async` and returns the next frame the radio
//! receives; concurrent `recv_frame` calls are an error
//! ([`DriverError::ConcurrentReceive`]) — the listen loop owns the
//! receive half exclusively, as is the case for every actual modem
//! API we've surveyed.

use async_trait::async_trait;

/// What the [`PacketRadioTransport`](super::PacketRadioTransport) needs
/// from a hardware-specific driver.
#[async_trait]
pub trait PacketRadioDriver: Send + Sync + 'static {
    /// Stable identifier for metrics + logs. Examples: `"lora-sx1276"`,
    /// `"ax25-kiss"`, `"mock"`. Static-str typed so it can flow into
    /// `tracing` spans + metric labels without allocation.
    fn medium_id(&self) -> &'static str;

    /// Transmit one frame's bytes. The driver owns the on-air framing
    /// (datagram-shape modems pass straight through; stream-shape
    /// modems add their own delimiter encoding). Blocks the calling
    /// task until the radio has accepted the frame for transmission,
    /// NOT until the receiver has acked.
    async fn send_frame(&self, bytes: &[u8]) -> Result<(), DriverError>;

    /// Receive one frame from the medium. Returns when a complete
    /// frame is available; the listen loop is the sole caller. Bytes
    /// returned are the OUTPUT of any on-air framing the driver
    /// applies — i.e. ready to hand to
    /// [`crate::transport::packet_radio::frame::decode_frame_view`].
    ///
    /// Implementations MUST be cancel-safe wrt the caller's tokio
    /// task: cancelling the future during `recv_frame` must not leave
    /// the radio in a half-consumed state.
    async fn recv_frame(&self) -> Result<Vec<u8>, DriverError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The underlying hardware returned an error (modem busy, USB
    /// detached, GPIO unreachable, etc.). String form because every
    /// radio vendor has its own error vocabulary; the transport surfaces
    /// this opaquely.
    #[error("packet-radio driver hardware error: {0}")]
    Hardware(String),
    /// `recv_frame` was called concurrently from multiple tasks. Per the
    /// trait contract, the listen loop must be the sole receiver.
    #[error("concurrent recv_frame: only one listener may consume the receive half")]
    ConcurrentReceive,
    /// `send_frame` was called with a buffer larger than the medium
    /// can carry in a single packet. The transport layer's
    /// [`crate::transport::packet_radio::frame::MAX_PAYLOAD_LEN`] is
    /// the soft cap; this driver-level cap is the hard hardware limit
    /// (e.g. 255 bytes for a stock SX127x LoRa packet).
    #[error("frame exceeds medium MTU: got {got} bytes, limit {limit}")]
    FrameOverMtu { got: usize, limit: usize },
    /// The radio's RX queue overflowed before the listen loop could
    /// drain it. Surfaced so the listen loop can record a drop metric.
    #[error("rx queue overflow: dropped {dropped} frames")]
    RxOverflow { dropped: u64 },
}

#[cfg(test)]
pub(crate) mod mock {
    //! In-process driver for unit tests. Two `MockDriver`s wired
    //! through a shared bus simulate a peer pair on a radio medium.

    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Shared "channel" two [`MockDriver`]s exchange frames over.
    /// Newtype around an mpsc pair so the test fixture wiring is
    /// explicit ("alice's TX feeds bob's RX, bob's TX feeds alice's RX").
    pub struct MockBus {
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl MockBus {
        pub fn channel_pair() -> (Arc<MockBus>, Arc<MockBus>) {
            let (a_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
            let (b_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
            let alice = Arc::new(MockBus {
                tx: a_tx,
                rx: Mutex::new(a_rx),
            });
            let bob = Arc::new(MockBus {
                tx: b_tx,
                rx: Mutex::new(b_rx),
            });
            (alice, bob)
        }
    }

    pub struct MockDriver {
        bus: Arc<MockBus>,
        rx_lock: Mutex<()>,
        medium: &'static str,
    }

    impl MockDriver {
        pub fn new(bus: Arc<MockBus>) -> Self {
            Self {
                bus,
                rx_lock: Mutex::new(()),
                medium: "mock",
            }
        }
    }

    #[async_trait]
    impl PacketRadioDriver for MockDriver {
        fn medium_id(&self) -> &'static str {
            self.medium
        }

        async fn send_frame(&self, bytes: &[u8]) -> Result<(), DriverError> {
            self.bus
                .tx
                .send(bytes.to_vec())
                .map_err(|e| DriverError::Hardware(format!("mock bus closed: {e}")))
        }

        async fn recv_frame(&self) -> Result<Vec<u8>, DriverError> {
            // The `try_lock` enforces the "single receiver" contract
            // — concurrent recv_frame must return ConcurrentReceive.
            let _guard = self
                .rx_lock
                .try_lock()
                .map_err(|_| DriverError::ConcurrentReceive)?;
            let mut rx = self.bus.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| DriverError::Hardware("mock bus closed".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock::{MockBus, MockDriver};
    use std::sync::Arc;

    /// Two drivers wired into a mock bus exchange frames in both
    /// directions.
    #[tokio::test]
    async fn mock_drivers_round_trip_both_directions() {
        let (alice_bus, bob_bus) = MockBus::channel_pair();
        let alice = MockDriver::new(alice_bus);
        let bob = MockDriver::new(bob_bus);

        alice.send_frame(b"a -> b").await.expect("a send");
        let got = bob.recv_frame().await.expect("b recv");
        assert_eq!(got, b"a -> b");

        bob.send_frame(b"b -> a").await.expect("b send");
        let got = alice.recv_frame().await.expect("a recv");
        assert_eq!(got, b"b -> a");
    }

    /// Calling recv_frame concurrently from two tasks must surface
    /// `ConcurrentReceive` to the second caller.
    #[tokio::test]
    async fn concurrent_recv_returns_concurrent_receive_error() {
        let (alice_bus, _bob_bus) = MockBus::channel_pair();
        let alice = Arc::new(MockDriver::new(alice_bus));
        let a1 = Arc::clone(&alice);
        let a2 = Arc::clone(&alice);
        // Start one recv that blocks (no message yet).
        let blocking = tokio::spawn(async move { a1.recv_frame().await });
        // Give it time to acquire the lock.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // Second concurrent recv must error out.
        let r = a2.recv_frame().await;
        assert!(matches!(r, Err(DriverError::ConcurrentReceive)));
        // Clean up the blocking task.
        blocking.abort();
    }

    /// `medium_id` is exposed.
    #[test]
    fn medium_id_is_exposed() {
        let (bus, _) = MockBus::channel_pair();
        let d = MockDriver::new(bus);
        assert_eq!(d.medium_id(), "mock");
    }
}
