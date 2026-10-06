//! CIRISEdge#805 item 4 — **the A/V plane on the live node.**
//!
//! # What was missing
//!
//! The A/V spine (`av_spine`, `realtime_av_*`) is complete over the
//! dispatcher's transport-blind seam, and its real-RNS half
//! (`LeviculumAvSender` / `LinkDataPump`) wants a leviculum node's
//! `EventReceiver`. A node that also replicates cannot hand one over: the
//! Reticulum transport's listener owns the only one, and every
//! `LinkDataReceived` / `MessageReceived` it sees goes to replication
//! and attribution. So a call could only run on a second node, beside the
//! one the federation knows — the mesh harness carried its media on the
//! Resource path through `Transport::send` instead.
//!
//! # The shape
//!
//! The transport owns an [`AvSink`] and demultiplexes A/V link data into
//! it on its own event loop, the same loop replication uses:
//!
//! ```text
//!   NodeEvent::{MessageReceived, LinkDataReceived}
//!     └─ the link's PLANE, fixed at establishment (FSD §3.5/§3.6)
//!          ├─ Identity | Scoped ─► reassemble ─► attribute ─► replication sink
//!          └─ Av ────────────────► attribute (#393, same gate) ─► AvSink
//!                                     ├─ link claimed (we dialled it) ─► its queue
//!                                     └─ first frame of a peer-opened link ─► AvArrival
//! ```
//!
//! **Which plane a link is on** is decided once, from the destination it
//! was dialled to: an address the `ScopeAddressTable` resolves into a
//! group in the [`crate::av_addressing::AV_STREAM_GROUP_PREFIX`]
//! namespace makes it an A/V link for life. Nothing in a frame chooses
//! its route, so an A/V frame cannot reach the replication router and a
//! replication frame cannot reach this sink: the event loop's dispatch is
//! a match on the plane, and the replication path's entry point takes a
//! plane type that has no A/V variant.
//!
//! **Attribution** runs the same `Rooted ∧ owns_key` + hybrid
//! transport-binding gate (CIRISEdge#393) as a replication frame, per
//! frame. An A/V frame from a link whose peer does not pass is dropped
//! and counted; there is no unattributed A/V path.
//!
//! **Backpressure** never reaches the event loop. Each link has a bounded
//! queue ([`AV_LINK_QUEUE_DEPTH`]) and a full queue drops the newest
//! frame — the A/V drop policy `LinkDataPump` already had, now one type
//! ([`AvLinkQueue`]) both use. The drop is counted, logged at DEBUG
//! (routine realtime churn, CIRISEdge#460), and reported to the consumer
//! with the next frame so its hop counter skips past it rather than
//! desyncing ([`crate::transport::realtime_av_dispatcher::InboundWireFrame`]).
//! The sink's lock is a `std::sync::Mutex`, taken and released inside one
//! synchronous call: no guard exists across an `.await` (CIRISEdge#217).
//!
//! [`AV_LINK_QUEUE_DEPTH`]: crate::transport::realtime_av_runtime::AV_LINK_QUEUE_DEPTH

use std::collections::HashMap;
use std::sync::Mutex;

use leviculum_core::link::LinkId;
use tokio::sync::mpsc;

use crate::scope_addressing::InboundAddress;
use crate::transport::realtime_av_runtime::{
    AvLinkQueue, LeviculumAvSender, PumpReceiver, QueueOffer,
};
use crate::transport::SourceKeyId;

/// Bound on peer-opened A/V links waiting for the consumer to take them.
/// A link that finds this full is not admitted on that frame; its next
/// frame tries again.
pub const AV_ARRIVALS_DEPTH: usize = 64;

/// An A/V link a PEER opened to one of this node's A/V addresses, handed
/// to the consumer on its first attributed frame.
///
/// Carries both halves of the link: the inbound queue (already holding
/// that first frame) and a sender, because the far end of a peer-dialled
/// link is often where this node must push — a subscriber dials its
/// relay, and the relay fans the stream out on the subscriber's link.
pub struct AvArrival {
    /// The link (leviculum's 16-byte truncated hash).
    pub link_id: [u8; 16],
    /// The peer the link is attributed to — through the #393 gate.
    pub peer: SourceKeyId,
    /// The A/V address the peer dialled: its group names the stream, its
    /// member is this node. `None` only when that address was sealed out of
    /// the table before the link's first frame (a live link outlives its
    /// epoch's window by design); the link is on the A/V plane either way.
    pub address: Option<InboundAddress>,
    /// The link's inbound frames.
    pub inbound: PumpReceiver,
    /// A sender on the same link.
    pub sender: LeviculumAvSender,
}

/// An A/V link THIS node dialled ([`ReticulumTransport::open_av_link`]):
/// both halves, held for the call.
///
/// [`ReticulumTransport::open_av_link`]: crate::transport::reticulum::ReticulumTransport::open_av_link
pub struct AvLink {
    /// The link (leviculum's 16-byte truncated hash).
    pub link_id: [u8; 16],
    /// The peer it was dialled to.
    pub peer: String,
    /// Frames the peer sends back on the link, through the #393 gate.
    pub inbound: PumpReceiver,
    /// The Channel-path sender.
    pub sender: LeviculumAvSender,
}

impl std::fmt::Debug for AvLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvLink")
            .field("link_id", &hex::encode(self.link_id))
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AvArrival {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvArrival")
            .field("link_id", &hex::encode(self.link_id))
            .field("peer", &self.peer.as_str())
            .field(
                "group",
                &self
                    .address
                    .as_ref()
                    .map(|a| a.group().group_id().to_owned()),
            )
            .field("epoch", &self.address.as_ref().map(InboundAddress::epoch))
            .finish_non_exhaustive()
    }
}

/// What [`AvSink::deliver`] did with one frame. Every arm is named, and
/// the caller counts each one (CIRISEdge#425).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AvDelivery {
    /// Queued on a claimed or already-arrived link.
    Queued,
    /// The first frame of a peer-opened link: the link was handed to the
    /// consumer as an [`AvArrival`] with this frame queued.
    Arrived,
    /// The link's consumer is a full queue behind; dropped.
    DroppedFull,
    /// The link's consumer dropped its receiver; dropped, link forgotten.
    ConsumerGone,
    /// A peer-opened link and no consumer to take it (arrivals receiver
    /// never taken or dropped, or full); dropped.
    NoConsumer,
}

/// The transport's A/V sink. See the module docs.
pub struct AvSink {
    links: Mutex<HashMap<LinkId, AvLinkQueue>>,
    arrivals_tx: mpsc::Sender<AvArrival>,
    arrivals_rx: Mutex<Option<mpsc::Receiver<AvArrival>>>,
}

impl Default for AvSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AvSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        let (arrivals_tx, arrivals_rx) = mpsc::channel(AV_ARRIVALS_DEPTH);
        Self {
            links: Mutex::new(HashMap::new()),
            arrivals_tx,
            arrivals_rx: Mutex::new(Some(arrivals_rx)),
        }
    }

    /// Take the receiver of peer-opened A/V links. Once: the A/V plane has
    /// one consumer per node, as replication has one inbound sink.
    pub fn take_arrivals(&self) -> Option<mpsc::Receiver<AvArrival>> {
        self.arrivals_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Register the inbound queue of a link THIS node dialled, before any
    /// frame can arrive on it.
    pub(crate) fn claim(&self, link_id: LinkId) -> PumpReceiver {
        let (queue, rx) = AvLinkQueue::new(link_id);
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(link_id, queue);
        rx
    }

    /// Route one attributed frame. Never awaits.
    ///
    /// `arrival` builds the hand-off for a link no consumer holds yet —
    /// called at most once per call, and only on that branch.
    pub(crate) fn deliver(
        &self,
        link_id: LinkId,
        bytes: Vec<u8>,
        arrival: impl FnOnce(PumpReceiver) -> AvArrival,
    ) -> AvDelivery {
        let mut links = self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(queue) = links.get_mut(&link_id) {
            return match queue.offer(bytes) {
                QueueOffer::Queued => AvDelivery::Queued,
                QueueOffer::DroppedFull => AvDelivery::DroppedFull,
                QueueOffer::ConsumerGone => {
                    links.remove(&link_id);
                    AvDelivery::ConsumerGone
                }
            };
        }
        let (mut queue, rx) = AvLinkQueue::new(link_id);
        // A fresh queue has room; this cannot be refused.
        let _first = queue.offer(bytes);
        match self.arrivals_tx.try_send(arrival(rx)) {
            Ok(()) => {
                links.insert(link_id, queue);
                AvDelivery::Arrived
            }
            // Full: not admitted on this frame; the next one retries.
            // Closed: nobody will ever take it.
            Err(_) => AvDelivery::NoConsumer,
        }
    }

    /// Forget a closed link: its consumer's receiver then reports the link
    /// closed instead of waiting forever.
    pub(crate) fn forget(&self, link_id: &LinkId) {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link_id);
    }

    /// Links the sink currently routes for (tests + diagnostics).
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::realtime_av_dispatcher::AvLinkReceiver;

    fn link(n: u8) -> LinkId {
        LinkId::new([n; 16])
    }

    #[tokio::test]
    async fn a_claimed_link_queues_in_order() {
        let sink = AvSink::new();
        let rx = sink.claim(link(1));
        for i in 0..3u8 {
            let d = sink.deliver(link(1), vec![i], |_| unreachable!("claimed link"));
            assert_eq!(d, AvDelivery::Queued);
        }
        for i in 0..3u8 {
            let f = rx.recv_frame().await.expect("frame");
            assert_eq!(f.bytes, vec![i]);
            assert_eq!(f.dropped_before, 0);
        }
    }

    /// The never-block policy: a consumer a full queue behind loses the
    /// NEWEST frames, `deliver` returns at once, and the next frame that
    /// is queued carries the count so the hop counter can skip past it.
    #[tokio::test]
    async fn overflow_drops_newest_without_blocking_and_reports_the_gap() {
        use crate::transport::realtime_av_runtime::AV_LINK_QUEUE_DEPTH;
        let sink = AvSink::new();
        let rx = sink.claim(link(2));
        for i in 0..AV_LINK_QUEUE_DEPTH {
            assert_eq!(
                sink.deliver(link(2), i.to_be_bytes().to_vec(), |_| unreachable!()),
                AvDelivery::Queued
            );
        }
        for _ in 0..5 {
            assert_eq!(
                sink.deliver(link(2), b"over".to_vec(), |_| unreachable!()),
                AvDelivery::DroppedFull
            );
        }
        // Drain one, then the next delivered frame carries the gap.
        let _ = rx.recv_frame().await.expect("first");
        assert_eq!(
            sink.deliver(link(2), b"after".to_vec(), |_| unreachable!()),
            AvDelivery::Queued
        );
        let mut last = None;
        for _ in 0..AV_LINK_QUEUE_DEPTH {
            last = Some(rx.recv_frame().await.expect("frame"));
        }
        let last = last.expect("drained");
        assert_eq!(last.bytes, b"after");
        assert_eq!(
            last.dropped_before, 5,
            "the five dropped frames are reported"
        );
    }

    fn test_node() -> std::sync::Arc<leviculum_std::driver::ReticulumNode> {
        let mut priv_bytes = [0u8; 64];
        for (i, b) in priv_bytes.iter_mut().enumerate() {
            *b = u8::try_from(i)
                .expect("index < 64")
                .wrapping_mul(29)
                .wrapping_add(3);
        }
        let identity =
            leviculum_core::Identity::from_private_key_bytes(&priv_bytes).expect("identity");
        let storage =
            std::env::temp_dir().join(format!("ciris-edge-av-sink-test-{}", uuid::Uuid::new_v4()));
        std::sync::Arc::new(
            leviculum_std::driver::ReticulumNodeBuilder::new()
                .identity(identity)
                .storage_path(storage)
                .build_sync()
                .expect("test node"),
        )
    }

    fn av_address() -> InboundAddress {
        use crate::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
        let table = ScopeAddressTable::new(std::sync::Arc::new(ScopePrivacyDeriver));
        let group = crate::av_addressing::stream_group_id(crate::transport::realtime_av::StreamId(
            [0x5a; 32],
        ));
        table
            .install_group(
                &crate::CohortScope::SelfOnly,
                &group,
                1,
                &[0x42; 32],
                &["me", "peer"],
            )
            .expect("install");
        let me = table
            .send_address(&crate::CohortScope::SelfOnly, &group, "me")
            .expect("address");
        table.accepts_inbound(me.as_bytes()).expect("reverse index")
    }

    /// A peer-opened link is handed to the consumer ONCE, with its first
    /// frame already queued; later frames queue on the same receiver.
    #[tokio::test]
    async fn a_peer_opened_link_arrives_once_then_queues() {
        let node = test_node();
        let sink = AvSink::new();
        let mut arrivals = sink.take_arrivals().expect("arrivals");
        assert!(sink.take_arrivals().is_none(), "one consumer per node");
        let arrive = |rx: PumpReceiver| AvArrival {
            link_id: link(3).into_bytes(),
            peer: SourceKeyId::transport_authenticated("peer"),
            address: Some(av_address()),
            inbound: rx,
            sender: LeviculumAvSender::new(std::sync::Arc::clone(&node), link(3)),
        };
        assert_eq!(
            sink.deliver(link(3), b"first".to_vec(), arrive),
            AvDelivery::Arrived
        );
        assert_eq!(
            sink.deliver(link(3), b"second".to_vec(), |_| unreachable!(
                "arrived once"
            )),
            AvDelivery::Queued
        );
        let arrival = arrivals.recv().await.expect("arrival");
        assert_eq!(arrival.peer.as_str(), "peer");
        let address = arrival.address.as_ref().expect("address");
        assert!(crate::av_addressing::is_av_stream_group(
            address.group().group_id()
        ));
        assert_eq!(arrival.inbound.recv().await.expect("first"), b"first");
        assert_eq!(arrival.inbound.recv().await.expect("second"), b"second");
    }

    /// With nobody to take a peer-opened link, its frame is `NoConsumer` —
    /// named and counted by the caller — and nothing is registered.
    #[tokio::test]
    async fn a_peer_opened_link_with_no_consumer_is_named() {
        let node = test_node();
        let sink = AvSink::new();
        drop(sink.take_arrivals());
        let d = sink.deliver(link(5), b"x".to_vec(), |rx| AvArrival {
            link_id: link(5).into_bytes(),
            peer: SourceKeyId::transport_authenticated("peer"),
            address: Some(av_address()),
            inbound: rx,
            sender: LeviculumAvSender::new(std::sync::Arc::clone(&node), link(5)),
        });
        assert_eq!(d, AvDelivery::NoConsumer);
        assert_eq!(sink.link_count(), 0);
    }

    #[tokio::test]
    async fn forgetting_a_link_closes_its_consumer() {
        let sink = AvSink::new();
        let rx = sink.claim(link(4));
        sink.forget(&link(4));
        assert!(rx.recv_frame().await.is_err(), "closed link ⇒ recv error");
        assert_eq!(sink.link_count(), 0);
    }
}
