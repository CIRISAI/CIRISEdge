//! No-op transport for benches that drive `dispatch_inbound_for_test`
//! directly and never call the production `Edge::run` listener loop.
//! `send` returns `Delivered` so any incidentally-triggered outbound
//! dispatcher (we never start one in the bench) wouldn't deadlock;
//! `listen` returns immediately.
//!
//! Mirrors `tests/accord_carrier_verify.rs::NullTransport` and
//! `tests/steward_topology.rs::NullTransport`.

#![allow(clippy::pedantic, clippy::needless_pass_by_value, clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::cast_possible_truncation, clippy::cast_lossless, clippy::cast_sign_loss, clippy::cast_possible_wrap, clippy::items_after_statements, clippy::used_underscore_binding, clippy::field_reassign_with_default, clippy::needless_raw_string_hashes)]

use async_trait::async_trait;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use tokio::sync::mpsc;

pub struct NullTransport;

#[async_trait]
impl Transport for NullTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}
