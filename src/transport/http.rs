//! HTTP/HTTPS fallback transport.
//!
//! Documented fallback per OQ-02; Reticulum is canonical. Used by
//! deployments where Reticulum can't run (cloud-only, restrictive
//! networks). TLS at the deployment edge handles encryption (AV-15);
//! edge does not add a third encryption layer.
//!
//! The transport is symmetric: server-side accepts inbound envelopes
//! at `POST /edge/inbound`; client-side ships outbound envelopes via
//! the same URL on the destination peer. Resolution of
//! `destination_key_id → URL` is per-peer config.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    body::Bytes, extract::DefaultBodyLimit, extract::State, http::StatusCode,
    response::IntoResponse, routing::post, Router,
};
use chrono::Utc;
use tokio::sync::mpsc;

use super::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};

/// Maximum body size accepted on the inbound HTTP route. Mirrors
/// AV-13 (`MAX_BODY_BYTES = 8 MiB`) at the extractor layer so
/// oversized payloads reject before allocation.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTP transport configuration.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Address to listen on (server-side).
    pub listen_addr: SocketAddr,
    /// Map from `destination_key_id` → base URL of the peer's
    /// `/edge/inbound` route. Used by `send` to resolve outbound
    /// targets. Format: `https://api.peer.example/edge/inbound`.
    pub peer_urls: HashMap<String, String>,
    /// Outbound request timeout.
    pub request_timeout: Duration,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            peer_urls: HashMap::new(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// HTTP transport. Implements [`Transport`]; spawned by `Edge::run`.
pub struct HttpTransport {
    config: HttpTransportConfig,
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(config: HttpTransportConfig) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| TransportError::Config(format!("reqwest client build: {e}")))?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Transport for HttpTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let url = self
            .config
            .peer_urls
            .get(destination_key_id)
            .ok_or_else(|| {
                TransportError::Unreachable(format!(
                    "no HTTP URL configured for destination_key_id={destination_key_id}"
                ))
            })?;

        if envelope_bytes.len() > MAX_BODY_BYTES {
            return Err(TransportError::BodyTooLarge {
                actual: envelope_bytes.len(),
                limit: MAX_BODY_BYTES,
            });
        }

        let resp = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(envelope_bytes.to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    TransportError::Timeout(self.config.request_timeout)
                } else if e.is_connect() {
                    TransportError::Unreachable(format!("{e}"))
                } else {
                    TransportError::Io(format!("{e}"))
                }
            })?;

        let status = resp.status();
        if status.is_success() {
            Ok(TransportSendOutcome::Delivered)
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            Ok(TransportSendOutcome::Reject {
                class: "rate_limited".into(),
                detail: format!("HTTP {status}"),
            })
        } else if status.is_client_error() {
            let detail = resp.text().await.unwrap_or_default();
            Ok(TransportSendOutcome::Reject {
                class: "client_error".into(),
                detail: format!("HTTP {status}: {detail}"),
            })
        } else {
            Err(TransportError::Io(format!("HTTP {status}")))
        }
    }

    async fn listen(&self, sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        let state = HttpListenerState { sink };
        let app = Router::new()
            .route("/edge/inbound", post(inbound_handler))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|e| {
                TransportError::Config(format!("bind {}: {e}", self.config.listen_addr))
            })?;

        tracing::info!(addr = %self.config.listen_addr, "HTTP transport listening");

        axum::serve(listener, app)
            .await
            .map_err(|e| TransportError::Io(format!("axum serve: {e}")))?;

        Ok(())
    }
}

#[derive(Clone)]
struct HttpListenerState {
    sink: mpsc::Sender<InboundFrame>,
}

/// Inbound POST handler. Pushes the frame onto the shared inbound
/// channel; verify happens downstream in the dispatch loop.
async fn inbound_handler(State(state): State<HttpListenerState>, body: Bytes) -> impl IntoResponse {
    let frame = InboundFrame {
        envelope_bytes: body.to_vec(),
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    };
    match state.sink.send(frame).await {
        Ok(()) => StatusCode::ACCEPTED,
        Err(e) => {
            tracing::error!(error = %e, "inbound channel send failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
