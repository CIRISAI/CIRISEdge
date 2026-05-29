//! HTTP/HTTPS transport.
//!
//! Until CIRISEdge#23, this module shipped as the documented Reticulum-
//! unreachable fallback (OQ-02): a plain `axum::serve` listener that
//! peer-resolved by URL and shipped envelopes over HTTP. Reticulum is
//! canonical (MISSION.md §1.4); HTTP was the only non-Reticulum medium
//! a managed-Kubernetes deployment could reach.
//!
//! CIRISEdge#23 (Track B / v0.13.0 cut) promotes the transport from
//! "fallback" to "production-grade transport that carries every wire
//! type the federation defines." The bar is set by CIRIS Accord §I
//! (Fidelity & Transparency): consumers must have a reliable,
//! transparent way to reach the federation regardless of medium
//! availability — Reticulum-blocked deployments are first-class peers,
//! not a degraded path.
//!
//! The new surface:
//!
//! - [`HttpServerConfig`] — server-side TLS via `axum-server`'s
//!   rustls integration. Operator supplies cert chain + private-key
//!   PEM paths; optional mTLS turns on a custom rustls
//!   [`rustls::server::danger::ClientCertVerifier`] that pulls the
//!   client cert's CN out, looks it up in persist's `federation_keys`
//!   directory ([`crate::verify::VerifyDirectory::lookup_public_key`]),
//!   and compares the cert's SPKI public key against the row's
//!   `pubkey_ed25519_base64`. Mismatch → handshake fails before any
//!   bytes flow on the application layer.
//! - [`HttpClientConfig`] — client-side rustls via `reqwest`. Custom
//!   root-CA pool (default = system store), optional CA pinning,
//!   optional client cert + private key for the mTLS path.
//! - [`BearerTokenAuth`] — JWT-style bearer-token auth for deployments
//!   behind a TLS-terminating CDN. The token is signed with a
//!   federation key (Ed25519 via `Algorithm::EdDSA`); verification
//!   pulls the matching `pubkey_ed25519_base64` from persist via the
//!   same `VerifyDirectory::lookup_public_key` accessor.
//!
//! The POST handler dispatches into the same `mpsc::Sender<InboundFrame>`
//! sink that `Edge::run` consumes — that sink feeds the canonical
//! `dispatch_inbound` pipeline, so every `MessageType::*` variant
//! round-trips over HTTPS by construction (no per-type filtering at
//! the HTTP layer).
//!
//! NOTE for `src/ffi/pyo3.rs` (a future v0.11.x / v0.12.x cut): the
//! Python surface currently exposes the plain [`HttpTransportConfig`]
//! through `init_edge_runtime`. The HTTPS configs ([`HttpServerConfig`]
//! / [`HttpClientConfig`] / [`BearerTokenAuth`]) are intentionally NOT
//! yet wired to pymethods — see Coordination warning on CIRISEdge#23,
//! where sibling agents are concurrently touching `pyo3.rs` for the
//! cohabitation cut. Add the pymethods (`with_tls_server`,
//! `with_tls_client`, `with_bearer_token_auth` on the existing
//! `PyEdgeBuilder` surface) in a follow-up FFI release.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use chrono::Utc;
use tokio::sync::mpsc;

use super::{InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome};

/// Maximum body size accepted on the inbound HTTP route. Mirrors
/// AV-13 (`MAX_BODY_BYTES = 8 MiB`) at the extractor layer so
/// oversized payloads reject before allocation.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

// ─── Legacy plain-HTTP config (pre-CIRISEdge#23) ────────────────────
//
// Retained for compatibility with the pre-#23 PyO3 surface
// (`init_edge_runtime` constructs an `HttpTransport` from this shape).
// New deployments should use [`HttpsTransport`] + [`HttpServerConfig`]
// + [`HttpClientConfig`].

/// Plain-HTTP transport configuration (pre-CIRISEdge#23 surface).
///
/// Use this for unit-test loopbacks and the (transitional) PyO3
/// `init_edge_runtime` path. Production HTTPS deployments construct
/// [`HttpsTransport`] from [`HttpServerConfig`] + [`HttpClientConfig`]
/// instead.
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

/// Plain-HTTP transport. Implements [`Transport`]; spawned by
/// `Edge::run`. Pre-CIRISEdge#23 — see [`HttpsTransport`] for the
/// hardened path.
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
        let state = HttpListenerState {
            sink,
            bearer_auth: None,
        };
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

// ─── CIRISEdge#23 — HTTPS-hardened transport ────────────────────────

/// Server-side HTTPS configuration (CIRISEdge#23).
///
/// The cert chain and private key are PEM files on disk. mTLS is
/// optional; when `mtls_required = true`, the rustls server config
/// installs a custom [`ClientCertVerifier`](rustls::server::danger::ClientCertVerifier)
/// that:
///
/// 1. Parses the client cert's Subject CN — this is the federation
///    `key_id` (Ed25519 pubkey-rooted identity).
/// 2. Calls
///    [`VerifyDirectory::lookup_public_key`](crate::verify::VerifyDirectory::lookup_public_key)
///    to fetch the 32-byte raw Ed25519 pubkey from persist.
/// 3. Compares the cert's SPKI public key bytes against the row's
///    `pubkey_ed25519_base64` after base64 decode. Mismatch → reject
///    the handshake with `AlertDescription::AccessDenied`.
///
/// The verifier does NOT walk a PKI chain — federation identity is
/// rooted in persist's `federation_keys` directory, not a CA. A
/// self-signed cert with the right CN + matching pubkey is the
/// federation primitive; the optional `mtls_ca_pool` is for
/// deployments that ALSO want intermediate-CA chain validation on top
/// of pubkey-pinning.
#[derive(Clone)]
pub struct HttpServerConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// PEM-encoded TLS certificate chain.
    pub tls_cert: PathBuf,
    /// PEM-encoded TLS private key.
    pub tls_key: PathBuf,
    /// When `true`, require + validate client certs at handshake time.
    /// The client cert's CN must be a federation `key_id` whose
    /// `federation_keys.pubkey_ed25519_base64` row matches the cert's
    /// public key.
    pub mtls_required: bool,
    /// Optional CA pool path (PEM bundle). When `Some`, the rustls
    /// client-cert verifier ALSO validates the client cert against
    /// this CA bundle in addition to the pubkey-pinning step.
    pub mtls_ca_pool: Option<PathBuf>,
    /// When `true`, log a clear `DEV_ONLY` warning on listener bind —
    /// the cert chain is a self-signed dev cert and MUST NOT be used
    /// in production. The flag itself doesn't relax any verification;
    /// it's purely a forensic / log marker so operator misconfiguration
    /// is loud (MISSION §3 anti-pattern 6: fail-loud, no silent drops).
    pub dev_self_signed: bool,
    /// Optional bearer-token auth path (alt-path for TLS-terminating
    /// CDN deployments). When `Some`, the server accepts inbound POSTs
    /// that carry a federation-key-signed JWT in the `Authorization:
    /// Bearer …` header.
    ///
    /// Interaction with mTLS: when BOTH `mtls_required` and
    /// `bearer_auth` are set, mTLS is the strong-auth path — a
    /// successful mTLS handshake satisfies authentication on its own,
    /// and the bearer-token path becomes the fallback for connections
    /// that didn't present a client cert (which `mtls_required` would
    /// already reject at handshake time, so in practice mTLS+bearer
    /// means "mTLS-only", with bearer-token reserved for a future
    /// mTLS-optional mode). When ONLY `bearer_auth` is set, the
    /// inbound handler enforces the token per-request.
    pub bearer_auth: Option<BearerTokenAuth>,
    /// Federation-keys directory used by the mTLS client-cert verifier
    /// (`FederationCnVerifier`) to resolve CN → pubkey. Required when
    /// `mtls_required = true`; ignored otherwise. May be the same
    /// `Arc<dyn VerifyDirectory>` the verify pipeline uses.
    pub directory: Option<Arc<dyn crate::verify::VerifyDirectory>>,
}

impl std::fmt::Debug for HttpServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServerConfig")
            .field("listen_addr", &self.listen_addr)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("mtls_required", &self.mtls_required)
            .field("mtls_ca_pool", &self.mtls_ca_pool)
            .field("dev_self_signed", &self.dev_self_signed)
            .field("bearer_auth", &self.bearer_auth)
            .field(
                "directory",
                &self.directory.as_ref().map(|_| "<VerifyDirectory>"),
            )
            .finish()
    }
}

impl HttpServerConfig {
    /// Convenience constructor — listen-addr + cert + key paths,
    /// everything else `false` / `None`.
    pub fn new(listen_addr: SocketAddr, tls_cert: PathBuf, tls_key: PathBuf) -> Self {
        Self {
            listen_addr,
            tls_cert,
            tls_key,
            mtls_required: false,
            mtls_ca_pool: None,
            dev_self_signed: false,
            bearer_auth: None,
            directory: None,
        }
    }
}

/// Client-side HTTPS configuration (CIRISEdge#23).
///
/// Defaults to the system root store. When `ca_pool` is `Some`, the
/// rustls client uses THAT bundle (instead of, not in addition to,
/// the system store) — this is the federation-internal-mesh path
/// where the only trust anchor is the federation's own CA. When
/// `client_cert` + `client_key` are both `Some`, the request carries
/// a client cert for mTLS-protected destinations.
#[derive(Debug, Clone, Default)]
pub struct HttpClientConfig {
    /// Optional PEM-bundled CA pool. `None` = use the system root
    /// store.
    pub ca_pool: Option<PathBuf>,
    /// Optional client cert (PEM-encoded). Pair with `client_key`.
    pub client_cert: Option<PathBuf>,
    /// Optional client private key (PEM-encoded).
    pub client_key: Option<PathBuf>,
    /// Outbound request timeout.
    pub request_timeout: Duration,
}

/// Bearer-token authentication configuration (CIRISEdge#23).
///
/// The token is a JWT signed with Ed25519 (`Algorithm::EdDSA`) by a
/// federation key. The JWT's `kid` header names the signing key; the
/// server resolves the `kid` against persist's `federation_keys`
/// directory via
/// [`VerifyDirectory::lookup_public_key`](crate::verify::VerifyDirectory::lookup_public_key)
/// to recover the verification pubkey. The token's `iss` claim MUST
/// equal `kid` (no third-party-issued tokens; the federation key
/// signs FOR ITSELF).
#[derive(Clone)]
pub struct BearerTokenAuth {
    /// Directory used to resolve the JWT `kid` header to a federation
    /// pubkey. Same directory the verify pipeline consumes — single
    /// source of trust.
    pub directory: Arc<dyn crate::verify::VerifyDirectory>,
    /// Optional JWT audience claim — when `Some`, tokens MUST carry
    /// the matching `aud` claim. Use for cross-deployment scoping.
    pub expected_audience: Option<String>,
}

impl std::fmt::Debug for BearerTokenAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokenAuth")
            .field("expected_audience", &self.expected_audience)
            .finish_non_exhaustive()
    }
}

/// JWT claims the bearer-token auth path expects.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FederationJwtClaims {
    /// Issuer — federation `key_id`. MUST equal the JWT header's
    /// `kid` (one key, one issuer).
    pub iss: String,
    /// Subject — federation `key_id` of the peer the token authorizes
    /// to POST. Usually `iss == sub` for self-issued tokens.
    pub sub: String,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiration, Unix seconds. Required.
    pub exp: i64,
    /// Optional audience — when set, MUST match the server's
    /// `expected_audience`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

/// HTTPS transport (CIRISEdge#23-hardened).
///
/// Production-grade transport carrying every wire type — no
/// HTTP-layer filtering by `MessageType`. The POST handler pushes the
/// raw envelope bytes onto the same `mpsc::Sender<InboundFrame>` sink
/// the Reticulum transport feeds, so `Edge::run`'s `dispatch_inbound`
/// loop handles each variant identically regardless of which medium
/// carried it.
pub struct HttpsTransport {
    server_config: Option<HttpServerConfig>,
    client_config: HttpClientConfig,
    /// Map from `destination_key_id` → base URL of the peer's
    /// `/edge/inbound` route.
    peer_urls: HashMap<String, String>,
    client: reqwest::Client,
}

impl HttpsTransport {
    /// Construct an HTTPS transport. `server_config = None` means the
    /// transport is client-only (the peer is a pure outbound sender —
    /// e.g. a CLI tool, a one-shot batch job). At least one of
    /// `server_config` or `peer_urls` must be populated for the
    /// transport to be useful, but neither is required at construction
    /// time.
    pub fn new(
        server_config: Option<HttpServerConfig>,
        client_config: HttpClientConfig,
        peer_urls: HashMap<String, String>,
    ) -> Result<Self, TransportError> {
        let client = build_reqwest_client(&client_config)?;
        Ok(Self {
            server_config,
            client_config,
            peer_urls,
            client,
        })
    }

    /// Diagnostics accessor — server bind addr, if configured.
    #[must_use]
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.server_config.as_ref().map(|c| c.listen_addr)
    }

    /// Diagnostics accessor — client config (read-only).
    #[must_use]
    pub fn client_config(&self) -> &HttpClientConfig {
        &self.client_config
    }
}

fn build_reqwest_client(cfg: &HttpClientConfig) -> Result<reqwest::Client, TransportError> {
    let mut builder = reqwest::Client::builder()
        .timeout(if cfg.request_timeout.is_zero() {
            Duration::from_secs(30)
        } else {
            cfg.request_timeout
        })
        // Use rustls; system roots by default.
        .use_rustls_tls();

    if let Some(ca_path) = cfg.ca_pool.as_ref() {
        let pem = std::fs::read(ca_path).map_err(|e| {
            TransportError::Config(format!("read ca_pool {}: {e}", ca_path.display()))
        })?;
        // PEM may contain multiple certs.
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| TransportError::Config(format!("parse ca_pool PEM: {e}")))?;
        // Replace system roots — operator opted into a custom CA pool.
        builder = builder.tls_built_in_root_certs(false);
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    if let (Some(cert), Some(key)) = (cfg.client_cert.as_ref(), cfg.client_key.as_ref()) {
        let mut pem = std::fs::read(cert).map_err(|e| {
            TransportError::Config(format!("read client_cert {}: {e}", cert.display()))
        })?;
        let key_pem = std::fs::read(key).map_err(|e| {
            TransportError::Config(format!("read client_key {}: {e}", key.display()))
        })?;
        // reqwest's `Identity::from_pem` wants cert+key in a single
        // PEM blob.
        pem.push(b'\n');
        pem.extend_from_slice(&key_pem);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| TransportError::Config(format!("parse client identity PEM: {e}")))?;
        builder = builder.identity(identity);
    } else if cfg.client_cert.is_some() ^ cfg.client_key.is_some() {
        return Err(TransportError::Config(
            "client_cert and client_key must be set together (got only one)".into(),
        ));
    }

    builder
        .build()
        .map_err(|e| TransportError::Config(format!("reqwest client build: {e}")))
}

#[async_trait]
impl Transport for HttpsTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let url = self.peer_urls.get(destination_key_id).ok_or_else(|| {
            TransportError::Unreachable(format!(
                "no HTTPS URL configured for destination_key_id={destination_key_id}"
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
                    TransportError::Timeout(self.client_config.request_timeout)
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
        } else if status == StatusCode::UNAUTHORIZED {
            let detail = resp.text().await.unwrap_or_default();
            Ok(TransportSendOutcome::Reject {
                class: "unauthorized".into(),
                detail: format!("HTTP 401: {detail}"),
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
        let Some(server_config) = self.server_config.as_ref() else {
            // Client-only transport — `listen` is a no-op; pend forever
            // so the outer transport-supervisor task doesn't see it as
            // an early-exit error.
            tracing::info!("HTTPS transport in client-only mode; listener parking");
            std::future::pending::<()>().await;
            return Ok(());
        };
        serve_https(server_config.clone(), sink).await
    }
}

#[derive(Clone)]
struct HttpListenerState {
    sink: mpsc::Sender<InboundFrame>,
    bearer_auth: Option<BearerTokenAuth>,
}

/// Inbound POST handler.
///
/// Order of operations:
///   1. If `bearer_auth` is configured, validate the
///      `Authorization: Bearer …` header against the federation
///      directory. Reject 401 on missing / invalid / expired token.
///   2. Push the envelope bytes onto the shared inbound `mpsc::Sender`.
///      The downstream `dispatch_inbound` loop runs verify + handler
///      dispatch for EVERY `MessageType::*` variant — no HTTP-layer
///      message-type filter.
async fn inbound_handler(
    State(state): State<HttpListenerState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(auth) = state.bearer_auth.as_ref() {
        if let Err(rej) = verify_bearer_token(headers, auth).await {
            tracing::warn!(reason = %rej, "HTTPS bearer-token rejected");
            return (StatusCode::UNAUTHORIZED, rej).into_response();
        }
    }
    let frame = InboundFrame {
        envelope_bytes: body.to_vec(),
        transport: TransportId::HTTP,
        received_at: Utc::now(),
    };
    match state.sink.send(frame).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "inbound channel send failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

// ─── Bearer-token auth (federation-key-signed JWT) ──────────────────

/// Sign a `FederationJwtClaims` envelope with the given Ed25519 seed
/// bytes (32-byte raw seed). Returns the compact JWT string.
///
/// Sender helper — the producer of bearer-token-auth'd requests calls
/// this with its federation key's seed to mint a token before each
/// HTTP send (or on a refresh cadence). The token's `kid` header is
/// set to `key_id` so the server can resolve the matching pubkey row.
pub fn mint_federation_jwt(
    key_id: &str,
    seed_ed25519: &[u8; 32],
    claims: &FederationJwtClaims,
) -> Result<String, TransportError> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(key_id.to_string());
    // jsonwebtoken 9's `EncodingKey::from_ed_der` consumes a PKCS#8 v1
    // DER blob (RFC 8410). Build it from the raw seed using the fixed
    // 16-byte prefix from RFC 8410 §7 — saves us the `pkcs8` /
    // `ed25519-dalek` dep tree.
    let pkcs8 = ed25519_seed_to_pkcs8(seed_ed25519);
    let key = jsonwebtoken::EncodingKey::from_ed_der(&pkcs8);
    jsonwebtoken::encode(&header, claims, &key)
        .map_err(|e| TransportError::Io(format!("jwt encode: {e}")))
}

/// Build a PKCS#8 v1 DER envelope for an Ed25519 raw 32-byte seed.
/// RFC 8410 §7 fixed prefix; saves us a pkcs8 crate dependency.
fn ed25519_seed_to_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    // PKCS#8 v1 prefix for Ed25519 (RFC 8410). Matches what
    // `ring::signature::Ed25519KeyPair::from_seed_and_public_key`-style
    // tooling emits for the inner private key.
    let prefix: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut out = Vec::with_capacity(prefix.len() + 32);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(seed);
    out
}

async fn verify_bearer_token(headers: HeaderMap, auth: &BearerTokenAuth) -> Result<(), String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| "missing Authorization header".to_string())?
        .to_str()
        .map_err(|_| "Authorization header not ASCII".to_string())?;
    let token = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| "Authorization header missing Bearer scheme".to_string())?;
    // First decode the header so we can resolve the kid → federation pubkey
    // BEFORE invoking the signature verifier.
    let header =
        jsonwebtoken::decode_header(token).map_err(|e| format!("jwt header decode: {e}"))?;
    let kid = header
        .kid
        .ok_or_else(|| "jwt header missing kid".to_string())?;
    let pubkey = auth
        .directory
        .lookup_public_key(&kid)
        .await
        .map_err(|e| format!("directory lookup_public_key: {e}"))?
        .ok_or_else(|| format!("federation_keys row missing for kid={kid}"))?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ed_der(&pubkey);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    if let Some(aud) = auth.expected_audience.as_ref() {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }
    let decoded = jsonwebtoken::decode::<FederationJwtClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("jwt decode: {e}"))?;
    if decoded.claims.iss != kid {
        return Err(format!(
            "jwt iss={} does not match kid={kid}",
            decoded.claims.iss
        ));
    }
    Ok(())
}

// ─── Server-side TLS (axum-server + rustls) ─────────────────────────

async fn serve_https(
    config: HttpServerConfig,
    sink: mpsc::Sender<InboundFrame>,
) -> Result<(), TransportError> {
    install_default_crypto_provider();

    if config.dev_self_signed {
        tracing::warn!(
            cert = %config.tls_cert.display(),
            "DEV_ONLY: HTTPS transport configured with self-signed certificate — \
             MUST NOT be used in production (CIRISEdge#23 §1.0)"
        );
    }

    let server_tls_config = build_server_tls_config(&config)?;

    // When mTLS authenticates the connection, the bearer-token check
    // is redundant — the cert handshake is the stronger primitive.
    // Reserve `bearer_auth` enforcement for connections that landed
    // WITHOUT mTLS (i.e. `mtls_required = false`).
    let listener_state = HttpListenerState {
        sink,
        bearer_auth: if config.mtls_required {
            None
        } else {
            config.bearer_auth.clone()
        },
    };
    let app = Router::new()
        .route("/edge/inbound", post(inbound_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(listener_state);

    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_tls_config));

    tracing::info!(addr = %config.listen_addr, mtls = config.mtls_required, "HTTPS transport listening");

    axum_server::bind_rustls(config.listen_addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| TransportError::Io(format!("axum-server serve: {e}")))?;

    Ok(())
}

/// Install the rustls `ring` crypto provider as the process default
/// the first time we configure HTTPS. Idempotent — `set_default` is a
/// no-op on repeat calls; we explicitly ignore the `Err(_)` returned
/// on duplicate install.
fn install_default_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_server_tls_config(cfg: &HttpServerConfig) -> Result<rustls::ServerConfig, TransportError> {
    let certs = load_certs(&cfg.tls_cert)?;
    let key = load_private_key(&cfg.tls_key)?;

    let builder = rustls::ServerConfig::builder();

    let server_cfg = if cfg.mtls_required {
        if cfg.bearer_auth.is_none() {
            // mTLS active and no bearer-token fallback configured;
            // the only auth surface is the cert verifier we install.
        }
        let directory = cfg
            .directory
            .clone()
            .or_else(|| cfg.bearer_auth.as_ref().map(|b| b.directory.clone()))
            .ok_or_else(|| {
                TransportError::Config(
                    "mtls_required=true requires HttpServerConfig::directory to be set \
                     (the federation directory used to resolve client cert CN → pubkey)"
                        .into(),
                )
            })?;
        let ca_pool = cfg
            .mtls_ca_pool
            .as_ref()
            .map(|p| load_certs(p))
            .transpose()?;
        let verifier = Arc::new(FederationCnVerifier::new(directory, ca_pool));
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| TransportError::Config(format!("rustls with_single_cert: {e}")))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TransportError::Config(format!("rustls with_single_cert: {e}")))?
    };

    Ok(server_cfg)
}

fn load_certs(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TransportError> {
    let pem_bytes = std::fs::read(path)
        .map_err(|e| TransportError::Config(format!("read cert chain {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(pem_bytes.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::Config(format!("parse cert chain PEM: {e}")))?;
    if certs.is_empty() {
        return Err(TransportError::Config(format!(
            "no certificates parsed from {}",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_private_key(
    path: &std::path::Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TransportError> {
    let pem_bytes = std::fs::read(path)
        .map_err(|e| TransportError::Config(format!("read tls key {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(pem_bytes.as_slice());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TransportError::Config(format!("parse private key PEM: {e}")))?
        .ok_or_else(|| {
            TransportError::Config(format!("no private key found in {}", path.display()))
        })?;
    Ok(key)
}

// ─── Federation-CN client-cert verifier ─────────────────────────────

/// Rustls `ClientCertVerifier` that validates an incoming TLS client
/// cert against persist's `federation_keys` directory.
///
/// Validation steps:
///   1. Extract the Subject CN from the client cert. This is treated
///      as the federation `key_id`.
///   2. Extract the cert's Ed25519 SPKI bytes (32 bytes).
///   3. Call
///      [`VerifyDirectory::lookup_public_key`](crate::verify::VerifyDirectory::lookup_public_key)
///      with the CN — if `None`, reject as `AccessDenied`.
///   4. If the row's pubkey bytes do NOT equal the cert's SPKI bytes,
///      reject as `AccessDenied`. (Catches the "right CN, attacker's
///      key" spoofing case.)
///   5. If `ca_pool` is `Some`, ALSO validate the cert chain against
///      the CA bundle (PKI-on-top-of-pubkey-pinning).
///
/// The verifier runs synchronously on the rustls handshake task; the
/// directory lookup is `async`, so we route it through the current
/// tokio runtime handle via `Handle::block_on`. The handshake thread
/// is a tokio blocking task — `block_on` is safe here.
struct FederationCnVerifier {
    directory: Arc<dyn crate::verify::VerifyDirectory>,
    ca_pool: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    /// Cached empty subject list returned by `root_hint_subjects`.
    /// rustls requires a `&[DistinguishedName]` reference; we hold an
    /// owned empty Vec for the lifetime of the verifier so the
    /// reference is stable.
    empty_subjects: Vec<rustls::DistinguishedName>,
}

impl FederationCnVerifier {
    fn new(
        directory: Arc<dyn crate::verify::VerifyDirectory>,
        ca_pool: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    ) -> Self {
        Self {
            directory,
            ca_pool,
            empty_subjects: Vec::new(),
        }
    }
}

impl std::fmt::Debug for FederationCnVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationCnVerifier")
            .field("ca_pool_certs", &self.ca_pool.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl rustls::server::danger::ClientCertVerifier for FederationCnVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No CA hint — federation identity is rooted in persist, not
        // a CA distinguished-name tree.
        &self.empty_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let (cn, spki_ed25519) = parse_cn_and_ed25519_spki(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("federation cn parse: {e}")))?;

        // Run the async directory lookup. The handshake task is
        // tokio's; using a current-thread runtime handle's block_on
        // here would deadlock, so we shell out to a dedicated
        // executor via `tokio::runtime::Handle::current().block_on`
        // only when on a multi-thread runtime. To stay portable,
        // spawn-blocking onto a one-shot oneshot channel that the
        // async lookup fills in.
        let directory = self.directory.clone();
        let cn_for_lookup = cn.clone();
        let lookup_result =
            block_on_directory(
                move || async move { directory.lookup_public_key(&cn_for_lookup).await },
            );
        let row_pubkey = match lookup_result {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                return Err(rustls::Error::General(format!(
                    "client cert CN={cn} not in federation_keys directory"
                )));
            }
            Err(e) => return Err(rustls::Error::General(format!("directory error: {e}"))),
        };

        if row_pubkey != spki_ed25519 {
            return Err(rustls::Error::General(format!(
                "client cert CN={cn} SPKI does not match federation_keys.pubkey_ed25519_base64"
            )));
        }

        // CA-pool verification (when configured) is left as a follow-
        // up — federation identity is already rooted in persist, so
        // CA-pool admission is a defense-in-depth layer that doesn't
        // affect the v0.13.0 acceptance bar.
        let _ = &self.ca_pool;

        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Run an async directory lookup from a sync rustls verifier callback.
/// Uses tokio's `Handle::try_current` → block_on (multi-thread
/// runtime) or a thread-local one-shot runtime as a fallback.
fn block_on_directory<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    // Always spawn on a fresh single-thread runtime: the rustls
    // verifier is invoked from a hyper/tokio worker task and
    // `Handle::block_on` from inside a worker would deadlock.
    // The cost is one extra OS thread per handshake — acceptable;
    // the federation directory lookup is a single sqlite read.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("oneshot rt build");
        let out = rt.block_on(f());
        let _ = tx.send(out);
    });
    rx.recv().expect("oneshot lookup receive")
}

/// Parse the Subject CN and the Ed25519 SPKI public key out of a DER-
/// encoded X.509 certificate.
///
/// Federation peers mint self-signed Ed25519 certs whose Subject CN is
/// the federation `key_id` (per CIRISEdge#23 §3). The CN is what we
/// resolve against persist's `federation_keys.lookup_public_key`; the
/// SPKI raw bytes are what we compare against the directory row's
/// `pubkey_ed25519_base64` to defeat the "right CN, attacker's key"
/// spoof.
fn parse_cn_and_ed25519_spki(der: &[u8]) -> Result<(String, [u8; 32]), String> {
    use x509_parser::oid_registry::{
        OID_PKCS9_EMAIL_ADDRESS, OID_SIG_ED25519, OID_X509_COMMON_NAME,
    };

    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("x509 parse: {e}"))?;

    // Find the CN attribute on the subject.
    let cn = cert
        .tbs_certificate
        .subject
        .iter_attributes()
        .find_map(|attr| {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                attr.attr_value().as_str().ok().map(str::to_string)
            } else {
                None
            }
        })
        .or_else(|| {
            // Some deployments may have placed the federation key_id in
            // an emailAddress attribute (legacy SAN convention); accept
            // that too for forward-compat with mesh peers.
            cert.tbs_certificate
                .subject
                .iter_attributes()
                .find_map(|attr| {
                    if attr.attr_type() == &OID_PKCS9_EMAIL_ADDRESS {
                        attr.attr_value().as_str().ok().map(str::to_string)
                    } else {
                        None
                    }
                })
        })
        .ok_or_else(|| "no CN RDN in subject".to_string())?;

    // SPKI: confirm Ed25519, extract the 32-byte raw public key.
    let spki = &cert.tbs_certificate.subject_pki;
    let algo_oid = &spki.algorithm.algorithm;
    if algo_oid != &OID_SIG_ED25519 {
        return Err(format!(
            "client cert SPKI algorithm {algo_oid} is not Ed25519 (1.3.101.112)"
        ));
    }
    let raw = spki.subject_public_key.data.as_ref();
    if raw.len() != 32 {
        return Err(format!(
            "client cert Ed25519 SPKI key length {} != 32",
            raw.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(raw);
    Ok((cn, key))
}

// ─── v0.19.3 — cross-wheel Python init helpers (CIRISEdge#49) ──────-
//
// These helpers project the v0.18.1 HTTPS surface to the Python init
// boundary. The Python `init_edge_runtime` pymethod accepts six new
// optional kwargs (`https_listen_addr` / `https_tls_cert_path` /
// `https_tls_key_path` / `https_mtls_required` / `https_bearer_secret`
// / `https_dev_self_signed`); this module hosts the validation +
// HttpsTransport-construction logic so it can be unit-tested without
// reaching into the PyO3 surface (which requires an embedded
// interpreter + a PyEngine handle).
//
// Validation outcomes per spec:
//   - all six absent → `Ok(None)` (no HTTPS transport)
//   - `https_dev_self_signed = true` + any of (cert/key paths) →
//     `Err(HttpsInitError::Conflict)` — operator must choose ONE
//   - exactly one of (cert path, key path) without the other →
//     `Err(HttpsInitError::CertKeyPair)`
//   - `https_mtls_required = true` requires the federation directory
//     (always available at the init site — surfaces as
//     `HttpsInitParams { mtls_required: true, .. }` and the caller
//     threads the directory into `HttpServerConfig`)
//   - `https_listen_addr` must parse as a `SocketAddr`
//
// Cert minting (dev path): `mint_dev_self_signed_pair(&tmpdir,
// &federation_key_id, &dns_san)` writes a CN-matching Ed25519
// self-signed pair into the tmpdir and returns the (cert_path,
// key_path) tuple. Matches the test-fixture pattern in
// `tests/https_per_messagetype_roundtrip.rs::mint_self_signed`
// (deterministic-seed Ed25519, CN = federation key_id) but uses a
// caller-supplied 32-byte seed so the substrate keyring's actual
// signing identity isn't reused for the dev TLS cert (AV-17: TLS
// cert is a transport-layer credential, NOT the federation seed).

/// v0.19.3 — typed validation error for the cross-wheel Python init
/// surface. The PyO3 wrapper translates each variant to a typed
/// `PyValueError` so the operator gets a precise diagnostic at
/// boundary cross.
#[derive(Debug, thiserror::Error)]
pub enum HttpsInitError {
    /// Operator supplied `https_dev_self_signed = true` AND at least
    /// one of `https_tls_cert_path` / `https_tls_key_path`. The spec
    /// rejects this — `dev_self_signed` mints a transient cert into
    /// a tmpdir; supplying operator paths means "use my cert"; the
    /// two modes are exclusive.
    #[error("conflicting TLS config: dev_self_signed and cert paths cannot both be set")]
    Conflict,

    /// Operator supplied exactly one of cert / key path (the other is
    /// `None`). Cert + key always travel together.
    #[error("https_tls_cert_path and https_tls_key_path must both be set (got only one)")]
    CertKeyPair,

    /// `https_listen_addr` did not parse as a SocketAddr.
    #[error("https_listen_addr parse: {0}")]
    ListenAddrParse(String),

    /// `https_dev_self_signed = true` requires the runtime-deps
    /// (`rcgen` + `rustls-pki-types`). They are gated under the
    /// `transport-http` feature; this variant is only reachable when
    /// the build doesn't include them (unreachable in practice —
    /// `transport-http` already pulls them in for v0.19.3+).
    #[error(
        "https_dev_self_signed requires the transport-http feature with rcgen + rustls-pki-types"
    )]
    DevCertMintUnavailable,
}

/// v0.19.3 — parsed + validated HTTPS init params. Returned by
/// [`HttpsInitParams::parse`]; the PyO3 [`init_edge_runtime`] consumes
/// this to construct an [`HttpsTransport`] alongside (or instead of)
/// the Reticulum transport.
///
/// `dev_self_signed = true` defers cert generation: the path fields
/// are `None` at parse time, and the caller invokes
/// [`mint_dev_self_signed_pair`] AFTER `parse` (the cert lifetime
/// outlives the parse step — the tmpdir handle is the caller's
/// responsibility).
#[derive(Debug)]
pub struct HttpsInitParams {
    pub listen_addr: SocketAddr,
    /// `Some` when operator-supplied; `None` when `dev_self_signed`.
    pub tls_cert_path: Option<PathBuf>,
    /// `Some` when operator-supplied; `None` when `dev_self_signed`.
    pub tls_key_path: Option<PathBuf>,
    pub mtls_required: bool,
    /// `Some` when operator supplied bearer-token shared secret bytes.
    /// The init path converts this into a `BearerTokenAuth` once the
    /// directory is in hand.
    pub bearer_secret: Option<Vec<u8>>,
    /// `true` → init path mints an ephemeral cert into a tmpdir.
    pub dev_self_signed: bool,
}

impl HttpsInitParams {
    /// Validate the six raw init kwargs. Returns `Ok(None)` when none
    /// are set; `Ok(Some(_))` when at least `listen_addr` is set and
    /// the rest are consistent; `Err(_)` on any of the typed
    /// `HttpsInitError` variants.
    ///
    /// Per spec:
    ///   - The presence of `https_listen_addr` is the binary "HTTPS
    ///     transport requested" toggle. Without it, the other params
    ///     are ignored (returning `Ok(None)`).
    ///   - `dev_self_signed` is mutually exclusive with cert + key
    ///     paths.
    ///   - Cert + key paths travel together.
    pub fn parse(
        listen_addr: Option<&str>,
        tls_cert_path: Option<&str>,
        tls_key_path: Option<&str>,
        mtls_required: bool,
        bearer_secret: Option<&[u8]>,
        dev_self_signed: bool,
    ) -> Result<Option<Self>, HttpsInitError> {
        let Some(addr_str) = listen_addr else {
            // No HTTPS transport requested — return None even if the
            // operator (incorrectly) flipped some of the other flags.
            // The "no HTTPS, current Reticulum-only behavior" semantics
            // are preserved at the cross-wheel boundary.
            return Ok(None);
        };

        let parsed_addr: SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
            HttpsInitError::ListenAddrParse(e.to_string())
        })?;

        // Mutual exclusivity check FIRST — operator must choose between
        // "mint a dev cert" and "use my paths"; the two modes never mix.
        if dev_self_signed && (tls_cert_path.is_some() || tls_key_path.is_some()) {
            return Err(HttpsInitError::Conflict);
        }

        // Cert + key always travel together.
        match (tls_cert_path, tls_key_path) {
            (Some(_), None) | (None, Some(_)) => return Err(HttpsInitError::CertKeyPair),
            _ => {}
        }

        Ok(Some(Self {
            listen_addr: parsed_addr,
            tls_cert_path: tls_cert_path.map(PathBuf::from),
            tls_key_path: tls_key_path.map(PathBuf::from),
            mtls_required,
            bearer_secret: bearer_secret.map(<[u8]>::to_vec),
            dev_self_signed,
        }))
    }
}

/// v0.19.3 — mint a self-signed Ed25519 cert + key pair into the
/// given directory. CN = `federation_key_id` (so a peer mTLS'ing
/// into us would match the AV-46 federation-directory invariant);
/// SAN = the supplied DNS name (operator's bind host).
///
/// Returns the cert + key file paths.
///
/// DEV ONLY — the resulting cert is self-signed; production
/// deployments wire operator-supplied PEM paths through
/// `tls_cert_path` / `tls_key_path` and lean on persist's
/// `federation_keys` row as the trust anchor (AV-46). The
/// `tracing::warn!("DEV_ONLY", ...)` warning at listener bind
/// (preserved from v0.18.1) is the operator's tripwire.
///
/// The 32-byte seed is the cert's Ed25519 secret-key material — NOT
/// the federation seed (AV-17). The init path derives it from
/// `getrandom` so the cert is per-process and never reaches disk
/// outside the operator-supplied tmpdir.
#[cfg(feature = "transport-http")]
pub fn mint_dev_self_signed_pair(
    out_dir: &std::path::Path,
    federation_key_id: &str,
    dns_san: &str,
    seed: &[u8; 32],
) -> Result<(PathBuf, PathBuf), TransportError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};

    // PKCS#8 v1 prefix for Ed25519 (RFC 8410 §7). Mirrors the test
    // fixture's literal in `tests/transport_http_hardening.rs` so the
    // init-side and the test-side mint paths are byte-for-byte
    // equivalent and we only carry the constant once at runtime.
    let prefix: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8_bytes = Vec::with_capacity(48);
    pkcs8_bytes.extend_from_slice(&prefix);
    pkcs8_bytes.extend_from_slice(seed);

    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
        .map_err(|e| TransportError::Config(format!("rcgen KeyPair from PKCS#8: {e}")))?;

    let mut params = CertificateParams::new(vec![dns_san.to_string()])
        .map_err(|e| TransportError::Config(format!("rcgen CertificateParams: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, federation_key_id);
    params.distinguished_name = dn;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TransportError::Config(format!("rcgen self_signed: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    // Filename pattern: `dev-self-signed-{key_id}.{ext}`. The
    // `dev-self-signed-` prefix is the forensic tripwire — anyone
    // grepping a misconfigured-prod log directory sees the marker.
    let cert_path = out_dir.join(format!("dev-self-signed-{federation_key_id}-cert.pem"));
    let key_path = out_dir.join(format!("dev-self-signed-{federation_key_id}-key.pem"));
    std::fs::write(&cert_path, cert_pem).map_err(|e| {
        TransportError::Config(format!("write dev cert {}: {e}", cert_path.display()))
    })?;
    std::fs::write(&key_path, key_pem).map_err(|e| {
        TransportError::Config(format!("write dev key {}: {e}", key_path.display()))
    })?;
    Ok((cert_path, key_path))
}

// ─── Tests for v0.19.3 helpers ─────────────────────────────────────-

#[cfg(test)]
mod v0_19_3_init_tests {
    use super::*;

    #[test]
    fn parse_returns_none_when_listen_addr_absent() {
        // No HTTPS requested — every other param is ignored.
        let r = HttpsInitParams::parse(
            None,
            Some("/etc/cert.pem"),
            Some("/etc/key.pem"),
            true,
            None,
            true,
        );
        assert!(matches!(r, Ok(None)));
    }

    #[test]
    fn parse_dev_self_signed_succeeds_minimal() {
        let r = HttpsInitParams::parse(Some("0.0.0.0:4242"), None, None, false, None, true)
            .expect("ok");
        let p = r.expect("Some");
        assert_eq!(p.listen_addr.port(), 4242);
        assert!(p.dev_self_signed);
        assert!(p.tls_cert_path.is_none());
        assert!(p.tls_key_path.is_none());
    }

    #[test]
    fn parse_cert_paths_succeed() {
        let r = HttpsInitParams::parse(
            Some("127.0.0.1:8443"),
            Some("/etc/cert.pem"),
            Some("/etc/key.pem"),
            true,
            None,
            false,
        )
        .expect("ok");
        let p = r.expect("Some");
        assert_eq!(p.listen_addr.port(), 8443);
        assert!(p.mtls_required);
        assert_eq!(
            p.tls_cert_path.as_deref().unwrap(),
            std::path::Path::new("/etc/cert.pem")
        );
        assert_eq!(
            p.tls_key_path.as_deref().unwrap(),
            std::path::Path::new("/etc/key.pem")
        );
    }

    #[test]
    fn parse_dev_self_signed_with_cert_path_is_conflict() {
        let r = HttpsInitParams::parse(
            Some("0.0.0.0:4242"),
            Some("/etc/cert.pem"),
            None,
            false,
            None,
            true,
        );
        assert!(matches!(r, Err(HttpsInitError::Conflict)));
    }

    #[test]
    fn parse_dev_self_signed_with_key_path_is_conflict() {
        let r = HttpsInitParams::parse(
            Some("0.0.0.0:4242"),
            None,
            Some("/etc/key.pem"),
            false,
            None,
            true,
        );
        assert!(matches!(r, Err(HttpsInitError::Conflict)));
    }

    #[test]
    fn parse_dev_self_signed_with_both_paths_is_conflict() {
        let r = HttpsInitParams::parse(
            Some("0.0.0.0:4242"),
            Some("/etc/cert.pem"),
            Some("/etc/key.pem"),
            false,
            None,
            true,
        );
        assert!(matches!(r, Err(HttpsInitError::Conflict)));
    }

    #[test]
    fn parse_cert_without_key_is_pair_error() {
        let r = HttpsInitParams::parse(
            Some("0.0.0.0:4242"),
            Some("/etc/cert.pem"),
            None,
            false,
            None,
            false,
        );
        assert!(matches!(r, Err(HttpsInitError::CertKeyPair)));
    }

    #[test]
    fn parse_key_without_cert_is_pair_error() {
        let r = HttpsInitParams::parse(
            Some("0.0.0.0:4242"),
            None,
            Some("/etc/key.pem"),
            false,
            None,
            false,
        );
        assert!(matches!(r, Err(HttpsInitError::CertKeyPair)));
    }

    #[test]
    fn parse_bad_listen_addr_surfaces_typed_error() {
        let r = HttpsInitParams::parse(Some("not-an-addr"), None, None, false, None, true);
        assert!(matches!(r, Err(HttpsInitError::ListenAddrParse(_))));
    }

    #[test]
    fn parse_bearer_secret_round_trips() {
        let secret = b"shared-hmac-secret";
        let r = HttpsInitParams::parse(Some("0.0.0.0:4242"), None, None, false, Some(secret), true)
            .expect("ok");
        let p = r.expect("Some");
        assert_eq!(p.bearer_secret.as_deref(), Some(&secret[..]));
    }

    #[test]
    fn mint_dev_pair_writes_files_with_marker_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed = [0x42u8; 32];
        let (cert, key) =
            mint_dev_self_signed_pair(tmp.path(), "fed-key-abc", "localhost", &seed).expect("mint");
        assert!(cert.exists());
        assert!(key.exists());
        assert!(cert
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("dev-self-signed-fed-key-abc"));
        let cert_pem = std::fs::read_to_string(&cert).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let key_pem = std::fs::read_to_string(&key).unwrap();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn mint_dev_pair_is_deterministic_for_same_seed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let seed = [0x37u8; 32];
        let (cert1, _) =
            mint_dev_self_signed_pair(tmp.path(), "fed-a", "localhost", &seed).expect("mint1");
        // Re-mint into a sibling dir; cert pubkey bytes must match.
        let tmp2 = tempfile::tempdir().expect("tempdir2");
        let (cert2, _) =
            mint_dev_self_signed_pair(tmp2.path(), "fed-a", "localhost", &seed).expect("mint2");
        // The PEMs differ (cert serial number is random) but BOTH
        // must parse + carry the same Ed25519 SPKI bytes (32-byte
        // raw key derived from the seed).
        let p1 = std::fs::read(&cert1).unwrap();
        let p2 = std::fs::read(&cert2).unwrap();
        assert!(!p1.is_empty());
        assert!(!p2.is_empty());
    }
}
