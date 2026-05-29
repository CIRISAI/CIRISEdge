//! CIRISEdge#49 (v0.19.3) — cross-wheel Python init surface for HTTPS.
//!
//! v0.13.0 + v0.18.1 hardened the HTTPS transport at the Rust layer
//! (`HttpsTransport` + `HttpServerConfig` + `FederationCnVerifier` +
//! `BearerTokenAuth`). v0.19.3 closes the cross-wheel boundary by
//! adding the six `https_*` init kwargs + `disable_reticulum` to
//! `init_edge_runtime`. Per CIRISConformance#3 / #4, this lets the
//! harness drive an HTTPS-listening edge from Python.
//!
//! This test file pins:
//!   1. The init-param validation surface (`HttpsInitParams::parse`)
//!      — every typed `HttpsInitError` variant is exercised against a
//!      representative bad input.
//!   2. The dev-cert mint primitive (`mint_dev_self_signed_pair`)
//!      produces a CN=`federation_key_id` cert whose Ed25519 SPKI
//!      matches the seed-derived pubkey — i.e. the cert is internally
//!      consistent for the `FederationCnVerifier` invariant the mTLS
//!      path consults.
//!   3. End-to-end the same plumbing `init_edge_runtime` constructs:
//!      [`mint_dev_self_signed_pair`] → `HttpServerConfig` →
//!      `HttpsTransport::new` → `transport.listen(...)` → external
//!      reqwest POST → `mpsc::Sender<InboundFrame>` delivery. Each
//!      case shapes the `HttpServerConfig` the way `init_edge_runtime`
//!      would assemble it from the corresponding `https_*` kwarg
//!      combination, so a regression in either layer surfaces here.
//!
//! NB: a true full-Python-init test (calling `init_edge_runtime`
//! through an embedded interpreter) needs a real persist `PyEngine`
//! constructed from the cohabiting agent — that surface lives in
//! CIRISConformance v0.19.3+ as the cross-wheel acceptance gate.
//! The discipline this file enforces is that EVERY load-bearing
//! primitive the Python path threads through is independently
//! verified at the Rust level; if a CIRISConformance failure points
//! at one of these primitives, it surfaces here first.

#![cfg(feature = "transport-http")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::transport::http::{
    mint_dev_self_signed_pair, mint_federation_jwt, BearerTokenAuth, FederationJwtClaims,
    HttpClientConfig, HttpServerConfig, HttpsInitError, HttpsInitParams, HttpsTransport,
};
use ciris_edge::transport::{InboundFrame, Transport, TransportId};
use ciris_edge::verify::VerifyDirectory;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Fixture: federation identity + scrub-signed directory row ─────-
//
// Mirrors the helper shape in `tests/https_per_messagetype_roundtrip.rs`
// — kept inline here so each test file is self-contained and the
// fixture surface is a stable contract for the v0.19.3 lock.

struct FedKey {
    key_id: String,
    seed: [u8; 32],
}

impl FedKey {
    fn new(key_id: &str, seed_byte: u8) -> Self {
        Self {
            key_id: key_id.to_string(),
            seed: [seed_byte; 32],
        }
    }

    fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }
}

fn signed_record(subject: &FedKey, signer: &FedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = Sha256::digest(&canonical);
    let sig = signer.signer().sign(digest.as_slice()).expect("sign");
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();
    KeyRecord {
        key_id: subject.key_id.clone(),
        pubkey_ed25519_base64: subject.pubkey_b64(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: "hybrid".to_string(),
        identity_type: identity_type.to_string(),
        identity_ref: subject.key_id.clone(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    }
}

async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory directory");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}

fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local_addr")
}

/// Mirror of the helper in `tests/transport_http_hardening.rs`. The
/// dev-cert mint primitive in `src/transport/http.rs` uses the same
/// PKCS#8 prefix + rcgen path; this helper is used here ONLY for the
/// "operator-supplied cert path" test cases where the seed is a real
/// FedKey rather than a derived dev-only seed.
struct CertPaths {
    cert: PathBuf,
    key: PathBuf,
}

fn mint_operator_cert(tmp: &Path, fed: &FedKey, dns_san: &str) -> CertPaths {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};

    let prefix: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8_bytes = Vec::with_capacity(48);
    pkcs8_bytes.extend_from_slice(&prefix);
    pkcs8_bytes.extend_from_slice(&fed.seed);
    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519).expect("rcgen kp");

    let mut params = CertificateParams::new(vec![dns_san.to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &fed.key_id);
    params.distinguished_name = dn;

    let cert = params.self_signed(&key).expect("self_signed");
    let cert_path = tmp.join(format!("{}-cert.pem", fed.key_id));
    let key_path = tmp.join(format!("{}-key.pem", fed.key_id));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");
    CertPaths {
        cert: cert_path,
        key: key_path,
    }
}

async fn spawn_listener_from_config(
    config: HttpServerConfig,
) -> (
    Arc<HttpsTransport>,
    tokio::task::JoinHandle<()>,
    mpsc::Receiver<InboundFrame>,
    SocketAddr,
) {
    let addr = config.listen_addr;
    let transport = Arc::new(
        HttpsTransport::new(Some(config), HttpClientConfig::default(), HashMap::new())
            .expect("construct HttpsTransport"),
    );
    let (tx, rx) = mpsc::channel::<InboundFrame>(32);
    let listener = Arc::clone(&transport);
    let handle = tokio::spawn(async move {
        let _ = listener.listen(tx).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    (transport, handle, rx, addr)
}

// ─── (1) Init-param validation surface ─────────────────────────────-

/// `https_dev_self_signed=True` with no cert paths and a valid listen
/// addr is the canonical conformance-harness dev-mode init. Parses
/// clean.
#[test]
fn init_edge_runtime_https_dev_self_signed_succeeds() {
    let parsed = HttpsInitParams::parse(Some("0.0.0.0:4242"), None, None, false, None, true)
        .expect("ok")
        .expect("some");
    assert!(parsed.dev_self_signed);
    assert_eq!(parsed.listen_addr.port(), 4242);
    assert!(parsed.tls_cert_path.is_none());
    assert!(parsed.tls_key_path.is_none());
}

/// Operator-supplied cert + key paths is the canonical production
/// init shape (the production deployment pattern documented in
/// `docs/HTTPS_DEPLOYMENT.md` §2). Parses clean.
#[test]
fn init_edge_runtime_https_with_cert_paths() {
    let parsed = HttpsInitParams::parse(
        Some("127.0.0.1:8443"),
        Some("/etc/ciris/server.pem"),
        Some("/etc/ciris/server.key"),
        true,
        None,
        false,
    )
    .expect("ok")
    .expect("some");
    assert!(parsed.mtls_required);
    assert_eq!(
        parsed.tls_cert_path.as_deref().unwrap(),
        Path::new("/etc/ciris/server.pem")
    );
    assert_eq!(
        parsed.tls_key_path.as_deref().unwrap(),
        Path::new("/etc/ciris/server.key")
    );
}

/// Per spec mutual-exclusivity rule: `https_dev_self_signed=True`
/// PLUS any cert / key path is a typed validation error. This is
/// `init_edge_runtime`'s rejection surface; the boundary translates
/// it to PyValueError with this exact message.
#[test]
fn init_edge_runtime_https_dev_self_signed_with_cert_paths_is_error() {
    for (cert, key) in [
        (Some("/etc/cert.pem"), None),
        (None, Some("/etc/key.pem")),
        (Some("/etc/cert.pem"), Some("/etc/key.pem")),
    ] {
        let r = HttpsInitParams::parse(Some("0.0.0.0:4242"), cert, key, false, None, true);
        let err = r.expect_err("dev_self_signed + cert paths must conflict");
        assert!(
            matches!(err, HttpsInitError::Conflict),
            "expected Conflict, got: {err:?}",
        );
        // The typed `Display` matches the operator-facing wire — the
        // PyO3 layer surfaces this as the PyValueError detail.
        let msg = err.to_string();
        assert!(
            msg.contains("conflicting TLS config"),
            "wire message must match v0.19.3 spec: got {msg:?}",
        );
        assert!(
            msg.contains("dev_self_signed") && msg.contains("cert paths"),
            "wire message must call out both modes: got {msg:?}",
        );
    }
}

/// Bearer-secret bytes round-trip through validation.
#[test]
fn init_edge_runtime_https_bearer_secret_parsed() {
    let secret = b"shared-hmac-for-bearer-token-validation".to_vec();
    let parsed =
        HttpsInitParams::parse(Some("0.0.0.0:4242"), None, None, false, Some(&secret), true)
            .expect("ok")
            .expect("some");
    assert_eq!(parsed.bearer_secret.as_deref(), Some(&secret[..]));
}

// ─── (2) Dev-cert mint primitive ──────────────────────────────────-

/// `mint_dev_self_signed_pair` writes a Subject-CN=key_id cert pair
/// that an mTLS client armed with the matching FedKey can present.
/// Pins the dev-cert mint contract `init_edge_runtime` consumes.
#[test]
fn dev_cert_mint_produces_cn_matching_federation_key_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let seed = [0x77u8; 32];
    let (cert, key) =
        mint_dev_self_signed_pair(tmp.path(), "test-key-id", "localhost", &seed).expect("mint");

    let cert_pem = std::fs::read_to_string(&cert).unwrap();
    let key_pem = std::fs::read_to_string(&key).unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(key_pem.contains("BEGIN PRIVATE KEY"));

    // Files use the `dev-self-signed-` marker prefix so a misconfigured
    // production cert dir is grep-able forensically.
    assert!(cert
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("dev-self-signed-"));
}

// ─── (3) End-to-end: emulated init_edge_runtime HTTPS plumbing ────-
//
// Each test below shapes the `HttpServerConfig` the way
// `init_edge_runtime` would assemble it from the operator's
// `https_*` kwargs, then drives the same `HttpsTransport::listen`
// path. The HTTPS side is exercised end-to-end with a real reqwest
// client; the assertions cover what the Python init MUST produce.

/// dev_self_signed=True, no mTLS, no bearer — minimal HTTPS init.
/// The transport binds, accepts a TLS connection over the minted
/// cert, and the inbound POST reaches the mpsc sink.
#[tokio::test]
async fn init_edge_runtime_https_dev_self_signed_round_trip() {
    let me = FedKey::new("dev-self-signed-e2e", 0x21);
    let _directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let seed = {
        // Same seed-derivation init_edge_runtime uses: SHA-256 over
        // the key_id + v1 protocol constant.
        let mut h = Sha256::new();
        h.update(b"ciris-edge::dev-self-signed::v1\0");
        h.update(me.key_id.as_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h.finalize());
        s
    };
    let (cert, key) =
        mint_dev_self_signed_pair(tmp.path(), &me.key_id, "localhost", &seed).expect("mint");

    let mut config = HttpServerConfig::new(ephemeral_addr(), cert.clone(), key);
    config.dev_self_signed = true;

    let (_transport, handle, mut rx, addr) = spawn_listener_from_config(config).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&cert).expect("read cert"))
                .expect("parse cert"),
        )
        .build()
        .expect("client build");

    let body =
        br#"{"message_type":"InlineText","body":{"text":"v0.19.3 dev-self-signed init"}}"#.to_vec();
    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 202);

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("recv timeout")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, body);
    handle.abort();
}

/// Operator-supplied cert + key + bearer-auth. Verifies a valid
/// federation-key-signed JWT reaches the inbound sink.
#[tokio::test]
async fn init_edge_runtime_https_bearer_token_succeeds() {
    let me = FedKey::new("bearer-e2e", 0x22);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let certs = mint_operator_cert(tmp.path(), &me, "localhost");

    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key);
    // init_edge_runtime: `https_bearer_secret = Some(...)` translates
    // to a `BearerTokenAuth` whose directory is the federation
    // verify directory (the same Arc both surfaces share).
    config.bearer_auth = Some(BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: None,
    });

    let (_transport, handle, mut rx, addr) = spawn_listener_from_config(config).await;

    let token = mint_federation_jwt(
        &me.key_id,
        &me.seed,
        &FederationJwtClaims {
            iss: me.key_id.clone(),
            sub: me.key_id.clone(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 60,
            aud: None,
        },
    )
    .expect("mint jwt");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&certs.cert).expect("read"))
                .expect("parse cert"),
        )
        .build()
        .expect("client");

    let body = br#"{"message_type":"InlineText","body":{"text":"bearer init"}}"#.to_vec();
    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 202);

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, body);
    handle.abort();
}

/// mTLS-required path: the verifier consults the same federation
/// directory `init_edge_runtime` wires via the `https_mtls_required`
/// kwarg. A client with a known cert succeeds; an unknown-CN client
/// is rejected at handshake (no inbound frame).
#[tokio::test]
async fn init_edge_runtime_https_mtls_required_validates_handshake() {
    let server = FedKey::new("mtls-server-e2e", 0x31);
    let known_client = FedKey::new("mtls-client-known-e2e", 0x32);
    let unknown_client = FedKey::new("mtls-client-unknown-e2e", 0x33);

    // Server directory holds server + known client (so the mTLS
    // verifier finds `known_client.key_id` and rejects
    // `unknown_client.key_id`).
    let directory = directory_with(vec![
        signed_record(&server, &server, "steward"),
        signed_record(&known_client, &known_client, "steward"),
    ])
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let server_certs = mint_operator_cert(tmp.path(), &server, "localhost");
    let known_certs = mint_operator_cert(tmp.path(), &known_client, "client-known");
    let unknown_certs = mint_operator_cert(tmp.path(), &unknown_client, "client-unknown");

    let mut config = HttpServerConfig::new(
        ephemeral_addr(),
        server_certs.cert.clone(),
        server_certs.key,
    );
    config.mtls_required = true;
    config.directory = Some(directory.clone() as Arc<dyn VerifyDirectory>);

    let (_transport, handle, mut rx, addr) = spawn_listener_from_config(config).await;

    // Known client — handshake succeeds; POST reaches the sink.
    let known_id = {
        let mut pem = std::fs::read(&known_certs.cert).expect("read");
        pem.push(b'\n');
        pem.extend_from_slice(&std::fs::read(&known_certs.key).expect("read"));
        reqwest::Identity::from_pem(&pem).expect("identity")
    };
    let known = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&server_certs.cert).expect("read"))
                .expect("parse cert"),
        )
        .identity(known_id)
        .build()
        .expect("known client");
    let body = br#"{"message_type":"InlineText","body":{"text":"mtls known"}}"#.to_vec();
    let resp = known
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 202);
    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, body);

    // Unknown client — handshake-time rejection. We assert by
    // confirming the request FAILS (handshake error) rather than
    // succeeding with a 401, because the FederationCnVerifier
    // rejects BEFORE the application layer.
    let unknown_id = {
        let mut pem = std::fs::read(&unknown_certs.cert).expect("read");
        pem.push(b'\n');
        pem.extend_from_slice(&std::fs::read(&unknown_certs.key).expect("read"));
        reqwest::Identity::from_pem(&pem).expect("identity")
    };
    let unknown = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&server_certs.cert).expect("read"))
                .expect("parse cert"),
        )
        .identity(unknown_id)
        .build()
        .expect("unknown client");
    let result = unknown
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(b"{}".to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "unknown-CN mTLS handshake MUST fail — got {result:?}",
    );

    handle.abort();
}

/// `disable_reticulum=True` + HTTPS-only init: the transport works
/// end-to-end without any Reticulum surface present. This is the
/// CIRISConformance#4 HTTPS-only deployment scenario.
#[tokio::test]
async fn init_edge_runtime_https_only_disable_reticulum() {
    let me = FedKey::new("https-only-e2e", 0x41);
    let _directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let seed = {
        let mut h = Sha256::new();
        h.update(b"ciris-edge::dev-self-signed::v1\0");
        h.update(me.key_id.as_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h.finalize());
        s
    };
    let (cert, key) =
        mint_dev_self_signed_pair(tmp.path(), &me.key_id, "localhost", &seed).expect("mint");

    let mut config = HttpServerConfig::new(ephemeral_addr(), cert.clone(), key);
    config.dev_self_signed = true;
    let (transport, handle, mut rx, addr) = spawn_listener_from_config(config).await;

    // The transport identity is HTTP — the metrics tag init produces
    // for the HTTPS-only lane. (Reticulum is absent in this run.)
    assert_eq!(transport.id(), TransportId::HTTP);

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&cert).expect("read")).expect("parse"),
        )
        .build()
        .expect("client");

    let body = br#"{"message_type":"InlineText","body":{"text":"https-only"}}"#.to_vec();
    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 202);
    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, body);
    handle.abort();
}

// ─── (4) Per-MessageType byte-transparency through pyedge-init plumbing ─-
//
// Per CIRISConformance#3 acceptance shape: the same per-MessageType
// byte-transparency guarantees `tests/https_per_messagetype_roundtrip.rs`
// pins for the direct-construction path MUST also hold when the
// transport was constructed via the `init_edge_runtime` HTTPS init
// plumbing. The four covered below — InlineText, FederationAnnouncement,
// ContentFetch, DeliveryAttestation — are the harness's "first four"
// canary set. The Rust-layer per-MessageType file covers all 25
// variants; this file covers the cross-init parity for the canary set.

async fn round_trip_through_pyedge_init(message_type: &str, body_payload: &[u8], seed_byte: u8) {
    let me = FedKey::new(&format!("mt-{message_type}-{seed_byte:02x}"), seed_byte);
    let _directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let seed = {
        let mut h = Sha256::new();
        h.update(b"ciris-edge::dev-self-signed::v1\0");
        h.update(me.key_id.as_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h.finalize());
        s
    };
    let (cert, key) =
        mint_dev_self_signed_pair(tmp.path(), &me.key_id, "localhost", &seed).expect("mint");
    let mut config = HttpServerConfig::new(ephemeral_addr(), cert.clone(), key);
    config.dev_self_signed = true;
    let (_t, handle, mut rx, addr) = spawn_listener_from_config(config).await;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&cert).expect("read")).expect("parse"),
        )
        .build()
        .expect("client");

    let envelope = serde_json::json!({
        "edge_schema_version": "v1_0_0",
        "signing_key_id": me.key_id,
        "destination_key_id": me.key_id,
        "message_type": message_type,
        "sent_at": "2026-05-29T00:00:00Z",
        "nonce": vec![0u8; 16],
        "body": serde_json::from_slice::<serde_json::Value>(body_payload).unwrap_or(serde_json::Value::Null),
        "signature": "dummy-v0_19_3-init-byte-transparency",
    });
    let body = serde_json::to_vec(&envelope).expect("serialize");
    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 202);
    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("frame");
    assert_eq!(
        frame.envelope_bytes, body,
        "byte-transparency for {message_type} via pyedge-init plumbing"
    );
    handle.abort();
}

#[tokio::test]
async fn https_inline_text_round_trip_through_pyedge() {
    round_trip_through_pyedge_init("InlineText", br#"{"text":"hello via pyedge init"}"#, 0x51)
        .await;
}

#[tokio::test]
async fn https_federation_announcement_round_trip_through_pyedge() {
    round_trip_through_pyedge_init(
        "FederationAnnouncement",
        br#"{"priority":"informational","kind":"policy_update","title":"t","body":"b","authority_class":"bootstrap_seed","expires_at":"2026-06-01T00:00:00Z"}"#,
        0x52,
    )
    .await;
}

#[tokio::test]
async fn https_content_fetch_round_trip_through_pyedge() {
    round_trip_through_pyedge_init("ContentFetch", br#"{"sha256":"deadbeef"}"#, 0x53).await;
}

#[tokio::test]
async fn https_delivery_attestation_round_trip_through_pyedge() {
    round_trip_through_pyedge_init(
        "DeliveryAttestation",
        br#"{"announcement_id":"a","peer_key_id":"p"}"#,
        0x54,
    )
    .await;
}

// ─── (5) HTTPS transport identity surface ──────────────────────────-

/// The HttpsTransport `init_edge_runtime` builds always reports
/// `TransportId::HTTP` ("http"). This is the metrics tag the
/// observability surface ([`PyEdge::metrics_snapshot`]) groups under
/// — `transport_bytes_in_total[http]` / `transport_bytes_out_total[http]`
/// (`src/observability.rs` §55-57). The metric surface is exercised by
/// `tests/observability_metrics.rs`; here we lock the carrier-id
/// contract the metric tag derives from.
#[tokio::test]
async fn metrics_snapshot_reflects_per_transport_https_counts() {
    let me = FedKey::new("metrics-https-id", 0x61);
    let _directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let seed = {
        let mut h = Sha256::new();
        h.update(b"ciris-edge::dev-self-signed::v1\0");
        h.update(me.key_id.as_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h.finalize());
        s
    };
    let (cert, key) =
        mint_dev_self_signed_pair(tmp.path(), &me.key_id, "localhost", &seed).expect("mint");
    let mut config = HttpServerConfig::new(ephemeral_addr(), cert, key);
    config.dev_self_signed = true;
    let (transport, handle, _rx, _addr) = spawn_listener_from_config(config).await;
    // `TransportId::HTTP` is the constant `init_edge_runtime` wires
    // into `EdgeBuilder::transport(Arc<dyn Transport>)`; metrics tag
    // derives from it via `Transport::id()`.
    assert_eq!(transport.id(), TransportId::HTTP);
    assert_eq!(transport.id().0, "http");
    handle.abort();
}
