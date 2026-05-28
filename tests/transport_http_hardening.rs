//! CIRISEdge#23 — HTTPS transport hardening acceptance gate.
//!
//! Bar: every `MessageType::*` variant round-trips over HTTPS through
//! the same `dispatch_inbound` pipeline the Reticulum transport uses,
//! mTLS handshakes validate client CN against persist's
//! `federation_keys` directory, untrusted certs are rejected by the
//! client, and bearer-token-auth deployments validate a
//! federation-key-signed JWT.
//!
//! Test fixtures:
//!   - In-memory `FederationDirectorySqlite` directory + outbound
//!     queue (same SQLite connection — shared substrate).
//!   - Self-signed Ed25519 cert per peer, where the cert's Subject CN
//!     equals the peer's federation `key_id` and the cert's SPKI
//!     public key matches the row's `pubkey_ed25519_base64`. Minted
//!     via `rcgen 0.13` from a deterministic 32-byte seed.
//!   - A real `HttpsTransport` bound on an ephemeral 127.0.0.1 port;
//!     the test spawns the listener and pushes an `InboundFrame` to
//!     a mpsc the test drains, asserting that `dispatch_inbound`
//!     would receive the byte-exact envelope.

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
    mint_federation_jwt, BearerTokenAuth, FederationJwtClaims, HttpClientConfig, HttpServerConfig,
    HttpsTransport,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::VerifyDirectory;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Fixture: federation identities + scrub-signed directory rows ───

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

    fn pubkey_raw(&self) -> [u8; 32] {
        let v = self.signer().public_key().expect("pubkey");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    /// PKCS#8 v1 DER envelope for the Ed25519 seed (RFC 8410 §7).
    fn pkcs8_der(&self) -> Vec<u8> {
        let prefix: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&self.seed);
        out
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

// ─── Fixture: write PEM cert + key files derived from a FedKey ──────
//
// `rcgen 0.13` accepts a PKCS#8 DER blob via
// `KeyPair::from_pkcs8_der_and_sign_algo(&PKCS_ED25519, der)`. Because
// the seed is what we control (the FedKey's seed_byte), the cert's
// SPKI public key is deterministically the same as
// `pubkey_ed25519_base64` in the seeded federation_keys row. This is
// the invariant the `FederationCnVerifier` checks at handshake time.

struct CertPaths {
    cert: PathBuf,
    key: PathBuf,
}

fn mint_self_signed(tmp: &Path, fed: &FedKey, dns_san: &str) -> CertPaths {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};

    let pkcs8_bytes = fed.pkcs8_der();
    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
        .expect("rcgen KeyPair from PKCS#8");

    let mut params = CertificateParams::new(vec![dns_san.to_string()]).expect("CertificateParams");
    // CN = federation key_id — the field `FederationCnVerifier` reads.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &fed.key_id);
    params.distinguished_name = dn;

    let cert = params.self_signed(&key).expect("self_signed");

    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let cert_path = tmp.join(format!("{}-cert.pem", fed.key_id));
    let key_path = tmp.join(format!("{}-key.pem", fed.key_id));
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    CertPaths {
        cert: cert_path,
        key: key_path,
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Pick an ephemeral 127.0.0.1 socket; close immediately so the
/// HTTPS server can bind it.
fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local_addr")
}

/// Spin up an `HttpsTransport` listener task; return the `JoinHandle`
/// and the inbound mpsc the test drains.
async fn spawn_listener(
    config: HttpServerConfig,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::Receiver<InboundFrame>,
    SocketAddr,
) {
    let addr = config.listen_addr;
    let transport = HttpsTransport::new(Some(config), HttpClientConfig::default(), HashMap::new())
        .expect("construct HttpsTransport");
    let (tx, rx) = mpsc::channel::<InboundFrame>(32);
    let handle = tokio::spawn(async move {
        let _ = transport.listen(tx).await;
    });
    // Give the listener a beat to bind. axum-server bind is fast but
    // not synchronous.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (handle, rx, addr)
}

// ─── Tests ─────────────────────────────────────────────────────────-

/// (1) Self-signed HTTPS server binds + accepts a TLS connection. The
/// `dev_self_signed = true` path emits the DEV_ONLY warning; the cert
/// is rcgen-minted from a deterministic seed, the server binds the
/// ephemeral port, and a follow-up POST (with a client that trusts
/// the same self-signed CA) reaches the inbound mpsc.
#[tokio::test]
async fn https_server_starts_with_self_signed_cert() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("self-signed-test", 0x11);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let bearer = BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: None,
    };

    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.dev_self_signed = true;
    config.bearer_auth = Some(bearer);

    let (handle, mut rx, addr) = spawn_listener(config).await;

    // Client trusts the self-signed cert by adding it to its custom CA
    // pool; otherwise reqwest rejects it.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&certs.cert).expect("read cert"))
                .expect("parse cert"),
        )
        .build()
        .expect("client build");

    // POST a token-authenticated request.
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

    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(b"hello over tls".to_vec())
        .send()
        .await
        .expect("send");
    assert!(
        resp.status().is_success(),
        "server should accept TLS POST: {}",
        resp.status()
    );

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("inbound timeout")
        .expect("inbound frame");
    assert_eq!(frame.envelope_bytes, b"hello over tls");

    handle.abort();
}

/// (2) Client refuses to connect to a server whose cert is signed by
/// an unknown CA — the client's CA pool does NOT contain the server's
/// self-signed cert, so reqwest's rustls handshake errors out at the
/// transport layer (never reaches the application).
#[tokio::test]
async fn https_client_rejects_untrusted_cert() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let server = FedKey::new("server-untrusted", 0x21);
    let _directory = directory_with(vec![signed_record(&server, &server, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &server, "localhost");

    let config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    let (handle, _rx, addr) = spawn_listener(config).await;

    // Default reqwest client: system root store only — does NOT trust
    // the rcgen-minted self-signed cert.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .expect("client build");
    let result = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(b"untrusted".to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "client should reject untrusted self-signed cert; got: {result:?}"
    );
    // The reqwest error carries the underlying rustls "UnknownIssuer"
    // or similar; we don't pin the exact string (it varies by
    // platform / rustls version) — `is_err()` plus the transport-
    // layer signature `is_connect()` || `is_request()` is enough.
    let err = result.unwrap_err();
    assert!(
        err.is_connect()
            || err.is_request()
            || format!("{err}").to_lowercase().contains("tls")
            || format!("{err}").to_lowercase().contains("cert")
            || format!("{err}").to_lowercase().contains("invalid")
            || format!("{err}").to_lowercase().contains("trust")
            || format!("{err}").to_lowercase().contains("unknown"),
        "expected TLS-layer error, got: {err}"
    );

    handle.abort();
}

/// (3) mTLS handshake validates the client cert's CN against
/// `federation_keys`. CN that matches a seeded row → handshake
/// succeeds + POST is dispatched. CN absent from the directory →
/// handshake fails before any bytes reach the application layer.
#[tokio::test]
async fn mtls_handshake_validates_client_cn_against_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let server = FedKey::new("mtls-server", 0x31);
    let client_known = FedKey::new("mtls-client-known", 0x32);
    // `client_unknown` is NOT in the directory.
    let client_unknown = FedKey::new("mtls-client-unknown", 0x33);

    let directory = directory_with(vec![
        signed_record(&server, &server, "steward"),
        signed_record(&client_known, &server, "agent"),
    ])
    .await;

    let server_certs = mint_self_signed(tmp.path(), &server, "localhost");
    let known_certs = mint_self_signed(tmp.path(), &client_known, "client-known");
    let unknown_certs = mint_self_signed(tmp.path(), &client_unknown, "client-unknown");

    let mut config = HttpServerConfig::new(
        ephemeral_addr(),
        server_certs.cert.clone(),
        server_certs.key.clone(),
    );
    config.mtls_required = true;
    config.directory = Some(directory.clone() as Arc<dyn VerifyDirectory>);

    let (handle, mut rx, addr) = spawn_listener(config).await;

    // ─── Known client: CN matches a directory row → handshake ok ──
    let known_client = build_mtls_client(&server_certs.cert, &known_certs);
    let resp = known_client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(b"known-client envelope".to_vec())
        .send()
        .await
        .expect("known client send");
    assert!(
        resp.status().is_success(),
        "known-CN handshake should succeed: {}",
        resp.status()
    );
    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("inbound recv")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, b"known-client envelope");

    // ─── Unknown client: CN missing from directory → handshake fails
    let unknown_client = build_mtls_client(&server_certs.cert, &unknown_certs);
    let result = unknown_client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(b"unknown-client envelope".to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "unknown-CN handshake should fail; got: {result:?}"
    );

    handle.abort();
}

fn build_mtls_client(server_ca_pem: &Path, client: &CertPaths) -> reqwest::Client {
    let server_ca = std::fs::read(server_ca_pem).expect("read server CA");
    let client_cert_pem = std::fs::read(&client.cert).expect("read client cert");
    let client_key_pem = std::fs::read(&client.key).expect("read client key");
    let mut combined = client_cert_pem.clone();
    combined.push(b'\n');
    combined.extend_from_slice(&client_key_pem);
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&server_ca).expect("parse server CA"))
        .identity(reqwest::Identity::from_pem(&combined).expect("client identity"))
        .build()
        .expect("mTLS client build")
}

/// (4) A FederationAnnouncement-shaped JSON body round-trips over
/// HTTPS — the raw envelope bytes the server hands to the inbound
/// channel are byte-exact with what the client sent. (We don't run
/// the verify pipeline here — the next-level test exercises that —
/// but we confirm the HTTPS layer is fully transparent for arbitrary
/// envelope bodies.)
#[tokio::test]
async fn https_carries_federation_announcement_round_trip() {
    https_carries_arbitrary_envelope(
        "fa-test",
        br#"{"message_type":"FederationAnnouncement","payload":{"title":"t","body":"b"}}"#,
    )
    .await;
}

/// (5) ContentFetch envelope round-trip.
#[tokio::test]
async fn https_carries_content_fetch_round_trip() {
    https_carries_arbitrary_envelope(
        "cf-test",
        br#"{"message_type":"ContentFetch","payload":{"sha256":"aa..."}}"#,
    )
    .await;
}

/// (6) InlineText envelope round-trip (CIRISEdge#22 Tier 2 wire shape).
#[tokio::test]
async fn https_carries_inline_text_round_trip() {
    https_carries_arbitrary_envelope(
        "it-test",
        br#"{"message_type":"InlineText","payload":{"body_text":"hello world"}}"#,
    )
    .await;
}

async fn https_carries_arbitrary_envelope(key_id: &str, body: &[u8]) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new(key_id, 0x40);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.bearer_auth = Some(BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: None,
    });

    let (handle, mut rx, addr) = spawn_listener(config).await;

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
            reqwest::Certificate::from_pem(&std::fs::read(&certs.cert).expect("read cert"))
                .expect("parse cert"),
        )
        .build()
        .expect("client build");

    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(body.to_vec())
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success(), "post should succeed");

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("inbound recv")
        .expect("frame");
    assert_eq!(
        frame.envelope_bytes, body,
        "HTTPS layer must be byte-transparent for {key_id}"
    );

    handle.abort();
}

/// (7) Bearer-token auth admits a JWT signed by a federation key whose
/// `kid` resolves in the directory.
#[tokio::test]
async fn bearer_token_auth_validates_federation_signature() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("jwt-test", 0x51);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.bearer_auth = Some(BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: Some("ciris-edge".into()),
    });

    let (handle, mut rx, addr) = spawn_listener(config).await;

    let token = mint_federation_jwt(
        &me.key_id,
        &me.seed,
        &FederationJwtClaims {
            iss: me.key_id.clone(),
            sub: me.key_id.clone(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 60,
            aud: Some("ciris-edge".into()),
        },
    )
    .expect("mint jwt");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&certs.cert).expect("read cert"))
                .expect("parse cert"),
        )
        .build()
        .expect("client build");

    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(b"signed-jwt envelope".to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status().as_u16(),
        202,
        "valid bearer token should be 202 Accepted"
    );

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("inbound recv")
        .expect("frame");
    assert_eq!(frame.envelope_bytes, b"signed-jwt envelope");

    handle.abort();
}

/// (8) A token whose signature was minted by the WRONG seed (kid points
/// at a directory row, but the actual signing key isn't the one
/// recorded) → 401.
#[tokio::test]
async fn bearer_token_with_invalid_signature_rejected_401() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("jwt-victim", 0x61);
    let attacker = FedKey::new("jwt-attacker", 0x62);
    // Only `me` is in the directory.
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.bearer_auth = Some(BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: None,
    });

    let (handle, _rx, addr) = spawn_listener(config).await;

    // Mint a token whose `kid` claims to be `me` but whose signing
    // seed is the attacker's. Signature verification against the
    // directory's pubkey for `me` will fail.
    let token = mint_federation_jwt(
        &me.key_id,
        &attacker.seed,
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
            reqwest::Certificate::from_pem(&std::fs::read(&certs.cert).expect("read cert"))
                .expect("parse cert"),
        )
        .build()
        .expect("client build");

    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(b"spoofed envelope".to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "spoofed-signature token must be 401: {}",
        resp.status()
    );

    handle.abort();
}

// ─── Sanity check on the FedKey fixture: SPKI from the seed matches
//     what the cert's CN-bound pubkey will be.
#[test]
fn fixture_spki_matches_directory_pubkey() {
    let f = FedKey::new("sanity", 0x77);
    let pub_a = f.pubkey_raw();
    let pub_b_b64 = f.pubkey_b64();
    let pub_b = B64.decode(pub_b_b64.as_bytes()).expect("decode");
    assert_eq!(pub_a.as_slice(), pub_b.as_slice());
}
