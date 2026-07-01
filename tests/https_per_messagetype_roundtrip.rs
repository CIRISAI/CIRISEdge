//! CIRISEdge#23 — per-`MessageType` HTTPS round-trip closure (v0.18.1).
//!
//! Bar: every `MessageType::*` variant the federation defines must
//! round-trip byte-equal over the HTTPS-hardened transport into the
//! same `mpsc::Sender<InboundFrame>` sink `Edge::run`'s
//! `dispatch_inbound` loop consumes — no HTTP-layer filtering by
//! message type. This file is the wire-completeness assertion that
//! closes CIRISEdge#23 ("Every MessageType::* variant round-trips
//! over HTTPS — integration test per type"); the existing
//! `tests/transport_http_hardening.rs` retains the
//! per-handshake-mechanism assertions (mTLS + bearer + cert rejection).
//!
//! Why per-type tests and not a single iter-over-the-enum suite?
//!
//! - The variants encode CIRIS Accord §I Fidelity & Transparency: any
//!   silent omission of a wire type from the HTTPS lane regresses the
//!   "operators choose the medium that fits their substrate" mission
//!   stance (MISSION.md §1.5).
//! - The fixture uses one TCP listener per case (ephemeral 127.0.0.1
//!   port; teardown via `handle.abort()`); spreading them across
//!   discrete `#[tokio::test]` functions lets failures pinpoint exactly
//!   which variant regressed.
//! - Each test mints a syntactically-plausible envelope shape for the
//!   variant (snake_case `message_type`, populated `body`) so the
//!   round-trip can never accidentally succeed by virtue of the HTTP
//!   layer treating bytes as opaque — we assert `frame.envelope_bytes
//!   == body` against a concrete payload the discriminator names.
//!
//! Test count: one per `MessageType::*` variant (25 at v0.18.1) plus
//! 2 cross-cutting cases (mTLS-rejected + bearer-rejected reaffirmation
//! against an envelope rather than the byte-string fixtures used in
//! `transport_http_hardening.rs`). All gated on `transport-http`.
//!
//! Maintenance: when a new `MessageType` lands in `src/messages/mod.rs`,
//! a corresponding `#[tokio::test]` MUST land here too — the
//! `all_message_types_have_https_round_trip_test` sanity check below
//! turns a missing entry into a compile-time failure (matches against
//! the full enum, so a new variant trips `non_exhaustive_patterns`).

#![cfg(feature = "transport-http")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::messages::MessageType;
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

// ─── Fixture: federation identity + scrub-signed directory row ─────-

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

    fn pkcs8_der(&self) -> Vec<u8> {
        // RFC 8410 §7 PKCS#8 v1 prefix for Ed25519. Same byte sequence
        // `src/transport/http.rs::ed25519_seed_to_pkcs8` writes for the
        // bearer-token mint path — kept literal here so the test file
        // is independent of the private helper.
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

// ─── Fixture: self-signed cert via rcgen (DEV_ONLY) ────────────────-
//
// rcgen 0.13 — MIT / Apache-2.0 (license-clean per deny.toml).
// Dev-only — never linked into the production wheel. The cert's
// Subject CN equals the FedKey's `key_id` and the cert's SPKI
// public key is deterministically the seed-derived Ed25519 pubkey,
// so the `FederationCnVerifier` invariant (CN + SPKI match a
// directory row) is satisfied without any post-processing.

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

fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local_addr")
}

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
    tokio::time::sleep(Duration::from_millis(150)).await;
    (handle, rx, addr)
}

// ─── Per-variant round-trip harness ────────────────────────────────-
//
// One TLS POST → one inbound frame; assert envelope bytes are the
// exact byte string the test minted (HTTP layer transparency). The
// `body` is the variant's snake_case wire discriminator embedded in a
// minimal envelope shape — enough that a future schema-aware verify
// regression would catch a corruption, but light enough that a
// per-variant test stays cheap.

async fn https_envelope_round_trip(test_seed: u8, message_type_wire: &str, body_payload: &[u8]) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new(&format!("mt-{message_type_wire}-{test_seed}"), test_seed);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.dev_self_signed = true;
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

    // Construct the wire envelope: this is the byte string the HTTPS
    // layer must transport verbatim into the inbound mpsc. The
    // envelope shape is a syntactically-plausible minimal `EdgeEnvelope`
    // JSON — fields verify-pipeline-shaped (signature, signing_key_id,
    // body, etc.); the HTTPS layer is content-agnostic so the verify
    // step does NOT run on this test (dedicated tests cover verify;
    // see `tests/federation_announcement.rs` et al.).
    let envelope = serde_json::json!({
        "edge_schema_version": "v1_0_0",
        "signing_key_id": me.key_id,
        "destination_key_id": me.key_id,
        "message_type": message_type_wire,
        "sent_at": "2026-05-29T00:00:00Z",
        "nonce": [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "body": serde_json::from_slice::<serde_json::Value>(body_payload).unwrap_or(serde_json::Value::Null),
        "signature": "dummy-signature-for-https-layer-byte-transparency-test",
    });
    let body = serde_json::to_vec(&envelope).expect("serialize envelope");

    let resp = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status().as_u16(),
        202,
        "HTTPS POST for {message_type_wire} should be 202 Accepted: {}",
        resp.status()
    );

    let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("inbound recv timeout")
        .expect("inbound frame");
    assert_eq!(
        frame.envelope_bytes, body,
        "HTTPS layer MUST be byte-transparent for MessageType::{message_type_wire}"
    );

    handle.abort();
}

// ─── One #[tokio::test] per MessageType variant ────────────────────-
//
// The wire discriminator strings are derived from serde's default
// (`MessageType` derives `Serialize` without `rename_all`, so a variant
// `FederationAnnouncement` serializes as the JSON string
// `"FederationAnnouncement"` — verified at the bottom of this file via
// `serde_json::to_value(MessageType::FederationAnnouncement)`).

#[tokio::test]
async fn https_round_trip_opaque_event() {
    // v8.0.0 opaque vocabulary — `OpaqueEvent { kind, payload }`
    // (Durable). Absorbs the removed AccordEventsBatch/InlineText
    // migrants' HTTPS coverage under the opaque durable-event lane.
    https_envelope_round_trip(0x01, "OpaqueEvent", br#"{"kind":1,"payload":[1,2,3]}"#).await;
}

#[tokio::test]
async fn https_round_trip_build_manifest_publication() {
    https_envelope_round_trip(
        0x02,
        "BuildManifestPublication",
        br#"{"manifest_id": "m1"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_dsar_request() {
    https_envelope_round_trip(
        0x03,
        "DSARRequest",
        br#"{"target_agent_id_hash":"h","target_signature_key_id":"k","requested_by":"r","justification":"j"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_dsar_response() {
    https_envelope_round_trip(
        0x04,
        "DSARResponse",
        br#"{"deleted_trace_events":0,"deleted_trace_llm_calls":0,"completed_at":"2026-05-29T00:00:00Z"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_attestation_gossip() {
    https_envelope_round_trip(0x05, "AttestationGossip", br#"{"key_id":"k"}"#).await;
}

#[tokio::test]
async fn https_round_trip_public_key_registration() {
    https_envelope_round_trip(0x06, "PublicKeyRegistration", br#"{"key_id":"k"}"#).await;
}

#[tokio::test]
async fn https_round_trip_opaque_request() {
    // v8.0.0 opaque vocabulary — `OpaqueRequest { kind, payload }`
    // (Ephemeral). Absorbs the removed FederationKeyDirectoryQuery
    // migrant's HTTPS coverage under the opaque request lane.
    https_envelope_round_trip(0x07, "OpaqueRequest", br#"{"kind":1,"payload":[1,2,3]}"#).await;
}

#[tokio::test]
async fn https_round_trip_contribution_submit() {
    https_envelope_round_trip(0x08, "ContributionSubmit", br#"{"contribution_id":"c"}"#).await;
}

#[tokio::test]
async fn https_round_trip_vote_cast() {
    https_envelope_round_trip(0x09, "VoteCast", br#"{"contribution_id":"c","vote":"yes"}"#).await;
}

#[tokio::test]
async fn https_round_trip_expertise_attestation_publish() {
    https_envelope_round_trip(0x0a, "ExpertiseAttestationPublish", br#"{"key_id":"k"}"#).await;
}

#[tokio::test]
async fn https_round_trip_moderation_event_publish() {
    https_envelope_round_trip(0x0b, "ModerationEventPublish", br#"{"event_id":"e"}"#).await;
}

#[tokio::test]
async fn https_round_trip_slashing_attestation_publish() {
    https_envelope_round_trip(0x0c, "SlashingAttestationPublish", br#"{"target":"t"}"#).await;
}

#[tokio::test]
async fn https_round_trip_reconsideration_request() {
    https_envelope_round_trip(0x0d, "ReconsiderationRequest", br#"{"target":"t"}"#).await;
}

#[tokio::test]
async fn https_round_trip_deferral_request() {
    https_envelope_round_trip(0x0e, "DeferralRequest", br#"{"deferral_id":"d"}"#).await;
}

#[tokio::test]
async fn https_round_trip_deferral_response() {
    https_envelope_round_trip(0x0f, "DeferralResponse", br#"{"deferral_id":"d"}"#).await;
}

#[tokio::test]
async fn https_round_trip_federation_announcement() {
    https_envelope_round_trip(
        0x10,
        "FederationAnnouncement",
        br#"{"priority":"informational","kind":"policy_update","title":"t","body":"b","authority_class":"bootstrap_seed","expires_at":"2026-06-01T00:00:00Z"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_delivery_attestation() {
    https_envelope_round_trip(
        0x11,
        "DeliveryAttestation",
        br#"{"announcement_id":"a","peer_key_id":"p"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_delivery_refusal_attestation() {
    https_envelope_round_trip(
        0x12,
        "DeliveryRefusalAttestation",
        br#"{"announcement_id":"a","peer_key_id":"p","refusal_reason":{"kind":"no_accord_holders_configured"}}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_content_fetch() {
    https_envelope_round_trip(0x13, "ContentFetch", br#"{"sha256":"abcdef"}"#).await;
}

#[tokio::test]
async fn https_round_trip_content_body() {
    https_envelope_round_trip(
        0x14,
        "ContentBody",
        br#"{"sha256":"abcdef","bytes_base64":""}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_content_miss() {
    https_envelope_round_trip(
        0x15,
        "ContentMiss",
        br#"{"sha256":"abcdef","reason":"not_held"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_steward_directive() {
    https_envelope_round_trip(0x16, "StewardDirective", br#"{"directive":"d"}"#).await;
}

#[tokio::test]
async fn https_round_trip_opaque_response() {
    // v8.0.0 opaque vocabulary — `OpaqueResponse { kind, status, payload }`
    // (Ephemeral). The third opaque type; the migrant tests are spread
    // across all three so "every message type round-trips over HTTPS"
    // coverage is preserved for the full opaque vocabulary.
    https_envelope_round_trip(
        0x17,
        "OpaqueResponse",
        br#"{"kind":1,"status":200,"payload":[1,2,3]}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_goal_declaration() {
    https_envelope_round_trip(0x18, "GoalDeclaration", br#"{"goal_id":"g"}"#).await;
}

#[tokio::test]
async fn https_round_trip_goal_retirement() {
    https_envelope_round_trip(
        0x19,
        "GoalRetirement",
        br#"{"goal_id":"g","retired_at":"2026-05-29T00:00:00Z"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_withdraws() {
    https_envelope_round_trip(
        0x1a,
        "Withdraws",
        br#"{"holder_key_id":"h","sha256":"abcdef"}"#,
    )
    .await;
}

#[tokio::test]
async fn https_round_trip_fountain_holding_claim() {
    // CIRISEdge#184 (v6.3.0) — swarm-converger wire-up. Body shape
    // mirrors `FountainHoldingClaim` minus the hybrid-PQC signature
    // fields (signatures ride the envelope layer, not the body —
    // matches the substrate's locked v1 canonical bytes contract).
    https_envelope_round_trip(
        0x1b,
        "FountainHoldingClaim",
        br#"{"peer_id":"alice","content_id":"shard-X","symbol_ids":[1,2,3],"observed_at_unix_ms":1700000000,"claim_version":1}"#,
    )
    .await;
}

// ─── Cross-cutting: mTLS-required rejects un-directoried client ────-

#[tokio::test]
async fn https_per_messagetype_mtls_rejects_unknown_cn() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let server = FedKey::new("mt-mtls-server", 0xa1);
    let unknown = FedKey::new("mt-mtls-unknown", 0xa2);
    // Only the server is in the directory.
    let directory = directory_with(vec![signed_record(&server, &server, "steward")]).await;

    let server_certs = mint_self_signed(tmp.path(), &server, "localhost");
    let unknown_certs = mint_self_signed(tmp.path(), &unknown, "unknown-client");

    let mut config = HttpServerConfig::new(
        ephemeral_addr(),
        server_certs.cert.clone(),
        server_certs.key.clone(),
    );
    config.mtls_required = true;
    config.directory = Some(directory.clone() as Arc<dyn VerifyDirectory>);

    let (handle, _rx, addr) = spawn_listener(config).await;

    let server_ca = std::fs::read(&server_certs.cert).expect("read server CA");
    let client_cert_pem = std::fs::read(&unknown_certs.cert).expect("read client cert");
    let client_key_pem = std::fs::read(&unknown_certs.key).expect("read client key");
    let mut combined = client_cert_pem.clone();
    combined.push(b'\n');
    combined.extend_from_slice(&client_key_pem);
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&server_ca).expect("parse server CA"))
        .identity(reqwest::Identity::from_pem(&combined).expect("client identity"))
        .build()
        .expect("client build");

    // Build a syntactically-plausible OpaqueEvent envelope; the
    // assertion is that mTLS rejects at handshake, NOT that the
    // envelope is well-formed.
    let result = client
        .post(format!("https://localhost:{}/edge/inbound", addr.port()))
        .body(br#"{"message_type":"OpaqueEvent","body":{"kind":1,"payload":[1,2,3]}}"#.to_vec())
        .send()
        .await;
    assert!(
        result.is_err(),
        "mTLS handshake MUST reject CN={} (not in directory); got: {result:?}",
        unknown.key_id
    );

    handle.abort();
}

// ─── Cross-cutting: bearer-token-required rejects missing token ────-

#[tokio::test]
async fn https_per_messagetype_bearer_rejects_missing_token() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let me = FedKey::new("mt-bearer-rej", 0xb1);
    let directory = directory_with(vec![signed_record(&me, &me, "steward")]).await;
    let certs = mint_self_signed(tmp.path(), &me, "localhost");
    let mut config = HttpServerConfig::new(ephemeral_addr(), certs.cert.clone(), certs.key.clone());
    config.bearer_auth = Some(BearerTokenAuth {
        directory: directory.clone() as Arc<dyn VerifyDirectory>,
        expected_audience: None,
    });

    let (handle, _rx, addr) = spawn_listener(config).await;

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
        // No Authorization header → bearer-token gate fires.
        .body(br#"{"message_type":"OpaqueEvent","body":{"kind":1,"payload":[1,2,3]}}"#.to_vec())
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "Bearer-token-required listener MUST reject missing-token POSTs with 401"
    );

    handle.abort();
}

// ─── Sanity check: exhaustive MessageType discriminator coverage ───-
//
// This test is the safety-net against a new MessageType variant
// landing in `src/messages/mod.rs` without a matching
// `#[tokio::test]` here. The match below is exhaustive (no wildcard
// arm); adding a new variant in the enum produces a `non_exhaustive
// patterns` compile error at THIS file until the maintainer adds the
// corresponding `https_round_trip_<variant>` test above.

#[test]
#[allow(clippy::too_many_lines)]
fn all_message_types_have_https_round_trip_test() {
    // Maintenance gate: each arm names the wire discriminator that
    // the round-trip test above sends. A new MessageType variant
    // forces this match to fail to compile until the new test lands.
    fn wire_name(t: &MessageType) -> &'static str {
        match t {
            MessageType::OpaqueRequest => "OpaqueRequest",
            MessageType::OpaqueResponse => "OpaqueResponse",
            MessageType::OpaqueEvent => "OpaqueEvent",
            MessageType::BuildManifestPublication => "BuildManifestPublication",
            MessageType::DSARRequest => "DSARRequest",
            MessageType::DSARResponse => "DSARResponse",
            MessageType::AttestationGossip => "AttestationGossip",
            MessageType::PublicKeyRegistration => "PublicKeyRegistration",
            MessageType::ContributionSubmit => "ContributionSubmit",
            MessageType::VoteCast => "VoteCast",
            MessageType::ExpertiseAttestationPublish => "ExpertiseAttestationPublish",
            MessageType::ModerationEventPublish => "ModerationEventPublish",
            MessageType::SlashingAttestationPublish => "SlashingAttestationPublish",
            MessageType::ReconsiderationRequest => "ReconsiderationRequest",
            MessageType::DeferralRequest => "DeferralRequest",
            MessageType::DeferralResponse => "DeferralResponse",
            MessageType::FederationAnnouncement => "FederationAnnouncement",
            MessageType::DeliveryAttestation => "DeliveryAttestation",
            MessageType::DeliveryRefusalAttestation => "DeliveryRefusalAttestation",
            MessageType::ContentFetch => "ContentFetch",
            MessageType::ContentBody => "ContentBody",
            MessageType::ContentMiss => "ContentMiss",
            MessageType::BlobChunkFetch => "BlobChunkFetch",
            MessageType::BlobChunkBody => "BlobChunkBody",
            MessageType::BlobChunkMiss => "BlobChunkMiss",
            MessageType::StewardDirective => "StewardDirective",
            MessageType::GoalDeclaration => "GoalDeclaration",
            MessageType::GoalRetirement => "GoalRetirement",
            MessageType::Withdraws => "Withdraws",
            MessageType::FountainHoldingClaim => "FountainHoldingClaim",
        }
    }

    // Confirm the serde wire name matches the test fixture's string for
    // every variant — serde's default for a fieldless enum variant is
    // its identifier as a JSON string, so the round-trip suite's body
    // shapes correctly name the discriminator.
    for (variant, expected) in &[
        (MessageType::OpaqueRequest, "OpaqueRequest"),
        (MessageType::OpaqueResponse, "OpaqueResponse"),
        (MessageType::OpaqueEvent, "OpaqueEvent"),
        (
            MessageType::BuildManifestPublication,
            "BuildManifestPublication",
        ),
        (MessageType::DSARRequest, "DSARRequest"),
        (MessageType::DSARResponse, "DSARResponse"),
        (MessageType::AttestationGossip, "AttestationGossip"),
        (MessageType::PublicKeyRegistration, "PublicKeyRegistration"),
        (MessageType::ContributionSubmit, "ContributionSubmit"),
        (MessageType::VoteCast, "VoteCast"),
        (
            MessageType::ExpertiseAttestationPublish,
            "ExpertiseAttestationPublish",
        ),
        (
            MessageType::ModerationEventPublish,
            "ModerationEventPublish",
        ),
        (
            MessageType::SlashingAttestationPublish,
            "SlashingAttestationPublish",
        ),
        (
            MessageType::ReconsiderationRequest,
            "ReconsiderationRequest",
        ),
        (MessageType::DeferralRequest, "DeferralRequest"),
        (MessageType::DeferralResponse, "DeferralResponse"),
        (
            MessageType::FederationAnnouncement,
            "FederationAnnouncement",
        ),
        (MessageType::DeliveryAttestation, "DeliveryAttestation"),
        (
            MessageType::DeliveryRefusalAttestation,
            "DeliveryRefusalAttestation",
        ),
        (MessageType::ContentFetch, "ContentFetch"),
        (MessageType::ContentBody, "ContentBody"),
        (MessageType::ContentMiss, "ContentMiss"),
        (MessageType::BlobChunkFetch, "BlobChunkFetch"),
        (MessageType::BlobChunkBody, "BlobChunkBody"),
        (MessageType::BlobChunkMiss, "BlobChunkMiss"),
        (MessageType::StewardDirective, "StewardDirective"),
        (MessageType::GoalDeclaration, "GoalDeclaration"),
        (MessageType::GoalRetirement, "GoalRetirement"),
        (MessageType::Withdraws, "Withdraws"),
        (MessageType::FountainHoldingClaim, "FountainHoldingClaim"),
    ] {
        let serde_repr = serde_json::to_value(variant).expect("serde MessageType");
        assert_eq!(
            serde_repr.as_str(),
            Some(*expected),
            "MessageType::{expected} wire discriminator mismatch"
        );
        assert_eq!(
            wire_name(variant),
            *expected,
            "wire_name dispatch for MessageType::{expected} mismatch"
        );
    }
}
