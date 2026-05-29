# HTTPS deployment guide (CIRISEdge#23, v0.18.1)

CIRISEdge ships three production-grade HTTPS auth surfaces, each
tailored to a deployment substrate. All three terminate in the same
`mpsc::Sender<InboundFrame>` sink that `Edge::run`'s
`dispatch_inbound` loop consumes, so every `MessageType::*` variant
round-trips byte-equivalent over the chosen path (no message-type
filtering at the HTTPS layer). Pick the section whose deployment
constraints match yours.

> **Mission anchor.** MISSION.md §1.4 names Reticulum as canonical;
> MISSION.md §1.5 names multi-medium reach as **not** a tier — HTTPS is
> production-grade-equivalent, not a degraded path. CIRIS Accord §I
> (Fidelity & Transparency) is the bar: operators choose the medium
> that fits their substrate without sacrificing wire fidelity.

---

## 1. Self-signed dev path

For local development, integration tests, and the per-MessageType
HTTPS round-trip suite (`tests/https_per_messagetype_roundtrip.rs`).
Mints an Ed25519 self-signed cert at runtime via the `rcgen` dev-
dependency; the cert's Subject CN equals the federation `key_id` so
the `FederationCnVerifier` invariant (CN + SPKI match a
`federation_keys` row) is satisfied without any post-processing.

**Threat-model invariants this path preserves**

- AV-43 (cohabitation): keying is process-internal; no seed reaches
  disk outside the test temp dir.
- AV-46 (peer-mgmt opinion-vs-attestation): self-signed peer identity
  is *operator opinion* — the cert is not federation-attested.
  Production must use the mTLS or bearer paths below.

**Wire-up snippet** (`tests/https_per_messagetype_roundtrip.rs`-style;
`src/transport/http.rs::HttpServerConfig::dev_self_signed = true`
loud-warns on listener bind via `tracing::warn!`):

```rust
use ciris_edge::transport::http::{HttpServerConfig, HttpsTransport};

let mut config = HttpServerConfig::new(
    "127.0.0.1:0".parse().unwrap(),
    "/tmp/dev-cert.pem".into(),
    "/tmp/dev-key.pem".into(),
);
config.dev_self_signed = true; // emits DEV_ONLY tracing::warn! on bind
let transport = HttpsTransport::new(Some(config), Default::default(), HashMap::new())?;
```

The `dev_self_signed` flag does **not** relax any verification — it is
a forensic / log marker so operator misconfiguration is loud (MISSION
§3 anti-pattern 6: fail-loud, no silent drops). Tests mint the cert
via `rcgen 0.13` (MIT / Apache-2.0; in dev-dependencies only; never
linked into the production wheel).

> **WARNING.** A `tls_cert` path under `tests/fixtures/` or any
> `target/test-*` directory MUST trigger an operator review before
> bind. Self-signed identity is appropriate only when both sides of
> the connection are under the same operator and `federation_keys`
> seeding happens out-of-band.

---

## 2. Production mTLS

For operator-deployed federation peers where TLS termination happens
on the edge host itself (no CDN, no L7 load balancer rewriting cert
chains). The operator mints an Ed25519 cert whose Subject CN equals
the federation `key_id` and whose SPKI public key bytes equal the
`federation_keys.pubkey_ed25519_base64` row (after base64 decode);
edge's `FederationCnVerifier`
(`src/transport/http.rs::FederationCnVerifier::verify_client_cert`)
rejects the handshake before any bytes reach the application layer
when either the CN is missing from persist or the SPKI bytes do not
match the row.

**Threat-model invariants this path preserves**

- AV-43 (cohabitation): the mTLS handshake key is per-host federation
  identity, derived from the host's keyring seed; not commingled with
  bearer-token signing material.
- AV-46 (peer-mgmt opinion-vs-attestation): mTLS verifier consults
  the federation-attested directory (persist's `federation_keys`),
  not the operator's local `TrustClass` opinion. Marking a peer
  `EdgePeerTrust::Blocked` does **not** revoke its mTLS handshake —
  that lives in persist's identity row, where federation attestation
  governs.

**Wire-up snippet**:

```rust
use std::sync::Arc;
use ciris_edge::transport::http::{HttpServerConfig, HttpsTransport};
use ciris_edge::verify::VerifyDirectory;

let mut config = HttpServerConfig::new(
    "0.0.0.0:8443".parse().unwrap(),
    "/etc/ciris/edge-cert.pem".into(),
    "/etc/ciris/edge-key.pem".into(),
);
config.mtls_required = true;
config.directory = Some(persist_directory.clone() as Arc<dyn VerifyDirectory>);
// Optional intermediate-CA chain validation on top of pubkey-pinning:
// config.mtls_ca_pool = Some("/etc/ciris/federation-ca-bundle.pem".into());
let transport = HttpsTransport::new(Some(config), Default::default(), HashMap::new())?;
```

The `FederationCnVerifier` does **not** walk a PKI chain by default —
federation identity is rooted in persist's directory, not a CA. A
self-signed cert with the right CN and matching pubkey IS the
federation primitive; the optional `mtls_ca_pool` is for deployments
that ALSO want CA-chain validation on top of pubkey-pinning.

> **WARNING.** Rotating the federation key requires re-issuing the
> mTLS cert with the new SPKI bytes AND updating the
> `federation_keys.pubkey_ed25519_base64` row through persist's
> standard rotation flow. A mismatch — old cert, new directory row —
> reads as the "right CN, attacker's key" spoofing case the verifier
> is designed to defeat, so the handshake will fail loudly with
> `rustls::Error::General("client cert CN=... SPKI does not match
> federation_keys.pubkey_ed25519_base64")`.

---

## 3. Production bearer-token (CDN-terminated)

For deployments where TLS termination happens upstream of edge — a
managed-Kubernetes ingress, a CDN, an L7 reverse proxy. The L7 hop
preserves TLS confidentiality from the client to the ingress, but the
hop from ingress to edge typically rides plain HTTP within a private
VPC and the client cert is stripped. The bearer token is a federation-
key-signed JWT (`Algorithm::EdDSA`, kid header = federation `key_id`)
that the edge verifier resolves against the same `federation_keys`
directory the mTLS path uses, so the cryptographic primitive (Ed25519
signature against a directory-rooted pubkey) is identical — only the
transport carrier differs.

**Threat-model invariants this path preserves**

- AV-43 (cohabitation): the JWT signing seed is the federation-key
  keyring seed; no separate "API key" material lives in operator
  storage.
- AV-46 (peer-mgmt opinion-vs-attestation): JWT verifier consults
  persist's federation-attested directory, not the operator's
  `TrustClass` opinion. A bearer-token-authenticated peer is a
  federation-attested identity; `EdgePeerTrust::Blocked` is a
  local policy filter applied after the token verifies.

**Wire-up snippet** (`mint_federation_jwt` is the sender-side helper;
`src/transport/http.rs::verify_bearer_token` is the receiver-side
verifier, consulted from `inbound_handler`):

```rust
use std::sync::Arc;
use ciris_edge::transport::http::{
    mint_federation_jwt, BearerTokenAuth, FederationJwtClaims,
    HttpServerConfig, HttpsTransport,
};
use ciris_edge::verify::VerifyDirectory;

// Server side: bearer-token-required listener.
let mut config = HttpServerConfig::new(
    "0.0.0.0:8443".parse().unwrap(),
    "/etc/ciris/edge-cert.pem".into(),
    "/etc/ciris/edge-key.pem".into(),
);
config.bearer_auth = Some(BearerTokenAuth {
    directory: persist_directory.clone() as Arc<dyn VerifyDirectory>,
    expected_audience: Some("ciris-edge-federation".into()),
});

// Client side: mint a JWT per outbound request (or on a refresh cadence).
let token = mint_federation_jwt(
    &my_key_id,
    &my_seed_ed25519,
    &FederationJwtClaims {
        iss: my_key_id.clone(),
        sub: my_key_id.clone(),
        iat: chrono::Utc::now().timestamp(),
        exp: chrono::Utc::now().timestamp() + 60,
        aud: Some("ciris-edge-federation".into()),
    },
)?;
// → set `Authorization: Bearer <token>` on the outbound request.
```

The JWT's `iss` claim MUST equal the header's `kid` (no third-party-
issued tokens; the federation key signs FOR ITSELF). The
`expected_audience` claim is optional — useful for cross-deployment
scoping (separate `ciris-edge-prod` / `ciris-edge-staging` audiences
prevent a staging-signed JWT from authenticating against production).

> **WARNING.** Bearer-token deployments inherit the AV-13 body-size
> ceiling (8 MiB) at the extractor layer the same way mTLS deployments
> do. The token itself rides the `Authorization` header, which the
> reqwest client emits per request; if the CDN strips or rewrites
> headers, the inbound bearer-token gate fires and returns 401 — same
> failure mode `tests/https_per_messagetype_roundtrip.rs::https_per_messagetype_bearer_rejects_missing_token`
> pins.

> **WARNING.** The mTLS + bearer interaction is documented in
> `src/transport/http.rs::HttpServerConfig` doc-comment: when BOTH are
> set, mTLS is the strong-auth path — a successful mTLS handshake
> satisfies authentication on its own, and the bearer-token path
> becomes the fallback for connections that landed WITHOUT mTLS
> (which `mtls_required = true` would already reject at handshake
> time, so in practice mTLS+bearer means "mTLS-only" with bearer-
> token reserved for a future mTLS-optional mode).

---

## 4. Per-MessageType wire completeness

Every `MessageType::*` variant the federation defines (25 at
v0.18.1) round-trips byte-equivalent over all three paths above —
pinned by `tests/https_per_messagetype_roundtrip.rs`. The
`all_message_types_have_https_round_trip_test` sanity check is the
maintenance gate: an exhaustive match on `MessageType` that fails to
compile if a new variant lands without a matching `#[tokio::test]`.

The HTTPS layer is fully byte-transparent — no per-type filtering, no
per-type rewriting. The verify pipeline (`Edge::run`'s
`dispatch_inbound` loop) is the single chokepoint that runs over
`InboundFrame::envelope_bytes` regardless of carrier; HTTPS, Reticulum,
and any future medium share that verification surface.

For the operator running an HTTPS-only deployment: the wire fidelity
contract is the same one Reticulum carries — what an HTTPS-served
peer sees is byte-equivalent to what a Reticulum-served peer sees,
and the verify pipeline catches the same set of canonicalization,
signature, and replay invariants.
