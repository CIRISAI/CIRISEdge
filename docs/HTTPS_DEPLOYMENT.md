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

---

## 5. Driving HTTPS from the Python init surface (v0.19.3)

v0.13.0 + v0.18.1 made HTTPS production-grade at the **Rust layer**.
v0.19.3 (CIRISEdge#49) exposes the same surface at the **cross-wheel
Python boundary** so the cohabiting agent (and the CIRISConformance
v0.19.3+ harness) can stand up an HTTPS-listening edge from Python.

Six new optional kwargs land on `init_edge_runtime`, all backward-
compatible (absence preserves the v0.19.0 Reticulum-only behaviour
exactly):

```python
# Python harness / agent-side init:
edge.init_edge_runtime(
    engine, identity_path,
    https_listen_addr="0.0.0.0:4242",
    https_tls_cert_path="/etc/ciris/server.pem",
    https_tls_key_path="/etc/ciris/server.key",
    https_mtls_required=True,
)
```

| kwarg                       | Type     | Default | Purpose                                                                  |
| --------------------------- | -------- | ------- | ------------------------------------------------------------------------ |
| `https_listen_addr`         | `str?`   | `None`  | Toggle. When set, edge constructs an `HttpsTransport`.                   |
| `https_tls_cert_path`       | `str?`   | `None`  | Operator-supplied PEM cert chain.                                        |
| `https_tls_key_path`        | `str?`   | `None`  | Operator-supplied PEM private key.                                       |
| `https_mtls_required`       | `bool`   | `False` | Enable `FederationCnVerifier` (§2).                                      |
| `https_bearer_secret`       | `bytes?` | `None`  | Optional shared HMAC secret for the bearer-token path (§3).              |
| `https_dev_self_signed`     | `bool`   | `False` | Mint an ephemeral CN=key_id cert into a tmpdir at init time (§1).        |
| `disable_reticulum`         | `bool`   | `False` | HTTPS-only mode. Requires `https_listen_addr`. Skips Reticulum entirely. |

**Mutual exclusivity rule.** `https_dev_self_signed=True` PLUS any of
`https_tls_cert_path` / `https_tls_key_path` is rejected with a typed
`ValueError("conflicting TLS config: dev_self_signed and cert paths
cannot both be set")`. Operator must choose ONE mode — either
"mint an ephemeral cert" or "use my PEM paths".

**Cert + key pair rule.** Exactly one of `https_tls_cert_path` /
`https_tls_key_path` without the other yields
`ValueError("https_tls_cert_path and https_tls_key_path must both
be set (got only one)")`.

**Multi-transport coexistence.** When `disable_reticulum=False` (the
default) AND `https_listen_addr` is set, the edge runs BOTH
Reticulum AND HTTPS concurrently. Both transports listen; outbound
`Edge::send` routes per `transport_id` resolution. This is the
canonical "operator wants both substrates active" deployment.

**HTTPS-only deployments.** `disable_reticulum=True` + `https_listen_addr`
constructs an edge that listens only on HTTPS. Useful for managed-K8s
deployments where Reticulum's UDPv6 multicast is unreachable.
`disable_reticulum=True` WITHOUT `https_listen_addr` is rejected —
an edge with no transports cannot dispatch.

**Dev-cert minting (v0.19.3).** When `https_dev_self_signed=True`,
`init_edge_runtime` mints a CN=`federation_key_id` Ed25519 self-
signed cert into a tmpdir whose lifetime is bound to the
returned `PyEdge` (the tmpdir is held by the `Arc<TempDir>`
threaded into `PyEdge._dev_cert_tmpdir`). The seed is derived
deterministically from `SHA-256("ciris-edge::dev-self-signed::v1\0"
‖ federation_key_id)` — reproducible per-key_id, NOT reused
from the federation seed (AV-17). The `dev_self_signed` flag is
also flipped on `HttpServerConfig`, so the v0.18.1 listener-bind
`tracing::warn!("DEV_ONLY", ...)` warning fires.

**Cross-wheel acceptance gate.** CIRISConformance v0.19.3+ (#3 + #4)
drives `init_edge_runtime` with the matrix:

- HTTPS-only via `https_dev_self_signed=True` + `disable_reticulum=True`
- Reticulum + HTTPS via `https_listen_addr` only
- HTTPS with mTLS via `https_tls_cert_path` + `https_mtls_required=True`
- HTTPS with bearer via `https_bearer_secret`

Each conformance cell exercises one combination end-to-end via the
real persist `PyEngine` + the real Python interpreter; the Rust-
side pin is `tests/https_pyedge_init.rs`, which validates every
load-bearing primitive (`HttpsInitParams::parse`,
`mint_dev_self_signed_pair`, `HttpsTransport` construction)
without spinning up Python — a Python failure points back to one
of those primitives, which fails here first.
