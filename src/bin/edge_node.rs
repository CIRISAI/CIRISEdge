//! `edge_node` — ONE edge occurrence, for the multi-container mesh harness.
//!
//! The criterion benches in `benches/` answer *"what does the substrate
//! cost per operation"*. They are all in-process, and the one that calls
//! itself e2e (now `benches/realtime_av_mdc_substrate.rs`) said in its own docs
//! that it "does NOT validate a real MDC codec" — it pushes `vec![0u8;
//! N]` through seal/fan-out arithmetic.
//!
//! This binary answers the other question: **does a real edge occurrence
//! deliver real video to N peers across a real network while the roster
//! changes.** One process, one container, one identity. `bench-mesh/`
//! stands several of them up on a docker network.
//!
//! # What is REAL here
//!
//! - **A distinct occurrence per container.** Its own Ed25519 federation
//!   seed (generated in its own private volume, never shared), its own
//!   leviculum transport identity, its own on-disk XChaCha-sealed KV
//!   ([`XChaChaKvStore::open`]), its own persist federation directory
//!   handle. Nothing is shared between containers except *public*
//!   bootstrap data.
//! - **A real `ReticulumTransport`** over real TCP interfaces on a real
//!   docker network, and **real announce-based rooting** — a node learns
//!   its peers by verifying their signed announce attestations against
//!   the federation directory. No `inject_rooted_peer_for_test`
//!   anywhere in this binary.
//! - **A real MLS `CohortGroup`** (openmls 0.8.1, X-Wing ciphersuite
//!   0x004D), joined **across process boundaries**: the joiner mints a
//!   real KeyPackage, ships it over the real RNS wire, and the creator's
//!   `add_member` Welcome comes back over the same wire.
//! - **The scope-address lifecycle driven exactly as documented** —
//!   `cohort_addressing::snapshot(&group).await?` → `lifecycle.install`
//!   / `.advance` / `.seal_due`, with the **real `ReticulumTransport` as
//!   the [`ScopedDestinationSink`]**, so every register/retire hits the
//!   live leviculum node's routing table.
//! - **Real encoded video.** `bench-mesh/` generates a fixed-duration,
//!   fixed-seed H.264 file with ffmpeg at image-build time; the
//!   publisher reads **real encoded frames** out of it (Annex-B NAL
//!   framing) and seals each one with `seal_av_inner` under an
//!   MLS-derived key, then `seal_av_outer` per link.
//! - **A real blob** — the media file itself, fanned out chunk-by-chunk
//!   over the same real transport, verified end-to-end by SHA-256.
//!
//! # What is a SEAM (stubbed, and named)
//!
//! Two things the harness cannot reach today, each behind a narrow
//! trait so the real API drops in as a second impl without touching the
//! measurement or the reporting. Both are APIs being built concurrently
//! (`av_spine`, scope-native blob fetch):
//!
//! - [`MediaLink`] — how a sealed chunk crosses the wire. Today's impl
//!   ([`TransportMediaLink`]) uses `Transport::send`, the real RNS
//!   resource path. `src/transport/av_spine.rs` (join→subscribe→relay→
//!   heal) is the intended production driver; when it lands it becomes a
//!   second `MediaLink` impl and nothing else here changes.
//!
//!   *Why the seam is needed at all*: `AvPublisher`/`AvRelay`/
//!   `LeviculumAvSender`/`LinkDataPump` in `realtime_av_runtime.rs`
//!   require an `Arc<ReticulumNode>`, and `ReticulumTransport::node()`
//!   is `pub(crate)` + `#[cfg(feature = "pyo3")]`. A downstream consumer
//!   holding a `ReticulumTransport` **cannot** reach the node, so it
//!   cannot construct the real-RNS A/V sender. See the report.
//!
//! Blob fetch is scope-*gated* here but not yet scope-*native*:
//! `src/blob_swarm/` is being extended concurrently. See [`BlobPlane`].
//!
//! # How seal retirement is measured (CIRISEdge#499)
//!
//! An earlier shape of the `conformance.seal_retires` leg tried to
//! RNS-dial the member's scope-derived address directly, through the
//! relay. Running it proved that structurally impossible, and BY
//! DESIGN: a scope-derived destination is registered with
//! `Destination::with_explicit_hash`, and an explicit-hash destination
//! cannot announce (`AnnounceError::ExplicitHashCannotAnnounce`;
//! leviculum answers a path request for one with silence, because a
//! path response IS an announce and an announce for a caller-supplied
//! hash is unverifiable). No multi-hop RNS path to one can exist. The
//! federation destination escapes this only because a node registers an
//! *announceable* named destination beside it; a scoped address has no
//! such twin, since announcing one would publish the very reachability
//! fact the derivation exists to withhold. **A scoped address is an
//! arrival discriminator, not a routable endpoint.**
//!
//! So the leg measures retirement at the ADMISSION SEAM instead. The
//! publisher CAN reach the member over its announced node destination —
//! `mesh.rooting` proves those paths exist through the relay — so it
//! sends an application-level [`Control::AddressProbe`] naming the
//! 16 derived bytes, and the member answers from the SAME lookup the
//! production transport consults when it stamps
//! `InboundFrame::arrival_scope` on every arriving frame
//! (`ReticulumTransport::inbound_scope` →
//! `ScopeAddressTable::accepts_inbound`, the reverse index). After the
//! seal the superseded address must be refused (`held: false`) WHILE
//! the live address still answers `held: true` — the live answer is the
//! aliveness control that makes "refused" distinguishable from "node
//! down". That is the honest network observable under #499.
//!
//! # Honesty
//!
//! Every leg emits exactly one JSON line ([`Leg`]) carrying `ran` and,
//! only when `ran` is true, `ok`. **A leg that did not run reports that
//! it did not run.** There is no path in this file that reports a
//! measurement it did not take, and no summary that is green over a
//! skipped leg. `main` exits non-zero if any leg did not run or did not
//! pass.
//!
//! # CIRISEdge#217
//!
//! Every duration here is `std::time::Instant` (never `tokio::time::
//! Instant`, which panics under the cross-cdylib runtime aliasing
//! class), and no lock guard is held across an `.await`.
//!
//! [`XChaChaKvStore::open`]: ciris_persist::encrypted_kv::XChaChaKvStore::open
//! [`ScopedDestinationSink`]: ciris_edge::scope_lifecycle::ScopedDestinationSink

// The harness stands up real nodes and measures them; it is not library
// code and its role functions are long by nature.
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};

use ciris_crypto::{kdf, ClassicalSigner, Ed25519Signer};
use ciris_edge::chat;
use ciris_edge::cohort_scope::CohortScope;
use ciris_edge::identity::LocalSigner;
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, CommitApplyOutcome, ScopeStateProvider};
use ciris_edge::replication::convergence::ConvergenceWaiter;
use ciris_edge::replication::protocol::EnvelopeKind;
use ciris_edge::replication::ReplicationPeer;
use ciris_edge::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink, TransitionOutcome};
use ciris_edge::transport::realtime_av::{
    open_av_chunk, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch, EpochDek,
    SealedAvChunk, StreamId, CODEC_OPAQUE,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport, TransportError};
use ciris_edge::verify::{HybridPolicy, RootingDirectory};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;

// ═══════════════════════════════════════════════════════════════════
// Reporting — the honesty layer
// ═══════════════════════════════════════════════════════════════════

/// CIRISEdge#568 — how long the owner-binding convergence leg waits.
///
/// Capped well under the run's barrier so a genuinely stalled binding is
/// reported as a red leg with a number rather than eating the budget the chat
/// legs below still need.
fn budget_owner_binding(barrier: Duration) -> Duration {
    barrier.min(Duration::from_secs(120))
}

/// One measured or attempted leg of the harness.
///
/// `ran` and `ok` are deliberately separate and `ok` is `Option`: a leg
/// that did not run has no verdict, and there is no way to spell "green
/// because we skipped it". `main` treats `ran == false` as a failure of
/// the run, so a skipped leg can never be read as a pass.
#[derive(Debug, serde::Serialize)]
struct Leg {
    /// Stable leg name, e.g. `conformance.rotation_frame_loss`.
    #[serde(rename = "leg")]
    name: String,
    /// Emitting node's federation key id.
    node: String,
    /// Emitting node's role.
    role: String,
    /// When the row was emitted (RFC 3339, UTC). The census keys on `leg`
    /// and ignores unknown members, so this is free to add — and without it
    /// the artifact could not answer "where did the time go": no per-node
    /// wall clock, no leg ordering, no gap between two nodes' verdicts.
    ts: String,
    /// Did this leg actually execute end to end?
    ran: bool,
    /// Verdict. `None` iff `!ran`.
    ok: Option<bool>,
    /// Why it did not run. `Some` iff `!ran`.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_run_reason: Option<String>,
    /// Leg-specific measurements. Never synthesised.
    detail: serde_json::Value,
}

/// Sink for [`Leg`] lines: stdout always, plus `EDGE_RESULTS` when set.
struct Reporter {
    node: String,
    role: String,
    path: Option<PathBuf>,
    legs: std::sync::Mutex<Vec<serde_json::Value>>,
}

impl Reporter {
    fn new(node: &str, role: &str, path: Option<PathBuf>) -> Self {
        Self {
            node: node.to_owned(),
            role: role.to_owned(),
            path,
            legs: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Record a leg that ran, with its verdict and measurements.
    fn ran(&self, leg: &str, ok: bool, detail: serde_json::Value) {
        self.emit(&Leg {
            name: leg.to_owned(),
            node: self.node.clone(),
            role: self.role.clone(),
            ts: chrono::Utc::now().to_rfc3339(),
            ran: true,
            ok: Some(ok),
            not_run_reason: None,
            detail,
        });
    }

    /// Record a leg that did NOT run. There is no `ok`.
    fn not_run(&self, leg: &str, reason: impl Into<String>) {
        self.emit(&Leg {
            name: leg.to_owned(),
            node: self.node.clone(),
            role: self.role.clone(),
            ts: chrono::Utc::now().to_rfc3339(),
            ran: false,
            ok: None,
            not_run_reason: Some(reason.into()),
            detail: serde_json::json!({}),
        });
    }

    fn emit(&self, leg: &Leg) {
        let value = serde_json::to_value(leg).unwrap_or(serde_json::Value::Null);
        let line = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
        println!("{line}");
        if let Some(p) = self.path.as_ref() {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                // ONE write, newline included. Every node in the mesh appends to
                // the SAME file on a shared volume, and `writeln!` formats —
                // which can issue the line and the newline as separate `write()`
                // syscalls. Two nodes finishing a leg at the same moment then
                // interleave into a single line carrying two JSON objects, and
                // the census dies with `JSONDecodeError: Extra data` — observed
                // at M=4, the point with the most concurrent deliveries.
                //
                // A single `write_all` of the complete record under `O_APPEND`
                // is the atomic-append shape: the kernel takes one offset and
                // writes one buffer, so records cannot split into each other.
                let mut record = line.into_bytes();
                record.push(b'\n');
                let _ = f.write_all(&record);
            }
        }
        self.legs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(value);
    }

    /// `(any_leg_recorded, all_ran_and_passed)`.
    fn verdict(&self) -> (bool, bool) {
        let legs = self
            .legs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let all = legs.iter().all(|l| {
            l.get("ran").and_then(serde_json::Value::as_bool) == Some(true)
                && l.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
        });
        (!legs.is_empty(), all)
    }
}

/// Percentile over a sorted-in-place sample, in the sample's own units.
/// Returns `None` for an empty sample — a percentile over nothing is not
/// zero, it is absent, and the JSON says so.
fn pct(sorted: &[u128], p: f64) -> Option<u128> {
    if sorted.is_empty() {
        return None;
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted.get(idx).copied()
}

/// Latency summary in microseconds. Every field is `Option` so an
/// unmeasured statistic is absent rather than zero.
fn latency_json(samples: &mut [u128]) -> serde_json::Value {
    samples.sort_unstable();
    serde_json::json!({
        "n": samples.len(),
        "p50_us": pct(samples, 0.50),
        "p95_us": pct(samples, 0.95),
        "p99_us": pct(samples, 0.99),
        "min_us": samples.first().copied(),
        "max_us": samples.last().copied(),
    })
}

// ═══════════════════════════════════════════════════════════════════
// Configuration — role and topology from the environment
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Creates the cohort, publishes the stream and the blob.
    Publisher,
    /// A transit node — carries ciphertext, holds no cohort secret.
    Relay,
    /// A cohort member: receives frames and the blob, measures.
    Subscriber,
    /// A real node on the mesh that is NOT in the cohort. Exists so the
    /// refusal leg cannot pass by refusing everything.
    NonMember,
}

impl Role {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "publisher" => Ok(Self::Publisher),
            "relay" => Ok(Self::Relay),
            "subscriber" => Ok(Self::Subscriber),
            "nonmember" => Ok(Self::NonMember),
            other => Err(format!(
                "EDGE_ROLE={other:?} is not one of publisher|relay|subscriber|nonmember"
            )),
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::Relay => "relay",
            Self::Subscriber => "subscriber",
            Self::NonMember => "nonmember",
        }
    }
    /// Does this role hold the cohort's MLS state?
    fn in_cohort(self) -> bool {
        matches!(self, Self::Publisher | Self::Subscriber)
    }
}

struct Config {
    role: Role,
    node_id: String,
    /// Private, per-container. Federation seed + transport identity +
    /// sealed KV live here and nowhere else.
    state_dir: PathBuf,
    /// Shared, PUBLIC-ONLY. Carries the bootstrap roster that
    /// production learns via directory-cache anti-entropy
    /// (CIRISEdge#175). No private key is ever written here.
    mesh_dir: PathBuf,
    listen: std::net::SocketAddr,
    /// `host:port` this node is reachable at on the docker network.
    advertise: String,
    /// Peers to dial with a TCP client interface.
    bootstrap: Vec<String>,
    /// Every node id expected in the mesh, publisher first.
    expect: Vec<String>,
    /// Cohort members (a subset of `expect`) — publisher + subscribers.
    cohort_members: Vec<String>,
    /// Rooted peers on the mesh that are NOT in the cohort, and which the
    /// publisher addresses ciphertext to anyway. Without this the
    /// "a non-member cannot fetch" leg has nothing to refuse, and a leg
    /// that refuses nothing proves nothing.
    observers: Vec<String>,
    community_id: String,
    scope: CohortScope,
    media_path: PathBuf,
    frames: usize,
    /// Frame index at which a late joiner is admitted mid-stream, which
    /// advances the MLS epoch and re-derives every member's address.
    rotate_at: Option<usize>,
    /// The node admitted at `rotate_at` (a subscriber that waits).
    late_joiner: Option<String>,
    convergence: Duration,
    /// Ceiling on the announce-rooting cold start.
    root_timeout: Duration,
    /// Ceiling on any single barrier.
    barrier_timeout: Duration,
    results: Option<PathBuf>,
}

fn env_str(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn env_list(k: &str) -> Vec<String> {
    env_str(k)
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn env_usize(k: &str, default: usize) -> usize {
    env_str(k).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_secs(k: &str, default: u64) -> Duration {
    Duration::from_secs(env_str(k).and_then(|v| v.parse().ok()).unwrap_or(default))
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let role = Role::parse(&env_str("EDGE_ROLE").ok_or("EDGE_ROLE is required")?)?;
        let node_id = env_str("EDGE_NODE_ID").ok_or("EDGE_NODE_ID is required")?;
        let listen = env_str("EDGE_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:4242".to_owned())
            .parse()
            .map_err(|e| format!("EDGE_LISTEN: {e}"))?;
        let scope = match env_str("EDGE_SCOPE")
            .unwrap_or_else(|| "family".to_owned())
            .as_str()
        {
            "family" => CohortScope::Family,
            other => other.strip_prefix("cohort:").map_or_else(
                || CohortScope::Cohort {
                    cohort_id: other.to_owned(),
                },
                |id| CohortScope::Cohort {
                    cohort_id: id.to_owned(),
                },
            ),
        };
        let expect = env_list("EDGE_EXPECT");
        if expect.is_empty() {
            return Err("EDGE_EXPECT must list every node id in the mesh".to_owned());
        }
        let cohort_members = env_list("EDGE_COHORT_MEMBERS");
        if cohort_members.is_empty() {
            return Err("EDGE_COHORT_MEMBERS must list the cohort roster".to_owned());
        }
        Ok(Self {
            role,
            node_id: node_id.clone(),
            state_dir: PathBuf::from(
                env_str("EDGE_STATE_DIR").unwrap_or_else(|| format!("/state/{node_id}")),
            ),
            mesh_dir: PathBuf::from(env_str("EDGE_MESH_DIR").unwrap_or_else(|| "/mesh".to_owned())),
            listen,
            advertise: env_str("EDGE_ADVERTISE")
                .unwrap_or_else(|| format!("{node_id}:{}", listen.port())),
            bootstrap: env_list("EDGE_BOOTSTRAP"),
            expect,
            cohort_members,
            observers: env_list("EDGE_OBSERVERS"),
            community_id: env_str("EDGE_COMMUNITY").unwrap_or_else(|| "bench-mesh".to_owned()),
            scope,
            media_path: PathBuf::from(
                env_str("EDGE_MEDIA").unwrap_or_else(|| "/media/testsrc.h264".to_owned()),
            ),
            frames: env_usize("EDGE_FRAMES", 120),
            rotate_at: env_str("EDGE_ROTATE_AT").and_then(|v| v.parse().ok()),
            late_joiner: env_str("EDGE_LATE_JOINER"),
            convergence: env_secs("EDGE_CONVERGENCE_SECS", 20),
            root_timeout: env_secs("EDGE_ROOT_TIMEOUT_SECS", 120),
            barrier_timeout: env_secs("EDGE_BARRIER_TIMEOUT_SECS", 180),
            results: env_str("EDGE_RESULTS").map(PathBuf::from),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Bootstrap ceremony — public data only crosses the shared volume
// ═══════════════════════════════════════════════════════════════════

/// What a node publishes about itself so the mesh can reach and root it.
///
/// Everything here is public: an Ed25519 public key, a leviculum
/// transport public key, and a `host:port`. The private halves are
/// generated in the node's own state dir and never leave it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RosterEntry {
    key_id: String,
    role: String,
    advertise: String,
    /// Base64 32-byte Ed25519 federation public key.
    fed_pubkey_b64: String,
    /// The node's OWNER — a person (`identity_type: user`).
    ///
    /// Federation directory discovery resolves an identifier to the PERSON and
    /// then to their nodes, so a fleet of owner-less agents is unresolvable by
    /// construction: `owner_of` returns `None` and every lookup stops there.
    /// That is why the earlier `ladder.discover` leg could only cover route
    /// reachability. Giving each node a real owner is what makes the
    /// fedID → person → nodes path exercisable over the wire.
    #[serde(default)]
    owner_key_id: String,
    /// Base64 32-byte Ed25519 public key of that owner.
    #[serde(default)]
    owner_pubkey_b64: String,
    /// Base64 ML-DSA-65 public key of the node.
    ///
    /// Published alongside the classical half because the steward builds every
    /// peer's directory record from this roster, and a record without the PQC
    /// pubkey cannot verify a PQC signature — `verify_hybrid` takes the
    /// signature and the pubkey both-or-neither.
    #[serde(default)]
    fed_pqc_pubkey_b64: String,
    /// Base64 ML-DSA-65 public key of the owner.
    #[serde(default)]
    owner_pqc_pubkey_b64: String,
    /// The AGENT identity running on this node.
    ///
    /// Three keys are the minimum for a viable agent — **human, node, agent** —
    /// and they are deliberately separate. The harness used to mint two and
    /// register the node's transport key as `identity_type: "agent"`, which
    /// conflates the thing you DIAL with the thing that ACTS.
    ///
    /// Keeping them apart is what makes the dial path real: an agentID resolves
    /// to its owner (an agent cannot consent), the owner resolves to the nodes
    /// they own, and the NODE is what you address. Conflated, that walk is a
    /// tautology — the agent id already was the transport id.
    #[serde(default)]
    agent_key_id: String,
    #[serde(default)]
    agent_pubkey_b64: String,
    #[serde(default)]
    agent_pqc_pubkey_b64: String,
}

/// The TEST TRUST ROOT that scrub-signs the roster into `federation_keys` rows.
///
/// **This id is not cosmetic** — it is the key_id persist pins for holder slot 0
/// under the test anchor. The terminus ROW itself is not built here: persist
/// emits it (`genesis::test_anchor_genesis_records`) and `open_directory` seeds
/// it into every node. This constant is only the id the harness scrub-signs
/// AS, using the private half of the same seed, so the rows it signs chain to
/// the row persist seeded.
///
/// A node is admitted `Rooted` (rather than `Advisory`) only when its provenance
/// chain terminates at a self-signed `steward`/`accord_holder` row **whose
/// Ed25519 pubkey is in the pinned trusted anchor**. That anchor is
/// `accord_holder_bootstrap_anchor()`, which is secure by default: the real
/// HUMANITY_ACCORD holders (A1/B1/C1). No harness-invented steward can ever be
/// in it, so before this the mesh's peers were **structurally unable** to root —
/// measured as `resolved_provenance=Advisory` on every inbound frame, with the
/// E3 gate then refusing to attribute any of them.
///
/// `CIRIS_TEST_TRUST_ROOT*` (compile-fenced behind `test-anchor`, runtime-gated
/// on `CIRIS_TESTING_MODE`) overrides that anchor with one throwaway software
/// hybrid key — the same mechanism CIRISServer's traceflow harness uses, and
/// generated by the same runner:
///
/// ```text
/// CIRIS_TEST_TRUST_ROOT_SEED=<b64 32B> \
///   cargo run --release --example test_anchor_env --features test-anchor
/// ```
///
/// Every node roots under this one SW root exactly as a production canonical
/// roots under an A1-scrubbed record — no operator hardware key, and never
/// touching the real trust key.
const STEWARD_KEY_ID: &str = "test-accord-holder-0";

/// The env the test anchor is armed with. Absent ⇒ the harness refuses to
/// start, rather than running a mesh whose peers can never root.
const TEST_TRUST_ROOT_SEED_ENV: &str = "CIRIS_TEST_TRUST_ROOT_SEED";

/// The shared test trust root's Ed25519 seed, from the environment.
///
/// A hard error when absent. The alternative — inventing a seed — produces a
/// root that is not in the pinned anchor, so every peer roots `Advisory`, every
/// frame is refused attribution, and the mesh fails several legs later with no
/// hint of the cause. Fail here, where the remedy is one line of compose.
fn test_trust_root_seed() -> Result<[u8; 32], String> {
    let raw = std::env::var(TEST_TRUST_ROOT_SEED_ENV).map_err(|_| {
        format!(
            "{TEST_TRUST_ROOT_SEED_ENV} is unset. The mesh roots every node under a \
             synthetic trust root; without the seed the terminus is not in the pinned \
             anchor and NO peer can ever be admitted `Rooted`. Generate the block with \
             `cargo run --example test_anchor_env --features test-anchor` and set it on \
             every container."
        )
    })?;
    B64.decode(raw.trim())
        .map_err(|e| format!("{TEST_TRUST_ROOT_SEED_ENV} is not base64: {e}"))?
        .try_into()
        .map_err(|_| format!("{TEST_TRUST_ROOT_SEED_ENV} must decode to exactly 32 bytes"))
}

fn roster_dir(mesh: &Path) -> PathBuf {
    mesh.join("roster")
}

fn directory_path(mesh: &Path) -> PathBuf {
    mesh.join("directory.json")
}

/// Publish this node's public bootstrap record.
fn publish_roster_entry(mesh: &Path, entry: &RosterEntry) -> std::io::Result<()> {
    let dir = roster_dir(mesh);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{}.tmp", entry.key_id));
    let final_path = dir.join(format!("{}.json", entry.key_id));
    std::fs::write(&tmp, serde_json::to_vec_pretty(entry).unwrap_or_default())?;
    // Rename so a reader never observes a half-written record.
    std::fs::rename(&tmp, &final_path)
}

/// The transport half of a node's public record, published once its
/// leviculum identity exists. Separate from [`RosterEntry`] because it
/// cannot be known until after the transport is built, and the
/// directory-signing barrier depends on the first half.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TransportEntry {
    key_id: String,
    /// Base64 of the ed25519 half (bytes 32..64) of the dual-key
    /// leviculum transport identity.
    transport_ed25519_b64: String,
}

fn publish_transport_entry(mesh: &Path, entry: &TransportEntry) -> std::io::Result<()> {
    let dir = roster_dir(mesh);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{}.transport.tmp", entry.key_id));
    let final_path = dir.join(format!("{}.transport.json", entry.key_id));
    std::fs::write(&tmp, serde_json::to_vec_pretty(entry).unwrap_or_default())?;
    std::fs::rename(&tmp, &final_path)
}

fn read_roster(mesh: &Path) -> BTreeMap<String, RosterEntry> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(roster_dir(mesh)) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        let is_transport_half = p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".transport.json"));
        if p.extension().is_some_and(|x| x == "json") && !is_transport_half {
            if let Ok(bytes) = std::fs::read(&p) {
                if let Ok(entry) = serde_json::from_slice::<RosterEntry>(&bytes) {
                    out.insert(entry.key_id.clone(), entry);
                }
            }
        }
    }
    out
}

/// Wait until every id in `expect` has published a roster entry.
///
/// Returns `Err` with the ids still missing when the deadline passes —
/// the caller reports a leg that did not run, never a green one.
async fn await_roster(
    mesh: &Path,
    expect: &[String],
    timeout: Duration,
) -> Result<BTreeMap<String, RosterEntry>, String> {
    // A roster is a file the other containers write, so nothing in the
    // replication plane signals it — the UNSIGNALLED waiter, whose floor is
    // exactly this barrier's old poll interval.
    let outcome = ConvergenceWaiter::unsignalled()
        .with_poll_floor(Duration::from_millis(250))
        .await_until(timeout, || async {
            let roster = read_roster(mesh);
            expect.iter().all(|k| roster.contains_key(k))
        })
        .await;
    let roster = read_roster(mesh);
    if outcome.is_converged() {
        return Ok(roster);
    }
    let missing: Vec<&String> = expect.iter().filter(|k| !roster.contains_key(*k)).collect();
    Err(format!(
        "roster barrier timed out after {}s; still missing {missing:?}",
        timeout.as_secs()
    ))
}

/// Runtime-agnostic sleep (CIRISEdge#217 — never `tokio::time::sleep` on
/// a path that may be driven by a foreign runtime).
async fn tokio_sleep(d: Duration) {
    futures_timer::Delay::new(d).await;
}

/// Wait for a file to appear, then read it.
async fn await_file(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    // Another container writes this file; admission does not signal it.
    let outcome = ConvergenceWaiter::unsignalled()
        .with_poll_floor(Duration::from_millis(250))
        .await_until(timeout, || async {
            std::fs::read(path).is_ok_and(|b| !b.is_empty())
        })
        .await;
    if outcome.is_converged() {
        if let Ok(b) = std::fs::read(path) {
            if !b.is_empty() {
                return Ok(b);
            }
        }
    }
    Err(format!(
        "{} did not appear within {}s",
        path.display(),
        timeout.as_secs()
    ))
}

/// A deterministic-from-seed federation identity.
///
/// The seed itself is CSPRNG-generated on first boot **inside the node's
/// own private state dir**; it is written once and reloaded thereafter,
/// so a restarted container keeps its identity and two containers can
/// never share one.
struct FedKey {
    seed: [u8; 32],
    /// The ML-DSA-65 half. NOT optional: the federation tier is PQC-mandatory
    /// (CC 5.3.2.4.3.1) and persist verifies attestation envelopes under
    /// `HybridPolicy::Strict`, so a classical-only harness identity produces
    /// rows that canonicalize and hash correctly, verify their Ed25519 half,
    /// and are then refused as hybrid-pending. A harness whose identities
    /// cannot sign what production signs is not testing production.
    pqc_seed: [u8; 32],
}

impl FedKey {
    /// Load both seeds under `dir`, generating either on first boot.
    fn load_or_create(key_id: &str, dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let _ = key_id;
        Ok(Self {
            seed: Self::seed_at(&dir.join("ed25519.seed"))?,
            pqc_seed: Self::seed_at(&dir.join("mldsa65.seed"))?,
        })
    }

    /// Read a 32-byte seed, minting it from the CSPRNG on first boot.
    ///
    /// Edge has no "mint a fresh federation identity" verb — every existing
    /// fixture writes its own seed. Recorded as a DX finding; the harness does
    /// the same.
    fn seed_at(path: &Path) -> Result<[u8; 32], String> {
        if path.exists() {
            let b = std::fs::read(path).map_err(|e| format!("read seed: {e}"))?;
            return b
                .try_into()
                .map_err(|_| format!("{} is not a 32-byte seed", path.display()));
        }
        let mut arr = [0u8; 32];
        ciris_crypto::random::fill(&mut arr).map_err(|e| format!("csprng: {e}"))?;
        std::fs::write(path, arr).map_err(|e| format!("write seed: {e}"))?;
        Ok(arr)
    }

    /// Derive from an explicit Ed25519 seed rather than the node's own state
    /// dir — for the TEST TRUST ROOT, whose seed every container shares.
    ///
    /// The ML-DSA half is derived exactly as CIRISServer's
    /// `examples/test_anchor_env` and `src/test_bless.rs` derive it, because
    /// the resulting pubkeys must equal the `CIRIS_TEST_TRUST_ROOT*` values the
    /// anchor is pinned to. One seed, one root, both halves.
    fn from_root_seed(seed: [u8; 32]) -> Self {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(seed);
        Self {
            seed,
            pqc_seed: h.finalize().into(),
        }
    }

    /// The full hybrid signing identity — what every federation-tier producer
    /// in the library takes.
    fn local_signer(&self, key_id: &str) -> Result<LocalSigner, String> {
        let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&self.seed, key_id)
                .map_err(|e| format!("ed25519 signer: {e}"))?,
        );
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
                &self.pqc_seed,
                format!("{key_id}-pqc"),
            )
            .map_err(|e| format!("ml-dsa-65 signer: {e}"))?,
        );
        Ok(LocalSigner::new(key_id, classical, Some(pqc)))
    }

    /// Base64 ML-DSA-65 public key — the directory record must carry it, or
    /// `verify_hybrid` sees a PQC signature with no pubkey to check it against
    /// and refuses the pair outright.
    async fn pqc_pubkey_b64(&self, key_id: &str) -> Result<String, String> {
        let signer = self.local_signer(key_id)?;
        let pqc = signer.pqc.as_ref().ok_or("no pqc half")?;
        Ok(B64.encode(
            pqc.public_key()
                .await
                .map_err(|e| format!("pqc pubkey: {e}"))?,
        ))
    }

    fn signer(&self) -> Result<Ed25519Signer, String> {
        Ed25519Signer::from_seed(&self.seed).map_err(|e| format!("ed25519 from seed: {e}"))
    }

    fn pubkey_b64(&self) -> Result<String, String> {
        Ok(B64.encode(
            self.signer()?
                .public_key()
                .map_err(|e| format!("pubkey: {e}"))?,
        ))
    }
}

/// Build one scrub-signed `federation_keys` row.
///
/// Same shape as `tests/common::signed_record` / `benches/common::
/// signed_record` — kept in step with them deliberately: a change to the
/// admitted row shape must break all three at once.
async fn signed_record(
    subject_key_id: &str,
    subject_pubkey_b64: &str,
    subject_pqc_pubkey_b64: &str,
    signer: &LocalSigner,
    signer_key_id: &str,
    identity_type: &str,
) -> Result<KeyRecord, String> {
    // The envelope must BIND the row's identity — `key_id`, `identity_type`,
    // and BOTH pubkey legs. CIRISVerify's provenance walk requires exactly
    // these (`ProvenanceLink::subject_binding`), and refuses a link whose
    // signed bytes omit any of them.
    //
    // The attack it closes: with the identity fields outside the signed bytes,
    // an attacker wraps a victim's genuine, validly-signed envelope in a link
    // declaring their OWN key_id and pubkeys. The content hash matches (it
    // really is the victim's envelope), the signatures verify (really signed by
    // the real parent), linkage passes — and the chain roots the attacker's
    // key. Both pubkey legs are bound, not just the name, because binding the
    // name alone loses on a node that has not yet replicated the victim's row.
    //
    // A `{"key_id": …}`-only envelope is why every harness node rooted
    // `Advisory`: each link was refused with "signed bytes do not carry
    // `identity_type` — an absent binding is skippable by omission", so the
    // chain never assembled and the E3 gate attributed nothing.
    let mut envelope = serde_json::json!({
        "key_id": subject_key_id,
        "identity_type": identity_type,
        "pubkey_ed25519_base64": subject_pubkey_b64,
    });
    if !subject_pqc_pubkey_b64.is_empty() {
        envelope["pubkey_ml_dsa_65_base64"] = serde_json::json!(subject_pqc_pubkey_b64);
    }
    // JCS canonicalization, and SIGN THE CANONICAL BYTES — not their digest.
    //
    // The rooting provenance walk verifies every link's scrub-signature over
    // `jcs::canonicalize(registration_envelope)` (CIRISVerify `provenance.rs`).
    // Signing the SHA-256 digest instead verifies against nothing, so the chain
    // never assembles, every peer is admitted `Advisory` rather than `Rooted`,
    // and the E3 gate refuses to attribute a single inbound frame. Measured as
    // `resolved_owns_key=true, resolved_provenance=Advisory` on 123 frames —
    // `owns_key` passed all along; the chain signature was the failure.
    //
    // The identical mistake was made in the attestation producer earlier in
    // this branch and fixed there; this is the second instance of one class.
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(signer, &canonical, "key record").await?;
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .map_err(|e| format!("ts: {e}"))?
        .into();
    Ok(KeyRecord {
        key_id: subject_key_id.to_owned(),
        pubkey_ed25519_base64: subject_pubkey_b64.to_owned(),
        pubkey_ml_dsa_65_base64: (!subject_pqc_pubkey_b64.is_empty())
            .then(|| subject_pqc_pubkey_b64.to_owned()),
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: subject_key_id.to_owned(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: signer_key_id.to_owned(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    })
}

/// Emit the OWNER-BINDING attestation: `owner` is responsible for `node`.
///
/// This is what makes federation directory discovery answerable. `owner_of`
/// resolves through `live_owner_binding_granters`, and `nodes_owned_by` walks
/// owner bindings — so without one, a fedID lookup finds a person with no
/// nodes and every discovery stops there. Route reachability alone was all the
/// harness could prove before this existed.
///
/// The substrate recognises a binding by `delegation_purpose: "owner_binding"`
/// (CC 2.4.1.2's canonical marker) or by the internal dimension; the raw
/// `delegates_to` emit path carries only the former, so that is what a producer
/// writes. Keying on the dimension alone let the raw path bypass the
/// single-owner gate (CIRISPersist#378), which is why both are recognised.
///
/// Written into this node's OWN persist. It then replicates on the Attestation
/// plane like any other signed row — the harness seeds nothing into a peer.
async fn emit_owner_binding(
    dir: &Arc<SqliteBackend>,
    owner_key_id: &str,
    owner_signer: &LocalSigner,
    node_id: &str,
) -> Result<(), String> {
    // Fixed instant so a restarted container re-emits a byte-identical row
    // rather than a second, competing binding.
    const ASSERTED_AT: &str = "2026-05-01T00:00:00Z";
    let ts: chrono::DateTime<chrono::Utc> = chrono::DateTime::parse_from_rfc3339(ASSERTED_AT)
        .map_err(|e| format!("ts: {e}"))?
        .into();

    // The library builds and signs it. The harness deliberately does NOT
    // hand-roll this envelope: doing so is what produced two failed mesh runs
    // (a missing signed `asserted_at`, then a missing `row` mirror) plus a
    // signature over the digest instead of the canonical bytes. The producer
    // is unit-tested against a real persist backend, so those failures are now
    // caught in under a second instead of a full mesh round-trip.
    let att = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        owner_key_id,
        node_id,
        ts,
        owner_signer,
    )
    .await?;

    tracing::info!(
        owner = %owner_key_id,
        node = %node_id,
        attestation_id = %att.attestation_id,
        hybrid = att.scrub_signature_pqc.is_some(),
        "emitting owner binding"
    );

    // persist v41.0.0 (#804) — this node signed the binding just above.
    dir.put_attestation_authored(ciris_persist::federation::SignedAttestation { attestation: att })
        .await
        .map_err(|e| {
            // Name the refusal AT the source. Downstream this is a bare
            // "standup failed" in a census cell, which is an investigation
            // rather than a read.
            tracing::error!(
                owner = %owner_key_id,
                node = %node_id,
                error = %e,
                "owner binding REFUSED by persist — federation directory discovery \
                 cannot resolve this node's owner, so every fedID lookup against it \
                 will stop at owner_of => None"
            );
            format!("put owner binding: {e}")
        })?;
    Ok(())
}

/// Open a fresh per-container persist directory and seed it with `rows`.
///
/// One backend per container — the containers never share a handle, a
/// file, or a connection pool.
async fn open_directory(rows: Vec<KeyRecord>) -> Result<Arc<SqliteBackend>, String> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .map_err(|e| format!("open directory: {e}"))?;
    backend
        .run_migrations()
        .await
        .map_err(|e| format!("migrate: {e}"))?;

    // GENESIS FIRST — every node, before any roster row.
    //
    // A node is admitted `Rooted` (not `Advisory`) only when its provenance
    // chain terminates at a row whose Ed25519 pubkey is in the pinned anchor.
    // That anchor is secure by default (the real HUMANITY_ACCORD holders), so
    // nothing a harness invents can ever satisfy it — before this, every peer
    // rooted Advisory and the E3 gate attributed nothing.
    //
    // `test_anchor_genesis_records()` is the SYNTHETIC-ONLY accessor: `Some`
    // exactly when the test anchor is armed. Its sibling
    // `effective_accord_holder_records()` is the WRONG call here — it falls
    // back to the real baked constitutional roster, so a mis-armed harness
    // would quietly seed production's holders into a throwaway directory and
    // look like it worked. `None` is a hard error instead.
    //
    // Seeded per node, not by the publisher: each node opens its own persist,
    // and a chain is walked against the directory doing the walking.
    let holders =
        ciris_persist::federation::genesis::test_anchor_genesis_records().ok_or_else(|| {
            format!(
                "the SYNTHETIC trust root is not armed, so no node could ever root. Set \
                 the whole CIRIS_TEST_TRUST_ROOT* block — verify reads the Ed25519 \
                 pubkeys, persist reads the ML-DSA pubkeys AND both scrub signatures, \
                 and {TEST_TRUST_ROOT_SEED_ENV} is the private half this harness signs \
                 with — and build with the `test-anchor` feature."
            )
        })?;
    backend
        .seed_genesis_accord_holders(&holders)
        .await
        .map_err(|e| format!("seed synthetic genesis holders: {e}"))?;

    for rec in rows {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .map_err(|e| format!("put_public_key: {e}"))?;
    }
    Ok(backend)
}

// ═══════════════════════════════════════════════════════════════════
// The wire — a compact harness frame over the real RNS resource path
// ═══════════════════════════════════════════════════════════════════

/// `MESH1` ‖ u8 kind ‖ u32be header_len ‖ header JSON ‖ payload.
///
/// The transport carries opaque bytes (its own loopback acceptance test
/// asserts byte-exactness), so the harness frames its own control and
/// media messages rather than pretending each video chunk is a signed
/// federation envelope.
const MAGIC: &[u8; 5] = b"MESH1";
/// Blob fan-out chunk size. Fixed so completion times compare run to run.
const BLOB_CHUNK: usize = 32 * 1024;
/// How many frames are addressed to a non-member observer.
///
/// The refusal claim is about an AEAD key the observer does not hold, so
/// it fails identically on every frame — a handful is as conclusive as a
/// thousand, and a thousand would mean the publisher paying a transport
/// timeout per frame after the observer exits, which would quietly turn
/// the fan-out throughput number into a measure of how fast a dead peer
/// fails.
const OBSERVER_FRAMES: usize = 4;
/// Ceiling on frames a subscriber will hold awaiting a not-yet-applied
/// epoch commit. Bounds the make-before-break buffer against a peer that
/// floods wrong-epoch headers.
const MAX_DEFERRED: usize = 4096;
const KIND_CONTROL: u8 = 1;
const KIND_MEDIA: u8 = 2;
const KIND_BLOB: u8 = 3;

fn encode_frame(kind: u8, header: &serde_json::Value, payload: &[u8]) -> Vec<u8> {
    let h = serde_json::to_vec(header).unwrap_or_default();
    let mut out = Vec::with_capacity(MAGIC.len() + 5 + h.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(kind);
    out.extend_from_slice(&u32::try_from(h.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
    out
}

fn decode_frame(bytes: &[u8]) -> Option<(u8, serde_json::Value, &[u8])> {
    if bytes.len() < MAGIC.len() + 5 || &bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let kind = bytes[MAGIC.len()];
    let len_at = MAGIC.len() + 1;
    let header_len = u32::from_be_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
    let body_at = len_at + 4;
    let header = serde_json::from_slice(bytes.get(body_at..body_at + header_len)?).ok()?;
    Some((kind, header, bytes.get(body_at + header_len..)?))
}

/// Control-plane messages. Carried over the same real transport as the
/// media, so the MLS join really does cross the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t")]
enum Control {
    /// Joiner → creator: a real openmls KeyPackage.
    KeyPackage { key_id: String, kp_b64: String },
    /// Creator → joiner: the Welcome `add_member` produced.
    Welcome { key_id: String, welcome_b64: String },
    /// Creator → existing members: an MLS commit to apply.
    Commit { epoch: u64, commit_b64: String },
    /// Member → creator: "my cohort state and addresses are installed".
    Ready { key_id: String, epoch: u64 },
    /// Creator → all: the stream is about to start.
    StreamStart {
        stream_id_hex: String,
        frames: usize,
    },
    /// Creator → all: no more frames.
    StreamEnd { frames_sent: usize },
    /// Creator → all: blob metadata.
    BlobStart {
        sha256: String,
        bytes: usize,
        chunks: usize,
    },
    /// Member → creator: "probe my live and superseded addresses BEFORE
    /// I seal". Carries no addresses: the creator derives them from its
    /// OWN table, which is additionally the cross-node agreement check —
    /// a probe answered `held: true` proves both nodes derived the same
    /// 16 bytes. Sent only by a member that crossed an epoch advance and
    /// therefore has a superseded epoch to retire.
    SealProbe {
        key_id: String,
        superseded_epoch: u64,
    },
    /// Creator → member: "does your transport's arrival-admission table
    /// currently hold this scope-derived address?" Sent over the
    /// member's announced, rooted node destination — a scoped address
    /// itself cannot be dialled across a relay (explicit-hash
    /// destinations never announce), so this application-level probe is
    /// how a peer observes admission (see the module doc). The address
    /// travels as the raw 16 derived bytes (hex) because the answering
    /// lookup — `ReticulumTransport::inbound_scope`, the same
    /// `ScopeAddressTable::accepts_inbound` reverse index that stamps
    /// `InboundFrame::arrival_scope` on every arriving frame — is keyed
    /// on exactly those bytes.
    AddressProbe { address_hex: String, nonce: u64 },
    /// Member → creator: the admission answer. `held` is the production
    /// lookup's verdict, not a parallel bookkeeping read. The ack
    /// ARRIVING is itself the aliveness proof that distinguishes
    /// "refused" (`held: false`) from "node down" (silence); silence is
    /// transport loss, never an admission answer.
    AddressProbeAck { nonce: u64, held: bool },
    /// Creator → member: "I have taken the before-reading; seal now".
    SealGo { key_id: String },
    /// Member → creator: the seal ran; here is what it did.
    Sealed {
        key_id: String,
        sealed: usize,
        unretired: usize,
    },
    /// Member → creator: final per-node measurements.
    Report {
        key_id: String,
        body: serde_json::Value,
    },
}

/// One inbound data frame: `(attributed sender, header, payload)`.
type DataFrame = (Option<String>, serde_json::Value, Vec<u8>);
/// One inbound control frame: `(attributed sender, message)`.
type ControlFrame = (Option<String>, Control);

/// A live inbound mailbox: the `listen` sink demultiplexed by frame kind.
struct Mailbox {
    control: Mutex<mpsc::UnboundedReceiver<ControlFrame>>,
    media: Mutex<mpsc::UnboundedReceiver<DataFrame>>,
    blob: Mutex<mpsc::UnboundedReceiver<DataFrame>>,
}

/// Spawn the transport listener and the demultiplexer.
///
/// `listen` may be called exactly once per transport, so this is the one
/// place that does it.
/// What the listener did with inbound frames.
///
/// Reported in `ladder.discover_by_fedid`'s detail because the JSONL is this
/// harness's real instrument — `tracing` output is a log a reader may or may
/// not have. If discovery fails, these four numbers say WHERE: no frames at
/// all is a transport problem, frames routed but nothing converging is a
/// replication problem, and `not_replication` counting everything means the
/// peer is not speaking the protocol we think it is.
#[derive(Default, Debug)]
struct InboundStats {
    routed: std::sync::atomic::AtomicUsize,
    not_replication: std::sync::atomic::AtomicUsize,
    unattributed: std::sync::atomic::AtomicUsize,
    errors: std::sync::atomic::AtomicUsize,
}

impl InboundStats {
    fn record(&self, d: &ciris_edge::replication::RouteDisposition) {
        use ciris_edge::replication::RouteDisposition as D;
        use std::sync::atomic::Ordering::Relaxed;
        match d {
            D::Routed => {
                self.routed.fetch_add(1, Relaxed);
            }
            D::NotReplication => {
                self.not_replication.fetch_add(1, Relaxed);
            }
            D::Unattributed => {
                self.unattributed.fetch_add(1, Relaxed);
            }
            D::Failed(e) => {
                self.errors.fetch_add(1, Relaxed);
                tracing::warn!(error = %e, "replication routing failed");
            }
        }
    }

    fn as_json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({
            "routed": self.routed.load(Relaxed),
            "not_replication": self.not_replication.load(Relaxed),
            "unattributed": self.unattributed.load(Relaxed),
            "errors": self.errors.load(Relaxed),
        })
    }
}

/// Drain the transport, splitting harness frames from REPLICATION frames.
///
/// `Transport::listen` claims the node's single event receiver, so whoever
/// calls it owns every inbound frame. The harness used to decode its own
/// `MESH1` framing and DROP everything else with a debug line — which meant
/// every replication frame a peer sent was thrown away. Rounds went out,
/// nothing came back, and the Attestation plane never converged: exactly the
/// `owned_nodes: []` the census reported, with no error anywhere.
///
/// Edge says so explicitly (`replication::runtime` module docs): *"Wiring the
/// registry's `route_inbound_bytes` INTO that loop is operator code (a one-line
/// addition to the application's listen-handler), not edge's job."* The harness
/// is the operator here and had not written the line.
fn spawn_inbound(
    transport: &Arc<ReticulumTransport>,
    router: ciris_edge::replication::InboundRouter,
    stats: Arc<InboundStats>,
) -> Arc<Mailbox> {
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(4096);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    let (med_tx, med_rx) = mpsc::unbounded_channel();
    let (blb_tx, blb_rx) = mpsc::unbounded_channel();

    let t = Arc::clone(transport);
    tokio::spawn(async move {
        if let Err(e) = t.listen(tx).await {
            tracing::error!(error = %e, "transport listener exited");
        }
    });

    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let src = frame.source_key_id.as_ref().map(|k| k.as_str().to_owned());
            let Some((kind, header, payload)) = decode_frame(&frame.envelope_bytes) else {
                // Not harness framing — hand it to replication before giving up
                // on it. This is THE line the module docs ask the operator for.
                stats.record(&router.try_route(&frame).await);
                continue;
            };
            match kind {
                KIND_CONTROL => match serde_json::from_value::<Control>(header) {
                    Ok(c) => {
                        let _ = ctl_tx.send((src, c));
                    }
                    Err(e) => tracing::warn!(error = %e, "undecodable control frame"),
                },
                KIND_MEDIA => {
                    let _ = med_tx.send((src, header, payload.to_vec()));
                }
                KIND_BLOB => {
                    let _ = blb_tx.send((src, header, payload.to_vec()));
                }
                other => tracing::warn!(kind = other, "unknown harness frame kind"),
            }
        }
    });

    Arc::new(Mailbox {
        control: Mutex::new(ctl_rx),
        media: Mutex::new(med_rx),
        blob: Mutex::new(blb_rx),
    })
}

impl Mailbox {
    /// Await the next control message, or `Err` on timeout.
    ///
    /// The receiver guard is taken and released inside the `select!`
    /// arm's own future — no guard is alive across the timeout branch
    /// (CIRISEdge#217).
    async fn next_control(&self, timeout: Duration) -> Result<(Option<String>, Control), String> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut rx = self.control.lock().await;
                if let Ok(msg) = rx.try_recv() {
                    return Ok(msg);
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("no control frame within {}s", timeout.as_secs()));
            }
            tokio_sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Send a control message over the real transport.
async fn send_control(
    transport: &ReticulumTransport,
    to: &str,
    msg: &Control,
) -> Result<(), TransportError> {
    let header = serde_json::to_value(msg).unwrap_or(serde_json::Value::Null);
    let bytes = encode_frame(KIND_CONTROL, &header, &[]);
    transport.send(to, &bytes).await.map(|_| ())
}

// ═══════════════════════════════════════════════════════════════════
// The two in-flight seams
// ═══════════════════════════════════════════════════════════════════

/// **SEAM 1 — how a sealed A/V chunk crosses the wire.**
///
/// `src/transport/av_spine.rs` (join→subscribe→relay→heal) is being
/// built concurrently and is the intended production driver. It cannot
/// be used from here today for a structural reason worth recording:
/// `AvPublisher` / `AvRelay` / `LeviculumAvSender` / `LinkDataPump` all
/// need an `Arc<ReticulumNode>`, and `ReticulumTransport::node()` is
/// `pub(crate)` + `#[cfg(feature = "pyo3")]` — a downstream consumer
/// holding a `ReticulumTransport` cannot reach the node, and a second
/// node would need the event receiver the transport's listener already
/// owns.
///
/// So the harness drives the wire through the verb it *can* reach, and
/// keeps it behind this trait so the spine slots in as a second impl.
#[async_trait::async_trait]
trait MediaLink: Send + Sync {
    /// Name of the mechanism actually used, for the JSON output.
    fn mechanism(&self) -> &'static str;
    /// Deliver one sealed chunk to one peer.
    async fn deliver(
        &self,
        to: &str,
        header: &serde_json::Value,
        chunk: &[u8],
    ) -> Result<(), String>;
}

/// Today's `MediaLink`: the real RNS resource path.
struct TransportMediaLink {
    transport: Arc<ReticulumTransport>,
}

#[async_trait::async_trait]
impl MediaLink for TransportMediaLink {
    fn mechanism(&self) -> &'static str {
        "reticulum_transport_send"
    }
    async fn deliver(
        &self,
        to: &str,
        header: &serde_json::Value,
        chunk: &[u8],
    ) -> Result<(), String> {
        let bytes = encode_frame(KIND_MEDIA, header, chunk);
        self.transport
            .send(to, &bytes)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════
// The admission-seam address probe (`conformance.seal_retires`)
// ═══════════════════════════════════════════════════════════════════
//
// See "How seal retirement is measured" in the module doc. A scoped
// address is an arrival discriminator, not a routable endpoint, so the
// probe rides the member's rooted node destination and the ANSWER — not
// a link establishing — is the observable.

/// Publisher side: send one [`Control::AddressProbe`] for `address` to
/// `member` and await the matching ack.
///
/// Returns `Some(held)` when the ack arrives — the member's production
/// admission verdict for those 16 bytes — and `None` on silence, which
/// is transport loss and never an admission answer.
///
/// The tail of the publisher run is ONE state machine on purpose (two
/// loops each discarding the other's messages is the shape that
/// silently loses one), so a `Report` arriving while this waits is
/// folded into `member_reports` rather than dropped. Stale acks from an
/// earlier probe are skipped by nonce.
/// The publisher-loop state a probe bracket must feed instead of eat:
/// member Reports land in the report map, and OTHER members' seal traffic
/// (SealProbe/Sealed) is stashed for the outer loop rather than dropped.
struct ProbeSideChannel<'a> {
    member_reports: &'a mut serde_json::Map<String, serde_json::Value>,
    stash: &'a mut std::collections::VecDeque<Control>,
}

async fn probe_scope_address(
    transport: &ReticulumTransport,
    mailbox: &Mailbox,
    member: &str,
    address: &MemberAddress,
    nonce: u64,
    timeout: Duration,
    side: &mut ProbeSideChannel<'_>,
) -> Option<bool> {
    let probe = Control::AddressProbe {
        address_hex: hex::encode(address.as_bytes()),
        nonce,
    };
    if send_control(transport, member, &probe).await.is_err() {
        return None;
    }
    let until = Instant::now() + timeout;
    while Instant::now() < until {
        let Ok((_s, msg)) = mailbox.next_control(Duration::from_secs(2)).await else {
            continue;
        };
        match msg {
            Control::AddressProbeAck { nonce: n, held } if n == nonce => return Some(held),
            Control::Report { key_id, body } => {
                side.member_reports.insert(key_id, body);
            }
            // Another member's seal traffic arriving DURING this bracket's
            // ack-wait must not be eaten — at M≥3 several members cross the
            // epoch and probe near-simultaneously, and a discarded SealProbe
            // strands that member for its full 90 s SealGo wait (the M=4
            // "no SealGo from the publisher" class). Stash for the outer
            // loop; everything else (stale acks) still drops.
            m @ (Control::SealProbe { .. } | Control::Sealed { .. }) => side.stash.push_back(m),
            _ => {}
        }
    }
    None
}

/// Member side: answer one [`Control::AddressProbe`].
///
/// The answer is routed through `ReticulumTransport::inbound_scope` —
/// the SAME `ScopeAddressTable::accepts_inbound` reverse-index lookup
/// the transport's arrival path performs to stamp
/// `InboundFrame::arrival_scope` on every real inbound frame — so the
/// leg measures the production admission decision, not a parallel
/// bookkeeping read. Bytes that do not decode to a 16-byte hash are
/// answered `held: false`: they name nothing this table could admit.
async fn answer_address_probe(
    transport: &ReticulumTransport,
    to: &str,
    address_hex: &str,
    nonce: u64,
) {
    let held = hex::decode(address_hex)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .is_some_and(|h| transport.inbound_scope(&h).is_some());
    let _ = send_control(transport, to, &Control::AddressProbeAck { nonce, held }).await;
}

/// The `conformance.seal_retires` after-reading, as a pure verdict.
///
/// Inputs are exactly what [`probe_scope_address`] produces post-seal:
/// `Some(held)` from an ack's payload, `None` on silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealAfterVerdict {
    /// Both post-seal probes were acked and the pair is the retirement
    /// shape: the superseded address refused (`held: false`) WHILE the
    /// live control still answered `held: true` — the aliveness control
    /// that makes "refused" distinguishable from "node down".
    Retired,
    /// Both probes were acked but the pair is not the retirement shape.
    /// The reading is evaluable and it is a FAILURE: `old_held` means
    /// the seal did not retire at the admission seam; `!live_held`
    /// (from a node demonstrably alive — it acked) means the seal took
    /// the live address down with it.
    NotRetired { live_held: bool, old_held: bool },
    /// A probe went silent. Silence is transport loss, not an admission
    /// answer — a refusal is an ack carrying `held: false` — so the
    /// reading is NOT evaluable and the leg must say `not_run` rather
    /// than guess. `!live_answered` is the indistinguishable-from-
    /// node-down case.
    Unanswerable {
        live_answered: bool,
        old_answered: bool,
    },
}

fn seal_after_verdict(after_live: Option<bool>, after_old: Option<bool>) -> SealAfterVerdict {
    match (after_live, after_old) {
        (Some(true), Some(false)) => SealAfterVerdict::Retired,
        (Some(live_held), Some(old_held)) => SealAfterVerdict::NotRetired {
            live_held,
            old_held,
        },
        (live, old) => SealAfterVerdict::Unanswerable {
            live_answered: live.is_some(),
            old_answered: old.is_some(),
        },
    }
}

/// **SEAM 2 — scope-native blob fetch.**
///
/// `src/blob_swarm/` is being extended concurrently with a scope-native
/// fetch path. Today the harness pushes the blob over the same real
/// transport and gates *admission* on cohort membership, which is enough
/// to assert both halves of the refusal property; it is not yet a swarm
/// fetch. When the scope-native fetch lands it becomes the second impl
/// of this trait.
#[async_trait::async_trait]
trait BlobPlane: Send + Sync {
    fn mechanism(&self) -> &'static str;
    async fn push_chunk(
        &self,
        to: &str,
        header: &serde_json::Value,
        chunk: &[u8],
    ) -> Result<(), String>;
}

struct TransportBlobPlane {
    transport: Arc<ReticulumTransport>,
}

#[async_trait::async_trait]
impl BlobPlane for TransportBlobPlane {
    fn mechanism(&self) -> &'static str {
        "reticulum_transport_send"
    }
    async fn push_chunk(
        &self,
        to: &str,
        header: &serde_json::Value,
        chunk: &[u8],
    ) -> Result<(), String> {
        let bytes = encode_frame(KIND_BLOB, header, chunk);
        self.transport
            .send(to, &bytes)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Media — real encoded frames out of the ffmpeg-generated file
// ═══════════════════════════════════════════════════════════════════

/// Split an Annex-B elementary stream into access units.
///
/// `bench-mesh/Dockerfile` produces `testsrc.h264` — a raw H.264
/// elementary stream from `testsrc`, fixed duration and fixed encoder
/// settings, so the byte content is identical on every build. Each
/// returned element is a real encoded access unit (its own NAL start
/// codes intact), not a slice of a buffer of zeros.
///
/// Returns `Err` when the file has no start codes at all — that means
/// the media step did not produce what the harness expects, and the leg
/// must report that rather than "publish" nothing.
fn annexb_access_units(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            starts.push(i);
            i += 3;
        } else if i + 4 < bytes.len()
            && bytes[i] == 0
            && bytes[i + 1] == 0
            && bytes[i + 2] == 0
            && bytes[i + 3] == 1
        {
            starts.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    if starts.is_empty() {
        return Err(
            "no Annex-B start code found — the media file is not a raw H.264 elementary stream"
                .to_owned(),
        );
    }
    // Group NALs into access units: a new AU begins at each VCL NAL that
    // follows a non-VCL one. Coarse but deterministic, and every emitted
    // unit is real encoded video.
    let mut units = Vec::new();
    for (n, &s) in starts.iter().enumerate() {
        let e = starts.get(n + 1).copied().unwrap_or(bytes.len());
        units.push(bytes[s..e].to_vec());
    }
    Ok(units)
}

// ═══════════════════════════════════════════════════════════════════
// The occurrence
// ═══════════════════════════════════════════════════════════════════

/// One live edge occurrence: identity, sealed state, transport, and the
/// scope-address lifecycle driving the real transport.
struct Occurrence {
    cfg: Config,
    /// The real anti-entropy runtime. Owner bindings reach peers through this
    /// and nothing else — the harness seeds no state into any peer.
    replication: Arc<ciris_edge::replication::ReplicationRuntime>,
    /// What the listener did with inbound frames — reported by the discovery
    /// leg so a failure says WHERE, not just that it failed.
    inbound_stats: Arc<InboundStats>,
    transport: Arc<ReticulumTransport>,
    mailbox: Arc<Mailbox>,
    table: Arc<ScopeAddressTable>,
    lifecycle: Arc<ScopeLifecycle>,
    roster: BTreeMap<String, RosterEntry>,
    reporter: Arc<Reporter>,
    /// This node's hybrid signer — CUSTODY: it co-scrubs the owner's rows at
    /// the crossing and signs what the node itself attests.
    node_signer: Arc<LocalSigner>,
    /// The OWNER's hybrid signer — the ACTOR: a chat message is attested and
    /// signed by the human whose words it is (sign-at-write), and the
    /// widening to the room is the human's own `supersedes`. The harness holds
    /// it because it plays the human; a real node never does.
    owner_signer: Arc<LocalSigner>,
    /// This node's persist directory — what `contact::PersistLens` reads, so
    /// the discovery leg resolves against the SAME state replication feeds.
    directory: Arc<SqliteBackend>,
}

/// The only two planes the harness replicates.
///
/// `EnvelopeKind::ALL` is FIFTEEN, and a coordinator is registered per
/// (peer, kind) — sixty of them across four peers, all dialing one Reticulum
/// transport. That saturated the link pool and the harness's own control
/// frames began timing out, so replication starved the mesh it was meant to
/// serve (leviculum#29, CIRISEdge#508/#531). Discovery needs Key (directory
/// rows) and Attestation (owner bindings); nothing else earns a round here.
const _: () = {
    // The harness's plane list MUST contain the bootstrap pair. A compile-time
    // check, because omitting one is silent at runtime: an advisory link simply
    // never promotes and every later plane reports nothing new.
    let mut i = 0;
    while i < EnvelopeKind::BOOTSTRAP_PLANES.len() {
        let needed = EnvelopeKind::BOOTSTRAP_PLANES[i];
        let mut found = false;
        let mut j = 0;
        while j < DISCOVERY_PLANES.len() {
            if DISCOVERY_PLANES[j] as u8 == needed as u8 {
                found = true;
            }
            j += 1;
        }
        assert!(found, "DISCOVERY_PLANES must contain every BOOTSTRAP_PLANE");
        i += 1;
    }
};

const DISCOVERY_PLANES: [EnvelopeKind; 4] = [
    // The three that PROMOTE an advisory link to an attributed one. The harness
    // first registered `EnvelopeKind::ALL` (sixty coordinators — it saturated
    // the transport), then narrowed to `Key` + `Attestation`, which omits two
    // of the three planes an advisory link needs to earn attribution. Register
    // all three or no other plane ever flows.
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
    // What discovery actually reads.
    EnvelopeKind::Attestation,
];

/// Build the whole occurrence: keys, sealed KV, directory, transport,
/// address table, lifecycle.
async fn stand_up(cfg: Config, reporter: Arc<Reporter>) -> Result<Occurrence, String> {
    std::fs::create_dir_all(&cfg.state_dir)
        .map_err(|e| format!("create state dir {}: {e}", cfg.state_dir.display()))?;

    // ── 1. This node's own federation key (private; own volume only) ──
    let fed = FedKey::load_or_create(&cfg.node_id, &cfg.state_dir.join("fed"))?;

    // The PERSON who owns this node. A node cannot consent and cannot be a
    // contact — its owner is both — so directory discovery resolves an
    // identifier to the person first and to their nodes second. Without a real
    // owner every lookup stops at `owner_of` returning `None`, which is exactly
    // why the route-reachability leg could not cover resolution.
    let owner_key_id = format!("{}-owner", cfg.node_id);
    let owner = FedKey::load_or_create(&owner_key_id, &cfg.state_dir.join("owner"))?;

    // The AGENT that runs here — the third of the three keys (human, node,
    // agent). Distinct from `cfg.node_id`, which is the NODE: the dialable
    // transport identity. An agent is resolved to a node in order to be
    // reached, so the two cannot be the same key without making that
    // resolution meaningless.
    let agent_key_id = format!("{}-agent", cfg.node_id);
    let agent = FedKey::load_or_create(&agent_key_id, &cfg.state_dir.join("agent"))?;

    // ── 2. Publish the public half + reachability ────────────────────
    publish_roster_entry(
        &cfg.mesh_dir,
        &RosterEntry {
            key_id: cfg.node_id.clone(),
            role: cfg.role.as_str().to_owned(),
            advertise: cfg.advertise.clone(),
            fed_pubkey_b64: fed.pubkey_b64()?,
            owner_key_id: owner_key_id.clone(),
            owner_pubkey_b64: owner.pubkey_b64()?,
            fed_pqc_pubkey_b64: fed.pqc_pubkey_b64(&cfg.node_id).await?,
            owner_pqc_pubkey_b64: owner.pqc_pubkey_b64(&owner_key_id).await?,
            agent_key_id: agent_key_id.clone(),
            agent_pubkey_b64: agent.pubkey_b64()?,
            agent_pqc_pubkey_b64: agent.pqc_pubkey_b64(&agent_key_id).await?,
        },
    )
    .map_err(|e| format!("publish roster entry: {e}"))?;

    // ── 3. The publisher plays steward and signs the directory ───────
    let dir_path = directory_path(&cfg.mesh_dir);
    if cfg.role == Role::Publisher {
        let roster = await_roster(&cfg.mesh_dir, &cfg.expect, cfg.barrier_timeout).await?;
        let steward = FedKey::from_root_seed(test_trust_root_seed()?);
        let steward_signer = steward.local_signer(STEWARD_KEY_ID)?;
        let mut rows: Vec<KeyRecord> = Vec::new();
        for entry in roster.values() {
            // The NODE — what peers dial. `identity_type: "node"`, not
            // "agent": conflating them is what made the agent→node dial walk a
            // tautology.
            rows.push(
                signed_record(
                    &entry.key_id,
                    &entry.fed_pubkey_b64,
                    &entry.fed_pqc_pubkey_b64,
                    &steward_signer,
                    STEWARD_KEY_ID,
                    "node",
                )
                .await?,
            );
            // The AGENT that runs on it — a separate identity, and the third
            // key an agent needs to be viable.
            if !entry.agent_key_id.is_empty() {
                rows.push(
                    signed_record(
                        &entry.agent_key_id,
                        &entry.agent_pubkey_b64,
                        &entry.agent_pqc_pubkey_b64,
                        &steward_signer,
                        STEWARD_KEY_ID,
                        "agent",
                    )
                    .await?,
                );
            }
            // The owner, as a PERSON. `identity_type` is the authority on what
            // an identifier names — never the string's shape — so this is what
            // makes `resolve` route a lookup to the person rather than
            // treating the owner as another agent.
            if !entry.owner_key_id.is_empty() {
                rows.push(
                    signed_record(
                        &entry.owner_key_id,
                        &entry.owner_pubkey_b64,
                        &entry.owner_pqc_pubkey_b64,
                        &steward_signer,
                        STEWARD_KEY_ID,
                        "user",
                    )
                    .await?,
                );
            }
        }
        let tmp = cfg.mesh_dir.join("directory.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&rows).map_err(|e| format!("encode directory: {e}"))?,
        )
        .map_err(|e| format!("write directory: {e}"))?;
        std::fs::rename(&tmp, &dir_path).map_err(|e| format!("publish directory: {e}"))?;
    }

    // ── 4. Every node opens its OWN directory from the signed rows ───
    let dir_bytes = await_file(&dir_path, cfg.barrier_timeout).await?;
    let rows: Vec<KeyRecord> =
        serde_json::from_slice(&dir_bytes).map_err(|e| format!("decode directory: {e}"))?;
    let directory = open_directory(rows).await?;

    // This node's own owner binding, written locally and replicated from here.
    // Nothing is seeded into a peer: a peer learns this the same way it learns
    // any other signed row, which is the point of testing discovery rather
    // than testing a fixture.
    // Bind BOTH the node and the agent to the same human.
    //
    // `owner_of` walks owner bindings for a node OR an agent alike, so the
    // agent needs its own binding or `resolve(agentID)` finds no owner and the
    // walk stops before it ever reaches a dialable node.
    let owner_signer = Arc::new(owner.local_signer(&owner_key_id)?);
    for subject in [&cfg.node_id, &agent_key_id] {
        emit_owner_binding(&directory, &owner_key_id, &owner_signer, subject).await?;
    }

    let roster = read_roster(&cfg.mesh_dir);

    // ── This node's DIRECTED consent grants ──────────────────────────
    //
    // The Attestation plane is consent-gated at the RECIPIENT, not per row: a
    // peer that does not resolve to a consent-membership proof withholds the
    // WHOLE plane, fail-closed. Without these grants every node held only its
    // OWN owner binding and every person→node walk starved one hop out — which
    // is exactly what the mesh reported (`identity_type: "user"` with
    // `owned_nodes: []`, on every node) and reads as slow convergence rather
    // than an absent grant.
    //
    // Consent is DIRECTED and SELF-ATTESTED (CEG 1.0-RC29 §5.6.8.15): A
    // granting B says nothing about B granting A, so each node authors its own
    // half — the same shape CIRISServer's `POST /v1/federation/peering` writes,
    // which is where this pattern is taken from rather than invented.
    let node_signer = fed.local_signer(&cfg.node_id)?;
    for peer in roster.keys().filter(|k| *k != &cfg.node_id) {
        let grant = ciris_edge::replication::attestation_bind::replication_consent_attestation(
            &cfg.node_id,
            peer,
            &ciris_edge::replication::attestation_bind::DEFAULT_CONSENT_PREFIXES,
            chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .map_err(|e| format!("ts: {e}"))?
                .into(),
            &node_signer,
        )
        .await?;
        // persist v41.0.0 (#804) — the consent grant is minted here, by this
        // node's own signer, one statement up.
        directory
            .put_attestation_authored(ciris_persist::federation::SignedAttestation {
                attestation: grant,
            })
            .await
            .map_err(|e| {
                tracing::error!(
                    node = %cfg.node_id, %peer, error = %e,
                    "replication consent grant REFUSED — this peer will be offered \
                     NO attestations at all, so no owner binding reaches it"
                );
                format!("put consent grant for {peer}: {e}")
            })?;
    }
    tracing::info!(
        node = %cfg.node_id,
        peers = roster.len().saturating_sub(1),
        "directed replication consent granted"
    );

    // ── This node's PAIR ROOMS with every roster owner ───────────────
    //
    // Authored at STANDUP, before replication starts, so a peer's message —
    // or its MLS handshake row — is admissible the moment it arrives: AV-45
    // proves the writer's membership against the room the row names, and a
    // room that is not yet known is a transient refusal that costs a whole
    // round. Both humans are FOUNDERS (`chat::pair_community`), so the room
    // has its moderators by construction. Idempotent on both ends.
    let founded_at: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .map_err(|e| format!("ts: {e}"))?
            .into();
    let mut rooms = 0usize;
    for entry in roster.values().filter(|e| e.key_id != cfg.node_id) {
        if entry.owner_key_id.is_empty() {
            continue;
        }
        let row = chat::signed_pair_community(
            &owner_key_id,
            &entry.owner_key_id,
            founded_at,
            &node_signer,
        )
        .await?;
        match directory.put_community(row).await {
            Ok(()) | Err(ciris_persist::federation::Error::Conflict(_)) => rooms += 1,
            Err(e) => {
                tracing::warn!(
                    node = %cfg.node_id, peer_owner = %entry.owner_key_id, error = %e,
                    "pair room refused at standup — the chat legs will author it again"
                );
            }
        }
    }
    tracing::info!(node = %cfg.node_id, rooms, "pair rooms authored at standup");

    // ── 5. The federation signer, from this node's own seed ──────────
    // The HYBRID signer, not a classical-only one.
    //
    // The transport self-publishes its own hybrid-signed
    // `SignedTransportDestination` at construction (CIRISEdge#406) — the
    // producer for the #393 item-2 gate. That producer is FAIL-OPEN and one of
    // its documented failure modes is exactly "Ed25519-only signer": it warns
    // once and carries on, and no row is ever written.
    //
    // Measured effect of fixing it: inbound frames ROUTED went from 0 to ~650
    // per node. It did not by itself make them ATTRIBUTED — the logs showed
    // `resolved_owns_key=true, resolved_provenance=Advisory`, so `owns_key` was
    // already passing and the chain walk was the separate failure (see
    // `signed_record`, which was signing a digest instead of the canonical
    // envelope the provenance walk verifies).
    //
    // Same class as the owner binding: classical-only where the federation tier
    // is PQC-mandatory. `FedKey` already carries both halves.
    let signer = Arc::new(fed.local_signer(&cfg.node_id)?);
    // Kept for the chat legs: the NODE co-scrubs the owner's message at the
    // crossing, under the owner binding it acts under.
    let node_signer = Arc::clone(&signer);

    // ── 6. The real transport, on the real docker network ────────────
    //
    // The legacy `listen_addr` + `bootstrap_peers` shape rather than the
    // typed `add_interface` one, deliberately: it is the configuration
    // `benches/transport_reticulum_loopback.rs::build_loopback` proves
    // converges through **real announce-based rooting**, with no primed
    // binding anywhere. `interfaces` being non-empty suppresses both
    // fields, so the two styles cannot be mixed.
    let mut tcfg =
        ReticulumTransportConfig::new(cfg.state_dir.join("transport.id"), cfg.node_id.clone());
    tcfg.listen_addr = cfg.listen;
    tcfg.announce_interval = Duration::from_secs(2);
    for peer in &cfg.bootstrap {
        tcfg.bootstrap_peers
            .push(resolve_addr(peer, cfg.barrier_timeout).await?);
    }
    // A relay carries other nodes' traffic; leaves do not.
    tcfg = tcfg.with_transport_node(cfg.role == Role::Relay);

    let auth = ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(&directory) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    };
    let transport = Arc::new(
        ReticulumTransport::new(tcfg, auth)
            .await
            .map_err(|e| format!("build transport: {e}"))?,
    );
    let mut own_transport_ed25519 = [0u8; 32];
    own_transport_ed25519.copy_from_slice(&transport.local_transport_pubkey()[32..64]);
    publish_transport_entry(
        &cfg.mesh_dir,
        &TransportEntry {
            key_id: cfg.node_id.clone(),
            transport_ed25519_b64: B64.encode(own_transport_ed25519),
        },
    )
    .map_err(|e| format!("publish transport entry: {e}"))?;

    // ── 7. The address table + lifecycle, over the REAL transport ────
    //
    // This is the DX under test: the sink IS the live transport, so a
    // lifecycle install registers a destination on the leviculum node
    // and a seal retires it.
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    transport
        .install_scope_address_table(Arc::clone(&table))
        .map_err(|e| format!("install scope address table: {e}"))?;
    let lifecycle = Arc::new(ScopeLifecycle::new(
        Arc::clone(&table),
        Arc::clone(&transport) as Arc<dyn ScopedDestinationSink>,
        cfg.node_id.clone(),
        cfg.convergence,
    ));

    // ── 8. THE REPLICATION PLANE ─────────────────────────────────────
    //
    // Without this the harness has no anti-entropy at all: each node held
    // the steward's key records plus its OWN owner binding, and nothing ever
    // carried a binding between nodes. `ladder.discover_by_fedid` therefore
    // could not pass by construction — `nodes_owned_by(peer-owner)` was
    // permanently empty, and the leg's failure was reported as
    // `NotYetDiscovered`, which reads like slow convergence rather than an
    // absent mechanism.
    //
    // Starting the real runtime is what makes the leg test the FEDERATION
    // DIRECTORY DISCOVERY MECHANISM rather than a fixture: a peer's owner
    // binding now arrives the way every other signed row does, over the
    // Attestation plane, and this is also the first in-repo consumer of
    // `ReplicationRuntime::start` — the shape a downstream chat harness
    // copies.
    //
    // Cadence is tightened from the 30s default: the mesh's barriers are
    // measured in tens of seconds, so a default-cadence node would spend the
    // whole budget waiting for its first round.
    // ONLY the two planes discovery needs — Key (the directory rows) and
    // Attestation (the owner bindings).
    //
    // `EnvelopeKind::ALL` is FIFTEEN kinds, and a coordinator is registered per
    // (peer, kind): with four peers that is SIXTY of them, each opening a round
    // on a 2s cadence over one Reticulum transport. That saturated the link
    // pool and the harness's own control frames started timing out
    // (`resource transfer failed: Timeout` on a KeyPackage send) — replication
    // starved the very mesh it was supposed to serve. The concurrency ceiling
    // is a known constraint (leviculum#29, CIRISEdge#508/#531), and this
    // harness has to share the transport with real media fan-out.
    //
    // Eight coordinators on a 5s cadence leaves the barrier tens of rounds,
    // which is many more than convergence needs.
    let peers: Vec<ReplicationPeer> = roster
        .keys()
        .filter(|k| *k != &cfg.node_id)
        .flat_map(|peer| {
            DISCOVERY_PLANES
                .into_iter()
                .map(move |kind| ReplicationPeer {
                    peer_key_id: peer.clone(),
                    kind,
                })
        })
        .collect();
    let replication = Arc::new(
        ciris_edge::replication::ReplicationRuntime::start(
            Arc::clone(&directory) as Arc<dyn ciris_persist::federation::FederationDirectory>,
            Arc::clone(&transport) as Arc<dyn ciris_edge::transport::Transport>,
            peers,
            ciris_edge::replication::ReplicationRuntimeConfig {
                scheduler: ciris_edge::replication::SchedulerConfig {
                    cadence: Duration::from_secs(5),
                    round_timeout: Duration::from_secs(10),
                },
                local_key_id: Some(cfg.node_id.clone()),
                ..Default::default()
            },
            // THE SELF-PUBLISH SET — the three identities this node speaks
            // for. Built by the library helper so the harness and the server
            // construct it the same way.
            Some({
                let publish = [
                    cfg.node_id.as_str(),
                    agent_key_id.as_str(),
                    owner_key_id.as_str(),
                ];
                tracing::info!(
                    node = %cfg.node_id,
                    publishes = ?publish,
                    "self-publish set installed — these identities' Key / \
                     IdentityOccurrence / TransportDestination rows are advertised \
                     to peers. TransportDestination is the transport hint peers \
                     need for #393 item 2"
                );
                ciris_edge::replication::self_publish_set(publish)
            }),
        )
        .await,
    );

    // The listener LAST: it claims the transport's single event receiver and
    // must be able to hand replication frames to a live registry.
    let inbound_stats = Arc::new(InboundStats::default());
    let mailbox = spawn_inbound(
        &transport,
        ciris_edge::replication::InboundRouter::new(replication.registry()),
        Arc::clone(&inbound_stats),
    );

    Ok(Occurrence {
        cfg,
        replication,
        inbound_stats,
        transport,
        mailbox,
        table,
        lifecycle,
        roster,
        reporter,
        node_signer,
        owner_signer,
        directory,
    })
}

/// Resolve `host:port` with retries — a container's DNS name may not
/// resolve until its peer is up.
async fn resolve_addr(hostport: &str, timeout: Duration) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs as _;
    // DNS for a sibling container that may not be up yet. Unsignalled by
    // definition — but it goes through the same helper as every other wait, so
    // there is exactly one waiting shape in this binary.
    let outcome = ConvergenceWaiter::unsignalled()
        .with_poll_floor(Duration::from_millis(500))
        .await_until(timeout, || async {
            hostport
                .to_socket_addrs()
                .is_ok_and(|mut it| it.next().is_some())
        })
        .await;
    if outcome.is_converged() {
        if let Ok(mut it) = hostport.to_socket_addrs() {
            if let Some(a) = it.next() {
                return Ok(a);
            }
        }
    }
    Err(format!(
        "could not resolve {hostport} within {}s",
        timeout.as_secs()
    ))
}

impl Occurrence {
    /// A waiter on this node's convergence signal — bumped by every ADMITTED
    /// envelope, so a leg wakes when the row it needs lands rather than on a
    /// poll boundary.
    fn replication_convergence(&self) -> ciris_edge::replication::convergence::ConvergenceWaiter {
        self.replication.convergence()
    }

    /// Wait for real announce-based rooting to converge with every peer
    /// we need to talk to. No test hook: this is the production
    /// cold-start path, and a timeout is reported as a leg that did not
    /// run.
    async fn await_rooting(&self, peers: &[String]) -> Result<Duration, String> {
        // Rooting is announce-driven, and an announce carries attestations that
        // get ADMITTED — so the convergence signal is genuinely relevant here
        // and this wakes on the admit rather than on a 500ms boundary. The
        // floor still covers the transport's own route table, which admission
        // does not signal.
        let outcome = self
            .replication_convergence()
            .with_poll_floor(Duration::from_millis(500))
            .await_until(self.cfg.root_timeout, || async {
                for p in peers {
                    if p != &self.cfg.node_id && !self.transport.knows_peer(p).await {
                        return false;
                    }
                }
                true
            })
            .await;
        if outcome.is_converged() {
            return Ok(outcome.waited());
        }
        let mut missing = Vec::new();
        for p in peers {
            if p != &self.cfg.node_id && !self.transport.knows_peer(p).await {
                missing.push(p.clone());
            }
        }
        Err(format!(
            "announce rooting did not converge within {}s; unrooted: {missing:?}",
            self.cfg.root_timeout.as_secs()
        ))
    }

    /// Install this cohort's scope addresses through the documented two
    /// lines, against the real transport.
    async fn install_addresses(&self, group: &CohortGroup) -> Result<TransitionOutcome, String> {
        let snap = ciris_edge::cohort_addressing::snapshot(group)
            .await
            .map_err(|e| format!("cohort_addressing::snapshot: {e}"))?;
        self.lifecycle
            .install(&self.cfg.scope, &snap)
            .map_err(|e| format!("lifecycle.install: {e}"))
    }

    /// Advance them make-before-break after an epoch bump.
    async fn advance_addresses(&self, group: &CohortGroup) -> Result<TransitionOutcome, String> {
        let snap = ciris_edge::cohort_addressing::snapshot(group)
            .await
            .map_err(|e| format!("cohort_addressing::snapshot: {e}"))?;
        self.lifecycle
            .advance(&self.cfg.scope, &snap, Instant::now())
            .map_err(|e| format!("lifecycle.advance: {e}"))
    }

    fn group_id(&self) -> String {
        format!("cohort:{}", self.cfg.community_id)
    }
}

/// Open this node's own on-disk sealed KV.
///
/// The passphrase is derived from the node's own federation seed, so two
/// containers can never open each other's store even if the files were
/// swapped. One sealed KV per occurrence — never shared.
fn open_sealed_kv(state_dir: &Path, fed_seed_path: &Path) -> Result<XChaChaKvStore, String> {
    let seed = std::fs::read(fed_seed_path).map_err(|e| format!("read seed: {e}"))?;
    let pass = kdf::hkdf_sha256(
        &seed,
        b"ciris-edge/bench-mesh/sealed-kv/v1",
        b"cohort-mls-state",
        32,
    )
    .map_err(|e| format!("kv passphrase kdf: {e}"))?;
    std::fs::create_dir_all(state_dir).map_err(|e| format!("create kv dir: {e}"))?;
    XChaChaKvStore::open(state_dir.join("cohort-state.kv"), &pass)
        .map_err(|e| format!("open sealed kv: {e}"))
}

/// The media DEK and the per-link transit key for an epoch.
///
/// **Labelled, harness-only derivation.** Production takes the A/V DEK
/// from an `AvSession`'s own MLS group and the transit key from a
/// `FederationSession` hybrid KEX. Neither is reachable across process
/// boundaries today: the A/V session join rides on the in-flight spine,
/// and `SessionHandshakeMsg` has no serde wire form, so a cross-process
/// KEX would need a hand-rolled codec.
///
/// What is used instead is still a *real* MLS exporter — the cohort's
/// record-plane secret, which every member derives identically and which
/// changes on every epoch advance (which is exactly the property the
/// rotation conformance leg turns on). It is a separate labelled
/// derivation, not a reuse of the record plane's key: the info string
/// names the harness and the plane.
fn epoch_keys(
    record_secret: &[u8; 32],
    stream: &StreamId,
    epoch: u64,
) -> Result<([u8; 32], [u8; 32]), String> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"ciris-edge/bench-mesh/media/v1");
    info.extend_from_slice(&stream.0);
    info.extend_from_slice(&epoch.to_be_bytes());
    let dek = kdf::hkdf_sha256(record_secret, b"bench-mesh-dek", &info, 32)
        .map_err(|e| format!("dek kdf: {e}"))?;
    let transit = kdf::hkdf_sha256(record_secret, b"bench-mesh-transit", &info, 32)
        .map_err(|e| format!("transit kdf: {e}"))?;
    let mut d = [0u8; 32];
    d.copy_from_slice(&dek);
    let mut t = [0u8; 32];
    t.copy_from_slice(&transit);
    Ok((d, t))
}

// ═══════════════════════════════════════════════════════════════════
// Roles
// ═══════════════════════════════════════════════════════════════════

/// The fedID-discovery leg: fedID → person → their nodes → a node this node
/// can actually address.
///
/// Shared by BOTH roles. It was written inline on the publisher only, while
/// the census expects the cell on publisher and subscriber alike — so every
/// subscriber reported it missing, independent of whether discovery worked.
/// Discovery must hold in both directions anyway: the publisher resolving a
/// subscriber's owner says nothing about a subscriber resolving the
/// publisher's, and that is the direction a contact request travels.
async fn run_discover_by_fedid_leg(
    occ: &Occurrence,
    lens: &ciris_edge::contact::PersistLens<'_>,
    routes: &ciris_edge::contact::ReticulumRoutes<'_>,
) {
    use ciris_edge::contact;

    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;

    // A PEER's owner — never our own, or this would prove only that a node
    // can read what it just wrote.
    //
    // Prefer a COHORT peer. The roster is ordered by key_id, so the naive
    // `.first()` picked `nonmember` — the node the harness deliberately holds
    // at arm's length. It roots against the publisher and nothing else, drives
    // no replication rounds, and exists to prove EXCLUSION; its owner binding
    // is therefore not expected to converge anywhere. Targeting it made an
    // identity-plane leg depend on a node contracted not to participate, and
    // the leg failed with `NotYetDiscovered { nonmember-owner }` — a true
    // report about the wrong subject.
    //
    // A cohort peer is one this occurrence exchanges state with by contract,
    // which is exactly the population whose bindings must converge.
    let candidates: Vec<&RosterEntry> = occ
        .roster
        .values()
        .filter(|e| e.key_id != cfg.node_id && !e.owner_key_id.is_empty())
        .collect();
    let peer_owner = candidates
        .iter()
        .find(|e| cfg.cohort_members.contains(&e.key_id))
        .or_else(|| candidates.first())
        .map(|e| (e.owner_key_id.clone(), e.key_id.clone()));

    let Some((owner_id, expect_node)) = peer_owner else {
        rep.not_run(
            "ladder.discover_by_fedid",
            "no peer published an owner in the roster — nothing to resolve",
        );
        return;
    };

    // WAIT for the peer's binding, through the shared helper.
    //
    // The row is replicated, not seeded, so asking once races the Attestation
    // plane and fails on timing rather than on the property under test. What
    // this leg claims is that discovery CONVERGES over the wire — so waiting
    // for convergence is the measurement, and the elapsed time is reported as
    // part of it.
    //
    // `await_until` wakes on an ADMITTED envelope rather than on a poll
    // boundary, so this resolves the moment the binding lands. Route
    // reachability is not signalled by admission — that lives in the
    // transport's table — so the helper's floor covers it, and the leg does not
    // have to know which half of its predicate is signalled.
    // The predicate answers ONE question and captures nothing, so the closure
    // stays `Send` and the helper needs no interior mutability from callers.
    // The snapshot used for reporting comes from a single call afterwards —
    // cheap, and the same shape on the converged and timed-out paths alike.
    // A DEDICATED budget, not the whole barrier.
    //
    // This leg runs before `cohort.join`, so a failure that burns the entire
    // barrier leaves the publisher not reading control frames for five
    // minutes — its peers' KeyPackage sends then time out and EVERY later leg
    // reports missing. One leg's failure must cost one leg, not the run: the
    // previous attempt turned a single red cell into fifteen.
    let discovery_budget = cfg.barrier_timeout.min(Duration::from_secs(90));
    // Rounds are KICKED toward the peer and re-kicked on every admission
    // until the walk resolves, so the Key → attribution → Attestation chain
    // runs back to back instead of one plane per cadence tick.
    let outcome = occ
        .replication
        .sync_and_await(&expect_node, discovery_budget, || async {
            matches!(
                contact::discover(lens, routes, &owner_id).await,
                Ok(ref f)
                    if f.subject.nodes.contains(&expect_node)
                        && f.reachable.contains(&expect_node)
            )
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "sync_and_await: scheduler unavailable");
            ciris_edge::replication::convergence::Converged::TimedOut {
                waited: Duration::ZERO,
                checks: 0,
            }
        });
    let (last, last_stall) = match contact::discover(lens, routes, &owner_id).await {
        Ok(found) => (Some(found), None),
        Err(stall) => (None, Some(format!("{stall:?}"))),
    };
    let attempts = outcome.checks();
    let waited_ms = outcome.waited().as_millis();
    if let Some(found) = last {
        let named = found.subject.nodes.contains(&expect_node);
        let reachable = found.reachable.contains(&expect_node);
        if !(named && reachable) {
            tracing::error!(
                queried = %owner_id,
                expected_node = %expect_node,
                nodes = ?found.subject.nodes,
                reachable = ?found.reachable,
                waited_ms,
                attempts,
                "discovery did not converge: the peer's owner binding never named \
                 a reachable expected node within the barrier"
            );
        }
        rep.ran(
            "ladder.discover_by_fedid",
            named && reachable,
            serde_json::json!({
                "queried": owner_id,
                "resolved_person": found.subject.fed_id,
                "resolved_from": format!("{:?}", found.subject.resolved_from),
                "nodes": found.subject.nodes,
                "reachable": found.reachable,
                "expected_node": expect_node,
                "peer_is_cohort_member": cfg.cohort_members.contains(&expect_node),
                "named_expected_node": named,
                "reachable_expected_node": reachable,
                "converged_ms": waited_ms,
                "attempts": attempts,
                "inbound": occ.inbound_stats.as_json(),
                "covers": "fedID -> person -> owned nodes -> addressable, against the \
                           peer's owner binding learned over the wire",
            }),
        );
    } else {
        // Ask the directory the two questions the stall cannot separate. Both
        // surface as `NotYetDiscovered`, but they have different causes and
        // different remedies: no key record means the steward's directory row
        // never arrived; a key record with no owned nodes means the row is here
        // and the owner-binding ATTESTATION is what did not replicate or admit.
        use ciris_edge::contact::DirectoryLens as _;
        let has_key_record = lens.identity_type_of(&owner_id).await;
        let owned = lens.nodes_owned_by(&owner_id).await;
        tracing::error!(
            queried = %owner_id,
            stall = ?last_stall,
            waited_ms,
            attempts,
            identity_type = ?has_key_record,
            owned_nodes = ?owned,
            "discovery never resolved the peer's owner. identity_type=None means the \
             KEY RECORD is missing; identity_type=Some with owned_nodes=[] means the \
             record is here and the owner-binding ATTESTATION did not replicate or \
             did not admit"
        );
        rep.ran(
            "ladder.discover_by_fedid",
            false,
            serde_json::json!({
                "queried": owner_id,
                "stall": last_stall,
                "waited_ms": waited_ms,
                "attempts": attempts,
                "identity_type": has_key_record,
                "owned_nodes": owned,
                "inbound": occ.inbound_stats.as_json(),
                // WHICH LINK IN THE CHAIN IS MISSING. Each of these is a
                // distinct fault with a distinct remedy, and the stall alone
                // cannot tell them apart:
                //   key record absent  -> the steward's directory row never
                //                         arrived
                //   route absent       -> the peer's TransportDestination (its
                //                         transport hint) has not replicated,
                //                         so #393 item 2 cannot be satisfied
                //                         and its frames are dropped
                //   both present, no
                //   owned nodes        -> the owner-binding attestation is what
                //                         is missing
                "peer_route_known": occ.transport.knows_peer(&expect_node).await,
                "peer_key_record": lens.identity_type_of(&expect_node).await,
            }),
        );
    }
}

/// The pair chat legs — `ladder.open_chat` and `ladder.send_message` — over
/// the real mesh, through the one-verb DX (`docs/FSD_REPLICATION_DX.md`).
///
/// Runs on the PUBLISHER and the FIRST subscriber only; every other role
/// reports `not_run` with the reason, which the census accepts as
/// documentation. Two parties, one room:
///
/// 1. Both derive the same room id from the two OWNER fed-IDs
///    (`chat::pair_community_key_id`, order-free) and author the pair
///    `Community` row locally. Members are the two HUMANS, not the nodes:
///    AV-45 at the put door resolves a node writer through `owner_of` and
///    checks the OWNER against the roster (`admission_identity_for_writer`).
///    Authoring it on both sides is idempotent and removes any dependency on
///    the Community plane's replication timing.
/// 2. The publisher's OWNER authors a message — `tier: local`,
///    `cohort_scope: self`, attested and signed by the human (sign-at-write)
///    — stores it, and `share(With::Community)`s it: the row enters the mesh
///    over the same bytes with the node's co-scrub, then the human's own
///    `supersedes` places it in the room. Two rows; the peer gets the second.
/// 3. The subscriber waits, through the convergence helper, until the row
///    lands and `chat::messages_in_room` returns it — keyed on the sender's
///    fed-ID and the derived room, read off the plane like a client would.
///
/// Nothing bespoke crosses the wire. The message is an ordinary
/// federation-tier `scores` row on `chat:message:v1`, so RNS transport,
/// the relay hop, and LXMF come along for free.
/// The one message the pair chat sends. Fixed so the receiver can check it.
const CHAT_BODY: &str = "hello over the mesh";

/// Put a row and share it with the room — the ONE way a chat leg places
/// anything: authored `self`, entered over the same bytes with the node's
/// co-scrub, widened to `community` by the owner's own `supersedes`.
async fn share_in_room(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    row: ciris_persist::federation::Attestation,
    room: &str,
    signers: ciris_edge::replication::attestation_bind::Signers<'_>,
) -> Result<ciris_edge::replication::attestation_bind::Shared, String> {
    use ciris_edge::replication::attestation_bind::{share, CrossingBasis, Shared, With};
    // persist v41.0.0 (#804) — the local `self` placement of a row this leg
    // authored. The authored door is what makes a chat leg's own sends immune
    // to the per-peer quota that #804 measured refusing 652 of 900 of them.
    dir.put_attestation_authored(ciris_persist::federation::SignedAttestation {
        attestation: row.clone(),
    })
    .await
    .map_err(|e| format!("put {}: {e}", row.attestation_id))?;
    let crossing = share(
        dir,
        &row,
        With::Community {
            community_key_id: room.to_owned(),
        },
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await?;
    match crossing.shared {
        Shared::Placed { .. } | Shared::AlreadyThere { .. } => Ok(crossing.shared),
        Shared::AwaitingActor { .. } => Err(format!("{:?}", crossing.shared)),
    }
}

async fn run_chat_legs(occ: &Occurrence) {
    use ciris_edge::chat::{self, Body, PairRole, RoomKey};
    use ciris_edge::mls::cohort_group::{
        key_package_from_bytes, key_package_to_bytes, mint_cohort_key_material,
    };
    use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
    use ciris_edge::replication::attestation_bind::Signers;
    use ciris_persist::encrypted_kv::XChaChaKvStore;
    use ciris_persist::federation::FederationDirectory as _;

    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;

    // publisher ↔ first subscriber. `cohort_members` is [publisher, sub-1, …].
    let Some(publisher) = cfg.cohort_members.first().cloned() else {
        rep.not_run("ladder.open_chat", "no cohort");
        rep.not_run("ladder.send_message", "no cohort");
        return;
    };
    let Some(first_sub) = cfg.cohort_members.get(1).cloned() else {
        rep.not_run("ladder.open_chat", "no subscriber in the cohort");
        rep.not_run("ladder.send_message", "no subscriber in the cohort");
        return;
    };
    let (i_send, peer_node) = if cfg.node_id == publisher {
        (true, first_sub)
    } else if cfg.node_id == first_sub {
        (false, publisher)
    } else {
        let why = "the pair chat legs run on the publisher and the first subscriber only";
        rep.not_run("ladder.open_chat", why);
        rep.not_run("ladder.send_message", why);
        return;
    };

    let my_owner = format!("{}-owner", cfg.node_id);
    let Some(peer_owner) = occ
        .roster
        .get(&peer_node)
        .map(|e| e.owner_key_id.clone())
        .filter(|o| !o.is_empty())
    else {
        rep.not_run("ladder.open_chat", "peer published no owner");
        rep.not_run("ladder.send_message", "peer published no owner");
        return;
    };

    // ── ladder.owner_binding_converged (CIRISEdge#568) ───────────────
    //
    // The announce race, MEASURED. Every leg below reads the peer's owner from
    // `cfg.cohort_members` / the roster, so none of them has ever waited on the
    // owner→node binding actually replicating — the race was produced on every
    // run (standup authors the binding locally and it converges over the
    // Attestation plane like any other row; the harness seeds nothing into a
    // peer) and observed by nothing.
    //
    // #568 measured it out of band: 33 s in one direction and 90 s (three
    // rounds) in the other for the same pair of announces, because the owner's
    // Key and the binding that names it ride two independently-scheduled
    // planes. This leg puts that number on the artifact, per direction, so a
    // regression is a red cell instead of a slow run nobody attributes.
    //
    // The pass criterion NAMES THE ROW: `owner_of(peer_node)` must resolve to
    // the peer owner the roster names. "Some owner resolved" would go green on
    // this node's own binding.
    {
        let started = std::time::Instant::now();
        let deadline = started + budget_owner_binding(cfg.barrier_timeout);
        let mut resolved: Option<String> = None;
        while std::time::Instant::now() < deadline {
            resolved = ciris_persist::federation::admission::owner_of(&*occ.directory, &peer_node)
                .await
                .ok()
                .flatten();
            if resolved.as_deref() == Some(peer_owner.as_str()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let ok = resolved.as_deref() == Some(peer_owner.as_str());
        if !ok {
            tracing::error!(
                peer = %peer_node,
                expected_owner = %peer_owner,
                got = ?resolved,
                elapsed_ms,
                "owner binding never converged — every fedID lookup against this \
                 peer stops at owner_of => None (CIRISEdge#568)"
            );
        }
        rep.ran(
            "ladder.owner_binding_converged",
            ok,
            serde_json::json!({
                // Per DIRECTION: this row is what THIS node learned about the
                // PEER, and #568's two directions differed by 57 s.
                "peer": peer_node,
                "expected_owner": peer_owner,
                "resolved_owner": resolved,
                "elapsed_ms": elapsed_ms,
            }),
        );
    }
    let room = chat::pair_community_key_id(&my_owner, &peer_owner);
    let founded_at: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .expect("const ts")
            .into();
    let dir: &dyn ciris_persist::federation::FederationDirectory = &*occ.directory;
    let signers = Signers {
        node: &occ.node_signer,
        actor: Some(&occ.owner_signer),
    };
    let budget = cfg.barrier_timeout.min(Duration::from_secs(90));
    let mut members = vec![my_owner.clone(), peer_owner.clone()];
    members.sort_unstable();

    // ── open_chat: the room record (standup authored it; idempotent) ──
    let room_how =
        match chat::signed_pair_community(&my_owner, &peer_owner, founded_at, &occ.node_signer)
            .await
        {
            Err(e) => Err(e),
            Ok(row) => match occ.directory.put_community(row).await {
                Ok(()) => Ok("authored"),
                Err(ciris_persist::federation::Error::Conflict(_)) => Ok("already present"),
                Err(e) => Err(format!("put_community: {e}")),
            },
        };
    let room_how = match room_how {
        Ok(how) => how,
        Err(e) => {
            tracing::error!(%room, error = %e, "open_chat: the room record failed");
            rep.ran(
                "ladder.open_chat",
                false,
                serde_json::json!({ "room": room, "error": e }),
            );
            rep.not_run("ladder.send_message", "open_chat failed");
            return;
        }
    };

    // ── open_chat: the MLS handshake, OVER THE ROOM ──────────────────
    // Both rows are ordinary community-scoped attestations the owner signs;
    // the audience gate serves each to exactly the other member's nodes.
    let role = PairRole::of(&my_owner, &peer_owner);
    let handshake_start = Instant::now();
    let handshake: Result<(RoomKey, serde_json::Value), String> = async {
        let kv = XChaChaKvStore::open_in_memory(room.as_bytes())
            .map_err(|e| format!("open_in_memory: {e}"))?;
        let store = ScopeStateProvider::new(Arc::new(kv));
        match role {
            PairRole::Creator => {
                let group = CohortGroup::create(store, &room, &my_owner, 16)
                    .await
                    .map_err(|e| format!("CohortGroup::create: {e}"))?;
                let waited = occ
                    .replication
                    .sync_and_await(&peer_node, budget, || async {
                        chat::key_package_from(dir, &peer_owner, &room)
                            .await
                            .is_ok_and(|k| k.is_some())
                    })
                    .await
                    .map_err(|e| format!("sync_and_await: {e}"))?;
                let kp_bytes = chat::key_package_from(dir, &peer_owner, &room)
                    .await?
                    .ok_or_else(|| {
                        format!(
                            "the joiner's KeyPackage did not arrive within {} ms ({} checks)",
                            waited.waited().as_millis(),
                            waited.checks()
                        )
                    })?;
                let kp =
                    key_package_from_bytes(&kp_bytes).map_err(|e| format!("KeyPackage: {e}"))?;
                let commit = group
                    .add_member(&peer_owner, kp)
                    .await
                    .map_err(|e| format!("add_member: {e}"))?;
                let epoch = commit.epoch();
                let welcome = commit
                    .welcome()
                    .ok_or("add_member produced no Welcome")?
                    .to_vec();
                let row = chat::welcome_attestation(
                    &occ.owner_signer,
                    &peer_owner,
                    &welcome,
                    epoch,
                    chrono::Utc::now(),
                )
                .await?;
                let shared = share_in_room(dir, row, &room, signers).await?;
                let key = RoomKey::of(&group).await?;
                Ok((
                    key,
                    serde_json::json!({
                        "role": "creator",
                        "key_package_waited_ms": waited.waited().as_millis(),
                        "key_package_checks": waited.checks(),
                        "key_package_bytes": kp_bytes.len(),
                        "welcome_bytes": welcome.len(),
                        "welcome_shared": shared,
                        "epoch": epoch,
                    }),
                ))
            }
            PairRole::Joiner => {
                let (material, kp) = mint_cohort_key_material(&my_owner)
                    .map_err(|e| format!("mint_cohort_key_material: {e}"))?;
                let kp_bytes = key_package_to_bytes(kp).map_err(|e| format!("KeyPackage: {e}"))?;
                let row = chat::key_package_attestation(
                    &occ.owner_signer,
                    &peer_owner,
                    &kp_bytes,
                    chrono::Utc::now(),
                )
                .await?;
                let shared = share_in_room(dir, row, &room, signers).await?;
                let waited = occ
                    .replication
                    .sync_and_await(&peer_node, budget, || async {
                        chat::welcome_from(dir, &peer_owner, &room)
                            .await
                            .is_ok_and(|w| w.is_some())
                    })
                    .await
                    .map_err(|e| format!("sync_and_await: {e}"))?;
                let (welcome, epoch) = chat::welcome_from(dir, &peer_owner, &room)
                    .await?
                    .ok_or_else(|| {
                        format!(
                            "the creator's Welcome did not arrive within {} ms ({} checks)",
                            waited.waited().as_millis(),
                            waited.checks()
                        )
                    })?;
                let group = CohortGroup::join(store, &room, material, &welcome, 16)
                    .await
                    .map_err(|e| format!("CohortGroup::join: {e}"))?;
                let key = RoomKey::of(&group).await?;
                Ok((
                    key,
                    serde_json::json!({
                        "role": "joiner",
                        "key_package_bytes": kp_bytes.len(),
                        "key_package_shared": shared,
                        "welcome_waited_ms": waited.waited().as_millis(),
                        "welcome_checks": waited.checks(),
                        "welcome_bytes": welcome.len(),
                        "epoch": epoch,
                    }),
                ))
            }
        }
    }
    .await;
    let handshake_ms = handshake_start.elapsed().as_millis();
    let (key, mls) = match handshake {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%room, ?role, error = %e, handshake_ms, "open_chat: the MLS handshake failed");
            rep.ran(
                "ladder.open_chat",
                false,
                serde_json::json!({ "room": room, "role": format!("{role:?}"), "handshake_ms": handshake_ms, "error": e }),
            );
            rep.not_run("ladder.send_message", "the MLS handshake failed");
            return;
        }
    };
    rep.ran(
        "ladder.open_chat",
        true,
        serde_json::json!({
            "room": room,
            "members": members,
            "other_member": peer_owner,
            "how": room_how,
            "role": format!("{role:?}"),
            "mls": mls,
            "handshake_ms": handshake_ms,
            "epoch": key.epoch(),
            "covers": "both ends derive the same two-person room from the two owner \
                       fed-IDs (both FOUNDERS, so both moderators); the MLS handshake \
                       (KeyPackage, Welcome; X-Wing 0x004D) rode the room as ordinary \
                       community-scoped rows the owners signed, and both ends now hold \
                       the room's record secret",
        }),
    );

    // ── send_message ─────────────────────────────────────────────────
    if i_send {
        let sent = async {
            let msg = chat::chat_message_attestation(
                &occ.owner_signer,
                &peer_owner,
                CHAT_BODY,
                chrono::Utc::now(),
                &key,
            )
            .await?;
            // The wire never carries the plaintext — checked at the source.
            let wire = serde_json::to_string(&msg.attestation_envelope).unwrap_or_default();
            if wire.contains(CHAT_BODY) {
                return Err("PLAINTEXT ON THE WIRE: the envelope contains the body".to_owned());
            }
            let sealed = msg.attestation_envelope.get(chat::FIELD_SEALED).cloned();
            let crossing = {
                use ciris_edge::replication::attestation_bind::{share, CrossingBasis, With};
                // persist v41.0.0 (#804) — authored: this leg sealed and
                // signed the message a few lines up.
                occ.directory
                    .put_attestation_authored(ciris_persist::federation::SignedAttestation {
                        attestation: msg.clone(),
                    })
                    .await
                    .map_err(|e| format!("put message: {e}"))?;
                share(
                    dir,
                    &msg,
                    With::Community {
                        community_key_id: room.clone(),
                    },
                    CrossingBasis::ProducerAuthority,
                    signers,
                )
                .await?
            };
            Ok::<_, String>((msg.attestation_id, sealed, crossing))
        }
        .await;
        match sent {
            Ok((id, sealed, crossing)) => {
                use ciris_edge::replication::attestation_bind::Shared;
                tracing::info!(%room, attestation_id = %id, shared = ?crossing.shared, "chat message shared (sealed)");
                rep.ran(
                    "ladder.send_message",
                    matches!(crossing.shared, Shared::Placed { .. }),
                    serde_json::json!({
                        "room": room,
                        "authored_attestation_id": id,
                        "sealed": sealed,
                        "body_on_wire_is_ciphertext": true,
                        "crossing": crossing,
                        "author": my_owner,
                        "attested_by": my_owner,
                        "custody": cfg.node_id,
                        "with": "community",
                        "covers": "the body SEALED under the room's MLS record secret (XChaCha20-Poly1305, \
                                   HKDF per message), authored tier:local / cohort:self by the OWNER \
                                   (sign-at-write, full hybrid), then share(With::Community): enter_mesh \
                                   over the same bytes with the node's co-scrub, then the owner's own \
                                   supersedes at community (CC 5.3.2.4.2 + 4.4.3.3.1)",
                    }),
                );
            }
            Err(e) => {
                tracing::error!(%room, error = %e, "send_message failed");
                rep.ran(
                    "ladder.send_message",
                    false,
                    serde_json::json!({ "room": room, "error": e }),
                );
            }
        }
        return;
    }

    // Receiver: kick rounds toward the sender until the WIDENING — the
    // `supersedes` their share wrote at `community` — is here, then OPEN it.
    let senders = vec![peer_owner.clone()];
    let outcome = occ
        .replication
        .sync_and_await(&peer_node, budget, || async {
            chat::messages_in_room(dir, &senders, &room, &key)
                .await
                .is_ok_and(|m| m.iter().any(|x| x.widens.is_some()))
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "sync_and_await: scheduler unavailable");
            ciris_edge::replication::convergence::Converged::TimedOut {
                waited: Duration::ZERO,
                checks: 0,
            }
        });
    let seen = chat::messages_in_room(dir, &senders, &room, &key)
        .await
        .unwrap_or_default();
    let opened = seen.iter().any(|m| {
        m.widens.is_some()
            && m.body == Body::Text(CHAT_BODY.to_owned())
            && m.author_key_id == peer_owner
            && m.attesting_key_id == peer_owner
    });
    // The RAW rows: the peer's `self` copy must not be here (CC 5.2), and no
    // chat row may carry the plaintext.
    let raw = dir
        .list_attestations_by(&peer_owner)
        .await
        .unwrap_or_default();
    let leaked_self_rows: Vec<String> = raw
        .iter()
        .filter(|a| {
            a.cohort_scope == ciris_persist::federation::types::cohort_scope::SELF
                && a.attestation_envelope
                    .get("dimension")
                    .and_then(serde_json::Value::as_str)
                    == Some(chat::CHAT_MESSAGE_DIMENSION)
        })
        .map(|a| a.attestation_id.clone())
        .collect();
    let plaintext_on_wire: Vec<String> = raw
        .iter()
        .filter(|a| {
            serde_json::to_string(&a.attestation_envelope)
                .unwrap_or_default()
                .contains(CHAT_BODY)
        })
        .map(|a| a.attestation_id.clone())
        .collect();
    let ok = opened && leaked_self_rows.is_empty() && plaintext_on_wire.is_empty();
    if !ok {
        tracing::error!(
            %room, waited_ms = outcome.waited().as_millis(), checks = outcome.checks(),
            messages = seen.len(), opened, leaked_self_rows = ?leaked_self_rows,
            plaintext_on_wire = ?plaintext_on_wire,
            "the peer's sealed WIDENING did not arrive and open within the budget, or a \
             self copy / plaintext leaked here"
        );
    }
    rep.ran(
        "ladder.send_message",
        ok,
        serde_json::json!({
            "room": room,
            "converged_ms": outcome.waited().as_millis(),
            "attempts": outcome.checks(),
            "messages": seen.iter().map(|m| serde_json::json!({
                "attestation_id": m.attestation_id,
                "widens": m.widens,
                "author": m.author_key_id,
                "attested_by": m.attesting_key_id,
                "body": format!("{:?}", m.body),
                "epoch": m.epoch,
            })).collect::<Vec<_>>(),
            "expected_author": peer_owner,
            "expected_attested_by": peer_owner,
            "opened_with_room_key": opened,
            "leaked_self_rows": leaked_self_rows,
            "plaintext_on_wire": plaintext_on_wire,
            "peer_node": peer_node,
            "inbound": occ.inbound_stats.as_json(),
            "covers": "a community-scoped, SEALED chat row attested and signed by the peer's \
                       human — the supersedes their share wrote — arrived over RNS through \
                       the relay, was read back by room, and OPENED with the room's MLS \
                       record secret; no self copy and no plaintext reached this node",
        }),
    );
}

/// The publisher: cohort creator, stream source, blob source, and the
/// node that drives the mid-stream epoch advance.
async fn run_publisher(occ: Occurrence) -> Result<(), String> {
    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;

    // ── Rooting ──────────────────────────────────────────────────────
    let peers: Vec<String> = cfg
        .expect
        .iter()
        .filter(|k| *k != &cfg.node_id)
        .cloned()
        .collect();
    let root_elapsed = match occ.await_rooting(&peers).await {
        Ok(d) => d,
        Err(e) => {
            rep.not_run("mesh.rooting", e.clone());
            return Err(e);
        }
    };
    rep.ran(
        "mesh.rooting",
        true,
        serde_json::json!({
            "peers": peers.len(),
            "converged_ms": root_elapsed.as_millis(),
            "mechanism": "announce_attestation_rooting",
        }),
    );

    // ── Ladder: discovery over the REAL route table ──────────────────
    //
    // CIRISEdge#554. The ladder's resolution logic is unit-tested against a fake
    // lens; what only a running mesh can prove is that a node can actually
    // ADDRESS the peers it has rooted. `knows_peer` is the transport's own
    // readback — the same question the send path asks before it dials — so this
    // leg fails exactly when a send would, rather than when a fixture disagrees.
    //
    // Reachability here also carries the multi-hop claim: a peer is addressable
    // through whatever path Reticulum found, and this node did no relaying to
    // make that true.
    {
        use ciris_edge::contact::{ReticulumRoutes, RouteLens as _};
        let routes = ReticulumRoutes::new(&occ.transport);
        let mut reachable = Vec::new();
        let mut unreachable = Vec::new();
        for peer in &peers {
            if routes.has_destination(peer).await {
                reachable.push(peer.clone());
            } else {
                unreachable.push(peer.clone());
            }
        }
        let all_reachable = unreachable.is_empty() && !reachable.is_empty();
        rep.ran(
            "ladder.discover",
            all_reachable,
            serde_json::json!({
                "rooted_peers": peers.len(),
                "reachable": reachable.len(),
                "unreachable": unreachable,
                "readback": "transport.knows_peer",
                // Stated so a reader of the census knows what this leg does NOT
                // cover: identifier resolution is the NEXT leg
                // (`ladder.discover_by_fedid`), which walks owner bindings.
                "covers": "route reachability only; identifier resolution is the next leg",
            }),
        );
    }

    // ── Ladder: DISCOVERY THROUGH THE FEDERATION DIRECTORY ───────────
    //
    // The rung the server's chat harness stops at, and the one only a running
    // mesh can prove. Everything here resolves against this node's persist
    // directory — the same state replication feeds — for a PEER's owner, whose
    // binding this node never seeded and learned over the wire.
    //
    // fedID → person → their nodes → a node this node can actually address.
    // That is the whole discovery mechanism: `identity_type` says what an
    // identifier names, `owner_of`/`nodes_owned_by` walk the owner bindings,
    // and `discover` refuses to report someone as found when nothing answers.
    {
        use ciris_edge::contact::{PersistLens, ReticulumRoutes};
        let lens = PersistLens::new(occ.directory.as_ref());
        let routes = ReticulumRoutes::new(&occ.transport);

        run_discover_by_fedid_leg(&occ, &lens, &routes).await;
    }

    // ── Ladder: the pair chat, through the one-verb DX ───────────────
    {
        run_chat_legs(&occ).await;
    }

    // ── Cohort: create, admit members over the real wire ─────────────
    let kv = Arc::new(open_sealed_kv(
        &cfg.state_dir,
        &cfg.state_dir.join("fed/ed25519.seed"),
    )?);
    let store = ScopeStateProvider::new(kv);
    let group = CohortGroup::create(store, &cfg.community_id, &cfg.node_id, 16)
        .await
        .map_err(|e| format!("CohortGroup::create: {e}"))?;

    // Members that join before the stream starts. The late joiner (if
    // any) is deliberately held back so its admission rotates the epoch
    // MID-STREAM, which is what the conformance leg measures.
    let early: Vec<String> = cfg
        .cohort_members
        .iter()
        .filter(|m| *m != &cfg.node_id && Some(*m) != cfg.late_joiner.as_ref())
        .cloned()
        .collect();

    let join_start = Instant::now();
    let mut admitted: Vec<String> = Vec::new();
    let mut pending_late: Option<(String, String)> = None;
    while admitted.len() < early.len() {
        let (_src, msg) = occ
            .mailbox
            .next_control(cfg.barrier_timeout)
            .await
            .map_err(|e| format!("waiting for KeyPackages: {e}"))?;
        let Control::KeyPackage { key_id, kp_b64 } = msg else {
            continue;
        };
        if Some(&key_id) == cfg.late_joiner.as_ref() {
            // Hold it: this one is admitted mid-stream.
            pending_late = Some((key_id, kp_b64));
            continue;
        }
        if admitted.contains(&key_id) {
            continue;
        }
        let (welcome, commit, epoch) = admit(&group, &key_id, &kp_b64).await?;
        send_control(
            &occ.transport,
            &key_id,
            &Control::Welcome {
                key_id: key_id.clone(),
                welcome_b64: B64.encode(&welcome),
            },
        )
        .await
        .map_err(|e| format!("send Welcome to {key_id}: {e}"))?;
        // Every already-admitted member must advance in step — a
        // member left behind holds keys for a dead epoch and dies on
        // the NEXT commit it sees. Distribution is awaited member by
        // member before the next admission is taken, so at most one
        // commit is ever outstanding toward any member; the receive
        // side still absorbs reordering (`CommitApplyOutcome`), this
        // just keeps the hold buffer off the happy path.
        let commit_b64 = B64.encode(&commit);
        for m in &admitted {
            let _ = send_control(
                &occ.transport,
                m,
                &Control::Commit {
                    epoch,
                    commit_b64: commit_b64.clone(),
                },
            )
            .await;
        }
        admitted.push(key_id);
        // A short pause between successive admissions lets the fanned
        // commit clear the transport before its successor is minted —
        // pacing, not an ack protocol.
        tokio_sleep(Duration::from_millis(150)).await;
    }
    rep.ran(
        "cohort.join",
        true,
        serde_json::json!({
            "members_admitted": admitted.len(),
            "epoch": group.epoch().await,
            "elapsed_ms": join_start.elapsed().as_millis(),
            "mechanism": "real_mls_keypackage_and_welcome_over_rns",
        }),
    );

    // ── Scope addresses, through the documented two lines ────────────
    let installed = occ.install_addresses(&group).await?;
    rep.ran(
        "scope.install",
        true,
        serde_json::json!({
            "derived": installed.derived,
            "epoch": installed.epoch,
            "own_address": hex::encode(installed.own_address.as_bytes()),
            "registered_on_transport": occ
                .transport
                .inbound_scope(installed.own_address.as_bytes())
                .is_some(),
        }),
    );

    // Wait for every early member to say its addresses are installed.
    let mut ready: Vec<String> = Vec::new();
    while ready.len() < admitted.len() {
        let (_src, msg) = occ
            .mailbox
            .next_control(cfg.barrier_timeout)
            .await
            .map_err(|e| format!("waiting for Ready: {e}"))?;
        match msg {
            Control::Ready { key_id, .. } => {
                if !ready.contains(&key_id) {
                    ready.push(key_id);
                }
            }
            // The late joiner's KeyPackage races this barrier. Dropping
            // it here loses it for good: the joiner then waits out its
            // whole barrier for a Welcome that can never come, and the
            // mid-stream advance never happens.
            Control::KeyPackage { key_id, kp_b64 } if Some(&key_id) == cfg.late_joiner.as_ref() => {
                pending_late = Some((key_id, kp_b64));
            }
            _ => {}
        }
    }

    // ── The stream ───────────────────────────────────────────────────
    let media = std::fs::read(&cfg.media_path)
        .map_err(|e| format!("read media {}: {e}", cfg.media_path.display()))?;
    let units = annexb_access_units(&media)?;
    let media_sha = hex::encode(Sha256::digest(&media));

    let mut stream_id_bytes = [0u8; 32];
    stream_id_bytes.copy_from_slice(&Sha256::digest(cfg.community_id.as_bytes()));
    let stream_id = StreamId(stream_id_bytes);

    for m in &admitted {
        let _ = send_control(
            &occ.transport,
            m,
            &Control::StreamStart {
                stream_id_hex: hex::encode(stream_id.0),
                frames: cfg.frames,
            },
        )
        .await;
    }

    let link = TransportMediaLink {
        transport: Arc::clone(&occ.transport),
    };
    let mut record = *group
        .record_secret()
        .await
        .map_err(|e| format!("record_secret: {e}"))?
        .as_bytes();
    let mut epoch = group.epoch().await;
    let (mut dek_bytes, mut transit) = epoch_keys(&record, &stream_id, epoch)?;

    let mut send_lat: Vec<u128> = Vec::new();
    let mut rotation: Option<serde_json::Value> = None;
    let mut frames_sent = 0usize;
    let mut bytes_sent = 0u64;
    // Wall time spent at the rotation barrier, excluded from the fan-out
    // window below and reported on its own.
    let mut rotation_stall = Duration::ZERO;
    let mut live: Vec<String> = admitted.clone();
    let stream_start = Instant::now();

    for seq in 0..cfg.frames {
        // Mid-stream epoch advance: admit the late joiner, then move the
        // addresses make-before-break. Every existing member must keep
        // receiving across this.
        if cfg.rotate_at == Some(seq) {
            // The late joiner may have presented its KeyPackage after the
            // pre-stream collection loop ended, in which case it is sitting
            // in the mailbox rather than in `pending_late`. Drain for it,
            // bounded — and if it never comes, report a leg that did not run
            // rather than a rotation that silently did not happen.
            if pending_late.is_none() && cfg.late_joiner.is_some() {
                let want = cfg.late_joiner.clone();
                let until = Instant::now() + cfg.barrier_timeout;
                while pending_late.is_none() && Instant::now() < until {
                    if let Ok((_s, Control::KeyPackage { key_id, kp_b64 })) =
                        occ.mailbox.next_control(Duration::from_secs(5)).await
                    {
                        if Some(&key_id) == want.as_ref() {
                            pending_late = Some((key_id, kp_b64));
                        }
                    }
                }
            }
            let rotation_started = Instant::now();
            let t0 = rotation_started;
            // Two ways to advance the epoch mid-stream, both real MLS:
            // admitting a late joiner (the roster changes - what
            // CIRISEdge#499's criterion is written about), or a plain
            // `rotate()` when the topology has no member to hold back
            // (M=1, where holding one back would leave nobody present
            // ACROSS the advance to assert zero-loss on).
            let (commit_bytes, new_epoch, joiner) = match pending_late.take() {
                Some((late_id, late_kp)) => {
                    let (welcome, commit_bytes, new_epoch) =
                        admit(&group, &late_id, &late_kp).await?;
                    send_control(
                        &occ.transport,
                        &late_id,
                        &Control::Welcome {
                            key_id: late_id.clone(),
                            welcome_b64: B64.encode(&welcome),
                        },
                    )
                    .await
                    .map_err(|e| format!("send late Welcome: {e}"))?;
                    (commit_bytes, new_epoch, Some(late_id))
                }
                None if cfg.late_joiner.is_some() => {
                    rep.not_run(
                        "scope.rotation",
                        "EDGE_ROTATE_AT named a late joiner that never presented a \
                         KeyPackage, so no mid-stream epoch advance was driven",
                    );
                    return Err("late joiner never presented a KeyPackage".to_owned());
                }
                None => {
                    let commit = group
                        .rotate()
                        .await
                        .map_err(|e| format!("CohortGroup::rotate: {e}"))?;
                    let epoch = commit.epoch();
                    let (_e, bytes, _w) = commit.into_parts();
                    (bytes, epoch, None)
                }
            };
            // Existing members apply the commit and advance in step.
            let commit_b64 = B64.encode(&commit_bytes);
            for m in &live {
                let _ = send_control(
                    &occ.transport,
                    m,
                    &Control::Commit {
                        epoch: new_epoch,
                        commit_b64: commit_b64.clone(),
                    },
                )
                .await;
            }
            let advanced = occ.advance_addresses(&group).await?;
            record = *group
                .record_secret()
                .await
                .map_err(|e| format!("record_secret after advance: {e}"))?
                .as_bytes();
            epoch = new_epoch;
            let keys = epoch_keys(&record, &stream_id, epoch)?;
            dek_bytes = keys.0;
            transit = keys.1;
            if let Some(id) = joiner.as_ref() {
                live.push(id.clone());
            }
            rotation = Some(serde_json::json!({
                "at_frame": seq,
                "new_epoch": new_epoch,
                "kind": if joiner.is_some() { "member_join" } else { "rekey_only" },
                "late_joiner": joiner,
                "derived": advanced.derived,
                "own_address": hex::encode(advanced.own_address.as_bytes()),
                "pending_seals": occ.lifecycle.pending_seals(),
                "advance_ms": t0.elapsed().as_millis(),
            }));
            rotation_stall += rotation_started.elapsed();
        }

        let plaintext = &units[seq % units.len()];
        let dek = EpochDek::from_bytes(dek_bytes);
        let inner = seal_av_inner(
            plaintext,
            &dek,
            stream_id,
            Epoch(epoch),
            ChunkSeq(seq as u64),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .map_err(|e| format!("seal_av_inner: {e}"))?;

        // Members get the chunk to open; observers get the identical
        // ciphertext to fail on, for a bounded prefix of the stream.
        // Sending to an observer is deliberate — it is what makes the
        // refusal falsifiable.
        let observers: &[String] = if seq < OBSERVER_FRAMES {
            &cfg.observers
        } else {
            &[]
        };
        for m in live.iter().chain(observers.iter()) {
            let sealed = seal_av_outer(&inner, &transit, m.as_bytes(), seq as u64)
                .map_err(|e| format!("seal_av_outer: {e}"))?;
            let wire = sealed.to_bytes();
            let header = serde_json::json!({
                "seq": seq,
                "epoch": epoch,
                "from": cfg.node_id,
            });
            let t0 = Instant::now();
            let is_member = live.iter().any(|l| l == m);
            match link.deliver(m, &header, &wire).await {
                Ok(()) => {
                    // Only member deliveries are the fan-out being timed;
                    // observer sends exist for the refusal leg and would
                    // otherwise inflate the throughput number.
                    if is_member {
                        send_lat.push(t0.elapsed().as_micros());
                        bytes_sent += wire.len() as u64;
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %m, error = %e, "chunk delivery failed");
                }
            }
        }
        frames_sent += 1;
    }
    // The fan-out window is the streaming wall time MINUS the rotation
    // barrier — the barrier is a wait for a peer, not fan-out work.
    let stream_elapsed = stream_start.elapsed().saturating_sub(rotation_stall);

    for m in &live {
        let _ = send_control(&occ.transport, m, &Control::StreamEnd { frames_sent }).await;
    }

    let secs = stream_elapsed.as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let chunks_per_s = (secs > 0.0).then(|| (frames_sent * live.len()) as f64 / secs);
    #[allow(clippy::cast_precision_loss)]
    let bytes_per_s = (secs > 0.0).then(|| bytes_sent as f64 / secs);
    rep.ran(
        "perf.publish_fanout",
        frames_sent == cfg.frames,
        serde_json::json!({
            "frames_sent": frames_sent,
            "frames_requested": cfg.frames,
            "subscribers": live.len(),
            "media_sha256": media_sha,
            "access_units_in_file": units.len(),
            "bytes_sent": bytes_sent,
            "elapsed_ms": stream_elapsed.as_millis(),
            "rotation_stall_ms": rotation_stall.as_millis(),
            "throughput_excludes_rotation_stall": true,
            "fanout_chunks_per_s": chunks_per_s,
            "fanout_bytes_per_s": bytes_per_s,
            "send_latency": latency_json(&mut send_lat),
            "link_mechanism": link.mechanism(),
            "observers": cfg.observers.len(),
            "observer_frames_each": OBSERVER_FRAMES.min(cfg.frames),
            "observer_sends_excluded_from_throughput": true,
        }),
    );

    let rotated = rotation.is_some();
    match rotation {
        Some(r) => rep.ran("scope.rotation", true, r),
        None => rep.not_run(
            "scope.rotation",
            "EDGE_ROTATE_AT was not set, so no mid-stream epoch advance was driven",
        ),
    }

    // ── Blob fan-out ─────────────────────────────────────────────────
    let blob = TransportBlobPlane {
        transport: Arc::clone(&occ.transport),
    };
    let chunks: Vec<&[u8]> = media.chunks(BLOB_CHUNK).collect();
    for m in &live {
        let _ = send_control(
            &occ.transport,
            m,
            &Control::BlobStart {
                sha256: media_sha.clone(),
                bytes: media.len(),
                chunks: chunks.len(),
            },
        )
        .await;
    }
    let mut per_peer_ms = serde_json::Map::new();
    let blob_start = Instant::now();
    for m in &live {
        let t0 = Instant::now();
        let mut ok = true;
        for (i, c) in chunks.iter().enumerate() {
            let header = serde_json::json!({ "i": i, "n": chunks.len(), "sha256": media_sha });
            if let Err(e) = blob.push_chunk(m, &header, c).await {
                tracing::warn!(peer = %m, error = %e, "blob chunk push failed");
                ok = false;
                break;
            }
        }
        per_peer_ms.insert(
            m.clone(),
            if ok {
                serde_json::json!(t0.elapsed().as_millis())
            } else {
                serde_json::Value::Null
            },
        );
    }
    rep.ran(
        "perf.blob_fanout",
        per_peer_ms.values().all(|v| !v.is_null()),
        serde_json::json!({
            "bytes": media.len(),
            "chunk_bytes": BLOB_CHUNK,
            "chunks": chunks.len(),
            "peers": live.len(),
            "total_ms": blob_start.elapsed().as_millis(),
            "completion_ms_per_peer": per_peer_ms,
            "mechanism": blob.mechanism(),
            "scope_native_fetch": false,
            "note": "push over the real transport; scope-native swarm fetch is the in-flight seam",
        }),
    );

    // ── The tail: one drain loop over every post-stream message ──────
    //
    // Reports and the seal handshake interleave, so a single state
    // machine handles both. Two loops each discarding the other's
    // messages is the shape that silently loses one.
    let probe_timeout = Duration::from_secs(15);
    let mut probe_nonce: u64 = 0;
    let mut member_reports = serde_json::Map::new();
    // `(owner, live_addr, superseded_addr, before_live, before_old)` —
    // the before-readings are `Option<bool>`: `Some(held)` from an ack,
    // `None` on silence.
    #[allow(clippy::type_complexity)]
    let mut seal_probe: Option<(
        String,
        MemberAddress,
        MemberAddress,
        Option<bool>,
        Option<bool>,
    )> = None;
    // No rotation means no superseded address, so the leg says that up
    // front rather than by timing out on a probe that can never come.
    let mut seal_done = if rotated {
        false
    } else {
        rep.not_run(
            "conformance.seal_retires",
            "no epoch advance was driven in this run, so no address was superseded and \
             there is nothing whose retirement could be observed",
        );
        true
    };
    let deadline = Instant::now() + cfg.barrier_timeout;

    // A member sends its Report only AFTER its seal handshake, so all
    // reports in + seal_done is normally the end of the run. If every
    // report is in and no probe ever came, give it a bounded grace and
    // then say so — waiting out the whole barrier would turn a reportable
    // fact into a hang.
    let mut probe_grace: Option<Instant> = None;
    // Seal traffic that arrived while a probe bracket was awaiting its ack
    // (stashed by `probe_scope_address` instead of eaten) — drained before
    // the mailbox so no member's handshake is lost to another's bracket.
    let mut stash: std::collections::VecDeque<Control> = std::collections::VecDeque::new();
    while Instant::now() < deadline {
        if member_reports.len() >= live.len() {
            if seal_done {
                break;
            }
            let until =
                *probe_grace.get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
            if Instant::now() >= until {
                break;
            }
        }
        let msg = if let Some(m) = stash.pop_front() {
            m
        } else {
            let Ok((_s, msg)) = occ.mailbox.next_control(Duration::from_secs(5)).await else {
                continue;
            };
            msg
        };
        match msg {
            Control::Report { key_id, body } => {
                member_reports.insert(key_id, body);
            }
            // EVERY member that crossed the advance probes and then waits on
            // SealGo — at M≥3 that is several members, near-simultaneously.
            // The network-observed bracket (`conformance.seal_retires`) is
            // measured ONCE, on the first prober; every LATER prober gets an
            // immediate SealGo so its own owner-side `scope.seal` leg can
            // run — withholding it strands that member for its full 90 s
            // wait and reds a leg this loop was starving, not measuring.
            Control::SealProbe { key_id, .. } if seal_probe.is_some() || seal_done => {
                let _ = send_control(
                    &occ.transport,
                    &key_id,
                    &Control::SealGo {
                        key_id: key_id.clone(),
                    },
                )
                .await;
            }
            Control::SealProbe {
                key_id,
                superseded_epoch,
            } => {
                let gid = occ.group_id();
                let (Some(live_a), Some(old_a)) = (
                    occ.table.send_address(&cfg.scope, &gid, &key_id),
                    occ.table
                        .address_at(&cfg.scope, &gid, superseded_epoch, &key_id),
                ) else {
                    rep.not_run(
                        "conformance.seal_retires",
                        format!(
                            "this node's own table holds no live+superseded pair for                              {key_id} at epoch {superseded_epoch}"
                        ),
                    );
                    seal_done = true;
                    // The bracket cannot run, but the member's own
                    // `scope.seal` leg still can — don't strand it.
                    let _ = send_control(
                        &occ.transport,
                        &key_id,
                        &Control::SealGo {
                            key_id: key_id.clone(),
                        },
                    )
                    .await;
                    continue;
                };
                // BEFORE-reading, at the ADMISSION SEAM (module doc:
                // "How seal retirement is measured"). A scoped address
                // is an explicit-hash destination — an arrival
                // discriminator, not a routable endpoint — so it is not
                // dialled: the probe rides the member's announced,
                // rooted node destination through the relay (the path
                // `mesh.rooting` proved), and the member answers from
                // the production arrival-admission lookup. Both
                // addresses must come back `held: true` here, or the
                // after-reading proves nothing. Superseded first, then
                // live — the trailing live answer re-proves the node
                // was still answering after the superseded probe.
                probe_nonce += 1;
                let before_old = probe_scope_address(
                    &occ.transport,
                    &occ.mailbox,
                    &key_id,
                    &old_a,
                    probe_nonce,
                    probe_timeout,
                    &mut ProbeSideChannel {
                        member_reports: &mut member_reports,
                        stash: &mut stash,
                    },
                )
                .await;
                probe_nonce += 1;
                let before_live = probe_scope_address(
                    &occ.transport,
                    &occ.mailbox,
                    &key_id,
                    &live_a,
                    probe_nonce,
                    probe_timeout,
                    &mut ProbeSideChannel {
                        member_reports: &mut member_reports,
                        stash: &mut stash,
                    },
                )
                .await;
                // SealGo goes out even when the before-reading failed:
                // the member's own `scope.seal` leg must still run, and
                // the verdict arm below reports the failed precondition
                // honestly.
                seal_probe = Some((key_id.clone(), live_a, old_a, before_live, before_old));
                let _ = send_control(
                    &occ.transport,
                    &key_id,
                    &Control::SealGo {
                        key_id: key_id.clone(),
                    },
                )
                .await;
            }
            Control::Sealed {
                key_id,
                sealed,
                unretired,
            } => {
                let Some((probe_id, live_a, old_a, before_live, before_old)) = seal_probe.clone()
                else {
                    continue;
                };
                if probe_id != key_id {
                    continue;
                }
                // AFTER-reading: superseded first, then the live
                // control. The seal must refuse the superseded address
                // WHILE the live one still answers — the live answer is
                // what distinguishes "refused" from "node down".
                probe_nonce += 1;
                let after_old = probe_scope_address(
                    &occ.transport,
                    &occ.mailbox,
                    &key_id,
                    &old_a,
                    probe_nonce,
                    probe_timeout,
                    &mut ProbeSideChannel {
                        member_reports: &mut member_reports,
                        stash: &mut stash,
                    },
                )
                .await;
                probe_nonce += 1;
                let after_live = probe_scope_address(
                    &occ.transport,
                    &occ.mailbox,
                    &key_id,
                    &live_a,
                    probe_nonce,
                    probe_timeout,
                    &mut ProbeSideChannel {
                        member_reports: &mut member_reports,
                        stash: &mut stash,
                    },
                )
                .await;
                seal_done = true;
                if before_live != Some(true) || before_old != Some(true) {
                    // The before-reading is the leg's precondition: with
                    // no evidence both addresses were admitted PRE-seal,
                    // a post-seal refusal proves nothing about the seal.
                    // (`null` = the probe went unanswered; `false` = the
                    // member answered but did not hold the address.)
                    rep.not_run(
                        "conformance.seal_retires",
                        format!(
                            "the before-reading did not establish both addresses held \
                             (live={before_live:?}, superseded={before_old:?}); a post-seal \
                             refusal could not be attributed to the seal",
                        ),
                    );
                    continue;
                }
                let verdict = seal_after_verdict(after_live, after_old);
                match verdict {
                    SealAfterVerdict::Retired | SealAfterVerdict::NotRetired { .. } => {
                        rep.ran(
                            "conformance.seal_retires",
                            sealed > 0 && unretired == 0 && verdict == SealAfterVerdict::Retired,
                            serde_json::json!({
                                "owner": key_id,
                                "sealed": sealed,
                                "unretired": unretired,
                                "probe_live_before_held": before_live,
                                "probe_superseded_before_held": before_old,
                                "probe_live_after_held": after_live,
                                "probe_superseded_after_held": after_old,
                                "live_address": hex::encode(live_a.as_bytes()),
                                "superseded_address": hex::encode(old_a.as_bytes()),
                                "addresses_derived_by": "the PROBER's own table, so a \
                                                         held=true answer also proves \
                                                         cross-node derivation agreement",
                                "admission_lookup": "ReticulumTransport::inbound_scope -> \
                                                     ScopeAddressTable::accepts_inbound (the \
                                                     arrival_scope reverse index)",
                                "probe_plane": "application-level AddressProbe over the \
                                                member's announced node destination, \
                                                through the relay",
                                "convergence_secs": cfg.convergence.as_secs(),
                                "measured_by": "a DIFFERENT node than the one that sealed",
                                "note": "a scoped address is an arrival discriminator, not \
                                         a routable endpoint (explicit-hash destinations \
                                         never announce), so admission — not link \
                                         establishment — is the network observable",
                            }),
                        );
                    }
                    SealAfterVerdict::Unanswerable {
                        live_answered,
                        old_answered,
                    } => {
                        rep.not_run(
                            "conformance.seal_retires",
                            if live_answered {
                                format!(
                                    "the post-seal superseded-address probe went \
                                     unanswered (old_answered={old_answered}); silence is \
                                     transport loss, not a refusal (a refusal is an ack \
                                     carrying held=false), so the reading is not evaluable",
                                )
                            } else {
                                "the post-seal live-control probe went unanswered, so \
                                 'superseded refused' would be indistinguishable from \
                                 'node down'"
                                    .to_owned()
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }

    if !seal_done {
        rep.not_run(
            "conformance.seal_retires",
            "no member offered a seal probe before the barrier expired — either no member \
             crossed the epoch advance, or the handshake did not complete",
        );
    }
    if member_reports.len() == live.len() {
        rep.ran(
            "mesh.member_reports",
            true,
            serde_json::json!({ "reports": member_reports }),
        );
    } else {
        rep.not_run(
            "mesh.member_reports",
            format!(
                "only {} of {} members reported before the barrier expired",
                member_reports.len(),
                live.len()
            ),
        );
    }
    Ok(())
}

/// Admit a member from a base64 KeyPackage.
///
/// Returns `(welcome, commit, epoch)`: the Welcome goes to the joiner,
/// the Commit goes to every existing member so they advance in step.
///
/// Edge exposes no KeyPackage byte codec — `mint_cohort_key_material`
/// hands back an openmls `KeyPackage` by value and `add_member` takes
/// one by value, so a cross-process join has to do the tls-codec hop
/// itself. Recorded as a DX finding; done here rather than worked around.
async fn admit(
    group: &CohortGroup,
    key_id: &str,
    kp_b64: &str,
) -> Result<(Vec<u8>, Vec<u8>, u64), String> {
    use openmls::prelude::{
        tls_codec::Deserialize as _, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
    };
    use openmls_traits::OpenMlsProvider as _;

    let raw = B64
        .decode(kp_b64)
        .map_err(|e| format!("decode KeyPackage: {e}"))?;
    let msg = MlsMessageIn::tls_deserialize(&mut raw.as_slice())
        .map_err(|e| format!("KeyPackage wire decode: {e:?}"))?;
    let MlsMessageBodyIn::KeyPackage(kp_in) = msg.extract() else {
        return Err("the joiner did not send a KeyPackage".to_owned());
    };
    let provider = openmls_libcrux_crypto::Provider::default();
    let kp = kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("KeyPackage validate: {e:?}"))?;
    let commit = group
        .add_member(key_id, kp)
        .await
        .map_err(|e| format!("add_member: {e}"))?;
    let epoch = commit.epoch();
    let (_e, commit_bytes, welcome) = commit.into_parts();
    let welcome = welcome.ok_or_else(|| "add_member produced no Welcome".to_owned())?;
    Ok((welcome, commit_bytes, epoch))
}

/// What one inbound Commit control frame produced.
///
/// Mirrors [`CommitApplyOutcome`] plus the harness-side follow-through
/// (address advance, key-ring extension). `Failed` is the only
/// verdict-bearing arm — and it fails the LEG, never the node: a
/// member that stops applying commits still owes the publisher its
/// barrier traffic and its delivery report.
enum CommitDisposition {
    /// Applied (possibly draining held successors); addresses advanced
    /// and the key ring now covers the new epoch.
    Applied(u64),
    /// Framed in a future epoch; held inside the cohort group until
    /// its predecessor lands. Nothing to do here.
    Held,
    /// Duplicate/replay; already applied. Nothing to do.
    Duplicate,
    /// A genuine fault — bad wire bytes, a commit that failed
    /// validation in its own epoch, or the post-apply follow-through
    /// failing.
    Failed(String),
}

/// Feed one base64 Commit through the cohort group and, when it
/// applies, advance addresses and extend the key ring. Ordering
/// weather (out-of-order arrival, duplicates) is absorbed by
/// `apply_remote_commit`'s hold buffer; every problem comes back as a
/// [`CommitDisposition`], never as an `Err` that would kill the node.
///
/// The key ring gains only the epoch the apply LANDED on. A chained
/// drain skips intermediate epochs' keys by design: their exporters
/// are gone once the group ratchets past them (forward secrecy), and
/// no media is sealed under them — the publisher only seals while its
/// epoch is stable, at the stream-start and post-rotation plateaus.
async fn handle_commit_control(
    occ: &Occurrence,
    group: &CohortGroup,
    stream_id: &StreamId,
    key_ring: &mut BTreeMap<u64, ([u8; 32], [u8; 32])>,
    commit_b64: &str,
) -> CommitDisposition {
    let bytes = match B64.decode(commit_b64) {
        Ok(b) => b,
        Err(e) => return CommitDisposition::Failed(format!("decode commit: {e}")),
    };
    match group.apply_remote_commit(&bytes).await {
        Ok(CommitApplyOutcome::Applied(now_epoch)) => {
            if let Err(e) = occ.advance_addresses(group).await {
                return CommitDisposition::Failed(format!("advance_addresses: {e}"));
            }
            let secret = match group.record_secret().await {
                Ok(s) => *s.as_bytes(),
                Err(e) => return CommitDisposition::Failed(format!("record_secret: {e}")),
            };
            match epoch_keys(&secret, stream_id, now_epoch) {
                Ok(keys) => {
                    key_ring.insert(now_epoch, keys);
                    CommitDisposition::Applied(now_epoch)
                }
                Err(e) => CommitDisposition::Failed(format!("epoch_keys: {e}")),
            }
        }
        Ok(CommitApplyOutcome::Deferred { held_for_epoch }) => {
            tracing::info!(
                held_for_epoch,
                "commit arrived ahead of its predecessor; held"
            );
            CommitDisposition::Held
        }
        Ok(CommitApplyOutcome::AlreadyApplied(epoch)) => {
            tracing::info!(epoch, "duplicate commit; already applied");
            CommitDisposition::Duplicate
        }
        Err(e) => CommitDisposition::Failed(format!("apply_remote_commit: {e}")),
    }
}

/// What happened to one inbound media frame.
enum MediaOutcome {
    /// Opened under the epoch's real keys.
    Opened,
    /// Parsed or AEAD-failed under keys we DO hold - a genuine fault.
    Failed,
    /// We hold no keys for that epoch yet. Not a loss: the commit is in
    /// flight. Distinguished from `Failed` deliberately - collapsing the
    /// two would score the make-before-break window as frame loss.
    NoKeyYet,
}

/// Open one sealed chunk under the keys of the epoch its header names.
fn open_media(
    key_ring: &BTreeMap<u64, ([u8; 32], [u8; 32])>,
    epoch: u64,
    seq: u64,
    payload: &[u8],
    link_id: &[u8],
    latency_us: &mut Vec<u128>,
) -> MediaOutcome {
    let Some((dek_bytes, transit)) = key_ring.get(&epoch) else {
        return MediaOutcome::NoKeyYet;
    };
    let Ok(sealed) = SealedAvChunk::from_bytes(payload) else {
        return MediaOutcome::Failed;
    };
    let dek = EpochDek::from_bytes(*dek_bytes);
    let t0 = Instant::now();
    match open_av_chunk(&sealed, transit, link_id, seq, &dek) {
        Ok(plain) if !plain.is_empty() => {
            latency_us.push(t0.elapsed().as_micros());
            MediaOutcome::Opened
        }
        _ => MediaOutcome::Failed,
    }
}

/// An in-progress blob reception.
struct BlobRecv {
    sha256: String,
    expected_bytes: usize,
    slots: Vec<Option<Vec<u8>>>,
    started: Instant,
}

/// A cohort member: joins over the wire, installs addresses, receives.
async fn run_subscriber(occ: Occurrence) -> Result<(), String> {
    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;
    let publisher = cfg
        .cohort_members
        .first()
        .cloned()
        .ok_or("EDGE_COHORT_MEMBERS must name the publisher first")?;

    let root_elapsed = match occ.await_rooting(std::slice::from_ref(&publisher)).await {
        Ok(d) => d,
        Err(e) => {
            rep.not_run("mesh.rooting", e.clone());
            return Err(e);
        }
    };
    rep.ran(
        "mesh.rooting",
        true,
        serde_json::json!({
            "peer": publisher,
            "converged_ms": root_elapsed.as_millis(),
            "mechanism": "announce_attestation_rooting",
        }),
    );

    // A late joiner waits before presenting its KeyPackage so its
    // admission lands mid-stream.
    if cfg.late_joiner.as_deref() == Some(cfg.node_id.as_str()) {
        tokio_sleep(env_secs("EDGE_LATE_JOIN_DELAY_SECS", 5)).await;
    }

    // ── Ladder: discovery over the REAL route table ──────────────────
    //
    // CIRISEdge#554, subscriber side. Discovery must work in BOTH directions:
    // the publisher reaching a subscriber proves nothing about a subscriber
    // reaching back, and a contact request travels the way the publisher does
    // not. A one-directional check passes on a mesh where half the ladder is
    // broken.
    {
        use ciris_edge::contact::{ReticulumRoutes, RouteLens as _};
        let routes = ReticulumRoutes::new(&occ.transport);
        let mut reachable = Vec::new();
        let mut unreachable = Vec::new();
        // The subscriber roots against the publisher, so that is the peer whose
        // reachability the return direction depends on.
        for peer in std::slice::from_ref(&publisher) {
            if routes.has_destination(peer).await {
                reachable.push(peer.clone());
            } else {
                unreachable.push(peer.clone());
            }
        }
        rep.ran(
            "ladder.discover",
            unreachable.is_empty() && !reachable.is_empty(),
            serde_json::json!({
                "rooted_peers": 1,
                "reachable": reachable.len(),
                "unreachable": unreachable,
                "readback": "transport.knows_peer",
                "direction": "subscriber -> publisher",
            }),
        );
    }

    // ── Ladder: DISCOVERY THROUGH THE FEDERATION DIRECTORY ───────────
    //
    // Same leg the publisher runs, in the return direction: this subscriber
    // resolves the PUBLISHER's owner from a binding it learned over the wire.
    {
        use ciris_edge::contact::{PersistLens, ReticulumRoutes};
        let lens = PersistLens::new(occ.directory.as_ref());
        let routes = ReticulumRoutes::new(&occ.transport);
        run_discover_by_fedid_leg(&occ, &lens, &routes).await;
    }

    // ── Ladder: the pair chat, through the one-verb DX ───────────────
    {
        run_chat_legs(&occ).await;
    }

    // ── Real cross-process MLS join ──────────────────────────────────
    let (material, kp) = mint_cohort_key_material(&cfg.node_id)
        .map_err(|e| format!("mint_cohort_key_material: {e}"))?;
    let kp_bytes = {
        use openmls::prelude::tls_codec::Serialize as _;
        openmls::prelude::MlsMessageOut::from(kp)
            .tls_serialize_detached()
            .map_err(|e| format!("serialize KeyPackage: {e:?}"))?
    };
    send_control(
        &occ.transport,
        &publisher,
        &Control::KeyPackage {
            key_id: cfg.node_id.clone(),
            kp_b64: B64.encode(&kp_bytes),
        },
    )
    .await
    .map_err(|e| format!("send KeyPackage: {e}"))?;

    let join_start = Instant::now();
    // Commits can outrun this node's own Welcome on an unordered
    // transport. One consumed here is one the receive loop can never
    // see — a permanent hole in the epoch chain — so they are stashed
    // and fed through the normal commit path once the group exists.
    let mut pre_welcome_commits: std::collections::VecDeque<(u64, String)> =
        std::collections::VecDeque::new();
    let welcome = loop {
        let (_s, msg) = occ
            .mailbox
            .next_control(cfg.barrier_timeout)
            .await
            .map_err(|e| format!("waiting for Welcome: {e}"))?;
        match msg {
            Control::Welcome {
                key_id,
                welcome_b64,
            } if key_id == cfg.node_id => {
                break B64
                    .decode(&welcome_b64)
                    .map_err(|e| format!("decode Welcome: {e}"))?;
            }
            Control::Commit { epoch, commit_b64 } => {
                pre_welcome_commits.push_back((epoch, commit_b64));
            }
            _ => {}
        }
    };
    let kv = Arc::new(open_sealed_kv(
        &cfg.state_dir,
        &cfg.state_dir.join("fed/ed25519.seed"),
    )?);
    let store = ScopeStateProvider::new(kv);
    let group = CohortGroup::join(store, &cfg.community_id, material, &welcome, 16)
        .await
        .map_err(|e| format!("CohortGroup::join: {e}"))?;
    rep.ran(
        "cohort.join",
        true,
        serde_json::json!({
            "epoch": group.epoch().await,
            "members": group.member_count().await,
            "elapsed_ms": join_start.elapsed().as_millis(),
            "mechanism": "real_mls_welcome_over_rns",
        }),
    );

    // ── Addresses ────────────────────────────────────────────────────
    let installed = occ.install_addresses(&group).await?;
    let own_hash = *installed.own_address.as_bytes();
    rep.ran(
        "scope.install",
        true,
        serde_json::json!({
            "derived": installed.derived,
            "epoch": installed.epoch,
            "own_address": hex::encode(own_hash),
            "registered_on_transport": occ.transport.inbound_scope(&own_hash).is_some(),
            "agrees_with_table": occ
                .table
                .send_address(&cfg.scope, &occ.group_id(), &cfg.node_id)
                .map(|a| *a.as_bytes() == own_hash),
        }),
    );
    send_control(
        &occ.transport,
        &publisher,
        &Control::Ready {
            key_id: cfg.node_id.clone(),
            epoch: installed.epoch,
        },
    )
    .await
    .map_err(|e| format!("send Ready: {e}"))?;

    // ── Receive ──────────────────────────────────────────────────────
    let mut stream_id_bytes = [0u8; 32];
    stream_id_bytes.copy_from_slice(&Sha256::digest(cfg.community_id.as_bytes()));
    let stream_id = StreamId(stream_id_bytes);

    // A key RING, not a single key. Each epoch has its own record-plane
    // exporter, so a frame must be opened under the keys of the epoch its
    // header names - never under "the current" ones.
    let mut key_ring: BTreeMap<u64, ([u8; 32], [u8; 32])> = BTreeMap::new();
    {
        let secret = *group
            .record_secret()
            .await
            .map_err(|e| format!("record_secret: {e}"))?
            .as_bytes();
        let e = group.epoch().await;
        key_ring.insert(e, epoch_keys(&secret, &stream_id, e)?);
    }
    // Frames that arrived under an epoch whose commit has not landed yet.
    // THIS is the make-before-break window from the receive side: the
    // publisher advances and sends under the new epoch before every member
    // has applied the commit, and those frames must be held, not dropped.
    // Bounded by MAX_DEFERRED so a wrong-epoch flood cannot grow it
    // without limit.
    let mut deferred: Vec<(u64, u64, Vec<u8>)> = Vec::new();
    let mut deferred_dropped = 0usize;

    // Commit-arrival weather, reported rather than fatal: out-of-order
    // and duplicate arrivals are absorbed (`CommitApplyOutcome`), and
    // even a genuinely failed apply fails a LEG, never the node — a
    // dead member starves the publisher's barriers and cascades.
    let mut commits_applied = 0usize;
    let mut commits_held = 0usize;
    let mut commits_duplicate = 0usize;
    let mut commit_apply_fatal: Option<String> = None;
    // Commits stashed while this node was still waiting for its own
    // Welcome, replayed through the same arm as live arrivals.
    let mut pending_commits = pre_welcome_commits;

    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut opened = 0usize;
    let mut open_failed = 0usize;
    let mut recv_lat: Vec<u128> = Vec::new();
    let mut first_frame_at: Option<Duration> = None;
    let mut stream_end_frames: Option<usize> = None;
    let mut epochs_seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut blob_state: Option<BlobRecv> = None;
    let mut blob_result: Option<serde_json::Value> = None;
    // Chunks that arrived before their announcement. Control and data
    // are separate channels, so nothing orders them.
    let mut blob_early: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut blob_early_dropped = 0usize;
    let mut early_replayed = 0usize;
    // A node admitted mid-stream cannot have received the frames that
    // preceded its own admission, so the zero-loss criterion — which is
    // about members present ACROSS the advance — does not apply to it.
    let joined_mid_stream = cfg.late_joiner.as_deref() == Some(cfg.node_id.as_str());
    // Bounded settle grace once the stream and the blob have both been
    // announced complete, so a run always terminates.
    let mut settle_deadline: Option<Instant> = None;

    let recv_start = Instant::now();
    let deadline = Instant::now() + cfg.barrier_timeout;
    while Instant::now() < deadline {
        // Control first — a commit changes the keys the media path uses.
        {
            // Stashed pre-Welcome commits replay through the SAME arm
            // as live arrivals, so they get identical ordering
            // tolerance and identical follow-through.
            let got = if let Some((epoch, commit_b64)) = pending_commits.pop_front() {
                Some((None, Control::Commit { epoch, commit_b64 }))
            } else {
                let mut rx = occ.mailbox.control.lock().await;
                let got = rx.try_recv().ok();
                drop(rx);
                got
            };
            if let Some((_s, msg)) = got {
                match msg {
                    Control::Commit {
                        epoch: e,
                        commit_b64,
                    } => {
                        // Whatever this arm produces, the member LIVES:
                        // ordering weather is absorbed, and a genuine
                        // fault is reported as a failed leg at the end
                        // of the run instead of `?`-ing the node away
                        // mid-stream.
                        match handle_commit_control(
                            &occ,
                            &group,
                            &stream_id,
                            &mut key_ring,
                            &commit_b64,
                        )
                        .await
                        {
                            CommitDisposition::Applied(now_epoch) => {
                                commits_applied += 1;
                                tracing::info!(
                                    announced_epoch = e,
                                    applied_epoch = now_epoch,
                                    "applied a remote commit and advanced addresses"
                                );
                                // Drain what arrived ahead of the commit.
                                let held = std::mem::take(&mut deferred);
                                for (seq, ep, payload) in held {
                                    match open_media(
                                        &key_ring,
                                        ep,
                                        seq,
                                        &payload,
                                        cfg.node_id.as_bytes(),
                                        &mut recv_lat,
                                    ) {
                                        MediaOutcome::Opened => {
                                            opened += 1;
                                            seen.insert(seq);
                                        }
                                        MediaOutcome::Failed => open_failed += 1,
                                        MediaOutcome::NoKeyYet => deferred.push((seq, ep, payload)),
                                    }
                                }
                            }
                            CommitDisposition::Held => commits_held += 1,
                            CommitDisposition::Duplicate => commits_duplicate += 1,
                            CommitDisposition::Failed(why) => {
                                tracing::warn!(
                                    announced_epoch = e,
                                    error = %why,
                                    "commit apply failed; member stays up, leg will report it"
                                );
                                commit_apply_fatal.get_or_insert(why);
                            }
                        }
                    }
                    Control::StreamEnd { frames_sent } => {
                        stream_end_frames = Some(frames_sent);
                    }
                    Control::BlobStart {
                        sha256,
                        bytes,
                        chunks,
                    } => {
                        let mut recv = BlobRecv {
                            sha256,
                            expected_bytes: bytes,
                            slots: vec![None; chunks],
                            started: Instant::now(),
                        };
                        // Replay whatever outran the announcement.
                        early_replayed = blob_early.len();
                        for (i, payload) in std::mem::take(&mut blob_early) {
                            if let Some(slot) = recv.slots.get_mut(i) {
                                *slot = Some(payload);
                            }
                        }
                        blob_state = Some(recv);
                    }
                    _ => {}
                }
            }
        }

        // Media.
        let media_msg = {
            let mut rx = occ.mailbox.media.lock().await;
            let m = rx.try_recv().ok();
            drop(rx);
            m
        };
        if let Some((_s, header, payload)) = media_msg {
            let seq = header
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX);
            let hdr_epoch = header
                .get("epoch")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            epochs_seen.insert(hdr_epoch);
            if first_frame_at.is_none() {
                first_frame_at = Some(recv_start.elapsed());
            }
            match open_media(
                &key_ring,
                hdr_epoch,
                seq,
                &payload,
                cfg.node_id.as_bytes(),
                &mut recv_lat,
            ) {
                MediaOutcome::Opened => {
                    opened += 1;
                    seen.insert(seq);
                }
                MediaOutcome::Failed => open_failed += 1,
                MediaOutcome::NoKeyYet => {
                    // Held, not lost - the commit for this epoch has not
                    // reached us yet.
                    if deferred.len() < MAX_DEFERRED {
                        deferred.push((seq, hdr_epoch, payload));
                    } else {
                        deferred_dropped += 1;
                    }
                }
            }
        }

        // Blob.
        let blob_msg = {
            let mut rx = occ.mailbox.blob.lock().await;
            let m = rx.try_recv().ok();
            drop(rx);
            m
        };
        if let Some((_s, header, payload)) = blob_msg {
            let i = usize::try_from(
                header
                    .get("i")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(u64::MAX),
            )
            .unwrap_or(usize::MAX);
            if blob_state.is_none() {
                // The announcement has not been processed yet. Hold it.
                if blob_early.len() < MAX_DEFERRED {
                    blob_early.push((i, payload));
                } else {
                    blob_early_dropped += 1;
                }
            } else if let Some(recv) = blob_state.as_mut() {
                if let Some(slot) = recv.slots.get_mut(i) {
                    *slot = Some(payload);
                }
                if recv.slots.iter().all(Option::is_some) {
                    let mut buf = Vec::with_capacity(recv.expected_bytes);
                    for s in recv.slots.iter().flatten() {
                        buf.extend_from_slice(s);
                    }
                    let got = hex::encode(Sha256::digest(&buf));
                    blob_result = Some(serde_json::json!({
                        "chunks": recv.slots.len(),
                        "bytes": buf.len(),
                        "expected_bytes": recv.expected_bytes,
                        "sha256_matches": got == recv.sha256,
                        "completion_ms": recv.started.elapsed().as_millis(),
                        "chunks_arrived_before_announcement": early_replayed,
                        "early_chunks_dropped_over_budget": blob_early_dropped,
                    }));
                    blob_state = None;
                }
            }
        }

        // Done when the stream ended, every announced frame arrived, and
        // the blob completed.
        if stream_end_frames.is_some() {
            let all_in = stream_end_frames.is_some_and(|total| seen.len() >= total);
            if all_in && blob_result.is_some() && !joined_mid_stream {
                break;
            }
            // The grace starts at StreamEnd, NOT at blob completion. A
            // blob that never completes must still end the run and be
            // REPORTED as incomplete rather than wait out the whole
            // barrier — the previous shape only started the clock once
            // the blob had already finished, so an incomplete one hung.
            let settle =
                *settle_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
            if Instant::now() >= settle {
                break;
            }
        }
        tokio_sleep(Duration::from_millis(5)).await;
    }

    // ── Report ───────────────────────────────────────────────────────
    let expected = stream_end_frames;
    let (delivery_ok, delivery_detail) = match expected {
        Some(total) => {
            let missing: Vec<u64> = (0..total as u64).filter(|s| !seen.contains(s)).collect();
            #[allow(clippy::cast_precision_loss)]
            let ratio = if total == 0 {
                None
            } else {
                Some(seen.len() as f64 / total as f64)
            };
            (
                missing.is_empty(),
                serde_json::json!({
                    "frames_announced": total,
                    "frames_opened": opened,
                    "distinct_seqs": seen.len(),
                    "delivery_ratio": ratio,
                    "missing_seqs": missing,
                    "open_failures": open_failed,
                    "still_deferred_awaiting_commit": deferred.len(),
                    "deferred_dropped_over_budget": deferred_dropped,
                    "commits_applied": commits_applied,
                    "commits_held_for_order": commits_held,
                    "commits_duplicate": commits_duplicate,
                    "epochs_observed": epochs_seen.iter().copied().collect::<Vec<u64>>(),
                    "time_to_first_frame_ms": first_frame_at.map(|d| d.as_millis()),
                    "open_latency": latency_json(&mut recv_lat.clone()),
                }),
            )
        }
        None => (false, serde_json::json!({})),
    };

    if expected.is_none() {
        rep.not_run(
            "conformance.rotation_frame_loss",
            "the publisher never announced StreamEnd, so no delivery ratio could be computed",
        );
        rep.not_run(
            "perf.receive",
            "the publisher never announced StreamEnd, so nothing bounds what should have arrived",
        );
    } else if joined_mid_stream {
        // THE honest arm. This node was admitted at the rotation, so the
        // frames before it are not losses. Scoring it against zero-loss
        // would be scoring the wrong node; saying nothing would hide that
        // a member's numbers were dropped.
        rep.not_run(
            "conformance.rotation_frame_loss",
            "this node was admitted mid-stream; the zero-loss criterion is about members \
             present ACROSS the advance, and pre-admission frames are not losses",
        );
        rep.ran("perf.receive", !seen.is_empty() && open_failed == 0, {
            let mut d = delivery_detail.clone();
            if let Some(o) = d.as_object_mut() {
                o.insert("joined_mid_stream".to_owned(), serde_json::json!(true));
                o.insert(
                    "scored_on".to_owned(),
                    serde_json::json!("frames received after admission open cleanly"),
                );
            }
            d
        });
    } else {
        rep.ran(
            "conformance.rotation_frame_loss",
            delivery_ok && epochs_seen.len() > 1,
            {
                let mut d = delivery_detail.clone();
                if let Some(o) = d.as_object_mut() {
                    o.insert(
                        "crossed_an_epoch_advance".to_owned(),
                        serde_json::json!(epochs_seen.len() > 1),
                    );
                }
                d
            },
        );
        rep.ran("perf.receive", delivery_ok, delivery_detail);
    }

    // A commit-apply fault surfaces HERE, as a failed leg — the member
    // stayed up for the barriers and its delivery report above, which
    // is what keeps one bad commit from cascading into starved
    // publishers and null blob completions.
    if let Some(why) = commit_apply_fatal.as_ref() {
        rep.ran(
            "cohort.commit_apply",
            false,
            serde_json::json!({
                "error": why,
                "commits_applied": commits_applied,
                "commits_held_for_order": commits_held,
                "commits_duplicate": commits_duplicate,
            }),
        );
    }

    match blob_result.clone() {
        Some(b) => rep.ran(
            "conformance.member_can_fetch",
            b.get("sha256_matches").and_then(serde_json::Value::as_bool) == Some(true),
            b,
        ),
        None => rep.not_run(
            "conformance.member_can_fetch",
            "the blob did not complete within the barrier",
        ),
    }

    // ── Seal handshake ───────────────────────────────────────────────
    //
    // Only the OWNER of an address can retire it, so this node seals and
    // the PUBLISHER takes the before/after network reading. The order is
    // strict: probe → publisher's before-probes → SealGo → seal → Sealed
    // → publisher's after-probes. Anything else and the two readings
    // would not bracket the seal.
    //
    // The publisher's readings are application-level `AddressProbe`s
    // over THIS node's announced destination (a scoped address is an
    // arrival discriminator, not a routable endpoint — module doc), and
    // this node answers each one from the production arrival-admission
    // lookup, so the answers ARE the admission seam, not bookkeeping.
    let gid = occ.group_id();
    match occ
        .table
        .live_epochs(&cfg.scope, &gid)
        .and_then(|e| e.previous)
    {
        None => rep.not_run(
            "scope.seal",
            "this node holds no superseded epoch — it did not cross an epoch advance, so \
             there is nothing to retire",
        ),
        Some(previous) => {
            let handshake = async {
                send_control(
                    &occ.transport,
                    &publisher,
                    &Control::SealProbe {
                        key_id: cfg.node_id.clone(),
                        superseded_epoch: previous,
                    },
                )
                .await
                .map_err(|e| format!("send SealProbe: {e}"))?;
                // Wait for the publisher's before-reading to be taken,
                // answering its address probes while doing so — the
                // before-reading IS those probes, so a loop that only
                // listened for SealGo would deadlock the handshake.
                let until = Instant::now() + Duration::from_secs(90);
                loop {
                    if Instant::now() >= until {
                        return Err("no SealGo from the publisher".to_owned());
                    }
                    match occ.mailbox.next_control(Duration::from_secs(5)).await {
                        Ok((_s, Control::SealGo { key_id })) if key_id == cfg.node_id => break,
                        Ok((_s, Control::AddressProbe { address_hex, nonce })) => {
                            answer_address_probe(&occ.transport, &publisher, &address_hex, nonce)
                                .await;
                        }
                        _ => {}
                    }
                }
                // The convergence window is what makes a seal legitimate;
                // sealing before it elapses would cut off a straggler.
                tokio_sleep(cfg.convergence + Duration::from_secs(1)).await;
                let outcome = occ.lifecycle.seal_due(Instant::now());
                send_control(
                    &occ.transport,
                    &publisher,
                    &Control::Sealed {
                        key_id: cfg.node_id.clone(),
                        sealed: outcome.sealed,
                        unretired: outcome.unretired,
                    },
                )
                .await
                .map_err(|e| format!("send Sealed: {e}"))?;
                // The publisher's after-reading is two more probes
                // (superseded, then the live control). Service them
                // before moving on to the Report — the seal already ran,
                // so each answer is the POST-seal admission verdict. The
                // count bounds the wait when both arrive; the deadline
                // bounds it when a probe is lost in transit.
                let mut answered = 0u8;
                let until = Instant::now() + Duration::from_secs(60);
                while answered < 2 && Instant::now() < until {
                    if let Ok((_s, Control::AddressProbe { address_hex, nonce })) =
                        occ.mailbox.next_control(Duration::from_secs(5)).await
                    {
                        answer_address_probe(&occ.transport, &publisher, &address_hex, nonce).await;
                        answered += 1;
                    }
                }
                Ok::<_, String>((outcome, previous))
            }
            .await;

            match handshake {
                Ok((outcome, prev_epoch)) => {
                    let old = occ
                        .table
                        .address_at(&cfg.scope, &gid, prev_epoch, &cfg.node_id);
                    let live_addr = occ.table.send_address(&cfg.scope, &gid, &cfg.node_id);
                    rep.ran(
                        "scope.seal",
                        outcome.sealed > 0
                            && outcome.unretired == 0
                            && old.is_none()
                            && live_addr.as_ref().is_some_and(|a| {
                                occ.transport.inbound_scope(a.as_bytes()).is_some()
                            }),
                        serde_json::json!({
                            "superseded_epoch": prev_epoch,
                            "sealed": outcome.sealed,
                            "unretired": outcome.unretired,
                            "superseded_still_in_table": old.is_some(),
                            "live_still_answers": live_addr
                                .as_ref()
                                .map(|a| occ.transport.inbound_scope(a.as_bytes()).is_some()),
                            "convergence_secs": cfg.convergence.as_secs(),
                        }),
                    );
                }
                Err(e) => rep.not_run("scope.seal", e),
            }
        }
    }

    // Hand the numbers back to the publisher so one place has the mesh
    // view. Failure to deliver the report is not a silent success.
    let (_any, all_ok) = rep.verdict();
    let _ = send_control(
        &occ.transport,
        &publisher,
        &Control::Report {
            key_id: cfg.node_id.clone(),
            body: serde_json::json!({
                "all_legs_ran_and_passed": all_ok,
                "frames_opened": opened,
                "blob": blob_result,
            }),
        },
    )
    .await;
    Ok(())
}

/// A relay: a real transit node on the mesh. It carries ciphertext and
/// holds no cohort secret — which is exactly what makes the refusal leg
/// meaningful for it too.
async fn run_relay(occ: Occurrence) -> Result<(), String> {
    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;
    let peers: Vec<String> = cfg
        .expect
        .iter()
        .filter(|k| *k != &cfg.node_id)
        .cloned()
        .collect();
    match occ.await_rooting(&peers).await {
        Ok(d) => rep.ran(
            "mesh.rooting",
            true,
            serde_json::json!({
                "peers": peers.len(),
                "converged_ms": d.as_millis(),
                "transit_node": true,
                "mechanism": "announce_attestation_rooting",
            }),
        ),
        Err(e) => {
            rep.not_run("mesh.rooting", e.clone());
            return Err(e);
        }
    }
    // A relay holds no cohort state, so it must derive no address.
    let derived = occ
        .table
        .send_address(&cfg.scope, &occ.group_id(), &cfg.node_id)
        .is_some();
    rep.ran(
        "conformance.relay_holds_no_cohort_address",
        !derived,
        serde_json::json!({
            "derived_an_address": derived,
            "why": "a relay is not in the cohort roster, so no exporter secret reaches it",
        }),
    );
    // Stay up for the whole run so the mesh has its transit path.
    tokio_sleep(cfg.barrier_timeout).await;
    Ok(())
}

/// A real node on the mesh that is NOT in the cohort.
///
/// Its whole job is to make the refusal assertion falsifiable: it is
/// rooted, reachable, and receives the same ciphertext, and it must
/// still be unable to open it or to name a cohort-scoped address.
async fn run_nonmember(occ: Occurrence) -> Result<(), String> {
    let rep = Arc::clone(&occ.reporter);
    let cfg = &occ.cfg;
    let publisher = cfg
        .cohort_members
        .first()
        .cloned()
        .ok_or("EDGE_COHORT_MEMBERS must name the publisher first")?;

    match occ.await_rooting(std::slice::from_ref(&publisher)).await {
        Ok(d) => rep.ran(
            "mesh.rooting",
            true,
            serde_json::json!({
                "peer": publisher,
                "converged_ms": d.as_millis(),
                "mechanism": "announce_attestation_rooting",
            }),
        ),
        Err(e) => {
            rep.not_run("mesh.rooting", e.clone());
            return Err(e);
        }
    }

    // (a) It cannot derive any cohort-scoped address — it has no
    //     exporter secret, so the table holds nothing for it.
    let no_address = occ
        .table
        .send_address(&cfg.scope, &occ.group_id(), &cfg.node_id)
        .is_none();

    // (b) It cannot open ciphertext it is handed. Wait for a real media
    //     frame (it is on the mesh; the harness addresses one to it) and
    //     try, with a key it derives from material it actually holds.
    let mut tried = 0usize;
    let mut opened = 0usize;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && tried == 0 {
        let msg = {
            let mut rx = occ.mailbox.media.lock().await;
            let m = rx.try_recv().ok();
            drop(rx);
            m
        };
        if let Some((_s, header, payload)) = msg {
            tried += 1;
            let seq = header
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if let Ok(sealed) = SealedAvChunk::from_bytes(&payload) {
                // The best a non-member can do: guess. It has no cohort
                // record secret, so it has neither the transit key nor
                // the DEK.
                let guess = [0u8; 32];
                let dek = EpochDek::from_bytes([0u8; 32]);
                if open_av_chunk(&sealed, &guess, cfg.node_id.as_bytes(), seq, &dek).is_ok() {
                    opened += 1;
                }
            }
        }
        tokio_sleep(Duration::from_millis(50)).await;
    }

    if tried == 0 {
        rep.not_run(
            "conformance.nonmember_cannot_fetch",
            "no cohort ciphertext reached the non-member, so the refusal could not be tested \
             — a leg that refuses nothing proves nothing",
        );
    } else {
        rep.ran(
            "conformance.nonmember_cannot_fetch",
            no_address && opened == 0,
            serde_json::json!({
                "derived_a_scoped_address": !no_address,
                "ciphertext_frames_offered": tried,
                "frames_opened": opened,
                "why": "no cohort exporter secret ⇒ no derived address and no AEAD key",
            }),
        );
    }
    // Stay on the mesh for the rest of the run. A non-member that exits
    // mid-stream is not just unrealistic — it makes the publisher pay a
    // transport timeout on every remaining send to it, which would
    // silently corrupt the fan-out throughput number.
    tokio_sleep(cfg.barrier_timeout).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// main
// ═══════════════════════════════════════════════════════════════════

fn main() -> std::process::ExitCode {
    // Logs to STDERR (the JSONL owns stdout, and mixing them would corrupt the
    // census's input). Default `info`, overridable with `RUST_LOG`.
    //
    // This used to be absent, with a comment explaining that `tracing_subscriber`
    // was a dev-dependency and a `[[bin]]` compiles against `[dependencies]`
    // only. True, and the consequence was that every `tracing::error!` in this
    // binary went nowhere: five consecutive mesh failures were investigated with
    // the diagnostics that would have named the fault compiled in and silent.
    // The dependency is now optional behind `mesh-harness`, which costs library
    // consumers nothing.
    #[cfg(feature = "mesh-harness")]
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let _ = fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .try_init();
    }
    //
    // Reticulum needs a genuine multi-thread runtime.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{{\"fatal\":\"tokio runtime: {e}\"}}");
            return std::process::ExitCode::FAILURE;
        }
    };

    rt.block_on(async {
        let cfg = match Config::from_env() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{{\"fatal\":\"config: {e}\"}}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let reporter = Arc::new(Reporter::new(
            &cfg.node_id,
            cfg.role.as_str(),
            cfg.results.clone(),
        ));
        let role = cfg.role;

        let occ = match stand_up(cfg, Arc::clone(&reporter)).await {
            Ok(o) => o,
            Err(e) => {
                reporter.not_run("mesh.standup", e);
                return std::process::ExitCode::FAILURE;
            }
        };
        reporter.ran(
            "mesh.standup",
            true,
            serde_json::json!({
                "role": role.as_str(),
                "in_cohort": role.in_cohort(),
                "peers_in_roster": occ.roster.len(),
                "transport_dest_hash": hex::encode(occ.transport.local_dest_hash()),
                "interfaces": occ.transport.interface_specs().len(),
                // Intent only: the transport's own INFO wiring-decision
                // log is the authority on the effective (config-wins,
                // clamped) value. `null` when the env var is unset.
                "control_channel_capacity_env":
                    std::env::var("CIRIS_EDGE_RETICULUM_CONTROL_CHANNEL_CAPACITY").ok(),
            }),
        );

        let outcome = match role {
            Role::Publisher => run_publisher(occ).await,
            Role::Relay => run_relay(occ).await,
            Role::Subscriber => run_subscriber(occ).await,
            Role::NonMember => run_nonmember(occ).await,
        };
        if let Err(e) = outcome {
            reporter.not_run("mesh.role_completion", e);
        }

        let (any, all_ok) = reporter.verdict();
        // A run with no legs is a failure, not a pass. So is any leg that
        // did not run.
        if any && all_ok {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{seal_after_verdict, SealAfterVerdict};

    // Field provenance (the #336 lesson): every input below is exactly a
    // value `probe_scope_address` produces — `Some(held)` is an
    // `AddressProbeAck`'s payload, `None` is silence — not a convenient
    // stand-in. The four evaluable combinations first.

    #[test]
    fn after_reading_retired_cleanly() {
        // Superseded refused WHILE the live control still answers: the
        // one shape that passes.
        assert_eq!(
            seal_after_verdict(Some(true), Some(false)),
            SealAfterVerdict::Retired
        );
    }

    #[test]
    fn after_reading_superseded_still_admitted_fails() {
        // The node acked both probes and still holds the superseded
        // address: the seal did not retire at the admission seam.
        assert_eq!(
            seal_after_verdict(Some(true), Some(true)),
            SealAfterVerdict::NotRetired {
                live_held: true,
                old_held: true
            }
        );
    }

    #[test]
    fn after_reading_live_also_retired_fails() {
        // Both acked, both refused: the node is demonstrably alive (it
        // answered), so this is over-retirement — the seal took the
        // live address down with it — and must FAIL, not not_run.
        assert_eq!(
            seal_after_verdict(Some(false), Some(false)),
            SealAfterVerdict::NotRetired {
                live_held: false,
                old_held: false
            }
        );
    }

    #[test]
    fn after_reading_inverted_pair_fails() {
        // Live gone, superseded kept — evaluable and wrong.
        assert_eq!(
            seal_after_verdict(Some(false), Some(true)),
            SealAfterVerdict::NotRetired {
                live_held: false,
                old_held: true
            }
        );
    }

    // The un-evaluable readings: silence is transport loss, never an
    // admission answer, so no `held` payload may be invented for it.

    #[test]
    fn after_reading_live_control_silent_is_indistinguishable() {
        // The live control went unanswered: "superseded refused" would
        // be indistinguishable from "node down", whatever the
        // superseded probe said.
        assert_eq!(
            seal_after_verdict(None, Some(false)),
            SealAfterVerdict::Unanswerable {
                live_answered: false,
                old_answered: true
            }
        );
    }

    #[test]
    fn after_reading_superseded_probe_silent_is_unanswerable() {
        // The live control answered but the superseded probe was lost:
        // a refusal is an ack carrying held=false, so silence cannot be
        // scored as retirement.
        assert_eq!(
            seal_after_verdict(Some(true), None),
            SealAfterVerdict::Unanswerable {
                live_answered: true,
                old_answered: false
            }
        );
    }

    #[test]
    fn after_reading_both_silent_is_unanswerable() {
        assert_eq!(
            seal_after_verdict(None, None),
            SealAfterVerdict::Unanswerable {
                live_answered: false,
                old_answered: false
            }
        );
    }
}
