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
//!   the federation directory. No `inject_rooted_peer_for_test` on the
//!   federation plane.
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
//! Three things the harness cannot reach today, each behind a narrow
//! trait so the real API drops in as a second impl without touching the
//! measurement or the reporting. Two are APIs being built concurrently
//! (`av_spine`, scope-native blob fetch); the third is a verb that does
//! not exist at all yet:
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
//! - [`ScopedDialer`] — how a *scope-derived* address is dialled.
//!   `ScopeAddressTable::send_address` hands you the peer's 16 bytes and
//!   there is no transport verb that takes them; `link_open` resolves
//!   its signing key from the rooted-peer map, which is keyed on
//!   federation destinations. The harness installs the missing binding
//!   itself ([`HarnessScopedDialer`]) and says so in its output
//!   (`dial_binding: "harness_installed"`), so no reader mistakes the
//!   seal-retirement leg for proof that a production dial path exists.
//!
//!   Running it produced a second, larger finding: **a scope-derived
//!   destination is not reachable off-link at all.** It is registered
//!   with `Destination::with_explicit_hash`, and an explicit-hash
//!   destination cannot announce, so no multi-hop RNS path to one can
//!   exist. The federation destination escapes this only because a node
//!   registers an *announceable* named destination beside it; a scoped
//!   address has no such twin by design, since announcing one would
//!   publish the reachability fact the derivation exists to withhold.
//!   So the peer-dials-it half of "a sealed address finds nobody home"
//!   is not measurable from a relayed peer today, and the leg reports
//!   `ran: false` carrying that diagnosis. The owner-side half IS
//!   measured, by the member's own `scope.seal` leg.
//!
//! Blob fetch is scope-*gated* here but not yet scope-*native*:
//! `src/blob_swarm/` is being extended concurrently. See [`BlobPlane`].
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
use ciris_edge::cohort_scope::CohortScope;
use ciris_edge::identity::LocalSigner;
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, CommitApplyOutcome, ScopeStateProvider};
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
                let _ = writeln!(f, "{line}");
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
}

/// The steward that scrub-signs the roster into `federation_keys` rows.
///
/// A federation has a trust root; in a harness the publisher plays it.
/// Its seed lives in the publisher's own private state dir. The shared
/// volume carries only the resulting signed *rows*.
const STEWARD_KEY_ID: &str = "bench-mesh-steward";

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

/// Read a peer's transport ed25519 half, or `None` if it has not
/// published one yet.
fn peer_transport_ed25519(mesh: &Path, key_id: &str) -> Option<[u8; 32]> {
    let path = roster_dir(mesh).join(format!("{key_id}.transport.json"));
    let bytes = std::fs::read(path).ok()?;
    let entry: TransportEntry = serde_json::from_slice(&bytes).ok()?;
    let raw = B64.decode(entry.transport_ed25519_b64).ok()?;
    raw.try_into().ok()
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
    let start = Instant::now();
    loop {
        let roster = read_roster(mesh);
        let missing: Vec<&String> = expect.iter().filter(|k| !roster.contains_key(*k)).collect();
        if missing.is_empty() {
            return Ok(roster);
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "roster barrier timed out after {}s; still missing {missing:?}",
                timeout.as_secs()
            ));
        }
        tokio_sleep(Duration::from_millis(250)).await;
    }
}

/// Runtime-agnostic sleep (CIRISEdge#217 — never `tokio::time::sleep` on
/// a path that may be driven by a foreign runtime).
async fn tokio_sleep(d: Duration) {
    futures_timer::Delay::new(d).await;
}

/// Wait for a file to appear, then read it.
async fn await_file(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    loop {
        if let Ok(b) = std::fs::read(path) {
            if !b.is_empty() {
                return Ok(b);
            }
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "{} did not appear within {}s",
                path.display(),
                timeout.as_secs()
            ));
        }
        tokio_sleep(Duration::from_millis(250)).await;
    }
}

/// A deterministic-from-seed federation identity.
///
/// The seed itself is CSPRNG-generated on first boot **inside the node's
/// own private state dir**; it is written once and reloaded thereafter,
/// so a restarted container keeps its identity and two containers can
/// never share one.
struct FedKey {
    seed: [u8; 32],
}

impl FedKey {
    /// Load the seed at `dir/ed25519.seed`, generating it on first boot.
    fn load_or_create(key_id: &str, dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join("ed25519.seed");
        let seed = if path.exists() {
            let b = std::fs::read(&path).map_err(|e| format!("read seed: {e}"))?;
            let arr: [u8; 32] = b
                .try_into()
                .map_err(|_| format!("{} is not a 32-byte seed", path.display()))?;
            arr
        } else {
            // Edge has no "mint a fresh federation identity" verb — every
            // existing fixture writes the seed itself. Recorded as a DX
            // finding; the harness does the same, from the CSPRNG.
            let mut arr = [0u8; 32];
            ciris_crypto::random::fill(&mut arr).map_err(|e| format!("csprng: {e}"))?;
            std::fs::write(&path, arr).map_err(|e| format!("write seed: {e}"))?;
            arr
        };
        let _ = key_id;
        Ok(Self { seed })
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
fn signed_record(
    subject_key_id: &str,
    subject_pubkey_b64: &str,
    signer: &Ed25519Signer,
    signer_key_id: &str,
    identity_type: &str,
) -> Result<KeyRecord, String> {
    let envelope = serde_json::json!({ "key_id": subject_key_id });
    let canonical = serde_json::to_vec(&envelope).map_err(|e| format!("canonical: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let sig = signer
        .sign(digest.as_slice())
        .map_err(|e| format!("scrub sign: {e}"))?;
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .map_err(|e| format!("ts: {e}"))?
        .into();
    Ok(KeyRecord {
        key_id: subject_key_id.to_owned(),
        pubkey_ed25519_base64: subject_pubkey_b64.to_owned(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: subject_key_id.to_owned(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
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
    /// Member → creator: "dial my live and superseded addresses BEFORE
    /// I seal". Carries no addresses: the creator derives them from its
    /// OWN table, which is additionally the cross-node agreement check —
    /// a dial that lands proves both nodes derived the same 16 bytes.
    /// Sent only by a member that crossed an epoch advance and therefore
    /// has a superseded epoch to retire.
    SealProbe {
        key_id: String,
        superseded_epoch: u64,
    },
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
fn spawn_inbound(transport: &Arc<ReticulumTransport>) -> Arc<Mailbox> {
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
                tracing::debug!("dropping a non-harness inbound frame");
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

/// **SEAM 2 — how a *scope-derived* address is dialled.**
///
/// `ScopeAddressTable::send_address(scope, group, member)` hands back a
/// peer's 16-byte derived address and there is no transport verb that
/// accepts one: `register_scoped_destination` / `retire_scoped_
/// destination` / `inbound_scope` cover the LISTEN half, and
/// `link_open` resolves its peer signing key from the rooted-peer map,
/// which is keyed on federation destinations. `send_address` has zero
/// non-test callers in the tree.
///
/// The harness supplies the binding itself so the seal-retirement leg
/// can make a real *network* assertion, and stamps
/// `dial_binding: "harness_installed"` on the result so nobody reads
/// that leg as evidence a production dial path exists.
#[async_trait::async_trait]
trait ScopedDialer: Send + Sync {
    fn binding_source(&self) -> &'static str;
    /// Try to establish a link to a scope-derived address. `Ok(true)`
    /// means somebody answered.
    async fn dial(
        &self,
        address: &MemberAddress,
        peer_transport_ed25519: [u8; 32],
        timeout: Duration,
    ) -> bool;
}

struct HarnessScopedDialer {
    transport: Arc<ReticulumTransport>,
}

#[async_trait::async_trait]
impl ScopedDialer for HarnessScopedDialer {
    fn binding_source(&self) -> &'static str {
        // Named, not hidden: the production verb does not exist yet.
        "harness_installed"
    }
    async fn dial(
        &self,
        address: &MemberAddress,
        peer_transport_ed25519: [u8; 32],
        timeout: Duration,
    ) -> bool {
        let hash = *address.as_bytes();
        // Install exactly the (derived hash → peer transport key) binding
        // the missing `dial_scoped` verb would resolve internally. A
        // pseudo key id keyed on the hash keeps it out of the federation
        // peer namespace.
        let pseudo = format!("scoped:{}", hex::encode(hash));
        self.transport
            .inject_rooted_peer_for_test(&pseudo, hash, peer_transport_ed25519)
            .await;
        self.transport.link_open(&hash, timeout).await.is_ok()
    }
}

/// **SEAM 3 — scope-native blob fetch.**
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
    transport: Arc<ReticulumTransport>,
    mailbox: Arc<Mailbox>,
    table: Arc<ScopeAddressTable>,
    lifecycle: Arc<ScopeLifecycle>,
    roster: BTreeMap<String, RosterEntry>,
    reporter: Arc<Reporter>,
}

/// Build the whole occurrence: keys, sealed KV, directory, transport,
/// address table, lifecycle.
async fn stand_up(cfg: Config, reporter: Arc<Reporter>) -> Result<Occurrence, String> {
    std::fs::create_dir_all(&cfg.state_dir)
        .map_err(|e| format!("create state dir {}: {e}", cfg.state_dir.display()))?;

    // ── 1. This node's own federation key (private; own volume only) ──
    let fed = FedKey::load_or_create(&cfg.node_id, &cfg.state_dir.join("fed"))?;

    // ── 2. Publish the public half + reachability ────────────────────
    publish_roster_entry(
        &cfg.mesh_dir,
        &RosterEntry {
            key_id: cfg.node_id.clone(),
            role: cfg.role.as_str().to_owned(),
            advertise: cfg.advertise.clone(),
            fed_pubkey_b64: fed.pubkey_b64()?,
        },
    )
    .map_err(|e| format!("publish roster entry: {e}"))?;

    // ── 3. The publisher plays steward and signs the directory ───────
    let dir_path = directory_path(&cfg.mesh_dir);
    if cfg.role == Role::Publisher {
        let roster = await_roster(&cfg.mesh_dir, &cfg.expect, cfg.barrier_timeout).await?;
        let steward = FedKey::load_or_create(STEWARD_KEY_ID, &cfg.state_dir.join("steward"))?;
        let steward_signer = steward.signer()?;
        let mut rows = vec![signed_record(
            STEWARD_KEY_ID,
            &steward.pubkey_b64()?,
            &steward_signer,
            STEWARD_KEY_ID,
            "steward",
        )?];
        for entry in roster.values() {
            rows.push(signed_record(
                &entry.key_id,
                &entry.fed_pubkey_b64,
                &steward_signer,
                STEWARD_KEY_ID,
                "agent",
            )?);
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
    let roster = read_roster(&cfg.mesh_dir);

    // ── 5. The federation signer, from this node's own seed ──────────
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: cfg.node_id.clone(),
        key_path: cfg.state_dir.join("fed/ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .map_err(|e| format!("load_local_seed: {e}"))?;
    let signer = Arc::new(LocalSigner::new(cfg.node_id.clone(), classical, None));

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

    let mailbox = spawn_inbound(&transport);

    Ok(Occurrence {
        cfg,
        transport,
        mailbox,
        table,
        lifecycle,
        roster,
        reporter,
    })
}

/// Resolve `host:port` with retries — a container's DNS name may not
/// resolve until its peer is up.
async fn resolve_addr(hostport: &str, timeout: Duration) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs as _;
    let start = Instant::now();
    loop {
        if let Ok(mut it) = hostport.to_socket_addrs() {
            if let Some(a) = it.next() {
                return Ok(a);
            }
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "could not resolve {hostport} within {}s",
                timeout.as_secs()
            ));
        }
        tokio_sleep(Duration::from_millis(500)).await;
    }
}

impl Occurrence {
    /// Wait for real announce-based rooting to converge with every peer
    /// we need to talk to. No test hook: this is the production
    /// cold-start path, and a timeout is reported as a leg that did not
    /// run.
    async fn await_rooting(&self, peers: &[String]) -> Result<Duration, String> {
        let start = Instant::now();
        loop {
            let mut missing = Vec::new();
            for p in peers {
                if p != &self.cfg.node_id && !self.transport.knows_peer(p).await {
                    missing.push(p.clone());
                }
            }
            if missing.is_empty() {
                return Ok(start.elapsed());
            }
            if start.elapsed() >= self.cfg.root_timeout {
                return Err(format!(
                    "announce rooting did not converge within {}s; unrooted: {missing:?}",
                    self.cfg.root_timeout.as_secs()
                ));
            }
            tokio_sleep(Duration::from_millis(500)).await;
        }
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
    let dialer = HarnessScopedDialer {
        transport: Arc::clone(&occ.transport),
    };
    let dial_timeout = Duration::from_secs(10);
    let mut member_reports = serde_json::Map::new();
    let mut seal_probe: Option<(String, MemberAddress, MemberAddress, bool, bool)> = None;
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
        let Ok((_s, msg)) = occ.mailbox.next_control(Duration::from_secs(5)).await else {
            continue;
        };
        match msg {
            Control::Report { key_id, body } => {
                member_reports.insert(key_id, body);
            }
            Control::SealProbe {
                key_id,
                superseded_epoch,
            } if seal_probe.is_none() => {
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
                    continue;
                };
                let Some(peer_key) = peer_transport_ed25519(&cfg.mesh_dir, &key_id) else {
                    rep.not_run(
                        "conformance.seal_retires",
                        format!("{key_id} published no transport key, so it cannot be dialled"),
                    );
                    seal_done = true;
                    continue;
                };
                // BEFORE. Both must answer, or the after-reading proves
                // nothing.
                let before_live = dialer.dial(&live_a, peer_key, dial_timeout).await;
                let before_old = dialer.dial(&old_a, peer_key, dial_timeout).await;
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
                let Some(peer_key) = peer_transport_ed25519(&cfg.mesh_dir, &key_id) else {
                    continue;
                };
                // AFTER.
                let after_live = dialer.dial(&live_a, peer_key, dial_timeout).await;
                let after_old = dialer.dial(&old_a, peer_key, dial_timeout).await;
                seal_done = true;
                if before_live && before_old {
                    rep.ran(
                        "conformance.seal_retires",
                        sealed > 0
                            && unretired == 0
                            && after_live
                            && !after_old,
                        serde_json::json!({
                            "owner": key_id,
                            "sealed": sealed,
                            "unretired": unretired,
                            "dial_live_before": before_live,
                            "dial_superseded_before": before_old,
                            "dial_live_after": after_live,
                            "dial_superseded_after": after_old,
                            "live_address": hex::encode(live_a.as_bytes()),
                            "superseded_address": hex::encode(old_a.as_bytes()),
                            "addresses_derived_by": "the DIALLER's own table, so a landed                                                      dial also proves cross-node derivation                                                      agreement",
                            "convergence_secs": cfg.convergence.as_secs(),
                            "dial_binding": dialer.binding_source(),
                            "measured_by": "a DIFFERENT node than the one that sealed",
                            "note": "the dial-side binding is installed by the harness: no \
                                     transport verb dials a ScopeAddressTable::send_address \
                                     result",
                        }),
                    );
                } else {
                    // DIAGNOSED, not shrugged at. A scope-derived
                    // destination is registered with
                    // `Destination::with_explicit_hash`, and an
                    // explicit-hash destination CANNOT announce
                    // (`AnnounceError::ExplicitHashCannotAnnounce`;
                    // leviculum answers path requests for one with
                    // silence, because a path response IS an announce and
                    // an announce for a caller-supplied hash is
                    // unverifiable). It therefore has no multi-hop RNS
                    // path, and this topology puts a relay between the
                    // dialler and the owner.
                    //
                    // So the peer-dials-it form of "the superseded address
                    // finds nobody home" is not measurable today — not
                    // because the seal failed, but because there is no
                    // route to dial in the first place. The owner-side
                    // half IS measured, by the member's own `scope.seal`
                    // leg: table closed, transport retired
                    // (`unretired == 0`), live address still answering.
                    rep.not_run(
                        "conformance.seal_retires",
                        format!(
                            "pre-seal dials did not establish (live={before_live}, \
                             superseded={before_old}), so an after-reading would be \
                             indistinguishable from a broken dial. DIAGNOSIS: a \
                             scope-derived destination is an explicit-hash destination, \
                             which cannot announce, so no multi-hop RNS path to it can \
                             exist and this topology relays between dialler and owner. \
                             The owner-side half of the claim is measured by that \
                             member's `scope.seal` leg instead."
                        ),
                    );
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
    // strict: probe → publisher dials → SealGo → seal → Sealed →
    // publisher dials again. Anything else and the two readings would not
    // bracket the seal.
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
                // Wait for the publisher's before-reading to be taken.
                let until = Instant::now() + Duration::from_secs(90);
                loop {
                    if Instant::now() >= until {
                        return Err("no SealGo from the publisher".to_owned());
                    }
                    if let Ok((_s, Control::SealGo { key_id })) =
                        occ.mailbox.next_control(Duration::from_secs(5)).await
                    {
                        if key_id == cfg.node_id {
                            break;
                        }
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
    // No `tracing_subscriber` init: it is a dev-dependency, and a
    // `[[bin]]` compiles against `[dependencies]` only. The JSONL on
    // stdout is the instrument; `tracing` events compile and are
    // available to any consumer that installs a subscriber.
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
