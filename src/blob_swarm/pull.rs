//! CIRISEdge#601 — **pull on attestation**: the mechanism between "the
//! attestation arrived" and "the member can read it".
//!
//! # The model, stated once
//!
//! Attestations flow first. The attestation is both this node's
//! **authorization** to pull a blob and its **entire ability to know the
//! blob exists** — "no blobs without CEG envelopes/attestations signed by
//! someone; that is an invalid state" ([`super::meaning`]). Blobs never
//! replicate to all peers: holder claims anti-entropy within the roster and
//! bytes move on demand, by pulling. Before this module nothing turned an
//! arriving attestation into a pull, so on every non-author member the
//! transcript was pointers to bytes the node never asked for, reading
//! `Unopened` forever.
//!
//! # Where it sits
//!
//! The replication bridge, on ADMITTING an attestation that references a
//! blob, offers the row to a [`PullSink`] — a bounded channel, `try_send`,
//! never awaited, so admission never blocks on a fetch. The [`BlobPuller`]
//! drains it: for each sha the row references it projects the meaning, runs
//! the store gate (armed with [`super::PersistBlobStorePolicy`]), fetches
//! through the swarm from the holders persist knows, and stores the result
//! through the door the gate's verdict names. One "should we possess this"
//! predicate, run once, before a byte moves.
//!
//! # What it refuses to do
//!
//! - It never fetches on a `holds_bytes` row. Possession is not meaning
//!   ([`BlobMeaning::referenced_shas`] returns nothing for one), and a
//!   puller that fetched on possession claims would fetch every blob every
//!   peer announced.
//! - It never fetches what the store gate refuses. The gate runs inside the
//!   scheduler ahead of dispatch; a refusal ends the pull with no request
//!   sent.
//! - It never guesses an epoch. A `CommunityDek` pointer without a
//!   sealed-under epoch (a row from before the pointer carried one) is left
//!   unfetched and named, because a guessed binding is a blob that reads
//!   `NotGranted` forever with no way to tell it from a real refusal.
//! - It is bounded everywhere: the queue, the in-flight set, the retry
//!   ledger, and the retry count. Overflow drops WITH a log line and a
//!   counter, never a silent stall.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciris_persist::federation::blobs::BlobStorage;
use ciris_persist::federation::types::cohort_scope::CryptoTier;
use ciris_persist::federation::{
    AdoptDisposition, Attestation, BlobBody, BlobProvenance, FederationDirectory,
};
use tokio::sync::mpsc;

use super::meaning::{BlobMeaning, MeaningRefusal};
use super::store_gate::{BlobStorePolicy, StoreDisposition};
use super::{
    BlobChunkVerifier, ChunkManifestLite, ChunkVerifyError, PersistBlobStorePolicy, SwarmConfig,
    SwarmError, SwarmScheduler,
};

/// An ADMITTED attestation that references at least one blob. The bridge
/// offers one per admitted row; the puller works out which shas.
#[derive(Debug, Clone)]
pub struct PullRequest {
    /// The referencing row, as persist admitted it.
    pub row: Attestation,
}

/// What happened when the bridge offered a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullOffer {
    /// Queued for the puller.
    Queued,
    /// The row references no blob (or is a `holds_bytes` row); nothing to do.
    NotAReference,
    /// The queue is full; the offer was DROPPED, logged and counted. The
    /// row is still in persist, so a later re-read (a peer re-advertising
    /// it, a converger sweep) can offer it again.
    Dropped,
}

/// The bridge's handle: a bounded, non-blocking way to say "this row was
/// admitted and references a blob".
#[derive(Clone)]
pub struct PullSink {
    tx: mpsc::Sender<PullRequest>,
    dropped: Arc<AtomicU64>,
}

impl std::fmt::Debug for PullSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullSink")
            .field("capacity", &self.tx.capacity())
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish()
    }
}

impl PullSink {
    /// Offer an admitted row. Never blocks and never awaits: this runs on
    /// the replication apply path.
    ///
    /// The cheap pre-check ([`BlobMeaning::referenced_shas`]) keeps every
    /// row that references nothing — the overwhelming majority of the
    /// attestation plane — from being cloned across the channel.
    pub fn offer(&self, row: &Attestation) -> PullOffer {
        if BlobMeaning::referenced_shas(row).is_empty() {
            return PullOffer::NotAReference;
        }
        match self.tx.try_send(PullRequest { row: row.clone() }) {
            Ok(()) => PullOffer::Queued,
            Err(mpsc::error::TrySendError::Full(req)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    attestation_id = %req.row.attestation_id,
                    dropped_total = n,
                    "pull queue FULL — an admitted row that references a blob was not \
                     queued for fetch. The row is held; the bytes will not be pulled \
                     until it is offered again (CIRISEdge#601)"
                );
                PullOffer::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(req)) => {
                tracing::error!(
                    attestation_id = %req.row.attestation_id,
                    "pull queue CLOSED — the BlobPuller has exited; blob pulls are dark \
                     on this node (CIRISEdge#601)"
                );
                PullOffer::Dropped
            }
        }
    }

    /// How many offers the full queue has dropped since start-up.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A sink whose puller will never run — for tests and for consumers
    /// that want the bridge's hook wired but no puller behind it. Every
    /// offer reports `Dropped` (closed), loudly.
    #[doc(hidden)]
    #[must_use]
    pub fn disconnected() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Bounds and cadence. Every number is a ceiling, never a target.
#[derive(Debug, Clone)]
pub struct PullConfig {
    /// Offers the bridge may queue ahead of the puller. Beyond this, offers
    /// are dropped and counted.
    pub queue_capacity: usize,
    /// Fetches the puller runs concurrently. Each is a swarm fetch with its
    /// own per-peer limits; this bounds the node's total pull fan-out.
    pub max_in_flight: usize,
    /// Rows the puller will retry after a fetch found no fresh holder or
    /// failed transiently. Beyond this the oldest retry is dropped.
    pub retry_capacity: usize,
    /// How many times one blob is retried before it is given up on.
    pub max_attempts: u32,
    /// Delay before the first retry; doubles per attempt.
    pub retry_backoff: Duration,
    /// The swarm scheduler's own knobs.
    pub swarm: SwarmConfig,
    /// The blessed-sender roster for COMMONS content (axis 1 of the store
    /// gate, `CIRISEdge#581`): a federation-tier blob is pulled only from a
    /// holder on this list. Empty refuses every commons blob — the
    /// standing rule ("only content from approved senders gets replicated
    /// at public/federation tiers"). Cohort/family/self content is judged
    /// on membership, not this list.
    pub commons_allowlist: Vec<String>,
    /// The operator's own answer (axis 3): what this node agrees to hold
    /// and whether it advertises holding it, per content class.
    pub consent: super::store_gate::OperatorStoreConsent,
}

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 256,
            max_in_flight: 4,
            retry_capacity: 256,
            max_attempts: 5,
            retry_backoff: Duration::from_secs(5),
            swarm: SwarmConfig::default(),
            commons_allowlist: Vec::new(),
            consent: super::store_gate::OperatorStoreConsent::default(),
        }
    }
}

/// The outcome of one `(row, sha)` pull. Every arm is a named state, so a
/// test can assert which one it reached and a log line can say why nothing
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// The bytes were already here; nothing fetched.
    AlreadyHeld,
    /// Fetched, gated, stored. `announced` is whether a `holds_bytes` claim
    /// went out — the gate's verdict, carried into persist's door.
    Stored { announced: bool },
    /// Another pull for this sha is in flight; this one stood down.
    InFlight,
    /// The row does not give these bytes a meaning this node accepts.
    NoMeaning(MeaningRefusal),
    /// The store gate said no. The refusal is named on the error.
    Refused(String),
    /// persist knows no fresh holder; queued for retry (or given up, if
    /// `attempts` reached the ceiling).
    NoHolders { attempts: u32, retrying: bool },
    /// CIRISEdge#646 — a self/family pull found no node of the author to
    /// ask. These tiers never consult the claim index (CC 5.2: no
    /// `holds_bytes` exists for them by construction); the holders are the
    /// author's nodes, resolved through the directory
    /// (`FSD/CONTENT_TRANSFER.md` §6.2). `retrying` when the directory has
    /// not converged on the author yet (`NotYetDiscovered`) or every node
    /// resolved is this one — a device coming online is a retry, not a
    /// terminal miss.
    NoOtherNode { attempts: u32, retrying: bool },
    /// The fetch failed for a reason that may clear (timeout, transport,
    /// a dishonest holder); queued for retry or given up.
    FetchFailed { reason: String, retrying: bool },
    /// The bytes arrived and the store door refused them. Not retried: the
    /// same bytes and the same provenance will get the same answer.
    StoreFailed(String),
    /// A `CommunityDek` pointer with no sealed-under epoch. Not retried;
    /// the row will never carry one.
    NoEpoch,
}

/// Hash-only verifier for the pull's swarm fetch: the assembled blob is
/// stored by the puller through persist's own door, not chunk by chunk, so
/// the scheduler's per-chunk hook only has to answer "did the peer lie".
struct HashOnlyVerifier;

impl BlobChunkVerifier for HashOnlyVerifier {
    fn verify_and_store(
        &self,
        _blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        bytes: &[u8],
        // Honoured by the CALLER of the scheduler, not here: this verifier
        // stores nothing, so there is no door for it to choose. The puller
        // takes the same verdict back from
        // `fetch_blob_scoped_with_disposition` and picks the persist door.
        _disposition: StoreDisposition,
    ) -> Result<(), ChunkVerifyError> {
        use sha2::{Digest as _, Sha256};
        let got: [u8; 32] = Sha256::digest(bytes).into();
        if got != chunk_sha256 {
            return Err(ChunkVerifyError::Mismatch {
                chunk_sha: hex::encode(chunk_sha256),
            });
        }
        Ok(())
    }
}

/// A pull that did not complete and may be tried again.
#[derive(Debug, Clone)]
struct Retry {
    row: Attestation,
    sha: [u8; 32],
    attempts: u32,
    not_before: std::time::Instant,
}

/// The worker. One per node; built by [`BlobPuller::spawn`].
pub struct BlobPuller<B> {
    edge: Arc<crate::Edge>,
    engine: ciris_persist::Engine,
    backend: Arc<B>,
    local_key_id: String,
    policy: Arc<dyn BlobStorePolicy>,
    config: PullConfig,
    in_flight: Mutex<HashSet<[u8; 32]>>,
    retries: Mutex<HashMap<[u8; 32], Retry>>,
}

/// CIRISEdge#646 — the `scope:source` label for `blob_pull_sources`. A
/// closed set (four scope kinds × two sources) so the counter's keys are
/// enumerable; `author_nodes` is the CC 5.2 path, `claim_index` is
/// `list_holders`.
fn pull_source_tag(scope: &crate::CohortScope, author_nodes: bool) -> &'static str {
    use crate::CohortScope;
    match (scope, author_nodes) {
        (CohortScope::SelfOnly, true) => "self:author_nodes",
        (CohortScope::SelfOnly, false) => "self:claim_index",
        (CohortScope::Family, true) => "family:author_nodes",
        (CohortScope::Family, false) => "family:claim_index",
        (CohortScope::Cohort { .. }, true) => "community:author_nodes",
        (CohortScope::Cohort { .. }, false) => "community:claim_index",
        (CohortScope::Public, true) => "federation:author_nodes",
        (CohortScope::Public, false) => "federation:claim_index",
    }
}

impl<B> BlobPuller<B>
where
    B: FederationDirectory + BlobStorage + Send + Sync + 'static,
{
    /// Build the puller and start its loop. Returns the sink the bridge
    /// offers rows to and the loop's handle.
    ///
    /// `backend` is the persist backend `engine` is built over — the same
    /// substrate, reached as a concrete `BlobStorage` because `list_holders`
    /// and `has_blob` are not object-safe. `local_key_id` is this node's
    /// derived federation key: it is excluded from every holder set (a node
    /// does not fetch from itself) and it is the gate's "me".
    ///
    /// The store gate is ARMED here unconditionally, with persist's rosters
    /// as its facts. There is no unarmed puller: a puller exists only to
    /// take bytes this node did not ask for by hand, which is exactly the
    /// path the gate was built for (CIRISEdge#581).
    pub fn spawn(
        edge: Arc<crate::Edge>,
        engine: ciris_persist::Engine,
        backend: Arc<B>,
        directory: Arc<dyn FederationDirectory>,
        local_key_id: impl Into<String>,
        config: PullConfig,
    ) -> (PullSink, tokio::task::JoinHandle<()>) {
        Self::new(edge, engine, backend, directory, local_key_id, config).start()
    }

    /// Build the puller without starting it. [`Self::pull_one`] can then be
    /// driven directly — how a test asserts the arm one `(row, sha)` reaches
    /// — and [`Self::start`] runs the loop behind a sink.
    pub fn new(
        edge: Arc<crate::Edge>,
        engine: ciris_persist::Engine,
        backend: Arc<B>,
        directory: Arc<dyn FederationDirectory>,
        local_key_id: impl Into<String>,
        config: PullConfig,
    ) -> Arc<Self> {
        let local_key_id = local_key_id.into();
        let policy: Arc<dyn BlobStorePolicy> = Arc::new(
            PersistBlobStorePolicy::new(directory, local_key_id.clone())
                .with_commons_allowlist(config.commons_allowlist.iter().cloned())
                .with_consent(config.consent),
        );
        Arc::new(Self {
            edge,
            engine,
            backend,
            local_key_id,
            policy,
            config,
            in_flight: Mutex::new(HashSet::new()),
            retries: Mutex::new(HashMap::new()),
        })
    }

    /// Start the loop. Returns the sink the bridge offers rows to and the
    /// loop's handle.
    pub fn start(self: Arc<Self>) -> (PullSink, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(self.config.queue_capacity.max(1));
        let sink = PullSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let handle = tokio::spawn(self.run(rx));
        (sink, handle)
    }

    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<PullRequest>) {
        let limiter = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_in_flight.max(1),
        ));
        let mut tick =
            tokio::time::interval(self.config.retry_backoff.max(Duration::from_millis(50)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                req = rx.recv() => {
                    let Some(req) = req else { break };
                    for sha in BlobMeaning::referenced_shas(&req.row) {
                        self.dispatch(&limiter, req.row.clone(), sha, 0);
                    }
                }
                _ = tick.tick() => {
                    for r in self.due_retries() {
                        self.dispatch(&limiter, r.row, r.sha, r.attempts);
                    }
                }
            }
        }
        tracing::info!("BlobPuller: sink closed, exiting");
    }

    fn dispatch(
        self: &Arc<Self>,
        limiter: &Arc<tokio::sync::Semaphore>,
        row: Attestation,
        sha: [u8; 32],
        attempts: u32,
    ) {
        let me = Arc::clone(self);
        let limiter = Arc::clone(limiter);
        tokio::spawn(async move {
            let Ok(_permit) = limiter.acquire().await else {
                return;
            };
            let outcome = me.pull_one(&row, sha, attempts).await;
            tracing::debug!(
                blob = %hex::encode(sha),
                attestation_id = %row.attestation_id,
                ?outcome,
                "pull"
            );
        });
    }

    fn due_retries(&self) -> Vec<Retry> {
        let now = std::time::Instant::now();
        let Ok(mut retries) = self.retries.lock() else {
            return Vec::new();
        };
        let due: Vec<[u8; 32]> = retries
            .iter()
            .filter(|(_, r)| r.not_before <= now)
            .map(|(k, _)| *k)
            .collect();
        due.into_iter().filter_map(|k| retries.remove(&k)).collect()
    }

    /// Book a retry, bounded. Returns whether it was booked (false when the
    /// attempt ceiling is reached).
    fn book_retry(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> bool {
        if attempts + 1 >= self.config.max_attempts {
            return false;
        }
        let backoff = self
            .config
            .retry_backoff
            .checked_mul(1u32 << attempts.min(6))
            .unwrap_or(self.config.retry_backoff);
        let Ok(mut retries) = self.retries.lock() else {
            return false;
        };
        if retries.len() >= self.config.retry_capacity && !retries.contains_key(&sha) {
            // Drop the retry that has waited longest. Bounded means bounded.
            if let Some(oldest) = retries
                .iter()
                .min_by_key(|(_, r)| r.not_before)
                .map(|(k, _)| *k)
            {
                retries.remove(&oldest);
                tracing::warn!(
                    dropped = %hex::encode(oldest),
                    "pull retry ledger FULL — dropped the oldest pending retry (CIRISEdge#601)"
                );
            }
        }
        retries.insert(
            sha,
            Retry {
                row: row.clone(),
                sha,
                attempts: attempts + 1,
                not_before: std::time::Instant::now() + backoff,
            },
        );
        true
    }

    /// **The sequence**, for one blob one row references. Public so a test
    /// can drive it directly and assert the arm it reached.
    ///
    /// Trust → may we accept → should we accept, in that order: the meaning
    /// comes from the signed row (trust), the gate decides possession (may),
    /// and only then does a request go out (should — the holders answer).
    pub async fn pull_one(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> PullOutcome {
        // Dedupe: one fetch per sha at a time, across every row that names it.
        {
            let Ok(mut set) = self.in_flight.lock() else {
                return PullOutcome::InFlight;
            };
            if !set.insert(sha) {
                return PullOutcome::InFlight;
            }
        }
        let outcome = self.pull_one_inner(row, sha, attempts).await;
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&sha);
        }
        outcome
    }

    /// CIRISEdge#646 / `FSD/CONTENT_TRANSFER.md` §6.2 — for a self or
    /// family row the author's identity is the self room's id and the
    /// author's NODES are the holders, so the one directory walk
    /// (`contact::resolve`: key → person → their nodes, CC 4.4.3.2.4.1(b))
    /// is done up front and feeds both the projector and the source rule.
    /// Community and commons rows never need it.
    async fn resolve_author(
        &self,
        row: &Attestation,
    ) -> Option<Result<crate::contact::Subject, crate::contact::LadderStall>> {
        if matches!(
            row.cohort_scope.as_str(),
            ciris_persist::federation::types::cohort_scope::SELF
                | ciris_persist::federation::types::cohort_scope::FAMILY
        ) {
            let lens = crate::contact::PersistLens::new(&*self.backend);
            Some(crate::contact::resolve(&lens, &row.attesting_key_id).await)
        } else {
            None
        }
    }

    /// **The source rule** (CIRISEdge#646, FSD §6.2). The holder SOURCE
    /// follows the key plane's tier, not the row's placement (persist#878):
    /// `InvisibleEncrypted` bytes are never claimed anywhere (CC 5.2,
    /// persist I52), so the claim index is not consulted and `NoHolders` is
    /// not a possible outcome — the holders are the author's nodes, the
    /// sealing node among them. Every other tier is discovered through
    /// `list_holders` as before. `Err` carries the outcome to return.
    async fn holders_for(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        author: Option<&Result<crate::contact::Subject, crate::contact::LadderStall>>,
    ) -> Result<Vec<String>, PullOutcome> {
        let key_plane = meaning.key_plane();
        // The tier is the POINTER's (persist#878), which is also what
        // `key_plane` reads — one source, so the branch and the label cannot
        // disagree about which plane this blob is on.
        let tier = meaning.pointer().map_or(CryptoTier::Plaintext, |p| p.tier);
        if tier != CryptoTier::InvisibleEncrypted {
            self.edge
                .metrics()
                .inc_blob_pull_source(pull_source_tag(key_plane.cohort_scope(), false));
            return match self.backend.list_holders(&sha).await {
                Ok(h) => Ok(h.into_iter().filter(|k| *k != self.local_key_id).collect()),
                Err(e) => Err(PullOutcome::StoreFailed(format!("list_holders: {e}"))),
            };
        }
        let nodes = match author {
            Some(Ok(subject)) => subject.nodes.clone(),
            Some(Err(stall)) => {
                tracing::debug!(
                    blob = %hex::encode(sha),
                    author = %row.attesting_key_id,
                    stall = ?stall,
                    "self/family pull: the author's nodes are not resolvable yet — retrying \
                     on the directory, never asking the claim index (CIRISEdge#646)"
                );
                Vec::new()
            }
            // Unreachable by construction: a self/family row resolved its author.
            None => Vec::new(),
        };
        self.edge
            .metrics()
            .inc_blob_pull_source(pull_source_tag(key_plane.cohort_scope(), true));
        let others: Vec<String> = nodes
            .into_iter()
            .filter(|k| *k != self.local_key_id)
            .collect();
        if others.is_empty() {
            let retrying = self.book_retry(row, sha, attempts);
            return Err(PullOutcome::NoOtherNode { attempts, retrying });
        }
        Ok(others)
    }

    async fn pull_one_inner(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> PullOutcome {
        let blob_hex = hex::encode(sha);

        // Idempotent: held is held.
        match self.backend.has_blob(&sha).await {
            Ok(true) => return PullOutcome::AlreadyHeld,
            Ok(false) => {}
            Err(e) => return PullOutcome::StoreFailed(format!("has_blob: {e}")),
        }

        // TRUST — what the signed row says these bytes are.
        // CIRISEdge#646 / `FSD/CONTENT_TRANSFER.md` §6.2 — for a self or
        // family row the author's identity is the self room's id and the
        // author's NODES are the holders, so the one directory walk
        // (`contact::resolve`: key → person → their nodes, CC 4.4.3.2.4.1(b))
        // is done up front and feeds both the projector and the source rule.
        // Community and commons rows never need it.
        let author = self.resolve_author(row).await;
        let author_identity = author
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(|subject| subject.fed_id.clone());
        let meaning = match BlobMeaning::project_with(row, &sha, author_identity.as_deref()) {
            Ok(m) => m,
            Err(r) => return PullOutcome::NoMeaning(r),
        };

        // The binding the adopt door will need, decided BEFORE any request:
        // a row that cannot be adopted is not worth a fetch.
        let tier = meaning.pointer().map_or(CryptoTier::Plaintext, |p| p.tier);
        if tier == CryptoTier::CommunityDek && meaning.pointer().and_then(|p| p.epoch).is_none() {
            tracing::warn!(
                blob = %blob_hex,
                attestation_id = %row.attestation_id,
                "pull refused: a community_dek pointer with no sealed-under epoch — the \
                 row predates the epoch-bearing pointer, and a guessed epoch is a blob \
                 that reads NotGranted forever (CIRISEdge#601)"
            );
            return PullOutcome::NoEpoch;
        }

        // Who has it — persist's holder plane, minus ourselves.
        let holders = match self
            .holders_for(row, sha, attempts, &meaning, author.as_ref())
            .await
        {
            Ok(h) => h,
            Err(outcome) => return outcome,
        };
        if holders.is_empty() {
            let retrying = self.book_retry(row, sha, attempts);
            return PullOutcome::NoHolders { attempts, retrying };
        }

        // MAY (the gate, inside the scheduler, ahead of dispatch) + the fetch.
        let scheduler = SwarmScheduler::new(
            Arc::clone(&self.edge),
            Arc::new(HashOnlyVerifier),
            self.config.swarm.clone(),
        )
        .with_store_policy(Arc::clone(&self.policy));
        let (bytes, disposition) = match scheduler
            .fetch_blob_scoped_with_disposition(
                sha,
                ChunkManifestLite::whole_blob(sha),
                holders,
                Some(meaning.clone()),
            )
            .await
        {
            Ok(ok) => ok,
            Err(SwarmError::StoreRefused { refusal, axis, .. }) => {
                return PullOutcome::Refused(format!("axis {axis}: {refusal:?}"));
            }
            Err(SwarmError::GoneFederationWide(_)) => {
                return PullOutcome::Refused("withdrawn or revoked federation-wide".into());
            }
            Err(e) => {
                let retrying = self.book_retry(row, sha, attempts);
                return PullOutcome::FetchFailed {
                    reason: e.to_string(),
                    retrying,
                };
            }
        };

        // Store, through the door the gate's verdict names.
        match tier {
            CryptoTier::Plaintext => {
                self.store_plaintext(row, sha, &meaning, bytes, disposition)
                    .await
            }
            CryptoTier::CommunityDek | CryptoTier::InvisibleEncrypted => {
                self.adopt_sealed(row, sha, &meaning, tier, &bytes, disposition)
                    .await
            }
        }
    }

    /// Commons bytes (a manifest, a public attachment): persist's plaintext
    /// door, `put_blob_signing` — stores AND emits this node's hybrid-signed
    /// `holds_bytes`.
    ///
    /// There is no `LocalOnly` plaintext door a consumer can reach:
    /// `store_blob_local` takes a `StorageFloor` that only persist can mint
    /// (I22 — "no code outside this crate can name a `StorageFloor`"). The
    /// commons is everyone's, so the gate answers `Announce` for it in every
    /// case edge has; if a policy ever says `LocalOnly` for plaintext, this
    /// refuses by name rather than announce against the verdict or store
    /// through a door that does not exist.
    async fn store_plaintext(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        bytes: Vec<u8>,
        disposition: StoreDisposition,
    ) -> PullOutcome {
        if disposition == StoreDisposition::LocalOnly {
            return PullOutcome::StoreFailed(
                "the store gate said LocalOnly for PLAINTEXT bytes, and persist exposes no \
                 local-only plaintext door to a consumer (store_blob_local needs a \
                 StorageFloor only persist can mint, I22); refusing rather than announcing \
                 against the verdict"
                    .into(),
            );
        }
        let media_type = meaning.media_type().map(ToOwned::to_owned);
        match self
            .engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                media_type.as_deref(),
                &row.attesting_key_id,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
        {
            Ok(()) => PullOutcome::Stored { announced: true },
            Err(e) => PullOutcome::StoreFailed(e.to_string()),
        }
    }

    /// Sealed bytes: persist's `adopt_sealed_blob` — stored verbatim at the
    /// tier and `(community, epoch)` binding the AUTHOR declared on the row,
    /// never re-sealed (BLOB_REPLICATION.md §3). The AAD is rebuilt from the
    /// row exactly as a reader rebuilds it; persist carries it and does not
    /// record it.
    async fn adopt_sealed(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        tier: CryptoTier,
        bytes: &[u8],
        disposition: StoreDisposition,
    ) -> PullOutcome {
        let Some(pointer) = meaning.pointer() else {
            // A sealed tier is only ever declared by a typed pointer; an
            // `evidence_refs` reference has no tier and resolved Plaintext.
            return PullOutcome::StoreFailed(
                "sealed tier without a typed pointer — cannot form a provenance".into(),
            );
        };
        // v46.1.0 (CIRISPersist#878) — the provenance is READ OFF the row the
        // bytes flowed from, and the constructor now sees edge's reference
        // shape: a typed `BlobPointer` at these bytes is a reference, and it
        // is AUTHORITATIVE for the key plane (tier, community, epoch) while
        // the ROW's placement stands as the access grant. That is the rule
        // edge's own builder implemented; persist owns the one spelling now,
        // and adds what a caller could not: the row must reference the bytes,
        // a `community` row's pointer must name the cohort the row is signed
        // for, and the floor check binds tier to placement.
        //
        // `minter` is `None`: the minter is the key whose cascade MINTED the
        // epoch — the SEALING NODE that signed the `key_grant` set, not the
        // author (for a chat row the author is the person). This node neither
        // minted it nor is told who did, so persist derives it from the one
        // admitted set that granted this node a wrap, and rebinds a row
        // stored against a wrong minter when the next set arrives.
        let provenance = match BlobProvenance::from_attestation(row, &sha, pointer.epoch, None) {
            Ok(p) => p,
            Err(e) => {
                return PullOutcome::StoreFailed(format!(
                    "provenance from the referencing row {}: {e}",
                    row.attestation_id
                ))
            }
        };
        debug_assert_eq!(
            provenance.tier, tier,
            "the pointer persist read is the pointer the meaning projection read"
        );
        let aad = crate::group_content::content_aad(
            &row.attesting_key_id,
            row.asserted_at,
            pointer.content_field,
        );
        let adopt = match disposition {
            StoreDisposition::Announce => AdoptDisposition::Announce,
            StoreDisposition::LocalOnly => AdoptDisposition::LocalOnly,
        };
        match self
            .engine
            .adopt_sealed_blob(bytes, provenance, Some(&aad), adopt)
            .await
        {
            Ok(outcome) => {
                debug_assert_eq!(
                    outcome.sha256, sha,
                    "adopt stores at the ciphertext's address"
                );
                PullOutcome::Stored {
                    announced: outcome.announced,
                }
            }
            Err(e) => PullOutcome::StoreFailed(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::meaning::fixture::{bare_row, content_row};
    use super::*;

    const SHA: [u8; 32] = [0xAB; 32];

    fn sink_with(capacity: usize) -> (PullSink, mpsc::Receiver<PullRequest>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            PullSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// The sink is the apply path's one door, and it must never block or
    /// grow: a full queue drops, counts, and reports it.
    /// CIRISEdge#646 — the counter's keys are a closed set, and the
    /// self/family arms name `author_nodes`: the label a run greps for to
    /// prove a self pull never touched the claim index.
    #[test]
    fn pull_source_tags_are_a_closed_set() {
        use crate::CohortScope;
        let cohort = CohortScope::Cohort {
            cohort_id: "c".into(),
        };
        assert_eq!(
            pull_source_tag(&CohortScope::SelfOnly, true),
            "self:author_nodes"
        );
        assert_eq!(
            pull_source_tag(&CohortScope::Family, true),
            "family:author_nodes"
        );
        assert_eq!(pull_source_tag(&cohort, false), "community:claim_index");
        assert_eq!(
            pull_source_tag(&CohortScope::Public, false),
            "federation:claim_index"
        );
    }

    #[tokio::test]
    async fn a_full_sink_drops_and_counts_rather_than_blocking() {
        let (sink, _rx) = sink_with(1);
        let row = content_row("community", "room", &SHA);
        assert_eq!(sink.offer(&row), PullOffer::Queued);
        assert_eq!(sink.offer(&row), PullOffer::Dropped, "capacity 1 is full");
        assert_eq!(sink.dropped(), 1);
        assert_eq!(sink.offer(&row), PullOffer::Dropped);
        assert_eq!(sink.dropped(), 2);
    }

    /// A row that references nothing costs the apply path no clone and no
    /// channel slot — and a `holds_bytes` row counts as referencing nothing.
    #[tokio::test]
    async fn non_references_never_enter_the_queue() {
        let (sink, mut rx) = sink_with(4);
        let plain = bare_row("federation");
        assert_eq!(sink.offer(&plain), PullOffer::NotAReference);
        let mut holds = bare_row("federation");
        holds.attestation_type = format!("holds_bytes:sha256:{}", &hex::encode(SHA)[..16]);
        holds.attestation_envelope =
            serde_json::json!({ "kind": "holds_bytes", "evidence_refs": [hex::encode(SHA)] });
        assert_eq!(
            sink.offer(&holds),
            PullOffer::NotAReference,
            "possession is not meaning: a holds_bytes row never triggers a pull"
        );
        assert!(rx.try_recv().is_err(), "nothing was queued");
        assert_eq!(sink.dropped(), 0);
    }

    /// CIRISPersist#878 — the two axes of a sealed pull's provenance, on the
    /// shape production actually has: a chat row placed at `self` scope whose
    /// body is sealed under the room's DEK, referencing the bytes with a typed
    /// `BlobPointer` and NO `evidence_refs`. The row gives authorship and
    /// placement; the POINTER gives the community, the epoch and the tier.
    /// Resolving the tier from the row's scope would adopt community-DEK
    /// ciphertext as `InvisibleEncrypted`, and requiring `evidence_refs` would
    /// refuse the row outright — both regressions this pins.
    #[test]
    fn a_pointer_only_chat_row_keeps_the_pointers_tier_and_community() {
        let mut row = content_row(
            ciris_persist::federation::types::cohort_scope::SELF,
            "chat:pair:v1:room",
            &SHA,
        );
        row.attestation_envelope["content"]["tier"] = serde_json::json!("community_dek");
        row.attestation_envelope["content"]["epoch"] = serde_json::json!(7);
        assert!(
            row.attestation_envelope.get("evidence_refs").is_none(),
            "fixture drift: a chat row references its blob by POINTER only"
        );
        let meaning = BlobMeaning::project(&row, &SHA).expect("the pointer is the reference");
        let pointer = meaning.pointer().expect("typed pointer");
        assert_eq!(pointer.tier, CryptoTier::CommunityDek);

        let p = BlobProvenance::from_attestation(&row, &SHA, pointer.epoch, None)
            .expect("the row references the bytes by pointer");
        assert_eq!(p.author_key_id, "alice", "the ROW's attester authors");
        assert_eq!(
            p.cohort_scope,
            ciris_persist::federation::types::cohort_scope::SELF,
            "the ROW's placement is the row's own"
        );
        assert_eq!(
            p.community_key_id.as_deref(),
            Some("chat:pair:v1:room"),
            "the POINTER names the community whose DEK sealed the bytes"
        );
        assert_eq!(p.epoch, Some(7), "the POINTER carries the epoch");
        assert_eq!(
            p.tier,
            CryptoTier::CommunityDek,
            "the POINTER's resolved tier is authoritative — the row sits at self \
             scope and its bytes are sealed under the room's DEK"
        );
    }

    /// CIRISPersist#876 — the minter is NEVER the author. Edge does not mint
    /// epochs and is not told who did, so it always defers the derivation.
    #[test]
    fn the_minter_is_never_transcribed_from_the_author() {
        for author in ["alice", "ciris-node-a-3yr5psjdy4", "someone-else"] {
            let mut row = content_row("community", "room", &SHA);
            row.attesting_key_id = author.to_owned();
            row.attestation_envelope["content"]["tier"] = serde_json::json!("community_dek");
            let meaning = BlobMeaning::project(&row, &SHA).expect("pointer");
            let pointer = meaning.pointer().expect("typed pointer");
            let p = BlobProvenance::from_attestation(&row, &SHA, pointer.epoch, None)
                .expect("the row references the bytes by pointer");
            assert_eq!(p.author_key_id, author);
            assert_eq!(
                p.minter_key_id, None,
                "the sealing node minted the epoch; persist derives it from the \
                 admitted key_grant set (CIRISPersist#876)"
            );
        }
    }

    /// A closed sink (no puller) is loud, not a hang.
    #[test]
    fn a_disconnected_sink_reports_dropped() {
        let sink = PullSink::disconnected();
        let row = content_row("community", "room", &SHA);
        assert_eq!(sink.offer(&row), PullOffer::Dropped);
    }
}
