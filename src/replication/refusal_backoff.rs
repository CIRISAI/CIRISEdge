//! CIRISEdge#544 — the retry DISPOSITION of an apply refusal, and the bounded
//! per-row memory that acts on it.
//!
//! # The loop this closes
//!
//! Anti-entropy's re-offer is RECEIVER-PULLED, not sender-pushed: the round's
//! `want` is `remote.refs ∖ local_holdings` ([`super::session::Session`]'s
//! `on_summary`). A refused row is never stored, so it never enters
//! `local_holdings`, so it is in `want` again next round — and the peer, doing
//! exactly what it was asked, delivers the same bytes again. Every round.
//! At the same transport cost as a healthy delivery.
//!
//! For a refusal that CAN clear on its own that IS the convergence mechanism and
//! it is correct — [`super::bridge::ApplyRefusalClass::is_transient`] documents
//! it as "convergence by construction, not by a retry queue". For one that
//! cannot, it is a permanent uniform-rate burn. #544 measured it on the CIRIS
//! canonical: ONE `Key` row refused `conflicting_version`, re-offered **55× in
//! 30 minutes**, the same content hash every time — so byte-identical, so
//! refused on attempt 56 for the reason it was refused on attempt 1.
//!
//! # What this module does, and what it deliberately does NOT do
//!
//! It suppresses the **ask**, never the **admit**. A suppressed hash is dropped
//! from `want`; an unsolicited Deliver carrying it (the #927 proactive push) is
//! still applied on its merits. Nothing here can withhold a row from local
//! state — the failure mode of an over-eager suppression is a re-offer that
//! arrives a few minutes later, never a row silently dropped.
//!
//! It is keyed on the **content hash**, which is what makes the issue's "the
//! sender needs some way forward other than retrying" work by construction: a
//! corrected, SUPERSEDING record is different bytes, so a different hash, so it
//! is never suppressed. Only the exact bytes that lost are throttled.
//!
//! It is never permanent. A terminal entry decays to a long window, not to
//! silence: the node re-asks on a schedule that shrinks the 55/30min to ~1/30min
//! and then to a handful a day, so a verdict that DOES move (an operator prunes
//! the conflicting row; a code upgrade fixes a wire skew — the latter restarts
//! the process and empties this map anyway) still converges without an operator
//! knowing this memory exists.
//!
//! # Bounded, because the key is peer-influenced
//!
//! The map key contains a content hash a peer chooses by choosing what to offer.
//! An unbounded map would relocate the exhaustion vector into the mitigation —
//! the [`crate::log_throttle`] lesson. Same cure: a front-drop cap
//! ([`DEFAULT_MAX_KEYS`]). Evicting an entry only costs one re-ask. Rows
//! parked on a signer have a ring of their own ([`DEFAULT_MAX_PARKED`],
//! CIRISEdge#858), so ordinary refusals cannot evict them.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::protocol::EnvelopeKind;

/// A refusal's answer to the only question the retry loop actually has:
/// **should this node ask for THESE EXACT BYTES again?**
///
/// Orthogonal to *why* the row was refused — persist's
/// [`kind()`](ciris_persist::federation::Error::kind), the Key plane's
/// [`KeyRefusalReason`](ciris_persist::federation::register::KeyRefusalReason)
/// token, and edge's [`ApplyRefusalClass`](super::bridge::ApplyRefusalClass)
/// all answer *which gate*. This answers *what the transport does next*, and
/// the two axes do not collapse: `federation_write_scope_refused` is one
/// `kind()` with both dispositions in it depending on whether the roster has
/// landed yet, which is exactly why #522 introduced a second axis rather than
/// re-reading the first.
///
/// # Getting it wrong, in both directions
///
/// A **permanent** refusal labelled `Transient` asserts a convergence that never
/// arrives: it keeps the row in `want` forever and spins the #531 advertise
/// re-sweep against bytes that can never land. That is the #544 bug.
///
/// A **recoverable** refusal labelled `Terminal` silently drops work that would
/// have converged. That one is worse — the first burns transport visibly, the
/// second withholds state invisibly — so where a persist token collapses a
/// recoverable arm and an unrecoverable one into the SAME value (`re_scrub`,
/// `unverifiable_signature`), the call is `Transient`, and the backoff is what
/// makes that safe to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryDisposition {
    /// The verdict was decided by state that is still MOVING — a roster that
    /// has not landed, a signer key that has not replicated, a lost write race.
    /// Re-asking is the convergence mechanism; it only needs a rate.
    Transient,
    /// The verdict is a function of state replication cannot move. Re-asking
    /// yields the identical answer, so the only outcomes are "succeeds
    /// eventually" (impossible) and "burns transport forever".
    Terminal,
}

impl RetryDisposition {
    /// The stable, low-cardinality token for logs and any future ledger key.
    /// Consumers key on THIS, never on message prose (the #433/#565 rule this
    /// crate already enforces on the two refusal-reason axes).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Terminal => "terminal",
        }
    }

    /// `true` iff re-offering the identical bytes cannot change the verdict.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }

    /// The suppression window to install after `attempts` consecutive refusals
    /// of the same bytes: the disposition's base, doubled per attempt, clamped
    /// to its cap. `attempts` is 1-based (the window after the FIRST refusal is
    /// the base).
    ///
    /// Doubling rather than a flat window because the two failure shapes want
    /// opposite things from the first few minutes: a roster-ordering refusal
    /// usually clears in the first round or two and should not pay a long
    /// penalty for it, while a row that has been refused eleven times has
    /// earned the cap.
    #[must_use]
    pub fn window(self, attempts: u32) -> Duration {
        let (base, cap) = match self {
            Self::Transient => (TRANSIENT_BASE, TRANSIENT_CAP),
            Self::Terminal => (TERMINAL_BASE, TERMINAL_CAP),
        };
        // Shift capped well below 64 so the `<<` cannot overflow; the `min(cap)`
        // below makes anything past a handful of doublings equivalent anyway.
        let shift = attempts.saturating_sub(1).min(16);
        let secs = base.as_secs().saturating_mul(1u64 << shift);
        Duration::from_secs(secs).min(cap)
    }
}

/// First transient window. CIRISEdge#636 (production speed): 20 s — under
/// the 30 s cadence, and with propagation kicks a round-trip away. The common
/// transient is an ORDERING refusal (an attestation before its attesting key,
/// an occurrence before its owner-binding) whose missing row arrives on the
/// next round; the first re-ask should land right after it, not two cadences
/// later. The doubling below (20 → 40 → 80 → 160 → cap) still bounds a row
/// that keeps failing to a handful of asks an hour. (Was 60 s; the server's
/// timeline read a first re-ask at +601 s — most of that was rounds not
/// completing, but the base was the floor.)
pub const TRANSIENT_BASE: Duration = Duration::from_secs(20);
/// Transient ceiling. Deliberately SHORT: the transient classes converge on
/// state that is actively replicating, and worst-case added convergence latency
/// is this value. 5 minutes turns the flat-out 120 asks/hour into at most 12
/// while keeping a stalled cohort roster's recovery inside a coffee break.
pub const TRANSIENT_CAP: Duration = Duration::from_secs(300);
/// First terminal window. On the #544 measurement this alone is the fix: 55
/// re-offers in 30 minutes becomes 1.
pub const TERMINAL_BASE: Duration = Duration::from_secs(1800);
/// Terminal ceiling — the "never permanently dark" bound. A row whose verdict
/// genuinely moves (the conflicting local row is pruned) is re-asked within 6
/// hours with no operator action and no knowledge that this memory exists.
pub const TERMINAL_CAP: Duration = Duration::from_secs(21_600);
/// Front-drop cap on the memory's ORDINARY rows (the #544 windows). Sized
/// like [`crate::log_throttle`]'s key cap and leviculum's live-link ring:
/// large enough that a real mesh's genuinely stuck rows all fit, small enough
/// that a peer cycling junk hashes cannot grow it without bound. Eviction
/// costs exactly one re-ask.
pub const DEFAULT_MAX_KEYS: usize = 4096;
/// CIRISEdge#858 — front-drop cap on rows PARKED on a signer (an absent `Key`,
/// or an occurrence signer whose standing has not landed), held apart from
/// [`DEFAULT_MAX_KEYS`]. Until #858 one 4096-entry ring held both, and the
/// Attestation plane's ordinary refusals (the canonical books them by the
/// thousand) front-dropped a fresh node's occurrence parks, so the parked
/// rows came straight back into `want` and were refused again every round.
/// A park is worth more than an ordinary window — it is the only thing
/// standing between a row that cannot verify yet and a WARN per round — so it
/// gets a ring of its own, sixteen times wider. Still bounded: the key is
/// peer-influenced (an attacker can sign junk with keys this node never met),
/// and an eviction here costs one re-ask and one throttled WARN.
pub const DEFAULT_MAX_PARKED: usize = 65_536;
/// CIRISEdge#858 (FSD `STRUCTURAL_REFUSALS.md` §2, S1 → S2) — how many
/// consecutive windows a transient refusal with NO named dependency may spend
/// at [`TRANSIENT_CAP`] before it moves to the terminal schedule. A transient
/// verdict that has not moved through 20 minutes of re-asks (20 + 40 + 80 +
/// 160 + 3 × 300 s) is not waiting on state that is replicating; at the
/// transient cap it would cost 12 asks and 12 WARNs an hour forever (the
/// legacy never-verifiable rows of #858). The terminal schedule still re-asks
/// (30 min doubling to 6 h), so a verdict that does move converges.
pub const TRANSIENT_CAP_HITS_BEFORE_TERMINAL: u32 = 3;

/// `(plane, content hash)` — the same identity the wire uses. `EnvelopeKind` is
/// part of the key because the hash spaces are per-plane and a refusal is a
/// verdict about a row on a plane, never about 32 bytes in the abstract.
type RowKey = (EnvelopeKind, [u8; 32]);

struct Entry {
    /// Consecutive refusals of these bytes. Drives the doubling; reset only by
    /// [`RefusalBackoff::clear`] (an admit), a release, or eviction.
    attempts: u32,
    /// The MOST RECENT verdict. A row can change disposition — a signer key
    /// lands and `unverifiable_signature` becomes `conflicting_version` — and
    /// the latest reading is the one that should govern the next window.
    disposition: RetryDisposition,
    /// When this node may ask for these bytes again.
    retry_at: Instant,
    /// CIRISEdge#679 — the signer whose `Key` row this row is PARKED on, if
    /// the refusal was structural (the signer is absent from the directory).
    /// Indexed in [`State::by_signer`] so the Key admit releases every row at
    /// once; `None` for an ordinary #544 window.
    waiting_on: Option<String>,
    /// CIRISEdge#776 — the peer that offered the refused bytes, when the row
    /// waits on a dependency another plane delivers: the release asks THAT
    /// peer again at once (a kick), not at the next cadence tick.
    waiting_from: Option<String>,
    /// CIRISEdge#858 — consecutive transient windows booked AT
    /// [`TRANSIENT_CAP`] while the row named no dependency. Past
    /// [`TRANSIENT_CAP_HITS_BEFORE_TERMINAL`] the row moves to the terminal
    /// schedule.
    cap_hits: u32,
    /// CIRISEdge#858 — `Some(stamp)` iff the row is in the PARKED class (its
    /// live stamp in [`State::parked_order`]); `None` for an ordinary row
    /// (which sits in [`State::order`]). Set together with `waiting_on`.
    park_stamp: Option<u64>,
}

struct State {
    entries: HashMap<RowKey, Entry>,
    /// Eviction order of the ORDINARY rows; front is oldest. Exact (every key
    /// here is an ordinary entry), capped at `max_keys`.
    order: VecDeque<RowKey>,
    /// CIRISEdge#858 — eviction order of the PARKED rows, front oldest, as
    /// `(stamp, key)`. LAZY: a release or clear leaves its stamp behind and
    /// eviction skips any stamp that no longer matches its entry, so releasing
    /// a signer's rows never scans a 65,536-entry ring per row. Compacted when
    /// the dead stamps outnumber the live ones.
    parked_order: VecDeque<(u64, RowKey)>,
    /// Live parked entries (the ones `parked_order` would keep).
    parked: usize,
    next_stamp: u64,
    /// CIRISEdge#858 — parks evicted by the park capacity since construction.
    park_evictions: u64,
    /// CIRISEdge#679 — signer → the rows parked on its `Key`. Kept in
    /// lockstep with `entries` (insert on park, remove on clear/evict), so a
    /// release never touches a row that was already forgotten.
    by_signer: HashMap<String, Vec<RowKey>>,
}

impl State {
    /// Forget `key` entirely, whichever class it is in, keeping the order and
    /// the signer index in lockstep. A parked row's stamp is left for the lazy
    /// ring to skip.
    fn remove(&mut self, key: &RowKey) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        if entry.park_stamp.is_some() {
            self.parked = self.parked.saturating_sub(1);
        } else {
            self.order.retain(|k| k != key);
        }
        if let Some(signer) = &entry.waiting_on {
            RefusalBackoff::unindex(&mut self.by_signer, signer, key);
        }
        Some(entry)
    }

    /// Front-drop one ORDINARY entry when the ordinary class is at capacity
    /// (matching `LogThrottle`), so a peer cycling hashes cannot grow the
    /// memory unbounded. Never touches a parked row (#858).
    fn evict_ordinary_if_full(&mut self, max_keys: usize) {
        if self.order.len() >= max_keys {
            if let Some(evict) = self.order.pop_front() {
                if let Some(e) = self.entries.remove(&evict) {
                    if let Some(signer) = e.waiting_on {
                        RefusalBackoff::unindex(&mut self.by_signer, &signer, &evict);
                    }
                }
            }
        }
    }

    /// CIRISEdge#858 — front-drop the oldest LIVE park when the parked class is
    /// at capacity. Returns `true` when a park was evicted.
    fn evict_parked_if_full(&mut self, max_parked: usize) -> bool {
        if self.parked < max_parked {
            return false;
        }
        while let Some((stamp, key)) = self.parked_order.pop_front() {
            let live = self
                .entries
                .get(&key)
                .is_some_and(|e| e.park_stamp == Some(stamp));
            if live {
                self.remove(&key);
                self.park_evictions = self.park_evictions.saturating_add(1);
                return true;
            }
        }
        false
    }

    /// CIRISEdge#858 — move an existing entry into the PARKED class (no-op if
    /// it is already there): out of the ordinary ring, into the parked one,
    /// evicting the oldest park first if that ring is full. Returns `true`
    /// when a park was evicted to make room.
    fn move_to_parked(&mut self, key: &RowKey, max_parked: usize) -> bool {
        match self.entries.get(key) {
            Some(e) if e.park_stamp.is_none() => {}
            _ => return false,
        }
        self.order.retain(|k| k != key);
        let evicted = self.evict_parked_if_full(max_parked);
        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.wrapping_add(1);
        if let Some(e) = self.entries.get_mut(key) {
            e.park_stamp = Some(stamp);
        }
        self.parked += 1;
        self.parked_order.push_back((stamp, *key));
        // Amortised compaction: dead stamps (released / cleared parks) are
        // dropped once they outnumber the live ones.
        if self.parked_order.len() > self.parked.saturating_mul(2).saturating_add(64) {
            let entries = &self.entries;
            self.parked_order.retain(|(stamp, key)| {
                entries
                    .get(key)
                    .is_some_and(|e| e.park_stamp == Some(*stamp))
            });
        }
        evicted
    }

    /// Point `key`'s signer index at `signer` (moving it off any previous
    /// signer). The entry must exist.
    fn index_on(&mut self, key: &RowKey, signer: &str) {
        let previous = self
            .entries
            .get_mut(key)
            .and_then(|e| e.waiting_on.replace(signer.to_owned()));
        if let Some(old) = previous {
            if old != signer {
                RefusalBackoff::unindex(&mut self.by_signer, &old, key);
            }
        }
        let rows = self.by_signer.entry(signer.to_owned()).or_default();
        if !rows.contains(key) {
            rows.push(*key);
        }
    }

    /// Book one refusal of a NEW key as an ordinary entry, or bump an existing
    /// one's attempt count. Returns the attempt count after the booking.
    fn bump_or_insert(&mut self, key: RowKey, max_keys: usize, now: Instant) -> u32 {
        if let Some(e) = self.entries.get_mut(&key) {
            e.attempts = e.attempts.saturating_add(1);
            return e.attempts;
        }
        self.insert_ordinary(key, RetryDisposition::Terminal, now, max_keys);
        1
    }

    fn insert_ordinary(
        &mut self,
        key: RowKey,
        disposition: RetryDisposition,
        retry_at: Instant,
        max_keys: usize,
    ) {
        self.evict_ordinary_if_full(max_keys);
        self.entries.insert(
            key,
            Entry {
                attempts: 1,
                disposition,
                retry_at,
                waiting_on: None,
                waiting_from: None,
                cap_hits: 0,
                park_stamp: None,
            },
        );
        self.order.push_back(key);
    }
}

/// The node-wide refusal memory.
///
/// **Node-wide, not per-peer, on purpose.** A refusal is a verdict about THIS
/// NODE'S state versus a row; which peer happened to carry the bytes is not part
/// of it. A per-session memory would learn the same verdict once per peer and
/// re-burn the round for every peer that offers the row — precisely the
/// amplification #544 is about. One instance lives on the shared
/// [`FederationDirectoryReplicationBridge`](super::bridge::FederationDirectoryReplicationBridge),
/// which every per-peer provider and the one shared applier already sit on top
/// of, so the first refusal teaches every peer's next round.
///
/// In-memory and process-lifetime by design: a restart is the one event that
/// can change a verdict this module calls terminal without any row moving (a
/// new build parses bytes the old one could not; an operator wires the
/// operational providers that were absent), so forgetting on restart is correct
/// rather than a limitation.
///
/// CIRISEdge#858 — two classes, two rings: ORDINARY rows (the #544 windows,
/// [`DEFAULT_MAX_KEYS`]) and rows PARKED on a signer ([`DEFAULT_MAX_PARKED`]).
/// An ordinary refusal can never evict a park.
pub struct RefusalBackoff {
    state: Mutex<State>,
    max_keys: usize,
    max_parked: usize,
}

impl Default for RefusalBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalBackoff {
    /// A memory capped at [`DEFAULT_MAX_KEYS`] ordinary rows and
    /// [`DEFAULT_MAX_PARKED`] parked ones.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacities(DEFAULT_MAX_KEYS, DEFAULT_MAX_PARKED)
    }

    /// A memory capped at `max_keys` front-drop ORDINARY entries (tests; a
    /// host with an unusually wide stuck set). Parks keep
    /// [`DEFAULT_MAX_PARKED`].
    #[must_use]
    pub fn with_capacity(max_keys: usize) -> Self {
        Self::with_capacities(max_keys, DEFAULT_MAX_PARKED)
    }

    /// CIRISEdge#858 — a memory capped at `max_keys` ordinary entries and
    /// `max_parked` parked ones.
    #[must_use]
    pub fn with_capacities(max_keys: usize, max_parked: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                order: VecDeque::new(),
                parked_order: VecDeque::new(),
                parked: 0,
                next_stamp: 0,
                park_evictions: 0,
                by_signer: HashMap::new(),
            }),
            max_keys: max_keys.max(1),
            max_parked: max_parked.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Book one refusal of `(kind, envelope_hash)` and install the resulting
    /// suppression window. Returns the window, so the caller can say how long
    /// it will be quiet in the same line that says what was refused.
    ///
    /// `now` is passed in rather than read here so the whole schedule is
    /// testable without sleeping.
    ///
    /// CIRISEdge#858 (FSD §2 S1 → S2) — a TRANSIENT refusal of a row that names
    /// no dependency (not parked, not indexed on a signer) that has already
    /// spent [`TRANSIENT_CAP_HITS_BEFORE_TERMINAL`] windows at
    /// [`TRANSIENT_CAP`] moves to the terminal schedule: its verdict is not
    /// waiting on anything this node can see replicating.
    pub fn record_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        disposition: RetryDisposition,
        now: Instant,
    ) -> Duration {
        let key = (kind, envelope_hash);
        let mut st = self.lock();

        if let Some(e) = st.entries.get_mut(&key) {
            e.attempts = e.attempts.saturating_add(1);
            if disposition == RetryDisposition::Transient && e.park_stamp.is_none() {
                if RetryDisposition::Transient.window(e.attempts) >= TRANSIENT_CAP {
                    e.cap_hits = e.cap_hits.saturating_add(1);
                }
                if e.cap_hits > TRANSIENT_CAP_HITS_BEFORE_TERMINAL {
                    let window = RetryDisposition::Terminal
                        .window(e.cap_hits - TRANSIENT_CAP_HITS_BEFORE_TERMINAL);
                    e.disposition = RetryDisposition::Terminal;
                    e.retry_at = now + window;
                    return window;
                }
            }
            e.disposition = disposition;
            let window = disposition.window(e.attempts);
            e.retry_at = now + window;
            return window;
        }

        // New key — evict the oldest ORDINARY row first if at capacity
        // (front-drop, matching `LogThrottle`), so a peer cycling hashes cannot
        // grow this unbounded.
        let window = disposition.window(1);
        st.insert_ordinary(key, disposition, now + window, self.max_keys);
        window
    }

    /// CIRISEdge#679 — book a STRUCTURAL refusal: `(kind, envelope_hash)` was
    /// refused because `signer`'s `Key` row is absent from this directory, and
    /// re-asking cannot change that until the key lands. The row is parked on
    /// the signer under the TERMINAL schedule (`TERMINAL_BASE` doubling to
    /// `TERMINAL_CAP` — never silence) and indexed, so
    /// [`Self::release_signer`] frees every row parked on that key the instant
    /// the key admits. Until then the ask is quiet; a peer that pushes the
    /// bytes anyway is still applied on its merits (the #544 rule: this gates
    /// the ASK, never the ADMIT).
    ///
    /// Why terminal-shaped rather than the 20 s transient window: the missing
    /// row is not "still replicating" in any sense this node can act on — the
    /// Key plane is `SelfOwn`, so a third party's key never arrives from the
    /// peer that offered the row, and the one recovery this node has (a
    /// `Pull` for the signer's own key, #552 B) either answers or it does not.
    /// What DOES move the verdict is the key landing, and that is what the
    /// index is for. A row parked here costs at most ~4 asks a day instead of
    /// 12 an hour.
    ///
    /// This BOOKS the refusal (one attempt) and parks it. A refusal already
    /// booked by [`Self::record_at`] is parked with [`Self::park_booked_at`],
    /// which does not count it twice (#858).
    pub fn record_waiting_on_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        signer: &str,
        now: Instant,
    ) -> Duration {
        let key = (kind, envelope_hash);
        let mut st = self.lock();
        st.bump_or_insert(key, self.max_keys, now);
        self.park_locked(&mut st, &key, signer, None, now)
    }

    /// CIRISEdge#858 — park a refusal [`Self::record_at`] ALREADY booked on
    /// `signer`'s absent `Key`, without counting it a second time.
    ///
    /// The apply choke books every refusal (`record_at`, one attempt) and then
    /// decides the park. Parking through [`Self::record_waiting_on_at`] there
    /// counted the one refusal twice, so the FIRST park installed the terminal
    /// window for attempt 2 — 3600 s, not the 1800 s the FSD states — and every
    /// later window was doubled once more than earned. `from_peer` is the peer
    /// that offered the bytes, so the release kicks a re-ask of it at once.
    /// A row evicted between the two calls is booked afresh (one attempt).
    pub fn park_booked_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        signer: &str,
        from_peer: Option<&str>,
        now: Instant,
    ) -> Duration {
        let key = (kind, envelope_hash);
        let mut st = self.lock();
        if !st.entries.contains_key(&key) {
            st.insert_ordinary(key, RetryDisposition::Terminal, now, self.max_keys);
        }
        self.park_locked(&mut st, &key, signer, from_peer, now)
    }

    /// The shared park: terminal window for the entry's CURRENT attempt count,
    /// indexed on `signer`, moved into the parked class.
    fn park_locked(
        &self,
        st: &mut State,
        key: &RowKey,
        signer: &str,
        from_peer: Option<&str>,
        now: Instant,
    ) -> Duration {
        st.move_to_parked(key, self.max_parked);
        let Some(e) = st.entries.get_mut(key) else {
            // Unreachable: the entry was inserted or found above, and the park
            // eviction never evicts the row being parked (it is not in the
            // parked ring yet). Fail open — nothing is suppressed.
            return Duration::ZERO;
        };
        let window = RetryDisposition::Terminal.window(e.attempts);
        e.disposition = RetryDisposition::Terminal;
        e.retry_at = now + window;
        if let Some(peer) = from_peer {
            e.waiting_from = Some(peer.to_owned());
        }
        st.index_on(key, signer);
        window
    }

    /// CIRISEdge#776 — index an ALREADY-booked refusal on the `signer` whose
    /// standing it waits for, WITHOUT changing its schedule (a transient row
    /// keeps its transient window). [`Self::release_signer`] then frees it the
    /// moment the dependency lands instead of when the window elapses. Returns
    /// `false` when no refusal is booked for the row (nothing to index).
    pub fn index_waiting_on(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        signer: &str,
        from_peer: Option<&str>,
    ) -> bool {
        let key = (kind, envelope_hash);
        let mut st = self.lock();
        let Some(entry) = st.entries.get_mut(&key) else {
            return false;
        };
        entry.waiting_from = from_peer.map(str::to_owned);
        st.move_to_parked(&key, self.max_parked);
        st.index_on(&key, signer);
        true
    }

    /// CIRISEdge#858 — index an already-booked refusal on a signer this node
    /// HOLDS but whose standing for the row's identity has not landed ("signer
    /// S is neither identity I nor an active occurrence of it, nor a node it
    /// owns"), and from the SECOND consecutive refusal put it on the terminal
    /// schedule (attempt 2 earns `TERMINAL_BASE`, then doubling).
    ///
    /// The first refusal keeps its transient window: the common case is the
    /// standup race #776 named (the binding is a round behind), and it clears
    /// in seconds. A row refused again after that window is not racing
    /// anything: on the transient ladder it cost ~12 asks and 12 WARNs an hour
    /// forever. The index stays, so the binding or occurrence that WOULD make
    /// the signer act for the identity still releases it at once. Returns the
    /// window now installed, or `None` when no refusal is booked for the row.
    pub fn index_held_signer_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        signer: &str,
        from_peer: Option<&str>,
        now: Instant,
    ) -> Option<Duration> {
        let key = (kind, envelope_hash);
        let mut st = self.lock();
        let entry = st.entries.get_mut(&key)?;
        entry.waiting_from = from_peer.map(str::to_owned);
        let window = if entry.attempts >= 2 {
            let window = RetryDisposition::Terminal.window(entry.attempts - 1);
            entry.disposition = RetryDisposition::Terminal;
            entry.retry_at = now + window;
            window
        } else {
            entry.retry_at.saturating_duration_since(now)
        };
        st.move_to_parked(&key, self.max_parked);
        st.index_on(&key, signer);
        Some(window)
    }

    /// CIRISEdge#679 — `signer`'s `Key` row landed: forget every row parked on
    /// it, so the next round's `want` asks for them immediately. Returns how
    /// many rows were released (the witness that the park→release path fired).
    ///
    /// CIRISEdge#776 — also called when an owner binding or an identity
    /// occurrence that makes `signer` an occurrence of an identity is admitted:
    /// a row refused because its signer was not yet bound is released then.
    pub fn release_signer(&self, signer: &str) -> usize {
        self.release_signer_from(signer).0
    }

    /// CIRISEdge#776 — [`Self::release_signer`], also naming who to ask: the
    /// distinct `(plane, peer)` pairs the released rows were offered from
    /// (rows booked without a peer contribute to the count only). The caller
    /// kicks one round per pair — the release forgets the rows, so a kicked
    /// re-ask that is refused again is booked afresh on the ordinary window,
    /// never kicked twice by one release.
    pub fn release_signer_from(&self, signer: &str) -> (usize, Vec<(EnvelopeKind, String)>) {
        let mut st = self.lock();
        let Some(rows) = st.by_signer.remove(signer) else {
            return (0, Vec::new());
        };
        let mut released = 0;
        let mut ask: Vec<(EnvelopeKind, String)> = Vec::new();
        for key in rows {
            if let Some(entry) = st.remove(&key) {
                released += 1;
                if let Some(peer) = entry.waiting_from {
                    if !ask.iter().any(|(k, p)| *k == key.0 && *p == peer) {
                        ask.push((key.0, peer));
                    }
                }
            }
        }
        (released, ask)
    }

    /// CIRISEdge#679 — how many rows are currently parked on an absent signer's
    /// `Key`. The structural-refusal witness: a bound nobody can observe is the
    /// kind that silently stops holding.
    #[must_use]
    pub fn parked_on_signer_len(&self) -> usize {
        self.lock().parked
    }

    /// CIRISEdge#858 — how many rows are parked on `signer` right now (the
    /// `N` of the one-line-per-signer park log).
    #[must_use]
    pub fn parked_on(&self, signer: &str) -> usize {
        self.lock().by_signer.get(signer).map_or(0, Vec::len)
    }

    /// CIRISEdge#858 — parks the park capacity has evicted since construction.
    /// Each eviction costs one re-ask of a row that still cannot verify.
    #[must_use]
    pub fn park_evictions(&self) -> u64 {
        self.lock().park_evictions
    }

    /// CIRISEdge#858 — the ORDINARY-row cap ([`DEFAULT_MAX_KEYS`] by default).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_keys
    }

    /// CIRISEdge#858 — the PARKED-row cap ([`DEFAULT_MAX_PARKED`] by default).
    #[must_use]
    pub fn park_capacity(&self) -> usize {
        self.max_parked
    }

    fn unindex(by_signer: &mut HashMap<String, Vec<RowKey>>, signer: &str, key: &RowKey) {
        if let Some(rows) = by_signer.get_mut(signer) {
            rows.retain(|k| k != key);
            if rows.is_empty() {
                by_signer.remove(signer);
            }
        }
    }

    /// Should the round's `want` DROP `(kind, envelope_hash)` at `now`?
    ///
    /// Fail-open in every uncertain direction: an unknown row, an expired
    /// window, or an evicted entry all answer `false` (ask for it). The only
    /// `true` is "this node refused these exact bytes and the window it earned
    /// has not elapsed".
    #[must_use]
    pub fn suppressed_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
        now: Instant,
    ) -> bool {
        self.lock()
            .entries
            .get(&(kind, *envelope_hash))
            .is_some_and(|e| now < e.retry_at)
    }

    /// Forget `(kind, envelope_hash)` — the row landed (or was already held), so
    /// the refusal history that produced the backoff is obsolete. Called on
    /// every non-refusing apply outcome so a row that recovers does not carry a
    /// stale attempt count into a future refusal of the same bytes.
    pub fn clear(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) {
        self.lock().remove(&(kind, *envelope_hash));
    }

    /// How many rows are currently remembered, both classes. The memory's own
    /// witness — a bound nobody can observe is the kind that silently stops
    /// holding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// `true` iff nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests_679 {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = seed;
        x
    }

    /// CIRISEdge#679 — a parked row is quiet on the TERMINAL schedule (every
    /// transient window would have elapsed long before) and is released the
    /// instant its signer's key lands; a row parked on another signer is
    /// untouched.
    #[test]
    fn rows_parked_on_a_signer_stay_quiet_until_that_signer_is_released() {
        let b = RefusalBackoff::new();
        let now = Instant::now();
        let w = b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "stranger-a", now);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(2), "stranger-a", now);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(3), "stranger-b", now);
        assert_eq!(w, TERMINAL_BASE, "the first park earns the terminal base");
        assert_eq!(b.parked_on_signer_len(), 3);
        let later = now + TRANSIENT_CAP + Duration::from_secs(1);
        assert!(
            b.suppressed_at(EnvelopeKind::Attestation, &h(1), later),
            "still quiet past every transient window"
        );
        assert_eq!(b.release_signer("stranger-a"), 2, "both rows on stranger-a");
        assert!(!b.suppressed_at(EnvelopeKind::Attestation, &h(1), now));
        assert!(!b.suppressed_at(EnvelopeKind::Attestation, &h(2), now));
        assert!(
            b.suppressed_at(EnvelopeKind::Attestation, &h(3), now),
            "stranger-b's row is untouched"
        );
        assert_eq!(b.parked_on_signer_len(), 1);
        assert_eq!(b.release_signer("stranger-a"), 0, "idempotent");
        assert_eq!(b.release_signer("nobody"), 0);
    }

    /// The index never outlives its entry: `clear` (the row landed) and
    /// front-drop eviction both drop the park, so a later release cannot
    /// resurrect a forgotten row or miscount. Since #858 the eviction that
    /// drops a park is the PARK ring's own, never an ordinary refusal.
    #[test]
    fn clear_and_eviction_keep_the_signer_index_in_lockstep() {
        let b = RefusalBackoff::with_capacities(2, 2);
        let now = Instant::now();
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s", now);
        b.clear(EnvelopeKind::Attestation, &h(1));
        assert_eq!(b.parked_on_signer_len(), 0);
        assert_eq!(b.release_signer("s"), 0);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s", now);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(2), "s", now);
        // A third PARK evicts h(1) (front-drop within the park ring).
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(3), "t", now);
        assert_eq!(b.len(), 2);
        assert_eq!(b.park_evictions(), 1);
        assert_eq!(
            b.parked_on_signer_len(),
            2,
            "the evicted park left the index"
        );
        assert_eq!(b.release_signer("s"), 1, "only h(2) is still parked on s");
        assert_eq!(b.release_signer("t"), 1);
        assert!(b.is_empty());
    }

    /// CIRISEdge#858 (fix 5) — ordinary refusals never evict a park. Before
    /// #858 one 4096 ring held both, and the Attestation plane's ordinary
    /// refusals front-dropped a fresh node's occurrence parks.
    #[test]
    fn ordinary_refusals_never_evict_a_park_858() {
        let b = RefusalBackoff::with_capacity(8);
        let now = Instant::now();
        b.record_waiting_on_at(EnvelopeKind::IdentityOccurrence, h(1), "absent", now);
        for i in 10..30u8 {
            b.record_at(
                EnvelopeKind::Attestation,
                h(i),
                RetryDisposition::Transient,
                now,
            );
        }
        assert_eq!(b.parked_on_signer_len(), 1, "the park survived the churn");
        assert!(b.suppressed_at(EnvelopeKind::IdentityOccurrence, &h(1), now));
        assert_eq!(b.len(), 9, "8 ordinary + 1 parked");
        assert_eq!(b.park_evictions(), 0);
    }

    /// CIRISEdge#858 (fix 3) — a refusal the choke already booked parks on
    /// its FIRST attempt's terminal window (1800 s), not attempt 2's.
    #[test]
    fn a_booked_refusal_parks_on_the_first_terminal_window_858() {
        let b = RefusalBackoff::new();
        let now = Instant::now();
        b.record_at(
            EnvelopeKind::IdentityOccurrence,
            h(1),
            RetryDisposition::Transient,
            now,
        );
        let w = b.park_booked_at(EnvelopeKind::IdentityOccurrence, h(1), "p", Some("r"), now);
        assert_eq!(w, TERMINAL_BASE);
        // The second refusal of the same bytes doubles once.
        b.record_at(
            EnvelopeKind::IdentityOccurrence,
            h(1),
            RetryDisposition::Transient,
            now,
        );
        let w2 = b.park_booked_at(EnvelopeKind::IdentityOccurrence, h(1), "p", Some("r"), now);
        assert_eq!(w2, TERMINAL_BASE * 2);
        let (n, ask) = b.release_signer_from("p");
        assert_eq!(n, 1);
        assert_eq!(
            ask,
            vec![(EnvelopeKind::IdentityOccurrence, "r".to_owned())],
            "a park remembers the peer that offered it, so its release kicks"
        );
    }

    /// CIRISEdge#858 (fix 4) — a row indexed on a HELD signer keeps its
    /// transient window on the first refusal and earns the terminal schedule
    /// from the second.
    #[test]
    fn a_held_signer_index_goes_terminal_from_attempt_two_858() {
        let b = RefusalBackoff::new();
        let now = Instant::now();
        let k = EnvelopeKind::IdentityOccurrence;
        b.record_at(k, h(1), RetryDisposition::Transient, now);
        assert_eq!(
            b.index_held_signer_at(k, h(1), "s", None, now),
            Some(TRANSIENT_BASE)
        );
        b.record_at(k, h(1), RetryDisposition::Transient, now);
        assert_eq!(
            b.index_held_signer_at(k, h(1), "s", None, now),
            Some(TERMINAL_BASE)
        );
        assert!(b.suppressed_at(k, &h(1), now + TRANSIENT_CAP + Duration::from_secs(1)));
        assert_eq!(b.parked_on("s"), 1);
        assert_eq!(b.index_held_signer_at(k, h(9), "s", None, now), None);
    }

    /// CIRISEdge#858 (fix 6, FSD §2 S1 → S2) — a transient refusal with no
    /// named dependency spends three windows at the transient cap, then moves
    /// to the terminal schedule (and keeps doubling there).
    #[test]
    fn a_transient_refusal_stuck_at_the_cap_moves_to_the_terminal_schedule_858() {
        let b = RefusalBackoff::new();
        let now = Instant::now();
        let windows: Vec<Duration> = (0..10)
            .map(|_| b.record_at(EnvelopeKind::Key, h(1), RetryDisposition::Transient, now))
            .collect();
        let s = Duration::from_secs;
        assert_eq!(
            windows,
            vec![
                s(20),
                s(40),
                s(80),
                s(160),
                TRANSIENT_CAP,
                TRANSIENT_CAP,
                TRANSIENT_CAP,
                TERMINAL_BASE,
                TERMINAL_BASE * 2,
                TERMINAL_BASE * 4,
            ]
        );
        // A PARKED row is governed by its park, never escalated here.
        let p = RefusalBackoff::new();
        p.record_waiting_on_at(EnvelopeKind::Key, h(2), "s", now);
        for _ in 0..10 {
            p.record_at(EnvelopeKind::Key, h(2), RetryDisposition::Transient, now);
        }
        assert_eq!(
            p.record_at(EnvelopeKind::Key, h(2), RetryDisposition::Transient, now),
            TRANSIENT_CAP,
            "record_at alone leaves a parked row on its booked disposition; the \
             choke re-parks it"
        );
    }

    /// The lazy park ring stays bounded under park/release churn.
    #[test]
    fn the_lazy_park_ring_is_compacted_under_churn_858() {
        let b = RefusalBackoff::with_capacities(4, 4);
        let now = Instant::now();
        for round in 0..200u32 {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&round.to_be_bytes());
            b.record_waiting_on_at(EnvelopeKind::Attestation, hash, "s", now);
            b.release_signer("s");
        }
        assert!(b.is_empty());
        assert!(
            b.lock().parked_order.len() <= 2 + 64 + 1,
            "dead stamps are compacted"
        );
        assert_eq!(b.park_evictions(), 0, "a released park is never evicted");
    }

    /// Re-parking the same row on a different signer moves the index; the
    /// attempt count keeps doubling toward the cap, never resets on a re-park.
    #[test]
    fn a_re_park_moves_the_index_and_keeps_doubling() {
        let b = RefusalBackoff::new();
        let now = Instant::now();
        let w1 = b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s1", now);
        let w2 = b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s2", now);
        assert_eq!(w2, w1 * 2);
        assert_eq!(b.release_signer("s1"), 0, "no longer parked on s1");
        assert_eq!(b.release_signer("s2"), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    /// The #544 measurement, in miniature: the FIRST terminal refusal already
    /// takes the row out of `want` for half an hour, so the 55-per-30-minutes
    /// re-offer becomes one.
    #[test]
    fn a_terminal_refusal_suppresses_the_row_for_the_whole_first_window() {
        let b = RefusalBackoff::new();
        let t0 = Instant::now();
        let window = b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Terminal, t0);
        assert_eq!(window, TERMINAL_BASE);
        // Every 30 s round inside the window is a round that does not ask.
        for round in 1..=55 {
            let t = t0 + Duration::from_secs(30 * round);
            if t < t0 + TERMINAL_BASE {
                assert!(
                    b.suppressed_at(EnvelopeKind::Key, &hash(1), t),
                    "round {round} must not re-ask for a terminally refused row"
                );
            }
        }
    }

    /// Never permanently dark: the window expires and the node asks again.
    #[test]
    fn a_terminal_suppression_expires_so_a_verdict_that_moves_still_converges() {
        let b = RefusalBackoff::new();
        let t0 = Instant::now();
        b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Terminal, t0);
        assert!(!b.suppressed_at(EnvelopeKind::Key, &hash(1), t0 + TERMINAL_BASE));
    }

    /// The suppression is per-(plane, content hash): the SUPERSEDING record the
    /// issue says a stuck sender needs is different bytes, so a different hash,
    /// so it is never held back by its predecessor's verdict.
    #[test]
    fn a_different_content_hash_is_never_suppressed_by_its_predecessors_refusal() {
        let b = RefusalBackoff::new();
        let t0 = Instant::now();
        b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Terminal, t0);
        assert!(!b.suppressed_at(EnvelopeKind::Key, &hash(2), t0));
        // …and the same hash on a DIFFERENT plane is a different row.
        assert!(!b.suppressed_at(EnvelopeKind::Attestation, &hash(1), t0));
    }

    #[test]
    fn the_window_doubles_per_consecutive_refusal_and_stops_at_the_cap() {
        let b = RefusalBackoff::new();
        let mut t = Instant::now();
        let mut windows = Vec::new();
        // Seven refusals: the ladder up to its third window at the cap. The
        // eighth leaves the transient schedule (CIRISEdge#858, pinned by
        // `a_transient_refusal_stuck_at_the_cap_moves_to_the_terminal_schedule_858`).
        for _ in 0..7 {
            let w = b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Transient, t);
            windows.push(w);
            t += w;
        }
        assert_eq!(
            &windows[..3],
            &[TRANSIENT_BASE, TRANSIENT_BASE * 2, TRANSIENT_BASE * 4][..],
            "consecutive refusals double the window: {windows:?}"
        );
        assert!(
            windows.iter().all(|w| *w <= TRANSIENT_CAP),
            "no window may exceed the cap: {windows:?}"
        );
        assert_eq!(
            *windows.last().expect("7 windows"),
            TRANSIENT_CAP,
            "the schedule settles AT the cap, it does not keep growing"
        );
    }

    /// A transient refusal costs at most one skipped round before its first
    /// re-ask, and never more than the (short) transient cap — the property
    /// that makes it safe to classify an ambiguous persist token transient.
    #[test]
    fn the_transient_schedule_stays_inside_the_short_cap() {
        assert_eq!(RetryDisposition::Transient.window(1), TRANSIENT_BASE);
        assert_eq!(RetryDisposition::Transient.window(99), TRANSIENT_CAP);
        assert!(
            TRANSIENT_CAP < TERMINAL_BASE,
            "a transient row is re-asked long before a terminal one"
        );
    }

    #[test]
    fn an_admitted_row_forgets_its_refusal_history() {
        let b = RefusalBackoff::new();
        let t0 = Instant::now();
        b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Transient, t0);
        b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Transient, t0);
        b.clear(EnvelopeKind::Key, &hash(1));
        assert!(b.is_empty(), "clear drops the entry, not just the deadline");
        assert!(!b.suppressed_at(EnvelopeKind::Key, &hash(1), t0));
        // …and the attempt count went with it: the next refusal starts at base.
        assert_eq!(
            b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Transient, t0),
            TRANSIENT_BASE
        );
    }

    /// The key contains a peer-chosen content hash, so the map must not be a
    /// memory-exhaustion vector of its own.
    #[test]
    fn the_memory_is_capacity_bounded_and_front_drops_the_oldest_row() {
        let b = RefusalBackoff::with_capacity(4);
        let t0 = Instant::now();
        for i in 0..64u8 {
            b.record_at(EnvelopeKind::Key, hash(i), RetryDisposition::Terminal, t0);
        }
        assert_eq!(b.len(), 4, "the cap holds under hash churn");
        // The oldest was evicted — which costs exactly one re-ask, never a
        // wrong answer.
        assert!(!b.suppressed_at(EnvelopeKind::Key, &hash(0), t0));
        assert!(b.suppressed_at(EnvelopeKind::Key, &hash(63), t0));
    }

    /// A row whose verdict changes class carries its attempt count but adopts
    /// the NEW disposition's schedule.
    #[test]
    fn a_re_classified_row_adopts_the_latest_verdicts_schedule() {
        let b = RefusalBackoff::new();
        let t0 = Instant::now();
        b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Transient, t0);
        let w = b.record_at(EnvelopeKind::Key, hash(1), RetryDisposition::Terminal, t0);
        assert_eq!(w, RetryDisposition::Terminal.window(2));
    }
}
