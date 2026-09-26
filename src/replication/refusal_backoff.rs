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
//! ([`DEFAULT_MAX_KEYS`]). Evicting an entry only costs one re-ask.

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
/// Front-drop cap on the memory. Sized like [`crate::log_throttle`]'s key cap
/// and leviculum's live-link ring: large enough that a real mesh's genuinely
/// stuck rows all fit, small enough that a peer cycling junk hashes cannot
/// grow it without bound. Eviction costs exactly one re-ask.
pub const DEFAULT_MAX_KEYS: usize = 4096;

/// `(plane, content hash)` — the same identity the wire uses. `EnvelopeKind` is
/// part of the key because the hash spaces are per-plane and a refusal is a
/// verdict about a row on a plane, never about 32 bytes in the abstract.
type RowKey = (EnvelopeKind, [u8; 32]);

struct Entry {
    /// Consecutive refusals of these bytes. Drives the doubling; reset only by
    /// [`RefusalBackoff::clear`] (an admit) or eviction.
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
}

struct State {
    entries: HashMap<RowKey, Entry>,
    /// Eviction order; front is oldest. Capped at `max_keys`.
    order: VecDeque<RowKey>,
    /// CIRISEdge#679 — signer → the rows parked on its `Key`. Kept in
    /// lockstep with `entries` (insert on park, remove on clear/evict), so a
    /// release never touches a row that was already forgotten.
    by_signer: HashMap<String, Vec<RowKey>>,
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
pub struct RefusalBackoff {
    state: Mutex<State>,
    max_keys: usize,
}

impl Default for RefusalBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalBackoff {
    /// A memory capped at [`DEFAULT_MAX_KEYS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_KEYS)
    }

    /// A memory capped at `max_keys` front-drop entries (tests; a host with an
    /// unusually wide stuck set).
    #[must_use]
    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                order: VecDeque::new(),
                by_signer: HashMap::new(),
            }),
            max_keys: max_keys.max(1),
        }
    }

    /// Book one refusal of `(kind, envelope_hash)` and install the resulting
    /// suppression window. Returns the window, so the caller can say how long
    /// it will be quiet in the same line that says what was refused.
    ///
    /// `now` is passed in rather than read here so the whole schedule is
    /// testable without sleeping.
    pub fn record_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        disposition: RetryDisposition,
        now: Instant,
    ) -> Duration {
        let key = (kind, envelope_hash);
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(e) = st.entries.get_mut(&key) {
            e.attempts = e.attempts.saturating_add(1);
            e.disposition = disposition;
            let window = disposition.window(e.attempts);
            e.retry_at = now + window;
            return window;
        }

        // New key — evict oldest first if at capacity (front-drop, matching
        // `LogThrottle`), so a peer cycling hashes cannot grow this unbounded.
        Self::evict_if_full(&mut st, self.max_keys);
        let window = disposition.window(1);
        st.entries.insert(
            key,
            Entry {
                attempts: 1,
                disposition,
                retry_at: now + window,
                waiting_on: None,
            },
        );
        st.order.push_back(key);
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
    pub fn record_waiting_on_at(
        &self,
        kind: EnvelopeKind,
        envelope_hash: [u8; 32],
        signer: &str,
        now: Instant,
    ) -> Duration {
        let key = (kind, envelope_hash);
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let attempts = if let Some(e) = st.entries.get_mut(&key) {
            e.attempts = e.attempts.saturating_add(1);
            e.attempts
        } else {
            Self::evict_if_full(&mut st, self.max_keys);
            st.entries.insert(
                key,
                Entry {
                    attempts: 1,
                    disposition: RetryDisposition::Terminal,
                    retry_at: now,
                    waiting_on: None,
                },
            );
            st.order.push_back(key);
            1
        };
        let window = RetryDisposition::Terminal.window(attempts);
        let previous = {
            let e = st.entries.get_mut(&key).expect("inserted above");
            e.disposition = RetryDisposition::Terminal;
            e.retry_at = now + window;
            e.waiting_on.replace(signer.to_owned())
        };
        // Re-parked on a different signer: drop the old index entry.
        if let Some(old) = previous {
            if old != signer {
                Self::unindex(&mut st.by_signer, &old, &key);
            }
        }
        let rows = st.by_signer.entry(signer.to_owned()).or_default();
        if !rows.contains(&key) {
            rows.push(key);
        }
        window
    }

    /// CIRISEdge#679 — `signer`'s `Key` row landed: forget every row parked on
    /// it, so the next round's `want` asks for them immediately. Returns how
    /// many rows were released (the witness that the park→release path fired).
    pub fn release_signer(&self, signer: &str) -> usize {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(rows) = st.by_signer.remove(signer) else {
            return 0;
        };
        let mut released = 0;
        for key in rows {
            if st.entries.remove(&key).is_some() {
                st.order.retain(|k| *k != key);
                released += 1;
            }
        }
        released
    }

    /// CIRISEdge#679 — how many rows are currently parked on an absent signer's
    /// `Key`. The structural-refusal witness: a bound nobody can observe is the
    /// kind that silently stops holding.
    #[must_use]
    pub fn parked_on_signer_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_signer
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Front-drop one entry when at capacity (matching `LogThrottle`), so a
    /// peer cycling hashes cannot grow the memory unbounded. Keeps the signer
    /// index in lockstep.
    fn evict_if_full(st: &mut State, max_keys: usize) {
        if st.order.len() >= max_keys {
            if let Some(evict) = st.order.pop_front() {
                if let Some(e) = st.entries.remove(&evict) {
                    if let Some(signer) = e.waiting_on {
                        Self::unindex(&mut st.by_signer, &signer, &evict);
                    }
                }
            }
        }
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
        let st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.entries
            .get(&(kind, *envelope_hash))
            .is_some_and(|e| now < e.retry_at)
    }

    /// Forget `(kind, envelope_hash)` — the row landed (or was already held), so
    /// the refusal history that produced the backoff is obsolete. Called on
    /// every non-refusing apply outcome so a row that recovers does not carry a
    /// stale attempt count into a future refusal of the same bytes.
    pub fn clear(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) {
        let key = (kind, *envelope_hash);
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(e) = st.entries.remove(&key) {
            st.order.retain(|k| *k != key);
            if let Some(signer) = e.waiting_on {
                Self::unindex(&mut st.by_signer, &signer, &key);
            }
        }
    }

    /// How many rows are currently remembered. The memory's own witness — a
    /// bound nobody can observe is the kind that silently stops holding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
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
    /// resurrect a forgotten row or miscount.
    #[test]
    fn clear_and_eviction_keep_the_signer_index_in_lockstep() {
        let b = RefusalBackoff::with_capacity(2);
        let now = Instant::now();
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s", now);
        b.clear(EnvelopeKind::Attestation, &h(1));
        assert_eq!(b.parked_on_signer_len(), 0);
        assert_eq!(b.release_signer("s"), 0);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(1), "s", now);
        b.record_waiting_on_at(EnvelopeKind::Attestation, h(2), "s", now);
        // A third entry evicts h(1) (front-drop).
        b.record_at(EnvelopeKind::Key, h(9), RetryDisposition::Transient, now);
        assert_eq!(b.len(), 2);
        assert_eq!(
            b.parked_on_signer_len(),
            1,
            "the evicted park left the index"
        );
        assert_eq!(b.release_signer("s"), 1);
        assert_eq!(b.len(), 1, "only the unrelated Key entry remains");
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
        for _ in 0..8 {
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
            *windows.last().expect("8 windows"),
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
