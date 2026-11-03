//! C7 — the deterministic decision log.
//!
//! Every controller decision (subscribe, switch, failover, admit, refuse,
//! shed, a peer-state change, a learned ceiling, a detected loop) is one
//! record `(at_ms, node, kind, subject, value, reason)`. Records are folded
//! into a running SHA-256 over a canonical, length-prefixed encoding, so the
//! same seed gives the same hash, and a field log replays in the sim. A
//! bounded tail of rendered records is kept for failure messages, and a
//! per-kind counter for telemetry.

use std::collections::{BTreeMap, VecDeque};

use sha2::{Digest, Sha256};

use super::PeerRef;

/// What was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecisionKind {
    /// Selector asked a forwarder for a role.
    Subscribe,
    /// Selector left a forwarder.
    Unsubscribe,
    /// Make-before-break started (new primary admitted, old one still on).
    PromoteStart,
    /// Make-before-break finished: new primary confirmed, old one demoted.
    Switch,
    /// Failure-driven switch.
    Failover,
    /// Admission admitted.
    Admit,
    /// Admission refused.
    Refuse,
    /// Admission shed a subscriber.
    Shed,
    /// A peer-state transition.
    PeerState,
    /// A loop slipped through and was caught by the ancestry backstop.
    LoopDetected,
    /// Admission learned (or moved) its measured ceiling.
    Ceiling,
    /// Advertised capacity exceeds measured by more than the over-claim ratio.
    OverClaim,
}

impl DecisionKind {
    const fn tag(self) -> u8 {
        self as u8
    }
}

/// The log.
#[derive(Debug, Clone)]
pub struct DecisionLog {
    hasher: Sha256,
    count: u64,
    tail: VecDeque<String>,
    tail_cap: usize,
    counters: BTreeMap<DecisionKind, u64>,
    buf: Vec<u8>,
}

impl Default for DecisionLog {
    fn default() -> Self {
        Self::new(64)
    }
}

impl DecisionLog {
    /// A log keeping the last `tail_cap` rendered records.
    #[must_use]
    pub fn new(tail_cap: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            count: 0,
            tail: VecDeque::with_capacity(tail_cap),
            tail_cap,
            counters: BTreeMap::new(),
            buf: Vec::with_capacity(128),
        }
    }

    /// Record one decision.
    pub fn record<P: PeerRef>(
        &mut self,
        at_ms: u64,
        node: &P,
        kind: DecisionKind,
        subject: Option<&P>,
        value: i64,
        reason: &'static str,
    ) {
        self.buf.clear();
        self.buf.extend_from_slice(&at_ms.to_be_bytes());
        node.encode(&mut self.buf);
        self.buf.push(kind.tag());
        match subject {
            Some(s) => {
                self.buf.push(1);
                s.encode(&mut self.buf);
            }
            None => self.buf.push(0),
        }
        self.buf.extend_from_slice(&value.to_be_bytes());
        let r = reason.as_bytes();
        self.buf
            .extend_from_slice(&u32::try_from(r.len()).unwrap_or(0).to_be_bytes());
        self.buf.extend_from_slice(r);
        self.hasher.update(&self.buf);
        self.count += 1;
        *self.counters.entry(kind).or_insert(0) += 1;
        if self.tail_cap > 0 {
            if self.tail.len() == self.tail_cap {
                self.tail.pop_front();
            }
            self.tail.push_back(format!(
                "t={at_ms} node={node:?} {kind:?} subj={subject:?} v={value} ({reason})"
            ));
        }
    }

    /// The running hash over every record so far.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }

    /// The hash as lowercase hex.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(64);
        for b in self.hash() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Records so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// How many records of `kind`.
    #[must_use]
    pub fn count(&self, kind: DecisionKind) -> u64 {
        self.counters.get(&kind).copied().unwrap_or(0)
    }

    /// The rendered tail, oldest first (for failure messages).
    #[must_use]
    pub fn tail(&self) -> String {
        self.tail.iter().cloned().collect::<Vec<_>>().join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_records_same_hash_order_matters() {
        let mut a = DecisionLog::new(4);
        let mut b = DecisionLog::new(4);
        for log in [&mut a, &mut b] {
            log.record(1, &7u32, DecisionKind::Admit, Some(&9u32), 1, "x");
            log.record(2, &7u32, DecisionKind::Shed, None, 0, "y");
        }
        assert_eq!(a.hash(), b.hash());
        let mut c = DecisionLog::new(4);
        c.record(2, &7u32, DecisionKind::Shed, None, 0, "y");
        c.record(1, &7u32, DecisionKind::Admit, Some(&9u32), 1, "x");
        assert_ne!(a.hash(), c.hash());
        assert_eq!(a.count(DecisionKind::Admit), 1);
        assert_eq!(a.len(), 2);
    }
}
