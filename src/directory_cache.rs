//! §3.3 federation directory cache (CIRISEdge#175, v6.0.0).
//!
//! CEWP `SCOPE_PRIVACY.md` §3.3 — every participating L1 peer
//! maintains a complete local copy of the federation directory's
//! X-Wing + ML-DSA-65 public keys, refreshed via the substrate's
//! existing `federation_keys` anti-entropy stream. **No per-
//! invitation directory query is emitted.** Phone-class peers query
//! through their L1-relay parent over a relay-blinded path (the
//! existing Reticulum transport-node mode).
//!
//! The cache exposes the federation-public X-Wing keys (already
//! public per FSD §9.5) without exposing the per-invitation
//! `querier → invitee` edges that would otherwise be subpoenable
//! under §5's "subpoena federation directory" defense.
//!
//! # v6.0.0 surface
//!
//! - [`DirectoryCache`] — in-memory `HashMap<FederationKeyId,
//!   FederationDirectoryEntry>` with `RwLock`-backed concurrent
//!   reads. The anti-entropy subscription wiring (the producer side
//!   that fills the cache from the substrate's `federation_keys`
//!   stream) is deferred to v6.1.0 — v6.0.0 ships the cache with a
//!   public [`DirectoryCache::insert`] / [`DirectoryCache::remove`]
//!   API for the v6.1.0 wiring agent to drive against.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::mls::welcome_wrap::FederationDirectoryEntry;

/// §3.3 directory key identifier. Caller-scoped (a key_id,
/// fingerprint, or federation_id — edge does not interpret); the
/// only required property is that it round-trips byte-equal on the
/// substrate-wide `federation_keys` anti-entropy stream.
pub type FederationKeyId = String;

/// Reachability hint stored on the directory entry. Used by the
/// emission layer to choose a route (direct vs. relay-blinded
/// through an L1 parent) without re-querying the directory at send
/// time.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// Peer is directly reachable on at least one transport
    /// interface the local peer participates on.
    Direct,
    /// Peer is reachable only through an L1 relay parent (FSD §3.3
    /// phone-class-via-relay path).
    Relay,
    /// Unknown reachability — treat as relay for safety.
    #[default]
    Unknown,
}

/// §3.3 directory identity type. Caller-tagged (`steward`, `agent`,
/// `phone`, `infra`, etc.) — edge does not interpret. Drives the
/// emission layer's relay-blinding policy at the application tier.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IdentityType(pub String);

impl IdentityType {
    /// `phone` — phone-class peers query through their L1-relay
    /// parent over a relay-blinded path (§3.3).
    pub fn phone() -> Self {
        Self("phone".into())
    }
    /// `steward` — federation steward / governance tier.
    pub fn steward() -> Self {
        Self("steward".into())
    }
    /// `agent` — full-tier participating peer.
    pub fn agent() -> Self {
        Self("agent".into())
    }
}

/// In-memory federation directory entry. Mirrors the four-field
/// shape FSD §3.3 enumerates: X-Wing public key, ML-DSA-65 public
/// key, identity_type, reachability.
#[derive(Debug, Clone)]
pub struct DirectoryRecord {
    /// Federation identifier (the cache key).
    pub federation_id: FederationKeyId,
    /// ML-DSA-65 public key bytes (the
    /// `EncodedVerifyingKey<MlDsa65>` form).
    pub ml_dsa_pk: Vec<u8>,
    /// X-Wing public key (X25519 + ML-KEM-768 halves). Optional
    /// because some directory entries — e.g. read-only governance
    /// keys — may carry only ML-DSA-65.
    pub x_wing_pk: Option<XWingPublic>,
    /// Caller-tagged identity type.
    pub identity_type: IdentityType,
    /// Reachability hint.
    pub reachability: Reachability,
}

/// Plain-data X-Wing public key. Mirrors
/// [`ciris_crypto::hpke::XWingRecipientPublic`] but as
/// `Serialize`/`Deserialize` so directory entries can ride the
/// anti-entropy stream.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct XWingPublic {
    /// X25519 public key (32 bytes).
    pub x25519_pub: [u8; 32],
    /// ML-KEM-768 public key bytes.
    pub mlkem768_pub: Vec<u8>,
}

impl From<XWingPublic> for ciris_crypto::hpke::XWingRecipientPublic {
    fn from(p: XWingPublic) -> Self {
        Self {
            x25519_pub: p.x25519_pub,
            mlkem768_pub: p.mlkem768_pub,
        }
    }
}

impl From<&XWingPublic> for ciris_crypto::hpke::XWingRecipientPublic {
    fn from(p: &XWingPublic) -> Self {
        Self {
            x25519_pub: p.x25519_pub,
            mlkem768_pub: p.mlkem768_pub.clone(),
        }
    }
}

/// §3.3 federation directory cache.
///
/// Clone-cheap: holds an `Arc<RwLock<HashMap>>` so multiple Edge
/// surfaces (Welcome wrap, emission layer, scope echo) share one
/// view without per-handle copies.
#[derive(Clone, Default)]
pub struct DirectoryCache {
    inner: Arc<RwLock<HashMap<FederationKeyId, DirectoryRecord>>>,
}

impl DirectoryCache {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / update a directory record. Used by the anti-entropy
    /// driver (v6.1.0 — see module docs).
    pub fn insert(&self, record: DirectoryRecord) {
        let mut g = self.inner.write();
        g.insert(record.federation_id.clone(), record);
    }

    /// Remove a directory record by `federation_id`. Used when the
    /// anti-entropy stream observes a key revocation.
    pub fn remove(&self, federation_id: &str) -> Option<DirectoryRecord> {
        let mut g = self.inner.write();
        g.remove(federation_id)
    }

    /// Lookup a directory record by `federation_id`.
    #[must_use]
    pub fn get(&self, federation_id: &str) -> Option<DirectoryRecord> {
        let g = self.inner.read();
        g.get(federation_id).cloned()
    }

    /// Total number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// `true` iff the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// `true` iff `federation_id` is present in the cache.
    #[must_use]
    pub fn contains(&self, federation_id: &str) -> bool {
        self.inner.read().contains_key(federation_id)
    }

    /// Build a closure usable as the `directory_lookup` argument to
    /// [`crate::mls::welcome_wrap::unwrap_welcome`]. The closure
    /// resolves `pk_id → FederationDirectoryEntry` against THIS
    /// cache.
    pub fn welcome_wrap_lookup(&self) -> impl FnMut(&str) -> Option<FederationDirectoryEntry> + '_ {
        move |pk_id: &str| {
            let g = self.inner.read();
            g.get(pk_id).map(|r| FederationDirectoryEntry {
                pk_id: r.federation_id.clone(),
                ml_dsa_pk: r.ml_dsa_pk.clone(),
                x_wing_pk: r.x_wing_pk.as_ref().map(Into::into),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, pk_byte: u8) -> DirectoryRecord {
        DirectoryRecord {
            federation_id: id.into(),
            ml_dsa_pk: vec![pk_byte; 1952],
            x_wing_pk: Some(XWingPublic {
                x25519_pub: [pk_byte; 32],
                mlkem768_pub: vec![pk_byte; 1184],
            }),
            identity_type: IdentityType::agent(),
            reachability: Reachability::Direct,
        }
    }

    #[test]
    fn insert_get_roundtrip() {
        let cache = DirectoryCache::new();
        assert!(cache.is_empty());
        cache.insert(rec("alice", 0xaa));
        assert_eq!(cache.len(), 1);
        assert!(cache.contains("alice"));
        let got = cache.get("alice").unwrap();
        assert_eq!(got.federation_id, "alice");
        assert_eq!(got.ml_dsa_pk[0], 0xaa);
        assert_eq!(got.identity_type, IdentityType::agent());
    }

    #[test]
    fn lookup_missing_returns_none() {
        let cache = DirectoryCache::new();
        cache.insert(rec("alice", 0xaa));
        assert!(cache.get("bob").is_none());
    }

    #[test]
    fn remove_pulls_entry() {
        let cache = DirectoryCache::new();
        cache.insert(rec("alice", 0xaa));
        let removed = cache.remove("alice").unwrap();
        assert_eq!(removed.federation_id, "alice");
        assert!(cache.get("alice").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn welcome_wrap_lookup_resolves_via_cache() {
        let cache = DirectoryCache::new();
        cache.insert(rec("alice", 0xaa));
        let mut lookup = cache.welcome_wrap_lookup();
        let entry = lookup("alice").unwrap();
        assert_eq!(entry.pk_id, "alice");
        assert_eq!(entry.ml_dsa_pk[0], 0xaa);
        assert!(lookup("bob").is_none());
    }

    #[test]
    fn insert_overwrites_existing() {
        let cache = DirectoryCache::new();
        cache.insert(rec("alice", 0xaa));
        cache.insert(rec("alice", 0xbb));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("alice").unwrap().ml_dsa_pk[0], 0xbb);
    }

    #[test]
    fn reachability_default_is_unknown() {
        assert_eq!(Reachability::default(), Reachability::Unknown);
    }

    #[test]
    fn xwing_public_into_recipient_roundtrip() {
        let p = XWingPublic {
            x25519_pub: [0x42; 32],
            mlkem768_pub: vec![0x11; 1184],
        };
        let recipient: ciris_crypto::hpke::XWingRecipientPublic = (&p).into();
        assert_eq!(recipient.x25519_pub, p.x25519_pub);
        assert_eq!(recipient.mlkem768_pub, p.mlkem768_pub);
    }
}
