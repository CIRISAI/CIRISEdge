//! The key objects of a node, named once, and the ONE way each resolves to
//! another (CIRISEdge#636).
//!
//! Every node holds **two keypairs**, and every attribution bug from #402
//! through #636 came from treating them as one:
//!
//! | object | what it is | where it shows up |
//! |---|---|---|
//! | [`FederationKey`] | `key_id` + Ed25519 pubkey (+ ML-DSA-65); signs every record | `federation_keys`, the announce's claimed pubkey, the `Key` record |
//! | [`TransportIdentityPub`] | the RNS identity `x25519 ‖ ed25519`, minted by the transport keystore, hash = `sha256(pub64)[:16]`; PROVEN by the link handshake | `get_remote_identity(link)`, `link_proven_identity_hash` |
//! | [`TransportBinding`] | *FederationKey ↔ TransportIdentity*, asserted under the federation key's signature | the announce attestation (`{transport_identity_pubkey, key_id, epoch}` signed by F); the `SignedTransportDestination` row (`occurrence_key_id → transport_{x25519,ed25519}_pubkey`) |
//!
//! The transport identity is **not derived from** the federation key and its
//! Ed25519 half is **never equal to** the federation pubkey (the server's
//! measurement in #636: `94GA…` vs `Q1y2…` on every node). The two are bound
//! only by a signed row. So:
//!
//! - *"which federation key holds this link?"* is answered by resolving the
//!   link's proven [`TransportIdentityPub`] through a [`TransportBinding`] —
//!   never by comparing a record's federation pubkey to the link.
//! - *"does this announcer own the key it claims?"* is answered by
//!   [`key_id_binds_pubkey`] (the key id's fingerprint IS the pubkey's) plus
//!   the attestation's self-signature — never by `transport_ed25519 ==
//!   federation_pubkey`.
//!
//! [`FederationKey`]: https://github.com/CIRISAI/CIRISVerify — `ciris_verify_core::fedcode::derive_key_id`

use leviculum_core::Identity;

/// The public halves of an RNS transport identity, `x25519 ‖ ed25519`, exactly
/// as leviculum's `Identity::public_key_bytes()` lays them out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportIdentityPub {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

impl std::fmt::Debug for TransportIdentityPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportIdentityPub")
            .field("hash", &hex::encode(self.hash()))
            .finish_non_exhaustive()
    }
}

impl TransportIdentityPub {
    /// From the 64-byte public form (`x25519 ‖ ed25519`).
    #[must_use]
    pub fn from_pub64(pub64: &[u8; 64]) -> Self {
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&pub64[..32]);
        ed25519.copy_from_slice(&pub64[32..]);
        Self { x25519, ed25519 }
    }

    /// From the identity a link handshake proved (`get_remote_identity`).
    #[must_use]
    pub fn from_identity(identity: &Identity) -> Self {
        Self::from_pub64(&identity.public_key_bytes())
    }

    /// From a `SignedTransportDestination` row's two base64 halves. `None`
    /// when either half is absent or malformed — a partial row binds nothing.
    #[must_use]
    pub fn from_row_halves(x25519_b64: Option<&str>, ed25519_b64: Option<&str>) -> Option<Self> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let x = b64.decode(x25519_b64?).ok()?;
        let e = b64.decode(ed25519_b64?).ok()?;
        Some(Self {
            x25519: x.as_slice().try_into().ok()?,
            ed25519: e.as_slice().try_into().ok()?,
        })
    }

    /// The 64-byte public form.
    #[must_use]
    pub fn pub64(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519);
        out[32..].copy_from_slice(&self.ed25519);
        out
    }

    /// The RNS identity hash, `sha256(x25519 ‖ ed25519)[:16]` — what
    /// `link_proven_identity_hash` logs and what the peers map keys on.
    /// `[0; 16]` for halves leviculum refuses (never matches a real link).
    #[must_use]
    pub fn hash(&self) -> [u8; 16] {
        Identity::from_public_keys(&self.x25519, &self.ed25519).map_or([0u8; 16], |id| *id.hash())
    }
}

/// Whether `key_id` is the id of `federation_pubkey_ed25519`: a federation key
/// id is `<label>-<fingerprint>` with the fingerprint recomputable from the
/// pubkey (`ciris_verify_core::fedcode::derive_key_id`). A claimed id whose
/// fingerprint is not the claimed pubkey's is a claim about someone else's key.
///
/// This is the directory-free half of "the announcer owns the key it claims";
/// the other half is the attestation's self-signature under that pubkey.
/// Legacy / test ids with no fingerprint answer `false` and are lifted only by
/// the directory walk.
#[must_use]
pub fn key_id_binds_pubkey(key_id: &str, federation_pubkey_ed25519: &[u8; 32]) -> bool {
    // `derive_key_id("", pk)` is `id-<fp>`; the fingerprint is everything after
    // the first dash, and a real id ends in `-<fp>`.
    let derived = ciris_verify_core::fedcode::derive_key_id("", federation_pubkey_ed25519);
    let Some(fp) = derived.strip_prefix("id-") else {
        return false;
    };
    key_id
        .rsplit_once('-')
        .is_some_and(|(_, suffix)| suffix == fp)
}

/// Where a [`TransportBinding`] was learned. Only sources this node has
/// VERIFIED are ever consulted for attribution: an announce whose attestation
/// self-verified, or a `SignedTransportDestination` row persist admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingSource {
    /// The live peers map — installed from a verified announce (Stage 1 or 2).
    PeersMap,
    /// The stored `transport_destinations` row — admitted (signature-verified)
    /// by persist.
    StoredTransportDestination,
}

impl BindingSource {
    /// Stable label for logs and the outcome counter.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeersMap => "peers_map",
            Self::StoredTransportDestination => "stored_transport_destination",
        }
    }
}

/// *This federation key holds this transport identity* — the only fact that
/// attributes a link to a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportBinding {
    pub key_id: String,
    pub transport: TransportIdentityPub,
    pub source: BindingSource,
}

/// What the bootstrap door decides for a bootstrap-kind Deliver on a link
/// (CIRISEdge#402 / #624, corrected by #636). The door never DROPS: every
/// bootstrap record is self-authenticating and persist verifies it at
/// admission; the door only says whether the link can be attributed now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapDoor {
    /// The link is already attributed, the link has no proven identity, or the
    /// frame is not a bootstrap Deliver — the door has no job.
    NotApplicable,
    /// A verified binding for a key named by the Deliver holds THIS link's
    /// transport identity: attribute the link to that key.
    Attributed {
        key_id: String,
        source: BindingSource,
    },
    /// No verified binding names this link: deliver the frame un-attributed
    /// (the carve-out). Its records are admitted on their own signatures; the
    /// binding they carry, once admitted, attributes the NEXT frame.
    Unbound,
}

impl BootstrapDoor {
    /// Stable label for logs and the outcome counter.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Attributed { .. } => "attributed",
            Self::Unbound => "unbound",
        }
    }
}

/// The bootstrap door, pure (CIRISEdge#636). `candidate` is the link's
/// existing attribution; `link` its proven transport identity; `bindings` the
/// verified [`TransportBinding`]s resolved for every key the Deliver names.
///
/// - Attributed link, unidentified link, or no bindings gathered (not a
///   bootstrap Deliver) ⇒ `NotApplicable`.
/// - A binding whose transport identity hash is the link's ⇒ `Attributed`.
/// - Otherwise ⇒ `Unbound`. Third-party records (a rooted peer relaying
///   another node's Key / occurrence / TD row) are the normal case here, not
///   evidence of anything — pre-#636 they were a `Mismatch` and dropped.
#[must_use]
pub fn decide_bootstrap_door(
    candidate: Option<&str>,
    link: Option<&TransportIdentityPub>,
    bindings: Option<&[TransportBinding]>,
) -> BootstrapDoor {
    let (Some(link), Some(bindings)) = (link, bindings) else {
        return BootstrapDoor::NotApplicable;
    };
    if candidate.is_some() {
        return BootstrapDoor::NotApplicable;
    }
    let link_hash = link.hash();
    bindings
        .iter()
        .find(|b| b.transport.hash() == link_hash)
        .map_or(BootstrapDoor::Unbound, |b| BootstrapDoor::Attributed {
            key_id: b.key_id.clone(),
            source: b.source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(tag: u8) -> TransportIdentityPub {
        // Real curve points: derive from a private identity so `hash()` is a
        // genuine RNS identity hash, never the `[0; 16]` sentinel.
        let mut prv = [0u8; 64];
        for (i, b) in prv.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("in range") ^ tag;
        }
        let id = Identity::from_private_key_bytes(&prv).expect("identity");
        TransportIdentityPub::from_identity(&id)
    }

    fn fed_pubkey(tag: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("in range").wrapping_mul(7) ^ tag;
        }
        pk
    }

    fn binding(key_id: &str, tag: u8, source: BindingSource) -> TransportBinding {
        TransportBinding {
            key_id: key_id.to_owned(),
            transport: ident(tag),
            source,
        }
    }

    // ── the objects ────────────────────────────────────────────────────────

    #[test]
    fn transport_identity_round_trips_and_hashes_like_leviculum() {
        let t = ident(0x11);
        let again = TransportIdentityPub::from_pub64(&t.pub64());
        assert_eq!(t, again);
        let via_lev = Identity::from_public_keys(&t.x25519, &t.ed25519).expect("valid");
        assert_eq!(t.hash(), *via_lev.hash());
        assert_ne!(t.hash(), [0u8; 16]);
    }

    #[test]
    fn a_row_with_a_missing_half_binds_nothing() {
        use base64::Engine as _;
        let t = ident(0x12);
        let b64 = base64::engine::general_purpose::STANDARD;
        let x = b64.encode(t.x25519);
        let e = b64.encode(t.ed25519);
        assert_eq!(
            TransportIdentityPub::from_row_halves(Some(&x), Some(&e)),
            Some(t)
        );
        assert_eq!(TransportIdentityPub::from_row_halves(None, Some(&e)), None);
        assert_eq!(TransportIdentityPub::from_row_halves(Some(&x), None), None);
        assert_eq!(
            TransportIdentityPub::from_row_halves(Some("not base64!"), Some(&e)),
            None
        );
    }

    /// The fingerprint rule: a key id derived from a pubkey binds that pubkey
    /// and no other; ids without a fingerprint bind nothing.
    #[test]
    fn key_id_binds_exactly_its_own_pubkey() {
        let pk = fed_pubkey(0x21);
        let other = fed_pubkey(0x22);
        let id = ciris_verify_core::fedcode::derive_key_id("ciris-canonical-1", &pk);
        assert!(id.starts_with("ciris-canonical-1-"));
        assert!(key_id_binds_pubkey(&id, &pk));
        assert!(!key_id_binds_pubkey(&id, &other));
        assert!(
            !key_id_binds_pubkey("ciris-canonical-1", &pk),
            "no fingerprint"
        );
        assert!(!key_id_binds_pubkey("agent-alice", &pk));
        assert!(!key_id_binds_pubkey("", &pk));
        // A label containing dashes still binds (the fingerprint is the LAST
        // dash-separated part).
        let dashed = ciris_verify_core::fedcode::derive_key_id("a-b-c", &pk);
        assert!(key_id_binds_pubkey(&dashed, &pk));
    }

    // ── the door: the three cases from CIRISEdge#636 ───────────────────────

    /// A node whose federation key and transport identity DIFFER (every real
    /// node) serves its own record on a link the peer already attributed to
    /// it: the door has no job, the record is admitted. Pre-#636 this was
    /// `Mismatch` → dropped (the canonical's own record on node-a, ×25).
    #[test]
    fn an_attributed_link_is_never_belted_on_federation_pubkeys() {
        let link = ident(0x31);
        let bindings = vec![binding(
            "ciris-canonical-1-bm7v4wdpgk",
            0x31,
            BindingSource::PeersMap,
        )];
        assert_eq!(
            decide_bootstrap_door(
                Some("ciris-canonical-1-bm7v4wdpgk"),
                Some(&link),
                Some(&bindings)
            ),
            BootstrapDoor::NotApplicable
        );
    }

    /// A third party's record served on an un-attributed link (the canonical
    /// relaying node-a's Key to node-b): no binding names this link ⇒ the
    /// frame goes through un-attributed and is admitted on its own signature.
    /// Pre-#636 this was `Mismatch` → dropped (node-b, ×21).
    #[test]
    fn a_third_party_record_on_an_unattributed_link_is_unbound_not_dropped() {
        let link = ident(0x41);
        let bindings = vec![binding(
            "ciris-node-a-3yr5psjdy4",
            0x42, // node-a's transport identity ≠ this link's
            BindingSource::StoredTransportDestination,
        )];
        assert_eq!(
            decide_bootstrap_door(None, Some(&link), Some(&bindings)),
            BootstrapDoor::Unbound
        );
    }

    /// First contact: the link's proven transport identity IS the one a
    /// verified binding holds for a key the Deliver names ⇒ attributed to that
    /// key — through the binding, never through a federation-pubkey compare.
    #[test]
    fn a_link_holding_a_bound_transport_identity_is_attributed_to_its_key() {
        let link = ident(0x51);
        let bindings = vec![
            binding("ciris-node-b-w3yueqf4ok", 0x52, BindingSource::PeersMap),
            binding(
                "ciris-node-a-3yr5psjdy4",
                0x51,
                BindingSource::StoredTransportDestination,
            ),
        ];
        assert_eq!(
            decide_bootstrap_door(None, Some(&link), Some(&bindings)),
            BootstrapDoor::Attributed {
                key_id: "ciris-node-a-3yr5psjdy4".into(),
                source: BindingSource::StoredTransportDestination,
            }
        );
    }

    #[test]
    fn no_identity_or_no_bindings_is_not_this_door() {
        let link = ident(0x61);
        assert_eq!(
            decide_bootstrap_door(None, None, Some(&[])),
            BootstrapDoor::NotApplicable
        );
        assert_eq!(
            decide_bootstrap_door(None, Some(&link), None),
            BootstrapDoor::NotApplicable
        );
        assert_eq!(
            decide_bootstrap_door(None, Some(&link), Some(&[])),
            BootstrapDoor::Unbound,
            "a bootstrap Deliver naming keys none of which are bound here"
        );
    }
}
