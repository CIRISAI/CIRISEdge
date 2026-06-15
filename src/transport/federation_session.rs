//! Federation session — hybrid X25519+ML-KEM-768 KEX over CIRIS federation transports.
//!
//! Closes CIRISEdge#54 (Fed TM §3.3 Gap C — harvest-now-decrypt-later
//! vulnerability).
//!
//! ## Threat addressed
//!
//! Without a PQ-aware KEX, an attacker capturing federation ciphertexts
//! today (when classical-only) keeps a copy of every wrapped DEK / session
//! key forever, then decrypts it once a CRQC (cryptographically-relevant
//! quantum computer) emerges. CIRIS federation messages contain
//! AV-RECONSIDER votes, hard_case adjudications, and skill-import
//! manifests — content whose secrecy must survive into the post-quantum
//! era. The hybrid construction below means an attacker must break BOTH
//! X25519 AND ML-KEM-768 to recover the session key; ML-KEM-768 is
//! FIPS 203 final.
//!
//! ## Layering
//!
//! [`FederationSession`] sits ABOVE the transport medium (HTTPS / Reticulum)
//! and BELOW the application-layer signed-envelope shape. It produces a
//! 32-byte session key per peer pair; the transport AEAD layer (existing
//! per-medium code, plus follow-up #62 for realtime A/V) consumes that key
//! to wrap individual frames. The KEX is one-shot per session; key
//! rotation and forward secrecy across re-handshakes are caller-managed
//! and out of scope for this module.
//!
//! Edge does NOT generate KEX keypairs itself — the keyring + crypto
//! crates from CIRISVerify (already pulled via `ciris-crypto`) own
//! keypair generation, and federation pubkey advertisement rides the
//! existing peer-info / federation-directory surfaces. This module is
//! the verb (initiate/respond); the nouns (KEX pubkey provenance) live
//! upstream.
//!
//! ## Negotiation rules
//!
//! - Hybrid is the default.
//! - Classical fallback is admitted iff the peer's advertised KEX pubkeys
//!   lack the ML-KEM-768 half.
//! - **ML-KEM-only is rejected at v1** — both peers MUST support X25519
//!   for fallback safety. A peer advertising ML-KEM-768 without X25519 is
//!   out-of-spec; honoring it would create a degraded ciphersuite an
//!   attacker could force by stripping the X25519 advertisement.
//!
//! These rules are encoded structurally in [`PeerKexPubkeys`]
//! (`x25519_pub` is required; `mlkem768_pub` is `Option`) and enforced
//! in [`FederationSession::initiate`].

use ciris_crypto::hybrid_kex::{
    self, ClassicalHandshakeMsg, HybridHandshakeMsg, KEX_ALGORITHM_CLASSICAL_V1,
    KEX_ALGORITHM_HYBRID_V1,
};
use zeroize::Zeroize;

/// Algorithm identifier strings as they appear on the wire — re-exported
/// from the `ciris-crypto` crate so callers don't have to reach across
/// the dependency boundary. Match the spec in CIRISEdge#54 verbatim.
pub const ALGORITHM_HYBRID_V1: &str = KEX_ALGORITHM_HYBRID_V1;
pub const ALGORITHM_CLASSICAL_V1: &str = KEX_ALGORITHM_CLASSICAL_V1;

/// The negotiated outcomes. ML-KEM-only is intentionally not
/// representable — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexAlgorithm {
    /// Hybrid X25519 + ML-KEM-768. Default whenever the peer advertises
    /// both halves; falls back to [`Self::Classical`] silently when the
    /// peer is classical-only.
    Hybrid,
    /// Hybrid X25519 + ML-KEM-768 with NO classical fallback. Caller
    /// asserts the channel content is HNDL-sensitive (CEG §10.5.5;
    /// realtime A/V; key_grant DEK distribution) — a peer that hasn't
    /// advertised ML-KEM-768 is REJECTED with
    /// [`SessionError::HybridRequiredButPeerLacksMlkem`] rather than
    /// silently degraded.
    HybridRequired,
    /// Classical X25519 only. Admitted when the peer hasn't published
    /// an ML-KEM-768 pubkey AND the caller opted in to fallback via
    /// [`Self::Hybrid`] (NOT [`Self::HybridRequired`]).
    Classical,
}

impl KexAlgorithm {
    /// Stable identifier — call sites stamp this into the transport
    /// envelope per CIRISEdge#54 acceptance criterion 1. `HybridRequired`
    /// stamps the same wire ID as `Hybrid` (they negotiate to the same
    /// wire output — `HybridRequired` differs only in refusing the
    /// fallback path).
    pub fn wire_id(self) -> &'static str {
        match self {
            Self::Hybrid | Self::HybridRequired => ALGORITHM_HYBRID_V1,
            Self::Classical => ALGORITHM_CLASSICAL_V1,
        }
    }
}

/// What a peer publishes for KEX. X25519 is required (fallback safety);
/// ML-KEM-768 is optional (a peer at older keying levels is admitted via
/// classical fallback). A peer publishing ONLY the ML-KEM-768 half is
/// represented by `mlkem768_pub: Some` with `x25519_pub` defaulted —
/// callers MUST verify the X25519 half is present before constructing
/// this type from wire input; [`FederationSession::initiate`] additionally
/// rejects the case at runtime as defense-in-depth.
#[derive(Debug, Clone)]
pub struct PeerKexPubkeys {
    pub x25519_pub: [u8; 32],
    pub mlkem768_pub: Option<Vec<u8>>,
}

/// The local side's KEX private keys. Required for [`FederationSession::respond`].
///
/// `mlkem768_priv` + `mlkem768_pub` are paired; both required when
/// responding to a hybrid initiate (the ML-KEM-768 pubkey is bound into
/// the HKDF salt, so the responder must know its own pubkey to recompute
/// the same session key).
#[derive(Clone)]
pub struct OwnKexKeys {
    pub x25519_priv: [u8; 32],
    pub mlkem768_priv: Option<Vec<u8>>,
    pub mlkem768_pub: Option<Vec<u8>>,
}

impl Drop for OwnKexKeys {
    fn drop(&mut self) {
        self.x25519_priv.zeroize();
        if let Some(p) = self.mlkem768_priv.as_mut() {
            p.zeroize();
        }
    }
}

impl std::fmt::Debug for OwnKexKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnKexKeys")
            .field("x25519_priv", &"<redacted>")
            .field(
                "mlkem768_priv",
                &self.mlkem768_priv.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "mlkem768_pub",
                &self
                    .mlkem768_pub
                    .as_ref()
                    .map(|p| format!("<{} bytes>", p.len())),
            )
            .finish()
    }
}

/// Wire form of the initiator → responder handshake message. Algorithm
/// branches are flat enums so JSON / cbor / msgpack consumers can serialize
/// without separate algorithm-specific call sites.
#[derive(Debug, Clone)]
pub enum SessionHandshakeMsg {
    Hybrid(HybridHandshakeMsg),
    Classical(ClassicalHandshakeMsg),
}

impl SessionHandshakeMsg {
    /// The wire algorithm ID — stamped into the transport envelope so
    /// the responder routes to the right `respond_*` path.
    pub fn algorithm(&self) -> &str {
        match self {
            Self::Hybrid(m) => &m.algorithm,
            Self::Classical(m) => &m.algorithm,
        }
    }
}

/// 32-byte shared session key. Zeroized on drop. Consumers must NOT
/// `Clone` or `Copy` this type casually — wrap in [`std::sync::Arc`] if
/// multi-task sharing is needed; the AEAD path takes `&[u8; 32]` by
/// reference.
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Borrow the raw 32 bytes — for the AEAD path. Callers MUST NOT
    /// log, persist, or transmit these bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("bytes", &"<redacted 32B>")
            .finish()
    }
}

/// Errors a session-setup call can return. Mirrors `ciris_crypto::hybrid_kex::KexError`
/// shape but stays inside the edge crate's error vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("KEX primitive failed: {0:?}")]
    Crypto(hybrid_kex::KexError),
    /// The peer advertised ML-KEM-768 but not X25519 — out of spec per
    /// CIRISEdge#54 acceptance criterion 4. This case CAN reach this
    /// module if construction-time validation is bypassed (e.g. tests,
    /// or a future deserializer that doesn't enforce the X25519
    /// non-default invariant).
    #[error("ML-KEM-only mode rejected — both peers MUST support X25519")]
    MlKemOnlyRejected,
    /// The responder received a handshake message whose `algorithm`
    /// field doesn't match either KEX mode the responder supports.
    /// Producer error or version downgrade attempt.
    #[error("algorithm mismatch — observed {observed:?}, expected {expected}")]
    AlgorithmMismatch { observed: String, expected: String },
    /// The responder received a hybrid handshake but lacks an ML-KEM-768
    /// key pair to decapsulate.
    #[error("hybrid responder missing ML-KEM-768 private key")]
    HybridResponderMissingMlkem,
    /// Caller requested [`KexAlgorithm::HybridRequired`] (HNDL-strict
    /// mode) against a peer that hasn't advertised ML-KEM-768. Refused
    /// rather than silently negotiated down to classical — `HybridRequired`
    /// is the caller asserting the channel content must survive into the
    /// post-quantum era, and a classical-only outcome would violate that.
    #[error("HybridRequired mode rejects classical-fallback peer (HNDL discipline)")]
    HybridRequiredButPeerLacksMlkem,
}

impl From<hybrid_kex::KexError> for SessionError {
    fn from(e: hybrid_kex::KexError) -> Self {
        Self::Crypto(e)
    }
}

/// Setup verbs for the per-peer KEX. Stateless — both calls own all the
/// material they need via their arguments.
pub struct FederationSession;

impl FederationSession {
    /// Initiator side. Caller supplies the peer's advertised KEX
    /// pubkeys + the preferred algorithm. Negotiation rules per
    /// module docs are applied here:
    ///
    /// - `Hybrid` requested + peer has ML-KEM-768 → hybrid
    /// - `Hybrid` requested + peer lacks ML-KEM-768 → classical fallback
    /// - `Classical` requested → classical (caller already negotiated down)
    /// - Peer has ML-KEM-768 but NO X25519 → [`SessionError::MlKemOnlyRejected`]
    ///   even though the type system tries to make this unrepresentable
    ///   (defense in depth for callers constructing via deserializers).
    ///
    /// Returns the wire message to send the responder PLUS the
    /// initiator's session key.
    pub fn initiate(
        peer: &PeerKexPubkeys,
        requested: KexAlgorithm,
    ) -> Result<(SessionHandshakeMsg, SessionKey), SessionError> {
        // ML-KEM-only sanity check. The `PeerKexPubkeys` type requires
        // `x25519_pub: [u8; 32]` (no `Option`), so this branch fires only
        // when an upstream constructor silently defaulted the X25519
        // field to all zeros (which is itself a refusable pubkey — see
        // [Curve25519 small-subgroup attacks]). Treat all-zero as
        // "not advertised" and refuse.
        if peer.x25519_pub == [0u8; 32] && peer.mlkem768_pub.is_some() {
            return Err(SessionError::MlKemOnlyRejected);
        }
        // Negotiation:
        // - HybridRequired + peer has ML-KEM → hybrid
        // - HybridRequired + peer lacks ML-KEM → REJECT (HNDL discipline)
        // - Hybrid + peer has ML-KEM → hybrid
        // - Hybrid + peer lacks ML-KEM → classical fallback
        // - Classical (requested) → classical
        let actual = match (requested, peer.mlkem768_pub.is_some()) {
            (KexAlgorithm::HybridRequired, false) => {
                return Err(SessionError::HybridRequiredButPeerLacksMlkem);
            }
            (KexAlgorithm::HybridRequired | KexAlgorithm::Hybrid, true) => KexAlgorithm::Hybrid,
            (KexAlgorithm::Hybrid, false) | (KexAlgorithm::Classical, _) => KexAlgorithm::Classical,
        };
        match actual {
            KexAlgorithm::Hybrid => {
                let mlkem_pub = peer.mlkem768_pub.as_deref().expect("checked above");
                let (msg, k) = hybrid_kex::initiate_hybrid(&peer.x25519_pub, mlkem_pub)?;
                Ok((SessionHandshakeMsg::Hybrid(msg), SessionKey(k)))
            }
            KexAlgorithm::Classical => {
                let (msg, k) = hybrid_kex::initiate_classical(&peer.x25519_pub)?;
                Ok((SessionHandshakeMsg::Classical(msg), SessionKey(k)))
            }
            // `actual` is the post-negotiation outcome — the negotiation
            // arm above either returns Err for `HybridRequired` against
            // a classical peer or collapses to `Hybrid` against a
            // hybrid one, so `HybridRequired` never reaches here.
            KexAlgorithm::HybridRequired => unreachable!(
                "post-negotiation actual is Hybrid or Classical; HybridRequired never escapes"
            ),
        }
    }

    /// Responder side. Recomputes the same session key from the
    /// initiator's wire message + the responder's KEX private keys.
    ///
    /// The responder dispatches on the wire algorithm field. A hybrid
    /// message routed to a responder without ML-KEM-768 keys returns
    /// [`SessionError::HybridResponderMissingMlkem`] — the responder
    /// is expected to have advertised hybrid support iff it has the
    /// keys; routing a hybrid to a classical-only responder is the
    /// initiator's bug.
    pub fn respond(
        own: &OwnKexKeys,
        msg: &SessionHandshakeMsg,
    ) -> Result<SessionKey, SessionError> {
        match msg {
            SessionHandshakeMsg::Hybrid(m) => {
                let priv_ = own
                    .mlkem768_priv
                    .as_deref()
                    .ok_or(SessionError::HybridResponderMissingMlkem)?;
                let pub_ = own
                    .mlkem768_pub
                    .as_deref()
                    .ok_or(SessionError::HybridResponderMissingMlkem)?;
                let k = hybrid_kex::respond_hybrid_with_public(&own.x25519_priv, priv_, pub_, m)?;
                Ok(SessionKey(k))
            }
            SessionHandshakeMsg::Classical(m) => {
                let k = hybrid_kex::respond_classical(&own.x25519_priv, m)?;
                Ok(SessionKey(k))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ml_kem, x25519};

    /// Helper — generate a fresh recipient hybrid keypair set. Mirrors
    /// the persist team's own internal helper from `wheel_hybrid_kex.rs`
    /// so our tests share the same shape of "fresh keys → round-trip".
    fn fresh_recipient() -> OwnKexKeys {
        let (x_secret, _x_public) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
        let (mlkem_secret, mlkem_public) = ml_kem::generate_keypair().expect("ml-kem keypair");
        OwnKexKeys {
            x25519_priv: x_secret,
            mlkem768_priv: Some(mlkem_secret.clone()),
            mlkem768_pub: Some(mlkem_public.clone()),
        }
    }

    fn advertise(own: &OwnKexKeys) -> PeerKexPubkeys {
        PeerKexPubkeys {
            x25519_pub: x25519::public_from_secret(&own.x25519_priv),
            mlkem768_pub: own.mlkem768_pub.clone(),
        }
    }

    fn advertise_classical_only(own: &OwnKexKeys) -> PeerKexPubkeys {
        PeerKexPubkeys {
            x25519_pub: x25519::public_from_secret(&own.x25519_priv),
            mlkem768_pub: None,
        }
    }

    /// Acceptance criterion 2 — round-trip initiate → respond yields the
    /// same 32-byte session key on both sides. Hybrid mode.
    #[test]
    fn hybrid_round_trip_yields_matching_session_keys() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        let (msg, initiator_key) =
            FederationSession::initiate(&peer_view, KexAlgorithm::Hybrid).expect("initiate");
        assert_eq!(msg.algorithm(), ALGORITHM_HYBRID_V1);
        let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
        assert_eq!(
            initiator_key.as_bytes(),
            responder_key.as_bytes(),
            "session keys diverged"
        );
        // Length sanity — 32B as advertised.
        assert_eq!(initiator_key.as_bytes().len(), 32);
    }

    /// Same as above, classical mode (X25519 only).
    #[test]
    fn classical_round_trip_yields_matching_session_keys() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        let (msg, initiator_key) =
            FederationSession::initiate(&peer_view, KexAlgorithm::Classical).expect("initiate");
        assert_eq!(msg.algorithm(), ALGORITHM_CLASSICAL_V1);
        let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
        assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
    }

    /// Acceptance criterion 3 — classical fallback when peer hasn't
    /// advertised ML-KEM-768. Requesting hybrid against such a peer
    /// negotiates DOWN to classical, NOT failing.
    #[test]
    fn hybrid_requested_against_classical_only_peer_falls_back() {
        let responder = fresh_recipient();
        let peer_view = advertise_classical_only(&responder);
        let (msg, initiator_key) =
            FederationSession::initiate(&peer_view, KexAlgorithm::Hybrid).expect("initiate");
        assert_eq!(
            msg.algorithm(),
            ALGORITHM_CLASSICAL_V1,
            "fallback should pick classical"
        );
        let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
        assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
    }

    /// Acceptance criterion 4 — ML-KEM-only mode rejected. A peer view
    /// that names ML-KEM-768 but defaults X25519 to all-zero (the
    /// hallmark of a deserialize-skipped or never-published X25519
    /// half) MUST be refused before any crypto runs.
    #[test]
    fn mlkem_only_peer_view_rejected() {
        let responder = fresh_recipient();
        let bad_peer_view = PeerKexPubkeys {
            x25519_pub: [0u8; 32],
            mlkem768_pub: responder.mlkem768_pub.clone(),
        };
        let r = FederationSession::initiate(&bad_peer_view, KexAlgorithm::Hybrid);
        assert!(
            matches!(r, Err(SessionError::MlKemOnlyRejected)),
            "expected MlKemOnlyRejected, got {r:?}"
        );
    }

    /// Algorithm-ID downgrade resistance — if a wire message claims the
    /// hybrid algorithm but its responder-side processing dispatches to
    /// classical (or vice versa), the underlying `respond_*` primitives
    /// surface `AlgorithmMismatch`. This dispatch is structural in our
    /// `SessionHandshakeMsg` enum, so the only way to hit this is to
    /// hand-craft a message — verify the crypto layer's own check fires
    /// for that hand-craft.
    #[test]
    fn handcrafted_algorithm_downgrade_caught_by_crypto_layer() {
        let responder = fresh_recipient();
        // Craft a "classical" responder call with a handshake whose
        // algorithm string is hybrid. ciris_crypto::hybrid_kex must
        // reject this.
        let bogus = ClassicalHandshakeMsg {
            algorithm: KEX_ALGORITHM_HYBRID_V1.to_string(),
            x25519_ephemeral_pub: [0u8; 32],
        };
        let r = hybrid_kex::respond_classical(&responder.x25519_priv, &bogus);
        assert!(matches!(
            r,
            Err(hybrid_kex::KexError::AlgorithmMismatch { .. })
        ));
    }

    /// Hybrid responder with no ML-KEM-768 keys — graceful refusal,
    /// not a panic or silent classical degradation.
    #[test]
    fn hybrid_message_to_classical_responder_refused() {
        let real = fresh_recipient();
        let peer_view = advertise(&real);
        let (msg, _) =
            FederationSession::initiate(&peer_view, KexAlgorithm::Hybrid).expect("initiate");
        // Strip the ML-KEM keys from the "responder" we hand to respond().
        let degraded = OwnKexKeys {
            x25519_priv: real.x25519_priv,
            mlkem768_priv: None,
            mlkem768_pub: None,
        };
        let r = FederationSession::respond(&degraded, &msg);
        assert!(matches!(r, Err(SessionError::HybridResponderMissingMlkem)));
    }

    /// SessionKey debug output redacts the bytes — no accidental log leaks.
    #[test]
    fn session_key_debug_is_redacted() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        let (_msg, k) =
            FederationSession::initiate(&peer_view, KexAlgorithm::Hybrid).expect("initiate");
        let s = format!("{k:?}");
        assert!(s.contains("<redacted"), "session key leaked in Debug: {s}");
        assert!(
            !s.contains(&hex::encode(&k.as_bytes()[..4])),
            "session key bytes appeared in Debug"
        );
    }

    /// OwnKexKeys Debug output redacts the private material — same.
    #[test]
    fn own_kex_keys_debug_is_redacted() {
        let own = fresh_recipient();
        let s = format!("{own:?}");
        assert!(s.contains("<redacted>"), "private key leaked: {s}");
    }

    /// HNDL-strict mode succeeds against a hybrid peer — produces the
    /// same hybrid session key as plain `Hybrid` mode would.
    #[test]
    fn hybrid_required_succeeds_against_hybrid_peer() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        let (msg, initiator_key) =
            FederationSession::initiate(&peer_view, KexAlgorithm::HybridRequired)
                .expect("initiate");
        assert_eq!(msg.algorithm(), ALGORITHM_HYBRID_V1);
        let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
        assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
    }

    /// HNDL-strict mode refuses a classical-only peer instead of
    /// silently degrading. This is the load-bearing assertion for
    /// CEG §10.5.5 realtime A/V + key_grant DEK distribution: the
    /// content's HNDL-secrecy is the caller's intent, and the substrate
    /// honors it by refusal rather than fallback.
    #[test]
    fn hybrid_required_refuses_classical_only_peer() {
        let responder = fresh_recipient();
        let peer_view = advertise_classical_only(&responder);
        let r = FederationSession::initiate(&peer_view, KexAlgorithm::HybridRequired);
        assert!(
            matches!(r, Err(SessionError::HybridRequiredButPeerLacksMlkem)),
            "expected HybridRequiredButPeerLacksMlkem, got {r:?}"
        );
    }

    /// HybridRequired still rejects the ML-KEM-only peer view shape
    /// (defense-in-depth — the all-zero X25519 sentinel from upstream
    /// deserializers should NOT trigger fallback semantics).
    #[test]
    fn hybrid_required_rejects_mlkem_only_peer_view() {
        let responder = fresh_recipient();
        let bad = PeerKexPubkeys {
            x25519_pub: [0u8; 32],
            mlkem768_pub: responder.mlkem768_pub.clone(),
        };
        let r = FederationSession::initiate(&bad, KexAlgorithm::HybridRequired);
        assert!(matches!(r, Err(SessionError::MlKemOnlyRejected)));
    }

    /// HybridRequired stamps the hybrid wire ID — interop with existing
    /// `Hybrid` responders is byte-identical, only the initiator
    /// negotiation policy differs.
    #[test]
    fn hybrid_required_wire_id_matches_hybrid() {
        assert_eq!(KexAlgorithm::HybridRequired.wire_id(), ALGORITHM_HYBRID_V1);
        assert_eq!(KexAlgorithm::Hybrid.wire_id(), ALGORITHM_HYBRID_V1);
        assert_eq!(KexAlgorithm::Classical.wire_id(), ALGORITHM_CLASSICAL_V1);
    }
}
