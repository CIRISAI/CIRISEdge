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
//! - Hybrid X25519+ML-KEM-768 is MANDATORY. Both peers MUST advertise the
//!   ML-KEM-768 half; a peer that lacks it is REJECTED, not degraded.
//! - **The classical X25519-only KEX is RETIRED (CIRISEdge#481).** There is
//!   no negotiable classical path: [`FederationSession::initiate`] refuses a
//!   classical request (or a classical-only peer) and
//!   [`FederationSession::respond`] refuses a classical handshake, both with
//!   [`SessionError::ClassicalKexRetired`]. Fed TM §3.3 Gap C is only closed
//!   if an active attacker cannot force EITHER side down to a
//!   quantum-vulnerable session by stripping the ML-KEM advertisement —
//!   which requires the classical path to be gone, not merely deprioritized.
//!   `Hybrid` and `HybridRequired` are consequently identical on the
//!   initiate side; the `Classical` enum/wire variants are retained ONLY so
//!   a downgrade attempt parses to a typed, logged refusal.
//! - **ML-KEM-only is rejected** — both peers MUST support X25519 as the
//!   classical half of the hybrid construction. A peer advertising ML-KEM-768
//!   without X25519 is out-of-spec; honoring it would create a degraded
//!   ciphersuite an attacker could force by stripping the X25519 half.
//!
//! **`PeerKexPubkeys.mlkem768_pub` is REQUIRED (CIRISEdge#481 item 4).**
//! In a 100% PQC fleet the ML-KEM-less peer no longer exists, so the type
//! no longer represents it: the field is `Vec<u8>`, not `Option`. The one
//! seam through which "maybe-absent" ML-KEM material may still approach
//! this type — Option-shaped FFI tuples and deserializers — is
//! [`PeerKexPubkeys::from_advertisement`], which refuses absence with the
//! typed [`SessionError::HybridRequiredButPeerLacksMlkem`] at CONSTRUCTION.
//! The illegal state is unrepresentable rather than policy-checked: the
//! old `Hybrid → Classical` fallback arm in [`FederationSession::initiate`]
//! is gone because its predicate (`mlkem768_pub.is_some()`) can no longer
//! be false. `OwnKexKeys.mlkem768_priv/pub` deliberately REMAIN `Option`:
//! [`FederationSession::respond`]'s refusal paths
//! ([`SessionError::HybridResponderMissingMlkem`]) need degraded local-key
//! fixtures to exist as test witnesses, mirroring the #481 item-5 decision
//! for `LocalSigner.pqc`.

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
    /// Hybrid X25519 + ML-KEM-768. The peer MUST advertise both halves; a
    /// classical-only peer is REJECTED with
    /// [`SessionError::HybridRequiredButPeerLacksMlkem`]. Since CIRISEdge#481
    /// retired the classical fallback, this is now IDENTICAL to
    /// [`Self::HybridRequired`] on the initiate side (there is no longer a
    /// weaker mode to fall back to).
    Hybrid,
    /// Hybrid X25519 + ML-KEM-768, HNDL-strict. Retained as a distinct name
    /// for callers that assert the channel content is HNDL-sensitive
    /// (CEG §10.5.5; realtime A/V; key_grant DEK distribution). Post-#481 its
    /// negotiation is the same as [`Self::Hybrid`] — a classical-only peer is
    /// REJECTED with [`SessionError::HybridRequiredButPeerLacksMlkem`].
    HybridRequired,
    /// Classical X25519 only — **RETIRED (CIRISEdge#481)**. No longer a
    /// negotiable outcome: requesting it makes [`FederationSession::initiate`]
    /// return [`SessionError::ClassicalKexRetired`]. The variant is retained
    /// so a classical wire message parses to a typed, logged refusal (see
    /// [`SessionHandshakeMsg::Classical`]) rather than a blind parse failure.
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

/// What a peer publishes for KEX. BOTH halves are required
/// (CIRISEdge#481 item 4): the hybrid X25519+ML-KEM-768 construction is
/// mandatory, and a peer that lacks either half is not representable by
/// this type. A peer publishing ONLY the ML-KEM-768 half is represented
/// by `x25519_pub` defaulted to all-zero — callers MUST verify the
/// X25519 half is present before constructing this type from wire
/// input; [`FederationSession::initiate`] additionally rejects the
/// all-zero case at runtime as defense-in-depth.
///
/// Sources that hold "maybe-absent" ML-KEM material (FFI tuples,
/// deserializers) MUST construct through
/// [`PeerKexPubkeys::from_advertisement`], which turns absence into the
/// typed [`SessionError::HybridRequiredButPeerLacksMlkem`] at the
/// construction boundary instead of a policy check downstream.
#[derive(Debug, Clone)]
pub struct PeerKexPubkeys {
    pub x25519_pub: [u8; 32],
    pub mlkem768_pub: Vec<u8>,
}

impl PeerKexPubkeys {
    /// Construct from an Option-shaped KEX advertisement — the ONLY
    /// seam through which possibly-absent ML-KEM material may approach
    /// this type (CIRISEdge#481 item 4). Absence is refused HERE, with
    /// a typed error, so the ML-KEM-less peer is unrepresentable
    /// everywhere downstream: `initiate` needs no fallback arm, and the
    /// A/V-MLS roster gates need no `is_none` pre-checks.
    ///
    /// # Errors
    ///
    /// `mlkem768_pub == None` →
    /// [`SessionError::HybridRequiredButPeerLacksMlkem`].
    pub fn from_advertisement(
        x25519_pub: [u8; 32],
        mlkem768_pub: Option<Vec<u8>>,
    ) -> Result<Self, SessionError> {
        match mlkem768_pub {
            Some(mlkem768_pub) => Ok(Self {
                x25519_pub,
                mlkem768_pub,
            }),
            None => Err(SessionError::HybridRequiredButPeerLacksMlkem),
        }
    }
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
    /// The peer's KEX advertisement lacks the ML-KEM-768 half. Post-
    /// CIRISEdge#481 hybrid is unconditionally required (`Hybrid` ≡
    /// `HybridRequired`), and item 4 made the ML-KEM-less peer
    /// UNREPRESENTABLE by [`PeerKexPubkeys`] — so this error now fires
    /// at exactly one place: [`PeerKexPubkeys::from_advertisement`],
    /// the construction boundary where Option-shaped sources (FFI
    /// tuples, deserializers) are converted. It can no longer be
    /// produced by [`FederationSession::initiate`], whose old
    /// classical-fallback refusal arm this construction-time refusal
    /// replaced.
    #[error(
        "peer KEX advertisement lacks ML-KEM-768 — hybrid X25519+ML-KEM-768 \
         is mandatory (CIRISEdge#481, HNDL discipline)"
    )]
    HybridRequiredButPeerLacksMlkem,
    /// CIRISEdge#481 — the classical X25519-only KEX is RETIRED. Fed TM
    /// §3.3 Gap C (harvest-now-decrypt-later) is only closed if there is
    /// NO negotiable classical path at all: an active attacker who strips a
    /// peer's ML-KEM-768 advertisement must not be able to force either side
    /// down to a quantum-vulnerable session key. This error fires when
    /// `initiate` is asked for classical (explicitly, or via a peer that
    /// lacks ML-KEM-768) OR when `respond` receives a classical handshake.
    /// The `Classical` wire/enum variants are RETAINED so the refusal is a
    /// typed, observable rejection (a downgrade attempt is logged as itself)
    /// rather than a parse failure an attacker could probe blindly.
    #[error("classical KEX is retired (CIRISEdge#481, HNDL discipline) — hybrid X25519+ML-KEM-768 is mandatory")]
    ClassicalKexRetired,
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
    /// pubkeys + the preferred algorithm. Post-CIRISEdge#481 there is
    /// nothing left to negotiate:
    ///
    /// - `Hybrid` | `HybridRequired` → hybrid ([`PeerKexPubkeys`] proves
    ///   the ML-KEM-768 half exists — item 4 made the ML-KEM-less peer
    ///   unrepresentable, so the old classical-fallback and
    ///   refuse-classical-peer arms are structurally gone from here)
    /// - `Classical` requested → [`SessionError::ClassicalKexRetired`]
    /// - Peer has ML-KEM-768 but NO X25519 (all-zero `x25519_pub`) →
    ///   [`SessionError::MlKemOnlyRejected`] — defense in depth for
    ///   callers constructing via deserializers that default the field.
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
        if peer.x25519_pub == [0u8; 32] {
            return Err(SessionError::MlKemOnlyRejected);
        }
        // CIRISEdge#481 — nothing to negotiate. `Hybrid` and `HybridRequired`
        // are IDENTICAL on the initiate side, and item 4 moved the "peer lacks
        // ML-KEM" refusal to `PeerKexPubkeys::from_advertisement`: by the time
        // a value of this type exists, the ML-KEM half provably exists. The
        // silent `Hybrid + peer-lacks-ML-KEM → classical` fallback that used to
        // live here was PRECISELY the downgrade an active attacker forces by
        // stripping a peer's ML-KEM advertisement; Fed TM §3.3 Gap C is only
        // closed once that path is gone — now it is unwritable, not merely
        // deleted.
        match requested {
            KexAlgorithm::Hybrid | KexAlgorithm::HybridRequired => {
                let (msg, k) = hybrid_kex::initiate_hybrid(&peer.x25519_pub, &peer.mlkem768_pub)?;
                Ok((SessionHandshakeMsg::Hybrid(msg), SessionKey(k)))
            }
            KexAlgorithm::Classical => Err(SessionError::ClassicalKexRetired),
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
            // CIRISEdge#481 — a responder MUST NOT derive a key from a classical
            // handshake. This is the ACTIVE-attacker close: an attacker who
            // strips the initiator's ML-KEM advertisement (or hand-crafts a
            // classical handshake) must not establish a quantum-vulnerable
            // session with us. The `Classical` variant is still PARSED so the
            // refusal is typed and observable (a downgrade attempt is logged as
            // itself), but no key is ever computed from it.
            SessionHandshakeMsg::Classical(_m) => Err(SessionError::ClassicalKexRetired),
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
            mlkem768_pub: own
                .mlkem768_pub
                .clone()
                .expect("hybrid fixture always carries ML-KEM-768"),
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

    /// CIRISEdge#481 — an explicit `Classical` request is RETIRED. `initiate`
    /// refuses it with [`SessionError::ClassicalKexRetired`] rather than
    /// producing a classical session key (was: `classical_round_trip`).
    #[test]
    fn classical_initiate_is_retired() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        let r = FederationSession::initiate(&peer_view, KexAlgorithm::Classical);
        assert!(
            matches!(r, Err(SessionError::ClassicalKexRetired)),
            "classical initiate must be retired, got {r:?}"
        );
    }

    /// CIRISEdge#481 item 4 — the classical-only peer is now
    /// UNREPRESENTABLE by `PeerKexPubkeys`; the refusal the old
    /// `hybrid_requested_against_classical_only_peer_is_rejected` test
    /// asserted at `initiate` now fires one layer earlier, at the
    /// construction boundary. Field-exact fixture: the Option shape is
    /// EXACTLY what the FFI produces (`peer_mlkem768_pub.map(<[u8]>::
    /// to_vec)` with Python `None`) — a stripped ML-KEM advertisement
    /// arriving from outside — with a REAL X25519 half, so the only
    /// thing being refused is the ML-KEM absence.
    #[test]
    fn mlkem_absent_advertisement_rejected_at_construction() {
        let responder = fresh_recipient();
        let x25519_pub = x25519::public_from_secret(&responder.x25519_priv);
        let r = PeerKexPubkeys::from_advertisement(x25519_pub, None);
        assert!(
            matches!(r, Err(SessionError::HybridRequiredButPeerLacksMlkem)),
            "ML-KEM-less advertisement must be refused at construction, got {r:?}"
        );
    }

    /// CIRISEdge#481 item 4 — the accepting half of the construction
    /// boundary: a complete advertisement constructs, and the value
    /// initiates a hybrid session under BOTH `Hybrid` and
    /// `HybridRequired` (the modes are identical post-#481; this
    /// preserves the item-2 coverage on the new constructor path).
    #[test]
    fn complete_advertisement_constructs_and_initiates_hybrid() {
        let responder = fresh_recipient();
        let peer_view = PeerKexPubkeys::from_advertisement(
            x25519::public_from_secret(&responder.x25519_priv),
            responder.mlkem768_pub.clone(),
        )
        .expect("complete advertisement must construct");
        for mode in [KexAlgorithm::Hybrid, KexAlgorithm::HybridRequired] {
            let (msg, initiator_key) =
                FederationSession::initiate(&peer_view, mode).expect("initiate");
            assert_eq!(msg.algorithm(), ALGORITHM_HYBRID_V1);
            let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
            assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
        }
    }

    /// CIRISEdge#481 — the ACTIVE-attacker close: even a WELL-FORMED classical
    /// handshake (what an attacker who stripped the initiator's ML-KEM
    /// advertisement would present) is REFUSED by the responder, never
    /// completed into a session key.
    #[test]
    fn respond_rejects_classical_handshake() {
        let responder = fresh_recipient();
        let peer_view = advertise(&responder);
        // Produce a genuine classical handshake via the crypto layer directly
        // — `initiate` itself will no longer emit one.
        let (classical_msg, _initiator_key) = hybrid_kex::initiate_classical(&peer_view.x25519_pub)
            .expect("classical initiate (crypto layer)");
        let wire = SessionHandshakeMsg::Classical(classical_msg);
        let r = FederationSession::respond(&responder, &wire);
        assert!(
            matches!(r, Err(SessionError::ClassicalKexRetired)),
            "responder must refuse a classical handshake, got {r:?}"
        );
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
            mlkem768_pub: responder
                .mlkem768_pub
                .clone()
                .expect("hybrid fixture always carries ML-KEM-768"),
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

    // (was: `hybrid_required_refuses_classical_only_peer` — CIRISEdge#481
    // item 4 made the classical-only peer UNREPRESENTABLE, so the HNDL-
    // strict refusal that test asserted is now the construction-time
    // refusal covered by `mlkem_absent_advertisement_rejected_at_
    // construction`; there is no weaker representable peer left for
    // `HybridRequired` to refuse.)

    /// HybridRequired still rejects the ML-KEM-only peer view shape
    /// (defense-in-depth — the all-zero X25519 sentinel from upstream
    /// deserializers should NOT trigger fallback semantics).
    #[test]
    fn hybrid_required_rejects_mlkem_only_peer_view() {
        let responder = fresh_recipient();
        let bad = PeerKexPubkeys {
            x25519_pub: [0u8; 32],
            mlkem768_pub: responder
                .mlkem768_pub
                .clone()
                .expect("hybrid fixture always carries ML-KEM-768"),
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
