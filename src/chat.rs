//! **Chat over the federation planes** — the vocabulary and the producer.
//!
//! A chat message is not a bespoke transport message. It is an ordinary
//! federation-tier `scores` attestation in the `chat:` namespace, carried by
//! the Attestation plane like every other signed row. Everything that plane
//! already does therefore comes along for free: RNS-native transport,
//! multi-hop through relays, store-and-forward, and LXMF interop — none of
//! which chat has to re-implement or even know about.
//!
//! # The two-party room is DERIVED, never negotiated
//!
//! [`pair_community_key_id`] hashes the two fed-IDs in sorted order, so both
//! ends compute the same room id without exchanging anything. Two nodes that
//! never coordinated find the same room; there is no create/join race to lose,
//! and no roster to disagree about.
//!
//! # Who signs — and why the NODE attesting is a WORKAROUND, not the design
//!
//! As built, the NODE attests and signs, on the owner's behalf, and the author
//! rides INSIDE the signed envelope as `on_behalf_of_key_id` — so a relay cannot
//! rewrite whose words these are. This copies CIRISServer's shape, and both
//! exist for one reason: persist's `promote_attestation` re-signs with the
//! node's key and clears `additional_scrubs`, so an actor-attested row could
//! not survive placement at `community`. Under the two-granters rule the
//! SENDER of a message is the actor (the human's FedID, or an AgentID) and the
//! node is custody; a node-only key cannot carry agency
//! (`check_node_agency_admission`). Persist's `enter_federation` /
//! `widen_audience` make the actor the attester with the node as co-scrub;
//! this producer re-bases onto them and this section goes away. See
//! `docs/FSD_REPLICATION_DX.md`, correction of 2026-09-02 — the reason
//! v18.15.0 is held.
//!
//! What makes that a verifiable claim rather than the node's say-so is the
//! owner binding it acts under: `delegates_to(owner → node)` is itself a
//! federation-tier, replicated, revocable row, so the far side can resolve the
//! chain — and an owner who withdraws the binding invalidates the authority for
//! every message that leaned on it.
//!
//! # Wire compatibility
//!
//! Every constant here MUST stay byte-identical to CIRISServer's
//! `contacts_chat.rs`. The wire is the contract, and edge is upstream of the
//! server, so the values are restated rather than imported — the same
//! discipline persist applies to `owner_binding`. A divergence here is a
//! silent interop break, which is why
//! `tests/chat_message_federates.rs` pins the shape.

use ciris_persist::federation::Attestation;
use sha2::{Digest as _, Sha256};

/// The `scores` dimension every chat message carries.
///
/// Versioned because persist's `require_version_segment` demands a `:vN`
/// segment on every `scores` dimension, and `chat:`-prefixed because that
/// prefix is NOT reserved by `default_reserved_prefix_rules` — an ordinary
/// `user` identity may emit it.
pub const CHAT_MESSAGE_DIMENSION: &str = "chat:message:v1";

/// The replication-consent prefix a grant MUST cover for chat to federate.
///
/// Omit it and messages are authored, admitted locally, and never offered to
/// the contact — the plane is consent-gated at the recipient, so a missing
/// prefix is silent.
pub const CHAT_ATTESTATION_PREFIX: &str = "chat:";

/// The derived-id prefix for a two-party chat community.
pub const PAIR_COMMUNITY_PREFIX: &str = "chat:pair:v1:";

/// Envelope member naming the community a message belongs to.
pub const FIELD_COMMUNITY_ID: &str = "community_id";
/// **The attribution member: whose words these are.** Inside the signed bytes.
pub const FIELD_ON_BEHALF_OF: &str = "on_behalf_of_key_id";
/// The message text.
pub const FIELD_BODY: &str = "body";
/// The body's content type.
pub const FIELD_CONTENT_TYPE: &str = "content_type";

/// **The room two people share, derived from their fed-IDs alone.**
///
/// Order-free by construction: the pair is sorted before hashing, so Alice and
/// Bob compute the same id from opposite sides having exchanged nothing. That
/// is what lets a message be addressed to a room the recipient has not created
/// yet — the id is a function of who is talking, not of who spoke first.
#[must_use]
pub fn pair_community_key_id(a: &str, b: &str) -> String {
    let mut pair = [a, b];
    pair.sort_unstable();
    let mut h = Sha256::new();
    h.update(pair[0].as_bytes());
    h.update(b"\n");
    h.update(pair[1].as_bytes());
    format!("{PAIR_COMMUNITY_PREFIX}{}", hex::encode(h.finalize()))
}

/// Build a chat message as a federation-tier `scores` attestation.
///
/// `node_signer` is THIS NODE's signer — the node attests and signs, and
/// `author_key_id` (the human) rides in the signed envelope. See the module
/// docs for why it is the node rather than the owner.
///
/// `recipient_key_id` is the fed-ID being spoken to. It is used ONLY to derive
/// the room id — it is deliberately NOT named on the row, because a
/// community placement must name no party but its own producer.
///
/// # Placement: authored `self`, promoted to `community`
///
/// The returned row is `tier: local`, `cohort_scope: self` — authored, and not
/// yet shareable. The two are different axes: tier is REPLICABILITY, scope is
/// VISIBILITY, and promotion moves both. Promote
/// it with
/// [`promote_to_scope`](crate::replication::attestation_bind::promote_to_scope)
/// to `community` after storing it — that is the visibility tier a two-party
/// chat belongs at, and the put door refuses a `community` row from any signer,
/// so promotion is the only way one is placed.
///
/// **Never `federation`.** That tier is PUBLIC (lightnet) data: a private
/// message placed there is published, not sent. Most promotions in this system
/// go to `family` / `community` / `affiliations`; `federation` is for rows that
/// are meant to be world-readable, like the identity plane.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn chat_message_attestation(
    node_key_id: &str,
    author_key_id: &str,
    recipient_key_id: &str,
    body: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    node_signer: &crate::identity::LocalSigner,
) -> Result<Attestation, String> {
    use sha2::Digest as _;

    let asserted_at = crate::replication::attestation_bind::truncate_to_micros(asserted_at);
    let community_id = pair_community_key_id(author_key_id, recipient_key_id);
    // Deterministic per (room, author, instant) so a retry is idempotent rather
    // than a second message.
    let attestation_id = {
        let mut h = Sha256::new();
        h.update(community_id.as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(asserted_at.to_rfc3339().as_bytes());
        h.update(body.as_bytes());
        format!("chat-{}", hex::encode(h.finalize())[..32].to_owned())
    };
    // PRODUCER-ONLY at both. A `community` placement is a producer's
    // self-declaration about its OWN content's visibility, so the promotion
    // door refuses a row naming any other party (CIRISPersist#592 / AV-84):
    // "a claim about a third party belongs at a broad belonging-tier".
    //
    // The recipient is therefore NOT named on the row. Addressing is the
    // derived `community_id` in the envelope plus the room's roster — which is
    // the contextual-integrity model working as intended: `cohort_scope` is the
    // VISIBILITY mechanism, while `subject_key_ids` governs REVOCATION rights,
    // and those are different questions about the same flow. The subject here
    // is the producer, because these are the producer's own words.
    let subjects = vec![node_key_id.to_owned()];

    let mut envelope = serde_json::json!({
        "dimension": CHAT_MESSAGE_DIMENSION,
        FIELD_COMMUNITY_ID: community_id,
        FIELD_ON_BEHALF_OF: author_key_id,
        FIELD_BODY: body,
        FIELD_CONTENT_TYPE: "text/plain",
        // A `scores` row carries a score; the magnitude is not load-bearing for
        // a message, and a positive constant is the honest "this was said".
        "score": 1.0,
    });
    crate::replication::attestation_bind::bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &crate::replication::attestation_bind::AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: node_key_id,
            attestation_type: "scores",
            attested_key_id: node_key_id,
            subject_key_ids: &subjects,
            // SELF at authorship. The put door refuses a `community` row from
            // any signer — only a promotion may place one — so the message is
            // authored at the narrowest scope and promoted.
            cohort_scope: ciris_persist::federation::types::cohort_scope::SELF,
            weight: None,
        },
    );

    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(node_signer, &canonical, "chat message").await?;

    Ok(Attestation {
        attestation_id,
        attesting_key_id: node_key_id.to_owned(),
        attested_key_id: node_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::SELF.to_owned(),
        // LOCAL tier, not federation. `tier` and `cohort_scope` are different
        // axes and collapsing them is a real bug: tier is REPLICABILITY
        // (local = producer-only-authority, self-visible-only), cohort_scope is
        // VISIBILITY. A row authored at `tier: federation` is already promoted,
        // so `promote_attestation` returns `Ok(false)` and places nothing —
        // silently, because that is its idempotency arm, not an error.
        //
        // Promotion is what flips the tier to federation AND sets the scope, so
        // a message must be authored local/self and promoted into the room.
        tier: ciris_persist::federation::types::attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

/// Read a room's messages, oldest first.
///
/// `participant_nodes` are the NODES that speak in the room — one per person,
/// since the node attests on its owner's behalf. Rows are listed BY issuer
/// because a chat row names no recipient: a `community` placement is a
/// producer self-declaration, so the only party on the row is the producer.
/// Addressing lives in the derived `community_id` and the room's roster.
///
/// Filters on the envelope's `dimension` and `community_id` — the two members
/// the producer signed — so a row is recognised by its content, never by the
/// link it arrived on.
///
/// # Errors
/// A directory read failure.
pub async fn messages_in_room(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    participant_nodes: &[String],
    community_id: &str,
) -> Result<Vec<ChatMessage>, String> {
    let mut out: Vec<ChatMessage> = Vec::new();
    for node in participant_nodes {
        let rows = directory
            .list_attestations_by(node)
            .await
            .map_err(|e| format!("list_attestations_by({node}): {e}"))?;
        out.extend(
            rows.iter()
                .filter_map(|a| ChatMessage::from_row(a, community_id)),
        );
    }
    out.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    out.dedup_by(|a, b| a.attestation_id == b.attestation_id);
    Ok(out)
}

/// One message, as read back off the plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// The SENDER's attestation id — a value the receiver cannot manufacture,
    /// which is what makes "it arrived" checkable rather than assumed.
    pub attestation_id: String,
    /// Whose words: the human, read from inside the signed envelope.
    pub author_key_id: String,
    /// The node that attested and signed on the author's behalf.
    pub attesting_key_id: String,
    pub body: String,
    pub asserted_at: chrono::DateTime<chrono::Utc>,
}

impl ChatMessage {
    /// Recognise a chat row for `community_id`, or `None`.
    #[must_use]
    pub fn from_row(a: &Attestation, community_id: &str) -> Option<Self> {
        let env = &a.attestation_envelope;
        if env.get("dimension").and_then(serde_json::Value::as_str) != Some(CHAT_MESSAGE_DIMENSION)
        {
            return None;
        }
        if env
            .get(FIELD_COMMUNITY_ID)
            .and_then(serde_json::Value::as_str)
            != Some(community_id)
        {
            return None;
        }
        Some(Self {
            attestation_id: a.attestation_id.clone(),
            author_key_id: env
                .get(FIELD_ON_BEHALF_OF)
                .and_then(serde_json::Value::as_str)?
                .to_owned(),
            attesting_key_id: a.attesting_key_id.clone(),
            body: env
                .get(FIELD_BODY)
                .and_then(serde_json::Value::as_str)?
                .to_owned(),
            asserted_at: a.asserted_at,
        })
    }
}
