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
//! # Who signs — the ACTOR, at write
//!
//! The SENDER of a message is the person (or agent) whose words they are, and
//! that is who attests and signs it: `attesting_key_id` is the author's own
//! key, and the row is signed at the moment it is written (sign-at-write —
//! CIRISPersist FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE §5.4, answered by
//! edge). The node is CUSTODY: it stores the row, co-scrubs it when the row
//! enters the mesh, and dials on the author's behalf — it never stands in as
//! the sender, because a node-only key cannot carry agency (CC 4.4 two
//! granters, `check_node_agency_admission`).
//!
//! Under persist ≤ v38 this was impossible: the one promotion primitive
//! re-signed every row with the node's key, so the node had to attest and the
//! author rode inside the envelope as `on_behalf_of_key_id`. Persist v39.0.0
//! split promotion into `enter_mesh` (same bytes, actor's signature kept) and
//! `widen_audience` (a `supersedes` the actor signs), and this producer moved
//! to the design. [`ChatMessage::from_row`] still reads the old member, so a
//! pre-v39 row is read back with its author intact.
//!
//! What makes "the author signed it" checkable at the far end is the author's
//! key record on the Key plane, and — for the node that relayed it — the
//! owner binding `delegates_to(owner → node)`: a federation-tier, replicated,
//! revocable row, so the far side can resolve the chain and an owner who
//! withdraws the binding invalidates the node's custody for everything after.
//!
//! # Placement: authored `self`, shared to `community` — TWO rows
//!
//! A message is authored `tier: local`, `cohort_scope: self` and shared to
//! the room with [`share`](crate::replication::attestation_bind::share). That
//! is two operations, and after it there are two rows: the original, now
//! `(federation, self)` — replicated to the author's own devices and never
//! advertised (CC 5.2) — and a `supersedes` at `community`, the row the other
//! person receives. [`messages_in_room`] folds them so a room reads as one
//! message per thing said.
//!
//! **Never `federation`.** That tier is PUBLIC (lightnet) data: a private
//! message placed there is published, not sent.
//!
//! # Wire compatibility
//!
//! Every constant here is the wire contract, and edge is upstream of
//! CIRISServer, so the values are stated here rather than imported — the same
//! discipline persist applies to `owner_binding`. Two things moved with
//! persist v39 and CIRISServer's `contacts_chat.rs` moves with them: the
//! attester is the author, and the room member is `community_key_id` (the
//! canonical cohort-target alias, [`FIELD_COMMUNITY_ID`]) — persist's widening
//! carries the placement under that name, so the row a peer receives names
//! the room by it whatever the author wrote. `tests/chat_message_federates.rs`
//! pins the shape.

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

/// Envelope member naming the community a message belongs to — persist's
/// canonical cohort-target alias, so the author's row and the `supersedes`
/// persist's widening writes name the room by the same member.
pub const FIELD_COMMUNITY_ID: &str = "community_key_id";
/// **Pre-v39 attribution member.** Read, never written: under persist ≤ v38
/// the node attested and the author rode here. A row that carries it is
/// read back with that author; a row that does not is its attester's words.
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

/// Build a chat message: a `scores` attestation the AUTHOR attests and signs.
///
/// `author` is the sender's own signer — the human's FedID as they hit send,
/// or an AgentID in-process. It is the attester, the attested key, the sole
/// subject, and the signature: sign-at-write, so the row carries the actor's
/// signature from the first byte and the node can co-scrub it at the crossing
/// whether or not the author is still reachable then.
///
/// `recipient_key_id` is the fed-ID being spoken to. It is used ONLY to derive
/// the room id — it is deliberately NOT named on the row, because a
/// community placement must name no party but its own producer
/// (CIRISPersist#592 / AV-84).
///
/// The returned row is `tier: local`, `cohort_scope: self` — authored, and
/// not yet shared. Share it with
/// [`share`](crate::replication::attestation_bind::share) at
/// `With::Community { community_key_id }` after storing it; the put door
/// refuses a `community` row from any direct write, so the widening is the
/// only way one is placed, and it is the actor's own `supersedes`.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn chat_message_attestation(
    author: &crate::identity::LocalSigner,
    recipient_key_id: &str,
    body: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };

    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let community_key_id = pair_community_key_id(author_key_id, recipient_key_id);
    // Deterministic per (room, author, instant, body) so a retry is idempotent
    // rather than a second message. The instant is hashed in its canonical
    // rendering, so the id is a function of the signed bytes' own value.
    let attestation_id = {
        let mut h = Sha256::new();
        h.update(community_key_id.as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(body.as_bytes());
        format!("chat-{}", hex::encode(h.finalize())[..32].to_owned())
    };
    // PRODUCER-ONLY at both. A `community` placement is a producer's
    // self-declaration about its OWN content's visibility, so the door
    // refuses a row naming any other party (CIRISPersist#592 / AV-84).
    //
    // The recipient is therefore NOT named on the row. Addressing is the
    // derived `community_key_id` in the envelope plus the room's roster —
    // which is the contextual-integrity model working as intended:
    // `cohort_scope` is the VISIBILITY axis, while `subject_key_ids` governs
    // REVOCATION, and those are different questions about the same flow. The
    // subject here is the author, because these are the author's own words.
    let subjects = vec![author_key_id.to_owned()];

    let mut envelope = serde_json::json!({
        "dimension": CHAT_MESSAGE_DIMENSION,
        FIELD_COMMUNITY_ID: community_key_id,
        FIELD_BODY: body,
        FIELD_CONTENT_TYPE: "text/plain",
        // A `scores` row carries a score; the magnitude is not load-bearing for
        // a message, and a positive constant is the honest "this was said".
        "score": 1.0,
    });
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            // SELF at authorship: the narrowest scope. The widening to the
            // room is the author's own `supersedes`, written by `share`.
            cohort_scope: ciris_persist::federation::types::cohort_scope::SELF,
            weight: None,
        },
    );

    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(author, &canonical, "chat message").await?;

    Ok(Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::SELF.to_owned(),
        // LOCAL tier, not federation. `tier` and `cohort_scope` are different
        // axes: tier is REPLICABILITY (local = producer-only-authority,
        // self-visible-only), cohort_scope is VISIBILITY. A row authored at
        // `tier: federation` is already in the mesh, and `share` would only
        // widen it; authoring local keeps "sent" a deliberate act.
        tier: ciris_persist::federation::types::attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

/// Read a room's messages, oldest first, one per thing said.
///
/// `participants` are the KEYS that speak in the room — the humans (or agents)
/// who author messages. Rows are listed BY issuer because a chat row names no
/// recipient: a `community` placement is a producer self-declaration, so the
/// only party on the row is the producer. Addressing lives in the derived
/// `community_key_id` and the room's roster.
///
/// Filters on the envelope's `dimension` and cohort target — the members the
/// author signed — so a row is recognised by its content, never by the link it
/// arrived on. Then FOLDS `supersedes`: a widening IS the claim at the wider
/// audience (CC 4.4.3.3.1), so when both the author's `self` row and its
/// `community` widening are present (on the author's own devices), the prior
/// is dropped and the widening stands. A peer holds only the widening.
///
/// # Errors
/// A directory read failure.
pub async fn messages_in_room(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    participants: &[String],
    community_key_id: &str,
) -> Result<Vec<ChatMessage>, String> {
    let mut rows: Vec<Attestation> = Vec::new();
    for who in participants {
        rows.extend(
            directory
                .list_attestations_by(who)
                .await
                .map_err(|e| format!("list_attestations_by({who}): {e}"))?,
        );
    }
    let superseded: std::collections::BTreeSet<String> = rows
        .iter()
        .filter_map(|a| {
            a.attestation_envelope
                .get(ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut out: Vec<ChatMessage> = rows
        .iter()
        .filter(|a| !superseded.contains(&a.attestation_id))
        .filter_map(|a| ChatMessage::from_row(a, community_key_id))
        .collect();
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
    /// The row's id — the widening's, on a peer. A value the receiver cannot
    /// manufacture, which is what makes "it arrived" checkable rather than
    /// assumed.
    pub attestation_id: String,
    /// Whose words: the attester — or, on a pre-v39 row, the author the node
    /// signed for (`on_behalf_of_key_id`, inside the signed envelope).
    pub author_key_id: String,
    /// Who attested and signed the row. Equal to `author_key_id` from
    /// persist v39 on; the relaying node on a pre-v39 row.
    pub attesting_key_id: String,
    pub body: String,
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// The `self` row this widening supersedes, when it is one. Present on
    /// every row a peer receives; absent on the author's own `self` copy.
    pub widens: Option<String>,
}

impl ChatMessage {
    /// Recognise a chat row for `community_key_id`, or `None`.
    ///
    /// The room is read through persist's cohort-target resolver, which
    /// accepts every alias (`community_id`, `community_key_id`, ...) and
    /// refuses a split-brain row naming two — so the author's row and the
    /// widening persist wrote for it match the same room.
    #[must_use]
    pub fn from_row(a: &Attestation, community_key_id: &str) -> Option<Self> {
        use ciris_persist::federation::envelope::paths;
        let env = &a.attestation_envelope;
        if env
            .get(paths::DIMENSION)
            .and_then(serde_json::Value::as_str)
            != Some(CHAT_MESSAGE_DIMENSION)
        {
            return None;
        }
        if ciris_persist::federation::admission::envelope_cohort_target(env)
            .ok()
            .flatten()
            != Some(community_key_id)
        {
            return None;
        }
        Some(Self {
            attestation_id: a.attestation_id.clone(),
            author_key_id: env
                .get(FIELD_ON_BEHALF_OF)
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| a.attesting_key_id.clone(), str::to_owned),
            attesting_key_id: a.attesting_key_id.clone(),
            body: env
                .get(FIELD_BODY)
                .and_then(serde_json::Value::as_str)?
                .to_owned(),
            asserted_at: a.asserted_at,
            widens: env
                .get(paths::REFERENCES_ATTESTATION_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }
}
