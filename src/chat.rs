//! **Chat over the federation planes** — the vocabulary, the producers, and
//! the seal.
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
//! and no roster to disagree about. [`pair_community`] is the room as a
//! record: both people `founder`s, so both are moderators by construction.
//!
//! # Community tier is ENCRYPTED — the body is sealed under the room's key
//!
//! A `community` placement is cohort-filtered visibility, and its bytes are
//! encrypted at rest (CC 4.4.3.2.1). For chat that is not a substrate promise
//! about storage; it is the message. The body of every message is sealed
//! under the room's MLS **record secret** ([`RoomKey`], the group's exporter
//! for records) with XChaCha20-Poly1305, keyed through HKDF over the room,
//! the author, the claim's signed instant and the epoch — so a ciphertext
//! lifted onto any other row does not open. (The instant became bindable in
//! persist v40.0.0, which carries the CLAIM's `asserted_at` verbatim onto a
//! widening and gives the placement its own `widened_at`; under v39.0.0 the
//! widening re-stamped it, so the far end — which only ever receives the
//! widening — could not have opened a message keyed on it.) What crosses the
//! wire, and what the
//! relay and every node that is not a member holds, is ciphertext inside a
//! signed envelope. There is no plaintext producer.
//!
//! # The MLS handshake rides the room — directory-only MLS
//!
//! The room's key is an MLS group between the two people (ciphersuite
//! `0x004D`, X-Wing). The handshake needs two messages, and both are ordinary
//! community-scoped rows in the room, shared like any other:
//!
//! 1. the **joiner** (the lexicographically greater fed-ID, [`PairRole`])
//!    mints key material and shares its KeyPackage
//!    ([`key_package_attestation`], `chat:key_package:v1`);
//! 2. the **creator** creates the group, admits the joiner from that row, and
//!    shares the Welcome ([`welcome_attestation`], `chat:welcome:v1`);
//! 3. the joiner joins from the Welcome; both derive the same record secret.
//!
//! The KeyPackage's own credential is a fresh MLS signing key; what binds it
//! to the PERSON is the row it rides in, signed by their FedID hybrid key and
//! admitted at the put door against their directory record. No side channel,
//! no extra plane, and the audience gate serves each row to exactly the other
//! member's nodes.
//!
//! # Who signs — the ACTOR, at write, with the full hybrid key
//!
//! The SENDER of a message is the person (or agent) whose words they are, and
//! that is who attests and signs it — `attesting_key_id` is the author's own
//! key, signed at the moment it is written (sign-at-write — CIRISPersist
//! FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE §5.4, answered by edge), with
//! the FULL Ed25519 + ML-DSA-65 keypair, no fallback. The node is CUSTODY: it
//! stores the row, co-scrubs it when it enters the mesh, and dials on the
//! author's behalf — never the sender, because a node-only key cannot carry
//! agency (CC 4.4 two granters, `check_node_agency_admission`).
//!
//! Under persist ≤ v38 this was impossible: the one promotion primitive
//! re-signed every row with the node's key, so the node had to attest and the
//! author rode inside the envelope as `on_behalf_of_key_id`. Persist v39.0.0
//! split promotion into `enter_mesh` (same bytes, actor's signature kept) and
//! `widen_audience` (a `supersedes` the actor signs), and this producer moved
//! to the design.
//!
//! **Attribution is the attester, never a claim** (CIRISEdge#564).
//! `on_behalf_of_key_id` is signed BY the attester, so it proves authorship of
//! the string and nothing more; preferring it let any room member render text
//! under any key. [`ChatMessage::from_row`] attributes to the attester and
//! surfaces the raw claim separately, and only [`messages_in_room`] promotes
//! it — after checking a live owner binding backs it.
//!
//! # Placement: authored `self`, shared to `community` — TWO rows
//!
//! A row is authored `tier: local`, `cohort_scope: self` and shared to the
//! room with [`share`](crate::replication::attestation_bind::share). That is
//! two operations, and after it there are two rows: the original, now
//! `(federation, self)` — replicated to the author's own devices and never
//! advertised (CC 5.2) — and a `supersedes` at `community`, the row the other
//! person receives. The readers here fold them so a room reads as one row per
//! thing said. **Never `federation`.** That tier is PUBLIC (lightnet) data.
//!
//! # Wire compatibility
//!
//! Every constant here is the wire contract, and edge is upstream of
//! CIRISServer, so the values are stated here rather than imported. The room
//! member is `community_key_id` (persist's canonical cohort-target alias —
//! its widening carries the placement under that name), the attester is the
//! author, and the body is sealed. `tests/chat_message_federates.rs` pins
//! the shape.

use ciris_persist::federation::Attestation;
use sha2::{Digest as _, Sha256};

/// The `scores` dimension every chat message carries.
///
/// Versioned because persist's `require_version_segment` demands a `:vN`
/// segment on every `scores` dimension, and `chat:`-prefixed because that
/// prefix is NOT reserved by `default_reserved_prefix_rules` — an ordinary
/// `user` identity may emit it.
pub const CHAT_MESSAGE_DIMENSION: &str = "chat:message:v1";
/// The joiner's MLS KeyPackage for a room — step 1 of the handshake.
pub const KEY_PACKAGE_DIMENSION: &str = "chat:key_package:v1";
/// The creator's MLS Welcome for the joiner — step 2 of the handshake.
pub const WELCOME_DIMENSION: &str = "chat:welcome:v1";

/// The replication-consent prefix a grant MUST cover for chat to federate.
///
/// Omit it and messages are authored, admitted locally, and never offered to
/// the contact — the plane is consent-gated at the recipient, so a missing
/// prefix is silent.
pub const CHAT_ATTESTATION_PREFIX: &str = "chat:";

/// The derived-id prefix for a two-party chat community.
pub const PAIR_COMMUNITY_PREFIX: &str = "chat:pair:v1:";

/// Envelope member naming the community a row belongs to — persist's
/// canonical cohort-target alias, so the author's row and the `supersedes`
/// persist's widening writes name the room by the same member.
pub const FIELD_COMMUNITY_ID: &str = "community_key_id";
/// **Pre-v39 attribution member — an UNAUTHENTICATED claim.** Read, never
/// written: under persist ≤ v38 the node attested and the author rode here.
///
/// It sits inside the attester's own signed envelope, so the signature proves
/// only that *the attester wrote this string* — never that the named key
/// authored anything. Treating it as authorship let any room member render
/// text under any key (CIRISEdge#564). It is surfaced as
/// [`ChatMessage::on_behalf_of_claim`] and promoted to
/// [`ChatMessage::author_key_id`] ONLY by [`messages_in_room`], and only when
/// a live owner binding proves `owner_of(attester) == claim` — which a node
/// can satisfy for its own owner and for nobody else.
pub const FIELD_ON_BEHALF_OF: &str = "on_behalf_of_key_id";
/// The PLAINTEXT's content type, stated beside the ciphertext.
pub const FIELD_CONTENT_TYPE: &str = "content_type";
/// CIRISEdge#586 — the blob pointer that REPLACES [`FIELD_BODY`] +
/// [`FIELD_SEALED`] once a room's content lives in the group's blob store.
///
/// A row carries one shape or the other, never both. The reader recognises
/// whichever it finds, which is what makes the migration reversible up to
/// the point content is actually backfilled (`FSD/GROUP_CONTENT_ON_BLOBS.md`
/// §8).
pub const FIELD_CONTENT: &str = "content";
/// The MLS handshake payload on a KeyPackage / Welcome row: base64 bytes.
pub const FIELD_MLS_BYTES: &str = "mls_bytes";
/// On a Welcome row: the group epoch the Welcome joins the joiner at.
pub const FIELD_MLS_EPOCH: &str = "mls_epoch";

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

/// **The two-person room, as a record — both people founders, and therefore
/// both moderators.**
///
/// CC 4.5.4 / §11.11: no unmoderated federated space. Persist refuses to
/// federate any content keyed on a community that has no live named
/// moderator, and a named moderator exists iff the community has a
/// steward-bound AUTHORITY root — a `founder`, or under any protocol but
/// `founder_only`, any member. A pair room is two equals, so both are named
/// `founder` outright: each is an authority root and a zero-hop moderator
/// **by construction of the record**, not by the accident of a protocol
/// setting. `unanimous` is kept so that nothing decides without both.
///
/// Everything that opens a pair room — the mesh harness, the tests, a
/// consumer — builds it here, so the roster shape cannot drift between them.
/// Sign it with [`signed_pair_community`].
#[must_use]
pub fn pair_community(
    a: &str,
    b: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::types::Community {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::{consensus_protocol, Community, CommunityMember};
    let mut members = [a, b];
    members.sort_unstable();
    Community {
        community_key_id: pair_community_key_id(a, b),
        community_name: format!("{} <-> {}", members[0], members[1]),
        members: members
            .iter()
            .map(|k| CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: founded_at,
                role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at,
        consensus_protocol: consensus_protocol::UNANIMOUS.to_owned(),
        policy_blob: None,
        persist_row_hash: String::new(),
    }
}

/// [`pair_community`], hybrid-signed by `authority` — the key that vouches
/// for the record (the node that opens the room, in the harness). Both ends
/// author the same derived row; the second `put_community` is a `Conflict`,
/// which is the same room either way.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn signed_pair_community(
    a: &str,
    b: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<ciris_persist::federation::types::SignedCommunity, String> {
    let community = pair_community(a, b, founded_at);
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
        .map_err(|e| format!("canonicalize room: {e}"))?;
    let (scrub_signature_classical, scrub_signature_pqc) =
        crate::identity::sign_bound_hybrid(authority, &canonical, "pair community").await?;
    Ok(ciris_persist::federation::types::SignedCommunity {
        community,
        authority_key_id: authority.key_id.clone(),
        scrub_signature_classical,
        scrub_signature_pqc,
    })
}

/// Which side of the MLS handshake a person is in a pair room — decided
/// from the two fed-IDs alone, like the room id, so neither has to be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRole {
    /// The lexicographically smaller fed-ID: creates the group, admits the
    /// joiner from their KeyPackage row, shares the Welcome.
    Creator,
    /// The other: mints key material, shares a KeyPackage, joins from the
    /// Welcome.
    Joiner,
}

impl PairRole {
    /// `me`'s role in the room with `peer`.
    #[must_use]
    pub fn of(me: &str, peer: &str) -> Self {
        if me < peer {
            PairRole::Creator
        } else {
            PairRole::Joiner
        }
    }
}

/// **The room's key** — the MLS group's record secret at an epoch.
///
/// Obtained from a live [`CohortGroup`](crate::mls::CohortGroup) with
/// [`RoomKey::of`]; every message sealed under it names the epoch, so a
/// message from before a rotation is refused rather than mis-opened.
/// Zeroed on drop; never printed.
#[derive(Clone)]
pub struct RoomKey {
    secret: [u8; 32],
    epoch: u64,
}

impl std::fmt::Debug for RoomKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomKey")
            .field("epoch", &self.epoch)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for RoomKey {
    fn drop(&mut self) {
        // Safe scrub (this crate denies `unsafe`): zero, then pin the write
        // with `black_box` so the optimizer keeps it.
        for b in &mut self.secret {
            *b = 0;
        }
        std::hint::black_box(&self.secret);
    }
}

impl RoomKey {
    /// The record secret of a live group, at its current epoch.
    ///
    /// # Errors
    /// The group cannot export (not active, or the exporter failed).
    pub async fn of(group: &crate::mls::CohortGroup) -> Result<Self, String> {
        let secret = group
            .record_secret()
            .await
            .map_err(|e| format!("record_secret: {e}"))?;
        Ok(Self {
            secret: *secret.as_bytes(),
            epoch: group.epoch().await,
        })
    }

    /// A key from its parts — for a consumer that already holds the MLS
    /// exporter (a server whose group lives elsewhere), and for tests.
    #[must_use]
    pub fn from_parts(secret: [u8; 32], epoch: u64) -> Self {
        Self { secret, epoch }
    }

    /// The MLS epoch this key belongs to.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// The ONE producer every chat row goes through: authored `tier: local` /
/// `cohort_scope: self` by `author`, bound (canonical instant + row mirror),
/// hybrid-signed at write. `members` is the row's own payload, on top of the
/// dimension, the room and the `score` a `scores` row carries.
async fn chat_row(
    author: &crate::identity::LocalSigner,
    room: &str,
    dimension: &str,
    members: serde_json::Map<String, serde_json::Value>,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let mut envelope = serde_json::json!({
        "dimension": dimension,
        FIELD_COMMUNITY_ID: room,
        // A `scores` row carries a score; the magnitude is not load-bearing
        // for chat, and a positive constant is the honest "this was said".
        "score": 1.0,
    });
    for (k, v) in members {
        envelope[k] = v;
    }
    // Deterministic per (dimension, room, author, instant, payload) so a retry
    // is idempotent rather than a second row.
    let attestation_id = {
        let mut h = Sha256::new();
        h.update(dimension.as_bytes());
        h.update(room.as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(
            ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
                .map_err(|e| format!("canonicalize: {e}"))?,
        );
        format!("chat-{}", hex::encode(h.finalize())[..32].to_owned())
    };
    // PRODUCER-ONLY at both. A `community` placement is a producer's
    // self-declaration about its OWN content's visibility, so the door
    // refuses a row naming any other party (CIRISPersist#592 / AV-84). The
    // recipient is NOT named on the row: addressing is the derived room.
    let subjects = vec![author_key_id.to_owned()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: ciris_persist::federation::types::cohort_scope::SELF,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(author, &canonical, dimension).await?;
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
        // LOCAL tier: tier is REPLICABILITY, cohort_scope is VISIBILITY. The
        // share is what enters the mesh and widens to the room.
        tier: ciris_persist::federation::types::attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

pub async fn chat_message_attestation(
    author: &crate::identity::LocalSigner,
    recipient_key_id: &str,
    body: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    store: &dyn crate::group_content::GroupContentStore,
) -> Result<(Attestation, crate::group_content::SealedContent), String> {
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;
    let room = pair_community_key_id(&author.key_id, recipient_key_id);

    // One truncation, feeding both the row's column and the AAD. Deriving
    // them separately is how they drift.
    let at = truncate_to_substrate_resolution(asserted_at);

    let sealed = store
        .seal(crate::group_content::SealRequest {
            cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY,
            community_key_id: Some(&room),
            author_key_id: &author.key_id,
            asserted_at: at,
            field: crate::group_content::ContentField::Body,
            plaintext: body.as_bytes(),
            media_type: Some("text/plain"),
        })
        .await
        .map_err(|e| format!("seal chat content: {e}"))?;

    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_CONTENT.to_owned(),
        serde_json::to_value(&sealed.pointer).map_err(|e| format!("pointer: {e}"))?,
    );
    members.insert(
        FIELD_CONTENT_TYPE.to_owned(),
        serde_json::json!("text/plain"),
    );

    let row = chat_row(author, &room, CHAT_MESSAGE_DIMENSION, members, at).await?;
    // `sealed` is returned rather than dropped so the caller can see
    // `excluded` — who, of this room, cannot read what was just written.
    // persist: "a caller that ignores this is ignoring who cannot read what
    // it just wrote."
    Ok((row, sealed))
}

/// Step 1 of the handshake: the JOINER's KeyPackage for the room, as a row
/// the joiner signs. `key_package` is the wire form
/// ([`key_package_to_bytes`](crate::mls::cohort_group::key_package_to_bytes)).
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn key_package_attestation(
    author: &crate::identity::LocalSigner,
    recipient_key_id: &str,
    key_package: &[u8],
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use base64::Engine as _;
    let room = pair_community_key_id(&author.key_id, recipient_key_id);
    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_MLS_BYTES.to_owned(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(key_package)),
    );
    chat_row(author, &room, KEY_PACKAGE_DIMENSION, members, asserted_at).await
}

/// Step 2 of the handshake: the CREATOR's Welcome for the joiner, as a row
/// the creator signs. The Welcome is HPKE-sealed to the joiner's KeyPackage
/// by MLS itself; the row only carries it.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn welcome_attestation(
    author: &crate::identity::LocalSigner,
    recipient_key_id: &str,
    welcome: &[u8],
    epoch: u64,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use base64::Engine as _;
    let room = pair_community_key_id(&author.key_id, recipient_key_id);
    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_MLS_BYTES.to_owned(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(welcome)),
    );
    members.insert(FIELD_MLS_EPOCH.to_owned(), serde_json::json!(epoch));
    chat_row(author, &room, WELCOME_DIMENSION, members, asserted_at).await
}

/// The room a stored row names, through persist's cohort-target resolver
/// (every alias; a split-brain row naming two is `None`).
fn room_of(a: &Attestation) -> Option<String> {
    ciris_persist::federation::admission::envelope_cohort_target(&a.attestation_envelope)
        .ok()
        .flatten()
        .map(str::to_owned)
}

fn dimension_of(a: &Attestation) -> Option<&str> {
    a.attestation_envelope
        .get(ciris_persist::federation::envelope::paths::DIMENSION)
        .and_then(serde_json::Value::as_str)
}

/// Every row `participants` placed in `room`, FOLDED: a `supersedes` IS the
/// claim at the wider audience (CC 4.4.3.3.1), so when both the author's
/// `self` row and its `community` widening are present (on the author's own
/// devices) the prior is dropped and the widening stands. A peer holds only
/// the widening.
/// Every chat-plane row in `room` from `participants`, unopened.
///
/// Public because a caller often wants to know a row ARRIVED without paying
/// to open its content — a convergence poll asks "has the widening landed",
/// which is a question about the row and not about the body.
///
/// # Errors
/// A directory read failure.
pub async fn rows_in_room(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    participants: &[String],
    room: &str,
) -> Result<Vec<Attestation>, String> {
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
    let mut out: Vec<Attestation> = rows
        .into_iter()
        .filter(|a| !superseded.contains(&a.attestation_id))
        .filter(|a| room_of(a).as_deref() == Some(room))
        .collect();
    out.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    out.dedup_by(|a, b| a.attestation_id == b.attestation_id);
    Ok(out)
}

/// Read a room's messages, oldest first, one per thing said, OPENED with the
/// room's key. A row that will not open is reported as
/// [`Body::Unopened`] with the reason, never dropped and never returned as
/// ciphertext pretending to be text.
///
/// `participants` are the KEYS that speak in the room — the humans (or
/// agents) who author messages. Rows are listed BY issuer because a chat row
/// names no recipient.
///
/// # Attribution (CIRISEdge#564)
///
/// [`ChatMessage::author_key_id`] is the ATTESTER. A pre-v39 row's
/// `on_behalf_of_key_id` is promoted to the author **only** when this
/// directory holds a live owner binding making the claimed key the attester's
/// owner (`owner_of(attester) == claim`) — the legitimate "a node speaks for
/// its owner" case, which a node can satisfy for its own owner and for nobody
/// else. An unbacked claim stays in [`ChatMessage::on_behalf_of_claim`] and
/// changes nothing. Fail-closed: an unresolvable or ambiguous owner promotes
/// nothing.
///
/// # Errors
/// A directory read failure.
pub async fn messages_in_room(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    participants: &[String],
    room: &str,
    store: &dyn crate::group_content::GroupContentStore,
    viewer_key_id: &str,
) -> Result<Vec<ChatMessage>, String> {
    let mut out: Vec<ChatMessage> = rows_in_room(directory, participants, room)
        .await?
        .iter()
        .filter(|a| dimension_of(a) == Some(CHAT_MESSAGE_DIMENSION))
        .filter_map(|a| ChatMessage::from_row(a, room))
        .collect();
    // Corroborate the pre-v39 claims, one owner walk per distinct attester.
    let mut owner_of: std::collections::BTreeMap<String, Option<String>> =
        std::collections::BTreeMap::new();
    for m in &mut out {
        let Some(claim) = m.on_behalf_of_claim.clone() else {
            continue;
        };
        if !owner_of.contains_key(&m.attesting_key_id) {
            let resolved =
                ciris_persist::federation::admission::owner_of(directory, &m.attesting_key_id)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::debug!(
                            attester = %m.attesting_key_id,
                            error = %e,
                            "owner_of unresolved — an on_behalf_of claim stays unpromoted \
                             (CIRISEdge#564 fail-closed)"
                        );
                        None
                    });
            owner_of.insert(m.attesting_key_id.clone(), resolved);
        }
        if owner_of.get(&m.attesting_key_id).and_then(Clone::clone) == Some(claim.clone()) {
            // The attester IS a node whose owner is the claimed key: the
            // legitimate pre-v39 shape, and unforgeable — a node cannot name
            // anyone but its own owner and have this hold.
            m.author_key_id = claim;
        } else {
            tracing::debug!(
                attester = %m.attesting_key_id,
                claimed = %claim,
                "on_behalf_of claim NOT backed by an owner binding — attributing to \
                 the attester (CIRISEdge#564)"
            );
        }
    }

    // CIRISEdge#586 — resolve every pointer to its content.
    //
    // Sequential rather than concurrent, deliberately: each open is a local
    // substrate read plus a decrypt, and a room's worth of them fanned out
    // would put a burst on the blocking pool that the thread budget
    // (CIRISEdge#583) exists to keep bounded. A failure never fails the
    // room — it becomes `Body::Unopened` carrying its reason, because one
    // unreadable message must not cost a reader every other one.
    for m in &mut out {
        m.resolve_content(store, viewer_key_id).await;
    }

    Ok(out)
}

/// The KeyPackage `from` shared in `room`, if it has arrived — step 1 of the
/// handshake, as the creator reads it.
///
/// # Errors
/// A directory read failure.
pub async fn key_package_from(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
) -> Result<Option<Vec<u8>>, String> {
    use base64::Engine as _;
    Ok(rows_in_room(directory, &[from.to_owned()], room)
        .await?
        .iter()
        .filter(|a| dimension_of(a) == Some(KEY_PACKAGE_DIMENSION))
        .filter_map(|a| {
            a.attestation_envelope
                .get(FIELD_MLS_BYTES)
                .and_then(serde_json::Value::as_str)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        })
        .next_back())
}

/// The Welcome `from` shared in `room`, with its epoch, if it has arrived —
/// step 2 of the handshake, as the joiner reads it.
///
/// # Errors
/// A directory read failure.
pub async fn welcome_from(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    use base64::Engine as _;
    Ok(rows_in_room(directory, &[from.to_owned()], room)
        .await?
        .iter()
        .filter(|a| dimension_of(a) == Some(WELCOME_DIMENSION))
        .filter_map(|a| {
            let env = &a.attestation_envelope;
            let bytes = env
                .get(FIELD_MLS_BYTES)
                .and_then(serde_json::Value::as_str)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())?;
            let epoch = env
                .get(FIELD_MLS_EPOCH)
                .and_then(serde_json::Value::as_u64)?;
            Some((bytes, epoch))
        })
        .next_back())
}

/// A message body as read back: opened text, or why it did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Opened — from the inline seal, or from the group's blob store.
    Text(String),
    /// CIRISEdge#586 — the row points at group-store content that has not
    /// been fetched yet.
    ///
    /// Reading a blob is async and may touch the network; recognising the
    /// row is neither. Keeping them apart is what lets [`ChatMessage::from_row`]
    /// stay synchronous and total — a caller that only wants to list a room
    /// never pays for content it is not going to show, and a caller that
    /// does calls [`ChatMessage::resolve_content`].
    Pointer(crate::group_content::BlobPointer),
    /// Sealed, and this key does not open it (rotated epoch, foreign
    /// algorithm, tampered, or not a member's key) — or not sealed at all,
    /// which a community row must never be.
    Unopened { reason: String },
}

/// One message, as read back off the plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// The row's id — the widening's, on a peer. A value the receiver cannot
    /// manufacture, which is what makes "it arrived" checkable.
    pub attestation_id: String,
    /// **Whose words, established cryptographically.** The attester — the key
    /// whose hybrid signature persist verified against its registered
    /// pubkeys — unless [`messages_in_room`] promoted a
    /// [`Self::on_behalf_of_claim`] that a live owner binding backs.
    ///
    /// Never taken from an envelope member on its own (CIRISEdge#564): a
    /// producer-asserted field is signed by its asserter, which proves
    /// authorship of the *string*, not of the message.
    pub author_key_id: String,
    /// Who attested and signed the row. Equal to [`Self::author_key_id`] for
    /// every row edge produces from v19.0.0 on, where the human signs.
    pub attesting_key_id: String,
    /// The row's raw `on_behalf_of_key_id`, if it carries one — an
    /// **UNVERIFIED claim by the attester**. Never render it as authorship;
    /// it is here so a caller can see what was claimed and, if it wants,
    /// corroborate it the way [`messages_in_room`] does.
    pub on_behalf_of_claim: Option<String>,
    /// The body, opened — or the reason it did not open.
    pub body: Body,
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// The `self` row this widening supersedes, when it is one. Present on
    /// every row a peer receives; absent on the author's own `self` copy.
    pub widens: Option<String>,
}

impl ChatMessage {
    /// Recognise a chat row in `room`, or `None` if the row is not a chat
    /// message there.
    ///
    /// **Takes no room key.** Content lives in the group's blob store, so
    /// recognising a row needs no key and touches no store — a caller
    /// listing a room never pays for content it is not going to show.
    /// [`Self::resolve_content`] fetches it when the caller wants the text.
    ///
    /// Every failure past the dimension-and-room check becomes
    /// [`Body::Unopened`] with a reason rather than `None`: by that point
    /// the row IS a chat message, and dropping it would delete a message
    /// from a room with no record anywhere of why.
    #[must_use]
    pub fn from_row(a: &Attestation, room: &str) -> Option<Self> {
        if dimension_of(a) != Some(CHAT_MESSAGE_DIMENSION) || room_of(a).as_deref() != Some(room) {
            return None;
        }
        let env = &a.attestation_envelope;

        let Some(raw) = env.get(FIELD_CONTENT) else {
            return Some(Self::from_parts(
                a,
                env,
                Body::Unopened {
                    reason: "row carries no `content` pointer — chat content lives in \
                             the group's blob store (CIRISEdge#586)"
                        .to_owned(),
                },
            ));
        };
        let body = match serde_json::from_value::<crate::group_content::BlobPointer>(raw.clone()) {
            Ok(pointer) => Body::Pointer(pointer),
            Err(e) => Body::Unopened {
                reason: format!("row carries an unreadable `content` pointer: {e}"),
            },
        };
        Some(Self::from_parts(a, env, body))
    }

    /// The members both row shapes share. Factored so the inline path and
    /// the blob path cannot drift on attribution — which is the one field
    /// here that has already been got wrong once (CIRISEdge#564).
    fn from_parts(a: &Attestation, env: &serde_json::Value, body: Body) -> Self {
        use ciris_persist::federation::envelope::paths;
        Self {
            attestation_id: a.attestation_id.clone(),
            // CIRISEdge#564 — the ATTESTER, always. persist established this
            // key by verifying the hybrid signature against its registered
            // pubkeys; the envelope's `on_behalf_of_key_id` established
            // nothing, so it cannot outrank it. `messages_in_room` may
            // promote a claim the owner binding actually backs.
            author_key_id: a.attesting_key_id.clone(),
            attesting_key_id: a.attesting_key_id.clone(),
            on_behalf_of_claim: env
                .get(FIELD_ON_BEHALF_OF)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            body,
            asserted_at: a.asserted_at,
            widens: env
                .get(paths::REFERENCES_ATTESTATION_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        }
    }

    /// CIRISEdge#586 — fetch and open the content a [`Body::Pointer`] names.
    ///
    /// A no-op on any other body, so a caller can hand it every message in a
    /// room without first sorting them by shape.
    ///
    /// **The binding inputs come off THIS row**, never from the caller: the
    /// attester and the row's own instant. That is the symmetry the whole
    /// contract rests on — a reader that can rebuild those two values from
    /// the row gets the content, and one that cannot is not going to be
    /// rescued by holding a key.
    ///
    /// `viewer_key_id` is the reader's **occurrence** key id, not their
    /// identity key id — see
    /// [`OpenRequest::viewer_key_id`](crate::group_content::OpenRequest).
    /// An identity key produces a `NotGranted` that reads like a
    /// permissions failure and is really a wrong-handle one.
    ///
    /// # Errors
    /// Never — a failure to open becomes [`Body::Unopened`] with the reason,
    /// because one unreadable message must not fail a room's whole read.
    pub async fn resolve_content(
        &mut self,
        store: &dyn crate::group_content::GroupContentStore,
        viewer_key_id: &str,
    ) {
        let Body::Pointer(pointer) = &self.body else {
            return;
        };
        let req = crate::group_content::OpenRequest {
            pointer,
            author_key_id: &self.attesting_key_id,
            asserted_at: self.asserted_at,
            viewer_key_id,
        };
        self.body = match store.open(req).await {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Body::Text(text),
                Err(e) => Body::Unopened {
                    reason: format!("content is not UTF-8: {e}"),
                },
            },
            Err(e) => Body::Unopened {
                reason: e.to_string(),
            },
        };
    }
}
