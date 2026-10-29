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
//! # Community tier is ENCRYPTED — the body is a blob under the room's DEK
//!
//! A `community` placement is cohort-filtered visibility, and its bytes are
//! encrypted at rest (CC 4.4.3.2.1). For chat that is not a substrate promise
//! about storage; it is the message. The body of every message is written to
//! the room's encrypted blob store ([`chat_message_attestation`] →
//! [`GroupContentStore`](crate::group_content::GroupContentStore)) and the
//! row carries only a [`BlobPointer`](crate::group_content::BlobPointer). The
//! key is persist's **community DEK** — minted per `(community, minter,
//! epoch)`, wrapped per active identity occurrence of each roster member
//! (X25519 + ML-KEM-768 hybrid, CIRISPersist#848), and rotated by the
//! substrate when a member is revoked. The AAD binds the domain, the author,
//! the claim's signed instant and the field, so a ciphertext lifted onto any
//! other row does not open. What crosses the wire, and what the relay and
//! every node that is not a member holds, is ciphertext inside a signed
//! envelope. There is no plaintext producer, and there is no second seal:
//! the pre-v24 `RoomKey` (the group's exporter, HKDF'd per message) is
//! deleted (CIRISEdge#604, v25.0.0). `FSD/GROUP_CONTENT_ON_BLOBS.md` §2.1
//! says which layer answers which clause.
//!
//! # The MLS handshake rides the room — the room's ADDRESSING root
//!
//! Every room still has an MLS group between its people (ciphersuite
//! `0x004D`, X-Wing), and the handshake that builds it is two ordinary
//! community-scoped rows in the room, shared like any other:
//!
//! 1. the **joiner** (the lexicographically greater fed-ID, [`PairRole`])
//!    mints key material and shares its KeyPackage
//!    ([`key_package_attestation`], `chat:key_package:v1`);
//! 2. the **creator** creates the group, admits the joiner from that row, and
//!    shares the Welcome ([`welcome_attestation`], `chat:welcome:v1`);
//! 3. the joiner joins from the Welcome; both stand on the same group at the
//!    same epoch.
//!
//! The group does NOT key the body (above). It is the room's **CC 5.4
//! addressing root**: `K_record_id` and `K_symbol` are HKDF-Expand over the
//! group's raw `exporter_secret` (CC 5.4.1, byte-pinned in
//! [`scope_privacy`](crate::scope_privacy)), they rebind on every Add/Remove
//! (CC 5.4.3), and a below-federation destination never announces — members
//! resolve it from a cached directory entry plus that group-and-epoch-bound
//! schedule (CC 5.4.6). [`cohort_addressing::snapshot`](crate::cohort_addressing::snapshot)
//! is that derivation over a room's [`CohortGroup`](crate::mls::CohortGroup),
//! and the Welcome wrap is the CC 5.4.4 shape
//! ([`mls::welcome_wrap`](crate::mls::welcome_wrap)). The KeyPackage's own
//! credential is a fresh MLS signing key; what binds it to the PERSON is the
//! row it rides in, signed by their FedID hybrid key and admitted at the put
//! door against their directory record. No side channel, no extra plane, and
//! the audience gate serves each row to exactly the other member's nodes.
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

/// A room's MLS **Commit** as a signed community row (CIRISEdge#604).
///
/// Until v25.1.0 no commit ever crossed the mesh for a chat room: the
/// KeyPackage/Welcome handshake rode the plane and every later commit
/// (a rotate, an Add, a Remove) stayed on the node that made it, so the
/// fork #604 names could not even be reached — the other node simply
/// never heard. This dimension carries the commit, and the row's
/// `asserted_at` + `attesting_key_id` ARE the [`crate::mls::CommitClaim`]
/// the receiver contests it on: bound into the signed bytes, so every
/// peer adjudicates the same tuple.
pub const COMMIT_DIMENSION: &str = "chat:commit:v1";

/// CIRISEdge#805 item 6 — **a call is a CEG attestation whose data subjects
/// are its attendees** (CIRISPersist#1095: the final name; `chat:*` is an
/// open family in persist's vendored registry, so v57 admits it by pattern).
///
/// One row PER ATTENDEE: on joining, an attendee writes its OWN row, naming
/// the call ([`FIELD_CALL_ID`]) and the room, with itself as attester and as
/// the only subject (CC 2.4.1: a `supersedes` replaces only its own
/// attester's row, so nobody rewrites another's). The attendee set is the
/// UNION of the subjects over every row of the call, so concurrent joins are
/// two rows, never a fork, and a leaver's row stands: it attended. Leaving
/// writes nothing; erasure is the attendee withdrawing its OWN row (CC 1c),
/// through the existing withdraws door.
pub const CALL_DIMENSION: &str = "chat:call:v1";

/// The call row member naming the call: the lowercase hex of its `CallId`.
pub const FIELD_CALL_ID: &str = "call_id";

/// The replication-consent prefix a grant MUST cover for chat to federate.
///
/// Omit it and messages are authored, admitted locally, and never offered to
/// the contact — the plane is consent-gated at the recipient, so a missing
/// prefix is silent.
pub const CHAT_ATTESTATION_PREFIX: &str = "chat:";

/// The derived-id prefix for a two-party chat community.
pub const PAIR_COMMUNITY_PREFIX: &str = "chat:pair:v1:";
/// The allocated-id prefix for an N-member chat room (CIRISEdge#608).
///
/// A pair room's id is a FUNCTION of its two members, so both ends derive it
/// having exchanged nothing. An N-member room has no such function — its
/// roster is whatever its creator declared, and two creators declaring the
/// same three people are two rooms, not one — so its id is ALLOCATED at
/// creation ([`new_room_community_key_id`]) and the signed `Community` record
/// is the only source of truth for who is in it.
pub const ROOM_COMMUNITY_PREFIX: &str = "chat:room:v1:";

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
/// Crate-private since v25.0.0 (CIRISEdge#604): the member is wire contract
/// for the two handshake rows, read and written only by the producers and
/// readers below; nothing outside this module has a reason to name it.
const FIELD_MLS_BYTES: &str = "mls_bytes";
/// On a Welcome row: the group epoch the Welcome joins the joiner at.
/// Crate-private, as above.
const FIELD_MLS_EPOCH: &str = "mls_epoch";
/// The envelope member that names a handshake row's room, by kind
/// (CIRISEdge#657 review).
///
/// `chat_row` wrote `community_key_id` for every room, which is right for a
/// community and **wrong for a family**: persist's widen door and write gate
/// read a family placement through `family_key_id`
/// ([`ScopeRoom::cohort_target_field`]), so a family handshake widened to
/// `With::MyFamily` would carry the id under a member the family arm does not
/// write — two spellings of the same fact, which is the failure `ScopeRoom`
/// exists to end.
///
/// A **self** room takes `community_key_id` deliberately: the four aliases
/// `admission::envelope_cohort_target` accepts have no self member, and a
/// handshake row carries no pointer to name the owner the way a file row
/// does — so the row must name its room through an alias the reader reads,
/// or `rows_in_room` cannot find it at all (which is CIRISEdge#656's
/// symptom by another route).
fn room_member_for(room: &crate::scope_room::ScopeRoom) -> &'static str {
    room.cohort_target_field().unwrap_or(FIELD_COMMUNITY_ID)
}

/// On a Welcome row: **whom** the Welcome is for (CIRISEdge#656).
///
/// A pair room needed no such member — the room id WAS the pair, so "which
/// room" and "for whom" were one fact. A room with more than two members
/// (a self collective of three devices, a family) breaks that: the creator
/// places one Welcome per joiner into the SAME room, and a joiner must be
/// able to tell which one is theirs. Crate-private, like its siblings.
const FIELD_MLS_FOR: &str = "mls_for_key_id";

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

/// **A fresh id for an N-member room** — `chat:room:v1:<uuid>`, lowercase, so
/// it satisfies the same canonical-id rule every other key id does (CC 2.6.3)
/// and cannot collide with a derived pair id.
#[must_use]
pub fn new_room_community_key_id() -> String {
    format!("{ROOM_COMMUNITY_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

/// The roster shape every community record built here satisfies — spelled
/// once so the general builder and the pair convenience cannot drift.
fn build_community(
    community_key_id: &str,
    community_name: &str,
    members: &[(&str, Option<&str>)],
    consensus_protocol: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::types::Community {
    use ciris_persist::federation::types::{Community, CommunityMember};
    Community {
        community_key_id: community_key_id.to_owned(),
        community_name: community_name.to_owned(),
        members: members
            .iter()
            .map(|(k, role)| CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: founded_at,
                role: role.map(str::to_owned),
            })
            .collect(),
        founded_at,
        consensus_protocol: consensus_protocol.to_owned(),
        policy_blob: None,
        persist_row_hash: String::new(),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
    }
}

/// **An N-member room, as a record** (CIRISEdge#608).
///
/// `members` is the roster in the order given — `(identity key, role)`; the
/// roster names PERSONS (identity keys), never nodes or occurrences, and the
/// DEK cascade resolves each person to their active occurrences at seal time.
/// `joined_at` is `founded_at` for every founding member.
///
/// # What is refused, and why it is refused HERE
///
/// CC 4.5.4 / §11.11: no unmoderated federated space. Persist refuses to
/// federate any content keyed on a community with no live named moderator,
/// and a named moderator exists iff the community's authority set has a
/// steward-bound root. The authority set is every `founder`, plus — under
/// any protocol but `founder_only` — every member. So a roster with no
/// `founder` under `founder_only` is a room whose messages persist will
/// admit locally and never carry, and the failure surfaces as silence at the
/// far end. This builder refuses that roster, and an empty or duplicated
/// one, at construction — where the caller still holds the roster — rather
/// than at some reader's screen.
///
/// Whether the founder is steward-bound (a `user`-role identity, an
/// occurrence of one, or delegated from one) is a directory fact the caller
/// establishes; this builder can only guarantee the roster's shape.
///
/// # Errors
/// An empty roster, a duplicated member, or no `founder`.
pub fn community(
    community_key_id: &str,
    community_name: &str,
    members: &[(&str, Option<&str>)],
    consensus_protocol: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
) -> Result<ciris_persist::federation::types::Community, String> {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    if members.is_empty() {
        return Err(format!(
            "room {community_key_id}: a roster with nobody on it"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for (k, _) in members {
        if !seen.insert(*k) {
            return Err(format!(
                "room {community_key_id}: {k} is on the roster twice"
            ));
        }
    }
    if !members
        .iter()
        .any(|(_, role)| *role == Some(MEMBER_ROLE_FOUNDER))
    {
        return Err(format!(
            "room {community_key_id}: no member is tagged `{MEMBER_ROLE_FOUNDER}` — a room \
             with no founder has no authority root, so it has no named moderator and \
             persist will refuse to federate anything keyed on it (CC 4.5.4)"
        ));
    }
    Ok(build_community(
        community_key_id,
        community_name,
        members,
        consensus_protocol,
        founded_at,
    ))
}

/// **The two-person room's founding record — founded by its opener alone.**
///
/// persist v52.0.0 (CIRISPersist#955, CIRISConstitution#133): *nobody joins a
/// family or community without their own consent*. A founding record admits
/// only the members who signed it, so the record lists the OPENER alone
/// (`founder`); the other person joins by accepting a
/// `membership:proposal:v1` offering them `founder`, and the opener's side
/// then widens the roster ([`open_pair_room`], [`accept_pair_proposal`],
/// [`crate::membership`]). The END STATE is unchanged from the two-founder
/// record this replaced: both people are founders, so both are authority
/// roots and zero-hop moderators (CC 4.5.4 / §11.11), and `unanimous` keeps
/// nothing decided without both once the second founder is in.
///
/// The room id is still derived from the pair ([`pair_community_key_id`]) and
/// the name is still the sorted pair, so the record is a function of (opener,
/// peer, `founded_at`). Two ends that open the same pair CONCURRENTLY author
/// differing records under one id (a `Conflict` at the door); the mesh
/// harness avoids it by letting only the [`PairRole::Creator`] open.
#[must_use]
pub fn pair_community(
    opener: &str,
    peer: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::types::Community {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::consensus_protocol;
    let mut pair = [opener, peer];
    pair.sort_unstable();
    // One founder satisfies `community`'s roster rule by construction, so the
    // validating door is not consulted — the shape IS the rule.
    build_community(
        &pair_community_key_id(opener, peer),
        &format!("{} <-> {}", pair[0], pair[1]),
        &[(opener, Some(MEMBER_ROLE_FOUNDER))],
        consensus_protocol::UNANIMOUS,
        founded_at,
    )
}

/// What [`open_pair_room`] did.
#[derive(Debug, Clone, PartialEq)]
pub struct PairRoomOpened {
    /// The derived room id.
    pub room: String,
    /// `true` when this call authored the founding record; `false` when this
    /// directory already held it (an idempotent re-open).
    pub founded: bool,
    /// The proposal inviting the peer — the one this call stored, or the live
    /// one it found already pending. `None` once the peer is a member.
    pub proposal: Option<Attestation>,
}

/// **Host call: open the pair room with `peer`** (persist v52.0.0,
/// CIRISPersist#955). Founds the room with `opener` alone as `founder`
/// (signed by `authority`, which must act for `opener`), then proposes `peer`
/// at role `founder`, live until `expires_at` (at most 30 days out). The
/// proposal replicates to the peer's nodes; their acceptance replicates back,
/// and the opener's node widens the roster on its arrival when its
/// replication bridge carries a [`crate::membership::MembershipWidener`] for
/// `opener`'s key — no further call on this side.
///
/// Idempotent: a room already held here is not re-founded, and a live
/// proposal already pending for `peer` is returned instead of a second one.
///
/// # Errors
/// The room is held here but `opener` is not its founder (the peer opened it
/// — accept their proposal instead: [`pair_proposal_for`] /
/// [`accept_pair_proposal`]); the founding or proposal refused; a build or
/// signing failure.
pub async fn open_pair_room(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    opener: &str,
    peer: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<PairRoomOpened, String> {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    let room = pair_community_key_id(opener, peer);
    let held = directory
        .lookup_community(&room)
        .await
        .map_err(|e| format!("lookup room {room}: {e}"))?;
    let founded = if let Some(held) = held {
        if !held
            .members
            .iter()
            .any(|m| m.key_id == opener && m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER))
        {
            return Err(format!(
                "room {room} is already held here and {opener} did not found it — the \
                 other side opened it; accept its proposal (chat::pair_proposal_for → \
                 chat::accept_pair_proposal) (CIRISPersist#955)"
            ));
        }
        false
    } else {
        let row = signed_pair_community(opener, peer, founded_at, authority).await?;
        directory
            .put_community(row)
            .await
            .map_err(|e| format!("found room {room}: {e}"))?;
        true
    };
    let active = directory
        .active_community_members(&room)
        .await
        .map_err(|e| format!("read room {room}: {e}"))?;
    if active.iter().any(|m| m.key_id == peer) {
        return Ok(PairRoomOpened {
            room,
            founded,
            proposal: None,
        });
    }
    if let Some(live) = live_proposal_by(directory, &authority.key_id, &room, peer).await? {
        return Ok(PairRoomOpened {
            room,
            founded,
            proposal: Some(live),
        });
    }
    let proposal = crate::membership::propose(
        directory,
        crate::membership::GroupScope::Community,
        &room,
        peer,
        Some(MEMBER_ROLE_FOUNDER),
        expires_at,
        authority,
    )
    .await
    .map_err(|e| format!("propose {peer} into {room}: {e}"))?;
    Ok(PairRoomOpened {
        room,
        founded,
        proposal: Some(proposal),
    })
}

/// Page size of the proposer walk in [`live_proposal_by`]: a proposer's
/// proposals are few, and the walk is a host call.
const PROPOSAL_PAGE: std::num::NonZeroU32 =
    ciris_persist::federation::attestation_query::page_size(64);

/// A live proposal `proposer_key_id` signed inviting `invitee` into `room`
/// that the invitee has not declined, if one is held here.
async fn live_proposal_by(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    proposer_key_id: &str,
    room: &str,
    invitee: &str,
) -> Result<Option<Attestation>, String> {
    use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    let now = chrono::Utc::now();
    let live_here = |p: &Attestation| {
        p.subject_key_ids.first().map(String::as_str) == Some(invitee)
            && p.attestation_envelope
                .get(FIELD_COMMUNITY_ID)
                .and_then(serde_json::Value::as_str)
                == Some(room)
            && p.expires_at.is_some_and(|t| t > now)
    };
    // persist v56 (#1001): the proposer's proposals, newest first. Proposals
    // are attested to their PROPOSER (emit's default), so the invitee is a
    // subject filter here, not `to`. A NotServed page is an Err, never "no
    // live proposal" (which would mint a duplicate).
    let mut live: Vec<Attestation> = Vec::new();
    let mut proposals = AttestationQuery::by(proposer_key_id, PROPOSAL_PAGE)
        .dimension(crate::membership::PROPOSAL_DIMENSION)
        .pages();
    while let Some(page) = proposals
        .next(directory)
        .await
        .map_err(|e| format!("list proposals by {proposer_key_id}: {e}"))?
    {
        live.extend(page.into_iter().filter(|p| live_here(p)));
    }
    // Declines are attested to the invitee who signed them (`to`, as v55's
    // `list_attestations_for`). Every one counts, so the walk runs to the end.
    let mut declined: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut replies = AttestationQuery::to(invitee, FOLD_PAGE)
        .dimension(crate::membership::DECLINE_DIMENSION)
        .pages();
    while let Some(page) = replies
        .next(directory)
        .await
        .map_err(|e| format!("list replies of {invitee}: {e}"))?
    {
        declined.extend(page.into_iter().filter_map(|r| {
            r.attestation_envelope
                .get("references_attestation_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }));
    }
    live.retain(|p| !declined.contains(&p.attestation_id));
    live.sort_by_key(|p| std::cmp::Reverse(p.asserted_at));
    Ok(live.into_iter().next())
}

/// **Host call: the pending proposal inviting `me` into the pair room with
/// `peer`**, if one is held here (the invite inbox, narrowed to one room).
///
/// # Errors
/// A directory read failure.
pub async fn pair_proposal_for(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    me: &str,
    peer: &str,
) -> Result<Option<crate::membership::PendingProposal>, crate::membership::MembershipError> {
    let room = pair_community_key_id(me, peer);
    Ok(crate::membership::pending_proposals_for(directory, me)
        .await?
        .into_iter()
        .find(|p| p.group_key_id == room))
}

/// **Host call: accept a pair-room proposal** — `signer` acts for the
/// invitee (their person key, or a device bound to them). The acceptance
/// replicates back and the opener's node widens the roster; see
/// [`crate::membership::reply`] for the refusals (by rule).
///
/// # Errors
/// [`crate::membership::reply`]'s.
pub async fn accept_pair_proposal(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    proposal_attestation_id: &str,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, crate::membership::MembershipError> {
    crate::membership::reply(directory, proposal_attestation_id, true, signer).await
}

/// **Host call: decline a pair-room proposal.** Final for that proposal: a
/// later widening naming the invitee under it is refused by persist with
/// `membership_declined`.
///
/// # Errors
/// [`crate::membership::reply`]'s.
pub async fn decline_pair_proposal(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    proposal_attestation_id: &str,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, crate::membership::MembershipError> {
    crate::membership::reply(directory, proposal_attestation_id, false, signer).await
}

/// A [`Community`](ciris_persist::federation::types::Community) record,
/// hybrid-signed by `authority` — the key that vouches for it. Persist's
/// `put_community` verifies this signature (hybrid-Strict) against
/// `authority`'s REGISTERED pubkeys over
/// [`Community::signing_envelope`](ciris_persist::federation::types::Community::signing_envelope)
/// before any write, so `authority` must be a registered hybrid key.
///
/// A record admitted once is idempotent on identical bytes and a `Conflict`
/// on differing ones under the same id — a room is created ONCE; later
/// membership changes go through [`crate::community_roster`], not through a
/// second record.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn signed_community(
    community: ciris_persist::federation::types::Community,
    authority: &crate::identity::LocalSigner,
) -> Result<ciris_persist::federation::types::SignedCommunity, String> {
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
        .map_err(|e| format!("canonicalize room: {e}"))?;
    let (scrub_signature_classical, scrub_signature_pqc) =
        crate::identity::sign_bound_hybrid(authority, &canonical, "community").await?;
    Ok(ciris_persist::federation::types::SignedCommunity {
        community,
        authority_key_id: authority.key_id.clone(),
        scrub_signature_classical,
        scrub_signature_pqc,
        supersede_proof: None,
        cosignatures: Vec::new(),
        lineage: Vec::new(),
    })
}

/// [`pair_community`], hybrid-signed by `authority` — the key that vouches
/// for the record, acting for `opener` (the opener's node, in the harness).
/// Only the opener authors it; the peer joins by proposal ([`open_pair_room`]).
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn signed_pair_community(
    opener: &str,
    peer: &str,
    founded_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<ciris_persist::federation::types::SignedCommunity, String> {
    signed_community(pair_community(opener, peer, founded_at), authority).await
}

/// Which side of the MLS handshake a person is in a pair room — decided
/// from the two fed-IDs alone, like the room id, so neither has to be told.
/// The handshake builds the room's group, the CC 5.4 addressing root (module
/// doc); it does not key the body.
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

/// The ONE producer every chat row goes through: authored `tier: local` /
/// `cohort_scope: self` by `author`, bound (canonical instant + row mirror),
/// hybrid-signed at write. `members` is the row's own payload, on top of the
/// dimension, the room and the `score` a `scores` row carries.
/// CIRISEdge#646 — the content sha a typed [`BlobPointer`](crate::group_content::BlobPointer)
/// member cites, if this envelope member IS one. Deliberately structural
/// (deserialize into the type) rather than a `content_sha256` key probe, so a
/// member that merely happens to carry that key is not mistaken for a
/// reference — the same test `BlobMeaning::referenced_shas` applies.
fn pointer_sha(member: &serde_json::Value) -> Option<String> {
    if !member.is_object() {
        return None;
    }
    serde_json::from_value::<crate::group_content::BlobPointer>(member.clone())
        .ok()
        .map(|p| p.content_sha256)
}

/// CIRISEdge#646 — add `sha` to the envelope's `evidence_refs`, creating the
/// array if absent and never duplicating. This is the CEG-native relation
/// between an attestation and a blob (CEG RC27 §11.10); persist's binding
/// predicate reads nothing else.
pub(crate) fn cite_evidence(envelope: &mut serde_json::Value, sha: &str) {
    let refs = envelope
        .as_object_mut()
        .expect("chat envelopes are objects")
        .entry("evidence_refs")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if let Some(arr) = refs.as_array_mut() {
        if !arr.iter().any(|r| r.as_str() == Some(sha)) {
            arr.push(serde_json::Value::String(sha.to_owned()));
        }
    }
}

async fn chat_row_in(
    author: &crate::identity::LocalSigner,
    room: &crate::scope_room::ScopeRoom,
    dimension: &str,
    mut members: serde_json::Map<String, serde_json::Value>,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    let member = room_member_for(room);
    if member != FIELD_COMMUNITY_ID {
        // `chat_row` writes FIELD_COMMUNITY_ID itself; anything else is
        // added here and the id is passed through under it too, so exactly
        // one alias carries the room and none can disagree with another.
        members.insert(
            member.to_owned(),
            serde_json::json!(room.content_group_id()),
        );
        return chat_row_raw(author, None, dimension, members, asserted_at).await;
    }
    chat_row(
        author,
        room.content_group_id(),
        dimension,
        members,
        asserted_at,
    )
    .await
}

async fn chat_row(
    author: &crate::identity::LocalSigner,
    room: &str,
    dimension: &str,
    members: serde_json::Map<String, serde_json::Value>,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    chat_row_raw(author, Some(room), dimension, members, asserted_at).await
}

async fn chat_row_raw(
    author: &crate::identity::LocalSigner,
    room: Option<&str>,
    dimension: &str,
    members: serde_json::Map<String, serde_json::Value>,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    chat_row_shaped(
        author,
        room,
        dimension,
        members,
        asserted_at,
        RowShape::SAID,
    )
    .await
}

/// What kind of row a chat producer writes, and at which audience.
#[derive(Clone, Copy)]
struct RowShape {
    attestation_type: &'static str,
    cohort_scope: &'static str,
    tier: &'static str,
}

impl RowShape {
    /// A thing said: a `scores` row at `self`, shared to the room by a
    /// widening.
    const SAID: Self = Self {
        attestation_type: ciris_persist::federation::types::attestation_type::SCORES,
        cohort_scope: ciris_persist::federation::types::cohort_scope::SELF,
        tier: ciris_persist::federation::types::attestation_tier::LOCAL,
    };

    /// A composer over a message already in the room, born AT the room and
    /// at federation tier (CIRISPersist#1155). Born `self`, it would reach the
    /// room only through a widening, and a widening is a `supersedes` OF the
    /// composer: its own type and target would reach nobody else.
    const fn composer(attestation_type: &'static str) -> Self {
        Self {
            attestation_type,
            cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY,
            tier: ciris_persist::federation::types::attestation_tier::FEDERATION,
        }
    }
}

async fn chat_row_shaped(
    author: &crate::identity::LocalSigner,
    room: Option<&str>,
    dimension: &str,
    members: serde_json::Map<String, serde_json::Value>,
    asserted_at: chrono::DateTime<chrono::Utc>,
    shape: RowShape,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let mut envelope = serde_json::json!({ "dimension": dimension });
    if shape.attestation_type == ciris_persist::federation::types::attestation_type::SCORES {
        // A `scores` row carries a score; the magnitude is not load-bearing
        // for chat, and a positive constant is the honest "this was said".
        envelope["score"] = serde_json::json!(1.0);
    }
    if let Some(room) = room {
        // Inserted rather than written as `Option`, so an absent room leaves
        // the member OUT — `serde_json` would have serialized `None` as an
        // explicit null, which `envelope_cohort_target` reads as a present
        // alias and refuses against the one that carries the id.
        envelope[FIELD_COMMUNITY_ID] = serde_json::json!(room);
    }
    // CIRISEdge#646 — **a blob is cited the blob-native way, always.** A typed
    // `BlobPointer` carries the key-plane facts needed to OPEN the bytes (tier,
    // epoch, community, field); `evidence_refs` is the RELATION persist indexes
    // and every consumer reads: `attestations_binding_content`,
    // `envelope_binds_content`, `BlobProvenance::from_attestation`, and the
    // revocation register's "every known reference" set. A pointer-only row is
    // invisible to all of them — `blob_swarm::revocation`'s own module docs
    // named this residual and its closure ("producers carry the sha in
    // `evidence_refs`", as CIRISVerify#281 did for manifests). Chat blobs are
    // not special, so a chat row carries BOTH: the pointer to open, the
    // citation to be found.
    for (k, v) in members {
        if let Some(sha) = pointer_sha(&v) {
            cite_evidence(&mut envelope, &sha);
        }
        envelope[k] = v;
    }
    // Deterministic per (dimension, room, author, instant, payload) so a retry
    // is idempotent rather than a second row.
    let attestation_id = {
        let mut h = Sha256::new();
        h.update(dimension.as_bytes());
        h.update(room.unwrap_or_default().as_bytes());
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
            attestation_type: shape.attestation_type,
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: shape.cohort_scope,
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
        attestation_type: shape.attestation_type.to_owned(),
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
        cohort_scope: shape.cohort_scope.to_owned(),
        // Tier is REPLICABILITY, cohort_scope is VISIBILITY. A thing said is
        // LOCAL until the share enters it into the mesh and widens it to the
        // room; a composer is born in the room at federation tier.
        tier: shape.tier.to_owned(),
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
    let room = pair_community_key_id(&author.key_id, recipient_key_id);
    chat_message_attestation_in(author, &room, body, asserted_at, store).await
}

/// **A message into a room named by its community id** (CIRISEdge#608) —
/// the general form [`chat_message_attestation`] is the two-person
/// convenience over.
///
/// `community_key_id` is any community the author is a member of: a derived
/// pair id ([`pair_community_key_id`]) or an allocated room id
/// ([`new_room_community_key_id`]). The body is sealed under that room's
/// DEK — the cascade resolves the roster through persist and wraps to every
/// member's active occurrences — and the row names the room by
/// [`FIELD_COMMUNITY_ID`]. Nothing about the row or the seal knows how many
/// people are in the room.
///
/// # Errors
/// Seal failure, a seal nobody could open (CIRISEdge#599), canonicalization
/// or signing failure.
pub async fn chat_message_attestation_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    body: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    store: &dyn crate::group_content::GroupContentStore,
) -> Result<(Attestation, crate::group_content::SealedContent), String> {
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;
    let room = community_key_id;

    // One truncation, feeding both the row's column and the AAD. Deriving
    // them separately is how they drift.
    let at = truncate_to_substrate_resolution(asserted_at);
    let (members, sealed) = sealed_body_members(author, room, body, at, store).await?;
    let row = chat_row(author, room, CHAT_MESSAGE_DIMENSION, members, at).await?;
    // `sealed` is returned rather than dropped so the caller can see
    // `excluded` — who, of this room, cannot read what was just written.
    // persist: "a caller that ignores this is ignoring who cannot read what
    // it just wrote."
    Ok((row, sealed))
}

/// Seal `body` under `room`'s DEK for `author` at `at` (already truncated to
/// the substrate's resolution) and return the row members that carry it.
///
/// # Errors
/// Seal failure, or a seal nobody could open (CIRISEdge#599).
async fn sealed_body_members(
    author: &crate::identity::LocalSigner,
    room: &str,
    body: &str,
    at: chrono::DateTime<chrono::Utc>,
    store: &dyn crate::group_content::GroupContentStore,
) -> Result<
    (
        serde_json::Map<String, serde_json::Value>,
        crate::group_content::SealedContent,
    ),
    String,
> {
    let sealed = store
        .seal(crate::group_content::SealRequest {
            cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY,
            community_key_id: Some(room),
            author_key_id: &author.key_id,
            asserted_at: at,
            field: crate::group_content::ContentField::Body,
            plaintext: body.as_bytes(),
            // A chat body's format is its dimension's (`chat:message:v1` is
            // text), so it carries no description: nothing to seal beside
            // encrypted bytes, and no format for persist to record
            // (CIRISEdge#698).
            description: None,
        })
        .await
        .map_err(|e| format!("seal chat content: {e}"))?;

    // CIRISEdge#599 — REFUSE a write nobody can read.
    //
    // The DEK cascade wraps per active identity OCCURRENCE, so a room whose
    // members have none resolves to no wrap targets and seals with
    // `granted: []`. Every layer below reports success: the blob is written,
    // the row is valid, the pointer resolves — and the read returns
    // `Body::Unopened`, on the author's own node, forever.
    //
    // `readable_by_nobody()` has named that state since the store landed and
    // nothing called it. Writing content no key can open is not a degraded
    // write, it is a lost message that looks like a sent one, so it fails
    // HERE — where the caller still has the plaintext — rather than at some
    // reader's screen.
    //
    // Not folded into `excluded`: persist can only exclude occurrences it
    // ENUMERATED, so a member with no occurrence at all is absent from both
    // lists (CIRISPersist#843). `excluded` would say "one phone cannot read
    // this" about a message nobody can read.
    if sealed.readable_by_nobody() {
        return Err(format!(
            "chat content sealed under the room's DEK with NO grants — nobody can \
             read it, including you. The cascade wraps per active identity \
             OCCURRENCE, so this means no member of {room} has one registered on \
             this node. Provision it (ciris_edge::content_occurrence, or \
             Engine::self_at_login for an app+agent identity) before sending \
             (CIRISEdge#599)"
        ));
    }

    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_CONTENT.to_owned(),
        serde_json::to_value(&sealed.pointer).map_err(|e| format!("pointer: {e}"))?,
    );
    members.insert(
        FIELD_CONTENT_TYPE.to_owned(),
        serde_json::json!("text/plain"),
    );
    Ok((members, sealed))
}

/// The member a chat `withdraws` / `recants` carries its reason code under.
/// A composer sits at the room's scope, where its members are plaintext to
/// every holder, so the reason is a code from [`ComposerReason`], never free
/// text.
pub const FIELD_REASON_CODE: &str = "reason_code";

/// Why an author withdrew or recanted a message: a closed set, because the
/// row it rides is plaintext to every holder of the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposerReason {
    /// No reason given. Valid on both composers.
    Unspecified,
    /// Withdraw: sent by mistake.
    SentInError,
    /// Withdraw: the author no longer wants it held.
    Privacy,
    /// Withdraw: no longer current.
    Outdated,
    /// Recant: the author says it was false.
    Incorrect,
    /// A code this build does not know, as read off a row from a newer one.
    /// Never produced.
    Unknown(String),
}

impl ComposerReason {
    /// The code as written on the row.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unspecified => "unspecified",
            Self::SentInError => "sent_in_error",
            Self::Privacy => "privacy",
            Self::Outdated => "outdated",
            Self::Incorrect => "incorrect",
            Self::Unknown(code) => code,
        }
    }

    /// Read a code off a row. An unknown code is kept, not refused, so a
    /// newer client's code does not fail an older reader.
    #[must_use]
    pub fn parse(code: &str) -> Self {
        match code {
            "unspecified" => Self::Unspecified,
            "sent_in_error" => Self::SentInError,
            "privacy" => Self::Privacy,
            "outdated" => Self::Outdated,
            "incorrect" => Self::Incorrect,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Whether this code may ride a composer of `attestation_type`.
    #[must_use]
    pub fn allowed_on(&self, attestation_type: &str) -> bool {
        use ciris_persist::federation::types::attestation_type as ty;
        match self {
            Self::Unspecified => true,
            Self::SentInError | Self::Privacy | Self::Outdated => attestation_type == ty::WITHDRAWS,
            Self::Incorrect => attestation_type == ty::RECANTS,
            Self::Unknown(_) => false,
        }
    }
}

/// **Whether `composer` is the author's own act over `target`**: the same
/// attester, the same room, and the composer names `target`. The one rule
/// both [`rows_in_room`] and a caller deciding what a viewer may do apply.
///
/// The attester is the author: from v19.0.0 every chat row, and every
/// widening of one, is signed by the person who said it. A composer by anyone
/// else changes nothing, in a room of two or of twenty.
#[must_use]
pub fn composer_is_authors(composer: &Attestation, target: &Attestation) -> bool {
    composer.attesting_key_id == target.attesting_key_id
        && room_of(composer).is_some()
        && room_of(composer) == room_of(target)
        && ciris_persist::federation::precedence::references_attestation_id_from_envelope(
            &composer.attestation_envelope,
        ) == Some(target.attestation_id.as_str())
}

/// Refuse a composer `author` may not write over `target` in `room`.
fn check_composer_target(
    author: &crate::identity::LocalSigner,
    room: &str,
    target: &Attestation,
) -> Result<(), String> {
    if dimension_of(target) != Some(CHAT_MESSAGE_DIMENSION) {
        return Err(format!(
            "row {} is not a chat message ({:?})",
            target.attestation_id,
            dimension_of(target)
        ));
    }
    if room_of(target).as_deref() != Some(room) {
        return Err(format!(
            "row {} is not in room {room} ({:?})",
            target.attestation_id,
            room_of(target)
        ));
    }
    if target.attesting_key_id != author.key_id {
        return Err(format!(
            "row {} was said by {}, not {}: only its author revises or retracts a message",
            target.attestation_id, target.attesting_key_id, author.key_id
        ));
    }
    Ok(())
}

/// **The author revises a message**: a `supersedes` naming `target`, with
/// `new_body` sealed exactly as [`chat_message_attestation_in`] seals a body.
///
/// `target` is the current head of the message: the placed row readers hold
/// ([`ChatMessage::attestation_id`]), or the latest revision of it. Two
/// composers by one author naming the same row are one composer to persist's
/// replay dedup, so a second revision naming the original is dropped.
///
/// The row is born in the room at federation tier (CIRISPersist#1155):
/// written with `put_attestation`, not shared. Sharing a `self` row widens
/// it, and the widening would carry neither this row's type nor its target.
///
/// # Errors
/// `target` is not `author`'s chat message in `room`; seal failure, a seal
/// nobody could open, canonicalization or signing failure.
pub async fn chat_message_supersede_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    target: &Attestation,
    new_body: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    store: &dyn crate::group_content::GroupContentStore,
) -> Result<(Attestation, crate::group_content::SealedContent), String> {
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::types::attestation_type as ty;
    let room = community_key_id;
    check_composer_target(author, room, target)?;
    let at = truncate_to_substrate_resolution(asserted_at);
    let (mut members, sealed) = sealed_body_members(author, room, new_body, at, store).await?;
    members.insert(
        paths::REFERENCES_ATTESTATION_ID.to_owned(),
        serde_json::json!(target.attestation_id),
    );
    let row = chat_row_shaped(
        author,
        Some(room),
        CHAT_MESSAGE_DIMENSION,
        members,
        at,
        RowShape::composer(ty::SUPERSEDES),
    )
    .await?;
    Ok((row, sealed))
}

/// **The author withdraws a message**: a `withdraws` naming `target` (the
/// current head, as for [`chat_message_supersede_in`]), retracting it
/// without saying it was false. Born in the room at federation tier.
///
/// # Errors
/// `target` is not `author`'s chat message in `room`; `reason` is not a
/// withdraw code; canonicalization or signing failure.
pub async fn chat_message_withdraw_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    target: &Attestation,
    reason: &ComposerReason,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    retraction_in(
        author,
        community_key_id,
        target,
        reason,
        asserted_at,
        ciris_persist::federation::types::attestation_type::WITHDRAWS,
    )
    .await
}

/// **The author recants a message**: a `recants` naming `target` (the
/// current head), saying it was false. Outranks a withdraw and a revision of
/// the same row (CEG §6.1). Born in the room at federation tier.
///
/// # Errors
/// As [`chat_message_withdraw_in`], with recant codes.
pub async fn chat_message_recant_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    target: &Attestation,
    reason: &ComposerReason,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    retraction_in(
        author,
        community_key_id,
        target,
        reason,
        asserted_at,
        ciris_persist::federation::types::attestation_type::RECANTS,
    )
    .await
}

async fn retraction_in(
    author: &crate::identity::LocalSigner,
    room: &str,
    target: &Attestation,
    reason: &ComposerReason,
    asserted_at: chrono::DateTime<chrono::Utc>,
    attestation_type: &'static str,
) -> Result<Attestation, String> {
    check_composer_target(author, room, target)?;
    if !reason.allowed_on(attestation_type) {
        return Err(format!(
            "reason `{}` is not a `{attestation_type}` code",
            reason.as_str()
        ));
    }
    // persist's own composer shape, so the members its precedence fold joins
    // on are spelled by the authority; a recant differs only in `kind`.
    let serde_json::Value::Object(mut members) =
        ciris_persist::federation::replication::withdraws_attestation_envelope(
            &target.attestation_id,
            &target.attestation_type,
        )
    else {
        return Err("persist's composer envelope is not an object".to_owned());
    };
    members.insert("kind".to_owned(), serde_json::json!(attestation_type));
    members.insert(
        FIELD_REASON_CODE.to_owned(),
        serde_json::json!(reason.as_str()),
    );
    chat_row_shaped(
        author,
        Some(room),
        CHAT_MESSAGE_DIMENSION,
        members,
        asserted_at,
        RowShape::composer(attestation_type),
    )
    .await
}

/// CIRISEdge#805 item 6 — **the attendee's own call row**: `author` attended
/// call `call_id_hex` in room `community_key_id` from `asserted_at`. Authored
/// `self` like every chat row and shared to the room by the caller (it
/// reaches exactly the room's members); attester = subject = `author`.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn call_attestation_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    call_id_hex: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    let mut members = serde_json::Map::new();
    members.insert(FIELD_CALL_ID.to_owned(), serde_json::json!(call_id_hex));
    chat_row(
        author,
        community_key_id,
        CALL_DIMENSION,
        members,
        asserted_at,
    )
    .await
}

/// The call a [`CALL_DIMENSION`] row names, if it names one.
#[must_use]
pub fn call_id_of(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get(FIELD_CALL_ID)
        .and_then(serde_json::Value::as_str)
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
    let room = crate::scope_room::ScopeRoom::community(pair_community_key_id(
        &author.key_id,
        recipient_key_id,
    ));
    key_package_attestation_in(author, &room, key_package, asserted_at).await
}

/// **A KeyPackage into a named room** (CIRISEdge#656) —
/// the twin of [`commit_attestation_in`], and what any room that is not a
/// PAIR needs.
///
/// [`key_package_attestation`] derives a pair room from `(author,
/// recipient)`, which has no meaning for a self collective (whose group id
/// is the owner's key id) or a family. `self_room::decide` returns
/// `PublishKeyPackage` and `Add`, and before this neither could be executed
/// through the public API: the row landed in `chat:pair:v1:<hash>` while
/// the adder looked in the self room, so the creator held a KeyPackage it
/// could not see and the room stayed at one member — every step logging
/// success.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn key_package_attestation_in(
    author: &crate::identity::LocalSigner,
    room: &crate::scope_room::ScopeRoom,
    key_package: &[u8],
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use base64::Engine as _;
    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_MLS_BYTES.to_owned(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(key_package)),
    );
    chat_row_in(author, room, KEY_PACKAGE_DIMENSION, members, asserted_at).await
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
    let room = crate::scope_room::ScopeRoom::community(pair_community_key_id(
        &author.key_id,
        recipient_key_id,
    ));
    welcome_attestation_in(author, &room, recipient_key_id, welcome, epoch, asserted_at).await
}

/// **A Welcome into a named room, for a named joiner** (CIRISEdge#656).
///
/// Takes **both** the room and the recipient, because they are two facts.
/// [`welcome_attestation`]'s single `recipient_key_id` answered "which
/// room" *and* "for whom" at once — true only for a pair, where the room
/// IS the pair — and a room with three members needs one Welcome per
/// joiner in the same room, which that shape cannot express. The recipient
/// rides the signed envelope so a joiner can find its own
/// ([`welcome_for`]).
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn welcome_attestation_in(
    author: &crate::identity::LocalSigner,
    room: &crate::scope_room::ScopeRoom,
    recipient_key_id: &str,
    welcome: &[u8],
    epoch: u64,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Attestation, String> {
    use base64::Engine as _;
    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_MLS_BYTES.to_owned(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(welcome)),
    );
    members.insert(FIELD_MLS_EPOCH.to_owned(), serde_json::json!(epoch));
    members.insert(
        FIELD_MLS_FOR.to_owned(),
        serde_json::json!(recipient_key_id),
    );
    chat_row_in(author, room, WELCOME_DIMENSION, members, asserted_at).await
}

/// **A commit into a room named by its community id** (CIRISEdge#604) —
/// the room's MLS Commit as a signed community row, carrying its claim.
///
/// The row's `asserted_at` is the commit's claimed instant and its author
/// is the committer, so the claim rides in the signed bytes rather than as
/// a member a peer could disagree about. The producer REFUSES a commit
/// whose claim names a different committer than `author`: a row that
/// mislabelled the claim would make two nodes order the same contest
/// differently, which is the one thing CC 3's rule cannot survive.
///
/// # Errors
/// The claim's committer is not `author`, or signing failed.
pub async fn commit_attestation_in(
    author: &crate::identity::LocalSigner,
    community_key_id: &str,
    commit: &crate::mls::CohortCommit,
) -> Result<Attestation, String> {
    use base64::Engine as _;
    let claim = commit.claim();
    if claim.committer_key_id() != author.key_id {
        return Err(format!(
            "commit claimed by {} cannot be carried by {}: the row's author IS the claim's \
             committer, and a mislabelled claim would fork the contest (CIRISEdge#604)",
            claim.committer_key_id(),
            author.key_id
        ));
    }
    let mut members = serde_json::Map::new();
    members.insert(
        FIELD_MLS_BYTES.to_owned(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(commit.commit())),
    );
    members.insert(
        FIELD_MLS_EPOCH.to_owned(),
        serde_json::json!(commit.epoch()),
    );
    chat_row(
        author,
        community_key_id,
        COMMIT_DIMENSION,
        members,
        claim.asserted_at(),
    )
    .await
}

/// [`commit_attestation_in`] for the two-person room derived from the
/// pair (the convenience every other pair producer here offers).
///
/// # Errors
/// As [`commit_attestation_in`].
pub async fn commit_attestation(
    author: &crate::identity::LocalSigner,
    recipient_key_id: &str,
    commit: &crate::mls::CohortCommit,
) -> Result<Attestation, String> {
    let room = pair_community_key_id(&author.key_id, recipient_key_id);
    commit_attestation_in(author, &room, commit).await
}

/// The room a stored row names, through persist's cohort-target resolver
/// (every alias; a split-brain row naming two is `None`).
fn room_of(a: &Attestation) -> Option<String> {
    ciris_persist::federation::admission::envelope_cohort_target(&a.attestation_envelope)
        .ok()
        .flatten()
        .map(str::to_owned)
}

/// A `withdraws` or `recants`: it retracts a row and is never itself a
/// thing said.
fn is_retraction(a: &Attestation) -> bool {
    use ciris_persist::federation::types::attestation_type as ty;
    a.attestation_type == ty::WITHDRAWS || a.attestation_type == ty::RECANTS
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
/// Every chat-plane row of `dimension` in `room` from `participants`,
/// unopened. The dimension is pushed into the read (persist v56, #1001),
/// so a caller no longer filters it after the call.
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
    dimension: &str,
) -> Result<Vec<Attestation>, String> {
    use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use ciris_persist::federation::types::attestation_type as ty;
    // persist v56 (#1001): each participant's rows of `dimension`, plus the
    // composers that can fold one out, each walked page by page. A widening
    // carries its prior's envelope, dimension included, so it matches the
    // first walk. A retraction carries no dimension, so the composer walk has
    // none. The room is matched below, not in the query: `scope()` needs a
    // cohort_scope, and a room's rows sit at two (the author's original at
    // `self`, its share at the room's scope), so a scope filter would drop the
    // originals the fold needs.
    // A NotServed page is an Err, never an empty room.
    let mut rows: Vec<Attestation> = Vec::new();
    for who in participants {
        let mut in_dimension = AttestationQuery::by(who, FOLD_PAGE)
            .dimension(dimension)
            .types(&[ty::SCORES, ty::SUPERSEDES])
            .pages();
        while let Some(page) = in_dimension
            .next(directory)
            .await
            .map_err(|e| format!("rows by {who} in {dimension}: {e}"))?
        {
            rows.extend(page);
        }
        let mut composers = AttestationQuery::by(who, FOLD_PAGE)
            .types(&[ty::WITHDRAWS, ty::RECANTS])
            .pages();
        while let Some(page) = composers
            .next(directory)
            .await
            .map_err(|e| format!("composers by {who}: {e}"))?
        {
            rows.extend(page);
        }
    }
    // A row is folded out when its author's own composer names it: a
    // widening or a revision (`supersedes`) replaces it, a `withdraws` or
    // `recants` retracts it. A chain folds to its head, since each link names
    // the one before. A composer by anyone else names nothing here
    // ([`composer_is_authors`]), and one whose target this node does not hold
    // waits for it.
    let by_id: std::collections::BTreeMap<&str, &Attestation> = rows
        .iter()
        .map(|a| (a.attestation_id.as_str(), a))
        .collect();
    let mut folded = std::collections::BTreeSet::<String>::new();
    let mut foreign = std::collections::BTreeSet::<String>::new();
    for c in &rows {
        let Some(target) =
            ciris_persist::federation::precedence::references_attestation_id_from_envelope(
                &c.attestation_envelope,
            )
        else {
            continue;
        };
        let Some(t) = by_id.get(target) else {
            continue;
        };
        if composer_is_authors(c, t) {
            folded.insert(target.to_owned());
        } else {
            // Someone else's composer over this message is not a thing said
            // either: it is dropped, not shown as an empty message.
            tracing::debug!(
                composer = %c.attestation_id,
                by = %c.attesting_key_id,
                target,
                author = %t.attesting_key_id,
                "a composer over another author's message is ignored"
            );
            foreign.insert(c.attestation_id.clone());
        }
    }
    let mut out: Vec<Attestation> = rows
        .into_iter()
        .filter(|a| !folded.contains(&a.attestation_id) && !foreign.contains(&a.attestation_id))
        .filter(|a| !is_retraction(a))
        .filter(|a| room_of(a).as_deref() == Some(room))
        .filter(|a| dimension_of(a) == Some(dimension))
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
    let mut out: Vec<ChatMessage> =
        rows_in_room(directory, participants, room, CHAT_MESSAGE_DIMENSION)
            .await?
            .iter()
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

/// CIRISEdge#676 — when `from` LAST published a KeyPackage in `room`
/// (`asserted_at` of its newest `chat:key_package:v1` row), if ever. The
/// restart signal's input: a member of the tree publishing a KeyPackage
/// AFTER it was added is asking to be re-Welcomed
/// (`FSD/MLS_STATE_AT_REST.md` §4).
///
/// # Errors
/// A directory read failure, as a string.
pub async fn latest_key_package_at(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
    Ok(
        rows_in_room(directory, &[from.to_owned()], room, KEY_PACKAGE_DIMENSION)
            .await?
            .iter()
            .map(|a| a.asserted_at)
            .max(),
    )
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
    Ok(
        rows_in_room(directory, &[from.to_owned()], room, KEY_PACKAGE_DIMENSION)
            .await?
            .iter()
            .filter_map(|a| {
                a.attestation_envelope
                    .get(FIELD_MLS_BYTES)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            })
            .next_back(),
    )
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
    Ok(
        rows_in_room(directory, &[from.to_owned()], room, WELCOME_DIMENSION)
            .await?
            .iter()
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
            .next_back(),
    )
}

/// A Welcome row as placed: its bytes, the epoch it welcomes into, and the
/// row's `asserted_at` (CIRISEdge#696).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedWelcome {
    /// The serialized MLS Welcome.
    pub bytes: Vec<u8>,
    /// The epoch the Welcome joins the recipient into.
    pub epoch: u64,
    /// When the row was asserted — what a restarted creator compares with
    /// `CohortGroup::member_added_at` to tell whether a member in its tree
    /// was welcomed FOR ITS CURRENT ADD (`asserted_at >= added_at`), or only
    /// for an earlier one (a crash between `add_member` and placing the
    /// Welcome).
    pub asserted_at: chrono::DateTime<chrono::Utc>,
}

/// **The Welcome addressed to `recipient_key_id`** in `room` (CIRISEdge#656).
///
/// [`welcome_from`] returns the LAST Welcome in the room, which is right
/// for a pair and wrong for anything wider: a self collective's creator
/// places one Welcome per device into one room, so "the last one" is
/// whichever device joined most recently. This picks the one whose signed
/// envelope names `recipient_key_id`.
///
/// A Welcome written by the pair-era producer carries no recipient member.
/// Those are matched only when the room IS the pair of `(from,
/// recipient)` — so a legacy pair handshake keeps working and a wider
/// room never hands a joiner somebody else's Welcome.
///
/// The bytes and epoch only; [`welcome_for_row`] also returns the row's
/// instant.
///
/// # Errors
/// The directory read.
pub async fn welcome_for(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
    recipient_key_id: &str,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    Ok(welcome_for_row(directory, from, room, recipient_key_id)
        .await?
        .map(|w| (w.bytes, w.epoch)))
}

/// [`welcome_for`], with the row's `asserted_at` (CIRISEdge#696,
/// `FSD/MLS_STATE_AT_REST.md` §2 `welcome`).
///
/// # Errors
/// The directory read.
pub async fn welcome_for_row(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
    recipient_key_id: &str,
) -> Result<Option<PlacedWelcome>, String> {
    use base64::Engine as _;
    let pair_room = pair_community_key_id(from, recipient_key_id);
    Ok(
        rows_in_room(directory, &[from.to_owned()], room, WELCOME_DIMENSION)
            .await?
            .iter()
            .filter(|a| {
                match a
                    .attestation_envelope
                    .get(FIELD_MLS_FOR)
                    .and_then(serde_json::Value::as_str)
                {
                    Some(named) => named == recipient_key_id,
                    // Pair-era: the room was the address.
                    None => room == pair_room,
                }
            })
            .filter_map(|a| {
                let env = &a.attestation_envelope;
                let bytes = env
                    .get(FIELD_MLS_BYTES)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())?;
                let epoch = env
                    .get(FIELD_MLS_EPOCH)
                    .and_then(serde_json::Value::as_u64)?;
                Some(PlacedWelcome {
                    bytes,
                    epoch,
                    asserted_at: a.asserted_at,
                })
            })
            .next_back(),
    )
}

/// Every commit `from` placed in `room`, oldest claim first, each with the
/// [`crate::mls::CommitClaim`] its row binds — the input to
/// [`crate::mls::CohortGroup::apply_remote_commit_claimed`] (CIRISEdge#604).
///
/// The claim is rebuilt from the row's `asserted_at` and `attesting_key_id`,
/// which is exactly what the producer bound, so the receiver contests the
/// tuple the committer signed.
///
/// # Errors
/// A directory read failure.
pub async fn commits_from(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
) -> Result<Vec<(Vec<u8>, crate::mls::CommitClaim)>, String> {
    use base64::Engine as _;
    Ok(
        rows_in_room(directory, &[from.to_owned()], room, COMMIT_DIMENSION)
            .await?
            .iter()
            .filter_map(|a| {
                let bytes = a
                    .attestation_envelope
                    .get(FIELD_MLS_BYTES)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())?;
                Some((
                    bytes,
                    crate::mls::CommitClaim::new(a.asserted_at, a.attesting_key_id.clone()),
                ))
            })
            .collect(),
    )
}

/// What [`apply_room_commits`] did with the commit rows it read (CIRISEdge#604).
#[derive(Debug, Default)]
#[must_use = "`reproposed` carries commits that MUST be emitted as rows and shared"]
pub struct AppliedCommits {
    /// Rows whose commit merged (a plain apply, or the winner of a contest
    /// after a rollback).
    pub applied: usize,
    /// Rows that contested an epoch and LOST against the claim this node
    /// holds — their author will re-propose.
    pub discarded: usize,
    /// Rows this node could not act on: framed ahead of its epoch (held), or
    /// already reached.
    pub other: usize,
    /// This node's own commits, re-issued against a winner's line after a
    /// rollback. Each MUST be carried as a [`commit_attestation_in`] row and
    /// shared, or the node's re-proposals exist nowhere but here.
    pub reproposed: Vec<crate::mls::CohortCommit>,
}

/// Apply every commit row `from` placed in `room` to `group`, in claim order,
/// contesting each by the claim its row binds — the receive half of
/// CIRISEdge#604. Idempotent: rows already applied read as `other`, rows
/// already discarded read as `discarded` again, and no state moves.
///
/// # Errors
/// A directory read failure, or a contest this node cannot resolve
/// ([`crate::mls::CohortGroupError::ForkBeyondWindow`] — surfaced, never
/// silently absorbed).
pub async fn apply_room_commits(
    group: &crate::mls::CohortGroup,
    directory: &dyn ciris_persist::federation::FederationDirectory,
    from: &str,
    room: &str,
) -> Result<AppliedCommits, String> {
    use crate::mls::ClaimedApplyOutcome;
    let mut out = AppliedCommits::default();
    for (bytes, claim) in commits_from(directory, from, room).await? {
        match group
            .apply_remote_commit_claimed(&bytes, Some(claim))
            .await
            .map_err(|e| format!("apply commit from {from} in {room}: {e}"))?
        {
            ClaimedApplyOutcome::Applied(_) => out.applied += 1,
            ClaimedApplyOutcome::Discarded { .. } => out.discarded += 1,
            ClaimedApplyOutcome::Superseded { reproposed, .. } => {
                out.applied += 1;
                out.reproposed.extend(reproposed);
            }
            ClaimedApplyOutcome::Deferred { .. } | ClaimedApplyOutcome::AlreadyApplied(_) => {
                out.other += 1;
            }
        }
    }
    Ok(out)
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
    /// The content did not open, and [`UnopenedReason`] says which of the
    /// distinct states that is. CIRISEdge#601: "the bytes are not here yet"
    /// and "this key does not open them" used to share one string, and a
    /// reader could not tell a state to wait through from the
    /// confidentiality boundary working.
    Unopened { reason: UnopenedReason },
}

/// CIRISEdge#601 — **why a body did not open**, as an arm rather than a
/// sentence.
///
/// The two that matter are the first two. [`Self::NotFetched`] is a state a
/// reader waits through: the row arrived, the bytes have not, and the pull
/// (`blob_swarm::pull`) is what changes it. [`Self::NotGranted`] is
/// USUALLY the boundary working: the bytes are here and this viewer holds no
/// grant. It is NOT always final — see its own doc for the transient case
/// (CIRISEdge#772) — so a reader that must tell "not yet" from "never" cannot
/// do it from this arm alone today. CIRISServer's contact view asserts on
/// this difference; before the split it string-matched persist's prose.
///
/// Every arm carries `detail` — the substrate's own sentence — because a
/// refusal that cannot be followed back is one nobody can act on. `Display`
/// renders it, so a caller that only wants text gets what it got before.
///
/// `#[non_exhaustive]` (CIRISEdge#779, in the same MAJOR as
/// [`crate::group_content::GroupContentError`]'s): a match outside this
/// crate carries a wildcard arm, so the next reason is not a MAJOR.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnopenedReason {
    /// Not held on this node yet. A pull may be in flight, queued, or not
    /// yet triggered; the state to wait through.
    NotFetched { detail: String },
    /// Held, and this viewer's occurrence holds no grant for it — usually the
    /// confidentiality boundary, working as designed.
    ///
    /// **Not always terminal (CIRISEdge#772).** persist binds a sealed body to
    /// the epoch's MINTER, and when it cannot tell which admitted `key_grant`
    /// set granted this viewer — the bytes landed before the set, or the room
    /// has several minters at that epoch and the pointer names none
    /// (CIRISPersist I128/I129) — it binds the body to the author and reports
    /// no grant until a set for that axis is admitted again, when it rebinds
    /// (#876) and the body opens. Observed on the mesh: a pair room with two
    /// epoch-0 minters read `NotGranted` for ~3.5 s after the bytes arrived.
    /// Persist's refusal does not distinguish the two cases, so neither can
    /// this arm; [`Self::is_pending`] still answers `false` for it.
    NotGranted { detail: String },
    /// CIRISEdge#797 — held, this viewer is authorized on the file, and the
    /// key of one of its chunks has not arrived yet (persist v53's
    /// `blob_chunk_key_not_yet_granted`, CIRISPersist#969). A state to wait
    /// through, not a verdict: key sets follow the bytes on their own plane.
    /// [`Self::is_pending`] answers `true`.
    AwaitingKey { detail: String },
    /// Held once, swept: the epoch was destroyed or the bytes evicted.
    Evicted { detail: String },
    /// The row referencing the bytes was withdrawn by its subject (CC 2.3
    /// at the bytes plane; persist v47.2.0, CIRISEdge#669). A verdict, not
    /// a state to wait through: the retraction is honoured, the bytes stop.
    Withdrawn { detail: String },
    /// The seal did not open under the AAD rebuilt from this row — the
    /// row and the bytes disagree, or the bytes were tampered with.
    SealMismatch { detail: String },
    /// The row itself is not a well-formed chat message (no pointer, an
    /// unreadable pointer), so there was nothing to open.
    MalformedRow { detail: String },
    /// The bytes opened but are not UTF-8 text.
    NotText { detail: String },
    /// A substrate fault while opening; retrying may or may not help.
    Substrate { detail: String },
}

impl UnopenedReason {
    /// Stable lower-case label for the arm, for logs and metrics.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotFetched { .. } => "not_fetched",
            Self::NotGranted { .. } => "not_granted",
            Self::AwaitingKey { .. } => "awaiting_key",
            Self::Evicted { .. } => "evicted",
            Self::Withdrawn { .. } => "withdrawn",
            Self::SealMismatch { .. } => "seal_mismatch",
            Self::MalformedRow { .. } => "malformed_row",
            Self::NotText { .. } => "not_text",
            Self::Substrate { .. } => "substrate",
        }
    }

    /// The substrate's own sentence.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::NotFetched { detail }
            | Self::NotGranted { detail }
            | Self::AwaitingKey { detail }
            | Self::Evicted { detail }
            | Self::Withdrawn { detail }
            | Self::SealMismatch { detail }
            | Self::MalformedRow { detail }
            | Self::NotText { detail }
            | Self::Substrate { detail } => detail,
        }
    }

    /// Is this a state a reader should wait through (the bytes, or a
    /// chunk's key, may still arrive), as opposed to a verdict?
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::NotFetched { .. } | Self::AwaitingKey { .. })
    }

    /// The one mapping from the store's typed error. Kept here, once, so
    /// `resolve_content` and any future opener agree on the arms.
    pub(crate) fn from_store_error(e: &crate::group_content::GroupContentError) -> Self {
        use crate::group_content::GroupContentError as E;
        let detail = e.to_string();
        match e {
            E::NotHeld { .. } => Self::NotFetched { detail },
            E::NotGranted { .. } => Self::NotGranted { detail },
            E::ChunkKeyPending { .. } => Self::AwaitingKey { detail },
            E::Evicted { .. } => Self::Evicted { detail },
            // persist v54.1.0 — a purge withholds the bytes as a withdrawal
            // does, and the reader's remedy is the same (none).
            E::Withdrawn { .. } | E::Purged { .. } => Self::Withdrawn { detail },
            E::SealMismatch { .. } => Self::SealMismatch { detail },
            // CIRISEdge#737 — a range past the end is the file reader's to
            // name (`FileError::RangeNotSatisfiable`) before it reaches here;
            // a chat body is never read by range, so here it is a fault.
            // CIRISEdge#744 — the two streamed-WRITE refusals never arise on
            // a read; if one reached here it is a fault, not a reader state.
            // persist v55 — a stream-keyed chunk under a community epoch is an
            // adopt/promote fault, never a read state.
            E::RangeNotSatisfiable { .. }
            | E::StreamKeyedChunkCommunityEpoch { .. }
            | E::DeclaredLengthMismatch { .. }
            | E::Reader { .. }
            | E::Substrate(_) => Self::Substrate { detail },
        }
    }
}

impl std::fmt::Display for UnopenedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind(), self.detail())
    }
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
    /// The message this row revises, when it is an author's revision
    /// ([`chat_message_supersede_in`]): the row it replaced in the room.
    pub edits: Option<String>,
}

impl ChatMessage {
    /// Recognise a chat row in `room`, or `None` if the row is not a chat
    /// message there. A `withdraws` or `recants` in the room is not one.
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
        if dimension_of(a) != Some(CHAT_MESSAGE_DIMENSION)
            || room_of(a).as_deref() != Some(room)
            || is_retraction(a)
        {
            return None;
        }
        let env = &a.attestation_envelope;

        let Some(raw) = env.get(FIELD_CONTENT) else {
            return Some(Self::from_parts(
                a,
                env,
                Body::Unopened {
                    reason: UnopenedReason::MalformedRow {
                        detail: "row carries no `content` pointer — chat content lives in \
                                 the group's blob store (CIRISEdge#586)"
                            .to_owned(),
                    },
                },
            ));
        };
        let body = match serde_json::from_value::<crate::group_content::BlobPointer>(raw.clone()) {
            Ok(pointer) => Body::Pointer(pointer),
            Err(e) => Body::Unopened {
                reason: UnopenedReason::MalformedRow {
                    detail: format!("row carries an unreadable `content` pointer: {e}"),
                },
            },
        };
        Some(Self::from_parts(a, env, body))
    }

    /// The members both row shapes share. Factored so the inline path and
    /// the blob path cannot drift on attribution — which is the one field
    /// here that has already been got wrong once (CIRISEdge#564).
    fn from_parts(a: &Attestation, env: &serde_json::Value, body: Body) -> Self {
        use ciris_persist::federation::envelope::paths;
        let references = env
            .get(paths::REFERENCES_ATTESTATION_ID)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let widening = env.get(paths::WIDENED_AT).is_some();
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
            // Both are `supersedes`; a widening carries `widened_at` and a
            // revision does not.
            widens: references.clone().filter(|_| widening),
            edits: references.filter(|_| {
                !widening
                    && a.attestation_type
                        == ciris_persist::federation::types::attestation_type::SUPERSEDES
            }),
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
    /// Never — a failure to open becomes [`Body::Unopened`] with a typed
    /// [`UnopenedReason`], because one unreadable message must not fail a
    /// room's whole read. The two arms a reader must tell apart:
    /// [`UnopenedReason::NotFetched`] (the bytes are not here yet — wait, the
    /// pull is what changes it) and [`UnopenedReason::NotGranted`] (the bytes
    /// are here and this viewer may not open them — the boundary working).
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
                    reason: UnopenedReason::NotText {
                        detail: format!("content is not UTF-8: {e}"),
                    },
                },
            },
            Err(e) => Body::Unopened {
                reason: UnopenedReason::from_store_error(&e),
            },
        };
    }
}
