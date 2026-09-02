//! CIRISEdge#552/#554 — the contact ladder: **announce → discover → request →
//! consent → chat**.
//!
//! # Why this module exists at all
//!
//! Every rung of this ladder already existed as a primitive, and none of it was
//! reachable without knowing five subsystems. Discovery meant resolving a
//! `TransportDestination` yourself; a contact meant hand-building a
//! `consent:replication:v1` grant; a chat room meant knowing it is really a
//! 2-member `Community`. That is not a DX problem in the cosmetic sense — it is
//! why the ladder had never been walked end to end, and why nobody could say
//! which rung was broken.
//!
//! So the surface here takes a **fedID and nothing else**. Anything a caller
//! must look up first is a rung they can get wrong.
//!
//! # What lives here, and what deliberately does not
//!
//! Edge owns the rungs that are about REACHING someone:
//!
//! * [`resolve`] — any identifier (fedID, nodeID, agentID) to the person and the
//!   nodes that reach them;
//! * [`discover`] — that, plus a transport destination, so "discovered" means
//!   contactable rather than merely known.
//!
//! **Consent and chat are CIRISServer's**, and are not reimplemented here.
//! `POST /v1/contacts` already ensures a `consent:replication:v1` grant covers
//! `chat:`; `POST /v1/chat` already writes a 2-member `Community`;
//! `POST /v1/chat/{id}/messages` already writes a `chat:message:v1` attestation.
//! A second implementation of any of those in edge would be two components
//! owning one rule — which is the failure this codebase keeps paying for, and
//! the reason [`Rung`] names those rungs without implementing them: the ladder
//! is a shared vocabulary for diagnosis, not a claim about who executes each
//! step.
//!
//! # Multi-hop is free, and that is load-bearing
//!
//! A node publishes its RNS transport key on the `TransportDestination` plane.
//! Once discovery yields that, **Reticulum routes to it across however many hops
//! separate the two nodes** — edge does not implement relaying, path discovery,
//! or a DHT to make contact work at range.
//!
//! This is why the hash-first directory (#552) does not need multi-hop hash
//! propagation to deliver contact: what has to travel is the *destination*, and
//! the transport already carries it. A node one hop from a body-holder can
//! discover anyone that holder knows, and then reach them directly at any
//! distance.
//!
//! # Every rung logs, and says what to do
//!
//! The ladder is diagnosed from logs, because its failures are distributed: the
//! rung that breaks is usually not on the node you are looking at. So each rung
//! emits a structured event with the same shape — step, subject, outcome — and a
//! failure names the ACTIONABLE cause, not the mechanical one. "no transport
//! destination for X: it has not announced, or this node has not admitted its
//! announce" beats "lookup returned None".

use std::fmt;

/// What a `key_id` names.
///
/// Three identifier types reach this surface — a fedID, a nodeID, an agentID —
/// and a caller usually holds one without knowing which. `key_id` is
/// `"<label>-<fingerprint>"` and the label is operator-chosen, so it is NOT a
/// reliable discriminator: `frank-laptop-a3k…` could be anything. The directory
/// is the authority, via `identity_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityKind {
    /// A person. The party that CONSENTS.
    Person,
    /// A node. The party you actually reach over the wire.
    Node,
    /// An agent. Owned by a person, and cannot consent on their behalf.
    Agent,
    /// Something else in the directory — steward, accord holder, partner.
    Other(String),
}

impl IdentityKind {
    #[must_use]
    pub fn from_identity_type(t: &str) -> Self {
        match t {
            "user" => Self::Person,
            "node" => Self::Node,
            "agent" => Self::Agent,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Who you are talking to, and what you actually contact.
///
/// The two are DIFFERENT and the split is the footgun this type exists to
/// remove. A person consents; a node is reachable. Collapsing them lets a caller
/// send a consent request to a node (nobody is there to accept it) or try to
/// open a link to a person (they have no transport key), and both fail in ways
/// that look like the network.
///
/// Whatever identifier you started from — fedID, nodeID, agentID — you end up
/// here, so the rest of the ladder is written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The person. Who consents, and who a conversation is *with*.
    pub fed_id: String,
    /// Their nodes. What a contact request is actually delivered to, and where
    /// Reticulum routes — across as many hops as separate you.
    pub nodes: Vec<String>,
    /// Which identifier the caller supplied, so a log line can say how it got
    /// here. A stall on a nodeID and the same stall on its owner's fedID are
    /// different situations to an operator.
    pub resolved_from: IdentityKind,
}

/// The directory reads resolution needs. A trait so the ladder is testable
/// without standing up persist — the resolution rules are the part that gets
/// this wrong, not the SQL.
#[async_trait::async_trait]
pub trait DirectoryLens: Send + Sync {
    /// `identity_type` for a key, or `None` if the directory has never seen it.
    async fn identity_type_of(&self, key_id: &str) -> Option<String>;
    /// The person who owns this node or agent.
    async fn owner_of(&self, key_id: &str) -> Option<String>;
    /// Every node that person owns.
    async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String>;

    /// CIRISEdge#552 — ask for a key's BODY on demand, returning whether a
    /// fetch was actually queued.
    ///
    /// A hash-first server holds this key's hash without its body, so
    /// `identity_type_of` answers `None` for a key the node demonstrably knows
    /// about. Reporting that as "wait for convergence" would be advice that
    /// never comes true: bulk convergence is exactly what hash-first suppressed.
    /// The fetch reuses the missing-signer queue — a resolution miss and a
    /// stalled admission want the identical thing, a `Key` body — so it drains
    /// through the same Key Pull on the next round.
    ///
    /// Defaults to `false`: a node holding bodies has nothing to request, and
    /// its miss really is "not announced yet".
    async fn request_key_body(&self, _key_id: &str) -> bool {
        false
    }

    /// CIRISEdge#552 — can this node read its directory at all?
    ///
    /// Separates "the key is absent" from "the local read failed", which
    /// `identity_type_of` reports identically as `None`. Only the first is
    /// repairable by a peer; treating the second as absence emits a Pull no
    /// reply can satisfy while telling an operator to wait for a round that
    /// will not help.
    ///
    /// Defaults to `true` — a lens with no backend to fail.
    async fn directory_readable(&self) -> bool {
        true
    }
}

/// Resolve any identifier to the person and the nodes that reach them.
///
/// The rule is one sentence: **whatever you hand me, I find the person, then
/// their nodes.** A nodeID and an agentID resolve through their owner; a fedID
/// is already the person.
///
/// A stall here is nearly always `NotYetDiscovered`, which is the honest reading
/// of "the directory has not converged on this key yet" — it is not an error and
/// it fixes itself.
///
/// # Errors
/// [`LadderStall::NotYetDiscovered`] when the directory does not yet know the
/// key, its owner, or any node to reach.
pub async fn resolve(lens: &dyn DirectoryLens, any_id: &str) -> Result<Subject, LadderStall> {
    resolve_inner(lens, any_id, FetchOnMiss::Yes).await
}

/// May a resolution miss QUEUE a network fetch for the identifier?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchOnMiss {
    Yes,
    /// The caller already holds the key — a self-contained fedcode carries it —
    /// so a Pull would ask the mesh for something sitting in the caller's hand.
    /// Worse than redundant: contact lookups share the bounded missing-signer
    /// queue, so repeated direct-code contacts would displace genuine signer
    /// recovery.
    No,
}

async fn resolve_inner(
    lens: &dyn DirectoryLens,
    any_id: &str,
    fetch_on_miss: FetchOnMiss,
) -> Result<Subject, LadderStall> {
    let stall = || LadderStall::NotYetDiscovered {
        fed_id: any_id.to_owned(),
    };
    // CIRISEdge#552 — before calling a miss "not announced yet", ask whether
    // this node is merely holding the hash. If a fetch is queued the remedy is
    // different and the wait is bounded, so the stall must say so; a caller
    // told to wait for an announce that already happened waits forever.
    let Some(identity_type) = lens.identity_type_of(any_id).await else {
        // A local read failure is not an absence. Check before queueing: a Pull
        // cannot repair a backend this node cannot read, and reporting
        // `BodyFetchQueued` would promise a remedy that never arrives.
        if !lens.directory_readable().await {
            return Err(LadderStall::DirectoryUnreadable {
                key_id: any_id.to_owned(),
            });
        }
        return Err(
            if fetch_on_miss == FetchOnMiss::Yes && lens.request_key_body(any_id).await {
                LadderStall::BodyFetchQueued {
                    key_id: any_id.to_owned(),
                }
            } else {
                stall()
            },
        );
    };
    let kind = IdentityKind::from_identity_type(identity_type.as_str());

    let fed_id = match &kind {
        IdentityKind::Person => any_id.to_owned(),
        // A node or agent cannot consent; its OWNER does. Resolving through the
        // owner is what makes "add frank-laptop as a contact" mean "add Frank".
        IdentityKind::Node | IdentityKind::Agent => match lens.owner_of(any_id).await {
            Some(owner) => owner,
            None => {
                // The readability probe runs only when the KEY lookup misses. A
                // key that resolves and an owner that does not can still be a
                // local backend failure, and reporting that as
                // `NotYetDiscovered` tells an operator to wait for replication
                // to repair a disk.
                return Err(if lens.directory_readable().await {
                    stall()
                } else {
                    LadderStall::DirectoryUnreadable {
                        key_id: any_id.to_owned(),
                    }
                });
            }
        },
        // A steward or accord holder is not a contactable person. TERMINAL, not
        // `NotYetDiscovered`: the latter self-resolves, so a caller would retry
        // forever against something that will never become contactable — and the
        // remedy ("wait for convergence") would be advice that never comes true.
        IdentityKind::Other(t) => {
            return Err(LadderStall::NotContactable {
                key_id: any_id.to_owned(),
                identity_type: t.clone(),
            })
        }
    };

    let nodes = lens.nodes_owned_by(&fed_id).await;
    if nodes.is_empty() && !lens.directory_readable().await {
        return Err(LadderStall::DirectoryUnreadable { key_id: fed_id });
    }
    if nodes.is_empty() {
        // Known person, nothing to reach. Distinct from "unknown key", and the
        // remedy is the same: wait for their announce to replicate.
        return Err(LadderStall::NotYetDiscovered { fed_id });
    }
    Ok(Subject {
        fed_id,
        nodes,
        resolved_from: kind,
    })
}

/// Where a contact request came from — a pasted code, or a bare identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactInputSource {
    /// A `CIRIS-V…` fedcode. **Self-contained**: it carries the public key, so
    /// it works for someone the directory has never heard of.
    Code,
    /// A bare `key_id`. Resolvable only if the directory already knows it,
    /// which for a stranger it does not and will not.
    Identifier,
}

/// The key material a pasted code carries, for the caller to ADMIT.
///
/// This is the whole reason a code exists. For a stranger the directory can
/// supply nothing — that is what "stranger" means — so the pubkey has to travel
/// with the invitation. Registering it is what turns a decoded code into a
/// contact whose signatures this node can verify.
///
/// Edge deliberately does not register it: admission is the host's gate
/// (`register_federation_key`), and edge is the substrate that hands it a
/// verified, typed value rather than a string to re-parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeAdmission {
    /// The federation address to register the key under. Verified to be derived
    /// from `pubkey_ed25519_base64`.
    pub key_id: String,
    /// Ed25519 public key, base64 standard, raw 32 bytes.
    pub pubkey_ed25519_base64: String,
    /// `"user"` / `"agent"` / `"node"` / `"family"` / `"community"` — the wire
    /// string persist's `identity_type` expects.
    pub identity_type: &'static str,
    /// Optional transport hint (e.g. a public base URL) the sender offered.
    pub transport_hint: Option<String>,
    /// Display-only alias the sender suggested. Never an authorization input.
    pub alias_hint: Option<String>,
}

/// One pasted string, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCandidate {
    /// The federation address this refers to, either decoded from the code or
    /// taken verbatim.
    pub key_id: String,
    /// What kind of entity it names.
    pub kind: IdentityKind,
    /// How it arrived.
    pub source: ContactInputSource,
    /// `Some` only for a code: the material to admit before this contact can be
    /// verified. `None` for a bare identifier — there is nothing new to admit.
    pub admission: Option<CodeAdmission>,
}

/// Classify what a person typed into "Add contact" — **a code or an ID**.
///
/// # Why this exists
///
/// The two inputs are not interchangeable and must never be confused. A code
/// carries a public key; an identifier is a lookup into a directory that, for a
/// stranger, will never contain them. Posting a code into a `key_id` field
/// produces `unknown_fed_id` — a correct answer to the wrong question, and
/// exactly the failure CIRISEdge#526 reported: three doors, all shut, because
/// nothing decoded the one input that carries what a stranger needs.
///
/// Confusion is impossible here rather than merely discouraged: a fedcode has an
/// unambiguous `CIRIS-V…` prefix, so anything carrying it is a code **or an
/// error** — never silently demoted to an identifier.
///
/// # Security
///
/// A code is not a credential and this function does not treat it as one.
/// `fedcode::decode` verifies a CRC, which proves only that the code survived
/// transit intact; the sender authored every byte and can claim any `key_id`.
/// So the claimed `key_id` is re-derived from the pubkey the code carries, and a
/// mismatch is refused as [`LadderStall::CodeIdentityMismatch`]. Without that
/// check, "paste a code to add a contact" is an impersonation primitive:
/// register an attacker's key under a victim's address and every signature the
/// victim should make becomes forgeable.
///
/// What it still does NOT establish: that the human who sent the code is who
/// they say. Nothing in a self-issued code can. That is what the out-of-band
/// exchange and the receiving human's judgement are for.
///
/// # Errors
///
/// [`LadderStall::MalformedCode`] for a `CIRIS-V…` string that will not decode,
/// and [`LadderStall::CodeIdentityMismatch`] when the code's key does not derive
/// its claimed address. Both TERMINAL — neither improves by retrying.
pub fn parse_contact_input(raw: &str) -> Result<ContactCandidate, LadderStall> {
    let trimmed = raw.trim();

    if !looks_like_fedcode(trimmed) {
        return Ok(ContactCandidate {
            key_id: trimmed.to_owned(),
            // A bare identifier says nothing about what it names; only the
            // directory's `identity_type` can, and `resolve` asks it.
            kind: IdentityKind::Other(String::new()),
            source: ContactInputSource::Identifier,
            admission: None,
        });
    }

    let decoded =
        ciris_verify_core::fedcode::decode(trimmed).map_err(|e| LadderStall::MalformedCode {
            detail: e.to_string(),
        })?;

    verify_code_binds_its_key(&decoded)?;

    let identity_type = decoded.kind.as_str();
    Ok(ContactCandidate {
        key_id: decoded.key_id.clone(),
        kind: IdentityKind::from_identity_type(identity_type),
        source: ContactInputSource::Code,
        admission: Some(CodeAdmission {
            key_id: decoded.key_id,
            pubkey_ed25519_base64: decoded.pubkey_ed25519_base64,
            identity_type,
            transport_hint: decoded.transport_hint,
            alias_hint: decoded.alias_hint,
        }),
    })
}

/// Does this string announce itself as a fedcode?
///
/// Prefix-only, and deliberately so: the question is "did the user intend a
/// code", not "is this code valid". A malformed code must surface AS a malformed
/// code, never fall through to be tried as an identifier — falling through is
/// what turns a bad paste into a confusing `unknown_fed_id`.
#[must_use]
pub fn looks_like_fedcode(raw: &str) -> bool {
    // `trim()` already strips Unicode `White_Space` from both ends.
    let up = raw.trim().to_ascii_uppercase();
    let Some(rest) = up.strip_prefix("CIRIS-V") else {
        return false;
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || !rest[digits.len()..].starts_with('-') {
        return false;
    }
    // A version-shaped PREFIX is not enough: a label is operator-chosen and may
    // literally be `CIRIS-V2`, making `CIRIS-V2-<fingerprint>` a perfectly
    // valid IDENTIFIER. Anything that parses as a well-formed identifier is
    // one, whatever it looks like — so the discriminator is the complete
    // structure, not the prefix.
    !is_well_formed_identifier(raw)
}

/// Does this parse as a `label-fingerprint` federation key_id?
///
/// The fingerprint is exactly [`KEY_ID_FINGERPRINT_LEN`] base32 characters
/// (`derive_key_id`), and a label may contain anything else including hyphens —
/// so the fingerprint is the LAST hyphen-separated segment. A fedcode body is
/// a base32 payload carrying a 32-byte pubkey and a CRC; it is far longer than
/// a fingerprint and cannot be mistaken for one.
///
/// [`KEY_ID_FINGERPRINT_LEN`]: ciris_verify_core::fedcode::KEY_ID_FINGERPRINT_LEN
#[must_use]
fn is_well_formed_identifier(raw: &str) -> bool {
    let trimmed = raw.trim();
    let Some((label, fingerprint)) = trimmed.rsplit_once('-') else {
        return false;
    };
    if label.is_empty() {
        return false;
    }
    fingerprint.len() == ciris_verify_core::fedcode::KEY_ID_FINGERPRINT_LEN
        && fingerprint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != '1' && c != '8' && c != '9')
}

/// Re-derive the claimed `key_id` from the carried pubkey and require a match.
///
/// `derive_key_id(label, pubkey)` is `"<label>-<fingerprint>"` where the
/// fingerprint is the first [`KEY_ID_FINGERPRINT_LEN`] base32 chars of
/// `sha256(pubkey)`. The label is operator-chosen cleartext and proves nothing;
/// the fingerprint is the binding. So the label is taken from the claim and only
/// the fingerprint half is actually verified — which is the correct reading of
/// the format, and the reason a re-derivation rather than a substring compare.
///
/// [`KEY_ID_FINGERPRINT_LEN`]: ciris_verify_core::fedcode::KEY_ID_FINGERPRINT_LEN
fn verify_code_binds_its_key(
    decoded: &ciris_verify_core::fedcode::FedCode,
) -> Result<(), LadderStall> {
    use base64::Engine as _;

    let mismatch = || LadderStall::CodeIdentityMismatch {
        claimed_key_id: decoded.key_id.clone(),
        derived_key_id: "<undecodable pubkey>".to_string(),
    };

    let pubkey = base64::engine::general_purpose::STANDARD
        .decode(decoded.pubkey_ed25519_base64.as_bytes())
        .map_err(|_| mismatch())?;
    // Exactly 32 bytes, or it is not an Ed25519 public key.
    //
    // `derive_key_id` hashes whatever it is handed, so a sender could derive a
    // matching id from a one-byte value and receive a "verified"
    // `CodeAdmission` whose documented contract says raw-32. The host
    // registration gate would then reject it — a confusing failure one layer
    // too late, and a needless admission attempt on material this layer
    // already knows is malformed.
    if pubkey.len() != 32 {
        return Err(LadderStall::MalformedCode {
            detail: format!(
                "pubkey is {} bytes; an Ed25519 public key is exactly 32",
                pubkey.len()
            ),
        });
    }

    // The label is everything before the LAST hyphen: labels may contain
    // hyphens, the fingerprint never does.
    let label = decoded
        .key_id
        .rsplit_once('-')
        .map_or("", |(label, _fingerprint)| label);

    let derived = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);
    if derived == decoded.key_id {
        Ok(())
    } else {
        Err(LadderStall::CodeIdentityMismatch {
            claimed_key_id: decoded.key_id.clone(),
            derived_key_id: derived,
        })
    }
}

/// The outcome of "Add contact", given a code or an ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactResolution {
    /// The directory already knows them. Nothing to admit; proceed to the
    /// consent rung. A re-pasted code for someone already admitted lands here
    /// too, so pasting twice is idempotent rather than an error.
    Known(Subject),
    /// A stranger, from a code — and the code is SUFFICIENT.
    ///
    /// `subject` is built from the code itself, not from the directory, because
    /// a code carries what the directory would have supplied. Admitting
    /// `admission` registers the key so the stranger's signatures verify;
    /// nothing further needs to converge first.
    ///
    /// **`subject.nodes` is empty**: a user code names a person, not their
    /// nodes, and a stranger has no owner bindings here. Reach them through
    /// [`CodeAdmission::transport_hint`], which travels with the key for
    /// exactly this reason. No hint means the code gives you an identity you
    /// can verify and no way to contact them yet.
    ///
    /// This is the shape the earlier `AdmitThenRetry` got wrong. It told the
    /// caller to admit and re-resolve, but a re-resolve runs
    /// `nodes_owned_by(fed_id)` against the directory — and a stranger has no
    /// owner-binding attestations there, so the retry returned
    /// `NotYetDiscovered` forever. Admitting a key never creates an ownership
    /// graph. The code was always the contact.
    ReadyFromCode {
        subject: Subject,
        admission: Box<CodeAdmission>,
    },
}

/// **The one call "Add contact" needs.** Takes a code or an ID and says what to
/// do next.
///
/// # The gap this closes (CIRISEdge#526)
///
/// Two people who have never met could not become contacts through the UI at
/// all. Pasting a code posted the raw string as a `key_id` and was refused
/// `unknown_fed_id`; the peer-claim surface is for claiming your OWN node; and
/// a directory lookup cannot help someone who never announced.
///
/// A fedcode closes it because it is self-contained: identity, public key, and
/// a transport hint travel together, so it works precisely where the directory
/// cannot — including for a person who opted out of announcing entirely.
///
/// # Contract
///
/// * A **bare identifier** resolves through the directory exactly as before.
/// * A **code for someone already known** resolves to [`Known`], so re-pasting
///   is safe and never re-admits a registered key.
/// * A **code for a stranger** resolves to [`ReadyFromCode`] with a usable
///   [`Subject`] — no second round-trip, no waiting.
/// * A code naming something that is not a contactable person — a family or
///   community roster — is [`LadderStall::NotContactable`] here, rather than
///   instructing the caller to admit a key and then discover the same terminal
///   answer on retry.
///
/// Admission stays the host's: edge hands over a verified, typed
/// [`CodeAdmission`] and the caller feeds its own `register_federation_key`
/// gate. Edge never registers a key on the strength of a pasted string.
///
/// [`Known`]: ContactResolution::Known
/// [`ReadyFromCode`]: ContactResolution::ReadyFromCode
///
/// # Errors
///
/// Every [`LadderStall`] `resolve` can produce, plus
/// [`LadderStall::MalformedCode`] and [`LadderStall::CodeIdentityMismatch`] for
/// a bad or forged code.
pub async fn resolve_contact(
    lens: &dyn DirectoryLens,
    raw: &str,
) -> Result<ContactResolution, LadderStall> {
    let candidate = parse_contact_input(raw)?;

    // A roster is not a person. Refuse BEFORE telling anyone to admit a key:
    // `resolve` treats these as terminal, so an admit-then-retry would end at
    // exactly this answer having registered a key for nothing.
    if let Some(admission) = candidate.admission.as_ref() {
        if is_roster_code_kind(admission.identity_type) {
            return Err(LadderStall::NotContactable {
                key_id: candidate.key_id,
                identity_type: admission.identity_type.to_string(),
            });
        }
    }

    // Ask the directory first, whatever the input was: a code for someone
    // already admitted must behave like the identifier for the same person.
    // A code carries the key, so a miss must not queue a fetch for it: the
    // host can admit what it already holds, and the recovery queue is bounded
    // and shared with genuine missing-signer work.
    let fetch_on_miss = if candidate.admission.is_some() {
        FetchOnMiss::No
    } else {
        FetchOnMiss::Yes
    };
    match resolve_inner(lens, &candidate.key_id, fetch_on_miss).await {
        Ok(subject) => Ok(ContactResolution::Known(subject)),
        Err(stall) => {
            let Some(admission) = candidate.admission.clone() else {
                log_rung(Rung::Discover, &candidate.key_id, Some(&stall));
                return Err(stall);
            };
            // A terminal stall stays terminal even with a code in hand: a code
            // carries a key, and a key does not make a steward into a person.
            if !matches!(
                stall,
                LadderStall::NotYetDiscovered { .. } | LadderStall::BodyFetchQueued { .. }
            ) {
                log_rung(Rung::Discover, &candidate.key_id, Some(&stall));
                return Err(stall);
            }
            // A STRANGER's node/agent code cannot produce a person. `resolve`
            // routes a KNOWN node through `owner_of`, which is why the known
            // case above is fine; a stranger has no owner binding here, so
            // there is nothing to route to. Writing the node's key into
            // `Subject.fed_id` would aim the consent rung at a machine.
            if !code_alone_yields_a_person(admission.identity_type) {
                let stall = LadderStall::NotContactable {
                    key_id: candidate.key_id.clone(),
                    identity_type: admission.identity_type.to_string(),
                };
                log_rung(Rung::Discover, &candidate.key_id, Some(&stall));
                return Err(stall);
            }
            tracing::info!(
                key_id = %candidate.key_id,
                identity_type = %admission.identity_type,
                has_transport_hint = admission.transport_hint.is_some(),
                "contact: stranger from a code — the directory does not know \
                 them, which is expected; the code carries what it cannot \
                 (CIRISEdge#526)"
            );
            Ok(ContactResolution::ReadyFromCode {
                subject: subject_from_code(&candidate, &admission),
                admission: Box::new(admission),
            })
        }
    }
}

/// Is this code a ROSTER rather than anything contactable?
///
/// `family` and `community` codes are perfectly valid — [`FedKind`] encodes
/// them and a group can hand one out — they are simply not a party you open a
/// conversation with. Refused before the caller is told to admit anything.
///
/// [`FedKind`]: ciris_verify_core::fedcode::FedKind
#[must_use]
fn is_roster_code_kind(identity_type: &str) -> bool {
    matches!(identity_type, "family" | "community")
}

/// Can a code of this `identity_type` yield a [`Subject`] **on its own**?
///
/// Only `user`. This is narrower than "can be contacted" and the difference is
/// the invariant [`Subject`] exists to hold: `fed_id` is *the person who
/// consents*, and a node or an agent cannot consent — its OWNER does.
///
/// For a KNOWN node or agent that is fine, because [`resolve`] routes them
/// through `owner_of` and returns the owner as `fed_id`. For a STRANGER it is
/// not: a stranger has no owner-binding attestation in this node's directory —
/// that is what "stranger" means — so there is no owner to route to, and
/// writing the node's key into the person slot would send a consent request to
/// a machine. Nobody is there to accept it.
///
/// So a stranger's node/agent code is terminal, and its remedy is the true
/// one: get the OWNER's code.
#[must_use]
fn code_alone_yields_a_person(identity_type: &str) -> bool {
    identity_type == "user"
}

/// Build the [`Subject`] a code yields on its own.
///
/// Only reached for a `user` code (see [`code_alone_yields_a_person`]), so
/// `fed_id` holds a person — the invariant the type is for.
///
/// # `nodes` is EMPTY, deliberately
///
/// A user code names a PERSON. It does not name their nodes, and this node has
/// no owner-binding attestations for a stranger, so their node set is genuinely
/// unknown — that is what "stranger" means.
///
/// An earlier revision put the person's own `key_id` in `nodes`. That was
/// wrong twice over: `nodes` holds NODE ids, and `RouteLens::has_destination`
/// resolves them as such, so a caller following the ladder would have tried to
/// dial a person key as though it were a node. Filling a field with the only
/// value in hand is how a type stops meaning what it says.
///
/// Reachability for a code comes from [`CodeAdmission::transport_hint`], which
/// travels with the key precisely because the directory cannot supply it. When
/// the hint is absent the code gives identity and no way to reach them — worth
/// stating plainly rather than papering over with a node id that is not one.
fn subject_from_code(candidate: &ContactCandidate, admission: &CodeAdmission) -> Subject {
    debug_assert!(
        code_alone_yields_a_person(admission.identity_type),
        "subject_from_code must only build a Subject for a person: fed_id is \
         the party who consents"
    );
    Subject {
        fed_id: candidate.key_id.clone(),
        nodes: Vec::new(),
        resolved_from: candidate.kind.clone(),
    }
}

/// A rung of the ladder. Stable strings — an operator greps these, and a
/// dashboard groups by them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// This node published its own identity and transport key.
    Announce,
    /// Resolve a fedID to something reachable.
    Discover,
    /// Ask a peer to be a contact. Point-to-point; leaves no federation trace.
    RequestContact,
    /// Grant replication consent — the contact becomes real and replicable.
    Consent,
    /// Open or find the 2-member community that carries the conversation.
    OpenChat,
    /// Put a message in it.
    SendMessage,
}

impl Rung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Announce => "announce",
            Self::Discover => "discover",
            Self::RequestContact => "request_contact",
            Self::Consent => "consent",
            Self::OpenChat => "open_chat",
            Self::SendMessage => "send_message",
        }
    }

    /// The rung before this one. A failure is nearly always the previous rung
    /// not having completed, so the diagnostic can say where to look.
    #[must_use]
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Announce => None,
            Self::Discover => Some(Self::Announce),
            Self::RequestContact => Some(Self::Discover),
            Self::Consent => Some(Self::RequestContact),
            Self::OpenChat => Some(Self::Consent),
            Self::SendMessage => Some(Self::OpenChat),
        }
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a rung did not complete — in terms of what an operator can do about it.
///
/// Deliberately NOT a wrapper over the underlying error types. A caller that
/// needs the mechanical cause has the log; this is the axis a human acts on, and
/// keeping it small is what makes it usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderStall {
    /// The subject has not announced, or this node has not admitted its
    /// announce yet. Resolves itself as replication converges.
    NotYetDiscovered { fed_id: String },
    /// Discovered, but nothing answered. The peer may be offline; RNS will route
    /// when it returns.
    Unreachable { fed_id: String },
    /// The peer has not consented. Not an error — the ladder is waiting on a
    /// human, and no amount of retrying changes that.
    AwaitingConsent { fed_id: String },
    /// This node has not consented to the peer. The reciprocal of the above.
    ConsentNotGranted { fed_id: String },
    /// The rung before this one has not completed.
    PriorRungIncomplete { rung: Rung, prior: Rung },
    /// CIRISEdge#526 — the input looked like a fedcode (it carries the
    /// `CIRIS-V…` prefix) but did not decode. TERMINAL: a corrupted or
    /// truncated paste does not repair itself, and treating it as an identifier
    /// is the bug this variant exists to prevent — that is what produced
    /// `unknown_fed_id` for a perfectly good code.
    MalformedCode { detail: String },
    /// CIRISEdge#526 — the code's `key_id` is NOT derived from the public key
    /// it carries. TERMINAL, and a security event rather than a typo.
    ///
    /// `fedcode::decode` verifies a CRC, which proves the code was not
    /// corrupted in transit. It proves nothing about authorship: the sender
    /// builds every byte, so a code can claim any `key_id` while carrying its
    /// own key. Admitting that would register an attacker's pubkey under a
    /// victim's federation address — every signature the victim is supposed to
    /// make becomes forgeable by the holder of that code.
    CodeIdentityMismatch {
        claimed_key_id: String,
        derived_key_id: String,
    },
    /// CIRISEdge#552 — the local directory could not be read. NOT
    /// self-resolving: no peer reply repairs a local backend failure, so
    /// retrying is the one thing that cannot help.
    DirectoryUnreadable { key_id: String },
    /// CIRISEdge#552 — this node knows the key as a HASH and has queued a fetch
    /// for its body. Self-resolving, but for a different reason than
    /// [`Self::NotYetDiscovered`]: nothing is waiting on the subject to
    /// announce, only on this node's next Key round.
    BodyFetchQueued { key_id: String },
    /// The key resolves, but not to anything a person can be contacted through
    /// — a steward, an accord holder, a partner record. TERMINAL: no amount of
    /// convergence turns one of these into a contactable person, so a caller
    /// that retries is retrying forever.
    NotContactable {
        key_id: String,
        identity_type: String,
    },
}

impl LadderStall {
    /// What an operator should do. Every arm answers it — a stall with no
    /// remedy is a bug report, not a diagnostic.
    #[must_use]
    pub fn remedy(&self) -> String {
        match self {
            Self::NotYetDiscovered { fed_id } => format!(
                "no transport destination for {fed_id}: either it has not announced, \
                 or this node has not admitted its announce yet. Check that the peer \
                 is running and that a replication round with it has completed."
            ),
            Self::Unreachable { fed_id } => format!(
                "{fed_id} is discoverable but did not answer. It is probably offline; \
                 Reticulum will route to it across the mesh when it returns. No action \
                 needed unless it stays unreachable while known to be up."
            ),
            Self::AwaitingConsent { fed_id } => format!(
                "waiting for {fed_id} to accept the contact request. This is a person, \
                 not a timeout — retrying does not help and re-sending is spam."
            ),
            Self::ConsentNotGranted { fed_id } => format!(
                "this node has not granted replication consent to {fed_id}. Accept the \
                 contact request to make the conversation replicable in both directions."
            ),
            Self::NotContactable {
                key_id,
                identity_type,
            } => format!(
                "{key_id} is registered as identity_type={identity_type}, which is \
                 not a person and cannot hold a conversation. Contact its OWNER \
                 instead, or check that the identifier is the one you meant — this \
                 will not resolve by waiting."
            ),
            Self::MalformedCode { detail } => format!(
                "that looks like a CIRIS code but does not decode ({detail}). Ask \
                 for it again — a partial copy/paste is the usual cause, and the \
                 code is self-validating so a truncated one can always be told \
                 from a good one. It will NOT start working by retrying."
            ),
            Self::CodeIdentityMismatch {
                claimed_key_id,
                derived_key_id,
            } => format!(
                "REFUSED: that code claims to be {claimed_key_id}, but the public \
                 key inside it derives {derived_key_id}. A code proves only that \
                 it was not corrupted in transit — anyone can build one claiming \
                 any name. Do not admit it. If the sender is genuine, they should \
                 re-issue the code from the node that actually holds the key."
            ),
            Self::DirectoryUnreadable { key_id } => format!(
                "the local federation directory could not be read while resolving \
                 {key_id}. This is a LOCAL fault — no peer reply repairs it and \
                 retrying will not help. Check the node's persist backend \
                 (disk, permissions, migration state) before looking at the mesh."
            ),
            Self::BodyFetchQueued { key_id } => format!(
                "{key_id} is known to this node as a hash, but its body was not \
                 held — this node runs hash-first retention. A fetch is queued and \
                 goes out on the next Key replication round; retry the lookup \
                 after it. Waiting for the peer to announce would NOT help: it \
                 already did."
            ),
            Self::PriorRungIncomplete { rung, prior } => format!(
                "{rung} cannot proceed because {prior} has not completed. Look at the \
                 {prior} rung on this node first — a ladder failure is nearly always \
                 the rung before it."
            ),
        }
    }

    /// Is this a stall the ladder resolves on its own?
    ///
    /// The distinction that matters operationally: a `false` here means the
    /// ladder is waiting on a HUMAN, and an operator watching a dashboard should
    /// not treat it as a fault to escalate.
    #[must_use]
    pub const fn self_resolving(&self) -> bool {
        match self {
            Self::NotYetDiscovered { .. }
            | Self::Unreachable { .. }
            // The fetch is queued; the next Key round carries it.
            | Self::BodyFetchQueued { .. } => true,
            Self::AwaitingConsent { .. }
            | Self::ConsentNotGranted { .. }
            | Self::PriorRungIncomplete { .. }
            // Terminal by nature: a steward does not become a person.
            | Self::NotContactable { .. }
            // A local backend fault: the one stall retrying cannot fix.
            | Self::DirectoryUnreadable { .. }
            // A bad paste does not repair itself, and a mismatched code is a
            // forgery attempt — retrying it is the last thing anyone should do.
            | Self::MalformedCode { .. }
            | Self::CodeIdentityMismatch { .. } => false,
        }
    }
}

/// Emit the one structured line a rung produces.
///
/// One shape for every rung, so `step=` is greppable and a dashboard can group
/// without parsing prose. Success is INFO because walking the ladder is a rare,
/// meaningful event — not a hot path — and the first question after "it did not
/// work" is always which rungs DID.
pub fn log_rung(rung: Rung, fed_id: &str, stall: Option<&LadderStall>) {
    match stall {
        None => tracing::info!(
            step = rung.as_str(),
            fed_id,
            outcome = "ok",
            "contact ladder: {rung} completed for {fed_id}"
        ),
        Some(s) if s.self_resolving() => tracing::info!(
            step = rung.as_str(),
            fed_id,
            outcome = "waiting",
            remedy = %s.remedy(),
            "contact ladder: {rung} is waiting — this resolves itself"
        ),
        Some(s) => tracing::warn!(
            step = rung.as_str(),
            fed_id,
            outcome = "stalled",
            remedy = %s.remedy(),
            "contact ladder: {rung} stalled and needs someone to act"
        ),
    }
}

/// [`RouteLens`] over the live Reticulum transport.
///
/// This is the half unit tests cannot reach. Resolution is pure logic and is
/// tested against a fake lens; whether a real node can actually address a peer
/// depends on announces having arrived and routes having been admitted, which is
/// only true in a running mesh. `knows_peer` is the transport's own readback for
/// "can this node address that key right now" — the same question the send path
/// asks before it dials.
#[cfg(feature = "transport-reticulum")]
pub struct ReticulumRoutes<'a> {
    transport: &'a crate::transport::reticulum::ReticulumTransport,
}

#[cfg(feature = "transport-reticulum")]
impl<'a> ReticulumRoutes<'a> {
    #[must_use]
    pub fn new(transport: &'a crate::transport::reticulum::ReticulumTransport) -> Self {
        Self { transport }
    }
}

#[cfg(feature = "transport-reticulum")]
#[async_trait::async_trait]
impl RouteLens for ReticulumRoutes<'_> {
    async fn has_destination(&self, node_key_id: &str) -> bool {
        self.transport.knows_peer(node_key_id).await
    }
}

/// A resolved subject that is actually CONTACTABLE.
///
/// [`resolve`] proves someone owns nodes. This proves at least one of them can
/// be reached — which is a different claim, and the one a caller acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    pub subject: Subject,
    /// The nodes with a transport destination this node can dial. Never empty.
    pub reachable: Vec<String>,
}

/// Resolve an identifier AND confirm somewhere to send.
///
/// `nodes_owned_by` proves ownership, not reachability: a person can own nodes
/// this node has no route to, and reporting that as discovered hands the caller
/// a `Subject` whose every send fails. The distinction matters because the two
/// have different remedies — an unknown key waits for the directory, an
/// unreachable node waits for the peer.
///
/// Once a destination IS known, distance stops mattering: a node publishes its
/// RNS transport key, and Reticulum routes to it across however many hops
/// separate the two. Edge implements no relaying to make that work.
///
/// # Errors
/// [`LadderStall::NotYetDiscovered`] if the identifier does not resolve;
/// [`LadderStall::Unreachable`] if it resolves to a person whose nodes have no
/// route yet.
pub async fn discover(
    lens: &dyn DirectoryLens,
    routes: &dyn RouteLens,
    any_id: &str,
) -> Result<Discovered, LadderStall> {
    // Log the RESOLUTION stall here rather than `?`-ing past it. The stalls
    // that reach this line — an unknown key, a queued body fetch, a missing
    // owner, a non-contactable identity — are the ordinary ones in a
    // distributed directory, and returning silently left `step=discover` in the
    // diagnostic stream only for route failures and successes. The rung that
    // fails most is then the one an operator cannot see.
    let subject = match resolve(lens, any_id).await {
        Ok(subject) => subject,
        Err(stall) => {
            log_rung(Rung::Discover, any_id, Some(&stall));
            return Err(stall);
        }
    };
    let mut reachable = Vec::new();
    for node in &subject.nodes {
        if routes.has_destination(node).await {
            reachable.push(node.clone());
        }
    }
    if reachable.is_empty() {
        let stall = LadderStall::Unreachable {
            fed_id: subject.fed_id.clone(),
        };
        log_rung(Rung::Discover, &subject.fed_id, Some(&stall));
        return Err(stall);
    }
    log_rung(Rung::Discover, &subject.fed_id, None);
    Ok(Discovered { subject, reachable })
}

/// Whether this node has a transport destination for a peer.
///
/// Separate from [`DirectoryLens`] because it is a TRANSPORT question, not a
/// directory one: the answer changes as announces arrive, and conflating them
/// would make discovery look like a directory failure when it is a routing one.
#[async_trait::async_trait]
pub trait RouteLens: Send + Sync {
    async fn has_destination(&self, node_key_id: &str) -> bool;
}

/// The [`DirectoryLens`] over a real persist directory.
///
/// Thin on purpose: every rule that can be got wrong lives in [`resolve`] and is
/// tested without a database. This adapter only says which persist call answers
/// which question.
pub struct PersistLens<'a> {
    directory: &'a dyn ciris_persist::federation::FederationDirectory,
    /// CIRISEdge#552 — where an on-demand body fetch is queued. `None` on a
    /// node that holds bodies: there is nothing to fetch, and the lens must
    /// then answer `request_key_body` with `false` so the stall stays the
    /// honest "not announced yet".
    replication: Option<std::sync::Arc<dyn crate::replication::directory::ReplicationDirectory>>,
}

impl<'a> PersistLens<'a> {
    #[must_use]
    pub fn new(directory: &'a dyn ciris_persist::federation::FederationDirectory) -> Self {
        Self {
            directory,
            replication: None,
        }
    }

    /// Give the lens the replication directory, so a resolution miss on a
    /// hash-first node can queue the body fetch instead of reporting a wait
    /// that never ends.
    #[must_use]
    pub fn with_replication(
        mut self,
        replication: std::sync::Arc<dyn crate::replication::directory::ReplicationDirectory>,
    ) -> Self {
        self.replication = Some(replication);
        self
    }
}

#[async_trait::async_trait]
impl DirectoryLens for PersistLens<'_> {
    async fn identity_type_of(&self, key_id: &str) -> Option<String> {
        self.directory
            .lookup_public_key(key_id)
            .await
            .ok()
            .flatten()
            .map(|record| record.identity_type)
    }

    async fn directory_readable(&self) -> bool {
        // CIRISEdge#552 — an error and an absence were folded together here on
        // the reasoning that both mean "cannot say yet" and share a remedy. They
        // no longer do. An ABSENCE on a hash-first node queues a body fetch and
        // reports `BodyFetchQueued`, whose remedy is "the next Key round carries
        // it". A local backend failure cannot be repaired by any peer, so that
        // remedy is false and the Pull is pointless traffic emitted on every
        // retry. Probing the same read is enough to separate them.
        self.directory.lookup_public_key("").await.is_ok()
    }

    async fn owner_of(&self, key_id: &str) -> Option<String> {
        ciris_persist::federation::admission::owner_of(self.directory, key_id)
            .await
            .ok()
            .flatten()
    }

    async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
        ciris_persist::federation::admission::nodes_owned_by(self.directory, fed_id)
            .await
            .unwrap_or_default()
    }

    async fn request_key_body(&self, key_id: &str) -> bool {
        let Some(replication) = self.replication.as_ref() else {
            return false;
        };
        // Under `Bodies` the signer's Key body replicates on its own and #544
        // admits the row later, so queueing would ask for something already in
        // flight.
        if !crate::replication::retention::should_note_missing_signer(
            replication.retention(crate::replication::protocol::EnvelopeKind::Key),
        ) {
            return false;
        }
        // No delivering peer — a contact lookup is not repairing a row someone
        // sent us — so the name is recorded UNROUTED and offered to successive
        // peers until a CONFERRED one answers. That works because of the axis-3
        // widening: a responder holding `infra:serve` answers an identifier
        // Pull for any subject on a public plane, which is exactly what
        // carrying the directory means. Before that widening this had to return
        // `false`, because no peer would have answered.
        replication.note_missing_signer(
            crate::replication::protocol::EnvelopeKind::Key,
            key_id,
            None,
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{LadderStall, Rung};

    /// A fake directory. The resolution RULES are what get this wrong, not the
    /// SQL, so the tests exercise the rules directly.
    struct FakeLens {
        types: std::collections::HashMap<String, String>,
        owners: std::collections::HashMap<String, String>,
        nodes: std::collections::HashMap<String, Vec<String>>,
    }

    #[async_trait::async_trait]
    impl super::DirectoryLens for FakeLens {
        async fn identity_type_of(&self, key_id: &str) -> Option<String> {
            self.types.get(key_id).cloned()
        }
        async fn owner_of(&self, key_id: &str) -> Option<String> {
            self.owners.get(key_id).cloned()
        }
        async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
            self.nodes.get(fed_id).cloned().unwrap_or_default()
        }
    }

    fn frank() -> FakeLens {
        let mut types = std::collections::HashMap::new();
        types.insert("frank-fed-aaa".into(), "user".into());
        types.insert("frank-laptop-bbb".into(), "node".into());
        types.insert("frank-agent-ccc".into(), "agent".into());
        types.insert("some-steward-ddd".into(), "steward".into());
        let mut owners = std::collections::HashMap::new();
        owners.insert("frank-laptop-bbb".into(), "frank-fed-aaa".into());
        owners.insert("frank-agent-ccc".into(), "frank-fed-aaa".into());
        let mut nodes = std::collections::HashMap::new();
        nodes.insert(
            "frank-fed-aaa".into(),
            vec!["frank-laptop-bbb".into(), "frank-phone-eee".into()],
        );
        FakeLens {
            types,
            owners,
            nodes,
        }
    }

    /// The headline DX property: all three identifier types land on the same
    /// person and the same reachable nodes. A caller holding "a Frank
    /// identifier" does not have to know which one it is.
    #[tokio::test]
    async fn any_identifier_resolves_to_the_same_person_and_nodes() {
        let lens = frank();
        for id in ["frank-fed-aaa", "frank-laptop-bbb", "frank-agent-ccc"] {
            let s = super::resolve(&lens, id).await.expect("{id} must resolve");
            assert_eq!(s.fed_id, "frank-fed-aaa", "{id} must resolve to the PERSON");
            assert_eq!(
                s.nodes.len(),
                2,
                "{id} must yield every node that reaches him"
            );
        }
    }

    /// And it records HOW it got there — a stall on a nodeID and the same stall
    /// on its owner's fedID are different situations to whoever is debugging.
    #[tokio::test]
    async fn the_subject_remembers_which_identifier_it_came_from() {
        let lens = frank();
        let from_node = super::resolve(&lens, "frank-laptop-bbb").await.unwrap();
        assert_eq!(from_node.resolved_from, super::IdentityKind::Node);
        let from_person = super::resolve(&lens, "frank-fed-aaa").await.unwrap();
        assert_eq!(from_person.resolved_from, super::IdentityKind::Person);
    }

    /// An agent cannot consent on its owner's behalf, so addressing one must
    /// resolve to the PERSON. Returning the agent would send a consent request
    /// to something that cannot accept it — and it would look like the peer
    /// simply never answered.
    #[tokio::test]
    async fn an_agent_resolves_to_its_owner_not_itself() {
        let lens = frank();
        let s = super::resolve(&lens, "frank-agent-ccc").await.unwrap();
        assert_eq!(s.fed_id, "frank-fed-aaa");
        assert!(!s.nodes.contains(&"frank-agent-ccc".to_string()));
    }

    /// A steward or accord holder is not a contactable person. Refusing beats
    /// resolving to something that looks addressable and is not.
    #[tokio::test]
    async fn a_non_contactable_identity_type_stalls_rather_than_resolving() {
        let lens = frank();
        let Err(stall) = super::resolve(&lens, "some-steward-ddd").await else {
            panic!("a steward is not a contactable person");
        };
        assert!(
            !stall.self_resolving(),
            "a steward never becomes contactable — a self-resolving stall would \
             make the caller retry forever"
        );
        assert!(stall.remedy().contains("steward"), "{}", stall.remedy());
    }

    /// A key the directory has never seen is NOT an error the operator caused —
    /// it is an unconverged directory, and it fixes itself.
    #[tokio::test]
    async fn an_unknown_key_stalls_as_not_yet_discovered_and_self_resolves() {
        let lens = frank();
        let Err(stall) = super::resolve(&lens, "stranger-zzz").await else {
            panic!("an unknown key cannot resolve");
        };
        assert!(
            stall.self_resolving(),
            "an unconverged directory must not page anyone"
        );
    }

    /// A known person with no reachable node is its own case: the remedy names
    /// THEM, not the identifier the caller happened to type.
    #[tokio::test]
    async fn a_person_with_no_nodes_stalls_naming_the_person() {
        let mut lens = frank();
        lens.nodes.clear();
        let Err(stall) = super::resolve(&lens, "frank-laptop-bbb").await else {
            panic!("no reachable node means no contact");
        };
        assert!(
            stall.remedy().contains("frank-fed-aaa"),
            "the remedy must name the person we could not reach: {}",
            stall.remedy()
        );
    }

    struct AllRouted;
    #[async_trait::async_trait]
    impl super::RouteLens for AllRouted {
        async fn has_destination(&self, _node: &str) -> bool {
            true
        }
    }
    struct NoRoutes;
    #[async_trait::async_trait]
    impl super::RouteLens for NoRoutes {
        async fn has_destination(&self, _node: &str) -> bool {
            false
        }
    }
    struct OnlyPhone;
    #[async_trait::async_trait]
    impl super::RouteLens for OnlyPhone {
        async fn has_destination(&self, node: &str) -> bool {
            node == "frank-phone-eee"
        }
    }

    /// Discovery means CONTACTABLE, not merely known. Owning nodes this node has
    /// no route to is not discovery — reporting it as such hands the caller a
    /// subject whose every send fails, with no clue why.
    #[tokio::test]
    async fn owning_nodes_with_no_route_is_not_discovery() {
        let Err(stall) = super::discover(&frank(), &NoRoutes, "frank-fed-aaa").await else {
            panic!("no route means not contactable");
        };
        assert!(
            matches!(stall, super::LadderStall::Unreachable { .. }),
            "an unreachable peer and an unknown key have DIFFERENT remedies — one \
             waits for the peer, the other for the directory"
        );
        assert!(stall.self_resolving(), "the peer may simply be offline");
    }

    /// Only the nodes with a route are offered. Handing back an unroutable node
    /// alongside a routable one invites the caller to pick the wrong one.
    #[tokio::test]
    async fn discovery_returns_only_the_reachable_nodes() {
        let d = super::discover(&frank(), &OnlyPhone, "frank-laptop-bbb")
            .await
            .expect("one routable node is enough");
        assert_eq!(d.reachable, vec!["frank-phone-eee".to_string()]);
        assert_eq!(
            d.subject.nodes.len(),
            2,
            "the subject still knows about both — only REACHABLE is filtered"
        );
    }

    /// And any identifier still gets there.
    #[tokio::test]
    async fn discovery_works_from_any_identifier() {
        for id in ["frank-fed-aaa", "frank-laptop-bbb", "frank-agent-ccc"] {
            let d = super::discover(&frank(), &AllRouted, id)
                .await
                .expect("resolves");
            assert_eq!(d.subject.fed_id, "frank-fed-aaa");
            assert_eq!(d.reachable.len(), 2);
        }
    }

    /// The ladder is ordered, and the order is the diagnostic. A failure is
    /// nearly always the previous rung, so every rung must be able to name it.
    #[test]
    fn every_rung_but_the_first_names_its_predecessor() {
        assert_eq!(Rung::Announce.previous(), None, "announce is the base");
        for rung in [
            Rung::Discover,
            Rung::RequestContact,
            Rung::Consent,
            Rung::OpenChat,
            Rung::SendMessage,
        ] {
            assert!(
                rung.previous().is_some(),
                "{rung} must name the rung to look at first"
            );
        }
    }

    /// Waiting on a PERSON is not a fault. An operator dashboard that escalates
    /// "awaiting consent" trains people to ignore it, and then they ignore the
    /// real ones too.
    #[test]
    fn waiting_on_a_human_is_not_self_resolving() {
        let awaiting = LadderStall::AwaitingConsent {
            fed_id: "fed_abc".into(),
        };
        assert!(!awaiting.self_resolving());

        let converging = LadderStall::NotYetDiscovered {
            fed_id: "fed_abc".into(),
        };
        assert!(
            converging.self_resolving(),
            "an unconverged directory fixes itself and must not page anyone"
        );
    }

    /// Every stall answers "what do I do". A diagnostic that names a condition
    /// and no action is a bug report addressed to the wrong person.
    #[test]
    fn every_stall_states_a_remedy_naming_its_subject() {
        let id = "fed_7f3a9c21e4b8";
        let stalls = [
            LadderStall::NotYetDiscovered { fed_id: id.into() },
            LadderStall::Unreachable { fed_id: id.into() },
            LadderStall::AwaitingConsent { fed_id: id.into() },
            LadderStall::ConsentNotGranted { fed_id: id.into() },
        ];
        for s in stalls {
            let r = s.remedy();
            assert!(r.len() > 40, "a remedy must actually say something: {r}");
            assert!(
                r.contains(id),
                "a remedy must name its subject so a log line is actionable alone: {r}"
            );
        }
        // The structural one names rungs rather than a fedID.
        let prior = LadderStall::PriorRungIncomplete {
            rung: Rung::OpenChat,
            prior: Rung::Consent,
        };
        let r = prior.remedy();
        assert!(r.contains("open_chat") && r.contains("consent"), "{r}");
    }

    /// The rung strings are an operator interface: they are grepped and grouped.
    #[test]
    fn rung_names_are_stable_and_distinct() {
        let names: Vec<&str> = [
            Rung::Announce,
            Rung::Discover,
            Rung::RequestContact,
            Rung::Consent,
            Rung::OpenChat,
            Rung::SendMessage,
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "rung names must be distinct");
        assert!(names.contains(&"request_contact"));
    }

    /// Build a real fedcode for a freshly generated key, the way a sender's
    /// node would.
    fn issue_code(label: &str, kind: ciris_verify_core::fedcode::FedKind) -> (String, String) {
        use base64::Engine as _;

        // `derive_key_id` hashes the bytes; it does not care that they are a
        // valid curve point, and neither does the binding check under test.
        let mut pubkey = [0u8; 32];
        pubkey[0..label.len().min(32)].copy_from_slice(&label.as_bytes()[..label.len().min(32)]);
        pubkey[31] = u8::try_from(label.len()).unwrap_or(0);

        let key_id = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);
        let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind,
            key_id: key_id.clone(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
            transport_hint: Some("https://example.invalid".to_string()),
            alias_hint: Some("Frank".to_string()),
            group_key_id: None,
        })
        .expect("encode");
        (code, key_id)
    }

    /// CIRISEdge#526 — a pasted code is decoded, not posted as a key_id.
    ///
    /// The reported failure: `addContact(keyId)` sent the raw code string as
    /// `key_id` and the server answered `unknown_fed_id` — a correct answer to
    /// the wrong question. The code carries the public key the directory cannot
    /// supply for a stranger, and nothing was decoding it.
    #[test]
    fn a_pasted_code_is_decoded_and_carries_the_key_to_admit() {
        let (code, key_id) = issue_code("frank", ciris_verify_core::fedcode::FedKind::User);

        let candidate = super::parse_contact_input(&code).expect("a good code decodes");

        assert_eq!(candidate.source, super::ContactInputSource::Code);
        assert_eq!(
            candidate.key_id, key_id,
            "the key_id comes from INSIDE the code, never from the pasted string"
        );
        assert_eq!(
            candidate.kind,
            super::IdentityKind::Person,
            "kind: user => Person"
        );

        let admission = candidate
            .admission
            .expect("a code must yield the material to admit — that is its whole job");
        assert_eq!(admission.key_id, key_id);
        assert_eq!(admission.identity_type, "user");
        assert!(
            !admission.pubkey_ed25519_base64.is_empty(),
            "the pubkey is the thing the directory cannot supply for a stranger"
        );
        assert_eq!(admission.alias_hint.as_deref(), Some("Frank"));
    }

    /// CIRISEdge#526 — a label that merely STARTS with V is not a fedcode.
    ///
    /// `key_id` is `label-fingerprint` with an operator-chosen label, so
    /// `CIRIS-Victor-<fingerprint>` is a perfectly valid identifier. A
    /// `starts_with("CIRIS-V")` probe would send it to the fedcode decoder and
    /// return `MalformedCode`, making a real person unreachable because of
    /// their name. The discriminator is the COMPLETE versioned prefix.
    #[test]
    fn a_label_beginning_with_v_is_an_identifier_not_a_code() {
        for id in [
            // Fingerprints are base32 (a-z, 2-7) — `derive_key_id` lowercases
            // the first 10 chars of the digest, so these are shaped like the
            // real thing.
            "CIRIS-Victor-abc234def5",
            "CIRIS-V-abc234def5",
            "ciris-vera-abc234def5",
            "CIRIS-Vv2-abc234def5",
            // The label can literally BE a version string. A prefix test —
            // even one demanding digits and a delimiter — classifies this as a
            // code and makes the person unreachable; only the complete
            // structure tells them apart.
            "CIRIS-V2-abc234def5",
            "CIRIS-V1-zzzzzzzzzz",
        ] {
            assert!(
                !super::looks_like_fedcode(id),
                "{id} is an identifier — a label may start with V, and a code \
                 needs CIRIS-V<digits>-"
            );
            let candidate = super::parse_contact_input(id).expect("plain identifier");
            assert_eq!(candidate.source, super::ContactInputSource::Identifier);
        }
        for code in ["CIRIS-V1-AAAA", "CIRIS-V2-AAAA", "ciris-v2-aaaa"] {
            assert!(
                super::looks_like_fedcode(code),
                "{code} announces itself as a versioned fedcode"
            );
        }
    }

    /// CIRISEdge#526 — an Ed25519 public key is exactly 32 bytes.
    ///
    /// Tested against the BINDING CHECK directly rather than through a round
    /// trip, because our own `encode` refuses a short key ("pubkey must be 32
    /// raw bytes"). That defence does not cover the case that matters: a
    /// hand-crafted code on the wire never touches our encoder. `derive_key_id`
    /// hashes whatever it is handed, so without this length check a sender
    /// could derive a matching id from one byte and receive a "verified"
    /// admission whose contract promises raw-32 — rejected one layer later by
    /// the host's registration gate, which is a confusing place to find out.
    #[test]
    fn a_pubkey_that_is_not_32_bytes_is_malformed() {
        use base64::Engine as _;
        for len in [1usize, 31, 33, 64] {
            let bytes = vec![7u8; len];
            // The id DERIVES correctly from these bytes, so the binding check
            // alone would pass it. Only the length check catches it.
            let key_id = ciris_verify_core::fedcode::derive_key_id("shorty", &bytes);
            let hand_crafted = ciris_verify_core::fedcode::FedCode {
                kind: ciris_verify_core::fedcode::FedKind::User,
                key_id,
                pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                transport_hint: None,
                alias_hint: None,
                group_key_id: None,
            };
            match super::verify_code_binds_its_key(&hand_crafted) {
                Err(LadderStall::MalformedCode { detail }) => {
                    assert!(detail.contains("32"), "state the contract: {detail}");
                }
                other => panic!("a {len}-byte pubkey is not an Ed25519 key: {other:?}"),
            }
        }
    }

    /// CIRISEdge#526 — a bare identifier still behaves exactly as before, and is
    /// never mistaken for a code.
    #[test]
    fn a_bare_identifier_is_passed_through_with_nothing_to_admit() {
        let candidate = super::parse_contact_input("  frank-abc123def4  ").expect("plain id");
        assert_eq!(candidate.source, super::ContactInputSource::Identifier);
        assert_eq!(candidate.key_id, "frank-abc123def4", "trimmed, not parsed");
        assert!(
            candidate.admission.is_none(),
            "an identifier carries no key — there is nothing new to admit"
        );
    }

    /// CIRISEdge#526 — a code that will not decode surfaces AS a bad code.
    ///
    /// It must never fall through to be tried as an identifier: that is what
    /// turned a truncated paste into a baffling `unknown_fed_id` about a string
    /// that was obviously a code.
    #[test]
    fn a_truncated_code_is_a_code_error_not_an_unknown_identifier() {
        let (code, _) = issue_code("frank", ciris_verify_core::fedcode::FedKind::User);
        let truncated = &code[..code.len() - 6];

        match super::parse_contact_input(truncated) {
            Err(LadderStall::MalformedCode { detail }) => {
                assert!(!detail.is_empty(), "say what was wrong with it");
            }
            other => panic!(
                "a CIRIS-V… string that does not decode must be MalformedCode, \
                 never demoted to an identifier: {other:?}"
            ),
        }
    }

    /// CIRISEdge#526 SECURITY — a code claiming someone else's address is
    /// REFUSED.
    ///
    /// `fedcode::decode` verifies a CRC, which proves only that the code
    /// survived transit. The sender authors every byte, so nothing stops one
    /// claiming a victim's `key_id` while carrying its own key. Admitting that
    /// registers an attacker's pubkey under the victim's federation address, and
    /// every signature the victim is supposed to make becomes forgeable by
    /// whoever holds that code.
    #[test]
    fn a_code_claiming_another_identity_is_refused() {
        use base64::Engine as _;

        // The victim's real address.
        let (_, victim_key_id) = issue_code("victim", ciris_verify_core::fedcode::FedKind::User);

        // The attacker's own key, presented under the victim's address.
        let attacker_pubkey = [0xAAu8; 32];
        let forged = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind: ciris_verify_core::fedcode::FedKind::User,
            key_id: victim_key_id.clone(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD
                .encode(attacker_pubkey),
            transport_hint: None,
            alias_hint: Some("Totally The Victim".to_string()),
            group_key_id: None,
        })
        .expect("a forgery encodes perfectly well — that is the point");

        // It decodes cleanly. The CRC is fine. Only the BINDING catches it.
        assert!(
            ciris_verify_core::fedcode::decode(&forged).is_ok(),
            "the forgery is well-formed; the checksum cannot detect authorship"
        );

        match super::parse_contact_input(&forged) {
            Err(LadderStall::CodeIdentityMismatch {
                claimed_key_id,
                derived_key_id,
            }) => {
                assert_eq!(claimed_key_id, victim_key_id);
                assert_ne!(
                    derived_key_id, victim_key_id,
                    "the key inside derives a DIFFERENT address — that is the tell"
                );
            }
            other => panic!(
                "a code whose key does not derive its claimed address MUST be \
                 refused; admitting it is an impersonation primitive: {other:?}"
            ),
        }
    }

    /// CIRISEdge#526 END TO END — a stranger's code yields something to DO,
    /// not a stall.
    ///
    /// The directory knowing nothing about them is the expected state for a
    /// stranger, not a failure. Reporting `NotYetDiscovered` — whose remedy is
    /// "wait for replication" — would be advice that never comes true, because
    /// replication will never deliver a stranger's key to a node that has no
    /// reason to hold it.
    #[tokio::test]
    async fn a_strangers_code_resolves_to_admit_then_retry() {
        let (code, key_id) = issue_code("stranger", ciris_verify_core::fedcode::FedKind::User);
        // A directory that has never heard of them — the whole point.
        let empty = FakeLens {
            types: std::collections::HashMap::new(),
            owners: std::collections::HashMap::new(),
            nodes: std::collections::HashMap::new(),
        };

        match super::resolve_contact(&empty, &code).await {
            Ok(super::ContactResolution::ReadyFromCode { subject, admission }) => {
                assert_eq!(admission.key_id, key_id);
                assert_eq!(admission.identity_type, "user");
                assert!(!admission.pubkey_ed25519_base64.is_empty());
                // The half that was missing: a usable identity, built from the
                // code. Admitting a key never creates owner-binding
                // attestations, so a directory retry would return
                // NotYetDiscovered forever — the code has to be sufficient.
                assert_eq!(subject.fed_id, key_id);
                // And `nodes` is EMPTY: a user code names a PERSON, not their
                // nodes, and a stranger has no owner bindings here. Putting the
                // person's own key in a NODE list made a caller dial a person
                // key as a node — filling a field with the only value in hand
                // is how a type stops meaning what it says.
                assert!(
                    subject.nodes.is_empty(),
                    "a user code does not name nodes: {:?}",
                    subject.nodes
                );
                // Reachability travels as the transport hint instead.
                assert_eq!(
                    admission.transport_hint.as_deref(),
                    Some("https://example.invalid"),
                    "the hint is how a code carries reachability, since the \
                     directory cannot supply it for a stranger"
                );
            }
            other => panic!(
                "a stranger's code must yield BOTH the key to admit and a \
                 usable subject — the directory cannot supply either: {other:?}"
            ),
        }
    }

    /// CIRISEdge#526 — a STRANGER's node/agent code never puts a machine in
    /// the person slot.
    ///
    /// `Subject.fed_id` is *the party who consents*, and a node cannot consent
    /// — its OWNER does. `resolve` upholds that for a KNOWN node by routing
    /// through `owner_of`; a stranger has no owner binding here, so there is
    /// nothing to route to. Building a Subject anyway would aim the consent
    /// rung at a machine, and the harness guide keys that rung on `fed_id`.
    ///
    /// This was the untested crack: every other code test mints `User`, and
    /// rosters are caught by their own guard.
    #[tokio::test]
    async fn a_strangers_node_code_is_terminal_not_a_person() {
        use base64::Engine as _;
        let empty = FakeLens {
            types: std::collections::HashMap::new(),
            owners: std::collections::HashMap::new(),
            nodes: std::collections::HashMap::new(),
        };

        for (kind, wire) in [
            (ciris_verify_core::fedcode::FedKind::Node, "node"),
            (ciris_verify_core::fedcode::FedKind::Agent, "agent"),
        ] {
            let mut pubkey = [0u8; 32];
            pubkey[0] = u8::try_from(wire.len()).unwrap_or(1);
            let key_id = ciris_verify_core::fedcode::derive_key_id(wire, &pubkey);
            let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
                kind,
                key_id: key_id.clone(),
                pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
                transport_hint: Some("https://example.invalid".into()),
                alias_hint: None,
                group_key_id: None,
            })
            .expect("encode");

            match super::resolve_contact(&empty, &code).await {
                Err(LadderStall::NotContactable {
                    identity_type,
                    key_id: refused,
                }) => {
                    assert_eq!(identity_type, wire);
                    assert_eq!(refused, key_id);
                }
                Ok(super::ContactResolution::ReadyFromCode { subject, .. }) => panic!(
                    "a stranger's {wire} code must NOT yield a Subject — \
                     fed_id would hold {}, a machine, and the consent rung is \
                     keyed on it",
                    subject.fed_id
                ),
                other => panic!("expected NotContactable for a stranger {wire} code: {other:?}"),
            }
        }
    }

    /// CIRISEdge#526 — a self-contained code must not queue a network fetch
    /// for the key it is already carrying.
    ///
    /// The recovery queue is bounded and shared with genuine missing-signer
    /// work, so repeated direct-code contacts would displace it — asking the
    /// mesh for something sitting in the caller's hand.
    #[tokio::test]
    async fn a_code_does_not_queue_a_fetch_for_the_key_it_carries() {
        use base64::Engine as _;
        struct CountingLens {
            requested: std::sync::Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl super::DirectoryLens for CountingLens {
            async fn identity_type_of(&self, _k: &str) -> Option<String> {
                None // hash-first: knows the hash, not the body
            }
            async fn owner_of(&self, _k: &str) -> Option<String> {
                None
            }
            async fn nodes_owned_by(&self, _f: &str) -> Vec<String> {
                Vec::new()
            }
            async fn request_key_body(&self, key_id: &str) -> bool {
                self.requested.lock().unwrap().push(key_id.to_owned());
                true
            }
        }

        let mut pubkey = [0u8; 32];
        pubkey[0] = 21;
        let key_id = ciris_verify_core::fedcode::derive_key_id("selfcontained", &pubkey);
        let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind: ciris_verify_core::fedcode::FedKind::User,
            key_id,
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
            transport_hint: None,
            alias_hint: None,
            group_key_id: None,
        })
        .expect("encode");

        let lens = CountingLens {
            requested: std::sync::Mutex::new(Vec::new()),
        };
        let out = super::resolve_contact(&lens, &code).await;
        assert!(
            matches!(out, Ok(super::ContactResolution::ReadyFromCode { .. })),
            "the code is sufficient: {out:?}"
        );
        assert!(
            lens.requested.lock().unwrap().is_empty(),
            "no fetch may be queued for a key the code already carries — the \
             queue is bounded and shared with real signer recovery"
        );

        // A BARE identifier still queues, because nothing carries that key.
        let lens = CountingLens {
            requested: std::sync::Mutex::new(Vec::new()),
        };
        let _ = super::resolve_contact(&lens, "someone-abc234def5").await;
        assert_eq!(
            lens.requested.lock().unwrap().len(),
            1,
            "an identifier miss has nothing in hand, so it must still ask"
        );
    }

    /// CIRISEdge#526 — a family/community code is refused BEFORE the caller is
    /// told to admit anything.
    ///
    /// `resolve` treats these as terminal, so an admit-then-retry would end at
    /// exactly this answer having registered a key for nothing.
    #[tokio::test]
    async fn a_roster_code_is_not_contactable_and_says_so_before_admission() {
        use base64::Engine as _;
        let mut pubkey = [0u8; 32];
        pubkey[0] = 3;
        let key_id = ciris_verify_core::fedcode::derive_key_id("book-club", &pubkey);
        let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind: ciris_verify_core::fedcode::FedKind::Community,
            key_id: key_id.clone(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
            transport_hint: None,
            alias_hint: None,
            group_key_id: Some(key_id.clone()),
        })
        .expect("encode");

        let empty = FakeLens {
            types: std::collections::HashMap::new(),
            owners: std::collections::HashMap::new(),
            nodes: std::collections::HashMap::new(),
        };
        match super::resolve_contact(&empty, &code).await {
            Err(LadderStall::NotContactable { identity_type, .. }) => {
                assert_eq!(identity_type, "community");
            }
            other => panic!(
                "a roster is not a person — refuse before instructing a \
                 pointless registration: {other:?}"
            ),
        }
    }

    /// CIRISEdge#526 — pasting a code for someone already admitted is
    /// idempotent, not a re-admission.
    #[tokio::test]
    async fn a_code_for_a_known_person_resolves_as_known() {
        use base64::Engine as _;

        // Mint a code whose key_id is one the directory already knows.
        let mut pubkey = [0u8; 32];
        pubkey[0] = 7;
        let label = "frank-fed";
        let key_id = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);

        let mut lens = frank();
        lens.types.insert(key_id.clone(), "user".into());
        lens.nodes
            .insert(key_id.clone(), vec!["frank-laptop-bbb".into()]);

        let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind: ciris_verify_core::fedcode::FedKind::User,
            key_id: key_id.clone(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
            transport_hint: None,
            alias_hint: None,
            group_key_id: None,
        })
        .expect("encode");

        match super::resolve_contact(&lens, &code).await {
            Ok(super::ContactResolution::Known(subject)) => {
                assert_eq!(subject.fed_id, key_id);
            }
            other => panic!(
                "a code for someone ALREADY admitted must resolve as Known, so \
                 pasting twice does not re-admit a registered key: {other:?}"
            ),
        }
    }

    /// CIRISEdge#526 — a terminal stall stays terminal even with a code in hand.
    ///
    /// A code carries a key; it does not make a steward into a contactable
    /// person. Admission cannot fix what admission is not about.
    #[tokio::test]
    async fn a_code_does_not_rescue_a_terminal_stall() {
        use base64::Engine as _;

        let mut pubkey = [0u8; 32];
        pubkey[0] = 9;
        let key_id = ciris_verify_core::fedcode::derive_key_id("steward", &pubkey);

        let mut lens = frank();
        lens.types.insert(key_id.clone(), "steward".into());

        let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
            kind: ciris_verify_core::fedcode::FedKind::User,
            key_id: key_id.clone(),
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
            transport_hint: None,
            alias_hint: None,
            group_key_id: None,
        })
        .expect("encode");

        match super::resolve_contact(&lens, &code).await {
            Err(LadderStall::NotContactable { .. }) => {}
            other => panic!("a steward is not contactable, code or no code: {other:?}"),
        }
    }

    /// CIRISEdge#552 — a hash-first node that knows the key as a HASH must
    /// queue the body fetch, and must say so.
    ///
    /// The bug this closes: `identity_type_of` answers `None` because the body
    /// was never fetched, and the ladder reports `NotYetDiscovered`, whose
    /// remedy is "wait for the peer to announce". The peer already announced.
    /// Bulk convergence is exactly what hash-first suppressed, so that wait
    /// never ends — the same shape as a kill order that cannot land.
    #[tokio::test]
    async fn a_resolution_miss_on_a_hash_first_node_queues_the_body_fetch() {
        struct HashOnlyLens {
            requested: std::sync::Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl super::DirectoryLens for HashOnlyLens {
            async fn identity_type_of(&self, _key_id: &str) -> Option<String> {
                None // the body is not held — only its hash
            }
            async fn owner_of(&self, _key_id: &str) -> Option<String> {
                None
            }
            async fn nodes_owned_by(&self, _fed_id: &str) -> Vec<String> {
                Vec::new()
            }
            async fn request_key_body(&self, key_id: &str) -> bool {
                self.requested.lock().unwrap().push(key_id.to_owned());
                true
            }
        }

        let lens = HashOnlyLens {
            requested: std::sync::Mutex::new(Vec::new()),
        };
        let err = super::resolve(&lens, "frank-abc123")
            .await
            .expect_err("the body is not held, so this cannot resolve yet");

        assert_eq!(
            lens.requested.lock().unwrap().as_slice(),
            ["frank-abc123"],
            "the miss must QUEUE the fetch — without it the lookup can never \
             succeed on a hash-first node"
        );
        match &err {
            LadderStall::BodyFetchQueued { key_id } => {
                assert_eq!(key_id, "frank-abc123");
            }
            other => panic!("expected BodyFetchQueued, got {other:?}"),
        }
        assert!(err.self_resolving(), "the next Key round carries the fetch");
        assert!(
            err.remedy().contains("already did"),
            "the remedy must NOT tell an operator to wait for an announce that \
             already happened: {}",
            err.remedy()
        );
    }

    /// CIRISEdge#552 — a local backend failure must NOT be reported as a
    /// queued fetch.
    ///
    /// `identity_type_of` answers `None` for both "absent" and "the read
    /// failed". Only the first is repairable by a peer. Conflating them emits a
    /// Pull no reply can satisfy — on every retry — while telling an operator
    /// the next Key round will resolve it, which is a remedy that never comes.
    #[tokio::test]
    async fn a_backend_failure_is_not_reported_as_a_queued_fetch() {
        struct BrokenBackendLens {
            requested: std::sync::Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl super::DirectoryLens for BrokenBackendLens {
            async fn identity_type_of(&self, _key_id: &str) -> Option<String> {
                None // indistinguishable from absence, by construction
            }
            async fn owner_of(&self, _key_id: &str) -> Option<String> {
                None
            }
            async fn nodes_owned_by(&self, _fed_id: &str) -> Vec<String> {
                Vec::new()
            }
            async fn directory_readable(&self) -> bool {
                false
            }
            async fn request_key_body(&self, key_id: &str) -> bool {
                self.requested.lock().unwrap().push(key_id.to_owned());
                true
            }
        }

        let lens = BrokenBackendLens {
            requested: std::sync::Mutex::new(Vec::new()),
        };
        let err = super::resolve(&lens, "frank-abc123")
            .await
            .expect_err("a node that cannot read its directory resolves nothing");

        assert!(
            lens.requested.lock().unwrap().is_empty(),
            "no Pull may be emitted for a LOCAL read failure — no peer reply can \
             repair it, so the traffic is pointless on every retry"
        );
        assert!(
            matches!(err, LadderStall::DirectoryUnreadable { .. }),
            "expected DirectoryUnreadable, got {err:?}"
        );
        assert!(
            !err.self_resolving(),
            "retrying is the one thing that cannot fix a local backend fault"
        );
        assert!(
            err.remedy().contains("LOCAL"),
            "the remedy must send an operator to the node, not the mesh: {}",
            err.remedy()
        );
    }

    /// A node that holds bodies has nothing to fetch, so its miss really is
    /// "not announced yet" — the default must not manufacture a fetch.
    #[tokio::test]
    async fn a_bodies_node_still_reports_not_yet_discovered() {
        struct BodiesLens;
        #[async_trait::async_trait]
        impl super::DirectoryLens for BodiesLens {
            async fn identity_type_of(&self, _key_id: &str) -> Option<String> {
                None
            }
            async fn owner_of(&self, _key_id: &str) -> Option<String> {
                None
            }
            async fn nodes_owned_by(&self, _fed_id: &str) -> Vec<String> {
                Vec::new()
            }
        }
        let err = super::resolve(&BodiesLens, "frank-abc123")
            .await
            .expect_err("unknown key");
        assert!(
            matches!(err, LadderStall::NotYetDiscovered { .. }),
            "a bodies-retention node's miss is an ordinary not-yet-discovered, \
             got {err:?}"
        );
    }
}
