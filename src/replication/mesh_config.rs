//! CIRISEdge#440 — the resolved mesh-config read seam: RELIEF, never a gate.
//!
//! Persist v28.3.0 (CIRISPersist#570 ask 1) landed the `mesh_config` plane:
//! federation-scoped, accord-authored, TTL'd rows whose read-time answer is a
//! **per-root most-restrictive fold**
//! ([`ciris_persist::federation::mesh_config::resolve_mesh_config`]) with two
//! guarantees edge leans on rather than re-deriving:
//!
//! - **relieve-never-expand** (CC 4.2.1 rule 1): `effective` never means more
//!   flow than the host-supplied baseline, so nothing a root signs can make
//!   this node do MORE than its owner configured; and
//! - **most-restrictive-across-roots** (CC 4.2.1 rule 2): where roots
//!   disagree, the tightest value binds.
//!
//! Edge consumes eight of the registered keys (their `consumer` fields
//! in persist's closed registry name edge-side loops):
//!
//! | wire key                         | edge consumer                             |
//! |----------------------------------|-------------------------------------------|
//! | `antientropy.round_secs`         | scheduler cadence (next round)            |
//! | `antientropy.page_limit`         | the bridge's since-page limit             |
//! | `feature.trace_replication`      | pause the `trace:*` advertise/serve plane |
//! | `feature.av_streams`             | ALM admission toggle (`plan_parent_gated`)|
//! | `redundancy.k_repair_symbols`    | `FountainPolicy::k_repair`                |
//! | `redundancy.min_viable_symbols`  | `FountainPolicy::min_viable_symbols`      |
//! | `redundancy.target_holders`      | swarm converger `target_holders` (`H`)    |
//! | `redundancy.min_viable_holders`  | swarm converger `min_viable`              |
//!
//! The last four land on the swarm converger (CIRISEdge#546); persist v30.0.0
//! (CIRISPersist#602) split the fused redundancy pair onto the SYMBOL and
//! HOLDER axes precisely so each key names one edge field. Their consumer is
//! [`crate::swarm::runtime::SwarmRuntimeConfig::with_mesh_relief`], applied on
//! the converger tick — the swarm runtime had no setter at all before #546, so
//! these four were `consumed: false` in CIRISServer#365's map for want of a
//! place to put the answer, not for want of a mapping.
//!
//! ## Relief, not a gate — absence is EXACTLY today's behavior
//!
//! [`MeshConfigRelief`] carries an `Option` per tunable and a `bool` per
//! feature pause, and each is populated **only from a fold setting whose
//! `relieved` flag is true** — i.e. only when some root actually moved the key
//! off the baseline. An empty plane, an unresolvable plane, a directory error,
//! or no reader at all each yield [`MeshConfigRelief::NONE`], and every
//! consumer's `None`/`false` arm is the pre-#440 code path untouched. This is
//! the fail-open-by-construction shape: there is no default value to get wrong,
//! because absence is not a value.
//!
//! The `relieved`-gating also insulates sub-second and out-of-domain host
//! configs from the plane's integer domains: a 10 ms test cadence or a
//! `u32::MAX` "unlimited" page limit is clamped into domain only for the FOLD's
//! baseline (so admission and clamping still work), while the consumer keeps
//! running its exact configured value until a root actually relieves the key.
//!
//! ## Cadence — once per round-ish, never per row
//!
//! [`MeshConfigReader::relief`] memoizes the resolved snapshot for
//! [`DEFAULT_RELIEF_TTL`] (sized to the default anti-entropy cadence), so a
//! round's advertise sweep + N fetches + the scheduler's post-round check share
//! ONE persist resolution. A between-round config change lands at the next
//! refresh — the same freshness contract the #400 consent-send-set memo set.
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ciris_persist::federation::{
    resolve_mesh_config, FederationDirectory, MeshConfigBaseline, MeshConfigFold, MeshConfigKey,
};

/// How long one resolved [`MeshConfigRelief`] snapshot stays fresh. Sized to
/// the default scheduler cadence (30 s), so the plane is re-read about once per
/// round: a relief takes effect within one round, and a TTL-expired emergency
/// row stops applying within one round of its expiry.
pub const DEFAULT_RELIEF_TTL: Duration = Duration::from_secs(30);

/// The resolved mesh-config RELIEF snapshot — what the plane is currently
/// asking this node to do LESS of.
///
/// Every field is populated only from a fold setting whose `relieved` flag is
/// true (a root actually moved the key off the baseline). [`Self::NONE`] — the
/// value every failure/absence path yields — makes every consumer behave
/// byte-identically to a build without the reader wired at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshConfigRelief {
    /// `antientropy.round_secs`, as a cadence, iff relieved. Applied by the
    /// scheduler at the next round boundary.
    pub round_cadence: Option<Duration>,
    /// `antientropy.page_limit` iff relieved. The bridge takes
    /// `min(configured, relieved)` — relief can only shrink a page.
    pub page_limit: Option<u32>,
    /// `feature.trace_replication` relieved to `0`: the advertise sweep and the
    /// direct-fetch twin withhold `trace:*` rows, booking
    /// [`crate::observability::WithholdReason::ConfigPaused`].
    pub trace_replication_paused: bool,
    /// `feature.av_streams` relieved to `0`: ALM admission
    /// (`plan_parent_gated`) refuses with a named error.
    pub av_streams_paused: bool,
    /// CIRISEdge#546 — `redundancy.k_repair_symbols` iff relieved. The swarm
    /// runtime takes `min(configured, relieved)` into
    /// [`crate::holonomic::fountain_defaults::FountainPolicy::k_repair`].
    pub k_repair_symbols: Option<u32>,
    /// CIRISEdge#546 — `redundancy.min_viable_symbols` iff relieved →
    /// [`crate::holonomic::fountain_defaults::FountainPolicy::min_viable_symbols`]
    /// (the BLINKING_DOT floor), `min`'d against the configured value.
    pub min_viable_symbols: Option<u32>,
    /// CIRISEdge#546 — `redundancy.target_holders` iff relieved → the swarm
    /// converger's `H`. Distinct axis from [`Self::k_repair_symbols`]: peers,
    /// not symbols (CIRISPersist#602 split the fused pair for exactly this).
    pub target_holders: Option<u32>,
    /// CIRISEdge#546 — `redundancy.min_viable_holders` iff relieved → the
    /// holder floor below which the converger emits `RepairNeeded`.
    pub min_viable_holders: Option<u32>,
}

impl MeshConfigRelief {
    /// No relief — the exact pre-#440 behavior on every consumer.
    pub const NONE: Self = Self {
        round_cadence: None,
        page_limit: None,
        trace_replication_paused: false,
        av_streams_paused: false,
        k_repair_symbols: None,
        min_viable_symbols: None,
        target_holders: None,
        min_viable_holders: None,
    };

    /// Derive the relief snapshot from a resolved fold. Pure; the
    /// `relieved`-gating documented on the struct happens here and only here.
    #[must_use]
    pub fn from_fold(fold: &MeshConfigFold) -> Self {
        let relieved = |key: MeshConfigKey| {
            fold.setting(key)
                .filter(|s| s.relieved)
                .map(|s| s.effective)
        };
        let paused = |key: MeshConfigKey| relieved(key).is_some_and(|v| v == 0);
        // Every count-shaped key lands in a `u32` edge field; persist's domains
        // cap at 4096, so the saturating conversion is a belt on an i64 that
        // cannot be negative in-domain, never a live path.
        let count =
            |key: MeshConfigKey| relieved(key).map(|v| u32::try_from(v).unwrap_or(u32::MAX));
        Self {
            round_cadence: relieved(MeshConfigKey::AntientropyRoundSecs)
                .and_then(|v| u64::try_from(v).ok())
                .map(Duration::from_secs),
            page_limit: count(MeshConfigKey::AntientropyPageLimit),
            trace_replication_paused: paused(MeshConfigKey::FeatureTraceReplication),
            av_streams_paused: paused(MeshConfigKey::FeatureAvStreams),
            // CIRISEdge#546 — the swarm converger's four. Read here and only
            // here; the `min(configured, relieved)` bound that keeps a root
            // from raising them past the operator's own ceiling lives at the
            // consumer (`SwarmRuntimeConfig::with_mesh_relief`), mirroring
            // `bridge::effective_page_limit`.
            k_repair_symbols: count(MeshConfigKey::RedundancyKRepairSymbols),
            min_viable_symbols: count(MeshConfigKey::RedundancyMinViableSymbols),
            target_holders: count(MeshConfigKey::RedundancyTargetHolders),
            min_viable_holders: count(MeshConfigKey::RedundancyMinViableHolders),
        }
    }
}

/// The one edge-side reader over persist's mesh-config fold. Shared
/// (`Arc`) by the bridge, the scheduler, and — via
/// [`crate::replication::runtime::ReplicationRuntime::mesh_config_reader`] —
/// any host-wired [`crate::transport::realtime_av_alm::TransitGate`].
pub struct MeshConfigReader {
    directory: Arc<dyn FederationDirectory>,
    /// The node whose subscription (`delegates_to(node → root)` edges) and
    /// consent baseline the fold is about — `ReplicationRuntimeConfig::local_key_id`.
    node_key_id: String,
    /// What this node's owner consented to: the ACTUAL configured operating
    /// values, so `effective == baseline` (no relief) is exactly today.
    baseline: MeshConfigBaseline,
    ttl: Duration,
    /// `(snapshot, resolved_at)`. `std` mutex, never held across an `await`.
    cache: Mutex<Option<(MeshConfigRelief, Instant)>>,
}

impl MeshConfigReader {
    /// Build a reader for `node_key_id` over `directory`, folding against
    /// `baseline` (see [`Self::baseline_for`]).
    #[must_use]
    pub fn new(
        directory: Arc<dyn FederationDirectory>,
        node_key_id: String,
        baseline: MeshConfigBaseline,
    ) -> Self {
        Self {
            directory,
            node_key_id,
            baseline,
            ttl: DEFAULT_RELIEF_TTL,
            cache: Mutex::new(None),
        }
    }

    /// Override the snapshot TTL (tests; a host with a non-default cadence).
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The fold baseline for edge's four keys: persist's `owner_defaults` with
    /// the two tunables pinned to the node's ACTUAL configured values, so a
    /// plane that says nothing resolves to exactly what the node already runs.
    /// (`MeshConfigBaseline::with` clamps into each key's domain; the
    /// `relieved`-gating in [`MeshConfigRelief::from_fold`] keeps that clamp
    /// from ever leaking into an un-relieved consumer.)
    #[must_use]
    pub fn baseline_for(cadence: Duration, page_limit: u32) -> MeshConfigBaseline {
        MeshConfigBaseline::owner_defaults()
            .with(
                MeshConfigKey::AntientropyRoundSecs,
                i64::try_from(cadence.as_secs()).unwrap_or(i64::MAX),
            )
            .with(MeshConfigKey::AntientropyPageLimit, i64::from(page_limit))
    }

    /// A reader that always answers `relief` without touching any directory —
    /// consumer-wiring tests only. The reader→fold→admission chain itself is
    /// covered by the field-provenance tests below and in `bridge.rs`.
    #[cfg(test)]
    pub(crate) fn fixed_for_test(
        directory: Arc<dyn FederationDirectory>,
        relief: MeshConfigRelief,
    ) -> Self {
        Self {
            directory,
            node_key_id: String::new(),
            baseline: MeshConfigBaseline::owner_defaults(),
            ttl: Duration::from_secs(u64::MAX / 4),
            cache: Mutex::new(Some((relief, Instant::now()))),
        }
    }

    /// The current relief snapshot — cached within [`Self::ttl`], resolved via
    /// persist's per-root most-restrictive fold on a miss.
    ///
    /// **Fail-open, loudly**: a resolve error yields [`MeshConfigRelief::NONE`]
    /// (config is relief, not a gate — an unreadable plane must not change
    /// behavior) with a WARN naming the error; `unreadable_roots` (persist
    /// #601 — a subscribed root whose rows could not be read on a
    /// restrict-only plane) likewise warns, since it renders this node under
    /// fewer restrictions than it consented to.
    pub async fn relief(&self) -> MeshConfigRelief {
        if let Ok(cache) = self.cache.lock() {
            if let Some((snapshot, resolved_at)) = cache.as_ref() {
                if resolved_at.elapsed() < self.ttl {
                    return *snapshot;
                }
            }
        }
        let resolved = match resolve_mesh_config(
            &*self.directory,
            &self.node_key_id,
            &self.baseline,
            chrono::Utc::now(),
        )
        .await
        {
            Ok(fold) => {
                if !fold.unreadable_roots.is_empty() {
                    tracing::warn!(
                        node_key_id = %self.node_key_id,
                        unreadable_roots = ?fold.unreadable_roots,
                        "mesh-config fold could not read some subscribed roots — on a \
                         restrict-only plane this node may be running under FEWER \
                         restrictions than it consented to (CIRISPersist#601 / CIRISEdge#440)"
                    );
                }
                MeshConfigRelief::from_fold(&fold)
            }
            Err(e) => {
                tracing::warn!(
                    node_key_id = %self.node_key_id,
                    error = %e,
                    "mesh-config resolve FAILED — failing OPEN to the configured baseline \
                     (relief, not a gate: an unreadable plane must not change behavior; \
                     CIRISEdge#440)"
                );
                MeshConfigRelief::NONE
            }
        };
        if let Ok(mut cache) = self.cache.lock() {
            let changed = cache.as_ref().map(|(prev, _)| *prev) != Some(resolved);
            if changed {
                tracing::info!(
                    node_key_id = %self.node_key_id,
                    round_cadence_secs = resolved.round_cadence.map(|d| d.as_secs()),
                    page_limit = resolved.page_limit,
                    trace_replication_paused = resolved.trace_replication_paused,
                    av_streams_paused = resolved.av_streams_paused,
                    // CIRISEdge#546 — the swarm four. Named here because the
                    // change detection above is over the WHOLE snapshot: a line
                    // that fires while showing only the #440 fields reads as a
                    // spurious log rather than as the redundancy row it was.
                    k_repair_symbols = resolved.k_repair_symbols,
                    min_viable_symbols = resolved.min_viable_symbols,
                    target_holders = resolved.target_holders,
                    min_viable_holders = resolved.min_viable_holders,
                    "mesh-config relief snapshot changed (CIRISEdge#440)"
                );
            }
            *cache = Some((resolved, Instant::now()));
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_persist::federation::mesh_config::{mesh_config_envelope, MeshConfigForm};
    use ciris_persist::federation::types::{
        algorithm, identity_type, Attestation, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use ciris_persist::federation::{record_mesh_config_row, MeshConfigOutcome};
    use ciris_persist::store::MemoryBackend;
    use sha2::{Digest as _, Sha256};

    // ── Field-provenance fixtures — the same deterministic hybrid-signing
    //    shape `bridge.rs`'s test module carries (persist's
    //    `tier_ingest::test_support` mirror), self-contained here because test
    //    modules cannot import each other's cfg(test) items. ──

    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed");
        let mldsa = Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"));
        (
            B64.encode(ed.public_key().expect("ed pk")),
            Some(B64.encode(mldsa.public_key().expect("mldsa pk"))),
        )
    }

    fn sign_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(signing_key_id)).expect("ed seed");
        let mldsa =
            Box::new(MlDsa65Signer::from_seed(&seed_for(signing_key_id)).expect("mldsa seed"));
        let canonical = ciris_verify_core::jcs::canonicalize(envelope).expect("jcs canonicalize");
        let hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (hash, B64.encode(&ed_sig), Some(B64.encode(&pqc_sig)))
    }

    async fn seed_key(backend: &MemoryBackend, key_id: &str) {
        let now = Utc::now();
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let record = KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.to_string(),
            identity_type: identity_type::NODE.to_string(),
            identity_ref: format!("node-ref-{key_id}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": key_id,
                "identity_type": identity_type::NODE,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed key record");
    }

    /// #598 (v31.0.0) + #643: bind the `asserted_at` instant the fold orders on
    /// (RFC3339, MICROSECOND precision — ns is REFUSED) and the `row` mirror of
    /// the typed columns INTO the envelope BEFORE signing, else the row is
    /// refused as an unbound replay. Duplicated verbatim from `bridge.rs`'s test
    /// module (cfg(test) items cannot cross module boundaries).
    #[allow(clippy::too_many_arguments)] // mirrors the attestation's typed-column set
    fn bind_attestation_envelope(
        envelope: &mut serde_json::Value,
        asserted_at: chrono::DateTime<chrono::Utc>,
        attestation_id: &str,
        attesting_key_id: &str,
        attestation_type: &str,
        attested_key_id: &str,
        subject_key_ids: &[&str],
        cohort_scope: &str,
    ) {
        let Some(obj) = envelope.as_object_mut() else {
            return;
        };
        obj.entry("asserted_at")
            .or_insert_with(|| serde_json::json!(asserted_at.to_rfc3339()));
        let mut row = serde_json::json!({
            "attestation_id": attestation_id,
            "attesting_key_id": attesting_key_id,
            "attestation_type": attestation_type,
            "attested_key_id": attested_key_id,
            "cohort_scope": cohort_scope,
        });
        if !subject_key_ids.is_empty() {
            row["subject_key_ids"] = serde_json::json!(subject_key_ids);
        }
        obj.entry("row").or_insert(row);
    }

    fn attestation(
        attester: &str,
        subject: &str,
        attestation_type: &str,
        mut envelope: serde_json::Value,
    ) -> Attestation {
        use chrono::SubsecRound as _;
        // #598: the fold orders on the `asserted_at` COLUMN, so bind that instant
        // (µs-truncated) + the #643 `row` mirror into the envelope before signing.
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            attester,
            attestation_type,
            subject,
            &[subject],
            "federation",
        );
        let (hash, ed_sig, pqc_sig) = sign_envelope(attester, &envelope);
        Attestation {
            attestation_id,
            attesting_key_id: attester.to_string(),
            attested_key_id: subject.to_string(),
            attestation_type: attestation_type.to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attester.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_string()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        }
    }

    /// The subscription edge: `delegates_to(node → root)` — "the trust edge is
    /// the subscription" (persist's `trusted_roots_of`).
    async fn seed_subscription(backend: &MemoryBackend, node: &str, root: &str) {
        let envelope = serde_json::json!({
            "attesting_key_id": node,
            "attested_key_id": root,
            "attestation_type": "delegates_to",
            // Infra duty scopes only — the reject-agency-on-node-key gate
            // (persist #236) refuses a delegation conferring AGENCY on a
            // node-typed key, and an absent scope set reads as agency.
            "scope": ["infra:attest", "infra:serve"],
        });
        backend
            .put_attestation(SignedAttestation {
                attestation: attestation(node, root, "delegates_to", envelope),
            })
            .await
            .expect("seed subscription edge");
    }

    /// One mesh-config row, root-authored, filed against the root — built with
    /// persist's own `mesh_config_envelope` so the shape cannot drift from the
    /// fold's `parse_row`.
    fn mesh_row(root: &str, key: MeshConfigKey, value: i64, form: MeshConfigForm) -> Attestation {
        let valid_until = match form {
            MeshConfigForm::Emergency => Some(Utc::now() + chrono::Duration::hours(1)),
            MeshConfigForm::Durable => None,
        };
        let envelope = mesh_config_envelope(
            key,
            value,
            root,
            form,
            valid_until,
            "delegation-test-1",
            None,
            "test relief",
        );
        attestation(root, root, "scores", envelope)
    }

    fn baseline() -> MeshConfigBaseline {
        MeshConfigReader::baseline_for(Duration::from_secs(30), u32::MAX)
    }

    async fn reader_over(backend: &Arc<MemoryBackend>) -> MeshConfigReader {
        let dir: Arc<dyn FederationDirectory> = Arc::clone(backend) as _;
        MeshConfigReader::new(dir, "node-local".to_string(), baseline()).with_ttl(Duration::ZERO)
    }

    /// ABSENCE — an empty plane resolves to `MeshConfigRelief::NONE` exactly:
    /// no Option populated, no pause flagged. This is the byte-identical
    /// absence contract every consumer's `None` arm rides on.
    #[tokio::test]
    async fn absence_resolves_to_relief_none_exactly() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;
        let reader = reader_over(&backend).await;
        assert_eq!(reader.relief().await, MeshConfigRelief::NONE);
    }

    /// FIELD PROVENANCE, admission door — an emergency `round_secs` relief
    /// admitted through persist's REAL `record_mesh_config_row` (root-authored,
    /// TTL-bounded, subscription + signature + domain checked) changes the
    /// reader's cadence answer; a second key (`page_limit`) via the same door
    /// shrinks the page.
    #[tokio::test]
    async fn admitted_relief_changes_cadence_and_page_limit() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;

        for (key, value) in [
            (MeshConfigKey::AntientropyRoundSecs, 300),
            (MeshConfigKey::AntientropyPageLimit, 100),
        ] {
            let row = mesh_row("root-1", key, value, MeshConfigForm::Emergency);
            let outcome =
                record_mesh_config_row(&*backend, "node-local", &baseline(), &row, Utc::now())
                    .await
                    .expect("admission door reachable");
            assert!(
                matches!(outcome, MeshConfigOutcome::Admitted),
                "the REAL admission door must admit the fixture row (fixture rot \
                 otherwise invalidates every downstream assertion): {outcome:?}"
            );
        }

        let relief = reader_over(&backend).await.relief().await;
        assert_eq!(relief.round_cadence, Some(Duration::from_secs(300)));
        assert_eq!(relief.page_limit, Some(100));
        assert!(!relief.trace_replication_paused);
        assert!(!relief.av_streams_paused);
    }

    /// FIELD PROVENANCE, CIRISEdge#546 — the swarm converger's four keys,
    /// admitted through persist's REAL door, each landing on its OWN relief
    /// field. Every value is deliberately distinct so a fold that fused the
    /// symbol and holder axes back together (the pre-CIRISPersist#602 shape)
    /// shows up as a crossed assertion rather than as a passing test.
    #[tokio::test]
    async fn admitted_redundancy_rows_populate_each_swarm_field_separately() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;

        // All four are `HigherMeansMoreFlow` against persist's `owner_default`
        // ceilings (k_repair 20, min_viable_symbols 20, both holder keys 64),
        // so every value below is a RELIEF and none is clamped away.
        for (key, value) in [
            (MeshConfigKey::RedundancyKRepairSymbols, 4),
            (MeshConfigKey::RedundancyMinViableSymbols, 3),
            (MeshConfigKey::RedundancyTargetHolders, 12),
            (MeshConfigKey::RedundancyMinViableHolders, 2),
        ] {
            let row = mesh_row("root-1", key, value, MeshConfigForm::Emergency);
            let outcome =
                record_mesh_config_row(&*backend, "node-local", &baseline(), &row, Utc::now())
                    .await
                    .expect("admission door reachable");
            assert!(
                matches!(outcome, MeshConfigOutcome::Admitted),
                "the REAL admission door must admit the fixture row (fixture rot \
                 otherwise invalidates every downstream assertion): {outcome:?}"
            );
        }

        let relief = reader_over(&backend).await.relief().await;
        assert_eq!(relief.k_repair_symbols, Some(4));
        assert_eq!(relief.min_viable_symbols, Some(3));
        assert_eq!(relief.target_holders, Some(12));
        assert_eq!(relief.min_viable_holders, Some(2));
        assert_eq!(
            relief.round_cadence, None,
            "the #440 keys stay un-relieved — a redundancy row must not move them"
        );
    }

    /// FIELD PROVENANCE, replication plane — feature pause rows arriving the
    /// way edge actually receives them (`put_attestation`, the door persist's
    /// own docs designate: "the read-time clamp in `fold_mesh_config` is what
    /// holds for rows that arrive on the replication plane") flip both pauses.
    #[tokio::test]
    async fn replicated_feature_rows_flip_the_pauses() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;
        for key in [
            MeshConfigKey::FeatureTraceReplication,
            MeshConfigKey::FeatureAvStreams,
        ] {
            backend
                .put_attestation(SignedAttestation {
                    attestation: mesh_row("root-1", key, 0, MeshConfigForm::Emergency),
                })
                .await
                .expect("replication-plane admit");
        }
        let relief = reader_over(&backend).await.relief().await;
        assert!(relief.trace_replication_paused);
        assert!(relief.av_streams_paused);
        assert_eq!(
            relief.round_cadence, None,
            "untouched keys stay un-relieved"
        );
    }

    /// RELIEVE-NEVER-EXPAND consumed, not re-derived: a replicated row asking
    /// for MORE flow than the baseline (round_secs=1 under a 30 s baseline)
    /// clamps to the baseline in the fold — so it is NOT relieved and the
    /// consumer keeps its configured cadence.
    #[tokio::test]
    async fn expansion_clamps_to_baseline_and_is_not_relief() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;
        backend
            .put_attestation(SignedAttestation {
                attestation: mesh_row(
                    "root-1",
                    MeshConfigKey::AntientropyRoundSecs,
                    1,
                    MeshConfigForm::Emergency,
                ),
            })
            .await
            .expect("replication-plane admit");
        let relief = reader_over(&backend).await.relief().await;
        assert_eq!(
            relief.round_cadence, None,
            "an expanding row must clamp to baseline (not relieved) — the CC 4.2.1 \
             rule 1 guarantee, consumed from persist's fold"
        );
    }

    /// A row from a root this node holds NO subscription edge to does not
    /// count — "the trust edge is the subscription."
    #[tokio::test]
    async fn unsubscribed_root_rows_do_not_count() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-stranger").await;
        // NO delegates_to(node → root-stranger).
        backend
            .put_attestation(SignedAttestation {
                attestation: mesh_row(
                    "root-stranger",
                    MeshConfigKey::FeatureTraceReplication,
                    0,
                    MeshConfigForm::Emergency,
                ),
            })
            .await
            .expect("replication-plane admit");
        let relief = reader_over(&backend).await.relief().await;
        assert_eq!(relief, MeshConfigRelief::NONE);
    }

    /// The snapshot TTL: a fresh cache does NOT re-read (a row landing inside
    /// the window is invisible until expiry); TTL zero re-reads every call.
    #[tokio::test]
    async fn snapshot_ttl_bounds_the_re_read() {
        let backend = Arc::new(MemoryBackend::new());
        seed_key(&backend, "node-local").await;
        seed_key(&backend, "root-1").await;
        seed_subscription(&backend, "node-local", "root-1").await;
        let dir: Arc<dyn FederationDirectory> = Arc::clone(&backend) as _;
        let cached = MeshConfigReader::new(dir, "node-local".to_string(), baseline())
            .with_ttl(Duration::from_secs(3600));
        assert_eq!(cached.relief().await, MeshConfigRelief::NONE);
        backend
            .put_attestation(SignedAttestation {
                attestation: mesh_row(
                    "root-1",
                    MeshConfigKey::AntientropyPageLimit,
                    50,
                    MeshConfigForm::Emergency,
                ),
            })
            .await
            .expect("replication-plane admit");
        assert_eq!(
            cached.relief().await,
            MeshConfigRelief::NONE,
            "within the TTL the memo answers"
        );
        let fresh = reader_over(&backend).await;
        assert_eq!(fresh.relief().await.page_limit, Some(50));
    }
}
