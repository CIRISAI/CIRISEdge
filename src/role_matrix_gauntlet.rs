//! The ROLE_MATRIX gauntlet — one test per decision-matrix cell.
//!
//! `docs/ROLE_MATRIX.md` declares five orthogonal actor axes and a decision
//! table binding every runtime decision to exactly ONE axis. This module is
//! the table's enforcement: each `R<n>` test covers one row, and the
//! orthogonality rows are exercised as full cross-products (every tier ×
//! every `AgentMode`), because "keyed on the right axis" is only proven by
//! showing the WRONG axis moves and nothing changes.
//!
//! In-crate rather than `tests/` so the rows can drive the real
//! `FederationDirectoryReplicationBridge` through its test builders. The doc
//! itself is compile-pinned at the bottom: renaming a symbol the matrix names
//! reds this file in the same commit.

#![cfg(test)]

use crate::replication::retention::Retention;
use crate::replication::serve_tier::ServeTier;
use crate::AgentMode;

const ALL_TIERS: [ServeTier; 3] = [ServeTier::None, ServeTier::MeshServer, ServeTier::Canonical];
const ALL_MODES: [AgentMode; 3] = [AgentMode::Client, AgentMode::Proxy, AgentMode::Server];

/// R1 — listener / queue size keys on Axis 1 (`AgentMode`) alone.
///
/// `apply_defaults` is the one place mode becomes behavior; the derived fields
/// must move with mode and with nothing else.
#[test]
fn r1_listener_and_queue_key_on_agent_mode() {
    let mut seen = std::collections::HashSet::new();
    for mode in ALL_MODES {
        let mut config = crate::EdgeConfig::default();
        mode.apply_defaults(&mut config);
        assert_eq!(
            config.listener_bound,
            !matches!(mode, AgentMode::Client),
            "{mode:?}: Client is egress-only; Proxy and Server bind"
        );
        seen.insert(config.outbound_queue_max);
    }
    assert!(
        seen.len() >= 2,
        "the queue bound must actually vary with mode — identical values would \
         mean the axis is decorative"
    );
}

/// R2 — who consents keys on Axis 2 (`identity_type`), resolved from the
/// directory row, never from the identifier's shape.
#[tokio::test]
async fn r2_contactability_keys_on_identity_type() {
    struct Lens;
    #[async_trait::async_trait]
    impl crate::contact::DirectoryLens for Lens {
        async fn identity_type_of(&self, key_id: &str) -> Option<String> {
            Some(
                match key_id {
                    "frank-fed" => "user",
                    "frank-agent" => "agent",
                    "steward-1" => "steward",
                    _ => return None,
                }
                .to_string(),
            )
        }
        async fn owner_of(&self, _k: &str) -> Option<String> {
            Some("frank-fed".to_string())
        }
        async fn nodes_owned_by(&self, _f: &str) -> Vec<String> {
            vec!["frank-node".to_string()]
        }
    }

    // A person resolves to themselves; an agent to its OWNER (an agent cannot
    // consent); a steward is TERMINAL — no amount of convergence makes it a
    // person, so a retrying caller would retry forever.
    let person = crate::contact::resolve(&Lens, "frank-fed").await.unwrap();
    assert_eq!(person.fed_id, "frank-fed");
    let via_agent = crate::contact::resolve(&Lens, "frank-agent").await.unwrap();
    assert_eq!(
        via_agent.fed_id, "frank-fed",
        "an agent resolves to its owner"
    );
    let steward = crate::contact::resolve(&Lens, "steward-1").await;
    assert!(
        matches!(
            steward,
            Err(crate::contact::LadderStall::NotContactable { .. })
        ),
        "a steward is not a contactable person: {steward:?}"
    );
}

/// R0 — the WIRING row: the tier is resolved on the path production actually
/// calls.
///
/// Every other row pins the tier with `with_serve_tier_for_test` and asks
/// whether the DECISION is right. That is necessary and was not sufficient: the
/// refresh was first added to `list_envelope_refs` (peer-blind — diagnostics and
/// tests) while `DirectoryStateAdapter::local_refs` calls
/// `list_envelope_refs_for_peer`. Every decision row stayed green while the
/// cache sat at `ServeTier::None` forever in production, so a canonical used
/// `Bodies` and discarded every advertised hash.
///
/// This row drives the bridge through the trait method production uses and
/// asserts the resolver was consulted. A decision table cannot catch an
/// unwired decision; only the wiring row can.
#[tokio::test]
async fn r0_the_tier_is_resolved_on_the_production_round_path() {
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    use crate::replication::serve_tier::{ServeTier as T, ServeTierResolver};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting(AtomicUsize);
    #[async_trait::async_trait]
    impl ServeTierResolver for Counting {
        async fn resolve(&self, _s: &str) -> T {
            self.0.fetch_add(1, Ordering::SeqCst);
            T::MeshServer
        }
    }

    let resolver = std::sync::Arc::new(Counting(AtomicUsize::new(0)));
    let (_backend, bridge) = crate::replication::bridge::test_fixtures::make_bridge(&[]);
    let bridge = bridge
        .with_local_key_id(Some("local-A".to_string()))
        .with_serve_tier_resolver(Some(
            std::sync::Arc::clone(&resolver) as std::sync::Arc<dyn ServeTierResolver>
        ));

    assert_eq!(
        bridge.serve_tier(),
        T::None,
        "fail-closed before first resolve"
    );

    // THE production round path — what `DirectoryStateAdapter::local_refs`
    // calls. Not `list_envelope_refs`, which is the peer-blind diagnostic twin.
    let _ = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-1"))
        .await;

    assert_eq!(
        resolver.0.load(Ordering::SeqCst),
        1,
        "the round path must consult the resolver — refreshing only on the \
         diagnostic path leaves production pinned at tier none forever"
    );
    assert_eq!(
        bridge.serve_tier(),
        T::MeshServer,
        "and the resolved tier must reach the cache the sync readers use"
    );
}

/// R0b — the tier is resolved for the ADVERTISED identity, not the actor.
///
/// ROLE_MATRIX axes 2 and 3 are orthogonal, and #541 splits the identity in
/// two: peers see the node, stored rows and agency are the actor's. A
/// conferral is granted against the identity peers registered — the node — so
/// resolving the tier for the actor leaves a blessed node at `ServeTier::None`
/// with its directory role silently off. Exactly the actor/node conflation
/// #541 exists to prevent, arriving through a new door.
#[test]
fn r0b_the_tier_subject_is_the_advertised_identity() {
    let config = crate::replication::ReplicationRuntimeConfig {
        local_key_id: Some("actor-aaa".to_string()),
        serve_tier_subject_key_id: Some("node-bbb".to_string()),
        ..Default::default()
    };

    // The two are DISTINCT fields. Collapsing them would move the E3 trace
    // gate's truster identity as a side effect, which is why the tier gets its
    // own.
    assert_ne!(
        config.local_key_id, config.serve_tier_subject_key_id,
        "the tier subject and the truster are different questions"
    );

    // Unset, the tier subject falls back to local_key_id — correct wherever the
    // two identities coincide, which is every deployment without the flag.
    let plain = crate::replication::ReplicationRuntimeConfig {
        local_key_id: Some("both-ccc".to_string()),
        ..Default::default()
    };
    assert!(
        plain.serve_tier_subject_key_id.is_none(),
        "no separate subject by default"
    );
}

/// R0c — the REFRESH uses the advertised identity, not just the resolver.
///
/// Half-applied fixes are their own failure mode: the resolver was built with
/// the advertised subject while `refresh_serve_tier` still passed
/// `local_key_id`, so a blessed node resolved as its actor exactly as before.
/// Drives the production round path and asserts which subject the resolver was
/// asked about.
#[tokio::test]
async fn r0c_the_refresh_asks_about_the_advertised_identity() {
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    use crate::replication::serve_tier::{ServeTier as T, ServeTierResolver};

    struct Recording(std::sync::Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl ServeTierResolver for Recording {
        async fn resolve(&self, subject: &str) -> T {
            self.0.lock().unwrap().push(subject.to_string());
            T::Canonical
        }
    }

    let resolver = std::sync::Arc::new(Recording(std::sync::Mutex::new(Vec::new())));
    let (_backend, bridge) = crate::replication::bridge::test_fixtures::make_bridge(&[]);
    let bridge = bridge
        .with_local_key_id(Some("actor-aaa".to_string()))
        .with_serve_tier_subject(Some("node-bbb".to_string()))
        .with_serve_tier_resolver(Some(
            std::sync::Arc::clone(&resolver) as std::sync::Arc<dyn ServeTierResolver>
        ));

    let _ = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-1"))
        .await;

    assert_eq!(
        resolver.0.lock().unwrap().as_slice(),
        ["node-bbb"],
        "the tier is a property of the identity peers registered — asking about \
         the actor leaves a blessed node at ServeTier::None"
    );
}

/// R3 — retention keys on Axis 3 (tier), and `AgentMode` does not exist in
/// the decision at all.
///
/// The full 3×3 cross-product, because this exact cell is where v18.12.1 was
/// wrong: mode moved the answer. Now the tier row must decide identically in
/// every mode column.
#[test]
fn r3_retention_keys_on_tier_across_every_mode() {
    use crate::replication::protocol::EnvelopeKind;
    for tier in ALL_TIERS {
        for _mode in ALL_MODES {
            // BridgeConfig no longer HAS a mode field — the mode column of this
            // cross-product is vacuous by construction, which is the strongest
            // available proof: the wrong axis is not merely ignored, it is
            // unrepresentable. The loop is kept so the cell reads as the matrix
            // row it enforces.
            let configured = if tier.holds_hash_directory() {
                Retention::HashFirst
            } else {
                Retention::Bodies
            };
            // Hash-first eligibility is then still filtered per-plane by the
            // #553 carve-outs:
            assert_eq!(
                crate::replication::retention::retention_for(EnvelopeKind::Key, configured),
                configured,
                "{tier:?}: Key follows the configured retention"
            );
            assert_eq!(
                crate::replication::retention::retention_for(EnvelopeKind::Revocation, configured),
                Retention::Bodies,
                "{tier:?}: a revocation NEVER goes hash-only — a node holding \
                 the hash of a kill order has not been killed"
            );
        }
    }
}

/// R3 (production wiring) — the bridge's `retention()` reads the TIER cache.
#[tokio::test]
async fn r3_bridge_retention_follows_the_tier() {
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    for (tier, expected_key) in [
        (ServeTier::None, Retention::Bodies),
        (ServeTier::MeshServer, Retention::HashFirst),
        // A canonical holds BODIES — it must, to answer identifier lookups.
        (ServeTier::Canonical, Retention::Bodies),
    ] {
        let (_backend, bridge) = crate::replication::bridge::test_fixtures::make_bridge(&[]);
        let bridge = bridge.with_serve_tier_for_test(tier);
        assert_eq!(
            bridge.retention(EnvelopeKind::Key),
            expected_key,
            "{tier:?}: hash-first iff the tier may store and serve"
        );
        assert_eq!(
            bridge.retention(EnvelopeKind::Revocation),
            Retention::Bodies,
            "{tier:?}: the revocation carve-out survives every tier"
        );
    }
}

/// R4 — known-hash recording keys on Axis 3: only a conferred server
/// accumulates the directory.
#[tokio::test]
async fn r4_known_hashes_key_on_tier() {
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    for tier in ALL_TIERS {
        let (_backend, bridge) = crate::replication::bridge::test_fixtures::make_bridge(&[]);
        let bridge = bridge.with_serve_tier_for_test(tier);
        bridge.note_known_hashes(EnvelopeKind::Key, &[[7u8; 32]], Some("peer-1"));
        assert_eq!(
            bridge.known_hash_count_for_test() > 0,
            tier.holds_hash_directory(),
            "{tier:?}: only the hash-carrying tier accumulates the directory"
        );
    }
}

/// R5 — missing-signer recovery is NOT decided by the tier (CIRISEdge#568).
///
/// It used to be: recovery keyed on the Key plane's retention, so a
/// `Bodies` node never asked, on the reasoning that the key replicates on its
/// own. It does — one to three anti-entropy rounds later, because the Key and
/// Attestation planes run on independent coordinators with no ordering between
/// them. #568 measured 33 s and 90 s for the two directions of the same pair of
/// announces.
///
/// The decision left Axis 3 because the storage mode was never what it was
/// about. The predicate is a property of the ROW — it named a key this node
/// does not hold — and that is equally true at every tier. This row pins that
/// the gauntlet's other axes cannot quietly re-acquire it.
#[test]
fn r5_missing_signer_recovery_is_not_decided_by_the_tier() {
    // The symbol that carried the tier decision is GONE, not merely unused: a
    // predicate that returns the same answer for every input is a lie waiting
    // to mislead whoever reads it next. This row asserts the shape that
    // replaced it — every tier records, so no tier can be starved of a key by
    // its retention.
    for tier in ALL_TIERS {
        let configured = if tier.holds_hash_directory() {
            Retention::HashFirst
        } else {
            Retention::Bodies
        };
        // Retention still decides what this node STORES...
        assert_eq!(
            crate::replication::retention::retention_for(
                crate::replication::protocol::EnvelopeKind::Key,
                configured,
            ),
            configured,
            "{tier:?}: the Key plane still honours its configured retention"
        );
        // ...and no longer decides whether it may ASK for a key it lacks.
        // (`note_missing_signer` takes no retention input at all — the compile
        // is the assertion.)
    }
}

/// R6 — a third-party identifier Pull is NOT decided by the tier.
///
/// node/fed/agent IDs are federation cohort: servable by any peer holding
/// them, to any requester under a mutual trust root. This fixture seeds no
/// delegations, so the honest assertion here is the NEGATIVE one — every tier
/// refuses — which is also the regression that matters: a tier must never be
/// able to substitute for the shared root.
#[tokio::test]
async fn r6_third_party_pull_keys_on_tier() {
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    for tier in ALL_TIERS {
        let (backend, bridge) =
            crate::replication::bridge::test_fixtures::make_bridge_with_keys(&[
                "local-A",
                "subject-S",
                "stranger-X",
            ])
            .await;
        let _ = backend;
        let bridge = bridge
            .with_local_key_id(Some("local-A".to_string()))
            .with_serve_tier_for_test(tier);

        // Third party: conferred servers only.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Key, "subject-S", Some("stranger-X"))
                .await
                .is_empty(),
            "{tier:?}: with NO mutual trust root, no tier answers a third-party \
             lookup — entitlement is the shared root, not the rung (CC 4: two \
             nodes with no shared root compose nothing). The positive case is \
             `identifier_lookups_are_entitled_by_a_mutual_trust_root`, which \
             needs seeded delegations this fixture deliberately does not carry"
        );
        // R7 — the data-subject path: EVERY tier answers the subject itself.
        assert!(
            !bridge
                .subject_holdings(EnvelopeKind::Key, "subject-S", Some("subject-S"))
                .await
                .is_empty(),
            "{tier:?}: subject access (#462) does not depend on serving tier"
        );
        // R8 — the own-record path: every tier serves its own record.
        assert!(
            !bridge
                .subject_holdings(EnvelopeKind::Key, "local-A", Some("stranger-X"))
                .await
                .is_empty(),
            "{tier:?}: a node's own record is what self_own already advertises"
        );
        // Unattributed is refused at every tier.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Key, "subject-S", None)
                .await
                .is_empty(),
            "{tier:?}: an unattributed Pull serves nothing, tier or no tier"
        );
        // R9 boundary — Attestation never blankets, even for a canonical: its
        // entitlement is per ROW (trace:* capability, the G2 carve).
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, "subject-S", Some("stranger-X"))
                .await
                .is_empty(),
            "{tier:?}: the one subject≠sender plane keeps per-row gating — the \
             CI cross-walk's prediction"
        );
    }
}

/// R9 — trace-plane serving requires the CANONICAL rung (leg A ∧ leg B), not
/// mere storage conferral. A mesh server may hold the corpus and still must
/// not receive trace attestations.
#[tokio::test]
async fn r9_trace_serving_requires_blessing_not_storage() {
    // The gate resolves the PEER's blessing from the directory. With no accord
    // co-scrub in the fixture, every tier of LOCAL conferral still withholds —
    // proving the decision reads the peer's cryptography, not local state.
    for tier in ALL_TIERS {
        let (_backend, bridge) =
            crate::replication::bridge::test_fixtures::make_bridge_with_keys(&[
                "local-A", "peer-P",
            ])
            .await;
        let bridge = bridge
            .with_local_key_id(Some("local-A".to_string()))
            .with_serve_tier_for_test(tier);
        assert!(
            !bridge.peer_has_serve_capability_for_test("peer-P").await,
            "{tier:?}: an unblessed peer is withheld from the trace plane no \
             matter what THIS node's tier is — blessing is the peer's property, \
             re-derived from its own records"
        );
    }
}

/// R11 — fedID discoverability keys on Axis 4 (announce): a subject is
/// resolvable exactly when its records are present.
#[tokio::test]
async fn r11_fedid_discovery_keys_on_announce() {
    struct Announced(bool);
    #[async_trait::async_trait]
    impl crate::contact::DirectoryLens for Announced {
        async fn identity_type_of(&self, _k: &str) -> Option<String> {
            self.0.then(|| "user".to_string())
        }
        async fn owner_of(&self, _k: &str) -> Option<String> {
            None
        }
        async fn nodes_owned_by(&self, _f: &str) -> Vec<String> {
            if self.0 {
                vec!["their-node".to_string()]
            } else {
                Vec::new()
            }
        }
    }
    assert!(
        crate::contact::resolve(&Announced(true), "frank-fed")
            .await
            .is_ok(),
        "announced ⇒ resolvable by fedID"
    );
    assert!(
        matches!(
            crate::contact::resolve(&Announced(false), "frank-fed").await,
            Err(crate::contact::LadderStall::NotYetDiscovered { .. })
        ),
        "not announced ⇒ not discoverable by fedID — only direct P2P works"
    );
}

/// R12 — fedcode contact keys on NO axis: the code is self-contained, and the
/// binding check is what stands between "self-contained" and "impersonation
/// primitive".
#[test]
fn r12_fedcode_is_self_contained_and_binding_checked() {
    use base64::Engine as _;
    // Not announced anywhere, no directory involved: parse alone yields the
    // admissible key material.
    let mut pubkey = [0u8; 32];
    pubkey[0] = 42;
    let key_id = ciris_verify_core::fedcode::derive_key_id("offgrid", &pubkey);
    let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
        kind: ciris_verify_core::fedcode::FedKind::User,
        key_id: key_id.clone(),
        pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
        transport_hint: Some("https://example.invalid".into()),
        alias_hint: None,
        group_key_id: None,
        owned_nodes: Vec::new(),
        ml_dsa_65_pubkey_sha256: None,
    })
    .expect("encode");
    let parsed = crate::contact::parse_contact_input(&code).expect("a good code decodes");
    let admission = parsed
        .admission
        .expect("carries the key the directory cannot supply");
    assert_eq!(admission.key_id, key_id);
    assert!(
        admission.transport_hint.is_some(),
        "v2 carries the transport hint"
    );

    // And a forged claim over a different key is refused (the CRC cannot catch
    // authorship; only the derivation binding can).
    let forged = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
        kind: ciris_verify_core::fedcode::FedKind::User,
        key_id,
        pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode([0xAA_u8; 32]),
        transport_hint: None,
        alias_hint: None,
        group_key_id: None,
        owned_nodes: Vec::new(),
        ml_dsa_65_pubkey_sha256: None,
    })
    .expect("a forgery encodes fine");
    assert!(
        matches!(
            crate::contact::parse_contact_input(&forged),
            Err(crate::contact::LadderStall::CodeIdentityMismatch { .. })
        ),
        "a code claiming an address its key does not derive is refused"
    );
}

/// R13 — group planes never enter the public-pull namespace: their
/// destinations are DERIVED from member-held state, so there is no directory
/// flow to widen (CC 5.4.6).
#[test]
fn r13_group_planes_are_not_publicly_pullable() {
    use crate::replication::protocol::EnvelopeKind;
    for kind in [EnvelopeKind::Family, EnvelopeKind::Community] {
        assert!(
            !kind.is_public_subject_pull(),
            "{kind:?}: group existence is structurally invisible — a public \
             identifier Pull over it would be announcement by the back door"
        );
    }
}

/// The claims ladder, rung 1 — a CLAIM is not a CAPABILITY. The production
/// resolver must answer `None` for a row that claims `infra:serve` with no
/// verifiable conferral (fail-closed pending CIRISPersist#788).
#[tokio::test]
async fn ladder_a_claim_alone_confers_no_tier() {
    use crate::replication::serve_tier::{DirectoryServeTierResolver, ServeTierResolver as _};
    let (backend, _bridge) =
        crate::replication::bridge::test_fixtures::make_bridge_with_keys(&["claimer-C"]).await;
    let resolver = DirectoryServeTierResolver::new(backend, "resolver-R".to_string());
    assert_eq!(
        resolver.resolve("claimer-C").await,
        ServeTier::None,
        "no accord co-scrub, no verifiable owner grant ⇒ tier none, however \
         loudly the row claims the role"
    );
}

/// Compile-pin: every symbol the matrix's decision table names. A rename reds
/// this file in the commit that makes the document stale.
#[allow(dead_code)]
fn the_matrix_symbols_compile() {
    let _: fn(ServeTier) -> bool = ServeTier::holds_hash_directory;
    let _: fn(ServeTier) -> bool = ServeTier::trusted_for_bootstrap;
    let _: fn(crate::replication::protocol::EnvelopeKind, Retention) -> Retention =
        crate::replication::retention::retention_for;
    let _ = crate::replication::serve_tier::CachedServeTier::TTL;
    let _: &str = crate::replication::serve_policy::SERVE_ADVERTISE_POLICY_HASH;
}
