//! **Announce and share traces are two consents.** The witnesses for
//! [`trace_recipient_withholds`](FederationDirectoryReplicationBridge::trace_recipient_withholds).
//!
//! The first half drives the gate directly with the two values production hands
//! it: [`advertise_gate_view`](FederationDirectoryReplicationBridge::advertise_gate_view)
//! of a stored row, and the bare wire row a fetch parses. The `test-anchor`
//! half drives the whole advertise and fetch paths past the `infra:serve` gate,
//! which needs a genuine accord co-scrub (CIRISPersist#484).
use super::*;
use crate::observability::WithholdReason;

const ANNOUNCE: [&str; 2] = ["ownership:", "self:delegates_to:"];
const SHARE: [&str; 1] = ["trace:"];
const LOCAL: &str = "trace-node";

/// A `consent:replication:v1` grant by `granter` naming `subject`, with extra
/// payload members. Returns its id.
async fn seed_grant(
    backend: &SqliteBackend,
    granter: &str,
    subject: &str,
    prefixes: &[&str],
    extra: serde_json::Value,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let mut payload = serde_json::json!({
        "grants": "transfer",
        "attestation_prefixes": prefixes,
    });
    if let serde_json::Value::Object(extra) = extra {
        for (k, v) in extra {
            payload[k] = v;
        }
    }
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": granter,
        "attested_key_id": subject,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": payload,
    });
    seed_raw_attestation(backend, &id, granter, subject, "scores", envelope).await;
    id
}

fn no_extra() -> serde_json::Value {
    serde_json::json!({})
}

/// The stored row whose dimension starts with `prefix`, as the directory
/// returns it to the advertise sweep.
async fn stored_row(backend: &SqliteBackend, author: &str, prefix: &str) -> Attestation {
    backend
        .list_attestations_since(None, 1000)
        .await
        .expect("read the plane")
        .into_iter()
        .map(|served| served.attestation)
        .find(|a| {
            a.attesting_key_id == author
                && a.attestation_envelope
                    .get("dimension")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|d| d.starts_with(prefix))
        })
        .expect("the seeded row is on the plane")
}

/// The gate's answer on BOTH production inputs, which must agree.
async fn withholds(
    bridge: &FederationDirectoryReplicationBridge,
    row: &Attestation,
    peer: &str,
) -> bool {
    type B = FederationDirectoryReplicationBridge;
    let view = B::advertise_gate_view(row);
    let on_advertise = bridge
        .trace_recipient_withholds(
            &view,
            &B::audience_of_view(&view),
            peer,
            &mut TraceConsentMemo::default(),
            "advertise",
        )
        .await;
    let wire = serde_json::to_value(row).expect("the wire row");
    let on_fetch = bridge
        .trace_recipient_withholds(
            &wire,
            &B::audience_of_row_value(&wire),
            peer,
            &mut TraceConsentMemo::default(),
            "fetch",
        )
        .await;
    assert_eq!(
        on_advertise, on_fetch,
        "the advertise and fetch twins must answer alike for {peer}"
    );
    on_fetch
}

fn local_bridge(
    keys: &[(&str, &str)],
) -> (
    Arc<SqliteBackend>,
    FederationDirectoryReplicationBridge,
    crate::observability::EdgeMetrics,
) {
    let cohort: Vec<String> = keys.iter().map(|(k, _)| (*k).to_string()).collect();
    let (backend, bridge, metrics) = make_metered_bridge(&cohort);
    (
        backend,
        bridge.with_local_key_id(Some(LOCAL.to_string())),
        metrics,
    )
}

/// **The ruling.** Same node, one promoted trace row: the peer whose grant
/// covers `trace:` is served, the peer holding an announce-only grant is not,
/// and the one refusal is booked with its dimension.
#[tokio::test]
async fn a_grant_for_one_peer_is_not_consent_for_another() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("lens-a", identity_type::NODE),
        ("canonical-b", identity_type::NODE),
    ];
    let (backend, bridge, metrics) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_grant(&backend, LOCAL, "lens-a", &SHARE, no_extra()).await;
    seed_grant(&backend, LOCAL, "canonical-b", &ANNOUNCE, no_extra()).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;

    assert!(!withholds(&bridge, &row, "lens-a").await);
    assert_eq!(
        metrics.withholds(WithholdReason::TraceNotConsentedToRecipient),
        0,
        "an allowed row books nothing"
    );
    assert!(withholds(&bridge, &row, "canonical-b").await);
    let snap = metrics.snapshot();
    assert_eq!(
        snap.withholds_by_reason
            .get(&WithholdReason::TraceNotConsentedToRecipient)
            .copied(),
        Some(2),
        "one count per decision: the advertise call and the fetch call"
    );
    let last = snap.recent_withholds.last().expect("a recent entry");
    assert_eq!(last.peer_key_id, "canonical-b");
    assert_eq!(last.detail, "trace:complete:v1");
}

/// Coverage is by dimension, with the grammar's own `covers`.
#[tokio::test]
async fn a_narrow_prefix_covers_only_its_own_dimensions() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("lens-covered", identity_type::NODE),
        ("lens-elsewhere", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_grant(
        &backend,
        LOCAL,
        "lens-covered",
        &["trace:complete:"],
        no_extra(),
    )
    .await;
    seed_grant(
        &backend,
        LOCAL,
        "lens-elsewhere",
        &["trace:other:"],
        no_extra(),
    )
    .await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    assert!(!withholds(&bridge, &row, "lens-covered").await);
    assert!(withholds(&bridge, &row, "lens-elsewhere").await);
}

/// A grant the promotion sweep would decline covers nothing here either: a
/// principle that does not authorize transmission, a lapsed `valid_until`, an
/// ingress grant.
#[tokio::test]
async fn a_grant_that_does_not_authorize_egress_covers_nothing() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("lens-retain", identity_type::NODE),
        ("lens-lapsed", identity_type::NODE),
        ("lens-ingress", identity_type::NODE),
        ("lens-publish", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    let lapsed = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    for (peer, extra) in [
        ("lens-retain", serde_json::json!({ "principle": "retain" })),
        ("lens-lapsed", serde_json::json!({ "valid_until": lapsed })),
        (
            "lens-ingress",
            serde_json::json!({ "direction": "ingress" }),
        ),
        (
            "lens-publish",
            serde_json::json!({ "principle": "publish" }),
        ),
    ] {
        seed_grant(&backend, LOCAL, peer, &SHARE, extra).await;
    }
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    assert!(withholds(&bridge, &row, "lens-retain").await);
    assert!(withholds(&bridge, &row, "lens-lapsed").await);
    assert!(withholds(&bridge, &row, "lens-ingress").await);
    assert!(
        !withholds(&bridge, &row, "lens-publish").await,
        "`publish` propagates, as `share` does"
    );
}

/// **A relay keeps flowing.** A row another key authored is that producer's
/// flow: a node holding no grant from it carries it on. The trap is the
/// self-publish set, which names third parties' anchored keys: a row by such a
/// key is still a relay.
#[tokio::test]
async fn a_relayed_row_is_not_this_nodes_consent_to_give() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("agent-elsewhere", identity_type::AGENT),
        ("lens-a", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    let publish = vec![LOCAL.to_string(), "agent-elsewhere".to_string()];
    let bridge = bridge.with_self_provider(Some(Arc::new(move || publish.clone())));
    register_fixture_keys(&backend, &keys).await;
    seed_grant(&backend, LOCAL, "lens-a", &ANNOUNCE, no_extra()).await;
    seed_trace_attestation(&backend, "agent-elsewhere").await;
    let row = stored_row(&backend, "agent-elsewhere", "trace:").await;
    assert!(!withholds(&bridge, &row, "lens-a").await);
}

/// The owner's own row is this node's to consent for: it is gated, not relayed.
#[tokio::test]
async fn a_row_of_this_nodes_owner_is_gated() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("owner-u", identity_type::USER),
        ("lens-a", identity_type::NODE),
        ("canonical-b", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_owner_binding(&backend, "owner-u", LOCAL).await;
    // The owner's own grant, naming no machine: it speaks for the owner's rows.
    seed_grant(&backend, "owner-u", "lens-a", &SHARE, no_extra()).await;
    seed_trace_attestation(&backend, "owner-u").await;
    let row = stored_row(&backend, "owner-u", "trace:").await;
    assert!(!withholds(&bridge, &row, "lens-a").await);
    assert!(withholds(&bridge, &row, "canonical-b").await);
}

/// **The split home.** The node is the wire identity, the agent authors the
/// trace, and the owner's grant names the agent in `for_key_id`. A lens the
/// owner named is served; a canonical the owner only announced to is not; and
/// the owner's grant for a SIBLING agent says nothing about this one.
#[tokio::test]
async fn an_owner_grant_for_the_agent_counts_through_the_steward() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("agent-x", identity_type::AGENT),
        ("agent-sibling", identity_type::AGENT),
        ("owner-u", identity_type::USER),
        ("lens-a", identity_type::NODE),
        ("lens-of-sibling", identity_type::NODE),
        ("canonical-b", identity_type::NODE),
    ];
    let (backend, bridge, metrics) = local_bridge(&keys);
    let bridge = bridge.with_consent_subjects(vec!["agent-x".to_string()]);
    register_fixture_keys(&backend, &keys).await;
    seed_owner_binding(&backend, "owner-u", "agent-x").await;
    seed_owner_binding(&backend, "owner-u", "agent-sibling").await;
    let for_agent = serde_json::json!({ "for_key_id": "agent-x" });
    seed_grant(&backend, "owner-u", "lens-a", &SHARE, for_agent.clone()).await;
    seed_grant(&backend, "owner-u", "canonical-b", &ANNOUNCE, for_agent).await;
    seed_grant(
        &backend,
        "owner-u",
        "lens-of-sibling",
        &SHARE,
        serde_json::json!({ "for_key_id": "agent-sibling" }),
    )
    .await;
    seed_trace_attestation(&backend, "agent-x").await;
    let row = stored_row(&backend, "agent-x", "trace:").await;

    assert!(
        !withholds(&bridge, &row, "lens-a").await,
        "the steward's grant naming the agent covers the agent's trace"
    );
    assert!(withholds(&bridge, &row, "canonical-b").await);
    assert!(withholds(&bridge, &row, "lens-of-sibling").await);
    assert_eq!(metrics.withholds(WithholdReason::TraceConsentReadError), 0);
}

/// The same shape on a home where the host did NOT name the agent as a consent
/// subject: a row whose author IS the local key still reads that key's stewards.
#[tokio::test]
async fn an_owner_grant_for_the_local_key_counts_without_consent_subjects() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("owner-u", identity_type::USER),
        ("lens-a", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_owner_binding(&backend, "owner-u", LOCAL).await;
    seed_grant(
        &backend,
        "owner-u",
        "lens-a",
        &SHARE,
        serde_json::json!({ "for_key_id": LOCAL }),
    )
    .await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    assert!(!withholds(&bridge, &row, "lens-a").await);
}

/// A grant names a PERSON; their bound node is how they are reached (#524), the
/// same axis that put the node in the send set. Refusing here would leave the
/// peer in the send set and dark.
#[tokio::test]
async fn a_grant_naming_a_person_covers_the_node_they_own() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("person-p", identity_type::USER),
        ("node-of-p", identity_type::NODE),
        ("node-of-nobody", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_owner_binding(&backend, "person-p", "node-of-p").await;
    seed_grant(&backend, LOCAL, "person-p", &SHARE, no_extra()).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    assert!(!withholds(&bridge, &row, "node-of-p").await);
    assert!(withholds(&bridge, &row, "node-of-nobody").await);
}

/// Scope is `trace:` only, and a first party keeps its own testimony.
#[tokio::test]
async fn only_trace_rows_to_third_parties_are_gated() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("canonical-b", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_grant(&backend, LOCAL, "canonical-b", &ANNOUNCE, no_extra()).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let trace = stored_row(&backend, LOCAL, "trace:").await;
    let mut capacity = trace.clone();
    capacity.attestation_envelope["dimension"] = serde_json::json!("capacity:cpu:v1");
    assert!(!withholds(&bridge, &capacity, "canonical-b").await);
    let mut about_peer = trace.clone();
    about_peer.subject_key_ids = vec!["canonical-b".to_string()];
    assert!(!withholds(&bridge, &about_peer, "canonical-b").await);
}

/// A placement on a cohort is delivered by its membership, which the audience
/// gate already judged: no grant is read for the owner's own node (CC 3.2). A
/// federation row is what the gate exists for.
#[tokio::test]
async fn a_self_placed_trace_is_the_audience_gates_not_this_gates() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("second-device", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let federation = stored_row(&backend, LOCAL, "trace:").await;
    assert!(withholds(&bridge, &federation, "second-device").await);
    let mut self_placed = federation.clone();
    self_placed.cohort_scope = "self".to_string();
    assert!(!withholds(&bridge, &self_placed, "second-device").await);
}

/// Grants are read at decision time: a withdrawn grant refuses at the next
/// round, with the send-set memo still holding the peer.
#[tokio::test]
async fn a_withdrawn_grant_refuses_at_the_next_round() {
    let keys = [
        (LOCAL, identity_type::NODE),
        ("lens-a", identity_type::NODE),
    ];
    let (backend, bridge, metrics) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    let grant = seed_grant(&backend, LOCAL, "lens-a", &SHARE, no_extra()).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    assert!(!withholds(&bridge, &row, "lens-a").await);
    seed_withdraws(&backend, LOCAL, &grant).await;
    assert!(withholds(&bridge, &row, "lens-a").await);
    assert_eq!(
        metrics.withholds(WithholdReason::TraceNotConsentedToRecipient),
        2
    );
}

/// The memo is the round's and no more: inside one memo the answer is stable,
/// and a fresh memo (the next round) sees the new grant.
#[tokio::test]
async fn a_memo_holds_for_its_round_and_no_longer() {
    type B = FederationDirectoryReplicationBridge;
    let keys = [
        (LOCAL, identity_type::NODE),
        ("lens-late", identity_type::NODE),
    ];
    let (backend, bridge, _) = local_bridge(&keys);
    register_fixture_keys(&backend, &keys).await;
    seed_trace_attestation(&backend, LOCAL).await;
    let row = stored_row(&backend, LOCAL, "trace:").await;
    let view = B::advertise_gate_view(&row);
    let audience = B::audience_of_view(&view);
    let mut round = TraceConsentMemo::default();
    assert!(
        bridge
            .trace_recipient_withholds(&view, &audience, "lens-late", &mut round, "advertise")
            .await
    );
    seed_grant(&backend, LOCAL, "lens-late", &SHARE, no_extra()).await;
    assert!(
        bridge
            .trace_recipient_withholds(&view, &audience, "lens-late", &mut round, "advertise")
            .await,
        "one round is one reading"
    );
    assert!(!withholds(&bridge, &row, "lens-late").await);
}

/// A read this gate cannot answer refuses, and books the read error, not a
/// statement about consent. The branch that decides, with the value the reads
/// return: persist refuses a second owner, so `AmbiguousNodeOwner` cannot be
/// seeded, and an in-memory read does not fail.
#[tokio::test]
async fn a_failed_read_refuses_under_its_own_reason() {
    let (_, bridge, metrics) = local_bridge(&[(LOCAL, identity_type::NODE)]);
    let failed = Err(ciris_persist::federation::Error::Backend(
        "the read failed".to_string(),
    ));
    assert!(bridge.book_trace_decision(failed, "trace:complete:v1", "lens-a", "advertise"));
    assert_eq!(metrics.withholds(WithholdReason::TraceConsentReadError), 1);
    assert_eq!(
        metrics.withholds(WithholdReason::TraceNotConsentedToRecipient),
        0
    );
}

#[cfg(feature = "test-anchor")]
mod through_the_serve_paths {
    use super::*;
    use ciris_persist::federation::accord_test_support::{
        register_accord_holder, signed_canonical_record_with_roles, Identity,
    };
    use ciris_persist::federation::genesis::effective_accord_holder_records;

    const ROOT: &str = "trust-root-1";
    const ATTESTER: &str = "accord-holder-live";

    /// A node on a live trust graph. Only what the bridge reads at decision time
    /// is seeded after it is built, so a peer blessed through [`Self::bless`]
    /// joins a running node.
    struct World {
        backend: Arc<SqliteBackend>,
        bridge: FederationDirectoryReplicationBridge,
        metrics: crate::observability::EdgeMetrics,
        holders: Vec<Identity>,
    }

    impl World {
        /// `cohort` is what the node was started with. Nothing else is named at
        /// boot.
        async fn boot(cohort: &[&str]) -> Self {
            let cohort: Vec<String> = cohort.iter().map(|k| (*k).to_string()).collect();
            let (backend, bridge, metrics) = make_metered_bridge(&cohort);
            let bridge = bridge.with_local_key_id(Some(LOCAL.to_string()));
            let holders: Vec<Identity> = effective_accord_holder_records()
                .iter()
                .map(|r| Identity::new(&r.record.key_id))
                .collect();
            for h in &holders {
                register_accord_holder(&*backend, h)
                    .await
                    .expect("register accord holder");
            }
            register_fixture_keys(
                &backend,
                &[
                    (LOCAL, identity_type::NODE),
                    (ROOT, identity_type::NODE),
                    ("owner-u", identity_type::USER),
                    ("agent-x", identity_type::AGENT),
                    ("agent-elsewhere", identity_type::AGENT),
                ],
            )
            .await;
            let mut attester = fixture_key_record(ATTESTER, identity_type::ACCORD_HOLDER);
            attester.attestation_evidence = Some(
                ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
            );
            backend
                .put_public_key(SignedKeyRecord { record: attester })
                .await
                .expect("seed attester");
            seed_root_charter(&backend, ROOT, &[format!("{ROOT}-successor")]).await;
            seed_acceptance_edge(
                &backend,
                LOCAL,
                ROOT,
                &serde_json::json!(["infra:attest", "infra:serve"]),
            )
            .await;
            seed_accord_lifecycle(&backend, ATTESTER, ROOT).await;
            Self {
                backend,
                bridge,
                metrics,
                holders,
            }
        }

        /// `peer` takes its seat: an accord-co-scrubbed record carrying
        /// `infra:serve`, and a live grant of that scope from the root this node
        /// trusts. Returns the grant's id.
        async fn bless(&self, peer: &str) -> String {
            let (ed_pk, mldsa_pk) = hybrid_pubkeys(peer);
            let record = signed_canonical_record_with_roles(
                peer,
                identity_type::NODE,
                &ed_pk,
                mldsa_pk.as_deref(),
                vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()],
                serde_json::json!({ "key_id": peer }),
                &[&self.holders[0], &self.holders[1]],
            );
            self.backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed co-scrubbed peer");
            seed_common_root(&self.backend, &[LOCAL, peer]).await;
            seed_delegates_to(
                &self.backend,
                ROOT,
                peer,
                &serde_json::json!(["infra:serve"]),
            )
            .await
        }

        /// Does a round offer `peer` this row, and may it fetch the bytes?
        async fn served(&self, peer: &str, hash: &[u8; 32]) -> (bool, bool) {
            let offered = self
                .bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == *hash);
            let fetched = self
                .bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, hash, Some(peer))
                .await
                .is_some();
            (offered, fetched)
        }

        /// The send-set memo's TTL running out: the next round re-reads it.
        fn round_memo_expires(&self) {
            *self.bridge.consent_memo.lock().unwrap() = None;
        }
    }

    /// **The integration witness.** Both peers hold a live `infra:serve`, both
    /// are consent peers, one node, one promoted row. A gets it on both paths, B
    /// on neither, and each path books one refusal.
    #[tokio::test]
    async fn the_share_peer_gets_the_row_and_the_announce_peer_does_not() {
        let w = World::boot(&["peer-a", "peer-b"]).await;
        w.bless("peer-a").await;
        w.bless("peer-b").await;
        seed_grant(&w.backend, LOCAL, "peer-a", &SHARE, no_extra()).await;
        seed_grant(&w.backend, LOCAL, "peer-b", &ANNOUNCE, no_extra()).await;
        seed_trace_attestation(&w.backend, LOCAL).await;
        let hash = locate_trace_hash(&w.bridge).await;

        assert_eq!(w.served("peer-a", &hash).await, (true, true));
        assert_eq!(
            w.metrics
                .withholds(WithholdReason::TraceNotConsentedToRecipient),
            0
        );
        assert_eq!(w.served("peer-b", &hash).await, (false, false));
        assert_eq!(
            w.metrics
                .withholds(WithholdReason::TraceNotConsentedToRecipient),
            2,
            "one count on the advertise, one on the fetch"
        );
    }

    /// The split home on the real paths: the agent authors, the owner's grant
    /// names the agent, and the peers differ only in what that grant covers.
    #[tokio::test]
    async fn the_steward_grant_serves_on_the_real_paths() {
        let w = World::boot(&["peer-a", "peer-b"]).await;
        let bridge = w.bridge;
        let w = World {
            bridge: bridge.with_consent_subjects(vec!["agent-x".to_string()]),
            ..w
        };
        seed_owner_binding(&w.backend, "owner-u", "agent-x").await;
        w.bless("peer-a").await;
        w.bless("peer-b").await;
        let for_agent = serde_json::json!({ "for_key_id": "agent-x" });
        seed_grant(&w.backend, "owner-u", "peer-a", &SHARE, for_agent.clone()).await;
        seed_grant(&w.backend, "owner-u", "peer-b", &ANNOUNCE, for_agent).await;
        seed_trace_attestation(&w.backend, "agent-x").await;
        let hash = locate_trace_hash(&w.bridge).await;
        assert_eq!(w.served("peer-a", &hash).await, (true, true));
        assert_eq!(w.served("peer-b", &hash).await, (false, false));
    }

    /// A relay is untouched on the real paths: an announce-only peer that is
    /// serve-capable still takes a third party's trace from this node.
    #[tokio::test]
    async fn a_relayed_trace_still_reaches_an_announce_only_peer() {
        let w = World::boot(&["lens-b"]).await;
        w.bless("lens-b").await;
        seed_grant(&w.backend, LOCAL, "lens-b", &ANNOUNCE, no_extra()).await;
        seed_trace_attestation(&w.backend, "agent-elsewhere").await;
        let hash = locate_trace_hash(&w.bridge).await;
        assert_eq!(w.served("lens-b", &hash).await, (true, true));
    }

    /// **The roster is live.** One running bridge, never rebuilt. A canonical
    /// nobody named at boot, in no cohort and no baked list, takes its seat and
    /// its grant: served. It loses the grant: refused. A canonical present at
    /// boot has `infra:serve` withdrawn: refused, by the capability gate, with
    /// its grant still live. Each answer is the next round's.
    #[tokio::test]
    async fn a_canonical_joining_or_leaving_the_roster_needs_no_restart() {
        let w = World::boot(&["canonical-early"]).await;
        let baked = crate::edge::baked_canonical_genesis_ids();
        for peer in ["canonical-early", "canonical-late"] {
            assert!(
                !baked.iter().any(|id| id == peer),
                "the witness must not lean on the baked list"
            );
        }
        w.bless("canonical-early").await;
        seed_grant(&w.backend, LOCAL, "canonical-early", &SHARE, no_extra()).await;
        seed_trace_attestation(&w.backend, LOCAL).await;
        let hash = locate_trace_hash(&w.bridge).await;
        assert_eq!(w.served("canonical-early", &hash).await, (true, true));
        assert_eq!(
            w.served("canonical-late", &hash).await,
            (false, false),
            "unknown at boot: no record, no grant"
        );

        // JOIN: the seat alone, with an announce grant: found, and no traces.
        w.bless("canonical-late").await;
        seed_grant(&w.backend, LOCAL, "canonical-late", &ANNOUNCE, no_extra()).await;
        w.round_memo_expires();
        assert_eq!(w.served("canonical-late", &hash).await, (false, false));

        // JOIN: the share grant lands. The row the watermark passed comes back
        // on the rolling re-sweep.
        let share = seed_grant(&w.backend, LOCAL, "canonical-late", &SHARE, no_extra()).await;
        w.round_memo_expires();
        assert_eq!(w.served("canonical-late", &hash).await, (true, true));

        // LEAVE, the grant: refused next round, without waiting out the memo.
        seed_withdraws(&w.backend, LOCAL, &share).await;
        assert_eq!(w.served("canonical-late", &hash).await, (false, false));

        // LEAVE, the role: `infra:serve` tombstoned on the live directory.
        let missing = WithholdReason::ServeCapabilityMissing;
        let before = w.metrics.withholds(missing);
        w.backend
            .record_role_withdrawal(
                FederationDirectoryReplicationBridge::SERVE_CAPABILITY,
                "canonical-early",
                None,
                "digest-of-the-accord-decision",
            )
            .await
            .expect("tombstone the role");
        assert_eq!(w.served("canonical-early", &hash).await, (false, false));
        assert!(
            w.metrics.withholds(missing) > before,
            "the capability gate refused it, on live state"
        );
    }

    /// LEAVE the other way: the root that conferred `infra:serve` withdraws the
    /// grant of it. The accord's blessing is untouched; the walk reads no seat.
    #[tokio::test]
    async fn a_withdrawn_conferral_takes_effect_at_the_next_round() {
        let w = World::boot(&["canonical-early"]).await;
        let conferral = w.bless("canonical-early").await;
        seed_grant(&w.backend, LOCAL, "canonical-early", &SHARE, no_extra()).await;
        seed_trace_attestation(&w.backend, LOCAL).await;
        let hash = locate_trace_hash(&w.bridge).await;
        assert_eq!(w.served("canonical-early", &hash).await, (true, true));
        // Attested ABOUT the subject: the walk reads a conferral's tombstones
        // from the subject's slice.
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": ROOT,
            "attested_key_id": "canonical-early",
            "attestation_type": "withdraws",
            "references_attestation_id": conferral,
            "withdrawal_reason": "test: the root withdraws its conferral",
        });
        seed_raw_attestation(
            &w.backend,
            &id,
            ROOT,
            "canonical-early",
            "withdraws",
            envelope,
        )
        .await;
        assert_eq!(w.served("canonical-early", &hash).await, (false, false));
    }
}
