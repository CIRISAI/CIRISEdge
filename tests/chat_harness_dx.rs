//! Compile-pin for `docs/CHAT_HARNESS_INTEGRATION.md`.
//!
//! The integration guide handed to CIRISServer (CIRISServer#524) names a
//! specific public surface and tells them to build a chat harness on it. A
//! document is the one artifact that cannot fail its own CI, so this test
//! references every symbol the guide names.
//!
//! It asserts almost nothing at runtime, and that is the point: the value is
//! entirely in COMPILING. If someone renames `LadderStall::BodyFetchQueued`,
//! changes `discover`'s arity, or makes `Ts` private again, this file stops
//! building and the guide is known-stale in the same commit — instead of a
//! downstream team discovering it against a version we already shipped.
//!
//! Add a symbol here whenever the guide starts naming it.

use ciris_edge::contact::{Discovered, IdentityKind, LadderStall, PersistLens, Rung, Subject};
use ciris_edge::invite_gate::{InviteGate, InviteVerdict, RefuseReason, Ts};
use ciris_edge::replication::ReplicationRuntimeConfig;
use ciris_edge::AgentMode;

/// §0 — the ONE field a Rust composer must set itself: `local_key_id`. The
/// serve-tier resolver, the own-record Pull arm, and missing-signer recovery
/// are all keyed on it, and a default-constructed config leaves it `None` —
/// silently inert, not broken.
///
/// `AgentMode` is deliberately NOT here any more: `BridgeConfig` has no mode
/// field. The directory role (retention, identifier lookups) keys on the
/// node's own `infra:serve` conferral, resolved from the directory
/// (ROLE_MATRIX axis 3) — conferred by the owner, blessed by the trust root
/// for canonicals. Mode stays what it always was: listener + queue posture on
/// the Edge itself.
#[test]
fn the_wiring_the_guide_says_is_mandatory_exists() {
    let config = ReplicationRuntimeConfig {
        local_key_id: Some("node-abc123".to_string()),
        ..Default::default()
    };
    assert!(
        config.local_key_id.is_some(),
        "§0 tells the server to set local_key_id; without it the serve-tier \
         resolver cannot run and the Pull responder cannot recognise its own \
         record"
    );

    // AgentMode still exists — on the Edge, for listener/queue. Its absence
    // from BridgeConfig is the point: the v18.12.1 mis-key is unrepresentable.
    assert!(matches!(AgentMode::default(), AgentMode::Proxy));
}

/// §6 — the stranger-contact surface the guide's code block calls, and the
/// shape of its success case.
///
/// Pinned because the guide tells the server to use `subject` DIRECTLY after
/// admission rather than re-resolving. An earlier revision returned
/// "admit, then retry", and that retry could never succeed: it runs
/// `nodes_owned_by` against the directory, where a stranger has no
/// owner-binding attestations. If this ever compiles back to a retry shape,
/// the guide is teaching a loop that never terminates.
#[test]
fn the_stranger_contact_surface_matches_the_guide() {
    use base64::Engine as _;
    use ciris_edge::contact::LadderStall;

    // A code minted the way a sender's node would.
    let mut pubkey = [0u8; 32];
    pubkey[0] = 77;
    let key_id = ciris_verify_core::fedcode::derive_key_id("stranger", &pubkey);
    let code = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
        kind: ciris_verify_core::fedcode::FedKind::User,
        key_id: key_id.clone(),
        pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(pubkey),
        transport_hint: Some("https://example.invalid".into()),
        alias_hint: None,
        group_key_id: None,
        owned_nodes: Vec::new(),
    })
    .expect("encode");

    // §6: classification never demotes a code to an identifier.
    let candidate = ciris_edge::contact::parse_contact_input(&code).expect("decodes");
    let admission = candidate
        .admission
        .expect("a code carries the key to admit");
    assert_eq!(admission.key_id, key_id);
    assert_eq!(admission.identity_type, "user");
    assert!(
        admission.transport_hint.is_some(),
        "v2 carries the transport hint"
    );

    // §6: a forged code is refused, and the guide says do not admit it.
    let forged = ciris_verify_core::fedcode::encode(&ciris_verify_core::fedcode::FedCode {
        kind: ciris_verify_core::fedcode::FedKind::User,
        key_id,
        pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode([0xAA_u8; 32]),
        transport_hint: None,
        alias_hint: None,
        group_key_id: None,
        owned_nodes: Vec::new(),
    })
    .expect("a forgery encodes fine — the CRC cannot see authorship");
    assert!(
        matches!(
            ciris_edge::contact::parse_contact_input(&forged),
            Err(LadderStall::CodeIdentityMismatch { .. })
        ),
        "§6 tells the server to refuse this without admitting"
    );

    // §6: the success variant the guide destructures is pinned by
    // `the_ready_from_code_shape` at module scope.
}

/// §6 — the success variant the guide's code block destructures.
///
/// Compile-only: building one needs a lens, but the SHAPE is what the guide
/// depends on. `ReadyFromCode` carrying a USABLE `Subject` is the whole fix —
/// an earlier "admit, then retry" shape could never terminate, because the
/// retry ran `nodes_owned_by` against a directory where a stranger has no
/// owner-binding attestations.
#[allow(dead_code)]
fn the_ready_from_code_shape(r: ciris_edge::contact::ContactResolution) {
    use ciris_edge::contact::ContactResolution;
    match r {
        ContactResolution::Known(subject) => {
            let _: String = subject.fed_id;
        }
        ContactResolution::ReadyFromCode { subject, admission } => {
            // Usable immediately: nodes to dial, no directory round-trip.
            let _: Vec<String> = subject.nodes;
            let _: String = admission.key_id;
        }
    }
}

/// §1 — the rung vocabulary, and `previous()` for pointing at the right place.
#[test]
fn the_rung_ladder_is_the_documented_shape() {
    let documented = [
        (Rung::Announce, "announce", None),
        (Rung::Discover, "discover", Some(Rung::Announce)),
        (
            Rung::RequestContact,
            "request_contact",
            Some(Rung::Discover),
        ),
        (Rung::Consent, "consent", Some(Rung::RequestContact)),
        (Rung::OpenChat, "open_chat", Some(Rung::Consent)),
        (Rung::SendMessage, "send_message", Some(Rung::OpenChat)),
    ];
    for (rung, wire, prior) in documented {
        assert_eq!(rung.as_str(), wire, "§1 prints these strings in a table");
        assert_eq!(rung.previous(), prior, "§1 documents the ladder order");
    }
}

/// §3 — the stall table. Every variant the guide lists, with the
/// `self_resolving()` value it tells the harness to branch on, and a
/// non-empty `remedy()` the guide says to surface verbatim.
#[test]
fn every_documented_stall_has_the_documented_disposition() {
    let fed = || "frank-abc123".to_string();
    let documented: Vec<(LadderStall, bool)> = vec![
        (LadderStall::NotYetDiscovered { fed_id: fed() }, true),
        (LadderStall::Unreachable { fed_id: fed() }, true),
        (LadderStall::BodyFetchQueued { key_id: fed() }, true),
        (LadderStall::AwaitingConsent { fed_id: fed() }, false),
        (LadderStall::ConsentNotGranted { fed_id: fed() }, false),
        (LadderStall::DirectoryUnreadable { key_id: fed() }, false),
        (
            LadderStall::NotContactable {
                key_id: fed(),
                identity_type: "steward".to_string(),
            },
            false,
        ),
        (
            LadderStall::PriorRungIncomplete {
                rung: Rung::Consent,
                prior: Rung::RequestContact,
            },
            false,
        ),
    ];
    for (stall, self_resolving) in documented {
        assert_eq!(
            stall.self_resolving(),
            self_resolving,
            "§3's table says self_resolving={self_resolving} for {stall:?}; the \
             harness branches retry-vs-surface on exactly this"
        );
        assert!(
            !stall.remedy().is_empty(),
            "§3 tells the server to show remedy() verbatim, so every variant \
             must have one: {stall:?}"
        );
    }
}

/// §4 — the invite gate's placement and promotion contract.
#[test]
fn the_invite_gate_behaves_as_the_guide_describes() {
    let now: Ts = 1_000_000;
    let mut gate = InviteGate::new();

    assert!(
        matches!(gate.admit("stranger", now), InviteVerdict::Allow),
        "§4: a stranger's first invite reaches the person"
    );
    assert!(
        matches!(
            gate.admit("stranger", now),
            InviteVerdict::Refuse {
                reason: RefuseReason::AlreadyPending | RefuseReason::BudgetSpent
            }
        ),
        "§4: STRANGER_BUDGET is 1"
    );

    // The line the guide warns about forgetting.
    gate.mark_accepted("stranger");
    assert!(
        matches!(gate.admit("stranger", now), InviteVerdict::Allow),
        "§4: mark_accepted promotes permanently — forgetting it leaves every \
         established contact on the 1-invite stranger budget"
    );

    assert_eq!(InviteGate::STRANGER_BUDGET, 1, "§4 quotes this");
    assert_eq!(InviteGate::CONTACT_BUDGET, 8, "§4 quotes this");
    assert_eq!(InviteGate::REFILL_SECS, 86_400, "§4 quotes this");
}

/// Consume a value at a stated type. The call is what makes each line a real
/// use rather than a no-effect binding, and the turbofish is the assertion.
#[allow(dead_code)]
fn pin<T>(_: T) {}

/// §2/§5 — the resolution entry points and result types the harness
/// destructures, plus the logging call.
///
/// Compile-only: exercising these needs a live directory, but their SHAPES are
/// what the guide's code blocks depend on.
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    clippy::diverging_sub_expression
)]
async fn the_documented_call_shapes_typecheck() {
    let lens: PersistLens<'_> = unreachable!();

    // §2: `resolve` — identifier in, Subject out.
    pin::<Result<Subject, LadderStall>>(ciris_edge::contact::resolve(&lens, "frank-abc123").await);

    // §2: `discover` — identifier + routes in, Discovered out.
    let routes: &dyn ciris_edge::contact::RouteLens = unreachable!();
    let found: Result<Discovered, LadderStall> =
        ciris_edge::contact::discover(&lens, routes, "frank-abc123").await;

    // The fields §2 tells the harness to read. `pin` consumes each one, so the
    // reference is a real use and the TYPE is what is being asserted.
    let found: Discovered = found.unwrap();
    pin::<&Subject>(&found.subject);
    pin::<&String>(&found.subject.fed_id);
    pin::<&Vec<String>>(&found.subject.nodes);
    pin::<&Vec<String>>(&found.reachable);
    pin::<&IdentityKind>(&found.subject.resolved_from);

    // §5's one-shape-per-rung logger.
    ciris_edge::contact::log_rung(Rung::Discover, "frank-abc123", None);
}

/// §2 — `ReticulumRoutes` is the production `RouteLens`, and it is behind the
/// `transport-reticulum` feature. The guide says so; this pins that it is true,
/// because a downstream build that omits the feature gets a confusing
/// "no `ReticulumRoutes` in `contact`" rather than a missing-feature message.
#[cfg(feature = "transport-reticulum")]
#[allow(
    dead_code,
    unreachable_code,
    unused_variables,
    clippy::diverging_sub_expression
)]
fn the_production_route_lens_exists_under_its_feature() {
    let routes: ciris_edge::contact::ReticulumRoutes<'_> = unreachable!();
    pin::<&dyn ciris_edge::contact::RouteLens>(&routes);
}
