//! **One boot entry point** (CIRISEdge#676, `FSD/MLS_STATE_AT_REST.md` §5;
//! CIRISServer#623): re-install every persisted room's derived addresses
//! from the sealed store and persist's roster fold, once, after the
//! transport and [`ScopeLifecycle`] are armed.
//!
//! A restarted holder used to listen on nothing until a local op revisited
//! each conversation; peers read "no holder" for every room it was in. The
//! host calls [`readdress_persisted_rooms`] once and logs the report.
//! Idempotent: the lifecycle's install is a superseding write.

use crate::cohort_scope::CohortScope;
use crate::contact::DirectoryLens;
use crate::mls::{CohortGroups, ScopeStateProvider};
use crate::scope_lifecycle::ScopeLifecycle;
use crate::scope_room::ScopeRoom;

/// One room whose addresses were (re-)installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRoom {
    /// The room, as classified.
    pub room: ScopeRoom,
    /// The MLS epoch the addresses were derived at.
    pub epoch: u64,
    /// How many member NODES the epoch's address set covers.
    pub members: usize,
}

/// What the boot re-address did, room by room. Nothing here is fatal: a
/// room this node has left, a room the host cannot classify, or a group
/// that will not export a secret is a `skipped` row by name, and the rest
/// are installed regardless.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReaddressReport {
    /// Rooms whose addresses are now installed.
    pub installed: Vec<InstalledRoom>,
    /// `(room id, reason)` for every room not installed.
    pub skipped: Vec<(String, String)>,
}

/// The classifier a host supplies when its room naming is not the default:
/// the sealed store knows a room's id, not its kind.
pub type RoomClassifier<'a> = &'a (dyn Fn(&str) -> Option<ScopeRoom> + Sync);

/// The naming edge itself uses: `chat:pair:v1:*` / `chat:room:v1:*` are
/// community rooms; `family:*` is a family; anything else is a self room
/// **iff** the lens resolves it to a `user` identity. Everything else is
/// unclassified and skipped by name.
async fn default_classify(id: &str, lens: &dyn DirectoryLens) -> Option<ScopeRoom> {
    if id.starts_with(crate::chat::PAIR_COMMUNITY_PREFIX)
        || id.starts_with(crate::chat::ROOM_COMMUNITY_PREFIX)
    {
        return Some(ScopeRoom::community(id));
    }
    if let Some(family) = id.strip_prefix("family:") {
        return Some(ScopeRoom::family(family));
    }
    match lens.identity_type_of(id).await.as_deref() {
        Some(ciris_persist::federation::identity_type::USER) => {
            Some(ScopeRoom::self_collective(id))
        }
        _ => None,
    }
}

/// **Re-install every persisted room's addresses** (FSD §5).
///
/// For each room id in the store's index: open the group (restores the
/// snapshot), classify it (`classify` first, then the default naming),
/// snapshot it — the self room from the MLS tree
/// ([`crate::self_room::snapshot`]), any other room through the lens so
/// members become their nodes
/// ([`crate::cohort_addressing::snapshot_for_nodes`]) — and
/// [`ScopeLifecycle::install`] it. The roster the addresses are installed
/// for is the directory's fold, never the tree alone; `decide` closes any
/// gap on the next tick.
pub async fn readdress_persisted_rooms(
    store: &ScopeStateProvider,
    groups: &CohortGroups,
    lifecycle: &ScopeLifecycle,
    lens: &dyn DirectoryLens,
    classify: Option<RoomClassifier<'_>>,
) -> ReaddressReport {
    let mut report = ReaddressReport::default();
    let ids = match store.persisted_room_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            report
                .skipped
                .push(("*".to_owned(), format!("room index unreadable: {e}")));
            return report;
        }
    };
    for id in ids {
        let room = match classify.and_then(|c| c(&id)) {
            Some(r) => Some(r),
            None => default_classify(&id, lens).await,
        };
        let Some(room) = room else {
            report
                .skipped
                .push((id, "unclassified room id (supply a classifier)".to_owned()));
            continue;
        };
        let group = match groups.open(&id).await {
            Ok(g) => g,
            Err(e) => {
                report
                    .skipped
                    .push((id, format!("group did not open: {e}")));
                continue;
            }
        };
        let snapshot = match &room {
            ScopeRoom::SelfCollective { identity_key_id } => {
                crate::self_room::snapshot(&group, identity_key_id).await
            }
            _ => crate::cohort_addressing::snapshot_for_nodes(&group, lens)
                .await
                .map(|r| r.snapshot),
        };
        let snapshot = match snapshot {
            Ok(s) => s,
            Err(e) => {
                report
                    .skipped
                    .push((id, format!("no address snapshot: {e}")));
                continue;
            }
        };
        let scope: CohortScope = room.scope();
        // `install` refuses a group the lifecycle already holds (by design:
        // a second install would drop live addresses); a room this process
        // already re-addressed — a second boot call, or a host that also
        // drove it — is reconciled with the lifecycle's own make-before-break
        // verb, `refresh_members`, at the same epoch. Idempotent by the
        // lifecycle's rules, not by swallowing its refusal.
        let outcome = match lifecycle.install(&scope, &snapshot) {
            Err(crate::scope_lifecycle::ScopeLifecycleError::Table(_)) => {
                lifecycle.refresh_members(&scope, &snapshot)
            }
            other => other,
        };
        match outcome {
            Ok(_) => report.installed.push(InstalledRoom {
                room,
                epoch: snapshot.epoch,
                members: snapshot.members.len(),
            }),
            Err(e) => report.skipped.push((id, format!("lifecycle refused: {e}"))),
        }
    }
    tracing::info!(
        installed = report.installed.len(),
        skipped = report.skipped.len(),
        "boot re-address: every persisted room's derived addresses re-installed (CIRISEdge#676)"
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::CohortGroup;
    use crate::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
    use crate::scope_lifecycle::ScopedDestinationSink;
    use std::sync::{Arc, Mutex};

    struct Sink(Mutex<Vec<CohortScope>>);
    impl ScopedDestinationSink for Sink {
        fn register(&self, _a: &MemberAddress, scope: &CohortScope) -> Result<(), String> {
            self.0.lock().unwrap().push(scope.clone());
            Ok(())
        }
        fn retire(&self, _a: &MemberAddress, _s: &CohortScope) -> Result<(), String> {
            Ok(())
        }
    }

    /// Every node is its own person; `person-p` owns `node-p`.
    struct Lens;
    #[async_trait::async_trait]
    impl DirectoryLens for Lens {
        async fn identity_type_of(&self, key_id: &str) -> Option<String> {
            if key_id.starts_with("person-") {
                Some(ciris_persist::federation::identity_type::USER.to_owned())
            } else if key_id.starts_with("node-") {
                Some(ciris_persist::federation::identity_type::NODE.to_owned())
            } else {
                None
            }
        }
        async fn owner_of(&self, key_id: &str) -> Option<String> {
            key_id.strip_prefix("node-").map(|p| format!("person-{p}"))
        }
        async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
            fed_id
                .strip_prefix("person-")
                .map(|p| vec![format!("node-{p}")])
                .unwrap_or_default()
        }
    }

    fn lifecycle(sink: Arc<Sink>, own: &str) -> ScopeLifecycle {
        let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
        ScopeLifecycle::new(
            table,
            sink as Arc<dyn ScopedDestinationSink>,
            own.to_owned(),
            std::time::Duration::from_secs(1),
        )
    }

    /// FSD §7 S1 + S6 — rooms of two kinds are persisted; a FRESH
    /// `CohortGroups` over the same store (the restart) re-addresses them
    /// into the lifecycle; the unclassifiable one is skipped by name; a
    /// second call is idempotent; a host classifier wins over the default.
    #[tokio::test]
    async fn a_restarted_node_readdresses_every_persisted_room() {
        let store = ScopeStateProvider::ephemeral();
        for room in ["person-a", "chat:pair:v1:deadbeef", "mystery-room"] {
            let g = CohortGroup::create(store.clone(), room, "node-a", 16)
                .await
                .unwrap();
            drop(g);
        }
        assert_eq!(store.persisted_room_ids().await.unwrap().len(), 3);

        let groups = CohortGroups::new(store.clone(), "node-a");
        let sink = Arc::new(Sink(Mutex::new(Vec::new())));
        let life = lifecycle(Arc::clone(&sink), "node-a");
        let report = readdress_persisted_rooms(&store, &groups, &life, &Lens, None).await;
        let installed: Vec<&str> = report
            .installed
            .iter()
            .map(|r| match &r.room {
                ScopeRoom::SelfCollective { identity_key_id } => identity_key_id.as_str(),
                ScopeRoom::Community { community_key_id } => community_key_id.as_str(),
                ScopeRoom::Family { family_key_id } => family_key_id.as_str(),
            })
            .collect();
        assert!(
            installed.contains(&"person-a"),
            "the self room is re-addressed: {report:?}"
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|(id, why)| id == "mystery-room" && why.contains("unclassified")),
            "the unclassifiable room is skipped BY NAME: {report:?}"
        );
        assert!(
            !sink.0.lock().unwrap().is_empty(),
            "addresses were registered on the sink"
        );

        let again = readdress_persisted_rooms(&store, &groups, &life, &Lens, None).await;
        assert_eq!(again.installed.len(), report.installed.len(), "idempotent");

        let classify = |id: &str| (id == "mystery-room").then(|| ScopeRoom::community(id));
        let classified =
            readdress_persisted_rooms(&store, &groups, &life, &Lens, Some(&classify)).await;
        assert!(
            !classified
                .skipped
                .iter()
                .any(|(id, why)| id == "mystery-room" && why.contains("unclassified")),
            "the host's naming classified it: {classified:?}"
        );
    }
}
