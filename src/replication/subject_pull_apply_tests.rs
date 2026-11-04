//! The requester's half of a subject Pull, on two real nodes.
//!
//! CIRISServer's contact harness, run ce7: the canonical served dan's binding at
//! 16:55:18.5 and alice applied it at 16:56:03.5. A listing witness cannot see
//! those 45 s, so this one asserts the row in the requester's directory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;

use super::key_plane_v59_tests::NodeA;
use super::park_fresh_858_tests::{hold, substrate, Ident};
use super::protocol::EnvelopeKind;
use super::registry::ReplicationRegistry;
use super::{
    self_publish_set, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig,
    SchedulerConfig,
};
use crate::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

type Registries = Arc<std::sync::Mutex<HashMap<String, Arc<ReplicationRegistry>>>>;

struct Loopback {
    me: String,
    registries: Registries,
}

#[async_trait::async_trait]
impl Transport for Loopback {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        let dest = self
            .registries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(destination_key_id)
            .cloned();
        let Some(dest) = dest else {
            return Err(TransportError::Io(format!("no node {destination_key_id}")));
        };
        let (me, bytes) = (self.me.clone(), envelope_bytes.to_vec());
        tokio::spawn(async move {
            let _ = dest.route_inbound_bytes(&me, &bytes).await;
        });
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        Ok(())
    }
}

async fn start(
    dir: &Arc<SqliteBackend>,
    me: &str,
    peer: &str,
    publish: Vec<String>,
    registries: &Registries,
) -> ReplicationRuntime {
    let me = me.to_owned();
    let rt = ReplicationRuntime::start(
        Arc::clone(dir) as Arc<dyn FederationDirectory>,
        Arc::new(Loopback {
            me: me.clone(),
            registries: Arc::clone(registries),
        }) as Arc<dyn Transport>,
        // Every Pull plane already has its coordinator, as a running node's do:
        // a coordinator's FIRST tick fires at spawn, so one registered by the
        // Pull itself would read the reply by luck and hide the wait.
        EnvelopeKind::subject_pullable()
            .into_iter()
            .map(|kind| ReplicationPeer {
                peer_key_id: peer.to_owned(),
                kind,
            })
            .collect(),
        ReplicationRuntimeConfig {
            scheduler: SchedulerConfig {
                // The cadence is the wait under test: an hour, so a row that
                // needs a tick to apply cannot make the bound.
                cadence: Duration::from_secs(3600),
                round_timeout: Duration::from_secs(5),
                ..SchedulerConfig::default()
            },
            local_key_id: Some(me.clone()),
            ..ReplicationRuntimeConfig::default()
        },
        Some(self_publish_set(publish)),
    )
    .await;
    registries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(me, rt.registry());
    rt
}

async fn holds_key(dir: &Arc<SqliteBackend>, key_id: &str) -> bool {
    matches!(
        FederationDirectory::lookup_public_key(&**dir, key_id).await,
        Ok(Some(_))
    )
}

/// The served rows are fetched and APPLIED in the Pull's own exchange: the
/// requester holds the row within 2 s with the next tick an hour away. Fails on
/// the wait this replaces (the reply parked until a driven round read it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pulled_row_is_applied_within_two_seconds_not_on_the_tick() {
    let holder = NodeA::build("pull-apply", 0x61).await;
    let n = holder.n.key_id().to_owned();
    let asker = Ident::mint("node-alice-pull-apply", "node", 0x71).await;
    let asker_dir = substrate().await;
    hold(&asker_dir, &asker).await;
    let a = asker.key_id().to_owned();

    let registries: Registries = Arc::new(std::sync::Mutex::new(HashMap::new()));
    // The holder publishes nothing, so anti-entropy cannot bring its own Key:
    // only the Pull can.
    let mut rt_holder = start(&holder.dir, &n, &a, Vec::new(), &registries).await;
    let mut rt_asker = start(&asker_dir, &a, &n, vec![a.clone()], &registries).await;
    // Let the start-up fan-out finish: past this, nothing is driving a round.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !holds_key(&asker_dir, &n).await,
        "precondition: the row did not arrive by anti-entropy"
    );

    let asked_at = Instant::now();
    rt_asker
        .pull_subject_testimony(&n, &n)
        .await
        .expect("the Pull leaves");
    let bound = Duration::from_secs(2);
    while !holds_key(&asker_dir, &n).await {
        assert!(
            asked_at.elapsed() < bound,
            "the holder's Key was not APPLIED within {bound:?} of the Pull: its reply \
             is waiting on something other than its own frames"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    rt_asker.shutdown().await;
    rt_holder.shutdown().await;
}
