//! CIRISEdge#988 — the blackhole rules and the edge-detection writer over
//! persist's directory-ops proxy, holding the capsules the proxy points into.
//!
//! In a two-wheel process every store call must run inside persist's library:
//! edge's own compiled copy of persist's store code takes the store's
//! `parking_lot` locks through edge's waiter queue, and a waiter one binary
//! parks is never woken by the other's unlock. Persist 61.4.0
//! (CIRISPersist#1227 / #1244) routes `BlackholeRules` and
//! `DerivedSchema::put_edge_detection_event` through `DirectoryOp`s on its
//! `OpsDirectory`; these wrappers keep that proxy's capsule and executor alive
//! for as long as edge holds the view, exactly as `KeptDirectory` does for
//! the directory.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use ciris_persist::federation::{BlackholeRecord, BlackholeRules, Error};
use ciris_persist::ffi::directory_capsule::OpsDirectory;

/// Persist's ops proxy plus the capsules its copies point into.
pub(crate) struct KeptOpsViews {
    inner: Arc<OpsDirectory>,
    _executor: Arc<crate::ffi::pyo3::KeptExecutor>,
    _capsule: pyo3::Py<pyo3::PyAny>,
}

impl KeptOpsViews {
    pub(crate) fn new(
        inner: Arc<OpsDirectory>,
        executor: Arc<crate::ffi::pyo3::KeptExecutor>,
        capsule: pyo3::Py<pyo3::PyAny>,
    ) -> Self {
        Self {
            inner,
            _executor: executor,
            _capsule: capsule,
        }
    }
}

#[async_trait::async_trait]
impl BlackholeRules for KeptOpsViews {
    async fn blackhole_list(&self) -> Result<Vec<BlackholeRecord>, Error> {
        self.inner.blackhole_list().await
    }

    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<DateTime<Utc>>,
        reason: Option<&str>,
    ) -> Result<(), Error> {
        self.inner
            .blackhole_upsert(identity_hash, until, reason)
            .await
    }

    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), Error> {
        self.inner.blackhole_remove(identity_hash).await
    }

    async fn blackhole_record_hit(&self, identity_hash: &[u8]) -> Result<(), Error> {
        self.inner.blackhole_record_hit(identity_hash).await
    }

    async fn blackhole_prune_expired(&self, now: DateTime<Utc>) -> Result<u64, Error> {
        self.inner.blackhole_prune_expired(now).await
    }
}

#[async_trait::async_trait]
impl crate::detector::EdgeDetectionAdmission for KeptOpsViews {
    async fn put_edge_detection_event(
        &self,
        event: ciris_persist::derived::types::EdgeDetectionEvent,
    ) -> Result<(), ciris_persist::derived::Error> {
        <OpsDirectory as ciris_persist::derived::DerivedSchema>::put_edge_detection_event(
            &self.inner,
            event,
        )
        .await
    }
}
