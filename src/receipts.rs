//! **Delivery receipts for files** — CC 5.3.3.6 `delivery_receipt:{stream_id}`
//! (CIRISEdge#738, lane 4 of #734; `FSD/CONTENT_TRANSFER.md` §6.10).
//!
//! Every file is a stream (a chunked file's `stream_id`, an inline file's
//! one-leaf log — below), so a file receipt is CC 5.3.3.6's object at the
//! file's stream with `K` = the stream's `tree_size` (its chunk count, 1 for
//! an inline file): the receiving NODE's signed statement that it
//! holds bytes committing to every chunk under the named root. Proof of
//! DELIVERY, never of consumption; "delivered" is the caller's verdict.
//!
//! # The four places a receipt is touched, one function each
//!
//! 1. **Publish** — [`stream_sth_for_file`] builds the producer-signed STH
//!    through persist's one producer (`stream_sth::produce_stream_sth`, the
//!    root `put_stream_sth`'s anti-equivocation gate recomputes, signed by
//!    the node's hybrid signer); `files::publish` puts it through persist's
//!    `put_stream_sth` and carries it on the file row as [`FIELD_STREAM_STH`],
//!    so it travels with the row at the row's audience and a receiver holds
//!    the claim the moment it holds the row.
//! 2. **Receive** — [`on_file_pulled`], called once from the DAG pull after
//!    `promote` and once from the whole-blob pull after an inline file is
//!    stored: the receiver puts the row's STH into its OWN store, where
//!    persist recomputes the root from the bytes this node just adopted — so
//!    the root it signs is one its own bytes reproduce — then signs the receipt
//!    as the node, stores it, and emits it as a `scores` row on
//!    `delivery_receipt:{stream_id}:v1` at the file's own cohort (self → the
//!    owner's devices, family → the family, community → the room). Never at
//!    federation scope, and never twice for one `(stream, epoch, receiver)`.
//! 3. **Admit** — [`admit_receipt_row`], on the author's node when the receipt
//!    row arrives: every refusal has a name ([`ReceiptRefusal::tag`]), counted
//!    under `delivery_receipts`, then persist's `put_delivery_receipt` (the
//!    signature over the pinned key and the JOIN against a published root).
//! 4. **Read** — `FileRow::received_by` over
//!    `list_stored_delivery_receipts_for` (with the instant the author's store
//!    took each receipt), and the [`ReceiptLedger`] the replication bridge
//!    consults so a row a peer has receipted in full is not re-offered to that
//!    peer.
//!
//! # Every file is a stream
//!
//! A chunked file's stream is its `stream_id`, its leaves the chunk addresses
//! in `seq` order. An inline file (≤ 1 MiB) is one blob with no stream rows;
//! its log is persist's `stream_sth::inline_blob_stream_id(&sha)` (the at-rest
//! address as 64 lowercase hex, CIRISPersist#953) with ONE leaf, the blob's
//! own address, `tree_size` 1. [`receipt_stream_id`] is the one place a
//! file's stream is named.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use base64::Engine as _;
use ciris_persist::federation::stream_receipt::StoredDeliveryReceipt;
use ciris_persist::federation::stream_receipt::{receipt_signing_bytes, DeliveryReceipt};
use ciris_persist::federation::stream_sth::{inline_blob_of_stream_id, inline_blob_stream_id};
use ciris_persist::federation::{Attestation, BlobError, BlobStorage, FederationDirectory};
use ciris_verify_core::transparency::SignedTreeHead;

use crate::files::{FileRow, FILE_DIMENSION};
use crate::group_content::BlobPointer;

/// The reserved family's stem (CC 3.4.6, registered to Edge).
pub const RECEIPT_DIMENSION_PREFIX: &str = "delivery_receipt:";

/// The version segment the namespace grammar requires on the family.
pub const RECEIPT_DIMENSION_VERSION: &str = "v1";

/// The envelope member carrying the receipt on a receipt row.
pub const FIELD_RECEIPT: &str = "receipt";

/// The envelope member naming the file row the receiver pulled.
pub const FIELD_FILE_ATTESTATION_ID: &str = "file_attestation_id";

/// The envelope member carrying the stream's producer-signed STH on a file row.
pub const FIELD_STREAM_STH: &str = "stream_sth";

/// The persist epoch label a one-shot file is written under; the receipt's
/// epoch for a `self`/`family` file (whose pointer carries none).
pub const FILE_STREAM_EPOCH: u64 = 0;

/// `delivery_receipts` tag: the chunk_root names no STH this node published.
pub const RECEIPT_ROOT_UNPUBLISHED: &str = "receipt_root_unpublished";
/// `delivery_receipts` tag: the published tree is shorter than `K`.
pub const RECEIPT_TREE_SIZE_SHORT: &str = "receipt_tree_size_short";
/// `delivery_receipts` tag: the receipt's epoch is not the file's.
pub const RECEIPT_EPOCH_MISMATCH: &str = "receipt_epoch_mismatch";
/// `delivery_receipts` tag: the signer's principal is not in the file's room.
pub const RECEIPT_SIGNER_NOT_MEMBER: &str = "receipt_signer_not_member";
/// `delivery_receipts` tag: this receiver already receipted this stream + epoch.
pub const RECEIPT_DUPLICATE: &str = "receipt_duplicate";
/// `delivery_receipts` tag: the row is not a well-formed receipt row.
pub const RECEIPT_MALFORMED: &str = "receipt_malformed";
/// `delivery_receipts` tag: the file row the receipt names is not held here.
pub const RECEIPT_FILE_UNKNOWN: &str = "receipt_file_unknown";
/// `delivery_receipts` tag: persist refused for a reason not named above.
pub const RECEIPT_SUBSTRATE: &str = "receipt_substrate";
/// `delivery_receipts` tag: a receipt this node emitted for bytes it pulled.
pub const RECEIPT_EMITTED: &str = "emitted";
/// `delivery_receipts` tag: a receipt admitted on the author's node.
pub const RECEIPT_ADMITTED: &str = "admitted";
/// `delivery_receipts` tag: pulled, but the row carries no STH to receipt.
pub const RECEIPT_NOT_EMITTED_NO_STH: &str = "not_emitted_no_sth";
/// `delivery_receipts` tag: pulled, but the row's STH does not verify here
/// (persist's gate: the claimed root is not what this node's chunks
/// reproduce, or the producer signature fails).
pub const RECEIPT_NOT_EMITTED_STH_REFUSED: &str = "not_emitted_sth_refused";
/// `delivery_receipts` tag: pulled, but signing, storing or emitting failed.
pub const RECEIPT_NOT_EMITTED_FAILED: &str = "not_emitted_failed";
/// `delivery_receipts` tag: a row the peer has receipted in full was not
/// re-offered to that peer.
pub const RE_OFFER_SUPPRESSED_RECEIPTED: &str = "re_offer_suppressed_receipted";

/// The receipts one stream's reads look at. A file has one per receiving node;
/// this bounds a hostile stream, not a real one.
const RECEIPT_LIST_LIMIT: i64 = 4096;

/// The streams the ledger hydrates from the store per process. Past it the
/// bridge simply re-offers (cost, never correctness).
const LEDGER_STREAM_CAP: usize = 65_536;

/// The dimension a receipt row for `stream_id` carries.
#[must_use]
pub fn receipt_dimension(stream_id: &str) -> String {
    format!("{RECEIPT_DIMENSION_PREFIX}{stream_id}:{RECEIPT_DIMENSION_VERSION}")
}

/// The `stream_id` a receipt row's dimension names, or `None` for any other.
#[must_use]
pub fn stream_of_receipt_dimension(dimension: &str) -> Option<&str> {
    dimension
        .strip_prefix(RECEIPT_DIMENSION_PREFIX)?
        .strip_suffix(RECEIPT_DIMENSION_VERSION)?
        .strip_suffix(':')
        .filter(|s| !s.is_empty())
}

/// The receipt row's `stream_id`, when `row` is one.
#[must_use]
pub fn receipt_row_stream(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .and_then(stream_of_receipt_dimension)
}

/// **The stream a file's receipts name** — the one place it is spelled. A
/// chunk DAG's is its `stream_id`; an inline file's is persist's
/// [`inline_blob_stream_id`] over its at-rest address (CIRISPersist#953).
/// `None` only for a pointer whose address is not 32 bytes of hex.
#[must_use]
pub fn receipt_stream_id(pointer: &BlobPointer) -> Option<String> {
    if let Some(stream_id) = &pointer.stream_id {
        return Some(stream_id.clone());
    }
    inline_address(pointer).map(|sha| inline_blob_stream_id(&sha))
}

/// An inline pointer's at-rest address, decoded.
fn inline_address(pointer: &BlobPointer) -> Option<[u8; 32]> {
    hex::decode(&pointer.content_sha256)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

/// The stream a FILE row's receipts name — the cheap read the advertise loop
/// uses (no full `FileRow` parse). A chunked row's `stream_id`; an inline
/// row's address, which is its log's name exactly when it is spelled the way
/// [`inline_blob_stream_id`] spells it (64 lowercase hex, as every edge
/// pointer is written) — so this agrees with [`receipt_stream_id`].
#[must_use]
pub fn file_row_stream(row: &Attestation) -> Option<&str> {
    let env = &row.attestation_envelope;
    if env.get("dimension").and_then(serde_json::Value::as_str) != Some(FILE_DIMENSION) {
        return None;
    }
    let content = env.get(crate::chat::FIELD_CONTENT)?;
    if let Some(stream_id) = content.get("stream_id").and_then(serde_json::Value::as_str) {
        return Some(stream_id);
    }
    content
        .get("content_sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|sha| inline_blob_of_stream_id(sha).is_some())
}

// ─── The stream log: persist's six doors, object-safe ────────────────

/// persist's per-stream transparency-log and receipt doors, as an object-safe
/// trait so a `dyn` store, the puller's concrete backend and the bridge's
/// engine all reach the same six calls. Implemented for every
/// [`BlobStorage`]; no edge-side storage.
#[async_trait::async_trait]
pub trait StreamLog: Send + Sync {
    /// The stream's chunk addresses in `seq` order — the leaves.
    async fn stream_chunk_shas(&self, stream_id: &str) -> Result<Vec<[u8; 32]>, BlobError>;
    /// persist's anti-equivocation gate, then insert.
    async fn put_stream_sth(
        &self,
        sth: SignedTreeHead,
        producer_key_id: &str,
    ) -> Result<(), BlobError>;
    /// The highest-`tree_size` STH stored for the stream.
    async fn latest_stream_sth(&self, stream_id: &str)
        -> Result<Option<SignedTreeHead>, BlobError>;
    /// persist's signature check + JOIN, then insert.
    async fn put_delivery_receipt(&self, receipt: DeliveryReceipt) -> Result<(), BlobError>;
    /// The stored receipts for the stream.
    async fn list_delivery_receipts_for(
        &self,
        stream_id: &str,
        limit: i64,
    ) -> Result<Vec<DeliveryReceipt>, BlobError>;
    /// The stored receipts for the stream, each with the instant this store
    /// took it (CIRISPersist#953).
    async fn list_stored_delivery_receipts_for(
        &self,
        stream_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredDeliveryReceipt>, BlobError>;
}

#[async_trait::async_trait]
impl<T> StreamLog for T
where
    T: BlobStorage + Send + Sync + 'static,
{
    async fn stream_chunk_shas(&self, stream_id: &str) -> Result<Vec<[u8; 32]>, BlobError> {
        Ok(BlobStorage::stream_chunks(self, stream_id)
            .await?
            .chunks
            .into_iter()
            .map(|c| c.chunk_sha)
            .collect())
    }

    async fn put_stream_sth(
        &self,
        sth: SignedTreeHead,
        producer_key_id: &str,
    ) -> Result<(), BlobError> {
        BlobStorage::put_stream_sth(self, sth, producer_key_id).await
    }

    async fn latest_stream_sth(
        &self,
        stream_id: &str,
    ) -> Result<Option<SignedTreeHead>, BlobError> {
        BlobStorage::latest_stream_sth(self, stream_id).await
    }

    async fn put_delivery_receipt(&self, receipt: DeliveryReceipt) -> Result<(), BlobError> {
        BlobStorage::put_delivery_receipt(self, receipt).await
    }

    async fn list_delivery_receipts_for(
        &self,
        stream_id: &str,
        limit: i64,
    ) -> Result<Vec<DeliveryReceipt>, BlobError> {
        BlobStorage::list_delivery_receipts_for(self, stream_id, limit).await
    }

    async fn list_stored_delivery_receipts_for(
        &self,
        stream_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredDeliveryReceipt>, BlobError> {
        BlobStorage::list_stored_delivery_receipts_for(self, stream_id, limit).await
    }
}

/// The stream log an [`Engine`](ciris_persist::Engine) is built over, or
/// `None` for a backend edge has not wired (receipts then simply do not
/// exist on that node, and every caller says so).
#[must_use]
#[allow(unreachable_patterns)] // the wildcard is live only when persist builds without `postgres`
pub fn stream_log_of(engine: &ciris_persist::Engine) -> Option<std::sync::Arc<dyn StreamLog>> {
    match engine.backend() {
        ciris_persist::BackendDispatch::Sqlite(b) => Some(b.clone()),
        #[cfg(feature = "pyo3")]
        ciris_persist::BackendDispatch::Postgres(b) => Some(b.clone()),
        _ => None,
    }
}

// ─── Publish: the stream's STH ─────────────────────────────────────────

/// **The stream's producer-signed STH — the one place edge builds it**
/// (CIRISEdge#738, CC 5.3.3.3).
///
/// One call to persist's producer,
/// `federation::stream_sth::produce_stream_sth(local, stream_id,
/// chunk_shas_in_seq_order, tree_size, timestamp)` (CIRISPersist#950): the
/// RFC 6962 root over the first `tree_size` leaves, `log_id =
/// stream:<stream_id>`, [`SignedTreeHead::signing_bytes`], and the full
/// hybrid under `signer` — exactly the root `put_stream_sth`'s
/// anti-equivocation gate recomputes. No byte here is spelled by edge. For an
/// inline file the call is `(inline_blob_stream_id(&sha), &[sha], 1)`
/// ([`file_leaves`]).
///
/// # Errors
/// `tree_size` is 0 or exceeds the leaves given, or the signer has no PQC
/// half (the federation tier is PQC-mandatory, CC 5.3.2.4.3) or fails.
pub async fn stream_sth_for_file(
    signer: &crate::identity::LocalSigner,
    stream_id: &str,
    chunk_shas_in_seq_order: &[[u8; 32]],
    tree_size: u64,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<SignedTreeHead, String> {
    if signer.pqc.is_none() {
        return Err(format!(
            "stream {stream_id}: signer {} has no ML-DSA-65 half — a stream STH is the full \
             hybrid or nothing (CC 5.3.2.4.3)",
            signer.key_id
        ));
    }
    let local = ciris_persist::signing::LocalSigner::from_hardware_parts(
        signer.classical.clone(),
        signer.key_id.clone(),
        signer.pqc.clone(),
        Some(signer.key_id.clone()),
    )
    .await
    .map_err(|e| format!("stream {stream_id}: signer {}: {e}", signer.key_id))?;
    ciris_persist::federation::stream_sth::produce_stream_sth(
        &local,
        stream_id,
        chunk_shas_in_seq_order,
        tree_size,
        timestamp,
    )
    .await
    .map_err(|e| format!("stream {stream_id}: {e}"))
}

/// **A file's stream and its leaves in `seq` order**, read from the store
/// that sealed it: a chunk DAG's chunk addresses, or an inline file's one
/// leaf — its own at-rest address, under [`inline_blob_stream_id`].
///
/// # Errors
/// The pointer names no readable address, the chunk read failed, or the
/// stream holds no chunks.
pub async fn file_leaves(
    log: &dyn StreamLog,
    pointer: &BlobPointer,
) -> Result<(String, Vec<[u8; 32]>), String> {
    if let Some(stream_id) = &pointer.stream_id {
        let shas = log
            .stream_chunk_shas(stream_id)
            .await
            .map_err(|e| format!("stream {stream_id}: chunks: {e}"))?;
        if shas.is_empty() {
            return Err(format!("stream {stream_id}: no chunks to commit to"));
        }
        return Ok((stream_id.clone(), shas));
    }
    let sha = inline_address(pointer).ok_or_else(|| {
        format!(
            "inline file: address {:?} is not 32 bytes of hex",
            pointer.content_sha256
        )
    })?;
    Ok((inline_blob_stream_id(&sha), vec![sha]))
}

/// **Publish a file's STH** — the file's stream and leaves
/// ([`file_leaves`]), the STH over all of them ([`stream_sth_for_file`]),
/// through persist's gate. Returns the claim the file row carries.
///
/// # Errors
/// The leaf read, the STH build, or persist's gate refused.
pub async fn publish_file_sth(
    log: &dyn StreamLog,
    signer: &crate::identity::LocalSigner,
    pointer: &BlobPointer,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<StreamSthClaim, String> {
    let (stream_id, shas) = file_leaves(log, pointer).await?;
    let sth = stream_sth_for_file(signer, &stream_id, &shas, shas.len() as u64, timestamp).await?;
    log.put_stream_sth(sth.clone(), &signer.key_id)
        .await
        .map_err(|e| format!("stream {stream_id}: put_stream_sth: {e}"))?;
    Ok(StreamSthClaim::of(&stream_id, &sth, &signer.key_id))
}

/// **The STH as the file row carries it.** Compact: the signature's two
/// halves travel as base64 and the public keys are NOT carried — every
/// verifier resolves them from its own directory by `producer_key_id`
/// (persist's discipline: the pinned key, never one embedded in the
/// signature).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamSthClaim {
    /// The stream.
    pub stream_id: String,
    /// Chunks committed to.
    pub tree_size: u64,
    /// Hex RFC 6962 root.
    pub root_hash: String,
    /// When the producer signed it (RFC 3339, nanosecond precision — it is
    /// inside the signed bytes).
    pub timestamp: String,
    /// The producing node's key.
    pub producer_key_id: String,
    /// Base64 Ed25519 half.
    pub sig_ed25519: String,
    /// Base64 ML-DSA-65 half.
    pub sig_ml_dsa_65: String,
}

impl StreamSthClaim {
    /// The claim for `sth`.
    #[must_use]
    pub fn of(stream_id: &str, sth: &SignedTreeHead, producer_key_id: &str) -> Self {
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            stream_id: stream_id.to_owned(),
            tree_size: sth.tree_size,
            root_hash: hex::encode(sth.root_hash),
            timestamp: sth
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            producer_key_id: producer_key_id.to_owned(),
            sig_ed25519: b64.encode(&sth.signature.classical.signature),
            sig_ml_dsa_65: b64.encode(&sth.signature.pqc.signature),
        }
    }

    /// The claim a file row carries, if any.
    #[must_use]
    pub fn from_row(row: &Attestation) -> Option<Self> {
        serde_json::from_value(row.attestation_envelope.get(FIELD_STREAM_STH)?.clone()).ok()
    }

    /// The root, decoded.
    ///
    /// # Errors
    /// Not 32 bytes of hex.
    pub fn root(&self) -> Result<[u8; 32], String> {
        decode_root(&self.root_hash)
    }

    /// Back to a [`SignedTreeHead`], the producer's public keys resolved from
    /// `directory`.
    ///
    /// # Errors
    /// A malformed member, or a producer this directory does not know.
    pub async fn to_sth(
        &self,
        directory: &dyn FederationDirectory,
    ) -> Result<SignedTreeHead, String> {
        let timestamp = chrono::DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|e| format!("stream_sth.timestamp: {e}"))?
            .with_timezone(&chrono::Utc);
        Ok(SignedTreeHead {
            log_id: ciris_persist::federation::log_id_for_stream(&self.stream_id),
            tree_size: self.tree_size,
            root_hash: self.root()?,
            timestamp,
            signature: hybrid_from_parts(
                directory,
                &self.producer_key_id,
                &self.sig_ed25519,
                &self.sig_ml_dsa_65,
            )
            .await?,
            witness_signatures: Vec::new(),
        })
    }
}

fn decode_root(hex_root: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_root)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("root {hex_root:?} is not 32 bytes of hex"))
}

/// A [`ciris_crypto::HybridSignature`] from its two halves and the signer's
/// pinned public keys.
async fn hybrid_from_parts(
    directory: &dyn FederationDirectory,
    key_id: &str,
    ed_b64: &str,
    pqc_b64: &str,
) -> Result<ciris_crypto::HybridSignature, String> {
    use ciris_crypto::{
        ClassicalAlgorithm, PqcAlgorithm, SignatureMode, TaggedClassicalSignature,
        TaggedPqcSignature, CRYPTO_KIND_CIRIS_V1,
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let record = directory
        .lookup_public_key(key_id)
        .await
        .map_err(|e| format!("lookup {key_id}: {e}"))?
        .ok_or_else(|| format!("{key_id} is not in this directory"))?;
    let decode = |what: &str, s: &str| b64.decode(s).map_err(|e| format!("{what}: {e}"));
    let pqc_pub = record
        .pubkey_ml_dsa_65_base64
        .as_deref()
        .ok_or_else(|| format!("{key_id} has no ML-DSA-65 key"))?;
    Ok(ciris_crypto::HybridSignature {
        crypto_kind: CRYPTO_KIND_CIRIS_V1,
        classical: TaggedClassicalSignature {
            algorithm: ClassicalAlgorithm::Ed25519,
            signature: decode("ed25519 signature", ed_b64)?,
            public_key: decode("ed25519 key", &record.pubkey_ed25519_base64)?,
        },
        pqc: TaggedPqcSignature {
            algorithm: PqcAlgorithm::MlDsa65,
            signature: decode("ml-dsa-65 signature", pqc_b64)?,
            public_key: decode("ml-dsa-65 key", pqc_pub)?,
        },
        mode: SignatureMode::HybridRequired,
    })
}

// ─── The receipt on the wire ──────────────────────────────────────────

/// **The receipt as a receipt row carries it** — persist's
/// [`DeliveryReceipt`], with the signature's halves in base64 (the public keys
/// come from the verifier's directory, as for [`StreamSthClaim`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptClaim {
    /// The stream.
    pub stream_id: String,
    /// The receiving node.
    pub subscriber_key_id: String,
    /// The epoch the bytes were sealed under.
    pub epoch: u64,
    /// Chunks acknowledged (`K`).
    pub k: u64,
    /// Hex root acknowledged.
    pub chunk_root: String,
    /// Base64 Ed25519 half over `receipt_signing_bytes`.
    pub sig_ed25519: String,
    /// Base64 ML-DSA-65 half.
    pub sig_ml_dsa_65: String,
}

impl ReceiptClaim {
    /// The claim for `receipt`.
    #[must_use]
    pub fn of(receipt: &DeliveryReceipt) -> Self {
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            stream_id: receipt.stream_id.clone(),
            subscriber_key_id: receipt.subscriber_key_id.clone(),
            epoch: receipt.epoch,
            k: receipt.k,
            chunk_root: hex::encode(receipt.chunk_root),
            sig_ed25519: b64.encode(&receipt.signature.classical.signature),
            sig_ml_dsa_65: b64.encode(&receipt.signature.pqc.signature),
        }
    }

    /// Back to persist's type.
    ///
    /// # Errors
    /// A malformed member or an unknown subscriber.
    pub async fn to_receipt(
        &self,
        directory: &dyn FederationDirectory,
    ) -> Result<DeliveryReceipt, String> {
        Ok(DeliveryReceipt {
            stream_id: self.stream_id.clone(),
            subscriber_key_id: self.subscriber_key_id.clone(),
            epoch: self.epoch,
            k: self.k,
            chunk_root: decode_root(&self.chunk_root)?,
            signature: hybrid_from_parts(
                directory,
                &self.subscriber_key_id,
                &self.sig_ed25519,
                &self.sig_ml_dsa_65,
            )
            .await?,
        })
    }
}

/// **Sign a receipt as this node** — persist's canonical bytes
/// ([`receipt_signing_bytes`], the one spelling), the engine's hybrid signer
/// (the node's key: the node received the bytes; CC 5.3.3.6 names the
/// subscriber key, not the person).
///
/// # Errors
/// The engine has no hybrid local signer.
pub async fn sign_receipt(
    engine: &ciris_persist::Engine,
    subscriber_key_id: &str,
    stream_id: &str,
    epoch: u64,
    chunk_root: [u8; 32],
    k: u64,
) -> Result<DeliveryReceipt, String> {
    let bytes = receipt_signing_bytes(subscriber_key_id, stream_id, epoch, &chunk_root, k);
    let signature = engine
        .sign_hybrid(&bytes)
        .await
        .map_err(|e| format!("sign receipt: {e}"))?;
    Ok(DeliveryReceipt {
        stream_id: stream_id.to_owned(),
        subscriber_key_id: subscriber_key_id.to_owned(),
        epoch,
        k,
        chunk_root,
        signature,
    })
}

/// **Emit a receipt row** at the file row's own cohort — the room's delivered
/// path (self → the owner's devices; family and community → their rosters,
/// with the same cohort target the file row carries). Signed by the engine's
/// node identity. Refuses any other scope: a receipt is never a
/// federation-scope row.
///
/// # Errors
/// The file row's scope is not a room's, or persist refused the emit.
pub async fn emit_receipt_row(
    engine: &ciris_persist::Engine,
    file_row: &Attestation,
    receipt: &DeliveryReceipt,
) -> Result<String, String> {
    use ciris_persist::federation::types::cohort_scope as cs;
    let scope = file_row.cohort_scope.as_str();
    if !matches!(scope, cs::SELF | cs::FAMILY | cs::COMMUNITY) {
        return Err(format!(
            "a receipt rides the room's delivered path; {scope:?} is not a room's scope"
        ));
    }
    let mut envelope = serde_json::json!({
        "dimension": receipt_dimension(&receipt.stream_id),
        FIELD_RECEIPT: ReceiptClaim::of(receipt),
        FIELD_FILE_ATTESTATION_ID: file_row.attestation_id,
    });
    for field in ["community_key_id", "family_key_id"] {
        if let Some(v) = file_row.attestation_envelope.get(field) {
            envelope[field] = v.clone();
        }
    }
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .map_err(|e| format!("receipt envelope: {e}"))?;
    engine
        .emit_attestation_self(
            ciris_persist::federation::EmitAttestationInput::with_envelope("scores", core, scope),
        )
        .await
        .map_err(|e| format!("emit receipt row: {e}"))
}

/// Why a receipt was not emitted on the receiving node. Each is counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotEmitted {
    /// The file row carries no STH (published before CIRISEdge#738, or by a
    /// store with no stream log).
    NoSth,
    /// This node's store refused the row's STH: the claimed root is not what
    /// the chunks just adopted here reproduce, or the signature fails.
    SthRefused(String),
    /// Signing, storing or emitting failed.
    Failed(String),
}

impl NotEmitted {
    /// The `delivery_receipts` tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoSth => RECEIPT_NOT_EMITTED_NO_STH,
            Self::SthRefused(_) => RECEIPT_NOT_EMITTED_STH_REFUSED,
            Self::Failed(_) => RECEIPT_NOT_EMITTED_FAILED,
        }
    }
}

/// What [`emit_receipt`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emitted {
    /// A new receipt: stored here and emitted as the named row.
    New {
        /// The receipt row.
        row_id: String,
        /// The receipt.
        receipt: Box<DeliveryReceiptView>,
    },
    /// This node already receipted this stream at this epoch; nothing new.
    AlreadyReceipted,
}

/// The parts of a receipt a caller compares — `DeliveryReceipt` has no `Eq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceiptView {
    /// The stream.
    pub stream_id: String,
    /// The receiving node.
    pub subscriber_key_id: String,
    /// The epoch.
    pub epoch: u64,
    /// `K`.
    pub k: u64,
    /// The root acknowledged.
    pub chunk_root: [u8; 32],
}

impl From<&DeliveryReceipt> for DeliveryReceiptView {
    fn from(r: &DeliveryReceipt) -> Self {
        Self {
            stream_id: r.stream_id.clone(),
            subscriber_key_id: r.subscriber_key_id.clone(),
            epoch: r.epoch,
            k: r.k,
            chunk_root: r.chunk_root,
        }
    }
}

/// The epoch a receipt for `file` names: the pointer's sealed-under epoch
/// (a community file), else the stream's label (`self`/`family`).
#[must_use]
pub fn file_epoch(file: &FileRow) -> u64 {
    file.pointer.epoch.unwrap_or(FILE_STREAM_EPOCH)
}

/// **Receipt a pulled file** — the receiving half, exactly once per
/// `(stream, epoch, receiver)`.
///
/// Puts the row's STH into THIS node's store first: persist recomputes the root
/// from the chunks this node just adopted and refuses a root they do not
/// reproduce, so the root signed is one this node's own bytes commit to. Then
/// signs (`K` = `tree_size`), stores, and emits the row.
///
/// # Errors
/// [`NotEmitted`], naming why.
pub async fn emit_receipt<B>(
    engine: &ciris_persist::Engine,
    backend: &B,
    local_key_id: &str,
    row: &Attestation,
    file: &FileRow,
    stream_id: &str,
) -> Result<Emitted, NotEmitted>
where
    B: FederationDirectory + StreamLog,
{
    let claim = StreamSthClaim::from_row(row).ok_or(NotEmitted::NoSth)?;
    if claim.stream_id != stream_id {
        return Err(NotEmitted::SthRefused(format!(
            "the row's STH names stream {} and its pointer {stream_id}",
            claim.stream_id
        )));
    }
    let sth = claim
        .to_sth(backend)
        .await
        .map_err(NotEmitted::SthRefused)?;
    StreamLog::put_stream_sth(backend, sth.clone(), &claim.producer_key_id)
        .await
        .map_err(|e| NotEmitted::SthRefused(e.to_string()))?;

    let epoch = file_epoch(file);
    let held = StreamLog::list_delivery_receipts_for(backend, stream_id, RECEIPT_LIST_LIMIT)
        .await
        .map_err(|e| NotEmitted::Failed(format!("list receipts: {e}")))?;
    if held
        .iter()
        .any(|r| r.subscriber_key_id == local_key_id && r.epoch == epoch)
    {
        return Ok(Emitted::AlreadyReceipted);
    }

    let receipt = sign_receipt(
        engine,
        local_key_id,
        stream_id,
        epoch,
        sth.root_hash,
        sth.tree_size,
    )
    .await
    .map_err(NotEmitted::Failed)?;
    StreamLog::put_delivery_receipt(backend, receipt.clone())
        .await
        .map_err(|e| NotEmitted::Failed(format!("put_delivery_receipt: {e}")))?;
    let row_id = emit_receipt_row(engine, row, &receipt)
        .await
        .map_err(NotEmitted::Failed)?;
    Ok(Emitted::New {
        row_id,
        receipt: Box::new(DeliveryReceiptView::from(&receipt)),
    })
}

/// **The pull's receipt hook** — called from exactly two places in
/// `blob_swarm::pull`: the DAG walk after `promote`, and the whole-blob pull
/// after an inline file is stored. On `Stored` for a file row,
/// [`emit_receipt`] over the file's stream ([`receipt_stream_id`]), counted.
/// Every other outcome — a refusal, a wait for the key, a resume still
/// missing chunks — emits nothing, which is what "none before promote" and
/// "none after a tampered chunk" rest on.
pub async fn on_file_pulled<B>(
    engine: &ciris_persist::Engine,
    backend: &B,
    local_key_id: &str,
    row: &Attestation,
    outcome: &crate::blob_swarm::PullOutcome,
    metrics: &crate::observability::EdgeMetrics,
) where
    B: FederationDirectory + StreamLog,
{
    if !matches!(outcome, crate::blob_swarm::PullOutcome::Stored { .. }) {
        return;
    }
    let Some(file) = FileRow::from_row(row) else {
        return;
    };
    let Some(stream_id) = receipt_stream_id(&file.pointer) else {
        return;
    };
    match emit_receipt(engine, backend, local_key_id, row, &file, &stream_id).await {
        Ok(Emitted::New { row_id, receipt }) => {
            metrics.inc_delivery_receipt(RECEIPT_EMITTED);
            tracing::info!(
                stream_id = %stream_id,
                file = %row.attestation_id,
                receipt_row = %row_id,
                k = receipt.k,
                "delivery receipt emitted (CC 5.3.3.6, CIRISEdge#738)"
            );
        }
        Ok(Emitted::AlreadyReceipted) => {}
        Err(not) => {
            metrics.inc_delivery_receipt(not.tag());
            tracing::warn!(
                stream_id = %stream_id,
                file = %row.attestation_id,
                reason = ?not,
                "file pulled and NOT receipted (CIRISEdge#738)"
            );
        }
    }
}

// ─── Admit: the author's side ─────────────────────────────────────────

/// **Why a receipt row was refused** on the node that published the stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptRefusal {
    /// The `chunk_root` is not a root this node published for the stream.
    #[error("receipt_root_unpublished: stream {stream_id}: {detail}")]
    RootUnpublished {
        /// The stream.
        stream_id: String,
        /// What was found.
        detail: String,
    },
    /// `K` is past the published tree.
    #[error("receipt_tree_size_short: stream {stream_id}: K {k} > tree_size {tree_size}")]
    TreeSizeShort {
        /// The stream.
        stream_id: String,
        /// The receipt's `K`.
        k: u64,
        /// The published `tree_size`.
        tree_size: u64,
    },
    /// The receipt's epoch is not the file's.
    #[error("receipt_epoch_mismatch: stream {stream_id}: receipt {receipt}, file {file}")]
    EpochMismatch {
        /// The stream.
        stream_id: String,
        /// The receipt's epoch.
        receipt: u64,
        /// The file's.
        file: u64,
    },
    /// The signer's principal is not a member of the file's room.
    #[error("receipt_signer_not_member: {subscriber} (principal {principal}) is not in {room}")]
    SignerNotMember {
        /// The receiving node.
        subscriber: String,
        /// Whom it acts for.
        principal: String,
        /// The room.
        room: String,
    },
    /// This receiver already receipted this stream at this epoch.
    #[error(
        "receipt_duplicate: {subscriber} already receipted stream {stream_id} at epoch {epoch}"
    )]
    Duplicate {
        /// The stream.
        stream_id: String,
        /// The receiving node.
        subscriber: String,
        /// The epoch.
        epoch: u64,
    },
    /// Not a well-formed receipt row.
    #[error("receipt_malformed: {0}")]
    Malformed(String),
    /// The file row it names is not held here, or does not point at the stream.
    #[error("receipt_file_unknown: {0}")]
    FileUnknown(String),
    /// persist refused for a reason not named above.
    #[error("receipt_substrate: {0}")]
    Substrate(String),
}

impl ReceiptRefusal {
    /// The `delivery_receipts` tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::RootUnpublished { .. } => RECEIPT_ROOT_UNPUBLISHED,
            Self::TreeSizeShort { .. } => RECEIPT_TREE_SIZE_SHORT,
            Self::EpochMismatch { .. } => RECEIPT_EPOCH_MISMATCH,
            Self::SignerNotMember { .. } => RECEIPT_SIGNER_NOT_MEMBER,
            Self::Duplicate { .. } => RECEIPT_DUPLICATE,
            Self::Malformed(_) => RECEIPT_MALFORMED,
            Self::FileUnknown(_) => RECEIPT_FILE_UNKNOWN,
            Self::Substrate(_) => RECEIPT_SUBSTRATE,
        }
    }
}

/// Is `subscriber` a member of the room `file` lives in? The principal is the
/// node's owner (a node acts for its person, CC 3.3.6), else the key itself.
async fn membership(
    directory: &dyn FederationDirectory,
    file_row: &Attestation,
    file: &FileRow,
    subscriber: &str,
) -> Result<(), ReceiptRefusal> {
    use crate::contact::DirectoryLens as _;
    use ciris_persist::federation::types::cohort_scope as cs;
    let lens = crate::contact::PersistLens::new(directory);
    let principal = lens
        .owner_of(subscriber)
        .await
        .unwrap_or_else(|| subscriber.to_owned());
    let group = file.pointer.community_key_id.as_str();
    let is_member = match file_row.cohort_scope.as_str() {
        cs::SELF => principal == group,
        cs::FAMILY => directory
            .active_family_members(group)
            .await
            .map_err(|e| ReceiptRefusal::Substrate(format!("family {group}: {e}")))?
            .iter()
            .any(|m| m.key_id == principal || m.key_id == subscriber),
        cs::COMMUNITY => directory
            .active_community_members(group)
            .await
            .map_err(|e| ReceiptRefusal::Substrate(format!("community {group}: {e}")))?
            .iter()
            .any(|m| m.key_id == principal || m.key_id == subscriber),
        _ => false,
    };
    if is_member {
        Ok(())
    } else {
        Err(ReceiptRefusal::SignerNotMember {
            subscriber: subscriber.to_owned(),
            principal,
            room: format!("{}:{group}", file_row.cohort_scope),
        })
    }
}

/// **Admit a receipt row on the node that published the stream** — every
/// refusal named, in this order: well-formed, the file it names, the signer's
/// room membership, the epoch, the published root and its `tree_size`, a
/// duplicate; then persist's `put_delivery_receipt` (the signature over the
/// pinned key and the JOIN). A receipt for all `tree_size` chunks is recorded
/// in `ledger`, which is what stops the bridge re-offering the row to that
/// node.
///
/// # Errors
/// [`ReceiptRefusal`].
#[allow(clippy::too_many_lines)] // the named refusals, in order, in one place on purpose
pub async fn admit_receipt_row(
    log: &dyn StreamLog,
    directory: &dyn FederationDirectory,
    row: &Attestation,
    ledger: &ReceiptLedger,
) -> Result<DeliveryReceiptView, ReceiptRefusal> {
    let stream_id = receipt_row_stream(row)
        .ok_or_else(|| ReceiptRefusal::Malformed("not a delivery_receipt row".into()))?
        .to_owned();
    let claim: ReceiptClaim = row
        .attestation_envelope
        .get(FIELD_RECEIPT)
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| ReceiptRefusal::Malformed(format!("no `{FIELD_RECEIPT}` member")))?;
    if claim.stream_id != stream_id {
        return Err(ReceiptRefusal::Malformed(format!(
            "the dimension names stream {stream_id} and the receipt {}",
            claim.stream_id
        )));
    }
    if claim.subscriber_key_id != row.attesting_key_id {
        return Err(ReceiptRefusal::Malformed(format!(
            "the receipt names subscriber {} and the row is signed by {}",
            claim.subscriber_key_id, row.attesting_key_id
        )));
    }

    let file_id = row
        .attestation_envelope
        .get(FIELD_FILE_ATTESTATION_ID)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReceiptRefusal::Malformed(format!("no `{FIELD_FILE_ATTESTATION_ID}` member"))
        })?;
    let file_row = directory
        .get_attestation(file_id)
        .await
        .map_err(|e| ReceiptRefusal::Substrate(format!("read {file_id}: {e}")))?
        .ok_or_else(|| ReceiptRefusal::FileUnknown(format!("{file_id} is not held here")))?;
    let file = FileRow::from_row(&file_row)
        .filter(|f| receipt_stream_id(&f.pointer).as_deref() == Some(stream_id.as_str()))
        .ok_or_else(|| {
            ReceiptRefusal::FileUnknown(format!("{file_id} is not a file on stream {stream_id}"))
        })?;

    membership(directory, &file_row, &file, &claim.subscriber_key_id).await?;
    if row.cohort_scope != file_row.cohort_scope {
        return Err(ReceiptRefusal::Malformed(format!(
            "a receipt for a {} file rides at {}",
            file_row.cohort_scope, row.cohort_scope
        )));
    }

    let epoch = file_epoch(&file);
    if claim.epoch != epoch {
        return Err(ReceiptRefusal::EpochMismatch {
            stream_id,
            receipt: claim.epoch,
            file: epoch,
        });
    }

    let root = decode_root(&claim.chunk_root).map_err(ReceiptRefusal::Malformed)?;
    let sth = log
        .latest_stream_sth(&stream_id)
        .await
        .map_err(|e| ReceiptRefusal::Substrate(format!("latest_stream_sth: {e}")))?
        .ok_or_else(|| ReceiptRefusal::RootUnpublished {
            stream_id: stream_id.clone(),
            detail: "no STH is published for the stream here".into(),
        })?;
    if sth.root_hash != root {
        return Err(ReceiptRefusal::RootUnpublished {
            stream_id,
            detail: format!(
                "receipted root {} is not the published root {}",
                claim.chunk_root,
                hex::encode(sth.root_hash)
            ),
        });
    }
    if claim.k > sth.tree_size {
        return Err(ReceiptRefusal::TreeSizeShort {
            stream_id,
            k: claim.k,
            tree_size: sth.tree_size,
        });
    }

    let held = log
        .list_delivery_receipts_for(&stream_id, RECEIPT_LIST_LIMIT)
        .await
        .map_err(|e| ReceiptRefusal::Substrate(format!("list receipts: {e}")))?;
    if held
        .iter()
        .any(|r| r.subscriber_key_id == claim.subscriber_key_id && r.epoch == claim.epoch)
    {
        return Err(ReceiptRefusal::Duplicate {
            stream_id,
            subscriber: claim.subscriber_key_id,
            epoch: claim.epoch,
        });
    }

    let receipt = claim
        .to_receipt(directory)
        .await
        .map_err(ReceiptRefusal::Malformed)?;
    log.put_delivery_receipt(receipt.clone())
        .await
        .map_err(|e| match e {
            BlobError::InvalidArgument(detail) if detail.contains("no published STH") => {
                ReceiptRefusal::RootUnpublished {
                    stream_id: stream_id.clone(),
                    detail,
                }
            }
            other => ReceiptRefusal::Substrate(other.to_string()),
        })?;
    if receipt.k == sth.tree_size {
        ledger.record_full(&stream_id, &receipt.subscriber_key_id);
    }
    Ok(DeliveryReceiptView::from(&receipt))
}

/// [`admit_receipt_row`], counted — the bridge's call.
pub async fn admit_and_count(
    log: &dyn StreamLog,
    directory: &dyn FederationDirectory,
    row: &Attestation,
    ledger: &ReceiptLedger,
    metrics: Option<&crate::observability::EdgeMetrics>,
) -> Result<DeliveryReceiptView, ReceiptRefusal> {
    let out = admit_receipt_row(log, directory, row, ledger).await;
    let tag = match &out {
        Ok(_) => RECEIPT_ADMITTED,
        Err(refusal) => {
            tracing::warn!(
                attestation_id = %row.attestation_id,
                attester = %row.attesting_key_id,
                %refusal,
                "delivery receipt refused (CIRISEdge#738)"
            );
            refusal.tag()
        }
    };
    if let Some(m) = metrics {
        m.inc_delivery_receipt(tag);
    }
    out
}

// ─── The ledger: which peers hold which files in full ─────────────────

/// **Which nodes have receipted which file streams in full** — an in-process
/// index over the store's receipts, so the advertise loop can ask per row
/// without a read per row per peer. Fed by [`admit_receipt_row`] and hydrated
/// once per stream from the store; a stream past the cap is simply not
/// suppressed (a re-offer costs a Summary entry, never correctness).
#[derive(Debug, Default)]
pub struct ReceiptLedger {
    inner: Mutex<LedgerInner>,
}

#[derive(Debug, Default)]
struct LedgerInner {
    full: HashMap<String, HashSet<String>>,
    hydrated: HashSet<String>,
}

impl ReceiptLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `subscriber` has receipted every chunk of `stream_id`.
    pub fn record_full(&self, stream_id: &str, subscriber: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.full
                .entry(stream_id.to_owned())
                .or_default()
                .insert(subscriber.to_owned());
        }
    }

    /// Has `peer` receipted `stream_id` in full?
    #[must_use]
    pub fn is_receipted(&self, peer: &str, stream_id: &str) -> bool {
        self.inner
            .lock()
            .is_ok_and(|g| g.full.get(stream_id).is_some_and(|s| s.contains(peer)))
    }

    /// Load `stream_id`'s full receipts from `log` once per process.
    pub async fn hydrate(&self, log: &dyn StreamLog, stream_id: &str) {
        {
            let Ok(mut g) = self.inner.lock() else {
                return;
            };
            if g.hydrated.contains(stream_id) || g.hydrated.len() >= LEDGER_STREAM_CAP {
                return;
            }
            g.hydrated.insert(stream_id.to_owned());
        }
        let Ok(Some(sth)) = log.latest_stream_sth(stream_id).await else {
            return;
        };
        let Ok(receipts) = log
            .list_delivery_receipts_for(stream_id, RECEIPT_LIST_LIMIT)
            .await
        else {
            return;
        };
        for r in receipts
            .iter()
            .filter(|r| r.k == sth.tree_size && r.chunk_root == sth.root_hash)
        {
            self.record_full(stream_id, &r.subscriber_key_id);
        }
    }
}

// ─── Read: who received a file ────────────────────────────────────────

/// One node's receipt for a file, as the author's drive shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The receiving node.
    pub node_key_id: String,
    /// The epoch it receipted.
    pub epoch: u64,
    /// Chunks acknowledged (`K`); equal to the file's chunk count for a whole
    /// file (1 for an inline file).
    pub k: u64,
    /// When the author's store took the receipt (persist's `received_at`,
    /// CIRISPersist#953) — the store's fact, not the subscriber's claim.
    pub at: chrono::DateTime<chrono::Utc>,
}

/// The receipts `stream_id` holds in `log`, as [`Received`].
///
/// # Errors
/// The store read failed.
pub async fn received_for(log: &dyn StreamLog, stream_id: &str) -> Result<Vec<Received>, String> {
    Ok(log
        .list_stored_delivery_receipts_for(stream_id, RECEIPT_LIST_LIMIT)
        .await
        .map_err(|e| format!("list receipts for {stream_id}: {e}"))?
        .into_iter()
        .map(
            |StoredDeliveryReceipt {
                 receipt,
                 received_at,
             }| Received {
                node_key_id: receipt.subscriber_key_id,
                epoch: receipt.epoch,
                k: receipt.k,
                at: received_at,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dimension_round_trips_and_is_in_the_reserved_family() {
        let stream = "file-6c1f0f7e-2a52-4d7b-9d0b-0e1b7f4c9a10";
        let dim = receipt_dimension(stream);
        assert_eq!(dim, format!("delivery_receipt:{stream}:v1"));
        assert_eq!(stream_of_receipt_dimension(&dim), Some(stream));
        assert_eq!(stream_of_receipt_dimension("delivery_receipt::v1"), None);
        assert_eq!(stream_of_receipt_dimension("delivery_receipt:x"), None);
        assert_eq!(stream_of_receipt_dimension("file:v1"), None);
        let matched = ciris_persist::federation::namespace::matcher::match_family(&dim);
        assert_eq!(
            matched.family,
            Some("delivery_receipt:{stream_id}"),
            "the receipt dimension resolves to CC 3.4.6's reserved family"
        );
        assert!(matched.refusal.is_none(), "{:?}", matched.refusal);
        assert_eq!(
            matched.binds.get("stream_id").map(String::as_str),
            Some(stream)
        );
    }

    #[test]
    fn refusal_tags_are_a_closed_set() {
        let s = || "s".to_owned();
        let all = [
            ReceiptRefusal::RootUnpublished {
                stream_id: s(),
                detail: s(),
            },
            ReceiptRefusal::TreeSizeShort {
                stream_id: s(),
                k: 2,
                tree_size: 1,
            },
            ReceiptRefusal::EpochMismatch {
                stream_id: s(),
                receipt: 1,
                file: 0,
            },
            ReceiptRefusal::SignerNotMember {
                subscriber: s(),
                principal: s(),
                room: s(),
            },
            ReceiptRefusal::Duplicate {
                stream_id: s(),
                subscriber: s(),
                epoch: 0,
            },
            ReceiptRefusal::Malformed(s()),
            ReceiptRefusal::FileUnknown(s()),
            ReceiptRefusal::Substrate(s()),
        ];
        let tags: HashSet<&str> = all.iter().map(ReceiptRefusal::tag).collect();
        assert_eq!(tags.len(), all.len(), "one tag per refusal");
        for r in &all {
            assert!(
                r.to_string().starts_with(r.tag()),
                "the message leads with its tag: {r}"
            );
        }
    }

    #[test]
    fn the_ledger_suppresses_only_the_receipting_peer_and_only_that_stream() {
        let ledger = ReceiptLedger::new();
        assert!(!ledger.is_receipted("peer-b", "file-1"));
        ledger.record_full("file-1", "peer-b");
        assert!(ledger.is_receipted("peer-b", "file-1"));
        assert!(!ledger.is_receipted("peer-c", "file-1"));
        assert!(!ledger.is_receipted("peer-b", "file-2"));
    }

    #[test]
    fn a_file_row_names_its_stream_and_nothing_else_does() {
        let mut row = Attestation {
            attestation_id: "f".into(),
            attesting_key_id: "a".into(),
            attested_key_id: "a".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": FILE_DIMENSION,
                "content": { "stream_id": "file-x" },
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "a".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "self".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        assert_eq!(file_row_stream(&row), Some("file-x"));
        // An inline file names its one-leaf log: its address, as persist
        // spells it — and only that spelling.
        let sha = [0xab; 32];
        let inline = inline_blob_stream_id(&sha);
        row.attestation_envelope["content"] = serde_json::json!({ "content_sha256": inline });
        assert_eq!(file_row_stream(&row), Some(inline.as_str()));
        row.attestation_envelope["content"] =
            serde_json::json!({ "content_sha256": inline.to_uppercase() });
        assert_eq!(file_row_stream(&row), None, "not persist's spelling");
        row.attestation_envelope["dimension"] = serde_json::json!("chat.message");
        assert_eq!(file_row_stream(&row), None);
        row.attestation_envelope["dimension"] = serde_json::json!(receipt_dimension("file-x"));
        assert_eq!(receipt_row_stream(&row), Some("file-x"));
    }
}
