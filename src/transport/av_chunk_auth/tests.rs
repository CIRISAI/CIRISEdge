//! Witnesses for chunk source authentication (CIRISEdge#805). Each one was
//! mutation-checked: with the signature check disabled in
//! [`ChunkAuth::check`] the refusal witnesses fail.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use ciris_crypto::{Ed25519Verifier, MlDsa65Verifier, PqcVerifier as _};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};

use super::*;
use crate::transport::realtime_av::{
    open_av_inner, seal_av_inner, ChunkLayer, ChunkSeq, EpochDek, CODEC_OPAQUE,
};

const ROOM: &str = "room-chunk-auth";
const A: &str = "node-a";
const B: &str = "node-b";

fn signer(key_id: &str, seed: u8) -> LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
            .expect("ml-dsa-65"),
    );
    LocalSigner::new(key_id, classical, Some(pqc))
}

/// The directory's view of each key: its Ed25519 and ML-DSA-65 public keys,
/// checked the way persist checks a hybrid signature (ML-DSA over the signed
/// bytes followed by the Ed25519 signature).
struct Keys(HashMap<String, (Vec<u8>, Vec<u8>)>);

impl Keys {
    async fn of(signers: &[&LocalSigner]) -> Self {
        let mut m = HashMap::new();
        for s in signers {
            let ed = s.classical.public_key().await.unwrap();
            let pq = s.pqc.as_ref().unwrap().public_key().await.unwrap();
            m.insert(s.key_id.clone(), (ed, pq));
        }
        Self(m)
    }
}

#[async_trait::async_trait]
impl StreamKeyVerifier for Keys {
    async fn verify_publisher_signature(
        &self,
        signed: &[u8],
        key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: &str,
    ) -> Result<(), String> {
        let (ed, pq) = self.0.get(key_id).ok_or("unknown key")?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let ed_sig = b64.decode(ed25519_sig_b64).map_err(|e| e.to_string())?;
        let pq_sig = b64.decode(ml_dsa_65_sig_b64).map_err(|e| e.to_string())?;
        if !Ed25519Verifier::new()
            .verify_strict(ed, signed, &ed_sig)
            .unwrap_or(false)
        {
            return Err("ed25519".into());
        }
        let mut bound = signed.to_vec();
        bound.extend_from_slice(&ed_sig);
        if !MlDsa65Verifier::new()
            .verify(pq, &bound, &pq_sig)
            .unwrap_or(false)
        {
            return Err("ml-dsa-65".into());
        }
        Ok(())
    }
}

fn members() -> Vec<String> {
    vec![A.to_owned(), B.to_owned()]
}

fn dek() -> EpochDek {
    // Every member of the room derives the same stream DEK; the witnesses
    // hand the forger that DEK directly.
    EpochDek::from_bytes([0x42; 32])
}

fn seal(stream: StreamId, epoch: u64, seq: u64, pt: &[u8]) -> InnerSealed {
    seal_av_inner(
        pt,
        &dek(),
        stream,
        Epoch(epoch),
        ChunkSeq(seq),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .unwrap()
}

/// `key`'s binding for `publisher`'s stream from `nonce` at `epoch`, accepted
/// by `auth`.
async fn bind(
    auth: &ChunkAuth,
    keys: &Keys,
    publisher: &LocalSigner,
    nonce: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> BindingOutcome {
    let stream = call_stream_id(ROOM, &publisher.key_id, &nonce);
    let b = StreamKeyBinding::sign(publisher, ROOM, nonce, stream, Epoch(epoch), key)
        .await
        .expect("bind");
    auth.accept_binding(&b.to_bytes(), &members(), keys).await
}

fn relabel(inner: &InnerSealed, stream: StreamId, epoch: u64, seq: u64) -> InnerSealed {
    inner_sealed_from_parts(
        stream,
        Epoch(epoch),
        ChunkSeq(seq),
        inner.codec_id(),
        inner.layer(),
        inner.inner_ciphertext().to_vec(),
    )
}

/// **The publisher's chunks verify and open.** A's chunk, signed with its
/// bound key, passes the check, names A, and opens under the DEK once the
/// signature is removed. The signature adds exactly 64 bytes.
#[tokio::test]
async fn the_publishers_chunks_verify_and_open() {
    let (a, b) = (signer(A, 1), signer(B, 2));
    let keys = Keys::of(&[&a, &b]).await;
    let auth = ChunkAuth::new(ROOM);
    let nonce = [7; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let key = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    assert!(matches!(
        bind(&auth, &keys, &a, nonce, 3, key.public()).await,
        BindingOutcome::Installed(_)
    ));
    for seq in 0..5 {
        let inner = seal(stream, 3, seq, format!("a-{seq}").as_bytes());
        let signed = key.sign(&inner).unwrap();
        assert_eq!(
            signed.inner_ciphertext().len(),
            inner.inner_ciphertext().len() + CHUNK_SIG_LEN
        );
        let (publisher, opened) = auth.check(&signed).expect("A's own chunk verifies");
        assert_eq!(&*publisher, A);
        assert_eq!(
            open_av_inner(&opened, &dek()).unwrap(),
            format!("a-{seq}").as_bytes()
        );
    }
    assert_eq!(auth.counts().verified, 5);
    assert_eq!(auth.counts().forged, 0);
}

/// **A member holding the DEK cannot forge the publisher's chunks.** B holds
/// the stream's DEK and seals a chunk for A's stream that opens under it.
/// Unsigned, or signed with any key of B's, it is refused and counted. B
/// cannot bind a key to A's stream either: not under A's name (the hybrid
/// signature is B's), and not under its own (the stream id is A's).
#[tokio::test]
async fn a_member_holding_the_dek_cannot_forge_the_publishers_chunks() {
    let (a, b) = (signer(A, 1), signer(B, 2));
    let keys = Keys::of(&[&a, &b]).await;
    let auth = ChunkAuth::new(ROOM);
    let nonce = [7; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let key_a = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    assert!(matches!(
        bind(&auth, &keys, &a, nonce, 3, key_a.public()).await,
        BindingOutcome::Installed(_)
    ));

    // B's chunk is validly encrypted: the DEK opens it.
    let forged = seal(stream, 3, 9, b"forged by b");
    assert_eq!(open_av_inner(&forged, &dek()).unwrap(), b"forged by b");

    // Unsigned (B's 64 bytes of anything) and signed by B's own key.
    let mut junk = forged.inner_ciphertext().to_vec();
    junk.extend_from_slice(&[0u8; CHUNK_SIG_LEN]);
    let junk = with_ciphertext(&forged, junk);
    assert_eq!(auth.check(&junk).unwrap_err(), ChunkAuthError::Forged);
    let key_b = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    let by_b = key_b.sign(&forged).unwrap();
    assert_eq!(auth.check(&by_b).unwrap_err(), ChunkAuthError::Forged);
    // Too short to carry a signature at all.
    let bare = with_ciphertext(&forged, vec![0u8; 10]);
    assert_eq!(auth.check(&bare).unwrap_err(), ChunkAuthError::Forged);
    assert_eq!(auth.counts().forged, 3, "every forgery is counted");
    assert_eq!(auth.counts().verified, 0);

    // B cannot bind its key to A's stream under A's name ...
    let mut lie = StreamKeyBinding {
        room: ROOM.to_owned(),
        publisher: A.to_owned(),
        join_nonce: nonce,
        stream,
        epoch: Epoch(4),
        chunk_key: key_b.public(),
        sig_ed25519: Vec::new(),
        sig_ml_dsa_65: Vec::new(),
    };
    let (ed, pq) = crate::identity::sign_bound_hybrid(&b, &lie.signed_bytes(), "lie")
        .await
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    lie.sig_ed25519 = b64.decode(ed).unwrap();
    lie.sig_ml_dsa_65 = b64.decode(pq.unwrap()).unwrap();
    assert!(matches!(
        auth.accept_binding(&lie.to_bytes(), &members(), &keys)
            .await,
        BindingOutcome::Refused(BindingError::Signature(_))
    ));
    // ... nor under its own: the stream id names A.
    assert!(
        StreamKeyBinding::sign(&b, ROOM, nonce, stream, Epoch(4), key_b.public())
            .await
            .is_err()
    );
    let mut own = lie.clone();
    own.publisher = B.to_owned();
    let (ed, pq) = crate::identity::sign_bound_hybrid(&b, &own.signed_bytes(), "own")
        .await
        .unwrap();
    own.sig_ed25519 = b64.decode(ed).unwrap();
    own.sig_ml_dsa_65 = b64.decode(pq.unwrap()).unwrap();
    assert!(matches!(
        auth.accept_binding(&own.to_bytes(), &members(), &keys)
            .await,
        BindingOutcome::Refused(BindingError::NotThePublishersStream(_))
    ));
    // A non-member's binding of its own stream is refused too.
    let c = signer("node-c", 3);
    let keys_c = Keys::of(&[&a, &b, &c]).await;
    assert!(matches!(
        bind(&auth, &keys_c, &c, [1; 32], 3, [5; 32]).await,
        BindingOutcome::Refused(BindingError::NotAMember(_))
    ));
    // Still only A's key for epoch 3, and B's chunk is still refused.
    assert_eq!(auth.bound(stream, Epoch(4)).map(|b| b.key), None);
    assert_eq!(auth.check(&by_b).unwrap_err(), ChunkAuthError::Forged);
}

/// **A chunk replayed under another stream id, epoch or sequence number is
/// refused**, even where the SAME key is bound there: the signature covers
/// the header.
#[tokio::test]
async fn a_chunk_replayed_under_another_stream_or_epoch_is_refused() {
    let (a, b) = (signer(A, 1), signer(B, 2));
    let keys = Keys::of(&[&a, &b]).await;
    let auth = ChunkAuth::new(ROOM);
    let (n1, n2) = ([1; 32], [2; 32]);
    let (s1, s2) = (call_stream_id(ROOM, A, &n1), call_stream_id(ROOM, A, &n2));
    let key = ChunkSigner::from_seed(s1, Epoch(3), [9; 32]);
    // One key bound to two streams and two epochs.
    for (nonce, epoch) in [(n1, 3), (n2, 3), (n1, 4)] {
        assert!(matches!(
            bind(&auth, &keys, &a, nonce, epoch, key.public()).await,
            BindingOutcome::Installed(_)
        ));
    }
    let chunk = key.sign(&seal(s1, 3, 5, b"s1 e3 #5")).unwrap();
    assert!(auth.check(&chunk).is_ok(), "the original verifies");
    for (stream, epoch, seq, what) in [
        (s2, 3, 5, "another stream"),
        (s1, 4, 5, "another epoch"),
        (s1, 3, 6, "another sequence number"),
    ] {
        assert_eq!(
            auth.check(&relabel(&chunk, stream, epoch, seq))
                .unwrap_err(),
            ChunkAuthError::Forged,
            "replayed under {what}"
        );
    }
    // A stream with nothing bound refuses it as unbound.
    let s9 = call_stream_id(ROOM, A, &[9; 32]);
    assert_eq!(
        auth.check(&relabel(&chunk, s9, 3, 5)).unwrap_err(),
        ChunkAuthError::Unbound
    );
    assert_eq!(auth.counts().forged, 3);
    assert_eq!(auth.counts().unbound, 1);
}

/// **An epoch roll rebinds the key.** After the roll to epoch 4 the old key
/// cannot sign a chunk of epoch 4; epoch 3's chunks still in flight verify
/// under epoch 3's key; after the next roll epoch 3's key is gone and its
/// binding is refused as stale.
#[tokio::test]
async fn an_epoch_roll_rebinds_and_the_old_key_is_refused() {
    let (a, b) = (signer(A, 1), signer(B, 2));
    let keys = Keys::of(&[&a, &b]).await;
    let auth = ChunkAuth::new(ROOM);
    let nonce = [7; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let old = ChunkSigner::from_seed(stream, Epoch(3), [3; 32]);
    let new = ChunkSigner::from_seed(stream, Epoch(4), [4; 32]);
    let old_at_new = ChunkSigner::from_seed(stream, Epoch(4), [3; 32]);

    let old_wire = StreamKeyBinding::sign(&a, ROOM, nonce, stream, Epoch(3), old.public())
        .await
        .unwrap()
        .to_bytes();
    assert!(matches!(
        auth.accept_binding(&old_wire, &members(), &keys).await,
        BindingOutcome::Installed(_)
    ));
    let pre = old.sign(&seal(stream, 3, 0, b"pre")).unwrap();
    assert!(auth.check(&pre).is_ok());

    // The roll: epoch 4 is bound to a new key.
    assert!(matches!(
        bind(&auth, &keys, &a, nonce, 4, new.public()).await,
        BindingOutcome::Installed(_)
    ));
    let by_old = old_at_new.sign(&seal(stream, 4, 0, b"old key")).unwrap();
    assert_eq!(
        auth.check(&by_old).unwrap_err(),
        ChunkAuthError::Forged,
        "the old key signs no chunk of the new epoch"
    );
    assert!(auth
        .check(&new.sign(&seal(stream, 4, 0, b"new")).unwrap())
        .is_ok());
    assert!(
        auth.check(&pre).is_ok(),
        "epoch 3's chunks in flight across the roll still verify"
    );

    // The next roll: epoch 3's key is gone, and its binding cannot return.
    let newer = ChunkSigner::from_seed(stream, Epoch(5), [5; 32]);
    assert!(matches!(
        bind(&auth, &keys, &a, nonce, 5, newer.public()).await,
        BindingOutcome::Installed(_)
    ));
    assert_eq!(auth.check(&pre).unwrap_err(), ChunkAuthError::Unbound);
    assert!(matches!(
        auth.accept_binding(&old_wire, &members(), &keys).await,
        BindingOutcome::Known(_) | BindingOutcome::Refused(BindingError::Stale(3))
    ));
    assert!(auth.bound(stream, Epoch(3)).is_none(), "never reinstalled");
}

/// A binding travels as parts sized to the link, reassembles in any order
/// and interleaved with another, and a malformed or foreign part is refused.
#[tokio::test]
async fn bindings_ride_as_parts_and_reassemble() {
    let a = signer(A, 1);
    let nonce = [7; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let w1 = StreamKeyBinding::sign(&a, ROOM, nonce, stream, Epoch(1), [1; 32])
        .await
        .unwrap()
        .to_bytes();
    let w2 = StreamKeyBinding::sign(&a, ROOM, nonce, stream, Epoch(2), [2; 32])
        .await
        .unwrap()
        .to_bytes();
    assert!(
        w1.len() > 3000,
        "the hybrid signature makes it {} B",
        w1.len()
    );
    assert_eq!(StreamKeyBinding::from_bytes(&w1).unwrap().epoch, Epoch(1));
    for limit in [100, 383, 1237] {
        let parts = StreamKeyBinding::parts(&w1, Some(limit));
        assert!(parts.iter().all(|p| p.len() <= limit));
        let mut asm = BindingAssembler::default();
        let mut out = None;
        for p in parts.iter().rev() {
            match asm.push(p) {
                Part::Complete(w) => out = Some(w),
                Part::Incomplete => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(out.as_deref(), Some(w1.as_slice()));
    }
    // Interleaved.
    let (p1, p2) = (
        StreamKeyBinding::parts(&w1, Some(1000)),
        StreamKeyBinding::parts(&w2, Some(1000)),
    );
    let mut asm = BindingAssembler::default();
    let mut done = Vec::new();
    for (x, y) in p1.iter().zip(p2.iter()) {
        for p in [x, y] {
            if let Part::Complete(w) = asm.push(p) {
                done.push(w);
            }
        }
    }
    assert_eq!(done, vec![w1.clone(), w2.clone()]);
    // A part of the right shape whose reassembly does not hash to its id.
    let mut bad = StreamKeyBinding::parts(&w1, Some(10_000));
    assert_eq!(bad.len(), 1);
    let last = bad[0].len() - 1;
    bad[0][last] ^= 1;
    assert_eq!(BindingAssembler::default().push(&bad[0]), Part::Malformed);
    // A chunk is not a part; a link too small for a part carries none.
    assert_eq!(
        BindingAssembler::default().push(&[0x51; 120]),
        Part::NotAPart
    );
    assert!(StreamKeyBinding::parts(&w1, Some(40)).is_empty());
    assert!(collides_with_binding_part(StreamId(
        *b"CSKB\x01xxxxxxxxxxxxxxxxxxxxxxxxxxx"
    )));
}
