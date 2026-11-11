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
            inner.inner_ciphertext().len() + CHUNK_TRAILER_LEN
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
    junk.extend_from_slice(&[0u8; CHUNK_TRAILER_LEN]);
    let junk = with_ciphertext(&forged, junk);
    assert_eq!(
        auth.check(&junk).unwrap_err(),
        ChunkAuthError::TrailerInvalid
    );
    let key_b = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    let by_b = key_b.sign(&forged).unwrap();
    assert_eq!(
        auth.check(&by_b).unwrap_err(),
        ChunkAuthError::TrailerInvalid
    );
    // Too short to carry a signature at all.
    let bare = with_ciphertext(&forged, vec![0u8; 10]);
    assert_eq!(
        auth.check(&bare).unwrap_err(),
        ChunkAuthError::TrailerMissing
    );
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
        codecs: None,
        replaces: None,
        end: None,
        final_seq: None,
        kind: 0,
        framing: 0,
        explicit_v2: false,
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
    assert_eq!(
        auth.check(&by_b).unwrap_err(),
        ChunkAuthError::TrailerInvalid
    );
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
            ChunkAuthError::TrailerInvalid,
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
        ChunkAuthError::TrailerInvalid,
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

// ─── KAT vectors (for CIRISVerify) ──────────────────────────────────

/// Expected values of [`kat_vectors_are_deterministic`]; regenerate by
/// running it with `--nocapture` after an intended format change.
mod kat {
    pub const STREAM_ID: &str = "c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8";
    pub const CHUNK_KEY_PUB: &str =
        "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d";
    pub const BINDING_SIGNED_BYTES: &str =
        "63697269732d656467653a61762d73747265616d2d6b65793a7631010008726f6f6d2d6b6174000a6e6f64652d6b61742d610707070707070707070707070707070707070707070707070707070707070707c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d800000000000000050b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d";
    pub const BINDING_SIG_ED25519: &str =
        "cfee152e5695500e16a6138276132a1e4f3684951dfbfb838e3eade0240eee6b0cc7d1976935d8e4ea2bf11f3ea802cf8dfcb5cf93671856b5e1c66290130008";
    pub const BINDING_SIG_ML_DSA_65_SHA256: &str =
        "f4c5aec87ce37cd46f8ab10370e9c321cac1daba2ff6d89594b9e3dc0baf21d3";
    pub const BINDING_WIRE_SHA256: &str =
        "558daab6b4434ced81ddd497f38ade2c2f8d109be3e22a663174bb2d156fc4f8";
    pub const BINDING_ID: &str = "558daab6b4434ced";
    pub const INNER_AEAD: &str = "b3b432abd9ea536a45a933956e21b34dc01e4571e5196d0aa08396";
    pub const CHUNK_SIG_MESSAGE: &str =
        "63697269732d656467653a61762d6368756e6b2d7369673a7632c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d800000000000000050000000000000000ff000000000001a0c4506c00b3b432abd9ea536a45a933956e21b34dc01e4571e5196d0aa08396";
    pub const TRAILER: &str =
        "000001a0c4506c00cf846332f5b31fbf08b8b340514a53895515dff7d164b22be777779fe38a3f3ff5d55e896cba1ae768320aa633ad0b6a09fb2c58ea19154eb1b6b6d00a14ff09";
    pub const FORGED_TRAILER: &str =
        "000001a0c4506c008d2ebc021ef41a20e0734ac2ef78e408da634e1c47a3a0c6ab55132a9e3a6b977742bdef28be63574723b24c60a061a6da2340a064a70785195d093b80454006";
}

/// **KAT vectors from fixed seeds**, printed as hex and asserted, so
/// CIRISVerify can copy them: a binding (signing bytes and both signature
/// halves), a chunk (its inner AEAD, the bytes its trailer signs, the
/// trailer) with its verdict, and a forged chunk refused by token.
///
/// Inputs: publisher `node-kat-a` with Ed25519 seed `01`×32 and ML-DSA-65
/// seed `54`×32; room `room-kat`; join nonce `07`×32; epoch 5; chunk key seed
/// `0c`×32; DEK `42`×32; chunk_seq 0, codec `ff`, layer (0,0,0), plaintext
/// `kat-chunk-0`; source timestamp 1790000000000 ms; forger chunk key seed
/// `0f`×32.
#[tokio::test]
async fn kat_vectors_are_deterministic() {
    const PUBLISHER: &str = "node-kat-a";
    const KAT_ROOM: &str = "room-kat";
    // 2026-09-21T15:06:40Z, the chunk's signed source timestamp.
    const KAT_SOURCE_MS: u64 = 1_790_000_000_000;
    let publisher = signer(PUBLISHER, 1);
    let keys = Keys::of(&[&publisher]).await;
    let nonce = [0x07; 32];
    let epoch = Epoch(5);
    let stream = call_stream_id(KAT_ROOM, PUBLISHER, &nonce);
    let key = ChunkSigner::from_seed(stream, epoch, [0x0c; 32]);

    let binding = StreamKeyBinding::sign(&publisher, KAT_ROOM, nonce, stream, epoch, key.public())
        .await
        .unwrap();
    let again = StreamKeyBinding::sign(&publisher, KAT_ROOM, nonce, stream, epoch, key.public())
        .await
        .unwrap();
    assert_eq!(binding, again, "both signature halves are deterministic");
    let wire = binding.to_bytes();
    let auth = ChunkAuth::new(KAT_ROOM);
    assert!(matches!(
        auth.accept_binding(&wire, &[PUBLISHER.to_owned()], &keys)
            .await,
        BindingOutcome::Installed(_)
    ));

    let inner = seal_av_inner(
        b"kat-chunk-0",
        &dek(),
        stream,
        epoch,
        ChunkSeq(0),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .unwrap();
    let signed = key.sign_at(&inner, KAT_SOURCE_MS).unwrap();
    let trailer = &signed.inner_ciphertext()[inner.inner_ciphertext().len()..];
    let (who, opened) = auth.check(&signed).expect("verdict: verified");
    assert_eq!(&*who, PUBLISHER);
    assert_eq!(open_av_inner(&opened, &dek()).unwrap(), b"kat-chunk-0");

    let forger_key = ChunkSigner::from_seed(stream, epoch, [0x0f; 32]);
    let forged = forger_key.sign_at(&inner, KAT_SOURCE_MS).unwrap();
    let forged_trailer = &forged.inner_ciphertext()[inner.inner_ciphertext().len()..];
    let refused = auth.check(&forged).unwrap_err();
    assert_eq!(refused.refusal().as_str(), "av_chunk_trailer_invalid");
    let short = with_ciphertext(&inner, inner.inner_ciphertext()[..20].to_vec());
    assert_eq!(
        auth.check(&short).unwrap_err().refusal().as_str(),
        "av_chunk_trailer_missing"
    );

    let got = [
        ("STREAM_ID", hex::encode(stream.0)),
        ("CHUNK_KEY_PUB", hex::encode(key.public())),
        ("BINDING_SIGNED_BYTES", hex::encode(binding.signed_bytes())),
        ("BINDING_SIG_ED25519", hex::encode(&binding.sig_ed25519)),
        (
            "BINDING_SIG_ML_DSA_65_SHA256",
            hex::encode(Sha256::digest(&binding.sig_ml_dsa_65)),
        ),
        ("BINDING_WIRE_SHA256", hex::encode(Sha256::digest(&wire))),
        ("BINDING_ID", hex::encode(StreamKeyBinding::id_of(&wire))),
        ("INNER_AEAD", hex::encode(inner.inner_ciphertext())),
        (
            "CHUNK_SIG_MESSAGE",
            hex::encode(chunk_sig_message(
                &inner,
                inner.inner_ciphertext(),
                KAT_SOURCE_MS,
            )),
        ),
        ("TRAILER", hex::encode(trailer)),
        ("FORGED_TRAILER", hex::encode(forged_trailer)),
    ];
    for (name, value) in &got {
        println!("KAT {name} = {value}");
    }
    println!("KAT VERDICT chunk = verified (publisher {PUBLISHER})");
    println!("KAT VERDICT forged = {}", refused.refusal());
    let want = [
        kat::STREAM_ID,
        kat::CHUNK_KEY_PUB,
        kat::BINDING_SIGNED_BYTES,
        kat::BINDING_SIG_ED25519,
        kat::BINDING_SIG_ML_DSA_65_SHA256,
        kat::BINDING_WIRE_SHA256,
        kat::BINDING_ID,
        kat::INNER_AEAD,
        kat::CHUNK_SIG_MESSAGE,
        kat::TRAILER,
        kat::FORGED_TRAILER,
    ];
    for ((name, value), want) in got.iter().zip(want) {
        assert_eq!(value, want, "KAT {name}");
    }
}

/// Every refusal token is distinct, snake_case and `av_`-prefixed.
#[test]
fn refusal_tokens_are_stable_and_distinct() {
    let tokens: Vec<&str> = AvAuthRefusal::ALL.iter().map(|r| r.as_str()).collect();
    let mut sorted = tokens.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), tokens.len());
    for t in tokens {
        assert!(t.starts_with("av_"));
        assert!(t.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

/// CC 5.3.3.2.3 / CC 2.6.3: both signature lengths MUST hold at parse, so an
/// ML-DSA-65 signature of any length but 3309 is refused before verify.
#[test]
fn binding_parse_enforces_both_signature_lengths() {
    let good = StreamKeyBinding {
        room: "room".to_owned(),
        publisher: "pub".to_owned(),
        join_nonce: [1u8; 32],
        stream: StreamId([2u8; 32]),
        epoch: Epoch(1),
        chunk_key: [3u8; 32],
        sig_ed25519: vec![0u8; 64],
        sig_ml_dsa_65: vec![0u8; ML_DSA_65_SIG_LEN],
        codecs: None,
        replaces: None,
        end: None,
        final_seq: None,
        kind: 0,
        framing: 0,
        explicit_v2: false,
    };
    assert!(StreamKeyBinding::from_bytes(&good.to_bytes()).is_ok());
    for len in [1, ML_DSA_65_SIG_LEN - 1, ML_DSA_65_SIG_LEN + 1] {
        let mut bad = good.clone();
        bad.sig_ml_dsa_65 = vec![0u8; len];
        assert!(
            matches!(
                StreamKeyBinding::from_bytes(&bad.to_bytes()),
                Err(BindingError::Malformed("signature length"))
            ),
            "ML-DSA length {len} must be refused at parse"
        );
    }
    let mut bad = good.clone();
    bad.sig_ed25519 = vec![0u8; 63];
    assert!(StreamKeyBinding::from_bytes(&bad.to_bytes()).is_err());
}

/// A phone's audio-and-video codec map: `{0x04: h264, 0xFF: opus}`.
fn av_map() -> CodecMap {
    CodecMap::new([CodecToken::Opus, CodecToken::H264]).expect("a map")
}

/// A binding with the KAT's inputs and these v2 members, unsigned (the
/// signatures are not what these witnesses read).
fn kat_v2(v2: Option<V2Members>) -> StreamKeyBinding {
    let hex32 = |h: &str| -> [u8; 32] {
        let v = hex::decode(h).expect("hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };
    let explicit_v2 = v2.is_some();
    let (codecs, replaces, end, final_seq, kind, framing) = match v2 {
        Some(m) => (m.codecs, m.replaces, m.end, m.final_seq, m.kind, m.framing),
        None => (None, None, None, None, 0, 0),
    };
    StreamKeyBinding {
        room: "room-kat".to_owned(),
        publisher: "node-kat-a".to_owned(),
        join_nonce: [0x07; 32],
        stream: StreamId(hex32(kat::STREAM_ID)),
        epoch: Epoch(5),
        chunk_key: hex32(kat::CHUNK_KEY_PUB),
        sig_ed25519: vec![0u8; 64],
        sig_ml_dsa_65: vec![0u8; ML_DSA_65_SIG_LEN],
        codecs,
        replaces,
        end,
        final_seq,
        kind,
        framing,
        explicit_v2,
    }
}

// Shaped to `kat_v2`'s and `sign_v2`'s parameter, which take the members as an option.
#[allow(clippy::unnecessary_wraps, clippy::large_types_passed_by_value)]
fn v2m(codecs: CodecMap) -> Option<V2Members> {
    Some(V2Members {
        codecs: Some(codecs),
        replaces: None,
        end: None,
        final_seq: None,
        kind: 0,
        framing: 0,
    })
}

/// KAT — the v2 binding's signed bytes (CC reading (rc17) of 5.3.3.2.1–.3,
/// pending text): the v2 domain, version 2, v1's members 2-7, then the codec
/// map (`u8 count`, then per class sorted `class u8 ‖ u16_be len ‖ ascii
/// token`), `replaces` (`u8 present ‖ [stream 32]`), `end` (`u8`: 0 live, 1
/// left, 2 backgrounded, 3 this stream ended) and, with an end, `final_seq
/// u64_be`, then (v45, CC reading rc18) `kind u8` and `framing u8`. Same inputs as
/// [`kat_vectors_are_deterministic`], map `{0x04: h264, 0xFF: opus}`; a
/// second vector replaces stream `aa`x32, ends `left`, final_seq 42. The v1
/// signed bytes of the same inputs are unchanged.
#[test]
fn binding_v2_signed_bytes_kat() {
    const V2_SIGNED: &str = "63697269732d656467653a61762d73747265616d2d6b65793a7632020008726f6f6d2d6b6174000a6e6f64652d6b61742d610707070707070707070707070707070707070707070707070707070707070707c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d800000000000000050b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d0204000468323634ff00046f70757300000000";
    const V2_REPLACES_LEFT: &str = "63697269732d656467653a61762d73747265616d2d6b65793a7632020008726f6f6d2d6b6174000a6e6f64652d6b61742d610707070707070707070707070707070707070707070707070707070707070707c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d800000000000000050b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d0204000468323634ff00046f70757301aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01000000000000002a0000";
    // A share (kind 1), framed (framing 1), ended with `end = 3`, final_seq 9.
    const V2_SHARE_FRAMED_ENDED: &str = "63697269732d656467653a61762d73747265616d2d6b65793a7632020008726f6f6d2d6b6174000a6e6f64652d6b61742d610707070707070707070707070707070707070707070707070707070707070707c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d800000000000000050b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d0204000468323634ff00046f707573000300000000000000090101";
    let v2 = kat_v2(v2m(av_map()));
    assert_eq!(v2.version(), BINDING_VERSION_V2);
    assert_eq!(hex::encode(v2.signed_bytes()), V2_SIGNED);
    let full = kat_v2(Some(V2Members {
        codecs: Some(av_map()),
        replaces: Some(StreamId([0xaa; 32])),
        end: Some(SignedEnd::Left),
        final_seq: Some(42),
        kind: 0,
        framing: 0,
    }));
    assert_eq!(hex::encode(full.signed_bytes()), V2_REPLACES_LEFT);
    let share = kat_v2(Some(V2Members {
        codecs: Some(av_map()),
        replaces: None,
        end: Some(SignedEnd::Ended),
        final_seq: Some(9),
        kind: STREAM_KIND_SHARE,
        framing: FRAMING_FRAGMENTS,
    }));
    assert_eq!(hex::encode(share.signed_bytes()), V2_SHARE_FRAMED_ENDED);
    assert_eq!(
        hex::encode(kat_v2(None).signed_bytes()),
        kat::BINDING_SIGNED_BYTES,
        "v1 unchanged"
    );
    for b in [v2, full, share, kat_v2(None)] {
        let wire = b.to_bytes();
        assert_eq!(StreamKeyBinding::version_of(&wire), Some(b.version()));
        assert_eq!(StreamKeyBinding::from_bytes(&wire), Ok(b));
    }
}

/// The token table, and the map's own rules: each token under its class,
/// sorted by class, no class twice; an unregistered token, a token under
/// another class, an out-of-order or empty map, or a bad `replaces` / `end`
/// byte is malformed.
#[test]
#[allow(clippy::too_many_lines)] // every rule of the map, one after another
fn the_codec_map_rules() {
    use crate::transport::realtime_av::{CODEC_AV1_SVC, CODEC_OPAQUE, CODEC_TEMPORAL_LAYERED};
    let table: Vec<(&str, u8)> = CodecToken::ALL
        .iter()
        .map(|t| (t.as_str(), t.class()))
        .collect();
    assert_eq!(
        table,
        [
            ("av1", CODEC_AV1_SVC),
            ("h264", CODEC_TEMPORAL_LAYERED),
            ("opus", CODEC_OPAQUE),
        ]
    );
    for bad in ["opaque", "H264", "", "theora", "vp8", "vp9"] {
        assert_eq!(CodecToken::parse(bad), None, "{bad:?}");
    }
    assert_eq!(
        CodecMap::new([CodecToken::H264, CodecToken::H264]),
        Err(BindingError::Malformed("codec map class twice"))
    );
    assert_eq!(
        CodecMap::new([]),
        Err(BindingError::Malformed("codec map size"))
    );
    assert_eq!(
        av_map()
            .entries()
            .iter()
            .map(|(c, t)| (*c, t.as_str()))
            .collect::<Vec<_>>(),
        [(CODEC_TEMPORAL_LAYERED, "h264"), (CODEC_OPAQUE, "opus")],
        "sorted by class"
    );
    let good = kat_v2(v2m(av_map())).to_bytes();
    // The map starts right after the chunk key: count, then 0x04 h264, then
    // 0xff opus.
    let at = good
        .windows(2)
        .position(|w| w == [0x02, CODEC_TEMPORAL_LAYERED])
        .expect("the map");
    let rewrite = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut w = good.clone();
        f(&mut w);
        StreamKeyBinding::from_bytes(&w)
    };
    // h264 under 0xff instead of 0x04 (and the order with it).
    assert_eq!(
        rewrite(&|w| w[at + 1] = CODEC_OPAQUE),
        Err(BindingError::Malformed("codec class"))
    );
    // An unregistered token binds (an undecodable class here), and a token
    // that is not printable ASCII is malformed.
    let tok = good.windows(4).position(|w| w == b"opus").expect("opus");
    let unknown = rewrite(&|w| w[tok..tok + 4].copy_from_slice(b"flac")).expect("binds");
    assert_eq!(
        unknown.codecs.map(|m| m.class_codec(CODEC_OPAQUE)),
        Some(ClassCodec::Undecodable)
    );
    assert_eq!(
        rewrite(&|w| w[tok] = 0x07),
        Err(BindingError::Malformed("codec token"))
    );
    // A count of zero with the entries still there: they read as the next
    // members, which do not parse.
    assert!(rewrite(&|w| w[at] = 0).is_err());
    // v45 — a v2 binding with no map, no replacement, no end, kind 0 and
    // framing 0 binds: it states "framing 0" (every v45 stream signs one).
    let plain = kat_v2(Some(V2Members {
        codecs: None,
        replaces: None,
        end: None,
        final_seq: None,
        kind: STREAM_KIND_MEDIA,
        framing: FRAMING_NONE,
    }));
    assert_eq!(plain.version(), BINDING_VERSION_V2);
    assert_eq!(StreamKeyBinding::from_bytes(&plain.to_bytes()), Ok(plain));
    // An end statement of a stream that declared no codecs: an empty map.
    let end_only = kat_v2(Some(V2Members {
        codecs: None,
        replaces: None,
        end: Some(SignedEnd::Backgrounded),
        final_seq: Some(7),
        kind: 0,
        framing: 0,
    }));
    assert_eq!(end_only.version(), BINDING_VERSION_V2);
    assert_eq!(
        StreamKeyBinding::from_bytes(&end_only.to_bytes()),
        Ok(end_only)
    );
    // replaces byte 2, end byte 3 (the last two bytes of the v2 members sit
    // just before the Ed25519 length).
    let tail = at + 1 + (1 + 2 + 4) + (1 + 2 + 4);
    assert_eq!(
        rewrite(&|w| w[tail] = 2),
        Err(BindingError::Malformed("replaces"))
    );
    assert_eq!(
        rewrite(&|w| w[tail + 1] = 4),
        Err(BindingError::Malformed("end"))
    );
    // 7e kind: any value binds (an unknown one renders as media); 7f framing:
    // only 0 or 1.
    let unknown_kind = rewrite(&|w| w[tail + 2] = 9).expect("an unknown kind binds");
    assert_eq!(unknown_kind.kind, 9);
    assert_eq!(
        rewrite(&|w| w[tail + 3] = 2),
        Err(BindingError::Malformed("framing"))
    );
    // A v2 binding that says only "share" is still v2.
    let kind_only = kat_v2(Some(V2Members {
        codecs: None,
        replaces: None,
        end: None,
        final_seq: None,
        kind: STREAM_KIND_SHARE,
        framing: FRAMING_NONE,
    }));
    assert_eq!(kind_only.version(), BINDING_VERSION_V2);
    assert_eq!(
        StreamKeyBinding::from_bytes(&kind_only.to_bytes()),
        Ok(kind_only)
    );
}

/// The life rule on the whole map: a second v2 binding for the same
/// (stream, epoch), or for a later epoch, naming another map is refused
/// `av_binding_codec_changed`; the same map in a later epoch, and a v1
/// binding (no map), are not.
#[test]
fn a_stream_keeps_its_codec_map_for_its_life() {
    let auth = ChunkAuth::new("room-kat");
    let wire = |b: &StreamKeyBinding| Arc::new(b.to_bytes());
    let first = kat_v2(v2m(av_map()));
    auth.install(&first, wire(&first)).expect("first binding");
    let vp8 = CodecMap::new([CodecToken::Opus, CodecToken::Av1]).expect("map");
    let other = kat_v2(v2m(vp8));
    let refused = auth.install(&other, wire(&other));
    assert_eq!(
        refused,
        Err(BindingError::CodecChanged {
            held: av_map().to_string(),
            got: vp8.to_string()
        })
    );
    assert_eq!(
        refused.unwrap_err().refusal().as_str(),
        "av_binding_codec_changed"
    );
    let audio_only = kat_v2(v2m(CodecMap::new([CodecToken::Opus]).expect("map")));
    assert!(
        matches!(
            auth.install(&audio_only, wire(&audio_only)),
            Err(BindingError::CodecChanged { .. })
        ),
        "dropping a class is a different map"
    );
    let mut later = kat_v2(v2m(vp8));
    later.epoch = Epoch(6);
    assert!(
        matches!(
            auth.install(&later, wire(&later)),
            Err(BindingError::CodecChanged { .. })
        ),
        "in any epoch"
    );
    let mut same = kat_v2(v2m(av_map()));
    same.epoch = Epoch(6);
    assert_eq!(auth.install(&same, wire(&same)), Ok(()));
    let v1 = kat_v2(None);
    assert_eq!(auth.install(&v1, wire(&v1)), Ok(()), "v1 names no codec");
    assert_eq!(auth.codecs_of(first.stream), Some(av_map()));
}

/// A relay forwards each held binding's v1 encoding to every new leg and
/// its v2 encoding only to a peer that takes v2.
#[test]
fn a_relay_forwards_v2_only_to_peers_that_take_it() {
    let auth = ChunkAuth::new("room-kat");
    let v1 = kat_v2(None);
    let v2 = kat_v2(v2m(CodecMap::new([CodecToken::Av1]).expect("map")));
    auth.install(&v1, Arc::new(v1.to_bytes())).expect("v1");
    auth.install(&v2, Arc::new(v2.to_bytes())).expect("v2");
    let versions = |ok: bool| -> Vec<Option<u8>> {
        let mut v: Vec<Option<u8>> = auth
            .bindings_except("someone-else", ok)
            .iter()
            .map(|w| StreamKeyBinding::version_of(w))
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(versions(false), [Some(1)]);
    assert_eq!(versions(true), [Some(1), Some(BINDING_VERSION_V2)]);
    assert!(
        auth.bindings_except("node-kat-a", true).is_empty(),
        "never its own"
    );
}

/// The chunk-class rule on a phone's audio-and-video stream (`{0x04: h264,
/// 0xFF: opus}`), through the real binding path (signed, verified,
/// installed): its audio (0xFF) and its video (0x04, any temporal layer)
/// both verify; a chunk of a class the map does not name (0x01) is refused
/// `av_chunk_class_unlisted`, its signature good. A v1-only stream is not
/// checked.
#[tokio::test]
async fn a_chunk_of_a_class_its_map_does_not_name_is_refused() {
    use crate::transport::realtime_av::{CODEC_AV1_SVC, CODEC_TEMPORAL_LAYERED};
    let a = signer(A, 1);
    let keys = Keys::of(&[&a]).await;
    let auth = ChunkAuth::new(ROOM);
    let nonce = [7; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let key = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    let b = StreamKeyBinding::sign_v2(
        &a,
        ROOM,
        nonce,
        stream,
        Epoch(3),
        key.public(),
        v2m(av_map()),
    )
    .await
    .expect("bind");
    assert!(matches!(
        auth.accept_binding(&b.to_bytes(), &members(), &keys).await,
        BindingOutcome::Installed(_)
    ));
    let chunk = |seq, codec, temporal| {
        let inner = seal_av_inner(
            b"frame",
            &dek(),
            stream,
            Epoch(3),
            ChunkSeq(seq),
            codec,
            ChunkLayer {
                spatial: 0,
                temporal,
                quality: 0,
            },
        )
        .expect("seal");
        key.sign(&inner).expect("sign")
    };
    assert!(auth.check(&chunk(0, CODEC_OPAQUE, 0)).is_ok(), "audio");
    assert!(
        auth.check(&chunk(1, CODEC_TEMPORAL_LAYERED, 0)).is_ok(),
        "video base"
    );
    assert!(
        auth.check(&chunk(2, CODEC_TEMPORAL_LAYERED, 2)).is_ok(),
        "video t=2"
    );
    let refused = auth.check(&chunk(3, CODEC_AV1_SVC, 0)).unwrap_err();
    assert_eq!(refused, ChunkAuthError::ClassUnlisted);
    assert_eq!(refused.refusal().as_str(), "av_chunk_class_unlisted");
    // A v1-only stream names no codecs: every class passes.
    let nonce1 = [8; 32];
    let s1 = call_stream_id(ROOM, A, &nonce1);
    let k1 = ChunkSigner::generate(s1, Epoch(3)).unwrap();
    assert!(matches!(
        bind(&auth, &keys, &a, nonce1, 3, k1.public()).await,
        BindingOutcome::Installed(_)
    ));
    let inner = seal_av_inner(
        b"frame",
        &dek(),
        s1,
        Epoch(3),
        ChunkSeq(0),
        CODEC_AV1_SVC,
        ChunkLayer::BASE,
    )
    .expect("seal");
    assert!(auth.check(&k1.sign(&inner).expect("sign")).is_ok());
}

/// CC reading (rc17), pending text: a map naming a codec this build does not
/// know binds; that class is undecodable here (its chunks dropped and
/// counted) and the stream's other classes play. `{0x04: <unknown>, 0xFF:
/// opus}`: audio plays, the 0x04 chunks are dropped.
#[tokio::test]
async fn an_unknown_codec_binds_as_an_undecodable_class() {
    use crate::transport::realtime_av::CODEC_TEMPORAL_LAYERED;
    let a = signer(A, 1);
    let keys = Keys::of(&[&a]).await;
    let auth = ChunkAuth::new(ROOM);
    let nonce = [9; 32];
    let stream = call_stream_id(ROOM, A, &nonce);
    let key = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    let map = CodecMap::with_entries([
        (CODEC_TEMPORAL_LAYERED, Token::new("h266-2031").unwrap()),
        (CODEC_OPAQUE, Token::from(CodecToken::Opus)),
    ])
    .expect("an unknown token under its class is a map");
    let b = StreamKeyBinding::sign_v2(&a, ROOM, nonce, stream, Epoch(3), key.public(), v2m(map))
        .await
        .expect("bind");
    assert!(matches!(
        auth.accept_binding(&b.to_bytes(), &members(), &keys).await,
        BindingOutcome::Installed(_)
    ));
    let chunk = |seq, codec| {
        let inner = seal_av_inner(
            b"frame",
            &dek(),
            stream,
            Epoch(3),
            ChunkSeq(seq),
            codec,
            ChunkLayer::BASE,
        )
        .expect("seal");
        key.sign(&inner).expect("sign")
    };
    assert!(auth.check(&chunk(0, CODEC_OPAQUE)).is_ok(), "audio plays");
    assert_eq!(
        auth.check(&chunk(1, CODEC_TEMPORAL_LAYERED)).unwrap_err(),
        ChunkAuthError::ClassUndecodable
    );
    assert!(auth.check(&chunk(2, CODEC_OPAQUE)).is_ok());
    assert_eq!(auth.counts().undecodable, 1, "counted");
    // A registered token under another class is still malformed.
    assert_eq!(
        CodecMap::with_entries([(CODEC_TEMPORAL_LAYERED, Token::from(CodecToken::Opus))]),
        Err(BindingError::Malformed("codec class"))
    );
    // A token longer than 32 bytes is malformed.
    assert_eq!(
        Token::new(&"x".repeat(MAX_TOKEN_LEN + 1)),
        Err(BindingError::Malformed("codec token"))
    );
}

/// A stream `nonce` of A's at epoch 3, its key, and a binding of it
/// (unsigned: these witnesses install directly, as an accepted binding is).
fn ending_stream(
    nonce: u8,
    end: Option<(SignedEnd, u64)>,
) -> (StreamId, ChunkSigner, StreamKeyBinding) {
    let n = [nonce; 32];
    let stream = call_stream_id(ROOM, A, &n);
    let key = ChunkSigner::generate(stream, Epoch(3)).unwrap();
    let b = binding_for(stream, n, key.public(), end);
    (stream, key, b)
}

fn binding_for(
    stream: StreamId,
    nonce: [u8; 32],
    key: [u8; 32],
    end: Option<(SignedEnd, u64)>,
) -> StreamKeyBinding {
    StreamKeyBinding {
        room: ROOM.to_owned(),
        publisher: A.to_owned(),
        join_nonce: nonce,
        stream,
        epoch: Epoch(3),
        chunk_key: key,
        sig_ed25519: vec![0u8; 64],
        sig_ml_dsa_65: vec![0u8; ML_DSA_65_SIG_LEN],
        codecs: None,
        replaces: None,
        end: end.map(|(e, _)| e),
        final_seq: end.map(|(_, f)| f),
        kind: 0,
        framing: 0,
        explicit_v2: false,
    }
}

fn signed_chunk(key: &ChunkSigner, stream: StreamId, seq: u64) -> InnerSealed {
    key.sign(&seal(stream, 3, seq, b"frame")).expect("sign")
}

/// CC: `end` is final. After a verified end, a replayed `end = 0` binding of
/// the stream (in any epoch) is refused `av_binding_stream_ended`; a chunk
/// past the signed `final_seq` is refused `av_chunk_past_end`, never played;
/// chunks up to it still verify.
#[test]
fn a_signed_end_is_final_and_nothing_past_it_plays() {
    let auth = ChunkAuth::new(ROOM);
    let (stream, key, live) = ending_stream(21, None);
    auth.install(&live, Arc::new(live.to_bytes()))
        .expect("live");
    for seq in 0..=4 {
        assert!(auth.check(&signed_chunk(&key, stream, seq)).is_ok());
    }
    let end = binding_for(stream, [21; 32], key.public(), Some((SignedEnd::Left, 4)));
    auth.install(&end, Arc::new(end.to_bytes()))
        .expect("the end");
    let mut replay = binding_for(stream, [21; 32], key.public(), None);
    for epoch in [3, 4] {
        replay.epoch = Epoch(epoch);
        let refused = auth.install(&replay, Arc::new(replay.to_bytes()));
        assert_eq!(refused, Err(BindingError::StreamEnded), "epoch {epoch}");
        assert_eq!(
            refused.unwrap_err().refusal().as_str(),
            "av_binding_stream_ended"
        );
    }
    assert!(
        auth.check(&signed_chunk(&key, stream, 4)).is_ok(),
        "up to final_seq"
    );
    let past = auth.check(&signed_chunk(&key, stream, 5)).unwrap_err();
    assert_eq!(past, ChunkAuthError::PastEnd);
    assert_eq!(past.refusal().as_str(), "av_chunk_past_end");
    assert_eq!(auth.counts().past_end, 1);
    // The verdict: the tail arrived. Past it the stream's keys go, and its
    // presence stays.
    assert!(!auth.settle_end(stream), "the tail arrived");
    assert!(!auth.truncated(stream));
    assert_eq!(auth.counts().truncated, 0);
    assert!(auth.bound(stream, Epoch(3)).is_none(), "nothing more plays");
    assert!(auth.heard(stream));
}

/// v45 (CC rc18: "check the eviction order never drops a live stream") — a
/// camera and a share, then the camera replaced four times in a row: each
/// replacement retires the stream it names, and the four-newest bound
/// evicts retired streams first, so the share (live, the oldest install)
/// and the newest camera always bind.
#[test]
fn replacements_never_evict_a_live_share() {
    let auth = ChunkAuth::new(ROOM);
    let (cam, cam_key, b) = ending_stream(60, None);
    auth.install(&b, Arc::new(b.to_bytes())).expect("camera");
    let (share, share_key, b) = ending_stream(61, None);
    auth.install(&b, Arc::new(b.to_bytes())).expect("share");
    let mut prev = cam;
    let mut newest = (cam, cam_key);
    for n in 62..=66u8 {
        let (s, key, mut b) = ending_stream(n, None);
        b.replaces = Some(prev);
        auth.install(&b, Arc::new(b.to_bytes()))
            .expect("replacement");
        prev = s;
        newest = (s, key);
        assert!(
            auth.check(&signed_chunk(&share_key, share, u64::from(n)))
                .is_ok(),
            "the share still binds after replacement {n}"
        );
    }
    assert!(auth.check(&signed_chunk(&newest.1, newest.0, 0)).is_ok());
    assert!(
        auth.bound(cam, Epoch(3)).is_none(),
        "the first camera, long replaced, is gone"
    );
}

/// v45 — an ended stream leaves the publisher's newest-streams list, so a
/// member that adds and ends shares never pushes its camera out of the
/// four-newest bound at a receiver.
#[test]
fn ended_shares_never_evict_the_camera() {
    let auth = ChunkAuth::new(ROOM);
    let (cam, cam_key, cam_b) = ending_stream(40, None);
    auth.install(&cam_b, Arc::new(cam_b.to_bytes()))
        .expect("camera");
    for n in 41..=46u8 {
        let (share, key, b) = ending_stream(n, None);
        auth.install(&b, Arc::new(b.to_bytes())).expect("share");
        assert!(auth.check(&signed_chunk(&key, share, 0)).is_ok());
        let end = binding_for(share, [n; 32], key.public(), Some((SignedEnd::Left, 0)));
        auth.install(&end, Arc::new(end.to_bytes()))
            .expect("share ends");
        assert!(!auth.settle_end(share));
    }
    assert!(
        auth.check(&signed_chunk(&cam_key, cam, 0)).is_ok(),
        "six shares added and ended, the camera still binds"
    );
}

/// CC: a relay that drops the tail before a signed leave is caught: the end
/// names `final_seq` 9, this receiver verified up to 5 and nothing more came
/// before the verdict, and it reports the truncation, counted once.
#[test]
fn a_dropped_tail_before_a_signed_end_is_reported() {
    let auth = ChunkAuth::new(ROOM);
    let (stream, key, live) = ending_stream(22, None);
    auth.install(&live, Arc::new(live.to_bytes()))
        .expect("live");
    for seq in 0..=5 {
        assert!(auth.check(&signed_chunk(&key, stream, seq)).is_ok());
    }
    let end = binding_for(
        stream,
        [22; 32],
        key.public(),
        Some((SignedEnd::Backgrounded, 9)),
    );
    auth.install(&end, Arc::new(end.to_bytes()))
        .expect("the end");
    assert!(!auth.truncated(stream), "no verdict before it is settled");
    assert!(auth.settle_end(stream));
    assert!(auth.truncated(stream));
    assert!(auth.settle_end(stream), "the verdict holds");
    assert_eq!(auth.counts().truncated, 1, "counted once");
}

/// v45 — the tail may land after the end: the end names `final_seq` 9, this
/// receiver had verified up to 5 when it landed, and 6..=9 arrive after it
/// (inside the reorder window, before the verdict). They verify and play,
/// and the verdict is no truncation. A chunk past 9 still is refused.
#[test]
fn a_tail_that_lands_after_its_signed_end_is_no_truncation() {
    let auth = ChunkAuth::new(ROOM);
    let (stream, key, live) = ending_stream(25, None);
    auth.install(&live, Arc::new(live.to_bytes()))
        .expect("live");
    for seq in 0..=5 {
        assert!(auth.check(&signed_chunk(&key, stream, seq)).is_ok());
    }
    let end = binding_for(stream, [25; 32], key.public(), Some((SignedEnd::Left, 9)));
    auth.install(&end, Arc::new(end.to_bytes()))
        .expect("the end");
    for seq in [7, 6, 9, 8] {
        assert!(
            auth.check(&signed_chunk(&key, stream, seq)).is_ok(),
            "tail chunk {seq} after the end"
        );
    }
    assert_eq!(
        auth.check(&signed_chunk(&key, stream, 10)).unwrap_err(),
        ChunkAuthError::PastEnd
    );
    assert!(!auth.settle_end(stream));
    assert!(!auth.truncated(stream));
    assert_eq!(auth.counts().truncated, 0);
}

/// CC: an old signed leave replayed after a rejoin does nothing to the new
/// stream (a rejoin mints a new nonce, so a new stream id): the old end is
/// refused (it is final) and the new stream stays bound and plays.
#[test]
fn an_old_leave_replayed_after_a_rejoin_does_nothing_to_the_new_stream() {
    let auth = ChunkAuth::new(ROOM);
    let (old, old_key, live) = ending_stream(23, None);
    auth.install(&live, Arc::new(live.to_bytes()))
        .expect("live");
    let end = binding_for(old, [23; 32], old_key.public(), Some((SignedEnd::Left, 0)));
    auth.install(&end, Arc::new(end.to_bytes())).expect("left");
    let (new, new_key, rejoin) = ending_stream(24, None);
    assert_ne!(old, new);
    auth.install(&rejoin, Arc::new(rejoin.to_bytes()))
        .expect("rejoined");
    assert_eq!(
        auth.install(&end, Arc::new(end.to_bytes())),
        Err(BindingError::StreamEnded),
        "the replay"
    );
    assert!(auth.bound(new, Epoch(3)).is_some());
    for seq in 0..3 {
        assert!(auth.check(&signed_chunk(&new_key, new, seq)).is_ok());
    }
    assert!(!auth.truncated(new));
}

/// **KAT — framed chunks with the shipping trailer** (v45, CC reading rc18;
/// for CIRISVerify and CC 5.3.3.2.3): the KAT inputs of
/// [`kat_vectors_are_deterministic`] (stream, epoch 5, chunk key seed `0c`,
/// DEK `42`, source 1790000000000 ms), codec `0x04`, layer (0,0,0).
/// Vector 1: a whole frame `kat-frame` in one framed chunk, chunk_seq 0, its
/// plaintext the marker `0000 0001 00000000` (frame_seq 0) ‖ the frame.
/// Vector 2: the 30-byte frame `kat-frag-frame-012345678901234` at an
/// 18-byte budget, three fragments (chunk_seq 1, 2, 3; markers `0000 0003`,
/// `0001 0003`, `0002 0003`, each `‖ 00000001`, frame_seq 1), each a
/// whole sealed, signed chunk. frame_seq is keyed on (stream, class,
/// spatial, temporal, quality), the codec block's whole layer triple: here
/// (0x04, 0, 0, 0). Each value is the chunk's inner ciphertext ‖
/// trailer, hex. All four verify under the bound key, open, and reassemble
/// to their frames.
#[tokio::test]
async fn framed_chunk_kats_with_the_shipping_trailer() {
    use crate::transport::av_call::frame::{split, Reassembler};
    use crate::transport::realtime_av::CODEC_TEMPORAL_LAYERED;
    const PUBLISHER: &str = "node-kat-a";
    const KAT_ROOM: &str = "room-kat";
    const KAT_SOURCE_MS: u64 = 1_790_000_000_000;
    // Pinned at the first build (v45, 2026-11-10).
    const FRAMED_ONE: &str = "d8d54687ba82260445e5779cb0d4c1dff96382336f1d28026cf9e6946fb16ada50000001a0c4506c00a8f74015bacba932e255c6ff1b9bdccf720264e0fc93deb184f8c11fbaacc7fd21847a676675c25403661a43509730ae6d67820293286b152ebfa726af1fba0d";
    const FRAMED_THREE: [&str; 3] = [
        "ffc67f3a37f3911ddb75235c9db05fc24b1dae11e9514d22b45cf1b8a0658957881f000001a0c4506c003f146f4d305166790528c1c031979411cce1d7a8c26e858b4b3c56120b1518fe667ca40b3783607032d2ed80407bbe4a48bdb9e1798240325d42af150f10bf01",
        "b73c07787e6333f9d5038668001641edb4e140acd777b81a4d75e8f9f1e860eb4713000001a0c4506c00bd8e35ea296ef437be59f21153907532c65974b284804a2ad26a50e4a89ede66857167cbe287ac0034d774177d5ec654de6382adb7d377a80c153333d4e36105",
        "022f40b36032476ff4db9efb1f03ce81c1da56a54f6a7b658a50c1bc5cbd8cf3f172000001a0c4506c00e4ba491b4c36e5dfb49b6a9e445bfc982127edea23d1a4600cc6e3f9b0045decaf58025577bb527cd2730c2181db071f99692402be92431cdbee2647b355a709",
    ];
    let publisher = signer(PUBLISHER, 1);
    let keys = Keys::of(&[&publisher]).await;
    let nonce = [0x07; 32];
    let epoch = Epoch(5);
    let stream = call_stream_id(KAT_ROOM, PUBLISHER, &nonce);
    let key = ChunkSigner::from_seed(stream, epoch, [0x0c; 32]);
    let binding = StreamKeyBinding::sign(&publisher, KAT_ROOM, nonce, stream, epoch, key.public())
        .await
        .unwrap();
    let auth = ChunkAuth::new(KAT_ROOM);
    assert!(matches!(
        auth.accept_binding(&binding.to_bytes(), &[PUBLISHER.to_owned()], &keys)
            .await,
        BindingOutcome::Installed(_)
    ));
    let seal = |seq: u64, plaintext: &[u8]| {
        let inner = seal_av_inner(
            plaintext,
            &dek(),
            stream,
            epoch,
            ChunkSeq(seq),
            CODEC_TEMPORAL_LAYERED,
            ChunkLayer::BASE,
        )
        .unwrap();
        key.sign_at(&inner, KAT_SOURCE_MS).unwrap()
    };
    let one = split(b"kat-frame", 1_000, 0).expect("fits");
    assert_eq!(one.len(), 1);
    assert_eq!(&one[0][..8], &[0, 0, 0, 1, 0, 0, 0, 0]);
    let three = split(b"kat-frag-frame-012345678901234", 18, 1).expect("fits");
    assert_eq!(three.len(), 3);
    let sealed: Vec<_> = std::iter::once((0u64, &one[0]))
        .chain((1u64..).zip(three.iter()))
        .map(|(seq, p)| seal(seq, p))
        .collect();
    let got: Vec<String> = sealed
        .iter()
        .map(|c| hex::encode(c.inner_ciphertext()))
        .collect();
    for (i, g) in got.iter().enumerate() {
        println!("KAT FRAMED chunk_seq {i} = {g}");
    }
    let want: Vec<&str> = std::iter::once(FRAMED_ONE).chain(FRAMED_THREE).collect();
    assert!(!want.contains(&"PIN"), "pin the framed KATs: {got:?}");
    assert_eq!(got, want);
    let mut r = Reassembler::default();
    let mut frames = Vec::new();
    for (i, c) in sealed.iter().enumerate() {
        let (who, opened) = auth.check(c).expect("verified");
        assert_eq!(&*who, PUBLISHER);
        let plain = open_av_inner(&opened, &dek()).unwrap();
        let out = r.push(crate::transport::av_call::ReceivedFrame {
            publisher: PUBLISHER.into(),
            stream,
            epoch,
            chunk_seq: ChunkSeq(u64::try_from(i).unwrap()),
            codec_id: CODEC_TEMPORAL_LAYERED,
            layer: ChunkLayer::BASE,
            bytes: plain,
            frame_seq: None,
            source_ts_ms: 1_790_000_000_000,
        });
        assert!(out.refused.is_empty());
        frames.extend(out.frame.map(|f| f.bytes));
    }
    assert_eq!(
        frames,
        vec![
            b"kat-frame".to_vec(),
            b"kat-frag-frame-012345678901234".to_vec()
        ]
    );
}
