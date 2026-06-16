//! `realtime_av_rekey` — membership-change rekey cost as a function of
//! N (members), churn type (Join vs Leave), and rekey strategy
//! (flat unicast rewrap baseline vs MLS-backed `AvSession::advance_epoch`).
//!
//! Closes the bench half of CIRISEdge#129 — the brief there is "I'll
//! bench it and post numbers here": (a) per-delta hybrid-KEM wrap cost,
//! (b) O(N) flat vs O(log N) tree, with crossover data.
//!
//! # What this bench measures (and what it does NOT)
//!
//! - **`flat_unicast_rewrap`** — the v3.7.x baseline AvSession would
//!   have run had T3' not landed: derive a fresh random 32-byte
//!   `EpochDek`, then for each remaining member run one hybrid
//!   X25519+ML-KEM-768 KEX (via `FederationSession::initiate(
//!   peer, KexAlgorithm::HybridRequired)`) plus one AES-256-GCM wrap of
//!   the new DEK under the resulting session-key bytes plus one
//!   wire-serialize of the handshake message. The bench mimics the
//!   baseline INLINE (not via a baseline `AvSession` — the v3.7.x
//!   shape was rip-and-replaced in T6, so there's no surviving code to
//!   call). This is a faithful reconstruction of the per-member wrap
//!   cost the baseline would have paid.
//!
//! - **`mls_rekey`** — the v3.8.0 surface: `AvSession::advance_epoch(
//!   RosterDelta::{Join,Leave})` over an `AvSession::create(...)`-
//!   initialized session. Measures the sender-side cost
//!   (commit_construct + tls-codec serialize + Welcome on Join) of one
//!   rekey.
//!
//! # The multicast-amortization caveat (release-notes-quotable)
//!
//! Under **unicast** delivery, the MLS variant's sender-side cost is
//! also O(N) wraps per commit (sum of copath resolutions in a balanced
//! binary tree is N-1 wraps at N=2^k — see T3 discussion in
//! `realtime_av_session.rs`), not O(log N). The receiver-side O(log N)
//! advantage doesn't show in a sender-side bench. So the sender CPU
//! ratio of `mls_rekey / flat_unicast_rewrap` should hover around 1
//! at large N (both flatten to "do an asymmetric crypto op per
//! remaining member"); MLS's load-bearing constant factor is its use
//! of HPKE under X-Wing per copath resolution vs. the baseline's
//! ad-hoc hybrid X25519+ML-KEM-768 KEX wrap. The empirical ratio
//! depends on which path's primitives are better-optimized in this
//! build.
//!
//! The MLS rekey's TRUE win materializes under **multicast** delivery —
//! one Commit message broadcast to all receivers vs N distinct
//! messages in flat. Reticulum has no native multicast, so the
//! empirical win comes from the SFU relay path measured in
//! `realtime_av_relay.rs` (L4-C, separate bench, separate PR).
//!
//! Readers MUST NOT interpret this bench's numbers as "MLS rekey is
//! slow / fast vs flat" full-stop. The numbers are sender CPU under
//! unicast — the worst case for MLS. The full story needs the relay
//! bench's multicast curve.
//!
//! # Parameter sweep
//!
//! - **N (members)** ∈ {2, 8, 32, 128, 512, 2048} — extended to 2048 to
//!   surface the asymptote.
//! - **operation** ∈ {Join, Leave} — Join produces Commit + Welcome,
//!   Leave produces Commit only.
//!
//! Each (N, op) point is reported per-rekey time. Throughput is
//! reported as N members covered per rekey (the natural unit for the
//! "per-member wrap cost" framing #129 asked for).
//!
//! # Fixture hygiene
//!
//! Setup cost (creating the initial `AvSession` with N members, and
//! generating N fresh hybrid keypairs for the flat baseline's
//! recipients) is excluded from the steady-state rekey measurement:
//! the setup builds an `AvSession` plus a peer-roster vector once per
//! parameter, and criterion's `iter_batched` re-clones the cheap
//! per-iteration inputs at each sample so the rekey itself is the
//! timed step.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::field_reassign_with_default,
    clippy::needless_raw_string_hashes
)]

use std::time::Duration;

use ciris_crypto::{aes_gcm, ml_kem, x25519};
use ciris_edge::transport::federation_session::{FederationSession, KexAlgorithm, PeerKexPubkeys};
use ciris_edge::transport::realtime_av::StreamId;
use ciris_edge::transport::realtime_av_mls::Member;
use ciris_edge::transport::realtime_av_session::{AvSession, RosterDelta};
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

// ─── Parameter sweeps ───────────────────────────────────────────────

/// N values the bench fans out over. Extended to 2048 to surface the
/// asymptote per the brief.
const N_MEMBERS: &[usize] = &[2usize, 8, 32, 128, 512, 2048];

/// What kind of churn — affects which side of `advance_epoch`
/// (commit_add vs commit_remove) we hit and whether the baseline's
/// "remaining roster" is N or N-1.
#[derive(Copy, Clone, Debug)]
enum Op {
    Join,
    Leave,
}

impl Op {
    fn tag(self) -> &'static str {
        match self {
            Op::Join => "Join",
            Op::Leave => "Leave",
        }
    }
}

// ─── Fixture helpers ────────────────────────────────────────────────

/// One pre-generated hybrid recipient — both the advertised pubkey set
/// (what the flat baseline would publish on the federation directory)
/// AND a label for the rekey delta. The private material is dropped on
/// the fly; the bench only uses the pubkey-half because the baseline
/// flat-rewrap runs the initiator side (sender) only.
struct SyntheticPeer {
    key_id: String,
    advertised: PeerKexPubkeys,
}

/// Generate one hybrid-ready peer with synthetic CIRIS-side KEX
/// pubkeys. Uses `ciris_crypto::x25519::generate_ephemeral_keypair` +
/// `ciris_crypto::ml_kem::generate_keypair` — the same primitives
/// `federation_session::tests::fresh_recipient` uses.
fn fresh_synthetic_peer(idx: usize) -> SyntheticPeer {
    let (x_secret, _) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
    let x_pub = x25519::public_from_secret(&x_secret);
    let (_, mlkem_pub) = ml_kem::generate_keypair().expect("ml-kem keypair");
    SyntheticPeer {
        key_id: format!("peer-{idx:06}"),
        advertised: PeerKexPubkeys {
            x25519_pub: x_pub,
            mlkem768_pub: Some(mlkem_pub),
        },
    }
}

/// Build a `Member` from a `SyntheticPeer` — what `AvSession::create`
/// and `advance_epoch(Join)` consume.
fn synthetic_member(peer: &SyntheticPeer) -> Member {
    Member {
        key_id: peer.key_id.clone(),
        kex_pubkeys: peer.advertised.clone(),
    }
}

/// 32-byte fixed nonce for the bench's per-recipient AES-GCM wrap.
/// Real callers would derive a fresh per-(recipient, epoch) nonce; the
/// bench only cares about the wall-clock of one encrypt + the wire
/// shape, not nonce semantics.
const BENCH_DEK_WRAP_NONCE: [u8; 12] = [0xA5; 12];

/// Synthetic fresh EpochDek bytes — the flat baseline would generate
/// this from an OS CSPRNG at the start of each rekey. We mimic that
/// here with a fixed seed XOR'd against an iteration counter so each
/// iteration has fresh bytes but we don't pay the syscall cost (which
/// is not what this bench measures).
fn fresh_dek_bytes(iter: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = ((iter ^ (i as u64)).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u8;
    }
    out
}

/// Dummy stream-id — the bench's `AvSession::create` needs one but the
/// rekey path doesn't consume it cryptographically.
fn dummy_stream() -> StreamId {
    StreamId([0xAB; 32])
}

// ─── Flat unicast rewrap baseline ───────────────────────────────────

/// One full **flat-unicast-rewrap** rekey, sender side: for each
/// remaining member, run a hybrid KEX initiate (producing a fresh
/// session key), AES-256-GCM-wrap the new DEK under that session key,
/// and JSON-serialize the handshake message (proxy for the
/// wire-encoding cost; ciris-edge's federation_session uses serde, not
/// tls-codec — see notes below).
///
/// Returns the total bytes the sender would have produced (for
/// throughput accounting). The hot loop is N hybrid KEX calls + N
/// AES-GCM wraps + N serde_json encodes.
fn flat_unicast_rewrap(
    new_dek_bytes: &[u8; 32],
    remaining: &[SyntheticPeer],
) -> Result<usize, ciris_edge::transport::federation_session::SessionError> {
    let mut total_bytes = 0usize;
    for peer in remaining {
        // (a) Per-recipient hybrid X25519+ML-KEM-768 KEX.
        let (handshake, session_key) =
            FederationSession::initiate(&peer.advertised, KexAlgorithm::HybridRequired)?;

        // (b) AES-256-GCM wrap the new DEK under the session key bytes
        // (the KEM-DEM step the baseline would have shipped on the
        // wire as the per-member DekWrap).
        let wrap = aes_gcm::encrypt(session_key.as_bytes(), &BENCH_DEK_WRAP_NONCE, new_dek_bytes)
            .expect("aes-gcm encrypt");

        // (c) Wire-serialize the handshake message (proxy for the
        // wire-codec cost the baseline would have paid). Edge's
        // federation_session uses serde, not tls-codec — close
        // enough for the order-of-magnitude question this bench
        // answers.
        let msg_bytes = match &handshake {
            ciris_edge::transport::federation_session::SessionHandshakeMsg::Hybrid(m) => {
                serde_json::to_vec(m).expect("ser hybrid")
            }
            ciris_edge::transport::federation_session::SessionHandshakeMsg::Classical(m) => {
                // HybridRequired never falls back, but the type system
                // doesn't know that — keep the arm for completeness.
                serde_json::to_vec(m).expect("ser classical")
            }
        };

        total_bytes += wrap.len() + msg_bytes.len();
        black_box(&wrap);
        black_box(&msg_bytes);
    }
    Ok(total_bytes)
}

// ─── Bench groups ───────────────────────────────────────────────────

fn bench_flat_unicast_rewrap(c: &mut Criterion) {
    let mut group = c.benchmark_group("flat_unicast_rewrap");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));

    for &n in N_MEMBERS {
        for op in [Op::Join, Op::Leave] {
            // For Join: the baseline rewraps for the N existing members
            // PLUS the new joiner — N+1 recipients. For Leave: the
            // baseline rewraps for the N-1 remaining members. We pick
            // "remaining roster size" = N either way for clean
            // comparison with the mls_rekey numbers (the baseline
            // would have done the same number of wraps as a function
            // of "remaining-mesh size N").
            //
            // To keep the variable comparable, we sweep N as "members
            // the sender must wrap to" — same axis #129 asks for.
            let remaining: Vec<SyntheticPeer> = (0..n).map(fresh_synthetic_peer).collect();

            group.throughput(Throughput::Elements(n as u64));
            group.bench_with_input(BenchmarkId::new(op.tag(), n), &(n, op), |b, &(_n, _op)| {
                let mut counter = 0u64;
                b.iter_batched(
                    || {
                        counter = counter.wrapping_add(1);
                        fresh_dek_bytes(counter)
                    },
                    |dek_bytes| {
                        let r = flat_unicast_rewrap(&dek_bytes, &remaining);
                        black_box(r).ok();
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_mls_rekey(c: &mut Criterion) {
    let mut group = c.benchmark_group("mls_rekey");
    // openmls commits at N=2048 take seconds each — keep sample
    // budgets tight so the bench completes in reasonable wall-clock
    // (criterion's default is otherwise blown). Per the brief: report
    // time per rekey, not statistical exhaustiveness.
    group
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));

    for &n in N_MEMBERS {
        for op in [Op::Join, Op::Leave] {
            // Build the initial AvSession ONCE per parameter
            // combination (this is the expensive part — N member
            // KeyPackage mints + N add_members commits inside
            // MlsSession::create). The rekey itself is the timed
            // step; iter_batched clones the AvSession state fresh
            // each sample via the setup closure.
            //
            // For Join: initial roster is (N-1) members + creator =
            // N members, then we add one more (the bench iter
            // synthesizes a fresh joiner). For Leave: initial roster
            // is N members + creator, then we remove one of them.
            //
            // Note: the openmls libcrux provider is per-AvSession, so
            // re-creating an AvSession every iteration is expensive
            // (~milliseconds-to-seconds at large N). We use a single
            // pre-built session AND a `iter_batched` clone path:
            // since AvSession itself is not Clone (the MLS provider
            // holds mutable storage), we re-create it inside the
            // setup closure. This means the setup-cost dominates at
            // large N — criterion's `BatchSize::PerIteration`
            // separates that from the timed step.
            //
            // Floor: at N=2048 even the SETUP is ~tens of seconds.
            // We accept that cost; the alternative (one global
            // session reused across samples) would mutate the session
            // state mid-bench and produce non-comparable per-sample
            // costs as the MLS tree grew. Documented tradeoff.

            let create_initial = build_initial_members(n, op);

            group.throughput(Throughput::Elements(n as u64));
            group.bench_with_input(BenchmarkId::new(op.tag(), n), &(n, op), |b, &(_n, op)| {
                b.iter_batched(
                    || {
                        // Per-iteration setup: build a fresh
                        // AvSession at the pre-rekey state.
                        let (session, _dek) =
                            AvSession::create(dummy_stream(), "creator", create_initial.clone())
                                .expect("AvSession::create");
                        session
                    },
                    |mut session| {
                        let delta = match op {
                            Op::Join => {
                                let joiner = fresh_synthetic_peer(999_999);
                                RosterDelta::Join(synthetic_member(&joiner))
                            }
                            Op::Leave => {
                                // Remove "peer-000000" — the
                                // first member we added at
                                // create-time.
                                RosterDelta::Leave("peer-000000".to_string())
                            }
                        };
                        let r = session.advance_epoch(delta);
                        black_box(r).ok();
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

/// Build the initial `Member` set the bench's `AvSession::create`
/// consumes for a given (N, op) point.
///
/// - Join axis: we want post-rekey roster size = N+1 (creator + N-1
///   pre-existing + 1 joiner). Initial = N-1 members (creator + N-1
///   = N pre-rekey, +1 joiner = N+1 post).
/// - Leave axis: we want post-rekey roster size = N-1. Initial = N
///   members (creator + N = N+1 pre-rekey, -1 leaver = N post).
///
/// For the bench's purposes we use a uniform shape: initial = N
/// pre-generated members so the "N axis" maps cleanly to the
/// commit-cost variable. Receiver-side accounting is out of scope
/// (the rekey numbers are sender-side per the brief).
fn build_initial_members(n: usize, _op: Op) -> Vec<Member> {
    (0..n)
        .map(|i| {
            let p = fresh_synthetic_peer(i);
            synthetic_member(&p)
        })
        .collect()
}

criterion_group!(benches, bench_flat_unicast_rewrap, bench_mls_rekey);
criterion_main!(benches);
