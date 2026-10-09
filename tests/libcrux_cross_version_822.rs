//! CIRISEdge#822 — MLS compatibility across the libcrux-kem 0.0.7 → 0.0.10
//! provider swap (openmls_libcrux_crypto 0.3.1 → 0.3.1+ciris.1).
//!
//! One binary cannot hold both providers, so this file is built TWICE —
//! once against the pre-#822 lock (OLD) and once against the fork (NEW) —
//! and its stages are run in order, alternating binaries, over one fixture
//! directory (`CIRIS_822_DIR`):
//!
//! ```text
//!   s1_old  A creates; B's KeyPackage is minted + stashed (file-backed
//!           store), A adds B → Welcome(B) sealed under OLD, not consumed;
//!           C's KeyPackage minted + stashed under OLD.
//!   s2_new  PERSISTED STATE: A loads its OLD store; B restores its OLD
//!           X-Wing private material and opens the OLD Welcome; both agree
//!           on the exporter; B self-updates (rotate), A applies it.
//!           MIXED FLEET: A (NEW) adds C's OLD KeyPackage, then rotates;
//!           D's KeyPackage minted + stashed under NEW.
//!   s3_old  C (OLD) opens the NEW Welcome and applies the NEW rotate;
//!           C adds D's NEW KeyPackage and rotates — OLD commits.
//!   s4_new  A, B apply C's OLD commits; D (NEW) opens the OLD Welcome and
//!           applies the OLD rotate; all four agree on the exporter.
//! ```
//!
//! Every stage is `#[ignore]`d: it is a cross-build witness, not a unit
//! test, and a lone run has no fixtures to read.

use std::path::PathBuf;
use std::sync::Arc;

use ciris_edge::mls::cohort_group::{
    key_package_from_bytes, key_package_to_bytes, mint_cohort_key_material, CohortGroup,
    CohortGroups, CommitApplyOutcome,
};
use ciris_edge::mls::ScopeStateProvider;
use ciris_persist::encrypted_kv::XChaChaKvStore;

const ROOM: &str = "c-822";
const RETAINED: u64 = 16;

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("CIRIS_822_DIR").expect("CIRIS_822_DIR names the fixture dir"))
}

/// A node's file-backed MLS state store — the real at-rest shape.
fn store(node: &str) -> ScopeStateProvider {
    let kv = XChaChaKvStore::open(dir().join(format!("{node}.kv")), b"ciris-822-witness")
        .expect("open file-backed store");
    ScopeStateProvider::new(Arc::new(kv))
}

fn put(name: &str, bytes: &[u8]) {
    std::fs::write(dir().join(name), bytes).unwrap();
}

fn get(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

async fn load(node: &str) -> CohortGroup {
    CohortGroup::load(store(node), ROOM, RETAINED)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{node} has a persisted group"))
}

async fn mint_and_stash(node: &str) {
    let (material, kp) = mint_cohort_key_material(node).unwrap();
    CohortGroups::new(store(node), node)
        .stash_key_material(ROOM, &material)
        .await
        .unwrap();
    put(
        &format!("kp_{node}.bin"),
        &key_package_to_bytes(kp).unwrap(),
    );
}

async fn join_from_stash(node: &str, welcome: &[u8]) -> CohortGroup {
    let groups = CohortGroups::new(store(node), node);
    let material = groups
        .restore_key_material(ROOM)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{node}'s stashed key material survives"));
    groups
        .join(ROOM, material, welcome)
        .await
        .unwrap_or_else(|e| panic!("{node} opens the Welcome: {e}"))
}

async fn apply(g: &CohortGroup, commit: &[u8], who: &str) {
    match g.apply_remote_commit(commit).await {
        Ok(CommitApplyOutcome::Applied(_)) => {}
        other => panic!("{who} applies the commit: {other:?}"),
    }
}

async fn secret(g: &CohortGroup) -> [u8; 32] {
    *g.record_secret().await.unwrap().as_bytes()
}

async fn assert_agree(groups: &[(&str, &CohortGroup)]) {
    let (n0, g0) = groups[0];
    let (e0, s0) = (g0.epoch().await, secret(g0).await);
    for (n, g) in &groups[1..] {
        assert_eq!(g.epoch().await, e0, "{n} vs {n0}: epoch");
        assert_eq!(secret(g).await, s0, "{n} vs {n0}: exporter-derived secret");
    }
}

#[tokio::test]
#[ignore = "cross-build witness (CIRISEdge#822): run by stage, OLD then NEW"]
async fn s1_old() {
    let a = CohortGroup::create(store("node-a"), ROOM, "node-a", RETAINED)
        .await
        .unwrap();
    mint_and_stash("node-b").await;
    let add_b = a
        .add_member(
            "node-b",
            key_package_from_bytes(&get("kp_node-b.bin")).unwrap(),
        )
        .await
        .unwrap();
    put("welcome_b.bin", add_b.welcome().unwrap());
    put("secret_s1.bin", &secret(&a).await);
    mint_and_stash("node-c").await;
}

#[tokio::test]
#[ignore = "cross-build witness (CIRISEdge#822): run by stage, OLD then NEW"]
async fn s2_new() {
    // Witness 1: OLD at-rest state opens under NEW.
    let a = load("node-a").await;
    assert_eq!(
        secret(&a).await.to_vec(),
        get("secret_s1.bin"),
        "A's OLD state"
    );
    let b = join_from_stash("node-b", &get("welcome_b.bin")).await;
    assert_agree(&[("A", &a), ("B", &b)]).await;
    let upd = b.rotate().await.unwrap();
    apply(&a, upd.commit(), "A").await;
    assert_agree(&[("A", &a), ("B", &b)]).await;

    // Witness 2a: NEW adds an OLD-minted KeyPackage, then commits again.
    let add_c = a
        .add_member(
            "node-c",
            key_package_from_bytes(&get("kp_node-c.bin")).unwrap(),
        )
        .await
        .unwrap();
    apply(&b, add_c.commit(), "B").await;
    put("welcome_c.bin", add_c.welcome().unwrap());
    let rot = a.rotate().await.unwrap();
    apply(&b, rot.commit(), "B").await;
    put("commit_rot_new.bin", rot.commit());
    assert_agree(&[("A", &a), ("B", &b)]).await;
    put("secret_s2.bin", &secret(&a).await);

    mint_and_stash("node-d").await;
}

#[tokio::test]
#[ignore = "cross-build witness (CIRISEdge#822): run by stage, OLD then NEW"]
async fn s3_old() {
    // OLD opens a NEW Welcome and applies a NEW commit.
    let c = join_from_stash("node-c", &get("welcome_c.bin")).await;
    apply(&c, &get("commit_rot_new.bin"), "C").await;
    assert_eq!(
        secret(&c).await.to_vec(),
        get("secret_s2.bin"),
        "C agrees with NEW A"
    );

    // Witness 2b: OLD adds a NEW-minted KeyPackage, then commits again.
    let add_d = c
        .add_member(
            "node-d",
            key_package_from_bytes(&get("kp_node-d.bin")).unwrap(),
        )
        .await
        .unwrap();
    put("welcome_d.bin", add_d.welcome().unwrap());
    put("commit_add_d.bin", add_d.commit());
    let rot = c.rotate().await.unwrap();
    put("commit_rot_old.bin", rot.commit());
    put("secret_s3.bin", &secret(&c).await);
}

#[tokio::test]
#[ignore = "cross-build witness (CIRISEdge#822): run by stage, OLD then NEW"]
async fn s4_new() {
    let a = load("node-a").await;
    let b = load("node-b").await;
    for (n, g) in [("A", &a), ("B", &b)] {
        apply(g, &get("commit_add_d.bin"), n).await;
        apply(g, &get("commit_rot_old.bin"), n).await;
    }
    let d = join_from_stash("node-d", &get("welcome_d.bin")).await;
    apply(&d, &get("commit_rot_old.bin"), "D").await;
    assert_agree(&[("A", &a), ("B", &b), ("D", &d)]).await;
    assert_eq!(
        secret(&a).await.to_vec(),
        get("secret_s3.bin"),
        "NEW agrees with OLD C"
    );
    // And the NEW fleet keeps working on state the OLD build wrote into it.
    let upd = d.rotate().await.unwrap();
    for (n, g) in [("A", &a), ("B", &b)] {
        apply(g, upd.commit(), n).await;
    }
    assert_agree(&[("A", &a), ("B", &b), ("D", &d)]).await;
}
