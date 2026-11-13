//! The cohabiting binding's verify view runs inside persist's `.so`.
//!
//! `ciris_edge.abi3.so` and `ciris_persist.abi3.so` each statically link
//! `parking_lot_core`, and its waiter queue is a per-binary static. When edge
//! ran its own compiled copy of persist's SQLite store code against the
//! wheel's backend (the concrete `Arc<SqliteBackend>` lifted out of
//! `outbound_queue_capsule`), the two binaries took the store's writer mutex
//! through two different queues. A waiter parked by one is never woken by an
//! unlock from the other, so the first `dispatch_inbound_bytes` after
//! `init_edge_runtime` could hang forever in its key lookup.
//!
//! The live witness is `tools/scenarios/cohab_store_lock_contention.py`
//! (two wheels, one store, constant contention: red within seconds on a
//! wheel with the defect). This scan keeps `init_edge_runtime` from binding
//! `verify_dir` to a concrete backend arm again: the view every inbound
//! verify reads must be `PersistSideVerifyDirectory` over the ops proxy.

fn binding_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ffi/pyo3.rs");
    std::fs::read_to_string(path).expect("read src/ffi/pyo3.rs")
}

#[test]
fn init_edge_runtime_verifies_through_the_persist_side_view() {
    let src = binding_source();
    let bindings: Vec<_> = src.match_indices("let verify_dir").collect();
    assert_eq!(
        bindings.len(),
        1,
        "init_edge_runtime binds `verify_dir` exactly once, as its own `let` \
         (a tuple binding out of a `BackendDispatch` match is the defect)"
    );
    let (at, _) = bindings[0];
    let stmt_end = src[at..].find(";\n").expect("statement end") + at;
    let stmt = &src[at..stmt_end];
    assert!(
        stmt.contains("PersistSideVerifyDirectory::new("),
        "`verify_dir` must be the persist-side view over the ops proxy, got:\n{stmt}"
    );
    assert!(
        !stmt.contains("BackendDispatch"),
        "`verify_dir` must not come from a concrete backend arm:\n{stmt}"
    );
    assert!(
        !src.contains("let (verify_dir,"),
        "a concrete arm may not produce `verify_dir` through a tuple binding"
    );
}
