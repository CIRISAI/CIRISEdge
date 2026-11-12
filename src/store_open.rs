//! Opening a file-backed persist store, with the reader pool off on Apple
//! targets until persist fixes it.
//!
//! **Why (CIRISPersist#1261).** At persist 61.2.2 a file-backed
//! `SqliteBackend::open` fails on macOS with `sqlite open readers: unable to
//! open database file`: the writer opens and sets WAL, then the read-only
//! reader pool's open returns `SQLITE_CANTOPEN`. Found by edge v45.0.0's macOS
//! lane; on a macos-15 runner `CIRIS_PERSIST_SQLITE_READERS=0` clears it, the
//! memory-map knob and the temp directory do not, and the open-file limit was
//! not the cause. Persist 61.0.5 opened the same stores. iOS links the same
//! system SQLite and is presumed affected; nobody has opened a file-backed
//! 61.2.x store there.
//!
//! **What this does.** On macOS and iOS, when the operator has not set
//! `CIRIS_PERSIST_SQLITE_READERS`, a file-backed store is opened with no reader
//! pool: reads fall back to the writer connection, off the runtime, which is
//! the model persist ran before the pool existed. The cost is concurrency
//! only. An operator's own setting wins, every other platform is untouched,
//! and an in-memory store never had a pool.
//!
//! Remove this module when the persist pin carries the fix.

use std::path::Path;
use std::sync::Arc;

use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;

/// persist's reader-count override (`sqlite_conn_model::READERS_ENV`).
const READERS_ENV: &str = ciris_persist::store::sqlite_conn_model::READERS_ENV;

/// Whether this build is for a platform where the reader pool is off by default.
const APPLE: bool = cfg!(any(target_os = "macos", target_os = "ios"));

/// The reader count to force, or `None` to leave persist's default.
///
/// Pure: `apple` is the platform, `operator` the value of
/// `CIRIS_PERSIST_SQLITE_READERS` if set, `in_memory` whether the path names an
/// in-memory database.
fn forced_readers(apple: bool, operator: Option<&str>, in_memory: bool) -> Option<usize> {
    (apple && operator.is_none() && !in_memory).then_some(0)
}

/// Open (or create) the SQLite store at `db_path` and run its migrations: what
/// `FederationDirectorySqlite::open` does, with [`forced_readers`] applied.
///
/// # Errors
///
/// persist's open or migration error.
pub async fn open_federation_sqlite(
    db_path: impl AsRef<Path>,
) -> Result<Arc<SqliteBackend>, ciris_persist::store::Error> {
    let path = db_path.as_ref();
    let in_memory = path == Path::new(":memory:");
    let operator = std::env::var(READERS_ENV).ok();
    let Some(readers) = forced_readers(APPLE, operator.as_deref(), in_memory) else {
        return ciris_persist::prelude::FederationDirectorySqlite::open(path).await;
    };
    tracing::warn!(
        readers,
        env = READERS_ENV,
        "opening the SQLite store with no reader pool on this platform \
         (tracked: CIRISPersist#1261); set the env var to override"
    );
    let backend =
        SqliteBackend::open_with_readers(path.to_string_lossy().into_owned(), readers).await?;
    backend.run_migrations().await?;
    Ok(Arc::new(backend))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool is forced off only on an Apple target, only for a file, and
    /// only when the operator said nothing.
    #[test]
    fn the_reader_pool_is_off_only_on_apple_for_a_file_with_no_operator_setting() {
        assert_eq!(forced_readers(true, None, false), Some(0));
        assert_eq!(
            forced_readers(true, Some("4"), false),
            None,
            "operator wins"
        );
        assert_eq!(
            forced_readers(true, Some("0"), false),
            None,
            "operator wins"
        );
        assert_eq!(
            forced_readers(true, None, true),
            None,
            "in-memory has no pool"
        );
        assert_eq!(forced_readers(false, None, false), None, "other platforms");
        assert_eq!(forced_readers(false, Some("2"), false), None);
    }

    /// A file-backed store opens through this door on the host platform and
    /// is usable: on macOS this is the open that failed at persist 61.2.2.
    #[tokio::test]
    async fn a_file_backed_store_opens_and_reopens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.db");
        let first = open_federation_sqlite(&path).await.expect("open");
        drop(first);
        open_federation_sqlite(&path).await.expect("reopen");
    }
}
