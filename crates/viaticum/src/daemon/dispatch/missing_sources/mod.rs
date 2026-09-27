//! dr-i11: how many live catalog files have no source on this machine.
//!
//! Counting means one `stat()` per live file. A NAS holds 10^5-10^6 files and the web
//! dashboard polls `status` every few seconds, so the count is never taken inside the
//! async status handler: it runs on the blocking pool, and `status` reads the last
//! result. The first call waits for the first count (awaited, not blocking the
//! runtime); after that a stale value triggers one background recount and is returned
//! as is. The count only reads the disk and the catalog — it never changes either.

#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use viaticum_core::db::{Db, DbError};
use viaticum_core::system_state::catalog::is_live_file;

/// How old the count may get before a `status` call triggers a recount.
pub const MISSING_SOURCE_REFRESH: Duration = Duration::from_secs(30);

/// Live catalog files whose path does not exist on this machine. Pure of caching.
pub(crate) fn count_files_without_source(db: &Db) -> Result<u32, DbError> {
    let n = db
        .list_all_files()?
        .iter()
        .filter(|f| is_live_file(f) && !std::path::Path::new(&f.path).exists())
        .count();
    Ok(n as u32)
}

#[derive(Debug, Default)]
struct CacheState {
    value: Option<u32>,
    counted_at: Option<Instant>,
    counting: bool,
}

/// The last `count_files_without_source` result, refreshed in the background.
#[derive(Debug)]
pub struct MissingSourceCache {
    refresh: Duration,
    state: Mutex<CacheState>,
}

impl Default for MissingSourceCache {
    fn default() -> Self {
        Self::new(MISSING_SOURCE_REFRESH)
    }
}

impl MissingSourceCache {
    pub fn new(refresh: Duration) -> Self {
        MissingSourceCache {
            refresh,
            state: Mutex::new(CacheState::default()),
        }
    }

    /// The count for `status`. First call: waits for a count on the blocking pool.
    /// Later: returns the last count at once; if it is older than the refresh period
    /// and no recount runs, starts one in the background. A failed count keeps the
    /// previous value (0 if there never was one) and is logged.
    pub async fn get(self: &Arc<Self>, db: &Db) -> u32 {
        let (known, start) = {
            let mut st = self.state.lock().expect("missing-source cache lock");
            let stale = st.counted_at.is_none_or(|t| t.elapsed() >= self.refresh);
            let start = stale && !st.counting;
            if start {
                st.counting = true;
            }
            (st.value, start)
        };
        if !start {
            return known.unwrap_or(0);
        }
        let this = Arc::clone(self);
        let db = db.clone();
        let task = tokio::task::spawn_blocking(move || {
            let result = count_files_without_source(&db);
            this.store(result)
        });
        match known {
            // Never counted: wait for this first count.
            None => task.await.unwrap_or(0),
            Some(v) => v,
        }
    }

    fn store(&self, result: Result<u32, DbError>) -> u32 {
        let mut st = self.state.lock().expect("missing-source cache lock");
        st.counting = false;
        st.counted_at = Some(Instant::now());
        match result {
            Ok(n) => st.value = Some(n),
            Err(e) => tracing::warn!(error = %e, "status: cannot count files without a source"),
        }
        st.value.unwrap_or(0)
    }
}
