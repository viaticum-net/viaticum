// Block preparations that outlived their tick (pos-i7-d-a).
//
// A tick waits for a block's preparation only until its deadline. A preparation still
// running then is not dropped: its handle moves here, into a `JoinSet` that the run loop
// drains in its own `select!` arm (like the publishes in `in_flight`), so the loop never
// waits for it and the tick that started it is long over when it ends. The placements of
// a block preparing here are neither started again by a tick nor counted as new starts.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::task::{Id, JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::warn;
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::prepare::PreparedChallenge;

/// A preparation that ended after its tick: the challenges to publish now.
pub(crate) struct PrepDone {
    pub(super) block_id: SourceBlockId,
    /// Challenges per week of each holder, for the issue log line.
    pub(super) cpw_of: HashMap<DeviceId, u32>,
    pub(super) result: Result<Vec<PreparedChallenge>, JoinError>,
}

/// What is known of one preparation in flight.
struct Prep {
    block_id: SourceBlockId,
    /// When its tick started it.
    started: Instant,
    /// When the stuck-preparation WARN was last logged for it (pos-i7-d-b).
    last_warn: Option<Instant>,
}

/// The preparations in flight past their tick.
#[derive(Default)]
pub(crate) struct Preparing {
    set: JoinSet<PrepDone>,
    preps: HashMap<Id, Prep>,
}

impl Preparing {
    pub(super) fn len(&self) -> usize {
        self.set.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// The blocks preparing: a tick starts none of them again, for any holder.
    pub(super) fn blocks(&self) -> HashSet<SourceBlockId> {
        self.preps.values().map(|p| p.block_id).collect()
    }

    /// Age of the oldest preparation at `now` (zero when none).
    pub(super) fn oldest_age(&self, now: Instant) -> Duration {
        self.preps
            .values()
            .map(|p| now.saturating_duration_since(p.started))
            .max()
            .unwrap_or_default()
    }

    /// pos-i7-d-b: WARN for each preparation older than `periods` × `period`, at most once
    /// per `period` for a block. The slot is not freed.
    pub(super) fn warn_stuck(&mut self, now: Instant, period: Duration, periods: u32) {
        for p in self.preps.values_mut() {
            let age = now.saturating_duration_since(p.started);
            let quiet = p
                .last_warn
                .is_none_or(|w| now.saturating_duration_since(w) >= period);
            if age >= period * periods && quiet {
                p.last_warn = Some(now);
                warn!(
                    block = %p.block_id,
                    age_s = age.as_secs(),
                    "scheduler: PoS preparation still running"
                );
            }
        }
    }

    /// Adopt a preparation the tick stopped waiting for.
    pub(super) fn adopt(
        &mut self,
        block_id: SourceBlockId,
        cpw_of: HashMap<DeviceId, u32>,
        started: Instant,
        handle: JoinHandle<Vec<PreparedChallenge>>,
    ) {
        let task = self.set.spawn(async move {
            PrepDone {
                block_id,
                cpw_of,
                result: handle.await,
            }
        });
        self.preps.insert(
            task.id(),
            Prep {
                block_id,
                started,
                last_warn: None,
            },
        );
    }

    /// The next preparation to end (None when none is in flight).
    pub(super) async fn join_next(&mut self) -> Option<PrepDone> {
        let done = self.set.join_next_with_id().await?;
        Some(self.forget(done))
    }

    /// Stop waiting for every preparation (shutdown). The blocking tasks themselves run
    /// to their end; nothing is published from them, the placements are due at restart.
    pub(super) async fn shutdown(&mut self) {
        self.set.abort_all();
        while self.set.join_next().await.is_some() {}
        self.preps.clear();
    }

    fn forget(&mut self, done: Result<(Id, PrepDone), JoinError>) -> PrepDone {
        match done {
            Ok((id, p)) => {
                self.preps.remove(&id);
                p
            }
            // The wrapper only awaits the handle: it fails only when aborted (shutdown) or
            // when the runtime drops it.
            Err(e) => PrepDone {
                block_id: self
                    .preps
                    .remove(&e.id())
                    .map_or(SourceBlockId([0; 32]), |p| p.block_id),
                cpw_of: HashMap::new(),
                result: Err(e),
            },
        }
    }
}
