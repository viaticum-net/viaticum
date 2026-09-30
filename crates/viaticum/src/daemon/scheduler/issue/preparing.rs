// Block preparations that outlived their tick (pos-i7-d-a).
//
// A tick waits for a block's preparation only until its deadline. A preparation still
// running then is not dropped: its handle moves here, into a `JoinSet` that the run loop
// drains in its own `select!` arm (like the publishes in `in_flight`), so the loop never
// waits for it and the tick that started it is long over when it ends. The placements of
// a block preparing here are neither started again by a tick nor counted as new starts.

use std::collections::HashMap;

use tokio::task::{Id, JoinError, JoinHandle, JoinSet};
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::super::PendingKey;
use super::prepare::PreparedChallenge;

/// A preparation that ended after its tick: the challenges to publish now.
pub(crate) struct PrepDone {
    pub(super) block_id: SourceBlockId,
    /// Challenges per week of each holder, for the issue log line.
    pub(super) cpw_of: HashMap<DeviceId, u32>,
    pub(super) result: Result<Vec<PreparedChallenge>, JoinError>,
}

/// The preparations in flight past their tick, with the (block, holder) keys they cover.
#[derive(Default)]
pub(crate) struct Preparing {
    set: JoinSet<PrepDone>,
    keys: HashMap<Id, (SourceBlockId, Vec<PendingKey>)>,
}

impl Preparing {
    pub(super) fn len(&self) -> usize {
        self.set.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// The (block, holder) of every placement whose block is preparing.
    pub(super) fn keys(&self) -> impl Iterator<Item = &PendingKey> {
        self.keys.values().flat_map(|(_, keys)| keys)
    }

    /// Adopt a preparation the tick stopped waiting for.
    pub(super) fn adopt(
        &mut self,
        block_id: SourceBlockId,
        cpw_of: HashMap<DeviceId, u32>,
        keys: Vec<PendingKey>,
        handle: JoinHandle<Vec<PreparedChallenge>>,
    ) {
        let task = self.set.spawn(async move {
            PrepDone {
                block_id,
                cpw_of,
                result: handle.await,
            }
        });
        self.keys.insert(task.id(), (block_id, keys));
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
        self.keys.clear();
    }

    fn forget(&mut self, done: Result<(Id, PrepDone), JoinError>) -> PrepDone {
        match done {
            Ok((id, p)) => {
                self.keys.remove(&id);
                p
            }
            // The wrapper only awaits the handle: it fails only when aborted (shutdown) or
            // when the runtime drops it.
            Err(e) => PrepDone {
                block_id: self
                    .keys
                    .remove(&e.id())
                    .map_or(SourceBlockId([0; 32]), |k| k.0),
                cpw_of: HashMap::new(),
                result: Err(e),
            },
        }
    }
}
