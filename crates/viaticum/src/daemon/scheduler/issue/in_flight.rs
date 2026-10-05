// Challenge publishes in flight (pos-i7-c, W-1 of СТ-0c round 3).
//
// The issue tick spawns the publishes and returns; they end later and are settled by the
// scheduler's run loop (a `join_next_any` arm of its `select!`, which also collects the
// block preparations that outlived their tick, `preparing.rs`). So a slow publish — up to
// PEER_REQUEST_TIMEOUT (15 s) when no postman answers — never holds the loop: the loop
// keeps resolving responses, accruing the ledger and checking timeouts meanwhile.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::{Id, JoinError, JoinSet};
use tracing::instrument::WithSubscriber;
use tracing::{debug, error, info, warn};
use viaticum_core::mailbox::MailboxEntry;
use viaticum_core::types::hex_encode;

use super::super::{PendingHashChallenge, PendingKey, Scheduler};
use super::preparing::{Done, PrepDone, Preparing};
use crate::daemon::mailbox::routing::MailboxRouter;

/// What ended in `InFlight`: a publish, a block preparation that outlived its tick, or a batch of
/// overdue preparations (its members' results, all ready, its permit already given back).
pub(crate) enum Ended {
    Published(Result<Published, JoinError>),
    Prepared(PrepDone),
    Batch(Vec<PrepDone>),
}

/// A challenge publish that ended: what goes into pending on an Ack.
pub(crate) struct Published {
    challenge: PendingHashChallenge,
    cpw: u32,
    acks: anyhow::Result<usize>,
    took: Duration,
}

/// Publishes settled since the last issue-tick line (printed and reset by the tick).
#[derive(Debug, Default)]
pub(crate) struct SettleStats {
    /// Publishes with 0 acks, an error or a failed task (the challenge stays due).
    pub(crate) zero_ack: usize,
    /// The longest publish, from spawn to its first Ack (or its end).
    pub(crate) slowest_publish: Duration,
}

/// The owner's challenge publishes in flight, keyed by (block, holder) so a tick does not
/// issue a second challenge to a placement whose first is still being published.
#[derive(Default)]
pub(crate) struct InFlight {
    set: JoinSet<Published>,
    keys: HashMap<Id, PendingKey>,
    /// Block preparations that outlived their tick (pos-i7-d-a).
    pub(in crate::daemon::scheduler) preparing: Preparing,
    pub(crate) settled: SettleStats,
}

impl InFlight {
    pub(crate) fn len(&self) -> usize {
        self.set.len()
    }

    /// Nothing to wait for: no publish in flight and no preparation running.
    pub(crate) fn is_idle(&self) -> bool {
        self.set.is_empty() && self.preparing.is_empty()
    }

    /// The (block, holder) of every publish in flight.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &PendingKey> {
        self.keys.values()
    }

    pub(super) fn spawn(
        &mut self,
        key: PendingKey,
        publish: impl Future<Output = Published> + Send + 'static,
    ) {
        let handle = self.set.spawn(publish.with_current_subscriber());
        self.keys.insert(handle.id(), key);
    }

    /// The next publish to end (None when none is in flight).
    pub(crate) async fn join_next(&mut self) -> Option<Result<Published, JoinError>> {
        let done = self.set.join_next_with_id().await?;
        Some(self.forget(done))
    }

    /// A publish that already ended, without waiting.
    pub(super) fn try_join_next(&mut self) -> Option<Result<Published, JoinError>> {
        let done = self.set.try_join_next_with_id()?;
        Some(self.forget(done))
    }

    /// The next publish or preparation to end (None when none is in flight).
    pub(crate) async fn join_next_any(&mut self) -> Option<Ended> {
        tokio::select! {
            Some(prepared) = self.preparing.join_next() => Some(match prepared {
                Done::One(one) => Ended::Prepared(one),
                Done::Batch(many) => Ended::Batch(many),
            }),
            Some(done) = self.set.join_next_with_id() => Some(Ended::Published(self.forget(done))),
            else => None,
        }
    }

    /// Abort every publish in flight and wait for them to go, and stop waiting for the
    /// preparations (shutdown). An aborted publish's challenge was never put in pending;
    /// the placement is due at restart.
    pub(crate) async fn shutdown(&mut self) {
        self.preparing.shutdown().await;
        self.set.shutdown().await;
        self.keys.clear();
    }

    fn forget(&mut self, done: Result<(Id, Published), JoinError>) -> Result<Published, JoinError> {
        match done {
            Ok((id, p)) => {
                self.keys.remove(&id);
                Ok(p)
            }
            Err(e) => {
                self.keys.remove(&e.id());
                Err(e)
            }
        }
    }
}

/// Publish one challenge entry: returns at the first Ack (mailbox-i60) or when every
/// postman answered or timed out.
pub(super) async fn publish_challenge(
    router: Arc<MailboxRouter>,
    entry: MailboxEntry,
    challenge: PendingHashChallenge,
    cpw: u32,
) -> Published {
    let started = Instant::now();
    let acks = router.publish(entry, None).await;
    Published {
        challenge,
        cpw,
        acks,
        took: started.elapsed(),
    }
}

impl Scheduler {
    /// Account one ended publish: on ≥ 1 Ack the challenge goes into pending (W-3), on
    /// 0 acks or an error it stays due for the next tick. The insert comes after the
    /// Ack, possibly a while after it: the poll loop does not remember a response to a
    /// challenge not pending yet (pos-i6, `forwarded.rs` `select`), so a response that
    /// races its pending entry is forwarded again by the next poll.
    pub(crate) async fn settle_publish(
        &self,
        done: Result<Published, JoinError>,
        stats: &mut SettleStats,
    ) {
        let p = match done {
            Ok(p) => p,
            Err(join_err) => {
                error!(
                    err = %join_err,
                    "scheduler: PoS challenge publish task failed (panicked or cancelled) — will retry next tick"
                );
                stats.zero_ack += 1;
                return;
            }
        };
        stats.slowest_publish = stats.slowest_publish.max(p.took);
        let block_id = p.challenge.source_block_id;
        let holder_id = p.challenge.holder_id;
        // MAILBOX_STORE_TIMEOUT_SECS is the per-peer request timeout (enforced in routing.rs).
        match p.acks {
            Ok(0) => {
                warn!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    "scheduler: PoS challenge: 0 acks — treating as unsent, will retry next tick"
                );
                stats.zero_ack += 1;
                return;
            }
            Ok(ack_count) => {
                debug!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    ack_count,
                    "scheduler: PoS challenge published via mailbox"
                );
            }
            Err(e) => {
                warn!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    err = %e,
                    "scheduler: PoS challenge publish error — will retry next tick"
                );
                stats.zero_ack += 1;
                return;
            }
        }

        let challenge_id = p.challenge.challenge_id;
        self.pending
            .lock()
            .await
            .insert((block_id, holder_id), p.challenge);
        info!(
            block_id = %block_id,
            holder_id = %holder_id,
            challenge_id = %hex_encode(&challenge_id),
            cpw = p.cpw,
            "scheduler: PoS hash challenge issued via mailbox"
        );
    }
}
