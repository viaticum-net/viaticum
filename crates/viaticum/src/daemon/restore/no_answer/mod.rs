// restore-i26: a round nobody answered is not a verdict.
//
// Right after `viaticum dr`, or when the owner's Wi-Fi drops for ten seconds in the
// middle of a long restore, every request fails at once: since C4 `send_to_device`
// dials a peer without a live connection, but with the network gone each dial fails
// (`Unreachable`, then the negative cache answers at once) and a holder without a
// usable address is `PeerNotAuthenticated` right away. Without a retry the job would
// give up every remaining block in milliseconds. So when a round of a block's fetch
// gives nothing new and some holder did not answer (`RoundEnd::NoAnswer`, also when
// others answered empty, restore-i33), the coordinator redials the block's holders
// (`RestoreSource::reconnect`), waits, and tries the same fetch again, keeping what
// it already collected.
//
// The pauses are a budget of the JOB, not of a block: `NO_ANSWER_PAUSES_SECS`
// (1, 5, 15 min, divided by `time_scale`), used in order. Only an answer from a
// holder that had gone silent (failed in a `NoAnswer` round) refills it: that
// proves the connection came back (restore-i34). An answer from a holder that never
// went silent does not — else "some holders are dead" would make the budget one per
// block (500 lost blocks × 21 min). Once it is spent, a block whose round gets no
// answer is given up at once (`holders_unavailable`), and so is every later such
// block: with dead holders the whole job waits at most 21 min. A round where every
// holder asked answered and none gave anything new ends the block without a pause,
// as before (restore-i12).
//
// While the job waits, the registry shows until when (`waiting_for_holders_until`),
// so `--status` and the web UI do not look hung (restore-i4). The wait stops on the
// daemon's cancel token (T10).

use std::collections::HashSet;
use std::time::Duration;

use tracing::{info, warn};
use viaticum_core::erasure::Symbol;
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId, SymbolPlacement, Timestamp};

use super::{RestoreCoordinator, RestoreError};
use crate::daemon::restore::staging::JobId;
use crate::daemon::symbol_fetch::{
    BlockFetch, FailedInTask, RESTORE_FETCH_CHUNK_BYTES, RestoreSource, Round, RoundEnd, chunk_esis,
};

#[cfg(test)]
mod tests;

/// The pauses after rounds nobody answered, in order, at `time_scale = 1`
/// (restore-i26). Total 21 min: a job with dead holders gives up after that.
pub(crate) const NO_ANSWER_PAUSES_SECS: [u64; 3] = [60, 5 * 60, 15 * 60];

/// The no-answer pause budget of one restore job.
#[derive(Debug)]
pub(crate) struct NoAnswerPauses {
    job_id: JobId,
    /// `NO_ANSWER_PAUSES_SECS` divided by `time_scale`.
    schedule: Vec<Duration>,
    /// Pauses taken since the budget was last full.
    used: usize,
    /// Holders that failed in a `NoAnswer` round and have not answered since.
    silent: HashSet<DeviceId>,
    /// Holders that did not answer a request in time anywhere in this job: asked last for
    /// the rest of it (restore-i44). Unlike `silent`, an answer does not take a holder out.
    failed_in_job: FailedInTask,
}

impl NoAnswerPauses {
    /// A full budget for `job_id`; pauses are divided by `time_scale` (≥ 1).
    pub(crate) fn new(job_id: JobId, time_scale: u64) -> Self {
        let scale = time_scale.max(1);
        NoAnswerPauses {
            job_id,
            schedule: NO_ANSWER_PAUSES_SECS
                .iter()
                .map(|s| Duration::from_millis(s * 1000 / scale))
                .collect(),
            used: 0,
            silent: HashSet::new(),
            failed_in_job: FailedInTask::default(),
        }
    }

    /// The job this budget belongs to.
    pub(crate) fn job_id(&self) -> JobId {
        self.job_id
    }

    /// The next pause, or `None` when the budget is spent.
    pub(crate) fn take(&mut self) -> Option<Duration> {
        let pause = self.schedule.get(self.used).copied()?;
        self.used += 1;
        Some(pause)
    }

    /// Account one round (restore-i34): a silent holder that answered refills the
    /// budget and is silent no more; the holders that failed in a `NoAnswer` round
    /// become silent. Answers from holders that never went silent change nothing.
    pub(crate) fn observe(&mut self, round: &Round) {
        let mut came_back = false;
        for holder in &round.answered {
            came_back |= self.silent.remove(holder);
        }
        if came_back && self.used > 0 {
            info!(
                job = %self.job_id,
                "restore: a silent holder answered again; pause budget refilled"
            );
        }
        if came_back {
            self.used = 0;
        }
        if round.end == RoundEnd::NoAnswer {
            self.silent.extend(round.failed.iter().copied());
        }
    }
}

impl RestoreCoordinator {
    /// Fetch symbols for a source block from holders over the network: chunked
    /// requests in rounds, no deadline (restore-i12); a round with nothing new and a
    /// holder that did not answer is retried after a redial and a pause from the
    /// job's budget (restore-i26, i33, i34);
    /// abandoned on the daemon's cancel token (T10).
    pub(crate) async fn fetch_from_holders(
        &self,
        block_id: &SourceBlockId,
        placements: &[SymbolPlacement],
        params: &ErasureParams,
        pauses: &mut NoAnswerPauses,
    ) -> Result<Vec<Symbol>, RestoreError> {
        // Without a symbol source no holder is reachable: InsufficientSymbols(got=0).
        let Some(source) = self.config.symbols.as_ref() else {
            return Err(RestoreError::InsufficientSymbols {
                block: *block_id,
                got: 0,
                need: params.k_eff as usize,
            });
        };
        let cancel = &self.config.cancel;
        let chunk = chunk_esis(RESTORE_FETCH_CHUNK_BYTES, params.t);
        let mut fetch = BlockFetch::new(&self.encoder, block_id, placements, params, chunk)
            .in_task(&pauses.failed_in_job);
        loop {
            let round = fetch
                .round(source.as_ref(), Some(cancel))
                .await
                .map_err(RestoreError::from_fetch)?;
            pauses.observe(&round);
            match round.end {
                RoundEnd::Progress => {}
                RoundEnd::Complete | RoundEnd::NothingNew | RoundEnd::NobodyToAsk => break,
                RoundEnd::NoAnswer => {
                    let Some(pause) = pauses.take() else {
                        warn!(
                            job = %pauses.job_id,
                            block = %block_id,
                            have = fetch.have(),
                            need = params.k_eff,
                            "restore: holders did not answer and this job's pauses are spent; \
                             block given up"
                        );
                        break;
                    };
                    info!(
                        job = %pauses.job_id,
                        block = %block_id,
                        have = fetch.have(),
                        need = params.k_eff,
                        pause_secs = pause.as_secs_f64(),
                        "restore: holders did not answer; redialing them and retrying after a pause"
                    );
                    self.redial_and_wait(source.as_ref(), &fetch, pause, pauses.job_id)
                        .await?;
                }
            }
        }
        fetch.finish().map_err(RestoreError::from_fetch)
    }

    /// One redial of the block's holders, then `pause`, shown in the job's
    /// progress. Both stop on the daemon's cancel token (→ `Cancelled`).
    async fn redial_and_wait(
        &self,
        source: &dyn RestoreSource,
        fetch: &BlockFetch<'_>,
        pause: Duration,
        job_id: JobId,
    ) -> Result<(), RestoreError> {
        let cancel = &self.config.cancel;
        let holders = fetch.holder_ids();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RestoreError::Cancelled),
            _ = source.reconnect(&holders) => {}
        }
        let until = Timestamp::now().0 + pause.as_secs_f64().ceil() as u64;
        self.config.jobs.set_waiting(job_id, Some(until));
        let woke = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(RestoreError::Cancelled),
            _ = tokio::time::sleep(pause) => Ok(()),
        };
        self.config.jobs.set_waiting(job_id, None);
        woke
    }
}
