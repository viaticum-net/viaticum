use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::daemon::{ProcessorMsg, ScheduledCmd};

// ============================================================
// Constants
// ============================================================

const TICK: Duration = Duration::from_secs(300); // 5 minutes
const WEEKLY: Duration = Duration::from_secs(604_800); // 7 days
const MONTHLY: Duration = Duration::from_secs(2_592_000); // 30 days
const POS_FIRST_OFFSET: Duration = Duration::from_secs(86_400); // 1 day
const REPAIR_FIRST_OFFSET: Duration = Duration::from_secs(172_800); // 2 days

// ============================================================
// run()
// ============================================================

/// Run the scheduler task. Loops until `cancel` is signalled.
/// Checks at every tick whether each scheduled task is due; if so, sends the command.
pub async fn run(cancel: CancellationToken, processor_tx: mpsc::Sender<ProcessorMsg>) {
    let start = Instant::now();

    // Compute initial due instants. Tasks fire after their first-run offset.
    // On restart the cycle resets from the new startup instant.
    let mut weekly_sync_due = start + WEEKLY;
    let mut pos_round_due = start + POS_FIRST_OFFSET;
    let mut repair_check_due = start + REPAIR_FIRST_OFFSET;
    let mut vacuum_due = start + MONTHLY;

    tracing::debug!("scheduler: started");
    tracing::debug!(
        secs = WEEKLY.as_secs(),
        "scheduler: next weekly_sync in"
    );
    tracing::debug!(
        secs = POS_FIRST_OFFSET.as_secs(),
        "scheduler: next pos_round in"
    );
    tracing::debug!(
        secs = REPAIR_FIRST_OFFSET.as_secs(),
        "scheduler: next repair_check in"
    );
    tracing::debug!(
        secs = MONTHLY.as_secs(),
        "scheduler: next vacuum in"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("scheduler: cancelled");
                break;
            }
            _ = tokio::time::sleep(TICK) => {
                let now = Instant::now();
                let mut any_fired = false;

                if now >= weekly_sync_due {
                    send_cmd(&processor_tx, ScheduledCmd::WeeklySync, "weekly_sync").await;
                    weekly_sync_due = now + WEEKLY;
                    any_fired = true;
                }
                if now >= pos_round_due {
                    send_cmd(&processor_tx, ScheduledCmd::PosRound, "pos_round").await;
                    pos_round_due = now + WEEKLY;
                    any_fired = true;
                }
                if now >= repair_check_due {
                    send_cmd(&processor_tx, ScheduledCmd::RepairCheck, "repair_check").await;
                    repair_check_due = now + WEEKLY;
                    any_fired = true;
                }
                if now >= vacuum_due {
                    send_cmd(&processor_tx, ScheduledCmd::Vacuum, "vacuum").await;
                    vacuum_due = now + MONTHLY;
                    any_fired = true;
                }

                if !any_fired {
                    tracing::trace!("scheduler: tick (no tasks due)");
                }
            }
        }
    }

    tracing::debug!("scheduler: stopped");
}

async fn send_cmd(tx: &mpsc::Sender<ProcessorMsg>, cmd: ScheduledCmd, name: &str) {
    tracing::info!(task = name, "scheduler: firing task");
    tx.send(ProcessorMsg::Scheduled(cmd))
        .await
        .unwrap_or_else(|_| panic!("scheduler: processor channel closed for task {name}"));
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;

    use crate::daemon::{ProcessorMsg, ScheduledCmd};

    fn make_channel(cap: usize) -> (mpsc::Sender<ProcessorMsg>, mpsc::Receiver<ProcessorMsg>) {
        mpsc::channel(cap)
    }

    fn drain_cmds(rx: &mut mpsc::Receiver<ProcessorMsg>) -> Vec<ScheduledCmd> {
        let mut cmds = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let ProcessorMsg::Scheduled(cmd) = msg {
                cmds.push(cmd);
            }
        }
        cmds
    }

    // -------------------------------------------------------
    // scheduler_shuts_down_cleanly_on_cancel
    // -------------------------------------------------------

    #[tokio::test]
    async fn scheduler_shuts_down_cleanly_on_cancel() {
        let cancel = CancellationToken::new();
        let (tx, _rx) = make_channel(4);

        let handle = tokio::spawn(super::run(cancel.clone(), tx));

        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok(), "scheduler did not shut down within 1 second");
        result.unwrap().expect("scheduler task panicked");
    }

    // -------------------------------------------------------
    // scheduler_does_not_fire_before_due
    // -------------------------------------------------------
    // After one tick (5 minutes), no task should fire because all tasks have
    // at least a 1-day first-run offset.

    #[tokio::test(start_paused = true)]
    async fn scheduler_does_not_fire_before_due() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        // One tick: 5 minutes + 10 seconds headroom.
        tokio::time::advance(Duration::from_secs(310)).await;
        tokio::task::yield_now().await;

        let cmds = drain_cmds(&mut rx);
        assert!(
            cmds.is_empty(),
            "expected no commands after one tick, got: {cmds:?}"
        );

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_fires_pos_round_before_weekly_sync
    // -------------------------------------------------------
    // PosRound first-run offset = 1 day. WeeklySync first-run offset = 7 days.
    // After 2 days + 1 tick, PosRound fires but WeeklySync does not.

    #[tokio::test(start_paused = true)]
    async fn scheduler_fires_pos_round_before_weekly_sync() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        // Advance past POS_FIRST_OFFSET (1 day) but not WEEKLY (7 days).
        // We need to cross tick boundaries: advance in TICK-sized chunks.
        let target = Duration::from_secs(2 * 24 * 3600); // 2 days
        let ticks = target.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let cmds = drain_cmds(&mut rx);

        let has_pos = cmds.iter().any(|c| matches!(c, ScheduledCmd::PosRound));
        let has_sync = cmds.iter().any(|c| matches!(c, ScheduledCmd::WeeklySync));

        assert!(has_pos, "expected PosRound after 2 days, got: {cmds:?}");
        assert!(!has_sync, "did not expect WeeklySync after only 2 days");

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_fires_weekly_sync_after_seven_days
    // -------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn scheduler_fires_weekly_sync_after_seven_days() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        let target = Duration::from_secs(7 * 24 * 3600 + 60);
        let ticks = target.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let cmds = drain_cmds(&mut rx);

        assert!(
            cmds.iter().any(|c| matches!(c, ScheduledCmd::WeeklySync)),
            "expected WeeklySync after 7 days, got: {cmds:?}"
        );

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_fires_repair_check_after_two_days
    // -------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn scheduler_fires_repair_check_after_two_days() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        let target = Duration::from_secs(2 * 24 * 3600 + 60);
        let ticks = target.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let cmds = drain_cmds(&mut rx);

        assert!(
            cmds.iter().any(|c| matches!(c, ScheduledCmd::RepairCheck)),
            "expected RepairCheck after 2 days, got: {cmds:?}"
        );

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_fires_vacuum_after_thirty_days
    // -------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn scheduler_fires_vacuum_after_thirty_days() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        let target = Duration::from_secs(30 * 24 * 3600 + 60);
        let ticks = target.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let cmds = drain_cmds(&mut rx);

        assert!(
            cmds.iter().any(|c| matches!(c, ScheduledCmd::Vacuum)),
            "expected Vacuum after 30 days, got: {cmds:?}"
        );

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_does_not_fire_vacuum_before_thirty_days
    // -------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn scheduler_does_not_fire_vacuum_before_thirty_days() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(16);

        tokio::spawn(super::run(cancel.clone(), tx));

        // Advance 8 days — weekly tasks fire, vacuum should not.
        let target = Duration::from_secs(8 * 24 * 3600 + 60);
        let ticks = target.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let cmds = drain_cmds(&mut rx);

        assert!(
            !cmds.iter().any(|c| matches!(c, ScheduledCmd::Vacuum)),
            "did not expect Vacuum before 30 days, got: {cmds:?}"
        );

        cancel.cancel();
    }

    // -------------------------------------------------------
    // scheduler_fires_weekly_sync_twice_in_two_periods
    // -------------------------------------------------------
    // After 7 days the weekly task fires once. Advance another 7 days and
    // it fires again. Ensures the due time advances correctly after each fire.

    #[tokio::test(start_paused = true)]
    async fn scheduler_fires_weekly_sync_twice_in_two_periods() {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = make_channel(32);

        tokio::spawn(super::run(cancel.clone(), tx));

        // First period: advance 7 days.
        let period = Duration::from_secs(7 * 24 * 3600 + 60);
        let ticks = period.as_secs() / super::TICK.as_secs() + 1;
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let first = drain_cmds(&mut rx)
            .into_iter()
            .filter(|c| matches!(c, ScheduledCmd::WeeklySync))
            .count();

        // Second period: advance another 7 days.
        for _ in 0..ticks {
            tokio::time::advance(super::TICK + Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let second = drain_cmds(&mut rx)
            .into_iter()
            .filter(|c| matches!(c, ScheduledCmd::WeeklySync))
            .count();

        assert_eq!(first, 1, "expected exactly 1 WeeklySync in first period");
        assert_eq!(second, 1, "expected exactly 1 WeeklySync in second period");

        cancel.cancel();
    }
}
