// backup-i7: the WARN "cannot load source block for PoS" is written once per day per block,
// on the monotonic clock (never scaled by `time_scale`); the clock is injected.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use viaticum_core::types::SourceBlockId;

use crate::daemon::scheduler::issue::{POS_LOAD_WARN_INTERVAL, should_warn};

const DAY: Duration = Duration::from_secs(86_400);

#[test]
fn pos_load_failure_warns_once_per_day_per_block() {
    let mut map = HashMap::new();
    let (a, b) = (SourceBlockId([1; 32]), SourceBlockId([2; 32]));
    let t0 = Instant::now();

    assert_eq!(POS_LOAD_WARN_INTERVAL, DAY);
    assert!(should_warn(&mut map, a, t0), "the first failure is a WARN");
    // Every tick of the day after it is quiet: a tick each hour, and each minute.
    for minutes in 1..24 * 60 {
        assert!(
            !should_warn(&mut map, a, t0 + Duration::from_secs(minutes * 60)),
            "minute {minutes}: DEBUG, not a WARN"
        );
    }
    assert!(
        !should_warn(&mut map, a, t0 + DAY - Duration::from_secs(1)),
        "one second short of the day"
    );
    // Another block has its own day.
    assert!(should_warn(&mut map, b, t0 + Duration::from_secs(5)));
    assert!(!should_warn(&mut map, b, t0 + Duration::from_secs(6)));
    // The day is over: one WARN again, and its day starts from that moment.
    assert!(should_warn(&mut map, a, t0 + DAY));
    assert!(!should_warn(&mut map, a, t0 + DAY + Duration::from_secs(1)));
    assert!(!should_warn(
        &mut map,
        a,
        t0 + DAY + DAY - Duration::from_secs(1)
    ));
    assert!(should_warn(&mut map, a, t0 + DAY + DAY));
}

#[test]
fn should_warn_drops_entries_that_ran_out() {
    let mut map = HashMap::new();
    let t0 = Instant::now();
    for i in 0..10u8 {
        assert!(should_warn(&mut map, SourceBlockId([i; 32]), t0));
    }
    assert_eq!(map.len(), 10);
    // A day later a WARN for a new block sweeps the ten expired ones.
    assert!(should_warn(&mut map, SourceBlockId([99; 32]), t0 + DAY));
    assert_eq!(map.len(), 1);
}

// The place of the call: what `BlockPrep::run` writes when the source block cannot be loaded.

use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::daemon::scheduler::issue::log_load_failure;

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` and return what it logged at DEBUG and above (this thread only).
fn logged(f: impl FnOnce()) -> String {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    f();
    drop(guard);
    String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
}

fn lines_with(logs: &str, level: &str) -> usize {
    logs.lines()
        .filter(|l| {
            l.contains("cannot load source block for PoS hash")
                && l.split_whitespace().nth(1) == Some(level)
        })
        .count()
}

#[test]
fn load_failure_of_one_block_logs_one_warn_a_day_at_the_call_site() {
    let warned = Mutex::new(HashMap::new());
    let block = SourceBlockId([7; 32]);
    let err = anyhow::anyhow!("source over the size limit");
    let t0 = Instant::now();

    let logs = logged(|| {
        log_load_failure(&warned, block, t0, &err);
        log_load_failure(&warned, block, t0 + Duration::from_secs(60), &err);
        log_load_failure(&warned, block, t0 + DAY - Duration::from_secs(1), &err);
    });
    assert_eq!(lines_with(&logs, "WARN"), 1, "one WARN a day: {logs}");
    assert_eq!(lines_with(&logs, "DEBUG"), 2, "the rest DEBUG: {logs}");
    assert!(logs.contains("source over the size limit"), "{logs}");

    let logs = logged(|| {
        log_load_failure(&warned, block, t0 + DAY, &err);
        log_load_failure(&warned, block, t0 + DAY + Duration::from_secs(5), &err);
    });
    assert_eq!(
        lines_with(&logs, "WARN"),
        1,
        "a day later, one WARN again: {logs}"
    );
    assert_eq!(lines_with(&logs, "DEBUG"), 1, "{logs}");
}
