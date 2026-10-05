// ESI space bookkeeping (repair-i8 ceiling, C-SP §2.6): which blocks are "not repairable"
// and when the worker warns about them.

use std::time::{Duration, Instant};

use viaticum_core::types::SourceBlockId;

use super::{EXHAUSTED_WARN_INTERVAL, EsiSpace, HALF_ESI_SPACE};

fn block(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

#[test]
fn note_plan_when_cut_reports_block_and_warns_once_per_day() {
    let space = EsiSpace::default();
    let t0 = Instant::now();

    let first = space.note_plan(block(1), true, 1 << 24, t0);
    let again = space.note_plan(block(1), true, 1 << 24, t0 + Duration::from_secs(60));
    let next_day = space.note_plan(block(1), true, 1 << 24, t0 + EXHAUSTED_WARN_INTERVAL);

    assert!(first.warned_exhausted);
    assert!(!again.warned_exhausted, "one WARN per block per day");
    assert!(next_day.warned_exhausted);
    assert_eq!(space.exhausted_blocks(), vec![block(1)]);
}

#[test]
fn note_plan_when_not_cut_clears_block() {
    let space = EsiSpace::default();
    let t0 = Instant::now();
    space.note_plan(block(1), true, 1 << 24, t0);
    space.note_plan(block(2), true, 1 << 24, t0);

    let notice = space.note_plan(block(1), false, 1 << 24, t0);

    assert!(!notice.warned_exhausted);
    assert_eq!(space.exhausted_blocks(), vec![block(2)]);
}

#[test]
fn note_plan_warns_past_half_once_per_block() {
    let space = EsiSpace::default();
    let t0 = Instant::now();

    let below = space.note_plan(block(1), false, HALF_ESI_SPACE, t0);
    let past = space.note_plan(block(1), false, HALF_ESI_SPACE + 1, t0);
    let again = space.note_plan(block(1), false, HALF_ESI_SPACE + 9, t0);

    assert!(!below.warned_past_half);
    assert!(past.warned_past_half);
    assert!(!again.warned_past_half);
    assert!(space.exhausted_blocks().is_empty());
}
