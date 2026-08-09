// Tests for the 4R pair-ledger recorder (У-2).
//
// Acceptance criteria (spec: private/beta-planning/tasks/pair_ledger.md):
//   AC-1  accrual is the kernel, bit for bit (a SEQUENCE of steps when sub-stepping).
//   AC-2′ the clock decides the contribution, not the number of ticks; the decay covers
//         every elapsed day while the measured volume only charges the OBSERVED tail
//         (Д-A); skipping ticks inside that tail stays within a bound derived from the
//         Euler scheme, never a tuned epsilon.
//   AC-7  the daemon decides nothing differently — covered by the absence of decision
//         readers and by the untouched expectations of every pre-existing test.

use super::{
    AccrualStats, PairLedgerRecorder, Volumes, accrue, accrue_interval, observed_window_days,
    sub_steps, tick_interval_secs,
};
use crate::constants::{
    BYTES_PER_GB, PAIR_LEDGER_LAMBDA, PAIR_LEDGER_LAMBDA_SLOW, PAIR_LEDGER_OBSERVED_WINDOW_TICKS,
    PAIR_LEDGER_TICK_SECS,
};
use crate::db::Db;
use crate::db::testutil::test_db;
use crate::four_r::{update_capital, update_depth};
use crate::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, PairLedger, PeerRecord, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

// ── Fixtures ────────────────────────────────────────────────────────────────

const DAY: u64 = 86_400;
/// One on-schedule tick at `time_scale = 1`, where real and scaled seconds coincide.
/// Anywhere a test drives another scale it must ask [`tick_interval_secs`] instead — the
/// scheduler's timer is `(3600/scale).max(1)` REAL seconds and that is not `3600/scale`
/// scaled seconds once the floor bites (BLOCK-1).
const TICK: u64 = PAIR_LEDGER_TICK_SECS;
/// The observed window at `time_scale = 1`: 3 tick periods = 3 h = 0.125 d.
fn real_time_window() -> f64 {
    observed_window_days(1)
}
/// `t × symbol_count` chosen so one placement is EXACTLY one gibibyte (2^15 × 2^15 = 2^30),
/// keeping every expected value in the tests an exact binary fraction.
const T_BYTES: u16 = 32_768;
const SYMBOLS_PER_GB: u32 = 32_768;

fn master(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn device(seed: u8) -> DeviceId {
    DeviceId([seed; 32])
}

fn my_master() -> IdentityPub {
    master(0x01)
}

fn vol(they_store_for_us: f64, we_store_for_them: f64) -> Volumes {
    Volumes {
        they_store_for_us,
        we_store_for_them,
    }
}

fn peer_of(dev: DeviceId, m: IdentityPub) -> PeerRecord {
    PeerRecord {
        device_id: dev,
        master_identity: m,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

/// Record that `holder` keeps `gb` gibibytes of ours alive (owner-side view).
fn peer_stores_for_us(db: &Db, block_seed: u8, holder: DeviceId, gb: u32) {
    placement_in_status(db, block_seed, holder, gb, PlacementStatus::Alive);
}

/// The same, in an arbitrary placement status — for checking what the volume queries
/// EXCLUDE.
fn placement_in_status(
    db: &Db,
    block_seed: u8,
    holder: DeviceId,
    gb: u32,
    status: PlacementStatus,
) {
    let block = SourceBlockRecord {
        block_id: SourceBlockId([block_seed; 32]),
        k: 10,
        t: T_BYTES,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&block).unwrap();
    db.upsert_placement(&SymbolPlacement {
        source_block_id: block.block_id,
        holder_id: holder,
        file_id: crate::types::FileId(1),
        esi_ranges: vec![(0, SYMBOLS_PER_GB * gb)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    })
    .unwrap();
}

/// Record that WE keep `gb` gibibytes of `owner`'s data (holder-side view).
fn we_store_for(db: &Db, block_seed: u8, owner: IdentityPub, gb: u64) {
    holding_in_status(db, block_seed, owner, gb, HoldingStatus::Active);
}

/// The same, in an arbitrary holding status — for checking what the volume queries EXCLUDE.
fn holding_in_status(db: &Db, block_seed: u8, owner: IdentityPub, gb: u64, status: HoldingStatus) {
    db.upsert_holding(&HoldingRecord {
        source_block_id: SourceBlockId([block_seed; 32]),
        owner_id: owner,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: gb * (BYTES_PER_GB as u64),
        status,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
}

fn ledger_at(they_store: f64, we_store: f64, depth: f64, last_update: Option<u64>) -> PairLedger {
    PairLedger {
        gb_days_they_store_for_us: they_store,
        gb_days_we_store_for_them: we_store,
        depth_of_their_service: depth,
        last_update: last_update.map(Timestamp),
        ..PairLedger::default()
    }
}

// ── AC-1: the accrual IS the kernel ─────────────────────────────────────────

#[test]
fn accrual_equals_the_kernel_step_for_an_interval_that_needs_no_sub_step() {
    let mut ledger = ledger_at(11.0, 22.0, 33.0, None);
    let volumes = vol(3.0, 5.0);
    let dt = 7.0;

    accrue(&mut ledger, &volumes, dt);

    // Bit-for-bit, not "close to": the recorder must BE update_capital, so that a series
    // recorded in the field is comparable with a kernel/sim run without a fudge factor.
    assert_eq!(
        ledger.gb_days_they_store_for_us,
        update_capital(11.0, volumes.they_store_for_us, PAIR_LEDGER_LAMBDA, dt)
    );
    assert_eq!(
        ledger.gb_days_we_store_for_them,
        update_capital(22.0, volumes.we_store_for_them, PAIR_LEDGER_LAMBDA, dt)
    );
    assert_eq!(
        ledger.depth_of_their_service,
        update_depth(33.0, volumes.they_store_for_us, dt, PAIR_LEDGER_LAMBDA_SLOW)
    );
}

#[test]
fn accrual_equals_the_kernel_sequence_when_the_interval_needs_sub_steps() {
    // 90 days at λ=1/60 is λΔt = 1.5: a single Euler step is already outside the monotone
    // region, so the recorder must split. The expectation is the SEQUENCE, computed here
    // with the same kernel calls in the same order.
    let mut ledger = ledger_at(100.0, 200.0, 300.0, None);
    let volumes = vol(2.0, 4.0);
    let dt = 90.0;
    let plan = sub_steps(dt);
    assert_eq!(
        (plan.count, plan.step_days),
        (3, 30.0),
        "90 days → 3 × 30-day sub-steps"
    );

    accrue(&mut ledger, &volumes, dt);

    let (mut they, mut we, mut depth) = (100.0_f64, 200.0_f64, 300.0_f64);
    for _ in 0..plan.count {
        they = update_capital(
            they,
            volumes.they_store_for_us,
            PAIR_LEDGER_LAMBDA,
            plan.step_days,
        );
        we = update_capital(
            we,
            volumes.we_store_for_them,
            PAIR_LEDGER_LAMBDA,
            plan.step_days,
        );
        depth = update_depth(
            depth,
            volumes.they_store_for_us,
            plan.step_days,
            PAIR_LEDGER_LAMBDA_SLOW,
        );
    }
    assert_eq!(ledger.gb_days_they_store_for_us, they);
    assert_eq!(ledger.gb_days_we_store_for_them, we);
    assert_eq!(ledger.depth_of_their_service, depth);
}

#[test]
fn sub_steps_keep_lambda_dt_inside_the_stability_margin_and_cover_the_whole_interval() {
    for dt in [
        0.001, 1.0, 29.999, 30.0, 30.001, 42.0, 90.0, 365.0, 4_200.0, 100_000.0,
    ] {
        let plan = sub_steps(dt);
        assert!(plan.count >= 1, "dt={dt}: at least one step");
        assert!(
            PAIR_LEDGER_LAMBDA * plan.step_days <= 0.5 + 1e-12,
            "dt={dt}: λ·step={} exceeds the margin",
            PAIR_LEDGER_LAMBDA * plan.step_days
        );
        assert_eq!(plan.uncovered_days, 0.0, "dt={dt}: nothing may be dropped");
        let covered = plan.count as f64 * plan.step_days;
        assert!(
            (covered - dt).abs() <= 1e-9 * dt.max(1.0),
            "dt={dt}: steps must tile the interval exactly, got {covered}"
        );
    }
}

#[test]
fn a_long_outage_accrues_the_decay_instead_of_inverting_the_capital() {
    // The failure this exists to prevent: a daemon down for three months comes back and,
    // in ONE kernel step, is handed a large NEGATIVE capital for a pair that stopped
    // storing. Sub-stepping turns that into the honest exponential decay.
    let naive_single_step = update_capital(100.0, 0.0, PAIR_LEDGER_LAMBDA, 90.0);
    assert!(
        naive_single_step < 0.0,
        "premise: one 90-day step inverts the sign (got {naive_single_step})"
    );

    let mut ledger = ledger_at(100.0, 0.0, 0.0, None);
    accrue(&mut ledger, &vol(0.0, 0.0), 90.0);

    // 3 × (1 − 0.5) = 1/8 of the capital survives; positive, monotone, no inversion.
    assert_eq!(ledger.gb_days_they_store_for_us, 12.5);
}

#[test]
fn an_absurd_interval_stops_on_the_steady_state_and_reports_what_it_did_not_cover() {
    // A corrupt `last_update` (or a wildly accelerated run) must not hang the tick. The
    // step ceiling is reached only far past convergence, so stopping there is exact — but
    // the days beyond it are reported rather than silently dropped (N-3).
    let mut ledger = ledger_at(0.0, 0.0, 0.0, None);
    let v = 3.0;
    let dt = 1.0e12;

    let uncovered = accrue(&mut ledger, &vol(v, v), dt);

    let g_star = v / PAIR_LEDGER_LAMBDA;
    let d_star = v / PAIR_LEDGER_LAMBDA_SLOW;
    assert!(
        (ledger.gb_days_they_store_for_us - g_star).abs() < 1e-9,
        "capital must sit on G* = V/λ, got {}",
        ledger.gb_days_they_store_for_us
    );
    assert!(
        (ledger.depth_of_their_service - d_star).abs() < 1e-9,
        "depth must sit on D* = V/λ_slow, got {}",
        ledger.depth_of_their_service
    );
    assert!(
        uncovered > 0.0,
        "the ceiling bit, so the shortfall must be visible to the caller"
    );
    assert!(
        (uncovered - (dt - 3_000_000.0)).abs() < 1.0,
        "100k sub-steps of 30 days cover 3M days; the rest is uncovered, got {uncovered}"
    );
}

// ── AC-2′ / Д-A: the clock decides, and only the observed tail is charged ────

/// Accrue `total_days` in `calls` equal ticks — "the daemon woke up `calls` times".
fn split_accrual(calls: u32, total_days: f64, v: f64) -> f64 {
    let mut ledger = PairLedger::default();
    for _ in 0..calls {
        accrue(&mut ledger, &vol(v, 0.0), total_days / calls as f64);
    }
    ledger.gb_days_they_store_for_us
}

/// The bound derived in the spec BEFORE running anything: for constant `v` over horizon
/// `T` with `λT ≤ 1`, any two step counts differ by at most `|g₀ − g*|·(λT)²/2`.
fn euler_spread_bound(g0: f64, v: f64, total_days: f64) -> f64 {
    let g_star = v / PAIR_LEDGER_LAMBDA;
    let lambda_t = PAIR_LEDGER_LAMBDA * total_days;
    assert!(lambda_t <= 1.0, "the bound is only claimed for λT ≤ 1");
    (g0 - g_star).abs() * lambda_t * lambda_t / 2.0
}

#[test]
fn skipping_ticks_stays_within_the_pre_derived_euler_bound() {
    let (total_days, v) = (15.0, 2.0);
    let bound = euler_spread_bound(0.0, v, total_days);

    let once = split_accrual(1, total_days, v);
    let hundred = split_accrual(100, total_days, v);

    assert!(
        (once - hundred).abs() <= bound,
        "one tick vs a hundred over the same {total_days} days differ by {}, bound {bound}",
        (once - hundred).abs()
    );
    // And the sign is the known over-relaxation of the coarse step, not a lost contribution.
    assert!(
        once > hundred,
        "the coarse step must overshoot TOWARDS G*, not fall short"
    );
}

#[test]
fn every_tick_cadence_over_one_horizon_lands_inside_a_single_bound_width() {
    let (total_days, v) = (15.0, 2.0);
    let bound = euler_spread_bound(0.0, v, total_days);

    let results: Vec<f64> = [1, 2, 3, 5, 8, 13, 21, 34, 55, 100]
        .into_iter()
        .map(|calls| split_accrual(calls, total_days, v))
        .collect();
    let lo = results.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = results.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    assert!(
        hi - lo <= bound,
        "cadence spread {} exceeds the derived bound {bound}",
        hi - lo
    );
}

#[test]
fn an_interval_inside_the_observed_window_is_charged_in_full() {
    // The ordinary case: the tick fired roughly on time, so everything it spans is
    // vouched for by the volumes read at its end.
    let mut charged = PairLedger::default();
    let mut whole = PairLedger::default();
    let dt = real_time_window();

    let outcome = accrue_interval(&mut charged, &vol(4.0, 6.0), dt, real_time_window());
    accrue(&mut whole, &vol(4.0, 6.0), dt);

    assert_eq!(outcome.unobserved_days, 0.0);
    assert_eq!(
        charged, whole,
        "no split, no difference from a plain accrual"
    );
}

#[test]
fn the_observed_window_spans_several_tick_periods_so_ordinary_jitter_is_charged_in_full() {
    // The accrual shares the scheduler's select! loop with awaited PoS work, so a tick can
    // slip a period or two under load. That is not an outage and must not be charged as
    // one; only a gap longer than the window is.
    let window = real_time_window();
    let one_tick = TICK as f64 / DAY as f64;

    assert!(
        window >= 2.0 * one_tick,
        "a window of {window} days must absorb at least two missed ticks ({one_tick} d each)"
    );
    let mut ledger = PairLedger::default();
    let outcome = accrue_interval(&mut ledger, &vol(1.0, 0.0), 2.0 * one_tick, window);
    assert_eq!(outcome.unobserved_days, 0.0);
}

#[test]
fn an_unobserved_gap_is_charged_as_decay_and_only_its_tail_carries_volume() {
    // Д-A. The volumes are read AFTER the gap, so they are evidence about the tail only.
    // Charging the whole week would write a number the model never produces: the sim
    // accrues volume·dt only on an observed tick and decays unconditionally.
    let window = real_time_window();
    let mut ledger = ledger_at(50.0, 0.0, 500.0, None);
    let mut expected = ledger.clone();

    let outcome = accrue_interval(&mut ledger, &vol(10.0, 0.0), 7.0, window);

    // Oldest first: the dark stretch decays the old capital, then the observed tail charges.
    accrue(&mut expected, &vol(0.0, 0.0), 7.0 - window);
    accrue(&mut expected, &vol(10.0, 0.0), window);
    assert_eq!(ledger, expected);
    assert!((outcome.unobserved_days - (7.0 - window)).abs() < 1e-12);
    assert!(
        ledger.gb_days_they_store_for_us < 50.0,
        "a week without a single confirmation must LOSE capital, not gain a week of it"
    );
}

#[test]
fn the_unobserved_gap_decays_every_axis_including_the_depth() {
    let window = real_time_window();
    let mut ledger = ledger_at(40.0, 80.0, 900.0, None);

    accrue_interval(&mut ledger, &vol(0.0, 0.0), 30.0 + window, window);

    assert!(ledger.gb_days_they_store_for_us < 40.0);
    assert!(ledger.gb_days_we_store_for_them < 80.0);
    assert!(
        ledger.depth_of_their_service < 900.0,
        "the slow axis leaks through an outage too, only slower"
    );
}

#[test]
fn charging_the_gap_before_decaying_it_would_have_given_a_different_answer() {
    // Guards the ORDER, which is the part that is easy to get wrong and impossible to see
    // afterwards: the dark stretch happened first, so it must decay the capital that
    // existed then, not the capital the observed tail just added.
    let window = real_time_window();
    let mut oldest_first = ledger_at(0.0, 0.0, 0.0, None);
    let mut newest_first = ledger_at(0.0, 0.0, 0.0, None);

    accrue_interval(&mut oldest_first, &vol(20.0, 0.0), 40.0, window);
    accrue(&mut newest_first, &vol(20.0, 0.0), window);
    accrue(&mut newest_first, &vol(0.0, 0.0), 40.0 - window);

    assert!(
        oldest_first.gb_days_they_store_for_us > newest_first.gb_days_they_store_for_us,
        "charging the tail last must leave it undecayed: {} vs {}",
        oldest_first.gb_days_they_store_for_us,
        newest_first.gb_days_they_store_for_us
    );
}

#[test]
fn a_second_tick_at_the_same_instant_accrues_nothing() {
    let db = test_db();
    let them = master(0x20);
    db.upsert_peer(&peer_of(device(0x21), them)).unwrap();
    we_store_for(&db, 0x22, them, 4);
    let recorder = PairLedgerRecorder::new(db.clone());
    let now = Timestamp(10 * DAY);

    recorder.tick(&my_master(), Timestamp(3 * DAY), 1).unwrap();
    recorder.tick(&my_master(), now, 1).unwrap();
    let after_first = db.get_pair_ledger(&them).unwrap().unwrap();
    let stats = recorder.tick(&my_master(), now, 1).unwrap();
    let after_second = db.get_pair_ledger(&them).unwrap().unwrap();

    assert_eq!(
        after_first, after_second,
        "a clock that did not move accrues nothing"
    );
    assert_eq!(
        stats,
        AccrualStats {
            idle: 1,
            ..AccrualStats::default()
        }
    );
}

#[test]
fn a_tick_after_a_week_of_downtime_decays_the_week_and_charges_only_the_observed_tail() {
    // AC-2′(a) as re-stated by Д-A: the contribution is set by the clock, but the volume
    // read on return only vouches for the observed window.
    let db = test_db();
    let them = master(0x30);
    db.upsert_peer(&peer_of(device(0x31), them)).unwrap();
    we_store_for(&db, 0x32, them, 2);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    let stats = recorder.tick(&my_master(), Timestamp(7 * DAY), 1).unwrap();

    let window = real_time_window();
    let mut expected = PairLedger::default();
    accrue(&mut expected, &vol(0.0, 0.0), 7.0 - window);
    accrue(&mut expected, &vol(0.0, 2.0), window);
    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    assert_eq!(
        stored.gb_days_we_store_for_them, expected.gb_days_we_store_for_them,
        "a week nobody watched is decay plus the observed tail, not a week of service"
    );
    assert_eq!(stored.last_update, Some(Timestamp(7 * DAY)));
    assert_eq!(
        stats,
        AccrualStats {
            accrued: 1,
            with_unobserved_gap: 1,
            ..AccrualStats::default()
        }
    );
}

#[test]
fn an_on_schedule_tick_reports_no_unobserved_gap() {
    let db = test_db();
    let them = master(0x35);
    db.upsert_peer(&peer_of(device(0x36), them)).unwrap();
    we_store_for(&db, 0x37, them, 2);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    let stats = recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    assert_eq!(
        stats,
        AccrualStats {
            accrued: 1,
            ..AccrualStats::default()
        }
    );
    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    let mut expected = PairLedger::default();
    accrue(&mut expected, &vol(0.0, 2.0), TICK as f64 / DAY as f64);
    assert_eq!(
        stored.gb_days_we_store_for_them,
        expected.gb_days_we_store_for_them
    );
}

#[test]
fn the_first_tick_seeds_the_clock_without_integrating() {
    let db = test_db();
    let them = master(0x40);
    db.upsert_peer(&peer_of(device(0x41), them)).unwrap();
    we_store_for(&db, 0x42, them, 9);

    let stats = PairLedgerRecorder::new(db.clone())
        .tick(&my_master(), Timestamp(5 * DAY), 1)
        .unwrap();

    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    assert_eq!(
        stored,
        ledger_at(0.0, 0.0, 0.0, Some(5 * DAY)),
        "there is no interval to integrate over yet — only the clock starts"
    );
    assert_eq!(
        stats,
        AccrualStats {
            seeded: 1,
            ..AccrualStats::default()
        }
    );
}

#[test]
fn a_backward_clock_jump_leaves_the_ledger_untouched() {
    let db = test_db();
    let them = master(0x50);
    db.upsert_peer(&peer_of(device(0x51), them)).unwrap();
    we_store_for(&db, 0x52, them, 1);
    let recorder = PairLedgerRecorder::new(db.clone());
    recorder
        .tick(&my_master(), Timestamp(100 * DAY), 1)
        .unwrap();
    recorder
        .tick(&my_master(), Timestamp(110 * DAY), 1)
        .unwrap();
    let before = db.get_pair_ledger(&them).unwrap().unwrap();

    // NTP steps the clock back a day.
    let stats = recorder
        .tick(&my_master(), Timestamp(109 * DAY), 1)
        .unwrap();

    assert_eq!(
        db.get_pair_ledger(&them).unwrap().unwrap(),
        before,
        "a negative interval must not discharge the integrator"
    );
    assert_eq!(stats.idle, 1);
    assert_eq!(
        before.last_update,
        Some(Timestamp(110 * DAY)),
        "and the clock must not be rewound either"
    );
}

// ── Which volume charges which axis ─────────────────────────────────────────

#[test]
fn the_they_store_axis_is_charged_by_what_all_devices_of_the_master_store_for_us() {
    // Р3: the ledger is per-MASTER while placements are per-DEVICE. Charging the row with
    // one device's number would under-count the axis by however many machines the peer runs.
    let db = test_db();
    let them = master(0x60);
    db.upsert_peer(&peer_of(device(0x61), them)).unwrap();
    db.upsert_peer(&peer_of(device(0x62), them)).unwrap();
    peer_stores_for_us(&db, 0x63, device(0x61), 3);
    peer_stores_for_us(&db, 0x64, device(0x62), 5);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    let mut expected = PairLedger::default();
    accrue(&mut expected, &vol(8.0, 0.0), TICK as f64 / DAY as f64);
    assert_eq!(
        stored.gb_days_they_store_for_us, expected.gb_days_they_store_for_us,
        "both devices of the person must charge the one row (3 + 5 gb)"
    );
}

#[test]
fn the_we_store_axis_is_charged_by_what_we_store_for_the_master() {
    let db = test_db();
    let them = master(0x70);
    db.upsert_peer(&peer_of(device(0x71), them)).unwrap();
    we_store_for(&db, 0x72, them, 6);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    let mut expected = PairLedger::default();
    accrue(&mut expected, &vol(0.0, 6.0), TICK as f64 / DAY as f64);
    assert_eq!(
        stored.gb_days_we_store_for_them,
        expected.gb_days_we_store_for_them
    );
    assert_eq!(
        stored.gb_days_they_store_for_us, 0.0,
        "holdings we keep must not leak into the axis about THEIR service"
    );
}

#[test]
fn the_depth_is_charged_by_the_peers_service_to_us_and_not_by_ours_to_them() {
    // The κ_O reciprocity key is `kappa_key(g, D)` where BOTH terms are "this owner served
    // ME, the holder" (four_r/mod.rs:338-340, and 697-703 "this is the direction the old
    // doc comment inverted"; sim engine.rs:1884-1886 charges g_ho and depth_ho with the
    // SAME accrual, engine.rs:1972-1979 reads both from that cell). A depth charged by our
    // OWN service would make the loyalty floor read "I keep your data because I have
    // already kept your data".
    let db = test_db();
    let they_serve_us = master(0x80);
    let we_serve_them = master(0x90);
    db.upsert_peer(&peer_of(device(0x81), they_serve_us))
        .unwrap();
    db.upsert_peer(&peer_of(device(0x91), we_serve_them))
        .unwrap();
    peer_stores_for_us(&db, 0x82, device(0x81), 4);
    we_store_for(&db, 0x92, we_serve_them, 4);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    let dt = TICK as f64 / DAY as f64;
    let served_by_them = db.get_pair_ledger(&they_serve_us).unwrap().unwrap();
    let served_by_us = db.get_pair_ledger(&we_serve_them).unwrap().unwrap();
    assert_eq!(
        served_by_them.depth_of_their_service,
        update_depth(0.0, 4.0, dt, PAIR_LEDGER_LAMBDA_SLOW),
        "the pair that keeps OUR data alive builds loyalty depth"
    );
    assert_eq!(
        served_by_us.depth_of_their_service, 0.0,
        "storing FOR someone must not build depth about them"
    );
    assert!(
        served_by_us.gb_days_we_store_for_them > 0.0,
        "premise: that pair did accrue on the other axis"
    );
}

#[test]
fn the_we_store_axis_first_step_matches_the_existing_gb_day_sum_over_the_same_holdings() {
    // W-3: the recorder's gigabyte and day must be the ones `stored_for_peer_gb_days`
    // already uses, or the new series compares to nothing. Over one observed hour of a
    // holding received at t0, both must produce the same gb·days.
    let db = test_db();
    let them = master(0xA0);
    db.upsert_peer(&peer_of(device(0xA1), them)).unwrap();
    we_store_for(&db, 0xA2, them, 7);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    let existing = db
        .stored_for_peer_gb_days(&them, Timestamp(TICK), 1)
        .unwrap();
    assert!(
        (existing - 7.0 / 24.0).abs() < 1e-12,
        "premise: 7 gb held for exactly an hour, got {existing}"
    );
    assert_eq!(
        stored.gb_days_we_store_for_them, existing,
        "same gigabyte (2^30) and same day as the existing gb·day sums"
    );
}

// ── Sweep shape: who gets a row ─────────────────────────────────────────────

#[test]
fn our_own_master_never_gets_a_ledger_row() {
    // Cluster siblings are ordinary PEERS rows carrying OUR master identity. Without the
    // guard the sweep would open an economic ledger of ourselves against ourselves.
    let db = test_db();
    db.upsert_peer(&peer_of(device(0xB1), my_master())).unwrap();
    db.upsert_peer(&peer_of(device(0xB2), master(0xB0)))
        .unwrap();

    PairLedgerRecorder::new(db.clone())
        .tick(&my_master(), Timestamp(DAY), 1)
        .unwrap();

    let keys: Vec<IdentityPub> = db
        .list_pair_ledgers()
        .unwrap()
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    assert_eq!(keys, vec![master(0xB0)]);
}

#[test]
fn a_peer_whose_master_is_still_the_zero_placeholder_never_gets_a_ledger_row() {
    // WARN-2. `IdentityPub([0; 32])` is the "master unknown" marker left by the deprecated
    // `TrustEngine::upsert_peer` and by peer rows written before a DeviceCertExchange; DR
    // repairs such rows on re-authentication (CS-DR-12), which is proof they occur in live
    // databases. Without the guard every unidentified device folds into ONE "zero person"
    // whose ledger is the sum of unrelated strangers' storage.
    let db = test_db();
    let unknown = IdentityPub([0u8; 32]);
    db.upsert_peer(&peer_of(device(0xB3), unknown)).unwrap();
    db.upsert_peer(&peer_of(device(0xB4), unknown)).unwrap();
    peer_stores_for_us(&db, 0xB5, device(0xB3), 3);
    peer_stores_for_us(&db, 0xB6, device(0xB4), 5);
    let recorder = PairLedgerRecorder::new(db.clone());

    recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
    let stats = recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();

    assert!(db.list_pair_ledgers().unwrap().is_empty());
    assert_eq!(stats, AccrualStats::default());
    assert_eq!(
        db.bytes_master_stores_for_us(&unknown).unwrap(),
        0,
        "and the point query must not fold them together either"
    );
}

#[test]
fn a_master_with_many_devices_gets_exactly_one_row() {
    let db = test_db();
    let them = master(0xC0);
    for seed in [0xC1u8, 0xC2, 0xC3] {
        db.upsert_peer(&peer_of(device(seed), them)).unwrap();
    }

    let stats = PairLedgerRecorder::new(db.clone())
        .tick(&my_master(), Timestamp(DAY), 1)
        .unwrap();

    assert_eq!(db.list_pair_ledgers().unwrap().len(), 1);
    assert_eq!(stats.seeded, 1, "the economic pair is the person");
}

#[test]
fn a_node_with_no_peers_writes_nothing() {
    let db = test_db();

    let stats = PairLedgerRecorder::new(db.clone())
        .tick(&my_master(), Timestamp(DAY), 1)
        .unwrap();

    assert_eq!(stats, AccrualStats::default());
    assert!(db.list_pair_ledgers().unwrap().is_empty());
}

#[test]
fn the_sweep_and_the_point_queries_report_the_same_volumes() {
    // Д-C replaced the per-master queries inside the tick with one pass per table, and
    // kept the per-master ones for point lookups. Two implementations of one formula drift
    // unless something compares them.
    //
    // The fixture is deliberately NOT all-`Alive`/all-`Active` (N-4): both implementations
    // filter by status, and a filter that drifts on one side only shows up if something
    // that must be excluded is present. `PresumedLost` and `MarkedForDelete` are the two
    // states an ordinary node really accumulates.
    let db = test_db();
    let a = master(0xF0);
    let b = master(0xF1);
    db.upsert_peer(&peer_of(device(0xF2), a)).unwrap();
    db.upsert_peer(&peer_of(device(0xF3), a)).unwrap();
    db.upsert_peer(&peer_of(device(0xF4), b)).unwrap();
    peer_stores_for_us(&db, 0xF5, device(0xF2), 3);
    peer_stores_for_us(&db, 0xF6, device(0xF3), 5);
    peer_stores_for_us(&db, 0xF7, device(0xF4), 2);
    we_store_for(&db, 0xF8, a, 11);
    we_store_for(&db, 0xF9, b, 13);
    placement_in_status(&db, 0xFA, device(0xF2), 7, PlacementStatus::PresumedLost);
    holding_in_status(&db, 0xFB, a, 17, HoldingStatus::MarkedForDelete);

    let sweep = db.storage_bytes_by_master().unwrap();

    assert_eq!(sweep.len(), 2);
    let a_row = sweep.iter().find(|r| r.master == a).expect("row for a");
    assert_eq!(
        a_row.they_store_for_us,
        8 * BYTES_PER_GB as u64,
        "the PresumedLost placement must not be counted by the sweep"
    );
    assert_eq!(
        a_row.we_store_for_them,
        11 * BYTES_PER_GB as u64,
        "nor the MarkedForDelete holding"
    );
    for row in sweep {
        assert_eq!(
            row.they_store_for_us,
            db.bytes_master_stores_for_us(&row.master).unwrap(),
            "sweep vs point query disagree for {:?}",
            row.master
        );
        assert_eq!(
            row.we_store_for_them,
            db.bytes_we_store_for_master(&row.master).unwrap(),
            "sweep vs point query disagree for {:?}",
            row.master
        );
    }
}

// ── Д1: the accelerated calendar ────────────────────────────────────────────

#[test]
fn time_scale_advances_the_ledger_on_the_simulated_calendar() {
    // Without this, an accelerated run (E2E uses time_scale = 1000) would accrue 1/1000 of
    // the history its own timers and gb·day sums are living on — and "check that the
    // accounting actually accumulated" is verified exactly there. The daemon's ledger timer
    // is divided by the scale too, so the tick below is the on-schedule one at scale 1000:
    // `(3600/1000).max(1)` = 3 real seconds, integer division and NOT 3.6.
    let db = test_db();
    let them = master(0xD0);
    db.upsert_peer(&peer_of(device(0xD1), them)).unwrap();
    we_store_for(&db, 0xD2, them, 1);
    let recorder = PairLedgerRecorder::new(db.clone());
    let tick = tick_interval_secs(1000);
    assert_eq!(tick, 3, "premise: the scheduler's period at scale 1000");

    recorder.tick(&my_master(), Timestamp(0), 1000).unwrap();
    let stats = recorder.tick(&my_master(), Timestamp(tick), 1000).unwrap();

    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    let mut expected = PairLedger::default();
    let scaled_days = tick as f64 * 1000.0 / DAY as f64;
    accrue(&mut expected, &vol(0.0, 1.0), scaled_days);
    assert_eq!(
        stored.gb_days_we_store_for_them,
        expected.gb_days_we_store_for_them
    );
    assert_eq!(
        stats.with_unobserved_gap, 0,
        "an on-schedule tick is fully observed at scale 1000"
    );
    // The same three seconds on the real calendar would be a thousand times less.
    assert!(
        (stored.gb_days_we_store_for_them - scaled_days).abs() < 1e-12,
        "got {}",
        stored.gb_days_we_store_for_them
    );
}

#[test]
fn the_observed_window_is_three_tick_periods_at_every_time_scale() {
    // BLOCK-1 (third gate). The window is compared against an ALREADY-scaled interval, so
    // it must not be scaled a second time — but neither is it a fixed number of seconds:
    // the scheduler's period is `(3600/scale).max(1)` REAL seconds, so one tick spans
    // `max(1, 3600/scale)·scale` SCALED seconds, which stops being 3600 above scale 3600.
    // A window frozen at 3·3600 scaled seconds degenerated exactly there: at scale 100_000
    // (used by experiments/local_delete_test.sh and local_pos_repair_test.sh) it would have
    // covered 10.8 % of every on-schedule tick.
    for scale in [1u64, 2, 1000, 3600, 3601, 10_800, 100_000, 1_000_000] {
        let tick_scaled = tick_interval_secs(scale) as f64 * scale as f64;
        assert_eq!(
            observed_window_days(scale),
            PAIR_LEDGER_OBSERVED_WINDOW_TICKS as f64 * tick_scaled / DAY as f64,
            "scale {scale}: the window must be a whole number of tick periods"
        );
        assert!(
            observed_window_days(scale) >= tick_scaled / DAY as f64,
            "scale {scale}: a window shorter than one tick would darken every tick"
        );
    }
    // And at scale 1, where the two clocks coincide, it is still the 3 h of Д-A.
    assert_eq!(real_time_window(), 3.0 * 3600.0 / DAY as f64);
}

#[test]
fn an_on_schedule_tick_is_fully_charged_at_a_time_scale_that_outruns_the_tick_divisor() {
    // The regression BLOCK-1 named. At scale 100_000 the timer is floored at one real
    // second, so one on-schedule tick is 100_000 scaled seconds ≈ 1.157 simulated days —
    // nine times the 0.125-day window the seconds-valued constant used to give. The tick
    // must still be charged in FULL, and by the volume, not by 10.8 % of it.
    let scale = 100_000u64;
    let db = test_db();
    let them = master(0xD5);
    db.upsert_peer(&peer_of(device(0xD6), them)).unwrap();
    we_store_for(&db, 0xD7, them, 1);
    let recorder = PairLedgerRecorder::new(db.clone());
    let tick = tick_interval_secs(scale);
    assert_eq!(tick, 1, "premise: the timer floor bites at this scale");

    recorder.tick(&my_master(), Timestamp(0), scale).unwrap();
    let stats = recorder.tick(&my_master(), Timestamp(tick), scale).unwrap();

    let scaled_days = tick as f64 * scale as f64 / DAY as f64;
    assert!(
        scaled_days > 3.0 * PAIR_LEDGER_TICK_SECS as f64 / DAY as f64,
        "premise: one tick here is LONGER than the old fixed window ({scaled_days} d)"
    );
    assert_eq!(
        stats.with_unobserved_gap, 0,
        "an on-schedule tick is not an outage, whatever the scale"
    );
    let mut expected = PairLedger::default();
    accrue(&mut expected, &vol(0.0, 1.0), scaled_days);
    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    assert_eq!(
        stored.gb_days_we_store_for_them, expected.gb_days_we_store_for_them,
        "the whole tick carries the measured volume"
    );
}

#[test]
fn a_gap_one_tick_longer_than_the_window_goes_dark_at_every_time_scale() {
    // The window must stay a THRESHOLD at every scale, not quietly become "everything".
    // NB this test is self-referential — it takes `observed_window_days(scale)` as both the
    // subject and the yardstick, so it is blind to the window's VALUE and does NOT catch
    // BLOCK-1 (it passes under the frozen-seconds mutation). That is caught by
    // `the_observed_window_is_three_tick_periods_at_every_time_scale`. This one answers a
    // different question: is the window still a threshold at all.
    // Checked at scale 1 (a period is 3600 real seconds), 1000 (3 s) and 100_000 (1 s, the
    // timer floor) — the last is the case a seconds-valued window could not express at all.
    // The dark stretch is compared with a RELATIVE tolerance because `window + period` and
    // `window` are two roundings apart, not because any epsilon was tuned.
    for scale in [1u64, 1000, 100_000] {
        let window = observed_window_days(scale);
        let period_days = tick_interval_secs(scale) as f64 * scale as f64 / DAY as f64;

        // A non-zero starting capital, or "the dark stretch decayed something" would be
        // indistinguishable from "the dark stretch did nothing": decay of zero is zero.
        let mut on_time = ledger_at(50.0, 0.0, 0.0, None);
        let exact = accrue_interval(&mut on_time, &vol(1.0, 0.0), window, window);
        let mut late = ledger_at(50.0, 0.0, 0.0, None);
        let over = accrue_interval(&mut late, &vol(1.0, 0.0), window + period_days, window);

        assert_eq!(
            exact.unobserved_days, 0.0,
            "scale {scale}: a gap of exactly the window is still jitter"
        );
        assert!(
            (over.unobserved_days - period_days).abs() <= 1e-9 * period_days,
            "scale {scale}: one period past the window must be dark, got {} of {period_days}",
            over.unobserved_days
        );
        assert!(
            late.gb_days_they_store_for_us < on_time.gb_days_they_store_for_us,
            "scale {scale}: and the dark stretch must cost capital, not merely be counted"
        );
    }
}

// ── Restart ─────────────────────────────────────────────────────────────────

#[test]
fn accrual_resumes_from_the_stored_clock_after_a_restart() {
    // The whole point of landing the recorder early is accumulation across CALENDAR time,
    // which means across restarts: the second run must continue the row, not restart it.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("db.redb");
    let them = master(0xE0);

    {
        let db = Db::open(&path).unwrap();
        db.upsert_peer(&peer_of(device(0xE1), them)).unwrap();
        we_store_for(&db, 0xE2, them, 2);
        let recorder = PairLedgerRecorder::new(db.clone());
        recorder.tick(&my_master(), Timestamp(0), 1).unwrap();
        recorder.tick(&my_master(), Timestamp(TICK), 1).unwrap();
    }

    let db = Db::open(&path).unwrap();
    let before = db.get_pair_ledger(&them).unwrap().unwrap();
    PairLedgerRecorder::new(db.clone())
        .tick(&my_master(), Timestamp(2 * TICK), 1)
        .unwrap();
    let after = db.get_pair_ledger(&them).unwrap().unwrap();

    let mut expected = before.clone();
    accrue(&mut expected, &vol(0.0, 2.0), TICK as f64 / DAY as f64);
    assert_eq!(
        after.gb_days_we_store_for_them,
        expected.gb_days_we_store_for_them
    );
    assert!(
        after.gb_days_we_store_for_them > before.gb_days_we_store_for_them,
        "the restarted daemon must continue the integral, not reset it"
    );
}
