// D-4a..D-4c: the shape and the level of the 4R lines. Also home of the log-capture helper the
// holder_cleanup / processor shadow tests use.

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use viaticum_core::budget::DiskPressure;
use viaticum_core::four_r::EvictPhase;
use viaticum_core::four_r_holder::{
    FourRParams, OfferIn, OldPlan, QuotaInputs, RAW_RECORD_VERSION, ShadowOffer,
    ShadowPressureInput, raw_pressure_record, shadow_offer, shadow_pressure_tick,
};
use viaticum_core::types::{HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp};

use super::{log_offer, log_pressure_tick, log_record_with};

/// In-memory log sink for tests (no ANSI).
#[derive(Clone, Default)]
pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Install a thread-local subscriber with `filter` (EnvFilter syntax) writing into a
/// [`Captured`] sink. Keep the guard alive for the duration of the capture.
pub(crate) fn capture(filter: &str) -> (Captured, tracing::subscriber::DefaultGuard) {
    let sink = Captured::default();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(sink.clone())
        .finish();
    let guard = tracing::subscriber::set_default(sub);
    (sink, guard)
}

/// Like [`capture`], but returns the subscriber as a `Dispatch` instead of installing it on
/// the calling thread: for threads the test does not run on (a runtime's blocking pool, via
/// its `on_thread_start` hook).
pub(crate) fn capture_dispatch(filter: &str) -> (Captured, tracing::Dispatch) {
    let sink = Captured::default();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(sink.clone())
        .finish();
    (sink, tracing::Dispatch::new(sub))
}

fn holding(owner: u8, blk: u8, bytes: u64) -> HoldingRecord {
    HoldingRecord {
        source_block_id: SourceBlockId([blk; 32]),
        owner_id: IdentityPub([owner; 32]),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// A small shadow tick: two owners, contention (Q = 1000, H = 990).
fn with_tick(f: impl FnOnce(&ShadowPressureInput, &viaticum_core::four_r_holder::ShadowTick)) {
    let holdings = vec![holding(1, 10, 500), holding(2, 20, 490)];
    let input = ShadowPressureInput {
        holdings: &holdings,
        ledgers: &[],
        placements: &[],
        peers: &[],
        own_master: IdentityPub([0xEE; 32]),
        quota: QuotaInputs::from_holdings(&holdings, 1 << 40, 1000, 0, 0),
        phase_prev: EvictPhase::default(),
        old_owner_order: vec![IdentityPub([2; 32]), IdentityPub([1; 32])],
        old_plan: OldPlan {
            pressure: DiskPressure::Hard,
            immediate: vec![],
            notices: vec![],
        },
    };
    let tick = shadow_pressure_tick(&input, &FourRParams::default());
    f(&input, &tick);
}

/// D-4a: a record is ONE line `four_r: record rec=<JSON>` with valid JSON of the current
/// format version ([`RAW_RECORD_VERSION`]).
#[test]
fn a_shadow_record_is_one_line_of_valid_json_of_the_current_version() {
    let (sink, _g) = capture("viaticum::four_r=debug");
    with_tick(|input, tick| {
        log_record_with(|| raw_pressure_record(input, &FourRParams::default(), tick, 42));
    });
    let text = sink.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("four_r: record"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    let json = lines[0].split_once("rec=").expect("rec= field").1;
    let v: serde_json::Value = serde_json::from_str(json).expect("valid JSON to end of line");
    assert_eq!(v["v"], RAW_RECORD_VERSION);
    assert_eq!(v["kind"], "pressure");
    assert_eq!(v["now"], 42);
    assert_eq!(v["owners"].as_array().unwrap().len(), 2);
    assert_eq!(v["out"]["phase"], true);
    assert_eq!(v["old_plan"]["pressure"], "Hard");
    assert!(v["out"]["q_bytes"].is_i64());
    assert!(lines[0].contains("DEBUG") && lines[0].contains("viaticum::four_r"));
}

/// D-4b: the tick summary is INFO; owner rows and records are DEBUG.
#[test]
fn shadow_records_are_debug_and_summaries_info() {
    let (sink, g) = capture("viaticum::four_r=info");
    with_tick(|input, tick| {
        log_pressure_tick(tick, &input.quota, &input.old_plan);
        log_record_with(|| raw_pressure_record(input, &FourRParams::default(), tick, 1));
    });
    drop(g);
    let text = sink.text();
    let summary: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("four_r: pressure tick"))
        .collect();
    assert_eq!(summary.len(), 1, "{text}");
    assert!(summary[0].contains(" INFO "), "{}", summary[0]);
    assert!(summary[0].contains("mode=\"shadow\""), "{}", summary[0]);
    for key in [
        "phi_actual=",
        "phase=true",
        "zk_asked_bytes=",
        "first_owner_new=",
        "old_pressure=Hard",
        "kendall_tau=",
    ] {
        assert!(summary[0].contains(key), "missing {key}: {}", summary[0]);
    }
    assert!(!text.contains("four_r: owner"));
    assert!(!text.contains("four_r: record"));

    let (sink, _g) = capture("viaticum::four_r=debug");
    with_tick(|input, tick| {
        log_pressure_tick(tick, &input.quota, &input.old_plan);
    });
    let text = sink.text();
    let owners: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("four_r: owner"))
        .collect();
    assert_eq!(owners.len(), 2);
    assert!(
        owners
            .iter()
            .all(|l| l.contains("DEBUG") && l.contains("zk_class=NeverAsked"))
    );
}

/// D-4c (W-6): with DEBUG of the target off, the record is not even BUILT.
#[test]
fn no_raw_record_is_built_when_debug_is_off() {
    let built = Cell::new(false);
    {
        let (_sink, _g) = capture("info");
        with_tick(|input, tick| {
            log_record_with(|| {
                built.set(true);
                raw_pressure_record(input, &FourRParams::default(), tick, 1)
            });
        });
    }
    assert!(
        !built.get(),
        "make() must not run when DEBUG of viaticum::four_r is off"
    );
    {
        let (_sink, _g) = capture("viaticum::four_r=debug");
        with_tick(|input, tick| {
            log_record_with(|| {
                built.set(true);
                raw_pressure_record(input, &FourRParams::default(), tick, 1)
            });
        });
    }
    assert!(built.get());
}

/// A free (4R admits) and a refused (Q ≤ 0) offer shadow over an empty holder.
fn offer_outcomes() -> (OfferIn, ShadowOffer, ShadowOffer) {
    let offer = OfferIn {
        owner: IdentityPub([3; 32]),
        block: SourceBlockId([30; 32]),
        offer_bytes: 100,
    };
    let decide = |reserve: u64| {
        shadow_offer(
            &[],
            &[],
            IdentityPub([0xEE; 32]),
            QuotaInputs::from_holdings(&[], 1 << 20, 0, reserve, 0),
            EvictPhase::default(),
            &offer,
            &FourRParams::default(),
        )
    };
    let free = decide(0);
    let refused = decide(1 << 21); // Q = free − reserve < 0
    assert!(free.admit.admits());
    assert!(!refused.admit.admits());
    (offer, free, refused)
}

/// D-4d (review N5): the offer line is INFO exactly when 4R would answer differently from the
/// old rule (old accept vs 4R reject, old reject vs 4R admit), DEBUG when they agree.
#[test]
fn the_offer_line_is_info_on_disagreement_and_debug_on_agreement() {
    let (offer, free, refused) = offer_outcomes();
    let cases = [
        (true, &free, false),     // both accept
        (false, &free, true),     // old reject, 4R admits
        (true, &refused, true),   // old accept, 4R refuses
        (false, &refused, false), // both refuse
    ];
    let (sink, g) = capture("viaticum::four_r=debug");
    for (old_accept, out, _) in &cases {
        log_offer(&offer, out, *old_accept, 0);
    }
    drop(g);
    let text = sink.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("four_r: offer"))
        .collect();
    assert_eq!(lines.len(), cases.len(), "{text}");
    for (line, (old_accept, out, disagree)) in lines.iter().zip(&cases) {
        let want = if *disagree { " INFO " } else { "DEBUG" };
        assert!(line.contains(want), "want {want}: {line}");
        let old = if *old_accept {
            "old=accept"
        } else {
            "old=reject"
        };
        assert!(line.contains(old), "{line}");
        assert!(line.contains(&format!("new={}", out.admit.tag())), "{line}");
    }
    // At INFO only the two disagreements are printed.
    let (sink, g) = capture("viaticum::four_r=info");
    for (old_accept, out, _) in &cases {
        log_offer(&offer, out, *old_accept, 0);
    }
    drop(g);
    assert_eq!(
        sink.text()
            .lines()
            .filter(|l| l.contains("four_r: offer"))
            .count(),
        2
    );
}
