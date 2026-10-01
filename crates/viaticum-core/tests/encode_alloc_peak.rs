//! Allocation-peak measurements for the encoder (R1-d-b, backup-i24).
//!
//! A separate test binary: the counting global allocator must not leak into the other unit
//! tests. Peaks are measured ABOVE the input the caller already holds (the padded block). The
//! bars are a function of K (spec v3.4/v3.5): the model has one named tolerance, `δ = 0.02 *
//! E_pad`, and NO other slack — a bar that does not hold is a STOP for that unit and a model
//! change by a spec delta, never a looser number here. Tests serialise on one lock because the
//! counters are process-wide; under nextest each test is its own process anyway.

// A counting GlobalAlloc is unsafe by definition; it only forwards to System.
#![allow(unsafe_code)]
// Measures the erasure entry points themselves.
#![allow(clippy::disallowed_methods)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::time::Instant;

use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder, SourceBlockEncodingPlan};
use viaticum_core::erasure::{
    ErasureEncoder, POS_SYMBOL_BUFFERS, RaptorQEncoder, Symbol, encoder_bytes,
    intermediate_symbols, pad_for_encoding,
};
use viaticum_core::pos::ChainHasher;
use viaticum_core::types::ErasureParams;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// A histogram of the live blocks of at least `HIST_MIN` bytes by exact size, snapshotted at every
// new peak while `HIST_ON` (the S/H unit). Fixed tables: the allocator must not allocate.
const HIST_MIN: usize = 32 * 1024;
const SLOTS: usize = 512;
static HIST_ON: AtomicBool = AtomicBool::new(false);
static SIZES: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static COUNT: [AtomicIsize; SLOTS] = [const { AtomicIsize::new(0) }; SLOTS];
static AT_PEAK: [AtomicIsize; SLOTS] = [const { AtomicIsize::new(0) }; SLOTS];
static HIST_OVERFLOW: AtomicUsize = AtomicUsize::new(0);

fn hist_slot(size: usize) -> Option<usize> {
    let start = size.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40;
    for i in 0..SLOTS {
        let idx = (start + i) % SLOTS;
        let cur = SIZES[idx].load(Ordering::Relaxed);
        if cur == size {
            return Some(idx);
        }
        if cur == 0 {
            match SIZES[idx].compare_exchange(0, size, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(idx),
                Err(c) if c == size => return Some(idx),
                Err(_) => continue,
            }
        }
    }
    None
}

fn hist_add(size: usize, delta: isize) {
    if size < HIST_MIN {
        return;
    }
    match hist_slot(size) {
        Some(idx) => {
            COUNT[idx].fetch_add(delta, Ordering::Relaxed);
        }
        None => {
            HIST_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    let prev = PEAK.fetch_max(now, Ordering::Relaxed);
    if now > prev && HIST_ON.load(Ordering::Relaxed) {
        for i in 0..SLOTS {
            AT_PEAK[i].store(COUNT[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            hist_add(layout.size(), 1);
            grew(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            hist_add(layout.size(), 1);
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        hist_add(layout.size(), -1);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            hist_add(layout.size(), -1);
            hist_add(new_size, 1);
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

static SERIAL: Mutex<()> = Mutex::new(());

const MIB: usize = 1 << 20;
const E: usize = 16 * MIB;
/// The symbol size of the daemon (`SYMBOL_SIZE`).
const T: usize = 65_535;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Run `f`; return its result and the peak of live bytes above the level at entry.
fn measure<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = live();
    PEAK.store(base, Ordering::Relaxed);
    let r = f();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    (r, peak)
}

/// A 16 MiB blob (not a multiple of T), padded in place to k * t, as the daemon callers do.
fn padded_block() -> (Vec<u8>, ErasureParams) {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    let mut blob: Vec<u8> = (0..E).map(|i| (i % 251) as u8 + 1).collect();
    pad_for_encoding(&mut blob, &params);
    assert_eq!(blob.len(), params.k as usize * params.t as usize);
    (blob, params)
}

fn e_pad(params: &ErasureParams) -> usize {
    params.k as usize * params.t as usize
}

fn ratio(peak: usize, e_pad: usize) -> f64 {
    peak as f64 / e_pad as f64
}

/// What the plan of `k` source symbols holds after `SourceBlockEncodingPlan::generate(k)`:
/// P(K) of the model. The caller holds the serial lock.
fn plan_held(k: u32) -> usize {
    let base = live();
    let plan = SourceBlockEncodingPlan::generate(k as u16);
    let held = live().saturating_sub(base);
    drop(plan);
    held
}

// ─── The model (spec v3.4 "Бары", v3.5 NOTE 2, WARN-3) ──────────────────────────────────────────
//
// With the input already padded to k*t, in bytes above it (L = L(K) of RFC 6330, σ = size of a
// `Symbol`, P = the plan held after generation, n = output symbols):
//   build        B   = (K + L)·T + P                      source copies, intermediates, plan
//   end of raw   (K + L)·T + n·(T + σ) [+ T]              the encoder lives while output piles up;
//                                                         + T only when a repair ESI is in the
//                                                         range (the `repair_packets` packet)
//   walk (each)       (K + L)·T + T                       no output piles up
//   peak = max of the stages; bar = peak + δ, δ = 0.02·E_pad.

struct Model {
    k: u32,
    t: usize,
    l: usize,
    e_pad: usize,
    plan: usize,
}

impl Model {
    fn new(params: &ErasureParams, plan: usize) -> Model {
        Model {
            k: params.k,
            t: params.t as usize,
            l: intermediate_symbols(params.k) as usize,
            e_pad: e_pad(params),
            plan,
        }
    }
    /// `(1 + L/K)·E_pad`: the source copies and the intermediate symbols.
    fn encoder(&self) -> usize {
        (self.k as usize + self.l) * self.t
    }
    fn build(&self) -> usize {
        self.encoder() + self.plan
    }
    fn end_of_raw(&self, n: usize, repair: bool) -> usize {
        self.encoder()
            + n * (self.t + std::mem::size_of::<Symbol>())
            + if repair { self.t } else { 0 }
    }
    fn walk(&self) -> usize {
        self.encoder() + self.t
    }
    fn delta(&self) -> usize {
        self.e_pad / 50
    }
    fn bar(&self, model: usize) -> usize {
        model + self.delta()
    }
}

fn report(name: &str, m: &Model, model: usize, peak: usize) {
    println!(
        "{name}: K = {} L = {} P = {:.4} E_pad | model {:.4} bar {:.4} measured {:.4} (E_pad units)",
        m.k,
        m.l,
        ratio(m.plan, m.e_pad),
        ratio(model, m.e_pad),
        ratio(m.bar(model), m.e_pad),
        ratio(peak, m.e_pad),
    );
}

/// Peak of `encode_raw` for `count` symbols from ESI `start`, with the model of its stages.
fn raw_peak_checked(name: &str, start: u32, count: u32) {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let m = Model::new(&params, plan_held(params.k));
    let enc = RaptorQEncoder::new();
    let (symbols, peak) = measure(|| enc.encode_raw(&blob, &params, start, count).unwrap());
    assert_eq!(symbols.len(), count as usize);
    let n = count as usize;
    let repair = start + count > params.k;
    let model = m.build().max(m.end_of_raw(n, repair));
    report(name, &m, model, peak);
    assert!(
        peak <= m.bar(model),
        "{name}: peak {:.4} E_pad above the bar {:.4} (model {:.4})",
        ratio(peak, m.e_pad),
        ratio(m.bar(model), m.e_pad),
        ratio(model, m.e_pad)
    );
    // The estimate of the daemon must cover the measurement: `estimate_worker` takes
    // `encoder_bytes` plus the output and the packet on top of the input (M36).
    let covered = encoder_bytes(params.k, params.t) as usize
        + n * (m.t + std::mem::size_of::<Symbol>())
        + m.t;
    assert!(
        peak <= covered,
        "{name}: peak {} B is above the estimate {covered} B",
        peak
    );
}

#[test]
fn encode_raw_alloc_peak_r0_25_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    // ESI 0..k/4: source ESIs only, no repair packet (no `+T`).
    raw_peak_checked("r0.25", 0, params.k / 4);
}

#[test]
fn encode_raw_alloc_peak_r2_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    raw_peak_checked("r2", params.k, 2 * params.k);
}

#[test]
fn encode_raw_alloc_peak_r10_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    raw_peak_checked("r10", params.k, 10 * params.k);
}

/// One encoder build and no walk (`encode_raw_ranges_each` with no ranges): the build stage alone,
/// `B + δ`.
#[test]
fn encoder_build_alloc_peak_within_model() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let m = Model::new(&params, plan_held(params.k));
    let peak = build_peak(&blob, &params);
    report("build", &m, m.build(), peak);
    assert!(
        peak <= m.bar(m.build()),
        "build: peak {:.4} E_pad above the bar {:.4}",
        ratio(peak, m.e_pad),
        ratio(m.bar(m.build()), m.e_pad)
    );
}

fn build_peak(blob: &[u8], params: &ErasureParams) -> usize {
    let enc = RaptorQEncoder::new();
    let ((), peak) = measure(|| {
        enc.encode_raw_ranges_each(blob, params, &[], &mut |_, _| Ok(()))
            .unwrap();
    });
    peak
}

/// F8': the walk over the union hands each symbol to the holders' hashers and drops it. Returns
/// the peak for `holders` hashers.
fn each_peak(blob: &[u8], params: &ErasureParams, holders: u32) -> usize {
    let enc = RaptorQEncoder::new();
    let k = params.k;
    // Union: part of the source ESIs, then R_due = 2 of repair symbols.
    let union = [(0u32, k / 2), (k + 10, 2 * k)];
    let challenge = [7u8; 16];
    let mut hashers: Vec<ChainHasher> =
        (0..holders).map(|_| ChainHasher::new(&challenge)).collect();
    let mut pushed = vec![0usize; holders as usize];
    let ((), peak) = measure(|| {
        enc.encode_raw_ranges_each(blob, params, &union, &mut |esi, data| {
            for (j, h) in hashers.iter_mut().enumerate() {
                // Holders overlap: every third ESI goes to all of them.
                if esi % holders == j as u32 || esi % 3 == 0 {
                    h.push(esi, data);
                    pushed[j] += 1;
                }
            }
            Ok(())
        })
        .unwrap();
    });
    for (h, n) in hashers.into_iter().zip(pushed) {
        assert!(n > 0, "fixture: every holder must hash something");
        h.finish().unwrap();
    }
    peak
}

/// F8' (spec v3.7b): the MODEL bar of the walk. `each = max(build, walk) = build`, because the plan
/// is let go before the walk: `(1 + L/K)·E_pad + P(K)`, with P(K) the plan held after generation,
/// measured in this same test (`plan_held`: 0.0395 E_pad at K = 257 — the term v3.5 could not name).
/// The bar is the model plus delta (0.02 E_pad), no other slack. Measured 2.1918 against the bar 2.2113.
#[test]
fn encode_raw_ranges_each_alloc_peak_within_model() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let m = Model::new(&params, plan_held(params.k));
    let build = build_peak(&blob, &params);
    let model = m.build().max(m.walk());
    let mut failures = Vec::new();
    for holders in [1u32, 4, 8] {
        let peak = each_peak(&blob, &params, holders);
        report(&format!("each h={holders}"), &m, model, peak);
        println!(
            "each h={holders}: build {} B, each {} B, P {} B, each - build = {} B = {:.2} T",
            build,
            peak,
            m.plan,
            peak as i64 - build as i64,
            (peak as f64 - build as f64) / m.t as f64
        );
        if peak > m.bar(model) {
            failures.push((holders, peak));
        }
    }
    assert!(
        failures.is_empty(),
        "each above the model bar: {failures:?}"
    );
}

/// What `estimate_pos_issue` takes above the input — `encoder_bytes` plus the symbol buffers —
/// covers the measured walk (held by M7, M37; the model bar above holds the exact term, v3.7b).
#[test]
fn encode_raw_ranges_each_peak_is_covered_by_the_estimate() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let covered = encoder_bytes(params.k, params.t) as usize + POS_SYMBOL_BUFFERS as usize * T;
    for holders in [1u32, 4, 8] {
        let peak = each_peak(&blob, &params, holders);
        println!(
            "each h={holders}: peak {:.4} E_pad, estimate above the input {:.4} E_pad",
            ratio(peak, e_pad(&params)),
            ratio(covered, e_pad(&params))
        );
        assert!(
            peak <= covered,
            "h={holders}: peak {peak} B above encoder_bytes + {POS_SYMBOL_BUFFERS}·T = {covered} B"
        );
    }
}

#[test]
fn encode_raw_ranges_each_peak_does_not_depend_on_holders() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let peaks: Vec<usize> = [1u32, 4, 8]
        .iter()
        .map(|&h| each_peak(&blob, &params, h))
        .collect();
    let (lo, hi) = (*peaks.iter().min().unwrap(), *peaks.iter().max().unwrap());
    assert!(
        hi - lo <= MIB,
        "the peak must not depend on the number of holders: {peaks:?}"
    );
}

/// By hand (E = 256 MiB, K = 4096): the build peak of the production K against what the estimate
/// reserves (`encoder_bytes`). One run per fix round, numbers to `runs.jsonl` (v3.5 NOTE 4).
#[test]
#[ignore = "manual measurement: K = 4096 (E = 256 MiB), one run per fix round"]
fn encoder_build_alloc_peak_k4096() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let params = ErasureParams::compute(4096 * T as u64, 0.5).unwrap();
    assert_eq!(params.k, 4096);
    let mut blob = vec![5u8; 4096 * T];
    pad_for_encoding(&mut blob, &params);
    let m = Model::new(&params, plan_held(params.k));
    let peak = build_peak(&blob, &params);
    let est = encoder_bytes(params.k, params.t) as usize;
    report("build K=4096", &m, m.build(), peak);
    println!(
        "build K=4096: measured {peak} B = {:.4} E_pad, encoder_bytes {est} B = {:.4} E_pad",
        ratio(peak, m.e_pad),
        ratio(est, m.e_pad)
    );
    assert!(peak <= est, "measured {peak} B above encoder_bytes {est} B");
}

// ─── S and H of the table, against what the encoder allocates (v3.5a WARN-A) ────────────────────

/// Build a raptorq encoder directly (T = 65 535) and read the histogram of the live blocks at the
/// peak of the allocations, by exact size. The source symbols are K separate blocks of exactly T
/// bytes (`create_symbols`) and the intermediate symbols ONE `SymbolSlab` of exactly L(K)·T. The
/// asserts are exact integers, no byte tolerance: an error of one symbol in S or H of the table
/// changes the integer L(K)·T and turns the unit red. If raptorq ever allocated the slab per
/// symbol, the blocks of size T would be K + L(K) and the form of this check changes here, in the
/// open, not the number.
#[test]
fn table_s_and_h_match_the_encoder_build() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for k in [10u32, 257, 306, 1307] {
        let l = intermediate_symbols(k) as usize;
        let data = vec![3u8; k as usize * T];
        let config = ObjectTransmissionInformation::new(k as u64 * T as u64, T as u16, 1, 1, 1);

        for slot in &AT_PEAK {
            slot.store(0, Ordering::Relaxed);
        }
        HIST_ON.store(true, Ordering::Relaxed);
        let (encoder, peak) = measure(|| {
            let plan = SourceBlockEncodingPlan::generate(k as u16);
            SourceBlockEncoder::with_encoding_plan(0, &config, &data, &plan)
        });
        HIST_ON.store(false, Ordering::Relaxed);
        drop(encoder);

        let mut hist: Vec<(usize, isize)> = (0..SLOTS)
            .filter_map(|i| {
                let c = AT_PEAK[i].load(Ordering::Relaxed);
                (c != 0).then(|| (SIZES[i].load(Ordering::Relaxed), c))
            })
            .collect();
        hist.sort();
        println!(
            "K = {k} (L = {l}): peak {peak} B; live blocks >= {HIST_MIN} B at the peak \
             (size: count): {hist:?}; overflow {}",
            HIST_OVERFLOW.load(Ordering::Relaxed)
        );
        let count_of = |size: usize| hist.iter().find(|(s, _)| *s == size).map_or(0, |(_, c)| *c);
        assert_eq!(
            count_of(T),
            k as isize,
            "K = {k}: blocks of exactly T bytes (the source symbol copies)"
        );
        assert_eq!(
            count_of(l * T),
            1,
            "K = {k}: blocks of exactly L(K)·T = {} bytes (the intermediate symbols, one slab); \
             S or H of the table is wrong if this fails",
            l * T
        );
    }
}

// ─── raptorq plan: size, retention in the process-wide cache, time ──────────────────────────────

/// `SourceBlockEncodingPlan::generate(k)`: its own size stays under 0.05 * K * T (T = 65535), and
/// raptorq's constructor keeps such a plan in a process-wide cache after the encoder is gone
/// (the reason `make_block_encoder` builds a private plan).
fn plan_alloc_and_retention(k: u16) {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let threshold = 0.05 * k as f64 * 65_535.0;

    let base = live();
    let started = Instant::now();
    let (plan, peak) = measure(|| SourceBlockEncodingPlan::generate(k));
    let gen_time = started.elapsed();
    let held = live() - base;
    drop(plan);
    let after_drop = live() - base;

    // The cache: build an encoder the ordinary way (tiny T: the plan does not depend on T).
    let t: u16 = 8;
    let config = ObjectTransmissionInformation::new(k as u64 * t as u64, t, 1, 1, 1);
    let data = vec![3u8; k as usize * t as usize];
    let base2 = live();
    let started = Instant::now();
    drop(SourceBlockEncoder::new(0, &config, &data));
    let new_time = started.elapsed();
    let cached = live() - base2;
    // Second build: the plan is found in the cache.
    let started = Instant::now();
    drop(SourceBlockEncoder::new(0, &config, &data));
    let new_cached_time = started.elapsed();
    // Private plan on the same data, for the time comparison.
    let started = Instant::now();
    let private_plan = SourceBlockEncodingPlan::generate(k);
    drop(SourceBlockEncoder::with_encoding_plan(
        0,
        &config,
        &data,
        &private_plan,
    ));
    let private_time = started.elapsed();

    println!(
        "plan K={k}: generate {gen_time:?}, peak {:.3} MiB = {:.4} K*T, held {:.3} MiB = {:.4} K*T, \
         after drop {after_drop} B; cache retains {:.3} MiB after the encoder is gone; \
         encoder new (miss) {new_time:?}, new (hit) {new_cached_time:?}, private plan + build {private_time:?}",
        peak as f64 / MIB as f64,
        peak as f64 / (k as f64 * 65_535.0),
        held as f64 / MIB as f64,
        held as f64 / (k as f64 * 65_535.0),
        cached as f64 / MIB as f64,
    );

    assert!(
        (held as f64) <= threshold,
        "plan {held} B exceeds 0.05 * K * T = {threshold}"
    );
    // Generation itself (v3.4): the peak while the plan is built stays under the same bound
    // (measured 0.0448).
    assert!(
        (peak as f64) <= threshold,
        "plan generation peak {peak} B exceeds 0.05 * K * T = {threshold}"
    );
    assert!(
        after_drop < 64 * 1024,
        "dropping the plan must free it: {after_drop} B left"
    );
    assert!(
        cached * 2 >= held,
        "expected the raptorq cache to keep the plan ({held} B) after the encoder is dropped, \
         it kept {cached} B"
    );
}

#[test]
fn raptorq_plan_generate_4096_alloc_peak_and_retention() {
    plan_alloc_and_retention(4096);
}

#[test]
fn raptorq_plan_generate_16384_alloc_peak_and_retention() {
    plan_alloc_and_retention(16384);
}

/// By hand, once before release (v3.5 NOTE 5, a release gate): the plan at the largest K the
/// daemon can meet (56 403, a block over 3 GiB). Prediction: peak <= 0.06 * K * T. Above 0.05 the
/// model needs its own constant for K > 16 384 (measured x 1.1; procedure in the spec, v3.4).
#[test]
#[ignore = "manual measurement: K = 56 403, numbers go to runs.jsonl (release gate)"]
fn raptorq_plan_generate_56403_alloc_peak() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let k: u16 = 56_403;
    let started = Instant::now();
    let (plan, peak) = measure(|| SourceBlockEncodingPlan::generate(k));
    let gen_time = started.elapsed();
    let kt = k as f64 * 65_535.0;
    println!(
        "plan K={k}: generate {gen_time:?}, peak {peak} B = {:.4} K*T",
        peak as f64 / kt
    );
    drop(plan);
    assert!(
        peak as f64 <= 0.06 * kt,
        "plan generation peak {:.4} K*T is above the 0.06 prediction",
        peak as f64 / kt
    );
}
