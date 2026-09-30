//! Allocation-peak measurements for the encoder (R1-d-b, backup-i24).
//!
//! A separate test binary: the counting global allocator must not leak into the other unit
//! tests. Peaks are measured ABOVE the input the caller already holds (the padded block), so
//! "2.1 * E_pad" is what the operation adds on top of the 1 * E_pad input: with the input that
//! is the 3.1 * E model of the spec (§1.2). Tests serialise on one lock because the counters are
//! process-wide; under nextest each test is its own process anyway.

// A counting GlobalAlloc is unsafe by definition; it only forwards to System.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder, SourceBlockEncodingPlan};
use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, pad_for_encoding};
use viaticum_core::pos::ChainHasher;
use viaticum_core::types::ErasureParams;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
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

/// At E = 16 MiB (K = 257) the LDPC and HDPC rows are ~10% of K, not the ~3% of a large block, so
/// the intermediate symbols are 1.11 E instead of 1.03 E (measured 2.157 E_pad for the build
/// stage). The model's 2.1 is the large-K figure; this slack is what a small K adds.
const SMALL_K_SLACK: f64 = 0.1;

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

/// Peak of `encode_raw` for `count` symbols from ESI `start`, in units of E_pad.
fn raw_peak(start: u32, count: u32) -> (usize, usize) {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let enc = RaptorQEncoder::new();
    let (symbols, peak) = measure(|| enc.encode_raw(&blob, &params, start, count).unwrap());
    assert_eq!(symbols.len(), count as usize);
    (peak, e_pad(&params))
}

// Model (spec §1.2, v3.3 B2): with the input already padded to k*t the operation adds the source
// symbols (1.0 E) + the intermediate symbols (~1.03-1.1 E) + the plan (~0.035 E) while building,
// plus the output symbols the caller asked for (R * E). A copy of the padded input (F5) or of the
// source packets (F6) adds another 1.0 E on top.

#[test]
fn encode_raw_alloc_peak_r0_25_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    let (peak, e_pad) = raw_peak(0, params.k / 4);
    let r = 0.25;
    println!("r0.25: peak/E_pad = {:.3}", ratio(peak, e_pad));
    assert!(
        peak as f64 <= (2.1 + SMALL_K_SLACK + r) * e_pad as f64 + MIB as f64,
        "peak {} MiB = {:.3} E_pad",
        peak / MIB,
        ratio(peak, e_pad)
    );
}

#[test]
fn encode_raw_alloc_peak_r2_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    let (peak, e_pad) = raw_peak(params.k, 2 * params.k);
    println!("r2: peak/E_pad = {:.3}", ratio(peak, e_pad));
    assert!(
        peak as f64 <= (2.1 + SMALL_K_SLACK + 2.0) * e_pad as f64 + MIB as f64,
        "peak {} MiB = {:.3} E_pad",
        peak / MIB,
        ratio(peak, e_pad)
    );
}

#[test]
fn encode_raw_alloc_peak_r10_within_model() {
    let params = ErasureParams::compute(E as u64, 0.5).unwrap();
    let (peak, e_pad) = raw_peak(params.k, 10 * params.k);
    println!("r10: peak/E_pad = {:.3}", ratio(peak, e_pad));
    assert!(
        peak as f64 <= (2.1 + SMALL_K_SLACK + 10.0) * e_pad as f64 + MIB as f64,
        "peak {} MiB = {:.3} E_pad",
        peak / MIB,
        ratio(peak, e_pad)
    );
}

/// F8': the walk over the union hands each symbol to the holders' hashers and drops it; the
/// peak is the build stage, whatever the number of holders and of symbols.
#[test]
fn encode_raw_ranges_each_alloc_peak_within_model() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (blob, params) = padded_block();
    let enc = RaptorQEncoder::new();
    let k = params.k;
    // Union: part of the source ESIs, then R_due = 2 of repair symbols.
    let union = [(0u32, k / 2), (k + 10, 2 * k)];
    let bound = (2.1 + SMALL_K_SLACK) * e_pad(&params) as f64 + 4.0 * params.t as f64 + MIB as f64;

    let mut peaks = Vec::new();
    for holders in [1u32, 4, 8] {
        let challenge = [7u8; 16];
        let mut hashers: Vec<ChainHasher> =
            (0..holders).map(|_| ChainHasher::new(&challenge)).collect();
        let mut pushed = vec![0usize; holders as usize];
        let ((), peak) = measure(|| {
            enc.encode_raw_ranges_each(&blob, &params, &union, &mut |esi, data| {
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
        println!(
            "each h={holders}: peak/E_pad = {:.3} (bound {:.3})",
            ratio(peak, e_pad(&params)),
            bound / e_pad(&params) as f64
        );
        assert!(
            peak as f64 <= bound,
            "h={holders}: peak {} MiB = {:.3} E_pad",
            peak / MIB,
            ratio(peak, e_pad(&params))
        );
        peaks.push(peak);
    }
    let (lo, hi) = (*peaks.iter().min().unwrap(), *peaks.iter().max().unwrap());
    assert!(
        hi - lo <= MIB,
        "the peak must not depend on the number of holders: {peaks:?}"
    );
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
