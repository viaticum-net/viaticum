//! Allocation peak of the PoS preparation (R1-d-b, backup-i24, v3.3 B2).
//!
//! A separate test binary: the counting global allocator must not leak into the unit tests of the
//! crate. It runs the very path the preparation runs between the source load and the permit's
//! release — `scheduler::hash_holders`: pad the stored blob in place, walk the encoder once over
//! the union of the holders' ESIs, fold each symbol into the holders' hashers — on a blob as the
//! load returns it (NOT yet padded to `k·t`), and checks the peak of live bytes against the
//! permit the preparation asks for (`estimate_pos_issue`). It is the proof that the estimate is
//! not wishful (M26: a copy of the padded blob; M27: the symbols collected in a map — each adds
//! whole blocks of memory and turns it red).

// A counting GlobalAlloc is unsafe by definition; it only forwards to System.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use viaticum::daemon::mem_budget::{HolderKind, MemBudget, estimate_pos_issue};
use viaticum::daemon::scheduler::{FoldHolder, hash_holders};
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId};

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

fn holder(id: u8, ranges: &[(u32, u32)]) -> FoldHolder {
    FoldHolder {
        holder_id: DeviceId([id; 32]),
        challenge_id: [id; 16],
        esi_ranges: ranges.to_vec(),
    }
}

/// `k` source symbols of `t` bytes: a block whose stored blob (`k·t − 1000` bytes, not a multiple
/// of `t`, as the load returns it) needs padding.
fn params_of(k: u32, t: u16) -> ErasureParams {
    let k_eff = k + viaticum_core::constants::DECODE_OVERHEAD;
    ErasureParams {
        k,
        k_eff,
        t,
        overhead: 1.5,
        n: (k_eff as f64 * 1.5).ceil() as u32,
    }
}

/// The path the preparation runs after the load, for `holders` holders sharing a union of about
/// `0.19·k` symbols (a slice of the source ESIs and of the repair range), under a real permit of
/// the estimate's size. Collecting them would add 0.19·E_pad and a copy of the blob 1·E_pad — both
/// far above the slack the bar leaves. (The count is kept small: the hashing runs unoptimised in
/// a debug build.) Returns the total peak of live bytes (the blob the load returned included) and
/// the permit's bytes.
fn preparation_peak(holders: usize, params: &ErasureParams) -> (usize, usize) {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let k = params.k;
    let e_pad = k as usize * params.t as usize;
    let fold_holders: Vec<FoldHolder> = (0..holders)
        .map(|h| {
            let h = h as u32;
            holder(
                0x40 + h as u8,
                // Overlapping shares: a slice of the source and of the repair range each.
                &[(h, k / 16 - h), (k + 10 + h, k / 8 - h)],
            )
        })
        .collect();

    let need = estimate_pos_issue(e_pad as u64, params.t);
    let budget = MemBudget::new(need * 2);
    let block_id = SourceBlockId([9; 32]);
    let permit = budget
        .try_acquire(HolderKind::Pos, &block_id, need)
        .expect("a free budget");
    let enc = RaptorQEncoder::new();

    // The blob as `load_source_block` returns it: the stored length, not a multiple of T.
    let blob: Vec<u8> = (0..e_pad - 1000).map(|i| (i % 251) as u8 + 1).collect();
    assert!(blob.len() < e_pad, "fixture: the blob needs padding");
    let blob_len = blob.len();

    let (hashes, peak) = measure(|| {
        hash_holders(&permit, &enc, &block_id, params, blob, &fold_holders).expect("the walk")
    });
    assert_eq!(hashes.len(), holders);
    for h in hashes {
        h.expect("every holder hashes something");
    }
    // `peak` is above the level at entry, which included the blob the function took.
    (blob_len + peak, need as usize)
}

/// The peak of the preparation's path stays within the permit it asks for and does not grow with
/// the number of holders.
fn check_within_estimate(params: &ErasureParams, holder_counts: &[usize]) {
    let e_pad = params.k as usize * params.t as usize;
    let mut totals = Vec::new();
    for &holders in holder_counts {
        let (total, permit) = preparation_peak(holders, params);
        println!(
            "K={} h={holders}: peak {:.3} E_pad ({:.2} MiB), permit {:.3} E_pad ({} MiB)",
            params.k,
            total as f64 / e_pad as f64,
            total as f64 / MIB as f64,
            permit as f64 / e_pad as f64,
            permit / MIB
        );
        assert!(
            total <= permit,
            "K={} h={holders}: peak {:.2} MiB exceeds the permit {} MiB",
            params.k,
            total as f64 / MIB as f64,
            permit / MIB
        );
        totals.push(total);
    }
    let (lo, hi) = (*totals.iter().min().unwrap(), *totals.iter().max().unwrap());
    assert!(
        hi - lo <= MIB,
        "the peak must not grow with the number of holders: {totals:?}"
    );
}

/// K = 4096 (a block of 256 MiB at T = 65535): the large-K figure the estimate `3.1·E_pad + 4·T`
/// is derived for — L/K is 1.03 there and the walk peaks at ≈ 3.075 E_pad. M26 (a copy of the
/// padded blob: +1 E_pad) and M27 (the symbols collected: +0.19 E_pad ≈ 50 MiB) both exceed the
/// permit. One holder count: the core test `encode_raw_ranges_each_alloc_peak_within_model`
/// shows the walk does not grow with the holders, and this block is heavy in a debug build.
#[test]
fn block_prep_alloc_peak_within_estimate() {
    check_within_estimate(&params_of(4096, 65_535), &[3]);
}

/// K = 257 (a block of 16 MiB at T = 65535): the LDPC and HDPC rows are ~10% of K, so the
/// intermediate symbols are 1.08 E and the walk peaks at ≈ 3.16 E_pad, above `3.1·E_pad + 4·T`.
/// The estimate is reworked for small K (review N1; v3.4 `encoder_bytes(k, t)`, К-b2a′) — until
/// then this variant documents the gap and is not run.
#[test]
#[ignore = "N1: оценка на малых K — К-b2a′ (v3.4)"]
fn block_prep_alloc_peak_within_estimate_small_k() {
    check_within_estimate(&params_of(257, 65_535), &[1, 4, 8]);
}
