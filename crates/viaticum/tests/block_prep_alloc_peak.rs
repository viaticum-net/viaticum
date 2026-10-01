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

use viaticum::daemon::backup::pipeline::compress_and_encrypt;
use viaticum::daemon::mem_budget::{
    HolderKind, MemBudget, encode_block, estimate_pos_issue, estimate_restore_network,
    estimate_restore_plaintext,
};
use viaticum::daemon::restore::staging::{JobId, StagingWriter};
use viaticum::daemon::restore::{decode_decrypt_stage, member_bytes, plaintext_stage};
use viaticum::daemon::scheduler::{FoldHolder, hash_holders};
use viaticum_core::erasure::{RaptorQEncoder, pad_for_encoding};
use viaticum_core::types::{
    DeviceId, ErasureParams, FileId, FileRecord, FileVersion, SourceBlockId, SourceBlockType,
    Timestamp,
};

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

    let need = estimate_pos_issue(params.k, params.t);
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

/// K = 4096 (a block of 256 MiB at T = 65535): L/K is 1.04 there and the walk peaks at ≈ 3.076
/// E_pad against a permit of `k·t + encoder_bytes + 4·T` ≈ 3.09 E_pad. M26 (a copy of the padded
/// blob: +1 E_pad) and M27 (the symbols collected: +0.19 E_pad ≈ 50 MiB) both exceed the permit.
/// One holder count: that the walk does not grow with the holders is checked by the core test
/// `encode_raw_ranges_each_peak_does_not_depend_on_holders`; this block is heavy in debug.
#[test]
fn block_prep_alloc_peak_within_estimate() {
    check_within_estimate(&params_of(4096, 65_535), &[3]);
}

/// K = 257 (a block of 16 MiB at T = 65535): the LDPC and HDPC rows are ~10% of K, so the
/// intermediate symbols are 1.15 E and the walk peaks at ≈ 3.19 E_pad. The permit is the
/// function of K (`estimate_pos_issue`: the input, `encoder_bytes(k, t)` from the RFC 6330 table,
/// four symbol buffers) — 3.217 E_pad, no slack added to make it pass (v3.4 N1).
#[test]
fn block_prep_alloc_peak_within_estimate_small_k() {
    check_within_estimate(&params_of(257, 65_535), &[1, 4, 8]);
}

// ─── Restore, the network tier (К-b3, restore-i39; spec v3.8 §3, v3.9 WARN-2) ───────────────────────
//
// The very stages the restore runs on the blocking pool (`decode_decrypt_stage`, `plaintext_stage`),
// each under a permit of the size the coordinator holds for it, on a block whose plaintext is four
// times its encrypted size (compressible: S ≈ 4E). The base of the counting allocator is taken
// BEFORE the symbols exist — the fixture makes them inside the measurement, as the fetch does — and
// every stage is judged by the ABSOLUTE live bytes above it against the permit of that stage:
//   decode stage     ≤ estimate_restore_network  + δ   (includes the k_eff·T of symbols in hand)
//   plaintext stage  ≤ estimate_restore_plaintext + δ   (the compressed block and the plaintext)
// M59 (the symbols kept alive into the plaintext stage: +E) and M60 (`decode_all` instead of the
// exact allocation: up to 2S) both exceed the second.

fn reset_peak() {
    PEAK.store(live(), Ordering::Relaxed);
}

/// `len` bytes that compress about four to one at zstd's level 3: per 64 KiB, 16 KiB of noise
/// and the same 16 KiB three more times (within the window).
fn compressible_plaintext(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut chunk = Vec::with_capacity(16 * 1024);
        for _ in 0..16 * 1024 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.push((state >> 32) as u8);
        }
        for _ in 0..4 {
            out.extend_from_slice(&chunk);
        }
    }
    out.truncate(len);
    out
}

#[test]
fn restore_network_peak_follows_the_permit() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let key = [42u8; 32];
    let block = SourceBlockId([5; 32]);
    let budget = MemBudget::new(4 << 30);
    let enc = RaptorQEncoder::new();

    let base = live();
    // The fixture: what the fetch hands over — the raw symbols, ESIs from the repair range (the
    // worst case of the decode) — made inside the measurement; everything else of it is gone
    // before the stages run.
    let (symbols, params, encrypted_size, want_hash, plain_len) = {
        let plaintext = compressible_plaintext(64 << 20);
        let want_hash = blake3::hash(&plaintext);
        let plain_len = plaintext.len() as u64;
        let mut stored = compress_and_encrypt(&plaintext, &key).unwrap();
        drop(plaintext);
        let encrypted_size = stored.len() as u64;
        let params = ErasureParams::compute(encrypted_size, 1.0).unwrap();
        assert!(
            (256..=260).contains(&params.k),
            "fixture: a block of about 16 MiB (K = {})",
            params.k
        );
        pad_for_encoding(&mut stored, &params);
        let permit = budget
            .try_acquire(HolderKind::Restore, &block, 2 << 30)
            .unwrap();
        let symbols =
            encode_block(&permit, &enc, &stored, &params, &[(params.k, params.k_eff)]).unwrap();
        (symbols, params, encrypted_size, want_hash, plain_len)
    };
    let e_pad = params.k as usize * params.t as usize;
    let delta = e_pad / 50;
    println!(
        "fixture: E = {:.4} E_pad, S = {:.4} E_pad, symbols in hand {:.4} E_pad",
        encrypted_size as f64 / e_pad as f64,
        plain_len as f64 / e_pad as f64,
        (live() - base) as f64 / e_pad as f64,
    );

    // Stage one: decode, decrypt, count — under the decode permit.
    let permit = budget
        .try_acquire(
            HolderKind::Restore,
            &block,
            estimate_restore_network(params.k, params.t),
        )
        .unwrap();
    reset_peak();
    let decrypted = decode_decrypt_stage(
        &permit,
        &enc,
        symbols,
        &params,
        encrypted_size,
        &key,
        &block,
    )
    .expect("the decode stage");
    let peak_one = PEAK.load(Ordering::Relaxed) - base;
    println!(
        "decode stage: permit {:.4} E_pad bar {:.4} measured {:.4} (E_pad units)",
        permit.bytes() as f64 / e_pad as f64,
        (permit.bytes() as usize + delta) as f64 / e_pad as f64,
        peak_one as f64 / e_pad as f64,
    );
    assert!(
        peak_one <= permit.bytes() as usize + delta,
        "decode stage: {:.4} E_pad live above the base, the permit holds {:.4} (+ delta {:.4})",
        peak_one as f64 / e_pad as f64,
        permit.bytes() as f64 / e_pad as f64,
        delta as f64 / e_pad as f64,
    );
    assert_eq!(decrypted.plaintext_len, plain_len, "the counted length");
    drop(permit);

    // Stage two: the plaintext — under the permit cut to (or taken again for) it.
    let need =
        estimate_restore_plaintext(decrypted.compressed.len() as u64, decrypted.plaintext_len);
    let permit = budget
        .try_acquire(HolderKind::Restore, &block, need)
        .unwrap();
    reset_peak();
    let plaintext = plaintext_stage(&permit, &block, decrypted).expect("the plaintext stage");
    let peak_two = PEAK.load(Ordering::Relaxed) - base;
    println!(
        "plaintext stage: permit {:.4} E_pad bar {:.4} measured {:.4} (E_pad units)",
        permit.bytes() as f64 / e_pad as f64,
        (permit.bytes() as usize + delta) as f64 / e_pad as f64,
        peak_two as f64 / e_pad as f64,
    );
    assert!(
        peak_two <= permit.bytes() as usize + delta,
        "plaintext stage: {:.4} E_pad live above the base, the permit holds {:.4} (+ delta {:.4})",
        peak_two as f64 / e_pad as f64,
        permit.bytes() as f64 / e_pad as f64,
        delta as f64 / e_pad as f64,
    );
    assert_eq!(
        blake3::hash(&plaintext),
        want_hash,
        "the plaintext is the block's"
    );
}

/// M65: a single-file block is written from the slice of its plaintext — the writer makes no copy
/// of it (the memory outside the budget while the file is written is the one plaintext, not two).
#[test]
fn restore_single_writes_from_a_slice_without_a_copy() {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let plaintext = vec![0xABu8; 16 * MIB];
    let dir = tempfile::tempdir().unwrap();
    let staging_root = dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let writer = StagingWriter::open(&staging_root, dir.path(), JobId::new()).unwrap();
    let record = FileRecord {
        file_id: FileId(1),
        path: "/data/single.bin".to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    };
    let version = FileVersion {
        content_hash: *blake3::hash(&plaintext).as_bytes(),
        source_block_id: SourceBlockId([1; 32]),
        k: 256,
        t: 65_535,
        created_at: Timestamp(1),
        backed_up_at: Some(Timestamp(2)),
    };
    let validated = viaticum_core::path_safety::validate_record_path(&record.path).unwrap();

    let (path, peak) = measure(|| {
        let bytes = member_bytes(&SourceBlockType::Single, &plaintext, &record, &version)
            .expect("the whole block is the file");
        writer.write_file(&validated, bytes).unwrap()
    });

    println!(
        "single write: peak {peak} B above the plaintext (T = {} B)",
        65_535
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        plaintext.len() as u64
    );
    assert!(
        peak <= 65_535,
        "writing a single-file block allocated {peak} B: a copy of the plaintext is {} B",
        plaintext.len()
    );
}
