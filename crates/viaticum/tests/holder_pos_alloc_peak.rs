//! Allocation peak of the holder's PoS answer (К-b4, pos-i14, spec v3.10 §3, v3.10a).
//!
//! A separate test binary: the counting global allocator must not leak into the unit tests of
//! the crate. It runs the very path the daemon runs — `PosResponder::compute_response` over a
//! real share on disk, the read-and-hash on the blocking pool — and checks the peak of live
//! bytes the answer adds against the model of the spec: one symbol buffer T, the list of ESIs
//! 4·n, plus δ = 16 KiB for what is not the share (the path, the file, the hasher, the task, the
//! signed reply). The bar has no further slack:
//!
//!   n = 64:   T + 4·n + δ = 82 175 B      n = 1024: T + 4·n + δ = 86 015 B   (T = 65 535)
//!
//! and the peak must not depend on the share: `peak(1024) − peak(64) ≤ 4·960 + δ`.
//! M15 (the symbols collected in a `Vec`: ≈ 64 MiB at n = 1024) and M77 (a new buffer per symbol,
//! none let go: the peak grows with n) turn it red.
//!
//! The blocking pool's thread (its birth and its thread-local state) and one answer are warmed up
//! before the measurement: they are not the answer's memory.

// A counting GlobalAlloc is unsafe by definition; it only forwards to System.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use viaticum::daemon::processor::PosResponder;
use viaticum_core::db::Db;
use viaticum_core::messages::{Message, build_pos_hash_challenge};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp, hex_encode,
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

/// Bytes of a symbol: the T of the product (`SYMBOL_SIZE`, a bound symbol is exactly T).
const T: usize = 65_535;
/// δ: what the answer holds that is neither the buffer nor the ESI list (v3.10 §3).
const DELTA: usize = 16 * 1024;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// A holder of `n` symbols of T bytes for one owner: the responder, the challenge for all of them.
struct Fixture {
    _dir: tempfile::TempDir,
    responder: PosResponder,
    owner: IdentityPub,
    challenge: viaticum_core::messages::PosHashChallengeMsg,
}

fn fixture(n: u32) -> Fixture {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x71u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x72; 32]);
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, n)],
        importance: 0.5,
        total_bytes: n as u64 * T as u64,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
    let block_dir = dir.path().join(hex_encode(&block_id.0));
    std::fs::create_dir_all(&block_dir).unwrap();
    for esi in 0..n {
        let symbol: Vec<u8> = (0..T).map(|i| (i as u32 ^ esi) as u8).collect();
        std::fs::write(block_dir.join(format!("{esi}.bin")), symbol).unwrap();
    }
    let device_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let responder = PosResponder::new(
        db,
        dir.path().to_path_buf(),
        device_key,
        IdentityPub([0xABu8; 32]),
        None,
    );
    let challenge = build_pos_hash_challenge(
        [0x73; 16],
        block_id,
        vec![(0, n)],
        Timestamp::now(),
        device_id,
        &owner_key,
    );
    Fixture {
        _dir: dir,
        responder,
        owner,
        challenge,
    }
}

/// The peak of live bytes one answer adds, over `n` symbols, after the warm-up.
fn answer_peak(n: u32) -> usize {
    let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let f = fixture(n);
    // Warm-up: the blocking pool's thread is born, and one answer runs (the database's and the
    // signature's lazy state), neither counted in the peak.
    rt.block_on(async {
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        let reply = f
            .responder
            .compute_response(f.owner, f.challenge.clone())
            .await
            .expect("the warm-up answer");
        assert!(matches!(reply, Message::PosHashResponse(_)));
    });

    let challenge = f.challenge.clone();
    let base = live();
    PEAK.store(base, Ordering::Relaxed);
    let reply = rt
        .block_on(f.responder.compute_response(f.owner, challenge))
        .expect("the answer");
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(base);
    assert!(matches!(reply, Message::PosHashResponse(_)));
    peak
}

#[test]
fn holder_pos_answer_alloc_peak_within_model() {
    let mut peaks = Vec::new();
    for n in [64u32, 1024] {
        let peak = answer_peak(n);
        let model = T + 4 * n as usize;
        let bar = model + DELTA;
        println!("n={n}: peak {peak} B, model {model} B, bar {bar} B");
        assert!(
            peak <= bar,
            "n={n}: the answer's peak {peak} B is above the bar {bar} B (model {model} B)"
        );
        peaks.push(peak);
    }
    assert!(
        peaks[1].saturating_sub(peaks[0]) <= 4 * (1024 - 64) + DELTA,
        "the peak must not grow with the share: {peaks:?}"
    );
}
