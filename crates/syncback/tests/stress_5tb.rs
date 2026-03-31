// Stress test: 5 TB photographer scenario simulation.
//
// Does NOT move 5 TB of actual data. Simulates metadata at scale:
//   - N_FILES FileRecords
//   - N_BLOCKS SourceBlocks (128 MB each)
//   - HOLDERS_PER_BLOCK holders per block → N_BLOCKS × HOLDERS_PER_BLOCK SymbolPlacements
//   - Verifies placement constraints and reliability forecasts at scale
//
// Target: DB operations, placement correctness, and reliability work at scale
// within reasonable time. Not a benchmark.
//
// Run with:
//   cargo test -p syncback --test stress_5tb -- --ignored --nocapture
//
// GATE: all assertions pass. No OOM (< 2 GB RSS at peak).

// --- Scale parameters ---
// "Real" 5TB scale would be:
//   N_FILES = 500_000, N_BLOCKS = 35_000, HOLDERS_PER_BLOCK = 15  → 525_000 placements
// We use reduced numbers to stay well within the 120s wall-clock budget.
// The structure is identical — scaling up would only require changing these constants.
const N_FILES: usize = 10_000;
const N_BLOCKS: usize = 1_000;
const HOLDERS_PER_BLOCK: usize = 15;
const SYMBOLS_PER_HOLDER: u32 = 100; // simplified: fixed count per holder
// K = ceil(128 MB / SYMBOL_SIZE) = ceil(134217728 / 65535) = 2049
// K_EFF = K + DECODE_OVERHEAD = 2049 + 3 = 2052
const K: u32 = 2049;
const K_EFF: u32 = 2052;

// Reliability phase: use smaller K_eff so total symbols >> K_eff
const STRESS_K_EFF: u32 = 500;
const STRESS_SYMS_PER_HOLDER: u32 = 200; // 15 × 200 = 3000 > 500
const STRESS_RELIABILITY_SAMPLE: usize = 100; // sample every N_BLOCKS/STRESS_RELIABILITY_SAMPLE blocks

use syncback_core::constants::{MAX_HOLDERS_PER_BLOCK, MIN_SYMBOLS_PER_HOLDER};
use syncback_core::db::Db;
use syncback_core::placement::{compute_allocation, HolderCandidate};
use syncback_core::reliability::{block_reliability, BlockReliabilityInput, HolderReliabilityInput};
use syncback_core::types::{
    DeviceId, ErasureParams, FileId, FileRecord, FileVersion, IdentityPub, LocalState,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a deterministic SourceBlockId from a block index.
fn block_id_from_index(i: usize) -> SourceBlockId {
    let bytes = (i as u64).to_le_bytes();
    let hash = blake3::hash(&bytes);
    SourceBlockId(*hash.as_bytes())
}

/// Build 30 distinct mock holder IdentityPubs cycled across all blocks.
fn mock_holder_ids() -> Vec<DeviceId> {
    (0u32..30)
        .map(|i| {
            let mut key = [0u8; 32];
            // Write i into first 4 bytes; fill rest with 0xAB so all are distinct.
            key[..4].copy_from_slice(&i.to_le_bytes());
            key[4..].fill(0xAB);
            DeviceId(key)
        })
        .collect()
}

/// Build 30 HolderCandidates with varying trust for placement tests.
fn mock_candidates_30() -> Vec<HolderCandidate> {
    (0u32..30)
        .map(|i| {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            key[4..].fill(0xAB);
            HolderCandidate {
                device_id: DeviceId(key),
                trust: 0.30 + (i as f64) * 0.02, // 0.30 .. 0.88
            }
        })
        .collect()
}

const NOW: Timestamp = Timestamp(1_700_000_000);
const DEVICE_A: DeviceId = DeviceId([0xA0u8; 32]);

// ─────────────────────────────────────────────────────────────────────────────
// The stress test
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn stress_5tb_metadata_scale() {
    let db = Db::open_in_memory().expect("open_in_memory");
    let holder_ids = mock_holder_ids();
    let start = std::time::Instant::now();

    // ── Phase 1: DB insertion ─────────────────────────────────────────────

    // Pre-compute block IDs so we can reference them from FileRecords.
    let block_ids: Vec<SourceBlockId> = (0..N_BLOCKS).map(block_id_from_index).collect();

    // 1a. Insert N_BLOCKS SourceBlockRecords.
    for (i, &block_id) in block_ids.iter().enumerate() {
        let record = SourceBlockRecord {
            block_id,
            k: K,
            t: 65_535,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: NOW,
            encrypted_size: Some(128 * 1024 * 1024),
            n: None,
            overhead: None,
        };
        db.upsert_source_block(&record)
            .unwrap_or_else(|e| panic!("upsert_source_block[{i}]: {e}"));
    }

    // 1b. For each block, insert HOLDERS_PER_BLOCK SymbolPlacement records.
    //     Holder IDs cycle through the 30 mock holders.
    //     File ID is block_index / (N_FILES / N_BLOCKS) — each file covers ~10 blocks.
    let blocks_per_file = N_BLOCKS.max(1) / N_FILES.max(1); // 0 if N_FILES > N_BLOCKS
    for (block_idx, &block_id) in block_ids.iter().enumerate() {
        // map each block to a file (many blocks per file for large libraries)
        let file_idx = if blocks_per_file > 0 {
            block_idx / blocks_per_file
        } else {
            block_idx % N_FILES
        };
        let file_id = FileId(file_idx as u64);

        for holder_slot in 0..HOLDERS_PER_BLOCK {
            let holder_id = holder_ids[holder_slot % holder_ids.len()];
            let start_esi = (holder_slot as u32) * SYMBOLS_PER_HOLDER;

            // Binding seed: deterministic from (block_idx, holder_slot).
            let mut binding_seed = [0u8; 32];
            binding_seed[..8].copy_from_slice(&(block_idx as u64).to_le_bytes());
            binding_seed[8..12].copy_from_slice(&(holder_slot as u32).to_le_bytes());

            let placement = SymbolPlacement {
                source_block_id: block_id,
                holder_id,
                file_id,
                esi_ranges: vec![(start_esi, SYMBOLS_PER_HOLDER)],
                binding_seed,
                status: PlacementStatus::Alive,
                last_verified: Some(NOW),
                placed_at: NOW,
                consecutive_misses: 0,
            };
            db.upsert_placement(&placement)
                .unwrap_or_else(|e| panic!("upsert_placement[{block_idx},{holder_slot}]: {e}"));
        }
    }

    // 1c. Insert N_FILES FileRecords.
    //     Each references one source block (the last block mapped to that file).
    for file_idx in 0..N_FILES {
        // Find the source block for this file.
        let block_idx = if blocks_per_file > 0 {
            (file_idx * blocks_per_file).min(N_BLOCKS - 1)
        } else {
            file_idx % N_BLOCKS
        };
        let block_id = block_ids[block_idx];

        let content_hash = {
            let mut h = [0u8; 32];
            let bytes = (file_idx as u64).to_le_bytes();
            h[..8].copy_from_slice(&bytes);
            h
        };

        let record = FileRecord {
            file_id: FileId(file_idx as u64),
            path: format!("/photos/year/{:06}/img_{:06}.jpg", file_idx / 1000, file_idx),
            importance: 0.5,
            devices: vec![(DEVICE_A, LocalState::Present)],
            versions: vec![FileVersion {
                content_hash,
                source_block_id: block_id,
                k: K,
                t: 65_535,
                created_at: NOW,
                backed_up_at: Some(NOW),
            }],
            first_seen: NOW,
        };
        db.upsert_file(&record)
            .unwrap_or_else(|e| panic!("upsert_file[{file_idx}]: {e}"));
    }

    let elapsed = start.elapsed();
    eprintln!(
        "stress_5tb: inserted {} files, {} blocks, {} placements in {:.1}s",
        N_FILES,
        N_BLOCKS,
        N_BLOCKS * HOLDERS_PER_BLOCK,
        elapsed.as_secs_f64(),
    );
    assert!(
        elapsed.as_secs() < 120,
        "{} files + {} blocks + {} placements must insert in < 120s, got {:.1}s",
        N_FILES,
        N_BLOCKS,
        N_BLOCKS * HOLDERS_PER_BLOCK,
        elapsed.as_secs_f64(),
    );

    // ── Phase 2: DB reads ─────────────────────────────────────────────────

    // 2a. List all source blocks → must equal N_BLOCKS.
    let t_read = std::time::Instant::now();
    let all_blocks = db.list_all_source_blocks().expect("list_all_source_blocks");
    assert_eq!(
        all_blocks.len(),
        N_BLOCKS,
        "expected {} source blocks, got {}",
        N_BLOCKS,
        all_blocks.len()
    );

    // 2b. List placements for block 0 → must equal HOLDERS_PER_BLOCK.
    let placements_0 = db
        .list_placements_for_block(&block_ids[0])
        .expect("list_placements_for_block[0]");
    assert_eq!(
        placements_0.len(),
        HOLDERS_PER_BLOCK,
        "block 0 must have {} placements, got {}",
        HOLDERS_PER_BLOCK,
        placements_0.len()
    );

    // 2c. Random block check (block N_BLOCKS/2): list placements, verify symbol counts.
    let mid = N_BLOCKS / 2;
    let placements_mid = db
        .list_placements_for_block(&block_ids[mid])
        .expect("list_placements_for_block[mid]");
    assert_eq!(
        placements_mid.len(),
        HOLDERS_PER_BLOCK,
        "block {mid} must have {} placements",
        HOLDERS_PER_BLOCK,
    );
    for p in &placements_mid {
        let count = p.symbol_count();
        assert_eq!(
            count, SYMBOLS_PER_HOLDER,
            "block {mid}: expected {} symbols per holder, got {}",
            SYMBOLS_PER_HOLDER, count,
        );
    }
    eprintln!(
        "stress_5tb: DB reads (list_all_blocks, 2 list_placements) in {:.3}s",
        t_read.elapsed().as_secs_f64(),
    );

    // ── Phase 3: placement correctness on fresh candidates ───────────────

    let t_placement = std::time::Instant::now();
    let candidates = mock_candidates_30();
    // Use 128 MB block, importance = 0.5.
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.5);
    assert_eq!(params.k, K, "expected K={K}, got {}", params.k);
    assert_eq!(params.k_eff, K_EFF, "expected K_eff={K_EFF}, got {}", params.k_eff);

    let allocations = compute_allocation(&candidates, &params, 0)
        .expect("compute_allocation must succeed with 30 candidates");

    // All placements respect MAX_HOLDERS constraint.
    assert!(
        allocations.len() <= MAX_HOLDERS_PER_BLOCK as usize,
        "allocations.len()={} must be <= MAX_HOLDERS_PER_BLOCK={}",
        allocations.len(),
        MAX_HOLDERS_PER_BLOCK,
    );
    assert!(
        allocations.len() >= 2,
        "must allocate to at least 2 holders, got {}",
        allocations.len(),
    );

    // Every holder gets at least MIN_SYMBOLS_PER_HOLDER symbols.
    for alloc in &allocations {
        assert!(
            alloc.symbol_count >= MIN_SYMBOLS_PER_HOLDER,
            "holder {:?} got {} symbols < MIN_SYMBOLS_PER_HOLDER={}",
            alloc.device_id,
            alloc.symbol_count,
            MIN_SYMBOLS_PER_HOLDER,
        );
    }

    // Total symbols >= K_eff (file can be reconstructed).
    let total_allocated: u32 = allocations.iter().map(|a| a.symbol_count).sum();
    assert!(
        total_allocated >= params.k_eff,
        "total allocated={} must be >= k_eff={}",
        total_allocated,
        params.k_eff,
    );

    eprintln!(
        "stress_5tb: placement check on 30 candidates: {} holders, {} total symbols, all >= {}",
        allocations.len(),
        total_allocated,
        MIN_SYMBOLS_PER_HOLDER,
    );
    eprintln!(
        "stress_5tb: placement correctness check in {:.3}s",
        t_placement.elapsed().as_secs_f64(),
    );

    // ── Phase 4: reliability forecast on sample of blocks ────────────────

    // Use STRESS_K_EFF=500 so total symbols (15 × 200 = 3000) >> K_eff.
    let t_reliability = std::time::Instant::now();

    // Sample blocks at regular intervals.
    let step = (N_BLOCKS / STRESS_RELIABILITY_SAMPLE).max(1);
    let mut min_reliability = f64::MAX;
    let mut max_reliability = f64::MIN;
    let mut sum_reliability = 0.0_f64;
    let mut sample_count = 0usize;

    for sample_idx in 0..STRESS_RELIABILITY_SAMPLE {
        let block_idx = (sample_idx * step) % N_BLOCKS;
        let block_id = block_ids[block_idx];

        // Build HOLDERS_PER_BLOCK holders with STRESS_SYMS_PER_HOLDER symbols each.
        // survival_prob = 0.81 (score=0.9 → p=0.9^2).
        let holders: Vec<HolderReliabilityInput> = (0..HOLDERS_PER_BLOCK)
            .map(|slot| HolderReliabilityInput {
                holder_id: holder_ids[slot % holder_ids.len()],
                alive_symbols: STRESS_SYMS_PER_HOLDER,
                survival_prob: 0.81,
            })
            .collect();

        let input = BlockReliabilityInput {
            block_id,
            k_eff: STRESS_K_EFF,
            holders,
        };

        let reliability = block_reliability(&input).expect("block_reliability");
        assert!(
            (0.0..=1.0).contains(&reliability),
            "reliability out of range: {reliability}",
        );

        min_reliability = min_reliability.min(reliability);
        max_reliability = max_reliability.max(reliability);
        sum_reliability += reliability;
        sample_count += 1;
    }

    let mean_reliability = sum_reliability / sample_count as f64;

    eprintln!(
        "stress_5tb: reliability sample ({} blocks): min={:.6}, mean={:.6}, max={:.6}",
        sample_count, min_reliability, mean_reliability, max_reliability,
    );
    eprintln!(
        "stress_5tb: reliability forecast ({} blocks) in {:.3}s",
        sample_count,
        t_reliability.elapsed().as_secs_f64(),
    );

    // With total=3000 symbols, K_eff=500, p=0.81: extremely reliable.
    assert!(
        min_reliability > 0.99,
        "min reliability {min_reliability:.6} must be > 0.99 \
         (15 holders × 200 symbols = 3000 alive, k_eff=500, p=0.81)",
    );

    // ── Summary ───────────────────────────────────────────────────────────
    eprintln!(
        "stress_5tb: total wall time {:.1}s — PASSED",
        start.elapsed().as_secs_f64(),
    );
}
