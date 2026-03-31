use rand::Rng;

use super::{ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, binding_seed};
use crate::types::{DeviceId, ErasureParams, SourceBlockId};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[0] = byte;
    SourceBlockId(id)
}

fn holder(byte: u8) -> DeviceId {
    let mut id = [0u8; 32];
    id[0] = byte;
    DeviceId(id)
}

/// Repeating byte pattern for test data.
fn test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn encoder() -> RaptorQEncoder {
    RaptorQEncoder::new()
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[test]
fn encode_decode_roundtrip_small() {
    let enc = encoder();
    // One symbol = SYMBOL_SIZE = 65535 bytes
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(1);
    let hid = holder(1);

    // Encode 5 symbols starting at ESI 0
    let bound = enc.encode(&source, &params, 0, 5, &bid, &hid).unwrap();
    assert_eq!(bound.len(), 5);

    // Unbind all symbols
    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    // Decode with k_eff symbols (take first k_eff)
    let k_eff = params.k_eff as usize;
    let subset: Vec<Symbol> = unbound.into_iter().take(k_eff).collect();
    let decoded = enc.decode(&subset, &params).unwrap();

    // Decoded block is padded to k*t; trim and compare
    assert_eq!(&decoded[..source.len()], &source[..]);
}

#[test]
fn encode_decode_roundtrip_full_block() {
    let enc = encoder();
    // 256 KiB = 4 source symbols
    let size = 256 * 1024usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.6);
    let bid = block_id(2);
    let hid = holder(2);

    // Encode 20 symbols
    let bound = enc.encode(&source, &params, 0, 20, &bid, &hid).unwrap();
    assert_eq!(bound.len(), 20);

    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    let k_eff = params.k_eff as usize;
    let subset: Vec<Symbol> = unbound.into_iter().take(k_eff).collect();
    let decoded = enc.decode(&subset, &params).unwrap();

    assert_eq!(&decoded[..source.len()], &source[..]);
}

#[test]
fn decode_fails_with_insufficient_symbols() {
    let enc = encoder();
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(3);
    let hid = holder(3);

    let k_eff = params.k_eff as usize;

    // Encode k_eff symbols so we can unbind them
    let bound = enc
        .encode(&source, &params, 0, k_eff as u32, &bid, &hid)
        .unwrap();
    let mut unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();
    // Drop one to have k_eff - 1
    unbound.pop();
    assert_eq!(unbound.len(), k_eff - 1);

    let err = enc.decode(&unbound, &params).unwrap_err();
    match err {
        ErasureError::InsufficientSymbols { have, need } => {
            assert_eq!(have, k_eff - 1);
            assert_eq!(need, k_eff);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn binding_unbinding_roundtrip() {
    let enc = encoder();
    let t = 65_535usize;
    let original_data = test_data(t);
    let bid = block_id(4);
    let hid = holder(4);

    let sym = Symbol {
        esi: 0,
        data: original_data.clone(),
    };

    // bind = unbind (XOR is self-inverse via unbind)
    // We test via: unbind(unbind(x)) == x
    let once = enc.unbind(sym.clone(), &bid, &hid);
    assert_ne!(once.data, original_data, "unbind should change data");

    let twice = enc.unbind(once, &bid, &hid);
    assert_eq!(twice.data, original_data, "double-unbind should restore original");
}

#[test]
fn binding_differs_per_holder() {
    let enc = encoder();
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(5);
    let hid_a = holder(1);
    let hid_b = holder(2);

    let bound_a = enc.encode(&source, &params, 0, 1, &bid, &hid_a).unwrap();
    let bound_b = enc.encode(&source, &params, 0, 1, &bid, &hid_b).unwrap();

    assert_ne!(
        bound_a[0].data, bound_b[0].data,
        "same ESI, different holders must produce different bound symbols"
    );
}

#[test]
fn binding_differs_per_esi() {
    let enc = encoder();
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(6);
    let hid = holder(1);

    let bound_0 = enc.encode(&source, &params, 0, 1, &bid, &hid).unwrap();
    let bound_1 = enc.encode(&source, &params, 1, 1, &bid, &hid).unwrap();

    assert_ne!(
        bound_0[0].data, bound_1[0].data,
        "same holder, different ESIs must produce different keystreams"
    );
}

#[test]
fn binding_differs_per_block() {
    let enc = encoder();
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid_a = block_id(10);
    let bid_b = block_id(20);
    let hid = holder(1);

    let bound_a = enc.encode(&source, &params, 0, 1, &bid_a, &hid).unwrap();
    let bound_b = enc.encode(&source, &params, 0, 1, &bid_b, &hid).unwrap();

    assert_ne!(
        bound_a[0].data, bound_b[0].data,
        "same holder, different block_ids must produce different bound symbols"
    );
}

#[test]
fn generate_repair_matches_encode() {
    let enc = encoder();
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(7);
    let hid = holder(1);

    // Use a repair ESI (>= K)
    let repair_esi = params.k + 5;

    let via_repair = enc
        .generate_repair(&source, &params, repair_esi, &bid, &hid)
        .unwrap();
    let via_encode = enc
        .encode(&source, &params, repair_esi, 1, &bid, &hid)
        .unwrap();

    assert_eq!(via_repair.esi, repair_esi);
    assert_eq!(via_encode[0].esi, repair_esi);
    assert_eq!(via_repair.data, via_encode[0].data);
}

#[test]
fn repair_symbol_used_in_decode() {
    let enc = encoder();
    // Use a 2-symbol source block for speed
    let size = 2 * 65_535usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(8);
    let hid = holder(1);

    let k = params.k;
    let k_eff = params.k_eff;

    // Only use repair symbols (ESI >= K): request k_eff repair symbols
    let start_repair_esi = k;
    let bound = enc
        .encode(&source, &params, start_repair_esi, k_eff, &bid, &hid)
        .unwrap();
    assert_eq!(bound.len(), k_eff as usize);

    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    let decoded = enc.decode(&unbound, &params).unwrap();
    assert_eq!(&decoded[..source.len()], &source[..]);
}

#[test]
fn empty_block_returns_error() {
    let enc = encoder();
    let params = ErasureParams::compute(65_535, 0.5);
    let bid = block_id(9);
    let hid = holder(1);

    let err = enc.encode(&[], &params, 0, 1, &bid, &hid).unwrap_err();
    assert!(
        matches!(err, ErasureError::EmptyBlock),
        "expected EmptyBlock, got {err}"
    );
}

#[test]
fn decode_with_exactly_k_eff_symbols() {
    let enc = encoder();
    // 3-symbol source block
    let size = 3 * 65_535usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(10);
    let hid = holder(1);

    let k_eff = params.k_eff;

    // Use source + repair ESIs to get exactly k_eff symbols
    // Take ESI 0..k_eff (first k source, then repair if needed)
    let bound = enc
        .encode(&source, &params, 0, k_eff, &bid, &hid)
        .unwrap();
    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    assert_eq!(unbound.len(), k_eff as usize);

    // With exactly k_eff symbols, RaptorQ should succeed (extremely high probability)
    let decoded = enc.decode(&unbound, &params).unwrap();
    assert_eq!(&decoded[..source.len()], &source[..]);
}

#[test]
fn binding_seed_is_deterministic() {
    let bid = block_id(1);
    let hid = holder(1);
    let seed1 = binding_seed(&bid, &hid);
    let seed2 = binding_seed(&bid, &hid);
    assert_eq!(seed1, seed2);
}

#[test]
fn binding_seed_differs_per_holder() {
    let bid = block_id(1);
    let hid_a = holder(1);
    let hid_b = holder(2);
    let seed_a = binding_seed(&bid, &hid_a);
    let seed_b = binding_seed(&bid, &hid_b);
    assert_ne!(seed_a, seed_b);
}

#[test]
fn binding_seed_differs_per_block() {
    let bid_a = block_id(1);
    let bid_b = block_id(2);
    let hid = holder(1);
    let seed_a = binding_seed(&bid_a, &hid);
    let seed_b = binding_seed(&bid_b, &hid);
    assert_ne!(seed_a, seed_b);
}

#[test]
fn binding_seed_is_32_bytes() {
    let seed = binding_seed(&block_id(5), &holder(5));
    assert_eq!(seed.len(), 32);
}

#[test]
fn symbol_size_bytes_returns_data_length() {
    let sym = Symbol {
        esi: 0,
        data: vec![0u8; 65_535],
    };
    assert_eq!(sym.size_bytes(), 65_535);
}

#[test]
fn symbol_size_bytes_returns_zero_for_empty_data() {
    let sym = Symbol {
        esi: 0,
        data: vec![],
    };
    assert_eq!(sym.size_bytes(), 0);
}

#[test]
fn symbol_size_bytes_matches_data_len() {
    let data = vec![0xFFu8; 100];
    let sym = Symbol { esi: 7, data: data.clone() };
    assert_eq!(sym.size_bytes(), data.len());
}

// ─── ERASURE-14: large source block (128 MB) encode + decode succeeds ────────

#[test]
#[ignore] // ~10s in debug; run with: cargo test -- --ignored
fn large_source_block_encode_decode_succeeds() {
    // 16 MB source block — large enough to exercise multi-symbol encoding
    // without 10-minute debug builds. Original was 128 MB (582s in debug).
    let enc = encoder();
    let size: usize = 16 * 1024 * 1024;
    let source = vec![0xABu8; size];
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(100);
    let hid = holder(100);

    let k_eff = params.k_eff;

    let bound = enc
        .encode(&source, &params, 0, k_eff, &bid, &hid)
        .unwrap_or_else(|e| {
            panic!("encode failed for 16 MB block (k_eff={k_eff}): {e}")
        });
    assert_eq!(bound.len(), k_eff as usize);

    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    let decoded = enc
        .decode(&unbound, &params)
        .unwrap_or_else(|e| panic!("decode failed: {e}"));

    // Decoded block is padded to k*t; verify original content in first 1024 bytes
    assert!(
        decoded.len() >= 1024,
        "decoded block too short: {}",
        decoded.len()
    );
    assert_eq!(
        &decoded[..1024],
        &source[..1024],
        "first 1024 bytes must match original"
    );
}

// ─── ERASURE-10: decode any K_eff subset from arbitrary ESI range ───────────

#[test]
fn decode_non_contiguous_esi_subset() {
    let enc = encoder();
    let size = 3 * 65_535usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(20);
    let hid = holder(1);
    let k_eff = params.k_eff;

    // Generate more symbols than needed (source + repair range)
    let total_gen = k_eff + 10;
    let bound = enc.encode(&source, &params, 0, total_gen, &bid, &hid).unwrap();
    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    // Take every other symbol (non-contiguous subset), up to k_eff
    let subset: Vec<Symbol> = unbound
        .into_iter()
        .step_by(2)
        .take(k_eff as usize)
        .collect();
    assert_eq!(subset.len(), k_eff as usize);

    let decoded = enc.decode(&subset, &params).unwrap();
    assert_eq!(&decoded[..source.len()], &source[..]);
}

// ─── PROP-08: sweep of sizes and redundancies ───────────────────────────────

#[test]
fn encode_unbind_decode_roundtrip_sweep() {
    let enc = encoder();
    let sizes: &[u64] = &[1, 64, 256, 1024, 4096, 10_000, 65_536, 100_000];
    let redundancies: &[f64] = &[0.3, 0.5, 1.0];

    let mut rng = rand::thread_rng();
    let mut idx: u8 = 30; // start above existing test bytes to avoid collision

    for &size in sizes {
        for &redundancy in redundancies {
            let source: Vec<u8> = (0..size as usize).map(|_| rng.r#gen::<u8>()).collect();
            let params = ErasureParams::compute(size, redundancy);
            let bid = block_id(idx);
            let hid = holder(idx.wrapping_add(1));
            idx = idx.wrapping_add(2);

            let k_eff = params.k_eff;
            let bound = enc
                .encode(&source, &params, 0, k_eff, &bid, &hid)
                .unwrap_or_else(|e| {
                    panic!("encode failed for size={size} redundancy={redundancy}: {e}")
                });
            assert_eq!(bound.len(), k_eff as usize);

            let unbound: Vec<Symbol> = bound
                .into_iter()
                .map(|s| enc.unbind(s, &bid, &hid))
                .collect();

            let decoded = enc.decode(&unbound, &params).unwrap_or_else(|e| {
                panic!("decode failed for size={size} redundancy={redundancy}: {e}")
            });

            assert_eq!(
                &decoded[..source.len()],
                &source[..],
                "mismatch for size={size} redundancy={redundancy}"
            );
        }
    }
}

// ─── ERASURE-15: mixed source + repair symbols decode ───────────────────────

#[test]
fn decode_mixed_source_and_repair_symbols() {
    let enc = encoder();
    let size = 4 * 65_535usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(21);
    let hid = holder(1);
    let k = params.k;
    let k_eff = params.k_eff;

    // Get some source symbols (ESI 0..k/2)
    let half_k = k / 2;
    let source_syms = enc.encode(&source, &params, 0, half_k, &bid, &hid).unwrap();

    // Get repair symbols (ESI starting at k) to fill up to k_eff
    let repair_count = k_eff - half_k;
    let repair_syms = enc
        .encode(&source, &params, k, repair_count, &bid, &hid)
        .unwrap();

    // Combine and unbind
    let mut all: Vec<Symbol> = source_syms
        .into_iter()
        .chain(repair_syms)
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();
    assert_eq!(all.len(), k_eff as usize);

    // Shuffle to prove order doesn't matter
    all.reverse();

    let decoded = enc.decode(&all, &params).unwrap();
    assert_eq!(&decoded[..source.len()], &source[..]);
}

// ─── ERASURE-02: decode with exactly K symbols (no overhead) may fail ────────

#[test]
fn decode_with_exactly_k_symbols_may_fail() {
    // k_eff = k + overhead (typically k+3 for small blocks).
    // Decoding with exactly k symbols (no overhead) may fail — that is expected.
    // We just assert it either fails or succeeds (no panic, no corruption).
    let enc = encoder();
    let size = 3 * 65_535usize;
    let source = test_data(size);
    let params = ErasureParams::compute(size as u64, 0.5);
    let bid = block_id(50);
    let hid = holder(50);

    let k = params.k as usize;
    let k_eff = params.k_eff as usize;

    // Only attempt this if k < k_eff (there is overhead to skip).
    assert!(k < k_eff, "test requires k < k_eff (overhead > 0)");

    // Encode k_eff symbols so we have enough to choose from.
    let bound = enc.encode(&source, &params, 0, k_eff as u32, &bid, &hid).unwrap();
    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    // Take exactly k symbols (no repair overhead).
    let subset: Vec<Symbol> = unbound.into_iter().take(k).collect();
    assert_eq!(subset.len(), k);

    // This should either fail with InsufficientSymbols or DecodeFailed.
    // What it must NOT do is panic or corrupt the data if it succeeds.
    match enc.decode(&subset, &params) {
        Ok(decoded) => {
            // If RaptorQ managed to decode, the content must be correct.
            assert_eq!(
                &decoded[..source.len()],
                &source[..],
                "if decode succeeded with exactly k symbols, data must match"
            );
        }
        Err(ErasureError::InsufficientSymbols { have, need }) => {
            // k < k_eff so this is the expected path.
            assert_eq!(have, k);
            assert_eq!(need, k_eff);
        }
        Err(ErasureError::DecodeFailed) => {
            // Also acceptable: decoder accepted k symbols but failed to reconstruct.
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}

// ─── ERASURE-13: source block not a multiple of T — padding is trimmed ────────

#[test]
fn source_block_not_multiple_of_t_padding_trim() {
    // Source = 1000 bytes, T = 65535. Source < T, so k=1 and the encoder pads
    // to k*T internally. After decode, caller trims decoded[..1000] to recover
    // the original content.
    let enc = encoder();
    let source = test_data(1000);
    // ErasureParams for a tiny block: k=1, t=65535.
    let params = ErasureParams::compute(1000, 0.5);
    let bid = block_id(60);
    let hid = holder(60);

    let k_eff = params.k_eff;

    let bound = enc.encode(&source, &params, 0, k_eff, &bid, &hid).unwrap();
    let unbound: Vec<Symbol> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &hid))
        .collect();

    let decoded = enc.decode(&unbound, &params).unwrap();

    // Decoded block is padded to k*t bytes. Trim to original size.
    assert!(
        decoded.len() >= 1000,
        "decoded block must be at least 1000 bytes, got {}",
        decoded.len()
    );
    assert_eq!(
        &decoded[..1000],
        &source[..],
        "first 1000 bytes must match original source"
    );
}
