use super::{ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, binding_seed};
use crate::types::{ErasureParams, IdentityPub, SourceBlockId};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[0] = byte;
    SourceBlockId(id)
}

fn holder(byte: u8) -> IdentityPub {
    let mut id = [0u8; 32];
    id[0] = byte;
    IdentityPub(id)
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
