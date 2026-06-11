// Unit tests for the wire-validation / dedup / cap boundary logic of the symbol
// fetch path (CS-DR-2, CS-DR-5). These exercise `accept_holder_symbols`, the pure
// helper extracted from `fetch_unbound_symbols`, with real symbols and a real
// RaptorQEncoder — no swarm needed. The full network round-trip is covered by
// restore/tests.rs integration tests and local_e2e_test.sh.
//
// Pattern: what_when_then.

use std::collections::HashSet;
use std::sync::Arc;

use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol};
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::accept_holder_symbols;

const SYMBOL_LEN: usize = 4;

fn encoder() -> Arc<dyn ErasureEncoder> {
    Arc::new(RaptorQEncoder::new())
}

fn block() -> SourceBlockId {
    SourceBlockId([1u8; 32])
}

fn holder() -> DeviceId {
    DeviceId([2u8; 32])
}

fn sym(esi: u32, len: usize) -> Symbol {
    Symbol {
        esi,
        data: vec![0xABu8; len],
    }
}

/// CS-DR-2: a holder reply containing a symbol with `esi >= 2^24` AND another
/// with the wrong data length must be skipped without panicking; only the
/// well-formed, requested symbol is accepted.
#[test]
fn fetch_skips_symbol_with_oversized_esi_and_wrong_length_without_panic() {
    let enc = encoder();
    let blk = block();
    let hld = holder();

    let wanted: HashSet<u32> = [0u32, 1u32].into_iter().collect();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();

    let symbols = vec![
        sym(1 << 24, SYMBOL_LEN), // oversized ESI → would assert-panic in decode
        sym(0, SYMBOL_LEN + 1),   // wrong length → would slice-panic in decode
        sym(0, SYMBOL_LEN),       // well-formed, requested → accepted
    ];

    // Must not panic.
    accept_holder_symbols(
        &enc,
        &blk,
        &hld,
        symbols,
        &wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        /*k_eff*/ 2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32].into_iter().collect::<HashSet<u32>>(),
        "only the well-formed, requested symbol (esi=0) is accepted"
    );
    assert_eq!(unbound.len(), 1, "exactly one unbound symbol produced");
    assert_eq!(unbound[0].esi, 0);
}

/// CS-DR-5: a symbol whose ESI was not requested from this holder is rejected.
#[test]
fn fetch_rejects_unrequested_esi() {
    let enc = encoder();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();
    let wanted: HashSet<u32> = [5u32].into_iter().collect();

    let symbols = vec![sym(7, SYMBOL_LEN), sym(5, SYMBOL_LEN)];
    accept_holder_symbols(
        &enc,
        &block(),
        &holder(),
        symbols,
        &wanted,
        2,
        SYMBOL_LEN,
        2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [5u32].into_iter().collect::<HashSet<u32>>(),
        "esi=7 was never requested and must be rejected; only esi=5 accepted"
    );
}

/// CS-DR-5: per-holder cap and global dedup — duplicate ESIs from one holder do
/// not pad the quota.
#[test]
fn fetch_dedups_and_caps_per_holder() {
    let enc = encoder();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();
    let wanted: HashSet<u32> = [0u32, 1u32].into_iter().collect();

    // Holder returns esi=0 three times (dupes) plus esi=1 once.
    let symbols = vec![
        sym(0, SYMBOL_LEN),
        sym(0, SYMBOL_LEN),
        sym(0, SYMBOL_LEN),
        sym(1, SYMBOL_LEN),
    ];
    accept_holder_symbols(
        &enc,
        &block(),
        &holder(),
        symbols,
        &wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        /*k_eff*/ 2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32, 1u32].into_iter().collect::<HashSet<u32>>(),
        "each ESI counts once; dupes don't pad quota"
    );
    assert_eq!(unbound.len(), 2, "two distinct symbols accepted");
}

/// CS-DR-5: a Byzantine first holder that floods k_eff duplicate symbols cannot
/// starve honest holders — progress is measured by UNIQUE accepted ESIs, so the
/// honest holder's distinct symbols still get us to k_eff.
#[test]
fn byzantine_first_holder_cannot_starve_honest_holders() {
    let enc = encoder();
    let blk = block();
    let k_eff = 3usize;

    let byzantine = DeviceId([0xBBu8; 32]);
    let honest = DeviceId([0xAAu8; 32]);

    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();

    // Byzantine holder is asked for esi 0 (requested set = {0}); it floods many
    // copies of esi=0. With raw-count logic this would fill the k_eff quota; with
    // unique-ESI logic it contributes exactly one ESI.
    let byz_wanted: HashSet<u32> = [0u32].into_iter().collect();
    let byz_symbols: Vec<Symbol> = (0..k_eff * 4).map(|_| sym(0, SYMBOL_LEN)).collect();
    accept_holder_symbols(
        &enc,
        &blk,
        &byzantine,
        byz_symbols,
        &byz_wanted,
        /*holder_cap*/ 1, // only esi 0 was requested from it
        SYMBOL_LEN,
        k_eff,
        &mut accepted_esis,
        &mut unbound,
    );
    assert_eq!(
        accepted_esis.len(),
        1,
        "Byzantine flood contributes exactly one distinct ESI, not k_eff"
    );

    // Honest holder is asked for the remaining ESIs {1,2} and returns them.
    let honest_wanted: HashSet<u32> = [1u32, 2u32].into_iter().collect();
    let honest_symbols = vec![sym(1, SYMBOL_LEN), sym(2, SYMBOL_LEN)];
    accept_holder_symbols(
        &enc,
        &blk,
        &honest,
        honest_symbols,
        &honest_wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        k_eff,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32, 1u32, 2u32].into_iter().collect::<HashSet<u32>>(),
        "honest holder's distinct symbols still reach k_eff despite the flood"
    );
    assert_eq!(accepted_esis.len(), k_eff, "collected k_eff distinct ESIs");
}
