// F8' (R1-d-b): the hashes of a PoS preparation, folded while the block is encoded, equal the
// hashes of the old way — every symbol of the union collected, bound per holder, hashed at the
// end — for overlapping, non-adjacent and duplicated ranges (repair-i9, NOTE 1).

use std::collections::HashMap;

use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, binding_keystream};
use viaticum_core::types::{ErasureParams, SourceBlockId, esi_list_to_ranges, ranges_to_esi_list};

use super::{make_identity, make_source_block_record, pos_block_bytes};
use crate::daemon::mem_budget::{HolderKind, MemBudget};
use crate::daemon::scheduler::{FoldHolder, hash_holders};

fn holder(id: u8, challenge: u8, ranges: &[(u32, u32)]) -> FoldHolder {
    FoldHolder {
        holder_id: make_identity(id),
        challenge_id: [challenge; 16],
        esi_ranges: ranges.to_vec(),
    }
}

/// The hash the way the preparation computed it before F8': one `encode_raw_ranges` of the
/// union into a map, then per holder the bound symbols of its sorted ESIs (duplicates kept) and
/// `compute_chain_hash`.
fn old_hash(
    enc: &RaptorQEncoder,
    block_id: &SourceBlockId,
    params: &ErasureParams,
    blob: &[u8],
    holders: &[FoldHolder],
    of: usize,
) -> [u8; 32] {
    let mut all: Vec<u32> = holders
        .iter()
        .flat_map(|h| ranges_to_esi_list(&h.esi_ranges))
        .collect();
    all.sort_unstable();
    all.dedup();
    let raw: HashMap<u32, Vec<u8>> = enc
        .encode_raw_ranges(blob, params, &esi_list_to_ranges(&all))
        .unwrap()
        .into_iter()
        .map(|s| (s.esi, s.data))
        .collect();
    let h = &holders[of];
    let mut esis = ranges_to_esi_list(&h.esi_ranges);
    esis.sort_unstable();
    let bound: Vec<(u32, Vec<u8>)> = esis
        .iter()
        .map(|&esi| {
            let mut data = raw[&esi].clone();
            let ks = binding_keystream(block_id, &h.holder_id, esi, data.len());
            for (d, k) in data.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            (esi, data)
        })
        .collect();
    let refs: Vec<(u32, &[u8])> = bound.iter().map(|(e, d)| (*e, d.as_slice())).collect();
    viaticum_core::pos::compute_chain_hash(&h.challenge_id, &refs).unwrap()
}

/// The folded hashes of `holders` over `blob`, under a real permit.
fn folded(blob: Vec<u8>, holders: &[FoldHolder]) -> (SourceBlockId, ErasureParams, Vec<[u8; 32]>) {
    let block_id = SourceBlockId(*blake3::hash(&blob).as_bytes());
    let params = make_source_block_record(block_id).erasure_params();
    let budget = MemBudget::new(64 << 20);
    let permit = budget
        .try_acquire(HolderKind::Pos, &block_id, 1 << 20)
        .expect("a free budget");
    let hashes = hash_holders(
        &permit,
        &RaptorQEncoder::new(),
        &block_id,
        &params,
        blob,
        holders,
    )
    .expect("the walk");
    (
        block_id,
        params,
        hashes.into_iter().map(|h| h.expect("a hash")).collect(),
    )
}

/// Holders that overlap each other (shared source and repair ESIs), hold non-adjacent ranges,
/// list their ranges unsorted, and one of them lists the same ESIs twice.
#[test]
fn pos_issue_fold_equals_old_hash() {
    let blob = pos_block_bytes(0x21);
    let holders = vec![
        holder(0x81, 1, &[(0, 4), (12, 3)]),
        holder(0x82, 2, &[(2, 5), (11, 4)]),
        holder(0x83, 3, &[(11, 2), (0, 2), (20, 6)]),
        holder(0x84, 4, &[(9, 8), (40, 5)]),
    ];
    let (block_id, params, hashes) = folded(blob.clone(), &holders);
    let enc = RaptorQEncoder::new();
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(
            *hash,
            old_hash(&enc, &block_id, &params, &blob, &holders, i),
            "holder {i}"
        );
    }
    let distinct: std::collections::HashSet<_> = hashes.iter().collect();
    assert_eq!(
        distinct.len(),
        holders.len(),
        "the hashes are not all equal"
    );
}

/// NOTE 1: the holder answers without removing duplicates, so an ESI listed twice by one holder
/// (two ranges that overlap) is hashed twice in a row — by the old way and by the fold.
#[test]
fn f8_prime_matches_old_hash_with_overlapping_ranges_of_one_holder() {
    let blob = pos_block_bytes(0x22);
    let holders = vec![
        // ESIs 2, 3, 3, 4, 4, 5 (and 12, 12): overlapping ranges of one holder.
        holder(0x85, 9, &[(3, 2), (2, 3), (4, 2), (12, 1), (12, 1)]),
        holder(0x86, 8, &[(3, 3)]),
    ];
    let (block_id, params, hashes) = folded(blob.clone(), &holders);
    let enc = RaptorQEncoder::new();
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(
            *hash,
            old_hash(&enc, &block_id, &params, &blob, &holders, i),
            "holder {i}"
        );
    }
    // The duplicates count: the same holder without them hashes differently.
    let deduped = vec![holder(0x85, 9, &[(2, 4), (12, 1)])];
    let (_, _, single) = folded(blob, &deduped);
    assert_ne!(hashes[0], single[0]);
}

/// A block shorter than `k·t` (as stored) is padded inside the preparation and gives the same
/// hashes as the old way, which let the encoder pad a copy.
#[test]
fn fold_pads_a_short_block_and_gives_the_old_hash() {
    let mut blob = pos_block_bytes(0x23);
    blob.truncate(500);
    let holders = vec![holder(0x87, 5, &[(0, 12)]), holder(0x88, 6, &[(8, 10)])];
    let (block_id, params, hashes) = folded(blob.clone(), &holders);
    let enc = RaptorQEncoder::new();
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(
            *hash,
            old_hash(&enc, &block_id, &params, &blob, &holders, i),
            "holder {i}"
        );
    }
}

/// A holder with no ESIs has nothing to hash: its slot is an error, the others are unaffected.
#[test]
fn fold_gives_an_error_for_a_holder_without_symbols_and_hashes_the_rest() {
    let blob = pos_block_bytes(0x24);
    let block_id = SourceBlockId(*blake3::hash(&blob).as_bytes());
    let params = make_source_block_record(block_id).erasure_params();
    let holders = vec![holder(0x89, 1, &[]), holder(0x8A, 2, &[(0, 3)])];
    let budget = MemBudget::new(64 << 20);
    let permit = budget
        .try_acquire(HolderKind::Pos, &block_id, 1 << 20)
        .unwrap();
    let out = hash_holders(
        &permit,
        &RaptorQEncoder::new(),
        &block_id,
        &params,
        blob.clone(),
        &holders,
    )
    .unwrap();
    assert!(out[0].is_err());
    assert_eq!(
        *out[1].as_ref().unwrap(),
        old_hash(
            &RaptorQEncoder::new(),
            &block_id,
            &params,
            &blob,
            &holders,
            1
        )
    );
}
