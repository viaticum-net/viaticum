// The hashes of one block's PoS preparation, folded while the block is encoded (F8', R1-d-b).
//
// One encoder walk over the union of the holders' ESIs, in ascending order. Each raw symbol is
// bound for every holder that asked for it and pushed into that holder's `ChainHasher` — as many
// times as the ESI occurs in the holder's expanded range list (the holder answers without
// removing duplicates, so a duplicate is hashed twice in a row) — and then dropped. Nothing but
// the encoder's own state, one raw symbol, one binding buffer and a keystream is alive, so the
// peak is ≈ 3.1·E_pad + 3·T whatever the number of holders (`mem_budget::estimate_pos_issue`).
//
// `pub` (and re-exported `#[doc(hidden)]` by `scheduler`) only so the allocation-peak test
// binary `tests/block_prep_alloc_peak.rs` can run this very path under a counting allocator.

use viaticum_core::erasure::{ErasureEncoder, ErasureError, binding_keystream, pad_for_encoding};
use viaticum_core::pos::{ChainHasher, PosError};
use viaticum_core::types::{
    DeviceId, ErasureParams, SourceBlockId, esi_list_to_ranges, ranges_to_esi_list,
};

use crate::daemon::mem_budget::{self, MemPermit};

/// One holder of the block: the ranges it holds and the challenge the hash is seeded with.
pub struct FoldHolder {
    pub holder_id: DeviceId,
    pub challenge_id: [u8; 16],
    pub esi_ranges: Vec<(u32, u32)>,
}

/// A holder's ESIs, ascending, each with the number of times it occurs (duplicates kept), and
/// the hasher fed while the walk goes.
struct Folding {
    esis: Vec<(u32, u32)>,
    next: usize,
    hasher: ChainHasher,
}

/// The expected chain hash of every holder, in the order of `holders`: the walk over the union of
/// their ESIs runs once, under `permit`. `blob` is the block as stored (its id already checked);
/// it is padded IN PLACE to `k·t` (F5: the encoder borrows it, no second copy) and dropped when
/// the walk ends. `Err` is an encoder failure; a holder with nothing to hash gets `Err` in its slot.
pub fn hash_holders(
    permit: &MemPermit,
    encoder: &dyn ErasureEncoder,
    block_id: &SourceBlockId,
    params: &ErasureParams,
    mut blob: Vec<u8>,
    holders: &[FoldHolder],
) -> Result<Vec<Result<[u8; 32], PosError>>, ErasureError> {
    let mut folding: Vec<Folding> = holders
        .iter()
        .map(|h| {
            let mut list = ranges_to_esi_list(&h.esi_ranges);
            list.sort_unstable();
            let mut esis: Vec<(u32, u32)> = Vec::new();
            for esi in list {
                match esis.last_mut() {
                    Some((last, count)) if *last == esi => *count += 1,
                    _ => esis.push((esi, 1)),
                }
            }
            Folding {
                esis,
                next: 0,
                hasher: ChainHasher::new(&h.challenge_id),
            }
        })
        .collect();

    // The union, sorted, deduplicated, merged into ranges: one encoder build for every range.
    let mut union: Vec<u32> = folding
        .iter()
        .flat_map(|f| f.esis.iter().map(|&(esi, _)| esi))
        .collect();
    union.sort_unstable();
    union.dedup();
    let union_ranges = esi_list_to_ranges(&union);
    drop(union);

    pad_for_encoding(&mut blob, params);

    let mut bound: Vec<u8> = Vec::new();
    mem_budget::encode_ranges_each(
        permit,
        encoder,
        &blob,
        params,
        &union_ranges,
        &mut |esi, data| {
            for (f, holder) in folding.iter_mut().zip(holders) {
                let Some(&(want, times)) = f.esis.get(f.next) else {
                    continue;
                };
                if want != esi {
                    continue;
                }
                f.next += 1;
                bound.clear();
                bound.extend_from_slice(data);
                let keystream = binding_keystream(block_id, &holder.holder_id, esi, data.len());
                for (b, k) in bound.iter_mut().zip(keystream.iter()) {
                    *b ^= k;
                }
                for _ in 0..times {
                    f.hasher.push(esi, &bound);
                }
            }
            Ok(())
        },
    )?;
    drop(blob);

    Ok(folding.into_iter().map(|f| f.hasher.finish()).collect())
}
