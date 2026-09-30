use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder, SourceBlockEncodingPlan,
};
use sha2::Sha256;
use std::borrow::Cow;

use crate::constants::RAPTORQ_MAX_SOURCE_SYMBOLS;
use crate::types::{DeviceId, ErasureParams, SourceBlockId};

/// One encoding symbol: ESI (which symbol) + T bytes of data.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub esi: u32,
    /// Always exactly ErasureParams.t bytes.
    /// `serde_bytes` forces CBOR byte-string encoding (3-byte overhead) instead of
    /// the default array-of-u8 (≈2 bytes per byte for random data → 90% wire bloat).
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl Symbol {
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

/// Split `symbols` into contiguous chunks whose cumulative `data.len()` stays
/// ≤ `budget_bytes`. A single symbol larger than the budget is still emitted as
/// its own chunk (the caller is responsible for enforcing SYMBOL_SIZE).
///
/// Order of symbols is preserved. Empty input yields an empty Vec.
///
/// Used by the owner side of the backup/repair delivery path to stay below
/// `MAX_MESSAGE_SIZE`. The budget leaves CBOR/overhead headroom — see
/// `SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES`.
pub fn chunk_symbols_by_size(symbols: Vec<Symbol>, budget_bytes: usize) -> Vec<Vec<Symbol>> {
    let mut out: Vec<Vec<Symbol>> = Vec::new();
    let mut current: Vec<Symbol> = Vec::new();
    let mut current_bytes: usize = 0;

    for symbol in symbols {
        let sz = symbol.data.len();
        if !current.is_empty() && current_bytes.saturating_add(sz) > budget_bytes {
            out.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(sz);
        current.push(symbol);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Receiver of one raw symbol (ESI, bytes) in `encode_raw_ranges_each`.
pub type SymbolSink<'a> = dyn FnMut(u32, &[u8]) -> Result<(), ErasureError> + 'a;

/// Errors from encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    /// Source block is empty.
    #[error("source block is empty")]
    EmptyBlock,

    /// `k` exceeds what the raptorq crate accepts for one source block (it panics above it).
    #[error("too many source symbols: k = {k}, RaptorQ single-block maximum is {max}")]
    TooManySourceSymbols { k: u32, max: u32 },

    /// Not enough symbols to decode (need at least K_eff).
    #[error("insufficient symbols: have {have}, need {need}")]
    InsufficientSymbols { have: usize, need: usize },

    /// RaptorQ decode failed (probabilistic; extremely rare with K_eff symbols).
    #[error("raptorq decode failed")]
    DecodeFailed,

    /// Symbol data has wrong size (not T bytes).
    #[error("symbol size mismatch: expected {expected}, got {got}")]
    SymbolSizeMismatch { expected: usize, got: usize },

    /// Source packet missing for the requested ESI (internal encoder inconsistency).
    #[error("source packet missing for esi {esi}")]
    SourcePacketMissing { esi: u32 },

    /// Repair packet not produced by RaptorQ for the requested ESI.
    #[error("repair packet not produced for esi {esi}")]
    RepairPacketMissing { esi: u32 },

    /// `encode_raw_ranges_each` needs ranges in ascending order without overlap.
    #[error("ranges are not ascending and disjoint")]
    RangesNotAscending,
}

/// Pad a stored blob in place to `k * t` bytes for encoding (no second copy).
///
/// The block id must be checked BEFORE padding: the padding changes the bytes the id is
/// taken over. Reserves exactly the missing tail, so the worst case is one transient
/// reallocation (2x the blob, before the encoder is built), not a permanent second copy.
/// A blob already `k * t` long or longer is left as is.
pub fn pad_for_encoding(blob: &mut Vec<u8>, params: &ErasureParams) {
    let padded_len = params.k as usize * params.t as usize;
    if blob.len() < padded_len {
        blob.reserve_exact(padded_len - blob.len());
        blob.resize(padded_len, 0u8);
    }
}

/// Erasure coding abstraction. Stateless — all inputs explicit.
pub trait ErasureEncoder: Send + Sync {
    /// Encode source_block into `count` bound symbols starting at `start_esi`.
    ///
    /// All returned symbols are per-holder bound (XOR ChaCha20 keystream).
    /// Symbols will have ESI = start_esi, start_esi+1, ..., start_esi+count-1.
    ///
    /// Caller pads source_block to a multiple of params.t if needed.
    fn encode(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Vec<Symbol>, ErasureError>;

    /// Decode source block from symbols (after unbinding).
    ///
    /// symbols must already be unbound (XOR'd back to raw RaptorQ output).
    /// Need at least params.k_eff symbols. May succeed with exactly k_eff.
    /// Returned block is padded to k * t bytes; caller trims to original size.
    fn decode(&self, symbols: &[Symbol], params: &ErasureParams) -> Result<Vec<u8>, ErasureError>;

    /// Generate a single repair symbol for a new ESI, bound to a holder.
    ///
    /// Used by repair flow when source file is available locally.
    /// Does NOT require downloading any existing symbols.
    fn generate_repair(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        esi: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Symbol, ErasureError>;

    /// Unbind a received bound symbol: XOR ChaCha20 keystream back off.
    /// Returns raw RaptorQ symbol data, ready for decode().
    fn unbind(&self, symbol: Symbol, block_id: &SourceBlockId, holder_id: &DeviceId) -> Symbol;

    /// Encode source_block into raw (unbound) RaptorQ symbols.
    /// No per-holder XOR is applied. ESI = start_esi..start_esi+count-1.
    fn encode_raw(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
    ) -> Result<Vec<Symbol>, ErasureError>;

    /// Encode raw (unbound) symbols for several `(start_esi, count)` ranges with ONE encoder
    /// build — the build is the costly part, so a plan whose ESIs are not contiguous (a
    /// holder re-offered its own range plus fresh numbers, repair-i9) still encodes once.
    /// Symbols come back in the order of `ranges`, each range in ascending ESI.
    fn encode_raw_ranges(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
    ) -> Result<Vec<Symbol>, ErasureError>;

    /// Like `encode_raw_ranges`, but each raw symbol goes to `f` and is dropped: nothing
    /// accumulates, so the peak does not grow with the number of symbols. ONE encoder build.
    ///
    /// `ranges` must be ascending and disjoint (`RangesNotAscending` otherwise); `f` is called
    /// in ascending ESI order. `f` returning `Err` stops the walk and is returned as is.
    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError>;

    /// Apply per-holder binding to a raw symbol.
    /// XORs the symbol data with the binding keystream derived from (block_id, holder_id, esi).
    fn apply_binding(
        &self,
        raw_symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Symbol;
}

/// RaptorQ implementation using the `raptorq` crate.
pub struct RaptorQEncoder;

impl RaptorQEncoder {
    pub fn new() -> Self {
        RaptorQEncoder
    }

    fn make_config(params: &ErasureParams) -> ObjectTransmissionInformation {
        let k = params.k as u64;
        let t = params.t as u64;
        ObjectTransmissionInformation::new(
            k * t,
            params.t,
            1, // single source block
            1, // single sub-block (required when symbol_size % 8 != 0)
            1, // alignment=1 to accommodate symbol_size=65535
        )
    }

    /// Build the encoder over `source_block` padded to `k * t`.
    ///
    /// A block already `k * t` long is used as is, without a copy (F5); a shorter one is
    /// copied and zero-padded (callers that can pad in place use `pad_for_encoding`). The
    /// encoding plan is generated here and dropped with the operation: raptorq's own
    /// constructor would park it in a process-wide cache for good (W2).
    fn make_block_encoder<'a>(
        source_block: &'a [u8],
        params: &ErasureParams,
    ) -> (SourceBlockEncoder, Cow<'a, [u8]>) {
        let config = Self::make_config(params);
        let padded_len = params.k as usize * params.t as usize;
        let input: Cow<[u8]> = if source_block.len() >= padded_len {
            Cow::Borrowed(&source_block[..padded_len])
        } else {
            let mut padded = Vec::with_capacity(padded_len);
            padded.extend_from_slice(source_block);
            padded.resize(padded_len, 0u8);
            Cow::Owned(padded)
        };
        let plan = SourceBlockEncodingPlan::generate(params.k as u16);
        let encoder = SourceBlockEncoder::with_encoding_plan(0, &config, &input, &plan);
        (encoder, input)
    }

    /// Walk `ranges` in the given order over one encoder; every raw symbol goes to `f`.
    /// Source ESIs are slices of the padded input (with one sub-block a symbol IS the chunk,
    /// F6); repair ESIs come from the encoder one at a time.
    fn walk_ranges(
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
        check_source_symbol_limit(params)?;
        if source_block.is_empty() {
            return Err(ErasureError::EmptyBlock);
        }
        let (encoder, input) = Self::make_block_encoder(source_block, params);
        let k = params.k;
        let t = params.t as usize;
        for &(start_esi, count) in ranges {
            for i in 0..count {
                let esi = start_esi + i;
                if esi < k {
                    let from = esi as usize * t;
                    f(esi, &input[from..from + t])?;
                } else {
                    let packet = encoder
                        .repair_packets(esi - k, 1)
                        .into_iter()
                        .next()
                        .ok_or(ErasureError::RepairPacketMissing { esi })?;
                    let (_, data) = packet.split();
                    if data.len() != t {
                        return Err(ErasureError::SymbolSizeMismatch {
                            expected: t,
                            got: data.len(),
                        });
                    }
                    f(esi, &data)?;
                }
            }
        }
        Ok(())
    }
}

/// Refuse a `k` the raptorq crate would panic on, before anything is allocated (backup-i5).
fn check_source_symbol_limit(params: &ErasureParams) -> Result<(), ErasureError> {
    if params.k > RAPTORQ_MAX_SOURCE_SYMBOLS {
        return Err(ErasureError::TooManySourceSymbols {
            k: params.k,
            max: RAPTORQ_MAX_SOURCE_SYMBOLS,
        });
    }
    Ok(())
}

impl Default for RaptorQEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// The implementation calls its own entry points; the daemon goes through `mem_budget`.
#[allow(clippy::disallowed_methods)]
impl ErasureEncoder for RaptorQEncoder {
    fn encode(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Vec<Symbol>, ErasureError> {
        let raw = self.encode_raw(source_block, params, start_esi, count)?;
        Ok(raw
            .into_iter()
            .map(|s| self.apply_binding(s, block_id, holder_id))
            .collect())
    }

    fn decode(&self, symbols: &[Symbol], params: &ErasureParams) -> Result<Vec<u8>, ErasureError> {
        check_source_symbol_limit(params)?;
        let k_eff = params.k_eff as usize;

        if symbols.len() < k_eff {
            return Err(ErasureError::InsufficientSymbols {
                have: symbols.len(),
                need: k_eff,
            });
        }

        let config = Self::make_config(params);
        let block_length = params.k as u64 * params.t as u64;
        let mut decoder = SourceBlockDecoder::new(0, &config, block_length);

        let packets: Vec<EncodingPacket> = symbols
            .iter()
            .map(|s| EncodingPacket::new(PayloadId::new(0, s.esi), s.data.clone()))
            .collect();

        decoder.decode(packets).ok_or(ErasureError::DecodeFailed)
    }

    fn generate_repair(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        esi: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Symbol, ErasureError> {
        let mut symbols = self.encode(source_block, params, esi, 1, block_id, holder_id)?;
        Ok(symbols.remove(0))
    }

    fn unbind(&self, mut symbol: Symbol, block_id: &SourceBlockId, holder_id: &DeviceId) -> Symbol {
        let t = symbol.data.len();
        let keystream = binding_keystream(block_id, holder_id, symbol.esi, t);
        xor_inplace(&mut symbol.data, &keystream);
        symbol
    }

    fn encode_raw(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
    ) -> Result<Vec<Symbol>, ErasureError> {
        check_source_symbol_limit(params)?;
        self.encode_raw_ranges(source_block, params, &[(start_esi, count)])
    }

    fn encode_raw_ranges(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
    ) -> Result<Vec<Symbol>, ErasureError> {
        let total: usize = ranges.iter().map(|&(_, count)| count as usize).sum();
        let mut symbols = Vec::with_capacity(total);
        Self::walk_ranges(source_block, params, ranges, &mut |esi, data| {
            symbols.push(Symbol {
                esi,
                data: data.to_vec(),
            });
            Ok(())
        })?;
        Ok(symbols)
    }

    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
        let mut next_free: u64 = 0;
        for &(start, count) in ranges {
            if (start as u64) < next_free {
                return Err(ErasureError::RangesNotAscending);
            }
            next_free = start as u64 + count as u64;
        }
        Self::walk_ranges(source_block, params, ranges, f)
    }

    fn apply_binding(
        &self,
        mut raw_symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Symbol {
        let t = raw_symbol.data.len();
        let keystream = binding_keystream(block_id, holder_id, raw_symbol.esi, t);
        xor_inplace(&mut raw_symbol.data, &keystream);
        raw_symbol
    }
}

/// Compute binding seed for a (block_id, holder_id) pair.
///
/// Returns the first 32 bytes of the HKDF output used for per-holder binding.
/// This value is stored in `SymbolPlacement.binding_seed` for the RestoreCoordinator.
pub fn binding_seed(block_id: &SourceBlockId, holder_id: &DeviceId) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(block_id.0.as_ref()), holder_id.0.as_ref());
    let mut okm = [0u8; 44];
    hk.expand(b"viaticum-binding", &mut okm)
        .expect("44 is a valid HKDF-SHA256 output length");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm[..32]);
    seed
}

/// Derive per-holder binding keystream for one symbol.
///
/// HKDF(salt=source_block_id, ikm=holder_id, info="viaticum-binding", len=44)
/// → 32-byte ChaCha20 key + 12-byte nonce base, with ESI XOR'd into nonce[8..12]
/// → ChaCha20 stream of `t` zero-bytes = keystream
pub fn binding_keystream(
    block_id: &SourceBlockId,
    holder_id: &DeviceId,
    esi: u32,
    t: usize,
) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(block_id.0.as_ref()), holder_id.0.as_ref());
    let mut okm = [0u8; 44];
    hk.expand(b"viaticum-binding", &mut okm)
        .expect("44 is a valid HKDF-SHA256 output length");

    let key: [u8; 32] = okm[..32].try_into().unwrap();
    let mut nonce: [u8; 12] = okm[32..44].try_into().unwrap();

    // XOR ESI into nonce[8..12] so each ESI gets a unique keystream
    let esi_bytes = esi.to_le_bytes();
    nonce[8] ^= esi_bytes[0];
    nonce[9] ^= esi_bytes[1];
    nonce[10] ^= esi_bytes[2];
    nonce[11] ^= esi_bytes[3];

    let mut keystream = vec![0u8; t];
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut keystream);
    keystream
}

fn xor_inplace(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= k;
    }
}

#[cfg(test)]
mod tests;
