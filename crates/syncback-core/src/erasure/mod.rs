use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use raptorq::{EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder, SourceBlockEncoder};
use sha2::Sha256;

use crate::types::{DeviceId, ErasureParams, SourceBlockId};

/// One encoding symbol: ESI (which symbol) + T bytes of data.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    pub esi: u32,
    /// Always exactly ErasureParams.t bytes.
    pub data: Vec<u8>,
}

impl Symbol {
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

/// Errors from encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    /// Source block is empty.
    #[error("source block is empty")]
    EmptyBlock,

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
    fn decode(
        &self,
        symbols: &[Symbol],
        params: &ErasureParams,
    ) -> Result<Vec<u8>, ErasureError>;

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
    fn unbind(
        &self,
        symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Symbol;

    /// Encode source_block into raw (unbound) RaptorQ symbols.
    /// No per-holder XOR is applied. ESI = start_esi..start_esi+count-1.
    fn encode_raw(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
    ) -> Result<Vec<Symbol>, ErasureError>;

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
            1,  // single source block
            1,  // single sub-block (required when symbol_size % 8 != 0)
            1,  // alignment=1 to accommodate symbol_size=65535
        )
    }

    fn make_block_encoder(
        source_block: &[u8],
        params: &ErasureParams,
    ) -> SourceBlockEncoder {
        let config = Self::make_config(params);
        let k = params.k as usize;
        let t = params.t as usize;
        let padded_len = k * t;
        let mut padded = source_block.to_vec();
        padded.resize(padded_len, 0u8);
        SourceBlockEncoder::new(0, &config, &padded)
    }
}

impl Default for RaptorQEncoder {
    fn default() -> Self {
        Self::new()
    }
}

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
        Ok(raw.into_iter().map(|s| self.apply_binding(s, block_id, holder_id)).collect())
    }

    fn decode(
        &self,
        symbols: &[Symbol],
        params: &ErasureParams,
    ) -> Result<Vec<u8>, ErasureError> {
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

    fn unbind(
        &self,
        mut symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Symbol {
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
        if source_block.is_empty() {
            return Err(ErasureError::EmptyBlock);
        }

        let encoder = Self::make_block_encoder(source_block, params);
        let k = params.k;
        let t = params.t as usize;

        // Fetch source packets once (only if we need any source-range ESIs).
        let source_packets: Option<Vec<EncodingPacket>> = if start_esi < k {
            Some(encoder.source_packets())
        } else {
            None
        };

        let mut symbols = Vec::with_capacity(count as usize);
        for i in 0..count {
            let esi = start_esi + i;
            let raw_data: Vec<u8> = if esi < k {
                source_packets
                    .as_ref()
                    .and_then(|v| v.get(esi as usize))
                    .ok_or(ErasureError::SourcePacketMissing { esi })?
                    .data()
                    .to_vec()
            } else {
                let repair_offset = esi - k;
                let packets = encoder.repair_packets(repair_offset, 1);
                packets
                    .into_iter()
                    .next()
                    .ok_or(ErasureError::RepairPacketMissing { esi })?
                    .data()
                    .to_vec()
            };

            if raw_data.len() != t {
                return Err(ErasureError::SymbolSizeMismatch {
                    expected: t,
                    got: raw_data.len(),
                });
            }

            symbols.push(Symbol { esi, data: raw_data });
        }

        Ok(symbols)
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
    hk.expand(b"syncback-binding", &mut okm)
        .expect("44 is a valid HKDF-SHA256 output length");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm[..32]);
    seed
}

/// Derive per-holder binding keystream for one symbol.
///
/// HKDF(salt=source_block_id, ikm=holder_id, info="syncback-binding", len=44)
/// → 32-byte ChaCha20 key + 12-byte nonce base, with ESI XOR'd into nonce[8..12]
/// → ChaCha20 stream of `t` zero-bytes = keystream
pub(crate) fn binding_keystream(
    block_id: &SourceBlockId,
    holder_id: &DeviceId,
    esi: u32,
    t: usize,
) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(block_id.0.as_ref()), holder_id.0.as_ref());
    let mut okm = [0u8; 44];
    hk.expand(b"syncback-binding", &mut okm)
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
