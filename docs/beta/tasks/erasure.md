# Task: erasure — ErasureEncoder trait + RaptorQ impl (β)

Module: `crates/syncback-core/src/erasure/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Новый модуль (не существовал в α). Инкапсулирует erasure coding за трейтом.

Единственная реализация: RaptorQ через crate `raptorq` (version ~1.x). Трейт позволяет заменить реализацию без изменений в остальном коде.

**Ключевые свойства RaptorQ для этого модуля:**
- `encode()`: source block → N binding symbols для конкретного holder'а.
- `decode()`: любые K_eff symbols → source block.
- `generate_repair()`: source block + новый ESI → один bound symbol (для ремонта без re-encode всего).
- Per-holder binding: `stored_symbol = symbol XOR ChaCha20(HKDF(source_block_id, holder_id))`.

---

## Dependencies

Crate `syncback-core/Cargo.toml` additions needed:
```toml
raptorq = "1"
hkdf = "0.12"
sha2 = "0.10"
chacha20 = "0.9"   # stream cipher only (no AEAD, just keystream)
```

- `crate::types::{SourceBlockId, IdentityPub, ErasureParams}`
- `crate::constants::{SYMBOL_SIZE, DECODE_OVERHEAD}`
- No DB. No async. Pure computation.

---

## Types

```rust
/// One encoding symbol: ESI (which symbol) + T bytes of data.
#[derive(Debug, Clone, PartialEq)]
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
}
```

---

## Trait

```rust
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
        holder_id: &IdentityPub,
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
        holder_id: &IdentityPub,
    ) -> Result<Symbol, ErasureError>;

    /// Unbind a received bound symbol: XOR ChaCha20 keystream back off.
    /// Returns raw RaptorQ symbol data, ready for decode().
    fn unbind(
        &self,
        symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Symbol;
}
```

---

## RaptorQ Implementation

```rust
/// RaptorQ implementation using the `raptorq` crate.
pub struct RaptorQEncoder;

impl RaptorQEncoder {
    pub fn new() -> Self { RaptorQEncoder }
}

impl ErasureEncoder for RaptorQEncoder { ... }
```

### encode() implementation sketch

```rust
// 1. Validate
if source_block.is_empty() { return Err(EmptyBlock) }

// 2. Pad source_block to k * t bytes
let k = params.k as usize;
let t = params.t as usize;
let padded_len = k * t;
let mut padded = source_block.to_vec();
padded.resize(padded_len, 0u8);

// 3. Create RaptorQ encoder
let encoder = raptorq::Encoder::with_defaults(&padded, params.t);
// Note: raptorq::Encoder::with_defaults takes (data, symbol_size)

// 4. Generate symbols
let mut symbols = Vec::with_capacity(count as usize);
for i in 0..count {
    let esi = start_esi + i;
    let packet = encoder.encode_packet(esi);
    // raptorq encodes ESI as u32; the crate API may differ - check at implementation time

    // 5. Bind: XOR with holder-specific keystream
    let mut data = packet.data().to_vec();
    let keystream = binding_keystream(block_id, holder_id, esi, t);
    xor_inplace(&mut data, &keystream);

    symbols.push(Symbol { esi, data });
}
Ok(symbols)
```

### decode() implementation sketch

```rust
// 1. Check we have enough
if symbols.len() < params.k_eff as usize {
    return Err(InsufficientSymbols { have: symbols.len(), need: params.k_eff as usize });
}

// 2. Build raptorq::SourceBlockDecoder
// (symbols must already be unbound before this call)
let mut decoder = raptorq::SourceBlockDecoder::new(
    0u8,              // source block number (always 0 for single-block use)
    &raptorq::PayloadId::new(0, start_esi)?, // placeholder
    params.k as u64 * params.t as u64,
);
// Note: actual raptorq API may differ — check crate docs at implementation time
// The crate uses EncodingPacket structs

for symbol in symbols {
    let packet = raptorq::EncodingPacket::new(
        raptorq::PayloadId::new(0, symbol.esi),
        symbol.data,
    );
    if let Some(result) = decoder.decode(vec![packet]) {
        return Ok(result);
    }
}
Err(DecodeFailed)
```

### Binding keystream (HKDF + ChaCha20)

```rust
/// Derive per-holder binding keystream for one symbol.
///
/// HKDF(salt=source_block_id, ikm=holder_id, info="syncback-binding", len=T)
/// → ChaCha20 key (32 bytes) + nonce derived from ESI
/// → ChaCha20 stream of T bytes
fn binding_keystream(
    block_id: &SourceBlockId,
    holder_id: &IdentityPub,
    esi: u32,
    t: usize,
) -> Vec<u8>;
```

Implementation:
```
1. HKDF-SHA256:
   ikm  = holder_id.0
   salt = block_id.0
   info = b"syncback-binding"
   → 44 bytes output: [32 bytes key] + [12 bytes nonce base]

2. XOR ESI into nonce: nonce[8..12] ^= esi.to_le_bytes()
   (Each ESI gets a different nonce → independent keystream)

3. ChaCha20 encrypt T zero-bytes with (key, nonce) → T-byte keystream
```

```rust
fn xor_inplace(data: &mut [u8], keystream: &[u8]) {
    debug_assert_eq!(data.len(), keystream.len());
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= k;
    }
}
```

### generate_repair()

Same as `encode()` for a single symbol. The key insight: RaptorQ can generate any ESI from source data at any time. So `generate_repair()` is exactly:

```rust
fn generate_repair(
    &self,
    source_block: &[u8],
    params: &ErasureParams,
    esi: u32,
    block_id: &SourceBlockId,
    holder_id: &IdentityPub,
) -> Result<Symbol, ErasureError> {
    let mut symbols = self.encode(source_block, params, esi, 1, block_id, holder_id)?;
    Ok(symbols.remove(0))
}
```

### unbind()

```rust
fn unbind(&self, mut symbol: Symbol, block_id: &SourceBlockId, holder_id: &IdentityPub) -> Symbol {
    let t = symbol.data.len();
    let keystream = binding_keystream(block_id, holder_id, symbol.esi, t);
    xor_inplace(&mut symbol.data, &keystream);
    symbol
}
```

Note: bind and unbind are the same XOR operation (self-inverse).

---

## Module structure

```rust
// erasure/mod.rs
mod binding;       // binding_keystream() + xor_inplace()
pub use mod::{ErasureEncoder, ErasureError, Symbol};
pub struct RaptorQEncoder;
impl ErasureEncoder for RaptorQEncoder { ... }

// erasure/tests.rs
// All test scenarios
```

Or keep everything in `mod.rs` if binding is small — implementer's call.

---

## raptorq crate API notes

DECISION NEEDED: The `raptorq` crate API has changed between versions. At implementation time, check:
1. `Encoder::with_defaults(data: &[u8], symbol_size: u16)` — confirm this is the correct constructor.
2. `encoder.encode_packet(esi: u32)` — or is it `encoder.get_encoded_packets(repair_packets_per_block)` returning source+repair together?
3. `SourceBlockDecoder::new(...)` — check exact constructor and whether it takes total_length or just K.
4. ESI handling: source symbols have ESI 0..K-1 (systematic), repair symbols have ESI >= K.

The implementer MUST read the `raptorq` crate source/docs before writing the encode/decode wrappers.

---

## Test Scenarios

Tests in `erasure/tests.rs`.

### 1. `encode_decode_roundtrip_small`

```
source_block = 64 KiB of test data (one symbol)
params = ErasureParams::compute(65_535, 0.5)
holder_id = test peer A
block_id = blake3(source_block)

Encode: 5 symbols starting at ESI 0
Unbind all symbols
Decode with k_eff symbols
Assert decoded == source_block (trimmed to original size)
```

### 2. `encode_decode_roundtrip_full_block`

```
source_block = 128 MiB of random bytes
params = ErasureParams::compute(128 * 1024 * 1024, 0.6)
Encode 20 symbols (not all N).
Unbind. Decode first k_eff.
Assert decoded matches source_block.
```

### 3. `decode_fails_with_insufficient_symbols`

```
Have k_eff - 1 symbols.
decode() returns Err(InsufficientSymbols { have: k_eff-1, need: k_eff })
```

### 4. `binding_unbinding_roundtrip`

```
symbol with random data
bind: data XOR keystream(block_id, holder_A, esi=0, t)
unbind: XOR again
assert unbound == original
```

### 5. `binding_differs_per_holder`

```
same source_block, same esi=0
encode for holder_A and holder_B
bound_A.data != bound_B.data
```

### 6. `binding_differs_per_esi`

```
same source_block, same holder
encode esi=0 and esi=1
bound_0.data != bound_1.data
(keystreams are different because nonce differs)
```

### 7. `binding_differs_per_block`

```
same holder, same esi=0
two different block_ids
bound symbols differ
```

### 8. `generate_repair_matches_encode`

```
generate_repair(source, params, esi=100, block_id, holder_A)
encode(source, params, start_esi=100, count=1, block_id, holder_A)[0]
assert they are equal
```

### 9. `repair_symbol_used_in_decode`

```
Deliberately lose ESI 0..k symbols (first K source symbols).
Request ESI >= K only (repair symbols).
Still decode successfully with k_eff of those.
```

### 10. `empty_block_returns_error`

```
encode(b"", params, 0, 1, block_id, holder)
→ Err(ErasureError::EmptyBlock)
```

### 11. `decode_with_exactly_k_eff_symbols`

```
Provide exactly k_eff symbols (no extras). Decode succeeds.
This exercises the RaptorQ "probabilistic" property — with k_eff symbols
success probability is extremely high (>99.99%).
Note: may occasionally fail due to RaptorQ's probabilistic nature.
If flaky, use k_eff + 2 symbols instead.
```

---

## Performance Notes (for implementer awareness, not test assertions)

- K=2048, T=64 KiB: encode 1 symbol ≈ microseconds (ChaCha20 is fast).
- Encode full N=4922 symbols ≈ a few seconds (dominated by RaptorQ intermediate).
- Decode ≈ 100-500 ms (matrix solution, O(K^2)).
- Binding (ChaCha20 XOR) is negligible vs RaptorQ itself.

No performance benchmarks required for Phase 1 gate. Add to `benchmarks/` post-phase-1 if desired.
