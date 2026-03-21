# Phase 7.7: Restore over network

## Scope

`RestoreCoordinator` already has a `network: Arc<NetworkHandle>` field but uses it nowhere
(`#[allow(dead_code)]`). When local symbol files are absent, the restore currently fails with
`RestoreError::InsufficientSymbols`. This phase adds network fetch: contact each holder via iroh,
send `RestoreRequestMsg`, receive `RestoreResponseMsg`, decrypt and collect symbols until
`k_eff` symbols are gathered, then decode.

## Files changed

- `crates/syncback/src/daemon/restore/mod.rs` — new `fetch_from_holders` method, modify
  `decode_block_local` to fall back to network, remove `#[allow(dead_code)]`
- `crates/syncback/src/daemon/restore/pipeline.rs` — no changes expected
- `crates/syncback/src/daemon/restore/tests.rs` — new network-fetch tests

## Dependencies

- `crate::daemon::network::NetworkHandle` — `get_connection`, `send_message`, `recv_message`
- `syncback_core::messages::{Message, RestoreRequestMsg, RestoreResponseMsg, RestoreDeniedMsg}`
- `syncback_core::db::Db` — `list_placements_for_block`, `get_source_block`
- `syncback_core::types::{PlacementStatus, SymbolPlacement}`
- `syncback_core::erasure::{ErasureEncoder, Symbol}`

## New public API

```rust
impl RestoreCoordinator {
    /// Fetch symbols for a source block from holders over the network.
    ///
    /// Tries holders in parallel (up to `config.parallel_holders` concurrent).
    /// Stops once `k_eff` unbound symbols are collected.
    ///
    /// Returns unbound symbols ready for `encoder.decode()`.
    ///
    /// Holders that return RestoreDenied are logged at WARN and skipped.
    /// Holders that return empty RestoreResponse are logged at DEBUG and skipped.
    /// Network errors per holder are logged at WARN and skipped.
    pub async fn fetch_from_holders(
        &self,
        block_id: &SourceBlockId,
        placements: &[SymbolPlacement],
        params: &ErasureParams,
    ) -> Result<Vec<Symbol>, RestoreError>
}
```

## Modified API

```rust
impl RestoreCoordinator {
    /// Decode one source block.
    ///
    /// Strategy:
    ///   1. Try local: read symbol files from symbols_dir.
    ///   2. If insufficient local symbols (<k_eff), try network fetch for remaining.
    ///   3. Combine local + network symbols, then decode.
    ///
    /// Previously: local only. Now: local-first, network fallback.
    pub async fn decode_block_local(  // name unchanged for compatibility
        &self,
        block_id: &SourceBlockId,
        params: &ErasureParams,
        encrypted_size: u64,
    ) -> Result<Vec<u8>, RestoreError>
}
```

Note: the method is renamed-in-spirit only; the external name `decode_block_local` is kept
because callers (the `restore` method itself, and tests) use it. The doc comment is updated to
describe the new fallback behavior.

## Implementation details

### `fetch_from_holders`

```rust
pub async fn fetch_from_holders(
    &self,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    params: &ErasureParams,
) -> Result<Vec<Symbol>, RestoreError> {
    let k_eff = params.k_eff as usize;
    let mut unbound_symbols: Vec<Symbol> = Vec::new();
    // Try holders sequentially for now (parallel is config.parallel_holders,
    // but sequential is simpler and correct for first implementation).
    for placement in placements {
        if placement.status != PlacementStatus::Alive {
            continue;
        }
        if unbound_symbols.len() >= k_eff {
            break;
        }

        // Determine how many more symbols we need.
        let still_needed = k_eff - unbound_symbols.len();

        // Build esi_list: request exactly still_needed ESIs from this holder's ranges.
        let wanted_esis: Vec<u32> = collect_esis_from_ranges(&placement.esi_ranges)
            .into_iter()
            .take(still_needed)
            .collect();

        if wanted_esis.is_empty() {
            continue;
        }

        let request = RestoreRequestMsg {
            v: 1,
            source_block_id: *block_id,
            esi_list: wanted_esis,
            timestamp: Timestamp::now(),
        };

        match self.fetch_symbols_from_holder(&placement.holder_id, request).await {
            Ok(symbols) => {
                for sym in symbols {
                    let unbound = self.encoder.unbind(sym, block_id, &placement.holder_id);
                    unbound_symbols.push(unbound);
                }
            }
            Err(RestoreError::EscrowDenied { ref holder, .. }) => {
                warn!(holder = %holder, block = %block_id, "fetch: holder denied restore");
            }
            Err(e) => {
                warn!(
                    holder = %placement.holder_id,
                    block = %block_id,
                    err = %e,
                    "fetch: holder failed, skipping"
                );
            }
        }
    }

    if unbound_symbols.len() < k_eff {
        Err(RestoreError::InsufficientSymbols {
            block: *block_id,
            got: unbound_symbols.len(),
            need: k_eff,
        })
    } else {
        Ok(unbound_symbols)
    }
}
```

### `fetch_symbols_from_holder` (private helper)

```rust
async fn fetch_symbols_from_holder(
    &self,
    holder_id: &IdentityPub,
    request: RestoreRequestMsg,
) -> Result<Vec<Symbol>, RestoreError> {
    let conn_arc = self.network.get_connection(*holder_id).await
        .map_err(RestoreError::Network)?;

    let mut guard = conn_arc.lock().await;

    // Send request.
    guard.send_message(&Message::RestoreRequest(request)).await
        .map_err(RestoreError::Network)?;

    // Receive response (first message; a well-behaved peer sends immediately).
    let resp_msg = guard.recv_message().await
        .map_err(RestoreError::Network)?;

    match resp_msg {
        Message::RestoreResponse(resp) => {
            debug!(
                holder = %holder_id,
                symbols = resp.symbols.len(),
                "fetch: received symbols"
            );
            Ok(resp.symbols)
        }
        Message::RestoreDenied(denied) => {
            Err(RestoreError::EscrowDenied {
                holder: *holder_id,
                current_trust: denied.current_trust,
                needed_trust: denied.needed_trust,
                restore_budget_gb: denied.restore_budget_gb,
                restore_gb: denied.restore_budget_gb + 1.0, // approximate
            })
        }
        other => {
            warn!(
                holder = %holder_id,
                msg = ?std::mem::discriminant(&other),
                "fetch: unexpected message type, treating as error"
            );
            Err(RestoreError::Network(
                crate::daemon::network::NetworkError::HandshakeFailed(
                    "unexpected message type during restore".to_string()
                )
            ))
        }
    }
}
```

### Modified `decode_block_local`

Replace the current implementation's final `InsufficientSymbols` return with a network fetch
fallback:

```rust
// After local symbol collection loop:
if unbound_symbols.len() < k_eff {
    // Not enough locally — try network fetch for the remainder.
    debug!(
        block = %block_id,
        local = unbound_symbols.len(),
        need = k_eff,
        "decode: insufficient local symbols, trying network"
    );
    let alive_placements: Vec<_> = self.db.list_placements_for_block(block_id)?
        .into_iter()
        .filter(|p| p.status == PlacementStatus::Alive)
        .collect();

    let mut network_symbols = self.fetch_from_holders(block_id, &alive_placements, params).await?;
    // Merge: avoid duplicates by ESI.
    let existing_esis: std::collections::HashSet<u32> =
        unbound_symbols.iter().map(|s| s.esi).collect();
    for sym in network_symbols.drain(..) {
        if !existing_esis.contains(&sym.esi) {
            unbound_symbols.push(sym);
            if unbound_symbols.len() >= k_eff {
                break;
            }
        }
    }

    if unbound_symbols.len() < k_eff {
        return Err(RestoreError::InsufficientSymbols {
            block: *block_id,
            got: unbound_symbols.len(),
            need: k_eff,
        });
    }
}
```

### Private helper `collect_esis_from_ranges`

```rust
fn collect_esis_from_ranges(ranges: &[(u32, u32)]) -> Vec<u32> {
    ranges.iter()
        .flat_map(|&(start, count)| start..start + count)
        .collect()
}
```

This is identical to `processor::ranges_to_esi_list` — consider moving to a shared utility in
`syncback_core` or just duplicate (keeping modules independent is fine for now).

## `RestoreError` — no new variants needed

`EscrowDenied` already exists in the error enum. `Network` already wraps `NetworkError`.

## Remove `#[allow(dead_code)]`

Delete this attribute from the `network` field of `RestoreCoordinator`.

## Test scenarios

Tests go in `crates/syncback/src/daemon/restore/tests.rs`. Network-restore tests require two real
iroh endpoints (same pattern as `network/tests.rs`). Use `RelayMode::Disabled`.

### Integration test: local restore still works unchanged

All existing tests in `restore/tests.rs` must pass without modification. They use `symbols_dir`
populated by `BackupCoordinator`, and local symbols are present, so the network path is never hit.

### New test: network fetch when local symbols absent

```
decode_block_fetches_from_network_when_local_files_missing
  Setup:
    - NodeA (owner): db with SourceBlockRecord and placements pointing at NodeB.
    - NodeA symbols_dir: EMPTY (simulate restore on a different machine).
    - NodeB (holder): has symbol files in holdings_dir, HoldingRecord with status=Active.
    - NodeB runs a Processor that handles RestoreRequest.
    - NodeA RestoreCoordinator has NodeB in its known_peers via network.add_peer.
  Action:
    - NodeA.decode_block_local(block_id, params, encrypted_size)
  Expect:
    - Returns plaintext bytes (same as original backup content).
    - NodeB's Processor receives RestoreRequestMsg and replies with RestoreResponseMsg.
```

This test is an integration test requiring two running daemon subsystems. Structure it as:
1. `NetworkHandle::start` for both A and B.
2. `Processor::new` for B (with real holdings_dir and db), spawn `processor.run(incoming_rx, inbound_rx, cancel)`.
3. `RestoreCoordinator::new` for A with B's `EndpointAddr` added via `network.add_peer`.
4. Write symbol files under B's holdings_dir manually (or via `BackupCoordinator`).
5. Verify A can reconstruct the original data.

### New test: fetch_from_holders returns InsufficientSymbols when all holders unreachable

```
fetch_from_holders_returns_insufficient_when_no_peers_reachable
  Setup:
    - 3 placements in DB, all Alive, but no peers in known_peers (no address).
    - NetworkHandle for owner (no known peers).
  Action:
    - fetch_from_holders(block_id, &placements, &params)
  Expect:
    - Err(RestoreError::Network(PeerNotFound(_))) — or InsufficientSymbols after all fail
    - Specifically: each `get_connection` fails with PeerNotFound → all holders skipped →
      InsufficientSymbols(got=0, need=k_eff)
```

### New test: fetch skips EscrowDenied holder and continues to next

```
fetch_skips_denied_holder_and_tries_next
  Setup:
    - 2 placements (HolderA, HolderB). HolderA returns RestoreDenied, HolderB returns valid symbols.
    - HolderA Processor: configured to always return RestoreDenied.
    - HolderB Processor: has symbols, returns them.
  Action:
    - fetch_from_holders targeting both
  Expect:
    - Symbols collected from HolderB only.
    - No error returned (k_eff satisfied by HolderB alone).
```

This test requires mock server behavior. Use the two-endpoint pattern and have the HolderA side
manually send `RestoreDenied` after receiving `RestoreRequest`.

### Unit test: collect_esis_from_ranges

```
collect_esis_from_ranges_empty()    -> []
collect_esis_from_ranges([(0,3)])   -> [0,1,2]
collect_esis_from_ranges([(0,2),(5,2)]) -> [0,1,5,6]
```

## `RestoreConfig` — no changes needed

The `parallel_holders` field already exists. Phase 7.7 uses sequential fetch for simplicity;
a future phase can add `FuturesUnordered` parallelism using this config.

## Acceptance criteria

- `#[allow(dead_code)]` removed from `network` field.
- `cargo test -p syncback` passes.
- Local restore tests (backup→restore roundtrip) continue to pass unchanged.
- The integration test `decode_block_fetches_from_network_when_local_files_missing` passes.
- No `unwrap()` calls in new production code (use `?` or explicit error handling).
