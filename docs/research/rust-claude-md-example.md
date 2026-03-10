# CLAUDE.md for SyncBack Rust Implementation (draft)

## Project

SyncBack — decentralized P2P cold backup. Rust reference implementation of the trust protocol.

## Architecture

```
syncback/
  src/
    trust/          # formula (PI+S multiplicative), escrow, adaptive n
    erasure/        # reed-solomon, shard management
    transport/      # QUIC (quinn), gossip relay
    storage/        # local shard storage, SQLite state
    protocol/       # message types, wire format (serde + bincode)
```

## Compiler-level enforcement

```rust
// lib.rs — these are compile ERRORS, not warnings
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]
```

## Bans

### Code
- `unsafe` — banned. No exceptions.
- `.unwrap()` / `.expect()` — banned. Use `?` or explicit match.
- `panic!` — banned in library code. Only in tests.
- `clone()` without a comment explaining why — banned. Clone is expensive, be explicit.
- `Arc<Mutex<T>>` — suspicious. Usually solvable via channels (tokio::sync::mpsc).
- `String` in structs where `&str` or an enum suffices — avoid allocations.

### Dependencies
- New dependency requires justification (what it does, why we can't write it, license).
- `openssl` — banned. Use `rustls` (pure Rust TLS).
- ORM — banned. Use `sqlx` with raw SQL (compile-time checked).
- Serialization: `serde` + `bincode` for wire format, `serde_json` for debug/config only.
- HTTP frameworks — banned. This is P2P, not a web server.
- `tokio-tungstenite` / WebSocket — banned. Use QUIC (quinn).

### Patterns
- No trait objects (`dyn Trait`) without justification. Prefer generics.
- No global state (`static mut`, `lazy_static`, `once_cell` for mutable state). State is passed explicitly.
- No builder pattern. Structs created via `new()` with explicit arguments.
- No inheritance through trait chaining. Composition only.
- No `impl Display` as a substitute for proper serialization.

### Dependency control (cargo-deny)

```toml
# deny.toml
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]

[bans]
deny = [
    { name = "openssl" },
    { name = "openssl-sys" },
    { name = "diesel" },
]
```

## Tests

- Every public function has at least 3 tests.
- Test naming: `what_when_condition_then_outcome` — e.g. `trust_with_zero_storage_returns_minimum`.
- Property-based tests for protocol functions (`proptest` crate).
- Integration tests in `tests/` — full scenario from start to finish.
- Benchmark tests for hot path (`criterion` crate).
- `cargo test` must complete in under 30 seconds for unit tests.

## Error handling

- All errors are typed enums (`thiserror` crate for library, `anyhow` banned in lib code).
- Error variants describe WHAT happened, not WHERE (no `GenericError(String)`).
- `anyhow` is allowed only in `main.rs` / CLI binary code.

```rust
// Good
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("peer {peer_id} not found in local store")]
    PeerNotFound { peer_id: PeerId },
    #[error("storage ratio {ratio} out of range [0, 1]")]
    InvalidStorageRatio { ratio: f64 },
}

// Bad
enum Error {
    Generic(String),        // no
    Io(std::io::Error),     // only if actually wrapping IO
}
```

## Allowed crates (approved list)

```toml
# Core
tokio = "1"               # async runtime
quinn = "0.11"            # QUIC transport
serde = "1"               # serialization framework
bincode = "1"             # wire format
serde_json = "1"          # config/debug only

# Crypto
blake3 = "1"              # hashing (PoS challenges)
ed25519-dalek = "2"       # signatures (identity, gossip)
x25519-dalek = "2"        # key exchange
chacha20poly1305 = "0.10" # symmetric encryption (shard data)

# Storage
sqlx = "0.8"              # SQLite, compile-time checked SQL
reed-solomon-erasure = "6" # erasure coding

# CLI / tooling
clap = "4"                # CLI arguments
tracing = "0.1"           # structured logging (not println!)

# Testing
proptest = "1"            # property-based testing
criterion = "0.5"         # benchmarks
```

New crates not on this list require explicit approval.

## Language

- Code and comments: English.
- Docs and discussion: Russian.
- Commit messages: English.

## AI workflow

- AI writes code, human reviews architecture and logic.
- `cargo build` must pass before submitting for review.
- `cargo clippy -- -D warnings` must pass.
- `cargo test` must pass.
- `cargo deny check` must pass.
- If compiler rejects code, fix the root cause. Do not add `#[allow(...)]`.
