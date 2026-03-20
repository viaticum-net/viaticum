# Task: trust — TrustEngine (β)

Module: `crates/syncback-core/src/trust/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Реализация доверия к пирам. Формула: `trust = (KP * P + KI * I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)`.

В β хранение полностью в памяти (HashMap), без redb. DB модуль в β строится отдельно. TrustEngine получает peers при инициализации и хранит состояние в RAM; персистентность — внешняя задача (DB module сохраняет PeerRecord'ы).

**Ключевое отличие от α:** поля `PeerRecord` изменились: `bytes_sent_to_peer`/`bytes_received_from_peer` → `bytes_we_store_for_peer`/`bytes_peer_stores_for_us`. S-score теперь про хранение, не про GB-переводы.

---

## Dependencies

- `crate::types::{IdentityPub, PeerRecord, Timestamp}`
- `crate::constants::{KP, KI, P_WINDOW_WEEKS, INITIAL_TRUST_P, S_CLAMP_MIN, S_CLAMP_MAX, SECS_PER_WEEK}`
- No DB. No async. No network.

---

## Types Needed

Define within `trust/mod.rs`:

```rust
/// Raw sub-scores for a peer. Returned by score() and recalculate().
#[derive(Debug, Clone, PartialEq)]
pub struct TrustScore {
    /// Rolling P_WINDOW_WEEKS PoS pass rate. [0.0, 1.0]
    pub p: f64,
    /// Cumulative mean of weekly PoS pass rates. [0.0, 1.0]
    pub i: f64,
    /// Raw pairwise storage ratio (not clamped).
    pub s_raw: f64,
    /// Final combined: (KP*p + KI*i) * clamp(s_raw, S_CLAMP_MIN, S_CLAMP_MAX)
    pub combined: f64,
}

/// Outcome of a single PoS round for one peer.
pub struct PosOutcome {
    /// Which protocol-week this round belongs to (monotonically increasing).
    pub week_number: u32,
    pub challenged: u32,
    pub passed: u32,
}

/// Internal per-week record, stored alongside PeerRecord.
#[derive(Debug, Clone)]
struct WeeklyPosRecord {
    pub challenged: u32,
    pub passed: u32,
    pub pass_rate: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown peer: {0}")]
    UnknownPeer(IdentityPub),
}
```

---

## Internal State

```rust
pub struct TrustEngine {
    /// Peer records, keyed by IdentityPub.
    peers: HashMap<IdentityPub, PeerRecord>,
    /// PoS weekly data: (peer, week_number) → record.
    pos_weekly: HashMap<(IdentityPub, u32), WeeklyPosRecord>,
}
```

`TrustEngine` is `Send` but not `Sync`. Caller owns it; in the daemon it lives behind a `Mutex<TrustEngine>` or in a dedicated tokio task.

---

## Public API

```rust
impl TrustEngine {
    /// Create empty engine.
    pub fn new() -> Self;

    /// Initialize from persisted state (called at daemon startup).
    /// peers: all PeerRecords loaded from DB.
    /// pos_history: all (peer, week, challenged, passed) rows from DB.
    pub fn load(
        peers: Vec<PeerRecord>,
        pos_history: Vec<(IdentityPub, u32, u32, u32)>, // (peer, week, challenged, passed)
    ) -> Self;

    /// Export all PeerRecords (for DB persistence).
    pub fn export_peers(&self) -> Vec<PeerRecord>;

    /// Export all PoS weekly data (for DB persistence).
    /// Returns (peer, week_number, challenged, passed).
    pub fn export_pos_history(&self) -> Vec<(IdentityPub, u32, u32, u32)>;

    // -------------------------------------------------------
    // Peer lifecycle
    // -------------------------------------------------------

    /// Register new peer or update last_seen on reconnect.
    /// Sets INITIAL_TRUST_P on first registration; preserves existing P/I/S on reconnect.
    pub fn upsert_peer(&mut self, peer: IdentityPub, now: Timestamp);

    // -------------------------------------------------------
    // PoS recording
    // -------------------------------------------------------

    /// Record the result of a PoS round. Accumulates into weekly bucket.
    /// Panics if week_number == 0 (reserved).
    pub fn record_pos_result(
        &mut self,
        peer: IdentityPub,
        outcome: PosOutcome,
    ) -> Result<(), TrustError>;

    // -------------------------------------------------------
    // S-score (pairwise storage ratio)
    // -------------------------------------------------------

    /// Update raw S-score after storage accounting changes.
    ///
    /// S_raw = bytes_peer_stores_for_us / bytes_we_store_for_peer
    /// If bytes_we_store_for_peer == 0: S_raw = 1.0 (neutral; we store nothing for them).
    /// Stores both byte counts on PeerRecord.
    pub fn update_storage_bytes(
        &mut self,
        peer: IdentityPub,
        bytes_we_store_for_peer: u64,
        bytes_peer_stores_for_us: u64,
    ) -> Result<(), TrustError>;

    // -------------------------------------------------------
    // Score calculation
    // -------------------------------------------------------

    /// Recalculate P and I from stored weekly records; update PeerRecord; return score.
    /// Also updates weeks_in_network = (now - first_seen) / SECS_PER_WEEK.
    pub fn recalculate(
        &mut self,
        peer: &IdentityPub,
        now: Timestamp,
        current_week: u32,
    ) -> Result<TrustScore, TrustError>;

    /// Recalculate all known peers. Returns count of peers updated.
    pub fn recalculate_all(&mut self, now: Timestamp, current_week: u32) -> usize;

    /// Read cached score from PeerRecord (no recalculation).
    pub fn score(&self, peer: &IdentityPub) -> Result<TrustScore, TrustError>;

    /// Read combined score only (convenience). Returns 0.0 for unknown peer (no error).
    pub fn combined_score(&self, peer: &IdentityPub) -> f64;

    // -------------------------------------------------------
    // Queries
    // -------------------------------------------------------

    /// Get PeerRecord. Returns None if unknown.
    pub fn get_peer(&self, peer: &IdentityPub) -> Option<&PeerRecord>;

    /// All peers sorted by combined score descending.
    pub fn peers_by_trust(&self) -> Vec<(&PeerRecord, TrustScore)>;

    /// Reset P and I to 0 for a peer (used after confirmed misbehavior).
    pub fn zero_trust(&mut self, peer: &IdentityPub) -> Result<(), TrustError>;
}

/// Pure formula helper (also useful in placement).
pub fn compute_combined(p: f64, i: f64, s_raw: f64) -> f64 {
    let s = s_raw.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
    (KP * p + KI * i) * s
}
```

---

## Business Rules

### Formula

```
trust = (KP * P + KI * I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)

KP = 0.4  (weight on rolling P)
KI = 1.75 (weight on cumulative I)
S_CLAMP_MIN = 0.1
S_CLAMP_MAX = 1.0
```

### P — Rolling window

- Covers the last `P_WINDOW_WEEKS` = 4 calendar weeks.
- `P = sum(passed in window) / sum(challenged in window)`.
- If `challenged == 0` in the entire window: `P = INITIAL_TRUST_P = 0.1` (preserve bootstrap trust; do NOT set to 0).
- Window: `week_num in [current_week - (P_WINDOW_WEEKS - 1), current_week]` inclusive.

### I — Cumulative mean

- Computed over ALL weeks where `challenged > 0` (not just the window).
- `I = mean(pass_rate_per_active_week)`.
- `pass_rate_per_week = passed / challenged`.
- If no active weeks yet: `I = 0.0`.

### S — Pairwise storage ratio

```
S_raw = bytes_peer_stores_for_us / bytes_we_store_for_peer
```
- If `bytes_we_store_for_peer == 0`: `S_raw = 1.0` (neutral).
- Clamped at use time: `clamp(S_raw, 0.1, 1.0)`.
- S > 1.0 is allowed raw but clamped to 1.0 in formula (you can't get more than full multiplier).

### Initial state for new peer

- `trust_p = INITIAL_TRUST_P = 0.1` (not 0; prevents dead-on-arrival).
- `trust_i = 0.0`.
- `trust_s = 1.0` (neutral).
- `bytes_we_store_for_peer = 0`.
- `bytes_peer_stores_for_us = 0`.
- `first_seen = now`, `last_seen = now`, `weeks_in_network = 0`.

### weeks_in_network

Computed as `(now.0 - first_seen.0) / SECS_PER_WEEK` (integer division, no rounding up). Updated in `recalculate()`.

---

## Test Scenarios

Tests in `trust/tests.rs`. Pattern: `fn what_when_then`.

### 1. `compute_combined_basic`

```
p=0.8, i=0.5, s_raw=0.7
expected = (0.4*0.8 + 1.75*0.5) * 0.7 = (0.32 + 0.875) * 0.7 = 1.195 * 0.7 = 0.8365
```

### 2. `compute_combined_s_clamp_min`

```
p=0.8, i=0.5, s_raw=0.0
S clamped to 0.1
expected = (0.4*0.8 + 1.75*0.5) * 0.1 = 1.195 * 0.1 = 0.1195
```

### 3. `compute_combined_s_clamp_max`

```
p=0.8, i=0.5, s_raw=2.5   (peer stores 2.5× more than us)
S clamped to 1.0
expected = 1.195 * 1.0 = 1.195
```

### 4. `upsert_peer_new_gets_initial_trust`

```
engine = TrustEngine::new()
engine.upsert_peer(peer_A, now)
score = engine.score(&peer_A)
assert score.p == INITIAL_TRUST_P  (0.1)
assert score.i == 0.0
assert score.s_raw == 1.0
combined = (0.4*0.1 + 1.75*0.0) * 1.0 = 0.04
```

### 5. `recalculate_p_rolling_window`

```
current_week = 10, P_WINDOW_WEEKS = 4
weeks 7,8,9,10 → in window
week 6 → excluded

Record: week 6 (challenged=5, passed=5), week 7 (challenged=5, passed=3), week 10 (challenged=2, passed=2)

P = (3+2) / (5+2) = 5/7 ≈ 0.714
I = mean(pass_rate for active weeks):
  week6 = 5/5 = 1.0, week7 = 3/5 = 0.6, week10 = 2/2 = 1.0
  I = (1.0 + 0.6 + 1.0) / 3 = 0.867
```

### 6. `recalculate_p_is_initial_when_no_pos_data_in_window`

```
Record only week 3 (old). current_week = 10, window = [7,10].
No data in window → P = INITIAL_TRUST_P = 0.1 (NOT 0.0)
I still computed from all active weeks = 1.0 (if week3 had all passed)
```

### 7. `update_storage_bytes_s_neutral_when_we_store_nothing`

```
bytes_we_store_for_peer = 0, bytes_peer_stores_for_us = 500_000
S_raw = 1.0  (neutral, not infinity)
```

### 8. `update_storage_bytes_s_below_one_when_peer_stores_less`

```
bytes_we_store_for_peer = 1_000_000_000  (1 GB)
bytes_peer_stores_for_us = 500_000_000   (0.5 GB)
S_raw = 0.5
```

### 9. `zero_trust_resets_p_and_i`

```
After many PoS rounds with good scores, call zero_trust().
score().p == 0.0, score().i == 0.0
S unchanged.
```

### 10. `load_round_trips_state`

```
engine1 with several peers and PoS records
peers = engine1.export_peers()
pos = engine1.export_pos_history()
engine2 = TrustEngine::load(peers, pos)
score from engine2 matches engine1 for all peers
```

### 11. `recalculate_all_returns_count`

```
3 peers registered. recalculate_all() returns 3.
```

### 12. `peers_by_trust_sorted_descending`

```
3 peers with different computed combined scores.
peers_by_trust() returns them in descending order of combined.
```

---

## Reference: α code

See `alpha_crates/syncback-core/src/trust/mod.rs`:
- `compute_combined()` — same formula, copy directly.
- `recalculate()` — same P/I logic but β uses in-memory `HashMap` instead of redb scan.
- `upsert_peer()` — same initial state (but field names changed: use `bytes_we_store_for_peer` / `bytes_peer_stores_for_us`).
- `record_pos_result()` — same accumulation logic, but store in `HashMap<(IdentityPub, u32), WeeklyPosRecord>`.

---

## Notes

- Tests go in `trust/tests.rs`, NOT inline. See CLAUDE.md.
- No `#[derive(Default)]` trick to initialize: use `TrustEngine::new()`.
- `combined_score()` for unknown peer returns `0.0`, never errors — used by placement engine for unknown holders.
