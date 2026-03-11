# Task Spec: trust.rs

Module: `crates/syncback-core/src/trust.rs`
Phase: 1 (syncback-core, pure logic)
Depends on: `types.rs`, `db.rs`

---

## Overview

TrustEngine maintains per-peer reputation scores that drive shard placement decisions. It computes three
sub-scores — P (recent performance), I (cumulative history), S (pairwise storage ratio) — and combines
them into a single trust value. All state is persisted in redb; the engine is stateless except for
the Db handle.

The trust formula is the only original part of SyncBack. Implementer must reproduce it exactly.

---

## Types

All types below live in `types.rs` unless marked as defined here.

```rust
// Already in types.rs:
pub struct IdentityPub(pub [u8; 32]);
pub struct Timestamp(pub u64);   // Unix seconds
```

The following types are DEFINED IN trust.rs (not types.rs — they are internal to trust logic):

```rust
/// Raw sub-scores for a peer. Stored in DB, returned by score().
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustScore {
    /// Rolling 4-week PoS pass rate: passed / total challenges in last 4 weeks.
    /// Range: [0.0, 1.0]. Zero if no challenges in window.
    pub p: f64,

    /// Cumulative mean of weekly PoS pass rates since first_seen.
    /// Range: [0.0, 1.0]. Zero if no complete weeks.
    pub i: f64,

    /// Pairwise GB ratio: bytes_received_from_peer / bytes_sent_to_peer.
    /// Clamped to [0.1, 1.0] in formula, stored raw here.
    /// f64::INFINITY if bytes_sent == 0 (peer is pure taker, but we gave nothing — neutral).
    /// Set to NEUTRAL (1.0) when bytes_sent_to_peer == 0 (no relationship yet).
    pub s_raw: f64,

    /// Final combined score: (kp * p + ki * i) * clamp(s_raw, 0.1, 1.0).
    /// Range: [0.0, ~4.0] (with kp=0.5, ki=2.0, p=1, i=1, s=1 => 2.5 max typical).
    pub combined: f64,
}

/// A single PoS round outcome for one peer.
pub struct PosOutcome {
    pub week_number: u32,   // monotonically increasing week index (weeks since epoch)
    pub challenged: u32,    // shards challenged this week
    pub passed: u32,        // shards that responded correctly
}

/// Transfer event: bytes exchanged with a peer (call after blob transfer completes).
pub struct TransferEvent {
    pub peer: IdentityPub,
    pub bytes_sent_to_peer: u64,      // we uploaded to peer (peer is holder of our shard)
    pub bytes_received_from_peer: u64, // we downloaded from peer (we hold peer's shard)
}
```

### Constants

All constants are imported from `crate::constants` (see `docs/tasks/constants.md`).
This module uses: `KP`, `KI`, `P_WINDOW_WEEKS`, `S_CLAMP_MIN`, `S_CLAMP_MAX`, `SECS_PER_WEEK`.

---

## DB Tables

trust.rs reads and writes the following tables. Table definitions live in `db.rs`; trust.rs uses
them via the `Db` wrapper.

### Table: `peers`

Key: `IdentityPub` (32 bytes, raw)
Value: CBOR-serialized `PeerRecord` (defined in types.rs)

```rust
// In types.rs:
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    pub identity: IdentityPub,
    pub trust_p: f64,          // current P score
    pub trust_i: f64,          // current I score
    pub trust_s: f64,          // current S raw (NOT clamped)
    pub bytes_sent_to_peer: u64,
    pub bytes_received_from_peer: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub weeks_in_network: u32, // calendar weeks since first_seen (for escrow)
    pub subnet: Option<[u8; 4]>, // /24 subnet of peer (first 3 octets + 0), for placement
}
```

### Table: `pos_weekly`

Stores per-week PoS outcomes per peer. Used to compute P (4-week rolling) and accumulate I.

Key: `(IdentityPub, week_number: u32)` — encode as 32 + 4 = 36 bytes, big-endian week.
Value: CBOR-serialized `WeeklyPosRecord`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeeklyPosRecord {
    pub challenged: u32,
    pub passed: u32,
    /// Computed pass rate = passed / challenged. 0.0 if challenged == 0.
    pub pass_rate: f64,
}
```

This table is append-only during a week. At trust update time, old weeks outside the rolling window
are NOT deleted (they contribute to I). The 4-week window is computed by scanning only the last 4
week keys for this peer.

---

## Public API

```rust
pub struct TrustEngine {
    db: Db,
}

impl TrustEngine {
    /// Create engine with an open DB handle.
    pub fn new(db: Db) -> Self;

    /// Ensure a peer exists in the DB (called on first contact / peer_announce).
    /// If peer already exists, updates last_seen only.
    /// Does NOT change trust scores.
    pub fn upsert_peer(
        &self,
        peer: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), TrustError>;

    /// Record the result of a PoS round for a peer.
    /// Accumulates into pos_weekly for the given week_number.
    /// Idempotent per (peer, week_number): calling multiple times in the same week
    /// ADDS challenged/passed to existing record (PoS is sampled 5 shards at a time).
    ///
    /// Does NOT recompute TrustScore — call recalculate() at end of week.
    pub fn record_pos_result(
        &self,
        peer: &IdentityPub,
        outcome: PosOutcome,
    ) -> Result<(), TrustError>;

    /// Record bytes exchanged with a peer after a blob transfer.
    /// Adds to cumulative bytes_sent_to_peer / bytes_received_from_peer in PeerRecord.
    /// Recomputes S_raw immediately and updates trust_s in PeerRecord.
    /// Does NOT recompute P or I — call recalculate() for full update.
    pub fn record_transfer(
        &self,
        event: &TransferEvent,
    ) -> Result<(), TrustError>;

    /// Recompute trust scores for a peer based on accumulated PoS data.
    /// Called by Scheduler at end of each week (WeeklySync).
    ///
    /// Algorithm:
    ///   1. Read pos_weekly records for this peer.
    ///   2. Compute P: sum(passed) / sum(challenged) over last P_WINDOW_WEEKS weeks.
    ///      If no challenges in window: P = 0.0.
    ///   3. Compute I: mean(pass_rate) over ALL historical weeks.
    ///      If no complete weeks: I = 0.0.
    ///   4. Read trust_s from PeerRecord (S already up-to-date from record_transfer calls).
    ///   5. combined = (KP * P + KI * I) * clamp(S_raw, S_CLAMP_MIN, S_CLAMP_MAX)
    ///   6. Write updated trust_p, trust_i back to PeerRecord.
    ///   7. Update weeks_in_network = (now - first_seen) / SECONDS_PER_WEEK.
    pub fn recalculate(
        &self,
        peer: &IdentityPub,
        now: Timestamp,
        current_week: u32,
    ) -> Result<TrustScore, TrustError>;

    /// Recalculate trust for ALL known peers.
    /// Called by Scheduler at end of each week.
    /// Returns number of peers updated.
    pub fn recalculate_all(
        &self,
        now: Timestamp,
        current_week: u32,
    ) -> Result<usize, TrustError>;

    /// Return current trust score for a peer WITHOUT recomputing.
    /// Reads trust_p, trust_i, trust_s from PeerRecord.
    /// Computes combined = (KP * p + KI * i) * clamp(s_raw, S_CLAMP_MIN, S_CLAMP_MAX).
    /// Returns TrustError::UnknownPeer if peer not in DB.
    pub fn score(&self, peer: &IdentityPub) -> Result<TrustScore, TrustError>;

    /// Return the combined trust value for a peer (convenience wrapper over score()).
    /// Returns 0.0 for unknown peers (not an error — used in placement hot path).
    pub fn combined_score(&self, peer: &IdentityPub) -> Result<f64, TrustError>;

    /// Set trust to zero for a peer: mark as cheater.
    /// Called when 2+ PoS failures on different shards are detected (hostile behavior).
    /// Sets trust_p = 0.0, trust_i = 0.0 in DB.
    /// Does NOT delete pos_weekly history (audit trail).
    pub fn zero_trust(
        &self,
        peer: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), TrustError>;

    /// List all known peers with their current scores.
    /// Returns pairs (PeerRecord, TrustScore). Score is computed on the fly from stored p/i/s.
    pub fn all_peers_with_scores(&self) -> Result<Vec<(PeerRecord, TrustScore)>, TrustError>;

    /// Return the full PeerRecord for a peer (includes weeks_in_network for escrow).
    pub fn get_peer(&self, peer: &IdentityPub) -> Result<Option<PeerRecord>, TrustError>;
}
```

### Error enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown peer: {0:?}")]
    UnknownPeer(IdentityPub),

    #[error("db error: {0}")]
    Db(#[from] redb::Error),

    #[error("serialization error: {0}")]
    Cbor(String),  // from ciborium
}
```

---

## Business Rules (exact formulas)

### Trust formula

```
trust_AB = (KP * P_B + KI * I_B) * clamp(S_AB, S_CLAMP_MIN, S_CLAMP_MAX)

where:
  KP = 0.4      (proportional: recent weeks matter)
  KI = 1.75     (integral: long history matters more)
  S_CLAMP_MIN = 0.1
  S_CLAMP_MAX = 1.0
```

### P: 4-week rolling PoS pass rate

```
P = Σ passed_w  /  Σ challenged_w
    for w in [current_week - P_WINDOW_WEEKS + 1, current_week]

Edge cases:
  - No challenges in window → P = 0.0
  - A week with challenged == 0 contributes 0 to both numerator and denominator
    (i.e., a silent week does NOT count as "passed" or "failed")
  - Week with challenged > 0 and passed == 0 → full fail for that week's weight
```

Why aggregate across weeks (not mean of rates): protects against a peer with 1 challenge/week.
If we averaged rates, 1-pass-1-challenged = 1.0 has same weight as 100-pass-100-challenged = 1.0.
Aggregating totals means more challenges = more signal.

### I: cumulative mean pass rate

```
I = mean(pass_rate_w)
    for ALL w in pos_weekly for this peer where challenged_w > 0

pass_rate_w = passed_w / challenged_w

Edge cases:
  - No weeks with challenges → I = 0.0
  - A week with 0 challenges is excluded from the mean (not averaged in as 0)
  - I is a simple arithmetic mean, not weighted, not exponentially decayed
```

### S: pairwise GB ratio

```
S_raw_AB = bytes_received_from_B / bytes_sent_to_B

Edge cases:
  - bytes_sent_to_B == 0: S_raw = 1.0 (neutral, no relationship established yet)
  - bytes_received_from_B == 0 and bytes_sent_to_B > 0: S_raw = 0.0
    (we sent but received nothing — freeloader, gets minimum S_CLAMP_MIN in formula)
  - S_raw is stored RAW (not clamped) in PeerRecord.trust_s
  - Clamping happens only at combined score calculation time
```

Semantics: S_AB measures how much B reciprocates our storage contribution. If B stores our shards
(we upload = bytes_sent_to_B grows), B should also hold shards for us which we download from them
(bytes_received_from_B grows). A peer that only takes but never gives → S_raw → 0 → trust halved.

DECIDED: S = bytes_received_from_B / bytes_sent_to_B. "sent_to" = us uploading our shards
TO peer B (B is holder). "received_from" = us downloading B's shards that WE hold.
This is pairwise holder-relationship semantics (confirmed, consistent with CLAUDE.md).

### Combined score final computation

```rust
pub fn compute_combined(p: f64, i: f64, s_raw: f64) -> f64 {
    let s_clamped = s_raw.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
    (KP * p + KI * i) * s_clamped
}
```

### Hostile behavior detection (trust zeroing)

From overview.md §1.3:
- 1 fail on 1 shard: bit rot / accident. Send storage_warning. Do NOT zero trust.
- 2+ fails on DIFFERENT shards: hostile behavior. Zero trust, remove all shard relationships.

The TrustEngine's `zero_trust()` method is called externally (by Processor/PoS logic) once
it determines the threshold has been crossed. TrustEngine does not detect the threshold itself —
it just applies the zeroing when told.

### weeks_in_network

```
weeks_in_network = (now.0 - peer.first_seen.0) / SECONDS_PER_WEEK

SECONDS_PER_WEEK = 7 * 24 * 60 * 60 = 604800

Truncating integer division. A peer seen 6 days ago has weeks_in_network = 0.
```

This field is used by EscrowChecker (escrow.rs) and is kept up-to-date in recalculate().

---

## DB Operations (detailed)

### upsert_peer

```
READ  peers[identity]
  → exists: update last_seen, write back
  → not exists: write new PeerRecord with trust_p=0, trust_i=0, trust_s=1.0 (neutral S),
                bytes_sent=0, bytes_received=0, first_seen=now, last_seen=now, weeks_in_network=0
```

### record_pos_result

```
READ  pos_weekly[(peer, week_number)]
  → exists: challenged += outcome.challenged, passed += outcome.passed, recompute pass_rate
  → not exists: create WeeklyPosRecord { challenged, passed, pass_rate }
WRITE pos_weekly[(peer, week_number)]
WRITE peers[peer] → update last_seen
```

### record_transfer

```
READ  peers[peer]
UPDATE bytes_sent_to_peer += event.bytes_sent_to_peer
       bytes_received_from_peer += event.bytes_received_from_peer
       trust_s = if bytes_sent == 0 { 1.0 } else { bytes_received / bytes_sent }
       last_seen = now (caller must supply now)
WRITE peers[peer]
```

DECIDED: record_transfer takes `now: Timestamp` parameter to keep last_seen always correct.

Updated signature:
```rust
pub fn record_transfer(
    &self,
    event: &TransferEvent,
    now: Timestamp,
) -> Result<(), TrustError>;
```

### recalculate (one peer)

```
READ  pos_weekly range scan: all keys starting with peer's IdentityPub bytes
  → compute P over last P_WINDOW_WEEKS weeks
  → compute I over all weeks with challenged > 0
READ  peers[peer]
  → S_raw = trust_s (already up-to-date)
  → combined = compute_combined(P, I, S_raw)
  → weeks_in_network = (now - first_seen) / SECONDS_PER_WEEK
WRITE peers[peer]: update trust_p, trust_i, last_seen, weeks_in_network
RETURN TrustScore { p, i, s_raw, combined }
```

### recalculate_all

```
SCAN  peers table (all keys)
FOR EACH peer: call recalculate(peer, now, current_week)
RETURN count of peers updated
```

---

## Test Scenarios

All tests use `testutil::test_db()` (real redb on tmpfile) and `testutil::test_peer()`.

### trust_score_is_zero_for_unknown_peer

```
Input:  engine.score(&unknown_peer)
Expect: TrustError::UnknownPeer
```

### combined_score_returns_zero_for_unknown_peer

```
Input:  engine.combined_score(&unknown_peer)
Expect: Ok(0.0)  — not an error, just neutral
```

### upsert_peer_creates_neutral_record

```
Input:  engine.upsert_peer(&peer, Timestamp(1000))
        engine.score(&peer)
Expect: TrustScore { p: 0.0, i: 0.0, s_raw: 1.0, combined: 0.0 }
  (combined = (0.4*0 + 1.75*0) * clamp(1.0) = 0.0)
```

### pos_success_increases_p_score

```
Setup:  engine.upsert_peer(&peer, t0)
        engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 5 })
        engine.recalculate(&peer, t0 + 1_week, current_week=1)
Expect: score.p == 1.0
        score.i == 1.0
        score.combined == (0.4*1.0 + 1.75*1.0) * clamp(1.0, 0.1, 1.0) == 2.15
```

### pos_partial_failure_reduces_p

```
Setup:  record_pos_result week=1: challenged=10, passed=8
        recalculate(week=1)
Expect: score.p == 0.8
        score.i == 0.8
        score.combined == (0.4*0.8 + 1.75*0.8) * 1.0 == 1.72
```

### p_window_is_exactly_4_weeks

```
Setup:  record_pos_result for weeks 1,2,3,4,5: each challenged=10, passed=10
        recalculate(current_week=5)
Expect: P window covers weeks 2,3,4,5 only (week 1 is outside 4-week window)
        P = (10+10+10+10)/(10+10+10+10) = 1.0  (passes trivially)

Setup2: record week 1: challenged=10, passed=0  (full fail)
        record weeks 2,3,4,5: challenged=10, passed=10
        recalculate(current_week=5)
Expect: P = (0+10+10+10)/(10+10+10+10) = 30/40 = 0.75  (week 1 outside window)
        NOT (0+10+10+10+10)/50 = 0.8
```

### i_is_cumulative_all_time_mean

```
Setup:  record week=1: challenged=10, passed=10  (rate=1.0)
        record week=2: challenged=10, passed=5   (rate=0.5)
        record week=3: challenged=10, passed=0   (rate=0.0)
        recalculate(current_week=3)
Expect: I = mean(1.0, 0.5, 0.0) = 0.5
        P = (10+5+0)/(10+10+10) = 0.5
```

### silent_week_not_counted_in_i

```
Setup:  record week=1: challenged=10, passed=10 (rate=1.0)
        [week 2: no record, peer was silent]
        record week=3: challenged=10, passed=10 (rate=1.0)
        recalculate(current_week=3)
Expect: I = mean(1.0, 1.0) = 1.0  (week 2 excluded from mean)
        P covers weeks 0,1,2,3 → weeks 1 and 3 have data: P = (10+10)/(10+10) = 1.0
```

### s_score_neutral_when_no_transfers

```
Setup:  upsert_peer(&peer, t0)
Expect: trust_s = 1.0  (neutral S, no relationship)
        (peer has not yet stored our shards)
```

### s_score_freeloader_gets_minimum

```
Setup:  upsert_peer(&peer, t0)
        record_transfer: bytes_sent_to_peer=1_000_000_000, bytes_received_from_peer=0
        recalculate(...)
Expect: trust_s stored = 0.0 (raw)
        combined = (KP*P + KI*I) * clamp(0.0, 0.1, 1.0)
               = (any) * 0.1  ← freeloader gets 1/10th weight
```

### s_score_good_reciprocator

```
Setup:  record_transfer: bytes_sent=1_000_000_000, bytes_received=1_000_000_000
Expect: trust_s = 1.0
        clamp(1.0, 0.1, 1.0) = 1.0
```

### s_score_exceeds_one_is_clamped

```
Setup:  record_transfer: bytes_sent=100, bytes_received=200
Expect: trust_s stored = 2.0 (raw)
        clamp(2.0, 0.1, 1.0) = 1.0  (capped, not penalized for over-contributing)
```

### zero_trust_clears_scores

```
Setup:  record_pos_result week=1: challenged=5, passed=5
        recalculate(...)  → combined > 0
        zero_trust(&peer, now)
        score(&peer)
Expect: TrustScore { p: 0.0, i: 0.0, s_raw: unchanged, combined: 0.0 }
```

### recalculate_all_updates_all_peers

```
Setup:  upsert_peer(peer_a, t0); upsert_peer(peer_b, t0)
        record_pos_result(peer_a, week=1, challenged=5, passed=5)
        record_pos_result(peer_b, week=1, challenged=5, passed=4)
        recalculate_all(now=t0 + 1_week, current_week=1)
Expect: score(peer_a).combined > score(peer_b).combined
```

### weeks_in_network_computed_correctly

```
Setup:  upsert_peer(&peer, Timestamp(0))
        recalculate(&peer, Timestamp(604800 * 13), current_week=13)
        get_peer(&peer)
Expect: peer_record.weeks_in_network == 13
```

### pos_results_accumulate_within_week

```
Setup:  record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 4 })
        record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 5 })
        recalculate(current_week=1)
Expect: P = (4+5)/(5+5) = 0.9  (accumulated within same week, not replaced)
```

### upsert_peer_idempotent

```
Setup:  upsert_peer(&peer, Timestamp(1000))
        upsert_peer(&peer, Timestamp(2000))
        get_peer(&peer)
Expect: peer.first_seen == Timestamp(1000)  (not overwritten)
        peer.last_seen == Timestamp(2000)   (updated)
```

---

## Dependencies

- `types.rs` — `IdentityPub`, `Timestamp`, `PeerRecord`
- `db.rs` — `Db` newtype, table definitions for `peers` and `pos_weekly`
- `redb` — read/write transactions
- `serde` + `ciborium` — CBOR for values
- `thiserror` — TrustError

trust.rs does NOT depend on escrow.rs, placement.rs, budget.rs, or messages.rs.

---

## Notes for Implementer

1. redb transactions: use one `WriteTransaction` per logical operation (upsert_peer, record_pos_result,
   etc.). Do not hold a write transaction open across multiple engine calls — the Processor task
   serializes all DB writes, so there is no concurrent write risk, but holding a transaction open
   unnecessarily blocks readers.

2. CBOR serialization: use `ciborium::into_writer` / `ciborium::from_reader`. Wrap errors in
   `TrustError::Cbor(e.to_string())`. Do not use `serde_cbor` — the workspace uses `ciborium`.

3. pos_weekly key encoding: encode as `[identity_pub_bytes (32)] ++ [week_number.to_be_bytes() (4)]`.
   redb range scans over fixed-length byte keys are fast. To scan all weeks for a peer, use range
   `[peer_bytes ++ [0,0,0,0], peer_bytes ++ [0xff,0xff,0xff,0xff]]`.

4. The test helper `testutil::week(n)` returns `Timestamp(n as u64 * 604800)` — use it in tests.

5. All f64 arithmetic: use standard IEEE 754. Do not worry about NaN — if challenged > 0,
   passed/challenged is always finite. The S_raw neutral value of 1.0 when bytes_sent==0 is a
   business rule, not a math convenience.

6. No tracing calls in the formula computation path. Log at DEBUG level only at the top of
   recalculate() and record_pos_result().
