# Task: Commitment Telemetry (Phase 4.4)

Module: `crates/syncback-core/src/commitment/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Commitment telemetry answers the question: "How likely is a given holder to keep our
symbols for the next N weeks?" It does this by *computing* the answer from observable
evidence — not by asking the holder (cheap talk, pooling Nash equilibrium, proven
unworkable in plan.md §"Commitment spectrum").

The module is purely a scoring engine. It reads signals that are already available in
existing data structures (`SymbolPlacement`, `PeerRecord`, `HoldingRecord`, eviction
priority) and combines them into a single `CommitmentScore ∈ [0.0, 1.0]`. This score is
then used by the owner to:

1. Decide whether proactive repair is needed (low commitment → redistribute before
   symbols are confirmed lost).
2. Feed into the `syncback status --forecast` reliability display (Phase 4.5).
3. Optionally bias future placement weights toward more committed holders.

The module does **no network I/O, no DB access, no async**. It is `syncback-core` pure
logic. The caller assembles `HolderProfile` from DB data and passes it in.

---

## Background: why computed, not self-reported

Self-reported commitment ("I will keep your data for 6 months") is a pooling equilibrium:
every rational holder claims the maximum regardless of intent, because truthful disclosure
carries no benefit and truthful low-reporting brings punishment. The signal collapses to
noise.

Computed commitment uses signals that are hard or impossible to fake without actually
behaving honestly:

| Signal | Why it's hard to fake |
|--------|----------------------|
| PoS pass rate | Requires actually storing and serving symbols |
| Offers rejected recently | Disk full → can't accept more → existing is at risk |
| Eviction priority of owner's data | Low-importance / low-trust data is evicted first |
| Age of relationship | Long-term holders have demonstrated persistence |
| Active eviction events | Holder already evicted *someone's* data recently |

---

## Dependencies

- `crate::types::{IdentityPub, SourceBlockId, Timestamp}`
- `crate::constants::{
    EVICTION_HYSTERESIS, AGE_BONUS_CAP, AGE_BONUS_WEEKS,
    SECS_PER_WEEK, POS_CONSECUTIVE_MISS_UNCERTAIN, POS_CONSECUTIVE_MISS_PRESUMED_LOST
  }`
- `crate::budget::eviction_priority` — reuse the holder-side eviction priority formula
- No DB. No async. No network.

---

## New Constants in `constants.rs`

Add these after the existing eviction priority block:

```rust
// === Commitment telemetry ===

/// Weight of PoS pass rate in commitment score.
pub const COMMITMENT_POS_WEIGHT: f64 = 0.5;

/// Weight of disk pressure signal in commitment score.
pub const COMMITMENT_PRESSURE_WEIGHT: f64 = 0.25;

/// Weight of relationship age signal in commitment score.
pub const COMMITMENT_AGE_WEIGHT: f64 = 0.15;

/// Weight of eviction priority of our data at the holder's node.
pub const COMMITMENT_PRIORITY_WEIGHT: f64 = 0.10;

/// Weeks of relationship needed to reach full age signal (1.0).
pub const COMMITMENT_AGE_SATURATION_WEEKS: f64 = 26.0;

/// Fraction of total PoS challenges issued in the last 4 weeks that must
/// be answered for the pass rate not to penalise (minimum activity threshold).
/// Below this: treat as if pass rate were 0. Prevents "no challenges = pass_rate=1.0".
pub const COMMITMENT_MIN_CHALLENGES: u32 = 1;

/// Eviction priority threshold below which commitment takes a penalty.
/// If our_eviction_priority < this * max_observed_priority, commitment is penalised.
/// Set to 0.0 to disable the relative penalty (use only absolute priority).
pub const COMMITMENT_PRIORITY_FLOOR: f64 = 0.0;
```

---

## Types

Define these in `commitment/mod.rs`:

```rust
/// Commitment score for one holder for one owner's data.
/// Range [0.0, 1.0]. Higher = more committed (less likely to evict).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommitmentScore(pub f64);

impl CommitmentScore {
    /// Clamps the inner value to [0.0, 1.0].
    pub fn new(raw: f64) -> Self {
        CommitmentScore(raw.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    /// Human-readable tier for CLI display.
    pub fn tier(self) -> CommitmentTier {
        match self.0 {
            x if x >= 0.75 => CommitmentTier::High,
            x if x >= 0.45 => CommitmentTier::Medium,
            x if x >= 0.20 => CommitmentTier::Low,
            _ => CommitmentTier::AtRisk,
        }
    }
}

/// Qualitative tier. Used only for display; business logic uses f64 score directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentTier {
    /// score >= 0.75. Holder is reliable, no action needed.
    High,
    /// 0.45 <= score < 0.75. Acceptable but worth monitoring.
    Medium,
    /// 0.20 <= score < 0.45. Consider proactive repair if importance is high.
    Low,
    /// score < 0.20. Trigger proactive repair regardless of current PlacementStatus.
    AtRisk,
}

/// All inputs needed to compute a CommitmentScore for one holder.
/// Assembled by the caller from DB records. No DB access inside this module.
#[derive(Debug, Clone)]
pub struct HolderProfile {
    /// The holder's identity (informational; not used in computation directly).
    pub holder_id: IdentityPub,

    // --- PoS signals ---

    /// Number of PoS challenges issued to this holder in the last 4 weeks.
    /// 0 = no challenges yet (new peer or very quiet period).
    pub recent_challenges: u32,

    /// Number of those challenges that passed (Pass outcome).
    pub recent_passes: u32,

    /// Consecutive timeout misses on this holder's current placement.
    /// Source: `SymbolPlacement::consecutive_misses`.
    pub consecutive_misses: u32,

    // --- Disk pressure signals ---

    /// Has this holder rejected symbol offers in the last 7 days?
    /// Observable: daemon tracks `symbol_offer` rejections per peer.
    pub offers_rejected_recently: bool,

    /// Has this holder sent a drop notice to us (or anyone observable) recently?
    /// Observable: DropNoticeTarget messages received from this holder in last 14 days.
    pub drop_notice_sent_recently: bool,

    // --- Eviction priority of our data at this holder ---

    /// Eviction priority of our data as computed by the holder's policy.
    /// Computed by the owner using `budget::eviction_priority(importance, holder_trust,
    /// placed_at, now_secs)`. Range [0.0, ~1.3] (unbounded above 1.0 due to age bonus).
    /// This is the priority our data has at the holder's eviction queue.
    pub our_eviction_priority: f64,

    /// Maximum eviction priority seen across all our placements at all holders
    /// (or at this holder across all blocks). Used to normalize the priority signal.
    /// If 0.0, the priority signal is treated as neutral.
    pub max_known_eviction_priority: f64,

    // --- Relationship age ---

    /// When did we first interact with this holder (Unix seconds).
    pub first_seen: Timestamp,

    /// Current time (Unix seconds).
    pub now: Timestamp,
}

/// Error variants for the commitment module.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    #[error("holder profile has inconsistent data: recent_passes ({passes}) > recent_challenges ({challenges})")]
    InconsistentPoSCounts { passes: u32, challenges: u32 },
}
```

---

## Public API

```rust
/// Compute commitment score for one holder from observable signals.
///
/// Returns Err only if the profile is internally inconsistent (passes > challenges).
/// All other edge cases (0 challenges, unknown priority, new peer) are handled
/// gracefully with conservative defaults.
///
/// Formula (weighted sum, then clamp to [0.0, 1.0]):
///   score = pos_component * COMMITMENT_POS_WEIGHT
///         + pressure_component * COMMITMENT_PRESSURE_WEIGHT
///         + age_component * COMMITMENT_AGE_WEIGHT
///         + priority_component * COMMITMENT_PRIORITY_WEIGHT
///
/// Each component is in [0.0, 1.0]. See Business Rules for each.
pub fn compute_commitment(profile: &HolderProfile) -> Result<CommitmentScore, CommitmentError>;

/// Convert a CommitmentScore to a probability of losing symbols in the next period.
///
/// Interpretation: eviction_risk = 1.0 - score^2
/// The quadratic mapping means:
///   - High commitment (0.9) → risk = 1 - 0.81 = 0.19 (19%)
///   - Medium (0.6)          → risk = 1 - 0.36 = 0.64 (64%)
///   - At-risk (0.1)         → risk = 1 - 0.01 = 0.99 (99%)
///
/// This is a *relative ordering* tool, not a calibrated probability.
/// Use it for prioritising repair decisions, not for mathematical reliability forecasts
/// (ReliabilityForecast does that, using PoS pass rates directly).
pub fn eviction_risk(score: CommitmentScore) -> f64;

/// Given a list of (holder, commitment) pairs for one source block,
/// return which holders should have proactive repair triggered.
///
/// A holder is flagged when:
///   tier == AtRisk
///   OR (tier == Low AND importance >= 0.7)
///
/// Returns a Vec of holder identities to act on.
/// Does not trigger repair itself — that is RepairAgent's job.
pub fn flag_for_proactive_repair(
    holders: &[(IdentityPub, CommitmentScore)],
    importance: f64,
) -> Vec<IdentityPub>;

/// Compute the PoS-pass-rate component (0.0..=1.0).
/// Exposed as pub for testing and for use by ReliabilityForecast.
pub fn pos_component(recent_challenges: u32, recent_passes: u32) -> f64;

/// Compute the disk pressure component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn pressure_component(offers_rejected_recently: bool, drop_notice_sent_recently: bool) -> f64;

/// Compute the relationship age component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn age_component(first_seen: Timestamp, now: Timestamp) -> f64;

/// Compute the eviction priority component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn priority_component(our_priority: f64, max_priority: f64) -> f64;
```

---

## Business Rules

### Component: PoS pass rate (`pos_component`)

```
if recent_challenges < COMMITMENT_MIN_CHALLENGES:
    return 0.5   // no data yet → neutral (neither good nor bad)

pass_rate = recent_passes as f64 / recent_challenges as f64

// Penalise consecutive misses on top of raw pass rate.
// Each miss below Uncertain threshold degrades the signal.
miss_penalty = match consecutive_misses:
    0                                          → 0.0
    1..POS_CONSECUTIVE_MISS_PRESUMED_LOST      → 0.15  // Uncertain
    POS_CONSECUTIVE_MISS_PRESUMED_LOST+        → 0.35  // PresumedLost or worse

return (pass_rate - miss_penalty).max(0.0)
```

Rationale: `pass_rate` captures long-term reliability; `miss_penalty` captures current
degradation that has not yet been folded into the weekly PoS history. The two signals are
complementary.

### Component: Disk pressure (`pressure_component`)

```
score = 1.0

if offers_rejected_recently:
    score -= 0.5   // Disk full → existing data at risk of eviction

if drop_notice_sent_recently:
    score -= 0.4   // Holder is actively shedding data

return score.max(0.0)
```

Note: both flags can be true simultaneously, giving score = max(0.0, 0.1) = 0.1.

### Component: Relationship age (`age_component`)

```
weeks_known = (now.0 - first_seen.0) as f64 / SECS_PER_WEEK as f64
age_signal = (weeks_known / COMMITMENT_AGE_SATURATION_WEEKS).min(1.0)
return age_signal
```

New peer (0 weeks) → 0.0. Peer known 26+ weeks → 1.0.

### Component: Eviction priority (`priority_component`)

```
if max_known_eviction_priority <= 0.0:
    return 0.5   // No reference point → neutral

normalized = (our_eviction_priority / max_known_eviction_priority).min(1.0)
return normalized
```

Our data has high priority at the holder → they are less likely to evict it.
Our data has low priority (low importance, low trust, new) → high eviction risk.

Edge case: if `our_eviction_priority` is 0.0 and `max_known_eviction_priority` is 0.0,
return 0.5 (no data → neutral).

### Final score assembly (`compute_commitment`)

```
score_raw = pos_component(...)      * COMMITMENT_POS_WEIGHT       // 0.50
          + pressure_component(...) * COMMITMENT_PRESSURE_WEIGHT  // 0.25
          + age_component(...)      * COMMITMENT_AGE_WEIGHT       // 0.15
          + priority_component(...) * COMMITMENT_PRIORITY_WEIGHT  // 0.10

CommitmentScore::new(score_raw)  // clamp to [0.0, 1.0]
```

The weights sum to 1.0. The individual components are each in [0.0, 1.0], so the weighted
sum is also naturally in [0.0, 1.0] before clamping. `CommitmentScore::new` still clamps
as a defensive measure.

### Eviction risk formula

```
eviction_risk(score) = 1.0 - score.value().powi(2)
```

Range: score=0.0 → risk=1.0; score=1.0 → risk=0.0.
This is quadratic (not linear) because commitment near 1.0 represents high confidence, and
confidence compounds: a 0.9-committed holder has much lower risk than the 0.1 difference
from 1.0 would suggest linearly.

### Proactive repair flagging (`flag_for_proactive_repair`)

```
for (holder_id, score) in holders:
    tier = score.tier()
    if tier == AtRisk:
        flag holder_id
    else if tier == Low AND importance >= 0.7:
        flag holder_id
```

The 0.7 importance threshold means we only preemptively repair important files when
commitment is merely Low (not outright AtRisk). For unimportant files, we wait until the
holder is actually AtRisk before spending repair bandwidth.

---

## DB Operations

None. This module has no DB dependency. The caller assembles `HolderProfile` from:

- `SymbolPlacement.consecutive_misses` (for `consecutive_misses`)
- `SymbolPlacement.placed_at` — used to call `budget::eviction_priority(importance,
  holder_trust, placed_at, now)` to get `our_eviction_priority`
- `PeerRecord.trust_p` / recent PoS history from `TrustEngine` — for `recent_challenges`
  and `recent_passes`
- `PeerRecord.first_seen` — for `first_seen`
- Daemon-level tracking of recent offer rejections — for `offers_rejected_recently`
- `HoldingRecord.drop_notice_sent_at` (holder side) is not directly visible to the owner;
  the owner infers it from receipt of a `DropNotice` message, which the daemon records.

The daemon integration point (informational, not implemented here):

```rust
// In scheduler tick (pseudocode, syncback/ crate):
for block in active_source_blocks {
    let placements = db.load_placements(block.id);
    let max_prio = placements.iter()
        .map(|p| budget::eviction_priority(
            block.importance,
            trust_engine.score(&p.holder_id).combined,
            p.placed_at,
            now_secs,
        ))
        .fold(0.0f64, f64::max);

    let mut flagged = Vec::new();
    for placement in &placements {
        let holder = db.load_peer(&placement.holder_id);
        let (challenges, passes) = trust_engine.recent_pos_stats(&placement.holder_id, 4);
        let our_prio = budget::eviction_priority(
            block.importance,
            trust_engine.score(&placement.holder_id).combined,
            placement.placed_at,
            now_secs,
        );
        let profile = HolderProfile {
            holder_id: placement.holder_id,
            recent_challenges: challenges,
            recent_passes: passes,
            consecutive_misses: placement.consecutive_misses,
            offers_rejected_recently: tracker.rejected_recently(&placement.holder_id),
            drop_notice_sent_recently: tracker.drop_notice_from(&placement.holder_id),
            our_eviction_priority: our_prio,
            max_known_eviction_priority: max_prio,
            first_seen: holder.first_seen,
            now: Timestamp(now_secs),
        };
        let score = commitment::compute_commitment(&profile)?;
        flagged.push((placement.holder_id, score));
    }
    let repair_targets = commitment::flag_for_proactive_repair(&flagged, block.importance);
    // Send repair_targets to RepairAgent
}
```

---

## Test Scenarios

All tests go in `crates/syncback-core/src/commitment/tests.rs`.
Naming convention: `what_when_then`.

### 1. `pos_component_no_challenges_returns_neutral`

```
recent_challenges = 0
recent_passes = 0
→ pos_component = 0.5  // neutral, no data
```

### 2. `pos_component_perfect_pass_rate`

```
recent_challenges = 10, recent_passes = 10, consecutive_misses = 0
→ pass_rate = 1.0, miss_penalty = 0.0
→ pos_component = 1.0
```

### 3. `pos_component_zero_pass_rate`

```
recent_challenges = 10, recent_passes = 0, consecutive_misses = 0
→ pass_rate = 0.0
→ pos_component = 0.0
```

### 4. `pos_component_uncertain_miss_degrades_score`

```
recent_challenges = 10, recent_passes = 8, consecutive_misses = 1  // Uncertain
→ pass_rate = 0.8, miss_penalty = 0.15
→ pos_component = 0.65
```

### 5. `pos_component_presumed_lost_degrades_more`

```
recent_challenges = 10, recent_passes = 8, consecutive_misses = 3  // PresumedLost
→ miss_penalty = 0.35
→ pos_component = (0.8 - 0.35).max(0.0) = 0.45
```

### 6. `pos_component_miss_cannot_go_below_zero`

```
recent_challenges = 4, recent_passes = 0, consecutive_misses = 5
→ pass_rate = 0.0, miss_penalty = 0.35
→ pos_component = (0.0 - 0.35).max(0.0) = 0.0
```

### 7. `pressure_component_no_signals`

```
offers_rejected_recently = false
drop_notice_sent_recently = false
→ pressure_component = 1.0
```

### 8. `pressure_component_rejected_only`

```
offers_rejected_recently = true
drop_notice_sent_recently = false
→ pressure_component = 0.5
```

### 9. `pressure_component_drop_notice_only`

```
offers_rejected_recently = false
drop_notice_sent_recently = true
→ pressure_component = 0.6
```

### 10. `pressure_component_both_signals`

```
offers_rejected_recently = true
drop_notice_sent_recently = true
→ pressure_component = max(0.0, 1.0 - 0.5 - 0.4) = 0.1
```

### 11. `age_component_new_peer`

```
first_seen = now (0 weeks)
→ age_component = 0.0
```

### 12. `age_component_saturates_at_26_weeks`

```
first_seen = 26 * SECS_PER_WEEK ago
→ age_component = 1.0
```

### 13. `age_component_half_saturation`

```
first_seen = 13 * SECS_PER_WEEK ago
→ age_component = 13.0 / 26.0 = 0.5
```

### 14. `age_component_beyond_saturation_capped`

```
first_seen = 52 * SECS_PER_WEEK ago
→ age_component = min(52.0/26.0, 1.0) = 1.0
```

### 15. `priority_component_no_reference`

```
our_eviction_priority = 0.8, max_known_eviction_priority = 0.0
→ priority_component = 0.5  // neutral, no reference
```

### 16. `priority_component_highest_priority`

```
our_priority = 1.0, max_priority = 1.0
→ priority_component = 1.0
```

### 17. `priority_component_lowest_priority`

```
our_priority = 0.0, max_priority = 1.0
→ priority_component = 0.0
```

### 18. `priority_component_midpoint`

```
our_priority = 0.5, max_priority = 1.0
→ priority_component = 0.5
```

### 19. `priority_component_capped_at_one`

```
our_priority = 2.0, max_priority = 1.0
→ normalized = min(2.0/1.0, 1.0) = 1.0
→ priority_component = 1.0
```

### 20. `compute_commitment_reliable_holder`

Reliable holder: perfect PoS, no pressure, long relationship, high priority.

```
profile = HolderProfile {
    recent_challenges: 10, recent_passes: 10, consecutive_misses: 0,
    offers_rejected_recently: false, drop_notice_sent_recently: false,
    our_eviction_priority: 1.0, max_known_eviction_priority: 1.0,
    first_seen: Timestamp(now - 30 * SECS_PER_WEEK),
    now: Timestamp(now),
}
pos     = 1.0 * 0.50 = 0.50
pressure= 1.0 * 0.25 = 0.25
age     = min(30/26, 1.0) * 0.15 = 1.0 * 0.15 = 0.15
priority= 1.0 * 0.10 = 0.10
→ score = 1.0
→ tier  = High
→ Ok(CommitmentScore(1.0))
```

### 21. `compute_commitment_at_risk_holder`

Holder is rejecting offers, sent drop notice, new peer, zero pass rate.

```
profile = HolderProfile {
    recent_challenges: 5, recent_passes: 0, consecutive_misses: 3,
    offers_rejected_recently: true, drop_notice_sent_recently: true,
    our_eviction_priority: 0.05, max_known_eviction_priority: 1.0,
    first_seen: Timestamp(now - 1 * SECS_PER_WEEK),
    now: Timestamp(now),
}
pos      = (0.0 - 0.35).max(0.0) * 0.50 = 0.0
pressure = max(0.0, 1.0 - 0.5 - 0.4) * 0.25 = 0.1 * 0.25 = 0.025
age      = (1.0/26.0) * 0.15 ≈ 0.006
priority = (0.05/1.0) * 0.10 = 0.005
→ score ≈ 0.036
→ tier = AtRisk
→ Ok(CommitmentScore(≈0.036))
```

Assert: `result.unwrap().tier() == CommitmentTier::AtRisk`

### 22. `compute_commitment_medium_holder`

Good pass rate, mild pressure, moderate age.

```
profile = HolderProfile {
    recent_challenges: 8, recent_passes: 6, consecutive_misses: 1,
    offers_rejected_recently: true, drop_notice_sent_recently: false,
    our_eviction_priority: 0.6, max_known_eviction_priority: 1.0,
    first_seen: Timestamp(now - 12 * SECS_PER_WEEK),
    now: Timestamp(now),
}
pos      = (0.75 - 0.15).max(0.0) * 0.50 = 0.60 * 0.50 = 0.30
pressure = (1.0 - 0.5) * 0.25 = 0.5 * 0.25 = 0.125
age      = (12.0/26.0) * 0.15 ≈ 0.069
priority = (0.6/1.0) * 0.10 = 0.06
→ score ≈ 0.554
→ tier = Medium
```

### 23. `compute_commitment_error_on_inconsistent_counts`

```
profile with recent_passes = 5, recent_challenges = 3  (passes > challenges)
→ Err(CommitmentError::InconsistentPoSCounts { passes: 5, challenges: 3 })
```

### 24. `eviction_risk_zero_score`

```
eviction_risk(CommitmentScore(0.0)) == 1.0
```

### 25. `eviction_risk_full_score`

```
eviction_risk(CommitmentScore(1.0)) == 0.0
```

### 26. `eviction_risk_mid_score`

```
eviction_risk(CommitmentScore(0.5)) == 1.0 - 0.25 = 0.75
```

### 27. `eviction_risk_high_commitment`

```
eviction_risk(CommitmentScore(0.9)) ≈ 1.0 - 0.81 = 0.19
// Assert: (result - 0.19).abs() < 1e-9
```

### 28. `flag_for_proactive_repair_at_risk_always_flagged`

```
holders = [(A, CommitmentScore(0.10)), (B, CommitmentScore(0.80))]
importance = 0.3
→ flagged = [A]  // A is AtRisk regardless of importance
```

### 29. `flag_for_proactive_repair_low_important_file`

```
holders = [(A, CommitmentScore(0.30))]  // Low tier
importance = 0.8  // >= 0.7
→ flagged = [A]
```

### 30. `flag_for_proactive_repair_low_unimportant_file`

```
holders = [(A, CommitmentScore(0.30))]  // Low tier
importance = 0.5  // < 0.7
→ flagged = []   // Low tier + unimportant → wait for AtRisk
```

### 31. `flag_for_proactive_repair_empty_input`

```
holders = []
importance = 1.0
→ flagged = []
```

### 32. `commitment_score_tier_boundaries`

```
CommitmentScore(0.74).tier() == Low
CommitmentScore(0.75).tier() == High
CommitmentScore(0.44).tier() == Low
CommitmentScore(0.45).tier() == Medium
CommitmentScore(0.19).tier() == AtRisk
CommitmentScore(0.20).tier() == Low
```

---

## Integration with Existing Modules

### What the caller provides

The daemon scheduler (in `syncback/` crate) is the only caller. It assembles
`HolderProfile` fields from:

| `HolderProfile` field | Source |
|-----------------------|--------|
| `recent_challenges` | `TrustEngine::recent_pos_stats(peer_id, 4_weeks)` — caller adds this method to TrustEngine if absent, or reads raw `pos_weekly` map |
| `recent_passes` | Same |
| `consecutive_misses` | `SymbolPlacement::consecutive_misses` from DB |
| `offers_rejected_recently` | Daemon-side offer-rejection tracker (in-memory, `HashMap<IdentityPub, Timestamp>`) |
| `drop_notice_sent_recently` | Daemon tracks received `DropNotice` messages per peer |
| `our_eviction_priority` | `budget::eviction_priority(importance, trust_combined, placed_at, now)` |
| `max_known_eviction_priority` | Max over all placements for this block (or across all blocks for this holder) |
| `first_seen` | `PeerRecord::first_seen` |

DECISION NEEDED: Should `max_known_eviction_priority` be max *across all blocks for this
holder* (holder-global), or max *across all holders for this block* (block-local)? The
current spec uses block-local (compare our data's priority against other owners' data at
this holder) as it better captures relative eviction order. If the daemon only has access
to its own block data, this is straightforward. If block-local is too narrow, use
holder-global. Leave as block-local for now.

### TrustEngine extension (if needed)

`TrustEngine` already stores `pos_weekly: HashMap<(IdentityPub, u32), WeeklyPosRecord>`.
The daemon scheduler needs recent aggregate stats. Add to TrustEngine in `trust/mod.rs`:

```rust
/// Returns (total_challenged, total_passed) for the last `weeks` weeks.
/// If no data for the period, returns (0, 0).
pub fn recent_pos_stats(&self, peer: &IdentityPub, weeks: u32) -> (u32, u32);
```

DECISION NEEDED: The spec above adds `recent_pos_stats` to `TrustEngine`. This is a small
addition and belongs logically in TrustEngine. However, it could also be computed by the
caller. If the implementer judges it cleaner to compute it externally, they may do so,
but `HolderProfile.recent_challenges / recent_passes` must be populated correctly either
way.

---

## Module Structure

```
crates/syncback-core/src/commitment/
    mod.rs      — CommitmentScore, CommitmentTier, HolderProfile, CommitmentError,
                  compute_commitment, eviction_risk, flag_for_proactive_repair,
                  pos_component, pressure_component, age_component, priority_component
    tests.rs    — all 32 test scenarios above
```

Add to `crates/syncback-core/src/lib.rs`:

```rust
pub mod commitment;
```

---

## What NOT to do

- Do not query the DB inside this module. Pure function inputs only.
- Do not add network calls or async.
- Do not store state in `CommitmentScore` or any struct in this module — all computation
  is stateless and deterministic given inputs.
- Do not use ML or adaptive thresholds — formulas are fixed constants.
- Do not trigger repair directly — return flagged holders to the caller, RepairAgent acts.
- Do not add logging (`tracing`) inside `syncback-core`. Logging belongs in the daemon.
- The `commitment_telemetry` feature is informational: it must never *block* a backup or
  restore operation. It is advisory input to RepairAgent, not a gate.

---

## Files to Create/Modify

1. `/home/ilya/projects/syncback/crates/syncback-core/src/constants.rs`
   — Add commitment telemetry constants block (8 new constants)

2. `/home/ilya/projects/syncback/crates/syncback-core/src/commitment/mod.rs`
   — New file: all types and public functions

3. `/home/ilya/projects/syncback/crates/syncback-core/src/commitment/tests.rs`
   — New file: 32 test scenarios

4. `/home/ilya/projects/syncback/crates/syncback-core/src/lib.rs`
   — Add `pub mod commitment;`

5. `/home/ilya/projects/syncback/crates/syncback-core/src/trust/mod.rs`
   — Add `recent_pos_stats` method to `TrustEngine` (small addition, ~15 lines)
   — Add corresponding test in `trust/tests.rs`

---

## Definition of Done

- `cargo test -p syncback-core` passes with no failures
- `cargo clippy -p syncback-core -- -D warnings` clean
- All 32 test scenarios present and passing in `commitment/tests.rs`
- `TrustEngine::recent_pos_stats` implemented and tested
- All 8 new constants present in `constants.rs`
- `CommitmentScore`, `CommitmentTier`, `HolderProfile`, `CommitmentError` exported from
  `crates/syncback-core/src/commitment/mod.rs`
- No inline `#[cfg(test)]` — tests exclusively in `tests.rs`
