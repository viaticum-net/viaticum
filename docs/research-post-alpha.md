# Post-Alpha Research — Ideas & Analysis

Collected 2026-03-12. Not prioritized for alpha. Revisit after real usage data.

---

## 1. Bandwidth throttling

**Observation:** peer could throttle bandwidth (upload/download speed).

**Analysis:** for cold backup (time constant = 1 week) this is not a real threat:
- PoS timeout (7 days) naturally catches extreme cases → trust decay
- Placement by trust → slow nodes get fewer shards
- Erasure coding → restore doesn't depend on a single node
- No rational incentive to throttle — only irrational "spite" behavior

**Verdict:** not a feature. Natural protocol defenses sufficient. Revisit only if real usage shows a problem.

---

## 2. Commitment spectrum (holder response)

**Idea:** instead of binary accept/reject, holder responds with commitment level ∈ [0.0, 1.0]:
- 1.0 = "will store reliably, as my own"
- 0.5 = "will take, but will drop under pressure"
- 0.0 = reject

**Value:** trust becomes promise-vs-delivery. High commitment + drop = big penalty. Low commitment + drop = expected, small penalty.

**Problem:** incentive to lie. Rational holder always says 0.3 to minimize penalty risk. Need incentive structure where honesty = dominant strategy. Possible: owner prefers high commitment in placement → more shards → faster trust growth → but higher risk.

**Related insights:**
- Current formula doesn't distinguish commitment levels — PoS is binary (pass/fail)
- `shard_reject` currently has zero effect on trust — could be a negative reliability signal
- This is a signaling game — needs game theory analysis (see #4)

**Verdict:** promising but non-trivial. Requires dedicated research + modeling round. Deferred.

---

## 3. Explicit negotiations between nodes

**Idea:** should nodes negotiate terms (capacity, timing, quid pro quo) instead of take-it-or-leave-it offers?

**Analysis:** current protocol already has "silent negotiations":
- S (pairwise GB ratio) — if you don't store my shards, S drops, I store fewer of yours
- `shard_reject` — holder can refuse, owner redistributes
- Trust-weighted placement — implicit reputation market

Explicit negotiations add protocol complexity (states, timeouts, corner cases) without clear benefit. The key question: what information do negotiations provide that can't be observed from behavior (PoS, accept/reject, S ratio)?

**Answer:** none identified. Silent negotiation through trust + S is sufficient.

**Verdict:** not needed. Documented here so the question doesn't recur.

---

## 4. Formal methods — game theory, combinatorics

**Meta-idea:** apply formal math to the protocol model.

**Where it adds value:**
- **Game theory:** commitment spectrum (#2) is a signaling game. Can formally prove Nash equilibrium existence, find optimal incentive structure. Also: prove current trust formula is incentive-compatible, prove freeloading is long-term unprofitable.
- **Combinatorics:** optimal placement (k-of-n, max 6/partner, trust-weighted) as combinatorial optimization. Closed-form formulas for restore probability vs network size/churn.
- **Worst-case guarantees:** simulations show average case, formal proofs cover all cases.

**What already exists:** 27 simulation experiments, calibrated trust formula, tested placement/eviction/budget.

**Planned order:**
1. Alpha works, collect real usage data
2. Formalize current model (trust, placement, eviction)
3. Game-theoretic analysis for new mechanics (commitment spectrum, negotiations)

**Verdict:** research track for post-alpha. Game theory required if #2 goes forward.
