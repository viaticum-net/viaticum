# Plan: Experiments 04-19

## Experiment 04: Sybil Attack ✅
**Question:** How many fake nodes needed to compromise a target's files with PID reputation + rate limiting?
**Result:** 5-of-15 coding practically immune (3.15% loss at 500 sybils/10 subnets/12 months). 6-of-10 vulnerable (58.9% at same). Subnet rate-limiting is the primary defence. See experiment-04-sybil-attack.md.

## Experiment 05: Free-rider Detection ✅
**Question:** Does PI reputation automatically prevent free-riding?
**Result:** 0-10% reliability free-riders excluded in 1-2 months. 25% gaming works at threshold=0.3, blocked at 0.5+. 50% reliability undetectable. Honest peers always 100% unaffected. See experiment-05-free-rider.md.

## Experiment 06: Mass Departure (Shock Event) ✅
**Question:** What happens when 30-50% of network leaves simultaneously?
**Result:** 5-of-15 survives 30% instant shock perfectly, 50% → 94.4%. 7-of-10 loses 35% at 30% shock. Death scream provides zero benefit. Gradual departure dramatically better. See experiment-06-mass-departure.md.

## Experiment 07: Targeted Spite ("Обиженка") ✅
**Question:** How many colluding nodes needed to deny restore to a specific target?
**Result:** 5-of-15 completely immune (0% in all 60 configs). 7-of-10: max 7.35% denial at 100 attackers/10 subnets/5 years. Cost: 50,000 GB-years. Economically irrational. See experiment-07-spite-attack.md.

## Experiment 08: Storage Lie + Proof-of-Storage ✅
**Question:** How quickly does proof-of-storage detect liars, and does repair outpace the lie?
**Result:** 100% file survival in ALL 72 configurations. Storage lying is completely harmless with 5-of-15 erasure. Detection in 3-30 days depending on check interval. D-trigger provides 0% advantage (system too resilient). See experiment-08-storage-lie.md.

## Experiment 09: Automatic Federation ⚠️
**Question:** Does "nobody trusts us, let's be friends" naturally produce geographic diversity?
**Result:** Initial model too simple — threshold had zero effect across all configs. Replaced by Experiment 10 (cluster formation with acceptance gate).

## Experiment 10: Cluster Formation (Living Network) ✅
**Question:** Do trust-based partnerships naturally form stable communities in a growing/churning network?
**Result:** Q≈0.42 at steady state (10 years), peaks at 0.64 during growth. 11-12 communities of 700-900 nodes. 66% cross-cohort edges, 73% bridge nodes. Acceptance gate drives initial clustering, churn creates healthy integration. See experiment-10-cluster-formation.md.

## Experiment 11: User Lifecycle ✅
**Question:** How does a single user experience the system from day 0 to year N?
**Result:** In warm-started network, bootstrap is instant (trust gate crossed month 0). 100% restore in ALL phases including departure and return. Trust drops to 77.8% after 6-month absence, recovers to 90.5% within 6 months back. Disk pressure handled gracefully via automatic eviction of low-trust partners. See experiment-11-user-lifecycle.md.

## Experiment 12: "Prison" Scenario (Captive Network) ✅
**Question:** What's the minimum viable network size? How does a bad apple affect a small network?
**Result:** Minimum viable size: N≥3 at 0% churn, N≥7 at 10%, N≥10 at 25%. Adaptive erasure coding (k-of-(n-1) for small networks) is critical. Bad apples have zero impact at N≥10; at N=5, freerider causes only -6.7% survival. N≥20 always 100% with full 5-of-15. See experiment-12-prison-network.md.

## Experiment 13: Behaviour Models / Archetypes ✅
**Question:** Does PI reputation correctly rank diverse behavioural archetypes?
**Result:** Kendall's tau = 0.0 (near-random) — PI does NOT correctly rank archetypes by actual usefulness. Hoarder (90% uptime, 20% storage) ranked #2 despite being #5 useful — PI measures uptime, not storage contribution. Weekend Warrior under-ranked (#5 vs actual #2). Seasonal recovery works well (year 2 summer drop 41% smaller than year 1). Design implication: need storage-balance term in trust formula. See experiment-13-behavior-models.md.

## Experiment 14: Individual Node Perspective ✅
**Question:** What does the system look like from one node's point of view?
**Result:** Three scenarios. (1) Flaky partners: 15/15 shards maintained, 100% restore, ~0.8 repairs/month, D-warnings 91% false positive rate. (2) Vacation 14d: trust drops 15.1%, recovers to 95.1% in 30 days, data 100% safe. (3) Disk pressure: automatic eviction of low-trust partners (30→13 over 18mo), own data untouched, trust stable. UX: system is invisible in normal operation. See experiment-14-node-perspective.md.

---

# Series 2: Revised PI+S Model

The trust formula was updated based on the findings from Series 1:
```
trust = kp × P_weekly + ki × I + ks × S

P_weekly = rolling 4-week window (binary: did the peer pass ≥1 check that week?)
I        = cumulative average of all weekly scores (no decay)
S        = GB_stored_for_others / GB_stored_by_others, clamp [0, 2]

Best parameters (Exp 15): kp=0.3, ki=1.5, ks=0.3
```

## Experiment 15: PI+S Convergence ✅
**Question:** Does the extended PI+S formula converge to correct archetype ranking?
**Result:** Kendall's tau = 0.97 (vs 0.0 for PI-only) by month 12. All 6 archetypes ranked correctly. Hoarder dropped from #2 to #5, Weekend Warrior rose from #5 to #2. The system is robust: any ks > 0 gives tau ≥ 0.83. Best configuration: kp=0.3, ki=1.5, ks=0.3. **Note:** global S was used. See experiment-15-pis-convergence.md.

## Experiment 16: PI+S Under Threats ✅
**Question:** Does the S-term break the existing defences against Sybil, free-rider, and spite attacks?
**Result:** The S-term does NOT break existing defences. Sybil: fake S reduces denial by 0.04-1.98pp (subnet-limit remains the primary defence). Free-rider: 100% survival across all 54 configurations (5-of-15 is immune). Spite: 0% denial (subnet diversity protects). S is useful for ranking (Exp 15, 22), not for security. Note: global additive S was used. See experiment-16-pis-threats.md.

## Experiment 17: Long-term Mixed Network ✅
**Question:** Is a network of 6 archetypes with PI+S (pairwise S) stable over 10 years?
**Result:** tau=0.667 (worse than Exp 15 due to Hoarder/Nomad inversion). Hoarder (rank 4, expected 5) > Nomad (rank 6, expected 4) — 90% uptime outweighs the S-penalty in the additive formula. Clusters are mixed (not by archetype): 17 communities, Q=0.290, 59.5% cross-cluster edges, 0 pure hoarder clusters. Trust from honest-only = same rank (tau_honest=0.733). Conclusion: the problem is the formula (additive S), not the clustering. See experiment-17-longterm-mixed.md.

## Experiment 18: Corrected UX (Node Perspective with PI+S)
**Question:** Does UX improve with PI+S + weekly checks + D-hysteresis?
- Scenario 1: flaky partners — D-warning false positive rate (was 91%)
- Scenario 2: vacation — trust drop with weekly P (should be lower)
- Scenario 3: disk pressure — S drops on eviction; is this visible in trust?

## Experiment 19: Trust Referral (Verifiable Evidence Sharing)
**Question:** Does exchanging signed proof-of-storage logs speed up bootstrap?
- A newcomer receives signed challenge-response logs from a friend, covering N peers
- The newcomer verifies the signatures and computes trust from third-party observations (with a discount)
- Question 1: how much does bootstrap speed up (time to first restore)?
- Question 2: what discount (0.3x? 0.5x? 0.7x?) is needed to avoid opening a Sybil vector?
- Question 3: can A hide negative entries? How does B detect this?
- Relation to Personal Cluster: inside a cluster, full sharing applies (discount=1.0)

## Experiment 20: Gossip Relay & Message Loss
**Question:** How do delivery delay and message loss in a gossip relay affect trust accuracy?
- Dedicated relay is replaced by gossip: each node stores "mail" for its neighbours (~2-4 MB) and forwards it on contact
- Parameters:
  - PoS check frequency: 1/day, 3/week, 2/week, 1/week
  - Message loss rate: 0%, 5%, 10%, 20%
  - Gossip hop limit: 3, 5, 7
  - Network connectivity: mean uptime 4h/day, 8h/day, 16h/day
- Metrics:
  - Trust accuracy (Kendall's tau vs ground truth)
  - False negative rate (honest peer penalised due to message loss)
  - Delivery latency distribution (hops, days)
  - Liar detection time (vs immediate delivery)
  - Total bandwidth and storage overhead on the network
- Key insight: daily checks + weekly aggregation (≥1 OK → 1) make the system resilient to loss (p_loss=10% → P(miss week) = 0.1^7 ≈ 0). But 1 check/week at 10% loss → 10% false penalties.
- Connection: if gossip works, a dedicated relay is unnecessary, removing a centralisation point

---

# Series 3: Adaptive Redundancy

A paradigm shift: from "filter out the bad" to "use everyone, manage the risk".
Low trust ≠ useless. Low trust = unreliable; compensate with redundancy (more shards).
Key question: which filtering mechanisms (gate, eviction, escrow) are still needed, and which are replaced by adaptive n?

## Experiment 21: Adaptive Shard Count (trust → n) ✅
**Question:** Does adaptive n (shard count based on partner trust) achieve target reliability without an acceptance gate?
**Result:** Gate is HARMFUL: survival is higher without it (99.0% vs 97.9%). Adaptive n saves ~13% overhead (2.55x vs 2.92x) at the cost of -2pp survival. ~40% of shards are lost to churn regardless of strategy. Bootstrap ~1 week in all scenarios. See experiment-21-adaptive-n.md.

## Experiment 22: Multiplicative vs Additive S ✅
**Question:** Which S formula gives better tau in a living network?
**Result:** Multiplicative S wins outright. tau=1.000 in ALL 4 configurations (parameters have no effect). Additive: max tau=0.933 (only at ks=2.0). Hybrid: max tau=0.960 (unnecessary complexity). Hoarder/Nomad inversion fixed: Nomad(0.904) > Hoarder(0.809). Final formula: trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0). See experiment-22-s-formula.md.

## Experiment 23: Eviction Strategies ✅
**Question:** Is eviction needed, and if so, which kind?
**Result:** Eviction is NOT needed. Multiplicative S alone gives tau≈1.0 without eviction (Strategy A). Hard eviction is HARMFUL: it creates ghettos (97% same-archetype at threshold=1.5), inflates Hoarder/Freeloader trust, and drops tau to 0.43. Soft eviction is a no-op (disk pressure never triggers). Conclusion: do NOT implement eviction. See experiment-23-eviction.md.

## Experiment 24: Escrow as Credit System ✅
**Question:** Escrow as a credit mechanism — bootstrap speed and free-rider resistance with adaptive n?
**Result:** Escrow blocks 100% of hit-and-run attacks (100%→0%). Adaptive n saves 29% overhead (3.00x→2.13x). Bootstrap: Tier1=4 weeks, Tier2=13 weeks, Tier3=26 weeks. Best combination: escrow + adaptive n (Config D). File survival 100% in all configurations. See experiment-24-escrow.md.

## Experiment 25: Full Model Integration ✅
**Question:** Does the full model (adaptive n + best S formula + best eviction + escrow) work?
**Result:** FULL model tau=1.000 in 4/5 scenarios, but survival is lower than S2 (96.1% vs 97.6%). Cause: uniform shard placement — unreliable partners receive shards on equal footing with reliable ones; adaptive n compensates with quantity but overhead grows (3.16x vs 2.93x). Escrow blocks 100% hit-and-run in both models. Scenario D (40% free-rider flood) is problematic: survival=91.7%, tau=0.600. See experiment-25-integration.md.

## Experiment 26: Weighted Shard Placement ✅
**Question:** Does weighted shard placement (core + insurance) solve the survival problem from Exp 25?
**Result:** YES. Baseline: WEIGHTED survival=98.06% > S2 97.69% at tau=1.000. Honest survival in free-rider flood: WEIGHTED 99.40% > S2 97.60%. Overhead 3.62x (higher than S2 2.93x — optimisable with Poisson binomial). Shard concentration (Gini=0.12, max 6/partner) protects honest nodes. See experiment-26-weighted-placement.md.
