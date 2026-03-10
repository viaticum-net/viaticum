# Plan: Experiments 04-14

## Experiment 04: Sybil Attack ✅
**Question:** How many fake nodes needed to compromise a target's files with PID reputation + rate limiting?
**Result:** 5-of-15 coding practically immune (3.15% loss at 500 sybils/10 subnets/12 months). 6-of-10 vulnerable (58.9% at same). Subnet rate-limiting is the primary defense. See experiment-04-sybil-attack.md.

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

## Experiment 13: Behavior Models / Archetypes ✅
**Question:** Does PI reputation correctly rank diverse behavioral archetypes?
**Result:** Kendall's tau = 0.0 (near-random) — PI does NOT correctly rank archetypes by actual usefulness. Hoarder (90% uptime, 20% storage) ranked #2 despite being #5 useful — PI measures uptime, not storage contribution. Weekend Warrior under-ranked (#5 vs actual #2). Seasonal recovery works well (year 2 summer drop 41% smaller than year 1). Design implication: need storage-balance term in trust formula. See experiment-13-behavior-models.md.

## Experiment 14: Individual Node Perspective ✅
**Question:** What does the system look like from one node's point of view?
**Result:** Three scenarios. (1) Flaky partners: 15/15 shards maintained, 100% restore, ~0.8 repairs/month, D-warnings 91% false positive rate. (2) Vacation 14d: trust drops 15.1%, recovers to 95.1% in 30 days, data 100% safe. (3) Disk pressure: automatic eviction of low-trust partners (30→13 over 18mo), own data untouched, trust stable. UX: system is invisible in normal operation. See experiment-14-node-perspective.md.
