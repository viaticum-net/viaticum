# Experiment 04: Sybil Attack Against P2P Backup

## Question
Can a Sybil attacker cause file loss by building reputation honestly then refusing to serve shards on restore?

## Model
- N honest peers (500) + M sybil nodes controlled by attacker
- Sybils distributed across limited /24 subnets; subnet rate-limit: 1 shard per /24 per file
- **Phase 1 (buildup):** sybils behave honestly for months, accumulating PID trust. Weekly repair cycles replace degraded shards; high-trust sybils get selected as replacements.
- **Phase 2 (attack):** target's disk fails, requests restore. Sybil nodes refuse to return shards.
- File survives if `(total_shards - sybil_shards) >= k`
- Attack cost = n_sybils × months × 100GB per sybil

## Sweep Parameters
- n_sybils: [10, 50, 100, 200, 500]
- sybil_subnets: [1, 3, 5, 10]
- reputation_months: [3, 6, 12]
- erasure profiles: 5-of-15 (documents) and 6-of-10 (media)
- 30 seeds per config, 120 total configs, 24 cores, 22.8 minutes

## Key Results

### 5-of-15 erasure coding (documents profile) — practically immune

| Sybils | Subnets | Months | P(loss) | Cost (GB-mo) |
|--------|---------|--------|---------|-------------|
| 10-100 | any | any | **0.00%** | 3K–120K |
| 200 | 1-5 | 3-6 | **0.00%** | 60K–120K |
| 200 | 10 | 12 | 0.04% | 240K |
| 500 | 1 | 12 | 0.10% | 600K |
| 500 | 5 | 12 | 1.39% | 600K |
| 500 | 10 | 12 | **3.15%** | 600K |

With 5-of-15 coding, the attacker tolerates n-k=10 sybil shards per file. Even 500 sybils across 10 subnets building reputation for a year achieve only 3.15% file loss. The subnet rate-limit (max 1 shard per /24 per file) is the primary defense — it caps sybil infiltration at min(sybil_subnets, n-k) shards per file.

### 6-of-10 erasure coding (media profile) — vulnerable at scale

| Sybils | Subnets | Months | P(loss) | Cost (GB-mo) |
|--------|---------|--------|---------|-------------|
| 10 | any | any | **0.00%** | 3K–12K |
| 50 | 10 | any | ~0.08% | 15K–60K |
| 100 | 5 | 12 | 1.28% | 120K |
| 200 | 3 | 12 | 8.16% | 240K |
| 200 | 10 | 12 | **11.76%** | 240K |
| 500 | 1 | 12 | 24.33% | 600K |
| 500 | 5 | 12 | **52.22%** | 600K |
| 500 | 10 | 12 | **58.93%** | 600K |

With 6-of-10 coding, tolerance is only n-k=4 sybil shards. 500 sybils across 10 subnets can capture 4.86 shards/file on average — enough to destroy majority of files.

### Most cost-efficient attacks

| Sybils | Subnets | Months | Profile | P(loss) | Cost | Efficiency |
|--------|---------|--------|---------|---------|------|-----------|
| 500 | 10 | 3 | 6-of-10 | 50.80% | 150K | 3.39e-6 |
| 500 | 5 | 3 | 6-of-10 | 32.69% | 150K | 2.18e-6 |
| 200 | 10 | 3 | 6-of-10 | 8.47% | 60K | 1.41e-6 |

Short buildup (3 months) with many sybils across many subnets is the most efficient strategy. Longer buildup increases damage but the marginal gain per GB-month decreases.

## Key Findings

1. **Subnet rate-limiting is the primary defense.** It caps sybil shards per file at min(sybil_subnets, n-k). With 5-of-15 coding and 3 subnets, even 500 sybils can only capture ~3 of 10 tolerable shard slots.

2. **Erasure code ratio is critical.** 5-of-15 (tolerance=10) is practically immune even to massive attacks. 6-of-10 (tolerance=4) is vulnerable. The "redundancy tax" of wider coding pays for itself in Sybil resistance.

3. **Attack cost is enormous.** Even the cheapest effective attack (200 sybils, 10 subnets, 3 months against 6-of-10) costs 60,000 GB-months = 200 sybils each storing 100GB for 3 months. That's ~20TB of real storage committed honestly.

4. **Sybil trust converges above honest peers.** Sybils have reliability=1.0 (always pass checks) vs honest peers at 0.95, so sybils end up with slightly higher trust. This is realistic but doesn't help much due to subnet rate-limiting.

5. **Subnet diversity is the attacker's key lever.** Going from 1 subnet to 10 subnets at 500 sybils increases damage from 0.10% to 3.15% (5-of-15) or from 24.33% to 58.93% (6-of-10). This validates the /24 subnet diversity requirement.

## Design Implications

- **Default erasure profile should be 5-of-15 or wider.** The 2x overhead is justified by near-immunity to Sybil attacks.
- **Subnet rate-limiting is non-negotiable.** Even 1 shard per /24 per file is effective, but should also consider ASN diversity.
- **For high-value data, recommend wider coding.** Users with sensitive data should use 5-of-20 or similar.
- **The economic argument works.** Attacking a network of 500 peers costs 60K–600K GB-months — orders of magnitude more than the data being protected. It's cheaper to just buy cloud storage.

## Code
`simulations/sybil_attack.py` — run with `--sweep --jobs 24`
