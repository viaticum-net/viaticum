# Experiment 07: Targeted Spite Attack

## Question
How many colluding nodes needed to deny restore to a specific target? What's the ROI?

## Model
- 500 honest peers + M attacker nodes (already have 6 months of honest reputation)
- Target has 1000 files stored as k-of-n shards across the network
- Attackers behave honestly but refuse to serve shards when target requests restore
- Wait phase: attackers maintain nodes for 1-5 years, accumulating shards via repair cycles
- At attack time: count attacker shards per file. File denied if (total - attacker_shards) < k
- Cost = M attackers × wait_years × 100GB per node

## Sweep Parameters
- n_attackers: [5, 10, 20, 50, 100]
- attacker_subnets: [1, 3, 5, 10]
- wait_years: [1, 2, 5]
- erasure profiles: 5-of-15, 7-of-10
- 120 configs, 30 seeds each, 24 cores, 42 minutes

## Key Results

### 5-of-15 (documents profile) — completely immune

**0.00% denial in ALL 60 configurations.** Even 100 attackers across 10 subnets maintaining nodes for 5 years cannot deny a single file restore. The tolerance of 10 shard losses makes targeted spite completely futile.

### 7-of-10 (media profile) — marginally vulnerable

| Attackers | Subnets | Wait | P(denied) | Cost (GB-yr) |
|-----------|---------|------|-----------|-------------|
| 5 | any | 1yr | 0.14% | 500 |
| 5 | any | 5yr | 0.82% | 2,500 |
| 20 | any | 5yr | 0.81% | 10,000 |
| 50 | 10 | 5yr | 1.50% | 25,000 |
| 100 | 1 | 1yr | 3.00% | 10,000 |
| 100 | 10 | 1yr | 6.30% | 10,000 |
| 100 | 10 | 5yr | **7.35%** | 50,000 |

Worst case: 100 attackers, 10 subnets, 5 years → 7.35% of files denied. Attackers accumulate ~1.65 shards per file on average (out of 10).

### Attacker shards per file

| Attackers | Wait 1yr | Wait 5yr |
|-----------|---------|---------|
| 5 | ~0.10 | ~0.30 |
| 20 | ~0.40 | ~0.65 |
| 50 | ~0.55 | ~0.90 |
| 100 | ~1.37-1.63 | ~1.62-1.65 |

Even 100 attackers capture only ~1.6 shards per file after 5 years. Well below the tolerance of 3 (7-of-10) or 10 (5-of-15).

## Key Findings

1. **5-of-15 makes spite attacks impossible.** Zero damage in every configuration. The tolerance of 10 shard losses is insurmountable for any realistic attacker.

2. **Subnet diversity barely matters for spite (unlike Sybil).** Going from 1 to 10 subnets changes 7-of-10 denial from 3.0% to 6.3% (at 100 attackers, 1yr). Compare with Sybil where subnets are the key lever. This is because spite attackers are already established — they get shards through normal trust-weighted selection, not subnet manipulation.

3. **Diminishing returns on wait time.** 100 attackers: 1yr → 6.3%, 2yr → 6.9%, 5yr → 7.35%. Each additional year adds less than 1% denial. The network's repair cycle distributes new shards randomly, diluting the attacker's concentration.

4. **Cost is enormous for marginal damage.** The "best ROI" attack: 100 attackers × 1 year × 100GB = 10,000 GB-years for 6.3% file denial. That's maintaining 100 real nodes with real storage for a year to maybe deny 63 out of 1000 files of ONE specific user.

5. **The attack is economically irrational.** Even for 7-of-10 with the worst-case scenario: 50,000 GB-years (= 5TB of real storage for 5 years) to deny 7.35% of one person's files. The attacker would spend more on electricity than the target's data is worth.

## Why This Attack Fails

Three factors combine:
- **Shard distribution is probabilistic.** Attacker can't choose which files their shards go to. With 500 peers and 100 attackers, each file gets ~2 attacker shards on average (100/500 × 10) — but needs 4+ to succeed.
- **Erasure coding tolerance.** 5-of-15: need 11 attacker shards per file (impossible). 7-of-10: need 4 (rare at 2 average).
- **Repair dilutes concentration.** Each repair cycle replaces some attacker shards with honest ones and vice versa, keeping the ratio near the population ratio.

## Design Implications

- **No special defense needed against spite.** Standard erasure coding (5-of-15) is sufficient.
- **This validates the RESEARCH.md spite analysis.** Years of honest investment for negligible ROI.
- **For paranoid users:** recommend 5-of-15 or wider coding. 7-of-10 has marginal vulnerability at extreme attacker sizes.
- **The real spite defense is the time cost.** The attacker must maintain nodes for months/years *hoping* the target's disk fails. Most will give up.

## Code
`simulations/spite_attack.py` — run with `--sweep --jobs 24`
