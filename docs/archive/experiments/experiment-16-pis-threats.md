# Experiment 16: PI+S Under Threats

## Question

Does the S term break existing defences against Sybil attacks, free-riders, and spite? Does adding storage_ratio to the trust formula make the system less secure compared to the PI-only baseline?

## Model

The same PI+S formula from Experiment 15, but with **global S** (not pairwise):

```
trust = 0.5×P_weekly + 2.0×I + ks×S
```

| Component | Definition |
|-----------|------------|
| P_weekly | Rolling 4-week window of binary weekly checks |
| I | Cumulative mean — accumulated history without decay |
| S | storage_ratio = gb_stored_for_others / max(gb_stored_by_others, 0.01), clamped [0, 2] |

Each scenario is run twice: with **ks=1.0** (PI+S) and **ks=0.0** (PI-only baseline) — for a direct comparison of the S term's effect.

Three threat scenarios:

- **A: Sybil attack** — many fake peers with varying subnet counts and volumes of fake storage
- **B: Free-rider** — peers that consume resources without contributing (S_fr << 1)
- **C: Spite attack** — real peers that accumulate trust and then delete shards

## Configuration

```
seeds             = 30
erasure_coding    = 5-of-15
comparison        = ks=1.0 (PI+S) vs ks=0.0 (PI-only baseline)

Scenario A (Sybil):
  subnet_limit    = 1 shard per /24 per file
  sybil_count     = 50 / 100 / 200 / 500
  subnets         = 1 / 5 / 10
  S_ratio         = 1.0 (real storage) / 0.1 (fake storage)
  configs         = 24

Scenario B (Free-rider):
  duration        = 12 months
  fr_pct          = 10% / 25% / 40%
  fr_reliability  = 25% / 50% / 80%
  S_fr            = 0.1 / 0.3 / 0.5
  threshold       = 0.3 / 0.5
  configs         = 54

Scenario C (Spite):
  attacker_storage = 1.0 (real storage)
  attacker_count  = 20 / 50 / 100
  wait_years      = 1 / 3 / 5
  configs         = 9
```

## Results

### Scenario A: Sybil attack

Sybil attack with **fake storage** (S_ratio=0.1) — the best case for differentiation through the S term:

| Sybils | Subnets | Denial PI+S | Denial PI | Delta |
|--------|---------|-------------|-----------|-------|
| 500 | 10 | 1.09% | 3.07% | **−1.98pp** |
| 500 | 5 | 0.33% | 1.07% | −0.73pp |
| 200 | 10 | 0.18% | 0.60% | −0.42pp |
| 100 | 10 | 0.04% | 0.19% | −0.15pp |
| 50 | any | ≈0% | ≈0% | ≈0 |

Sybil attack with **real storage** (S_ratio=1.0): delta ≈ 0 across all configurations — S cannot distinguish an honest node from a Sybil that genuinely stores data.

Subnet rate-limiting remains the primary defence. The S term provides an additional denial reduction of up to 2pp under the most extreme attack conditions.

### Scenario B: Free-rider

| Configuration | File survival (PI+S) | File survival (PI) | Delta |
|---|---|---|---|
| All 54 configs | **100%** | **100%** | 0 |

The S term has no effect on file survival — it is already 100% under any free-riding parameters, owing to 5-of-15 erasure coding.

Share of free-riders above the trust threshold (FR_above_thr):

| Reliability | S_fr | Threshold | FR_above_thr |
|------------|------|-----------|--------------|
| 25% | 0.1 | 0.5 | **89.5%** |
| 25% | 0.1 | 0.3 | 99.7% |
| 25% | 0.3+ | any | ≥99.7% |
| 50%+ | any | any | 100% |

Even at the minimum S_fr=0.1 with the strict threshold=0.5, only 10.5% of free-riders fall below the threshold. This does not affect file survival, however: 5-of-15 provides sufficient redundancy.

### Scenario C: Spite attack

| Attackers | Wait (years) | Denial PI+S | Denial PI | AtkTrust | AtkShards/target |
|-----------|-------------|-------------|-----------|----------|-----------------|
| 20 | 1 | 0% | 0% | 3.38 | 0.56 |
| 20 | 3 | 0% | 0% | 3.38 | 0.56 |
| 20 | 5 | 0% | 0% | 3.38 | 0.57 |
| 50 | 1 | 0% | 0% | 3.38 | 1.39 |
| 50 | 3 | 0% | 0% | 3.38 | 1.39 |
| 50 | 5 | 0% | 0% | 3.38 | 1.40 |
| 100 | 1 | 0% | 0% | 3.38 | 2.46 |
| 100 | 3 | 0% | 0% | 3.38 | 2.47 |
| 100 | 5 | 0% | 0% | 3.38 | 2.48 |

0% denial in all 9 configurations. Attackers have S=1.0 (real nodes) — the S term cannot identify them. Subnet diversity prevents the spite attack independently of the trust formula: even 100 attackers acquire fewer than 5 shards out of 15 for a target file.

## Key findings

1. **The S term does not break existing defences.** The main result of the experiment: in none of the three scenarios did adding the S term make the system less secure. No regression.

2. **S gives a minor improvement against Sybil with fake storage.** A denial reduction of up to 1.98pp at 500 sybils/10 subnets is statistically visible but practically small. Subnet rate-limiting remains the primary defence.

3. **Free-rider protection is determined by erasure coding, not the formula.** 5-of-15 already delivers 100% survival — the S term neither adds nor removes anything.

4. **Spite protection is determined by subnet diversity, not the formula.** Attackers with real storage are indistinguishable by S, and the subnet limit prevents concentrating enough shards to delete a file.

5. **An important caveat.** The experiment used global additive S. Pairwise multiplicative S (adopted in Exp 22) behaves differently for free-riders, but the key conclusion — S does not regress the defences — remains valid.

## Design implications

- **The S term is safe to add to the formula** — none of the three threat scenarios tested showed any degradation.
- **Do not rely on S for Sybil defence.** Subnet rate-limiting is the primary mechanism; S provides only a minor bonus against fake storage.
- **Free-rider protection comes from erasure coding (5-of-15), not the trust formula.** Changing the erasure coding parameters requires revisiting this conclusion.
- **Spite protection comes from subnet diversity, not the trust formula.** As long as subnet_limit=1 is active, a spite attack is impossible regardless of the formula.
- **The value of the S term is in RANKING (Exp 15, 22), not in security (this experiment).** This distinction matters when making design decisions: S is justified as a ranking mechanism, not as a security feature.

## Code

`simulations/pis_threats.py` — results in `results/pis_threats/scenario_a_sybil.json`, `scenario_b_freerider.json`, `scenario_c_spite.json`
