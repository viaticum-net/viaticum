# Experiment 10: Emergent Cluster Formation in Living Network

## Question
Do trust-based partnerships naturally form stable communities in a growing, churning network over 10 years?

## Model
- **Living network:** starts at 50 nodes, grows +100/mo (year 1), +1000/mo (after), caps at 10,000 active
- **Churn:** 25% annual departure rate, departed IDs recycled
- **Acceptance gate:** established nodes (I_score > 0.3) reject partnership requests from newcomers (I_score < 0.3). Newcomers forced to partner with other newcomers.
- **Reciprocity:** 2x weight for mutual partners in selection
- **Erasure:** 15 shards per node, max 50 partners
- **Community detection:** Leiden algorithm (igraph + leidenalg)
- **Duration:** 10 years (120 months), 3 seeds, 24 cores, 25.9 minutes

## Key Results

### Phase 1: Growth (months 0-18)
| Month | Active | Modularity Q | Communities | Cross-cohort | Bridge% |
|-------|--------|-------------|------------|-------------|---------|
| 6 | 555 | **0.412** | 4 | 0% | 26% |
| 12 | 1,038 | **0.445** | 5 | 0% | 34% |
| 18 | 6,429 | **0.640** | 8 | 27% | 16% |

During rapid growth, newcomers form tight clusters (high Q). Cross-cohort edges are initially 0% — first-year nodes only know each other.

### Phase 2: Maturation (months 18-36)
| Month | Active | Modularity Q | Communities | Cross-cohort | Bridge% |
|-------|--------|-------------|------------|-------------|---------|
| 24 | 9,760 | **0.627** | 11 | 22% | 23% |
| 30 | 9,757 | **0.562** | 12 | 32% | 42% |
| 36 | 9,771 | **0.513** | 13 | 39% | 58% |

Network reaches capacity. Churn starts replacing nodes — new arrivals mix with existing communities. Modularity declines as cohorts intermingle. Bridge nodes rise rapidly.

### Phase 3: Steady State (months 36-120)
| Month | Active | Modularity Q | Communities | Cross-cohort | Bridge% |
|-------|--------|-------------|------------|-------------|---------|
| 48 | 9,771 | **0.449** | 14 | 52% | 71% |
| 72 | 9,746 | **0.399** | 14 | 64% | 75% |
| 96 | 9,758 | **0.407** | 11 | 66% | 74% |
| 120 | 9,735 | **0.419** | 12 | 66% | 73% |

Modularity stabilizes at Q≈0.42. Community structure persists despite continuous turnover. Two-thirds of edges cross cohort boundaries. Three-quarters of nodes are bridges.

## Key Findings

1. **Communities form and persist.** Q≈0.42 at steady state — significant community structure (Q>0.3 is generally considered meaningful). Not as strong as static model (Q=0.75) but that's expected with 25% annual churn mixing cohorts.

2. **Acceptance gate drives initial clustering.** Peak Q=0.64 during rapid growth (month 18) when newcomers are forced to partner with each other. This validates the "nobody trusts us, let's be friends" hypothesis.

3. **Churn creates healthy integration.** By year 10, 66% of edges cross cohort boundaries and 73% of nodes are bridges. The network doesn't fragment into isolated generational ghettos — churn and replacement naturally mix communities.

4. **Community size is reasonable.** 11-12 communities of 700-900 nodes each at steady state. Largest community ~1900 nodes. No single dominant mega-cluster, no tiny orphan groups.

5. **Mutual partnerships are rare (0.1-0.2%).** Most relationships are asymmetric: A stores for B, but B doesn't store for A. This is fine — reciprocity isn't required for the trust model. Storage is based on trust scores, not explicit pairing.

6. **Degree is stable at ~30.** Each node has about 30 effective partnerships, well within the 50-partner limit. The network is not saturating its capacity.

## Design Implications

- **The acceptance gate works as intended.** New users naturally cluster together, build trust, then integrate with the established network. No manual federation needed.
- **Community structure is an emergent property, not a design goal.** We don't need to engineer federations — they happen naturally from trust-based selection.
- **Network resilience to generational turnover.** Even with 25% annual churn, community structure persists. No "death of old guard" catastrophe.
- **Cross-cohort connectivity is a health metric.** Monitoring XCohort% and Bridge% in production could indicate network health. Low values → new users are isolated. High values → network is well-integrated.

## Static Model Comparison (from earlier run)
Static 10K nodes (no churn, no growth): Q=0.752 at 24 months. Higher modularity because no mixing, but unrealistic.

## Code
`simulations/cluster_formation.py` — run with `--years 10 --seeds 3 --jobs 3`
