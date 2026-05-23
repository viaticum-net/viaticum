# Simulations

Phase 1 research code. Standalone Python scripts that explore the trust protocol numerically before it was implemented in Rust.

Each script answers one question about the protocol design: does the PID-style reputation converge, does the system survive a Sybil attack, how do mixed populations behave over years, etc. Writeups for each numbered experiment live in [`../docs/archive/experiments/`](../docs/archive/experiments/) — read those first for context. The scripts here are the source of truth: writeups summarize, scripts reproduce.

## Running

The scripts have no shared framework. Each one is self-contained, takes CLI flags, and writes results into `results/<script-name>/` (PNG plots, JSON metric dumps).

```
pip install numpy scipy matplotlib joblib
python pid_convergence.py --peers 1000
python pid_convergence.py --sweep --jobs 4
```

Flags vary per script — `--help` lists them.

## Script-to-experiment mapping

| Script | Experiment writeup |
|--------|--------------------|
| `pid_convergence.py` | 01 — PID reputation convergence (Kendall's tau) |
| `data_survival.py` | 02 — data survival under churn |
| `pid_repair.py` | 03 — PID early warning + repair |
| `sybil_attack.py` | 04 — Sybil resistance |
| `free_rider.py` | 05 — free-rider detection |
| `mass_departure.py` | 06 — mass departure shock |
| `spite_attack.py` | 07 — spite attack |
| `storage_lie.py` | 08 — storage-lie detection |
| `cluster_formation.py` | 10 — cluster formation dynamics |
| `user_lifecycle.py` | 11 — user lifecycle |
| `prison_network.py` | 12 — prison network attack |
| `behavior_models.py` | 13 — 6-archetype behavior model |
| `node_perspective.py` | 14 — node-perspective view |
| `pis_convergence.py` | 15 — P+I+S convergence |
| `pis_threats.py` | 16 — P+I+S under attacks |
| `pis_longterm.py` | 17 — long-term mixed populations |
| `pis_adaptive_n.py` | 21 — adaptive `n` (placement count) |
| `pis_s_formula.py` | 22 — S-component formula iteration |
| `pis_eviction.py` | 23 — eviction policy |
| `pis_escrow.py` | 24 — escrow mechanism |
| `pis_integration.py` | 25 — full integration |
| `pis_weighted_placement.py` | 26 — weighted shard placement |
| `shard_placement.py` | 27 — shard placement (final) |
| `user_perspective.py`, `pis_perspective.py`, `cluster_probe.py`, `cluster_probe_v2.py`, `federation.py` | supporting analyses, no dedicated writeup |

## Status

Research code. Not maintained against a style guide, not unit-tested. The Rust implementation (`crates/viaticum-core`) is the source of truth for protocol behavior in production. These scripts exist so the design decisions can be re-verified independently of the Rust code.

## License

[AGPL-3.0-only](../LICENSE), same as the rest of the project.
