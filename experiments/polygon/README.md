# Viaticum Polygon — Reusable Instrumented E2E Test Harness (v1)

> A **polygon** ("proving ground"), not a one-shot test. It spins up a fleet of REAL `viaticum`
> daemons on the 48-core / 64 GB server, drives them through a scenario, samples every node's
> user's-eye view + external resource use into a time series, then runs two oracles over the
> result: a HARD **bug-freeness** gate and a SOFT **fairness** characterizer that emits findings
> for the future Phase-4R economy redesign.
>
> v1 = honest nodes only. The only adversarial-ish archetype is a PASSIVE FREE-RIDER realized
> purely by config (tiny `soft_quota_gb`). NO new daemon Rust is required.

---

## Part 1 — Design Thinking

### First-Person Scenario

Ilya wants to know two things before publishing: "does the daemon ever crash / lose data / wedge
under realistic churn?" and "does the trust economy treat an honest user fairly?". He runs:

```
cd ~/projects/syncback
./rbuild.sh                                  # builds ./target/release/viaticum on the server
python3 experiments/polygon/run.py experiments/polygon/scenarios/steady_fairness.json
```

Step by step:

1. `run.py` reads the scenario JSON: archetype mix, requested node count `N=60`, churn schedule,
   `time_scale=2000`, duration `virtual_days=240`, `seed=1337`.
2. The fleet-manager resolves `BINARY` (env → `./target/release/viaticum`, exits if missing),
   creates a timestamped results dir `experiments/polygon/results/2026-06-13T18-22-09_steady_fairness/`,
   and copies the scenario JSON into it (provenance).
3. **Warm-up RSS probe.** It launches 6 representative daemons (covering the heaviest archetype),
   star-connects them, pushes one representative file each, lets PoS rounds fire, then samples
   `ps -o rss=` at the peak. It computes `peak_rss_mb`, then
   `N_cap = floor((usable_ram_mb - reserve_mb) / peak_rss_mb)`. It logs:
   `requested N=60, peak_rss=180MB, usable=58000MB, reserve=8000MB, N_cap=277 → using N=60`.
   If `requested > N_cap`, it reduces to `N_cap` and logs the reduction. It tears down the warm-up
   fleet. **It never silently truncates.**
4. **Fleet launch.** For each of N nodes: `mkdir`, `viaticum init` (distinct master — mandatory),
   write `config.toml` with that node's archetype knobs + a tiny `[metrics]` push disabled (we poll
   `status --json` as canonical), `mkdir files`, then
   `viaticum daemon --time-scale 2000 --watch-dir .../files`. Every PID is recorded.
5. Star-connect: poll node-00 for its `addr:` line (respect the ~1 s race), then launch parallel
   `viaticum connect <addr>` from every other node. Verify node-00 `peer_count >= N-1`.
6. **Seed data.** Each archetype's watch dir is filled with deterministic-size random files
   (seeded `random` so file *sizes* repeat run-to-run; content is fresh per run, hashed before backup).
7. **Drive loop.** The orchestrator's wall clock advances. Every `sample_interval_secs` (e.g. 8 s)
   the collector samples each node: `status --json`, `ps RSS`, `du holdings`, `stat db.redb`, and
   a tail of stderr. Each sample is appended as one CSV row keyed `(tick, node, archetype)`.
   When the wall clock reaches a churn event's mapped time, the fleet-manager kills/restarts the
   scheduled node(s) and re-resolves+re-connects on restart.
8. **End of run.** A final restore is requested for every honest backed-up file; the harness
   `find`s the staged file under `<data_dir>/restore/...` and compares its hash to the
   pre-backup original. Daemons are torn down SIGTERM → grace → SIGKILL (stderr scanned for
   `panicked`/ERROR *before* the -9 escalation).
9. **Oracles.** `oracle_bug.py` and `oracle_fair.py` read the CSV + the file-hash ledger + the
   stderr scan results and write `verdict.json` (bug-freeness PASS/FAIL + per-check detail) and
   `fairness_report.json` (every fairness metric characterized, never failing the run).
10. Ilya sees on stdout: `BUG-FREENESS: PASS (18/18 hard checks)`, `FAIRNESS: 6 findings (see report)`,
    and the path to the results dir. Exit code = 0 iff bug-freeness passed.

### Assumptions

| # | Assumption | If wrong → what breaks |
|---|---|---|
| **Identity** | Each node `init`s a DISTINCT master key; star is network bootstrap only, not a trust cluster. | If two nodes share a master they are sibling-excluded from each other's placement pool → zero placements → false "backup failure" in the oracle. The fleet-manager MUST `init` each node independently and never reuse a data-dir. |
| **Identity** | `StatusData.device_id` (first-8-hex) of node A equals the `PeerSummary.identity_hex` that node B reports for A. | If the join key differs, the collector cannot build the cross-fleet give/get graph (A17, clustering) and fairness edges are silent. Verified: both are "first 8 bytes of identity pubkey hex". The collector keys the node↔peer join on this. |
| **Identity** | `node_identity` (full IdentityPub hex) is stable across restarts (keyfile persists in data-dir). | If it rotates on restart, churn re-joins break and a restarted node looks like a newcomer. Verified stable (key in data-dir). The fleet-manager uses the launch-index `node-NN` as the durable label and records `node_identity` + `device_id` once at first-ready. |
| **Network** | Ephemeral ports (web_api `127.0.0.1:0`, libp2p `listen_port=0`) are self-discovered; no port map needed; ports CHANGE across restarts. | If we cache a node's libp2p `addr:` from t0 and reconnect a restarted node to it, the connect fails silently. The fleet-manager MUST re-resolve `addr:` at every (re)connect, never cache across restarts. |
| **Network** | The Kademlia mesh propagates from the star seed so any node can place on any other authenticated node. | If discovery is too slow at the chosen `time_scale`, placement may stall → false self-heal/onboarding failures. Mitigation: scenario `warmup_secs` before backups; oracle judges liveness only after warmup. |
| **State** | `holding_bytes == used_bytes` (same value, two field names); `backed_up_bytes`/`bytes_*` are ENCODED k·t units, not raw source size. | If the oracle cross-compares `backed_up_bytes` with `du` of the watch dir it gets garbage. The collector keeps give/get math strictly in the daemon's encoded accounting unit and uses `du` ONLY for the holdings/db disk-growth gate. |
| **State** | `peer_count_authenticated` resets on restart until cert re-exchange; not a bug. | If the oracle gates liveness on `peer_count_authenticated` immediately post-restart it false-fails. The bug oracle allows a re-auth settle window after each restart. |
| **Ordering** | The `addr:` line appears ~1 s AFTER `identity:` in `status`. | A solo/fresh node races; connect uses a stale/empty addr. `get_addr` polls 20×0.5 s. |
| **Ordering / Time** | `--time-scale` divides ALL internal cadences (incl. the now-fixed mailbox poll), floored at `.max(1)`; metrics push is NOT scaled (wall-clock). | If `time_scale` exceeds a base cadence the cadence pins at 1 s and stops accelerating (CPU burn, no extra virtual speed). The scenario picks `time_scale` so the slowest cadence we measure (weekly PoS 604800 s) stays > a few real seconds (i.e. `time_scale <= ~100000`). |
| **Concurrency** | ~N concurrent daemons + overlapping encodes fit in 64 GB only if N is RSS-capped. | If N is chosen blindly the box OOMs mid-run → false "crash". The warm-up RSS probe is mandatory and N is capped to fit. |
| **Concurrency** | `kill -9` without a SIGTERM grace can corrupt redb → false DB-integrity FAIL. | Teardown is two-pass (TERM, grace sleep, then -9); stderr panic scan runs before -9. |
| **State** | The free-rider is realized by a tiny `storage.soft_quota_gb` (effective_quota = min(soft_quota, disk_free − disk_reserve)), NOT by hard_quota. | If we set hard_quota instead, the GET-for-others ceiling is not capped and the node still holds for others → not a free-rider. The archetype maps to `soft_quota_gb ≈ 0.001`. |

### Invariant Impact

This harness is OBSERVE-ONLY: it spins up the unmodified daemon and reads it. It introduces no new
daemon code and therefore cannot break protocol invariants. The relevant question is the inverse —
which daemon invariants the polygon must MEASURE without perturbing:

| Invariant (daemon) | How the polygon preserves/observes it |
|---|---|
| **Distinct-master placement eligibility** (siblings excluded). | Every node `init`s its own master; the polygon never builds a real cluster. Star = transport only. |
| **Source files never deleted by eviction; only holdings shrink.** | Disk-pressure scenario asserts (via `du holdings` shrinking while watch-dir size & `db.redb` are intact) that eviction touches holdings only. The polygon never sets a watch dir under `holdings/`. |
| **No data loss for honest owners.** | End-of-run restore-hash ledger is the ground-truth oracle; it compares restored content to the pre-backup BLAKE3/md5, exactly as `local_delete_test.sh` does for deletion. |
| **Mailbox poll scales with time_scale (E1 fix).** | The polygon ONLY runs under `time_scale>1`, and the bug oracle asserts `pos_total_passes` actually CLIMBS (not just challenges issued) + `table_stats.mailbox_entries>0` — the only way to catch an E1-class regression. |
| **Bounded DB / disk growth (vacuum, record cap).** | `du(db.redb)` and `table_stats` row counts are sampled over the run; monotone unbounded growth is a FAIL. |

### Identity Walkthrough

Trace of the identity used to join observations across the fleet (the load-bearing key for every
fairness/clustering metric):

| Step | Participant | Key / identity used | Derived from | Consumed by |
|---|---|---|---|---|
| 1. init | node-NN daemon | master mnemonic → master IdentityPub | `viaticum init` (random per node) | keyfile in data-dir |
| 2. ready | fleet-manager | label `node-NN` ↔ `StatusData.node_identity` (full hex) + `StatusData.device_id` (first-8 hex) | first `status` after ready | `node_index.json` (durable label map) |
| 3. connect | peer node-MM | node-NN's libp2p multiaddr `addr:` (ephemeral, re-resolved) | node-NN `status` | `viaticum connect` |
| 4. observe self | node-NN | `StatusData.{holding_bytes, backed_up_bytes, ...}` | node-NN's own DB | collector row `(tick, node-NN)` |
| 5. observe edge | node-MM | `PeerSummary.identity_hex` (first-8 hex of node-NN) + `bytes_we_store`/`bytes_peer_stores`/`trust_*` | node-MM's DB | collector edge `(MM → NN)` |
| 6. join | collector | match `PeerSummary.identity_hex` (step 5) == `device_id` (step 2) | `node_index.json` | give/get graph, cohort tagging, Kendall-τ |

Every fairness edge depends on step 6's join key being identical between a node's self-reported
`device_id` and the `identity_hex` its peers report for it. This is verified in code
(`cli/types.rs`: both are "first 8 bytes of identity pubkey hex"). If a fleet has >20 peers per
node, each node only reports its **top-20-by-trust** peers, so the collector reconstructs the full
graph by UNIONING every node's `peers[]` list (each node reliably reports its own top-20; the union
covers most edges at polygon scale).

---

## Part 2 — Implementation Spec

The two north-star properties, archetype model, churn model, collector schema, scenario matrix,
modules, and determinism plan are all defined below. **No new Rust is required for v1** (optional
daemon exports are listed at the end).

### Confirmed status / config surface (verified against code)

- `status --json` → `StatusData` (`crates/viaticum/src/cli/types.rs`): `node_identity`, `device_id`,
  `node_addr`, `peer_count`, `peer_count_connected`, `peer_count_authenticated`, `avg_trust`,
  `holding_bytes`(==`used_bytes`), `backed_up_files`, `backed_up_bytes`, `blocks_needing_repair`,
  `effective_quota_bytes`, `pos_total_challenges`, `pos_total_passes`, `placement_count`,
  `placement_alive`, `placement_lost`, `blocks_ok`, `blocks_at_risk`,
  `table_stats{files, source_blocks, symbol_placements, peers, holdings, event_log, pos_weekly,
  file_holders, holder_files, mailbox_entries}`, `by_importance[]`, and `peers[]` (≤20, by trust):
  `PeerSummary{identity_hex, trust, trust_p, trust_i, trust_s, bytes_we_store, bytes_peer_stores,
  pos_challenges_recent, pos_passes_recent, last_seen, link}`.
- Trust formula (`trust/mod.rs:324`): `combined = (KP·p + KI·i)·clamp(s, S_CLAMP_MIN, S_CLAMP_MAX)`
  with `KP=0.4, KI=1.75, S_CLAMP_MIN=0.1, S_CLAMP_MAX=1.0, MAX_COMBINED_TRUST=2.15, INITIAL_TRUST_P=0.5`,
  `trust_i` starts 0.0, `P_WINDOW_WEEKS=4` (`constants.rs`).
- Eviction (`budget/mod.rs`): `SOFT_PRESSURE_THRESHOLD=0.15`, `HARD_PRESSURE_THRESHOLD=0.05`;
  `DiskPressure::{Normal, Soft, Hard}`; priority `= importance·trust_of_owner·(1+age_bonus)`, lowest
  evicted first; `hard_quota_bytes` is a never-evict-below floor.
- Config knobs (`config/mod.rs`): `[storage] soft_quota_gb / hard_quota_gb / disk_reserve_gb`,
  `[web_api] enabled/bind`, `[metrics] enabled/push_url/push_interval_secs`,
  `[backup] source_block_size_mb/max_versions/max_version_age_days`, `[[watch]] path/importance_multiplier`.
  CLI: `--data-dir` (global), `daemon --time-scale <u64> --watch-dir <repeatable>`, `--log-format json|text`.
- `restore` stages to `<data_dir>/restore/<job_id>/<original_path>` (alpha; `--dest` unsupported).
- Mailbox poll scales: `poll_interval_secs(time_scale)=(3600/time_scale.max(1)).max(1)` — the E1 fix.

### THE TWO ORACLES (verifiable form)

See the `oracles` field for the exact named checks. Summary of policy: **bug-freeness checks are
HARD** (any FAIL ⇒ run exit code != 0 and `verdict.json.bugfree.pass=false`); **fairness checks
NEVER fail the run** — they emit characterized findings into `fairness_report.json` for Phase-4R.
Both oracles read the same artifacts (`timeseries.csv`, `restore_ledger.json`, `stderr_scan.json`,
`node_index.json`, `scenario.json`). Thresholds taken from Exp-13/14/06/11/23/24 are used as
ORDERINGS and RELATIVE drops/recoveries, never absolute simulator magnitudes (the absolute numbers
are from the old Python simulator, not the real daemon). Each fairness check explicitly references
which experiment finding it characterizes against.

### ARCHETYPE MODEL (the 6 + passive free-rider)

Four config-only dimensions per Exp-13: **uptime** (churn schedule), **storage capacity**
(`soft_quota_gb`), **backup volume** (watch-dir bytes/files), **reliability priority**
(`importance_multiplier`). All realized via per-node TOML + churn schedule. No Rust.

| Archetype | uptime (churn) | soft_quota_gb | watch volume | importance_mult | Maps to AC |
|---|---|---|---|---|---|
| **reliable** | always-on (no kill) | large (e.g. 20) | medium (e.g. 8 files × 4 MB) | 1.0 | A2 highest-trust cohort |
| **weekend** | periodic ON-blocks (e.g. 2 virtual-days on / 5 off) | large | medium | 1.0 | optional P-window characterization |
| **seasonal** | long ON then long OFF block (e.g. on 120 vd, off 40 vd) | large | medium | 1.0 | onboarding/recovery flavor |
| **nomad** | random ~50% ON/OFF blocks (seeded) | large | medium | 1.0 | A3 lowest among full-capacity |
| **vacationer** | always-on then ONE bounded offline window then return | large | medium | 1.0 | A9 absence/recovery, CHURN-3 stickiness |
| **freerider** (passive) | always-on | **tiny (0.001)** | small (own data only) | 1.0 | A4/A5/A17, FR1–FR6, TC4/TC5 |
| **newcomer** | joins LATE (mid-run) into the mature fleet | large | medium | 0.0 (uses default) | A16, CHURN-5, TC3 |
| **donor** (optional) | always-on | very large (0 = unlimited) | small | 1.0 | high-capacity holder baseline |

Notes: `weekend`/`seasonal` periodicity at polygon scale won't reproduce Exp-13's 7-day window
exactly — they are OPTIONAL characterizations, not hard criteria. Every archetype is an independent
master. `importance_multiplier` is set via a `[[watch]]` block (the only place it lives in config);
the rest of the test config uses `--watch-dir` for the watch path but a node needing a non-default
importance writes a `[[watch]]` block with `path` + `importance_multiplier` and omits `--watch-dir`.

### CHURN + ONBOARDING MODEL (wall-clock → virtual time)

`virtual_elapsed = wall_elapsed × time_scale`. A churn event scheduled at `virtual_day=V` fires at
`wall_secs = V·86400 / time_scale` after fleet-start. The fleet-manager owns an event queue of:

- `kill {node|cohort}` at virtual time T → SIGTERM the PID(s), record `down` interval.
- `restart {node|cohort}` at virtual time T → relaunch with SAME data-dir + archetype config,
  re-resolve node-00 addr, `connect`, record `up`.
- `join {new_node, archetype}` at virtual time T → full fresh init+launch+connect (onboarding into
  a mature fleet). The newcomer starts with empty trust and must EARN it.
- `mass_depart {fraction f, mode: instant|gradual_window}` → kill `f·N` holders simultaneously
  (instant) or spread over a virtual window (gradual). For `gradual`, schedule individual kills
  uniformly across the window.

Each event records `(virtual_day, wall_secs, event_type, targets[])` into `churn_log.json` so the
oracles can attribute observations (a `placement_lost` spike) to a specific churn event and so the
collector can label whether a node is `up`/`down` at each tick. The newcomer's join time is also the
cohort tag used by the clustering oracle.

### COLLECTOR TIME-SERIES SCHEMA

One CSV (`timeseries.csv`), one row per `(tick, node)`. The per-edge `PeerSummary` data goes to a
second CSV (`edges.csv`, one row per `(tick, observer_node, target_peer)`), because it is a
variable-length list. Columns (exact):

`timeseries.csv`:
```
tick,wall_secs,virtual_day,node,archetype,up_state,
node_identity,device_id,
peer_count,peer_count_connected,peer_count_authenticated,
avg_trust,holding_bytes,used_bytes,backed_up_files,backed_up_bytes,
blocks_needing_repair,placement_count,placement_alive,placement_lost,
blocks_ok,blocks_at_risk,
pos_total_challenges,pos_total_passes,
effective_quota_bytes,
tbl_files,tbl_source_blocks,tbl_symbol_placements,tbl_peers,tbl_holdings,
tbl_event_log,tbl_pos_weekly,tbl_file_holders,tbl_holder_files,tbl_mailbox_entries,
imp_critical_p,imp_high_p,imp_medium_p,imp_low_p,imp_trivial_p,
rss_kb,du_holdings_kb,du_db_redb_bytes,du_datadir_kb,
status_ok
```
`edges.csv`:
```
tick,wall_secs,virtual_day,observer_node,target_identity_hex,
trust,trust_p,trust_i,trust_s,bytes_we_store,bytes_peer_stores,
pos_challenges_recent,pos_passes_recent,last_seen,link
```
`up_state ∈ {up, down}` (from churn_log at sample time). `status_ok ∈ {1,0}` (0 when the node was
down or `status` failed — distinguishes a real-zero from a missing sample). Missing numeric fields
(node down) are written as empty string, not 0. All byte fields are the daemon's accounting unit.

Auxiliary artifacts in the results dir:
- `node_index.json`: `{ "node-00": {"label","archetype","node_identity","device_id","join_virtual_day"}, ... }`
- `churn_log.json`: list of churn events with `(virtual_day, wall_secs, event_type, targets[])`.
- `restore_ledger.json`: `{ "node-07": [ {"path","orig_hash","restored_hash","match":true,"phase":"end"} ] }`.
- `stderr_scan.json`: per node `{ "node-03": {"panicked":0,"error_lines":2,"first_error":"..."} }`.
- `scenario.json`: a copy of the scenario config actually used (with the resolved N and time_scale).
- `verdict.json`, `fairness_report.json`: oracle outputs.

### SCENARIO MATRIX

See the `scenarios` field. Six v1 scenarios: steady-state fairness, churn+mass-departure,
onboarding-into-mature, disk-pressure/eviction, observational DoS (free-rider count invariance),
observational clustering. Each is one JSON config consumed by `run.py`.

### MODULE / DATA-FLOW DIAGRAM

```
scenario.json ─► run.py (L1 orchestrator)
                   │  ├─ config_gen.py  → per-node config.toml + node plan
                   │  ├─ fleet.py (L1)   → init/launch/connect/kill/restart/join, RSS-cap N
                   │  │     └─ feasibility.py → warm-up RSS probe → N_cap
                   │  ├─ archetypes.py (L2) → archetype→knobs + churn schedule expansion
                   │  ├─ churn.py (L3)   → virtual↔wall event queue, drives fleet kills/joins
                   │  └─ collector.py (L4) → poll status/ps/du/stderr → timeseries.csv + edges.csv
                   ▼
        results/<ts>_<id>/{timeseries.csv, edges.csv, node_index.json,
                           churn_log.json, restore_ledger.json, stderr_scan.json}
                   │
                   ├─► oracle_bug.py  (L5a, HARD)  → verdict.json
                   └─► oracle_fair.py (L5b, SOFT)  → fairness_report.json
                              ▲
                         common.py (shared: CSV load, graph build, give/get, Kendall-τ, cohorts)
```

### REPEATABILITY / DETERMINISM + RSS-CAP-N PLAN

- **Seeds.** Scenario carries a single `seed`. `config_gen`/`archetypes`/`churn` derive all
  randomness (file sizes, nomad ON/OFF blocks, gradual-departure kill ordering) from
  `random.Random(seed)` so the *structure* of a run repeats. File *content* is fresh per run
  (so hashes are meaningful) but content size is seeded. The seed is recorded in `scenario.json`.
- **Tolerant oracles.** Because the network + libp2p + wall-clock churn are real and stochastic,
  oracles use AGGREGATE thresholds (cohort means, monotone-ish trends with a slack band, orderings)
  not exact equality. Trends allow a configurable `noise_band` (default 5%). Kendall-τ targets are
  SOFT (≥0.8 desirable, <0.62 or a downward trend = finding).
- **RSS-cap-N.** `feasibility.probe(scenario)` launches `min(6, requested_N)` daemons of the
  HEAVIEST archetype in the scenario at the scenario's `time_scale`+`source_block_size_mb`,
  star-connects, pushes one representative file each, waits for steady state (PoS firing / holdings
  settled), samples `ps -o rss=` 3× at 5 s spacing and takes the MAX, returns `peak_rss_mb`.
  `N_cap = floor((usable_ram_mb - reserve_mb) / (peak_rss_mb × headroom))` with
  `usable_ram_mb` read from `/proc/meminfo` MemTotal, `reserve_mb` default 8000, `headroom` default
  1.3. Logs `requested, peak_rss, usable, reserve, N_cap, using`. If `requested > N_cap` reduce and
  log; NEVER silently truncate. During the run the collector samples RSS+du every tick; the bug
  oracle flags monotone unbounded growth (linear-fit slope over the back half of the run > a
  per-archetype threshold) as a leak FAIL — preferring trend over absolute because redb is mmap'd.

### CONSTRAINTS FOR AUTHORS

Authoring agents MUST: write files under `experiments/polygon/` only; syntax-check with
`python3 -m py_compile <file>` and `bash -n <file>`; NOT run a multi-node fleet; NOT `git commit`
or push. Running on the server + review + integration are the human's job. The agent sandbox is
8c/14G — never size the fleet against it (all sizing is for the 48c/64G server, computed at runtime).

### v1 NEEDS NO NEW RUST — optional nice-to-haves (deferred)

`needs_rust=false`. Optional later daemon exports that would SHARPEN (not enable) v1: a time-integrated
`gb_days` GIVE ledger (currently approximated by trapezoidal integration of `holding_bytes`/
`bytes_we_store` over the poll series); a full (un-capped) per-peer partner list +
per-relationship gb_days (currently the ≤20-by-trust cap is worked around by unioning all nodes'
`peers[]`); raw source bytes per version (`FileVersion.source_size`, known tech-debt — irrelevant to
the data-loss oracle which compares content hashes).