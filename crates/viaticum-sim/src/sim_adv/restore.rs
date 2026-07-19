//! Restore-truth — the World-v3 metric №1 (design `4r_world_v3_spec.md` §4 п.1, detail
//! §3.1, with the BLOCK-1 correction from spec §10 п.1).
//!
//! After a [`Disaster`](crate::sim_adv::scenario::Event::Disaster) the victim loses its
//! source data (P1: no source ⇒ no repair). The ONLY recovery is a COLD RESTORE — pulling
//! surviving symbols off the network's holders, over a window of days, as each holder
//! surfaces online. Restore-truth asks, per surviving victim block: can ≥ `k_eff` live
//! symbols be re-collected in the window?
//!
//! ## God-view, evaluator-only (anti-oracle)
//!
//! Everything here is read from the god-view [`World`] in the EVALUATOR role: the actual
//! `present ∧ alive ∧ online()` over the REAL engine run (`churn` keeps firing, the
//! victim's repair does NOT — the P1 gate in `place_own_data`). It is NEVER fed back into
//! a node decision, and `online()` is the SAME predicate the engine uses (one physics).
//! This is deliberately built on the real engine, NOT on the retired parallel hazard
//! scorer `evaluator::legacy_dr_metric` (spec §10 п.3).
//!
//! ## BLOCK-1: any live symbol counts, cream included
//!
//! RaptorQ reconstructs a block from ANY `k_eff` symbols, so the flagship metric counts
//! ANY re-collectable live symbol — floor OR cream. The floor-only count is reported
//! separately as the `durability_floor` column ("what is guaranteed", spec §10 п.1).
//!
//! ## Three collection models (spec §10 п.9 + F4/D7)
//!
//! * **Model U** (union-over-window): a symbol is collectable if its holder is still
//!   present, still holds it alive, and comes online at least once in the window. Models
//!   "pull each symbol whenever its holder next surfaces". No bandwidth limit. **U is
//!   ASPIRATIONAL** (F4 / D7): it assumes a restore loop that keeps retrying over days,
//!   which the daemon does not yet implement (tech-debt D7) — so U is the ceiling, not
//!   today's behaviour.
//! * **Model S** (bandwidth-aware): the SAME collectability, but the victim's TOTAL
//!   re-download over the window is capped at `restore_bw_gb_day × window_days` GB. A
//!   mandatory pessimistic co-report (Model U is optimistic exactly on the large-archive
//!   DR-primary tier, WARN-3). Blocks are restored greedily by importance (ι desc).
//! * **Model O** (one-shot, F4 / D7): a symbol is collectable ONLY if its holder is
//!   present, holds it alive, AND is online in the FIRST tick of the window (no union over
//!   the window). Models a single-shot restore that grabs whatever is reachable right now —
//!   the pessimistic floor that matches the daemon's current (no-retry) restore. `O ≤ U`
//!   always, and `O = U` under 100% uptime (always-online holders surface at the first tick
//!   too).

use std::collections::BTreeMap;

use crate::sim_adv::hetero::DemandClass;
use crate::sim_adv::scenario::WorldParams;
use crate::sim_dynamic::generator::{DAYS_PER_TICK, GiverTier, World};

/// The iota buckets the report slices restore-truth by (detail §3.1). Half-open on the
/// low edge, the top bucket closed at 1.0.
pub const IOTA_BUCKETS: [(f64, f64); 4] = [(0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)];

/// The bucket index (0..4) for an importance `iota`, clamped into the covered range: the
/// upper edge of each bucket is exclusive except the last, which is closed at 1.0.
pub fn iota_bucket(iota: f64) -> usize {
    let last = IOTA_BUCKETS.len() - 1;
    for (i, &(_, hi)) in IOTA_BUCKETS.iter().enumerate() {
        if i < last && iota < hi {
            return i;
        }
    }
    last
}

/// Re-collectability of ONE surviving victim block (one row of restore-truth).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockOutcome {
    /// God-view owner (victim) index.
    pub owner: usize,
    /// God-view block id.
    pub block_id: usize,
    /// Owner-declared importance ι.
    pub iota: f64,
    /// The victim's giver tier (for the tier breakdown, metric #7).
    pub tier: GiverTier,
    /// The victim's DEMAND CLASS (hetero-v2): the per-class restore-truth cut (`dr_hetero`).
    pub class: DemandClass,
    /// Distinct collectable holders, ANY symbol (floor + cream) — the BLOCK-1 count.
    pub n_collectable_any: usize,
    /// Distinct collectable holders, FLOOR symbols only — the durability count.
    pub n_collectable_floor: usize,
    /// F4 (D7): distinct collectable holders under Model O (any symbol, holder online at
    /// the FIRST window tick only) — the one-shot floor.
    pub n_collectable_oneshot: usize,
    /// Restorable under Model U (any ≥ `k_eff`) — the flagship (ASPIRATIONAL, D7) bit.
    pub restorable_u: bool,
    /// Restorable under Model S (any ≥ `k_eff` AND within the bandwidth budget).
    pub restorable_s: bool,
    /// F4 (D7): restorable under Model O (one-shot ≥ `k_eff`) — `O ≤ U` always.
    pub restorable_o: bool,
    /// Restorable counting FLOOR symbols only, Model U — "what is guaranteed".
    pub restorable_floor: bool,
}

/// The restore-truth result for one seed (one Disaster episode).
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreTruth {
    /// The tick(s) the disaster fired (min over victims, for the report header).
    pub disaster_tick: u64,
    /// Restore window `W` in days.
    pub window_days: f64,
    /// `W` rounded to whole ticks (the collection window length).
    pub window_ticks: u64,
    /// Model-S download budget in GB/day (0 ⇒ Model S ≡ Model U).
    pub restore_bw_gb_day: f64,
    /// How many victims the disaster struck.
    pub n_victims: usize,
    /// Reconstruction threshold `k_eff`.
    pub k_eff: usize,
    /// One row per surviving-victim block that EVER met its floor (the denominator).
    pub blocks: Vec<BlockOutcome>,
    /// The predator information model this run was scored under: `"none"` in 0.2 (no
    /// predators). NOTE-5: A9's two-run CROWN-1 comparison sets this to a DR-card label.
    pub info_model: &'static str,
}

impl RestoreTruth {
    /// Denominator: surviving-victim blocks that ever met their floor.
    pub fn n_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Flagship restore-truth (Model U, any symbol) = fraction of blocks restorable.
    /// `NaN` when there is no denominator (no such block).
    pub fn restore_truth_u(&self) -> f64 {
        self.frac(|b| b.restorable_u)
    }

    /// Bandwidth-aware restore-truth (Model S, any symbol).
    pub fn restore_truth_s(&self) -> f64 {
        self.frac(|b| b.restorable_s)
    }

    /// F4 (D7): one-shot restore-truth (Model O, any symbol) = fraction restorable when
    /// only the FIRST window tick's reachable holders count. `O ≤ U` always.
    pub fn restore_truth_o(&self) -> f64 {
        self.frac(|b| b.restorable_o)
    }

    /// Durability floor = fraction restorable counting FLOOR symbols only (Model U).
    pub fn durability_floor(&self) -> f64 {
        self.frac(|b| b.restorable_floor)
    }

    /// Fraction of the denominator blocks for which `pred` holds.
    fn frac(&self, pred: impl Fn(&BlockOutcome) -> bool) -> f64 {
        if self.blocks.is_empty() {
            return f64::NAN;
        }
        let n = self.blocks.iter().filter(|b| pred(b)).count();
        n as f64 / self.blocks.len() as f64
    }

    /// Restore-truth-U within one iota bucket (`NaN` if the bucket is empty here).
    pub fn restore_u_in_bucket(&self, bucket: usize) -> f64 {
        let rows: Vec<&BlockOutcome> = self
            .blocks
            .iter()
            .filter(|b| iota_bucket(b.iota) == bucket)
            .collect();
        if rows.is_empty() {
            return f64::NAN;
        }
        rows.iter().filter(|b| b.restorable_u).count() as f64 / rows.len() as f64
    }

    /// Restore-truth (any model) within one DEMAND CLASS (`NaN` if the class has no block
    /// here). `pred` picks the model (U / S / O / floor) — the per-class DR cut (`dr_hetero`).
    fn restore_in_class(&self, class: DemandClass, pred: impl Fn(&BlockOutcome) -> bool) -> f64 {
        let rows: Vec<&BlockOutcome> = self.blocks.iter().filter(|b| b.class == class).collect();
        if rows.is_empty() {
            return f64::NAN;
        }
        rows.iter().filter(|b| pred(b)).count() as f64 / rows.len() as f64
    }

    /// Model-U restore-truth within one demand class.
    pub fn restore_u_in_class(&self, class: DemandClass) -> f64 {
        self.restore_in_class(class, |b| b.restorable_u)
    }

    /// Model-S (bandwidth-aware) restore-truth within one demand class.
    pub fn restore_s_in_class(&self, class: DemandClass) -> f64 {
        self.restore_in_class(class, |b| b.restorable_s)
    }

    /// Model-O (one-shot, no-retry) restore-truth within one demand class.
    pub fn restore_o_in_class(&self, class: DemandClass) -> f64 {
        self.restore_in_class(class, |b| b.restorable_o)
    }

    /// Surviving-victim blocks in one demand class (the per-class denominator).
    pub fn n_blocks_in_class(&self, class: DemandClass) -> usize {
        self.blocks.iter().filter(|b| b.class == class).count()
    }
}

/// Bit-exact equality of two restore-truth results (used by the determinism board row).
pub fn bit_eq(a: &RestoreTruth, b: &RestoreTruth) -> bool {
    a.disaster_tick == b.disaster_tick
        && a.window_ticks == b.window_ticks
        && a.n_victims == b.n_victims
        && a.k_eff == b.k_eff
        && a.blocks.len() == b.blocks.len()
        && a.blocks.iter().zip(&b.blocks).all(|(x, y)| {
            x.owner == y.owner
                && x.block_id == y.block_id
                && x.class == y.class
                && x.iota.to_bits() == y.iota.to_bits()
                && x.n_collectable_any == y.n_collectable_any
                && x.n_collectable_floor == y.n_collectable_floor
                && x.n_collectable_oneshot == y.n_collectable_oneshot
                && x.restorable_u == y.restorable_u
                && x.restorable_s == y.restorable_s
                && x.restorable_o == y.restorable_o
                && x.restorable_floor == y.restorable_floor
        })
}

/// One collectable symbol's god-view facts (a symbol is one `(holder, block)` — the
/// spread keeps ≤ 1 symbol per holder per block, so the holder identifies it).
#[derive(Debug, Clone, Copy)]
struct Collectable {
    cream: bool,
    volume: f64,
}

/// One tracked victim block (its symbol re-collectability accumulates over the window).
struct TrackedBlock {
    owner: usize,
    block_id: usize,
    iota: f64,
    tier: GiverTier,
    class: DemandClass,
    return_tick: u64,
    /// Holder → its symbol's facts, for every holder online ≥ once in the window while
    /// still holding an alive symbol (Model U/S). BTreeMap ⇒ deterministic iteration.
    collectable: BTreeMap<usize, Collectable>,
    /// F4 (D7): holder → facts, for holders online at the FIRST window tick only (Model O,
    /// the one-shot floor). A subset of `collectable` by construction.
    collectable_oneshot: BTreeMap<usize, Collectable>,
}

/// Accumulates restore-truth across a run: snapshots the victim's surviving blocks at the
/// Disaster, records re-collectability tick-by-tick over the window, then finalises.
pub struct RestoreTracker {
    window_days: f64,
    window_ticks: u64,
    restore_bw_gb_day: f64,
    k_eff: usize,
    blocks: Vec<TrackedBlock>,
    n_victims: usize,
    first_disaster_tick: Option<u64>,
}

impl RestoreTracker {
    /// A fresh tracker for one seed. Reads the restore knobs from [`WorldParams`] and
    /// `k_eff` from the engine dials. `W` days → whole ticks via `DAYS_PER_TICK`.
    pub fn new(world_params: &WorldParams) -> Self {
        let window_ticks = (world_params.restore_window_days / DAYS_PER_TICK).round() as u64;
        RestoreTracker {
            window_days: world_params.restore_window_days,
            window_ticks: window_ticks.max(1),
            restore_bw_gb_day: world_params.restore_bw_gb_day,
            k_eff: world_params.base.k_eff,
            blocks: Vec::new(),
            n_victims: 0,
            first_disaster_tick: None,
        }
    }

    /// Whether any disaster was recorded (⇒ restore-truth is meaningful for this run).
    pub fn is_active(&self) -> bool {
        self.first_disaster_tick.is_some()
    }

    /// Record a Disaster on `victim` (of demand `class`) at `disaster_tick`. Snapshots the
    /// victim's blocks that EVER met their floor (the denominator — a never-fully-backed-up
    /// block is not a restore failure). Call AFTER [`disaster_strike`](crate::sim_dynamic::
    /// engine::disaster_strike): it reads `floor_ever_met` / ι / tier, all untouched by the strike.
    pub fn on_disaster(
        &mut self,
        world: &World,
        victim: usize,
        disaster_tick: u64,
        class: DemandClass,
    ) {
        self.n_victims += 1;
        self.first_disaster_tick = Some(match self.first_disaster_tick {
            Some(t) => t.min(disaster_tick),
            None => disaster_tick,
        });
        let return_tick = disaster_tick + 1;
        let tier = world.nodes[victim].disk.tier;
        for b in &world.nodes[victim].own_blocks {
            if !b.floor_ever_met {
                continue;
            }
            self.blocks.push(TrackedBlock {
                owner: victim,
                block_id: b.id,
                iota: b.iota,
                tier,
                class,
                return_tick,
                collectable: BTreeMap::new(),
                collectable_oneshot: BTreeMap::new(),
            });
        }
    }

    /// Observe re-collectability at `tick` for every tracked block whose window covers it
    /// (`return_tick ≤ tick < return_tick + window_ticks`). A symbol is grabbed the first
    /// time its holder is present, still holds it alive, and is online. Call at the TOP of
    /// the loop for `tick` (before `step`), so the state is "as tick `tick` begins".
    pub fn observe(&mut self, world: &World, tick: u64) {
        for tb in self.blocks.iter_mut() {
            if tick < tb.return_tick || tick >= tb.return_tick + self.window_ticks {
                continue;
            }
            // F4 (D7): the FIRST window tick also feeds Model O (one-shot).
            let is_first = tick == tb.return_tick;
            for (holder, node) in world.nodes.iter().enumerate() {
                if !node.present {
                    continue;
                }
                if tb.collectable.contains_key(&holder) {
                    continue; // already grabbed on an earlier window tick (Model U)
                }
                // Routed through `node_online` so a phase-2a uptime profile gates restore
                // transport too (a ragged/seasonal holder is reachable less often in the window);
                // falls through to the exact `online` on the honest path.
                let sym = node
                    .holdings
                    .iter()
                    .find(|s| s.alive && s.owner == tb.owner && s.block == tb.block_id)
                    .filter(|_| world.node_online(holder, tick));
                if let Some(s) = sym {
                    let c = Collectable {
                        cream: s.cream,
                        volume: s.volume,
                    };
                    tb.collectable.insert(holder, c);
                    // Model O: only holders reachable at the FIRST tick count.
                    if is_first {
                        tb.collectable_oneshot.insert(holder, c);
                    }
                }
            }
        }
    }

    /// Finalise into a [`RestoreTruth`]. Computes Model U / durability-floor per block,
    /// then Model S per victim (a greedy, importance-first, bandwidth-bounded restore).
    pub fn finalize(self) -> RestoreTruth {
        let k_eff = self.k_eff;
        // Per-block Model U + durability-floor.
        let mut rows: Vec<BlockOutcome> = self
            .blocks
            .iter()
            .map(|tb| {
                let n_any = tb.collectable.len();
                let n_floor = tb.collectable.values().filter(|c| !c.cream).count();
                let n_oneshot = tb.collectable_oneshot.len();
                BlockOutcome {
                    owner: tb.owner,
                    block_id: tb.block_id,
                    iota: tb.iota,
                    tier: tb.tier,
                    class: tb.class,
                    n_collectable_any: n_any,
                    n_collectable_floor: n_floor,
                    n_collectable_oneshot: n_oneshot,
                    restorable_u: n_any >= k_eff,
                    restorable_s: false, // filled below
                    restorable_o: n_oneshot >= k_eff,
                    restorable_floor: n_floor >= k_eff,
                }
            })
            .collect();

        // Model S: per victim, a total-download budget over the window. Restore blocks
        // greedily by importance (ι desc, block-id asc). A block costs the k_eff SMALLEST
        // collectable symbol volumes (uniform in 0.2, hetero-ready for 0.4). A block that
        // does not fit is SKIPPED (a cheaper later block may still fit — knapsack-greedy).
        let victims: Vec<usize> = {
            let mut v: Vec<usize> = self.blocks.iter().map(|b| b.owner).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        for victim in victims {
            let budget = if self.restore_bw_gb_day > 0.0 {
                self.restore_bw_gb_day * self.window_days
            } else {
                f64::INFINITY
            };
            let mut remaining = budget;
            // The victim's tracked blocks in importance-first order (ι desc, id asc).
            let mut order: Vec<usize> = (0..self.blocks.len())
                .filter(|&i| self.blocks[i].owner == victim)
                .collect();
            order.sort_by(|&a, &b| {
                self.blocks[b]
                    .iota
                    .total_cmp(&self.blocks[a].iota)
                    .then(self.blocks[a].block_id.cmp(&self.blocks[b].block_id))
            });
            for i in order {
                let tb = &self.blocks[i];
                if tb.collectable.len() < k_eff {
                    continue; // not even Model-U-restorable → never Model-S-restorable
                }
                let mut vols: Vec<f64> = tb.collectable.values().map(|c| c.volume).collect();
                vols.sort_by(|a, b| a.total_cmp(b));
                let cost: f64 = vols.iter().take(k_eff).sum();
                if remaining >= cost {
                    remaining -= cost;
                    rows[i].restorable_s = true;
                }
            }
        }

        RestoreTruth {
            disaster_tick: self.first_disaster_tick.unwrap_or(0),
            window_days: self.window_days,
            window_ticks: self.window_ticks,
            restore_bw_gb_day: self.restore_bw_gb_day,
            n_victims: self.n_victims,
            k_eff,
            blocks: rows,
            info_model: "none",
        }
    }
}
