//! `sim_dynamic` generator — the hidden god-view world.
//!
//! This is the ONLY place ground-truth lives in the dynamic harness: the hidden
//! [`Archetype`] (drives behaviour, NEVER a kernel input), the per-node disk /
//! holdings / own-data state, and the per-`(owner, holder)` capital state the
//! harness threads through `update_capital`.
//!
//! Anti-oracle (design §1, §10): `archetype` is god-view only — it gates BEHAVIOUR
//! (a Hoarder really rejects offers, a Freeloader really withholds), and the
//! [`crate::sim_dynamic::observer`] never reads it. The calendar predicate is
//! **tick-indexed + seed-derived, never wall-clock** (the environment forbids
//! `Date.now` / wall-clock; design §10.A).

use crate::generator::Rng;

/// One simulated week per tick. The capital leak `1/λ` is months, so `λ·dt < 1`
/// holds with room (design §10.C: weekly ticks × months-λ keeps the discrete
/// Euler step monotone). Days per tick = 7.
pub const DAYS_PER_TICK: f64 = 7.0;

/// Ticks per simulated year (≈ 52 weeks). Used only by the calendar predicate to
/// derive a tick-indexed month, never a wall-clock date.
pub const TICKS_PER_YEAR: u64 = 52;

/// The six Phase-1 archetypes (design §3). Hidden god-view; drives BEHAVIOUR only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archetype {
    /// 99% uptime, accepts ~all, holds. The baseline "always good".
    Reliable,
    /// Predictably periodic: high uptime Fri–Sun, low Mon–Thu.
    Weekend,
    /// Calendar dips: online Sep–May, mostly offline in summer.
    Seasonal,
    /// Unpredictable seeded ON/OFF (~50%), but reliable while online.
    Nomad,
    /// High uptime, but accepts ≤0.2 and quickly evicts others' data
    /// (exploits its position — takes a slot, stores little).
    Hoarder,
    /// Takes, does not give: accepts ≤0.1, near-zero outbound service.
    Freeloader,
}

impl Archetype {
    /// All six, in canonical order (for population construction / iteration).
    pub const ALL: [Archetype; 6] = [
        Archetype::Reliable,
        Archetype::Weekend,
        Archetype::Seasonal,
        Archetype::Nomad,
        Archetype::Hoarder,
        Archetype::Freeloader,
    ];

    /// Probability this archetype ACCEPTS an incoming symbol offer (design §10.A).
    /// A behaviour dial in god-view, NOT a number in any formula. Hoarder ≤0.2,
    /// Freeloader ≤0.1; the cooperative archetypes ≈1.0.
    pub fn accept_rate(self) -> f64 {
        match self {
            Archetype::Reliable | Archetype::Weekend | Archetype::Seasonal | Archetype::Nomad => {
                1.0
            }
            Archetype::Hoarder => 0.2,
            Archetype::Freeloader => 0.1,
        }
    }

    /// Eviction aggression (design §10.A): the fraction of an alive holder's
    /// retained-depth that this archetype shaves off — Hoarder/Freeloader drop
    /// others' symbols early, so their EFFECTIVE keep-depth is reduced. Cooperative
    /// archetypes keep what they accepted (aggression 0).
    pub fn evict_aggression(self) -> f64 {
        match self {
            Archetype::Hoarder => 0.7,
            Archetype::Freeloader => 0.85,
            _ => 0.0,
        }
    }

    /// Baseline (calendar-independent) uptime probability, used by [`online`] for
    /// the archetypes whose schedule is a flat Bernoulli (Reliable, Hoarder,
    /// Freeloader). Weekend/Seasonal/Nomad override this with their calendar.
    pub fn base_uptime(self) -> f64 {
        match self {
            Archetype::Reliable => 0.99,
            Archetype::Weekend => 0.95,  // unused (calendar overrides)
            Archetype::Seasonal => 0.95, // unused (calendar overrides)
            Archetype::Nomad => 0.5,     // unused (calendar overrides)
            Archetype::Hoarder => 0.90,
            Archetype::Freeloader => 0.80,
        }
    }
}

/// Population mix (design §3 shares): how many of each archetype in a population of
/// `n`. Returns a vec of length `n` of archetypes, deterministic in `n`.
///
/// Shares: Reliable 40%, Weekend 20%, Seasonal 15%, Nomad 10%, Hoarder 10%,
/// Freeloader 5%. The last archetype absorbs the rounding remainder so the counts
/// always sum to exactly `n`.
pub fn population_mix(n: usize) -> Vec<Archetype> {
    let shares = [
        (Archetype::Reliable, 0.40),
        (Archetype::Weekend, 0.20),
        (Archetype::Seasonal, 0.15),
        (Archetype::Nomad, 0.10),
        (Archetype::Hoarder, 0.10),
        (Archetype::Freeloader, 0.05),
    ];
    let mut out = Vec::with_capacity(n);
    for (a, frac) in shares.iter().take(shares.len() - 1) {
        let count = (frac * n as f64).round() as usize;
        for _ in 0..count {
            out.push(*a);
        }
    }
    // The remainder goes to the last archetype (Freeloader) so the total is exact.
    while out.len() < n {
        out.push(shares[shares.len() - 1].0);
    }
    out.truncate(n);
    out
}

/// Deterministic calendar predicate: is node `node_id` of `archetype` ONLINE at
/// `tick`? (design §10.A). Tick-indexed and seed-derived — NEVER a wall-clock
/// date. The seed mixes `run_seed` and `node_id` so two nodes of the same
/// archetype have independent (but reproducible) Nomad/Bernoulli draws.
///
/// * Weekend: online on the "weekend" ticks (the last 3 of every 7-day week — but
///   ticks ARE weeks here, so we map within the year: a node is "weekend-active"
///   on ~3/7 of ticks via a tick-phase predicate, with high uptime there and low
///   uptime otherwise). Concretely Fri–Sun is modelled as `tick % 7 >= 4`.
/// * Seasonal: online Sep–May (≈ months 0..3 and 8..12 of a 12-month year derived
///   from `tick`), low uptime in summer (Jun–Aug).
/// * Nomad: seeded Bernoulli(0.5).
/// * else: Bernoulli(base_uptime).
pub fn online(archetype: Archetype, node_id: u64, tick: u64, run_seed: u64) -> bool {
    let mut rng = Rng::derive(run_seed, ONLINE_TAG, node_id, tick, 0);
    let u = rng.unit();
    match archetype {
        Archetype::Weekend => {
            // "Weekend" ticks: the high-uptime window. tick % 7 in {4,5,6} = Fri–Sun.
            let is_weekend = (tick % 7) >= 4;
            if is_weekend { u < 0.95 } else { u < 0.30 }
        }
        Archetype::Seasonal => {
            // Derive a tick-indexed month in [0,12). Summer = Jun,Jul,Aug = months 5,6,7.
            let month = (tick % TICKS_PER_YEAR) * 12 / TICKS_PER_YEAR;
            let is_summer = (5..=7).contains(&month);
            if is_summer { u < 0.20 } else { u < 0.95 }
        }
        Archetype::Nomad => u < 0.50,
        other => u < other.base_uptime(),
    }
}

/// A tag for the calendar RNG stream so it cannot collide with the PoS stream
/// (which uses a different first key — the owner index).
const ONLINE_TAG: u64 = 0x0C0A_1E11_0A1D_0E11;

/// Per-`(owner, holder)` capital state the harness threads through `update_capital`
/// (design §10.C). The kernel's `update_capital` is one Euler step; the STATE
/// (the running `G` and the recent-outcome window) lives here.
#[derive(Debug, Clone)]
pub struct PairCapital {
    /// `G(O←h)`: this holder's service TO the owner (leaky integral of PoS-confirmed
    /// gb·days). The owner challenges; this rises only on a PASS.
    pub g_oh: f64,
    /// `G(h←O)`: the owner's service to the holder (the eviction-priority key the
    /// holder ranks on; bilaterally observable). The owner accrues this when it
    /// itself stores for the holder.
    pub g_ho: f64,
    /// `G(O←h)` from the PREVIOUS challenge tick — for the D-projection finite
    /// difference `trend_d = (g_now − g_prev)/dt`.
    pub g_oh_prev: f64,
    /// Demonstrated scale ratchet for this pair (max proven retained per-symbol
    /// volume). Rises on a pass, does not leak fast.
    pub v_dem: f64,
    /// Ring of recent PoS outcomes (true = pass) over the window — the P-projection
    /// `recent_rate_p` is the pass-fraction here.
    pub pos_window: Vec<bool>,
}

impl Default for PairCapital {
    fn default() -> Self {
        PairCapital {
            g_oh: 0.0,
            g_ho: 0.0,
            g_oh_prev: 0.0,
            v_dem: 0.0,
            pos_window: Vec::new(),
        }
    }
}

/// How many recent PoS outcomes the window keeps for the P-projection.
pub const POS_WINDOW_LEN: usize = 8;

impl PairCapital {
    /// Push a PoS outcome onto the ring (bounded to [`POS_WINDOW_LEN`]).
    pub fn push_outcome(&mut self, passed: bool) {
        self.pos_window.push(passed);
        if self.pos_window.len() > POS_WINDOW_LEN {
            let excess = self.pos_window.len() - POS_WINDOW_LEN;
            self.pos_window.drain(0..excess);
        }
    }

    /// P-projection: pass-fraction over the recent window (design §10.C). Zero
    /// samples ⇒ 0.0 (no evidence yet).
    pub fn recent_rate_p(&self) -> f64 {
        if self.pos_window.is_empty() {
            return 0.0;
        }
        let passes = self.pos_window.iter().filter(|&&p| p).count();
        passes as f64 / self.pos_window.len() as f64
    }
}

/// One symbol a holder physically stores for some owner (god-view holding).
#[derive(Debug, Clone)]
pub struct HeldSymbol {
    /// God-view owner index of the symbol's owner.
    pub owner: usize,
    /// Which of the owner's own blocks this symbol belongs to (god-view block id).
    pub block: usize,
    /// Owner-declared importance ι (first-hand metadata — the holder DOES observe
    /// this; it is not an oracle).
    pub iota: f64,
    /// Per-symbol volume (gb) — what the holder is asked to keep.
    pub volume: f64,
    /// God-view: is this symbol still alive on the holder? Set false when the
    /// holder evicts it OR when the holder leaves the network (churn).
    pub alive: bool,
}

/// One of an owner's OWN data blocks to back up (god-view).
#[derive(Debug, Clone)]
pub struct OwnBlock {
    /// God-view block index (unique per owner).
    pub id: usize,
    /// Total block volume (gb).
    pub volume: f64,
    /// Owner-declared importance ι for this block's symbols.
    pub iota: f64,
    /// God-view: the holders currently storing a symbol of this block, as
    /// `(holder_node_idx, symbol_alive)`. Repair refills this toward `r_target`.
    pub placements: Vec<BlockPlacement>,
}

/// One symbol of an owner's block placed on a holder (god-view bookkeeping).
#[derive(Debug, Clone, Copy)]
pub struct BlockPlacement {
    /// God-view holder node index.
    pub holder: usize,
}

/// A node in the dynamic world — god-view state.
#[derive(Debug, Clone)]
pub struct Node {
    /// Stable god-view id (used to key deterministic RNG streams).
    pub id: u64,
    /// Hidden archetype (god-view — drives behaviour, NEVER a kernel input).
    pub archetype: Archetype,
    /// Disk capacity (gb) for FOREIGN holdings.
    pub disk_cap: f64,
    /// Symbols this node currently stores for OTHERS (its holdings).
    pub holdings: Vec<HeldSymbol>,
    /// This node's OWN data blocks to back up.
    pub own_blocks: Vec<OwnBlock>,
    /// Address subnet bucket (the §7 spread key; first-hand observable).
    pub addr_subnet: u32,
    /// Master id byte (the alternative §7 spread key; first-hand observable).
    pub master_byte: u8,
    /// Per-tick eviction relay latch (design §10.G — threaded through ticks).
    pub evict_phase: viaticum_core::four_r::EvictPhase,
    /// Whether the node is currently present in the network (churn). A node that
    /// has left is skipped as a holder/candidate; its held symbols are marked dead.
    pub present: bool,
    /// The tick this node JOINED (so the newcomer probe can measure T_boot from
    /// the node's own arrival).
    pub joined_tick: u64,
}

impl Node {
    /// Used foreign-holdings disk (gb): sum of ALIVE held-symbol volumes.
    pub fn used_disk(&self) -> f64 {
        self.holdings
            .iter()
            .filter(|h| h.alive)
            .map(|h| h.volume)
            .sum()
    }

    /// `φ_node = 1 − used/cap` ∈ [0,1] (design §10.G; = `NodeLocal::phi_free_ratio`).
    pub fn phi_free_ratio(&self) -> f64 {
        if self.disk_cap <= 0.0 {
            return 0.0;
        }
        (1.0 - self.used_disk() / self.disk_cap).clamp(0.0, 1.0)
    }
}

/// The whole hidden god-view world.
#[derive(Debug, Clone)]
pub struct World {
    /// All nodes (present or departed — `Node::present` gates participation).
    pub nodes: Vec<Node>,
    /// The run seed — every deterministic draw keys off this.
    pub seed: u64,
    /// The current tick.
    pub tick: u64,
    /// Per-`(owner, holder)` capital state, indexed `[owner][holder]`. A dense
    /// matrix is fine at Exp-1 scale (~200 nodes); only touched pairs are nonzero.
    pub capital: Vec<Vec<PairCapital>>,
    /// Monotone block-id counter per owner (so a repaired/new block gets a fresh id).
    pub next_block_id: Vec<usize>,
    /// God-view served-volume TIME-INTEGRAL, indexed `[holder][owner]` (design §10.E).
    /// Each tick, for every (owner O, holder P) where P PASSED PoS on one of O's
    /// symbols that tick, the symbol's volume is added to `served[P][O]`. This is the
    /// integral of PoS-confirmed retained bytes OVER TIME (god-view ground truth, NOT
    /// the `G`-ledger), the load-bearing input for reciprocity metric (b). Grown with
    /// the node count when the newcomer joins. Monotone non-decreasing per cell.
    pub served: Vec<Vec<f64>>,
    /// Time-series of Freeloader-vs-Reliable INBOUND served volume (design §10.E
    /// "decay observable"). Each entry is `(tick, mean_freeloader_inbound,
    /// mean_reliable_inbound)`, sampled every `SERVED_SAMPLE_EVERY` ticks (and at the
    /// regime boundaries). Inbound(P) = Σ_O served[O][P] = data of P's OWN backups
    /// others retained-and-confirmed for P. A Freeloader's inbound should shrink
    /// relative to Reliable's across regimes if H3 bites.
    pub served_series: Vec<ServedSample>,
    /// Snapshot of `served` taken at the end of Regime-1 (design §10.E): the
    /// reciprocity balance is measured on the Regime-2 WINDOW integral
    /// (`served_now − served_regime1_end`), so the fill regime's accumulation does
    /// not swamp the steady-state signal. `None` until the boundary is reached.
    pub served_regime1_snapshot: Option<Vec<Vec<f64>>>,
}

/// One sample of the Freeloader-vs-Reliable inbound served-volume time-series
/// (design §10.E). Captured at regime boundaries and every `SERVED_SAMPLE_EVERY`
/// ticks so the relative decay (or its absence) is directly observable.
#[derive(Debug, Clone, Copy)]
pub struct ServedSample {
    /// The tick at which this sample was taken.
    pub tick: u64,
    /// Mean inbound served volume (integral so far) across Freeloader nodes.
    pub freeloader_inbound: f64,
    /// Mean inbound served volume (integral so far) across Reliable nodes.
    pub reliable_inbound: f64,
}

/// Sample the inbound-served time-series every this many ticks (plus always at the
/// two regime boundaries). Small enough to see a trend at Exp-1 horizon (~130 ticks).
pub const SERVED_SAMPLE_EVERY: u64 = 10;

impl World {
    /// Mean INBOUND served-volume integral across all nodes of `arch` (design §10.E):
    /// for owner P of archetype `arch`, inbound(P) = Σ_O `served[O][P]` (the running
    /// integral of P's OWN data that holders retained-and-PoS-confirmed). Returns the
    /// mean over the present nodes of that archetype (NaN if none).
    pub fn mean_inbound_served(&self, arch: Archetype) -> f64 {
        let n = self.nodes.len();
        let mut sum = 0.0;
        let mut cnt = 0usize;
        for p in 0..n {
            if self.nodes[p].archetype != arch {
                continue;
            }
            // Inbound = column p of `served` (sum over holders O of served[O][p]).
            let inbound: f64 = (0..n).map(|o| self.served[o][p]).sum();
            sum += inbound;
            cnt += 1;
        }
        if cnt == 0 { f64::NAN } else { sum / cnt as f64 }
    }

    /// Append a [`ServedSample`] of the current Freeloader-vs-Reliable inbound served
    /// integral to `served_series` (design §10.E decay observable).
    pub fn sample_served_series(&mut self) {
        let tick = self.tick;
        // Idempotent on a tick: a boundary sample taken on a tick that was already a
        // periodic sample must not duplicate the entry.
        if self.served_series.last().is_some_and(|s| s.tick == tick) {
            return;
        }
        let freeloader_inbound = self.mean_inbound_served(Archetype::Freeloader);
        let reliable_inbound = self.mean_inbound_served(Archetype::Reliable);
        self.served_series.push(ServedSample {
            tick,
            freeloader_inbound,
            reliable_inbound,
        });
    }
}
