//! `sim_dynamic` generator — the hidden god-view world.
//!
//! This is the ONLY place ground-truth lives in the dynamic harness: the hidden
//! [`Archetype`] (drives behaviour, NEVER a kernel input), the per-node disk /
//! holdings / own-data state, and the per-`(owner, holder)` capital state the
//! harness evolves by the A.1 leaky law inline (per-tick N² decay + on-challenge
//! accrual, see `engine::pos_and_capital`; the kernel `update_capital` is unit-tested
//! separately, not called from the harness loop).
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
    /// High uptime, but accepts ≤0.2 (exploits its position — advertises a normal disk
    /// but takes few holdings) and departs at a higher rate (aggression → churn, §9.4).
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

    /// Eviction aggression ∈ [0,1] (world-v2 §9.4). Post-§3-fix this NO LONGER touches
    /// the PoS outcome (the old `retained_edge` shave is gone — PoS-pass ⟺ alive ∧
    /// online). Aggression now lives ONLY in churn: an aggressive archetype
    /// (Hoarder/Freeloader) departs at a higher rate, so its held symbols die sooner.
    /// Cooperative archetypes have aggression 0 (base churn, no PoS effect).
    pub fn evict_aggression(self) -> f64 {
        match self {
            Archetype::Hoarder => 0.7,
            Archetype::Freeloader => 0.85,
            _ => 0.0,
        }
    }

    /// Whether this archetype is WILLING to accept a foreign symbol offer at all
    /// (the behavioural will gate, design §A.3). The Hoarder/Freeloader withhold
    /// their disk by a low willingness; cooperative archetypes are willing. This is
    /// the BEHAVIOUR half of acceptance — the other half is physical room (`φ`/quota,
    /// the `SymbolReject{QuotaExceeded}`-equivalent): a node accepts iff WILLING AND
    /// HAS ROOM. Splitting the two is the §A.3 fidelity fix: the old engine had only
    /// the Bernoulli will and no disk check, so it never produced a quota reject.
    pub fn willing_accept_rate(self) -> f64 {
        self.accept_rate()
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

/// Giver tier (audience tier P7, design §A layer-2). ORTHOGONAL to [`Archetype`]:
/// the archetype is BEHAVIOUR (uptime + accept/evict strategy), the giver tier is
/// the node's DISK SHAPE (how much own data it has relative to free space it can
/// lend, and how fast its own data grows). A Freeloader×T1-loose is a pure parasite
/// (lots of free disk, withholds it); a Reliable×T4-tight is honest-but-poor (full
/// disk, would lend but cannot) — and the two are MORALLY INDISTINGUISHABLE (design
/// §A: motive-blind). The tier is GOD-VIEW ONLY: it drives behaviour/contention and
/// must NEVER reach a kernel input (no field for it on `FirstHandObs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiverTier {
    /// T1 — self-hosters / NAS / multi-device geeks. Loose own:free ratio (~2-3 free
    /// per own), slow own-data growth. The backbone givers (P7 core).
    T1,
    /// T2 — photo/video makers. Growing own data (own:free ~1-1.5), FAST growth (the
    /// main contention driver: media accumulates).
    T2,
    /// T3 — ordinary laptop users with some free space. Moderate own:free (~1.5-2),
    /// slow growth.
    T3,
    /// T4 — periphery: a single near-full device. Tight own:free (<1), ~static own
    /// data. May not fit its own backups → W11 triage (honest-parasite owner-side).
    T4,
}

impl GiverTier {
    /// All four, in canonical order (for population construction / iteration).
    pub const ALL: [GiverTier; 4] = [GiverTier::T1, GiverTier::T2, GiverTier::T3, GiverTier::T4];

    /// Centre of the own:LENDABLE-free ratio band for this tier (design §A): the
    /// ratio of OWN data to the disk a node leaves FREE to lend to others. Lower ⇒
    /// MORE lendable disk (a generous giver). The lendable free is where foreign
    /// holdings accumulate and contend; own-data growth slowly shrinks it. We keep
    /// own data a MINORITY of the disk so the contention plays out on the HOLDINGS
    /// budget (the reciprocal-storage economy), not by own-data drowning the disk.
    /// God-view: this shapes the disk, it is NOT a kernel input.
    pub fn own_to_free_centre(self) -> f64 {
        match self {
            // own:free = r ⇒ own = cap·r/(1+r). r=0.18 ⇒ own≈15% of cap (T1: lots to
            // lend); r=0.25 ⇒ own≈20%; r=0.22 ⇒ own≈18%; r=0.5 ⇒ own≈33% (T4: tight).
            // Own data starts a SMALL minority of the disk so Regime-1 has ample room
            // to establish the placement floor (≥ k_eff holders per block); own-data
            // GROWTH (below) then expands it and tightens the world into contention.
            GiverTier::T1 => 0.18,
            GiverTier::T2 => 0.25,
            GiverTier::T3 => 0.22,
            GiverTier::T4 => 0.50,
        }
    }

    /// Per-tick own-data linear growth rate as a FRACTION of the node's initial own
    /// data (design §A.2 growth law). T2 (media) grows fast; T1/T3 slow; T4 ~static.
    /// God-view calibration dial — sets the onset of contention. Sized so that over
    /// the ~130-tick run own data grows enough to push total utilization from the
    /// accept-gate parking level (≈1−s_soft) DOWN through the eviction band (φ<s_hard),
    /// firing eviction (the W9/W11 dynamic: growing own data rations foreign holdings).
    pub fn own_growth_frac_per_tick(self) -> f64 {
        match self {
            GiverTier::T1 => 0.010,
            GiverTier::T2 => 0.022,
            GiverTier::T3 => 0.013,
            GiverTier::T4 => 0.004,
        }
    }
}

/// Giver-tier mix over a population of `n` (design §A / P7 shares): T1 35%, T2 30%,
/// T3 25%, T4 10%. Deterministic in `n`; the last tier absorbs the rounding
/// remainder so the counts sum to exactly `n`.
///
/// Assigned INDEPENDENTLY of the archetype mix (the two layers are orthogonal): we
/// stride the tiers across the node index so a given archetype is spread across
/// tiers rather than correlated with one (a Reliable can be any tier).
pub fn giver_tier_mix(n: usize, seed: u64) -> Vec<GiverTier> {
    let shares = [
        (GiverTier::T1, 0.35),
        (GiverTier::T2, 0.30),
        (GiverTier::T3, 0.25),
        (GiverTier::T4, 0.10),
    ];
    let mut pool: Vec<GiverTier> = Vec::with_capacity(n);
    for (t, frac) in shares.iter().take(shares.len() - 1) {
        let count = (frac * n as f64).round() as usize;
        for _ in 0..count {
            pool.push(*t);
        }
    }
    while pool.len() < n {
        pool.push(shares[shares.len() - 1].0);
    }
    pool.truncate(n);
    // Deterministically shuffle so tier is uncorrelated with the archetype index
    // (the archetype mix is laid out in blocks; an unshuffled tier pool would
    // correlate tier with archetype). Reproducible in the seed.
    let mut rng = Rng::derive(seed, TIER_SHUFFLE_TAG, n as u64, 0, 0);
    for i in (1..pool.len()).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        pool.swap(i, j.min(i));
    }
    pool
}

/// Tag for the giver-tier shuffle RNG stream (kept off the PoS/online streams).
const TIER_SHUFFLE_TAG: u64 = 0x71E7_5A17_DEAD_BEEF;

/// Hard ceiling on own-data as a fraction of the physical disk (design §A.2): even
/// the fastest-growing tier keeps `1 − OWN_DATA_DISK_FRACTION` of the disk as a
/// lendable floor, so contention is on the HOLDINGS budget (the reciprocal-storage
/// economy eviction rations), not own data flooding the disk into a death-spiral.
pub const OWN_DATA_DISK_FRACTION: f64 = 0.62;

/// God-view disk profile of a node (design §A layer-2). Drives own-data growth and
/// the physical disk split; NEVER reaches a kernel input. The kernel only ever sees
/// the resulting scalar `φ = 1 − (own+holdings)/cap` (a legal `NodeLocal` field, my
/// own first-hand disk), never the tier / growth-rate / own:free target here.
#[derive(Debug, Clone, Copy)]
pub struct DiskProfile {
    /// The node's giver tier (god-view: shapes the disk, not a kernel input).
    pub tier: GiverTier,
    /// Current OWN-data volume on disk (gb). Grows over ticks (design §A.2). Own data
    /// consumes the SAME physical disk as foreign holdings — so as it grows, free
    /// space (`φ`) shrinks, driving the world toward contention.
    pub own_data: f64,
    /// Per-tick additive own-data growth (gb/tick), seeded from the tier's fractional
    /// rate at build time. Linear law (design §A.2: start linear, complicate only if
    /// the onset is unrealistic).
    pub own_growth_per_tick: f64,
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

/// Per-`(owner, holder)` capital state the harness evolves by the A.1 leaky law
/// inline (design §10.C): per-tick N² decay `g ← g·(1−λΔt)` + on-challenge accrual
/// `+v_conf·Δt` in `engine::pos_and_capital`. The STATE (running `G`, recent-outcome
/// window) lives here; the kernel `update_capital` (one Euler step) is unit-tested only.
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
    /// God-view: is this a CREAM (over-the-floor) symbol (world-v2 §9.3 / A.11)?
    /// Cream symbols are placed with the owner's LEFTOVER per-tick bandwidth once the
    /// block's `n_symbols` FLOOR is met; they are NOT counted in the floor-durability
    /// metric and their death does NOT trigger repair (the cream-no-mandatory-repair
    /// invariant). A cream symbol is the entry channel for a new pair: a stranger with
    /// an empty disk can be handed cream even before it has earned reciprocity.
    pub cream: bool,
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
    /// Repair-storm bookkeeping (§7): has this block EVER reached its `n_symbols`
    /// floor? Distinguishes an INITIAL backup (never met floor → no detection latency,
    /// the owner knows it must place) from a REPAIR (met floor, then a holder death
    /// dropped it below → the owner learns of the loss only via the PoS cadence, so
    /// under a latent-detection run the refill is delayed). God-view only.
    pub floor_ever_met: bool,
    /// Repair-storm bookkeeping (§7): the tick this block was first OBSERVED below its
    /// `n_symbols` floor in the CURRENT deficit episode (`None` when at/above floor).
    /// Under latent detection the owner does not act on the deficit until a seeded,
    /// per-block cadence offset has elapsed since this tick — that phase spread is
    /// exactly what smears a synchronous holder-death shock across time. Reset to
    /// `None` the moment the floor is restored. Inert when detection is instant.
    pub floor_deficit_since: Option<u64>,
}

/// One symbol of an owner's block placed on a holder (god-view bookkeeping).
#[derive(Debug, Clone, Copy)]
pub struct BlockPlacement {
    /// God-view holder node index.
    pub holder: usize,
    /// Whether this placement is a CREAM (over-the-floor) symbol (world-v2 §9.3).
    /// Mirrors [`HeldSymbol::cream`]; the floor-vs-cream split lets repair count only
    /// FLOOR placements toward `n_symbols` (cream deaths never trigger repair).
    pub cream: bool,
}

/// A node in the dynamic world — god-view state.
#[derive(Debug, Clone)]
pub struct Node {
    /// Stable god-view id (used to key deterministic RNG streams).
    pub id: u64,
    /// Hidden archetype (god-view — drives behaviour, NEVER a kernel input).
    pub archetype: Archetype,
    /// Total physical disk capacity (gb). SHARED between this node's own data and
    /// the foreign symbols it holds — `φ = 1 − (own+holdings)/cap`. Own-data growth
    /// eating into this is the load-bearing contention driver (design §A.2).
    pub disk_cap: f64,
    /// God-view disk profile (design §A layer-2): giver tier + own-data + growth
    /// rate. NEVER a kernel input — the kernel sees only the resulting `φ` scalar.
    pub disk: DiskProfile,
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
    /// Used FOREIGN-holdings disk (gb): sum of ALIVE held-symbol volumes. (Own data
    /// is tracked separately in [`DiskProfile::own_data`].)
    pub fn used_disk(&self) -> f64 {
        self.holdings
            .iter()
            .filter(|h| h.alive)
            .map(|h| h.volume)
            .sum()
    }

    /// Total physical occupancy (gb): own data + alive foreign holdings. This is
    /// what fills the shared disk (design §A.2: own-data growth shrinks free space).
    pub fn used_total(&self) -> f64 {
        self.disk.own_data + self.used_disk()
    }

    /// Free physical disk (gb): `cap − (own + holdings)`, floored at 0. The room a
    /// new foreign offer needs (design §A.3: accept iff willing AND this ≥ offered).
    pub fn free_disk(&self) -> f64 {
        (self.disk_cap - self.used_total()).max(0.0)
    }

    /// `φ_node = 1 − (own+holdings)/cap` ∈ [0,1] (design §10.G / §A.2; the legal
    /// `NodeLocal::phi_free_ratio` field — my OWN first-hand disk free-ratio). As own
    /// data grows this falls, driving the world toward contention (utilization→1).
    pub fn phi_free_ratio(&self) -> f64 {
        if self.disk_cap <= 0.0 {
            return 0.0;
        }
        (1.0 - self.used_total() / self.disk_cap).clamp(0.0, 1.0)
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
    /// Log of every eviction event (design §A / §D.1 drop-ranking + §E contention
    /// observability): each time a holder drops a foreign symbol under disk pressure,
    /// record `(tick, holder, evicted_owner)`. The drop-ranking metric correlates the
    /// evicted owner with LOW god-view `served(holder←owner)` (NOT the G-ledger — that
    /// would be tautological). Also the headline "eviction actually fired" signal.
    pub eviction_log: Vec<EvictionEvent>,
    /// Count of ticks on which ≥1 eviction fired anywhere in the network (design §E /
    /// §A acceptance: the % of ticks with eviction firing is a contention signal).
    pub ticks_with_eviction: u64,
    /// World-v2 §9 newcomer-entry trace, indexed by node. `first_earned_g[i]` = the
    /// FIRST tick node `i` earned reciprocity as a HOLDER (its `g_ho` with some peer
    /// first became > 0, i.e. it served someone and passed PoS). `None` until then.
    /// The newcomer-entry chain (§9 metric) is `joined_tick → first_earned_g →
    /// first_own_accept`; the middle→last gap is the θ_p/λ prediction.
    pub first_earned_g: Vec<Option<u64>>,
    /// World-v2 §9 newcomer-entry trace, indexed by node: the FIRST tick node `i` had
    /// one of its OWN symbols accepted by any holder. `None` until then.
    pub first_own_accept: Vec<Option<u64>>,
    /// World-v2 §9 counter: how many times a PREEMPTIVE swap fired (a contended holder
    /// admitted a higher-`g_ho` owner by displacing its least-reciprocal victim, §2 /
    /// A.12-2). The bootstrap-world value was ~0 ("starved, not frozen"); this counts
    /// whether the world-v2 physics lets preemption actually engage.
    pub preempt_count: usize,
    /// Repair-storm instrumentation (§7): the LAST tick's repair activity, overwritten
    /// by `engine::place_own_data` each tick. Lets a god-view diagnostic read the
    /// per-tick repair concurrency / demand the engine actually acted on (detection-
    /// gated), which the correlated-holder-death sweep compares against bandwidth.
    /// Inert for the other experiments (they never read it).
    pub repair_stat: RepairStat,
}

/// Per-tick repair activity the engine records during placement (repair-storm §7).
/// Reset at the start of each tick's placement pass and filled as the FLOOR phase
/// walks below-floor blocks. God-view instrumentation ONLY — never a kernel input.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepairStat {
    /// Distinct present owners that had ≥1 mature, below-floor, DETECTED block this
    /// tick (i.e. actively repairing). The per-tick maximum of this over a run is the
    /// "peak concurrent repairers" — the synchronisation the storm hypothesis is about.
    pub owners_repairing: usize,
    /// Total symbols owed to restore all detected below-floor mature blocks to their
    /// `n_symbols` floor this tick (the detection-gated repair DEMAND, in symbols).
    pub detected_deficit_symbols: usize,
    /// Repair symbols actually PLACED this tick (a floor placement onto a block that
    /// had already met its floor before — a genuine repair, not an initial backup).
    pub symbols_repaired: usize,
}

/// One god-view eviction event (design §D.1 drop-ranking / §E observability).
#[derive(Debug, Clone, Copy)]
pub struct EvictionEvent {
    /// The tick the drop happened.
    pub tick: u64,
    /// The holder that dropped a symbol under disk pressure.
    pub holder: usize,
    /// The owner whose symbol was dropped (the "victim" of the eviction).
    pub owner: usize,
    /// The reciprocity key `capital[owner][holder].g_ho` AT DROP TIME (the owner's
    /// service to this holder). Diagnostic only: lets a god-view tool check whether
    /// drops concentrate on `g_ho≈0` placements (the mechanism singling out
    /// non-reciprocal data) vs falling on reciprocal placements too.
    pub g_ho_at_drop: f64,
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

    /// Mean free-ratio `φ` over present nodes (design §A contention-front
    /// observability). As own-data growth + greedy accept fill disks this falls
    /// toward 0 (utilization→1). NaN if no present nodes.
    pub fn mean_phi(&self) -> f64 {
        let mut sum = 0.0;
        let mut cnt = 0usize;
        for node in &self.nodes {
            if node.present {
                sum += node.phi_free_ratio();
                cnt += 1;
            }
        }
        if cnt == 0 { f64::NAN } else { sum / cnt as f64 }
    }

    /// Mean utilization `1 − φ = (own+holdings)/cap` over present nodes — the direct
    /// "utilization→1" reading (design §A acceptance: the world must reach this).
    pub fn mean_utilization(&self) -> f64 {
        let phi = self.mean_phi();
        if phi.is_nan() { f64::NAN } else { 1.0 - phi }
    }

    /// Grow every present node's OWN data by its seeded per-tick rate (design §A.2
    /// growth law). Own data shares the physical disk with foreign holdings, so this
    /// monotonically shrinks free space (`φ`) and is the load-bearing driver of the
    /// drift to contention (utilization→1). Linear, deterministic, god-view only.
    ///
    /// Own data is capped at [`OWN_DATA_DISK_FRACTION`] of the physical disk so a
    /// node — even a fast-growing T2 — always retains SOME lendable disk floor (the
    /// contention plays out on the HOLDINGS budget, not by own data drowning the
    /// whole disk). Past the cap the node is simply at its own-data ceiling.
    pub fn grow_own_data(&mut self) {
        for node in &mut self.nodes {
            if !node.present {
                continue;
            }
            let ceiling = node.disk_cap * OWN_DATA_DISK_FRACTION;
            let next = node.disk.own_data + node.disk.own_growth_per_tick;
            node.disk.own_data = next.min(ceiling.max(node.disk.own_data));
        }
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
