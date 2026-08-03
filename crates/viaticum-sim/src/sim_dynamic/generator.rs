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
use crate::sim_adv::scenario::AdvRole;
use crate::sim_adv::uptime::UptimeProfile;

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
    online_with_u(online_prob(archetype, tick), node_id, tick, run_seed)
}

/// The archetype-agnostic core of [`online`]: draw the per-tick online Bernoulli on the
/// `ONLINE_TAG` stream and compare against an EXPLICIT per-day uptime threshold `u_online`
/// (design axis 3 / phase-2a uptime profiles). Factoring the threshold out lets an opt-in
/// [`UptimeProfile`] drive the same draw with a structural per-tick `u` WITHOUT a new RNG
/// stream. `online(archetype, ..)` passes `online_prob(archetype, tick)`, so it is byte-
/// identical to the pre-profile code (one `rng.unit()` compared to the same threshold).
pub fn online_with_u(u_online: f64, node_id: u64, tick: u64, run_seed: u64) -> bool {
    let mut rng = Rng::derive(run_seed, ONLINE_TAG, node_id, tick, 0);
    rng.unit() < u_online
}

/// A tag for the calendar RNG stream so it cannot collide with the PoS stream
/// (which uses a different first key — the owner index).
const ONLINE_TAG: u64 = 0x0C0A_1E11_0A1D_0E11;

/// The per-tick online PROBABILITY `u` the [`online`] Bernoulli compares against for
/// `archetype` at `tick` (its threshold `u`). Mirrors [`online`] EXACTLY — it is the
/// same `u` that feeds `holder_online`, so [`surfaced_in_window`] can lift it to a
/// 7-day window probability without duplicating the calendar logic (F1 / D2).
pub fn online_prob(archetype: Archetype, tick: u64) -> f64 {
    match archetype {
        Archetype::Weekend => {
            if (tick % 7) >= 4 {
                0.95
            } else {
                0.30
            }
        }
        Archetype::Seasonal => {
            let month = (tick % TICKS_PER_YEAR) * 12 / TICKS_PER_YEAR;
            if (5..=7).contains(&month) { 0.20 } else { 0.95 }
        }
        Archetype::Nomad => 0.50,
        other => other.base_uptime(),
    }
}

/// F1 (D2 / rebase §6): did node `node_id` of `archetype` SURFACE at least once during
/// the 7-day PoS window ending at `tick`? PoS forgives a whole week — a live symbol
/// PASSES iff its holder came online on ANY of the ~7 iid days of the challenge-TTL
/// window, so the window-surfacing probability is `p_w = 1 − (1 − u)^7` where
/// `u = online_prob(archetype, tick)` is the per-tick daily uptime.
///
/// **Composed WITH the per-tick physics (rebase §6, mandatory).** So "online now ⇒
/// surfaced" holds and the transport/restore physics of the tick is untouched, we return
/// `online(..) ∨ extra`, where `extra` is a SEPARATE seeded Bernoulli with
/// `p_extra = (p_w − u)/(1 − u)` on its own salted stream (independent of the `online`
/// draw). Then `P(surfaced) = u + (1 − u)·p_extra = p_w` exactly. Guard: `u ≥ 1` ⇒ always
/// surfaced (the holder is always online, no extra draw). The extra draw is taken ONLY
/// when the holder is offline this tick, on the `SURFACE_TAG` stream, so it never perturbs
/// the `online`/PoS/churn/placement draws (determinism preserved).
pub fn surfaced_in_window(archetype: Archetype, node_id: u64, tick: u64, run_seed: u64) -> bool {
    surfaced_with_u(online_prob(archetype, tick), node_id, tick, run_seed)
}

/// The archetype-agnostic core of [`surfaced_in_window`]: the F1 window composition on an
/// EXPLICIT per-day uptime `u_online` (phase-2a uptime profiles). `surfaced_in_window(archetype,
/// ..)` passes `online_prob(archetype, tick)`, so it is byte-identical to the pre-profile code;
/// an opt-in [`UptimeProfile`] passes its structural `day_uptime` instead. Both draws ride the
/// EXISTING `ONLINE_TAG` (the "online now" check) + `SURFACE_TAG` (the extra window draw)
/// streams — no new RNG stream, so a profiled node perturbs nothing.
pub fn surfaced_with_u(u_online: f64, node_id: u64, tick: u64, run_seed: u64) -> bool {
    // "Online now ⇒ surfaced" — keep the per-tick physics.
    if online_with_u(u_online, node_id, tick, run_seed) {
        return true;
    }
    if u_online >= 1.0 {
        return true; // always online ⇒ always surfaces (guard, no draw)
    }
    let p_w = 1.0 - (1.0 - u_online).powi(7);
    // p_extra = (p_w − u)/(1 − u); clamp guards floating error at the edges.
    let p_extra = ((p_w - u_online) / (1.0 - u_online)).clamp(0.0, 1.0);
    let mut rng = Rng::derive(run_seed, SURFACE_TAG, node_id, tick, 0);
    rng.unit() < p_extra
}

/// Tag for the F1 window-surfacing extra-Bernoulli stream (distinct from [`ONLINE_TAG`]
/// so the extra draw is INDEPENDENT of the per-tick `online` draw — required for the
/// `P(surfaced) = p_w` composition — and off the PoS/churn/placement streams).
const SURFACE_TAG: u64 = 0x5E1F_AC1D_0B01_0A11;

/// Per-`(owner, holder)` capital state the harness evolves by the A.1 leaky law
/// inline (design §10.C): per-tick N² decay `g ← g·(1−λΔt)` + on-challenge accrual
/// `+v_conf·Δt` in `engine::pos_and_capital`. The STATE (running `G`, recent-outcome
/// window) lives here; the kernel `update_capital` (one Euler step) is unit-tested only.
#[derive(Debug, Clone)]
pub struct PairCapital {
    /// `G(O←h)`: this holder's service TO the owner (leaky integral of PoS-confirmed
    /// gb·days). The owner challenges; this rises only on a PASS.
    pub g_oh: f64,
    /// `G(h←O)`: the owner's service to the holder (the fast term of the eviction key
    /// the holder ranks on; bilaterally observable). The owner accrues this when it
    /// itself stores for the holder.
    pub g_ho: f64,
    /// `D` (A.4): the SLOW-leaky loyalty depth of the SAME `g_ho` direction ("O served
    /// h"), on the `τ_slow ≈ 6-month` time constant. Fed the SAME confirmed `V_conf`
    /// as `g_ho` (a second, slower tap) and decayed for EVERY pair each tick (W2), it
    /// is the W10 floor term of the κ_O eviction key ([`viaticum_core::four_r::
    /// kappa_key`]). Default 0.0 — a fresh pair trusts no one.
    pub depth_ho: f64,
    /// `G(O←h)` from the PREVIOUS challenge tick — for the D-projection finite
    /// difference `trend_d = (g_now − g_prev)/dt`.
    pub g_oh_prev: f64,
    /// Demonstrated scale ratchet for this pair (max proven retained per-symbol
    /// volume). Rises on a pass, does not leak fast.
    pub v_dem: f64,
    /// `σ` (A.5): the owner-side SUSPICION state for this pair — a fast-forgetting
    /// (`1/μ ≈ 2 weeks ≪ 1/λ`) charge that JUMPS by `j_σ` on a confirmed SILENT loss of
    /// this owner's data (holder death/departure) and decays every tick (W2 sweep,
    /// [`viaticum_core::four_r::update_suspicion`]). Read into `FirstHandObs::scrutiny`.
    /// Default 0.0 — a fresh pair suspects no one.
    pub sigma: f64,
    /// C2FARM-3 (A.2): LEAKY count of ANNOUNCED drop events of this owner's data by this
    /// holder (a live-holder PRESSURE eviction / preemption victim — the protocol sends a
    /// DropNotice; a Р-7 cap-trim does NOT count, транше-4). Owner-side; read into
    /// `FirstHandObs::drop_ann` → `retained_depth` drop_frac. Incremented `+= 1.0` per
    /// event and DECAYED each tick by `1 − λ_drop·Δt` in the W2 sweep — "the system must
    /// forgive" (Ilya 2026-07-07), one drop is not an eternal penalty. Default 0.0.
    pub drop_ann: f64,
    /// C2FARM-3 (A.2): LEAKY count of SILENT drop events of this owner's data by this
    /// holder (holder death/departure — detected next tick, no notice). Owner-side; read
    /// into `FirstHandObs::drop_silent`; same `λ_drop` decay as `drop_ann`. Default 0.0.
    pub drop_silent: f64,
    /// Ring of recent PoS outcomes (true = pass) over the window — the P-projection
    /// `recent_rate_p` is the pass-fraction here.
    pub pos_window: Vec<bool>,
}

impl Default for PairCapital {
    fn default() -> Self {
        PairCapital {
            g_oh: 0.0,
            g_ho: 0.0,
            depth_ho: 0.0,
            g_oh_prev: 0.0,
            v_dem: 0.0,
            sigma: 0.0,
            drop_ann: 0.0,
            drop_silent: 0.0,
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
    /// God-view: is this a CREAM (over-the-target) symbol (world-v2 §9.3 / A.11)?
    /// Cream symbols are placed with the owner's LEFTOVER per-tick bandwidth once the block's
    /// R̂ has REACHED `r_target` (SIM-UNIFICATION: the gate was "the `n_symbols` floor count is
    /// full"); they are NOT counted in the non-cream floor-fill metrics. A cream symbol is the
    /// entry channel for a new pair: a stranger with an empty disk can be handed cream even
    /// before it has earned reciprocity.
    ///
    /// **The old "cream death never triggers repair" rule does NOT survive the unification**
    /// (deliberate): the owner's reliability estimate counts every live symbol — erasure decode
    /// reads any `k_eff` of them — so cream raises R̂ and its death lowers it. The floor/cream
    /// split is now a placement-BUDGET label (which phase paid for the symbol) plus metric
    /// bookkeeping, not a second class of reliability.
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
    /// Has this block EVER reached its reliability TARGET — the owner's own estimate
    /// `R̂ ≥ r_target` ([`crate::sim_dynamic::engine::block_r_hat`])? SIM-UNIFICATION
    /// renamed and re-based this flag: it was `floor_ever_met` ("EVER held `n_symbols`
    /// non-cream symbols"), an integer-count fact; it is now the reliability fact the
    /// daemon works with. Distinguishes an INITIAL backup (never met target → no detection
    /// latency, the owner knows it must place) from a REPAIR (met target, then a holder
    /// death dropped it below → the owner learns of the loss only via the PoS cadence, so
    /// under a latent-detection run the refill is delayed). Monotone false→true. It is also
    /// the DENOMINATOR of the evaluator reads ("data that was once durable"): restore-truth,
    /// floor-fill, decodability. God-view only.
    pub target_ever_met: bool,
    /// The tick this block was first OBSERVED below its reliability target in the CURRENT
    /// deficit episode (`None` when at/above target). Under latent detection the owner does
    /// not act on the deficit until a seeded, per-block cadence offset has elapsed since
    /// this tick — that phase spread is exactly what smears a synchronous holder-death shock
    /// across time. Reset to `None` the moment the target is met again. Inert when detection
    /// is instant. (SIM-UNIFICATION: was `floor_deficit_since`, keyed on the floor count.)
    pub target_deficit_since: Option<u64>,
    /// World-v3 restore-cycle (axis 8, sub-tranche 0.2): the block's SOURCE is lost — the
    /// owner suffered a `Disaster` (its disk, and with it the source data these symbols
    /// were encoded from, is gone). P1 premise: no source ⇒ no repair (the owner can no
    /// longer re-encode symbols), only RESTORE from the surviving network holders. While
    /// `true`, [`crate::sim_dynamic::engine::place_own_data`] skips this block entirely (it
    /// must NOT "repair" a source-less block). Default `false`; set only by
    /// [`crate::sim_dynamic::engine::disaster_strike`]. God-view only.
    pub to_restore: bool,
}

/// One symbol of an owner's block placed on a holder (god-view bookkeeping).
#[derive(Debug, Clone, Copy)]
pub struct BlockPlacement {
    /// God-view holder node index.
    pub holder: usize,
    /// Whether this placement is a CREAM (over-the-target) symbol (world-v2 §9.3).
    /// Mirrors [`HeldSymbol::cream`]. SIM-UNIFICATION: cream symbols count toward the
    /// R̂ target estimate like any other (one reliability currency), so a cream death CAN
    /// trigger repair now; the label survives as a placement-budget/metrics distinction
    /// (non-cream floor-fill reads, cream-phase accounting), not a repair-trigger split.
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
    /// World-v2 §9 / Р-7 (A.14) counter: how many times a HOLDER-SIDE VOLUME-CAP trim
    /// fired (a holder dropped an owner's excess parked volume above `V_ret = V_free +
    /// κ_O/c_recip`, транш 3b). Distinct from `preempt_count` (an accept-time swap) and
    /// from the pressure-relief drops; the cap trims are ALSO counted in `eviction_log`,
    /// so this is a SEPARATE tally of just the tariff-enforcement subset.
    pub cap_trim_count: usize,
    /// Repair-storm instrumentation (§7): the LAST tick's repair activity, overwritten
    /// by `engine::place_own_data` each tick. Lets a god-view diagnostic read the
    /// per-tick repair concurrency / demand the engine actually acted on (detection-
    /// gated), which the correlated-holder-death sweep compares against bandwidth.
    /// Inert for the other experiments (they never read it).
    pub repair_stat: RepairStat,
    /// A.2 (транше 4) diagnostic: cumulative count of ANNOUNCED burn events applied — one
    /// per live-holder drop of an owner's symbol (eviction / preemption victim). God-view
    /// tally, never a kernel input.
    pub burn_ann_count: usize,
    /// A.2 (транше 4) diagnostic: cumulative count of SILENT burn events applied — one per
    /// (owner, departed-holder) confirmed silent loss (holder churn), applied on the NEXT
    /// tick (PoS-detection latency). God-view tally.
    pub burn_silent_count: usize,
    /// A.2 (транше 4): silent-loss events QUEUED by `churn` at tick T and applied at the
    /// start of tick T+1's capital pass (the "detected on the next PoS round" latency).
    /// Each is an owner whose data a now-departed holder silently lost. Drained every tick.
    pub pending_silent_loss: Vec<SilentLoss>,
    /// F2 (D5): eviction NOTICES queued by `run_eviction` at tick T (a DropNotice sent,
    /// symbol still alive) and applied at the START of tick T+1 by `apply_pending_evictions`
    /// — the pressure/cap drops die one tick after they are noticed, so the b_ann head-start
    /// axis is finally exercised (`t_n = DAYS_PER_TICK`) and space frees at T+1 (the accepted
    /// one-tick latch lag). Drained (and re-filled) every tick.
    pub pending_evictions: Vec<PendingEviction>,
    /// R̂-CALIBRATION prediction log (transche 0.3) — a GOD-VIEW, METRIC-ONLY channel. At
    /// each successful placement the engine appends the block's forecast survival `R̂_wc`
    /// over the calibration horizon `H` ([`crate::sim_dynamic::engine::DynParams::pred_horizon_ticks`]).
    /// It is written by the engine but read ONLY by the sim_adv evaluator (Brier +
    /// reliability/resolution) — NEVER by any placement/eviction/PoS decision (anti-oracle:
    /// a first-hand decision cannot see its own future-scored forecast). Writes are gated by
    /// [`World::pred_log_enabled`] so the diagnostic path costs nothing when off (sim_diag),
    /// and consume NO RNG, so enabling the log leaves every decision bit-identical.
    pub pred_log: Vec<PredEntry>,
    /// Whether the engine appends to [`World::pred_log`] this run. `false` by default (the
    /// engine and sim_diag pay nothing); the sim_adv runner sets it `true` to collect the
    /// R̂-calibration dataset. Gating a metric channel, NOT a decision — every decision is
    /// bit-identical regardless of this flag (the anti-oracle regression asserts it).
    pub pred_log_enabled: bool,
    /// World-v3 phase-1 ADVERSARY layer (predator injection). `adv[i] = Some(role)` marks
    /// node `i` as an injected predator whose per-tick behaviour the engine consults via
    /// `role.hook` — a `fn(&AdvContext) -> AdvAction` that by construction CANNOT borrow
    /// `&World` (the anti-oracle boundary, spec §10 п.14). `None` for every honest node; an
    /// all-`None` layer is the byte-identical honest path — the engine's adv branches
    /// (`admit_offer` accept override, `churn` rejoin) are simply never taken.
    pub adv: Vec<Option<AdvRole>>,
    /// World-v3 phase-1 god-view tally: how many times node `i` has WHITEWASH-rejoined (A4
    /// identity burn). Instrumentation for the ROI/re-entry report only — never a kernel
    /// input. `0` for every node with no A4 role.
    pub adv_rejoin_count: Vec<usize>,
    /// World-v3 A2 (DropNotice-refuser): the fractional VOLUNTARY-DROP debt carried by node
    /// `i`. Each tick an A2 adversary owes `drop_frac · (its alive foreign holdings)` more
    /// drops; only the WHOLE part is dropped, the remainder accumulates here — so a small
    /// `drop_frac` still lands on sparse holdings over time (a deterministic accumulator, no
    /// RNG). `0.0` for every non-A2 node; never touched on the honest path (byte-identical).
    pub adv_drop_debt: Vec<f64>,
    /// World-v3 phase-2a UPTIME-PROFILE layer (axis 3): `uptime[i] = Some(profile)` gives node
    /// `i` a STRUCTURAL per-tick availability pattern (a P7 tier's 24/7 NAS / diurnal user /
    /// ragged phone) instead of its archetype's iid Bernoulli. `None` for every node on the
    /// pre-profile path — [`World::node_online`] / [`World::node_surfaced_in_window`] then fall
    /// through to the EXACT `online` / `surfaced_in_window` free functions, so an all-`None`
    /// layer is byte-identical to the honest anchor. Read ONLY by those two accessors (PoS
    /// surfacing + restore transport); it drives no other draw and is god-view (not a kernel
    /// input). Assigned opt-in by the sim_adv runner ([`crate::sim_adv::uptime::UptimeMix`]).
    pub uptime: Vec<Option<UptimeProfile>>,
}

/// One R̂-calibration prediction (transche 0.3) — a GOD-VIEW metric row, never a kernel
/// input. Logged at a successful placement: the block's forecast survival over the
/// calibration horizon `H`, to be scored against the realised outcome `H` ticks later.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PredEntry {
    /// The owner whose block was (incrementally) placed.
    pub owner: usize,
    /// The block id.
    pub block: usize,
    /// The tick the prediction was made at (placement tick). The outcome is read at
    /// `tick + H` (`H = DynParams::pred_horizon_ticks`).
    pub tick: u64,
    /// The node's OWN decision-horizon forecast `R̂_wc` = `estimate_block_survival` over the
    /// block's current holders (committed + the just-placed symbol) at the DECISION horizon
    /// `tau = DAYS_PER_TICK` — the same estimate the kernel selection acts on. In `[0, 1]`.
    pub r_hat: f64,
    /// Whether the block held ≥ `k_eff` symbols AT THIS forecast (`committed.len() + 1 ≥
    /// k_eff`). When FALSE this is a still-INCOMPLETE block: the A.9 convolution is a
    /// STRUCTURAL ZERO (fewer than `k_eff` symbols can never meet the threshold), so `r_hat`
    /// is a forced `0.0` regardless of holder quality — NOT a real forecast. The Brier judge
    /// (WARN-1) scores ONLY `floor_complete` rows; the incomplete population is reported as a
    /// separate structural-zero diagnostic (its forecast carries no information).
    pub floor_complete: bool,
}

/// A.2 (транше 4): one confirmed SILENT loss to apply next tick — the owner `O` whose
/// symbols the now-departed holder `h` lost, with the volume lost. Queued by `churn`
/// (tick T) and consumed by `pos_and_capital` (tick T+1) so the silent burn + σ jump
/// land on the "next PoS round" as the model's detection latency prescribes.
#[derive(Debug, Clone, Copy)]
pub struct SilentLoss {
    /// The owner whose data was silently lost.
    pub owner: usize,
    /// The departed holder that lost it.
    pub holder: usize,
    /// Volume (gb) of the owner's symbols lost = V_lost = V_held (a total loss, all of
    /// this owner's alive symbols on the holder died at departure).
    pub volume: f64,
}

/// F2 (D5): why a symbol was NOTICED for eviction at tick T (it dies at T+1 with the
/// DropNotice head-start). The kind selects the death-time treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictNoticeKind {
    /// A disk-pressure squeeze drop: a reliability signal — burns `g_oh` at `b_ann` with
    /// the `t_n = DAYS_PER_TICK` head-start (the b_ann axis finally exercised) and bumps
    /// the `drop_ann` retention counter.
    Pressure,
    /// A Р-7 volume-cap trim (V_ret excess): a predictable tariff — burn-EXEMPT and
    /// drop-counter-EXEMPT (транш-4 decision), only the tally + free-at-T+1 timing.
    CapTrim,
}

/// F2 (D5): a symbol NOTICED for eviction at tick T (a DropNotice was sent) that is still
/// ALIVE this tick and dies at T+1. Queued by `run_eviction` (tick T) and drained by
/// `apply_pending_evictions` at the START of tick T+1 — so the holder's disk frees one
/// tick late (the accepted one-tick latch lag) and the owner had a 7-day head-start
/// (`t_n = DAYS_PER_TICK`) to repair before the symbol actually vanished.
#[derive(Debug, Clone, Copy)]
pub struct PendingEviction {
    /// The holder that will drop the symbol.
    pub holder: usize,
    /// The owner whose symbol is dropped.
    pub owner: usize,
    /// The god-view block id of the dropped symbol.
    pub block: usize,
    /// Why it was noticed (drives the death-time burn/counter treatment).
    pub kind: EvictNoticeKind,
}

/// Per-tick repair activity the engine records during placement (repair-storm §7).
/// Reset at the start of each tick's placement pass and filled as the FLOOR phase
/// walks below-TARGET blocks. God-view instrumentation ONLY — never a kernel input.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepairStat {
    /// Distinct present owners that had ≥1 mature, below-target, DETECTED block this
    /// tick (i.e. actively repairing). The per-tick maximum of this over a run is the
    /// "peak concurrent repairers" — the synchronisation the storm hypothesis is about.
    pub owners_repairing: usize,
    /// **SIM-UNIFICATION: BLOCKS, not symbols.** How many mature blocks the detection gate
    /// exposed as below their reliability target this tick — the WIDTH of the repair front
    /// (companion to `owners_repairing`, which counts the owners behind it). The old
    /// `detected_deficit_symbols` (`Σ n_symbols − floor`) no longer exists as a quantity:
    /// the R̂ loop does not compute "how many symbols are missing" — it places one symbol,
    /// recomputes R̂, and stops when the target is met, so the symbol demand is DISCOVERED,
    /// not known up front.
    ///
    /// ⚠ This is a BLOCK count: never compare it against a bandwidth in SYMBOLS. The
    /// symbol-unit demand instrument is [`RepairStat::detected_demand_symbols_lb`].
    pub detected_blocks_below_target: usize,
    /// **The symbol-unit repair DEMAND, as a documented LOWER BOUND** (`Σ` over the same
    /// detected below-target blocks). Since the R̂ loop discovers the true width by placing,
    /// the demand is not known up front; what IS known at the block's entry state is that
    /// the loop must run at least
    ///
    /// ```text
    /// max(1, min_width − alive)   capped by   (n_symbols − floor)   [0 when the cap is full]
    /// ```
    ///
    /// iterations — at least one (the block IS below target), and at least enough to reach
    /// the daemon's minimum redundancy `min_width`, never more than the `n_symbols` spread
    /// cap allows. Summed over blocks this is a strict LOWER BOUND on the symbols the owners
    /// OWE this tick, in the SAME unit as the aggregate bandwidth ceiling — so
    /// `demand_lb > bandwidth` certainly means the true demand exceeded bandwidth, while
    /// `demand_lb ≤ bandwidth` does NOT prove it did not.
    /// Deliberately counted BEFORE the budget check (demand is what is owed, not what fit).
    ///
    /// ⚠ It is a lower bound on DEMAND, not on UPLOADS: when `try_place_one_symbol` finds no
    /// admissible holder, fewer symbols move than the bound. That direction is safe (it makes
    /// the demand-vs-bandwidth assert stricter), but do not read it as "symbols transferred".
    ///
    /// ⚠ **Two conservatisms stack, both toward "no cascade" (review WARN-2):** (1) only
    /// REPAIRS are counted (`is_repair && detected`) — initial backups and cream consume the
    /// same bandwidth budget and contribute nothing to this numerator; (2) the storm
    /// configuration it is measured in is bandwidth-RICH relative to the polygon default
    /// (`storm_config`: `block_volume = 8` ⇒ ~5 symbols/tick/owner, vs `DynParams::default`
    /// `block_volume = 50` / `k_eff = 2` ⇒ ~1). A "no bandwidth cascade" reading from this
    /// instrument therefore says nothing about the default bandwidth-starved polygon, where
    /// 93 % of established blocks sit below target by t130.
    pub detected_demand_symbols_lb: usize,
    /// Repair symbols actually PLACED this tick (a floor placement onto a block that
    /// had already met its target before — a genuine repair, not an initial backup).
    /// Bounded by the bandwidth budget BY CONSTRUCTION, so it measures what the network
    /// DID, never what it needed (that is `detected_demand_symbols_lb`).
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
    /// Is node `i` ONLINE at `tick`, honoring an opt-in [`UptimeProfile`] (phase-2a axis 3)?
    /// `uptime[i] == None` ⇒ the EXACT `online(archetype, ..)` free function (byte-identical to
    /// the pre-profile path); `Some(profile)` ⇒ the profile's structural `day_uptime` on the
    /// SAME `ONLINE_TAG` stream. The single first-hand availability accessor for restore
    /// transport (Model U/O collectability). God-view; drives no kernel decision.
    pub fn node_online(&self, i: usize, tick: u64) -> bool {
        match self.uptime.get(i).and_then(|o| *o) {
            None => online(self.nodes[i].archetype, self.nodes[i].id, tick, self.seed),
            Some(p) => online_with_u(
                p.day_uptime(self.nodes[i].id, tick),
                self.nodes[i].id,
                tick,
                self.seed,
            ),
        }
    }

    /// Did node `i` SURFACE at least once in the 7-day PoS window ending at `tick`, honoring an
    /// opt-in [`UptimeProfile`] (phase-2a axis 3)? `uptime[i] == None` ⇒ the EXACT
    /// `surfaced_in_window(archetype, ..)` (byte-identical); `Some(profile)` ⇒ the F1 window
    /// composition on the profile's `day_uptime`. The PoS-pass predicate the engine reads — a
    /// Seasonal pause LONGER than the window (`day_uptime == 0` for a run of weeks) finally MISSES
    /// PoS honestly, the whole point of the axis.
    pub fn node_surfaced_in_window(&self, i: usize, tick: u64) -> bool {
        match self.uptime.get(i).and_then(|o| *o) {
            None => surfaced_in_window(self.nodes[i].archetype, self.nodes[i].id, tick, self.seed),
            Some(p) => surfaced_with_u(
                p.day_uptime(self.nodes[i].id, tick),
                self.nodes[i].id,
                tick,
                self.seed,
            ),
        }
    }

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
