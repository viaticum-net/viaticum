//! Scenario definition types (design `4r_world_v3_detail.md` §4 skeleton).
//!
//! A scenario is a Rust struct in the registry (convention "no magic": not a DSL /
//! toml parser). These types are the vocabulary the registry, runner and report share.
//!
//! ## Alignment with the real engine (deviations from the detail §4 sketch)
//!
//! The §4 sketch lists `uptime: Vec<UptimeProfile>` and `topology: TopologySpec` fields
//! and a `volume_classes` / `restore_window` on `WorldParams`. Those reference physics
//! that does NOT exist in the engine yet (uptime profiles = axis 3, topology = axis 4,
//! volume classes = axis 1, restore window = axis 8). Adding them now would be dead
//! "for-the-future" structure (against the crate conventions), so 0.1 carries ONLY what
//! it consumes; the restore-collection model returns with its own 0.2 tranche instead of
//! sitting here unread. See the 0.1 report for the full list.

use crate::sim_adv::verdict::Invariant;
use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, GiverTier};

/// Newtype id of a registered scenario (hard-coded like `Archetype::ALL`, so a
/// `&'static str` is the natural carrier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioId(pub &'static str);

impl ScenarioId {
    /// The bare name (for CLI matching and CSV/report headers).
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ScenarioId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The world the scenario builds. A superset wrapper over the engine [`DynParams`]:
/// the node count + base dials (`honest_v2` replays the v2 acceptance defaults), plus the
/// restore-cycle knobs the 0.2 restore-truth evaluator reads. Volume-class extensions
/// come in 0.4.
///
/// The restore knobs live HERE (not on [`DynParams`]) on purpose: restore-truth is an
/// EVALUATOR-layer god-view measurement (cold re-collection after a Disaster), NOT engine
/// physics — the honest engine never reads them, so they cannot leak into a node decision.
#[derive(Debug, Clone)]
pub struct WorldParams {
    /// Node count for `build_world`.
    pub n_nodes: usize,
    /// The engine dials (block volume, reciprocal placement, world-v2 toggles, ...).
    pub base: DynParams,
    /// Restore window `W` in DAYS (design §4 п.1 / spec §10 п.9): the cold-restore
    /// horizon after a Disaster. Default 14 days = 2 weekly ticks (`DAYS_PER_TICK = 7`).
    pub restore_window_days: f64,
    /// Model-S restore download budget in GB/DAY (spec §10 п.9, WARN-3): the victim can
    /// re-collect at most `restore_bw_gb_day × restore_window_days` GB over the window.
    /// **OPEN calibration guess: 50 GB/day** (~4.6 Mbps sustained) — generous enough that
    /// the small-uniform honest world is bandwidth-UNconstrained (Model S ≈ Model U there,
    /// which is honest: 10 GB symbols on a broadband downlink are not the bottleneck);
    /// Model S is designed to BITE on the large archive blocks of the 0.4 hetero world
    /// (WARN-3: Model U is optimistic exactly on the T1/archive DR-primary tier). Flagged
    /// for Ilya. `≤ 0` disables the budget (Model S ≡ Model U).
    pub restore_bw_gb_day: f64,
}

/// The full scenario (registry entry).
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Stable id (CLI name).
    pub id: ScenarioId,
    /// One-line human description for the report header.
    pub about: &'static str,
    /// The world to build.
    pub world: WorldParams,
    /// The DECLARED archetype mix (shares, Σ≈1). 0.1 `honest_v2` uses the engine's
    /// canonical `build_world` mix, so this documents that mix for the report; custom
    /// population INJECTION into `build_world` is a later tranche.
    pub population: Vec<(Archetype, f64)>,
    /// The DECLARED giver-tier mix (shares, Σ≈1). Same status as `population`.
    pub tiers: Vec<(GiverTier, f64)>,
    /// Predators (empty in 0.1 — the honest baseline).
    pub adversaries: Vec<AdvSpec>,
    /// Scripted, seeded events keyed by the tick they fire at. Executed as a NO-OP in
    /// 0.1 (dispatch skeleton only); real execution is 0.2+.
    pub events: Vec<(u64, Event)>,
    /// Run length in ticks (weekly ticks). `honest_v2` = 130 (the sim_diag horizon).
    pub horizon: u64,
    /// Default seed list (multi-seed is standard; single-seed numbers never headline).
    pub seeds: Vec<u64>,
    /// Which metrics this scenario reports (the vocabulary it draws from).
    pub metrics: Vec<MetricId>,
    /// The invariant board rows evaluated for this scenario.
    pub verdicts: Vec<Invariant>,
    /// Fast-mode member (prehook gate: ≤5 min, few seeds, horizon 120-ish).
    pub fast: bool,
}

/// A predator group in a scenario (design §4). Empty in 0.1.
#[derive(Debug, Clone)]
pub struct AdvSpec {
    /// Which zoo member (A1..A14).
    pub id: AdvId,
    /// How many such nodes.
    pub count: usize,
    /// The predator's declared information model.
    pub info_model: InfoModel,
    /// Per-adversary dials.
    pub dials: AdvDials,
}

/// The predator zoo id (design §3 / detail §2). The full vocabulary is fixed here;
/// bodies land phase 1+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvId {
    A1EpsilonWhale,
    A2DropRefuser,
    A3Flapper,
    A4Whitewasher,
    A5DeepSilent,
    A6Discriminator,
    A7SybilFarm,
    A8CollusionRing,
    A9EclipseTargeter,
    A10ProviderExit,
    A11SlowDegrade,
    A12Hostage,
    A13PosCheater,
    A14RepairBait,
}

impl AdvId {
    /// All fourteen, in canonical order (for validation / iteration).
    pub const ALL: [AdvId; 14] = [
        AdvId::A1EpsilonWhale,
        AdvId::A2DropRefuser,
        AdvId::A3Flapper,
        AdvId::A4Whitewasher,
        AdvId::A5DeepSilent,
        AdvId::A6Discriminator,
        AdvId::A7SybilFarm,
        AdvId::A8CollusionRing,
        AdvId::A9EclipseTargeter,
        AdvId::A10ProviderExit,
        AdvId::A11SlowDegrade,
        AdvId::A12Hostage,
        AdvId::A13PosCheater,
        AdvId::A14RepairBait,
    ];

    /// Short label for reports / CSV.
    pub fn label(self) -> &'static str {
        match self {
            AdvId::A1EpsilonWhale => "A1_epsilon_whale",
            AdvId::A2DropRefuser => "A2_drop_refuser",
            AdvId::A3Flapper => "A3_flapper",
            AdvId::A4Whitewasher => "A4_whitewasher",
            AdvId::A5DeepSilent => "A5_deep_silent",
            AdvId::A6Discriminator => "A6_discriminator",
            AdvId::A7SybilFarm => "A7_sybil_farm",
            AdvId::A8CollusionRing => "A8_collusion_ring",
            AdvId::A9EclipseTargeter => "A9_eclipse_targeter",
            AdvId::A10ProviderExit => "A10_provider_exit",
            AdvId::A11SlowDegrade => "A11_slow_degrade",
            AdvId::A12Hostage => "A12_hostage",
            AdvId::A13PosCheater => "A13_pos_cheater",
            AdvId::A14RepairBait => "A14_repair_bait",
        }
    }
}

/// The predator's information model (design §3; iii = god-view is FORBIDDEN and has no
/// variant here). `DrCard` is the single sanctioned god-view LEAK (CROWN-1) and affects
/// ONLY targeting/timing, never accept/evict — enforced by the [`BehaviorHook`] shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoModel {
    /// (i) First-hand only: the predator's own pairs + public info.
    Own,
    /// (ii) First-hand + a DR-card of victim `target`'s top holders (CROWN-1 leak,
    /// targeting/timing only).
    DrCard { target: usize },
}

/// Per-adversary dials (design §2). A single struct with all-adversary knobs (most
/// zero/ignored per predator) keeps the registry flat; predators read only their own.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdvDials {
    /// A1: own-block multiplier / ε-accept.
    pub whale_block_mult: f64,
    pub whale_accept: f64,
    /// A2: drop rate + whether a DropNotice is announced.
    pub drop_rate: f64,
    pub announce: bool,
    /// A3/A5: flap/vacation period + duty.
    pub period_ticks: u64,
    pub duty: f64,
    /// A7/A8/A9: group size + shared subnet.
    pub group_size: usize,
    pub group_subnet: u32,
    /// A11: creeping-degradation start tick + slope.
    pub degrade_start: u64,
    pub degrade_slope: f64,
}

/// A scripted world event (design §4). The vocabulary is fixed in 0.1; EXECUTION of
/// each (Disaster wiping a node, a subnet kill, ...) is phase 0.2+ — the 0.1 dispatcher
/// only RECORDS which event fired at which tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    /// Owner loses everything (source + holdings), returns without local data (axis 8).
    Disaster(NodeSel),
    /// Kill an entire subnet at once (axis 5).
    KillSubnet(u32),
    /// A provider's whole subnet exits after it has accumulated `after_share` (axis 5).
    ProviderExit { subnet: u32, after_share: f64 },
    /// A geo region goes down (axis 5).
    GeoCatastrophe(u16),
    /// A burst of `count` joiners arrives (axis 6).
    JoinWave { count: usize },
    /// Temporarily multiply churn for `window` ticks (axis 6).
    ChurnSpike { mult: f64, window: u64 },
    /// An owner replaces a block with fresh content, orphaning the old (axis 7).
    ContentChurn(NodeSel),
    /// A predator "wakes up" at this tick.
    AdvActivate(AdvId),
}

impl Event {
    /// The event's kind label, for the dispatch log / report / CSV.
    pub fn kind(self) -> EventKind {
        match self {
            Event::Disaster(_) => EventKind::Disaster,
            Event::KillSubnet(_) => EventKind::KillSubnet,
            Event::ProviderExit { .. } => EventKind::ProviderExit,
            Event::GeoCatastrophe(_) => EventKind::GeoCatastrophe,
            Event::JoinWave { .. } => EventKind::JoinWave,
            Event::ChurnSpike { .. } => EventKind::ChurnSpike,
            Event::ContentChurn(_) => EventKind::ContentChurn,
            Event::AdvActivate(_) => EventKind::AdvActivate,
        }
    }
}

/// The event kind (payload-free), used as the dispatch-log label so the skeleton is
/// testable without matching on payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Disaster,
    KillSubnet,
    ProviderExit,
    GeoCatastrophe,
    JoinWave,
    ChurnSpike,
    ContentChurn,
    AdvActivate,
}

impl EventKind {
    /// All eight kinds, in canonical order.
    pub const ALL: [EventKind; 8] = [
        EventKind::Disaster,
        EventKind::KillSubnet,
        EventKind::ProviderExit,
        EventKind::GeoCatastrophe,
        EventKind::JoinWave,
        EventKind::ChurnSpike,
        EventKind::ContentChurn,
        EventKind::AdvActivate,
    ];

    /// Short label.
    pub fn label(self) -> &'static str {
        match self {
            EventKind::Disaster => "disaster",
            EventKind::KillSubnet => "kill_subnet",
            EventKind::ProviderExit => "provider_exit",
            EventKind::GeoCatastrophe => "geo_catastrophe",
            EventKind::JoinWave => "join_wave",
            EventKind::ChurnSpike => "churn_spike",
            EventKind::ContentChurn => "content_churn",
            EventKind::AdvActivate => "adv_activate",
        }
    }
}

/// How an event selects its victim node(s) (design §4). Resolved against the built world
/// by [`crate::sim_adv::runner`] (each variant → concrete PRESENT node indices).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeSel {
    /// A specific node index.
    Index(usize),
    /// All nodes of an archetype.
    Archetype(Archetype),
    /// The top `frac` most-loaded holders.
    TopHolders(f64),
    /// `count` seeded-random nodes.
    Random(usize),
    /// The SINGLE EARLIEST-ESTABLISHED present node matching BOTH a giver tier and an
    /// archetype (empty if none) — resolved by `min_by(joined_tick)`, tie-broken by index
    /// (see `sim_adv::runner::resolve_nodesel`). The DR-primary selector: `dr_baseline`
    /// strikes one T1/Reliable node (the reliable backbone, the "Ilya's NAS" of the
    /// DR-primary doctrine).
    FirstTierArchetype(GiverTier, Archetype),
}

/// The measuring-layer metric vocabulary (design §4 / §3). 0.1 computes the subset that
/// exists on the honest baseline (extraction, decentralization-health snapshot, and the
/// invariant board); RestoreTruth/RhatCalibration/DetectLatency/AttackRoi/TierReport
/// arrive with their carrying tranches (0.2-0.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricId {
    RestoreTruth,
    Extraction,
    AttackRoi,
    RhatCalibration,
    DetectLatency,
    DecentHealth,
    TierReport,
    InvariantBoard,
}

impl MetricId {
    /// All eight, in canonical order.
    pub const ALL: [MetricId; 8] = [
        MetricId::RestoreTruth,
        MetricId::Extraction,
        MetricId::AttackRoi,
        MetricId::RhatCalibration,
        MetricId::DetectLatency,
        MetricId::DecentHealth,
        MetricId::TierReport,
        MetricId::InvariantBoard,
    ];

    /// Short label.
    pub fn label(self) -> &'static str {
        match self {
            MetricId::RestoreTruth => "restore_truth",
            MetricId::Extraction => "extraction",
            MetricId::AttackRoi => "attack_roi",
            MetricId::RhatCalibration => "rhat_calibration",
            MetricId::DetectLatency => "detect_latency",
            MetricId::DecentHealth => "decent_health",
            MetricId::TierReport => "tier_report",
            MetricId::InvariantBoard => "invariant_board",
        }
    }
}

// ============================================================
// Anti-oracle predator hook (spec §10 п.14 / WARN-5): the boundary as a TYPE.
// ============================================================

/// The first-hand context a predator hook may read — the anti-oracle boundary made a
/// TYPE. It carries the predator's own node index, the current tick, its DECLARED
/// info-model, its own strategy dials, and the tick its CURRENT identity joined — all
/// first-hand (a node knows its own strategy and its own join tick). It deliberately does
/// NOT (and cannot) borrow `&World`: a predator decides from first-hand pair state + its
/// info-model, never god-view. This shape (spec §10 п.14 / WARN-5) is what stops any
/// phase-1 predator smuggling a `&World` in.
#[derive(Debug, Clone, Copy)]
pub struct AdvContext {
    /// The predator's own god-view node index (identity only — NOT a god-view read).
    pub adv_node: usize,
    /// The current tick.
    pub tick: u64,
    /// The predator's declared information model.
    pub info_model: InfoModel,
    /// The predator's own strategy dials (first-hand: it knows its own plan).
    pub dials: AdvDials,
    /// The tick the predator's CURRENT identity joined (first-hand). A whitewasher measures
    /// its re-entry cadence from here (it resets on each identity burn).
    pub joined_tick: u64,
}

/// What a predator hook returns for a tick (phase 1: an ε-give accept override + a
/// whitewash-rejoin flag). A default [`AdvAction::NOOP`] is the honest / no-op action.
///
/// (0.1 carried only a `NoOp` sentinel; phase 1 enriches it with the two live levers the
/// A1/A4 predators need — the holder-side serve rate and the identity-burn self-exit.)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdvAction {
    /// Holder-side ε-give: the probability this adversary ACCEPTS an incoming symbol offer
    /// this tick, OVERRIDING the archetype rate. `None` ⇒ no override (archetype default).
    /// A1 returns `Some(ε)` — it serves almost nothing, so it earns almost no reciprocity
    /// κ_O and every holder caps its parked volume at ≈ V_free (Р-7).
    pub accept_rate: Option<f64>,
    /// A4 whitewash: at the END of this tick the adversary BURNS its identity — abandons
    /// everything it holds, orphans its own backed-up data, wipes its capital both ways, and
    /// re-enters next tick with a FRESH identity (κ_O = 0, new join tick). Models "burn
    /// reputation → new identity".
    pub rejoin: bool,
}

impl AdvAction {
    /// The honest / no-op action: no accept override, no rejoin.
    pub const NOOP: AdvAction = AdvAction {
        accept_rate: None,
        rejoin: false,
    };
}

impl Default for AdvAction {
    fn default() -> Self {
        AdvAction::NOOP
    }
}

/// The predator behaviour-override signature. By construction it takes ONLY an
/// [`AdvContext`] (first-hand) and never `&World` — this is the compile-time half of the
/// anti-oracle guarantee for predators (the other half is the one-way crate edge that
/// keeps the kernel blind). Phase-1 predators are `fn`s of this exact shape.
pub type BehaviorHook = fn(&AdvContext) -> AdvAction;

/// The per-node runtime adversary role the engine stores on the world (`World::adv[i]`) for
/// an injected predator. It bundles the predator's id, declared info-model, strategy dials
/// and behaviour hook — everything the engine needs to consult the hook at a decision point
/// (`admit_offer` / `churn`) WITHOUT ever handing it `&World`. `None` for every honest node,
/// so an all-`None` layer is the byte-identical honest path.
#[derive(Debug, Clone, Copy)]
pub struct AdvRole {
    /// Which zoo member (A1..A14).
    pub id: AdvId,
    /// The predator's declared information model.
    pub info_model: InfoModel,
    /// The predator's strategy dials.
    pub dials: AdvDials,
    /// The behaviour hook (`fn(&AdvContext) -> AdvAction`, no `&World`).
    pub hook: BehaviorHook,
}
