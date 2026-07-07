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
/// 0.1 needs only the node count and the base dials (`honest_v2` replays the v2
/// acceptance defaults). Restore/volume-class extensions come in 0.2 / 0.4.
#[derive(Debug, Clone)]
pub struct WorldParams {
    /// Node count for `build_world`.
    pub n_nodes: usize,
    /// The engine dials (block volume, reciprocal placement, world-v2 toggles, ...).
    pub base: DynParams,
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

/// How an event selects its victim node(s) (design §4).
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
/// TYPE. It carries ONLY the predator's own node index, the current tick and its
/// DECLARED info-model. It deliberately does NOT (and cannot) borrow `&World`: a
/// predator decides from first-hand pair state + its info-model, never god-view. 0.1
/// fixes this shape so no phase-1 predator can smuggle a `&World` in (spec §10 п.14).
#[derive(Debug, Clone, Copy)]
pub struct AdvContext {
    /// The predator's own god-view node index (identity only — NOT a god-view read).
    pub adv_node: usize,
    /// The current tick.
    pub tick: u64,
    /// The predator's declared information model.
    pub info_model: InfoModel,
}

/// What a predator hook returns for a tick. Skeleton in 0.1 (only `NoOp`); phase-1
/// enriches with drop/park/accept actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvAction {
    /// Do nothing this tick (the only 0.1 action).
    NoOp,
}

/// The predator behaviour-override signature. By construction it takes ONLY an
/// [`AdvContext`] (first-hand) and never `&World` — this is the compile-time half of the
/// anti-oracle guarantee for predators (the other half is the one-way crate edge that
/// keeps the kernel blind). Phase-1 predators are `fn`s of this exact shape.
pub type BehaviorHook = fn(&AdvContext) -> AdvAction;
