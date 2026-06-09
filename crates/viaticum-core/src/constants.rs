// All tunable protocol constants in one place.
// β version — RaptorQ, continuous importance, configurable block size.

// === Time ===

/// Seconds in one week (7 * 24 * 60 * 60).
pub const SECS_PER_WEEK: u64 = 604_800;

// === Trust formula ===
// trust = (KP * P + KI * I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)
// P = 4-week rolling pass rate, I = cumulative mean, S = pairwise GB ratio.

/// Weight on P (4-week rolling window).
pub const KP: f64 = 0.4;

/// Weight on I (cumulative mean).
pub const KI: f64 = 1.75;

/// Rolling window length for P score (weeks).
pub const P_WINDOW_WEEKS: u32 = 4;

/// Initial P value for newly connected peers — neutral Bayesian prior.
/// A new peer has no PoS history yet; we treat them as 50/50 rather than
/// "minimally trusted" so they get a real shot at being chosen as a holder
/// during their first few hours, before their P score becomes evidence-based.
/// Without this they sit at the trust floor (~0.04 combined) and lose every
/// holder selection to peers with even one passed challenge — bootstrap fails.
pub const INITIAL_TRUST_P: f64 = 0.5;

/// S floor — even zero-storage peers get 10% trust multiplier.
pub const S_CLAMP_MIN: f64 = 0.1;

/// S ceiling.
pub const S_CLAMP_MAX: f64 = 1.0;

// === Escrow (contribution-based) ===

/// Days of storage contribution required to earn 1 GB of restore credit.
/// Formula: restore_budget_gb = stored_gb_days / k_factor.
/// Default K=7: store 1 GB for 7 days → earn 1 GB restore budget.
pub const DEFAULT_ESCROW_K_FACTOR: f64 = 7.0;

/// Days of storage contribution required to earn 1 GB of OFFER budget (backup credit).
/// Formula: earned_offer_gb = Σ(gb_days × master_trust / MAX_COMBINED_TRUST) / K_OFFER.
/// Smaller than restore-K (7) on purpose — we want self-awareness for fresh
/// owners (a node holding for the network a few days can back up its first
/// files), and offering cost is already inflated ×overhead_factor by the
/// caller. Set to 5 (tunable). Sybil mitigation logged in tech-debt.
pub const OFFER_EARN_K_FACTOR_DAYS: f64 = 5.0;

// === Budget floor (owner-side) ===

/// Owner-side budget floor: minimum GB offered even with zero committed storage.
/// Used by budget planner (not escrow). Ensures new nodes can start backing up.
pub const FREE_TIER_GB: f64 = 1.0;

// === Cooldown (ransomware protection) ===

/// Owner-side cooldown before sending delete message (seconds).
pub const OWNER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Holder-side cooldown after receiving delete before physical removal (seconds).
pub const HOLDER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Phase 2 disk pressure: notice window before holder drops symbols (seconds).
pub const DROP_NOTICE_WINDOW_SECS: u64 = 7 * 24 * 3600; // 7 days

// === Erasure coding (RaptorQ) ===

/// Default source block size in bytes (128 MB). Configurable via config.toml.
pub const DEFAULT_SOURCE_BLOCK_SIZE: u64 = 128 * 1024 * 1024;

/// Symbol size T in bytes. Fixed at ~64 KB (max for raptorq crate, u16 limit).
pub const SYMBOL_SIZE: u16 = 65_535;

/// Decode overhead: K_eff = K + DECODE_OVERHEAD.
pub const DECODE_OVERHEAD: u32 = 3;

/// Overhead formula: overhead = OVERHEAD_BASE + importance * OVERHEAD_SCALE.
/// Range: 1.5x (importance=0) to 3.0x (importance=1).
pub const OVERHEAD_BASE: f64 = 1.5;
pub const OVERHEAD_SCALE: f64 = 1.5;

// === Placement ===

/// Maximum holders per source block. Beyond ~30, marginal fault tolerance
/// gain is tiny while PoS/restore overhead grows linearly.
pub const MAX_HOLDERS_PER_BLOCK: u32 = 30;

/// Physical survival ceiling: the probability that even a *fully trusted* holder
/// still has our data at the end of the repair horizon (~1 month), independent of
/// trust. Trust measures behaviour/commitment (does the holder store honestly);
/// it cannot capture involuntary loss — disk death, fire, theft, ISP/decommission,
/// the operator simply walking away — which happens to any node, however trusted.
/// So `p = BASELINE_HOLDER_SURVIVAL × f(trust)` caps p below 1: no holder is ever
/// a certainty, and the most important blocks therefore earn real replication
/// instead of a thin spread that assumed immortal holders. 0.90 ≈ "~10% of even
/// good nodes vanish over a month" — deliberately conservative (under-estimating p
/// over-places, the safe direction).
pub const BASELINE_HOLDER_SURVIVAL: f64 = 0.90;

/// Minimum symbols assigned per holder. Below this threshold the per-holder
/// tracking overhead (PoS, repair) isn't justified. Protects small-block configs.
pub const MIN_SYMBOLS_PER_HOLDER: u32 = 32; // 2 MB at T=64KB

/// Concentration cap factor: max_share = (1 - 1/overhead) * this.
pub const CONCENTRATION_CAP_FACTOR: f64 = 0.85;

// === Eviction priority ===
// priority = importance * trust_of_owner * (1 + age_bonus)

/// Hysteresis: new data must beat existing by this fraction to displace.
pub const EVICTION_HYSTERESIS: f64 = 0.2;

/// Max age bonus (+30% for old data).
pub const AGE_BONUS_CAP: f64 = 0.3;

/// Full age bonus reached after this many weeks.
pub const AGE_BONUS_WEEKS: f64 = 26.0;

/// Trust floor for unknown owners during eviction.
pub const UNKNOWN_OWNER_TRUST_FLOOR: f64 = 0.1;

// === Disk pressure ===

/// Default disk reserve in bytes (20 GB).
pub const DEFAULT_DISK_RESERVE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

// === PoS (Proof of Storage) ===

/// PoS response timeout (7 days, also relay TTL).
pub const POS_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// Base PoS challenges per holder per week.
pub const POS_BASE_CHALLENGES_PER_WEEK: u32 = 1;

/// volume_factor = ceil(holder_symbols / POS_VOLUME_DIVISOR).
pub const POS_VOLUME_DIVISOR: u32 = 1000;

// === Wire format ===

/// Max CBOR message frame size (128 MiB). Matches MAX_MSG_SIZE in swarm.rs codec.
pub const MAX_MESSAGE_SIZE: u32 = 128 * 1024 * 1024;

/// Soft budget for the symbol-data payload of a single SymbolTransferMsg.
/// Owners chunk larger deliveries into multiple transfers to stay below
/// MAX_MESSAGE_SIZE. The budget is expressed against *raw* `symbol.data.len()`
/// and is set conservatively (≈60% of MAX_MESSAGE_SIZE) to absorb CBOR
/// per-symbol overhead in the worst case we saw in gamma runs: ≈2240 symbols
/// × 65548 wire bytes ≈ 146 MiB wire from ≈140 MiB raw. Lowering from 100 MiB
/// to 80 MiB fixes those borderline cases; see tech-debt for the proper
/// wire-size accurate variant.
pub const SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES: usize = 80 * 1024 * 1024;

/// Protocol version for wire messages.
pub const PROTOCOL_VERSION: u8 = 1;

/// Handshake timestamp freshness window (+-300 seconds).
///
/// Used ONLY for security-critical handshake replay prevention (Noise IX setup).
/// For operational messages (SymbolOffer, PeerAnnounce, Delete, CancelDelete) use
/// `MESSAGE_FRESHNESS_SECS` — wider window tolerates NTP-less NAS deployments.
pub const HANDSHAKE_FRESHNESS_SECS: u64 = 300;

/// Operational message freshness window (1 hour).
///
/// Used for SymbolOffer, PeerAnnounce, Delete, CancelDelete and similar
/// operational messages. Wider than handshake window because clock skew on
/// NAS without NTP can exceed 5 minutes; cold backup tolerates 1h skew safely
/// since msg_id dedup + signature verify already prevent replay attacks.
pub const MESSAGE_FRESHNESS_SECS: u64 = 3600;

/// Target authenticated peer count.
///
/// When `authenticated.len() >= TARGET_PEERS`, Kademlia discovery skips new
/// dial attempts to avoid unbounded connection growth. Cold backup needs
/// only a small stable set of holders; more peers don't improve reliability
/// beyond redundancy targets.
pub const TARGET_PEERS: usize = 20;

/// Max concurrent discovery dials per Kademlia `GetProviders` result.
///
/// libp2p Kademlia can return up to K=20 providers per query, and DHT walks
/// aggregate across multiple hops. Without a cap we burst-dial every result,
/// blowing `pending_cert` HashMap and saturating `check_cert_timeouts` ticker.
pub const MAX_CONCURRENT_DISCOVERY_DIALS: usize = 5;

/// Max relay hop count — drop entries with hop >= this.
pub const MAX_RELAY_HOP: u8 = 2;

/// Relay entry TTL (7 days).
pub const RELAY_TTL_SECS: u64 = 7 * 24 * 3600;

/// HKDF info string for directed message encryption (ECDH -> ChaCha20).
pub const DIRECTED_ENCRYPTION_INFO: &[u8] = b"viaticum-directed";

// === Backup triggers ===

/// Debounce: wait this long after last fs event before processing (seconds).
pub const DEBOUNCE_SECS: u64 = 30 * 60; // 30 minutes

/// Flush packing queue if idle for this long (seconds).
pub const FLUSH_IDLE_SECS: u64 = 60 * 60; // 1 hour

/// Flush packing queue unconditionally after this long (seconds).
pub const FLUSH_FALLBACK_SECS: u64 = 24 * 60 * 60; // 24 hours

/// Minimum batch size for flushing packing queue (bytes).
///
/// CL-1: packed blocks below a few MB produce a small k_eff, which combined with
/// the concentration cap and a thin holder pool can leave a block with too few
/// placed symbols to ever decode. Keeping batches at >= 6 MB ensures packed
/// blocks have enough symbols to spread safely across the holder pool. (Single
/// large files bypass packing; their placement is guarded by the CL-1 cap relax
/// in `placement::compute_allocation`.)
pub const MIN_BATCH_BYTES: u64 = 6 * 1024 * 1024; // 6 MB

// === File versioning ===

/// Default max versions kept per file path.
pub const DEFAULT_MAX_VERSIONS: u32 = 5;

/// Default max age for old versions (90 days, seconds).
pub const DEFAULT_MAX_VERSION_AGE_SECS: u64 = 90 * 24 * 3600;

// === Vacuum ===

/// Fraction of invalid files in a batch to trigger repack.
pub const VACUUM_INVALID_THRESHOLD: f64 = 0.5;

// === Budget planner ===

/// Default placement success rate on first run (no history).
pub const DEFAULT_SUCCESS_RATE: f64 = 0.5;

/// Conservative headroom multiplier.
pub const WILLINGNESS_FACTOR: f64 = 1.0;

/// Rolling window for weekly placement stats.
pub const WEEKLY_STATS_WINDOW: u32 = 4;

// === Cluster ===

/// Default max events per cluster sync batch.
pub const DEFAULT_CLUSTER_SYNC_BATCH_SIZE: usize = 100;

// === Relay board limits ===

/// Max entries per relay board (from protocol.md §1.5).
pub const MAX_BOARD_ENTRIES: usize = 2000;

/// Max total board size in bytes (8 MB, from protocol.md §1.5).
pub const MAX_BOARD_SIZE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum relay board entries accepted from a single author per
/// `process_remote_entries` call.
///
/// Prevents a malicious peer from filling the entire board with its own
/// entries and crowding out legitimate messages (pos_challenge, peer_announce).
///
/// Derived from MAX_BOARD_ENTRIES / 10, assuming a cluster of ~10 peers.
/// Each peer gets a fair share of the 2000-entry board.
pub const MAX_BOARD_ENTRIES_PER_AUTHOR: usize = 200;

// === PoS placement status thresholds ===

/// Number of consecutive PoS timeouts before a placement is marked Uncertain.
/// First timeout → Uncertain immediately (1 miss = Uncertain).
pub const POS_CONSECUTIVE_MISS_UNCERTAIN: u32 = 1;

/// Number of consecutive PoS timeouts before a placement is marked PresumedLost.
/// 3+ consecutive misses → PresumedLost → triggers repair.
pub const POS_CONSECUTIVE_MISS_PRESUMED_LOST: u32 = 3;

// === Commitment telemetry ===

/// Weight of PoS pass rate in commitment score.
pub const COMMITMENT_POS_WEIGHT: f64 = 0.5;

/// Weight of disk pressure signal in commitment score.
pub const COMMITMENT_PRESSURE_WEIGHT: f64 = 0.25;

/// Weight of relationship age signal in commitment score.
pub const COMMITMENT_AGE_WEIGHT: f64 = 0.15;

/// Weight of eviction priority of our data at the holder's node.
pub const COMMITMENT_PRIORITY_WEIGHT: f64 = 0.10;

/// Weeks of relationship needed to reach full age signal (1.0).
pub const COMMITMENT_AGE_SATURATION_WEEKS: f64 = 26.0;

/// Minimum PoS challenges required for the pass rate to count.
/// Below this: treat as if pass rate were 0. Prevents "no challenges = pass_rate=1.0".
pub const COMMITMENT_MIN_CHALLENGES: u32 = 1;

/// Eviction priority threshold below which commitment takes a penalty.
/// Set to 0.0 to disable the relative penalty (use only absolute priority).
pub const COMMITMENT_PRIORITY_FLOOR: f64 = 0.0;

// === Reliability forecast ===

/// Default assumed annual churn (30%). Used when no per-holder commitment data
/// is available. Matches the calibration table in docs/beta/raptorq.md.
pub const DEFAULT_ANNUAL_CHURN_RATE: f64 = 0.30;

/// Reliability threshold below which a block is flagged needs_repair.
/// 99.0% = two nines. Blocks below this get flagged in ReliabilityReport.
pub const RELIABILITY_REPAIR_THRESHOLD: f64 = 0.99;

/// Small N threshold: use exact binomial CDF for N < this value, normal
/// approximation for N >= this value.
pub const BINOMIAL_EXACT_THRESHOLD: u32 = 100;

// === Priority scheduling ===

/// Default completion bonus coefficient for the priority formula.
/// `priority = importance × (1 + k × current_alive / n_target)`
/// At k=1.5: a block at 90% completion has priority ≈ 2.35× its importance.
pub const DEFAULT_COMPLETION_BONUS_COEFFICIENT: f64 = 1.5;

/// Maximum allowed value for completion_bonus_coefficient in config.
/// Above this the completion bonus dominates even large importance differences.
pub const MAX_COMPLETION_BONUS_COEFFICIENT: f64 = 5.0;

// === Dynamic N bounds ===

/// Minimum extra symbols beyond k_eff: n >= k_eff + MIN_REDUNDANCY.
/// Ensures at least 2 parity symbols regardless of trust or importance.
/// Prevents n == k_eff which would give zero fault tolerance.
pub const MIN_REDUNDANCY: u32 = 2;

/// Maximum overhead factor: n <= k_eff * MAX_OVERHEAD_FACTOR.
/// Caps symbol count to prevent runaway allocation on low-trust pools.
/// If target_p cannot be reached within this cap, solve_n_for_target
/// returns Ok(k_eff * MAX_OVERHEAD_FACTOR) and caller treats it as best-effort.
pub const MAX_OVERHEAD_FACTOR: u32 = 10;

// === Symbol offer handshake ===

/// Timeout for awaiting SymbolAccept on a direct connection (seconds).
/// Direct connection: 30s is generous for the offer→accept handshake.
pub const SYMBOL_OFFER_TIMEOUT_SECS: u64 = 30;

/// Timeout before an Offered placement is swept to Lost (seconds).
/// Must be long enough for full symbol delivery (encode + transfer + disk write).
/// 300s = 5 minutes — same as SYMBOL_OFFER_EXPIRY_SECS.
pub const OFFERED_PLACEMENT_TIMEOUT_SECS: u64 = 300;

/// Long-absence threshold for Offered placements (seconds).
/// Offered → Lost only after this interval if no real signal received.
/// Default: 14 days.
pub const LONG_ABSENCE_SECS: u64 = 14 * 24 * 3600; // 1_209_600

/// Stale accepted offer expiry (seconds). AcceptedOffers older than this are
/// discarded on next access even if no Transfer arrived.
pub const SYMBOL_OFFER_EXPIRY_SECS: u64 = 300;

// === Network reconnection ===

/// Seconds before retrying a failed peer connection.
pub const RECONNECT_BACKOFF_SECS: u64 = 30;

// === Holdings integrity scan ===

/// Default holdings integrity scan interval in seconds (1 day).
pub const DEFAULT_HOLDINGS_INTEGRITY_INTERVAL_SECS: u64 = 86_400;

// === Two-level trust ===

/// Fraction of master_trust inherited by a new device with zero device_trust.
/// effective_trust = base + dt * (1 - base/MAX_COMBINED_TRUST)
/// where base = master_trust.combined * TRUST_INHERITANCE_FACTOR
pub const TRUST_INHERITANCE_FACTOR: f64 = 0.3;

/// Maximum combined trust value (P=1, I=1, S=1 → KP + KI = 2.15).
/// Used in effective_trust formula denominator.
pub const MAX_COMBINED_TRUST: f64 = KP + KI; // = 2.15

// === Units ===

/// Bytes in one gibibyte (2^30).
pub const BYTES_PER_GB: f64 = 1_073_741_824.0;

// === Disaster Recovery ===

/// Maximum size of an encrypted SystemState blob accepted from a peer.
///
/// A legitimate SystemState blob for a cluster of ~20 peers (device certs,
/// trust records, placement metadata) compresses to tens of KB at most.
/// 2 MiB = ~100× headroom. Blobs above this limit are dropped with a warning
/// to prevent disk DoS from authenticated-but-malicious peers.
/// Must be << MAX_MESSAGE_SIZE (128 MiB).
pub const MAX_SYSTEM_STATE_BLOB_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

// === Mailbox (A2) ===

/// Candidate set size for mailbox write/read fanout (XOR-distance top-N).
pub const MAILBOX_CANDIDATES_N: usize = 1000;

/// Write fanout: top-30 peers by trust × avail_ewma.
pub const MAILBOX_WRITE_FANOUT: usize = 30;

/// Read fanout: broader overlap for fetch reliability.
pub const MAILBOX_READ_FANOUT: usize = 300;

/// DR walk batches: expanding search [100, 300, 1000].
pub const MAILBOX_DR_WALK_BATCHES: &[usize] = &[100, 300, 1000];

/// Kademlia bootstrap stabilization timeout for DR (seconds).
///
/// After starting the swarm in DR mode, we wait up to this long for the
/// Kademlia routing table to populate via bootstrap. 120 s is enough for a
/// small-to-medium network with 2+ seed peers (assumption A5 from the spec).
/// Best-effort: if fewer peers authenticate within this window we still proceed
/// with whatever is known.
pub const DR_KAD_STABILIZE_TIMEOUT_SECS: u64 = 120;

/// Mailbox poll interval: 1 hour.
pub const MAILBOX_POLL_INTERVAL_SECS: u64 = 3600;

/// Per-peer request timeout window for collecting the first MailboxStoreAck
/// before treating the challenge as unsent.
/// The MailboxRouter already enforces this as a per-peer network timeout (PEER_REQUEST_TIMEOUT).
/// This constant is referenced for the W-3 acked-wait comment; actual enforcement is in routing.rs.
pub const MAILBOX_STORE_TIMEOUT_SECS: u64 = 30;

/// Mailbox TTL-sweep interval: 6 hours.
pub const MAILBOX_SWEEP_INTERVAL_SECS: u64 = 6 * 3600;

/// Self-pointer republish interval: 30 days.
pub const MAILBOX_POINTER_REPUBLISH_SECS: u64 = 30 * 24 * 3600;

// ── EWMA availability constants (T-4a) ──────────────────────────────────────

/// EWMA smoothing factor. α=0.05 → half-life ≈ 13.5 daily ticks (~2 weeks).
/// Tuned so a node continuously online for 4 weeks converges to ≈0.76 from 0.1 start,
/// and a node absent for 28 days decays from 1.0 to ≈0.25.
pub const AVAIL_EWMA_ALPHA: f64 = 0.05;

/// Pessimistic starting value for new peers: availability is earned by contact,
/// consistent with trust_i=0.0 earn-it axis. Slows Sybil write-fanout capture.
pub const AVAIL_EWMA_INITIAL: f64 = 0.1;

/// Decay tick interval in seconds (24 hours). One "no-contact" observation per day.
pub const AVAIL_DECAY_TICK_SECS: u64 = 24 * 3600;

/// PoS challenge pending timeout: challenge_TTL + response_TTL + 2×poll_interval ≈ 14d 2h.
/// Response lives in mailbox for response_TTL; owner needs time to poll and receive it.
pub const POS_CHALLENGE_PENDING_TIMEOUT_SECS: u64 = 7 * 24 * 3600 + 7 * 24 * 3600 + 2 * 3600;

/// Delivery reward weight for mailbox reads (starting value — refine on scale-test).
/// Normal PoS pass = weight 1.0. Delivery reward = 0.05 (significantly less, but > 0).
pub const MAILBOX_DELIVERY_REWARD_WEIGHT: f64 = 0.05; // starting value, refine on scale-test

/// Per-postman mailbox trust ceiling (starting value — refine on scale-test).
/// Prevents mailbox-accumulated trust_p from reaching storage-trust threshold alone.
/// Per-postman in the LOCAL view of the fetcher node.
pub const MAILBOX_REWARD_CEILING: f64 = 0.3; // starting value, refine on scale-test

// === Compile-time sanity checks ===

const _: () = assert!(S_CLAMP_MIN < S_CLAMP_MAX);
const _: () = assert!(OVERHEAD_BASE > 1.0);
const _: () = assert!(DECODE_OVERHEAD > 0);
const _: () = assert!(SYMBOL_OFFER_TIMEOUT_SECS < SYMBOL_OFFER_EXPIRY_SECS);
const _: () = assert!(MAX_SYSTEM_STATE_BLOB_BYTES < MAX_MESSAGE_SIZE as usize);
const _: () = assert!(MIN_REDUNDANCY >= 1);
const _: () = assert!(MAX_OVERHEAD_FACTOR > 1);
