# Task spec: Config module (Phase 4.1)

## Overview

Implement `syncback_core::config` — a unified top-level configuration struct for the daemon,
deserialized from a TOML file. All subsystems currently take individual `*Config` structs;
this module defines the single `AppConfig` that the daemon reads on startup and then slices
into those structs.

Crate: `syncback-core` (pure logic, no async, no network).

---

## Location

```
crates/syncback-core/src/config/mod.rs
crates/syncback-core/src/config/tests.rs
```

Add to `crates/syncback-core/src/lib.rs`:
```rust
pub mod config;
```

---

## Dependencies to add

### `Cargo.toml` (workspace level)

```toml
toml = "0.8"
```

### `crates/syncback-core/Cargo.toml`

```toml
toml = { workspace = true }
```

`serde` is already a workspace dependency with `features = ["derive"]`, so no change needed
there.

---

## Public API

### Top-level struct

```rust
/// Unified daemon configuration. Loaded from `~/.syncback/config.toml` or an explicit path.
/// Every field has a sensible default; `AppConfig::default()` requires no file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub backup:  BackupCfg,
    pub storage: StorageCfg,
    pub escrow:  EscrowCfg,
    pub network: NetworkCfg,
    pub cluster: ClusterCfg,
}
```

### Section structs

```rust
/// [backup] — erasure coding and versioning parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct BackupCfg {
    /// Source block size in megabytes. Must be a power of two, >= 1.
    /// Default: 128 (128 MB). Use 32 on Raspberry Pi (~65 MB peak RAM).
    pub source_block_size_mb: u64,

    /// Maximum number of versions kept per file path.
    /// Default: 5.
    pub max_versions: u32,

    /// Maximum age of old file versions in days.
    /// Default: 90.
    pub max_version_age_days: u64,
}

/// [storage] — disk quota and data directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct StorageCfg {
    /// Soft quota in gigabytes. 0 = unlimited (no ceiling).
    /// effective_quota = min(soft_quota, disk_free - disk_reserve).
    /// Default: 0.
    pub soft_quota_gb: f64,

    /// Hard quota floor in gigabytes. 0 = no floor (evict freely).
    /// The holder will never evict below this floor even under pressure.
    /// Default: 0.
    pub hard_quota_gb: f64,

    /// Minimum free disk space to keep, in gigabytes. The daemon will start
    /// evicting symbols before disk_free drops below this value.
    /// Default: 20.
    pub disk_reserve_gb: f64,

    /// Root data directory: database, symbols, relay board.
    /// `~` is expanded to the user home directory.
    /// Default: "~/.syncback".
    pub data_dir: String,
}

/// [escrow] — trust-based restore credit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EscrowCfg {
    /// Demo credit available at trust=0 (GB). Default: 1.0.
    pub free_tier_gb: f64,

    /// GB of restore credit per unit of trust.
    /// max_restorable_gb = free_tier_gb + trust * trust_factor.
    /// Default: 20.0.
    pub trust_factor: f64,
}

/// [network] — epidemic relay board limits.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    /// Maximum number of entries on the local relay board.
    /// Default: 2000 (from protocol.md §1.5).
    pub relay_max_entries: usize,

    /// Maximum total relay board size in megabytes.
    /// Default: 8.
    pub relay_max_size_mb: usize,

    /// Relay entry time-to-live in days.
    /// Default: 7.
    pub relay_ttl_days: u64,
}

/// [cluster] — multi-device cluster parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ClusterCfg {
    /// Maximum events per cluster sync batch.
    /// Default: 100.
    pub sync_batch_size: usize,
}
```

### Load and validate

```rust
/// Errors from config loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error reading config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation error: {field}: {reason}")]
    Validation { field: String, reason: String },
}

impl AppConfig {
    /// Load config from a TOML file at `path`.
    ///
    /// Missing fields in the file are filled with `Default::default()`.
    /// After deserialization, `validate()` is called — returns Err if any
    /// constraint is violated.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError>;

    /// Return a fully-populated config with all defaults.
    /// Equivalent to `AppConfig::default()` but named for clarity at call sites.
    pub fn defaults() -> Self;

    /// Validate all cross-field constraints.
    ///
    /// Called by `load()`. May also be called by callers that build
    /// `AppConfig` programmatically.
    pub fn validate(&self) -> Result<(), ConfigError>;
}
```

### Conversion helpers

The daemon constructs subsystem `*Config` structs from `AppConfig`. Provide these free
functions (not trait impls — keep it explicit and grep-friendly):

```rust
/// Convert AppConfig fields → source_block_size in bytes.
///
/// Returns backup.source_block_size_mb * 1_048_576.
pub fn source_block_size_bytes(cfg: &AppConfig) -> u64;

/// Convert storage.soft_quota_gb → bytes. 0.0 maps to 0 (unlimited sentinel).
pub fn soft_quota_bytes(cfg: &AppConfig) -> u64;

/// Convert storage.hard_quota_gb → bytes. 0.0 maps to 0 (no floor sentinel).
pub fn hard_quota_bytes(cfg: &AppConfig) -> u64;

/// Convert storage.disk_reserve_gb → bytes.
pub fn disk_reserve_bytes(cfg: &AppConfig) -> u64;

/// Expand `~` in storage.data_dir to the user's home directory.
///
/// Uses `std::env::var("HOME")` on Unix, `USERPROFILE` on Windows.
/// If the env var is missing, returns the path as-is (no `~` expansion).
pub fn expand_data_dir(cfg: &AppConfig) -> std::path::PathBuf;
```

---

## Default values

All defaults are sourced from `crates/syncback-core/src/constants.rs`.

| Config field | Default | Constant |
|---|---|---|
| `backup.source_block_size_mb` | 128 | `DEFAULT_SOURCE_BLOCK_SIZE / 1_048_576` = 128 |
| `backup.max_versions` | 5 | `DEFAULT_MAX_VERSIONS` |
| `backup.max_version_age_days` | 90 | `DEFAULT_MAX_VERSION_AGE_SECS / 86400` = 90 |
| `storage.soft_quota_gb` | 0.0 | sentinel: unlimited |
| `storage.hard_quota_gb` | 0.0 | sentinel: no floor |
| `storage.disk_reserve_gb` | 20.0 | `DEFAULT_DISK_RESERVE_BYTES / 1_073_741_824` = 20 |
| `storage.data_dir` | `"~/.syncback"` | hardcoded |
| `escrow.free_tier_gb` | 1.0 | `FREE_TIER_GB` |
| `escrow.trust_factor` | 20.0 | `DEFAULT_ESCROW_TRUST_FACTOR` |
| `network.relay_max_entries` | 2000 | `MAX_BOARD_ENTRIES` |
| `network.relay_max_size_mb` | 8 | `MAX_BOARD_SIZE_BYTES / 1_048_576` = 8 |
| `network.relay_ttl_days` | 7 | `RELAY_TTL_SECS / 86400` = 7 |
| `cluster.sync_batch_size` | 100 | not in constants.rs yet — use 100 |

The `impl Default` for each struct must use these exact values. Do NOT define magic numbers
inside `config/mod.rs` — import from `constants.rs` wherever possible. For values not yet in
`constants.rs`, add a new constant with a comment explaining its purpose.

---

## Validation rules

`validate()` enforces all of the following. Each violation returns
`ConfigError::Validation { field, reason }` immediately (fail-fast, first error wins).

| Field | Rule | Reason |
|---|---|---|
| `backup.source_block_size_mb` | must be >= 1 | below 1 MB is nonsensical |
| `backup.source_block_size_mb` | must be a power of two | RaptorQ K must be integer; K = block_size / SYMBOL_SIZE; non-power-of-two creates fractional K |
| `backup.max_versions` | must be >= 1 | keeping 0 versions means no backup |
| `backup.max_version_age_days` | must be >= 1 | 0-day versions delete immediately |
| `storage.soft_quota_gb` | must be >= 0.0 | negative quota is nonsensical |
| `storage.hard_quota_gb` | must be >= 0.0 | negative quota is nonsensical |
| `storage.disk_reserve_gb` | must be >= 0.0 | negative reserve is nonsensical |
| `storage.hard_quota_gb` | if both nonzero: hard_quota_gb <= soft_quota_gb | hard floor above soft ceiling is contradictory |
| `escrow.free_tier_gb` | must be >= 0.0 | negative credit is nonsensical |
| `escrow.trust_factor` | must be >= 0.0 | negative factor is nonsensical |
| `network.relay_max_entries` | must be >= 1 | board with 0 entries is inoperable |
| `network.relay_max_size_mb` | must be >= 1 | board with 0 bytes is inoperable |
| `network.relay_ttl_days` | must be >= 1 | 0-day TTL expires entries immediately |
| `cluster.sync_batch_size` | must be >= 1 | batch of 0 events is inoperable |

Power-of-two check for `source_block_size_mb`:
```rust
fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}
```

---

## File format (TOML)

The full reference config. Every key is optional — missing keys use defaults.

```toml
[backup]
source_block_size_mb = 128   # 32 for Raspberry Pi, 256 for beefy NAS
max_versions = 5
max_version_age_days = 90

[storage]
soft_quota_gb = 0            # 0 = unlimited
hard_quota_gb = 0            # 0 = no floor
disk_reserve_gb = 20
data_dir = "~/.syncback"

[escrow]
free_tier_gb = 1.0
trust_factor = 20.0

[network]
relay_max_entries = 2000
relay_max_size_mb = 8
relay_ttl_days = 7

[cluster]
sync_batch_size = 100
```

An empty file (or a file with only some sections) must parse successfully with all missing
values filled from defaults.

---

## Implementation notes

### `AppConfig::load`

```
1. Read file contents via std::fs::read_to_string(path)  [returns ConfigError::Io on failure]
2. Deserialize via toml::from_str::<AppConfig>(&contents) [returns ConfigError::Parse on failure]
   — serde(default) on all structs fills missing fields automatically
3. Call self.validate()                                   [returns ConfigError::Validation on failure]
4. Return Ok(config)
```

The `#[serde(default)]` annotation on every struct and `#[serde(default)]` on `AppConfig`
itself is what enables partial files. Do not implement a manual merge — let serde do it.

### `expand_data_dir`

```rust
pub fn expand_data_dir(cfg: &AppConfig) -> std::path::PathBuf {
    let s = &cfg.storage.data_dir;
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        std::path::PathBuf::from(home).join(rest)
    } else {
        std::path::PathBuf::from(s)
    }
}
```

Note: `"~"` alone (without a following `/`) expands to the home dir directly.
`"~/".strip_prefix("~/")` handles the common case. A bare `"~"` edge case:

```rust
if s == "~" {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    return std::path::PathBuf::from(home);
}
```

Put both checks before the fallback.

### Conversion helpers: integer arithmetic

All `*_bytes` helpers use integer arithmetic to avoid floating-point rounding. For `f64`
quota fields, the conversion is:

```rust
pub fn soft_quota_bytes(cfg: &AppConfig) -> u64 {
    // 0.0 is the "unlimited" sentinel; preserve it exactly.
    if cfg.storage.soft_quota_gb == 0.0 {
        return 0;
    }
    (cfg.storage.soft_quota_gb * 1_073_741_824.0) as u64
}
```

Apply the same pattern for `hard_quota_bytes` and `disk_reserve_bytes`.

---

## Test scenarios

File: `crates/syncback-core/src/config/tests.rs`. Use `#[cfg(test)]` at top.

All tests that need a file write should use `tempfile::NamedTempFile`.

### Test naming pattern: `what_when_then`

```rust
fn config_loads_defaults_when_file_is_empty()
fn config_loads_partial_file_merging_with_defaults()
fn config_roundtrips_all_fields()
fn config_validate_rejects_source_block_size_zero()
fn config_validate_rejects_source_block_size_not_power_of_two()
fn config_validate_rejects_source_block_size_3mb()
fn config_validate_rejects_max_versions_zero()
fn config_validate_rejects_max_version_age_days_zero()
fn config_validate_rejects_negative_soft_quota()
fn config_validate_rejects_negative_hard_quota()
fn config_validate_rejects_hard_quota_above_soft_quota()
fn config_validate_allows_hard_quota_zero_with_nonzero_soft()
fn config_validate_allows_both_quotas_zero()
fn config_validate_rejects_relay_max_entries_zero()
fn config_validate_rejects_relay_ttl_days_zero()
fn config_validate_rejects_cluster_sync_batch_size_zero()
fn config_load_returns_parse_error_for_invalid_toml()
fn config_load_returns_io_error_for_missing_file()
fn source_block_size_bytes_converts_correctly()
fn soft_quota_bytes_returns_zero_for_unlimited()
fn soft_quota_bytes_converts_fractional_gb()
fn disk_reserve_bytes_converts_correctly()
fn expand_data_dir_expands_tilde()
fn expand_data_dir_leaves_absolute_path_unchanged()
fn expand_data_dir_handles_bare_tilde()
fn config_defaults_match_constants()
```

### Specific test cases with inputs and expected outputs

**`config_loads_defaults_when_file_is_empty`**
- Input: empty file `""`
- Expected: `AppConfig::default()` — all fields equal their documented defaults

**`config_loads_partial_file_merging_with_defaults`**
- Input TOML:
  ```toml
  [backup]
  source_block_size_mb = 32
  ```
- Expected: `backup.source_block_size_mb = 32`, all other fields = defaults
- Specifically: `storage.disk_reserve_gb = 20.0`, `escrow.trust_factor = 20.0`, etc.

**`config_roundtrips_all_fields`**
- Build an `AppConfig` with non-default values for every field:
  ```
  source_block_size_mb = 64, max_versions = 10, max_version_age_days = 180,
  soft_quota_gb = 500.0, hard_quota_gb = 10.0, disk_reserve_gb = 50.0,
  data_dir = "/data/syncback",
  free_tier_gb = 2.0, trust_factor = 30.0,
  relay_max_entries = 1000, relay_max_size_mb = 4, relay_ttl_days = 14,
  sync_batch_size = 200
  ```
- Serialize to TOML string via `toml::to_string`, write to tempfile, reload via `AppConfig::load`.
- Assert all fields match.

**`config_validate_rejects_source_block_size_not_power_of_two`**
- Input: `source_block_size_mb = 100`
- Expected: `Err(ConfigError::Validation { field: "backup.source_block_size_mb", .. })`

**`config_validate_rejects_source_block_size_3mb`**
- Input: `source_block_size_mb = 3`
- Expected: Err (3 is not a power of two)

**`config_validate_allows_source_block_size_1mb`**
- Input: `source_block_size_mb = 1`
- Expected: Ok (1 is a power of two and >= 1)

**`config_validate_rejects_hard_quota_above_soft_quota`**
- Input: `soft_quota_gb = 100.0`, `hard_quota_gb = 200.0`
- Expected: `Err(ConfigError::Validation { field: "storage.hard_quota_gb", .. })`

**`config_validate_allows_hard_quota_zero_with_nonzero_soft`**
- Input: `soft_quota_gb = 100.0`, `hard_quota_gb = 0.0`
- Expected: Ok (0 = no floor; does not trigger the contradiction check)

**`config_validate_allows_both_quotas_zero`**
- Input: `soft_quota_gb = 0.0`, `hard_quota_gb = 0.0`
- Expected: Ok

**`source_block_size_bytes_converts_correctly`**
- Input: `source_block_size_mb = 128`
- Expected: `source_block_size_bytes(&cfg) == 134_217_728` (128 × 1_048_576)

**`soft_quota_bytes_returns_zero_for_unlimited`**
- Input: `soft_quota_gb = 0.0`
- Expected: `soft_quota_bytes(&cfg) == 0`

**`soft_quota_bytes_converts_fractional_gb`**
- Input: `soft_quota_gb = 0.5`
- Expected: `soft_quota_bytes(&cfg) == 536_870_912` (0.5 × 1_073_741_824)

**`expand_data_dir_expands_tilde`**
- Set `HOME=/home/user`, input `"~/.syncback"`
- Expected: `PathBuf::from("/home/user/.syncback")`

**`expand_data_dir_leaves_absolute_path_unchanged`**
- Input: `"/mnt/data/syncback"`
- Expected: `PathBuf::from("/mnt/data/syncback")`

**`expand_data_dir_handles_bare_tilde`**
- Set `HOME=/home/user`, input `"~"`
- Expected: `PathBuf::from("/home/user")`

**`config_defaults_match_constants`**
- Assert that `AppConfig::default()` has:
  - `backup.source_block_size_mb == DEFAULT_SOURCE_BLOCK_SIZE / 1_048_576`
  - `backup.max_versions == DEFAULT_MAX_VERSIONS`
  - `storage.disk_reserve_gb == DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0`
  - `escrow.free_tier_gb == FREE_TIER_GB`
  - `escrow.trust_factor == DEFAULT_ESCROW_TRUST_FACTOR`
  - `network.relay_max_entries == MAX_BOARD_ENTRIES`
  - `network.relay_max_size_mb == MAX_BOARD_SIZE_BYTES / 1_048_576`

---

## New constants to add to `constants.rs`

The following values are not yet in `constants.rs` but are used by `ClusterSyncConfig` and
will be referenced by `ClusterCfg::default()`. Add them:

```rust
/// Default max events per cluster sync batch.
pub const DEFAULT_CLUSTER_SYNC_BATCH_SIZE: usize = 100;
```

Note: `ClusterSyncConfig::default()` in the daemon currently hardcodes `batch_size: 1000`.
The new config default is **100** — this is intentional. The daemon's hardcoded value was a
Phase 3 implementation placeholder; the config spec sets the real tuned default. The
implementer must update `ClusterSyncConfig::default()` to use
`DEFAULT_CLUSTER_SYNC_BATCH_SIZE` once this module exists, but that change is OUT OF SCOPE
for this task — just add the constant.

---

## Dependencies on other modules

- `syncback_core::constants` — reads default values from it
- No DB operations (pure struct, no persistence)
- No network operations

---

## What this module does NOT own

- Daemon startup logic (reading `~/.syncback/config.toml` on boot) — lives in `syncback/` binary
- Wiring AppConfig fields into subsystem `*Config` structs — lives in `syncback/daemon/mod.rs`
- The `epoch_key`, `signing_key`, `device_id` fields that come from the keystore, not from
  TOML config — those are runtime-derived, not user-configurable

---

## Checklist for implementer

- [ ] Add `toml = "0.8"` to `Cargo.toml` (workspace) and to `syncback-core/Cargo.toml`
- [ ] Create `crates/syncback-core/src/config/mod.rs`
- [ ] Create `crates/syncback-core/src/config/tests.rs`
- [ ] Register `pub mod config;` in `crates/syncback-core/src/lib.rs`
- [ ] Add `DEFAULT_CLUSTER_SYNC_BATCH_SIZE` to `constants.rs`
- [ ] All `impl Default` use constants, not magic numbers
- [ ] `AppConfig::load` calls `validate()` before returning
- [ ] All 28 test functions written and passing
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo test` passes (full workspace)
