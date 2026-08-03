//! CLI parsing for the `sim_adv` binary + the sweep-dial mapping.
//!
//! `sim_adv <scenario> [--seeds N] [--sweep dial=a,b,c] [--csv <file>] [--fast]`.
//! Parsing is a small hand-rolled pass (no clap dep in this harness) that returns a
//! [`SimAdvError`] on any problem — an unknown scenario/flag/dial is a graceful error,
//! never a panic (convention: network/timeout/misbehaviour → graceful).

use crate::sim_dynamic::engine::DynParams;

/// Errors from CLI parsing / scenario lookup / dial application.
#[derive(Debug, thiserror::Error)]
pub enum SimAdvError {
    /// No scenario name was given.
    #[error(
        "no scenario given; usage: sim_adv <scenario> [--seeds N] [--horizon T] [--sweep dial=a,b,c] [--csv <file>] [--fast]"
    )]
    MissingScenario,
    /// The scenario name is not in the registry.
    #[error("unknown scenario '{0}'; known: {1}")]
    UnknownScenario(String, String),
    /// A flag that expects a value was given none.
    #[error("flag '{0}' expects a value")]
    MissingValue(&'static str),
    /// An unrecognised flag.
    #[error("unrecognised flag '{0}'")]
    UnknownFlag(String),
    /// `--seeds` value was not a positive integer.
    #[error("--seeds expects a positive integer, got '{0}'")]
    BadSeeds(String),
    /// `--horizon` value was not a positive integer.
    #[error("--horizon expects a positive integer, got '{0}'")]
    BadHorizon(String),
    /// `--sweep` spec was not `dial=v1,v2,...`.
    #[error("--sweep expects 'dial=v1,v2,...', got '{0}'")]
    BadSweep(String),
    /// The sweep dial name is not one this harness can override.
    #[error("unknown sweep dial '{0}'; known: {1}")]
    UnknownDial(String, String),
    /// A CSV write failed.
    #[error("csv write to '{0}' failed: {1}")]
    CsvWrite(String, String),
}

/// A parsed dial sweep.
#[derive(Debug, Clone, PartialEq)]
pub struct Sweep {
    /// The `DynParams` field to override.
    pub dial: String,
    /// The values to run at.
    pub values: Vec<f64>,
}

/// A parsed CLI invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct Cli {
    /// The scenario name (registry key).
    pub scenario: String,
    /// Override the seed COUNT (seeds become `base, base+1, ...`); `None` = scenario default.
    pub seeds: Option<usize>,
    /// A dial sweep, if `--sweep` was given.
    pub sweep: Option<Sweep>,
    /// CSV output path, if `--csv` was given.
    pub csv: Option<String>,
    /// `--fast` flag (advisory in 0.1 — the fast/full split lands with more scenarios).
    pub fast: bool,
    /// Override the scenario HORIZON (ticks); `None` = the scenario default. A control knob for
    /// horizon experiments (e.g. the phase-2a monotonicity control: run a tiered scenario at 130
    /// vs 520). Does not change determinism (the shorter run is a prefix of the longer).
    pub horizon: Option<u64>,
}

/// The sweep dials this harness can override (kept small and curated — the A/B toggles).
pub(crate) const KNOWN_DIALS: &[&str] = &[
    "block_volume",
    "c_recip_days",
    "depth_w_d",
    "preempt_theta",
    "v_free_symbols",
    "burn_b_ann",
    "burn_b_max",
    // SIM-UNIFICATION: the per-block reliability TARGET is now THE placement/repair dial
    // (`DynParams::r_target`) — sweepable so its calibration can be re-examined (and the
    // ι-scaling follow-up measured) without touching the frozen default.
    "r_target",
];

/// Parse the CLI args (excluding argv[0]).
pub fn parse_cli(args: &[String]) -> Result<Cli, SimAdvError> {
    let mut scenario: Option<String> = None;
    let mut seeds: Option<usize> = None;
    let mut sweep: Option<Sweep> = None;
    let mut csv: Option<String> = None;
    let mut fast = false;
    let mut horizon: Option<u64> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seeds" => {
                let v = it.next().ok_or(SimAdvError::MissingValue("--seeds"))?;
                let n: usize = v.parse().map_err(|_| SimAdvError::BadSeeds(v.clone()))?;
                if n == 0 {
                    return Err(SimAdvError::BadSeeds(v.clone()));
                }
                seeds = Some(n);
            }
            "--horizon" => {
                let v = it.next().ok_or(SimAdvError::MissingValue("--horizon"))?;
                let h: u64 = v.parse().map_err(|_| SimAdvError::BadHorizon(v.clone()))?;
                if h == 0 {
                    return Err(SimAdvError::BadHorizon(v.clone()));
                }
                horizon = Some(h);
            }
            "--sweep" => {
                let spec = it.next().ok_or(SimAdvError::MissingValue("--sweep"))?;
                sweep = Some(parse_sweep(spec)?);
            }
            "--csv" => {
                let path = it.next().ok_or(SimAdvError::MissingValue("--csv"))?;
                csv = Some(path.clone());
            }
            "--fast" => fast = true,
            flag if flag.starts_with("--") => {
                return Err(SimAdvError::UnknownFlag(flag.to_string()));
            }
            name => {
                if scenario.is_none() {
                    scenario = Some(name.to_string());
                } else {
                    return Err(SimAdvError::UnknownFlag(name.to_string()));
                }
            }
        }
    }

    Ok(Cli {
        scenario: scenario.ok_or(SimAdvError::MissingScenario)?,
        seeds,
        sweep,
        csv,
        fast,
        horizon,
    })
}

/// Parse a `dial=v1,v2,...` sweep spec, validating the dial name.
fn parse_sweep(spec: &str) -> Result<Sweep, SimAdvError> {
    let (dial, rest) = spec
        .split_once('=')
        .ok_or_else(|| SimAdvError::BadSweep(spec.to_string()))?;
    if dial.is_empty() || rest.is_empty() {
        return Err(SimAdvError::BadSweep(spec.to_string()));
    }
    if !KNOWN_DIALS.contains(&dial) {
        return Err(SimAdvError::UnknownDial(
            dial.to_string(),
            KNOWN_DIALS.join(", "),
        ));
    }
    let mut values = Vec::new();
    for part in rest.split(',') {
        let v: f64 = part
            .trim()
            .parse()
            .map_err(|_| SimAdvError::BadSweep(spec.to_string()))?;
        values.push(v);
    }
    if values.is_empty() {
        return Err(SimAdvError::BadSweep(spec.to_string()));
    }
    Ok(Sweep {
        dial: dial.to_string(),
        values,
    })
}

/// Override one named `DynParams` dial (used by the sweep runner). Unknown dial ⇒ error.
pub(crate) fn apply_dial(
    params: &mut DynParams,
    dial: &str,
    value: f64,
) -> Result<(), SimAdvError> {
    match dial {
        "block_volume" => params.block_volume = value,
        "c_recip_days" => params.c_recip_days = value,
        "depth_w_d" => params.depth_w_d = value,
        "preempt_theta" => params.preempt_theta = value,
        "v_free_symbols" => params.v_free_symbols = value,
        "burn_b_ann" => params.burn_b_ann = value,
        "burn_b_max" => params.burn_b_max = value,
        "r_target" => params.r_target = value,
        _ => {
            return Err(SimAdvError::UnknownDial(
                dial.to_string(),
                KNOWN_DIALS.join(", "),
            ));
        }
    }
    Ok(())
}

/// Resolve the seed list for a run: `--seeds N` ⇒ `base, base+1, ..., base+N-1` (base =
/// the scenario's first default seed); otherwise the scenario's default list verbatim.
pub fn resolve_seeds(default_seeds: &[u64], override_count: Option<usize>) -> Vec<u64> {
    match override_count {
        Some(n) => {
            let base = default_seeds.first().copied().unwrap_or(0);
            (0..n as u64).map(|i| base + i).collect()
        }
        None => default_seeds.to_vec(),
    }
}
