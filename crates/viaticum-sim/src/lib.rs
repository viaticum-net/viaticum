//! `viaticum-sim` — offline design-verification simulator for the 4R trust model.
//!
//! This crate is NOT the daemon and is NOT production code. It is the harness
//! that drives the shared `viaticum_core::four_r` decision kernel with a
//! synthetic population, to verify model behaviour (loop stability, eviction
//! order, ...) at scales/horizons a live e2e test cannot reach.
//!
//! ## The structural anti-oracle (load-bearing)
//!
//! `viaticum-core` does **not** depend on `viaticum-sim`; the edge runs one way
//! only. Therefore a kernel function physically cannot reference this crate's
//! hidden [`generator::Population`] / [`generator::OwnerGt`] (the ground-truth
//! archetype + hidden hazards). The old Python sims' original sin
//! (`S = STORAGE_RATIOS[archetype[peer]]` fed straight into a trust formula) is
//! compile-impossible here.
//!
//! ## The four layers
//!
//! * [`generator`] — hidden ground-truth (archetypes, true pairwise service).
//! * [`observer`] — the single trust boundary: hidden event → first-hand shadow.
//! * [`engine`] — discrete-event loop; calls the kernel each tick.
//! * [`evaluator`] — god-view scorer; never feeds back into a decision.
//!
//! ## Surface-form discovery (SIM-12 / SIM-12b — offline calibration)
//!
//! * [`failure_gen`] — honest hazard generator; the hidden true FORM lives here
//!   and never reaches the estimator's decision.
//! * [`surface_fit`] — the OFFLINE nonparametric estimator (Kaplan-Meier + binned
//!   hazard + form classifier). Blind to the generator's form by construction.
//! * [`sim12`] — discover the surface form on honest data (distinguish forms).
//! * [`sim12b`] — graceful degradation under mis-specification (out-of-family).
//!
//! ## Diversity-cap (SIM-6 — addr-correlate placement)
//!
//! * [`sim6`] — the diversity-cap by risk-correlate: a hidden farm (N master-ids,
//!   one subnet) drops synchronously; the addr-correlate cap (policy B) raises the
//!   attacker's address-floor vs the master-id-only cap (policy A). STRUCTURAL: the
//!   sign holds across a dial sweep, the cost-ratio is reported, not pinned.
//!
//! ## Per-symbol block survival (SIM-R1 — K3 calibration)
//!
//! * [`sim_r1`] — the per-symbol forecast `p_i = surface × s(r;φ_O)` (Route A:
//!   holder reliability; Route B: eviction along the owner's ι-ladder) vs a god-view
//!   evaluator that realises hardware-death + two-level eviction. STRUCTURAL signs
//!   (robust to dials): the forecast is conservative (≤ actual), high-ι symbols
//!   actually survive more, and the per-symbol forecast beats the
//!   aggregate-per-holder-average it replaces.
//!
//! ## Dynamic harness (Experiment-1 — honest convergence over time)
//!
//! * [`sim_dynamic`] — the DYNAMIC time-loop harness (the §10 buildable spec of
//!   `sim_dynamic_design.md`). Stateful agent nodes with hidden archetypes drive
//!   behaviour over weekly ticks (place / PoS / capital / eviction / repair /
//!   churn), all through the observer boundary. Experiment-1 measures honest
//!   convergence (earned-G gap + Spearman ρ), reciprocity on god-view served
//!   volumes, DR sanity, and newcomer bootstrap — un-poisoned by the storage-oracle
//!   that inflated the Phase-1 Python sims.

pub mod engine;
pub mod evaluator;
pub mod failure_gen;
pub mod generator;
pub mod observer;
pub mod sim12;
pub mod sim12b;
pub mod sim2;
pub mod sim6;
pub mod sim_dynamic;
pub mod sim_r1;
pub mod surface_fit;
