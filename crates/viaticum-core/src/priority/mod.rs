#[cfg(test)]
mod tests;

/// Compute the scheduling priority for a block in the unified work queue.
///
/// Formula: `priority = importance × (1 + k × (current_alive / n_target))`
///
/// The completion bonus (`k × current_alive / n_target`) rewards blocks that are
/// closer to their holder target, biasing the worker toward finishing near-complete
/// blocks before starting fresh ones — while still allowing high-importance blocks
/// to outbid low-importance near-done blocks when the importance gap is large enough.
///
/// # Arguments
///
/// * `importance` — file importance in [0.0, 1.0]. Clamped defensively.
/// * `current_alive` — count of placements currently in `Alive` state.
/// * `n_target` — target holder count for this block. If 0, returns `importance`.
/// * `k` — completion bonus coefficient (from config). Clamped to ≥ 0.0.
///
/// # Returns
///
/// Priority value in [0.0, importance × (1.0 + k)]. Higher is more urgent.
///
/// # Panics
///
/// Never panics. All edge cases handled by defensive clamping.
pub fn priority(importance: f64, current_alive: u32, n_target: u32, k: f64) -> f64 {
    let imp = importance.clamp(0.0, 1.0);
    let k = k.max(0.0);

    if n_target == 0 {
        return imp;
    }

    let ratio = (current_alive as f64 / n_target as f64).min(1.0);
    imp * (1.0 + k * ratio)
}
