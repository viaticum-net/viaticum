// The restore estimates (К-b3, restore-i39; spec v3.8 §3, v3.9 WARN-1).

use super::*;

const T: u16 = 65_535;

fn e_pad(k: u32) -> f64 {
    k as f64 * T as f64
}

/// The network estimate in units of `E_pad`: 4.24 at K = 257 and 4.09 at K = 4096 (v3.9 WARN-1),
/// not the 5.23 / 5.09 of the first brief; the budget takes it rounded up to a whole MiB.
#[test]
fn estimate_restore_network_in_e_pad_units_at_the_table_ks() {
    let form = |k: u32| {
        let l = intermediate_symbols(k) as u64;
        (2 * (k as u64 + 3) + l + 3 + k as u64 + 1) * T as u64 + 3277 * k as u64
    };
    for (k, lo, hi) in [(257u32, 4.23, 4.25), (4096, 4.08, 4.10)] {
        let unrounded = form(k) as f64 / e_pad(k);
        assert!((lo..hi).contains(&unrounded), "K = {k}: {unrounded:.4}");
        let taken = estimate_restore_network(k, T);
        assert!(
            taken >= form(k) && taken < form(k) + MIB,
            "K = {k}: rounded up to a MiB"
        );
    }
}

/// The form: `(2·k_eff + L(k) + o + k + 1)·t + 3277·k`, rounded up to a MiB.
#[test]
fn estimate_restore_network_is_the_form_of_the_spec() {
    for k in [1u32, 2, 10, 257, 306, 1307, 4096, 16_385, 56_403] {
        let l = intermediate_symbols(k) as u64;
        let k_eff = k as u64 + 3;
        let bytes = (2 * k_eff + l + 3 + k as u64 + 1) * T as u64 + 3277 * k as u64;
        assert_eq!(
            estimate_restore_network(k, T),
            bytes.div_ceil(MIB) * MIB,
            "K = {k}"
        );
    }
}

/// K above the RaptorQ limit is clamped, as in `encoder_held`: the decoder refuses it before it
/// allocates, and an estimate must not panic.
#[test]
fn estimate_restore_network_clamps_k_and_does_not_panic() {
    assert_eq!(
        estimate_restore_network(u32::MAX, T),
        estimate_restore_network(RAPTORQ_MAX_SOURCE_SYMBOLS, T)
    );
    assert!(estimate_restore_network(1_000_000, T) >= MIB);
}

#[test]
fn estimate_restore_local_and_plaintext_follow_the_spec() {
    let (k, s) = (257u32, 64 * MIB);
    let local = 2 * k as u64 * T as u64 + s + ZSTD_WINDOW_BYTES;
    assert_eq!(estimate_restore_local(k, T, s), local.div_ceil(MIB) * MIB);
    let plain = 17 * MIB + s + ZSTD_WINDOW_BYTES;
    assert_eq!(estimate_restore_plaintext(17 * MIB, s), plain);
    // The window is the prediction of the spec: at most 8 MiB.
    assert_eq!(ZSTD_WINDOW_BYTES, 8 * MIB);
}
