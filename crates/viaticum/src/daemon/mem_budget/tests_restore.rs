// The restore estimates (К-b3, restore-i39; spec v3.8 §3, v3.9 WARN-1).

use super::*;

const T: u16 = 65_535;

fn e_pad(k: u32) -> f64 {
    k as f64 * T as f64
}

/// The network estimate in units of `E_pad`, without the window of zstd: 4.24 at K = 257 and 4.09
/// at K = 4096 (v3.9 WARN-1), not the 5.23 / 5.09 of the first brief; the budget takes it with the
/// window (v3.9b W4), rounded up to a whole MiB.
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
            taken >= form(k) + ZSTD_WINDOW_BYTES && taken < form(k) + ZSTD_WINDOW_BYTES + MIB,
            "K = {k}: with the window, rounded up to a MiB"
        );
    }
}

/// The form: `(2·k_eff + L(k) + o + k + 1)·t + 3277·k + window`, rounded up to a MiB.
#[test]
fn estimate_restore_network_is_the_form_of_the_spec() {
    for k in [1u32, 2, 10, 257, 306, 1307, 4096, 16_385, 56_403] {
        let l = intermediate_symbols(k) as u64;
        let k_eff = k as u64 + 3;
        let bytes = (2 * k_eff + l + 3 + k as u64 + 1) * T as u64
            + 3277 * k as u64
            + (2 * MIB + 128 * 1024);
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
    // The window is in the decode stage (the count of the plaintext runs under it); the stage of
    // the plaintext and the local tier hold the context of the one-shot call only (v3.9b W4).
    let local = 2 * k as u64 * T as u64 + s + DCTX_BYTES;
    assert_eq!(estimate_restore_local(k, T, s), local.div_ceil(MIB) * MIB);
    let plain = 17 * MIB + s + DCTX_BYTES;
    assert_eq!(estimate_restore_plaintext(17 * MIB, s), plain);
    assert_eq!(ZSTD_WINDOW_BYTES, 2 * MIB + 128 * 1024);
    assert_eq!(DCTX_BYTES, MIB);
}

/// The numbers of the spec v3.9b (W4), from the estimates themselves: a block of 16 MiB (K = 257)
/// takes 71 MiB (70.24 unrounded) for the decode stage, and the plaintext stage keeps that permit
/// (no regrant) while `E + S + 1 MiB` fits it: S up to 53 MiB at ×3.3 (the spec: ≈ 53). A block of
/// 64 KiB (K = 1) takes 5 MiB (4.63): a file of up to 3.94 MiB goes without a regrant (the spec
/// says ≈ 4.9; that is 5 MiB less the block, without the 1 MiB of the context of the one-shot
/// call).
#[test]
fn restore_estimates_at_the_numbers_of_v3_9b() {
    let net = estimate_restore_network(257, T);
    assert_eq!(net, 71 * MIB, "K = 257: {} MiB", net / MIB);
    // S at the compression of ×3.3 that the spec takes (E = S / 3.3): the largest S whose
    // plaintext stage still fits the permit of the decode stage.
    let fits = |s: u64| estimate_restore_plaintext((s as f64 / 3.3) as u64, s) <= net;
    let largest = (1..200u64).rev().find(|&mib| fits(mib * MIB)).unwrap();
    assert_eq!(
        largest, 53,
        "no regrant up to S = {largest} MiB (the spec: ≈ 53)"
    );
    // A block of 64 KiB (K = 1): the decode stage (5 MiB) holds the plaintext stage of a file of
    // 4 MiB less the block, and not of one byte more.
    let small = estimate_restore_network(1, T);
    assert_eq!(small, 5 * MIB, "K = 1: decode stage {} MiB", small / MIB);
    let block = T as u64;
    assert!(estimate_restore_plaintext(block, 4 * MIB - block) <= small);
    assert!(estimate_restore_plaintext(block, 4 * MIB - block + 1) > small);
}
