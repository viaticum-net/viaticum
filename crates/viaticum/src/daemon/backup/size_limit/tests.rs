use super::*;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
const NAS_RAM: u64 = 8_160_437_862; // 7.6 GiB

#[test]
fn size_limit_auto_is_ram_over_32_floored_and_clamped() {
    let cases: [(u64, u64); 8] = [
        (GIB, 32 * MIB),         // 1 GiB / 32 = 32 MiB: the floor
        (2 * GIB, 64 * MIB),     //
        (4 * GIB, 128 * MIB),    //
        (NAS_RAM, NAS_RAM / 32), // the 7.6 GiB NAS of the spec: 243 MiB and a bit
        (8 * GIB, 256 * MIB),    //
        (16 * GIB, 512 * MIB),   //
        (32 * GIB, GIB),         // the cap
        (64 * GIB, GIB),         //
    ];
    for (ram, want) in cases {
        assert_eq!(auto_max_file_size(ram), want, "ram {ram}");
    }
    assert_eq!(auto_max_file_size(NAS_RAM) / MIB, 243);
    // Below the floor's RAM: still the floor.
    assert_eq!(auto_max_file_size(GIB / 2), AUTO_FILE_SIZE_FLOOR);
    // Unknown RAM: the assumed 4 GiB.
    assert_eq!(auto_max_file_size(0), 128 * MIB);
}

#[test]
fn size_limit_override_wins_over_auto() {
    assert_eq!(effective_max_file_size(256, 64 * GIB), 256 * MIB);
    assert_eq!(effective_max_file_size(3072, GIB), 3 * GIB);
    assert_eq!(effective_max_file_size(0, 8 * GIB), 256 * MIB);
    // Never above the RaptorQ ceiling, whatever the caller passes.
    assert_eq!(effective_max_file_size(100_000, GIB), 3 * GIB);
}

#[test]
fn effective_pack_size_is_half_the_file_limit_at_most() {
    // 8 GiB machine: limit 243 MiB, pack min(128, 121).
    assert_eq!(
        effective_pack_size(128 * MIB, 243 * MIB),
        121 * MIB + MIB / 2
    );
    // Big machine: the configured size stays.
    assert_eq!(effective_pack_size(128 * MIB, GIB), 128 * MIB);
    assert_eq!(effective_pack_size(4 * MIB, 64 * MIB), 4 * MIB);
    // Whatever the inputs, a pack never exceeds half the file limit.
    for max_file in [32 * MIB, 100 * MIB, GIB, 3 * GIB] {
        assert!(effective_pack_size(1024 * MIB, max_file) <= max_file / 2);
    }
}

#[test]
fn ram_parsers_read_meminfo_and_cgroup_text() {
    let meminfo = "MemTotal:        7975392 kB\nMemFree:          123 kB\n";
    assert_eq!(parse_meminfo_total(meminfo), Some(7_975_392 * 1024));
    assert_eq!(parse_meminfo_total("nothing here"), None);

    assert_eq!(parse_cgroup_memory_max("max\n"), None);
    assert_eq!(parse_cgroup_memory_max("2147483648\n"), Some(2 * GIB));

    assert_eq!(
        parse_cgroup_v2_path("0::/user.slice/app.service\n"),
        Some("/user.slice/app.service")
    );
    assert_eq!(parse_cgroup_v2_path("12:memory:/x\n"), None);

    // The lesser of the host's RAM and the cgroup limit.
    assert_eq!(combine_ram(Some(16 * GIB), Some(2 * GIB)), Some(2 * GIB));
    assert_eq!(combine_ram(Some(2 * GIB), Some(16 * GIB)), Some(2 * GIB));
    assert_eq!(combine_ram(Some(2 * GIB), None), Some(2 * GIB));
    assert_eq!(combine_ram(None, Some(GIB)), Some(GIB));
    assert_eq!(combine_ram(None, None), None);
}

#[test]
fn size_limits_compute_combines_override_and_pack() {
    let auto = SizeLimits::compute(0, 128 * MIB, 8 * GIB);
    assert_eq!(auto.max_file_size, 256 * MIB);
    assert_eq!(auto.pack_size, 128 * MIB);
    assert!(!auto.overridden);

    let over = SizeLimits::compute(1024, 128 * MIB, 8 * GIB);
    assert!(over.overridden);
    assert_eq!(over.max_file_size, GIB);
    assert_eq!(over.auto_max_file_size, 256 * MIB);
    assert_eq!(over.pack_size, 128 * MIB);
}

#[test]
fn format_size_prints_mib_below_a_gib_and_gib_above() {
    assert_eq!(format_size(243 * MIB), "243 MiB");
    assert_eq!(format_size(GIB), "1.0 GiB");
    assert_eq!(format_size((7.6 * GIB as f64) as u64), "7.6 GiB");
}

#[test]
fn cgroup_v1_limit_parses_and_unlimited_is_none() {
    assert_eq!(parse_cgroup_v1_memory_limit("2147483648\n"), Some(2 * GIB));
    // The kernel's "no limit": LONG_MAX rounded down to a page, and anything from 2^62.
    assert_eq!(parse_cgroup_v1_memory_limit("9223372036854771712\n"), None);
    assert_eq!(parse_cgroup_v1_memory_limit("9223372036854775807"), None);
    assert_eq!(
        parse_cgroup_v1_memory_limit(&(1u64 << 62).to_string()),
        None
    );
    assert_eq!(
        parse_cgroup_v1_memory_limit(&((1u64 << 62) - 1).to_string()),
        Some((1u64 << 62) - 1)
    );
    assert_eq!(parse_cgroup_v1_memory_limit("max"), None);
    assert_eq!(parse_cgroup_v1_memory_limit(""), None);
}

#[test]
fn cgroup_v1_path_is_the_memory_controller_line() {
    let text = "12:cpu,cpuacct:/a\n11:memory:/docker/abc\n1:name=systemd:/x\n0::/\n";
    assert_eq!(parse_cgroup_v1_memory_path(text), Some("/docker/abc"));
    let combined = "5:cpu,memory,blkio:/svc\n";
    assert_eq!(parse_cgroup_v1_memory_path(combined), Some("/svc"));
    assert_eq!(parse_cgroup_v1_memory_path("0::/user.slice\n"), None);
    assert_eq!(parse_cgroup_v1_memory_path("4:memory_x:/nope\n"), None);
    assert_eq!(parse_cgroup_v1_memory_path("garbage"), None);
    // A v2 path is not a v1 path.
    assert_eq!(parse_cgroup_v2_path(text), Some("/"));
}

#[test]
fn cgroup_chain_takes_the_lowest_limit_up_to_the_root() {
    let root = tempfile::TempDir::new().unwrap();
    let child = root.path().join("parent/child");
    std::fs::create_dir_all(&child).unwrap();
    let put = |dir: &std::path::Path, text: &str| {
        std::fs::write(dir.join("memory.limit_in_bytes"), text).unwrap()
    };
    put(root.path(), "9223372036854771712\n");
    put(&root.path().join("parent"), "4294967296\n");
    put(&child, "8589934592\n");
    let lowest = |rel: &str| {
        lowest_up_the_chain(
            root.path(),
            rel,
            "memory.limit_in_bytes",
            parse_cgroup_v1_memory_limit,
        )
    };
    assert_eq!(
        lowest("/parent/child"),
        Some(4 * GIB),
        "the parent binds the child"
    );
    assert_eq!(lowest("/parent"), Some(4 * GIB));
    assert_eq!(lowest("/"), None, "the root has no limit");
}
