// Unit tests of the pure two-line verdict (install-i4, i14; M9, M17).

use super::*;

fn ok_inputs() -> VerdictInputs {
    VerdictInputs {
        supervisor: Supervisor::Container,
        linger: None,
        uptime_secs: 3600,
        peers_authenticated: 3,
        holder_pool: 3,
        folders_total: 2,
        folders_error: 0,
        scan_settled: true,
        files_total: 3,
        files_restorable: 3,
        files_degraded: 0,
        blocks_waiting_for_space: 0,
        blocks_in_flight: 0,
        dr_ready: true,
        phrase_confirmed: true,
        effective_quota_bytes: 7 * 1_073_741_824,
        health_state: None,
        reachability: None,
    }
}

fn check_of(v: &Verdict, id: CheckId) -> &VerdictCheck {
    v.node
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("missing check {id:?}"))
}

#[test]
fn node_green_when_all_ok() {
    let v = compute_verdict(&ok_inputs());
    assert_eq!(v.node.level, VerdictLevel::Green);
    assert_eq!(v.node.headline, "Your node is working.");
    assert!(
        v.node.checks.iter().all(|c| c.level == VerdictLevel::Green),
        "{:?}",
        v.node.checks
    );
    assert_eq!(v.protection.level, VerdictLevel::Green);
    assert_eq!(v.protection.reason, ProtectionReason::None);
    assert_eq!(v.protection.restorable_pct, 100);
    assert!(v.protection.detail.contains("100% of your files"));
    assert!(
        v.protection
            .detail
            .contains("Recovery with your 24 words: ready.")
    );
}

/// M9: a node that sees only the seed has one authenticated peer and a holder
/// pool of one — yellow. Counting raw peer records (or the worker's fallback)
/// would wrongly make it green.
#[test]
fn node_yellow_when_only_seed() {
    let mut i = ok_inputs();
    i.peers_authenticated = 1;
    i.holder_pool = 1;
    i.files_total = 0;
    i.files_restorable = 0;
    i.dr_ready = false;
    let v = compute_verdict(&i);
    assert_eq!(v.node.level, VerdictLevel::Yellow);
    assert_eq!(check_of(&v, CheckId::Network).level, VerdictLevel::Yellow);
    assert!(
        check_of(&v, CheckId::Network)
            .detail
            .contains("few friends online, need ≥ 2"),
        "{:?}",
        check_of(&v, CheckId::Network)
    );
}

#[test]
fn node_red_after_15_min_without_peers() {
    let mut i = ok_inputs();
    i.peers_authenticated = 0;
    i.holder_pool = 0;
    i.uptime_secs = 900;
    let v = compute_verdict(&i);
    assert_eq!(v.node.level, VerdictLevel::Red);
    assert_eq!(check_of(&v, CheckId::Network).level, VerdictLevel::Red);

    i.uptime_secs = 899;
    let v = compute_verdict(&i);
    assert_eq!(v.node.level, VerdictLevel::Yellow, "15 min is the red line");
}

#[test]
fn node_red_when_all_folders_error() {
    let mut i = ok_inputs();
    i.folders_total = 2;
    i.folders_error = 2;
    let v = compute_verdict(&i);
    assert_eq!(v.node.level, VerdictLevel::Red);
    assert_eq!(check_of(&v, CheckId::Folders).level, VerdictLevel::Red);
}

#[test]
fn node_service_linger_ignored_in_container() {
    let mut i = ok_inputs();
    i.supervisor = Supervisor::Container;
    i.linger = None;
    let v = compute_verdict(&i);
    assert_eq!(check_of(&v, CheckId::Service).level, VerdictLevel::Green);

    i.supervisor = Supervisor::SystemdUser;
    i.linger = Some(false);
    let v = compute_verdict(&i);
    assert_eq!(check_of(&v, CheckId::Service).level, VerdictLevel::Yellow);

    i.linger = Some(true);
    let v = compute_verdict(&i);
    assert_eq!(check_of(&v, CheckId::Service).level, VerdictLevel::Green);
}

#[test]
fn health_none_is_absent_from_checks() {
    let v = compute_verdict(&ok_inputs());
    assert!(!v.node.checks.iter().any(|c| c.id == CheckId::Health));

    let mut i = ok_inputs();
    i.health_state = Some("failing".into());
    let v = compute_verdict(&i);
    assert_eq!(check_of(&v, CheckId::Health).level, VerdictLevel::Red);
    assert_eq!(v.node.level, VerdictLevel::Red);
}

/// M17: a brand-new node with zero restorable files and an hour of uptime is
/// yellow with a reason, NEVER red.
#[test]
fn protection_never_red_for_newcomer() {
    let mut i = ok_inputs();
    i.uptime_secs = 7200;
    i.files_total = 5;
    i.files_restorable = 0;
    i.files_degraded = 0;
    i.dr_ready = false;
    i.phrase_confirmed = false;
    let v = compute_verdict(&i);
    assert_eq!(v.protection.level, VerdictLevel::Yellow);
    assert_ne!(v.protection.level, VerdictLevel::Red);

    // And every input shape we can think of stays yellow/green.
    for (total, restorable, degraded, pool, waiting, in_flight, scan) in [
        (0, 0, 0, 0, 0, 0, false),
        (0, 0, 0, 0, 0, 0, true),
        (5, 0, 5, 0, 1, 1, true),
        (5, 4, 1, 3, 0, 0, true),
        (5, 5, 0, 3, 0, 0, true),
    ] {
        i.files_total = total;
        i.files_restorable = restorable;
        i.files_degraded = degraded;
        i.holder_pool = pool;
        i.blocks_waiting_for_space = waiting;
        i.blocks_in_flight = in_flight;
        i.scan_settled = scan;
        let v = compute_verdict(&i);
        assert_ne!(
            v.protection.level,
            VerdictLevel::Red,
            "protection must never be red in R3"
        );
    }
}

#[test]
fn protection_zero_files_green_only_after_scan_settled() {
    let mut i = ok_inputs();
    i.files_total = 0;
    i.files_restorable = 0;
    i.dr_ready = true;
    i.scan_settled = false;
    let v = compute_verdict(&i);
    assert_eq!(v.protection.level, VerdictLevel::Yellow);
    assert_eq!(v.protection.reason, ProtectionReason::Scanning);

    i.scan_settled = true;
    let v = compute_verdict(&i);
    assert_eq!(v.protection.level, VerdictLevel::Green);
    assert_eq!(v.protection.restorable_pct, 100);
}

#[test]
fn protection_waiting_for_space_reason() {
    let mut i = ok_inputs();
    i.files_total = 4;
    i.files_restorable = 2;
    i.dr_ready = false;
    i.blocks_waiting_for_space = 3;
    let v = compute_verdict(&i);
    assert_eq!(v.protection.level, VerdictLevel::Yellow);
    assert_eq!(v.protection.reason, ProtectionReason::WaitingForSpace);
    assert!(
        v.protection
            .detail
            .contains("Friends have no room for you yet"),
        "{}",
        v.protection.detail
    );
    assert!(v.protection.detail.contains("normal for a new node"));
}

#[test]
fn protection_uploading_reason_uses_i14_words() {
    let mut i = ok_inputs();
    i.files_total = 4;
    i.files_restorable = 2;
    i.dr_ready = false;
    i.blocks_in_flight = 2;
    let v = compute_verdict(&i);
    assert_eq!(v.protection.reason, ProtectionReason::Uploading);
    assert!(
        v.protection
            .detail
            .contains("Uploading or waiting for space"),
        "{}",
        v.protection.detail
    );
}

#[test]
fn supervisor_detection() {
    assert_eq!(
        Supervisor::detect(Some("systemd-user"), false),
        Supervisor::SystemdUser
    );
    assert_eq!(
        Supervisor::detect(Some("container"), false),
        Supervisor::Container
    );
    assert_eq!(Supervisor::detect(Some("other"), false), Supervisor::Other);
    assert_eq!(Supervisor::detect(None, true), Supervisor::SystemdUser);
    assert_eq!(Supervisor::detect(None, false), Supervisor::None);
}
