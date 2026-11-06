// The two-line verdict (install-i4, install-i14; R3b b4).
//
// `compute_verdict` is pure: it takes counters the daemon already has and
// returns the same thing for CLI and Dashboard (A11). "Node" is the R3 gate and
// may be red; "Protection" is never red in R3 — a new node waits for friends to
// make room, and that is normal (И-6, И-10).

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLevel {
    Green,
    Yellow,
    Red,
}

impl VerdictLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    Service,
    Network,
    Folders,
    Giving,
    Phrase,
    Health,
}

impl CheckId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Network => "network",
            Self::Folders => "folders",
            Self::Giving => "giving",
            Self::Phrase => "phrase",
            Self::Health => "health",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionReason {
    None,
    Uploading,
    WaitingForSpace,
    FewFriends,
    Repairing,
    RecoveryNotReady,
    Scanning,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictCheck {
    pub id: CheckId,
    pub level: VerdictLevel,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeVerdict {
    pub level: VerdictLevel,
    pub headline: String,
    pub checks: Vec<VerdictCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtectionVerdict {
    pub level: VerdictLevel,
    pub restorable_pct: u8,
    pub dr_ready: bool,
    pub reason: ProtectionReason,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub node: NodeVerdict,
    pub protection: ProtectionVerdict,
}

/// Who restarts the daemon. `VIATICUM_SUPERVISOR` says which service manager;
/// absent, the parent process tells us (see `restart::under_service_manager`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    SystemdUser,
    Container,
    Other,
    None,
}

impl Supervisor {
    /// From `VIATICUM_SUPERVISOR` and the service-manager detection.
    pub fn detect(supervisor_env: Option<&str>, under_service_manager: bool) -> Self {
        match supervisor_env.map(str::trim) {
            Some("systemd-user") | Some("systemd") => Self::SystemdUser,
            Some("container") | Some("docker") => Self::Container,
            Some(s) if !s.is_empty() => Self::Other,
            _ if under_service_manager => Self::SystemdUser,
            _ => Self::None,
        }
    }

    pub fn from_env() -> Self {
        Self::detect(
            std::env::var("VIATICUM_SUPERVISOR").ok().as_deref(),
            crate::daemon::restart::under_service_manager(),
        )
    }
}

/// Does the user's systemd linger flag exist? systemd records it as a file in
/// `/var/lib/systemd/linger/<user>`. `None` on a platform without that path.
#[cfg(target_os = "linux")]
pub fn systemd_user_linger() -> Option<bool> {
    let user = std::env::var("USER").ok()?;
    if user.is_empty() {
        return None;
    }
    Some(
        std::path::Path::new("/var/lib/systemd/linger")
            .join(user)
            .exists(),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn systemd_user_linger() -> Option<bool> {
    None
}

/// Everything the verdict reads. Counters come from `status`, the holder pool
/// from the SAME function the worker places on (`holder_pool`), and
/// `scan_settled` from the watcher's startup signal (T10).
#[derive(Debug, Clone)]
pub struct VerdictInputs {
    pub supervisor: Supervisor,
    /// `Some` only when systemd-user would be restarted by linger; `None` for
    /// a container, where login sessions do not matter.
    pub linger: Option<bool>,
    pub uptime_secs: u64,
    pub peers_authenticated: u32,
    /// Placement candidates the worker would actually use, with the
    /// "too few authenticated peers" fallback EXCLUDED (A11, M9).
    pub holder_pool: u32,
    pub folders_total: u32,
    pub folders_error: u32,
    pub scan_settled: bool,
    pub files_total: u32,
    pub files_restorable: u32,
    pub files_degraded: u32,
    /// ST-1 reasons. Until ST-1 merges there is no counter in `status`; the
    /// input stays here so the wiring is one assignment, not a new shape.
    pub blocks_waiting_for_space: u32,
    pub blocks_in_flight: u32,
    pub dr_ready: bool,
    pub phrase_confirmed: bool,
    pub effective_quota_bytes: u64,
    pub health_state: Option<String>,
    /// `Some("relay_limited")` when this node is not directly reachable; no
    /// producer exists in a2, so it is `None` today.
    pub reachability: Option<String>,
}

const NO_PEERS_RED_AFTER_SECS: u64 = 900;

/// Pure two-line verdict.
pub fn compute_verdict(i: &VerdictInputs) -> Verdict {
    let checks = node_checks(i);
    let level = checks
        .iter()
        .map(|c| c.level)
        .max()
        .unwrap_or(VerdictLevel::Green);
    let headline = match level {
        VerdictLevel::Green => "Your node is working.",
        VerdictLevel::Yellow => "Your node needs attention.",
        VerdictLevel::Red => "Your node is not working.",
    }
    .to_string();
    Verdict {
        node: NodeVerdict {
            level,
            headline,
            checks,
        },
        protection: protection_verdict(i),
    }
}

fn check(id: CheckId, level: VerdictLevel, detail: impl Into<String>) -> VerdictCheck {
    VerdictCheck {
        id,
        level,
        detail: detail.into(),
    }
}

fn node_checks(i: &VerdictInputs) -> Vec<VerdictCheck> {
    let mut checks = Vec::with_capacity(6);
    checks.push(service_check(i));
    checks.push(network_check(i));
    checks.push(folders_check(i));
    checks.push(giving_check(i));
    checks.push(phrase_check(i));
    if let Some(health) = &i.health_state {
        checks.push(health_check(health));
    }
    checks
}

fn service_check(i: &VerdictInputs) -> VerdictCheck {
    match i.supervisor {
        Supervisor::SystemdUser => match i.linger {
            Some(true) => check(
                CheckId::Service,
                VerdictLevel::Green,
                "running under systemd-user with linger",
            ),
            _ => check(
                CheckId::Service,
                VerdictLevel::Yellow,
                "linger is off: the node starts only after you log in",
            ),
        },
        Supervisor::Container => check(
            CheckId::Service,
            VerdictLevel::Green,
            "running under a container restart policy",
        ),
        Supervisor::Other => check(
            CheckId::Service,
            VerdictLevel::Green,
            "running under a service manager",
        ),
        Supervisor::None => check(
            CheckId::Service,
            VerdictLevel::Yellow,
            "not running under a service manager: nothing restarts the node if it stops",
        ),
    }
}

fn network_check(i: &VerdictInputs) -> VerdictCheck {
    let relay_limited = i
        .reachability
        .as_deref()
        .is_some_and(|r| r.contains("relay"));
    if i.peers_authenticated == 0 && i.uptime_secs >= NO_PEERS_RED_AFTER_SECS {
        return check(
            CheckId::Network,
            VerdictLevel::Red,
            "no friends online for 15 minutes: check the network and the seed address",
        );
    }
    if relay_limited {
        return check(
            CheckId::Network,
            VerdictLevel::Yellow,
            "reachable only through a relay: forward the listen port for direct connections",
        );
    }
    if i.holder_pool >= 2 {
        return check(
            CheckId::Network,
            VerdictLevel::Green,
            format!("{} friends can store your data", i.holder_pool),
        );
    }
    if i.peers_authenticated == 0 {
        check(
            CheckId::Network,
            VerdictLevel::Yellow,
            "looking for friends…",
        )
    } else {
        check(
            CheckId::Network,
            VerdictLevel::Yellow,
            "few friends online, need ≥ 2",
        )
    }
}

fn folders_check(i: &VerdictInputs) -> VerdictCheck {
    if i.folders_total == 0 {
        return check(
            CheckId::Folders,
            VerdictLevel::Yellow,
            "no folders yet: add the folders you want to keep safe",
        );
    }
    if i.folders_error == i.folders_total {
        return check(
            CheckId::Folders,
            VerdictLevel::Red,
            format!("all {} folders have errors", i.folders_total),
        );
    }
    if i.folders_error > 0 {
        return check(
            CheckId::Folders,
            VerdictLevel::Yellow,
            format!(
                "{} of {} folders have errors",
                i.folders_error, i.folders_total
            ),
        );
    }
    check(
        CheckId::Folders,
        VerdictLevel::Green,
        format!("{} folders are being backed up", i.folders_total),
    )
}

fn giving_check(i: &VerdictInputs) -> VerdictCheck {
    if i.effective_quota_bytes > 0 {
        check(
            CheckId::Giving,
            VerdictLevel::Green,
            "friends have room to store their data here",
        )
    } else {
        check(
            CheckId::Giving,
            VerdictLevel::Yellow,
            "disk full or not detected: friends cannot store data here",
        )
    }
}

fn phrase_check(i: &VerdictInputs) -> VerdictCheck {
    if i.phrase_confirmed {
        check(CheckId::Phrase, VerdictLevel::Green, "phrase confirmed")
    } else {
        check(
            CheckId::Phrase,
            VerdictLevel::Yellow,
            "phrase not confirmed: run `viaticum phrase check`",
        )
    }
}

fn health_check(health: &str) -> VerdictCheck {
    match health {
        "ok" => check(CheckId::Health, VerdictLevel::Green, "health: ok"),
        "degraded" => check(CheckId::Health, VerdictLevel::Yellow, "health: degraded"),
        "failing" => check(CheckId::Health, VerdictLevel::Red, "health: failing"),
        other => check(
            CheckId::Health,
            VerdictLevel::Yellow,
            format!("health: {other}"),
        ),
    }
}

fn protection_verdict(i: &VerdictInputs) -> ProtectionVerdict {
    let total = i.files_total;
    let pct = if total == 0 {
        if i.scan_settled { 100 } else { 0 }
    } else {
        ((i.files_restorable.min(total) as u64 * 100) / total as u64) as u8
    };
    let green = i.dr_ready
        && ((total > 0 && i.files_restorable == total) || (total == 0 && i.scan_settled));
    if green {
        return ProtectionVerdict {
            level: VerdictLevel::Green,
            restorable_pct: pct,
            dr_ready: true,
            reason: ProtectionReason::None,
            detail: format!(
                "{pct}% of your files can be restored from the network. \
                 Recovery with your 24 words: ready."
            ),
        };
    }

    // Order matters (spec §2.2): scanning → few friends → repairing → waiting
    // for space → uploading → recovery not ready. Never red in R3.
    let reason = if !i.scan_settled {
        ProtectionReason::Scanning
    } else if i.holder_pool < 2 {
        ProtectionReason::FewFriends
    } else if i.files_degraded > 0 {
        ProtectionReason::Repairing
    } else if i.blocks_waiting_for_space > 0 {
        ProtectionReason::WaitingForSpace
    } else if i.blocks_in_flight > 0 || (i.dr_ready && total > 0) {
        // With `dr_ready` true the catalog is recoverable by phrase; what is
        // left is the files still reaching their holders. Until СТ-1 provides
        // the refusal counters, this is the honest i14 wording.
        ProtectionReason::Uploading
    } else {
        ProtectionReason::RecoveryNotReady
    };
    let recovery = if i.dr_ready { "ready" } else { "not ready yet" };
    let detail = match reason {
        ProtectionReason::Scanning => format!(
            "{pct}% of your files can be restored from the network. \
             Scanning your folders… this is normal right after start."
        ),
        ProtectionReason::FewFriends => format!(
            "{pct}% of your files can be restored from the network. \
             Few friends online, need ≥ 2. Recovery with your 24 words: {recovery}."
        ),
        ProtectionReason::Repairing => format!(
            "{pct}% of your files can be restored from the network. \
             Repairing: some copies are missing and the network is restoring them. \
             Recovery with your 24 words: {recovery}."
        ),
        ProtectionReason::WaitingForSpace => format!(
            "{pct}% of your files can be restored from the network. \
             Friends have no room for you yet — normal for a new node, can take weeks. \
             Recovery with your 24 words: {recovery}."
        ),
        ProtectionReason::Uploading => format!(
            "{pct}% of your files can be restored from the network. \
             Uploading or waiting for space — normal for a new node, can take weeks. \
             Recovery with your 24 words: {recovery}."
        ),
        ProtectionReason::RecoveryNotReady | ProtectionReason::None => format!(
            "{pct}% of your files can be restored from the network. \
             Recovery with your 24 words: {recovery}."
        ),
    };
    ProtectionVerdict {
        level: VerdictLevel::Yellow,
        restorable_pct: pct,
        dr_ready: i.dr_ready,
        reason,
        detail,
    }
}
