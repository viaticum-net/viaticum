//! Network knowledge in `status` (network-i14, C-DK Р-7) and the test-only
//! `net-probe` requests (C-DK Р-16).
//!
//! `known_devices` is read from the PeerRecord table — what this node KNOWS;
//! `authenticated_devices` from the swarm — what it is connected to now. A
//! scenario checks knowledge on the OTHER node (the cert exchange is mutual, so
//! "Y in known(X)" implies "X in known(Y)").

#[cfg(test)]
mod tests;

use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord};

use super::bytes_to_hex_8;
use crate::daemon::handle::DaemonState;
use crate::daemon::network::address_book::is_known;

/// DeviceIds as their first 8 bytes in hex, sorted (the `identity_hex` form of
/// the peer rows).
pub(crate) fn devices_hex8_sorted<'a>(
    devices: impl IntoIterator<Item = &'a DeviceId>,
) -> Vec<String> {
    let mut out: Vec<String> = devices.into_iter().map(|d| bytes_to_hex_8(&d.0)).collect();
    out.sort();
    out
}

/// The master whose devices are siblings, not known peers (network-i14): the
/// cluster's master, the anchor the swarm checks certificates against and seeds
/// its known set by (`AddressBook::new`). On a device that joined a cluster it
/// is the founder's identity, not this device's own `identity_pub`; that one is
/// used only when there is no cluster state (dispatch tests).
pub(crate) fn status_cluster_master(state: &DaemonState) -> IdentityPub {
    match state.cluster_state.as_ref() {
        Some(cluster) => cluster
            .lock()
            .expect("cluster_state lock poisoned")
            .master_pub(),
        None => state.identity_pub,
    }
}

/// network-i14: the known peers among `peers` (another master, a dialable
/// address; see `address_book::is_known`), first 8 bytes hex, sorted.
pub(crate) fn known_devices_hex8(
    peers: &[PeerRecord],
    own_master: &IdentityPub,
    own_device: &DeviceId,
) -> Vec<String> {
    devices_hex8_sorted(
        peers
            .iter()
            .filter(|p| is_known(p, own_master, own_device))
            .map(|p| &p.device_id),
    )
}

#[cfg(feature = "e2e-tools")]
pub(crate) use e2e::{dispatch_e2e_disconnect, dispatch_e2e_reach};

#[cfg(feature = "e2e-tools")]
mod e2e {
    use std::time::Instant;

    use viaticum_core::types::{DeviceId, PeerRecord, Timestamp, hex_encode};

    use crate::cli::types::CliResponse;
    use crate::daemon::handle::DaemonState;

    /// The PeerRecord device whose hex DeviceId starts with `hex` (at least 16
    /// hex chars, case-insensitive). Unknown or ambiguous = `Err` in words.
    pub(crate) fn resolve_device_hex(peers: &[PeerRecord], hex: &str) -> Result<DeviceId, String> {
        let want = hex.trim().to_ascii_lowercase();
        if want.len() < 16 || want.len() > 64 || !want.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "device {hex:?}: want 16..64 hex chars of a DeviceId"
            ));
        }
        let mut hits = peers
            .iter()
            .map(|p| p.device_id)
            .filter(|d| hex_encode(&d.0).starts_with(&want));
        match (hits.next(), hits.next()) {
            (Some(d), None) => Ok(d),
            (None, _) => Err(format!("device {want}: no PeerRecord with this id")),
            (Some(_), Some(_)) => Err(format!("device {want}: prefix matches several peers")),
        }
    }

    /// The device of `hex` from this node's PeerRecords, or why not (in words).
    fn resolve(state: &DaemonState, hex: &str) -> Result<DeviceId, String> {
        let peers = state
            .db
            .list_all_peers()
            .map_err(|e| format!("db error listing peers: {e}"))?;
        resolve_device_hex(&peers, hex)
    }

    /// `net-probe disconnect`: close every connection to the peer (both sides
    /// then drop it from `authenticated_devices`).
    pub(crate) async fn dispatch_e2e_disconnect(state: &DaemonState, hex: &str) -> CliResponse {
        let device = match resolve(state, hex) {
            Ok(d) => d,
            Err(e) => return CliResponse::Error(e),
        };
        let Some(swarm) = state.swarm_handle.as_ref() else {
            return CliResponse::Error("swarm not available".to_string());
        };
        let t0 = Instant::now();
        match swarm.disconnect_device(device).await {
            Ok(was_connected) => CliResponse::E2eProbe {
                device_hex: hex_encode(&device.0),
                detail: if was_connected {
                    "disconnected".to_string()
                } else {
                    "was not connected".to_string()
                },
                elapsed_ms: t0.elapsed().as_millis() as u64,
            },
            Err(e) => CliResponse::Error(format!("disconnect {}: {e}", hex_encode(&device.0))),
        }
    }

    /// `net-probe reach`: send a PeerAnnounce (harmless, idempotent; answered
    /// with an Ack) through `send_to_device` exactly as production requests go:
    /// a peer that is not connected is dialed on demand (network-i42; the log
    /// says `swarm: on-demand dial … msg=PeerAnnounce`).
    pub(crate) async fn dispatch_e2e_reach(state: &DaemonState, hex: &str) -> CliResponse {
        let device = match resolve(state, hex) {
            Ok(d) => d,
            Err(e) => return CliResponse::Error(e),
        };
        let Some(swarm) = state.swarm_handle.as_ref() else {
            return CliResponse::Error("swarm not available".to_string());
        };
        let announce = swarm.build_peer_announce(Timestamp::now());
        let t0 = Instant::now();
        let result = swarm
            .send_to_device(
                device,
                viaticum_core::messages::Message::PeerAnnounce(announce),
            )
            .await;
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        match result {
            Ok(_) => {
                tracing::info!(device = %device, elapsed_ms, "e2e: reach ok");
                CliResponse::E2eProbe {
                    device_hex: hex_encode(&device.0),
                    detail: "reached".to_string(),
                    elapsed_ms,
                }
            }
            Err(e) => {
                tracing::info!(device = %device, elapsed_ms, err = %e, "e2e: reach failed");
                CliResponse::Error(format!(
                    "reach {} failed after {elapsed_ms} ms: {e}",
                    hex_encode(&device.0)
                ))
            }
        }
    }
}
