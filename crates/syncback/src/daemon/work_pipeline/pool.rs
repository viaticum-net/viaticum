// Pool snapshot and signature computation for the unified work pipeline.
//
// pool_signature: stable hash of the current holder pool composition.
// snapshot_pool: build pool from authenticated peers + DB trust.

use std::hash::{Hash, Hasher};

use syncback_core::db::Db;
use syncback_core::placement::HolderCandidate;
use syncback_core::types::DeviceId;

use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::peer_backoff::PeerBackoff;

/// Snapshot of the current holder pool.
pub struct PoolSnapshot {
    /// Authenticated peers with non-zero trust (filtered, ready for allocation).
    pub candidates: Vec<HolderCandidate>,
    /// Stable hash of this pool's composition.
    /// Changes when the peer set or trust buckets change.
    /// `0` = empty pool (sentinel used by `reset_all_cooldowns` and `next_work_item`).
    pub signature: u64,
}

/// Compute pool_signature from a candidate list.
///
/// Signature = DefaultHasher over sorted (device_id_bytes ++ trust_bucket_byte) pairs.
/// Trust is bucketed to nearest 0.05 to avoid micro-changes causing spurious re-encodes.
///
/// Invariant: `pool_signature(&[]) == 0`.
pub fn pool_signature(candidates: &[HolderCandidate]) -> u64 {
    if candidates.is_empty() {
        return 0;
    }
    let mut pairs: Vec<([u8; 32], u8)> = candidates
        .iter()
        .map(|c| (c.device_id.0, trust_bucket(c.trust)))
        .collect();
    // Sort by device_id bytes for stable ordering.
    pairs.sort_unstable_by_key(|(did, _)| *did);

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (did, bucket) in &pairs {
        did.hash(&mut hasher);
        bucket.hash(&mut hasher);
    }
    // Reserve 0 as the sentinel for "empty pool".
    // In the astronomically unlikely case that the hash is 0, use 1.
    let sig = Hasher::finish(&hasher);
    if sig == 0 { 1 } else { sig }
}

/// Round trust to nearest 0.05, expressed as an integer multiple.
/// Range 0..=20 (trust 0.0..=1.0).
fn trust_bucket(trust: f64) -> u8 {
    ((trust / 0.05).round() as u8).min(20)
}

/// Build a PoolSnapshot from the current swarm state + DB trust values.
///
/// Excludes: self, peers not authenticated, peers on backoff.
/// Falls back to unfiltered candidates if fewer than `min_size` authenticated peers.
pub async fn snapshot_pool(
    swarm: Option<&SwarmHandle>,
    db: &Db,
    peer_backoff: Option<&PeerBackoff>,
    own_device_id: &DeviceId,
    min_size: usize,
) -> PoolSnapshot {
    // Get authenticated peer set.
    let authenticated: std::collections::HashSet<DeviceId> = match swarm {
        Some(s) => s
            .peer_sets()
            .await
            .map(|(auth, _)| auth)
            .unwrap_or_default(),
        None => std::collections::HashSet::new(),
    };

    // Build candidates from DB trust.
    let peers = match db.list_all_peers() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("snapshot_pool: list_all_peers failed: {e}");
            return PoolSnapshot {
                candidates: vec![],
                signature: 0,
            };
        }
    };

    let all_candidates: Vec<HolderCandidate> = peers
        .into_iter()
        .filter(|p| &p.device_id != own_device_id)
        .map(|p| {
            let trust_raw = (syncback_core::constants::KP * p.trust_p
                + syncback_core::constants::KI * p.trust_i)
                * p.trust_s.clamp(
                    syncback_core::constants::S_CLAMP_MIN,
                    syncback_core::constants::S_CLAMP_MAX,
                );
            HolderCandidate {
                device_id: p.device_id,
                trust: trust_raw.clamp(0.0, 0.999),
            }
        })
        .collect();

    // Backoff filter.
    let candidates_after_backoff = if let Some(backoff) = peer_backoff {
        let raw = all_candidates.clone();
        let filtered = backoff.filter(all_candidates, 2, |c| &c.device_id);
        if filtered.is_empty() { raw } else { filtered }
    } else {
        all_candidates
    };

    // Online filter.
    let auth_filtered: Vec<HolderCandidate> = candidates_after_backoff
        .iter()
        .filter(|c| authenticated.contains(&c.device_id))
        .cloned()
        .collect();

    let candidates = if auth_filtered.len() < min_size.max(2) {
        // Fallback: not enough authenticated peers (boot, no swarm, test).
        candidates_after_backoff
    } else {
        auth_filtered
    };

    let signature = pool_signature(&candidates);
    PoolSnapshot {
        candidates,
        signature,
    }
}
