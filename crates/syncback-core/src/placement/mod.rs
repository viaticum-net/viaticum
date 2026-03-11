#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use rand::Rng;

use crate::{
    constants::{
        ADAPTIVE_N_LOW_TRUST, ADAPTIVE_N_MID_TRUST, MAX_SHARDS_PER_PARTNER,
    },
    db::{Db, DbError},
    trust::{TrustEngine, TrustError},
    types::{ErasureTier, IdentityPub, ShardStatus, UnitId},
};

#[cfg(test)]
mod tests;

// === Structs ===

/// Parameters selected for a unit's erasure coding.
#[derive(Debug, Clone, PartialEq)]
pub struct ErasureParams {
    /// Data shards (k). Must have at least k shards to recover.
    pub k: usize,
    /// Total shards (n). n >= k.
    pub n: usize,
}

/// A concrete holder assignment for one shard.
#[derive(Debug, Clone)]
pub struct ShardAssignment {
    pub shard_index: u8,
    pub holder: IdentityPub,
}

/// Output of a placement decision for one unit.
#[derive(Debug, Clone)]
pub struct PlacementPlan {
    pub unit_id: UnitId,
    pub params: ErasureParams,
    /// Length == params.n. shard_index matches position in vec.
    pub assignments: Vec<ShardAssignment>,
}

// === Error ===

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("not enough eligible peers: need {need}, have {have}")]
    NotEnoughPeers { need: usize, have: usize },

    #[error("importance too low (below 0.1): {0}")]
    ImportanceTooLow(f64),

    #[error("trust error: {0}")]
    Trust(#[from] TrustError),

    #[error("db error: {0}")]
    Db(#[from] DbError),
}

// === Engine ===

/// Engine for shard placement decisions.
pub struct PlacementEngine {
    db: Db,
    trust: TrustEngine,
}

impl PlacementEngine {
    pub fn new(db: Db, trust: TrustEngine) -> Self {
        PlacementEngine { db, trust }
    }

    /// Return ErasureParams for a given importance score.
    /// Pure function, no DB access.
    pub fn erasure_params(importance: f64) -> ErasureParams {
        match ErasureTier::from_importance(importance) {
            Some(tier) => ErasureParams {
                k: tier.k(),
                n: tier.n_base(),
            },
            None => ErasureParams { k: 5, n: 0 },
        }
    }

    /// Return adjusted n after applying adaptive-n rule.
    /// avg_trust is the mean trust score over all candidate peers.
    /// Pure function, no DB access.
    pub fn adaptive_n(base_n: usize, avg_trust: f64) -> usize {
        let extra = if avg_trust < ADAPTIVE_N_LOW_TRUST {
            2
        } else if avg_trust < ADAPTIVE_N_MID_TRUST {
            1
        } else {
            0
        };
        base_n + extra
    }

    /// Count how many shards of a given unit each peer currently holds
    /// in the `shards` table (status Offered, Accepted, or Stored).
    pub fn current_shard_counts(
        &self,
        unit_id: UnitId,
    ) -> Result<HashMap<IdentityPub, usize>, PlacementError> {
        let shards = self.db.list_shards_for_unit(&unit_id)?;
        let mut counts: HashMap<IdentityPub, usize> = HashMap::new();
        for shard in shards {
            match shard.status {
                ShardStatus::Offered | ShardStatus::Accepted | ShardStatus::Stored => {
                    *counts.entry(shard.holder_id).or_insert(0) += 1;
                }
                ShardStatus::Lost | ShardStatus::Deleting => {}
            }
        }
        Ok(counts)
    }

    /// Select holders for a unit and return a PlacementPlan.
    pub fn select_holders(
        &self,
        unit_id: UnitId,
        importance: f64,
    ) -> Result<PlacementPlan, PlacementError> {
        if ErasureTier::from_importance(importance).is_none() {
            return Err(PlacementError::ImportanceTooLow(importance));
        }

        let base_params = Self::erasure_params(importance);
        let base_n = base_params.n;

        let all_peers = self.trust.all_peers_with_scores()?;

        // Filter to candidates with positive trust
        let candidates: Vec<(IdentityPub, f64, Option<[u8; 3]>)> = all_peers
            .into_iter()
            .filter(|(_, score)| score.combined > 0.0)
            .map(|(record, score)| (record.identity, score.combined, record.subnet_prefix))
            .collect();

        let avg_trust = if candidates.is_empty() {
            0.0
        } else {
            candidates.iter().map(|(_, t, _)| *t).sum::<f64>() / candidates.len() as f64
        };

        let n = Self::adaptive_n(base_n, avg_trust);
        let params = ErasureParams { k: base_params.k, n };

        let existing_counts = self.current_shard_counts(unit_id)?;

        // Build weighted pool: (peer, weight, subnet_prefix)
        // weight = trust^2
        let mut pool: Vec<(IdentityPub, f64, Option<[u8; 3]>)> = candidates
            .iter()
            .filter(|(peer, _, _)| {
                let count = existing_counts.get(peer).copied().unwrap_or(0);
                count < MAX_SHARDS_PER_PARTNER as usize
            })
            .map(|(peer, trust, subnet)| (*peer, trust * trust, *subnet))
            .collect();

        let eligible_count = pool.len();
        if eligible_count < n {
            return Err(PlacementError::NotEnoughPeers {
                need: n,
                have: eligible_count,
            });
        }

        let mut assignments: Vec<ShardAssignment> = Vec::with_capacity(n);
        // Track subnets used in this placement
        let mut used_subnets: Vec<[u8; 3]> = Vec::new();
        // TODO: ASN diversity not enforced (ASN data not collected in MVP)

        let mut rng = rand::thread_rng();
        let mut shard_index: u8 = 0;
        let mut relaxed_subnet = false;

        while assignments.len() < n {
            let total_weight: f64 = pool.iter().map(|(_, w, _)| *w).sum();
            if total_weight <= 0.0 {
                break;
            }

            // Weighted sample
            let target = rng.r#gen::<f64>() * total_weight;
            let mut acc = 0.0;
            let mut chosen_idx = 0;
            for (i, (_, w, _)) in pool.iter().enumerate() {
                acc += w;
                if acc >= target {
                    chosen_idx = i;
                    break;
                }
            }

            let (peer, _, subnet) = pool[chosen_idx];

            // Subnet diversity check (best-effort)
            let subnet_ok = match subnet {
                None => true,
                Some(s) => relaxed_subnet || !used_subnets.contains(&s),
            };

            if !subnet_ok {
                // Remove from pool and try next
                pool.remove(chosen_idx);
                if pool.is_empty() {
                    // Relax subnet rule — all remaining peers share a subnet
                    tracing::debug!(
                        unit_id = %unit_id,
                        "subnet diversity rule relaxed: all remaining peers share a subnet"
                    );
                    relaxed_subnet = true;
                    // Rebuild pool without subnet filtering
                    pool = candidates
                        .iter()
                        .filter(|(peer, _, _)| {
                            let count = existing_counts.get(peer).copied().unwrap_or(0);
                            count < MAX_SHARDS_PER_PARTNER as usize
                        })
                        .filter(|(peer, _, _)| !assignments.iter().any(|a| a.holder == *peer))
                        .map(|(peer, trust, subnet)| (*peer, trust * trust, *subnet))
                        .collect();
                    if pool.is_empty() {
                        break;
                    }
                }
                continue;
            }

            // Accept this holder
            if let Some(s) = subnet {
                used_subnets.push(s);
            }
            assignments.push(ShardAssignment {
                shard_index,
                holder: peer,
            });
            shard_index += 1;
            pool.remove(chosen_idx);
        }

        if assignments.len() < n {
            return Err(PlacementError::NotEnoughPeers {
                need: n,
                have: assignments.len(),
            });
        }

        Ok(PlacementPlan {
            unit_id,
            params,
            assignments,
        })
    }
}
