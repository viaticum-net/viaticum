use std::collections::HashMap;

use crate::constants::{
    INITIAL_TRUST_P, KI, KP, MAX_COMBINED_TRUST, P_WINDOW_WEEKS, S_CLAMP_MAX, S_CLAMP_MIN,
    TRUST_INHERITANCE_FACTOR,
};
use crate::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

/// Raw sub-scores for a peer. Returned by score() and recalculate().
#[derive(Debug, Clone, PartialEq)]
pub struct TrustScore {
    /// Rolling P_WINDOW_WEEKS PoS pass rate. [0.0, 1.0]
    pub p: f64,
    /// Cumulative mean of weekly PoS pass rates. [0.0, 1.0]
    pub i: f64,
    /// Raw pairwise storage ratio (not clamped).
    pub s_raw: f64,
    /// Final combined: (KP*p + KI*i) * clamp(s_raw, S_CLAMP_MIN, S_CLAMP_MAX)
    pub combined: f64,
}

/// Outcome of a single PoS round for one peer.
pub struct PosOutcome {
    /// Which protocol-week this round belongs to (monotonically increasing).
    pub week_number: u32,
    pub challenged: u32,
    pub passed: u32,
}

/// Internal per-week record stored alongside PeerRecord.
#[derive(Debug, Clone)]
struct WeeklyPosRecord {
    pub challenged: u32,
    pub passed: u32,
    pub pass_rate: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown device: {0}")]
    UnknownDevice(DeviceId),
}

pub struct TrustEngine {
    peers: HashMap<DeviceId, PeerRecord>,
    pos_weekly: HashMap<(DeviceId, u32), WeeklyPosRecord>,
}

impl Default for TrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustEngine {
    pub fn new() -> Self {
        TrustEngine {
            peers: HashMap::new(),
            pos_weekly: HashMap::new(),
        }
    }

    pub fn load(
        peers: Vec<PeerRecord>,
        pos_history: Vec<(DeviceId, u32, u32, u32)>,
    ) -> Self {
        let mut engine = TrustEngine::new();
        for record in peers {
            engine.peers.insert(record.device_id, record);
        }
        for (device, week, challenged, passed) in pos_history {
            let pass_rate = if challenged > 0 {
                passed as f64 / challenged as f64
            } else {
                0.0
            };
            engine.pos_weekly.insert(
                (device, week),
                WeeklyPosRecord {
                    challenged,
                    passed,
                    pass_rate,
                },
            );
        }
        engine
    }

    pub fn export_peers(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }

    pub fn export_pos_history(&self) -> Vec<(DeviceId, u32, u32, u32)> {
        self.pos_weekly
            .iter()
            .map(|((device, week), rec)| (*device, *week, rec.challenged, rec.passed))
            .collect()
    }

    /// Insert or update a device in the engine. Takes DeviceId and master IdentityPub.
    pub fn upsert_peer_device(&mut self, device_id: DeviceId, master: IdentityPub, now: Timestamp) {
        if let Some(record) = self.peers.get_mut(&device_id) {
            record.last_seen = now;
        } else {
            let record = PeerRecord {
                device_id,
                master_identity: master,
                trust_p: INITIAL_TRUST_P,
                trust_i: 0.0,
                trust_s: 1.0,
                bytes_we_store_for_peer: 0,
                bytes_peer_stores_for_us: 0,
                first_seen: now,
                last_seen: now,
                revoked_device_pub_keys: vec![],
                addrs: vec![],
                x25519_pub: None,
            };
            self.peers.insert(device_id, record);
        }
    }

    /// Backward-compat alias: upsert using DeviceId only (master = zero IdentityPub).
    /// Use upsert_peer_device for new code.
    #[deprecated(note = "Use upsert_peer_device instead")]
    pub fn upsert_peer(&mut self, device_id: DeviceId, now: Timestamp) {
        self.upsert_peer_device(device_id, IdentityPub([0u8; 32]), now);
    }

    pub fn record_pos_result(
        &mut self,
        device_id: DeviceId,
        outcome: PosOutcome,
    ) -> Result<(), TrustError> {
        assert!(outcome.week_number != 0, "week_number 0 is reserved");
        if !self.peers.contains_key(&device_id) {
            return Err(TrustError::UnknownDevice(device_id));
        }
        let entry = self
            .pos_weekly
            .entry((device_id, outcome.week_number))
            .or_insert(WeeklyPosRecord {
                challenged: 0,
                passed: 0,
                pass_rate: 0.0,
            });
        entry.challenged += outcome.challenged;
        entry.passed += outcome.passed;
        entry.pass_rate = if entry.challenged > 0 {
            entry.passed as f64 / entry.challenged as f64
        } else {
            0.0
        };
        Ok(())
    }

    pub fn update_storage_bytes(
        &mut self,
        device_id: DeviceId,
        bytes_we_store_for_peer: u64,
        bytes_peer_stores_for_us: u64,
    ) -> Result<(), TrustError> {
        let record = self
            .peers
            .get_mut(&device_id)
            .ok_or(TrustError::UnknownDevice(device_id))?;
        record.bytes_we_store_for_peer = bytes_we_store_for_peer;
        record.bytes_peer_stores_for_us = bytes_peer_stores_for_us;
        record.trust_s = if bytes_we_store_for_peer == 0 {
            1.0
        } else {
            bytes_peer_stores_for_us as f64 / bytes_we_store_for_peer as f64
        };
        Ok(())
    }

    pub fn recalculate(
        &mut self,
        device_id: &DeviceId,
        _now: Timestamp,
        current_week: u32,
    ) -> Result<TrustScore, TrustError> {
        let window_start = current_week.saturating_sub(P_WINDOW_WEEKS - 1);

        let mut p_challenged = 0u64;
        let mut p_passed = 0u64;
        let mut all_pass_rates: Vec<f64> = Vec::new();

        for ((entry_device, week_num), rec) in &self.pos_weekly {
            if entry_device != device_id {
                continue;
            }
            if rec.challenged > 0 {
                all_pass_rates.push(rec.pass_rate);
            }
            if *week_num >= window_start && *week_num <= current_week && rec.challenged > 0 {
                p_challenged += rec.challenged as u64;
                p_passed += rec.passed as u64;
            }
        }

        let p = if p_challenged == 0 {
            INITIAL_TRUST_P
        } else {
            p_passed as f64 / p_challenged as f64
        };

        let i = if all_pass_rates.is_empty() {
            0.0
        } else {
            all_pass_rates.iter().sum::<f64>() / all_pass_rates.len() as f64
        };

        let record = self
            .peers
            .get_mut(device_id)
            .ok_or(TrustError::UnknownDevice(*device_id))?;

        let s_raw = record.trust_s;
        let combined = compute_combined(p, i, s_raw);

        record.trust_p = p;
        record.trust_i = i;

        Ok(TrustScore {
            p,
            i,
            s_raw,
            combined,
        })
    }

    pub fn recalculate_all(&mut self, now: Timestamp, current_week: u32) -> usize {
        let peers: Vec<DeviceId> = self.peers.keys().copied().collect();
        let count = peers.len();
        for peer in peers {
            let _ = self.recalculate(&peer, now, current_week);
        }
        count
    }

    pub fn score(&self, device_id: &DeviceId) -> Result<TrustScore, TrustError> {
        let record = self
            .peers
            .get(device_id)
            .ok_or(TrustError::UnknownDevice(*device_id))?;
        let p = record.trust_p;
        let i = record.trust_i;
        let s_raw = record.trust_s;
        let combined = compute_combined(p, i, s_raw);
        Ok(TrustScore {
            p,
            i,
            s_raw,
            combined,
        })
    }

    pub fn combined_score(&self, device_id: &DeviceId) -> f64 {
        match self.peers.get(device_id) {
            Some(record) => compute_combined(record.trust_p, record.trust_i, record.trust_s),
            None => 0.0,
        }
    }

    pub fn get_peer(&self, device_id: &DeviceId) -> Option<&PeerRecord> {
        self.peers.get(device_id)
    }

    pub fn peers_by_trust(&self) -> Vec<(&PeerRecord, TrustScore)> {
        let mut result: Vec<(&PeerRecord, TrustScore)> = self
            .peers
            .values()
            .map(|record| {
                let score = TrustScore {
                    p: record.trust_p,
                    i: record.trust_i,
                    s_raw: record.trust_s,
                    combined: compute_combined(record.trust_p, record.trust_i, record.trust_s),
                };
                (record, score)
            })
            .collect();
        result.sort_by(|a, b| b.1.combined.partial_cmp(&a.1.combined).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    /// Returns (total_challenged, total_passed) for the last `weeks` weeks ending at `current_week`.
    /// If no data for the period, returns (0, 0).
    pub fn recent_pos_stats(&self, device_id: &DeviceId, current_week: u32, weeks: u32) -> (u32, u32) {
        let window_start = current_week.saturating_sub(weeks.saturating_sub(1));
        let mut total_challenged = 0u32;
        let mut total_passed = 0u32;
        for week in window_start..=current_week {
            if let Some(rec) = self.pos_weekly.get(&(*device_id, week)) {
                total_challenged = total_challenged.saturating_add(rec.challenged);
                total_passed = total_passed.saturating_add(rec.passed);
            }
        }
        (total_challenged, total_passed)
    }

    pub fn zero_trust(&mut self, device_id: &DeviceId) -> Result<(), TrustError> {
        let record = self
            .peers
            .get_mut(device_id)
            .ok_or(TrustError::UnknownDevice(*device_id))?;
        record.trust_p = 0.0;
        record.trust_i = 0.0;
        Ok(())
    }
}

/// Pure formula helper (also useful in placement).
pub fn compute_combined(p: f64, i: f64, s_raw: f64) -> f64 {
    let s = s_raw.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
    (KP * p + KI * i) * s
}

// ============================================================
// Two-level trust types
// ============================================================

/// Raw P/I trust scores for a specific device, earned via PoS responses.
/// Keyed by DeviceId. Starts at zero, dies with the device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceTrustRecord {
    pub device_id: DeviceId,
    /// 4-week rolling PoS pass rate.
    pub trust_p: f64,
    /// Cumulative mean of weekly PoS pass rates.
    pub trust_i: f64,
    /// Last week number when PoS data was recorded.
    pub last_week: u32,
}

/// Aggregated trust for a master identity. Derived from device trust.
/// Keyed by IdentityPub. Survives device replacement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasterTrustRecord {
    pub identity: IdentityPub,
    /// Weighted average of device_trust.combined scores across active devices.
    /// Weighted by symbols_stored (proxy for contribution).
    pub combined: f64,
    /// When last recalculated.
    pub last_updated: Timestamp,
}

// ============================================================
// Two-level trust computation
// ============================================================

/// Compute effective trust for a device.
///
/// Combines device-specific PoS history with inherited master reputation.
///
/// Formula:
///   dt   = compute_combined(device.trust_p, device.trust_i, s_raw=1.0)
///   mt   = master.combined
///   base = mt * TRUST_INHERITANCE_FACTOR
///   effective = base + dt * (1.0 - base / MAX_COMBINED_TRUST)
///
/// S component (storage reciprocity) is NOT included — it remains per-master
/// in PeerRecord.trust_s. Callers who need S must apply it separately.
///
/// Returns 0.0 if both device and master trust are absent.
/// Returns inheritance base if master trust present but device trust absent.
pub fn compute_effective_trust(
    device_trust: Option<&DeviceTrustRecord>,
    master_trust: Option<&MasterTrustRecord>,
) -> f64 {
    let mt = master_trust.map_or(0.0, |m| m.combined);
    let base = mt * TRUST_INHERITANCE_FACTOR;

    let dt = device_trust
        .map(|d| compute_combined(d.trust_p, d.trust_i, 1.0))
        .unwrap_or(0.0);

    base + dt * (1.0 - base / MAX_COMBINED_TRUST)
}

/// Recompute master_trust for a given master identity from all its devices' trust.
///
/// Algorithm:
///   For each device: dt_combined = compute_combined(device.trust_p, device.trust_i, 1.0)
///   master.combined = weighted_average(dt_combined, weight = symbols_stored)
///   If no devices or all weights zero: equal weight (arithmetic mean).
///   If no devices at all: returns 0.0.
pub fn recompute_master_trust(devices: &[(DeviceTrustRecord, u64)]) -> f64 {
    if devices.is_empty() {
        return 0.0;
    }

    let total_symbols: u64 = devices.iter().map(|(_, s)| *s).sum();

    if total_symbols == 0 {
        // Equal weight fallback
        let sum: f64 = devices
            .iter()
            .map(|(d, _)| compute_combined(d.trust_p, d.trust_i, 1.0))
            .sum();
        sum / devices.len() as f64
    } else {
        let weighted_sum: f64 = devices
            .iter()
            .map(|(d, symbols)| compute_combined(d.trust_p, d.trust_i, 1.0) * (*symbols as f64))
            .sum();
        weighted_sum / total_symbols as f64
    }
}

#[cfg(test)]
mod tests;
