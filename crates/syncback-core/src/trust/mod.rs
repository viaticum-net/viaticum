use std::collections::HashMap;

use crate::constants::{
    INITIAL_TRUST_P, KI, KP, P_WINDOW_WEEKS, S_CLAMP_MAX, S_CLAMP_MIN,
};
use crate::types::{IdentityPub, PeerRecord, Timestamp};

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
    #[error("unknown peer: {0}")]
    UnknownPeer(IdentityPub),
}

pub struct TrustEngine {
    peers: HashMap<IdentityPub, PeerRecord>,
    pos_weekly: HashMap<(IdentityPub, u32), WeeklyPosRecord>,
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
        pos_history: Vec<(IdentityPub, u32, u32, u32)>,
    ) -> Self {
        let mut engine = TrustEngine::new();
        for record in peers {
            engine.peers.insert(record.identity, record);
        }
        for (peer, week, challenged, passed) in pos_history {
            let pass_rate = if challenged > 0 {
                passed as f64 / challenged as f64
            } else {
                0.0
            };
            engine.pos_weekly.insert(
                (peer, week),
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

    pub fn export_pos_history(&self) -> Vec<(IdentityPub, u32, u32, u32)> {
        self.pos_weekly
            .iter()
            .map(|((peer, week), rec)| (*peer, *week, rec.challenged, rec.passed))
            .collect()
    }

    pub fn upsert_peer(&mut self, peer: IdentityPub, now: Timestamp) {
        if let Some(record) = self.peers.get_mut(&peer) {
            record.last_seen = now;
        } else {
            let record = PeerRecord {
                identity: peer,
                node_id: None,
                trust_p: INITIAL_TRUST_P,
                trust_i: 0.0,
                trust_s: 1.0,
                bytes_we_store_for_peer: 0,
                bytes_peer_stores_for_us: 0,
                first_seen: now,
                last_seen: now,
                device_id: None,
                revoked_device_pub_keys: vec![],
                addrs: vec![],
                x25519_pub: None,
            };
            self.peers.insert(peer, record);
        }
    }

    pub fn record_pos_result(
        &mut self,
        peer: IdentityPub,
        outcome: PosOutcome,
    ) -> Result<(), TrustError> {
        assert!(outcome.week_number != 0, "week_number 0 is reserved");
        if !self.peers.contains_key(&peer) {
            return Err(TrustError::UnknownPeer(peer));
        }
        let entry = self
            .pos_weekly
            .entry((peer, outcome.week_number))
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
        peer: IdentityPub,
        bytes_we_store_for_peer: u64,
        bytes_peer_stores_for_us: u64,
    ) -> Result<(), TrustError> {
        let record = self
            .peers
            .get_mut(&peer)
            .ok_or(TrustError::UnknownPeer(peer))?;
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
        peer: &IdentityPub,
        _now: Timestamp,
        current_week: u32,
    ) -> Result<TrustScore, TrustError> {
        let window_start = current_week.saturating_sub(P_WINDOW_WEEKS - 1);

        let mut p_challenged = 0u64;
        let mut p_passed = 0u64;
        let mut all_pass_rates: Vec<f64> = Vec::new();

        for ((entry_peer, week_num), rec) in &self.pos_weekly {
            if entry_peer != peer {
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
            .get_mut(peer)
            .ok_or(TrustError::UnknownPeer(*peer))?;

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
        let peers: Vec<IdentityPub> = self.peers.keys().copied().collect();
        let count = peers.len();
        for peer in peers {
            let _ = self.recalculate(&peer, now, current_week);
        }
        count
    }

    pub fn score(&self, peer: &IdentityPub) -> Result<TrustScore, TrustError> {
        let record = self
            .peers
            .get(peer)
            .ok_or(TrustError::UnknownPeer(*peer))?;
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

    pub fn combined_score(&self, peer: &IdentityPub) -> f64 {
        match self.peers.get(peer) {
            Some(record) => compute_combined(record.trust_p, record.trust_i, record.trust_s),
            None => 0.0,
        }
    }

    pub fn get_peer(&self, peer: &IdentityPub) -> Option<&PeerRecord> {
        self.peers.get(peer)
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
    pub fn recent_pos_stats(&self, peer: &IdentityPub, current_week: u32, weeks: u32) -> (u32, u32) {
        let window_start = current_week.saturating_sub(weeks.saturating_sub(1));
        let mut total_challenged = 0u32;
        let mut total_passed = 0u32;
        for week in window_start..=current_week {
            if let Some(rec) = self.pos_weekly.get(&(*peer, week)) {
                total_challenged = total_challenged.saturating_add(rec.challenged);
                total_passed = total_passed.saturating_add(rec.passed);
            }
        }
        (total_challenged, total_passed)
    }

    pub fn zero_trust(&mut self, peer: &IdentityPub) -> Result<(), TrustError> {
        let record = self
            .peers
            .get_mut(peer)
            .ok_or(TrustError::UnknownPeer(*peer))?;
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

#[cfg(test)]
mod tests;
