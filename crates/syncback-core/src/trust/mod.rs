use redb::ReadableTable;

use crate::constants::{KI, KP, P_WINDOW_WEEKS, S_CLAMP_MAX, S_CLAMP_MIN, SECS_PER_WEEK};
use crate::db::{Db, DbError, POS_WEEKLY};
use crate::types::{from_cbor_bytes, to_cbor_bytes, IdentityPub, PeerRecord, Timestamp};

/// Raw sub-scores for a peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustScore {
    /// Rolling 4-week PoS pass rate.
    pub p: f64,
    /// Cumulative mean of weekly PoS pass rates.
    pub i: f64,
    /// Pairwise GB ratio (raw, not clamped).
    pub s_raw: f64,
    /// Final combined score.
    pub combined: f64,
}

/// A single PoS round outcome for one peer.
pub struct PosOutcome {
    pub week_number: u32,
    pub challenged: u32,
    pub passed: u32,
}

/// Transfer event: bytes exchanged with a peer after a blob transfer completes.
pub struct TransferEvent {
    pub peer: IdentityPub,
    pub bytes_sent_to_peer: u64,
    pub bytes_received_from_peer: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WeeklyPosRecord {
    pub challenged: u32,
    pub passed: u32,
    pub pass_rate: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown peer: {0:?}")]
    UnknownPeer(IdentityPub),

    #[error("db error: {0}")]
    Db(Box<redb::Error>),

    #[error("serialization error: {0}")]
    Cbor(String),
}

impl From<redb::Error> for TrustError {
    fn from(e: redb::Error) -> Self {
        TrustError::Db(Box::new(e))
    }
}

impl From<DbError> for TrustError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Cbor(c) => TrustError::Cbor(c.to_string()),
            DbError::Redb(r) => TrustError::Db(r),
            DbError::Database(d) => TrustError::Db(Box::new(redb::Error::from(d))),
            DbError::Transaction(t) => TrustError::Db(Box::new(redb::Error::from(*t))),
            DbError::Table(t) => TrustError::Db(Box::new(redb::Error::from(t))),
            DbError::Storage(s) => TrustError::Db(Box::new(redb::Error::from(s))),
            DbError::Commit(c) => TrustError::Db(Box::new(redb::Error::from(c))),
            DbError::NotFound(msg) => TrustError::Cbor(format!("not found: {msg}")),
        }
    }
}

impl From<crate::types::CborError> for TrustError {
    fn from(e: crate::types::CborError) -> Self {
        TrustError::Cbor(e.to_string())
    }
}

fn pos_key(peer: &IdentityPub, week_number: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&peer.0);
    key[32..].copy_from_slice(&week_number.to_be_bytes());
    key
}


pub fn compute_combined(p: f64, i: f64, s_raw: f64) -> f64 {
    let s_clamped = s_raw.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
    (KP * p + KI * i) * s_clamped
}

pub struct TrustEngine {
    db: Db,
}

impl TrustEngine {
    pub fn new(db: Db) -> Self {
        TrustEngine { db }
    }

    pub fn upsert_peer(&self, peer: &IdentityPub, now: Timestamp) -> Result<(), TrustError> {
        match self.db.get_peer(peer)? {
            Some(mut record) => {
                record.last_seen = now;
                self.db.upsert_peer(&record)?;
            }
            None => {
                let record = PeerRecord {
                    identity: *peer,
                    node_id: None,
                    trust_p: 0.0,
                    trust_i: 0.0,
                    trust_s: 1.0,
                    bytes_sent_to_peer: 0,
                    bytes_received_from_peer: 0,
                    first_seen: now,
                    last_seen: now,
                    weeks_in_network: 0,
                    subnet_prefix: None,
                    allowlisted: false,
                };
                self.db.upsert_peer(&record)?;
            }
        }
        Ok(())
    }

    pub fn record_pos_result(&self, peer: &IdentityPub, outcome: PosOutcome) -> Result<(), TrustError> {
        tracing::debug!(peer = %peer, week = outcome.week_number, "record_pos_result");
        let key = pos_key(peer, outcome.week_number);
        let tx = self.db.inner.begin_write().map_err(redb::Error::from)?;
        {
            let mut table = tx.open_table(POS_WEEKLY).map_err(redb::Error::from)?;
            let existing_bytes = table.get(&key).map_err(redb::Error::from)?
                .map(|v| v.value().to_vec());
            let mut record = match existing_bytes {
                Some(bytes) => from_cbor_bytes::<WeeklyPosRecord>(&bytes)
                    .map_err(|e| TrustError::Cbor(e.to_string()))?,
                None => WeeklyPosRecord { challenged: 0, passed: 0, pass_rate: 0.0 },
            };
            record.challenged += outcome.challenged;
            record.passed += outcome.passed;
            record.pass_rate = if record.challenged > 0 {
                record.passed as f64 / record.challenged as f64
            } else {
                0.0
            };
            table.insert(&key, to_cbor_bytes(&record).as_slice()).map_err(redb::Error::from)?;
        }
        tx.commit().map_err(redb::Error::from)?;
        Ok(())
    }

    pub fn record_transfer(&self, event: &TransferEvent, now: Timestamp) -> Result<(), TrustError> {
        match self.db.get_peer(&event.peer)? {
            Some(mut record) => {
                record.bytes_sent_to_peer += event.bytes_sent_to_peer;
                record.bytes_received_from_peer += event.bytes_received_from_peer;
                record.trust_s = if record.bytes_sent_to_peer == 0 {
                    1.0
                } else {
                    record.bytes_received_from_peer as f64 / record.bytes_sent_to_peer as f64
                };
                record.last_seen = now;
                self.db.upsert_peer(&record)?;
            }
            None => return Err(TrustError::UnknownPeer(event.peer)),
        }
        Ok(())
    }

    pub fn recalculate(&self, peer: &IdentityPub, now: Timestamp, current_week: u32) -> Result<TrustScore, TrustError> {
        tracing::debug!(peer = %peer, current_week, "recalculate trust");

        // Scan all pos_weekly entries for this peer
        let tx = self.db.inner.begin_read().map_err(redb::Error::from)?;
        let table = tx.open_table(POS_WEEKLY).map_err(redb::Error::from)?;

        let mut all_weeks: Vec<(u32, WeeklyPosRecord)> = Vec::new();
        for entry in table.iter().map_err(redb::Error::from)? {
            let (k, v) = entry.map_err(redb::Error::from)?;
            let key_bytes: &[u8; 36] = k.value();
            if key_bytes[..32] != peer.0 {
                continue;
            }
            let week_num = u32::from_be_bytes(key_bytes[32..36].try_into().unwrap());
            let record: WeeklyPosRecord = from_cbor_bytes(v.value())
                .map_err(|e| TrustError::Cbor(e.to_string()))?;
            all_weeks.push((week_num, record));
        }
        drop(table);
        drop(tx);

        // Compute P: sum passed / sum challenged over last P_WINDOW_WEEKS
        let window_start = current_week.saturating_sub(P_WINDOW_WEEKS - 1);
        let mut p_challenged = 0u64;
        let mut p_passed = 0u64;
        for (week_num, rec) in &all_weeks {
            if *week_num >= window_start && *week_num <= current_week {
                p_challenged += rec.challenged as u64;
                p_passed += rec.passed as u64;
            }
        }
        let p = if p_challenged == 0 {
            0.0
        } else {
            p_passed as f64 / p_challenged as f64
        };

        // Compute I: mean of pass_rate over ALL weeks with challenged > 0
        let active_weeks: Vec<f64> = all_weeks
            .iter()
            .filter(|(_, rec)| rec.challenged > 0)
            .map(|(_, rec)| rec.pass_rate)
            .collect();
        let i = if active_weeks.is_empty() {
            0.0
        } else {
            active_weeks.iter().sum::<f64>() / active_weeks.len() as f64
        };

        // Read current peer record for S and other fields
        let mut peer_record = self.db.get_peer(peer)?.ok_or(TrustError::UnknownPeer(*peer))?;
        let s_raw = peer_record.trust_s;
        let combined = compute_combined(p, i, s_raw);

        // Update weeks_in_network
        let weeks_in_network = if now.0 >= peer_record.first_seen.0 {
            ((now.0 - peer_record.first_seen.0) / SECS_PER_WEEK) as u32
        } else {
            0
        };

        peer_record.trust_p = p;
        peer_record.trust_i = i;
        peer_record.weeks_in_network = weeks_in_network;
        peer_record.last_seen = now;
        self.db.upsert_peer(&peer_record)?;

        Ok(TrustScore { p, i, s_raw, combined })
    }

    pub fn recalculate_all(&self, now: Timestamp, current_week: u32) -> Result<usize, TrustError> {
        let peers = self.db.list_all_peers()?;
        let count = peers.len();
        for peer in &peers {
            self.recalculate(&peer.identity, now, current_week)?;
        }
        Ok(count)
    }

    pub fn score(&self, peer: &IdentityPub) -> Result<TrustScore, TrustError> {
        let record = self.db.get_peer(peer)?.ok_or(TrustError::UnknownPeer(*peer))?;
        let p = record.trust_p;
        let i = record.trust_i;
        let s_raw = record.trust_s;
        let combined = compute_combined(p, i, s_raw);
        Ok(TrustScore { p, i, s_raw, combined })
    }

    pub fn combined_score(&self, peer: &IdentityPub) -> Result<f64, TrustError> {
        match self.db.get_peer(peer)? {
            Some(record) => {
                Ok(compute_combined(record.trust_p, record.trust_i, record.trust_s))
            }
            None => Ok(0.0),
        }
    }

    pub fn zero_trust(&self, peer: &IdentityPub, now: Timestamp) -> Result<(), TrustError> {
        match self.db.get_peer(peer)? {
            Some(mut record) => {
                record.trust_p = 0.0;
                record.trust_i = 0.0;
                record.last_seen = now;
                self.db.upsert_peer(&record)?;
            }
            None => return Err(TrustError::UnknownPeer(*peer)),
        }
        Ok(())
    }

    pub fn all_peers_with_scores(&self) -> Result<Vec<(PeerRecord, TrustScore)>, TrustError> {
        let peers = self.db.list_all_peers()?;
        let mut result = Vec::with_capacity(peers.len());
        for record in peers {
            let score = self.score(&record.identity)?;
            result.push((record, score));
        }
        Ok(result)
    }

    pub fn get_peer(&self, peer: &IdentityPub) -> Result<Option<PeerRecord>, TrustError> {
        Ok(self.db.get_peer(peer)?)
    }
}


#[cfg(test)]
mod tests;
