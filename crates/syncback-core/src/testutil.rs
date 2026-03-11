use crate::db::Db;
use crate::types::{IdentityPub, ShardId, Timestamp, UnitId};

/// Create a deterministic IdentityPub from a small integer seed.
/// Used to generate stable, unique peer identities in tests.
pub fn test_peer(seed: u8) -> IdentityPub {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    IdentityPub(bytes)
}

/// Create n distinct IdentityPub values.
pub fn test_peers(n: usize) -> Vec<IdentityPub> {
    (0..n).map(|i| test_peer(i as u8)).collect()
}

/// Create a Timestamp representing the start of week n (week 0 = Unix epoch).
/// week(1) = Timestamp(604800), week(4) = Timestamp(4 * 604800), etc.
pub fn week(n: u32) -> Timestamp {
    Timestamp(n as u64 * 604800)
}

/// Create a deterministic ShardId from a small integer seed.
pub fn test_shard_id(seed: u8) -> ShardId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    ShardId(bytes)
}

/// Create a deterministic UnitId from a small integer seed.
pub fn test_unit_id(seed: u8) -> UnitId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    UnitId(bytes)
}

/// Open a database on a temporary file. Returns the Db and the temp file handle.
/// Caller must keep `_tmp` alive for the duration of the test.
pub fn test_db() -> (Db, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = Db::open(tmp.path()).unwrap();
    (db, tmp)
}
