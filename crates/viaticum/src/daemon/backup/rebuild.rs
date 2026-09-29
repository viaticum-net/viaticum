// Rebuild of a source block's plaintext from the files on this device, by content
// (backup-i22, INV-RB; spec c_l0_l1_watcher_rollback.md §2.2 К2b).
//
// The pack index lives inside the ciphertext, so a member keeps the `file_id` it was
// packed under. Its bytes are found by content instead: the member's hash is the hash of
// the FIRST version of the member's record that points at this block (the packing
// version — dedup versions on the same block come later, A10), and the bytes are read
// from the member's own record if it still holds them (whatever its state), else from
// any record Present on this device with a version of that hash. Every read is checked against the member's
// hash; the caller checks the rebuilt blob against the block id. A path that is gone
// is reported on the recheck channel (the watcher decides whether it is a deletion).

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use viaticum_core::db::{Db, DbError};
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, LocalState, PackEntry, SourceBlockId, SourceBlockRecord,
    SourceBlockType, to_cbor_bytes,
};

/// Paths a rebuild found gone, to the watcher's recheck (delete-i12 (в)). Bounded;
/// senders use `try_send` and drop a path when it is full.
pub type RecheckTx = tokio::sync::mpsc::Sender<PathBuf>;

/// Capacity of the recheck channel.
pub const RECHECK_CHANNEL_CAPACITY: usize = 256;

/// Who rebuilds: whose records may be read, and where gone paths are reported.
#[derive(Clone, Default)]
pub struct RebuildScope {
    /// This device: only records `Present` on it are read. `None` reads records Present
    /// on any device — the local restore tier and unit tests; the catalog holds only
    /// this device's records (FILES is written by this node's backup, DR moves history
    /// to this device), and every read is hash-checked.
    pub device: Option<DeviceId>,
    /// Where gone paths go. `None`: not reported (local restore tier, tests).
    pub recheck: Option<RecheckTx>,
}

impl RebuildScope {
    pub fn new(device: DeviceId, recheck: Option<RecheckTx>) -> Self {
        Self {
            device: Some(device),
            recheck,
        }
    }
}

/// Why a block cannot be rebuilt from this device's files.
#[derive(Debug, thiserror::Error)]
pub enum RebuildError {
    /// The content of these pack members is on no path of this device (F-pack, L3;
    /// P-C1: L2's liveness rule reads this). A Single block: `missing` is empty.
    #[error("block {block}: content of member(s) {missing:?} is on no path of this device")]
    SourceMissing {
        block: SourceBlockId,
        missing: Vec<FileId>,
    },
    #[error("catalog read: {0}")]
    Db(#[from] DbError),
}

/// Rebuild the plaintext of `block` (Single: the file bytes; Pack: index + members, in
/// the packed order) from the files on this device (INV-RB).
///
/// Every gone path met on the way (a Present record whose path is NotFound) is sent to
/// `scope.recheck`, on success too (N2): a renamed member is rebuilt from its new path
/// while its old path still needs to be marked deleted.
pub fn rebuild_plaintext_from_db(
    db: &Db,
    block: &SourceBlockRecord,
    scope: &RebuildScope,
) -> Result<Vec<u8>, RebuildError> {
    let files = db.list_all_files()?;
    let catalog = Catalog::new(&files, scope.device);
    let mut gone = BTreeSet::new();
    let result = rebuild(&catalog, block, &mut gone);
    if let Some(tx) = &scope.recheck {
        for path in gone {
            if tx.try_send(PathBuf::from(&path)).is_err() {
                tracing::debug!(path = %path, "rebuild: recheck channel full or closed; path dropped");
            }
        }
    }
    result
}

fn rebuild(
    catalog: &Catalog<'_>,
    block: &SourceBlockRecord,
    gone: &mut BTreeSet<String>,
) -> Result<Vec<u8>, RebuildError> {
    let block_id = block.block_id;
    match &block.block_type {
        SourceBlockType::Single => {
            // The first version of any record on this block gives its content hash.
            let hash = catalog.files.iter().find_map(|r| {
                r.versions
                    .iter()
                    .find(|v| v.source_block_id == block_id)
                    .map(|v| v.content_hash)
            });
            let bytes = hash.and_then(|h| catalog.read_content(None, &h, gone));
            bytes.ok_or(RebuildError::SourceMissing {
                block: block_id,
                missing: Vec::new(),
            })
        }
        SourceBlockType::Pack { entries } => {
            let mut members: Vec<(FileId, Vec<u8>)> = Vec::with_capacity(entries.len());
            let mut missing = Vec::new();
            for entry in entries {
                match catalog.read_member(entry, block_id, gone) {
                    Some(bytes) => members.push((entry.file_id, bytes)),
                    None => missing.push(entry.file_id),
                }
            }
            if !missing.is_empty() {
                return Err(RebuildError::SourceMissing {
                    block: block_id,
                    missing,
                });
            }
            Ok(pack_plaintext(&members))
        }
    }
}

/// `[CBOR(Vec<PackEntry>)][member bytes…]`, the layout of `packing::build_plaintext`.
fn pack_plaintext(members: &[(FileId, Vec<u8>)]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(members.len());
    let mut offset = 0u64;
    for (file_id, bytes) in members {
        entries.push(PackEntry {
            file_id: *file_id,
            offset,
            size: bytes.len() as u64,
        });
        offset += bytes.len() as u64;
    }
    let mut plaintext = to_cbor_bytes(&entries);
    for (_, bytes) in members {
        plaintext.extend_from_slice(bytes);
    }
    plaintext
}

/// One pass over the catalog: records by `file_id`, readable records by content hash.
struct Catalog<'a> {
    files: &'a [FileRecord],
    by_id: HashMap<FileId, &'a FileRecord>,
    /// Records Present on the device, per hash of any of their versions; a record whose
    /// last version has that hash comes first, then path order.
    by_hash: HashMap<[u8; 32], Vec<&'a FileRecord>>,
    device: Option<DeviceId>,
}

impl<'a> Catalog<'a> {
    fn new(files: &'a [FileRecord], device: Option<DeviceId>) -> Self {
        let mut by_id = HashMap::with_capacity(files.len());
        let mut by_hash: HashMap<[u8; 32], Vec<&FileRecord>> = HashMap::new();
        for r in files {
            by_id.insert(r.file_id, r);
            if !present_on(r, device) {
                continue;
            }
            let mut seen: Vec<[u8; 32]> = Vec::new();
            for v in &r.versions {
                if !seen.contains(&v.content_hash) {
                    seen.push(v.content_hash);
                    by_hash.entry(v.content_hash).or_default().push(r);
                }
            }
        }
        for (hash, records) in by_hash.iter_mut() {
            records.sort_by(|a, b| {
                let a_last = a.versions.last().map(|v| &v.content_hash) != Some(hash);
                let b_last = b.versions.last().map(|v| &v.content_hash) != Some(hash);
                (a_last, &a.path).cmp(&(b_last, &b.path))
            });
        }
        Self {
            files,
            by_id,
            by_hash,
            device,
        }
    }

    /// The bytes of one pack member of `block`, or `None` when its content is nowhere.
    fn read_member(
        &self,
        entry: &PackEntry,
        block: SourceBlockId,
        gone: &mut BTreeSet<String>,
    ) -> Option<Vec<u8>> {
        let Some(owner) = self.by_id.get(&entry.file_id).copied() else {
            tracing::debug!(block = %block, file_id = %entry.file_id,
                "rebuild: pack member has no catalog record");
            return None;
        };
        // The packing version: the first version of the member's record on this block.
        match owner.versions.iter().find(|v| v.source_block_id == block) {
            Some(first) => self.read_content(Some(owner), &first.content_hash, gone),
            None => {
                // No version of the record points here (not expected, A10): read its
                // path as before, unchecked; the blob check against the block id decides.
                tracing::debug!(block = %block, path = %owner.path,
                    "rebuild: member record has no version on this block; reading its path");
                read_path(&owner.path, gone, present_on(owner, self.device))
            }
        }
    }

    /// Bytes with hash `hash`: from `own` (the member's record) first, whatever its
    /// state — the read is hash-checked —, then from every record Present on the device
    /// with a version of that hash. A gone path is reported only for a Present record.
    fn read_content(
        &self,
        own: Option<&FileRecord>,
        hash: &[u8; 32],
        gone: &mut BTreeSet<String>,
    ) -> Option<Vec<u8>> {
        let others = self.by_hash.get(hash).into_iter().flatten().copied();
        let mut tried: Vec<&str> = Vec::new();
        for candidate in own.into_iter().chain(others) {
            if tried.contains(&candidate.path.as_str()) {
                continue;
            }
            tried.push(&candidate.path);
            let report_gone = present_on(candidate, self.device);
            if let Some(bytes) = read_path(&candidate.path, gone, report_gone)
                && blake3::hash(&bytes).as_bytes() == hash
            {
                return Some(bytes);
            }
        }
        None
    }
}

/// Read `path`. NotFound → `None`, and the path goes to `gone` when `report_gone`;
/// another error (permissions, a locked file) → `None` with DEBUG, next candidate (N3).
fn read_path(path: &str, gone: &mut BTreeSet<String>, report_gone: bool) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if report_gone {
                gone.insert(path.to_string());
            }
            None
        }
        Err(e) => {
            tracing::debug!(path = %path, error = %e, "rebuild: candidate unreadable; next one");
            None
        }
    }
}

/// `record` is Present on `device` (any device when `None`).
fn present_on(record: &FileRecord, device: Option<DeviceId>) -> bool {
    record
        .devices
        .iter()
        .any(|(d, s)| *s == LocalState::Present && device.is_none_or(|own| *d == own))
}
