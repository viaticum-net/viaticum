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
use std::path::{Path, PathBuf};

use viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES;
use viaticum_core::db::{Db, DbError};
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, LocalState, PackEntry, SourceBlockId, SourceBlockRecord,
    SourceBlockType, to_cbor_bytes,
};

use super::source_read::{SourceReadError, read_source_bounded};

/// Paths a rebuild found gone, to the watcher's recheck (delete-i12 (в)). Bounded;
/// senders use `try_send` and drop a path when it is full.
pub type RecheckTx = tokio::sync::mpsc::Sender<PathBuf>;

/// Capacity of the recheck channel.
pub const RECHECK_CHANNEL_CAPACITY: usize = 256;

/// Who rebuilds: whose records may be read, where gone paths are reported, and how large a
/// source file may be read.
#[derive(Clone)]
pub struct RebuildScope {
    /// This device: only records `Present` on it are read. `None` reads records Present
    /// on any device — the local restore tier and unit tests; the catalog holds only
    /// this device's records (FILES is written by this node's backup, DR moves history
    /// to this device), and every read is hash-checked.
    pub device: Option<DeviceId>,
    /// Where gone paths go. `None`: not reported (local restore tier, tests).
    pub recheck: Option<RecheckTx>,
    /// The size limit of this machine (backup-i5, J1): a candidate file above it is not
    /// read (DEBUG, next candidate — neither "gone" nor a recheck). Default: the RaptorQ
    /// ceiling; the daemon sets the limit in force (`with_max_source_bytes`).
    pub max_source_bytes: u64,
}

impl Default for RebuildScope {
    fn default() -> Self {
        Self {
            device: None,
            recheck: None,
            max_source_bytes: MAX_FILE_SIZE_CEILING_BYTES,
        }
    }
}

impl RebuildScope {
    pub fn new(device: DeviceId, recheck: Option<RecheckTx>) -> Self {
        Self {
            device: Some(device),
            recheck,
            ..Self::default()
        }
    }

    /// The same scope with the size limit `max_source_bytes`.
    pub fn with_max_source_bytes(mut self, max_source_bytes: u64) -> Self {
        self.max_source_bytes = max_source_bytes;
        self
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
/// the packed order) from the files on this device (INV-RB). Every read is hash-checked.
///
/// Every gone path met on the way (a Present record whose path is NotFound) is sent to
/// `scope.recheck`, on success too (N2): a renamed member is rebuilt from its new path
/// while its old path still needs to be marked deleted.
pub fn rebuild_plaintext_from_db(
    db: &Db,
    block: &SourceBlockRecord,
    scope: &RebuildScope,
) -> Result<Vec<u8>, RebuildError> {
    with_catalog(db, scope, |catalog, gone| rebuild(catalog, block, gone))?
}

/// A rebuilt plaintext, and whether it rests on unchecked reads.
pub struct Candidate {
    pub plaintext: Vec<u8>,
    /// `Some`: the checked rebuild failed with this error (`SourceMissing`), and the
    /// plaintext holds the missing members read UNCHECKED from their own record's path —
    /// a catalog from before L1 may record the hash of a file at enqueue while the block
    /// holds the bytes of the flush. The caller keeps it only when the sealed blob matches
    /// the block id, and otherwise reports this error.
    pub legacy_of: Option<RebuildError>,
}

/// As [`rebuild_plaintext_from_db`], with a last candidate when the content of a pack
/// member is nowhere by hash: its own record's path, read unchecked (see [`Candidate`]) —
/// only when that file's length is the member's packed size (W3 of the L0 review: an
/// edited member, the common `SourceMissing`, usually changes length, and re-reading and
/// sealing a doomed candidate would double the cost of a PoS prepare). `Err` means no
/// candidate was attempted.
pub fn rebuild_candidate(
    db: &Db,
    block: &SourceBlockRecord,
    scope: &RebuildScope,
) -> Result<Candidate, RebuildError> {
    with_catalog(db, scope, |catalog, gone| {
        match rebuild(catalog, block, gone) {
            Ok(plaintext) => Ok(Candidate {
                plaintext,
                legacy_of: None,
            }),
            Err(e) => {
                let plaintext = match &e {
                    RebuildError::SourceMissing { missing, .. } => {
                        unchecked(catalog, block, missing)
                    }
                    RebuildError::Db(_) => None,
                };
                match plaintext {
                    Some(plaintext) => Ok(Candidate {
                        plaintext,
                        legacy_of: Some(e),
                    }),
                    None => Err(e),
                }
            }
        }
    })?
}

/// What the files on this device allow, judged by `metadata` alone (R1-d-b, W3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCheck {
    /// Every source has a candidate file within the size limit: a rebuild may succeed.
    Ready,
    /// A source has no candidate file at all: a rebuild cannot succeed.
    Missing,
    /// A source has candidate files, all above the size limit of this machine (backup-i5).
    OverLimit,
}

/// Whether [`rebuild_plaintext_from_db`] could succeed, without reading a byte: for each source
/// (the file of a Single block; every member of a Pack) some candidate path must exist with
/// `len ≤ scope.max_source_bytes`. Optimistic — a candidate may still have changed content — but
/// never wrong the other way: `Missing` and `OverLimit` mean the rebuild fails. Reports no gone
/// paths (the rebuild itself does). Blocking: one catalog pass and a `metadata` per candidate.
pub fn precheck_sources(
    db: &Db,
    block: &SourceBlockRecord,
    scope: &RebuildScope,
) -> Result<SourceCheck, RebuildError> {
    with_catalog(db, scope, |catalog, _gone| precheck(catalog, block))
}

fn precheck(catalog: &Catalog<'_>, block: &SourceBlockRecord) -> SourceCheck {
    let block_id = block.block_id;
    match &block.block_type {
        SourceBlockType::Single => {
            let hash = catalog.files.iter().find_map(|r| {
                r.versions
                    .iter()
                    .find(|v| v.source_block_id == block_id)
                    .map(|v| v.content_hash)
            });
            match hash {
                Some(h) => catalog.candidates_ok(None, &h),
                None => SourceCheck::Missing,
            }
        }
        SourceBlockType::Pack { entries } => {
            for entry in entries {
                let verdict = match catalog.by_id.get(&entry.file_id).copied() {
                    None => SourceCheck::Missing,
                    Some(owner) => match owner
                        .versions
                        .iter()
                        .find(|v| v.source_block_id == block_id)
                    {
                        Some(first) => catalog.candidates_ok(Some(owner), &first.content_hash),
                        // No version on this block: the rebuild reads the record's own path.
                        None => path_check(&owner.path, catalog.limit),
                    },
                };
                if verdict != SourceCheck::Ready {
                    return verdict;
                }
            }
            SourceCheck::Ready
        }
    }
}

/// One candidate path by `metadata`: `Ready` if a file within `limit`, `OverLimit` if a file
/// above it, `Missing` otherwise (absent or unreadable).
fn path_check(path: &str, limit: u64) -> SourceCheck {
    match std::fs::metadata(path) {
        Ok(m) if m.len() <= limit => SourceCheck::Ready,
        Ok(_) => SourceCheck::OverLimit,
        Err(_) => SourceCheck::Missing,
    }
}

/// Run `f` over one pass of the catalog; the gone paths it met go to `scope.recheck`.
fn with_catalog<T>(
    db: &Db,
    scope: &RebuildScope,
    f: impl FnOnce(&Catalog<'_>, &mut BTreeSet<String>) -> T,
) -> Result<T, RebuildError> {
    let files = db.list_all_files()?;
    let catalog = Catalog::new(&files, scope.device, scope.max_source_bytes);
    let mut gone = BTreeSet::new();
    let out = f(&catalog, &mut gone);
    if let Some(tx) = &scope.recheck {
        for path in gone {
            if tx.try_send(PathBuf::from(&path)).is_err() {
                tracing::debug!(path = %path, "rebuild: recheck channel full or closed; path dropped");
            }
        }
    }
    Ok(out)
}

/// The legacy candidate of a pack: the `missing` members read UNCHECKED from their own
/// record's path, the others as the checked rebuild finds them. Nothing is read unless
/// every missing member's own file has exactly its packed size (a cheap `metadata` gate).
/// A Single block gets no legacy candidate: its plaintext size is not recorded, so the
/// gate is not available, and re-reading a large file for a doomed candidate is the most
/// expensive case (the pre-L1 mismatch there needed a change between two reads of one
/// event — rare).
fn unchecked(
    catalog: &Catalog<'_>,
    block: &SourceBlockRecord,
    missing: &[FileId],
) -> Option<Vec<u8>> {
    let SourceBlockType::Pack { entries } = &block.block_type else {
        return None;
    };
    let own_path = |file_id: &FileId| catalog.by_id.get(file_id).map(|r| r.path.as_str());
    for entry in entries.iter().filter(|e| missing.contains(&e.file_id)) {
        let len = std::fs::metadata(own_path(&entry.file_id)?).ok()?.len();
        if len != entry.size {
            return None;
        }
    }
    let mut members = Vec::with_capacity(entries.len());
    let mut ignored = BTreeSet::new();
    for entry in entries {
        let bytes = if missing.contains(&entry.file_id) {
            let path = own_path(&entry.file_id)?;
            match read_source_bounded(Path::new(path), catalog.limit, 0) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log_unreadable(path, &e, block.block_id);
                    return None;
                }
            }
        } else {
            catalog.read_member(entry, block.block_id, &mut ignored)?
        };
        members.push((entry.file_id, bytes));
    }
    Some(pack_plaintext(&members))
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
            let bytes = hash.and_then(|h| catalog.read_content(None, &h, block_id, gone));
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
    /// `RebuildScope::max_source_bytes`.
    limit: u64,
}

impl<'a> Catalog<'a> {
    fn new(files: &'a [FileRecord], device: Option<DeviceId>, limit: u64) -> Self {
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
            limit,
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
            Some(first) => self.read_content(Some(owner), &first.content_hash, block, gone),
            None => {
                // No version of the record points here (not expected, A10): read its
                // path as before, unchecked; the blob check against the block id decides.
                tracing::debug!(block = %block, path = %owner.path,
                    "rebuild: member record has no version on this block; reading its path");
                read_path(
                    &owner.path,
                    self.limit,
                    block,
                    gone,
                    present_on(owner, self.device),
                )
            }
        }
    }

    /// [`precheck_sources`] of one source: the same candidates `read_content` would try (`own`
    /// first, then the records Present with a version of `hash`), by `metadata`.
    fn candidates_ok(&self, own: Option<&FileRecord>, hash: &[u8; 32]) -> SourceCheck {
        let others = self.by_hash.get(hash).into_iter().flatten().copied();
        let mut over = false;
        for candidate in own.into_iter().chain(others) {
            match path_check(&candidate.path, self.limit) {
                SourceCheck::Ready => return SourceCheck::Ready,
                SourceCheck::OverLimit => over = true,
                SourceCheck::Missing => {}
            }
        }
        if over {
            SourceCheck::OverLimit
        } else {
            SourceCheck::Missing
        }
    }

    /// Bytes with hash `hash`: from `own` (the member's record) first, whatever its
    /// state — the read is hash-checked —, then from every record Present on the device
    /// with a version of that hash. A gone path is reported only for a Present record.
    fn read_content(
        &self,
        own: Option<&FileRecord>,
        hash: &[u8; 32],
        block: SourceBlockId,
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
            if let Some(bytes) = read_path(&candidate.path, self.limit, block, gone, report_gone)
                && blake3::hash(&bytes).as_bytes() == hash
            {
                return Some(bytes);
            }
        }
        None
    }
}

/// Read `path`, at most `limit` bytes. NotFound → `None`, and the path goes to `gone` when
/// `report_gone`; above the limit → `None` with DEBUG, not "gone" and no recheck (the file
/// is there, only too large for this machine; backup-i5); another error (permissions, a
/// locked file) → `None` with DEBUG, next candidate (N3).
fn read_path(
    path: &str,
    limit: u64,
    block: SourceBlockId,
    gone: &mut BTreeSet<String>,
    report_gone: bool,
) -> Option<Vec<u8>> {
    match read_source_bounded(Path::new(path), limit, 0) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.is_not_found() => {
            if report_gone {
                gone.insert(path.to_string());
            }
            None
        }
        Err(e) => {
            log_unreadable(path, &e, block);
            None
        }
    }
}

/// DEBUG for a candidate that was not read: over the size limit, or unreadable.
fn log_unreadable(path: &str, e: &SourceReadError, block: SourceBlockId) {
    match e {
        SourceReadError::TooLarge { size, limit } => {
            tracing::debug!(path = %path, size, limit, block = %block,
                "backup: source over the size limit, not read");
        }
        SourceReadError::Io { source, .. } => {
            tracing::debug!(path = %path, error = %source, "rebuild: candidate unreadable; next one");
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
