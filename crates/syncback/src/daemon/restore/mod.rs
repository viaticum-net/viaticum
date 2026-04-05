// RestoreCoordinator: orchestrate symbol fetch → decode → file write.
//
// Strategy: try local symbols first (symbols_dir); fall back to network fetch
// from holders if insufficient. Network fetch is sequential per holder.
//
// Module layout:
//   mod.rs      — RestoreCoordinator struct, public API, restore(), run()
//   pipeline.rs — decode_block(), extract_from_pack()
//   tests.rs    — all test scenarios

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, Symbol};
use syncback_core::messages::{Message, RestoreRequestMsg};
use syncback_core::types::{
    DeviceId, ErasureParams, FileRecord, FileVersion, IdentityPub, LocalState,
    PlacementStatus, SourceBlockId, SourceBlockType, SymbolPlacement, Timestamp,
};
use tracing::{debug, error, info, warn};

pub mod pipeline;

#[cfg(test)]
mod tests;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors from restore operations.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("file not found in catalog: {path}")]
    FileNotFound { path: String },

    #[error("version not found: {selector:?} for {path}")]
    VersionNotFound { path: String, selector: String },

    #[error("source block not found in DB: {0}")]
    BlockNotFound(SourceBlockId),

    #[error("no alive holders for block {0}")]
    NoHolders(SourceBlockId),

    #[error("insufficient symbols: collected {got}, need {need} for block {block}")]
    InsufficientSymbols {
        block: SourceBlockId,
        got: usize,
        need: usize,
    },

    #[error("decode failed for block {0}: {1}")]
    DecodeFailed(SourceBlockId, String),

    #[error("decryption failed for block {0}")]
    DecryptionFailed(SourceBlockId),

    #[error("decompression failed for block {0}: {1}")]
    DecompressionFailed(SourceBlockId, String),

    #[error("pack index parse failed for block {0}: {1}")]
    PackIndexParseFailed(SourceBlockId, String),

    #[error("restore denied by holder {holder}: trust {current_trust:.2}, budget {restore_budget_gb:.1} GB, requested {restore_gb:.1} GB")]
    EscrowDenied {
        holder: DeviceId,
        current_trust: f64,
        needed_trust: f64,
        restore_budget_gb: f64,
        restore_gb: f64,
    },

    #[error("swarm error: {0}")]
    Swarm(String),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// How to select which version of each file to restore.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionSelector {
    /// Latest backed-up version (default).
    Latest,
    /// Specific version by 0-based index into FileRecord.versions.
    Index(usize),
    /// Nearest version with backed_up_at <= given timestamp.
    BeforeDate(Timestamp),
}

/// A restore request from the user or daemon.
#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Path or prefix to restore. Trailing '/' treated as prefix query.
    pub path: String,
    /// Version selection for all matching files.
    pub version_selector: VersionSelector,
    /// Where to write restored files.
    pub output_dir: PathBuf,
    /// Device ID performing the restore (for LocalState update).
    pub device_id: DeviceId,
}

/// Result of a completed restore.
#[derive(Debug)]
pub struct RestoreResult {
    /// Number of files successfully restored.
    pub files_restored: usize,
    /// Number of source blocks decoded.
    pub blocks_fetched: usize,
    /// Paths that failed to restore (path, reason).
    pub failures: Vec<(String, String)>,
}

/// Configuration for RestoreCoordinator.
#[derive(Debug, Clone)]
pub struct RestoreConfig {
    /// Epoch key for decryption. 32 bytes. Must match the key used during backup.
    pub epoch_key: [u8; 32],
    /// Max parallel holders to fetch symbols from for one block.
    /// TODO: not yet used — fetch_from_holders iterates sequentially.
    pub parallel_holders: usize,
    /// This device's identity (for trust lookup and LocalState update).
    pub identity: IdentityPub,
    /// This device's ID (for LocalState).
    pub device_id: DeviceId,
    /// Directory where bound symbol files are stored (must match BackupConfig.symbols_dir).
    /// Used for Phase 2 local restore.
    pub symbols_dir: PathBuf,
    /// libp2p swarm handle for remote restore.
    /// When Some: fetch_from_holders uses send_to_device (request-response).
    /// When None: only local symbol files are used.
    pub swarm: Option<std::sync::Arc<crate::daemon::network::swarm::SwarmHandle>>,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        RestoreConfig {
            epoch_key: [0u8; 32],
            parallel_holders: 5,
            identity: IdentityPub([0u8; 32]),
            device_id: DeviceId([0u8; 32]),
            symbols_dir: PathBuf::from("symbols"),
            swarm: None,
        }
    }
}

// ─── RestoreCoordinator ───────────────────────────────────────────────────────

/// Orchestrates: path resolution → symbol fetch → decode → file write.
pub struct RestoreCoordinator {
    db: Db,
    config: RestoreConfig,
    encoder: Arc<dyn ErasureEncoder>,
    /// libp2p swarm handle for remote restore.
    swarm: Option<Arc<crate::daemon::network::swarm::SwarmHandle>>,
}

impl RestoreCoordinator {
    /// Create a new coordinator.
    pub fn new(
        db: Db,
        config: RestoreConfig,
        encoder: Arc<dyn ErasureEncoder>,
    ) -> Self {
        let swarm = config.swarm.clone();
        RestoreCoordinator {
            db,
            config,
            encoder,
            swarm,
        }
    }


    /// Execute a restore request.
    ///
    /// 1. Resolve path to FileRecords.
    /// 2. Select version per file.
    /// 3. Deduplicate source blocks.
    /// 4. Decode each block.
    /// 5. Extract + write files.
    /// 6. Update LocalState in DB.
    pub async fn restore(
        &self,
        request: RestoreRequest,
    ) -> Result<RestoreResult, RestoreError> {
        info!(path = %request.path, "restore started");

        // 1. Resolve path → FileRecords
        let file_records = self.resolve_path(&request.path)?;
        if file_records.is_empty() {
            return Ok(RestoreResult {
                files_restored: 0,
                blocks_fetched: 0,
                failures: vec![(
                    request.path.clone(),
                    "no matching files found".to_string(),
                )],
            });
        }

        // 2. Select version per file, collect (record, version) pairs
        let mut resolved: Vec<(FileRecord, FileVersion)> = Vec::new();
        let mut failures: Vec<(String, String)> = Vec::new();

        for record in file_records {
            // select_version borrows record; clone the version before moving record.
            let version_opt = Self::select_version(&record, &request.version_selector)
                .cloned();
            match version_opt {
                Some(version) => {
                    resolved.push((record, version));
                }
                None => {
                    failures.push((
                        record.path.clone(),
                        format!("no matching version for selector {:?}", request.version_selector),
                    ));
                }
            }
        }

        // 3. Deduplicate: source_block_id → Vec<(FileRecord, FileVersion)>
        let mut block_map: HashMap<SourceBlockId, Vec<(FileRecord, FileVersion)>> =
            HashMap::new();
        for (record, version) in resolved {
            block_map
                .entry(version.source_block_id)
                .or_default()
                .push((record, version));
        }

        // 4 & 5. For each unique block: decode → extract → write
        let mut files_restored = 0usize;
        let mut blocks_fetched = 0usize;

        for (block_id, files_in_block) in &block_map {
            // Get SourceBlockRecord for params
            let block_record = match self.db.get_source_block(block_id)? {
                Some(r) => r,
                None => return Err(RestoreError::BlockNotFound(*block_id)),
            };

            let encrypted_size = match block_record.encrypted_size {
                Some(s) => s,
                None => {
                    return Err(RestoreError::DecodeFailed(
                        *block_id,
                        "source block has no encrypted_size (legacy record)".to_string(),
                    ));
                }
            };

            let params = block_record.erasure_params();

            // Decode the block (Phase 2: local symbols_dir)
            let plaintext = self
                .decode_block_local(block_id, &params, encrypted_size)
                .await?;

            blocks_fetched += 1;

            // Extract each file from this block
            for (record, version) in files_in_block {
                let result = self.extract_and_write_file(
                    record,
                    version,
                    &block_record.block_type,
                    &plaintext,
                    &request.output_dir,
                );
                match result {
                    Ok(()) => {
                        if let Err(e) =
                            self.update_local_state(&record.path, request.device_id)
                        {
                            warn!(path = %record.path, "failed to update local state: {e}");
                        }
                        files_restored += 1;
                        info!(path = %record.path, "restored");
                    }
                    Err(e) => {
                        failures.push((record.path.clone(), e.to_string()));
                    }
                }
            }
        }

        Ok(RestoreResult {
            files_restored,
            blocks_fetched,
            failures,
        })
    }

    /// Decode one source block.
    ///
    /// Strategy:
    ///   1. Try local: read symbol files from symbols_dir.
    ///   2. If insufficient local symbols (<k_eff), try network fetch for remaining.
    ///   3. Combine local + network symbols, then decode.
    ///
    /// Decrypts and decompresses the decoded data before returning.
    pub async fn decode_block_local(
        &self,
        block_id: &SourceBlockId,
        params: &ErasureParams,
        encrypted_size: u64,
    ) -> Result<Vec<u8>, RestoreError> {
        let placements = self.db.list_placements_for_block(block_id)?;
        // For local symbol reads, use all non-deleted placements: the symbols
        // are on the owner's disk regardless of holder reachability status.
        // Lost means the holder's copy is gone, not the owner's local .bin files.
        let usable_placements: Vec<_> = placements
            .into_iter()
            .filter(|p| p.status != PlacementStatus::Deleting)
            .collect();

        if usable_placements.is_empty() {
            return Err(RestoreError::NoHolders(*block_id));
        }

        let block_dir = self
            .config
            .symbols_dir
            .join(pipeline::hex_encode(&block_id.0));

        let mut unbound_symbols: Vec<Symbol> = Vec::new();
        let k_eff = params.k_eff as usize;

        'outer: for placement in &usable_placements {
            for (start_esi, count) in &placement.esi_ranges {
                for i in 0..*count {
                    let esi = start_esi + i;
                    let symbol_path = block_dir.join(format!("{esi}.bin"));
                    let data = match std::fs::read(&symbol_path) {
                        Ok(d) => d,
                        Err(e) => {
                            debug!(
                                block = %block_id,
                                esi,
                                "symbol file missing or unreadable: {e}"
                            );
                            continue;
                        }
                    };
                    let bound = Symbol { esi, data };
                    let unbound = self
                        .encoder
                        .unbind(bound, block_id, &placement.holder_id);
                    unbound_symbols.push(unbound);

                    if unbound_symbols.len() >= k_eff {
                        break 'outer;
                    }
                }
            }
        }

        if unbound_symbols.len() < k_eff {
            // Not enough locally — try network fetch for the remainder.
            debug!(
                block = %block_id,
                local = unbound_symbols.len(),
                need = k_eff,
                "decode: insufficient local symbols, trying network"
            );

            // Only try network fetch for Alive placements (reachable holders).
            let alive_for_fetch: Vec<_> = usable_placements
                .iter()
                .filter(|p| p.status == PlacementStatus::Alive)
                .cloned()
                .collect();
            let mut network_symbols = self
                .fetch_from_holders(block_id, &alive_for_fetch, params)
                .await?;

            // Merge: avoid duplicates by ESI.
            let existing_esis: HashSet<u32> =
                unbound_symbols.iter().map(|s| s.esi).collect();
            for sym in network_symbols.drain(..) {
                if !existing_esis.contains(&sym.esi) {
                    unbound_symbols.push(sym);
                    if unbound_symbols.len() >= k_eff {
                        break;
                    }
                }
            }

            if unbound_symbols.len() < k_eff {
                return Err(RestoreError::InsufficientSymbols {
                    block: *block_id,
                    got: unbound_symbols.len(),
                    need: k_eff,
                });
            }
        }

        // Decode: padded to k*t bytes
        let padded = self
            .encoder
            .decode(&unbound_symbols, params)
            .map_err(|e| RestoreError::DecodeFailed(*block_id, e.to_string()))?;

        // Trim to stored blob size
        if padded.len() < encrypted_size as usize {
            return Err(RestoreError::DecodeFailed(
                *block_id,
                format!(
                    "decoded block ({} bytes) smaller than encrypted_size ({})",
                    padded.len(),
                    encrypted_size
                ),
            ));
        }
        let stored = &padded[..encrypted_size as usize];

        // Decrypt + decompress
        pipeline::decrypt_and_decompress(stored, &self.config.epoch_key).map_err(|e| {
            error!(block = %block_id, "decrypt_and_decompress failed: {e}");
            RestoreError::DecryptionFailed(*block_id)
        })
    }

    /// Fetch symbols for a source block from holders over the network.
    ///
    /// Tries holders sequentially, stopping once `k_eff` unbound symbols are
    /// collected. Holders that return RestoreDenied are logged at WARN and
    /// skipped. Network errors per holder are logged at WARN and skipped.
    ///
    /// Returns unbound symbols ready for `encoder.decode()`.
    pub async fn fetch_from_holders(
        &self,
        block_id: &SourceBlockId,
        placements: &[SymbolPlacement],
        params: &ErasureParams,
    ) -> Result<Vec<Symbol>, RestoreError> {
        let k_eff = params.k_eff as usize;
        let mut unbound_symbols: Vec<Symbol> = Vec::new();

        for placement in placements {
            if placement.status != PlacementStatus::Alive {
                continue;
            }
            if unbound_symbols.len() >= k_eff {
                break;
            }

            let still_needed = k_eff - unbound_symbols.len();
            let wanted_esis: Vec<u32> = collect_esis_from_ranges(&placement.esi_ranges)
                .into_iter()
                .take(still_needed)
                .collect();

            if wanted_esis.is_empty() {
                continue;
            }

            let request = RestoreRequestMsg {
                v: 1,
                source_block_id: *block_id,
                esi_list: wanted_esis,
                timestamp: Timestamp::now(),
            };

            match self
                .fetch_symbols_from_holder(&placement.holder_id, request)
                .await
            {
                Ok(symbols) => {
                    debug!(
                        holder = %placement.holder_id,
                        block = %block_id,
                        count = symbols.len(),
                        "fetch: received bound symbols from holder"
                    );
                    for sym in symbols {
                        let unbound = self.encoder.unbind(sym, block_id, &placement.holder_id);
                        unbound_symbols.push(unbound);
                    }
                }
                Err(RestoreError::EscrowDenied { ref holder, .. }) => {
                    warn!(
                        holder = %holder,
                        block = %block_id,
                        "fetch: holder denied restore (escrow), skipping"
                    );
                }
                Err(e) => {
                    warn!(
                        holder = %placement.holder_id,
                        block = %block_id,
                        err = %e,
                        "fetch: holder failed, skipping"
                    );
                }
            }
        }

        if unbound_symbols.len() < k_eff {
            Err(RestoreError::InsufficientSymbols {
                block: *block_id,
                got: unbound_symbols.len(),
                need: k_eff,
            })
        } else {
            Ok(unbound_symbols)
        }
    }

    /// Contact one holder, send a RestoreRequest, receive RestoreResponse via libp2p swarm.
    ///
    /// Returns the raw bound symbols (not yet unbound).
    async fn fetch_symbols_from_holder(
        &self,
        holder_device: &DeviceId,
        request: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, RestoreError> {
        let swarm = match &self.swarm {
            Some(s) => s,
            None => {
                return Err(RestoreError::Swarm(
                    "no swarm configured for remote restore".to_string(),
                ));
            }
        };

        let response = swarm
            .send_to_device(*holder_device, Message::RestoreRequest(request))
            .await
            .map_err(|e| RestoreError::Swarm(e.to_string()))?;

        match response {
            Message::RestoreResponse(resp) => {
                debug!(
                    holder = %holder_device,
                    symbols = resp.symbols.len(),
                    "fetch: received RestoreResponse via swarm"
                );
                Ok(resp.symbols)
            }
            Message::RestoreDenied(denied) => Err(RestoreError::EscrowDenied {
                holder: *holder_device,
                current_trust: denied.current_trust,
                needed_trust: denied.needed_trust,
                restore_budget_gb: denied.restore_budget_gb,
                restore_gb: denied.restore_budget_gb + 1.0, // approximate
            }),
            other => {
                warn!(
                    holder = %holder_device,
                    msg = ?std::mem::discriminant(&other),
                    "fetch: unexpected swarm response, treating as error"
                );
                Err(RestoreError::Swarm(
                    "unexpected message type during restore".to_string(),
                ))
            }
        }
    }

    /// Extract one file from decoded plaintext and write to output_dir.
    fn extract_and_write_file(
        &self,
        record: &FileRecord,
        version: &FileVersion,
        block_type: &SourceBlockType,
        plaintext: &[u8],
        output_dir: &std::path::Path,
    ) -> Result<(), RestoreError> {
        let file_bytes = match block_type {
            SourceBlockType::Pack { .. } => {
                let extracted = pipeline::extract_from_pack(plaintext, record.file_id)
                    .map_err(|e| {
                        RestoreError::PackIndexParseFailed(
                            version.source_block_id,
                            e.to_string(),
                        )
                    })?;
                match extracted {
                    Some(bytes) => bytes,
                    None => {
                        return Err(RestoreError::PackIndexParseFailed(
                            version.source_block_id,
                            format!("file_id {} not found in pack", record.file_id),
                        ));
                    }
                }
            }
            SourceBlockType::Single => plaintext.to_vec(),
        };

        // Strip leading '/' for relative output path
        let rel = record.path.trim_start_matches('/');
        let out_path = output_dir.join(rel);

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&out_path, &file_bytes)?;
        debug!(src = %record.path, dst = ?out_path, "wrote restored file");
        Ok(())
    }

    /// Update FileRecord.devices for device_id → LocalState::Present.
    fn update_local_state(
        &self,
        path: &str,
        device_id: DeviceId,
    ) -> Result<(), RestoreError> {
        if let Some(mut record) = self.db.get_file(path)? {
            match record.devices.iter_mut().find(|(d, _)| *d == device_id) {
                Some((_, state)) => *state = LocalState::Present,
                None => record.devices.push((device_id, LocalState::Present)),
            }
            self.db.upsert_file(&record)?;
        }
        Ok(())
    }

    /// Resolve path to FileRecords.
    ///
    /// Trailing '/' → prefix query.
    /// Otherwise: exact lookup, then prefix fallback for folder paths.
    fn resolve_path(&self, path: &str) -> Result<Vec<FileRecord>, RestoreError> {
        if path.ends_with('/') {
            Ok(self.db.list_files_with_prefix(path)?)
        } else {
            match self.db.get_file(path)? {
                Some(r) => Ok(vec![r]),
                None => Ok(self.db.list_files_with_prefix(path)?),
            }
        }
    }

    /// Select which FileVersion to restore.
    ///
    /// - `Latest`:      last version with `backed_up_at.is_some()`
    /// - `Index(n)`:    `versions[n]`
    /// - `BeforeDate`:  last version with `backed_up_at.is_some() && backed_up_at <= ts`
    pub fn select_version<'a>(
        record: &'a FileRecord,
        selector: &VersionSelector,
    ) -> Option<&'a FileVersion> {
        match selector {
            VersionSelector::Latest => record
                .versions
                .iter()
                .rev()
                .find(|v| v.backed_up_at.is_some()),
            VersionSelector::Index(n) => record.versions.get(*n),
            VersionSelector::BeforeDate(ts) => record
                .versions
                .iter()
                .rev()
                .find(|v| v.backed_up_at.map(|t| t.0 <= ts.0).unwrap_or(false)),
        }
    }

    /// Run the coordinator as a tokio task.
    ///
    /// Accepts (RestoreRequest, oneshot::Sender) from rx, processes sequentially.
    pub async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<(
            RestoreRequest,
            tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
        )>,
    ) -> anyhow::Result<()> {
        info!("RestoreCoordinator started");
        while let Some((request, reply)) = rx.recv().await {
            let result = self.restore(request).await;
            let _ = reply.send(result);
        }
        info!("RestoreCoordinator: channel closed, exiting");
        Ok(())
    }
}

// ─── Free helpers ─────────────────────────────────────────────────────────────

/// Expand (start, count) ESI ranges into a flat sorted list of ESIs.
pub(crate) fn collect_esis_from_ranges(ranges: &[(u32, u32)]) -> Vec<u32> {
    ranges
        .iter()
        .flat_map(|&(start, count)| start..start + count)
        .collect()
}
