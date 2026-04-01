// Epidemic relay module: local board management and partner sync.
//
// The relay implements an "announcement board" — an append-only file per node
// that stores broadcast and directed messages. Relay nodes copy messages from
// their partners' boards (hop < MAX_RELAY_HOP), achieving deferred
// store-and-forward messaging without requiring online simultaneity.
//
// Entry lifecycle:
//   hop=0  authored here, written directly
//   hop=1  copied from a direct partner (check_relay_hop passed on their hop=0)
//   hop=2  copied from a partner's partner (check_relay_hop passed on hop=1)
//   hop≥2  not relayed further (check_relay_hop returns Err)
//
// Thread-safety: RelayManager is Send but not Sync (uses &mut self for writes).
// The daemon wraps it in a Mutex<RelayManager> or runs it as a dedicated task.

use std::collections::HashSet;
use std::path::PathBuf;

use syncback_core::constants::{MAX_BOARD_ENTRIES, MAX_BOARD_SIZE_BYTES};
use syncback_core::messages::{
    build_broadcast_entry, build_directed_entry, check_relay_hop, decrypt_directed,
    encrypt_directed, from_cbor, is_board_entry_expired, relay_copy, to_cbor,
    verify_board_entry_sig, BoardEntryKind, MessageError, StoredEntry,
};
use syncback_core::types::{IdentityPub, Timestamp};
use tracing::{debug, error, info, warn};

mod board;

#[cfg(test)]
mod tests;

// ─── Public types ─────────────────────────────────────────────────────────────

/// A decoded inbound message directed at us, delivered to the daemon.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Who sent this message (author of the board entry).
    pub from: IdentityPub,
    /// Raw bytes of the inner message (already decrypted if directed).
    pub payload: Vec<u8>,
    /// Message type string (e.g. "pos_challenge").
    pub msg_type: String,
    /// Unique message identifier (16 bytes).
    pub msg_id: [u8; 16],
    /// When the entry was created (for logging / TTL checks).
    pub created_at: Timestamp,
}

/// Configuration for the relay module.
#[derive(Clone)]
pub struct RelayConfig {
    /// Path to the local board file.
    pub board_path: PathBuf,
    /// Our identity public key. Used to filter entries directed at us.
    pub identity_pub: IdentityPub,
    /// Our X25519 private key for decrypting directed messages.
    pub x25519_priv: x25519_dalek::StaticSecret,
    /// Our Ed25519 signing key for authoring board entries.
    pub signing_key: ed25519_dalek::SigningKey,
    /// Max entries on our board before oldest are pruned.
    pub max_entries: usize,
    /// Max total board size in bytes before oldest entries are pruned.
    pub max_size_bytes: usize,
    /// How often to prune the board (seconds).
    pub prune_interval_secs: u64,
}

impl RelayConfig {
    /// Convenience constructor for tests.
    pub fn defaults_for_test(board_path: PathBuf) -> Self {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
        let x25519_priv = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        Self {
            board_path,
            identity_pub,
            x25519_priv,
            signing_key,
            max_entries: MAX_BOARD_ENTRIES,
            max_size_bytes: MAX_BOARD_SIZE_BYTES,
            prune_interval_secs: 3600,
        }
    }
}

/// Errors from relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("io error reading/writing board: {0}")]
    Io(#[from] std::io::Error),

    #[error("message error: {0}")]
    Message(#[from] MessageError),

    #[error("board corrupted at entry {index}: {reason}")]
    BoardCorrupted { index: usize, reason: String },

    #[error("board size limit exceeded (max {max} entries)")]
    BoardFull { max: usize },
}

/// A trigger to sync boards with a partner (sent when a connection is established).
#[derive(Debug)]
pub struct SyncTrigger {
    pub partner_identity: IdentityPub,
    /// Partner's current board entries, already fetched by the network layer.
    pub partner_entries: Vec<StoredEntry>,
}

/// Command to post a message to the local board.
/// Sent by Scheduler/Processor via relay_post_tx.
#[derive(Debug)]
pub struct RelayPost {
    pub msg_type: String,
    pub target: Option<IdentityPub>, // None = broadcast
    pub payload: Vec<u8>,            // CBOR-encoded message
    pub msg_id: [u8; 16],
}

// ─── RelayManager ────────────────────────────────────────────────────────────

/// Manages the local relay board and syncs with partner boards.
pub struct RelayManager {
    config: RelayConfig,
    /// In-memory index of msg_ids we already have (for O(1) dedup).
    known_ids: HashSet<[u8; 16]>,
    /// All entries currently on our board, in append order.
    pub entries: Vec<StoredEntry>,
    /// msg_ids already delivered to inbound_tx. Prevents re-delivery on every scan.
    delivered_ids: HashSet<[u8; 16]>,
    /// True when entries changed since last board push (avoids redundant broadcasts).
    board_dirty: bool,
}

impl RelayManager {
    /// Create a new manager.
    ///
    /// Loads existing board from disk (if present), rebuilds the `known_ids`
    /// index, and prunes expired entries on startup.
    pub fn new(config: RelayConfig) -> Result<Self, RelayError> {
        let entries = board::load_board(&config.board_path)?;
        let known_ids: HashSet<[u8; 16]> = entries.iter().map(|e| e.msg_id).collect();

        let mut manager = Self {
            config,
            known_ids,
            board_dirty: !entries.is_empty(),
            entries,
            delivered_ids: HashSet::new(),
        };

        // Prune on startup so stale entries from a previous run don't linger.
        let now = Timestamp::now();
        let pruned = manager.prune(now)?;
        if pruned > 0 {
            info!(pruned, "pruned expired entries on startup");
        }

        Ok(manager)
    }

    // ── Posting ────────────────────────────────────────────────────────────

    /// Post a new broadcast entry authored by us (hop=0).
    ///
    /// Builds a [`BoardEntry`] via [`build_broadcast_entry`], appends to the
    /// board file and in-memory list, and returns the stored entry.
    pub fn post_broadcast(
        &mut self,
        msg_type: &str,
        msg_id: [u8; 16],
        payload: Vec<u8>,
        now: Timestamp,
    ) -> Result<StoredEntry, RelayError> {
        let entry = build_broadcast_entry(
            msg_type,
            msg_id,
            payload,
            self.config.identity_pub,
            now,
            &self.config.signing_key,
        );
        let stored = StoredEntry {
            msg_type: msg_type.to_string(),
            msg_id,
            entry,
        };
        self.append(stored)
    }

    /// Post a new directed entry authored by us (hop=0).
    ///
    /// Encrypts `plaintext_payload` for `target_pub` using ECDH
    /// (`encrypt_directed`), builds a [`BoardEntry`] via
    /// [`build_directed_entry`], appends to the board and returns the entry.
    ///
    /// The target's X25519 public key must be provided explicitly. In the full
    /// system, peers publish their X25519 key via `PeerAnnounceMsg`; in tests,
    /// the key is passed directly.
    pub fn post_directed_with_key(
        &mut self,
        msg_type: &str,
        msg_id: [u8; 16],
        target_pub: IdentityPub,
        target_x25519_pub: &x25519_dalek::PublicKey,
        plaintext_payload: &[u8],
        now: Timestamp,
    ) -> Result<StoredEntry, RelayError> {
        let envelope = encrypt_directed(plaintext_payload, target_x25519_pub)?;
        let encrypted_cbor = to_cbor(&envelope)?;

        let entry = build_directed_entry(
            msg_type,
            msg_id,
            target_pub,
            encrypted_cbor,
            self.config.identity_pub,
            now,
            &self.config.signing_key,
        );
        let stored = StoredEntry {
            msg_type: msg_type.to_string(),
            msg_id,
            entry,
        };
        self.append(stored)
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    /// Process entries received from a partner's board during sync.
    ///
    /// For each entry:
    /// 1. Skip if msg_id already in known_ids (dedup).
    /// 2. Skip if expired.
    /// 3. Skip if hop >= MAX_RELAY_HOP.
    /// 4. Verify sig — log and skip on failure.
    /// 5. relay_copy (hop+1) and append.
    ///
    /// Returns the count of entries accepted.
    pub fn process_remote_entries(
        &mut self,
        remote_entries: &[StoredEntry],
        now: Timestamp,
    ) -> Result<usize, RelayError> {
        let mut accepted = 0usize;

        for remote in remote_entries {
            // 1. Dedup.
            if self.known_ids.contains(&remote.msg_id) {
                debug!(msg_id = ?remote.msg_id, "relay: skipping known msg_id");
                continue;
            }

            // 2. TTL check.
            if is_board_entry_expired(&remote.entry, now) {
                debug!(msg_id = ?remote.msg_id, "relay: skipping expired entry");
                continue;
            }

            // 3. Hop check.
            if check_relay_hop(&remote.entry).is_err() {
                debug!(
                    msg_id = ?remote.msg_id,
                    hop = remote.entry.hop,
                    "relay: skipping entry at hop limit"
                );
                continue;
            }

            // 4. Signature verification.
            if let Err(e) =
                verify_board_entry_sig(&remote.entry, &remote.msg_type, &remote.msg_id)
            {
                warn!(
                    msg_id = ?remote.msg_id,
                    err = %e,
                    "relay: bad signature, dropping entry"
                );
                continue;
            }

            // 5. Accept: increment hop and store.
            let relayed = relay_copy(&remote.entry);
            let stored = StoredEntry {
                msg_type: remote.msg_type.clone(),
                msg_id: remote.msg_id,
                entry: relayed,
            };
            self.append(stored)?;
            accepted += 1;
        }

        Ok(accepted)
    }

    // ── Reading ────────────────────────────────────────────────────────────

    /// Scan our board for entries directed at us; decrypt and deliver them.
    ///
    /// Broadcast entries are delivered as-is (payload is already plain CBOR).
    /// Directed entries are decrypted with our X25519 private key.
    ///
    /// Uses `try_send` — if the channel is full the message is dropped and a
    /// warning is logged. Each msg_id is delivered at most once per manager
    /// lifetime (tracked via `delivered_ids`); entries already delivered are
    /// skipped on subsequent scans.
    ///
    /// Returns the count of messages sent to `inbound_tx`.
    pub fn scan_for_self(
        &mut self,
        inbound_tx: &tokio::sync::mpsc::Sender<InboundMessage>,
        now: Timestamp,
    ) -> usize {
        let mut delivered = 0usize;

        for stored in &self.entries {
            if is_board_entry_expired(&stored.entry, now) {
                continue;
            }

            // Skip entries already delivered in a previous scan.
            if self.delivered_ids.contains(&stored.msg_id) {
                continue;
            }

            let msg_opt = match stored.entry.kind {
                BoardEntryKind::Broadcast => Some(InboundMessage {
                    from: stored.entry.author,
                    payload: stored.entry.payload.clone(),
                    msg_type: stored.msg_type.clone(),
                    msg_id: stored.msg_id,
                    created_at: stored.entry.created_at,
                }),

                BoardEntryKind::Directed => {
                    // Only messages targeted at us.
                    if stored.entry.target_pub != Some(self.config.identity_pub) {
                        continue;
                    }

                    let envelope = match from_cbor(&stored.entry.payload) {
                        Ok(env) => env,
                        Err(e) => {
                            warn!(
                                msg_id = ?stored.msg_id,
                                err = %e,
                                "relay: failed to decode directed envelope"
                            );
                            continue;
                        }
                    };

                    let plaintext = match decrypt_directed(&envelope, &self.config.x25519_priv) {
                        Ok(pt) => pt,
                        Err(e) => {
                            warn!(
                                msg_id = ?stored.msg_id,
                                err = %e,
                                "relay: failed to decrypt directed payload"
                            );
                            continue;
                        }
                    };

                    Some(InboundMessage {
                        from: stored.entry.author,
                        payload: plaintext,
                        msg_type: stored.msg_type.clone(),
                        msg_id: stored.msg_id,
                        created_at: stored.entry.created_at,
                    })
                }
            };

            if let Some(msg) = msg_opt {
                match inbound_tx.try_send(msg) {
                    Ok(()) => {
                        self.delivered_ids.insert(stored.msg_id);
                        delivered += 1;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        warn!(msg_id = ?stored.msg_id, "relay: inbound channel full, dropping message");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        error!("relay: inbound channel closed");
                        break;
                    }
                }
            }
        }

        delivered
    }

    // ── Maintenance ────────────────────────────────────────────────────────

    /// Remove expired entries and enforce board size limits.
    ///
    /// TTL rule: `entry.created_at + RELAY_TTL_SECS <= now` → remove.
    /// Size rule: if count > max_entries OR total_bytes > max_size_bytes,
    ///   remove oldest entries (lowest `created_at`) until within limits.
    ///
    /// Rewrites the board file after pruning.
    /// Returns the count of entries removed.
    pub fn prune(&mut self, now: Timestamp) -> Result<usize, RelayError> {
        let before = self.entries.len();

        // 1. Remove expired entries.
        self.entries
            .retain(|e| !is_board_entry_expired(&e.entry, now));

        // 2. Enforce size limits (oldest-first: entries are in append order).
        // Drop from the front until within limits.
        while self.entries.len() > self.config.max_entries {
            self.entries.remove(0);
        }

        // Byte-size limit: approximate.
        let mut total_bytes: usize = self
            .entries
            .iter()
            .map(board::entry_size_bytes)
            .sum();
        while total_bytes > self.config.max_size_bytes && !self.entries.is_empty() {
            let removed = self.entries.remove(0);
            total_bytes = total_bytes.saturating_sub(board::entry_size_bytes(&removed));
        }

        let removed = before - self.entries.len();

        if removed > 0 {
            // Rebuild known_ids from survivors.
            self.known_ids = self.entries.iter().map(|e| e.msg_id).collect();

            // Discard delivered_ids for entries that are no longer on the board.
            self.delivered_ids.retain(|id| self.known_ids.contains(id));

            // Atomic rewrite.
            board::rewrite_board(&self.config.board_path, &self.entries)?;

            debug!(removed, remaining = self.entries.len(), "relay: pruned board");
        }

        Ok(removed)
    }

    /// Return a snapshot of all non-expired entries for sharing with a partner.
    ///
    /// Called when a partner connects and requests board sync.
    pub fn entries_for_sync(&self, now: Timestamp) -> Vec<StoredEntry> {
        self.entries
            .iter()
            .filter(|e| !is_board_entry_expired(&e.entry, now))
            .cloned()
            .collect()
    }

    /// Return `(entry_count, approximate_size_bytes)`.
    pub fn stats(&self) -> (usize, usize) {
        let bytes: usize = self.entries.iter().map(board::entry_size_bytes).sum();
        (self.entries.len(), bytes)
    }

    // ── Background task ────────────────────────────────────────────────────

    /// Run the relay manager as a tokio task.
    ///
    /// Listens for sync triggers (partner connections) via `sync_rx`.
    /// Accepts new posts from other subsystems via `post_rx`.
    /// Periodically broadcasts the board to all known peers.
    /// Runs a prune timer every `prune_interval_secs`.
    /// Delivers inbound messages to `inbound_tx`.
    pub async fn run(
        mut self,
        mut sync_rx: tokio::sync::mpsc::Receiver<SyncTrigger>,
        inbound_tx: tokio::sync::mpsc::Sender<InboundMessage>,
        mut post_rx: tokio::sync::mpsc::Receiver<RelayPost>,
        db: syncback_core::db::Db,
        board_sync_interval_secs: u64,
        swarm: Option<std::sync::Arc<crate::daemon::network::swarm::SwarmHandle>>,
    ) -> anyhow::Result<()> {

        use tokio::time::{interval, Duration};

        let prune_interval =
            Duration::from_secs(self.config.prune_interval_secs);
        let mut prune_timer = interval(prune_interval);
        // First tick fires immediately; skip it so we don't double-prune
        // right after `new()` already pruned on startup.
        prune_timer.tick().await;

        let mut board_push_timer = interval(Duration::from_secs(board_sync_interval_secs));
        // Skip first tick (entries are empty at startup anyway).
        board_push_timer.tick().await;

        info!(
            board_sync_interval_secs,
            "relay manager running"
        );

        loop {
            tokio::select! {
                trigger = sync_rx.recv() => {
                    match trigger {
                        None => {
                            info!("relay: sync_rx closed, shutting down");
                            break;
                        }
                        Some(t) => {
                            let now = Timestamp::now();
                            match self.process_remote_entries(&t.partner_entries, now) {
                                Ok(n) => {
                                    debug!(
                                        partner = %t.partner_identity,
                                        accepted = n,
                                        "relay: board sync"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        partner = %t.partner_identity,
                                        err = %e,
                                        "relay: board sync error"
                                    );
                                }
                            }
                            self.scan_for_self(&inbound_tx, now);
                        }
                    }
                }

                post = post_rx.recv() => {
                    match post {
                        None => {
                            info!("relay: post_rx closed, shutting down");
                            break;
                        }
                        Some(post) => {
                            let now = Timestamp::now();
                            if let Some(target) = post.target {
                                // PeerRecord is keyed by DeviceId; look up via master identity.
                                let peer_opt = db.get_devices_for_master(&target)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .find_map(|did| db.get_peer(&did).ok().flatten());
                                match peer_opt {
                                    Some(peer) => {
                                        if let Some(x25519_bytes) = peer.x25519_pub {
                                            let x25519_pub = x25519_dalek::PublicKey::from(x25519_bytes);
                                            if let Err(e) = self.post_directed_with_key(
                                                &post.msg_type, post.msg_id, target,
                                                &x25519_pub, &post.payload, now,
                                            ) {
                                                error!(err = %e, msg_type = %post.msg_type, "relay: post_directed failed");
                                            }
                                        } else {
                                            warn!(target = %target, msg_type = %post.msg_type,
                                                  "relay: no x25519_pub for target, dropping directed post");
                                        }
                                    }
                                    None => {
                                        warn!(target = %target, msg_type = %post.msg_type,
                                              "relay: peer not found for directed post");
                                    }
                                }
                            } else if let Err(e) = self.post_broadcast(
                                &post.msg_type, post.msg_id, post.payload, now,
                            ) {
                                error!(err = %e, msg_type = %post.msg_type, "relay: post_broadcast failed");
                            }
                        }
                    }
                }

                _ = board_push_timer.tick() => {
                    if let Some(ref swarm) = swarm {
                        self.push_board_to_peers(&db, swarm).await;
                    }
                }

                _ = prune_timer.tick() => {
                    let now = Timestamp::now();
                    match self.prune(now) {
                        Ok(n) => {
                            if n > 0 {
                                info!(pruned = n, "relay: periodic prune");
                            }
                        }
                        Err(e) => {
                            error!(err = %e, "relay: prune error");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Push local board entries to all connected peers via BoardSync messages.
    /// Only pushes when new entries were added since last push (board_dirty flag).
    async fn push_board_to_peers(
        &mut self,
        db: &syncback_core::db::Db,
        swarm: &crate::daemon::network::swarm::SwarmHandle,
    ) {
        use syncback_core::messages::{BoardSyncMsg, Message};

        if self.entries.is_empty() || !self.board_dirty {
            return;
        }
        self.board_dirty = false;

        let peers = match db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                warn!(err = %e, "relay: board push — failed to list peers");
                return;
            }
        };

        let msg = BoardSyncMsg {
            v: 1,
            entries: self.entries.clone(),
            timestamp: Timestamp::now(),
        };

        let mut ok = 0u32;
        let mut fail = 0u32;
        for peer in &peers {
            match swarm.send_to_device(peer.device_id, Message::BoardSync(msg.clone())).await {
                Ok(_) => { ok += 1; }
                Err(_) => { fail += 1; }
            }
        }

        if ok > 0 || fail > 0 {
            debug!(entries = self.entries.len(), ok, fail, "relay: board push complete");
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────

    /// Append an entry to the in-memory list, disk, and known_ids.
    fn append(&mut self, stored: StoredEntry) -> Result<StoredEntry, RelayError> {
        board::append_entry(&self.config.board_path, &stored)?;
        self.known_ids.insert(stored.msg_id);
        self.entries.push(stored.clone());
        self.board_dirty = true;
        Ok(stored)
    }
}
