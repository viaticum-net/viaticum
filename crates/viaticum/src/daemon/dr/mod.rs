// Disaster recovery: restore node state from seed phrase via mailbox bus.
//
// Runs standalone (no daemon, no Processor). Connects to seed peers via libp2p
// SwarmHandle, walks the mailbox candidate-set to find the freshest SelfPointer,
// then fetches and restores the DB from the base+diff blocks.
//
// DR is transactional (spec B2 §1.5.1): every refusal happens before the data dir
// changes, all work goes into drafts (`db.redb.dr-new`, `identity.key.dr-new`), and
// the drafts are installed by a series of renames only after the network phase
// succeeded. A failed DR leaves the folder as it was.
//
//   1. preflight (dr/preflight): phrase → keyfile in memory; lock probe on db.redb
//      (live daemon → stop); identity.key must carry the phrase's seed (same →
//      reuse it, device id kept; other → stop); claim the staging DB
//   2. KeySource::New: write the key draft
//   3. Db::create_from_file on the claimed staging file
//   4. Start SwarmHandle with seed peers as kademlia_bootstrap_peers
//   5. wait_for_kad_bootstrap_stable: drain PeerAuthenticated events,
//      upsert each peer to DB, return when min_peers reached or timeout
//   6. get_closest_peers(hash(my_master_pub)) → dial + authenticate closest peers
//      so MailboxRouter.dr_walk_for_pointer has a populated DB to work with
//   7. MailboxRouter.dr_walk_for_pointer: expanding batches [100,300,1000]
//      sends MailboxFetchRequest, verifies SelfPointer signatures, picks freshest
//   8. dial_pointer_holders: try HolderHint.addrs first (fast); if empty or failed,
//      fall back to get_closest_peers(holder_id) (B-1 Kademlia-first DR path)
//   9. fetch_ss_block per base+diffs → apply_diffs → restore_db_force (staging DB)
//  10. drop swarm + DB, commit (dr/commit): old db.redb → .dr-bak[.N], staging →
//      db.redb, key last. Any error in 2-9 → abort: remove only this run's drafts.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use viaticum_core::constants::DR_KAD_STABILIZE_TIMEOUT_SECS;
use viaticum_core::types::{IdentityPub, PeerRecord, Timestamp, hex_encode};

use crate::daemon::identity::{MnemonicProblem, derive_keys};
use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::mailbox::routing::MailboxRouter;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmConfig, SwarmHandle};

mod commit;
mod preflight;

#[cfg(test)]
mod tests;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Per-connection timeout for dial + DeviceCertExchange.
const AUTH_TIMEOUT_SECS: u64 = 15;

/// Minimum authenticated peers before DR walk proceeds.
///
/// 1 peer is the minimum: a single authenticated peer gives us a DB entry and
/// a live channel to send MailboxFetchRequest. We still drain more events until
/// the timeout so the DB is as full as possible, but we don't burn 120s waiting
/// for unreachable counts on small test networks. Rationale: in a 5-node cluster
/// only 4 other peers exist; with min=5 the full DR_KAD_STABILIZE_TIMEOUT_SECS
/// (120s) always fires, adding 120s to DR time unnecessarily.
const KAD_MIN_PEERS_FOR_DR: usize = 1;

/// Per-peer timeout when dialing candidate peers discovered via get_closest_peers.
const CANDIDATE_DIAL_TIMEOUT_SECS: u64 = 10;

// ─── Options and errors ──────────────────────────────────────────────────────

/// What `viaticum dr` was asked to do.
pub struct DrOptions {
    pub mnemonic: String,
    /// `--peer` multiaddrs (with `/p2p/<peer id>`).
    pub peers: Vec<String>,
    pub data_dir: PathBuf,
}

/// Why DR stopped. Every variant up to `Failed` leaves the data dir as it was;
/// the texts are what the friend reads.
#[derive(Debug, thiserror::Error)]
pub enum DrError {
    #[error("the recovery phrase is not valid: {0}. Nothing was changed.")]
    InvalidPhrase(MnemonicProblem),
    #[error(
        "{data_dir} belongs to a different identity (folder: {folder}, phrase: {phrase}). \
         Nothing was changed. Run DR into an empty directory (--data-dir <new dir>), or move \
         this directory away if you are sure it is not needed."
    )]
    ForeignIdentity {
        data_dir: String,
        folder: String,
        phrase: String,
    },
    #[error(
        "identity.key in {data_dir} is unreadable ({reason}). Nothing was changed. \
         Move it away and run DR again."
    )]
    KeyfileUnreadable { data_dir: String, reason: String },
    #[error(
        "{data_dir} is in use by a running Viaticum daemon or another DR. Stop it first. \
         Nothing was changed."
    )]
    DataDirInUse { data_dir: String },
    #[error("another DR is already running in {data_dir}. Nothing was changed.")]
    DrInProgress { data_dir: String },
    #[error(
        "could not reach any peer: check the --peer address and the network. \
         Nothing was changed."
    )]
    NoCandidates,
    /// `responders` goes to the log (the pre-B2.2 walk does not count them → None).
    #[error(
        "no catalog found for this recovery phrase. A node publishes its first \
         recovery pointer about 12 hours after install; if it is older, try other \
         --peer addresses. Nothing was changed."
    )]
    NoCatalogFound { responders: Option<usize> },
    /// Network / fetch / decode / restore failure before the commit.
    #[error("DR failed: {reason}. Nothing was changed.{hint}")]
    Failed { reason: String, hint: String },
    #[error("DR could not finish installing the recovered state: {0}")]
    Commit(String),
}

fn dr_failed(reason: impl std::fmt::Display) -> DrError {
    DrError::Failed {
        reason: reason.to_string(),
        hint: String::new(),
    }
}

/// Counts printed after a successful DR.
struct RecoveredSummary {
    files: usize,
    source_blocks: usize,
    placements: usize,
    peers: usize,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Run disaster recovery: restore node state from the recovery phrase into
/// `opts.data_dir`. Transactional: on `Err` the folder is as it was (see the module
/// header), except `DrError::Commit`, whose text says what lies where.
pub async fn run_dr(opts: DrOptions) -> Result<(), DrError> {
    println!("Starting disaster recovery...");
    println!("Data directory: {}", opts.data_dir.display());

    // ── 1. Preflight: phrase, folder, locks, staging claim ────────────────────
    let mut plan = preflight::preflight(&opts.data_dir, &opts.mnemonic)?;
    for w in &plan.warnings {
        eprintln!("warning: {w}");
    }
    println!(
        "Identity restored: {}",
        hex_encode(&plan.keyfile.identity_pub)
    );
    if plan.key_source == preflight::KeySource::Existing {
        println!("Using the existing identity.key in this folder (same identity, device id kept).");
    }

    // ── 2-9. Drafts + network; everything that holds the staging DB is dropped
    //         when this returns ────────────────────────────────────────────────
    let recovered = match plan.stage_key() {
        Ok(()) => recover_into_staging(&mut plan, &opts.peers).await,
        Err(e) => Err(e),
    };
    let summary = match recovered {
        Ok(s) => s,
        Err(e) => {
            commit::abort(&mut plan);
            return Err(e);
        }
    };

    // ── 10. Commit ────────────────────────────────────────────────────────────
    let outcome = commit::commit(plan)?;

    println!("DR restore successful:");
    println!("  Files:         {}", summary.files);
    println!("  Source blocks: {}", summary.source_blocks);
    println!("  Placements:    {}", summary.placements);
    println!("  Peers:         {}", summary.peers);
    if let Some(bak) = &outcome.db_backup {
        println!("Previous database kept as: {}", bak.display());
        println!("  (to go back to it: stop the daemon and move it over db.redb)");
    }
    println!();
    println!("Your files are not on this machine yet. The network keeps them, but they are");
    println!("not re-protected (repair, storage proofs) until they are back at their original");
    println!("paths.");
    println!("  1. viaticum daemon --watch-dir <folder>");
    println!("  2. viaticum restore <path>        (restored copies go to the staging folder)");
    println!("  3. Move the restored files back to their original paths.");

    Ok(())
}

/// Steps 3-9: build the recovered state in the staging DB. Takes the claimed
/// staging file from the plan; the DB, the swarm and the router live only inside
/// this call, so on return (Ok or Err) redb's handle on the staging file is closed.
async fn recover_into_staging(
    plan: &mut preflight::DrPlan,
    peer_addrs: &[String],
) -> Result<RecoveredSummary, DrError> {
    // ── 3. Fresh DB in the staging file ───────────────────────────────────────
    let staging_file = plan
        .staging
        .file
        .take()
        .ok_or_else(|| dr_failed("the staging database was not claimed"))?;
    // On Windows a second exclusive lock through the same handle fails (redb would
    // report DatabaseAlreadyOpen): hand redb an unlocked handle there (A15).
    #[cfg(windows)]
    let _ = staging_file.unlock();
    let db = viaticum_core::db::Db::create_from_file(staging_file)
        .map_err(|e| dr_failed(format!("cannot create the recovery database: {e}")))?;

    let keyfile = &plan.keyfile;
    let (master_key, device_key, _epoch_key_bytes) = derive_keys(keyfile, 0).map_err(dr_failed)?;
    let my_master_pub = viaticum_core::types::IdentityPub(keyfile.identity_pub);
    let device_id = viaticum_core::types::DeviceId(keyfile.device_id);

    // ── 4. Start SwarmHandle with seed peers as Kademlia bootstrap peers ──────
    // Parse seed addresses into Multiaddr for kademlia_bootstrap_peers so that
    // kad.bootstrap() (fired on the first event-loop tick) actually reaches them.
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&master_key, device_id, Timestamp::now());

    let bootstrap_multiaddrs: Vec<libp2p::Multiaddr> = peer_addrs
        .iter()
        .filter_map(|s| {
            // Keep the full /p2p/... multiaddr for Kademlia (it needs the PeerId component).
            match s.parse::<libp2p::Multiaddr>() {
                Ok(ma) => Some(ma),
                Err(e) => {
                    tracing::warn!("dr: skip invalid multiaddr '{s}': {e}");
                    None
                }
            }
        })
        .collect();

    let swarm_cfg = SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub: my_master_pub,
        cluster_master_pub: my_master_pub,
        device_cert,
        x25519_pub: None,
        listen_port: 0,
        cert_timeout_secs: AUTH_TIMEOUT_SECS,
        // Seed peers as Kademlia bootstrap so DHT routing table populates.
        kademlia_bootstrap_peers: bootstrap_multiaddrs.clone(),
        kademlia_disable_ipfs_bootstrap: true,
        kad_republish_interval_override: None,
        kad_discovery_interval_override: None,
        enable_relay_server: false,
    };

    let (swarm_handle, mut event_rx) = SwarmHandle::start(swarm_cfg)
        .await
        .map_err(|e| dr_failed(format!("cannot start networking: {e}")))?;
    println!("Network ready. Waiting for Kademlia bootstrap...");

    // ── 5. Wait for Kademlia bootstrap to stabilize ───────────────────────────
    // Drain PeerAuthenticated events, upsert each peer to the DB so that
    // MailboxRouter.dr_walk_for_pointer has candidates to work with.
    // Returns how many peers authenticated within the timeout.
    let kad_peers = wait_for_kad_bootstrap_stable(
        &swarm_handle,
        &mut event_rx,
        &db,
        DR_KAD_STABILIZE_TIMEOUT_SECS,
        KAD_MIN_PEERS_FOR_DR,
    )
    .await;

    println!("Bootstrap stabilization: {kad_peers} peer(s) authenticated.");

    // ── 6. Discover + authenticate closest peers via Kademlia ─────────────────
    // The DR pointer is stored by nodes closest to hash(my_master_pub).
    // get_closest_peers drives a live DHT query toward that key and returns
    // the closest known peers with their addresses.  We dial them so they are
    // authenticated and in the DB before dr_walk_for_pointer runs.
    let target_key = KademliaRoutingView::target_key(&my_master_pub);
    match swarm_handle.get_closest_peers(target_key.to_vec()).await {
        Ok(closest) => {
            tracing::info!(
                count = closest.len(),
                "dr: get_closest_peers returned candidate peers"
            );
            dial_and_authenticate_candidates(&swarm_handle, &mut event_rx, &db, closest).await;
        }
        Err(e) => {
            tracing::warn!(
                "dr: get_closest_peers failed: {e}; proceeding with bootstrap-authenticated peers"
            );
        }
    }

    // No peer at all: the seed address is wrong or unreachable.
    if db
        .list_all_peers()
        .map_err(|e| dr_failed(format!("recovery database: {e}")))?
        .is_empty()
    {
        return Err(DrError::NoCandidates);
    }

    // ── 7. Walk mailbox candidate-set for the freshest SelfPointer ───────────
    let swarm_handle = Arc::new(swarm_handle);
    let router = Arc::new(MailboxRouter::new(Arc::clone(&swarm_handle), db.clone()));

    println!("Searching for SelfPointer via mailbox...");
    let pointer = match router
        .dr_walk_for_pointer(&my_master_pub)
        .await
        .map_err(|e| dr_failed(format!("pointer search: {e}")))?
    {
        Some(p) => p,
        None => {
            tracing::info!("dr: no SelfPointer of this identity in the candidate-set");
            return Err(DrError::NoCatalogFound { responders: None });
        }
    };

    println!(
        "Selected self-pointer: generation={}, base={}, diffs={}, created_at={}",
        pointer.generation,
        hex_encode(&pointer.base.block_id.0),
        pointer.diffs.len(),
        pointer.created_at.0
    );

    // ── 8. Dial the pointer's holders so we can fetch from them ──────────────
    // B-1: try HolderHint.addrs first (fast); if empty or all fail, use
    // get_closest_peers(holder_id) as the primary DR path.
    dial_pointer_holders(&swarm_handle, &mut event_rx, &db, &pointer).await;

    // ── 9. Fetch base + diff blocks, reassemble, restore DB ──────────────────
    let dr_key = crate::daemon::system_state::identity_key_bytes_from_seed(&keyfile.seed)
        .map_err(|e| dr_failed(format!("DR key: {e}")))?;
    let encoder: Arc<dyn viaticum_core::erasure::ErasureEncoder> =
        Arc::new(viaticum_core::erasure::RaptorQEncoder::new());

    let base_bytes = fetch_ss_block(&swarm_handle, &encoder, &pointer.base, &dr_key)
        .await
        .map_err(|e| dr_failed(format!("failed to fetch SS base block: {e}")))?;
    let base_state: viaticum_core::system_state::SystemState =
        viaticum_core::types::from_cbor_bytes(&base_bytes)
            .map_err(|e| dr_failed(format!("decode base SystemState: {e}")))?;

    let mut diffs: Vec<Vec<viaticum_core::system_state::DiffOp>> =
        Vec::with_capacity(pointer.diffs.len());
    for dref in &pointer.diffs {
        let bytes = fetch_ss_block(&swarm_handle, &encoder, dref, &dr_key)
            .await
            .map_err(|e| dr_failed(format!("failed to fetch SS diff block: {e}")))?;
        diffs.push(
            viaticum_core::types::from_cbor_bytes(&bytes)
                .map_err(|e| dr_failed(format!("decode diff block: {e}")))?,
        );
    }

    let state = viaticum_core::system_state::apply_diffs(base_state, &diffs);

    // Use restore_db_force: the DB is fresh but not fully empty — bootstrap
    // upserted peer records during wait_for_kad_bootstrap_stable. The force
    // variant skips the empty-DB guard and overlays the restored state on top.
    viaticum_core::system_state::restore_db_force(&db, &state)
        .map_err(|e| dr_failed(format!("restore_db: {e}")))?;

    // Everything holding the staging DB (router, db) and the swarm drops here.
    Ok(RecoveredSummary {
        files: state.files.len(),
        source_blocks: state.source_blocks.len(),
        placements: state.symbol_placements.len(),
        peers: state.peers.len(),
    })
}

// ─── Kademlia bootstrap stabilization ────────────────────────────────────────

/// Wait for Kademlia bootstrap to produce authenticated peers, upserting each
/// one into `db` so that `MailboxRouter::dr_walk_for_pointer` has a populated
/// candidate set when it queries `db.list_all_peers()`.
///
/// Returns as soon as `min_peers` have been authenticated OR the overall
/// `timeout_secs` deadline elapses (best-effort: returns whatever was reached).
/// Non-PeerAuthenticated events are ignored but not dropped — in DR mode there
/// is no other consumer of `event_rx` at this stage.
///
/// min_peers rationale: 5 is enough to seed the candidate set for dr_walk.
/// Too small (1) = single point of failure; too large = long waits on small nets.
pub async fn wait_for_kad_bootstrap_stable(
    swarm: &SwarmHandle,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    timeout_secs: u64,
    min_peers: usize,
) -> usize {
    use tokio::time::timeout;
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};

    let mut count = 0usize;

    let _ = timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated {
                    peer_id: _,
                    device_id,
                    identity_pub,
                    device_cert: _,
                    x25519_pub,
                    listen_addrs: _,
                }) => {
                    let now = Timestamp::now();
                    // Build a minimal PeerRecord matching the pattern in processor/peer.rs
                    // on_peer_authenticated (new peer branch).
                    let record = match db.get_peer(&device_id) {
                        Ok(Some(mut existing)) => {
                            existing.master_identity = identity_pub;
                            existing.last_seen = now;
                            if x25519_pub.is_some() {
                                existing.x25519_pub = x25519_pub;
                            }
                            existing.avail_ewma = viaticum_core::types::ewma_contact_observed(
                                existing.avail_ewma,
                                viaticum_core::constants::AVAIL_EWMA_ALPHA,
                            );
                            existing.last_avail_sample = now.0;
                            existing
                        }
                        _ => PeerRecord {
                            device_id,
                            master_identity: identity_pub,
                            trust_p: INITIAL_TRUST_P,
                            trust_i: 0.0,
                            trust_s: 1.0,
                            bytes_we_store_for_peer: 0,
                            bytes_peer_stores_for_us: 0,
                            first_seen: now,
                            last_seen: now,
                            revoked_device_pub_keys: vec![],
                            addrs: vec![],
                            x25519_pub,
                            avail_ewma: AVAIL_EWMA_INITIAL,
                            last_avail_sample: now.0,
                        },
                    };

                    if let Err(e) = db.upsert_peer(&record) {
                        tracing::warn!(device = %device_id, "dr: upsert_peer failed: {e}");
                    } else {
                        count += 1;
                        tracing::info!(
                            device = %device_id,
                            master = %identity_pub,
                            count,
                            "dr: bootstrap: peer authenticated and upserted"
                        );
                    }

                    if count >= min_peers {
                        tracing::info!(
                            count,
                            "dr: bootstrap: min_peers reached, stopping stabilization wait"
                        );
                        return;
                    }
                }
                Some(ProtocolEvent::PeerIdentified {
                    device_id,
                    listen_addrs,
                }) => {
                    // Persist addresses to the already-upserted record.
                    if let Ok(Some(mut record)) = db.get_peer(&device_id) {
                        record.addrs = listen_addrs.iter().map(|a| a.to_string()).collect();
                        let _ = db.upsert_peer(&record);
                    }
                }
                Some(_) => {}
                None => return, // channel closed
            }
        }
    })
    .await;

    // Suppress "unused variable" from swarm borrow (swarm may be used later).
    let _ = swarm;
    count
}

// ─── Candidate peer dial (post-Kademlia walk) ─────────────────────────────────

/// Dial and authenticate peers returned by `get_closest_peers`, upserting each
/// into the DB so `dr_walk_for_pointer` has them as candidates.
///
/// Best-effort: dial / auth failures are logged at DEBUG level and skipped.
async fn dial_and_authenticate_candidates(
    swarm: &SwarmHandle,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    closest: Vec<(libp2p::PeerId, Vec<libp2p::Multiaddr>)>,
) {
    use crate::daemon::network::swarm::device_id_to_peer_id;
    use std::collections::HashSet;

    // Build a set of already-authenticated PeerIds so we can skip re-dialing them.
    // Re-dialing an already-connected peer hits PeerCondition::Disconnected guard
    // in libp2p (silently dropped), and wait_for_auth_any then burns the full
    // CANDIDATE_DIAL_TIMEOUT_SECS before giving up — ~10s wasted per peer.
    let already_auth_peer_ids: HashSet<libp2p::PeerId> = swarm
        .peer_sets()
        .await
        .map(|(auth, _)| auth)
        .unwrap_or_default()
        .iter()
        .filter_map(|dev| device_id_to_peer_id(dev).ok())
        .collect();

    for (peer_id, addrs) in &closest {
        // Skip peers already authenticated during bootstrap — they are already
        // in the DB and we have live connections to them.
        if already_auth_peer_ids.contains(peer_id) {
            tracing::debug!(
                %peer_id,
                "dr: candidate peer already authenticated — skip re-dial"
            );
            continue;
        }

        if addrs.is_empty() {
            tracing::debug!(
                %peer_id,
                "dr: candidate peer has no addrs (identify not yet run) — skip for now"
            );
            continue;
        }

        let mut dialed_any = false;
        for addr in addrs {
            match swarm.dial(*peer_id, addr.clone()).await {
                Ok(_) => {
                    dialed_any = true;
                }
                Err(e) => {
                    tracing::debug!(%peer_id, %addr, "dr: candidate dial failed: {e}");
                }
            }
        }

        if !dialed_any {
            continue;
        }

        // Wait for PeerAuthenticated (short per-peer timeout).
        match tokio::time::timeout(
            Duration::from_secs(CANDIDATE_DIAL_TIMEOUT_SECS),
            wait_for_auth_any(event_rx, *peer_id, db),
        )
        .await
        {
            Ok(Some(device_id)) => {
                // already upserted inside wait_for_auth_any
                tracing::info!(
                    %peer_id,
                    %device_id,
                    "dr: candidate peer authenticated"
                );
            }
            Ok(None) => {
                tracing::debug!(%peer_id, "dr: candidate auth failed or connection closed");
            }
            Err(_) => {
                tracing::debug!(%peer_id, "dr: candidate auth timed out");
            }
        }
    }
}

/// Wait for a PeerAuthenticated event from the swarm for `expected_peer_id`.
/// Unlike `wait_for_auth`, this also upserts the peer into `db` upon success.
///
/// Returns the DeviceId if authentication succeeds; None on channel close or
/// connection closed for that peer. Intended to be wrapped in a per-peer timeout
/// by the caller.
async fn wait_for_auth_any(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    expected_peer_id: libp2p::PeerId,
    db: &viaticum_core::db::Db,
) -> Option<viaticum_core::types::DeviceId> {
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
    loop {
        match event_rx.recv().await {
            Some(ProtocolEvent::PeerAuthenticated {
                peer_id,
                device_id,
                identity_pub,
                device_cert: _,
                x25519_pub,
                listen_addrs: _,
            }) => {
                // Upsert regardless of whether this is the expected peer.
                let now = Timestamp::now();
                let record = match db.get_peer(&device_id) {
                    Ok(Some(mut existing)) => {
                        existing.master_identity = identity_pub;
                        existing.last_seen = now;
                        if x25519_pub.is_some() {
                            existing.x25519_pub = x25519_pub;
                        }
                        existing.avail_ewma = viaticum_core::types::ewma_contact_observed(
                            existing.avail_ewma,
                            viaticum_core::constants::AVAIL_EWMA_ALPHA,
                        );
                        existing.last_avail_sample = now.0;
                        existing
                    }
                    _ => PeerRecord {
                        device_id,
                        master_identity: identity_pub,
                        trust_p: INITIAL_TRUST_P,
                        trust_i: 0.0,
                        trust_s: 1.0,
                        bytes_we_store_for_peer: 0,
                        bytes_peer_stores_for_us: 0,
                        first_seen: now,
                        last_seen: now,
                        revoked_device_pub_keys: vec![],
                        addrs: vec![],
                        x25519_pub,
                        avail_ewma: AVAIL_EWMA_INITIAL,
                        last_avail_sample: now.0,
                    },
                };
                let _ = db.upsert_peer(&record);

                if peer_id == expected_peer_id {
                    return Some(device_id);
                }
                // Different peer — keep waiting for the expected one.
            }
            Some(ProtocolEvent::ConnectionClosed {
                peer_id,
                device_id: _,
            }) => {
                if peer_id == expected_peer_id {
                    return None;
                }
            }
            Some(_) => {}
            None => return None,
        }
    }
}

// ─── Pointer holder dialing (B-1) ─────────────────────────────────────────────

/// From the collected `(timestamp, blob)` pairs, deserialize each blob as a
/// `SelfPointer`, keep only those whose signature verifies against the expected
/// master identity, and return the freshest valid one.
///
/// Freshness = `created_at` primary, `generation` tiebreak.
/// Retained for backwards-compatible unit tests.
#[cfg(test)]
fn select_freshest_valid_pointer(
    blobs: &[(u64, Vec<u8>)],
    expected_master: &IdentityPub,
) -> Option<viaticum_core::system_state::SelfPointer> {
    let mut pointers: Vec<viaticum_core::system_state::SelfPointer> = blobs
        .iter()
        .filter_map(|(_, blob)| {
            viaticum_core::types::from_cbor_bytes::<viaticum_core::system_state::SelfPointer>(blob)
                .ok()
        })
        .filter(|p| viaticum_core::system_state::verify_self_pointer(p, expected_master).is_ok())
        .collect();
    pointers.sort_by_key(|p| std::cmp::Reverse((p.created_at.0, p.generation)));
    pointers.into_iter().next()
}

/// Dial the holders named in the selected pointer so we can fetch their symbols.
///
/// B-1 strategy (spec §2.10 item 5):
///   1. If `hint.addrs` is non-empty: try those addresses first (fast, if still valid).
///   2. If addrs are empty OR all dials fail: fall back to
///      `swarm.get_closest_peers(holder_id_bytes)` — the Kademlia-backed path.
///      Empty addrs are normal (addr propagation is best-effort); log at INFO not WARN.
///   3. For each discovered address from Kademlia, dial and wait for auth.
///
/// Best-effort throughout: a holder that cannot be reached means fewer symbols
/// for that block (the erasure code tolerates this up to k_eff).
async fn dial_pointer_holders(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    pointer: &viaticum_core::system_state::SelfPointer,
) {
    let already_auth = swarm
        .peer_sets()
        .await
        .map(|(auth, _)| auth)
        .unwrap_or_default();

    // Collect unique holders across base + diffs not already authenticated.
    let mut seen: HashSet<viaticum_core::types::DeviceId> = HashSet::new();
    let mut targets: Vec<(viaticum_core::types::DeviceId, Vec<String>)> = Vec::new();
    for bref in std::iter::once(&pointer.base).chain(pointer.diffs.iter()) {
        for h in &bref.holders {
            if already_auth.contains(&h.holder_id) || !seen.insert(h.holder_id) {
                continue;
            }
            targets.push((h.holder_id, h.addrs.clone()));
        }
    }

    for (device, addrs) in targets {
        let authenticated = try_dial_holder_by_hints(swarm, event_rx, db, device, &addrs).await;

        if !authenticated {
            // B-1 Kademlia fallback: derive PeerId from DeviceId and look up
            // current addresses from the DHT.
            tracing::info!(
                %device,
                "dr: holder addrs empty or all failed — trying Kademlia get_closest_peers fallback"
            );
            try_dial_holder_via_kademlia(swarm, event_rx, db, device).await;
        }
    }
}

/// Try to dial a holder using the `HolderHint.addrs` list.
/// Returns `true` if the peer was successfully authenticated.
async fn try_dial_holder_by_hints(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    device: viaticum_core::types::DeviceId,
    addrs: &[String],
) -> bool {
    if addrs.is_empty() {
        // Empty addrs is normal — do not warn.
        tracing::info!(
            %device,
            "dr: holder has no addr hints (normal — will use Kademlia fallback)"
        );
        return false;
    }

    let mut peer_id_opt = None;
    for addr_str in addrs {
        match parse_multiaddr_with_peer_id(addr_str) {
            Ok((pid, multiaddr)) => {
                peer_id_opt = Some(pid);
                let _ = swarm.dial(pid, multiaddr).await;
            }
            Err(e) => tracing::debug!(%device, "dr: skip holder addr: {e}"),
        }
    }

    if let Some(pid) = peer_id_opt {
        match wait_for_auth(event_rx, db, pid).await {
            Some((did, identity_pub)) => {
                tracing::info!(%did, "dr: authenticated pointer holder (via hints)");
                // Upsert into DB so MailboxRouter can find this holder.
                // CS-DR-12: use the real identity from the auth event, not zeros.
                upsert_peer_minimal(db, did, identity_pub);
                return true;
            }
            None => {
                tracing::info!(%device, "dr: could not reach pointer holder via hints");
            }
        }
    }
    false
}

/// Try to dial a holder by looking up their current addresses via Kademlia.
///
/// Uses `get_closest_peers(holder_id_bytes)` — this drives a live DHT query
/// toward the holder's peer_id key, which is effective at finding nodes whose
/// listen addresses have changed since the SelfPointer was created.
async fn try_dial_holder_via_kademlia(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    device: viaticum_core::types::DeviceId,
) {
    // Derive PeerId from DeviceId (Ed25519 pubkey → libp2p PeerId).
    let peer_id = match crate::daemon::network::swarm::device_id_to_peer_id(&device) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%device, "dr: cannot derive PeerId for Kademlia holder lookup: {e}");
            return;
        }
    };

    // Use the raw peer_id bytes as the Kademlia lookup key — this finds the
    // node whose routing-table key is closest to the holder's own peer_id.
    let key = peer_id.to_bytes();
    match swarm.get_closest_peers(key).await {
        Ok(closest) => {
            // Look for the exact holder peer_id among the results.
            let holder_addrs: Vec<libp2p::Multiaddr> = closest
                .iter()
                .filter(|(pid, _)| *pid == peer_id)
                .flat_map(|(_, addrs)| addrs.iter().cloned())
                .collect();

            if holder_addrs.is_empty() {
                tracing::debug!(
                    %device,
                    %peer_id,
                    "dr: Kademlia did not return holder's own peer_id in closest set"
                );
                // Still try dialing any returned peers — one may route to holder.
                for (cpid, caddrs) in &closest {
                    for addr in caddrs {
                        let _ = swarm.dial(*cpid, addr.clone()).await;
                    }
                }
            } else {
                for addr in &holder_addrs {
                    let _ = swarm.dial(peer_id, addr.clone()).await;
                }

                match wait_for_auth(event_rx, db, peer_id).await {
                    Some((did, identity_pub)) => {
                        tracing::info!(%did, "dr: authenticated pointer holder (via Kademlia)");
                        // CS-DR-12: use the real identity from the auth event.
                        upsert_peer_minimal(db, did, identity_pub);
                    }
                    None => {
                        tracing::info!(%device, "dr: could not reach holder via Kademlia");
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(%device, "dr: Kademlia holder lookup failed: {e}");
        }
    }
}

/// Upsert a minimal PeerRecord into `db` for a freshly authenticated holder.
///
/// Called when dial_pointer_holders authenticates a holder that may not yet
/// have a DB record — ensures fetch_ss_block can use the authenticated connection.
fn upsert_peer_minimal(
    db: &viaticum_core::db::Db,
    device_id: viaticum_core::types::DeviceId,
    identity_pub: IdentityPub,
) {
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
    let now = Timestamp::now();
    let record = match db.get_peer(&device_id) {
        Ok(Some(mut r)) => {
            // Already exists — leave it, except: CS-DR-12, if this record was
            // created earlier with a zero (placeholder) identity and we now have
            // the real one from the auth event, fill it in so no zero-identity
            // zombie survives DR. Never clobber an already-real identity.
            if r.master_identity.0 == [0u8; 32] && identity_pub.0 != [0u8; 32] {
                r.master_identity = identity_pub;
            }
            r
        }
        _ => PeerRecord {
            device_id,
            master_identity: identity_pub,
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
            avail_ewma: AVAIL_EWMA_INITIAL,
            last_avail_sample: now.0,
        },
    };
    // Persist: a freshly-built minimal record, or an existing one (unchanged,
    // except a zero-identity placeholder repaired above per CS-DR-12). Trust /
    // counters / addrs of an existing record are never overwritten.
    if let Err(e) = db.upsert_peer(&record) {
        tracing::warn!(%device_id, "dr: upsert_peer_minimal failed: {e}");
    }
}

/// Fetch one SystemState block (base or diff) from its holder hints and return the
/// decrypted plaintext.
async fn fetch_ss_block(
    swarm: &Arc<SwarmHandle>,
    encoder: &Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    bref: &viaticum_core::system_state::BlockRef,
    dr_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    use viaticum_core::types::{ErasureParams, FileId, PlacementStatus, SymbolPlacement};

    let importance = crate::daemon::system_state::block::SYSTEM_STATE_IMPORTANCE;
    let params = ErasureParams::compute(bref.encrypted_size, importance)
        .map_err(|e| anyhow::anyhow!("erasure params for SS block: {e}"))?;

    let placements: Vec<SymbolPlacement> = bref
        .holders
        .iter()
        .map(|h| SymbolPlacement {
            source_block_id: bref.block_id,
            holder_id: h.holder_id,
            file_id: FileId(0),
            esi_ranges: h.esi_ranges.clone(),
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp::now(),
            consecutive_misses: 0,
        })
        .collect();

    let symbols = crate::daemon::symbol_fetch::fetch_unbound_symbols(
        swarm,
        encoder,
        &bref.block_id,
        &placements,
        &params,
    )
    .await
    .map_err(|e| anyhow::anyhow!("fetch_unbound_symbols: {e}"))?;

    let padded = encoder
        .decode(&symbols, &params)
        .map_err(|e| anyhow::anyhow!("decode SS block: {e}"))?;
    let size = bref.encrypted_size as usize;
    if padded.len() < size {
        anyhow::bail!(
            "decoded SS block ({} bytes) smaller than encrypted_size ({size})",
            padded.len()
        );
    }
    let stored = &padded[..size];
    crate::daemon::backup::pipeline::decrypt_and_decompress(stored, dr_key)
        .map_err(|e| anyhow::anyhow!("decrypt SS block: {e}"))
}

// ─── Utility ─────────────────────────────────────────────────────────────────

/// Parse a Multiaddr string that may contain a /p2p/<PeerId> component.
///
/// Returns (PeerId, Multiaddr-without-p2p) if the p2p component is present, or an error.
fn parse_multiaddr_with_peer_id(
    addr_str: &str,
) -> anyhow::Result<(libp2p::PeerId, libp2p::Multiaddr)> {
    use libp2p::multiaddr::Protocol;
    use std::str::FromStr;

    let ma = libp2p::Multiaddr::from_str(addr_str)
        .map_err(|e| anyhow::anyhow!("invalid multiaddr '{addr_str}': {e}"))?;

    for proto in ma.iter() {
        if let Protocol::P2p(peer_id) = proto {
            let transport_addr: libp2p::Multiaddr = ma
                .iter()
                .filter(|p| !matches!(p, Protocol::P2p(_)))
                .collect();
            return Ok((peer_id, transport_addr));
        }
    }

    anyhow::bail!("multiaddr '{addr_str}' has no /p2p/<PeerId> component")
}

/// Wait for a PeerAuthenticated event from the given peer_id.
///
/// Returns `(DeviceId, IdentityPub)` of the expected peer if authentication
/// succeeds within AUTH_TIMEOUT_SECS. Returns None on timeout, channel close,
/// or ConnectionClosed for the expected peer.
///
/// CS-DR-12: surfaces the authenticated peer's real `identity_pub` so the caller
/// upserts a correct master_identity instead of all-zeros.
///
/// CS-DR-13: like `wait_for_auth_any`, this also upserts OTHER peers that
/// authenticate while we wait, so a peer that authenticated during the window is
/// not lost to a later 15 s timeout + Kademlia fallback.
async fn wait_for_auth(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    db: &viaticum_core::db::Db,
    expected_peer_id: libp2p::PeerId,
) -> Option<(viaticum_core::types::DeviceId, IdentityPub)> {
    let deadline = Duration::from_secs(AUTH_TIMEOUT_SECS);

    tokio::time::timeout(deadline, async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated {
                    peer_id,
                    device_id,
                    identity_pub,
                    ..
                }) => {
                    if peer_id == expected_peer_id {
                        return Some((device_id, identity_pub));
                    }
                    // CS-DR-13: a different peer authenticated while we waited —
                    // persist it so it isn't lost when we move on to the next holder.
                    upsert_peer_minimal(db, device_id, identity_pub);
                }
                Some(ProtocolEvent::ConnectionClosed { peer_id, .. }) => {
                    if peer_id == expected_peer_id {
                        return None;
                    }
                }
                Some(ProtocolEvent::InboundRequest { .. }) => {}
                Some(ProtocolEvent::PeerIdentified { .. }) => {}
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}
