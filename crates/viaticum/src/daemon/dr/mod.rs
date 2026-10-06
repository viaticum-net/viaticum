// Disaster recovery: restore node state from the recovery phrase via the mailbox bus.
//
// Runs standalone (no daemon, no Processor). Connects to seed peers via a libp2p
// SwarmHandle, collects every SelfPointer of the identity from the mailbox candidate
// set, chooses the catalog, then fetches and restores the DB from its base + diff
// blocks.
//
// DR is transactional (spec B2 §1.5.1): every refusal happens before the data dir
// changes, all work goes into drafts (`db.redb.dr-new`, `identity.key.dr-new`), and
// the drafts are installed by a series of renames only after the network phase
// succeeded. A failed or interrupted DR leaves the folder as it was.
//
//   0. SIGINT / SIGTERM handlers (dr-i23) — from here on a stop signal only queues
//   1. preflight (dr/preflight): phrase → keyfile in memory; lock probe on db.redb
//      (live daemon → stop); identity.key must carry the phrase's seed (same →
//      reuse it, device id kept; other → stop); claim the staging DB
//   ── network phase: steps 2-8 race the stop signals; a signal → abort ──────────
//   2. KeySource::New: write the key draft
//   3. Db::create_from_file on the claimed staging file
//   4. SwarmHandle with the seed peers as Kademlia bootstrap peers
//   5. wait_for_kad_bootstrap_stable: authenticated peers upserted to the staging DB
//   6. RendezvousKeys from the seed (CROWN-1 C3a: one permanent box, no clock);
//      get_closest_peers(dr_lookup_key(rendezvous address)) — the PREIMAGE (F12) → dial
//   7. MailboxRouter::dr_collect_pointers: every valid pointer of every place from every
//      batch (CS-DR-1), opened with the seed-derived seal key; select_catalog: one
//      history → it, several → the user chooses with --catalog (spec B2 slice B2.2a);
//      attempts: the freshest pointer of each of the history's two places first, then
//      the rest (V.17.3)
//   8. dial the pointer's holders (one dial each, all at once), fetch base + diffs,
//      apply_diffs; the lost device becomes this DR's device in every file record
//      (dr-i19); restore into the staging DB and merge the peers learned live back
//      over the snapshot, `--peer` first (dr-i18); the DB gets a NEW catalog history
//   ── end of network phase ──────────────────────────────────────────────────────
//   9. commit (dr/commit, synchronous): old db.redb → .dr-bak[.N], staging → db.redb,
//      key last. A signal during the commit is only queued: the commit completes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use viaticum_core::constants::DR_KAD_STABILIZE_TIMEOUT_SECS;
use viaticum_core::mailbox::MailboxAddress;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys};
use viaticum_core::system_state::catalog::{
    CatalogSelectError, check_catalog_prefix, select_catalog,
};
use viaticum_core::system_state::{
    CatalogLineageId, DiffOp, SelfPointer, SystemState, apply_diffs,
};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, hex_encode};

use crate::daemon::handle::shutdown::ShutdownSignals;
use crate::daemon::identity::{IdentityKeyFile, MnemonicProblem, derive_keys};
use crate::daemon::mailbox::routing::MailboxRouter;
use crate::daemon::network::swarm::{SwarmConfig, SwarmHandle};

mod commit;
mod memory;
mod net;
mod preflight;
mod restored;

pub(crate) use net::addr_rank;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_memory;

// ─── Options and errors ──────────────────────────────────────────────────────

/// What `viaticum dr` was asked to do.
pub struct DrOptions {
    pub mnemonic: String,
    /// `--peer` multiaddrs (with `/p2p/<peer id>`).
    pub peers: Vec<String>,
    pub data_dir: PathBuf,
    /// `--catalog <hex prefix>`: the catalog history to restore when several exist.
    pub catalog: Option<String>,
}

/// Why DR stopped. Every variant except `Commit` leaves the data dir as it was; the
/// texts are what the friend reads.
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
    /// `responders` goes to the log.
    #[error(
        "no catalog found for this recovery phrase. A node publishes its first \
         recovery pointer about 12 hours after install; if it is older, try other \
         --peer addresses. Nothing was changed."
    )]
    NoCatalogFound { responders: Option<usize> },
    /// Several catalogs, or a bad / unknown `--catalog`. `run_dr` printed the table.
    #[error("{0}. Nothing was changed.")]
    Catalog(#[from] CatalogSelectError),
    /// Network / fetch / decode / restore failure before the commit. `hint` names
    /// another listed catalog to try (N-6), else empty.
    #[error("DR failed: {reason}. Nothing was changed.{hint}")]
    Failed { reason: String, hint: String },
    #[error("DR could not finish installing the recovered state: {0}")]
    Commit(String),
    /// dr-i23: SIGINT / SIGTERM during the network phase.
    #[error("DR interrupted. Nothing was changed.")]
    Interrupted,
    /// К-b3 (spec v3.9a): a node of this machine holds the block work lock and does not know the
    /// lease request.
    #[error(
        "dr: the node on this machine is older and cannot share memory; update or stop it. \
         Nothing was changed."
    )]
    NodeCannotShareMemory,
    /// Spec v3.9b p.5: the node answered 401/403 — DR runs as another user than the node.
    #[error(
        "dr: the node refused the request (status {status}); run dr as the same user as the \
         node. Nothing was changed."
    )]
    NodeRefusedLease { status: u16 },
    /// Spec v3.9b p.5: a status that is neither the lease stream, nor an old node's, nor a 5xx.
    #[error(
        "dr: the node on this machine answered the memory lease with status {status}. Nothing \
         was changed."
    )]
    NodeUnexpectedStatus { status: u16 },
    /// Spec v3.9b p.7: the node on this machine has no web API (a setting, nothing to wait for).
    #[error(
        "dr: the node on this machine has its web API off; enable it (or stop the node) and run \
         dr again. Nothing was changed."
    )]
    NodeWebApiOff,
}

fn dr_failed(reason: impl std::fmt::Display) -> DrError {
    DrError::Failed {
        reason: reason.to_string(),
        hint: String::new(),
    }
}

/// Kademlia lookup key for the postmen of a mailbox address: the PREIMAGE `address.0`
/// (F12, AC-18). libp2p-kad hashes the key it is given; postmen are ranked by
/// `SHA256(address.0)` (`KademliaRoutingView::target_key`), so passing that hash would
/// walk towards `SHA256(SHA256(address.0))`.
pub(crate) fn dr_lookup_key(target: &MailboxAddress) -> Vec<u8> {
    target.0.to_vec()
}

/// What the network phase recovered, for the final report.
#[derive(Debug)]
struct RecoveredSummary {
    live_files: u32,
    deleted_files: usize,
    source_blocks: usize,
    placements: usize,
    peers: usize,
    /// The NEW history of the recovered DB.
    lineage: CatalogLineageId,
    /// The history it was restored from.
    source_lineage: CatalogLineageId,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Run disaster recovery: restore node state from the recovery phrase into
/// `opts.data_dir`. Transactional: on `Err` the folder is as it was (see the module
/// header), except `DrError::Commit`, whose text says what lies where.
pub async fn run_dr(opts: DrOptions) -> Result<(), DrError> {
    let started = Instant::now();
    println!("Starting disaster recovery...");
    println!("Data directory: {}", opts.data_dir.display());

    // N4: a malformed --catalog is refused before anything else (no network time).
    if let Some(c) = &opts.catalog {
        check_catalog_prefix(c)?;
    }

    // ── 0. Stop signals: registered before anything is written, so a Ctrl-C at
    //       any later point is ours (queued), never the default "terminate". ──────
    let mut signals = ShutdownSignals::install()
        .map_err(|e| dr_failed(format!("cannot install the stop-signal handlers: {e}")))?;

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

    // ── Block work memory (К-b3): the machine's lock decides whose budget DR works on ────
    let memory = memory::Memory::open().inspect_err(|_| commit::abort(&mut plan))?;

    // ── 2-8. Network phase, interruptible ─────────────────────────────────────
    let work = recover_into_staging(
        plan.staging.file.take(),
        plan.keyfile.clone(),
        opts.peers.clone(),
        opts.catalog.clone(),
        memory,
    );
    let summary = guarded_network_phase(&mut plan, work, signals.recv()).await?;

    // ── 9. Commit: synchronous; a signal now only queues ──────────────────────
    let outcome = commit::commit(plan)?;

    println!("DR restore successful:");
    println!("  Files:         {}", summary.live_files);
    if summary.deleted_files > 0 {
        println!(
            "  Deleted files: {} (awaiting cleanup)",
            summary.deleted_files
        );
    }
    println!("  Source blocks: {}", summary.source_blocks);
    println!("  Placements:    {}", summary.placements);
    println!("  Peers:         {}", summary.peers);
    println!(
        "  Catalog:       {} (a new history, restored from {})",
        summary.lineage, summary.source_lineage
    );
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
    println!("'viaticum status' shows how many files are still missing locally.");
    println!(
        "If the machine you restored from is still running, do not keep this node running \
         as well: for a second device use 'viaticum init --mnemonic ... --new-device' instead."
    );
    println!("DR took {} s.", started.elapsed().as_secs());
    Ok(())
}

/// Steps 2-8 under the stop-signal guard (dr-i23): write the key draft, then run
/// `work` until it finishes or `interrupt` resolves. Any error, including an
/// interruption, aborts: only this run's drafts are removed. `work` must not borrow
/// the plan (it is dropped — closing the staging DB — before the abort).
async fn guarded_network_phase<T>(
    plan: &mut preflight::DrPlan,
    work: impl std::future::Future<Output = Result<T, DrError>>,
    interrupt: impl std::future::Future<Output = &'static str>,
) -> Result<T, DrError> {
    let result = match plan.stage_key() {
        Err(e) => Err(e),
        Ok(()) => tokio::select! {
            r = work => r,
            sig = interrupt => {
                tracing::info!(signal = sig, "dr: stop signal in the network phase, aborting");
                Err(DrError::Interrupted)
            }
        },
    };
    if result.is_err() {
        commit::abort(plan);
    }
    result
}

/// Steps 3-8: build the recovered state in the staging DB. The DB, the swarm and the
/// router live only inside this call, so on return (Ok or Err) — or when the future is
/// dropped by an interruption — redb's handle on the staging file is closed.
async fn recover_into_staging(
    staging_file: Option<std::fs::File>,
    keyfile: IdentityKeyFile,
    peer_addrs: Vec<String>,
    requested_catalog: Option<String>,
    mut memory: memory::Memory,
) -> Result<RecoveredSummary, DrError> {
    // ── 3. Fresh DB in the staging file ───────────────────────────────────────
    let staging_file =
        staging_file.ok_or_else(|| dr_failed("the staging database was not claimed"))?;
    // On Windows a second exclusive lock through the same handle fails (redb would
    // report DatabaseAlreadyOpen): hand redb an unlocked handle there (A15).
    #[cfg(windows)]
    let _ = staging_file.unlock();
    let db = viaticum_core::db::Db::create_from_file(staging_file)
        .map_err(|e| dr_failed(format!("cannot create the recovery database: {e}")))?;

    let (master_key, device_key, _epoch_key_bytes) = derive_keys(&keyfile, 0).map_err(dr_failed)?;
    let my_master_pub = IdentityPub(keyfile.identity_pub);
    let device_id = DeviceId(keyfile.device_id);

    // ── 4. SwarmHandle with the seed peers as Kademlia bootstrap peers ────────
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&master_key, device_id, Timestamp::now());
    let seed_multiaddrs: Vec<libp2p::Multiaddr> = peer_addrs
        .iter()
        .filter_map(|s| match s.parse::<libp2p::Multiaddr>() {
            Ok(ma) => Some(ma),
            Err(e) => {
                tracing::warn!("dr: skip invalid multiaddr '{s}': {e}");
                None
            }
        })
        .collect();
    let swarm_cfg = SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub: my_master_pub,
        cluster_master_pub: my_master_pub,
        device_cert,
        // F11: the DR node announces the same x25519 key as the daemon of this phrase.
        x25519_pub: Some(
            x25519_dalek::PublicKey::from(&viaticum_core::cluster::derive_x25519_secret(
                &keyfile.seed,
            ))
            .to_bytes(),
        ),
        listen_port: 0,
        cert_timeout_secs: net::AUTH_TIMEOUT_SECS,
        kademlia_bootstrap_peers: seed_multiaddrs.clone(),
        kad_discovery_interval_override: None,
        enable_relay_server: false,
        conn_policy: crate::daemon::network::swarm::ConnPolicy::off(),
    };
    let (swarm_handle, mut event_rx) = SwarmHandle::start(swarm_cfg)
        .await
        .map_err(|e| dr_failed(format!("cannot start networking: {e}")))?;
    println!("Network ready. Waiting for Kademlia bootstrap...");

    // ── 5. Kademlia bootstrap ─────────────────────────────────────────────────
    let kad_peers = net::wait_for_kad_bootstrap_stable(
        &mut event_rx,
        &db,
        DR_KAD_STABILIZE_TIMEOUT_SECS,
        net::KAD_MIN_PEERS_FOR_DR,
    )
    .await;
    println!("Bootstrap stabilization: {kad_peers} peer(s) authenticated.");

    // ── 6. The pointer box's postmen via Kademlia (F12: pass the preimage) ────
    // CROWN-1 C3a: the box and every key come from the phrase only (no clock).
    let rv = RendezvousKeys::derive(&keyfile.seed);
    tracing::info!(address = %rv.address, "dr: rendezvous box");
    let closest = match swarm_handle
        .get_closest_peers(dr_lookup_key(&rv.address))
        .await
    {
        Ok(closest) => {
            tracing::info!(
                count = closest.len(),
                "dr: get_closest_peers returned candidate peers"
            );
            closest
        }
        Err(e) => {
            tracing::warn!(
                "dr: get_closest_peers failed: {e}; proceeding with the authenticated peers"
            );
            Vec::new()
        }
    };
    // Also on a failed lookup: it upserts the peers that authenticated after the
    // stabilization wait stopped, so the walk asks every postman DR reached (dr-i1).
    net::dial_and_authenticate_candidates(&swarm_handle, &mut event_rx, &db, closest).await;
    if db
        .list_all_peers()
        .map_err(|e| dr_failed(format!("recovery database: {e}")))?
        .is_empty()
    {
        return Err(DrError::NoCandidates);
    }

    // ── 7. Every pointer of the identity, then the choice ─────────────────────
    let swarm_handle = Arc::new(swarm_handle);
    let router = Arc::new(MailboxRouter::new(Arc::clone(&swarm_handle), db.clone()));
    println!("Searching for SelfPointer via mailbox...");
    let walk = router
        .dr_collect_pointers(&rv, &my_master_pub, &device_id)
        .await
        .map_err(|e| dr_failed(format!("pointer search: {e}")))?;
    println!(
        "Mailbox search: asked {} postmen, {} answered, {} pointer(s) of this identity.",
        walk.candidates,
        walk.responders,
        walk.pointers.len()
    );
    if walk.candidates == 0 {
        return Err(DrError::NoCandidates);
    }
    if walk.pointers.is_empty() {
        tracing::info!(
            candidates = walk.candidates,
            responders = walk.responders,
            "dr: no SelfPointer of this identity in the candidate set"
        );
        return Err(DrError::NoCatalogFound {
            responders: Some(walk.responders),
        });
    }
    let slot_of: HashMap<[u8; 64], [u8; 16]> = walk
        .pointers
        .iter()
        .map(|(msg_id, p)| (p.signature, *msg_id))
        .collect();
    let pointers: Vec<SelfPointer> = walk.pointers.into_iter().map(|(_, p)| p).collect();
    let choice = match select_catalog(pointers, requested_catalog.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            if !e.rows().is_empty() {
                print!("{}", restored::render_catalog_rows(e.rows(), None));
            }
            return Err(DrError::Catalog(e));
        }
    };
    print!(
        "{}",
        restored::render_catalog_rows(
            &choice.rows,
            Some((choice.selected.catalog.lineage, choice.reason))
        )
    );
    if choice.rows.len() > 1 {
        println!(
            "To restore a different catalog: viaticum dr --mnemonic \"...\" --peer <addr> \
             --catalog <first 8 hex>"
        );
    }
    let rows = choice.rows;
    let source_lineage = choice.selected.catalog.lineage;
    // dr-i35 / V.17.3: the freshest pointer of each place of the history first, then
    // older pointers of the SAME history.
    let place_slots = [
        rv.pointer_slot(&source_lineage.0, PointerPlace::A),
        rv.pointer_slot(&source_lineage.0, PointerPlace::B),
    ];
    let attempts = order_attempts(choice.selected, choice.fallbacks, &slot_of, place_slots);
    log_attempt_plan(&attempts, &slot_of, place_slots);

    // ── 8. Holders, blocks, state ─────────────────────────────────────────────
    let dr_key = crate::daemon::system_state::identity_key_bytes_from_seed(&keyfile.seed)
        .map_err(|e| dr_failed(format!("DR key: {e}")))?;
    let encoder: Arc<dyn viaticum_core::erasure::ErasureEncoder> =
        Arc::new(viaticum_core::erasure::RaptorQEncoder::new());
    // restore-i44: a holder that failed a request in this DR run is asked last for the
    // rest of the run, whichever pointer and block.
    let failed_in_dr = crate::daemon::symbol_fetch::FailedInTask::default();
    let fetched = first_fetchable(&attempts, async |p: &SelfPointer| {
        println!(
            "Selected self-pointer: generation={}, base={}, diffs={}, created_at={}",
            p.generation,
            hex_encode(&p.base.block_id.0),
            p.diffs.len(),
            p.created_at.0
        );
        if memory.is_fatal() {
            return Err("DR stops: the node on this machine cannot share memory".to_string());
        }
        fetch_state(
            &swarm_handle,
            &mut event_rx,
            &db,
            &encoder,
            &dr_key,
            &mut memory,
            p,
            &failed_in_dr,
        )
        .await
    })
    .await;
    let (used, state) = match fetched {
        Ok(ok) => ok,
        Err(errors) => {
            // An old node on this machine ends DR whatever pointer is tried (v3.9a #5).
            if let Some(fatal) = memory.take_fatal() {
                return Err(fatal);
            }
            let last = errors.last().cloned().unwrap_or_default();
            return Err(DrError::Failed {
                reason: format!(
                    "none of the {} pointer(s) tried of this catalog could be fetched (last: {last})",
                    errors.len()
                ),
                hint: restored::fetch_failure_hint(&rows, source_lineage),
            });
        }
    };
    let pointer = &attempts[used];
    if used > 0 {
        println!(
            "The newest pointer of this catalog could not be fetched; restored from an older \
             one (created_at={}): files added after it are not in this catalog.",
            pointer.created_at.0
        );
    }

    // dr-i19: the files now belong to this DR's device.
    let prepared = restored::prepare_restored_state(state, &pointer.catalog, device_id);
    tracing::info!(
        lost_device = %pointer.catalog.publisher,
        dr_device = %device_id,
        records = prepared.reassigned,
        "dr: file records moved from the lost device to this device"
    );
    if prepared.live_files != pointer.catalog.files {
        tracing::warn!(
            restored = prepared.live_files,
            pointer = pointer.catalog.files,
            "dr: restored live file count differs from the pointer's catalog summary"
        );
    }

    // dr-i18: the peers learned live win over the snapshot's addresses, --peer first.
    let mut live = db
        .list_all_peers()
        .map_err(|e| dr_failed(format!("recovery database: {e}")))?;
    restored::prepend_seed_addrs(&mut live, &seed_multiaddrs);
    restored::install_restored_state(&db, &prepared.state, &live)
        .map_err(|e| dr_failed(format!("restore_db: {e}")))?;

    // A new history for the recovered DB: never the source's id (dr-i15).
    let lineage = db
        .get_or_create_catalog_lineage()
        .map_err(|e| dr_failed(format!("recovery database: {e}")))?;
    let peers = db
        .list_all_peers()
        .map_err(|e| dr_failed(format!("recovery database: {e}")))?
        .len();

    let state = &prepared.state;
    Ok(RecoveredSummary {
        live_files: prepared.live_files,
        deleted_files: state.files.len() - prepared.live_files as usize,
        source_blocks: state.source_blocks.len(),
        placements: state.symbol_placements.len(),
        peers,
        lineage,
        source_lineage,
    })
    // Everything holding the staging DB (router, db) and the swarm drops here.
}

/// The place (`A`, `B`, or `-` for an unknown `msg_id`) whose slot `p` was opened from.
pub(crate) fn attempt_place(
    p: &SelfPointer,
    slot_of: &HashMap<[u8; 64], [u8; 16]>,
    place_slots: [[u8; 16]; 2],
) -> &'static str {
    match slot_of.get(&p.signature) {
        Some(s) if *s == place_slots[0] => "A",
        Some(s) if *s == place_slots[1] => "B",
        _ => "-",
    }
}

/// One line per planned attempt, in order (dr-i48 observable in E2E):
/// `dr: attempt i/N place=A|B|- created_at=… base=…`.
fn log_attempt_plan(
    attempts: &[SelfPointer],
    slot_of: &HashMap<[u8; 64], [u8; 16]>,
    place_slots: [[u8; 16]; 2],
) {
    let n = attempts.len();
    for (i, p) in attempts.iter().enumerate() {
        tracing::info!(
            "dr: attempt {}/{} place={} created_at={} base={}",
            i + 1,
            n,
            attempt_place(p, slot_of, place_slots),
            p.created_at.0,
            hex_encode(&p.base.block_id.0[..8])
        );
    }
}

/// dr-i35: at most this many pointers of the chosen history are tried (each costs a
/// holder dial and a fetch).
const MAX_POINTER_ATTEMPTS: usize = 4;

/// The order in which DR tries the pointers of the chosen history (V.17.3, dr-i48):
/// the head (freshest pointer) of place A and of place B first, fresher head first;
/// then every other pointer, freshest first; at most `MAX_POINTER_ATTEMPTS`.
///
/// `selected` + `fallbacks` come from `select_catalog` (freshest first). `slot_of` maps
/// a pointer signature to the `msg_id` of the entry it was opened from; `place_slots` are
/// the history's two slots. Older versions of one place held by lagging postmen (other
/// bases included) can never push the other place's head out of the attempts: the head
/// of every place is at most the second attempt. A pointer under an unknown `msg_id`
/// (a postman moved it) is not a head of any place.
pub(crate) fn order_attempts(
    selected: SelfPointer,
    fallbacks: Vec<SelfPointer>,
    slot_of: &HashMap<[u8; 64], [u8; 16]>,
    place_slots: [[u8; 16]; 2],
) -> Vec<SelfPointer> {
    let all: Vec<SelfPointer> = std::iter::once(selected).chain(fallbacks).collect();
    let mut head_idx: Vec<usize> = Vec::with_capacity(2);
    for slot in place_slots {
        if let Some(i) = all
            .iter()
            .position(|p| slot_of.get(&p.signature) == Some(&slot))
        {
            head_idx.push(i);
        }
    }
    // `all` is freshest first, so the smaller index is the fresher head.
    head_idx.sort_unstable();
    head_idx.dedup();
    let mut attempts: Vec<SelfPointer> = head_idx.iter().map(|&i| all[i].clone()).collect();
    attempts.extend(
        all.into_iter()
            .enumerate()
            .filter(|(i, _)| !head_idx.contains(i))
            .map(|(_, p)| p),
    );
    attempts.truncate(MAX_POINTER_ATTEMPTS);
    attempts
}

/// dr-i35: try the pointers in order (the head first, then older pointers of the same
/// history) until one's state can be fetched. Returns the index of the pointer that
/// worked and its state, or every error in order.
async fn first_fetchable<T>(
    pointers: &[SelfPointer],
    mut fetch: impl AsyncFnMut(&SelfPointer) -> Result<T, String>,
) -> Result<(usize, T), Vec<String>> {
    let mut errors = Vec::new();
    for (i, p) in pointers.iter().enumerate() {
        match fetch(p).await {
            Ok(t) => return Ok((i, t)),
            Err(e) => {
                tracing::warn!(
                    created_at = p.created_at.0,
                    generation = p.generation,
                    error = %e,
                    "dr: this pointer's state could not be fetched"
                );
                errors.push(e);
            }
        }
    }
    Err(errors)
}

/// Dial the pointer's holders, fetch and decrypt its base and diff blocks, and apply the
/// diffs: the SystemState the pointer describes.
#[allow(clippy::too_many_arguments)]
async fn fetch_state(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut tokio::sync::mpsc::Receiver<crate::daemon::network::swarm::ProtocolEvent>,
    db: &viaticum_core::db::Db,
    encoder: &Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    dr_key: &[u8; 32],
    memory: &mut memory::Memory,
    pointer: &SelfPointer,
    failed_in_dr: &crate::daemon::symbol_fetch::FailedInTask,
) -> Result<SystemState, String> {
    net::dial_pointer_holders(swarm, event_rx, db, pointer).await;
    let base_state: SystemState =
        net::fetch_ss_block(swarm, encoder, &pointer.base, dr_key, memory, failed_in_dr)
            .await
            .map_err(|e| format!("failed to fetch SS base block: {e}"))?;
    let mut diffs: Vec<Vec<DiffOp>> = Vec::with_capacity(pointer.diffs.len());
    for dref in &pointer.diffs {
        diffs.push(
            net::fetch_ss_block(swarm, encoder, dref, dr_key, memory, failed_in_dr)
                .await
                .map_err(|e| format!("failed to fetch SS diff block: {e}"))?,
        );
    }
    Ok(apply_diffs(base_state, &diffs))
}
