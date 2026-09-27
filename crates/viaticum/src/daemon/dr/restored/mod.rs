//! What DR does to the recovered state before installing it, and how it shows the
//! catalogs it found. Pure functions plus one DB write (`install_restored_state`), so
//! they are tested without a network.

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use viaticum_core::db::Db;
use viaticum_core::system_state::catalog::{
    ChoiceReason, LineageRow, live_file_count, reassign_history_device,
};
use viaticum_core::system_state::{
    CatalogLineageId, CatalogSummary, SystemState, SystemStateError, merge_live_peer,
    restore_db_force,
};
use viaticum_core::types::{DeviceId, PeerRecord, hex_encode};

use crate::daemon::network::swarm::device_id_to_peer_id;

#[cfg(test)]
mod tests;

/// The restored state, made this DR's own.
#[derive(Debug)]
pub(crate) struct PreparedState {
    pub(crate) state: SystemState,
    /// Records whose lost-device entry now names the DR device (dr-i19).
    pub(crate) reassigned: usize,
    /// Live files (`live_file_count`) — what `dr` prints as `Files:`.
    pub(crate) live_files: u32,
}

/// dr-i19: the device that published the selected catalog is the lost machine; in every
/// restored file record it becomes `dr_device` (state kept). Siblings and the cluster
/// registry are not touched.
pub(crate) fn prepare_restored_state(
    mut state: SystemState,
    selected: &CatalogSummary,
    dr_device: DeviceId,
) -> PreparedState {
    let reassigned = reassign_history_device(&mut state.files, selected.publisher, dr_device);
    let live_files = live_file_count(&state.files);
    PreparedState {
        state,
        reassigned,
        live_files,
    }
}

/// Put the exact `--peer` multiaddr of each seed first in that seed's live record
/// (matched by the PeerId of its terminal `/p2p/` component). A seed without a live
/// record is ignored: DR did not reach it.
pub(crate) fn prepend_seed_addrs(live: &mut [PeerRecord], seeds: &[Multiaddr]) {
    for seed in seeds {
        let Some(Protocol::P2p(seed_pid)) = seed.iter().last() else {
            continue;
        };
        let seed_str = seed.to_string();
        for record in live.iter_mut() {
            if device_id_to_peer_id(&record.device_id).ok() != Some(seed_pid) {
                continue;
            }
            record.addrs.retain(|a| *a != seed_str);
            record.addrs.insert(0, seed_str.clone());
        }
    }
}

/// Install the restored state into the (staging) DB, then merge the peer records DR
/// learned live back over the snapshot (dr-i18): `restore_db_force` overwrites peers
/// with the snapshot, whose addresses may be stale. A live peer absent from the
/// snapshot stays as learned.
pub(crate) fn install_restored_state(
    db: &Db,
    state: &SystemState,
    live: &[PeerRecord],
) -> Result<(), SystemStateError> {
    restore_db_force(db, state)?;
    for l in live {
        let merged = match db.get_peer(&l.device_id)? {
            Some(snapshot) => merge_live_peer(&snapshot, l),
            None => l.clone(),
        };
        db.upsert_peer(&merged)?;
    }
    Ok(())
}

/// One line per catalog history, the selected one marked:
/// `  catalog=<32 hex> files=<n> published=<RFC3339> pointers=<k> publisher=<16 hex> [selected: …]`
pub(crate) fn render_catalog_rows(
    rows: &[LineageRow],
    selected: Option<(CatalogLineageId, ChoiceReason)>,
) -> String {
    let mut out = String::from("Catalogs found for this recovery phrase:\n");
    for r in rows {
        out.push_str(&format!(
            "  catalog={} files={} published={} pointers={} publisher={}",
            r.lineage.to_hex(),
            r.files,
            crate::daemon::dispatch::unix_secs_to_iso(r.created_at.0, true),
            r.pointers_seen,
            hex_encode(&r.publisher.0[..8]),
        ));
        if let Some((id, reason)) = selected
            && id == r.lineage
        {
            out.push_str(match reason {
                ChoiceReason::OnlyCatalog => " [selected: only one]",
                ChoiceReason::Requested => " [selected: requested]",
            });
        }
        out.push('\n');
    }
    out
}

/// N-6: when the chosen catalog cannot be fetched and others were listed, name the
/// next one to try. Empty when there is no other catalog.
pub(crate) fn fetch_failure_hint(rows: &[LineageRow], selected: CatalogLineageId) -> String {
    match rows.iter().find(|r| r.lineage != selected) {
        Some(next) => format!(
            " This catalog could not be fetched; you can try another one: --catalog {}",
            &next.lineage.to_hex()[..8]
        ),
        None => String::new(),
    }
}
