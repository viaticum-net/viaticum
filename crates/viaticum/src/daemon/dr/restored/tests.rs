// Tests for what DR does to the restored state (dr-i19 ownership, dr-i18 live peers)
// and how it lists catalogs. Real redb (in memory), no network.

use libp2p::Multiaddr;
use viaticum_core::db::Db;
use viaticum_core::deletion::{DeletionEngine, MarkDeletedResult};
use viaticum_core::system_state::catalog::{ChoiceReason, LineageRow};
use viaticum_core::system_state::{CatalogLineageId, CatalogSummary, snapshot_db};
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, IdentityPub, LocalState, PeerRecord, Timestamp,
};

use super::*;
use crate::daemon::network::swarm::device_id_to_peer_id;
use crate::daemon::network::swarm_test_helpers::make_signing_key;

fn file(id: u64, path: &str, devices: Vec<(DeviceId, LocalState)>) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices,
        versions: vec![],
        first_seen: Timestamp(1),
    }
}

/// A real Ed25519 device (so it maps to a PeerId).
fn device(seed: u8) -> DeviceId {
    DeviceId(make_signing_key(seed).verifying_key().to_bytes())
}

fn peer(d: DeviceId, addrs: &[String], trust_p: f64) -> PeerRecord {
    PeerRecord {
        device_id: d,
        master_identity: IdentityPub([9; 32]),
        trust_p,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(1),
        revoked_device_pub_keys: vec![],
        addrs: addrs.to_vec(),
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    }
}

fn summary(publisher: DeviceId, files: u32) -> CatalogSummary {
    CatalogSummary {
        lineage: CatalogLineageId([0xAB; 16]),
        publisher,
        files,
    }
}

/// dr-i19 end to end over the restore path: the lost device's records land in the
/// staging DB under the DR device, and deleting a file there starts the cooldown.
#[test]
fn dr_restored_state_is_reassigned_before_restore() {
    let d_rand = device(0x11);
    let d_star = device(0x22);
    let lost_db = Db::open_in_memory().unwrap();
    lost_db
        .upsert_file(&file(1, "/data/f1", vec![(d_rand, LocalState::Present)]))
        .unwrap();
    lost_db
        .upsert_file(&file(
            2,
            "/data/gone",
            vec![(d_rand, LocalState::Deleted(Timestamp(3)))],
        ))
        .unwrap();
    let state = snapshot_db(&lost_db).unwrap();

    let prepared = prepare_restored_state(state, &summary(d_rand, 1), d_star);
    assert_eq!(prepared.reassigned, 2);
    assert_eq!(prepared.live_files, 1);

    let staging = Db::open_in_memory().unwrap();
    install_restored_state(&staging, &prepared.state, &[]).unwrap();
    let f1 = staging.get_file("/data/f1").unwrap().expect("restored");
    assert_eq!(f1.devices, vec![(d_star, LocalState::Present)]);
    assert!(matches!(
        DeletionEngine::new()
            .mark_deleted(&f1, d_star, Timestamp(10))
            .unwrap(),
        MarkDeletedResult::CooldownStarted { .. }
    ));
}

#[test]
fn dr_into_the_lost_devices_own_folder_changes_no_owner() {
    // KeySource::Existing: the key in the folder IS the publisher → nothing to move.
    let d = device(0x11);
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&file(1, "/data/f1", vec![(d, LocalState::Present)]))
        .unwrap();
    let prepared = prepare_restored_state(snapshot_db(&db).unwrap(), &summary(d, 1), d);
    assert_eq!(prepared.reassigned, 0);
    assert_eq!(
        prepared.state.files[0].devices,
        vec![(d, LocalState::Present)]
    );
}

// ─── dr-i18: live peers over the snapshot ─────────────────────────────────────

fn seed_addr(d: DeviceId, port: u16) -> Multiaddr {
    let pid = device_id_to_peer_id(&d).unwrap();
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{pid}")
        .parse()
        .unwrap()
}

#[test]
fn prepend_seed_addrs_puts_peer_arg_first_for_matching_peer_id() {
    let seed = device(0x31);
    let other = device(0x32);
    let arg = seed_addr(seed, 5001);
    let mut live = vec![
        peer(other, &["/ip4/10.0.0.2/tcp/1".to_string()], 0.1),
        peer(
            seed,
            &["/ip4/10.0.0.1/tcp/1".to_string(), arg.to_string()],
            0.1,
        ),
    ];
    prepend_seed_addrs(&mut live, std::slice::from_ref(&arg));
    assert_eq!(
        live[1].addrs,
        vec![arg.to_string(), "/ip4/10.0.0.1/tcp/1".to_string()],
        "--peer first, no duplicate"
    );
    assert_eq!(live[0].addrs, vec!["/ip4/10.0.0.2/tcp/1".to_string()]);
}

#[test]
fn prepend_seed_addrs_ignores_seed_without_record() {
    let mut live = vec![peer(device(0x33), &[], 0.1)];
    prepend_seed_addrs(&mut live, &[seed_addr(device(0x34), 5002)]);
    assert!(live[0].addrs.is_empty());
}

/// The seed moved to a new port after the last pointer: the snapshot holds its old
/// address, DR reached it at the new one (`--peer`). After the restore the recovered
/// DB dials the new address first and keeps the snapshot's trust history.
#[test]
fn restored_db_keeps_seed_addr_from_peer_arg_over_snapshot_addr() {
    let seed = device(0x41);
    let old_addr = seed_addr(seed, 4001).to_string();
    let new_addr = seed_addr(seed, 4777);

    let lost_db = Db::open_in_memory().unwrap();
    lost_db
        .upsert_peer(&peer(seed, std::slice::from_ref(&old_addr), 0.93))
        .unwrap();
    let state = snapshot_db(&lost_db).unwrap();

    // What DR learned live, in the staging DB.
    let staging = Db::open_in_memory().unwrap();
    staging.upsert_peer(&peer(seed, &[], 0.1)).unwrap();
    let mut live = staging.list_all_peers().unwrap();
    prepend_seed_addrs(&mut live, std::slice::from_ref(&new_addr));
    install_restored_state(&staging, &state, &live).unwrap();

    let got = staging.get_peer(&seed).unwrap().unwrap();
    assert_eq!(got.addrs, vec![new_addr.to_string(), old_addr]);
    assert_eq!(got.trust_p, 0.93, "trust history from the snapshot");
}

#[test]
fn restored_db_keeps_a_live_peer_absent_from_the_snapshot() {
    let staging = Db::open_in_memory().unwrap();
    let newcomer = device(0x51);
    let live = vec![peer(newcomer, &["/ip4/10.0.0.7/tcp/1".to_string()], 0.1)];
    let empty = snapshot_db(&Db::open_in_memory().unwrap()).unwrap();
    install_restored_state(&staging, &empty, &live).unwrap();
    assert!(staging.get_peer(&newcomer).unwrap().is_some());
}

// ─── Catalog table and hint ───────────────────────────────────────────────────

fn row(b: u8, files: u32, created_at: u64) -> LineageRow {
    LineageRow {
        lineage: CatalogLineageId([b; 16]),
        files,
        created_at: Timestamp(created_at),
        generation: 1,
        publisher: DeviceId([b; 32]),
        pointers_seen: 2,
    }
}

#[test]
fn catalog_rows_list_history_files_date_publisher_and_mark_selection() {
    let rows = vec![row(0xaa, 3, 1_790_000_000), row(0xbb, 0, 1_790_000_100)];
    let out = render_catalog_rows(
        &rows,
        Some((CatalogLineageId([0xaa; 16]), ChoiceReason::Requested)),
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "Catalogs found for this recovery phrase:");
    assert_eq!(
        lines[1],
        format!(
            "  catalog={} files=3 published=2026-09-21T14:13:20Z pointers=2 publisher={} \
             [selected: requested]",
            "aa".repeat(16),
            "aa".repeat(8)
        )
    );
    assert!(lines[2].starts_with(&format!("  catalog={} files=0 ", "bb".repeat(16))));
    assert!(!lines[2].contains("[selected"));
}

#[test]
fn fetch_failure_hint_names_next_catalog_when_several() {
    let rows = vec![row(0xaa, 3, 10), row(0xbb, 0, 20)];
    let hint = fetch_failure_hint(&rows, CatalogLineageId([0xaa; 16]));
    assert!(hint.contains("--catalog bbbbbbbb"), "{hint}");
}

#[test]
fn fetch_failure_hint_empty_for_single() {
    let rows = vec![row(0xaa, 3, 10)];
    assert_eq!(fetch_failure_hint(&rows, CatalogLineageId([0xaa; 16])), "");
}
