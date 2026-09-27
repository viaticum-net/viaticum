// Tests for start-failure classification and start-time self-enrollment
// (daemon-i1).

use tempfile::TempDir;

use viaticum_core::cluster::{
    ClusterState, issue_device_certificate, master_identity, verify_device_certificate,
};
use viaticum_core::config::ConfigError;
use viaticum_core::db::{Db, DbError};
use viaticum_core::types::{CborError, DeviceId, Event, Timestamp};

use super::{
    EXIT_NEEDS_USER, EXIT_TEMPFAIL, Membership, StartError, StartFailureKind,
    classify_config_error, classify_db_error, classify_identity_error, ensure_own_device_enrolled,
};
use crate::daemon::identity::IdentityError;

fn key(byte: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
}

/// A database whose cluster state lists only `first_device`, certified by `master`.
fn cluster_with(
    dir: &TempDir,
    master: &ed25519_dalek::SigningKey,
    first_device: DeviceId,
) -> (Db, ClusterState) {
    let db = Db::open(&dir.path().join("db.redb")).expect("open db");
    let now = Timestamp::now();
    let cert = issue_device_certificate(master, first_device, now);
    let state =
        ClusterState::init(db.clone(), master_identity(master), cert, now, now).expect("init");
    (db, state)
}

#[test]
fn start_error_exit_code_is_78_for_needs_user_and_75_for_transient() {
    let needs_user = StartError::needs_user(anyhow::anyhow!("no key"));
    let transient = StartError::transient(anyhow::anyhow!("port busy"));
    assert_eq!(needs_user.kind, StartFailureKind::NeedsUser);
    assert_eq!(needs_user.exit_code(), EXIT_NEEDS_USER);
    assert_eq!(EXIT_NEEDS_USER, 78);
    assert_eq!(transient.kind, StartFailureKind::Transient);
    assert_eq!(transient.exit_code(), EXIT_TEMPFAIL);
    assert_eq!(EXIT_TEMPFAIL, 75);
}

#[test]
fn start_error_display_is_one_line_with_the_whole_context_chain() {
    let e = StartError::transient(
        anyhow::anyhow!("listen port 4001 is in use by another process")
            .context("libp2p swarm did not start"),
    );
    assert_eq!(
        e.to_string(),
        "libp2p swarm did not start: listen port 4001 is in use by another process"
    );
}

#[test]
fn classify_db_error_corrupted_or_old_format_needs_user() {
    let corrupted = DbError::Storage(redb::StorageError::Corrupted("bad page".into()));
    let upgrade = DbError::Database(redb::DatabaseError::UpgradeRequired(2));
    let corrupted_on_open = DbError::Database(redb::DatabaseError::Storage(
        redb::StorageError::Corrupted("bad header".into()),
    ));
    let undecodable = DbError::Cbor(CborError::Decode("truncated".into()));
    let wrapped = DbError::Redb(Box::new(redb::Error::Corrupted("x".into())));
    for e in [corrupted, upgrade, corrupted_on_open, undecodable, wrapped] {
        assert_eq!(classify_db_error(&e), StartFailureKind::NeedsUser, "{e}");
    }
}

#[test]
fn classify_db_error_lock_and_io_are_transient() {
    let locked = DbError::Database(redb::DatabaseError::DatabaseAlreadyOpen);
    let io = DbError::Storage(redb::StorageError::Io(std::io::Error::other("EIO")));
    let latched = DbError::Storage(redb::StorageError::PreviousIo);
    let repair_aborted = DbError::Database(redb::DatabaseError::RepairAborted);
    for e in [locked, io, latched, repair_aborted] {
        assert_eq!(classify_db_error(&e), StartFailureKind::Transient, "{e}");
    }
}

#[test]
fn enroll_is_noop_when_device_is_already_a_member() {
    let dir = TempDir::new().unwrap();
    let master = key(1);
    let device = DeviceId([7u8; 32]);
    let (db, mut state) = cluster_with(&dir, &master, device);
    let seq_before = db.last_event_seq().unwrap();

    let own = ensure_own_device_enrolled(&mut state, &master, device, Timestamp::now())
        .expect("member start");

    assert_eq!(own.membership, Membership::Member);
    assert_eq!(own.device_cert.device_id, device);
    assert_eq!(own.cluster_master_pub, master_identity(&master));
    assert_eq!(state.all_devices().len(), 1);
    assert_eq!(
        db.last_event_seq().unwrap(),
        seq_before,
        "no event for a member"
    );
}

/// The friend's recovery path (dr-i2): the stored cluster lists only the lost
/// device; this node holds the same master key under a new device id.
#[test]
fn enroll_adds_own_device_missing_from_restored_cluster_and_persists_it() {
    let dir = TempDir::new().unwrap();
    let master = key(1);
    let lost_device = DeviceId([7u8; 32]);
    let this_device = DeviceId([8u8; 32]);
    let (db, mut state) = cluster_with(&dir, &master, lost_device);

    let own = ensure_own_device_enrolled(&mut state, &master, this_device, Timestamp::now())
        .expect("enroll");

    assert_eq!(own.membership, Membership::Enrolled { device_index: 1 });
    assert_eq!(own.device_cert.device_id, this_device);
    verify_device_certificate(&own.device_cert, &master_identity(&master))
        .expect("the new certificate is signed by the cluster master");

    // Persisted: a fresh load of the same database sees both devices, and the
    // event log carries DeviceAdded for this device (siblings sync from it).
    let reloaded = ClusterState::load(db.clone()).expect("reload");
    assert!(
        reloaded.get_device(&lost_device).is_some(),
        "old device stays"
    );
    assert_eq!(
        reloaded.get_device(&this_device).map(|d| d.device_index),
        Some(1)
    );
    let events = db.events_after(0, 100).unwrap();
    assert!(
        events.iter().any(|(_, e)| matches!(
            e.event,
            Event::DeviceAdded { device_id } if device_id == this_device
        )),
        "DeviceAdded for the enrolled device must be in the event log"
    );
}

#[test]
fn enroll_refuses_needs_user_when_cluster_belongs_to_another_master() {
    let dir = TempDir::new().unwrap();
    let foreign_master = key(1);
    let our_master = key(2);
    let their_device = DeviceId([7u8; 32]);
    let our_device = DeviceId([8u8; 32]);
    let (db, mut state) = cluster_with(&dir, &foreign_master, their_device);

    let err = ensure_own_device_enrolled(&mut state, &our_master, our_device, Timestamp::now())
        .expect_err("a foreign cluster must not be joined");

    assert_eq!(err.kind, StartFailureKind::NeedsUser);
    assert_eq!(err.exit_code(), 78);
    assert!(
        err.to_string().contains("belongs to another master"),
        "{err}"
    );
    let reloaded = ClusterState::load(db).expect("reload");
    assert_eq!(reloaded.all_devices().len(), 1, "foreign state untouched");
    assert!(reloaded.get_device(&our_device).is_none());
}

#[test]
fn enroll_refuses_needs_user_when_cluster_is_full() {
    let dir = TempDir::new().unwrap();
    let master = key(1);
    let (_db, mut state) = cluster_with(&dir, &master, DeviceId([0u8; 32]));
    for i in 1..16u8 {
        let cert = issue_device_certificate(&master, DeviceId([i; 32]), Timestamp::now());
        state.add_device(cert, Timestamp::now()).expect("add");
    }
    assert_eq!(state.all_devices().len(), 16);

    let err =
        ensure_own_device_enrolled(&mut state, &master, DeviceId([99u8; 32]), Timestamp::now())
            .expect_err("a full cluster cannot take one more device");

    assert_eq!(err.kind, StartFailureKind::NeedsUser);
    assert!(err.to_string().contains("max devices"), "{err}");
}

/// Idempotence (agreed with line B): the start after an enrollment — and a
/// DR→DR chain, where the restored state already lists this device — finds the
/// device and changes nothing: no second DeviceAdded, no DeviceAlreadyRegistered.
#[test]
fn enroll_is_idempotent_on_the_next_start() {
    let dir = TempDir::new().unwrap();
    let master = key(1);
    let this_device = DeviceId([8u8; 32]);
    let (db, mut state) = cluster_with(&dir, &master, DeviceId([7u8; 32]));
    let first = ensure_own_device_enrolled(&mut state, &master, this_device, Timestamp::now())
        .expect("first start enrolls");
    assert_eq!(first.membership, Membership::Enrolled { device_index: 1 });
    let seq_after_enroll = db.last_event_seq().unwrap();

    // Next start: the state is loaded from the database again.
    let mut reloaded = ClusterState::load(db.clone()).expect("reload");
    let second = ensure_own_device_enrolled(&mut reloaded, &master, this_device, Timestamp::now())
        .expect("second start must not fail");

    assert_eq!(second.membership, Membership::Member);
    assert_eq!(second.device_cert.device_id, this_device);
    assert_eq!(reloaded.all_devices().len(), 2);
    assert_eq!(
        db.last_event_seq().unwrap(),
        seq_after_enroll,
        "no new event"
    );
}

#[test]
fn classify_identity_missing_key_needs_user_when_data_dir_is_readable() {
    let dir = TempDir::new().unwrap();
    assert_eq!(
        classify_identity_error(&IdentityError::NotInitialized, dir.path()),
        StartFailureKind::NeedsUser
    );
}

#[test]
fn classify_identity_missing_key_is_transient_when_data_dir_is_missing() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("home-not-mounted");
    assert_eq!(
        classify_identity_error(&IdentityError::NotInitialized, &missing),
        StartFailureKind::Transient
    );
}

#[test]
fn classify_identity_io_is_transient_and_corrupt_needs_user() {
    let dir = TempDir::new().unwrap();
    let io = IdentityError::Io(std::io::Error::other("EIO"));
    let corrupt = IdentityError::Corrupt(dir.path().join("identity.key"), "bad cbor".into());
    assert_eq!(
        classify_identity_error(&io, dir.path()),
        StartFailureKind::Transient
    );
    assert_eq!(
        classify_identity_error(&corrupt, dir.path()),
        StartFailureKind::NeedsUser
    );
}

#[test]
fn classify_config_io_is_transient_and_parse_or_validation_needs_user() {
    let io = ConfigError::Io(std::io::Error::other("EIO"));
    let dir = TempDir::new().unwrap();
    let broken = dir.path().join("config.toml");
    std::fs::write(&broken, "a = = 1\n").unwrap();
    let parse = viaticum_core::config::AppConfig::load(&broken).expect_err("broken toml");
    assert!(matches!(parse, ConfigError::Parse(_)), "{parse}");
    let validation = ConfigError::Validation {
        field: "network.listen_port".into(),
        reason: "bad".into(),
    };
    assert_eq!(classify_config_error(&io), StartFailureKind::Transient);
    assert_eq!(classify_config_error(&parse), StartFailureKind::NeedsUser);
    assert_eq!(
        classify_config_error(&validation),
        StartFailureKind::NeedsUser
    );
}
