// Start failures of the daemon (daemon-i1).
//
// A node either works as a whole or refuses to start loudly. Every reason
// `DaemonHandle::start` refuses is classified here, because the class decides
// what the service manager does next:
//
//   NeedsUser (exit 78, EX_CONFIG): nothing changes until a person acts — a
//     missing or corrupt identity, a broken config, a database this binary
//     cannot read, a cluster state that belongs to another master, a full
//     cluster. The unit ships `RestartPreventExitStatus=78`, so systemd stops
//     retrying and `status` shows the reason.
//   Transient (exit 75, EX_TEMPFAIL): the cause can go away by itself — the
//     listen port or the database lock is held by another process, the data
//     directory is not there yet (home not mounted or not unlocked when a
//     `systemd --user` unit with linger starts), a read or write failed.
//     systemd restarts us.
//
// Classification is explicit at every failure site in `start` (there is no
// blanket conversion): an unclassified error does not compile.
//
// This module also holds the start-time membership check: a node that holds
// the master key and is missing from the cluster state stored in its own data
// dir (a fresh `init` followed by `dr`) enrolls itself instead of starting
// without a network.

#[cfg(test)]
mod tests;

use std::path::Path;

use crate::daemon::identity::IdentityError;

use viaticum_core::cluster::{
    ClusterState, ClusterStateError, DeviceCertificate, issue_device_certificate, master_identity,
};
use viaticum_core::config::ConfigError;
use viaticum_core::db::DbError;
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

/// Exit status for a start failure that a restart can cure (sysexits EX_TEMPFAIL).
pub const EXIT_TEMPFAIL: u8 = 75;
/// Exit status for a start failure that needs a person (sysexits EX_CONFIG).
pub const EXIT_NEEDS_USER: u8 = 78;

/// Whether a failed start can succeed on a later attempt without a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFailureKind {
    /// Retrying does not help until someone fixes the key, config or state.
    NeedsUser,
    /// The cause can go away on its own (port, lock, disk); retry later.
    Transient,
}

/// Why `DaemonHandle::start` refused to run the node.
#[derive(Debug)]
pub struct StartError {
    /// Retry class; decides the exit status.
    pub kind: StartFailureKind,
    /// What failed, with context ("libp2p swarm did not start: listen port …").
    pub source: anyhow::Error,
}

impl StartError {
    /// A failure with an explicit class.
    pub fn new(kind: StartFailureKind, e: impl Into<anyhow::Error>) -> Self {
        Self {
            kind,
            source: e.into(),
        }
    }

    /// A failure that needs a person (exit 78).
    pub fn needs_user(e: impl Into<anyhow::Error>) -> Self {
        Self::new(StartFailureKind::NeedsUser, e)
    }

    /// A failure a later attempt can get past (exit 75).
    pub fn transient(e: impl Into<anyhow::Error>) -> Self {
        Self::new(StartFailureKind::Transient, e)
    }

    /// Process exit status for this failure.
    pub fn exit_code(&self) -> u8 {
        match self.kind {
            StartFailureKind::NeedsUser => EXIT_NEEDS_USER,
            StartFailureKind::Transient => EXIT_TEMPFAIL,
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // One line with the whole context chain: this is what the friend reads.
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Class of a database error hit while opening or reading the database at start.
///
/// NeedsUser when this binary cannot read what is on disk (corruption, an old
/// file format, a table schema that does not match, an undecodable record):
/// retrying reads the same bytes. Everything else — the lock held by another
/// process, I/O, a latched earlier I/O failure, an aborted repair on a
/// read-only file system — is Transient.
pub fn classify_db_error(e: &DbError) -> StartFailureKind {
    use redb::{DatabaseError, StorageError, TableError, TransactionError};

    fn storage(e: &StorageError) -> StartFailureKind {
        match e {
            StorageError::Corrupted(_) => StartFailureKind::NeedsUser,
            _ => StartFailureKind::Transient,
        }
    }
    fn table(e: &TableError) -> StartFailureKind {
        match e {
            TableError::TableTypeMismatch { .. }
            | TableError::TableIsMultimap(_)
            | TableError::TableIsNotMultimap(_)
            | TableError::TypeDefinitionChanged { .. } => StartFailureKind::NeedsUser,
            TableError::Storage(s) => storage(s),
            _ => StartFailureKind::Transient,
        }
    }

    match e {
        DbError::Cbor(_) => StartFailureKind::NeedsUser,
        DbError::Database(DatabaseError::UpgradeRequired(_)) => StartFailureKind::NeedsUser,
        DbError::Database(DatabaseError::Storage(s)) => storage(s),
        DbError::Storage(s) => storage(s),
        DbError::Table(t) => table(t),
        DbError::Transaction(t) => match t.as_ref() {
            TransactionError::Storage(s) => storage(s),
            _ => StartFailureKind::Transient,
        },
        DbError::Commit(redb::CommitError::Storage(s)) => storage(s),
        DbError::Redb(r) => match r.as_ref() {
            redb::Error::Corrupted(_)
            | redb::Error::UpgradeRequired(_)
            | redb::Error::TableTypeMismatch { .. }
            | redb::Error::TableIsMultimap(_)
            | redb::Error::TableIsNotMultimap(_)
            | redb::Error::TypeDefinitionChanged { .. } => StartFailureKind::NeedsUser,
            _ => StartFailureKind::Transient,
        },
        _ => StartFailureKind::Transient,
    }
}

/// Class of an identity load error at start.
///
/// A missing `identity.key` needs a person (`viaticum init`) only when the
/// data directory itself is there and readable. When the directory is missing
/// or unreadable, the key cannot be seen yet — typically the home directory is
/// not mounted or not unlocked when the unit starts — so a later attempt can
/// succeed. An I/O error reading the key is transient; an undecodable key is
/// not.
pub fn classify_identity_error(e: &IdentityError, data_dir: &Path) -> StartFailureKind {
    match e {
        IdentityError::NotInitialized if std::fs::read_dir(data_dir).is_ok() => {
            StartFailureKind::NeedsUser
        }
        IdentityError::NotInitialized | IdentityError::Io(_) => StartFailureKind::Transient,
        _ => StartFailureKind::NeedsUser,
    }
}

/// Class of a config load error at start: I/O is transient, a file that does
/// not parse or validate needs a person.
pub fn classify_config_error(e: &ConfigError) -> StartFailureKind {
    match e {
        ConfigError::Io(_) => StartFailureKind::Transient,
        ConfigError::Parse(_) | ConfigError::Validation { .. } => StartFailureKind::NeedsUser,
    }
}

/// Class of a cluster-state error at start (load, init, self-enrollment).
pub fn classify_cluster_error(e: &ClusterStateError) -> StartFailureKind {
    match e {
        ClusterStateError::Db(db) => classify_db_error(db),
        ClusterStateError::MaxDevicesReached => StartFailureKind::NeedsUser,
        _ => StartFailureKind::Transient,
    }
}

/// What the start-time membership check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Membership {
    /// This device already has a certificate in the stored cluster state.
    Member,
    /// This device was missing and has been enrolled with the master key.
    Enrolled {
        /// Index assigned to this device in the cluster.
        device_index: u8,
    },
}

/// This device's certificate and the cluster's master, as the swarm needs them.
#[derive(Debug, Clone)]
pub struct OwnMembership {
    /// Certificate of this device, signed by the cluster master.
    pub device_cert: DeviceCertificate,
    /// Master identity of the cluster (anchor for certificate checks).
    pub cluster_master_pub: IdentityPub,
    /// Whether the device was already a member or has just been enrolled.
    pub membership: Membership,
}

/// Make sure this device is a member of the cluster stored in this data dir.
///
/// A device without its own certificate cannot join the network (peers check
/// the certificate). The usual way to get here is a friend's recovery path: a
/// fresh `init` (random device key) followed by `dr`, which restores the old
/// cluster state listing only the lost device (dr-i2). The node holds the
/// master key (it is derived from the seed, P5), so it issues its own
/// certificate and enrolls — with a WARN naming the reason — instead of
/// starting without a network.
///
/// Idempotent: membership is looked up first and `add_device` runs only for a
/// device that is not there, so a later start (or a DR→DR chain, where the
/// deterministic DR device id is already in the restored state) finds its own
/// entry and changes nothing — `DeviceAlreadyRegistered` cannot arise here.
/// This is the only place that enrolls the local device after DR (agreed with
/// line B: `dr` itself does not; E2E proof is dr-i22 in `local_dr_test`).
///
/// Refuses (NeedsUser) when the stored cluster belongs to another master (the
/// database next to this identity is someone else's: this key cannot sign into
/// it) or when the cluster is full.
pub fn ensure_own_device_enrolled(
    state: &mut ClusterState,
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    now: Timestamp,
) -> Result<OwnMembership, StartError> {
    let cluster_master_pub = state.master_pub();
    if let Some(entry) = state.get_device(&device_id) {
        return Ok(OwnMembership {
            device_cert: entry.certificate.clone(),
            cluster_master_pub,
            membership: Membership::Member,
        });
    }

    let own_master = master_identity(master_key);
    if own_master != cluster_master_pub {
        return Err(StartError::needs_user(anyhow::anyhow!(
            "the cluster state in this data dir belongs to another master \
             (cluster master {cluster_master_pub}, this identity {own_master}); \
             this device ({device_id}) is not a member and cannot enroll itself. \
             Put the matching identity.key and db.redb together, or move db.redb \
             away to start a new cluster"
        )));
    }

    let cert = issue_device_certificate(master_key, device_id, now);
    if let Err(e) = state.add_device(cert.clone(), now) {
        let kind = classify_cluster_error(&e);
        return Err(StartError::new(
            kind,
            anyhow::Error::new(e).context(format!(
                "this device ({device_id}) is not in the cluster state and could not be enrolled"
            )),
        ));
    }
    let device_index = state
        .get_device(&device_id)
        .map(|entry| entry.device_index)
        .ok_or_else(|| {
            StartError::transient(anyhow::anyhow!(
                "device {device_id} missing from the cluster state right after enrollment"
            ))
        })?;
    tracing::warn!(
        device = %device_id,
        device_index,
        cluster_devices = state.all_devices().len(),
        "this device was not in the cluster state stored in this data dir (typical after \
         `viaticum dr` onto a fresh `init`); enrolled it with the master key so the node \
         can join the network"
    );
    Ok(OwnMembership {
        device_cert: cert,
        cluster_master_pub,
        membership: Membership::Enrolled { device_index },
    })
}
