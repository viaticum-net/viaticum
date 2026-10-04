// The ordered PeerRecord writer (C-DK C4 fix round 3).
//
// Ownership. The PeerRecords' authentication and identify updates belong to ONE consumer:
// this writer. `Processor::run` hands each `PeerAuthenticated` / `PeerIdentified` over with
// `PeerRecordQueue::push` and goes straight on to the next event — it never touches the
// disk for them, so an `InboundRequest` behind a burst of authentications is not delayed
// by their fsyncs (fix round 1 wrote them inline in the loop: two durable commits per
// authentication, 0.5-1 s each under load, 39 authentications took 73 s and every request
// in the same queue waited — PeerAnnounce timeouts at the seed).
//
// Order. One queue, one consumer, one batch in flight: everything pushed before an event
// is written no later than that event. Per device the queue keeps one merged entry
// (`PendingPeer`), folded in arrival order: a later authentication replaces the earlier
// one's facts, the latest non-empty address list wins, whether it came with the
// authentication or with identify. So "authentication, then identify" of one peer is
// never written as identify-before-record (fix round 1's race), and an identify that
// arrives before its authentication is written is not dropped either: it rides in the
// same entry.
//
// Batches. The writer takes up to `BATCH_MAX` entries and writes them in ONE write
// transaction (`Db::update_peers`): the PeerRecord and the device-to-master mapping of an
// authentication in the same commit, the whole batch in one sync. Whatever arrives while a
// commit syncs is the next batch. An identify that changes nothing is filtered on a read
// transaction first: a batch of such no-ops never begins a write.
//
// Bounded, lossless, never waiting. The queue holds at most one entry per device; a
// repeated event of a queued device folds into its entry and costs no memory. The number of
// distinct devices is capped at `PENDING_MAX` (a NEW device beyond it is dropped — that many
// distinct peers authenticated within one commit is a flood, not a network; an ERROR at
// most once per `DROP_LOG_EVERY` names how many were dropped since the last one, and the
// daemon counts every drop in `status` as `peer_record_dropped`). A
// WARN marks the queue growing past `PENDING_WARN` (the disk is far behind). `push` takes
// a std mutex for a map insert and returns; the loop never awaits the writer. Hence no
// bounded mpsc: a full mpsc forces the producer to wait (the loop must not) or to drop
// (authentications must not be lost); folding by device is the only way to be bounded,
// lossless and non-waiting at once.
//
// Thread. redb is synchronous: each batch runs in `spawn_blocking`, awaited by the writer
// task, so no runtime worker blocks on an fsync and exactly one batch is in flight. A
// dedicated OS thread would do the same but needs its own wake-up and shutdown plumbing;
// the async task gets both from `Notify` and the cancellation token.
//
// Revocation. `Processor::run` admits an authentication (revocation check) before it
// pushes it; a revocation committed between the push and the batch is seen inside the
// batch's transaction (`PeerBatch::is_device_revoked`, the same two lists): the entry is
// not written and its after-steps do not run (C-DK C4 fix round 4, N1).
//
// After the commit. For every authentication written the writer spawns
// `Processor::after_peer_authenticated` (cluster auto-add, PeerAnnounce, work wake) — the
// steps that may wait on the network, as before, now strictly after the record exists.
//
// Shutdown. The writer has its own token, cancelled by `Processor::run` only after its
// loop has ended: every push happens before the cancel, and the writer writes what is
// queued once it sees it (fix round 4, N2).
//
// No deadlock: the loop holds the queue mutex only for a map operation and never waits on
// the writer; the writer holds it only to take a batch and never while writing; the write
// transaction holds redb's single writer lock and nothing else (the cluster state is read
// from its table, not through the in-memory `ClusterState` mutex, which is taken BEFORE
// redb's writer lock elsewhere), and a concurrent `update_peer` (PeerAnnounce) just waits
// for it.
//
// Lost updates. Against `update_peer` each sees the other's commit whole. Not against the
// writers that read with `get_peer` and write back with `upsert_peer` in two transactions:
// a batch committed between the two is overwritten. The list and why it is left as it is:
// `Db::update_peers` in viaticum-core (`db/peer_batch`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use viaticum_core::cluster::DeviceCertificate;
use viaticum_core::constants::{AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::db::{Db, DbError, PeerBatch};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp, ewma_contact_observed};

use super::Processor;

#[cfg(test)]
mod tests;

/// Most entries one write transaction takes.
pub(crate) const BATCH_MAX: usize = 256;
/// A WARN when this many devices wait for the writer (once per backlog).
pub(crate) const PENDING_WARN: usize = 1024;
/// Most distinct devices waiting; a new device beyond it is dropped.
pub(crate) const PENDING_MAX: usize = 16_384;
/// The ERROR about devices dropped at the cap: at most once per this.
pub(crate) const DROP_LOG_EVERY: Duration = Duration::from_secs(10);

/// One PeerRecord event, in the swarm's order.
#[derive(Debug, Clone)]
pub(crate) enum PeerRecordEvent {
    /// The cert exchange succeeded (already admitted: not revoked).
    Authenticated {
        device_id: DeviceId,
        identity_pub: IdentityPub,
        /// Boxed: the certificate is most of the event's size.
        device_cert: Box<DeviceCertificate>,
        x25519_pub: Option<[u8; 32]>,
        /// Full multiaddr strings; empty = none known yet (a listener learns them from
        /// identify).
        listen_addrs: Vec<String>,
    },
    /// identify delivered the peer's listen addresses.
    Identified {
        device_id: DeviceId,
        listen_addrs: Vec<String>,
    },
}

/// The authentication facts of a queued device (the latest authentication).
#[derive(Debug, Clone)]
struct AuthFacts {
    identity_pub: IdentityPub,
    device_cert: DeviceCertificate,
    x25519_pub: Option<[u8; 32]>,
    /// Authentications folded into this entry (each is one observed contact).
    contacts: u32,
}

/// Everything not yet written about one device, folded in arrival order.
#[derive(Debug, Clone)]
pub(crate) struct PendingPeer {
    device_id: DeviceId,
    auth: Option<AuthFacts>,
    /// The latest non-empty address list (from an authentication or identify).
    addrs: Option<Vec<String>>,
}

impl PendingPeer {
    fn new(device_id: DeviceId) -> Self {
        PendingPeer {
            device_id,
            auth: None,
            addrs: None,
        }
    }

    fn fold(&mut self, event: PeerRecordEvent) {
        match event {
            PeerRecordEvent::Authenticated {
                identity_pub,
                device_cert,
                x25519_pub,
                listen_addrs,
                ..
            } => {
                let (contacts, earlier_x25519) = match &self.auth {
                    Some(a) => (a.contacts, a.x25519_pub),
                    None => (0, None),
                };
                self.auth = Some(AuthFacts {
                    identity_pub,
                    device_cert: *device_cert,
                    // As two writes in a row: a later authentication without a key keeps
                    // the earlier one's.
                    x25519_pub: x25519_pub.or(earlier_x25519),
                    contacts: contacts.saturating_add(1),
                });
                if !listen_addrs.is_empty() {
                    self.addrs = Some(listen_addrs);
                }
            }
            PeerRecordEvent::Identified { listen_addrs, .. } => {
                if !listen_addrs.is_empty() {
                    self.addrs = Some(listen_addrs);
                }
            }
        }
    }
}

impl PeerRecordEvent {
    fn device_id(&self) -> DeviceId {
        match self {
            PeerRecordEvent::Authenticated { device_id, .. }
            | PeerRecordEvent::Identified { device_id, .. } => *device_id,
        }
    }

    /// An identify without addresses changes nothing (as before: not queued).
    fn is_noop(&self) -> bool {
        matches!(self, PeerRecordEvent::Identified { listen_addrs, .. } if listen_addrs.is_empty())
    }
}

#[derive(Default)]
struct PendingState {
    /// Devices in first-arrival order.
    order: VecDeque<DeviceId>,
    by_device: HashMap<DeviceId, PendingPeer>,
    /// The PENDING_WARN line was printed for the current backlog.
    warned: bool,
    /// Drops at the cap not yet reported by an ERROR.
    dropped_unreported: u64,
    /// When the last drop ERROR was printed.
    last_drop_log: Option<Instant>,
}

impl PendingState {
    /// One drop at the cap at `now`: `Some(n)` = print the ERROR now, `n` dropped since the
    /// last one (this one included); `None` = within `DROP_LOG_EVERY` of the last line.
    fn note_drop(&mut self, now: Instant) -> Option<u64> {
        self.dropped_unreported += 1;
        self.drop_report_due(now)
    }

    /// The drops not yet reported, when the last report is `DROP_LOG_EVERY` old (or none
    /// was printed yet); the count is reset then.
    fn drop_report_due(&mut self, now: Instant) -> Option<u64> {
        if self.dropped_unreported == 0 {
            return None;
        }
        if self
            .last_drop_log
            .is_some_and(|t| now.saturating_duration_since(t) < DROP_LOG_EVERY)
        {
            return None;
        }
        self.last_drop_log = Some(now);
        Some(std::mem::take(&mut self.dropped_unreported))
    }
}

fn log_drops(dropped: u64, pending: usize) {
    error!(
        dropped,
        pending,
        every_secs = DROP_LOG_EVERY.as_secs(),
        "peer-record writer: queue at its cap of distinct devices, events of new devices dropped since the last such line"
    );
}

/// The writer's queue: one folded entry per device (see the module comment).
pub(crate) struct PeerRecordQueue {
    state: Mutex<PendingState>,
    wake: Notify,
    max_devices: usize,
}

impl PeerRecordQueue {
    pub(crate) fn new(max_devices: usize) -> Self {
        PeerRecordQueue {
            state: Mutex::new(PendingState::default()),
            wake: Notify::new(),
            max_devices,
        }
    }

    /// Queue `event` behind everything pushed before it and wake the writer. Never waits
    /// for the writer. Returns false only when a NEW device is refused at the cap (the
    /// caller counts it for `status`; the ERROR is rate-limited here).
    pub(crate) fn push(&self, event: PeerRecordEvent) -> bool {
        if event.is_noop() {
            return true;
        }
        let device_id = event.device_id();
        {
            let mut st = self.state.lock().expect("peer record queue poisoned");
            if let Some(entry) = st.by_device.get_mut(&device_id) {
                entry.fold(event);
            } else {
                if st.by_device.len() >= self.max_devices {
                    let pending = st.by_device.len();
                    if let Some(dropped) = st.note_drop(Instant::now()) {
                        log_drops(dropped, pending);
                    }
                    debug!(device = %device_id, "peer-record writer: event of a new device dropped at the cap");
                    return false;
                }
                let mut entry = PendingPeer::new(device_id);
                entry.fold(event);
                st.by_device.insert(device_id, entry);
                st.order.push_back(device_id);
                if st.by_device.len() >= PENDING_WARN && !st.warned {
                    st.warned = true;
                    warn!(
                        pending = st.by_device.len(),
                        "peer-record writer: devices waiting for the disk (no event is dropped)"
                    );
                }
            }
        }
        self.wake.notify_one();
        true
    }

    /// The oldest `max` entries (fewer when fewer wait), removed from the queue.
    pub(crate) fn take_batch(&self, max: usize) -> Vec<PendingPeer> {
        let mut st = self.state.lock().expect("peer record queue poisoned");
        let n = max.min(st.order.len());
        let mut batch = Vec::with_capacity(n);
        for _ in 0..n {
            let Some(device_id) = st.order.pop_front() else {
                break;
            };
            if let Some(entry) = st.by_device.remove(&device_id) {
                batch.push(entry);
            }
        }
        if st.by_device.is_empty() {
            st.warned = false;
        }
        // Drops after the last ERROR line are reported once its window has passed, even
        // when no further drop comes.
        if let Some(dropped) = st.drop_report_due(Instant::now()) {
            log_drops(dropped, st.by_device.len());
        }
        batch
    }

    /// Devices waiting for the writer.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .expect("peer record queue poisoned")
            .by_device
            .len()
    }
}

/// An authentication the writer wrote: what `after_peer_authenticated` needs.
#[derive(Debug, Clone)]
pub(crate) struct WrittenAuth {
    pub device_id: DeviceId,
    pub identity_pub: IdentityPub,
    pub device_cert: DeviceCertificate,
    pub is_new_peer: bool,
}

/// Write `batch` in one write transaction (`Db::update_peers`). Identify-only entries that
/// change nothing (no record — out of order or revoked; or the same addresses) are dropped
/// on a read transaction first, so a batch of only those begins no write. Returns the
/// authentications written, in batch order.
pub(crate) fn apply_batch(db: &Db, batch: Vec<PendingPeer>) -> Result<Vec<WrittenAuth>, DbError> {
    let batch: Vec<PendingPeer> = batch
        .into_iter()
        .filter(|p| p.auth.is_some() || identify_changes(db, p))
        .collect();
    if batch.is_empty() {
        return Ok(Vec::new());
    }
    let now = Timestamp::now();
    let (written, _committed) = db.update_peers(|b| {
        let mut written = Vec::new();
        for p in batch {
            if let Some(auth) = write_entry(b, p.device_id, p.auth, p.addrs, now)? {
                written.push(auth);
            }
        }
        Ok(written)
    })?;
    Ok(written)
}

/// Would this identify-only entry change the stored record? Read transaction only.
fn identify_changes(db: &Db, p: &PendingPeer) -> bool {
    let Some(addrs) = &p.addrs else {
        return false;
    };
    match db.get_peer(&p.device_id) {
        Ok(Some(record)) => record.addrs != *addrs,
        Ok(None) => {
            // Every authentication is queued before its identify and written no later: a
            // missing record means a revoked device (never recorded) — worth seeing.
            debug!(device = %p.device_id, "peer-record writer: PeerRecord missing, identify addresses dropped");
            false
        }
        // Let the write transaction meet (and report) the error.
        Err(_) => true,
    }
}

/// One entry inside the batch transaction. An authentication: the record (created or
/// updated as `on_peer_authenticated` always did; `addrs` from the entry when it has any —
/// in the write that creates the record, network-i2, I6) and the device-to-master mapping.
/// An identify alone: the addresses of an existing record.
fn write_entry(
    b: &mut PeerBatch<'_>,
    device_id: DeviceId,
    auth: Option<AuthFacts>,
    addrs: Option<Vec<String>>,
    now: Timestamp,
) -> Result<Option<WrittenAuth>, DbError> {
    let current = b.get(&device_id)?;
    let Some(auth) = auth else {
        // An identify alone: as before, the addresses of whatever record exists (a revoked
        // device's record included — admission never gated identify).
        if let (Some(mut record), Some(addrs)) = (current, addrs)
            && record.addrs != addrs
        {
            record.addrs = addrs;
            b.put(&record)?;
        }
        return Ok(None);
    };
    // N1: revoked after admission, before this commit — not written, no after-steps.
    if b.is_device_revoked(&device_id)? {
        warn!(device = %device_id, master = %auth.identity_pub,
            "peer-record writer: device revoked after its authentication was admitted — record not written");
        return Ok(None);
    }
    let is_new_peer = current.is_none();
    let mut record = match current {
        Some(mut existing) => {
            existing.master_identity = auth.identity_pub;
            existing.last_seen = now;
            if auth.x25519_pub.is_some() {
                existing.x25519_pub = auth.x25519_pub;
            }
            if existing.trust_p == 0.0 && existing.trust_i == 0.0 {
                existing.trust_p = INITIAL_TRUST_P;
            }
            for _ in 0..auth.contacts {
                existing.avail_ewma = ewma_contact_observed(existing.avail_ewma, AVAIL_EWMA_ALPHA);
            }
            existing.last_avail_sample = now.0;
            existing
        }
        None => PeerRecord {
            device_id,
            master_identity: auth.identity_pub,
            trust_p: INITIAL_TRUST_P,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now,
            last_seen: now,
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: auth.x25519_pub,
            avail_ewma: AVAIL_EWMA_INITIAL,
            last_avail_sample: now.0,
        },
    };
    if let Some(addrs) = addrs {
        record.addrs = addrs;
    }
    b.put(&record)?;
    // Two-level trust: the device's master, in the same commit as the record.
    b.set_master_for_device(&device_id, &auth.identity_pub)?;
    Ok(Some(WrittenAuth {
        device_id,
        identity_pub: auth.identity_pub,
        device_cert: auth.device_cert,
        is_new_peer,
    }))
}

/// The writer task (spawned by `Processor::run`): wait for events, write them batch by
/// batch, then run the after-steps of each authentication written. On cancellation it
/// writes what is still queued (a restart right after a first contact keeps the address,
/// network-i2) and stops; the after-steps are skipped then.
pub(crate) async fn run_writer(processor: Arc<Processor>, cancel: CancellationToken) {
    loop {
        // Cancellation first: once the token is cancelled every later round writes as a
        // stopping one (no after-steps), whatever wake permit is stored.
        let stopping = tokio::select! {
            biased;
            _ = cancel.cancelled() => true,
            _ = processor.peer_records.wake.notified() => false,
        };
        loop {
            let batch = processor.peer_records.take_batch(BATCH_MAX);
            if batch.is_empty() {
                break;
            }
            let db = processor.db.clone();
            let n = batch.len();
            match tokio::task::spawn_blocking(move || apply_batch(&db, batch)).await {
                Ok(Ok(written)) => {
                    if stopping {
                        continue;
                    }
                    for w in written {
                        let p = processor.clone();
                        tokio::spawn(async move {
                            p.after_peer_authenticated(
                                w.device_id,
                                w.identity_pub,
                                w.device_cert,
                                w.is_new_peer,
                            )
                            .await;
                        });
                    }
                }
                Ok(Err(e)) => {
                    error!(entries = n, err = %e, "peer-record writer: batch write failed, its updates are lost");
                }
                Err(e) => {
                    error!(entries = n, err = %e, "peer-record writer: batch task failed");
                }
            }
        }
        if stopping {
            break;
        }
    }
}
