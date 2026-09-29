// Shared set-up of the issue-tick tests (pos-i7-a, pos-i7-c): an owner with due
// placements and a postman whose stores take a chosen time and answer Ack or fail.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::DeviceId;

use super::{
    TEST_EPOCH_KEY, dummy_master_pub, make_identity, make_peer_record, make_pending_challenges,
    make_placement, make_test_encoder, seed_retained_pos_block,
};
use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::{PendingChallenges, Scheduler, SchedulerConfig};

pub(super) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// How the postman treats one store: after how long, and whether it acks (else fails).
type Behave = Box<dyn Fn(&MailboxStoreRequest) -> (Duration, bool) + Send + Sync>;

/// A postman that answers every store after a delay, recording each request (in arrival
/// order) with the unix second it arrived.
pub(super) struct SlowPostman {
    behave: Behave,
    stores: std::sync::Mutex<Vec<(u64, MailboxStoreRequest)>>,
}

impl SlowPostman {
    pub(super) fn new(
        behave: impl Fn(&MailboxStoreRequest) -> (Duration, bool) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(SlowPostman {
            behave: Box::new(behave),
            stores: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Acks every store after `delay`.
    pub(super) fn acking_after(delay: Duration) -> Arc<Self> {
        Self::new(move |_| (delay, true))
    }

    /// Acks every store after 20-50 ms, fixed per challenge (a LAN postman under load).
    pub(super) fn lan() -> Arc<Self> {
        Self::new(|req| {
            (
                Duration::from_millis(20 + u64::from(req.entry.msg_id[0]) % 31),
                true,
            )
        })
    }

    pub(super) fn store_count(&self) -> usize {
        self.stores.lock().unwrap().len()
    }

    pub(super) fn stores(&self) -> Vec<(u64, MailboxStoreRequest)> {
        self.stores.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl MailboxNetworkSender for SlowPostman {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let msg_id = req.entry.msg_id;
        let (delay, ack) = (self.behave)(&req);
        self.stores.lock().unwrap().push((unix_secs(), req));
        tokio::time::sleep(delay).await;
        if !ack {
            anyhow::bail!("slow postman: store refused");
        }
        Ok(MailboxStoreResponse::Ack { msg_id })
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("slow postman: fetch not used")
    }
}

pub(super) struct Owner {
    pub(super) scheduler: Scheduler,
    pub(super) pending: PendingChallenges,
    pub(super) db: Db,
    _data_dir: tempfile::TempDir,
}

/// An owner whose placements `seed` writes (it gets the db and the data dir for the
/// retained blocks), publishing through `postman`, its one known peer (a real Ed25519
/// id). Holders are no peers (medium trust): one store per publish.
pub(super) fn owner_with(
    time_scale: u64,
    postman: Arc<SlowPostman>,
    seed: impl FnOnce(&Db, &Path),
) -> Owner {
    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();
    let postman_key = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    db.upsert_peer(&make_peer_record(DeviceId(
        postman_key.verifying_key().to_bytes(),
    )))
    .unwrap();
    seed(&db, data_dir.path());
    let pending = make_pending_challenges();
    let router = Arc::new(MailboxRouter::with_sender(
        postman as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = Scheduler::new(
        db.clone(),
        SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        },
        repair_tx,
        pending.clone(),
        router,
        dummy_master_pub(),
        ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );
    Owner {
        scheduler,
        pending,
        db,
        _data_dir: data_dir,
    }
}

/// An owner with `blocks` blocks × `holders` holders, every placement due (never verified).
pub(super) fn owner_with_due(
    blocks: u8,
    holders: u8,
    time_scale: u64,
    postman: Arc<SlowPostman>,
) -> Owner {
    owner_with(time_scale, postman, |db, dir| {
        let holder_ids: Vec<DeviceId> = (0..holders).map(|h| make_identity(0x80 + h)).collect();
        for b in 0..blocks {
            let block_id = seed_retained_pos_block(dir, db, b);
            for h in &holder_ids {
                db.upsert_placement(&make_placement(block_id, *h)).unwrap();
            }
        }
    })
}
