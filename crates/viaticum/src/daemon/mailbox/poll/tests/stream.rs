// mailbox-i63: `poll_once` handles each postman's answer as it arrives — a sleeping
// postman does not delay the records of the others. mailbox-i69: the per-poll dedup
// merges only identical bytes, so a forgery from the first postman to answer does not
// hide the honest record a later postman brings. Virtual time (`start_paused`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep};
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
    PosHashResponseMsg, to_cbor,
};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::{NoAnswerHandler, gen_device_id, make_entry, make_identity, pending_for, response_to};
use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::pos_memo::{PollCounts, PosPollState};
use crate::daemon::processor::{
    DeleteMailboxHandler, ProcessorDropHandler, ProcessorRevocationHandler,
    RevocationMailboxHandler,
};
use crate::daemon::repair::RepairTrigger;

/// How one postman answers a fetch.
#[derive(Clone)]
enum Reply {
    /// These records after this many seconds.
    Answer(u64, Vec<MailboxEntry>),
    /// A half-open connection of a sleeping laptop: no answer for 10 minutes (the
    /// router gives up after 15 s).
    Asleep,
}

/// Postmen answering fetches after planned virtual delays; stores are acked at once.
#[derive(Default)]
struct Planned {
    plan: Mutex<HashMap<DeviceId, Reply>>,
}

#[async_trait::async_trait]
impl MailboxNetworkSender for Planned {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        Ok(MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
        })
    }

    async fn send_fetch(
        &self,
        device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        let reply = self.plan.lock().unwrap().get(&device).cloned();
        match reply.unwrap_or(Reply::Asleep) {
            Reply::Answer(s, entries) => {
                sleep(Duration::from_secs(s)).await;
                Ok(MailboxFetchResponse {
                    v: 1,
                    entries,
                    served_msg_ids: vec![],
                })
            }
            Reply::Asleep => {
                sleep(Duration::from_secs(600)).await;
                anyhow::bail!("idle connection closed")
            }
        }
    }
}

/// Records every DeleteRequest the poll dispatches: when (virtual time) and its payload.
#[derive(Default)]
struct RecordingDelete {
    calls: Mutex<Vec<(Instant, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl DeleteMailboxHandler for RecordingDelete {
    async fn handle_delete_request(
        &self,
        _from: IdentityPub,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.calls.lock().unwrap().push((Instant::now(), payload));
        Ok(())
    }
}

fn peer(device: DeviceId) -> PeerRecord {
    PeerRecord {
        device_id: device,
        master_identity: IdentityPub(device.0),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    }
}

/// The poll of `my_master`'s box over postmen answering as `replies` say.
struct Fixture {
    db: Db,
    router: Arc<MailboxRouter>,
    delete: Arc<RecordingDelete>,
    my_master: IdentityPub,
}

impl Fixture {
    fn new(replies: &[Reply]) -> Self {
        let db = Db::open_in_memory().expect("db");
        let sender = Arc::new(Planned::default());
        for r in replies {
            let d = gen_device_id();
            db.upsert_peer(&peer(d)).expect("upsert peer");
            sender.plan.lock().unwrap().insert(d, r.clone());
        }
        let router = Arc::new(MailboxRouter::with_sender(
            sender as Arc<dyn MailboxNetworkSender>,
            db.clone(),
        ));
        Fixture {
            db,
            router,
            delete: Arc::new(RecordingDelete::default()),
            my_master: my_master(),
        }
    }

    /// One `poll_once` at wall-clock now.
    async fn poll(
        &self,
        pos: &mut PosPollState,
        pos_tx: &mpsc::Sender<PosHashResponseMsg>,
    ) -> PollCounts {
        let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
        let challenge_handler: Arc<dyn super::super::PosMailboxChallengeHandler> =
            Arc::new(NoAnswerHandler);
        let drop_handler: Arc<dyn super::super::DropNoticeHandler> =
            Arc::new(ProcessorDropHandler::new(self.db.clone(), repair_tx));
        let delete_handler: Arc<dyn DeleteMailboxHandler> =
            Arc::clone(&self.delete) as Arc<dyn DeleteMailboxHandler>;
        let revocation_handler: Arc<dyn RevocationMailboxHandler> =
            Arc::new(ProcessorRevocationHandler::new(self.db.clone()));
        super::super::poll_once(
            &self.router,
            pos_tx,
            pos,
            &challenge_handler,
            &drop_handler,
            &delete_handler,
            &revocation_handler,
            &self.my_master,
            1,
            Timestamp::now().0,
        )
        .await
    }

    fn delete_payloads(&self) -> Vec<Vec<u8>> {
        let mut p: Vec<Vec<u8>> = self
            .delete
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, p)| p.clone())
            .collect();
        p.sort();
        p
    }
}

/// The master box this node polls.
fn my_master() -> IdentityPub {
    make_identity(0xAA)
}

/// A DeleteRequest to us, `msg_id` and `payload` as given.
fn delete_entry(msg_id: u8, payload: &[u8]) -> MailboxEntry {
    MailboxEntry {
        msg_id: [msg_id; 16],
        ..make_entry(MailboxClass::DeleteRequest, my_master(), payload.to_vec())
    }
}

/// mailbox-i63: one postman answers at once, another sleeps — the record of the quick one
/// is handled at once, not after the sleeper's 15 s.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn poll_dispatches_entries_before_a_sleeping_postman_answers() {
    let f = Fixture::new(&[
        Reply::Asleep,
        Reply::Answer(0, vec![delete_entry(1, b"delete")]),
    ]);
    let (pos_tx, _pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let mut pos = PosPollState::new(pending_for(&[]), 1);

    let start = Instant::now();
    f.poll(&mut pos, &pos_tx).await;

    let calls = f.delete.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "the quick postman's record is handled");
    assert!(
        calls[0].0 - start < Duration::from_secs(1),
        "handled at {:?}, not after the sleeper",
        calls[0].0 - start
    );
    assert!(
        start.elapsed() >= Duration::from_secs(15),
        "the sleeper was really asked (the poll ends when it times out)"
    );
}

/// mailbox-i69 under streaming: two postmen bring the same msg_id with different payloads
/// — both reach the handler (it tells them apart by the signature).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn poll_keeps_both_copies_with_one_msg_id_and_different_payloads() {
    let f = Fixture::new(&[
        Reply::Answer(0, vec![delete_entry(1, b"forged")]),
        Reply::Answer(1, vec![delete_entry(1, b"honest")]),
    ]);
    let (pos_tx, _pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let mut pos = PosPollState::new(pending_for(&[]), 1);

    f.poll(&mut pos, &pos_tx).await;

    assert_eq!(
        f.delete_payloads(),
        vec![b"forged".to_vec(), b"honest".to_vec()]
    );
}

/// Copies of the same bytes from several postmen (and twice in one answer, and with a
/// later `stored_at`) are handled once.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn poll_collapses_byte_identical_copies() {
    let e = delete_entry(1, b"delete");
    let restored = MailboxEntry {
        stored_at: e.stored_at + 5,
        ..e.clone()
    };
    let f = Fixture::new(&[
        Reply::Answer(0, vec![e.clone(), e.clone()]),
        Reply::Answer(1, vec![restored]),
        Reply::Answer(2, vec![e]),
    ]);
    let (pos_tx, _pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let mut pos = PosPollState::new(pending_for(&[]), 1);

    f.poll(&mut pos, &pos_tx).await;

    assert_eq!(f.delete_payloads(), vec![b"delete".to_vec()]);
}

/// mailbox-i69 + i63: the first postman to answer brings a forged PoS response under the
/// honest msg_id, a later one the honest response. The honest one still reaches the
/// scheduler (a first-wins dedup by msg_id would have hidden it).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stream_poll_forgery_from_first_postman_does_not_hide_later_honest_record() {
    let cid = [7u8; 16];
    let response_entry = |msg: &PosHashResponseMsg| MailboxEntry {
        msg_id: [5u8; 16],
        ..make_entry(
            MailboxClass::PosResponse,
            my_master(),
            to_cbor(msg).expect("encode"),
        )
    };
    let forged = PosHashResponseMsg {
        chain_hash: [0xEE; 32],
        sig: [0xEE; 64],
        ..response_to(cid)
    };
    let honest = PosHashResponseMsg {
        sig: [0x11; 64],
        ..response_to(cid)
    };
    let f = Fixture::new(&[
        Reply::Answer(0, vec![response_entry(&forged)]),
        Reply::Answer(2, vec![response_entry(&honest)]),
    ]);
    let (pos_tx, mut pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let mut pos = PosPollState::new(pending_for(&[cid]), 1);

    let counts = f.poll(&mut pos, &pos_tx).await;

    let mut sigs = vec![];
    while let Ok(r) = pos_rx.try_recv() {
        sigs.push(r.sig);
    }
    assert!(
        sigs.contains(&honest.sig),
        "the honest response reaches the scheduler (got {} responses, counts {counts:?})",
        sigs.len()
    );
}
