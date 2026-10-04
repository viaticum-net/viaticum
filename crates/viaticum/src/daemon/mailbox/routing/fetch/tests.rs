// mailbox-i63: a poll hands over each postman's answer as it arrives; a sleeping
// postman holds only its own answer; a late answer still records the contact.
// mailbox-i69: `PollSeen` lets through only records not seen earlier in the poll.
// Virtual time (`start_paused`): the seconds are exact.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::time::{Duration, Instant, sleep};
use viaticum_core::db::Db;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::super::{MailboxNetworkSender, MailboxRouter, PEER_REQUEST_TIMEOUT};
use super::{PollSeen, poll_entry_key};

/// How one postman answers a fetch.
#[derive(Clone)]
enum Reply {
    /// These records after this many seconds.
    Answer(u64, Vec<MailboxEntry>),
    /// A half-open connection of a sleeping laptop: no answer for 10 minutes.
    Asleep,
}

/// Postmen answering after planned virtual delays.
#[derive(Default)]
struct Planned {
    plan: Mutex<HashMap<DeviceId, Reply>>,
}

#[async_trait]
impl MailboxNetworkSender for Planned {
    async fn send_store(
        &self,
        _device: DeviceId,
        _req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        anyhow::bail!("not used")
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

fn gen_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let ed = Keypair::generate_ed25519().try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

fn peer(device: DeviceId) -> PeerRecord {
    PeerRecord {
        device_id: device,
        master_identity: IdentityPub(device.0),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(1_000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.3,
        last_avail_sample: 0,
    }
}

/// A router over postmen answering as `replies` say (one postman per reply).
fn router_over(replies: &[Reply]) -> (MailboxRouter, Db, Vec<DeviceId>) {
    let db = test_db();
    let sender = Arc::new(Planned::default());
    let mut devices = vec![];
    for r in replies {
        let d = gen_device_id();
        db.upsert_peer(&peer(d)).unwrap();
        sender.plan.lock().unwrap().insert(d, r.clone());
        devices.push(d);
    }
    let router = MailboxRouter::with_sender(sender as Arc<dyn MailboxNetworkSender>, db.clone());
    (router, db, devices)
}

fn my_box() -> MailboxAddress {
    MailboxAddress::for_master(&IdentityPub([0xAA; 32]))
}

/// A live DeleteRequest record `msg_id` with `payload`.
fn entry(msg_id: u8, payload: &[u8]) -> MailboxEntry {
    let now = Timestamp::now().0;
    MailboxEntry {
        target: my_box(),
        msg_id: [msg_id; 16],
        class: MailboxClass::DeleteRequest,
        payload_version: 1,
        payload: payload.to_vec(),
        expires_at: now + 3600,
        stored_at: now,
        sender: None,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn poll_stream_hands_over_an_answer_without_waiting_for_a_sleeping_postman() {
    let (router, _db, devices) =
        router_over(&[Reply::Asleep, Reply::Answer(0, vec![entry(1, b"a")])]);
    let start = Instant::now();
    let mut rx = router.poll_stream(&my_box(), None, None);

    let (postman, entries) = rx.recv().await.expect("the quick answer");
    assert_eq!(start.elapsed(), Duration::ZERO, "no wait for the sleeper");
    assert_eq!(postman, devices[1]);
    assert_eq!(entries, vec![entry(1, b"a")]);

    assert!(rx.recv().await.is_none(), "the sleeper sends nothing");
    assert_eq!(
        start.elapsed(),
        PEER_REQUEST_TIMEOUT,
        "the stream closes when the sleeper times out"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn poll_late_answer_updates_contact() {
    let (router, db, devices) = router_over(&[
        Reply::Answer(0, vec![entry(1, b"a")]),
        Reply::Answer(10, vec![]),
    ]);
    let late = devices[1];
    let before_secs = Timestamp::now().0;
    let mut rx = router.poll_stream(&my_box(), None, None);
    let (postman, _) = rx.recv().await.expect("the quick answer");
    assert_eq!(postman, devices[0]);
    // The reader stops reading after the first answer.
    drop(rx);
    let untouched = db.get_peer(&late).unwrap().unwrap();
    assert_eq!(untouched.last_seen, Timestamp(1_000), "not answered yet");

    sleep(Duration::from_secs(11)).await;
    let rec = db.get_peer(&late).unwrap().unwrap();
    assert!(
        rec.last_seen.0 >= before_secs,
        "late answer moves last_seen"
    );
    assert!(rec.avail_ewma > 0.3, "late answer raises avail");
    assert!(rec.last_avail_sample >= before_secs);
}

#[test]
fn poll_seen_skips_records_seen_earlier_in_the_poll_and_expired_ones() {
    let now = Timestamp::now().0;
    let mut seen = PollSeen::new(now);
    let honest = entry(1, b"honest");
    let forged = entry(1, b"forged");
    let other_class = MailboxEntry {
        class: MailboxClass::PosResponse,
        ..honest.clone()
    };
    let expired = MailboxEntry {
        expires_at: now,
        ..entry(2, b"old")
    };

    assert_eq!(
        seen.admit(vec![forged.clone(), expired]),
        vec![forged.clone()]
    );
    let later_copy = MailboxEntry {
        stored_at: honest.stored_at + 5,
        ..forged.clone()
    };
    assert_eq!(
        seen.admit(vec![
            later_copy,
            honest.clone(),
            honest.clone(),
            other_class.clone()
        ]),
        vec![honest.clone(), other_class.clone()],
        "a copy of the same bytes is skipped, the same msg_id with other bytes or class is not"
    );
    assert_ne!(poll_entry_key(&honest), poll_entry_key(&forged));
    assert_ne!(poll_entry_key(&honest), poll_entry_key(&other_class));
}

/// mailbox-i69: the unsigned `sender` decides where a holder answers a PosChallenge;
/// a copy of the honest payload under another `sender` is another record.
#[test]
fn same_payload_under_another_sender_is_another_record() {
    use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
    use viaticum_core::types::IdentityPub;
    let base = MailboxEntry {
        target: MailboxAddress::for_master(&IdentityPub([1; 32])),
        msg_id: [7; 16],
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload: b"signed challenge".to_vec(),
        expires_at: 10_000,
        stored_at: 100,
        sender: Some(IdentityPub([2; 32])),
    };
    let mut forged = base.clone();
    forged.sender = Some(IdentityPub([9; 32]));
    assert_ne!(poll_entry_key(&base), poll_entry_key(&forged));
}
