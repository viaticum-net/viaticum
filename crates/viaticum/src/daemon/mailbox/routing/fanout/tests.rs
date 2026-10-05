// mailbox-i60: a publication returns at the needed number of acks; a sleeping postman
// does not hold it; a late ack still records the contact. Virtual time
// (`start_paused`): the seconds are exact.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::time::{Duration, Instant, sleep};
use viaticum_core::db::Db;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry, MailboxRejectReason};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::super::{MailboxNetworkSender, MailboxRouter, PEER_REQUEST_TIMEOUT, PublishVerdict};

/// How one postman answers a store.
#[derive(Clone)]
enum Reply {
    /// Ack after this many seconds.
    Ack(u64),
    /// Refuse after this many seconds.
    Reject(u64, MailboxRejectReason),
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
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let reply = self.plan.lock().unwrap().get(&device).cloned();
        let msg_id = req.entry.msg_id;
        match reply.unwrap_or(Reply::Ack(0)) {
            Reply::Ack(s) => {
                sleep(Duration::from_secs(s)).await;
                Ok(MailboxStoreResponse::Ack { msg_id })
            }
            Reply::Reject(s, reason) => {
                sleep(Duration::from_secs(s)).await;
                Ok(MailboxStoreResponse::Reject { msg_id, reason })
            }
            Reply::Asleep => {
                sleep(Duration::from_secs(600)).await;
                anyhow::bail!("idle connection closed")
            }
        }
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("not used")
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

fn entry(seed: u8) -> MailboxEntry {
    let now = Timestamp::now().0;
    MailboxEntry {
        target: MailboxAddress::for_master(&IdentityPub([seed; 32])),
        msg_id: [seed; 16],
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload: vec![0; 32],
        expires_at: now + 3600,
        stored_at: now,
        sender: None,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn publish_returns_at_need_acks_without_waiting_for_a_sleeping_postman() {
    let (router, _db, devices) =
        router_over(&[Reply::Asleep, Reply::Ack(0), Reply::Ack(0), Reply::Ack(0)]);
    let start = Instant::now();
    let out = router.publish_detailed(entry(1), None, 1).await;
    assert_eq!(
        start.elapsed(),
        Duration::ZERO,
        "no wait for the sleeping postman"
    );
    assert!(!out.acks.is_empty());
    assert!(!out.acks.contains(&devices[0]));
    assert_eq!(out.pending, 1, "the sleeping postman is still pending");

    // The count-only wrapper (PoS, directed messages) behaves the same.
    let start = Instant::now();
    assert!(router.publish(entry(2), None).await.unwrap() >= 1);
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn publish_for_pointer_waits_for_threshold_acks() {
    let replies = [
        Reply::Ack(1),
        Reply::Ack(2),
        Reply::Ack(5),
        Reply::Asleep,
        Reply::Reject(0, MailboxRejectReason::ClockSkew),
    ];
    let (router, _db, _) = router_over(&replies);
    let start = Instant::now();
    let out = router.publish_detailed(entry(3), None, 3).await;
    assert_eq!(
        start.elapsed(),
        Duration::from_secs(5),
        "returns at the third ack"
    );
    assert_eq!(out.acks.len(), 3);
    assert_eq!(out.rejects.len(), 1);
    assert_eq!(out.pending, 1);

    // The same postmen with need = 1: back at the first ack.
    let start = Instant::now();
    let out = router.publish_detailed(entry(4), None, 1).await;
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert_eq!(out.acks.len(), 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn late_ack_after_return_still_updates_avail_and_last_seen() {
    let (router, db, devices) = router_over(&[Reply::Ack(0), Reply::Ack(10)]);
    let late = devices[1];
    let before_secs = Timestamp::now().0;
    let out = router.publish_detailed(entry(5), None, 1).await;
    assert_eq!(out.acks, vec![devices[0]]);
    assert_eq!(out.pending, 1);
    let untouched = db.get_peer(&late).unwrap().unwrap();
    assert_eq!(untouched.last_seen, Timestamp(1_000), "not answered yet");

    sleep(Duration::from_secs(11)).await;
    let rec = db.get_peer(&late).unwrap().unwrap();
    assert!(rec.last_seen.0 >= before_secs, "late ack moves last_seen");
    assert!(rec.avail_ewma > 0.3, "late ack raises avail");
    assert!(rec.last_avail_sample >= before_secs);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn publish_without_need_acks_returns_by_timeout_with_verdict() {
    let (router, _db, _) = router_over(&[
        Reply::Reject(0, MailboxRejectReason::ClockSkew),
        Reply::Reject(3, MailboxRejectReason::ClockSkew),
        Reply::Asleep,
    ]);
    let start = Instant::now();
    let out = router.publish_detailed(entry(6), None, 1).await;
    assert_eq!(
        start.elapsed(),
        PEER_REQUEST_TIMEOUT,
        "never longer than 15 s"
    );
    assert_eq!(out.pending, 1);
    assert_eq!(
        out.verdict(),
        PublishVerdict::AllClockSkew,
        "the verdict of the answers that came"
    );

    let (router, _db, _) = router_over(&[Reply::Asleep, Reply::Asleep]);
    let out = router.publish_detailed(entry(7), None, 1).await;
    assert_eq!((out.pending, out.verdict()), (2, PublishVerdict::NoAck));
}

/// RMW PeerRecord (tech-debt MED, 2026-10-05): a contact recorded while another task
/// writes the same record keeps that task's writes — `record_avail_contact` reads and
/// writes in one transaction. Mutation "get_peer + upsert_peer" → bumps lost.
#[test]
fn avail_contact_keeps_concurrent_writes_to_the_record() {
    use viaticum_core::db::testutil::bump_peer_in_thread;
    let db = test_db();
    let d = gen_device_id();
    db.upsert_peer(&peer(d)).unwrap();
    let start = db.get_peer(&d).unwrap().unwrap().bytes_peer_stores_for_us;
    let bump = bump_peer_in_thread(db.clone(), d, 300);
    for i in 0..300 {
        super::record_avail_contact(&db, d, 1_000 + i);
    }
    bump.join().unwrap();
    let rec = db.get_peer(&d).unwrap().unwrap();
    assert_eq!(rec.bytes_peer_stores_for_us, start + 300, "no bump lost");
    assert_eq!(rec.last_avail_sample, 1_299);
}
