// W-A (В-0b review, round 2): the offer shadow's `key_before` — the offer's own (owner, block)
// record as the old rule saw it — is read on the REAL offer path, before the reply leaves.
// D-3c builds the shadow job by hand, so it cannot see that read; this test goes through
// `handle_symbol_offer_inner` and lands the owner's transfer through the real receive path
// (`handle_symbol_transfer`'s merge) BETWEEN the reply and the shadow's re-read of HOLDINGS.
//
// How the wedge is made deterministic without any production hook: the shadow runs via
// `spawn_blocking` on the runtime current at the offer. The offer is handled inside a runtime
// with ONE blocking thread, which the test has parked first; the shadow therefore queues
// behind the park. The transfer (its file I/O also uses `spawn_blocking`) runs on a second
// runtime, so it never queues behind the park. Only then is the park released. The shadow
// logs on that pool thread, whose default subscriber is the capture sink (`on_thread_start`).

use std::sync::mpsc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::Symbol;
use viaticum_core::messages::{Message, SymbolTransferMsg, build_symbol_offer};
use viaticum_core::types::{HoldingRecord, HoldingStatus, IdentityPub, Timestamp};

use super::{make_block_id, make_processor_with_quota};
use crate::daemon::four_r_log::tests::capture_dispatch;

/// We hold ESI 0 of (owner, block) and have already sent the owner a DropNotice for it. The
/// owner offers ESIs 0..2 of the same block; the old rule (quota only) accepts. The owner's
/// transfer of ESI 1 is merged into the record (Active, notice kept, 2 symbols) before the
/// shadow re-reads HOLDINGS. The shadow must still judge the record as it was at the decision:
/// a notified block ⇒ `reason=NotifiedBlock` (Р-26). With `key_before` not read on the offer
/// path (`None`), the landed record is removed from the shadow's view, 4R admits on the free
/// path, agrees with the old answer, and no INFO offer line is logged — this test goes red.
#[test]
fn a_transfer_landing_before_the_offer_shadow_reads_still_leaves_the_block_notified() {
    let (sink, dispatch) = capture_dispatch("viaticum::four_r=info");
    // The shadow's runtime: one blocking thread, logging into the sink.
    let shadow_rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .on_thread_start(move || {
            // The sink stays this pool thread's default subscriber for the thread's life.
            std::mem::forget(tracing::dispatcher::set_default(&dispatch));
        })
        .build()
        .unwrap();
    // The processor, its swarm and the transfer's file I/O live on another runtime.
    let io_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let _io_ctx = io_rt.enter();

    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = io_rt.block_on(make_processor_with_quota(db.clone(), &dir, u64::MAX / 2, 0));
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner = IdentityPub(key.verifying_key().to_bytes());
    let blk = make_block_id(0x66);
    db.upsert_holding(&HoldingRecord {
        source_block_id: blk,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 64,
        status: HoldingStatus::Active,
        received_at: Timestamp(1),
        delete_requested_at: None,
        drop_notice_sent_at: Some(Timestamp(2)),
    })
    .unwrap();

    // Park the shadow runtime's only blocking thread.
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let park = shadow_rt.spawn_blocking(move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    started_rx.recv().unwrap();

    // The offer: the old rule answers now; the shadow (slot taken) queues behind the park.
    let reply = {
        let _shadow_ctx = shadow_rt.enter();
        p.handle_symbol_offer_inner(
            owner,
            build_symbol_offer([7; 16], blk, vec![(0, 2)], 0.5, Timestamp::now(), &key),
        )
    };
    assert!(
        matches!(reply, Message::SymbolAccept(_)),
        "premise: the old rule accepts (room)"
    );
    assert_eq!(
        p.shadow_offer_slot.available_permits(),
        0,
        "premise: the shadow was launched and is waiting"
    );

    // The owner's transfer lands through the real receive path: ESI 1 merged into the record.
    io_rt
        .block_on(p.handle_symbol_transfer(
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: blk,
                symbols: vec![Symbol {
                    esi: 1,
                    data: vec![0xAB; 64],
                }],
                timestamp: Timestamp::now(),
            },
        ))
        .unwrap();
    let merged = db.get_holding(&blk, &owner).unwrap().unwrap();
    assert_eq!(
        merged.esi_ranges,
        vec![(0, 2)],
        "premise: the transfer merged"
    );
    assert_eq!(merged.total_bytes, 128);
    assert!(
        merged.drop_notice_sent_at.is_some(),
        "the merge keeps the notice"
    );
    assert_eq!(
        p.shadow_offer_slot.available_permits(),
        0,
        "premise: the shadow has not run before the merge landed"
    );

    // Release the park: the shadow runs now, over HOLDINGS with the merged record.
    release_tx.send(()).unwrap();
    shadow_rt.block_on(park).unwrap();
    let t0 = Instant::now();
    while p.shadow_offer_slot.available_permits() == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "the offer shadow must run and release its slot"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let text = sink.text();
    let line = text
        .lines()
        .find(|l| l.contains("four_r: offer"))
        .unwrap_or_else(|| {
            panic!("no INFO offer-shadow line (4R agreed with the old accept?):\n{text}")
        });
    assert!(
        line.contains("reason=NotifiedBlock") && line.contains("old=accept"),
        "the shadow must see the block as notified at the decision: {line}"
    );
    io_rt.block_on(async move { drop(p) });
}
