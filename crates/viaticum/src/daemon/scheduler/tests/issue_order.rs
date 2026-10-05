// pos-i7-a, pos-i7-c: the order in which an issue tick serves the due blocks — least
// recently tried first (the later of `last_verified` and the last attempt), so neither a
// block verified long ago nor a block that cannot be served holds the head of every tick.

use std::collections::HashSet;
use std::time::Duration;

use viaticum_core::mailbox::MailboxAddress;
use viaticum_core::messages::PosHashChallengeMsg;
use viaticum_core::pos::ChallengeScheduleEntry;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp, from_cbor_bytes};

use super::issue_support::{SlowPostman, owner_with};
use super::{make_identity, make_placement, seed_holder_peer, seed_retained_pos_block};
use crate::daemon::scheduler::issue::{
    ISSUE_PUBLISH_CONCURRENCY, blocks_least_recently_tried_first,
};

#[test]
fn blocks_least_recently_tried_first_puts_never_tried_then_oldest() {
    let block = |b: u8| SourceBlockId([b; 32]);
    let (h1, h2) = (make_identity(1), make_identity(2));
    let entry = |b: u8, h: DeviceId| ChallengeScheduleEntry {
        holder_id: h,
        source_block_id: block(b),
        cpw: 1,
    };
    // In `due` order: A (300), B (h1 at 50, h2 never), C (100), D (100).
    let due = [
        entry(0xA, h1),
        entry(0xB, h1),
        entry(0xC, h1),
        entry(0xB, h2),
        entry(0xD, h1),
    ];
    let last_tried = |k: &(SourceBlockId, DeviceId)| match (k.0.0[0], k.1 == h2) {
        (0xA, _) => Some(Timestamp(300)),
        (0xB, false) => Some(Timestamp(50)),
        (0xB, true) => None,
        _ => Some(Timestamp(100)),
    };

    let ordered = blocks_least_recently_tried_first(due.iter(), last_tried);

    let order: Vec<u8> = ordered.iter().map(|(b, _)| b.0[0]).collect();
    assert_eq!(
        order,
        vec![0xB, 0xC, 0xD, 0xA],
        "never tried first, then oldest; C and D tie and keep the order of due"
    );
    let b_holders: Vec<DeviceId> = ordered[0].1.iter().map(|e| e.holder_id).collect();
    assert_eq!(b_holders, vec![h1, h2], "a block keeps all its due entries");
}

/// The order reaches the publishes: 20 blocks, `last_verified` the reverse of the order
/// the database lists them in, the listed last never verified. The first challenge
/// published is the never-verified block's, and the first publish wave is the
/// least recently verified blocks — not the database order.
#[tokio::test]
async fn the_tick_publishes_the_least_recently_verified_blocks_first() {
    let holder = make_identity(0x42);
    let postman = SlowPostman::acking_after(Duration::from_millis(1));
    let owner = owner_with(1, postman.clone(), |db, dir| {
        for b in 0..20 {
            let id = seed_retained_pos_block(dir, db, b);
            db.upsert_placement(&make_placement(id, holder)).unwrap();
            seed_holder_peer(db, holder);
        }
    });
    let listed = owner.db.list_all_placements().expect("list");
    let n = listed.len();
    for (i, p) in listed.iter().enumerate() {
        let mut p = p.clone();
        p.last_verified = (i + 1 < n).then(|| Timestamp(1000 + (n - i) as u64));
        owner.db.upsert_placement(&p).unwrap();
    }
    let expected: Vec<SourceBlockId> = listed.iter().rev().map(|p| p.source_block_id).collect();

    owner
        .scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let published: Vec<SourceBlockId> = postman
        .stores()
        .iter()
        .map(|(_, req)| {
            from_cbor_bytes::<PosHashChallengeMsg>(&req.entry.payload)
                .expect("challenge payload")
                .source_block_id
        })
        .collect();
    assert_eq!(published.len(), n, "every block published once");
    assert_eq!(
        published[0], expected[0],
        "the never-verified block is published first"
    );
    let wave = ISSUE_PUBLISH_CONCURRENCY;
    let first_wave: HashSet<_> = published[..wave].iter().collect();
    let oldest: HashSet<_> = expected[..wave].iter().collect();
    assert_eq!(
        first_wave, oldest,
        "the first wave is the least recently verified"
    );
}

/// pos-i7-c: 150 blocks that cannot be served (every store fails after 150 ms) sit at the
/// head (never verified); 5 servable blocks (verified long ago) behind them. A tick at
/// time_scale 900 (its waits end at 760 ms) tries ≈ 5 waves of 9 before its budget ends,
/// so the unservable take ⌈150 / ~45⌉ ≈ 4 ticks, fewer per tick on a loaded machine; the
/// servable are issued within 10. Ordered by `last_verified` alone, every tick would
/// retry the same unservable head (≈ 45 < 150) and never reach them.
#[tokio::test]
async fn unservable_blocks_at_the_head_do_not_starve_the_rest() {
    const UNSERVABLE: u8 = 150;
    const SERVABLE: u8 = 5;
    let bad = make_identity(0xBA);
    let good = make_identity(0x60);
    let bad_box = MailboxAddress::for_master(&IdentityPub(bad.0));
    let postman = SlowPostman::new(move |req| {
        if req.entry.target == bad_box {
            (Duration::from_millis(150), false)
        } else {
            (Duration::from_millis(5), true)
        }
    });
    let owner = owner_with(900, postman, |db, dir| {
        for b in 0..UNSERVABLE {
            let id = seed_retained_pos_block(dir, db, b);
            db.upsert_placement(&make_placement(id, bad)).unwrap();
            seed_holder_peer(db, bad);
        }
        for b in UNSERVABLE..UNSERVABLE + SERVABLE {
            let id = seed_retained_pos_block(dir, db, b);
            let mut p = make_placement(id, good);
            p.last_verified = Some(Timestamp(1));
            db.upsert_placement(&p).unwrap();
            seed_holder_peer(db, good);
        }
    });

    let mut ticks = 0;
    loop {
        ticks += 1;
        owner
            .scheduler
            .issue_due_challenges()
            .await
            .expect("issue_due_challenges");
        let issued_good = owner
            .pending
            .lock()
            .await
            .keys()
            .filter(|k| k.1 == good)
            .count();
        if issued_good == usize::from(SERVABLE) {
            break;
        }
        assert!(
            ticks < 10,
            "after {ticks} ticks {issued_good} of {SERVABLE} servable blocks issued: the \
             unservable head starves them"
        );
    }
}
