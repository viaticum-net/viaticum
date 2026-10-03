//! dr-i8: after a DR `device_to_master` is empty and PEERS (restored from the SS) carry the
//! master of every holder. The PoS challenge is addressed by PEERS; a holder whose master is
//! known nowhere is dropped by the tick's scan before any block is prepared for it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use viaticum_core::mailbox::{MailboxAddress, MailboxClass};

use super::issue_mem::{
    block_at, budgeted, deferred_tick_of, logged, pending_len, settle_until_idle, tick, tick_lines,
};
use super::issue_stall::StallingEncoder;
use super::issue_support::{SlowPostman, owner_with, seed_due};
use super::pos_scale::field;
use super::{holder_master_of, make_identity, seed_holder_peer};
use crate::daemon::scheduler::issue::InFlight;

/// The state after `restore_db_inner` + SS: a PeerRecord with the master, nothing in
/// `device_to_master`. The challenge goes to the box of that master, never to the device-id box.
#[tokio::test]
async fn pos_challenge_after_dr_targets_holder_master_box() {
    let postman = SlowPostman::acking_after(Duration::from_millis(1));
    let owner = owner_with(1, postman.clone(), |db, dir| seed_due(db, dir, 1, 1));
    let holder = make_identity(0x80);
    assert_eq!(owner.db.get_master_for_device(&holder).unwrap(), None);

    owner.scheduler.issue_due_challenges().await.unwrap();

    let stores = postman.stores();
    // One challenge is one store per candidate postman: all of them carry one target.
    let targets: std::collections::HashSet<_> = stores
        .iter()
        .filter(|(_, r)| r.entry.class == MailboxClass::PosChallenge)
        .map(|(_, r)| r.entry.target)
        .collect();
    assert_eq!(targets.len(), 1, "{targets:?}");
    let target = *targets.iter().next().unwrap();
    assert_eq!(
        target,
        MailboxAddress::for_master(&holder_master_of(holder))
    );
    assert_ne!(target, MailboxAddress(holder.0), "never the device-id box");
}

/// A holder with no master anywhere: no entry, no pending, no block loaded or encoded (no memory
/// permit taken), one WARN per period, `no_master` on the tick line. When the master appears the
/// very next tick issues the challenge.
#[tokio::test]
async fn pos_unknown_master_holder_not_due_and_block_not_prepared() {
    let encoder = StallingEncoder::new(0, 0, Duration::ZERO);
    let encodes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&encodes);
    encoder.set_hook(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let (owner, budget) = budgeted(1, 1, Arc::clone(&encoder) as _);
    let holder = make_identity(0x80);
    owner.db.delete_peer(&holder).unwrap();
    let lookups = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&lookups);
    *owner.scheduler.master_lookup_hook.lock().unwrap() = Some(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    let mut in_flight = InFlight::default();
    let buf = logged(async {
        for _ in 0..3 {
            tick(&owner, &mut in_flight).await;
        }
        settle_until_idle(&owner, &mut in_flight, Duration::from_millis(300)).await;
    })
    .await;

    assert_eq!(encodes.load(Ordering::SeqCst), 0, "no block was encoded");
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        0,
        "no preparation reached its lookup"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(
        pending_len(&owner),
        0,
        "no challenge, so no timeout accrues"
    );
    assert!(in_flight.is_idle());
    assert_eq!(deferred_tick_of(&owner, &block_at(0)), None);
    let lines = tick_lines(&buf);
    assert_eq!(lines.len(), 3, "the tick line is printed: {lines:?}");
    for l in &lines {
        assert_eq!(field(l, "no_master"), Some(1), "{l}");
        assert_eq!(field(l, "issued"), Some(0), "{l}");
    }
    assert_eq!(
        buf.text().matches("holder master unknown").count(),
        1,
        "one WARN per holder per period"
    );

    // The master becomes known (a PeerRecord appears): the next tick issues.
    seed_holder_peer(&owner.db, holder);
    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    assert_eq!(pending_len(&owner), 1);
    assert!(encodes.load(Ordering::SeqCst) > 0);
}
