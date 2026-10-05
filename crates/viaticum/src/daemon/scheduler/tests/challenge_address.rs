// pos-i15 (C-SP К1): the challenge the owner publishes names the device of the placement it
// checks (`device_id`, covered by the owner's master signature) and goes to that device's
// master box. Without this, the holder's siblings reading the same box cannot tell whose
// challenge it is, and the holder's guard (`processor/pos.rs`) refuses every challenge.

use std::collections::HashSet;
use std::time::Duration;

use viaticum_core::mailbox::MailboxAddress;
use viaticum_core::messages::{PosHashChallengeMsg, verify_pos_hash_challenge};
use viaticum_core::types::{IdentityPub, from_cbor_bytes};

use super::issue_support::{SlowPostman, owner_with_due};

/// One block on 8 holders, one issue tick: every stored challenge decodes, carries a valid
/// owner signature, names exactly the placement's device (the pending of the same
/// `challenge_id` is for that device, and the ranges are that placement's) and is addressed
/// to that device's master box; each of the 8 placements gets one. Mutation: publish with
/// `DeviceId([0; 32])` instead of the placement's `holder_id` → reddens.
#[tokio::test]
async fn published_challenge_names_the_placement_device_and_is_signed() {
    let postman = SlowPostman::acking_after(Duration::from_millis(5));
    let owner = owner_with_due(1, 8, 1, postman.clone());

    owner
        .scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let stores = postman.stores();
    // Each challenge goes to several postmen (one store each): 8 challenges, one per placement.
    let ids: HashSet<[u8; 16]> = stores.iter().map(|(_, r)| r.entry.msg_id).collect();
    assert_eq!(ids.len(), 8, "one challenge per placement");
    let placements = owner.db.list_all_placements().unwrap();
    let pending = owner.pending.lock().await;
    let mut addressed = HashSet::new();
    // The key the scheduler signs with (the fixture's `my_master_pub` is a placeholder).
    let owner_master = IdentityPub(owner.scheduler.signing_key.verifying_key().to_bytes());
    for (_, req) in &stores {
        let e = &req.entry;
        let msg: PosHashChallengeMsg = from_cbor_bytes(&e.payload).expect("challenge payload");
        verify_pos_hash_challenge(&msg, &owner_master)
            .expect("signed by the owner's master, device_id included");
        let key = pending.key_of(&e.msg_id).expect("pending");
        let p = pending.get(&key).expect("pending");
        assert_eq!(
            msg.device_id, p.holder_id,
            "addressed to the pending's device"
        );
        let placement = placements
            .iter()
            .find(|pl| pl.source_block_id == msg.source_block_id && pl.holder_id == msg.device_id)
            .unwrap_or_else(|| panic!("no placement of device {}", msg.device_id));
        assert_eq!(
            msg.esi_ranges, placement.esi_ranges,
            "the placement's ranges"
        );
        let master = owner
            .db
            .master_for_holder(&placement.holder_id)
            .unwrap()
            .expect("holder master");
        assert_eq!(
            e.target,
            MailboxAddress::for_master(&master),
            "the holder master's box"
        );
        addressed.insert(msg.device_id);
    }
    assert_eq!(addressed.len(), 8, "every placement's device is challenged");
}
