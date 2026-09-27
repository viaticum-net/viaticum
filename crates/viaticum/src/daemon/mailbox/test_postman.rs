// Test support (cfg(test) only): an in-process postman network and a deterministic
// "not in the candidate set" routing view.
//
// `InProcessPostmanNet` implements `MailboxNetworkSender` on top of the REAL postman
// handlers (`handle_mailbox_store` / `handle_mailbox_fetch`) with one real redb per
// postman, so router-level tests exercise the actual wire rules (write authorization,
// clock rule, pointer budget, proof-gated reads) instead of a mock that acks anything.
// The requester identity (master + device) is what the Noise-authenticated connection
// would give the postman; tests set it explicitly.

use std::collections::HashMap;

use async_trait::async_trait;
use libp2p::PeerId;
use viaticum_core::db::Db;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::MailboxAddress;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::mailbox::routing::MailboxNetworkSender;
use crate::daemon::network::swarm::device_id_to_peer_id;
use crate::daemon::processor::mailbox::{handle_mailbox_fetch, handle_mailbox_store};

/// A routing view in which `me` has exactly `closer` known peers strictly closer
/// to `target` than itself. Deterministic: `closer + 1` random peers are ranked by
/// XOR distance and the farthest one is `me`, so no rejection sampling and no
/// "gave up after N attempts" branch that silently changes the outcome.
pub(crate) fn view_with_closer_peers(
    target: &MailboxAddress,
    closer: usize,
) -> (PeerId, KademliaRoutingView) {
    let target_key = KademliaRoutingView::target_key(target);
    let mut peers: Vec<PeerId> = (0..=closer).map(|_| PeerId::random()).collect();
    peers.sort_by_key(|p| {
        KademliaRoutingView::xor_distance(&target_key, &KademliaRoutingView::peer_key(p))
    });
    let me = *peers.last().expect("closer + 1 >= 1 peers");
    (me, KademliaRoutingView::new(peers))
}

/// One in-process postman: its own redb and peer id.
pub(crate) struct Postman {
    pub db: Db,
    pub peer_id: PeerId,
}

/// In-process network of postmen reachable by device id.
pub(crate) struct InProcessPostmanNet {
    postmen: HashMap<DeviceId, Postman>,
    /// (master, device) the postmen see as the authenticated requester.
    requester: (IdentityPub, DeviceId),
}

impl InProcessPostmanNet {
    /// Postmen for the given devices (each a real Ed25519 key, so the router can
    /// derive their PeerIds), each with a fresh redb.
    pub(crate) fn new(
        devices: &[DeviceId],
        requester_master: IdentityPub,
        requester_device: DeviceId,
    ) -> Self {
        let postmen = devices
            .iter()
            .map(|d| {
                let peer_id = device_id_to_peer_id(d).expect("postman device is an Ed25519 key");
                (
                    *d,
                    Postman {
                        db: test_db(),
                        peer_id,
                    },
                )
            })
            .collect();
        InProcessPostmanNet {
            postmen,
            requester: (requester_master, requester_device),
        }
    }

    pub(crate) fn postman(&self, device: &DeviceId) -> &Postman {
        &self.postmen[device]
    }
}

#[async_trait]
impl MailboxNetworkSender for InProcessPostmanNet {
    async fn send_store(
        &self,
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let p = self
            .postmen
            .get(&device)
            .ok_or_else(|| anyhow::anyhow!("no postman {device}"))?;
        // Each postman is its own only known peer: always in the candidate set.
        let view = KademliaRoutingView::new(vec![p.peer_id]);
        Ok(handle_mailbox_store(
            &p.db,
            &view,
            &p.peer_id,
            req,
            Timestamp::now().0,
        ))
    }

    async fn send_fetch(
        &self,
        device: DeviceId,
        req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        let p = self
            .postmen
            .get(&device)
            .ok_or_else(|| anyhow::anyhow!("no postman {device}"))?;
        let (master, requester_device) = self.requester;
        Ok(handle_mailbox_fetch(
            &p.db,
            req,
            master,
            requester_device,
            Timestamp::now().0,
        ))
    }
}
