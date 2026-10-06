// restore-i43, daemon side: the "connected" set a round asks first is the swarm's
// authenticated devices. Two real swarms on loopback (like network/swarm_lru_tests.rs).
// Child of `symbol_fetch/tests.rs`.

use std::sync::Arc;

use viaticum_core::db::Db;

use super::super::{SwarmSymbols, SymbolSource};
use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::network::swarm_test_helpers::{
    cached_config, get_listen_addr, make_swarm_config, wait_auth,
};

/// Mutation "`authenticated_devices` returns an empty set" → the first assertion
/// reddens (the order in the daemon would fall back to the shuffle alone).
#[tokio::test]
async fn connected_holders_lists_an_authenticated_peer_and_drops_it_after_disconnect() {
    let (a, _events_a) = SwarmHandle::start(cached_config(131, 48, 10_000))
        .await
        .expect("swarm A");
    let a = Arc::new(a);
    let (b, _events_b) = SwarmHandle::start(make_swarm_config(132))
        .await
        .expect("swarm B");
    let addr_b = get_listen_addr(&b).await;
    a.dial(b.peer_id, addr_b).await.expect("dial");
    wait_auth(&a, b.device_id, true).await;
    let source = SwarmSymbols::new(a.clone(), Db::open_in_memory().unwrap());

    assert!(
        source.connected_holders().await.contains(&b.device_id),
        "an authenticated peer is a connected holder"
    );
    assert!(
        a.as_ref().connected_holders().await.contains(&b.device_id),
        "the bare SwarmHandle (DR) reports the same"
    );

    assert!(a.test_evict(b.peer_id).await, "the connection was open");
    wait_auth(&a, b.device_id, false).await;

    assert!(
        !source.connected_holders().await.contains(&b.device_id),
        "after the disconnect it is not"
    );
}
