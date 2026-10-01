// Unit tests for the address book (network-i14): which stored addresses are
// routes to a peer, and which PeerRecords count as known.

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::{dialable_addrs, is_known};
use crate::daemon::network::swarm::device_id_to_peer_id;
use crate::daemon::network::swarm_test_helpers::make_signing_key;

fn device(seed: u8) -> DeviceId {
    DeviceId(make_signing_key(seed).verifying_key().to_bytes())
}

fn record(device_id: DeviceId, master: IdentityPub, addrs: Vec<String>) -> PeerRecord {
    let now = Timestamp::now();
    PeerRecord {
        device_id,
        master_identity: master,
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs,
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

#[test]
fn dialable_addrs_strips_own_suffix_and_dedups() {
    let d = device(11);
    let peer = device_id_to_peer_id(&d).unwrap();
    let bare: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    let with_suffix = bare.clone().with(Protocol::P2p(peer));
    let other: Multiaddr = "/ip4/10.0.0.2/tcp/4001".parse().unwrap();
    let stored = vec![with_suffix.to_string(), bare.to_string(), other.to_string()];
    let mut skipped = 0;
    let (got_peer, addrs) = dialable_addrs(&d, &stored, &mut skipped).expect("dialable");
    assert_eq!(got_peer, peer);
    assert_eq!(
        addrs,
        vec![bare, other],
        "suffix stripped, duplicate dropped, order kept"
    );
    assert_eq!(skipped, 0);
}

#[test]
fn dialable_addrs_skips_unparseable_and_foreign_suffix() {
    let d = device(12);
    let stranger = device_id_to_peer_id(&device(13)).unwrap();
    let foreign: Multiaddr = "/ip4/127.0.0.1/tcp/4001"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(stranger));
    let stored = vec!["not-a-multiaddr".to_string(), foreign.to_string()];
    let mut skipped = 0;
    assert!(dialable_addrs(&d, &stored, &mut skipped).is_none());
    assert_eq!(skipped, 2, "both dropped addresses are counted");
}

#[test]
fn dialable_addrs_is_none_without_addrs() {
    let mut skipped = 0;
    assert!(dialable_addrs(&device(14), &[], &mut skipped).is_none());
    assert_eq!(skipped, 0);
}

#[test]
fn known_excludes_own_master_own_device_and_addrless_records() {
    let own_device = device(20);
    let own_master = IdentityPub([0xAA; 32]);
    let other_master = IdentityPub([0xBB; 32]);
    let addr = vec!["/ip4/127.0.0.1/tcp/4001".to_string()];

    let stranger = record(device(21), other_master, addr.clone());
    assert!(is_known(&stranger, &own_master, &own_device));

    let own = record(own_device, other_master, addr.clone());
    assert!(!is_known(&own, &own_master, &own_device), "own device");

    let sibling = record(device(22), own_master, addr.clone());
    assert!(
        !is_known(&sibling, &own_master, &own_device),
        "sibling of our master"
    );

    let addrless = record(device(23), other_master, vec![]);
    assert!(!is_known(&addrless, &own_master, &own_device), "no address");

    let only_foreign = record(
        device(24),
        other_master,
        vec![format!(
            "/ip4/127.0.0.1/tcp/4001/p2p/{}",
            device_id_to_peer_id(&device(25)).unwrap()
        )],
    );
    assert!(
        !is_known(&only_foreign, &own_master, &own_device),
        "an address naming another peer is not a route"
    );
}
