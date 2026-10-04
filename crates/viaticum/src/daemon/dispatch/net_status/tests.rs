// Unit tests for the network-knowledge status helpers (network-i14, C-DK Р-7)
// and the net-probe device lookup (C-DK Р-16).

use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::{devices_hex8_sorted, known_devices_hex8, unaddressed_devices_hex8};
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
fn devices_hex8_are_first_8_bytes_sorted() {
    let a = DeviceId([0xB0; 32]);
    let b = DeviceId([0x0A; 32]);
    assert_eq!(
        devices_hex8_sorted([&a, &b]),
        vec![
            "0a0a0a0a0a0a0a0a".to_string(),
            "b0b0b0b0b0b0b0b0".to_string()
        ]
    );
    assert!(devices_hex8_sorted(std::iter::empty()).is_empty());
}

#[test]
fn known_devices_lists_only_other_masters_with_a_dialable_addr() {
    let own_device = device(30);
    let own_master = IdentityPub([0x11; 32]);
    let other = IdentityPub([0x22; 32]);
    let addr = vec!["/ip4/127.0.0.1/tcp/4001".to_string()];
    let known_a = device(31);
    let known_b = device(32);
    let peers = vec![
        record(known_a, other, addr.clone()),
        record(own_device, other, addr.clone()),
        record(device(33), own_master, addr.clone()),
        record(device(34), other, vec![]),
        record(known_b, IdentityPub([0x33; 32]), addr),
    ];
    let got = known_devices_hex8(&peers, &own_master, &own_device);
    assert_eq!(got, devices_hex8_sorted([&known_a, &known_b]));
}

#[test]
fn unaddressed_devices_are_other_masters_without_a_dialable_addr() {
    let own_device = device(40);
    let own_master = IdentityPub([0x11; 32]);
    let other = IdentityPub([0x22; 32]);
    let addr = vec!["/ip4/127.0.0.1/tcp/4001".to_string()];
    let bare_a = device(41);
    let bare_b = device(42);
    let peers = vec![
        record(device(43), other, addr), // known
        record(bare_a, other, vec![]),   // no address
        record(
            bare_b,
            IdentityPub([0x33; 32]),
            vec!["not a multiaddr".to_string()],
        ),
        record(own_device, other, vec![]),      // own device
        record(device(44), own_master, vec![]), // a sibling
    ];
    let got = unaddressed_devices_hex8(&peers, &own_master, &own_device);
    assert_eq!(got, devices_hex8_sorted([&bare_a, &bare_b]));
    let known = known_devices_hex8(&peers, &own_master, &own_device);
    assert!(
        got.iter().all(|h| !known.contains(h)),
        "known and unaddressed never overlap"
    );
}

#[cfg(feature = "e2e-tools")]
#[test]
fn resolve_device_hex_finds_unique_prefix_and_refuses_the_rest() {
    use super::e2e::resolve_device_hex;
    use viaticum_core::types::hex_encode;

    let master = IdentityPub([0x22; 32]);
    let a = DeviceId([0xAB; 32]);
    let b = DeviceId([0xCD; 32]);
    let peers = vec![record(a, master, vec![]), record(b, master, vec![])];
    let hex_a = hex_encode(&a.0);

    assert_eq!(resolve_device_hex(&peers, &hex_a[..16]), Ok(a));
    assert_eq!(resolve_device_hex(&peers, &hex_a.to_uppercase()), Ok(a));
    assert!(resolve_device_hex(&peers, "ef").is_err(), "too short");
    assert!(
        resolve_device_hex(&peers, "efefefefefefefef").is_err(),
        "unknown"
    );
    assert!(
        resolve_device_hex(&peers, "zzzzzzzzzzzzzzzz").is_err(),
        "not hex"
    );

    let twin = DeviceId({
        let mut t = [0xAB; 32];
        t[31] = 0;
        t
    });
    let peers = vec![record(a, master, vec![]), record(twin, master, vec![])];
    assert!(
        resolve_device_hex(&peers, &hex_a[..16]).is_err(),
        "a prefix of two peers is ambiguous"
    );
}
