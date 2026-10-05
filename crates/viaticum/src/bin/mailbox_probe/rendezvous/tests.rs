use viaticum::daemon::identity::parse_mnemonic;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys};
use viaticum_core::types::hex_encode;

use super::rendezvous_json;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

#[test]
fn rendezvous_json_matches_the_daemon_derivation() {
    let lineage = [0x4C; 16];
    let v = rendezvous_json(PHRASE, Some(lineage), Some("b"), &[]).unwrap();
    let rv = RendezvousKeys::derive(&parse_mnemonic(PHRASE).unwrap().to_seed(""));
    assert_eq!(v["address"], hex_encode(&rv.address.0));
    assert_eq!(v["address_short"], rv.address.to_string());
    assert_eq!(v["address_short"].as_str().unwrap().len(), 16);
    let a = hex_encode(&rv.pointer_slot(&lineage, PointerPlace::A));
    let b = hex_encode(&rv.pointer_slot(&lineage, PointerPlace::B));
    assert_eq!(v["slot_a"], a);
    assert_eq!(v["slot_b"], b);
    assert_eq!(v["slot"], b);
    assert_ne!(a, b);
}

#[test]
fn rendezvous_json_without_lineage_has_only_the_address() {
    let v = rendezvous_json(PHRASE, None, None, &[]).unwrap();
    assert!(v.get("slot_a").is_none());
    assert!(rendezvous_json(PHRASE, None, Some("a"), &[]).is_err());
    assert!(rendezvous_json("not a phrase", None, None, &[]).is_err());
}

/// dr-i63: `--rank` orders devices by the Kademlia metric to the box, as the daemon's
/// candidate ranking does.
#[test]
fn rank_orders_devices_by_kademlia_distance_to_the_box() {
    use viaticum::daemon::mailbox::candidate::KademliaRoutingView;
    use viaticum::daemon::network::swarm::device_id_to_peer_id;
    use viaticum_core::types::DeviceId;
    let devices: Vec<DeviceId> = (1..=12u8)
        .map(|i| {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
            DeviceId(sk.verifying_key().to_bytes())
        })
        .collect();
    let v = rendezvous_json(PHRASE, None, None, &devices).unwrap();
    let ranked: Vec<String> = v["ranked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ranked.len(), 12);
    let rv = RendezvousKeys::derive(&parse_mnemonic(PHRASE).unwrap().to_seed(""));
    let target = KademliaRoutingView::target_key(&rv.address);
    let dist = |h: &str| {
        let d = devices.iter().find(|d| hex_encode(&d.0) == h).unwrap();
        let peer = device_id_to_peer_id(d).unwrap();
        KademliaRoutingView::xor_distance(&target, &KademliaRoutingView::peer_key(&peer))
    };
    for w in ranked.windows(2) {
        assert!(dist(&w[0]) < dist(&w[1]), "closest first");
    }
}
