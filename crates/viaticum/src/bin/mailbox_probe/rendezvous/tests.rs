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
    let v = rendezvous_json(PHRASE, Some(lineage), Some("b")).unwrap();
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
    let v = rendezvous_json(PHRASE, None, None).unwrap();
    assert!(v.get("slot_a").is_none());
    assert!(rendezvous_json(PHRASE, None, Some("a")).is_err());
    assert!(rendezvous_json("not a phrase", None, None).is_err());
}
