// `mailbox-probe rendezvous`: the pointer box address and the pointer place slots of a
// recovery phrase, derived offline (CROWN-1 C3a, V.3, V.16.6). No clock, no data dir:
// E2E scenarios compare these with the postmen's `target=` / `msg_id=` log fields.

use viaticum::daemon::identity::parse_mnemonic;
use viaticum::daemon::mailbox::candidate::KademliaRoutingView;
use viaticum::daemon::network::swarm::device_id_to_peer_id;
use viaticum_core::mailbox::MailboxAddress;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys};
use viaticum_core::types::{DeviceId, hex_encode};

/// JSON for `rendezvous --phrase P [--lineage HEX32] [--place a|b] [--rank DEV]...`:
/// `address` (64 hex), `address_short` (16 hex, as the postman logs `target=`), and
/// with a lineage `slot_a`, `slot_b` (32 hex each); with `--place` also `slot`; with
/// `--rank` the given devices as `ranked`, closest to the box first (dr-i63: the
/// Kademlia metric, the order a lookup of the box finds them).
pub(crate) fn rendezvous_json(
    phrase: &str,
    lineage: Option<[u8; 16]>,
    place: Option<&str>,
    rank: &[DeviceId],
) -> Result<serde_json::Value, String> {
    let mnemonic = parse_mnemonic(phrase).map_err(|e| format!("--phrase: {e}"))?;
    let seed = mnemonic.to_seed("");
    let rv = RendezvousKeys::derive(&seed);
    let mut out = serde_json::json!({
        "address": hex_encode(&rv.address.0),
        "address_short": rv.address.to_string(),
    });
    if !rank.is_empty() {
        let ranked: Vec<String> = rank_by_box(&rv.address, rank)?
            .iter()
            .map(|d| hex_encode(&d.0))
            .collect();
        out["ranked"] = ranked.into();
    }
    let place = match place {
        None => None,
        Some("a") | Some("A") => Some(PointerPlace::A),
        Some("b") | Some("B") => Some(PointerPlace::B),
        Some(other) => return Err(format!("--place: want a or b, got {other:?}")),
    };
    match (lineage, place) {
        (Some(l), p) => {
            out["slot_a"] = hex_encode(&rv.pointer_slot(&l, PointerPlace::A)).into();
            out["slot_b"] = hex_encode(&rv.pointer_slot(&l, PointerPlace::B)).into();
            if let Some(p) = p {
                out["slot"] = hex_encode(&rv.pointer_slot(&l, p)).into();
            }
        }
        (None, Some(_)) => return Err("--place needs --lineage".into()),
        (None, None) => {}
    }
    Ok(out)
}

/// `devices` ordered by XOR distance of SHA256(peer id) to SHA256(box address) —
/// Kademlia's metric for `dr_lookup_key` — closest first.
pub(crate) fn rank_by_box(
    address: &MailboxAddress,
    devices: &[DeviceId],
) -> Result<Vec<DeviceId>, String> {
    let target = KademliaRoutingView::target_key(address);
    let mut keyed = Vec::with_capacity(devices.len());
    for d in devices {
        let peer = device_id_to_peer_id(d).map_err(|e| format!("--rank {d}: {e}"))?;
        let dist =
            KademliaRoutingView::xor_distance(&target, &KademliaRoutingView::peer_key(&peer));
        keyed.push((dist, *d));
    }
    keyed.sort_by_key(|k| k.0);
    Ok(keyed.into_iter().map(|(_, d)| d).collect())
}

#[cfg(test)]
mod tests;
