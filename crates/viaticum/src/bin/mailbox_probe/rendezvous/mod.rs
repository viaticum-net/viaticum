// `mailbox-probe rendezvous`: the pointer box address and the pointer place slots of a
// recovery phrase, derived offline (CROWN-1 C3a, V.3, V.16.6). No clock, no data dir:
// E2E scenarios compare these with the postmen's `target=` / `msg_id=` log fields.

use viaticum::daemon::identity::parse_mnemonic;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys};
use viaticum_core::types::hex_encode;

/// JSON for `rendezvous --phrase P [--lineage HEX32] [--place a|b]`:
/// `address` (64 hex), `address_short` (16 hex, as the postman logs `target=`), and
/// with a lineage `slot_a`, `slot_b` (32 hex each); with `--place` also `slot`.
pub(crate) fn rendezvous_json(
    phrase: &str,
    lineage: Option<[u8; 16]>,
    place: Option<&str>,
) -> Result<serde_json::Value, String> {
    let mnemonic = parse_mnemonic(phrase).map_err(|e| format!("--phrase: {e}"))?;
    let seed = mnemonic.to_seed("");
    let rv = RendezvousKeys::derive(&seed);
    let mut out = serde_json::json!({
        "address": hex_encode(&rv.address.0),
        "address_short": rv.address.to_string(),
    });
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

#[cfg(test)]
mod tests;
