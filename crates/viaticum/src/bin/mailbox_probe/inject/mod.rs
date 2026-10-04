// `mailbox-probe inject`: write one entry straight into a postman's redb, bypassing every
// postman rule (a hostile postman). `--replace` overwrites the entry under the same
// (target, msg_id, class) — "the postman swapped my pointer place" (CROWN-1 V.15.4(б)).
// `--pos-response` forges a PoS response for a chosen device (C-SP, pos-i16).

use ed25519_dalek::Signer;
use viaticum_core::db::{Db, DbError};
use viaticum_core::mailbox::MailboxEntry;
use viaticum_core::messages::{PosHashResponseMsg, pos_hash_response_sig_input};
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp};

#[cfg(test)]
mod tests;

/// Store `entry`. With `replace`, an entry under the same (target, msg_id, class) is
/// deleted first. Returns whether such an entry existed (and was replaced).
pub(crate) fn store_injected(
    db: &Db,
    entry: &MailboxEntry,
    replace: bool,
) -> Result<bool, DbError> {
    let mut existed = false;
    if replace {
        existed = db
            .mailbox_list_for_target(&entry.target, 0)?
            .iter()
            .any(|e| e.msg_id == entry.msg_id && e.class == entry.class);
        if existed {
            db.mailbox_delete(&entry.target, entry.msg_id, entry.class)?;
        }
    }
    db.mailbox_insert(entry, entry.stored_at)?;
    Ok(existed)
}

/// The chain hash of a forged PoS response: junk, never the expected hash.
pub(crate) const FORGED_CHAIN_HASH: [u8; 32] = [0xBA; 32];

/// Which key of `--sign-with DIR` signs a forged PoS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForgeKey {
    /// The device key of DIR (a sibling device answering for itself).
    Device,
    /// The master key of DIR (the pre-C-SP scheme / anyone holding only the phrase).
    Master,
}

/// `device` | `master`.
pub(crate) fn parse_forge_key(s: &str) -> Option<ForgeKey> {
    match s {
        "device" => Some(ForgeKey::Device),
        "master" => Some(ForgeKey::Master),
        _ => None,
    }
}

/// `CID_HEX:BLOCK_HEX:DEVICE_HEX` (32, 64, 64 hex chars) → (challenge_id, block, device).
pub(crate) fn parse_pos_response_spec(s: &str) -> Option<([u8; 16], SourceBlockId, DeviceId)> {
    use super::audit::parse_hex;
    let mut parts = s.split(':');
    let cid = <[u8; 16]>::try_from(parse_hex(parts.next()?)?).ok()?;
    let block = <[u8; 32]>::try_from(parse_hex(parts.next()?)?).ok()?;
    let device = <[u8; 32]>::try_from(parse_hex(parts.next()?)?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((cid, SourceBlockId(block), DeviceId(device)))
}

/// A PoS response to `challenge_id` naming `device`, with a junk chain hash, signed by
/// `key` whatever device that key belongs to. The owner must ignore it unless `key` is
/// `device`'s own key (then it is that device's honest-looking answer, a Fail by hash).
pub(crate) fn forged_pos_response(
    challenge_id: [u8; 16],
    block: SourceBlockId,
    device: DeviceId,
    key: &ed25519_dalek::SigningKey,
    timestamp: Timestamp,
) -> PosHashResponseMsg {
    let input = pos_hash_response_sig_input(
        &challenge_id,
        &block,
        &device,
        &FORGED_CHAIN_HASH,
        &timestamp,
    );
    PosHashResponseMsg {
        v: viaticum_core::constants::PROTOCOL_VERSION,
        challenge_id,
        source_block_id: block,
        chain_hash: FORGED_CHAIN_HASH,
        timestamp,
        device_id: device,
        sig: key.sign(&input).to_bytes(),
    }
}
