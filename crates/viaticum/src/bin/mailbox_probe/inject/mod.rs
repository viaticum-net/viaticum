// `mailbox-probe inject`: write one entry straight into a postman's redb, bypassing every
// postman rule (a hostile postman). `--replace` overwrites the entry under the same
// (target, msg_id, class) — "the postman swapped my pointer place" (CROWN-1 V.15.4(б)).

use viaticum_core::db::{Db, DbError};
use viaticum_core::mailbox::MailboxEntry;

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
