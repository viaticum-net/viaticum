// `mailbox-probe remove`: delete the matching entries of one mailbox address straight
// from a postman's redb, by the same `Db::mailbox_delete` path as `inject --replace`.
// Used to stage "the answer is lost at every postman" (Р-4 C).

use viaticum_core::db::{Db, DbError};
use viaticum_core::mailbox::{MailboxAddress, MailboxClass};

#[cfg(test)]
mod tests;

/// Delete every entry of `target` matching `msg_id` and `class` (`None` matches any),
/// expired entries included. Returns how many were removed.
pub(crate) fn remove_matching(
    db: &Db,
    target: &MailboxAddress,
    msg_id: Option<[u8; 16]>,
    class: Option<MailboxClass>,
) -> Result<usize, DbError> {
    let doomed: Vec<_> = db
        .mailbox_list_for_target(target, 0)?
        .into_iter()
        .filter(|e| msg_id.is_none_or(|m| e.msg_id == m) && class.is_none_or(|c| e.class == c))
        .collect();
    for e in &doomed {
        db.mailbox_delete(target, e.msg_id, e.class)?;
    }
    Ok(doomed.len())
}
