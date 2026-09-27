// Applied signed letters by signature (DN-1): this node remembers every signed letter it has
// already applied, so a byte-identical repeat — the mailbox re-delivering the same entry for its
// whole TTL — applies nothing a second time (4r-i47). First user: the owner's DropNotice handler
// (class `DropNotice`); line B plugs Delete in (delete-i6) with its own class.
//
// What it is: a filter of byte-identical repeats of a SIGNED PAYLOAD, keyed by the payload's
// ed25519 signature AFTER the signature check (`verify_strict`). The key is canonical because
// ed25519-dalek 2.x (built without `legacy_compatibility`) rejects a non-canonical S in plain
// `verify` as well — a S+L twin never gets here; `verify_strict` adds the rejection of
// small-order R / public keys on top (unit DN1-7b). Compatible
// with the mailbox model (mailbox-i26): the envelope does not authenticate `msg_id` or times,
// the payload signature does. For DropNotice, times are deliberately NOT compared (the holder's
// clock stamps the letter, ours stamps `placed_at`; a holder clock running behind would make a
// genuine new drop look old and swallow it).
//
// Known limit (Cannot close of local_drop_loop_test): a malicious postman can keep an old
// letter and re-store it with a fresh `expires_at` (the envelope is not authenticated). Every
// time our row expires (once per retention window, 2 × TTL) its next delivery applies again —
// one application per window, indefinitely, for as long as the postman keeps doing it. For
// DropNotice: one re-placement of the block every ~28 days per letter; the У-4 ledger is not
// touched (the evidence predates the new episode: EvidenceBeforeEpisode). In a circle of
// friends the postmen are the friends themselves; for Delete, line B adds a time guard in C4.
//
// Two tables, both node-local and deliberately OUTSIDE `system_state::snapshot_db` (4r-i51):
//   * `seen_signed_letters`            sig(64) -> CBOR(SeenSignedLetter)
//   * `seen_signed_letters_by_expiry`  forget_after(u64 BE) ‖ sig(64) -> ()
// The index makes pruning a range scan over the EXPIRED keys only (O(expired), 4r-i49), done on
// every insert inside the inserting transaction.

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::{Db, DbError, DbWriteTxn};
use crate::types::{
    SeenSignedLetter, SignedLetterClass, Timestamp, from_cbor_bytes, to_cbor_bytes,
};

/// Applied signed letters by signature (DN-1). Deliberately outside `snapshot_db`.
pub(super) const SEEN_SIGNED_LETTERS: TableDefinition<&[u8; 64], &[u8]> =
    TableDefinition::new("seen_signed_letters");

/// Expiry index: `forget_after` (u64 big-endian) ‖ sig → (). Pruning is a range scan `..= now`.
/// A key can outlive its row's current `forget_after` (the row was rewritten after being
/// undecodable or expired): pruning then drops only the stale KEY, never the live row.
pub(super) const SEEN_SIGNED_LETTERS_BY_EXPIRY: TableDefinition<&[u8; 72], ()> =
    TableDefinition::new("seen_signed_letters_by_expiry");

fn expiry_key(forget_after: Timestamp, sig: &[u8; 64]) -> [u8; 72] {
    let mut key = [0u8; 72];
    key[..8].copy_from_slice(&forget_after.0.to_be_bytes());
    key[8..].copy_from_slice(sig);
    key
}

/// A row that decodes AND is still inside its retention at `now`.
fn is_live(bytes: &[u8], now: Timestamp) -> bool {
    match from_cbor_bytes::<SeenSignedLetter>(bytes) {
        Ok(rec) => rec.forget_after > now,
        Err(_) => false,
    }
}

impl Db {
    /// True iff a decodable row exists for `sig` with `forget_after > now`. An undecodable row →
    /// `Err` (the caller treats it as "not seen" and the next record overwrites it — FW-2).
    ///
    /// `sig` must be a signature that already passed the signature check against its signer.
    pub fn signed_letter_seen(&self, sig: &[u8; 64], now: Timestamp) -> Result<bool, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SEEN_SIGNED_LETTERS)?;
        match table.get(sig)? {
            None => Ok(false),
            Some(v) => {
                let rec: SeenSignedLetter = from_cbor_bytes(v.value())?;
                Ok(rec.forget_after > now)
            }
        }
    }

    /// Stand-alone write (for DropNotice: the "already Lost" path). Inserts
    /// `{class, first_seen: now, forget_after}` unless a decodable, still-live row exists (then
    /// its first `first_seen` is kept); an undecodable or expired row is overwritten (FW-2).
    /// Adds the index key. Prunes expired rows through the index in the same transaction.
    /// Returns the pruned count.
    pub fn record_signed_letter_seen(
        &self,
        sig: &[u8; 64],
        class: SignedLetterClass,
        now: Timestamp,
        forget_after: Timestamp,
    ) -> Result<usize, DbError> {
        let tx = self.inner.begin_write()?;
        let pruned = record_in(&tx, sig, class, now, forget_after)?;
        tx.commit()?;
        Ok(pruned)
    }

    /// All rows, key order. Tests and diagnostics only; undecodable rows are skipped with a warn.
    pub fn list_seen_signed_letters(&self) -> Result<Vec<([u8; 64], SeenSignedLetter)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SEEN_SIGNED_LETTERS)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            match from_cbor_bytes::<SeenSignedLetter>(v.value()) {
                Ok(rec) => out.push((*k.value(), rec)),
                Err(e) => {
                    tracing::warn!(err = %e, "db: undecodable seen_signed_letters row skipped")
                }
            }
        }
        Ok(out)
    }

    /// Number of keys in the expiry index. Tests and diagnostics only.
    pub fn seen_signed_letter_index_len(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let idx = tx.open_table(SEEN_SIGNED_LETTERS_BY_EXPIRY)?;
        Ok(redb::ReadableTableMetadata::len(&idx)?)
    }
}

impl DbWriteTxn<'_> {
    /// Same as [`Db::record_signed_letter_seen`], inside the caller's transaction (Д-DN1-5): the
    /// effect of the letter (for DropNotice: the placement transition) and "this letter is
    /// applied" commit together or not at all.
    pub fn record_signed_letter_seen(
        &mut self,
        sig: &[u8; 64],
        class: SignedLetterClass,
        now: Timestamp,
        forget_after: Timestamp,
    ) -> Result<usize, DbError> {
        record_in(&self.txn, sig, class, now, forget_after)
    }
}

/// Prune expired rows through the index, then insert the row under `sig` unless a live row is
/// already there. Pruning comes first so an expired row of the same `sig` is replaced, not kept.
fn record_in(
    txn: &redb::WriteTransaction,
    sig: &[u8; 64],
    class: SignedLetterClass,
    now: Timestamp,
    forget_after: Timestamp,
) -> Result<usize, DbError> {
    let mut seen = txn.open_table(SEEN_SIGNED_LETTERS)?;
    let mut idx = txn.open_table(SEEN_SIGNED_LETTERS_BY_EXPIRY)?;

    // O(expired): only the index keys with forget_after <= now are visited.
    let upper = expiry_key(now, &[0xff; 64]);
    let mut expired: Vec<[u8; 72]> = Vec::new();
    for item in idx.range::<&[u8; 72]>(..=&upper)? {
        let (k, _) = item?;
        expired.push(*k.value());
    }
    let mut pruned = 0usize;
    for key in expired {
        idx.remove(&key)?;
        let mut row_sig = [0u8; 64];
        row_sig.copy_from_slice(&key[8..]);
        // Drop the row unless it is live: a live row here was rewritten after this key was
        // written (its current key is later), so this key is merely stale.
        let drop_row = match seen.get(&row_sig)? {
            Some(v) => !is_live(v.value(), now),
            None => false,
        };
        if drop_row {
            seen.remove(&row_sig)?;
            pruned += 1;
        }
    }

    let keep_existing = match seen.get(sig)? {
        Some(v) => is_live(v.value(), now),
        None => false,
    };
    if !keep_existing {
        let rec = SeenSignedLetter {
            class,
            first_seen: now,
            forget_after,
        };
        let bytes = to_cbor_bytes(&rec);
        seen.insert(sig, bytes.as_slice())?;
        idx.insert(&expiry_key(forget_after, sig), ())?;
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests;
