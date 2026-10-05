// Mailbox tables: entries stored on behalf of other nodes (postman role) and the
// per-address byte counters behind the directed quota, the SelfPointer slots (one
// per pointer place of a catalog history, CROWN-1 C3a), plus the addressing lookups
// directed mail needs (recipient master and x25519 key).
//
// Two counters per address, both updated in the same write transaction as the entry
// table so they never diverge from it:
// - MAILBOX_BYTES_BY_TARGET: bytes of ALL entries of the address (also the set of
//   addresses with mail, `mailbox_list_all_targets`);
// - MAILBOX_SP_BYTES_BY_TARGET: bytes of the SelfPointer entries only. The directed
//   quota is `total - pointers` (AC-8: junk cannot starve the crown, pointers cannot
//   block mail). Pointers are bounded by the slot cap, not by bytes (mailbox-i50).

use redb::{ReadableDatabase, ReadableTable, WriteTransaction};

use super::{
    Db, DbError, MAILBOX_BYTES_BY_TARGET, MAILBOX_ENTRIES, MAILBOX_SP_BYTES_BY_TARGET,
    mailbox_entry_key,
};
use crate::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use crate::types::{DeviceId, IdentityPub, from_cbor_bytes, to_cbor_bytes};

/// Range bounds covering every MAILBOX_ENTRIES key of `target`.
fn target_range(target: &MailboxAddress) -> ([u8; 49], [u8; 49]) {
    let mut lo = [0u8; 49];
    let mut hi = [0u8; 49];
    lo[..32].copy_from_slice(&target.0);
    hi[..32].copy_from_slice(&target.0);
    hi[32..].fill(0xFF);
    (lo, hi)
}

/// Add `add` and subtract `sub` bytes on one address counter (row removed at 0).
fn adjust_counter(
    tx: &WriteTransaction,
    table: redb::TableDefinition<&[u8; 32], &[u8]>,
    target: &[u8; 32],
    add: u64,
    sub: u64,
) -> Result<(), DbError> {
    if add == 0 && sub == 0 {
        return Ok(());
    }
    let mut counters = tx.open_table(table)?;
    let current: u64 = match counters.get(target)? {
        Some(v) => from_cbor_bytes(v.value())?,
        None => 0,
    };
    let new_total = current.saturating_add(add).saturating_sub(sub);
    if new_total == 0 {
        counters.remove(target)?;
    } else {
        counters.insert(target, to_cbor_bytes(&new_total).as_slice())?;
    }
    Ok(())
}

/// Remove the given (key, target, size, class) rows and update both counters.
fn remove_rows(
    tx: &WriteTransaction,
    rows: &[([u8; 49], [u8; 32], u64, MailboxClass)],
) -> Result<(), DbError> {
    let mut all: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
    let mut sp: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
    {
        let mut entries = tx.open_table(MAILBOX_ENTRIES)?;
        for (key, target, size, class) in rows {
            entries.remove(key)?;
            *all.entry(*target).or_insert(0) += size;
            if *class == MailboxClass::SelfPointer {
                *sp.entry(*target).or_insert(0) += size;
            }
        }
    }
    for (target, delta) in &all {
        adjust_counter(tx, MAILBOX_BYTES_BY_TARGET, target, 0, *delta)?;
    }
    for (target, delta) in &sp {
        adjust_counter(tx, MAILBOX_SP_BYTES_BY_TARGET, target, 0, *delta)?;
    }
    Ok(())
}

fn read_counter(
    db: &Db,
    table: redb::TableDefinition<&[u8; 32], &[u8]>,
    target: &MailboxAddress,
) -> Result<u64, DbError> {
    let tx = db.inner.begin_read()?;
    let counters = tx.open_table(table)?;
    match counters.get(&target.0)? {
        Some(v) => Ok(from_cbor_bytes(v.value())?),
        None => Ok(0),
    }
}

/// Number of SelfPointer keys of `target` (the class byte is `key[48]`; values are
/// not decoded, so expired-but-unswept pointers count too).
fn slot_count_in(
    table: &impl ReadableTable<&'static [u8; 49], &'static [u8]>,
    target: &MailboxAddress,
) -> Result<usize, DbError> {
    let (lo, hi) = target_range(target);
    let mut n = 0usize;
    for item in table.range::<&[u8; 49]>(&lo..=&hi)? {
        let (k, _) = item?;
        if k.value()[48] == MailboxClass::SelfPointer.as_u8() {
            n += 1;
        }
    }
    Ok(n)
}

/// Outcome of [`Db::mailbox_put_self_pointer`] (CROWN-1 C3a, V.3 / V.5 п.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfPointerStore {
    /// Empty slot, below the slot cap: inserted.
    Stored,
    /// The slot held an older pointer (`previous_stored_at` < incoming): replaced.
    Replaced { previous_stored_at: u64 },
    /// The slot holds a pointer with the same `stored_at` and the same `payload`:
    /// nothing changed (a re-offer of the same envelope).
    Duplicate,
    /// The slot holds a pointer that is newer, or as new with another payload:
    /// nothing changed.
    Superseded { held_stored_at: u64 },
    /// Empty slot, but the address already has `max_slots` slots: nothing changed,
    /// nothing evicted.
    SlotsFull,
}

/// Raw mailbox content read for the offline audit (mailbox-probe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRawDump {
    /// Every mailbox address with the raw stored CBOR of its entries (expired included).
    pub boxes: Vec<(MailboxAddress, Vec<Vec<u8>>)>,
    /// The file needed crash recovery (the node was killed), so it was read from a
    /// repaired private COPY in the temp dir; the original was not touched.
    pub from_repaired_copy: bool,
}

/// Offline audit of a STOPPED node's `db.redb` without writing to it. Opens the file
/// with `redb::ReadOnlyDatabase` (no pre-open backup copy, no table creation). A node
/// stopped with SIGKILL leaves the file needing recovery, which a read-only handle
/// refuses (`RepairAborted`); then the file is copied to the temp dir, the COPY is
/// repaired and read, and the copy is deleted — the postman's disk stays byte-identical.
pub fn read_only_mailbox_raw_entries(path: &std::path::Path) -> Result<MailboxRawDump, DbError> {
    match redb::ReadOnlyDatabase::open(path) {
        Ok(db) => Ok(MailboxRawDump {
            boxes: dump_mailbox(&db)?,
            from_repaired_copy: false,
        }),
        Err(redb::DatabaseError::RepairAborted) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let copy = std::env::temp_dir()
                .join(format!("mailbox-audit-{}-{nanos}.redb", std::process::id()));
            std::fs::copy(path, &copy)
                .map_err(|e| DbError::NotFound(format!("copy {}: {e}", path.display())))?;
            let result = redb::Database::create(&copy)
                .map_err(DbError::from)
                .and_then(|db| dump_mailbox(&db));
            let _ = std::fs::remove_file(&copy);
            Ok(MailboxRawDump {
                boxes: result?,
                from_repaired_copy: true,
            })
        }
        Err(e) => Err(e.into()),
    }
}

#[allow(clippy::type_complexity)]
fn dump_mailbox(
    db: &impl ReadableDatabase,
) -> Result<Vec<(MailboxAddress, Vec<Vec<u8>>)>, DbError> {
    let tx = db.begin_read()?;
    let table = tx.open_table(MAILBOX_ENTRIES)?;
    let mut out: Vec<(MailboxAddress, Vec<Vec<u8>>)> = Vec::new();
    for item in table.iter()? {
        let (k, v) = item?;
        let mut target = [0u8; 32];
        target.copy_from_slice(&k.value()[..32]);
        let target = MailboxAddress(target);
        match out.last_mut() {
            Some((t, list)) if *t == target => list.push(v.value().to_vec()),
            _ => out.push((target, vec![v.value().to_vec()])),
        }
    }
    Ok(out)
}

impl Db {
    /// Store a mailbox entry. Fails with `DbError::Duplicate` if an entry with
    /// the same (target, msg_id, class) key already exists.
    ///
    /// `now_secs` is unused (the entry is stored as-is); kept for API symmetry with
    /// the sweep so callers pass a consistent clock.
    pub fn mailbox_insert(&self, entry: &MailboxEntry, _now_secs: u64) -> Result<(), DbError> {
        let key = mailbox_entry_key(&entry.target, entry.msg_id, entry.class);
        let entry_bytes = to_cbor_bytes(entry);
        let entry_size = entry_bytes.len() as u64;

        let tx = self.inner.begin_write()?;
        {
            let mut entries = tx.open_table(MAILBOX_ENTRIES)?;
            if entries.get(&key)?.is_some() {
                return Err(DbError::Duplicate);
            }
            entries.insert(&key, entry_bytes.as_slice())?;
        }
        adjust_counter(&tx, MAILBOX_BYTES_BY_TARGET, &entry.target.0, entry_size, 0)?;
        if entry.class == MailboxClass::SelfPointer {
            adjust_counter(
                &tx,
                MAILBOX_SP_BYTES_BY_TARGET,
                &entry.target.0,
                entry_size,
                0,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether an entry with this (target, msg_id, class) key is stored (expired or not).
    pub fn mailbox_contains(
        &self,
        target: &MailboxAddress,
        msg_id: [u8; 16],
        class: MailboxClass,
    ) -> Result<bool, DbError> {
        let tx = self.inner.begin_read()?;
        let entries = tx.open_table(MAILBOX_ENTRIES)?;
        Ok(entries
            .get(&mailbox_entry_key(target, msg_id, class))?
            .is_some())
    }

    /// List all non-expired entries for a target (for MailboxFetch).
    /// Entries with `expires_at < now_secs` are excluded (`now_secs = 0` lists all).
    pub fn mailbox_list_for_target(
        &self,
        target: &MailboxAddress,
        now_secs: u64,
    ) -> Result<Vec<MailboxEntry>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(MAILBOX_ENTRIES)?;
        let (lo, hi) = target_range(target);
        let mut result = Vec::new();
        for item in table.range::<&[u8; 49]>(&lo..=&hi)? {
            let (_, v) = item?;
            let entry: MailboxEntry = from_cbor_bytes(v.value())?;
            if entry.expires_at >= now_secs {
                result.push(entry);
            }
        }
        Ok(result)
    }

    /// Delete a single entry by (target, msg_id, class). No-op if not found.
    pub fn mailbox_delete(
        &self,
        target: &MailboxAddress,
        msg_id: [u8; 16],
        class: MailboxClass,
    ) -> Result<(), DbError> {
        let key = mailbox_entry_key(target, msg_id, class);
        let tx = self.inner.begin_write()?;
        let size: u64 = {
            let entries = tx.open_table(MAILBOX_ENTRIES)?;
            match entries.get(&key)? {
                Some(v) => v.value().len() as u64,
                None => 0,
            }
        };
        if size > 0 {
            remove_rows(&tx, &[(key, target.0, size, class)])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Sweep all expired entries (expires_at < now_secs) across all targets.
    /// Updates the per-target byte counters accordingly.
    /// Returns the count of entries removed.
    pub fn mailbox_sweep_expired(&self, now_secs: u64) -> Result<u64, DbError> {
        let tx = self.inner.begin_write()?;
        let expired: Vec<([u8; 49], [u8; 32], u64, MailboxClass)> = {
            let table = tx.open_table(MAILBOX_ENTRIES)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let entry: MailboxEntry = from_cbor_bytes(v.value())?;
                if entry.expires_at < now_secs {
                    out.push((
                        *k.value(),
                        entry.target.0,
                        v.value().len() as u64,
                        entry.class,
                    ));
                }
            }
            out
        };
        if expired.is_empty() {
            return Ok(0);
        }
        remove_rows(&tx, &expired)?;
        tx.commit()?;
        Ok(expired.len() as u64)
    }

    /// Bytes of ALL entries stored for a given target (0 if none).
    pub fn mailbox_bytes_for_target(&self, target: &MailboxAddress) -> Result<u64, DbError> {
        read_counter(self, MAILBOX_BYTES_BY_TARGET, target)
    }

    /// Sum of serialized sizes of SelfPointer entries stored for `target`.
    pub fn mailbox_self_pointer_bytes_for_target(
        &self,
        target: &MailboxAddress,
    ) -> Result<u64, DbError> {
        read_counter(self, MAILBOX_SP_BYTES_BY_TARGET, target)
    }

    /// Total mailbox bytes across all targets (full scan of MAILBOX_BYTES_BY_TARGET).
    pub fn mailbox_total_bytes(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(MAILBOX_BYTES_BY_TARGET)?;
        let mut total = 0u64;
        for item in table.iter()? {
            let (_, v) = item?;
            let bytes: u64 = from_cbor_bytes(v.value())?;
            total = total.saturating_add(bytes);
        }
        Ok(total)
    }

    /// Evict LRU non-high-trust entries for a target until bytes stored <= target_bytes.
    ///
    /// Only non-high-trust entries (class.is_high_trust()==false) are candidates for
    /// eviction, ordered by stored_at ascending (oldest first). High-trust entries
    /// (SelfPointer) are NEVER selected here: they leave only by TTL expiry or by a
    /// newer pointer replacing them in their own slot (`mailbox_put_self_pointer`). If after
    /// dropping all non-high-trust entries the target is still over, the function
    /// returns without touching the pointers (Bug-D / AC-6).
    ///
    /// Returns the count of entries removed.
    pub fn mailbox_evict_lru_for_target(
        &self,
        target: &MailboxAddress,
        target_bytes: u64,
    ) -> Result<u64, DbError> {
        let current_bytes = self.mailbox_bytes_for_target(target)?;
        if current_bytes <= target_bytes {
            return Ok(0);
        }
        let to_free = current_bytes - target_bytes;

        let tx = self.inner.begin_write()?;
        let victims = {
            let table = tx.open_table(MAILBOX_ENTRIES)?;
            let (lo, hi) = target_range(target);
            let mut non_ht: Vec<([u8; 49], u64, u64, MailboxClass)> = Vec::new();
            for item in table.range::<&[u8; 49]>(&lo..=&hi)? {
                let (k, v) = item?;
                let entry: MailboxEntry = from_cbor_bytes(v.value())?;
                if !entry.class.is_high_trust() {
                    non_ht.push((
                        *k.value(),
                        entry.stored_at,
                        v.value().len() as u64,
                        entry.class,
                    ));
                }
            }
            // Oldest stored_at first (LRU order).
            non_ht.sort_by_key(|e| e.1);
            let mut freed = 0u64;
            let mut out = Vec::new();
            for (key, _, size, class) in non_ht {
                if freed >= to_free {
                    break;
                }
                freed = freed.saturating_add(size);
                out.push((key, target.0, size, class));
            }
            out
        };
        if victims.is_empty() {
            return Ok(0);
        }
        remove_rows(&tx, &victims)?;
        tx.commit()?;
        Ok(victims.len() as u64)
    }

    /// Put a SelfPointer into its slot `(entry.target, entry.msg_id)` in ONE write
    /// transaction (mailbox-i31, i40/i50): the check, the replacement and the insert
    /// cannot interleave with another store (redb write transactions are serialized).
    ///
    /// Slot occupied:
    /// - same `stored_at` and same `payload` → `Duplicate` (nothing changes). Compared by
    ///   `payload`, not by the stored bytes: the postman clamps `expires_at`, so a re-offer
    ///   of the same envelope may serialize differently;
    /// - incoming `stored_at` > held → replaced, both byte counters move by (new − old)
    ///   → `Replaced`;
    /// - otherwise (older, or equal time with another payload) → `Superseded`.
    ///
    /// Slot empty: the SelfPointer keys of the target are counted (class byte, no value
    /// decode); at `max_slots` → `SlotsFull` and nothing is evicted — a dormant history
    /// must outlive any number of publications of other histories (dr-i6, dr-i42).
    /// Otherwise → inserted, `Stored`.
    pub fn mailbox_put_self_pointer(
        &self,
        entry: &MailboxEntry,
        max_slots: usize,
    ) -> Result<SelfPointerStore, DbError> {
        debug_assert_eq!(entry.class, MailboxClass::SelfPointer);
        let key = mailbox_entry_key(&entry.target, entry.msg_id, entry.class);
        let bytes = to_cbor_bytes(entry);
        let size = bytes.len() as u64;

        let tx = self.inner.begin_write()?;
        let (outcome, removed) = {
            let mut table = tx.open_table(MAILBOX_ENTRIES)?;
            let held = match table.get(&key)? {
                Some(v) => {
                    let held: MailboxEntry = from_cbor_bytes(v.value())?;
                    Some((held, v.value().len() as u64))
                }
                None => None,
            };
            match held {
                Some((held, _))
                    if held.stored_at == entry.stored_at && held.payload == entry.payload =>
                {
                    return Ok(SelfPointerStore::Duplicate);
                }
                Some((held, _)) if entry.stored_at <= held.stored_at => {
                    return Ok(SelfPointerStore::Superseded {
                        held_stored_at: held.stored_at,
                    });
                }
                Some((held, held_size)) => {
                    table.insert(&key, bytes.as_slice())?;
                    (
                        SelfPointerStore::Replaced {
                            previous_stored_at: held.stored_at,
                        },
                        held_size,
                    )
                }
                None => {
                    if slot_count_in(&table, &entry.target)? >= max_slots {
                        return Ok(SelfPointerStore::SlotsFull);
                    }
                    table.insert(&key, bytes.as_slice())?;
                    (SelfPointerStore::Stored, 0)
                }
            }
        };
        adjust_counter(&tx, MAILBOX_BYTES_BY_TARGET, &entry.target.0, size, removed)?;
        adjust_counter(
            &tx,
            MAILBOX_SP_BYTES_BY_TARGET,
            &entry.target.0,
            size,
            removed,
        )?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Number of SelfPointer slots stored for `target` (expired-unswept included).
    pub fn mailbox_self_pointer_slot_count(
        &self,
        target: &MailboxAddress,
    ) -> Result<usize, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(MAILBOX_ENTRIES)?;
        slot_count_in(&table, target)
    }

    /// List all unique targets that have at least one mailbox entry.
    ///
    /// Sourced from MAILBOX_BYTES_BY_TARGET (O(targets), not O(entries)).
    /// Used by `run_mailbox_self_cleanup` to iterate targets for membership checks.
    pub fn mailbox_list_all_targets(&self) -> Result<Vec<MailboxAddress>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(MAILBOX_BYTES_BY_TARGET)?;
        let mut targets = Vec::new();
        for item in table.iter()? {
            let (k, _) = item?;
            targets.push(MailboxAddress(*k.value()));
        }
        Ok(targets)
    }

    /// List all non-high-trust entries for a target (for membership-check eviction).
    ///
    /// Unlike `mailbox_list_for_target`, this does NOT filter by expiry — the cleanup
    /// task handles all non-high-trust entries regardless of TTL status. High-trust
    /// entries are excluded by definition (they are membership-check exempt).
    pub fn mailbox_list_non_high_trust_for_target(
        &self,
        target: &MailboxAddress,
    ) -> Result<Vec<MailboxEntry>, DbError> {
        Ok(self
            .mailbox_list_for_target(target, 0)?
            .into_iter()
            .filter(|e| !e.class.is_high_trust())
            .collect())
    }

    // ─── Addressing for directed mail (CROWN-1 §7.4.4) ─────────────────────────

    /// X25519 public key of `master`, resolved from PEERS (NOT device_to_master: that
    /// table is not in the SS snapshot, see `bytes_master_stores_for_us`). Zero master
    /// → None. Several devices of one master share the key (master-scoped). Rule (W5,
    /// AC-21, mailbox-i21): ANY record with `Some` wins over records with `None`
    /// regardless of `last_seen` (a DR-created minimal record without a key must not
    /// hide a known key); among several different `Some`, the one with the latest
    /// `last_seen`.
    pub fn x25519_for_master(&self, master: &IdentityPub) -> Result<Option<[u8; 32]>, DbError> {
        if master.0 == [0u8; 32] {
            return Ok(None);
        }
        Ok(self
            .list_all_peers()?
            .into_iter()
            .filter(|p| p.master_identity == *master)
            .filter_map(|p| p.x25519_pub.map(|k| (p.last_seen.0, k)))
            .max_by_key(|(last_seen, _)| *last_seen)
            .map(|(_, key)| key))
    }

    /// Master of a holder device, resolved from PEERS (`PeerRecord::master_identity`).
    /// Unknown device or zero placeholder → None. Replaces the
    /// `get_master_for_device(..).unwrap_or(device)` fallback that addressed mail to a
    /// device-id box nobody reads (F14).
    pub fn master_for_peer_device(
        &self,
        device: &DeviceId,
    ) -> Result<Option<IdentityPub>, DbError> {
        Ok(self
            .get_peer(device)?
            .map(|p| p.master_identity)
            .filter(|m| m.0 != [0u8; 32]))
    }

    /// Master of a holder device for addressing service mail (PoS challenge, Delete,
    /// revoke): PEERS first (`master_for_peer_device`, they travel in the SS, so they
    /// survive DR), `device_to_master` as a fallback (filled only by a direct
    /// certificate exchange, empty after DR). Zero placeholder is filtered in both
    /// branches. `None` = unknown anywhere: the caller sends nothing (dr-i8). The pair
    /// ledger keeps using `master_for_peer_device` alone (rule Д-M).
    pub fn master_for_holder(&self, device: &DeviceId) -> Result<Option<IdentityPub>, DbError> {
        if let Some(m) = self.master_for_peer_device(device)? {
            return Ok(Some(m));
        }
        Ok(self
            .get_master_for_device(device)?
            .filter(|m| m.0 != [0u8; 32]))
    }
}

#[cfg(test)]
mod tests;
