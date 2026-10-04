//! Catalog history ("lineage") of a node's DB, and which catalog DR restores.
//!
//! Every DB is its own history: a daemon mints a random id the first time it needs
//! one (first pointer push), and DR mints a NEW one for the DB it restores (the id is
//! kept in the DB's meta table, which is not part of the SystemState snapshot, so it
//! can never travel with the restored state). Nobody inherits an id, so two
//! installations of one identity (the lost machine and a shadow `init --mnemonic`
//! node, or a DR node left running) never look like one history.
//!
//! Every SelfPointer carries a signed [`CatalogSummary`]: the history, the device that
//! published it, and the number of live files its state holds.
//!
//! **The choice (spec B2 slice B2.2a, temporary rule).** Inside one history the freshest
//! pointer wins. If DR finds exactly one history it restores it; if it finds more than
//! one it does NOT choose: it lists them all and requires `--catalog <prefix>`. There is
//! no silent wrong choice by construction; the price is one extra step when several
//! histories exist. Whether some cases can be decided automatically is open (B2.2b).

use crate::mailbox::seal::PointerPlace;
use crate::system_state::SelfPointer;
use crate::types::{DeviceId, FileRecord, LocalState, SourceBlockId, Timestamp, hex_encode};

#[cfg(test)]
mod tests;

/// Minimum length of a `--catalog` hex prefix.
pub const MIN_CATALOG_PREFIX_LEN: usize = 8;

/// Random id of one catalog history (one DB).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct CatalogLineageId(pub [u8; 16]);

impl CatalogLineageId {
    /// 16 random bytes from the OS RNG.
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        CatalogLineageId(b)
    }

    /// Lowercase hex of all 16 bytes (32 chars).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl std::fmt::Display for CatalogLineageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Signed summary of the catalog a SelfPointer restores. Covered by the pointer's
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogSummary {
    /// The history (DB) this pointer belongs to.
    pub lineage: CatalogLineageId,
    /// Device that published this pointer. DR rewrites this device to its own in every
    /// restored `FileRecord` (dr-i19).
    pub publisher: DeviceId,
    /// [`live_file_count`] of the state this pointer reconstructs (base + listed diffs):
    /// the same number `dr` prints as `Files:`.
    pub files: u32,
}

/// A file is live unless it is recorded as deleted on EVERY device it was seen on.
/// Shared predicate for `CatalogSummary.files`, DR's `Files:` and status
/// `files_without_source`.
pub fn is_live_file(f: &FileRecord) -> bool {
    f.devices.is_empty()
        || !f
            .devices
            .iter()
            .all(|(_, s)| matches!(s, LocalState::Deleted(_)))
}

/// Number of live files (see [`is_live_file`]).
pub fn live_file_count(files: &[FileRecord]) -> u32 {
    files.iter().filter(|f| is_live_file(f)).count() as u32
}

/// dr-i19. In every record replace the entry of `lost` by `new`, keeping its state.
/// If `new` already has an entry in the same record it is removed first: the lost
/// device's entry is the history's own state. Other devices (cluster siblings) are
/// untouched. `lost == new` → no-op. Returns the number of records changed.
pub fn reassign_history_device(files: &mut [FileRecord], lost: DeviceId, new: DeviceId) -> usize {
    if lost == new {
        return 0;
    }
    let mut changed = 0;
    for f in files.iter_mut() {
        if !f.devices.iter().any(|(d, _)| *d == lost) {
            continue;
        }
        f.devices.retain(|(d, _)| *d != new);
        for (d, _) in f.devices.iter_mut() {
            if *d == lost {
                *d = new;
            }
        }
        changed += 1;
    }
    changed
}

/// One place of this history's pointer at the postmen, as the owner last sealed it
/// (CROWN-1 V.16.3, mailbox-i50..i56). Written to META BEFORE the envelope is sent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PlacePublication {
    /// Which of the two places; never derived from `generation`.
    pub place: PointerPlace,
    /// The base block of the pointer.
    pub base: SourceBlockId,
    /// The diff blocks the pointer lists (its placed prefix).
    pub diffs: Vec<SourceBlockId>,
    pub generation: u32,
    /// The pointer's `created_at` (= the envelope's `stored_at`).
    pub created_at: Timestamp,
    /// Live files of the state the pointer restores.
    pub files: u32,
    /// Distinct postmen that acked THIS envelope, accumulated over re-offers (≤ 64).
    pub acks: Vec<DeviceId>,
    /// CBOR of the sealed `MailboxEntry` as sent: re-offered byte-identical, also after
    /// a restart (mailbox-i47, i53).
    #[serde(with = "serde_bytes")]
    pub entry_cbor: Vec<u8>,
    /// Store signature of the envelope by the rendezvous box key.
    #[serde(with = "crate::types::sig_serde")]
    pub target_sig: [u8; 64],
    /// The last publication of this envelope that no postman acked (V.15.3, V.17.4);
    /// cleared by an ack.
    pub last_refusal: Option<PointerRefusal>,
    /// Bases (with their diffs) displaced out of THIS place, retired once this record
    /// has the dr-i39 number of acks (V.17.2). At most one waits: when a second one
    /// would join, the older is retired at once (its place was replaced twice).
    pub to_retire: Vec<RetiredPointer>,
    /// dr-i52: the last earlier envelope of this place AND this base that reached the
    /// dr-i39 threshold, kept while this envelope has fewer acks; DR readiness counts
    /// it until then (a new envelope starts with no acks, readiness must not blink).
    /// `None` after a change of base in the place and once this envelope reaches the
    /// threshold.
    #[serde(default)]
    pub reached: Option<ReachedEnvelope>,
}

/// An earlier envelope of a place (same base) that reached the dr-i39 threshold
/// (dr-i52). The postmen that acked it keep it until they accept a newer one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReachedEnvelope {
    /// The diff blocks its pointer lists.
    pub diffs: Vec<SourceBlockId>,
    pub generation: u32,
    /// Its pointer's `created_at`.
    pub created_at: Timestamp,
    /// Live files of the state it restores.
    pub files: u32,
    /// Distinct postmen that acked it.
    pub acks: u32,
    /// Its envelope's `expires_at`: after that the postmen no longer hold it.
    pub expires_at: u64,
}

/// A base and its diffs displaced out of a place, waiting to be retired locally.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetiredPointer {
    pub base: SourceBlockId,
    pub diffs: Vec<SourceBlockId>,
}

/// Why no postman acked a publication (V.15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RefusalKind {
    /// Every refusal was a clock skew: this computer's clock looks wrong.
    ClockSkew,
    /// Every refusal was "a newer pointer is held": the clock went back.
    Superseded,
    /// Every refusal was "no free place": 64 installations of this phrase.
    SlotsFull,
    /// Refusals of different reasons.
    Mixed {
        clock: u32,
        superseded: u32,
        slots_full: u32,
        other: u32,
    },
    /// Nobody answered.
    NoAck,
}

/// The last refused publication of one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointerRefusal {
    /// Unix secs of the refused attempt.
    pub at: u64,
    pub kind: RefusalKind,
    /// mailbox-i61: every refusal was "expired in transit" (`kind` is then `NoAck`, no
    /// clock verdict). Nobody holds the envelope: the publisher seals a new one, as
    /// after an all-`ClockSkew` refusal.
    #[serde(default)]
    pub expired: bool,
}

/// Why the newest catalog state is not in any accepted pointer (mailbox-i54).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WaitingReason {
    /// The catalog blocks (base or newest diffs) have no live holder yet.
    BlocksNotPlaced,
    /// Postmen refused the pointer (see the place's `last_refusal`).
    Refused,
    /// No postman answered.
    NoAck,
}

/// Since when the newest catalog state waits to enter the network, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Waiting {
    pub since: u64,
    pub reason: WaitingReason,
}

/// META of this history's pointer places (`pointer_publication_v2`, V.16.3): one record
/// per place, the newest base in `current`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PointerPublications {
    pub lineage: CatalogLineageId,
    /// The place of the newest base (diff pointers of it replace this record).
    pub current: Option<PlacePublication>,
    /// The other place: the previous base, or a stronger older one.
    pub other: Option<PlacePublication>,
    /// Set while the newest catalog state is in no accepted pointer (mailbox-i54).
    pub waiting: Option<Waiting>,
}

impl PointerPublications {
    /// No place used yet.
    pub fn new(lineage: CatalogLineageId) -> Self {
        PointerPublications {
            lineage,
            current: None,
            other: None,
            waiting: None,
        }
    }

    /// The record in `place`, if any.
    pub fn in_place(&self, place: PointerPlace) -> Option<&PlacePublication> {
        [self.current.as_ref(), self.other.as_ref()]
            .into_iter()
            .flatten()
            .find(|r| r.place == place)
    }

    /// The newest record at least one postman acked: `current` if acked, else `other`.
    pub fn newest_accepted(&self) -> Option<&PlacePublication> {
        [self.current.as_ref(), self.other.as_ref()]
            .into_iter()
            .flatten()
            .find(|r| !r.acks.is_empty())
    }
}

/// One history as DR lists it: its head (freshest pointer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageRow {
    pub lineage: CatalogLineageId,
    /// `catalog.files` of the head.
    pub files: u32,
    /// `created_at` of the head.
    pub created_at: Timestamp,
    /// `generation` of the head.
    pub generation: u32,
    /// `catalog.publisher` of the head.
    pub publisher: DeviceId,
    /// Distinct pointers (by signature) seen for this history.
    pub pointers_seen: usize,
}

/// Why DR restores the catalog it restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChoiceReason {
    /// Exactly one history was found.
    OnlyCatalog,
    /// `--catalog <prefix>` named it.
    Requested,
}

/// Result of [`select_catalog`].
#[derive(Debug, Clone)]
pub struct CatalogChoice {
    /// The head (freshest pointer) of the chosen history.
    pub selected: SelfPointer,
    /// dr-i35: the OTHER pointers of the chosen history, freshest first. DR falls back
    /// to them when the head's state cannot be fetched.
    pub fallbacks: Vec<SelfPointer>,
    pub reason: ChoiceReason,
    /// All histories: the selected one first, then the others freshest first.
    pub rows: Vec<LineageRow>,
}

/// Why DR did not choose a catalog. Rows (freshest first) are for the table DR prints.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CatalogSelectError {
    #[error("no catalog")]
    Empty,
    #[error("--catalog must be at least {MIN_CATALOG_PREFIX_LEN} hex characters, got {prefix:?}")]
    BadPrefix {
        prefix: String,
        rows: Vec<LineageRow>,
    },
    #[error("no catalog starts with {prefix}")]
    NoMatch {
        prefix: String,
        rows: Vec<LineageRow>,
    },
    #[error("more than one catalog starts with {prefix}; give more characters")]
    Ambiguous {
        prefix: String,
        rows: Vec<LineageRow>,
    },
    #[error(
        "{} catalogs were found for this recovery phrase (listed above). DR does not choose \
         between them: pick the one to restore with --catalog <first 8 hex>",
        rows.len()
    )]
    NeedsChoice { rows: Vec<LineageRow> },
}

impl CatalogSelectError {
    /// The rows to print before the error text (empty for `Empty` and for a prefix
    /// rejected before any pointer was seen).
    pub fn rows(&self) -> &[LineageRow] {
        match self {
            CatalogSelectError::NoMatch { rows, .. }
            | CatalogSelectError::Ambiguous { rows, .. }
            | CatalogSelectError::BadPrefix { rows, .. }
            | CatalogSelectError::NeedsChoice { rows } => rows,
            CatalogSelectError::Empty => &[],
        }
    }
}

/// Normalize a `--catalog` value (trim, lowercase) and check its form: at least
/// `MIN_CATALOG_PREFIX_LEN` hex characters. DR calls it before the network phase (N4),
/// so a malformed value costs no network time.
pub fn check_catalog_prefix(requested: &str) -> Result<String, CatalogSelectError> {
    let prefix = requested.trim().to_ascii_lowercase();
    if prefix.len() < MIN_CATALOG_PREFIX_LEN || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CatalogSelectError::BadPrefix {
            prefix,
            rows: vec![],
        });
    }
    Ok(prefix)
}

/// Choose the catalog DR restores (temporary rule of slice B2.2a).
///
/// `pointers` MUST already be signature-verified against the master identity;
/// duplicates are tolerated (counted once, by signature).
///
///   1. group by `catalog.lineage`; each history is represented by its head, the
///      freshest pointer by `(created_at, generation)`;
///   2. `requested = Some(prefix)` (≥ 8 hex chars, case-insensitive, exactly one history
///      starts with it) → that history, whatever else was found;
///   3. otherwise exactly one history → it; more than one → `NeedsChoice` with all rows.
///
/// The chosen history's other pointers come back as `fallbacks`, freshest first.
pub fn select_catalog(
    pointers: Vec<SelfPointer>,
    requested: Option<&str>,
) -> Result<CatalogChoice, CatalogSelectError> {
    // 1. Pointers per history (dedup by signature).
    let mut groups: Vec<(LineageRow, Vec<SelfPointer>)> = Vec::new();
    let mut seen_sigs: std::collections::HashSet<[u8; 64]> = std::collections::HashSet::new();
    for p in pointers {
        if !seen_sigs.insert(p.signature) {
            continue;
        }
        let lineage = p.catalog.lineage;
        match groups.iter_mut().find(|(r, _)| r.lineage == lineage) {
            Some((row, list)) => {
                row.pointers_seen += 1;
                list.push(p);
            }
            None => {
                let row = LineageRow {
                    lineage,
                    files: 0,
                    created_at: Timestamp(0),
                    generation: 0,
                    publisher: p.catalog.publisher,
                    pointers_seen: 1,
                };
                groups.push((row, vec![p]));
            }
        }
    }
    if groups.is_empty() {
        return Err(CatalogSelectError::Empty);
    }
    // Inside each history: freshest first; the head describes the row.
    for (row, list) in groups.iter_mut() {
        list.sort_by(|a, b| {
            (b.created_at, b.generation, b.signature).cmp(&(
                a.created_at,
                a.generation,
                a.signature,
            ))
        });
        set_head(row, &list[0]);
    }
    // Histories freshest first; the lineage id breaks exact ties so the order is stable.
    groups.sort_by(|(a, _), (b, _)| {
        (b.created_at, b.generation, b.lineage).cmp(&(a.created_at, a.generation, a.lineage))
    });
    let rows: Vec<LineageRow> = groups.iter().map(|(r, _)| r.clone()).collect();

    // 2. Explicit choice.
    if let Some(requested) = requested {
        let prefix = match check_catalog_prefix(requested) {
            Ok(p) => p,
            Err(CatalogSelectError::BadPrefix { prefix, .. }) => {
                return Err(CatalogSelectError::BadPrefix { prefix, rows });
            }
            Err(e) => return Err(e),
        };
        let matches: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.lineage.to_hex().starts_with(&prefix))
            .map(|(i, _)| i)
            .collect();
        return match matches.as_slice() {
            [i] => Ok(choice(groups, *i, ChoiceReason::Requested)),
            [] => Err(CatalogSelectError::NoMatch { prefix, rows }),
            _ => Err(CatalogSelectError::Ambiguous { prefix, rows }),
        };
    }

    // 3. One history → it; several → the user chooses.
    if groups.len() == 1 {
        return Ok(choice(groups, 0, ChoiceReason::OnlyCatalog));
    }
    Err(CatalogSelectError::NeedsChoice { rows })
}

fn set_head(row: &mut LineageRow, p: &SelfPointer) {
    row.files = p.catalog.files;
    row.created_at = p.created_at;
    row.generation = p.generation;
    row.publisher = p.catalog.publisher;
}

/// Build the choice for `groups[index]`: rows with the selected one first.
fn choice(
    mut groups: Vec<(LineageRow, Vec<SelfPointer>)>,
    index: usize,
    reason: ChoiceReason,
) -> CatalogChoice {
    let (row, mut list) = groups.remove(index);
    let selected = list.remove(0);
    let mut rows = Vec::with_capacity(groups.len() + 1);
    rows.push(row);
    rows.extend(groups.into_iter().map(|(r, _)| r));
    CatalogChoice {
        selected,
        fallbacks: list,
        reason,
        rows,
    }
}
