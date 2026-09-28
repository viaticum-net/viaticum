//! The holder's 4R view (T4, З-6, З-7, З-15, Р-20, Q4): HOLDINGS + ledger rows → the kernel's
//! `OwnerEvictionView`s, their κ, and THE reverse map from every view slot back to its holding.

use std::collections::HashMap;

use super::{FourRParams, bytes_to_gb, holder_kappa, holder_view_obs};
use crate::four_r::{OwnerEvictionView, SymbolDecl, SymbolId};
use crate::types::{HoldingRecord, HoldingStatus, IdentityPub, PairLedger, SourceBlockId};

/// A holding's identity on this holder (the HOLDINGS key: block × owner master).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HoldingKey {
    pub source_block_id: SourceBlockId,
    pub owner_id: IdentityPub,
}

/// One holding as the 4R view carries it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewHolding {
    pub key: HoldingKey,
    pub bytes: u64,
    /// Owner-declared ι that arrived with the symbols.
    pub importance: f64,
}

/// The holder's view: the kernel inputs plus everything the kernel must NOT see.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderView {
    /// Owners IN the view, ascending by master bytes (Q4: the tie order of equal κ and
    /// `observed_tau`; the kernel sort is stable).
    pub masters: Vec<IdentityPub>,
    /// `views[i]` is the kernel view of `masters[i]`.
    pub views: Vec<OwnerEvictionView>,
    /// `kappa[i]` = κ_O of `masters[i]` ([`holder_kappa`]; one key for every consumer).
    pub kappa: Vec<f64>,
    /// THE reverse map (З-6): `holdings[oi][si]` ↔ `views[oi].symbols[si]` (`SymbolId(si)`);
    /// per owner sorted by block id ascending; built in the SAME loop as `views`.
    pub holdings: Vec<Vec<ViewHolding>>,
    /// Holdings with a drop notice already sent — outside the view (З-7: they are in the φ
    /// forecast already and must not be capped or pressure-dropped a second time). Ordered
    /// by (owner bytes, block bytes).
    pub notified: Vec<ViewHolding>,
    /// `MarkedForDelete` holdings without a notice — outside κ and V_parked, first in the
    /// pressure list (Р-20). Ordered by (block bytes, owner bytes).
    pub marked_for_delete: Vec<ViewHolding>,
    /// Bytes of holdings owned by this node's own master — outside the view (Р-20).
    pub own_master_bytes: u64,
}

impl HolderView {
    /// Index of `master` in the view (`None` if it has no in-view holding here).
    pub fn index_of(&self, master: &IdentityPub) -> Option<usize> {
        self.masters.iter().position(|m| m == master)
    }

    /// In-view bytes (`V_parked` in bytes) of owner `oi`.
    pub fn parked_bytes(&self, oi: usize) -> u64 {
        self.holdings[oi].iter().map(|h| h.bytes).sum()
    }
}

fn view_holding(r: &HoldingRecord) -> ViewHolding {
    ViewHolding {
        key: HoldingKey {
            source_block_id: r.source_block_id,
            owner_id: r.owner_id,
        },
        bytes: r.total_bytes,
        importance: r.importance,
    }
}

/// Build the holder view. Exclusion precedence: own master → notified → MarkedForDelete →
/// view (`Active`, `Silent`). An owner whose every holding is excluded is not in the view.
/// Owners are keyed by MASTER (`HoldingRecord.owner_id` is the master from the handshake):
/// the siblings of one master are one owner, one κ, one `V_ret` (`4r-i24`).
pub fn build_holder_view(
    holdings: &[HoldingRecord],
    ledgers: &[(IdentityPub, PairLedger)],
    own_master: &IdentityPub,
    p: &FourRParams,
) -> HolderView {
    let mut own_master_bytes = 0u64;
    let mut notified: Vec<ViewHolding> = Vec::new();
    let mut marked_for_delete: Vec<ViewHolding> = Vec::new();
    let mut by_owner: HashMap<IdentityPub, Vec<ViewHolding>> = HashMap::new();
    for r in holdings {
        if r.owner_id == *own_master {
            own_master_bytes += r.total_bytes;
        } else if r.drop_notice_sent_at.is_some() {
            notified.push(view_holding(r));
        } else if r.status == HoldingStatus::MarkedForDelete {
            marked_for_delete.push(view_holding(r));
        } else {
            by_owner
                .entry(r.owner_id)
                .or_default()
                .push(view_holding(r));
        }
    }
    notified.sort_by(|a, b| {
        (a.key.owner_id.0, a.key.source_block_id.0)
            .cmp(&(b.key.owner_id.0, b.key.source_block_id.0))
    });
    marked_for_delete.sort_by(|a, b| {
        (a.key.source_block_id.0, a.key.owner_id.0)
            .cmp(&(b.key.source_block_id.0, b.key.owner_id.0))
    });

    let rows: HashMap<&IdentityPub, &PairLedger> = ledgers.iter().map(|(m, r)| (m, r)).collect();
    let mut masters: Vec<IdentityPub> = by_owner.keys().copied().collect();
    masters.sort_by_key(|m| m.0);

    let mut views = Vec::with_capacity(masters.len());
    let mut kappa = Vec::with_capacity(masters.len());
    let mut view_holdings = Vec::with_capacity(masters.len());
    for m in &masters {
        let mut hs = by_owner.remove(m).unwrap_or_default();
        hs.sort_by_key(|h| h.key.source_block_id.0);
        let row = rows.get(m).copied();
        // Slot si of the kernel view IS hs[si]: one loop builds both (З-6).
        let symbols: Vec<SymbolDecl> = hs
            .iter()
            .enumerate()
            .map(|(si, h)| SymbolDecl {
                id: SymbolId(si as u64),
                importance: h.importance,
                volume: bytes_to_gb(h.bytes),
            })
            .collect();
        views.push(OwnerEvictionView {
            obs: holder_view_obs(row, *m),
            depth: row.map_or(0.0, |r| r.depth_of_their_service),
            symbols,
        });
        kappa.push(holder_kappa(row, p));
        view_holdings.push(hs);
    }

    HolderView {
        masters,
        views,
        kappa,
        holdings: view_holdings,
        notified,
        marked_for_delete,
        own_master_bytes,
    }
}
