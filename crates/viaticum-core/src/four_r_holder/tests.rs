// Tests of the holder-side 4R bridge (В-0). Shared fixtures here; the cases live in
// `tests/*.rs` by area (H-1..H-4 view/quota, H-5..H-8 plan/measures, H-9..H-10 tick/record).

use super::*;
use crate::types::{
    DeviceId, FileId, HoldingRecord, HoldingStatus, IdentityPub, PairLedger, PeerRecord,
    PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};

mod offer;
mod plan_measure;
mod tick_record;
mod view_quota;

fn master(b: u8) -> IdentityPub {
    IdentityPub([b; 32])
}

/// Block `i` of owner byte `o` (distinct per owner and index; byte 0 orders blocks).
fn block(o: u8, i: u8) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[0] = i;
    id[1] = o;
    SourceBlockId(id)
}

fn holding(owner: IdentityPub, blk: SourceBlockId, bytes: u64, importance: f64) -> HoldingRecord {
    HoldingRecord {
        source_block_id: blk,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

fn notified(mut h: HoldingRecord) -> HoldingRecord {
    h.drop_notice_sent_at = Some(Timestamp(1));
    h
}

fn marked(mut h: HoldingRecord) -> HoldingRecord {
    h.status = HoldingStatus::MarkedForDelete;
    h.delete_requested_at = Some(Timestamp(1));
    h
}

fn ledger(g_they: f64, g_we: f64, depth: f64, v_dem: f64, tau: f64) -> PairLedger {
    PairLedger {
        gb_days_they_store_for_us: g_they,
        gb_days_we_store_for_them: g_we,
        depth_of_their_service: depth,
        v_dem,
        observed_volume: v_dem,
        observed_tau: tau,
        last_update: Some(Timestamp(1)),
        ..Default::default()
    }
}

fn peer(device: u8, m: IdentityPub) -> PeerRecord {
    PeerRecord {
        device_id: DeviceId([device; 32]),
        master_identity: m,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    }
}

fn placement(blk: SourceBlockId, device: u8, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: blk,
        holder_id: DeviceId([device; 32]),
        file_id: FileId(1),
        esi_ranges: vec![(0, 1)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

/// Quota inputs with an explicit soft cap and a large free disk (Q = soft).
fn soft_quota(h: &[HoldingRecord], soft: u64, hard: u64) -> QuotaInputs {
    QuotaInputs::from_holdings(h, 1 << 40, soft, 0, hard)
}

/// The S1 dials of the photo-whale scenario (`[four_r]` of the laptop L).
fn s1_params() -> FourRParams {
    FourRParams {
        enforce: false,
        v_free_gb: 0.0,
        c_recip_days: 3.0,
        w_d: 0.5,
        tau_ref_days: 365.0,
        theta_p: 0.2,
        v_min_gb: 0.002,
        hyst: crate::four_r::Hysteresis {
            s_hard: 0.05,
            s_target: 0.15,
            s_soft: 0.20,
        },
    }
}
