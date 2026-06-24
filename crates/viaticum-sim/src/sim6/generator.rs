//! SIM-6 generator — the hidden ground-truth population.
//!
//! This is the ONLY place the hidden "is-one-farm" correlation lives. A
//! [`Sim6Holder`] carries `is_farm` (ground-truth) and the farm's subnet
//! assignment; the [`crate::sim6::observer`] shadows each holder into a
//! `FirstHandObs` that exposes ONLY the observable `addr_subnet`/`master_id`/PoS
//! surface — never `is_farm`. The address-spread in `viaticum_core::four_r::place`
//! therefore cannot key on the hidden truth; it can only see the subnet.
//!
//! The farm passes PoS honestly (its surface is indistinguishable from an honest
//! holder), so the node has NO surface signal to reject it — the only lever is the
//! observable address-subnet spread. That is the whole point of SIM-6.

use crate::generator::Rng;
use crate::sim6::Dial;

/// One holder in the hidden SIM-6 population.
#[derive(Debug, Clone)]
pub struct Sim6Holder {
    /// Distinct master-id byte (observable). The farm mints many of these cheaply.
    pub master: u32,
    /// Observable subnet / ASN proxy (first-hand at connect). Honest holders are
    /// spread across distinct subnets; the farm is confined to a small set.
    pub subnet: u32,
    /// GROUND-TRUTH: is this holder part of the synchronously-dropping farm?
    /// Read ONLY by the evaluator to score survival — never by `place`/the observer
    /// output. There is no field for it on `FirstHandObs`.
    pub is_farm: bool,
}

/// The hidden SIM-6 population: honest holders on varied subnets + an adversary
/// farm of many master-ids confined to `farm_subnets` distinct subnets.
#[derive(Debug, Clone)]
pub struct Sim6Pop {
    pub holders: Vec<Sim6Holder>,
}

impl Sim6Pop {
    /// Build the population for one dial and a chosen farm address-spread.
    ///
    /// * Honest holders: `dial.honest_holders` of them, each on its OWN subnet
    ///   (varied ASNs) and its own master-id. They never drop (honest).
    /// * Farm: `dial.farm_masters` master-ids, spread across `farm_subnets`
    ///   distinct subnets (the address-diversity the attacker pays for). All farm
    ///   holders pass PoS honestly until they drop SYNCHRONOUSLY at hour X.
    ///
    /// Subnet id-spaces are disjoint: honest subnets are `0..honest_holders`, farm
    /// subnets are `1_000_000 + (0..farm_subnets)`. Master id-spaces are disjoint
    /// too. So a farm subnet never accidentally collides with an honest one.
    ///
    /// Candidates are interleaved (farm last would let a naive greedy fill honestly
    /// first); we shuffle deterministically so ordering does not give the defender
    /// a free win — the cap, not luck, must do the work.
    pub fn build(dial: Dial, farm_subnets: usize, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut holders = Vec::new();

        // Honest holders: distinct subnet + master each.
        for i in 0..dial.honest_holders {
            holders.push(Sim6Holder {
                master: i as u32,
                subnet: i as u32,
                is_farm: false,
            });
        }

        // Farm holders: many masters, confined to `farm_subnets` subnets.
        let fs = farm_subnets.max(1);
        for j in 0..dial.farm_masters {
            holders.push(Sim6Holder {
                master: 1_000_000 + j as u32,
                subnet: 1_000_000 + (j % fs) as u32,
                is_farm: true,
            });
        }

        // Deterministic Fisher-Yates shuffle so candidate order is not adversarial
        // to either policy (the cap, not interleaving, decides the outcome).
        let n = holders.len();
        for i in (1..n).rev() {
            let j = (rng.unit() * (i + 1) as f64) as usize;
            holders.swap(i, j.min(i));
        }

        Sim6Pop { holders }
    }
}
