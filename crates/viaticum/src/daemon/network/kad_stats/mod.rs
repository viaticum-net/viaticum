// Kademlia lookup statistics (C-DK Р-7, spec §2.4).
//
// A lookup that ends with `Ok([])` looks the same whether the seed's answer was
// too large to decode (H1), the seed was overloaded (H2), its inbound substream
// limit was hit (H3) or our table was empty (H4). The request/success/failure
// counters and the duration of the lookup tell them apart, so every finished
// get_closest_peers logs them (DEBUG) and an empty result from a non-empty table
// is a WARN at most once per EMPTY_LOOKUP_WARN_EVERY.

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

/// Minimum spacing of the WARN "kademlia lookup found no peers" (10 min).
pub(crate) const EMPTY_LOOKUP_WARN_EVERY: Duration = Duration::from_secs(600);

/// Counters of one finished Kademlia lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LookupStats {
    /// Requests the lookup sent (0 = the table was empty when it started, H4).
    pub(crate) requests: u32,
    /// Requests answered with a decodable response.
    pub(crate) successes: u32,
    /// Requests that failed (an oversized answer is a failure, H1).
    pub(crate) failures: u32,
    /// Wall time of the lookup in ms; 0 when it never started.
    pub(crate) duration_ms: u64,
}

impl LookupStats {
    /// Read the counters libp2p kept for the query.
    pub(crate) fn from_query(stats: &libp2p::kad::QueryStats) -> Self {
        LookupStats {
            requests: stats.num_requests(),
            successes: stats.num_successes(),
            failures: stats.num_failures(),
            duration_ms: stats.duration().map_or(0, |d| d.as_millis() as u64),
        }
    }
}

/// True when a lookup deserves the WARN: the routing table had peers, the
/// lookup found none, and no such WARN was logged in the last
/// [`EMPTY_LOOKUP_WARN_EVERY`] (`last` = when the previous one was).
pub(crate) fn empty_lookup_warn_due(
    last: Option<Instant>,
    now: Instant,
    table_entries: usize,
    found: usize,
) -> bool {
    if table_entries == 0 || found > 0 {
        return false;
    }
    match last {
        None => true,
        Some(t) => now.saturating_duration_since(t) >= EMPTY_LOOKUP_WARN_EVERY,
    }
}
