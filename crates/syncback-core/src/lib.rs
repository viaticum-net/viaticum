// SyncBack core: pure logic, no network, no async.
// See docs/protocol/ for protocol specification.
// See ADR-003 for implementation conventions.

pub mod constants;

// Phase 1 modules (uncomment as implemented):
pub mod types;
pub mod db;
pub mod trust;
pub mod escrow;
pub mod placement;
pub mod budget;
pub mod messages;

// Test utilities (available to integration tests too)
#[cfg(any(test, feature = "testutil"))]
pub mod testutil;
