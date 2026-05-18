// SyncBack core: pure logic, no network, no async.
// β version — RaptorQ, continuous importance, personal cluster.
// See docs/beta/ for design docs.

pub mod budget;
pub mod cluster;
pub mod commitment;
pub mod deletion;
pub mod config;
pub mod constants;
pub mod db;
pub mod erasure;
pub mod escrow;
pub mod messages;
pub mod path_safety;
pub mod placement;
pub mod priority;
pub mod reliability;
pub mod pos;
pub mod trust;
pub mod system_state;
pub mod types;
