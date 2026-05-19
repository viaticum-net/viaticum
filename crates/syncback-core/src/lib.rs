// SyncBack core: pure logic, no network, no async.
// β version — RaptorQ, continuous importance, personal cluster.
// See docs/beta/ for design docs.

pub mod budget;
pub mod cluster;
pub mod commitment;
pub mod config;
pub mod constants;
pub mod db;
pub mod deletion;
pub mod erasure;
pub mod escrow;
pub mod importance;
pub mod messages;
pub mod migration;
pub mod path_safety;
pub mod placement;
pub mod pos;
pub mod priority;
pub mod reliability;
pub mod system_state;
pub mod trust;
pub mod types;
