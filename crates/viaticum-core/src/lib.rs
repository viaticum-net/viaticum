// Viaticum core: pure logic, no network, no async.
// β version — RaptorQ, continuous importance, personal cluster.
// See docs/beta/ for design docs.

// Unit tests may call the erasure entry points directly (the daemon gate is clippy.toml).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod budget;
pub mod cluster;
pub mod commitment;
pub mod config;
pub mod constants;
pub mod db;
pub mod deletion;
pub mod erasure;
pub mod four_r;
pub mod four_r_holder;
pub mod importance;
pub mod mailbox;
pub mod messages;
pub mod migration;
pub mod pair_ledger;
pub mod path_safety;
pub mod placement;
pub mod pos;
pub mod priority;
pub mod reliability;
pub mod system_state;
pub mod trust;
pub mod types;
