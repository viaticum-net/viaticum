// Library facade for integration tests and other crates.
// The binary entry point is in main.rs; this file re-exports the same modules
// so that `crates/syncback/tests/` can reference them as `syncback::...`.

pub mod cli;
pub mod daemon;
