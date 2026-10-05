// Unit tests may call the erasure entry points directly (the gate is clippy.toml).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod build_info;
pub mod cli;
pub mod daemon;
pub mod http_client;
