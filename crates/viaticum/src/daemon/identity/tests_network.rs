// The `[network]` of the init template (R2a: Р2-0, network-i28, i31): `init`
// writes a working network — a fixed random port, the default seeds — not the
// inert struct defaults.

use viaticum_core::config::AppConfig;
use viaticum_core::constants::{DEFAULT_SEEDS, LISTEN_PORT_RANGE};

use super::{default_config_toml, init_identity, write_default_config_if_absent};
use crate::daemon::network::listen_port::is_denied;

fn network_after_init(dir: &std::path::Path) -> viaticum_core::config::NetworkCfg {
    AppConfig::load(&dir.join("config.toml"))
        .expect("the daemon loads the init config")
        .network
}

// Mutation: the template without `listen_port` (or with 0) → the node is inert
// or changes port on every start, test red.
#[test]
fn init_template_network_is_production() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path()).expect("init");
    let net = network_after_init(dir.path());
    assert!(
        LISTEN_PORT_RANGE.contains(&net.listen_port),
        "listen_port {} not in {LISTEN_PORT_RANGE:?}",
        net.listen_port
    );
    assert!(
        !is_denied(net.listen_port),
        "{} is denylisted",
        net.listen_port
    );
    let seeds: Vec<&str> = net
        .kademlia_bootstrap_peers
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(seeds, DEFAULT_SEEDS, "init writes the default seeds");
    assert!(!net.is_inert(), "an init node is not inert");
}

// Mutation: write_default_config_if_absent re-renders an existing config → the
// port changes under a forwarded router rule, test red.
#[test]
fn init_picks_port_in_range_and_persists_it() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path()).expect("init");
    let port = network_after_init(dir.path()).listen_port;
    assert!(LISTEN_PORT_RANGE.contains(&port));
    // DR over this data dir, a later default write: the port stays.
    write_default_config_if_absent(dir.path()).expect("write if absent");
    assert_eq!(network_after_init(dir.path()).listen_port, port);
}

// The seeds render in their order (QUIC address before TCP, network-i28) and
// load back verbatim, DNS names included.
#[test]
fn default_config_renders_seeds_in_order() {
    let seeds = [
        "/dns4/seed.lab/udp/27210/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        "/dns4/seed.lab/tcp/27210/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
    ];
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        default_config_toml(23817, &seeds),
    )
    .unwrap();
    let net = network_after_init(dir.path());
    assert_eq!(net.listen_port, 23817);
    assert_eq!(net.kademlia_bootstrap_peers, seeds);
}
