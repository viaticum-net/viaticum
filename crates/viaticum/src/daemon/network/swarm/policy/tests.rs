// Unit tests of the connection policy (network-i15, i41).

use libp2p::{Multiaddr, PeerId};
use viaticum_core::config::RelayRole;
use viaticum_core::types::IdentityPub;

use super::{ConnPolicy, friend_infra_peers};
use crate::daemon::network::address_book::AddressBook;
use crate::daemon::network::conn_lru::InfraRule;

fn addr(port: u16, peer: &PeerId) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
        .parse()
        .unwrap()
}

/// v3.3 NOTE: two addresses of one seed are one peer — the first two DISTINCT
/// PeerIds are infrastructure, the rest ordinary.
#[test]
fn friend_infra_is_first_two_distinct_bootstrap_peers() {
    let (seed, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
    let no_p2p: Multiaddr = "/ip4/127.0.0.1/tcp/9".parse().unwrap();
    let bootstrap = vec![
        addr(1, &seed),
        no_p2p,
        addr(2, &seed),
        addr(3, &b),
        addr(4, &c),
    ];
    assert_eq!(friend_infra_peers(&bootstrap), vec![seed, b]);
    assert!(friend_infra_peers(&[]).is_empty());
}

fn book() -> (tempfile::TempDir, AddressBook) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).expect("db");
    let device = viaticum_core::types::DeviceId([1; 32]);
    (dir, AddressBook::new(db, IdentityPub([2; 32]), device))
}

#[test]
fn relay_role_punch_selects_seed_policy() {
    let (_d, b) = book();
    let seed = PeerId::random();
    let p = ConnPolicy::for_role(RelayRole::Punch, b.clone(), &[addr(1, &seed)], 60);
    assert!(p.is_seed());
    assert_eq!(p.infra, InfraRule::AllUpTo(1024));
    assert_eq!(
        (p.cap, p.dial_on_demand, p.time_scale),
        (Some(48), true, Some(60))
    );

    let p = ConnPolicy::for_role(RelayRole::Off, b, &[addr(1, &seed)], 60);
    assert!(!p.is_seed());
    assert_eq!(p.infra, InfraRule::Peers(vec![seed]));
    assert_eq!((p.cap, p.dial_on_demand), (Some(48), true));
}

#[test]
fn policy_off_has_no_cache_no_dial_and_never_settles() {
    let p = ConnPolicy::off();
    assert_eq!((p.cap, p.dial_on_demand, p.time_scale), (None, false, None));
    assert!(p.address_book.is_none());
    assert_eq!(p.infra, InfraRule::None);
}
