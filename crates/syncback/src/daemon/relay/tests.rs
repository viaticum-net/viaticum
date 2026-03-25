// Relay module tests.
//
// Pattern: what_when_then
// All tests are synchronous (no tokio runtime needed for unit tests).

use rand::rngs::OsRng;
use syncback_core::constants::{MAX_BOARD_ENTRIES, MAX_BOARD_SIZE_BYTES, RELAY_TTL_SECS};
use syncback_core::cluster::{
    issue_device_certificate, issue_revocation, verify_device_certificate, verify_revocation,
    EpochCounter,
};
use syncback_core::messages::{
    build_broadcast_entry, build_directed_entry, encrypt_directed, from_cbor, to_cbor,
    BoardEntryKind, RevocationBroadcast, StoredEntry,
};
use syncback_core::types::{DeviceId, IdentityPub, Timestamp};
use tempfile::TempDir;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use super::{RelayConfig, RelayManager};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn make_config(dir: &TempDir) -> RelayConfig {
    RelayConfig::defaults_for_test(dir.path().join("board.bin"))
}

fn make_identity() -> (ed25519_dalek::SigningKey, IdentityPub) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    (signing_key, identity_pub)
}

fn make_x25519() -> (StaticSecret, X25519Pub) {
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = X25519Pub::from(&priv_key);
    (priv_key, pub_key)
}

// Build a valid broadcast StoredEntry authored by a given key.
fn make_broadcast_entry(
    signing_key: &ed25519_dalek::SigningKey,
    identity: IdentityPub,
    msg_type: &str,
    msg_id: [u8; 16],
    now: Timestamp,
) -> StoredEntry {
    let entry = build_broadcast_entry(
        msg_type,
        msg_id,
        b"test payload".to_vec(),
        identity,
        now,
        signing_key,
    );
    StoredEntry {
        msg_type: msg_type.to_string(),
        msg_id,
        entry,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn post_broadcast_appends_to_board() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let msg_id = [0u8; 16];
    let payload = b"hello world".to_vec();
    let entry = manager
        .post_broadcast("peer_announce", msg_id, payload.clone(), Timestamp(1000))
        .unwrap();

    assert_eq!(entry.msg_id, msg_id);
    assert_eq!(entry.entry.hop, 0);
    assert_eq!(entry.entry.kind, BoardEntryKind::Broadcast);
    assert_eq!(manager.stats().0, 1);
}

#[test]
fn post_broadcast_persists_to_disk() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);

    {
        let mut manager = RelayManager::new(config.clone()).unwrap();
        manager
            .post_broadcast("peer_announce", [0u8; 16], b"data".to_vec(), Timestamp(1000))
            .unwrap();
        assert_eq!(manager.stats().0, 1);
    }

    // Reload from same path.
    // Disable startup prune by using a timestamp of 0 (nothing expired).
    // However RelayManager::new uses Timestamp::now() for startup prune,
    // and our entry has created_at = 1000, which would be far in the past
    // from real system time. So we need a very recent timestamp.
    // Workaround: create a fresh entry with Timestamp::now().
    let now = Timestamp::now();
    let config2 = make_config(&dir);
    {
        let mut manager = RelayManager::new(config2.clone()).unwrap();
        // Post with current time so startup prune doesn't delete it.
        manager
            .post_broadcast("peer_announce", [1u8; 16], b"data".to_vec(), now)
            .unwrap();
    }
    let manager2 = RelayManager::new(config2).unwrap();
    assert_eq!(manager2.stats().0, 1);
}

#[test]
fn post_directed_encrypts_payload() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (target_priv, target_x25519_pub) = make_x25519();
    let target_identity = IdentityPub([3u8; 32]);
    let _ = target_priv; // recipient has the private key

    let msg_id = [1u8; 16];
    let plaintext = b"secret message";

    let stored = manager
        .post_directed_with_key(
            "pos_challenge",
            msg_id,
            target_identity,
            &target_x25519_pub,
            plaintext,
            Timestamp(1000),
        )
        .unwrap();

    assert_eq!(stored.entry.kind, BoardEntryKind::Directed);
    assert_eq!(stored.entry.target_pub, Some(target_identity));
    // Payload must not be the raw plaintext (it's encrypted).
    assert_ne!(stored.entry.payload.as_slice(), plaintext);
}

#[test]
fn process_remote_entries_accepts_valid_hop0_entry_as_hop1() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (partner_key, partner_identity) = make_identity();
    let remote = make_broadcast_entry(&partner_key, partner_identity, "peer_announce", [2u8; 16], Timestamp(500));

    let count = manager
        .process_remote_entries(&[remote], Timestamp(1000))
        .unwrap();

    assert_eq!(count, 1);
    assert_eq!(manager.stats().0, 1);
    assert_eq!(manager.entries[0].entry.hop, 1);
}

#[test]
fn process_remote_entries_deduplicates_known_msg_id() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (partner_key, partner_identity) = make_identity();
    let msg_id = [3u8; 16];
    let remote = make_broadcast_entry(&partner_key, partner_identity, "peer_announce", msg_id, Timestamp(500));

    let count1 = manager
        .process_remote_entries(&[remote.clone()], Timestamp(1000))
        .unwrap();
    let count2 = manager
        .process_remote_entries(&[remote], Timestamp(1000))
        .unwrap();

    assert_eq!(count1, 1);
    assert_eq!(count2, 0);
    assert_eq!(manager.stats().0, 1);
}

#[test]
fn process_remote_entries_rejects_expired_entry() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (partner_key, partner_identity) = make_identity();
    // Created 8 days ago (> 7-day TTL).
    let remote = make_broadcast_entry(
        &partner_key,
        partner_identity,
        "peer_announce",
        [4u8; 16],
        Timestamp(1000),
    );

    let now = Timestamp(1000 + RELAY_TTL_SECS + 1);
    let count = manager.process_remote_entries(&[remote], now).unwrap();

    assert_eq!(count, 0);
    assert_eq!(manager.stats().0, 0);
}

#[test]
fn process_remote_entries_rejects_hop2_entry() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (partner_key, partner_identity) = make_identity();
    let mut remote = make_broadcast_entry(
        &partner_key,
        partner_identity,
        "peer_announce",
        [5u8; 16],
        Timestamp(500),
    );
    // Force hop=2 (beyond limit).
    remote.entry.hop = 2;

    let count = manager
        .process_remote_entries(&[remote], Timestamp(1000))
        .unwrap();

    assert_eq!(count, 0);
}

#[test]
fn process_remote_entries_rejects_bad_signature() {
    let dir = TempDir::new().unwrap();
    let mut manager = RelayManager::new(make_config(&dir)).unwrap();

    let (partner_key, partner_identity) = make_identity();
    let mut remote = make_broadcast_entry(
        &partner_key,
        partner_identity,
        "peer_announce",
        [6u8; 16],
        Timestamp(500),
    );
    // Corrupt the signature.
    remote.entry.sig_author[0] ^= 0xFF;

    let count = manager
        .process_remote_entries(&[remote], Timestamp(1000))
        .unwrap();

    assert_eq!(count, 0);
}

#[test]
fn scan_for_self_delivers_directed_message() {
    let dir = TempDir::new().unwrap();

    let (our_x25519_priv, our_x25519_pub) = make_x25519();
    let (our_signing_key, our_identity) = make_identity();

    let config = RelayConfig {
        board_path: dir.path().join("board.bin"),
        identity_pub: our_identity,
        x25519_priv: our_x25519_priv,
        signing_key: our_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager = RelayManager::new(config).unwrap();

    // Sender builds a directed message to us.
    let (sender_key, sender_identity) = make_identity();
    let plaintext = b"pos_challenge_payload";

    // Encrypt for us.
    let envelope = encrypt_directed(plaintext, &our_x25519_pub).unwrap();
    let envelope_cbor = to_cbor(&envelope).unwrap();

    let entry = build_directed_entry(
        "pos_challenge",
        [5u8; 16],
        our_identity,
        envelope_cbor,
        sender_identity,
        Timestamp(1000),
        &sender_key,
    );
    manager.entries.push(StoredEntry {
        msg_type: "pos_challenge".to_string(),
        msg_id: [5u8; 16],
        entry,
    });

    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);
    let count = manager.scan_for_self(&inbound_tx, Timestamp(2000));

    assert_eq!(count, 1);
    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.payload, plaintext);
    assert_eq!(msg.from, sender_identity);
    assert_eq!(msg.msg_type, "pos_challenge");
}

#[test]
fn scan_for_self_ignores_directed_to_other() {
    let dir = TempDir::new().unwrap();

    let (our_x25519_priv, _our_x25519_pub) = make_x25519();
    let (our_signing_key, our_identity) = make_identity();

    let config = RelayConfig {
        board_path: dir.path().join("board.bin"),
        identity_pub: our_identity,
        x25519_priv: our_x25519_priv,
        signing_key: our_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager = RelayManager::new(config).unwrap();

    // Entry directed to someone else.
    let (sender_key, sender_identity) = make_identity();
    let other_identity = IdentityPub([99u8; 32]);
    let entry = build_directed_entry(
        "pos_challenge",
        [6u8; 16],
        other_identity,
        vec![0u8; 32], // fake encrypted payload
        sender_identity,
        Timestamp(1000),
        &sender_key,
    );
    manager.entries.push(StoredEntry {
        msg_type: "pos_challenge".to_string(),
        msg_id: [6u8; 16],
        entry,
    });

    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);
    let count = manager.scan_for_self(&inbound_tx, Timestamp(2000));

    assert_eq!(count, 0);
    assert!(inbound_rx.try_recv().is_err());
}

#[test]
fn scan_for_self_delivers_broadcast_entries() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let (our_identity, our_signing_key) = (config.identity_pub, config.signing_key.clone());
    let mut manager = RelayManager::new(config).unwrap();

    // Add a broadcast entry.
    let (sender_key, sender_identity) = make_identity();
    let entry = build_broadcast_entry(
        "peer_announce",
        [7u8; 16],
        b"broadcast_data".to_vec(),
        sender_identity,
        Timestamp(1000),
        &sender_key,
    );
    let _ = our_identity;
    let _ = our_signing_key;
    manager.entries.push(StoredEntry {
        msg_type: "peer_announce".to_string(),
        msg_id: [7u8; 16],
        entry,
    });

    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);
    let count = manager.scan_for_self(&inbound_tx, Timestamp(2000));

    assert_eq!(count, 1);
    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.payload, b"broadcast_data");
    assert_eq!(msg.msg_type, "peer_announce");
}

#[test]
fn prune_removes_expired_entries() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let now_real = Timestamp::now();

    let mut manager = RelayManager::new(config.clone()).unwrap();

    // Entries far in the future so they survive startup prune.
    // Then we'll use a "now" value that makes two of them expired.
    let base = now_real.0 + 1_000_000; // 1M seconds in future

    // Two entries created at `base`, one far in the future.
    // At `base + RELAY_TTL_SECS + 1`, the first two expire; the third survives.
    manager
        .post_broadcast("a", [0u8; 16], b"x".to_vec(), Timestamp(base))
        .unwrap();
    manager
        .post_broadcast("a", [1u8; 16], b"x".to_vec(), Timestamp(base))
        .unwrap();
    manager
        .post_broadcast("a", [2u8; 16], b"x".to_vec(), Timestamp(base + 2_000_000))
        .unwrap();

    assert_eq!(manager.stats().0, 3);

    // Now = base + TTL + 1 → first two entries expired, third still valid.
    let prune_now = Timestamp(base + RELAY_TTL_SECS + 1);
    let pruned = manager.prune(prune_now).unwrap();

    assert_eq!(pruned, 2);
    assert_eq!(manager.stats().0, 1);
}

#[test]
fn prune_respects_max_entries_limit() {
    let dir = TempDir::new().unwrap();
    let config = RelayConfig {
        board_path: dir.path().join("board.bin"),
        max_entries: 10,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        ..RelayConfig::defaults_for_test(dir.path().join("board.bin"))
    };
    let now_real = Timestamp::now();
    let base = now_real.0 + 1_000_000;

    let mut manager = RelayManager::new(config).unwrap();

    for i in 0u8..15 {
        manager
            .post_broadcast(
                "peer_announce",
                [i; 16],
                b"x".to_vec(),
                Timestamp(base + i as u64),
            )
            .unwrap();
    }

    assert_eq!(manager.stats().0, 15);

    // Nothing expired yet.
    let prune_now = Timestamp(base + 2000);
    manager.prune(prune_now).unwrap();

    assert!(manager.stats().0 <= 10);
}

#[test]
fn entries_for_sync_excludes_expired() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let now_real = Timestamp::now();
    let base = now_real.0 + 1_000_000;

    let mut manager = RelayManager::new(config).unwrap();

    manager
        .post_broadcast("a", [0u8; 16], b"x".to_vec(), Timestamp(base))
        .unwrap();
    manager
        .post_broadcast("a", [1u8; 16], b"x".to_vec(), Timestamp(base + 2_000_000))
        .unwrap();

    // First entry expires, second doesn't.
    let sync_now = Timestamp(base + RELAY_TTL_SECS + 1);
    let entries = manager.entries_for_sync(sync_now);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry.created_at, Timestamp(base + 2_000_000));
}

#[test]
fn board_survives_reload() {
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let now_real = Timestamp::now();
    let base = now_real.0 + 1_000_000; // far future to survive startup prune

    {
        let mut manager = RelayManager::new(config.clone()).unwrap();
        for i in 0u8..5 {
            manager
                .post_broadcast(
                    "peer_announce",
                    [i; 16],
                    b"payload".to_vec(),
                    Timestamp(base + i as u64),
                )
                .unwrap();
        }
        assert_eq!(manager.stats().0, 5);
    }

    // Reload.
    let manager2 = RelayManager::new(config).unwrap();
    assert_eq!(manager2.stats().0, 5);
}

#[test]
fn relay_three_hop_propagation() {
    // Gate test: A posts → B relays (hop 0→1) → C reads from B (hop 1→2).
    // Then D tries to relay from C — should be rejected (hop=2 at limit).

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();
    let dir_d = TempDir::new().unwrap();

    let now = Timestamp::now();
    let future = Timestamp(now.0 + 1_000_000);

    // ── A: setup ────────────────────────────────────────────────────────
    let (a_signing_key, a_identity) = make_identity();
    let (c_x25519_priv, c_x25519_pub) = make_x25519();
    let (_, c_identity) = make_identity();

    let config_a = RelayConfig {
        board_path: dir_a.path().join("board.bin"),
        identity_pub: a_identity,
        x25519_priv: StaticSecret::random_from_rng(OsRng),
        signing_key: a_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_a = RelayManager::new(config_a).unwrap();

    let msg_id = [7u8; 16];
    manager_a
        .post_directed_with_key(
            "pos_challenge",
            msg_id,
            c_identity,
            &c_x25519_pub,
            b"challenge_data",
            future,
        )
        .unwrap();

    // ── B: sync from A ──────────────────────────────────────────────────
    let (b_signing_key, b_identity) = make_identity();
    let config_b = RelayConfig {
        board_path: dir_b.path().join("board.bin"),
        identity_pub: b_identity,
        x25519_priv: StaticSecret::random_from_rng(OsRng),
        signing_key: b_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_b = RelayManager::new(config_b).unwrap();

    let a_entries = manager_a.entries_for_sync(future);
    assert_eq!(a_entries.len(), 1);
    assert_eq!(a_entries[0].entry.hop, 0);

    let accepted = manager_b
        .process_remote_entries(&a_entries, future)
        .unwrap();
    assert_eq!(accepted, 1);
    assert_eq!(manager_b.entries[0].entry.hop, 1);

    // ── C: sync from B ──────────────────────────────────────────────────
    let (c_signing_key, _) = make_identity();
    let config_c = RelayConfig {
        board_path: dir_c.path().join("board.bin"),
        identity_pub: c_identity,
        x25519_priv: c_x25519_priv,
        signing_key: c_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_c = RelayManager::new(config_c).unwrap();

    let b_entries = manager_b.entries_for_sync(future);
    assert_eq!(b_entries.len(), 1);
    assert_eq!(b_entries[0].entry.hop, 1);

    let accepted = manager_c
        .process_remote_entries(&b_entries, future)
        .unwrap();
    assert_eq!(accepted, 1);
    assert_eq!(manager_c.entries[0].entry.hop, 2);

    // ── C reads directed message ─────────────────────────────────────────
    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);
    let count = manager_c.scan_for_self(&inbound_tx, future);
    assert_eq!(count, 1);

    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.payload, b"challenge_data");
    assert_eq!(msg.from, a_identity);

    // ── D: try to relay from C — must be rejected (hop=2) ───────────────
    let (d_signing_key, d_identity) = make_identity();
    let config_d = RelayConfig {
        board_path: dir_d.path().join("board.bin"),
        identity_pub: d_identity,
        x25519_priv: StaticSecret::random_from_rng(OsRng),
        signing_key: d_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_d = RelayManager::new(config_d).unwrap();

    let c_entries = manager_c.entries_for_sync(future);
    assert_eq!(c_entries[0].entry.hop, 2);

    let accepted_d = manager_d
        .process_remote_entries(&c_entries, future)
        .unwrap();
    assert_eq!(accepted_d, 0, "hop=2 entry must not be relayed further");
    assert_eq!(manager_d.stats().0, 0);
}

#[test]
fn revocation_broadcast_propagates_through_relay() {
    // RELAY-13: RevocationBroadcast must survive full relay round-trip:
    // post (node A) → sync (node B) → scan → deserialize → verify.

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let now = Timestamp::now();
    let future = Timestamp(now.0 + 1_000_000);

    // ── 1. Build master key, device key, issue cert, issue revocation ────
    let master_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let master_pub = syncback_core::cluster::master_identity(&master_key);

    let device_id = DeviceId([0xABu8; 16]);
    let device_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let device_pub_bytes = device_key.verifying_key().to_bytes();

    let device_cert = issue_device_certificate(&master_key, device_id, device_pub_bytes, future);
    let revocation = issue_revocation(&master_key, device_id, future, EpochCounter(1));

    // ── 2. Serialize RevocationBroadcast ────────────────────────────────
    let broadcast = RevocationBroadcast {
        revocation: revocation.clone(),
        device_cert: device_cert.clone(),
    };
    let payload = to_cbor(&broadcast).unwrap();

    // ── 3. Node A posts broadcast ────────────────────────────────────────
    let (a_signing_key, a_identity) = make_identity();
    let config_a = RelayConfig {
        board_path: dir_a.path().join("board.bin"),
        identity_pub: a_identity,
        x25519_priv: StaticSecret::random_from_rng(OsRng),
        signing_key: a_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_a = RelayManager::new(config_a).unwrap();

    let msg_id = [0xCCu8; 16];
    let stored = manager_a
        .post_broadcast("device_revocation", msg_id, payload, future)
        .unwrap();
    assert_eq!(stored.entry.hop, 0);

    // ── 4. Node B syncs from A ───────────────────────────────────────────
    let (b_signing_key, b_identity) = make_identity();
    let config_b = RelayConfig {
        board_path: dir_b.path().join("board.bin"),
        identity_pub: b_identity,
        x25519_priv: StaticSecret::random_from_rng(OsRng),
        signing_key: b_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_b = RelayManager::new(config_b).unwrap();

    let a_entries = manager_a.entries_for_sync(future);
    assert_eq!(a_entries.len(), 1);

    let accepted = manager_b
        .process_remote_entries(&a_entries, future)
        .unwrap();
    assert_eq!(accepted, 1);
    assert_eq!(manager_b.entries[0].entry.hop, 1);

    // ── 5. Node B scans and delivers via channel ─────────────────────────
    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);
    let count = manager_b.scan_for_self(&inbound_tx, future);
    assert_eq!(count, 1);

    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.msg_type, "device_revocation");
    assert_eq!(msg.msg_id, msg_id);

    // ── 6. Deserialize payload and verify certificates ───────────────────
    let decoded: RevocationBroadcast = from_cbor(&msg.payload).unwrap();

    verify_revocation(&decoded.revocation, &master_pub).unwrap();
    verify_device_certificate(&decoded.device_cert, &master_pub).unwrap();

    assert_eq!(decoded.revocation.device_id, device_id);
    assert_eq!(decoded.revocation.new_epoch, EpochCounter(1));
    assert_eq!(decoded.device_cert.device_pub_key, device_pub_bytes);
}

// ─── RELAY-11: board_sync_exchange_fills_missing_entries ─────────────────────

/// Bidirectional sync: node A has {E1, E2}, node B has {E2, E3}.
/// After A syncs from B and B syncs from A, both have {E1, E2, E3}.
#[test]
fn board_sync_exchange_fills_missing_entries() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let (key_a, identity_a) = make_identity();
    let (key_b, identity_b) = make_identity();
    let (key_e3, identity_e3) = make_identity();

    let now = Timestamp::now();

    // Build E1 (authored by A), E2 (authored by E3), E3 (authored by E3).
    let e1 = make_broadcast_entry(&key_a, identity_a, "peer_announce", [0x01u8; 16], now);
    let e2 = make_broadcast_entry(&key_e3, identity_e3, "peer_announce", [0x02u8; 16], now);
    let e3 = make_broadcast_entry(&key_b, identity_b, "peer_announce", [0x03u8; 16], now);

    // Node A: has E1, E2.
    let config_a = RelayConfig {
        board_path: dir_a.path().join("board.bin"),
        identity_pub: identity_a,
        x25519_priv: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        signing_key: key_a,
        max_entries: 100,
        max_size_bytes: 1_000_000,
        prune_interval_secs: 3600,
    };
    let mut manager_a = RelayManager::new(config_a).unwrap();
    manager_a.process_remote_entries(&[e1.clone(), e2.clone()], now).unwrap();
    assert_eq!(manager_a.entries.len(), 2);

    // Node B: has E2, E3.
    let config_b = RelayConfig {
        board_path: dir_b.path().join("board.bin"),
        identity_pub: identity_b,
        x25519_priv: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        signing_key: key_b,
        max_entries: 100,
        max_size_bytes: 1_000_000,
        prune_interval_secs: 3600,
    };
    let mut manager_b = RelayManager::new(config_b).unwrap();
    manager_b.process_remote_entries(&[e2.clone(), e3.clone()], now).unwrap();
    assert_eq!(manager_b.entries.len(), 2);

    // Exchange: A syncs from B, B syncs from A.
    let a_entries = manager_a.entries_for_sync(now);
    let b_entries = manager_b.entries_for_sync(now);

    let accepted_by_b = manager_b.process_remote_entries(&a_entries, now).unwrap();
    let accepted_by_a = manager_a.process_remote_entries(&b_entries, now).unwrap();

    // A received E3 (the only entry from B it was missing).
    assert_eq!(accepted_by_a, 1, "A should have accepted 1 new entry from B");
    // B received E1 (the only entry from A it was missing); E2 deduped.
    assert_eq!(accepted_by_b, 1, "B should have accepted 1 new entry from A");

    // Both now have 3 entries.
    assert_eq!(manager_a.entries.len(), 3, "A should have E1, E2, E3");
    assert_eq!(manager_b.entries.len(), 3, "B should have E1, E2, E3");

    let a_ids: std::collections::HashSet<[u8; 16]> =
        manager_a.entries.iter().map(|e| e.msg_id).collect();
    let b_ids: std::collections::HashSet<[u8; 16]> =
        manager_b.entries.iter().map(|e| e.msg_id).collect();

    assert!(a_ids.contains(&[0x01u8; 16]), "A missing E1");
    assert!(a_ids.contains(&[0x02u8; 16]), "A missing E2");
    assert!(a_ids.contains(&[0x03u8; 16]), "A missing E3");
    assert!(b_ids.contains(&[0x01u8; 16]), "B missing E1");
    assert!(b_ids.contains(&[0x02u8; 16]), "B missing E2");
    assert!(b_ids.contains(&[0x03u8; 16]), "B missing E3");
}

#[test]
fn scan_for_self_delivers_each_msg_once() {
    // Post a broadcast entry, call scan_for_self twice.
    // The second call must not re-deliver the same message.
    let dir = TempDir::new().unwrap();
    let config = make_config(&dir);
    let mut manager = RelayManager::new(config).unwrap();

    let now = Timestamp::now();
    let future = Timestamp(now.0 + 1_000_000);

    let (sender_key, sender_identity) = make_identity();
    let entry = build_broadcast_entry(
        "peer_announce",
        [0xA1u8; 16],
        b"once_only".to_vec(),
        sender_identity,
        future,
        &sender_key,
    );
    manager.entries.push(StoredEntry {
        msg_type: "peer_announce".to_string(),
        msg_id: [0xA1u8; 16],
        entry,
    });

    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);

    // First scan: must deliver 1 message.
    let count1 = manager.scan_for_self(&inbound_tx, future);
    assert_eq!(count1, 1);
    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.msg_id, [0xA1u8; 16]);

    // Second scan: same entry is still on the board but must not be re-delivered.
    let count2 = manager.scan_for_self(&inbound_tx, future);
    assert_eq!(count2, 0);
    assert!(inbound_rx.try_recv().is_err(), "no second delivery expected");
}

#[test]
fn scan_for_self_delivers_new_after_prune() {
    // After prune clears the old entry and a new entry arrives, scan delivers it.
    let dir = TempDir::new().unwrap();
    let now_real = Timestamp::now();
    let base = now_real.0 + 1_000_000;

    let config = RelayConfig {
        board_path: dir.path().join("board.bin"),
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
        ..RelayConfig::defaults_for_test(dir.path().join("board.bin"))
    };
    let mut manager = RelayManager::new(config).unwrap();

    let (sender_key, sender_identity) = make_identity();

    // Post entry A with a timestamp that will expire when we advance "now".
    let entry_a = build_broadcast_entry(
        "peer_announce",
        [0xB1u8; 16],
        b"entry_a".to_vec(),
        sender_identity,
        Timestamp(base),
        &sender_key,
    );
    manager.entries.push(StoredEntry {
        msg_type: "peer_announce".to_string(),
        msg_id: [0xB1u8; 16],
        entry: entry_a,
    });

    let (inbound_tx, mut inbound_rx) = mpsc::channel(10);

    // First scan: delivers entry A.
    let count1 = manager.scan_for_self(&inbound_tx, Timestamp(base + 1));
    assert_eq!(count1, 1);
    let _ = inbound_rx.try_recv().unwrap();

    // Advance time past TTL so entry A expires; prune removes it.
    let prune_now = Timestamp(base + RELAY_TTL_SECS + 1);
    let pruned = manager.prune(prune_now).unwrap();
    assert_eq!(pruned, 1, "entry A should have been pruned");
    assert_eq!(manager.entries.len(), 0);

    // Post entry B with a fresh timestamp (far future, won't expire).
    let entry_b = build_broadcast_entry(
        "peer_announce",
        [0xB2u8; 16],
        b"entry_b".to_vec(),
        sender_identity,
        Timestamp(base + 2_000_000),
        &sender_key,
    );
    manager.entries.push(StoredEntry {
        msg_type: "peer_announce".to_string(),
        msg_id: [0xB2u8; 16],
        entry: entry_b,
    });

    // Second scan with new "now": entry B is new and must be delivered.
    let count2 = manager.scan_for_self(&inbound_tx, prune_now);
    assert_eq!(count2, 1);
    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.msg_id, [0xB2u8; 16]);
    assert_eq!(msg.payload, b"entry_b");
}
