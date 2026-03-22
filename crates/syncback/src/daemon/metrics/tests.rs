use crate::cli::types::{PeerSummary, StatusData};
use super::format_prometheus;

fn make_status(peers: Vec<PeerSummary>) -> StatusData {
    StatusData {
        node_identity: "abcdef0123456789".to_string(),
        node_addr: "test-addr".to_string(),
        peer_count: peers.len() as u32,
        avg_trust: 0.75,
        holding_bytes: 1024,
        backed_up_files: 3,
        backed_up_bytes: 4096,
        blocks_needing_repair: 1,
        peers,
        effective_quota_bytes: 10_000_000,
        used_bytes: 500,
        pos_total_challenges: 42,
        pos_total_passes: 40,
        placement_count: 10,
        placement_alive: 8,
        placement_lost: 2,
        blocks_ok: 5,
        blocks_at_risk: 1,
    }
}

fn make_peer(identity_hex: &str, trust: f64) -> PeerSummary {
    PeerSummary {
        identity_hex: identity_hex.to_string(),
        trust,
        bytes_we_store: 100,
        bytes_peer_stores: 200,
        last_seen: "2026-03-22".to_string(),
        trust_p: 0.8,
        trust_i: 0.6,
        trust_s: 1.0,
        pos_challenges_recent: 5,
        pos_passes_recent: 4,
    }
}

#[test]
fn format_prometheus_includes_node_gauges() {
    let status = make_status(vec![]);
    let out = format_prometheus(&status, "node01");

    assert!(out.contains("syncback_peer_count{node=\"node01\"} 0"));
    assert!(out.contains("syncback_avg_trust{node=\"node01\"}"));
    assert!(out.contains("syncback_holding_bytes{node=\"node01\"} 1024"));
    assert!(out.contains("syncback_backed_up_files{node=\"node01\"} 3"));
    assert!(out.contains("syncback_backed_up_bytes{node=\"node01\"} 4096"));
    assert!(out.contains("syncback_blocks_ok{node=\"node01\"} 5"));
    assert!(out.contains("syncback_blocks_at_risk{node=\"node01\"} 1"));
    assert!(out.contains("syncback_placement_alive{node=\"node01\"} 8"));
    assert!(out.contains("syncback_placement_lost{node=\"node01\"} 2"));
    assert!(out.contains("syncback_pos_challenges_total{node=\"node01\"} 42"));
    assert!(out.contains("syncback_pos_passes_total{node=\"node01\"} 40"));
    assert!(out.contains("syncback_effective_quota_bytes{node=\"node01\"} 10000000"));
    assert!(out.contains("syncback_used_bytes{node=\"node01\"} 500"));
}

#[test]
fn format_prometheus_includes_per_peer_metrics() {
    let peers = vec![make_peer("aabbccdd", 0.9)];
    let status = make_status(peers);
    let out = format_prometheus(&status, "node01");

    assert!(out.contains("syncback_trust_p{node=\"node01\",peer=\"aabbccdd\"}"));
    assert!(out.contains("syncback_trust_i{node=\"node01\",peer=\"aabbccdd\"}"));
    assert!(out.contains("syncback_trust_s{node=\"node01\",peer=\"aabbccdd\"}"));
    assert!(out.contains("syncback_trust_combined{node=\"node01\",peer=\"aabbccdd\"}"));
    assert!(out.contains("syncback_peer_bytes_we_store{node=\"node01\",peer=\"aabbccdd\"} 100"));
    assert!(out.contains("syncback_peer_bytes_stored_for_us{node=\"node01\",peer=\"aabbccdd\"} 200"));
}

#[test]
fn format_prometheus_empty_peers_no_per_peer_lines() {
    let status = make_status(vec![]);
    let out = format_prometheus(&status, "node01");

    assert!(!out.contains("syncback_trust_p{"));
    assert!(!out.contains("syncback_peer_bytes_we_store{"));
}

#[test]
fn format_prometheus_multiple_peers() {
    let peers = vec![
        make_peer("peer_aaa", 0.9),
        make_peer("peer_bbb", 0.5),
    ];
    let status = make_status(peers);
    let out = format_prometheus(&status, "n1");

    assert!(out.contains("peer=\"peer_aaa\""));
    assert!(out.contains("peer=\"peer_bbb\""));
    // Node-level metrics should appear once
    let count = out.matches("syncback_peer_count{").count();
    assert_eq!(count, 1);
}
