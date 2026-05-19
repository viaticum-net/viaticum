// bootstrap-trust — demo helper for multi-node clusters.
//
// Two subcommands:
//
//   identity-show --data-dir <path>
//       Reads <data_dir>/identity.key (CBOR IdentityKeyFile) and prints
//       JSON {"device_id": "<hex>", "identity_pub": "<hex>"}.
//       Used by the orchestrator to build a global peer manifest.
//
//   seed --db <path/to/db.redb> --peers <peers.json> [--score 0.95] [--skip-self <id_hex>]
//       Pre-seeds high mutual trust into a node's redb so the placement
//       engine treats listed peers as already-vetted holders without
//       waiting for PoS rounds. Daemon must be stopped.
//
//       peers.json: [{"device_id": "<64-hex>", "identity_pub": "<64-hex>"}, ...]
//
//       For each peer (except --skip-self):
//         device_to_master[device_id] = identity_pub
//         device_trust[device_id]     = { trust_p: score, trust_i: score, last_week: 0 }
//         master_trust[identity_pub]  = { combined: score, last_updated: now }

use clap::{Parser, Subcommand};
use viaticum::daemon::identity::load_identity;
use viaticum_core::db::Db;
use viaticum_core::trust::{DeviceTrustRecord, MasterTrustRecord};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

#[derive(Parser, Debug)]
#[command(about = "Demo trust pre-seed + identity dump", long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print {"device_id":"...","identity_pub":"..."} from <data_dir>/identity.key.
    IdentityShow {
        #[arg(long)]
        data_dir: std::path::PathBuf,
    },
    /// Write trust records for listed peers into the node's redb.
    Seed {
        #[arg(long)]
        db: std::path::PathBuf,
        #[arg(long)]
        peers: std::path::PathBuf,
        #[arg(long, default_value_t = 0.95)]
        score: f64,
        /// Hex device_id to skip (typically the node's own).
        #[arg(long)]
        skip_self: Option<String>,
    },
}

#[derive(serde::Deserialize)]
struct PeerEntry {
    device_id: String,
    identity_pub: String,
}

fn parse_hex32(s: &str, what: &str) -> [u8; 32] {
    let s = s.trim();
    let v = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex in {}: {}", what, e))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        v.len(),
        32,
        "{} must be 32 bytes (64 hex chars), got {}",
        what,
        v.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let args = Args::parse();
    match args.cmd {
        Cmd::IdentityShow { data_dir } => {
            let id = load_identity(&data_dir)
                .unwrap_or_else(|e| panic!("load identity from {}: {}", data_dir.display(), e));
            println!(
                "{{\"device_id\":\"{}\",\"identity_pub\":\"{}\"}}",
                hex32(&id.device_id),
                hex32(&id.identity_pub),
            );
        }
        Cmd::Seed {
            db,
            peers,
            score,
            skip_self,
        } => {
            let peers_text = std::fs::read_to_string(&peers)
                .unwrap_or_else(|e| panic!("read {}: {}", peers.display(), e));
            let entries: Vec<PeerEntry> = serde_json::from_str(&peers_text)
                .unwrap_or_else(|e| panic!("parse peers.json: {}", e));

            let skip: Option<[u8; 32]> = skip_self.as_deref().map(|s| parse_hex32(s, "skip-self"));

            let db = Db::open(&db).unwrap_or_else(|e| panic!("open db {}: {}", db.display(), e));

            let mut written = 0usize;
            let mut skipped = 0usize;
            for p in &entries {
                let device_id = DeviceId(parse_hex32(&p.device_id, "device_id"));
                if Some(device_id.0) == skip {
                    skipped += 1;
                    continue;
                }
                let identity = IdentityPub(parse_hex32(&p.identity_pub, "identity_pub"));

                db.set_master_for_device(&device_id, &identity)
                    .unwrap_or_else(|e| panic!("set_master_for_device: {}", e));
                db.set_device_trust(&DeviceTrustRecord {
                    device_id,
                    trust_p: score,
                    trust_i: score,
                    last_week: 0,
                })
                .unwrap_or_else(|e| panic!("set_device_trust: {}", e));
                db.set_master_trust(&MasterTrustRecord {
                    identity,
                    combined: score,
                    last_updated: Timestamp::now(),
                })
                .unwrap_or_else(|e| panic!("set_master_trust: {}", e));

                written += 1;
            }

            eprintln!(
                "bootstrap-trust seed: wrote {} peers (skipped {}) score={}",
                written, skipped, score
            );
        }
    }
}
