// mailbox-probe — offline instrument for reading and planting postman mailbox
// state in E2E scenarios (CROWN-1 Part 0 §0.3). NOT a user-facing CLI.
//
// The node must be STOPPED (redb holds a file lock). Subcommands:
//
//   audit --data-dir D [--needle-hex [LABEL=]HEX]... [--needle-str [LABEL=]STR]...
//         [--known LABEL=HEX]...
//       Reads only the mailbox table, READ-ONLY (redb ReadOnlyDatabase: nothing is
//       written to the postman's disk; a killed node's file is read from a repaired
//       copy in the temp dir), every address, expired entries included, and
//       prints one JSON document: per entry the address, class, payload_version,
//       sizes, msg_id, which inner message types the payload decodes as, whether the
//       stored CBOR map carries a `sender` key (generic CBOR, so it works before and
//       after that field is removed from the type), which needles occur in the stored
//       bytes outside the `target` field, and which `--known` identities the address
//       equals (raw or SHA256). A summary counts entries by class. Reading only the
//       mailbox table means no false hits from PeerRecord.addrs or holdings.
//
//   inject --data-dir D --target HEX --class C [--version V] [--msg-id HEX]
//          [--stored-at N] [--expires-in N] [--replace]
//          (--junk-len N | --copy-from TARGET_HEX:MSGID_HEX:CLASS
//           | --sign-with DIR --drop-block HEX
//           | --sign-with DIR --pos-response CID_HEX:BLOCK_HEX:DEVICE_HEX --key device|master)
//       Writes one entry straight into redb (`Db::mailbox_insert`), bypassing every
//       postman rule: a hostile postman. `--replace` first deletes the entry under the
//       same (target, msg_id, class), so a pointer place can be swapped (S1 step 6f). `--sign-with` builds a VALIDLY signed
//       SymbolDropNoticeBatchMsg with the master key of DIR/identity.key (a holder of
//       the same run) and stores it as plaintext version 1 (S1 step 6c). With
//       `--pos-response` it builds a PosHashResponseMsg for challenge CID / block BLOCK
//       naming device DEVICE (full 32-byte hex), a junk chain hash, signed by the device
//       key or the master key of DIR/identity.key (`--class PosResponse`, `--target` = the
//       owner's master box, sender = DIR's master): the forgeries of C-SP step 4 (pos-i16).
//
//   remove --data-dir D --target HEX [--msg-id HEX] [--class C]
//       Deletes the matching entries of one address (expired included) by the same
//       `Db::mailbox_delete` path as `inject --replace`; without `--msg-id` every entry
//       of the class, without `--class` every class. Prints `{"removed": n}`.
//
//   peer-x25519 --data-dir D --device HEX --clear
//       Clears `PeerRecord.x25519_pub` of one peer (S1 step 10, mailbox-i8).
//
//   rendezvous --phrase "<words>" [--lineage HEX32] [--place a|b] [--json]
//       Offline, no data dir, no clock: the phrase's pointer box address (`address`,
//       `address_short` as the postman logs `target=`) and, with a catalog history,
//       its two pointer place slots `slot_a`, `slot_b` (`slot` for `--place`).

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use viaticum::daemon::identity::{derive_keys, load_identity};
use viaticum_core::cluster::{derive_master_key, master_identity};
use viaticum_core::db::{Db, read_only_mailbox_raw_entries};
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{SymbolDropNoticeBatchMsg, build_signed_symbol_drop_notice};
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp, hex_encode, to_cbor_bytes};

mod audit;
mod inject;
mod remove;
mod rendezvous;

#[derive(Parser, Debug)]
#[command(about = "Offline postman mailbox audit / injection (E2E instrument)")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print a JSON audit of every stored mailbox entry.
    Audit {
        #[arg(long)]
        data_dir: PathBuf,
        /// Byte needle, `LABEL=HEX` or `HEX`. Searched raw, as a CBOR u8 array and as hex text.
        #[arg(long)]
        needle_hex: Vec<String>,
        /// Text needle, `LABEL=TEXT` or `TEXT`.
        #[arg(long)]
        needle_str: Vec<String>,
        /// Identity to compare addresses against, `LABEL=HEX` (raw and SHA256).
        #[arg(long)]
        known: Vec<String>,
    },
    /// Write one entry straight into redb, bypassing the postman rules.
    Inject {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        class: String,
        /// payload_version (default: 2 for junk, source version for copy, 1 for sign-with).
        #[arg(long)]
        version: Option<u8>,
        #[arg(long)]
        msg_id: Option<String>,
        #[arg(long)]
        stored_at: Option<u64>,
        #[arg(long, default_value_t = 600)]
        expires_in: u64,
        #[arg(long)]
        junk_len: Option<usize>,
        #[arg(long)]
        copy_from: Option<String>,
        #[arg(long)]
        sign_with: Option<PathBuf>,
        #[arg(long)]
        drop_block: Option<String>,
        /// With --sign-with: forge a PoS response `CID_HEX:BLOCK_HEX:DEVICE_HEX`.
        #[arg(long)]
        pos_response: Option<String>,
        /// With --pos-response: sign with DIR's `device` or `master` key.
        #[arg(long)]
        key: Option<String>,
        /// Overwrite an entry under the same (target, msg_id, class).
        #[arg(long)]
        replace: bool,
    },
    /// Delete the matching entries of one mailbox address.
    Remove {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        target: String,
        /// Only this msg_id (default: every msg_id).
        #[arg(long)]
        msg_id: Option<String>,
        /// Only this class (default: every class).
        #[arg(long)]
        class: Option<String>,
    },
    /// Offline: the pointer box address and place slots of a recovery phrase.
    Rendezvous {
        #[arg(long)]
        phrase: String,
        #[arg(long)]
        lineage: Option<String>,
        #[arg(long)]
        place: Option<String>,
        /// Accepted for scripts; the output is always JSON.
        #[arg(long)]
        json: bool,
    },
    /// Clear the x25519 key of one peer record.
    PeerX25519 {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        device: String,
        #[arg(long)]
        clear: bool,
    },
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("mailbox-probe: {msg}");
    std::process::exit(2);
}

fn open_db(data_dir: &Path) -> Db {
    let path = data_dir.join("db.redb");
    if !path.exists() {
        die(format!("{} does not exist", path.display()));
    }
    Db::open(&path).unwrap_or_else(|e| {
        die(format!(
            "open {} (is the node stopped?): {e}",
            path.display()
        ))
    })
}

fn hex32(s: &str, what: &str) -> [u8; 32] {
    audit::parse_hex(s)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .unwrap_or_else(|| die(format!("{what}: expected 64 hex chars, got {s:?}")))
}

fn hex16(s: &str, what: &str) -> [u8; 16] {
    audit::parse_hex(s)
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .unwrap_or_else(|| die(format!("{what}: expected 32 hex chars, got {s:?}")))
}

fn class(s: &str) -> MailboxClass {
    audit::parse_class(s).unwrap_or_else(|| die(format!("unknown class {s:?}")))
}

fn now_secs() -> u64 {
    Timestamp::now().0
}

fn main() {
    match Args::parse().cmd {
        Cmd::Audit {
            data_dir,
            needle_hex,
            needle_str,
            known,
        } => {
            let needles = audit::parse_needles(&needle_hex, &needle_str)
                .unwrap_or_else(|e| die(format!("needle: {e}")));
            let known = audit::parse_known(&known).unwrap_or_else(|e| die(format!("known: {e}")));
            // Read-only: the audit writes nothing to the postman's disk (no pre-open
            // backup copy, no table creation — unlike `Db::open`).
            let path = data_dir.join("db.redb");
            let boxes = read_only_mailbox_raw_entries(&path).unwrap_or_else(|e| {
                die(format!(
                    "read {} (is the node stopped?): {e}",
                    path.display()
                ))
            });
            if boxes.from_repaired_copy {
                eprintln!(
                    "mailbox-probe: {} needed crash recovery (killed node); read a repaired copy, original untouched",
                    path.display()
                );
            }
            let entries: Vec<_> = boxes
                .boxes
                .iter()
                .flat_map(|(_, raw)| raw.iter())
                .map(|bytes| audit::audit_entry(bytes, &needles, &known))
                .collect();
            let report = audit::report(entries);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| die(e))
            );
        }
        Cmd::Inject {
            data_dir,
            target,
            class: class_name,
            version,
            msg_id,
            stored_at,
            expires_in,
            junk_len,
            copy_from,
            sign_with,
            drop_block,
            pos_response,
            key,
            replace,
        } => {
            let target = MailboxAddress(hex32(&target, "--target"));
            let class = class(&class_name);
            let msg_id = msg_id
                .map(|m| hex16(&m, "--msg-id"))
                .unwrap_or_else(rand::random);
            let now = now_secs();
            let stored_at = stored_at.unwrap_or(now);
            let db = open_db(&data_dir);

            let (payload_version, payload, sender) = match (junk_len, copy_from, sign_with) {
                (Some(len), None, None) => {
                    let payload: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
                    (version.unwrap_or(2), payload, None)
                }
                (None, Some(spec), None) => {
                    let src = audit::parse_copy_from(&spec).unwrap_or_else(|| {
                        die(format!("--copy-from {spec:?}: want TARGET:MSGID:CLASS"))
                    });
                    let found = db
                        .mailbox_list_for_target(&src.0, 0)
                        .unwrap_or_else(|e| die(e))
                        .into_iter()
                        .find(|e| e.msg_id == src.1 && e.class == src.2)
                        .unwrap_or_else(|| die(format!("--copy-from: no entry {spec}")));
                    (
                        version.unwrap_or(found.payload_version),
                        found.payload,
                        found.sender,
                    )
                }
                (None, None, Some(dir)) if pos_response.is_some() => {
                    if class != MailboxClass::PosResponse {
                        die("--pos-response builds a PoS response: use --class PosResponse");
                    }
                    if drop_block.is_some() {
                        die("--pos-response and --drop-block are exclusive");
                    }
                    let spec = pos_response.as_deref().unwrap_or_default();
                    let (cid, block, device) = inject::parse_pos_response_spec(spec)
                        .unwrap_or_else(|| {
                            die(format!(
                                "--pos-response {spec:?}: want CID_HEX:BLOCK_HEX:DEVICE_HEX"
                            ))
                        });
                    let which = key
                        .as_deref()
                        .and_then(inject::parse_forge_key)
                        .unwrap_or_else(|| die("--pos-response needs --key device|master"));
                    let keyfile = load_identity(&dir)
                        .unwrap_or_else(|e| die(format!("identity in {}: {e}", dir.display())));
                    let (master_key, device_key, _) =
                        derive_keys(&keyfile, 0).unwrap_or_else(|e| die(e));
                    let signer = match which {
                        inject::ForgeKey::Device => &device_key,
                        inject::ForgeKey::Master => &master_key,
                    };
                    let response =
                        inject::forged_pos_response(cid, block, device, signer, Timestamp(now));
                    (
                        version.unwrap_or(1),
                        to_cbor_bytes(&response),
                        Some(master_identity(&master_key)),
                    )
                }
                (None, None, Some(dir)) => {
                    if key.is_some() {
                        die("--key goes with --pos-response");
                    }
                    if class != MailboxClass::DropNotice {
                        die("--sign-with builds a DropNotice: use --class DropNotice");
                    }
                    let block = SourceBlockId(hex32(
                        drop_block
                            .as_deref()
                            .unwrap_or_else(|| die("--sign-with needs --drop-block")),
                        "--drop-block",
                    ));
                    let keyfile = load_identity(&dir)
                        .unwrap_or_else(|e| die(format!("identity in {}: {e}", dir.display())));
                    let master_key = derive_master_key(&keyfile.seed).unwrap_or_else(|e| die(e));
                    let notice = build_signed_symbol_drop_notice(
                        block,
                        vec![(0, u32::MAX)],
                        Timestamp(now),
                        Timestamp(now),
                        &master_key,
                    );
                    let batch = SymbolDropNoticeBatchMsg {
                        v: 1,
                        notices: vec![notice],
                    };
                    (
                        version.unwrap_or(1),
                        to_cbor_bytes(&batch),
                        Some(master_identity(&master_key)),
                    )
                }
                _ => die("exactly one of --junk-len, --copy-from, --sign-with is required"),
            };

            let entry = MailboxEntry {
                target,
                msg_id,
                class,
                payload_version,
                payload,
                expires_at: now + expires_in,
                stored_at,
                sender,
            };
            let replaced = inject::store_injected(&db, &entry, replace)
                .unwrap_or_else(|e| die(format!("insert: {e}")));
            println!(
                "{}",
                serde_json::json!({
                    "target": hex_encode(&entry.target.0),
                    "msg_id": hex_encode(&entry.msg_id),
                    "class": format!("{:?}", entry.class),
                    "payload_version": entry.payload_version,
                    "payload_len": entry.payload.len(),
                    "stored_at": entry.stored_at,
                    "expires_at": entry.expires_at,
                    "replaced": replaced,
                })
            );
        }
        Cmd::Remove {
            data_dir,
            target,
            msg_id,
            class: class_name,
        } => {
            let target = MailboxAddress(hex32(&target, "--target"));
            let msg_id = msg_id.map(|m| hex16(&m, "--msg-id"));
            let class = class_name.as_deref().map(class);
            let db = open_db(&data_dir);
            let removed = remove::remove_matching(&db, &target, msg_id, class)
                .unwrap_or_else(|e| die(format!("remove: {e}")));
            println!("{}", serde_json::json!({ "removed": removed }));
        }
        Cmd::Rendezvous {
            phrase,
            lineage,
            place,
            json: _,
        } => {
            let lineage = lineage.map(|l| hex16(&l, "--lineage"));
            let v = rendezvous::rendezvous_json(&phrase, lineage, place.as_deref())
                .unwrap_or_else(|e| die(e));
            println!("{v}");
        }
        Cmd::PeerX25519 {
            data_dir,
            device,
            clear,
        } => {
            if !clear {
                die("only --clear is supported");
            }
            let device = DeviceId(hex32(&device, "--device"));
            let db = open_db(&data_dir);
            let mut rec = db
                .get_peer(&device)
                .unwrap_or_else(|e| die(e))
                .unwrap_or_else(|| die(format!("no peer record for {device}")));
            let had = rec.x25519_pub.is_some();
            rec.x25519_pub = None;
            db.upsert_peer(&rec).unwrap_or_else(|e| die(e));
            println!(
                "{}",
                serde_json::json!({ "device": hex_encode(&device.0), "had_key": had, "cleared": true })
            );
        }
    }
}
