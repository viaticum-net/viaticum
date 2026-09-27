// mailbox-probe audit: the checks S1 relies on must see what is really on disk.

use sha2::{Digest, Sha256};
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::SymbolDropNoticeBatchMsg;
use viaticum_core::system_state::catalog::{CatalogLineageId, CatalogSummary};
use viaticum_core::system_state::{BlockRef, HolderHint, sign_self_pointer};
use viaticum_core::types::{
    DeviceId, IdentityPub, SourceBlockId, Timestamp, hex_encode, to_cbor_bytes,
};

use super::*;

fn entry(
    target: [u8; 32],
    class: MailboxClass,
    payload: Vec<u8>,
    sender: Option<IdentityPub>,
) -> MailboxEntry {
    MailboxEntry {
        target: MailboxAddress(target),
        msg_id: [0x33; 16],
        class,
        payload_version: 1,
        payload,
        expires_at: 2_000,
        stored_at: 1_000,
        sender,
    }
}

fn plaintext_pointer(holder: DeviceId) -> (Vec<u8>, ed25519_dalek::SigningKey) {
    let key = viaticum_core::cluster::derive_master_key(&[9u8; 64]).unwrap();
    let pointer = sign_self_pointer(
        &key,
        1,
        BlockRef {
            block_id: SourceBlockId([0xB1; 32]),
            encrypted_size: 10,
            holders: vec![HolderHint {
                holder_id: holder,
                addrs: vec!["/ip4/127.0.0.1/tcp/4001".into()],
                esi_ranges: vec![(0, 3)],
            }],
        },
        vec![],
        Timestamp(5),
        CatalogSummary {
            lineage: CatalogLineageId([0xB2; 16]),
            publisher: DeviceId([0xD0; 32]),
            files: 1,
        },
    );
    (to_cbor_bytes(&pointer), key)
}

#[test]
fn plaintext_self_pointer_is_reported_readable_with_its_needles() {
    let holder = DeviceId([0xD7; 32]);
    let (payload, key) = plaintext_pointer(holder);
    let master = viaticum_core::cluster::master_identity(&key);
    let bytes = to_cbor_bytes(&entry(
        master.0,
        MailboxClass::SelfPointer,
        payload,
        Some(master),
    ));

    let needles = parse_needles(
        &[
            format!("holder={}", hex_encode(&holder.0)),
            format!("block={}", hex_encode(&[0xB1; 32])),
            format!("master={}", hex_encode(&master.0)),
        ],
        &["maddr=/ip4/127.0.0.1/tcp/4001".to_string()],
    )
    .unwrap();
    let known = parse_known(&[format!("A={}", hex_encode(&master.0))]).unwrap();
    let a = audit_entry(&bytes, &needles, &known);

    assert_eq!(a.class, "SelfPointer");
    assert_eq!(a.decodes_as, vec!["SelfPointer"]);
    assert!(a.sender_key && a.sender_non_null);
    // master is found through `sender`, not through the blanked `target`.
    assert_eq!(a.needles, vec!["holder", "block", "master", "maddr"]);
    assert_eq!(a.target_is, vec!["A"]);
}

/// A 32-byte key inside a CBOR u8 array is not contiguous in the bytes: a raw
/// search alone would report "no needle" for a plaintext record.
#[test]
fn needle_inside_cbor_u8_array_is_found_only_via_array_form() {
    let holder = DeviceId([0xD7; 32]);
    let (payload, _) = plaintext_pointer(holder);
    let raw_only = vec![Needle {
        label: "raw".into(),
        forms: vec![holder.0.to_vec()],
    }];
    assert!(audit_entry(&payload, &raw_only, &[]).needles.is_empty());
    let all = parse_needles(&[format!("h={}", hex_encode(&holder.0))], &[]).unwrap();
    assert_eq!(audit_entry(&payload, &all, &[]).needles, vec!["h"]);
}

#[test]
fn target_equal_to_needle_is_not_a_hit_but_target_is_matches_hash() {
    let id = [0x42u8; 32];
    let hashed: [u8; 32] = Sha256::digest(id).into();
    let bytes = to_cbor_bytes(&entry(
        hashed,
        MailboxClass::DropNotice,
        vec![0xEE; 8],
        None,
    ));
    let needles = parse_needles(&[format!("id_hash={}", hex_encode(&hashed))], &[]).unwrap();
    let known = parse_known(&[format!("B={}", hex_encode(&id))]).unwrap();
    let a = audit_entry(&bytes, &needles, &known);
    assert!(a.needles.is_empty(), "the target field itself is blanked");
    assert_eq!(
        a.target_is,
        vec!["B"],
        "address = SHA256(known) is reported"
    );
    assert!(a.sender_key && !a.sender_non_null);
}

#[test]
fn opaque_payload_decodes_as_nothing() {
    let bytes = to_cbor_bytes(&entry(
        [1; 32],
        MailboxClass::DropNotice,
        vec![0x5A; 300],
        None,
    ));
    let a = audit_entry(&bytes, &[], &[]);
    assert!(a.decodes_as.is_empty());
    assert_eq!(a.payload_len, 300);
}

#[test]
fn plaintext_drop_notice_batch_is_decodable() {
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![],
    };
    let bytes = to_cbor_bytes(&entry(
        [1; 32],
        MailboxClass::DropNotice,
        to_cbor_bytes(&batch),
        None,
    ));
    assert!(
        audit_entry(&bytes, &[], &[])
            .decodes_as
            .contains(&"SymbolDropNoticeBatchMsg")
    );
}

#[test]
fn sender_key_is_detected_generically_on_foreign_layouts() {
    #[derive(serde::Serialize)]
    struct Legacy {
        sender: Option<u8>,
        other: u8,
    }
    let bytes = to_cbor_bytes(&Legacy {
        sender: Some(1),
        other: 2,
    });
    let a = audit_entry(&bytes, &[], &[]);
    assert!(a.sender_key && a.sender_non_null);
    assert!(a.decode_error.is_some(), "not a mailbox entry");

    #[derive(serde::Serialize)]
    struct NoSender {
        other: u8,
    }
    assert!(!audit_entry(&to_cbor_bytes(&NoSender { other: 2 }), &[], &[]).sender_key);
}

#[test]
fn report_counts_by_class_version_and_flags() {
    let (payload, _) = plaintext_pointer(DeviceId([1; 32]));
    let e1 = audit_entry(
        &to_cbor_bytes(&entry([1; 32], MailboxClass::SelfPointer, payload, None)),
        &[],
        &[],
    );
    let mut sealed = entry([2; 32], MailboxClass::PosChallenge, vec![7; 50], None);
    sealed.payload_version = 2;
    let e2 = audit_entry(&to_cbor_bytes(&sealed), &[], &[]);
    let r = report(vec![e1, e2]);
    assert_eq!(r.summary.total, 2);
    assert_eq!(r.summary.by_class["SelfPointer"], 1);
    assert_eq!(r.summary.by_class["PosChallenge"], 1);
    assert_eq!(r.summary.by_version[&1], 1);
    assert_eq!(r.summary.by_version[&2], 1);
    assert_eq!(r.summary.decodable, 1);
    assert_eq!(r.summary.with_sender_key, 2);
}

#[test]
fn parsers_accept_and_reject() {
    assert_eq!(parse_hex("0aff"), Some(vec![0x0a, 0xff]));
    assert_eq!(parse_hex("0af"), None);
    assert_eq!(parse_hex("zz"), None);
    assert_eq!(parse_class("DropNotice"), Some(MailboxClass::DropNotice));
    assert_eq!(parse_class("dropnotice"), None);
    let t = hex_encode(&[3u8; 32]);
    let m = hex_encode(&[4u8; 16]);
    assert_eq!(
        parse_copy_from(&format!("{t}:{m}:Revocation")),
        Some((MailboxAddress([3; 32]), [4; 16], MailboxClass::Revocation))
    );
    assert_eq!(parse_copy_from(&format!("{t}:{m}")), None);
    assert!(parse_known(&["x=00".to_string()]).is_err());
    assert!(parse_needles(&["x=".to_string()], &[]).is_err());
}

#[test]
fn cbor_u8_array_form_matches_ciborium_layout() {
    let bytes = [0u8, 23, 24, 255];
    let encoded = to_cbor_bytes(&bytes);
    // array(4) header 0x84, then the elements.
    assert_eq!(&encoded[1..], cbor_u8_array_form(&bytes).as_slice());
}
