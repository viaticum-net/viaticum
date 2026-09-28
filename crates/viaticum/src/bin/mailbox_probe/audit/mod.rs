// Pure audit logic of mailbox-probe: what one stored mailbox entry reveals.

use std::collections::BTreeMap;

use ciborium::Value;
use sha2::{Digest, Sha256};
use viaticum_core::mailbox::{DeleteRequestPayload, MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    PosHashChallengeMsg, PosHashResponseMsg, RevocationBroadcast, SymbolDropNoticeBatchMsg,
};
use viaticum_core::system_state::SelfPointer;
use viaticum_core::types::{from_cbor_bytes, hex_encode};

/// A needle and the byte forms it is searched in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Needle {
    pub label: String,
    pub forms: Vec<Vec<u8>>,
}

/// Audit of one stored entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct EntryAudit {
    pub target: String,
    pub class: String,
    pub payload_version: u8,
    pub entry_len: usize,
    pub payload_len: usize,
    pub msg_id: String,
    pub stored_at: u64,
    pub expires_at: u64,
    /// Inner message types the payload decodes as (empty = opaque).
    pub decodes_as: Vec<&'static str>,
    /// The stored CBOR map has a `sender` key (any value).
    pub sender_key: bool,
    /// ... and its value is not null.
    pub sender_non_null: bool,
    /// Labels of needles found in the stored bytes outside the `target` field.
    pub needles: Vec<String>,
    /// Labels of `--known` identities the address equals (raw) or hashes to (SHA256).
    pub target_is: Vec<String>,
    /// Set when the bytes do not decode as a mailbox entry at all.
    pub decode_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct Summary {
    pub total: usize,
    pub by_class: BTreeMap<String, usize>,
    pub by_version: BTreeMap<u8, usize>,
    pub decodable: usize,
    pub with_sender_key: usize,
    pub with_needles: usize,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct Report {
    pub summary: Summary,
    pub entries: Vec<EntryAudit>,
}

pub(crate) fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn parse_class(s: &str) -> Option<MailboxClass> {
    Some(match s {
        "SelfPointer" => MailboxClass::SelfPointer,
        "PosChallenge" => MailboxClass::PosChallenge,
        "PosResponse" => MailboxClass::PosResponse,
        "DropNotice" => MailboxClass::DropNotice,
        "Generic" => MailboxClass::Generic,
        "DeleteRequest" => MailboxClass::DeleteRequest,
        "Revocation" => MailboxClass::Revocation,
        _ => return None,
    })
}

/// `LABEL=VALUE` or `VALUE` (label = the value itself, truncated).
fn split_label(arg: &str) -> (String, &str) {
    match arg.split_once('=') {
        Some((label, value)) => (label.to_string(), value),
        None => (arg.chars().take(16).collect(), arg),
    }
}

/// How ciborium lays out a `[u8; N]` field: an array whose u8 elements are CBOR
/// unsigned ints (0..=23 in one byte, 24..=255 as `0x18 b`). A 32-byte key stored
/// that way never appears as its raw 32 bytes, so a raw search alone would miss it.
pub(crate) fn cbor_u8_array_form(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        if b < 24 {
            out.push(b);
        } else {
            out.push(0x18);
            out.push(b);
        }
    }
    out
}

/// Hex needles are searched raw, in CBOR u8-array form and as lowercase hex text;
/// text needles as their UTF-8 bytes.
pub(crate) fn parse_needles(hex: &[String], text: &[String]) -> Result<Vec<Needle>, String> {
    let mut out = Vec::new();
    for arg in hex {
        let (label, value) = split_label(arg);
        let bytes = parse_hex(value).ok_or_else(|| format!("bad hex in {arg:?}"))?;
        if bytes.is_empty() {
            return Err(format!("empty needle {arg:?}"));
        }
        out.push(Needle {
            label,
            forms: vec![
                bytes.clone(),
                cbor_u8_array_form(&bytes),
                hex_encode(&bytes).into_bytes(),
            ],
        });
    }
    for arg in text {
        let (label, value) = split_label(arg);
        if value.is_empty() {
            return Err(format!("empty needle {arg:?}"));
        }
        out.push(Needle {
            label,
            forms: vec![value.as_bytes().to_vec()],
        });
    }
    Ok(out)
}

pub(crate) fn parse_known(args: &[String]) -> Result<Vec<(String, [u8; 32])>, String> {
    args.iter()
        .map(|arg| {
            let (label, value) = split_label(arg);
            let bytes = parse_hex(value)
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .ok_or_else(|| format!("{arg:?}: want LABEL=<64 hex>"))?;
            Ok((label, bytes))
        })
        .collect()
}

/// `TARGET_HEX:MSGID_HEX:CLASS`.
pub(crate) fn parse_copy_from(s: &str) -> Option<(MailboxAddress, [u8; 16], MailboxClass)> {
    let mut parts = s.split(':');
    let target = <[u8; 32]>::try_from(parse_hex(parts.next()?)?).ok()?;
    let msg_id = <[u8; 16]>::try_from(parse_hex(parts.next()?)?).ok()?;
    let class = parse_class(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((MailboxAddress(target), msg_id, class))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Inner message types `payload` decodes as.
pub(crate) fn decodes_as(payload: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    if from_cbor_bytes::<SelfPointer>(payload).is_ok() {
        out.push("SelfPointer");
    }
    if from_cbor_bytes::<PosHashChallengeMsg>(payload).is_ok() {
        out.push("PosHashChallengeMsg");
    }
    if from_cbor_bytes::<PosHashResponseMsg>(payload).is_ok() {
        out.push("PosHashResponseMsg");
    }
    if from_cbor_bytes::<SymbolDropNoticeBatchMsg>(payload).is_ok() {
        out.push("SymbolDropNoticeBatchMsg");
    }
    if from_cbor_bytes::<DeleteRequestPayload>(payload).is_ok() {
        out.push("DeleteRequestPayload");
    }
    if from_cbor_bytes::<RevocationBroadcast>(payload).is_ok() {
        out.push("RevocationBroadcast");
    }
    out
}

fn map_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

/// Audit the stored CBOR bytes of one entry.
pub(crate) fn audit_entry(
    bytes: &[u8],
    needles: &[Needle],
    known: &[(String, [u8; 32])],
) -> EntryAudit {
    let generic: Option<Value> = ciborium::de::from_reader(bytes).ok();
    let map: &[(Value, Value)] = match &generic {
        Some(Value::Map(m)) => m,
        _ => &[],
    };
    let sender = map_field(map, "sender");

    // Bytes the needles are searched in: the stored record with its `target`
    // blanked, so an address that happens to equal a needle is not a hit.
    let searchable = match &generic {
        Some(Value::Map(m)) => {
            let blanked: Vec<(Value, Value)> = m
                .iter()
                .map(|(k, v)| match k {
                    Value::Text(t) if t == "target" => (k.clone(), Value::Null),
                    _ => (k.clone(), v.clone()),
                })
                .collect();
            let mut out = Vec::new();
            ciborium::ser::into_writer(&Value::Map(blanked), &mut out)
                .expect("re-encoding a decoded CBOR value cannot fail");
            out
        }
        _ => bytes.to_vec(),
    };
    let found: Vec<String> = needles
        .iter()
        .filter(|n| n.forms.iter().any(|f| contains(&searchable, f)))
        .map(|n| n.label.clone())
        .collect();

    let typed: Result<MailboxEntry, _> = from_cbor_bytes(bytes);
    let (target, class, version, payload, msg_id, stored_at, expires_at, err) = match typed {
        Ok(e) => (
            e.target.0,
            format!("{:?}", e.class),
            e.payload_version,
            e.payload,
            e.msg_id,
            e.stored_at,
            e.expires_at,
            None,
        ),
        Err(err) => (
            [0; 32],
            "?".into(),
            0,
            Vec::new(),
            [0; 16],
            0,
            0,
            Some(err.to_string()),
        ),
    };
    let target_is = known
        .iter()
        .filter(|(_, k)| *k == target || Sha256::digest(k).as_slice() == target.as_slice())
        .map(|(label, _)| label.clone())
        .collect();

    EntryAudit {
        target: hex_encode(&target),
        class,
        payload_version: version,
        entry_len: bytes.len(),
        payload_len: payload.len(),
        msg_id: hex_encode(&msg_id),
        stored_at,
        expires_at,
        decodes_as: decodes_as(&payload),
        sender_key: sender.is_some(),
        sender_non_null: sender.is_some_and(|v| !v.is_null()),
        needles: found,
        target_is,
        decode_error: err,
    }
}

pub(crate) fn report(entries: Vec<EntryAudit>) -> Report {
    let mut summary = Summary {
        total: entries.len(),
        by_class: BTreeMap::new(),
        by_version: BTreeMap::new(),
        decodable: 0,
        with_sender_key: 0,
        with_needles: 0,
    };
    for e in &entries {
        *summary.by_class.entry(e.class.clone()).or_insert(0) += 1;
        *summary.by_version.entry(e.payload_version).or_insert(0) += 1;
        summary.decodable += usize::from(!e.decodes_as.is_empty());
        summary.with_sender_key += usize::from(e.sender_key);
        summary.with_needles += usize::from(!e.needles.is_empty());
    }
    Report { summary, entries }
}

#[cfg(test)]
mod tests;
