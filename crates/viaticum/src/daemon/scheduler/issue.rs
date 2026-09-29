// Owner side of PoS issuance: the issue tick (pos-i7, pos-i7-a).
//
// One tick finds the due placements, orders their blocks least recently verified first,
// and per block re-encodes the source once and publishes one challenge per holder. The
// publishes run `ISSUE_PUBLISH_CONCURRENCY` at a time and overlap the next block's
// encode. The tick stops starting blocks when its time budget (a fifth of the PoS tick
// period) would run out: the rest stays due and goes next tick — nothing is stored for
// it. The tick runs inside the scheduler's `select!` loop, so while it runs no response
// is resolved, no ledger accrues and no timeout is checked: the budget is what keeps
// the loop's other work going (pos-i7-a).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::{JoinError, JoinSet};
use tracing::instrument::WithSubscriber;
use tracing::{debug, error, info, warn};
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::to_cbor;
use viaticum_core::pos::{ChallengeScheduleEntry, due_challenges};
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp, hex_encode,
};

use super::{
    PendingHashChallenge, PendingKey, Scheduler, holder_trust_map, random_challenge_id,
    scaled_timer_secs,
};
use crate::daemon::mailbox::routing::MailboxRouter;

/// An issue tick may spend 1 / `ISSUE_BUDGET_DIVISOR` of the PoS tick period (pos-i7-a:
/// ≈ 20 %, the bar of the tick's `elapsed_ms`).
const ISSUE_BUDGET_DIVISOR: u32 = 5;

/// Challenge publishes in flight at once within one issue tick (pos-i7-a). A publish
/// returns at its first postman Ack (mailbox-i60), ~15 ms on a LAN, while a block's
/// re-encode is ~100 ms at 1 MiB: 16 in flight keep the publishes of about two blocks of
/// 8 holders going under the next block's encode, the tick's serial cost.
pub(crate) const ISSUE_PUBLISH_CONCURRENCY: usize = 16;

/// The time budget of one issue tick: a fifth of the PoS tick period, which is scaled
/// by `time_scale` like the timer itself (`scaled_timer_secs`, floor 1 s). Production
/// (3600 s, scale 1): 720 s; the E2E at scale 900: 800 ms.
pub(crate) fn issue_budget(pos_interval_secs: u64, time_scale: u64) -> Duration {
    Duration::from_secs(scaled_timer_secs(pos_interval_secs, time_scale)) / ISSUE_BUDGET_DIVISOR
}

/// Counters of one PoS issue tick, printed by `scheduler: PoS issue tick` (pos-i7).
#[derive(Debug, Default)]
struct IssueTick {
    /// Placements due this tick (`due_challenges`).
    due: usize,
    /// Challenges published with ≥ 1 ack and put in pending.
    issued: usize,
    /// Due placements skipped because a challenge is already pending for them.
    skipped_pending: usize,
    /// Due placements not pending whose block the tick did not start: the budget ran
    /// out (pos-i7-a). They stay due for the next tick.
    deferred: usize,
    /// Challenge publishes with 0 acks or an error (retried next tick).
    zero_ack: usize,
    cpw_min: u32,
    cpw_max: u32,
    /// The longest publish of this tick, from spawn to its first Ack (or its end).
    slowest_publish: Duration,
}

/// One challenge of a block, its expected answer computed.
struct PreparedChallenge {
    holder_id: DeviceId,
    challenge_id: [u8; 16],
    expected_chain_hash: [u8; 32],
    esi_ranges: Vec<(u32, u32)>,
}

/// A challenge publish that ended: what goes into pending on an Ack.
struct Published {
    challenge: PendingHashChallenge,
    cpw: u32,
    acks: anyhow::Result<usize>,
    took: Duration,
}

/// The due entries grouped by block, blocks in the order of their least recently
/// verified entry (a never-verified one first); equal blocks keep the order of `due`.
///
/// Fairness of a tick cut by the budget (pos-i7-a): the tail of this order stays due.
/// An issued challenge leaves the due set while it is pending, and a Pass moves its
/// placement's `last_verified` to now — to the back. So the next tick starts with what
/// this one did not reach, and no placement waits behind one verified more recently.
/// What stays at the front is only what could not be issued at all (0 acks, a block
/// that cannot be loaded) — the least verified, rightly first.
pub(crate) fn blocks_least_recently_verified_first<'a>(
    due: impl IntoIterator<Item = &'a ChallengeScheduleEntry>,
    last_verified: impl Fn(&PendingKey) -> Option<Timestamp>,
) -> Vec<(SourceBlockId, Vec<&'a ChallengeScheduleEntry>)> {
    let mut order: Vec<SourceBlockId> = Vec::new();
    // Per block: its least recent `last_verified` (None < Some) and its entries.
    let mut by_block: HashMap<SourceBlockId, (Option<Timestamp>, Vec<&ChallengeScheduleEntry>)> =
        HashMap::new();
    for e in due {
        let lv = last_verified(&(e.source_block_id, e.holder_id));
        let slot = by_block.entry(e.source_block_id).or_insert_with(|| {
            order.push(e.source_block_id);
            (lv, Vec::new())
        });
        slot.0 = slot.0.min(lv);
        slot.1.push(e);
    }
    order.sort_by_key(|b| by_block[b].0);
    order
        .into_iter()
        .filter_map(|b| by_block.remove(&b).map(|(_, entries)| (b, entries)))
        .collect()
}

impl Scheduler {
    /// Issue PoS hash challenges to the holders that are due, within the tick's budget.
    ///
    /// Steps:
    ///   1. List the challengeable placements (Alive / Uncertain / PresumedLost, SS
    ///      blocks excluded — Bug-B); `due_challenges` picks the due ones.
    ///   2. Skip placements with a challenge already pending (no double issue).
    ///   3. Order the blocks least recently verified first (fairness, see
    ///      `blocks_least_recently_verified_first`).
    ///   4. Per block, while the budget lasts: encode_raw once (union of the holders' ESI
    ///      ranges), per holder the binding + chain hash in spawn_blocking; then spawn one
    ///      publish per holder, at most `ISSUE_PUBLISH_CONCURRENCY` in flight.
    ///   5. Each challenge takes its own time when it is published: `timestamp`,
    ///      `expires_at`, `stored_at` and the pending `issued_at` (pos-i7-a) — a long tick
    ///      does not age its late challenges.
    ///   6. W-3: a challenge goes into pending ONLY after ≥ 1 MailboxStoreAck; 0 acks =
    ///      retry next tick. The poll loop does not remember a response to a challenge
    ///      not pending yet (pos-i6), so one that races its pending entry is forwarded
    ///      by the next poll.
    ///
    /// Budget: a block starts only if the time spent plus the slowest block and the
    /// slowest publish of this tick still fit `issue_budget` (the first block always
    /// starts, so a block slower than the budget is still issued). The tick then waits
    /// for its publishes in flight.
    ///
    /// pos-i7: linear in the placements — `due_challenges` indexes `last_verified`, the
    /// pending keys are a set, the placements are indexed by (block, holder), and a
    /// holder's trust is read once per tick. A tick with due challenges ends with one
    /// INFO line `scheduler: PoS issue tick` (due, issued, skipped_pending, deferred,
    /// zero_ack, elapsed_ms, cpw_min, cpw_max).
    pub async fn issue_due_challenges(&self) -> anyhow::Result<()> {
        let started = Instant::now();
        let budget = issue_budget(self.config.pos_interval_secs, self.config.time_scale);
        // Decides what is due; every challenge takes its own time at publish (pos-i7-a).
        let tick_now = Timestamp::now();

        let placements = match self.db.list_all_placements() {
            Ok(ps) => ps,
            Err(e) => {
                error!("scheduler: list_all_placements failed: {e}");
                return Ok(());
            }
        };

        // Bug-B: SS-blocks are excluded from due_challenges until hash-PoS for SS-blocks
        // is implemented (separate near-term task, high priority). See TODO(bug-b) in pos/mod.rs.
        let ss_ids = match self.db.ss_block_id_set() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    "scheduler: ss_block_id_set failed: {e}; treating as empty (may challenge SS blocks)"
                );
                HashSet::new()
            }
        };

        // Only challenge placements in a challengeable state, excluding SS-blocks.
        let challengeable: Vec<_> = placements
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                ) && !ss_ids.contains(&p.source_block_id.0)
            })
            .collect();

        if challengeable.is_empty() {
            debug!("scheduler: no challengeable placements");
            return Ok(());
        }

        // Build last_verified slice for due_challenges.
        let last_verified: Vec<_> = challengeable
            .iter()
            .map(|p| (p.source_block_id, p.holder_id, p.last_verified))
            .collect();

        // 5b (pos-i7): a holder's trust is three redb reads; read it once per holder per
        // tick, not once per placement.
        let trust = holder_trust_map(&challengeable, |h| self.holder_trust(h));

        let due = due_challenges(
            &challengeable,
            &last_verified,
            tick_now,
            |h| trust.get(h).copied().unwrap_or(0.5),
            self.config.time_scale,
        );

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            return Ok(());
        }
        let mut tick = IssueTick {
            due: due.len(),
            cpw_min: due.iter().map(|e| e.cpw).min().unwrap_or(0),
            cpw_max: due.iter().map(|e| e.cpw).max().unwrap_or(0),
            ..IssueTick::default()
        };

        // Snapshot pending keys once to avoid repeatedly locking inside the loop.
        let already_pending: HashSet<PendingKey> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };

        // The challengeable placements by (block, holder), built once per tick.
        let placement_of: HashMap<PendingKey, &SymbolPlacement> = challengeable
            .iter()
            .map(|p| ((p.source_block_id, p.holder_id), p))
            .collect();

        let not_pending: Vec<&ChallengeScheduleEntry> = due
            .iter()
            .filter(|e| !already_pending.contains(&(e.source_block_id, e.holder_id)))
            .collect();
        tick.skipped_pending = due.len() - not_pending.len();
        let blocks = blocks_least_recently_verified_first(not_pending, |k| {
            placement_of.get(k).and_then(|p| p.last_verified)
        });

        let mut publishes: JoinSet<Published> = JoinSet::new();
        let mut slowest_block = Duration::ZERO;
        let mut blocks_started = 0usize;
        let mut blocks = blocks.into_iter();
        while let Some((block_id, block_entries)) = blocks.next() {
            while let Some(done) = publishes.try_join_next() {
                self.settle_publish(done, &mut tick).await;
            }
            // pos-i7-a: start a block only while it fits the budget. The first block
            // always starts: a tick issues something even if one block outlasts it.
            if blocks_started > 0
                && started.elapsed() + slowest_block + tick.slowest_publish > budget
            {
                tick.deferred =
                    block_entries.len() + blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                break;
            }
            blocks_started += 1;
            let block_started = Instant::now();

            let cpw_of: HashMap<DeviceId, u32> =
                block_entries.iter().map(|e| (e.holder_id, e.cpw)).collect();
            let holder_placements: Vec<&SymbolPlacement> = block_entries
                .iter()
                .filter_map(|e| placement_of.get(&(e.source_block_id, e.holder_id)).copied())
                .collect();

            for prepared in self.prepare_block(block_id, &holder_placements).await {
                while publishes.len() >= ISSUE_PUBLISH_CONCURRENCY {
                    match publishes.join_next().await {
                        Some(done) => self.settle_publish(done, &mut tick).await,
                        None => break,
                    }
                }
                let cpw = cpw_of.get(&prepared.holder_id).copied().unwrap_or(0);
                if let Some((entry, challenge)) = self.challenge_entry(block_id, prepared) {
                    publishes.spawn(
                        publish_challenge(Arc::clone(&self.mailbox_router), entry, challenge, cpw)
                            .with_current_subscriber(),
                    );
                }
            }
            slowest_block = slowest_block.max(block_started.elapsed());
        }
        while let Some(done) = publishes.join_next().await {
            self.settle_publish(done, &mut tick).await;
        }

        // pos-i7 observable: one line per tick with due challenges.
        info!(
            due = tick.due,
            issued = tick.issued,
            skipped_pending = tick.skipped_pending,
            deferred = tick.deferred,
            zero_ack = tick.zero_ack,
            elapsed_ms = started.elapsed().as_millis() as u64,
            cpw_min = tick.cpw_min,
            cpw_max = tick.cpw_max,
            "scheduler: PoS issue tick"
        );

        Ok(())
    }

    /// Re-encode one block once and compute every holder's expected chain hash (pos-i7:
    /// the honest cost, 1× per block per tick). Empty when the block cannot be served
    /// this tick (logged).
    async fn prepare_block(
        &self,
        block_id: SourceBlockId,
        holder_placements: &[&SymbolPlacement],
    ) -> Vec<PreparedChallenge> {
        if holder_placements.is_empty() {
            return Vec::new();
        }

        // Load source block data (retained SS blob, else rebuild from source files).
        let source_data = match self.load_source_block_data(&block_id).await {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    block_id = %block_id,
                    err = %e,
                    "scheduler: cannot load source block for PoS hash, skipping"
                );
                return Vec::new();
            }
        };

        let block_record = match self.db.get_source_block(&block_id) {
            Ok(Some(r)) => r,
            _ => {
                warn!(block_id = %block_id, "scheduler: source block record missing, skipping");
                return Vec::new();
            }
        };
        let params = block_record.erasure_params();

        // Compute union of all ESI ranges across all holders for this block.
        let mut all_esi_ranges: Vec<(u32, u32)> = Vec::new();
        for p in holder_placements {
            all_esi_ranges.extend_from_slice(&p.esi_ranges);
        }

        // Per-holder data for the spawn_blocking closure.
        let holder_data: Vec<(DeviceId, Vec<(u32, u32)>)> = holder_placements
            .iter()
            .map(|p| (p.holder_id, p.esi_ranges.clone()))
            .collect();

        // Generate challenge_ids BEFORE spawn_blocking so the OsRng nonce is committed
        // before compute_chain_hash runs. This binds expected_hash to this challenge_id.
        let challenge_ids: HashMap<DeviceId, [u8; 16]> = holder_data
            .iter()
            .map(|(holder_id, _)| (*holder_id, random_challenge_id()))
            .collect();
        let challenge_ids_clone = challenge_ids.clone();

        let encoder = Arc::clone(&self.encoder);
        let block_id_clone = block_id;

        // encode_raw once for the block, then compute per-holder chain hashes.
        #[allow(clippy::type_complexity)]
        let hash_results =
            tokio::task::spawn_blocking(move || -> Vec<(DeviceId, [u8; 32], Vec<(u32, u32)>)> {
                // Encode raw symbols for the union of all holders' ESI ranges.
                let mut raw_symbols: HashMap<u32, Vec<u8>> = HashMap::new();
                for &(start, count) in &all_esi_ranges {
                    if count == 0 {
                        continue;
                    }
                    match encoder.encode_raw(&source_data, &params, start, count) {
                        Ok(syms) => {
                            for sym in syms {
                                raw_symbols.insert(sym.esi, sym.data);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                block_id = %block_id_clone,
                                "scheduler: encode_raw failed: {e}"
                            );
                            return vec![];
                        }
                    }
                }

                // Per-holder: apply binding, compute chain hash.
                let mut results = Vec::new();
                for (holder_id, esi_ranges) in &holder_data {
                    // Expand ranges to sorted ESI list.
                    let mut esis: Vec<u32> = esi_ranges
                        .iter()
                        .flat_map(|&(start, count)| start..start + count)
                        .collect();
                    esis.sort_unstable();

                    // Apply binding keystream and collect bound symbols.
                    let bound_pairs: Vec<(u32, Vec<u8>)> = esis
                        .iter()
                        .filter_map(|&esi| {
                            raw_symbols.get(&esi).map(|raw_data| {
                                let mut data = raw_data.clone();
                                let ks = viaticum_core::erasure::binding_keystream(
                                    &block_id_clone,
                                    holder_id,
                                    esi,
                                    data.len(),
                                );
                                for (d, k) in data.iter_mut().zip(ks.iter()) {
                                    *d ^= k;
                                }
                                (esi, data)
                            })
                        })
                        .collect();

                    let refs: Vec<(u32, &[u8])> = bound_pairs
                        .iter()
                        .map(|(esi, data)| (*esi, data.as_slice()))
                        .collect();

                    // Use the pre-generated challenge_id to seed the chain hash.
                    // Invariant: challenge_ids_clone is built from the same holder_data
                    // iterated here, so the key is always present. Falling back to a
                    // constant seed would silently bind chain_hash to a known value —
                    // expect() surfaces any future invariant violation immediately.
                    let cid = *challenge_ids_clone
                        .get(holder_id)
                        .expect("challenge_id always present: built from same holder_data");
                    match viaticum_core::pos::compute_chain_hash(&cid, &refs) {
                        Ok(hash) => results.push((*holder_id, hash, esi_ranges.clone())),
                        Err(e) => {
                            tracing::error!(
                                holder = %holder_id,
                                block_id = %block_id_clone,
                                "scheduler: chain hash failed: {e}"
                            );
                        }
                    }
                }
                results
            })
            .await;

        // CS-POS-8: a JoinError here means the blocking task panicked (e.g. the
        // `expect` inside it). `unwrap_or_default()` would silently swallow that and
        // skip the whole block with zero logs. Log it loudly and degrade gracefully —
        // treat it as "no hashes for this block this tick" rather than re-panicking the
        // scheduler task.
        let hash_results = match hash_results {
            Ok(results) => results,
            Err(join_err) => {
                error!(
                    block_id = %block_id,
                    err = %join_err,
                    "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block this tick"
                );
                return Vec::new();
            }
        };

        hash_results
            .into_iter()
            .map(
                |(holder_id, expected_chain_hash, esi_ranges)| PreparedChallenge {
                    holder_id,
                    challenge_id: challenge_ids[&holder_id],
                    expected_chain_hash,
                    esi_ranges,
                },
            )
            .collect()
    }

    /// The signed mailbox entry of one challenge and its pending record, both stamped
    /// with the time of this call — the moment the challenge is published (pos-i7-a).
    /// None when the challenge cannot be encoded (logged).
    fn challenge_entry(
        &self,
        block_id: SourceBlockId,
        c: PreparedChallenge,
    ) -> Option<(MailboxEntry, PendingHashChallenge)> {
        let holder_master = self
            .db
            .get_master_for_device(&c.holder_id)
            .ok()
            .flatten()
            .map(|m| IdentityPub(m.0))
            .unwrap_or_else(|| IdentityPub(c.holder_id.0));

        let now = Timestamp::now();
        // CS-ID-5 / P1-2: sign the challenge with our master key so the holder can
        // authenticate it against MailboxEntry.sender before doing any disk work.
        let challenge_msg = viaticum_core::messages::build_pos_hash_challenge(
            c.challenge_id,
            block_id,
            c.esi_ranges.clone(),
            now,
            Some(c.holder_id),
            &self.signing_key,
        );
        let payload = match to_cbor(&challenge_msg) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    holder_id = %c.holder_id,
                    err = %e,
                    "scheduler: failed to encode PosHashChallenge"
                );
                return None;
            }
        };

        let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
            viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
            self.config.time_scale,
        );
        let entry = MailboxEntry {
            target: MailboxAddress::for_master(&holder_master),
            msg_id: c.challenge_id,
            class: MailboxClass::PosChallenge,
            payload_version: 1,
            payload,
            expires_at: now.0 + ttl_secs,
            stored_at: now.0,
            // W-3: sender is our master_pub so holder knows where to publish the response.
            sender: Some(self.my_master_pub),
        };
        // CS-POS-3: capture the holder_master resolved above so the response is later
        // verified against the SAME key the challenge was addressed to — not a re-resolve
        // that may have degraded to device-pub by then.
        let challenge = PendingHashChallenge {
            source_block_id: block_id,
            holder_id: c.holder_id,
            esi_ranges: c.esi_ranges,
            expected_chain_hash: c.expected_chain_hash,
            issued_at: now,
            challenge_id: c.challenge_id,
            holder_master,
        };
        Some((entry, challenge))
    }

    /// Account one ended publish: on ≥ 1 Ack the challenge goes into pending (W-3),
    /// on 0 acks or an error it stays due for the next tick.
    async fn settle_publish(&self, done: Result<Published, JoinError>, tick: &mut IssueTick) {
        let p = match done {
            Ok(p) => p,
            Err(join_err) => {
                error!(
                    err = %join_err,
                    "scheduler: PoS challenge publish task failed (panicked or cancelled) — will retry next tick"
                );
                tick.zero_ack += 1;
                return;
            }
        };
        tick.slowest_publish = tick.slowest_publish.max(p.took);
        let block_id = p.challenge.source_block_id;
        let holder_id = p.challenge.holder_id;
        // MAILBOX_STORE_TIMEOUT_SECS is the per-peer request timeout (enforced in routing.rs).
        match p.acks {
            Ok(0) => {
                warn!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    "scheduler: PoS challenge: 0 acks — treating as unsent, will retry next tick"
                );
                tick.zero_ack += 1;
                return;
            }
            Ok(ack_count) => {
                debug!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    ack_count,
                    "scheduler: PoS challenge published via mailbox"
                );
            }
            Err(e) => {
                warn!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    err = %e,
                    "scheduler: PoS challenge publish error — will retry next tick"
                );
                tick.zero_ack += 1;
                return;
            }
        }

        let challenge_id = p.challenge.challenge_id;
        self.pending
            .lock()
            .await
            .insert((block_id, holder_id), p.challenge);
        tick.issued += 1;
        info!(
            block_id = %block_id,
            holder_id = %holder_id,
            challenge_id = %hex_encode(&challenge_id),
            cpw = p.cpw,
            "scheduler: PoS hash challenge issued via mailbox"
        );
    }
}

/// Publish one challenge entry: returns at the first Ack (mailbox-i60) or when every
/// postman answered or timed out.
async fn publish_challenge(
    router: Arc<MailboxRouter>,
    entry: MailboxEntry,
    challenge: PendingHashChallenge,
    cpw: u32,
) -> Published {
    let started = Instant::now();
    let acks = router.publish(entry, None).await;
    Published {
        challenge,
        cpw,
        acks,
        took: started.elapsed(),
    }
}
