//! DR's block work memory (К-b3, restore-i39; spec v3.8 §2, v3.9a).
//!
//! The decode of an SS block is block work and takes memory like any other: one block at a time,
//! sized by `estimate_restore_network` of the block's parameters, from the fetch of its symbols
//! (outside) to the decrypted plaintext (inside), released before the CBOR is parsed and before
//! the next fetch. Whose budget it is depends on the machine's block work lock
//! (`mem_budget::machine_lock`):
//!
//!   * the lock is free: this DR takes it, writes `{kind: dr}`, and works on a budget of its own
//!     from the same `M` (`block_work_budget_bytes`), holding the lock to the end — a node that
//!     starts meanwhile brings the network up and waits for it;
//!   * a node holds it: for each SS block the DR leases the memory from that node
//!     (`POST /api/budget/lease`, by block id and encrypted size; the node does the sums) and gives
//!     it back (`POST /api/budget/release`) before the next block. The DR's decode is then a
//!     part of the node's budget: the sum does not grow, and the node's worker and PoS checks
//!     yield to it as to a restore;
//!   * a node holds it and does not answer: DR waits, trying again every 30 s — and takes the
//!     lock itself if the node has stopped; a node too old to know the request makes DR stop with
//!     a message.

use std::sync::Arc;
use std::time::Duration;

use viaticum_core::types::{ErasureParams, SourceBlockId};

use super::DrError;
use crate::daemon::backup::size_limit::machine_ram_limit_bytes;
use crate::daemon::mem_budget::machine_lock::{
    self, LockKind, LockOutcome, LockRecord, MachineLock,
};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, MemPermit, TEST_BUDGET_ENV, estimate_restore_network,
    resolve_block_work_budget,
};

/// DR prints that it waits for memory after this (the wait is the node's, or a budget too small
/// for the block).
const WAIT_SHOWN_AFTER: Duration = Duration::from_secs(5);

/// Between two tries when the node on this machine does not answer.
const SILENT_NODE_RETRY: Duration = Duration::from_secs(30);

/// A silent node: nothing, not even a blank line of the keepalive, for this long.
const SILENCE: Duration = Duration::from_secs(30);

/// The connect timeout to the node on this machine.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const SILENT_NODE_LINE: &str = "dr: the node on this machine does not answer; waiting for it to \
                                answer or stop (Ctrl+C to cancel)";

/// `dr: waiting for memory (N MiB)` — what DR says when the wait outlasts 5 s.
fn waiting_line(need_bytes: u64) -> String {
    format!(
        "dr: waiting for memory ({} MiB)",
        need_bytes.div_ceil(1 << 20)
    )
}

/// Why a lease was not obtained.
#[derive(Debug)]
enum LeaseFailure {
    /// The node does not answer (or answers nothing): wait and try again.
    Silent(String),
    /// The node does not know the request (an older version).
    OldNode,
    /// The node refused the request itself.
    Refused(String),
}

/// Where DR's lines go (stdout; a test collects them).
type Say = Arc<dyn Fn(String) + Send + Sync>;

fn stdout() -> Say {
    Arc::new(|line| println!("{line}"))
}

/// How DR gets memory for its SS blocks.
pub(super) struct Memory {
    mode: Mode,
    /// A failure that must end DR, whatever pointer is tried next (an old node).
    fatal: Option<DrError>,
    /// Where the lock files live (tests give their own).
    lock_dir: std::path::PathBuf,
    say: Say,
    /// Between two tries when the node on this machine does not answer.
    silent_retry: Duration,
}

enum Mode {
    /// DR's own budget; `lock` is the machine lock it holds (`None`: no lock could be used).
    Own {
        budget: Arc<MemBudget>,
        _lock: Option<MachineLock>,
    },
    /// The node holding the lock lends the memory.
    Lease(NodeClient),
}

/// What DR holds for one SS block: the permit its decode runs under and, when the memory is
/// leased, the lease to give back.
pub(super) struct BlockMemory {
    permit: MemPermit,
    lease: Option<ActiveLease>,
    say: Say,
}

impl BlockMemory {
    pub(super) fn permit(&self) -> &MemPermit {
        &self.permit
    }

    /// Give the memory back: before the CBOR of the block is parsed and before the next fetch.
    /// A lease the node took back at its ceiling is said in one line; DR goes on.
    pub(super) async fn release(self) {
        let BlockMemory { permit, lease, say } = self;
        drop(permit);
        if let Some(lease) = lease
            && lease.release().await == Some(true)
        {
            say(
                "dr: the node took the memory lease of a block back (it was held too long); \
                 continuing"
                    .to_string(),
            );
        }
    }
}

/// The budget of a DR process of this machine: `M·14/32` like the node's (the test override
/// of the budget applies to DR as well).
fn own_budget() -> Arc<MemBudget> {
    MemBudget::new(resolve_block_work_budget(
        machine_ram_limit_bytes(),
        std::env::var(TEST_BUDGET_ENV).ok().as_deref(),
    ))
}

impl Memory {
    /// Decide whose memory DR works on (see the module header). Blocking: one file.
    pub(super) fn open() -> Result<Memory, DrError> {
        Self::open_in(machine_lock::machine_lock_dir(), own_budget)
    }

    pub(super) fn open_in(
        lock_dir: std::path::PathBuf,
        budget: impl FnOnce() -> Arc<MemBudget>,
    ) -> Result<Memory, DrError> {
        let mode = match machine_lock::try_lock(&lock_dir, &LockRecord::dr()) {
            LockOutcome::Acquired(lock) => Mode::Own {
                budget: budget(),
                _lock: Some(lock),
            },
            LockOutcome::Unavailable(why) => {
                eprintln!(
                    "warning: this machine's block work lock is not used ({why}); DR works on a \
                     budget of its own"
                );
                Mode::Own {
                    budget: budget(),
                    _lock: None,
                }
            }
            LockOutcome::HeldElsewhere(Some(held)) if held.kind == LockKind::Dr => {
                return Err(DrError::Failed {
                    reason: "another viaticum dr is running on this machine; wait for it to \
                             finish"
                        .to_string(),
                    hint: String::new(),
                });
            }
            // A node (or a holder whose record cannot be read: treated as a node).
            LockOutcome::HeldElsewhere(held) => {
                Mode::Lease(NodeClient::new(held.and_then(|h| h.data_dir)))
            }
        };
        Ok(Memory {
            mode,
            fatal: None,
            lock_dir,
            say: stdout(),
            silent_retry: SILENT_NODE_RETRY,
        })
    }

    /// DR's own budget in a test, without a lock.
    #[cfg(test)]
    pub(super) fn own_for_test(budget: Arc<MemBudget>) -> Memory {
        Memory {
            mode: Mode::Own {
                budget,
                _lock: None,
            },
            fatal: None,
            lock_dir: std::path::PathBuf::new(),
            say: stdout(),
            silent_retry: SILENT_NODE_RETRY,
        }
    }

    /// Test seam: DR's lines go to `say`, and a silent node is tried again after `retry`.
    #[cfg(test)]
    pub(super) fn with_test_seams(mut self, say: Say, retry: Duration) -> Memory {
        self.say = say;
        self.silent_retry = retry;
        self
    }

    /// The failure that must end DR, if one happened (taken once).
    pub(super) fn take_fatal(&mut self) -> Option<DrError> {
        self.fatal.take()
    }

    pub(super) fn is_fatal(&self) -> bool {
        self.fatal.is_some()
    }

    /// Memory for the decode of one SS block, after its symbols are in (they are outside the
    /// budget while DR waits, as the fetched symbols of a waiting restore block are).
    pub(super) async fn acquire(
        &mut self,
        block: &SourceBlockId,
        encrypted_size: u64,
        params: &ErasureParams,
    ) -> Result<BlockMemory, DrError> {
        let need = estimate_restore_network(params.k, params.t);
        let mut said_silent = false;
        loop {
            match &mut self.mode {
                Mode::Own { budget, .. } => {
                    let say = Arc::clone(&self.say);
                    let permit = budget
                        .acquire(HolderKind::Dr, block, need, WAIT_SHOWN_AFTER, |_| {
                            say(waiting_line(need.min(budget.total_bytes())));
                        })
                        .await;
                    return Ok(BlockMemory {
                        permit,
                        lease: None,
                        say: Arc::clone(&self.say),
                    });
                }
                Mode::Lease(client) => match client
                    .lease(block, encrypted_size, need, &self.say)
                    .await
                {
                    Ok((lease, permit)) => {
                        return Ok(BlockMemory {
                            permit,
                            lease: Some(lease),
                            say: Arc::clone(&self.say),
                        });
                    }
                    Err(LeaseFailure::OldNode) => {
                        let e = DrError::NodeCannotShareMemory;
                        self.fatal = Some(DrError::NodeCannotShareMemory);
                        return Err(e);
                    }
                    Err(LeaseFailure::Refused(why)) => {
                        return Err(DrError::Failed {
                            reason: format!("the node on this machine refused the lease: {why}"),
                            hint: String::new(),
                        });
                    }
                    Err(LeaseFailure::Silent(why)) => {
                        tracing::debug!("dr: lease: {why}");
                        if !said_silent {
                            (self.say)(SILENT_NODE_LINE.to_string());
                            said_silent = true;
                        }
                        tokio::time::sleep(self.silent_retry).await;
                        // The node may have stopped: then its lock is free and DR works alone.
                        let dir = self.lock_dir.clone();
                        let outcome = tokio::task::spawn_blocking(move || {
                            machine_lock::try_lock(&dir, &LockRecord::dr())
                        })
                        .await;
                        if let Ok(LockOutcome::Acquired(lock)) = outcome {
                            self.mode = Mode::Own {
                                budget: own_budget(),
                                _lock: Some(lock),
                            };
                        }
                    }
                },
            }
        }
    }
}

// ─── The node on this machine ─────────────────────────────────────────────────

/// The HTTP client of the node that holds the machine's lock: its `api-port` and `api-token` are
/// in its data directory (the lock file says where).
struct NodeClient {
    data_dir: Option<std::path::PathBuf>,
}

/// A lease the node gave: the open response is the "connection" the node ties the lease to.
struct ActiveLease {
    response: reqwest::Response,
    id: u64,
    base: String,
    token: String,
    http: reqwest::Client,
}

impl ActiveLease {
    /// Give the lease back. `Some(true)`: the node had taken it back already.
    async fn release(self) -> Option<bool> {
        let answered = self
            .http
            .post(format!("{}/api/budget/release", self.base))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "id": self.id }))
            .send()
            .await
            .ok()?;
        let body: serde_json::Value = answered.json().await.ok()?;
        // Dropping the response closes the connection, the node's second way to release.
        drop(self.response);
        Some(body["status"] == "revoked")
    }
}

impl NodeClient {
    fn new(data_dir: Option<String>) -> Self {
        NodeClient {
            data_dir: data_dir.map(std::path::PathBuf::from),
        }
    }

    /// Ask the node for the memory of one SS block; on the grant, a permit of a small private
    /// budget of that size stands for it in DR's own decode (the wrapper wants a permit).
    async fn lease(
        &self,
        block: &SourceBlockId,
        encrypted_size: u64,
        need: u64,
        say: &Say,
    ) -> Result<(ActiveLease, MemPermit), LeaseFailure> {
        let silent = |why: String| LeaseFailure::Silent(why);
        let dir = self
            .data_dir
            .as_ref()
            .ok_or_else(|| silent("the lock file does not say where the node's API is".into()))?;
        let (port, token) = crate::daemon::web_auth::read_port_and_token(dir)
            .map_err(|e| silent(format!("cannot read the node's api-port or api-token: {e}")))?;
        let base = format!("http://127.0.0.1:{port}");
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| silent(e.to_string()))?;
        let mut response = http
            .post(format!("{base}/api/budget/lease"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "block_id": viaticum_core::types::hex_encode(&block.0),
                "encrypted_size": encrypted_size,
            }))
            .send()
            .await
            .map_err(|e| silent(e.to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(silent("the node did not accept the token".into()));
        }
        // An old node answers an unknown request with its web page (or a 404): not a stream of
        // lines.
        let is_lines = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/x-ndjson"));
        if !is_lines {
            return Err(LeaseFailure::OldNode);
        }
        let id = read_grant(&mut response, need, say).await?;
        let witness = MemBudget::new(need);
        let block_id = *block;
        let permit = witness
            .try_acquire(HolderKind::Dr, &block_id, need)
            .ok_or_else(|| silent("a private budget refused its own size".into()))?;
        Ok((
            ActiveLease {
                response,
                id,
                base,
                token,
                http,
            },
            permit,
        ))
    }
}

/// Read the lines of a lease response until the grant. Blank lines are the keepalive.
async fn read_grant(
    response: &mut reqwest::Response,
    need: u64,
    say: &Say,
) -> Result<u64, LeaseFailure> {
    let silent = |why: String| LeaseFailure::Silent(why);
    let mut pending = Vec::<u8>::new();
    let slow = tokio::time::sleep(WAIT_SHOWN_AFTER);
    tokio::pin!(slow);
    let mut shown = false;
    loop {
        let chunk = tokio::select! {
            _ = &mut slow, if !shown => {
                shown = true;
                say(waiting_line(need));
                continue;
            }
            chunk = tokio::time::timeout(SILENCE, response.chunk()) => chunk,
        };
        match chunk {
            Err(_) => return Err(silent("the node sent nothing for 30 s".into())),
            Ok(Err(e)) => return Err(silent(e.to_string())),
            Ok(Ok(None)) => return Err(silent("the node ended the lease response".into())),
            Ok(Ok(Some(bytes))) => pending.extend_from_slice(&bytes),
        }
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                return Err(LeaseFailure::OldNode);
            };
            match value["lease"].as_str() {
                Some("granted") => {
                    return value["id"]
                        .as_u64()
                        .ok_or_else(|| silent("a grant without an id".into()));
                }
                Some("error") => {
                    return Err(LeaseFailure::Refused(
                        value["message"].as_str().unwrap_or("").to_string(),
                    ));
                }
                _ => return Err(LeaseFailure::OldNode),
            }
        }
    }
}
