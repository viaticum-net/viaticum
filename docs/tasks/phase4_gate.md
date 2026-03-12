# Phase 4 GATE Tests — Task Spec

**Goal:** three integration tests proving that the full disaster recovery cycle works
end-to-end: backup → total loss → restore from seed phrase only → verify files.

**Test file:** `crates/syncback/tests/phase4_gate.rs`

**Run:** `cargo test -p syncback phase4 -- --test-threads=1 --nocapture`

---

## Prerequisites

All Phase 4 modules must be implemented before writing the GATE test.
The GATE test exercises the real code paths, not stubs.

| Spec | What it provides |
|---|---|
| `phase4_packer_update.md` | `DEFAULT_UNIT_SIZE_BYTES = 32 MB` (in packer/mod.rs), `MAX_MESSAGE_SIZE = 64 MB`, zstd compress/decompress in packer pipeline |
| `phase4_system_state.md` | `SystemState` struct, `snapshot_db`, `pack_system_state`, `unpack_system_state`, `restore_db` |
| `phase4_dr_flow.md` | New messages (`SystemStateBackup`, `SystemStateRequest`, `SystemStateResponse`, `SystemStateAck`), `SYSTEM_STATE_BLOBS` DB table, Processor handlers, `CliCmd::DrRestore`, `ScheduledCmd::SystemStateBackup` |

**Key difference from Phase 3 test 3** (`full_backup_restore_from_seed_inprocess`):
Phase 3 copied the DB file. Phase 4 destroys the DB entirely and reconstructs it from
system state downloaded from a peer.

---

## Test infrastructure

### Reuse from phase3_gate.rs

```rust
async fn wait_for_socket(path: &std::path::Path)
async fn send_cli_request_raw(path: &std::path::Path, req: &CliRequest) -> CliResponse
async fn wait_for_file(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()>
async fn connect_peers(socket: &std::path::Path, node_addr: &str) -> anyhow::Result<()>
async fn get_node_addr(socket: &std::path::Path) -> String
fn make_config(syncback_dir: PathBuf, include: Vec<IncludeEntry>) -> Config
fn fixed_mnemonic(seed: u8) -> Vec<String>   // entropy = [seed; 32]
```

### New helpers needed

```rust
/// Create N small test files with known content in dir.
/// Returns (relative_path_string, content_bytes) pairs.
fn create_test_files(dir: &std::path::Path, n: usize) -> Vec<(String, Vec<u8>)>;

/// Wait until Status.shards_placed >= min_shards or timeout.
async fn wait_for_shards_placed(
    socket: &std::path::Path,
    min_shards: usize,
    timeout: Duration,
) -> anyhow::Result<()>;

/// Wait until Status.system_state_backed_up == true or timeout.
/// Requires adding system_state_backed_up: bool to StatusPayload.
async fn wait_for_system_state_backup(
    socket: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<()>;

/// Destroy a node completely: remove all files from syncback_dir, remove user files.
fn destroy_node(syncback_dir: &std::path::Path, files_dir: &std::path::Path);
```

### New StatusPayload field

Add `system_state_backed_up: bool` to `StatusPayload` and `StatusReply`.
Processor tracks this as internal state (set to true after first successful system state backup).

### System state backup trigger

Per DR flow spec: `WeeklySync` handler calls `handle_system_state_backup()` at the end.
So `CliRequest::BackupNow` → `WeeklySync` → `handle_system_state_backup()` automatically.
The test triggers system state backup by calling `BackupNow`, then waits for
`system_state_backed_up == true` via `wait_for_system_state_backup`.

---

## Scenario 1: `phase4_full_dr_cycle_backup_destroy_restore`

The golden DR test. Proves that seed phrase + peer address is sufficient to recover all files.

### Signature

```rust
#[tokio::test]
async fn phase4_full_dr_cycle_backup_destroy_restore() {
    tokio::time::timeout(
        Duration::from_secs(180),
        run_full_dr_cycle(),
    )
    .await
    .expect("test timed out after 180s")
    .expect("test failed");
}
```

### Steps

```
Step 1: Create directory structure
  root/
    files_a/          ← original files (Node A owns these)
    node_a/           ← Node A syncback dir
    node_b/           ← Node B syncback dir (holder)
    node_c/           ← Node C syncback dir (holder)
    restored/         ← where files will be restored

Step 2: Write 5 test files of mixed content
  files_a/text1.txt       ← "hello world repeated\n" × 50  (compressible)
  files_a/text2.txt       ← "another text file\n" × 80     (compressible)
  files_a/config.json     ← '{"key":"value","n":42}\n' × 20
  files_a/binary1.bin     ← vec![0xAB; 4096]               (incompressible)
  files_a/binary2.bin     ← (0u8..=255).cycle().take(8192) (incompressible)

Step 3: Init Node A (seed = entropy [20u8; 32])
Step 4: Init Node B (seed = entropy [21u8; 32])
Step 5: Init Node C (seed = entropy [22u8; 32])

Step 6: Start Node B (holder)
  config_b: syncback_dir=node_b, storage.quota_gb=10, no backup includes
Step 7: Start Node C (holder)
  config_c: syncback_dir=node_c, storage.quota_gb=10, no backup includes
Step 8: Start Node A (owner)
  config_a: syncback_dir=node_a, backup.include=[{path=files_a, importance=0.9}],
            storage.quota_gb=1

Step 9: Wait for sockets on A, B, C

Step 10: Connect A → B and A → C
  connect_peers(sock_a, addr_b)
  connect_peers(sock_a, addr_c)
  sleep 500ms (allow handshake + PeerConnected to propagate)

Step 11: Trigger backup on Node A
  send_cli_request_raw(sock_a, CliRequest::BackupNow)
  assert response is Ok or Accepted

Step 12: Wait for shards placed (>= 1 placed means at least 1 unit uploaded)
  wait_for_shards_placed(sock_a, 1, Duration::from_secs(60))

Step 13: Wait for system state backup (triggered automatically after WeeklySync)
  wait_for_system_state_backup(sock_a, Duration::from_secs(30))

Step 14: Shutdown Node A
  handle_a.shutdown().await

Step 15: Destroy Node A completely
  destroy_node(node_a dir, files_a dir)
  assert !node_a/syncback.redb.exists()
  assert !files_a exists

Step 16: Create new Node A directory (empty, except identity.key re-derived from seed)
  Init with same mnemonic (entropy [20u8; 32]):
  syncback::cli::init::init_with_mnemonic(node_a_fresh, &mnemonic_a)
  // This creates identity.key with same keys as original Node A.
  // DB is empty — no file/unit/shard/peer records.

Step 17: Start fresh daemon A and send DrRestore
  config_a_fresh = make_config(node_a_fresh, vec![])  // no backup includes
  handle_a_fresh = DaemonHandle::start(config_a_fresh).await
  wait_for_socket(sock_a_fresh)

  resp = send_cli_request_raw(sock_a_fresh, CliRequest::DrRestore {
      seed_phrase: mnemonic_a_words.join(" "),
      peer_addr: addr_b,
  })
  assert matches!(resp, CliResponse::Ok { .. })
  // DrRestore is synchronous: daemon downloads, decrypts, populates DB before replying Ok.

Step 18: Verify DB was populated and restore files
  connect_peers(sock_a_fresh, addr_b)
  connect_peers(sock_a_fresh, addr_c)
  sleep 500ms

Step 19: Restore each of the 5 files
  For each (rel_path, original_content) in test_files:
    dest = restored/rel_path
    std::fs::create_dir_all(dest.parent())
    resp = send_cli_request_raw(sock_a_fresh, CliRequest::RestoreFile {
      path: original_path_string,
      dest: dest.to_str(),
    })
    assert matches!(resp, CliResponse::Ok | CliResponse::Accepted)
    wait_for_file(dest, Duration::from_secs(30))

    restored_bytes = std::fs::read(dest)
    assert_eq!(restored_bytes, original_content,
      "file {} must restore byte-for-byte", rel_path)

Step 20: Shutdown all
  handle_b.shutdown().await
  handle_c.shutdown().await
  handle_a_fresh.shutdown().await
```

### Assertions

| Assertion | Why |
|---|---|
| Response to BackupNow is Ok/Accepted | Backup triggered |
| shards_placed >= 1 within 60s | At least one unit uploaded |
| system_state_backed_up == true within 30s | Blob sent to at least one peer |
| After destroy: node_a/syncback.redb does not exist | Node truly destroyed |
| Response to DrRestore is Ok (not Accepted) | DR is synchronous — DB populated before reply |
| All 5 restored files match originals byte-for-byte | Full pipeline correct |

---

## Scenario 2: `phase4_dr_restore_with_compression`

Proves zstd compression works correctly for both compressible and incompressible data
through the full backup → destroy → DR boot → restore pipeline.

### Signature

```rust
#[tokio::test]
async fn phase4_dr_restore_with_compression() {
    tokio::time::timeout(
        Duration::from_secs(180),
        run_dr_with_compression(),
    )
    .await
    .expect("test timed out after 180s")
    .expect("test failed");
}
```

### Test files

```rust
// Highly compressible: same byte repeated — zstd ratio ~1000:1
let compressible = vec![b'A'; 16 * 1024];
// Truly incompressible: cycling bytes — zstd adds ~0.1% overhead
let incompressible: Vec<u8> = (0u8..=255).cycle().take(16 * 1024).collect();
```

### Steps

1. Create Node A (owner), Node B (holder) — same pattern as Scenario 1.
2. Write 2 test files: `files_a/text.txt` (compressible) and `files_a/random.bin` (incompressible).
3. Start B, start A with backup include pointing at files_a.
4. Connect A → B. Trigger BackupNow. Wait for shards_placed >= 1.
5. Wait for system_state_backed_up == true.
6. Shutdown A. Destroy node_a dir + files_a dir.
7. Init fresh node_a (same seed). Start daemon. DrRestore (peer = B).
8. Connect fresh A → B.
9. Restore `text.txt` and `random.bin` to `restored/`.
10. Verify both files match originals byte-for-byte.

### Key assertions

- Both files restore correctly: compressible content matches exactly, incompressible content matches exactly.
- Compression is transparent — the test doesn't check compressed sizes, only that the round-trip works.

---

## Scenario 3: `phase4_system_state_backup_overwrites_previous`

Proves that when system state is backed up multiple times, the holder keeps only
the latest version, and DR restore gets the latest state (including files added later).

### Signature

```rust
#[tokio::test]
async fn phase4_system_state_backup_overwrites_previous() {
    tokio::time::timeout(
        Duration::from_secs(180),
        run_system_state_overwrite(),
    )
    .await
    .expect("test timed out after 180s")
    .expect("test failed");
}
```

### Steps

```
Step 1: Init Node A (owner), Node B (holder). Start both.
Step 2: Connect A → B.

Step 3: Write file1.txt to files_a/
Step 4: BackupNow on A. Wait shards_placed >= 1.
Step 5: Wait system_state_backed_up == true.
  (System state v1: knows about file1.txt)

Step 6: Add file2.txt to files_a/
Step 7: BackupNow on A again. Wait shards_placed increases.
Step 8: Wait for system state backup to run again.
  (System state v2: knows about file1.txt AND file2.txt)

Step 9: Shutdown A. Destroy node_a + files_a.
Step 10: Init fresh node_a (same seed). Start daemon. DrRestore (peer = B).
  (Should get system state v2, not v1)

Step 11: Connect fresh A → B.

Step 12: Restore file1.txt → verify matches original.
Step 13: Restore file2.txt → verify matches original.
  (If DR got state v1, file2.txt won't be in DB and restore fails.
   Test proves that overwrite worked and we got v2.)

Step 14: Shutdown all.
```

### Key assertions

- After DrRestore, fresh node A knows about both file1 and file2 (not just file1).
- Both files restore correctly from shards held by B.
- Holder B stores exactly 1 system state blob per owner (not accumulating versions).

---

## Timing constants

| Step | Timeout |
|---|---|
| wait_for_socket | 2 s (20 × 100 ms) |
| wait_for_shards_placed | 60 s |
| wait_for_system_state_backup | 30 s |
| DrRestore (synchronous) | inside 180 s overall timeout |
| wait_for_file (each file) | 30 s |
| Whole test | 180 s |

---

## Checklist for reviewer

- [ ] All naming aligns with DR flow spec: `DrRestore` (not DrBoot), `SystemStateBackup` message (not SystemStateStore)
- [ ] No `compressed: bool` on UnitRecord — all Phase 4 units are compressed, packer handles this transparently
- [ ] System state backup triggered via `BackupNow` → `WeeklySync` → `handle_system_state_backup()`
- [ ] 3 test scenarios present and cover: full DR cycle, compression transparency, overwrite semantics
- [ ] All Phase 1-3 tests still pass (344 tests)
- [ ] `cargo clippy -p syncback -- -D warnings` clean
