#!/bin/bash
# SyncBack E2E test: "Repair from Holders" (W3)
#
# Scenario:
#   1. 5 nodes: node-00 (owner), node-01 (Holder A — symbols deleted),
#      node-02..04 (surviving holders + repair target candidate).
#      (Why 5 not 4 — see NUM_NODES comment below.)
#   2. Owner backs up a 2 MB file. Waits for placement_alive >= 2.
#   3. All daemons killed.
#   4. Owner: source file + all symbols deleted (DB intact).
#      Holder A: all .bin symbol files deleted from holdings dir (DB intact).
#   5. All daemons restarted and reconnected.
#   6. Natural trigger: PoS challenge → Holder A has no symbols → PosHashNack
#      → owner marks placement Lost → RepairTrigger::RepairNow → repair_placement
#      → load_or_rebuild_blob: block.bin missing → local rebuild fails (source file gone)
#      → fetch_and_rebuild_blob from Holder B → re-encode → Offer/Accept/Transfer.
#   7. AC1-AC5 validated. Restore + MD5 check.
#
# Acceptance Criteria:
#   [AC1] "rebuilt blob from holder symbols (network fallback)" in owner.log >= 1
#   [AC2] "repair: local rebuild failed" in owner.log >= 1
#   [AC3] placement_alive >= 2 after repair
#   [AC4] restored file MD5 == original MD5
#   [AC5] "repair_placement: failed:" NOT in owner.log (0 occurrences)
#         Matches the Display output of any RepairError; the enum name
#         "EncodeFailed" never reaches the log text (tracing uses thiserror).
#
# Usage:
#   bash experiments/local_repair_from_holders_test.sh
#   WORK_DIR_PRESERVE=1 bash experiments/local_repair_from_holders_test.sh  (keep logs)
#
# Decisions:
#   - TIME_SCALE=100000: PoS fires ~3s wall-clock (pos_period_secs=2 virtual)
#   - k_factor=0.001: escrow threshold near-zero, fetch allowed immediately
#   - Natural PosHashNack trigger (no CLI repair-scan command needed)
#   - holdings path: {data_dir}/holdings/{block_id_hex}/{esi}.bin
#   - symbols path:  {data_dir}/symbols/{block_id_hex}/{esi}.bin

set -euo pipefail

NUM_NODES=5
# Why 5 (owner + 4 holders):
#   max_per_holder = k_eff - 1, so a single surviving holder can never carry
#   enough symbols to reach k_eff. After killing Holder A we need >= 2 other
#   holders with data. With 4 initial holders the placement algorithm can
#   distribute across 3+ of them, so losing one still leaves >= 2 alive.
TIME_SCALE=100000  # PoS fires ~3s wall-clock at pos_period_secs=2 virtual
TEST_DIR="/tmp/syncback-repair-holders-$$"
BINARY="${BINARY:-syncback}"

PASS=0; FAIL=0; SKIP=0
PIDS=()

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "  SKIP: $1"; ((SKIP++)) || true; }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "  Killed ${#PIDS[@]} daemon processes"
    if [ "${WORK_DIR_PRESERVE:-0}" = "1" ]; then
        echo "  Logs preserved at: $TEST_DIR"
    else
        rm -rf "$TEST_DIR" 2>/dev/null || true
        echo "  Test dir removed (set WORK_DIR_PRESERVE=1 to keep)"
    fi
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }

run_cli() {
    local idx="$1"; shift
    "$BINARY" --data-dir "$(node_dir "$idx")" "$@"
}

run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    local idx="$1"
    for i in $(seq 1 40); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then return 0; fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    local RAW_ADDR
    RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" | grep -oE '/ip4/[^ ]+')
    [ -z "$RAW_ADDR" ] && return
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
    local RAW
    RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

# wait_for_log FILE PATTERN MAX_SLEEP_ITER
# Returns 0 if pattern found, 1 on timeout.
wait_for_log() {
    local logfile="$1" pattern="$2" max_attempts="$3"
    for i in $(seq 1 "$max_attempts"); do
        if grep -q "$pattern" "$logfile" 2>/dev/null; then return 0; fi
        sleep 2
    done
    return 1
}

# wait_for_alive_placements OWNER_IDX MIN_ALIVE MAX_ATTEMPTS
wait_for_alive_placements() {
    local owner_idx="$1" min_alive="$2" max_attempts="$3"
    local PA BF
    for i in $(seq 1 "$max_attempts"); do
        PA=$(get_json_field "$owner_idx" placement_alive)
        BF=$(get_json_field "$owner_idx" backed_up_files)
        if [ "${BF:-0}" -ge 1 ] && [ "${PA:-0}" -ge "$min_alive" ]; then return 0; fi
        sleep 2
    done
    return 1
}

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/syncback"
    [ ! -x "$BINARY" ] && echo "ERROR: syncback binary not found. Run: cargo build --release" && exit 1
fi

echo "============================================================"
echo "  SyncBack: Repair from Holders E2E Test (W3)"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "[Phase 1] Setup: init ${NUM_NODES} nodes"

mkdir -p "$TEST_DIR"

echo "  Initializing ${NUM_NODES} nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    run_cli "$i" init > /dev/null 2>&1 &
done
wait

# Config: no disk reserve, escrow near-zero (A7 from spec)
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[storage]
disk_reserve_gb = 0.0

[escrow]
k_factor = 0.001
CFGEOF
done

echo "  Starting daemons (time_scale=${TIME_SCALE})..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then ((READY++)) || true; else echo "    node-$(printf '%02d' "$i") NOT ready"; fi
done
echo "  $READY/$NUM_NODES daemons ready"

# Connect all to node-00 (star topology)
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"
echo "  Connecting node-01..03 → node-00..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
done
sleep 3

PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}/$((NUM_NODES-1))"
[ "${PC:-0}" -ge 2 ] \
    && pass "star connect: ${PC} peers" \
    || fail "star connect: only ${PC:-0} peers (need >= 2 for placement)"

# ── PHASE 2: BACKUP + WAIT FOR PLACEMENTS ───────────────────────
echo ""
echo "[Phase 2] Backup: create 30 MB test file + wait for placement_alive >= 3"
# Why 30 MB: max_per_holder = k_eff - 1 and MIN_SYMBOLS_PER_HOLDER = 32, so
# a small file produces n ~= 2 * 32 = 64 and goes to exactly 2 holders.
# Losing one holder then leaves a single survivor that by design cannot carry
# k_eff symbols (max_per = k_eff - 1). A larger file grows k proportionally,
# pushes n past 3 * 32 = 96, and the placement spreads symbols across
# >= 3 holders — so after killing one, the remaining >= 2 holders together
# have >= k_eff unbound symbols and the network fallback can actually
# reconstruct the blob.

OWNER_DIR="$(node_dir 0)"
OWNER_LOG="$(node_log 0)"
TEST_FILE="${OWNER_DIR}/files/repair_test.bin"

echo "  Creating 30 MB test file..."
dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=30720 2>/dev/null
ORIG_MD5=$(md5sum "$TEST_FILE" | awk '{print $1}')
echo "  Original MD5: $ORIG_MD5"

echo "  Waiting for backup + placement_alive >= 3 (max 120s)..."
if wait_for_alive_placements 0 3 60; then
    PA=$(get_json_field 0 placement_alive)
    BF=$(get_json_field 0 backed_up_files)
    echo "  Backup complete: files=$BF, placements_alive=$PA"
    pass "file backed up with placement_alive >= 3"
else
    PA=$(get_json_field 0 placement_alive)
    BF=$(get_json_field 0 backed_up_files)
    fail "backup/placement not complete after 120s (files=${BF:-0}, placement_alive=${PA:-0})"
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$OWNER_LOG"
    echo "============================================================"
    echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "============================================================"
    exit 1
fi

# Extra wait for symbol transfer to holders to complete
echo "  Waiting 5s for symbol delivery to holders..."
sleep 5

# Verify at least one holder actually has symbols
HOLDER_WITH_SYMBOLS=""
for i in $(seq 1 $((NUM_NODES-1))); do
    HB=$(get_json_field "$i" holding_bytes)
    if [ "${HB:-0}" -gt 0 ]; then
        HOLDER_WITH_SYMBOLS="$i"
        echo "  node-$(printf '%02d' "$i") holds ${HB} bytes"
    fi
done
[ -z "$HOLDER_WITH_SYMBOLS" ] && echo "  WARNING: no holder has holding_bytes > 0 yet (symbols may still be in flight)"

# ── PHASE 3: KILL ALL + DELETE DATA ─────────────────────────────
echo ""
echo "[Phase 3] Kill all daemons + delete local data"

HOLDER_A_DIR="$(node_dir 1)"

# SIGTERM all daemons (clean shutdown)
echo "  Sending SIGTERM to all daemons..."
for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
done
sleep 2

# SIGKILL any remaining
for pid in "${PIDS[@]}"; do
    kill -9 "$pid" 2>/dev/null || true
done
echo "  All daemons stopped"

# Owner: delete source file + entire symbols dir (DB intact)
# This forces the cascade: block.bin missing → local rebuild fails → network fallback
echo "  Deleting owner source file and symbols..."
rm -f "$TEST_FILE"
rm -rf "${OWNER_DIR}/symbols"

# Verify owner DB is still present (critical for repair trigger)
[ -f "${OWNER_DIR}/db.redb" ] && echo "  Owner db.redb: present" || echo "  WARNING: owner db.redb missing!"

# Holder A (node-01): delete only symbol files, keep DB
# DB must stay so Holder A has HoldingRecord → will respond PosHashNack when symbols missing.
# Path: {data_dir}/holdings/{block_id_hex}/{esi}.bin
echo "  Deleting Holder A symbol files (keeping DB)..."
DELETED_COUNT=0
if [ -d "${HOLDER_A_DIR}/holdings" ]; then
    DELETED_COUNT=$(find "${HOLDER_A_DIR}/holdings" -name "*.bin" 2>/dev/null | wc -l)
    find "${HOLDER_A_DIR}/holdings" -name "*.bin" -delete 2>/dev/null || true
    echo "  Deleted ${DELETED_COUNT} symbol files from Holder A"
else
    echo "  WARNING: Holder A holdings dir not found: ${HOLDER_A_DIR}/holdings"
    echo "  (may not have received symbols yet — check timing)"
fi

# Verify Holder A DB is still present
[ -f "${HOLDER_A_DIR}/db.redb" ] && echo "  Holder A db.redb: present" || echo "  WARNING: Holder A db.redb missing!"

pass "local data deleted"

# ── PHASE 4: RESTART ALL DAEMONS ────────────────────────────────
echo ""
echo "[Phase 4] Restart all daemons + reconnect peers"

# Reset PIDS array
PIDS=()

echo "  Starting daemons (same config)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        >> "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then ((READY++)) || true; else echo "    node-$(printf '%02d' "$i") NOT ready after restart"; fi
done
echo "  $READY/$NUM_NODES daemons ready after restart"

# Re-connect peers after restart.
# libp2p peers do not persist between restarts without DHT bootstrap (R1 from spec).
# Must reconnect explicitly so PoS challenge can reach Holder A.
ADDR_00=$(get_addr 0)
echo "  Re-connecting node-01..03 → node-00 ($ADDR_00)..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
done
sleep 3

PC=$(get_json_field 0 peer_count)
echo "  node-00 peers after restart: ${PC:-0}"
[ "${PC:-0}" -ge 2 ] \
    && pass "peers reconnected after restart (${PC})" \
    || fail "not enough peers after restart: ${PC:-0} (need >= 2)"

# ── PHASE 5: WAIT FOR REPAIR VIA NATURAL POSHASH NACK ──────────
echo ""
echo "[Phase 5] Wait for repair via natural PosHashNack trigger (max 120s)"
echo "  Flow: PoS challenge → Holder A missing symbols → PosHashNack"
echo "        → placement Lost → RepairTrigger::RepairNow"
echo "        → load_or_rebuild_blob → network fallback"
echo ""

# AC2 fires first (local rebuild fails), then AC1 (network fallback succeeds)
echo "  Waiting for 'repair: local rebuild failed' in owner log (max 120s)..."
if wait_for_log "$OWNER_LOG" "repair: local rebuild failed" 60; then
    echo "  Found: local rebuild failed log entry"
    pass "AC2 logged: repair: local rebuild failed"
else
    fail "AC2 timeout: 'repair: local rebuild failed' not found after 120s"
    echo ""
    echo "=== Holder A log (last 20 lines) ==="
    tail -20 "$(node_log 1)" || true
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$OWNER_LOG"
fi

echo "  Waiting for 'rebuilt blob from holder symbols' in owner log (max 60s)..."
if wait_for_log "$OWNER_LOG" "rebuilt blob from holder symbols" 30; then
    echo "  Found: network fallback success log entry"
    pass "AC1 logged: rebuilt blob from holder symbols (network fallback)"
else
    fail "AC1 timeout: 'rebuilt blob from holder symbols (network fallback)' not found after 60s"
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$OWNER_LOG"
fi

# Give repair a moment to complete the new placement transfer
sleep 5

# ── PHASE 6: VALIDATE AC1–AC3, AC5 ─────────────────────────────
echo ""
echo "[Phase 6] Validate Acceptance Criteria (AC1-AC3, AC5)"

# AC1: network fallback log count
AC1_COUNT=$(grep -c "rebuilt blob from holder symbols (network fallback)" "$OWNER_LOG" 2>/dev/null || true)
echo "  AC1: 'rebuilt blob from holder symbols (network fallback)' count = $AC1_COUNT"
[ "${AC1_COUNT:-0}" -ge 1 ] \
    && pass "AC1: network fallback log found ($AC1_COUNT times)" \
    || fail "AC1: network fallback log not found (count=${AC1_COUNT:-0})"

# AC2: local rebuild failed log count
AC2_COUNT=$(grep -c "repair: local rebuild failed" "$OWNER_LOG" 2>/dev/null || true)
echo "  AC2: 'repair: local rebuild failed' count = $AC2_COUNT"
[ "${AC2_COUNT:-0}" -ge 1 ] \
    && pass "AC2: local rebuild failed log found ($AC2_COUNT times)" \
    || fail "AC2: local rebuild failed log not found (count=${AC2_COUNT:-0})"

# AC3: placement_alive >= 2 after repair
PA_AFTER=$(get_json_field 0 placement_alive)
echo "  AC3: placement_alive after repair = ${PA_AFTER:-0}"
[ "${PA_AFTER:-0}" -ge 2 ] \
    && pass "AC3: placement_alive >= 2 after repair (${PA_AFTER})" \
    || fail "AC3: placement_alive < 2 after repair (${PA_AFTER:-0})"

# AC5: no "repair_placement: failed:" errors in owner log.
# The enum name "EncodeFailed" never reaches the log text — tracing uses
# thiserror Display, which produces strings like "erasure encode failed: ...".
# The single reliable marker of any RepairError is "repair_placement: failed:"
# emitted by scan_and_repair() for every failed repair iteration.
AC5_COUNT=$(grep -c "repair_placement: failed:" "$OWNER_LOG" 2>/dev/null || true)
echo "  AC5: 'repair_placement: failed:' count = $AC5_COUNT"
[ "${AC5_COUNT:-0}" -eq 0 ] \
    && pass "AC5: no repair_placement failures in owner log" \
    || fail "AC5: repair_placement failed $AC5_COUNT time(s) — see owner log"

# ── PHASE 7: RESTORE + VALIDATE AC4 ─────────────────────────────
echo ""
echo "[Phase 7] Restore file + validate MD5 (AC4)"

RESTORE_DEST="${TEST_DIR}/restore"
mkdir -p "$RESTORE_DEST"

# The restore path = original absolute path as stored in catalog
RESTORE_PATH="${TEST_FILE}"

echo "  Requesting restore: $RESTORE_PATH → $RESTORE_DEST"
set +e
RESTORE_OUTPUT=$(run_cli 0 restore "$RESTORE_PATH" --dest "$RESTORE_DEST" 2>&1)
RESTORE_EXIT=$?
set -e

if [ $RESTORE_EXIT -ne 0 ]; then
    fail "AC4: restore command failed (exit=$RESTORE_EXIT): $RESTORE_OUTPUT"
else
    echo "  Restore command accepted (async). Waiting for file to appear (max 30s)..."
    RESTORE_OK=0
    for attempt in $(seq 1 30); do
        RESTORED_FILE=$(find "$RESTORE_DEST" -name "repair_test.bin" -type f 2>/dev/null | head -1)
        if [ -n "$RESTORED_FILE" ] && [ -f "$RESTORED_FILE" ]; then
            RESTORED_MD5=$(md5sum "$RESTORED_FILE" | awk '{print $1}')
            if [ "$ORIG_MD5" = "$RESTORED_MD5" ]; then
                pass "AC4: restored file MD5 matches original (${attempt}s)"
            else
                fail "AC4: MD5 mismatch: expected=$ORIG_MD5 got=$RESTORED_MD5"
            fi
            RESTORE_OK=1
            break
        fi
        sleep 1
    done
    if [ "$RESTORE_OK" -eq 0 ]; then
        fail "AC4: restored file not found in $RESTORE_DEST after 30s"
        echo "  Restore log:"
        grep -i "restore" "$OWNER_LOG" 2>/dev/null | tail -10 || true
    fi
fi

# ── PHASE 8: RESULTS ────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 50 lines) ==="
    tail -50 "$OWNER_LOG" || true
    echo ""
    echo "=== node-01 (Holder A) log (last 30 lines) ==="
    tail -30 "$(node_log 1)" || true
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

if [ "$FAIL" -eq 0 ]; then
    echo "PASS"
    exit 0
else
    echo "FAIL: $FAIL acceptance criteria failed"
    exit 1
fi
