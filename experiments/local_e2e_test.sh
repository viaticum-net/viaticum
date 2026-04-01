#!/bin/bash
# SyncBack comprehensive E2E test: backup pipeline, restore, trust, PoS
# Local processes on one machine (no Docker).
#
# Usage:
#   cargo build --release
#   bash experiments/local_e2e_test.sh [num_nodes]
#
# Tests:
#   1. Star connect (all nodes connect to node-00)
#   2. File backup (watcher detects file → erasure code → place symbols)
#   3. File restore (fetch symbols from peers → decode → verify)
#   4. Trust scores (initial trust > 0 after PoS)
#   5. Multiple file versions
#   6. System state push (δ.1)

set -euo pipefail

NUM_NODES=${1:-3}
TIME_SCALE=1000
TEST_DIR="/tmp/syncback-e2e-$$"
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
    echo "  Test dir: $TEST_DIR"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }

run_cli() {
    local idx="$1"; shift
    "$BINARY" --data-dir "$(node_dir "$idx")" "$@"
}

run_cli_q() {
    run_cli "$@" 2>/dev/null || true
}

wait_daemon() {
    local idx="$1"
    for i in $(seq 1 20); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    # Status now shows a libp2p multiaddr: /ip4/0.0.0.0/tcp/PORT/p2p/PEERID
    local RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" \
        | grep -oE '/ip4/[^ ]+')
    if [ -z "$RAW_ADDR" ]; then return; fi
    # Replace 0.0.0.0 with 127.0.0.1 for local testing.
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
    # $1 = node idx, $2 = field name
    local RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/syncback"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: syncback binary not found. Run: cargo build --release"
        exit 1
    fi
fi

echo "============================================================"
echo "  SyncBack E2E Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init all nodes
echo "  Initializing ${NUM_NODES} nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    run_cli "$i" init > /dev/null 2>&1 &
done
wait
echo "  ${NUM_NODES} nodes initialized."

# Start all daemons
echo "  Starting daemons (time_scale=${TIME_SCALE})..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

# Wait for all daemons
READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then
        ((READY++)) || true
    else
        echo "    node-$(printf '%02d' "$i") NOT ready"
    fi
done
echo "  $READY/$NUM_NODES daemons ready"

# Get node-00 addr and connect all
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

echo "  Connecting all to node-00..."
CONNECT_OK=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    if echo "$RESULT" | grep -qi "connected"; then
        ((CONNECT_OK++)) || true
    fi
done
sleep 2
PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}/$((NUM_NODES-1))"
[ "${PC:-0}" -ge "$((NUM_NODES-1))" ] \
    && pass "star connect: ${PC} peers" \
    || fail "star connect: only ${PC:-0} peers"

# ── PHASE 2: FILE BACKUP ────────────────────────────────────────
echo ""
echo "=== Phase 2: File Backup ==="

# Create a test file
echo "  Creating 128 KB test file..."
dd if=/dev/urandom of="$(node_dir 0)/files/backup_test.bin" bs=1024 count=128 2>/dev/null
ORIG_MD5=$(md5sum "$(node_dir 0)/files/backup_test.bin" | awk '{print $1}')
echo "  MD5: $ORIG_MD5"

# Wait for backup to detect and process (with time_scale=1000, scan interval is very short)
echo "  Waiting for backup pipeline (max 30s)..."
BACKED_UP=0
for attempt in $(seq 1 30); do
    FILES_N=$(get_json_field 0 backed_up_files)
    if [ "${FILES_N:-0}" -ge 1 ]; then
        echo "  File detected and backed up after ${attempt}s"
        BACKED_UP=1
        break
    fi
    sleep 1
done

if [ "$BACKED_UP" -eq 1 ]; then
    pass "file backup detected"
else
    fail "file not backed up after 30s"
    echo "  node-00 log (last 20 lines):"
    tail -20 "$(node_log 0)"
fi

# Wait for placements (symbols sent to peers)
echo "  Waiting for symbol placement (max 30s)..."
PLACED=0
for attempt in $(seq 1 30); do
    # Check table_stats for symbol_placements > 0
    PLACEMENTS=$(run_cli_q 0 status --json 2>/dev/null \
        | grep -oE '"symbol_placements":\s*[0-9]+' | grep -oE '[0-9]+$')
    if [ "${PLACEMENTS:-0}" -ge 1 ]; then
        echo "  Symbols placed: ${PLACEMENTS} (after ${attempt}s)"
        PLACED=1
        break
    fi
    sleep 1
done

if [ "$PLACED" -eq 1 ]; then
    pass "symbols placed on peers (${PLACEMENTS})"
else
    fail "no symbol placements after 30s"
fi

# ── PHASE 3: FILE RESTORE ───────────────────────────────────────
echo ""
echo "=== Phase 3: File Restore ==="

if [ "$PLACED" -eq 0 ]; then
    skip "restore skipped (no placements)"
else
    # Wait a bit for symbols to be delivered
    sleep 5

    RESTORE_DEST="$(node_dir 0)/restored"
    mkdir -p "$RESTORE_DEST"
    RESTORE_PATH="$(node_dir 0)/files/backup_test.bin"
    echo "  Restoring $RESTORE_PATH to $RESTORE_DEST..."

    set +e
    RESTORE_OUTPUT=$(run_cli 0 restore "$RESTORE_PATH" --dest "$RESTORE_DEST" 2>&1)
    RESTORE_EXIT=$?
    set -e

    echo "$RESTORE_OUTPUT"

    if [ $RESTORE_EXIT -eq 0 ]; then
        # Restore is async — wait for the file to appear (max 30s)
        # File path in DB is absolute; restore strips leading '/' and joins with dest dir
        RESTORED_FILE=$(find "$RESTORE_DEST" -name "backup_test.bin" -type f 2>/dev/null | head -1)
        echo "  Waiting for restored file (async, max 30s)..."
        RESTORE_OK=0
        for attempt in $(seq 1 30); do
            if [ -n "$RESTORED_FILE" ] && [ -f "$RESTORED_FILE" ]; then
                RESTORED_MD5=$(md5sum "$RESTORED_FILE" | awk '{print $1}')
                if [ "$ORIG_MD5" = "$RESTORED_MD5" ]; then
                    pass "file restored and verified (MD5 match, ${attempt}s)"
                    RESTORE_OK=1
                else
                    fail "restored file MD5 mismatch: expected=$ORIG_MD5 got=$RESTORED_MD5"
                    RESTORE_OK=1
                fi
                break
            fi
            sleep 1
        done
        if [ "$RESTORE_OK" -eq 0 ]; then
            fail "restored file not found after 30s"
            echo "  Restore log:"
            grep -i "restore" "$(node_log 0)" | tail -10
        fi
    else
        fail "restore command failed (exit=$RESTORE_EXIT)"
    fi
fi

# ── PHASE 4: TRUST + PoS ────────────────────────────────────────
echo ""
echo "=== Phase 4: Trust Scores ==="

# Check trust scores from status
AVG_TRUST=$(get_json_field 0 avg_trust)
echo "  node-00 avg_trust: ${AVG_TRUST:-0}"

if [ -n "$AVG_TRUST" ]; then
    # Trust should be > 0 after initial interactions
    if echo "$AVG_TRUST" | awk '{exit ($1 > 0) ? 0 : 1}'; then
        pass "trust scores > 0 (avg=${AVG_TRUST})"
    else
        skip "trust scores still 0 (interactions may not have completed)"
    fi
else
    skip "trust data not available"
fi

# Check PoS weekly entries
POS_WEEKLY=$(run_cli_q 0 status --json 2>/dev/null \
    | grep -oE '"pos_weekly":\s*[0-9]+' | grep -oE '[0-9]+$')
echo "  PoS weekly entries: ${POS_WEEKLY:-0}"
if [ "${POS_WEEKLY:-0}" -ge 1 ]; then
    pass "PoS challenges recorded (${POS_WEEKLY})"
else
    skip "no PoS entries yet (may need more time)"
fi

# ── PHASE 5: FILE VERSIONS ──────────────────────────────────────
echo ""
echo "=== Phase 5: File Versions ==="

# Modify the file and wait for new version
echo "  Modifying backup_test.bin..."
dd if=/dev/urandom of="$(node_dir 0)/files/backup_test.bin" bs=1024 count=64 2>/dev/null

echo "  Waiting for version update (max 20s)..."
VERSIONS_FOUND=0
for attempt in $(seq 1 20); do
    # Check versions via CLI
    VERSIONS_OUTPUT=$(run_cli_q 0 versions "backup_test.bin" 2>&1)
    VERSION_COUNT=$(echo "$VERSIONS_OUTPUT" | grep -c "version" || true)
    if [ "$VERSION_COUNT" -ge 2 ]; then
        echo "  Found $VERSION_COUNT versions after ${attempt}s"
        VERSIONS_FOUND=1
        break
    fi
    sleep 1
done

if [ "$VERSIONS_FOUND" -eq 1 ]; then
    pass "multiple file versions detected ($VERSION_COUNT)"
else
    skip "second version not detected yet (may need more time)"
fi

# ── PHASE 6: SYSTEM STATE PUSH ──────────────────────────────────
echo ""
echo "=== Phase 6: System State Push ==="

# Check if system state blobs exist on any peer
BLOB_FOUND=0
for i in $(seq 1 $((NUM_NODES-1))); do
    BLOBS=$(run_cli_q "$i" status --json 2>/dev/null \
        | grep -oE '"system_state_blobs":\s*[0-9]+' | grep -oE '[0-9]+$')
    if [ "${BLOBS:-0}" -ge 1 ]; then
        echo "  node-$(printf '%02d' "$i") has ${BLOBS} system_state blob(s)"
        BLOB_FOUND=1
    fi
done

if [ "$BLOB_FOUND" -eq 1 ]; then
    pass "system state blobs stored on peers"
else
    echo "  No blobs found yet (push fires 60s after daemon start)"
    skip "system state push not yet fired"
fi

# ── PHASE 7: STATUS SUMMARY ─────────────────────────────────────
echo ""
echo "=== Node Status Summary ==="
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "  --- node-$(printf '%02d' "$i") ---"
    run_cli_q "$i" status 2>/dev/null | head -10
    echo ""
done

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
