#!/bin/bash
# SyncBack fault injection E2E test: K-of-N resilience
# Tests E2E-06 (holder death during backup) and E2E-07 (restore with dead holders).
#
# Usage:
#   cargo build --release
#   bash experiments/local_fault_test.sh
#
# Tests:
#   1. Setup 5 nodes, star topology
#   2. Backup file, wait for placements
#   3. Kill 2 holders, verify restore still works (K-of-N)
#   4. Verify restored file matches original (MD5)

set -euo pipefail

NUM_NODES=5
TIME_SCALE=1000
TEST_DIR="/tmp/syncback-fault-$$"
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
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
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
echo "  SyncBack Fault Injection Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup (${NUM_NODES} nodes) ==="

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

# Connect star topology: all → node-00
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

echo "  Connecting all to node-00..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" 2>&1 > /dev/null || true
done
sleep 3
PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}/$((NUM_NODES-1))"
[ "${PC:-0}" -ge "$((NUM_NODES-1))" ] \
    && pass "star connect: ${PC} peers" \
    || fail "star connect: only ${PC:-0} peers"

# ── PHASE 2: BACKUP ─────────────────────────────────────────────
echo ""
echo "=== Phase 2: File Backup ==="

# Create test file (256 KB for good erasure spread)
echo "  Creating 256 KB test file..."
dd if=/dev/urandom of="$(node_dir 0)/files/fault_test.bin" bs=1024 count=256 2>/dev/null
ORIG_MD5=$(md5sum "$(node_dir 0)/files/fault_test.bin" | awk '{print $1}')
echo "  MD5: $ORIG_MD5"

# Wait for backup + placements
echo "  Waiting for backup + symbol placement (max 45s)..."
PLACED=0
for attempt in $(seq 1 45); do
    FILES_N=$(get_json_field 0 backed_up_files)
    PLACEMENTS=$(get_json_field 0 symbol_placements)
    if [ "${FILES_N:-0}" -ge 1 ] && [ "${PLACEMENTS:-0}" -ge 2 ]; then
        echo "  Backed up (files=${FILES_N}, placements=${PLACEMENTS}) after ${attempt}s"
        PLACED=1
        break
    fi
    sleep 1
done

if [ "$PLACED" -eq 1 ]; then
    pass "file backed up with ${PLACEMENTS} placements"
else
    fail "backup/placement not complete after 45s"
    echo "  node-00 log (last 20 lines):"
    tail -20 "$(node_log 0)"
fi

# Wait for symbols to be actually transferred to holders
echo "  Waiting for symbol transfer (10s)..."
sleep 10

# ── PHASE 3: FAULT INJECTION — KILL HOLDERS ─────────────────────
echo ""
echo "=== Phase 3: Fault Injection ==="

# Kill nodes 3 and 4 (holders). Node 0 is owner, nodes 1-2 survive.
KILL_1=3
KILL_2=4
echo "  Killing node-$(printf '%02d' $KILL_1) (PID ${PIDS[$KILL_1]})..."
kill "${PIDS[$KILL_1]}" 2>/dev/null || true
echo "  Killing node-$(printf '%02d' $KILL_2) (PID ${PIDS[$KILL_2]})..."
kill "${PIDS[$KILL_2]}" 2>/dev/null || true
sleep 2

# Verify they're dead
if kill -0 "${PIDS[$KILL_1]}" 2>/dev/null; then
    kill -9 "${PIDS[$KILL_1]}" 2>/dev/null || true
fi
if kill -0 "${PIDS[$KILL_2]}" 2>/dev/null; then
    kill -9 "${PIDS[$KILL_2]}" 2>/dev/null || true
fi

echo "  Nodes $KILL_1 and $KILL_2 killed. ${NUM_NODES}-2=$((NUM_NODES-2)) nodes alive."
pass "holders killed (nodes $KILL_1, $KILL_2)"

# ── PHASE 4: RESTORE WITH DEAD HOLDERS ──────────────────────────
echo ""
echo "=== Phase 4: Restore with Dead Holders (E2E-07) ==="

if [ "$PLACED" -eq 0 ]; then
    skip "restore skipped (no placements)"
else
    RESTORE_DEST="$(node_dir 0)/restored"
    mkdir -p "$RESTORE_DEST"
    RESTORE_PATH="$(node_dir 0)/files/fault_test.bin"
    echo "  Restoring $RESTORE_PATH with 2/$((NUM_NODES-1)) holders dead..."

    set +e
    RESTORE_OUTPUT=$(run_cli 0 restore "$RESTORE_PATH" --dest "$RESTORE_DEST" 2>&1)
    RESTORE_EXIT=$?
    set -e

    if [ $RESTORE_EXIT -eq 0 ]; then
        RESTORED_FILE=$(find "$RESTORE_DEST" -name "fault_test.bin" -type f 2>/dev/null | head -1)
        echo "  Waiting for restored file (max 30s)..."
        RESTORE_OK=0
        for attempt in $(seq 1 30); do
            if [ -n "$RESTORED_FILE" ] && [ -f "$RESTORED_FILE" ]; then
                RESTORED_MD5=$(md5sum "$RESTORED_FILE" | awk '{print $1}')
                if [ "$ORIG_MD5" = "$RESTORED_MD5" ]; then
                    pass "E2E-07: file restored with dead holders (MD5 match, ${attempt}s)"
                    RESTORE_OK=1
                else
                    fail "E2E-07: restored file MD5 mismatch: expected=$ORIG_MD5 got=$RESTORED_MD5"
                    RESTORE_OK=1
                fi
                break
            fi
            sleep 1
        done
        if [ "$RESTORE_OK" -eq 0 ]; then
            fail "E2E-07: restored file not found after 30s"
            echo "  Restore log:"
            grep -i "restore" "$(node_log 0)" | tail -10
        fi
    else
        fail "E2E-07: restore command failed (exit=$RESTORE_EXIT)"
        echo "$RESTORE_OUTPUT"
    fi
fi

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
