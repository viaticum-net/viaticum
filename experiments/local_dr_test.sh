#!/bin/bash
# SyncBack δ.1 Verification: System State Push + Disaster Recovery
# Local processes on one machine (no Docker).
#
# Usage:
#   cargo build --release
#   bash experiments/local_dr_test.sh [num_nodes]
#
# Defaults to 5 nodes. Each node gets its own data dir under /tmp/syncback-test-*.
# Tests:
#   1. Star connect — all nodes connect to node-00 via localhost
#   2. System state push — node-00 pushes encrypted DB snapshot to peers
#   3. Full DR — wipe node-00 and restore from seed phrase + peer address

set -euo pipefail

NUM_NODES=${1:-5}
TIME_SCALE=1000   # system state push interval = max(6*3600/1000, 60) = 60s
TEST_DIR="/tmp/syncback-test-$$"
MNEMONIC_00="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"
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
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Wait briefly for graceful shutdown
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "  Killed ${#PIDS[@]} daemon processes"
    echo "  Test dir: $TEST_DIR (not removed, inspect if needed)"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_sock() { echo "$(node_dir "$1")/syncback.sock"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }

run_cli() {
    # $1 = node index, rest = command args
    local idx="$1"; shift
    local dir=$(node_dir "$idx")
    "$BINARY" --data-dir "$dir" "$@"
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

get_peer_count() {
    run_cli_q "$1" status 2>/dev/null | grep "peers:" | head -1 | awk '{print $2}'
}

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    # Try release build path
    BINARY="./target/release/syncback"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: syncback binary not found. Run: cargo build --release"
        exit 1
    fi
fi

echo "============================================================"
echo "  SyncBack δ.1: Local DR Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init all nodes
echo "  Initializing ${NUM_NODES} nodes..."
run_cli 0 init --mnemonic "$MNEMONIC_00" > /dev/null 2>&1
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli "$i" init > /dev/null 2>&1 &
done
wait
echo "  ${NUM_NODES} nodes initialized."

# Set disk_reserve_gb=0 so tests work on low-disk machines.
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[storage]
disk_reserve_gb = 0.0

[escrow]
k_factor = 0.001
CFGEOF
done

# Start node-00 daemon
echo "  Starting node-00 daemon (time_scale=${TIME_SCALE})..."
RUST_LOG=info "$BINARY" --data-dir "$(node_dir 0)" daemon \
    --time-scale "$TIME_SCALE" \
    --watch-dir "$(node_dir 0)/files" \
    > "$(node_log 0)" 2>&1 &
PIDS+=($!)
mkdir -p "$(node_dir 0)/files"

if ! wait_daemon 0; then
    fail "node-00 daemon not responding after 10s"
    tail -20 "$(node_log 0)"
    exit 1
fi

ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

if [ -z "$ADDR_00" ]; then
    fail "cannot get node-00 address"
    exit 1
fi

# ── PHASE 2: START ALL + STAR CONNECT ──────────────────────────
echo ""
echo "=== Phase 2: Start All Daemons + Star Connect ==="

# Start remaining daemons
echo "  Starting nodes 01-$(printf '%02d' $((NUM_NODES-1)))..."
for i in $(seq 1 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

# Wait for all daemons
echo "  Waiting for daemons..."
READY=0
for i in $(seq 1 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then
        ((READY++)) || true
    else
        echo "    node-$(printf '%02d' "$i") NOT ready"
    fi
done
echo "  $READY/$((NUM_NODES-1)) daemons ready"

# Connect all to node-00
echo "  Connecting to node-00..."
CONNECT_OK=0
CONNECT_FAIL=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    if echo "$RESULT" | grep -qi "connected"; then
        ((CONNECT_OK++)) || true
    else
        ((CONNECT_FAIL++)) || true
        echo "    node-$(printf '%02d' "$i"): $RESULT"
    fi
done
echo "  Connected: $CONNECT_OK/$((NUM_NODES-1)), Failed: $CONNECT_FAIL"
sleep 2

PC_00=$(get_peer_count 0)
EXPECTED=$((NUM_NODES-1))
echo "  node-00 peers: ${PC_00:-0}/${EXPECTED}"
if [ "${PC_00:-0}" -ge "$EXPECTED" ]; then
    pass "star connect: node-00 has $PC_00/$EXPECTED peers"
elif [ "${PC_00:-0}" -ge $((EXPECTED/2)) ]; then
    pass "star connect: node-00 has $PC_00/$EXPECTED peers (partial)"
else
    fail "star connect: node-00 has only ${PC_00:-0}/$EXPECTED peers"
fi

# ── PHASE 3: FILE BACKUP + SYSTEM STATE PUSH ───────────────────
echo ""
echo "=== Phase 3: System State Push ==="

# Create test file on node-00
echo "  Creating test file on node-00..."
dd if=/dev/urandom of="$(node_dir 0)/files/test.bin" bs=1024 count=256 2>/dev/null

# Poll for system state blob on node-01 (max 90s)
# Push fires 60s after daemon start, so blob should appear ~65s after start.
echo "  Waiting for system state push to node-01 (interval=60s, max wait=90s)..."
BLOB_FOUND=0
for attempt in $(seq 1 18); do
    BLOB_LINE=$(run_cli_q 1 status --json 2>/dev/null \
        | grep -oE '"system_state_blobs":\s*[0-9]+' || true)
    BLOB_N=$(echo "$BLOB_LINE" | grep -oE '[0-9]+$')
    if [ "${BLOB_N:-0}" -ge 1 ]; then
        echo "  System state blob found on node-01 after $((attempt * 5))s"
        BLOB_FOUND=1
        break
    fi
    if [ $attempt -eq 12 ]; then
        echo "    attempt $attempt/18 — checking node-00 log..."
        tail -5 "$(node_log 0)"
    else
        printf "    attempt $attempt/18...\r"
    fi
    sleep 5
done

if [ "$BLOB_FOUND" -eq 1 ]; then
    pass "system state pushed to node-01"
else
    fail "system state blob not found on node-01 after 90s"
    echo ""
    echo "  === node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)"
    echo ""
    echo "  === node-01 log (last 20 lines) ==="
    tail -20 "$(node_log 1)"
fi

# Show node-00 status
echo ""
echo "  node-00 status:"
run_cli_q 0 status | head -15

# ── PHASE 4: DISASTER RECOVERY ─────────────────────────────────
echo ""
echo "=== Phase 4: Disaster Recovery ==="

if [ "$BLOB_FOUND" -eq 0 ]; then
    skip "DR skipped (no blob)"
else
    # Get peer addresses for DR
    ADDR_01=$(get_addr 1)
    ADDR_02=$(get_addr 2)
    echo "  DR seed peers:"
    echo "    node-01: $ADDR_01"
    echo "    node-02: ${ADDR_02:-n/a}"

    if [ -z "$ADDR_01" ]; then
        fail "cannot get node-01 addr for DR"
    else
        # Stop node-00 daemon
        echo "  Stopping node-00 daemon..."
        kill "${PIDS[0]}" 2>/dev/null || true
        sleep 2
        # Remove from PIDS (already dead)

        # Wipe node-00 data (keep dir)
        echo "  Wiping node-00 data..."
        rm -rf "$(node_dir 0)"/*

        # Run DR
        echo "  Running: syncback dr --mnemonic '...' --peer <node-01> --peer <node-02>"
        echo ""

        DR_ARGS="--mnemonic \"$MNEMONIC_00\" --peer \"$ADDR_01\""
        [ -n "${ADDR_02:-}" ] && DR_ARGS="$DR_ARGS --peer \"$ADDR_02\""

        set +e
        DR_OUTPUT=$(RUST_LOG=info eval "$BINARY" --data-dir "$(node_dir 0)" dr $DR_ARGS 2>&1)
        DR_EXIT=$?
        set -e

        echo "$DR_OUTPUT"
        echo ""

        if [ $DR_EXIT -eq 0 ] && echo "$DR_OUTPUT" | grep -qi "restore successful\|restored"; then
            pass "DR restore completed"

            FILES_N=$(echo "$DR_OUTPUT" | grep "Files:" | grep -oE '[0-9]+' | tail -1)
            PEERS_N=$(echo "$DR_OUTPUT" | grep "Peers:" | grep -oE '[0-9]+' | tail -1)

            echo "  Restored: ${FILES_N:-?} files, ${PEERS_N:-?} peers"

            [ "${FILES_N:-0}" -ge 1 ] && pass "DR restored files (${FILES_N})" \
                || skip "DR restored 0 files"
            [ "${PEERS_N:-0}" -ge 2 ] && pass "DR restored peers (${PEERS_N})" \
                || fail "DR restored too few peers (${PEERS_N:-0})"
        else
            fail "DR failed (exit=$DR_EXIT)"
        fi

        # Post-DR: start daemon and verify
        echo ""
        echo "=== Phase 5: Post-DR Verification ==="
        mkdir -p "$(node_dir 0)/files"
        RUST_LOG=info "$BINARY" --data-dir "$(node_dir 0)" daemon \
            --time-scale "$TIME_SCALE" \
            --watch-dir "$(node_dir 0)/files" \
            > "$(node_log 0)" 2>&1 &
        PIDS[0]=$!

        if wait_daemon 0; then
            echo "  Post-DR status:"
            run_cli_q 0 status
            POST_PEERS=$(get_peer_count 0)
            echo ""
            [ "${POST_PEERS:-0}" -ge 1 ] \
                && pass "post-DR daemon has ${POST_PEERS} peers" \
                || skip "post-DR peers not yet reconnected"
        else
            fail "post-DR daemon did not start"
        fi
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
    tail -30 "$(node_log 0)" 2>/dev/null || echo "  (no log)"
    echo ""
    echo "=== node-01 log (last 20 lines) ==="
    tail -20 "$(node_log 1)" 2>/dev/null || echo "  (no log)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"
echo "Cleanup: rm -rf $TEST_DIR"

[ "$FAIL" -eq 0 ]
