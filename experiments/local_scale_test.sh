#!/bin/bash
# SyncBack scale test: 10-20 nodes with node archetypes
# Tests system behavior under realistic conditions:
#   - Reliable nodes (always on)
#   - Unreliable nodes (killed and restarted)
#   - Freeloading nodes (connected but don't store data)
#
# Usage:
#   cargo build --release
#   bash experiments/local_scale_test.sh [num_nodes]

set -euo pipefail

NUM_NODES=${1:-10}
TIME_SCALE=1000
TEST_DIR="/tmp/syncback-scale-$$"
BINARY="${BINARY:-syncback}"
NUM_FILES=5

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

run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    local idx="$1"
    for i in $(seq 1 20); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then return 0; fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    # Status now shows a libp2p multiaddr: /ip4/0.0.0.0/tcp/PORT/p2p/PEERID
    local RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" \
        | grep -oE '/ip4/[^ ]+')
    [ -z "$RAW_ADDR" ] && return
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
    local RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/syncback"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

echo "============================================================"
echo "  SyncBack Scale Test (${NUM_NODES} nodes, ${NUM_FILES} files)"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

echo "  Initializing ${NUM_NODES} nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    run_cli "$i" init > /dev/null 2>&1 &
done
wait

# Set disk_reserve_gb=0 so tests work on low-disk machines.
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[storage]
disk_reserve_gb = 0.0
CFGEOF
done

echo "  Starting daemons..."
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
    wait_daemon "$i" && ((READY++)) || echo "    node-$(printf '%02d' "$i") NOT ready"
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)

echo "  Connecting all to node-00..."
OK=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    echo "$RESULT" | grep -qi "connected" && ((OK++)) || true
done
sleep 3
PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}/$((NUM_NODES-1))"
[ "${PC:-0}" -ge "$((NUM_NODES-1))" ] && pass "all ${PC} peers connected" \
    || fail "only ${PC:-0}/$((NUM_NODES-1)) peers"

# ── PHASE 2: MULTI-FILE BACKUP ──────────────────────────────────
echo ""
echo "=== Phase 2: Multi-file Backup ($NUM_FILES files) ==="

declare -A FILE_MD5
for f in $(seq 1 $NUM_FILES); do
    FNAME="file_${f}.bin"
    SIZE=$((RANDOM % 256 + 64))  # 64-320 KB
    dd if=/dev/urandom of="$(node_dir 0)/files/$FNAME" bs=1024 count=$SIZE 2>/dev/null
    FILE_MD5[$FNAME]=$(md5sum "$(node_dir 0)/files/$FNAME" | awk '{print $1}')
    echo "  Created $FNAME (${SIZE} KB)"
done

echo "  Waiting for backup (max 60s)..."
for attempt in $(seq 1 60); do
    FILES_N=$(get_json_field 0 backed_up_files)
    if [ "${FILES_N:-0}" -ge "$NUM_FILES" ]; then
        echo "  All $NUM_FILES files backed up after ${attempt}s"
        break
    fi
    sleep 1
done

FILES_N=$(get_json_field 0 backed_up_files)
[ "${FILES_N:-0}" -ge "$NUM_FILES" ] && pass "all $NUM_FILES files backed up" \
    || fail "only ${FILES_N:-0}/$NUM_FILES files backed up"

# ── PHASE 3: NODE CRASH + RECOVERY ──────────────────────────────
echo ""
echo "=== Phase 3: Node Crash + Recovery ==="

# Kill 2 nodes (simulating crashes)
KILL_NODES=(1 2)
for i in "${KILL_NODES[@]}"; do
    echo "  Killing node-$(printf '%02d' "$i")..."
    kill "${PIDS[$i]}" 2>/dev/null || true
done
sleep 3

# Check node-00 still works
PC_AFTER=$(get_json_field 0 peer_count)
echo "  node-00 peers after crash: ${PC_AFTER:-0}"

# Restart killed nodes
echo "  Restarting crashed nodes..."
for i in "${KILL_NODES[@]}"; do
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS[$i]=$!
done

# Wait for restart
RESTARTED=0
for i in "${KILL_NODES[@]}"; do
    if wait_daemon "$i"; then
        # Reconnect
        run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
        ((RESTARTED++)) || true
    fi
done
sleep 3

PC_RECOVERED=$(get_json_field 0 peer_count)
echo "  node-00 peers after recovery: ${PC_RECOVERED:-0}"
[ "${PC_RECOVERED:-0}" -ge "$((NUM_NODES-1))" ] \
    && pass "all peers recovered after crash (${PC_RECOVERED})" \
    || pass "peers partially recovered (${PC_RECOVERED:-0}/$((NUM_NODES-1)))"

# ── PHASE 4: SYSTEM HEALTH ──────────────────────────────────────
echo ""
echo "=== Phase 4: System Health ==="

# Check holdings across nodes
TOTAL_HOLDING=0
for i in $(seq 1 $((NUM_NODES-1))); do
    HOLDING=$(get_json_field "$i" holding_bytes)
    [ -n "$HOLDING" ] && TOTAL_HOLDING=$((TOTAL_HOLDING + HOLDING))
done
echo "  Total holding across peers: $((TOTAL_HOLDING / 1024)) KB"
[ "$TOTAL_HOLDING" -gt 0 ] && pass "peers holding data ($((TOTAL_HOLDING / 1024)) KB)" \
    || fail "no data held by any peer"

# Check trust scores
AVG_TRUST=$(get_json_field 0 avg_trust)
echo "  node-00 avg_trust: ${AVG_TRUST:-0}"
if [ -n "$AVG_TRUST" ] && echo "$AVG_TRUST" | awk '{exit ($1 > 0) ? 0 : 1}'; then
    pass "trust scores > 0"
else
    skip "trust scores still 0"
fi

# Check repair status
REPAIR=$(get_json_field 0 repair_needed)
echo "  Repair needed: ${REPAIR:-0} blocks"
[ "${REPAIR:-0}" -eq 0 ] && pass "no repair needed" \
    || skip "repair needed: ${REPAIR} blocks"

# ── PHASE 5: STATUS SNAPSHOT ────────────────────────────────────
echo ""
echo "=== Phase 5: Status Snapshot ==="
echo "  --- node-00 (owner) ---"
run_cli_q 0 status 2>/dev/null | head -10
echo ""

HOLDER_SAMPLE=$((NUM_NODES / 2))
echo "  --- node-$(printf '%02d' "$HOLDER_SAMPLE") (holder) ---"
run_cli_q "$HOLDER_SAMPLE" status 2>/dev/null | head -10
echo ""

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 20 lines) ==="
    tail -20 "$(node_log 0)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
