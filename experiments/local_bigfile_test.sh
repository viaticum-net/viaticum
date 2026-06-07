#!/bin/bash
# Viaticum big-file stress test: realistic file sizes (10-100 MB).
# Monitors RAM and disk usage per node during backup.
#
# Usage:
#   cargo build --release
#   bash experiments/local_bigfile_test.sh
#
# Tests:
#   1. Backup 50 MB file, verify symbols placed
#   2. Backup 100 MB file, verify symbols placed
#   3. Restore 100 MB file, verify MD5
#   4. Check RAM/disk: no duplication, reasonable footprint
#   5. Backup 10 x 10 MB files, verify all placed

set -euo pipefail

NUM_NODES=5
TIME_SCALE=100
TEST_DIR="/tmp/viaticum-bigfile-$$"
BINARY="${BINARY:-viaticum}"

PASS=0; FAIL=0
PIDS=()

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

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
    echo "  Test dir: $TEST_DIR (kept for inspection)"
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
    for i in $(seq 1 120); do
        if run_cli "$idx" status 2>/dev/null | grep -q "identity:" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    # Status shows a libp2p multiaddr: /ip4/0.0.0.0/tcp/PORT/p2p/PEERID.
    # wait_daemon returns on "identity:" (available from the keyfile almost
    # immediately), but the swarm listen address is reported ~1s later. Poll
    # until it appears so a freshly/solo-started node does not race.
    local RAW_ADDR=""
    for _ in $(seq 1 20); do
        RAW_ADDR=$(timeout 5 "$BINARY" --data-dir "$(node_dir "$idx")" status 2>/dev/null \
            | grep "addr:" | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$RAW_ADDR" ] && break
        sleep 0.5
    done
    if [ -z "$RAW_ADDR" ]; then return; fi
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
    local RAW=$(timeout 5 "$BINARY" --data-dir "$(node_dir "$1")" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

measure_node() {
    local idx="$1"
    local dir="$(node_dir "$idx")"
    local pid="${PIDS[$idx]}"
    local rss=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
    local disk=$(du -sk "$dir" 2>/dev/null | cut -f1)
    echo "    node-$(printf '%02d' "$idx"): RSS=${rss}KB disk=${disk}KB (PID $pid)"
}

measure_all() {
    echo "  --- Resource snapshot ---"
    for i in $(seq 0 $((NUM_NODES-1))); do
        measure_node "$i"
    done
    echo "  --- end snapshot ---"
}

# Verify binary
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: viaticum binary not found"
        exit 1
    fi
fi

echo "============================================================"
echo "  Viaticum Big File Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Distinct master per node: same-master siblings are excluded from the placement
# pool by design, so independent owners are required to exercise backup/placement.
echo "  Initializing ${NUM_NODES} nodes as independent owners (distinct masters)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
done

for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
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
    if wait_daemon "$i"; then
        ((READY++)) || true
    fi
done
echo "  ${READY}/${NUM_NODES} daemons ready"

# Connect star topology
ADDR0=$(get_addr 0)
echo "  node-00 addr: $ADDR0"
echo "  Connecting all to node-00..."
CONNECT_PIDS=()
for i in $(seq 1 $((NUM_NODES-1))); do
    timeout 10 "$BINARY" --data-dir "$(node_dir "$i")" connect "$ADDR0" > /dev/null 2>&1 &
    CONNECT_PIDS+=($!)
done
for cpid in "${CONNECT_PIDS[@]}"; do
    wait "$cpid" 2>/dev/null || true
done
sleep 3

PEERS=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PEERS}/$((NUM_NODES-1))"

echo ""
echo "=== Baseline resource usage ==="
measure_all

# ── PHASE 2: 50 MB FILE ─────────────────────────────────────────
echo ""
echo "=== Phase 2: Backup 50 MB file ==="
dd if=/dev/urandom of="$(node_dir 0)/files/big50.bin" bs=1M count=50 2>/dev/null
MD5_50=$(md5sum "$(node_dir 0)/files/big50.bin" | cut -d' ' -f1)
echo "  Created 50 MB file (MD5: $MD5_50)"

echo "  Waiting for backup (max 120s)..."
for i in $(seq 1 120); do
    PLACEMENTS=$(get_json_field 0 placement_count)
    if [ -n "$PLACEMENTS" ] && [ "$PLACEMENTS" -gt 0 ] 2>/dev/null; then
        echo "  Backed up after ${i}s (placements=$PLACEMENTS)"
        pass "50 MB file backed up (${PLACEMENTS} placements)"
        break
    fi
    sleep 1
done
if [ -z "$PLACEMENTS" ] || [ "$PLACEMENTS" -eq 0 ] 2>/dev/null; then
    fail "50 MB file backup timed out"
fi

echo ""
echo "=== Post-50MB resource usage ==="
measure_all

# Wait for symbol delivery
echo "  Waiting 15s for symbol delivery..."
sleep 15

echo ""
echo "=== Post-delivery resource usage ==="
measure_all

# Check for disk duplication: owner's symbols dir should be cleaned after delivery
SYMBOLS_DIR="$(node_dir 0)/symbols"
OWNER_SYMBOLS_KB=$(du -sk "$SYMBOLS_DIR" 2>/dev/null | cut -f1 || echo "0")
echo "  Owner symbols dir after delivery: ${OWNER_SYMBOLS_KB} KB"
if [ "$OWNER_SYMBOLS_KB" -lt 10000 ]; then
    pass "owner symbols cleaned after delivery (<10 MB remaining)"
else
    fail "owner symbols NOT cleaned: ${OWNER_SYMBOLS_KB} KB remaining"
fi

# ── PHASE 3: 100 MB FILE ────────────────────────────────────────
echo ""
echo "=== Phase 3: Backup 100 MB file ==="
dd if=/dev/urandom of="$(node_dir 0)/files/big100.bin" bs=1M count=100 2>/dev/null
MD5_100=$(md5sum "$(node_dir 0)/files/big100.bin" | cut -d' ' -f1)
echo "  Created 100 MB file (MD5: $MD5_100)"

echo "  Waiting for backup (max 180s)..."
PREV_PLACEMENTS=$PLACEMENTS
for i in $(seq 1 180); do
    PLACEMENTS=$(get_json_field 0 placement_count)
    if [ -n "$PLACEMENTS" ] && [ "$PLACEMENTS" -gt "$PREV_PLACEMENTS" ] 2>/dev/null; then
        echo "  Backed up after ${i}s (placements=$PLACEMENTS)"
        pass "100 MB file backed up"
        break
    fi
    sleep 1
done

echo "  Waiting 20s for symbol delivery..."
sleep 20

echo ""
echo "=== Post-100MB resource usage ==="
measure_all

# Check total holder disk usage — should be roughly proportional to data
TOTAL_HOLDING=0
for i in $(seq 1 $((NUM_NODES-1))); do
    H_DIR="$(node_dir "$i")/holdings"
    H_SIZE=$(du -sk "$H_DIR" 2>/dev/null | cut -f1 || echo "0")
    TOTAL_HOLDING=$((TOTAL_HOLDING + H_SIZE))
done
echo "  Total holder disk: $((TOTAL_HOLDING / 1024)) MB across $((NUM_NODES-1)) peers"

# ── PHASE 4: RESTORE 100 MB ─────────────────────────────────────
echo ""
echo "=== Phase 4: Restore 100 MB file ==="
# Alpha: restore writes to <data_dir>/restore/<job_id>/<original_path>.
# --dest is not yet supported (API returns "dest_not_supported_in_alpha").
RESTORE_DIR="$(node_dir 0)/restore"
run_cli 0 restore "$(node_dir 0)/files/big100.bin" 2>&1 | head -5 &

echo "  Waiting for restored file (max 60s) under $RESTORE_DIR ..."
for i in $(seq 1 60); do
    RESTORED=$(find "$RESTORE_DIR" -name "big100.bin" -size +1M 2>/dev/null | head -1)
    if [ -n "$RESTORED" ]; then
        RESTORED_MD5=$(md5sum "$RESTORED" | cut -d' ' -f1)
        if [ "$RESTORED_MD5" = "$MD5_100" ]; then
            pass "100 MB file restored and verified (MD5 match, ${i}s)"
        else
            fail "100 MB restore MD5 mismatch: expected $MD5_100 got $RESTORED_MD5"
        fi
        break
    fi
    sleep 1
done
if [ -z "$RESTORED" ]; then
    fail "100 MB restore timed out"
fi

echo ""
echo "=== Post-restore resource usage ==="
measure_all

# ── PHASE 5: 10 x 10 MB ─────────────────────────────────────────
echo ""
echo "=== Phase 5: Backup 10 x 10 MB files ==="
for j in $(seq 1 10); do
    dd if=/dev/urandom of="$(node_dir 0)/files/batch_${j}.bin" bs=1M count=10 2>/dev/null
done
echo "  Created 10 files (10 MB each, 100 MB total)"

echo "  Waiting for all to be backed up (max 180s)..."
for i in $(seq 1 180); do
    FILES=$(get_json_field 0 backed_up_files)
    # We expect 12 files total (big50 + big100 + 10 batch)
    if [ -n "$FILES" ] && [ "$FILES" -ge 12 ] 2>/dev/null; then
        echo "  All files backed up after ${i}s (backed_up_files=$FILES)"
        pass "10 x 10 MB batch backup complete"
        break
    fi
    sleep 1
done
if [ -z "$FILES" ] || [ "$FILES" -lt 12 ] 2>/dev/null; then
    fail "batch backup: only $FILES/12 files detected"
fi

echo ""
echo "=== Final resource usage ==="
measure_all

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

exit $FAIL
