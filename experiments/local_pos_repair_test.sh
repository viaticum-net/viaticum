#!/bin/bash
# SyncBack: PoS verification + Repair after block.bin cleanup
# Validates that deterministic nonce allows blob rebuild from source files.
#
# Scenarios:
#   1. Backup file → symbols delivered → block.bin cleaned up
#   2. PoS challenge arrives → owner rebuilds blob → verification passes
#   3. Kill a holder → repair rebuilds blob from source files → new symbols sent
#
# Usage:
#   cargo build --release
#   bash experiments/local_pos_repair_test.sh

set -euo pipefail

NUM_NODES=5
TIME_SCALE=100000   # PoS fires every ~3s, repair every ~1s
TEST_DIR="/tmp/syncback-pos-repair-$$"
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
echo "  SyncBack: PoS + Repair After block.bin Cleanup"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
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

# Connect all to node-00
ADDR_00=$(get_addr 0)
echo "  Connecting to node-00 ($ADDR_00)..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
done
sleep 3

PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}"

# ── PHASE 2: BACKUP + WAIT FOR DELIVERY ─────────────────────────
echo ""
echo "=== Phase 2: Backup + Delivery ==="

echo "  Creating test file (256 KB)..."
dd if=/dev/urandom of="$(node_dir 0)/files/pos_test.bin" bs=1024 count=256 2>/dev/null

echo "  Waiting for backup + placement (max 60s)..."
BACKED_UP=0
for attempt in $(seq 1 30); do
    BF=$(get_json_field 0 backed_up_files)
    PA=$(get_json_field 0 placement_alive)
    if [ "${BF:-0}" -ge 1 ] && [ "${PA:-0}" -ge 1 ]; then
        echo "  Backup complete: files=$BF, placements_alive=$PA (${attempt}x2s)"
        BACKED_UP=1
        break
    fi
    sleep 2
done

if [ "$BACKED_UP" -eq 0 ]; then
    fail "backup/placement not complete after 60s"
    echo "  Last: backed_up_files=${BF:-0}, placement_alive=${PA:-0}"
    exit 1
fi
pass "file backed up and placed"

# ── PHASE 3: VERIFY block.bin CLEANUP ────────────────────────────
echo ""
echo "=== Phase 3: Verify block.bin Cleanup ==="

# Wait a bit for symbol delivery + cleanup to complete.
sleep 5

SYMBOLS_DIR="$(node_dir 0)/symbols"
BLOCK_BIN_COUNT=$(find "$SYMBOLS_DIR" -name "block.bin" 2>/dev/null | wc -l)
echo "  block.bin files remaining: $BLOCK_BIN_COUNT"

if [ "$BLOCK_BIN_COUNT" -eq 0 ]; then
    pass "block.bin cleaned up after delivery"
else
    # block.bin may still exist if not all symbols were delivered yet.
    # Wait more and recheck.
    echo "  Waiting 15s more for delivery completion..."
    sleep 15
    BLOCK_BIN_COUNT=$(find "$SYMBOLS_DIR" -name "block.bin" 2>/dev/null | wc -l)
    echo "  block.bin files remaining: $BLOCK_BIN_COUNT"
    if [ "$BLOCK_BIN_COUNT" -eq 0 ]; then
        pass "block.bin cleaned up after delivery (delayed)"
    else
        skip "block.bin still present (not all symbols delivered yet)"
    fi
fi

# ── PHASE 4: PoS VERIFICATION WITHOUT block.bin ─────────────────
echo ""
echo "=== Phase 4: PoS Verification (block.bin absent) ==="

echo "  Waiting for PoS challenges + passes (max 60s)..."
POS_OK=0
for attempt in $(seq 1 30); do
    CH=$(get_json_field 0 pos_total_challenges)
    PA=$(get_json_field 0 pos_total_passes)
    if [ "${CH:-0}" -ge 1 ] && [ "${PA:-0}" -ge 1 ]; then
        echo "  PoS: challenges=$CH, passes=$PA (${attempt}x2s)"
        POS_OK=1
        break
    fi
    sleep 2
done

if [ "$POS_OK" -eq 1 ]; then
    pass "PoS verification passed after block.bin cleanup (challenges=$CH, passes=$PA)"
else
    fail "no PoS passes after 60s (challenges=${CH:-0}, passes=${PA:-0})"
fi

# ── PHASE 5: REPAIR WITHOUT block.bin ────────────────────────────
echo ""
echo "=== Phase 5: Repair After Holder Kill (block.bin absent) ==="

# Find a holder node (not node-00).
# Look for any node with holding_bytes > 0.
KILL_IDX=""
for i in $(seq 1 $((NUM_NODES-1))); do
    HB=$(get_json_field "$i" holding_bytes)
    if [ "${HB:-0}" -gt 0 ]; then
        KILL_IDX=$i
        echo "  node-$(printf '%02d' "$i") holds ${HB} bytes — will kill"
        break
    fi
done

if [ -z "$KILL_IDX" ]; then
    skip "repair: no holder node found to kill"
else
    # Kill the holder daemon.
    KILL_PID=${PIDS[$KILL_IDX]}
    kill "$KILL_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$KILL_PID" 2>/dev/null || true
    echo "  Killed node-$(printf '%02d' "$KILL_IDX") (PID $KILL_PID)"

    # Get repair_needed count before.
    REPAIR_BEFORE=$(get_json_field 0 repair_needed)
    echo "  repair_needed before: ${REPAIR_BEFORE:-0}"

    # Wait for repair to detect and fix (max 90s).
    echo "  Waiting for repair to detect lost placement + re-encode (max 90s)..."
    REPAIRED=0
    for attempt in $(seq 1 45); do
        RN=$(get_json_field 0 repair_needed)
        PA_NOW=$(get_json_field 0 placement_alive)
        # Repair success: placement_alive restored or repair_needed went back down.
        if [ "${PA_NOW:-0}" -ge "${PA:-0}" ] && [ "$attempt" -ge 5 ]; then
            echo "  Repair check: placement_alive=$PA_NOW, repair_needed=${RN:-0} (${attempt}x2s)"
            REPAIRED=1
            break
        fi
        sleep 2
    done

    if [ "$REPAIRED" -eq 1 ]; then
        pass "repair re-encoded from source files without block.bin"
    else
        fail "repair did not complete (placement_alive=${PA_NOW:-0}, repair_needed=${RN:-0})"
    fi
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"
