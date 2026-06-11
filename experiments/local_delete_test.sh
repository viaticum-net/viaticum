#!/bin/bash
# Viaticum: owner deletion E2E — multi-holder erasure delete reaches ALL holders.
# Local processes on one machine (no Docker).
#
# WHY THIS TEST EXISTS (intent / acceptance criteria — fixed before the script):
#   Deletion is a load-bearing product property: when the owner removes a backed-up
#   file, the data must actually disappear from the network. Until now this path was
#   only unit-tested (single placement) and never exercised E2E across multiple live
#   holders. The H3 review finding showed a real bug class here (per-BLOCK dedup meant
#   only ONE holder of an erasure-coded block ever received the Delete; holders 2..n
#   kept the data forever). Erasure coding spreads every block across n>=k+2 holders,
#   so multi-holder is the NORMAL case — this test guards it.
#
#   AC1 (H3, the core): after the file is removed from the watch dir, EVERY holder that
#        stored its symbols deletes them (holding_bytes -> 0 on all of them), not just one.
#   AC2: the owner cleans up afterwards — placement records for the block reach 0
#        (CleanupPlacement -> CleanupBlock fired), so no orphan metadata is left behind.
#   AC3: deletion is HONORED, not merely believed — we assert against actual holder
#        on-disk state (holding_bytes), never against the owner's own optimistic view.
#
# Scenarios:
#   1. 5 nodes, distinct masters, star-connect to node-00.
#   2. node-00 backs up a file -> symbols erasure-coded across >=2 holders.
#   3. Record the full holder set (every node with holding_bytes > 0).
#   4. Remove the file from node-00's watch dir.
#   5. Owner cooldown elapses (compressed by --time-scale) -> DeleteMsg via mailbox
#      -> EVERY holder marks for delete and (after holder cooldown) drops the symbols.
#   6. Verify ALL holders reach holding_bytes == 0 (AC1) and owner placement_count -> 0 (AC2).
#
# Usage:
#   cargo build --release
#   bash experiments/local_delete_test.sh [num_nodes]

set -euo pipefail

NUM_NODES="${1:-5}"
# OWNER/HOLDER delete cooldowns are 4 weeks each. At scale 100000 they compress to
# ~24s apiece, so the full owner-cooldown -> DeleteMsg -> holder-cooldown -> drop
# chain finishes in ~60-90s wall-clock. Timeouts below allow generous slack.
TIME_SCALE=100000
TEST_DIR="/tmp/viaticum-delete-$$"
BINARY="${BINARY:-viaticum}"

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
    for i in $(seq 1 120); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then return 0; fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    local RAW_ADDR=""
    for _ in $(seq 1 20); do
        RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" \
            | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$RAW_ADDR" ] && break
        sleep 0.5
    done
    if [ -z "$RAW_ADDR" ]; then return; fi
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

get_json_field() {
    local RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

echo "============================================================"
echo "  Viaticum: Owner Deletion E2E (multi-holder, H3)"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init each node as an independent owner with its OWN master identity.
# Same-master siblings are excluded from the placement pool by design (sibling
# exclusion, cluster phase 1), so distinct owners are required; cross-cluster
# peers authenticate via self-signed cert (CertTrustPath::Cross) and become
# eligible holders for each other.
echo "  Initializing ${NUM_NODES} nodes as independent owners (distinct masters)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
done
echo "  ${NUM_NODES} nodes initialized (distinct master keys)."

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
echo "  Connecting to node-00 ($ADDR_00)..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
done

for attempt in $(seq 1 30); do
    PC=$(get_json_field 0 peer_count)
    if [ "${PC:-0}" -ge "$((NUM_NODES-1))" ]; then break; fi
    sleep 1
done
PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}"

# ── PHASE 2: BACKUP + WAIT FOR DELIVERY ─────────────────────────
echo ""
echo "=== Phase 2: Backup + Delivery ==="

TEST_FILE="$(node_dir 0)/files/delete_test.bin"
echo "  Creating test file (256 KB)..."
dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=256 2>/dev/null

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

# Let symbol delivery settle so holding_bytes reflects the final holder set.
sleep 5

# ── PHASE 3: RECORD THE FULL HOLDER SET ─────────────────────────
echo ""
echo "=== Phase 3: Record Holder Set ==="

# Every node (except the owner) that holds bytes for node-00. For an erasure-coded
# block n >= k+2, so we expect >= 2 distinct holders — the multi-holder (H3) case.
HOLDERS=()
for i in $(seq 1 $((NUM_NODES-1))); do
    HB=$(get_json_field "$i" holding_bytes)
    if [ "${HB:-0}" -gt 0 ]; then
        HOLDERS+=("$i")
        echo "  node-$(printf '%02d' "$i") holds ${HB} bytes"
    fi
done

NUM_HOLDERS=${#HOLDERS[@]}
echo "  Total holders: $NUM_HOLDERS"

if [ "$NUM_HOLDERS" -eq 0 ]; then
    fail "no holders found after backup — cannot test deletion"
    exit 1
fi
if [ "$NUM_HOLDERS" -ge 2 ]; then
    pass "multi-holder block confirmed ($NUM_HOLDERS holders) — H3 case exercised"
else
    skip "only 1 holder — single-holder delete tested, H3 multi-holder NOT exercised"
fi

# ── PHASE 4: DELETE THE FILE ────────────────────────────────────
echo ""
echo "=== Phase 4: Delete File from Watch Dir ==="

echo "  Removing $TEST_FILE ..."
rm -f "$TEST_FILE"

# Give the watcher time to observe the removal (inotify + periodic scan) and the
# scheduler to start the owner delete cooldown.
echo "  Waiting for watcher to register the deletion..."
sleep 5

# ── PHASE 5: VERIFY EVERY HOLDER DELETES (AC1 / H3) ─────────────
echo ""
echo "=== Phase 5: Verify ALL Holders Delete (AC1 / H3) ==="

# Owner cooldown (~24s) -> DeleteMsg via mailbox -> holder marks -> holder cooldown
# (~24s) -> holder drops symbols. Poll every 3s up to 180s for ALL holders to reach
# holding_bytes == 0. A bug where only one holder gets the Delete (H3) leaves the
# others stuck > 0 and this phase FAILS — exactly the regression we are guarding.
ALL_DELETED=0
for attempt in $(seq 1 60); do
    STILL_HOLDING=()
    for i in "${HOLDERS[@]}"; do
        HB=$(get_json_field "$i" holding_bytes)
        if [ "${HB:-0}" -gt 0 ]; then
            STILL_HOLDING+=("$i")
        fi
    done
    if [ "${#STILL_HOLDING[@]}" -eq 0 ]; then
        echo "  All $NUM_HOLDERS holders dropped their symbols (${attempt}x3s)"
        ALL_DELETED=1
        break
    fi
    if [ $((attempt % 5)) -eq 0 ]; then
        echo "  still holding: ${#STILL_HOLDING[@]}/$NUM_HOLDERS holders (nodes ${STILL_HOLDING[*]}) (${attempt}x3s)"
    fi
    sleep 3
done

if [ "$ALL_DELETED" -eq 1 ]; then
    pass "AC1: every holder ($NUM_HOLDERS) deleted the symbols after owner delete"
else
    fail "AC1/H3: ${#STILL_HOLDING[@]}/$NUM_HOLDERS holders still hold data after 180s (nodes ${STILL_HOLDING[*]})"
    echo "  This is the H3 multi-holder regression signature (delete reaches only some holders)."
fi

# ── PHASE 6: VERIFY OWNER CLEANUP (AC2) ─────────────────────────
echo ""
echo "=== Phase 6: Verify Owner Cleanup (AC2) ==="

# After all holders are done, the owner runs CleanupPlacement per holder and
# CleanupBlock once all placements are cleaned -> placement_count drops to 0.
OWNER_CLEAN=0
for attempt in $(seq 1 30); do
    PCNT=$(get_json_field 0 placement_count)
    if [ "${PCNT:-1}" -eq 0 ]; then
        echo "  Owner placement_count = 0 (${attempt}x3s)"
        OWNER_CLEAN=1
        break
    fi
    sleep 3
done

if [ "$OWNER_CLEAN" -eq 1 ]; then
    pass "AC2: owner cleaned up placements (CleanupBlock fired)"
else
    PCNT=$(get_json_field 0 placement_count)
    fail "AC2: owner placement_count still ${PCNT:-?} after 90s (CleanupBlock did not fire)"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
