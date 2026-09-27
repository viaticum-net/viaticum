#!/bin/bash
# Viaticum scale E2E: 10-20 nodes, several files, two holders crash and restart,
# every file restored from the network by hash.
#
# Scenario: N independent owners (default 10), star-connected to node-00. node-00 backs
#   up 5 files of 64-320 KB; two other nodes crash (SIGKILL) and are restarted and
#   reconnected; then node-00 loses all 5 files locally and restores each of them.
# Intent: restore-i1 (Phase 4, five files), restore-i9 (partial: restore right after
#   the delete); backup-i1 (file pending; proposed id: a backed-up file has >= k_eff
#   symbols on holder disks).
# Proves: all files reach "restorable" with >= k_eff symbols on holder disks; after two
#   crashes + restarts the network is whole again (authenticated peers) and every file
#   comes back from holders byte-identical (sha256).
# Adversarial: SIGKILL of two nodes after placement, then restart with their data dirs.
# Cannot close: freeloading or unreliable-by-design archetypes (not implemented here,
#   despite the old header); automatic reconnection (the script reconnects with
#   `connect`; NET-09 is local_network's job); trust dynamics (printed as INFO);
#   restore-i3 (honest outcome): the CLI answers exit 0 + "started" even when nothing
#   was restored, e2e_lib.sh turns that into a FAIL instead of proving the report.
# Steps: 1. backup 5 files -> each restorable, >= k_eff symbols on holders (backup-i1)
#             — check: wait_file_restorable, block_symbols_on
#        2. SIGKILL two nodes, restart, `connect` -> all peers authenticated — check:
#             wait_auth_peers
#        3. rm all 5 sources -> each registered deleted — check: assert_delete_window,
#             wait_file_deleted
#        4. restore each -> sha256 match, 5/5 (restore-i1, restore-i9) — check:
#             restore_from_network per file
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_scale_test.sh [num_nodes]

set -euo pipefail

NUM_NODES=${1:-10}
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-scale-$$"
BINARY="${BINARY:-viaticum}"
NUM_FILES=5

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
    # Status shows a libp2p multiaddr: /ip4/0.0.0.0/tcp/PORT/p2p/PEERID.
    # wait_daemon returns on "identity:" (available from the keyfile almost
    # immediately), but the swarm listen address is reported ~1s later. Poll
    # until it appears so a freshly/solo-started node does not race.
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

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum Scale Test (${NUM_NODES} nodes, ${NUM_FILES} files)"
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

# Set disk_reserve_gb=0 so tests work on low-disk machines.
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
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
    if wait_daemon "$i"; then READY=$((READY + 1)); else echo "    node-$(printf '%02d' "$i") NOT ready"; fi
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)

echo "  Connecting all to node-00..."
OK=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    echo "$RESULT" | grep -qi "connected" && ((OK++)) || true
done
if wait_auth_peers 0 $((NUM_NODES-1)) 40; then
    pass "all $(status_num 0 peer_count_authenticated) peers authenticated"
else
    fail "only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) peers authenticated after 40s"
fi

# ── PHASE 2: MULTI-FILE BACKUP ──────────────────────────────────
echo ""
echo "=== Phase 2: Multi-file Backup ($NUM_FILES files) ==="

declare -A FILE_HASH
for f in $(seq 1 $NUM_FILES); do
    FNAME="file_${f}.bin"
    SIZE=$((RANDOM % 256 + 64))  # 64-320 KB
    dd if=/dev/urandom of="$(node_dir 0)/files/$FNAME" bs=1024 count=$SIZE 2>/dev/null
    FILE_HASH[$FNAME]=$(content_hash "$(node_dir 0)/files/$FNAME")
    echo "  Created $FNAME (${SIZE} KB)"
done

RESTORABLE=0
for f in $(seq 1 $NUM_FILES); do
    P="$(node_dir 0)/files/file_${f}.bin"
    if wait_file_restorable 0 "$P" 90; then
        BLK=$(file_block_hex 0 "$P"); TGT=$(file_field 0 "$P" '.effective_status.target // 0'); ON=0
        for i in $(seq 1 $((NUM_NODES-1))); do ON=$((ON + $(block_symbols_on "$i" "$BLK"))); done
        if [ "$ON" -ge "${TGT:-1}" ] && [ "${TGT:-0}" -gt 0 ]; then
            RESTORABLE=$((RESTORABLE + 1))
        else
            echo "    file_${f}.bin: ${ON} symbols on holder disks < k_eff ${TGT}"
        fi
    fi
done
if [ "$RESTORABLE" -eq "$NUM_FILES" ]; then
    pass "all $NUM_FILES files restorable with >= k_eff symbols on holder disks"
else
    fail "only $RESTORABLE/$NUM_FILES files restorable with symbols on holder disks"
fi

# ── PHASE 3: NODE CRASH + RECOVERY ──────────────────────────────
echo ""
echo "=== Phase 3: Node Crash + Recovery ==="

KILL_NODES=(1 2)
for i in "${KILL_NODES[@]}"; do
    echo "  Crashing node-$(printf '%02d' "$i") (SIGKILL)..."
    kill -9 "${PIDS[$i]}" 2>/dev/null || true
    wait "${PIDS[$i]}" 2>/dev/null || true
done

echo "  Restarting crashed nodes..."
for i in "${KILL_NODES[@]}"; do
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        >> "$(node_log "$i")" 2>&1 &
    PIDS[$i]=$!
done
for i in "${KILL_NODES[@]}"; do
    if wait_daemon "$i"; then
        run_cli_q "$i" connect "$ADDR_00" > /dev/null
    else
        fail "node-$(printf '%02d' "$i") did not restart"
    fi
done
if wait_auth_peers 0 $((NUM_NODES-1)) 40; then
    pass "all $((NUM_NODES-1)) peers authenticated again after crash + restart"
else
    fail "only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) peers authenticated 40s after restart"
fi

# ── PHASE 4: LOSE EVERY FILE LOCALLY -> RESTORE FROM THE NETWORK ─
echo ""
echo "=== Phase 4: Delete all files locally -> restore each from the network ==="

assert_delete_window "$TIME_SCALE"
for f in $(seq 1 $NUM_FILES); do rm -f "$(node_dir 0)/files/file_${f}.bin"; done
for f in $(seq 1 $NUM_FILES); do
    wait_file_deleted 0 "$(node_dir 0)/files/file_${f}.bin" 30 \
        || fail "owner did not register the delete of file_${f}.bin"
done
RESTORED=0
for f in $(seq 1 $NUM_FILES); do
    FNAME="file_${f}.bin"
    if restore_from_network 0 "$(node_dir 0)/files/$FNAME" "${FILE_HASH[$FNAME]}" 90 > /dev/null; then
        RESTORED=$((RESTORED + 1))
    else
        echo "    $FNAME: $RESTORE_MSG"
    fi
done
if [ "$RESTORED" -eq "$NUM_FILES" ]; then
    pass "all $NUM_FILES files restored from the network (sha256 match)"
else
    fail "only $RESTORED/$NUM_FILES files restored from the network by hash"
fi

# ── INFO ─────────────────────────────────────────────────────────
echo ""
echo "=== Info (not verdicts) ==="
info "node-00 avg_trust=$(status_num 0 avg_trust) blocks_at_risk=$(status_num 0 blocks_at_risk)"

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 20 lines) ==="
    tail -20 "$(node_log 0)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
