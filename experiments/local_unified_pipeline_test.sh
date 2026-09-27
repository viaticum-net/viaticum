#!/bin/bash
# Wave 11b: Unified Work Pipeline E2E Test
#
# Scenario: 7 independent owners, star-connected to node-00, time_scale 10000. node-00
#   backs up 3 small text files (importance 1.0). Once they sit at their reliability
#   target a spare node joins, then two holders of their block are killed.
# Intent: backup-i1, backup-i3, pos-i2, repair-i1 (file pending; proposed ids:
#   backup-i1 = a backed-up file has >= k_eff symbols on holder disks, backup-i3 = the
#   owner keeps no copy of its own blocks, pos-i2 = the owner detects dead holders via
#   PoS timeouts, repair-i1 = a block that dropped below target is repaired from the
#   source file onto a new holder).
# Proves: the WorkPipeline worker brings every file to its reliability target (owner's
#   is_safe_to_delete) with the block's symbols on holder disks; the owner never writes
#   block.bin / raw/ / {esi}.bin anywhere in its data dir, before or after repair (W11b
#   I5); after the kill, PoS detects the dead holders and the worker places symbols of
#   the degraded block on the spare, which received none while the block was at target.
# Adversarial: SIGKILL of two holders at once after the files reached their target.
# Cannot close: that the repaired set alone decodes (restore after repair is not run);
#   repair with no spare peer (one placement per holder per block, so a fully used pool
#   cannot be repaired); large or multi-block files (local_bigfile).
# Steps: 1. backup 3 files -> 3/3 at reliability target; holder disks >= k_eff
#             (backup-i1) — check: is_safe_to_delete, block_symbols_on sum
#        2. no own-block artifacts in node-00 data dir (backup-i3) — check: find
#        3. spare joins, holds 0 symbols for 10 s (precondition) — check:
#             block_symbols_on spare
#        4. SIGKILL two holders -> PoS timeouts for both within 420 s (pos-i2) —
#             check: node-00 log
#        5. spare's disk gets symbols of the block (repair-i1) — check:
#             block_symbols_on spare
#        6. still no own-block artifacts after repair (backup-i3) — check: find
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_unified_pipeline_test.sh

set -euo pipefail

NUM_NODES=7
TIME_SCALE=10000
TEST_DIR="/tmp/viaticum-unified-pipeline-$$"
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
    local RAW
    RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: viaticum binary not found. Run: ./rbuild.sh" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

# W11b I5: no own-block artifact anywhere in node-00's data dir (holdings/ = other
# owners' symbols, excluded). Prints the offending paths.
own_block_artifacts() {
    find "$(node_dir 0)" -path "$(node_dir 0)/holdings" -prune -o -type f \
        \( -name block.bin -o -path '*/raw/*' -o -regex '.*/[0-9a-f]\{64\}/[0-9]+\.bin' \) -print
}

echo "============================================================"
echo "  Wave 11b Unified Pipeline E2E Test"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup (${NUM_NODES} nodes) ==="

mkdir -p "$TEST_DIR"

# Distinct master per node: same-master siblings are excluded from the placement
# pool by design, so independent owners are required to exercise backup/placement.
echo "  Initializing ${NUM_NODES} nodes as independent owners (distinct masters)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
done
echo "  ${NUM_NODES} nodes initialized (distinct master keys)."

# Write config for all nodes.
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
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
    if wait_daemon "$i"; then ((READY++)) || true; fi
done
echo "  $READY/$NUM_NODES daemons ready"

# Connect all nodes to node-00.
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"
echo "  Connecting all nodes to node-00..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1 || true
done

if wait_auth_peers 0 $((NUM_NODES-1)) 40; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 40s"
fi

# ── PHASE 2: BACKUP 3 TEXT FILES ────────────────────────────────────────────
echo ""
echo "=== Phase 2: Backup 3 text files -> reliability target ==="

FILES_DIR="$(node_dir 0)/files"
FILES=("$FILES_DIR/doc1.txt" "$FILES_DIR/doc2.txt" "$FILES_DIR/notes.md")
echo "Wave 11b test file 1 - important documents content" > "${FILES[0]}"
echo "Wave 11b test file 2 - backup verification data" > "${FILES[1]}"
echo "Wave 11b test file 3 - pipeline test content" > "${FILES[2]}"

AT_TARGET=0
for attempt in $(seq 1 120); do
    AT_TARGET=0
    for f in "${FILES[@]}"; do
        [ "$(file_field 0 "$f" '.is_safe_to_delete')" = "true" ] && AT_TARGET=$((AT_TARGET + 1))
    done
    [ "$AT_TARGET" -eq 3 ] && break
    sleep 1
done
if [ "$AT_TARGET" -eq 3 ]; then
    pass "all 3 files at their reliability target after ${attempt}s"
else
    fail "only ${AT_TARGET}/3 files reached their reliability target after 120s"
fi

BLOCK=$(file_block_hex 0 "${FILES[0]}")
BSHORT=${BLOCK:0:16}
ON=0; WHO=""
for i in $(seq 1 $((NUM_NODES-1))); do
    n=$(block_symbols_on "$i" "$BLOCK")
    [ "$n" -gt 0 ] && WHO="$WHO $i"
    ON=$((ON + n))
done
TARGET=$(file_field 0 "${FILES[0]}" '.effective_status.target // 0')
echo "  block $BSHORT.. on holders:${WHO:- none} (${ON} symbols, k_eff=${TARGET})"
if [ "$ON" -ge "${TARGET:-1}" ] && [ "${TARGET:-0}" -gt 0 ]; then
    pass "holder disks carry ${ON} symbols of the block (>= k_eff ${TARGET})"
else
    fail "holder disks carry ${ON} symbols of block ${BLOCK:-none}, k_eff=${TARGET:-?}"
fi

# ── PHASE 3: NO DISK SPILL (W11b invariant I5) ──────────────────────────────
echo ""
echo "=== Phase 3: No own-block artifacts on node-00 disk (W11b I5) ==="
SPILL=$(own_block_artifacts | wc -l)
if [ "$SPILL" -eq 0 ]; then
    pass "no block.bin / raw/ / {esi}.bin files in node-00 data dir"
else
    fail "${SPILL} own-block artifact(s) in node-00 data dir"
    own_block_artifacts | head -5 || true
fi

# ── PHASE 4: SPARE JOINS, TWO HOLDERS DIE -> WORKER REPAIRS ONTO THE SPARE ──
echo ""
echo "=== Phase 4: Spare joins, two holders die -> repair onto the spare ==="

# Repair runs only when a block falls below target, and never puts a second
# placement of a block on the same holder; initial placement uses the whole pool,
# so the spare must join after the block is at target.
SPARE=$NUM_NODES
mkdir -p "$(node_dir "$SPARE")/files"
run_cli "$SPARE" init > /dev/null 2>&1
cp "$(node_dir 0)/config.toml" "$(node_dir "$SPARE")/config.toml"
RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$SPARE")" daemon \
    --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$SPARE")/files" \
    > "$(node_log "$SPARE")" 2>&1 &
PIDS+=($!)
wait_daemon "$SPARE" || fail "spare did not start"
run_cli_q "$SPARE" connect "$ADDR_00" > /dev/null
if wait_auth_peers 0 "$NUM_NODES" 30; then
    pass "spare node-$(printf '%02d' "$SPARE") joined"
else
    fail "spare did not authenticate with node-00 within 30s"
fi

sleep 10   # negative window: nothing should land on the spare while at target
PRE=$(block_symbols_on "$SPARE" "$BLOCK")
if [ "$PRE" -eq 0 ]; then
    pass "spare holds 0 symbols of the block while it is at target (10s window)"
else
    fail "spare received ${PRE} symbols before any loss; repair below cannot be attributed to the kill"
fi

read -r -a HOLDER_IDX <<< "$WHO"
if [ "${#HOLDER_IDX[@]}" -lt 3 ]; then
    fail "only ${#HOLDER_IDX[@]} holders; need >= 3 to kill two and keep one"
    exit 1
fi
KILLED=("${HOLDER_IDX[0]}" "${HOLDER_IDX[1]}")
KILL_DEVS=()
for k in "${KILLED[@]}"; do
    KILL_DEVS+=("$(api_get "$k" /api/status | jq -r '.device_id // empty' 2>/dev/null || true)")
done
echo "  Killing node-$(printf '%02d' "${KILLED[0]}") and node-$(printf '%02d' "${KILLED[1]}")"
for k in "${KILLED[@]}"; do
    kill -9 "${PIDS[$k]}" 2>/dev/null || true
    wait "${PIDS[$k]}" 2>/dev/null || true
done
T0=$(date +%s)

# At time_scale 10000 a PoS week is ~60 s and a pending challenge times out after
# ~122 s, so detection takes minutes, not seconds.
DETECTED=0
for _ in $(seq 1 210); do
    DETECTED=0
    for d in "${KILL_DEVS[@]}"; do
        plain_log 0 | grep -a "PoS challenge timed out" | grep -a "$BSHORT" | grep -aq "${d:-NO_DEVICE}" \
            && DETECTED=$((DETECTED + 1))
    done
    [ "$DETECTED" -ge 2 ] && break
    sleep 2
done
if [ "$DETECTED" -ge 2 ]; then
    pass "owner detected both dead holders via PoS timeouts after $(( $(date +%s) - T0 ))s"
else
    fail "owner logged PoS timeouts for ${DETECTED}/2 dead holders of block $BSHORT.. within 420s"
fi

# Repair does not wait for PresumedLost (3 misses, ~400 s): the spare gets symbols
# ~170 s after the kill, right after the first PoS timeouts. The old 480 s deadline
# masked a worker starved by below-target SystemState blocks; 240 s is the margin
# that lets this step catch such starvation again (repair-i4).
REPAIR_DEADLINE=240
GOT=0
while [ $(( $(date +%s) - T0 )) -lt "$REPAIR_DEADLINE" ]; do
    GOT=$(block_symbols_on "$SPARE" "$BLOCK")
    [ "$GOT" -gt 0 ] && break
    sleep 2
done
if [ "$GOT" -gt 0 ]; then
    pass "worker repaired the degraded block: ${GOT} symbols on the spare after $(( $(date +%s) - T0 ))s"
else
    fail "no symbols of the block on the spare within ${REPAIR_DEADLINE}s of the kill"
    plain_log 0 | grep -a "$BSHORT" | grep -ai "picked block\|candidates\|repair" | tail -6 || true
fi

# ── PHASE 5: NO DISK SPILL AFTER REPAIR ─────────────────────────────────────
echo ""
echo "=== Phase 5: No own-block artifacts after repair ==="
SPILL=$(own_block_artifacts | wc -l)
if [ "$SPILL" -eq 0 ]; then
    pass "no own-block artifacts after repair (W11b I5 holds post-repair)"
else
    fail "${SPILL} own-block artifact(s) after repair"
    own_block_artifacts | head -5 || true
fi

# ── RESULTS ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
