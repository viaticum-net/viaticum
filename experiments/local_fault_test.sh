#!/bin/bash
# Viaticum fault injection E2E: restore from the network with a dead holder (K-of-N).
# Local processes on one machine (no Docker). E2E-07.
#
# Scenario: 7 independent owners, star-connected to node-00. node-00 backs up a 4 MB
#   file; the holder with the most symbols of its block is killed (SIGKILL), then the
#   owner's local copy is deleted and the file is restored from the surviving holders.
#   Then every survivor loses part of its symbol files on disk so that no single holder
#   has k_eff symbols, and the file is restored again.
# Intent: restore-i1 (Phase 4), restore-i2 (Phases 4-5: the "some holders offline,
#   restore still passes" half only), restore-i9 (partial: restore right after the
#   delete).
# Proves: with one holder dead and the source gone, the block decodes from the
#   survivors' symbols and the restored file is byte-identical (sha256); surviving
#   holders log serving it; restore does not hang on the dead holder beyond the deadline;
#   with partial loss on every survivor, restore combines symbols from >= 2 holders.
# Adversarial: SIGKILL of the biggest holder before restore; silent partial disk loss
#   on every survivor (symbol files removed behind the holder daemon's back).
# Cannot close: holder death DURING backup (E2E-06; the kill happens after placement);
#   more than one simultaneous loss; the repair that should follow (local_pos_repair /
#   local_unified_pipeline); partition vs. crash (both look like SIGKILL here); the
#   restore-i2 "clear refusal" half (too few holders alive -> a named failure) and
#   restore-i3 (honest outcome): the CLI answers exit 0 + "started" even when nothing
#   was restored, e2e_lib.sh turns that into a FAIL instead of proving the report.
# Steps: 1. backup 4 MB -> restorable per owner — check: wait_file_restorable
#        2. SIGKILL the biggest holder; survivors still hold >= k_eff (precondition)
#             — check: block_symbols_on sum
#        3. rm source -> restore -> sha256 match, survivors log RestoreResponse
#             (restore-i1, restore-i2, restore-i9) — check: assert_delete_window,
#             restore_from_network, restore_responses_for
#        4. wipe survivor symbols: observed max per survivor < k_eff <= union
#             (precondition) — check: MAX_LEFT from block_symbols_on after the wipe
#        5. restore again -> sha256 match, >= 2 survivors served (restore-i2) — check:
#             restore_from_network, per-survivor restore_responses_for delta
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_fault_test.sh

set -euo pipefail

NUM_NODES=7
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-fault-$$"
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

run_cli_q() {
    run_cli "$@" 2>/dev/null || true
}

wait_daemon() {
    local idx="$1"
    for i in $(seq 1 120); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then
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

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"
        exit 1
    fi
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum Fault Injection Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup (${NUM_NODES} nodes) ==="

mkdir -p "$TEST_DIR"

# Init each node as an independent owner with its OWN master identity.
# Same-master siblings are excluded from the placement pool by design, so distinct
# owners are required to exercise the real backup/placement flow.
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
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

# ── PHASE 2: BACKUP ─────────────────────────────────────────────
echo ""
echo "=== Phase 2: File Backup ==="

FILE="$(node_dir 0)/files/fault_test.bin"
dd if=/dev/urandom of="$FILE" bs=1024 count=4096 2>/dev/null
ORIG_HASH=$(content_hash "$FILE")
echo "  Created 4 MB file, sha256 $ORIG_HASH"

TARGET=0
if wait_file_restorable 0 "$FILE" 90; then
    TARGET=$(file_field 0 "$FILE" '.effective_status.target')
    pass "owner reports the file restorable (k_eff=${TARGET})"
else
    fail "file not restorable per owner after 90s"
fi

BLOCK=$(file_block_hex 0 "$FILE")
declare -A SYMS
KILL_IDX=""; KILL_N=0; TOTAL=0
for i in $(seq 1 $((NUM_NODES-1))); do
    SYMS[$i]=$(block_symbols_on "$i" "$BLOCK")
    TOTAL=$((TOTAL + SYMS[$i]))
    [ "${SYMS[$i]}" -gt 0 ] && echo "  node-$(printf '%02d' "$i") holds ${SYMS[$i]} symbols of block ${BLOCK:0:16}.."
    if [ "${SYMS[$i]}" -gt "$KILL_N" ]; then KILL_IDX=$i; KILL_N=${SYMS[$i]}; fi
done

# ── PHASE 3: FAULT INJECTION — KILL THE BIGGEST HOLDER ──────────
echo ""
echo "=== Phase 3: Fault Injection ==="

if [ -z "$KILL_IDX" ]; then
    fail "no holder has symbols of block ${BLOCK:-none} on disk; nothing to kill"
    exit 1
fi
SURVIVING=$((TOTAL - KILL_N))
echo "  Killing node-$(printf '%02d' "$KILL_IDX") (${KILL_N} symbols); ${SURVIVING} symbols stay on survivors, k_eff=${TARGET}"
kill -9 "${PIDS[$KILL_IDX]}" 2>/dev/null || true
wait "${PIDS[$KILL_IDX]}" 2>/dev/null || true
if kill -0 "${PIDS[$KILL_IDX]}" 2>/dev/null; then
    fail "node-$(printf '%02d' "$KILL_IDX") still alive after SIGKILL"
fi
# Placement may give each holder a full k_eff set (replica mode). Then any one
# survivor decodes alone and combining symbols across holders is NOT exercised.
MAX_SURVIVOR=0
for i in "${!SYMS[@]}"; do
    [ "$i" != "$KILL_IDX" ] && [ "${SYMS[$i]}" -gt "$MAX_SURVIVOR" ] && MAX_SURVIVOR=${SYMS[$i]}
done
if [ "$TARGET" -gt 0 ] && [ "$MAX_SURVIVOR" -ge "$TARGET" ]; then
    info "a single survivor holds ${MAX_SURVIVOR} >= k_eff symbols: restore can succeed from one replica; cross-holder decode not exercised"
fi
# The scenario only means something if the survivors can still decode.
if [ "$SURVIVING" -ge "$TARGET" ] && [ "$TARGET" -gt 0 ]; then
    pass "precondition: survivors hold ${SURVIVING} >= k_eff ${TARGET} symbols"
else
    fail "precondition: survivors hold ${SURVIVING} < k_eff ${TARGET} symbols; placement left no redundancy for one loss"
fi

# ── PHASE 4: RESTORE WITH A DEAD HOLDER (E2E-07) ────────────────
echo ""
echo "=== Phase 4: Delete local copy -> restore from survivors (E2E-07) ==="

assert_delete_window "$TIME_SCALE"
rm -f "$FILE"
if ! wait_file_deleted 0 "$FILE" 30; then
    fail "owner did not register the local delete within 30s"
fi

SURVIVORS=()
for i in $(seq 1 $((NUM_NODES-1))); do [ "$i" != "$KILL_IDX" ] && SURVIVORS+=("$i"); done
SERVED_BEFORE=$(restore_responses_for "$BLOCK" "${SURVIVORS[@]}")
T0=$(date +%s)
if restore_from_network 0 "$FILE" "$ORIG_HASH" 180; then
    pass "E2E-07: restored with node-$(printf '%02d' "$KILL_IDX") dead in $(( $(date +%s) - T0 ))s: $RESTORE_MSG"
else
    fail "E2E-07: $RESTORE_MSG"
    echo "  node-00 restore log:"
    grep -ai "restore\|fetch" "$(node_log 0)" | tail -10 || true
fi
SERVED=$(( $(restore_responses_for "$BLOCK" "${SURVIVORS[@]}") - SERVED_BEFORE ))
if [ "$SERVED" -ge 1 ]; then
    pass "surviving holders logged ${SERVED} RestoreResponse(s)"
else
    fail "no surviving holder logged a RestoreResponse for block ${BLOCK:-none}"
fi

# ── PHASE 5: PARTIAL LOSS ON EVERY SURVIVOR -> CROSS-HOLDER DECODE ──
echo ""
echo "=== Phase 5: Partial symbol loss on every survivor -> cross-holder decode ==="

# Each holder keeps its own distinct ESI range, often a full k_eff set, so Phase 4
# may have decoded from one replica. Here every survivor loses part of its symbol
# files on disk (partial disk loss the holder daemon does not notice) so that NO
# single holder has k_eff symbols but the survivors together still do. Restore must
# then combine symbols from several holders.
KEEP=$(( (TARGET * 2 + 4) / 5 ))   # ~40% of k_eff per survivor
[ "$KEEP" -ge "$TARGET" ] && KEEP=$((TARGET - 1))
UNION=0
for i in "${SURVIVORS[@]}"; do
    d="$(node_dir "$i")/holdings/$BLOCK"
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f -name '*.bin' | sort -V | tail -n +$((KEEP + 1)) | xargs -r rm -f
done
# The precondition is checked on what the disks actually hold after the wipe,
# not on the intended cap KEEP: a survivor that still has k_eff symbols would
# let restore decode from one replica.
MAX_LEFT=0
for i in "${SURVIVORS[@]}"; do
    left=$(block_symbols_on "$i" "$BLOCK")
    UNION=$((UNION + left))
    [ "$left" -gt "$MAX_LEFT" ] && MAX_LEFT=$left
    echo "  node-$(printf '%02d' "$i") keeps ${left} symbols"
done
if [ "$TARGET" -gt 0 ] && [ "$UNION" -ge "$TARGET" ] && [ "$MAX_LEFT" -lt "$TARGET" ]; then
    pass "precondition: max per survivor ${MAX_LEFT} < k_eff=${TARGET}, survivors together hold ${UNION}"
else
    fail "precondition: max per survivor ${MAX_LEFT} (want < k_eff=${TARGET}), survivors together hold ${UNION} (want >= ${TARGET})"
fi

declare -A SERVED_B
for i in "${SURVIVORS[@]}"; do SERVED_B[$i]=$(restore_responses_for "$BLOCK" "$i"); done
if restore_from_network 0 "$FILE" "$ORIG_HASH" 180; then
    pass "cross-holder restore: $RESTORE_MSG"
else
    fail "cross-holder restore: $RESTORE_MSG"
    grep -ai "restore\|fetch\|insufficient" "$(node_log 0)" | tail -10 || true
fi
CONTRIB=0
for i in "${SURVIVORS[@]}"; do
    [ $(( $(restore_responses_for "$BLOCK" "$i") - SERVED_B[$i] )) -ge 1 ] && CONTRIB=$((CONTRIB + 1))
done
if [ "$CONTRIB" -ge 2 ]; then
    pass "${CONTRIB} survivors served symbols for the cross-holder restore"
else
    fail "only ${CONTRIB} survivor(s) served symbols; cross-holder decode not exercised"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
