#!/bin/bash
# Viaticum: PoS verification of a user block + repair after a holder dies.
# Local processes on one machine (no Docker).
#
# Scenario: 7 independent owners, star-connected to node-00, time_scale 100000 (a PoS
#   week is ~6 s). node-00 backs up a 256 KB .txt file (importance 1.0). PoS challenges
#   run against its holders. Once the block sits at its reliability target a spare node
#   joins, then two holders are killed: the block drops below target and the owner must
#   detect the loss and repair from its source file onto the spare.
# Intent: pos-i1, pos-i2, repair-i1, backup-i3 (file pending; proposed ids: pos-i1 =
#   PoS of a user block resolves as Pass without an owner-side block copy, pos-i2 = the
#   owner detects dead holders via PoS timeouts, repair-i1 = a block that dropped below
#   target is repaired from the source file onto a new holder, backup-i3 = the owner
#   keeps no copy of its own blocks).
# Proves: the owner keeps no copy of the block on disk (no block.bin / raw/ anywhere in
#   its data dir) yet resolves PoS challenges for THIS block as Pass (expected hash
#   re-derived from the source file); the owner detects dead holders via PoS timeouts;
#   repair puts symbols of the block on the spare's disk, and the spare received none
#   while the block was at target (so the kill caused it).
# Adversarial: SIGKILL of two holders at once after the block reached its target.
# Cannot close: that the repaired set alone decodes (no restore after repair); PoS
#   against a lying holder; repair when the source file is gone (impossible by design,
#   P1); repair when no spare peer exists (placement is one placement per holder per
#   block, so a fully used pool cannot be repaired — see the work_pipeline log).
# Steps: 1. backup -> restorable per owner — check: wait_file_restorable
#        2. no block.bin / raw/ / <block>.. files in node-00 data dir (backup-i3) —
#             check: find
#        3. PoS for the block resolves Pass, no non-Pass from honest holders (pos-i1)
#             — check: node-00 log
#        4. block at target; spare joins and holds 0 symbols for 10 s (precondition)
#             — check: is_safe_to_delete, block_symbols_on spare
#        5. SIGKILL two holders -> owner logs PoS timeouts for both within 120 s
#             (pos-i2) — check: node-00 log
#        6. spare's disk gets symbols of the block within 180 s (repair-i1) — check:
#             block_symbols_on spare
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_pos_repair_test.sh

set -euo pipefail

NUM_NODES=7
TIME_SCALE=100000   # PoS fires every ~3s, repair every ~1s
TEST_DIR="/tmp/viaticum-pos-repair-$$"
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
    local RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

echo "============================================================"
echo "  Viaticum: PoS of a user block + repair after holder death"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init each node as an independent owner with its OWN master identity.
# Same-master siblings are excluded from the placement pool by design (sibling
# exclusion, cluster phase 1), so distinct owners are required to exercise the
# real backup/placement flow; cross-cluster peers authenticate via self-signed
# cert (CertTrustPath::Cross) and become eligible holders for each other.
echo "  Initializing ${NUM_NODES} nodes as independent owners (distinct masters)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
done
echo "  ${NUM_NODES} nodes initialized (distinct master keys)."

# Write config for all nodes (web_api + storage).
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
    if wait_daemon "$i"; then READY=$((READY + 1)); else echo "    node-$(printf "%02d" "$i") NOT ready"; fi
done
echo "  $READY/$NUM_NODES daemons ready"

# Connect all to node-00
ADDR_00=$(get_addr 0)
echo "  Connecting to node-00 ($ADDR_00)..."
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null 2>&1
done

if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

# ── PHASE 2: BACKUP ─────────────────────────────────────────────
echo ""
echo "=== Phase 2: Backup ==="

FILE="$(node_dir 0)/files/pos_test.txt"   # .txt = importance 1.0
head -c 196608 /dev/urandom | base64 -w 0 > "$FILE"   # ~256 KB of text
if wait_file_restorable 0 "$FILE" 60; then
    pass "file backed up and restorable per owner"
else
    fail "file not restorable per owner after 60s"
    exit 1
fi
BLOCK=$(file_block_hex 0 "$FILE")
BSHORT=${BLOCK:0:16}
echo "  block: $BLOCK"

# ── PHASE 3: PRECONDITION — NO LOCAL COPY OF THE BLOCK ──────────
echo ""
echo "=== Phase 3: Owner keeps no copy of the block ==="

# Wave 11b: symbols are produced in RAM from the source file; nothing like block.bin
# or raw/{esi}.bin may exist anywhere in the owner's data dir (holdings/ = other
# owners' data, excluded). This makes Phase 4 meaningful: the owner has no stored
# copy to compute PoS expectations from.
LOCAL_COPIES=$(find "$(node_dir 0)" -path "$(node_dir 0)/holdings" -prune -o \
    \( -name block.bin -o -path '*/raw/*.bin' -o -path "*/$BLOCK/*" \) -type f -print | wc -l)
if [ "$LOCAL_COPIES" -eq 0 ]; then
    pass "precondition: no block.bin / raw/ / $BSHORT.. files in node-00 data dir"
else
    fail "node-00 keeps ${LOCAL_COPIES} local block file(s)"
    find "$(node_dir 0)" -path "$(node_dir 0)/holdings" -prune -o \
        \( -name block.bin -o -path '*/raw/*.bin' -o -path "*/$BLOCK/*" \) -type f -print | head -5 || true
fi

# ── PHASE 4: PoS OF THIS BLOCK ──────────────────────────────────
echo ""
echo "=== Phase 4: PoS challenges for the user block resolve as Pass ==="

# pos_total_passes also counts PoS of the owner's SystemState blocks, whose blobs ARE
# retained on disk — so it proves nothing about rebuild-from-source. Count only
# responses resolved for this block.
POS_PASS=0; POS_OTHER=0
for attempt in $(seq 1 45); do
    POS_PASS=$(plain_log 0 | grep -a "mailbox PosResponse resolved" | grep -a "$BSHORT" | grep -ac "outcome=Pass" || true)
    POS_OTHER=$(plain_log 0 | grep -a "mailbox PosResponse resolved" | grep -a "$BSHORT" | grep -avc "outcome=Pass" || true)
    [ "${POS_PASS:-0}" -ge 1 ] && break
    sleep 2
done
echo "  PoS responses for $BSHORT..: pass=${POS_PASS:-0} other=${POS_OTHER:-0}"
if [ "${POS_PASS:-0}" -ge 1 ]; then
    pass "PoS for the user block resolved as Pass (${POS_PASS}x) without a local block copy"
else
    fail "no PoS Pass for block $BSHORT.. after 90s (issued: $(plain_log 0 | grep -a "challenge issued" | grep -ac "$BSHORT" || true))"
fi
if [ "${POS_OTHER:-0}" -gt 0 ]; then
    fail "${POS_OTHER} PoS response(s) for the block with a non-Pass outcome from honest holders"
    plain_log 0 | grep -a "mailbox PosResponse resolved" | grep -a "$BSHORT" | grep -av "outcome=Pass" | head -3 || true
fi

# ── PHASE 5: SPARE JOINS, TWO HOLDERS DIE -> REPAIR ONTO THE SPARE ──
echo ""
echo "=== Phase 5: Spare joins, two holders die -> repair onto the spare ==="

# Repair only runs when the block falls below its reliability target, and placement
# never puts a second placement of a block on the same holder. Initial placement
# spreads over the whole pool, so a spare must join AFTER the block is at target.
AT_TARGET=0
for _ in $(seq 1 60); do
    [ "$(file_field 0 "$FILE" '.is_safe_to_delete')" = "true" ] && { AT_TARGET=1; break; }
    sleep 1
done
if [ "$AT_TARGET" -eq 1 ]; then
    pass "block reached its reliability target (is_safe_to_delete)"
else
    fail "block did not reach its reliability target within 60s; repair attribution below is unreliable"
fi

SPARE=$NUM_NODES
mkdir -p "$(node_dir "$SPARE")/files"
run_cli "$SPARE" init > /dev/null 2>&1
cp "$(node_dir 0)/config.toml" "$(node_dir "$SPARE")/config.toml"
RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$SPARE")" daemon \
    --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$SPARE")/files" \
    > "$(node_log "$SPARE")" 2>&1 &
PIDS+=($!)
wait_daemon "$SPARE" || fail "spare node-$(printf '%02d' "$SPARE") did not start"
run_cli_q "$SPARE" connect "$ADDR_00" > /dev/null
if wait_auth_peers 0 "$NUM_NODES" 30; then
    pass "spare node-$(printf '%02d' "$SPARE") joined ($(status_num 0 peer_count_authenticated) authenticated peers)"
else
    fail "spare did not authenticate with node-00 within 30s"
fi

# Negative window: with the block at target, nothing should be placed on the spare.
sleep 10
PRE=$(block_symbols_on "$SPARE" "$BLOCK")
if [ "$PRE" -eq 0 ]; then
    pass "spare holds 0 symbols of the block while it is at target (10s window)"
else
    fail "spare received ${PRE} symbols before any loss; the repair below cannot be attributed to the kill"
fi

declare -A BEFORE
HOLDER_IDX=()
for i in $(seq 1 $((NUM_NODES-1))); do
    BEFORE[$i]=$(block_symbols_on "$i" "$BLOCK")
    echo "  node-$(printf '%02d' "$i"): ${BEFORE[$i]} symbols"
    [ "${BEFORE[$i]}" -gt 0 ] && HOLDER_IDX+=("$i")
done
if [ "${#HOLDER_IDX[@]}" -lt 3 ]; then
    fail "only ${#HOLDER_IDX[@]} holders; need >= 3 to kill two and keep one"
    exit 1
fi
KILLED=("${HOLDER_IDX[0]}" "${HOLDER_IDX[1]}")
KILL_DEVS=()
for k in "${KILLED[@]}"; do
    KILL_DEVS+=("$(api_get "$k" /api/status | jq -r '.device_id // empty' 2>/dev/null || true)")
done
echo "  Killing node-$(printf '%02d' "${KILLED[0]}") (${KILL_DEVS[0]:-?}) and node-$(printf '%02d' "${KILLED[1]}") (${KILL_DEVS[1]:-?})"
for k in "${KILLED[@]}"; do
    kill -9 "${PIDS[$k]}" 2>/dev/null || true
    wait "${PIDS[$k]}" 2>/dev/null || true
done
T0=$(date +%s)

# Detection: PoS timeouts for this block naming each dead holder.
DETECTED=0
for _ in $(seq 1 60); do
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
    fail "owner logged PoS timeouts for ${DETECTED}/2 dead holders of block $BSHORT.. within 120s"
fi

# Repair evidence on the spare's own disk.
GOT=0
for _ in $(seq 1 90); do
    GOT=$(block_symbols_on "$SPARE" "$BLOCK")
    [ "$GOT" -gt 0 ] && break
    sleep 2
done
if [ "$GOT" -gt 0 ]; then
    pass "repair placed ${GOT} symbols of the block on the spare after $(( $(date +%s) - T0 ))s"
else
    fail "no symbols of the block on the spare 180s after the kill"
    plain_log 0 | grep -a "$BSHORT" | grep -ai "picked block\|candidates\|repair" | tail -6 || true
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
