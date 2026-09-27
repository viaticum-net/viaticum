#!/bin/bash
# Viaticum: owner deletion E2E — multi-holder erasure delete reaches ALL holders.
# Local processes on one machine (no Docker).
#
# Scenario: 5 independent owners, star-connected to node-00, time_scale 100000 (owner
#   and holder delete cooldowns of 4 weeks each become ~24 s). node-00 backs up a file,
#   the file is removed from the watch dir, and the delete must reach every holder.
# Intent: delete-i1, delete-i2 (file pending; proposed ids: delete-i1 = after the owner
#   deletes a file and the cooldowns expire, every holder drops its symbols, delete-i2 =
#   the owner's catalog stops referencing the block). AC1..AC3 below.
# Proves: every holder that stored symbols of the file's block (read from each holder's
#   own holdings/<block>/ on disk) drops all of them after the owner's delete (H3: not
#   just one holder); the owner's catalog stops referencing the block (CleanupBlock).
# Adversarial: none beyond the multi-holder case (H3); a holder offline during the
#   delete is not exercised (see Cannot close).
# Cannot close: deletion of a block shared by several files (packs) — covered by
#   local_pack_delete_test (delete-i3); a holder offline during the delete (mailbox
#   delivery later);
#   un-delete inside the cooldown (restore of a deleted file: local_e2e).
# Steps: 1. backup -> restorable per owner — check: wait_file_restorable
#        2. >= 2 holders have symbols of the block on disk (precondition) — check:
#             block_symbols_on per holder
#        3. rm source -> local_state deleted — check: wait_file_deleted
#        4. every recorded holder's holdings/<block> empty within 180 s (delete-i1,
#             AC1/AC3) — check: block_symbols_on per holder
#        5. no catalog version references the block within 90 s (delete-i2, AC2) —
#             check: /api/versions
#
# WHY THIS TEST EXISTS (intent / acceptance criteria — fixed before the script):
#   Deletion is a load-bearing product property: when the owner removes a backed-up
#   file, the data must actually disappear from the network. The H3 review finding
#   showed a real bug class here (per-BLOCK dedup meant only ONE holder of an
#   erasure-coded block ever received the Delete; holders 2..n kept the data forever).
#
#   AC1 (H3, the core): after the file is removed from the watch dir, EVERY holder that
#        stored its symbols deletes them, not just one. Checked per block on each
#        holder's disk. (Total holding_bytes is NOT used: holders also store other
#        owners' SystemState blocks, which are not part of this delete.)
#   AC2: the owner cleans up afterwards — no version in the catalog references the
#        deleted block (CleanupPlacement -> CleanupBlock fired).
#   AC3: deletion is HONORED, not merely believed — AC1 reads holder disks, never the
#        owner's own optimistic view.
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_delete_test.sh [num_nodes]

set -euo pipefail

NUM_NODES="${1:-5}"
# OWNER/HOLDER delete cooldowns are 4 weeks each. At scale 100000 they compress to
# ~24s apiece, so the full owner-cooldown -> DeleteMsg -> holder-cooldown -> drop
# chain finishes in ~60-90s wall-clock. Timeouts below allow generous slack.
TIME_SCALE=100000
TEST_DIR="/tmp/viaticum-delete-$$"
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

# ── PHASE 2: BACKUP + WAIT FOR DELIVERY ─────────────────────────
echo ""
echo "=== Phase 2: Backup + Delivery ==="

TEST_FILE="$(node_dir 0)/files/delete_test.bin"
echo "  Creating test file (256 KB)..."
dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=256 2>/dev/null

if wait_file_restorable 0 "$TEST_FILE" 60; then
    pass "file backed up and restorable per owner"
else
    fail "file not restorable per owner after 60s"
    exit 1
fi
BLOCK=$(file_block_hex 0 "$TEST_FILE")
echo "  block: $BLOCK"

# ── PHASE 3: RECORD THE FULL HOLDER SET (from holder disks) ─────
echo ""
echo "=== Phase 3: Record Holder Set ==="

# Placement may still be adding holders right after "restorable"; take the set once
# it has been stable for 5 consecutive seconds (max 30 s).
HOLDERS=(); PREV=""; STABLE=0
for _ in $(seq 1 30); do
    CUR=""
    for i in $(seq 1 $((NUM_NODES-1))); do
        [ "$(block_symbols_on "$i" "$BLOCK")" -gt 0 ] && CUR="$CUR $i"
    done
    if [ "$CUR" = "$PREV" ] && [ -n "$CUR" ]; then STABLE=$((STABLE + 1)); else STABLE=0; fi
    PREV="$CUR"
    [ "$STABLE" -ge 5 ] && break
    sleep 1
done
read -r -a HOLDERS <<< "$PREV"
for i in "${HOLDERS[@]}"; do
    echo "  node-$(printf '%02d' "$i") holds $(block_symbols_on "$i" "$BLOCK") symbols of the block"
done
NUM_HOLDERS=${#HOLDERS[@]}

if [ "$NUM_HOLDERS" -eq 0 ]; then
    fail "no holder has symbols of block $BLOCK on disk — cannot test deletion"
    exit 1
fi
if [ "$NUM_HOLDERS" -ge 2 ]; then
    pass "multi-holder block confirmed ($NUM_HOLDERS holders) — H3 case exercised"
else
    fail "only 1 holder — the H3 multi-holder case is NOT exercised"
fi

# ── PHASE 4: DELETE THE FILE ────────────────────────────────────
echo ""
echo "=== Phase 4: Delete File from Watch Dir ==="

echo "  Removing $TEST_FILE ..."
rm -f "$TEST_FILE"
if wait_file_deleted 0 "$TEST_FILE" 30; then
    pass "owner registered the local delete"
else
    fail "owner did not register the local delete within 30s"
fi

# ── PHASE 5: VERIFY EVERY HOLDER DELETES (AC1 / H3) ─────────────
echo ""
echo "=== Phase 5: Verify ALL Holders Delete (AC1 / H3) ==="

# Owner cooldown (~24s) -> DeleteMsg via mailbox -> holder marks -> holder cooldown
# (~24s) -> holder drops symbols. Poll every 3s up to 180s for ALL holders to have
# no symbol files of the block left on disk.
ALL_DELETED=0
for attempt in $(seq 1 60); do
    STILL_HOLDING=()
    for i in "${HOLDERS[@]}"; do
        [ "$(block_symbols_on "$i" "$BLOCK")" -gt 0 ] && STILL_HOLDING+=("$i")
    done
    if [ "${#STILL_HOLDING[@]}" -eq 0 ]; then
        echo "  All $NUM_HOLDERS holders dropped the block's symbols (${attempt}x3s)"
        ALL_DELETED=1
        break
    fi
    if [ $((attempt % 5)) -eq 0 ]; then
        echo "  still holding: ${#STILL_HOLDING[@]}/$NUM_HOLDERS holders (nodes ${STILL_HOLDING[*]}) (${attempt}x3s)"
    fi
    sleep 3
done

if [ "$ALL_DELETED" -eq 1 ]; then
    pass "AC1: every holder ($NUM_HOLDERS) deleted the block's symbols after owner delete"
else
    fail "AC1/H3: ${#STILL_HOLDING[@]}/$NUM_HOLDERS holders still hold the block after 180s (nodes ${STILL_HOLDING[*]})"
    echo "  This is the H3 multi-holder regression signature (delete reaches only some holders)."
fi

# ── PHASE 6: VERIFY OWNER CLEANUP (AC2) ─────────────────────────
echo ""
echo "=== Phase 6: Verify Owner Cleanup (AC2) ==="

# After all holders are done, the owner runs CleanupPlacement per holder and
# CleanupBlock once all placements are cleaned, pruning the version entry that
# references the block. (The total placement_count is not used: it also counts the
# owner's own SystemState blocks.)
OWNER_CLEAN=0
for attempt in $(seq 1 30); do
    REFS=$(api_get 0 "/api/versions?path=$(urlencode "$TEST_FILE")" \
        | jq --arg b "$BLOCK" '[.[] | select(.source_block_id_hex == $b)] | length' 2>/dev/null || echo "?")
    if [ "$REFS" = "0" ]; then
        echo "  Catalog no longer references the block (${attempt}x3s)"
        OWNER_CLEAN=1
        break
    fi
    sleep 3
done

if [ "$OWNER_CLEAN" -eq 1 ]; then
    pass "AC2: owner cleaned up the block (CleanupBlock fired)"
else
    fail "AC2: catalog still references block ${BLOCK:0:16}.. after 90s (refs=${REFS})"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
