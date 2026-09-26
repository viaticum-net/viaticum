#!/bin/bash
# Viaticum big-file E2E: realistic sizes (10-100 MB), restore of a 100 MB file from
# the network, RAM/disk footprint per node.
#
# Scenario: 5 independent owners, star-connected to node-00. node-00 backs up a 50 MB
#   and a 100 MB file, loses the 100 MB file locally and restores it from holders, then
#   backs up a batch of 10 x 10 MB files. RSS/disk snapshots are printed along the way.
# Intent: restore-i1 (Phase 4), restore-i9 (partial: restore right after the delete);
#   backup-i1, backup-i3 (file pending; proposed ids: backup-i1 = a backed-up file has
#   >= k_eff symbols on holder disks, backup-i3 = the owner keeps no copy of its own
#   blocks, storage-layout doctrine).
# Proves: 50/100 MB files and a 10-file batch reach "restorable" per the owner and
#   their symbols are on holder disks (the holder-disk sum reaches the owner's Alive
#   symbol count, >= k_eff); the owner keeps no copy of its own blocks (data dir minus
#   watch dir/holdings/restore stays small, storage-layout doctrine); with the local
#   source gone the 100 MB file comes back from holders byte-identical (sha256) and the
#   holders log serving it.
# Adversarial: the 100 MB source is deleted while the daemon runs, so restore must
#   fetch ~100 MB of symbols from holders.
# Cannot close: RAM ceilings (RSS is printed, not asserted); files larger than one
#   128 MB source block (multi-block files); restore of the batch; throughput numbers
#   (all nodes share one host); per-holder placement check (the API gives only the
#   owner's total Alive symbol count, not which holder should hold how many, so
#   holder_check compares sums); redundancy above k_eff (at "restorable" a block may
#   sit on exactly one holder with exactly k_eff symbols); restore-i3 (honest outcome):
#   the CLI answers exit 0 + "started" even when nothing was restored, e2e_lib.sh turns
#   that into a FAIL instead of proving the report.
# Steps: 1. backup 50 MB -> restorable; holder-disk sum >= owner Alive >= k_eff
#             (backup-i1) — check: wait_file_restorable, holder_check (polled 120 s)
#        2. owner data dir minus files/holdings/restore/log < 10 MB (backup-i3) —
#             check: du
#        3. backup 100 MB -> same as step 1 (backup-i1)
#        4. rm 100 MB source -> restore -> sha256 match; holders log RestoreResponse
#             (restore-i1, restore-i9) — check: assert_delete_window,
#             restore_from_network, restore_responses_for
#        5. 10 x 10 MB -> 10/10 restorable; holder_check on batch_1 and batch_10
#             (backup-i1)
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_bigfile_test.sh

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

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

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
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

echo ""
echo "=== Baseline resource usage ==="
measure_all

# holder_check PATH LABEL: poll (deadline 120 s) until the symbols of PATH's block
# on holder disks reach the owner's Alive symbol count (`effective_status.live`,
# re-read every poll), then require that count >= k_eff. The API gives no
# per-holder breakdown of placements, so the match is on the sum over holders.
holder_check() {
    local path="$1" label="$2" blk tgt live n on=0 who=""
    blk=$(file_block_hex 0 "$path")
    for _ in $(seq 1 120); do
        tgt=$(file_field 0 "$path" '.effective_status.target // 0')
        live=$(file_field 0 "$path" '.effective_status.live // 0')
        on=0; who=""
        for i in $(seq 1 $((NUM_NODES-1))); do
            n=$(block_symbols_on "$i" "$blk")
            [ "$n" -gt 0 ] && who="$who node-$(printf '%02d' "$i")=$n"
            on=$((on + n))
        done
        [ -n "$blk" ] && [ "${live:-0}" -gt 0 ] && [ "$on" -ge "$live" ] && break
        sleep 1
    done
    echo "  $label block ${blk:0:16}.. on holder disks:${who:- none} (owner Alive symbols: ${live:-?})"
    if [ -n "$blk" ] && [ "${tgt:-0}" -gt 0 ] && [ "${live:-0}" -ge "$tgt" ] && [ "$on" -ge "$live" ]; then
        pass "$label: holders store ${on} symbols >= owner's Alive ${live} >= k_eff ${tgt}"
    else
        fail "$label: holders store ${on} symbols, owner Alive ${live:-?}, k_eff=${tgt:-?} (block=${blk:-none})"
    fi
}

# ── PHASE 2: 50 MB FILE ─────────────────────────────────────────
echo ""
echo "=== Phase 2: Backup 50 MB file ==="
F50="$(node_dir 0)/files/big50.bin"
dd if=/dev/urandom of="$F50" bs=1M count=50 2>/dev/null
echo "  Created 50 MB file (sha256 $(content_hash "$F50"))"

T0=$(date +%s)
if wait_file_restorable 0 "$F50" 240; then
    pass "50 MB file restorable per owner after $(( $(date +%s) - T0 ))s"
else
    fail "50 MB file not restorable per owner after 240s"
fi
holder_check "$F50" "50 MB"

echo ""
echo "=== Post-50MB resource usage ==="
measure_all

# Storage-layout doctrine: the owner does not keep its own blocks on disk. What is
# left in its data dir besides the watch dir, peer holdings, restore staging and the
# log is metadata (redb, SS blobs) and must stay far below the 50 MB just backed up.
OWNER_OVERHEAD_KB=$(du -sk --exclude=files --exclude=holdings --exclude=restore \
    --exclude=daemon.log "$(node_dir 0)" | cut -f1)
echo "  node-00 data dir without files/holdings/restore/log: ${OWNER_OVERHEAD_KB} KB"
if [ "${OWNER_OVERHEAD_KB:-999999}" -lt 10240 ]; then
    pass "owner keeps no copy of its blocks (${OWNER_OVERHEAD_KB} KB < 10 MB)"
else
    fail "owner data dir holds ${OWNER_OVERHEAD_KB} KB outside files/holdings (own blocks on disk?)"
    du -sk "$(node_dir 0)"/* 2>/dev/null | sort -rn | head -5 || true
fi

# ── PHASE 3: 100 MB FILE ────────────────────────────────────────
echo ""
echo "=== Phase 3: Backup 100 MB file ==="
F100="$(node_dir 0)/files/big100.bin"
dd if=/dev/urandom of="$F100" bs=1M count=100 2>/dev/null
HASH_100=$(content_hash "$F100")
echo "  Created 100 MB file (sha256 $HASH_100)"

T0=$(date +%s)
if wait_file_restorable 0 "$F100" 300; then
    pass "100 MB file restorable per owner after $(( $(date +%s) - T0 ))s"
else
    fail "100 MB file not restorable per owner after 300s"
fi
holder_check "$F100" "100 MB"

echo ""
echo "=== Post-100MB resource usage ==="
measure_all

TOTAL_HOLDING=0
for i in $(seq 1 $((NUM_NODES-1))); do
    H_SIZE=$(du -sk "$(node_dir "$i")/holdings" 2>/dev/null | cut -f1)
    TOTAL_HOLDING=$((TOTAL_HOLDING + ${H_SIZE:-0}))
done
info "total holder disk: $((TOTAL_HOLDING / 1024)) MB across $((NUM_NODES-1)) peers for 150 MB of source"

# ── PHASE 4: LOSE 100 MB LOCALLY -> RESTORE FROM THE NETWORK ────
echo ""
echo "=== Phase 4: Delete 100 MB file locally -> restore from the network ==="
# restore writes to <data_dir>/restore/<job_id>/<original_path>; --dest is not
# supported in alpha. The owner-delete cooldown (4 weeks) is ~6.7 h at scale 100.
BLOCK_100=$(file_block_hex 0 "$F100")
assert_delete_window "$TIME_SCALE"
rm -f "$F100"
if ! wait_file_deleted 0 "$F100" 30; then
    fail "owner did not register the local delete within 30s"
fi
SERVED_BEFORE=$(restore_responses_for "$BLOCK_100" $(seq 1 $((NUM_NODES-1))))
T0=$(date +%s)
if restore_from_network 0 "$F100" "$HASH_100" 300; then
    pass "100 MB restore from network in $(( $(date +%s) - T0 ))s: $RESTORE_MSG"
else
    fail "100 MB restore from network: $RESTORE_MSG"
    grep -ai "restore\|fetch" "$(node_log 0)" | tail -10 || true
fi
SERVED=$(( $(restore_responses_for "$BLOCK_100" $(seq 1 $((NUM_NODES-1)))) - SERVED_BEFORE ))
if [ "$SERVED" -ge 1 ]; then
    pass "holders logged ${SERVED} RestoreResponse(s) for the 100 MB block"
else
    fail "no holder logged a RestoreResponse for block ${BLOCK_100:-none}"
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

T0=$(date +%s)
READY_N=0
for _ in $(seq 1 300); do
    READY_N=$(api_get 0 /api/files | jq '[.[] | select((.path | test("/batch_[0-9]+\\.bin$")) and .effective_status.kind == "restorable")] | length' 2>/dev/null || echo 0)
    [ "${READY_N:-0}" -ge 10 ] && break
    sleep 1
done
if [ "${READY_N:-0}" -ge 10 ]; then
    pass "10 x 10 MB batch restorable per owner after $(( $(date +%s) - T0 ))s"
else
    fail "batch: only ${READY_N:-0}/10 files restorable per owner after 300s"
fi
holder_check "$(node_dir 0)/files/batch_1.bin" "batch_1"
holder_check "$(node_dir 0)/files/batch_10.bin" "batch_10"

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

[ "$FAIL" -eq 0 ]
