#!/bin/bash
# Viaticum E2E: backup -> holders -> edit -> accidental delete -> restore from the network.
# Local processes on one machine (no Docker).
#
# Scenario: 3 independent owners on localhost, star-connected to node-00. node-00 backs
#   up a 128 KB file, edits it (second version), then the user deletes it by accident and
#   restores it while the owner-delete cooldown (4 weeks = ~40 min at time_scale 1000) runs.
# Intent: restore-i1 (Phase 4), restore-i9 (partial: restore right after the delete,
#   not a scaled week later), restore-i6 (Phase 4: no [escrow] override in the config;
#   sensitive to the removed holder gate only while the restore finishes before the
#   bound the script computes from holder disks — typically several hundred s after
#   daemon start at TIME_SCALE=1000; the run needs ~20 s; slower = FAIL, not skip);
#   backup-i1, backup-i2 (file pending; proposed ids:
#   backup-i1 = a backed-up file has >= k_eff symbols on holder disks, backup-i2 = an
#   edit becomes a new catalog version).
# Proves: the watcher -> encode -> place pipeline puts >= k_eff symbols of the block on
#   holder disks (read from the holders' own holdings/, not the owner's view); an edit
#   produces a second catalog version; with the local source gone, the latest version
#   comes back from holders byte-identical (sha256), and the holders log serving it.
# Adversarial: the source is deleted while the daemon runs (watcher Remove event), so
#   restore cannot rebuild from the local file and must go to the network.
# Cannot close: PoS, trust and SelfPointer delivery (timing-dependent at this scale;
#   covered by local_pos_repair / local_dr); restore of an older version (the old block
#   is orphaned by design, P2); restore after the delete cooldown expired (the network
#   is then allowed to drop the data); restore on another machine (local_dr);
#   restore-i3 (honest outcome): the CLI answers exit 0 + "started" even when nothing
#   was restored, e2e_lib.sh turns that into a FAIL instead of proving the report.
# Steps: 1. backup 128 KB -> restorable, >= k_eff symbols on holders (backup-i1) —
#             check: wait_file_restorable + block_symbols_on per holder
#        2. edit -> >= 2 catalog versions (backup-i2) — check: /api/versions length
#        3. rm source -> local_state deleted (restore-i9) — check: assert_delete_window,
#             wait_file_deleted
#        4. restore -> sha256 == pre-delete hash; holders log RestoreResponse
#             (restore-i1) — check: restore_from_network, restore_responses_for
#        4b. the restore finished while the pre-v1 holder gate (budget = held bytes x
#             scaled age / 7 days < c x 65535 requested) would have refused EVERY holder
#             of the block (restore-i6) — check: elapsed since daemon start < bound
#             computed per holder from status.holding_bytes / du and its symbol count
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_e2e_test.sh [num_nodes]

set -euo pipefail

NUM_NODES=${1:-3}
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-e2e-$$"
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
echo "  Viaticum E2E Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init each node as an independent owner with its OWN master identity.
# Cross-cluster peers authenticate via self-signed cert (CertTrustPath::Cross)
# and become eligible holders for each other's data. Same-master siblings are
# excluded from the placement pool by design (sibling exclusion, cluster phase 1),
# so a single shared cluster cannot place — distinct owners are required to
# exercise the real backup/placement flow.
echo "  Initializing ${NUM_NODES} nodes as independent owners (distinct masters)..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    "$BINARY" --data-dir "$(node_dir "$i")" init > /dev/null 2>&1
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
# restore-i6 guard anchor: no holding can be older than this.
T_DAEMONS=$(date +%s)
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
    else
        echo "    node-$(printf '%02d' "$i") NOT ready"
    fi
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
# Authenticated = cert exchange done, i.e. eligible for placement/restore traffic.
# (peer_count is DB rows and includes peers that never finished the handshake.)
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

# ── PHASE 2: BACKUP, CHECKED ON HOLDER DISKS ────────────────────
echo ""
echo "=== Phase 2: Backup (checked on holder disks) ==="

FILE="$(node_dir 0)/files/backup_test.bin"
dd if=/dev/urandom of="$FILE" bs=1024 count=128 2>/dev/null
HASH_V1=$(content_hash "$FILE")
echo "  Created 128 KB file, sha256 $HASH_V1"

# Owner belief first: >= k_eff symbols on Alive placements.
if wait_file_restorable 0 "$FILE" 90; then
    TARGET=$(file_field 0 "$FILE" '.effective_status.target')
    pass "owner reports v1 restorable (k_eff=${TARGET})"
else
    fail "v1 not restorable per owner after 90s"
    TARGET=0
fi

# Holder reality: count the block's symbol files on every other node's disk.
BLOCK_V1=$(file_block_hex 0 "$FILE")
ON_DISK=0; HOLDERS=""
for i in $(seq 1 $((NUM_NODES-1))); do
    n=$(block_symbols_on "$i" "$BLOCK_V1")
    [ "$n" -gt 0 ] && HOLDERS="$HOLDERS node-$(printf '%02d' "$i")=$n"
    ON_DISK=$((ON_DISK + n))
done
echo "  block ${BLOCK_V1:0:16}.. symbols on holder disks:${HOLDERS:- none}"
if [ -n "$BLOCK_V1" ] && [ "$TARGET" -gt 0 ] && [ "$ON_DISK" -ge "$TARGET" ]; then
    pass "holders store ${ON_DISK} symbols >= k_eff ${TARGET} on disk"
else
    fail "holders store ${ON_DISK} symbols on disk, need k_eff=${TARGET:-?} (block=${BLOCK_V1:-none})"
fi

# ── PHASE 3: EDIT -> SECOND VERSION ─────────────────────────────
echo ""
echo "=== Phase 3: Edit -> second version ==="

dd if=/dev/urandom of="$FILE" bs=1024 count=64 2>/dev/null
HASH_V2=$(content_hash "$FILE")
echo "  Rewrote file (64 KB), sha256 $HASH_V2"

VCOUNT=0
for _ in $(seq 1 60); do
    VCOUNT=$(api_get 0 "/api/versions?path=$(urlencode "$FILE")" | jq 'length' 2>/dev/null || echo 0)
    [ "${VCOUNT:-0}" -ge 2 ] && break
    sleep 1
done
if [ "${VCOUNT:-0}" -ge 2 ]; then
    pass "catalog has ${VCOUNT} versions after the edit"
else
    fail "catalog has ${VCOUNT:-0} version(s) 60s after the edit, expected 2"
fi

if wait_file_restorable 0 "$FILE" 90; then
    pass "owner reports v2 restorable"
else
    fail "v2 not restorable per owner after 90s"
fi

# ── PHASE 4: ACCIDENTAL DELETE -> RESTORE FROM THE NETWORK ──────
echo ""
echo "=== Phase 4: Accidental delete -> restore from the network ==="

# The owner rebuilds blocks from its own source files when they exist
# (restore/mod.rs: rebuild-from-source first). With the file gone that path fails
# and restore must fetch symbols from holders. Deleting while the daemon runs is
# the realistic case; the network keeps the data for the owner-delete cooldown.
assert_delete_window "$TIME_SCALE"
rm -f "$FILE"
if wait_file_deleted 0 "$FILE" 30; then
    pass "owner registered the local delete"
else
    fail "owner did not register the local delete within 30s"
fi

BLOCK_V2=$(file_block_hex 0 "$FILE")
SERVED_BEFORE=$(restore_responses_for "$BLOCK_V2" $(seq 1 $((NUM_NODES-1))))

# restore-i6 guard. The removed holder gate refused a block when
#   sum(total_bytes of the owner's holdings) * age_days_scaled / 7  <  c * SYMBOL_SIZE
# (c = ESIs of this block on the holder, SYMBOL_SIZE = 65535). An upper bound for the
# left side on holder h: B_h = max(status.holding_bytes, du of holdings/) (all owners,
# all statuses) aged since daemon start. So the gate refused EVERY holder of the block
# while  elapsed < min_h (7 days / TIME_SCALE) * c_h * 65535 / B_h.
GATE_BOUND=""
for i in $(seq 1 $((NUM_NODES-1))); do
    c=$(block_symbols_on "$i" "$BLOCK_V2")
    [ "$c" -gt 0 ] || continue
    b_api=$(status_num "$i" holding_bytes)
    b_du=$(du -sb "$(node_dir "$i")/holdings" 2>/dev/null | cut -f1 || echo 0)
    b=$(( b_api > b_du ? b_api : b_du ))
    [ "$b" -gt 0 ] || continue
    bound=$(awk -v c="$c" -v b="$b" -v ts="$TIME_SCALE" 'BEGIN { printf "%d", 7*86400/ts * c*65535 / b }')
    echo "  holder node-$(printf '%02d' "$i"): ${c} symbols of the block, ${b} bytes held -> old gate refuses for ${bound}s"
    if [ -z "$GATE_BOUND" ] || [ "$bound" -lt "$GATE_BOUND" ]; then GATE_BOUND=$bound; fi
done

if restore_from_network 0 "$FILE" "$HASH_V2" 120; then
    pass "restore from network: $RESTORE_MSG"
else
    fail "restore from network: $RESTORE_MSG"
fi
ELAPSED_I6=$(( $(date +%s) - T_DAEMONS ))
if [ -z "$GATE_BOUND" ]; then
    fail "restore-i6 guard: no holder of block ${BLOCK_V2:-none} to compute the gate bound"
elif [ "$ELAPSED_I6" -lt "$GATE_BOUND" ]; then
    pass "restore-i6: restored ${ELAPSED_I6}s after daemon start < ${GATE_BOUND}s, while the removed escrow gate would have refused every holder"
else
    fail "restore-i6 not checked: restore finished ${ELAPSED_I6}s after daemon start >= ${GATE_BOUND}s, the old gate could have passed"
fi
SERVED=$(( $(restore_responses_for "$BLOCK_V2" $(seq 1 $((NUM_NODES-1)))) - SERVED_BEFORE ))
if [ -n "$BLOCK_V2" ] && [ "$SERVED" -ge 1 ]; then
    pass "holders logged ${SERVED} RestoreResponse(s) for block ${BLOCK_V2:0:16}.."
else
    fail "no holder logged a RestoreResponse for block ${BLOCK_V2:-none}"
fi

# ── INFO: timing-dependent signals (not verdicts) ───────────────
echo ""
echo "=== Info (not verdicts: timing-dependent at time_scale=${TIME_SCALE}) ==="
info "node-00 avg_trust=$(status_num 0 avg_trust)"
info "node-00 PoS challenges=$(status_num 0 pos_total_challenges) passes=$(status_num 0 pos_total_passes)"
for i in $(seq 1 $((NUM_NODES-1))); do
    info "node-$(printf '%02d' "$i") mailbox_entries=$(api_get "$i" /api/status | jq -r '.table_stats.mailbox_entries // 0' 2>/dev/null || echo 0)"
done

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
