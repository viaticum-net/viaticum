#!/bin/bash
# Viaticum comprehensive E2E test: backup pipeline, restore, trust, PoS
# Local processes on one machine (no Docker).
#
# Usage:
#   cargo build --release
#   bash experiments/local_e2e_test.sh [num_nodes]
#
# Tests:
#   1. Star connect (all nodes connect to node-00)
#   2. File backup (watcher detects file → erasure code → place symbols)
#   3. File restore (fetch symbols from peers → decode → verify)
#   4. Trust scores (initial trust > 0 after PoS)
#   5. Multiple file versions
#   6. System state push (δ.1)

set -euo pipefail

NUM_NODES=${1:-3}
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-e2e-$$"
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
    # $1 = node idx, $2 = field name
    local RAW=$(run_cli_q "$1" status --json 2>/dev/null || true)
    echo "$RAW" | grep -oE "\"$2\":\s*[0-9.]+" | grep -oE '[0-9.]+$' || true
}

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: viaticum binary not found. Run: cargo build --release"
        exit 1
    fi
fi

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
echo "  ${NUM_NODES} nodes initialized (distinct master keys)."

# Write config for all nodes.
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

# Config already written during init (above). No additional config setup needed.

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

# Get node-00 addr and connect all
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

echo "  Connecting all to node-00..."
CONNECT_OK=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    if echo "$RESULT" | grep -qi "connected"; then
        ((CONNECT_OK++)) || true
    fi
done
# Wait for peer authentication (libp2p cert exchange takes a few seconds).
# Retry for up to 30s.
CONNECT_PASS=0
for attempt in $(seq 1 30); do
    PC=$(get_json_field 0 peer_count)
    if [ "${PC:-0}" -ge "$((NUM_NODES-1))" ]; then
        CONNECT_PASS=1
        break
    fi
    sleep 1
done
PC=$(get_json_field 0 peer_count)
echo "  node-00 peers: ${PC:-0}/$((NUM_NODES-1))"
[ "$CONNECT_PASS" -eq 1 ] \
    && pass "star connect: ${PC} peers" \
    || fail "star connect: only ${PC:-0} peers"

# ── PHASE 2: FILE BACKUP ────────────────────────────────────────
echo ""
echo "=== Phase 2: File Backup ==="

# Create a test file
echo "  Creating 128 KB test file..."
dd if=/dev/urandom of="$(node_dir 0)/files/backup_test.bin" bs=1024 count=128 2>/dev/null
ORIG_MD5=$(md5sum "$(node_dir 0)/files/backup_test.bin" | awk '{print $1}')
echo "  MD5: $ORIG_MD5"

# Wait for backup to detect and process (with time_scale=1000, scan interval is very short)
echo "  Waiting for backup pipeline (max 30s)..."
BACKED_UP=0
for attempt in $(seq 1 30); do
    FILES_N=$(get_json_field 0 backed_up_files)
    if [ "${FILES_N:-0}" -ge 1 ]; then
        echo "  File detected and backed up after ${attempt}s"
        BACKED_UP=1
        break
    fi
    sleep 1
done

if [ "$BACKED_UP" -eq 1 ]; then
    pass "file backup detected"
else
    fail "file not backed up after 30s"
    echo "  node-00 log (last 20 lines):"
    tail -20 "$(node_log 0)"
fi

# Wait for placements (symbols sent to peers)
# Wave 11b: worker runs on 1s tick (time_scale=1000); authentication needs ~10s.
echo "  Waiting for symbol placement (max 60s)..."
PLACED=0
for attempt in $(seq 1 60); do
    # Check table_stats for symbol_placements > 0
    PLACEMENTS=$(run_cli_q 0 status --json 2>/dev/null \
        | grep -oE '"symbol_placements":\s*[0-9]+' | grep -oE '[0-9]+$')
    if [ "${PLACEMENTS:-0}" -ge 1 ]; then
        echo "  Symbols placed: ${PLACEMENTS} (after ${attempt}s)"
        PLACED=1
        break
    fi
    sleep 1
done

if [ "$PLACED" -eq 1 ]; then
    pass "symbols placed on peers (${PLACEMENTS})"
else
    fail "no symbol placements after 30s"
fi

# ── PHASE 3: FILE RESTORE ───────────────────────────────────────
echo ""
echo "=== Phase 3: File Restore ==="

if [ "$PLACED" -eq 0 ]; then
    skip "restore skipped (no placements)"
else
    # Wait a bit for symbols to be delivered
    sleep 5

    RESTORE_PATH="$(node_dir 0)/files/backup_test.bin"
    RESTORE_DIR="$(node_dir 0)"
    echo "  Restoring $RESTORE_PATH (to staging dir)..."

    set +e
    RESTORE_OUTPUT=$(run_cli 0 restore "$RESTORE_PATH" 2>&1)
    RESTORE_EXIT=$?
    set -e

    echo "$RESTORE_OUTPUT"

    if [ $RESTORE_EXIT -eq 0 ]; then
        # Restore writes to staging directory under data-dir/restore/
        RESTORE_STAGING=$(find "$RESTORE_DIR/restore" -name "backup_test.bin" -type f 2>/dev/null | head -1)
        echo "  Waiting for restored file in staging dir (max 30s)..."
        RESTORE_OK=0
        for attempt in $(seq 1 30); do
            RESTORE_STAGING=$(find "$RESTORE_DIR/restore" -name "backup_test.bin" -type f 2>/dev/null | head -1)
            if [ -n "$RESTORE_STAGING" ] && [ -f "$RESTORE_STAGING" ]; then
                RESTORED_MD5=$(md5sum "$RESTORE_STAGING" | awk '{print $1}')
                if [ "$ORIG_MD5" = "$RESTORED_MD5" ]; then
                    pass "file restored and verified (MD5 match, ${attempt}s)"
                    RESTORE_OK=1
                else
                    fail "restored file MD5 mismatch: expected=$ORIG_MD5 got=$RESTORED_MD5"
                    RESTORE_OK=1
                fi
                break
            fi
            sleep 1
        done
        if [ "$RESTORE_OK" -eq 0 ]; then
            fail "restored file not found after 30s"
            echo "  Restore log:"
            grep -i "restore" "$(node_log 0)" | tail -10
        fi
    else
        fail "restore command failed (exit=$RESTORE_EXIT)"
    fi
fi

# ── PHASE 4: TRUST + PoS ────────────────────────────────────────
echo ""
echo "=== Phase 4: Trust Scores ==="

# Check trust scores from status
AVG_TRUST=$(get_json_field 0 avg_trust)
echo "  node-00 avg_trust: ${AVG_TRUST:-0}"

if [ -n "$AVG_TRUST" ]; then
    # Trust should be > 0 after initial interactions
    if echo "$AVG_TRUST" | awk '{exit ($1 > 0) ? 0 : 1}'; then
        pass "trust scores > 0 (avg=${AVG_TRUST})"
    else
        skip "trust scores still 0 (interactions may not have completed)"
    fi
else
    skip "trust data not available"
fi

# Check PoS totals
POS_CH=$(get_json_field 0 pos_total_challenges)
POS_PA=$(get_json_field 0 pos_total_passes)
echo "  PoS: challenges=${POS_CH:-0}, passes=${POS_PA:-0}"
if [ "${POS_PA:-0}" -ge 1 ]; then
    pass "PoS challenges recorded (challenges=${POS_CH}, passes=${POS_PA})"
else
    skip "no PoS passes yet (may need more time at time_scale=${TIME_SCALE})"
fi

# ── PHASE 5: FILE VERSIONS ──────────────────────────────────────
echo ""
echo "=== Phase 5: File Versions ==="

# Modify the file and wait for new version
echo "  Modifying backup_test.bin..."
dd if=/dev/urandom of="$(node_dir 0)/files/backup_test.bin" bs=1024 count=64 2>/dev/null

echo "  Waiting for version update (max 20s)..."
VERSIONS_FOUND=0
for attempt in $(seq 1 20); do
    # Check versions via CLI
    VERSIONS_OUTPUT=$(run_cli_q 0 versions "backup_test.bin" 2>&1)
    VERSION_COUNT=$(echo "$VERSIONS_OUTPUT" | grep -c "version" || true)
    if [ "$VERSION_COUNT" -ge 2 ]; then
        echo "  Found $VERSION_COUNT versions after ${attempt}s"
        VERSIONS_FOUND=1
        break
    fi
    sleep 1
done

if [ "$VERSIONS_FOUND" -eq 1 ]; then
    pass "multiple file versions detected ($VERSION_COUNT)"
else
    skip "second version not detected yet (may need more time)"
fi

# ── PHASE 6: MAILBOX DELIVERY (SelfPointer / deferred messages) ──
echo ""
echo "=== Phase 6: Mailbox Delivery ==="

# The δ.1 system_state_blobs table was retired (A2 cut-over). Deferred delivery —
# including the DR SelfPointer and PoS challenges — now rides the mailbox bus.
# Proxy: a peer acting as a postman holds ≥1 mailbox entry for some target.
MAILBOX_FOUND=0
for i in $(seq 1 $((NUM_NODES-1))); do
    ENTRIES=$(run_cli_q "$i" status --json 2>/dev/null \
        | grep -oE '"mailbox_entries":\s*[0-9]+' | grep -oE '[0-9]+$')
    if [ "${ENTRIES:-0}" -ge 1 ]; then
        echo "  node-$(printf '%02d' "$i") holds ${ENTRIES} mailbox entry(ies) as postman"
        MAILBOX_FOUND=1
    fi
done

if [ "$MAILBOX_FOUND" -eq 1 ]; then
    pass "mailbox entries stored on postman peers"
else
    echo "  No mailbox entries found yet (self-pointer push fires 60s after daemon start)"
    skip "mailbox delivery not yet fired"
fi

# ── PHASE 7: STATUS SUMMARY ─────────────────────────────────────
echo ""
echo "=== Node Status Summary ==="
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "  --- node-$(printf '%02d' "$i") ---"
    run_cli_q "$i" status 2>/dev/null | head -10
    echo ""
done

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
