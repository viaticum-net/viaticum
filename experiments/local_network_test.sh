#!/bin/bash
# Viaticum network resilience E2E: graceful shutdown, reconnection after restart,
# placement onto the restarted peer.
#
# Scenario: 3 independent owners, star-connected to node-00. node-02 gets SIGTERM, is
#   restarted with its data dir (new random listen port), and must come back into the
#   network on its own; then node-00 backs up a file.
# Intent: network-i1, network-i2 (file pending; proposed ids: network-i1 = SIGTERM
#   ends the daemon cleanly with exit 0, network-i2 = after a restart the node returns
#   to the network on its own). Both currently FAIL (baseline 09-26: SIGTERM exit 143,
#   no automatic redial), product bugs.
# Proves: SIGTERM ends the daemon promptly with exit status 0 and no panic (NET-14);
#   the restarted node is re-authenticated by node-00 WITHOUT a manual `connect`
#   (NET-09: auto-dial of known peers); a file backed up afterwards lands on the
#   restarted node's disk (it is back in the placement pool).
# Adversarial: SIGTERM + restart on a new random listen port.
# Cannot close: backoff timing under repeated failures; connection reuse (NET-05 is
#   printed as INFO only: log lines cannot tell reuse from a fresh handshake); NAT or
#   address change of the node that stays up.
# Steps: 1. SIGTERM node-02 -> exits within 15 s, status 0, no panic (network-i1) —
#             check: wait + $?, grep panic in its log
#        2. restart node-02 -> node-00 re-authenticates it without `connect` within
#             75 s (network-i2) — check: wait_auth_peers on node-00
#        3. backup on node-00 -> restorable; node-02's disk holds symbols of the block
#             (network-i2) — check: wait_file_restorable, block_symbols_on node-02
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_network_test.sh

set -euo pipefail

NUM_NODES=3
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-net-$$"
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

start_node() {
    local i="$1"
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        >> "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
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
echo "  Viaticum Network Resilience Test (${NUM_NODES} nodes)"
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

# Set disk_reserve_gb=0 so tests work on low-disk machines.
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
    start_node "$i"
done

READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then
        ((READY++)) || true
    fi
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

# ── PHASE 2: GRACEFUL SHUTDOWN (NET-14) ──────────────────────────
echo ""
echo "=== Phase 2: Graceful Shutdown (NET-14) ==="

NODE_TO_STOP=2
STOP_PID=${PIDS[$NODE_TO_STOP]}
echo "  Sending SIGTERM to node-$(printf '%02d' $NODE_TO_STOP) (PID $STOP_PID)..."
kill "$STOP_PID" 2>/dev/null || true
EXITED=0
for _ in $(seq 1 30); do
    kill -0 "$STOP_PID" 2>/dev/null || { EXITED=1; break; }
    sleep 0.5
done
if [ "$EXITED" -eq 1 ]; then
    set +e; wait "$STOP_PID" 2>/dev/null; RC=$?; set -e
    if [ "$RC" -eq 0 ]; then
        pass "NET-14: exited within 15s with status 0"
    else
        fail "NET-14: exited with status $RC after SIGTERM (not a clean shutdown)"
    fi
else
    fail "NET-14: still running 15s after SIGTERM"
    kill -9 "$STOP_PID" 2>/dev/null || true
fi
if grep -qai "panicked\|SIGSEGV\|SIGABRT" "$(node_log $NODE_TO_STOP)" 2>/dev/null; then
    fail "NET-14: panic in node-$(printf '%02d' $NODE_TO_STOP) log"
    grep -ai "panicked" "$(node_log $NODE_TO_STOP)" | tail -5 || true
else
    pass "NET-14: no panic in the log"
fi

# ── PHASE 3: RECONNECTION AFTER RESTART (NET-09) ────────────────
echo ""
echo "=== Phase 3: Reconnection After Restart (NET-09) ==="

echo "  Restarting node-$(printf '%02d' $NODE_TO_STOP) (no manual connect)..."
start_node "$NODE_TO_STOP"
wait_daemon "$NODE_TO_STOP" || fail "NET-09: node-$(printf '%02d' $NODE_TO_STOP) failed to restart"

# The restarted node listens on a new port, so node-00 cannot redial its old address;
# the restarted node must dial the peers it knows. Redial runs at start and every
# max(300 s / time_scale, 30 s).
T0=$(date +%s)
if wait_auth_peers 0 $((NUM_NODES-1)) 75; then
    pass "NET-09: node-00 re-authenticated the restarted peer on its own after $(( $(date +%s) - T0 ))s"
else
    fail "NET-09: no automatic reconnection within 75s (node-00 auth peers: $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)))"
    sed 's/\x1b\[[0-9;]*m//g' "$(node_log $NODE_TO_STOP)" | grep -a "auto-dial" | tail -3 || true
    echo "  Falling back to a manual connect so the rest of the scenario can run..."
    run_cli_q "$NODE_TO_STOP" connect "$ADDR_00" > /dev/null
    if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
        info "manual connect restored the link"
    else
        fail "even a manual connect did not restore the link within 30s"
    fi
fi

# NET-05 (connection reuse) cannot be told apart from a fresh handshake by log
# lines; reported for the record only.
LINES_BEFORE=$(wc -l < "$(node_log 0)")
run_cli_q 1 connect "$ADDR_00" > /dev/null
sleep 2
NEW_HANDSHAKES=$(tail -n +$((LINES_BEFORE + 1)) "$(node_log 0)" | grep -ci "handshake" || true)
info "NET-05: ${NEW_HANDSHAKES} handshake log line(s) after a second connect of node-01"

# ── PHASE 4: BACKUP LANDS ON THE RESTARTED PEER ─────────────────
echo ""
echo "=== Phase 4: Backup after the restart ==="

FILE="$(node_dir 0)/files/net_test.bin"
dd if=/dev/urandom of="$FILE" bs=1024 count=128 2>/dev/null
if wait_file_restorable 0 "$FILE" 60; then
    pass "file restorable per owner after the restart"
else
    fail "file not restorable per owner 60s after the restart"
fi
BLOCK=$(file_block_hex 0 "$FILE")
N_RESTARTED=0
for _ in $(seq 1 30); do
    N_RESTARTED=$(block_symbols_on "$NODE_TO_STOP" "$BLOCK")
    [ "$N_RESTARTED" -gt 0 ] && break
    sleep 1
done
if [ "$N_RESTARTED" -gt 0 ]; then
    pass "restarted node-$(printf '%02d' $NODE_TO_STOP) stores ${N_RESTARTED} symbols of the new block"
else
    fail "restarted node-$(printf '%02d' $NODE_TO_STOP) stores no symbols of block ${BLOCK:-none} (not back in the placement pool)"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    for i in $(seq 0 $((NUM_NODES-1))); do
        echo "=== node-$(printf '%02d' "$i") log (last 10 lines) ==="
        tail -10 "$(node_log "$i")" 2>/dev/null
        echo ""
    done
fi

echo "Logs: $TEST_DIR/node-*/daemon.log"
[ "$FAIL" -eq 0 ]
