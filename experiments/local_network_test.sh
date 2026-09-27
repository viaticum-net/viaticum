#!/bin/bash
# Viaticum network resilience E2E: graceful shutdown, reconnection after restart,
# placement onto the restarted peer, stop during startup.
#
# Scenario: 3 independent owners, star-connected to node-00. node-02 gets SIGTERM
#   right after its first peer record is written, is restarted with its data dir
#   (new random listen port) and must come back into the network on its own; then
#   node-00 backs up a file. Finally a second daemon is launched on the data dir
#   of the running node-01: it waits for the db lock and is SIGTERMed there.
# Intent: network-i1, network-i2, network-i6 (private/intent/network.md).
# Proves: SIGTERM ends the daemon promptly with exit status 0, no panic, and a
#   clean database close (`shutdown complete`; the next start of the SAME db does
#   not log `redb: repair in progress`) (network-i1, NET-14); the restarted node
#   dials its known peers itself (`auto-dial pass` with known_peers >= 1,
#   no_addrs = 0, dialed >= 1) and node-00 re-authenticates it WITHOUT a manual
#   `connect` (network-i2, NET-09); a file backed up afterwards lands on the
#   restarted node's disk (it is back in the placement pool); a SIGTERM that
#   arrives while the start is still in progress (blocked on the db lock) aborts
#   the start with status 0 and `during startup, aborting start`, and the running
#   instance on that data dir is not disturbed (network-i6).
# Adversarial: SIGTERM as soon as node-02's own db holds a peer record (the
#   address written with the first contact may be the only one it has) + restart
#   on a new random listen port; SIGTERM to a start that is provably unfinished
#   (it logged `db locked, retrying`), not a timing guess.
# Cannot close: backoff timing under repeated failures; connection reuse (NET-05 is
#   printed as INFO only: log lines cannot tell reuse from a fresh handshake); NAT or
#   address change of the node that stays up; a second signal during the drain
#   (exit 1, unit-level); a task stuck past the 10 s drain (unit-level:
#   wait_with_deadline_reports_timeout_when_task_hangs).
# Caveat (N8): if step 2 falls back to a manual `connect`, step 3's PASS proves only
#   placement after a manual link — it is NOT evidence for network-i2.
# Steps: 1. precondition: node-02's own db knows >= 1 peer (poll /api/status
#             peer_count; FAIL = outside this slice), then SIGTERM node-02 -> exits
#             within 15 s, status 0, `shutdown complete`, no panic (network-i1) —
#             check: wait + $?, grep its log
#        2. restart node-02 -> no `redb: repair in progress` among the lines of
#             THIS start (network-i1); node-00 re-authenticates it without
#             `connect` within 75 s (network-i2); node-02's first `auto-dial pass`
#             line has known_peers >= 1, no_addrs = 0, dialed >= 1, each checked
#             separately (network-i2) — check: log lines after the pre-restart
#             count, wait_auth_peers on node-00; precondition: after the stop
#             node-00 drops to NUM_NODES-2 authenticated peers within 10 s (else
#             NET-09 could pass on a link that never went away)
#        3. backup on node-00 -> restorable; node-02's disk holds symbols of the block
#             (network-i2) — check: wait_file_restorable, block_symbols_on node-02
#        4. launch a second daemon on node-01's data dir while node-01 runs ->
#             wait (<= 20 s, else FAIL setup) for `db locked, retrying` in its own
#             log, SIGTERM it -> exit within 15 s, status 0, `during startup,
#             aborting start` + `shutdown complete`; node-01 still answers status
#             and node-00 still sees 2 authenticated peers (network-i6) — check:
#             $?, duplicate.log, status on node-01, wait_auth_peers on node-00
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
NODE_NAME="node-$(printf '%02d' $NODE_TO_STOP)"
STOP_PID=${PIDS[$NODE_TO_STOP]}

# Precondition of the adversarial step: the node to be stopped must itself know a
# peer in its own db. Poll fast so the SIGTERM lands right after the record is
# written (its address may not be complete yet — that is the point).
KNOWN=0
for _ in $(seq 1 150); do
    KNOWN=$(status_num "$NODE_TO_STOP" peer_count)
    [ "$KNOWN" -ge 1 ] && break
    sleep 0.2
done
if [ "$KNOWN" -ge 1 ]; then
    info "precondition: $NODE_NAME db knows $KNOWN peer(s)"
else
    fail "precondition: $NODE_NAME db knows no peer after 30s (outside this slice: first contact never persisted)"
fi

echo "  Sending SIGTERM to $NODE_NAME (PID $STOP_PID)..."
kill "$STOP_PID" 2>/dev/null || true
if wait_pid_exit "$STOP_PID" 15; then
    if [ "$EXIT_RC" -eq 0 ]; then
        pass "NET-14: exited within 15s with status 0"
    else
        fail "NET-14: exited with status $EXIT_RC after SIGTERM (not a clean shutdown)"
    fi
else
    fail "NET-14: still running 15s after SIGTERM"
    kill -9 "$STOP_PID" 2>/dev/null || true
fi
if log_since "$NODE_TO_STOP" 0 | grep -q "shutdown complete"; then
    pass "NET-14: 'shutdown complete' in the log"
else
    fail "NET-14: no 'shutdown complete' in the $NODE_NAME log"
    log_since "$NODE_TO_STOP" 0 | grep -aiE "shutting down|abandoned|failed" | tail -5 || true
fi
# node-00 must drop the old connection first, otherwise NET-09 below could pass
# on a link that never went away.
RELEASED=0
for _ in $(seq 1 50); do
    [ "$(status_num 0 peer_count_authenticated)" -eq $((NUM_NODES-2)) ] && { RELEASED=1; break; }
    sleep 0.2
done
if [ "$RELEASED" -eq 1 ]; then
    pass "NET-09 precondition: node-00 released the old connection ($((NUM_NODES-2)) authenticated peers)"
else
    fail "NET-09 precondition: node-00 did not release the old connection within 10s (auth peers: $(status_num 0 peer_count_authenticated), want $((NUM_NODES-2)))"
fi
if grep -qai "panicked\|SIGSEGV\|SIGABRT" "$(node_log $NODE_TO_STOP)" 2>/dev/null; then
    fail "NET-14: panic in $NODE_NAME log"
    grep -ai "panicked" "$(node_log $NODE_TO_STOP)" | tail -5 || true
else
    pass "NET-14: no panic in the log"
fi

# ── PHASE 3: RECONNECTION AFTER RESTART (NET-09) ────────────────
echo ""
echo "=== Phase 3: Reconnection After Restart (NET-09) ==="

echo "  Restarting $NODE_NAME (no manual connect)..."
LINES_BEFORE_RESTART=$(log_line_count "$NODE_TO_STOP")
start_node "$NODE_TO_STOP"
wait_daemon "$NODE_TO_STOP" || fail "NET-09: $NODE_NAME failed to restart"

# redb logs this on every open of a file that was not closed cleanly (and always
# on a brand-new file, which is why only the lines of this start count).
if log_since "$NODE_TO_STOP" "$LINES_BEFORE_RESTART" | grep -q "redb: repair in progress"; then
    fail "network-i1: 'redb: repair in progress' on restart — the db was not closed cleanly"
else
    pass "network-i1: no redb repair on restart (db closed cleanly)"
fi

# The restarted node listens on a new port, so node-00 cannot redial its old address;
# the restarted node must dial the peers it knows. Redial runs at start and every
# max(300 s / time_scale, 30 s).
MANUAL_FALLBACK=0
T0=$(date +%s)
if wait_auth_peers 0 $((NUM_NODES-1)) 75; then
    pass "NET-09: node-00 re-authenticated the restarted peer on its own after $(( $(date +%s) - T0 ))s"
else
    fail "NET-09: no automatic reconnection within 75s (node-00 auth peers: $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)))"
    echo "  Falling back to a manual connect so the rest of the scenario can run..."
    MANUAL_FALLBACK=1
    run_cli_q "$NODE_TO_STOP" connect "$ADDR_00" > /dev/null
    if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
        info "manual connect restored the link"
    else
        fail "even a manual connect did not restore the link within 30s"
    fi
fi

# The first redial pass of this start. Its three counters fail for different
# reasons, so each is checked on its own: known_peers = 0 -> the peers table was
# lost; no_addrs > 0 -> a peer was stored without an address; dialed = 0 with
# addresses -> the dial path itself is broken.
PASS_LINE=""
for _ in $(seq 1 20); do
    PASS_LINE=$(log_since "$NODE_TO_STOP" "$LINES_BEFORE_RESTART" | grep -a "auto-dial pass" | head -1 || true)
    [ -n "$PASS_LINE" ] && break
    sleep 0.5
done
if [ -z "$PASS_LINE" ]; then
    fail "NET-09: no 'auto-dial pass' line after the restart (redial did not run, or it knew no peers)"
else
    info "first pass: $(echo "$PASS_LINE" | grep -oE 'auto-dial pass.*')"
    KP=$(log_field "$PASS_LINE" known_peers)
    NA=$(log_field "$PASS_LINE" no_addrs)
    DI=$(log_field "$PASS_LINE" dialed)
    if [ "${KP:-0}" -ge 1 ]; then
        pass "NET-09: auto-dial knows ${KP} peer(s) after the restart"
    else
        fail "NET-09: auto-dial known_peers=${KP:-missing} after the restart"
    fi
    if [ -n "$NA" ] && [ "$NA" -eq 0 ]; then
        pass "NET-09: every known peer has a stored address (no_addrs=0)"
    else
        fail "NET-09: no_addrs=${NA:-missing}: a peer was persisted without an address"
    fi
    if [ "${DI:-0}" -ge 1 ]; then
        pass "NET-09: auto-dial dialed ${DI} peer(s) on its own"
    else
        fail "NET-09: auto-dial dialed=${DI:-missing}"
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
N8_NOTE=""
[ "$MANUAL_FALLBACK" -eq 1 ] && N8_NOTE=" (after the manual-connect fallback: NOT evidence for network-i2)"
if [ "$N_RESTARTED" -gt 0 ]; then
    pass "restarted $NODE_NAME stores ${N_RESTARTED} symbols of the new block${N8_NOTE}"
else
    fail "restarted node-$(printf '%02d' $NODE_TO_STOP) stores no symbols of block ${BLOCK:-none} (not back in the placement pool)"
fi

# ── PHASE 5: STOP DURING STARTUP (network-i6) ───────────────────
echo ""
echo "=== Phase 5: Stop during startup (network-i6) ==="

# A second daemon on the data dir of the RUNNING node-01 cannot get the redb lock
# and waits in open_db_with_retry (`db locked, retrying`, up to ~60 s). That is a
# start that is deterministically still in progress when the SIGTERM arrives.
# Before the db open the start only reads identity.key and config.toml, so the
# second process cannot disturb node-01. Its output goes to a separate log.
NODE_B=1
NODE_B_NAME="node-$(printf '%02d' $NODE_B)"
B_PID=${PIDS[$NODE_B]}
DUP_LOG="$(node_dir "$NODE_B")/duplicate.log"
RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$NODE_B")" daemon \
    --time-scale "$TIME_SCALE" \
    --watch-dir "$(node_dir "$NODE_B")/files" \
    > "$DUP_LOG" 2>&1 &
DUP_PID=$!
PIDS+=("$DUP_PID")

DUP_WAITING=0
for _ in $(seq 1 100); do
    if sed 's/\x1b\[[0-9;]*m//g' "$DUP_LOG" 2>/dev/null | grep -q "db locked, retrying"; then
        DUP_WAITING=1
        break
    fi
    if ! kill -0 "$DUP_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if [ "$DUP_WAITING" -eq 1 ]; then
    echo "  second daemon on $NODE_B_NAME's data dir waits for the db lock; SIGTERM to PID $DUP_PID..."
    kill "$DUP_PID" 2>/dev/null || true
    if wait_pid_exit "$DUP_PID" 15; then
        if [ "$EXIT_RC" -eq 0 ]; then
            pass "network-i6: SIGTERM while the start waits for the db lock -> status 0"
        else
            fail "network-i6: SIGTERM while the start waits for the db lock -> status $EXIT_RC"
        fi
    else
        fail "network-i6: still running 15s after a SIGTERM during startup"
        kill -9 "$DUP_PID" 2>/dev/null || true
    fi
    DUP_CLEAN=$(sed 's/\x1b\[[0-9;]*m//g' "$DUP_LOG" 2>/dev/null || true)
    if echo "$DUP_CLEAN" | grep -q "during startup, aborting start" \
        && echo "$DUP_CLEAN" | grep -q "shutdown complete"; then
        pass "network-i6: 'received SIGTERM during startup, aborting start' + 'shutdown complete'"
    else
        fail "network-i6: no 'during startup, aborting start' / 'shutdown complete' in $DUP_LOG"
        tail -5 "$DUP_LOG" 2>/dev/null || true
    fi
elif ! kill -0 "$DUP_PID" 2>/dev/null; then
    wait "$DUP_PID" 2>/dev/null && DUP_RC=0 || DUP_RC=$?
    fail "network-i6 setup: the second daemon exited (status $DUP_RC) before reaching the db lock"
    tail -5 "$DUP_LOG" 2>/dev/null || true
else
    fail "network-i6 setup: no 'db locked, retrying' from the second daemon within 20s"
    tail -5 "$DUP_LOG" 2>/dev/null || true
    kill -9 "$DUP_PID" 2>/dev/null || true
fi

# The running node-01 must be untouched by the aborted second start.
if kill -0 "$B_PID" 2>/dev/null && run_cli_q "$NODE_B" status 2>/dev/null | grep -q "identity:"; then
    pass "network-i6: $NODE_B_NAME (PID $B_PID) still running and answering status"
else
    fail "network-i6: $NODE_B_NAME stopped answering after the aborted second start"
fi
if wait_auth_peers 0 $((NUM_NODES-1)) 10; then
    pass "network-i6: node-00 still sees $((NUM_NODES-1)) authenticated peers"
else
    fail "network-i6: node-00 auth peers $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) after the aborted second start"
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
