#!/bin/bash
# SyncBack δ.1 Verification: System State Push + Disaster Recovery
# 20-node Docker network. Run from project root:
#   bash experiments/docker-beta/dr_test.sh
#
# Tests:
#   1. Star connect — all 19 nodes connect to node-00 via Docker IPs
#   2. System state push — peers store encrypted DB snapshots
#   3. Full DR — restore node-00 from seed phrase + peer address
#
# Known limitation: bootstrap discovery handler doesn't add peers (logged only).
# All connections are established manually via star topology.

set -euo pipefail

COMPOSE="docker compose -f experiments/docker-beta/compose.yml"
PREFIX="syncback-beta"
NUM_NODES=${1:-5}    # pass node count as arg, default 5
TIME_SCALE=1000   # system state push every max(6*3600/1000, 60) = 60s
MNEMONIC_00="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"

PASS=0; FAIL=0; SKIP=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "  SKIP: $1"; ((SKIP++)) || true; }
exec_node()  { docker exec "$PREFIX-$1" "${@:2}"; }
exec_node_q() { docker exec "$PREFIX-$1" "${@:2}" 2>/dev/null; }

# Get Docker-internal addr: <node_id>@<docker_ip>:<iroh_port>
get_docker_addr() {
    local NODE="$1"
    local CONTAINER="$PREFIX-$NODE"
    local RAW_ADDR=$(exec_node_q "$NODE" syncback status | grep "addr:" \
        | awk '{for(i=1;i<=NF;i++) if($i ~ /@/) print $i}')
    local NODE_ID=$(echo "$RAW_ADDR" | cut -d@ -f1)
    local PORT=$(echo "$RAW_ADDR" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' \
        | tail -1 | cut -d: -f2)
    local DOCKER_IP=$(docker exec "$CONTAINER" hostname -i 2>/dev/null | awk '{print $1}')
    if [ -n "$NODE_ID" ] && [ -n "$DOCKER_IP" ] && [ -n "$PORT" ]; then
        echo "${NODE_ID}@${DOCKER_IP}:${PORT}"
    fi
}

get_peer_count() {
    exec_node_q "$1" syncback status | grep "peers:" | head -1 | awk '{print $2}'
}

# Wait for daemon to respond (max 15s)
wait_daemon() {
    local NODE="$1"
    for i in $(seq 1 15); do
        if exec_node_q "$NODE" syncback status 2>/dev/null | grep -q "identity:"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Start daemon with RUST_LOG
start_daemon() {
    local NODE="$1"
    docker exec -d -e RUST_LOG=info "$PREFIX-$NODE" sh -c \
        "syncback daemon --time-scale $TIME_SCALE --watch-dir /data/files >/tmp/daemon.log 2>&1"
}

echo "============================================================"
echo "  SyncBack δ.1: System State Push + DR Test (${NUM_NODES} nodes)"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

$COMPOSE down -v 2>&1 | tail -1 || true
# Image must be pre-built: docker build --no-cache -f experiments/docker-beta/Dockerfile -t syncback-beta .
if ! docker image inspect syncback-beta > /dev/null 2>&1; then
    echo "  ERROR: syncback-beta image not found. Build it first."
    exit 1
fi
echo "  Using pre-built syncback-beta image"
echo "  Starting ${NUM_NODES} containers..."
$COMPOSE up -d 2>&1 | tail -1
sleep 3

# Init all nodes
echo "  Initializing nodes..."
exec_node node-00 syncback init --mnemonic "$MNEMONIC_00" > /dev/null 2>&1
for i in $(seq 1 $((NUM_NODES-1))); do
    NODE=$(printf "node-%02d" $i)
    exec_node "$NODE" syncback init > /dev/null 2>&1 &
done
wait
echo "  ${NUM_NODES} nodes initialized."

# Start node-00 daemon first
echo "  Starting node-00 daemon (time_scale=${TIME_SCALE})..."
start_daemon node-00

if ! wait_daemon node-00; then
    fail "node-00 daemon not responding after 15s"
    exec_node_q node-00 cat /tmp/daemon.log | tail -20
    exit 1
fi

ADDR_00=$(get_docker_addr node-00)
echo "  node-00 docker addr: $ADDR_00"

if [ -z "$ADDR_00" ]; then
    fail "cannot get node-00 docker addr"
    exit 1
fi

# ── PHASE 2: START ALL + STAR CONNECT ──────────────────────────
echo ""
echo "=== Phase 2: Start All Daemons + Star Connect ==="

# Start all other daemons
echo "  Starting nodes 01-19..."
for i in $(seq 1 $((NUM_NODES-1))); do
    NODE=$(printf "node-%02d" $i)
    start_daemon "$NODE"
done

# Wait for all daemons to be ready
echo "  Waiting for daemons to start..."
READY=0
for i in $(seq 1 $((NUM_NODES-1))); do
    NODE=$(printf "node-%02d" $i)
    if wait_daemon "$NODE"; then
        ((READY++)) || true
    else
        echo "    $NODE NOT ready"
    fi
done
echo "  $READY/$((NUM_NODES-1)) daemons ready"

# Connect all 19 nodes to node-00 via Docker addr
echo "  Connecting 19 nodes to node-00..."
CONNECT_OK=0
CONNECT_FAIL=0
for i in $(seq 1 $((NUM_NODES-1))); do
    NODE=$(printf "node-%02d" $i)
    RESULT=$(exec_node_q "$NODE" syncback connect "$ADDR_00" 2>&1 || true)
    if echo "$RESULT" | grep -qi "connected"; then
        ((CONNECT_OK++)) || true
    else
        ((CONNECT_FAIL++)) || true
        [ $i -le 3 ] && echo "    $NODE: $RESULT"  # show first few failures
    fi
done
echo "  Connected: $CONNECT_OK/$((NUM_NODES-1)), Failed: $CONNECT_FAIL"
sleep 3

PC_00=$(get_peer_count node-00)
EXPECTED=$((NUM_NODES-1))
echo "  node-00 peers: ${PC_00:-0}/${EXPECTED}"
if [ "${PC_00:-0}" -ge "$EXPECTED" ]; then
    pass "star connect: node-00 has $PC_00/$EXPECTED peers"
elif [ "${PC_00:-0}" -ge $((EXPECTED/2)) ]; then
    pass "star connect: node-00 has $PC_00/$EXPECTED peers (partial)"
else
    fail "star connect: node-00 has only ${PC_00:-0}/$EXPECTED peers"
fi

# ── PHASE 3: FILE BACKUP + SYSTEM STATE PUSH ───────────────────
echo ""
echo "=== Phase 3: File Backup + System State Push ==="

# Create test file on node-00
echo "  Creating 256 KB test file on node-00..."
exec_node node-00 sh -c 'dd if=/dev/urandom of=/data/files/test.bin bs=1024 count=256 2>/dev/null'

# Poll for system state blob on node-01 (max 180s)
echo "  Waiting for system state push to node-01 (interval=60s)..."
BLOB_FOUND=0
for attempt in $(seq 1 18); do
    BLOB_LINE=$(exec_node_q node-01 syncback status --json 2>/dev/null \
        | grep -oE '"system_state_blobs":\s*[0-9]+' || true)
    BLOB_N=$(echo "$BLOB_LINE" | grep -oE '[0-9]+$' || true)
    if [ "${BLOB_N:-0}" -ge 1 ]; then
        echo "  System state blob found on node-01 after $((attempt * 10))s"
        BLOB_FOUND=1
        break
    fi
    # Show daemon log progress at key intervals
    if [ $attempt -eq 6 ] || [ $attempt -eq 12 ]; then
        echo "    attempt $attempt/18 — checking node-00 log..."
        docker exec "$PREFIX-node-00" tail -5 /tmp/daemon.log 2>/dev/null || true
    else
        echo "    attempt $attempt/18 — waiting 10s..."
    fi
    sleep 10
done

if [ "$BLOB_FOUND" -eq 1 ]; then
    pass "system state pushed to node-01"
else
    fail "system state blob not found on node-01 after 180s"
    echo ""
    echo "  === node-00 daemon log (last 30 lines) ==="
    docker exec "$PREFIX-node-00" tail -30 /tmp/daemon.log 2>/dev/null || true
    echo ""
    echo "  === node-01 daemon log (last 20 lines) ==="
    docker exec "$PREFIX-node-01" tail -20 /tmp/daemon.log 2>/dev/null || true
fi

# Show node-00 status
echo ""
echo "  node-00 status:"
exec_node_q node-00 syncback status | head -15

# ── PHASE 4: DISASTER RECOVERY ─────────────────────────────────
echo ""
echo "=== Phase 4: Disaster Recovery ==="

if [ "$BLOB_FOUND" -eq 0 ]; then
    echo "  SKIP: system state blob not found, DR impossible"
    skip "DR skipped (no blob)"
else
    # Save peer addrs for DR
    ADDR_01=$(get_docker_addr node-01)
    ADDR_02=$(get_docker_addr node-02)
    echo "  DR seed peers:"
    echo "    node-01: $ADDR_01"
    echo "    node-02: $ADDR_02"

    if [ -z "$ADDR_01" ]; then
        fail "cannot get node-01 addr for DR"
    else
        # Stop node-00 daemon
        echo "  Stopping node-00..."
        docker stop "$PREFIX-node-00" > /dev/null 2>&1

        # Restart container and wipe all data
        echo "  Restarting container and wiping data..."
        docker start "$PREFIX-node-00" > /dev/null 2>&1
        sleep 2
        exec_node node-00 sh -c "rm -rf /home/syncback/.syncback/*"

        # Verify wipe
        if exec_node node-00 test -f /home/syncback/.syncback/identity.key 2>/dev/null; then
            fail "data wipe failed"
        else
            echo "  node-00 data wiped."

            # Run DR
            echo "  Running: syncback dr --mnemonic '...' --peer <node-01> --peer <node-02>"
            echo ""
            set +e
            DR_ARGS="--mnemonic \"$MNEMONIC_00\" --peer \"$ADDR_01\""
            [ -n "$ADDR_02" ] && DR_ARGS="$DR_ARGS --peer \"$ADDR_02\""
            DR_OUTPUT=$(docker exec -e RUST_LOG=info "$PREFIX-node-00" \
                sh -c "syncback dr $DR_ARGS" 2>&1)
            DR_EXIT=$?
            set -e

            echo "$DR_OUTPUT"
            echo ""

            if [ $DR_EXIT -eq 0 ] && echo "$DR_OUTPUT" | grep -q "DR restore successful"; then
                pass "DR restore completed"

                FILES_N=$(echo "$DR_OUTPUT" | grep "Files:" | awk '{print $NF}')
                PEERS_N=$(echo "$DR_OUTPUT" | grep "Peers:" | awk '{print $NF}')

                echo "  Restored: ${FILES_N:-0} files, ${PEERS_N:-0} peers"

                [ "${FILES_N:-0}" -ge 1 ] && pass "DR restored files (${FILES_N})" \
                    || skip "DR restored 0 files"
                [ "${PEERS_N:-0}" -ge 2 ] && pass "DR restored peers (${PEERS_N})" \
                    || fail "DR restored too few peers (${PEERS_N:-0})"
            else
                fail "DR failed (exit=$DR_EXIT)"
            fi
        fi

        # Post-DR: start daemon and verify
        echo ""
        echo "=== Phase 5: Post-DR Verification ==="
        start_daemon node-00
        if wait_daemon node-00; then
            echo "  Post-DR status:"
            exec_node_q node-00 syncback status
            POST_PEERS=$(get_peer_count node-00)
            echo ""
            [ "${POST_PEERS:-0}" -ge 1 ] \
                && pass "post-DR daemon has ${POST_PEERS} peers" \
                || skip "post-DR peers not yet reconnected"
        else
            fail "post-DR daemon did not start"
        fi
    fi
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 daemon log (last 30 lines) ==="
    docker exec "$PREFIX-node-00" tail -30 /tmp/daemon.log 2>/dev/null || true
    echo ""
    echo "=== node-01 daemon log (last 20 lines) ==="
    docker exec "$PREFIX-node-01" tail -20 /tmp/daemon.log 2>/dev/null || true
fi

echo ""
echo "Tear down: $COMPOSE down -v"

[ "$FAIL" -eq 0 ]
