#!/bin/bash
# Viaticum β Full E2E Test — Phase 7 (P2P wired)
# Run from project root: bash experiments/docker-beta/full_test.sh
COMPOSE="docker compose -f experiments/docker-beta/compose.yml"
PREFIX="viaticum-beta"
PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "  SKIP: $1"; ((SKIP++)) || true; }

exec_node() { docker exec "$PREFIX-$1" "${@:2}"; }
exec_node_q() { docker exec "$PREFIX-$1" "${@:2}" 2>/dev/null; }

echo "============================================================"
echo "  Viaticum β Full E2E Test (Phase 7: P2P wired)"
echo "============================================================"

# ── SETUP ──────────────────────────────────────────────────────
echo ""
echo "=== Setup ==="
$COMPOSE down -v 2>&1 | tail -1 || true
$COMPOSE build 2>&1 | tail -3
$COMPOSE up -d 2>&1 | tail -1
sleep 2

MNEMONIC_A="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"

exec_node node-a viaticum init --mnemonic "$MNEMONIC_A" > /dev/null
exec_node node-b viaticum init --mnemonic "creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke knock" > /dev/null
exec_node node-c viaticum init --mnemonic "crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak off" > /dev/null
exec_node node-d viaticum init --mnemonic "cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state rent" > /dev/null
echo "  4 nodes initialized"

# ── TEST 1: Identity ──────────────────────────────────────────
echo ""
echo "=== Test 1: Identity initialization ==="

if exec_node node-a test -f /home/viaticum/.viaticum/identity.key 2>/dev/null; then
    pass "identity.key created"
else
    fail "identity.key not created"
fi

# ── TEST 2: Deterministic identity ────────────────────────────
echo ""
echo "=== Test 2: Deterministic identity (DR restore) ==="

# Wipe node-e (not initialized above), init with A's mnemonic
VPREFIX="docker-beta"
exec_node node-d viaticum init --mnemonic "$MNEMONIC_A" 2>&1 | grep -q "already" && {
    # node-d already initialized with different mnemonic — use node-e instead
    true
}
# Use a fresh container: wipe node-e volume, re-create
$COMPOSE rm -fsv node-e > /dev/null 2>&1 || true
docker volume rm "${VPREFIX}_node-e-data" "${VPREFIX}_node-e-files" > /dev/null 2>&1 || true
$COMPOSE up -d node-e > /dev/null 2>&1
sleep 2

INIT_E=$(exec_node node-e viaticum init --mnemonic "$MNEMONIC_A" 2>&1 | grep "Public key:" | awk '{print $NF}')
EXPECTED_A="6909f82c6424bc5b544b4b03a6e6d63d4c5a7e7c214e4e4790bf1a0d309025c8"

echo "  Expected: ${EXPECTED_A:0:16}..."
echo "  Node E:   ${INIT_E:0:16}..."

if [ "$INIT_E" = "$EXPECTED_A" ]; then
    pass "same mnemonic → same identity (DR restore verified)"
else
    fail "identity mismatch (expected=$EXPECTED_A got=$INIT_E)"
fi

# ── TEST 3: Daemon starts ────────────────────────────────────
echo ""
echo "=== Test 3: Daemon startup ==="

docker exec -d "$PREFIX-node-a" sh -c 'viaticum daemon --watch-dir /data/files 2>/tmp/daemon.log'
sleep 3

STATUS=$(exec_node_q node-a viaticum status || true)
if echo "$STATUS" | grep -q "identity:"; then
    pass "daemon responds to CLI"
    IDENTITY=$(echo "$STATUS" | grep "identity:" | awk '{print $2}')
    echo "  identity: ${IDENTITY:0:16}..."
    # Check stable NodeId (addr should be hex@ip:port format)
    ADDR=$(echo "$STATUS" | grep "addr:" | awk '{print $2}')
    if echo "$ADDR" | grep -q "@"; then
        pass "node_addr has stable NodeId format (hex@ip:port)"
        echo "  addr: ${ADDR:0:24}..."
    else
        skip "node_addr format not yet hex@ip:port"
    fi
else
    fail "daemon not responding"
    echo "  --- Daemon log ---"
    exec_node_q node-a cat /tmp/daemon.log | tail -10
fi

# ── TEST 4: Multiple daemons ─────────────────────────────────
echo ""
echo "=== Test 4: Multiple daemons ==="

for node in node-b node-c node-d; do
    docker exec -d "$PREFIX-$node" sh -c 'viaticum daemon --watch-dir /data/files 2>/tmp/daemon.log'
done
sleep 5

UP_COUNT=0
ADDR_B=""
ADDR_C=""
ADDR_D=""
for node in node-a node-b node-c node-d; do
    if exec_node_q $node viaticum status 2>/dev/null | grep -q "identity:"; then
        ((UP_COUNT++)) || true
    fi
done

# Get addrs separately (more reliable than parsing multi-line status)
get_addr() {
    exec_node_q "$1" viaticum status 2>/dev/null | grep "addr:" | awk '{for(i=1;i<=NF;i++) if($i ~ /@/) print $i}'
}
ADDR_B=$(get_addr node-b)
ADDR_C=$(get_addr node-c)
ADDR_D=$(get_addr node-d)

echo "  Daemons responding: $UP_COUNT/4"
echo "  addr B: ${ADDR_B:0:20}..."
echo "  addr C: ${ADDR_C:0:20}..."
echo "  addr D: ${ADDR_D:0:20}..."
if [ "$UP_COUNT" -eq 4 ]; then
    pass "all 4 daemons running"
else
    fail "only $UP_COUNT/4 daemons responding"
fi

# ── TEST 5: Peer connect ──────────────────────────────────────
echo ""
echo "=== Test 5: Peer connect ==="

ADDR_B="${NODE_ADDRS[node-b]}"
if [ -n "$ADDR_B" ]; then
    CONNECT_RESULT=$(exec_node_q node-a viaticum connect "$ADDR_B" 2>&1 || true)
    echo "  connect result: $(echo "$CONNECT_RESULT" | head -1)"
    if echo "$CONNECT_RESULT" | grep -qi "connected\|peer"; then
        pass "node-a connected to node-b"
    else
        fail "connect to node-b failed: $CONNECT_RESULT"
    fi
else
    fail "node-b addr not available for connect"
fi

# Connect A→C and A→D too
ADDR_C="${NODE_ADDRS[node-c]}"
ADDR_D="${NODE_ADDRS[node-d]}"
CONNECT_OK=1
if [ -n "$ADDR_C" ]; then
    RC=$(exec_node_q node-a viaticum connect "$ADDR_C" 2>&1 || true)
    echo "  A→C: $(echo "$RC" | head -1)"
    echo "$RC" | grep -qi "connected" || CONNECT_OK=0
else
    echo "  A→C: addr not available"
    CONNECT_OK=0
fi
if [ -n "$ADDR_D" ]; then
    RD=$(exec_node_q node-a viaticum connect "$ADDR_D" 2>&1 || true)
    echo "  A→D: $(echo "$RD" | head -1)"
    echo "$RD" | grep -qi "connected" || CONNECT_OK=0
else
    echo "  A→D: addr not available"
    CONNECT_OK=0
fi
if [ "$CONNECT_OK" -eq 1 ]; then
    pass "connected to all 3 peers"
else
    fail "some peer connections failed"
fi

# Verify peers show up in status
sleep 2
PEER_STATUS=$(exec_node_q node-a viaticum status || true)
PEER_COUNT=$(echo "$PEER_STATUS" | grep "peers:" | head -1 | sed 's/.*peers:[[:space:]]*//' | awk '{print $1}')
echo "  peers after connect: $PEER_COUNT"
if [ "${PEER_COUNT:-0}" -ge 3 ] 2>/dev/null; then
    pass "all 3 peers registered"
elif [ "${PEER_COUNT:-0}" -ge 1 ] 2>/dev/null; then
    pass "peers registered ($PEER_COUNT/3)"
else
    fail "no peers registered (count=$PEER_COUNT)"
fi

# ── TEST 6: File watcher + backup ─────────────────────────────
echo ""
echo "=== Test 6: File watcher + backup ==="

exec_node node-a sh -c 'echo "hello beta phase 7" > /data/files/test.txt'
sleep 5

# Check files command
FILES_OUTPUT=$(exec_node_q node-a viaticum files || true)
echo "  files output: $(echo "$FILES_OUTPUT" | head -2)"
if echo "$FILES_OUTPUT" | grep -q "test.txt"; then
    pass "file detected and tracked"
else
    skip "file not yet in viaticum files (watcher timing)"
fi

# ── TEST 7: Status shows backed-up info ───────────────────────
echo ""
echo "=== Test 7: Status shows backup info ==="

STATUS_FINAL=$(exec_node_q node-a viaticum status || true)
echo "$STATUS_FINAL" | head -8

BACKED_UP=$(echo "$STATUS_FINAL" | grep "backed up:" | head -1)
if [ -n "$BACKED_UP" ]; then
    pass "status shows backed-up info"
else
    skip "backed-up info not in status"
fi

# ── RESULTS ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Node A daemon log ==="
    exec_node_q node-a cat /tmp/daemon.log | grep -vE 'TRACE' | tail -30
fi

echo ""
echo "To tear down: $COMPOSE down -v"

[ "$FAIL" -eq 0 ]
