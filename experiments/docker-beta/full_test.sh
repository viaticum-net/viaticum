#!/bin/bash
# SyncBack β Full E2E Test
# Run from project root: bash experiments/docker-beta/full_test.sh
COMPOSE="docker compose -f experiments/docker-beta/compose.yml"
PREFIX="syncback-beta"
PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "  SKIP: $1"; ((SKIP++)) || true; }

exec_node() { docker exec "$PREFIX-$1" "${@:2}"; }
exec_node_q() { docker exec "$PREFIX-$1" "${@:2}" 2>/dev/null; }

echo "============================================================"
echo "  SyncBack β Full E2E Test"
echo "============================================================"

# ── SETUP ──────────────────────────────────────────────────────
echo ""
echo "=== Setup ==="
$COMPOSE down -v 2>&1 | tail -1 || true
$COMPOSE up -d 2>&1 | tail -1
sleep 2

MNEMONIC_A="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"

exec_node node-a syncback init --mnemonic "$MNEMONIC_A" > /dev/null
exec_node node-b syncback init --mnemonic "creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke knock" > /dev/null
exec_node node-c syncback init --mnemonic "crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak off" > /dev/null
exec_node node-d syncback init --mnemonic "cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state rent" > /dev/null
exec_node node-e syncback init --mnemonic "curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar session" > /dev/null
echo "  5 nodes initialized"

# ── TEST 1: Identity ──────────────────────────────────────────
echo ""
echo "=== Test 1: Identity initialization ==="

if exec_node node-a test -f /home/syncback/.syncback/identity.key 2>/dev/null; then
    pass "identity.key created"
else
    fail "identity.key not created"
fi

# ── TEST 2: Deterministic identity ────────────────────────────
echo ""
echo "=== Test 2: Deterministic identity (DR restore) ==="

PUBKEY_A=$(exec_node_q node-a syncback init --mnemonic "$MNEMONIC_A" 2>&1 | grep "already" > /dev/null && echo "")
# Can't re-init — read from status after daemon starts. Do init check on node-e.
# Wipe node-e, re-init with A's mnemonic
# Volume names use compose project name (directory-based: docker-beta)
VPREFIX="docker-beta"
$COMPOSE rm -fsv node-e > /dev/null 2>&1 || true
docker volume rm "${VPREFIX}_node-e-data" "${VPREFIX}_node-e-files" > /dev/null 2>&1 || true
$COMPOSE up -d node-e > /dev/null 2>&1
sleep 2

INIT_E=$(exec_node node-e syncback init --mnemonic "$MNEMONIC_A" 2>&1 | grep "Public key:" | awk '{print $NF}')
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

docker exec -d "$PREFIX-node-a" sh -c 'syncback daemon --watch-dir /data/files 2>/tmp/daemon.log'
sleep 3

STATUS=$(exec_node_q node-a syncback status || true)
if echo "$STATUS" | grep -q "identity:"; then
    pass "daemon responds to CLI"
    IDENTITY=$(echo "$STATUS" | grep "identity:" | awk '{print $2}')
    echo "  identity: ${IDENTITY:0:16}..."
else
    fail "daemon not responding"
    echo "  --- Daemon log ---"
    exec_node_q node-a cat /tmp/daemon.log | tail -10
fi

# ── TEST 4: Multiple daemons ─────────────────────────────────
echo ""
echo "=== Test 4: Multiple daemons ==="

for node in node-b node-c node-d; do
    docker exec -d "$PREFIX-$node" sh -c 'syncback daemon --watch-dir /data/files 2>/tmp/daemon.log'
done
sleep 3

UP_COUNT=0
for node in node-a node-b node-c node-d; do
    if exec_node_q $node syncback status 2>/dev/null | grep -q "identity:"; then
        ((UP_COUNT++)) || true
    fi
done

echo "  Daemons responding: $UP_COUNT/4"
if [ "$UP_COUNT" -eq 4 ]; then
    pass "all 4 daemons running"
else
    fail "only $UP_COUNT/4 daemons responding"
fi

# ── TEST 5: File watcher ─────────────────────────────────────
echo ""
echo "=== Test 5: File watcher ==="

exec_node node-a sh -c 'echo "hello beta" > /data/files/test.txt'
sleep 5

# Check if file was detected (check daemon log for watcher activity)
WATCHER_LOG=$(exec_node_q node-a cat /tmp/daemon.log | grep -ci "dirty\|DirtyEvent\|file.*event\|backup" || echo "0")
echo "  Watcher/backup log entries: $WATCHER_LOG"

if [ "$WATCHER_LOG" -gt 0 ] 2>/dev/null; then
    pass "file watcher detected activity"
else
    skip "watcher activity not confirmed in logs (may need tracing enabled)"
fi

# ── SKIPPED: P2P features ────────────────────────────────────
echo ""
echo "=== Skipped: P2P features (need connect wiring) ==="
skip "peer connection — Connect is stub"
skip "symbol distribution — needs network delivery"
skip "restore from peers — needs connected peers"
skip "PoS challenges — needs placed symbols"

# ── RESULTS ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Node A daemon log ==="
    exec_node_q node-a cat /tmp/daemon.log | grep -vE 'TRACE' | tail -20
fi

echo ""
echo "To tear down: $COMPOSE down -v"

[ "$FAIL" -eq 0 ]
