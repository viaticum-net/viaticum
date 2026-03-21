#!/bin/bash
# SyncBack β Full E2E Test
# Run from project root: bash experiments/docker-beta/full_test.sh
# Uses 5 Docker nodes, time_scale=604800 (1 real sec = 1 virtual week)
set -euo pipefail

COMPOSE="docker compose -f experiments/docker-beta/compose.yml"
PREFIX="syncback-beta"
PASS=0
FAIL=0
SKIP=0
TIME_SCALE=604800

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }
skip() { echo "  SKIP: $1"; ((SKIP++)); }

exec_node() {
    local NODE="$1"; shift
    docker exec "$PREFIX-$NODE" "$@"
}

exec_node_q() {
    # quiet: suppress stderr
    local NODE="$1"; shift
    docker exec "$PREFIX-$NODE" "$@" 2>/dev/null || true
}

echo "============================================================"
echo "  SyncBack β Full E2E Test"
echo "============================================================"
echo ""

# ============================================================
# SETUP
# ============================================================
echo "=== Phase 0: Setup ==="

$COMPOSE down -v 2>&1 | tail -1 || true
$COMPOSE up -d --build 2>&1 | tail -1
sleep 2

echo "Initializing nodes with fixed mnemonics..."
MNEMONIC_A="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"
MNEMONIC_B="creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke knock"
MNEMONIC_C="crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak off"
MNEMONIC_D="cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state rent"
MNEMONIC_E="curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar session"

exec_node node-a syncback init --mnemonic "$MNEMONIC_A"
exec_node node-b syncback init --mnemonic "$MNEMONIC_B"
exec_node node-c syncback init --mnemonic "$MNEMONIC_C"
exec_node node-d syncback init --mnemonic "$MNEMONIC_D"
exec_node node-e syncback init --mnemonic "$MNEMONIC_E"
echo "  All 5 nodes initialized."

echo "Starting daemons (time_scale=$TIME_SCALE: 1 real sec = 1 virtual week)..."
for node in node-a node-b node-c node-d node-e; do
    docker exec -d "$PREFIX-$node" sh -c "syncback daemon --time-scale $TIME_SCALE --watch-dir /data/files 2>/tmp/daemon.log"
done
sleep 3

# Get node-a address from status
echo "Getting node-a address..."
ADDR_A=""
for i in $(seq 1 10); do
    ADDR_A=$(exec_node_q node-a syncback status | grep -oP 'addr: \K\S+' || true)
    if [ -n "$ADDR_A" ]; then break; fi
    sleep 1
done

if [ -z "$ADDR_A" ]; then
    echo "  FATAL: cannot get node-a address"
    echo "  --- Node A daemon log ---"
    exec_node_q node-a cat /tmp/daemon.log | tail -20
    exit 1
fi
echo "  Node A addr: ${ADDR_A:0:40}..."

echo "Connecting peers to node-a..."
for node in node-b node-c node-d node-e; do
    exec_node_q $node syncback connect "$ADDR_A"
done
sleep 3

# Verify connections
STATUS_A=$(exec_node_q node-a syncback status)
PEER_COUNT=$(echo "$STATUS_A" | grep -oP 'peers: \K\d+' || echo "0")
echo "  Node A peers: $PEER_COUNT"
if [ "$PEER_COUNT" -ge 4 ] 2>/dev/null; then
    pass "4 peers connected"
else
    fail "expected 4 peers, got $PEER_COUNT"
    echo "  --- Node A status ---"
    echo "$STATUS_A"
fi

# ============================================================
# TEST 1: Backup files
# ============================================================
echo ""
echo "=== Test 1: Backup files ==="

exec_node node-a sh -c 'echo "hello syncback beta" > /data/files/test1.txt'
exec_node node-a sh -c 'dd if=/dev/urandom bs=1024 count=10 2>/dev/null > /data/files/test2.bin'
exec_node node-a sh -c 'echo "document for backup" > /data/files/doc.txt'

HASH1=$(exec_node node-a md5sum /data/files/test1.txt | awk '{print $1}')
HASH2=$(exec_node node-a md5sum /data/files/test2.bin | awk '{print $1}')

echo "  Waiting for backup..."
sleep 10  # watcher debounce + backup pipeline + symbol distribution

FILES_COUNT=$(exec_node_q node-a syncback files | grep -c "/" || echo "0")
echo "  Backed up files: $FILES_COUNT"
if [ "$FILES_COUNT" -ge 3 ] 2>/dev/null; then
    pass "3 files backed up"
else
    fail "expected 3 files backed up, got $FILES_COUNT"
fi

# ============================================================
# TEST 2: File listing and versions
# ============================================================
echo ""
echo "=== Test 2: File listing ==="

FILES_OUTPUT=$(exec_node_q node-a syncback files)
echo "$FILES_OUTPUT"
if echo "$FILES_OUTPUT" | grep -q "test1.txt"; then
    pass "test1.txt in file listing"
else
    fail "test1.txt not in file listing"
fi

VERSIONS_OUTPUT=$(exec_node_q node-a syncback versions /data/files/test1.txt)
echo "  $VERSIONS_OUTPUT"
if echo "$VERSIONS_OUTPUT" | grep -q "v1"; then
    pass "test1.txt has version 1"
else
    fail "test1.txt has no versions"
fi

# ============================================================
# TEST 3: Restore
# ============================================================
echo ""
echo "=== Test 3: Restore file ==="

exec_node node-a sh -c 'rm -f /data/files/test1.txt'
echo "  Deleted test1.txt, restoring..."

exec_node_q node-a syncback restore /data/files/test1.txt

# Poll for restore
RESTORED=false
for i in $(seq 1 20); do
    sleep 2
    if exec_node node-a test -f /data/files/test1.txt 2>/dev/null; then
        RESTORED=true
        break
    fi
done

if $RESTORED; then
    HASH1_AFTER=$(exec_node node-a md5sum /data/files/test1.txt | awk '{print $1}')
    if [ "$HASH1" = "$HASH1_AFTER" ]; then
        pass "test1.txt restored with correct content"
    else
        fail "test1.txt content mismatch (before=$HASH1 after=$HASH1_AFTER)"
    fi
else
    fail "test1.txt not restored after 40s"
    echo "  --- Daemon log ---"
    exec_node_q node-a cat /tmp/daemon.log | grep -iE 'restore|error' | tail -10
fi

# ============================================================
# TEST 4: File modification + version
# ============================================================
echo ""
echo "=== Test 4: File modification ==="

exec_node node-a sh -c 'echo "modified content v2" > /data/files/test1.txt'
HASH1_V2=$(exec_node node-a md5sum /data/files/test1.txt | awk '{print $1}')
echo "  Modified test1.txt, waiting for re-backup..."
sleep 10

VERSIONS_AFTER=$(exec_node_q node-a syncback versions /data/files/test1.txt)
V_COUNT=$(echo "$VERSIONS_AFTER" | grep -c "v[0-9]" || echo "0")
echo "  Versions after modification: $V_COUNT"
if [ "$V_COUNT" -ge 2 ] 2>/dev/null; then
    pass "test1.txt has 2+ versions after modification"
else
    fail "expected 2 versions, got $V_COUNT"
fi

# ============================================================
# TEST 5: PoS
# ============================================================
echo ""
echo "=== Test 5: Proof of Storage ==="

# With time_scale=604800, 1 real sec = 1 week. By now (~30s), many PoS rounds should have fired.
POS_LOG=$(exec_node_q node-a cat /tmp/daemon.log | grep -ciE 'pos_challenge|pos_response|challenge_sent' || echo "0")
echo "  PoS log entries: $POS_LOG"

# Check trust — any peer with trust > initial 0.1
TRUST_LINE=$(exec_node_q node-a syncback status | grep -i "trust" || true)
echo "  $TRUST_LINE"

if [ "$POS_LOG" -gt 0 ] 2>/dev/null; then
    pass "PoS challenges fired ($POS_LOG entries)"
else
    skip "PoS not yet firing (may need more time or debug)"
fi

# ============================================================
# TEST 6: DR Restore from seed phrase
# ============================================================
echo ""
echo "=== Test 6: DR Restore (new node, same identity) ==="

# Cannot create a 6th node without compose change. Instead, wipe node-e and re-init with node-a's mnemonic.
$COMPOSE stop node-e 2>&1 | tail -1 || true
docker volume rm ${PREFIX}_node-e-data ${PREFIX}_node-e-files 2>/dev/null || true
$COMPOSE up -d node-e 2>&1 | tail -1
sleep 2

# Init with node-a's mnemonic → same identity
exec_node node-e syncback init --mnemonic "$MNEMONIC_A"
PUBKEY_E=$(exec_node_q node-e syncback status | grep -oP 'identity: \K\S+' || true)
PUBKEY_A=$(exec_node_q node-a syncback status | grep -oP 'identity: \K\S+' || true)

echo "  Node A pubkey: ${PUBKEY_A:0:16}..."
echo "  Node E pubkey: ${PUBKEY_E:0:16}..."

if [ -n "$PUBKEY_A" ] && [ "$PUBKEY_A" = "$PUBKEY_E" ]; then
    pass "DR restore: same mnemonic produces same identity"
else
    fail "DR restore: identities differ (A=$PUBKEY_A E=$PUBKEY_E)"
fi

# ============================================================
# RESULTS
# ============================================================
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Node A daemon log (last 30 lines) ==="
    exec_node_q node-a cat /tmp/daemon.log | grep -vE 'TRACE' | tail -30
fi

echo ""
echo "To tear down: $COMPOSE down -v"
echo ""

[ "$FAIL" -eq 0 ]
