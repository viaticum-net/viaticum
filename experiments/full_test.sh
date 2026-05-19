#!/bin/bash
# Full end-to-end test: backup, restore, file change, PoS, eviction.
# Run from project root: bash experiments/full_test.sh
# No set -e — handle errors explicitly
COMPOSE="docker compose -f experiments/docker/compose.yml"
PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }
skip() { echo "  SKIP: $1"; ((SKIP++)); }

# Socket communication helper
sock_cmd() {
    local NODE="$1"
    local JSON="$2"
    echo "$JSON" | docker exec -i "viaticum-$NODE" socat - UNIX-CONNECT:/home/viaticum/.viaticum/viaticum.sock 2>/dev/null
}

get_node_addr() {
    local RESP
    RESP=$(sock_cmd "$1" '{"cmd":"status"}')
    if [ -z "$RESP" ]; then echo ""; return; fi
    python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('own_node_id',''))" "$RESP" 2>/dev/null || echo ""
}

get_status_field() {
    # $1 = node, $2 = field name
    docker exec "viaticum-$1" viaticum status 2>&1 | grep "$2" | awk '{print $NF}'
}

connect_peer() {
    local NODE="$1"
    local ADDR="$2"
    python3 -c "import json,sys; print(json.dumps({'cmd':'connect_peer','node_addr':sys.argv[1]}))" "$ADDR" \
        | docker exec -i "viaticum-$NODE" socat - UNIX-CONNECT:/home/viaticum/.viaticum/viaticum.sock 2>/dev/null
}

echo "============================================================"
echo "  Viaticum Full E2E Test"
echo "============================================================"
echo ""

# ============================================================
# SETUP
# ============================================================
echo "=== Phase 0: Setup ==="

$COMPOSE down -v 2>&1 | tail -1
$COMPOSE up -d 2>&1 | tail -1
sleep 2

echo "Initializing nodes..."
docker exec viaticum-node-a viaticum init --mnemonic "cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double" 2>/dev/null
docker exec viaticum-node-b viaticum init --mnemonic "creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke knock" 2>/dev/null
docker exec viaticum-node-c viaticum init --mnemonic "crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak off" 2>/dev/null
docker exec viaticum-node-d viaticum init --mnemonic "cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state rent" 2>/dev/null
docker exec viaticum-node-e viaticum init --mnemonic "curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar session" 2>/dev/null

echo "Starting daemons (time_scale=86400: 1 real sec = 1 virtual day)..."
# All nodes: time_scale=86400 (1 real sec = 1 virtual day).
# quota-gb is u64 so minimum is 1 GB.
docker exec -d viaticum-node-a sh -c 'viaticum daemon --quota-gb 1 --include "/data/files:0.9" --time-scale 86400 2>/tmp/daemon.log'
for node in node-b node-c node-d node-e; do
    docker exec -d viaticum-$node sh -c 'viaticum daemon --quota-gb 10 --time-scale 86400 2>/tmp/daemon.log'
done
sleep 3

echo "Connecting peers..."
NODE_B=$(get_node_addr node-b)
NODE_C=$(get_node_addr node-c)
NODE_D=$(get_node_addr node-d)
NODE_E=$(get_node_addr node-e)

for ADDR in "$NODE_B" "$NODE_C" "$NODE_D" "$NODE_E"; do
    connect_peer node-a "$ADDR" > /dev/null
done
sleep 2

PEERS=$(get_status_field node-a "peers:")
echo "Node A peers: $PEERS"
if [ "$PEERS" -eq 4 ] 2>/dev/null; then pass "4 peers connected"; else fail "expected 4 peers, got $PEERS"; fi

# ============================================================
# TEST 1: Backup small files
# ============================================================
echo ""
echo "=== Test 1: Backup small files ==="

# Create 5 files with known content
docker exec viaticum-node-a sh -c 'echo "file_one_content_12345" > /data/files/test_1.txt'
docker exec viaticum-node-a sh -c 'echo "file_two_content_67890" > /data/files/test_2.txt'
docker exec viaticum-node-a sh -c 'dd if=/dev/urandom bs=1024 count=10 2>/dev/null > /data/files/test_3.bin'
docker exec viaticum-node-a sh -c 'dd if=/dev/urandom bs=1024 count=10 2>/dev/null > /data/files/test_4.bin'
docker exec viaticum-node-a sh -c 'dd if=/dev/urandom bs=1024 count=10 2>/dev/null > /data/files/test_5.bin'

# Save hashes for later comparison
HASH1=$(docker exec viaticum-node-a md5sum /data/files/test_1.txt | awk '{print $1}')
HASH3=$(docker exec viaticum-node-a md5sum /data/files/test_3.bin | awk '{print $1}')

echo "Waiting for watcher debounce (30s)..."
for i in $(seq 1 12); do
    sleep 5
    DIRTY=$(get_status_field node-a "dirty")
    if [ "$DIRTY" -gt 0 ] 2>/dev/null; then
        echo "  Files detected after $((i*5))s (dirty=$DIRTY)"
        break
    fi
done

echo "Triggering backup..."
docker exec viaticum-node-a viaticum backup 2>&1

# Poll for shards placed
for i in $(seq 1 12); do
    sleep 2
    PLACED=$(get_status_field node-a "placed:")
    if [ "$PLACED" -gt 0 ] 2>/dev/null; then break; fi
done

echo "  Shards placed: $PLACED"
if [ "$PLACED" -gt 0 ] 2>/dev/null; then pass "shards placed ($PLACED)"; else fail "no shards placed"; fi

# Check holder distribution
HELD_B=$(get_status_field node-b "held:")
HELD_C=$(get_status_field node-c "held:")
HELD_D=$(get_status_field node-d "held:")
HELD_E=$(get_status_field node-e "held:")
TOTAL_HELD=$((HELD_B + HELD_C + HELD_D + HELD_E))
echo "  Holder distribution: B=$HELD_B C=$HELD_C D=$HELD_D E=$HELD_E (total=$TOTAL_HELD)"
if [ "$TOTAL_HELD" -gt 0 ]; then pass "holders have shards"; else fail "no holder has shards"; fi

# ============================================================
# TEST 2: Quota / eviction
# ============================================================
echo ""
echo "=== Test 2: Quota (quota-gb is u64, min 1 GB — eviction needs larger files) ==="
# quota-gb accepts only integers (u64). With 10 GB quota and ~50 KB total shards,
# eviction can't be triggered with small test files. Skipping for now.
# To test eviction: need files totaling > quota, or a fractional quota-gb option.
skip "eviction test needs fractional quota-gb (currently u64)"

# ============================================================
# TEST 3: Restore from multiple peers
# ============================================================
echo ""
echo "=== Test 3: Restore file from multiple peers ==="

# Save hash of test_3.bin before deleting
HASH3_BEFORE=$(docker exec viaticum-node-a md5sum /data/files/test_3.bin | awk '{print $1}')

# Delete original files
docker exec viaticum-node-a sh -c 'rm -f /data/files/test_1.txt /data/files/test_3.bin'

# Restore test_1.txt (text file)
echo "  Restoring /data/files/test_1.txt..."
docker exec viaticum-node-a viaticum restore /data/files/test_1.txt 2>&1 || true

# Poll until file appears (async restore)
RESTORED=false
for i in $(seq 1 20); do
    sleep 2
    if docker exec viaticum-node-a test -f /data/files/test_1.txt 2>/dev/null; then
        RESTORED=true
        break
    fi
done

if $RESTORED; then
    HASH1_AFTER=$(docker exec viaticum-node-a md5sum /data/files/test_1.txt 2>/dev/null | awk '{print $1}')
    if [ "$HASH1" = "$HASH1_AFTER" ]; then
        pass "test_1.txt restored with correct content"
    else
        fail "test_1.txt restored but content differs (before=$HASH1 after=$HASH1_AFTER)"
    fi
else
    fail "test_1.txt did not appear after 40s"
    # Dump restore-related logs
    echo "  --- Node A restore log ---"
    docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -iE 'restore|shard_data|denied|escrow' | tail -10
fi

# Restore test_3.bin (binary file)
echo "  Restoring /data/files/test_3.bin..."
docker exec viaticum-node-a viaticum restore /data/files/test_3.bin 2>&1 || true

RESTORED=false
for i in $(seq 1 20); do
    sleep 2
    if docker exec viaticum-node-a test -f /data/files/test_3.bin 2>/dev/null; then
        RESTORED=true
        break
    fi
done

if $RESTORED; then
    HASH3_AFTER=$(docker exec viaticum-node-a md5sum /data/files/test_3.bin 2>/dev/null | awk '{print $1}')
    if [ "$HASH3_BEFORE" = "$HASH3_AFTER" ]; then
        pass "test_3.bin restored with correct content"
    else
        fail "test_3.bin restored but content differs"
    fi
else
    fail "test_3.bin did not appear after 40s"
    echo "  --- Node A restore log ---"
    docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -iE 'restore|shard_data|denied|escrow' | tail -10
fi

# ============================================================
# TEST 4: File modification and re-backup
# ============================================================
echo ""
echo "=== Test 4: File modification and re-backup ==="

PLACED_BEFORE=$PLACED

# Modify test_2.txt
docker exec viaticum-node-a sh -c 'echo "modified_content_99999" > /data/files/test_2.txt'
HASH2_NEW=$(docker exec viaticum-node-a md5sum /data/files/test_2.txt | awk '{print $1}')

echo "  Waiting for watcher to detect modification (30s)..."
for i in $(seq 1 12); do
    sleep 5
    DIRTY=$(get_status_field node-a "dirty")
    if [ "$DIRTY" -gt 0 ] 2>/dev/null; then
        echo "  Modified file detected after $((i*5))s"
        break
    fi
done

if [ "$DIRTY" -gt 0 ] 2>/dev/null; then
    pass "watcher detected file modification"
else
    fail "watcher did not detect modification"
fi

echo "  Triggering re-backup..."
docker exec viaticum-node-a viaticum backup 2>&1

sleep 10

PLACED_AFTER=$(get_status_field node-a "placed:")
echo "  Shards before: $PLACED_BEFORE, after: $PLACED_AFTER"
if [ "$PLACED_AFTER" -gt "$PLACED_BEFORE" ] 2>/dev/null; then
    pass "new shards created for modified file ($PLACED_BEFORE → $PLACED_AFTER)"
else
    fail "no new shards after re-backup"
fi

# Restore modified file and verify new content
docker exec viaticum-node-a sh -c 'rm -f /data/files/test_2.txt'
echo "  Restoring modified test_2.txt..."
docker exec viaticum-node-a viaticum restore /data/files/test_2.txt 2>&1 || true

RESTORED=false
for i in $(seq 1 20); do
    sleep 2
    if docker exec viaticum-node-a test -f /data/files/test_2.txt 2>/dev/null; then
        RESTORED=true
        break
    fi
done

if $RESTORED; then
    HASH2_RESTORED=$(docker exec viaticum-node-a md5sum /data/files/test_2.txt 2>/dev/null | awk '{print $1}')
    if [ "$HASH2_NEW" = "$HASH2_RESTORED" ]; then
        pass "test_2.txt restored with NEW (modified) content"
    else
        fail "test_2.txt restored but has wrong content (expected=$HASH2_NEW got=$HASH2_RESTORED)"
    fi
else
    fail "test_2.txt did not appear after 40s"
    echo "  --- Node A restore log ---"
    docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -iE 'restore|shard_data|denied|escrow' | tail -10
fi

# ============================================================
# TEST 5: Proof of Storage
# ============================================================
echo ""
echo "=== Test 5: Proof of Storage ==="

# With time_scale=86400, PoS fires every 7 real seconds.
# By now (~120s real = ~120 virtual days), several PoS rounds should have fired.
# Check trust P values — should be > 0 if PoS passed.

# Check node-A logs for PoS activity
POS_CHALLENGES=$(docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -c "pos_challenge\|pos_response\|pos round\|pos_round" || true)
POS_PASSES=$(docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -c "PoS pass\|pos.*pass\|verified" || true)
echo "  PoS log entries: challenges=$POS_CHALLENGES verifications=$POS_PASSES"

# Check trust P values via peers command
PEERS_OUTPUT=$(docker exec viaticum-node-a viaticum peers 2>&1)
echo "  $PEERS_OUTPUT"

# Parse P values — any peer with P > 0 means PoS passed
P_NONZERO=$(echo "$PEERS_OUTPUT" | awk 'NR>1 && $2 > 0 {count++} END {print count+0}')
if [ "$P_NONZERO" -gt 0 ] 2>/dev/null; then
    pass "PoS verified: $P_NONZERO peers have trust P > 0"
else
    # Check if PoS round actually fired
    POS_FIRED=$(docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -c "pos round\|run_pos_round\|sample_pos" || true)
    if [ "$POS_FIRED" -gt 0 ]; then
        fail "PoS rounds fired ($POS_FIRED) but no peer has P > 0"
        docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -iE 'pos' | tail -10
    else
        fail "PoS round never fired (time_scale issue?)"
    fi
fi

# Check holder side — did they receive challenges?
POS_HOLDER=$(docker exec viaticum-node-b cat /tmp/daemon.log 2>/dev/null | grep -c "pos_challenge\|answer_pos" || true)
echo "  Node B PoS activity: $POS_HOLDER log entries"

# ============================================================
# RESULTS
# ============================================================
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================================"

# Dump key logs on failure
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Node A daemon log (last 40 lines) ==="
    docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -vE 'TRACE|cli_server.*request|cli_server.*response' | tail -40
    echo ""
    echo "=== Node B daemon log (last 20 lines) ==="
    docker exec viaticum-node-b cat /tmp/daemon.log 2>/dev/null | grep -vE 'TRACE|cli_server' | tail -20
fi

echo ""
echo "To tear down: $COMPOSE down -v"
echo ""

# Exit with error if any test failed
[ "$FAIL" -eq 0 ]
