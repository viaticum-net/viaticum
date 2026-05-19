#!/bin/bash
# Manual 5-node smoke test.
# Run from project root: bash experiments/manual_test.sh
set -e

COMPOSE="docker compose -f experiments/docker/compose.yml"

echo "=== Starting containers ==="
$COMPOSE up -d
sleep 2

echo "=== Initializing nodes ==="
# Valid BIP39 mnemonics generated from fixed entropy [seed; 32]
docker exec viaticum-node-a viaticum init --mnemonic "cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"
docker exec viaticum-node-b viaticum init --mnemonic "creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke grid creek office smoke knock"
docker exec viaticum-node-c viaticum init --mnemonic "crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak make crouch payment artist half drive borrow speak off"
docker exec viaticum-node-d viaticum init --mnemonic "cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state pluck cry predict essence heavy fashion once state rent"
docker exec viaticum-node-e viaticum init --mnemonic "curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar short curtain random mirror hockey gloom brand sugar session"

echo "=== Starting daemons ==="
# Node A: owner with backup files (redirect stderr to log file for debugging)
docker exec -d viaticum-node-a sh -c 'viaticum daemon --quota-gb 1 --include "/data/files:0.9" 2>/tmp/daemon.log'
# Holders
for node in node-b node-c node-d node-e; do
    docker exec -d viaticum-$node sh -c 'viaticum daemon --quota-gb 10 2>/tmp/daemon.log'
done

echo "=== Waiting for daemons to start ==="
sleep 3
for node in node-a node-b node-c node-d node-e; do
    echo -n "$node: "
    docker exec viaticum-$node viaticum status 2>&1 | head -1
done

echo "=== Getting node addresses ==="
# Pipe JSON from host stdin into container via docker exec -i — avoids all shell escaping issues
sock_cmd() {
    local NODE="$1"
    local JSON="$2"
    echo "$JSON" | docker exec -i "viaticum-$NODE" socat - UNIX-CONNECT:/home/viaticum/.viaticum/viaticum.sock 2>/dev/null
}

# Get own_node_id (JSON-encoded EndpointAddr) from each holder's status
get_node_addr() {
    local RESP
    RESP=$(sock_cmd "$1" '{"cmd":"status"}')
    python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('own_node_id',''))" "$RESP" 2>/dev/null
}

NODE_B=$(get_node_addr node-b)
NODE_C=$(get_node_addr node-c)
NODE_D=$(get_node_addr node-d)
NODE_E=$(get_node_addr node-e)

echo "B addr: ${NODE_B:0:60}..."
echo "C addr: ${NODE_C:0:60}..."
echo "D addr: ${NODE_D:0:60}..."
echo "E addr: ${NODE_E:0:60}..."

echo "=== Connecting A to all holders ==="
connect_peer() {
    local ADDR="$1"
    # Build proper JSON with python3, pipe into container
    python3 -c "import json,sys; print(json.dumps({'cmd':'connect_peer','node_addr':sys.argv[1]}))" "$ADDR" \
        | docker exec -i viaticum-node-a socat - UNIX-CONNECT:/home/viaticum/.viaticum/viaticum.sock
}

for ADDR in "$NODE_B" "$NODE_C" "$NODE_D" "$NODE_E"; do
    echo "  connecting: ${ADDR:0:60}..."
    connect_peer "$ADDR" || true
done
sleep 3

echo "=== Node A peers after connect ==="
docker exec viaticum-node-a viaticum peers 2>&1

echo "=== Creating test files on Node A ==="
docker exec viaticum-node-a sh -c 'for i in 1 2 3 4 5; do dd if=/dev/urandom bs=1024 count=10 2>/dev/null > /data/files/test_$i.bin; done'
docker exec viaticum-node-a ls -la /data/files/

echo "=== Waiting for watcher to detect files (30s debounce) ==="
for i in $(seq 1 20); do
    sleep 5
    DIRTY=$(docker exec viaticum-node-a viaticum status 2>&1 | grep "dirty files" | awk '{print $NF}')
    echo "[$((i*5))s] dirty_files=$DIRTY"
    if [ "$DIRTY" -gt 0 ] 2>/dev/null; then
        echo "  -> Files detected!"
        break
    fi
done

echo "=== Triggering backup ==="
docker exec viaticum-node-a viaticum backup

echo "=== Waiting for shards to be placed (polling every 5s, up to 60s) ==="
for i in $(seq 1 12); do
    sleep 5
    STATUS=$(docker exec viaticum-node-a viaticum status 2>&1)
    echo "[$((i*5))s] $STATUS"
    PLACED=$(echo "$STATUS" | grep "shards placed" | awk '{print $NF}')
    if [ "$PLACED" -gt 0 ] 2>/dev/null; then
        echo "  -> Shards placed!"
        break
    fi
done

echo ""
echo "=== Final status ==="
for node in node-a node-b node-c node-d node-e; do
    echo "--- $node ---"
    docker exec viaticum-$node viaticum status 2>&1
    echo ""
done

echo "=== Peers view from Node A ==="
docker exec viaticum-node-a viaticum peers 2>&1

echo "=== Node A daemon log ==="
docker exec viaticum-node-a cat /tmp/daemon.log 2>/dev/null | grep -E 'ERROR|backup|budget|weekly|shard|placement|dirty' | tail -30

echo "=== Stopping daemons ==="
for node in node-a node-b node-c node-d node-e; do
    docker exec viaticum-$node viaticum stop 2>&1 || true
done

echo ""
echo "=== DONE ==="
echo "To tear down: $COMPOSE down -v"
