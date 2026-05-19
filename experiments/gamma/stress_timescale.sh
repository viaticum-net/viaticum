#!/bin/bash
# Stress test: find max usable time_scale for gamma experiments.
# Runs 3 nodes, creates files, waits 90s, checks if pipeline completed.
#
# Usage: bash experiments/gamma/stress_timescale.sh [binary_path]

set -euo pipefail

BINARY="${1:-./target/release/viaticum}"
SCALES=(1000 5000 10000 25000 50000 100000)
WAIT=90  # seconds to let the system work
NUM_NODES=3

if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY"
    echo "Build first: cargo build --release -p viaticum"
    exit 1
fi

echo "============================================================"
echo "  Time-scale stress test (${NUM_NODES} nodes, ${WAIT}s per round)"
echo "  Binary: $BINARY"
echo "============================================================"

pass() { echo "    PASS: $1"; }
fail() { echo "    FAIL: $1"; }

for SCALE in "${SCALES[@]}"; do
    TEST_DIR="/tmp/viaticum-stress-$$-${SCALE}"
    PIDS=()
    SIM_WEEKS=$(echo "scale=1; $WAIT * $SCALE / 604800" | bc)

    echo ""
    echo "=== time_scale=$SCALE (${WAIT}s real ≈ ${SIM_WEEKS} sim weeks) ==="

    # Setup
    mkdir -p "$TEST_DIR"
    for i in 0 1 2; do
        dir="$TEST_DIR/node-$i"
        mkdir -p "$dir/files"
        "$BINARY" --data-dir "$dir" init > /dev/null 2>&1 || true
        # Disable relay so nodes connect directly via localhost
        cat > "$dir/config.toml" << 'CFGEOF'
[network]
enable_relay = false
CFGEOF
    done

    # Start daemons
    for i in 0 1 2; do
        dir="$TEST_DIR/node-$i"
        RUST_LOG=warn "$BINARY" --data-dir "$dir" daemon \
            --time-scale "$SCALE" --watch-dir "$dir/files" \
            > "$dir/daemon.log" 2>&1 &
        PIDS+=($!)
    done

    # Wait for daemons
    sleep 3
    READY=0
    for i in 0 1 2; do
        if "$BINARY" --data-dir "$TEST_DIR/node-$i" status > /dev/null 2>&1; then
            ((READY++)) || true
        fi
    done

    if [ "$READY" -lt "$NUM_NODES" ]; then
        fail "only $READY/$NUM_NODES daemons started"
        for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
        rm -rf "$TEST_DIR"
        continue
    fi

    # Connect: node-0 → node-1, node-0 → node-2
    ADDR1=$("$BINARY" --data-dir "$TEST_DIR/node-1" status --json 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['node_addr'])" 2>/dev/null || echo "")
    ADDR2=$("$BINARY" --data-dir "$TEST_DIR/node-2" status --json 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['node_addr'])" 2>/dev/null || echo "")

    if [ -n "$ADDR1" ]; then
        "$BINARY" --data-dir "$TEST_DIR/node-0" connect "$ADDR1" > /dev/null 2>&1 || true
    fi
    if [ -n "$ADDR2" ]; then
        "$BINARY" --data-dir "$TEST_DIR/node-0" connect "$ADDR2" > /dev/null 2>&1 || true
    fi
    sleep 2

    # Create test file
    dd if=/dev/urandom of="$TEST_DIR/node-0/files/stress.dat" bs=1024 count=50 2>/dev/null

    # Wait
    echo "    waiting ${WAIT}s..."
    sleep "$WAIT"

    # Collect results
    S0=$("$BINARY" --data-dir "$TEST_DIR/node-0" status --json 2>/dev/null || echo "{}")

    PEERS=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('peer_count',0))" 2>/dev/null || echo 0)
    FILES=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('backed_up_files',0))" 2>/dev/null || echo 0)
    BACKED=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('backed_up_bytes',0))" 2>/dev/null || echo 0)
    PL_ALIVE=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('placement_alive',0))" 2>/dev/null || echo 0)
    POS_CH=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('pos_total_challenges',0))" 2>/dev/null || echo 0)
    POS_PA=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('pos_total_passes',0))" 2>/dev/null || echo 0)
    AVG_T=$(echo "$S0" | python3 -c "import json,sys; print(round(json.load(sys.stdin).get('avg_trust',0),4))" 2>/dev/null || echo 0)
    BLOCKS_OK=$(echo "$S0" | python3 -c "import json,sys; print(json.load(sys.stdin).get('blocks_ok',0))" 2>/dev/null || echo 0)

    # Check CPU usage of daemon processes
    CPU_TOTAL=0
    for pid in "${PIDS[@]}"; do
        CPU=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")
        CPU_TOTAL=$(echo "$CPU_TOTAL + $CPU" | bc 2>/dev/null || echo "0")
    done

    echo "    peers=$PEERS files=$FILES backed=${BACKED}B placements=$PL_ALIVE"
    echo "    pos=$POS_PA/$POS_CH avg_trust=$AVG_T blocks_ok=$BLOCKS_OK"
    echo "    cpu_total=${CPU_TOTAL}%"

    # Evaluate
    RESULT="OK"
    [ "$PEERS" -lt 2 ] && RESULT="NO_PEERS"
    [ "$PL_ALIVE" -eq 0 ] && RESULT="NO_PLACEMENTS"

    if [ "$RESULT" = "OK" ]; then
        pass "scale=$SCALE works (peers=$PEERS pl=$PL_ALIVE pos=$POS_PA/$POS_CH cpu=${CPU_TOTAL}%)"
    else
        fail "scale=$SCALE: $RESULT"
    fi

    # Cleanup
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    rm -rf "$TEST_DIR"
done

echo ""
echo "============================================================"
echo "  Done."
echo "============================================================"
