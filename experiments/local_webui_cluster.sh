#!/bin/bash
# Local cluster of N viaticum daemons with web UI, real time scale.
# Run, open dashboards in browser, poke around, Ctrl-C to stop.
#
# Usage:
#   bash experiments/local_webui_cluster.sh [num_nodes]
#
# Each node listens on its own web port (8400+i) and serves the same
# web-ui/dist bundle. node-00 has a couple of demo files in its watch dir
# so Dashboard / Files have something to show.

set -euo pipefail

NUM_NODES=${1:-4}
TIME_SCALE=1
TEST_DIR="/tmp/viaticum-cluster"
WEB_PORT_BASE=8400
BINARY="${BINARY:-/home/ilya/projects/syncback/target/release/viaticum}"
STATIC_DIR="/home/ilya/projects/syncback/web-ui/dist"

PIDS=()

cleanup() {
    echo ""
    echo "=== Stopping cluster ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "Stopped ${#PIDS[@]} daemon(s). Data left in $TEST_DIR"
}
trap cleanup EXIT INT TERM

node_dir()  { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log()  { echo "$(node_dir "$1")/daemon.log"; }
node_port() { echo "$((WEB_PORT_BASE + $1))"; }

run_cli()   { "$BINARY" --data-dir "$(node_dir "$1")" "${@:2}"; }
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    local idx="$1"
    for _ in $(seq 1 30); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local raw
    raw=$(run_cli_q "$1" status 2>/dev/null | grep "addr:" | grep -oE '/ip4/[^ ]+' | head -1)
    [ -z "$raw" ] && return
    echo "$raw" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

# ── Sanity ───────────────────────────────────────────────────────────────────
[ -x "$BINARY" ] || { echo "ERROR: binary not found: $BINARY"; exit 1; }
[ -d "$STATIC_DIR" ] || { echo "ERROR: web-ui/dist missing: $STATIC_DIR"; exit 1; }

# Detect existing standalone on 8384 and warn
if ss -ltn 2>/dev/null | grep -q ':8384 '; then
    echo "NOTE: a daemon is already listening on :8384 (standalone). Cluster uses 8400+."
fi

echo "============================================================"
echo "  Viaticum web-UI cluster: $NUM_NODES nodes, time_scale=$TIME_SCALE"
echo "  Data: $TEST_DIR"
echo "============================================================"

# ── Init ─────────────────────────────────────────────────────────────────────
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "Initializing $NUM_NODES identities..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")/files"
    run_cli "$i" init > "$(node_dir "$i")/init.log" 2>&1 &
done
wait

# Per-node config: web_api on its own port, low escrow k_factor for instant restore
for i in $(seq 0 $((NUM_NODES-1))); do
    port=$(node_port "$i")
    cat > "$(node_dir "$i")/config.toml" <<CFGEOF
[storage]
disk_reserve_gb = 0.0
soft_quota_gb   = 50.0

[escrow]
# Tiny k_factor so restore credit accrues immediately — this is a demo cluster.
k_factor = 0.001

[network]
bootstrap_peers = []

[web_api]
enabled    = true
bind       = "127.0.0.1:$port"
static_dir = "$STATIC_DIR"
CFGEOF
done

# ── Start daemons ────────────────────────────────────────────────────────────
echo "Starting daemons..."
for i in $(seq 0 $((NUM_NODES-1))); do
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

ready=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then
        ((ready++)) || true
    else
        echo "  node-$(printf '%02d' "$i") NOT ready, see $(node_log "$i")"
    fi
done
echo "  $ready/$NUM_NODES daemons ready"
[ "$ready" -lt "$NUM_NODES" ] && { echo "Some daemons failed to start, aborting."; exit 1; }

# ── Star connect ─────────────────────────────────────────────────────────────
addr0=$(get_addr 0)
echo "Connecting all to node-00 ($addr0)..."
ok=0
for i in $(seq 1 $((NUM_NODES-1))); do
    if run_cli_q "$i" connect "$addr0" 2>&1 | grep -qi connected; then
        ((ok++)) || true
    fi
done
sleep 2
echo "  $ok/$((NUM_NODES-1)) connected"

# ── Seed demo files into node-00's watch dir ─────────────────────────────────
seed_dir="$(node_dir 0)/files"
echo "Seeding demo files into $seed_dir..."
echo "Hello from Viaticum web-UI demo cluster." > "$seed_dir/readme.txt"
mkdir -p "$seed_dir/photos"
dd if=/dev/urandom of="$seed_dir/photos/sample-1.bin" bs=1024 count=64  status=none
dd if=/dev/urandom of="$seed_dir/photos/sample-2.bin" bs=1024 count=128 status=none
mkdir -p "$seed_dir/docs"
for n in 1 2 3; do
    head -c 8192 /dev/urandom | base64 > "$seed_dir/docs/note-$n.txt"
done

# ── Print dashboards ─────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Cluster up. Dashboards:"
for i in $(seq 0 $((NUM_NODES-1))); do
    printf "    node-%02d  http://localhost:%d   data=%s\n" \
        "$i" "$(node_port "$i")" "$(node_dir "$i")"
done
echo ""
echo "  Logs:    $TEST_DIR/node-*/daemon.log"
echo "  Stop:    Ctrl-C in this terminal (cluster will shut down)"
echo "============================================================"

# Keep script alive while daemons run
wait
