#!/bin/bash
# Viaticum: in a small circle, blocks that can never reach their target do not hold the
# worker's queue. Local processes, no Docker.
#
# Scenario:     4 independent owners: node-00 (owner), node-01/02 (holders), node-03 (a
#               friend who joins later). time_scale 30 - deliberately SMALL: the worker tick
#               (60/30 = 2 s) is longer than the block cooldown (30/30 = 1 s), as in
#               production (60 s > 30 s). source_block_size_mb = 1, so each ~1.2 MB file is its
#               own block at once (no 2-minute idle flush). node-00 backs up two .txt files
#               (importance 1.0): with two holders at p <= 0.9 they reach at most 0.99 <
#               0.99999 and stay below target forever ("stuck"). Then a .txt J in a second
#               [[watch]] with importance_multiplier = 0.65 (outranked by the stuck ones).
# Intent:       repair-i4, backup-i12, repair-i1
# Proves:       J's symbols land on the holders' OWN disks (and later on the new friend's
#               disk) while two higher-priority blocks sit below target with nobody to take
#               them; the owner does not re-pick a stuck block every tick (<= 3 picks per
#               block in a 60 s = 30-tick quiet window); after an owner restart a new file
#               still lands on another node's disk.
# Adversarial:  owner restart while everything is parked (the park is RAM-only and is lost)
#               plus a new file in the watch-dir right after it.
# Cannot close: a circle whose pool changes every minute (every change lifts the park -
#               behaviour as before); thousands of stuck blocks (cost of the next_work_item
#               scan, bounded to 16 per iteration); >= 2 SystemState periods (720 s each at
#               this scale - the stuck blocks here are user files, which the worker treats
#               the same way); that parking without the in-iteration skip (or vice versa)
#               would still be caught here - see "Mutations" in the spec: the quiet-window
#               bound catches "never park", the J step catches "neither".
# Steps:        1. two stuck .txt files (A, B) -> .bin of each on node-01 and node-02;
#                  owner picked each with current < target and parked it (precondition)
#                  — check: block_symbols_on, plain_log, awk
#               2. quiet window 60 s (30 ticks) -> <= 3 "picked block for work" per block
#                  id: a pick needs a wake (the 120 s park expiring, <= 1 in 60 s, or a
#                  pool-signature change); 3 is a margin, not a count of expected wakes.
#                  Without parking it is ~30 (repair-i4) — check: log_since
#               3. J (.txt, multiplier 0.65) -> <= 30 s after J's block exists (the
#                  watcher debounce is 60 s here) .bin of J on node-01 AND node-02;
#                  owner picked J with importance 0.65 (outranked) (backup-i12)
#                  — check: block_symbols_on, plain_log
#               4. J parked at the owner ("block parked", no candidates: both holders
#                  already hold it) BEFORE node-03 joins -> <= 90 s .bin of J on node-03,
#                  so the park is released by PeerAuthenticated / the pool change, not by
#                  the 120 s timer (repair-i4, repair-i1) — check: plain_log,
#                  block_symbols_on
#               5. (adversarial) SIGTERM + restart node-00, peers reconnect, new .txt N ->
#                  <= 30 s after N's block exists .bin of N on node-01; in 60 s after
#                  restart <= 8 picks per block id (wakes: 1 restart + 3 peer
#                  authentications + pool changes as peers reconnect, with margin;
#                  without parking it is ~30) (repair-i4) — check: block_symbols_on,
#                  log_since
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_small_circle_test.sh

set -euo pipefail

TIME_SCALE=30
TEST_DIR="/tmp/viaticum-small-circle-$$"
BINARY="${BINARY:-viaticum}"

PASS=0; FAIL=0
PIDS=()

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    echo "  Test dir: $TEST_DIR"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }
run_cli() { local idx="$1"; shift; "$BINARY" --data-dir "$(node_dir "$idx")" "$@"; }
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    for _ in $(seq 1 120); do
        run_cli_q "$1" status 2>/dev/null | grep -q "identity:" && return 0
        sleep 0.5
    done
    return 1
}

get_addr() {
    local RAW_ADDR=""
    for _ in $(seq 1 20); do
        RAW_ADDR=$(run_cli_q "$1" status 2>/dev/null | grep "addr:" | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$RAW_ADDR" ] && break
        sleep 0.5
    done
    [ -n "$RAW_ADDR" ] && echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }
log_float() { echo "$1" | grep -oE "(^|[[:space:]])$2=[0-9.eE+-]+" | head -1 | sed "s/.*$2=//" || true; }
# A ~1.2 MB text file: above source_block_size_mb = 1, so it becomes its own block now.
make_txt() { head -c 900000 /dev/urandom | base64 -w 0 > "$1"; }

init_node() {
    local i="$1"
    mkdir -p "$(node_dir "$i")/files" "$(node_dir "$i")/files-low"
    run_cli "$i" init > /dev/null 2>&1
    {
        echo '[web_api]'
        echo 'enabled = true'
        echo 'bind = "127.0.0.1:0"'
        echo '[storage]'
        echo 'disk_reserve_gb = 0.0'
        echo '[escrow]'
        echo 'k_factor = 0.001'
        echo '[backup]'
        echo 'source_block_size_mb = 1'
        echo '[[watch]]'
        echo "path = \"$(node_dir "$i")/files-low\""
        echo 'importance_multiplier = 0.65'
    } > "$(node_dir "$i")/config.toml"
}

start_node() {
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$1")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$1")/files" \
        >> "$(node_log "$1")" 2>&1 &
    PIDS[$1]=$!
}

# Poll until block BLOCK_HEX has .bin files on every node listed; SECS deadline.
wait_symbols_on() {
    local block="$1" secs="$2"; shift 2
    local ok n
    for _ in $(seq 1 "$secs"); do
        ok=1
        for n in "$@"; do [ "$(block_symbols_on "$n" "$block")" -gt 0 ] || ok=0; done
        [ "$ok" -eq 1 ] && return 0
        sleep 1
    done
    return 1
}

# Largest number of "picked block for work" lines for one block id in LINES (stdin).
max_picks_per_block() {
    grep -a "picked block for work" | grep -oE "block_id=[0-9a-f]+" | sort | uniq -c \
        | sort -rn | head -1 | awk '{print ($1 == "" ? 0 : $1) " " $2}' || true
}

echo "============================================================"
echo "  Viaticum: stuck blocks do not hold the queue (small circle)"
echo "  time_scale: ${TIME_SCALE} (tick 2 s > cooldown 1 s)"
echo "============================================================"

# ── SETUP ────────────────────────────────────────────────────────
echo ""
echo "=== Setup: node-00 + two holders ==="
mkdir -p "$TEST_DIR"
for i in 0 1 2; do init_node "$i"; start_node "$i"; done
for i in 0 1 2; do wait_daemon "$i" || { fail "node-0$i did not start"; exit 1; }; done
ADDR_00=$(get_addr 0)
for i in 1 2; do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
if wait_auth_peers 0 2 30; then
    pass "node-00 sees 2 authenticated holders"
else
    fail "node-00 sees $(status_num 0 peer_count_authenticated)/2 peers after 30s"; exit 1
fi

# ── STEP 1: TWO STUCK BLOCKS ─────────────────────────────────────
echo ""
echo "=== Step 1: two importance-1.0 files that can never reach their target ==="
STUCK=()
for name in a b; do
    f="$(node_dir 0)/files/stuck_$name.txt"
    make_txt "$f"
    hex=""
    for _ in $(seq 1 90); do hex=$(file_block_hex 0 "$f"); [ -n "$hex" ] && break; sleep 1; done
    [ -n "$hex" ] || { fail "stuck_$name.txt got no block within 90s (debounce 60 s)"; exit 1; }
    if wait_symbols_on "$hex" 60 1 2; then
        pass "stuck_$name.txt (${hex:0:16}): .bin on node-01 and node-02"
    else
        fail "stuck_$name.txt: not on both holders' disks within 60s"
    fi
    PARKED=0
    for _ in $(seq 1 30); do
        plain_log 0 | grep -a "block parked" | grep -aq "block_id=${hex:0:16}" && { PARKED=1; break; }
        sleep 1
    done
    LAST=$(plain_log 0 | grep -a "picked block for work" | grep -a "block_id=${hex:0:16}" | tail -1 || true)
    c=$(log_float "$LAST" current_reliability); t=$(log_float "$LAST" target_reliability)
    imp=$(log_float "$LAST" importance)
    if [ "$PARKED" -eq 1 ] && [ -n "$c" ] && awk -v c="$c" -v t="$t" -v i="$imp" \
        'BEGIN { exit !(c < t && i == 1) }'; then
        pass "precondition: ${hex:0:16} importance 1 picked at $c < target $t, then parked (stuck)"
    else
        fail "precondition: ${hex:0:16} is not a stuck block (parked=$PARKED importance=$imp current=$c target=$t)"
    fi
    STUCK+=("$hex")
done

# ── STEP 2: QUIET WINDOW ─────────────────────────────────────────
echo ""
echo "=== Step 2: quiet window 60 s (30 ticks): no per-tick re-picking (repair-i4) ==="
L0=$(log_line_count 0)
sleep 60
read -r MAXP MAXB <<< "$(log_since 0 "$L0" | max_picks_per_block)"
MAXP=${MAXP:-0}
for hex in "${STUCK[@]}"; do
    n=$(log_since 0 "$L0" | grep -a "picked block for work" | grep -ac "block_id=${hex:0:16}" || true)
    echo "  ${hex:0:16}: ${n} pick(s) in the window"
done
if [ "$MAXP" -le 3 ]; then
    pass "every block picked <= 3 times in 30 ticks (max ${MAXP}${MAXB:+ for $MAXB})"
else
    fail "${MAXB} picked ${MAXP} times in a 60 s quiet window (a stuck block is re-picked per tick)"
fi

# ── STEP 3: A LOWER-PRIORITY FILE STILL GOES OUT ─────────────────
echo ""
echo "=== Step 3: J (importance 0.65) lands on the holders while A, B are stuck (backup-i12) ==="
J="$(node_dir 0)/files-low/j.txt"
make_txt "$J"
JHEX=""
for _ in $(seq 1 90); do JHEX=$(file_block_hex 0 "$J"); [ -n "$JHEX" ] && break; sleep 1; done
[ -n "$JHEX" ] || { fail "j.txt got no block within 90s (debounce 60 s)"; exit 1; }
# Measured from the moment J's block exists: the watcher debounce (60 s here) is an
# intended delay, the worker's queue is what this step is about.
T_J=$(date +%s)
if wait_symbols_on "$JHEX" 30 1 2; then
    pass "J (${JHEX:0:16}) on node-01 and node-02 disks $(( $(date +%s) - T_J ))s after its block existed"
else
    fail "J not on both holders' disks within 30s of its block (stuck blocks hold the queue?)"
fi
JLINE=$(plain_log 0 | grep -a "picked block for work" | grep -a "block_id=${JHEX:0:16}" | head -1 || true)
JIMP=$(log_float "$JLINE" importance)
awk -v i="${JIMP:-1}" 'BEGIN { exit !(i < 1) }' \
    && pass "precondition: J was outranked (importance ${JIMP} < 1)" \
    || fail "precondition: J importance ${JIMP:-?} is not below the stuck blocks' 1.0"

# ── STEP 4: A NEW FRIEND GETS J ──────────────────────────────────
echo ""
echo "=== Step 4: node-03 joins -> J reaches the new friend (repair-i4, repair-i1) ==="
# J must be parked BEFORE node-03 connects: then only the PeerAuthenticated release (or
# the pool change) can bring it back within 90 s - the 120 s park timer cannot.
JPARKED=0
for _ in $(seq 1 60); do
    plain_log 0 | grep -a "block parked" | grep -a "block_id=${JHEX:0:16}" \
        | grep -aq "no candidates" && { JPARKED=1; break; }
    sleep 1
done
if [ "$JPARKED" -eq 1 ]; then
    pass "precondition: J (${JHEX:0:16}) parked with no candidates before node-03 joins"
else
    fail "precondition: J not parked ('block parked' ... 'no candidates') within 60s; step 4 would not test the park release"
fi
init_node 3; start_node 3
wait_daemon 3 || fail "node-03 did not start"
run_cli_q 3 connect "$ADDR_00" > /dev/null
T3=$(date +%s)
if wait_symbols_on "$JHEX" 90 3; then
    pass "J on node-03's disk $(( $(date +%s) - T3 ))s after it joined"
else
    fail "J not on node-03's disk within 90s of joining"
fi

# ── STEP 5: OWNER RESTART + NEW FILE ─────────────────────────────
echo ""
echo "=== Step 5 (adversarial): owner restart, then a new file ==="
kill -TERM "${PIDS[0]}" 2>/dev/null || true
wait "${PIDS[0]}" 2>/dev/null || true
L0R=$(log_line_count 0)
start_node 0
wait_daemon 0 || { fail "node-00 did not restart"; exit 1; }
T_R=$(date +%s)
ADDR_00=$(get_addr 0)
for i in 1 2 3; do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
wait_auth_peers 0 3 30 || fail "after restart node-00 sees $(status_num 0 peer_count_authenticated)/3 peers"
N="$(node_dir 0)/files/new_after_restart.txt"
make_txt "$N"
# Picks in the first 60 s after the restart: the park was lost with the RAM.
REST=$(( 60 - ($(date +%s) - T_R) ))
[ "$REST" -gt 0 ] && sleep "$REST"
read -r MAXR MAXRB <<< "$(log_since 0 "$L0R" | max_picks_per_block)"
MAXR=${MAXR:-0}
if [ "$MAXR" -le 8 ]; then
    pass "after restart every block picked <= 8 times in 60 s (max ${MAXR}${MAXRB:+ for $MAXRB})"
else
    fail "after restart ${MAXRB} picked ${MAXR} times in 60 s (per-tick re-picking)"
fi
NHEX=""
for _ in $(seq 1 90); do NHEX=$(file_block_hex 0 "$N"); [ -n "$NHEX" ] && break; sleep 1; done
if [ -n "$NHEX" ] && wait_symbols_on "$NHEX" 30 1; then
    pass "new file (${NHEX:0:16}) on node-01's disk after the restart"
else
    fail "new file not on node-01's disk within 30s of its block after the restart"
fi

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo "Logs: $TEST_DIR/node-*/daemon.log"
[ "$FAIL" -eq 0 ]
