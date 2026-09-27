#!/bin/bash
# Viaticum: deleting one file of a pack must not release the pack (delete-i3).
# Local processes on one machine (no Docker).
#
# Scenario:     5 daemons, independent masters, star to node-00, time_scale 40000 (owner and
#               holder delete windows ≈ 60 s each). The owner backs up a pack of four small files
#               X1..X4 (one Pack block) and, later, a control file Z (its own block). It deletes
#               X1 and Z together, waits until Z is gone from every holder (proof the owner and
#               holder windows ran), and checks that the pack is still on the holders. Then it
#               removes X2..X4 and restores them from the network by hash.
# Intent:       delete-i3, restore-i13 (mechanism), delete-i1 (control), restore-i1
# Proves:       deleting one file of a pack does not release the pack while its siblings live;
#               deleting all of them does. Checked on holder disks and by network restore.
# Adversarial:  the delete of a pack member (was a silent loss of the whole pack before B1.0);
#               a tight race: X2..X4 restored inside their own ~60 s owner window.
# Cannot close: two paths with identical content (dedup Single) — unit test only; a restored file
#               moved to another path — unit test only; vacuum/repack (not implemented).
# Expectation:  RED on code before B1.0 (step 4), logged in runs.jsonl; GREEN after B1.0.
# Steps:        see private/beta-planning/tasks/b1_honest_restore.md §0.4
#   1. X1..X4 (512 KiB each) created outside the watch dir, moved in by ONE mv; all four
#      restorable and on the SAME block — check: file_block_hex x4 (else FAIL "pack not built")
#   2. Z (512 KiB) moved in after step 1; restorable, block != pack — check: file_block_hex
#   3. PACK_ON / Z_ON = symbols of each block on holder disks (stable 5 s); rm X1 Z (one
#      command); both registered deleted — check: block_symbols_on, wait_file_deleted
#   4. Z gone from every holder disk (deadline 360 s: the owner and holder windows ran,
#      delete-i1); then the pack is still whole on holder disks (== PACK_ON) and stays so
#      for a 20 s grace, and no holder logged a Delete for the pack (delete-i3) — check:
#      block_symbols_on, delete_marks_for
#   5. rm X2 X3 X4, registered deleted; restore each from the network by sha256; holders
#      log RestoreResponse for the pack; no holder has a Delete for the pack yet; the whole
#      step ends before T+40 s (owner window of these deletes = 60 s) — check:
#      restore_from_network, restore_responses_for, delete_marks_for, elapsed < 40
#   6. the pack leaves every holder disk (deadline 360 s): released once all its files are
#      deleted and the last window ran (delete-i3 boundary) — check: block_symbols_on == 0
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_pack_delete_test.sh

set -euo pipefail

NUM_NODES=5
# 4-week owner and holder delete windows / 40000 ≈ 60 s each: long enough for three
# network restores inside the window of X2..X4, short enough to run both windows twice.
TIME_SCALE=40000
TEST_DIR="/tmp/viaticum-packdel-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)

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

run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    local idx="$1"
    for _ in $(seq 1 120); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then return 0; fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1" RAW_ADDR=""
    for _ in $(seq 1 20); do
        RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" \
            | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$RAW_ADDR" ] && break
        sleep 0.5
    done
    [ -z "$RAW_ADDR" ] && return
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found. Run: ./rbuild.sh" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

# Sum of symbol files of BLOCK_HEX over all holder disks.
symbols_on_holders() {
    local total=0 i
    for i in "${HOLDERS[@]}"; do
        total=$((total + $(block_symbols_on "$i" "$1")))
    done
    echo "$total"
}

# Per-holder symbol counts of BLOCK_HEX, for messages.
symbols_breakdown() {
    local out="" i
    for i in "${HOLDERS[@]}"; do
        out="$out node-$(printf '%02d' "$i")=$(block_symbols_on "$i" "$1")"
    done
    echo "${out# }"
}

echo "============================================================"
echo "  Viaticum: pack member delete (delete-i3)"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# The scenario races the owner window on purpose (step 5): floor 60 s, and step 5
# asserts its own elapsed time.
assert_delete_window "$TIME_SCALE" 60
OWNER_WINDOW=$((OWNER_DELETE_COOLDOWN_SECS / TIME_SCALE))

# ── SETUP ────────────────────────────────────────────────────────
echo ""
echo "=== Setup ==="
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then READY=$((READY + 1)); else echo "    node-$(printf '%02d' "$i") NOT ready"; fi
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)
for i in $(seq 1 $((NUM_NODES-1))); do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
    exit 1
fi

FILES="$(node_dir 0)/files"
SRC="$(node_dir 0)/staging_src"
mkdir -p "$SRC"

# ── STEP 1: ONE PACK OF FOUR FILES ───────────────────────────────
echo ""
echo "=== Step 1: X1..X4 moved in by one mv -> one pack ==="
declare -A HASH
for n in 1 2 3 4; do
    dd if=/dev/urandom of="$SRC/x$n.bin" bs=1024 count=512 2>/dev/null
    HASH[x$n]=$(content_hash "$SRC/x$n.bin")
done
# One mv: the four watcher events land within milliseconds, inside one pack-flush
# window (idle 1 s / fallback 2 s at this scale).
mv "$SRC"/x1.bin "$SRC"/x2.bin "$SRC"/x3.bin "$SRC"/x4.bin "$FILES"/

for n in 1 2 3 4; do
    if ! wait_file_restorable 0 "$FILES/x$n.bin" 90; then
        fail "x$n.bin not restorable per owner after 90s"
        exit 1
    fi
done
PACK=$(file_block_hex 0 "$FILES/x1.bin")
SAME=1
for n in 2 3 4; do
    b=$(file_block_hex 0 "$FILES/x$n.bin")
    echo "  x$n.bin block ${b:0:16}.."
    [ "$b" = "$PACK" ] || SAME=0
done
if [ -n "$PACK" ] && [ "$SAME" -eq 1 ]; then
    pass "X1..X4 restorable and share one block (pack ${PACK:0:16}..)"
else
    fail "pack not built: X1..X4 are not on one block (x1=${PACK:0:16}..) — the scenario cannot test delete-i3"
    exit 1
fi

# ── STEP 2: CONTROL FILE Z ON ITS OWN BLOCK ──────────────────────
echo ""
echo "=== Step 2: control file Z ==="
dd if=/dev/urandom of="$SRC/z.bin" bs=1024 count=512 2>/dev/null
mv "$SRC/z.bin" "$FILES/"
if ! wait_file_restorable 0 "$FILES/z.bin" 90; then
    fail "z.bin not restorable per owner after 90s"
    exit 1
fi
ZBLOCK=$(file_block_hex 0 "$FILES/z.bin")
if [ -n "$ZBLOCK" ] && [ "$ZBLOCK" != "$PACK" ]; then
    pass "Z restorable on its own block ${ZBLOCK:0:16}.."
else
    fail "Z block '${ZBLOCK:0:16}' is empty or equals the pack block"
    exit 1
fi

# ── STEP 3: RECORD HOLDER DISKS, DELETE X1 AND Z ─────────────────
echo ""
echo "=== Step 3: symbols on holder disks; rm X1 Z ==="
# Placement may still add holders right after "restorable": take counts once both
# have been stable for 5 consecutive seconds (max 60 s).
PREV=""; STABLE=0
for _ in $(seq 1 60); do
    CUR="$(symbols_on_holders "$PACK")/$(symbols_on_holders "$ZBLOCK")"
    if [ "$CUR" = "$PREV" ]; then STABLE=$((STABLE + 1)); else STABLE=0; fi
    PREV="$CUR"
    [ "$STABLE" -ge 5 ] && break
    sleep 1
done
PACK_ON=$(symbols_on_holders "$PACK")
Z_ON=$(symbols_on_holders "$ZBLOCK")
PACK_HOLDERS=0
for i in "${HOLDERS[@]}"; do
    [ "$(block_symbols_on "$i" "$PACK")" -gt 0 ] && PACK_HOLDERS=$((PACK_HOLDERS + 1))
done
echo "  pack: $PACK_ON symbols ($(symbols_breakdown "$PACK"))"
echo "  Z:    $Z_ON symbols ($(symbols_breakdown "$ZBLOCK"))"
if [ "$PACK_ON" -gt 0 ] && [ "$Z_ON" -gt 0 ] && [ "$PACK_HOLDERS" -ge 2 ]; then
    pass "pack on $PACK_HOLDERS holders ($PACK_ON symbols), Z on holders ($Z_ON symbols)"
else
    fail "precondition: pack=$PACK_ON symbols on $PACK_HOLDERS holders, Z=$Z_ON symbols"
    exit 1
fi

rm -f "$FILES/x1.bin" "$FILES/z.bin"
if wait_file_deleted 0 "$FILES/x1.bin" 30 && wait_file_deleted 0 "$FILES/z.bin" 30; then
    pass "owner registered the delete of X1 and Z"
else
    fail "owner did not register the delete of X1 and Z within 30s"
    exit 1
fi

# ── STEP 4: Z GONE (WINDOWS RAN), PACK STILL WHOLE ───────────────
echo ""
echo "=== Step 4: Z leaves every holder; the pack stays (delete-i3) ==="
Z_GONE=0
for attempt in $(seq 1 120); do
    if [ "$(symbols_on_holders "$ZBLOCK")" -eq 0 ]; then
        Z_GONE=1
        echo "  Z gone from every holder disk after ~$((attempt * 3))s"
        break
    fi
    [ $((attempt % 10)) -eq 0 ] && echo "  Z still on holders: $(symbols_breakdown "$ZBLOCK") (${attempt}x3s)"
    sleep 3
done
if [ "$Z_GONE" -eq 1 ]; then
    pass "control: Z left every holder (owner and holder windows ran, delete-i1)"
else
    fail "control: Z still on holders after 360s ($(symbols_breakdown "$ZBLOCK")) — the windows did not run, nothing is proven"
    exit 1
fi

PACK_OK=1
for _ in $(seq 1 10); do
    NOW_ON=$(symbols_on_holders "$PACK")
    if [ "$NOW_ON" -ne "$PACK_ON" ]; then PACK_OK=0; break; fi
    sleep 2
done
if [ "$PACK_OK" -eq 1 ]; then
    pass "pack whole on holder disks 20 s after Z left: $PACK_ON symbols ($(symbols_breakdown "$PACK"))"
else
    fail "delete-i3: pack released with X1 — $NOW_ON of $PACK_ON symbols left on holders ($(symbols_breakdown "$PACK"))"
fi
MARKS=$(delete_marks_for "$PACK" "${HOLDERS[@]}")
if [ "$MARKS" -eq 0 ]; then
    pass "no holder received a Delete for the pack (Z marks: $(delete_marks_for "$ZBLOCK" "${HOLDERS[@]}"))"
else
    fail "delete-i3: $MARKS holder(s) logged 'holding marked for deletion' for the pack after deleting X1 only"
fi

# ── STEP 5: DELETE THE REST, RESTORE FROM THE NETWORK IN THE WINDOW ──
echo ""
echo "=== Step 5: rm X2 X3 X4 -> restore each from the network (inside ${OWNER_WINDOW}s window) ==="
SERVED_BEFORE=$(restore_responses_for "$PACK" "${HOLDERS[@]}")
rm -f "$FILES/x2.bin" "$FILES/x3.bin" "$FILES/x4.bin"
T=$(date +%s)
for n in 2 3 4; do
    if ! wait_file_deleted 0 "$FILES/x$n.bin" 30; then
        fail "owner did not register the delete of x$n.bin within 30s"
    fi
done
for n in 2 3 4; do
    if restore_from_network 0 "$FILES/x$n.bin" "${HASH[x$n]}" 30; then
        pass "restore x$n.bin from network: $RESTORE_MSG"
    else
        fail "restore x$n.bin from network: $RESTORE_MSG"
    fi
done
ELAPSED=$(( $(date +%s) - T ))
MARKS=$(delete_marks_for "$PACK" "${HOLDERS[@]}")
if [ "$ELAPSED" -lt 40 ]; then
    pass "step 5 done ${ELAPSED}s after the delete (< 40 s, owner window ${OWNER_WINDOW}s)"
else
    fail "step 5 took ${ELAPSED}s >= 40 s — restores may have raced the owner window, verdict void"
fi
if [ "$MARKS" -eq 0 ]; then
    pass "no holder received a Delete for the pack inside the window of X2..X4 (restore-i9)"
else
    fail "restore-i9: $MARKS holder(s) marked the pack for deletion ${ELAPSED}s after X2..X4 were deleted (window from an earlier delete?)"
fi
SERVED=$(( $(restore_responses_for "$PACK" "${HOLDERS[@]}") - SERVED_BEFORE ))
if [ "$SERVED" -ge 1 ]; then
    pass "holders logged ${SERVED} RestoreResponse(s) for the pack"
else
    fail "no holder logged a RestoreResponse for pack ${PACK:0:16}.."
fi

# ── STEP 6: ALL FILES DELETED -> PACK RELEASED ───────────────────
echo ""
echo "=== Step 6: all pack files deleted -> the pack leaves every holder ==="
PACK_GONE=0
for attempt in $(seq 1 120); do
    if [ "$(symbols_on_holders "$PACK")" -eq 0 ]; then
        PACK_GONE=1
        echo "  pack gone from every holder disk $(( $(date +%s) - T ))s after X2..X4 were deleted"
        break
    fi
    [ $((attempt % 10)) -eq 0 ] && echo "  pack still on holders: $(symbols_breakdown "$PACK") (${attempt}x3s)"
    sleep 3
done
if [ "$PACK_GONE" -eq 1 ]; then
    pass "pack released once all its files were deleted (delete-i3 boundary)"
else
    fail "pack still on holders 360 s after its last file was deleted ($(symbols_breakdown "$PACK"))"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 deletion log (last 20 lines) ==="
    grep -aE "DeleteMsg|cleaned up|deletion" "$(node_log 0)" | tail -20 || true
fi
echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"

[ "$FAIL" -eq 0 ]
