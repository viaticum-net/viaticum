#!/bin/bash
# Viaticum: repair never re-offers a block to a holder that went silent on PoS; a block
# exactly at its reliability target is left alone. Local processes, no Docker.
#
# Scenario:     6 independent owners, star to node-00, time_scale 100000 (PoS pending
#               timeout ~12 s). node-00 backs up a 256 KB .txt (importance 1.0): 5 full
#               copies. Once all 5 holders passed PoS the block sits EXACTLY on the float
#               boundary of its target (1 - 0.1^5 computes one ulp below 0.99999). A witness
#               node joins and leaves. Then two holders silently lose the block's symbol
#               files (directory kept, daemons alive, still answering the network); later a
#               spare joins; finally one silent holder gets its files back.
# Intent:       repair-i2, repair-i3, repair-i1, pos-i2
# Proves:       on the silent holders' OWN disks and logs: no new symbols of the block and
#               no accepted offer after the silence began, although the owner worked the
#               block (>= 1 pick, a "no new candidates ... excluded_awaiting_verdict=2"
#               line); the spare's disk gets the block; the returning holder is back in the
#               count only through PoS (owner log: Pass, old_status=PresumedLost ->
#               new_status=Alive; owner API: live symbols + its copy) and holds exactly its own files.
#               repair-i3: at the float boundary the owner shows is_safe_to_delete=true and a
#               joining witness node's disk gets 0 symbols of the block (PeerAuthenticated
#               wakes the worker; the at-target block is not picked).
# Adversarial:  the silent holders are online, authenticated and - once the block is below
#               target - the only non-Alive peers of the pool (the most tempting candidates,
#               step 5); one silent holder returns with its data (step 7).
# Cannot close: real detection time (3 x 14 d 2 h ~ 6 weeks, here scaled); a holder frozen as
#               a whole (SIGSTOP); ALL holders of a block silent; Nack delivered by mailbox;
#               that the repaired set decodes (no restore); DR forgetting a PresumedLost
#               holder (line B).
# Steps:        1. backup -> restorable; exactly 5 holders, equal .bin counts (full copies)
#                  - precondition — check: wait_file_restorable, block_symbols_on
#               2. PoS Pass from all 5 -> owner logs the block at target with raw
#                  current < raw target (float boundary, precondition); is_safe_to_delete
#                  = true <= 30 s; a witness joins: 0 .bin of the block on the witness for
#                  15 s, 0 picks of the block, no pick of any block within tolerance of its
#                  target (repair-i3) — check: plain_log, file_field, block_symbols_on, awk
#               3. S1, S2 (first two holders): move holdings/<B>/*.bin to a stash, keep the
#                  dir, daemons alive (setup)
#               4. <= 180 s: owner logs PoS timeouts for B with S1 and S2 reaching
#                  new_status=PresumedLost; S1/S2 log "symbol missing, sending nack" for B
#                  (online, got the challenge); no "symbol directory missing" for B
#                  (pos-i2, repair-i2 precondition) — check: plain_log, log_since
#               5. owner: >= 1 "picked block for work" for B and a "no new candidates" line
#                  for B with excluded_awaiting_verdict=2; on S1 and S2: 0 .bin of B, no
#                  "SymbolOffer accepted" for B since step 3 (repair-i2) — check: log_since,
#                  block_symbols_on
#               6. spare joins -> <= 60 s spare's disk has .bin of B; S1, S2 still 0
#                  (repair-i1, repair-i2) — check: block_symbols_on
#               7. S1 gets its stash back -> <= 120 s owner: PosResponse Pass for B from S1
#                  with old_status=PresumedLost new_status=Alive; owner live symbols +S1's copy; S1 holds
#                  exactly its original .bin count, no "SymbolOffer accepted" for B since
#                  step 3; S2 still 0 (repair-i2 exit door) — check: plain_log, file_field,
#                  block_symbols_on, log_since
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_silent_holder_test.sh

set -euo pipefail

NUM_NODES=6
TIME_SCALE=100000
TEST_DIR="/tmp/viaticum-silent-holder-$$"
BINARY="${BINARY:-viaticum}"
# Must match RELIABILITY_TARGET_REL_TOL in crates/viaticum-core/src/constants.rs.
REL_TOL=1e-6

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
    echo "  Killed ${#PIDS[@]} daemon processes"
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
dev16() { api_get "$1" /api/status | jq -r '.device_id // empty' 2>/dev/null | cut -c1-16 || true; }
# Float value of FIELD in a tracing LINE ("" when absent).
log_float() { echo "$1" | grep -oE "(^|[[:space:]])$2=[0-9.eE+-]+" | head -1 | sed "s/.*$2=//" || true; }

init_node() {
    mkdir -p "$(node_dir "$1")/files"
    run_cli "$1" init > /dev/null 2>&1
    cat > "$(node_dir "$1")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
[escrow]
k_factor = 0.001
CFGEOF
}

start_node() {
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$1")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$1")/files" \
        >> "$(node_log "$1")" 2>&1 &
    PIDS[$1]=$!
}

echo "============================================================"
echo "  Viaticum: silent holder is not re-offered; at-target block left alone"
echo "  Nodes: ${NUM_NODES} (+witness, +spare), time_scale: ${TIME_SCALE}"
echo "============================================================"

# ── SETUP ────────────────────────────────────────────────────────
echo ""
echo "=== Setup ==="
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES-1))); do init_node "$i"; start_node "$i"; done
for i in $(seq 0 $((NUM_NODES-1))); do
    wait_daemon "$i" || { fail "node-$(printf '%02d' "$i") did not start"; exit 1; }
done
ADDR_00=$(get_addr 0)
for i in $(seq 1 $((NUM_NODES-1))); do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) peers after 30s"
    exit 1
fi

# ── STEP 1: BACKUP, 5 FULL COPIES ────────────────────────────────
echo ""
echo "=== Step 1: backup -> 5 full copies ==="
FILE="$(node_dir 0)/files/notes.txt"   # .txt = importance 1.0
head -c 196608 /dev/urandom | base64 -w 0 > "$FILE"   # ~256 KB of text
if wait_file_restorable 0 "$FILE" 60; then
    pass "file backed up and restorable per owner"
else
    fail "file not restorable per owner after 60s"; exit 1
fi
BLOCK=$(file_block_hex 0 "$FILE")
BSHORT=${BLOCK:0:16}
echo "  block: $BLOCK"

HOLDERS=(); COUNTS=()
for _ in $(seq 1 30); do
    HOLDERS=(); COUNTS=()
    for i in $(seq 1 $((NUM_NODES-1))); do
        c=$(block_symbols_on "$i" "$BLOCK")
        [ "$c" -gt 0 ] && { HOLDERS+=("$i"); COUNTS+=("$c"); }
    done
    [ "${#HOLDERS[@]}" -eq 5 ] && break
    sleep 1
done
UNIQ=$(printf '%s\n' "${COUNTS[@]:-}" | sort -u | wc -l)
if [ "${#HOLDERS[@]}" -eq 5 ] && [ "$UNIQ" -eq 1 ]; then
    pass "precondition: 5 holders with ${COUNTS[0]} .bin each (full copies)"
else
    fail "precondition: not 5 full copies (holders=${HOLDERS[*]:-none} counts=${COUNTS[*]:-none})"
    exit 1
fi
declare -A DEV
for i in "${HOLDERS[@]}"; do DEV[$i]=$(dev16 "$i"); done

# ── STEP 2: AT THE FLOAT BOUNDARY OF THE TARGET (repair-i3) ──────
echo ""
echo "=== Step 2: block exactly at target is left alone (repair-i3) ==="
ALL_PASSED=0
for _ in $(seq 1 45); do
    ALL_PASSED=1
    for i in "${HOLDERS[@]}"; do
        plain_log 0 | grep -a "mailbox PosResponse resolved" | grep -a "block_id=$BSHORT" \
            | grep -a "holder=${DEV[$i]}" | grep -aq "outcome=Pass" || { ALL_PASSED=0; break; }
    done
    [ "$ALL_PASSED" -eq 1 ] && break
    sleep 2
done
if [ "$ALL_PASSED" -eq 1 ]; then
    pass "PoS Pass for the block from all 5 holders"
else
    fail "not all 5 holders passed PoS for $BSHORT.. within 90s"
fi

# Owner's own verdict flip, with the raw numbers (logged only when "at target" flips).
AT_LINE=""
for _ in $(seq 1 30); do
    AT_LINE=$(plain_log 0 | grep -a "block target status changed" | grep -a "block_id=$BSHORT" | tail -1 || true)
    echo "$AT_LINE" | grep -q "at_target=true" && break
    sleep 1
done
CUR=$(log_float "$AT_LINE" current_reliability); TGT=$(log_float "$AT_LINE" target_reliability)
echo "  at-target line: current=$CUR target=$TGT"
if echo "$AT_LINE" | grep -q "at_target=true" \
    && awk -v c="$CUR" -v t="$TGT" 'BEGIN { exit !(c < t) }'; then
    pass "precondition: at target with raw current < raw target ($CUR < $TGT) - the float boundary is exercised"
elif echo "$AT_LINE" | grep -q "at_target=true"; then
    fail "precondition: at target but raw current >= target ($CUR >= $TGT) - the boundary is not exercised"
else
    fail "owner never logged the block at target (last: ${AT_LINE:-none})"
fi
L0_AT=$(log_line_count 0)

SAFE=""
for _ in $(seq 1 30); do
    SAFE=$(file_field 0 "$FILE" '.is_safe_to_delete')
    [ "$SAFE" = "true" ] && break
    sleep 1
done
[ "$SAFE" = "true" ] && pass "is_safe_to_delete = true at the float boundary" \
    || fail "is_safe_to_delete = ${SAFE:-?} 30s after the block reached its target"

# Witness joins: PeerAuthenticated resets every cooldown and wakes the worker. A block
# below target (by a raw >=) would be offered to the new peer.
WITNESS=7
init_node "$WITNESS"; start_node "$WITNESS"
wait_daemon "$WITNESS" || fail "witness did not start"
run_cli_q "$WITNESS" connect "$ADDR_00" > /dev/null
wait_auth_peers 0 "$NUM_NODES" 30 || fail "witness did not authenticate with node-00 within 30s"
sleep 15
W_SYMS=$(block_symbols_on "$WITNESS" "$BLOCK")
W_OTHER=$(find "$(node_dir "$WITNESS")/holdings" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l || true)
if [ "$W_SYMS" -eq 0 ]; then
    pass "witness holds 0 symbols of the at-target block (it got ${W_OTHER} other block dir(s))"
else
    fail "witness received ${W_SYMS} symbols of a block that is at its target"
fi
PICKS_B=$(log_since 0 "$L0_AT" | grep -a "picked block for work" | grep -ac "block_id=$BSHORT" || true)
[ "${PICKS_B:-0}" -eq 0 ] && pass "0 picks of the at-target block since it reached target" \
    || fail "${PICKS_B} picks of the at-target block since it reached target"
NEAR=$(log_since 0 "$L0_AT" | grep -a "picked block for work" | while read -r line; do
    c=$(log_float "$line" current_reliability); t=$(log_float "$line" target_reliability)
    [ -n "$c" ] && [ -n "$t" ] && awk -v c="$c" -v t="$t" -v tol="$REL_TOL" \
        'BEGIN { exit !((1-c) <= (1-t)*(1+tol)) }' && echo "$line"
done | wc -l || true)
[ "$NEAR" -eq 0 ] && pass "no block within tolerance of its target was picked" \
    || fail "${NEAR} picks of blocks within tolerance of their target"
kill "${PIDS[$WITNESS]}" 2>/dev/null || true
wait "${PIDS[$WITNESS]}" 2>/dev/null || true

# ── STEP 3: TWO HOLDERS GO SILENT ────────────────────────────────
echo ""
echo "=== Step 3: S1, S2 lose the block's symbol files (dir kept, daemons alive) ==="
S1=${HOLDERS[0]}; S2=${HOLDERS[1]}
S1_ORIG=$(block_symbols_on "$S1" "$BLOCK")
L_S1=$(log_line_count "$S1"); L_S2=$(log_line_count "$S2"); L0_3=$(log_line_count 0)
for s in "$S1" "$S2"; do
    mkdir -p "$TEST_DIR/stash-$s"
    mv "$(node_dir "$s")/holdings/$BLOCK/"*.bin "$TEST_DIR/stash-$s/"
done
if [ "$(block_symbols_on "$S1" "$BLOCK")" -eq 0 ] && [ "$(block_symbols_on "$S2" "$BLOCK")" -eq 0 ] \
    && [ -d "$(node_dir "$S1")/holdings/$BLOCK" ] && [ -d "$(node_dir "$S2")/holdings/$BLOCK" ] \
    && kill -0 "${PIDS[$S1]}" && kill -0 "${PIDS[$S2]}"; then
    pass "setup: S1=node-0$S1, S2=node-0$S2 hold 0 .bin, dirs kept, daemons alive"
else
    fail "setup: stash did not leave S1/S2 silent (dir kept, alive)"; exit 1
fi

# ── STEP 4: OWNER DETECTS SILENCE VIA PoS TIMEOUTS ───────────────
echo ""
echo "=== Step 4: PoS timeouts -> PresumedLost (pos-i2) ==="
DETECTED=0
for _ in $(seq 1 90); do
    DETECTED=0
    for s in "$S1" "$S2"; do
        log_since 0 "$L0_3" | grep -a "PoS challenge timed out" | grep -a "block_id=$BSHORT" \
            | grep -a "${DEV[$s]}" | grep -aq "new_status=PresumedLost" && DETECTED=$((DETECTED + 1))
    done
    [ "$DETECTED" -ge 2 ] && break
    sleep 2
done
[ "$DETECTED" -ge 2 ] && pass "owner moved S1 and S2 to PresumedLost for the block via PoS timeouts" \
    || fail "PresumedLost for ${DETECTED}/2 silent holders within 180s"
for s in "$S1" "$S2"; do
    NACK=$(log_since "$s" "$( [ "$s" = "$S1" ] && echo "$L_S1" || echo "$L_S2")" \
        | grep -a "symbol missing, sending nack" | grep -ac "block_id=$BSHORT" || true)
    DIRMISS=$(plain_log "$s" | grep -a "symbol directory missing" | grep -ac "$BSHORT" || true)
    [ "${NACK:-0}" -ge 1 ] && pass "node-0$s is online and got the challenge (${NACK} nack line(s))" \
        || fail "node-0$s logged no 'symbol missing, sending nack' for the block (not reached?)"
    [ "${DIRMISS:-0}" -eq 0 ] || fail "node-0$s reported 'symbol directory missing': emulation became an explicit drop"
done
AUTH=$(status_num 0 peer_count_authenticated)
[ "$AUTH" -ge 5 ] && pass "owner still sees ${AUTH} authenticated peers (silent != offline)" \
    || fail "owner sees only ${AUTH} authenticated peers"

# ── STEP 5: NOT RE-OFFERED TO THE SILENT HOLDERS (repair-i2) ─────
echo ""
echo "=== Step 5: owner works the block but does not re-offer to S1/S2 (repair-i2) ==="
NOCAND=""
for _ in $(seq 1 15); do
    NOCAND=$(log_since 0 "$L0_3" | grep -a "no new candidates" | grep -a "block_id=$BSHORT" \
        | grep -a "excluded_awaiting_verdict=2" | tail -1 || true)
    [ -n "$NOCAND" ] && break
    sleep 2
done
sleep 10
PICKS=$(log_since 0 "$L0_3" | grep -a "picked block for work" | grep -ac "block_id=$BSHORT" || true)
[ "${PICKS:-0}" -ge 1 ] && pass "owner picked the block ${PICKS}x after the silence began" \
    || fail "owner never picked the block after the silence began: step is empty"
[ -n "$NOCAND" ] && pass "owner: no new candidates for the block, excluded_awaiting_verdict=2" \
    || fail "no 'no new candidates ... excluded_awaiting_verdict=2' line for the block"
for s in "$S1" "$S2"; do
    since=$( [ "$s" = "$S1" ] && echo "$L_S1" || echo "$L_S2")
    SYM=$(block_symbols_on "$s" "$BLOCK")
    ACC=$(log_since "$s" "$since" | grep -a "SymbolOffer accepted" | grep -ac "block_id=$BSHORT" || true)
    if [ "$SYM" -eq 0 ] && [ "${ACC:-0}" -eq 0 ]; then
        pass "node-0$s (silent): 0 .bin of the block, no accepted offer since the silence"
    else
        fail "node-0$s (silent) got the block again: ${SYM} .bin, ${ACC} accepted offer(s)"
    fi
done

# ── STEP 6: SPARE GETS THE BLOCK ─────────────────────────────────
echo ""
echo "=== Step 6: spare joins -> repair lands on the spare (repair-i1) ==="
SPARE=6
init_node "$SPARE"; start_node "$SPARE"
wait_daemon "$SPARE" || fail "spare did not start"
run_cli_q "$SPARE" connect "$ADDR_00" > /dev/null
GOT=0
for _ in $(seq 1 30); do
    GOT=$(block_symbols_on "$SPARE" "$BLOCK")
    [ "$GOT" -gt 0 ] && break
    sleep 2
done
[ "$GOT" -gt 0 ] && pass "spare holds ${GOT} symbols of the block" \
    || fail "no symbols of the block on the spare within 60s"
for s in "$S1" "$S2"; do
    if [ "$(block_symbols_on "$s" "$BLOCK")" -eq 0 ]; then
        pass "node-0$s (silent) still holds 0 .bin after the spare joined"
    else
        fail "node-0$s (silent) got symbols of the block after the spare joined"
    fi
done

# ── STEP 7: S1 RETURNS WITH ITS DATA ─────────────────────────────
echo ""
echo "=== Step 7: S1 gets its files back -> back in the count only through PoS ==="
LIVE_BEFORE=$(file_field 0 "$FILE" '.effective_status.live // 0')
L0_7=$(log_line_count 0)
mv "$TEST_DIR/stash-$S1/"*.bin "$(node_dir "$S1")/holdings/$BLOCK/"
BACK=""
for _ in $(seq 1 60); do
    BACK=$(log_since 0 "$L0_7" | grep -a "mailbox PosResponse resolved" | grep -a "block_id=$BSHORT" \
        | grep -a "holder=${DEV[$S1]}" | grep -a "outcome=Pass" | tail -1 || true)
    [ -n "$BACK" ] && break
    sleep 2
done
if echo "$BACK" | grep -q "old_status=PresumedLost" && echo "$BACK" | grep -q "new_status=Alive"; then
    pass "S1 passed PoS: PresumedLost -> Alive"
else
    fail "no PoS Pass PresumedLost -> Alive for S1 within 120s (last: ${BACK:-none})"
fi
LIVE_AFTER=""
for _ in $(seq 1 10); do
    LIVE_AFTER=$(file_field 0 "$FILE" '.effective_status.live // 0')
    [ "${LIVE_AFTER:-0}" -gt "${LIVE_BEFORE:-0}" ] && break
    sleep 1
done
# effective_status.live counts Alive SYMBOLS: S1 back = + its full copy.
[ "${LIVE_AFTER:-0}" -eq $(( ${LIVE_BEFORE:-0} + S1_ORIG )) ] \
    && pass "owner counts S1 again: live symbols ${LIVE_BEFORE} -> ${LIVE_AFTER} (+${S1_ORIG})" \
    || fail "owner live symbols ${LIVE_BEFORE} -> ${LIVE_AFTER:-?}, expected +${S1_ORIG}"
S1_NOW=$(block_symbols_on "$S1" "$BLOCK")
S1_ACC=$(log_since "$S1" "$L_S1" | grep -a "SymbolOffer accepted" | grep -ac "block_id=$BSHORT" || true)
[ "$S1_NOW" -eq "$S1_ORIG" ] && [ "${S1_ACC:-0}" -eq 0 ] \
    && pass "S1 holds exactly its original ${S1_ORIG} .bin, no accepted offer since the silence" \
    || fail "S1 holds ${S1_NOW} .bin (orig ${S1_ORIG}), ${S1_ACC} accepted offer(s) since the silence"
[ "$(block_symbols_on "$S2" "$BLOCK")" -eq 0 ] && pass "S2 (still silent) holds 0 .bin of the block" \
    || fail "S2 got symbols of the block"

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo "Logs: $TEST_DIR/node-*/daemon.log"
[ "$FAIL" -eq 0 ]
