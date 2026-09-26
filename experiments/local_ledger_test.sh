#!/bin/bash
# Viaticum: the 4R pair ledger records confirmed service, not belief.
# Local processes on one machine (no Docker).
#
# Scenario:     7 independent owners star-connected to node-00, the owner O. O backs up one
#               256 KB .txt file. node-01..05 run at time_scale 100000 and answer PoS; node-06
#               (S) runs at time_scale 1: it accepts and stores symbols but reads its mailbox
#               only at startup and then hourly, so no challenge reaches it within the run. One
#               honest holder P proves the block; O is restarted mid-service; then P is
#               SIGKILLed and goes silent. O's per-pair ledger (4R recorder, decides nothing) is
#               read from O's `pair-ledger row` debug lines (RUST_LOG=info,viaticum::ledger=debug
#               on O).
# Intent:       4r-i1, 4r-i2, 4r-i3, 4r-i4, 4r-i5, 4r-i6 (only when step 5 takes the "long" branch;
#               otherwise i6 rests on unit C-16)
# Proves:       on O: S (accepted, never answered) accrues nothing (v_dem, g_they, depth,
#               observed_tau all 0 while believed_gb > 0); P's v_dem snaps to exactly its
#               confirmed volume on its first confirmed row and never drops below it; P stays
#               confirmed on every row while alive; observed_tau grows by observed days only,
#               so a short owner outage adds exactly one observed window (a long one ends the
#               run); after P dies its confirmation ends by the confirmation window (pass age
#               <= 15 s, before the owner's PoS timeout for P), the run resets
#               (observed_tau = observed_volume = 0) and v_dem melts strictly, stays > 0 and
#               inside [V*(1 - l_dem*T), V*exp(-l_dem*T)]. Cross-node: S's symbols are on S's
#               own disk and S's log has no PoS response; P's log has PoS responses for the
#               block; O challenged S and never resolved a response from it.
# Adversarial:  a freeloading holder (S stores, never proves); owner SIGTERM + restart with a
#               >= 4 s outage mid-service, the owner rejoining on its own (auto-redial);
#               SIGKILL of the proving holder P.
# Cannot close: the ledger is O's local view and no other node can read it (compensated by
#               two holders with opposite behaviour under the same belief, and by holder-side
#               logs and disks); real time (weekly PoS, W_conf = 14 d 3 h, laptop-sleep bias):
#               at 100000 the 1 s timer floor compresses everything and the observed window is
#               formal; per-master summing over cluster siblings (unit D-2 only); DR carriage
#               of the ledger (pair_ledger.md R2); "the ledger decides nothing" in general
#               (grep + unchanged regression suite only); clock jumps (units T-3, C-9); a
#               holder answering with a wrong hash (Fail -> Lost); the "we store for them" axis;
#               the step in every series once Bug-B (PoS of SystemState blocks) is fixed —
#               confirmed_gb of every pair jumps by its SS volume that day (matters for the
#               В-3½ sweep); S's believed_gb may come from O's SS blocks, so it is not
#               attributed to the user block (the guard for "S accepted the user block" is
#               S's own disk in step 2).
# Steps:        1. start 7 daemons (S at time_scale 1), star-connect -> O has 6 authenticated
#                    peers and, within 10 s, `pair-ledger row` lines for all 6 peer masters
#                    (4r-i5) — check: wait_auth_peers; set of master= == node_identity[0:16]
#                    of node-01..06
#               2. O writes the file -> restorable within 60 s; S holds >= 1 symbol of the
#                    block on its own disk; >= 1 of node-01..05 holds symbols (4r-i1, 4r-i5)
#                    — check: wait_file_restorable, block_symbols_on; no S placement =
#                    FAIL(setup), not skip
#               3. P = lowest-index honest holder with `mailbox PosResponse resolved` +
#                    outcome=Pass for the block in O's log within 30 s; P's own log has
#                    `responding with chain hash` for the block; O's P rows: the first row with
#                    confirmed_gb > 0 has v_dem == confirmed_gb (same text); every row
#                    v_dem >= confirmed_gb; wait for 20 confirmed rows (deadline 40 s):
#                    observed_tau and g_they strictly increase; blinks (confirmed_gb = 0 after
#                    the first confirmed row) 0 -> PASS, >= 1 -> ROUGH, > 20 % -> FAIL
#                    (4r-i2, 4r-i3, 4r-i4) — check: grep + awk over O's log
#               4. S: O issued >= 1 challenge to S's device and resolved none from it; S's log
#                    has no `responding with chain hash`; every S row on O has confirmed_gb =
#                    v_dem = g_they = depth = observed_tau = 0, and >= 1 row has
#                    believed_gb > 0 (4r-i1; believed_gb is not attributed to the user block,
#                    see Cannot close) — check: logs of O and S
#               5. [adversarial] right after a fresh P Pass in O's log: SIGTERM O (clean
#                    stop since R1-a), wait for exit (<= 15 s, else FAIL(setup)), keep it
#                    down >= 4 s since SIGTERM, restart with the same args, log appended
#                    (split O's log at the line count taken before the restart); NO explicit
#                    `connect`: O must rejoin on its own (auto-redial, R1-a) —
#                    wait_auth_peers 6 within 30 s, else FAIL "auto-redial" (network-i*
#                    promise, not a ledger one). First P row after restart: dt_days > 3.4722 (a dark
#                    part existed). Branch on the age of P's last pre-stop Pass at that row
#                    (log timestamps): age <= 11 s -> short outage (4r-i4): confirmed_gb > 0,
#                    observed_tau rose by 3.4722222 (+-1e-9), observed_volume and v_dem
#                    unchanged; age >= 14 s -> long outage (4r-i6): confirmed_gb = 0,
#                    observed_tau = observed_volume = 0, 0 < v_dem < V; 11-14 s ->
#                    inconclusive. Long or inconclusive branch -> ROUGH ("4r-i4 door not
#                    exercised"), a wrong answer in either branch -> FAIL. Then >= 1 P Pass in
#                    O's log after the restart (deadline 30 s) is required before step 6;
#                    blinks between restart and that Pass -> ROUGH, not FAIL (4r-i4, 4r-i6,
#                    4r-i2)
#               6. after >= 5 confirmed P rows following the post-restart Pass: SIGKILL P. On
#                    the FIRST P row with confirmed_gb = 0: (a) age of P's last Pass (O's
#                    `mailbox PosResponse resolved ... outcome=Pass` timestamp) <= 15 s
#                    (window 12 + tick 1 + slack); (b) the row precedes O's first
#                    `PoS challenge timed out` line for P's device after the kill, i.e. the
#                    user-block placement was still Alive, so the confirmation window ended
#                    it, not the status machine (timeout expected at ~18-19 s); believed_gb > 0
#                    on it too (weak alone: P also holds O's never-challenged SS blocks);
#                    (c) observed_tau = observed_volume = 0. Deadline measured as pass age
#                    (30 s). Also: no P Pass in O's log after the kill; `kill -0` on P's pid
#                    fails (4r-i3, 4r-i4)
#               7. from the last confirmed P row A (v_dem = V) over >= 10 later rows to B:
#                    v_dem strictly decreases row to row, v_B > 0,
#                    V*(1 - l_dem*sum_dt) <= v_B <= V*exp(-l_dem*sum_dt), l_dem = 1/365 (keep in
#                    sync with PAIR_LEDGER_LAMBDA_DEM), sum_dt = sum of dt_days of rows after A;
#                    g_they strictly decreases (4r-i2) — check: awk
#               8. whole run: S rows still all zero; rows for all 6 masters continue after the
#                    restart (4r-i1, 4r-i5)
#
# Implementation notes (how the passport is executed, not what it claims):
#   - The log is split at the line count taken right BEFORE the restarted O is launched
#     (the SIGTERM line count is recorded too): a row O may still log while shutting down
#     is pre-restart, and must not be read as "the first row after the restart".
#   - Step 6 kills P right after a FRESH P Pass (as step 5 does for O): the next challenge
#     is then >= 6 s away, so no answer of P can still be in flight in a mailbox — that is
#     what makes "no P Pass after the kill" a check and not a race.
#   - The owner's outage in step 5 is measured from SIGTERM and includes the clean-stop
#     drain (up to SHUTDOWN_DRAIN = 10 s): a slow stop pushes the pass age past 11 s and the
#     step into the "long"/"inconclusive" branch (ROUGH, not FAIL). The rejoin after the
#     restart is the daemon's own auto-redial; the script never calls `connect` there.
#   - Verdicts per step: PASS / ROUGH / FAIL. Exit code: 0 PASS, 3 ROUGH, 1 FAIL
#     (run_e2e.sh logs 3 as pass-rough).
#
# Usage:
#   private/testing/run_e2e.sh ledger          # on the build server (release build)
#   bash experiments/local_ledger_test.sh      # with ./target/release/viaticum present

set -uo pipefail
# awk/printf must print "1.5", never "1,5": the log parsing below does arithmetic on text.
export LC_ALL=C

NUM_NODES=7
TIME_SCALE=100000
S_IDX=6                       # the freeloader: time_scale 1
S_TIME_SCALE=1
O_RUST_LOG="info,viaticum::ledger=debug"
H_RUST_LOG="info,viaticum::daemon::processor::pos=debug"
# Keep in sync with the code (the scenario is the guard of these numbers):
#   PAIR_LEDGER_LAMBDA_DEM = 1/365; observed window at 100000 = 3 * 100000 / 86400 days.
L_DEM="0.0027397260273972603"   # 1/365
OBS_WINDOW="3.4722222222222223"  # observed_window_days(100000)
TEST_DIR="/tmp/viaticum-ledger-$$"
BINARY="${BINARY:-viaticum}"
T_BASE=$(date -u +%s)

PIDS=()
declare -A VERDICT
STEP_ORDER=(1 2 3 4 5 6 7 8)
CUR_STEP=0

rank() { case "$1" in PASS) echo 0 ;; ROUGH) echo 1 ;; *) echo 2 ;; esac; }
# verdict STEP PASS|ROUGH|FAIL MESSAGE — a step's verdict is the worst of its checks.
verdict() {
    local step="$1" v="$2" msg="$3" cur
    echo "  $v [step $step]: $msg"
    cur="${VERDICT[$step]:-}"
    if [ -z "$cur" ] || [ "$(rank "$v")" -gt "$(rank "$cur")" ]; then
        VERDICT[$step]="$v"
    fi
}
pass() { verdict "$CUR_STEP" PASS "$1"; }
rough() { verdict "$CUR_STEP" ROUGH "$1"; }
fail() { verdict "$CUR_STEP" FAIL "$1"; }

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
    local raw=""
    for _ in $(seq 1 20); do
        raw=$(run_cli_q "$1" status 2>/dev/null | grep "addr:" | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$raw" ] && break
        sleep 0.5
    done
    [ -n "$raw" ] && echo "$raw" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

start_node() { # IDX SCALE RUST_LOG — appends to the node's log
    local idx="$1" scale="$2" filter="$3"
    RUST_LOG="$filter" "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$scale" --watch-dir "$(node_dir "$idx")/files" \
        >> "$(node_log "$idx")" 2>&1 &
    PIDS[$idx]=$!
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

# ── Log parsing ─────────────────────────────────────────────────
#
# events FILE PATTERN KEY... -> one line per log line containing PATTERN:
#   "<t> <line> <value of KEY1> <value of KEY2> ..."   ("-" for a missing key)
# t = seconds since T_BASE from the log's own RFC 3339 UTC timestamp; line = line number
# in FILE. ANSI colour codes are stripped first.
AWK_EPOCH='
function epoch(ts,   y, mo, d, h, mi, s, yy, era, yoe, doy, doe) {
    y = substr(ts, 1, 4) + 0; mo = substr(ts, 6, 2) + 0; d = substr(ts, 9, 2) + 0
    h = substr(ts, 12, 2) + 0; mi = substr(ts, 15, 2) + 0
    s = substr(ts, 18); sub(/Z$/, "", s); s = s + 0
    yy = y - (mo <= 2 ? 1 : 0)
    era = int(yy / 400); yoe = yy - era * 400
    doy = int((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s
}'
events() {
    local file="$1" pat="$2"; shift 2
    sed 's/\x1b\[[0-9;]*m//g' "$file" 2>/dev/null | awk -v pat="$pat" -v keys="$*" \
        -v base="$T_BASE" "$AWK_EPOCH"'
        index($0, pat) {
            n = split(keys, K, " ")
            split("", kv)
            for (i = 2; i <= NF; i++) {
                p = index($i, "=")
                if (p > 1) kv[substr($i, 1, p - 1)] = substr($i, p + 1)
            }
            out = sprintf("%.3f %d", epoch($1) - base, NR)
            for (j = 1; j <= n; j++) out = out " " ((K[j] in kv) ? kv[K[j]] : "-")
            print out
        }' || true
}
now_t() { echo "$(( $(date -u +%s) - T_BASE ))"; }
log_lines() { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

O_LOG=""   # set after setup
# ledger_rows MASTER16 [AFTER_LINE] [UP_TO_LINE] -> rows of O's ledger for that master:
#   1 t  2 line  3 dt_days  4 believed_gb  5 confirmed_gb  6 v_dem  7 g_they  8 depth
#   9 observed_volume  10 observed_tau
ledger_rows() {
    events "$O_LOG" "pair-ledger row" master dt_days believed_gb confirmed_gb v_dem g_they \
        depth observed_volume observed_tau \
        | awk -v m="$1" -v lo="${2:-0}" -v hi="${3:-999999999}" \
            '$3 == m && ($2 + 0) > lo && ($2 + 0) <= hi \
             { print $1, $2, $4, $5, $6, $7, $8, $9, $10, $11 }' || true
}
# passes_of DEV16 [AFTER_LINE] -> "t line" of O's resolved Pass lines for the block from DEV.
passes_of() {
    events "$O_LOG" "mailbox PosResponse resolved" block_id holder outcome \
        | awk -v b="$BSHORT" -v h="$1" -v lo="${2:-0}" \
            '$3 == b && $4 == h && $5 == "Pass" && ($2 + 0) > lo { print $1, $2 }' || true
}
resolved_from() { # DEV16 -> count of resolved responses (any block, any outcome) from DEV
    events "$O_LOG" "mailbox PosResponse resolved" holder \
        | awk -v h="$1" '$3 == h' | wc -l | tr -d ' '
}
challenges_to() { # DEV16 -> count of challenges for the block issued to DEV
    events "$O_LOG" "PoS hash challenge issued via mailbox" block_id holder_id \
        | awk -v b="$BSHORT" -v h="$1" '$3 == b && $4 == h' | wc -l | tr -d ' '
}
timeouts_of() { # DEV16 AFTER_LINE -> "t line" of O's PoS timeouts for DEV after the line
    events "$O_LOG" "PoS challenge timed out" block_id holder_id \
        | awk -v h="$1" -v lo="$2" '$4 == h && ($2 + 0) > lo { print $1, $2 }' || true
}
chain_hash_answers() { # IDX -> count of `responding with chain hash` for the block in IDX's log
    sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null \
        | grep -a "responding with chain hash" | grep -ac "$BSHORT" || true
}

finish() {
    echo ""
    echo "============================================================"
    local overall=PASS s v
    for s in "${STEP_ORDER[@]}"; do
        v="${VERDICT[$s]:-FAIL}"
        [ -z "${VERDICT[$s]:-}" ] && v="FAIL (not reached)"
        echo "  step $s: $v"
        [ "$(rank "${v%% *}")" -gt "$(rank "$overall")" ] && overall="${v%% *}"
    done
    echo "  RESULT: $overall"
    echo "============================================================"
    echo "Logs: $TEST_DIR/node-*/daemon.log"
    # Exit code carries the verdict to run_e2e.sh: 0 PASS, 3 ROUGH, 1 FAIL.
    case "$overall" in
        PASS) exit 0 ;;
        ROUGH) exit 3 ;;
        *) exit 1 ;;
    esac
}

echo "============================================================"
echo "  Viaticum: 4R pair ledger — confirmation, ratchet, run"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE} (node-0${S_IDX}: ${S_TIME_SCALE})"
echo "============================================================"

# ── STEP 1: setup, star connect, a ledger row per peer master ──────────
CUR_STEP=1
echo ""
echo "=== Step 1: start, star-connect, ledger rows for all 6 peer masters ==="
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES - 1))); do
    mkdir -p "$(node_dir "$i")/files"
    run_cli "$i" init > /dev/null 2>&1
    # As local_pos_repair_test, without [escrow]: this scenario restores nothing.
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF
done
start_node 0 "$TIME_SCALE" "$O_RUST_LOG"
for i in $(seq 1 $((NUM_NODES - 1))); do
    if [ "$i" -eq "$S_IDX" ]; then
        start_node "$i" "$S_TIME_SCALE" "$H_RUST_LOG"
    else
        start_node "$i" "$TIME_SCALE" "$H_RUST_LOG"
    fi
done
O_LOG=$(node_log 0)
for i in $(seq 0 $((NUM_NODES - 1))); do
    wait_daemon "$i" || { fail "node-0$i did not start"; finish; }
done
declare -A ADDR MASTER DEV
for i in $(seq 0 $((NUM_NODES - 1))); do
    ADDR[$i]=$(get_addr "$i")
    MASTER[$i]=$(api_get "$i" /api/status | jq -r '.node_identity // empty' | cut -c1-16)
    DEV[$i]=$(api_get "$i" /api/status | jq -r '.device_id // empty')
    if [ -z "${ADDR[$i]}" ] || [ -z "${MASTER[$i]}" ] || [ -z "${DEV[$i]}" ]; then
        fail "node-0$i: missing addr/identity/device (${ADDR[$i]:-?} ${MASTER[$i]:-?} ${DEV[$i]:-?})"
        finish
    fi
    info "node-0$i master=${MASTER[$i]} device=${DEV[$i]}"
done
# S is connected like everyone else, after its startup mailbox poll already ran (its
# `wait_daemon` above), so the next poll that could fetch a challenge is an hour away.
for i in $(seq 1 $((NUM_NODES - 1))); do
    run_cli_q "$i" connect "${ADDR[0]}" > /dev/null
done
if wait_auth_peers 0 $((NUM_NODES - 1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: $(status_num 0 peer_count_authenticated)/$((NUM_NODES - 1)) authenticated after 30 s"
    finish
fi
WANT_MASTERS=$(for i in $(seq 1 $((NUM_NODES - 1))); do echo "${MASTER[$i]}"; done | sort | tr '\n' ' ')
GOT_MASTERS=""
for _ in $(seq 1 10); do
    GOT_MASTERS=$(events "$O_LOG" "pair-ledger row" master | awk '{print $3}' | sort -u | tr '\n' ' ')
    [ "$GOT_MASTERS" = "$WANT_MASTERS" ] && break
    sleep 1
done
if [ "$GOT_MASTERS" = "$WANT_MASTERS" ]; then
    pass "pair-ledger rows on O for exactly the 6 peer masters (4r-i5)"
else
    fail "pair-ledger masters on O: [${GOT_MASTERS}] want [${WANT_MASTERS}] (10 s after auth)"
fi

# ── STEP 2: backup; S and an honest holder hold symbols on their own disks ──
CUR_STEP=2
echo ""
echo "=== Step 2: backup — S and an honest holder hold the block ==="
FILE="$(node_dir 0)/files/ledger_test.txt"   # .txt = importance 1.0
head -c 196608 /dev/urandom | base64 -w 0 > "$FILE"   # ~256 KB of text
if wait_file_restorable 0 "$FILE" 60; then
    pass "file backed up and restorable per owner"
else
    fail "file not restorable per owner after 60 s (4r-i5: did placement start reading the ledger?)"
    finish
fi
BLOCK=$(file_block_hex 0 "$FILE")
BSHORT=${BLOCK:0:16}
info "block: $BLOCK"
# "Restorable" needs only k_eff symbols on Alive placements, so it can be reached before
# every holder's transfer finished: poll S's own disk with a deadline instead of reading
# it once.
S_SYMS=0
for _ in $(seq 1 30); do
    S_SYMS=$(block_symbols_on "$S_IDX" "$BLOCK")
    [ "$S_SYMS" -gt 0 ] && break
    sleep 1
done
HONEST=()
for i in $(seq 1 $((NUM_NODES - 1))); do
    [ "$i" -eq "$S_IDX" ] && continue
    n=$(block_symbols_on "$i" "$BLOCK")
    info "node-0$i holds $n symbols of the block"
    [ "$n" -gt 0 ] && HONEST+=("$i")
done
info "node-0$S_IDX (S) holds $S_SYMS symbols of the block"
if [ "$S_SYMS" -gt 0 ]; then
    pass "S holds $S_SYMS symbols of the user block on its own disk (4r-i1 premise)"
else
    fail "FAIL(setup): no symbol of the block on S's disk 30 s after restorable — the freeloader case cannot be exercised"
fi
if [ "${#HONEST[@]}" -ge 1 ]; then
    pass "${#HONEST[@]} honest holder(s) hold symbols: $(printf 'node-0%s ' "${HONEST[@]}")"
else
    fail "FAIL(setup): no honest holder holds symbols of the block"
    finish
fi

# ── STEP 3: P proves the block; its ledger row snaps, stays confirmed, grows ──
CUR_STEP=3
echo ""
echo "=== Step 3: P proves the block — v_dem snaps, the run grows, no blinks ==="
P=""
for _ in $(seq 1 30); do
    for i in "${HONEST[@]}"; do
        if [ -n "$(passes_of "${DEV[$i]}")" ]; then P="$i"; break; fi
    done
    [ -n "$P" ] && break
    sleep 1
done
if [ -z "$P" ]; then
    fail "no honest holder's PoS for block $BSHORT.. resolved as Pass in O's log within 30 s"
    finish
fi
PM="${MASTER[$P]}"
PD="${DEV[$P]}"
pass "P = node-0$P (master $PM, device $PD): Pass resolved on O"
if [ "$(chain_hash_answers "$P")" -ge 1 ]; then
    pass "P's own log: responded with a chain hash for $BSHORT.. ($(chain_hash_answers "$P")x)"
else
    fail "P's own log has no 'responding with chain hash' for $BSHORT.."
fi
# Wait for 20 confirmed rows from the first confirmed one.
FIRST_CONF_LINE=""
for _ in $(seq 1 40); do
    FIRST_CONF_LINE=$(ledger_rows "$PM" | awk '($5 + 0) > 0 { print $2; exit }')
    if [ -n "$FIRST_CONF_LINE" ]; then
        n=$(ledger_rows "$PM" "$((FIRST_CONF_LINE - 1))" | awk '($5 + 0) > 0' | wc -l)
        [ "$n" -ge 20 ] && break
    fi
    sleep 1
done
if [ -z "$FIRST_CONF_LINE" ]; then
    fail "no P row with confirmed_gb > 0 on O within 40 s (confirmation never reached the ledger)"
    finish
fi
FIRST_ROW=$(ledger_rows "$PM" "$((FIRST_CONF_LINE - 1))" | head -1)
echo "    first confirmed P row: $FIRST_ROW"
if [ "$(echo "$FIRST_ROW" | awk '{print $6}')" = "$(echo "$FIRST_ROW" | awk '{print $5}')" ]; then
    pass "first confirmed row: v_dem == confirmed_gb == $(echo "$FIRST_ROW" | awk '{print $5}') (same text, AC-3a)"
else
    fail "first confirmed row: v_dem $(echo "$FIRST_ROW" | awk '{print $6}') != confirmed_gb $(echo "$FIRST_ROW" | awk '{print $5}')"
fi
# Window of the check: from the first confirmed row to the 20th confirmed one.
WIN=$(ledger_rows "$PM" "$((FIRST_CONF_LINE - 1))" \
    | awk '{ print } ($5 + 0) > 0 { c++ } c >= 20 { exit }')
STATS=$(echo "$WIN" | awk '
    { n++; conf = ($5 + 0) > 0
      if (($6 + 0) < ($5 + 0)) below++
      if (!conf) blinks++
      if (conf && prevconf) {
          if (!(($10 + 0) > ptau)) tau_bad++
          if (!(($7 + 0) > pg)) g_bad++
      }
      if (conf) confs++
      prevconf = conf; ptau = $10 + 0; pg = $7 + 0 }
    END { printf "%d %d %d %d %d %d", n, confs, blinks + 0, below + 0, tau_bad + 0, g_bad + 0 }')
read -r W_N W_CONF W_BLINK W_BELOW W_TAU W_G <<< "$STATS"
info "P rows: $W_N in window, $W_CONF confirmed, $W_BLINK blinks"
[ "$W_CONF" -ge 20 ] && pass "20 confirmed P rows within 40 s" \
    || fail "only $W_CONF confirmed P rows within 40 s (W_conf applied twice? 4r-i3)"
[ "$W_BELOW" -eq 0 ] && pass "every P row has v_dem >= confirmed_gb (AC-3d)" \
    || fail "$W_BELOW P row(s) with v_dem < confirmed_gb"
[ "$W_TAU" -eq 0 ] && pass "observed_tau strictly increases over consecutive confirmed rows" \
    || fail "$W_TAU consecutive confirmed P row pair(s) where observed_tau did not grow"
[ "$W_G" -eq 0 ] && pass "g_they strictly increases over consecutive confirmed rows" \
    || fail "$W_G consecutive confirmed P row pair(s) where g_they did not grow"
if [ "$W_BLINK" -eq 0 ]; then
    pass "no blinks: P confirmed on every row (4r-i3)"
elif [ $((W_BLINK * 5)) -gt "$W_N" ]; then
    fail "$W_BLINK blinks in $W_N rows (> 20 %): an always-on holder falls out of confirmation"
else
    rough "$W_BLINK blink(s) in $W_N rows (<= 20 %): PoS cycle vs W_conf margin under load"
fi

# ── STEP 4: S — challenged, never answered, accrues nothing ─────────────
CUR_STEP=4
echo ""
echo "=== Step 4: S (accepted, never answered) accrues nothing ==="
SD="${DEV[$S_IDX]}"
SM="${MASTER[$S_IDX]}"
S_CHAL=0
for _ in $(seq 1 20); do
    S_CHAL=$(challenges_to "$SD")
    [ "$S_CHAL" -ge 1 ] && break
    sleep 1
done
[ "$S_CHAL" -ge 1 ] && pass "O issued $S_CHAL challenge(s) for $BSHORT.. to S's device" \
    || fail "O issued no challenge for $BSHORT.. to S within 20 s — 'asked and never answered' is not shown"
S_RES=$(resolved_from "$SD")
[ "$S_RES" -eq 0 ] && pass "O resolved no PoS response from S" \
    || fail "O resolved $S_RES PoS response(s) from S — S is not a freeloader in this run"
S_ANS=$(chain_hash_answers "$S_IDX")
[ "$S_ANS" -eq 0 ] && pass "S's own log: no 'responding with chain hash'" \
    || fail "S's own log: $S_ANS chain-hash answers for $BSHORT.."
check_s_rows() { # prints "rows nonzero believed>0"
    ledger_rows "$SM" | awk '
        { n++
          if (($5 + 0) != 0 || ($6 + 0) != 0 || ($7 + 0) != 0 || ($8 + 0) != 0 || ($10 + 0) != 0) bad++
          if (($4 + 0) > 0) believed++ }
        END { printf "%d %d %d", n + 0, bad + 0, believed + 0 }'
}
read -r S_N S_BAD S_BEL <<< "$(check_s_rows)"
if [ "$S_N" -ge 1 ] && [ "$S_BAD" -eq 0 ]; then
    pass "all $S_N S rows: confirmed_gb = v_dem = g_they = depth = observed_tau = 0 (4r-i1)"
else
    fail "S rows: $S_N total, $S_BAD with non-zero service ($(ledger_rows "$SM" | awk '($6 + 0) != 0' | head -1))"
fi
[ "$S_BEL" -ge 1 ] && pass "$S_BEL S row(s) with believed_gb > 0 — belief without proof" \
    || fail "no S row with believed_gb > 0: the freeloader's placements never reached the sweep"

# ── STEP 5: owner outage (SIGTERM + restart) mid-service ─────────────────
CUR_STEP=5
echo ""
echo "=== Step 5: owner SIGTERM + restart mid-service, rejoin by auto-redial ==="
N_PASS=$(passes_of "$PD" | wc -l)
FRESH=""
for _ in $(seq 1 30); do
    [ "$(passes_of "$PD" | wc -l)" -gt "$N_PASS" ] && { FRESH=1; break; }
    sleep 0.5
done
[ -n "$FRESH" ] || { fail "FAIL(setup): no fresh P Pass within 15 s to stop O after"; finish; }
LINES_AT_SIGTERM=$(log_lines "$O_LOG")
T_SIGTERM=$(date -u +%s)
kill -TERM "${PIDS[0]}" 2>/dev/null
EXITED=""
for _ in $(seq 1 30); do
    kill -0 "${PIDS[0]}" 2>/dev/null || { EXITED=1; break; }
    sleep 0.5
done
if [ -z "$EXITED" ]; then
    kill -9 "${PIDS[0]}" 2>/dev/null
    fail "FAIL(setup): O did not exit within 15 s of SIGTERM (clean stop, R1-a)"
    finish
fi
wait "${PIDS[0]}" 2>/dev/null
O_EXIT=$?
info "O exited (code $O_EXIT) $(( $(date -u +%s) - T_SIGTERM )) s after SIGTERM"
[ "$O_EXIT" -eq 0 ] || fail "O exited with code $O_EXIT on SIGTERM (R1-a promises a clean stop = 0)"
while [ $(( $(date -u +%s) - T_SIGTERM )) -lt 4 ]; do sleep 0.2; done  # the outage itself
LINES_AT_RESTART=$(log_lines "$O_LOG")
info "O's log: $LINES_AT_SIGTERM lines at SIGTERM, $LINES_AT_RESTART at restart"
T_RESTART=$(date -u +%s)
start_node 0 "$TIME_SCALE" "$O_RUST_LOG"
wait_daemon 0 || { fail "FAIL(setup): O did not come back"; finish; }
# No `connect` here: the restarted owner must find its peers by itself (auto-redial, R1-a).
if wait_auth_peers 0 $((NUM_NODES - 1)) 30; then
    pass "O rejoined on its own: $(status_num 0 peer_count_authenticated) authenticated peers $(( $(date -u +%s) - T_RESTART )) s after restart (auto-redial)"
else
    fail "auto-redial: O has $(status_num 0 peer_count_authenticated)/$((NUM_NODES - 1)) authenticated peers 30 s after restart without an explicit connect (R1-a promise broken)"
fi
PRE=$(ledger_rows "$PM" 0 "$LINES_AT_RESTART" | tail -1)
POST=""
for _ in $(seq 1 15); do
    POST=$(ledger_rows "$PM" "$LINES_AT_RESTART" | head -1)
    [ -n "$POST" ] && break
    sleep 1
done
echo "    last P row before stop: $PRE"
echo "    first P row after restart: $POST"
if [ -z "$PRE" ] || [ -z "$POST" ]; then
    fail "missing P rows around the restart (pre='$PRE' post='$POST')"
    finish
fi
POST_T=$(echo "$POST" | awk '{print $1}')
POST_LINE=$(echo "$POST" | awk '{print $2}')
LAST_PASS_T=$(passes_of "$PD" | awk -v l="$POST_LINE" '($2 + 0) < l { t = $1; ln = $2 } END { print t }')
LAST_PASS_LINE=$(passes_of "$PD" | awk -v l="$POST_LINE" '($2 + 0) < l { ln = $2 } END { print ln }')
AGE=$(awk -v a="$POST_T" -v b="$LAST_PASS_T" 'BEGIN { printf "%.3f", a - b }')
PASS_WHEN=pre-stop; [ "${LAST_PASS_LINE:-0}" -gt "$LINES_AT_RESTART" ] && PASS_WHEN=post-restart
info "age of P's last Pass ($PASS_WHEN) at the first post-restart row: ${AGE} s"
if awk -v dt="$(echo "$POST" | awk '{print $3}')" -v w="$OBS_WINDOW" 'BEGIN { exit !(dt > w) }'; then
    pass "first post-restart P row has dt_days $(echo "$POST" | awk '{print $3}') > observed window $OBS_WINDOW (a dark part existed)"
else
    fail "first post-restart P row has dt_days $(echo "$POST" | awk '{print $3}') <= $OBS_WINDOW: no outage was recorded"
fi
BRANCH=$(awk -v a="$AGE" 'BEGIN { if (a <= 11) print "short"; else if (a >= 14) print "long"; else print "inconclusive" }')
case "$BRANCH" in
short)
    OK=$(awk -v pre="$PRE" -v post="$POST" -v w="$OBS_WINDOW" 'BEGIN {
        split(pre, a, " "); split(post, b, " ")
        d = (b[10] + 0) - (a[10] + 0) - (w + 0); if (d < 0) d = -d
        ok = ((b[5] + 0) > 0) && (d <= 1e-9) && (b[9] == a[9]) && (b[6] == a[6])
        print ok ? "1" : "0" }')
    if [ "$OK" = 1 ]; then
        pass "short outage (4r-i4): still confirmed, observed_tau +$OBS_WINDOW exactly, observed_volume and v_dem unchanged"
    else
        fail "short outage (4r-i4): wrong row — want confirmed > 0, Δobserved_tau = $OBS_WINDOW, observed_volume/v_dem unchanged"
    fi
    ;;
long)
    OK=$(awk -v pre="$PRE" -v post="$POST" 'BEGIN {
        split(pre, a, " "); split(post, b, " ")
        ok = ((b[5] + 0) == 0) && ((b[10] + 0) == 0) && ((b[9] + 0) == 0) \
             && ((b[6] + 0) > 0) && ((b[6] + 0) < (a[6] + 0))
        print ok ? "1" : "0" }')
    if [ "$OK" = 1 ]; then
        rough "long outage (4r-i6, age ${AGE} s): run ended, v_dem melted — correct, but the 4r-i4 door was not exercised"
    else
        fail "long outage (4r-i6, age ${AGE} s): want confirmed = observed_tau = observed_volume = 0, 0 < v_dem < V"
    fi
    ;;
*)
    rough "inconclusive pass age ${AGE} s (11-14 s): neither branch asserted — 4r-i4 door not exercised"
    ;;
esac
POST_PASS=""
for _ in $(seq 1 30); do
    POST_PASS=$(passes_of "$PD" "$LINES_AT_RESTART" | head -1)
    [ -n "$POST_PASS" ] && break
    sleep 1
done
if [ -z "$POST_PASS" ]; then
    fail "no P Pass on O within 30 s after the restart"
    finish
fi
POST_PASS_LINE=$(echo "$POST_PASS" | awk '{print $2}')
pass "P Pass resolved again after the restart"
BLINKS_RESTART=$(ledger_rows "$PM" "$LINES_AT_RESTART" "$POST_PASS_LINE" | awk '($5 + 0) == 0' | wc -l)
[ "$BLINKS_RESTART" -eq 0 ] && pass "no P blinks between the restart and P's next Pass" \
    || rough "$BLINKS_RESTART P blink(s) between the restart and P's next Pass (reconnect latency)"

# ── STEP 6: P dies; the confirmation window, not the status machine, ends it ──
CUR_STEP=6
echo ""
echo "=== Step 6: SIGKILL P — confirmation ends by the window ==="
for _ in $(seq 1 30); do
    [ "$(ledger_rows "$PM" "$POST_PASS_LINE" | awk '($5 + 0) > 0' | wc -l)" -ge 5 ] && break
    sleep 1
done
[ "$(ledger_rows "$PM" "$POST_PASS_LINE" | awk '($5 + 0) > 0' | wc -l)" -ge 5 ] \
    || { fail "FAIL(setup): fewer than 5 confirmed P rows after the post-restart Pass"; finish; }
N_PASS=$(passes_of "$PD" | wc -l)
FRESH=""
for _ in $(seq 1 30); do
    [ "$(passes_of "$PD" | wc -l)" -gt "$N_PASS" ] && { FRESH=1; break; }
    sleep 0.5
done
[ -n "$FRESH" ] || { fail "FAIL(setup): no fresh P Pass within 15 s to kill P after"; finish; }
LINES_AT_KILL=$(log_lines "$O_LOG")
kill -9 "${PIDS[$P]}" 2>/dev/null
wait "${PIDS[$P]}" 2>/dev/null
info "SIGKILL node-0$P at O log line $LINES_AT_KILL"
ZERO=""
while :; do
    ZERO=$(ledger_rows "$PM" "$LINES_AT_KILL" | awk '($5 + 0) == 0 { print; exit }')
    [ -n "$ZERO" ] && break
    LP_T=$(passes_of "$PD" | tail -1 | awk '{print $1}')
    if awk -v n="$(now_t)" -v p="$LP_T" 'BEGIN { exit !(n - p > 30) }'; then break; fi
    sleep 1
done
if [ -z "$ZERO" ]; then
    fail "P still confirmed 30 s after its last Pass (window not applied / not scaled? 4r-i3)"
    finish
fi
echo "    first unconfirmed P row: $ZERO"
Z_T=$(echo "$ZERO" | awk '{print $1}')
Z_LINE=$(echo "$ZERO" | awk '{print $2}')
LAST_T=$(passes_of "$PD" | awk -v l="$Z_LINE" '($2 + 0) < l { t = $1 } END { print t }')
Z_AGE=$(awk -v a="$Z_T" -v b="$LAST_T" 'BEGIN { printf "%.3f", a - b }')
awk -v a="$Z_AGE" 'BEGIN { exit !(a <= 15) }' \
    && pass "(a) P's last Pass was ${Z_AGE} s old on its first unconfirmed row (<= 15 s)" \
    || fail "(a) P's last Pass was ${Z_AGE} s old on its first unconfirmed row (> 15 s: window too long or unscaled)"
FIRST_TO=$(timeouts_of "$PD" "$LINES_AT_KILL" | head -1)
TO_LINE=$(echo "$FIRST_TO" | awk '{print $2}')
if [ -z "$FIRST_TO" ] || [ "$Z_LINE" -lt "$TO_LINE" ]; then
    pass "(b) the unconfirmed row precedes O's first PoS timeout for P (${FIRST_TO:-none yet}) — the window ended it"
else
    fail "(b) the unconfirmed row (line $Z_LINE) follows O's PoS timeout for P (line $TO_LINE) — the status machine ended it"
fi
awk -v b="$(echo "$ZERO" | awk '{print $4}')" 'BEGIN { exit !(b > 0) }' \
    && pass "(b) believed_gb > 0 on that row (placement still Alive)" \
    || fail "(b) believed_gb = 0 on that row: the placement had already left Alive"
awk -v r="$ZERO" 'BEGIN { split(r, z, " "); exit !((z[9] + 0) == 0 && (z[10] + 0) == 0) }' \
    && pass "(c) the run reset: observed_tau = observed_volume = 0" \
    || fail "(c) the run did not reset on an unconfirmed tail"
LATE=$(passes_of "$PD" "$LINES_AT_KILL" | wc -l)
[ "$LATE" -eq 0 ] && pass "no P Pass in O's log after the kill" \
    || fail "$LATE P Pass line(s) in O's log after the kill"
kill -0 "${PIDS[$P]}" 2>/dev/null && fail "P's process is still alive" || pass "P's process is gone"

# ── STEP 7: v_dem melts at λ_dem, not λ; g_they leaks ────────────────────
CUR_STEP=7
echo ""
echo "=== Step 7: v_dem melts at l_dem after P's death ==="
A_LINE=$(ledger_rows "$PM" 0 "$Z_LINE" | awk '($5 + 0) > 0 { l = $2 } END { print l }')
for _ in $(seq 1 30); do
    [ "$(ledger_rows "$PM" "$A_LINE" | wc -l)" -ge 10 ] && break
    sleep 1
done
MELT=$( { ledger_rows "$PM" "$((A_LINE - 1))" "$A_LINE"; ledger_rows "$PM" "$A_LINE" | head -10; } )
echo "$MELT" | sed 's/^/    | /'
RES=$(echo "$MELT" | awk -v l="$L_DEM" '
    NR == 1 { V = $6 + 0; pv = V; pg = $7 + 0; next }
    { n++; sum += $3 + 0
      if (!(($6 + 0) < pv)) vbad++
      if (!(($7 + 0) < pg)) gbad++
      pv = $6 + 0; pg = $7 + 0 }
    END {
      lo = V * (1 - l * sum); hi = V * exp(-l * sum)
      inb = (pv >= lo && pv <= hi)
      printf "%d %d %d %d %.17g %.17g %.17g %.17g", n + 0, vbad + 0, gbad + 0, inb, V, pv, lo, hi }')
read -r M_N M_VBAD M_GBAD M_IN M_V M_VB M_LO M_HI <<< "$RES"
info "A: V = $M_V; B (row $M_N after A): v_B = $M_VB; bounds [$M_LO, $M_HI]"
[ "$M_N" -ge 10 ] && pass "$M_N rows after the last confirmed one" \
    || fail "only $M_N P rows after the last confirmed one within 30 s"
[ "$M_VBAD" -eq 0 ] && pass "v_dem strictly decreases row to row (no pure max, 4r-i2)" \
    || fail "$M_VBAD row(s) where v_dem did not decrease"
awk -v v="$M_VB" 'BEGIN { exit !(v > 0) }' && pass "v_B > 0 (not reset, 4r-i2)" \
    || fail "v_B = $M_VB: the demonstrated scale was reset, not melted"
[ "$M_IN" -eq 1 ] && pass "v_B inside [V(1 - l_dem·Σdt), V·e^(-l_dem·Σdt)] — the leak is λ_dem, not λ" \
    || fail "v_B $M_VB outside [$M_LO, $M_HI]"
[ "$M_GBAD" -eq 0 ] && pass "g_they strictly decreases (no confirmed service)" \
    || fail "$M_GBAD row(s) where g_they did not decrease"

# ── STEP 8: whole run ─────────────────────────────────────────────────────
CUR_STEP=8
echo ""
echo "=== Step 8: whole run — S never accrued; all 6 masters still recorded ==="
read -r S_N S_BAD S_BEL <<< "$(check_s_rows)"
[ "$S_N" -ge 1 ] && [ "$S_BAD" -eq 0 ] \
    && pass "all $S_N S rows over the whole run are zero-service (4r-i1)" \
    || fail "S rows: $S_N total, $S_BAD with non-zero service"
POST_MASTERS=$(events "$O_LOG" "pair-ledger row" master \
    | awk -v lo="$LINES_AT_RESTART" '($2 + 0) > lo { print $3 }' | sort -u | tr '\n' ' ')
[ "$POST_MASTERS" = "$WANT_MASTERS" ] \
    && pass "rows for all 6 peer masters continue after the restart (4r-i5)" \
    || fail "post-restart masters [${POST_MASTERS}] want [${WANT_MASTERS}]"

finish
