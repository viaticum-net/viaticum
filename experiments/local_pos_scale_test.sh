#!/bin/bash
# Viaticum: PoS at scale — a holder computes each challenge once, the owner resolves every
# answer without channel loss, the issue tick stays short, DR readiness holds.
# Local processes on one machine (no Docker).
#
# Scenario:     10 nodes at time_scale 900, source block 1 MiB, star to node-00. Owner O
#               (node-00) seeds trust with 5 blocks, then backs up 1000 files (1000 blocks,
#               importance 0.2). Holders H1..H8 (node-01..08, soft quota 2 GB), H9 (node-09,
#               soft quota 0.2 GB) is a "daily laptop": SIGKILL, 66 s off, 30 s on, 28 cycles.
#               Nobody but O backs up. Four scaled weeks after the upload.
# Intent:       pos-i5, pos-i6, pos-i7, pos-i8; mailbox-i60 (step 7b); 4r-i113 (step 7,
#               A's checks 7a-7c)
# Proves:       holders compute each challenge once (their own logs, /proc/<pid>/io);
#               the owner resolves every answer without channel loss or stale WARNs (O's log);
#               the issue tick stays short, also with a stopped postman (O's log);
#               DR readiness holds (O's status); the laptop passes every day (O's log).
# Adversarial:  H9 SIGKILL schedule; H8 SIGSTOP/SIGCONT (sleeping laptop, half-open
#               connections); H1 restart mid-run (memory lost); O off for 5 min then restart
#               (everything due at once).
# Cannot close: T1 at 100k holdings (see СТ-L); healing of a response lost at every postman
#               (unit only); a world of 30-40; kernel sleep and Wi-Fi; clock jumps; the
#               laptop's online window is 30 s real = 7.5 scaled h (startup and transport are
#               real time, 4 scaled h would be shorter than the daemon's own start).
# Steps:        see the table in private/beta-planning/tasks/c_st0_pos_scale.md §2.
#               P0. init, configs, start 10 nodes, `connect` to node-00 -> within 120 s every
#                    node has peer_count_authenticated = 9, else FAIL(setup)
#               1a. O writes 5 x 1 MiB -> within 5 min O logs `mailbox PosResponse resolved
#                    outcome=Pass` from each of the 9 holders, else FAIL(setup)
#               0.  calibration, half a scaled week (336 s): R0(H) = 2 x rchar growth of H1..H8
#               1b. O writes 995 files -> within 60 min 1000 `backup: pipeline complete` lines and
#                    1000 files restorable on O, else FAIL(setup) with the pace (pace = NOTE)
#               2.  W1+W2: `scheduler: PoS issue tick` elapsed_ms p95 <= 800; gap between O's
#                    ledger accruals <= 12 s (pos-i7)
#               3.  W2, H1..H8, per challenge_id seen in W2: exactly 1 `responding with chain
#                    hash`; `PosResponse published` <= 4 + its 0-ack lines; every challenge first
#                    computed in [W2 start, W2 end - 200 s] has >= 1 `cached=true`; rchar growth
#                    <= 1.5 x sum(bytes of the block on H's disk per compute line of W2) + 1.5 x R0;
#                    `mailbox_poll: poll done` elapsed_ms p95 < 4000 (pos-i5)
#               4.  W2, O: every challenge issued in W2 to H1..H9 resolved by W2 end + 336 s;
#                    0 `PoS challenge timed out`; WARN `unknown challenge_id` <= timeouts (= 0);
#                    deferred_full sum = NOTE (pos-i6)
#               6.  W1..W3: O's dr_ready sampled every 30 s is true in every sample; before W1
#                    the first true within one scaled week, else FAIL "premise: DR did not become
#                    ready" (pos-i8)
#               7.  H9, 28 cycles over W1..W4: 0 timeouts to H9; >= 1 Pass from H9 on O in every
#                    online window; in every window H9 computes >= 90 % of its live challenges
#                    (issued by O to H9 in the 672 s before its start), < 90 % = FAIL "finding:
#                    the laptop does not keep up"; T_up = NOTE (4r-i113, pos-i5)
#               7b. W3: H8 SIGSTOP 66 s / SIGCONT 30 s, 7 cycles: issue tick elapsed_ms p95 <= 800;
#                    ledger gap <= 12 s; 0 timeouts to H8. Known: `poll done` elapsed_ms ~15000
#                    on every node while H8 is stopped -> ROUGH "known: poll waits for the slowest
#                    postman", not FAIL (pos-i7, mailbox-i60)
#               5.  W4 + 60 s: H1 SIGTERM, 10 s, start: challenges alive through the restart are
#                    computed exactly twice, the others once; rchar growth over the first poll
#                    with entries <= 1.5 x sum(bytes of the blocks of H1's live challenges) +
#                    1.5 x R0 x (elapsed / week); O: 0 timeouts to H1, WARN unknown <= timeouts
#                    (pos-i5, pos-i6)
#               8.  end of W4: O SIGTERM for 300 s (~3 scaled days), start: the first issue tick
#                    has due >= 0.8 x placements (elapsed_ms = NOTE); then half a week: 0
#                    timeouts, every new challenge resolved (+120 s margin), WARN unknown <=
#                    timeouts, ledger gap <= 12 s outside the first tick (the first = NOTE, K-5)
#                    (pos-i6, pos-i7)
#
# Pre-registered on the current code (СТ-0a in, СТ-0c not yet):
#   steps 2, 7b, 8 (issue-tick bars) are RED: the `scheduler: PoS issue tick` line comes with
#   СТ-0c. Step 4 is RED (the owner still forwards every live answer: WARN full / unknown
#   challenge_id). Step 5's owner half and step 8's WARN bar are RED for the same reason.
#   Step 3 and step 5's holder half are the СТ-0a proof. O's log grows by tens of MB per
#   minute until СТ-0c: run the baseline with STOP_AFTER=4.
#
# Implementation notes (how the passport is executed, not what it claims):
#   - "ledger accrual" is measured on O's `pair-ledger row` lines (target viaticum::ledger,
#     enabled by O's RUST_LOG): `scheduler: pair-ledger accrual tick` is a debug line of the
#     scheduler target, which O's pre-registered RUST_LOG does not enable. Every tick writes
#     one row per accrued pair, so the gap between rows is the gap between ticks.
#   - step 1b gates on "restorable" (>= k symbols on Alive placements, GET /api/files): the
#     status has no per-block ">= 1 Alive" count. Stronger than the passport's bar.
#   - step 4 matches an issue to its resolution by (block_id, holder): the issue line has no
#     challenge_id until СТ-0c, and one (block, holder) has at most one pending challenge.
#   - "challenge alive" on a holder is judged from the time the holder first computed it
#     (issue -> compute is a few polls): expiry ~ first compute + 672 s. Margins: 200 s for the
#     first cached re-publish (step 3), 60 s after the restart for "alive" (step 5).
#   - Lines 7a-7c (line A, 4r-i113) are appended after step 7 by line A (hook below).
#   - Verdicts per step: PASS / ROUGH / FAIL. Exit code: 0 PASS, 3 ROUGH, 1 FAIL.
#     STOP_AFTER=<step> (one of P0 1a 0 1b 2 3 4 7b 6 5 7 8, the evaluation order) ends the
#     run after that step; later steps print "not run" and do not count.
#   - The test dir is removed on PASS and kept otherwise.
#
# Usage:
#   private/testing/run_e2e.sh pos_scale          # on the build server (release build)
#   STOP_AFTER=4 bash experiments/local_pos_scale_test.sh

set -uo pipefail
export LC_ALL=C

NUM_NODES=10
TIME_SCALE=900
O=0
HS=(1 2 3 4 5 6 7 8)
H9=9
WEEK=672            # one scaled week at 900
HALF=336
H9_CYCLE=96         # SIGKILL, 66 s off, start, 30 s online
H9_OFF=66
H9_CYCLES=28
H8_STOP=66
H8_CYCLES=7
O_RUST_LOG="info,viaticum::ledger=debug"
H_RUST_LOG="info,viaticum::daemon::processor::pos=debug,viaticum::daemon::mailbox::poll=debug"
# Pre-registered dials (passport table; change only with a commit, before a run).
O_SOFT_GB="1.0"
H_SOFT_GB="2.0"
H9_SOFT_GB="0.2"
IMPORTANCE="0.2"
SEED_FILES=5
ALL_FILES=1000
MIB=1048576
MIN_FREE_GIB=20
BAR_TICK_MS=800
BAR_LEDGER_GAP=12
BAR_POLL_MS=4000
FIRST_CACHED_MARGIN=200
ALIVE_MARGIN=60
STEP8_MARGIN=120

E2E_BASE="${E2E_BASE:-$HOME/e2e-runs}"
TEST_DIR="$E2E_BASE/pos-scale-$$"
BINARY="${BINARY:-viaticum}"
T_BASE=$(date -u +%s)
STOP_AFTER="${STOP_AFTER:-}"

PIDS=()
BG_PIDS=()
declare -A VERDICT
STEP_ORDER=(P0 1a 0 1b 2 3 4 7b 6 5 7 8)
CUR_STEP=P0
STOPPED_AT=""
OVERALL=""

rank() { case "$1" in PASS) echo 0 ;; ROUGH) echo 1 ;; *) echo 2 ;; esac; }
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
note() { echo "  NOTE [step $CUR_STEP]: $1"; }

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }
run_cli() { local idx="$1"; shift; "$BINARY" --data-dir "$(node_dir "$idx")" "$@"; }
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    local pid
    for pid in "${BG_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    [ -f "$TEST_DIR/h9.pid" ] && PIDS[$H9]=$(cat "$TEST_DIR/h9.pid")
    [ -n "${PIDS[8]:-}" ] && kill -CONT "${PIDS[8]}" 2>/dev/null
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    echo "  Killed the daemons"
    if [ "$OVERALL" = "PASS" ]; then
        rm -rf "$TEST_DIR"
        echo "  PASS: removed $TEST_DIR"
    else
        echo "  Test dir kept: $TEST_DIR"
    fi
}
trap cleanup EXIT

finish() {
    echo ""
    echo "============================================================"
    local overall=PASS s v past=""
    for s in "${STEP_ORDER[@]}"; do
        if [ -n "$past" ]; then
            echo "  step $s: not run (STOP_AFTER=$STOPPED_AT)"
            continue
        fi
        v="${VERDICT[$s]:-}"
        [ -z "$v" ] && v="FAIL (not reached)"
        echo "  step $s: $v"
        [ "$(rank "${v%% *}")" -gt "$(rank "$overall")" ] && overall="${v%% *}"
        [ -n "$STOPPED_AT" ] && [ "$s" = "$STOPPED_AT" ] && past=1
    done
    echo "  RESULT: $overall"
    echo "============================================================"
    echo "Logs: $TEST_DIR/node-*/daemon.log"
    OVERALL="$overall"
    case "$overall" in
        PASS) exit 0 ;;
        ROUGH) exit 3 ;;
        *) exit 1 ;;
    esac
}

# stop_point STEP : end the run here when STOP_AFTER names STEP.
stop_point() {
    if [ -n "$STOP_AFTER" ] && [ "$STOP_AFTER" = "$1" ]; then
        STOPPED_AT="$1"
        finish
    fi
}

if [ -n "$STOP_AFTER" ] && [[ " ${STEP_ORDER[*]} " != *" $STOP_AFTER "* ]]; then
    echo "ERROR: STOP_AFTER=$STOP_AFTER is not a step (${STEP_ORDER[*]})"
    exit 1
fi

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

now_t() { echo "$(( $(date -u +%s) - T_BASE ))"; }

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

start_node() { # IDX — appends to the node's log; O watches its files dir via config
    local idx="$1" log_level="$H_RUST_LOG"
    [ "$idx" -eq "$O" ] && log_level="$O_RUST_LOG"
    RUST_LOG="$log_level" "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$TIME_SCALE" >> "$(node_log "$idx")" 2>&1 &
    PIDS[$idx]=$!
}

write_config() { # IDX SOFT_GB
    local idx="$1" soft="$2"
    {
        echo "[web_api]"
        echo "enabled = true"
        echo "bind = \"127.0.0.1:0\""
        echo "[storage]"
        echo "disk_reserve_gb = 0.0"
        echo "soft_quota_gb = $soft"
        echo "[backup]"
        echo "source_block_size_mb = 1"
        if [ "$idx" -eq "$O" ]; then
            echo "[[watch]]"
            echo "path = \"$(node_dir "$idx")/files\""
            echo "importance_multiplier = $IMPORTANCE"
        fi
    } > "$(node_dir "$idx")/config.toml"
}

# rchar_of IDX : rchar of node IDX's current process.
rchar_of() { proc_rchar "${PIDS[$1]}"; }

# restorable_count : files O reports as restorable.
restorable_count() {
    api_get "$O" /api/files \
        | jq '[.[] | select(.effective_status.kind == "restorable")] | length' 2>/dev/null \
        || echo 0
}

# Owner-side events (O's log). Times are seconds since T_BASE.
o_issues() { events_grep "$(node_log "$O")" "PoS hash challenge issued via mailbox" block_id holder_id; }
o_resolved() { events_grep "$(node_log "$O")" "mailbox PosResponse resolved" block_id holder outcome; }
o_timeouts() { events_grep "$(node_log "$O")" "PoS challenge timed out" block_id holder_id; }
o_unknown() { events_grep "$(node_log "$O")" "unknown challenge_id" challenge_id; }
o_issue_ticks() { events_grep "$(node_log "$O")" "scheduler: PoS issue tick" elapsed_ms due issued; }
o_ledger_rows() { events_grep "$(node_log "$O")" "pair-ledger row" master; }

# Holder-side events (the holder's own log).
h_computes() { events_grep "$(node_log "$1")" "responding with chain hash" challenge_id block_id; }
h_published() { events_grep "$(node_log "$1")" "mailbox_poll: PosResponse published" challenge_id acks cached; }
h_zero_acks() {
    { events_grep "$(node_log "$1")" "PosResponse publish got 0 acks" challenge_id
      events_grep "$(node_log "$1")" "PosResponse publish failed" challenge_id; } | sort -n
}
h_polls() { events_grep "$(node_log "$1")" "mailbox_poll: poll done" elapsed_ms entries deferred_full; }

count_in() { in_window "$1" "$2" | awk 'NF' | wc -l | tr -d ' '; }

# unresolved_issues A B DEADLINE [HOLDER16] : O's issues in [A, B] (optionally to one
# holder) without a `mailbox PosResponse resolved` for the same (block, holder) after the
# issue and by DEADLINE. Prints "<count> <issued>".
unresolved_issues() {
    local a="$1" b="$2" dl="$3" h="${4:-}"
    { o_resolved | awk '{ print "R", $1, $3, $4 }'
      o_issues | in_window "$a" "$b" | awk -v h="$h" 'h == "" || $4 == h { print "I", $1, $3, $4 }'
    } | awk -v dl="$dl" '
        $1 == "R" { k = $3 " " $4; r[k] = r[k] " " $2; next }
        $1 == "I" { n++; k = $3 " " $4; ok = 0; m = split(r[k], ts, " ")
                    for (i = 1; i <= m; i++) if (ts[i] + 0 > $2 + 0 && ts[i] + 0 <= dl) { ok = 1; break }
                    if (!ok) { bad++; if (bad <= 3) print "    unresolved: t=" $2 " block=" $3 " holder=" $4 > "/dev/stderr" } }
        END { print bad + 0, n + 0 }'
}

# ledger_gap A B : the largest gap between O's `pair-ledger row` lines in [A, B].
ledger_gap() { o_ledger_rows | in_window "$1" "$2" | awk '{ print $1 }' | max_gap; }

# tick_p95 A B : p95 of `scheduler: PoS issue tick` elapsed_ms in [A, B] ("" when none).
tick_p95() { o_issue_ticks | in_window "$1" "$2" | awk '$3 != "-" { print $3 }' | p95; }

echo "============================================================"
echo "  Viaticum: PoS at scale — nodes ${NUM_NODES}, time_scale ${TIME_SCALE}"
echo "  STOP_AFTER=${STOP_AFTER:-<all>}  dir=$TEST_DIR"
echo "============================================================"

# ── STEP P0: setup, star connect ───────────────────────────────────────────
CUR_STEP=P0
echo ""
echo "=== Step P0: init, configs, start 10 nodes, star-connect to node-00 ==="
command -v jq > /dev/null || { fail "FAIL(setup): jq missing"; finish; }
mkdir -p "$E2E_BASE"
FREE_B=$(df -P --block-size=1 "$E2E_BASE" | awk 'NR == 2 { print $4 }')
if [ "${FREE_B:-0}" -lt $((MIN_FREE_GIB * 1024 * MIB)) ]; then
    df -h "$E2E_BASE"
    fail "FAIL(setup): < ${MIN_FREE_GIB} GiB free on the file system of $E2E_BASE"
    finish
fi
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES - 1))); do
    mkdir -p "$(node_dir "$i")/files"
    run_cli "$i" init > /dev/null 2>&1
    case "$i" in
        "$O") write_config "$i" "$O_SOFT_GB" ;;
        "$H9") write_config "$i" "$H9_SOFT_GB" ;;
        *) write_config "$i" "$H_SOFT_GB" ;;
    esac
done
for i in $(seq 0 $((NUM_NODES - 1))); do start_node "$i"; done
for i in $(seq 0 $((NUM_NODES - 1))); do
    wait_daemon "$i" || { fail "FAIL(setup): node-0$i did not start"; finish; }
done
declare -A ADDR DEV
for i in $(seq 0 $((NUM_NODES - 1))); do
    ADDR[$i]=$(get_addr "$i")
    DEV[$i]=$(api_get "$i" /api/status | jq -r '.device_id // empty')
    if [ -z "${ADDR[$i]}" ] || [ -z "${DEV[$i]}" ]; then
        fail "FAIL(setup): node-0$i: missing addr/device (${ADDR[$i]:-?} ${DEV[$i]:-?})"
        finish
    fi
    info "node-0$i device=${DEV[$i]}"
done
for i in $(seq 1 $((NUM_NODES - 1))); do run_cli_q "$i" connect "${ADDR[$O]}" > /dev/null; done
DEADLINE=$(( $(now_t) + 120 ))
SHORT=""
while :; do
    SHORT=""
    for i in $(seq 0 $((NUM_NODES - 1))); do
        n=$(status_num "$i" peer_count_authenticated)
        [ "$n" -ge $((NUM_NODES - 1)) ] || SHORT="$SHORT node-0$i:$n"
    done
    [ -z "$SHORT" ] && break
    [ "$(now_t)" -ge "$DEADLINE" ] && break
    sleep 2
done
if [ -z "$SHORT" ]; then
    pass "every node has $((NUM_NODES - 1)) authenticated peers"
else
    fail "FAIL(setup): not fully connected within 120 s:$SHORT"
    finish
fi
stop_point P0

# ── STEP 1a: trust seed, every holder passes once ──────────────────────────
CUR_STEP=1a
echo ""
echo "=== Step 1a: O writes ${SEED_FILES} x 1 MiB; a Pass from each of the 9 holders ==="
for j in $(seq 1 "$SEED_FILES"); do
    head -c "$MIB" /dev/urandom > "$(node_dir "$O")/files/seed_$j.txt"
done
DEADLINE=$(( $(now_t) + 300 ))
MISSING=""
while :; do
    PASSED=$(o_resolved | awk '$5 == "Pass" { print $4 }' | sort -u)
    MISSING=""
    for h in "${HS[@]}" "$H9"; do
        echo "$PASSED" | grep -qx "${DEV[$h]}" || MISSING="$MISSING node-0$h"
    done
    [ -z "$MISSING" ] && break
    [ "$(now_t)" -ge "$DEADLINE" ] && break
    sleep 5
done
if [ -z "$MISSING" ]; then
    pass "O resolved a Pass from each of the 9 holders"
else
    fail "FAIL(setup): no Pass on O within 5 min from:$MISSING"
    finish
fi
stop_point 1a

# ── STEP 0: calibration of the holders' background reads ───────────────────
CUR_STEP=0
echo ""
echo "=== Step 0: calibration, ${HALF} s: R0(H) = 2 x rchar growth of H1..H8 ==="
declare -A R0 RC_A
for h in "${HS[@]}"; do RC_A[$h]=$(rchar_of "$h"); done
sleep "$HALF"
CAL_OK=1
for h in "${HS[@]}"; do
    b=$(rchar_of "$h")
    if [ -z "$b" ] || [ -z "${RC_A[$h]}" ]; then
        CAL_OK=""
        fail "FAIL(setup): cannot read /proc/<pid>/io of node-0$h"
        continue
    fi
    R0[$h]=$(( 2 * (b - RC_A[$h]) ))
    info "R0(node-0$h) = ${R0[$h]} bytes per scaled week"
done
[ -n "$CAL_OK" ] && pass "R0 measured for H1..H8" || finish
stop_point 0

# ── STEP 1b: the upload ────────────────────────────────────────────────────
CUR_STEP=1b
echo ""
echo "=== Step 1b: O writes $((ALL_FILES - SEED_FILES)) files; 1000 blocks restorable within 60 min ==="
T_UP0=$(now_t)
for j in $(seq $((SEED_FILES + 1)) "$ALL_FILES"); do
    head -c "$MIB" /dev/urandom > "$(node_dir "$O")/files/data_$j.txt"
done
DEADLINE=$(( $(now_t) + 3600 ))
PIPE=0; RESTORABLE=0; LAST_NOTE=$(now_t)
while :; do
    PIPE=$(grep -acF "backup: pipeline complete" "$(node_log "$O")" || true)
    RESTORABLE=$(restorable_count)
    [ "${PIPE:-0}" -ge "$ALL_FILES" ] && [ "${RESTORABLE:-0}" -ge "$ALL_FILES" ] && break
    [ "$(now_t)" -ge "$DEADLINE" ] && break
    if [ $(( $(now_t) - LAST_NOTE )) -ge 300 ]; then
        note "pace: $(( $(now_t) - T_UP0 )) s: blocks=$PIPE restorable=$RESTORABLE"
        LAST_NOTE=$(now_t)
    fi
    sleep 30
done
UP_SECS=$(( $(now_t) - T_UP0 ))
note "upload: $UP_SECS s for blocks=$PIPE restorable=$RESTORABLE (input of СТ-1)"
if [ "${PIPE:-0}" -ge "$ALL_FILES" ] && [ "${RESTORABLE:-0}" -ge "$ALL_FILES" ]; then
    pass "1000 blocks, 1000 files restorable on O after $UP_SECS s"
else
    fail "FAIL(setup): after 60 min blocks=$PIPE restorable=$RESTORABLE (pace above)"
    finish
fi
PLACEMENTS_AT_1B=$(status_num "$O" placement_count)
info "O: placement_count=$PLACEMENTS_AT_1B placement_alive=$(status_num "$O" placement_alive)"
stop_point 1b

# ── Premise of step 6: DR ready before W1 ───────────────────────────────────
CUR_STEP=6
DEADLINE=$(( $(now_t) + WEEK ))
DR_FIRST=""
while :; do
    [ "$(api_get "$O" /api/status | jq -r '.dr_ready // false')" = "true" ] && { DR_FIRST=1; break; }
    [ "$(now_t)" -ge "$DEADLINE" ] && break
    sleep 10
done
if [ -z "$DR_FIRST" ]; then
    fail "premise: DR did not become ready within a scaled week; status: $(api_get "$O" /api/status | jq -c '{dr_ready, dr_pointer_published_at, dr_pointer_acks, blocks_ok, blocks_at_risk}')"
fi

# ── W1 starts: the laptop's schedule and the DR sampler run in the background ─
T_W1=$(now_t)
T_W2=$((T_W1 + WEEK))
T_W3=$((T_W1 + 2 * WEEK))
T_W4=$((T_W1 + 3 * WEEK))
T_W5=$((T_W1 + 4 * WEEK))
echo ""
echo "=== W1 starts at t=$T_W1 (W2 $T_W2, W3 $T_W3, W4 $T_W4, end $T_W5) ==="
echo "${PIDS[$H9]}" > "$TEST_DIR/h9.pid"
: > "$TEST_DIR/h9_cycles.log"
h9_cycler() {
    local c t0 pid
    for c in $(seq 1 "$H9_CYCLES"); do
        t0=$((T_W1 + (c - 1) * H9_CYCLE))
        sleep_until "$t0"
        pid=$(cat "$TEST_DIR/h9.pid")
        kill -9 "$pid" 2>/dev/null
        for _ in $(seq 1 25); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
        echo "$c kill $(now_t)" >> "$TEST_DIR/h9_cycles.log"
        sleep_until $((t0 + H9_OFF))
        start_node "$H9"
        echo "${PIDS[$H9]}" > "$TEST_DIR/h9.pid"
        echo "$c up $(now_t)" >> "$TEST_DIR/h9_cycles.log"
    done
}
h9_cycler &
BG_PIDS+=($!)
: > "$TEST_DIR/dr.samples"
dr_sampler() {
    while [ "$(now_t)" -le "$T_W4" ]; do
        echo "$(now_t) $(api_get "$O" /api/status | jq -r '.dr_ready // "null"' 2>/dev/null)" \
            >> "$TEST_DIR/dr.samples"
        sleep 30
    done
}
dr_sampler &
BG_PIDS+=($!)

# ── W2: the measurement window of steps 3 and 4 ────────────────────────────
sleep_until "$T_W2"
declare -A RC_W2S RC_W2E
for h in "${HS[@]}"; do RC_W2S[$h]=$(rchar_of "$h"); done
sleep_until "$T_W3"
for h in "${HS[@]}"; do RC_W2E[$h]=$(rchar_of "$h"); done

# The SIGSTOP schedule of H8 (step 7b) runs through W3; only when the run goes past step 4.
if [ "$STOP_AFTER" != "2" ] && [ "$STOP_AFTER" != "3" ] && [ "$STOP_AFTER" != "4" ]; then
    : > "$TEST_DIR/h8_cycles.log"
    h8_cycler() {
        local c t0
        for c in $(seq 1 "$H8_CYCLES"); do
            t0=$((T_W3 + (c - 1) * H9_CYCLE))
            sleep_until "$t0"
            kill -STOP "${PIDS[8]}" 2>/dev/null
            echo "$c stop $(now_t)" >> "$TEST_DIR/h8_cycles.log"
            sleep_until $((t0 + H8_STOP))
            kill -CONT "${PIDS[8]}" 2>/dev/null
            echo "$c cont $(now_t)" >> "$TEST_DIR/h8_cycles.log"
        done
    }
    h8_cycler &
    BG_PIDS+=($!)
fi

# ── STEP 2: the issue tick over W1+W2 ──────────────────────────────────────
CUR_STEP=2
echo ""
echo "=== Step 2: W1+W2 issue tick p95 <= ${BAR_TICK_MS} ms, ledger gap <= ${BAR_LEDGER_GAP} s ==="
P95=$(tick_p95 "$T_W1" "$T_W3")
if [ -z "$P95" ]; then
    fail "no 'scheduler: PoS issue tick' line on O in W1+W2 (the line comes with СТ-0c; pre-registered red before it)"
elif [ "$P95" -le "$BAR_TICK_MS" ]; then
    pass "issue tick elapsed_ms p95 = $P95"
else
    fail "issue tick elapsed_ms p95 = $P95 > $BAR_TICK_MS"
fi
GAP=$(ledger_gap "$T_W1" "$T_W3")
ROWS=$(o_ledger_rows | count_in "$T_W1" "$T_W3")
if [ "$ROWS" -eq 0 ]; then
    fail "no 'pair-ledger row' on O in W1+W2"
elif awk -v g="$GAP" -v b="$BAR_LEDGER_GAP" 'BEGIN { exit !(g <= b) }'; then
    pass "ledger accrual gap max = ${GAP} s ($ROWS rows)"
else
    fail "ledger accrual gap max = ${GAP} s > ${BAR_LEDGER_GAP} s"
fi
stop_point 2

# ── STEP 3: every holder computed each challenge once in W2 ────────────────
CUR_STEP=3
echo ""
echo "=== Step 3: W2 [$T_W2, $T_W3], H1..H8: one compute per challenge, rare re-publish, reads ~ challenges ==="
for h in "${HS[@]}"; do
    SUMMARY=$({ h_computes "$h" | awk '{ print "C", $1, $3, $4 }'
                h_published "$h" | awk '{ print "P", $1, $3, $4, $5 }'
                h_zero_acks "$h" | awk '{ print "Z", $1, $3 }'
              } | awk -v a="$T_W2" -v b="$T_W3" -v m="$FIRST_CACHED_MARGIN" '
        ($2 + 0) > b { next }
        $1 == "C" { nc[$3]++; if (!($3 in tc)) tc[$3] = $2 + 0; if ($2 + 0 >= a) win[$3] = 1 }
        $1 == "P" { np[$3]++; if ($5 == "true") { ca[$3]++; cached++ }; if ($2 + 0 >= a) win[$3] = 1 }
        $1 == "Z" { nz[$3]++; if ($2 + 0 >= a) win[$3] = 1 }
        END {
            for (c in win) {
                n++
                if (nc[c] != 1) { bc++; if (ex == "") ex = c ":computes=" nc[c] + 0 }
                if (np[c] + 0 > 4 + nz[c]) { bp++; if (ex == "") ex = c ":published=" np[c] }
                if ((c in tc) && tc[c] >= a && tc[c] <= b - m) {
                    el++
                    if (ca[c] + 0 < 1) { bk++; if (ex == "") ex = c ":cached=0" }
                }
            }
            printf "%d %d %d %d %d %d %s\n", n, bc, bp, el, bk, cached, (ex == "" ? "-" : ex)
        }')
    read -r N_CID BAD_C BAD_P ELIG BAD_K N_CACHED EX <<< "$SUMMARY"
    # Reads: the block's symbols on H's own disk, per compute line of the window.
    declare -A BB=()
    SUM_B=0
    while read -r _ _ _ blk; do
        [ -n "$blk" ] || continue
        [ -z "${BB[$blk]:-}" ] && BB[$blk]=$(block_bytes_on "$h" "$blk")
        SUM_B=$((SUM_B + BB[$blk]))
    done < <(h_computes "$h" | in_window "$T_W2" "$T_W3")
    unset BB
    D_RCHAR=$(( ${RC_W2E[$h]:-0} - ${RC_W2S[$h]:-0} ))
    BOUND=$(awk -v s="$SUM_B" -v r="${R0[$h]}" 'BEGIN { printf "%.0f", 1.5 * s + 1.5 * r }')
    POLL95=$(h_polls "$h" | in_window "$T_W2" "$T_W3" | awk '$3 != "-" { print $3 }' | p95)
    info "node-0$h: challenges=$N_CID bad_computes=$BAD_C bad_published=$BAD_P eligible=$ELIG no_cached=$BAD_K cached_lines=$N_CACHED rchar=$D_RCHAR bound=$BOUND poll_p95=${POLL95:-none} ex=$EX"
    if [ "$N_CID" -eq 0 ]; then
        fail "node-0$h: no challenge seen in W2 (nothing to judge)"
        continue
    fi
    [ "$BAD_C" -eq 0 ] && pass "node-0$h: every W2 challenge computed exactly once ($N_CID)" \
        || fail "node-0$h: $BAD_C of $N_CID challenges not computed exactly once (e.g. $EX)"
    [ "$BAD_P" -eq 0 ] && pass "node-0$h: published <= 4 + 0-acks per challenge" \
        || fail "node-0$h: $BAD_P challenges published more than 4 + 0-acks times"
    if [ "$ELIG" -eq 0 ]; then
        fail "node-0$h: no challenge first computed in [W2, W2 end - ${FIRST_CACHED_MARGIN} s] (cannot judge the quarter-TTL re-publish)"
    elif [ "$BAD_K" -eq 0 ]; then
        pass "node-0$h: every eligible challenge ($ELIG) re-published from memory (cached=true)"
    else
        fail "node-0$h: $BAD_K of $ELIG eligible challenges without a cached=true re-publish"
    fi
    if [ "${RC_W2S[$h]:-}" = "" ] || [ "${RC_W2E[$h]:-}" = "" ]; then
        fail "node-0$h: rchar not read"
    elif [ "$D_RCHAR" -le "$BOUND" ]; then
        pass "node-0$h: rchar growth $D_RCHAR <= $BOUND"
    else
        fail "node-0$h: rchar growth $D_RCHAR > $BOUND (symbols re-read)"
    fi
    if [ -z "$POLL95" ]; then
        fail "node-0$h: no 'mailbox_poll: poll done' line in W2"
    elif [ "$POLL95" -lt "$BAR_POLL_MS" ]; then
        pass "node-0$h: poll elapsed_ms p95 = $POLL95"
    else
        fail "node-0$h: poll elapsed_ms p95 = $POLL95 >= $BAR_POLL_MS"
    fi
done
stop_point 3

# ── STEP 4: the owner resolved every W2 challenge ──────────────────────────
CUR_STEP=4
echo ""
echo "=== Step 4: O resolves every W2 challenge by W2 end + ${HALF} s, no stale WARNs ==="
sleep_until $((T_W3 + HALF))
read -r UNRES ISSUED <<< "$(unresolved_issues "$T_W2" "$T_W3" $((T_W3 + HALF)))"
TO=$(o_timeouts | count_in "$T_W2" $((T_W3 + HALF)))
UNK=$(o_unknown | count_in "$T_W2" $((T_W3 + HALF)))
DEFERRED=$(events_grep "$(node_log "$O")" "mailbox_poll: poll done" deferred_full \
    | in_window "$T_W2" $((T_W3 + HALF)) | awk '$3 != "-" { s += $3 } END { print s + 0 }')
FULL_WARN=$(events_grep "$(node_log "$O")" "pos_response_tx full" | count_in "$T_W2" $((T_W3 + HALF)))
note "deferred_full sum = $DEFERRED, 'pos_response_tx full' lines = $FULL_WARN"
if [ "$ISSUED" -eq 0 ]; then
    fail "no challenge issued by O in W2 (nothing to judge)"
elif [ "$UNRES" -eq 0 ]; then
    pass "all $ISSUED challenges of W2 resolved by W2 end + ${HALF} s"
else
    fail "$UNRES of $ISSUED W2 challenges not resolved by W2 end + ${HALF} s"
fi
[ "$TO" -eq 0 ] && pass "0 'PoS challenge timed out'" || fail "$TO 'PoS challenge timed out' in the window"
[ "$UNK" -le "$TO" ] && pass "WARN unknown challenge_id = $UNK <= timeouts ($TO)" \
    || fail "WARN unknown challenge_id = $UNK > timeouts ($TO)"
stop_point 4

# ── STEP 7b: W3 with H8 stopped/continued ──────────────────────────────────
CUR_STEP=7b
echo ""
echo "=== Step 7b: W3 [$T_W3, $T_W4], H8 SIGSTOP ${H8_STOP} s / SIGCONT, ${H8_CYCLES} cycles ==="
sleep_until "$T_W4"
STOPS=$(grep -c " stop " "$TEST_DIR/h8_cycles.log" 2>/dev/null)
STOPS=${STOPS:-0}
[ "$STOPS" -ge "$H8_CYCLES" ] && info "H8 stopped $STOPS times" \
    || fail "FAIL(setup): H8 stopped only $STOPS of $H8_CYCLES times"
P95=$(tick_p95 "$T_W3" "$T_W4")
if [ -z "$P95" ]; then
    fail "no 'scheduler: PoS issue tick' line on O in W3 (the line comes with СТ-0c)"
elif [ "$P95" -le "$BAR_TICK_MS" ]; then
    pass "issue tick elapsed_ms p95 = $P95 with a stopped postman (mailbox-i60)"
else
    fail "issue tick elapsed_ms p95 = $P95 > $BAR_TICK_MS with a stopped postman"
fi
GAP=$(ledger_gap "$T_W3" "$T_W4")
awk -v g="$GAP" -v b="$BAR_LEDGER_GAP" 'BEGIN { exit !(g <= b) }' \
    && pass "ledger accrual gap max = ${GAP} s" || fail "ledger accrual gap max = ${GAP} s > ${BAR_LEDGER_GAP} s"
TO8=$(o_timeouts | in_window "$T_W3" "$T_W4" | awk -v h="${DEV[8]}" '$4 == h' | awk 'NF' | wc -l | tr -d ' ')
[ "$TO8" -eq 0 ] && pass "0 timeouts to H8" || fail "$TO8 timeouts to H8"
ALL_POLL95=$(for i in $(seq 0 $((NUM_NODES - 1))); do
    h_polls "$i" | in_window "$T_W3" "$T_W4" | awk '$3 != "-" { print $3 }'
done | p95)
if [ -n "$ALL_POLL95" ] && [ "$ALL_POLL95" -ge "$BAR_POLL_MS" ]; then
    rough "known: poll waits for the slowest postman (routing.rs poll, 15 s per stopped peer): poll done elapsed_ms p95 over all nodes = $ALL_POLL95"
else
    info "poll done elapsed_ms p95 over all nodes = ${ALL_POLL95:-none}"
fi
stop_point 7b

# ── STEP 6: DR readiness held over W1..W3 ──────────────────────────────────
CUR_STEP=6
echo ""
echo "=== Step 6: O's dr_ready in every sample of W1..W3 ==="
N_S=$(awk -v a="$T_W1" -v b="$T_W4" '$1 >= a && $1 <= b' "$TEST_DIR/dr.samples" | wc -l | tr -d ' ')
N_BAD=$(awk -v a="$T_W1" -v b="$T_W4" '$1 >= a && $1 <= b && $2 != "true"' "$TEST_DIR/dr.samples" | wc -l | tr -d ' ')
if [ "$N_S" -eq 0 ]; then
    fail "no dr_ready sample in W1..W3"
elif [ "$N_BAD" -eq 0 ]; then
    pass "dr_ready = true in all $N_S samples"
else
    fail "dr_ready not true in $N_BAD of $N_S samples (first: $(awk -v a="$T_W1" -v b="$T_W4" '$1 >= a && $1 <= b && $2 != "true"' "$TEST_DIR/dr.samples" | head -1))"
fi
stop_point 6

# ── STEP 5: H1 restarts in W4 ──────────────────────────────────────────────
CUR_STEP=5
echo ""
echo "=== Step 5: W4 + 60 s: H1 SIGTERM, 10 s, start (memory lost) ==="
H1=1
sleep_until $((T_W4 + 60))
T_KILL=$(now_t)
kill -TERM "${PIDS[$H1]}" 2>/dev/null
wait_pid_exit "${PIDS[$H1]}" 30 || { kill -9 "${PIDS[$H1]}" 2>/dev/null; note "H1 did not exit in 30 s — SIGKILL"; }
sleep 10
start_node "$H1"
T_START=$(now_t)
RC_START=""
for _ in $(seq 1 50); do
    RC_START=$(rchar_of "$H1")
    [ -n "$RC_START" ] && break
    sleep 0.1
done
T_FIRST=""
for _ in $(seq 1 180); do
    T_FIRST=$(h_polls "$H1" | in_window "$T_START" 999999999 | awk '$4 != "-" && $4 + 0 > 0 { print $1; exit }')
    [ -n "$T_FIRST" ] && break
    sleep 1
done
RC_FIRST=$(rchar_of "$H1")
info "H1 killed t=$T_KILL, started t=$T_START, first poll with entries t=${T_FIRST:-none}"

# ── STEP 7 runs until W4 ends; then step 8 stops O, and 5 and 7 are judged meanwhile ─
sleep_until "$T_W5"
PLACEMENTS=$(status_num "$O" placement_count)
T_O_KILL=$(now_t)
kill -TERM "${PIDS[$O]}" 2>/dev/null
wait_pid_exit "${PIDS[$O]}" 60 || { kill -9 "${PIDS[$O]}" 2>/dev/null; echo "  NOTE: O did not exit in 60 s — SIGKILL"; }

echo ""
echo "=== Step 5 (judged): computes across the restart, reads, owner side ==="
SUMMARY=$(h_computes "$H1" | awk -v k="$T_KILL" -v s="$T_START" -v w="$WEEK" -v m="$ALIVE_MARGIN" '
    { t = $1 + 0; c = $3
      if (t < k) { n1[c]++; if (!(c in tc)) tc[c] = t; blk[c] = $4 } else if (t >= s) { n2[c]++ } }
    END {
        for (c in n1) {
            tot = n1[c] + n2[c]
            if (n1[c] > 1 || tot > 2) { bad++; if (ex == "") ex = c ":" n1[c] "+" n2[c] }
            if (tc[c] + w > s + m) { must2++; if (tot != 2) { bad++; if (ex == "") ex = c ":" n1[c] "+" n2[c] " (alive)" } }
            else if (tc[c] + w < k) { if (tot != 1) { bad++; if (ex == "") ex = c ":" n1[c] "+" n2[c] " (expired)" } }
            if (tc[c] + w > k) live = live " " blk[c]
        }
        for (c in n2) if (!(c in n1) && n2[c] != 1) { bad++; if (ex == "") ex = c ":0+" n2[c] " (new)" }
        printf "%d %d %s|%s\n", must2 + 0, bad + 0, (ex == "" ? "-" : ex), live
    }')
HEAD=${SUMMARY%%|*}; LIVE_BLOCKS=${SUMMARY#*|}
read -r MUST2 BAD5 EX5 <<< "$HEAD"
if [ "$MUST2" -eq 0 ]; then
    fail "no challenge of H1 alive through the restart (nothing to judge)"
elif [ "$BAD5" -eq 0 ]; then
    pass "H1: $MUST2 challenges alive through the restart computed exactly twice, the rest once"
else
    fail "H1: $BAD5 challenges with a wrong compute count across the restart (e.g. $EX5)"
fi
SUM_B=0
declare -A BB5=()
for blk in $LIVE_BLOCKS; do
    [ -z "${BB5[$blk]:-}" ] && BB5[$blk]=$(block_bytes_on "$H1" "$blk")
    SUM_B=$((SUM_B + BB5[$blk]))
done
if [ -z "$RC_START" ] || [ -z "$T_FIRST" ] || [ -z "$RC_FIRST" ]; then
    fail "H1: first poll after the restart not observed (rchar=${RC_START:-?}/${RC_FIRST:-?}, first=${T_FIRST:-none})"
else
    D5=$((RC_FIRST - RC_START))
    ELAPSED=$(awk -v a="$T_START" -v b="$T_FIRST" 'BEGIN { print b - a }')
    BOUND5=$(awk -v s="$SUM_B" -v r="${R0[$H1]}" -v e="$ELAPSED" -v w="$WEEK" \
        'BEGIN { printf "%.0f", 1.5 * s + 1.5 * r * e / w }')
    [ "$D5" -le "$BOUND5" ] && pass "H1: rchar over the first poll $D5 <= $BOUND5" \
        || fail "H1: rchar over the first poll $D5 > $BOUND5"
fi
TO1=$(o_timeouts | in_window "$T_KILL" "$T_W5" | awk -v h="${DEV[$H1]}" '$4 == h' | awk 'NF' | wc -l | tr -d ' ')
TO_ALL=$(o_timeouts | count_in "$T_KILL" "$T_W5")
UNK5=$(o_unknown | count_in "$T_KILL" "$T_W5")
[ "$TO1" -eq 0 ] && pass "O: 0 timeouts to H1" || fail "O: $TO1 timeouts to H1"
[ "$UNK5" -le "$TO_ALL" ] && pass "O: WARN unknown challenge_id = $UNK5 <= timeouts ($TO_ALL)" \
    || fail "O: WARN unknown challenge_id = $UNK5 > timeouts ($TO_ALL) after H1's restart"
stop_point 5

# ── STEP 7 (judged): the daily laptop ──────────────────────────────────────
CUR_STEP=7
echo ""
echo "=== Step 7 (judged): H9, ${H9_CYCLES} cycles over W1..W4 ==="
UPS=$(awk '$2 == "up" { print $1, $3 }' "$TEST_DIR/h9_cycles.log")
N_UP=$(echo "$UPS" | awk 'NF' | wc -l | tr -d ' ')
[ "$N_UP" -ge "$H9_CYCLES" ] || fail "FAIL(setup): H9 started only $N_UP of $H9_CYCLES times"
TO9=$(o_timeouts | in_window "$T_W1" "$T_W5" | awk -v h="${DEV[$H9]}" '$4 == h' | awk 'NF' | wc -l | tr -d ' ')
[ "$TO9" -eq 0 ] && pass "0 timeouts to H9" || fail "$TO9 timeouts to H9"
NO_PASS=""; SLOW=""; TUPS=""
PASS9=$(o_resolved | awk -v h="${DEV[$H9]}" '$4 == h && $5 == "Pass" { print $1 }')
ISS9=$(o_issues | awk -v h="${DEV[$H9]}" '$4 == h { print $1 }')
COMP9=$(h_computes "$H9")
POLL9=$(h_polls "$H9")
while read -r c up; do
    [ -n "$c" ] || continue
    end=$(awk -v n=$((c + 1)) '$1 == n && $2 == "kill" { print $3 }' "$TEST_DIR/h9_cycles.log")
    [ -n "$end" ] || end=$((up + H9_CYCLE - H9_OFF))
    np=$(echo "$PASS9" | awk -v a="$up" -v b="$((end + 8))" 'NF && $1 >= a && $1 <= b' | wc -l | tr -d ' ')
    [ "$np" -ge 1 ] || NO_PASS="$NO_PASS $c"
    live=$(echo "$ISS9" | awk -v a="$((up - WEEK))" -v b="$up" 'NF && $1 >= a && $1 <= b' | wc -l | tr -d ' ')
    comp=$(echo "$COMP9" | in_window "$up" "$end" | awk '{ print $3 }' | sort -u | awk 'NF' | wc -l | tr -d ' ')
    if [ "$live" -eq 0 ] || [ $((comp * 10)) -lt $((live * 9)) ]; then SLOW="$SLOW $c:$comp/$live"; fi
    tup=$(echo "$POLL9" | in_window "$up" "$end" | awk -v u="$up" '$4 != "-" && $4 + 0 > 0 { printf "%.0f", $1 - u; exit }')
    TUPS="$TUPS ${tup:-none}"
done <<< "$UPS"
[ -z "$NO_PASS" ] && pass "a Pass from H9 on O in every online window" \
    || fail "no Pass from H9 on O in windows:$NO_PASS"
[ -z "$SLOW" ] && pass "H9 computed >= 90 % of its live challenges in every window" \
    || fail "finding: the laptop does not keep up within the window (cycle:computed/live):$SLOW"
note "T_up per window (s):$TUPS"
# ── Steps 7a-7c (line A, 4r-i113): appended here by line A ─────────────────
stop_point 7

# ── STEP 8: the owner comes back after 3 scaled days ───────────────────────
CUR_STEP=8
echo ""
echo "=== Step 8: O off 300 s, start; the first issue tick, then half a week ==="
sleep_until $((T_O_KILL + 300))
start_node "$O"
T_O_START=$(now_t)
wait_daemon "$O" || { fail "O did not start again"; finish; }
FIRST_TICK=""
for _ in $(seq 1 180); do
    FIRST_TICK=$(o_issue_ticks | in_window "$T_O_START" 999999999 | head -1)
    [ -n "$FIRST_TICK" ] && break
    sleep 1
done
T8="$T_O_START"
if [ -z "$FIRST_TICK" ]; then
    fail "no 'scheduler: PoS issue tick' on O within 180 s of its start (the line comes with СТ-0c)"
else
    read -r T8 _ FT_MS FT_DUE _ <<< "$FIRST_TICK"
    T8=${T8%.*}
    note "first issue tick: elapsed_ms=$FT_MS due=$FT_DUE placements=$PLACEMENTS"
    awk -v d="$FT_DUE" -v p="$PLACEMENTS" 'BEGIN { exit !(p > 0 && d >= 0.8 * p) }' \
        && pass "first tick due=$FT_DUE >= 0.8 x $PLACEMENTS placements" \
        || fail "first tick due=$FT_DUE < 0.8 x $PLACEMENTS placements"
fi
T8_END=$((T8 + HALF))
sleep_until $((T8_END + STEP8_MARGIN))
read -r UNRES8 ISSUED8 <<< "$(unresolved_issues "$T_O_START" "$T8_END" $((T8_END + STEP8_MARGIN)))"
TO8A=$(o_timeouts | count_in "$T_O_START" $((T8_END + STEP8_MARGIN)))
UNK8=$(o_unknown | count_in "$T_O_START" $((T8_END + STEP8_MARGIN)))
if [ "$ISSUED8" -eq 0 ]; then
    fail "no challenge issued by O after its restart (nothing to judge)"
elif [ "$UNRES8" -eq 0 ]; then
    pass "all $ISSUED8 challenges issued after the restart resolved"
else
    fail "$UNRES8 of $ISSUED8 challenges issued after the restart not resolved"
fi
[ "$TO8A" -eq 0 ] && pass "0 timeouts after the restart" || fail "$TO8A timeouts after the restart"
[ "$UNK8" -le "$TO8A" ] && pass "WARN unknown challenge_id = $UNK8 <= timeouts ($TO8A)" \
    || fail "WARN unknown challenge_id = $UNK8 > timeouts ($TO8A) after the restart"
GAP_FIRST=$(ledger_gap "$T_O_START" $((T8 + 30)))
note "ledger gap around the first tick = ${GAP_FIRST} s (K-5, A's decision)"
GAP8=$(ledger_gap $((T8 + 30)) $((T8_END + STEP8_MARGIN)))
awk -v g="$GAP8" -v b="$BAR_LEDGER_GAP" 'BEGIN { exit !(g <= b) }' \
    && pass "ledger accrual gap after the first tick = ${GAP8} s" \
    || fail "ledger accrual gap after the first tick = ${GAP8} s > ${BAR_LEDGER_GAP} s"
stop_point 8

finish
