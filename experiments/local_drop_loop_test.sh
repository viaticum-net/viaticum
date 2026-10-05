#!/bin/bash
# Viaticum: a friend drops our block once — the stale DropNotice that the mailbox re-delivers
# for its whole TTL must not bounce the block between "lost" and "re-placed" (DN-1).
# Local processes on one machine (no Docker).
#
# Scenario:     4 independent nodes at time_scale 20000 star-connected to node-00, the owner O;
#               holders A (node-01), P1, P2. O backs up one 1 MiB file (block B1, on all three
#               holders). The test deletes B1's directory on A: A's integrity scan announces the
#               drop, O marks A's placement Lost and repair places B1 back on A — the only
#               candidate. The mailbox keeps re-delivering the old notice until its TTL (60 s)
#               ends; O is restarted inside that window. Then A drops B1 a second time (a
#               genuine new notice).
# Intent:       4r-i47, 4r-i48, 4r-i32 (mechanism; the clock-ahead variant is unit DN1-5)
# Proves:       one application per notice: O marks (B1, A) Lost exactly once per genuine drop
#               while it receives the same notice many times (already_applied=true), before and
#               after its own restart; A (another node) is offered B1 back exactly once per drop
#               and holds it at the end; a second genuine drop is applied, not swallowed.
# Adversarial:  mailbox re-delivery of a stale notice hitting a fresh placement; owner SIGTERM +
#               restart inside the notice TTL; a second genuine drop of the same block by the
#               same holder.
# Cannot close: a holder clock running ahead (no libfaketime; unit DN1-5); DR of the owner
#               inside the TTL (4r-i51; unit DN1-8 covers the mechanism); a stale notice whose
#               FIRST delivery comes after a re-placement (a Lost only if it names ESIs the new
#               placement holds, unit DN1-12; see the DELAYED item below); the final-notice flood after deleting a big folder (4r-i49; unit
#               DN1-15); pressure republication with new deadlines (new notices; В-1a); two
#               devices of one holder master (4r-i35; unit DN1-17 for the device choice); the
#               owner-side SymbolReject path choosing the first device (dead for
#               request-response, audit N-3; backup side is line C, R1-e); real time (14-day
#               TTL, hourly poll); two genuine drops of one block within one second of the
#               holder's clock (swallowed by design, 4r-i48); a malicious postman keeping the
#               old notice and re-storing it with a fresh expires_at (the envelope is not
#               authenticated, mailbox-i26) — one application per retention window (2 x TTL,
#               ~28 days) for as long as it keeps doing it, i.e. one re-placement of the block
#               per window per notice; the У-4 ledger is not touched (EvidenceBeforeEpisode); in
#               a circle of friends the postmen are the friends; no scenario forges an
#               envelope; a holder clock running ahead of the owner's by more than the SCALED
#               TTL on multi-machine demos (the postman's clamp is on the raw TTL); a DELAYED
#               first delivery of a notice arriving after repair re-placed the block on the
#               same holder (not staged here): since repair-i8 the re-placement gets fresh
#               ESIs, and since Р-3 (C-SP К1c) a notice that names no ESI of this master's
#               placements is ignored, so such a stale notice no longer marks the new
#               placement Lost (units drop_notice_without_intersection_changes_nothing,
#               DN1-12 for the intersecting case).
# Steps:        1. start 4 daemons, star-connect -> O has 3 authenticated peers (30 s)
#               2. O writes f1 (1 MiB random) -> restorable within 60 s; B1 = its block; symbols
#                    of B1 on the disks of A, P1 AND P2 (block_symbols_on) — premise, else
#                    FAIL(setup) with the table printed
#               3. [adversarial] t0: rm -rf A:holdings/<B1> -> within 15 s A logs `missing
#                    holding removed from DB, immediate-drop DropNotice sent` for B1/owner O;
#                    within 15 s more O logs `received SymbolDropNotice` block B1 holder A
#                    already_applied=false and `placement marked Lost` for (B1, A's device)
#               4. door: within 30 s of t0 A logs `SymbolOffer accepted` for B1 owner O and A's
#                    disk has B1's directory again (t_r = time of that line); missing -> ROUGH
#                    "re-placement to A did not happen, loop door not exercised"
#               5. [adversarial] if t0 + 60 - now >= 20 s: SIGTERM O, wait exit (<= 15 s, else
#                    FAIL(setup)), restart with the same args, wait_auth_peers 3 (auto-redial);
#                    else ROUGH "restart missed the TTL window". Wait until t_exp = t0 + 70 s.
#                    (a) O after the restart: >= 1 `received SymbolDropNotice` B1 holder A
#                        already_applied=true (0 -> ROUGH "no post-restart re-delivery")
#                    (b) O over [t0, t_exp]: `placement marked Lost` for (B1, A's device) == 1
#                        (>= 2 -> FAIL) (4r-i47)
#                    (c) A over [t0, t_exp]: `SymbolOffer accepted` for B1 owner O == 1
#                        (>= 2 -> FAIL) and B1's directory on A's disk at t_exp (4r-i47)
#                    (d) O before the restart: >= 1 already_applied=true for B1 logged after
#                        t_r (the stale notice met the fresh placement; 0 -> ROUGH)
#               6. [adversarial] t1 = t_exp + 2 s: rm -rf A:holdings/<B1> again -> within 15 s A
#                    logs a second `missing holding … DropNotice sent` for B1; within 15 s more
#                    O logs `received SymbolDropNotice` B1 holder A already_applied=false and
#                    the total of `placement marked Lost` for (B1, A) becomes 2 (still 1 ->
#                    FAIL "a new genuine drop was swallowed") (4r-i48); within 30 s A's
#                    `SymbolOffer accepted` for B1 totals 2; at t1 + 70 s both totals are still
#                    2 and B1's directory is on A's disk
#               7. control: P1, P2 have 0 `placement marked Lost` on O over the run; f1 is
#                    `restorable` on O at the end (O's belief, not a restore); with the У-4
#                    ledger on O (RUST_LOG info,viaticum::ledger=debug): exactly 2
#                    `pair-ledger drop event kind=Announced` for A's master over the run — a
#                    control of the У-4 episode check (a stale notice predates the re-placement
#                    and is not counted even without DN-1), BLIND to DN-1 (green under the
#                    no_seen_check mutation); the clock-ahead case 4r-i32 is unit DN1-5
#
# Implementation notes (how the passport is executed, not what it claims):
#   - Windows "over [t0, t_exp]" are cut by LINE numbers of each node's own log taken at t0 and
#     at t_exp (the log is appended across O's restart, so line numbers stay monotonic); "after
#     t_r" / "before the restart" likewise (A's accept line time t_r maps to O's line count at
#     the moment the script saw it, which is at or after t_r — conservative for (d)).
#   - (d) is polled for up to the time the restart window allows before O is stopped.
#   - Step 4's and 5(c)'s "no re-placement at all" is ROUGH (the loop door was not opened, a
#     property of repair, not of DN-1); a re-placement WITHOUT B1 on A's disk at t_exp is FAIL.
#   - Verdicts per step: PASS / ROUGH / FAIL; a step's verdict is the worst of its checks.
#     Exit code: 0 PASS, 3 ROUGH, 1 FAIL (run_e2e.sh logs 3 as pass-rough).
#
# Usage:
#   private/testing/run_e2e.sh drop_loop            # on the build server (release build)
#   bash experiments/local_drop_loop_test.sh        # with ./target/release/viaticum present

set -uo pipefail
# awk/printf must print "1.5", never "1,5": the log parsing below does arithmetic on text.
export LC_ALL=C

NUM_NODES=4
TIME_SCALE=20000
# Keep in sync with the code (the scenario is the guard of these numbers):
#   scaled_ttl_secs(DROP_NOTICE_TTL = 1_209_600, 20000) = 60; retention = 2 x 60 = 120.
NOTICE_TTL=60
O_RUST_LOG="info,viaticum::ledger=debug"
H_RUST_LOG="info"
TEST_DIR="/tmp/viaticum-drop-loop-$$"
BINARY="${BINARY:-viaticum}"
T_BASE=$(date -u +%s)

PIDS=()
declare -A VERDICT
STEP_ORDER=(1 2 3 4 5 6 7)
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

now_t() { echo "$(( $(date -u +%s) - T_BASE ))"; }
log_lines() { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
count_lines() { awk 'NF' | wc -l | tr -d ' '; }

O_LOG=""   # set after setup
# received_b1 AA LO [HI] -> O's `received SymbolDropNotice` lines for (B1, A's master) with
#   already_applied=AA (true|false|any), log line in (LO, HI]; one "t line" per line
received_b1() {
    events "$O_LOG" "received SymbolDropNotice" block_id holder already_applied \
        | awk -v b="$B1S" -v h="$AM" -v aa="$1" -v lo="$2" -v hi="${3:-999999999}" \
            '$3 == b && $4 == h && (aa == "any" || $5 == aa) && ($2 + 0) > lo && ($2 + 0) <= hi \
            { print $1, $2 }' || true
}
# lost_of DEV16 LO [HI] -> count of O's `placement marked Lost` for (B1, DEV) in (LO, HI]
lost_of() {
    events "$O_LOG" "placement marked Lost" block_id holder \
        | awk -v b="$B1S" -v h="$1" -v lo="$2" -v hi="${3:-999999999}" \
            '$3 == b && $4 == h && ($2 + 0) > lo && ($2 + 0) <= hi' | count_lines
}
# lost_any_block DEV16 -> count of O's `placement marked Lost` for DEV, any block, whole run
lost_any_block() {
    events "$O_LOG" "placement marked Lost" block_id holder \
        | awk -v h="$1" '$4 == h' | count_lines
}
# accepts_a LO [HI] -> "t line" of A's `SymbolOffer accepted` for B1 owner O in (LO, HI]
accepts_a() {
    events "$(node_log "$A")" "SymbolOffer accepted" owner block_id \
        | awk -v b="$B1S" -v o="$OM" -v lo="$1" -v hi="${2:-999999999}" \
            '$4 == b && $3 == o && ($2 + 0) > lo && ($2 + 0) <= hi { print $1, $2 }' || true
}
# drops_a LO -> "t line" of A's `missing holding removed from DB` for B1 owner O after line LO
drops_a() {
    events "$(node_log "$A")" "missing holding removed from DB" block_id owner \
        | awk -v b="$B1S" -v o="$OM" -v lo="$1" '$3 == b && $4 == o && ($2 + 0) > lo { print $1, $2 }' \
        || true
}
b1_on_a() { [ "$(block_symbols_on "$A" "$B1")" -gt 0 ]; }

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
echo "  Viaticum: DN-1 — one DropNotice, one application"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}, notice TTL ${NOTICE_TTL} s"
echo "============================================================"

# ── STEP 1: setup, star connect ────────────────────────────────────────────
CUR_STEP=1
echo ""
echo "=== Step 1: start 4 daemons, star-connect to O ==="
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES - 1))); do
    mkdir -p "$(node_dir "$i")/files"
    run_cli "$i" init > /dev/null 2>&1
    # As local_ledger_test: web API on, no disk reserve, no [escrow] (nothing is restored).
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF
done
start_node 0 "$TIME_SCALE" "$O_RUST_LOG"
for i in $(seq 1 $((NUM_NODES - 1))); do start_node "$i" "$TIME_SCALE" "$H_RUST_LOG"; done
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
OM="${MASTER[0]}"
A=1; P1=2; P2=3
AM=${MASTER[$A]}; AD=${DEV[$A]}
for i in $(seq 1 $((NUM_NODES - 1))); do run_cli_q "$i" connect "${ADDR[0]}" > /dev/null; done
if wait_auth_peers 0 $((NUM_NODES - 1)) 30; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers on O"
else
    fail "star connect: $(status_num 0 peer_count_authenticated)/$((NUM_NODES - 1)) authenticated after 30 s"
    finish
fi

# ── STEP 2: one file, one block, on all three holders ───────────────────────
CUR_STEP=2
echo ""
echo "=== Step 2: O backs up f1 (1 MiB); B1 must be on A, P1 AND P2 (premise of the loop door) ==="
F1="$(node_dir 0)/files/drop_loop_f1.txt"   # .txt = importance 1.0
head -c 786432 /dev/urandom | base64 -w 0 > "$F1"   # 1 MiB of text, one block
if ! wait_file_restorable 0 "$F1" 60; then
    fail "FAIL(setup): f1 not restorable per owner within 60 s"
    finish
fi
B1=$(file_block_hex 0 "$F1")
B1S=${B1:0:16}
[ -n "$B1" ] || { fail "FAIL(setup): no block id for f1"; finish; }
info "f1 -> block $B1"
holdings_table() {
    local i
    for i in 1 2 3; do echo "    node-0$i: B1 symbols=$(block_symbols_on "$i" "$B1")"; done
}
ON_ALL=""
for _ in $(seq 1 30); do   # restorable needs only k_eff symbols: late transfers may still land
    if [ "$(block_symbols_on "$A" "$B1")" -gt 0 ] && [ "$(block_symbols_on "$P1" "$B1")" -gt 0 ] \
        && [ "$(block_symbols_on "$P2" "$B1")" -gt 0 ]; then
        ON_ALL=1; break
    fi
    sleep 1
done
holdings_table
if [ -z "$ON_ALL" ]; then
    fail "FAIL(setup): B1 is not on all three holders 30 s after placement — A would not be the only repair candidate"
    finish
fi
pass "B1=$B1S.. is on A (node-0$A), P1 (node-0$P1) and P2 (node-0$P2): A is repair's only candidate after the drop"

# ── STEP 3: A drops B1 and announces it ────────────────────────────────────
CUR_STEP=3
echo ""
echo "=== Step 3: B1 vanishes from A's disk; A announces it; O marks (B1, A) Lost ==="
LO0=$(log_lines "$O_LOG")
LA0=$(log_lines "$(node_log "$A")")
rm -rf "$(node_dir "$A")/holdings/$B1"
T0=$(now_t)
info "t0 = $T0: removed node-0$A:holdings/$B1S.. (O log line $LO0, A log line $LA0)"
A_SENT=""
for _ in $(seq 1 15); do
    A_SENT=$(drops_a "$LA0" | head -1)
    [ -n "$A_SENT" ] && break
    sleep 1
done
[ -n "$A_SENT" ] && pass "A's own log: missing holding removed, immediate-drop DropNotice sent for $B1S../owner O" \
    || { fail "A's log has no 'missing holding removed from DB, immediate-drop DropNotice sent' for $B1S.. within 15 s"; finish; }
FIRST_RECV=""; FIRST_LOST=0
for _ in $(seq 1 15); do
    FIRST_RECV=$(received_b1 false "$LO0" | head -1)
    FIRST_LOST=$(lost_of "$AD" "$LO0")
    [ -n "$FIRST_RECV" ] && [ "$FIRST_LOST" -ge 1 ] && break
    sleep 1
done
[ -n "$FIRST_RECV" ] && pass "O: received SymbolDropNotice for (B1, A) already_applied=false" \
    || fail "O never logged 'received SymbolDropNotice' for (B1, A) with already_applied=false within 15 s"
[ "$FIRST_LOST" -ge 1 ] && pass "O: placement marked Lost for (B1, A's device)" \
    || fail "O never logged 'placement marked Lost' for (B1, A's device) within 15 s"

# ── STEP 4: the loop door — repair puts B1 back on A ────────────────────────
CUR_STEP=4
echo ""
echo "=== Step 4: repair re-places B1 on A (the only candidate) ==="
REPL=""
while [ "$(now_t)" -le $((T0 + 30)) ]; do
    REPL=$(accepts_a "$LA0" | head -1)
    [ -n "$REPL" ] && b1_on_a && break
    sleep 1
done
T_R=""; LO_R=0
if [ -n "$REPL" ] && b1_on_a; then
    T_R=$(echo "$REPL" | awk '{ print $1 }')
    LO_R=$(log_lines "$O_LOG")
    pass "A's own log: SymbolOffer accepted for $B1S../owner O at t_r = $T_R and B1 is on A's disk again ($(block_symbols_on "$A" "$B1") symbols)"
else
    rough "re-placement to A did not happen, loop door not exercised (accept: ${REPL:-none}, B1 symbols on A: $(block_symbols_on "$A" "$B1"))"
fi

# ── STEP 5: the stale notice keeps coming; O restarts inside its TTL ─────────
CUR_STEP=5
echo ""
echo "=== Step 5: re-deliveries of the old notice change nothing, before and after O's restart ==="
RESTARTED=""; LO_RESTART=0; D_SEEN=0
if [ -n "$T_R" ]; then
    # (d) is polled while the restart window still allows it.
    while [ $((T0 + NOTICE_TTL - $(now_t))) -gt 20 ]; do
        D_SEEN=$(received_b1 true "$LO_R" | count_lines)
        [ "$D_SEEN" -ge 1 ] && break
        sleep 1
    done
fi
LEFT=$((T0 + NOTICE_TTL - $(now_t)))
if [ "$LEFT" -ge 20 ]; then
    LO_SIGTERM=$(log_lines "$O_LOG")
    T_SIGTERM=$(date -u +%s)
    kill -TERM "${PIDS[0]}" 2>/dev/null
    if ! wait_pid_exit "${PIDS[0]}" 15; then
        kill -9 "${PIDS[0]}" 2>/dev/null
        fail "FAIL(setup): O did not exit within 15 s of SIGTERM (clean stop, R1-a)"
        finish
    fi
    info "O exited (code $EXIT_RC) $(( $(date -u +%s) - T_SIGTERM )) s after SIGTERM, ${LEFT} s of notice TTL left at SIGTERM"
    LO_RESTART=$(log_lines "$O_LOG")
    start_node 0 "$TIME_SCALE" "$O_RUST_LOG"
    wait_daemon 0 || { fail "FAIL(setup): O did not come back"; finish; }
    # No `connect` here: the restarted owner must find its peers by itself (auto-redial, R1-a).
    if wait_auth_peers 0 $((NUM_NODES - 1)) 30; then
        RESTARTED=1
        pass "O restarted inside the notice TTL and rejoined by itself ($(status_num 0 peer_count_authenticated) peers)"
    else
        rough "O restarted but has $(status_num 0 peer_count_authenticated)/$((NUM_NODES - 1)) authenticated peers 30 s later"
        RESTARTED=1
    fi
else
    LO_SIGTERM=$(log_lines "$O_LOG")
    rough "restart missed the TTL window (${LEFT} s of the ${NOTICE_TTL} s TTL left, need >= 20)"
fi
T_EXP=$((T0 + NOTICE_TTL + 10))
while [ "$(now_t)" -lt "$T_EXP" ]; do sleep 1; done
LO_EXP=$(log_lines "$O_LOG")
LA_EXP=$(log_lines "$(node_log "$A")")
TOTAL_RECV=$(received_b1 any "$LO0" "$LO_EXP" | count_lines)
TRUE_RECV=$(received_b1 true "$LO0" "$LO_EXP" | count_lines)
info "over [t0, t_exp]: O received the notice $TOTAL_RECV time(s), $TRUE_RECV of them already_applied=true"
# (a) after the restart
if [ -n "$RESTARTED" ]; then
    NA=$(received_b1 true "$LO_RESTART" "$LO_EXP" | count_lines)
    [ "$NA" -ge 1 ] && pass "(a) after the restart O received the old notice $NA time(s) with already_applied=true (the memory is on disk)" \
        || rough "(a) no post-restart re-delivery of the old notice (already_applied=true: 0)"
fi
# (b) one Lost per genuine drop
NL=$(lost_of "$AD" "$LO0" "$LO_EXP")
if [ "$NL" -eq 1 ]; then
    pass "(b) O marked (B1, A) Lost exactly once over [t0, t_exp] (4r-i47)"
elif [ "$NL" -ge 2 ]; then
    fail "(b) O marked (B1, A) Lost $NL times over [t0, t_exp] — the stale notice was applied again (4r-i47)"
else
    fail "(b) O never marked (B1, A) Lost over [t0, t_exp]"
fi
# (c) one re-placement on A, and B1 is on A's disk
NACC=$(accepts_a "$LA0" "$LA_EXP" | count_lines)
if [ "$NACC" -eq 1 ]; then
    b1_on_a && pass "(c) A accepted B1 back exactly once over [t0, t_exp] and holds it at t_exp ($(block_symbols_on "$A" "$B1") symbols) (4r-i47)" \
        || fail "(c) A accepted B1 once but B1's directory is not on A's disk at t_exp"
elif [ "$NACC" -ge 2 ]; then
    fail "(c) A accepted B1 $NACC times over [t0, t_exp] — the block bounced (4r-i47)"
else
    rough "(c) A never accepted B1 back over [t0, t_exp] (loop door not exercised; step 4)"
fi
# (d) the stale notice met the fresh placement before the restart
if [ -n "$T_R" ]; then
    D_SEEN=$(received_b1 true "$LO_R" "$LO_SIGTERM" | count_lines)
    [ "$D_SEEN" -ge 1 ] && pass "(d) before the restart the old notice met the fresh placement $D_SEEN time(s), already_applied=true, nothing changed" \
        || rough "(d) no already_applied=true re-delivery between the re-placement and the restart"
else
    rough "(d) not checkable: no re-placement (step 4)"
fi

# ── STEP 6: a second genuine drop is a new notice ──────────────────────────
CUR_STEP=6
echo ""
echo "=== Step 6: A drops B1 again — the new notice is applied, not swallowed ==="
while [ "$(now_t)" -lt $((T_EXP + 2)) ]; do sleep 1; done
if ! b1_on_a; then
    fail "FAIL(setup): B1 is not on A's disk at t1 — nothing to drop a second time"
    finish
fi
LO1=$(log_lines "$O_LOG")
LA1=$(log_lines "$(node_log "$A")")
rm -rf "$(node_dir "$A")/holdings/$B1"
T1=$(now_t)
info "t1 = $T1: removed node-0$A:holdings/$B1S.. again"
A_SENT2=""
for _ in $(seq 1 15); do
    A_SENT2=$(drops_a "$LA1" | head -1)
    [ -n "$A_SENT2" ] && break
    sleep 1
done
[ -n "$A_SENT2" ] && pass "A's own log: second 'missing holding removed … DropNotice sent' for $B1S.." \
    || { fail "A's log has no second 'missing holding removed' for $B1S.. within 15 s"; finish; }
RECV2=""; NL_TOTAL=0
for _ in $(seq 1 15); do
    RECV2=$(received_b1 false "$LO1" | head -1)
    NL_TOTAL=$(lost_of "$AD" "$LO0")
    [ -n "$RECV2" ] && [ "$NL_TOTAL" -ge 2 ] && break
    sleep 1
done
[ -n "$RECV2" ] && pass "O: received the NEW notice for (B1, A) with already_applied=false" \
    || fail "O never logged already_applied=false for (B1, A) after t1 — the new notice was taken for the old one"
if [ "$NL_TOTAL" -eq 2 ]; then
    pass "O marked (B1, A) Lost a second time (total 2) (4r-i48)"
elif [ "$NL_TOTAL" -le 1 ]; then
    fail "a new genuine drop was swallowed: (B1, A) marked Lost $NL_TOTAL time(s) in total (4r-i48)"
else
    fail "(B1, A) marked Lost $NL_TOTAL times in total, want 2"
fi
ACC2=0
while [ "$(now_t)" -le $((T1 + 30)) ]; do
    ACC2=$(accepts_a "$LA0" | count_lines)
    [ "$ACC2" -ge 2 ] && b1_on_a && break
    sleep 1
done
[ "$ACC2" -ge 2 ] && pass "A accepted B1 back after the second drop (total $ACC2)" \
    || rough "A did not accept B1 back within 30 s of the second drop (total $ACC2)"
T_END6=$((T1 + NOTICE_TTL + 10))
info "waiting for the second notice to live out its TTL (until t = $T_END6)"
while [ "$(now_t)" -lt "$T_END6" ]; do sleep 1; done
NL_FINAL=$(lost_of "$AD" "$LO0")
ACC_FINAL=$(accepts_a "$LA0" | count_lines)
TRUE2=$(received_b1 true "$LO1" | count_lines)
info "after the second TTL: Lost total $NL_FINAL, A's accepts total $ACC_FINAL, re-deliveries of the new notice with already_applied=true: $TRUE2"
[ "$NL_FINAL" -eq 2 ] && pass "(B1, A) Lost total still 2 after the second notice's TTL (4r-i47, 4r-i48)" \
    || fail "(B1, A) Lost total $NL_FINAL after the second notice's TTL, want 2"
if [ "$ACC_FINAL" -eq 2 ]; then
    b1_on_a && pass "A's accepts total still 2 and B1 is on A's disk at the end ($(block_symbols_on "$A" "$B1") symbols)" \
        || fail "A's accepts total 2 but B1 is not on A's disk at the end"
elif [ "$ACC_FINAL" -ge 3 ]; then
    fail "A accepted B1 $ACC_FINAL times — the new notice bounced the block"
else
    rough "A's accepts total $ACC_FINAL (the second re-placement did not happen)"
fi

# ── STEP 7: control ─────────────────────────────────────────────────────────
CUR_STEP=7
echo ""
echo "=== Step 7: control — P1, P2 untouched; f1 restorable; exactly 2 Announced for A ==="
for i in "$P1" "$P2"; do
    n=$(lost_any_block "${DEV[$i]}")
    [ "$n" -eq 0 ] && pass "node-0$i: 0 'placement marked Lost' on O over the run" \
        || fail "node-0$i: $n 'placement marked Lost' on O (it dropped nothing)"
done
wait_file_restorable 0 "$F1" 60 \
    && pass "f1 restorable on O at the end (O's belief; the source is still on disk, not a restore)" \
    || fail "f1 not restorable on O at the end"
NANN=$(events "$O_LOG" "pair-ledger drop event kind=" kind master block_id \
    | awk -v m="$AM" -v b="$B1S" '$3 == "Announced" && $4 == m && $5 == b' | count_lines)
[ "$NANN" -eq 2 ] && pass "exactly 2 'pair-ledger drop event kind=Announced' for (A, B1) over the run — control of the У-4 episode check (blind to DN-1; 4r-i32 is unit DN1-5)" \
    || fail "$NANN Announced event(s) for (A, B1) over the run, want 2"

finish
