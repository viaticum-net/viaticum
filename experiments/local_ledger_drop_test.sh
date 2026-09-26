#!/bin/bash
# Viaticum: the 4R pair ledger counts drops of our data per friend — one event per lost
# placement, by kind, and never for the owner's own deletions.
# Local processes on one machine (no Docker).
#
# Scenario:     6 independent nodes at time_scale 100000 star-connected to node-00, the
#               owner O, and holders node-01..05. O backs up three files one at a time (three
#               distinct blocks B1, B2, B3); the roles A, F, K, N1, N2 are assigned from the
#               holders' own disks AFTER placement (step 2).
#               Then: B1 vanishes from A's disk and A announces it (holdings integrity ->
#               DropNotice); one symbol of B2 is corrupted on F's disk and F answers PoS
#               with a wrong hash; O deletes f3 and the holders' cleanup sends the final
#               DropNotice for B3; K is SIGKILLed and goes silent. O's per-pair ledger (4R
#               recorder, decides nothing) is read from O's `pair-ledger row` and
#               `pair-ledger drop event` debug lines (RUST_LOG=info,viaticum::ledger=debug on O).
# Intent:       4r-i25, 4r-i26, 4r-i27, 4r-i28, 4r-i29, 4r-i30, 4r-i5
# Proves:       on O: exactly one Announced event for (A, B1) although the notice was
#               delivered >= 2 times; exactly one Silent event per Fail resolution for
#               (F, B2); zero events for B3 although holders sent DropNotice for it; exactly
#               E Presumed events for K (E = blocks of {B1,B2} on K's disk at the kill), none
#               at the first timeout, none added by later timeouts; the drop counters fold
#               as decay-then-add and then melt at lambda_drop = 1/56; N1/N2 stay at zero.
#               Cross-node: A's log shows it removed B1 and sent the notice; F's symbol file
#               changed and F still answered; K held E blocks and is dead; a holder's log
#               shows the post-delete cleanup notice for B3.
# Adversarial:  a holder losing data and announcing it (with mailbox re-delivery and, if it
#               happens, a stale re-delivered notice hitting a fresh re-placement); a holder
#               corrupting data silently; the owner's own deletion answered by DropNotice;
#               SIGKILL of a holder (timeouts past PresumedLost).
# Cannot close: real time (weekly PoS, 6 weeks to PresumedLost, 8-week decay — all compressed
#               by the 1 s timer floor); announced drops from disk pressure / advance notices
#               / future 4R trims (pressure tick floor 60 s, unscaled notice window) and the
#               republication with a new deadline (unit DP-3); NotHeld (not delivered over
#               the mailbox today); owner restart between recording and folding (unit DD-3);
#               DR (pending events and post-base drops are lost, 4r-i31); a holder master with
#               two devices holding one block — the notice names no device, so O may count
#               Announced on the wrong placement plus Presumed on the real one (double count,
#               4r-i35); a holder whose clock runs AHEAD: with the stale-notice loop (spec
#               У4-13 F-1) every re-placement stamped before the notice's timestamp counts a
#               new Announced (over-count, 4r-i32 — closed by the F-1 slice, not here); a live
#               holder that stops answering PoS and is re-offered its own block by repair
#               never reaches PresumedLost (4r-i33); clock jumps; comparability of counts
#               with the sim (different definitions, spec У4-5); whether 4R should ever punish
#               Presumed (phase C); the atomicity of "placement change + event" (one write
#               transaction in persist_placement_change — a crash between two separate commits
#               would under-count, or over-count on the next re-delivery; the window is not
#               reachable from a scenario, and no unit injects a failure inside it: the
#               invariant is a code comment only); the STRICTNESS of "evidence strictly
#               younger than placed_at": in every run so far a stale notice predates the
#               re-placement by >= 1 s, so step 3 cannot tell `<` from `<=` (a same-second
#               notice is not produced on demand) — units DC-1 and DP-6 hold it.
# Steps:        1. start 6 daemons, star-connect -> O has 5 authenticated peers and, within
#                    10 s, `pair-ledger row` lines for all 5 peer masters, every drop field and
#                    event count 0 (4r-i5) — check: wait_auth_peers; events over O's log
#               2. O writes f1, f2, f3 ONE AT A TIME, each restorable within 60 s; three
#                    DISTINCT blocks (file_block_hex). Roles by block_symbols_on over
#                    node-01..05, lowest index first, all distinct: A = holds B1; F = holds
#                    B2; K = holds B1 AND B2; N1, N2 = the rest. Premise (named, not assumed
#                    silently): the placement spreads each block over most of the 5 holders,
#                    as in local_pos_repair_test; no such assignment = FAIL(setup) with the
#                    holdings table printed, not skip. Then >= 1 Pass from each of A, F, K in
#                    O's log within 30 s; still zero `pair-ledger drop event` lines (backup
#                    and PoS are not drops)
#               3. [adversarial] rm -rf A:holdings/<B1> -> within 10 s A's log has `missing
#                    holding removed from DB, immediate-drop DropNotice sent` for B1/owner O;
#                    within 20 s O has exactly 1 `pair-ledger drop event kind=Announced` for
#                    (master A, B1); O's `received SymbolDropNotice` for (B1, holder=A) >= 2
#                    (== 1 -> ROUGH "re-delivery door not exercised"); branch: if O logs >= 2
#                    `placement marked Lost` for (B1, A's device), then >= 1 `pair-ledger drop
#                    not counted reason=EvidenceBeforeEpisode` and still 1 event (4r-i29),
#                    else ROUGH "stale-notice door not exercised"; A's rows: silent/presumed
#                    events 0 (4r-i25, 4r-i29)
#               4. [adversarial] overwrite 16 bytes of one symbol file F:holdings/<B2>/<esi>.bin
#                    (sha256 before != after) -> within 20 s O: `mailbox PosResponse resolved`
#                    block B2 holder F outcome=Fail; F's log `responding with chain hash` for
#                    B2 after the corruption time; `kind=Silent` events for F == number of
#                    those Fail lines (>= 1), all block B2; F's ann/presumed events 0 (4r-i27)
#               5. [adversarial] O deletes f3 from its watch dir (daemon alive) -> within 120 s
#                    >= 1 holder log `expired holding cleaned up, immediate-drop DropNotice
#                    sent via mailbox` for B3/owner O and O's `received SymbolDropNotice` for
#                    B3 -> zero `pair-ledger drop event` with block B3 over the whole run; no
#                    Deleting/missing placement produced an event (4r-i26)
#               6. [adversarial] after step 5 (K's B3 placement is Deleting or gone): E = number
#                    of {B1, B2} with symbols on K's disk (expect 2). Premise (4r-i33): a
#                    KILLED K is not authenticated, so repair (snapshot_pool takes only
#                    authenticated peers while >= min_size remain) cannot re-offer K and
#                    reset its timeout ladder; if O's log shows an offer/`Offered` placement to
#                    K's device after the kill -> FAIL(setup) "premise broken", not a verdict
#                    on the recorder. SIGKILL K -> within 120 s O
#                    logs `PoS challenge timed out` for K's device with new_status=PresumedLost
#                    for each of the E blocks (the transition line has misses=3; later lines
#                    repeat new_status=PresumedLost with misses >= 4); exactly E `kind=Presumed`
#                    events for K, one per block, each not earlier than the misses=3 line of
#                    that block; then wait
#                    until O logs >= 2 further timeouts for K's device -> still E; Σ
#                    presumed_events on K's rows == E; no Announced/Silent for K; `kill -0`
#                    on K fails (4r-i28)
#               7. fold order + decay: A's row R1 with ann_events=1: drop_ann(R1) ==
#                    drop_ann(R0)*decay(dt_R1) + 1 (rel. tol 1e-12; decay splits dark/observed
#                    exactly like the recorder when dt > 3.4722 days); then over >= 20 later A
#                    rows with ann_events=0: drop_ann strictly decreases, stays > 0 and lies in
#                    [V*(1 - L*Σdt), V*exp(-L*Σdt)], L = 1/56 (keep in sync with
#                    PAIR_LEDGER_LAMBDA_DROP; analytic bounds — the expected value at 20
#                    on-schedule rows is ~0.6586 inside [0.5866, 0.6615]; never widen the
#                    bound to fit a run); the same for F's drop_silent and K's
#                    drop_presumed over >= 10 rows (4r-i30)
#               8. control: over the whole run N1/N2 rows have every drop field and event count
#                    0; rows for all 5 masters continue to the end; f1 and f2 are back to
#                    `effective_status = restorable` on O at the end (wait_file_restorable —
#                    O's own belief that repair re-placed them; NOT a restore, the source is
#                    still on disk) (4r-i5)
#
# Implementation notes (how the passport is executed, not what it claims):
#   - "Each Presumed event not earlier than the misses=3 line of its block" (step 6) is checked
#     by CAUSE, not by clock: the event line is written inside the transition's own
#     transaction, i.e. microseconds BEFORE the scheduler's `PoS challenge timed out` info
#     line, so the check is "the first `PoS challenge timed out` line for (block, K's device)
#     after the event line has new_status=PresumedLost and misses=3". An event recorded at the
#     first timeout (misses=1) fails it.
#   - Step 6's premise guard reads O's `work_pipeline:` lines naming K's device after the
#     kill: every offer/transfer attempt of the worker logs the holder's device there.
#   - Step 7's fold check takes EVERY row with events of that kind (a second Fail after a
#     repair re-placed B2 on F would add a legitimate row) and the melt window starts after
#     the last of them.
#   - Whole-run re-checks at the end (B3 has zero events; A has exactly one Announced; F's
#     Silent events still equal its Fail lines) are booked on the step that owns them.
#   - Step 3's stale-notice branch catches a MISSING episode check (the mutation "no
#     evidence_at > placed_at" gives one Announced per re-placement), but not a NON-STRICT one
#     (`>=` instead of `>`): it would need a notice stamped in the same second as the
#     re-placement, which the run does not produce on demand. That strictness is units
#     DC-1 / DP-6 only (see Cannot close).
#   - Verdicts per step: PASS / ROUGH / FAIL. Exit code: 0 PASS, 3 ROUGH, 1 FAIL
#     (run_e2e.sh logs 3 as pass-rough).
#
# Usage:
#   private/testing/run_e2e.sh ledger_drop     # on the build server (release build)
#   bash experiments/local_ledger_drop_test.sh # with ./target/release/viaticum present

set -uo pipefail
# awk/printf must print "1.5", never "1,5": the log parsing below does arithmetic on text.
export LC_ALL=C

NUM_NODES=6
TIME_SCALE=100000
O_RUST_LOG="info,viaticum::ledger=debug"
H_RUST_LOG="info,viaticum::daemon::processor::pos=debug"
# Keep in sync with the code (the scenario is the guard of these numbers):
#   PAIR_LEDGER_LAMBDA_DROP = 1/56; the sub-step ceiling = PAIR_LEDGER_MAX_LAMBDA_DT / λ_drop
#   = 28 days; observed window at 100000 = 3 * 100000 / 86400 days.
L_DROP="0.017857142857142856"   # 1/56
MAX_STEP="28"
OBS_WINDOW="3.4722222222222223"  # observed_window_days(100000)
TEST_DIR="/tmp/viaticum-ledger-drop-$$"
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

now_t() { echo "$(( $(date -u +%s) - T_BASE ))"; }
now_tf() { awk -v n="$(date -u +%s.%N)" -v b="$T_BASE" 'BEGIN { printf "%.3f", n - b }'; }
log_lines() { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

O_LOG=""   # set after setup
# ledger_rows MASTER16 [AFTER_LINE] -> rows of O's ledger for that master:
#   1 t  2 line  3 dt_days  4 drop_ann  5 drop_silent  6 drop_presumed
#   7 ann_events  8 silent_events  9 presumed_events
ledger_rows() {
    events "$O_LOG" "pair-ledger row" master dt_days drop_ann drop_silent drop_presumed \
        ann_events silent_events presumed_events \
        | awk -v m="$1" -v lo="${2:-0}" \
            '$3 == m && ($2 + 0) > lo { print $1, $2, $4, $5, $6, $7, $8, $9, $10 }' || true
}
# drop_events KIND|any MASTER16|any -> "t line kind master block holder" of O's event lines
drop_events() {
    events "$O_LOG" "pair-ledger drop event kind=" kind master block_id holder \
        | awk -v k="$1" -v m="$2" '(k == "any" || $3 == k) && (m == "any" || $4 == m) \
            { print $1, $2, $3, $4, $5, $6 }' || true
}
count_lines() { awk 'NF' | wc -l | tr -d ' '; }
# resolved DEV16 OUTCOME [BLOCK16|any] -> "t line block" of O's resolved PoS for DEV
resolved() {
    events "$O_LOG" "mailbox PosResponse resolved" block_id holder outcome \
        | awk -v h="$1" -v o="$2" -v b="${3:-any}" \
            '$4 == h && $5 == o && (b == "any" || $3 == b) { print $1, $2, $3 }' || true
}
# timeouts_of DEV16 [AFTER_LINE] -> "t line block new_status misses"
timeouts_of() {
    events "$O_LOG" "PoS challenge timed out" block_id holder_id new_status misses \
        | awk -v h="$1" -v lo="${2:-0}" '$4 == h && ($2 + 0) > lo { print $1, $2, $3, $5, $6 }' \
        || true
}
notices_received() { # BLOCK16 HOLDER_MASTER16|any [AFTER_LINE] -> count
    events "$O_LOG" "received SymbolDropNotice" block_id holder \
        | awk -v b="$1" -v h="$2" -v lo="${3:-0}" \
            '$3 == b && (h == "any" || $4 == h) && ($2 + 0) > lo' | count_lines
}
all_row_drop_fields_zero() { # MASTER16|any -> "rows nonzero missing"
    events "$O_LOG" "pair-ledger row" master drop_ann drop_silent drop_presumed ann_events \
        silent_events presumed_events \
        | awk -v m="$1" '(m == "any" || $3 == m) { n++
            for (i = 4; i <= 9; i++) { if ($i == "-") miss++; else if (($i + 0) != 0) bad++ } }
            END { printf "%d %d %d", n + 0, bad + 0, miss + 0 }'
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

# check_fold_melt MASTER16 VALUE_COL EVENTS_COL NAME MIN_ROWS
#   Every row with events > 0: value == prev_value * decay(dt) + events (rel. tol 1e-12),
#   decay = the recorder's split (dark part first, then the observed window; each part in
#   sub-steps of at most MAX_STEP days, factor max(0, 1 - L*step)). Then the first MIN_ROWS
#   rows after the LAST event row: events == 0, value strictly decreasing, > 0, and the last
#   one inside [V*(1 - L*Σdt), V*exp(-L*Σdt)]. Prints the verdict lines itself.
check_fold_melt() {
    local m="$1" vc="$2" ec="$3" name="$4" want="$5" rows res
    local n_ev fold_bad n_after dec_bad pos_bad inb v last lo hi sum
    rows=$(ledger_rows "$m")
    res=$(echo "$rows" | awk -v vc="$vc" -v ec="$ec" -v L="$L_DROP" -v MS="$MAX_STEP" \
        -v W="$OBS_WINDOW" -v want="$want" '
        function ceil(x) { return (x == int(x)) ? x : int(x) + 1 }
        function leak(dt,   n, step, f, g, i) {
            if (dt <= 0) return 1
            n = (dt <= MS) ? 1 : ceil(dt / MS); step = dt / n; f = 1
            for (i = 0; i < n; i++) { g = 1 - L * step; if (g < 0) g = 0; f = f * g }
            return f
        }
        function decay(dt) { return (dt > W) ? leak(dt - W) * leak(W) : leak(dt) }
        NF { r++; V[r] = $vc + 0; E[r] = $ec + 0; DT[r] = $3 + 0 }
        END {
            last = 0
            for (i = 2; i <= r; i++) if (E[i] > 0) {
                nev++; last = i
                exp_v = V[i - 1] * decay(DT[i]) + E[i]
                d = V[i] - exp_v; if (d < 0) d = -d
                tol = 1e-12 * (exp_v > 1 ? exp_v : 1)
                if (d > tol) fold_bad++
            }
            if (last == 0) { printf "0 0 0 0 0 0 0 0 0 0"; exit }
            vv = V[last]; pv = vv; sum = 0; n = 0
            for (i = last + 1; i <= r && n < want; i++) {
                n++; sum += DT[i]
                if (E[i] != 0) dec_bad++
                else if (!(V[i] < pv)) dec_bad++
                if (!(V[i] > 0)) pos_bad++
                pv = V[i]
            }
            lo = vv * (1 - L * sum); hi = vv * exp(-L * sum)
            inb = (n > 0 && pv >= lo && pv <= hi) ? 1 : 0
            printf "%d %d %d %d %d %d %.17g %.17g %.17g %.17g", nev, fold_bad + 0, n, \
                dec_bad + 0, pos_bad + 0, inb, vv, pv, lo, hi
        }')
    read -r n_ev fold_bad n_after dec_bad pos_bad inb v last lo hi <<< "$res"
    info "$name: $n_ev event row(s); melt over $n_after rows: V = $v -> $last, bounds [$lo, $hi]"
    if [ "$n_ev" -ge 1 ] && [ "$fold_bad" -eq 0 ]; then
        pass "$name: every event row = previous row x decay(dt) + events (decay first, then +N)"
    else
        fail "$name: $n_ev event row(s), $fold_bad folded differently from 'decay over the interval, then +N'"
    fi
    [ "$n_after" -ge "$want" ] && pass "$name: $n_after rows after the last event" \
        || fail "$name: only $n_after rows after the last event (want $want)"
    [ "$dec_bad" -eq 0 ] && pass "$name: strictly decreasing, no new events over the melt" \
        || fail "$name: $dec_bad row(s) that did not decrease or carried a new event"
    [ "$pos_bad" -eq 0 ] && pass "$name: stays > 0 (forgiven slowly, not reset)" \
        || fail "$name: $pos_bad row(s) at or below 0"
    [ "$inb" -eq 1 ] && pass "$name: inside [V(1 - L·Σdt), V·e^(-L·Σdt)], L = 1/56 (λ_drop, not λ)" \
        || fail "$name: $last outside [$lo, $hi]"
}

echo "============================================================"
echo "  Viaticum: 4R pair ledger — drop events per friend"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "============================================================"

# ── STEP 1: setup, star connect, zero drop fields on every row ───────────
CUR_STEP=1
echo ""
echo "=== Step 1: start, star-connect, ledger rows for all 5 peer masters, drops at 0 ==="
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
for i in $(seq 1 $((NUM_NODES - 1))); do run_cli_q "$i" connect "${ADDR[0]}" > /dev/null; done
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
[ "$GOT_MASTERS" = "$WANT_MASTERS" ] \
    && pass "pair-ledger rows on O for exactly the 5 peer masters (4r-i5)" \
    || fail "pair-ledger masters on O: [${GOT_MASTERS}] want [${WANT_MASTERS}] (10 s after auth)"
read -r R_N R_BAD R_MISS <<< "$(all_row_drop_fields_zero any)"
if [ "$R_N" -ge 1 ] && [ "$R_BAD" -eq 0 ] && [ "$R_MISS" -eq 0 ]; then
    pass "all $R_N rows so far carry the six drop fields, all 0"
else
    fail "rows so far: $R_N, $R_BAD non-zero drop field(s), $R_MISS missing drop field(s)"
fi

# ── STEP 2: three files, three blocks, roles from the holders' disks ───────
CUR_STEP=2
echo ""
echo "=== Step 2: back up f1, f2, f3 one at a time; roles A, F, K, N1, N2 from the disks ==="
declare -A FILE BLOCK BSHORT
for n in 1 2 3; do
    FILE[$n]="$(node_dir 0)/files/drop_f$n.txt"   # .txt = importance 1.0
    head -c 196608 /dev/urandom | base64 -w 0 > "${FILE[$n]}"   # ~256 KB of text, one block
    if ! wait_file_restorable 0 "${FILE[$n]}" 60; then
        fail "FAIL(setup): f$n not restorable per owner within 60 s"
        finish
    fi
    BLOCK[$n]=$(file_block_hex 0 "${FILE[$n]}")
    BSHORT[$n]=${BLOCK[$n]:0:16}
    info "f$n -> block ${BLOCK[$n]}"
done
if [ -z "${BLOCK[1]}" ] || [ -z "${BLOCK[2]}" ] || [ -z "${BLOCK[3]}" ] \
    || [ "${BLOCK[1]}" = "${BLOCK[2]}" ] || [ "${BLOCK[2]}" = "${BLOCK[3]}" ] \
    || [ "${BLOCK[1]}" = "${BLOCK[3]}" ]; then
    fail "FAIL(setup): the three files are not three distinct blocks (${BLOCK[1]:-?} ${BLOCK[2]:-?} ${BLOCK[3]:-?})"
    finish
fi
pass "three distinct blocks B1=${BSHORT[1]} B2=${BSHORT[2]} B3=${BSHORT[3]}"
B1S=${BSHORT[1]}; B2S=${BSHORT[2]}; B3S=${BSHORT[3]}
holds() { [ "$(block_symbols_on "$1" "$2")" -gt 0 ]; }
assign_roles() { # sets A F K N1 N2; returns 1 when no assignment exists
    local a f k i
    A=""; F=""; K=""; N1=""; N2=""
    for a in 1 2 3 4 5; do holds "$a" "${BLOCK[1]}" || continue
        for f in 1 2 3 4 5; do [ "$f" -eq "$a" ] && continue; holds "$f" "${BLOCK[2]}" || continue
            for k in 1 2 3 4 5; do
                [ "$k" -eq "$a" ] || [ "$k" -eq "$f" ] && continue
                holds "$k" "${BLOCK[1]}" && holds "$k" "${BLOCK[2]}" || continue
                A=$a; F=$f; K=$k
                for i in 1 2 3 4 5; do
                    [ "$i" -eq "$a" ] || [ "$i" -eq "$f" ] || [ "$i" -eq "$k" ] && continue
                    if [ -z "$N1" ]; then N1=$i; else N2=$i; fi
                done
                return 0
            done
        done
    done
    return 1
}
holdings_table() {
    local i
    for i in 1 2 3 4 5; do
        echo "    node-0$i: B1=$(block_symbols_on "$i" "${BLOCK[1]}") B2=$(block_symbols_on "$i" "${BLOCK[2]}") B3=$(block_symbols_on "$i" "${BLOCK[3]}")"
    done
}
ASSIGNED=""
for _ in $(seq 1 30); do   # restorable needs only k_eff symbols: late transfers may still land
    if assign_roles; then ASSIGNED=1; break; fi
    sleep 1
done
holdings_table
if [ -z "$ASSIGNED" ]; then
    fail "FAIL(setup): no distinct A (B1), F (B2), K (B1 and B2) among node-01..05 30 s after placement — the premise 'each block spreads over most holders' did not hold"
    finish
fi
AM=${MASTER[$A]}; AD=${DEV[$A]}; FM=${MASTER[$F]}; FD=${DEV[$F]}; KM=${MASTER[$K]}; KD=${DEV[$K]}
pass "roles: A=node-0$A F=node-0$F K=node-0$K N1=node-0$N1 N2=node-0$N2"
PASSED=""
for _ in $(seq 1 30); do
    if [ -n "$(resolved "$AD" Pass)" ] && [ -n "$(resolved "$FD" Pass)" ] && [ -n "$(resolved "$KD" Pass)" ]; then
        PASSED=1; break
    fi
    sleep 1
done
[ -n "$PASSED" ] && pass ">= 1 PoS Pass resolved on O from each of A, F, K" \
    || fail "no Pass from each of A ($(resolved "$AD" Pass | count_lines)), F ($(resolved "$FD" Pass | count_lines)), K ($(resolved "$KD" Pass | count_lines)) within 30 s"
N_EV=$(drop_events any any | count_lines)
[ "$N_EV" -eq 0 ] && pass "zero drop events after backup and PoS (neither is a drop)" \
    || fail "$N_EV drop event(s) before any drop: $(drop_events any any | head -3 | tr '\n' ';')"

# ── STEP 3: A loses B1 and announces it ─────────────────────────────────
CUR_STEP=3
echo ""
echo "=== Step 3: B1 vanishes from A's disk; A announces it — one Announced event ==="
L3=$(log_lines "$O_LOG")
rm -rf "$(node_dir "$A")/holdings/${BLOCK[1]}"
T3=$(now_t)
info "removed node-0$A:holdings/$B1S.. at t=$T3"
A_SENT=""
for _ in $(seq 1 10); do
    A_SENT=$(events "$(node_log "$A")" "missing holding removed from DB" block_id owner \
        | awk -v b="$B1S" -v o="$OM" '$3 == b && $4 == o' | head -1)
    [ -n "$A_SENT" ] && break
    sleep 1
done
[ -n "$A_SENT" ] && pass "A's own log: missing holding removed, immediate-drop DropNotice sent for $B1S../owner O" \
    || fail "A's log has no 'missing holding removed from DB, immediate-drop DropNotice sent' for $B1S.. within 10 s"
ANN_AB1=0
for _ in $(seq 1 20); do
    ANN_AB1=$(drop_events Announced "$AM" | awk -v b="$B1S" '$5 == b' | count_lines)
    [ "$ANN_AB1" -ge 1 ] && break
    sleep 1
done
[ "$ANN_AB1" -ge 1 ] || { fail "no Announced event for (A, $B1S..) on O within 20 s"; }
# Let the notice live out its TTL (12 s at 100000) plus polls: every re-delivery happens
# before we count.
while [ "$(now_t)" -lt $((T3 + 25)) ]; do sleep 1; done
ANN_AB1=$(drop_events Announced "$AM" | awk -v b="$B1S" '$5 == b' | count_lines)
DELIV=$(notices_received "$B1S" "$AM" "$L3")
info "O received the B1 notice from A $DELIV time(s); Announced events for (A, B1): $ANN_AB1"
[ "$ANN_AB1" -eq 1 ] && pass "exactly 1 Announced event for (A, $B1S..) (4r-i25)" \
    || fail "$ANN_AB1 Announced event(s) for (A, $B1S..), want exactly 1"
if [ "$DELIV" -ge 2 ]; then
    pass "the notice was delivered $DELIV times and counted once (re-delivery door, 4r-i25)"
elif [ "$DELIV" -eq 1 ]; then
    rough "the notice was delivered once — the re-delivery door was not exercised"
else
    fail "O never logged 'received SymbolDropNotice' for (B1, A)"
fi
LOST_AB1=$(events "$O_LOG" "placement marked Lost" block_id holder \
    | awk -v b="$B1S" -v h="$AD" -v lo="$L3" '$3 == b && $4 == h && ($2 + 0) > lo' | count_lines)
STALE=$(events "$O_LOG" "pair-ledger drop not counted" reason block_id holder \
    | awk -v b="$B1S" -v h="$AD" '$3 == "EvidenceBeforeEpisode" && $4 == b && $5 == h' | count_lines)
info "placement (B1, A) marked Lost $LOST_AB1 time(s); not counted as EvidenceBeforeEpisode: $STALE"
if [ "$LOST_AB1" -ge 2 ]; then
    [ "$STALE" -ge 1 ] && [ "$ANN_AB1" -eq 1 ] \
        && pass "stale notice hit a re-placement $((LOST_AB1 - 1)) time(s): not counted (EvidenceBeforeEpisode), still 1 event (4r-i29)" \
        || fail "(B1, A) marked Lost $LOST_AB1 times but $STALE 'not counted' line(s) and $ANN_AB1 event(s) (4r-i29)"
else
    rough "stale-notice door not exercised: (B1, A) marked Lost $LOST_AB1 time(s) (repair did not re-place B1 on A inside the notice TTL)"
fi
read -r A_SIL A_PRE A_ANN <<< "$(ledger_rows "$AM" | awk '{ s += $8; p += $9; a += $7 } END { printf "%d %d %d", s, p, a }')"
[ "$A_SIL" -eq 0 ] && [ "$A_PRE" -eq 0 ] && pass "A's rows: silent/presumed events 0" \
    || fail "A's rows: silent_events=$A_SIL presumed_events=$A_PRE"
[ "$A_ANN" -eq 1 ] && pass "Σ ann_events over A's rows = 1 (the event was folded, once)" \
    || fail "Σ ann_events over A's rows = $A_ANN, want 1"

# ── STEP 4: F corrupts B2 and answers PoS with a wrong hash ────────────────
CUR_STEP=4
echo ""
echo "=== Step 4: one symbol of B2 corrupted on F's disk — Silent events == Fail lines ==="
SYM=$(find "$(node_dir "$F")/holdings/${BLOCK[2]}" -maxdepth 1 -type f -name '*.bin' 2>/dev/null | sort | head -1)
if [ -z "$SYM" ]; then
    fail "FAIL(setup): F (node-0$F) has no symbol file of B2 any more"
    finish
fi
SHA_BEFORE=$(content_hash "$SYM")
T4=$(now_tf)
dd if=/dev/urandom of="$SYM" bs=16 count=1 conv=notrunc status=none
SHA_AFTER=$(content_hash "$SYM")
if [ "$SHA_BEFORE" != "$SHA_AFTER" ]; then
    pass "F's $(basename "$SYM") changed on F's own disk (sha256 ${SHA_BEFORE:0:12}.. -> ${SHA_AFTER:0:12}..)"
else
    fail "FAIL(setup): overwriting 16 bytes did not change F's symbol file"
    finish
fi
FAILS=""
for _ in $(seq 1 20); do
    FAILS=$(resolved "$FD" Fail "$B2S" | awk -v t="$T4" '($1 + 0) > t')
    [ -n "$FAILS" ] && break
    sleep 1
done
[ -n "$FAILS" ] && pass "O resolved F's PoS for $B2S.. as Fail after the corruption" \
    || fail "no 'mailbox PosResponse resolved ... outcome=Fail' for (B2, F) within 20 s"
F_ANSWERED=$(events "$(node_log "$F")" "responding with chain hash" block_id \
    | awk -v b="$B2S" -v t="$T4" '$3 == b && ($1 + 0) > t' | count_lines)
[ "$F_ANSWERED" -ge 1 ] && pass "F's own log: it answered with a chain hash for $B2S.. after the corruption (answered, not silent)" \
    || fail "F's log has no 'responding with chain hash' for $B2S.. after the corruption"
sleep 3   # the event is written with the Fail; let a trailing Fail and its fold land
check_silent() { # -> "fails silent_events silent_other_blocks f_ann f_pre"
    local nf ns no fa fp
    nf=$(resolved "$FD" Fail "$B2S" | count_lines)
    ns=$(drop_events Silent "$FM" | awk -v b="$B2S" '$5 == b' | count_lines)
    no=$(drop_events Silent "$FM" | awk -v b="$B2S" '$5 != b' | count_lines)
    fa=$(drop_events Announced "$FM" | count_lines)
    fp=$(drop_events Presumed "$FM" | count_lines)
    echo "$nf $ns $no $fa $fp"
}
read -r NF NS NO FA FP <<< "$(check_silent)"
info "(B2, F): $NF Fail resolution(s), $NS Silent event(s); F's other-block Silent: $NO"
[ "$NF" -ge 1 ] && [ "$NS" -eq "$NF" ] && [ "$NO" -eq 0 ] \
    && pass "Silent events for F == Fail resolutions for (B2, F) == $NF, all block B2 (4r-i27)" \
    || fail "Silent events for F: $NS on B2 + $NO elsewhere, Fail resolutions for (B2, F): $NF — $(events "$O_LOG" "pair-ledger drop not counted" reason cause holder | awk -v h="$FD" '$5 == h' | tr '\n' ';')"
[ "$FA" -eq 0 ] && [ "$FP" -eq 0 ] && pass "F: no Announced / Presumed events" \
    || fail "F: $FA Announced, $FP Presumed event(s)"

# ── STEP 5: the owner's own deletion is not a drop ──────────────────────────
CUR_STEP=5
echo ""
echo "=== Step 5: O deletes f3 — the holders' final DropNotice is not the friends' drop ==="
L5=$(log_lines "$O_LOG")
rm -f "${FILE[3]}"
T5=$(now_t)
CLEANED=""; RECV3=0
for _ in $(seq 1 120); do
    if [ -z "$CLEANED" ]; then
        for i in 1 2 3 4 5; do
            if events "$(node_log "$i")" "expired holding cleaned up" block_id owner \
                | awk -v b="$B3S" -v o="$OM" '$3 == b && $4 == o' | grep -q .; then
                CLEANED="node-0$i"; break
            fi
        done
    fi
    RECV3=$(notices_received "$B3S" any "$L5")
    [ -n "$CLEANED" ] && [ "$RECV3" -ge 1 ] && break
    sleep 1
done
info "f3 deleted at t=$T5; cleanup notice first seen on ${CLEANED:-none}; O received $RECV3 notice(s) for B3"
[ -n "$CLEANED" ] && pass "$CLEANED's own log: expired holding cleaned up, immediate-drop DropNotice sent for $B3S../owner O" \
    || fail "no holder logged 'expired holding cleaned up ...' for $B3S.. within 120 s"
[ "$RECV3" -ge 1 ] && pass "O received $RECV3 DropNotice(s) for B3 (the door was exercised)" \
    || fail "O never logged 'received SymbolDropNotice' for B3 within 120 s — 'zero events' would prove nothing"
sleep 3
EV3=$(drop_events any any | awk -v b="$B3S" '$5 == b' | count_lines)
[ "$EV3" -eq 0 ] && pass "zero drop events for B3 (4r-i26: my deletion is not the friend's drop)" \
    || fail "$EV3 drop event(s) for B3: $(drop_events any any | awk -v b="$B3S" '$5 == b' | head -3 | tr '\n' ';')"

# ── STEP 6: K dies; three missed challenges per block -> one Presumed each ──
CUR_STEP=6
echo ""
echo "=== Step 6: SIGKILL K — one Presumed per block at the third timeout, none later ==="
E_BLOCKS=""
for n in 1 2; do holds "$K" "${BLOCK[$n]}" && E_BLOCKS="$E_BLOCKS ${BSHORT[$n]}"; done
E=$(echo "$E_BLOCKS" | wc -w | tr -d ' ')
info "K (node-0$K) holds $E of {B1, B2} on its own disk:$E_BLOCKS"
if [ "$E" -eq 0 ]; then
    fail "FAIL(setup): K holds neither B1 nor B2 at the kill — nothing to presume lost"
    finish
fi
[ "$E" -eq 2 ] && pass "E = 2: K holds B1 and B2" \
    || rough "E = $E (expected 2): K no longer holds one of B1/B2 at the kill"
L6=$(log_lines "$O_LOG")
kill -9 "${PIDS[$K]}" 2>/dev/null
wait "${PIDS[$K]}" 2>/dev/null
info "SIGKILL node-0$K at O log line $L6"
DONE6=""
for _ in $(seq 1 120); do
    n3=0
    for b in $E_BLOCKS; do
        timeouts_of "$KD" "$L6" | awk -v b="$b" '$3 == b && $4 == "PresumedLost" && $5 == "3"' | grep -q . && n3=$((n3 + 1))
    done
    [ "$n3" -eq "$E" ] && { DONE6=1; break; }
    sleep 1
done
timeouts_of "$KD" "$L6" | sed 's/^/    timeout | /'
if [ -n "$DONE6" ]; then
    pass "O: PresumedLost (misses=3) for K on each of the $E block(s)"
else
    fail "O did not reach PresumedLost (misses=3) for K on all $E block(s) within 120 s"
fi
OFFERS_K=$(log_since 0 "$L6" | grep -a "work_pipeline:" | grep -ac "holder=$KD" || true)
if [ "$OFFERS_K" -gt 0 ]; then
    fail "FAIL(setup): premise broken (4r-i33) — O's worker named K's device $OFFERS_K time(s) after the kill (re-offer to a dead peer resets the ladder)"
fi
# Each Presumed event must be the misses=3 transition of its block: the FIRST timeout line
# for (block, K) after the event line is that transition.
presumed_ok() { # -> "events per_block_ok cause_bad blocks_seen"
    local evs
    evs=$(drop_events Presumed "$KM")
    echo "$evs" | awk 'NF' | while read -r _ eline _ _ eb _; do
        timeouts_of "$KD" "$eline" | awk -v b="$eb" '$3 == b { print $4, $5; exit }'
    done | awk -v n="$(echo "$evs" | count_lines)" \
        '{ if (!($1 == "PresumedLost" && $2 == "3")) bad++ } END { printf "%d %d", n, bad + 0 }'
}
read -r NP NP_BAD <<< "$(presumed_ok)"
PB=$(drop_events Presumed "$KM" | awk '{print $5}' | sort | tr '\n' ' ')
WANTB=$(for b in $E_BLOCKS; do echo "$b"; done | sort | tr '\n' ' ')
info "Presumed events for K: $NP on blocks [$PB] (want [$WANTB])"
[ "$NP" -eq "$E" ] && [ "$PB" = "$WANTB" ] && pass "exactly $E Presumed event(s) for K, one per block (4r-i28)" \
    || fail "$NP Presumed event(s) for K on [$PB], want one per block of [$WANTB]"
[ "$NP_BAD" -eq 0 ] && pass "each Presumed event is its block's misses=3 transition (none at the first timeout)" \
    || fail "$NP_BAD Presumed event(s) not produced by a misses=3 PresumedLost transition"
LAST3=$(timeouts_of "$KD" "$L6" | awk '$4 == "PresumedLost" && $5 == "3" { l = $2 } END { print l + 0 }')
MORE=0
for _ in $(seq 1 60); do
    MORE=$(timeouts_of "$KD" "$LAST3" | count_lines)
    [ "$MORE" -ge 2 ] && break
    sleep 1
done
[ "$MORE" -ge 2 ] && pass "$MORE further timeout(s) for K after PresumedLost" \
    || fail "only $MORE further timeout(s) for K within 60 s — 'later timeouts add nothing' is not shown"
sleep 2
NP2=$(drop_events Presumed "$KM" | count_lines)
[ "$NP2" -eq "$E" ] && pass "still $E Presumed event(s) after the later timeouts" \
    || fail "$NP2 Presumed event(s) after the later timeouts, want $E"
KSUM=$(ledger_rows "$KM" | awk '{ s += $9 } END { print s + 0 }')
[ "$KSUM" -eq "$E" ] && pass "Σ presumed_events on K's rows = $E (folded, once)" \
    || fail "Σ presumed_events on K's rows = $KSUM, want $E"
KAS=$(drop_events any "$KM" | awk '$3 != "Presumed"' | count_lines)
[ "$KAS" -eq 0 ] && pass "no Announced/Silent event for K" || fail "$KAS Announced/Silent event(s) for K"
kill -0 "${PIDS[$K]}" 2>/dev/null && fail "K's process is still alive" || pass "K's process is gone"

# ── STEP 7: fold order and the λ_drop melt ─────────────────────────────────
CUR_STEP=7
echo ""
echo "=== Step 7: decay first, then +N; the counters melt at l_drop = 1/56 ==="
wait_rows_after_last_event() { # MASTER16 EVENTS_COL N SECS
    local m="$1" ec="$2" want="$3" secs="$4" last n
    for _ in $(seq 1 "$secs"); do
        last=$(ledger_rows "$m" | awk -v c="$ec" '($c + 0) > 0 { l = $2 } END { print l + 0 }')
        n=$(ledger_rows "$m" "$last" | count_lines)
        [ "$last" -gt 0 ] && [ "$n" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}
wait_rows_after_last_event "$AM" 7 20 40 || true
check_fold_melt "$AM" 4 7 "A drop_ann" 20
wait_rows_after_last_event "$FM" 8 10 40 || true
check_fold_melt "$FM" 5 8 "F drop_silent" 10
wait_rows_after_last_event "$KM" 9 10 40 || true
check_fold_melt "$KM" 6 9 "K drop_presumed" 10

# ── STEP 8: control and whole-run re-checks ───────────────────────────────
CUR_STEP=8
echo ""
echo "=== Step 8: N1/N2 at zero all run; all masters still recorded; f1, f2 restorable ==="
for i in "$N1" "$N2"; do
    read -r R_N R_BAD R_MISS <<< "$(all_row_drop_fields_zero "${MASTER[$i]}")"
    [ "$R_N" -ge 1 ] && [ "$R_BAD" -eq 0 ] && [ "$R_MISS" -eq 0 ] \
        && pass "node-0$i (control): all $R_N rows have every drop field and event count 0" \
        || fail "node-0$i (control): $R_N rows, $R_BAD non-zero drop field(s), $R_MISS missing"
    NE=$(drop_events any "${MASTER[$i]}" | count_lines)
    [ "$NE" -eq 0 ] || fail "node-0$i (control): $NE drop event line(s)"
done
NOW=$(now_t)
STALE_M=""
for i in $(seq 1 $((NUM_NODES - 1))); do
    lt=$(ledger_rows "${MASTER[$i]}" | tail -1 | awk '{ print int($1) }')
    [ -n "$lt" ] && [ $((NOW - lt)) -le 5 ] || STALE_M="$STALE_M node-0$i(last=${lt:-none})"
done
[ -z "$STALE_M" ] && pass "rows for all 5 masters continue to the end (dead K included)" \
    || fail "masters without a row in the last 5 s:$STALE_M"
for n in 1 2; do
    wait_file_restorable 0 "${FILE[$n]}" 60 \
        && pass "f$n restorable on O at the end (O's belief after repair; the ledger decided nothing)" \
        || fail "f$n not restorable on O 60 s into step 8 (4r-i5: did a decision start reading the ledger?)"
done
# Whole-run re-checks, booked on the steps that own them.
EV3=$(drop_events any any | awk -v b="$B3S" '$5 == b' | count_lines)
[ "$EV3" -eq 0 ] && verdict 5 PASS "whole run: still zero drop events for B3" \
    || verdict 5 FAIL "whole run: $EV3 drop event(s) for B3"
ANN_A=$(drop_events Announced "$AM" | count_lines)
[ "$ANN_A" -eq 1 ] && verdict 3 PASS "whole run: still exactly 1 Announced event for A" \
    || verdict 3 FAIL "whole run: $ANN_A Announced event(s) for A"
read -r NF NS NO FA FP <<< "$(check_silent)"
[ "$NS" -eq "$NF" ] && [ "$NO" -eq 0 ] && verdict 4 PASS "whole run: Silent events for F ($NS) == Fail resolutions for (B2, F) ($NF)" \
    || verdict 4 FAIL "whole run: Silent events for F $NS (+$NO elsewhere) != Fail resolutions $NF"

finish
