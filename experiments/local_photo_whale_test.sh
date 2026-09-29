#!/bin/bash
# Viaticum: 4R "photo whale" smoke — a whale fills a friend's laptop; 4R must trim the whale
# first and let a serving friend in. SHADOW mode (В-0): the laptop still acts by the OLD rules;
# 4R's would-be decisions are logged (target viaticum::four_r) and replayed independently.
# Local processes on one machine (no Docker).
#
# Scenario:     8 independent nodes at time_scale 10000 star-connected to node-00, the laptop L
#               (small quota). node-01 = W, the whale (quota ~10 KiB: stores nothing for anyone);
#               node-02 = F, a friend who stores L's data and passes L's PoS; node-03..07 =
#               P1..P5 with room for everyone's repairs. L, F, P* back up a little; W backs up a
#               lot and fills L into the soft zone; F and then W offer L one more block; L is
#               restarted with a smaller quota (contention). L's 4R shadow is checked against
#               what L actually did and against an independent replay
#               (experiments/four_r_replay.py).
# Intent:       4r-i44, 4r-i45, 4r-i46, 4r-i50 (journal note only), 4r-i52, 4r-i66, 4r-i67 (В-0); later slices
#               add 4r-i12..i16, i18, i19, i21, i37, i41 to this file. F-Q (step 12): holder-i1,
#               holder-i4 (holder-i1-a — Q > 0 below the reserve — is proven by core units only).
# Proves:       on L: the shadow ranks W (no service to L) first and would cap-trim all of W's
#               parked bytes at the first contention while F (serving L) keeps its share; the
#               shadow would admit F's offer by preemption with W as the victim and would refuse
#               W's (accept-guard: W's V_ret is 0); L's actual answers and drops follow the old
#               rules. Cross-node: F gets QuotaFull from L for the block the shadow would admit;
#               W gets DropNotices from L only for blocks in the old path's plan; W's log shows
#               L's rejected offers (W is "asked");
#               F's log shows PoS answers for L's blocks (F's service is real). Every shadow
#               record replays exactly. Restore of F's, L's and two of W's files from the network
#               by sha256 (the shadow broke nothing). Step 12 (F-Q, the OLD path itself): L restarted
#               with a reserve above its disk is Critical — one pressure tick gives back ALL it holds
#               (hard floor 0), the owners get immediate DropNotices, new offers get QuotaFull, and
#               `status` says "disk below reserve". Red on the pre-F-Q code: the effective quota 0 was
#               read as "unlimited" → Normal, no eviction, no notices, status "quota: unlimited".
# Adversarial:  the whale offers the full laptop (refused in the shadow); contention entered
#               through a restart with a shrunken quota; an independent
#               replay of every shadow record (a seat-inverted kappa or a view that includes
#               notified holdings goes red).
# Cannot close: enforce behaviour (trims, preemption victims, 7-day windows, LowPriority, the
#               "no room" status) — В-1b..В-4 extend this file; the margin door for a
#               ZERO-service owner (with V_free = 0 its V_ret is 0 and the accept-guard refuses
#               first — unit K-5 only); the latch surviving a restart DURING contention (unit
#               D-2; step 6 restarts before the latch); absolute GB scale (MiB-scale dials, only
#               ratios transfer, audit R-22); real time; the shadow's offer latency at T1 scale
#               (~100k holdings); the sim twin (level 2, В-3½); the R2 number
#               itself (8 nodes started together: "never asked" ~ 0 by construction — polygon /
#               R4); disk full and "mount not found" (disk_free = 0: an invalid tick — the
#               phase is frozen already in the shadow, 4r-i66, and the tick is excluded from
#               the measures, 4r-i52; S1 has no zero disk, so no run proves it — units D-2b
#               and an_invalid_tick_does_not_move_the_latch_either_way hold it); clusters.
# Steps:        see private/beta-planning/tasks/v0_shadow.md В0-2 (1-4, 5a, 5b, 6, 7, R, 11).
#               1. start 8 nodes, star-connect -> L has 7 authenticated peers; >= 1
#                    `four_r: pressure tick` on L within 90 s with phase=false (4r-i44)
#               2. L 4 x 4 MiB, F 2 x 1 MiB, P* 1 MiB each back up -> restorable; symbols of L's
#                    blocks on F's and on every P's disk; premise of 5a (named): symbols of F's
#                    blocks on L's disk, else FAIL(setup) with the placement table
#               3. wait for F's service to L: `four_r: owner` of F on L with kappa >= 0.072
#                    (= 3 theta_p V_min / lambda) by the deadline t(first confirmed F row) +
#                    0.072 / V_conf(F) * 86400 / 10000 * 1.5 + 60 s; no confirmed F row within
#                    180 s -> FAIL(setup); F's log `responding with chain hash` for L's blocks
#                    (4r-i45)
#               4. W backs up 4 MiB files (batches of 8, <= 96) until L's holdings reach 0.85 Q_L
#                    -> x = bytes(W on L's disk) / Q_L >= 0.6 and the last
#                    L tick: phi_actual in [0.05, 0.15) (the OLD soft zone), accept_ok=false;
#                    `four_r: owner` of W: kappa = 0, zk_class=Asked; W's log >= 1 `SymbolOffer
#                    rejected (quota full)` with owner=L; W's upload time and the number of
#                    skipped offer shadows on L during it into the journal note (4r-i46, 4r-i50)
#              5a. F writes 1 MiB -> it offers L: L's `four_r: offer` owner=F with old=reject
#                    new=preempt victim=W, phi_actual < 0.15, kappa_offerer > kappa_victim +
#                    margin; F's own log: L rejected the same block with QuotaFull. No offer line
#                    of F on L within 60 s -> FAIL(setup) "F did not offer L" (premise of step
#                    2); a skipped shadow -> a new file, up to 3 times. Guard premise: parked_F +
#                    V_offer <= kappa_F / c_recip, else FAIL(setup) (dials, not code) (4r-i44)
#              5b. [adversarial] W writes 4 MiB -> offers L: L's `four_r: offer` owner=W with
#                    old=reject new=reject reason=Guard (V_ret(W) = 0 with data parked: the
#                    accept-guard refuses before the margin); W's own log: L rejected (4r-i44)
#               6. [adversarial] SIGTERM L, soft_quota_gb' = floor(H_L / 2^30 / 0.97) at
#                    0.0001, restart with the same args -> 7 authenticated peers again
#                    (auto-redial); within 90 s a tick with phase=true, old_pressure=Hard (4r-i44)
#               7. the first contention tick: premise W-4 (every owner but W has kappa > 1e-6);
#                    first_owner_new = W; cap_bytes(W) = parked_bytes(W); F: cap_bytes = 0,
#                    rank_new(F) > rank_new(W); zk_asked_bytes >= parked(W); OLD path: every
#                    `received SymbolDropNotice` on W from L is for a block of old_plan.immediate
#                    U old_plan.notices of L's Hard ticks (>= 1 such notice); L's `immediate-drop
#                    DropNotice published` lines with owner=W <= sum old_immediate(owner=W);
#                    R1/R2/top10_overlap/kendall_tau printed as NOTE (data, not a verdict;
#                    only ticks with measure_valid=true, 4r-i66) (4r-i44, 4r-i46)
#               R. replay: four_r_replay.py --dials <L's config.toml> on L's log (records of
#                    format v2 only; another version is a mismatch) -> mismatches=0 (incl.
#                    H/H_notified/H_mfd re-summed from holdings, presence re-joined from raw
#                    placements x device->master, the latch frozen on invalid ticks and
#                    continuous within a run of the holder task, an offer's H_notified =
#                    sum of its owners' notified bytes and H >= sum(parked + notified) + H_mfd,
#                    every record's params = the dials), pressure >= 3, phase_true >= 1,
#                    notified_records >= 1 (else FAIL(setup): the З-7 mutation would be
#                    invisible), offer >= 2, params_checked = records (the dials, not the
#                    defaults), latch_pairs >= 1 and latch_pairs_true >= 1 (continuity checked
#                    at least once across a persisted ON latch), measure_invalid printed
#                    (expected 0); zero records = FAIL (4r-i45, 4r-i52, 4r-i66, 4r-i67)
#              11. F, W, L delete sources with the daemon alive -> restore from the network: all
#                    of F's and L's files and 2 of W's match by sha256; holders logged `sending
#                    RestoreResponse` (the shadow broke nothing)
#              12. [F-Q] SIGTERM L, restart with disk_reserve_gb = BIG_RESERVE_GB (> L's filesystem
#                    size: free < reserve without filling a disk) -> within 180 s L logs `hard disk
#                    pressure` with critical=true (holder-i1); that first Critical tick frees all
#                    it holds (freed_bytes = used_bytes) and holding_bytes reach 0 (hard floor 0;
#                    Q = 0 case only; holder-i1-a is unit-proven); >= 1 `immediate-drop DropNotice published`
#                    on L and >= 1 `received SymbolDropNotice` from L in an owner's own log; L's
#                    `status` has "disk below reserve" (holder-i4); W and F write a new file ->
#                    `rejected offer for block … QuotaFull` from L in the offerer's own log (no
#                    offer to L within 120 s -> ROUGH: the offer rule is proven by units then).
#                    Red on the pre-F-Q code: no Critical line, holdings stay, no notices, status
#                    "quota: unlimited" (the QuotaFull check alone was green there too).
#
# Implementation notes (how the passport is executed, not what it claims):
#   - Numbers are derived from the dials by the passport's formulas and printed; a violated
#     premise is FAIL(setup) with the numbers, never a skip.
#   - Data sizes deviate from the spec's passport table (reported to the conductor): F 2 x 1 MiB
#     and P* 1 MiB each instead of 4 MiB, and W writes until L is full instead of a fixed
#     40 x 4 MiB. Formula: x = (0.85 Q_L - B_fr) / Q_L >= 0.6 needs B_fr <= 0.25 Q_L = 16 MiB of
#     friends' data on L; with a full copy per early block per holder (68 symbols x 64 KiB for
#     4 MiB) plus 2 SystemState blocks (2 x 256 KiB) per peer, the table's F 2 x 4 MiB + P* 5 x
#     4 MiB put B_fr ~ 34 MiB on L (x = 0.335 in run 20260927-060800); with 1 MiB friends' files
#     B_fr ~ 3 + 7 x 1.1 ~ 11 MiB -> x ~ 0.68.
#   - The per-tick numbers come from L's INFO `four_r: pressure tick` and DEBUG `four_r: owner`
#     lines (masters as full hex, compared with node_identity); the old plans come from the
#     DEBUG `four_r: record` JSON (old_plan = evaluate_pressure's result before the old path
#     acts).
#   - Step 11 races the owner-delete cooldown (242 s at 10000): each file is restored right
#     after its own deletion and the elapsed time is checked (assert_delete_window floor 200).
#   - Verdicts per step: PASS / ROUGH / FAIL. Exit code: 0 PASS, 3 ROUGH, 1 FAIL.
#
# Usage:
#   private/testing/run_e2e.sh photo_whale      # on the build server (release build)
#   bash experiments/local_photo_whale_test.sh  # with ./target/release/viaticum present

set -uo pipefail
export LC_ALL=C

NUM_NODES=8
TIME_SCALE=10000
L=0; W=1; F=2; PS=(3 4 5 6 7)
L_RUST_LOG="info,viaticum::four_r=debug,viaticum::ledger=debug"
W_RUST_LOG="info,viaticum::daemon::processor::symbol=debug"
H_RUST_LOG="info,viaticum::daemon::processor::pos=debug"
# Pre-registered dials (passport table; change only by formula, before a run, with a commit).
L_SOFT_GB="0.0625"      # Q_L = 64 MiB
W_SOFT_GB="0.00001"     # ~10 KiB < one 64 KiB symbol: W refuses every offer
P_SOFT_GB="1.0"
Q_L_BYTES=67108864
KAPPA_F_MIN="0.072"     # 3 * theta_p * V_min / lambda = 3 * 0.2 * 0.002 * 60
MIB=1048576
# W's upload (step 4): batches of W_BATCH files until L reaches the old soft zone. Why not a
# fixed "40 x 4 MiB": the daemon puts a FULL copy (68 symbols) of each early block on every
# holder and only ~11 symbols (704 KiB) of later blocks on L (run 20260927-060800), so a fixed
# count either never fills L or depends on placement dynamics; see Implementation notes.
W_BATCH=8
W_MAX=96
# Step 12: a reserve far above any disk of the run (tmpfs /tmp is 32 GB on the server), so
# L's free disk is below it without filling a disk.
BIG_RESERVE_GB="100000.0"
TEST_DIR="/tmp/viaticum-photo-whale-$$"
BINARY="${BINARY:-viaticum}"
T_BASE=$(date -u +%s)

PIDS=()
declare -A VERDICT
STEP_ORDER=(1 2 3 4 5a 5b 6 7 R 11 12)
CUR_STEP=0

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

FINISHED=0
cleanup() {
    local rc=$?
    # A step that dies without its verdict (errexit, a signal) still says so.
    if [ "$FINISHED" -eq 0 ]; then
        echo "  FAIL [step $CUR_STEP]: the script exited (rc=$rc) before the step's verdict"
    fi
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

rust_log_of() {
    case "$1" in
        "$L") echo "$L_RUST_LOG" ;;
        "$W") echo "$W_RUST_LOG" ;;
        *) echo "$H_RUST_LOG" ;;
    esac
}

start_node() { # IDX — appends to the node's log
    local idx="$1"
    RUST_LOG="$(rust_log_of "$idx")" "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$idx")/files" \
        >> "$(node_log "$idx")" 2>&1 &
    PIDS[$idx]=$!
}

write_config() { # IDX SOFT_GB [RESERVE_GB]
    local idx="$1" soft="$2" reserve="${3:-0.0}"
    {
        echo "[web_api]"
        echo "enabled = true"
        echo "bind = \"127.0.0.1:0\""
        echo "[storage]"
        echo "disk_reserve_gb = $reserve"
        echo "soft_quota_gb = $soft"
        echo "[backup]"
        echo "source_block_size_mb = 4"
        if [ "$idx" -eq "$L" ]; then
            echo "[four_r]"
            echo "v_min_gb = 0.002"
            echo "c_recip_days = 3.0"
            echo "theta_p = 0.2"
            echo "v_free_gb = 0.0"
            echo "w_d = 0.5"
            echo "tau_ref_days = 365.0"
            echo "s_hard = 0.05"
            echo "s_target = 0.15"
            echo "s_soft = 0.20"
        fi
    } > "$(node_dir "$idx")/config.toml"
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ ! -x "$BINARY" ] && echo "ERROR: binary not found" && exit 1
fi
REPLAY="$(dirname "${BASH_SOURCE[0]}")/four_r_replay.py"

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

now_t() { echo "$(( $(date -u +%s) - T_BASE ))"; }
log_lines() { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
count_lines() { awk 'NF' | wc -l | tr -d ' '; }

L_LOG=""
# ticks [AFTER_LINE] -> "t line phase phi_actual accept_ok h_bytes old_pressure first_new zk_asked
#                        h_notified measure_valid" of L's `four_r: pressure tick` lines
ticks() {
    events "$L_LOG" "four_r: pressure tick" phase phi_actual accept_ok h_bytes old_pressure \
        first_owner_new zk_asked_bytes h_notified_bytes measure_valid \
        | awk -v lo="${1:-0}" '($2 + 0) > lo' || true
}
# owner_rows MASTER_FULL [AFTER_LINE] -> "t line kappa cap_bytes parked_bytes zk_class rank_new"
owner_rows() {
    events "$L_LOG" "four_r: owner" master kappa cap_bytes parked_bytes zk_class rank_new \
        | awk -v m="$1" -v lo="${2:-0}" '$3 == m && ($2 + 0) > lo { print $1, $2, $4, $5, $6, $7, $8 }' \
        || true
}
# owner rows of ONE tick: the `four_r: owner` lines between tick line A and the next tick line
owner_rows_of_tick() { # TICK_LINE -> "master kappa cap parked zk rank"
    local a="$1" b
    b=$(ticks "$a" | head -1 | awk '{print $2}')
    events "$L_LOG" "four_r: owner" master kappa cap_bytes parked_bytes zk_class rank_new \
        | awk -v a="$a" -v b="${b:-999999999}" '($2 + 0) > a && ($2 + 0) < b { print $3, $4, $5, $6, $7, $8 }' \
        || true
}
# records_py 'PYTHON' — run PYTHON with `recs` = the JSON records of L's log (list, log order)
records_py() {
    python3 - "$L_LOG" "$1" <<'PY'
import json, re, sys, textwrap
ansi = re.compile(r"\x1b\[[0-9;]*m")
recs = []
for line in open(sys.argv[1], errors="replace"):
    line = ansi.sub("", line)
    if "four_r: record" in line and "rec=" in line:
        recs.append(json.loads(line.split("rec=", 1)[1].strip()))
exec(textwrap.dedent(sys.argv[2]))
PY
}

finish() {
    FINISHED=1
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
    case "$overall" in
        PASS) exit 0 ;;
        ROUGH) exit 3 ;;
        *) exit 1 ;;
    esac
}

echo "============================================================"
echo "  Viaticum: 4R photo whale (shadow) — nodes ${NUM_NODES}, time_scale ${TIME_SCALE}"
echo "============================================================"

# ── STEP 1: setup, star connect, the first shadow tick ───────────────────────
CUR_STEP=1
echo ""
echo "=== Step 1: start 8 nodes, star-connect to L, first 4R shadow tick on L ==="
command -v python3 > /dev/null || { fail "FAIL(setup): python3 missing (step R needs it)"; finish; }
mkdir -p "$TEST_DIR"
for i in $(seq 0 $((NUM_NODES - 1))); do
    mkdir -p "$(node_dir "$i")/files"
    run_cli "$i" init > /dev/null 2>&1
    case "$i" in
        "$L") write_config "$i" "$L_SOFT_GB" ;;
        "$W") write_config "$i" "$W_SOFT_GB" ;;
        *) write_config "$i" "$P_SOFT_GB" ;;
    esac
done
for i in $(seq 0 $((NUM_NODES - 1))); do start_node "$i"; done
L_LOG=$(node_log "$L")
for i in $(seq 0 $((NUM_NODES - 1))); do
    wait_daemon "$i" || { fail "node-0$i did not start"; finish; }
done
declare -A ADDR MASTER MFULL DEV
for i in $(seq 0 $((NUM_NODES - 1))); do
    ADDR[$i]=$(get_addr "$i")
    MFULL[$i]=$(api_get "$i" /api/status | jq -r '.node_identity // empty')
    MASTER[$i]=${MFULL[$i]:0:16}
    DEV[$i]=$(api_get "$i" /api/status | jq -r '.device_id // empty')
    if [ -z "${ADDR[$i]}" ] || [ -z "${MFULL[$i]}" ]; then
        fail "node-0$i: missing addr/identity (${ADDR[$i]:-?} ${MFULL[$i]:-?})"
        finish
    fi
    info "node-0$i master=${MASTER[$i]} device=${DEV[$i]:0:16}"
done
LM=${MFULL[$L]}; WM=${MFULL[$W]}; FM=${MFULL[$F]}
for i in $(seq 1 $((NUM_NODES - 1))); do run_cli_q "$i" connect "${ADDR[$L]}" > /dev/null; done
if wait_auth_peers "$L" $((NUM_NODES - 1)) 30; then
    pass "star connect: L has $(status_num "$L" peer_count_authenticated) authenticated peers"
else
    fail "star connect: $(status_num "$L" peer_count_authenticated)/$((NUM_NODES - 1)) authenticated after 30 s"
    finish
fi
FIRST_TICK=""
for _ in $(seq 1 90); do
    FIRST_TICK=$(ticks | head -1)
    [ -n "$FIRST_TICK" ] && break
    sleep 1
done
if [ -n "$FIRST_TICK" ] && [ "$(echo "$FIRST_TICK" | awk '{print $3}')" = "false" ]; then
    pass "first 4R shadow tick on L: $FIRST_TICK (phase=false)"
else
    fail "no 'four_r: pressure tick' with phase=false on L within 90 s (got: '${FIRST_TICK}')"
fi

# ── STEP 2: L, F, P* back up; placement premises ───────────────────────────
CUR_STEP=2
echo ""
echo "=== Step 2: L, F, P1..P5 back up; L's blocks on F and P*, F's blocks on L ==="
declare -A FILES
mk_files() { # IDX COUNT PREFIX SIZE_MIB [FIRST] -> appends the paths to FILES[IDX]
    local idx="$1" n="$2" pre="$3" mib="$4" first="${5:-1}" j p
    for j in $(seq "$first" $((first + n - 1))); do
        p="$(node_dir "$idx")/files/${pre}_$j.bin"
        head -c $((mib * MIB)) /dev/urandom > "$p"
        FILES[$idx]="${FILES[$idx]:-} $p"
    done
}
mk_files "$L" 4 laptop 4
mk_files "$F" 2 friend 1
for p in "${PS[@]}"; do mk_files "$p" 1 "p$p" 1; done
declare -A BLOCKS   # IDX -> block hexes
NOT_READY=""
for idx in "$L" "$F" "${PS[@]}"; do
    BLOCKS[$idx]=""
    for f in ${FILES[$idx]}; do
        if ! wait_file_restorable "$idx" "$f" 240; then
            NOT_READY="$NOT_READY node-0$idx:$(basename "$f")"
            continue
        fi
        BLOCKS[$idx]="${BLOCKS[$idx]} $(file_block_hex "$idx" "$f")"
    done
done
[ -z "$NOT_READY" ] && pass "all files of L, F, P1..P5 restorable per their owners" \
    || { fail "FAIL(setup): not restorable within 240 s:$NOT_READY"; finish; }
syms_of() { # HOLDER_IDX OWNER_IDX -> symbol files of OWNER's blocks on HOLDER's disk
    local h="$1" o="$2" b t=0
    for b in ${BLOCKS[$o]}; do t=$((t + $(block_symbols_on "$h" "$b"))); done
    echo "$t"
}
placement_table() {
    local h
    for h in "$L" "$F" "${PS[@]}"; do
        echo "    node-0$h holds: L=$(syms_of "$h" "$L") F=$(syms_of "$h" "$F")"
    done
}
PLACED=""
for _ in $(seq 1 30); do
    PLACED=1
    [ "$(syms_of "$F" "$L")" -gt 0 ] || PLACED=""
    for p in "${PS[@]}"; do [ "$(syms_of "$p" "$L")" -gt 0 ] || PLACED=""; done
    [ "$(syms_of "$L" "$F")" -gt 0 ] || PLACED=""
    [ -n "$PLACED" ] && break
    sleep 1
done
placement_table
if [ -n "$PLACED" ]; then
    pass "symbols of L's blocks on F and on every P*; symbols of F's blocks on L (premise of 5a)"
else
    fail "FAIL(setup): placement premise broken (L's blocks on F and every P*, F's blocks on L) — see the table"
    finish
fi

# ── STEP 3: F's service to L becomes visible in kappa ───────────────────────
CUR_STEP=3
echo ""
echo "=== Step 3: F serves L — kappa_F >= $KAPPA_F_MIN on L by the passport deadline ==="
T3=$(now_t)
FIRST_CONF=""
while [ "$(now_t)" -lt $((T3 + 180)) ]; do
    FIRST_CONF=$(events "$L_LOG" "pair-ledger row" master confirmed_gb \
        | awk -v m="${MASTER[$F]}" '$3 == m && ($4 + 0) > 0 { print; exit }')
    [ -n "$FIRST_CONF" ] && break
    sleep 1
done
if [ -z "$FIRST_CONF" ]; then
    fail "FAIL(setup): no confirmed pair-ledger row for F on L within 180 s"
    finish
fi
read -r T_CONF _ _ V_CONF <<< "$FIRST_CONF"
DEADLINE=$(awk -v t="$T_CONF" -v k="$KAPPA_F_MIN" -v v="$V_CONF" -v s="$TIME_SCALE" \
    'BEGIN { printf "%d", t + k / v * 86400 / s * 1.5 + 60 }')
info "first confirmed F row at t=${T_CONF}s, V_conf(F)=${V_CONF} GB -> deadline t=${DEADLINE}s"
KF_ROW=""
while [ "$(now_t)" -le "$DEADLINE" ]; do
    KF_ROW=$(owner_rows "$FM" | awk -v k="$KAPPA_F_MIN" '($3 + 0) >= k { print; exit }')
    [ -n "$KF_ROW" ] && break
    sleep 2
done
if [ -n "$KF_ROW" ]; then
    pass "kappa_F on L reached $(echo "$KF_ROW" | awk '{print $3}') >= $KAPPA_F_MIN at t=$(echo "$KF_ROW" | awk '{print $1}')s"
else
    fail "kappa_F on L stayed below $KAPPA_F_MIN until the deadline (last: $(owner_rows "$FM" | tail -1))"
fi
F_POS=0
for b in ${BLOCKS[$L]}; do
    n=$(grep -a "responding with chain hash" "$(node_log "$F")" | grep -ac "${b:0:16}" || true)
    F_POS=$((F_POS + ${n:-0}))
done
[ "$F_POS" -ge 1 ] && pass "F's own log: $F_POS PoS answers (responding with chain hash) for L's blocks" \
    || fail "F's log shows no 'responding with chain hash' for any of L's blocks"

# ── STEP 4: the whale fills L into the old soft zone ────────────────────────
CUR_STEP=4
echo ""
echo "=== Step 4: W backs up 4 MiB files until L is in the OLD soft zone; W asked and zero-kappa ==="
T4_START=$(date -u +%s)
L4_START=$(log_lines "$L_LOG")
l_disk_bytes() { # every holdings symbol file on L's disk
    find "$(node_dir "$L")/holdings" -type f -name '*.bin' -printf '%s\n' 2>/dev/null \
        | awk '{ t += $1 } END { print t + 0 }'
}
# W writes 4 MiB files in batches of W_BATCH until L's holdings reach the OLD soft zone
# (>= 0.85 Q_L on L's disk) or W_MAX files (passport: W stores as much as L accepts).
BLOCKS[$W]=""
N_W_FILES=0
FULL=""
# Step budget (mutation run 2026-09-27: a slow server made the unbounded loop + per-file lookups
# outlast the 1800 s scenario timeout): 12 batches x 180 s could reach 36 min on their own.
STEP4_BUDGET=900
while [ "$N_W_FILES" -lt "$W_MAX" ] && [ -z "$FULL" ] \
    && [ $(( $(date -u +%s) - T4_START )) -lt "$STEP4_BUDGET" ]; do
    mk_files "$W" "$W_BATCH" whale 4 $((N_W_FILES + 1))
    BATCH=$(echo ${FILES[$W]} | tr ' ' '\n' | tail -n "$W_BATCH")
    T_B=$(date -u +%s)
    # Until L is full, or every file of the batch is restorable per W (180 s per batch).
    while [ $(( $(date -u +%s) - T_B )) -lt 180 ]; do
        [ "$(l_disk_bytes)" -ge $((Q_L_BYTES * 85 / 100)) ] && { FULL=1; break; }
        ALL=1
        for f in $BATCH; do
            [ "$(file_field "$W" "$f" '.effective_status.kind // "none"')" = restorable ] || { ALL=""; break; }
        done
        [ -n "$ALL" ] && break
        sleep 2
    done
    N_W_FILES=$((N_W_FILES + W_BATCH))
done
[ -z "$FULL" ] && [ $(( $(date -u +%s) - T4_START )) -ge "$STEP4_BUDGET" ] \
    && info "step 4 budget ${STEP4_BUDGET}s spent before L reached 0.85 Q_L (the x check below decides)"
sleep 5   # the last accepted transfers land
NOT_RESTORABLE=0
T4_LOOKUP=$(date -u +%s)   # one 60 s deadline for all block lookups, not 30 s per file
for f in ${FILES[$W]}; do
    b=""
    while :; do
        b=$(file_block_hex "$W" "$f")
        [ -n "$b" ] && break
        [ $(( $(date -u +%s) - T4_LOOKUP )) -ge 60 ] && break
        sleep 1
    done
    [ -n "$b" ] && BLOCKS[$W]="${BLOCKS[$W]} $b"
    [ "$(file_field "$W" "$f" '.effective_status.kind // "none"')" = restorable ] \
        || NOT_RESTORABLE=$((NOT_RESTORABLE + 1))
done
note "W files not (yet) restorable per W while L refuses its offers: $NOT_RESTORABLE of $N_W_FILES (data, not a verdict)"
info "W wrote $N_W_FILES x 4 MiB; L's holdings on disk: $(l_disk_bytes) B (0.85 Q_L = $((Q_L_BYTES * 85 / 100)) B)"
T4_UP=$(( $(date -u +%s) - T4_START ))
N_SKIP4=$(log_since "$L" "$L4_START" | grep -a "four_r: offer shadow skipped" | grep -ac "${WM}" || true)
N_OFF4=$(log_since "$L" "$L4_START" | grep -a "four_r: offer" | grep -av "offer shadow skipped" | grep -ac "owner=${WM}" || true)
note "W uploaded $((N_W_FILES * 4)) MiB in ${T4_UP} s; L logged $N_OFF4 offer shadow(s) of W and skipped $N_SKIP4 (slot busy) (4r-i50 journal note; no threshold)"
w_bytes_on_l() {
    local b t=0 s
    for b in ${BLOCKS[$W]}; do
        s=$(find "$(node_dir "$L")/holdings/$b" -maxdepth 1 -type f -name '*.bin' -printf '%s\n' 2>/dev/null \
            | awk '{ t += $1 } END { print t + 0 }')
        t=$((t + s))
    done
    echo "$t"
}
# Let the late transfers land and two ticks pass on the filled disk.
L4=$(log_lines "$L_LOG")
TICK4=""
for _ in $(seq 1 150); do
    TICK4=$(ticks "$L4" | sed -n '2p')
    [ -n "$TICK4" ] && break
    sleep 1
done
[ -n "$TICK4" ] || { fail "FAIL(setup): no two L ticks within 150 s after W's backup"; finish; }
X_BYTES=$(w_bytes_on_l)
X=$(awk -v a="$X_BYTES" -v q="$Q_L_BYTES" 'BEGIN { printf "%.4f", a / q }')
read -r _ _ PH4 PHI4 ACC4 H4 _ _ _ _ _ <<< "$TICK4"
info "x = bytes(W on L) / Q_L = $X_BYTES / $Q_L_BYTES = $X; tick: phase=$PH4 phi_actual=$PHI4 accept_ok=$ACC4 h_bytes=$H4"
if awk -v x="$X" -v p="$PHI4" 'BEGIN { exit !(x >= 0.6 && p >= 0.05 && p < 0.15) }' \
    && [ "$ACC4" = "false" ]; then
    pass "L in the old soft zone: x=$X >= 0.6, phi_actual=$PHI4 in [0.05, 0.15), accept_ok=false"
else
    fail "FAIL(setup): x=$X (want >= 0.6), phi_actual=$PHI4 (want [0.05, 0.15)), accept_ok=$ACC4 (want false)"
    finish
fi
WROW=$(owner_rows "$WM" "$L4" | tail -1)
read -r _ _ WK _ WPARK WZK _ <<< "$WROW"
if awk -v k="${WK:-x}" 'BEGIN { exit !(k + 0 == 0 && k != "x") }' && [ "$WZK" = "Asked" ]; then
    pass "four_r: owner W on L: kappa=$WK zk_class=$WZK parked=$WPARK (4r-i46)"
else
    fail "four_r: owner W on L: '$WROW' (want kappa=0 zk_class=Asked)"
fi
W_REJ=$(grep -a "SymbolOffer rejected (quota full)" "$(node_log "$W")" | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -ac "owner=${MASTER[$L]}" || true)
[ "${W_REJ:-0}" -ge 1 ] && pass "W's own log: $W_REJ 'SymbolOffer rejected (quota full)' with owner=L (W was asked)" \
    || fail "W's log has no 'SymbolOffer rejected (quota full)' with owner=L"

# offer_lines OWNER_FULL AFTER_LINE -> "t line block old new reason victim kappa_offerer
#   kappa_victim margin phi_actual parked_offerer_bytes" of L's `four_r: offer` lines
offer_lines() {
    events "$L_LOG" "four_r: offer" owner block_id old new reason victim kappa_offerer \
        kappa_victim margin phi_actual parked_offerer_bytes \
        | awk -v o="$1" -v lo="$2" '$3 == o && ($5 == "accept" || $5 == "reject") && ($2 + 0) > lo { $3 = ""; print }' \
        | awk '{ $1 = $1; print }' || true
}
skipped_lines() { # OWNER_FULL AFTER_LINE -> count of skipped offer shadows of OWNER
    log_since "$L" "$2" | grep -a "four_r: offer shadow skipped" | grep -ac "owner=$1" || true
}
# first_offer OWNER_IDX PREFIX SIZE -> sets OFFER (one line of offer_lines) trying up to 3 new
#   files while the shadow is skipped; FAIL(setup) when OWNER never offers L within 60 s.
first_offer() {
    local idx="$1" pre="$2" size="$3" om="${MFULL[$1]}" try mark f
    OFFER=""
    for try in 1 2 3; do
        mark=$(log_lines "$L_LOG")
        f="$(node_dir "$idx")/files/${pre}_$try.bin"
        head -c "$size" /dev/urandom > "$f"
        for _ in $(seq 1 60); do
            OFFER=$(offer_lines "$om" "$mark" | head -1)
            [ -n "$OFFER" ] && return 0
            [ "$(skipped_lines "$om" "$mark")" -ge 1 ] && break
            sleep 1
        done
        if [ "$(skipped_lines "$om" "$mark")" -ge 1 ]; then
            info "the shadow of node-0$idx's offer was skipped (slot busy) — new file, try $((try + 1))"
            continue
        fi
        return 1
    done
    return 1
}

# ── STEP 5a: a serving friend's offer — 4R would preempt the whale ───────────
CUR_STEP=5a
echo ""
echo "=== Step 5a: F writes 1 MiB and offers L — old: reject; 4R: preempt W ==="
if ! first_offer "$F" friend_extra $((1 * MIB)); then
    fail "FAIL(setup): F did not offer L within 60 s (premise of step 2: L among F's holders) or every shadow was skipped"
else
    echo "    $OFFER"
    read -r _ _ O_BLK O_OLD O_NEW O_REASON O_VICTIM O_KOFF O_KVIC O_MARGIN O_PHI O_PARKED <<< "$OFFER"
    V_OFF=$(awk -v b="$MIB" 'BEGIN { printf "%.10f", b / 1073741824 }')
    GUARD_OK=$(awk -v pk="$O_PARKED" -v v="$V_OFF" -v k="$O_KOFF" \
        'BEGIN { print ((pk / 1073741824 + v <= k / 3.0) ? 1 : 0) }')
    if ! awk -v p="$O_PHI" 'BEGIN { exit !(p < 0.15) }' || [ "$GUARD_OK" != 1 ]; then
        fail "FAIL(setup): dials, not code — phi_actual=$O_PHI (want < 0.15), parked_F=$O_PARKED + V_offer vs kappa_F/c_recip=$O_KOFF/3 (guard ok=$GUARD_OK)"
    elif [ "$O_OLD" = reject ] && [ "$O_NEW" = preempt ] && [ "$O_VICTIM" = "$WM" ] \
        && awk -v a="$O_KOFF" -v b="$O_KVIC" -v m="$O_MARGIN" 'BEGIN { exit !(a > b + m) }'; then
        pass "L's shadow: F's offer old=reject new=preempt victim=W (kappa $O_KOFF > $O_KVIC + margin $O_MARGIN, phi_actual $O_PHI)"
    else
        fail "L's offer line for F: old=$O_OLD new=$O_NEW reason=$O_REASON victim=${O_VICTIM:0:16} kappa_offerer=$O_KOFF kappa_victim=$O_KVIC margin=$O_MARGIN"
    fi
    F_REJ=0
    for _ in $(seq 1 30); do
        F_REJ=$(grep -a "rejected offer for block ${O_BLK:0:16}" "$(node_log "$F")" | grep -a "QuotaFull" \
            | grep -ac "holder ${DEV[$L]:0:16}" || true)
        [ "${F_REJ:-0}" -ge 1 ] && break
        sleep 1
    done
    [ "${F_REJ:-0}" -ge 1 ] && pass "F's own log: L rejected block ${O_BLK:0:16} with QuotaFull — the reply followed the OLD rule" \
        || fail "F's log shows no QuotaFull rejection from L for block ${O_BLK:0:16}"
fi

# ── STEP 5b: the whale's offer — refused by 4R's accept-guard ─────────────────
CUR_STEP=5b
echo ""
echo "=== Step 5b: [adversarial] W writes 4 MiB and offers L — old: reject; 4R: reject (Guard) ==="
if ! first_offer "$W" whale_extra $((4 * MIB)); then
    fail "FAIL(setup): W did not offer L within 60 s or every shadow was skipped"
else
    echo "    $OFFER"
    read -r _ _ O_BLK O_OLD O_NEW O_REASON O_VICTIM _ _ _ _ _ <<< "$OFFER"
    [ "$O_OLD" = reject ] && [ "$O_NEW" = reject ] && [ "$O_REASON" = Guard ] \
        && pass "L's shadow: W's offer old=reject new=reject reason=Guard (V_ret(W) = 0)" \
        || fail "L's offer line for W: old=$O_OLD new=$O_NEW reason=$O_REASON (want reject/reject/Guard)"
    W_REJ5=0
    for _ in $(seq 1 30); do
        W_REJ5=$(grep -a "rejected offer for block ${O_BLK:0:16}" "$(node_log "$W")" \
            | grep -ac "holder ${DEV[$L]:0:16}" || true)
        [ "${W_REJ5:-0}" -ge 1 ] && break
        sleep 1
    done
    [ "${W_REJ5:-0}" -ge 1 ] && pass "W's own log: L rejected block ${O_BLK:0:16}" \
        || fail "W's log shows no rejection from L for block ${O_BLK:0:16}"
fi

# check_old_path_vs_plan WHEN: W's DropNotices from L only for blocks of L's Hard-tick old plans
#   (>= 1), and L's immediate-drop publications to W <= sum old_immediate(W), from the first
#   contention tick to now. Called at step 7 and again right before step 11 (booked on 7).
check_old_path_vs_plan() {
    local when="$1"
    OLD_W=$(records_py "
    blocks=set(); imm=0
    for r in recs:
        op=r.get('old_plan') or {}
        if op.get('pressure')!='Hard': continue
        for b,o in op['immediate']+op['notices']:
            if o=='$WM': blocks.add(b[:16])
        imm+=sum(1 for b,o in op['immediate'] if o=='$WM')
    print(imm, ' '.join(sorted(blocks)))")
    read -r W_IMM W_PLAN <<< "$OLD_W"
    W_GOT=$(events "$(node_log "$W")" "received SymbolDropNotice" block_id holder \
        | awk -v h="${MASTER[$L]}" '$4 == h { print $3 }' | sort -u)
    N_W_GOT=$(echo "$W_GOT" | count_lines)
    OUTSIDE=""
    for b in $W_GOT; do echo " $W_PLAN " | grep -q " $b " || OUTSIDE="$OUTSIDE $b"; done
    if [ "$N_W_GOT" -ge 1 ] && [ -z "$OUTSIDE" ]; then
        pass "($when) W's own log: DropNotices from L for $N_W_GOT block(s), all in L's old plans (4r-i44)"
    else
        fail "($when) W got DropNotices from L for $N_W_GOT block(s); outside the old plans:${OUTSIDE:- none} (plan: ${W_PLAN:-empty})"
    fi
    PUB_W=$(log_since "$L" "$CT_LINE" | grep -a "immediate-drop DropNotice published" | grep -ac "owner=${MASTER[$W]}" || true)
    [ "${PUB_W:-0}" -le "${W_IMM:-0}" ] \
        && pass "($when) L published $PUB_W immediate DropNotice(s) to W <= sum old_immediate(W) = $W_IMM" \
        || fail "($when) L published $PUB_W immediate DropNotices to W > sum old_immediate(W) = $W_IMM (a publisher outside the old path)"
}

# ── STEP 6: contention through a restart with a shrunken quota ──────────────
CUR_STEP=6
echo ""
echo "=== Step 6: SIGTERM L, shrink its quota to ~97% of what it holds, restart ==="
H_L=$(ticks | tail -1 | awk '{print $6}')
SOFT2=$(awk -v h="$H_L" 'BEGIN { g = h / 1073741824 / 0.97; printf "%.4f", int(g * 10000) / 10000 }')
info "H_L=$H_L bytes -> soft_quota_gb' = floor(H_L/2^30/0.97, 0.0001) = $SOFT2"
kill -TERM "${PIDS[$L]}" 2>/dev/null
wait_pid_exit "${PIDS[$L]}" 30 || { kill -9 "${PIDS[$L]}" 2>/dev/null; fail "FAIL(setup): L did not stop within 30 s"; finish; }
write_config "$L" "$SOFT2"
LSTART=$(log_lines "$L_LOG")
T_RESTART=$(date -u +%s)
start_node "$L"
wait_daemon "$L" || { fail "FAIL(setup): L did not come back"; finish; }
if wait_auth_peers "$L" $((NUM_NODES - 1)) 90; then
    pass "L rejoined by itself: $(status_num "$L" peer_count_authenticated) authenticated peers"
else
    fail "L has $(status_num "$L" peer_count_authenticated)/$((NUM_NODES - 1)) peers 90 s after restart"
fi
CT=""
while [ $(( $(date -u +%s) - T_RESTART )) -le 90 ]; do
    CT=$(ticks "$LSTART" | awk '$3 == "true" && $7 == "Hard"' | head -1)
    [ -n "$CT" ] && break
    sleep 1
done
if [ -n "$CT" ]; then
    pass "first tick after restart in contention: phase=true old_pressure=Hard ($CT)"
else
    fail "no tick with phase=true and old_pressure=Hard within 90 s of the restart (ticks: $(ticks "$LSTART" | head -2 | tr '\n' ';'))"
    finish
fi
CT_LINE=$(echo "$CT" | awk '{print $2}')

# ── STEP 7: the first contention — shadow vs old path ───────────────────────
CUR_STEP=7
echo ""
echo "=== Step 7: first contention — 4R would trim W whole; the old path did its own plan ==="
ROWS7=$(owner_rows_of_tick "$CT_LINE")
echo "$ROWS7" | sed 's/^/    owner /'
BAD_KAPPA=$(echo "$ROWS7" | awk -v w="$WM" 'NF && $1 != w && ($2 + 0) <= 1e-6 { print substr($1, 1, 16) }' | tr '\n' ' ')
[ -z "$BAD_KAPPA" ] || { fail "FAIL(setup): a friend has not confirmed yet — premise of step 7 (W-4): kappa <= 1e-6 for $BAD_KAPPA"; finish; }
read -r _ _ _ _ _ _ _ FIRST_NEW7 ZK_ASKED7 _ _ <<< "$CT"
WR=$(echo "$ROWS7" | awk -v w="$WM" '$1 == w')
FR=$(echo "$ROWS7" | awk -v f="$FM" '$1 == f')
read -r _ _ W_CAP W_PARK W_ZK W_RANK <<< "$WR"
read -r _ _ F_CAP _ _ F_RANK <<< "$FR"
[ "$FIRST_NEW7" = "$WM" ] && pass "first_owner_new = W" || fail "first_owner_new=${FIRST_NEW7:0:16}, want W=${MASTER[$W]}"
if [ -n "$W_PARK" ] && [ "$W_PARK" -gt 0 ] && [ "$W_CAP" = "$W_PARK" ]; then
    pass "cap_bytes(W) = parked_bytes(W) = $W_PARK (V_ret(W) = 0, hard_quota = 0)"
else
    fail "cap_bytes(W)=${W_CAP:-?} parked_bytes(W)=${W_PARK:-?} (want equal and > 0)"
fi
if [ "${F_CAP:-x}" = "0" ] && [ -n "$F_RANK" ] && [ "$F_RANK" -gt "${W_RANK:-99}" ]; then
    pass "F keeps its share: cap_bytes(F)=0, rank_new(F)=$F_RANK > rank_new(W)=$W_RANK"
else
    fail "F: cap_bytes=${F_CAP:-?} rank_new=${F_RANK:-?} (W rank ${W_RANK:-?})"
fi
[ "$W_ZK" = "Asked" ] && [ "${ZK_ASKED7:-0}" -ge "${W_PARK:-1}" ] \
    && pass "zk_asked_bytes=$ZK_ASKED7 >= parked(W)=$W_PARK, W zk_class=Asked (4r-i46)" \
    || fail "zk_asked_bytes=${ZK_ASKED7:-?} parked(W)=${W_PARK:-?} zk_class(W)=${W_ZK:-?}"
# The old path: W's notices from L only for blocks of L's Hard-tick old plans.
for _ in $(seq 1 60); do   # mailbox delivery of the first contention's notices
    events "$(node_log "$W")" "received SymbolDropNotice" block_id holder \
        | awk -v h="${MASTER[$L]}" '$4 == h' | grep -q . && break
    sleep 1
done
sleep 5
check_old_path_vs_plan "first contention"
# Measures of the first contention (data for В-3½, not a verdict).
records_py "
r=[x for x in recs if x['kind']=='pressure' and x['out']['phase'] and x['out']['measure_valid']][0]
o=r['out']; q=o['q_bytes']
size={(h['block'], ow['master']): h['bytes'] for ow in r['owners'] for h in ow['holdings']}
cap_all=sum(size[tuple(x)] for x in o['cap'])
cap_friends=sum(size[tuple(x)] for x in o['cap'] if x[1]!='$WM')
r1=cap_friends/q if q > 0 else -1
print('  NOTE [step 7]: R1 = cap of honest friends / Q = %.4f (cap all %d B, Q %d B); R2 zk=%s; top10_overlap=%s kendall_tau=%s first_owner_old=%s' % (
    r1, cap_all, q, o['zk'], o['top10_overlap'], o['kendall_tau'], (o['first_owner_old'] or '-')[:16]))
if r1 > 0.5: print('  NOTE [step 7]: R1 > 50% of the quota at honest friends: sweep V_free before enforce (audit 5.4)')"

# ── STEP R: independent replay ─────────────────────────────────────────────
CUR_STEP=R
echo ""
echo "=== Step R: independent replay of every shadow record on L ==="
LR=$(log_lines "$L_LOG")
for _ in $(seq 1 130); do   # a tick after the first contention: notified holdings in the input
    [ -n "$(ticks "$LR" | head -1)" ] && break
    sleep 1
done
# --dials: the replay checks every record's params against the [four_r] the script wrote
# into L's config (write_config) — the dials, not the defaults (4r-i67).
REPLAY_OUT=$(python3 "$REPLAY" --dials "$(node_dir "$L")/config.toml" "$L_LOG" 2>&1)
REPLAY_RC=$?
echo "$REPLAY_OUT" | sed 's/^/    /'
SUM=$(echo "$REPLAY_OUT" | grep -a "four_r replay:" | head -1)
rv() { echo "$SUM" | grep -oE " $1=[0-9]+" | head -1 | cut -d= -f2; }
if [ -z "$SUM" ] || [ "$(rv records)" = "0" ]; then
    fail "the replay found no shadow records (exit $REPLAY_RC)"
else
    [ "$REPLAY_RC" -eq 0 ] && [ "$(rv mismatches)" = "0" ] \
        && pass "every record replays: $SUM" || fail "replay mismatches: $SUM"
    [ "$(rv pressure)" -ge 3 ] && [ "$(rv phase_true)" -ge 1 ] \
        && pass "pressure records $(rv pressure) >= 3, with phase=true $(rv phase_true) >= 1" \
        || fail "pressure records $(rv pressure) (want >= 3), phase=true $(rv phase_true) (want >= 1)"
    [ "$(rv notified_records)" -ge 1 ] \
        && pass "$(rv notified_records) record(s) with h_notified_bytes > 0 (the З-7 mutation is visible)" \
        || fail "FAIL(setup): no record with h_notified_bytes > 0 — a view including notified holdings would go unseen"
    [ "$(rv offer)" -ge 2 ] && pass "offer records $(rv offer) >= 2 (steps 5a, 5b and the rest)" \
        || fail "offer records $(rv offer), want >= 2"
    [ "$(rv params_checked)" = "$(rv records)" ] \
        && pass "params of all $(rv records) records checked against L's [four_r] dials (4r-i67)" \
        || fail "params checked on $(rv params_checked) of $(rv records) records (want all)"
    [ "$(rv latch_pairs)" -ge 1 ] \
        && pass "latch continuity checked on $(rv latch_pairs) consecutive tick pair(s) over $(rv runs) run(s) of the holder task" \
        || fail "no consecutive pressure records within one run: latch continuity unchecked (runs=$(rv runs))"
    [ "$(rv latch_pairs_true)" -ge 1 ] \
        && pass "latch continuity checked on $(rv latch_pairs_true) pair(s) whose previous phase was true (the persisted ON latch)" \
        || fail "no tick pair after a phase=true tick within one run: continuity of the ON latch unchecked (latch_pairs=$(rv latch_pairs))"
    note "measure_invalid=$(rv measure_invalid) (ticks with disk_free = 0, excluded from R1/R2; expected 0, 4r-i52)"
fi

# Re-check the old path against its plans over everything L did before the deletions.
CUR_STEP=7
check_old_path_vs_plan "before step 11"

# ── STEP 11: the shadow broke nothing — restore from the network ─────────────
CUR_STEP=11
echo ""
echo "=== Step 11: F, W, L delete sources (daemon alive) -> restore from the network by sha256 ==="
assert_delete_window "$TIME_SCALE" 200
WINDOW=$((OWNER_DELETE_COOLDOWN_SECS / TIME_SCALE))
N_OK=0; N_ALL=0
restore_one() { # IDX PATH
    local idx="$1" f="$2" want blk t0 el resp
    want=$(content_hash "$f")
    blk=$(file_block_hex "$idx" "$f")
    rm -f "$f"
    t0=$(date -u +%s)
    N_ALL=$((N_ALL + 1))
    if restore_from_network "$idx" "$f" "$want" 120; then
        el=$(( $(date -u +%s) - t0 ))
        resp=$(restore_responses_for "$blk" $(seq 0 $((NUM_NODES - 1)) | grep -vx "$idx"))
        if [ "$el" -ge "$WINDOW" ]; then
            fail "node-0$idx $(basename "$f"): restored after ${el}s >= owner-delete window ${WINDOW}s (raced the delete)"
        elif [ "${resp:-0}" -ge 1 ]; then
            N_OK=$((N_OK + 1))
            pass "node-0$idx $(basename "$f"): $RESTORE_MSG; holders logged $resp RestoreResponse(s)"
        else
            fail "node-0$idx $(basename "$f"): hash matched but no holder logged 'sending RestoreResponse' for ${blk:0:16}"
        fi
    else
        fail "node-0$idx $(basename "$f"): $RESTORE_MSG"
    fi
}
for f in ${FILES[$F]}; do restore_one "$F" "$f"; done
for f in ${FILES[$L]}; do restore_one "$L" "$f"; done
for f in $(echo ${FILES[$W]} | tr ' ' '\n' | head -2); do restore_one "$W" "$f"; done
[ "$N_OK" -eq "$N_ALL" ] && [ "$N_ALL" -eq 8 ] \
    && pass "all $N_ALL restores matched by sha256 from the network" \
    || fail "$N_OK of $N_ALL restores (want 8 of 8)"

# ── STEP 12: free disk below the reserve — Critical (F-Q) ────────────────────
CUR_STEP=12
echo ""
echo "=== Step 12: [F-Q] restart L with a reserve above its disk — Critical: give back all, refuse offers ==="
FS_SIZE=$(df -B1 --output=size "$(node_dir "$L")" | tail -1 | tr -d ' ')
H12=$(status_num "$L" holding_bytes)
info "L holds $H12 bytes; its filesystem is $FS_SIZE bytes; reserve ${BIG_RESERVE_GB} GB"
if ! awk -v s="$FS_SIZE" -v r="$BIG_RESERVE_GB" 'BEGIN { exit !(s + 0 > 0 && s < r * 1073741824) }'; then
    fail "FAIL(setup): L's filesystem ($FS_SIZE B) is not below the reserve ${BIG_RESERVE_GB} GB"
    finish
fi
[ "${H12:-0}" -gt 0 ] || { fail "FAIL(setup): L holds nothing before step 12 (holding_bytes=$H12)"; finish; }
# Never `kill` an empty or 0 PID (0 = this script's whole process group).
case "${PIDS[$L]:-}" in
    ''|0|*[!0-9]*) fail "FAIL(setup): no PID recorded for L ('${PIDS[$L]:-}')"; finish ;;
esac
kill -TERM "${PIDS[$L]}" 2>/dev/null
wait_pid_exit "${PIDS[$L]}" 30 || { kill -9 "${PIDS[$L]}" 2>/dev/null; fail "FAIL(setup): L did not stop within 30 s"; finish; }
write_config "$L" "$SOFT2" "$BIG_RESERVE_GB"
LSTART12=$(log_lines "$L_LOG")
declare -A MARK12
for i in $(seq 1 $((NUM_NODES - 1))); do MARK12[$i]=$(log_lines "$(node_log "$i")"); done
T12=$(date -u +%s)
start_node "$L"
wait_daemon "$L" || { fail "FAIL(setup): L did not come back"; finish; }
# holder-i1 (Q = 0; holder-i1-a with Q > 0 is unit-only): the pressure tick (every 60 s at this time_scale) is Critical and gives
# back everything above the (zero) hard floor in one tick.
CRIT=""
while [ $(( $(date -u +%s) - T12 )) -le 180 ]; do
    CRIT=$(log_since "$L" "$LSTART12" | grep -a "holder_cleanup: hard disk pressure" \
        | grep -a "critical=true" | head -1)
    [ -n "$CRIT" ] && break
    sleep 2
done
if [ -n "$CRIT" ]; then
    pass "L's pressure tick is Critical: evictions=$(log_field "$CRIT" evictions) freed_bytes=$(log_field "$CRIT" freed_bytes) (holder-i1)"
else
    fail "no 'hard disk pressure' with critical=true on L within 180 s (pre-F-Q: quota 0 read as unlimited)"
fi
H_AFTER=""
for _ in $(seq 1 30); do
    H_AFTER=$(status_num "$L" holding_bytes)
    [ "${H_AFTER:-1}" -eq 0 ] && break
    sleep 2
done
# One tick: the FIRST Critical tick freed all it held (freed_bytes = used_bytes of that line;
# later ticks stay Critical with nothing left to evict).
USED1=$(log_field "$CRIT" used_bytes); FREED1=$(log_field "$CRIT" freed_bytes)
if [ "${H_AFTER:-1}" -eq 0 ] && [ -n "$USED1" ] && [ "$USED1" -gt 0 ] && [ "${FREED1:-0}" -eq "$USED1" ]; then
    pass "L gave back everything in one Critical tick: freed $FREED1 of $USED1 B; holding_bytes $H12 -> 0 (holder-i1, Q = 0)"
else
    fail "L: first Critical tick freed ${FREED1:-?} of ${USED1:-?} B; holding_bytes $H12 -> ${H_AFTER:-?} (want all in one tick, then 0)"
fi
PUB12=0; GOT12=0; GOT_BY=""
for _ in $(seq 1 60); do
    PUB12=$(log_since "$L" "$LSTART12" | grep -ac "immediate-drop DropNotice published" || true)
    GOT12=0; GOT_BY=""
    for i in $(seq 1 $((NUM_NODES - 1))); do
        n=$(log_since "$i" "${MARK12[$i]}" | grep -a "received SymbolDropNotice" \
            | grep -ac "holder=${MASTER[$L]}" || true)
        [ "${n:-0}" -ge 1 ] && { GOT12=$((GOT12 + n)); GOT_BY="$GOT_BY node-0$i:$n"; }
    done
    [ "${PUB12:-0}" -ge 1 ] && [ "$GOT12" -ge 1 ] && break
    sleep 2
done
[ "${PUB12:-0}" -ge 1 ] && [ "$GOT12" -ge 1 ] \
    && pass "L published $PUB12 immediate DropNotice(s); owners' own logs received $GOT12 from L:$GOT_BY" \
    || fail "L published ${PUB12:-0} immediate DropNotice(s), owners received $GOT12 from L (want >= 1 each)"
ST12=$(run_cli_q "$L" status)
if echo "$ST12" | grep -q "disk below reserve"; then
    pass "L's status: $(echo "$ST12" | grep "disk below reserve" | sed 's/^ *//') (holder-i4)"
else
    fail "L's status has no 'disk below reserve': $(echo "$ST12" | grep "quota:" | sed 's/^ *//')"
fi
# New offers to L: refused with QuotaFull, per the offerer's own log.
OMARK_W=$(log_lines "$(node_log "$W")"); OMARK_F=$(log_lines "$(node_log "$F")")
head -c $((4 * MIB)) /dev/urandom > "$(node_dir "$W")/files/whale_step12.bin"
head -c "$MIB" /dev/urandom > "$(node_dir "$F")/files/friend_step12.bin"
REJ12=""
for _ in $(seq 1 60); do
    REJ12=$( { log_since "$W" "$OMARK_W"; log_since "$F" "$OMARK_F"; } | grep -a "rejected offer for block" \
        | grep -a "QuotaFull" | grep -a "holder ${DEV[$L]:0:16}" | head -1)
    [ -n "$REJ12" ] && break
    sleep 2
done
if [ -n "$REJ12" ]; then
    pass "a new offer to L refused with QuotaFull: $(echo "$REJ12" | grep -oE 'rejected offer for block [0-9a-f]+')"
else
    rough "neither W nor F offered L within 120 s (backoff?) — the Critical offer rule stands on units only"
fi

finish
