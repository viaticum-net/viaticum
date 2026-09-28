#!/bin/bash
# Viaticum DR with a shadow node: the friend lost the machine, then by mistake brought up an
# EMPTY node with the same phrase (`init --mnemonic` + daemon), which publishes the freshest
# catalog pointer. A later DR must not silently restore that empty catalog.
# Local processes on one machine (no Docker).
#
# Scenario:     5 nodes, independent masters, star around node-01. The owner node-00 (plain
#               `init`) backs up 3 files and its pointer is published. The machine is lost. The
#               friend runs `init --mnemonic` in a new folder S and starts a daemon with an empty
#               watch dir: S publishes its own, empty, newest catalog. S is switched off. Finally
#               DR on a clean folder D.
# Intent:       dr-i6, dr-i12 (refused DR leaves D empty), dr-i13 (both catalogs listed, choice by
#               --catalog), restore-i1 (after DR). Temporary selection rule of spec B2 slice
#               B2.2a: one catalog history → restored; several → DR stops with the table and
#               requires --catalog (no automatic choice between histories).
#               CROWN-1 C3a: mailbox-i39, i40 (pointers only in the rendezvous box of the
#               phrase, never in the master box), mailbox-i46 / i56 (≤ 2 places per history,
#               a new base takes a place by strength, never by generation), dr-i42 (a
#               dormant history survives any number of publications of another), dr-i48
#               (DR tries the head of each place first), dr-i49 / dr-i50 (readiness drops
#               only when the holders of a block were not seen for W)
# Proves:       the owner's readiness survives holders silent for W/2 and drops (blocks placed <
#               total) once they are silent longer than W, and comes back when they answer;
#               the owner's and the shadow's pointers are two histories (status .catalog_lineage
#               differs); postmen hold the shadow's pointer in the phrase's rendezvous box (their
#               own logs; 0 lines addressed to the master); the shadow restarted twice (three
#               bases) holds exactly its 2 place slots at every postman (logs + an offline read
#               of node-04's disk), next to the owner's 1-2; the final DR lists
#               both histories with their file counts, does not pick the newest empty one, stops
#               with a non-zero code and changes nothing; with --catalog <owner prefix> it
#               restores the journal's 3 files, and each file restores byte-for-byte from the
#               network.
# Adversarial:  an empty catalog with the newest pointer (the shadow), published many times and
#               restarted twice; a DR that must refuse; every holder of the owner's SS base
#               frozen (SIGSTOP) for longer than W.
# Cannot close: 600 days of dormancy (replaced by step 3b + unit dormant_slot_survives_*); all
#               postmen of a dormant history leaving (V-A5); "two weak bases in a row" and
#               "holders offline at night during a compaction" (unit: controlled strengths);
#               the forgotten DR-node copy (dr-i15) and the fork point / automatic choice
#               between related histories (slice B2.2b, waits for Ilya); the shadow's own warning
#               in status (dr-i14, layer 2, B2.2b); shadow with a clock ahead (unit tests
#               select_catalog_*); same file count with changed contents (T3); cluster siblings.
# Depends on:   line C R1-b1: STEP 6 IS RED WITHOUT R1-b1 (the post-DR daemon enrolls its new
#               device into the restored cluster registry; without it the node has no
#               network). Runs WITHOUT any [escrow] section (B1.1, dr-i34).
# Steps:
#  1. 5 nodes plain `init`, star around node-01. node-00 backs up f1, f2, f3 one by one (journal
#     sha256); poll ≤ 300 s until node-00 dr_pointer_files == 3 && acks ≥ 1; L_OWNER = node-00
#     status .catalog_lineage — check: wait_file_restorable, status_num, api_get | jq
#     RADDR = `mailbox-probe rendezvous --phrase M` .address_short (offline).
# 1b. ADVERSARIAL (dr-i49, dr-i50): wait for dr_ready; SIGSTOP every node whose holdings hold
#     the owner's current SS base; at W/2 (W = 7 d / TIME_SCALE ≈ 605 s) dr_ready is still
#     true and blocks placed == total; within W + 180 s blocks placed < total and dr_ready
#     false; SIGCONT; dr_ready true again within 240 s; within 180 s ≥ 1 woken node logs
#     "SelfPointer published via mailbox", and since SIGCONT no node logs a "superseded"
#     refusal with held_stored_at == incoming_stored_at nor "the system clock went back"
#     (mailbox-i62: a wake-up burst sealed several envelopes into one place in one second)
#     — check: holders_of_prefix, status snapshots, grep. Mutation "strength without
#     last_seen" → placed stays == total → RED here.
#  2. kill node-00 (machine lost).
#  3. ADVERSARIAL (dr-i6) folder S: `init --mnemonic M` → stdout names `viaticum dr`; daemon on S
#     (empty watch dir), connect to node-01; poll ≤ 300 s until S dr_pointer_published_at > 0 &&
#     dr_pointer_files == 0; L_S = S .catalog_lineage != L_OWNER; nodes 01-04 logged more
#     "mailbox: stored SelfPointer entry" lines with target = RADDR after S started, and
#     none with target = the owner's master (mailbox-i39)
#     — check: grep, status_num, jq, grep -c on other nodes
# 3b. ADVERSARIAL (mailbox-i46, i56, dr-i42): S restarts twice; after each restart wait for a
#     publication of a NEW base (base= not seen before). Then on postmen 01-04, lines
#     target=RADDR: ≥ 4; every msg_id ∈ {owner slot_a/b, shadow slot_a/b} (probe with
#     L_OWNER / L_S); the shadow's distinct msg_ids == 2, the owner's 1-2; at each postman
#     the first line of every shadow slot has replaced=false, and ≥ 1 shadow line has
#     replaced=true. Offline read of node-04's disk (stopped): at RADDR exactly the 2
#     shadow slots and 1-2 owner slots. Kill S.
#     — check: sp_store_lines, mailbox-probe audit. Mutations: random msg_id → > 4 values;
#     place by generation → the shadow has 1 slot → RED.
#  4. clean folder D: dr --mnemonic M --peer node-01 → exit≠0; output has exactly 2 lines
#     "  catalog=" (two places of one history = one row); the L_OWNER row has files=3, the
#     L_S row files=0; the error names --catalog; the DR log names "dr: rendezvous box
#     address=RADDR"; D has no identity.key, db.redb or drafts (dr-i12, dr-i13)
#     — check: rc, grep -c, grep per row, grep, find
#     Mutation "pick the freshest pointer across histories" → DR restores L_S: exit 0 → RED here.
# 4b. clean folder D2: dr ... --catalog <first 8 hex of L_S>: the DR attempts 1 and 2 are the
#     heads of the shadow's places A and B (places {A, B}, bases == the shadow's last
#     published base of that place, the fresher first; dr-i48) — check: dr_attempt_plan
#  5. dr ... --catalog <first 8 hex of L_OWNER> into D → exit 0, "[selected: requested]" on the
#     L_OWNER row, Files == 3 — check: rc, grep, FILES_N -eq 3
#  6. daemon on D (no manual connect); restore f1..f3 → sha256 match; holders log
#     RestoreResponse (restore-i1) — check: wait_auth_peers, restore_from_network ×3,
#     restore_responses_for
#  7. no node logged "store rejected — plaintext payload" or "SelfPointer in the master box
#     — dropped" (mailbox-i39, i40) — check: grep
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_dr_shadow_test.sh

set -euo pipefail

TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-drshadow-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)

PASS=0; FAIL=0
PIDS=()
declare -A NODE_PID

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    echo "  Killed ${#PIDS[@]} processes"
    echo "  Test dir: $TEST_DIR (not removed, inspect if needed)"
}
trap cleanup EXIT

node_dir() {
    case "$1" in
        S|D) echo "$TEST_DIR/$1" ;;
        *) echo "$TEST_DIR/node-$(printf '%02d' "$1")" ;;
    esac
}
node_log() { echo "$TEST_DIR/logs/$1.log"; }

run_cli() {
    local idx="$1"; shift
    "$BINARY" --data-dir "$(node_dir "$idx")" "$@"
}
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    for _ in $(seq 1 120); do
        run_cli_q "$1" status | grep -q "identity:" && return 0
        sleep 0.5
    done
    return 1
}

get_addr() {
    local raw=""
    for _ in $(seq 1 20); do
        raw=$(run_cli_q "$1" status | grep "addr:" | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$raw" ] && break
        sleep 0.5
    done
    [ -n "$raw" ] || return 0
    echo "$raw" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

write_config() {
    cat > "$(node_dir "$1")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF
}

start_daemon() {
    local idx="$1"
    mkdir -p "$(node_dir "$idx")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$idx")/files" \
        >> "$(node_log "$idx")" 2>&1 &
    NODE_PID[$idx]=$!
    PIDS+=("$!")
}

stop_daemon() {
    local pid="${NODE_PID[$1]:-}"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$pid" 2>/dev/null || true
    NODE_PID[$1]=""
}

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

stored_pointer_lines() {
    sp_store_lines "$RADDR" "${HOLDERS[@]}" | wc -l
}

# Pointer store lines addressed to the owner's MASTER (must stay 0: mailbox-i39).
master_box_pointer_lines() {
    local t=0 i n
    for i in "${HOLDERS[@]}"; do
        n=$(plain_log "$i" | grep -a "mailbox: stored SelfPointer entry" \
            | grep -ac "target=${I_OWNER:0:16}" || true)
        t=$((t + ${n:-0}))
    done
    echo "$t"
}

# run_dr LABEL DATA_DIR [args...]: whole output to $TEST_DIR/logs/dr-<LABEL>.log.
run_dr() {
    local label="$1" dir="$2"; shift 2
    DR_LOG="$TEST_DIR/logs/dr-$label.log"
    local t0; t0=$(date +%s)
    set +e
    RUST_LOG=info timeout 900 "$BINARY" --data-dir "$dir" dr --mnemonic "$M" "$@" > "$DR_LOG" 2>&1
    DR_RC=$?
    set -e
    DR_ERRLINE=$(sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG" | grep -a '^error:' | tail -1 || true)
    FILES_N=$(grep -a "^  Files:" "$DR_LOG" | grep -oE '[0-9]+' | tail -1 || true)
    echo "    dr[$label] exit=$DR_RC wall=$(( $(date +%s) - t0 ))s log=$DR_LOG"
    sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG" | grep -avE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' \
        | sed 's/^/    | /' || true
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"; exit 1; }
fi
PROBE="$(cd "$(dirname "$(command -v "$BINARY")")" && pwd)/mailbox-probe"
[ -x "$PROBE" ] || { echo "ERROR: $PROBE not found (cargo build --release -p viaticum --features e2e-tools)"; exit 1; }

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum DR shadow test"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"
mkdir -p "$TEST_DIR/logs"

# ── STEP 1: OWNER BACKS UP, POINTER PUBLISHED ────────────────────
echo ""
echo "=== Step 1: 5 nodes, star around node-01; owner node-00 backs up 3 files ==="
for i in 0 1 2 3 4; do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > "$TEST_DIR/logs/init-$i.out" 2>&1
    write_config "$i"
done
M=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-0.out" | tail -1 | sed 's/^ *//')
I_OWNER=$(awk '/^Public key:/ {print $3}' "$TEST_DIR/logs/init-0.out")
[ ${#I_OWNER} -eq 64 ] || { fail "owner identity not captured"; exit 1; }
[ "$(echo "$M" | wc -w)" -eq 24 ] || { fail "owner phrase not captured"; exit 1; }
RADDR=$("$PROBE" rendezvous --phrase "$M" --json | jq -r .address_short)
[ ${#RADDR} -eq 16 ] || { fail "mailbox-probe rendezvous gave no address for M"; exit 1; }
echo "  rendezvous box of M: $RADDR (offline, from the phrase)"
start_daemon 1
wait_daemon 1 || { fail "node-01 not responding"; exit 1; }
ADDR_01=$(get_addr 1)
[ -n "$ADDR_01" ] || { fail "no node-01 address"; exit 1; }
for i in 0 2 3 4; do
    start_daemon "$i"
    wait_daemon "$i" || { fail "node-0$i not responding"; exit 1; }
    run_cli_q "$i" connect "$ADDR_01" > /dev/null
done
wait_auth_peers 1 4 60 || fail "star: node-01 has $(status_num 1 peer_count_authenticated)/4 peers"
wait_auth_peers 0 1 60 || fail "node-00 has no authenticated peer"

FILES_DIR="$(node_dir 0)/files"
declare -A HASH BLOCK
for f in f1 f2 f3; do
    dd if=/dev/urandom of="$TEST_DIR/$f.bin" bs=1024 count=64 2>/dev/null
    HASH[$f]=$(content_hash "$TEST_DIR/$f.bin")
    mv "$TEST_DIR/$f.bin" "$FILES_DIR/$f.bin"
    if wait_file_restorable 0 "$FILES_DIR/$f.bin" 180; then
        BLOCK[$f]=$(file_block_hex 0 "$FILES_DIR/$f.bin")
    else
        fail "$f not restorable per owner"; exit 1
    fi
done
pass "owner backed up f1, f2, f3"
READY=0
for _ in $(seq 1 60); do
    if [ "$(status_num 0 dr_pointer_files)" -eq 3 ] && [ "$(status_num 0 dr_pointer_acks)" -ge 1 ]; then
        READY=1; break
    fi
    sleep 5
done
L_OWNER=$(api_get 0 /api/status | jq -r '.catalog_lineage // empty')
if [ "$READY" -eq 1 ] && [ ${#L_OWNER} -eq 32 ]; then
    pass "owner's pointer (3 files) accepted; owner history ${L_OWNER:0:8}…"
else
    fail "owner's pointer not ready (files=$(status_num 0 dr_pointer_files) acks=$(status_num 0 dr_pointer_acks) lineage='$L_OWNER')"
    exit 1
fi

# ── STEP 1b: HOLDERS SILENT LONGER THAN W → READINESS DROPS ──────
echo ""
W_SECS=$(( 7 * 24 * 3600 / TIME_SCALE ))
echo "=== Step 1b: ADVERSARIAL every holder of the owner's SS base frozen > W = ${W_SECS}s (dr-i49, dr-i50) ==="
# One snapshot → "ready placed total acks threshold".
ready_snapshot() {
    api_get 0 /api/status | jq -r '"\(.dr_ready) \(.dr_ss_blocks_placed) \(.dr_ss_blocks_total) \(.dr_pointer_acks) \(.dr_pointer_ack_threshold)"' 2>/dev/null || true
}
R0=0
for _ in $(seq 1 60); do
    [ "$(status_num 0 dr_ready)" = "true" ] && { R0=1; break; }
    sleep 5
done
BASE16=$(plain_log 0 | grep -aE "system_state push: (base published|compacted to new base)" | tail -1 \
    | grep -oE 'base=[0-9a-f]+' | cut -d= -f2 || true)
FROZEN=$(holders_of_prefix "$BASE16" "${HOLDERS[@]}")
if [ "$R0" -eq 1 ] && [ -n "$FROZEN" ]; then
    pass "precondition: owner dr_ready; SS base $BASE16 held by node(s) $FROZEN"
else
    fail "precondition: dr_ready=$(status_num 0 dr_ready), base '$BASE16' holders '$FROZEN' — the negative would be blind"
fi
if [ -n "$FROZEN" ]; then
    for i in $FROZEN; do kill -STOP "${NODE_PID[$i]}" 2>/dev/null || true; done
    T1B=$(date +%s)
    sleep $(( W_SECS / 2 ))
    read -r rdy placed total _acks _thr <<< "$(ready_snapshot)"
    if [ "${rdy:-}" = "true" ] && [ "${total:-0}" -gt 0 ] && [ "${placed:-}" = "${total:-}" ]; then
        pass "holders silent $(( $(date +%s) - T1B ))s < W: still ready, blocks $placed/$total (a night offline does not count)"
    else
        fail "holders silent $(( $(date +%s) - T1B ))s < W: ready=${rdy:-?} blocks ${placed:-?}/${total:-?} (want ready, all placed)"
    fi
    DROPPED=""
    while [ $(( $(date +%s) - T1B )) -lt $(( W_SECS + 180 )) ]; do
        read -r rdy placed total _acks _thr <<< "$(ready_snapshot)"
        if [ "${rdy:-}" = "false" ] && [ -n "${total:-}" ] && [ "${placed:-0}" -lt "${total:-0}" ]; then
            DROPPED="after $(( $(date +%s) - T1B ))s: ready=false, blocks $placed/$total"; break
        fi
        sleep 10
    done
    declare -A CONT_FROM
    for i in 0 "${HOLDERS[@]}"; do CONT_FROM[$i]=$(log_line_count "$i"); done
    for i in $FROZEN; do kill -CONT "${NODE_PID[$i]}" 2>/dev/null || true; done
    if [ -n "$DROPPED" ]; then
        pass "holders silent > W: readiness dropped $DROPPED"
    else
        fail "holders silent $(( W_SECS + 180 ))s > W: readiness never dropped (ready=${rdy:-?} blocks ${placed:-?}/${total:-?}) — strength ignores last_seen?"
    fi
    BACK=0
    for _ in $(seq 1 48); do
        [ "$(status_num 0 dr_ready)" = "true" ] && { BACK=1; break; }
        sleep 5
    done
    if [ "$BACK" -eq 1 ]; then
        pass "holders answer again: dr_ready true again"
    else
        fail "dr_ready not back within 240 s after SIGCONT (blocks $(status_num 0 dr_ss_blocks_placed)/$(status_num 0 dr_ss_blocks_total))"
    fi
    wait_auth_peers 1 3 90 || fail "after SIGCONT node-01 has $(status_num 1 peer_count_authenticated) authenticated peers (want ≥ 3)"
    # mailbox-i62: woken publishers never put two envelopes with one stored_at into a
    # place. Positive evidence first: a woken node published its pointer after SIGCONT.
    WOKE_PUB=0
    for _ in $(seq 1 36); do
        WOKE_PUB=0
        for i in $FROZEN; do
            n=$(log_since "$i" "${CONT_FROM[$i]}" | grep -ac "SelfPointer published via mailbox" || true)
            [ "${n:-0}" -gt 0 ] && WOKE_PUB=$((WOKE_PUB + 1))
        done
        [ "$WOKE_PUB" -gt 0 ] && break
        sleep 5
    done
    EQ_SUP=0; CLOCK_BACK=0
    for i in 0 "${HOLDERS[@]}"; do
        n=$(log_since "$i" "${CONT_FROM[$i]}" | awk '/store rejected — superseded/ {
                h = ""; x = ""
                for (k = 1; k <= NF; k++) {
                    if ($k ~ /^held_stored_at=/) h = substr($k, 16)
                    if ($k ~ /^incoming_stored_at=/) x = substr($k, 20)
                }
                if (h != "" && h == x) c++
            } END { print c + 0 }' || true)
        EQ_SUP=$((EQ_SUP + ${n:-0}))
        n=$(log_since "$i" "${CONT_FROM[$i]}" | grep -ac "the system clock went back" || true)
        CLOCK_BACK=$((CLOCK_BACK + ${n:-0}))
    done
    if [ "$WOKE_PUB" -gt 0 ] && [ "$EQ_SUP" -eq 0 ] && [ "$CLOCK_BACK" -eq 0 ]; then
        pass "after SIGCONT $WOKE_PUB woken node(s) published their pointer; 0 equal-time 'superseded' refusals, 0 'clock went back' (mailbox-i62)"
    else
        fail "after SIGCONT: woken publishers $WOKE_PUB (want ≥ 1), equal-time superseded $EQ_SUP, 'clock went back' $CLOCK_BACK (want 0, 0) (mailbox-i62)"
    fi
fi

# ── STEP 2: MACHINE LOST ─────────────────────────────────────────
echo ""
echo "=== Step 2: the owner's machine is lost ==="
stop_daemon 0
rm -f "$FILES_DIR"/f*.bin
pass "node-00 stopped, sources gone"

# ── STEP 3: THE SHADOW NODE ──────────────────────────────────────
echo ""
echo "=== Step 3: ADVERSARIAL shadow: 'init --mnemonic' + daemon on an empty folder (dr-i6) ==="
S_DIR=$(node_dir S); mkdir -p "$S_DIR"
run_cli S init --mnemonic "$M" > "$TEST_DIR/logs/init-S.out" 2>&1
if grep -q "viaticum dr" "$TEST_DIR/logs/init-S.out"; then
    pass "init --mnemonic points the friend to 'viaticum dr'"
else
    fail "init --mnemonic prints no 'viaticum dr' hint"
fi
write_config S
STORED_BEFORE=$(stored_pointer_lines)
start_daemon S
wait_daemon S || { fail "shadow daemon not responding"; exit 1; }
run_cli_q S connect "$ADDR_01" > /dev/null
S_READY=0
for _ in $(seq 1 60); do
    if [ "$(status_num S dr_pointer_published_at)" -gt 0 ] && [ "$(status_num S dr_pointer_files)" -eq 0 ]; then
        S_READY=1; break
    fi
    sleep 5
done
L_S=$(api_get S /api/status | jq -r '.catalog_lineage // empty')
if [ "$S_READY" -eq 1 ] && [ ${#L_S} -eq 32 ] && [ "$L_S" != "$L_OWNER" ]; then
    pass "shadow published its own empty catalog: history ${L_S:0:8}… != owner's ${L_OWNER:0:8}…"
else
    fail "shadow: published_at=$(status_num S dr_pointer_published_at) files=$(status_num S dr_pointer_files) lineage='$L_S' (owner '$L_OWNER')"
fi
STORED_AFTER=$(stored_pointer_lines)
if [ "$STORED_AFTER" -gt "$STORED_BEFORE" ]; then
    pass "postmen stored the shadow's pointer in the phrase's rendezvous box ($STORED_BEFORE -> $STORED_AFTER lines with target=$RADDR)"
else
    fail "no postman logged storing a SelfPointer for target=$RADDR after the shadow started"
fi
IN_MASTER=$(master_box_pointer_lines)
if [ "$STORED_AFTER" -gt 0 ] && [ "$IN_MASTER" -eq 0 ]; then
    pass "0 pointer store lines addressed to the owner's master ${I_OWNER:0:16} (mailbox-i39)"
else
    fail "$IN_MASTER pointer store line(s) addressed to the owner's master ${I_OWNER:0:16}"
fi

# ── STEP 3b: THE SHADOW RESTARTS TWICE ───────────────────────────
echo ""
echo "=== Step 3b: ADVERSARIAL the shadow restarts twice: still exactly 2 places (mailbox-i46, i56, dr-i42) ==="
shadow_bases() {
    plain_log S | grep -a "SelfPointer published via mailbox" | grep -oE 'base=[0-9a-f]+' | cut -d= -f2 | sort -u || true
}
RESTARTS_OK=1
for r in 1 2; do
    SEEN=" $(shadow_bases | tr '\n' ' ') "
    stop_daemon S
    FROM=$(log_line_count S)
    start_daemon S
    wait_daemon S || { fail "shadow did not restart ($r)"; RESTARTS_OK=0; break; }
    run_cli_q S connect "$ADDR_01" > /dev/null
    NEWB=""
    for _ in $(seq 1 60); do
        line=$(log_since S "$FROM" | grep -a "SelfPointer published via mailbox" | tail -1 || true)
        NEWB=$(echo "$line" | grep -oE 'base=[0-9a-f]+' | cut -d= -f2 || true)
        if [ -n "$NEWB" ] && ! echo "$SEEN" | grep -q " $NEWB "; then break; fi
        NEWB=""
        sleep 5
    done
    if [ -n "$NEWB" ]; then
        echo "  restart $r: new base $NEWB in $(echo "$line" | grep -oE 'place=[AB]')"
    else
        fail "shadow restart $r: no publication of a new base within 300 s"; RESTARTS_OK=0
    fi
done
S_SLOTS=$("$PROBE" rendezvous --phrase "$M" --lineage "$L_S" --json)
O_SLOTS=$("$PROBE" rendezvous --phrase "$M" --lineage "$L_OWNER" --json)
SA=$(echo "$S_SLOTS" | jq -r .slot_a); SB=$(echo "$S_SLOTS" | jq -r .slot_b)
OA=$(echo "$O_SLOTS" | jq -r .slot_a); OB=$(echo "$O_SLOTS" | jq -r .slot_b)
LINES=$(sp_store_lines "$RADDR" "${HOLDERS[@]}")
N_LINES=$(echo "$LINES" | grep -c . || true)
IDS=$(sp_msg_ids "$RADDR" "${HOLDERS[@]}")
N_S=0; N_O=0; FOREIGN=""
for id in $IDS; do
    case "$id" in
        "$SA"|"$SB") N_S=$((N_S + 1)) ;;
        "$OA"|"$OB") N_O=$((N_O + 1)) ;;
        *) FOREIGN="$FOREIGN $id" ;;
    esac
done
if [ "$RESTARTS_OK" -eq 1 ] && [ "$N_LINES" -ge 4 ] && [ -z "$FOREIGN" ] && [ "$N_S" -eq 2 ] \
    && [ "$N_O" -ge 1 ] && [ "$N_O" -le 2 ]; then
    pass "postmen: $N_LINES store lines for $RADDR, msg_ids only from the two histories' slots: shadow 2, owner $N_O"
else
    fail "postmen for $RADDR: $N_LINES lines, shadow slots $N_S (want 2), owner slots $N_O (want 1-2), foreign:${FOREIGN:- none}"
fi
FIRST_BAD=""
for i in "${HOLDERS[@]}"; do
    for sl in "$SA" "$SB"; do
        first=$(echo "$LINES" | grep -a "^$i " | grep -a "msg_id=$sl" | head -1 || true)
        [ -z "$first" ] || echo "$first" | grep -q "replaced=false" || FIRST_BAD="$FIRST_BAD node-0$i:${sl:0:8}"
    done
done
REPL=$(echo "$LINES" | grep -aE "msg_id=($SA|$SB)" | grep -c "replaced=true" || true)
if [ -z "$FIRST_BAD" ] && [ "$REPL" -ge 1 ]; then
    pass "each shadow slot is new at its first store (replaced=false), $REPL later store(s) replaced it"
else
    fail "shadow slot stores: first line not replaced=false at$FIRST_BAD; replaced=true lines: $REPL"
fi
stop_daemon S
stop_daemon 4
AUD4="$TEST_DIR/logs/audit-node04.json"
if "$PROBE" audit --data-dir "$(node_dir 4)" > "$AUD4" 2> "$TEST_DIR/logs/audit-node04.err"; then
    A_IDS=$(jq -r --arg a "$RADDR" '[.entries[] | select(.class=="SelfPointer" and (.target|startswith($a))) | .msg_id] | .[]' "$AUD4")
    A_S=0; A_O=0; A_X=""
    for id in $A_IDS; do
        case "$id" in
            "$SA"|"$SB") A_S=$((A_S + 1)) ;;
            "$OA"|"$OB") A_O=$((A_O + 1)) ;;
            *) A_X="$A_X $id" ;;
        esac
    done
    if [ "$A_S" -eq 2 ] && [ "$A_O" -ge 1 ] && [ "$A_O" -le 2 ] && [ -z "$A_X" ]; then
        pass "node-04's disk: at $RADDR the shadow's 2 places and the owner's $A_O, nothing else"
    else
        fail "node-04's disk at $RADDR: shadow $A_S (want 2), owner $A_O (want 1-2), other:${A_X:- none}"
    fi
else
    fail "mailbox-probe audit of node-04 failed: $(tail -2 "$TEST_DIR/logs/audit-node04.err")"
fi
start_daemon 4
wait_daemon 4 || fail "node-04 did not restart after the audit"
run_cli_q 4 connect "$ADDR_01" > /dev/null

# ── STEP 4: DR MUST NOT PICK THE NEWEST EMPTY CATALOG ────────────
echo ""
echo "=== Step 4: DR on a clean folder: two histories → stop with the table (dr-i13, dr-i12) ==="
D_DIR=$(node_dir D); mkdir -p "$D_DIR"
run_dr choose "$D_DIR" --peer "$ADDR_01"
ROWS=$(grep -ac "^  catalog=" "$DR_LOG" || true)
ROW_OWNER=$(grep -a "^  catalog=$L_OWNER " "$DR_LOG" || true)
ROW_S=$(grep -a "^  catalog=$L_S " "$DR_LOG" || true)
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q -- "--catalog"; then
    pass "DR stopped (exit $DR_RC) and asks for --catalog"
else
    fail "DR did not stop on two histories: exit $DR_RC, Files=${FILES_N:-none}, '$DR_ERRLINE'"
fi
if [ "$ROWS" -eq 2 ] && echo "$ROW_OWNER" | grep -q " files=3 " && echo "$ROW_S" | grep -q " files=0 "; then
    pass "table: owner's history files=3, shadow's files=0"
else
    fail "table: $ROWS rows; owner row '$ROW_OWNER'; shadow row '$ROW_S'"
fi
# The field is ANSI-coloured in the raw log: strip first; count, not -q (pipefail SIGPIPE).
if [ "$(sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG" | grep -ac "dr: rendezvous box address=$RADDR" || true)" -ge 1 ]; then
    pass "DR looked in the phrase's rendezvous box $RADDR"
else
    fail "DR log has no 'dr: rendezvous box address=$RADDR'"
fi
LEFT=$(find "$D_DIR" -mindepth 1 | sed "s|$D_DIR/||" | tr '\n' ' ')
if [ -z "$LEFT" ]; then
    pass "D is still empty (no identity.key, db.redb, drafts)"
else
    fail "refused DR left files in D: $LEFT"
fi

# ── STEP 4b: DR TRIES THE HEAD OF EACH PLACE FIRST ───────────────
echo ""
echo "=== Step 4b: DR --catalog <shadow>: attempts 1-2 are the heads of the shadow's two places (dr-i48) ==="
D2_DIR="$TEST_DIR/D2"; mkdir -p "$D2_DIR"
run_dr heads "$D2_DIR" --peer "$ADDR_01" --catalog "${L_S:0:8}"
PLAN=$(dr_attempt_plan "$DR_LOG")
echo "$PLAN" | sed 's/^/    plan: /'
P1=$(echo "$PLAN" | sed -n 1p); P2=$(echo "$PLAN" | sed -n 2p)
HEAD_A=$(last_published_base S A); HEAD_B=$(last_published_base S B)
read -r _ PL1 C1 B1 <<< "$P1"; read -r _ PL2 C2 B2 <<< "$P2"
head_of() { [ "$1" = A ] && echo "$HEAD_A" || echo "$HEAD_B"; }
if [ -n "$P2" ] && { [ "$PL1$PL2" = "AB" ] || [ "$PL1$PL2" = "BA" ]; } \
    && [ "$B1" = "$(head_of "$PL1")" ] && [ "$B2" = "$(head_of "$PL2")" ] && [ "$C1" -ge "$C2" ]; then
    pass "DR attempts 1-2: heads of places $PL1 ($B1) and $PL2 ($B2), fresher first"
else
    fail "DR attempt plan: 1='$P1' 2='$P2'; shadow's last bases A=$HEAD_A B=$HEAD_B"
fi

# ── STEP 5: THE FRIEND CHOOSES ───────────────────────────────────
echo ""
echo "=== Step 5: DR --catalog <owner prefix> ==="
run_dr chosen "$D_DIR" --peer "$ADDR_01" --catalog "${L_OWNER:0:8}"
if [ "$DR_RC" -eq 0 ] && [ "${FILES_N:-0}" -eq 3 ] \
    && grep -a "^  catalog=$L_OWNER " "$DR_LOG" | grep -q "\[selected: requested\]"; then
    pass "DR restored the owner's catalog on request: Files == 3"
else
    fail "DR --catalog: exit $DR_RC, Files=${FILES_N:-none}, '$DR_ERRLINE'"
fi

# ── STEP 6: FILES BACK FROM THE NETWORK ──────────────────────────
echo ""
echo "=== Step 6: daemon on D; restore the files by hash (restore-i1) ==="
assert_delete_window "$TIME_SCALE"
write_config D
start_daemon D
wait_daemon D || { fail "daemon on D did not start"; exit 1; }
[ -n "$(get_addr D)" ] || fail "daemon on D has no network: waits R1-b (own device not enrolled)"
wait_auth_peers D 1 90 || fail "daemon on D reached no peer in 90 s"
for f in f1 f2 f3; do
    before=$(restore_responses_for "${BLOCK[$f]}" "${HOLDERS[@]}")
    if restore_from_network D "$FILES_DIR/$f.bin" "${HASH[$f]}" 180; then
        pass "restore $f: $RESTORE_MSG"
    else
        fail "restore $f: $RESTORE_MSG"
    fi
    served=$(( $(restore_responses_for "${BLOCK[$f]}" "${HOLDERS[@]}") - before ))
    if [ "$served" -ge 1 ]; then pass "holders logged $served RestoreResponse(s) for $f"
    else fail "no holder logged a RestoreResponse for $f"; fi
done

# ── STEP 7: HONEST NODES NEVER HIT THE POINTER GUARDS ────────────
echo ""
echo "=== Step 7: no plaintext-pointer refusal, no pointer in a master box (mailbox-i39, i40) ==="
NEG=$(honest_mailbox_negatives 0 S D "${HOLDERS[@]}")
if [ -z "$NEG" ] && [ "$STORED_AFTER" -gt 0 ]; then
    pass "0 'store rejected — plaintext payload' and 0 'SelfPointer in the master box' lines on all nodes"
else
    fail "pointer guards hit on honest nodes: $(echo "$NEG" | head -3)"
fi

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo "Logs: $TEST_DIR/logs/"
[ "$FAIL" -eq 0 ]
