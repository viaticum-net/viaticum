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
# Proves:       the owner's and the shadow's pointers are two histories (status .catalog_lineage
#               differs); postmen hold the shadow's pointer (their own logs); the final DR lists
#               both histories with their file counts, does not pick the newest empty one, stops
#               with a non-zero code and changes nothing; with --catalog <owner prefix> it
#               restores the journal's 3 files, and each file restores byte-for-byte from the
#               network.
# Adversarial:  an empty catalog with the newest pointer (the shadow); a DR that must refuse.
# Cannot close: the forgotten DR-node copy (dr-i15) and the fork point / automatic choice
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
#  2. kill node-00 (machine lost).
#  3. ADVERSARIAL (dr-i6) folder S: `init --mnemonic M` → stdout names `viaticum dr`; daemon on S
#     (empty watch dir), connect to node-01; poll ≤ 300 s until S dr_pointer_published_at > 0 &&
#     dr_pointer_files == 0; L_S = S .catalog_lineage != L_OWNER; nodes 01-04 logged more
#     "mailbox: stored SelfPointer entry" lines with target = the owner's identity after S
#     started (S publishes under the same identity; other nodes' own pointers do not count).
#     Kill S.
#     — check: grep, status_num, jq, grep -c on other nodes
#  4. clean folder D: dr --mnemonic M --peer node-01 → exit≠0; output has exactly 2 lines
#     "  catalog="; the L_OWNER row has files=3, the L_S row files=0; the error names --catalog;
#     D has no identity.key, db.redb or drafts (dr-i12, dr-i13)
#     — check: rc, grep -c, grep per row, grep, find
#     Mutation "pick the freshest pointer across histories" → DR restores L_S: exit 0 → RED here.
#  5. dr ... --catalog <first 8 hex of L_OWNER> into D → exit 0, "[selected: requested]" on the
#     L_OWNER row, Files == 3 — check: rc, grep, FILES_N -eq 3
#  6. daemon on D (no manual connect); restore f1..f3 → sha256 match; holders log
#     RestoreResponse (restore-i1) — check: wait_auth_peers, restore_from_network ×3,
#     restore_responses_for
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
    pass "postmen stored the shadow's pointer under the owner's identity ($STORED_BEFORE -> $STORED_AFTER lines with target=${I_OWNER:0:16})"
else
    fail "no postman logged storing a SelfPointer for target=${I_OWNER:0:16} after the shadow started"
fi
stop_daemon S

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
LEFT=$(find "$D_DIR" -mindepth 1 | sed "s|$D_DIR/||" | tr '\n' ' ')
if [ -z "$LEFT" ]; then
    pass "D is still empty (no identity.key, db.redb, drafts)"
else
    fail "refused DR left files in D: $LEFT"
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

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo "Logs: $TEST_DIR/logs/"
[ "$FAIL" -eq 0 ]
