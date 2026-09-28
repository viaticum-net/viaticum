#!/bin/bash
# Viaticum DR E2E: the friend loses the whole machine, recovers from the phrase (after the
# classic mistakes), restores the files from the network and puts them back.
# Local processes on one machine (no Docker).
#
# Scenario:     5 nodes, independent masters, star around node-00. node-00 is set up the way a
#               friend does it (plain `init`, phrase taken from stdout), backs up 3 files, and
#               its DR pointer is published. Then the machine is lost; the friend recovers with
#               the phrase, first making the classic mistakes, then correctly, restores the files
#               from the network and puts them back one by one.
# Intent:       dr-i1, dr-i2, dr-i3, dr-i4, dr-i5, dr-i9, dr-i10, dr-i11, dr-i18, dr-i19, dr-i22,
#               restore-i1 (after DR), dr-i8 (step 9, skeleton: filled by CROWN-1 C4)
# Rule:         the owner is created ONLY with plain `init` (random device id). Never
#               `init --mnemonic` for the owner: it hides the ghost device (dr-i19) and the cert
#               path (dr-i22).
# Timing:       every DR call prints its wall time; > 300 s (before CROWN-1 C3) → ROUGH (exit 3).
# Proves:       status shows DR readiness only after a postman accepted the pointer (the
#               postman's own log); DR follows the phrase; a successful DR over an old DB keeps it
#               as .dr-bak (hash) without clobbering an earlier .dr-bak; the catalog file count
#               equals the journal (0 = FAIL); every file restores byte-for-byte on a wiped machine
#               and holders log RestoreResponse; status counts files without a local source,
#               restore to staging does not reduce the count, putting files back does; a file whose
#               source is missing after DR is not deleted in the network, while a file the friend
#               deletes is (positive control in the same run and time scale — which also proves the
#               recovered files belong to the new device); the recovered daemon reaches the seed
#               by the address DR learned live although the snapshot holds its old address,
#               and the seed sees the new device authenticated; the recovered DB is a NEW
#               catalog history (never the lost machine's), and its first pointer carries it.
# Causal note (dr-i18): the recovered node reaches the moved seed because the peer records
#               DR learned LIVE are merged back over the snapshot (the live record of node-01
#               already holds the address DR dialed: swarm.rs puts the dialed address first
#               in listen_addrs). "--peer goes first" (prepend_seed_addrs) is NOT separately
#               proven here — a no-op prepend stays green; it is proven by the unit test
#               restored_db_keeps_seed_addr_from_peer_arg_over_snapshot_addr only.
# Mutations:    no merge of live peers after restore_db_force → step 6 (node-01 never "auth");
#               no ownership rewrite (dr-i19) → step 8 positive control; DR inherits the
#               source history → step 6 lineage check; "missing file → Deleted" → step 8
#               (BLOCK3); status "ready" on a built but unaccepted pointer → unit test only.
# Adversarial:  typo into a folder with a foreign key (3); the seed changed its address after the
#               last pointer (3a); valid foreign phrase then the right one into the same folder
#               (4); DR into an old node's folder twice and into a live node's folder (5); machine
#               lost (whole data dir wiped, source gone, new port); single seed peer.
# Cannot close: > 100 nodes (CS-DR-1 is unit-tested); 40-node DHT variant for F12 (discovery
#               degenerates at 40 nodes today, line C; F12 is unit-tested against libp2p's key
#               hashing); real NAT; real clock (pointer cadence is divided by time_scale); cluster
#               siblings; "0 acks → not ready" (unit test publish_step_does_not_record_*);
#               SIGKILL inside the DR commit (unit-tested per rename step); several catalog
#               histories (local_dr_shadow_test); restore-i3 (honest outcome) only on the
#               success path: restore_from_network requires CLI exit 0, job outcome
#               `complete`, the file in the job's restored_paths and staging ==
#               restored_paths; partial / failed outcomes are local_restore_network_test
#               (B1.4). Runs WITHOUT any [escrow] section (B1.1: restore of one's own data
#               has no escrow gate, dr-i34).
# Depends on:   line C R1-b1 (the post-DR daemon enrolls its new device into the restored
#               cluster registry). STEPS 6+ ARE RED WITHOUT R1-b1: the recovered node has no
#               network (step 6 names it "waits R1-b") and everything after fails for that
#               reason. Until R1-b1 is merged the scenario runs on a tree with session/net.
# Steps:
#  1. init node-00 with plain `init` → M, I, device D_old; nodes 01-04 plain `init` (M_01).
#     Back up f1 (1 MiB), f2 (8 KiB), f3 (256 KiB) one by one; journal = path → sha256; each
#     restorable per owner; the three blocks pairwise different — check: wait_file_restorable ×3,
#     file_block_hex (else FAIL setup, as in local_pack_delete_test)
#  2. right after start (before the first push tick): status dr_pointer_published_at == 0; then
#     poll ≤ 300 s until dr_pointer_files == 3 && dr_pointer_acks ≥ 1; ≥ 1 of nodes 01-04 logged
#     "mailbox: stored SelfPointer entry" with target = the owner's identity at or after that
#     publication time (dr-i9); L_OWNER = node-00 status .catalog_lineage
#     — check: status_num, log timestamps on other nodes filtered by target
#  3. ADVERSARIAL kill node-00 (its folder = OLD). Folder X = plain `init` (foreign key).
#     dr with a typo of M into X → exit≠0, error about the phrase; X/identity.key unchanged
#     (dr-i3) — check: rc, grep, sha256
# 3a. ADVERSARIAL (dr-i18) the seed moves: node-01 restarts on a NEW listen_port and is
#     authenticated with ≥ 1 of nodes 02-04 again; ADDR_01 := its new address. node-00's last
#     snapshot holds the OLD one. All DRs below use --peer ADDR_01 — check: get_addr differs,
#     status_num 1 peer_count_authenticated ≥ 1
#  4. ADVERSARIAL empty folder Y: dr --mnemonic M_X → exit≠0 "no catalog found", Y has no
#     identity.key; then dr M into Y → exit 0, "Identity restored:" == I, Files == 3 (dr-i4,
#     dr-i2) — check: rc, [ ! -e ], hex compare, FILES_N -eq 3
#  5. ADVERSARIAL H0 = sha256(OLD/db.redb); dr M into OLD → exit 0; OLD/db.redb.dr-bak == H0;
#     OLD/identity.key unchanged; second dr into OLD → .dr-bak still H0, .dr-bak.1 exists
#     (dr-i5). Live half: PRECONDITION node-01 dr_pointer_acks ≥ 1 (a DR that wrongly passed
#     the lock would find a catalog and commit — not blind); dr M_01 into node-01's folder →
#     exit≠0 "in use"; node-01 answers status; node-02 still counts node-01 authenticated; no
#     .dr-bak* in node-01's folder (dr-i5) — check: sha256, [ -e ], status_num, rc, grep, ls
#  6. wipe OLD (and X, Y). dr M --peer ADDR_01 into it → Files == 3 (0 = FAIL), output says
#     "not re-protected"; new machine = NEW listen_port. Stop nodes 02-04. Start node-00 (no
#     manual connect) → within 60 s node-00 status .peers has node-01's device with link
#     "auth" (only via the address DR learned live, merged over the snapshot's dead one,
#     dr-i18); DR's "Catalog: X (… restored from Y)": X != Y, Y == L_OWNER, and status
#     .catalog_lineage == X (a new history, dr-i15);
#     node-01's log has a NEW "peer authenticated" line (after the daemon start) for node-00's
#     new device, != D_old (dr-i22). Start 02-04 → wait_auth_peers 0 ≥ 3. files_without_source
#     == 3; restore each journal file → sha256 match, holders log RestoreResponse; after the
#     restores files_without_source is still 3 (dr-i1, dr-i11, restore-i1)
#     — check: FILES_N, grep, api_get .peers link with deadline, log_since grep on node-01,
#       wait_auth_peers, status_num, restore_from_network, restore_responses_for
#  7. move restored f1 and f2 to their original paths (f3 stays missing) → poll ≤ 60 s
#     files_without_source == 1 (dr-i11) — check: status_num. (The PoS corroboration of this
#     step needs a faster clock: it is checked in step 8.) Then poll ≤ 300 s for the recovered
#     node's first accepted pointer: its log line "SelfPointer published via mailbox" carries
#     lineage=X, status .catalog_lineage is still X — check: status_num, grep
#  8. dr-i10 + dr-i19 with a positive control. Restart ALL 5 daemons at --time-scale 20000
#     (owner and holder delete cooldowns ≈ 121 s each). Record BLOCK1/BLOCK3 symbols on nodes
#     01-04. Delete f1 at its original path. Poll every 5 s until DEADLINE ≈ 370 s:
#       FAIL at once if a holder logs "holding marked for deletion" for BLOCK3, node-00 logs
#       "scheduler: DeleteMsg published via mailbox" for BLOCK3 (scheduler at debug on node-00),
#       or BLOCK3 symbols on a holder decrease;
#       the positive control MUST appear: "holding marked for deletion" for BLOCK1 on ≥ 1 holder
#       (without dr-i19 f1 still lists the lost device as Present and no Delete goes out).
#     Also within the deadline: a holder's PoS response for BLOCK2 (back in place) resolves Pass
#     at node-00 ("mailbox PosResponse resolved … outcome=Pass", step 7's corroboration).
#     — check: block_symbols_on, delete_marks_for, grep -c with block prefix, deadline loop
#  9. (C4) holder node-03 offline during DR → a PoS challenge from node-00 lands in node-03's box
#     by its MASTER (dr-i8). SKELETON ONLY: not implemented until CROWN-1 C4.
# 10. move restored f3 back → poll files_without_source == 0 (f1 deleted = not live)
#     (dr-i11) — check: status_num
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_dr_test.sh

set -euo pipefail

NUM_NODES=5
TIME_SCALE=1000        # pointer push interval = max(6 h / 1000, 60 s) = 60 s
TIME_SCALE_DELETE=20000
TEST_DIR="/tmp/viaticum-test-$$"
BINARY="${BINARY:-viaticum}"
PORT_BASE=$(( 21000 + (RANDOM % 400) * 100 ))
DR_ROUGH_SECS=300
HOLDERS=(1 2 3 4)

PASS=0; FAIL=0; ROUGH=0
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
        X|Y) echo "$TEST_DIR/$1" ;;
        *) echo "$TEST_DIR/node-$(printf '%02d' "$1")" ;;
    esac
}
node_log() { echo "$TEST_DIR/logs/node-$(printf '%02d' "$1").log"; }

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

# write_config IDX PORT: web API on, no disk reserve, fixed listen port (a restart keeps the
# address unless the scenario changes it), IPFS bootstrap off.
write_config() {
    cat > "$(node_dir "$1")/config.toml" << CFGEOF
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
[network]
listen_port = $2
kademlia_disable_ipfs_bootstrap = true
CFGEOF
}

# start_daemon IDX SCALE [RUST_LOG]: logs are appended across restarts.
start_daemon() {
    local idx="$1" scale="$2" filter="${3:-info}"
    mkdir -p "$(node_dir "$idx")/files"
    RUST_LOG="$filter" "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$scale" --watch-dir "$(node_dir "$idx")/files" \
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

# run_dr LABEL DATA_DIR PHRASE [args...]: the whole output (stdout + stderr, incl. tracing)
# goes to $TEST_DIR/node-00.dr<LABEL>.log. Sets DR_RC, DR_LOG, DR_ERRLINE, FILES_N, DR_WALL.
run_dr() {
    local label="$1" dir="$2" phrase="$3"; shift 3
    DR_LOG="$TEST_DIR/node-00.dr${label}.log"
    local t0; t0=$(date +%s)
    set +e
    RUST_LOG=info timeout 900 "$BINARY" --data-dir "$dir" dr --mnemonic "$phrase" "$@" \
        > "$DR_LOG" 2>&1
    DR_RC=$?
    set -e
    DR_WALL=$(( $(date +%s) - t0 ))
    DR_ERRLINE=$(sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG" | grep -a '^error:' | tail -1 || true)
    FILES_N=$(grep -a "^  Files:" "$DR_LOG" | grep -oE '[0-9]+' | tail -1 || true)
    echo "    dr[$label] exit=$DR_RC wall=${DR_WALL}s log=$DR_LOG"
    sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG" | grep -avE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' \
        | sed 's/^/    | /' || true
    local via_hints via_kad
    via_hints=$(grep -ac "authenticated pointer holder (via hints)" "$DR_LOG" || true)
    via_kad=$(grep -ac "Kademlia get_closest_peers fallback" "$DR_LOG" || true)
    echo "    DR wall time: ${DR_WALL}s (holders via hints: ${via_hints}, Kademlia fallback: ${via_kad})"
    if [ "$DR_RC" -eq 0 ] && [ "$DR_WALL" -gt "$DR_ROUGH_SECS" ]; then
        echo "  ROUGH: DR[$label] took ${DR_WALL}s > ${DR_ROUGH_SECS}s"
        ROUGH=1
    fi
}

# Epoch seconds of the last "stored SelfPointer entry" line FOR THE OWNER (target = I_00) in
# node IDX's log (0 = none). Every node publishes its own pointer; only the owner's counts.
last_pointer_store_epoch() {
    local ts
    ts=$(plain_log "$1" | grep -a "mailbox: stored SelfPointer entry" | grep -a "target=${I_00:0:16}" \
        | tail -1 | awk '{print $1}' || true)
    [ -n "$ts" ] || { echo 0; return; }
    date -d "$ts" +%s 2>/dev/null || echo 0
}

sum_symbols() {
    local blk="$1" t=0 i
    for i in "${HOLDERS[@]}"; do t=$(( t + $(block_symbols_on "$i" "$blk") )); done
    echo "$t"
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"; exit 1; }
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum DR test (${NUM_NODES} nodes, ports from $PORT_BASE)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"
mkdir -p "$TEST_DIR/logs"

# ── STEP 1: SETUP, BACKUP OF THREE FILES ─────────────────────────
echo ""
echo "=== Step 1: plain init everywhere; node-00 backs up f1, f2, f3 ==="
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > "$TEST_DIR/logs/init-$i.out" 2>&1
    write_config "$i" $((PORT_BASE + i))
done
I_00=$(awk '/^Public key:/ {print $3}' "$TEST_DIR/logs/init-0.out")
D_OLD=$(awk '/^Device ID:/ {print $3}' "$TEST_DIR/logs/init-0.out")
M=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-0.out" | tail -1 | sed 's/^ *//')
M_01=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-1.out" | tail -1 | sed 's/^ *//')
if [ ${#I_00} -eq 64 ] && [ ${#D_OLD} -eq 64 ] && [ "$(echo "$M" | wc -w)" -eq 24 ] \
    && [ "$(echo "$M_01" | wc -w)" -eq 24 ]; then
    pass "plain init: node-00 identity ${I_00:0:16}…, device ${D_OLD:0:16}…, phrase captured"
else
    fail "init output not parsed (I='$I_00' D='$D_OLD')"; exit 1
fi

start_daemon 0 "$TIME_SCALE"
wait_daemon 0 || { fail "node-00 daemon not responding"; exit 1; }
# Step 2, first half: before the first push tick (≥ 60 s away) nothing is published.
PUB0=$(status_num 0 dr_pointer_published_at)
if [ "$PUB0" = "0" ] && run_cli_q 0 status | grep -q "DR:.*NOT READY"; then
    pass "fresh node: dr_pointer_published_at == 0, status says 'DR: NOT READY'"
else
    fail "fresh node: published_at='$PUB0', status DR line: $(run_cli_q 0 status | grep 'DR:' || echo none)"
fi
ADDR_00=$(get_addr 0)
[ -n "$ADDR_00" ] || { fail "cannot get node-00 address"; exit 1; }

for i in "${HOLDERS[@]}"; do start_daemon "$i" "$TIME_SCALE"; done
for i in "${HOLDERS[@]}"; do
    wait_daemon "$i" || { fail "node-0$i not responding"; exit 1; }
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
if wait_auth_peers 0 4 60; then
    pass "star connect: node-00 has $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: node-00 has $(status_num 0 peer_count_authenticated)/4 peers"
fi

FILES_DIR="$(node_dir 0)/files"
declare -A HASH SIZE_KIB BLOCK
SIZE_KIB[f1]=1024; SIZE_KIB[f2]=8; SIZE_KIB[f3]=256
for f in f1 f2 f3; do
    # Created outside the watch dir and moved in: one file per block, never a pack.
    dd if=/dev/urandom of="$TEST_DIR/$f.bin" bs=1024 count="${SIZE_KIB[$f]}" 2>/dev/null
    HASH[$f]=$(content_hash "$TEST_DIR/$f.bin")
    mv "$TEST_DIR/$f.bin" "$FILES_DIR/$f.bin"
    if wait_file_restorable 0 "$FILES_DIR/$f.bin" 180; then
        BLOCK[$f]=$(file_block_hex 0 "$FILES_DIR/$f.bin")
        pass "$f (${SIZE_KIB[$f]} KiB) restorable per owner, block ${BLOCK[$f]:0:16}.."
    else
        fail "$f not restorable per owner after 180 s"; exit 1
    fi
done
if [ -n "${BLOCK[f1]}" ] && [ -n "${BLOCK[f2]}" ] && [ -n "${BLOCK[f3]}" ] \
    && [ "${BLOCK[f1]}" != "${BLOCK[f2]}" ] && [ "${BLOCK[f1]}" != "${BLOCK[f3]}" ] \
    && [ "${BLOCK[f2]}" != "${BLOCK[f3]}" ]; then
    pass "the three files sit on three different blocks"
else
    fail "setup: blocks not pairwise different (f1=${BLOCK[f1]:0:16} f2=${BLOCK[f2]:0:16} f3=${BLOCK[f3]:0:16}): the delete oracle would be blind"
    exit 1
fi
JOURNAL_FILES=3

# ── STEP 2: DR READINESS IN STATUS ───────────────────────────────
echo ""
echo "=== Step 2: status says DR-ready only after a postman accepted the pointer (dr-i9) ==="
READY=0
for _ in $(seq 1 60); do
    if [ "$(status_num 0 dr_pointer_files)" -eq 3 ] && [ "$(status_num 0 dr_pointer_acks)" -ge 1 ]; then
        READY=1; break
    fi
    sleep 5
done
PUB_AT=$(status_num 0 dr_pointer_published_at)
L_OWNER=$(api_get 0 /api/status | jq -r '.catalog_lineage // empty')
if [ "$READY" -eq 1 ]; then
    pass "status: pointer with 3 files accepted by $(status_num 0 dr_pointer_acks) postman(s) at $PUB_AT"
    run_cli_q 0 status | grep "DR:" | sed 's/^/    | /' || true
else
    fail "status never reported a pointer with 3 files and ≥ 1 ack (files=$(status_num 0 dr_pointer_files) acks=$(status_num 0 dr_pointer_acks))"
fi
POSTMEN_OK=0
for i in "${HOLDERS[@]}"; do
    e=$(last_pointer_store_epoch "$i")
    if [ "$PUB_AT" -gt 0 ] && [ "$e" -ge "$PUB_AT" ]; then POSTMEN_OK=$((POSTMEN_OK + 1)); fi
done
if [ "$POSTMEN_OK" -ge 1 ]; then
    pass "$POSTMEN_OK postman(s) logged storing the owner's SelfPointer (target=${I_00:0:16}) at/after the publication"
else
    fail "no postman logged storing the owner's SelfPointer (target=${I_00:0:16}) at/after $PUB_AT"
fi

# ── STEP 3: MACHINE LOST; TYPO INTO A FOREIGN FOLDER ─────────────
echo ""
echo "=== Step 3: ADVERSARIAL node-00 lost; typo of M into a folder with a foreign key (dr-i3) ==="
stop_daemon 0
OLD="$(node_dir 0)"
cp "$(node_log 0)" "$TEST_DIR/logs/node-00.pre-dr.log"
X_DIR=$(node_dir X); mkdir -p "$X_DIR"
run_cli X init > "$TEST_DIR/logs/init-X.out" 2>&1
M_X=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-X.out" | tail -1 | sed 's/^ *//')
X_KEY=$(content_hash "$X_DIR/identity.key")
TYPO=$(echo "$M" | awk '{ $5 = "zzzz"; print }')
run_dr 3 "$X_DIR" "$TYPO" --peer "$(get_addr 1)"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "recovery phrase"; then
    pass "typo refused: exit $DR_RC, '$DR_ERRLINE'"
else
    fail "typo not refused (exit $DR_RC, '$DR_ERRLINE')"
fi
if [ "$(content_hash "$X_DIR/identity.key")" = "$X_KEY" ]; then
    pass "X/identity.key unchanged"
else
    fail "X/identity.key changed by a refused DR"
fi

# ── STEP 3a: THE SEED MOVES ──────────────────────────────────────
echo ""
echo "=== Step 3a: ADVERSARIAL the seed node-01 changes its address (dr-i18) ==="
ADDR_01_OLD=$(get_addr 1)
stop_daemon 1
write_config 1 $((PORT_BASE + 50))
start_daemon 1 "$TIME_SCALE"
wait_daemon 1 || { fail "node-01 did not restart"; exit 1; }
ADDR_01=$(get_addr 1)
if [ -n "$ADDR_01" ] && [ "$ADDR_01" != "$ADDR_01_OLD" ] && wait_auth_peers 1 1 90; then
    pass "node-01 moved: $ADDR_01_OLD -> $ADDR_01, authenticated with $(status_num 1 peer_count_authenticated) peer(s)"
else
    fail "node-01 move: old='$ADDR_01_OLD' new='$ADDR_01' auth=$(status_num 1 peer_count_authenticated)"
fi
DEV01=$(api_get 1 /api/status | jq -r '.device_id')

# ── STEP 4: FOREIGN PHRASE, THEN THE RIGHT ONE, INTO Y ────────────
echo ""
echo "=== Step 4: ADVERSARIAL empty folder Y: foreign phrase, then M (dr-i4, dr-i2) ==="
Y_DIR=$(node_dir Y); mkdir -p "$Y_DIR"
run_dr 4a "$Y_DIR" "$M_X" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "no catalog found" && [ ! -e "$Y_DIR/identity.key" ]; then
    pass "M_X into Y: exit $DR_RC 'no catalog found', no identity.key"
else
    fail "M_X into Y: exit $DR_RC '$DR_ERRLINE', Y: $(ls "$Y_DIR" | tr '\n' ' ')"
fi
run_dr 4b "$Y_DIR" "$M" --peer "$ADDR_01"
GOT_I=$(awk '/^Identity restored:/ {print $3}' "$DR_LOG")
if [ "$DR_RC" -eq 0 ] && [ "$GOT_I" = "$I_00" ] && [ "${FILES_N:-0}" -eq "$JOURNAL_FILES" ]; then
    pass "M into Y: exit 0, identity == init's, Files == $FILES_N"
else
    fail "M into Y: exit $DR_RC identity=${GOT_I:0:16} Files=${FILES_N:-none} ('$DR_ERRLINE')"
fi

# ── STEP 5: DR INTO THE OLD FOLDER, TWICE; INTO A LIVE NODE ───────
echo ""
echo "=== Step 5: ADVERSARIAL DR into the old node's folder twice, then into a live node (dr-i5) ==="
H0=$(content_hash "$OLD/db.redb")
KEY0=$(content_hash "$OLD/identity.key")
run_dr 5a "$OLD" "$M" --peer "$ADDR_01"
if [ "$DR_RC" -eq 0 ] && [ -f "$OLD/db.redb.dr-bak" ] && [ "$(content_hash "$OLD/db.redb.dr-bak")" = "$H0" ]; then
    pass "DR into OLD: exit 0, db.redb.dr-bak has the old DB's hash"
else
    fail "DR into OLD: exit $DR_RC, dr-bak: $(ls "$OLD" | grep dr-bak | tr '\n' ' ')"
fi
if [ "$(content_hash "$OLD/identity.key")" = "$KEY0" ]; then
    pass "OLD/identity.key untouched (existing key kept, its random device id too)"
else
    fail "OLD/identity.key changed"
fi
run_dr 5b "$OLD" "$M" --peer "$ADDR_01"
if [ "$DR_RC" -eq 0 ] && [ "$(content_hash "$OLD/db.redb.dr-bak")" = "$H0" ] && [ -f "$OLD/db.redb.dr-bak.1" ]; then
    pass "second DR: .dr-bak still == H0, .dr-bak.1 exists"
else
    fail "second DR: exit $DR_RC, $(ls "$OLD" | grep dr-bak | tr '\n' ' ')"
fi
# Live half.
N1_READY=0
for _ in $(seq 1 40); do
    [ "$(status_num 1 dr_pointer_acks)" -ge 1 ] && { N1_READY=1; break; }
    sleep 3
done
if [ "$N1_READY" -eq 1 ]; then
    pass "precondition: node-01 has an accepted pointer (a DR that passed the lock would commit)"
else
    fail "precondition: node-01 has no accepted pointer after 120 s: the live-half check would be blind"
fi
AUTH_02_BEFORE=$(status_num 2 peer_count_authenticated)
run_dr 5c "$(node_dir 1)" "$M_01" --peer "$(get_addr 2)"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "in use"; then
    pass "DR into live node-01's folder refused: 'in use'"
else
    fail "DR into live node-01's folder: exit $DR_RC '$DR_ERRLINE'"
fi
if run_cli_q 1 status | grep -q "identity:" && [ "$(status_num 2 peer_count_authenticated)" -eq "$AUTH_02_BEFORE" ] \
    && [ -z "$(ls "$(node_dir 1)" | grep dr-bak || true)" ]; then
    pass "node-01 still answers, node-02 still counts $AUTH_02_BEFORE authenticated, no .dr-bak in node-01"
else
    fail "live node disturbed: node-02 auth $AUTH_02_BEFORE -> $(status_num 2 peer_count_authenticated), node-01 files: $(ls "$(node_dir 1)" | tr '\n' ' ')"
fi

# ── STEP 6: THE REAL RECOVERY ON A WIPED MACHINE ─────────────────
echo ""
echo "=== Step 6: machine wiped, DR, daemon on a new port; restore from the network (dr-i1, dr-i11, dr-i18, dr-i22) ==="
assert_delete_window "$TIME_SCALE"
rm -rf "$X_DIR" "$Y_DIR"
rm -rf "${OLD:?}"/* "$OLD"/.[!.]* 2>/dev/null || true
for f in f1 f2 f3; do [ -e "$FILES_DIR/$f.bin" ] && fail "wipe left $f in place"; done
run_dr 6 "$OLD" "$M" --peer "$ADDR_01"
if [ "$DR_RC" -eq 0 ] && [ "${FILES_N:-0}" -eq "$JOURNAL_FILES" ]; then
    pass "DR on the wiped machine: Files == $FILES_N (journal $JOURNAL_FILES)"
else
    fail "DR on the wiped machine: exit $DR_RC Files=${FILES_N:-0} ('$DR_ERRLINE')"
fi
CAT_LINE=$(grep -a "^  Catalog:" "$DR_LOG" | tail -1 || true)
L_NEW=$(echo "$CAT_LINE" | awk '{print $2}')
L_SRC=$(echo "$CAT_LINE" | grep -oE 'restored from [0-9a-f]{32}' | awk '{print $3}' || true)
if [ ${#L_NEW} -eq 32 ] && [ "$L_NEW" != "$L_SRC" ] && [ "$L_SRC" = "$L_OWNER" ]; then
    pass "DR started a NEW history ${L_NEW:0:8}… restored from the owner's ${L_SRC:0:8}…"
else
    fail "DR history: '$CAT_LINE' (owner history '$L_OWNER')"
fi
if grep -aq "not re-protected" "$DR_LOG"; then
    pass "DR output says the files are not re-protected until they are back"
else
    fail "DR output lacks the 'not re-protected' paragraph"
fi
write_config 0 $((PORT_BASE + 60))
for i in 2 3 4; do stop_daemon "$i"; done
L01=$(log_line_count 1)
start_daemon 0 "$TIME_SCALE"
wait_daemon 0 || { fail "post-DR daemon did not start"; exit 1; }
if [ -z "$(get_addr 0)" ]; then
    fail "post-DR daemon has no network (no listen address): waits R1-b (own device not enrolled in the restored cluster registry)"
fi
DEV00_NEW=$(api_get 0 /api/status | jq -r '.device_id')
if [ "$(api_get 0 /api/status | jq -r '.catalog_lineage')" = "$L_NEW" ]; then
    pass "status .catalog_lineage of the recovered node == the history DR printed"
else
    fail "status .catalog_lineage '$(api_get 0 /api/status | jq -r '.catalog_lineage')' != DR's '$L_NEW'"
fi
SEED_AUTH=""
for _ in $(seq 1 60); do
    SEED_AUTH=$(api_get 0 /api/status | jq -r --arg d "$DEV01" '.peers[] | select(.identity_hex == $d) | .link' 2>/dev/null || true)
    [ "$SEED_AUTH" = "auth" ] && break
    sleep 1
done
if [ "$SEED_AUTH" = "auth" ]; then
    pass "recovered node reached the moved seed node-01 ($DEV01) on its own (nodes 02-04 off)"
else
    fail "recovered node: node-01 link '${SEED_AUTH:-absent}' after 60 s (only the live-learned address is current)"
fi
if [ -n "$DEV00_NEW" ] && [ "$DEV00_NEW" != "${D_OLD:0:16}" ] \
    && log_since 1 "$L01" | grep -a "peer authenticated" | grep -aq "device_id=$DEV00_NEW"; then
    pass "node-01 logged the NEW device $DEV00_NEW (≠ lost ${D_OLD:0:16}) authenticated after the daemon start (dr-i22)"
else
    fail "node-01 has no new 'peer authenticated' line for device '${DEV00_NEW}' (lost ${D_OLD:0:16}) — dr-i22, mechanism R1-b of line C"
fi
for i in 2 3 4; do start_daemon "$i" "$TIME_SCALE"; done
if wait_auth_peers 0 3 120; then
    pass "recovered node authenticated with $(status_num 0 peer_count_authenticated) peers"
else
    fail "recovered node has $(status_num 0 peer_count_authenticated) authenticated peers after 120 s"
fi
FWS=$(status_num 0 files_without_source)
if [ "$FWS" -eq 3 ]; then pass "files_without_source == 3 after DR"; else fail "files_without_source == $FWS after DR (want 3)"; fi
declare -A STAGED
for f in f1 f2 f3; do
    before=$(restore_responses_for "${BLOCK[$f]}" "${HOLDERS[@]}")
    if restore_from_network 0 "$FILES_DIR/$f.bin" "${HASH[$f]}" 180; then
        pass "restore $f: $RESTORE_MSG"
        STAGED[$f]="${RESTORE_MSG##* at }"
    else
        fail "restore $f: $RESTORE_MSG"
    fi
    served=$(( $(restore_responses_for "${BLOCK[$f]}" "${HOLDERS[@]}") - before ))
    if [ "$served" -ge 1 ]; then pass "holders logged $served RestoreResponse(s) for $f"
    else fail "no holder logged a RestoreResponse for $f (${BLOCK[$f]:0:16})"; fi
done
FWS=$(status_num 0 files_without_source)
if [ "$FWS" -eq 3 ]; then pass "after restore to staging files_without_source is still 3"
else fail "after restore to staging files_without_source == $FWS (staging is not 'back in place')"; fi

# ── STEP 7: PUT f1, f2 BACK ──────────────────────────────────────
echo ""
echo "=== Step 7: f1, f2 back at their original paths (dr-i11) ==="
for f in f1 f2; do
    if [ -n "${STAGED[$f]:-}" ]; then mv "${STAGED[$f]}" "$FILES_DIR/$f.bin"; fi
done
OK7=0
for _ in $(seq 1 60); do
    [ "$(status_num 0 files_without_source)" -eq 1 ] && { OK7=1; break; }
    sleep 1
done
if [ "$OK7" -eq 1 ]; then pass "files_without_source == 1 after putting f1, f2 back"
else fail "files_without_source == $(status_num 0 files_without_source) 60 s after putting f1, f2 back (want 1)"; fi
PUB_NEW=0
for _ in $(seq 1 60); do
    [ "$(status_num 0 dr_pointer_published_at)" -gt 0 ] && { PUB_NEW=1; break; }
    sleep 5
done
if [ "$PUB_NEW" -eq 1 ] && plain_log 0 | grep -a "SelfPointer published via mailbox" | grep -aq "lineage=$L_NEW" \
    && [ "$(api_get 0 /api/status | jq -r '.catalog_lineage')" = "$L_NEW" ]; then
    pass "the recovered node's first accepted pointer carries its new history ${L_NEW:0:8}…"
else
    fail "recovered node: published=$PUB_NEW, no pointer with lineage=$L_NEW (status lineage '$(api_get 0 /api/status | jq -r '.catalog_lineage')')"
fi

# ── STEP 8: DELETE f1 FOR REAL; f3 (MISSING) MUST SURVIVE ─────────
echo ""
echo "=== Step 8: dr-i10 + dr-i19: missing f3 is not deleted, deleted f1 is (time_scale $TIME_SCALE_DELETE) ==="
for i in 0 1 2 3 4; do stop_daemon "$i"; done
L00=$(log_line_count 0)
start_daemon 0 "$TIME_SCALE_DELETE" "info,viaticum::daemon::scheduler=debug"
for i in "${HOLDERS[@]}"; do start_daemon "$i" "$TIME_SCALE_DELETE"; done
for i in 0 "${HOLDERS[@]}"; do wait_daemon "$i" || fail "node-0$i did not restart"; done
wait_auth_peers 0 3 90 || fail "after restart node-00 has $(status_num 0 peer_count_authenticated) peers"
B1_ON=$(sum_symbols "${BLOCK[f1]}")
declare -A B3_ON
for i in "${HOLDERS[@]}"; do B3_ON[$i]=$(block_symbols_on "$i" "${BLOCK[f3]}"); done
B3_TOTAL=$(sum_symbols "${BLOCK[f3]}")
echo "  BLOCK1 symbols on holders: $B1_ON; BLOCK3: $B3_TOTAL"
if [ "$B1_ON" -eq 0 ] || [ "$B3_TOTAL" -eq 0 ]; then
    fail "holders hold nothing of BLOCK1/BLOCK3: the check would be blind"
fi
MARKS3_BEFORE=$(delete_marks_for "${BLOCK[f3]}" "${HOLDERS[@]}")
MARKS1_BEFORE=$(delete_marks_for "${BLOCK[f1]}" "${HOLDERS[@]}")
rm "$FILES_DIR/f1.bin"
T8=$(date +%s)
DEADLINE=370
POSITIVE=0; NEGATIVE=""; POS_PASS=0
while [ $(( $(date +%s) - T8 )) -lt "$DEADLINE" ]; do
    if [ "$(delete_marks_for "${BLOCK[f3]}" "${HOLDERS[@]}")" -gt "$MARKS3_BEFORE" ]; then
        NEGATIVE="a holder marked BLOCK3 (missing f3) for deletion"; break
    fi
    if log_since 0 "$L00" | grep -a "DeleteMsg published via mailbox" | grep -aq "${BLOCK[f3]:0:16}"; then
        NEGATIVE="node-00 published a Delete for BLOCK3"; break
    fi
    for i in "${HOLDERS[@]}"; do
        if [ "$(block_symbols_on "$i" "${BLOCK[f3]}")" -lt "${B3_ON[$i]}" ]; then
            NEGATIVE="BLOCK3 symbols on node-0$i dropped ${B3_ON[$i]} -> $(block_symbols_on "$i" "${BLOCK[f3]}")"
            break
        fi
    done
    [ -n "$NEGATIVE" ] && break
    if [ "$POS_PASS" -eq 0 ] && log_since 0 "$L00" | grep -a "mailbox PosResponse resolved" \
        | grep -a "${BLOCK[f2]:0:16}" | grep -aq "outcome=Pass"; then
        POS_PASS=1
        echo "  PoS for f2's block answered by a holder and resolved Pass ($(( $(date +%s) - T8 ))s)"
    fi
    if [ "$POSITIVE" -eq 0 ] && [ "$(delete_marks_for "${BLOCK[f1]}" "${HOLDERS[@]}")" -gt "$MARKS1_BEFORE" ]; then
        POSITIVE=$(( $(date +%s) - T8 ))
        echo "  positive control: a holder marked BLOCK1 for deletion after ${POSITIVE}s"
        # A wrong delete of BLOCK3 would have gone out no later than f1's: 20 s grace.
        DEADLINE=$(( POSITIVE + 20 ))
    fi
    sleep 5
done
if [ -n "$NEGATIVE" ]; then
    fail "dr-i10: $NEGATIVE"
else
    pass "dr-i10: missing f3 was not deleted (no mark, no Delete, symbols kept: $(sum_symbols "${BLOCK[f3]}"))"
fi
if [ "$POSITIVE" -gt 0 ]; then
    pass "dr-i19 positive control: the friend's deletion of f1 reached the holders (${POSITIVE}s)"
else
    fail "dr-i19: no holder marked BLOCK1 (deleted f1) within the deadline — the time scale, the oracle or the ownership of f1 is broken"
fi
if [ "$POS_PASS" -eq 0 ] && log_since 0 "$L00" | grep -a "mailbox PosResponse resolved" \
    | grep -a "${BLOCK[f2]:0:16}" | grep -aq "outcome=Pass"; then
    POS_PASS=1
fi
if [ "$POS_PASS" -eq 1 ]; then
    pass "dr-i11: a holder answers PoS for f2 again once it is back in place"
else
    fail "dr-i11: no PoS response for f2's block resolved Pass at node-00 within the deadline"
fi

# ── STEP 9: SKELETON (CROWN-1 C4) ────────────────────────────────
echo ""
echo "=== Step 9: dr-i8 (mail by master after DR) — skeleton, filled by CROWN-1 C4 ==="
info "not checked in this slice: needs CROWN-1 C4"

# ── STEP 10: f3 BACK ─────────────────────────────────────────────
echo ""
echo "=== Step 10: f3 back at its path (dr-i11) ==="
if [ -n "${STAGED[f3]:-}" ]; then mv "${STAGED[f3]}" "$FILES_DIR/f3.bin"; fi
OK10=0
for _ in $(seq 1 60); do
    [ "$(status_num 0 files_without_source)" -eq 0 ] && { OK10=1; break; }
    sleep 1
done
if [ "$OK10" -eq 1 ]; then pass "files_without_source == 0 (f1 deleted = not live, f2 and f3 in place)"
else fail "files_without_source == $(status_num 0 files_without_source) after putting f3 back (want 0)"; fi

# ── RESULTS ─────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed$([ "$ROUGH" -eq 1 ] && echo ', ROUGH (slow DR)')"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)" 2>/dev/null || true
fi
echo "Logs: $TEST_DIR/logs/, DR outputs: $TEST_DIR/node-00.dr*.log"
[ "$FAIL" -eq 0 ] || exit 1
[ "$ROUGH" -eq 0 ] || exit 3
exit 0
