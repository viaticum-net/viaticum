#!/bin/bash
# Viaticum watch-folder E2E, slice R1-c1: what enters the backup when a friend
# watches a whole "home".
#
# Scenario:     5 independent owners. node-00 is a friend who watches a whole
#               "home" ($T/home) with the node's data dir INSIDE it and NOT
#               hidden ($T/home/vdata — the NAS layout /volume1/viaticum under a
#               watched /volume1). Before its start the home holds a document, a
#               hidden directory, a symlink loop (docs/loop -> ..) and a symlink to
#               a directory outside the home. node-01..04 hold (they watch
#               <data-dir>/files, the layout of every other E2E). While node-00
#               runs, holders write symbols into its data dir, its own daemon
#               writes SystemState blobs there, and a hidden file changes.
# Intent:       backup-i13, backup-i14, backup-i15 (R1-c1); backup-i1 (control).
#               private/intent/backup.md
# Proves:       node-00's catalog never gets a path inside its data dir — neither
#               what only the startup scan could bring (identity.key, config.toml)
#               nor what only live events could bring (holdings/<block>/<esi>.bin
#               written by a friend's upload, checked as present on node-00's disk
#               first) — while control files of the same windows are backed up
#               (restorable, >= k_eff symbols on OTHER nodes' disks). WatchAdmin
#               refuses a data dir and a folder inside holdings with 400 and a
#               reason naming Viaticum's own data. A file in a hidden directory,
#               present at the start and changed while the daemon runs, is not in
#               the catalog. The startup scan finishes within 60 s despite the
#               loop; a.bin is in the catalog exactly once; nothing under the loop
#               or under the symlink to the outside directory is. SIGTERM ends
#               every node with 0, no panic.
# Adversarial:  holders write into the friend's data dir during step 2 (a live
#               event source the owner does not control); symlink loop and a
#               symlink to a foreign directory present at the start (step 4).
# Cannot close: proof of absence on another node (steps 2-4 read the owner's own
#               catalog: "nothing left the node" has no cross-node observable —
#               a path never cataloged is never offered); files the daemon writes
#               continuously (db.redb, daemon.log) under the trailing debounce may
#               never flush even without the fix, so they are not the live-event
#               probe (holdings are); a data dir that appears or moves inside the
#               folder at runtime (the subtree scan of R1-c2); another user's data
#               dir; macOS/Windows paths (unit tests only). R1-c2/c3 steps of this
#               scenario (directory moved in, inotify overflow, notify not created,
#               watch limit, folder first seen at restart, mounts, restore of
#               p2/u1) are not written yet — see R1-c2 / R1-c3 in
#               private/beta-planning/tasks/r1c_watcher.md §0.3.
# Caveat:       until R1-e2 is merged, the worker re-picks a block that cannot
#               reach its target every tick ('no new candidates'), starving the
#               blocks behind it. With 4 holders an importance-1.0 block never
#               reaches its target: documents (.txt) and SystemState blocks.
#               So the control files are .bin (importance 0.05, reach k_eff and
#               leave the queue) and TIME_SCALE is 100, not the 300 of the spec
#               (first SystemState block at 21600/ts = 216 s). A FAIL of steps
#               1-3 with many 'no new candidates' lines is that bug, not
#               backup-i13/i14 — the step prints the counters.
# Steps:        0. init 5 (node-00 data dir $T/home/vdata, [[watch]] $T/home);
#                  holders connect to node-00 → node-00 sees 4 authenticated
#                  ≤ 90 s — check: wait_auth_peers
#               1. docs/a.bin (startup scan) restorable ≤ 180 s and >= k_eff of
#                  its symbols on node-01..04 disks (backup-i1 control) — check:
#                  wait_file_restorable, block_symbols_on
#               2. node-01 writes h1.jpg; setup: >= 1 of its symbols lands in
#                  $T/home/vdata/holdings (live events in the data dir happened,
#                  else FAIL setup); then docs/b.bin → b.bin restorable + >= k_eff
#                  on OTHER disks; catalog: no path under $T/home/vdata/ (2a:
#                  identity.key/config.toml = scan path; 2b: holdings/ = live
#                  path); log: `data directory excluded from backup
#                  dir=$T/home/vdata` (backup-i13) — check: block_symbols_on, jq, has
#               2c. POST /api/watches {path: node-01's data dir} and {path: its
#                  holdings/} on node-00 → both 400, bodies name "Viaticum data
#                  directory" / "own storage"; /api/watches count unchanged
#                  (backup-i13) — check: api_post code + body
#               3. write .hidden/live.txt twice, then docs/c.bin → c.bin
#                  restorable + >= k_eff on OTHER disks; no catalog path contains
#                  /.hidden/ (neither pre.txt from the scan nor live.txt)
#                  (backup-i14) — check: wait_file_restorable, block_symbols_on, has
#               4. (loop docs/loop -> .. and z -> $T/outside were there before
#                  the start) `initial/periodic scan complete` ≤ 60 s after the
#                  start; exactly one catalog path ends in /docs/a.bin; none under
#                  docs/loop/ or z/ (backup-i15) — check: events, jq, has
#               15. SIGTERM all → exit 0; no panic in any log (network-i1) —
#                  check: wait_pid_exit, grep
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_watch_test.sh
#   (or: private/testing/run_e2e.sh watch)

set -euo pipefail
# Decimal point in awk/printf output (events prints seconds), whatever the server locale.
export LC_ALL=C

NUM_NODES=5
TIME_SCALE=100
T="/tmp/viaticum-watch-$$"
BINARY="${BINARY:-viaticum}"
HOME_DIR="$T/home"
DATA_00="$HOME_DIR/vdata"
OUTSIDE="$T/outside"

PASS=0; FAIL=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

node_dir() {
    if [ "$1" -eq 0 ]; then echo "$DATA_00"; else echo "$T/node-$(printf '%02d' "$1")"; fi
}
node_log() { echo "$(node_dir "$1")/daemon.log"; }
node_name() { echo "node-$(printf '%02d' "$1")"; }

run_cli() {
    local idx="$1"; shift
    "$BINARY" --data-dir "$(node_dir "$idx")" "$@"
}
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

# has TEXT PATTERN: does TEXT contain PATTERN (fixed string)? No pipe on
# purpose: with `set -o pipefail`, `echo "$big" | grep -q` fails with SIGPIPE
# on the writer when grep exits at the first match — a "not found" that turns
# every "must NOT contain" check into a false PASS.
has() { grep -qF -- "$2" <<< "$1"; }

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
fi
if [ ! -x "$BINARY" ] && ! command -v "$BINARY" &>/dev/null; then
    echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"
    exit 1
fi
BINARY="$(realpath "$(command -v "$BINARY" || echo "$BINARY")")"

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

declare -A DPID

start_node() {
    local i="$1" dir; dir=$(node_dir "$i")
    if [ "$i" -eq 0 ]; then
        # The friend's folders come from config.toml ([[watch]] $HOME_DIR).
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            >> "$(node_log "$i")" 2>&1 &
    else
        mkdir -p "$dir/files"
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            --watch-dir "$dir/files" >> "$(node_log "$i")" 2>&1 &
    fi
    DPID[$i]=$!
}

wait_daemon() {
    local idx="$1"
    for _ in $(seq 1 120); do
        has "$(run_cli_q "$idx" status)" "identity:" && return 0
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
    [ -n "$raw" ] && echo "$raw" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    local i p
    for i in "${!DPID[@]}"; do kill -TERM "${DPID[$i]}" 2>/dev/null || true; done
    sleep 1
    for i in "${!DPID[@]}"; do
        p="${DPID[$i]}"; kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
    done
    echo "  Test dir: $T"
}
trap cleanup EXIT

# All catalog paths of node-00, one per line ("" when the API is unreachable).
catalog_00() { api_get 0 /api/files | jq -r '.[].path' 2>/dev/null || true; }

# check_on_others STEP FILE: FILE restorable per node-00 and >= k_eff of its
# symbols on the disks of node-01..04.
check_on_others() {
    local step="$1" file="$2" target block on_disk=0 n i
    if wait_file_restorable 0 "$file" 180; then
        target=$(file_field 0 "$file" '.effective_status.target')
        pass "$step: $(basename "$file") restorable per node-00 (k_eff=$target)"
    else
        fail "$step: $(basename "$file") not restorable after 180s"
        info "$step: 'no new candidates' lines on node-00: $(log_since 0 0 | grep -c 'no new candidates' || true); SystemState blocks published: $(log_since 0 0 | grep -c 'system_state push: base published' || true) (R1-e2 starvation, see Caveat)"
        return
    fi
    block=$(file_block_hex 0 "$file")
    for i in 1 2 3 4; do
        n=$(block_symbols_on "$i" "$block")
        on_disk=$((on_disk + n))
    done
    if [ -n "$block" ] && [ "${target:-0}" -gt 0 ] && [ "$on_disk" -ge "$target" ]; then
        pass "$step: node-01..04 hold $on_disk symbols >= k_eff $target of $(basename "$file")"
    else
        fail "$step: node-01..04 hold $on_disk symbols of $(basename "$file"), need k_eff=${target:-?} (block=${block:-none})"
    fi
}

echo "============================================================"
echo "  Viaticum Watch Test, R1-c1 (${NUM_NODES} nodes, time_scale ${TIME_SCALE})"
echo "  Binary:   $BINARY"
echo "  Test dir: $T"
echo "============================================================"

# ── PHASE 0: SETUP ───────────────────────────────────────────────
echo ""
echo "=== Step 0: setup — node-00 watches $HOME_DIR with its data dir inside ==="
mkdir -p "$HOME_DIR/docs" "$HOME_DIR/.hidden" "$OUTSIDE"
A_TXT="$HOME_DIR/docs/a.bin"
head -c 65536 /dev/urandom > "$A_TXT"
echo "pre" > "$HOME_DIR/.hidden/pre.txt"
ln -s .. "$HOME_DIR/docs/loop"
echo "not the friend's to back up" > "$OUTSIDE/secret.txt"
ln -s "$OUTSIDE" "$HOME_DIR/z"

for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
    {
        echo '[web_api]'
        echo 'enabled = true'
        echo 'bind = "127.0.0.1:0"'
        echo '[storage]'
        echo 'disk_reserve_gb = 0.0'
        if [ "$i" -eq 0 ]; then
            echo '[[watch]]'
            echo "path = \"$HOME_DIR\""
        fi
    } > "$(node_dir "$i")/config.toml"
done

T_BASE=$(date +%s)
start_node 0
for i in $(seq 1 $((NUM_NODES-1))); do start_node "$i"; done
for i in $(seq 0 $((NUM_NODES-1))); do
    wait_daemon "$i" || fail "setup: $(node_name "$i") did not come up"
done
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"
for i in $(seq 1 $((NUM_NODES-1))); do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
if wait_auth_peers 0 4 90; then
    pass "step 0: node-00 sees 4 authenticated peers"
else
    fail "step 0: node-00 auth peers $(status_num 0 peer_count_authenticated)/4 after 90s"
fi

# ── STEP 1: CONTROL — THE STARTUP SCAN BACKS UP THE HOME ─────────
echo ""
echo "=== Step 1: docs/a.bin from the startup scan reaches OTHER disks (backup-i1) ==="
check_on_others "step 1" "$A_TXT"

# ── STEP 2: THE DATA DIR INSIDE THE HOME IS NOT BACKED UP ────────
echo ""
echo "=== Step 2: holders write into node-00's data dir; nothing of it is cataloged (backup-i13) ==="
H1="$(node_dir 1)/files/h1.jpg"
head -c 262144 /dev/urandom > "$H1"
H1_ON_00=0
if wait_file_restorable 1 "$H1" 180; then
    H1_BLOCK=$(file_block_hex 1 "$H1")
    for _ in $(seq 1 60); do
        H1_ON_00=$(block_symbols_on 0 "$H1_BLOCK")
        [ "$H1_ON_00" -ge 1 ] && break
        sleep 1
    done
fi
if [ "$H1_ON_00" -ge 1 ]; then
    pass "step 2 setup: node-00 holds $H1_ON_00 symbols of node-01's h1.jpg in $DATA_00/holdings (live events in the data dir happened)"
else
    fail "step 2 setup: no symbol of node-01's h1.jpg on node-00's disk — the live-event probe did not happen"
fi
SS_BLOBS=$(find "$DATA_00/system_state" -maxdepth 1 -type f -name '*.bin' 2>/dev/null | wc -l || true)
info "step 2: node-00 retained SystemState blobs in its data dir: $SS_BLOBS"
B_TXT="$HOME_DIR/docs/b.bin"
head -c 4096 /dev/urandom > "$B_TXT"
# b.bin is written after the holdings: its window closes after theirs.
check_on_others "step 2" "$B_TXT"
CAT=$(catalog_00)
if ! has "$CAT" "$A_TXT"; then
    fail "step 2: node-00 catalog unreadable or without a.bin (cannot judge absence): $(wc -l <<< "$CAT") lines"
else
    if has "$CAT" "$DATA_00/"; then
        fail "step 2: node-00 catalog has paths inside its data dir:"
        grep -F -- "$DATA_00/" <<< "$CAT" | head -8 | sed 's/^/    | /'
    else
        pass "step 2: no catalog path under $DATA_00/ ($(wc -l <<< "$CAT") paths cataloged)"
    fi
    # 2a: files only the startup scan can bring (written before the start, never live).
    if has "$CAT" "$DATA_00/identity.key" || has "$CAT" "$DATA_00/config.toml"; then
        fail "step 2a: the scan cataloged identity.key/config.toml of the data dir"
    else
        pass "step 2a: identity.key and config.toml of the data dir not cataloged (scan path)"
    fi
    # 2b: files only live events can bring (holdings were empty at the start).
    if has "$CAT" "$DATA_00/holdings/"; then
        fail "step 2b: symbols held for node-01 were cataloged (live path)"
    else
        pass "step 2b: nothing under $DATA_00/holdings/ cataloged (live path)"
    fi
fi
if has "$(grep -F "data directory excluded from backup" <<< "$(log_since 0 0)" || true)" "dir=$DATA_00"; then
    pass "step 2: node-00 log: 'data directory excluded from backup dir=$DATA_00'"
else
    fail "step 2: no 'data directory excluded from backup dir=$DATA_00' in node-00's log"
fi

# ── STEP 2c: WATCHADMIN REFUSES VIATICUM'S OWN STORAGE ───────────
echo ""
echo "=== Step 2c: POST /api/watches for a data dir / its holdings → 400 (backup-i13) ==="
WATCHES_BEFORE=$(api_get 0 /api/watches | jq 'length' 2>/dev/null || echo "?")
for spec in "$(node_dir 1)|Viaticum data directory" "$(node_dir 1)/holdings|own storage"; do
    target="${spec%%|*}"; want="${spec#*|}"
    resp=$(api_post 0 /api/watches "{\"path\":\"$target\"}")
    code="${resp%% *}"; body="${resp#* }"
    if [ "$code" = 400 ] && has "$body" "$want"; then
        pass "step 2c: POST $target → 400, body names '$want'"
    else
        fail "step 2c: POST $target → '$code' body '$body' (want 400 naming '$want')"
    fi
done
WATCHES_AFTER=$(api_get 0 /api/watches | jq 'length' 2>/dev/null || echo "?")
if [ "$WATCHES_BEFORE" = 1 ] && [ "$WATCHES_AFTER" = 1 ]; then
    pass "step 2c: /api/watches still lists 1 folder"
else
    fail "step 2c: /api/watches count $WATCHES_BEFORE → $WATCHES_AFTER (want 1 → 1)"
fi

# ── STEP 3: HIDDEN DIRECTORIES — SCAN AND LIVE ALIKE ─────────────
echo ""
echo "=== Step 3: a file in a hidden dir changes while running; not cataloged (backup-i14) ==="
echo x > "$HOME_DIR/.hidden/live.txt"
echo y >> "$HOME_DIR/.hidden/live.txt"
C_TXT="$HOME_DIR/docs/c.bin"
echo c > "$C_TXT"
check_on_others "step 3" "$C_TXT"
CAT=$(catalog_00)
if ! has "$CAT" "$C_TXT"; then
    fail "step 3: node-00 catalog unreadable or without c.bin (cannot judge absence)"
elif has "$CAT" "/.hidden/"; then
    fail "step 3: hidden paths cataloged:"
    grep -F -- "/.hidden/" <<< "$CAT" | sed 's/^/    | /'
else
    pass "step 3: no catalog path contains /.hidden/ (pre.txt from the scan, live.txt live)"
fi

# ── STEP 4: SYMLINKS TO DIRECTORIES ARE NOT FOLLOWED ─────────────
echo ""
echo "=== Step 4: symlink loop and link outside do not blow up or widen the scan (backup-i15) ==="
SCAN_T=$(events "$(node_log 0)" "initial/periodic scan complete" | head -1 | awk '{print $1}')
if [ -n "$SCAN_T" ] && awk -v t="$SCAN_T" 'BEGIN { exit !(t <= 60) }'; then
    pass "step 4: startup scan complete ${SCAN_T}s after the start (≤ 60 s)"
else
    fail "step 4: no 'initial/periodic scan complete' within 60 s of the start (t=${SCAN_T:-none})"
fi
CAT=$(catalog_00)
N_A=$(grep -c -- "/docs/a.bin\$" <<< "$CAT" || true)
if [ "$N_A" = 1 ]; then
    pass "step 4: exactly one catalog path ends in /docs/a.bin"
else
    fail "step 4: $N_A catalog paths end in /docs/a.bin (want 1)"
fi
if has "$CAT" "$HOME_DIR/docs/loop/"; then
    fail "step 4: paths under the loop $HOME_DIR/docs/loop/ cataloged ($(grep -cF -- "$HOME_DIR/docs/loop/" <<< "$CAT" || true))"
else
    pass "step 4: nothing under $HOME_DIR/docs/loop/ cataloged"
fi
if has "$CAT" "$HOME_DIR/z/" || has "$CAT" "$OUTSIDE/"; then
    fail "step 4: the directory behind symlink z (outside the home) was cataloged"
else
    pass "step 4: nothing behind symlink z -> $OUTSIDE cataloged"
fi

# ── STEP 15: CLEAN STOP OF EVERYONE ──────────────────────────────
echo ""
echo "=== Step 15: SIGTERM all → exit 0, no panic (network-i1) ==="
for i in $(seq 0 $((NUM_NODES-1))); do kill -TERM "${DPID[$i]}" 2>/dev/null || true; done
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_pid_exit "${DPID[$i]}" 30; then
        if [ "$EXIT_RC" = 0 ]; then
            pass "step 15: $(node_name "$i") exit 0"
        else
            fail "step 15: $(node_name "$i") exit $EXIT_RC (want 0)"
        fi
    else
        fail "step 15: $(node_name "$i") still running 30s after SIGTERM"
    fi
done
PANICS=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if grep -qa "panicked" "$(node_log "$i")" 2>/dev/null; then
        fail "step 15: panic in $(node_name "$i") log"
        grep -a "panicked" "$(node_log "$i")" | tail -3 | sed 's/^/    | /'
        PANICS=$((PANICS + 1))
    fi
done
[ "$PANICS" -eq 0 ] && pass "step 15: no panic in any of the $NUM_NODES logs"

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then
    for i in $(seq 0 $((NUM_NODES-1))); do
        echo "=== $(node_name "$i") log (last 10 lines) ==="
        tail -10 "$(node_log "$i")" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
        echo ""
    done
fi
echo "Logs: $DATA_00/daemon.log, $T/node-*/daemon.log"
[ "$FAIL" -eq 0 ]
