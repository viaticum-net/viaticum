#!/bin/bash
# Viaticum DR guard E2E: every wrong way a friend can run `viaticum dr` leaves the data
# folder exactly as it was, and DR never works for an identity other than the phrase's.
# Local processes on one machine (no Docker).
#
# Scenario:     2 processes. node-01 is an independent node (the "network", holds no
#               pointer for A). Folder A: a normal `init` + a short daemon run connected to
#               node-01 (so it has identity.key and db.redb). Folder F: another identity
#               (`init`, never started). The friend now runs `dr` wrongly in every way we
#               know: typo, bad checksum, a foreign phrase into A, a foreign phrase into an
#               empty folder then the right one, a `daemon` after a failed DR, DR into a
#               live node.
# Intent:       dr-i3, dr-i4, dr-i5 (live-daemon half), dr-i12, dr-i23, dr-i26, dr-i28
# Proves:       every refused/failed DR leaves the folder byte-identical (sha256 of every
#               file incl. identity.key and db.redb, full listing); a refused phrase never
#               reaches the network (node-01 logs no new "peer authenticated"); the identity
#               DR works with follows the phrase, never a key left in the folder; a DR that
#               failed on the network (it DID reach node-01, checked in node-01's log)
#               leaves an empty folder with no identity.key; a live daemon survives a DR
#               aimed at its folder (its status answers with its identity, node-01 still
#               counts it authenticated, db.redb keeps its inode, no .dr-bak/.dr-new);
#               `daemon` in a folder left by a failed DR does not start, points to
#               `viaticum dr`, and node-01 sees no new device; Ctrl-C / SIGTERM while DR
#               waits on the network cancels it with a non-zero code and "interrupted",
#               leaving no identity.key, db.redb or drafts.
# Adversarial:  typo (unknown word); valid words with bad checksum; valid foreign phrase
#               into a folder with a key; DR against a running daemon's data dir; stop
#               signals in the network phase (dead seed keeps DR there).
# Cannot close: success paths — .dr-bak after a successful DR (dr-i5, first half), catalog
#               found: they need a published pointer; proven only by local_dr_test steps
#               4-5 of slice B2.2 (spec B2 §0.3.2), here only by unit tests; the crash
#               window inside the commit (dr-i29, unit tests only); two
#               concurrent DRs (unit tests preflight_second_dr_*); filesystems without file
#               locks (unit test of the decision function only); Windows lock semantics;
#               SIGKILL inside the commit renames (unit tests in dr/commit); a signal
#               DURING the commit (milliseconds; the commit is a synchronous fn after the
#               guarded phase — unit test commit_is_a_synchronous_fn).
# Steps:
#  1. setup: node-01 daemon; A = `init` (phrase M_A, identity I_A from stdout), daemon
#     connected to node-01 (node-01 logs A authenticated), stopped; F = `init` (M_F, I_F).
#     Snapshot A. — check: files exist, grep node-01 log
#  2. dr <M_A with word 5 := "zzzz"> into A --peer node-01 → exit≠0, error mentions
#     "recovery phrase" and "word 5"; A unchanged; node-01 logs no new "peer
#     authenticated" (dr-i3) — check: rc, grep, snapshot diff, grep -c node-01 log
#  3. dr "abandon x24" (valid words, bad checksum) into A → exit≠0, error mentions
#     "checksum"; A unchanged (dr-i3) — check: rc, grep, snapshot diff
#  4. ADVERSARIAL dr M_F into A → exit≠0, error mentions "different identity" and the
#     first 16 hex of I_A and of I_F; no "Identity restored:" line; A unchanged; node-01
#     logs no new "peer authenticated" (dr-i4) — check: rc, grep, ! grep, snapshot diff
#  5. empty folder E: dr M_F --peer node-01 → exit≠0 "no catalog found", node-01 logged
#     I_F authenticated (DR reached the network); E is empty (dr-i12); then dr M_A typed
#     in UPPER CASE with extra spaces into E → "Identity restored: <I_A>" (== init
#     stdout), exit≠0 "no catalog found"; E still empty (dr-i4, dr-i12, dr-i28)
#     — check: rc, grep, find E, hex compare, grep -c node-01 log
#  6. `daemon` on E → exits ≠0 within 15 s, stderr mentions "viaticum dr"; E has no
#     identity.key/db.redb; node-01 logs no new "peer authenticated" (dr-i12)
#     — check: wait with deadline, rc, grep, [ ! -e ], grep -c node-01 log
#  7. ADVERSARIAL start A's daemon, connect to node-01, wait until node-01 logs A
#     authenticated again; dr M_A into A → exit≠0, error mentions "in use"; A's `status`
#     still prints I_A; node-01 peer_count_authenticated unchanged (≥1); A/db.redb same
#     inode; no db.redb.dr-bak* / *.dr-new in A; node-01 logs no DR connection (dr-i5, dr-i26)
#     — check: rc, grep "in use", status, status_num 1, stat -c %i, ls
#  8. ADVERSARIAL empty folder G: `dr M_A --peer /ip4/127.0.0.1/tcp/1/p2p/<node-01 id>` (dead
#     seed: DR stays in the network phase up to DR_KAD_STABILIZE_TIMEOUT_SECS) in the
#     background; poll its stdout ≤ 30 s for the anchor "Network ready. Waiting for Kademlia
#     bootstrap..." (FAIL if absent); SIGINT → exits within 10 s, code ≠ 0, stderr
#     "DR interrupted. Nothing was changed."; G has no identity.key, db.redb, *.dr-new.
#     Repeat with SIGTERM (dr-i23) — check: anchor poll with deadline, wait with deadline,
#     rc, grep, find G
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_dr_guard_test.sh

set -euo pipefail

TEST_DIR="/tmp/viaticum-drguard-$$"
BINARY="${BINARY:-viaticum}"
DR_TIMEOUT=300

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
    echo "  Test dir: $TEST_DIR (not removed, inspect if needed)"
}
trap cleanup EXIT

# Data dirs: node-01 = the network; A, F, E = the friend's folders. Logs live OUTSIDE
# the data dirs so they never enter a folder snapshot.
node_dir() {
    case "$1" in
        A|F|E) echo "$TEST_DIR/$1" ;;
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
    local idx="$1"
    for _ in $(seq 1 120); do
        run_cli_q "$idx" status | grep -q "identity:" && return 0
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1" raw=""
    for _ in $(seq 1 20); do
        raw=$(run_cli_q "$idx" status | grep "addr:" | grep -oE '/ip4/[^ ]+' || true)
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
    mkdir -p "$TEST_DIR/watch-$idx"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --watch-dir "$TEST_DIR/watch-$idx" >> "$(node_log "$idx")" 2>&1 &
    LAST_PID=$!
    PIDS+=("$LAST_PID")
}

stop_pid() {
    local pid="$1"
    kill -INT "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
    kill -9 "$pid" 2>/dev/null || true
    for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
}

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

# node-01's count of "peer authenticated" lines, optionally only for identity prefix $2
# (the daemon logs identity_pub as its first 16 hex chars).
auth_lines_on_01() {
    if [ -n "${1:-}" ]; then
        plain_log 1 | grep -a "peer authenticated" | grep -ac "identity_pub=$1" || true
    else
        plain_log 1 | grep -ac "peer authenticated" || true
    fi
}

# Wait until node-01's auth-line count for prefix $1 stops changing (3 s quiet, ≤ 20 s),
# so reconnect churn of a live daemon is not mistaken for a DR connection. Prints it.
settle_auth_count() {
    local prefix="$1" prev=-1 cur=0 quiet=0
    for _ in $(seq 1 20); do
        cur=$(auth_lines_on_01 "$prefix")
        if [ "$cur" = "$prev" ]; then
            quiet=$((quiet + 1)); [ "$quiet" -ge 3 ] && break
        else
            quiet=0
        fi
        prev=$cur
        sleep 1
    done
    echo "$cur"
}

wait_auth_line_on_01() {
    local prefix="$1" want="$2" secs="$3"
    for _ in $(seq 1 "$secs"); do
        [ "$(auth_lines_on_01 "$prefix")" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}

# Full content of a folder: every path (listing) + sha256 of every regular file.
folder_state() {
    local d="$1"
    ( cd "$d" && find . -mindepth 1 | LC_ALL=C sort && \
      find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum )
}

# run_dr LABEL DATA_DIR PHRASE [extra args...]: runs `dr`; sets DR_RC, DR_OUT (stdout
# file), DR_ERR (stderr file), DR_ERRLINE (the final "error: ..." line).
run_dr() {
    local label="$1" dir="$2" phrase="$3"; shift 3
    DR_OUT="$TEST_DIR/logs/dr-$label.out"; DR_ERR="$TEST_DIR/logs/dr-$label.err"
    set +e
    RUST_LOG=info timeout "$DR_TIMEOUT" "$BINARY" --data-dir "$dir" dr \
        --mnemonic "$phrase" "$@" > "$DR_OUT" 2> "$DR_ERR"
    DR_RC=$?
    set -e
    DR_ERRLINE=$(sed 's/\x1b\[[0-9;]*m//g' "$DR_ERR" | grep -a '^error:' | tail -1 || true)
    echo "    dr[$label] exit=$DR_RC"
    sed 's/^/    | /' "$DR_OUT"
    echo "    | ${DR_ERRLINE:-<no error line>}"
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"; exit 1; }
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum DR guard test"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"
mkdir -p "$TEST_DIR/logs"

# ── STEP 1: SETUP ───────────────────────────────────────────────
echo ""
echo "=== Step 1: node-01, folder A (init + daemon), folder F (init) ==="
mkdir -p "$(node_dir 1)"
run_cli 1 init > "$TEST_DIR/logs/init-01.out" 2>&1
write_config 1
start_daemon 1
wait_daemon 1 || { fail "node-01 daemon not responding"; tail -20 "$(node_log 1)"; exit 1; }
ADDR_01=$(get_addr 1)
[ -n "$ADDR_01" ] || { fail "cannot get node-01 address"; exit 1; }
echo "  node-01: $ADDR_01"

mkdir -p "$(node_dir A)"
run_cli A init > "$TEST_DIR/logs/init-A.out" 2>&1
I_A=$(awk '/^Public key:/ {print $3}' "$TEST_DIR/logs/init-A.out")
M_A=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-A.out" | tail -1 | sed 's/^ *//')
mkdir -p "$(node_dir F)"
run_cli F init > "$TEST_DIR/logs/init-F.out" 2>&1
I_F=$(awk '/^Public key:/ {print $3}' "$TEST_DIR/logs/init-F.out")
M_F=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-F.out" | tail -1 | sed 's/^ *//')
if [ ${#I_A} -eq 64 ] && [ ${#I_F} -eq 64 ] && [ "$(echo "$M_A" | wc -w)" -eq 24 ] \
    && [ "$(echo "$M_F" | wc -w)" -eq 24 ] && [ "$I_A" != "$I_F" ]; then
    pass "init: A=${I_A:0:16}… F=${I_F:0:16}…, 24-word phrases captured"
else
    fail "init output not parsed (I_A='$I_A' I_F='$I_F')"; exit 1
fi

write_config A
start_daemon A
PID_A=$LAST_PID
wait_daemon A || { fail "A daemon not responding"; tail -20 "$(node_log A)"; exit 1; }
run_cli_q A connect "$ADDR_01" > /dev/null
if wait_auth_line_on_01 "${I_A:0:16}" 1 30; then
    pass "node-01 authenticated A (${I_A:0:16})"
else
    fail "node-01 never authenticated A within 30 s"
fi
stop_pid "$PID_A"
A_DIR=$(node_dir A)
if [ -f "$A_DIR/identity.key" ] && [ -f "$A_DIR/db.redb" ]; then
    pass "A has identity.key and db.redb"
else
    fail "A lacks identity.key or db.redb: $(ls -A "$A_DIR" | tr '\n' ' ')"; exit 1
fi
A_STATE=$(folder_state "$A_DIR")

check_a_unchanged() {
    local label="$1" now
    now=$(folder_state "$A_DIR")
    if [ "$now" = "$A_STATE" ]; then
        pass "$label: folder A byte-identical (listing + sha256 of every file)"
    else
        fail "$label: folder A changed"
        diff <(echo "$A_STATE") <(echo "$now") | sed 's/^/    /' || true
    fi
}

# ── STEP 2: TYPO ────────────────────────────────────────────────
echo ""
echo "=== Step 2: typo in word 5 (dr-i3) ==="
TYPO=$(echo "$M_A" | awk '{ $5 = "zzzz"; print }')
AUTH_BEFORE=$(auth_lines_on_01)
run_dr typo "$A_DIR" "$TYPO" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "recovery phrase" \
    && echo "$DR_ERRLINE" | grep -q "word 5"; then
    pass "typo refused: exit $DR_RC, error names the phrase and word 5"
else
    fail "typo not refused as expected (exit $DR_RC, error '$DR_ERRLINE')"
fi
check_a_unchanged "typo"
if [ "$(auth_lines_on_01)" -eq "$AUTH_BEFORE" ]; then
    pass "typo: node-01 saw no new authenticated peer (DR never reached the network)"
else
    fail "typo: node-01 authenticated a peer during the refused DR"
fi

# ── STEP 3: CHECKSUM ────────────────────────────────────────────
echo ""
echo "=== Step 3: valid words, bad checksum (dr-i3) ==="
ABANDON24=$(printf 'abandon %.0s' $(seq 1 24) | sed 's/ $//')
run_dr checksum "$A_DIR" "$ABANDON24" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "checksum"; then
    pass "bad checksum refused: exit $DR_RC, error mentions the checksum"
else
    fail "bad checksum not refused as expected (exit $DR_RC, error '$DR_ERRLINE')"
fi
check_a_unchanged "checksum"

# ── STEP 4: FOREIGN PHRASE INTO A ───────────────────────────────
echo ""
echo "=== Step 4: ADVERSARIAL foreign valid phrase into A (dr-i4) ==="
AUTH_BEFORE=$(auth_lines_on_01)
run_dr foreign "$A_DIR" "$M_F" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "different identity" \
    && echo "$DR_ERRLINE" | grep -q "${I_A:0:16}" && echo "$DR_ERRLINE" | grep -q "${I_F:0:16}"; then
    pass "foreign phrase refused: 'different identity', names A and F"
else
    fail "foreign phrase not refused as expected (exit $DR_RC, error '$DR_ERRLINE')"
fi
if grep -q "Identity restored:" "$DR_OUT"; then
    fail "foreign phrase: DR printed 'Identity restored:' ($(grep 'Identity restored:' "$DR_OUT"))"
else
    pass "foreign phrase: no 'Identity restored:' line"
fi
check_a_unchanged "foreign phrase"
if [ "$(auth_lines_on_01)" -eq "$AUTH_BEFORE" ]; then
    pass "foreign phrase: node-01 saw no new authenticated peer"
else
    fail "foreign phrase: node-01 authenticated a peer during the refused DR"
fi

# ── STEP 5: EMPTY FOLDER, WRONG THEN RIGHT PHRASE ───────────────
echo ""
echo "=== Step 5: empty folder E: foreign phrase, then the right one (dr-i4, dr-i12) ==="
E_DIR=$(node_dir E)
check_e_empty() {
    local label="$1" left
    left=$(find "$E_DIR" -mindepth 1 2>/dev/null | sed "s|$E_DIR/||" | tr '\n' ' ' || true)
    if [ -d "$E_DIR" ] && [ -z "$left" ]; then
        pass "$label: E is empty (no identity.key, db.redb, drafts)"
    else
        fail "$label: E is not an empty folder: '${left}'"
    fi
}
F_AUTH_BEFORE=$(auth_lines_on_01 "${I_F:0:16}")
run_dr e-foreign "$E_DIR" "$M_F" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "no catalog found"; then
    pass "M_F into E: exit $DR_RC, 'no catalog found'"
else
    fail "M_F into E: expected 'no catalog found' (exit $DR_RC, error '$DR_ERRLINE')"
fi
if [ "$(auth_lines_on_01 "${I_F:0:16}")" -gt "$F_AUTH_BEFORE" ]; then
    pass "M_F into E: node-01 authenticated F's DR (the failure happened on the network)"
else
    fail "M_F into E: node-01 never saw F's DR, the network half was not exercised"
fi
check_e_empty "after failed DR with M_F"

A_AUTH_BEFORE=$(auth_lines_on_01 "${I_A:0:16}")
# The friend types the right phrase sloppily: capitals and extra spaces (dr-i28).
M_A_SLOPPY="  $(echo "$M_A" | tr '[:lower:]' '[:upper:]' | sed 's/ /   /g')  "
run_dr e-right "$E_DIR" "$M_A_SLOPPY" --peer "$ADDR_01"
GOT_I=$(awk '/^Identity restored:/ {print $3}' "$DR_OUT")
if [ "$GOT_I" = "$I_A" ]; then
    pass "M_A (UPPER CASE, extra spaces) into E: 'Identity restored:' == A's init identity"
else
    fail "M_A into E: 'Identity restored: ${GOT_I:-<none>}' != I_A $I_A"
fi
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "no catalog found"; then
    pass "M_A into E: exit $DR_RC, 'no catalog found' (A never published a pointer)"
else
    fail "M_A into E: expected 'no catalog found' (exit $DR_RC, error '$DR_ERRLINE')"
fi
if [ "$(auth_lines_on_01 "${I_A:0:16}")" -gt "$A_AUTH_BEFORE" ]; then
    pass "M_A into E: node-01 authenticated A's DR (reached the network)"
else
    fail "M_A into E: node-01 never saw A's DR"
fi
check_e_empty "after failed DR with M_A"

# ── STEP 6: DAEMON AFTER A FAILED DR ────────────────────────────
echo ""
echo "=== Step 6: 'daemon' in the folder a failed DR left (dr-i12) ==="
AUTH_BEFORE=$(auth_lines_on_01)
E_LOG="$TEST_DIR/logs/daemon-E.log"
"$BINARY" --data-dir "$E_DIR" daemon --watch-dir "$TEST_DIR/watch-E" > "$E_LOG" 2>&1 &
PID_E=$!
PIDS+=("$PID_E")
E_EXITED=0
for _ in $(seq 1 30); do
    kill -0 "$PID_E" 2>/dev/null || { E_EXITED=1; break; }
    sleep 0.5
done
if [ "$E_EXITED" -eq 1 ]; then
    set +e; wait "$PID_E"; E_RC=$?; set -e
    if [ "$E_RC" -ne 0 ] && grep -q "viaticum dr" "$E_LOG"; then
        pass "daemon on E exited $E_RC within 15 s and points to 'viaticum dr'"
    else
        fail "daemon on E: exit $E_RC, hint missing: $(tail -2 "$E_LOG")"
    fi
else
    fail "daemon on E still running after 15 s (a node started in a failed DR's folder)"
    kill -9 "$PID_E" 2>/dev/null || true
fi
if [ ! -e "$E_DIR/identity.key" ] && [ ! -e "$E_DIR/db.redb" ]; then
    pass "E still has no identity.key and no db.redb"
else
    fail "E gained identity.key/db.redb: $(ls -A "$E_DIR" | tr '\n' ' ')"
fi
if [ "$(auth_lines_on_01)" -eq "$AUTH_BEFORE" ]; then
    pass "node-01 saw no new authenticated device from E"
else
    fail "node-01 authenticated a device while 'daemon' ran on E"
fi

# ── STEP 7: DR AGAINST A LIVE DAEMON ────────────────────────────
echo ""
echo "=== Step 7: ADVERSARIAL DR into the folder of a running daemon (dr-i5) ==="
A_AUTH_BEFORE=$(auth_lines_on_01 "${I_A:0:16}")
start_daemon A
PID_A=$LAST_PID
wait_daemon A || { fail "A daemon (restart) not responding"; exit 1; }
run_cli_q A connect "$ADDR_01" > /dev/null
if wait_auth_line_on_01 "${I_A:0:16}" $((A_AUTH_BEFORE + 1)) 30 \
    && wait_auth_peers 1 1 30; then
    pass "A's daemon is live and authenticated on node-01"
else
    fail "A's daemon did not authenticate on node-01 within 30 s"
fi
A_AUTH_BEFORE=$(settle_auth_count "${I_A:0:16}")
PEERS_01_BEFORE=$(status_num 1 peer_count_authenticated)
INODE_BEFORE=$(stat -c %i "$A_DIR/db.redb")
run_dr live "$A_DIR" "$M_A" --peer "$ADDR_01"
if [ "$DR_RC" -ne 0 ] && echo "$DR_ERRLINE" | grep -q "in use"; then
    pass "DR into a live node's folder refused: exit $DR_RC, 'in use'"
else
    fail "DR into a live node's folder not refused as 'in use' (exit $DR_RC, error '$DR_ERRLINE')"
fi
if run_cli_q A status | grep "identity:" | grep -q "$I_A"; then
    pass "A's daemon still answers status with I_A"
else
    fail "A's daemon does not answer status with I_A after the DR"
fi
PEERS_01_AFTER=$(status_num 1 peer_count_authenticated)
if [ "$PEERS_01_AFTER" -eq "$PEERS_01_BEFORE" ] && [ "$PEERS_01_AFTER" -ge 1 ]; then
    pass "node-01 still counts $PEERS_01_AFTER authenticated peer(s) (unchanged)"
else
    fail "node-01 authenticated peers changed: $PEERS_01_BEFORE -> $PEERS_01_AFTER"
fi
if [ "$(stat -c %i "$A_DIR/db.redb")" = "$INODE_BEFORE" ]; then
    pass "A/db.redb kept its inode ($INODE_BEFORE)"
else
    fail "A/db.redb inode changed ($INODE_BEFORE -> $(stat -c %i "$A_DIR/db.redb" 2>/dev/null || echo gone))"
fi
LEFT=$(ls -A "$A_DIR" | grep -E '\.dr-bak|\.dr-new' || true)
if [ -z "$LEFT" ]; then
    pass "no .dr-bak / .dr-new in A"
else
    fail "DR left files in the live node's folder: $LEFT"
fi
if [ "$(auth_lines_on_01 "${I_A:0:16}")" -eq "$A_AUTH_BEFORE" ]; then
    pass "the refused DR never connected to node-01 as A"
else
    fail "the refused DR connected to node-01 as A (it went to the network)"
fi

# ── STEP 8: STOP SIGNAL IN THE NETWORK PHASE ─────────────────────
echo ""
echo "=== Step 8: ADVERSARIAL Ctrl-C / SIGTERM while DR waits on the network (dr-i23) ==="
PID_01_ID=$(echo "$ADDR_01" | grep -oE '/p2p/[^/]+$' | cut -d/ -f3)
DEAD_SEED="/ip4/127.0.0.1/tcp/1/p2p/$PID_01_ID"
G_DIR="$TEST_DIR/G"
interrupt_dr() {
    local sig="$1" out="$TEST_DIR/logs/dr-sig-$1.out" err="$TEST_DIR/logs/dr-sig-$1.err"
    RUST_LOG=info "$BINARY" --data-dir "$G_DIR" dr --mnemonic "$M_A" --peer "$DEAD_SEED" \
        > "$out" 2> "$err" &
    local pid=$!
    PIDS+=("$pid")
    local anchored=0
    for _ in $(seq 1 60); do
        if grep -q "Network ready. Waiting for Kademlia bootstrap..." "$out" 2>/dev/null; then
            anchored=1; break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    if [ "$anchored" -ne 1 ]; then
        fail "$sig: DR never reached the network phase within 30 s (no anchor line)"
        sed 's/^/    | /' "$out" "$err" | tail -10 || true
        kill -9 "$pid" 2>/dev/null || true
        return
    fi
    # The key draft and the staging DB exist now (the check is not blind).
    DRAFTS=$(ls -A "$G_DIR" | tr '\n' ' ')
    if ! echo "$DRAFTS" | grep -q "identity.key.dr-new" || ! echo "$DRAFTS" | grep -q "db.redb.dr-new"; then
        fail "$sig: no drafts in G during the network phase ('$DRAFTS'): the check would be blind"
    fi
    kill -s "$sig" "$pid"
    if wait_pid_exit "$pid" 10; then
        local errline
        errline=$(sed 's/\x1b\[[0-9;]*m//g' "$err" | grep -a '^error:' | tail -1 || true)
        if [ "$EXIT_RC" -ne 0 ] && echo "$errline" | grep -q "DR interrupted. Nothing was changed."; then
            pass "$sig: DR exited $EXIT_RC within 10 s: '$errline'"
        else
            fail "$sig: exit $EXIT_RC, error line '${errline:-<none>}'"
        fi
    else
        fail "$sig: DR still running 10 s after the signal"
        kill -9 "$pid" 2>/dev/null || true
    fi
    local left
    left=$(find "$G_DIR" -mindepth 1 2>/dev/null | sed "s|$G_DIR/||" | tr '\n' ' ' || true)
    if [ -z "$left" ]; then
        pass "$sig: G is empty again (before the signal it held: ${DRAFTS:-nothing})"
    else
        fail "$sig: DR left files in G: '$left'"
    fi
}
interrupt_dr INT
interrupt_dr TERM

# ── RESULTS ─────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-01 log (last 20 lines) ==="
    tail -20 "$(node_log 1)" 2>/dev/null || true
    echo "=== A log (last 20 lines) ==="
    tail -20 "$(node_log A)" 2>/dev/null || true
fi
echo ""
echo "Logs: $TEST_DIR/logs/"
[ "$FAIL" -eq 0 ]
