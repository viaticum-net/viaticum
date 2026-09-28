#!/bin/bash
# Viaticum daemon health E2E, slice R1-b1: a node either runs whole or refuses
# to start loudly; one missing watch folder does not stop the others.
#
# Scenario:     4 independent owners. node-00 (started by hand) and node-01 form
#               a star. node-02 is started against a fixed listen port P that a
#               python blocker holds; after the blocker is gone node-02 runs on P,
#               and node-03 is a second viaticum configured with the same P.
#               node-02 then backs up a file; node-03 then starts for the first
#               time (ephemeral port) with one watch folder that exists and one
#               that does not, and backs up from the one that exists. Nodes
#               other than node-00 run as real
#               `systemd-run --user` services (exit status read from systemd);
#               without a user systemd they are started directly and the status
#               comes from `wait`.
# Intent:       daemon-i1, daemon-i3 (first half: no rearm yet), network-i1
#               (clean stop stays 0). private/intent/daemon.md
# Proves:       a start that cannot get its listen port exits 75 within 100 s,
#               before the node is visible to anyone: no `daemon started`, no
#               `libp2p swarm started`, no `web API server started`, no api-port
#               file (N1); stderr names the port. A second viaticum on the same
#               fixed port is refused the same way while the first keeps
#               serving on P. A node refused earlier starts normally once the
#               port is free, and its file lands on OTHER nodes' disks
#               (>= k_eff symbols). SIGTERM still ends every node with 0.
#               A node with one missing watch folder stays
#               up, shows the folder as `error` / "folder does not exist" in
#               /api/watches, and a file from the healthy folder lands on OTHER
#               nodes' disks. The "nothing will restart it" WARN is printed by
#               the hand-started node and not by the systemd-run ones.
# Adversarial:  step 2b: second viaticum on the same fixed port — libp2p-tcp
#               binds with SO_REUSEPORT, so without the plain-bind probe it
#               would start silently and share P; step 1: port held by a
#               foreign process for the whole ~64 s handover window.
# Cannot close: `viaticum status` without a daemon and run history (R1-b3); a
#               task dying mid-run / exit 70 / panic hook / restart under a
#               manager (R1-b2); the folder being picked up when it appears,
#               inotify overflow, mount-point change (R1-c); systemd
#               Restart=/RestartPreventExitStatus= policy (R3 install
#               scenario — here the units have no Restart=); self-enrollment
#               after DR (unit tests here; E2E = local_dr_test, dr-i22);
#               redb Corrupted/UpgradeRequired → 78 (unit tests only).
# Note:         the work_pipeline starvation seen with R1-b1 (two stuck
#               SystemState blocks alternating forever, no file block placed on
#               nodes younger than ~2 minutes) is fixed by R1-e (repair-i4:
#               stuck blocks park, the worker moves on). A FAIL of step 3 with
#               many 'no new candidates' lines is a regression of repair-i4,
#               not daemon-i3 — the step prints both counters.
# Steps:        0. init 4 nodes; node-00 by hand, node-01 as a service; star
#                  → node-00 sees 1 authenticated peer — check: wait_auth_peers
#               1. python blocker holds 0.0.0.0:P (no SO_REUSEPORT; it binds P itself at
#                  setup, below the ephemeral range; bind failure = setup FAIL); node-02 with
#                  listen_port=P → exit 75 within 100 s; its log: `daemon failed
#                  to start` naming `listen port P`, and none of `daemon
#                  started` / `libp2p swarm started` / `web API server started`;
#                  no api-port file (daemon-i1, N1) — check: systemd
#                  ExecMainStatus (or $?), grep, test -e
#               1w. node-00 log has the no-service-manager WARN; node-02 (systemd)
#                  does not (daemon-i1) — check: grep
#               1b. blocker gone; node-02 starts on P (its status addr has
#                  /tcp/P/); the log of this start has `daemon started` and no
#                  `redb: repair in progress` (the refused start closed the DB)
#                  (daemon-i1) — check: status addr, grep
#               2. node-02 connects to node-00; 1 MiB file on node-02 → node-00
#                  sees 2 authenticated peers; restorable per owner; >= k_eff
#                  symbols of its block on node-00 + node-01 disks (daemon-i1:
#                  the refused node now works as a whole) — check:
#                  wait_auth_peers, wait_file_restorable, block_symbols_on
#               2b. node-03 with listen_port=P while node-02 serves on P → exit
#                  75 within 100 s, reason names P, no swarm/web/api-port; node-02
#                  still answers status on P (daemon-i1, adversarial) — check:
#                  exit status, grep, status
#               3. node-03 (never ran) starts on an ephemeral port with
#                  [[watch]] A (exists) and B (missing) → running; /api/watches:
#                  B `error` "folder does not exist", A not error; `watch folder
#                  unavailable` names B in its log; a file written in A →
#                  restorable, >= k_eff symbols on node-00/01/02 disks
#                  (daemon-i3) — check: api_get /api/watches, block_symbols_on
#               4. SIGTERM every running node → exit 0; no panic in any log
#                  (network-i1) — check: exit status, grep
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_daemon_health_test.sh
#   (or: private/testing/run_e2e.sh daemon_health)

set -euo pipefail

NUM_NODES=4
TIME_SCALE=1000
TEST_DIR="/tmp/viaticum-dh-$$"
BINARY="${BINARY:-viaticum}"
UNIT_PREFIX="viaticum-dh-$$"

PASS=0; FAIL=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
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

# Verify binary exists; systemd needs an absolute path.
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

# ── Launching: real systemd user services, direct start as fallback ──────────
# Per node: UNIT[idx] (systemd mode) or DPID[idx] (direct mode).
declare -A UNIT DPID
LAUNCH_SEQ=0
BLOCKER_PID=""
if systemd-run --user --quiet --wait -- true 2>/dev/null; then
    SVC_MODE=systemd
else
    SVC_MODE=direct
fi

# start_node IDX MODE: MODE = service (systemd-run when available) | hand.
start_node() {
    local i="$1" mode="$2" dir; dir=$(node_dir "$i")
    mkdir -p "$dir/files"
    if [ "$mode" = service ] && [ "$SVC_MODE" = systemd ]; then
        LAUNCH_SEQ=$((LAUNCH_SEQ + 1))
        UNIT[$i]="$UNIT_PREFIX-n$i-$LAUNCH_SEQ"
        DPID[$i]=""
        # No Restart=: this slice checks the exit status, not the restart policy.
        # RemainAfterExit keeps ExecMainStatus readable after a clean exit too.
        systemd-run --user --quiet --unit="${UNIT[$i]}" \
            -p RemainAfterExit=yes \
            -p StandardOutput=append:"$(node_log "$i")" \
            -p StandardError=append:"$(node_log "$i")" \
            --setenv=RUST_LOG=info \
            --working-directory="$TEST_DIR" \
            -- "$BINARY" --data-dir "$dir" daemon \
               --time-scale "$TIME_SCALE" --watch-dir "$dir/files"
    else
        UNIT[$i]=""
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon \
            --time-scale "$TIME_SCALE" --watch-dir "$dir/files" \
            >> "$(node_log "$i")" 2>&1 &
        DPID[$i]=$!
    fi
}

# Main PID of node IDX, or "" when it is not running.
node_pid() {
    local i="$1" p=""
    if [ -n "${UNIT[$i]:-}" ]; then
        p=$(systemctl --user show -p MainPID --value "${UNIT[$i]}" 2>/dev/null || true)
        [ "$p" = 0 ] && p=""
    else
        p="${DPID[$i]:-}"
        [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null && p=""
    fi
    echo "$p"
}

# wait_node_exit IDX SECS: poll until node IDX's process has exited; sets
# EXIT_RC (systemd ExecMainStatus, or $? of the direct child). Returns 1 with
# EXIT_RC empty if it is still running at the deadline.
wait_node_exit() {
    local i="$1" secs="$2" code
    EXIT_RC=""
    if [ -n "${UNIT[$i]:-}" ]; then
        for _ in $(seq 1 $(( secs * 5 ))); do
            code=$(systemctl --user show -p ExecMainCode --value "${UNIT[$i]}" 2>/dev/null || echo 0)
            if [ "${code:-0}" != 0 ]; then
                EXIT_RC=$(systemctl --user show -p ExecMainStatus --value "${UNIT[$i]}")
                # ExecMainCode 1 = exited; 2/3 = killed/dumped by a signal.
                [ "$code" = 1 ] || EXIT_RC=$((128 + EXIT_RC))
                return 0
            fi
            sleep 0.2
        done
        return 1
    fi
    wait_pid_exit "${DPID[$i]}" "$secs"
}

stop_node() {
    local p; p=$(node_pid "$1")
    [ -n "$p" ] && kill -TERM "$p" 2>/dev/null || true
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
    [ -n "$BLOCKER_PID" ] && kill "$BLOCKER_PID" 2>/dev/null || true
    local i
    for i in $(seq 0 $((NUM_NODES-1))); do stop_node "$i"; done
    sleep 1
    for i in $(seq 0 $((NUM_NODES-1))); do
        local p; p=$(node_pid "$i"); [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
    done
    for u in $(systemctl --user list-units --all --plain --no-legend "$UNIT_PREFIX-*" 2>/dev/null | awk '{print $1}'); do
        systemctl --user stop "$u" 2>/dev/null || true
        systemctl --user reset-failed "$u" 2>/dev/null || true
    done
    echo "  Test dir: $TEST_DIR"
}
trap cleanup EXIT

# A free TCP port (bound and released at once).
# Start the step-1 port blocker and set PORT_P to the port it holds. The blocker binds the
# port itself (no free-then-rebind window) and picks it below the kernel's ephemeral range,
# so no outgoing connection on the server can take P while the blocker is gone (step 1b).
# A blocker that cannot bind is a setup FAIL, never a silent pass.
start_port_blocker() {
    local port_file="$TEST_DIR/blocker.port"
    rm -f "$port_file"
    python3 - "$port_file" <<'PYEOF' &
import os, random, socket, sys, time
low = int(open("/proc/sys/net/ipv4/ip_local_port_range").read().split()[0])
s = None
for _ in range(500):
    p = random.randint(10000, low - 1)
    c = socket.socket()          # no SO_REUSEPORT, no SO_REUSEADDR
    try:
        c.bind(("0.0.0.0", p))
    except OSError:
        c.close()
        continue
    s = c
    break
if s is None:
    sys.exit("port blocker: no free port below the ephemeral range")
s.listen()
with open(sys.argv[1] + ".tmp", "w") as f:
    f.write(str(p))
os.rename(sys.argv[1] + ".tmp", sys.argv[1])
time.sleep(3600)
PYEOF
    BLOCKER_PID=$!
    for _ in $(seq 1 50); do
        [ -s "$port_file" ] && break
        kill -0 "$BLOCKER_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [ ! -s "$port_file" ]; then
        fail "setup: the port blocker could not bind a port (see stderr above)"
        echo "RESULT: FAIL (setup)"
        exit 1
    fi
    PORT_P=$(cat "$port_file")
}

# Checks on the lines node IDX wrote since line N: a refused start.
assert_refused_start() {
    local i="$1" from="$2" port="$3" what="$4" lines
    lines=$(log_since "$i" "$from")
    if has "$(grep -F "daemon failed to start" <<< "$lines" || true)" "listen port $port is in use"; then
        pass "$what: 'daemon failed to start' names 'listen port $port is in use'"
    else
        fail "$what: no 'daemon failed to start … listen port $port is in use' in the log"
        echo "$lines" | tail -5 | sed 's/^/    | /'
    fi
    local marker
    for marker in "daemon started" "libp2p swarm started" "web API server started"; do
        if has "$lines" "$marker"; then
            fail "$what: '$marker' in the log of a refused start (the node appeared before refusing)"
        else
            pass "$what: no '$marker' before the refusal"
        fi
    done
    if [ -e "$(node_dir "$i")/api-port" ]; then
        fail "$what: api-port file exists after a refused start (N1)"
    else
        pass "$what: no api-port file (N1)"
    fi
}

echo "============================================================"
echo "  Viaticum Daemon Health Test, R1-b1 (${NUM_NODES} nodes)"
echo "  Binary:   $BINARY"
echo "  Launcher: $SVC_MODE"
echo "  Test dir: $TEST_DIR"
echo "============================================================"
[ "$SVC_MODE" = systemd ] || info "no working 'systemd-run --user': nodes start directly, exit status from wait"

# ── PHASE 0: SETUP ───────────────────────────────────────────────
echo ""
echo "=== Phase 0: Setup ==="
mkdir -p "$TEST_DIR"
start_port_blocker
echo "  Fixed listen port for node-02/node-03: $PORT_P (held by the blocker until step 1b)"

for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
    {
        echo '[web_api]'
        echo 'enabled = true'
        echo 'bind = "127.0.0.1:0"'
        echo '[storage]'
        echo 'disk_reserve_gb = 0.0'
        echo '[escrow]'
        echo 'k_factor = 0.001'
        if [ "$i" -ge 2 ]; then
            echo '[network]'
            echo "listen_port = $PORT_P"
        fi
    } > "$(node_dir "$i")/config.toml"
done

start_node 0 hand
start_node 1 service
wait_daemon 0 || fail "setup: node-00 did not come up"
wait_daemon 1 || fail "setup: node-01 did not come up"
ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"
run_cli_q 1 connect "$ADDR_00" > /dev/null
if wait_auth_peers 0 1 30; then
    pass "setup: node-00 sees node-01 authenticated"
else
    fail "setup: node-00 auth peers $(status_num 0 peer_count_authenticated)/1 after 30s"
fi

# ── STEP 1: PORT HELD BY A FOREIGN PROCESS ───────────────────────
echo ""
echo "=== Step 1: listen port held by another process → exit 75 (daemon-i1) ==="
kill -0 "$BLOCKER_PID" 2>/dev/null || fail "step 1 setup: the port blocker is gone"
HELD=0
for _ in $(seq 1 25); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT_P") 2>/dev/null; then HELD=1; break; fi
    sleep 0.2
done
[ "$HELD" -eq 1 ] || fail "step 1 setup: the blocker does not listen on $PORT_P"
AUTH_BEFORE=$(status_num 0 peer_count_authenticated)

L2=$(log_line_count 2)
T0=$(date +%s)
start_node 2 service
if wait_node_exit 2 100; then
    ELAPSED=$(( $(date +%s) - T0 ))
    if [ "$EXIT_RC" = 75 ]; then
        pass "step 1: node-02 exited with status 75 after ${ELAPSED}s (transient refusal)"
    else
        fail "step 1: node-02 exited with status $EXIT_RC (want 75) after ${ELAPSED}s"
    fi
    info "step 1: waited ${ELAPSED}s (the ~64 s listen-port handover window)"
else
    fail "step 1: node-02 still running 100s after start on a held port (half-started node)"
    stop_node 2
    wait_node_exit 2 20 || true
fi
assert_refused_start 2 "$L2" "$PORT_P" "step 1"
info "step 1: node-00 authenticated peers before/after: $AUTH_BEFORE/$(status_num 0 peer_count_authenticated) (node-02 was never told to connect)"

# ── STEP 1w: WARN WITHOUT A SERVICE MANAGER ──────────────────────
if has "$(log_since 0 0)" "nothing will restart it"; then
    pass "step 1w: hand-started node-00 warns that nothing will restart it"
else
    fail "step 1w: no 'nothing will restart it' WARN in the hand-started node-00 log"
fi
if [ "$SVC_MODE" = systemd ]; then
    if has "$(log_since 2 "$L2")" "nothing will restart it"; then
        fail "step 1w: node-02 under systemd printed the no-service-manager WARN"
    else
        pass "step 1w: node-02 under systemd does not print the no-service-manager WARN"
    fi
fi

# ── STEP 1b: THE PORT IS FREE AGAIN ──────────────────────────────
echo ""
echo "=== Step 1b: port free again → node-02 runs on the fixed port (daemon-i1) ==="
kill "$BLOCKER_PID" 2>/dev/null || true
wait "$BLOCKER_PID" 2>/dev/null || true
BLOCKER_PID=""
L2B=$(log_line_count 2)
start_node 2 service
if wait_daemon 2; then
    ADDR_02=$(get_addr 2)
    if has "$ADDR_02" "/tcp/$PORT_P/"; then
        pass "step 1b: node-02 runs on the fixed port ($ADDR_02)"
    else
        fail "step 1b: node-02 listen address '$ADDR_02' is not on port $PORT_P"
    fi
else
    fail "step 1b: node-02 did not start once the port was free"
fi
# The refused start of step 1 must have closed the DB cleanly: this start's
# log (non-empty: it carries `daemon started`) shows no redb repair.
LOG_1B=$(log_since 2 "$L2B")
if ! has "$LOG_1B" "daemon started"; then
    fail "step 1b: no 'daemon started' in node-02's log of this start (cannot judge the DB close)"
elif has "$LOG_1B" "redb: repair in progress"; then
    fail "step 1b: node-02 repaired its DB on restart — the refused start left it unclean"
else
    pass "step 1b: node-02 opened its DB without repair (refused start closed it)"
fi

# ── STEP 2: THE ONCE-REFUSED NODE WORKS AS A WHOLE ───────────────
echo ""
echo "=== Step 2: node-02 backs up; symbols on OTHER nodes' disks (daemon-i1) ==="
run_cli_q 2 connect "$ADDR_00" > /dev/null
if wait_auth_peers 0 2 60; then
    pass "step 2: node-00 sees node-02 authenticated ($(status_num 0 peer_count_authenticated) peers)"
else
    fail "step 2: node-00 auth peers $(status_num 0 peer_count_authenticated)/2 after 60s"
fi
FILE2="$(node_dir 2)/files/after_refusal.bin"
dd if=/dev/urandom of="$FILE2" bs=1024 count=1024 2>/dev/null
TARGET=0
if wait_file_restorable 2 "$FILE2" 120; then
    TARGET=$(file_field 2 "$FILE2" '.effective_status.target')
    pass "step 2: node-02 reports its file restorable (k_eff=$TARGET)"
else
    fail "step 2: node-02 file not restorable after 120s"
fi
BLOCK2=$(file_block_hex 2 "$FILE2")
ON_DISK=0
for i in 0 1; do
    n=$(block_symbols_on "$i" "$BLOCK2")
    echo "    $(node_name "$i") holds $n symbols of ${BLOCK2:0:16}"
    ON_DISK=$((ON_DISK + n))
done
if [ -n "$BLOCK2" ] && [ "${TARGET:-0}" -gt 0 ] && [ "$ON_DISK" -ge "$TARGET" ]; then
    pass "step 2: node-00 + node-01 hold $ON_DISK symbols >= k_eff $TARGET on disk"
else
    fail "step 2: other nodes hold $ON_DISK symbols, need k_eff=${TARGET:-?} (block=${BLOCK2:-none})"
fi

# ── STEP 2b: SECOND VIATICUM ON THE SAME FIXED PORT ──────────────
echo ""
echo "=== Step 2b: second viaticum on node-02's fixed port → exit 75 (daemon-i1) ==="
L3=$(log_line_count 3)
T0=$(date +%s)
start_node 3 service
if wait_node_exit 3 100; then
    ELAPSED=$(( $(date +%s) - T0 ))
    if [ "$EXIT_RC" = 75 ]; then
        pass "step 2b: second viaticum (node-03) on port $PORT_P exited 75 after ${ELAPSED}s"
    else
        fail "step 2b: node-03 exited with status $EXIT_RC (want 75)"
    fi
else
    fail "step 2b: node-03 still running 100s after start on node-02's port (SO_REUSEPORT: silent sharing)"
    stop_node 3
    wait_node_exit 3 20 || true
fi
assert_refused_start 3 "$L3" "$PORT_P" "step 2b"
if [ -n "$(node_pid 2)" ] && has "$(run_cli_q 2 status)" "/tcp/$PORT_P/"; then
    pass "step 2b: node-02 still running and answering status on port $PORT_P"
else
    fail "step 2b: node-02 is not running/answering after the refused second instance"
fi

# ── STEP 3: ONE MISSING WATCH FOLDER ─────────────────────────────
# node-03 (refused in 2b, never ran) now starts for the first time, on an
# ephemeral port, with watch folder A (exists) and B (missing). A fresh node on
# purpose: see the passport note on work_pipeline starvation — the file must be
# placed before the node's first SystemState block (~60 s after its start).
echo ""
echo "=== Step 3: node-03 with a missing watch folder keeps backing up (daemon-i3) ==="
DIR_A="$(node_dir 3)/A"
DIR_B="$(node_dir 3)/B"
mkdir -p "$DIR_A"
rm -rf "$DIR_B"
{
    echo '[web_api]'
    echo 'enabled = true'
    echo 'bind = "127.0.0.1:0"'
    echo '[storage]'
    echo 'disk_reserve_gb = 0.0'
    echo '[escrow]'
    echo 'k_factor = 0.001'
    echo '[[watch]]'
    echo "path = \"$DIR_A\""
    echo '[[watch]]'
    echo "path = \"$DIR_B\""
} > "$(node_dir 3)/config.toml"
L3=$(log_line_count 3)
T_START3=$(date +%s)
start_node 3 service
wait_daemon 3 || fail "step 3: node-03 did not come up with a missing watch folder"
run_cli_q 3 connect "$ADDR_00" > /dev/null
if wait_auth_peers 0 3 60; then
    pass "step 3: node-00 sees node-03 authenticated (3 peers)"
else
    fail "step 3: node-00 auth peers $(status_num 0 peer_count_authenticated)/3 after 60s"
fi
FILE_A="$DIR_A/healthy_folder.bin"
dd if=/dev/urandom of="$FILE_A" bs=1024 count=256 2>/dev/null
info "step 3: file written in A $(( $(date +%s) - T_START3 ))s after node-03's start"
if [ -n "$(node_pid 3)" ]; then
    pass "step 3: node-03 is running with watch folder B missing"
else
    wait_node_exit 3 1 || true
    fail "step 3: node-03 is not running (exit ${EXIT_RC:-?}) with watch folder B missing"
fi
WATCHES=$(api_get 3 /api/watches)
B_STATUS=$(echo "$WATCHES" | jq -r --arg p "$DIR_B" '.[] | select(.path==$p) | .status' 2>/dev/null || true)
B_ERROR=$(echo "$WATCHES" | jq -r --arg p "$DIR_B" '.[] | select(.path==$p) | .error // ""' 2>/dev/null || true)
A_STATUS=$(echo "$WATCHES" | jq -r --arg p "$DIR_A" '.[] | select(.path==$p) | .status' 2>/dev/null || true)
if [ "$B_STATUS" = error ] && [ "$B_ERROR" = "folder does not exist" ]; then
    pass "step 3: /api/watches B: status error, '$B_ERROR'"
else
    fail "step 3: /api/watches B: status '$B_STATUS', error '$B_ERROR' (want error / folder does not exist)"
fi
if [ -n "$A_STATUS" ] && [ "$A_STATUS" != error ]; then
    pass "step 3: /api/watches A: status $A_STATUS (not error)"
else
    fail "step 3: /api/watches A: status '${A_STATUS:-absent}'"
fi
if has "$(grep -F "watch folder unavailable" <<< "$(log_since 3 "$L3")" || true)" "$DIR_B"; then
    pass "step 3: node-03 log names B in 'watch folder unavailable'"
else
    fail "step 3: no 'watch folder unavailable' line for B in node-03's log"
fi
TARGET=0
if wait_file_restorable 3 "$FILE_A" 120; then
    TARGET=$(file_field 3 "$FILE_A" '.effective_status.target')
    pass "step 3: file from healthy folder A restorable per node-03 (k_eff=$TARGET)"
else
    fail "step 3: file from folder A not restorable after 120s"
    # Tell a missing-B regression apart from worker starvation (separate bug).
    info "step 3: 'no new candidates' lines on node-03: $(log_since 3 "$L3" | grep -c 'no new candidates' || true); SystemState blocks published: $(log_since 3 "$L3" | grep -c 'system_state push: base published' || true)"
fi
BLOCK_A=$(file_block_hex 3 "$FILE_A")
ON_DISK=0
for i in 0 1 2; do
    n=$(block_symbols_on "$i" "$BLOCK_A")
    echo "    $(node_name "$i") holds $n symbols of ${BLOCK_A:0:16}"
    ON_DISK=$((ON_DISK + n))
done
if [ -n "$BLOCK_A" ] && [ "${TARGET:-0}" -gt 0 ] && [ "$ON_DISK" -ge "$TARGET" ]; then
    pass "step 3: node-00/01/02 hold $ON_DISK symbols >= k_eff $TARGET of A's file"
else
    fail "step 3: other nodes hold $ON_DISK symbols of A's file, need k_eff=${TARGET:-?} (block=${BLOCK_A:-none})"
fi

# ── STEP 4: CLEAN STOP OF EVERYONE ───────────────────────────────
echo ""
echo "=== Step 4: SIGTERM all → exit 0, no panic (network-i1) ==="
for i in 0 1 2 3; do stop_node "$i"; done
for i in 0 1 2 3; do
    if wait_node_exit "$i" 20; then
        if [ "$EXIT_RC" = 0 ]; then
            pass "step 4: $(node_name "$i") exit 0"
        else
            fail "step 4: $(node_name "$i") exit $EXIT_RC (want 0)"
        fi
    else
        fail "step 4: $(node_name "$i") still running 20s after SIGTERM"
    fi
done
PANICS=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if grep -qa "panicked" "$(node_log "$i")" 2>/dev/null; then
        fail "step 4: panic in $(node_name "$i") log"
        grep -a "panicked" "$(node_log "$i")" | tail -3 | sed 's/^/    | /'
        PANICS=$((PANICS + 1))
    fi
done
[ "$PANICS" -eq 0 ] && pass "step 4: no panic in any of the $NUM_NODES logs"

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
echo "Logs: $TEST_DIR/node-*/daemon.log"
[ "$FAIL" -eq 0 ]
