#!/bin/bash
# Viaticum DR E2E: lose the whole machine, recover from the mnemonic, restore a file
# from the network by content hash.
# Local processes on one machine (no Docker).
#
# Scenario: 5 independent owners, star-connected to node-00 (fixed mnemonic). node-00
#   backs up a 256 KB file and publishes a SelfPointer that covers it; then node-00's
#   whole data dir (DB, keys, watch dir) is wiped, `viaticum dr --mnemonic` rebuilds the
#   catalog from one seed peer, the daemon is started as `dr` instructs (no manual
#   connect) and the file is restored.
# Intent: dr-i1 (Phases 4-5; currently FAILs in Phase 5: the post-DR daemon gets 0
#   authenticated peers, product redial bug), restore-i1 after DR (Phase 5, same FAIL),
#   dr-i9 (Phase 3, only via the "SelfPointer published via mailbox" log line: status
#   does not expose DR readiness), restore-i6 after DR (no [escrow] override; the
#   removed holder gate — held bytes x scaled age / 7 days < c x 65535 requested —
#   would refuse while the restore finishes < ~600 s x (65535 / symbol size) after
#   placement at TIME_SCALE=1000; the run needs ~130 s; no in-script timing guard,
#   local_e2e_test has one).
# Proves: DR recovers a catalog whose file count equals the scenario's journal (1) and
#   that lists the backed-up file; the recovered daemon reaches holders on its own; the
#   file restored on the wiped machine is byte-identical to the original (sha256) and
#   holders log serving it.
# Adversarial: whole machine lost (data dir wiped incl. keys and source); DR seeded
#   with a single peer.
# Cannot close: DR on a genuinely different host/IP (same host, new process); DR with
#   the seed peer being a non-holder; a stale pointer (the test waits for a pointer that
#   covers the file, so "DR returns yesterday's catalog" is not exercised); cluster
#   siblings (single-device master); dr-i9 as the friend sees it (readiness in status
#   and acceptance by postmen); restore-i3 (honest outcome): NOT proven — the restore
#   CLI answers exit 0 + "started" even when the job restored nothing, and
#   e2e_lib.sh:restore_from_network only turns that defect into a FAIL
#   ("no <file> in staging"), it does not check what the CLI reports.
# Steps: 1. backup 256 KB -> restorable per owner — check: wait_file_restorable
#        2. SS snapshot after placement, then a SelfPointer covering it (dr-i9, log
#             only) — check: generation/diffs from "SelfPointer published via mailbox"
#        3. stop node-00, wipe its data dir; source gone — check: [ -e "$FILE" ]
#        4. `dr --mnemonic --peer node-01` -> exit 0, Files == journal (1) (dr-i1) —
#             check: DR_EXIT, FILES_N -eq JOURNAL_FILES
#        5. start daemon, no connect -> catalog lists the file, >= 1 authenticated peer
#             (dr-i1) — check: file_field .path, wait_auth_peers
#        6. restore -> sha256 match; holders log RestoreResponse (dr-i1,
#             restore-i1) — check: restore_from_network, restore_responses_for
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_dr_test.sh [num_nodes]

set -euo pipefail

NUM_NODES=${1:-5}
TIME_SCALE=1000   # system state push interval = max(6*3600/1000, 60) = 60s
TEST_DIR="/tmp/viaticum-test-$$"
MNEMONIC_00="cram muscle milk good case boil silver edge cram muscle milk good case boil silver edge cram muscle milk good case boil silver double"
BINARY="${BINARY:-viaticum}"

PASS=0; FAIL=0
PIDS=()

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Wait briefly for graceful shutdown
    sleep 1
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "  Killed ${#PIDS[@]} daemon processes"
    echo "  Test dir: $TEST_DIR (not removed, inspect if needed)"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }

run_cli() {
    # $1 = node index, rest = command args
    local idx="$1"; shift
    local dir=$(node_dir "$idx")
    "$BINARY" --data-dir "$dir" "$@"
}

run_cli_q() {
    run_cli "$@" 2>/dev/null || true
}

wait_daemon() {
    local idx="$1"
    for i in $(seq 1 120); do
        if run_cli_q "$idx" status 2>/dev/null | grep -q "identity:"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

get_addr() {
    local idx="$1"
    # Status shows a libp2p multiaddr: /ip4/0.0.0.0/tcp/PORT/p2p/PEERID.
    # wait_daemon returns on "identity:" (available from the keyfile almost
    # immediately), but the swarm listen address is reported ~1s later. Poll
    # until the addr appears so a solo-started node (node-00) doesn't race.
    local RAW_ADDR=""
    for _ in $(seq 1 20); do
        RAW_ADDR=$(run_cli_q "$idx" status 2>/dev/null | grep "addr:" \
            | grep -oE '/ip4/[^ ]+' || true)
        [ -n "$RAW_ADDR" ] && break
        sleep 0.5
    done
    if [ -z "$RAW_ADDR" ]; then return; fi
    # Replace 0.0.0.0 with 127.0.0.1 for local testing.
    echo "$RAW_ADDR" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

# Verify binary exists
if ! command -v "$BINARY" &>/dev/null; then
    # Try release build path
    BINARY="./target/release/viaticum"
    if [ ! -x "$BINARY" ]; then
        echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"
        exit 1
    fi
fi

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

# Daemon log without ANSI colour codes (tracing colours key=value fields).
plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

echo "============================================================"
echo "  Viaticum δ.1: Local DR Test (${NUM_NODES} nodes)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── PHASE 1: SETUP ──────────────────────────────────────────────
echo ""
echo "=== Phase 1: Setup ==="

mkdir -p "$TEST_DIR"

# Init all nodes. node-00 uses a FIXED mnemonic so the `dr` recovery command can
# re-derive its identity after simulated loss. The other nodes are independent
# owners with distinct masters: same-master siblings are excluded from the
# placement pool by design, so node-00 needs non-sibling holders for its data.
echo "  Initializing ${NUM_NODES} nodes (node-00 fixed mnemonic, others distinct masters)..."
mkdir -p "$(node_dir 0)"
run_cli 0 init --mnemonic "$MNEMONIC_00" > /dev/null 2>&1
for i in $(seq 1 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
done
echo "  ${NUM_NODES} nodes initialized."

# Set disk_reserve_gb=0 so tests work on low-disk machines.
for i in $(seq 0 $((NUM_NODES-1))); do
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF
done

# Start node-00 daemon
echo "  Starting node-00 daemon (time_scale=${TIME_SCALE})..."
RUST_LOG=info "$BINARY" --data-dir "$(node_dir 0)" daemon \
    --time-scale "$TIME_SCALE" \
    --watch-dir "$(node_dir 0)/files" \
    > "$(node_log 0)" 2>&1 &
PIDS+=($!)
mkdir -p "$(node_dir 0)/files"

if ! wait_daemon 0; then
    fail "node-00 daemon not responding after 10s"
    tail -20 "$(node_log 0)"
    exit 1
fi

ADDR_00=$(get_addr 0)
echo "  node-00 addr: $ADDR_00"

if [ -z "$ADDR_00" ]; then
    fail "cannot get node-00 address"
    exit 1
fi

# ── PHASE 2: START ALL + STAR CONNECT ──────────────────────────
echo ""
echo "=== Phase 2: Start All Daemons + Star Connect ==="

# Start remaining daemons
echo "  Starting nodes 01-$(printf '%02d' $((NUM_NODES-1)))..."
for i in $(seq 1 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG=info "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" \
        --watch-dir "$(node_dir "$i")/files" \
        > "$(node_log "$i")" 2>&1 &
    PIDS+=($!)
done

# Wait for all daemons
echo "  Waiting for daemons..."
READY=0
for i in $(seq 1 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then
        ((READY++)) || true
    else
        echo "    node-$(printf '%02d' "$i") NOT ready"
    fi
done
echo "  $READY/$((NUM_NODES-1)) daemons ready"

# Connect all to node-00
echo "  Connecting to node-00..."
CONNECT_OK=0
CONNECT_FAIL=0
for i in $(seq 1 $((NUM_NODES-1))); do
    RESULT=$(run_cli_q "$i" connect "$ADDR_00" 2>&1 || true)
    if echo "$RESULT" | grep -qi "connected"; then
        ((CONNECT_OK++)) || true
    else
        ((CONNECT_FAIL++)) || true
        echo "    node-$(printf '%02d' "$i"): $RESULT"
    fi
done
echo "  Connected: $CONNECT_OK/$((NUM_NODES-1)), Failed: $CONNECT_FAIL"
if wait_auth_peers 0 $((NUM_NODES-1)) 30; then
    pass "star connect: node-00 has $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: node-00 has only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 30s"
fi

# ── PHASE 3: BACKUP + A SELFPOINTER THAT COVERS IT ─────────────
echo ""
echo "=== Phase 3: Backup + SelfPointer covering it ==="

FILE="$(node_dir 0)/files/test.bin"
dd if=/dev/urandom of="$FILE" bs=1024 count=256 2>/dev/null
ORIG_HASH=$(content_hash "$FILE")
JOURNAL_FILES=1   # files this scenario backed up before the covering SelfPointer
echo "  Created 256 KB file, sha256 $ORIG_HASH"

if wait_file_restorable 0 "$FILE" 120; then
    pass "file restorable per owner"
else
    fail "file not restorable per owner after 120s"
fi
BLOCK=$(file_block_hex 0 "$FILE")

# DR restores whatever SystemState the freshest SelfPointer references. A pointer
# published before the file was placed describes a catalog without it, so wait for
# (1) an SS snapshot taken after the file became restorable, then (2) a SelfPointer
# that covers that snapshot: same generation and >= that many diffs, or a newer
# generation. Push interval = max(6h / time_scale, 60 s).
L0=$(plain_log 0 | wc -l)
SS_LINE=""; SS_GEN=0; SS_DIFFS=0
POINTER_OK=0
for attempt in $(seq 1 60); do
    if [ -z "$SS_LINE" ]; then
        SS_LINE=$(plain_log 0 | tail -n +$((L0 + 1)) | grep -anE "system_state push: (diff published|base published|compacted to new base)" | head -1 || true)
        if [ -n "$SS_LINE" ]; then
            SS_GEN=$(echo "$SS_LINE" | grep -oE 'generation=[0-9]+' | cut -d= -f2 || true)
            SS_DIFFS=$(echo "$SS_LINE" | grep -oE 'diffs=[0-9]+' | cut -d= -f2 || true)
            SS_DIFFS=${SS_DIFFS:-0}
            L1=$((L0 + ${SS_LINE%%:*}))
            echo "  SS snapshot after placement: generation=$SS_GEN diffs=$SS_DIFFS (${attempt}x5s)"
        fi
    fi
    if [ -n "$SS_LINE" ]; then
        while read -r line; do
            g=$(echo "$line" | grep -oE 'generation=[0-9]+' | cut -d= -f2 || true)
            d=$(echo "$line" | grep -oE 'diffs=[0-9]+' | cut -d= -f2 || true)
            if [ "${g:-0}" -gt "$SS_GEN" ] || { [ "${g:-0}" -eq "$SS_GEN" ] && [ "${d:-0}" -ge "$SS_DIFFS" ]; }; then
                echo "  covering SelfPointer: generation=$g diffs=$d (${attempt}x5s)"
                POINTER_OK=1
                break
            fi
        done < <(plain_log 0 | tail -n +$((L1 + 1)) | grep -a "SelfPointer published via mailbox" || true)
    fi
    [ "$POINTER_OK" -eq 1 ] && break
    sleep 5
done

if [ "$POINTER_OK" -eq 1 ]; then
    pass "SelfPointer covering the backed-up file published via mailbox"
else
    fail "no SelfPointer covering the file after 300s (snapshot line: ${SS_LINE:-none})"
    echo "  === node-00 log (SS lines) ==="
    plain_log 0 | grep -a "system_state" | tail -10 || true
fi

# ── PHASE 4: DISASTER RECOVERY ─────────────────────────────────
echo ""
echo "=== Phase 4: Disaster Recovery ==="

# Seed DR with a SINGLE holder. With the physical survival ceiling, the SS base
# (max-importance, few holders) is placed as full replicas — each holder holds a
# full decodable copy — so DR must recover from ANY one reachable holder, without
# needing to reach the others.
ADDR_01=$(get_addr 1)
echo "  DR seed peer (single holder): node-01 $ADDR_01"
[ -z "$ADDR_01" ] && { fail "cannot get node-01 addr for DR"; exit 1; }

echo "  Stopping node-00 daemon..."
kill "${PIDS[0]}" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "${PIDS[0]}" 2>/dev/null || break; sleep 0.5; done
kill -9 "${PIDS[0]}" 2>/dev/null || true

# Machine lost: DB, keys, config and the watch dir with the file itself.
cp "$(node_log 0)" "$TEST_DIR/node-00.pre-dr.log" 2>/dev/null || true
echo "  Wiping node-00 data dir (pre-DR log kept at $TEST_DIR/node-00.pre-dr.log)..."
rm -rf "$(node_dir 0)"/*
[ -e "$FILE" ] && fail "wipe left the source file in place"

set +e
DR_OUTPUT=$(RUST_LOG=info "$BINARY" --data-dir "$(node_dir 0)" dr \
    --mnemonic "$MNEMONIC_00" --peer "$ADDR_01" 2>&1)
DR_EXIT=$?
set -e
echo "$DR_OUTPUT" | grep -avE "\[2m20" | sed 's/^/    | /' || true

FILES_N=$(echo "$DR_OUTPUT" | grep -a "  Files:" | grep -oE '[0-9]+' | tail -1 || true)
PEERS_N=$(echo "$DR_OUTPUT" | grep -a "  Peers:" | grep -oE '[0-9]+' | tail -1 || true)
if [ $DR_EXIT -eq 0 ] && echo "$DR_OUTPUT" | grep -q "DR restore successful"; then
    pass "DR completed (files=${FILES_N:-?}, peers=${PEERS_N:-?})"
else
    fail "DR failed (exit=$DR_EXIT)"
fi
# dr-i1: == number of files in the scenario's journal (not ">= 1").
if [ "${FILES_N:-0}" -eq "$JOURNAL_FILES" ]; then
    pass "DR catalog has ${FILES_N} file(s) == journal ${JOURNAL_FILES}"
else
    fail "DR catalog has ${FILES_N:-0} files, journal has ${JOURNAL_FILES}"
fi

# ── PHASE 5: POST-DR DAEMON + RESTORE BY HASH ──────────────────
echo ""
echo "=== Phase 5: Post-DR daemon -> restore from the network ==="
mkdir -p "$(node_dir 0)/files"

# DR replaced config.toml with the default template (web_api commented out).
# The CLI needs web_api enabled to reach the daemon via api-port, so re-apply
# the test config (same pattern as Phase 1).
cat > "$(node_dir 0)/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
CFGEOF

RUST_LOG=info "$BINARY" --data-dir "$(node_dir 0)" daemon \
    --time-scale "$TIME_SCALE" \
    --watch-dir "$(node_dir 0)/files" \
    > "$(node_log 0)" 2>&1 &
PIDS[0]=$!

if ! wait_daemon 0; then
    fail "post-DR daemon did not start"
    exit 1
fi

if [ -n "$(file_field 0 "$FILE" '.path')" ]; then
    pass "recovered catalog lists $(basename "$FILE") ($(file_field 0 "$FILE" '.versions') version(s))"
else
    fail "recovered catalog does not list $FILE"
    api_get 0 /api/files | jq -r '.[].path' 2>/dev/null | head -5 || true
fi

# `dr` says: start the daemon, then restore. No manual connect.
if wait_auth_peers 0 1 60; then
    pass "post-DR daemon reconnected on its own ($(status_num 0 peer_count_authenticated) authenticated peers)"
else
    fail "post-DR daemon has 0 authenticated peers after 60s (known in DB: $(status_num 0 peer_count))"
fi

SERVED_BEFORE=$(restore_responses_for "$BLOCK" $(seq 1 $((NUM_NODES-1))))
if restore_from_network 0 "$FILE" "$ORIG_HASH" 120; then
    pass "post-DR restore: $RESTORE_MSG"
else
    fail "post-DR restore: $RESTORE_MSG"
    plain_log 0 | grep -ai "restore\|fetch" | tail -10 || true
fi
SERVED=$(( $(restore_responses_for "$BLOCK" $(seq 1 $((NUM_NODES-1)))) - SERVED_BEFORE ))
if [ "$SERVED" -ge 1 ]; then
    pass "holders logged ${SERVED} RestoreResponse(s) to the recovered node"
else
    fail "no holder logged a RestoreResponse for block ${BLOCK:-none}"
fi

# ── RESULTS ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 log (last 30 lines) ==="
    tail -30 "$(node_log 0)" 2>/dev/null || echo "  (no log)"
    echo ""
    echo "=== node-01 log (last 20 lines) ==="
    tail -20 "$(node_log 1)" 2>/dev/null || echo "  (no log)"
fi

echo ""
echo "Logs: $TEST_DIR/node-*/daemon.log"
echo "Cleanup: rm -rf $TEST_DIR"

[ "$FAIL" -eq 0 ]
