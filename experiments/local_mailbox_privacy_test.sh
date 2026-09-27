#!/bin/bash
# Viaticum: mailbox privacy E2E (CROWN-1, S1) — what a postman's disk reveals.
# Local processes on one machine (no Docker).
#
# Scenario:     7 nodes. Independent owners A (node-00) and B (node-01) set up with plain
#               `init` (phrases taken from stdout); holders node-02..04; node-05 is a
#               storage-less postman (tiny soft quota); node-06 is A's second device. A and B
#               back up files, PoS, a delete and a device revocation run through the mailbox.
#               node-05's disk is audited offline, junk is planted into it, then A and B are
#               recovered by DR from their phrases, including skewed DR clocks.
# Intent:       mailbox-i1, i2, i3, i4, i5, i6, i7, i9, i10, i13, i15, i16, i17, i18, i19,
#               i20, i23; mailbox-i8 (step 10); dr-i1, dr-i13 (catalog count and table only)
# Environment:  all daemons with RUST_LOG=info,viaticum=debug,viaticum_core=debug (anchors
#               at debug: `mailbox: opened entry`, `address=`, `pointer unchanged for DR`);
#               libfaketime from ~/opt for step 8 (absent -> "cannot close", not PASS).
# Proves:       on another node (the postman's redb, read offline by mailbox-probe) every
#               mailbox entry is sealed (v2, no inner type decodes, no node key / block id /
#               multiaddr bytes, no `sender`), pointer boxes are not addressed by any master
#               or its hash; recipients still act on every class with the right sender;
#               planted junk has no effect; DR by each phrase returns that owner's catalog,
#               also with the DR clock one epoch off, and fails with a clock hint 63 epochs off.
# Adversarial:  offline read of a postman's disk; junk / moved / plaintext / fake-pointer
#               entries planted into a postman; DR with the other owner's phrase; DR clock
#               +31 d, -31 d, +63 epochs; A's second device reads A's mail, then is revoked.
# Cannot close: live-transport linkage (R-1, accepted); > 1000 nodes (G2 targeting);
#               write/read authorization on the wire (needs a custom client: AC-7, AC-9,
#               AC-10 integration tests); shadow copy racing an honest poll (N4, unit);
#               owner republish across a real epoch boundary (variant B, ROUGH);
#               DropNotice from disk pressure / holdings integrity; CancelDelete (no
#               producer); size metadata (R-3); a revoked device still reading mail (R-6);
#               mailbox-i21 (key merge) and i22 (publisher clock) are unit-only; early-stop
#               of the DR walk (unit dr_collects_all_epochs_without_early_stop).
# Steps:        see the table in Part 0 §0.4 S1 of the CROWN-1 spec. Implemented so far
#               (slice C2 skeleton): 1 (setup + backups), 2 (pointer publications), 3 (offline
#               audit of the postman), 9 (log guard, with its positive). Steps 2b, 4-8, 10 are
#               added by C3/C4 and are reported as FAIL "not implemented" until then — the
#               scenario can never go green on a partial run.
#               On the pre-C3 code step 3 MUST be red (plaintext v1 entries, decodable
#               SelfPointer, `sender` present, pointer box = master key). Green there before
#               C3 = the audit is blind = BLOCK.
#
# Usage:
#   private/testing/run_e2e.sh mailbox_privacy     # on the build server, logs the verdict
#   bash experiments/local_mailbox_privacy_test.sh  # needs target/release/{viaticum,mailbox-probe,bootstrap-trust}

set -euo pipefail

NUM_NODES=6            # node-06 (A's second device) joins with step 4 (C4)
POSTMAN=5
TIME_SCALE=100000      # PoS every ~6 s; SS push interval clamps to 60 s
TEST_DIR="/tmp/viaticum-mbxpriv-$$"
BINARY="${BINARY:-viaticum}"
RUST_LOG_NODES="info,viaticum=debug,viaticum_core=debug"

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
    echo "  Test dir: $TEST_DIR (not removed, inspect if needed)"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }
run_cli() { local idx="$1"; shift; "$BINARY" --data-dir "$(node_dir "$idx")" "$@"; }
run_cli_q() { run_cli "$@" 2>/dev/null || true; }
plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null || true; }

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

start_daemon() {
    local i="$1"
    mkdir -p "$(node_dir "$i")/files"
    RUST_LOG="$RUST_LOG_NODES" "$BINARY" --data-dir "$(node_dir "$i")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$i")/files" \
        >> "$(node_log "$i")" 2>&1 &
    PIDS[$i]=$!
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"; exit 1; }
fi
BIN_DIR="$(cd "$(dirname "$(command -v "$BINARY")")" && pwd)"
PROBE="$BIN_DIR/mailbox-probe"
IDTOOL="$BIN_DIR/bootstrap-trust"
[ -x "$PROBE" ] || { echo "ERROR: $PROBE not found (cargo build --release -p viaticum)"; exit 1; }
[ -x "$IDTOOL" ] || { echo "ERROR: $IDTOOL not found"; exit 1; }

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

echo "============================================================"
echo "  Viaticum CROWN-1 S1: mailbox privacy (${NUM_NODES} nodes, time_scale ${TIME_SCALE})"
echo "  Binary: $BINARY   Probe: $PROBE"
echo "  Test dir: $TEST_DIR"
echo "============================================================"

# ── STEP 1: setup, star connect, backups ────────────────────────
echo ""
echo "=== Step 1: setup + backups (A = node-00, B = node-01, postman = node-05) ==="
mkdir -p "$TEST_DIR"
POSTMAN_PORT=$((20000 + RANDOM % 30000))
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    # Phrases of A and B are kept for the DR steps (7-8, C3).
    run_cli "$i" init > "$TEST_DIR/node-$(printf '%02d' "$i").init.txt" 2>&1
    cat > "$(node_dir "$i")/config.toml" << 'CFGEOF'
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0

[escrow]
k_factor = 0.001
CFGEOF
done
# The postman takes no symbols (hard_quota_gb = 0 means "no floor", not "no storage",
# so a ~1 KB soft quota is used) and has a fixed port so it can be restarted.
cat > "$(node_dir $POSTMAN)/config.toml" << CFGEOF
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
soft_quota_gb = 0.000001
[network]
listen_port = $POSTMAN_PORT
[escrow]
k_factor = 0.001
CFGEOF

declare -A MASTER DEVICE
for i in $(seq 0 $((NUM_NODES-1))); do
    ID_JSON=$("$IDTOOL" identity-show --data-dir "$(node_dir "$i")")
    MASTER[$i]=$(echo "$ID_JSON" | jq -r .identity_pub)
    DEVICE[$i]=$(echo "$ID_JSON" | jq -r .device_id)
done
if [ "${MASTER[0]}" = "${MASTER[1]}" ] || [ -z "${MASTER[0]}" ]; then
    fail "A and B must be independent masters (got ${MASTER[0]} / ${MASTER[1]})"
    exit 1
fi

for i in $(seq 0 $((NUM_NODES-1))); do start_daemon "$i"; done
for i in $(seq 0 $((NUM_NODES-1))); do
    wait_daemon "$i" || { fail "node-$i daemon not responding"; tail -20 "$(node_log "$i")"; exit 1; }
done
ADDR_00=$(get_addr 0)
[ -n "$ADDR_00" ] || { fail "cannot get node-00 address"; exit 1; }
for i in $(seq 1 $((NUM_NODES-1))); do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
# The postman also connects to every node directly, so both owners know it.
for i in $(seq 1 $((NUM_NODES-1))); do
    [ "$i" -eq "$POSTMAN" ] && continue
    A=$(get_addr "$i"); [ -n "$A" ] && run_cli_q "$POSTMAN" connect "$A" > /dev/null
done
if wait_auth_peers 0 $((NUM_NODES-1)) 30 && wait_auth_peers "$POSTMAN" $((NUM_NODES-1)) 30; then
    pass "star connect: node-00 and the postman each see $((NUM_NODES-1)) authenticated peers"
else
    fail "connect: node-00 $(status_num 0 peer_count_authenticated), postman $(status_num $POSTMAN peer_count_authenticated) authenticated peers"
fi

F1="$(node_dir 0)/files/f1.bin"; F2="$(node_dir 0)/files/f2.bin"
dd if=/dev/urandom of="$F1" bs=1024 count=64 2>/dev/null
dd if=/dev/urandom of="$F2" bs=1024 count=64 2>/dev/null
for g in 1 2 3 4; do dd if=/dev/urandom of="$(node_dir 1)/files/g$g.bin" bs=1024 count=32 2>/dev/null; done
JOURNAL_A=2; JOURNAL_B=4
ALL_OK=1
for f in "$F1" "$F2"; do wait_file_restorable 0 "$f" 180 || { ALL_OK=0; fail "A: $(basename "$f") not restorable"; }; done
for g in 1 2 3 4; do wait_file_restorable 1 "$(node_dir 1)/files/g$g.bin" 180 || { ALL_OK=0; fail "B: g$g not restorable"; }; done
[ "$ALL_OK" -eq 1 ] && pass "A backed up $JOURNAL_A files, B backed up $JOURNAL_B files (each restorable per owner)"
BLOCK_F1=$(file_block_hex 0 "$F1")
[ -n "$BLOCK_F1" ] || fail "no block id for f1"

# ── STEP 2: pointer publications of A and B ─────────────────────
echo ""
echo "=== Step 2: SelfPointer publications of A and B ==="
PUB_A=0; PUB_B=0
for _ in $(seq 1 60); do
    PUB_A=$(plain_log 0 | grep -ac "SelfPointer published via mailbox" || true)
    PUB_B=$(plain_log 1 | grep -ac "SelfPointer published via mailbox" || true)
    [ "$PUB_A" -ge 1 ] && [ "$PUB_B" -ge 1 ] && break
    sleep 5
done
if [ "$PUB_A" -ge 1 ] && [ "$PUB_B" -ge 1 ]; then
    pass "pointer publications: A $PUB_A, B $PUB_B"
else
    fail "pointer publications: A $PUB_A, B $PUB_B after 300 s"
fi
# C3 contract: the publication line carries epoch= (info) and address= (debug).
ADDR_A=$(plain_log 0 | grep -a "SelfPointer published via mailbox" | grep -oE 'address=[0-9a-f]+' | tail -1 | cut -d= -f2 || true)
ADDR_B=$(plain_log 1 | grep -a "SelfPointer published via mailbox" | grep -oE 'address=[0-9a-f]+' | tail -1 | cut -d= -f2 || true)
if [ -n "$ADDR_A" ] && [ -n "$ADDR_B" ]; then
    pass "publication log names the pointer box: A $ADDR_A, B $ADDR_B"
else
    fail "publication log has no address= for A/B (C3 contract, §0.3)"
fi

# ── STEP 2b: cadence (C3) ────────────────────────────────────────
echo ""
echo "=== Step 2b: pointer cadence ==="
fail "step 2b not implemented (C3: pointer only on DR-relevant change, mailbox-i23)"

# ── STEP 3: offline audit of the postman ────────────────────────
echo ""
echo "=== Step 3: offline audit of the postman (node-05) ==="
BLOCK_SHORT=${BLOCK_F1:0:16}
L0=$(plain_log 0 | wc -l)
POS_OK=0
for _ in $(seq 1 240); do
    if plain_log 0 | tail -n +$((L0 + 1)) | grep -a "mailbox PosResponse resolved" \
        | grep -a "$BLOCK_SHORT" | grep -qa "outcome=Pass"; then POS_OK=1; break; fi
    sleep 0.5
done
# Freeze the postman at once: PoS entries live ~6 s at this time scale.
kill -9 "${PIDS[$POSTMAN]}" 2>/dev/null || true
wait "${PIDS[$POSTMAN]}" 2>/dev/null || true
[ "$POS_OK" -eq 1 ] && pass "A resolved a PoS round for f1 with outcome=Pass" \
    || fail "no PoS Pass for f1 at A within 120 s"

NEEDLES=()
KNOWN=()
for i in $(seq 0 $((NUM_NODES-1))); do
    n=$(printf '%02d' "$i")
    NEEDLES+=(--needle-hex "master$n=${MASTER[$i]}" --needle-hex "device$n=${DEVICE[$i]}")
    NEEDLES+=(--needle-hex "master${n}_sha=$(echo -n "${MASTER[$i]}" | xxd -r -p | sha256sum | cut -c1-64)")
    KNOWN+=(--known "master$n=${MASTER[$i]}" --known "device$n=${DEVICE[$i]}")
done
[ -n "$BLOCK_F1" ] && NEEDLES+=(--needle-hex "block_f1=$BLOCK_F1")
for i in $(seq 0 $((NUM_NODES-1))); do
    port=$(plain_log "$i" | grep -a "swarm listening on new address" | grep -oE '/ip4/[0-9.]+/tcp/[0-9]+' | head -1 | grep -oE '[0-9]+$' || true)
    [ -n "$port" ] && NEEDLES+=(--needle-str "maddr$(printf '%02d' "$i")=/tcp/$port")
done
AUDIT="$TEST_DIR/audit1.json"
if ! "$PROBE" audit --data-dir "$(node_dir $POSTMAN)" "${NEEDLES[@]}" "${KNOWN[@]}" > "$AUDIT" 2> "$TEST_DIR/audit1.err"; then
    fail "mailbox-probe audit failed: $(tail -3 "$TEST_DIR/audit1.err")"
    echo '{"summary":{"total":0},"entries":[]}' > "$AUDIT"
fi
jq -c .summary "$AUDIT"

N_SP=$(jq '[.entries[] | select(.class=="SelfPointer")] | length' "$AUDIT")
N_POS=$(jq '[.entries[] | select(.class=="PosChallenge" or .class=="PosResponse")] | length' "$AUDIT")
N_ALL=$(jq '.entries | length' "$AUDIT")
SP_BYTES=$(jq '[.entries[] | select(.class=="SelfPointer") | .entry_len] | add // 0' "$AUDIT")
echo "  postman holds $N_ALL entries: $N_SP SelfPointer ($SP_BYTES bytes), $N_POS PoS"
# Positive first: an empty postman proves nothing.
if [ "$N_SP" -ge 1 ] && [ "$N_POS" -ge 1 ]; then
    pass "postman holds >= 1 SelfPointer and >= 1 PoS entry (audit is not empty)"
else
    fail "postman holds $N_SP SelfPointer / $N_POS PoS entries — nothing to audit"
fi
# Every check below is vacuous on an empty audit: without entries they FAIL, not PASS.
nonempty() { [ "$N_ALL" -gt 0 ] || { fail "$1: no entries audited"; return 1; }; }
nonempty_sp() { [ "$N_SP" -gt 0 ] || { fail "$1: no SelfPointer audited"; return 1; }; }
NOT_V2=$(jq '[.entries[] | select(.payload_version != 2)] | length' "$AUDIT")
if nonempty "sealed"; then
    [ "$NOT_V2" -eq 0 ] && pass "every entry is sealed (payload_version 2)" \
    || fail "$NOT_V2/$N_ALL entries are not payload_version 2 (plaintext on the postman's disk)"
fi
DECODES=$(jq -r '[.entries[] | select(.decodes_as | length > 0) | "\(.class):\(.decodes_as|join("+"))"] | group_by(.) | map("\(.[0]) x\(length)") | join(", ")' "$AUDIT")
if nonempty "opaque"; then
    [ -z "$DECODES" ] && pass "no payload decodes as an inner message type" \
    || fail "payloads readable by the postman: $DECODES"
fi
SP_READABLE=$(jq '[.entries[] | select(.class=="SelfPointer" and (.decodes_as|index("SelfPointer")))] | length' "$AUDIT")
if nonempty "pointer opaque"; then
    [ "$SP_READABLE" -eq 0 ] && pass "no SelfPointer (recovery map) is readable" \
    || fail "$SP_READABLE SelfPointer entries are readable on the postman (mailbox-i1)"
fi
HITS=$(jq -r '[.entries[] | .needles[]] | group_by(.) | map("\(.[0]) x\(length)") | join(", ")' "$AUDIT")
if nonempty "no identifying bytes"; then
    [ -z "$HITS" ] && pass "no node key / block id / multiaddr bytes in any entry" \
    || fail "identifying bytes in entries: $HITS"
fi
WITH_SENDER=$(jq '[.entries[] | select(.sender_key)] | length' "$AUDIT")
if nonempty "no sender"; then
    [ "$WITH_SENDER" -eq 0 ] && pass "no entry carries a sender field" \
    || fail "$WITH_SENDER/$N_ALL entries carry a sender field (mailbox-i6)"
fi
SP_ADDRESSED=$(jq -r '[.entries[] | select(.class=="SelfPointer" and (.target_is|length>0)) | .target_is[]] | unique | join(",")' "$AUDIT")
if nonempty_sp "pointer box unlinkable"; then
    [ -z "$SP_ADDRESSED" ] && pass "no pointer box equals a master / device key or its SHA256" \
    || fail "pointer boxes are computable from public keys: $SP_ADDRESSED (mailbox-i9)"
fi
DEV_TARGET=$(jq -r '[.entries[] | .target_is[] | select(startswith("device"))] | unique | join(",")' "$AUDIT")
if nonempty "no device box"; then
    [ -z "$DEV_TARGET" ] && pass "no entry is addressed to a device id" \
    || fail "entries addressed to device ids: $DEV_TARGET (F14)"
fi
if [ -n "$ADDR_A" ] && [ -n "$ADDR_B" ]; then
    SP_AT_A=$(jq --arg a "$ADDR_A" '[.entries[] | select(.class=="SelfPointer" and (.target|startswith($a)))] | length' "$AUDIT")
    [ "$ADDR_A" != "$ADDR_B" ] && [ "$SP_AT_A" -eq "$PUB_A" ] \
        && pass "A's pointers: $SP_AT_A at A's box = $PUB_A publications; B's box differs" \
        || fail "A's box holds $SP_AT_A pointers vs $PUB_A publications (A $ADDR_A, B $ADDR_B)"
else
    fail "pointer count per box: cannot attribute pointers without address= (C3)"
fi
echo "  audit: $AUDIT  pointer_count=$N_SP pointer_bytes=$SP_BYTES"

start_daemon "$POSTMAN"
if wait_daemon "$POSTMAN"; then
    run_cli_q "$POSTMAN" connect "$ADDR_00" > /dev/null
    pass "postman restarted after the audit"
else
    fail "postman did not restart"
fi

# ── STEPS 4-8, 10 (C3/C4) ───────────────────────────────────────
echo ""
echo "=== Steps 4-8, 10 ==="
fail "step 4 not implemented (C4: Delete / DropNotice sealed, sibling reads A's mail)"
fail "step 5 not implemented (C4: Revocation sealed)"
fail "step 6 not implemented (C3/C4: planted junk / moved / signed v1 / fake pointer)"
fail "step 7 not implemented (C3: DR by each phrase from the rendezvous boxes)"
fail "step 8 not implemented (C3: DR under skewed clocks, libfaketime)"
fail "step 10 not implemented (C4: missing recipient key -> blocked, visible)"

# ── STEP 9: guard over all logs, with its positive ──────────────
echo ""
echo "=== Step 9: log guard ==="
GUARD=0
for i in $(seq 0 $((NUM_NODES-1))); do
    n=$(plain_log "$i" | grep -acE "mailbox: store rejected — (unauthorized|clock skew|plaintext payload)|mailbox: open failed|recipient key unknown" || true)
    [ "$n" -gt 0 ] && { echo "    node-$i: $n guard lines"; plain_log "$i" | grep -aE "store rejected — (unauthorized|clock skew|plaintext)|open failed|recipient key unknown" | head -3; }
    GUARD=$((GUARD + n))
done
if [ "$PUB_A" -ge 1 ] && [ "$PUB_B" -ge 1 ] && [ "$GUARD" -eq 0 ]; then
    pass "0 unauthorized / clock-skew / plaintext / open-failed / key-unknown lines, with $PUB_A + $PUB_B accepted pointer publications"
else
    fail "guard: $GUARD guard lines (publications A $PUB_A, B $PUB_B)"
fi

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
echo "Logs: $TEST_DIR/node-*/daemon.log   Audit: $AUDIT"
[ "$FAIL" -eq 0 ]
