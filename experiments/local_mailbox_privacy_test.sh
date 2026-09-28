#!/bin/bash
# Viaticum: mailbox privacy E2E (CROWN-1, S1) — what a postman's disk reveals.
# Local processes on one machine (no Docker).
#
# Scenario:     7 nodes. Independent owners A (node-00) and B (node-01) set up with plain
#               `init` (phrases taken from stdout); holders node-02..04; node-05 is a
#               storage-less postman (tiny soft quota); node-06 is A's second device (C4). A and
#               B back up files; PoS, a delete and a device revocation run through the mailbox
#               (C4). node-05's disk is audited offline, junk is planted into it, then A and B
#               are recovered by DR from their phrases.
# Intent:       mailbox-i1, i2, i3, i4, i5, i6, i7, i9, i10, i15, i16, i17, i18, i19, i20;
#               mailbox-i39 (pointer sealed into the phrase's rendezvous box), i40 (DR opens
#               every place without poll or clock), i42 (unit), i46 (≤ 2 places per history,
#               replaced in place; replaces i23), i58 (the other place is re-sealed, never
#               expires while the owner runs); mailbox-i8 (step 10, C4); dr-i1, dr-i13
#               (catalog count and table only), dr-i42
# Stages:       S1_STAGE=c3a (default) | c4. c3a: the pointer group (steps 2, 3-pointer,
#               6(d-f), 7, 9) MUST pass; the directed group (audit of PoS entries, `sender`)
#               MUST be red — it is C4's baseline, green there = the audit is blind; steps
#               2b (C3b), 4, 5, 6(a-c), 10 (C4) print NOT-IN-STAGE. Exit: any FAIL → 1; c3a
#               with every in-stage check passed → 2 (a stage pass is NOT a scenario pass,
#               RS3.10); c4 all passed → 0 (3 when a DR was slower than DR_ROUGH_SECS).
# Environment:  all daemons with RUST_LOG=info,viaticum=debug,viaticum_core=debug (anchors at
#               debug: `system_state push: pointer box address= slot=`, `mailbox: opened
#               entry`). TIME_SCALE=100000: the pointer envelope lives 5 years / 100000 ≈ 26 min
#               of real time and is refreshed every 30 d / 100000 ≈ 26 s while the owner runs —
#               `current` by a new pointer, `other` by re-sealing the same pointer (i58), so no
#               place expires under a running owner. Once A is stopped for DR nothing refreshes
#               its envelopes: step 7 checks that < 20 min passed since A's last pointer store
#               (else FAIL of the set-up, not of the product). DR does not read the clock, so
#               no libfaketime step (the old step 8 is removed).
# Proves:       on another node (the postman's redb, read offline by mailbox-probe) every
#               pointer entry is sealed (v2, no inner type decodes, no node key / block id /
#               multiaddr / catalog history / publisher bytes, no `sender`); pointer boxes are
#               not addressed by any master or its hash; each owner's pointers sit at the
#               rendezvous address the phrase derives offline, in 1-2 entries whose msg_id is
#               one of the history's two place slots, replaced in place (the postman's own
#               log shows replaced=true); planted junk, a swapped place and 20 junk entries of
#               another class change nothing: DR by each phrase returns that owner's catalog
#               while a holder of A's SS base is frozen.
# Adversarial:  offline read of a postman's disk; junk pointer under a random msg_id and newer
#               stored_at; the postman swaps A's current place (inject --replace); 20 junk
#               DropNotice entries in A's rendezvous box; a holder of A's SS base under
#               SIGSTOP during DR; DR with the other owner's phrase in the same network.
#               (C4: moved / plaintext signed v1 / foreign-box copies; A's second device reads
#               A's mail, then is revoked.)
# Cannot close: live-transport linkage (R-1, accepted); > 1000 nodes (G2 targeting);
#               write/read authorization on the wire (needs a custom client: AC-7, AC-9,
#               AC-10 integration tests); DropNotice from disk pressure / holdings integrity;
#               CancelDelete (no producer); size metadata (R-3); a revoked device still
#               reading mail (R-6); mailbox-i21 (key merge) and i22 (publisher clock) are
#               unit-only; the order of DR attempts set by a hostile postman that relabels a
#               head (review N2 → dr-i51, C4); refresh without the time_scale division (churn
#               publishes every tick: blind here, unit AC-24′).
# Steps:        see the table in Part 0 §0.4 S1 of the CROWN-1 spec as amended by V.7,
#               V.15.4, V.16.6 (C3a). 1 setup + backups; 2 publications, address and slot
#               from the owner's debug line == `mailbox-probe rendezvous`; 3 offline audit
#               (pointer group + directed baseline); 6(d-f) + 7 planted junk, DR of A and B;
#               9 log guard with its positive.
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
S1_STAGE="${S1_STAGE:-c3a}"
DR_ROUGH_SECS=600
case "$S1_STAGE" in c3a|c4) ;; *) echo "ERROR: S1_STAGE must be c3a or c4"; exit 1 ;; esac

PASS=0; FAIL=0; ROUGH=0
PIDS=()
NOT_IN_STAGE=()

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
not_in_stage() { echo "  NOT-IN-STAGE ($S1_STAGE): $1"; NOT_IN_STAGE+=("$1"); }
# A step that belongs to C4: FAIL "not implemented" on c4, NOT-IN-STAGE on c3a.
c4_step() {
    if [ "$S1_STAGE" = c4 ]; then fail "$1 not implemented (C4)"; else not_in_stage "$1"; fi
}

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
echo "=== Step 2: SelfPointer publications of A and B; the box and the place from the phrase ==="
PHRASE_A=$(grep -A1 "^Mnemonic" "$TEST_DIR/node-00.init.txt" | tail -1 | sed 's/^ *//')
PHRASE_B=$(grep -A1 "^Mnemonic" "$TEST_DIR/node-01.init.txt" | tail -1 | sed 's/^ *//')
[ "$(echo "$PHRASE_A" | wc -w)" -eq 24 ] && [ "$(echo "$PHRASE_B" | wc -w)" -eq 24 ] \
    || { fail "phrases of A and B not captured from init"; exit 1; }
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
# The owner's debug line of a fresh publication names the box and the place slot (RS3.8).
box_field() {
    plain_log "$1" | grep -a "system_state push: pointer box" | tail -1 \
        | grep -oE "$2=[0-9a-f]+" | cut -d= -f2 || true
}
lineage_of() {
    plain_log "$1" | grep -a "SelfPointer published via mailbox" | tail -1 \
        | grep -oE 'lineage=[0-9a-f]+' | cut -d= -f2 || true
}
ADDR_A=$(box_field 0 address); ADDR_B=$(box_field 1 address)
L_A=$(lineage_of 0); L_B=$(lineage_of 1)
PROBE_A=$("$PROBE" rendezvous --phrase "$PHRASE_A" --lineage "${L_A:-00000000000000000000000000000000}" --json)
PROBE_B=$("$PROBE" rendezvous --phrase "$PHRASE_B" --lineage "${L_B:-00000000000000000000000000000000}" --json)
SLOTS_A="$(echo "$PROBE_A" | jq -r .slot_a) $(echo "$PROBE_A" | jq -r .slot_b)"
SLOTS_B="$(echo "$PROBE_B" | jq -r .slot_a) $(echo "$PROBE_B" | jq -r .slot_b)"
if [ -n "$ADDR_A" ] && [ -n "$ADDR_B" ] && [ ${#L_A} -eq 32 ] && [ ${#L_B} -eq 32 ] \
    && [ "$ADDR_A" = "$(echo "$PROBE_A" | jq -r .address)" ] \
    && [ "$ADDR_B" = "$(echo "$PROBE_B" | jq -r .address)" ] && [ "$ADDR_A" != "$ADDR_B" ]; then
    pass "each owner's pointer box == the rendezvous address of its phrase (offline probe): A ${ADDR_A:0:16}, B ${ADDR_B:0:16}"
else
    fail "pointer box: A '$ADDR_A' vs probe '$(echo "$PROBE_A" | jq -r .address)', B '$ADDR_B' vs '$(echo "$PROBE_B" | jq -r .address)', lineages '$L_A' '$L_B'"
fi
SLOT_CUR_A=$(box_field 0 slot); SLOT_CUR_B=$(box_field 1 slot)
if [ -n "$SLOT_CUR_A" ] && echo " $SLOTS_A " | grep -q " $SLOT_CUR_A " \
    && [ -n "$SLOT_CUR_B" ] && echo " $SLOTS_B " | grep -q " $SLOT_CUR_B "; then
    pass "the published slot is one of the history's two places (A ${SLOT_CUR_A:0:8}…, B ${SLOT_CUR_B:0:8}…)"
else
    fail "published slot not a place of the history: A '$SLOT_CUR_A' ∉ {$SLOTS_A}, B '$SLOT_CUR_B' ∉ {$SLOTS_B}"
fi
RA16=${ADDR_A:0:16}; RB16=${ADDR_B:0:16}

# ── STEP 2b: cadence (C3b) ───────────────────────────────────────
echo ""
echo "=== Step 2b: pointer cadence ==="
not_in_stage "step 2b (C3b: pointer cadence)"

# ── STEP 3: offline audit of the postman ────────────────────────
echo ""
echo "=== Step 3: offline audit of the postman (node-05) ==="
# At least two publications each, and the postman replaced A's place at least once (V.15.4a).
REPL_OK=0
for _ in $(seq 1 36); do
    PUB_A=$(plain_log 0 | grep -ac "SelfPointer published via mailbox" || true)
    PUB_B=$(plain_log 1 | grep -ac "SelfPointer published via mailbox" || true)
    N5=$(sp_store_lines "$RA16" "$POSTMAN" | grep -c . || true)
    R5=$(sp_store_lines "$RA16" "$POSTMAN" | grep -c "replaced=true" || true)
    if [ "$PUB_A" -ge 2 ] && [ "$PUB_B" -ge 2 ] && [ "$N5" -ge 2 ] && [ "$R5" -ge 1 ]; then REPL_OK=1; break; fi
    sleep 5
done
if [ "$REPL_OK" -eq 1 ]; then
    pass "set-up: A $PUB_A, B $PUB_B publications; the postman logged $N5 stores for A's box, $R5 of them replaced=true"
else
    fail "set-up: A $PUB_A, B $PUB_B publications, postman stores for A's box $N5 (replaced=true $R5) — the 1-2 entries below would not show replacement"
fi
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
# The pointer's catalog summary: history ids and the publishing device (catalog.publisher).
[ ${#L_A} -eq 32 ] && NEEDLES+=(--needle-hex "lineage_A=$L_A")
[ ${#L_B} -eq 32 ] && NEEDLES+=(--needle-hex "lineage_B=$L_B")
NEEDLES+=(--needle-hex "publisher_A=${DEVICE[0]}" --needle-hex "publisher_B=${DEVICE[1]}")
[ -n "$BLOCK_F1" ] && NEEDLES+=(--needle-hex "block_f1=$BLOCK_F1")
for i in $(seq 0 $((NUM_NODES-1))); do
    port=$(plain_log "$i" | grep -a "swarm listening on new address" | grep -oE '/ip4/[0-9.]+/tcp/[0-9]+' | head -1 | grep -oE '[0-9]+$' || true)
    [ -n "$port" ] && NEEDLES+=(--needle-str "maddr$(printf '%02d' "$i")=/tcp/$port")
done
# run_audit OUT: offline audit of the (stopped) postman into OUT.
run_audit() {
    if ! "$PROBE" audit --data-dir "$(node_dir $POSTMAN)" "${NEEDLES[@]}" "${KNOWN[@]}" > "$1" 2> "$1.err"; then
        fail "mailbox-probe audit failed: $(tail -3 "$1.err")"
        echo '{"summary":{"total":0},"entries":[]}' > "$1"
    fi
}
AUDIT="$TEST_DIR/audit1.json"
run_audit "$AUDIT"
jq -c .summary "$AUDIT"

N_SP=$(jq '[.entries[] | select(.class=="SelfPointer")] | length' "$AUDIT")
N_DIR=$(jq '[.entries[] | select(.class!="SelfPointer")] | length' "$AUDIT")
N_POS=$(jq '[.entries[] | select(.class=="PosChallenge" or .class=="PosResponse")] | length' "$AUDIT")
N_ALL=$(jq '.entries | length' "$AUDIT")
SP_BYTES=$(jq '[.entries[] | select(.class=="SelfPointer") | .entry_len] | add // 0' "$AUDIT")
echo "  postman holds $N_ALL entries: $N_SP SelfPointer ($SP_BYTES bytes), $N_POS PoS, $N_DIR directed in total"
# Positive first: an empty postman proves nothing.
if [ "$N_SP" -ge 1 ] && [ "$N_POS" -ge 1 ]; then
    pass "postman holds >= 1 SelfPointer and >= 1 PoS entry (audit is not empty)"
else
    fail "postman holds $N_SP SelfPointer / $N_POS PoS entries — nothing to audit"
fi
nonempty_sp() { [ "$N_SP" -gt 0 ] || { fail "$1: no SelfPointer audited"; return 1; }; }
nonempty() { [ "$N_ALL" -gt 0 ] || { fail "$1: no entries audited"; return 1; }; }

# ---- pointer group (in stage from c3a) ----
SP_NOT_V2=$(jq '[.entries[] | select(.class=="SelfPointer" and .payload_version != 2)] | length' "$AUDIT")
if nonempty_sp "pointer sealed"; then
    [ "$SP_NOT_V2" -eq 0 ] && pass "every SelfPointer is sealed (payload_version 2)" \
    || fail "$SP_NOT_V2/$N_SP SelfPointer entries are not payload_version 2"
fi
SP_DECODES=$(jq -r '[.entries[] | select(.class=="SelfPointer" and (.decodes_as | length > 0)) | .decodes_as | join("+")] | unique | join(", ")' "$AUDIT")
if nonempty_sp "pointer opaque"; then
    [ -z "$SP_DECODES" ] && pass "no SelfPointer payload decodes as any inner type (the recovery map is unreadable)" \
    || fail "SelfPointer payloads readable by the postman: $SP_DECODES (mailbox-i1)"
fi
SP_HITS=$(jq -r '[.entries[] | select(.class=="SelfPointer") | .needles[]] | group_by(.) | map("\(.[0]) x\(length)") | join(", ")' "$AUDIT")
if nonempty_sp "pointer no identifying bytes"; then
    [ -z "$SP_HITS" ] && pass "no node key / block id / multiaddr / history / publisher bytes in any SelfPointer" \
    || fail "identifying bytes in SelfPointer entries: $SP_HITS"
fi
# Spec §7.6: the pointer header has sender = None from C3; the `sender` field itself leaves
# MailboxEntry in C4 (with the directed classes). So c3a: no pointer NAMES a sender (the
# value is null — publisher bytes are also searched as needles above); c4: no key at all.
SP_SENDER_SET=$(jq '[.entries[] | select(.class=="SelfPointer" and .sender_non_null)] | length' "$AUDIT")
SP_SENDER_KEY=$(jq '[.entries[] | select(.class=="SelfPointer" and .sender_key)] | length' "$AUDIT")
if nonempty_sp "pointer no sender"; then
    if [ "$S1_STAGE" = c3a ]; then
        [ "$SP_SENDER_SET" -eq 0 ] && pass "no SelfPointer names a sender (sender = null in $SP_SENDER_KEY/$N_SP; the header field goes in C4)" \
        || fail "$SP_SENDER_SET SelfPointer entries name a sender (mailbox-i6, spec §7.6: None from C3)"
    else
        [ "$SP_SENDER_KEY" -eq 0 ] && pass "no SelfPointer carries a sender field (C4)" \
        || fail "$SP_SENDER_KEY SelfPointer entries carry a sender field (mailbox-i6)"
    fi
fi
SP_ADDRESSED=$(jq -r '[.entries[] | select(.class=="SelfPointer" and (.target_is|length>0)) | .target_is[]] | unique | join(",")' "$AUDIT")
if nonempty_sp "pointer box unlinkable"; then
    [ -z "$SP_ADDRESSED" ] && pass "no pointer box equals a master / device key or its SHA256 (the master box holds no pointer)" \
    || fail "pointer boxes are computable from public keys: $SP_ADDRESSED (mailbox-i9, i39)"
fi
DEV_TARGET=$(jq -r '[.entries[] | .target_is[] | select(startswith("device"))] | unique | join(",")' "$AUDIT")
if nonempty "no device box"; then
    [ -z "$DEV_TARGET" ] && pass "no entry is addressed to a device id" \
    || fail "entries addressed to device ids: $DEV_TARGET (F14)"
fi
# places_at ADDR SLOTS: "<count> <msg_ids not in SLOTS>" of the SelfPointer entries at ADDR.
places_at() {
    local ids bad="" id
    ids=$(jq -r --arg a "$1" '[.entries[] | select(.class=="SelfPointer" and .target==$a) | .msg_id] | .[]' "$AUDIT")
    for id in $ids; do echo " $2 " | grep -q " $id " || bad="$bad $id"; done
    echo "$(echo "$ids" | grep -c . || true) ${bad# }"
}
read -r N_SP_A BAD_A <<< "$(places_at "$ADDR_A" "$SLOTS_A")"
read -r N_SP_B BAD_B <<< "$(places_at "$ADDR_B" "$SLOTS_B")"
if [ -n "$ADDR_A" ] && [ "$N_SP_A" -ge 1 ] && [ "$N_SP_A" -le 2 ] && [ -z "${BAD_A:-}" ] \
    && [ "$N_SP_B" -ge 1 ] && [ "$N_SP_B" -le 2 ] && [ -z "${BAD_B:-}" ]; then
    pass "A's box holds $N_SP_A, B's box $N_SP_B pointer entries, every msg_id one of the history's two places (i46)"
else
    fail "places: A $N_SP_A entries (foreign msg_ids: ${BAD_A:-none}), B $N_SP_B (foreign: ${BAD_B:-none}); want 1-2 each, msg_id ∈ place slots"
fi
echo "  audit: $AUDIT  pointer_count=$N_SP pointer_bytes=$SP_BYTES"

# ---- directed group (C4): at c3a its entries are still plaintext = the baseline ----
DIR_OPEN=$(jq '[.entries[] | select(.class!="SelfPointer" and (.payload_version != 2 or (.decodes_as|length>0) or .sender_key or (.needles|length>0)))] | length' "$AUDIT")
DIR_WHAT=$(jq -r '[.entries[] | select(.class!="SelfPointer" and (.payload_version != 2 or (.decodes_as|length>0) or .sender_key)) | "\(.class):v\(.payload_version)\(if .sender_key then "+sender" else "" end)"] | group_by(.) | map("\(.[0]) x\(length)") | join(", ")' "$AUDIT")
if [ "$N_DIR" -eq 0 ]; then
    fail "directed group: no directed entry audited — the baseline cannot be judged"
elif [ "$S1_STAGE" = c3a ]; then
    [ "$DIR_OPEN" -gt 0 ] && pass "directed baseline (C4 to seal): $DIR_OPEN/$N_DIR directed entries still readable on the postman ($DIR_WHAT)" \
    || fail "directed group already sealed at stage c3a: the audit is blind or C4 has landed (run S1_STAGE=c4)"
else
    [ "$DIR_OPEN" -eq 0 ] && pass "every directed entry sealed, opaque, without sender (C4)" \
    || fail "directed entries readable on the postman: $DIR_OPEN/$N_DIR ($DIR_WHAT)"
fi

start_daemon "$POSTMAN"
ADDR_01=$(get_addr 1)
if wait_daemon "$POSTMAN"; then
    run_cli_q "$POSTMAN" connect "$ADDR_00" > /dev/null
    pass "postman restarted after the audit"
else
    fail "postman did not restart"
fi

# ── STEPS 4-6(a-c) (C4) ─────────────────────────────────────────
echo ""
echo "=== Steps 4, 5, 6(a-c) ==="
c4_step "step 4 (Delete / DropNotice sealed, sibling reads A's mail)"
c4_step "step 5 (Revocation sealed)"
c4_step "step 6(a-c) (junk DeleteRequest, foreign-box copy, signed plaintext v1 DropNotice)"

# ── STEPS 6(d-f) + 7: junk in A's box, then DR of A and B ───────
echo ""
echo "=== Steps 6(d-f) + 7: the postman plants junk and swaps A's place; DR by each phrase ==="
# A holder of A's SS base is frozen during DR (RS3.10): DR must still converge.
BASE_A16=$(plain_log 0 | grep -aE "system_state push: (base published|compacted to new base)" | tail -1 \
    | grep -oE 'base=[0-9a-f]+' | cut -d= -f2 || true)
BASE_HOLDERS=$(holders_of_prefix "$BASE_A16" 2 3 4 1)
FROZEN=$(echo "$BASE_HOLDERS" | awk '{print $1}')
[ -n "$FROZEN" ] || fail "no holder of A's SS base $BASE_A16 found on disk (nodes 01-04)"
SLOT_CUR_A=$(box_field 0 slot)
LAST_STORE_A=$(plain_log 0 | grep -aE "SelfPointer published via mailbox|pointer envelope re-sealed" | tail -1 | awk '{print $1}' || true)
LAST_STORE_A=$(date -d "$LAST_STORE_A" +%s 2>/dev/null || echo 0)
FILES_API_A=$(api_get 0 /api/files | jq '[.[] | select(.status != "Deleted")] | length' 2>/dev/null || echo "?")
echo "  A's catalog before the loss: $FILES_API_A live file(s) by /api/files (journal $JOURNAL_A)"
kill "${PIDS[0]}" 2>/dev/null || true; wait "${PIDS[0]}" 2>/dev/null || true
AGE=$(( $(date +%s) - LAST_STORE_A ))
if [ "$LAST_STORE_A" -gt 0 ] && [ "$AGE" -lt 1200 ]; then
    pass "set-up: A stopped ${AGE}s after its last pointer store (< 20 min of the ~26 min envelope life)"
else
    fail "set-up: A's last pointer store ${AGE}s ago (≥ 20 min or none): its envelopes may expire before DR"
fi
kill "${PIDS[$POSTMAN]}" 2>/dev/null || true; wait "${PIDS[$POSTMAN]}" 2>/dev/null || true
AUD_PRE="$TEST_DIR/audit-pre-inject.json"
AUDIT="$AUD_PRE"; run_audit "$AUDIT"
read -r N_SP_A7 _ <<< "$(places_at "$ADDR_A" "$SLOTS_A")"
PD="$(node_dir $POSTMAN)"
NOW=$(date +%s)
MSG_D=$("$PROBE" inject --data-dir "$PD" --target "$ADDR_A" --class SelfPointer --junk-len 2000 \
    --stored-at $((NOW + 60)) | jq -r .msg_id || true)
for _ in $(seq 1 20); do
    "$PROBE" inject --data-dir "$PD" --target "$ADDR_A" --class DropNotice --junk-len 200 > /dev/null || fail "inject (e) failed"
done
REPL_F=$("$PROBE" inject --data-dir "$PD" --target "$ADDR_A" --class SelfPointer --msg-id "$SLOT_CUR_A" \
    --replace --junk-len 2000 | jq -r .replaced || true)
AUD_POST="$TEST_DIR/audit-post-inject.json"
AUDIT="$AUD_POST"; run_audit "$AUDIT"
read -r N_SP_AI _ <<< "$(places_at "$ADDR_A" "$SLOTS_A $MSG_D")"
N_DN_A=$(jq --arg a "$ADDR_A" '[.entries[] | select(.class=="DropNotice" and .target==$a)] | length' "$AUDIT")
if [ ${#MSG_D} -eq 32 ] && [ "$REPL_F" = "true" ] && [ "$N_SP_AI" -eq $((N_SP_A7 + 1)) ] && [ "$N_DN_A" -eq 20 ]; then
    pass "planted: (d) junk pointer ${MSG_D:0:8}…, (e) 20 junk DropNotice, (f) A's place ${SLOT_CUR_A:0:8}… swapped; A's box $N_SP_A7 → $N_SP_AI pointer entries"
else
    fail "planting: (d) '${MSG_D}', (f) replaced=$REPL_F, pointers at A's box $N_SP_A7 → $N_SP_AI (want +1), DropNotice $N_DN_A (want 20)"
fi
start_daemon "$POSTMAN"
wait_daemon "$POSTMAN" || fail "postman did not restart after planting"
for i in 1 2 3 4; do
    A_I=$(get_addr "$i"); [ -n "$A_I" ] && run_cli_q "$POSTMAN" connect "$A_I" > /dev/null
done
POSTMAN_ADDR=$(get_addr "$POSTMAN")
wait_auth_peers "$POSTMAN" 4 60 || fail "postman has $(status_num $POSTMAN peer_count_authenticated)/4 peers after planting"
[ -n "$FROZEN" ] && kill -STOP "${PIDS[$FROZEN]}" 2>/dev/null || true
echo "  node-0$FROZEN (holder of A's SS base ${BASE_A16}) frozen for the DR"

# run_dr LABEL PHRASE: DR on a clean folder seeded by the postman.
run_dr() {
    local label="$1" phrase="$2" t0
    DR_DIR="$TEST_DIR/dr-$label"; DR_LOG="$TEST_DIR/dr-$label.log"
    rm -rf "$DR_DIR"; mkdir -p "$DR_DIR"
    t0=$(date +%s)
    set +e
    RUST_LOG=info timeout 900 "$BINARY" --data-dir "$DR_DIR" dr --mnemonic "$phrase" --peer "$POSTMAN_ADDR" \
        > "$DR_LOG" 2>&1
    DR_RC=$?
    set -e
    DR_WALL=$(( $(date +%s) - t0 ))
    FILES_N=$(grep -a "^  Files:" "$DR_LOG" | grep -oE '[0-9]+' | tail -1 || true)
    GOT_I=$(awk '/^Identity restored:/ {print $3}' "$DR_LOG")
    ROWS=$(grep -ac "^  catalog=" "$DR_LOG" || true)
    SEL=$(grep -a "^  catalog=" "$DR_LOG" | grep -c "\[selected" || true)
    echo "    dr[$label] exit=$DR_RC wall=${DR_WALL}s Files=${FILES_N:-none} rows=$ROWS log=$DR_LOG"
    if [ "$DR_RC" -eq 0 ] && [ "$DR_WALL" -gt "$DR_ROUGH_SECS" ]; then
        echo "  ROUGH: DR[$label] took ${DR_WALL}s > ${DR_ROUGH_SECS}s"; ROUGH=1
    fi
}
plain_dr() { sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG"; }

run_dr A "$PHRASE_A"
if [ "$DR_RC" -eq 0 ] && [ "$GOT_I" = "${MASTER[0]}" ] && [ "${FILES_N:-0}" -eq "$JOURNAL_A" ] \
    && [ "$ROWS" -eq 1 ] && [ "$SEL" -eq 1 ]; then
    pass "DR by A's phrase: identity A, Files == $FILES_N (journal $JOURNAL_A), one history [selected], ${DR_WALL}s with node-0$FROZEN frozen"
else
    fail "DR A: exit $DR_RC identity=${GOT_I:0:16} (A ${MASTER[0]:0:16}) Files=${FILES_N:-none} rows=$ROWS selected=$SEL: $(plain_dr | grep -a '^error:' | tail -1)"
fi
# grep -c, not -q: under pipefail an early-exiting grep -q SIGPIPEs sed (exit 141) and a
# present line reads as missing.
RBOX_A=$(plain_dr | grep -ac "dr: rendezvous box address=$RA16" || true)
[ "$RBOX_A" -ge 1 ] && pass "DR A asked A's rendezvous box $RA16" \
    || fail "DR A log has no 'dr: rendezvous box address=$RA16'"
OF_D=$(plain_dr | grep -a "mailbox: open failed" | grep -ac "msg_id=$MSG_D" || true)
OF_F=$(plain_dr | grep -a "mailbox: open failed" | grep -ac "msg_id=$SLOT_CUR_A" || true)
OF_OTHER=$(plain_dr | grep -a "mailbox: open failed" | grep -avE "msg_id=($MSG_D|$SLOT_CUR_A)" | grep -c . || true)
if [ "$OF_D" -ge 1 ] && [ "$OF_F" -ge 1 ] && [ "$OF_OTHER" -eq 0 ]; then
    pass "DR A skipped the planted pointers: open failed ×$OF_D for (d), ×$OF_F for the swapped place (f), no other"
else
    fail "DR A open failed: (d) $OF_D, (f) $OF_F, other $OF_OTHER (want ≥1, ≥1, 0)"
fi
FR5=$(plain_dr | grep -a "dr_walk: fetch response from peer" | grep -a "device=${DEVICE[$POSTMAN]:0:16}" | tail -1 || true)
E5=$(log_field "$FR5" entries)
if [ -n "$E5" ] && [ "$E5" -eq "$N_SP_AI" ]; then
    pass "the postman answered DR with $E5 entries = its $N_SP_AI pointer entries in A's box; the 20 DropNotice did not come (i20)"
else
    fail "postman's DR answer: entries='${E5:-none}' (want $N_SP_AI pointers; 20 DropNotice must not come): '$FR5'"
fi
[ -n "$FROZEN" ] && kill -CONT "${PIDS[$FROZEN]}" 2>/dev/null || true

run_dr B "$PHRASE_B"
if [ "$DR_RC" -eq 0 ] && [ "$GOT_I" = "${MASTER[1]}" ] && [ "${FILES_N:-0}" -eq "$JOURNAL_B" ] \
    && [ "$ROWS" -eq 1 ] && [ "$SEL" -eq 1 ]; then
    pass "DR by B's phrase: identity B, Files == $FILES_N (journal $JOURNAL_B), one history [selected], ${DR_WALL}s"
else
    fail "DR B: exit $DR_RC identity=${GOT_I:0:16} (B ${MASTER[1]:0:16}) Files=${FILES_N:-none} rows=$ROWS selected=$SEL: $(plain_dr | grep -a '^error:' | tail -1)"
fi
OF_B=$(plain_dr | grep -ac "mailbox: open failed" || true)
[ "$OF_B" -eq 0 ] && pass "DR B opened nothing planted (junk sits in A's box only)" \
    || fail "DR B logged $OF_B open failed line(s)"
echo "  (step 8 removed in C3a: DR does not read the clock)"

# ── STEP 9: guard over all daemon logs, with its positive ───────
echo ""
echo "=== Step 9: log guard ==="
GUARD=0
for i in $(seq 0 $((NUM_NODES-1))); do
    n=$(plain_log "$i" | grep -acE "mailbox: store rejected — (unauthorized|clock skew|plaintext payload)|mailbox: open failed|recipient key unknown|SelfPointer in the master box — dropped" || true)
    [ "$n" -gt 0 ] && { echo "    node-$i: $n guard lines"; plain_log "$i" | grep -aE "store rejected — (unauthorized|clock skew|plaintext)|open failed|recipient key unknown|SelfPointer in the master box" | head -3; }
    GUARD=$((GUARD + n))
done
if [ "$PUB_A" -ge 1 ] && [ "$PUB_B" -ge 1 ] && [ "$GUARD" -eq 0 ]; then
    pass "0 unauthorized / clock-skew / plaintext / open-failed / key-unknown / pointer-in-master-box lines, with $PUB_A + $PUB_B accepted pointer publications"
else
    fail "guard: $GUARD guard lines (publications A $PUB_A, B $PUB_B)"
fi

# ── STEP 10 (C4) ────────────────────────────────────────────────
c4_step "step 10 (missing recipient key -> blocked, visible)"

echo ""
echo "============================================================"
echo "  RESULTS (stage $S1_STAGE): $PASS passed, $FAIL failed, ${#NOT_IN_STAGE[@]} not in stage$([ "$ROUGH" -eq 1 ] && echo ', ROUGH (slow DR)')"
for x in "${NOT_IN_STAGE[@]}"; do echo "    not in stage: $x"; done
echo "============================================================"
echo "Logs: $TEST_DIR/node-*/daemon.log  DR: $TEST_DIR/dr-*.log  Audits: $TEST_DIR/audit*.json"
[ "$FAIL" -eq 0 ] || exit 1
if [ "$S1_STAGE" != c4 ]; then
    echo "STAGE $S1_STAGE PASSED — not a scenario PASS (that needs stage c4, RS3.10)"
    exit 2
fi
[ "$ROUGH" -eq 0 ] || exit 3
exit 0
