#!/bin/bash
# Viaticum: a returned file is protected again (line C, L1b).
# Local processes on one machine (no Docker).
#
# Scenario:     5 daemons, independent masters, star to node-00, time_scale 20000 (owner and
#               holder delete windows ~120 s, Delete mailbox TTL ~60 s, periodic rescan 60 s).
#               node-00 backs up single-file packs R, R2, Y, Z, S and a pack M = m1..m3; a file Q
#               is queued and the owner is killed -9 before the flush. Then R R2 Y Z S M are
#               deleted; S comes back before the Delete (to its path and as a copy under dl/);
#               after the holders mark the blocks for deletion R2 comes back to its path inside
#               the Delete replay window, Y comes back under another path, R comes back to its
#               path after the replay window, and m2 comes back while the owner is stopped.
# Intent:       backup-i8, backup-i21, delete-i9, backup-i25, delete-i6 (N1), delete-i1 (control),
#               delete-i8/delete-i5 (boundary: the pack is not revived), restore-i1.
#               private/intent/backup.md, delete.md
# Proves:       on holder disks and logs: a file returned after its Delete gets a NEW block id
#               (a new generation when the plaintext is the same), is stored again on >= 2
#               holders, survives past the moment the old block is wiped everywhere, is never
#               marked for deletion although the old Delete is replayed, and restores from the
#               network by sha256; a file returned before its Delete costs no new block and never
#               gets a Delete; a queued file survives a kill -9 without waiting for a scan.
# Adversarial:  return inside the Delete replay window (5); same content under another path (6);
#               return while the owner is stopped (8); kill -9 between enqueue and flush (1b).
# Cannot close: the race return x deletion tick on a stale snapshot (units reconcile_*); real
#               4-week windows and 14-day TTL; an owner off longer than the window before L2 W1;
#               DR from a snapshot older than the Delete; a postman keeping a Delete past its TTL;
#               the Stale window (L2); the large-file Single path (units); a pack with an
#               unrebuildable member as a dedup target (L2 K-5); cluster siblings; the worker race
#               (units, repair-i16); is_safe_to_delete (units); a file put back while the node is
#               off in production (weekly startup scan, Q2).
# Expectation:  RED on vps/l0 baaf3eb (before L1b): 1b (Q waits for the 60 s periodic rescan), 5,
#               6, 7, 8 (the returned file dedups onto the block being released: last block = the
#               old id), 9 (no symbols of the returned files after the windows), 10 (no new id),
#               11 (restore of R, R2, Y-again, m2 fails: holders wiped or do not serve the block).
#               Step 3 is GREEN on the old code too (guard). GREEN after L1b (K1-K3).
# Steps:        see private/beta-planning/tasks/c_l1b_serviceable_block.md §0.3 (v1.1)
#   0.  init 5; node-00 [[watch]] files/; start; star; assert_delete_window 20000 100;
#       TTL + 25 < W and TTL + sweep < W_h (from the constants) → 4 authenticated <= 90 s
#   1.  R, R2, Y, Z, S (256 KiB random) moved in one by one after the previous is restorable;
#       m1..m3 (64 KiB) by one mv; copies in $T/stash → each restorable <= 60 s; XR XR2 XY XZ
#       XS pairwise different; m1..m3 on one PM (else FAIL "setup: pack not built"); each block
#       >= k_eff on holder disks
#   1b. ADVERSARIAL kill -9 before the flush: wait for node-00's "periodic rescan complete"
#       (<= 70 s) → mv Q.bin in; sleep 0.4; kill -9; start (a fresh Qn.bin on each repeat).
#       setup: no "pipeline complete" after LINE_Q before the kill (else repeat with sleep 0.2,
#       <= 2 times; FAIL setup); Q in the catalog <= 5 s (else the kill beat the event: repeat
#       with sleep 0.6); "scan skipped (last scan recent enough)" in the new instance (else
#       repeat, <= 2 times, then ROUGH); <= 10 s from the start Q backed up and "reconcile:
#       resubmitted root=…/files … pending=N", N >= 1; <= 20 s after wait_auth_peers 4, Q >=
#       k_eff on holders; no periodic rescan in the window (else repeat) (backup-i25)
#   2.  T_del: one rm of R R2 Y Z S m1 m2 m3 → all eight deleted <= 15 s
#   3.  at T_del + 30: cp stash/S files/S.bin and files/dl/S-copy.bin → <= 15 s both on XS;
#       0 "pipeline complete" and 0 "content returned but its block is being released" for
#       S / S-copy in 15 s (positive control: pipeline lines exist from the seed); T_retS <=
#       T_del + W - 30 (backup-i21)
#   4.  first "holding marked for deletion" for XR, XR2, XY, PM (deadline T_del + W + 60) →
#       T_mark*; the owner logged "sent DeleteMsg via mailbox" for each (else FAIL "not in
#       window, nothing proven"). Step 5 fires as soon as XR2 is marked.
#   5.  ADVERSARIAL (replay window): <= T_markR2 + 5 cp stash/R2 files/R2.bin; T_retR2 <=
#       T_markR2 + TTL - 30 → <= 30 s R2 backed up on XR2' != XR2 (else FAIL "returned onto the
#       block being released"); owner "content returned …" and "sealed as a new generation …
#       seal_generation=1" with XR2' (none → FAIL setup "same-plaintext path not exercised");
#       <= 60 s "stored symbols for block" XR2' on >= 2 holders (backup-i8, delete-i9)
#   6.  after 5, at >= T_markY + 5: cp stash/Y files/dl/Y-again.bin → <= 30 s on XY' != XY,
#       backed up (else FAIL "dedup onto a block being released"); >= 2 holders store XY'
#       <= 60 s (backup-i21)
#   7.  at T_markR + TTL + 5: cp stash/R files/R.bin; T_retR <= T_del + 2W - 20 (else ROUGH
#       "timing", step skipped) → <= 30 s XR' != XR, "seal_generation=1" with XR'; >= 2
#       holders store XR' <= 60 s (backup-i8)
#   8.  ADVERSARIAL SIGTERM node-00 (exit 0 <= 15 s); cp stash/m2 files/m2.bin; start → 4 peers
#       <= 90 s; <= 90 s m2 backed up on YM2 != PM (start or periodic scan); >= 2 holders
#       store YM2 <= 60 s (backup-i8)
#   9.  wait until T_del + 2W + 45 → controls: holder symbols of XZ 0 (else FAIL "windows did
#       not pass: nothing proven"), PM 0 (the pack is not revived), XR 0, XR2 0, XY 0.
#       Protection: XR', XR2', XY', YM2, XS >= k_eff (poll <= 60 s), stable 10 s; no holder
#       marked XS for deletion (backup-i8, backup-i21, delete-i1, delete-i8)
#   10. wait until T_markR2 + TTL + W + 30 → 0 "holding marked for deletion" for XR2' after
#       LINE_H2 (the old Delete was replayed until T_pub + TTL); XR2' >= k_eff; the owner sent
#       no DeleteMsg for XR2' or XR' (delete-i9, delete-i6)
#   11. SERVED_XR, SERVED_XR2; rm R R2 dl/Y-again m2 S → deleted <= 15 s (T_fin); restore each
#       from the network; before each window_left T_fin > 0, else ROUGH "timing" and the rest
#       is skipped → sha matches for all five; RestoreResponse >= 1 for XR', XR2', XY', YM2,
#       XS; RestoreResponse growth for XR and XR2 = 0 (informational: the old generations are
#       wiped by then) (backup-i8, restore-i1)
#   12. SIGTERM all → exit 0 <= 15 s; no `panicked` in any log (network-i1)
# Verdicts:     PASS / ROUGH (timing) / FAIL; exit 0 / 3 / 1. ≈ 12 min.
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_revive_test.sh

set -euo pipefail

NUM_NODES=5
# Owner and holder delete windows 4 weeks / 20000 ≈ 120 s; Delete mailbox TTL 14 d / 20000
# ≈ 60 s; mailbox sweep 6 h / 20000 → 1 s; periodic rescan max(604800 / ts, 60) = 60 s;
# idle flush 1 s; reconcile max(3600 / ts, 60) = 60 s.
TIME_SCALE=20000
T="/tmp/viaticum-revive-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)
# Keep in sync with crates/viaticum-core/src/mailbox/mod.rs (class_config::DELETE_REQUEST_TTL),
# constants.rs (HOLDER_DELETE_COOLDOWN_SECS, MAILBOX_SWEEP_INTERVAL_SECS).
DELETE_REQUEST_TTL_SECS=1209600
HOLDER_DELETE_COOLDOWN_SECS=2419200
MAILBOX_SWEEP_INTERVAL_SECS=21600
# A restore is started only while this many seconds of the owner window are left.
WINDOW_MARGIN=10

PASS=0; FAIL=0; ROUGH=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
rough() { echo "  ROUGH: $1"; ((ROUGH++)) || true; }

node_dir() { echo "$T/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }

run_cli() {
    local idx="$1"; shift
    "$BINARY" --data-dir "$(node_dir "$idx")" "$@"
}
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

# has TEXT PATTERN: does TEXT contain PATTERN (fixed string)? No pipe (see local_watch_test).
has() { grep -qF -- "$2" <<< "$1"; }

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

declare -A DPID

start_node() {
    local i="$1" dir; dir=$(node_dir "$i")
    if [ "$i" -eq 0 ]; then
        # node-00's folder comes from config.toml ([[watch]] files/).
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            >> "$(node_log "$i")" 2>&1 &
    else
        mkdir -p "$dir/files"
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            --watch-dir "$dir/files" >> "$(node_log "$i")" 2>&1 &
    fi
    DPID[$i]=$!
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    local i p
    for i in "${!DPID[@]}"; do kill -CONT "${DPID[$i]}" 2>/dev/null || true; done
    for i in "${!DPID[@]}"; do kill -TERM "${DPID[$i]}" 2>/dev/null || true; done
    sleep 1
    for i in "${!DPID[@]}"; do
        p="${DPID[$i]}"; kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
    done
    echo "  Test dir: $T"
}
trap cleanup EXIT

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
fi
if [ ! -x "$BINARY" ] && ! command -v "$BINARY" &>/dev/null; then
    echo "ERROR: viaticum binary not found. Run: ./rbuild.sh"
    exit 1
fi
BINARY="$(realpath "$(command -v "$BINARY" || echo "$BINARY")")"

# Log times are read from the logs' own RFC 3339 stamps: T_BASE = 0 → unix seconds.
T_BASE=0

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

ZERO_BLOCK=$(printf '0%.0s' $(seq 1 64))

# Sum of symbol files of BLOCK_HEX over all holder disks.
symbols_on_holders() {
    local total=0 i
    for i in "${HOLDERS[@]}"; do
        total=$((total + $(block_symbols_on "$i" "$1")))
    done
    echo "$total"
}

# on_holders PATH: the latest version of PATH (node-00's catalog) is on a real block in
# service and holder disks hold >= k_eff of its symbols. Sets OH_BLOCK, OH_TARGET, OH_ON.
on_holders() {
    OH_BLOCK=$(file_block_hex 0 "$1")
    OH_TARGET=$(file_field 0 "$1" '.effective_status.target // 0')
    OH_ON=0
    [ -n "$OH_BLOCK" ] && [ "$OH_BLOCK" != "$ZERO_BLOCK" ] || return 1
    OH_ON=$(symbols_on_holders "$OH_BLOCK")
    [ "${OH_TARGET:-0}" -gt 0 ] && [ "$OH_ON" -ge "$OH_TARGET" ]
}

wait_on_holders() {
    for _ in $(seq 1 "$2"); do
        on_holders "$1" && return 0
        sleep 1
    done
    on_holders "$1"
}

# wait_last_block PATH WANT_HEX SECS: poll until the latest version of PATH is on WANT_HEX.
wait_last_block() {
    for _ in $(seq 1 "$3"); do
        [ "$(file_block_hex 0 "$1")" = "$2" ] && return 0
        sleep 1
    done
    return 1
}

# wait_block_change PATH OLD_HEX SECS: poll until the latest version of PATH is on a real
# block other than OLD_HEX; prints it. (`file_block_hex` is empty while pending.)
wait_block_change() {
    local b
    for _ in $(seq 1 "$3"); do
        b=$(file_block_hex 0 "$1")
        if [ -n "$b" ] && [ "$b" != "$2" ] && [ "$b" != "$ZERO_BLOCK" ]; then
            echo "$b"; return 0
        fi
        sleep 1
    done
    return 1
}

# wait_block PATH SECS: poll until the latest version of PATH is on a real block; prints it.
wait_block() {
    local b
    for _ in $(seq 1 "$2"); do
        b=$(file_block_hex 0 "$1")
        [ -n "$b" ] && { echo "$b"; return 0; }
        sleep 1
    done
    return 1
}

# assert_no_periodic_since LINE0: node-00 logged no periodic rescan after line LINE0.
assert_no_periodic_since() {
    ! has "$(log_since 0 "$1")" "periodic rescan complete"
}

# owner_since LINE0 PATTERN: node-00 log lines after LINE0 with PATTERN (count).
owner_since() {
    local out; out=$(log_since 0 "$1")
    grep -acF -- "$2" <<< "$out" || true
}

# owner_block_lines LINE0 PATTERN HEX: node-00 lines after LINE0 with PATTERN and
# block_id=HEX (16 hex) (count).
owner_block_lines() {
    local out; out=$(log_since 0 "$1" | grep -aF -- "$2" || true)
    grep -acF -- "block_id=${3:0:16}" <<< "$out" || true
}

# owner_path_lines LINE0 PATTERN PATH: node-00 lines after LINE0 with PATTERN and path=PATH.
owner_path_lines() {
    local out; out=$(log_since 0 "$1" | grep -aF -- "$2" || true)
    awk -v want="path=$3" '{ for (i = 1; i <= NF; i++) if ($i == want) { n++; break } }
        END { print n + 0 }' <<< "$out"
}

# holder_marks: LH[i] = current line count of holder i's log (a mark for *_since checks).
declare -A LH_R2 LH_Y LH_R LH_M2
mark_holders() {
    local -n arr="$1"; local i
    for i in "${HOLDERS[@]}"; do arr[$i]=$(log_line_count "$i"); done
}

# holders_since MARKS PATTERN HEX: holders whose log has a PATTERN line with block_id=HEX
# (16 hex) after their mark.
holders_since() {
    local -n arr="$1"; local pat="$2" hex="${3:0:16}" n=0 i out
    [ -n "$hex" ] || { echo 0; return; }
    for i in "${HOLDERS[@]}"; do
        out=$(log_since "$i" "${arr[$i]}" | grep -aF -- "$pat" || true)
        [ "$(grep -acF -- "block_id=$hex" <<< "$out" || true)" -ge 1 ] && n=$((n + 1))
    done
    echo "$n"
}

# wait_stored MARKS HEX SECS: poll until >= 2 holders logged "stored symbols" for HEX after
# their mark; prints the count.
wait_stored() {
    local n=0
    for _ in $(seq 1 "$3"); do
        n=$(holders_since "$1" "processor: stored symbols for block" "$2")
        [ "$n" -ge 2 ] && break
        sleep 1
    done
    echo "$n"
}

# first_mark_time HEX: the earliest unix time any holder logged "holding marked for
# deletion" for HEX (16 hex); empty when none.
first_mark_time() {
    local hex="${1:0:16}" i
    for i in "${HOLDERS[@]}"; do
        events "$(node_log "$i")" "holding marked for deletion" block_id \
            | awk -v h="$hex" '$3 == h { print int($1) }'
    done | sort -n | head -1
}

# owner_delete_sent HEX: node-00 lines "sent DeleteMsg via mailbox" for HEX (whole log).
owner_delete_sent() { owner_block_lines 0 "sent DeleteMsg via mailbox" "$1"; }

window_left() {
    echo $(( OWNER_WINDOW - ( $(date +%s) - $1 ) - WINDOW_MARGIN ))
}

sha_of() { content_hash "$1"; }

echo "============================================================"
echo "  Viaticum: a returned file is protected again (L1b)"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Test dir: $T"
echo "============================================================"

# ── STEP 0: SETUP ────────────────────────────────────────────────
echo ""
echo "=== Step 0: setup ==="
assert_delete_window "$TIME_SCALE" 100
OWNER_WINDOW=$((OWNER_DELETE_COOLDOWN_SECS / TIME_SCALE))
HOLDER_WINDOW=$((HOLDER_DELETE_COOLDOWN_SECS / TIME_SCALE))
TTL=$((DELETE_REQUEST_TTL_SECS / TIME_SCALE))
[ "$TTL" -ge 1 ] || TTL=1
SWEEP=$((MAILBOX_SWEEP_INTERVAL_SECS / TIME_SCALE))
[ "$SWEEP" -ge 1 ] || SWEEP=1
if [ $((TTL + 25)) -ge "$OWNER_WINDOW" ] || [ $((TTL + SWEEP)) -ge "$HOLDER_WINDOW" ]; then
    fail "timing precondition: TTL ${TTL}s + 25 < W ${OWNER_WINDOW}s and TTL + sweep ${SWEEP}s < W_h ${HOLDER_WINDOW}s"
    exit 1
fi
W=$OWNER_WINDOW
info "owner window ${W}s, holder window ${HOLDER_WINDOW}s, Delete TTL ${TTL}s, sweep ${SWEEP}s"

N0=$(node_dir 0)
FILES="$N0/files"
SRC="$T/src"
STASH="$T/stash"
mkdir -p "$SRC" "$STASH" "$FILES"

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
            echo "path = \"$FILES\""
        fi
    } > "$(node_dir "$i")/config.toml"
    start_node "$i"
done

READY=0
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_daemon "$i"; then READY=$((READY + 1)); else echo "    node-0$i NOT ready"; fi
done
echo "  $READY/$NUM_NODES daemons ready"

ADDR_00=$(get_addr 0)
[ -n "$ADDR_00" ] || { fail "setup: cannot get node-00 address"; exit 1; }
for i in "${HOLDERS[@]}"; do
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
if wait_auth_peers 0 $((NUM_NODES-1)) 90; then
    pass "star connect: $(status_num 0 peer_count_authenticated) authenticated peers"
else
    fail "star connect: only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 90s"
    exit 1
fi

# ── STEP 1: SEED ─────────────────────────────────────────────────
echo ""
echo "=== Step 1: seed R, R2, Y, Z, S one by one; pack M = m1..m3 ==="
declare -A H X
for n in R R2 Y Z S; do
    head -c 262144 /dev/urandom > "$SRC/$n.bin"
    cp "$SRC/$n.bin" "$STASH/$n.bin"
    H[$n]=$(sha_of "$SRC/$n.bin")
    mv "$SRC/$n.bin" "$FILES/$n.bin"
    if ! wait_file_restorable 0 "$FILES/$n.bin" 60; then
        fail "setup: $n.bin not restorable per node-00 after 60s"; exit 1
    fi
    if wait_on_holders "$FILES/$n.bin" 30; then
        X[$n]=$OH_BLOCK
        pass "$n.bin restorable, holders hold $OH_ON >= k_eff $OH_TARGET of ${OH_BLOCK:0:16}.."
    else
        fail "setup: $n.bin: holders hold $OH_ON of ${OH_BLOCK:0:16}.., need k_eff ${OH_TARGET:-?}"; exit 1
    fi
done
for n in m1 m2 m3; do
    head -c 65536 /dev/urandom > "$SRC/$n.bin"
    cp "$SRC/$n.bin" "$STASH/$n.bin"
    H[$n]=$(sha_of "$SRC/$n.bin")
done
mv "$SRC/m1.bin" "$SRC/m2.bin" "$SRC/m3.bin" "$FILES/"
for n in m1 m2 m3; do
    X[$n]=$(wait_block "$FILES/$n.bin" 60) || { fail "setup: $n.bin got no block"; exit 1; }
done
if [ "${X[m2]}" != "${X[m1]}" ] || [ "${X[m3]}" != "${X[m1]}" ]; then
    fail "setup: pack not built (m1 ${X[m1]:0:16}, m2 ${X[m2]:0:16}, m3 ${X[m3]:0:16})"; exit 1
fi
PM=${X[m1]}
if wait_file_restorable 0 "$FILES/m1.bin" 60 && wait_on_holders "$FILES/m1.bin" 60; then
    pass "pack PM ${PM:0:16}.. restorable, holders hold $OH_ON >= k_eff $OH_TARGET"
else
    fail "setup: pack PM not on holders ($OH_ON/${OH_TARGET:-?})"; exit 1
fi
XR=${X[R]}; XR2=${X[R2]}; XY=${X[Y]}; XZ=${X[Z]}; XS=${X[S]}
DISTINCT=$(printf '%s\n' "$XR" "$XR2" "$XY" "$XZ" "$XS" "$PM" | sort -u | wc -l)
if [ "$DISTINCT" -eq 6 ]; then pass "XR XR2 XY XZ XS PM pairwise different"
else fail "setup: the seeded blocks are not pairwise different ($DISTINCT distinct of 6)"; exit 1; fi
PIPE_SEED=$(owner_since 0 "backup: pipeline complete")

# ── STEP 1b: KILL -9 BEFORE THE FLUSH ────────────────────────────
echo ""
echo "=== Step 1b: ADVERSARIAL kill -9 between enqueue and flush (backup-i25) ==="
STEP1B_DONE=0
pause=0.4
SCAN_REPEATS=0
for attempt in 1 2 3 4 5; do
    QN="Q$attempt.bin"; [ "$attempt" -eq 1 ] && QN="Q.bin"
    Q="$FILES/$QN"
    head -c 65536 /dev/urandom > "$SRC/$QN"
    LINE_P=$(log_line_count 0)
    # Right after a periodic rescan: the restart then skips its start scan.
    SAW_RESCAN=0
    for _ in $(seq 1 70); do
        if has "$(log_since 0 "$LINE_P")" "periodic rescan complete"; then SAW_RESCAN=1; break; fi
        sleep 1
    done
    [ "$SAW_RESCAN" -eq 1 ] || { fail "setup: no periodic rescan at node-00 within 70s"; break; }
    LINE_Q=$(log_line_count 0)
    mv "$SRC/$QN" "$Q"
    sleep "$pause"
    kill -9 "${DPID[0]}"
    wait "${DPID[0]}" 2>/dev/null || true
    if [ "$(owner_since "$LINE_Q" "backup: pipeline complete")" -ge 1 ]; then
        info "attempt $attempt: Q was packed before the kill; repeating with sleep 0.2"
        pause=0.2; continue
    fi
    LINE_START=$(log_line_count 0)
    start_node 0
    T_START=$(date +%s)
    wait_daemon 0 || { fail "node-00 did not restart after kill -9"; exit 1; }
    IN_CAT=0
    for _ in $(seq 1 5); do
        [ -n "$(file_field 0 "$Q" '.path')" ] && { IN_CAT=1; break; }
        sleep 1
    done
    if [ "$IN_CAT" -eq 0 ]; then
        info "attempt $attempt: Q not in the catalog: the kill beat the event; repeating with sleep 0.6"
        pause=0.6; continue
    fi
    if ! has "$(log_since 0 "$LINE_START")" "scan skipped (last scan recent enough)"; then
        SCAN_REPEATS=$((SCAN_REPEATS + 1))
        info "attempt $attempt: the start scan ran (it finds Q too); repeating"
        [ "$SCAN_REPEATS" -ge 2 ] && { rough "step 1b: the start scan ran twice — not proven"; STEP1B_DONE=2; break; }
        continue
    fi
    Q_BACKED=0
    for _ in $(seq 1 10); do
        [ -n "$(file_block_hex 0 "$Q")" ] && { Q_BACKED=1; break; }
        sleep 1
    done
    T_QB=$(( $(date +%s) - T_START ))
    RLINE=$(log_since 0 "$LINE_START" | grep -aF "reconcile: resubmitted" | grep -aF "root=$FILES " || true)
    RPEND=$(log_field "$(head -1 <<< "$RLINE")" pending)
    wait_auth_peers 0 4 90 || true
    Q_ON=0
    for _ in $(seq 1 20); do
        on_holders "$Q" && { Q_ON=1; break; }
        sleep 1
    done
    if ! assert_no_periodic_since "$LINE_START"; then
        info "attempt $attempt: a periodic rescan ran in the window (it finds Q too); repeating"
        continue
    fi
    STEP1B_DONE=1
    if [ "$Q_BACKED" -eq 1 ]; then pass "$QN backed up ${T_QB}s after the restart (no scan)"
    else fail "backup-i25: $QN not backed up 10s after the restart (start scan skipped)"; fi
    if [ "${RPEND:-0}" -ge 1 ]; then pass "node-00: reconcile resubmitted pending=$RPEND under files/"
    else fail "backup-i25: no 'reconcile: resubmitted root=$FILES … pending>=1' line (got '${RLINE:0:200}')"; fi
    if [ "$Q_ON" -eq 1 ]; then pass "$QN >= k_eff on holder disks ($OH_ON/$OH_TARGET) within 20s of the peers"
    else fail "backup-i25: $QN on holders $OH_ON/${OH_TARGET:-?} 20s after the peers came back"; fi
    break
done
if [ "$STEP1B_DONE" -eq 0 ]; then
    fail "step 1b setup: no attempt had Q queued at the kill, in the catalog, with the start scan skipped and no periodic rescan"
fi
wait_auth_peers 0 4 90 || { fail "node-00 has not got its 4 peers back"; exit 1; }

# ── STEP 2: DELETE ───────────────────────────────────────────────
echo ""
echo "=== Step 2: one rm of R R2 Y Z S m1 m2 m3 ==="
T_DEL=$(date +%s)
rm "$FILES/R.bin" "$FILES/R2.bin" "$FILES/Y.bin" "$FILES/Z.bin" "$FILES/S.bin" \
    "$FILES/m1.bin" "$FILES/m2.bin" "$FILES/m3.bin"
DEL_OK=0
for n in R R2 Y Z S m1 m2 m3; do
    wait_file_deleted 0 "$FILES/$n.bin" 15 && DEL_OK=$((DEL_OK + 1))
done
if [ "$DEL_OK" -eq 8 ]; then pass "all eight deleted within 15s"
else fail "setup: $DEL_OK/8 deleted within 15s"; exit 1; fi

# ── STEP 3: RETURN BEFORE THE DELETE ─────────────────────────────
echo ""
echo "=== Step 3: S returned before its Delete, to its path and as dl/S-copy (backup-i21) ==="
sleep_until $((T_DEL + 30))
LINE_S=$(log_line_count 0)
T_RETS=$(date +%s)
mkdir -p "$FILES/dl"
cp "$STASH/S.bin" "$FILES/S.bin"
cp "$STASH/S.bin" "$FILES/dl/S-copy.bin"
if [ "$T_RETS" -gt $((T_DEL + W - 30)) ]; then
    rough "timing: S returned at T_del + $((T_RETS - T_DEL))s, later than W - 30"
fi
S_ON=0; SC_ON=0
wait_last_block "$FILES/S.bin" "$XS" 15 && S_ON=1
wait_last_block "$FILES/dl/S-copy.bin" "$XS" 15 && SC_ON=1
sleep_until $((T_RETS + 15))
if [ "$S_ON" -eq 1 ] && [ "$SC_ON" -eq 1 ]; then pass "S and dl/S-copy on XS ${XS:0:16}.."
else fail "backup-i21: S on '$(file_block_hex 0 "$FILES/S.bin" | cut -c1-16)', S-copy on '$(file_block_hex 0 "$FILES/dl/S-copy.bin" | cut -c1-16)' (want XS ${XS:0:16})"; fi
if [ "${PIPE_SEED:-0}" -ge 1 ]; then
    PIPE_S=$(owner_since "$LINE_S" "backup: pipeline complete")
    if [ "$PIPE_S" -eq 0 ]; then pass "no new block for S / S-copy (0 'pipeline complete' in 15s; $PIPE_SEED from the seed)"
    else fail "backup-i21: $PIPE_S 'pipeline complete' within 15s of returning S before its Delete"; fi
else
    fail "positive control: no 'pipeline complete' at node-00 from the seed — the check is blind"
fi
RET_S=$(( $(owner_path_lines "$LINE_S" "content returned but its block is being released" "$FILES/S.bin") \
    + $(owner_path_lines "$LINE_S" "content returned but its block is being released" "$FILES/dl/S-copy.bin") ))
if [ "$RET_S" -eq 0 ]; then pass "no 'content returned but its block is being released' for S / S-copy"
else fail "backup-i21: $RET_S 'content returned …' line(s) for S / S-copy (the gate is too strict)"; fi

# ── STEPS 4-5: THE DELETE MARKS; R2 BACK IN THE REPLAY WINDOW ────
echo ""
echo "=== Step 4: holders mark XR, XR2, XY, PM for deletion; step 5 fires at XR2's mark ==="
declare -A TMARK
DEADLINE=$((T_DEL + W + 60))
STEP5_FIRED=0
while :; do
    for pair in "R:$XR" "R2:$XR2" "Y:$XY" "PM:$PM"; do
        n=${pair%%:*}; hex=${pair##*:}
        [ -n "${TMARK[$n]:-}" ] && continue
        t=$(first_mark_time "$hex")
        [ -n "$t" ] && TMARK[$n]=$t
    done
    if [ "$STEP5_FIRED" -eq 0 ] && [ -n "${TMARK[R2]:-}" ]; then
        # Step 5 action: R2 back to its path inside the replay window.
        LINE_R2=$(log_line_count 0)
        mark_holders LH_R2
        T_RETR2=$(date +%s)
        cp "$STASH/R2.bin" "$FILES/R2.bin"
        STEP5_FIRED=1
    fi
    [ -n "${TMARK[R]:-}" ] && [ -n "${TMARK[R2]:-}" ] && [ -n "${TMARK[Y]:-}" ] && [ -n "${TMARK[PM]:-}" ] && break
    [ "$(date +%s)" -gt "$DEADLINE" ] && break
    sleep 1
done
MARKS_OK=1
for pair in "R:$XR" "R2:$XR2" "Y:$XY" "PM:$PM"; do
    n=${pair%%:*}; hex=${pair##*:}
    if [ -z "${TMARK[$n]:-}" ]; then
        fail "not in window, nothing proven: no holder marked $n ${hex:0:16}.. for deletion by T_del + W + 60"
        MARKS_OK=0
    elif [ "$(owner_delete_sent "$hex")" -lt 1 ]; then
        fail "not in window, nothing proven: $n ${hex:0:16}.. marked but no owner 'sent DeleteMsg via mailbox'"
        MARKS_OK=0
    else
        pass "$n ${hex:0:16}.. marked for deletion at T_del + $(( ${TMARK[$n]} - T_DEL ))s; the owner sent its Delete"
    fi
done
[ "$MARKS_OK" -eq 1 ] || exit 1

echo ""
echo "=== Step 5: ADVERSARIAL R2 back to its path inside the Delete replay window (backup-i8, delete-i9) ==="
STEP5_TIMED=1
if [ "$T_RETR2" -gt $((${TMARK[R2]} + TTL - 30)) ]; then
    rough "timing: R2 returned at T_markR2 + $((T_RETR2 - ${TMARK[R2]}))s, beyond TTL - 30 (not inside the replay window)"
    STEP5_TIMED=0
fi
XR2N=$(wait_block_change "$FILES/R2.bin" "$XR2" 30 || true)
if [ -n "$XR2N" ]; then pass "R2 backed up on XR2' ${XR2N:0:16}.. != XR2 ${XR2:0:16}.."
else fail "backup-i8: returned onto the block being released: R2 on '$(file_block_hex 0 "$FILES/R2.bin" | cut -c1-16)' (XR2 ${XR2:0:16})"; fi
RET_R2=$(owner_path_lines "$LINE_R2" "content returned but its block is being released" "$FILES/R2.bin")
GEN_R2=$(log_since 0 "$LINE_R2" | grep -aF "sealed as a new generation" | grep -aF "block_id=${XR2N:0:16}" \
    | grep -acF "seal_generation=1" || true)
if [ -n "$XR2N" ] && [ "$RET_R2" -ge 1 ] && [ "${GEN_R2:-0}" -ge 1 ]; then
    pass "owner: 'content returned …' for R2 and 'sealed as a new generation … seal_generation=1' for XR2'"
else
    fail "setup: same-plaintext path not exercised (content returned: $RET_R2, new generation lines for XR2': ${GEN_R2:-0})"
fi
if [ -n "$XR2N" ]; then
    ST=$(wait_stored LH_R2 "$XR2N" 60)
    if [ "$ST" -ge 2 ]; then pass "$ST holders stored symbols of XR2' after the return"
    else fail "backup-i8: $ST holder(s) stored symbols of XR2' within 60s"; fi
fi

# ── STEP 6: Y BACK UNDER ANOTHER PATH ────────────────────────────
echo ""
echo "=== Step 6: ADVERSARIAL Y back as dl/Y-again.bin after its Delete (backup-i21) ==="
sleep_until $((${TMARK[Y]} + 5))
mark_holders LH_Y
cp "$STASH/Y.bin" "$FILES/dl/Y-again.bin"
XYN=$(wait_block_change "$FILES/dl/Y-again.bin" "$XY" 30 || true)
if [ -n "$XYN" ]; then pass "dl/Y-again backed up on XY' ${XYN:0:16}.. != XY"
else fail "backup-i21: dedup onto a block being released: dl/Y-again on '$(file_block_hex 0 "$FILES/dl/Y-again.bin" | cut -c1-16)' (XY ${XY:0:16})"; fi
if [ -n "$XYN" ]; then
    ST=$(wait_stored LH_Y "$XYN" 60)
    if [ "$ST" -ge 2 ]; then pass "$ST holders stored symbols of XY'"
    else fail "backup-i21: $ST holder(s) stored symbols of XY' within 60s"; fi
fi

# ── STEP 7: R BACK AFTER THE REPLAY WINDOW ───────────────────────
echo ""
echo "=== Step 7: R back to its path after the Delete replay window (backup-i8) ==="
sleep_until $((${TMARK[R]} + TTL + 5))
XRN=""
if [ "$(date +%s)" -gt $((T_DEL + 2 * W - 20)) ]; then
    rough "timing: past T_del + 2W - 20 before R could return (CleanupBlock of XR may free its id); step 7 skipped"
else
    LINE_R=$(log_line_count 0)
    mark_holders LH_R
    cp "$STASH/R.bin" "$FILES/R.bin"
    XRN=$(wait_block_change "$FILES/R.bin" "$XR" 30 || true)
    GEN_R=$(log_since 0 "$LINE_R" | grep -aF "sealed as a new generation" | grep -aF "block_id=${XRN:0:16}" \
        | grep -acF "seal_generation=1" || true)
    if [ -n "$XRN" ] && [ "${GEN_R:-0}" -ge 1 ]; then pass "R on XR' ${XRN:0:16}.. != XR, sealed at generation 1"
    else fail "backup-i8: R on '${XRN:0:16}' (XR ${XR:0:16}), generation-1 lines ${GEN_R:-0}"; fi
    if [ -n "$XRN" ]; then
        ST=$(wait_stored LH_R "$XRN" 60)
        if [ "$ST" -ge 2 ]; then pass "$ST holders stored symbols of XR'"
        else fail "backup-i8: $ST holder(s) stored symbols of XR' within 60s"; fi
    fi
fi

# ── STEP 8: m2 BACK WHILE THE OWNER IS STOPPED ───────────────────
echo ""
echo "=== Step 8: ADVERSARIAL m2 back while node-00 is stopped (backup-i8) ==="
kill -TERM "${DPID[0]}"
if wait_pid_exit "${DPID[0]}" 15 && [ "$EXIT_RC" = 0 ]; then pass "node-00 stopped (exit 0)"
else fail "node-00 did not exit 0 within 15s (rc=${EXIT_RC:-running})"; exit 1; fi
cp "$STASH/m2.bin" "$FILES/m2.bin"
mark_holders LH_M2
start_node 0
wait_daemon 0 || { fail "node-00 did not restart"; exit 1; }
if wait_auth_peers 0 4 90; then pass "node-00 back with 4 authenticated peers"
else fail "node-00 back with $(status_num 0 peer_count_authenticated)/4 peers after 90s"; fi
YM2=$(wait_block_change "$FILES/m2.bin" "$PM" 90 || true)
if [ -n "$YM2" ]; then pass "m2 backed up on YM2 ${YM2:0:16}.. != PM"
else fail "backup-i8: m2 on '$(file_block_hex 0 "$FILES/m2.bin" | cut -c1-16)' 90s after the restart (PM ${PM:0:16})"; fi
if [ -n "$YM2" ]; then
    ST=$(wait_stored LH_M2 "$YM2" 60)
    if [ "$ST" -ge 2 ]; then pass "$ST holders stored symbols of YM2"
    else fail "backup-i8: $ST holder(s) stored symbols of YM2 within 60s"; fi
fi

# ── STEP 9: AFTER BOTH WINDOWS ───────────────────────────────────
echo ""
echo "=== Step 9: after both windows: the old blocks are wiped, the returned files are held ==="
sleep_until $((T_DEL + 2 * W + 45))
ZN=$(symbols_on_holders "$XZ")
if [ "$ZN" -eq 0 ]; then pass "control: XZ has 0 symbols on holders (the windows passed)"
else fail "windows did not pass: nothing proven (XZ still has $ZN symbols on holders)"; fi
for pair in "PM:$PM" "XR:$XR" "XR2:$XR2" "XY:$XY"; do
    n=${pair%%:*}; hex=${pair##*:}
    c=$(symbols_on_holders "$hex")
    if [ "$c" -eq 0 ]; then pass "$n ${hex:0:16}.. wiped on every holder"
    else fail "delete-i1/delete-i8: $n ${hex:0:16}.. still has $c symbols on holders"; fi
done
PROT_OK=1
for p in "$FILES/R.bin" "$FILES/R2.bin" "$FILES/dl/Y-again.bin" "$FILES/m2.bin" "$FILES/S.bin"; do
    [ -e "$p" ] || continue
    if wait_on_holders "$p" 60; then
        info "$(basename "$p") on ${OH_BLOCK:0:16}..: $OH_ON >= k_eff $OH_TARGET on holders"
    else
        fail "backup-i8: $(basename "$p") on ${OH_BLOCK:0:16}..: $OH_ON/${OH_TARGET:-?} on holders after the windows"
        PROT_OK=0
    fi
done
sleep 10
for p in "$FILES/R.bin" "$FILES/R2.bin" "$FILES/dl/Y-again.bin" "$FILES/m2.bin" "$FILES/S.bin"; do
    [ -e "$p" ] || continue
    if ! on_holders "$p"; then
        fail "backup-i8: $(basename "$p") dropped below k_eff within 10s ($OH_ON/${OH_TARGET:-?})"; PROT_OK=0
    fi
done
[ "$PROT_OK" -eq 1 ] && pass "R, R2, dl/Y-again, m2, S >= k_eff on holders past the windows, stable 10s"
MS=$(delete_marks_for "$XS" "${HOLDERS[@]}")
if [ "$MS" -eq 0 ]; then pass "no holder marked XS for deletion (returned before its Delete)"
else fail "backup-i21: $MS holder mark(s) for XS"; fi

# ── STEP 10: THE OLD DELETE NEVER HIT THE NEW GENERATION ─────────
echo ""
echo "=== Step 10: the replayed Delete of XR2 never marks XR2' (delete-i9, delete-i6) ==="
if [ -n "$XR2N" ]; then
    sleep_until $((${TMARK[R2]} + TTL + W + 30))
    MN=$(holders_since LH_R2 "holding marked for deletion" "$XR2N")
    if [ "$MN" -eq 0 ]; then
        if [ "$STEP5_TIMED" -eq 1 ]; then pass "0 holders marked XR2' although XR2's Delete was replayed until T_pub + TTL"
        else rough "0 holders marked XR2', but R2 did not return inside the replay window"; fi
    else
        fail "delete-i9: $MN holder(s) marked XR2' ${XR2N:0:16}.. for deletion"
    fi
    if wait_on_holders "$FILES/R2.bin" 30; then pass "XR2' >= k_eff on holders ($OH_ON/$OH_TARGET)"
    else fail "delete-i9: XR2' $OH_ON/${OH_TARGET:-?} on holders"; fi
    DS=$(owner_delete_sent "$XR2N")
    [ -n "$XRN" ] && DS=$((DS + $(owner_delete_sent "$XRN")))
    if [ "$DS" -eq 0 ]; then pass "the owner sent no DeleteMsg for XR2' or XR'"
    else fail "delete-i9: the owner sent $DS DeleteMsg(s) for XR2' / XR'"; fi
else
    fail "step 10: no XR2' (step 5 failed) — nothing to check"
fi

# ── STEP 11: RESTORE FROM THE NETWORK ────────────────────────────
echo ""
echo "=== Step 11: rm the returned files, restore them from the network (backup-i8, restore-i1) ==="
SERVED_XR=$(restore_responses_for "$XR" "${HOLDERS[@]}")
SERVED_XR2=$(restore_responses_for "$XR2" "${HOLDERS[@]}")
declare -A BLK SERVED0
for spec in "R.bin:R:${XRN:-}" "R2.bin:R2:${XR2N:-}" "dl/Y-again.bin:Y:${XYN:-}" "m2.bin:m2:${YM2:-}" "S.bin:S:$XS"; do
    IFS=: read -r rel n hex <<< "$spec"
    BLK[$rel]=$hex
    SERVED0[$rel]=$(restore_responses_for "$hex" "${HOLDERS[@]}")
done
T_FIN=$(date +%s)
rm -f "$FILES/R.bin" "$FILES/R2.bin" "$FILES/dl/Y-again.bin" "$FILES/m2.bin" "$FILES/S.bin"
for rel in R.bin R2.bin dl/Y-again.bin m2.bin S.bin; do
    wait_file_deleted 0 "$FILES/$rel" 15 || fail "setup: $rel not deleted within 15s"
done
for spec in "R.bin:R" "R2.bin:R2" "dl/Y-again.bin:Y" "m2.bin:m2" "S.bin:S"; do
    rel=${spec%%:*}; n=${spec##*:}
    left=$(window_left "$T_FIN")
    if [ "$left" -le 0 ]; then rough "timing: the owner window ran out before restoring $rel; rest skipped"; break; fi
    if [ -z "${BLK[$rel]}" ]; then fail "restore $rel: no block (an earlier step failed)"; continue; fi
    if restore_from_network 0 "$FILES/$rel" "${H[$n]}" "$left"; then
        pass "restore $rel from the network: $RESTORE_MSG"
        D=$(( $(restore_responses_for "${BLK[$rel]}" "${HOLDERS[@]}") - ${SERVED0[$rel]} ))
        if [ "$D" -ge 1 ]; then pass "holders logged $D RestoreResponse(s) for ${BLK[$rel]:0:16}.."
        else fail "restore $rel: no holder RestoreResponse for ${BLK[$rel]:0:16}.."; fi
    else
        fail "backup-i8: restore $rel from the network: $RESTORE_MSG"
    fi
done
info "RestoreResponse growth for the old XR: $(( $(restore_responses_for "$XR" "${HOLDERS[@]}") - SERVED_XR )), XR2: $(( $(restore_responses_for "$XR2" "${HOLDERS[@]}") - SERVED_XR2 )) (informational)"

# ── STEP 12: SHUTDOWN ────────────────────────────────────────────
echo ""
echo "=== Step 12: SIGTERM all ==="
for i in $(seq 0 $((NUM_NODES-1))); do
    kill -TERM "${DPID[$i]}" 2>/dev/null || true
done
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_pid_exit "${DPID[$i]}" 15 && [ "$EXIT_RC" = 0 ]; then :
    else fail "node-0$i did not exit 0 within 15s (rc=${EXIT_RC:-running})"; fi
    unset "DPID[$i]"
done
PANICS=$(cat "$T"/node-*/daemon.log 2>/dev/null | grep -ac "panicked" || true)
if [ "${PANICS:-0}" -eq 0 ]; then pass "all daemons exited, no panic in any log"
else fail "network-i1: $PANICS 'panicked' line(s) in the logs"; fi

echo ""
echo "============================================================"
echo "  PASS: $PASS  ROUGH: $ROUGH  FAIL: $FAIL"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
if [ "$ROUGH" -gt 0 ]; then exit 3; fi
exit 0
