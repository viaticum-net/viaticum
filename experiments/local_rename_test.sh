#!/bin/bash
# Viaticum: rename, trash, rollback — what a path points at (line C, L0 + L1).
# Local processes on one machine (no Docker).
#
# Scenario:     5 daemons, independent masters, star to node-00, time_scale 20000 (delete
#               windows ~120 s, Delete mailbox TTL ~60 s, periodic rescan 60 s). node-00
#               watches files/ and photos/. PHASE A: a queued file vanishes right before a
#               flush; a file is rolled back; a pre-"ransomware" version is put back in place.
#               PHASE B: a directory moved in; files trashed (outside and into a hidden
#               .Trash-1000); an editor-style atomic save; renames of files, a directory and a
#               file over another; two members of one pack swapped via tmp; a move between
#               folders; copies of pack members whose originals are edited/deleted; a rename
#               while the daemon is down; an inotify overflow that loses a trash event; finally
#               photos/ is moved away file by file (copy + delete, root removed last) while a
#               control file is trashed.
# Intent:       backup-i9, backup-i23 (A); delete-i12, backup-i22, restore-i38, dr-i64,
#               restore-i17 (moved-in directory part), delete-i1 (control) (B).
#               private/intent/backup.md, delete.md, restore.md, dr.md
# Proves:       trashed files get a Delete on OTHER nodes after the window, through the event
#               and not the recheck, and one whose event was lost to an overflow through the
#               recheck; a live atomic-save target gets none; a watch root moved away file by
#               file gets none although its first files were already marked deleted, while a
#               control file of the same moment gets one on all its holders; renamed / moved /
#               copied / swapped pack members stay provable (holders answer new PoS challenges,
#               the owner builds no new block, no Delete) and restore from the network by their
#               new paths; rollbacks and in-place restores are what the network restores; a
#               vanished queued file does not hold back its batch.
# Adversarial:  SIGSTOP around a flush while a queued file vanishes (8); holders must NOT serve
#               the undone version (10); atomic save over a live file (4); rename over an
#               existing file and a directory rename (5); swap inside one pack (5b); rename while
#               the owner is down (7); SIGSTOP + event flood to overflow inotify (7b); slow
#               file-by-file move of a watch root (11-12).
# Cannot close: real 4-week windows; macOS/Windows event shapes and root identity (unit tests);
#               case-insensitive FS; an ancestor of a watch root renamed; restore from trash
#               after the Delete was sent (backup-i8, L1b); cluster siblings; hard links; a
#               file changed between enqueue and flush (unit tests); cp -r / mkdir races
#               (R1-c2); DR side of dr-i64 (local_dr_test step 7); root self-heal on Scan (unit);
#               a move longer than the owner window.
# Expectation:  PHASE A is RED on the code before L1 (vps/run-1 ee01fb6):
#                 step 8  — the idle flush aborts on the vanished q1 ("flush error … q1.bin")
#                           and drops q2, q3 from the queue: they reach no holder within 20 s
#                           (only the 60 s periodic rescan would bring them back; the step
#                           repeats when a rescan falls into its window);
#                 step 9  — V rolled back to A keeps its last block XB (the same-path dedup
#                           only set Present); W put back from `restore --version 1` keeps XR;
#                 step 10 — restore of V returns B (holders log RestoreResponse for XB), W
#                           returns R.
#               GREEN after L1 (К1 + К2a). PHASE B steps are stubs until the L0-identity
#               sub-slice (К4, К2b, К3): each prints "SKIP [step N] L0-identity not
#               implemented", and PHASE=B / PHASE=all then end with exit 1 (nothing proven).
# Phases:       PHASE=A (default until L0 lands, ≈ 5 min) | PHASE=B (≈ 15 min) | PHASE=all.
# Verdicts:     PASS / ROUGH (timing: a restore window ran out, a step kept meeting the
#               periodic rescan) / FAIL; exit 0 / 3 / 1.
# Steps:        see private/beta-planning/tasks/c_l0_l1_watcher_rollback.md §0.3. PHASE A:
#   0.  init 5; node-00 config: [[watch]] files/ and photos/, files/.viaticumignore = flood/,
#       files/flood/; start; star; the delete window and TTL + 25 < W → 4 authenticated
#       ≤ 90 s — check: assert_delete_window, wait_auth_peers
#   1A. U, V (= A), W (= A_W), 256 KiB each, moved in one by one after the previous is
#       restorable → each restorable ≤ 60 s, ≥ k_eff of its symbols on holder disks — check:
#       wait_file_restorable, block_symbols_on
#   8.  ADVERSARIAL q1..q3 (64 KiB) by one mv; sleep 0.4; SIGSTOP node-00; q1 moved to the
#       trash; sleep 2; SIGCONT → setup: `file vanished since enqueue` or `flush error … q1.bin`
#       after the STOP (else repeat with sleep 0.2, ≤ 2 times); ≤ 20 s q2, q3 ≥ k_eff on
#       holder disks; no periodic rescan in the window (else repeat) (backup-i23) — check:
#       grep, block_symbols_on, assert_no_periodic_since
#   9.  V: cat B > V, wait XB ≠ XA restorable and on holders; cat A > V → ≤ 15 s last block XA.
#       W: random R > W, wait XR ≠ XAW restorable and on holders; restore W --version 1 →
#       sha A_W, holders log RestoreResponse for XAW; mv the staged copy to files/W.bin →
#       ≤ 15 s last block XAW (backup-i9) — check: /api/versions .[-1], restore_run,
#       restore_responses_for
#   10. (A part) SERVED_XB, SERVED_XR; rm V W → deleted ≤ 15 s; restore V, W from the
#       network → sha A, A_W; RestoreResponse ≥ 1 new for XA and XAW, 0 new for XB and XR
#       (ADVERSARIAL: holders must not serve the undone version); before each restore
#       window_left > 0, else ROUGH "timing" and the rest of the wave is skipped (backup-i9)
#       — check: restore_from_network, restore_responses_for, window_left
#   13. SIGTERM all → exit 0 ≤ 15 s; no `panicked` in any log (network-i1) — check:
#       wait_pid_exit, grep
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   PHASE=A bash experiments/local_rename_test.sh

set -euo pipefail

PHASE="${PHASE:-A}"
case "$PHASE" in
    A|B|all) ;;
    *) echo "ERROR: PHASE must be A, B or all (got '$PHASE')"; exit 2 ;;
esac
run_a() { [ "$PHASE" = A ] || [ "$PHASE" = all ]; }
run_b() { [ "$PHASE" = B ] || [ "$PHASE" = all ]; }

NUM_NODES=5
# Owner and holder delete windows 4 weeks / 20000 ≈ 121 s; Delete mailbox TTL 14 d / 20000
# ≈ 60 s; periodic rescan max(604800 / ts, 60) = 60 s; idle flush 1 s, fallback flush 4 s;
# watcher debounce 1800 s * 1000 / ts = 90 ms.
TIME_SCALE=20000
T="/tmp/viaticum-rename-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)
# Keep in sync with crates/viaticum-core/src/mailbox/mod.rs (class_config::DELETE_REQUEST_TTL).
DELETE_REQUEST_TTL_SECS=1209600
# A restore is started only while this many seconds of the owner window are left.
WINDOW_MARGIN=10
# Step 8: how long q2, q3 may take to reach k_eff on holder disks after SIGCONT.
Q_DEADLINE=20

PASS=0; FAIL=0; ROUGH=0; SKIPPED=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
rough() { echo "  ROUGH: $1"; ((ROUGH++)) || true; }
# A PHASE B step not written yet (the L0-identity sub-slice fills it in).
skip_b() { echo "  SKIP [step $1] L0-identity not implemented"; ((SKIPPED++)) || true; }

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
        # node-00's folders come from config.toml ([[watch]] files/ and photos/).
        RUST_LOG=info "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            >> "$(node_log "$i")" 2>&1 &
    else
        mkdir -p "$dir/files"
        # The PoS answer line is DEBUG (processor/pos.rs); PHASE B reads it.
        RUST_LOG=info,viaticum::daemon::processor::pos=debug "$BINARY" --data-dir "$dir" \
            daemon --time-scale "$TIME_SCALE" --watch-dir "$dir/files" \
            >> "$(node_log "$i")" 2>&1 &
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

# on_holders PATH: the latest version of PATH (node-00's catalog) is on a real block and
# holder disks hold >= k_eff of its symbols. Sets OH_BLOCK, OH_TARGET, OH_ON.
on_holders() {
    OH_BLOCK=$(file_block_hex 0 "$1")
    OH_TARGET=$(file_field 0 "$1" '.effective_status.target // 0')
    OH_ON=0
    [ -n "$OH_BLOCK" ] && [ "$OH_BLOCK" != "$ZERO_BLOCK" ] || return 1
    OH_ON=$(symbols_on_holders "$OH_BLOCK")
    [ "${OH_TARGET:-0}" -gt 0 ] && [ "$OH_ON" -ge "$OH_TARGET" ]
}

# wait_on_holders PATH SECS: poll on_holders until true.
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
# block other than OLD_HEX; prints it.
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

# assert_no_periodic_since LINE0: node-00 logged no periodic rescan after line LINE0 (a
# rescan re-adds every file and would mask a lost event or a dropped queue: the step is then
# void and repeated, not failed).
assert_no_periodic_since() {
    # Captured first: `log_since | grep -q` under pipefail turns a match into a SIGPIPE
    # failure of the writer, i.e. a false "no rescan".
    ! has "$(log_since 0 "$1")" "periodic rescan complete"
}

# window_left T_WAVE: seconds of the owner delete window (started by a delete at T_WAVE)
# left before a restore must start, minus WINDOW_MARGIN.
window_left() {
    echo $(( OWNER_WINDOW - ( $(date +%s) - $1 ) - WINDOW_MARGIN ))
}

sha_of() { content_hash "$1"; }

echo "============================================================"
echo "  Viaticum: rename / trash / rollback (PHASE=$PHASE)"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Test dir: $T"
echo "============================================================"

# ── STEP 0: SETUP ────────────────────────────────────────────────
echo ""
echo "=== Step 0: setup ==="
# The scenario races the owner window on purpose (step 10): floor 100 s.
assert_delete_window "$TIME_SCALE" 100
OWNER_WINDOW=$((OWNER_DELETE_COOLDOWN_SECS / TIME_SCALE))
TTL_SCALED=$((DELETE_REQUEST_TTL_SECS / TIME_SCALE))
if [ $((TTL_SCALED + 25)) -ge "$OWNER_WINDOW" ]; then
    fail "setup: Delete TTL ${TTL_SCALED}s + 25 >= owner window ${OWNER_WINDOW}s"
    exit 1
fi
info "owner window ${OWNER_WINDOW}s, Delete TTL ${TTL_SCALED}s"

N0=$(node_dir 0)
FILES="$N0/files"
PHOTOS="$N0/photos"
SRC="$T/src"
TRASH="$T/trash"
mkdir -p "$SRC" "$TRASH/files" "$FILES/flood" "$PHOTOS"
echo "flood/" > "$FILES/.viaticumignore"

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
            echo '[[watch]]'
            echo "path = \"$PHOTOS\""
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

# ── STEP 1A: SEED U, V, W ────────────────────────────────────────
if run_a; then
    echo ""
    echo "=== Step 1A: seed U, V (= A), W (= A_W), one by one ==="
    declare -A H X
    for n in U V W; do
        head -c 262144 /dev/urandom > "$SRC/$n.bin"
        H[$n]=$(sha_of "$SRC/$n.bin")
        mv "$SRC/$n.bin" "$FILES/$n.bin"
        if ! wait_file_restorable 0 "$FILES/$n.bin" 60; then
            fail "setup: $n.bin not restorable per node-00 after 60s"
            exit 1
        fi
        if wait_on_holders "$FILES/$n.bin" 30; then
            X[$n]=$OH_BLOCK
            pass "$n.bin restorable, holders hold $OH_ON >= k_eff $OH_TARGET of ${OH_BLOCK:0:16}.."
        else
            fail "setup: $n.bin: holders hold $OH_ON of block ${OH_BLOCK:0:16}.., need k_eff ${OH_TARGET:-?}"
            exit 1
        fi
    done
    XA=${X[V]}; XAW=${X[W]}; H_A=${H[V]}; H_AW=${H[W]}
fi

# ── STEPS 1B-7b: PHASE B (L0-identity) ───────────────────────────
if run_b; then
    echo ""
    echo "=== Steps 1B-7b: PHASE B ==="
    for s in 1B 2 3 4 5 5b 6 7 7b; do skip_b "$s"; done
fi

# ── STEP 8: A QUEUED FILE VANISHES RIGHT BEFORE THE FLUSH ────────
if run_a; then
    echo ""
    echo "=== Step 8: q1 vanishes while q1..q3 wait for the flush (backup-i23) ==="
    STEP8_DONE=0
    for attempt in 1 2 3; do
        sfx="a$attempt"
        [ "$attempt" -eq 1 ] && pause=0.4 || pause=0.2
        for n in 1 2 3; do head -c 65536 /dev/urandom > "$SRC/q${n}_$sfx.bin"; done
        Q1="$FILES/q1_$sfx.bin"; Q2="$FILES/q2_$sfx.bin"; Q3="$FILES/q3_$sfx.bin"
        mv "$SRC/q1_$sfx.bin" "$SRC/q2_$sfx.bin" "$SRC/q3_$sfx.bin" "$FILES/"
        sleep "$pause"
        kill -STOP "${DPID[0]}"
        LINE_STOP=$(log_line_count 0)
        mv "$Q1" "$TRASH/"
        sleep 2
        kill -CONT "${DPID[0]}"
        T_CONT=$(date +%s)

        Q_OK=0
        for _ in $(seq 1 "$Q_DEADLINE"); do
            if on_holders "$Q2" && Q2_ON="$OH_ON/$OH_TARGET" && on_holders "$Q3"; then
                Q_OK=1; break
            fi
            sleep 1
        done
        Q_WALL=$(( $(date +%s) - T_CONT ))
        on_holders "$Q2" || true; Q2_STATE="q2 ${OH_ON}/${OH_TARGET:-?} on ${OH_BLOCK:0:16}"
        on_holders "$Q3" || true; Q3_STATE="q3 ${OH_ON}/${OH_TARGET:-?} on ${OH_BLOCK:0:16}"

        # Setup: the vanish hit a queued file (the flush saw it gone), not an already packed one.
        VANISH=$(log_since 0 "$LINE_STOP" | grep -E "file vanished since enqueue|flush error" \
            | grep -cF "q1_$sfx.bin" || true)
        if [ "${VANISH:-0}" -eq 0 ]; then
            info "attempt $attempt: q1 was not queued at the flush after the STOP (packed before it?); repeating"
            continue
        fi
        if ! assert_no_periodic_since "$LINE_STOP"; then
            info "attempt $attempt: a periodic rescan ran in the window (it re-adds every file); repeating"
            continue
        fi
        STEP8_DONE=1
        if [ "$Q_OK" -eq 1 ]; then
            pass "q2, q3 >= k_eff on holder disks ${Q_WALL}s after SIGCONT; the vanished q1 did not hold them back ($Q2_STATE; $Q3_STATE)"
        else
            fail "backup-i23: ${Q_DEADLINE}s after SIGCONT: $Q2_STATE; $Q3_STATE (flush lines: $(log_since 0 "$LINE_STOP" | grep -E 'flush' | tail -3 | tr '\n' '|'))"
        fi
        break
    done
    if [ "$STEP8_DONE" -eq 0 ]; then
        rough "step 8: 3 attempts, none both hit a queued file and missed the periodic rescan — not proven"
    fi
fi

# ── STEP 9: ROLLBACK AND IN-PLACE RESTORE ────────────────────────
if run_a; then
    echo ""
    echo "=== Step 9: V rolled back A -> B -> A; W restored to version 1 in place (backup-i9) ==="
    V="$FILES/V.bin"; W="$FILES/W.bin"
    head -c 262144 /dev/urandom > "$SRC/B.bin"
    H_B=$(sha_of "$SRC/B.bin")
    cp "$V" "$SRC/A.bin"
    cat "$SRC/B.bin" > "$V"
    if XB=$(wait_block_change "$V" "$XA" 60) && wait_file_restorable 0 "$V" 60 \
        && wait_on_holders "$V" 30 && [ "$OH_BLOCK" = "$XB" ]; then
        info "V = B on ${XB:0:16}.. ($OH_ON symbols on holders)"
    else
        fail "setup: V = B not on a new block on holders (block ${XB:-none}, $OH_ON/${OH_TARGET:-?})"
        exit 1
    fi
    cat "$SRC/A.bin" > "$V"
    if wait_last_block "$V" "$XA" 15; then
        pass "V rolled back: its latest version is on A's block ${XA:0:16}.. again"
    else
        fail "backup-i9: V rolled back to A, latest block still $(file_block_hex 0 "$V" | cut -c1-16).. (XA ${XA:0:16}.., XB ${XB:0:16}..)"
    fi

    head -c 262144 /dev/urandom > "$W"
    if XR=$(wait_block_change "$W" "$XAW" 60) && wait_file_restorable 0 "$W" 60 \
        && wait_on_holders "$W" 30 && [ "$OH_BLOCK" = "$XR" ]; then
        info "W = R on ${XR:0:16}.. ($OH_ON symbols on holders)"
    else
        fail "setup: W = R not on a new block on holders (block ${XR:-none}, $OH_ON/${OH_TARGET:-?})"
        exit 1
    fi
    SERVED_AW0=$(restore_responses_for "$XAW" "${HOLDERS[@]}")
    # W holds R now: the owner cannot rebuild XAW from its own file, the restore goes to holders.
    restore_run 0 60 "$W" --version 1
    STAGED=""
    if [ "$RESTORE_RC" -eq 0 ] \
        && [ "$(echo "$RESTORE_LAST" | jq -r '.outcome // "none"' 2>/dev/null)" = complete ]; then
        STAGED="$(echo "$RESTORE_LAST" | jq -r '.staging_path')/${W#/}"
    fi
    if [ -n "$STAGED" ] && [ -f "$STAGED" ] && [ "$(sha_of "$STAGED")" = "$H_AW" ]; then
        pass "restore W --version 1: sha A_W"
    else
        fail "restore W --version 1: rc=$RESTORE_RC staged=${STAGED:-none} job=${RESTORE_LAST:0:400} err=${RESTORE_ERR:0:200}"
        exit 1
    fi
    SERVED_AW=$(( $(restore_responses_for "$XAW" "${HOLDERS[@]}") - SERVED_AW0 ))
    if [ "$SERVED_AW" -ge 1 ]; then
        pass "holders logged $SERVED_AW RestoreResponse(s) for XAW ${XAW:0:16}.."
    else
        fail "no holder logged a RestoreResponse for XAW ${XAW:0:16}.. (the restore did not use the network)"
    fi
    mv "$STAGED" "$W"
    if wait_last_block "$W" "$XAW" 15; then
        pass "W put back: its latest version is on A_W's block ${XAW:0:16}.. again"
    else
        fail "backup-i9: W put back from restore, latest block still $(file_block_hex 0 "$W" | cut -c1-16).. (XAW ${XAW:0:16}.., XR ${XR:0:16}..)"
    fi
fi

# ── STEP 10: WHAT THE NETWORK RESTORES ───────────────────────────
if run_b; then
    echo ""
    echo "=== Step 10 (PHASE B part: Delete controls, wave 1, B files of wave 2) ==="
    skip_b "10 (B)"
fi
if run_a; then
    echo ""
    echo "=== Step 10: rm V W; restore both from the network (backup-i9) ==="
    SERVED_XB0=$(restore_responses_for "$XB" "${HOLDERS[@]}")
    SERVED_XR0=$(restore_responses_for "$XR" "${HOLDERS[@]}")
    SERVED_XA0=$(restore_responses_for "$XA" "${HOLDERS[@]}")
    SERVED_XAW0=$(restore_responses_for "$XAW" "${HOLDERS[@]}")
    rm -f "$V" "$W"
    T_WAVE=$(date +%s)
    for f in "$V" "$W"; do
        wait_file_deleted 0 "$f" 15 || fail "$(basename "$f") not registered deleted within 15s"
    done
    declare -A WANT=(["$V"]="$H_A" ["$W"]="$H_AW")
    WAVE_CUT=0
    for f in "$V" "$W"; do
        left=$(window_left "$T_WAVE")
        if [ "$left" -le 0 ]; then
            rough "timing: owner window of the wave nearly over (${left}s left); rest of the wave skipped"
            WAVE_CUT=1; break
        fi
        if restore_from_network 0 "$f" "${WANT[$f]}" "$left"; then
            pass "restore $(basename "$f") from the network: $RESTORE_MSG"
        else
            fail "backup-i9: restore $(basename "$f") from the network: $RESTORE_MSG"
            [ "$f" = "$V" ] && [ -n "${RESTORE_JOB_JSON:-}" ] && info "V's B has sha $H_B"
        fi
    done
    if [ "$WAVE_CUT" -eq 0 ]; then
        D_XA=$(( $(restore_responses_for "$XA" "${HOLDERS[@]}") - SERVED_XA0 ))
        D_XAW=$(( $(restore_responses_for "$XAW" "${HOLDERS[@]}") - SERVED_XAW0 ))
        D_XB=$(( $(restore_responses_for "$XB" "${HOLDERS[@]}") - SERVED_XB0 ))
        D_XR=$(( $(restore_responses_for "$XR" "${HOLDERS[@]}") - SERVED_XR0 ))
        if [ "$D_XA" -ge 1 ] && [ "$D_XAW" -ge 1 ]; then
            pass "holders served the current versions: RestoreResponse +$D_XA for XA, +$D_XAW for XAW"
        else
            fail "holders did not serve the current versions: +$D_XA for XA, +$D_XAW for XAW"
        fi
        if [ "$D_XB" -eq 0 ] && [ "$D_XR" -eq 0 ]; then
            pass "no holder served the undone versions (XB +0, XR +0)"
        else
            fail "backup-i9: holders served undone versions: XB +$D_XB, XR +$D_XR"
        fi
    fi
fi

# ── STEPS 11-12: PHASE B (L0-identity) ───────────────────────────
if run_b; then
    echo ""
    echo "=== Steps 11-12: PHASE B ==="
    skip_b 11; skip_b 12
fi

# ── STEP 13: SHUTDOWN ────────────────────────────────────────────
echo ""
echo "=== Step 13: SIGTERM all ==="
for i in $(seq 0 $((NUM_NODES-1))); do kill -CONT "${DPID[$i]}" 2>/dev/null || true; done
for i in $(seq 0 $((NUM_NODES-1))); do kill -TERM "${DPID[$i]}" 2>/dev/null || true; done
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_pid_exit "${DPID[$i]}" 15 && [ "$EXIT_RC" = 0 ]; then
        :
    else
        fail "node-0$i did not exit 0 within 15s after SIGTERM (rc=${EXIT_RC:-still running})"
    fi
    unset "DPID[$i]"
done
PANICS=$(grep -la "panicked" "$T"/node-*/daemon.log 2>/dev/null || true)
if [ -z "$PANICS" ]; then
    pass "all nodes exited; no panic in any log"
else
    fail "panic in: $PANICS"
fi

# ── SUMMARY ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  SUMMARY (PHASE=$PHASE): $PASS passed, $FAIL failed, $ROUGH rough, $SKIPPED skipped"
echo "============================================================"
echo "Logs: $T/node-*/daemon.log"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 flush / dedup lines (last 20) ==="
    grep -aE "flush|dedup" "$(node_log 0)" | tail -20 || true
    exit 1
fi
if [ "$SKIPPED" -gt 0 ]; then
    echo "  PHASE B steps are stubs (L0-identity not implemented): nothing proven for B"
    exit 1
fi
[ "$ROUGH" -eq 0 ] || exit 3
exit 0
