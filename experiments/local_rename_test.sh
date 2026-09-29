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
#               a move longer than the owner window; a rollback while the edit is still queued
#               (unit only: dedup_same_path_after_supersede_does_not_duplicate_version); the
#               large-file path process_large_file (no E2E file reaches the 128 MiB block).
# Expectation:  PHASE A is RED on the code before L1 (vps/run-1 ee01fb6):
#                 step 8  — the idle flush aborts on the vanished q1 ("flush error … q1.bin")
#                           and drops q2, q3 from the queue: they reach no holder within 20 s
#                           (only the 60 s periodic rescan would bring them back; the step
#                           repeats when a rescan falls into its window);
#                 step 9  — V rolled back to A keeps its last block XB (the same-path dedup
#                           only set Present); W put back from `restore --version 1` keeps XR;
#                 step 10 — restore of V returns B (holders log RestoreResponse for XB), W
#                           returns R.
#               GREEN after L1 (К1 + К2a).
#               PHASE B is RED on the code before L0 (vps/run-1 9a8b882 = L1 only):
#                 step 2  — a directory moved in gives no event per file: p1..p3 are not in
#                           the catalog within 15 s (only the periodic rescan adds them; the
#                           step repeats when one falls into its window);
#                 step 3  — a move to the trash is read as Modified: T, G stay present;
#                 step 5  — m1, m2, R2 stay present; the PoS rebuild of PM by file_id reads
#                           the gone m1.bin: owner WARN, no holder answer;
#                 step 5b — PD rebuilt by file_id puts d2's bytes in d1's slot: no answer;
#                 step 6  — PC rebuilt from the edited c1 / the gone c2: no answer;
#                 step 7  — PM never proven again, the ghost m3.bin never deleted;
#                 step 7b — no overflow handling: after.bin waits for the periodic rescan
#                           (ROUGH/FAIL), Z.bin is never deleted;
#                 step 10 — restore of m1-renamed, photos/m2, m3-offline, R1, d1, d2,
#                           photos/c1-copy fails ("file_id … not found in pack", or d2's
#                           bytes for d1);
#                 step 11 — no Delete for XT, XG, XZ; photos/ not in error, keep1..3 deleted;
#                 step 12 — keep1..keep3, deleted one by one by their Remove events, get a
#                           Delete on their holders.
#               Step 4 (atomic save) and 1B are GREEN on the old code too (guards).
#               GREEN after L0-identity (К4, К2b, К3).
# Phases:       PHASE=all (default, ≈ 25 min) | PHASE=A (≈ 5 min) | PHASE=B (≈ 20 min).
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
#       after the STOP, and q2's and q3's block built after it (`backup: pipeline complete`
#       with their block_id after the STOP) — else repeat with sleep 0.2, ≤ 2 times; ≤ 20 s
#       q2, q3 ≥ k_eff on holder disks; no periodic rescan in the window (else repeat)
#       (backup-i23) — check: grep, block_symbols_on, assert_no_periodic_since
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
#   PHASE B (all checks on node-00's catalog are backed by holder logs of OTHER nodes):
#   1B. T G S R1 R2 Z K (64 KiB) one by one, each alone in its block; photos/keep1..3 by
#       one mv; packs M = m1..m3, C = c1..c3, D = d1, d2 (one mv each) → blocks, >= k_eff
#       on holders; members of a pack on one block (else FAIL "setup: pack not built");
#       >= 1 holder PoS answer for PM <= 120 s (else the PoS checks are blind)
#   2.  mv $T/src/album files/album (p1..p3) → <= 15 s all three present; "moved-in
#       directory scanned dir=…/album"; one pack AL, restorable; no periodic rescan in the
#       window (else repeat with album2, album3) (backup-i22, restore-i17)
#   3.  T to $T/trash, G into files/.Trash-1000/files → <= 10 s both deleted; 0 "recheck:
#       path gone" lines for T, G (deleted by the event); no catalog path under
#       .Trash-1000; before T_TR + W - 20 restore T from the network: sha, RestoreResponse
#       for XT (delete-i12)
#   4.  ADVERSARIAL atomic save: random > S.bin.tmp-1; mv over S.bin → <= 15 s S present on
#       XS2 != XS; S.bin.tmp-1 not in the catalog; no periodic rescan (else repeat)
#   5.  mv m1 → m1-renamed, m2 → photos/m2, R2 over R1, album → album-2026 → new paths on
#       PM, PM, X2, AL; old paths deleted; positive control "pipeline complete" before, 0 in
#       the 15 s rename window (no new block); rescan guard (repeat as album-2027)
#   5b. ADVERSARIAL swap d1 ↔ d2 via tmp → last versions swapped, both on PD
#   6.  cp c1, c2 → photos/c1-copy, c2-copy on PC; then c1 edited, c2 removed
#   5-6 (parallel windows): per action T, >= 1 holder PoS answer in [T+35, T+215] for PM,
#       X2, AL (5), PD (5b), PC (6); 0 owner WARN "cannot load source block" for them; 0
#       holder "stored symbols" for PM, X2, AL (no re-upload) (backup-i22)
#   7.  ADVERSARIAL SIGTERM node-00, mv m3 → m3-offline, start → 4 peers <= 90 s;
#       m3-offline on PM <= 90 s; PoS answer for PM in [start+35, start+215], 0 owner WARN
#       once m3-offline is found; <= 180 s m3.bin deleted AND a "recheck: path gone" line
#       for it (delete-i12 (в))
#   7b. ADVERSARIAL SIGSTOP; ceil((max_queued_events + 1000) / 3) files in flood/ (ignored);
#       Z to the trash; after.bin created; SIGCONT → setup "inotify event queue
#       overflowed" (else FAIL); <= 20 s after.bin present and "overflow rescan complete",
#       no periodic rescan (else ROUGH); <= 120 s Z deleted with a recheck line; no flood/
#       path in the catalog (delete-i12 (в), dr-i64)
#   10. (B) control: XT marked for deletion on >= 1 holder; none for XS2, PM, PD, X2, AL.
#       Wave 1: rm m1-renamed, photos/m2, m3-offline, R1, album-2026/*; restore m1-renamed,
#       m2, m3-offline, album-2026/p2, R1 (= R2) from the network; RestoreResponse for PM,
#       AL, X2. Wave 2 (with A's V, W): rm d1, d2, photos/c1-copy, c2-copy, c3; restore
#       d1 (= d2's content), d2 (= d1's), photos/c1-copy, and c1 --version 1 (c1 edited, on
#       disk); RestoreResponse for PD, PC (restore-i38)
#   11. (a) Delete marks for XT, XG, XZ on >= 2 holders, none for U (A). K to the trash;
#       photos/ moved away file by file (cp to $T/elsewhere, rm, sleep 1; keep1 deleted
#       before the root goes, else FAIL setup); rmdir photos → <= 10 s /api/watches photos
#       error "moved, renamed or removed"; "watch root lost; recent deletions undone
#       files=N", N >= 1; keep1..3 present; K deleted (delete-i12 (а), dr-i64)
#   12. wait for K's Delete mark on ALL its holders (by T_ROOT + W + 60, else FAIL "control:
#       nothing proven"), + 10 s → no Delete mark for the keep blocks on any holder
#   13. SIGTERM all → exit 0 ≤ 15 s; no `panicked` in any log (network-i1) — check:
#       wait_pid_exit, grep
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   PHASE=A bash experiments/local_rename_test.sh

set -euo pipefail

PHASE="${PHASE:-all}"
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

# ── PHASE B helpers ──────────────────────────────────────────────
# Log times are read from the logs' own RFC 3339 stamps (e2e_lib `events`, T_BASE = 0:
# unix seconds), so a check can be deferred and still look at its own window.
T_BASE=0
declare -A HH BB

# secs_until T: seconds from now to unix time T, at least 1 (a poll runs once at worst).
secs_until() {
    local d=$(( $1 - $(date +%s) ))
    if [ "$d" -ge 1 ]; then echo "$d"; else echo 1; fi
}

# mk NAME BYTES: random file $SRC/NAME; its sha256 in HH[NAME].
mk() {
    head -c "$2" /dev/urandom > "$SRC/$1"
    HH[$1]=$(sha_of "$SRC/$1")
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

# events_between IDX PATTERN FROM TO: node IDX's log lines with PATTERN stamped in [FROM, TO].
events_between() {
    events "$(node_log "$1")" "$2" | awk -v a="$3" -v b="$4" '$1 >= a && $1 <= b' | wc -l
}

# block_events_between PATTERN BLOCK FROM TO: holder log lines with PATTERN and
# block_id=BLOCK (16 hex) stamped in [FROM, TO], over all holders.
block_events_between() {
    local pat="$1" hex="${2:0:16}" from="$3" to="$4" total=0 n i
    [ -n "$hex" ] || { echo 0; return; }
    for i in "${HOLDERS[@]}"; do
        n=$(events "$(node_log "$i")" "$pat" block_id \
            | awk -v a="$from" -v b="$to" -v h="$hex" '$1 >= a && $1 <= b && $3 == h' | wc -l)
        total=$((total + n))
    done
    echo "$total"
}

# pos_answers_between BLOCK FROM TO: holder PoS answers for BLOCK (processor/pos.rs DEBUG).
pos_answers_between() { block_events_between "responding with chain hash" "$@"; }

# stored_marks_between BLOCK FROM TO: holders storing symbols of BLOCK (a re-upload).
stored_marks_between() { block_events_between "processor: stored symbols for block" "$@"; }

# wait_pos_answer BLOCK FROM SECS: poll until a holder answered PoS for BLOCK since FROM.
wait_pos_answer() {
    for _ in $(seq 1 "$3"); do
        [ "$(pos_answers_between "$1" "$2" "$(date +%s)")" -ge 1 ] && return 0
        sleep 1
    done
    return 1
}

# owner_warn_since LINE0 BLOCK: node-00 could not rebuild BLOCK for a PoS challenge.
owner_warn_since() {
    log_since 0 "$1" | grep -a "cannot load source block for PoS hash" \
        | grep -acF "block_id=${2:0:16}" || true
}

# recheck_lines_since LINE0 PATH...: node-00 recheck lines ("recheck: path gone") for PATHs.
recheck_lines_since() {
    local line0="$1"; shift
    local total=0 p n
    for p in "$@"; do
        n=$(log_since 0 "$line0" | awk -v want="path=$p" \
            'index($0, "recheck: path gone") && $NF == want' | wc -l)
        total=$((total + n))
    done
    echo "$total"
}

# holders_of BLOCK: holders with >= 1 symbol of BLOCK on disk.
holders_of() {
    local i out=()
    for i in "${HOLDERS[@]}"; do
        [ "$(block_symbols_on "$i" "$1")" -ge 1 ] && out+=("$i")
    done
    echo "${out[@]}"
}

# pos_window_checks LABEL:BLOCK:T_ACTION:LINE_ACTION...: for each, >= 1 holder PoS answer
# for BLOCK in [T_ACTION + 35, T_ACTION + 215] (a challenge issued after the action and
# answered: the owner rebuilt the block from what is on disk now), and no owner WARN "cannot
# load source block" for it since LINE_ACTION. The windows run in parallel.
pos_window_checks() {
    local spec label block t0 line0 done_all now answered warns
    declare -A ok=()
    while :; do
        now=$(date +%s); done_all=1
        for spec in "$@"; do
            IFS=: read -r label block t0 line0 <<< "$spec"
            [ -n "${ok[$label]:-}" ] && continue
            answered=$(pos_answers_between "$block" "$((t0 + 35))" "$((t0 + 215))")
            if [ "$answered" -ge 1 ]; then
                ok[$label]=1
                warns=$(owner_warn_since "$line0" "$block")
                if [ "${warns:-0}" -eq 0 ]; then
                    pass "$label ${block:0:16}..: holders answered a new PoS challenge $(( now - t0 ))s after the action; no owner WARN"
                else
                    fail "backup-i22: $label: $warns owner WARN(s) 'cannot load source block' since the action"
                fi
            elif [ "$now" -gt $((t0 + 215)) ]; then
                ok[$label]=1
                fail "backup-i22: $label ${block:0:16}..: no holder PoS answer in [+35, +215]s; owner WARNs $(owner_warn_since "$line0" "$block")"
            else
                done_all=0
            fi
        done
        [ "$done_all" -eq 1 ] && return 0
        sleep 5
    done
}

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

# ── STEP 1B: SEED (PHASE B) ──────────────────────────────────────
if run_b; then
    echo ""
    echo "=== Step 1B: seed T G S R1 R2 Z K one by one; keep1..3; packs M, C, D ==="
    # Singles each get their own pack (the next file moves in once the previous has a
    # block); a pack's members move in by one mv.
    for n in T G S R1 R2 Z K; do
        mk "$n.bin" 65536
        mv "$SRC/$n.bin" "$FILES/"
        if ! BB[$n]=$(wait_block "$FILES/$n.bin" 60); then
            fail "setup: $n.bin got no block within 60s"; exit 1
        fi
    done
    for n in keep1 keep2 keep3; do mk "$n.bin" 65536; done
    mv "$SRC/keep1.bin" "$SRC/keep2.bin" "$SRC/keep3.bin" "$PHOTOS/"
    for n in keep1 keep2 keep3; do
        BB[$n]=$(wait_block "$PHOTOS/$n.bin" 60) || { fail "setup: photos/$n.bin got no block"; exit 1; }
    done
    for set in "m1 m2 m3" "c1 c2 c3" "d1 d2"; do
        srcs=()
        for n in $set; do mk "$n.bin" 65536; srcs+=("$SRC/$n.bin"); done
        mv "${srcs[@]}" "$FILES/"
        for n in $set; do
            BB[$n]=$(wait_block "$FILES/$n.bin" 60) || { fail "setup: $n.bin got no block"; exit 1; }
        done
        first=${set%% *}
        for n in $set; do
            if [ "${BB[$n]}" != "${BB[$first]}" ]; then
                fail "setup: pack not built ($n.bin on ${BB[$n]:0:16}.., $first.bin on ${BB[$first]:0:16}..)"
                exit 1
            fi
        done
    done
    PM=${BB[m1]}; PC=${BB[c1]}; PD=${BB[d1]}
    XT=${BB[T]}; XG=${BB[G]}; XS=${BB[S]}; X1=${BB[R1]}; X2=${BB[R2]}; XZ=${BB[Z]}; XK=${BB[K]}
    # Each single is alone in its block (its Delete must not wait for a live neighbour).
    for n in T G S R1 R2 Z K; do
        for m in T G S R1 R2 Z K keep1 m1 c1 d1; do
            if [ "$n" != "$m" ] && [ "${BB[$n]}" = "${BB[$m]}" ]; then
                fail "setup: $n.bin shares block ${BB[$n]:0:16}.. with $m.bin"; exit 1
            fi
        done
    done
    for p in T G S R1 R2 Z K m1 c1 d1; do
        if ! wait_on_holders "$FILES/$p.bin" 60; then
            fail "setup: $p.bin: holders hold $OH_ON of ${OH_BLOCK:0:16}.., need k_eff ${OH_TARGET:-?}"
            exit 1
        fi
    done
    wait_on_holders "$PHOTOS/keep1.bin" 60 || { fail "setup: keep pack not on holders"; exit 1; }
    pass "seeded: 7 singles, keep pack ${BB[keep1]:0:16}.., PM ${PM:0:16}.., PC ${PC:0:16}.., PD ${PD:0:16}.., all >= k_eff on holders"
    # The PoS observable is not blind: holders answer challenges for PM.
    T_SEEDED=$(date +%s)
    if wait_pos_answer "$PM" "$((T_SEEDED - 120))" 120; then
        pass "holders answer PoS for PM (observable not blind)"
    else
        fail "setup: no PoS answer for PM within 120s — the PoS checks of steps 5-7 would be blind"
        exit 1
    fi
fi

# ── STEP 2: A DIRECTORY MOVED IN ─────────────────────────────────
if run_b; then
    echo ""
    echo "=== Step 2: a directory moved in is scanned (backup-i22, restore-i17) ==="
    STEP2_DONE=0
    for attempt in 1 2 3; do
        ALBUM=album; [ "$attempt" -gt 1 ] && ALBUM="album$attempt"
        mkdir -p "$SRC/$ALBUM"
        for p in p1 p2 p3; do mk "$ALBUM/$p.bin" 65536; done
        LINE2=$(log_line_count 0)
        mv "$SRC/$ALBUM" "$FILES/$ALBUM"
        IN=0
        for _ in $(seq 1 15); do
            IN=0
            for p in p1 p2 p3; do
                [ "$(file_field 0 "$FILES/$ALBUM/$p.bin" '.local_state')" = present ] && IN=$((IN + 1))
            done
            [ "$IN" -eq 3 ] && break
            sleep 1
        done
        if ! assert_no_periodic_since "$LINE2"; then
            info "attempt $attempt: a periodic rescan ran in the window (it adds the files too); repeating"
            continue
        fi
        STEP2_DONE=1
        if [ "$IN" -eq 3 ]; then
            pass "$ALBUM/p1..p3 in the catalog within 15s of the directory move"
        else
            fail "backup-i22: $IN/3 of $ALBUM/p1..p3 in the catalog 15s after the directory move"
        fi
        if has "$(log_since 0 "$LINE2")" "moved-in directory scanned dir=$FILES/$ALBUM"; then
            pass "node-00 logged 'moved-in directory scanned' for $ALBUM"
        else
            fail "no 'moved-in directory scanned dir=$FILES/$ALBUM' line"
        fi
        break
    done
    [ "$STEP2_DONE" -eq 1 ] || { rough "step 2: every attempt met a periodic rescan — not proven"; }
    for p in p1 p2 p3; do
        BB[$ALBUM/$p]=$(wait_block "$FILES/$ALBUM/$p.bin" 60) || { fail "setup: $ALBUM/$p got no block"; exit 1; }
    done
    AL=${BB[$ALBUM/p1]}
    ALBUM0=$ALBUM
    if [ "${BB[$ALBUM/p2]}" != "$AL" ] || [ "${BB[$ALBUM/p3]}" != "$AL" ]; then
        fail "setup: $ALBUM/p1..p3 not in one pack"; exit 1
    fi
    if wait_file_restorable 0 "$FILES/$ALBUM/p1.bin" 60 && wait_on_holders "$FILES/$ALBUM/p1.bin" 60; then
        pass "$ALBUM pack AL ${AL:0:16}.. restorable, $OH_ON >= k_eff on holders"
    else
        fail "setup: $ALBUM pack AL not on holders ($OH_ON/${OH_TARGET:-?})"; exit 1
    fi
fi

# ── STEP 3: TRASH ────────────────────────────────────────────────
if run_b; then
    echo ""
    echo "=== Step 3: T to the trash, G into a hidden .Trash-1000 (delete-i12) ==="
    SERVED_XT0=$(restore_responses_for "$XT" "${HOLDERS[@]}")
    LINE_TR=$(log_line_count 0)
    T_TR=$(date +%s)
    mv "$FILES/T.bin" "$TRASH/files/"
    mkdir -p "$FILES/.Trash-1000/files"
    mv "$FILES/G.bin" "$FILES/.Trash-1000/files/"
    for n in T G; do
        if wait_file_deleted 0 "$FILES/$n.bin" 10; then
            pass "$n.bin deleted within 10s"
        else
            fail "delete-i12: $n.bin not deleted 10s after the move to the trash (state $(file_field 0 "$FILES/$n.bin" '.local_state'))"
        fi
    done
    RECHECK_TG=$(recheck_lines_since "$LINE_TR" "$FILES/T.bin" "$FILES/G.bin")
    if [ "$RECHECK_TG" -eq 0 ]; then
        pass "T, G deleted by their events: 0 'recheck: path gone' lines for them"
    else
        fail "delete-i12: $RECHECK_TG 'recheck: path gone' line(s) for T/G — deleted by the recheck, not by the event"
    fi
    HIDDEN=$(api_get 0 /api/files | jq -r '.[].path' 2>/dev/null | grep -c "/.Trash-1000/" || true)
    if [ "${HIDDEN:-0}" -eq 0 ]; then pass "no catalog path under .Trash-1000"
    else fail "$HIDDEN catalog path(s) under the hidden .Trash-1000"; fi
    left=$(( T_TR + OWNER_WINDOW - 20 - $(date +%s) ))
    if [ "$left" -le 0 ]; then
        rough "timing: the owner window of T ran out before its restore"
    elif restore_from_network 0 "$FILES/T.bin" "${HH[T.bin]}" "$left"; then
        pass "restore T from the network within the window: $RESTORE_MSG"
        D_XT=$(( $(restore_responses_for "$XT" "${HOLDERS[@]}") - SERVED_XT0 ))
        if [ "$D_XT" -ge 1 ]; then pass "holders logged $D_XT RestoreResponse(s) for XT"
        else fail "no holder logged a RestoreResponse for XT"; fi
    else
        fail "restore T from the network: $RESTORE_MSG"
    fi
fi

# ── STEP 4: ATOMIC SAVE OVER A LIVE FILE ─────────────────────────
if run_b; then
    echo ""
    echo "=== Step 4: ADVERSARIAL editor-style atomic save over S.bin (delete-i12) ==="
    STEP4_DONE=0
    for attempt in 1 2 3; do
        LINE4=$(log_line_count 0)
        PREV_S=$(file_block_hex 0 "$FILES/S.bin")
        head -c 262144 /dev/urandom > "$FILES/S.bin.tmp-1"
        mv "$FILES/S.bin.tmp-1" "$FILES/S.bin"
        XS2=$(wait_block_change "$FILES/S.bin" "$PREV_S" 15 || true)
        STATE_S=$(file_field 0 "$FILES/S.bin" '.local_state')
        TMP_IN=$(file_field 0 "$FILES/S.bin.tmp-1" '.path')
        if ! assert_no_periodic_since "$LINE4"; then
            info "attempt $attempt: a periodic rescan ran in the window; repeating with new content"
            continue
        fi
        STEP4_DONE=1
        if [ "$STATE_S" = present ] && [ -n "$XS2" ] && [ "$XS2" != "$XS" ]; then
            pass "S.bin present on a new block ${XS2:0:16}.. after the atomic save"
        else
            fail "delete-i12: after the atomic save S.bin is '$STATE_S' on '${XS2:0:16}' (XS ${XS:0:16}..)"
        fi
        if [ -z "$TMP_IN" ]; then pass "S.bin.tmp-1 is not in the catalog"
        else fail "the atomic-save temporary S.bin.tmp-1 is in the catalog"; fi
        break
    done
    [ "$STEP4_DONE" -eq 1 ] || rough "step 4: every attempt met a periodic rescan — not proven"
    wait_on_holders "$FILES/S.bin" 60 || info "XS2 not yet on holders ($OH_ON/${OH_TARGET:-?})"
fi

# ── STEPS 5, 5b, 6: RENAMES, A SWAP IN ONE PACK, COPIES ──────────
if run_b; then
    echo ""
    echo "=== Step 5: renames: m1 in place, m2 to photos/, R2 over R1, the album directory (backup-i22) ==="
    PIPE_BEFORE=$(log_since 0 0 | grep -c "backup: pipeline complete" || true)
    if [ "${PIPE_BEFORE:-0}" -ge 1 ]; then pass "positive control: node-00 logged $PIPE_BEFORE 'pipeline complete' before the renames"
    else fail "positive control: no 'pipeline complete' at node-00 before the renames — the check below would be blind"; fi
    STEP5_DONE=0
    for attempt in 1 2; do
        NEW_ALBUM="album-2026"; [ "$attempt" -gt 1 ] && NEW_ALBUM="album-2027"
        LINE_REN=$(log_line_count 0)
        T_REN=$(date +%s)
        if [ "$attempt" -eq 1 ]; then
            mv "$FILES/m1.bin" "$FILES/m1-renamed.bin"
            mv "$FILES/m2.bin" "$PHOTOS/m2.bin"
            mv "$FILES/R2.bin" "$FILES/R1.bin"
        fi
        mv "$FILES/$ALBUM" "$FILES/$NEW_ALBUM"
        sleep 15
        T_REN15=$(date +%s)
        if ! assert_no_periodic_since "$LINE_REN"; then
            info "attempt $attempt: a periodic rescan ran in the window; repeating the directory rename"
            ALBUM=$NEW_ALBUM
            continue
        fi
        STEP5_DONE=1
        break
    done
    [ "$STEP5_DONE" -eq 1 ] || rough "step 5: the directory rename met a periodic rescan twice — album part not proven"
    ALBUM=$NEW_ALBUM
    for pair in "m1-renamed.bin:$PM" "$ALBUM/p1.bin:$AL" "$ALBUM/p2.bin:$AL" "$ALBUM/p3.bin:$AL" "R1.bin:$X2"; do
        p=${pair%%:*}; want=${pair##*:}
        got=$(file_block_hex 0 "$FILES/$p")
        if [ "$got" = "$want" ] && [ "$(file_field 0 "$FILES/$p" '.local_state')" = present ]; then
            pass "$p present on ${want:0:16}.."
        else
            fail "backup-i22: $p on '${got:0:16}' state '$(file_field 0 "$FILES/$p" '.local_state')' (want ${want:0:16}..)"
        fi
    done
    got=$(file_block_hex 0 "$PHOTOS/m2.bin")
    if [ "$got" = "$PM" ]; then pass "photos/m2.bin present on PM"
    else fail "backup-i22: photos/m2.bin on '${got:0:16}' (want PM ${PM:0:16}..)"; fi
    for p in "$FILES/m1.bin" "$FILES/m2.bin" "$FILES/R2.bin"; do
        if [ "$(file_field 0 "$p" '.local_state')" = deleted ]; then pass "$(basename "$p") deleted"
        else fail "delete-i12: old path $(basename "$p") is '$(file_field 0 "$p" '.local_state')', not deleted"; fi
    done
    OLD_ALBUM_LIVE=$(api_get 0 /api/files | jq -r --arg d "$FILES/$ALBUM0/" \
        '[.[] | select((.path | startswith($d)) and .local_state != "deleted")] | length' 2>/dev/null || echo "?")
    if [ "$OLD_ALBUM_LIVE" = 0 ]; then pass "no live record left under the old album directory"
    else fail "delete-i12: $OLD_ALBUM_LIVE live record(s) under the old album directory"; fi
    PIPE_REN=$(events_between 0 "backup: pipeline complete" "$T_REN" "$T_REN15")
    if [ "$PIPE_REN" -eq 0 ]; then pass "no new block at node-00 in the rename window (0 'pipeline complete')"
    else fail "backup-i22: $PIPE_REN 'pipeline complete' line(s) at node-00 in the rename window"; fi

    echo ""
    echo "=== Step 5b: ADVERSARIAL d1, d2 of one pack swapped via tmp (backup-i22) ==="
    LINE_5B=$(log_line_count 0)
    T_5B=$(date +%s)
    mv "$FILES/d1.bin" "$FILES/tmp.bin"
    mv "$FILES/d2.bin" "$FILES/d1.bin"
    mv "$FILES/tmp.bin" "$FILES/d2.bin"
    SWAPPED=0
    for _ in $(seq 1 15); do
        V1=$(api_get 0 "/api/versions?path=$(urlencode "$FILES/d1.bin")")
        V2=$(api_get 0 "/api/versions?path=$(urlencode "$FILES/d2.bin")")
        if [ "$(echo "$V1" | jq -r '.[-1].content_hash_hex')" = "$(echo "$V2" | jq -r '.[0].content_hash_hex')" ] \
            && [ "$(echo "$V2" | jq -r '.[-1].content_hash_hex')" = "$(echo "$V1" | jq -r '.[0].content_hash_hex')" ] \
            && [ "$(echo "$V1" | jq -r '.[-1].source_block_id_hex')" = "$PD" ] \
            && [ "$(echo "$V2" | jq -r '.[-1].source_block_id_hex')" = "$PD" ]; then
            SWAPPED=1; break
        fi
        sleep 1
    done
    if [ "$SWAPPED" -eq 1 ]; then pass "d1, d2 swapped: their last versions hold each other's content, both on PD"
    else fail "backup-i22: after the swap d1/d2 versions are not swapped on PD"; fi

    echo ""
    echo "=== Step 6: copies of pack members, originals edited / deleted (backup-i22) ==="
    cp "$FILES/c1.bin" "$PHOTOS/c1-copy.bin"
    cp "$FILES/c2.bin" "$PHOTOS/c2-copy.bin"
    for c in c1-copy c2-copy; do
        if wait_last_block "$PHOTOS/$c.bin" "$PC" 15; then pass "photos/$c.bin on PC"
        else fail "backup-i22: photos/$c.bin on '$(file_block_hex 0 "$PHOTOS/$c.bin" | cut -c1-16)' (want PC)"; fi
    done
    LINE_6=$(log_line_count 0)
    T_6=$(date +%s)
    echo x >> "$FILES/c1.bin"
    rm "$FILES/c2.bin"
    if wait_block_change "$FILES/c1.bin" "$PC" 15 > /dev/null; then pass "c1.bin has a new version"
    else fail "c1.bin: no new version 15s after the edit"; fi
    if wait_file_deleted 0 "$FILES/c2.bin" 15; then pass "c2.bin deleted"
    else fail "delete-i12: c2.bin not deleted 15s after rm"; fi

    echo ""
    echo "=== Steps 5-6: holders answer new PoS challenges; no re-upload; no owner WARN ==="
    pos_window_checks "PM:$PM:$T_REN:$LINE_REN" "X2:$X2:$T_REN:$LINE_REN" "AL:$AL:$T_REN:$LINE_REN" \
        "PD:$PD:$T_5B:$LINE_5B" "PC:$PC:$T_6:$LINE_6"
    for pair in "PM:$PM" "X2:$X2" "AL:$AL"; do
        STORED=$(stored_marks_between "${pair##*:}" "$T_REN" "$(date +%s)")
        if [ "$STORED" -eq 0 ]; then pass "${pair%%:*}: no holder stored new symbols after the renames"
        else fail "backup-i22: holders stored symbols of ${pair%%:*} $STORED time(s) after the renames"; fi
    done
fi

# ── STEP 7: RENAME WHILE THE OWNER IS DOWN ───────────────────────
if run_b; then
    echo ""
    echo "=== Step 7: ADVERSARIAL m3 renamed while node-00 is down (backup-i22, delete-i12 (в)) ==="
    kill -TERM "${DPID[0]}"
    if wait_pid_exit "${DPID[0]}" 15 && [ "$EXIT_RC" = 0 ]; then pass "node-00 stopped (exit 0)"
    else fail "node-00 did not exit 0 within 15s (rc=${EXIT_RC:-running})"; exit 1; fi
    mv "$FILES/m3.bin" "$FILES/m3-offline.bin"
    LINE_7=$(log_line_count 0)
    start_node 0
    T_7=$(date +%s)
    wait_daemon 0 || { fail "node-00 did not restart"; exit 1; }
    if wait_auth_peers 0 4 90; then pass "node-00 back with 4 authenticated peers"
    else fail "node-00 back with $(status_num 0 peer_count_authenticated)/4 peers after 90s"; fi
    if wait_last_block "$FILES/m3-offline.bin" "$PM" 90; then pass "m3-offline.bin on PM (found by the scan)"
    else fail "backup-i22: m3-offline.bin on '$(file_block_hex 0 "$FILES/m3-offline.bin" | cut -c1-16)' 90s after the restart (want PM)"; fi
    # Owner WARNs count from here: until the scan finds m3-offline (the start scan is
    # skipped when the last one is recent; the periodic one runs within 60 s) PM's
    # content m3 is honestly nowhere, and that PoS attempt is not what this step proves.
    LINE_7M=$(log_line_count 0)
    pos_window_checks "PM(after restart):$PM:$T_7:$LINE_7M"
    M3_GONE=0
    for _ in $(seq 1 180); do
        if [ "$(file_field 0 "$FILES/m3.bin" '.local_state')" = deleted ] \
            && [ "$(recheck_lines_since "$LINE_7" "$FILES/m3.bin")" -ge 1 ]; then
            M3_GONE=1; break
        fi
        sleep 1
    done
    if [ "$M3_GONE" -eq 1 ]; then pass "the ghost m3.bin was deleted by the recheck after the rebuild read m3-offline"
    else fail "delete-i12 (в): m3.bin '$(file_field 0 "$FILES/m3.bin" '.local_state')', recheck lines $(recheck_lines_since "$LINE_7" "$FILES/m3.bin")"; fi
fi

# ── STEP 7b: AN INOTIFY OVERFLOW EATS A TRASH EVENT ──────────────
if run_b; then
    echo ""
    echo "=== Step 7b: ADVERSARIAL inotify overflow loses the trash event of Z (delete-i12 (в), dr-i64) ==="
    MAXQ=$(cat /proc/sys/fs/inotify/max_queued_events 2>/dev/null || echo 16384)
    FLOOD=$(( (MAXQ + 1000 + 2) / 3 ))
    LINE_7B=$(log_line_count 0)
    kill -STOP "${DPID[0]}"
    (cd "$FILES/flood" && seq -f 'f%06g' 1 "$FLOOD" | xargs touch)
    mv "$FILES/Z.bin" "$TRASH/files/"
    head -c 4096 /dev/urandom > "$FILES/after.bin"
    kill -CONT "${DPID[0]}"
    T_CONT7B=$(date +%s)
    OVER=0
    for _ in $(seq 1 10); do
        has "$(log_since 0 "$LINE_7B")" "inotify event queue overflowed" && { OVER=1; break; }
        sleep 1
    done
    if [ "$OVER" -eq 0 ]; then
        fail "setup: no overflow (no 'inotify event queue overflowed' after $FLOOD files)"; exit 1
    fi
    AFTER_OK=0
    for _ in $(seq 1 20); do
        if [ "$(file_field 0 "$FILES/after.bin" '.local_state')" = present ] \
            && has "$(log_since 0 "$LINE_7B")" "watcher: overflow rescan complete"; then
            AFTER_OK=1; break
        fi
        sleep 1
    done
    if ! assert_no_periodic_since "$LINE_7B"; then
        rough "step 7b: a periodic rescan ran in the window — the overflow rescan is not proven by after.bin"
    elif [ "$AFTER_OK" -eq 1 ]; then
        pass "after.bin in the catalog $(( $(date +%s) - T_CONT7B ))s after SIGCONT, by the overflow rescan"
    else
        fail "delete-i12 (в): after.bin '$(file_field 0 "$FILES/after.bin" '.local_state')' 20s after SIGCONT; overflow rescan line: $(log_since 0 "$LINE_7B" | grep -c 'overflow rescan complete' || true)"
    fi
    Z_GONE=0
    for _ in $(seq 1 120); do
        if [ "$(file_field 0 "$FILES/Z.bin" '.local_state')" = deleted ] \
            && [ "$(recheck_lines_since "$LINE_7B" "$FILES/Z.bin")" -ge 1 ]; then
            Z_GONE=1; break
        fi
        sleep 1
    done
    T_ZDEL=$(date +%s)
    if [ "$Z_GONE" -eq 1 ]; then pass "Z.bin, whose event was lost, deleted by the recheck"
    else fail "delete-i12 (в): Z.bin '$(file_field 0 "$FILES/Z.bin" '.local_state')' 120s after SIGCONT, recheck lines $(recheck_lines_since "$LINE_7B" "$FILES/Z.bin")"; fi
    FLOOD_IN=$(api_get 0 /api/files | jq -r '.[].path' 2>/dev/null | grep -c "/flood/" || true)
    if [ "${FLOOD_IN:-0}" -eq 0 ]; then pass "no flood/ path in the catalog"
    else fail "$FLOOD_IN flood/ path(s) in the catalog (.viaticumignore)"; fi
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
        on_holders "$Q2" || true; Q2_BLOCK=$OH_BLOCK; Q2_STATE="q2 ${OH_ON}/${OH_TARGET:-?} on ${OH_BLOCK:0:16}"
        on_holders "$Q3" || true; Q3_BLOCK=$OH_BLOCK; Q3_STATE="q3 ${OH_ON}/${OH_TARGET:-?} on ${OH_BLOCK:0:16}"

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
        # Setup: q2 and q3 were still queued at the STOP too — their block was built by a flush
        # after it ("backup: pipeline complete" with that block_id after LINE_STOP). A fallback
        # flush (every 4 s) between their events and the STOP would have packed them already:
        # the old code then passes, so the attempt is void. (Blocks are logged by 16 hex.)
        if [ "$Q_OK" -eq 1 ]; then
            AFTER=$(log_since 0 "$LINE_STOP" | grep -F "backup: pipeline complete" || true)
            if ! has "$AFTER" "block_id=${Q2_BLOCK:0:16}" || ! has "$AFTER" "block_id=${Q3_BLOCK:0:16}"; then
                info "attempt $attempt: q2/q3 were packed before the STOP (no pipeline line for their block after it); repeating"
                continue
            fi
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
        rough "step 8: 3 attempts, none had q1..q3 all queued at the STOP and missed the periodic rescan — not proven"
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
echo ""
echo "=== Step 10: every source gone; restore from the network (backup-i9, backup-i22, restore-i38) ==="
# restore_wave NAME=PATH:SHA...: restore each from the network while the owner window of
# the wave (T_WAVE) lasts; ROUGH and the rest skipped when it runs out.
restore_wave() {
    local item path want left
    WAVE_CUT=0
    for item in "$@"; do
        path=${item%%:*}; want=${item##*:}
        left=$(window_left "$T_WAVE")
        if [ "$left" -le 0 ]; then
            rough "timing: owner window of the wave nearly over (${left}s left); rest of the wave skipped"
            WAVE_CUT=1; return 0
        fi
        if restore_from_network 0 "$path" "$want" "$left"; then
            pass "restore ${path#"$N0"/} from the network: $RESTORE_MSG"
        else
            fail "restore ${path#"$N0"/} from the network: $RESTORE_MSG"
        fi
    done
}
# served_since NAME BLOCK BASE: RestoreResponse lines for BLOCK on holders minus BASE.
served_since() { echo $(( $(restore_responses_for "$2" "${HOLDERS[@]}") - $3 )); }

if run_b; then
    # Positive control first: the trash of step 3 did reach the holders.
    CTRL=0
    for _ in $(seq 1 "$(secs_until $(( T_TR + OWNER_WINDOW + 60 )))"); do
        [ "$(delete_marks_for "$XT" "${HOLDERS[@]}")" -ge 1 ] && { CTRL=1; break; }
        sleep 1
    done
    if [ "$CTRL" -eq 1 ]; then pass "control: a holder marked XT (trashed T) for deletion"
    else fail "control: no holder marked XT for deletion by T_TR + W + 60 — the negatives below prove nothing"; fi
    for pair in "XS2:$XS2" "PM:$PM" "PD:$PD" "X2:$X2" "AL:$AL"; do
        n=$(delete_marks_for "${pair##*:}" "${HOLDERS[@]}")
        if [ "$n" -eq 0 ]; then pass "no Delete for ${pair%%:*} (live content)"
        else fail "delete-i12/backup-i22: $n holder(s) marked ${pair%%:*} ${pair##*:} for deletion"; fi
    done

    echo "  -- wave 1: renamed / moved members of PM, the album, R1 (= R2) --"
    S_PM=$(restore_responses_for "$PM" "${HOLDERS[@]}")
    S_AL=$(restore_responses_for "$AL" "${HOLDERS[@]}")
    S_X2=$(restore_responses_for "$X2" "${HOLDERS[@]}")
    W1=("$FILES/m1-renamed.bin" "$PHOTOS/m2.bin" "$FILES/m3-offline.bin" "$FILES/R1.bin"
        "$FILES/$ALBUM/p1.bin" "$FILES/$ALBUM/p2.bin" "$FILES/$ALBUM/p3.bin")
    rm -f "${W1[@]}"
    T_WAVE=$(date +%s)
    for f in "${W1[@]}"; do
        wait_file_deleted 0 "$f" 15 || fail "${f#"$N0"/} not registered deleted within 15s"
    done
    restore_wave "$FILES/m1-renamed.bin:${HH[m1.bin]}" "$PHOTOS/m2.bin:${HH[m2.bin]}" \
        "$FILES/m3-offline.bin:${HH[m3.bin]}" "$FILES/$ALBUM/p2.bin:${HH[$ALBUM0/p2.bin]}" \
        "$FILES/R1.bin:${HH[R2.bin]}"
    if [ "$WAVE_CUT" -eq 0 ]; then
        for pair in "PM:$PM:$S_PM" "AL:$AL:$S_AL" "X2:$X2:$S_X2"; do
            IFS=: read -r label block base <<< "$pair"
            d=$(served_since "$label" "$block" "$base")
            if [ "$d" -ge 1 ]; then pass "holders served $label: RestoreResponse +$d"
            else fail "restore-i38: no holder served $label ${block:0:16}.. (the restore did not use the network)"; fi
        done
    fi
fi

echo "  -- wave 2: rollbacks (A); swapped and copied pack members (B) --"
W2=()
if run_a; then
    V="$FILES/V.bin"; W="$FILES/W.bin"
    SERVED_XB0=$(restore_responses_for "$XB" "${HOLDERS[@]}")
    SERVED_XR0=$(restore_responses_for "$XR" "${HOLDERS[@]}")
    SERVED_XA0=$(restore_responses_for "$XA" "${HOLDERS[@]}")
    SERVED_XAW0=$(restore_responses_for "$XAW" "${HOLDERS[@]}")
    W2+=("$V" "$W")
fi
if run_b; then
    S_PD=$(restore_responses_for "$PD" "${HOLDERS[@]}")
    S_PC=$(restore_responses_for "$PC" "${HOLDERS[@]}")
    W2+=("$FILES/d1.bin" "$FILES/d2.bin" "$PHOTOS/c1-copy.bin" "$PHOTOS/c2-copy.bin" "$FILES/c3.bin")
fi
rm -f "${W2[@]}"
T_WAVE=$(date +%s)
for f in "${W2[@]}"; do
    wait_file_deleted 0 "$f" 15 || fail "${f#"$N0"/} not registered deleted within 15s"
done
WAVE2=()
run_a && WAVE2+=("$V:$H_A" "$W:$H_AW")
# After the swap d1 holds d2's content and d2 holds d1's.
run_b && WAVE2+=("$FILES/d1.bin:${HH[d2.bin]}" "$FILES/d2.bin:${HH[d1.bin]}" \
    "$PHOTOS/c1-copy.bin:${HH[c1.bin]}")
restore_wave "${WAVE2[@]}"
if run_b && [ "$WAVE_CUT" -eq 0 ]; then
    # c1 is on disk (edited): its version 1 is on PC, which nothing on disk can rebuild.
    restore_run 0 "$(secs_until $(( T_WAVE + OWNER_WINDOW - WINDOW_MARGIN )))" "$FILES/c1.bin" --version 1
    STAGED=""
    if [ "$RESTORE_RC" -eq 0 ] \
        && [ "$(echo "$RESTORE_LAST" | jq -r '.outcome // "none"' 2>/dev/null)" = complete ]; then
        STAGED="$(echo "$RESTORE_LAST" | jq -r '.staging_path')/${FILES#/}/c1.bin"
    fi
    if [ -n "$STAGED" ] && [ -f "$STAGED" ] && [ "$(sha_of "$STAGED")" = "${HH[c1.bin]}" ]; then
        pass "restore c1 --version 1: sha of the packed c1"
    else
        fail "restore-i38: restore c1 --version 1: rc=$RESTORE_RC staged=${STAGED:-none} job=${RESTORE_LAST:0:300}"
    fi
fi
if [ "$WAVE_CUT" -eq 0 ]; then
    if run_a; then
        D_XA=$(served_since XA "$XA" "$SERVED_XA0"); D_XAW=$(served_since XAW "$XAW" "$SERVED_XAW0")
        D_XB=$(served_since XB "$XB" "$SERVED_XB0"); D_XR=$(served_since XR "$XR" "$SERVED_XR0")
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
    if run_b; then
        for pair in "PD:$PD:$S_PD" "PC:$PC:$S_PC"; do
            IFS=: read -r label block base <<< "$pair"
            d=$(served_since "$label" "$block" "$base")
            if [ "$d" -ge 1 ]; then pass "holders served $label: RestoreResponse +$d"
            else fail "restore-i38: no holder served $label ${block:0:16}.."; fi
        done
    fi
fi

# ── STEPS 11-12: THE WATCH ROOT MOVED AWAY FILE BY FILE ──────────
if run_b; then
    echo ""
    echo "=== Step 11: trash K; move photos/ away file by file, the root last (delete-i12, dr-i64) ==="
    # (a) the trashed files reached the holders: T and G by their events, Z by the recheck.
    for pair in "XT:$XT:$T_TR" "XG:$XG:$T_TR" "XZ:$XZ:$T_ZDEL"; do
        IFS=: read -r label block t0 <<< "$pair"
        n=0
        for _ in $(seq 1 "$(secs_until $(( t0 + OWNER_WINDOW + 60 )))"); do
            n=$(delete_marks_for "$block" "${HOLDERS[@]}")
            [ "$n" -ge 2 ] && break
            sleep 1
        done
        if [ "$n" -ge 2 ]; then pass "$label: $n holders marked it for deletion"
        else fail "delete-i12: only $n holder(s) marked $label ${block:0:16}.. for deletion"; fi
    done
    RECHECK_TG=$(recheck_lines_since "$LINE_TR" "$FILES/T.bin" "$FILES/G.bin")
    [ "$RECHECK_TG" -eq 0 ] || fail "delete-i12: $RECHECK_TG late 'recheck: path gone' line(s) for T/G"
    if run_a; then
        n=$(delete_marks_for "${X[U]}" "${HOLDERS[@]}")
        if [ "$n" -eq 0 ]; then pass "no Delete for the live U"
        else fail "$n holder(s) marked the live U for deletion"; fi
    fi

    read -r -a K_HOLDERS <<< "$(holders_of "$XK")"
    [ "${#K_HOLDERS[@]}" -ge 1 ] || { fail "setup: no holder has symbols of XK"; exit 1; }
    KEEP_BLOCKS=$(printf '%s\n' "${BB[keep1]}" "${BB[keep2]}" "${BB[keep3]}" | sort -u)
    LINE_11=$(log_line_count 0)
    T_ROOT=$(date +%s)
    mv "$FILES/K.bin" "$TRASH/files/"
    mkdir -p "$T/elsewhere"
    FIRST_OK=0
    for n in keep1 keep2 keep3; do
        cp "$PHOTOS/$n.bin" "$T/elsewhere/"
        rm "$PHOTOS/$n.bin"
        if [ "$n" = keep1 ]; then
            wait_file_deleted 0 "$PHOTOS/keep1.bin" 10 && FIRST_OK=1
        fi
        sleep 1
    done
    if [ "$FIRST_OK" -eq 0 ]; then
        fail "setup: keep1 not deleted before the root went (the first files must be dropped before the root)"
        exit 1
    fi
    rmdir "$PHOTOS" 2>/dev/null || rm -rf "$PHOTOS"
    ERR_OK=0
    for _ in $(seq 1 10); do
        W_JSON=$(api_get 0 /api/watches | jq -c --arg p "$PHOTOS" '.[] | select(.path == $p)' 2>/dev/null || true)
        if [ "$(echo "$W_JSON" | jq -r '.status' 2>/dev/null)" = error ] \
            && has "$(echo "$W_JSON" | jq -r '.error // ""')" "moved, renamed or removed"; then
            ERR_OK=1; break
        fi
        sleep 1
    done
    if [ "$ERR_OK" -eq 1 ]; then pass "photos/ in error: $(echo "$W_JSON" | jq -r '.error')"
    else fail "dr-i64: photos/ not in error 10s after the root went: ${W_JSON:0:300}"; fi
    UNDONE=$(log_since 0 "$LINE_11" | grep -a "watch root lost; recent deletions undone" | tail -1 || true)
    N_UNDONE=$(log_field "$UNDONE" files)
    if [ "${N_UNDONE:-0}" -ge 1 ]; then pass "node-00 undid $N_UNDONE recent deletion(s) under photos/"
    else fail "delete-i12 (а): no 'watch root lost; recent deletions undone files=N>=1' line (${UNDONE:-none})"; fi
    for n in keep1 keep2 keep3; do
        st=$(file_field 0 "$PHOTOS/$n.bin" '.local_state')
        if [ "$st" = present ]; then pass "$n present again"
        else fail "dr-i64: $n is '$st' after the root went"; fi
    done
    if wait_file_deleted 0 "$FILES/K.bin" 10; then pass "K deleted (control)"
    else fail "control: K not deleted"; fi

    echo ""
    echo "=== Step 12: Delete for K reaches all its holders; none for keep1..keep3 (delete-i12 (а), dr-i64) ==="
    K_ALL=0
    for _ in $(seq 1 "$(secs_until $(( T_ROOT + OWNER_WINDOW + 60 )))"); do
        marked=0
        for i in "${K_HOLDERS[@]}"; do
            [ "$(delete_marks_for "$XK" "$i")" -ge 1 ] && marked=$((marked + 1))
        done
        [ "$marked" -eq "${#K_HOLDERS[@]}" ] && { K_ALL=1; break; }
        sleep 1
    done
    if [ "$K_ALL" -eq 1 ]; then
        pass "control: all ${#K_HOLDERS[@]} holders of XK marked it for deletion"
        sleep 10
        KEEP_MARKS=0
        for b in $KEEP_BLOCKS; do
            KEEP_MARKS=$(( KEEP_MARKS + $(delete_marks_for "$b" "${HOLDERS[@]}") ))
        done
        if [ "$KEEP_MARKS" -eq 0 ]; then
            pass "no holder got a Delete for keep1..keep3 although their first deletions preceded the root's loss"
        else
            fail "delete-i12 (а)/dr-i64: $KEEP_MARKS Delete mark(s) for the keep blocks — a watch root moved away was deleted"
        fi
    else
        fail "control: nothing proven — not all holders of XK (${K_HOLDERS[*]}) marked it by T_ROOT + W + 60"
    fi
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
echo "  SUMMARY (PHASE=$PHASE): $PASS passed, $FAIL failed, $ROUGH rough"
echo "============================================================"
echo "Logs: $T/node-*/daemon.log"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== node-00 flush / dedup / recheck / root lines (last 30) ==="
    grep -aE "flush|dedup|recheck|watch root|moved-in|overflow" "$(node_log 0)" | tail -30 || true
    exit 1
fi
[ "$ROUGH" -eq 0 ] || exit 3
exit 0
