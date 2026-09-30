#!/bin/bash
# Viaticum: a file above the size limit is refused loudly, not "protected" (R1-d, CS-ERA-1).
# Local processes on one machine (no Docker).
#
# Scenario:     5 nodes, independent masters, star on node-00, time_scale 20000. node-00 (owner)
#               runs with max_file_size_mb = 256 (PHASE b: a 2 GiB block-work budget via test env,
#               glibc mmap threshold 64 KiB on all nodes). PHASE a: a sparse 4 GiB file, normal
#               files, a protected file in an importance-0 folder that grows over and shrinks
#               under the limit, a limit raise across a restart with a marked file removed while
#               down, the automatic limit on a default node, a config above the ceiling.
#               PHASE b: a random 240 MiB file measured on a fresh process; a second big file
#               delivered while two holders are stopped (budget held) with a small-pack PoS, a
#               big-block PoS and a network restore competing; a holder answering PoS on a
#               240 MiB share.
# Intent:       a: backup-i4, backup-i5, backup-i7 (backup-i1 for normal files)
#               b: backup-i24, pos-i13, pos-i14, restore-i39
# Proves:       a: an over-limit file is refused before any read and shown in files/status/
#               watches; no block is made for it (owner logs no "pipeline complete", no version), so the
#               other nodes get nothing; a grown protected file keeps its old
#               version, is not re-read, is no longer safe to delete, and holders stop getting
#               PoS for it; shrink / limit raise back it up; the start pass drops the mark of a
#               file removed while down.
#               b: the worker peak is within p <= 3.1 + R + 1; while a big block holds the
#               budget a small-pack PoS is still issued and answered, a big-block PoS is
#               deferred then served after the worker yields, a restore waits for memory and
#               completes; a holder answers PoS on a big share without reading it into RAM.
# Adversarial:  1 (4 GiB sparse); 3b (two holders SIGSTOPped during a big delivery); 4 (growth
#               under PoS); 6 (removed while down + raise).
# Cannot close: small machines (override emulates limit and budget, not memory pressure);
#               R = 10 and the effect of F5/F6 (unit alloc tests); production glibc settings
#               (mmap threshold is set for measurement); >3.44 GiB encode (never, RaptorQ guard
#               is a unit test); cgroup limits (unit); a file growing during the read (unit);
#               cluster siblings; DR onto a smaller machine; DR SS decode under the budget (unit);
#               4R ledger credit of anchor holders (T7); holders' disks are not compared in
#               step 1 (SystemState blocks land there any time; the owner's pipeline log is the
#               proof); step 4 memory: ok.bin / doc.txt are removed and the peak is reset right
#               after a fresh GB answer, a PoS of another block in flight is not excluded.
# Steps:        private/beta-planning/tasks/r1_bigfile_refusal.md §0.3
#
# Implemented here: PHASE=a (R1-d-a: steps 0a, 1, 1b, 2a, 4, 5, 6, 7, 8, 9). The steps of
# PHASE b (0b, 2b, 3, 3b, 3c) are stubs that print a NOTE ("R1-d-b, not implemented yet"):
# they never FAIL. PHASE=all currently = a + the stubs.
#
# Verdicts:     PASS / ROUGH / FAIL; exit 0 / 3 / 1. tmpfs dir ($T) is removed on PASS only.
#
# Usage:
#   ./rbuild.sh      # release binary, built on the server
#   PHASE=a bash experiments/local_bigfile_limit_test.sh     # a | b | all (default all)

set -euo pipefail

PHASE="${PHASE:-all}"
case "$PHASE" in
    a | b | all) ;;
    *) echo "ERROR: PHASE must be a, b or all (got '$PHASE')"; exit 2 ;;
esac
run_a() { [ "$PHASE" = a ] || [ "$PHASE" = all ]; }
run_b() { [ "$PHASE" = b ] || [ "$PHASE" = all ]; }

NUM_NODES=5
TIME_SCALE=20000
T="/tmp/viaticum-bigfile-limit-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)

MIB=1048576
LIMIT_MB_0=256                 # node-00's max_file_size_mb (raised to 512 in step 6)
CEILING_MB=3072                # MAX_FILE_SIZE_CEILING (2A.1)
# Automatic limit: clamp(floor(M / RAM_DIVISOR), 32 MiB, 1 GiB). 32 = 2 * (14 + 2) with R1-d-b;
# 76 for R1-d-a alone (spec 2A.6). Set RAM_DIVISOR=76 to match a build without R1-d-b.
RAM_DIVISOR="${RAM_DIVISOR:-32}"
AUTO_FLOOR_BYTES=$((32 * MIB))
AUTO_CAP_BYTES=$((1024 * MIB))

PASS=0; FAIL=0; ROUGH=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }
rough() { echo "  ROUGH: $1"; ((ROUGH++)) || true; }
note() { echo "  NOTE: $1"; }
stub_b() { run_b && note "R1-d-b, not implemented yet: $1" || true; }

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

# glibc mmap threshold 64 KiB on all nodes: big buffers are mmap'd and returned to the OS, so
# VmHWM measures the work (step 3, PHASE b). Harmless in PHASE a.
# node-00: debug for the backup / scheduler / restore modules (the refusal, the mark and the
# source rebuild lines). Holders: the PoS answer line is DEBUG (processor/pos.rs).
# PHASE b adds the block-work budget of 2 GiB via the test-only env.
start_node() {
    local i="$1" dir; dir=$(node_dir "$i")
    local bw=()
    if run_b; then bw=(VIATICUM_TEST_BLOCK_WORK_BUDGET_MB=2048); fi
    if [ "$i" -eq 0 ]; then
        # node-00's folders come from config.toml ([[watch]] files/ and bulk/).
        env MALLOC_MMAP_THRESHOLD_=65536 "${bw[@]}" \
            RUST_LOG=info,viaticum::daemon::backup=debug,viaticum::daemon::scheduler=debug,viaticum::daemon::restore=debug \
            "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            >> "$(node_log "$i")" 2>&1 &
    else
        mkdir -p "$dir/files"
        env MALLOC_MMAP_THRESHOLD_=65536 \
            RUST_LOG=info,viaticum::daemon::processor::pos=debug \
            "$BINARY" --data-dir "$dir" daemon --time-scale "$TIME_SCALE" \
            --watch-dir "$dir/files" >> "$(node_log "$i")" 2>&1 &
    fi
    DPID[$i]=$!
}

cleanup() {
    local rc=$?
    echo ""
    echo "=== Cleanup ==="
    local i p
    for i in "${!DPID[@]}"; do kill -CONT "${DPID[$i]}" 2>/dev/null || true; done
    for i in "${!DPID[@]}"; do kill -TERM "${DPID[$i]}" 2>/dev/null || true; done
    sleep 1
    for i in "${!DPID[@]}"; do
        p="${DPID[$i]}"; kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
    done
    # Gigabytes of test data on tmpfs: keep the directory only when the run was not a PASS.
    if [ "$rc" -eq 0 ]; then
        case "$T" in
            /tmp/viaticum-bigfile-limit-*) rm -rf "$T"; echo "  Test dir removed (pass)" ;;
            *) echo "  Test dir: $T (unexpected path, kept)" ;;
        esac
    else
        echo "  Test dir: $T (kept for inspection, exit $rc)"
    fi
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

# Log times are read from the logs' own RFC 3339 stamps: T_BASE = 0 -> unix seconds.
T_BASE=0

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

ZERO_BLOCK=$(printf '0%.0s' $(seq 1 64))

# ── Helpers of this scenario ─────────────────────────────────────

# count_lines TEXT: number of non-empty lines in TEXT.
count_lines() { printf '%s' "$1" | grep -ac . || true; }

# poll SECS CMD ARGS...: run CMD until it succeeds (1 s apart); the last try decides.
poll() {
    local secs="$1"; shift
    for _ in $(seq 1 "$secs"); do
        "$@" && return 0
        sleep 1
    done
    "$@"
}

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
wait_on_holders() { poll "$2" on_holders "$1"; }

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

# tl_field IDX PATH JQ: a field of the catalog entry of PATH on node IDX ("none" when null).
tl_field() { file_field "$1" "$2" "$3 // \"none\""; }

# tl_size_is IDX PATH SIZE: PATH carries too_large.size_bytes == SIZE.
tl_size_is() { [ "$(tl_field "$1" "$2" '.too_large.size_bytes')" = "$3" ]; }

# tl_gone IDX PATH: PATH is in the catalog and carries no too_large mark.
tl_gone() { [ "$(tl_field "$1" "$2" '.too_large.size_bytes')" = none ] \
    && [ -n "$(file_field "$1" "$2" '.path')" ]; }

# status_is IDX FIELD VALUE: `status` field equals VALUE.
status_is() { [ "$(status_num "$1" "$2")" = "$3" ]; }

# versions_count PATH: number of versions of PATH on node-00.
versions_count() {
    api_get 0 "/api/versions?path=$(urlencode "$1")" | jq 'length' 2>/dev/null || echo 0
}

# make_file DEST SIZE_BYTES: random content, built in $SRC and moved in (one rename event).
make_random() {
    local dest="$1" size="$2" tmp="$SRC/$(basename "$1").$$"
    head -c "$size" /dev/urandom > "$tmp"
    mv "$tmp" "$dest"
}
# make_sparse DEST SIZE_BYTES: sparse file (no data blocks), built in $SRC and moved in.
make_sparse() {
    local dest="$1" size="$2" tmp="$SRC/$(basename "$1").$$"
    truncate -s "$size" "$tmp"
    mv "$tmp" "$dest"
}

# hwm_delta_check LABEL LIMIT_KIB: the peak RSS of node-00 since the last hwm_reset grew by
# less than LIMIT_KIB.
hwm_delta_check() {
    local d; d=$(hwm_delta_kb "${DPID[0]}")
    if [ -z "$d" ]; then fail "$1: cannot read VmHWM of node-00"; return; fi
    if [ "$d" -lt "$2" ]; then pass "$1: node-00 ΔVmHWM = $((d / 1024)) MiB < $(($2 / 1024)) MiB"
    else fail "$1: node-00 ΔVmHWM = $((d / 1024)) MiB >= $(($2 / 1024)) MiB (the file was read)"; fi
}

# auto_limit_bytes: sets AUTO_N and AUTO_M_BYTES (no subshell!): the expected automatic limit of a default node:
# clamp(floor(M / RAM_DIVISOR), 32 MiB, 1 GiB), M = min(MemTotal, memory.max of this cgroup
# and its ancestors; "max" = no limit). The daemons started here inherit this cgroup.
auto_limit_bytes() {
    local m p f lim n
    m=$(( $(awk '/^MemTotal:/ { print $2 }' /proc/meminfo) * 1024 ))
    p=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup 2>/dev/null || true)
    while [ -n "$p" ]; do
        f="/sys/fs/cgroup${p}/memory.max"
        if [ -r "$f" ]; then
            lim=$(cat "$f" 2>/dev/null || true)
            if [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -lt "$m" ]; then m=$lim; fi
        fi
        [ "$p" = "/" ] && break
        p="${p%/*}"; [ -n "$p" ] || p="/"
    done
    if [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then   # cgroup v1
        lim=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || true)
        if [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -lt "$m" ]; then m=$lim; fi
    fi
    AUTO_M_BYTES=$m
    n=$((m / RAM_DIVISOR))
    [ "$n" -lt "$AUTO_FLOOR_BYTES" ] && n=$AUTO_FLOOR_BYTES
    [ "$n" -gt "$AUTO_CAP_BYTES" ] && n=$AUTO_CAP_BYTES
    AUTO_N=$n
}

write_config() {
    local i="$1"
    {
        echo '[web_api]'
        echo 'enabled = true'
        echo 'bind = "127.0.0.1:0"'
        echo '[storage]'
        echo 'disk_reserve_gb = 0.0'
        echo '[backup]'
        echo 'upload_limit_mbit = 0'      # R1-u2 junction: no rate limit in this scenario
        if [ "$i" -eq 0 ]; then
            echo "max_file_size_mb = $LIMIT_MB_0"
            echo '[[watch]]'
            echo "path = \"$FILES\""
            echo '[[watch]]'
            echo "path = \"$BULK\""
            echo 'importance_multiplier = 0.0'   # importance 0 -> reliability target 0.5
        fi
    } > "$(node_dir "$i")/config.toml"
}

echo "============================================================"
echo "  Viaticum: a file above the size limit is refused (R1-d), PHASE=$PHASE"
echo "  Nodes: ${NUM_NODES}, time_scale: ${TIME_SCALE}"
echo "  Test dir: $T"
echo "============================================================"

# ── STEP 0: SETUP ────────────────────────────────────────────────
echo ""
echo "=== Step 0: init, configs, start, star ==="
assert_delete_window "$TIME_SCALE" 100
N0=$(node_dir 0)
FILES="$N0/files"
BULK="$N0/bulk"
SRC="$T/src"
mkdir -p "$SRC" "$FILES" "$BULK"

for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > /dev/null 2>&1
    write_config "$i"
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

# Manual limit on node-00 (backup-i4: the limit is a property of the machine, set by config).
WANT_0=$((LIMIT_MB_0 * MIB))
if poll 30 status_is 0 max_file_size_bytes "$WANT_0"; then
    pass "node-00 status: max_file_size_bytes == $WANT_0"
else
    fail "backup-i4: node-00 max_file_size_bytes == $(status_num 0 max_file_size_bytes), want $WANT_0"
fi
# Automatic limit on node-01 (default config).
auto_limit_bytes
info "M = min(MemTotal, cgroup) = $AUTO_M_BYTES bytes, divisor $RAM_DIVISOR -> expected automatic limit $AUTO_N bytes"
if poll 30 status_is 1 max_file_size_bytes "$AUTO_N"; then
    pass "node-01 status: max_file_size_bytes == $AUTO_N (automatic)"
else
    fail "backup-i4: node-01 max_file_size_bytes == $(status_num 1 max_file_size_bytes), want $AUTO_N (M=$AUTO_M_BYTES, divisor $RAM_DIVISOR)"
fi
stub_b "step 0 (b): block_work_budget_bytes == 2147483648 on node-00 + WARN '(test only)'; node-01 budget == floor(M*14/32)"
# The peak-RSS reset must work, otherwise every ΔVmHWM below is meaningless.
if hwm_reset "${DPID[0]}"; then
    HD=$(hwm_delta_kb "${DPID[0]}")
    if [ -n "$HD" ] && [ "$HD" -lt 16384 ]; then pass "VmHWM reset works (Δ = ${HD} KiB right after the reset)"
    else fail "setup: VmHWM of node-00 did not drop to VmRSS after clear_refs (Δ = ${HD:-?} KiB): the ΔVmHWM checks would be blind"; exit 1; fi
else
    fail "setup: cannot reset VmHWM of node-00 (echo 5 > /proc/PID/clear_refs)"; exit 1
fi

if run_a; then

# ── STEP 1: 4 GiB SPARSE FILE ────────────────────────────────────
echo ""
echo "=== Step 1: ADVERSARIAL sparse 4 GiB file above the limit (backup-i4, backup-i5) ==="
HUGE="$FILES/huge.mkv"
HUGE_SIZE=$((4 * 1024 * MIB))
hwm_reset "${DPID[0]}" || { fail "setup: VmHWM reset failed"; exit 1; }
LINE1=$(log_line_count 0)
make_sparse "$HUGE" "$HUGE_SIZE"
if poll 60 tl_size_is 0 "$HUGE" "$HUGE_SIZE"; then
    pass "huge.mkv marked too_large: size_bytes == $HUGE_SIZE"
else
    fail "backup-i4: huge.mkv has no too_large mark within 60s (too_large: $(file_field 0 "$HUGE" '.too_large'), status: $(file_field 0 "$HUGE" '.effective_status'))"
fi
sleep 20   # a refused file must stay refused: give the daemon time to do anything wrong
LIM=$(tl_field 0 "$HUGE" '.too_large.limit_bytes')
[ "$LIM" = "$WANT_0" ] && pass "too_large.limit_bytes == $WANT_0" \
    || fail "backup-i4: too_large.limit_bytes == $LIM, want $WANT_0"
LBU=$(file_field 0 "$HUGE" '.last_backed_up')
[ "$LBU" = never ] && pass "huge.mkv last_backed_up == \"never\"" \
    || fail "backup-i4: huge.mkv last_backed_up == '$LBU', want \"never\""
SAFE=$(file_field 0 "$HUGE" '.is_safe_to_delete')
[ "$SAFE" = false ] && pass "huge.mkv is_safe_to_delete == false" \
    || fail "backup-i4: huge.mkv is_safe_to_delete == '$SAFE', want false"
if status_is 0 files_too_large 1; then pass "status files_too_large == 1"
else fail "backup-i4: status files_too_large == $(status_num 0 files_too_large), want 1"; fi
W1=$(count_lines "$(owner_lines_since "$LINE1" "file too large to back up" | grep -aF huge.mkv || true)")
[ "$W1" -eq 1 ] && pass "exactly 1 WARN 'file too large to back up' for huge.mkv" \
    || fail "backup-i4: $W1 WARN 'file too large to back up' lines for huge.mkv since the file appeared, want 1"
hwm_delta_check "backup-i5 (huge.mkv not read)" $((64 * 1024))
# The watch folder is not green (backup-i4 observable).
watch_not_green() {
    api_get 0 /api/watches | jq -e --arg p "$FILES" \
        '.[] | select(.path == $p) | .traffic_light != "green"' > /dev/null 2>&1
}
if poll 90 watch_not_green; then
    pass "/api/watches: files/ traffic light is $(api_get 0 /api/watches | jq -r --arg p "$FILES" '.[] | select(.path == $p) | .traffic_light')"
else
    fail "backup-i4: /api/watches: files/ still green 90s after a too-large file appeared"
fi
# Nothing was packed or sent for huge.mkv. The check is on the owner: the pipeline logs
# "backup: pipeline complete" for every block it seals (INFO, no path), and nothing but
# huge.mkv is in a watched folder in this window, so any such line is huge.mkv's. The holders'
# disks are NOT compared: SystemState blocks (base after ~60 s, diffs every 60 s) land in
# their holdings/ at any time (local_delete_test does not use holding_bytes for that reason).
PC1=$(count_lines "$(owner_lines_since "$LINE1" "backup: pipeline complete")")
[ "$PC1" -eq 0 ] && pass "backup-i5: 0 'pipeline complete' lines on node-00 while only huge.mkv existed (no block was made, nothing went to the other nodes)" \
    || fail "backup-i5: $PC1 'pipeline complete' line(s) on node-00 while only huge.mkv existed: a block was made for the refused file"
V1=$(versions_count "$HUGE")
[ "$V1" -eq 0 ] && pass "huge.mkv has no version" \
    || fail "backup-i5: huge.mkv has $V1 version(s), want 0"

# ── STEP 1b: THE MARK IS NOT RE-EVALUATED LOUDLY ─────────────────
echo ""
echo "=== Step 1b: touch huge.mkv twice: DEBUG 'mark unchanged', still 1 WARN (backup-i4) ==="
LINE1B=$(log_line_count 0)
# touch changes the mtime; the same-size truncate is an IN_MODIFY the watcher never ignores.
touch "$HUGE"; sleep 2
truncate -s "$HUGE_SIZE" "$HUGE"; sleep 2
touch "$HUGE"; sleep 2
truncate -s "$HUGE_SIZE" "$HUGE"
count_unchanged() {
    [ "$(count_lines "$(owner_lines_since "$LINE1B" "too large, mark unchanged" | grep -aF huge.mkv || true)")" -ge 2 ]
}
if poll 30 count_unchanged; then
    pass "1b: >= 2 DEBUG 'too large, mark unchanged' for huge.mkv (the file was evaluated again)"
else
    fail "backup-i4: 1b: $(count_lines "$(owner_lines_since "$LINE1B" "too large, mark unchanged" | grep -aF huge.mkv || true)") DEBUG 'too large, mark unchanged' lines for huge.mkv after the touches, want >= 2"
fi
W1B=$(count_lines "$(owner_lines_since "$LINE1" "file too large to back up" | grep -aF huge.mkv || true)")
[ "$W1B" -eq 1 ] && pass "1b: still exactly 1 WARN for huge.mkv" \
    || fail "backup-i4: 1b: $W1B WARN 'file too large to back up' for huge.mkv, want 1 (one per file, not per evaluation)"

# ── STEP 2 (a): NORMAL FILES ─────────────────────────────────────
echo ""
echo "=== Step 2 (a): doc.txt 10 KB, ok.bin 100 MiB, bulk/grow.bin 200 MiB (backup-i1) ==="
DOC="$FILES/doc.txt"; OKB="$FILES/ok.bin"; GROW="$BULK/grow.bin"
make_random "$DOC" 10240
make_random "$OKB" $((100 * MIB))
make_random "$GROW" $((200 * MIB))
for p in "$DOC" "$OKB" "$GROW"; do
    if ! wait_file_restorable 0 "$p" 300; then
        fail "backup-i1: $(basename "$p") not restorable per node-00 after 300s"; exit 1
    fi
    if wait_on_holders "$p" 120; then
        pass "$(basename "$p") restorable, holders hold $OH_ON >= k_eff $OH_TARGET of ${OH_BLOCK:0:16}.."
    else
        fail "backup-i1: $(basename "$p"): holders hold $OH_ON of ${OH_BLOCK:0:16}.., need k_eff ${OH_TARGET:-?}"; exit 1
    fi
done
# Positive control of step 1: the line step 1 counted to zero is the one blocks are sealed with.
PC2=$(count_lines "$(owner_lines_since "$LINE1" "backup: pipeline complete")")
[ "$PC2" -ge 1 ] && pass "control of step 1: node-00 logged $PC2 'pipeline complete' line(s) for the step 2 blocks" \
    || fail "control of step 1: no 'pipeline complete' line for the step 2 blocks — step 1's zero proves nothing"
GB=$(file_block_hex 0 "$GROW")
[ -n "$GB" ] || { fail "setup: grow.bin has no block"; exit 1; }
T_GB_READY=$(date +%s)
info "grow.bin block GB = ${GB:0:16}.., importance-0 folder target $(file_field 0 "$GROW" '.effective_status.target')"
stub_b "step 2 (b): files/r.bin 200 MiB, full copy on node-01 or node-02"

fi  # run_a (steps 0a..2a)

# ── STEP 3, 3b, 3c: PHASE b ──────────────────────────────────────
echo ""
echo "=== Steps 3, 3b, 3c: peak of a 240 MiB encode, the memory budget, PoS on a big share ==="
stub_b "step 3 (worker peak p <= 3.1 + R + 1 on a fresh process)"
stub_b "step 3b (ADVERSARIAL: two holders SIGSTOPped, budget held; PoS deferred / small-pack PoS / restore waits)"
stub_b "step 3c (a holder answers PoS on a 240 MiB share, ΔVmHWM < 64 MiB)"
run_b || note "PHASE=$PHASE: steps 3, 3b, 3c belong to PHASE b (R1-d-b)"

if run_a; then

# ── STEP 4: GROWTH UNDER PoS ─────────────────────────────────────
echo ""
echo "=== Step 4: ADVERSARIAL a protected file grows over the limit (backup-i4, backup-i5, backup-i7) ==="
# Positive control 1: holders answer PoS for GB (else the "no PoS after growth" check is blind).
GB_ANSWERED=0
for _ in $(seq 1 120); do
    GB_ANSWERED=$(pos_answers_since "$GB" "$T_GB_READY")
    [ "$GB_ANSWERED" -ge 1 ] && break
    sleep 1
done
if [ "$GB_ANSWERED" -ge 1 ]; then pass "4 control: holders answered PoS for GB ($GB_ANSWERED answers)"
else rough "4 blind: no holder PoS answer for GB within 120s: 'no PoS after growth' cannot be proven"; fi
# Quiet the owner before the memory measurement: ok.bin (100 MiB) and doc.txt may share a pack,
# and a PoS issue for that pack re-reads it (a legitimate 100 MiB+ peak that would swamp the
# ΔVmHWM check). Both files served step 2; remove them now: the PoS rebuild of their block
# then fails cheaply on the missing member.
rm -f "$OKB" "$DOC"
wait_file_deleted 0 "$OKB" 60 && wait_file_deleted 0 "$DOC" 60 \
    || note "4: ok.bin / doc.txt not both registered as deleted in 60 s (the memory check may be noisy)"
# Positive control 2: the protected file is safe to delete before it grows.
safe_true() { [ "$(file_field 0 "$GROW" '.is_safe_to_delete')" = true ]; }
if poll 120 safe_true; then
    pass "4 control: grow.bin is_safe_to_delete == true before the growth"
else
    rough "4 M9 blind: grow.bin is_safe_to_delete != true within 120s: the 'no longer safe' check proves nothing"
fi
D=$(file_field 0 "$GROW" '.last_backed_up')
V_BEFORE=$(versions_count "$GROW")
info "grow.bin before: last_backed_up $D, $V_BEFORE version(s), block ${GB:0:16}.."
# Reset the peak right after a fresh holder answer for GB: the owner has just finished a PoS
# issue for GB (the 200 MiB rebuild), so none is likely to be mid-flight at the reset.
T_F=$(date +%s)
fresh_gb_answer() { [ "$(pos_answers_since "$GB" $((T_F + 1)))" -ge 1 ]; }
poll 90 fresh_gb_answer || note "4: no fresh PoS answer for GB in 90 s before the growth (the memory check may include a PoS in flight)"
hwm_reset "${DPID[0]}" || { fail "setup: VmHWM reset failed"; exit 1; }
LINE4=$(log_line_count 0)
T4=$(date +%s)
GROW_BIG=$((300 * MIB))
truncate -s 300M "$GROW"
if poll 60 tl_size_is 0 "$GROW" "$GROW_BIG"; then
    pass "grow.bin marked too_large: size_bytes == $GROW_BIG"
else
    fail "backup-i4: grow.bin has no too_large mark within 60s after growing to 300 MiB"
fi
LBU4=$(file_field 0 "$GROW" '.last_backed_up')
[ "$LBU4" = "$D" ] && pass "grow.bin last_backed_up still $D (the old version stands)" \
    || fail "backup-i7: grow.bin last_backed_up '$D' -> '$LBU4': the grown content was treated as backed up"
V4=$(versions_count "$GROW")
[ "$V4" = "$V_BEFORE" ] && pass "grow.bin has $V4 version(s), no new version for the grown content" \
    || fail "backup-i7: grow.bin versions $V_BEFORE -> $V4: a version was written for content above the limit"
SAFE4=$(file_field 0 "$GROW" '.is_safe_to_delete')
[ "$SAFE4" = false ] && pass "grow.bin is_safe_to_delete == false after the growth" \
    || fail "backup-i7: grow.bin is_safe_to_delete == '$SAFE4' after the growth, want false"
if poll 30 status_is 0 files_too_large 2; then pass "status files_too_large == 2"
else fail "backup-i4: status files_too_large == $(status_num 0 files_too_large), want 2"; fi
# The PoS issue for GB must try to rebuild the block and be refused before any read.
refused_rebuild() {
    [ "$(count_lines "$(owner_lines_since "$LINE4" "source over the size limit, not read" | grep -aF grow.bin || true)")" -ge 1 ]
}
if poll 120 refused_rebuild; then
    pass "backup-i5: DEBUG 'source over the size limit, not read' for grow.bin (the rebuild was tried and refused)"
else
    fail "backup-i5: no 'source over the size limit, not read' line for grow.bin within 120s (the PoS rebuild was not exercised, or it read the file)"
fi
# Window [LINE, +180 s]: exactly one WARN for GB; no PoS answers in [+60, +180].
while [ "$(date +%s)" -lt $((T4 + 180)) ]; do sleep 2; done
hwm_delta_check "backup-i5 (grown grow.bin not read)" $((64 * 1024))
# The same text is logged at WARN (once per unscaled day per block) and at DEBUG (every other
# tick), so the level decides. tracing's fmt prints the level as " WARN " / "DEBUG".
PWARN_TXT="cannot load source block for PoS"
PLINES4=$(owner_lines_since "$LINE4" "$PWARN_TXT" | grep -aF "block_id=${GB:0:16}" || true)
WARN4=$(count_lines "$(grep -aE '[[:space:]]WARN[[:space:]]' <<< "$PLINES4" || true)")
DBG4=$(count_lines "$(grep -aE '[[:space:]]DEBUG[[:space:]]' <<< "$PLINES4" || true)")
if [ "$DBG4" -ge 2 ]; then pass "4 control: $DBG4 DEBUG '$PWARN_TXT' for GB (the PoS issue kept trying, the refusals were quiet)"
else fail "backup-i7: only $DBG4 DEBUG '$PWARN_TXT' for GB in 180s, want >= 2 (the issue did not run every tick, so 'exactly 1 WARN' proves nothing)"; fi
if [ "$WARN4" -eq 1 ]; then pass "backup-i7: exactly 1 WARN '$PWARN_TXT' for GB in 180s"
elif [ "$WARN4" -eq 0 ]; then fail "backup-i7: no WARN '$PWARN_TXT' for GB in 180s (PoS not issued for GB, or the refusal is silent)"
else fail "backup-i7: $WARN4 WARN '$PWARN_TXT' for GB in 180s, want 1 (one per unscaled day)"; fi
ANS4=$(pos_answers_since "$GB" $((T4 + 60)) $((T4 + 180)))
if [ "$ANS4" -eq 0 ]; then pass "backup-i7: 0 holder PoS answers for GB in [+60, +180] s (holders stopped being challenged for the grown file)"
else fail "backup-i7: $ANS4 holder PoS answers for GB in [+60, +180] s after the growth"; fi
P4=$(count_lines "$(log_since 0 "$LINE4" | grep -a "panicked" || true)")
[ "$P4" -eq 0 ] && pass "no panic in node-00's log after the growth" || fail "backup-i5: $P4 'panicked' line(s) in node-00's log after the growth"

# ── STEP 5: SHRINK UNDER THE LIMIT ───────────────────────────────
echo ""
echo "=== Step 5: grow.bin shrinks to 100 MiB: the mark goes, a new version is backed up (backup-i4) ==="
LINE5=$(log_line_count 0)
truncate -s 100M "$GROW"
if poll 90 tl_gone 0 "$GROW"; then pass "grow.bin: too_large mark removed"
else fail "backup-i4: grow.bin still marked too_large 90s after shrinking to 100 MiB"; fi
if [ -n "$(owner_lines_since "$LINE5" "file is within the size limit again")" ]; then
    pass "INFO 'file is within the size limit again' logged"
else
    fail "backup-i4: no INFO 'file is within the size limit again' after the shrink"
fi
GB2=$(wait_block_change "$GROW" "$GB" 180) || GB2=""
if [ -n "$GB2" ]; then
    pass "grow.bin has a new version on block ${GB2:0:16}.. != GB ${GB:0:16}.."
    if wait_file_restorable 0 "$GROW" 180 && wait_on_holders "$GROW" 120; then
        pass "the new version is restorable, holders hold $OH_ON >= k_eff $OH_TARGET"
    else
        fail "backup-i4: the new grow.bin version is not restorable / not on holders (on $OH_ON of ${OH_TARGET:-?})"
    fi
else
    fail "backup-i4: grow.bin got no new block within 180s after shrinking (last block ${GB:0:16}..)"
fi
if poll 30 status_is 0 files_too_large 1; then pass "status files_too_large == 1"
else fail "backup-i4: status files_too_large == $(status_num 0 files_too_large), want 1"; fi

# ── STEP 6: LIMIT RAISE ACROSS A RESTART ─────────────────────────
echo ""
echo "=== Step 6: ADVERSARIAL a marked file removed while down + the limit raised (backup-i4) ==="
MID="$FILES/mid.bin"; GONE="$FILES/gone.bin"
make_sparse "$MID" $((300 * MIB))
make_sparse "$GONE" $((400 * MIB))
if poll 60 tl_size_is 0 "$MID" $((300 * MIB)) && poll 60 tl_size_is 0 "$GONE" $((400 * MIB)); then
    pass "mid.bin (300 MiB) and gone.bin (400 MiB) marked too_large"
else
    fail "backup-i4: mid.bin / gone.bin not both marked too_large within 60s"
fi
if poll 30 status_is 0 files_too_large 3; then pass "status files_too_large == 3"
else fail "backup-i4: status files_too_large == $(status_num 0 files_too_large), want 3"; fi
kill -TERM "${DPID[0]}"
if wait_pid_exit "${DPID[0]}" 30 && [ "$EXIT_RC" = 0 ]; then pass "node-00 stopped with exit 0"
else fail "node-00 did not exit 0 within 30s (rc=${EXIT_RC:-running})"; fi
unset "DPID[0]"
rm -f "$GONE"
LIMIT_MB_0=512
write_config 0
LINE6=$(log_line_count 0)
start_node 0
wait_daemon 0 || { fail "node-00 did not come back after the restart"; exit 1; }
RECON=""
for _ in $(seq 1 90); do
    RECON=$(owner_lines_since "$LINE6" "too-large marks reconciled" | head -1)
    [ -n "$RECON" ] && break
    sleep 1
done
if [ -n "$RECON" ]; then
    RQ=$(log_field "$RECON" requeued); DM=$(log_field "$RECON" dropped_missing)
    DO=$(log_field "$RECON" dropped_outside); KP=$(log_field "$RECON" kept)
    if [ "$RQ" = 1 ] && [ "$DM" = 1 ] && [ "${DO:-0}" = 0 ] && [ "$KP" = 1 ]; then
        pass "start pass: requeued=1 dropped_missing=1 dropped_outside=${DO:-0} kept=1"
    else
        fail "backup-i4: start pass: requeued=$RQ dropped_missing=$DM dropped_outside=${DO:-?} kept=$KP, want 1 / 1 / 0 / 1: $RECON"
    fi
else
    fail "backup-i4: no INFO 'too-large marks reconciled' within 90s after the restart"
fi
if poll 60 status_is 0 files_too_large 1; then pass "status files_too_large == 1 after the raise"
else fail "backup-i4: status files_too_large == $(status_num 0 files_too_large) after the raise, want 1"; fi
LIM6=$(tl_field 0 "$HUGE" '.too_large.limit_bytes')
[ "$LIM6" = 536870912 ] && pass "huge.mkv is still too_large with limit_bytes == 536870912" \
    || fail "backup-i4: huge.mkv too_large.limit_bytes == '$LIM6', want 536870912 (mark missing or limit not refreshed)"
status_is 0 max_file_size_bytes 536870912 && pass "status max_file_size_bytes == 536870912" \
    || fail "backup-i4: status max_file_size_bytes == $(status_num 0 max_file_size_bytes), want 536870912"
GONE_IN_CATALOG=$(api_get 0 /api/files | jq --arg p "$GONE" 'any(.[]; .path == $p)' 2>/dev/null || echo unknown)
[ "$GONE_IN_CATALOG" = false ] && pass "gone.bin: no mark and no catalog entry" \
    || fail "backup-i4: gone.bin is still listed on node-00 after removal while down (any entry: $GONE_IN_CATALOG)"
if wait_auth_peers 0 $((NUM_NODES-1)) 90; then :
else fail "after the restart only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 90s"; fi
if wait_file_restorable 0 "$MID" 300; then pass "mid.bin (300 MiB, below the raised limit) is restorable"
else fail "backup-i4: mid.bin not restorable 300s after the limit was raised"; fi

# ── STEP 7: AUTOMATIC LIMIT ON A DEFAULT NODE ────────────────────
echo ""
echo "=== Step 7: node-01 (default config): a file of limit + 1 byte is refused (backup-i4) ==="
EDGE="$(node_dir 1)/files/edge.bin"
make_sparse "$EDGE" $((AUTO_N + 1))
if poll 60 tl_size_is 1 "$EDGE" $((AUTO_N + 1)); then
    pass "edge.bin ($((AUTO_N + 1)) bytes) marked too_large on node-01"
else
    fail "backup-i4: edge.bin (limit + 1) has no too_large mark on node-01 within 60s"
fi
LIM7=$(tl_field 1 "$EDGE" '.too_large.limit_bytes')
[ "$LIM7" = "$AUTO_N" ] && pass "node-01 too_large.limit_bytes == $AUTO_N (M = $AUTO_M_BYTES)" \
    || fail "backup-i4: node-01 too_large.limit_bytes == '$LIM7', want $AUTO_N (M = $AUTO_M_BYTES, divisor $RAM_DIVISOR)"

# ── STEP 8: CONFIG ABOVE THE CEILING ─────────────────────────────
echo ""
echo "=== Step 8: max_file_size_mb = 4096 is refused at start with exit 78 (backup-i4) ==="
D8="$T/node-cfg"
mkdir -p "$D8"
"$BINARY" --data-dir "$D8" init > /dev/null 2>&1
{
    echo '[web_api]'
    echo 'enabled = true'
    echo 'bind = "127.0.0.1:0"'
    echo '[backup]'
    echo 'max_file_size_mb = 4096'
} > "$D8/config.toml"
RC8=0
OUT8=$(RUST_LOG=info timeout 30 "$BINARY" --data-dir "$D8" daemon --time-scale "$TIME_SCALE" 2>&1) || RC8=$?
if [ "$RC8" -eq 78 ]; then pass "daemon with max_file_size_mb = 4096 refused to start: exit 78"
else fail "backup-i4: daemon with max_file_size_mb = 4096 exited $RC8, want 78 (124 = it kept running)"; fi
if has "$OUT8" "$CEILING_MB"; then pass "the message names the ceiling $CEILING_MB"
else fail "backup-i4: the refusal does not name $CEILING_MB: ${OUT8:0:300}"; fi

fi  # run_a

# ── STEP 9: SHUTDOWN ─────────────────────────────────────────────
echo ""
echo "=== Step 9: SIGTERM all ==="
for i in $(seq 0 $((NUM_NODES-1))); do
    kill -TERM "${DPID[$i]}" 2>/dev/null || true
done
for i in $(seq 0 $((NUM_NODES-1))); do
    if wait_pid_exit "${DPID[$i]}" 30 && [ "$EXIT_RC" = 0 ]; then :
    else fail "node-0$i did not exit 0 within 30s (rc=${EXIT_RC:-running})"; fi
    unset "DPID[$i]"
done
PANICS=$(cat "$T"/node-*/daemon.log 2>/dev/null | grep -ac "panicked" || true)
if [ "${PANICS:-0}" -eq 0 ]; then pass "all daemons exited 0, no panic in any log"
else fail "$PANICS 'panicked' line(s) in the logs"; fi

echo ""
echo "============================================================"
echo "  PHASE=$PHASE  PASS: $PASS  ROUGH: $ROUGH  FAIL: $FAIL"
echo "============================================================"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
if [ "$ROUGH" -gt 0 ]; then exit 3; fi
exit 0
