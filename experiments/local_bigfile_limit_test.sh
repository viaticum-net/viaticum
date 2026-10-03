#!/bin/bash
# Viaticum: a file above the size limit is refused loudly, not "protected" (R1-d, CS-ERA-1).
# Local processes on one machine (no Docker).
#
# Scenario:     5 nodes, independent masters, star on node-00, time_scale 20000. node-00 (owner)
#               runs with max_file_size_mb = 256 (PHASE b: a 1792 MiB block-work budget via test env,
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
# Implemented here: PHASE=a (R1-d-a: steps 0a, 1, 1b, 2a, 4, 5, 6, 7, 8, 9) and PHASE=b (R1-d-b,
# K-b6, spec v3.11 + v3.11a: 0 (anchors in the binary), 0b, 2b-before, 3, 2b, 3b, 3c, 9).
# PHASE=all = a's steps 0a..2a, then b's 2b/3/3b/3c (step 3 is only printed, never judged: the
# blocks of PHASE a dirty its window), then a's steps 4..8, then 9.
# STOP_AFTER=<0b|3|2b|3b|3c> (PHASE b / all): end the run after that step (mutation runs); the
# whole-log checks and the shutdown still run.
# PHASE b order: 0, 0b, 2b-before (doc.txt), 3 (near.bin, fresh process), 2b (r.bin), 3b, 3c, 9.
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
case "${STOP_AFTER:-}" in
    "" | 0b | 3 | 2b | 3b | 3c) ;;
    *) echo "ERROR: STOP_AFTER must be 0b, 3, 2b, 3b or 3c (got '$STOP_AFTER')"; exit 2 ;;
esac
if [ -n "${STOP_AFTER:-}" ] && [ "$PHASE" = a ]; then echo "ERROR: STOP_AFTER needs PHASE b or all"; exit 2; fi
run_a() { [ "$PHASE" = a ] || [ "$PHASE" = all ]; }
run_b() { [ "$PHASE" = b ] || [ "$PHASE" = all ]; }

NUM_NODES=5
TIME_SCALE=20000
T="/tmp/viaticum-bigfile-limit-$$"
BINARY="${BINARY:-viaticum}"
HOLDERS=(1 2 3 4)

MIB=1048576
LIMIT_MB_0=256                 # node-00's max_file_size_mb (raised to 512 in step 6)
PACK_MB_0=32                   # node-00's source_block_size_mb (B_eff = 32 MiB)
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
# PHASE b adds the block-work budget of 1792 MiB via the test-only env (v3.11 §1) and the
# mem_budget / work_pipeline DEBUG lines on node-00. All nodes: VIATICUM_TEST_MACHINE_LOCK_DIR
# (exported by e2e_lib.sh).
start_node() {
    local i="$1" dir; dir=$(node_dir "$i")
    local bw=()
    if run_b; then bw=(VIATICUM_TEST_BLOCK_WORK_BUDGET_MB=1792); fi
    if [ "$i" -eq 0 ]; then
        # node-00's folders come from config.toml ([[watch]] files/ and bulk/).
        env MALLOC_MMAP_THRESHOLD_=65536 "${bw[@]}" \
            RUST_LOG=info,viaticum::daemon::backup=debug,viaticum::daemon::scheduler=debug,viaticum::daemon::restore=debug,viaticum::daemon::mem_budget=debug,viaticum::daemon::work_pipeline=debug \
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

# ── Step 0 (b): the log anchors must exist in the binary (v3.11a WARN-1) ─────────────────────
# A text that does not match shows here, not as "gate not exercised" ten minutes later. Format
# strings with {…} are checked in pieces (before and after the substitution).
if run_b; then
    ANCHORS=(
        "memory: block work budget set by " " (test only)"
        "mem_budget: granted" "mem_budget: released" "mem_budget: released (shrunk)"
        "mem_budget: written off a stuck holder"
        "pos: block deferred, memory budget busy" "pos: blocks marked, memory queue busy"
        "scheduler: marked blocks now wait for memory as a batch"
        "pos: overdue batch waiting for memory" "pos: overdue batch ended early"
        "half a period of work" "nine tenths of the period" "a restore does not fit beside it"
        "pos: a batch member panicked" "scheduler: PoS late preparation published"
        "scheduler: PoS preparation still running" "scheduler: PoS verdict"
        "work_pipeline: encoded raw symbols" "work_pipeline: chunk sent"
        "work_pipeline: yielding memory to overdue PoS" "work_pipeline: yielding memory to restore"
        "work_pipeline: symbols confirmed stored, placement Offered→Alive"
        "work_pipeline: iteration complete"
        "work_pipeline: paused while a restore job runs or a DR session leases memory"
        "restore: waiting for memory budget" "restore: regrant for plaintext"
        "processor: PosHashChallenge — responding with chain hash"
        "processor: sending RestoreResponse"
    )
    MISSING=""
    for a in "${ANCHORS[@]}"; do
        grep -aqF -- "$a" "$BINARY" || MISSING="$MISSING [$a]"
    done
    if [ -n "$MISSING" ]; then
        fail "anchor missing:$MISSING"
        echo "  (the log text the scenario reads is not in $BINARY: fix the scenario or the build)"
        exit 1
    fi
    echo "  anchors: all ${#ANCHORS[@]} log texts are in the binary"
fi

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
            # Pack size 32 MiB (B_eff = min(32, N/2)): grow.bin (64 MiB, importance 0) takes
            # the large-file path — the pack queue never selects importance-0 files
            # (select_backup_batch) — and its PoS rebuild fits the issue tick's time budget
            # at time_scale 20000 (a 200 MiB block is always cut there: pos-i7-d boundary).
            echo "source_block_size_mb = $PACK_MB_0"
            echo '[[watch]]'
            echo "path = \"$FILES\""
            # PHASE b: a *.bin file is class Unknown (importance 0.05, target reliability 0.708,
            # R = 4/3 over 4 holders). The spec's dials assume R = 4 (a holder carries about k
            # symbols; v3.3, v3.11 §1): the multiplier 20 lifts importance to 1.0 (target 0.99999).
            run_b && echo 'importance_multiplier = 20.0'
            echo '[[watch]]'
            echo "path = \"$BULK\""
            echo 'importance_multiplier = 0.0'   # importance 0 -> reliability target 0.5
        fi
    } > "$(node_dir "$i")/config.toml"
}

# ── PHASE b: helpers ─────────────────────────────────────────────
# (K-b6, spec v3.11 / v3.11a: private/beta-planning/tasks/r1_bigfile_refusal.md)

BUDGET_MB_0=1792               # node-00's block work budget via the test env (v3.11 §1)
NEAR_MB=240; RB_MB=200; B2_MB=200
SYMBOL_BYTES=65535             # T (SYMBOL_SIZE): E = k * T
STOPPED=0
PROC_BOUNDS=""                 # log line counts at which node-00 was restarted (a new process starts)

# stop_after STEP: true (and STOPPED=1) when STOP_AFTER names this step; the caller returns.
stop_after() {
    [ "${STOP_AFTER:-}" = "$1" ] || return 1
    STOPPED=1; note "STOP_AFTER=$1: the run ends after step $1 (shutdown and the whole-log checks still run)"
    return 0
}

# clog IDX [FROM [TO]]: node IDX's log lines FROM..TO (1-based, inclusive), ANSI colours stripped.
clog() {
    local f; f=$(node_log "$1")
    [ -f "$f" ] || return 0
    sed 's/\x1b\[[0-9;]*m//g' "$f" | sed -n "${2:-1},${3:-\$}p"
}

# ev IDX FROM PATTERN KEY...: "<t> <n> <KEY values...>" for the lines of node IDX's log (from line
# FROM on) that contain PATTERN (`events`: t = unix seconds of the log's own stamp).
ev() {
    local idx="$1" from="$2" pat="$3"; shift 3
    events <(clog "$idx" "$from" | grep -aF -- "$pat" || true) "$pat" "$@"
}

# ids of the node as the logs print them (first 16 hex of the device id).
dev_id() { api_get "$1" /api/status | jq -r '.device_id // empty' 2>/dev/null || true; }

# held_trace IDX FROM TO: replays the mem_budget grants/releases of the log lines FROM..TO.
# Prints "max=<peak sum of held bytes> end=<space-separated kind|block still held at TO>".
held_trace() {
    clog "$1" "$2" "$3" | awk '
        function kv(name,   s) {
            if (match($0, "[ ]" name "=[^ ]+")) { s = substr($0, RSTART + 2 + length(name), RLENGTH - 2 - length(name)); return s }
            return ""
        }
        /mem_budget: granted/ { k = kv("kind") "|" kv("block"); n = kv("bytes") + 0; cnt[k]++; sum += n; if (sum > max) max = sum }
        /mem_budget: released kind=/ || /mem_budget: released \(written off\)/ {
            k = kv("kind") "|" kv("block"); n = kv("bytes") + 0; cnt[k]--; sum -= n }
        /mem_budget: released \(shrunk\)/ { sum -= kv("bytes") + 0 }
        END { out = ""; for (k in cnt) if (cnt[k] > 0) out = out " " k; printf "max=%d end=%s\n", max, out }'
}

# foreign_granted_bytes IDX FROM TO BLOCK16: bytes of the grants in the log lines FROM..TO that are
# not the worker's grants for BLOCK16.
foreign_granted_bytes() {
    clog "$1" "$2" "$3" | grep -aF "mem_budget: granted" | awk -v nb="$4" '
        function kv(name) { if (match($0, "[ ]" name "=[^ ]+")) return substr($0, RSTART + 2 + length(name), RLENGTH - 2 - length(name)); return "" }
        !(kv("kind") == "worker" && kv("block") == nb) { s += kv("bytes") + 0 }
        END { printf "%d\n", s }'
}

# holder_answers HEX16 FROM TO: PoS answers for HEX16 by node-01/02 with a log time in [FROM, TO].
holder_answers() {
    local n=0 i c
    for i in 1 2; do
        c=$(events "$(node_log "$i")" "responding with chain hash" block_id \
            | awk -v a="$2" -v b="$3" -v h="$1" '$1 >= a && $1 <= b && $3 == h' | wc -l)
        n=$((n + c))
    done
    echo "$n"
}

fnum() { awk -v x="$1" 'BEGIN { printf "%.2f", x }'; }
fle()  { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a <= b) }'; }   # a <= b (floats)
now_f() { date +%s.%N | cut -c1-14; }

# Step-3 verdicts are notes in PHASE=all (the blocks of PHASE a dirty the window, v3.3 B3).
s3_pass()  { if [ "$PHASE" = all ]; then note "step 3 (PHASE=all, not judged) would PASS: $1"; else pass "$1"; fi; }
s3_rough() { if [ "$PHASE" = all ]; then note "step 3 (PHASE=all, not judged) would be ROUGH: $1"; else rough "$1"; fi; }
s3_fail()  { if [ "$PHASE" = all ]; then note "step 3 (PHASE=all, not judged) would FAIL: $1"; else fail "$1"; fi; }

# restart_node0: SIGTERM node-00 (exit 0), start a fresh process, wait for 4 authenticated peers.
# Sets RS_L0 = the log line count before the new process.
restart_node0() {
    kill -TERM "${DPID[0]}"
    if wait_pid_exit "${DPID[0]}" 60 && [ "$EXIT_RC" = 0 ]; then pass "node-00 stopped with exit 0 (fresh process for the measurement)"
    else fail "node-00 did not exit 0 within 60s (rc=${EXIT_RC:-running})"; fi
    unset "DPID[0]"
    RS_L0=$(log_line_count 0)
    PROC_BOUNDS="$PROC_BOUNDS $RS_L0"
    start_node 0
    wait_daemon 0 || { fail "node-00 did not come back after the restart"; exit 1; }
    wait_auth_peers 0 $((NUM_NODES-1)) 90 \
        || { fail "after the restart only $(status_num 0 peer_count_authenticated)/$((NUM_NODES-1)) authenticated peers after 90s"; exit 1; }
}

# s3_attempt NAME: step 3 on a fresh process with the file NAME. Sets S3_* (see the end).
s3_attempt() {
    local name="$1" path="$FILES/$1" Lreset Lend found="" end_t line ob fb
    restart_node0
    S3_L0=$RS_L0
    hwm_reset "${DPID[0]}" || { fail "setup: VmHWM reset failed"; exit 1; }
    S3_RSS0=$HWM_RSS0_KB
    Lreset=$(log_line_count 0)
    make_random "$path" $((NEAR_MB * MIB))
    end_t=$(( $(date +%s) + 420 ))
    while [ "$(date +%s)" -lt "$end_t" ]; do
        found=$(tail -n +$((Lreset + 1)) "$(node_log 0)" | grep -aF -m1 "work_pipeline: encoded raw symbols" || true)
        [ -n "$found" ] && break
        sleep 0.2
    done
    # The end of the window is THIS read, not the line ("released (shrunk)" is printed before it).
    S3_HWM=$(hwm_kb "${DPID[0]}"); S3_RSS=$(rss_kb "${DPID[0]}")
    Lend=$(log_line_count 0)
    if [ -z "$found" ]; then
        S3_OK=0; fail "step 3: no 'work_pipeline: encoded raw symbols' for $name within 420s"; return 0
    fi
    S3_OK=1
    line=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$found")
    S3_NB=$(grep -oE 'block_id=[0-9a-f]+' <<< "$line" | head -1 | cut -d= -f2)
    S3_N=$(log_field "$line" symbols)
    S3_NAME=$name
    # k from the version: size_bytes = k * T.
    local sz=0
    for _ in $(seq 1 60); do
        sz=$(api_get 0 "/api/versions?path=$(urlencode "$path")" | jq -r '.[-1].size_bytes // 0' 2>/dev/null || echo 0)
        [ "${sz:-0}" -gt 0 ] && break
        sleep 1
    done
    S3_K=$(( ${sz:-0} / SYMBOL_BYTES ))
    # t_encode: granted kind=worker block=NB -> encoded raw symbols block_id=NB.
    local tg te
    tg=$(ev 0 $((Lreset + 1)) "mem_budget: granted" kind block | awk -v nb="$S3_NB" '$3 == "worker" && $4 == nb { if (!_d++) print $1 }')
    te=$(ev 0 $((Lreset + 1)) "work_pipeline: encoded raw symbols" block_id | awk -v nb="$S3_NB" '$3 == nb { if (!_d++) print $1 }')
    S3_TENC=""
    [ -n "$tg" ] && [ -n "$te" ] && S3_TENC=$(awk -v a="$tg" -v b="$te" 'BEGIN { printf "%.1f", b - a }')
    # Cleanliness (a): every grant paired with a release at the reset; (b): foreign grants <= 16 MiB.
    local ht; ht=$(held_trace 0 $((S3_L0 + 1)) "$Lreset")
    S3_OPEN=$(sed 's/^max=[0-9]* end=//' <<< "$ht")
    fb=$(foreign_granted_bytes 0 $((Lreset + 1)) "$Lend" "$S3_NB")
    S3_FOREIGN=$fb
    S3_DIRTY=0
    if [ -n "${S3_OPEN// /}" ] || [ "$fb" -gt $((16 * MIB)) ]; then S3_DIRTY=1; fi
    S3_DIRTY_WHY="grants open at the reset: [${S3_OPEN# }]; foreign grants in the window: $((fb / MIB)) MiB (limit 16)"
    S3_L_END=$Lend
}

# step3: the peak of the worker on a fresh process (spec v3.11 §2 "3").
step3() {
    echo ""
    echo "=== Step 3: worker peak of a $NEAR_MB MiB block on a fresh process ==="
    [ "$PHASE" = all ] && note "PHASE=all: step 3 is measured and printed, never judged (the blocks of PHASE a dirty the window)"
    s3_attempt near.bin
    if [ "$S3_OK" -eq 1 ] && [ "$S3_DIRTY" -eq 1 ]; then
        info "step 3 is dirty ($S3_DIRTY_WHY): one repeat with a restart and near2.bin"
        s3_attempt near2.bin
    fi
    if [ "$S3_OK" -ne 1 ]; then return 0; fi
    NB=$S3_NB
    local p r model hi lo d
    d=$(( S3_HWM - S3_RSS0 ))
    r=$(awk -v n="$S3_N" -v k="$S3_K" 'BEGIN { if (k > 0) printf "%.3f", n / k; else print 0 }')
    p=$(awk -v d="$d" -v k="$S3_K" -v t="$SYMBOL_BYTES" 'BEGIN { if (k > 0) printf "%.3f", d * 1024 / (k * t); else print 0 }')
    model=$(awk -v r="$r" 'BEGIN { printf "%.3f", 3.047 + r }')
    info "step 3: file $S3_NAME NB=$NB k=$S3_K N=$S3_N R=$r t_encode=${S3_TENC:-?}s"
    info "step 3: VmHWM-RSS0 = $((d / 1024)) MiB, E = $((S3_K * SYMBOL_BYTES / MIB)) MiB, p = $p; model 3.047 + R = $model (bar 3.1 + R + 1.0 = $(awk -v r="$r" 'BEGIN { printf "%.2f", 4.1 + r }'), ROUGH below 3.1 + R - 2 = $(awk -v r="$r" 'BEGIN { printf "%.2f", 1.1 + r }'))"
    S3_P=$p; S3_R=$r
    if [ "$S3_K" -le 0 ] || [ -z "${S3_TENC:-}" ]; then
        fail "step 3: cannot read k ($S3_K) or t_encode (${S3_TENC:-none}) — the check would be blind"; return 0
    fi
    local fb_hex; fb_hex=$(file_block_hex 0 "$FILES/$S3_NAME")
    if [ -n "$fb_hex" ] && [ "${fb_hex:0:16}" != "$NB" ]; then
        info "step 3: the catalog block of $S3_NAME is ${fb_hex:0:16}.., the encoded block_id is $NB"
    fi
    if [ "$S3_DIRTY" -eq 1 ]; then
        s3_rough "step 3 contaminated by a concurrent preparation ($S3_DIRTY_WHY), twice"
    elif awk -v p="$p" -v r="$r" 'BEGIN { exit !(p > 3.1 + r + 1.0) }'; then
        s3_fail "step 3: p = $p > 3.1 + R + 1.0 = $(awk -v r="$r" 'BEGIN { printf "%.2f", 4.1 + r }') (R = $r): the model is wrong; constants stay, STOP"
        [ "$PHASE" = all ] || exit 1
    elif awk -v p="$p" -v r="$r" 'BEGIN { exit !(p < 3.1 + r - 2) }'; then
        s3_rough "step 3: p = $p < 3.1 + R - 2 = $(awk -v r="$r" 'BEGIN { printf "%.2f", 1.1 + r }') (R = $r): the model is much too high"
    else
        s3_pass "step 3: worker peak p = $p <= 3.1 + R + 1.0 (R = $r, model $model, t_encode ${S3_TENC}s)"
    fi
    sleep 30
    local rss30; rss30=$(rss_kb "${DPID[0]}")
    info "step 3: VmRSS - RSS0 after 30 s = $(( (${rss30:-0} - S3_RSS0) / 1024 )) MiB (retention)"
}

# nb_alive_on IDX...: NB is Alive (symbols confirmed stored) on every listed holder, per node-00's log.
nb_alive_on() {
    local i d
    for i in "$@"; do
        d=$(dev_id "$i"); [ -n "$d" ] || return 1
        [ -n "$(ev 0 "${NB_L0:-1}" "work_pipeline: symbols confirmed stored" block_id holder \
            | awk -v nb="$NB" -v d="$d" '$3 == nb && $4 == d { if (!_d++) print }')" ] || return 1
    done
}

# step2b: r.bin 200 MiB restorable, RB on node-01/02, NB Alive on node-01/02.
step2b() {
    echo ""
    echo "=== Step 2b: r.bin $RB_MB MiB (RB) restorable; NB Alive on node-01 and node-02 ==="
    RB_FILE="$FILES/r.bin"
    make_random "$RB_FILE" $((RB_MB * MIB))
    if wait_file_restorable 0 "$RB_FILE" 600; then pass "r.bin restorable per node-00"
    else fail "step 2b: r.bin not restorable per node-00 after 600s"; exit 1; fi
    RB_HASH=$(content_hash "$RB_FILE")
    RB=$(file_block_hex 0 "$RB_FILE"); RB16=${RB:0:16}
    local tgt on
    tgt=$(file_field 0 "$RB_FILE" '.effective_status.target // 0')
    on=$(( $(block_symbols_on 1 "$RB") + $(block_symbols_on 2 "$RB") ))
    if [ "${tgt:-0}" -gt 0 ] && [ "$on" -ge "$tgt" ]; then pass "RB ${RB16}.. has $on >= k_eff $tgt symbols on node-01 + node-02 (the two that stay alive)"
    else rough "3b (г) blind: RB ${RB16}.. has $on symbols on node-01 + node-02, k_eff ${tgt:-?}"; fi
    local ok=0
    for _ in $(seq 1 300); do nb_alive_on 1 2 && { ok=1; break; }; sleep 1; done
    if [ "$ok" -eq 1 ]; then pass "NB $NB: placements Offered→Alive on node-01 and node-02"
    else rough "3b (в) blind: NB $NB is not Alive on both node-01 and node-02 after 300s"; fi
    DP=$(file_block_hex 0 "$DOC"); DP16=${DP:0:16}
    [ -n "$DP16" ] && info "DP (doc.txt pack) = $DP16, NB = $NB, RB = $RB16" \
        || { fail "setup: doc.txt has no block (DP)"; exit 1; }
}

# restore_bg: the restore of r.bin in the background; sets RST_PID, RST_T0 (unix s), files in $T.
restore_bg() {
    RST_OUT="$T/restore.out"; RST_ERR="$T/restore.err"
    : > "$RST_OUT"; : > "$RST_ERR"
    RST_T0=$(now_f)
    timeout 300 "$BINARY" --data-dir "$(node_dir 0)" restore "$RB_FILE" --json > "$RST_OUT" 2> "$RST_ERR" &
    RST_PID=$!
}

# step3b: the adversarial budget run (spec v3.11 §2 "3b").
step3b() {
    echo ""
    echo "=== Step 3b: ADVERSARIAL budget under load: node-03/04 stopped, r.bin removed, big2.bin delivered, restore of r.bin ==="
    mkdir -p "$T/stash"
    mv "$RB_FILE" "$T/stash/"
    hwm_reset "${DPID[0]}" || { fail "setup: VmHWM reset failed"; exit 1; }
    L3B=$(log_line_count 0); T3B=$(date +%s)
    B2_FILE="$FILES/big2.bin"
    make_random "$B2_FILE" $((B2_MB * MIB))
    B2=""; RST_PID=""; T_CONT=""; RST_DONE=0
    # v3.12c: node-03/04 are stopped only after the worker's first grant for B2 (the step checks the
    # memory budget, not the pick order: a small block with dead holders can outrank B2, repair-i5).
    local gend=$(( $(date +%s) + 120 ))
    while [ "$(date +%s)" -lt "$gend" ]; do
        B2=$(ev 0 "$((L3B + 1))" "mem_budget: granted" kind block bytes | awk -v nb="$NB" -v rb="$RB16" '$3 == "worker" && $4 != nb && $4 != rb && $5 + 0 >= 1000 * 1048576 { if (!_d++) print $4 }')
        [ -n "$B2" ] && break
        sleep 0.5
    done
    # The offer order is random: if a holder to be stopped is first, stopping right at the grant makes
    # the first offer time out and the worker yields to PoS and never returns to B2 in the window
    # (repair-i5 hole, v3.12c). So the stop waits for the first chunk of B2 that reached a holder.
    if [ -n "$B2" ]; then
        local cend=$(( $(date +%s) + 90 ))
        while [ "$(date +%s)" -lt "$cend" ]; do
            clog 0 "$L3B" | grep -aF "work_pipeline: chunk sent" | grep -aqF "block_id=$B2" && break
            sleep 0.5
        done
    fi
    kill -STOP "${DPID[3]}" "${DPID[4]}"
    if [ -n "$B2" ]; then info "step 3b: worker granted for B2 = $B2, first chunk delivered; at +$(( $(date +%s) - T3B )) s node-03/04 stopped"
    else
        rough "3b: B2 never picked within 120 s of big2.bin (node-03/04 stopped anyway); picks in the window: $(clog 0 "$((L3B + 1))" | grep -aF 'picked block for work' | grep -ao 'block_id=[0-9a-f]*' | sort | uniq -c | tr '\n' ' ')"
    fi
    local now line tend restore_deadline=0
    while :; do
        now=$(date +%s)
        if [ -z "$B2" ]; then
            B2=$(ev 0 "$L3B" "mem_budget: granted" kind block bytes | awk -v nb="$NB" -v rb="$RB16" '$3 == "worker" && $4 != nb && $4 != rb && $5 + 0 >= 1000 * 1048576 { if (!_d++) print $4 }')
        fi
        if [ -n "$B2" ] && [ -z "$RST_PID" ]; then
            line=$(clog 0 "$L3B" | grep -aF "work_pipeline: chunk sent" | grep -aF "block_id=$B2" | head -1 || true)
            if [ -n "$line" ]; then
                info "step 3b: B2 = $B2, first chunk sent at +$((now - T3B)) s: restore of r.bin starts"
                restore_bg; restore_deadline=$((now + 300))
            fi
        fi
        if [ -z "$T_CONT" ] && [ "$now" -ge $((T3B + 240)) ]; then
            kill -CONT "${DPID[3]}" "${DPID[4]}" 2>/dev/null || true
            T_CONT=$now
            if [ -z "$RST_PID" ]; then
                fail "step 3b: no 'chunk sent' for B2 (${B2:-unknown}) in 240 s: the restore starts late, the window did not hold"
                restore_bg; restore_deadline=$((now + 300))
            fi
        fi
        if [ -n "$RST_PID" ] && [ "$RST_DONE" -eq 0 ] && ! kill -0 "$RST_PID" 2>/dev/null; then
            RST_DONE=1; wait "$RST_PID" 2>/dev/null && RST_RC=0 || RST_RC=$?
            RST_TEND=$(now_f)
        fi
        # (г): the restore is awaited with its own deadline (300 s from the command), not at the window end.
        if [ -n "$T_CONT" ] && { [ "$RST_DONE" -eq 1 ] || [ "$now" -ge "$restore_deadline" ]; }; then break; fi
        sleep 1
    done
    if [ "$RST_DONE" -eq 0 ]; then
        RST_TEND=$(now_f); kill "$RST_PID" 2>/dev/null || true; wait "$RST_PID" 2>/dev/null || true; RST_RC=124
    fi
    S3B_HWMD=$(hwm_delta_kb "${DPID[0]}")
    L3B_END=$(log_line_count 0); T3B_END=$(now_f)
    info "step 3b: window and restore over: restore rc=$RST_RC after $(awk -v a="$RST_T0" -v b="$RST_TEND" 'BEGIN { printf "%.0f", b - a }') s; node-03/04 resumed at +$((T_CONT - T3B)) s"
    step3b_judge
    b2_settle
}

# b2_settle: by the end of 3b (after the resume and the restore) B2 is Alive on node-01 and node-02
# (symbols confirmed stored), else FAIL "B2 never completes under overdue PoS" (v3.12 §4, backup-i24-a).
# The poll runs <= 180 s from the later of the resume and the end of the restore job (the worker is
# paused while the job runs, v3.12a: the 180 s count from when it may work again).
b2_settle() {
    local d1 d2 t0 end_t ok1="" ok2=""
    d1=$(dev_id 1); d2=$(dev_id 2)
    t0=$T_CONT; [ "$(date +%s)" -gt "$t0" ] && t0=$(date +%s)
    end_t=$(( t0 + 180 ))
    while :; do
        ok1=$(ev 0 "$((L3B + 1))" "work_pipeline: symbols confirmed stored" block_id holder | awk -v b="$B2" -v d="$d1" '$3 == b && $4 == d { if (!_d++) print }')
        ok2=$(ev 0 "$((L3B + 1))" "work_pipeline: symbols confirmed stored" block_id holder | awk -v b="$B2" -v d="$d2" '$3 == b && $4 == d { if (!_d++) print }')
        [ -n "$ok1" ] && [ -n "$ok2" ] && break
        [ "$(date +%s)" -ge "$end_t" ] && break
        sleep 3
    done
    if [ -n "$ok1" ] && [ -n "$ok2" ]; then pass "3b: B2 Alive on node-01 and node-02 by the end of the step"
    else fail "3b: B2 never completes under overdue PoS: Alive on node-01: ${ok1:+yes}${ok1:-NO}, node-02: ${ok2:+yes}${ok2:-NO} (180 s after the resume and the end of the restore)"; fi
}

step3b_judge() {
    local F=$((L3B + 1)) NBL=$NB
    # ---- (a) the gate is entered
    local def defnb inrange marked batched
    def=$(ev 0 "$F" "pos: block deferred, memory budget busy" block need_mib queued)
    defnb=$(awk -v nb="$NB" '$3 == nb' <<< "$def")
    inrange=$(awk -v nb="$NB" '$3 == nb && $5 == 0 && $4 >= 743 && $4 <= 745' <<< "$def")
    marked=$(ev 0 "$F" "pos: blocks marked, memory queue busy" marked queued)
    batched=$(ev 0 "$F" "scheduler: marked blocks now wait for memory as a batch" batched)
    info "3b (a): deferred lines for NB: $(count_lines "$defnb") (queued=0 and need_mib in [743,745]: $(count_lines "$inrange")); 'blocks marked': $(count_lines "$marked"); 'batch': $(count_lines "$batched")"
    if [ -n "$(awk '$5 == 0' <<< "$defnb")" ] && [ -z "$inrange" ]; then
        fail "3b (a): NB deferred at queued=0 with need_mib outside [743, 745]: $(awk '$5 == 0 { print $4 }' <<< "$defnb" | sort -u | tr '\n' ' ')"
    elif [ -n "$inrange" ]; then
        pass "3b (a): pos: block deferred, memory budget busy block=NB queued=0 need_mib=$(head -1 <<< "$inrange" | awk '{ print $4 }') (in [743, 745])"
    elif [ -n "$marked" ] && [ -n "$batched" ]; then
        pass "3b (a): blocks marked at a busy queue, then 'marked blocks now wait for memory as a batch'"
    else
        local ht mx; ht=$(held_trace 0 "$((L3B + 1))" "$L3B_END"); mx=$(sed -E 's/^max=([0-9]+).*/\1/' <<< "$ht")
        if [ "$mx" -gt $((BUDGET_MB_0 * MIB)) ]; then
            fail "3b (a): budget does not hold: max sum of held = $((mx / MIB)) MiB > $BUDGET_MB_0 MiB, and NB was neither deferred nor marked"
        else
            rough "3b (a): dials do not exercise the gate (R = ${S3_R:-?}): no deferral / mark of NB; max held $((mx / MIB)) MiB (no big3.bin repeat made)"
        fi
    fi
    # ---- (b) bytes, not a mutex
    local tg tend2 g w
    g=$(ev 0 "$F" "mem_budget: granted" kind block | awk -v b="$B2" '$3 == "worker" && $4 == b { if (!_d++) print $1 }')
    tend2=$( { ev 0 "$F" "mem_budget: released kind=" kind block | awk -v b="$B2" -v g="${g:-0}" '$3 == "worker" && $4 == b && $1 >= g { print $1 }'
               ev 0 "$F" "work_pipeline: yielding memory to" block | awk -v b="$B2" -v g="${g:-0}" '$3 == b && $1 >= g { print $1 }'; } | sort -n | head -1)
    if [ -z "$g" ]; then
        rough "3b (b) not exercised: no 'granted kind=worker block=B2' (B2 = ${B2:-unknown})"
    else
        [ -n "$tend2" ] || tend2=$(awk -v a="$T3B_END" 'BEGIN { print a }')
        local ans bad
        ans=$(holder_answers "$DP16" "$g" "$tend2")
        bad=$(awk -v dp="$DP16" -v a="$g" -v b="$tend2" '$3 == dp && $5 == 0 && $1 >= a && $1 <= b' <<< "$def")
        info "3b (b): B2 holds the budget from $(awk -v a="$T3B" -v b="$g" 'BEGIN { printf "%.0f", b - a }') s to +$(awk -v a="$T3B" -v b="$tend2" 'BEGIN { printf "%.0f", b - a }') s; PoS answers for DP on node-01/02 in it: $ans; DP deferred at queued=0 in it: $(count_lines "$bad")"
        if [ -n "$bad" ]; then fail "3b (b): pos: block deferred, memory budget busy block=DP queued=0 inside the B2 holding window (the pack was refused at an empty queue: a mutex, not bytes)"
        elif [ "$ans" -ge 1 ]; then pass "3b (b): $ans PoS answer(s) for the small pack DP while B2 held the budget"
        else rough "3b (b) not exercised: no due DP at an empty queue inside the B2 holding window"; fi
    fi
    # ---- (c) the overdue NB is served after the worker yields
    local A B C D E tA tB tC tD tEB2 lim
    A=$(ev 0 "$F" "pos: overdue batch waiting for memory" blocks need_mib | awk -v nb="$NB" 'index($3, nb) { if (!_d++) print }')
    tA=$(awk '{ print $1 }' <<< "$A")
    if [ -n "$tA" ]; then
        tB=$(ev 0 "$F" "work_pipeline: yielding memory to overdue PoS" block | awk -v b="$B2" -v a="$tA" '$3 == b && $1 >= a { if (!_d++) print $1 }')
        [ -n "$tB" ] && tC=$(ev 0 "$F" "mem_budget: granted" kind waited_ms | awk -v a="$tB" '$3 == "pos" && $1 >= a { if (!_d++) print $1 }')
        [ -n "${tC:-}" ] && tD=$(ev 0 "$F" "scheduler: PoS late preparation published" block_id | awk -v nb="$NB" -v a="$tC" '$3 == nb && $1 >= a { if (!_d++) print $1 }')
    fi
    if [ -n "${tD:-}" ]; then
        E=$(holder_answers "$NB" "$tD" 9999999999)
        info "3b (c): batch waits at +$(awk -v a="$T3B" -v b="$tA" 'BEGIN { printf "%.1f", b - a }') s ($(awk '{ print "need_mib=" $4 }' <<< "$A")), yield at +$(awk -v a="$T3B" -v b="$tB" 'BEGIN { printf "%.1f", b - a }') s, pos grant +$(awk -v a="$T3B" -v b="$tC" 'BEGIN { printf "%.1f", b - a }') s, published +$(awk -v a="$T3B" -v b="$tD" 'BEGIN { printf "%.1f", b - a }') s; NB answers after: $E"
        tEB2=$(ev 0 "$F" "work_pipeline: encoded raw symbols" block_id | awk -v b="$B2" '$3 == b { if (!_d++) print $1 }')
        if [ -n "$tEB2" ] && fle "$tEB2" "$tA"; then lim=65
        elif [ -n "$tEB2" ]; then lim=$(awk -v e="$tEB2" -v a="$tA" 'BEGIN { printf "%.1f", e - a + 65 }')
        else lim=65; fi
        local dl; dl=$(awk -v a="$tA" -v b="$tB" 'BEGIN { printf "%.1f", b - a }')
        if [ "$E" -lt 1 ]; then fail "3b (c): NB was published (+$(awk -v a="$T3B" -v b="$tD" 'BEGIN { printf "%.0f", b - a }') s) but no holder answered PoS for NB after it"
        elif fle "$dl" "$lim"; then pass "3b (c): overdue NB served after the yield: batch wait -> yielding to overdue PoS B2 in ${dl} s (limit ${lim} s), grant kind=pos, published, $E answer(s)"
        else fail "3b (c): batch wait -> yielding took ${dl} s > ${lim} s (batch line at $tA, encoded B2 at ${tEB2:-none}, yield at $tB)"; fi
    else
        fail "3b (c): not all four lines in order: batch wait for NB ${tA:+yes}${tA:-NO}; yield to overdue PoS for B2 ${tB:+yes}${tB:-NO}; grant kind=pos ${tC:+yes}${tC:-NO}; late preparation published for NB ${tD:+yes}${tD:-NO}"
    fi
    # ---- (d) the restore waits for memory and gets through
    local W G1 tW tG shr reg rel tres sha_ok="" outcome sp f got
    tW=$(ev 0 "$F" "restore: waiting for memory budget" block tier need_mib queued_ahead | awk -v b="$RB16" '$3 == b { if (!_d++) print $1 " " $5 " " $6 " " $4 }')
    G1=$(ev 0 "$F" "mem_budget: granted" kind block | awk -v b="$RB16" '$3 == "restore" && $4 == b { print $1 }')
    tG=$(awk 'NR == 1 { print }' <<< "$G1")
    shr=$(ev 0 "$F" "mem_budget: released (shrunk)" kind block | awk -v b="$RB16" '$3 == "restore" && $4 == b { if (!_d++) print $1 }')
    reg=$(ev 0 "$F" "restore: regrant for plaintext" block | awk -v b="$RB16" '$3 == b { if (!_d++) print $1 }')
    rel=$(ev 0 "$F" "mem_budget: released kind=" kind block | awk -v b="$RB16" '$3 == "restore" && $4 == b { t = $1 } END { print t }')
    tres=$(ev 0 "$F" "restored path=" path | awk '$3 ~ /r\.bin$/ { if (!_d++) print $1 }')
    info "3b (d): waiting line: ${tW:-none} (t need_mib queued_ahead tier); granted restore RB: $(count_lines "$G1")x; shrunk: ${shr:-none}; regrant: ${reg:-none}; last release: ${rel:-none}; restored line: ${tres:-none}"
    # v3.12a/b + Q-V9 (a): a running restore job pauses the backup (the worker yields at a portion
    # boundary and the gate holds it), and the restore asks for memory only after it fetched the
    # symbols. So the INFO 'waiting' line is not guaranteed any more: without it the worker must have
    # given way to the restore before the grant (checked below), otherwise FAIL.
    # The worker gives way in one of three logged forms (portion boundary, gate after the permit
    # (K-b2a^5 step 5b), pause line); all are grep'd by prefix "restore gate is up" / "yielding memory to restore".
    local gave_way
    gave_way=$({ ev 0 "$F" "work_pipeline: yielding memory to restore" block | awk -v b="$B2" '$3 == b { print $1 }'; \
                 ev 0 "$F" "restore gate is up after the permit was granted" block | awk -v b="$B2" '$3 == b { print $1 }'; } | head -1)
    if [ -z "$tW" ] && [ -z "$gave_way" ]; then
        fail "3b (d): no INFO 'restore: waiting for memory budget ... block=RB' and no 'yielding memory to restore' by the worker (the restore neither waited nor was given the budget)"
    else
        [ -n "$tW" ] || note "3b (d): no 'waiting for memory budget' line: the worker paused the backup for the restore first (Q-V9 (a)), the grant came without a wait"
        local tw_t; tw_t=${tW%% *}
        [ -n "$tG" ] || fail "3b (d): no DEBUG 'mem_budget: granted kind=restore block=RB'"
        if [ -n "$tG" ]; then
            local ok=1
            if [ -n "$shr" ] || { [ -n "$reg" ] && [ "$(count_lines "$G1")" -ge 2 ]; }; then :; else
                ok=0; fail "3b (d): after the grant neither 'released (shrunk) kind=restore' nor a regrant with a second grant for RB"; fi
            [ -n "$rel" ] && [ -n "$tres" ] && fle "$rel" "$tres" && [ "$ok" -eq 1 ] \
                && pass "3b (d): released kind=restore block=RB ($rel) is not later than 'restored' ($tres)" \
                || { [ "$ok" -eq 1 ] && fail "3b (d): released kind=restore (${rel:-none}) not earlier than 'restored' (${tres:-none})"; }
            # yield of the worker to the restore: before the grant
            local y1 y2
            y1=$(ev 0 "$F" "work_pipeline: yielding memory to restore" block | awk -v b="$B2" -v g="$tG" '$3 == b && $1 <= g { if (!_d++) print $1 }')
            y2=$(ev 0 "$F" "mem_budget: released kind=" kind block | awk -v b="$B2" -v g="$tG" '$3 == "worker" && $4 == b && $1 <= g { if (!_d++) print $1 }')
            if [ -n "$y1" ] || [ -n "$y2" ]; then pass "3b (d): the worker gave way to the restore (${y1:+yielding memory to restore at $y1}${y1:+ }${y2:+released kind=worker block=B2 at $y2}) before the restore's grant"
            else fail "3b (d): no 'yielding memory to restore' / 'released kind=worker block=B2' before 'granted kind=restore block=RB'"; fi
            local wt; wt=$(awk -v a="$tw_t" -v b="$tG" 'BEGIN { printf "%.1f", b - a }')
            local lim2; lim2=$(awk -v t="${S3_TENC:-0}" 'BEGIN { printf "%.1f", t + 90 }')
            if [ -z "$tW" ]; then :
            elif fle "$wt" "$lim2"; then pass "3b (d): the restore waited ${wt} s for memory (limit t_encode ${S3_TENC}s + 90 = ${lim2} s)"
            else rough "3b (d): restore waited past one holder attempt: ${wt} s > t_encode + 90 = ${lim2} s"; fi
        fi
    fi
    # content: the finished job, hash
    outcome=$(tail -n 1 "$RST_OUT" 2>/dev/null | jq -r '.outcome // "none"' 2>/dev/null || echo none)
    if [ "${RST_RC:-1}" -eq 0 ] && [ "$outcome" = complete ]; then
        sp=$(tail -n 1 "$RST_OUT" | jq -r '.staging_path')
        f="$sp/${RB_FILE#/}"
        if [ -f "$f" ]; then
            got=$(content_hash "$f")
            [ "$got" = "$RB_HASH" ] && pass "3b (d): restored r.bin sha256 matches the original ($(file_size "$f") bytes)" \
                || fail "3b (d): sha256 MISMATCH: want $RB_HASH got $got at $f"
        else fail "3b (d): the job claims complete, but $f does not exist"; fi
    else
        fail "3b (d): the restore did not complete: rc=${RST_RC:-?} outcome=$outcome (124 = still running 300 s after the command); stderr: $(head -c 300 "$RST_ERR" 2>/dev/null); last: $(tail -n 1 "$RST_OUT" 2>/dev/null | head -c 400)"
    fi
    local rr; rr=$(restore_responses_for "$RB16" 1 2)
    [ "$rr" -ge 1 ] && pass "3b (d): node-01/02 logged $rr 'sending RestoreResponse' for RB (the network was used)" \
        || fail "3b (d): no 'sending RestoreResponse' for RB at node-01/02"
    # ---- v3.12 §4: progress between the yields of the worker for B2
    local ys cs ws nys gap_bad
    ys=$(ev 0 "$F" "work_pipeline: yielding memory to" block | awk -v b="$B2" '$3 == b { print $1 }' | sort -n)
    cs=$(ev 0 "$F" "work_pipeline: chunk sent" block_id reply | awk -v b="$B2" '$3 == b && $4 == "stored" { print $1 }')
    ws=$( { ev 0 "$F" "rejected offer for block" ; ev 0 "$F" "deliver_to_holder_worker failed"; } | awk '{ print $1 }')
    nys=$(count_lines "$ys")
    gap_bad=$( { echo "Y $ys"; echo "P $cs $ws"; } | awk '
        $1 == "Y" { for (i = 2; i <= NF; i++) y[++ny] = $i }
        $1 == "P" { for (i = 2; i <= NF; i++) p[++np] = $i }
        END { for (i = 1; i < ny; i++) { ok = 0; for (j = 1; j <= np; j++) if (p[j] > y[i] && p[j] <= y[i + 1]) ok = 1; if (!ok) printf "%.1f-%.1f ", y[i], y[i + 1] } }')
    if [ -n "$gap_bad" ]; then fail "3b: no stored chunk (new ESIs) and no failed-offer WARN between two yields of the worker for B2 (backup-i24-a): $gap_bad"
    else pass "3b: $nys yield(s) for B2; every gap between two yields has a stored chunk with new ESIs or a failed-offer WARN"; fi
    local paused; paused=$(clog 0 "$F" | grep -aF "work_pipeline: paused while a restore job runs or a DR session leases memory" | head -3 | cut -c1-30 | tr '\n' ' ')
    note "3b: INFO paused-while-restore line (once per pause, Q-V9 (a)): ${paused:-none}; worker grants during the restore job: $(ev 0 "$F" "mem_budget: granted" kind block | awk -v a="$RST_T0" -v b="$RST_TEND" '$3 == "worker" && $1 >= a && $1 <= b' | wc -l)"
    # ---- memory
    local bar_kib=$((2656 * 1024))
    if [ -z "$S3B_HWMD" ]; then fail "3b: cannot read VmHWM of node-00"
    elif [ "$S3B_HWMD" -le "$bar_kib" ]; then pass "3b: node-00 ΔVmHWM = $((S3B_HWMD / 1024)) MiB <= 2656 MiB"
    else fail "3b: node-00 ΔVmHWM = $((S3B_HWMD / 1024)) MiB > 2656 MiB"; fi
}

# step3c: a holder answers PoS on a big share (spec v3.11 §2 "3c").
step3c() {
    echo ""
    echo "=== Step 3c: a holder answers PoS on a $NEAR_MB MiB share (pos-i14) ==="
    local h attempt D hwm_end settled=0 end_t d
    # B2 delivery must have settled on h: all its placements Alive, or an iteration without a yield.
    end_t=$(( T_CONT + 180 ))
    for attempt in 1 2; do
        h=$attempt; D=$(dev_id "$h")
        [ -n "$D" ] || { rough "3c: no device id for node-0$h"; continue; }
        if [ "$attempt" -eq 1 ]; then
            while :; do
                if [ -n "$(ev 0 "$((L3B + 1))" "work_pipeline: symbols confirmed stored" block_id holder | awk -v b="$B2" -v d="$D" '$3 == b && $4 == d { if (!_d++) print }')" ] \
                    || [ -n "$(ev 0 "$((L3B + 1))" "work_pipeline: iteration complete" block_id yielded | awk -v b="$B2" '$3 == b && $4 == "false" { if (!_d++) print }')" ]; then
                    settled=1; break; fi
                [ "$(date +%s)" -ge "$end_t" ] && break
                sleep 2
            done
            [ "$settled" -eq 1 ] || rough "3c: B2 delivery did not settle on node-0$h within 180 s of the resume"
        fi
        nb_alive_on "$h" || { note "3c: NB is not Alive on node-0$h"; continue; }
        hwm_reset "${DPID[$h]}" || { fail "setup: VmHWM reset of node-0$h failed"; exit 1; }
        local rss0=$HWM_RSS0_KB Lh L0 t0 found="" tR dh vt
        Lh=$(log_line_count "$h"); L0=$(log_line_count 0); t0=$(now_f)
        end_t=$(( $(date +%s) + 120 ))
        while [ "$(date +%s)" -lt "$end_t" ]; do
            found=$(tail -n +$((Lh + 1)) "$(node_log "$h")" | sed 's/\x1b\[[0-9;]*m//g' | grep -aF "responding with chain hash" | grep -aF -m1 "block_id=$NB" || true)
            [ -n "$found" ] && break
            sleep 0.2
        done
        hwm_end=$(hwm_kb "${DPID[$h]}")
        if [ -z "$found" ]; then fail "3c: node-0$h did not answer a PoS challenge for NB within 120 s"; continue; fi
        dh=$(( hwm_end - rss0 ))
        tR=$(ev "$h" "$((Lh + 1))" "responding with chain hash" block_id | awk -v nb="$NB" '$3 == nb { if (!_d++) print $1 }')
        # clean: the owner sent no chunk to h in [t0, the answer] (T8)
        local ch
        ch=$(ev 0 "$((L0 + 1))" "work_pipeline: chunk sent" holder block_id | awk -v d="$D" -v a="$t0" -v b="${tR:-$t0}" '$3 == d && $1 >= a && $1 <= b' | wc -l)
        # the owner's verdict
        vt=""
        for _ in $(seq 1 60); do
            vt=$(ev 0 "$((L0 + 1))" "scheduler: PoS verdict" block_id holder outcome | awk -v nb="$NB" -v d="$D" '$3 == nb && $4 == d && $5 == "pass" { if (!_d++) print $1 }')
            [ -n "$vt" ] && break
            sleep 1
        done
        info "3c: holder node-0$h ($D): ΔVmHWM = $((dh / 1024)) MiB (bar 64), owner chunks to h in the window: $ch, verdict pass: ${vt:-none}"
        if [ "$ch" -gt 0 ]; then
            if [ "$attempt" -lt 2 ]; then info "3c: contaminated by a transfer (attempt $attempt): the other holder"; continue; fi
            rough "3c contaminated by a transfer (2 attempts: $ch chunk(s) to node-0$h in the window; ΔVmHWM $((dh / 1024)) MiB)"
            return 0
        fi
        if [ "$dh" -lt $((64 * 1024)) ]; then pass "3c: node-0$h answered PoS on a ${NEAR_MB} MiB share with ΔVmHWM = $((dh / 1024)) MiB < 64 MiB"
        else fail "3c: node-0$h ΔVmHWM = $((dh / 1024)) MiB >= 64 MiB (the share was read into RAM)"; fi
        [ -n "$vt" ] && pass "3c: owner logged scheduler: PoS verdict block_id=NB holder=node-0$h outcome=pass" \
            || fail "3c: no 'scheduler: PoS verdict ... block_id=NB holder=$D outcome=pass' within 60 s of the answer"
        return 0
    done
    rough "3c contaminated / blind: no clean attempt"
}

# whole-log lines of node-00 (pre-registered, PHASE b), called before the shutdown.
final_lines_check() {
    local n
    n=$(count_lines "$(clog 0 | grep -aF 'mem_budget: written off a stuck holder' || true)")
    [ "$n" -eq 0 ] && pass "no 'mem_budget: written off a stuck holder' on node-00" || fail "$n 'mem_budget: written off a stuck holder' line(s) on node-00 (nothing hangs in this scenario)"
    n=$(count_lines "$(clog 0 | grep -aF 'pos: overdue batch ended early' | grep -aF 'reason=written off' || true)")
    [ "$n" -eq 0 ] && pass "no 'overdue batch ended early ... reason=written off'" || fail "$n 'pos: overdue batch ended early ... reason=written off' line(s)"
    n=$(count_lines "$(clog 0 | grep -aF 'pos: a batch member panicked' || true)")
    [ "$n" -eq 0 ] && pass "no 'pos: a batch member panicked'" || fail "$n 'pos: a batch member panicked' line(s)"
    # v3.12 §4 (M85 guard): no (holder, ESI) pair twice in `chunk sent ... reply=stored` within one process.
    local dup
    dup=$(awk -v bounds="$PROC_BOUNDS" -v logf="$(node_log 0)" '
        function kv(name) { if (match($0, "[ ]" name "=[^ ]+")) return substr($0, RSTART + 2 + length(name), RLENGTH - 2 - length(name)); return "" }
        BEGIN { n = split(bounds, B, " "); for (i = 1; i <= n; i++) cut[B[i]] = 1 }
        { gsub(/\033\[[0-9;]*m/, "") }
        (FNR - 1) in cut { delete seen }
        /work_pipeline: chunk sent/ && /reply=stored/ {
            h = kv("holder"); b = kv("block_id"); m = split(kv("esis"), R, ",")
            for (i = 1; i <= m; i++) {
                if (split(R[i], ab, "\\.\\.") != 2) continue
                for (e = ab[1] + 0; e <= ab[2] + 0; e++) {
                    k = h "|" b "|" e
                    if (k in seen) { dups++; if (dups <= 3) ex = ex " " h "/" b "/" e "@" FNR }
                    seen[k] = 1
                }
            }
        }
        END { printf "%d%s\n", dups, ex }' "$(node_log 0)")
    if [ "${dup%% *}" = "0" ]; then pass "no (holder, ESI) pair stored twice in one process (no delivery restart)"
    else fail "delivery restarts: (holder, ESI) pair(s) sent and stored twice in one process: ${dup}"; fi
    # 'still running': NB is ROUGH only past 2 x t_encode(NB); another block is ROUGH always.
    local sr; sr=$(ev 0 1 "scheduler: PoS preparation still running" block age_s)
    if [ -z "$sr" ]; then info "no 'PoS preparation still running' on node-00"
    else
        local lim; lim=$(awk -v t="${S3_TENC:-0}" 'BEGIN { printf "%.1f", 2 * t }')
        local bad_nb other
        bad_nb=$(awk -v nb="${NB:-none}" -v l="$lim" '$3 == nb && $4 + 0 > l + 0' <<< "$sr")
        other=$(awk -v nb="${NB:-none}" '$3 != nb' <<< "$sr")
        info "'PoS preparation still running': $(count_lines "$sr") line(s): $(awk '{ printf "%s age_s=%s; ", $3, $4 }' <<< "$sr")"
        if [ -n "$bad_nb" ] || [ -n "$other" ]; then rough "stuck warn on a loaded rig: PoS preparation still running (NB limit age > 2 x t_encode = ${lim} s): $(awk '{ printf "%s age_s=%s; ", $3, $4 }' <<< "${bad_nb}${bad_nb:+$'\n'}${other}")"
        else note "'still running' for NB only, age <= 2 x t_encode (${lim} s): not a finding (v3.11a WARN-2 a)"; fi
    fi
}

# phase_b: steps 2b-before, 3, 2b, 3b, 3c.
phase_b() {
    DOC="${DOC:-$FILES/doc.txt}"
    if ! run_a; then
        echo ""
        echo "=== Step 2b (before): doc.txt 10 KB restorable (DP) ==="
        make_random "$DOC" 10240
        wait_file_restorable 0 "$DOC" 300 || { fail "step 2b: doc.txt not restorable per node-00 after 300s"; exit 1; }
        wait_on_holders "$DOC" 120 && pass "doc.txt restorable, holders hold $OH_ON >= k_eff $OH_TARGET" \
            || { fail "step 2b: doc.txt: holders hold $OH_ON of ${OH_TARGET:-?}"; exit 1; }
    fi
    NB_L0=1
    step3
    [ "${S3_OK:-0}" -eq 1 ] || { fail "step 3 gave no measurement: the later steps need NB"; return 0; }
    stop_after 3 && return 0
    step2b
    stop_after 2b && return 0
    step3b
    stop_after 3b && return 0
    step3c
    stop_after 3c && return 0
    return 0   # the last stop_after returns 1 when no STOP_AFTER is set: under set -e that killed the run before step 9
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
if run_b; then
    # 0b: the budget of node-00 is the test one; node-01's follows the formula M*14/32, in whole MiB.
    WANT_B0=$((BUDGET_MB_0 * MIB))
    WANT_B1=$(( (AUTO_M_BYTES * 14 / 32) / MIB * MIB ))
    OK_0B=1
    status_is 0 block_work_budget_bytes "$WANT_B0" \
        || { fail "0b: node-00 block_work_budget_bytes == $(status_num 0 block_work_budget_bytes), want $WANT_B0"; OK_0B=0; }
    grep -aF "memory: block work budget set by VIATICUM_TEST_BLOCK_WORK_BUDGET_MB (test only)" "$(node_log 0)" > /dev/null \
        || { fail "0b: no WARN 'memory: block work budget set by VIATICUM_TEST_BLOCK_WORK_BUDGET_MB (test only)' in node-00's log"; OK_0B=0; }
    status_is 1 block_work_budget_bytes "$WANT_B1" \
        || { fail "0b: node-01 block_work_budget_bytes == $(status_num 1 block_work_budget_bytes), want $WANT_B1 (floor(floor(M*14/32)/MiB)*MiB, M=$AUTO_M_BYTES)"; OK_0B=0; }
    [ "$OK_0B" -eq 1 ] && pass "0b: node-00 budget == $WANT_B0 (+ WARN '(test only)'), node-01 budget == $WANT_B1 (M*14/32 in MiB)"
    stop_after 0b || true
fi
# The peak-RSS reset must work, otherwise every ΔVmHWM below is meaningless.
if hwm_reset "${DPID[0]}"; then
    HD=$(hwm_delta_kb "${DPID[0]}")
    if [ -n "$HD" ] && [ "$HD" -lt 16384 ]; then pass "VmHWM reset works (Δ = ${HD} KiB right after the reset)"
    else fail "setup: VmHWM of node-00 did not drop to VmRSS after clear_refs (Δ = ${HD:-?} KiB): the ΔVmHWM checks would be blind"; exit 1; fi
else
    fail "setup: cannot reset VmHWM of node-00 (echo 5 > /proc/PID/clear_refs)"; exit 1
fi

if run_a && [ "$STOPPED" -eq 0 ]; then

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
    # Folder rollups are recomputed every 5 min; ask for a recompute first.
    api_post 0 /api/watches/refresh '{}' > /dev/null
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
echo "=== Step 2 (a): doc.txt 10 KB, ok.bin 100 MiB, bulk/grow.bin 64 MiB (backup-i1) ==="
DOC="$FILES/doc.txt"; OKB="$FILES/ok.bin"; GROW="$BULK/grow.bin"
make_random "$DOC" 10240
make_random "$OKB" $((100 * MIB))
make_random "$GROW" $((64 * MIB))
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

# ── STEPS 2b, 3, 3b, 3c: PHASE b ─────────────────────────────────
if run_b && [ "$STOPPED" -eq 0 ]; then
    phase_b
else
    run_b || note "PHASE=$PHASE: steps 2b, 3, 3b, 3c belong to PHASE b (R1-d-b)"
fi

if run_a && [ "$STOPPED" -eq 0 ]; then

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
# issue for GB (the 64 MiB rebuild), so none is likely to be mid-flight at the reset.
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
echo "=== Step 5: grow.bin shrinks to 48 MiB: the mark goes, a new version is backed up (backup-i4) ==="
LINE5=$(log_line_count 0)
# 48 MiB: >= B_eff (large-file path, importance 0 never leaves the pack queue) and a prefix
# of the original 64 MiB, so new content (not a dedup back onto GB).
truncate -s 48M "$GROW"
if poll 90 tl_gone 0 "$GROW"; then pass "grow.bin: too_large mark removed"
else fail "backup-i4: grow.bin still marked too_large 90s after shrinking to 48 MiB"; fi
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
for i in "${!DPID[@]}"; do kill -CONT "${DPID[$i]}" 2>/dev/null || true; done
run_b && final_lines_check
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
