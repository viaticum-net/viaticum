#!/bin/bash
# Shared helpers for experiments/local_*_test.sh. Sourced, never executed.
#
# The sourcing script must define `node_dir IDX` (a node's --data-dir), `BINARY`
# and `fail` (and `node_log IDX` for the log helpers, `T_BASE` for `events`), and source
# this file AFTER those definitions.
#
# Anti-false-green rules these helpers exist to enforce:
#   - restore is checked only after the local source is gone (otherwise the
#     owner rebuilds the block from its own file and the network is never used);
#   - content is compared by hash, never by "a file appeared";
#   - holder-side state is read from the holder's own disk, not the owner's view;
#   - every wait is a poll with a deadline; "nothing happened" is a FAIL.

# The CLI treats VIATICUM_SERVER / VIATICUM_TOKEN as "talk to a remote daemon".
# rbuild.sh/rtest.sh use VIATICUM_SERVER for the build host, so it must never
# leak into a test run.
unset VIATICUM_SERVER VIATICUM_TOKEN

info() { echo "  INFO: $1"; }

content_hash() { sha256sum "$1" | awk '{print $1}'; }
file_size() { stat -c %s "$1"; }

urlencode() { jq -rn --arg v "$1" '$v|@uri'; }

# GET a web-API endpoint of node IDX. Prints the body ("" when unreachable).
api_get() {
    local dir; dir=$(node_dir "$1")
    [ -f "$dir/api-port" ] && [ -f "$dir/api-token" ] || return 0
    curl -s --max-time 10 \
        -H "Authorization: Bearer $(tr -d '[:space:]' < "$dir/api-token")" \
        "http://127.0.0.1:$(tr -d '[:space:]' < "$dir/api-port")$2" 2>/dev/null || true
}

# Numeric field of `status --json` straight from the API (no CLI parsing).
status_num() {
    local v
    v=$(api_get "$1" /api/status | jq -r ".$2 // empty" 2>/dev/null || true)
    echo "${v:-0}"
}

# jq expression evaluated on the catalog entry (GET /api/files) for PATH.
file_field() {
    api_get "$1" /api/files \
        | jq -r --arg p "$2" ".[] | select(.path==\$p) | $3" 2>/dev/null || true
}

# Full hex id of the source block holding the latest version of PATH. Empty while that
# version is still pending: its id is a zero placeholder until the pipeline patches in the
# real block (a poll that captured the zeros used to wait on a block that never exists).
file_block_hex() {
    api_get "$1" "/api/versions?path=$(urlencode "$2")" \
        | jq -r '.[-1] | select(.backed_up_at != "pending")
                 | .source_block_id_hex // empty | select(test("^0+$") | not)' 2>/dev/null || true
}

# Poll until owner IDX reports PATH as restorable (>= k_eff symbols on Alive
# placements). This is the owner's own belief; the tests then prove it by
# restoring from the network or by reading holder disks.
wait_file_restorable() {
    local idx="$1" path="$2" secs="$3" kind=""
    for _ in $(seq 1 "$secs"); do
        kind=$(file_field "$idx" "$path" '.effective_status.kind // "none"')
        [ "$kind" = "restorable" ] && return 0
        sleep 1
    done
    echo "    last effective_status of $(basename "$path"): $(file_field "$idx" "$path" '.effective_status')"
    return 1
}

# Poll until owner IDX has registered PATH as deleted locally.
wait_file_deleted() {
    local idx="$1" path="$2" secs="$3"
    for _ in $(seq 1 "$secs"); do
        [ "$(file_field "$idx" "$path" '.local_state')" = "deleted" ] && return 0
        sleep 1
    done
    return 1
}

# Symbol files node IDX holds for BLOCK_HEX, read from the holder's own disk
# (holdings/{block_hex}/{esi}.bin).
block_symbols_on() {
    local d; d="$(node_dir "$1")/holdings/$2"
    [ -d "$d" ] || { echo 0; return; }
    # The holder may delete the directory mid-scan (delete flow): never fail.
    find "$d" -maxdepth 1 -type f -name '*.bin' 2>/dev/null | wc -l || true
}

# Poll until owner IDX sees at least N authenticated peers.
wait_auth_peers() {
    local idx="$1" want="$2" secs="$3" have=0
    for _ in $(seq 1 "$secs"); do
        have=$(status_num "$idx" peer_count_authenticated)
        [ "$have" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}

# restore_run IDX TIMEOUT_SECS ARGS...
#
# `viaticum restore ARGS --json` on node IDX, killed after TIMEOUT_SECS (the CLI
# itself has no deadline: it waits for the job, restore-i4). Sets RESTORE_RC (the
# CLI exit code: 0 complete, 2 partial, 1 nothing / refused / lost contact; 124 =
# our timeout), RESTORE_FIRST (the submitted job, first NDJSON line), RESTORE_LAST
# (the finished job, last line; "" if none), RESTORE_ERR (stderr).
restore_run() {
    local idx="$1" secs="$2"; shift 2
    local out errf
    errf=$(mktemp)
    set +e
    out=$(timeout "$secs" "$BINARY" --data-dir "$(node_dir "$idx")" restore "$@" --json 2>"$errf")
    RESTORE_RC=$?
    set -e
    RESTORE_ERR=$(cat "$errf"); rm -f "$errf"
    RESTORE_FIRST=$(printf '%s\n' "$out" | sed -n '1p')
    RESTORE_LAST=$(printf '%s\n' "$out" | sed -n '2,$p' | tail -1)
}

# staging_matches_job JOB_JSON
#
# The regular files in the job's staging dir (without the daemon's `.viaticum-*`
# entries) are exactly the job's `restored_paths` (as a set). Sets RESTORE_MSG on
# a mismatch.
staging_matches_job() {
    local job="$1" dir want got
    dir=$(echo "$job" | jq -r '.staging_path')
    [ -d "$dir" ] || { RESTORE_MSG="staging dir $dir does not exist"; return 1; }
    want=$(echo "$job" | jq -r '.restored_paths[]' | sort)
    got=$(cd "$dir" && find . -path './.viaticum-*' -prune -o -type f -print | sed 's|^\.||' | sort)
    if [ "$want" != "$got" ]; then
        RESTORE_MSG="staging $dir holds [$(echo $got)] but the job claims [$(echo $want)]"
        return 1
    fi
}

# restore_from_network IDX PATH EXPECTED_HASH SECS
#
# Restores PATH on node IDX and checks the staged copy by content hash.
# Precondition (asserted): PATH does not exist on disk, so the owner cannot
# rebuild the block from its own source and must fetch symbols from holders.
# Requires: the CLI waited for the job and exited 0 within SECS; the job's
# outcome is `complete`; PATH is in its `restored_paths`; the staged file
# `staging_path/PATH` has EXPECTED_HASH; staging holds exactly `restored_paths`.
# Files appear in staging only complete (restore-i14): no size-settle loop.
# Sets RESTORE_MSG and RESTORE_JOB_JSON (the finished job).
restore_from_network() {
    local idx="$1" path="$2" want="$3" secs="$4"
    RESTORE_MSG=""
    RESTORE_JOB_JSON=""
    if [ -e "$path" ]; then
        RESTORE_MSG="source $path still on disk: restore would not touch the network"
        return 1
    fi
    restore_run "$idx" "$secs" "$path"
    RESTORE_JOB_JSON="$RESTORE_LAST"
    if [ -n "$RESTORE_FIRST" ]; then
        info "restore job $(echo "$RESTORE_FIRST" | jq -r '.job_id' 2>/dev/null) for $path"
    fi
    if [ "$RESTORE_RC" -ne 0 ]; then
        RESTORE_MSG="restore CLI exit $RESTORE_RC (want 0; 124 = still running after ${secs}s); stderr: ${RESTORE_ERR:0:300}; job: ${RESTORE_LAST:0:600}"
        return 1
    fi
    local outcome staging f got
    outcome=$(echo "$RESTORE_LAST" | jq -r '.outcome // "none"' 2>/dev/null || echo "unparsable")
    if [ "$outcome" != "complete" ]; then
        RESTORE_MSG="job outcome $outcome (want complete): ${RESTORE_LAST:0:600}"
        return 1
    fi
    if ! echo "$RESTORE_LAST" | jq -e --arg p "$path" '.restored_paths | index($p) != null' >/dev/null; then
        RESTORE_MSG="$path is not in the job's restored_paths: ${RESTORE_LAST:0:600}"
        return 1
    fi
    staging=$(echo "$RESTORE_LAST" | jq -r '.staging_path')
    f="$staging/${path#/}"
    if [ ! -f "$f" ]; then
        RESTORE_MSG="the job claims $path, but $f does not exist"
        return 1
    fi
    staging_matches_job "$RESTORE_LAST" || return 1
    got=$(content_hash "$f")
    if [ "$got" != "$want" ]; then
        RESTORE_MSG="sha256 MISMATCH: want=$want got=$got ($(file_size "$f") bytes) at $f"
        return 1
    fi
    RESTORE_MSG="sha256 match ($(file_size "$f") bytes) at $f"
}

# Delete-window guard. Call right before removing a source file that the scenario
# will then restore from the network (restore-i9).
#
# Requirement: scenarios that restore after deleting the source rely on the owner
# still having the file's placements when restore runs. The owner sends the Delete
# to holders once the owner-delete cooldown expires:
#   scaled_cooldown = OWNER_DELETE_COOLDOWN_SECS / time_scale   (integer division,
#   crates/viaticum-core/src/deletion/mod.rs: owner_cooldown)
#   OWNER_DELETE_COOLDOWN_SECS = 4 * SECS_PER_WEEK = 2419200
#   (crates/viaticum-core/src/constants.rs)
# That must be much longer than the rest of the run, otherwise a green restore
# depends on racing the delete. The floor is 600 s; keep this constant in sync
# with constants.rs.
OWNER_DELETE_COOLDOWN_SECS=2419200
DELETE_WINDOW_FLOOR_SECS=600

# assert_delete_window TIME_SCALE [FLOOR_SECS]: FAIL and exit when the scaled
# owner-delete cooldown is below the floor (default DELETE_WINDOW_FLOOR_SECS).
# A scenario that deliberately races the window (local_pack_delete_test) passes a
# lower floor and then checks its own elapsed time explicitly.
assert_delete_window() {
    local scale="$1" floor="${2:-$DELETE_WINDOW_FLOOR_SECS}" scaled
    [ "$scale" -ge 1 ] || scale=1
    scaled=$((OWNER_DELETE_COOLDOWN_SECS / scale))
    if [ "$scaled" -lt "$floor" ]; then
        fail "delete window: OWNER_DELETE_COOLDOWN_SECS/${scale} = ${scaled}s < ${floor}s; the network may drop the file before restore runs"
        exit 1
    fi
    info "delete window: OWNER_DELETE_COOLDOWN_SECS/${scale} = ${scaled}s (floor ${floor}s)"
}

# Holder-side corroboration that a restore went over the network: number of
# "sending RestoreResponse" log lines for BLOCK_HEX across the given nodes' logs.
# The daemon logs block ids as their first 16 hex chars.
restore_responses_for() {
    local hex="${1:0:16}"; shift
    local total=0 n i
    [ -n "$hex" ] || { echo 0; return; }
    for i in "$@"; do
        n=$(grep -a "sending RestoreResponse" "$(node_log "$i")" 2>/dev/null | grep -ac "$hex" || true)
        total=$((total + ${n:-0}))
    done
    echo "$total"
}

# ── Process and log helpers ─────────────────────────────────────────────────
# Daemon logs are appended (`>>`) across restarts, so "what this instance
# wrote" = the lines after the count taken right before it was started.

# Current number of lines in node IDX's log (0 when there is no log yet).
log_line_count() {
    local f; f=$(node_log "$1")
    if [ -f "$f" ]; then wc -l < "$f"; else echo 0; fi
}

# ── Timestamped log events (moved from local_ledger_test.sh, У-4) ─────────────
#
# events FILE PATTERN KEY... -> one line per log line containing PATTERN:
#   "<t> <line> <value of KEY1> <value of KEY2> ..."   ("-" for a missing key)
# t = seconds since T_BASE (set by the sourcing script, unix seconds) from the log's own
# RFC 3339 UTC timestamp; line = line number in FILE. ANSI colour codes are stripped first.
# Values are the text after `key=` up to the next space (tracing's key=value fields).
AWK_EPOCH='
function epoch(ts,   y, mo, d, h, mi, s, yy, era, yoe, doy, doe) {
    y = substr(ts, 1, 4) + 0; mo = substr(ts, 6, 2) + 0; d = substr(ts, 9, 2) + 0
    h = substr(ts, 12, 2) + 0; mi = substr(ts, 15, 2) + 0
    s = substr(ts, 18); sub(/Z$/, "", s); s = s + 0
    yy = y - (mo <= 2 ? 1 : 0)
    era = int(yy / 400); yoe = yy - era * 400
    doy = int((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s
}'
events() {
    local file="$1" pat="$2"; shift 2
    sed 's/\x1b\[[0-9;]*m//g' "$file" 2>/dev/null | awk -v pat="$pat" -v keys="$*" \
        -v base="${T_BASE:-0}" "$AWK_EPOCH"'
        index($0, pat) {
            n = split(keys, K, " ")
            split("", kv)
            for (i = 2; i <= NF; i++) {
                p = index($i, "=")
                if (p > 1) kv[substr($i, 1, p - 1)] = substr($i, p + 1)
            }
            out = sprintf("%.3f %d", epoch($1) - base, NR)
            for (j = 1; j <= n; j++) out = out " " ((K[j] in kv) ? kv[K[j]] : "-")
            print out
        }' || true
}

# Lines of node IDX's log after line N, ANSI colors stripped.
log_since() {
    tail -n +$(( $2 + 1 )) "$(node_log "$1")" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true
}

# Integer value of FIELD in a tracing key=value log LINE ("" when absent).
log_field() {
    echo "$1" | grep -oE "(^|[[:space:]])$2=[0-9]+" | head -1 | grep -oE '[0-9]+$' || true
}

# wait_pid_exit PID SECS: poll until PID (a child of this shell) exits; sets
# EXIT_RC to its exit status. Returns 1 (EXIT_RC empty) if it is still running.
wait_pid_exit() {
    local pid="$1" secs="$2"
    EXIT_RC=""
    for _ in $(seq 1 $(( secs * 5 ))); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null && EXIT_RC=0 || EXIT_RC=$?
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Holder-side proof that a Delete for BLOCK_HEX reached a holder: number of
# "holding marked for deletion" log lines for BLOCK_HEX across the given nodes'
# logs (processor/symbol.rs, the holder flips its holding Active -> MarkedForDelete
# and stops serving it). Block ids are logged as their first 16 hex chars.
delete_marks_for() {
    local hex="${1:0:16}"; shift
    local total=0 n i
    [ -n "$hex" ] || { echo 0; return; }
    for i in "$@"; do
        n=$(grep -a "holding marked for deletion" "$(node_log "$i")" 2>/dev/null | grep -ac "$hex" || true)
        total=$((total + ${n:-0}))
    done
    echo "$total"
}

# api_post IDX PATH JSON: POST JSON to a web-API endpoint of node IDX. Prints
# "<http_code> <body>" ("000 " when the node is unreachable), never fails.
api_post() {
    local dir; dir=$(node_dir "$1")
    if [ ! -f "$dir/api-port" ] || [ ! -f "$dir/api-token" ]; then
        echo "000 "
        return 0
    fi
    local out
    out=$(curl -s --max-time 10 -X POST \
        -H "Authorization: Bearer $(tr -d '[:space:]' < "$dir/api-token")" \
        -H "Content-Type: application/json" \
        -d "$3" -w '\n%{http_code}' \
        "http://127.0.0.1:$(tr -d '[:space:]' < "$dir/api-port")$2" 2>/dev/null || true)
    # curl prints the body, a newline, then the status code.
    local code="${out##*$'\n'}"
    local body="${out%$'\n'*}"
    [ "$code" = "$out" ] && body=""
    echo "${code:-000} $body"
}

# ── Pointer places at the postmen (CROWN-1 C3a) ──────────────────────────────
#
# The postman logs every accepted pointer as
#   "mailbox: stored SelfPointer entry target=<16 hex> msg_id=<32 hex> replaced=<bool>";
# the rendezvous address is `mailbox-probe rendezvous --phrase` .address_short.

# sp_store_lines RADDR16 IDX... : the store lines for RADDR16 across the nodes' logs,
# each prefixed by "<IDX> ".
sp_store_lines() {
    local raddr="$1" i; shift
    for i in "$@"; do
        sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$i")" 2>/dev/null \
            | grep -a "mailbox: stored SelfPointer entry" | grep -a "target=$raddr" \
            | sed "s/^/$i /" || true
    done
}

# sp_msg_ids RADDR16 IDX... : distinct msg_ids stored for RADDR16, space-separated, sorted.
sp_msg_ids() {
    sp_store_lines "$@" | grep -oE 'msg_id=[0-9a-f]+' | cut -d= -f2 | sort -u | tr '\n' ' ' \
        | sed 's/ $//' || true
}

# sp_postmen_with_store RADDR16 IDX... : how many of the nodes logged >= 1 store for RADDR16.
sp_postmen_with_store() {
    local raddr="$1" n=0 i; shift
    for i in "$@"; do
        [ -n "$(sp_store_lines "$raddr" "$i")" ] && n=$((n + 1))
    done
    echo "$n"
}

# honest_mailbox_negatives IDX... : lines no honest node may ever log in C3a — a postman
# refusing a plaintext pointer (an honest publisher seals every pointer) and a pointer
# found in a master box (pointers live only in the rendezvous box).
honest_mailbox_negatives() {
    local i
    for i in "$@"; do
        sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$i")" 2>/dev/null \
            | grep -aE "mailbox: store rejected — plaintext payload|SelfPointer in the master box — dropped" \
            | sed "s/^/node $i: /" || true
    done
}

# holders_of_prefix HEX16 IDX... : the nodes whose holdings hold >= 1 symbol of the block
# whose id starts with HEX16 (SS blocks are logged by their first 16 hex chars).
holders_of_prefix() {
    local hex="$1" out="" i d; shift
    for i in "$@"; do
        for d in "$(node_dir "$i")"/holdings/"$hex"*; do
            [ -d "$d" ] || continue
            if [ "$(find "$d" -maxdepth 1 -type f -name '*.bin' 2>/dev/null | wc -l)" -gt 0 ]; then
                out="$out $i"; break
            fi
        done
    done
    echo "${out# }"
}

# dr_attempt_plan DR_LOG : the DR attempt lines "i/N place created_at base", one per line.
dr_attempt_plan() {
    sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -a "dr: attempt " \
        | sed -E 's/.*dr: attempt ([0-9]+\/[0-9]+) place=([AB-]) created_at=([0-9]+) base=([0-9a-f]+).*/\1 \2 \3 \4/' \
        || true
}

# last_published_base IDX PLACE : base (16 hex) of the node's last "SelfPointer published
# via mailbox" line with place=PLACE ("" when none).
last_published_base() {
    sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$1")" 2>/dev/null \
        | grep -a "SelfPointer published via mailbox" | grep -a "place=$2" | tail -1 \
        | grep -oE 'base=[0-9a-f]+' | cut -d= -f2 || true
}

# ── Scale measurements (СТ-0, local_pos_scale_test) ─────────────────────────
#
# Times are the `events` times (seconds since T_BASE, from the log's own timestamps).

# events_grep FILE PATTERN KEY... : `events` over only the lines that contain PATTERN
# (pre-filtered with grep -F, so a multi-GB log costs one grep). The line field counts
# the filtered lines, not the file's; use times, not line numbers, with it.
events_grep() {
    local file="$1" pat="$2"; shift 2
    events <(grep -aF -- "$pat" "$file" 2>/dev/null || true) "$pat" "$@"
}

# in_window A B : keep the `events` lines whose time (field 1) is in [A, B].
in_window() { awk -v a="$1" -v b="$2" '($1 + 0) >= a && ($1 + 0) <= b'; }

# p95 : the 95th percentile (nearest rank) of the numbers on stdin; "" when there are none.
p95() {
    sort -n | awk '{ v[NR] = $1 }
        END { if (NR) { i = int(NR * 0.95); if (i < NR * 0.95) i++; if (i < 1) i = 1; print v[i] } }'
}

# max_gap : the largest difference between consecutive numbers on stdin (sorted first);
# 0 for fewer than two numbers.
max_gap() {
    sort -n | awk 'NR > 1 && $1 - p > g { g = $1 - p } { p = $1 } END { printf "%.1f\n", g + 0 }'
}

# proc_rchar PID : bytes the process has read so far (`rchar` of /proc/PID/io; "" when
# the process is gone or unreadable). Counts every read(2) incl. page-cache hits, which
# is what a re-read of the same symbols costs the holder.
proc_rchar() { awk '/^rchar:/ { print $2 }' "/proc/$1/io" 2>/dev/null || true; }

# block_bytes_on IDX HEX16 : bytes of the symbol files node IDX holds, on its own disk,
# for the block whose id starts with HEX16 (holdings/{block_hex}/{esi}.bin).
block_bytes_on() {
    local d total=0 s
    for d in "$(node_dir "$1")"/holdings/"$2"*; do
        [ -d "$d" ] || continue
        s=$(find "$d" -maxdepth 1 -type f -name '*.bin' -printf '%s\n' 2>/dev/null \
            | awk '{ t += $1 } END { print t + 0 }')
        total=$((total + s))
    done
    echo "$total"
}

# sleep_until T : sleep until `events` time T (seconds since T_BASE); no-op if past.
sleep_until() {
    local d=$(( $1 - ( $(date -u +%s) - T_BASE ) ))
    [ "$d" -gt 0 ] && sleep "$d"
    return 0
}
