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

# Full hex id of the source block holding the latest version of PATH.
file_block_hex() {
    api_get "$1" "/api/versions?path=$(urlencode "$2")" \
        | jq -r '.[-1].source_block_id_hex // empty' 2>/dev/null || true
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

# restore_from_network IDX PATH EXPECTED_HASH SECS
#
# Restores PATH on node IDX and checks the staged copy by content hash.
# Precondition (asserted): PATH does not exist on disk, so the owner cannot
# rebuild the block from its own source and must fetch symbols from holders.
# Sets RESTORE_MSG; returns 0 only on a hash match.
restore_from_network() {
    local idx="$1" path="$2" want="$3" secs="$4"
    local base; base=$(basename "$path")
    RESTORE_MSG=""
    if [ -e "$path" ]; then
        RESTORE_MSG="source $path still on disk: restore would not touch the network"
        return 1
    fi
    local out rc staging="" got="" jobs_root
    jobs_root="$(node_dir "$idx")/restore"
    # Job dirs that exist before this restore must never satisfy it.
    local before; before=$(ls "$jobs_root" 2>/dev/null | sort || true)
    set +e
    out=$("$BINARY" --data-dir "$(node_dir "$idx")" restore "$path" 2>&1)
    rc=$?
    set -e
    echo "$out" | sed 's/^/    | /'
    staging=$(echo "$out" | awk '/^  staging:/ {print $2}')
    local deadline="$secs"
    if [ -n "$staging" ] && [ "$rc" -eq 0 ]; then
        # POST /api/restore answers after the job finished, so the file is either
        # there now or the job failed (the daemon still reports "started").
        deadline=5
    elif [ -z "$staging" ]; then
        if echo "$out" | grep -qiE "blocked|restore failed|not found"; then
            RESTORE_MSG="restore command failed (exit=$rc)"
            return 1
        fi
        # The CLI gives up after 30 s but the daemon keeps restoring.
        info "restore CLI exited $rc before the daemon finished; polling new job dirs"
    fi
    local f="" size_prev=-1 size_now=0 root="" d
    for _ in $(seq 1 "$deadline"); do
        if [ -n "$staging" ]; then
            root="$staging"
        else
            root=""
            for d in $(ls "$jobs_root" 2>/dev/null | sort || true); do
                echo "$before" | grep -qx "$d" || root="$jobs_root/$d"
            done
        fi
        f=""
        [ -n "$root" ] && f=$(find "$root" -type f -name "$base" 2>/dev/null | head -1 || true)
        if [ -n "$f" ]; then
            # The staging writer publishes only complete files (restore-i14), so the
            # size check is redundant now; kept until B1.3 rewrites this helper.
            size_now=$(file_size "$f")
            if [ "$size_now" -eq "$size_prev" ]; then
                got=$(content_hash "$f")
                if [ "$got" = "$want" ]; then
                    RESTORE_MSG="sha256 match ($size_now bytes) at $f"
                    return 0
                fi
                RESTORE_MSG="sha256 MISMATCH: want=$want got=$got ($size_now bytes) at $f"
                return 1
            fi
            size_prev=$size_now
        fi
        sleep 1
    done
    if [ -n "$staging" ] && [ "$rc" -eq 0 ]; then
        RESTORE_MSG="CLI exit 0 and status 'started', but no $base in $staging: the job ended without restoring it (see node log)"
        return 1
    fi
    root="${root:-$jobs_root}"
    RESTORE_MSG="no restored file named $base under $root after ${secs}s"
    return 1
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
