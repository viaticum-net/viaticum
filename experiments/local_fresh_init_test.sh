#!/bin/bash
# Viaticum fresh-init E2E (mini-fixes F1, F13, F9): what a friend gets from
# `viaticum init` + `viaticum daemon --watch-dir <folder>` (the README's "Try it",
# literally) with nothing edited by hand.
#
# Scenario:     one node, clean data dir. `init` with defaults, no config edits;
#               the daemon is started the way the README says (`daemon --watch-dir`
#               a folder with one small file), restarted by SIGTERM + start and by
#               POST /api/restart (what the Settings "Save & restart" sends), and
#               the Settings form is read and saved back unchanged over the web API
#               after the friend wrote `soft_quota_gb = 50` (a TOML integer) by hand.
# Intent:       daemon-i9 (F1), daemon-i10 (F13) private/intent/daemon.md;
#               delete-i7 (F9) private/intent/delete.md
# Proves:       after a plain `init` the CLI reaches the daemon (`status --json`
#               answers), `token --url` gives the Dashboard URL (what `open`
#               launches) and `GET /` = 200 — on the port written in config.toml
#               (not 0, loopback), the same port after a restart, a plain one and
#               the web UI's self re-exec (POST /api/restart). An integer quota
#               reads back as 50 in the Settings API and survives Save unchanged.
#               The web UI the daemon serves does not call a file "safe to delete".
# Adversarial:  red on the old code, per fix:
#               F1 (template without `[web_api] enabled = true`): step 1 (config
#                  has no enabled web API) and step 2 — no api-port file, `status
#                  --json` fails "cannot read .../api-port" for the whole deadline;
#                  every later step fails with it.
#               F13 (read_editable reads the quota by `as_float()` only): step 6 —
#                  GET /api/config gives the default 0, and the unchanged Save
#                  writes 0.0 over the friend's 50.
#               F9 (old badge text): step 4 — the served JS contains "safe to
#                  delete" / "without your local copy".
#               README start line (W1: `--watch` instead of `--watch-dir`): clap
#                  refuses the flag, the daemon exits — step 2 fails "daemon exited:
#                  error: unexpected argument '--watch'", every later step with it.
#               Self re-exec that loses the port (child binds another / cannot bind
#                  while the parent drains, or never comes up): step 5b — status does
#                  not answer within the deadline, or api-port ≠ P.
#               Positive controls keep the greps honest: the bundle must be the
#               Files view (contains `is_safe_to_delete` and the new label "at
#               target"), and the quota is checked against a value ≠ the default.
# Cannot close: port taken by another program at start (daemon-i7, refused start
#               — local_daemon_health_test covers the listen-port twin); LAN
#               access and choosing another port (R2a/R3b); `open` itself (it
#               launches a browser — `token --url` prints the same URL); the
#               web-ui pages rendering in a browser (the Settings page's own poll
#               after "Save & restart" — step 5b sends the same POST); that the
#               watched folder's file gets backed up (one node, no peers — other
#               scenarios cover backup).
# Steps:        0. setup: a folder with one small file to watch (the README's
#                  ~/Documents)
#               1. `init` (defaults) → config.toml: [web_api] enabled = true,
#                  bind loopback, port P ≠ 0 (daemon-i9) — check: tomllib
#               1b. setup: P must be free before the daemon starts (taken =
#                  setup FAIL, never a skip) — check: ss
#               2. `daemon --watch-dir <folder>` (README) → `status --json` answers
#                  (exit 0, JSON) within 30 s; api-port = P (daemon-i9) — check:
#                  poll with deadline
#               3. `token --url` → http://127.0.0.1:P/auth/start?token=…; that URL
#                  → 303; `GET /` → 200 HTML (daemon-i9) — check: curl codes
#               4. every JS asset referenced by index.html → 200, contains
#                  `is_safe_to_delete` and "at target", contains neither "safe to
#                  delete" nor "without your local copy" (delete-i7) — check: grep
#               5. SIGTERM → exit 0; restart → status answers; port in config and
#                  api-port still P (daemon-i9) — check: poll, compare
#               5b. POST /api/restart (bearer token) → 202; the old process exits
#                  within 60 s; the re-exec'd child (same args) answers `status`
#                  within 30 s; config bind and api-port still P (daemon-i9) —
#                  check: wait_pid_exit, pgrep, poll, compare
#               6. stop; `soft_quota_gb = 50` (integer) under [storage]; start →
#                  GET /api/config .storage.soft_quota_gb = 50; PUT the same body
#                  → 200; config.toml soft_quota_gb = 50 and GET again = 50
#                  (daemon-i10) — check: jq, tomllib
#               7. SIGTERM → exit 0; no panic in the log — check: exit status, grep
#
# Usage:
#   Needs: jq, curl, python3 (tomllib), ss, pgrep.
#   ./rbuild.sh      # release binary, built on the server
#   bash experiments/local_fresh_init_test.sh
#   (or: private/testing/run_e2e.sh fresh_init)

set -euo pipefail

TEST_DIR="/tmp/viaticum-fi-$$"
BINARY="${BINARY:-viaticum}"
STATUS_DEADLINE=30
# The folder the README tells the friend to watch (`--watch-dir ~/Documents`).
WATCH_DIR="$TEST_DIR/Documents"

PASS=0; FAIL=0
DPID=""

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

node_dir() { echo "$TEST_DIR/node-00"; }
node_log() { echo "$(node_dir 0)/daemon.log"; }
CFG="$TEST_DIR/node-00/config.toml"

run_cli() { "$BINARY" --data-dir "$(node_dir 0)" "$@"; }

# has TEXT PATTERN: fixed-string match without a pipe (a pipe + grep -q under
# pipefail turns "must NOT contain" into a false PASS on SIGPIPE).
has() { grep -qF -- "$2" <<< "$1"; }

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

cleanup() {
    if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then
        kill "$DPID" 2>/dev/null || true
        wait_pid_exit "$DPID" 10 || kill -9 "$DPID" 2>/dev/null || true
    fi
    # A re-exec'd daemon step 5b could not find (not this shell's child) must not
    # outlive the run on the shared server.
    pkill -TERM -f -- "--data-dir $TEST_DIR/node-00 daemon" 2>/dev/null || true
    if [ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]; then
        rm -rf "$TEST_DIR"
    else
        echo "  Kept for inspection: $TEST_DIR"
    fi
}
trap cleanup EXIT

# toml_get SECTION KEY: the value of [SECTION].KEY in config.toml as JSON
# (`null` when absent, `ERR` when the file does not parse).
toml_get() {
    python3 - "$CFG" "$1" "$2" << 'PY' 2>/dev/null || echo ERR
import json, sys, tomllib
with open(sys.argv[1], "rb") as f:
    doc = tomllib.load(f)
print(json.dumps(doc.get(sys.argv[2], {}).get(sys.argv[3])))
PY
}

# The binary itself in the background (not the run_cli function: $! would be a
# subshell, and SIGTERM would miss the daemon), started the way the README says:
# `daemon --watch-dir <folder>` — a flag the CLI does not know exits the daemon,
# and wait_status reports it.
start_daemon() {
    "$BINARY" --data-dir "$(node_dir 0)" daemon --watch-dir "$WATCH_DIR" \
        >> "$(node_log 0)" 2>&1 &
    DPID=$!
}

# wait_status SECS: poll `status --json` until it exits 0 with JSON. Sets STATUS_ERR.
wait_status() {
    local out deadline=$(( $(date +%s) + $1 ))
    STATUS_ERR=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if out=$(run_cli status --json 2> "$TEST_DIR/status.err") && jq -e . <<< "$out" > /dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$DPID" 2>/dev/null; then
            STATUS_ERR="daemon exited: $(tail -n 3 "$(node_log 0)" 2>/dev/null | tr '\n' ' ')"
            return 1
        fi
        sleep 0.5
    done
    STATUS_ERR=$(tr '\n' ' ' < "$TEST_DIR/status.err")
    return 1
}

# stop_daemon: SIGTERM, then the exit status within 60 s. Sets EXIT_RC.
stop_daemon() {
    kill -TERM "$DPID" 2>/dev/null || true
    if ! wait_pid_exit "$DPID" 60; then
        kill -9 "$DPID" 2>/dev/null || true
        EXIT_RC="timeout"
    fi
    DPID=""
}

api_port_file() { tr -d '[:space:]' < "$(node_dir 0)/api-port" 2>/dev/null || true; }

# http_code URL: status code of a plain GET ("000" when unreachable).
http_code() { curl -s -o /dev/null --max-time 10 -w '%{http_code}' "$1" 2>/dev/null || echo 000; }

# api_put PATH JSON: PUT JSON with the bearer token. Prints "<code> <body>".
api_put() {
    local dir out code body; dir=$(node_dir 0)
    out=$(curl -s --max-time 10 -X PUT \
        -H "Authorization: Bearer $(tr -d '[:space:]' < "$dir/api-token")" \
        -H "Content-Type: application/json" -d "$2" -w '\n%{http_code}' \
        "http://127.0.0.1:$(api_port_file)$1" 2>/dev/null || true)
    code="${out##*$'\n'}"; body="${out%$'\n'*}"
    [ "$code" = "$out" ] && body=""
    echo "${code:-000} $body"
}

mkdir -p "$(node_dir 0)"

echo "=== Step 0: setup — a folder with one small file to watch ==="
mkdir -p "$WATCH_DIR"
printf 'fresh-init %s\n' "$$" > "$WATCH_DIR/note.txt"

echo "=== Step 1: init with defaults → web API on a fixed loopback port (daemon-i9) ==="
run_cli init > "$TEST_DIR/init.out" 2>&1 || fail "step 1: init exited non-zero: $(tail -3 "$TEST_DIR/init.out")"
ENABLED=$(toml_get web_api enabled)
BIND=$(toml_get web_api bind | jq -r '. // empty' 2>/dev/null || true)
P="${BIND##*:}"
if [ "$ENABLED" = "true" ] && [[ "$BIND" == 127.0.0.1:* ]] && [[ "$P" =~ ^[0-9]+$ ]] && [ "$P" -ne 0 ]; then
    pass "step 1: config.toml has [web_api] enabled = true, bind = $BIND"
else
    fail "step 1: config.toml web_api enabled=$ENABLED bind='$BIND' (need true, 127.0.0.1:<port ≠ 0>)"
fi

echo "=== Step 1b: the template's port is free before the daemon starts ==="
if [[ "$P" =~ ^[0-9]+$ ]] && [ "$P" -ne 0 ]; then
    LISTENERS=$(ss -Htln "sport = :$P" 2>/dev/null || true)
    if [ -n "$LISTENERS" ]; then
        fail "setup: port $P is already taken on this machine — cannot test the fresh-init port"
    else
        info "port $P is free"
    fi
fi

echo "=== Step 2: the CLI reaches the daemon with nothing edited (daemon-i9) ==="
start_daemon
if wait_status "$STATUS_DEADLINE"; then
    pass "step 2: status --json answers within ${STATUS_DEADLINE}s"
else
    fail "step 2: status --json did not answer within ${STATUS_DEADLINE}s: $STATUS_ERR"
fi
AP=$(api_port_file)
if [ -n "$AP" ] && [ "$AP" = "$P" ]; then
    pass "step 2: api-port = $AP, the port in config.toml"
else
    fail "step 2: api-port '$AP' ≠ config port '$P'"
fi

echo "=== Step 3: the Dashboard URL works (daemon-i9) ==="
URL=$(run_cli token --url 2>/dev/null || true)
if [[ "$URL" == "http://127.0.0.1:$P/auth/start?token="?* ]]; then
    pass "step 3: token --url gives http://127.0.0.1:$P/auth/start?token=…"
else
    fail "step 3: token --url gave '${URL%%token=*}…'"
fi
C_AUTH=$(http_code "$URL")
C_ROOT=$(http_code "http://127.0.0.1:$P/")
if [ "$C_AUTH" = "303" ] && [ "$C_ROOT" = "200" ]; then
    pass "step 3: /auth/start → 303, GET / → 200"
else
    fail "step 3: /auth/start → $C_AUTH (want 303), GET / → $C_ROOT (want 200)"
fi

echo "=== Step 4: the served web UI never calls a file safe to delete (delete-i7) ==="
INDEX=$(curl -s --max-time 10 "http://127.0.0.1:$P/" 2>/dev/null || true)
ASSETS=$(grep -oE '/assets/[A-Za-z0-9._-]+\.js' <<< "$INDEX" | sort -u || true)
if [ -z "$ASSETS" ]; then
    fail "step 4: index.html references no /assets/*.js (nothing to check is a FAIL)"
fi
FILES_VIEW=0; BAD=""
for a in $ASSETS; do
    JS=$(curl -s --max-time 10 "http://127.0.0.1:$P$a" 2>/dev/null || true)
    [ -n "$JS" ] || { BAD="$BAD $a(empty)"; continue; }
    if has "$JS" "is_safe_to_delete" && has "$JS" "at target"; then FILES_VIEW=1; fi
    for phrase in "safe to delete" "without your local copy"; do
        if grep -qiF -- "$phrase" <<< "$JS"; then BAD="$BAD $a:'$phrase'"; fi
    done
done
if [ "$FILES_VIEW" -eq 1 ]; then
    pass "step 4: the served bundle carries the Files view (is_safe_to_delete + \"at target\")"
else
    fail "step 4: no served JS carries the Files view badge (is_safe_to_delete + \"at target\") — stale dist?"
fi
if [ -n "$ASSETS" ] && [ -z "$BAD" ]; then
    pass "step 4: no served JS says \"safe to delete\" / \"without your local copy\""
else
    fail "step 4: served JS:$BAD"
fi

echo "=== Step 5: restart keeps the port (daemon-i9) ==="
stop_daemon
[ "$EXIT_RC" = "0" ] && pass "step 5: SIGTERM → exit 0" || fail "step 5: SIGTERM → exit $EXIT_RC"
start_daemon
if wait_status "$STATUS_DEADLINE"; then
    pass "step 5: status answers after the restart"
else
    fail "step 5: status did not answer after the restart: $STATUS_ERR"
fi
BIND2=$(toml_get web_api bind | jq -r '. // empty' 2>/dev/null || true)
AP2=$(api_port_file)
if [ "$BIND2" = "$BIND" ] && [ "$AP2" = "$P" ]; then
    pass "step 5: config bind and api-port still $P"
else
    fail "step 5: after restart bind='$BIND2' api-port='$AP2' (was $BIND)"
fi

echo "=== Step 5b: POST /api/restart — the re-exec'd daemon answers on the same port (daemon-i9) ==="
# The Settings "Save & restart" path: the daemon spawns a child with the same
# binary and args, then drains and exits; the child waits for the DB lock and
# binds the same fixed web port.
OLD_PID="$DPID"
read -r RS_CODE RS_BODY <<< "$(api_post 0 /api/restart '{}')"
if [ "$RS_CODE" = "202" ]; then
    pass "step 5b: POST /api/restart → 202"
else
    fail "step 5b: POST /api/restart → $RS_CODE $RS_BODY (want 202)"
fi
if wait_pid_exit "$OLD_PID" 60; then
    pass "step 5b: the old daemon (pid $OLD_PID) exited after the restart request"
    info "old daemon exit status: $EXIT_RC"
    # The child is not this shell's child: find it by its command line (the
    # per-run data dir makes it unique).
    NEW_PID=$(pgrep -f -- "--data-dir $(node_dir 0) daemon" | grep -vx "$OLD_PID" | head -n 1 || true)
    DPID="$NEW_PID"
    [ -n "$NEW_PID" ] || fail "step 5b: no re-exec'd daemon runs for $(node_dir 0)"
else
    fail "step 5b: the old daemon (pid $OLD_PID) still runs 60 s after POST /api/restart"
fi
if wait_status "$STATUS_DEADLINE"; then
    pass "step 5b: status answers from the re-exec'd daemon (pid $DPID) within ${STATUS_DEADLINE}s"
else
    fail "step 5b: status did not answer after POST /api/restart: $STATUS_ERR"
fi
BIND3=$(toml_get web_api bind | jq -r '. // empty' 2>/dev/null || true)
AP3=$(api_port_file)
if [ "$BIND3" = "$BIND" ] && [ "$AP3" = "$P" ]; then
    pass "step 5b: config bind and api-port still $P after the self re-exec"
else
    fail "step 5b: after POST /api/restart bind='$BIND3' api-port='$AP3' (was $BIND)"
fi

echo "=== Step 6: an integer quota survives the Settings round-trip (daemon-i10) ==="
stop_daemon
python3 - "$CFG" << 'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s, n = re.subn(r"(?m)^\[storage\]\n", "[storage]\nsoft_quota_gb = 50\n", s, count=1)
assert n == 1, "no [storage] table in the init config"
open(p, "w").write(s)
PY
[ "$(toml_get storage soft_quota_gb)" = "50" ] || fail "step 6: setup: soft_quota_gb = 50 not in config as an integer"
start_daemon
wait_status "$STATUS_DEADLINE" || fail "step 6: status did not answer after the quota edit: $STATUS_ERR"
FORM=$(api_get 0 /api/config)
Q1=$(jq -r '.storage.soft_quota_gb // empty' <<< "$FORM" 2>/dev/null || true)
if [ -n "$Q1" ] && jq -e '.storage.soft_quota_gb == 50' <<< "$FORM" > /dev/null 2>&1; then
    pass "step 6: GET /api/config soft_quota_gb = 50"
else
    fail "step 6: GET /api/config soft_quota_gb = '${Q1}' (want 50; 0 = the default read instead)"
fi
read -r PUT_CODE PUT_BODY <<< "$(api_put /api/config "$FORM")"
if [ "$PUT_CODE" = "200" ]; then
    pass "step 6: PUT /api/config with the unchanged form → 200"
else
    fail "step 6: PUT /api/config → $PUT_CODE $PUT_BODY"
fi
Q_FILE=$(toml_get storage soft_quota_gb)
Q2=$(api_get 0 /api/config | jq -r '.storage.soft_quota_gb // empty' 2>/dev/null || true)
if [[ "$Q_FILE" =~ ^50(\.0)?$ ]] && [[ "$Q2" =~ ^50(\.0)?$ ]]; then
    pass "step 6: after Save config.toml soft_quota_gb = $Q_FILE, GET = $Q2"
else
    fail "step 6: after Save config.toml soft_quota_gb = $Q_FILE, GET = '$Q2' (want 50)"
fi

echo "=== Step 7: clean stop ==="
stop_daemon
[ "$EXIT_RC" = "0" ] && pass "step 7: SIGTERM → exit 0" || fail "step 7: SIGTERM → exit $EXIT_RC"
if grep -aq "panicked" "$(node_log 0)" 2>/dev/null; then
    fail "step 7: panic in the daemon log"
else
    pass "step 7: no panic in the daemon log"
fi

echo ""
echo "============================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "============================================================"
[ "$FAIL" -eq 0 ]
