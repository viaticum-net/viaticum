#!/bin/bash
# Viaticum setup E2E: a friend installs a node with one command, answers two
# questions, writes 24 words on paper, and later recovers the machine from them.
# Local processes on one machine (the VM stand is R3c).
#
# Scenario:      H0..H3 are ordinary authenticated hosts (star around H0). The
#                friend node N (node-04) is set up the way install.sh will call
#                `setup`: mode new, folders and quota, a phrase grid in a pty,
#                Ctrl-C at the check, then the same phrase shown again, one wrong
#                word, the right words. N starts as a container-supervised daemon
#                with only the seed H0, so the node verdict is yellow ("few
#                friends"); connecting H1..H3 turns it green. Its Dashboard URL is
#                printed headless with an `ssh -L` line. Three files are backed up
#                and restorable with symbols on the hosts. Then the machine dies:
#                data dir and sources are deleted, `setup --mode restore` runs
#                from a 0600 phrase file, the daemon comes back with the same
#                identity, and `viaticum restore <folder>/` brings the three files
#                back by sha256. The phrase never appears in a log, config or
#                capture under the run dir (except identity.key).
# Intent:       install-i2, i3, i4, i9, i13, i14
# Proves:       the phrase is shown only in a tty; Ctrl-C leaves identity.key and
#               no phrase-confirmed; a re-run shows the same words and the same
#               identity; the check asks three positions, retries once and then
#               succeeds; phrase-confirmed exists; quota = max(1, floor(0.2 × free))
#               from statvfs of the data dir; folders as given; web API on; init's
#               output still has `Mnemonic (SAVE THIS):`; without a tty new needs
#               --yes and never prints the phrase, restore needs a 0600 phrase file;
#               node yellow with only the seed and green with all hosts; protection
#               never red; `open` prints URL and an ssh tunnel line without DISPLAY;
#               three files restore byte-for-byte after the data dir and sources are
#               gone; no three consecutive phrase words leak.
# Adversarial:  Ctrl-C at the check; one wrong word; no tty with and without --yes;
#               restore without a phrase file; phrase file mode 0644; only the seed
#               reachable; machine lost (data dir and sources deleted).
# Cannot close:  a real service/systemd unit and linger (R3c), reboot, the shell
#               installer and get.sh (R3c), VM disks, a real Raspberry Pi, a human
#               reading the guide (I-8). `open` launching a browser is not asserted
#               (only the printed URL/tunnel); the browser attempt may fail.
# Steps:        1. hosts H0..H3 up; setup --mode new in a pty; Ctrl-C at check
#               2. re-run in a pty: same words/identity, one wrong word, success
#               3. config: quota, watch, web; plain `init` output untouched
#               4. without a tty: refusals and the --yes path; phrase file mode;
#                  half-tty (`setup | tee`): stdin pty, stdout file, no phrase
#               5. all four hosts: green; then H1..H3 stopped: yellow "few
#                  friends"; back to green; protection never red
#               6. `viaticum open` without DISPLAY: URL + ssh -L, exit 0
#               7. files are Queued/Replicating: protection.reason "uploading"
#                  with the i14 wording; then 100% restorable, dr_ready
#               8. lose the machine; setup --mode restore --phrase-file; same
#                  identity; a second restore creates a missing --watch folder;
#                  restore the folder; sha256 of the three files match
#               9. no three consecutive phrase words under the run dir
#
# Usage:
#   cargo build --release -p viaticum --features e2e-tools
#   env -u VIATICUM_SERVER -u VIATICUM_TOKEN BINARY=./target/release/viaticum \
#       bash experiments/local_setup_test.sh

set -euo pipefail

NUM_HOSTS=4
FRIEND=4
TIME_SCALE=1000
E2E_TMP="${VIATICUM_E2E_TMP:-$HOME/e2e-tmp}"; mkdir -p "$E2E_TMP"
TEST_DIR="$E2E_TMP/viaticum-setup-$$"
BINARY="${BINARY:-viaticum}"
PORT_BASE=$(( 23000 + (RANDOM % 300) * 100 ))
PASS=0; FAIL=0
PIDS=()
declare -A NODE_PID
PHASE_DIR="$E2E_TMP/ds2"
PHASE_FILE="$PHASE_DIR/phrase-$$"
mkdir -p "$PHASE_DIR"

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1"; ((FAIL++)) || true; }

cleanup() {
    local rc=$?
    echo ""
    echo "=== Cleanup ==="
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    echo "  Killed ${#PIDS[@]} processes"
    rm -f -- "$PHASE_FILE"
    e2e_cleanup_on_pass "$TEST_DIR" "$rc"
}
trap cleanup EXIT

node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$TEST_DIR/logs/node-$(printf '%02d' "$1").log"; }

run_cli() { local idx="$1"; shift; "$BINARY" --data-dir "$(node_dir "$idx")" "$@"; }
run_cli_q() { run_cli "$@" 2>/dev/null || true; }

wait_daemon() {
    for _ in $(seq 1 120); do
        run_cli_q "$1" status | grep -q "identity:" && return 0
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
    [ -n "$raw" ] || return 0
    echo "$raw" | sed 's|/ip4/0.0.0.0/|/ip4/127.0.0.1/|'
}

write_config() {
    cat > "$(node_dir "$1")/config.toml" << CFGEOF
[web_api]
enabled = true
bind = "127.0.0.1:0"
[storage]
disk_reserve_gb = 0.0
[network]
listen_port = $2
CFGEOF
}

# start_node IDX SCALE [WATCH_DIR]
start_node() {
    local idx="$1" scale="$2" watch="${3:-}" dir
    dir=$(node_dir "$idx")
    mkdir -p "$(dirname "$(node_log "$idx")")"
    local -a cmd=("$BINARY" --data-dir "$dir" daemon --time-scale "$scale")
    [ -n "$watch" ] && cmd+=(--watch-dir "$watch")
    if [ "$idx" = "$FRIEND" ]; then
        env VIATICUM_SUPERVISED=1 VIATICUM_SUPERVISOR=container RUST_LOG=info \
            "${cmd[@]}" >> "$(node_log "$idx")" 2>&1 &
    else
        RUST_LOG=info "${cmd[@]}" >> "$(node_log "$idx")" 2>&1 &
    fi
    NODE_PID[$idx]=$!
    PIDS+=("$!")
}

stop_node() {
    local pid="${NODE_PID[$1]:-}"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$pid" 2>/dev/null || true
    NODE_PID[$1]=""
}

# The level of the friend's server verdict, straight from status --json.
friend_level() {
    run_cli_q "$FRIEND" status --json | jq -r '.verdict.node.level // empty' 2>/dev/null || true
}
friend_protection_level() {
    run_cli_q "$FRIEND" status --json | jq -r '.verdict.protection.level // empty' 2>/dev/null || true
}
friend_network_detail() {
    run_cli_q "$FRIEND" status --json \
        | jq -r '.verdict.node.checks[] | select(.id == "network") | .detail // empty' 2>/dev/null || true
}
friend_protection_reason() {
    run_cli_q "$FRIEND" status --json \
        | jq -r '.verdict.protection.reason // empty' 2>/dev/null || true
}
friend_protection_detail() {
    run_cli_q "$FRIEND" status --json \
        | jq -r '.verdict.protection.detail // empty' 2>/dev/null || true
}

# A phrase red line for PROTECTION: red in any poll is a FAIL, even if the
# scenario later becomes green (install-i14, M17).
protection_poll() {
    local lvl
    lvl=$(friend_protection_level)
    if [ "$lvl" = "red" ]; then
        fail "protection went red (install-i14: it never does in R3)"
        return 1
    fi
    return 0
}

# Wait for a friend verdict level with a deadline; polls protection each time.
wait_level() {
    local want="$1" secs="$2" deadline lvl
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        protection_poll || return 1
        lvl=$(friend_level)
        [ "$lvl" = "$want" ] && return 0
        sleep 10
    done
    echo "    last node level: '$(friend_level)', protection: '$(friend_protection_level)'"
    return 1
}

# Words of a phrase found in a text, in grid order.
grid_phrase() {
    { grep -oE '[0-9]{1,2}\. [a-z]+' <<< "$1" || true; } \
        | sort -n | awk '{print $2}' | paste -sd' ' -
}

# True when no three consecutive words of PHRASE occur in TEXT.
phrase_leaks() {
    local text="$1" words triples i norm
    # Normalize the grid form too: "1. word 2. word" becomes "word word".
    norm=$(sed -E 's/[0-9]{1,2}\.[[:space:]]*//g' <<< "$text" | tr -s '[:space:]' ' ')
    read -r -a words <<< "$PHRASE1"
    for ((i = 0; i + 2 < ${#words[@]}; i++)); do
        triples="${words[i]} ${words[i+1]} ${words[i+2]}"
        if grep -qF -- "$triples" <<< "$norm"; then
            echo "    leaked triple: ${triples}"
            return 0
        fi
    done
    return 1
}

if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "ERROR: viaticum binary not found. Run ./rbuild.sh"; exit 1; }
fi
BINARY="$(realpath "$BINARY")"

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

assert_delete_window "$TIME_SCALE"

echo "============================================================"
echo "  Viaticum setup E2E (${NUM_HOSTS} hosts + 1 friend, ports from $PORT_BASE)"
echo "  Binary: $BINARY"
echo "  Test dir: $TEST_DIR"
echo "============================================================"
mkdir -p "$TEST_DIR/logs"

# ── STEP 1: HOSTS, FIRST SETUP, CTRL-C AT THE CHECK ───────────────────────────
echo ""
echo "=== Step 1: hosts H0..H3; setup --mode new in a pty; Ctrl-C at the check ==="
for i in $(seq 0 $((NUM_HOSTS-1))); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > "$TEST_DIR/logs/init-$i.out" 2>&1
    write_config "$i" $((PORT_BASE + i))
    start_node "$i" "$TIME_SCALE" "$(node_dir "$i")/files"
done
for i in $(seq 0 $((NUM_HOSTS-1))); do
    wait_daemon "$i" || { fail "host H$i did not answer status"; exit 1; }
done
ADDR_00=$(get_addr 0)
[ -n "$ADDR_00" ] || { fail "cannot get H0's address"; exit 1; }
for i in 1 2 3; do run_cli_q "$i" connect "$ADDR_00" > /dev/null; done
if wait_auth_peers 0 3 90; then
    pass "hosts H0..H3 are up and H0 sees 3 authenticated friends"
else
    fail "H0 sees $(status_num 0 peer_count_authenticated)/3 authenticated friends"
    exit 1
fi
declare -A ADDR
for i in 0 1 2 3; do ADDR[$i]=$(get_addr "$i"); done

FRIEND_DIR=$(node_dir "$FRIEND")
WATCH_DIR="$FRIEND_DIR/files"
mkdir -p "$WATCH_DIR"

set +e
OUT1=$(RUST_LOG=info python3 "$(dirname "${BASH_SOURCE[0]}")/setup_pty.py" \
    --binary "$BINARY" --data-dir "$FRIEND_DIR" --watch "$WATCH_DIR" \
    --stop-at-check --timeout 180 --stderr-file "$TEST_DIR/logs/setup-1.err" -- \
    --seed "$ADDR_00" 2>&1)
RC1=$?
set -e
PHRASE1=$(grid_phrase "$OUT1")
PHRASE_CONFIRMED="$FRIEND_DIR/phrase-confirmed"
if [ "$RC1" -eq 130 ] || [ "$RC1" -eq 4 ]; then
    pass "Ctrl-C at the phrase check exits non-zero ($RC1)"
else
    fail "Ctrl-C at the phrase check exited $RC1 (want 130 or 4)"
fi
if [ -f "$FRIEND_DIR/identity.key" ]; then
    pass "identity.key exists after Ctrl-C"
else
    fail "identity.key missing after Ctrl-C"
fi
if [ ! -e "$PHRASE_CONFIRMED" ]; then
    pass "no phrase-confirmed after Ctrl-C"
else
    fail "phrase-confirmed exists after Ctrl-C"
fi
if [ "$(echo "$PHRASE1" | wc -w)" -eq 24 ]; then
    pass "the pty showed 24 words (kept only in this shell)"
else
    fail "the pty transcript yielded $(echo "$PHRASE1" | wc -w) words"
    exit 1
fi
KEY_HASH1=$(sha256sum "$FRIEND_DIR/identity.key" | awk '{print $1}')
KEY_MODE1=$(stat -c %a "$FRIEND_DIR/identity.key")
[ "$KEY_MODE1" = "600" ] && pass "identity.key is mode 0600" || fail "identity.key mode is $KEY_MODE1"

# ── STEP 2: SAME PHRASE, SAME IDENTITY, ONE WRONG WORD ────────────────────────
echo ""
echo "=== Step 2: re-run shows the same phrase; one wrong word; then success ==="
set +e
OUT2=$(RUST_LOG=info python3 "$(dirname "${BASH_SOURCE[0]}")/setup_pty.py" \
    --binary "$BINARY" --data-dir "$FRIEND_DIR" --watch "$WATCH_DIR" \
    --wrong-once --timeout 240 -- \
    --seed "$ADDR_00" --json 2>&1)
RC2=$?
set -e
PHRASE2=$(grid_phrase "$OUT2")
REPORT=$(grep '^{' <<< "$OUT2" | tail -1 || true)
IDENTITY2=$(jq -r '.identity_pub // empty' <<< "${REPORT:-{}}" 2>/dev/null || true)
if [ "$RC2" -eq 0 ]; then
    pass "setup finished after the right words (exit 0)"
else
    fail "setup exited $RC2 after the right words (details hidden: the transcript holds the phrase)"
fi
if grep -q "Word #[0-9]*?" <<< "$OUT2"; then
    pass "the check really asked for words by position (M3)"
else
    fail "the pty transcript has no 'Word #N?' prompt: the check may be skipped (M3)"
fi
if grep -q "does not match" <<< "$OUT2"; then
    pass "the one wrong word was rejected and asked again"
else
    fail "the one wrong word produced no retry"
fi
if [ "$PHRASE1" = "$PHRASE2" ] && [ -n "$PHRASE2" ]; then
    pass "the re-run showed the same 24 words"
else
    fail "the re-run showed different words"
fi
KEY_HASH2=$(sha256sum "$FRIEND_DIR/identity.key" | awk '{print $1}')
if [ "$KEY_HASH1" = "$KEY_HASH2" ]; then
    pass "identity.key is unchanged (same identity_pub, ${IDENTITY2:0:16}…)"
else
    fail "identity.key changed between the interrupted run and the re-run"
fi
if [ ${#IDENTITY2} -eq 64 ]; then
    pass "setup --json reports identity_pub ${IDENTITY2:0:16}…"
else
    fail "setup --json did not report a 64-hex identity_pub ('$IDENTITY2')"
fi
[ -f "$PHRASE_CONFIRMED" ] && pass "phrase-confirmed exists" || fail "phrase-confirmed missing"
[ "$(stat -c %a "$FRIEND_DIR/identity.key")" = "600" ] \
    && pass "identity.key is still mode 0600" || fail "identity.key mode changed"

# ── STEP 3: CONFIG ────────────────────────────────────────────────────────────
echo ""
echo "=== Step 3: quota from statvfs, watch dirs as given, web API on ==="
FREE_GB=$(df -B1 --output=avail "$FRIEND_DIR" | tail -1 | awk '{printf "%.6f", $1/1073741824}')
EXPECTED_QUOTA=$(python3 -c "import math; print(max(1, math.floor(0.2*$FREE_GB)))")
CFG="$FRIEND_DIR/config.toml"
read -r QUOTA_CFG WATCH_CFG WEB_ENABLED <<< "$(python3 - "$CFG" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    d = tomllib.load(f)
watch = ",".join(w.get("path", "") for w in d.get("watch", []))
print(d.get("storage", {}).get("soft_quota_gb", 0), watch, str(d.get("web_api", {}).get("enabled", False)).lower())
PY
)"
QDIFF=$(python3 -c "print(abs(float('$QUOTA_CFG') - float('$EXPECTED_QUOTA')))")
if python3 -c "import sys; sys.exit(0 if $QDIFF <= 1 else 1)"; then
    pass "soft_quota_gb = $QUOTA_CFG (df says ${FREE_GB} GB free → expected ${EXPECTED_QUOTA} ±1)"
else
    fail "soft_quota_gb = $QUOTA_CFG, expected ${EXPECTED_QUOTA} ±1 from df (${FREE_GB} GB free)"
fi
if [ "$WATCH_CFG" = "$WATCH_DIR" ]; then
    pass "watch folder is exactly $WATCH_DIR"
else
    fail "watch folders are '$WATCH_CFG', want '$WATCH_DIR'"
fi
[ "$WEB_ENABLED" = "true" ] && pass "[web_api] enabled = true" || fail "[web_api] is not enabled"

INIT_FRESH="$TEST_DIR/init-check"
INIT_OUT=$("$BINARY" --data-dir "$INIT_FRESH" init 2>&1)
if grep -qF "Mnemonic (SAVE THIS):" <<< "$INIT_OUT"; then
    pass "plain init still prints 'Mnemonic (SAVE THIS):'"
else
    fail "plain init output changed (no 'Mnemonic (SAVE THIS):')"
fi

# ── STEP 4: NO TTY ────────────────────────────────────────────────────────────
echo ""
echo "=== Step 4: without a tty: refusals, --yes, phrase-file mode ==="
NONTTY="$TEST_DIR/nontty-new"
mkdir -p "$NONTTY"
set +e
"$BINARY" --data-dir "$NONTTY" setup --mode new < /dev/null > "$TEST_DIR/logs/nontty-new.out" 2>&1
RC_NOTTY=$?
set -e
if [ "$RC_NOTTY" -ne 0 ] && [ ! -e "$NONTTY/identity.key" ]; then
    pass "setup --mode new without --yes refuses and writes no identity"
else
    fail "setup --mode new without --yes: rc=$RC_NOTTY, identity=$( [ -e "$NONTTY/identity.key" ] && echo yes || echo no )"
fi

rm -f "$PHRASE_CONFIRMED"
set +e
OUT_YES=$("$BINARY" --data-dir "$FRIEND_DIR" setup --mode new --yes < /dev/null 2>&1)
RC_YES=$?
set -e
if [ "$RC_YES" -eq 0 ]; then
    pass "setup --mode new --yes succeeds without a tty"
else
    fail "setup --mode new --yes exited $RC_YES"
fi
if phrase_leaks "$OUT_YES"; then
    fail "setup --yes printed three consecutive phrase words"
else
    pass "setup --yes printed no three consecutive phrase words"
fi
if [ ! -e "$PHRASE_CONFIRMED" ]; then
    pass "without a tty the phrase is not confirmed (M3″)"
else
    fail "without a tty setup wrote phrase-confirmed"
fi
# `phrase check` with stdin answers writes the marker back (install-i2).
read -r -a PHRASE_WORDS <<< "$PHRASE1"
printf '%s\n%s\n%s\n' "${PHRASE_WORDS[0]}" "${PHRASE_WORDS[1]}" "${PHRASE_WORDS[2]}" \
    | "$BINARY" --data-dir "$FRIEND_DIR" phrase check --positions 1,2,3 > "$TEST_DIR/logs/phrase-check.out" 2>&1
if [ -f "$PHRASE_CONFIRMED" ]; then
    pass "phrase check with stdin answers writes phrase-confirmed"
else
    fail "phrase check did not write phrase-confirmed"
fi
# `phrase show` without a tty must refuse and print nothing.
set +e
"$BINARY" --data-dir "$FRIEND_DIR" phrase show \
    > "$TEST_DIR/logs/phrase-show.stdout" 2> "$TEST_DIR/logs/phrase-show.stderr"
RC_SHOW=$?
set -e
if [ "$RC_SHOW" -ne 0 ] && [ ! -s "$TEST_DIR/logs/phrase-show.stdout" ]; then
    pass "phrase show refuses outside a tty and prints nothing on stdout"
else
    fail "phrase show outside a tty: rc=$RC_SHOW, $(wc -c < "$TEST_DIR/logs/phrase-show.stdout") bytes on stdout"
fi

# F1/B1: `setup | tee install.log` — stdin is a pty, stdout is a file. This is
# the leak path the old `&&` vs `||` guard was blind to. It must refuse and put
# zero bytes, hence zero phrase words, into the installer log.
HALF_TTY_DATA="$TEST_DIR/half-tty-new"
HALF_TTY_OUT="$TEST_DIR/logs/half-tty-install.log"
mkdir -p "$HALF_TTY_DATA"
set +e
RUST_LOG=info python3 "$(dirname "${BASH_SOURCE[0]}")/setup_pty.py" \
    --binary "$BINARY" --data-dir "$HALF_TTY_DATA" --stdout-file "$HALF_TTY_OUT" \
    --timeout 30 -- --mode new --watch "$WATCH_DIR" --quota-gb 2 \
    > "$TEST_DIR/logs/half-tty.pty" 2>&1
RC_HALF=$?
set -e
if [ "$RC_HALF" -ne 0 ] && [ ! -e "$HALF_TTY_DATA/identity.key" ]; then
    pass "half-tty (setup | tee) refuses without --yes and writes no identity"
else
    fail "half-tty setup: rc=$RC_HALF, identity=$( [ -e "$HALF_TTY_DATA/identity.key" ] && echo yes || echo no )"
fi
if [ ! -s "$HALF_TTY_OUT" ] && ! phrase_leaks "$(cat "$HALF_TTY_OUT" 2>/dev/null || true)"; then
    pass "the half-tty stdout log is empty (zero phrase words)"
else
    fail "half-tty stdout log has $(wc -c < "$HALF_TTY_OUT") bytes: phrase words reached the installer log"
fi

NONTTY_RESTORE="$TEST_DIR/nontty-restore"
mkdir -p "$NONTTY_RESTORE"
set +e
"$BINARY" --data-dir "$NONTTY_RESTORE" setup --mode restore --seed "$ADDR_00" \
    < /dev/null > "$TEST_DIR/logs/nontty-restore.out" 2>&1
RC_NR=$?
set -e
if [ "$RC_NR" -ne 0 ] && [ ! -e "$NONTTY_RESTORE/identity.key" ]; then
    pass "restore without --phrase-file refuses and writes no identity"
else
    fail "restore without --phrase-file: rc=$RC_NR, identity=$( [ -e "$NONTTY_RESTORE/identity.key" ] && echo yes || echo no )"
fi

phrase_file_unused="$PHASE_DIR/wide-mode-$$"
printf '%s\n' "this is not a phrase and must never be read" > "$phrase_file_unused"
chmod 0644 "$phrase_file_unused"
set +e
"$BINARY" --data-dir "$NONTTY_RESTORE" setup --mode restore \
    --phrase-file "$phrase_file_unused" --seed "$ADDR_00" \
    < /dev/null > "$TEST_DIR/logs/phrase-mode.out" 2>&1
RC_PM=$?
set -e
rm -f -- "$phrase_file_unused"
if [ "$RC_PM" -ne 0 ] && grep -qa "readable by other users" "$TEST_DIR/logs/phrase-mode.out"; then
    pass "a phrase file with mode 0644 is refused"
else
    fail "a phrase file with mode 0644 was not refused (rc=$RC_PM)"
fi

# ── STEP 5: ALL HOSTS; THEN ONLY THE SEED ─────────────────────────────────────
echo ""
echo "=== Step 5: all hosts → green; then H1..H3 stopped → yellow; back to green ==="
# B2: first the good morning state — the friend sees all four hosts and the
# verdict is green. Then H1..H3 are stopped. Their records stay in the friend's
# DB, so a fallback-counting implementation (`.candidates.len()`) would stay
# green; the correct holder pool is the authenticated set (= H0 only) and the
# verdict must return to yellow "few friends".
start_node "$FRIEND" "$TIME_SCALE"
wait_daemon "$FRIEND" || { fail "friend daemon did not answer status"; exit 1; }
wait_auth_peers "$FRIEND" 1 120 || fail "the friend did not authenticate with the seed H0"
for i in 1 2 3; do run_cli_q "$FRIEND" connect "${ADDR[$i]}" > /dev/null; done
wait_auth_peers "$FRIEND" 4 240 || fail "the friend did not authenticate all four hosts"
if wait_level green 240; then
    pass "with all four hosts the node verdict is green"
else
    fail "with all four hosts the node verdict is '$(friend_level)'"
fi
protection_poll && pass "protection was never red while the node became green" || true

# Only the seed reachable now: H1..H3 are stopped, but the friend has met them
# (their PeerRecords remain). This is the ordinary morning after a restart or a
# host outage, and the case that makes the pool fallback visible.
for i in 1 2 3; do stop_node "$i"; done
if wait_level yellow 180; then
    pass "after H1..H3 stop, the node verdict returns to yellow"
else
    fail "after H1..H3 stop, the node verdict is '$(friend_level)' (want yellow)"
fi
NET_DETAIL=$(friend_network_detail)
if grep -qF "few friends online, need ≥ 2" <<< "$NET_DETAIL"; then
    pass "the network check says 'few friends online, need ≥ 2'"
else
    fail "network check text is '$NET_DETAIL'"
fi
# Bar 5 says `status --json`; read it once through the CLI.
CLI_LEVEL=$(run_cli "$FRIEND" status --json | jq -r '.verdict.node.level')
[ "$CLI_LEVEL" = "yellow" ] && pass "viaticum status --json agrees (yellow)" || fail "CLI status level $CLI_LEVEL"
CLI_IDENTITY=$(run_cli "$FRIEND" status --json | jq -r '.node_identity')
[ "$CLI_IDENTITY" = "$IDENTITY2" ] \
    && pass "the running node has identity_pub ${IDENTITY2:0:16}… (same as setup)" \
    || fail "status identity ${CLI_IDENTITY:0:16}… != setup ${IDENTITY2:0:16}…"

# Restore H1..H3 for the green half and the rest of the scenario.
for i in 1 2 3; do
    start_node "$i" "$TIME_SCALE" "$(node_dir "$i")/files"
    wait_daemon "$i" || fail "host H$i did not come back"
    run_cli_q "$i" connect "$ADDR_00" > /dev/null
done
wait_auth_peers 0 3 90 || fail "H0 does not see H1..H3 after the restart"
for i in 1 2 3; do run_cli_q "$FRIEND" connect "${ADDR[$i]}" > /dev/null; done
wait_auth_peers "$FRIEND" 4 240 || fail "the friend did not authenticate all four hosts again"
if wait_level green 240; then
    pass "with H1..H3 back the node verdict is green again"
else
    fail "with H1..H3 back the node verdict is '$(friend_level)'"
fi
protection_poll && pass "protection was never red on the way back to green" || true
[ "$(friend_protection_level)" != "red" ] && pass "protection is '$(friend_protection_level)'" || fail "protection is red"

# ── STEP 6: OPEN WITHOUT A DISPLAY ────────────────────────────────────────────
echo ""
echo "=== Step 6: viaticum open without DISPLAY/WAYLAND_DISPLAY ==="
set +e
OPEN_OUT=$(env -u DISPLAY -u WAYLAND_DISPLAY timeout 30 "$BINARY" --data-dir "$FRIEND_DIR" open 2>&1)
OPEN_RC=$?
set -e
if [ "$OPEN_RC" -eq 0 ]; then
    pass "viaticum open exits 0 without a display"
else
    fail "viaticum open exited $OPEN_RC without a display"
fi
if grep -qE 'Dashboard: http://127\.0\.0\.1:[0-9]+/auth/start\?token=' <<< "$OPEN_OUT"; then
    pass "open printed the Dashboard URL"
else
    fail "open did not print the Dashboard URL: ${OPEN_OUT:0:300}"
fi
if grep -qE 'ssh -L [0-9]+:127\.0\.0\.1:[0-9]+ ' <<< "$OPEN_OUT"; then
    pass "open printed the ssh -L tunnel line"
else
    fail "open did not print the ssh -L line: ${OPEN_OUT:0:300}"
fi
WEB_PORT=$(sed -n 's/^Dashboard: http:\/\/127\.0\.0\.1:\([0-9]*\).*/\1/p' <<< "$OPEN_OUT")
[ -n "$WEB_PORT" ] && pass "the Dashboard URL names port $WEB_PORT" || fail "no web port in open's output"

# ── STEP 7: THREE FILES, RESTORABLE, DR READY ─────────────────────────────────
echo ""
echo "=== Step 7: three files restorable (100%); symbols on hosts; dr_ready ==="
declare -A FILE_HASH FILE_BLOCK FILE_TARGET
FILES=(f1.bin f2.txt f3.dat)
for f in "${FILES[@]}"; do
    p="$WATCH_DIR/$f"
    case "$f" in
        f1.bin) head -c 1048576 /dev/urandom > "$p" ;;
        f2.txt) head -c 8192 /dev/urandom > "$p" ;;
        f3.dat) head -c 262144 /dev/urandom > "$p" ;;
    esac
    FILE_HASH[$f]=$(content_hash "$p")
done
pass "three files written to the watch folder (sha256 kept in this shell)"

# NOTE 1 / i14: while the files are Queued/Replicating the protection reason
# must be "uploading" with the newcomer wording. `holder_pool` is 4 here (all
# hosts are authenticated), so the only way to get there is `blocks_in_flight`
# being wired from the same per-file loop that counts Restorable.
REASON_UPLOADING=0
DEADLINE=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    reason=$(friend_protection_reason)
    if [ "$reason" = "uploading" ]; then
        REASON_UPLOADING=1
        break
    fi
    all_restorable=1
    for f in "${FILES[@]}"; do
        kind=$(file_field "$FRIEND" "$WATCH_DIR/$f" '.effective_status.kind // "none"')
        [ "$kind" = "restorable" ] || all_restorable=0
    done
    [ "$all_restorable" -eq 1 ] && break
    sleep 0.2
done
if [ "$REASON_UPLOADING" -eq 1 ]; then
    pass "protection.reason is 'uploading' while the files are in flight"
    PROT_DETAIL=$(friend_protection_detail)
    if grep -qF "normal for a new node, can take weeks" <<< "$PROT_DETAIL"; then
        pass "the protection reason says this is normal for a new node (i14)"
    else
        fail "protection detail lacks the i14 wording: '$PROT_DETAIL'"
    fi
else
    fail "protection.reason never said 'uploading' while files were Queued/Replicating (last: '$(friend_protection_reason)')"
fi

# Wait for the files to enter the catalog and become restorable FIRST: a fresh
# node with zero files is green by design (0 files after the scan = 100%), so
# polling only the percentage would pass before any backup happened.
FILES_READY=1
for f in "${FILES[@]}"; do
    p="$WATCH_DIR/$f"
    if wait_file_restorable "$FRIEND" "$p" 600; then
        pass "$f is restorable on the owner"
    else
        fail "$f never became restorable (600 s)"
        FILES_READY=0
    fi
done
pct=$(status_num "$FRIEND" verdict.protection.restorable_pct)
[ "$FILES_READY" -eq 1 ] && [ "$pct" = "100" ] \
    && pass "protection.restorable_pct == 100 with 3 files" \
    || fail "protection.restorable_pct is $pct (files ready: $FILES_READY)"

for f in "${FILES[@]}"; do
    p="$WATCH_DIR/$f"
    FILE_BLOCK[$f]=$(file_block_hex "$FRIEND" "$p")
    FILE_TARGET[$f]=$(file_field "$FRIEND" "$p" '.effective_status.target // 0')
done
HOLDERS_OK=1
for f in "${FILES[@]}"; do
    blk="${FILE_BLOCK[$f]}"
    tgt="${FILE_TARGET[$f]}"
    if [ -z "$blk" ] || [ "${tgt:-0}" -le 0 ]; then
        fail "$f has no block/target (block='$blk', target='${tgt:-0}')"
        HOLDERS_OK=0
        continue
    fi
    deadline=$(( $(date +%s) + 120 )); on=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        on=0
        for i in 0 1 2 3; do on=$(( on + $(block_symbols_on "$i" "$blk") )); done
        [ "$on" -ge "$tgt" ] && break
        sleep 2
    done
    if [ "$on" -ge "$tgt" ]; then
        pass "$f: hosts hold $on >= k symbols $tgt (${blk:0:16}…)"
    else
        fail "$f: hosts hold $on < k $tgt symbols (${blk:0:16}…)"
        HOLDERS_OK=0
    fi
done

DR_OK=0
DEADLINE=$(( $(date +%s) + 900 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    protection_poll || break
    if [ "$(status_num "$FRIEND" dr_ready)" = "true" ]; then DR_OK=1; break; fi
    sleep 5
done
[ "$DR_OK" -eq 1 ] && pass "dr_ready is true (recovery by phrase)" \
    || fail "dr_ready stayed false for 900 s"
if [ "$FILES_READY" -eq 1 ] && [ "$(friend_protection_level)" = "green" ]; then
    pass "protection is green with 3 files at 100% (scan_settled true, T10)"
elif [ "$FILES_READY" -eq 1 ]; then
    fail "protection is '$(friend_protection_level)' with 3 files at 100%: scan_settled never became true"
else
    fail "protection green is not proven: the files never became restorable"
fi

# ── STEP 8: MACHINE LOST; RESTORE BY PHRASE ───────────────────────────────────
echo ""
echo "=== Step 8: machine lost; setup --mode restore from a 0600 phrase file ==="
stop_node "$FRIEND"
rm -rf "$FRIEND_DIR"   # data dir, identity.key, db, watch folder and sources
mkdir -p "$WATCH_DIR"
printf '%s\n' "$PHRASE1" > "$PHASE_FILE"
chmod 0600 "$PHASE_FILE"

set +e
RESTORE_SETUP_OUT=$("$BINARY" --data-dir "$FRIEND_DIR" setup --mode restore \
    --phrase-file "$PHASE_FILE" --seed "$ADDR_00" --watch "$WATCH_DIR" \
    --quota-gb 2 --json < /dev/null 2>&1)
RC_RS=$?
set -e
RESTORE_REPORT=$(grep '^{' <<< "$RESTORE_SETUP_OUT" | tail -1 || true)
RESTORED_ID=$(jq -r '.identity_pub // empty' <<< "${RESTORE_REPORT:-{}}" 2>/dev/null || true)
if [ "$RC_RS" -eq 0 ]; then
    pass "setup --mode restore --phrase-file exits 0 on the empty data dir"
else
    fail "setup --mode restore exited $RC_RS"
    tail -40 <<< "$RESTORE_SETUP_OUT" | sed 's/^/    | /'
fi
[ -f "$FRIEND_DIR/phrase-confirmed" ] && pass "restore wrote phrase-confirmed" \
    || fail "restore did not write phrase-confirmed"
if [ "$RESTORED_ID" = "$IDENTITY2" ] && [ -n "$RESTORED_ID" ]; then
    pass "the restored identity is the same (${RESTORED_ID:0:16}…)"
else
    fail "restored identity '$RESTORED_ID' != '$IDENTITY2'"
fi

# F3/W1: on a new machine the watch folder may not exist yet (files come back
# into staging). Restore must create it before DR commits and still exit 0 with
# a usable config; the old order failed with FolderMissing after the identity.
MISSING_DATA="$TEST_DIR/restore-missing-data"
MISSING_WATCH="$TEST_DIR/restore-missing-folder"
mkdir -p "$MISSING_DATA"
set +e
RESTORE_MISS_OUT=$("$BINARY" --data-dir "$MISSING_DATA" setup --mode restore \
    --phrase-file "$PHASE_FILE" --seed "$ADDR_00" --watch "$MISSING_WATCH" \
    --quota-gb 2 --json < /dev/null 2>&1)
RC_RM=$?
set -e
if [ "$RC_RM" -eq 0 ]; then
    pass "restore with a missing --watch folder exits 0"
else
    fail "restore with a missing --watch folder exited $RC_RM"
    tail -40 <<< "$RESTORE_MISS_OUT" | sed 's/^/    | /'
fi
if [ -d "$MISSING_WATCH" ] && [ "$(stat -c %a "$MISSING_WATCH")" = "700" ]; then
    pass "restore created the missing watch folder 0700"
else
    fail "missing watch folder: dir=$( [ -d "$MISSING_WATCH" ] && echo yes || echo no ), mode=$(stat -c %a "$MISSING_WATCH" 2>/dev/null || echo none)"
fi
if python3 - "$MISSING_DATA/config.toml" "$MISSING_WATCH" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
sys.exit(0 if any(w.get("path") == sys.argv[2] for w in cfg.get("watch", [])) else 1)
PY
then
    pass "the restore config lists the folder that did not exist yet"
else
    fail "the restore config does not list $MISSING_WATCH"
fi

rm -f -- "$PHASE_FILE"

start_node "$FRIEND" "$TIME_SCALE"
wait_daemon "$FRIEND" || { fail "restored daemon did not answer status"; exit 1; }
for i in 1 2 3; do run_cli_q "$FRIEND" connect "${ADDR[$i]}" > /dev/null; done
wait_auth_peers "$FRIEND" 3 120 || fail "restored node has $(status_num "$FRIEND" peer_count_authenticated)/3 authenticated hosts"

restore_run "$FRIEND" 900 "$WATCH_DIR/"
if [ "$RESTORE_RC" -eq 0 ]; then
    pass "viaticum restore <folder>/ exits 0"
else
    fail "restore exit $RESTORE_RC (want 0); ${RESTORE_ERR:0:300}"
fi
JOB_JSON="${RESTORE_LAST:-}"
[ -n "$JOB_JSON" ] || JOB_JSON='{}'
OUTCOME=$(jq -r '.outcome // "none"' <<< "$JOB_JSON" 2>/dev/null || echo none)
[ "$OUTCOME" = "complete" ] && pass "restore job outcome is complete" \
    || fail "restore outcome '$OUTCOME'"
STAGING=$(jq -r '.staging_path // empty' <<< "$JOB_JSON" 2>/dev/null || true)
N_RESTORED=$(jq -r '.restored_paths | length' <<< "$JOB_JSON" 2>/dev/null || echo 0)
[ "$N_RESTORED" -eq 3 ] && pass "the job restored all three files" \
    || fail "the job restored $N_RESTORED/3 files"
ALL_HASH_OK=1
for f in "${FILES[@]}"; do
    p="$WATCH_DIR/$f"
    staged="$STAGING/${p#/}"
    if [ ! -f "$staged" ]; then
        fail "$f is missing from staging ($staged)"
        ALL_HASH_OK=0
    elif [ "$(content_hash "$staged")" = "${FILE_HASH[$f]}" ]; then
        pass "$f restored byte-for-byte (${FILE_HASH[$f]:0:16}…)"
    else
        fail "$f sha256 mismatch: want ${FILE_HASH[$f]} got $(content_hash "$staged")"
        ALL_HASH_OK=0
    fi
done
if staging_matches_job "$JOB_JSON"; then
    pass "staging holds exactly the job's restored_paths"
else
    fail "$RESTORE_MSG"
fi

# ── STEP 9: NO PHRASE LEAK ────────────────────────────────────────────────────
echo ""
echo "=== Step 9: no three consecutive phrase words under the run dir ==="
read -r -a PHRASE_WORDS <<< "$PHRASE1"
LEAK_CORPUS="$TEST_DIR/logs/leak-corpus.txt"
: > "$LEAK_CORPUS"
while IFS= read -r -d '' f; do
    sed -E 's/[0-9]{1,2}\.[[:space:]]*//g' "$f" 2>/dev/null >> "$LEAK_CORPUS" || true
    echo >> "$LEAK_CORPUS"
done < <(find "$TEST_DIR" -type f ! -name identity.key ! -path "$LEAK_CORPUS" -print0)
LEAK=""
for ((i = 0; i + 2 < ${#PHRASE_WORDS[@]}; i++)); do
    triple="${PHRASE_WORDS[i]} ${PHRASE_WORDS[i+1]} ${PHRASE_WORDS[i+2]}"
    if tr -s '[:space:]' ' ' < "$LEAK_CORPUS" | grep -qF -- "$triple"; then
        LEAK="$triple"
        break
    fi
done
if [ -z "$LEAK" ]; then
    pass "no three consecutive phrase words in logs, config or files (identity.key excluded)"
else
    fail "phrase leak: $LEAK"
fi
for capture in "$OUT_YES" "$RESTORE_SETUP_OUT" "$OPEN_OUT"; do
    if [ -n "$capture" ] && phrase_leaks "$capture"; then
        fail "phrase leak in a non-tty captured stdout/stderr stream"
    fi
done
pass "non-tty CLI captures hold no three consecutive phrase words"
# Positive control: the scanner really reads the logs (a known daemon line).
if grep -qa "daemon started" "$(node_log 0)" 2>/dev/null; then
    pass "the leak scanner's corpus contains the daemons' logs"
else
    fail "no 'daemon started' line in H0's log: the leak check would be blind"
fi

# ── RESULT ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Results: PASS=$PASS FAIL=$FAIL"
echo "  Steps:"
for f in f1.bin f2.txt f3.dat; do
    echo "    $f sha256=${FILE_HASH[$f]} block=${FILE_BLOCK[$f]:0:16}… k=${FILE_TARGET[$f]}"
done
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
