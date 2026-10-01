#!/bin/bash
# Viaticum discovery at scale (C-DK): 40 friends find each other through one seed.
#
# Scenario:     40 independent owners on one host: seed node-00 (fixed listen port P,
#               relay_role = "punch") + 39 friends whose config names only the seed
#               (kademlia_bootstrap_peers), no `connect` anywhere. Every node advertises AMP
#               loopback aliases (e2e-tools amplifier, default 20) so peer records are large.
#               Converge, place one file each, hold, SIGKILL + restart the seed, a 41st friend
#               joins late, reach known-but-disconnected peers on demand (net-probe reach; a
#               restore from holders with no live connection; a holder turned black hole),
#               and a DR of one friend onto a clean machine (NOTE for line B).
#               MODE=lru24: CAP=24 (model: k=20 < cap), TIME_SCALE=60 — the proof of i42.
#               MODE=lru: CAP=12 (stress: k > cap), TIME_SCALE=60.
#               MODE=hold: CAP=12, TIME_SCALE=1: converge, then 30 min at production cadence.
# Intent:       network-i14, i15, i16 (final v3.2 editions), i17, i18, i19 (probabilistic),
#               i20 (via the i18 path), i41, i42, i43
# Proves:       every node KNOWS >= 20 other owners within 300 s (a PeerRecord with a
#               dialable address), symmetric on the OTHER node, never decreasing; every
#               friend stays under the connection cap (connected - busy - infra - closing,
#               one snapshot); maintenance never re-dials a peer it evicted (origin redial /
#               discovery = 0) and lookups slow down after convergence; a known peer with no
#               connection is reached on demand (seen on THAT peer) and a restore from cold
#               holders succeeds without the no-answer redial (bars in lru24/lru; NOTE in the
#               main run); every friend's file lands on >= 2 holders other than the seed
#               (symbols on THEIR disks); the seed's crash goes unnoticed and the seed rejoins
#               every live friend without `connect`; the late node is known by >= 10 old
#               nodes (on THEIR status); no daemon ever opens a TCP socket (any state) to a
#               non-local address.
# Adversarial:  SIGKILL of the seed; late joiner; node-39 carries the legacy key
#               kademlia_disable_ipfs_bootstrap = false (it switched the IPFS bootstrap on
#               before C-DK C3; now ignored); oversized peer records (amplifier);
#               forced disconnects before an on-demand reach and a restore; a holder that
#               accepts TCP and stays silent (8c); cap 12/24 < 39 peers (lru, lru24, hold).
# Cannot close: NAT / separate hosts (network-i21, R2); DNS seed; > 41 nodes (cap pressure
#               only simulated by CAP); a real IPFS node mixing in (in-process test only);
#               malicious peers; a permanently lost seed; liveness of known peers (known !=
#               online); the placement pool drawn from known peers (в-2); closing cold
#               connections (i40, R2); on-demand reach at TIME_SCALE=1200 (the mailbox poll
#               every 3 s keeps everyone connected: step 8 is a NOTE there, spec v3.2 BL-1).
# Steps:        0. preconditions: >= 12 GiB free, e2e-tools binary + net-probe, alias log
#                  line per node (AMP > 0), connection-cap log line per node (CAP set),
#                  alias 127.0.0.2:P dialable, H1 forecast 51*N_v4 + 63*N_v6 > 775, P free
#                  and < 28000 — else FAIL(setup)
#               1. 40 nodes, no connect -> <= 300 s (hold 600, ROUGH > 120 / 300): every
#                  node known >= 20, seed known = 39; symmetry on the other side (100 % PASS,
#                  >= 95 % ROUGH, else FAIL); every sample: friends connected - busy - infra
#                  - closing <= CAP_eff; seed connected = its authenticated (CAP modes: 39);
#                  H1..H4 signature printed (spec §2.4) (i14, i18, i41) — status, logs
#               2. each friend adds a 64 KB .jpg -> <= 180 s (lru*: 300, ROUGH > 180)
#                  restorable and on >= 2 holders other than the seed (i14) — holder disks
#               3. hold W (13 min; FAST=1: 3; lru*: 10; hold: 30), sample every 30 s (hold
#                  60): known >= 20 and never down; cap invariant; evictable_for_ms <= 11000;
#                  lookup/bootstrap starts after convergence <= ceil(W/T_s)+1 (bar in CAP
#                  modes); re-dial of evicted with origin redial|discovery = 0; main: after
#                  minute 5 every `auto-dial pass` with already_connected >= 16 has dialed=0
#                  (i14, i19, i41, i43)
#               4a. SIGKILL seed 90 s -> friends' known not below the value before, at +30 s
#                  and +90 s (i15); on-demand reach node-03/node-17 -> NOTE (i42)
#               4b. seed restarts, same dir and port -> <= 120 s seed known = 39, auth >= 39,
#                  no connect, first auto-dial pass dialed + already_connected = 39 (i15, i43)
#               5. node-40 joins, adds a file -> <= 180 s (lru*: 300) known >= 20, >= 10 old
#                  non-seed nodes list it in THEIR known_devices, file on >= 2 non-seed
#                  holders (i16)
#               6. whole run: no TCP socket (any state) of any daemon to a non-local address,
#                  0 `outgoing connection error` with an IPFS bootstrap PeerId, node-39 keeps
#                  its legacy key = false — the key must change nothing (i17)
#               8a. 5 pairs (X, Y): cold pair (checked on both sides <= 1 s before), net-probe
#                  reach -> exit 0 <= 15 s, X in authenticated_devices(Y) on Y <= 5 s, X logs
#                  `swarm: on-demand dial peer_id=<Y>`; 0 pairs = FAIL (i42; bar in lru24/lru/
#                  hold, NOTE in main)
#               8b. node-07's holders cold, source deleted at a live daemon, restore -> <= 120
#                  s hash match, 0 `fetch: redialed holders`, >= 1 cold holder sends
#                  RestoreResponse and was dialed on demand (i42; bar in lru24/lru, NOTE main)
#               8c. black-hole holder H (>= 2 of 6 blocks), restore 6 files -> <= 180 s hashes
#                  match; in the restore window on-demand failures to H <= 1 + ceil(T/60),
#                  cached-unreachable lines >= blocks(H) - failures (i42; lru24/lru only)
#               7. NOTE for line B (dr-i63): SIGKILL node-05, DR of its phrase onto a clean
#                  node-42 — postmen asked/answered/pointers, Kademlia candidates, dr_ready
#                  (runs last: it kills node-05, an X of step 8a)
#
# Modes (spec C-DK v3.2 "Варианты"):
#   MODE=main  (default) TIME_SCALE=1200, AMP=20, no CAP (48): steps 0-7, 8a/8b as NOTE.
#   MODE=lru24 CAP=24, TIME_SCALE=60: 0, 1, 2, 3 (10 min), 5, 8a-8c.
#   MODE=lru   CAP=12, TIME_SCALE=60: 0, 1, 2, 3 (10 min), 5, 8a-8c.
#   MODE=hold  CAP=12, TIME_SCALE=1:  0, 1, 3 (30 min), 8a.
#   AMP=0 = the realistic control run. FAST=1 = step 3 of 3 min (debugging only).
#   SEED_NEW_PORT=1 = the seed restarts on P+1 (mutation M7). STEPS="..." overrides the set.
#   BASELINE=1 = a C1 baseline run (M0 / M0+amp on a build BEFORE the C2 fix): only then
#   step 1 prints the W2 stop rule's verdict. Without it W2_VERDICT=n/a — on a fixed build
#   "M0+amp not RED" is the expected result, not "H1 refuted".
#   A build without the connection cap (before C-DK C4) cannot run lru/lru24/hold: step 0
#   FAILs(setup) on the missing `e2e: connection cap N` line.
#
# Usage (on the build server; binary with --features e2e-tools, ./rbuild.sh builds it):
#   bash experiments/local_discovery_test.sh              # main run, ~35 min
#   MODE=lru24 bash experiments/local_discovery_test.sh
# Takes the server: 41 daemons (~5-9 GB RAM). Run it detached under the E2E lock with
# TIMEOUT >= 3600 (the main run is ~35-45 min). C1 baselines M0 / M0+amp (pre-C2 build):
#   BASELINE=1 STEPS="0 1" AMP=0 …   /   BASELINE=1 STEPS="0 1" AMP=20 …
#   -> steps 0, 1, 6 and W2_VERDICT=continue|stop. Any run without BASELINE=1 prints
#   W2_VERDICT=n/a (not a baseline run).
# Exit: 0 pass, 1 fail, 2 FAIL(setup), 3 pass-rough. TEST_DIR defaults to
# ~/viaticum-e2e-runs (not tmpfs); on a non-PASS only logs and configs are kept.

set -euo pipefail

MODE="${MODE:-main}"
case "$MODE" in
    main)  TS_DEF=1200; CAP_DEF="";  HOLD_DEF=780;  SAMPLE_DEF=30; BAR8=0
           STEPS_DEF="0 1 2 3 4a 4b 5 8a 8b 7" ;;
    lru)   TS_DEF=60;   CAP_DEF=12;  HOLD_DEF=600;  SAMPLE_DEF=30; BAR8=1
           STEPS_DEF="0 1 2 3 5 8a 8b 8c" ;;
    lru24) TS_DEF=60;   CAP_DEF=24;  HOLD_DEF=600;  SAMPLE_DEF=30; BAR8=1
           STEPS_DEF="0 1 2 3 5 8a 8b 8c" ;;
    hold)  TS_DEF=1;    CAP_DEF=12;  HOLD_DEF=1800; SAMPLE_DEF=60; BAR8=1
           STEPS_DEF="0 1 3 8a" ;;
    *) echo "unknown MODE=$MODE (main | lru | lru24 | hold)"; exit 2 ;;
esac
FAST="${FAST:-0}"
[ "$FAST" = 1 ] && [ "$MODE" = main ] && HOLD_DEF=180
TIME_SCALE="${TIME_SCALE:-$TS_DEF}"
CAP="${CAP-$CAP_DEF}"
CAP_EFF="${CAP:-48}"
HOLD_SECS="${HOLD_SECS:-$HOLD_DEF}"
SAMPLE_SECS="${SAMPLE_SECS:-$SAMPLE_DEF}"
STEPS=" ${STEPS:-$STEPS_DEF} "
AMP="${AMP:-20}"
SEED_PORT="${SEED_PORT:-27411}"
SEED_NEW_PORT="${SEED_NEW_PORT:-0}"
BASELINE="${BASELINE:-0}"
NUM_FRIENDS=39
SEED=0
LATE=40          # the late joiner (step 5)
DR_NODE=42       # the clean machine of step 7
DR_SOURCE=5      # the friend whose phrase step 7 recovers
IPFS_KEY_NODE=39 # carries the legacy kademlia_disable_ipfs_bootstrap = false (step 6)
# On disk, not /tmp: /tmp on the build server is tmpfs (RAM), and 41 DEBUG logs are large.
TEST_DIR="${TEST_DIR:-$HOME/viaticum-e2e-runs/discovery-$$}"
BINARY="${BINARY:-viaticum}"
KEEP="${KEEP:-0}"
# Our swarm module and libp2p-kad's query failures at DEBUG: the lookup statistics and
# the "Request to peer in query failed" lines are the H1..H4 signatures (spec §2.4).
NODE_LOG_FILTER="${NODE_LOG_FILTER:-info,libp2p_kad::behaviour=debug,viaticum::daemon::network::swarm=debug}"
# IPFS bootstrap PeerIds — the list swarm.rs dialed under `kademlia_disable_ipfs_bootstrap =
# false` until C-DK C3 removed it (network-i17) — step 6. A later build has no way to dial
# them; seeing one is a regression (M2).
IPFS_PEER_IDS=(
    QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa
    QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt
    QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM
    QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64
)

T_BASE=$(date -u +%s)
KNOW_BAR=""; SIGNATURE=""; H1_FORECAST="not computed"
declare -A NODE_PID ALIVE DEV8 PEER_ID DEV_IDX VERDICT DETAIL
PIDS=()
BH_PID=""

# ── Verdicts ────────────────────────────────────────────────────────────────
# One verdict per step, the worst wins: PASS < ROUGH < FAIL. NOTE lines never change it.
CUR="0"
rank_of() { case "$1" in PASS) echo 1 ;; ROUGH) echo 2 ;; FAIL) echo 3 ;; *) echo 0 ;; esac; }
verdict() {
    local s="$1" v="$2" m="$3" cur="${VERDICT[$1]:-}"
    echo "  $v [$s]: $m"
    if [ "$(rank_of "$v")" -gt "$(rank_of "$cur")" ]; then
        VERDICT[$s]="$v"; DETAIL[$s]="$m"
    fi
}
pass() { verdict "$CUR" PASS "$1"; }
rough() { verdict "$CUR" ROUGH "$1"; }
fail() { verdict "$CUR" FAIL "$1"; }
note() { echo "  NOTE [$CUR]: $1"; }
# A step 8 check: a bar in the CAP modes, a NOTE in the main run (spec v3.2 BL-1).
bar8_fail() {
    if [ "$BAR8" = 1 ]; then fail "$1"; else note "(bar only in lru24/lru/hold) RED: $1"; fi
}
bar8_pass() {
    if [ "$BAR8" = 1 ]; then pass "$1"; else note "(bar only in lru24/lru/hold) GREEN: $1"; fi
}
setup_fail() {
    echo "  FAIL(setup) [$CUR]: $1"
    VERDICT[$CUR]="FAIL"; DETAIL[$CUR]="setup: $1"
    if [ "${NODES_STARTED:-0}" = 1 ] && [ "${IN_STEP6:-0}" = 0 ]; then IN_STEP6=1; run_step6; fi
    summary
    exit 2
}
# soft_setup_fail MSG: FAIL(setup) of the current step only; the caller skips the rest of it.
SETUP_FAILED=0
soft_setup_fail() {
    SETUP_FAILED=1
    echo "  FAIL(setup) [$CUR]: $1 — step skipped"
    VERDICT[$CUR]="FAIL"; DETAIL[$CUR]="setup: $1"
}
runs_step() { [[ "$STEPS" == *" $1 "* ]]; }
step() { CUR="$1"; echo ""; echo "=== Step $1: $2 ($(( $(date -u +%s) - T_BASE ))s) ==="; }

summary() {
    echo ""
    echo "============================================================"
    echo "  Discovery test summary (MODE=$MODE TIME_SCALE=$TIME_SCALE CAP=${CAP:-none} AMP=$AMP)"
    echo "============================================================"
    local s worst=PASS
    for s in 0 1 2 3 4a 4b 5 6 8a 8b 8c 7; do
        [ -n "${VERDICT[$s]:-}" ] || continue
        printf '  STEP %-3s %-5s %s\n' "$s" "${VERDICT[$s]}" "${DETAIL[$s]:0:160}"
        [ "$(rank_of "${VERDICT[$s]}")" -gt "$(rank_of "$worst")" ] && worst="${VERDICT[$s]}"
    done
    [ -n "${W2_VERDICT:-}" ] && echo "  W2_VERDICT=$W2_VERDICT"
    echo "  RESULT: $worst"
    RESULT="$worst"
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    [ -n "$BH_PID" ] && kill "$BH_PID" 2>/dev/null || true
    local pid
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    echo "  Killed ${#PIDS[@]} daemon processes"
    local d
    if [ "${OWN_TEST_DIR:-0}" != 1 ]; then
        echo "  Test dir not created by this run, left untouched: ${TEST_DIR:-}"
    elif [ "$KEEP" = 1 ]; then
        echo "  KEEP=1: test dir kept whole: $TEST_DIR"
    elif [ "${RESULT:-FAIL}" = "PASS" ]; then
        rm -rf "${TEST_DIR:?}"; echo "  PASS: removed $TEST_DIR"
    else
        # Keep what a verdict is read from (daemon logs, configs, init/DR output); drop
        # the databases, holdings and watched files (41 nodes).
        for d in "${TEST_DIR:?}"/node-*; do
            [ -d "$d" ] || continue
            find "$d" -mindepth 1 -maxdepth 1 ! -name daemon.log ! -name config.toml -exec rm -rf {} + 2>/dev/null || true
        done
        echo "  Logs kept (data removed; KEEP=1 keeps everything): $TEST_DIR"
    fi
}
trap cleanup EXIT

# ── Node plumbing ───────────────────────────────────────────────────────────
node_dir() { echo "$TEST_DIR/node-$(printf '%02d' "$1")"; }
node_log() { echo "$(node_dir "$1")/daemon.log"; }
run_cli() { local idx="$1"; shift; "$BINARY" --data-dir "$(node_dir "$idx")" "$@"; }

# write_config IDX PORT BOOTSTRAP_ADDR EXTRA_NETWORK_LINES
write_config() {
    local idx="$1" port="$2" boot="$3" extra="${4:-}"
    {
        echo '[web_api]'
        echo 'enabled = true'
        echo 'bind = "127.0.0.1:0"'
        echo '[storage]'
        echo 'disk_reserve_gb = 0.0'
        echo '[network]'
        echo "listen_port = $port"
        if [ -n "$boot" ]; then echo "kademlia_bootstrap_peers = [\"$boot\"]"; fi
        if [ -n "$extra" ]; then echo "$extra"; fi
    } > "$(node_dir "$idx")/config.toml"
}

start_daemon() {
    local idx="$1"
    mkdir -p "$(node_dir "$idx")/files"
    local envs=(RUST_LOG="$NODE_LOG_FILTER" VIATICUM_E2E_LOOPBACK_ALIASES="$AMP")
    [ -n "$CAP" ] && envs+=(VIATICUM_E2E_CONN_CAP="$CAP")
    env "${envs[@]}" "$BINARY" --data-dir "$(node_dir "$idx")" daemon \
        --time-scale "$TIME_SCALE" --watch-dir "$(node_dir "$idx")/files" \
        >> "$(node_log "$idx")" 2>&1 &
    NODE_PID[$idx]=$!
    PIDS+=("$!")
    ALIVE[$idx]=1
}

kill_node() { # SIGKILL, the node is gone for good (or until start_daemon)
    local pid="${NODE_PID[$1]:-}"
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
    ALIVE[$1]=0
}

# wait_api IDX SECS: the web API answers /api/status.
wait_api() {
    local i
    for i in $(seq 1 $(( $2 * 2 ))); do
        [ -n "$(api_get "$1" /api/status)" ] && return 0
        sleep 0.5
    done
    return 1
}

# learn_identity IDX: DEV8[IDX] (status device_id) and PEER_ID[IDX] (from node_addr /p2p/).
learn_identity() {
    local js addr i
    for i in $(seq 1 40); do
        js=$(api_get "$1" /api/status)
        addr=$(echo "$js" | jq -r '.node_addr // ""' 2>/dev/null || true)
        if [[ "$addr" == */p2p/* ]] && [[ "$addr" == /ip* ]]; then
            DEV8[$1]=$(echo "$js" | jq -r '.device_id')
            PEER_ID[$1]="${addr##*/p2p/}"
            DEV_IDX[${DEV8[$1]}]=$1
            return 0
        fi
        sleep 0.5
    done
    return 1
}

alive_nodes() { local i; for i in "${!ALIVE[@]}"; do [ "${ALIVE[$i]}" = 1 ] && echo "$i"; done | sort -n; }
alive_friends() { alive_nodes | awk -v s="$SEED" '$1 != s'; }
plain_log_since() { tail -n +$(( $2 + 1 )) "$(node_log "$1")" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true; }
# log_has_since IDX LINE0 TEXT1 TEXT2 : a line of node IDX after LINE0 contains both fixed
# strings. Counts instead of `grep -q`: an early grep exit under pipefail reads as a miss.
log_has_since() {
    local n
    n=$(plain_log_since "$1" "$2" | grep -aF -- "$3" | grep -acF -- "$4" || true)
    [ "${n:-0}" -gt 0 ]
}

# ── One status sample of every live node ────────────────────────────────────
# Fills K (known), A (authenticated), C (connected), BUSY/INFRA/CLOSING ("NA" when the
# build has no such field), KD/AD (",hex8,hex8," lists), HAS_KNOWN (Y/N).
declare -A K A C BUSY INFRA CLOSING KD AD HAS_KNOWN WAKES
FIELDS_NOTED=0
sample_all() {
    local i js row
    for i in $(alive_nodes); do
        js=$(api_get "$i" /api/status)
        if [ -z "$js" ]; then K[$i]=""; continue; fi
        row=$(echo "$js" | jq -r '[
            (if has("peer_count_known") then .peer_count_known else "NA" end),
            .peer_count_authenticated, .peer_count_connected,
            (if has("busy_peers") then .busy_peers else "NA" end),
            (if has("infra_peers") then .infra_peers else "NA" end),
            (if has("closing_peers") then .closing_peers else "NA" end),
            ("," + ((.known_devices // []) | join(",")) + ","),
            ("," + ((.authenticated_devices // []) | join(",")) + ","),
            (if has("known_devices") then "Y" else "N" end),
            (if has("work_wakes_suppressed") then .work_wakes_suppressed else "NA" end)
          ] | @tsv' 2>/dev/null || true)
        IFS=$'\t' read -r "K[$i]" "A[$i]" "C[$i]" "BUSY[$i]" "INFRA[$i]" "CLOSING[$i]" "KD[$i]" "AD[$i]" \
            "HAS_KNOWN[$i]" "WAKES[$i]" <<< "$row"
    done
}

# Friends' cap invariant on the current sample: connected - busy - infra - closing <= CAP_eff
# (spec v3.2 WR-1). A build without those fields counts them as 0 — stricter, never greener.
CAP_VIOLATIONS=""
check_cap_sample() {
    local i inv b f c
    for i in $(alive_friends); do
        [ -n "${K[$i]:-}" ] || continue
        b="${BUSY[$i]:-NA}"; f="${INFRA[$i]:-NA}"; c="${CLOSING[$i]:-NA}"
        if [ "$FIELDS_NOTED" = 0 ] && { [ "$b" = NA ] || [ "$f" = NA ] || [ "$c" = NA ]; }; then
            note "status has no busy_peers/infra_peers/closing_peers (build before C4): the cap invariant uses peer_count_connected alone (stricter)"
            FIELDS_NOTED=1
        fi
        [ "$b" = NA ] && b=0; [ "$f" = NA ] && f=0; [ "$c" = NA ] && c=0
        inv=$(( ${C[$i]:-0} - b - f - c ))
        if [ "$inv" -gt "$CAP_EFF" ]; then
            CAP_VIOLATIONS="$CAP_VIOLATIONS node-$i:$inv@$(( $(date -u +%s) - T_BASE ))s"
        fi
    done
}

# Step 6 on every sample: non-local sockets of every live daemon (any TCP state).
NONLOCAL_HITS=""
MAX_DUP_SOCKETS=0
check_sockets_sample() {
    local snap i pid hits est dup
    snap=$(ss_snapshot)
    for i in $(alive_nodes); do
        pid="${NODE_PID[$i]:-}"; [ -n "$pid" ] || continue
        hits=$(nonlocal_sockets_of_pid "$pid" "$snap")
        [ -n "$hits" ] && NONLOCAL_HITS="$NONLOCAL_HITS
node-$i @$(( $(date -u +%s) - T_BASE ))s: $(echo "$hits" | head -3 | tr '\n' ';')"
        est=$(established_sockets_of_pid "$pid" "$snap")
        dup=$(( est - ${C[$i]:-0} ))
        [ "$dup" -gt "$MAX_DUP_SOCKETS" ] && MAX_DUP_SOCKETS=$dup
    done
    return 0
}

# ── H1..H4 signature of step 1 (spec §2.4) and the W2 stop rule (Part 0) ─────
# KNOW_BAR (GREEN|RED) = the step 1 knowledge bar alone (every node knows >= 20, the
# seed 39), set before this runs: the signature explains THAT bar, not the step's
# composite verdict (symmetry, cap, seed links are separate checks).
print_lookup_signature() {
    local i f n ex=0 ex_nodes=0 eof=0 warn=0 rt_list="" h3 sample=""
    local stats_file="$TEST_DIR/lookup_stats.txt"
    : > "$stats_file"
    for i in $(alive_friends); do
        f=$(node_log "$i")
        # Only kad query failures on the 16 KiB frame: identify (4096b), relay and dcutr
        # report the same codec phrase with their own limits.
        n=$(grep -a "Request to peer in query failed" "$f" 2>/dev/null \
            | grep -acF "exceeds maximum of 16384b" || true)
        ex=$((ex + ${n:-0})); [ "${n:-0}" -gt 0 ] && ex_nodes=$((ex_nodes + 1))
        if [ -z "$sample" ] && [ "${n:-0}" -gt 0 ]; then
            sample=$(grep -a "Request to peer in query failed" "$f" | grep -a -m1 -F "exceeds maximum of 16384b" \
                | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-240 || true)
        fi
        # H3 seen from the asking side: a kad request cut off (UnexpectedEof) — spec §2.4.
        n=$(grep -a "Request to peer in query failed" "$f" 2>/dev/null | grep -ac "UnexpectedEof" || true)
        eof=$((eof + ${n:-0}))
        n=$(grep -ac "kademlia lookup found no peers" "$f" 2>/dev/null || true); warn=$((warn + ${n:-0}))
        events_grep "$f" "dht: get_closest_peers complete" count requests successes failures duration_ms \
            | awk '{ print $3, $4, $5, $6, $7 }' >> "$stats_file"
        n=$(sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -a "kademlia routing table updated" \
            | grep -oE 'peer_id=[A-Za-z0-9]+' | sort -u | wc -l || true)
        rt_list="$rt_list ${n:-0}"
    done
    h3=$(grep -ac "exceeds inbound substream limit" "$(node_log "$SEED")" 2>/dev/null || true)
    local rt_med
    rt_med=$(echo "$rt_list" | tr ' ' '\n' | grep -v '^$' | sort -n \
        | awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)]; else print 0 }' || true)
    # stats lines: count requests successes failures duration_ms ("-" = no such field)
    local summary_line med
    summary_line=$(awk '
        $2 == "-" { nostats++; next }
        { total++; if ($1 + 0 == 0) { empty++; if ($3 + 0 == 0 && $4 + 0 >= 1) s0f1++; if ($2 + 0 == 0) r0++ } }
        END { printf "%d %d %d %d %d\n", total, empty, s0f1, r0, nostats }' "$stats_file" 2>/dev/null \
        || echo "0 0 0 0 0")
    # Median duration of the FAILED empty lookups only (successes=0, failures>=1): a
    # lookup that never started (requests=0, 0 ms) says nothing about H1 vs H2.
    med=$(awk '$2 != "-" && $1 + 0 == 0 && $3 + 0 == 0 && $4 + 0 >= 1 { print $5 + 0 }' "$stats_file" 2>/dev/null \
        | sort -n | awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)]; else print -1 }' || true)
    local total empty s0f1 r0 nostats
    read -r total empty s0f1 r0 nostats <<< "$summary_line"
    note "lookups (friends): total=$total empty=$empty (successes=0,failures>=1: $s0f1; requests=0: $r0); median duration of the failed empty ones=${med}ms; lines without statistics=$nostats"
    note "kad 'Request to peer in query failed … exceeds maximum of 16384b': $ex on $ex_nodes friends${sample:+ — e.g. $sample}"
    note "WARN 'kademlia lookup found no peers': $warn; seed hit the inbound substream limit ${h3:-0} times; friends' kad requests cut off (UnexpectedEof): $eof; distinct peers in 'routing table updated' per friend (median): $rt_med"
    [ "$total" -gt 0 ] || setup_fail "no lookup statistics ('dht: get_closest_peers complete' with requests=) in any friend's log: DEBUG filter or a build without Р-7"
    # H1 condition by condition, so a miss says which one failed.
    local h1_fail=""
    [ "$KNOW_BAR" = RED ] || h1_fail="$h1_fail knowledge-bar-green"
    [ $(( empty * 2 )) -ge "$total" ] || h1_fail="$h1_fail empty<50%(${empty}/${total})"
    [ $(( s0f1 * 2 )) -ge "$empty" ] || h1_fail="$h1_fail s0f1<50%-of-empty(${s0f1}/${empty})"
    [ "$ex" -gt 0 ] || h1_fail="$h1_fail no-16384b-query-failures"
    { [ "$med" -ge 0 ] && [ "$med" -lt 1000 ]; } || h1_fail="$h1_fail median-duration=${med}ms"
    [ "$rt_med" -le 2 ] || h1_fail="$h1_fail routing-table-peers-median=$rt_med>2"
    # Each hypothesis on its own evidence; a mix is reported as a mix.
    local hs=()
    if [ "$KNOW_BAR" = GREEN ]; then
        SIGNATURE="none (knowledge bar green)"
    elif [ $(( empty * 2 )) -lt "$total" ]; then
        SIGNATURE="unclassified (most lookups found peers, yet the knowledge bar is red; H1 fails:$h1_fail)"
    else
        [ -z "$h1_fail" ] && hs+=(H1)
        if [ $(( s0f1 * 2 )) -ge "$empty" ] && [ "$med" -ge 9000 ]; then hs+=(H2); fi
        # H3 needs the asking side too (cut-off requests, short lookups), not only the
        # seed's WARN: otherwise it is a NOTE (printed above), not part of the signature.
        if [ "${h3:-0}" -gt 0 ] && [ "$eof" -gt 0 ] && [ "$med" -ge 0 ] && [ "$med" -lt 1000 ]; then hs+=(H3); fi
        if [ $(( r0 * 2 )) -ge "$empty" ]; then hs+=(H4); fi
        case "${#hs[@]}" in
            0) SIGNATURE="unclassified (H1 fails:$h1_fail)" ;;
            1) SIGNATURE="${hs[0]}" ;;
            *) SIGNATURE="mixed($(IFS=+; echo "${hs[*]}"))" ;;
        esac
    fi
    [ -n "$h1_fail" ] && [ "$KNOW_BAR" = RED ] && note "H1 conditions not met:$h1_fail"
    echo "  STEP1_KNOWLEDGE_BAR=$KNOW_BAR"
    echo "  STEP1_SIGNATURE=$SIGNATURE"
}

# W2 (spec Part 0, "Правило остановки после C1"), meaningful ONLY on the C1 baseline runs
# (BASELINE=1, a build before the C2 fix): stop if (a) M0 (AMP=0) is RED on the knowledge
# bar with a signature other than H1, or (b) M0+amp (AMP>0) is not RED with H1. A mixed
# signature is not H1: the mechanism is ambiguous, the architect decides. On a fixed build
# M0+amp is GREEN by design, so the rule would read "H1 refuted" falsely: n/a there.
W2_VERDICT=""
print_w2_verdict() {
    local v
    if [ "$BASELINE" != 1 ]; then
        v="n/a (not a baseline run)"
    elif [ "$AMP" -eq 0 ]; then
        if [ "$KNOW_BAR" = RED ] && [ "$SIGNATURE" != H1 ]; then
            v="stop (M0 RED with signature $SIGNATURE, not H1)"
        elif [ "$KNOW_BAR" = RED ]; then
            v="continue (M0 RED with H1; forecast: $H1_FORECAST)"
        elif [[ "$H1_FORECAST" == overflow* ]]; then
            v="continue (M0 GREEN although the forecast was overflow — a finding to record)"
        else
            v="continue (M0 GREEN, forecast no overflow)"
        fi
    else
        if [ "$KNOW_BAR" = RED ] && [ "$SIGNATURE" = H1 ]; then
            v="continue (M0+amp RED with H1)"
        else
            v="stop (M0+amp: knowledge bar $KNOW_BAR, signature $SIGNATURE — H1 refuted as the mechanism)"
        fi
    fi
    W2_VERDICT="$v"
    echo "  W2_VERDICT=$v"
}

# ── Step 6 (the whole run): no foreign sockets, no IPFS ─────────────────────
# Evaluated before steps 8a-8c (so a stop there cannot lose it), again at the end, and
# from setup_fail once the nodes run. The verdict keeps the worst of all evaluations.
STEP6_RUNS=0
run_step6() {
    local i f n m p save="$CUR"
    STEP6_RUNS=$((STEP6_RUNS + 1))
    step 6 "the whole run so far (evaluation $STEP6_RUNS): no socket to a non-local address, no IPFS bootstrap"
    sample_all; check_sockets_sample
    if [ -z "$NONLOCAL_HITS" ]; then
        pass "no daemon held a TCP socket (any state) to a non-local address on any sample"
    else
        fail "sockets to non-local addresses:$(echo "$NONLOCAL_HITS" | head -8 | tr '\n' ' ' | cut -c1-500)"
    fi
    local ipfs_err=""
    for i in $(seq 0 $LATE); do
        f=$(node_log "$i"); [ -f "$f" ] || continue
        n=0
        for p in "${IPFS_PEER_IDS[@]}"; do
            m=$(grep -a "outgoing connection error" "$f" | grep -acF "$p" || true); n=$((n + m))
        done
        if [ "$n" -gt 0 ]; then ipfs_err="$ipfs_err node-$i:$n"; fi
    done
    if [ -z "$ipfs_err" ]; then
        pass "0 'outgoing connection error' lines with an IPFS bootstrap PeerId"
    else
        fail "dials to IPFS bootstrap nodes:$ipfs_err"
    fi
    if grep -q '^kademlia_disable_ipfs_bootstrap = false' "$(node_dir $IPFS_KEY_NODE)/config.toml"; then
        pass "node-$IPFS_KEY_NODE still carries the legacy kademlia_disable_ipfs_bootstrap = false"
    else
        fail "node-$IPFS_KEY_NODE config lost the key"
    fi
    CUR="$save"
}

# ── Pairs for on-demand reach (steps 4a, 8a) ────────────────────────────────
declare -A XRANK
xor_ranks_load() { # over the nodes that have a PeerId now
    local ids=() idx=() i a b r
    XRANK=()
    for i in $(printf '%s\n' "${!PEER_ID[@]}" | sort -n); do ids+=("${PEER_ID[$i]}"); idx+=("$i"); done
    while read -r a b r; do XRANK["${idx[$a]}:${idx[$b]}"]=$r; done < <(xor_rank_table "${ids[@]}")
}
outside_xor20() { [ "${XRANK[$1:$2]:-0}" -gt 20 ] && [ "${XRANK[$2:$1]:-0}" -gt 20 ]; }
in_list() { [[ "$2" == *",$1,"* ]]; }

# cold X Y: neither lists the other as authenticated (read on both, now). A node that
# does not answer, or a status without the field, is NOT cold: unknown is not proof.
cold() {
    local ax ay
    ax=$(authenticated_devices_of "$1") || return 1
    ay=$(authenticated_devices_of "$2") || return 1
    ax=",$(echo "$ax" | tr '\n' ','),"; ay=",$(echo "$ay" | tr '\n' ','),"
    ! in_list "${DEV8[$2]}" "$ax" && ! in_list "${DEV8[$1]}" "$ay"
}

# make_cold X Y: net-probe disconnect Y on X until cold on both sides (<= 10 s each), at
# most 3 tries. Returns 1 when the pair stays warm (kad reconnected it).
make_cold() {
    local x="$1" y="$2" try t
    for try in 1 2 3; do
        cold "$x" "$y" && return 0
        "$NET_PROBE" --data-dir "$(node_dir "$x")" disconnect "${DEV8[$y]}" > /dev/null 2>&1 || true
        for t in $(seq 1 20); do cold "$x" "$y" && return 0; sleep 0.5; done
    done
    return 1
}

# reach_pair X Y: the step 8a / 4a protocol. Sets PAIR_MSG; returns 0 (reached), 1 (RED),
# 2 (pair dropped: stayed warm).
reach_pair() {
    local x="$1" y="$2" try line0 t0 rc out el got
    PAIR_MSG=""
    for try in 1 2 3; do
        make_cold "$x" "$y" || { PAIR_MSG="node-$x/node-$y stayed connected after 3 disconnects"; return 2; }
        cold "$x" "$y" && break   # the cold check right before reach (<= 1 s)
        [ "$try" = 3 ] && { PAIR_MSG="node-$x/node-$y re-connected before reach 3 times"; return 2; }
    done
    line0=$(log_line_count "$x")
    t0=$(date +%s%N)
    out=$(timeout 20 "$NET_PROBE" --data-dir "$(node_dir "$x")" reach "${DEV8[$y]}" 2>&1) && rc=0 || rc=$?
    el=$(( ( $(date +%s%N) - t0 ) / 1000000 ))
    if [ "$rc" -ne 0 ] || [ "$el" -gt 15000 ]; then
        PAIR_MSG="node-$x -> node-$y: net-probe reach exit $rc after ${el}ms: ${out:0:200}"
        return 1
    fi
    got=0
    for t in $(seq 1 10); do
        in_list "${DEV8[$x]}" ",$(authenticated_devices_of "$y" | tr '\n' ',')" && { got=1; break; }
        sleep 0.5
    done
    if [ "$got" != 1 ]; then
        PAIR_MSG="node-$x -> node-$y reached in ${el}ms, but node-$y does not list node-$x as authenticated within 5 s"
        return 1
    fi
    if ! log_has_since "$x" "$line0" "swarm: on-demand dial" "peer_id=${PEER_ID[$y]}"; then
        PAIR_MSG="node-$x -> node-$y reached in ${el}ms without a 'swarm: on-demand dial peer_id=${PEER_ID[$y]}' line (kad reconnected it?)"
        return 1
    fi
    PAIR_MSG="node-$x -> node-$y reached on demand in ${el}ms, seen on node-$y"
    return 0
}

# pick_target X: a known, live, non-seed peer of X (seeded random), outside XOR-20 of X
# when there is one; in CAP modes a naturally cold one first. Empty when X knows nobody.
pick_target() {
    local x="$1" kd cands=() far=() cold_far=() h j
    kd=$(known_devices_of "$x" || true)
    for h in $kd; do
        j="${DEV_IDX[$h]:-}"
        [ -n "$j" ] && [ "$j" != "$SEED" ] && [ "$j" != "$x" ] && [ "${ALIVE[$j]:-0}" = 1 ] || continue
        cands+=("$j")
        outside_xor20 "$x" "$j" && far+=("$j")
    done
    [ "${#cands[@]}" -gt 0 ] || return 0
    [ "${#far[@]}" -gt 0 ] || far=("${cands[@]}")
    if [ "$BAR8" = 1 ]; then
        for j in "${far[@]}"; do cold "$x" "$j" && cold_far+=("$j"); done
        [ "${#cold_far[@]}" -gt 0 ] && far=("${cold_far[@]}")
    fi
    # Fixed choice per X (RANDOM is re-seeded in the $(...) subshell of the caller).
    echo "${far[$(( (x * 2654435761 + PAIR_SEED) % ${#far[@]} ))]}"
}

# ── Binaries ────────────────────────────────────────────────────────────────
if ! command -v "$BINARY" &>/dev/null; then
    BINARY="./target/release/viaticum"
    [ -x "$BINARY" ] || { echo "FAIL(setup): viaticum binary not found (./rbuild.sh)"; exit 2; }
fi
NET_PROBE="$(cd "$(dirname "$(command -v "$BINARY")")" && pwd)/net-probe"

# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

PAIR_SEED=4242   # fixed seed: the same pairs every run

echo "============================================================"
echo "  Viaticum discovery test: MODE=$MODE TIME_SCALE=$TIME_SCALE CAP=${CAP:-none (48)} AMP=$AMP"
echo "  steps:$STEPS  hold ${HOLD_SECS}s, sample every ${SAMPLE_SECS}s"
echo "  Binary: $BINARY   Test dir: $TEST_DIR"
echo "============================================================"
# Never a directory this run did not create: guard the path, refuse an existing one.
case "${TEST_DIR:-}" in
    "" | / | "$HOME" | "$HOME/") echo "FAIL(setup): unsafe TEST_DIR='${TEST_DIR:-}'"; exit 2 ;;
esac
if [ -e "${TEST_DIR:?}" ]; then
    echo "FAIL(setup): TEST_DIR $TEST_DIR already exists; this run removes only a directory it created"
    exit 2
fi
mkdir -p "${TEST_DIR:?}/logs"
OWN_TEST_DIR=1

# ── STEP 0: PRECONDITIONS ───────────────────────────────────────────────────
step 0 "preconditions"
FREE_G=$(df -BG --output=avail "$TEST_DIR" | tail -1 | tr -dc '0-9')
[ "${FREE_G:-0}" -ge 12 ] || setup_fail "free disk ${FREE_G}G < 12G under $TEST_DIR"
[ -x "$NET_PROBE" ] || setup_fail "$NET_PROBE missing: build with --features e2e-tools (./rbuild.sh)"
command -v python3 >/dev/null || setup_fail "python3 missing (XOR ranks, black-hole listener)"
[ "$SEED_PORT" -lt 28000 ] || setup_fail "seed port $SEED_PORT >= 28000"
if [ -n "$(ss -ltn "( sport = :$SEED_PORT )" 2>/dev/null | tail -n +2)" ]; then
    setup_fail "seed port $SEED_PORT is taken"
fi
N_V4=$(ip -o -4 addr show 2>/dev/null | wc -l)
N_V6=$(ip -o -6 addr show 2>/dev/null | wc -l)
H1_LOAD=$(( 51 * N_V4 + 63 * N_V6 ))
if [ "$AMP" -gt 0 ]; then
    H1_FORECAST="overflow (amplifier: $AMP aliases ~ $(( 51 * AMP + 44 )) B per peer > 819 B)"
elif [ "$H1_LOAD" -gt 775 ]; then
    H1_FORECAST="overflow (51*$N_V4 + 63*$N_V6 = $H1_LOAD > 775)"
else
    H1_FORECAST="no overflow (51*$N_V4 + 63*$N_V6 = $H1_LOAD <= 775)"
fi
note "H1 forecast (answer of 20 peers > 16 KiB): $H1_FORECAST"
note "MemAvailable: $(awk '/MemAvailable/ { printf "%.1f GiB", $2 / 1048576 }' /proc/meminfo) (A10: 41 daemons ~ 5-9 GB)"

# ── STEP 1: 40 NODES, SEED ONLY IN CONFIG ───────────────────────────────────
step 1 "40 owners, only the seed in config, no connect"
for i in $(seq 0 $NUM_FRIENDS); do
    mkdir -p "$(node_dir "$i")"
    run_cli "$i" init > "$TEST_DIR/logs/init-$i.out" 2>&1 || setup_fail "init node-$i: $(tail -2 "$TEST_DIR/logs/init-$i.out")"
done
M_DR_SOURCE=$(grep -A1 "^Mnemonic" "$TEST_DIR/logs/init-$DR_SOURCE.out" | tail -1 | sed 's/^ *//' || true)
[ "$(echo "$M_DR_SOURCE" | wc -w)" -eq 24 ] || setup_fail "node-$DR_SOURCE init printed no 24-word phrase"
# Seed: fixed port, the infrastructure role of spec v3.2 (ignored by builds before C4).
write_config "$SEED" "$SEED_PORT" "" 'relay_role = "punch"'
start_daemon "$SEED"
wait_api "$SEED" 60 || setup_fail "seed daemon does not answer"
learn_identity "$SEED" || setup_fail "seed has no listen address"
SEED_ADDR="/ip4/127.0.0.1/tcp/$SEED_PORT/p2p/${PEER_ID[$SEED]}"
echo "  seed: $SEED_ADDR (device ${DEV8[$SEED]})"
for i in $(seq 1 $NUM_FRIENDS); do
    extra=""
    [ "$i" = "$IPFS_KEY_NODE" ] && extra="kademlia_disable_ipfs_bootstrap = false"
    write_config "$i" 0 "$SEED_ADDR" "$extra"
done
T1=$(date -u +%s)
NODES_STARTED=1
for i in $(seq 1 $NUM_FRIENDS); do start_daemon "$i"; done
for i in $(seq 1 $NUM_FRIENDS); do
    wait_api "$i" 60 || setup_fail "node-$i daemon does not answer"
    learn_identity "$i" || setup_fail "node-$i has no listen address"
done

# Step 0, second half: what only a running daemon can show.
CUR=0
if [ "$AMP" -gt 0 ]; then
    MISSING=""
    for i in $(seq 0 $NUM_FRIENDS); do
        grep -aq "e2e: advertising $AMP loopback aliases" "$(node_log "$i")" || MISSING="$MISSING $i"
    done
    [ -z "$MISSING" ] || setup_fail "no 'e2e: advertising $AMP loopback aliases' on nodes:$MISSING (binary without e2e-tools?)"
    # A11: the advertised alias really reaches the node. The port is the one the node
    # logged (`listen=` of its IPv4 listener): friends listen on ephemeral ports, and
    # their v6 listener has another port — an alias of that one would be dead.
    DEAD=""
    for i in "$SEED" 1 20 "$NUM_FRIENDS"; do
        APORT=$(sed 's/\x1b\[[0-9;]*m//g' "$(node_log "$i")" | grep -a "e2e: advertising $AMP loopback aliases" \
            | head -1 | grep -oE 'listen=/ip4/[^ ]*/tcp/[0-9]+' | grep -oE '[0-9]+$' || true)
        if [ -z "$APORT" ]; then DEAD="$DEAD node-$i:no-ipv4-listen-field"; continue; fi
        timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.2/$APORT" 2>/dev/null || DEAD="$DEAD node-$i:127.0.0.2:$APORT"
    done
    if [ -z "$DEAD" ]; then
        pass "alias 127.0.0.2:<IPv4 port> reaches the seed and friends 1, 20, $NUM_FRIENDS (A11); every node advertises $AMP aliases"
    else
        setup_fail "advertised aliases do not reach the node (A11):$DEAD"
    fi
fi
if [ -n "$CAP" ]; then
    MISSING=""
    for i in $(seq 0 $NUM_FRIENDS); do
        grep -aq "e2e: connection cap $CAP" "$(node_log "$i")" || MISSING="$MISSING $i"
    done
    [ -z "$MISSING" ] || setup_fail "no 'e2e: connection cap $CAP' on nodes:$MISSING (a build before C-DK C4 has no connection cache: MODE=$MODE cannot run)"
    pass "every node runs under connection cap $CAP"
fi
grep -q '^kademlia_disable_ipfs_bootstrap = false' "$(node_dir $IPFS_KEY_NODE)/config.toml" \
    || setup_fail "node-$IPFS_KEY_NODE config lost its kademlia_disable_ipfs_bootstrap = false"
[ -n "${VERDICT[0]:-}" ] || pass "preconditions hold"

CUR=1
FIELD_OK=1
sample_all
for i in $(alive_nodes); do
    # Only nodes that answered: a status without the field is a build before C-DK C1.
    if [ -n "${K[$i]:-}" ] && [ "${HAS_KNOWN[$i]:-N}" != Y ]; then FIELD_OK=0; fi
done
[ "$FIELD_OK" = 1 ] || setup_fail "status has no known_devices/peer_count_known (build before C-DK C1)"

if [ "$MODE" = hold ]; then BAR1=600; ROUGH1=300; else BAR1=300; ROUGH1=120; fi
CONVERGED_AT=""
while :; do
    sample_all; check_cap_sample; check_sockets_sample
    LAG=""
    for i in $(alive_nodes); do
        if [ "$i" = "$SEED" ]; then
            [ "${K[$i]:-0}" = "$NUM_FRIENDS" ] || LAG="$LAG seed:${K[$i]:-?}"
        else
            [ "${K[$i]:-0}" -ge 20 ] 2>/dev/null || LAG="$LAG $i:${K[$i]:-?}"
        fi
    done
    NOW=$(( $(date -u +%s) - T1 ))
    if [ -z "$LAG" ]; then CONVERGED_AT=$NOW; break; fi
    [ "$NOW" -ge "$BAR1" ] && break
    sleep 5
done
read -r AMIN AMED AMAX <<< "$(auth_sample_all $(alive_nodes))"
note "peer_count_authenticated min/median/max: $AMIN/$AMED/$AMAX"
if [ -n "$CONVERGED_AT" ]; then KNOW_BAR=GREEN; else KNOW_BAR=RED; fi
if [ -n "$CONVERGED_AT" ]; then
    if [ "$CONVERGED_AT" -gt "$ROUGH1" ]; then
        rough "every node knows >= 20, seed knows $NUM_FRIENDS, after ${CONVERGED_AT}s (> ${ROUGH1}s)"
    else
        pass "every node knows >= 20, seed knows $NUM_FRIENDS, after ${CONVERGED_AT}s"
    fi
else
    fail "after ${BAR1}s not every node knows >= 20 (node:known):$(echo "$LAG" | cut -c1-400)"
fi
print_lookup_signature
print_w2_verdict

# Symmetry: Y in known(X) => X in known(Y), read on Y (network-i14). Poll <= 60 s.
SYM_DEADLINE=$(( $(date -u +%s) + 60 ))
while :; do
    sample_all
    PAIRS=0; ASYM=0; ASYM_LIST=""
    for x in $(alive_nodes); do
        for h in $(echo "${KD[$x]}" | tr ',' ' '); do
            y="${DEV_IDX[$h]:-}"
            [ -n "$y" ] && [ "${ALIVE[$y]:-0}" = 1 ] || continue
            PAIRS=$((PAIRS + 1))
            if ! in_list "${DEV8[$x]}" "${KD[$y]}"; then
                ASYM=$((ASYM + 1)); ASYM_LIST="$ASYM_LIST $x>$y"
            fi
        done
    done
    [ "$ASYM" -eq 0 ] && [ "$PAIRS" -gt 0 ] && break
    [ "$(date -u +%s)" -ge "$SYM_DEADLINE" ] && break
    sleep 5
done
if [ "$PAIRS" -eq 0 ]; then
    fail "symmetry: 0 known pairs to check"
elif [ "$ASYM" -eq 0 ]; then
    pass "symmetry: all $PAIRS known pairs are known on the other side too"
elif [ $(( (PAIRS - ASYM) * 100 )) -ge $(( PAIRS * 95 )) ]; then
    rough "symmetry: $ASYM of $PAIRS pairs one-sided (X>Y = Y knows not X):$(echo "$ASYM_LIST" | cut -c1-300)"
else
    fail "symmetry: $ASYM of $PAIRS pairs one-sided:$(echo "$ASYM_LIST" | cut -c1-300)"
fi
if [ -z "$CAP_VIOLATIONS" ]; then
    pass "every sample: friends' connected - busy - infra - closing <= $CAP_EFF"
else
    fail "cap invariant broken:$(echo "$CAP_VIOLATIONS" | cut -c1-300)"
fi
SEED_OK=""
for t in $(seq 1 12); do
    sample_all
    if [ "${C[$SEED]:-x}" = "${A[$SEED]:-y}" ] && { [ -z "$CAP" ] || [ "${C[$SEED]}" -ge "$NUM_FRIENDS" ]; }; then
        SEED_OK=1; break
    fi
    sleep 5
done
if [ -n "$SEED_OK" ]; then
    pass "seed: connected ${C[$SEED]} = authenticated ${A[$SEED]}${CAP:+ (not capped at $CAP)}"
else
    fail "seed: connected ${C[$SEED]:-?} vs authenticated ${A[$SEED]:-?}${CAP:+ (want $NUM_FRIENDS: infrastructure outside the cap, M17)}"
fi

# ── STEP 2: ONE FILE PER FRIEND ─────────────────────────────────────────────
declare -A FILE_PATH FILE_HASH FILE_BLOCK
# add_file IDX NAME : a 64 KB random .jpg in the node's watch dir.
add_file() {
    local p; p="$(node_dir "$1")/files/$2"
    dd if=/dev/urandom of="$p" bs=1024 count=64 2>/dev/null
    FILE_PATH["$1:$2"]="$p"; FILE_HASH["$1:$2"]=$(content_hash "$p")
}
# placed_off_seed OWNER BLOCK : holders (not the owner, not the seed) with symbols of BLOCK.
placed_off_seed() {
    local n=0 j
    for j in $(alive_nodes); do
        [ "$j" = "$1" ] || [ "$j" = "$SEED" ] && continue
        [ "$(block_symbols_on "$j" "$2")" -gt 0 ] && n=$((n + 1))
    done
    echo "$n"
}
# wait_placed "IDX:NAME ..." SECS : every file restorable and on >= 2 non-seed holders.
# Sets PLACED_SECS (seconds to the last one) and NOT_PLACED.
wait_placed() {
    local keys="$1" secs="$2" t0 k idx kind blk
    local -A done_k=()
    t0=$(date -u +%s); NOT_PLACED=""
    while :; do
        NOT_PLACED=""
        for k in $keys; do
            [ -n "${done_k[$k]:-}" ] && continue
            idx="${k%%:*}"
            kind=$(file_field "$idx" "${FILE_PATH[$k]}" '.effective_status.kind // "none"')
            if [ "$kind" = restorable ]; then
                blk=$(file_block_hex "$idx" "${FILE_PATH[$k]}")
                if [ -n "$blk" ] && [ "$(placed_off_seed "$idx" "$blk")" -ge 2 ]; then
                    FILE_BLOCK[$k]="$blk"; done_k[$k]=1; continue
                fi
            fi
            NOT_PLACED="$NOT_PLACED $k($kind)"
        done
        PLACED_SECS=$(( $(date -u +%s) - t0 ))
        [ -z "$NOT_PLACED" ] && return 0
        [ "$PLACED_SECS" -ge "$secs" ] && return 1
        sleep 5
    done
}

if runs_step 2; then
    step 2 "each friend adds a 64 KB .jpg"
    KEYS=""
    for i in $(alive_friends); do add_file "$i" photo.jpg; KEYS="$KEYS $i:photo.jpg"; done
    if [ "$MODE" = main ]; then BAR2=180; else BAR2=300; fi
    if wait_placed "$KEYS" "$BAR2"; then
        if [ "$MODE" != main ] && [ "$PLACED_SECS" -gt 180 ]; then
            rough "all $(echo $KEYS | wc -w) files restorable on >= 2 non-seed holders after ${PLACED_SECS}s (> 180s)"
        else
            pass "all $(echo $KEYS | wc -w) files restorable on >= 2 non-seed holders after ${PLACED_SECS}s"
        fi
    else
        fail "after ${BAR2}s not placed:$(echo "$NOT_PLACED" | cut -c1-400)${CAP:+ (lru24: stop point v3-B)}"
    fi
fi

# ── STEP 3: HOLD ────────────────────────────────────────────────────────────
if runs_step 3; then
    step 3 "hold ${HOLD_SECS}s, sample every ${SAMPLE_SECS}s"
    # A status that does not answer within the API timeout on one sample (a loaded build
    # host pauses every node at once) is a missed sample, not fallen knowledge: it goes to
    # a NOTE (node@second) and leaves PREV_K alone, so "never down" compares with the last
    # value received. Two or more missed samples IN A ROW of one node are a FAIL
    # (i:no-status×N).
    declare -A LINE3 PREV_K MISS_RUN3 MISS_MAX3
    for i in $(alive_nodes); do LINE3[$i]=$(log_line_count "$i"); done
    T3=$(date -u +%s)
    KNOW_BAD=""; CAP_VIOLATIONS=""; SAMPLES=0; MISSED3=0; MISSED3_AT=""
    sample_all
    for i in $(alive_nodes); do PREV_K[$i]="${K[$i]:-0}"; done
    while [ $(( $(date -u +%s) - T3 )) -lt "$HOLD_SECS" ]; do
        sleep "$SAMPLE_SECS"
        sample_all; check_cap_sample; check_sockets_sample
        SAMPLES=$((SAMPLES + 1))
        for i in $(alive_nodes); do
            k="${K[$i]:-}"
            if [ -z "$k" ]; then
                MISSED3=$((MISSED3 + 1))
                MISSED3_AT="$MISSED3_AT node-$i@$(( $(date -u +%s) - T_BASE ))s"
                MISS_RUN3[$i]=$(( ${MISS_RUN3[$i]:-0} + 1 ))
                [ "${MISS_RUN3[$i]}" -gt "${MISS_MAX3[$i]:-0}" ] && MISS_MAX3[$i]="${MISS_RUN3[$i]}"
                continue
            fi
            MISS_RUN3[$i]=0
            if [ "$k" = NA ]; then KNOW_BAD="$KNOW_BAD $i:no-known-field"; continue; fi
            [ "$k" -lt 20 ] && KNOW_BAD="$KNOW_BAD $i:$k<20"
            [ "$k" -lt "${PREV_K[$i]:-0}" ] && KNOW_BAD="$KNOW_BAD $i:${PREV_K[$i]}->$k"
            PREV_K[$i]="$k"
        done
    done
    T3_END=$(date -u +%s)
    for i in "${!MISS_MAX3[@]}"; do
        [ "${MISS_MAX3[$i]}" -ge 2 ] && KNOW_BAD="$KNOW_BAD $i:no-status×${MISS_MAX3[$i]}"
    done
    [ "$MISSED3" -gt 0 ] && note "status missed on $MISSED3 node-samples (single misses are not a fall):$(echo "$MISSED3_AT" | cut -c1-300)"
    if [ "$SAMPLES" -eq 0 ]; then
        fail "0 samples taken"
    elif [ -z "$KNOW_BAD" ]; then
        pass "$SAMPLES samples ($MISSED3 node-samples missed): every node knows >= 20 and its known count never went down"
    else
        fail "knowledge fell:$(echo "$KNOW_BAD" | cut -c1-300)"
    fi
    if [ -z "$CAP_VIOLATIONS" ]; then
        pass "$SAMPLES samples: friends' connected - busy - infra - closing <= $CAP_EFF"
    else
        fail "cap invariant broken:$(echo "$CAP_VIOLATIONS" | cut -c1-300)"
    fi
    # Log bars (spec v3.2 BL-2). Lines of a build without the cache are simply absent.
    EVICT=0; SLOW_EVICT=""; REDIAL_CAR=0; DISC_CAR=0; KAD_CAR=0; OND_CAR=0; LOOKUPS_MAX=0; BOOTS_MAX=0
    OVER_MS=0; KEEPALIVE=0
    for i in $(alive_nodes); do
        L="$(plain_log_since "$i" "${LINE3[$i]}")"
        n=$(grep -ac "lru: evicted peer" <<< "$L" || true); EVICT=$((EVICT + n))
        while read -r ms; do
            [ -n "$ms" ] && [ "$ms" -gt 11000 ] && SLOW_EVICT="$SLOW_EVICT $i:${ms}ms"
        done < <(grep -a "lru: evicted peer" <<< "$L" | grep -oE 'evictable_for_ms=[0-9]+' | cut -d= -f2 || true)
        LF=$(node_log "$i"); L0I="${LINE3[$i]}"
        REDIAL_CAR=$((REDIAL_CAR + $(carousel_count "$LF" redial "$L0I")))
        DISC_CAR=$((DISC_CAR + $(carousel_count "$LF" discovery "$L0I")))
        KAD_CAR=$((KAD_CAR + $(carousel_count "$LF" kad "$L0I")))
        OND_CAR=$((OND_CAR + $(carousel_count "$LF" on_demand "$L0I")))
        n=$(grep -ac "kademlia discovery lookup started" <<< "$L" || true); [ "$n" -gt "$LOOKUPS_MAX" ] && LOOKUPS_MAX=$n
        n=$(grep -ac "kademlia bootstrap started" <<< "$L" || true); [ "$n" -gt "$BOOTS_MAX" ] && BOOTS_MAX=$n
        n=$(grep -a "lru: under cap" <<< "$L" | grep -oE 'after_ms=[0-9]+' | cut -d= -f2 | awk '{ s += $1 } END { print s + 0 }' || true)
        OVER_MS=$((OVER_MS + ${n:-0}))
        n=$(grep -a "connection closed" <<< "$L" | grep -ac "KeepAliveTimeout" || true); KEEPALIVE=$((KEEPALIVE + n))
    done
    W=$(( T3_END - T3 ))
    T_S=$(( 1800 / TIME_SCALE )); [ "$T_S" -lt 60 ] && T_S=60
    START_BAR=$(( (W + T_S - 1) / T_S + 1 ))
    if [ -n "$SLOW_EVICT" ]; then
        fail "victims closed later than 11 s after they became evictable:$(echo "$SLOW_EVICT" | cut -c1-200)"
    elif [ "$EVICT" -gt 0 ]; then
        pass "$EVICT evictions, each within 11 s of becoming evictable"
    fi
    if [ $((REDIAL_CAR + DISC_CAR)) -gt 0 ]; then
        fail "carousel: re-dials of evicted peers origin=redial $REDIAL_CAR, origin=discovery $DISC_CAR"
    elif [ "$EVICT" -gt 0 ]; then
        pass "no re-dial of an evicted peer by redial or discovery (carousel = 0, $EVICT evictions)"
    elif [ -n "$CAP" ]; then
        fail "0 evictions under cap $CAP with $NUM_FRIENDS peers: the carousel check is blind (no connection cache?)"
    else
        note "0 evictions (cap 48 > peers): the carousel check has nothing to see in this mode"
    fi
    note "evictions $EVICT; re-dials of evicted peers: origin=kad $KAD_CAR, origin=on_demand $OND_CAR"
    if [ -n "$CAP" ]; then
        if [ "$LOOKUPS_MAX" -eq 0 ] || [ "$BOOTS_MAX" -eq 0 ]; then
            fail "no 'kademlia discovery lookup started' / 'kademlia bootstrap started' lines (max $LOOKUPS_MAX / $BOOTS_MAX): the lookup cadence is not observable"
        elif [ "$LOOKUPS_MAX" -le "$START_BAR" ] && [ "$BOOTS_MAX" -le "$START_BAR" ]; then
            pass "after convergence at most $LOOKUPS_MAX lookups and $BOOTS_MAX bootstraps per node in ${W}s (bar ceil(W/T_s)+1 = $START_BAR, T_s = ${T_S}s)"
        else
            fail "lookups do not slow down after convergence: max $LOOKUPS_MAX lookups / $BOOTS_MAX bootstraps per node > $START_BAR (M15)"
        fi
        FRAC=$(( OVER_MS / 10 / (W * $(alive_friends | wc -l)) ))
        if [ "$FRAC" -gt 60 ]; then rough "time over the cap ${FRAC}% of friend-time (> 60 %)"; else note "time over the cap ${FRAC}% of friend-time (estimate ~35 %)"; fi
    else
        note "lookup starts per node after convergence: max $LOOKUPS_MAX, bootstraps max $BOOTS_MAX (ceil(W/T_s)+1 = $START_BAR; no lines = build before C4); evictions at cap 48 > 39 peers: $EVICT (expected 0)"
        # Main run: after minute 5 of the run, a node with >= 16 authenticated peers dials
        # nobody in its maintenance pass (i43). already_connected = its authenticated known peers.
        CHECKED=0; DIALING=""
        for i in $(alive_nodes); do
            while read -r t _l dialed ac; do
                [ "$ac" = "-" ] && continue
                [ "$ac" -ge 16 ] || continue
                CHECKED=$((CHECKED + 1))
                [ "$dialed" -gt 0 ] && DIALING="$DIALING $i:dialed=$dialed@${t%.*}s"
            done < <(events_grep "$(node_log "$i")" "auto-dial pass" dialed already_connected \
                | in_window $(( T1 - T_BASE + 300 )) $(( T3_END - T_BASE )))
        done
        if [ "$CHECKED" -eq 0 ]; then
            fail "no 'auto-dial pass' of a node with >= 16 authenticated peers after minute 5: the maintenance bar saw nothing"
        elif [ -z "$DIALING" ]; then
            pass "$CHECKED maintenance passes of nodes with >= 16 authenticated peers after minute 5: all dialed=0"
        else
            fail "maintenance passes dialed at >= 16 authenticated:$(echo "$DIALING" | cut -c1-300)"
        fi
    fi
    read -r AMIN AMED AMAX <<< "$(auth_sample_all $(alive_nodes))"
    note "peer_count_authenticated min/median/max at the end: $AMIN/$AMED/$AMAX; established sockets - connected peers (W6 duplicates) max $MAX_DUP_SOCKETS"
    [ "$MODE" = hold ] && note "closes with cause KeepAliveTimeout: $KEEPALIVE (expected 0: identify keeps links alive, v3-C)"
    if [ "${WAKES[$SEED]:-NA}" = NA ]; then
        note "work_wakes_suppressed absent from status (build before C4, Р-18)"
    else
        note "work_wakes_suppressed: $(for i in $(alive_nodes); do echo "${WAKES[$i]:-0}"; done | awk '{ s += $1 } END { print s + 0 }') over all nodes"
    fi
fi

# ── STEP 4a: SEED DOWN ──────────────────────────────────────────────────────
if runs_step 4a; then
    step 4a "SIGKILL the seed for 90 s"
    sample_all
    declare -A K_BEFORE
    for i in $(alive_friends); do K_BEFORE[$i]="${K[$i]:-0}"; done
    kill_node "$SEED"
    T4=$(date -u +%s)
    # As in step 3: a status missed on one check is a NOTE and keeps the comparison with the
    # last value received; missed on both checks in a row is a FAIL (i:no-status×2).
    declare -A MISS_RUN4
    check_known_kept() { # LABEL
        local i bad="" missed=""
        sample_all
        for i in $(alive_friends); do
            if [ -z "${K[$i]:-}" ]; then
                MISS_RUN4[$i]=$(( ${MISS_RUN4[$i]:-0} + 1 ))
                missed="$missed node-$i@$(( $(date -u +%s) - T_BASE ))s"
                [ "${MISS_RUN4[$i]}" -ge 2 ] && bad="$bad $i:no-status×${MISS_RUN4[$i]}"
                continue
            fi
            MISS_RUN4[$i]=0
            [ "${K[$i]}" -ge "${K_BEFORE[$i]}" ] 2>/dev/null || bad="$bad $i:${K_BEFORE[$i]}->${K[$i]}"
            K_BEFORE[$i]="${K[$i]}"
        done
        [ -n "$missed" ] && note "$1: status missed (not a fall):$(echo "$missed" | cut -c1-300)"
        if [ -z "$bad" ]; then pass "$1: no friend's known count fell"; else fail "$1: known fell:$(echo "$bad" | cut -c1-300)"; fi
    }
    sleep_until $(( T4 - T_BASE + 30 ))
    check_known_kept "+30 s"
    xor_ranks_load
    for x in 3 17; do
        y=$(pick_target "$x")
        if [ -z "$y" ]; then note "node-$x knows no live non-seed peer to reach"; continue; fi
        reach_pair "$x" "$y" && rc=0 || rc=$?
        case "$rc" in
            0) note "(i42 bar only in lru24/lru/hold) GREEN: $PAIR_MSG" ;;
            1) note "(i42 bar only in lru24/lru/hold) RED: $PAIR_MSG" ;;
            *) note "pair dropped: $PAIR_MSG" ;;
        esac
    done
    LATE_BY=$(( $(date -u +%s) - T4 - 90 ))
    sleep_until $(( T4 - T_BASE + 90 ))
    [ "$LATE_BY" -gt 0 ] && note "the +90 s check runs ${LATE_BY}s late (reach took long)"
    check_known_kept "+90 s"
fi

# ── STEP 4b: SEED BACK ──────────────────────────────────────────────────────
if runs_step 4b; then
    step 4b "the seed restarts with the same data dir"
    NEW_P="$SEED_PORT"
    if [ "$SEED_NEW_PORT" = 1 ]; then NEW_P=$(( SEED_PORT + 1 )); note "M7: seed restarts on port $NEW_P"; fi
    write_config "$SEED" "$NEW_P" "" 'relay_role = "punch"'
    SEED_ADDR="/ip4/127.0.0.1/tcp/$NEW_P/p2p/${PEER_ID[$SEED]}"
    L0=$(log_line_count "$SEED")
    start_daemon "$SEED"
    wait_api "$SEED" 60 || fail "seed does not answer after restart"
    T4B=$(date -u +%s); OK4B=""
    while [ $(( $(date -u +%s) - T4B )) -lt 120 ]; do
        sample_all; check_sockets_sample
        if [ "${K[$SEED]:-0}" = "$NUM_FRIENDS" ] && [ "${A[$SEED]:-0}" -ge "$NUM_FRIENDS" ]; then OK4B=$(( $(date -u +%s) - T4B )); break; fi
        sleep 3
    done
    if [ -n "$OK4B" ]; then
        pass "seed back: knows ${K[$SEED]}, authenticated ${A[$SEED]} after ${OK4B}s"
    else
        fail "seed after 120 s: known ${K[$SEED]:-?} (want $NUM_FRIENDS), authenticated ${A[$SEED]:-?} (want >= $NUM_FRIENDS)"
    fi
    CONNECTS=$(plain_log_since "$SEED" "$L0" | grep -ac "dial initiated — peer will be registered" || true)
    [ "$CONNECTS" -eq 0 ] && pass "no connect was called" || fail "$CONNECTS connect calls on the seed"
    FIRST_PASS=$(plain_log_since "$SEED" "$L0" | grep -a "auto-dial pass" | head -1 || true)
    D=$(log_field "$FIRST_PASS" dialed); AC=$(log_field "$FIRST_PASS" already_connected)
    if [ -z "$FIRST_PASS" ]; then
        fail "no 'auto-dial pass' line from the restarted seed"
    elif [ $(( ${D:-0} + ${AC:-0} )) -eq "$NUM_FRIENDS" ]; then
        pass "first seed pass: dialed $D + already_connected $AC = $NUM_FRIENDS"
    else
        fail "first seed pass: dialed ${D:-?} + already_connected ${AC:-?} != $NUM_FRIENDS"
    fi
fi

# ── STEP 5: THE LATE FRIEND ─────────────────────────────────────────────────
if runs_step 5; then
    step 5 "node-$LATE joins late"
    mkdir -p "$(node_dir $LATE)"
    run_cli "$LATE" init > "$TEST_DIR/logs/init-$LATE.out" 2>&1 || fail "init node-$LATE"
    write_config "$LATE" 0 "$SEED_ADDR"
    start_daemon "$LATE"
    wait_api "$LATE" 60 && learn_identity "$LATE" || setup_fail "node-$LATE does not start"
    T5=$(date -u +%s)
    if [ "$MODE" = main ]; then BAR5=180; else BAR5=300; fi
    FILE_ADDED=0; OK_KNOWN=""; OK_KNOWN_BY=""
    while [ $(( $(date -u +%s) - T5 )) -lt "$BAR5" ]; do
        [ "$FILE_ADDED" = 0 ] && [ $(( $(date -u +%s) - T5 )) -ge 60 ] && { add_file "$LATE" photo.jpg; FILE_ADDED=1; T5F=$(date -u +%s); }
        sample_all; check_sockets_sample
        [ -z "$OK_KNOWN" ] && [ "${K[$LATE]:-0}" -ge 20 ] 2>/dev/null && OK_KNOWN=$(( $(date -u +%s) - T5 ))
        KNOWN_BY=0
        for i in $(alive_friends); do
            [ "$i" = "$LATE" ] && continue
            in_list "${DEV8[$LATE]}" "${KD[$i]:-}" && KNOWN_BY=$((KNOWN_BY + 1))
        done
        [ -z "$OK_KNOWN_BY" ] && [ "$KNOWN_BY" -ge 10 ] && OK_KNOWN_BY=$(( $(date -u +%s) - T5 ))
        [ -n "$OK_KNOWN" ] && [ -n "$OK_KNOWN_BY" ] && [ "$FILE_ADDED" = 1 ] && break
        sleep 5
    done
    [ -n "$OK_KNOWN" ] && pass "node-$LATE knows ${K[$LATE]} after ${OK_KNOWN}s" \
        || fail "node-$LATE knows ${K[$LATE]:-?} < 20 after ${BAR5}s"
    [ -n "$OK_KNOWN_BY" ] && pass "$KNOWN_BY old non-seed nodes list node-$LATE in THEIR known_devices (>= 10 after ${OK_KNOWN_BY}s)" \
        || fail "only $KNOWN_BY old non-seed nodes know node-$LATE after ${BAR5}s (want >= 10)"
    if [ "$FILE_ADDED" = 1 ]; then
        # The file bar counts from the moment the file was added.
        REMAIN=$(( BAR5 - ( $(date -u +%s) - T5F ) ))
        [ "$REMAIN" -lt 1 ] && REMAIN=1
        if wait_placed "$LATE:photo.jpg" "$REMAIN"; then
            pass "node-$LATE's file restorable on >= 2 non-seed holders"
        else
            fail "node-$LATE's file not placed on >= 2 non-seed holders:$NOT_PLACED"
        fi
    else
        fail "node-$LATE never added its file"
    fi
fi

# ── STEP 6, first evaluation (before the steps that may stop early) ─────────
run_step6

# ── STEP 8a: REACH ON DEMAND ────────────────────────────────────────────────
if runs_step 8a; then
    step 8a "5 pairs: a cold known peer reached on demand"
    xor_ranks_load
    OKP=0; REDP=0; DROPPED=0
    for x in 5 11 23 31 40; do
        [ "${ALIVE[$x]:-0}" = 1 ] || { note "node-$x is not running (step 5 skipped?)"; continue; }
        y=$(pick_target "$x")
        if [ -z "$y" ]; then note "node-$x knows no live non-seed peer"; continue; fi
        cold "$x" "$y" && note "node-$x/node-$y cold already (natural)" || note "node-$x/node-$y connected: forced disconnect"
        reach_pair "$x" "$y" && rc=0 || rc=$?
        case "$rc" in
            0) OKP=$((OKP + 1)); echo "    ok: $PAIR_MSG" ;;
            1) REDP=$((REDP + 1)); echo "    RED: $PAIR_MSG" ;;
            *) DROPPED=$((DROPPED + 1)); echo "    dropped: $PAIR_MSG" ;;
        esac
    done
    if [ $((OKP + REDP)) -eq 0 ]; then
        bar8_fail "0 pairs in the sample ($DROPPED dropped)"
    elif [ "$REDP" -eq 0 ]; then
        bar8_pass "$OKP/$((OKP + REDP)) pairs reached on demand ($DROPPED dropped)"
    else
        bar8_fail "$REDP/$((OKP + REDP)) pairs not reached on demand ($DROPPED dropped)"
    fi
fi

# ── STEP 8b: RESTORE FROM COLD HOLDERS ──────────────────────────────────────
OWNER=7
# Precondition of 8b/8c: node-07's file is placed. Not placed (M0: no pool) = RED of
# the step (a NOTE in the main run), the steps are skipped — never an exit that would
# lose steps 6 and 7.
SKIP_8BC=0
if runs_step 8b || runs_step 8c; then
    if [ -z "${FILE_BLOCK[$OWNER:photo.jpg]:-}" ]; then
        CUR=8b
        [ -n "${FILE_PATH[$OWNER:photo.jpg]:-}" ] || add_file "$OWNER" photo.jpg
        if ! wait_placed "$OWNER:photo.jpg" 180; then
            bar8_fail "precondition: node-$OWNER's file is not placed on >= 2 non-seed holders ($NOT_PLACED): 8b/8c skipped"
            SKIP_8BC=1
        fi
    fi
fi
if runs_step 8b && [ "$SKIP_8BC" = 0 ]; then
    step 8b "restore from holders with no live connection"
    K8="$OWNER:photo.jpg"; BLK="${FILE_BLOCK[$K8]}"
    HOLDERS=""
    for j in $(alive_nodes); do
        [ "$j" = "$OWNER" ] && continue
        [ "$(block_symbols_on "$j" "$BLK")" -gt 0 ] && HOLDERS="$HOLDERS $j"
    done
    note "holders of node-$OWNER's block ${BLK:0:16}:$HOLDERS"
    assert_delete_window "$TIME_SCALE"
    rm -f "${FILE_PATH[$K8]}"
    wait_file_deleted "$OWNER" "${FILE_PATH[$K8]}" 60 || note "the deletion is not registered after 60 s"
    COLD=""
    for try in 1 2 3; do
        for j in $HOLDERS; do make_cold "$OWNER" "$j" || true; done
        COLD=""; for j in $HOLDERS; do cold "$OWNER" "$j" && COLD="$COLD $j"; done
        [ -n "$COLD" ] && break
    done
    if [ -z "$COLD" ]; then
        bar8_fail "sample empty: no holder cold at the start of restore (kad reconnected all)"
    else
        note "cold at restore start (checked on both sides):$COLD"
        declare -A HL0
        for j in $COLD; do HL0[$j]=$(log_line_count "$j"); done
        L7=$(log_line_count "$OWNER")
        if restore_from_network "$OWNER" "${FILE_PATH[$K8]}" "${FILE_HASH[$K8]}" 120; then
            bar8_pass "restore: $RESTORE_MSG"
        else
            bar8_fail "restore: $RESTORE_MSG"
        fi
        REDIALS=$(plain_log_since "$OWNER" "$L7" | grep -ac "fetch: redialed holders before a retry" || true)
        [ "$REDIALS" -eq 0 ] && bar8_pass "0 'fetch: redialed holders before a retry' during restore" \
            || bar8_fail "$REDIALS 'fetch: redialed holders before a retry' during restore (reached only by restore-i26 redial)"
        SERVED=""
        for j in $COLD; do
            if log_has_since "$j" "${HL0[$j]}" "sending RestoreResponse" "${BLK:0:16}" \
                && log_has_since "$OWNER" "$L7" "swarm: on-demand dial" "peer_id=${PEER_ID[$j]}"; then
                SERVED="$SERVED $j"
            fi
        done
        [ -n "$SERVED" ] && bar8_pass "cold holders dialed on demand that sent RestoreResponse:$SERVED" \
            || bar8_fail "no cold holder was dialed on demand and sent RestoreResponse (cold:$COLD)"
    fi
fi

# ── STEP 8c: A BLACK-HOLE HOLDER ────────────────────────────────────────────
run_8c() {
    step 8c "a holder that accepts TCP and stays silent"
    KEYS="$OWNER:photo.jpg"
    for n in 1 2 3 4 5; do add_file "$OWNER" "bh$n.jpg"; KEYS="$KEYS $OWNER:bh$n.jpg"; done
    # The step 8b file was deleted and restored to staging; bring it back in place for this round.
    if [ ! -e "${FILE_PATH[$OWNER:photo.jpg]}" ]; then
        add_file "$OWNER" photo.jpg
    fi
    wait_placed "$KEYS" 180 || fail "node-$OWNER's 6 files not placed on >= 2 holders in 180 s:$NOT_PLACED"
    H=""; HB=0
    for j in $(alive_nodes); do
        [ "$j" = "$OWNER" ] || [ "$j" = "$SEED" ] || [ "$j" = "$DR_SOURCE" ] && continue
        n=0
        for k in $KEYS; do [ "$(block_symbols_on "$j" "${FILE_BLOCK[$k]:-none}")" -gt 0 ] && n=$((n + 1)); done
        [ "$n" -gt "$HB" ] && { H=$j; HB=$n; }
    done
    if [ -z "$H" ] || [ "$HB" -lt 2 ]; then
        soft_setup_fail "sample: no holder (not the seed) with >= 2 of node-$OWNER's 6 blocks"; return 0
    fi
    H_PORT=$(api_get "$H" /api/status | jq -r '.node_addr' | grep -oE '/tcp/[0-9]+' | cut -d/ -f3 || true)
    if [ -z "$H_PORT" ]; then soft_setup_fail "node-$H reports no listen port"; return 0; fi
    note "black hole: node-$H (port $H_PORT) holds $HB of 6 blocks"
    kill_node "$H"
    sleep 1
    black_hole_listen "$H_PORT"
    BH_UP=0
    for t in $(seq 1 10); do timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$H_PORT" 2>/dev/null && { BH_UP=1; break; }; sleep 0.5; done
    if [ "$BH_UP" != 1 ]; then soft_setup_fail "black-hole listener on $H_PORT is not up"; return 0; fi
    assert_delete_window "$TIME_SCALE"
    for k in $KEYS; do rm -f "${FILE_PATH[$k]}"; done
    for k in $KEYS; do wait_file_deleted "$OWNER" "${FILE_PATH[$k]}" 60 || note "${FILE_PATH[$k]} deletion not registered"; done
    L7=$(log_line_count "$OWNER")
    T8C=$(date +%s)
    restore_run "$OWNER" 180 "$(node_dir "$OWNER")/files/"
    T_RESTORE=$(( $(date +%s) - T8C ))
    L7_END=$(log_line_count "$OWNER")
    OK_FILES=0
    if [ "$RESTORE_RC" -eq 0 ]; then
        ST=$(echo "$RESTORE_LAST" | jq -r '.staging_path')
        for k in $KEYS; do
            f="$ST/${FILE_PATH[$k]#/}"
            [ -f "$f" ] && [ "$(content_hash "$f")" = "${FILE_HASH[$k]}" ] && OK_FILES=$((OK_FILES + 1))
        done
    fi
    [ "$OK_FILES" -eq 6 ] && pass "all 6 files restored, hashes match, in ${T_RESTORE}s" \
        || fail "restore: $OK_FILES/6 files match (exit $RESTORE_RC, ${T_RESTORE}s): ${RESTORE_LAST:0:300}"
    # Only the lines of the restore window (spec v3.2 WR-2): earlier failures do not count.
    WIN=$(sed -n "$(( L7 + 1 )),${L7_END}p" "$(node_log "$OWNER")" | sed 's/\x1b\[[0-9;]*m//g')
    FAILS=$(grep -a "swarm: on-demand dial failed" <<< "$WIN" | grep -acF "peer_id=${PEER_ID[$H]}" || true)
    CACHED=$(grep -a "on-demand: unreachable (cached)" <<< "$WIN" | grep -acF "peer_id=${PEER_ID[$H]}" || true)
    FAIL_BAR=$(( 1 + (T_RESTORE + 59) / 60 ))
    [ "$FAILS" -le "$FAIL_BAR" ] && pass "on-demand dial failures to node-$H in the restore window: $FAILS <= $FAIL_BAR" \
        || fail "on-demand dial failures to node-$H: $FAILS > $FAIL_BAR (M16: no negative cache)"
    [ "$CACHED" -ge $(( HB - FAILS )) ] && pass "cached-unreachable answers for node-$H: $CACHED >= $HB - $FAILS" \
        || fail "cached-unreachable answers for node-$H: $CACHED < $HB blocks - $FAILS failures (no negative cache on this build?)"
    kill "$BH_PID" 2>/dev/null || true; BH_PID=""
}
if runs_step 8c && [ "$SKIP_8BC" = 0 ]; then run_8c; fi

# ── STEP 7: DR ONTO A CLEAN MACHINE (NOTE for line B) ───────────────────────
if runs_step 7; then
    step 7 "NOTE for line B (dr-i63): DR of node-$DR_SOURCE's phrase onto a clean node-$DR_NODE"
    kill_node "$DR_SOURCE"
    mkdir -p "$(node_dir $DR_NODE)"
    DR_LOG="$TEST_DIR/logs/dr-$DR_NODE.log"
    set +e
    RUST_LOG=info timeout 900 "$BINARY" --data-dir "$(node_dir $DR_NODE)" dr --mnemonic "$M_DR_SOURCE" \
        --peer "$SEED_ADDR" > "$DR_LOG" 2>&1
    DR_RC=$?
    set -e
    DRP=$(sed 's/\x1b\[[0-9;]*m//g' "$DR_LOG")
    MS=$(grep -a "Mailbox search: asked" <<< "$DRP" | tail -1 || true)
    if [ -n "$MS" ]; then
        note "dr exit $DR_RC: $MS"
    else
        note "dr exit $DR_RC: DR did not reach the mailbox search"
    fi
    grep -aq "Mailbox search: asked [0-9]* postmen, [0-9]* answered, 0 pointer" <<< "$DRP" \
        && note "no pointer found: $(grep -a '^error:' <<< "$DRP" | tail -1 || echo 'no error line')"
    CAND=$(grep -a "dr: get_closest_peers returned candidate peers" <<< "$DRP" | grep -oE 'count=[0-9]+' | tail -1 || true)
    KFAIL=$(grep -ac "dr: get_closest_peers failed" <<< "$DRP" || true)
    note "Kademlia candidates: ${CAND:-none}; 'dr: get_closest_peers failed': $KFAIL"
    if [ "$DR_RC" -eq 0 ]; then
        write_config "$DR_NODE" 0 "$SEED_ADDR"
        start_daemon "$DR_NODE"
        if wait_api "$DR_NODE" 60; then
            RDY="false"
            for t in $(seq 1 12); do RDY=$(status_num "$DR_NODE" dr_ready); [ "$RDY" = true ] && break; sleep 5; done
            note "dr_ready of the recovered node-$DR_NODE: $RDY"
        else
            note "the recovered node-$DR_NODE daemon does not answer"
        fi
    fi
    VERDICT[7]="${VERDICT[7]:-}"; [ -n "${VERDICT[7]}" ] || { VERDICT[7]=NOTE; DETAIL[7]="baseline for line B, no bar"; }
fi

# ── STEP 6, final evaluation over the whole run ─────────────────────────────
if runs_step 8a || runs_step 8b || runs_step 8c || runs_step 7; then run_step6; fi

summary
# 0 pass, 1 fail, 2 FAIL(setup), 3 pass-rough (as local_dr_test.sh: e2e_collect.sh reads it).
[ "$SETUP_FAILED" = 1 ] && exit 2
[ "$RESULT" = FAIL ] && exit 1
[ "$RESULT" = ROUGH ] && exit 3
exit 0
