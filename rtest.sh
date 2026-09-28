#!/bin/bash
# Remote test: run the gate on the build server. Local run only with an explicit --local.
set -euo pipefail

# Load local-only config (real server address). .env is gitignored.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/.env" ] && set -a && . "$SCRIPT_DIR/.env" && set +a

SERVER="${VIATICUM_SERVER:-your-user@your-server}"
# One server dir per checkout: parallel worktrees (syncback-<name>) must not
# rsync --delete over each other. Main checkout keeps projects/syncback.
REMOTE_DIR="projects/$(basename "$SCRIPT_DIR")"
# Two gates (2026-09-26): daemon+core tests finish in ~15 s, the simulator's
# heavy scenario tests take ~8 min. Default = fast gate (simulator compiled and
# clippy-checked, its tests skipped). `--full` runs everything — required when
# touching viaticum-core / viaticum-sim, and on every branch merge.
SIM_FILTER="-E 'not package(viaticum-sim)'"
LOCAL=""
while [ $# -gt 0 ]; do
    case "$1" in
        --full) SIM_FILTER=""; shift ;;
        --local) LOCAL=1; shift ;;
        *) break ;;
    esac
done
ARGS="${@:---workspace}"

# Server probe: 3 tries, 5 s each. A single failed 2-second probe used to fall
# through to a silent LOCAL build (2026-09-27: ~30 min and 7.8 GB on the laptop).
server_up() {
    local i
    for i in 1 2 3; do
        ssh -o ConnectTimeout=5 -o BatchMode=yes "$SERVER" "echo ok" &>/dev/null && return 0
        sleep 2
    done
    return 1
}

if [ -z "$LOCAL" ] && server_up; then
    echo "=== Server online, testing remotely ==="
    # --checksum --no-times: sync by content and stamp changed files with a fresh mtime.
    # Plain -a keeps the source mtime, so a file reverted to older content (branch
    # switch, undone mutation) looks unchanged to cargo and the build goes stale.
    rsync -az --checksum --no-times --delete \
        --exclude target \
        --exclude .claude \
        --exclude '.git/objects' \
        . "$SERVER:~/$REMOTE_DIR/"
    ssh "$SERVER" "source ~/.cargo/env && cd ~/$REMOTE_DIR && \
        cargo fmt --all --check && \
        if command -v cargo-nextest >/dev/null; then \
            cargo nextest run --no-fail-fast $ARGS $SIM_FILTER && cargo test --doc $ARGS; \
        else cargo test $ARGS; fi && \
        cargo clippy --workspace --all-targets -- -D warnings"
    echo "=== Done (remote) ==="
elif [ -z "$LOCAL" ]; then
    echo "=== Build server $SERVER unreachable (3 tries) — NOT testing locally. Retry, or pass --local explicitly. ===" >&2
    exit 9
else
    echo "=== --local: testing on this machine ==="
    cargo fmt --all --check
    cargo test $ARGS
    cargo clippy --workspace --all-targets -- -D warnings
    echo "=== Done (local) ==="
fi
