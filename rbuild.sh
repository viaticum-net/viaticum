#!/bin/bash
# Remote build: compile on the build server. Local build only with an explicit --local.
set -euo pipefail

# Load local-only config (real server address). .env is gitignored.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/.env" ] && set -a && . "$SCRIPT_DIR/.env" && set +a

SERVER="${VIATICUM_SERVER:-your-user@your-server}"
# One server dir per checkout (see rtest.sh).
REMOTE_DIR="projects/$(basename "$SCRIPT_DIR")"
LOCAL=""
if [ "${1:-}" = "--local" ]; then LOCAL=1; shift; fi
ARGS="${@:---release -p viaticum}"

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
    echo "=== Server online, building remotely ==="
    # --checksum --no-times: sync by content and stamp changed files with a fresh mtime.
    # Plain -a keeps the source mtime, so a file reverted to older content (branch
    # switch, undone mutation) looks unchanged to cargo and the build goes stale.
    rsync -az --checksum --no-times --delete \
        --exclude target \
        --exclude .claude \
        --exclude '.git/objects' \
        . "$SERVER:~/$REMOTE_DIR/"
    ssh "$SERVER" "source ~/.cargo/env && cd ~/$REMOTE_DIR && cargo build $ARGS"
    echo "=== Copying binaries ==="
    mkdir -p target/release
    scp "$SERVER:~/$REMOTE_DIR/target/release/viaticum" \
        "$SERVER:~/$REMOTE_DIR/target/release/bootstrap-trust" \
        target/release/ 2>/dev/null || true
    echo "=== Done (remote) ==="
elif [ -z "$LOCAL" ]; then
    echo "=== Build server $SERVER unreachable (3 tries) — NOT building locally. Retry, or pass --local explicitly. ===" >&2
    exit 9
else
    echo "=== --local: building on this machine ==="
    cargo build $ARGS
    echo "=== Done (local) ==="
fi
