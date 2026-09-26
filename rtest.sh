#!/bin/bash
# Remote test: run cargo test on server if available, locally otherwise.
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
if [ "${1:-}" = "--full" ]; then SIM_FILTER=""; shift; fi
ARGS="${@:---workspace}"

if ssh -o ConnectTimeout=2 -o BatchMode=yes "$SERVER" "echo ok" &>/dev/null; then
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
else
    echo "=== Server offline, testing locally ==="
    cargo fmt --all --check
    cargo test $ARGS
    cargo clippy --workspace --all-targets -- -D warnings
    echo "=== Done (local) ==="
fi
