#!/bin/bash
# Remote test: run cargo test on server if available, locally otherwise.
set -euo pipefail

SERVER="${SYNCBACK_SERVER:-your-user@your-server}"
REMOTE_DIR="projects/syncback"
ARGS="${@:---workspace}"

if ssh -o ConnectTimeout=2 -o BatchMode=yes "$SERVER" "echo ok" &>/dev/null; then
    echo "=== Server online, testing remotely ==="
    rsync -az --delete \
        --exclude target \
        --exclude .claude \
        --exclude '.git/objects' \
        . "$SERVER:~/$REMOTE_DIR/"
    ssh "$SERVER" "source ~/.cargo/env && cd ~/$REMOTE_DIR && \
        cargo fmt --all --check && \
        cargo test $ARGS && \
        cargo clippy --workspace --all-targets -- -D warnings"
    echo "=== Done (remote) ==="
else
    echo "=== Server offline, testing locally ==="
    cargo fmt --all --check
    cargo test $ARGS
    cargo clippy --workspace --all-targets -- -D warnings
    echo "=== Done (local) ==="
fi
