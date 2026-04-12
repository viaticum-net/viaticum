#!/bin/bash
# Remote build: compile on server if available, locally otherwise.
# Server is faster (48 cores) and keeps laptop cool.
set -euo pipefail

SERVER="${SYNCBACK_SERVER:-your-user@your-server}"
REMOTE_DIR="projects/syncback"
ARGS="${@:---release -p syncback}"

if ssh -o ConnectTimeout=2 -o BatchMode=yes "$SERVER" "echo ok" &>/dev/null; then
    echo "=== Server online, building remotely ==="
    rsync -az --delete \
        --exclude target \
        --exclude .claude \
        --exclude '.git/objects' \
        . "$SERVER:~/$REMOTE_DIR/"
    ssh "$SERVER" "source ~/.cargo/env && cd ~/$REMOTE_DIR && cargo build $ARGS"
    echo "=== Copying binary ==="
    mkdir -p target/release
    scp "$SERVER:~/$REMOTE_DIR/target/release/syncback" target/release/ 2>/dev/null || true
    echo "=== Done (remote) ==="
else
    echo "=== Server offline, building locally ==="
    cargo build $ARGS
    echo "=== Done (local) ==="
fi
