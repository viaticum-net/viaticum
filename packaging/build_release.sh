#!/bin/bash
# Build the Linux release artifacts of Viaticum (install-i11).
#
#   packaging/build_release.sh --snapshot     # HEAD of a clean tree, build id <ver>+<rev7>
#   packaging/build_release.sh 0.1.0-alpha.1  # tag v0.1.0-alpha.1, build id <ver>+<rev7>
#
# Runs on the build server inside a git checkout (it needs `git archive`). The
# source is taken from git, never from the working tree, so the build id names
# exactly the revision that was built. The web UI is rebuilt from scratch
# (`npm ci && npm run build`) inside the archive: a stale `dist/` from a laptop
# or an earlier build is never embedded.
#
# Targets: static musl binaries for x86_64 and aarch64, cross-built with
# cargo-zigbuild, without features (no e2e tools in a user build).
#
# Environment:
#   VIATICUM_RELEASE_WORK  work dir (default ~/.cache/viaticum-release): source
#                          archive, persistent cargo target dir, output.
#   VIATICUM_TARGETS       space-separated targets (default: both).
set -euo pipefail
export LC_ALL=C

TARGETS_DEFAULT="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

die() {
    echo "build_release: error: $*" >&2
    exit 1
}

log() {
    echo "build_release: $*" >&2
}

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found in PATH ($2)"
}

# Workspace version from the [workspace.package] section of a Cargo.toml.
workspace_version() {
    awk '
        /^\[workspace\.package\]/ { in_pkg = 1; next }
        /^\[/ { in_pkg = 0 }
        in_pkg && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
    ' "$1"
}

# Resolve what to build: sets REF, VERSION, REV7, BUILD_ID.
resolve_ref() {
    local arg="$1"
    if [ "$arg" = "--snapshot" ]; then
        # A dirty tree would make the build id lie about the revision.
        if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
            die "--snapshot needs a clean tree (commit or stash tracked changes first)"
        fi
        REF="HEAD"
    else
        REF="v$arg"
        git rev-parse -q --verify "refs/tags/$REF" >/dev/null || die "tag $REF does not exist"
    fi
    REV7="$(git rev-parse --short=7 "$REF^{commit}")"
    VERSION="$(git show "$REF:Cargo.toml" | workspace_version /dev/stdin)"
    [ -n "$VERSION" ] || die "no [workspace.package] version in Cargo.toml at $REF"
    if [ "$arg" != "--snapshot" ] && [ "$arg" != "$VERSION" ]; then
        die "tag $REF has Cargo.toml version $VERSION, expected $arg"
    fi
    BUILD_ID="$VERSION+$REV7"
}

# Fresh source tree of REF in $SRC (target dir lives outside it and persists).
extract_source() {
    rm -rf "$SRC"
    mkdir -p "$SRC"
    git archive --format=tar "$REF" | tar -x -C "$SRC"
}

build_web_ui() {
    log "web UI: npm ci && npm run build"
    (cd "$SRC/web-ui" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent) >&2
    [ -f "$SRC/web-ui/dist/index.html" ] || die "web UI build produced no dist/index.html"
}

build_target() {
    local target="$1"
    local -a env_extra=()
    if [ "${target%%-*}" = "aarch64" ]; then
        # Raspberry Pi 5 kernels use 16K pages; jemalloc built for 4K aborts there
        # ("Unsupported system page size"). 16K works on 4K kernels too.
        env_extra+=(JEMALLOC_SYS_WITH_LG_PAGE=14)
    fi
    log "building $target ($BUILD_ID)"
    (cd "$SRC" && env "${env_extra[@]}" VIATICUM_BUILD_ID="$BUILD_ID" \
        CARGO_TARGET_DIR="$TARGET_DIR" \
        cargo zigbuild --release --locked -p viaticum --bin viaticum --target "$target") >&2
}

# Who pulls aws-lc-sys into the user build (Р-4′). Prints the inverted tree; empty = none.
# A failing `cargo tree` must not pass as "none": its error goes to stderr and fails the build.
aws_lc_report() {
    local target="$1"
    local out err
    err="$WORK/cargo-tree.err"
    if out="$(cd "$SRC" && cargo tree --locked -e normal -p viaticum --target "$target" -i aws-lc-sys 2>"$err")"; then
        echo "$out"
    elif grep -q "did not match any packages" "$err"; then
        return 0 # not even in Cargo.lock
    else
        cat "$err" >&2
        die "cargo tree failed for $target"
    fi
}

# A static binary has no NEEDED entries in its dynamic section.
check_static() {
    local bin="$1"
    local needed
    needed="$(readelf -d "$bin" 2>/dev/null | grep -c NEEDED || true)"
    [ "$needed" = "0" ] || die "$bin is dynamically linked ($needed NEEDED entries)"
}

main() {
    [ $# -ge 1 ] || usage
    case "$1" in -h | --help) usage ;; esac

    need_tool git "run inside a viaticum git checkout"
    need_tool cargo "source ~/.cargo/env"
    need_tool cargo-zigbuild "cargo install cargo-zigbuild"
    need_tool zig "zig in PATH, e.g. ~/.local/bin/zig"
    need_tool npm "node.js + npm"
    need_tool readelf "binutils"

    cd "$(git rev-parse --show-toplevel)"
    resolve_ref "$1"

    WORK="${VIATICUM_RELEASE_WORK:-$HOME/.cache/viaticum-release}"
    SRC="$WORK/src"
    TARGET_DIR="$WORK/target"
    OUT="$WORK/out/$BUILD_ID"
    local targets="${VIATICUM_TARGETS:-$TARGETS_DEFAULT}"
    log "ref $REF -> build id $BUILD_ID; work dir $WORK"

    extract_source
    build_web_ui
    rm -rf "$OUT"
    mkdir -p "$OUT"

    local target arch bin tree
    for target in $targets; do
        build_target "$target"
        arch="${target%%-*}"
        bin="$TARGET_DIR/$target/release/viaticum"
        [ -x "$bin" ] || die "no binary at $bin"
        check_static "$bin"
        mkdir -p "$OUT/$arch"
        cp "$bin" "$OUT/$arch/viaticum"
        tree="$(aws_lc_report "$target")"
        if [ -n "$tree" ]; then
            echo "$tree" >&2
            die "$target: aws-lc-sys is in the build (R3 Р-4′: rustls must use ring), see the tree above"
        fi
        log "$target: no aws-lc-sys"
        log "$target: $(stat -c %s "$OUT/$arch/viaticum") bytes; $(file -b "$OUT/$arch/viaticum")"
    done
    echo "$BUILD_ID" >"$OUT/VERSION"
    log "done: $OUT"
}

main "$@"
