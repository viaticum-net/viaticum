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
# Every build compiles the whole workspace from this archive: files are extracted
# with the extraction time as mtime (`tar -m`) into a target dir of their own build
# id. With commit-time mtimes and a shared target dir, cargo saw the sources of an
# older-dated revision as older than the last build and kept its compiled
# viaticum-core: right --version, someone else's core (install-i17).
#
# Checks (any failure = no release, nothing in out/): static ELF (no NEEDED,
# `file` says statically linked); no aws-lc-sys in the tree of either target; the
# binary embeds the fresh index.html and the build id; no path under $HOME in the
# binary (sources are remapped, install-i18); where the binary runs here,
# `--version` = `viaticum <build id>` and `build-info` names the build id and the
# fresh index.html blake3 (M14′).
# Not yet (R3a a4 part 2): manifest tarball, notices, SHA256SUMS, get.sh.
#
# Environment:
#   VIATICUM_RELEASE_WORK  work dir (default ~/.cache/viaticum-release/<checkout
#                          dir name>): source archive, target dir, output. One
#                          build at a time per work dir (flock).
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
    # The binary refuses to compile with a malformed id too (build_info.rs);
    # this names the problem before a long build.
    [[ "$BUILD_ID" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\+[0-9a-f]{7}$ ]] ||
        die "malformed build id '$BUILD_ID' (expected <semver>+<rev7>)"
}

# Fresh source tree of REF in $SRC. `-m`: mtime = now, never the commit time
# (install-i17, see the header).
extract_source() {
    rm -rf "$SRC"
    mkdir -p "$SRC"
    git archive --format=tar "$REF" | tar -x -m -C "$SRC"
}

# The target dir of this build id; target dirs of other build ids are dropped
# (one cold build per release, bounded disk).
prepare_target_dir() {
    local d
    mkdir -p "$WORK/target"
    for d in "$WORK/target"/*; do
        [ -e "$d" ] || continue
        [ "$d" = "$TARGET_DIR" ] || rm -rf "$d"
    done
    mkdir -p "$TARGET_DIR"
}

build_web_ui() {
    log "web UI: npm ci && npm run build"
    (cd "$SRC/web-ui" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent) >&2
    [ -f "$SRC/web-ui/dist/index.html" ] || die "web UI build produced no dist/index.html"
    # The FRESH index.html (copy + hash), kept before cargo embeds anything: the
    # checks compare the binary with this, not with whatever dist/ holds later.
    FRESH_INDEX="$WORK/fresh-index.html"
    cp "$SRC/web-ui/dist/index.html" "$FRESH_INDEX"
    WEB_INDEX_B3="$(b3sum --no-names "$FRESH_INDEX")"
}

build_target() {
    local target="$1"
    local -a env_extra=()
    if [ "${target%%-*}" = "aarch64" ]; then
        # Raspberry Pi 5 kernels use 16K pages; jemalloc built for 4K aborts there
        # ("Unsupported system page size"). 16K works on 4K kernels too.
        env_extra+=(JEMALLOC_SYS_WITH_LG_PAGE=14)
    fi
    # No path under $HOME in the binary (install-i18): Rust (panic locations,
    # file!()) and C (assert __FILE__ in jemalloc, zstd, ring) see remapped paths.
    local registry="$HOME/.cargo/registry/src"
    # rustc: the last matching mapping wins, so the general $HOME goes first.
    local remap="--remap-path-prefix=$HOME=/home --remap-path-prefix=$registry=/cargo/registry --remap-path-prefix=$SRC=/viaticum --remap-path-prefix=$TARGET_DIR=/target"
    local cmap="-ffile-prefix-map=$registry=/cargo/registry -ffile-prefix-map=$SRC=/viaticum -ffile-prefix-map=$TARGET_DIR=/target -ffile-prefix-map=$HOME=/home"
    local tvar="${target//-/_}"
    env_extra+=("CFLAGS_$tvar=$cmap")
    log "building $target ($BUILD_ID)"
    (cd "$SRC" && env "${env_extra[@]}" VIATICUM_BUILD_ID="$BUILD_ID" \
        CARGO_TARGET_DIR="$TARGET_DIR" RUSTFLAGS="$remap" \
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

# The binary must name this build and embed THIS web UI (install-i11, N8, M14′).
# Static check (any target): the fresh dist/index.html bytes and the build id are in
# the binary (rust-embed stores release assets uncompressed). Run check (when the
# binary runs here: host arch, or qemu-aarch64[-static]): `--version` and
# `build-info` report exactly this build id and the fresh index.html hash.
check_identity() {
    local bin="$1" target="$2"
    python3 - "$bin" "$FRESH_INDEX" "$BUILD_ID" <<'PY' || die "$target: binary does not embed the fresh web UI or the build id"
import sys
binary = open(sys.argv[1], "rb").read()
index = open(sys.argv[2], "rb").read()
if binary.find(index) < 0:
    sys.exit("fresh dist/index.html is not embedded")
if binary.find(sys.argv[3].encode()) < 0:
    sys.exit("build id is not in the binary")
PY
    local -a run=()
    if [ "${target%%-*}" != "$(uname -m)" ]; then
        if command -v qemu-aarch64-static >/dev/null 2>&1 && [ "${target%%-*}" = "aarch64" ]; then
            run=(qemu-aarch64-static)
        elif command -v qemu-aarch64 >/dev/null 2>&1 && [ "${target%%-*}" = "aarch64" ]; then
            run=(qemu-aarch64)
        else
            log "$target: not executed here (no qemu-aarch64); static check only"
            return 0
        fi
    fi
    local version info
    version="$("${run[@]}" "$bin" --version)"
    [ "$version" = "viaticum $BUILD_ID" ] || die "$target: --version says '$version', expected 'viaticum $BUILD_ID'"
    info="$("${run[@]}" "$bin" build-info)"
    python3 - "$info" "$BUILD_ID" "$WEB_INDEX_B3" <<'PY' || die "$target: build-info disagrees with this build: $info"
import json, sys
info = json.loads(sys.argv[1])
if info.get("build_id") != sys.argv[2]:
    sys.exit("build_id %r != %r" % (info.get("build_id"), sys.argv[2]))
if info.get("web_ui_index_blake3") != sys.argv[3]:
    sys.exit("web_ui_index_blake3 %r != fresh dist %r" % (info.get("web_ui_index_blake3"), sys.argv[3]))
PY
    log "$target: --version and build-info match ($BUILD_ID, index.html $WEB_INDEX_B3)"
}

# A static ELF: `file` says so (a non-ELF has no dynamic section either), and no
# NEEDED entries in the dynamic section.
check_static() {
    local bin="$1" kind needed
    kind="$(file -b "$bin")"
    case "$kind" in
        ELF*"statically linked"*) ;;
        *) die "$bin is not a static ELF: $kind" ;;
    esac
    needed="$(readelf -d "$bin" 2>/dev/null | grep -c NEEDED || true)"
    [ "$needed" = "0" ] || die "$bin is dynamically linked ($needed NEEDED entries)"
}

# No build-machine path under $HOME in the binary (install-i18).
check_no_home_paths() {
    local bin="$1"
    python3 - "$bin" "$HOME" <<'PY' || die "$bin carries paths under \$HOME (remap missed them)"
import re, sys
data = open(sys.argv[1], "rb").read()
home = sys.argv[2].encode()
n = data.count(home)
if n:
    seen = sorted({m.group(0)[:120].decode("utf-8", "replace")
                   for m in re.finditer(re.escape(home) + rb"[\x21-\x7e]*", data)})
    print("%d occurrences of %s, e.g.:" % (n, sys.argv[2]), file=sys.stderr)
    for s in seen[:10]:
        print("  " + s, file=sys.stderr)
    sys.exit(1)
PY
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
    need_tool b3sum "cargo install b3sum"
    need_tool python3 "python 3"
    need_tool file "file(1)"
    need_tool flock "util-linux"

    cd "$(git rev-parse --show-toplevel)"
    resolve_ref "$1"

    WORK="${VIATICUM_RELEASE_WORK:-$HOME/.cache/viaticum-release/$(basename "$PWD")}"
    SRC="$WORK/src"
    TARGET_DIR="$WORK/target/$BUILD_ID"
    OUT="$WORK/out/$BUILD_ID"
    local targets="${VIATICUM_TARGETS:-$TARGETS_DEFAULT}"
    mkdir -p "$WORK"
    # One build per work dir: the next one would rm -rf this one's source.
    exec 9>"$WORK/.lock"
    flock -n 9 || die "another build_release.sh is running in $WORK"
    log "ref $REF -> build id $BUILD_ID; work dir $WORK"

    extract_source
    prepare_target_dir
    build_web_ui

    # Build and check every target first; out/ gets files only when all passed.
    local target bin tree
    local -a built=()
    for target in $targets; do
        build_target "$target"
        bin="$TARGET_DIR/$target/release/viaticum"
        [ -x "$bin" ] || die "no binary at $bin"
        check_static "$bin"
        check_no_home_paths "$bin"
        check_identity "$bin" "$target"
        tree="$(aws_lc_report "$target")"
        if [ -n "$tree" ]; then
            echo "$tree" >&2
            die "$target: aws-lc-sys is in the build (R3 Р-4′: rustls must use ring), see the tree above"
        fi
        log "$target: no aws-lc-sys; no \$HOME paths"
        log "$target: $(stat -c %s "$bin") bytes; $(file -b "$bin")"
        built+=("$target")
    done
    rm -rf "$OUT"
    mkdir -p "$OUT"
    for target in "${built[@]}"; do
        mkdir -p "$OUT/${target%%-*}"
        cp "$TARGET_DIR/$target/release/viaticum" "$OUT/${target%%-*}/viaticum"
    done
    echo "$BUILD_ID" >"$OUT/VERSION"
    log "done: $OUT"
}

main "$@"
