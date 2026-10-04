#!/bin/bash
# Check install-i17: a release build of revision B carries B's viaticum-core, also
# right after a build of revision A whose commit is newer than B's.
#
#   packaging/check_rebuild.sh [BUILD_SCRIPT]
#
# BUILD_SCRIPT defaults to packaging/build_release.sh of this checkout; pass a
# mutated copy to see the check go red. In a throwaway clone: commit A puts marker
# A into a viaticum-core error message, commit B (dated a year before A) replaces
# it with marker B. Build A, then B (x86_64 only, one shared work dir), and require
# B's binary to hold marker B and not marker A. Exit 0 = rebuilt, 1 = stale core.
set -euo pipefail
export LC_ALL=C

die() {
    echo "check_rebuild: error: $*" >&2
    exit 2
}

main() {
    local repo script tmp
    repo="$(git rev-parse --show-toplevel)"
    script="$(realpath "${1:-$repo/packaging/build_release.sh}")"
    [ -f "$script" ] || die "no build script $script"
    # Not under /tmp: a tmpfs on the build server; a release build needs gigabytes.
    mkdir -p "$HOME/.cache"
    tmp="$(mktemp -d "$HOME/.cache/viaticum-rebuild-check.XXXXXX")"
    # shellcheck disable=SC2064 # expand $tmp now
    trap "rm -rf '$tmp'" EXIT

    git clone -q "$repo" "$tmp/repo"
    cd "$tmp/repo"
    local file=crates/viaticum-core/src/config/mod.rs
    local needle='toml parse error: {0}'
    grep -qF "$needle" "$file" || die "marker site '$needle' not found in $file"

    local now old
    now="$(date +%s)"
    old=$((now - 365 * 86400))
    sed -i "s/toml parse error: {0}/toml parse error REBUILD_MARK_A: {0}/" "$file"
    GIT_AUTHOR_DATE="@$now" GIT_COMMITTER_DATE="@$now" \
        git -c user.name=check -c user.email=check@localhost commit -qam "rebuild check: A"
    local rev_a
    rev_a="$(git rev-parse HEAD)"
    sed -i "s/REBUILD_MARK_A/REBUILD_MARK_B/" "$file"
    GIT_AUTHOR_DATE="@$old" GIT_COMMITTER_DATE="@$old" \
        git -c user.name=check -c user.email=check@localhost commit -qam "rebuild check: B (older date)"
    local rev_b
    rev_b="$(git rev-parse HEAD)"

    export VIATICUM_RELEASE_WORK="$tmp/work" VIATICUM_TARGETS=x86_64-unknown-linux-musl
    git checkout -q "$rev_a"
    echo "check_rebuild: building A ($rev_a)" >&2
    bash "$script" --snapshot >"$tmp/a.log" 2>&1 || {
        tail -20 "$tmp/a.log" >&2
        die "build of A failed"
    }
    git checkout -q "$rev_b"
    echo "check_rebuild: building B ($rev_b, dated a year earlier)" >&2
    bash "$script" --snapshot >"$tmp/b.log" 2>&1 || {
        tail -20 "$tmp/b.log" >&2
        die "build of B failed"
    }

    local bin
    bin="$(ls "$tmp"/work/out/*+"${rev_b:0:7}"/x86_64/viaticum)"
    local has_a has_b
    has_a="$(grep -c -a REBUILD_MARK_A "$bin" || true)"
    has_b="$(grep -c -a REBUILD_MARK_B "$bin" || true)"
    if [ "$has_b" -gt 0 ] && [ "$has_a" = 0 ]; then
        echo "check_rebuild: PASS — B's binary carries B's viaticum-core (marker B, no marker A)"
        return 0
    fi
    echo "check_rebuild: FAIL — B's binary: marker A $has_a, marker B $has_b (stale viaticum-core)"
    return 1
}

main "$@"
