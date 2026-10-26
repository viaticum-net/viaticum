#!/bin/bash
# Self-test of the log parsers in e2e_lib.sh that carry an E2E bar, on synthetic log lines
# (no daemon, seconds). Run: bash experiments/e2e_lib_selftest.sh  -> exit 0 when all hold.
#
# ss_turns_before_first_pick (backup-i28 bar of local_discovery_test.sh step 5): a pass case,
# a fail case, an SS attempt without offers (not a turn, backup-i28-e), a build without the
# `ss=` field (NOSS, never a pass), a block never picked, no block at all.

set -uo pipefail
VIATICUM_TEST_MACHINE_LOCK_DIR=/nonexistent-selftest  # e2e_lib must not create a lock dir
# shellcheck source=experiments/e2e_lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/e2e_lib.sh"

DIR=$(mktemp -d "${TMPDIR:-/tmp}/e2e-lib-selftest-XXXXXX")
trap 'rm -rf "$DIR"' EXIT
FAILS=0
check() {
    local name="$1" want="$2" got="$3"
    if [ "$got" = "$want" ]; then echo "  ok   $name: $got"
    else echo "  FAIL $name: want '$want', got '$got'"; FAILS=$((FAILS + 1)); fi
}

PHOTO=aaaa000011112222ffffffffffffffffffffffffffffffffffffffffffffffff
T='2026-10-26T12:00:'
created() { echo "${T}$1.000000Z  INFO viaticum::daemon::backup::pipeline: backup: pipeline complete (block record only; worker places) block_id=aaaa000011112222 k=3 n=60 importance=0.05"; }
pick() { echo "${T}$1.000000Z  INFO viaticum::daemon::work_pipeline: work_pipeline: picked block for work block_id=$2 ${3:+ss=$3 }importance=$4 current_alive=0 pool_size=4"; }
done_() { echo "${T}$1.000000Z  INFO viaticum::daemon::work_pipeline: work_pipeline: iteration complete block_id=$2 acked=0 failed=0 encoded=true offered=$3 yielded=false"; }

# Pass: an SS attempt in flight when the photo is created (picked before the window, not
# counted), one SS turn with offers in the window, then the photo.
{
    pick 00 bbbb000000000001 true 1.0
    created 01
    done_ 02 bbbb000000000001 4
    pick 03 bbbb000000000002 true 1.0
    done_ 05 bbbb000000000002 4
    pick 06 aaaa000011112222 false 0.05
} > "$DIR/pass.log"
check "one SS turn: pass" "OK 1 1 5" "$(ss_turns_before_first_pick "$DIR/pass.log" "$PHOTO")"

# Fail: two SS turns with offers before the photo (the starvation backup-i28 removes).
{
    created 00
    pick 01 bbbb000000000002 true 1.0
    done_ 02 bbbb000000000002 4
    pick 03 bbbb000000000003 true 1.0
    done_ 04 bbbb000000000003 2
    pick 05 cccc000000000001 false 0.5
    done_ 06 cccc000000000001 2
    pick 07 aaaa000011112222 false 0.05
} > "$DIR/fail.log"
check "two SS turns: counted" "OK 2 2 7" "$(ss_turns_before_first_pick "$DIR/fail.log" "$PHOTO")"

# backup-i28-e: SS picks without offers (nobody to offer to; parked for a small pool — no
# `iteration complete` line at all) are picks, not turns.
{
    created 00
    pick 01 bbbb000000000002 true 1.0
    done_ 01 bbbb000000000002 0
    pick 02 bbbb000000000003 true 1.0
    pick 03 bbbb000000000004 true 1.0
    done_ 04 bbbb000000000004 3
    pick 05 aaaa000011112222 false 0.05
} > "$DIR/nooffer.log"
check "SS picks without offers are not turns" "OK 1 3 5" "$(ss_turns_before_first_pick "$DIR/nooffer.log" "$PHOTO")"

# A build before backup-i28: picks have no ss= field.
{
    created 00
    pick 01 bbbb000000000002 "" 1.0
    done_ 02 bbbb000000000002 4
    pick 03 aaaa000011112222 "" 0.05
} > "$DIR/noss.log"
check "no ss= field: NOSS" "NOSS 0 0 3" "$(ss_turns_before_first_pick "$DIR/noss.log" "$PHOTO")"

{
    created 00
    pick 01 bbbb000000000002 true 1.0
    done_ 02 bbbb000000000002 4
} > "$DIR/nopick.log"
check "never picked: NOPICK" "NOPICK 1 1 -" "$(ss_turns_before_first_pick "$DIR/nopick.log" "$PHOTO")"

pick 01 bbbb000000000002 true 1.0 > "$DIR/noblock.log"
check "no block: NOBLOCK" "NOBLOCK 0 0 -" "$(ss_turns_before_first_pick "$DIR/noblock.log" "$PHOTO")"

[ "$FAILS" -eq 0 ] && { echo "e2e_lib selftest: PASS"; exit 0; }
echo "e2e_lib selftest: $FAILS FAIL"; exit 1
