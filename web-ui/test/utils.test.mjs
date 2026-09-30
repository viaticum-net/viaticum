// Manual verification for pathToB64url.
// Run: node --input-type=module < web-ui/test/utils.test.mjs
// OR:  node web-ui/test/utils.test.mjs

import {
  pathToB64url, describeRestoreJob, explainRestoreRejection, restoreFailureReason,
  restoreAction, tooLargeBadge, isBackedUp,
} from '../src/lib/utils.js';

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

// ASCII sanity: output must match reference value computed without TextEncoder
assert(pathToB64url('/home/user/docs') === 'L2hvbWUvdXNlci9kb2Nz', 'ASCII path encodes correctly');

// Cyrillic: must not throw, must return non-empty string
const cyrillic = pathToB64url('/home/иван/Документы');
assert(typeof cyrillic === 'string' && cyrillic.length > 0, 'Cyrillic path returns non-empty string');

// Emoji: must not throw
const emoji = pathToB64url('/home/user/📁/file.txt');
assert(typeof emoji === 'string' && emoji.length > 0, 'Emoji path returns non-empty string');

// Accented chars
const accents = pathToB64url('/home/André/résumé.txt');
assert(typeof accents === 'string' && accents.length > 0, 'Accented chars return non-empty string');

// Empty string
assert(pathToB64url('') === '', 'Empty string returns empty string');

// No padding chars in any result
for (const [label, val] of [
  ['ASCII', pathToB64url('/home/user/docs')],
  ['Cyrillic', cyrillic],
  ['Emoji', emoji],
  ['Accents', accents],
]) {
  assert(!val.includes('='), `No = padding in ${label} output`);
  assert(!val.includes('+'), `No + in ${label} output`);
  assert(!val.includes('/'), `No / in ${label} output`);
}

// Round-trip sanity (decode and verify for ASCII)
function b64urlDecode(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - s.length % 4) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

assert(b64urlDecode(pathToB64url('/home/user/docs')) === '/home/user/docs', 'ASCII round-trip');
assert(
  b64urlDecode(pathToB64url('/home/иван/Документы')) === '/home/иван/Документы',
  'Cyrillic round-trip'
);

// Restore jobs (restore-i3, i4): a finished job never reads as "started"; nothing
// restored is not ok; each failure names its path and reason.
const baseJob = {
  job_id: 'j1', path: '/home/kolya/photos/', files_total: 3, restored_paths: [],
  staging_path: '/data/restore/j1', submitted_at: '', finished_at: null,
};
const running = describeRestoreJob({ ...baseJob, state: 'running', files_restored: 1, failures: [], outcome: null });
assert(running.ok && running.text.includes('1 of 3'), 'running job shows progress');
assert(!running.hint.includes('did not answer'), 'no wait shown when not waiting');
const waiting = describeRestoreJob({
  ...baseJob, state: 'running', files_restored: 1, failures: [], outcome: null,
  waiting_for_holders_until: '2026-09-27T10:05:00Z',
});
assert(waiting.ok && waiting.hint.includes('did not answer')
  && waiting.hint.includes(new Date('2026-09-27T10:05:00Z').toLocaleString())
  && !waiting.hint.includes('2026-09-27T10:05:00Z'),
  'a job waiting for holders says until when, in local time (restore-i26)');
const nothing = describeRestoreJob({
  ...baseJob, state: 'finished', files_restored: 0, outcome: 'nothing_restored',
  failures: [{ path: '/home/kolya/photos/a.jpg', kind: 'holders_unavailable', detail: 'collected 1 of 3' }],
});
assert(!nothing.ok, 'nothing restored is not ok');
assert(!nothing.text.includes('started'), 'finished job never says started');
assert(nothing.failures[0].includes('/home/kolya/photos/a.jpg') && nothing.failures[0].includes('retry later'),
  'failure names path and reason');
const partial = describeRestoreJob({ ...baseJob, state: 'finished', files_restored: 2, outcome: 'partial', failures: [] });
assert(!partial.ok && partial.hint.includes('NOT protected'), 'partial is not ok and warns about staging');
assert(explainRestoreRejection({ error: 'not_in_catalog', path: '/x' }, 404).includes('/x'), 'rejection names the path');
assert(explainRestoreRejection({ error: 'version_not_found', path: '/x', version: 7, available: [1, 3] }, 404)
  === 'Version 7 not found for /x (available: 1, 3).', 'unknown version names version and available ones');
assert(restoreFailureReason('interrupted').includes('daemon stopped'), 'interrupted reason');

// restore-i28: the owner's blocker estimate never locks the Restore button; it is
// shown as a warning (restore also asks Uncertain / PresumedLost holders, i2).
const blocked = restoreAction({ restore_blocker: { kind: 'insufficient_placements', have: 1, need: 3 } });
assert(blocked.enabled === true, 'blocker does not disable Restore');
assert(blocked.warning.includes('1 of 3'), 'blocker shown as warning text');
const offline = restoreAction({ restore_blocker: { kind: 'all_holders_offline' } });
assert(offline.enabled === true && offline.warning.includes('offline'), 'all holders offline still enabled, warned');
const clear = restoreAction({ restore_blocker: null });
assert(clear.enabled === true && clear.warning === '', 'no blocker: enabled, no warning');

// backup-i4, backup-i7: a too-large file is shown as such, never as backed up.
const big = { size_bytes: 4 * 1024 ** 3, limit_bytes: 256 * 1024 ** 2, since: '2026-09-30' };
assert(tooLargeBadge(null, 'never') === null, 'no mark: no too-large badge');
const neverBadge = tooLargeBadge(big, 'never');
assert(neverBadge.label === 'Too large' && neverBadge.kind === 'bad', 'too-large badge');
assert(neverBadge.tooltip.includes('4.0 GB > 256.0 MB') && neverBadge.tooltip.includes('not backed up'), 'tooltip names sizes');
assert(!neverBadge.tooltip.includes('kept in the network'), 'never backed up: no kept version');
assert(tooLargeBadge(big, '2026-09-01').tooltip.includes('version of 2026-09-01 is kept'), 'grown file names its kept version');
assert(isBackedUp({ last_backed_up: '2026-09-01', too_large: null }) === true, 'backed up file counts');
assert(isBackedUp({ last_backed_up: '2026-09-01', too_large: big }) === false, 'grown file does not count');
assert(isBackedUp({ last_backed_up: 'never' }) === false, 'never does not count');
assert(isBackedUp({ last_backed_up: 'pending' }) === false, 'pending does not count');

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
