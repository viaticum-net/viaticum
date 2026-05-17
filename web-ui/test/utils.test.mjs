// Manual verification for pathToB64url.
// Run: node --input-type=module < web-ui/test/utils.test.mjs
// OR:  node web-ui/test/utils.test.mjs

import { pathToB64url } from '../src/lib/utils.js';

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

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
