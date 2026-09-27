/**
 * Encode a filesystem path as URL-safe base64 (no padding) over UTF-8 bytes.
 * Equivalent to Rust's base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path.as_bytes()).
 * Replaces btoa() which throws InvalidCharacterError on non-ASCII paths
 * (Cyrillic, emoji, accented characters).
 *
 * Manual verification:
 *   pathToB64url('/home/user/docs')          === 'L2hvbWUvdXNlci9kb2Nz'   (ASCII sanity)
 *   pathToB64url('/home/иван/Документы')     // no throw, valid base64url
 *   pathToB64url('/home/user/📁/file.txt')   // no throw, valid base64url
 *   pathToB64url('/home/André/résumé.txt')   // no throw, valid base64url
 *   pathToB64url('')                         === ''
 *
 * Run with: node --input-type=module < web-ui/test/utils.test.mjs
 */
export function pathToB64url(path) {
  const bytes = new TextEncoder().encode(path);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

// Backend emits ISO-8601 with explicit Z (e.g. "2026-05-02T15:22:31Z"), or
// the literal "pending" / "never" sentinel. Render in user's locale.
// Falls back to the raw value if not parseable.
export function formatTime(s) {
  if (!s || s === 'pending' || s === 'never') return s ?? '';
  const t = Date.parse(s);
  if (Number.isNaN(t)) return s;
  return new Date(t).toLocaleString();
}

// Render an EffectiveStatus value (from FileEntry.effective_status or
// VersionEntry.effective_status) as a UI-ready badge spec.
// Returns { label, kind, tooltip } where kind ∈ {pending, working, ok, bad}.
//
// `live` / `target` / `lost` are SYMBOL counts (RaptorQ ESIs), not holders.
// We need `target` symbols to decode; each holder typically carries many.
export function statusBadge(s) {
  if (!s) return { label: 'Pending', kind: 'pending', tooltip: 'Waiting for the encoder.' };
  const pct = (n, d) => d > 0 ? Math.min(100, Math.round((n / d) * 100)) : 0;
  switch (s.kind) {
    case 'queued':
      return { label: 'Queued', kind: 'pending', tooltip: 'In encoder queue, no symbols generated yet.' };
    case 'replicating':
      return {
        label: `Replicating ${pct(s.live, s.target)}%`,
        kind: 'working',
        tooltip: `${s.live} of ${s.target} erasure symbols confirmed across holders. Restore opens at 100 %.`,
      };
    case 'restorable':
      return {
        label: 'Protected',
        kind: 'ok',
        tooltip: `Fully protected: ${s.live} symbols available, only ${s.target} needed. Restore is available now.`,
      };
    case 'degraded': {
      const lostPct = pct(s.lost, s.target);
      return {
        label: `Degraded (${lostPct}% lost)`,
        kind: 'bad',
        tooltip: `${s.lost} of ${s.target} symbols lost; only ${s.live} alive. Repair pipeline is rebuilding from survivors.`,
      };
    }
    default:
      return { label: s.kind ?? 'Unknown', kind: 'pending', tooltip: 'Unrecognised status.' };
  }
}

// Convert a RestoreBlocker JSON (from POST /api/restore 409 body) to a
// human-readable explanation. Returns { reason, hint, eta } strings.
export function explainRestoreBlocker(b) {
  if (!b || !b.kind) return { reason: 'Unknown reason.', hint: '', eta: '' };
  switch (b.kind) {
    case 'insufficient_placements':
      return {
        reason: `Only ${b.have} of ${b.need} erasure symbols available — some holders are offline or haven't accepted yet.`,
        hint: 'Will succeed once enough holders are reachable. Try again after a few minutes, or trigger repair.',
        eta: '',
      };
    case 'all_holders_offline':
      return {
        reason: 'All known holders for this block are offline.',
        hint: 'Wait for at least one holder to come online.',
        eta: '',
      };
    default:
      return { reason: b.kind, hint: '', eta: '' };
  }
}
