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

// Convert a RestoreBlocker JSON (VersionEntry.restore_blocker: the owner's own
// estimate from placement counts) to a human-readable explanation.
// Returns { reason, hint, eta } strings.
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

// The Restore button for one version (restore-i28). Always enabled: the blocker
// is only the owner's estimate from Alive placements, while restore also asks
// Uncertain and PresumedLost holders (restore-i2), which may be back. The
// estimate is shown as a warning next to the button, never as a lock.
export function restoreAction(v) {
  const blocker = v && v.restore_blocker;
  return {
    enabled: true,
    warning: blocker ? explainRestoreBlocker(blocker).reason : '',
  };
}

// ─── Restore jobs (restore-i3, i4) ────────────────────────────────────────────

// Why a file was not restored (RestoreFailure.kind), in words.
export function restoreFailureReason(kind) {
  switch (kind) {
    case 'holders_unavailable': return 'not enough holders answered; retry later';
    case 'not_backed_up': return 'no backed-up version';
    case 'block_missing': return 'its block record is missing from the catalog';
    case 'corrupt': return 'the data did not decode';
    case 'path_unsafe': return 'unsafe path in the catalog';
    case 'write_failed': return 'could not write it into staging';
    case 'interrupted': return 'the daemon stopped before it was restored';
    default: return 'internal error';
  }
}

// A refused restore request (RestoreRejection JSON, `{"error": ...}`) in words.
export function explainRestoreRejection(body, httpStatus) {
  const e = body && body.error;
  switch (e) {
    case 'not_in_catalog': return `${body.path} is not in the backup catalog.`;
    case 'not_backed_up': return `Nothing under ${body.path} has a backed-up version yet.`;
    case 'version_not_found':
      return `Version ${body.version} not found for ${body.path} (available: ${(body.available || []).join(', ')}).`;
    case 'dest_not_supported': return 'Restoring to another destination is not supported.';
    case 'invalid_date': return `Invalid date ${body.date}.`;
    case 'busy': return `The restore queue is full (${body.active} job(s)); try again later.`;
    case 'unavailable': return 'The daemon is not taking restore jobs (shutting down?).';
    case 'unknown_job': return `Unknown restore job ${body.job_id}.`;
    default: return `Restore refused (HTTP ${httpStatus}).`;
  }
}

// The state of a restore job (RestoreJob JSON) as { ok, text, hint, failures }.
// A finished job never reads as "started"; nothing restored is not ok.
export function describeRestoreJob(job) {
  const n = job.files_restored;
  const m = job.files_total;
  if (job.state !== 'finished') {
    return {
      ok: true,
      text: job.state === 'queued'
        ? `Restore queued — files will appear in ${job.staging_path}`
        : `Restoring: ${n} of ${m} restored, ${job.failures.length} failed — files appear in ${job.staging_path}`,
      // restore-i26: holders did not answer; the daemon redialed them and retries
      // then (shown in the browser's local time).
      hint: (job.waiting_for_holders_until
        ? `Holders did not answer; reconnecting and retrying at ${formatTime(job.waiting_for_holders_until)}. `
        : '') + 'Cold backup: this can take hours. You can close this panel; the restore keeps going.',
      failures: [],
    };
  }
  const head = {
    complete: `Restored ${n} of ${m} to ${job.staging_path}`,
    partial: `Restored ${n} of ${m} to ${job.staging_path}`,
    nothing_restored: `Nothing restored (0 of ${m}).`,
    interrupted: `Restore interrupted: the daemon stopped. ${n} of ${m} restored to ${job.staging_path}`,
  }[job.outcome] ?? `Restore finished: ${n} of ${m}`;
  return {
    ok: job.outcome === 'complete',
    text: head,
    hint: n > 0
      ? 'The files are in staging and NOT protected there. Move them into a watched folder (the original one or any other) within ~4 weeks of the deletion to protect them again.'
      : '',
    failures: job.failures.map((f) => `${f.path} — ${restoreFailureReason(f.kind)} (${f.detail})`),
  };
}
