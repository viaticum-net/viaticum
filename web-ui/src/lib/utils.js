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
// Returns { label, kind, tooltip } where kind ∈ {pending, working, cold, ok, bad}.
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
    case 'replicated_cold':
      return {
        label: 'Cold',
        kind: 'cold',
        tooltip: `Symbols are placed (${s.live}/${s.target}), but restore is held by escrow until you accumulate enough storage contribution. Typical wait: a few days.`,
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
    case 'escrow_locked': {
      const eta = (b.est_seconds && Number.isFinite(b.est_seconds))
        ? `Estimated unlock in ~${Math.round(b.est_seconds / 3600)}h.`
        : 'No ETA — depends on how long you hold data for other peers.';
      return {
        reason: `Holders refused via escrow. Your restore budget is ${(b.budget_gb ?? 0).toFixed(2)} GB; this block needs ${Number.isFinite(b.needed_gb) ? b.needed_gb.toFixed(2) + ' GB' : 'more than that'}.`,
        hint: 'You earn restore credit by holding other peers\' data. Add more peers (Connect page) and let them place data on you.',
        eta,
      };
    }
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
