<script>
  import { onMount } from 'svelte';

  // ── State ───────────────────────────────────────────────────────────────────
  let current = $state(null);            // last-fetched config
  let draft = $state(null);              // user-editable copy
  let errors = $state({});               // { 'storage.disk_reserve_gb': 'msg' }
  let loadError = $state(null);          // load-time error
  let phase = $state('idle');            // 'idle' | 'saving' | 'restarting' | 'online' | 'failed'
  let phaseMessage = $state('');         // human text for restarting/failed states
  let loading = $state(true);

  // Field meta for labels + help text. Matches the EditableConfig surface.
  const fields = [
    {
      group: 'Storage',
      key: ['storage', 'disk_reserve_gb'],
      label: 'Disk reserve (GB)',
      help: 'Keep at least this much free space on the data-dir disk. ' +
            'The daemon stops accepting new offers and starts evicting before going below.',
      kind: 'float',
      min: 0,
      max: 1000,
    },
    {
      group: 'Storage',
      key: ['storage', 'soft_quota_gb'],
      label: 'Soft quota (GB)',
      help: 'Maximum amount of data to hold for other peers. 0 = unlimited (use disk-based limit).',
      kind: 'float',
      min: 0,
      max: 100000,
    },
    {
      group: 'Network',
      key: ['network', 'listen_port'],
      label: 'Listen port',
      help: 'libp2p TCP port. 0 = ephemeral (OS picks). Changing this requires a daemon restart.',
      kind: 'int',
      min: 0,
      max: 65535,
    },
  ];

  // ── Helpers ─────────────────────────────────────────────────────────────────
  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  function getVal(obj, keyPath) {
    return keyPath.reduce((acc, k) => acc?.[k], obj);
  }
  function setVal(obj, keyPath, v) {
    let o = obj;
    for (let i = 0; i < keyPath.length - 1; i++) o = o[keyPath[i]];
    o[keyPath[keyPath.length - 1]] = v;
  }
  function dottedKey(keyPath) { return keyPath.join('.'); }

  let dirtyCount = $derived.by(() => {
    if (!current || !draft) return 0;
    let n = 0;
    for (const f of fields) {
      if (getVal(current, f.key) !== getVal(draft, f.key)) n++;
    }
    return n;
  });

  let canSave = $derived.by(() => {
    if (phase === 'saving' || phase === 'restarting') return false;
    if (dirtyCount === 0) return false;
    if (Object.keys(errors).length > 0) return false;
    return true;
  });

  function clientValidate(field, raw) {
    const key = dottedKey(field.key);
    if (raw === '' || raw === null || raw === undefined) {
      errors[key] = 'required';
      return null;
    }
    let v;
    if (field.kind === 'int') {
      if (!/^-?\d+$/.test(String(raw))) { errors[key] = 'must be an integer'; return null; }
      v = parseInt(raw, 10);
    } else {
      v = Number(raw);
      if (!Number.isFinite(v)) { errors[key] = 'must be a finite number'; return null; }
    }
    if (v < field.min || v > field.max) {
      errors[key] = `must be in [${field.min}, ${field.max}]`;
      return null;
    }
    delete errors[key];
    errors = { ...errors };
    return v;
  }

  function handleChange(field, ev) {
    const raw = ev.target.value;
    const v = clientValidate(field, raw);
    if (v === null) return;
    setVal(draft, field.key, v);
    draft = clone(draft);
  }

  // ── Network ─────────────────────────────────────────────────────────────────
  // "HTTP <code>: <the server's text>" — the daemon says why (e.g. a config
  // value it cannot read, daemon-i10); long bodies are cut.
  async function httpError(res) {
    let text = '';
    try { text = (await res.text()).trim(); } catch { /* no body */ }
    if (text.length > 300) text = text.slice(0, 300) + '…';
    return text ? `HTTP ${res.status}: ${text}` : `HTTP ${res.status}`;
  }

  async function fetchConfig() {
    loading = true;
    loadError = null;
    try {
      const res = await fetch('/api/config');
      if (!res.ok) throw new Error(await httpError(res));
      const body = await res.json();
      current = body;
      draft = clone(body);
      errors = {};
    } catch (e) {
      loadError = e.message;
    } finally {
      loading = false;
    }
  }

  async function save() {
    // Re-validate everything client-side.
    errors = {};
    for (const f of fields) {
      clientValidate(f, getVal(draft, f.key));
    }
    if (Object.keys(errors).length > 0) return;

    phase = 'saving';
    phaseMessage = '';
    let res;
    try {
      res = await fetch('/api/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      });
    } catch (e) {
      phase = 'failed';
      phaseMessage = `Network error: ${e.message}`;
      return;
    }
    if (res.status === 400) {
      try {
        const body = await res.json();
        if (body.field) {
          errors[body.field] = body.error || 'invalid';
          errors = { ...errors };
        } else {
          phaseMessage = body.error || 'validation failed';
        }
      } catch {
        phaseMessage = await res.text();
      }
      phase = 'idle';
      return;
    }
    if (!res.ok) {
      phase = 'failed';
      phaseMessage = `Save failed: ${await httpError(res)}`;
      return;
    }

    // PUT succeeded — kick off restart.
    phase = 'restarting';
    phaseMessage = 'Daemon restarting…';
    try {
      await fetch('/api/restart', { method: 'POST' });
    } catch {
      // Connection drop is expected as the daemon goes down.
    }

    // Poll /api/status up to 60s. Parent shutdown can take 20s+ under
    // active backup load (DB Arc held by BackupCoordinator until its
    // current cycle drains); child's open_db_with_retry envelope matches.
    const start = Date.now();
    let online = false;
    while (Date.now() - start < 60_000) {
      await new Promise(r => setTimeout(r, 1000));
      if (Date.now() - start > 15_000 && phaseMessage === 'Daemon restarting…') {
        phaseMessage = 'Daemon restarting… (parent draining, can take up to 60s)';
      }
      try {
        const s = await fetch('/api/status');
        if (s.ok) { online = true; break; }
      } catch { /* still down */ }
    }
    if (online) {
      phase = 'online';
      phaseMessage = 'Daemon back online';
      setTimeout(async () => {
        await fetchConfig();
        if (phase === 'online') { phase = 'idle'; phaseMessage = ''; }
      }, 1500);
    } else {
      phase = 'failed';
      phaseMessage =
        'Daemon did not come back within 60s. The child may still be retrying ' +
        'to acquire the DB lock from the parent — wait a few more seconds and ' +
        'reload the page. If the daemon is truly stuck, check the daemon log ' +
        '(typically ~/.viaticum/main/daemon.log). To restore previous config: ' +
        'rename config.toml.bak → config.toml, then restart the daemon.';
    }
  }

  onMount(fetchConfig);
</script>

<h1>Settings</h1>

{#if loading}
  <p class="muted">Loading…</p>
{:else if loadError}
  <div class="error-box">
    <p>Cannot load config: {loadError}</p>
    <button onclick={fetchConfig}>Retry</button>
  </div>
{:else if current && draft}
  {#each ['Storage', 'Network'] as group}
    <section class="settings-group">
      <h2>{group}</h2>
      {#each fields.filter(f => f.group === group) as f}
        {@const k = dottedKey(f.key)}
        <div class="row">
          <label for={k}>{f.label}</label>
          <input
            id={k}
            type="number"
            step={f.kind === 'int' ? 1 : 'any'}
            min={f.min}
            max={f.max}
            value={getVal(draft, f.key)}
            oninput={(e) => handleChange(f, e)}
            disabled={phase === 'saving' || phase === 'restarting'}
          />
          <p class="help">{f.help}</p>
          {#if errors[k]}
            <p class="field-error">{errors[k]}</p>
          {/if}
        </div>
      {/each}
    </section>
  {/each}

  {#if dirtyCount > 0}
    <p class="dirty-note">
      ⚠ {dirtyCount} change{dirtyCount > 1 ? 's' : ''} pending — daemon will restart.
    </p>
  {/if}

  {#if phase === 'restarting'}
    <div class="phase-banner phase-warn">{phaseMessage}</div>
  {:else if phase === 'online'}
    <div class="phase-banner phase-ok">{phaseMessage}</div>
  {:else if phase === 'failed'}
    <div class="phase-banner phase-bad">{phaseMessage}</div>
  {/if}

  <button class="save-btn" disabled={!canSave} onclick={save}>
    {#if phase === 'saving'}Saving…
    {:else if phase === 'restarting'}Restarting…
    {:else}Save & restart daemon{/if}
  </button>
{/if}

<style>
  h1 { font-size: 1.4rem; color: #58a6ff; margin: 0 0 1rem; }
  .settings-group {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin-bottom: 1rem;
  }
  .settings-group h2 {
    font-size: 1rem;
    color: #58a6ff;
    margin: 0 0 0.8rem;
  }
  .row { margin-bottom: 1rem; }
  .row label {
    display: block;
    font-size: 0.85rem;
    color: #c9d1d9;
    margin-bottom: 0.3rem;
  }
  .row input {
    background: #0d1117;
    color: #e1e4e8;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.4rem 0.6rem;
    font-size: 0.95rem;
    width: 200px;
  }
  .row input:focus { outline: 1px solid #58a6ff; }
  .row .help {
    font-size: 0.78rem;
    color: #8b949e;
    margin: 0.3rem 0 0;
    max-width: 600px;
  }
  .field-error {
    color: #f85149;
    font-size: 0.78rem;
    margin: 0.2rem 0 0;
  }
  .dirty-note {
    color: #d29922;
    font-size: 0.85rem;
    margin: 0.5rem 0 1rem;
  }
  .phase-banner {
    border-radius: 6px;
    padding: 0.6rem 0.9rem;
    margin-bottom: 1rem;
    font-size: 0.85rem;
  }
  .phase-warn { background: #2c2510; border: 1px solid #d29922; color: #e1e4e8; }
  .phase-ok { background: #122d1c; border: 1px solid #3fb950; color: #aff5b4; }
  .phase-bad { background: #2d1b1b; border: 1px solid #f85149; color: #f8a8a8; }
  .save-btn {
    background: #238636;
    color: white;
    border: none;
    padding: 0.55rem 1.2rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
  }
  .save-btn:disabled {
    background: #2d3748;
    color: #8b949e;
    cursor: not-allowed;
  }
  .save-btn:not(:disabled):hover { background: #2ea043; }
</style>
