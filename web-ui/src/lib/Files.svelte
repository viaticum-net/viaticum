<script>
  import { onMount, onDestroy } from 'svelte';
  import {
    formatBytes, formatTime, statusBadge, tooLargeBadge, isBackedUp, restoreAction,
    explainRestoreRejection, describeRestoreJob,
  } from './utils.js';

  let files = $state([]);            // flat list from API
  let watches = $state([]);          // watch roots from /api/watches
  let tree = $state(null);           // forest: one synthetic root per watch dir
  let expanded = $state(new Set());  // expanded folder paths
  let versions = $state([]);
  let selectedPath = $state(null);
  let filter = $state('');
  let loading = $state(true);
  let error = $state(null);
  let restoreMsg = $state(null);
  let restorePoll = null;             // interval id while a restore job is watched

  async function fetchFiles() {
    loading = true;
    error = null;
    try {
      const [filesRes, watchesRes] = await Promise.all([
        fetch('/api/files'),
        fetch('/api/watches'),
      ]);
      if (!filesRes.ok) throw new Error(`HTTP ${filesRes.status} on /api/files`);
      if (!watchesRes.ok) throw new Error(`HTTP ${watchesRes.status} on /api/watches`);
      files = await filesRes.json();
      watches = await watchesRes.json();
      tree = buildForest(files, watches);
      // Auto-expand watch roots so the user sees their folders right away.
      expanded = new Set(Object.keys(tree.dirs));
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  // Build a forest: each watch root is a top-level node. File paths are
  // displayed relative to whichever watch contains them. Files outside every
  // watch (e.g. residue from a removed watch) land under a synthetic
  // "(unwatched)" group so they don't disappear silently.
  function buildForest(items, watchEntries) {
    // Sort watch paths longest-first so we match the most specific one when
    // future nested-watch support lands. Today the backend rejects nested
    // watches, but harmless either way.
    const roots = [...(watchEntries || [])]
      .map(w => (w.path || '').replace(/\/+$/, ''))
      .filter(Boolean)
      .sort((a, b) => b.length - a.length);

    const forest = { dirs: {}, files: [], total: 0, backed_up: 0, size: 0 };

    function findRoot(filePath) {
      for (const r of roots) {
        if (filePath === r || filePath.startsWith(r + '/')) return r;
      }
      return null;
    }

    function ensureNode(parent, key, name, fullPath) {
      if (!parent.dirs[key]) {
        parent.dirs[key] = {
          name, path: fullPath, dirs: {}, files: [],
          total: 0, backed_up: 0, size: 0,
        };
      }
      return parent.dirs[key];
    }

    // Pre-create a node for every watch even if it has no files yet — that
    // keeps the watch visible in the tree right after it's added.
    for (const r of roots) {
      ensureNode(forest, r, r, r);
    }

    for (const f of items) {
      const root = findRoot(f.path);
      let node;
      let relPath;
      if (root) {
        node = forest.dirs[root];
        relPath = f.path.slice(root.length); // leading "/" or empty for root file
      } else {
        // Fallback bucket for orphan files.
        node = ensureNode(forest, '__unwatched__', '(unwatched)', '__unwatched__');
        relPath = f.path;
      }

      const parts = relPath.split('/').filter(Boolean);
      const fname = parts.pop();
      let parentPath = node.path;
      for (const p of parts) {
        parentPath += '/' + p;
        node = ensureNode(node, parentPath, p, parentPath);
      }
      node.files.push({ ...f, name: fname });
    }

    // Roll up counts (DFS).
    function roll(n) {
      let total = n.files.length;
      let backed = n.files.filter(isBackedUp).length;
      let size = n.files.reduce((s, x) => s + (x.size_bytes || 0), 0);
      for (const child of Object.values(n.dirs)) {
        roll(child);
        total += child.total;
        backed += child.backed_up;
        size += child.size;
      }
      n.total = total;
      n.backed_up = backed;
      n.size = size;
    }
    roll(forest);
    return forest;
  }

  // Filter tree by substring in path. Returns a NEW tree containing only matching files.
  function filterTree(node, q) {
    if (!q) return node;
    const ql = q.toLowerCase();
    function visit(n) {
      const out = { name: n.name, path: n.path, dirs: {}, files: [], total: 0, backed_up: 0, size: 0 };
      for (const f of n.files) {
        if (f.path.toLowerCase().includes(ql)) out.files.push(f);
      }
      for (const [k, child] of Object.entries(n.dirs)) {
        const sub = visit(child);
        if (sub.total > 0) out.dirs[k] = sub;
      }
      let total = out.files.length, backed = out.files.filter(isBackedUp).length;
      let size = out.files.reduce((s, x) => s + (x.size_bytes || 0), 0);
      for (const c of Object.values(out.dirs)) { total += c.total; backed += c.backed_up; size += c.size; }
      out.total = total; out.backed_up = backed; out.size = size;
      return out;
    }
    return visit(node);
  }

  function toggle(path) {
    if (expanded.has(path)) expanded.delete(path); else expanded.add(path);
    expanded = new Set(expanded);
  }

  // When filter active, every matching folder auto-expands.
  $effect(() => {
    if (filter && tree) {
      const f = filterTree(tree, filter);
      const open = new Set();
      function walk(n) { open.add(n.path); for (const c of Object.values(n.dirs)) walk(c); }
      walk(f);
      expanded = open;
    }
  });

  let view = $derived(tree ? filterTree(tree, filter) : null);

  async function fetchVersions(path) {
    selectedPath = path;
    versions = [];
    try {
      const res = await fetch(`/api/versions?path=${encodeURIComponent(path)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      versions = await res.json();
    } catch (e) {
      error = e.message;
    }
  }

  // A restore is a job in the daemon (restore-i4): POST answers 202 with the job,
  // then the job is polled every 2 s while this view is mounted. Leaving the view
  // stops watching, never the restore.
  async function restore(path, version) {
    stopWatching();
    restoreMsg = null;
    try {
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, version }),
      });
      const body = await res.json().catch(() => null);
      if (res.status !== 202 || !body) {
        restoreMsg = { ok: false, text: explainRestoreRejection(body, res.status), failures: [] };
        return;
      }
      restoreMsg = describeRestoreJob(body);
      watchJob(body.job_id);
    } catch (e) {
      restoreMsg = { ok: false, text: `Restore failed: ${e.message}`, failures: [] };
    }
  }

  function watchJob(jobId) {
    restorePoll = setInterval(async () => {
      try {
        const res = await fetch(`/api/restore/jobs/${encodeURIComponent(jobId)}`);
        if (res.status === 404) {
          stopWatching();
          restoreMsg = {
            ok: false,
            text: `Lost track of restore job ${jobId} (daemon restarted?). Check its staging directory.`,
            failures: [],
          };
          return;
        }
        if (!res.ok) return; // transient; try again on the next tick
        const job = await res.json();
        restoreMsg = describeRestoreJob(job);
        if (job.state === 'finished') stopWatching();
      } catch (_) {
        // daemon unreachable for a moment; keep polling
      }
    }, 2000);
  }

  function stopWatching() {
    if (restorePoll !== null) {
      clearInterval(restorePoll);
      restorePoll = null;
    }
  }

  function closeVersions() {
    selectedPath = null;
    versions = [];
    // A watched job keeps reporting here; only a finished report is dismissed.
    if (restorePoll === null) restoreMsg = null;
  }

  onDestroy(stopWatching);
  onMount(fetchFiles);
</script>

<div class="toolbar">
  <input
    type="text"
    placeholder="Filter files..."
    bind:value={filter}
  />
  <button onclick={fetchFiles}>Reload</button>
</div>

{#if loading}
  <p class="muted">Loading...</p>
{:else if error}
  <div class="error-box"><p>{error}</p></div>
{:else if !view || (view.total === 0 && Object.keys(view.dirs).length === 0)}
  <p class="muted">No watch folders configured. Add one on the Folders page.</p>
{:else if view.total === 0 && filter}
  <p class="muted">No files match filter.</p>
{:else}
  <div class="tree">
    {#each Object.values(view.dirs) as dir}
      {@render renderDir(dir, 0)}
    {/each}
    {#each view.files as f}
      {@render renderFile(f, 0)}
    {/each}
  </div>
{/if}

{#snippet renderDir(node, depth)}
  <div class="row dir-row" style="--depth: {depth}" onclick={() => toggle(node.path)} role="button" tabindex="0" onkeydown={(e) => e.key === 'Enter' && toggle(node.path)}>
    <span class="caret">{expanded.has(node.path) ? 'v' : '>'}</span>
    <span class="name dir-name">{node.name}/</span>
    <span class="meta">
      {node.backed_up}/{node.total} files · {formatBytes(node.size)}
    </span>
  </div>
  {#if expanded.has(node.path)}
    {#each Object.values(node.dirs) as sub}
      {@render renderDir(sub, depth + 1)}
    {/each}
    {#each node.files as f}
      {@render renderFile(f, depth + 1)}
    {/each}
  {/if}
{/snippet}

{#snippet renderFile(f, depth)}
  {@const tl = tooLargeBadge(f.too_large, f.last_backed_up)}
  {@const b = tl ?? statusBadge(f.effective_status)}
  <div class="row file-row" style="--depth: {depth}" onclick={() => fetchVersions(f.path)} role="button" tabindex="0" onkeydown={(e) => e.key === 'Enter' && fetchVersions(f.path)}>
    <span class="caret"> </span>
    <span class="name file-name">{f.name}</span>
    <span class="meta">
      <span class="badge badge-{b.kind}" title={b.tooltip}>
        {b.label}
      </span>
      {#if f.local_state === 'present' && !tl}
        {#if f.is_safe_to_delete}
          <!-- delete-i7: the network keeps the current state of your files, not a history;
               a file deleted from this computer leaves the network after the deletion window. Never
               suggest the local copy can go. -->
          <span class="badge badge-ok" title="Reached its target reliability on the network. Keep your local copy: a file deleted from this computer is removed from the network too after the deletion window.">at target</span>
        {:else if f.last_backed_up !== 'pending' && f.last_backed_up !== 'never'}
          <span class="badge badge-working" title="Below its target reliability — the network is still adding redundancy.">below target</span>
        {/if}
      {/if}
      {#if tl}
        {formatBytes(f.too_large.size_bytes)}
        <span class="muted">· {f.last_backed_up === 'never' ? 'not backed up' : `last backed up ${formatTime(f.last_backed_up)}`}</span>
      {:else}
        {formatBytes(f.size_bytes)}
        <span class="muted">· {formatTime(f.last_backed_up)}</span>
      {/if}
    </span>
  </div>
{/snippet}

{#if selectedPath}
  <div class="overlay" onclick={closeVersions} onkeydown={(e) => e.key === 'Escape' && closeVersions()} role="dialog" tabindex="-1">
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div class="panel" onclick={(e) => e.stopPropagation()} role="document">
      <div class="panel-header">
        <h3>Versions: <span class="mono">{selectedPath}</span></h3>
        <button class="close-btn" onclick={closeVersions}>x</button>
      </div>

      {#if restoreMsg}
        <div class="restore-msg" class:restore-ok={restoreMsg.ok} class:restore-err={!restoreMsg.ok}>
          <div>{restoreMsg.text}</div>
          {#if restoreMsg.hint}<div class="restore-hint">{restoreMsg.hint}</div>{/if}
          {#if restoreMsg.failures && restoreMsg.failures.length > 0}
            <div class="restore-hint">Not restored ({restoreMsg.failures.length}):</div>
            <ul class="restore-failures">
              {#each restoreMsg.failures as f}<li class="mono">{f}</li>{/each}
            </ul>
          {/if}
        </div>
      {/if}

      {#if versions.length === 0}
        <p class="muted">Loading versions...</p>
      {:else}
        <table>
          <thead>
            <tr><th>Ver</th><th>Created</th><th>Backed up</th><th>Size</th><th>Status</th><th>Hash</th><th></th></tr>
          </thead>
          <tbody>
            {#each versions as v}
              {@const vb = statusBadge(v.effective_status)}
              {@const action = restoreAction(v)}
              <tr>
                <td>{v.version}</td>
                <td>{formatTime(v.created_at)}</td>
                <td>{formatTime(v.backed_up_at)}</td>
                <td>{formatBytes(v.size_bytes)}</td>
                <td><span class="badge badge-{vb.kind}" title={vb.tooltip}>{vb.label}</span></td>
                <td class="mono">{v.content_hash_hex.slice(0, 12)}...</td>
                <td>
                  <button
                    class="btn-sm"
                    disabled={!action.enabled}
                    onclick={() => restore(selectedPath, v.version)}>Restore</button>
                  {#if action.warning}
                    <div class="restore-warning">May not restore: {action.warning}</div>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
{/if}

<style>
  .toolbar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }
  .toolbar input {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e1e4e8;
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    font-size: 0.9rem;
  }
  .toolbar button {
    background: #238636; color: white; border: none;
    padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer;
  }

  .tree {
    border: 1px solid #30363d;
    border-radius: 6px;
    background: #0d1117;
    padding: 0.25rem 0;
  }
  .row {
    display: flex;
    align-items: center;
    padding: 4px 8px 4px calc(8px + var(--depth) * 18px);
    gap: 0.6rem;
    cursor: pointer;
    user-select: none;
    font-size: 0.88rem;
  }
  .row:hover { background: #1c2128; }
  .caret {
    width: 12px;
    color: #8b949e;
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.78rem;
  }
  .name { flex: 0 0 auto; }
  .dir-name { color: #58a6ff; font-weight: 500; }
  .file-name { color: #e1e4e8; font-family: 'SF Mono', Monaco, Consolas, monospace; }
  .meta {
    margin-left: auto;
    display: flex; align-items: center; gap: 0.5rem;
    color: #8b949e; font-size: 0.78rem;
  }
  .muted { color: #8b949e; }

  .badge {
    font-size: 0.72rem;
    padding: 1px 6px;
    border-radius: 4px;
    cursor: help;
    white-space: nowrap;
  }
  /* pending: not yet started encoding */
  .badge-pending { background: #21262d; color: #8b949e; }
  /* working: encoded, waiting for placements to land */
  .badge-working { background: #3d2b1b; color: #d29922; }
  /* ok: fully restorable */
  .badge-ok { background: #1b3d2f; color: #3fb950; }
  /* bad: degraded, holders lost */
  .badge-bad { background: #3d1b1b; color: #f85149; }

  .overlay {
    position: fixed; inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex; align-items: center; justify-content: center;
    z-index: 100;
  }
  .panel {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 1.5rem; max-width: 800px; width: 90%;
    max-height: 80vh; overflow-y: auto;
  }
  .panel-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 1rem;
  }
  .panel-header h3 { margin: 0; font-size: 1rem; color: #e1e4e8; }
  .close-btn {
    background: none; border: none; color: #8b949e;
    font-size: 1.2rem; cursor: pointer;
  }
  .btn-sm {
    background: #1f6feb; color: white; border: none;
    padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; cursor: pointer;
  }
  .restore-msg {
    padding: 0.5rem 0.75rem; border-radius: 6px;
    margin-bottom: 0.75rem; font-size: 0.85rem;
  }
  .restore-ok { background: #1b3d2f; color: #3fb950; }
  .restore-err { background: #3d1b1b; color: #f85149; }
  .restore-warning {
    margin-top: 0.2rem;
    font-size: 0.75rem;
    color: #d29922;
    max-width: 22rem;
  }
  .restore-failures {
    margin: 4px 0 0 16px;
    padding: 0;
    font-size: 12px;
  }
  .restore-hint {
    margin-top: 0.3rem;
    font-size: 0.78rem;
    opacity: 0.85;
  }
  .btn-sm:disabled {
    opacity: 0.45;
    cursor: not-allowed;
    background: #30363d;
  }
</style>
