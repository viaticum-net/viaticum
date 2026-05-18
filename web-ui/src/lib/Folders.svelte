<script>
  import { onMount, onDestroy } from 'svelte';
  import { pathToB64url } from './utils.js';

  let folders = $state([]);
  let error = $state(null);
  let loading = $state(true);

  // Dialog state
  let showAddDialog = $state(false);
  let showEditDialog = $state(false);
  let showDeleteDialog = $state(false);
  let dialogError = $state(null);

  // Add dialog fields
  let addPath = $state('');
  let addImportance = $state(1.0);

  // Inline folder picker
  let browse = $state(null);   // { path, parent, entries: [{name,is_dir}] } | null
  let browseError = $state(null);

  async function openBrowser() {
    browseError = null;
    await fetchBrowse(addPath.trim() || '~');
  }
  async function fetchBrowse(p) {
    try {
      const res = await fetch(`/api/browse?path=${encodeURIComponent(p)}`);
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t);
      }
      browse = await res.json();
    } catch (e) {
      browseError = e.message;
      browse = null;
    }
  }
  function useCurrentAsPath() {
    if (browse) addPath = browse.path;
    browse = null;
  }
  function descend(name) {
    const next = browse.path.endsWith('/')
      ? browse.path + name
      : browse.path + '/' + name;
    fetchBrowse(next);
  }
  function goUp() {
    if (browse && browse.parent) fetchBrowse(browse.parent);
  }

  // Edit dialog
  let editEntry = $state(null);
  let editImportance = $state(1.0);

  // Delete dialog
  let deleteEntry = $state(null);
  let deletePurge = $state(false);

  async function fetchFolders() {
    try {
      const res = await fetch('/api/watches');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      folders = await res.json();
      error = null;
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function addFolder() {
    dialogError = null;
    try {
      const res = await fetch('/api/watches', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: addPath, importance_multiplier: addImportance }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
      }
      showAddDialog = false;
      addPath = '';
      addImportance = 1.0;
      await fetchFolders();
    } catch (e) {
      dialogError = e.message;
    }
  }

  async function patchFolder() {
    dialogError = null;
    try {
      const b64 = pathToB64url(editEntry.path);
      const res = await fetch(`/api/watches/${b64}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ importance_multiplier: editImportance }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
      }
      showEditDialog = false;
      editEntry = null;
      await fetchFolders();
    } catch (e) {
      dialogError = e.message;
    }
  }

  async function deleteFolder() {
    dialogError = null;
    try {
      const b64 = pathToB64url(deleteEntry.path);
      const res = await fetch(`/api/watches/${b64}?purge=${deletePurge}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
      }
      showDeleteDialog = false;
      deleteEntry = null;
      deletePurge = false;
      await fetchFolders();
    } catch (e) {
      dialogError = e.message;
    }
  }

  async function rescan(entry) {
    const b64 = pathToB64url(entry.path);
    try {
      await fetch(`/api/watches/${b64}/scan`, { method: 'POST' });
    } catch (e) {
      // best-effort
    }
  }

  async function refreshRollups() {
    try {
      await fetch('/api/watches/refresh', { method: 'POST' });
      await fetchFolders();
    } catch (e) {
      // best-effort
    }
  }

  function openEdit(entry) {
    editEntry = entry;
    editImportance = entry.importance_multiplier;
    dialogError = null;
    showEditDialog = true;
  }

  function openDelete(entry) {
    deleteEntry = entry;
    deletePurge = false;
    dialogError = null;
    showDeleteDialog = true;
  }

  function statusDot(status, tl) {
    if (tl === 'green') return '🟢';
    if (tl === 'yellow') return '🟡';
    if (tl === 'orange') return '🟠';
    if (tl === 'red') return '🔴';
    return '⚪';
  }

  function statusLabel(status) {
    return status.charAt(0).toUpperCase() + status.slice(1);
  }

  onMount(() => {
    fetchFolders();
    const id = setInterval(fetchFolders, 5000);
    return () => clearInterval(id);
  });
</script>

<div class="folders-page">
  <div class="page-header">
    <h1>Folders</h1>
    <div class="header-actions">
      <button onclick={refreshRollups} class="btn-secondary">Refresh stats</button>
      <button onclick={() => { showAddDialog = true; dialogError = null; addPath = ''; addImportance = 1.0; }} class="btn-primary">
        + Add folder
      </button>
    </div>
  </div>

  {#if loading && folders.length === 0}
    <p class="muted">Loading...</p>
  {:else if error}
    <div class="error-box">
      <strong>Error:</strong> {error}
      <button onclick={fetchFolders}>Retry</button>
    </div>
  {:else if folders.length === 0}
    <p class="muted">No folders configured. Click "Add folder" to start watching a directory.</p>
  {:else}
    <div class="folder-list">
      {#each folders as entry}
        <div class="folder-card card">
          <div class="folder-header">
            <div class="folder-path">
              <span class="traffic-dot">{statusDot(entry.status, entry.traffic_light)}</span>
              <span class="mono truncate">{entry.path}</span>
            </div>
            <div class="folder-actions">
              <button class="icon-btn" onclick={() => rescan(entry)} title="Rescan now">↺</button>
              <button class="icon-btn" onclick={() => openEdit(entry)} title="Edit">✏</button>
              <button class="icon-btn danger" onclick={() => openDelete(entry)} title="Remove">🗑</button>
            </div>
          </div>

          <div class="folder-meta">
            <span class="badge badge-{entry.traffic_light}">{statusLabel(entry.status)}</span>
            <span class="muted">importance: {(entry.importance_multiplier ?? entry.importance ?? 1.0).toFixed(1)}×</span>
            {#if entry.rollup_age_secs !== null}
              <span class="muted">stats {Math.round(entry.rollup_age_secs / 60)}m old</span>
            {/if}
          </div>

          <div class="folder-stats">
            <span>Files: <strong>{entry.total_files}</strong></span>
            <span>Backed up: <strong>{entry.backed_up}</strong></span>
            {#if entry.at_risk > 0}
              <span class="warn">At risk: <strong>{entry.at_risk}</strong></span>
            {/if}
            {#if entry.lost > 0}
              <span class="danger-text">Lost: <strong>{entry.lost}</strong></span>
            {/if}
            {#if entry.encoding > 0}
              <span>Encoding: <strong>{entry.encoding}</strong></span>
            {/if}
          </div>

          {#if entry.status === 'error' && entry.error}
            <div class="folder-error muted">Error: {entry.error}</div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Add folder dialog -->
{#if showAddDialog}
  <div class="dialog-backdrop" onclick={() => showAddDialog = false}>
    <div class="dialog" onclick={(e) => e.stopPropagation()}>
      <h2>Add folder</h2>
      <label>
        Path
        <div class="path-row">
          <input
            type="text"
            bind:value={addPath}
            placeholder="/home/user/Documents"
            class="input-full"
          />
          <button type="button" class="btn-secondary" onclick={openBrowser}>Browse…</button>
        </div>
      </label>

      {#if browse}
        <div class="picker">
          <div class="picker-header">
            <span class="mono picker-path">{browse.path}</span>
            <div>
              <button type="button" class="btn-secondary btn-sm" onclick={goUp} disabled={!browse.parent}>↑ Up</button>
              <button type="button" class="btn-primary btn-sm" onclick={useCurrentAsPath}>Use this folder</button>
            </div>
          </div>
          {#if browse.entries.length === 0}
            <p class="muted">(no subdirectories)</p>
          {:else}
            <ul class="picker-list">
              {#each browse.entries as e}
                <li><button type="button" onclick={() => descend(e.name)}>📁 {e.name}</button></li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}
      {#if browseError}
        <p class="dialog-error">{browseError}</p>
      {/if}
      <label>
        Importance: {addImportance.toFixed(1)}×
        <input
          type="range"
          bind:value={addImportance}
          min="0" max="2" step="0.1"
          class="input-full"
        />
      </label>
      {#if dialogError}
        <p class="dialog-error">{dialogError}</p>
      {/if}
      <div class="dialog-buttons">
        <button onclick={() => showAddDialog = false} class="btn-secondary">Cancel</button>
        <button onclick={addFolder} class="btn-primary" disabled={!addPath.trim()}>Save</button>
      </div>
    </div>
  </div>
{/if}

<!-- Edit dialog -->
{#if showEditDialog && editEntry}
  <div class="dialog-backdrop" onclick={() => showEditDialog = false}>
    <div class="dialog" onclick={(e) => e.stopPropagation()}>
      <h2>Edit folder</h2>
      <p class="mono">{editEntry.path}</p>
      <label>
        Importance: {editImportance.toFixed(1)}×
        <input
          type="range"
          bind:value={editImportance}
          min="0" max="2" step="0.1"
          class="input-full"
        />
      </label>
      {#if dialogError}
        <p class="dialog-error">{dialogError}</p>
      {/if}
      <div class="dialog-buttons">
        <button onclick={() => showEditDialog = false} class="btn-secondary">Cancel</button>
        <button onclick={patchFolder} class="btn-primary">Save</button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete dialog -->
{#if showDeleteDialog && deleteEntry}
  <div class="dialog-backdrop" onclick={() => showDeleteDialog = false}>
    <div class="dialog" onclick={(e) => e.stopPropagation()}>
      <h2>Stop watching folder?</h2>
      <p class="mono">{deleteEntry.path}</p>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={deletePurge} />
        Also delete network copies (purge)
      </label>
      <p class="muted warn-text">
        {#if deletePurge}
          Network copies will be queued for deletion. This is irreversible.
        {:else}
          Existing backups remain available. Only monitoring stops.
        {/if}
      </p>
      {#if dialogError}
        <p class="dialog-error">{dialogError}</p>
      {/if}
      <div class="dialog-buttons">
        <button onclick={() => showDeleteDialog = false} class="btn-secondary">Cancel</button>
        <button onclick={deleteFolder} class="btn-danger">
          {deletePurge ? 'Stop & Purge' : 'Stop watching'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .folders-page {
    width: 100%;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.5rem;
  }

  .page-header h1 {
    font-size: 1.4rem;
    font-weight: 600;
    color: #58a6ff;
    margin: 0;
  }

  .header-actions {
    display: flex;
    gap: 0.5rem;
  }

  .folder-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .folder-card {
    padding: 1rem;
  }

  .folder-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.5rem;
  }

  .folder-path {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-width: 0;
    flex: 1;
  }

  .traffic-dot {
    font-size: 0.8rem;
    flex-shrink: 0;
  }

  .folder-actions {
    display: flex;
    gap: 0.3rem;
    flex-shrink: 0;
  }

  .folder-meta {
    display: flex;
    gap: 1rem;
    align-items: center;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
  }

  .folder-stats {
    display: flex;
    gap: 1.2rem;
    font-size: 0.85rem;
    flex-wrap: wrap;
  }

  .folder-error {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: #f85149;
  }

  .badge {
    font-size: 0.75rem;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-weight: 500;
  }

  .badge-green { background: #1a3d1a; color: #3fb950; }
  .badge-yellow { background: #3d3019; color: #d29922; }
  .badge-orange { background: #3d2219; color: #f0883e; }
  .badge-red { background: #3d1a1a; color: #f85149; }

  .warn { color: #d29922; }
  .danger-text { color: #f85149; }

  .icon-btn {
    background: none;
    border: 1px solid #30363d;
    color: #8b949e;
    width: 28px;
    height: 28px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.85rem;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }

  .icon-btn:hover {
    color: #e1e4e8;
    border-color: #58a6ff;
  }

  .icon-btn.danger:hover {
    color: #f85149;
    border-color: #f85149;
  }

  .btn-primary {
    background: #1f6feb;
    color: white;
    border: none;
    padding: 0.4rem 0.9rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .btn-primary:hover:not(:disabled) { background: #388bfd; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-secondary {
    background: none;
    color: #8b949e;
    border: 1px solid #30363d;
    padding: 0.4rem 0.9rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .btn-secondary:hover { color: #e1e4e8; border-color: #8b949e; }

  .btn-danger {
    background: #b91c1c;
    color: white;
    border: none;
    padding: 0.4rem 0.9rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .btn-danger:hover { background: #dc2626; }

  /* Dialogs */
  .dialog-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.5rem;
    width: 400px;
    max-width: 90vw;
  }

  .dialog h2 {
    margin: 0 0 1rem;
    font-size: 1.1rem;
    color: #58a6ff;
  }

  .dialog label {
    display: block;
    margin-bottom: 1rem;
    font-size: 0.9rem;
    color: #8b949e;
  }

  .input-full {
    display: block;
    width: 100%;
    margin-top: 0.3rem;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e1e4e8;
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    font-size: 0.9rem;
    box-sizing: border-box;
  }

  input[type="range"].input-full {
    padding: 0;
    border: none;
    background: none;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    color: #e1e4e8;
  }

  .warn-text {
    font-size: 0.8rem;
    margin-top: 0.3rem;
  }

  .dialog-error {
    color: #f85149;
    font-size: 0.85rem;
    margin: 0.5rem 0;
  }

  .path-row {
    display: flex;
    gap: 0.5rem;
    align-items: stretch;
  }
  .path-row input { flex: 1; }

  .picker {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin: 0.5rem 0;
    max-height: 240px;
    overflow-y: auto;
  }
  .picker-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem;
    border-bottom: 1px solid #30363d;
    position: sticky; top: 0;
    background: #0d1117;
    gap: 0.5rem;
  }
  .picker-path {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    font-size: 0.85rem;
  }
  .picker-list {
    list-style: none;
    margin: 0;
    padding: 0.25rem 0;
  }
  .picker-list li button {
    display: block;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    color: #e1e4e8;
    padding: 0.4rem 0.75rem;
    cursor: pointer;
    font-size: 0.9rem;
  }
  .picker-list li button:hover { background: #1c2128; }
  .btn-sm { font-size: 0.75rem; padding: 0.2rem 0.5rem; }

  .dialog-buttons {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
