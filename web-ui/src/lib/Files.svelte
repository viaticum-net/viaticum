<script>
  import { onMount } from 'svelte';
  import { formatBytes } from './utils.js';

  let files = $state([]);
  let versions = $state([]);
  let selectedPath = $state(null);
  let prefix = $state('');
  let loading = $state(true);
  let error = $state(null);
  let restoreMsg = $state(null);

  async function fetchFiles() {
    loading = true;
    error = null;
    try {
      const params = prefix ? `?prefix=${encodeURIComponent(prefix)}` : '';
      const res = await fetch(`/api/files${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      files = await res.json();
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

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

  async function restore(path, version) {
    restoreMsg = null;
    try {
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, version }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
      }
      const data = await res.json();
      restoreMsg = { ok: true, text: `Restore started: ${data.path} v${data.version_used}` };
    } catch (e) {
      restoreMsg = { ok: false, text: `Restore failed: ${e.message}` };
    }
  }

  function closeVersions() {
    selectedPath = null;
    versions = [];
    restoreMsg = null;
  }

  onMount(fetchFiles);
</script>

<div class="toolbar">
  <input
    type="text"
    placeholder="Filter by path prefix..."
    bind:value={prefix}
    onkeydown={(e) => e.key === 'Enter' && fetchFiles()}
  />
  <button onclick={fetchFiles}>Search</button>
</div>

{#if loading}
  <p class="muted">Loading...</p>
{:else if error}
  <div class="error-box"><p>{error}</p></div>
{:else if files.length === 0}
  <p class="muted">No files found.</p>
{:else}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Path</th>
          <th>Versions</th>
          <th>Size</th>
          <th>Status</th>
          <th>Last backed up</th>
        </tr>
      </thead>
      <tbody>
        {#each files as file}
          <tr class="clickable" onclick={() => fetchVersions(file.path)}>
            <td class="mono path-cell">{file.path}</td>
            <td>{file.versions}</td>
            <td>{formatBytes(file.size_bytes)}</td>
            <td>
              <span class="badge" class:badge-ok={file.local_state === 'present'} class:badge-warn={file.local_state !== 'present'}>
                {file.local_state}
              </span>
            </td>
            <td>{file.last_backed_up}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

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
          {restoreMsg.text}
        </div>
      {/if}

      {#if versions.length === 0}
        <p class="muted">Loading versions...</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Ver</th>
              <th>Created</th>
              <th>Backed up</th>
              <th>Size</th>
              <th>Hash</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each versions as v}
              <tr>
                <td>{v.version}</td>
                <td>{v.created_at}</td>
                <td>{v.backed_up_at}</td>
                <td>{formatBytes(v.size_bytes)}</td>
                <td class="mono">{v.content_hash_hex.slice(0, 12)}...</td>
                <td>
                  <button class="btn-sm" onclick={() => restore(selectedPath, v.version)}>
                    Restore
                  </button>
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
    background: #238636;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
  }

  .clickable {
    cursor: pointer;
  }
  .clickable:hover td {
    background: #1c2128;
  }

  .path-cell {
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .badge {
    font-size: 0.75rem;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .badge-ok { background: #1b3d2f; color: #3fb950; }
  .badge-warn { background: #3d2b1b; color: #d29922; }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1.5rem;
    max-width: 800px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .panel-header h3 {
    margin: 0;
    font-size: 1rem;
    color: #e1e4e8;
  }

  .close-btn {
    background: none;
    border: none;
    color: #8b949e;
    font-size: 1.2rem;
    cursor: pointer;
  }

  .btn-sm {
    background: #1f6feb;
    color: white;
    border: none;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.8rem;
    cursor: pointer;
  }

  .restore-msg {
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    margin-bottom: 0.75rem;
    font-size: 0.85rem;
  }
  .restore-ok { background: #1b3d2f; color: #3fb950; }
  .restore-err { background: #3d1b1b; color: #f85149; }
</style>
