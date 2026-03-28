<script>
  import { onMount } from 'svelte';

  let devices = $state([]);
  let loading = $state(true);
  let error = $state(null);

  async function fetchDevices() {
    try {
      const res = await fetch('/api/devices');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      devices = await res.json();
      error = null;
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  onMount(fetchDevices);
</script>

{#if loading}
  <p class="muted">Loading...</p>
{:else if error}
  <div class="error-box"><p>{error}</p></div>
{:else if devices.length === 0}
  <p class="muted">No devices registered.</p>
{:else}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Device ID</th>
          <th>Label</th>
          <th>Added</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {#each devices as dev}
          <tr>
            <td class="mono">{dev.device_id_hex.slice(0, 16)}...</td>
            <td>{dev.label}</td>
            <td>{dev.added_at}</td>
            <td>
              {#if dev.is_current}
                <span class="badge badge-current">current</span>
              {:else if dev.revoked}
                <span class="badge badge-revoked">revoked</span>
              {:else}
                <span class="badge badge-active">active</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .badge {
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 4px;
  }
  .badge-current { background: #1f3d6f; color: #58a6ff; }
  .badge-active { background: #1b3d2f; color: #3fb950; }
  .badge-revoked { background: #3d1b1b; color: #f85149; }
</style>
