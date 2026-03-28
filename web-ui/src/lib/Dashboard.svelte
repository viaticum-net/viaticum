<script>
  import { onMount } from 'svelte';
  import { formatBytes } from './utils.js';

  let status = $state(null);
  let error = $state(null);
  let loading = $state(true);

  async function fetchStatus() {
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      status = await res.json();
      error = null;
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  });
</script>

{#if loading}
  <p class="muted">Loading...</p>
{:else if error}
  <div class="error-box">
    <p>Cannot reach daemon: {error}</p>
    <button onclick={fetchStatus}>Retry</button>
  </div>
{:else if status}
  <div class="grid">
    <div class="card">
      <h2>Node</h2>
      <dl>
        <dt>Identity</dt>
        <dd class="mono">{status.node_identity.slice(0, 16)}...</dd>
        <dt>Address</dt>
        <dd class="mono truncate">{status.node_addr.slice(0, 40)}...</dd>
        <dt>Peers</dt>
        <dd>{status.peer_count}</dd>
        <dt>Avg Trust</dt>
        <dd>{status.avg_trust.toFixed(3)}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Storage</h2>
      <dl>
        <dt>Holding for others</dt>
        <dd>{formatBytes(status.holding_bytes)}</dd>
        <dt>Quota</dt>
        <dd>{status.effective_quota_bytes ? formatBytes(status.effective_quota_bytes) : 'unlimited'}</dd>
        <dt>Used</dt>
        <dd>{formatBytes(status.used_bytes)}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Backup</h2>
      <dl>
        <dt>Files</dt>
        <dd>{status.backed_up_files}</dd>
        <dt>Total size</dt>
        <dd>{formatBytes(status.backed_up_bytes)}</dd>
        <dt>Blocks OK / At risk</dt>
        <dd>{status.blocks_ok} / {status.blocks_at_risk}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Proof of Storage</h2>
      <dl>
        <dt>Challenges</dt>
        <dd>{status.pos_total_challenges}</dd>
        <dt>Passes</dt>
        <dd>{status.pos_total_passes}</dd>
        <dt>Placements</dt>
        <dd>{status.placement_alive} alive / {status.placement_lost} lost</dd>
      </dl>
    </div>
  </div>

  {#if status.peers.length > 0}
    <section class="table-section">
      <h2>Peers (top {status.peers.length})</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Identity</th>
              <th>Trust</th>
              <th>We store</th>
              <th>They store</th>
              <th>PoS (4w)</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {#each status.peers as peer}
              <tr>
                <td class="mono">{peer.identity_hex}</td>
                <td>{peer.trust.toFixed(3)}</td>
                <td>{formatBytes(peer.bytes_we_store)}</td>
                <td>{formatBytes(peer.bytes_peer_stores)}</td>
                <td>{peer.pos_passes_recent}/{peer.pos_challenges_recent}</td>
                <td>{peer.last_seen}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
{/if}
