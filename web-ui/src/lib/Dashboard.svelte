<script>
  import { onMount } from 'svelte';
  import { formatBytes, formatTime } from './utils.js';

  let status = $state(null);
  let error = $state(null);
  let loading = $state(true);
  let warmupCounts = $state({ replicating: 0, restorable: 0, degraded: 0, total: 0 });
  let bannerDismissed = $state(false);

  // The banner shows for the first 24h of cluster lifetime and as long as no file
  // is Restorable yet. Tracked in localStorage so it doesn't reset on page reload.
  const FIRST_SEEN_KEY = 'viaticum_first_seen_ms';
  const DISMISSED_KEY = 'viaticum_warmup_banner_dismissed';
  const ONE_DAY_MS = 24 * 3600 * 1000;

  function rememberFirstSeen() {
    if (!localStorage.getItem(FIRST_SEEN_KEY)) {
      localStorage.setItem(FIRST_SEEN_KEY, String(Date.now()));
    }
  }
  function withinWarmupWindow() {
    const t = parseInt(localStorage.getItem(FIRST_SEEN_KEY) || '0', 10);
    if (!t) return true;
    return Date.now() - t < ONE_DAY_MS;
  }
  function dismissBanner() {
    localStorage.setItem(DISMISSED_KEY, '1');
    bannerDismissed = true;
  }

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

  async function fetchWarmupCounts() {
    try {
      const res = await fetch('/api/files');
      if (!res.ok) return;
      const files = await res.json();
      const counts = { replicating: 0, restorable: 0, degraded: 0, total: files.length };
      for (const f of files) {
        const k = f.effective_status?.kind;
        if (k === 'replicating') counts.replicating++;
        else if (k === 'restorable') counts.restorable++;
        else if (k === 'degraded') counts.degraded++;
      }
      warmupCounts = counts;
    } catch { /* silent — banner just hides */ }
  }

  let showWarmup = $derived(
    !bannerDismissed
    && warmupCounts.total > 0
    && warmupCounts.restorable === 0
    && withinWarmupWindow()
  );

  onMount(() => {
    rememberFirstSeen();
    bannerDismissed = localStorage.getItem(DISMISSED_KEY) === '1';
    fetchStatus();
    fetchWarmupCounts();
    const interval = setInterval(() => {
      fetchStatus();
      fetchWarmupCounts();
    }, 5000);
    return () => clearInterval(interval);
  });
</script>

{#if showWarmup}
  <div class="warmup-banner">
    <div class="warmup-icon">⏳</div>
    <div class="warmup-text">
      <strong>Cluster is warming up.</strong>
      Files are being encrypted and distributed across peers ({warmupCounts.replicating} replicating).
      A file can be restored from the network as soon as enough peers hold its pieces.
      This is expected on day one of a new cluster.
    </div>
    <button class="warmup-close" onclick={dismissBanner} aria-label="Dismiss">×</button>
  </div>
{/if}

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
        <dt>Peers (auth / conn / known)</dt>
        <dd title="authenticated = cert exchange complete (can place/restore); connected = libp2p TCP+Noise live; known = ever seen via identify (DB rows)">
          {status.peer_count_authenticated ?? 0}
          / {status.peer_count_connected ?? 0}
          / {status.peer_count}
        </dd>
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
        <!-- holder-i1/i2: 0 is "no room", never "unlimited"; an unread disk says so -->
        <dd>{status.quota_state === 'unknown'
          ? 'unknown'
          : status.effective_quota_bytes
            ? formatBytes(status.effective_quota_bytes)
            : '0 B — disk at reserve, giving space back'}</dd>
        {#if status.quota_note}
          <dt>Warning</dt>
          <dd>{status.quota_note}</dd>
        {/if}
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
              <th>Link</th>
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
                <td>
                  {#if peer.link === 'auth'}
                    <span class="link-badge link-auth" title="Cert exchange complete; can place/restore symbols.">auth</span>
                  {:else}
                    <span class="link-badge link-known" title="Only PeerRecord row in DB; not currently connected.">known</span>
                  {/if}
                </td>
                <td>{peer.trust.toFixed(3)}</td>
                <td>{formatBytes(peer.bytes_we_store)}</td>
                <td>{formatBytes(peer.bytes_peer_stores)}</td>
                <td>{peer.pos_passes_recent}/{peer.pos_challenges_recent}</td>
                <td>{formatTime(peer.last_seen)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if status.by_importance && status.by_importance.length > 0}
    <section class="table-section">
      <h2>Backup by importance</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Bucket</th>
              <th>Blocks</th>
              <th>P(recoverable)</th>
              <th>Target P</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {#each status.by_importance as entry}
              {@const pct = entry.mean_p_recoverable}
              {@const target = entry.target_p}
              {@const color = entry.status === 'empty' ? 'muted'
                : pct >= target * 0.99 ? 'green'
                : pct >= target * 0.90 ? 'yellow'
                : 'red'}
              <tr>
                <td>{entry.bucket.charAt(0).toUpperCase() + entry.bucket.slice(1)}</td>
                <td>{entry.block_count}</td>
                <td>
                  {#if entry.status === 'empty'}
                    <span class="muted">—</span>
                  {:else}
                    <span class="p-badge p-{color}">{entry.mean_p_recoverable.toFixed(5)}</span>
                  {/if}
                </td>
                <td class="muted">{entry.target_p.toFixed(5)}</td>
                <td>
                  {#if entry.status === 'empty'}
                    <span class="status-pill status-empty">empty</span>
                  {:else if entry.status === 'healthy'}
                    <span class="status-pill status-healthy">healthy</span>
                  {:else}
                    <span class="status-pill status-degraded">degraded</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
{/if}

<style>
  .link-badge {
    display: inline-block;
    font-size: 0.72rem;
    padding: 2px 6px;
    border-radius: 4px;
    line-height: 1;
  }
  .link-auth { background: #1b3d2f; color: #3fb950; }
  .link-known { background: #2d2a1b; color: #d29922; }

  /* Importance bucket table */
  .p-badge {
    display: inline-block;
    font-size: 0.72rem;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: monospace;
  }
  .p-green  { background: #1b3d2f; color: #3fb950; }
  .p-yellow { background: #2d2a1b; color: #d29922; }
  .p-red    { background: #3d1b1b; color: #f85149; }
  .p-muted  { color: #8b949e; }

  .status-pill {
    display: inline-block;
    font-size: 0.72rem;
    padding: 2px 6px;
    border-radius: 4px;
    line-height: 1;
  }
  .status-healthy  { background: #1b3d2f; color: #3fb950; }
  .status-degraded { background: #3d1b1b; color: #f85149; }
  .status-empty    { background: #21262d; color: #8b949e; }
</style>
