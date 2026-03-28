<script>
  let addr = $state('');
  let result = $state(null);
  let connecting = $state(false);

  async function connect() {
    if (!addr.trim()) return;
    connecting = true;
    result = null;
    try {
      const res = await fetch('/api/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ addr: addr.trim() }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text);
      }
      const data = await res.json();
      result = { ok: true, text: `Connected! Peer ID: ${data.peer_id.slice(0, 16)}...` };
      addr = '';
    } catch (e) {
      result = { ok: false, text: `Failed: ${e.message}` };
    } finally {
      connecting = false;
    }
  }
</script>

<div class="connect-form">
  <h2>Connect to Peer</h2>
  <p class="hint">
    Enter the peer's iroh node address. Format: <code>NodeId_hex@ip:port</code>
  </p>

  <div class="input-row">
    <input
      type="text"
      placeholder="abcdef1234...@192.168.1.5:12345"
      bind:value={addr}
      onkeydown={(e) => e.key === 'Enter' && connect()}
      disabled={connecting}
    />
    <button onclick={connect} disabled={connecting || !addr.trim()}>
      {connecting ? 'Connecting...' : 'Connect'}
    </button>
  </div>

  {#if result}
    <div class="result" class:result-ok={result.ok} class:result-err={!result.ok}>
      {result.text}
    </div>
  {/if}
</div>

<style>
  .connect-form {
    max-width: 600px;
  }

  h2 {
    color: #58a6ff;
    font-size: 1.1rem;
    margin: 0 0 0.5rem;
  }

  .hint {
    color: #8b949e;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }

  .hint code {
    background: #1c2128;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 0.8rem;
  }

  .input-row {
    display: flex;
    gap: 0.5rem;
  }

  input {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e1e4e8;
    padding: 0.6rem 0.75rem;
    border-radius: 6px;
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.85rem;
  }

  button {
    background: #238636;
    color: white;
    border: none;
    padding: 0.6rem 1.2rem;
    border-radius: 6px;
    cursor: pointer;
    white-space: nowrap;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .result {
    margin-top: 1rem;
    padding: 0.6rem 0.75rem;
    border-radius: 6px;
    font-size: 0.9rem;
  }
  .result-ok { background: #1b3d2f; color: #3fb950; }
  .result-err { background: #3d1b1b; color: #f85149; }
</style>
