<script>
  import Dashboard from './lib/Dashboard.svelte';
  import Files from './lib/Files.svelte';
  import Folders from './lib/Folders.svelte';
  import Devices from './lib/Devices.svelte';
  import Connect from './lib/Connect.svelte';
  import Settings from './lib/Settings.svelte';

  const pages = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'folders', label: 'Folders' },
    { id: 'files', label: 'Files' },
    { id: 'devices', label: 'Devices' },
    { id: 'settings', label: 'Settings' },
    { id: 'connect', label: 'Connect' },
  ];

  let currentPage = $state('dashboard');
</script>

<div class="app">
  <nav>
    <div class="brand">Viaticum</div>
    <ul>
      {#each pages as page}
        <li>
          <button
            class:active={currentPage === page.id}
            onclick={() => currentPage = page.id}
          >
            {page.label}
          </button>
        </li>
      {/each}
    </ul>
  </nav>

  <main>
    {#if currentPage === 'dashboard'}
      <Dashboard />
    {:else if currentPage === 'folders'}
      <Folders />
    {:else if currentPage === 'files'}
      <Files />
    {:else if currentPage === 'devices'}
      <Devices />
    {:else if currentPage === 'settings'}
      <Settings />
    {:else if currentPage === 'connect'}
      <Connect />
    {/if}
  </main>
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f1117;
    color: #e1e4e8;
  }

  :global(.muted) {
    color: #8b949e;
  }

  :global(.mono) {
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.85rem;
  }

  :global(.truncate) {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  :global(.error-box) {
    background: #2d1b1b;
    border: 1px solid #f85149;
    border-radius: 8px;
    padding: 1rem;
  }

  :global(.warmup-banner) {
    display: flex;
    align-items: flex-start;
    gap: 0.8rem;
    background: #2c2510;
    border: 1px solid #d29922;
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 1rem;
    color: #e1e4e8;
    font-size: 0.88rem;
    line-height: 1.4;
  }
  :global(.warmup-icon) {
    font-size: 1.4rem;
    line-height: 1;
  }
  :global(.warmup-text) {
    flex: 1;
  }
  :global(.warmup-text strong) {
    color: #d29922;
    margin-right: 0.4rem;
  }
  :global(.warmup-close) {
    background: none;
    border: none;
    color: #8b949e;
    font-size: 1.4rem;
    line-height: 1;
    cursor: pointer;
    padding: 0 0.2rem;
  }
  :global(.warmup-close:hover) {
    color: #e1e4e8;
  }

  :global(.error-box button) {
    margin-top: 0.5rem;
    background: #f85149;
    color: white;
    border: none;
    padding: 0.4rem 1rem;
    border-radius: 4px;
    cursor: pointer;
  }

  :global(.grid) {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }

  :global(.card) {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
  }

  :global(.card h2) {
    margin: 0 0 0.8rem;
    font-size: 1rem;
    color: #58a6ff;
  }

  :global(dl) { margin: 0; }

  :global(dt) {
    color: #8b949e;
    font-size: 0.8rem;
    margin-top: 0.5rem;
  }

  :global(dd) {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 500;
  }

  :global(.table-section) {
    margin-top: 1rem;
  }

  :global(.table-section h2) {
    font-size: 1.1rem;
    margin-bottom: 0.8rem;
    color: #58a6ff;
  }

  :global(.table-wrap) {
    overflow-x: auto;
  }

  :global(table) {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  :global(th) {
    text-align: left;
    color: #8b949e;
    font-weight: 500;
    padding: 0.5rem;
    border-bottom: 1px solid #30363d;
  }

  :global(td) {
    padding: 0.5rem;
    border-bottom: 1px solid #21262d;
  }

  .app {
    display: flex;
    min-height: 100vh;
  }

  nav {
    width: 180px;
    background: #161b22;
    border-right: 1px solid #30363d;
    padding: 1.5rem 0;
    flex-shrink: 0;
  }

  .brand {
    font-size: 1.3rem;
    font-weight: 600;
    color: #58a6ff;
    padding: 0 1.2rem 1.5rem;
    border-bottom: 1px solid #30363d;
    margin-bottom: 0.75rem;
  }

  ul {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  li button {
    display: block;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    color: #8b949e;
    padding: 0.6rem 1.2rem;
    font-size: 0.9rem;
    cursor: pointer;
    border-left: 3px solid transparent;
  }

  li button:hover {
    color: #e1e4e8;
    background: #1c2128;
  }

  li button.active {
    color: #58a6ff;
    border-left-color: #58a6ff;
    background: #1c2128;
  }

  main {
    flex: 1;
    padding: 2rem;
    max-width: 960px;
  }
</style>
