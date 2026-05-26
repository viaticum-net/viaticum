# Backup flow: detailed diagram

---

## 1. Change detection

### Watcher (continuous)

fs-notify watches the backup directories and classifies events:

```
Event                Action
──────────           ──────────────────────────
File created         → dirty_files.insert(path, Added)
File modified        → dirty_files.insert(path, Modified)
File deleted         → dirty_files.insert(path, Deleted)
```

**Debounce:** 30 minutes after the last event for a given path. If an editor saves a file 10 times, only one dirty entry is created. If 50 photos are imported over 5 minutes, we wait 30 minutes after the last one, then flush.

**dirty_files** — an in-RAM set, periodically persisted to the DB for crash safety.

### Full scan (fallback)

The watcher may miss events (daemon restart, system sleep, fs-notify buffer overflow).

On daemon startup: walk all backup dirs → compute content_hash for each file → compare with the catalog → any discrepancies → add to dirty.

This runs only on restart, not every week.

---

## 2. Backup trigger

**Event-driven, NOT once a week.** "Time constant = 1 week" refers to PoS/repair/trust, not to backup scheduling.

### Packing queues

Three queues, one per data type:

```
photo_queue:    [img1.jpg, img2.jpg, ...]
document_queue: [report.docx, notes.md, ...]
large_files:    [video.mp4]                    // ≥128 MB (source_block_size), handled separately immediately
```

### Flush conditions (any one is sufficient)

```
1. Queue ≥ source_block_size (128 MB) → flush immediately (full batch)
2. No activity for 1 hour             → flush whatever is queued (user finished working)
3. 24 hours have elapsed              → flush whatever is queued (fallback)

Min batch size: 1 MB. Smaller than that — wait for the next flush.
```

---

## 3. BackupCoordinator: processing dirty entries

```
for each (path, event) in dirty_files:

  DELETED:
    → FileRecord.local_state = Deleted(ts) on this device
    → if ALL devices = Deleted → start cooldown (4+4 = 8 weeks)
    → no network activity
    → done

  ADDED:
    → read file → content_hash = blake3(file)
    → dedup: is content_hash already in catalog?
      → yes: add device/path to FileRecord → done (zero traffic)
      → no: classify file type → add to packing queue

  MODIFIED:
    → read file → new content_hash
    → dedup: is new content_hash already in catalog?
      → yes: add as a new version → done (zero traffic)
      → no: classify → packing queue
    → FileRecord.versions.push(new_version)
```

---

## 4. Packing → source blocks

```
Flush photo_queue (≥128 MB or timer):
  files = photo_queue.drain()

  group into batches ~128 MB:
    batch_1: [img1(5MB), img2(8MB), img3(3MB), ...] = ~128 MB
    batch_2: [img11(10MB), img12(7MB), ...]          = ~128 MB
    last_batch: [img45(3MB), img46(5MB)]              = ~8 MB (< 50, ok)

  for each batch:
    plaintext = [PackIndex (CBOR)] + [file1 bytes] + [file2 bytes] + ...
    → zstd compress (streaming)
    → ChaCha20-Poly1305 encrypt (streaming)
    → ciphertext = source block
    → source_block_id = blake3(ciphertext)

Flush large_files:
  for each file ≥ 128 MB (source_block_size):
    → compress → encrypt → own source block
```

---

## 5. Encode → placement → distribute

```
for each source_block:
  K = ceil(source_block_size / T)         // T = 64 KB default
  N = K × overhead(importance)            // overhead = 1.5 + imp × 1.5

  // Placement
  holders = placement_engine.compute_allocation(
    candidates,
    weight: trust / sqrt(1 - trust),     // mean-variance optimum
    max_per_holder: min(K_eff - 1, concentration_cap × N),
    max_holders: 30,                      // MAX_HOLDERS_PER_BLOCK
    min_symbols: 32,                      // MIN_SYMBOLS_PER_HOLDER
  )
  // Symbols allocated proportionally to weight (NOT equally!)

  // ESI allocation
  esi_offset = 0
  for each holder:
    esi_range = (esi_offset, holder.symbols_allocated)
    esi_offset += holder.symbols_allocated

    // Generate + encrypt + send
    for esi in esi_range:
      symbol = raptorq.encode(source_block, esi)
      bound = symbol XOR ChaCha20(HKDF(source_block_id, holder_id))

      try direct_connection(holder):
        send(bound)                        // 64 KB
      fail:
        queue symbol_offer via epidemic relay
        // holder picks up the offer → direct connection later → send
```

---

## 6. Holder accepts symbols

```
Holder receives symbol_offer:
  → check: is there space? (effective_quota)
  → check: is eviction priority of the new symbol > min existing?
  → accept / reject

Holder receives symbols:
  → verify: hash(received) matches expected
  → store to disk
  → update held_symbols DB
  → send symbol_stored confirmation

Owner receives confirmation:
  → SymbolPlacement.status = Alive
  → RAM hot: total_alive += symbols_stored
  → EventLog: Placed { source_block_id, holder_id, esi_range }
```

---

## 7. DB updates (summary)

```
After a successful backup cycle:

FileRecord:
  new: { path, importance, devices: [(this_device, Present)],
         versions: [{ content_hash, source_block_id, ts }] }
  or: existing → add version / add device

SourceBlock:
  new: { block_id, K, T, type: Pack{index}/Single, status: Active }

SymbolPlacement × N_holders:
  new: { holder_id, esi_ranges, binding_seed, status: Alive }

EventLog:
  append: Placed events

RAM hot:
  BlockAgg: { K, total_alive }
  PlacementAgg: { symbol_count, status, last_pos }
```

---

## 8. Full picture

```
         Watcher (fs-notify, continuous)
                  │
                  ▼
         dirty_files (RAM + persist)
                  │
         debounce 30 min
                  │
                  ▼
         BackupCoordinator
                  │
      ┌───────────┼────────────┐
      ▼           ▼            ▼
   DELETED     DEDUP?      ADDED/MODIFIED
   → mark      → skip      │
   → cooldown   (zero       classify by type
                traffic)    │
                    ┌───────┼────────┐
                    ▼       ▼        ▼
                 photos   docs    large files
                 queue    queue   (immediate)
                    │       │        │
              ──────┼───────┼────────┼──── flush trigger:
              │  ≥128MB / 1hr idle / 24hr fallback
              │  min batch: 1 MB
                    │       │        │
                    ▼       ▼        ▼
                  batch   batch   source
                  ~128MB   ~128MB   block
                    │       │        │
                    └───────┼────────┘
                            ▼
                   compress → encrypt → source block
                            │
                            ▼
                   RaptorQ encode (K symbols, N total)
                            │
                            ▼
                   per-holder ChaCha20 bind
                            │
                   placement (trust/√(1-t) weight)
                            │
                   ┌────────┼────────┐
                   ▼        ▼        ▼
                holder   holder   holder
                online   online   offline
                → send   → send   → relay offer
                → stored → stored → send later
                            │
                            ▼
                   DB update: FileRecord, SourceBlock,
                   SymbolPlacement, EventLog, RAM hot
```

---

## 9. Timing examples

```
Photographer imports 50 photos (500 MB):
  17:00 — import
  17:01 — watcher: 50 dirty entries
  17:30 — debounce expired
  17:31 — flush: 4 batches × 128 MB
  17:35 — encode + distribute done
  Total: 35 minutes from import to backed up.

A single document changed (200 KB):
  10:00 — save
  10:30 — debounce expired
  10:30 — < 1 MB in queue → wait
  ... 3 more documents during the day ...
  18:00 — 1 hour of inactivity → flush (4 files, 800 KB < 1 MB → wait)
  Next day 10:30 — 24hr fallback → flush whatever is queued
  Or: more files added → ≥ 1 MB → flush.

2 GB video:
  20:00 — file created
  20:30 — debounce expired
  20:31 — ≥ 128 MB (source_block_size) → 16 source blocks
  20:35 — encode (K=2048, N≈3999 at imp=0.3)
  20:40 — distribute to 15 holders (~260 MB each)
  ~21:00 — backed up (depends on upload speed)
```
