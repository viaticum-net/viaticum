# Experiment 08: Storage Lie + Proof-of-Storage

## Question
How quickly does proof-of-storage detect liars, and does repair outpace the lie?

## Model
- 500 peers total (400-490 honest + 10-100 liars), 500 files, 5-of-15 erasure coding
- Honest peers: reliability 0.95, always serve shards
- Liars: accept shards honestly, then delete them after `lie_delay` days to free space
- Liars continue answering "online" pings but fail proof-of-storage challenges
- Detection: proof-of-storage checks at configurable intervals (7, 14, 30 days)
- Two repair strategies: PI-only (wait for trust to drop) vs PID-trigger (D detects the drop)
- 12-month simulation, 30 seeds per config

## Sweep Parameters
- n_liars: [10, 25, 50, 100]
- lie_delay_days: [7, 30, 90] — time from accepting shard to deleting it
- check_interval_days: [7, 14, 30] — proof-of-storage frequency
- repair_strategy: [pi_only, pid_trigger]
- 72 configs total, 24 cores, 6.8 minutes

## Key Result

**100% file survival in ALL 72 configurations.** Storage lying is completely harmless with 5-of-15 erasure coding.

Even the worst case (100 liars = 20% of network, monthly checks, deleting after 7 days) results in zero file losses.

## Detection Times

| Check Interval | Lie Delay 7d | Lie Delay 30d | Lie Delay 90d |
|----------------|-------------|--------------|--------------|
| **7 days** | 5.0 days | 3.0 days | 5.9 days |
| **14 days** | 5.0 days | 10.0 days | 6.0 days |
| **30 days** | 23.0 days | 30.0 days | 29.9 days |

Detection time is driven by check interval, not by number of liars. With weekly checks, liars are caught within 3-6 days. Even monthly checks detect liars in ~23-30 days.

## Key Findings

1. **Erasure coding makes storage lying pointless.** With 5-of-15 (tolerance = 10 shards), even 100 liars (20% of network) can't cause any file loss. A file would need 11+ of its 15 shards to be on liars — effectively impossible with random placement.

2. **Proof-of-storage detects liars quickly.** Weekly checks catch liars in 3-6 days. Even monthly checks detect within 30 days. The repair cycle easily outpaces the lying.

3. **D-trigger provides 0% advantage.** With 100% survival everywhere, there's no room for D to help. The system is so resilient that early warning is unnecessary for this attack.

4. **Liar trust does drop.** Liars with monthly checks end up at trust ~2.30 vs honest ~2.47. But this trust drop doesn't matter because the files are already safe. The trust drop is a secondary signal, not the defense.

5. **Number of liars is irrelevant.** 10 vs 100 liars produce identical results. The defense is in the erasure coding, not in detecting the liars.

6. **Lie delay doesn't matter either.** Whether the liar deletes after 7, 30, or 90 days, the result is the same — 100% survival. The lie delay only affects when detection occurs, but detection always happens before enough shards are lost.

## Why This Attack Fails

The fundamental reason: to lose a file with 5-of-15 erasure, you need 11+ shards to be gone. With 20% liars in the network, the expected number of liar shards per file is ~3. Even accounting for variance, the probability of 11+ liar shards on a single file is astronomically small (roughly 10^-8).

Compare with the Sybil attack (Exp 04) where attackers can concentrate shards via subnet manipulation. Storage liars can't concentrate — they're randomly distributed across the network.

## Design Implications

- **Proof-of-storage interval of 7-14 days is sufficient.** Monthly works too, but weekly gives faster detection and less wasted bandwidth (serving data that's already deleted).
- **The real defense against storage lying is erasure coding.** Proof-of-storage is belt-and-suspenders — nice to have, but the system would survive without it.
- **Storage lying is a self-defeating strategy.** The liar gains nothing (they still need to be online, they lose trust, and the freed space is tiny compared to the shard they already committed to the network).
- **No need for complex proof-of-storage protocols.** A simple periodic challenge (send hash of shard + nonce) is enough. The attack is too weak to justify expensive cryptographic proofs.

## Code
`simulations/storage_lie.py` — run with `--sweep --jobs 24`
