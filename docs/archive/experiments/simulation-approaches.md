# Overview of Simulation Approaches for P2P Storage Systems

## Conclusion: what we use

**Python + numpy + SimPy.** Computationally lightweight — PID reputation is arithmetic on arrays; 10K peers × 10K steps takes seconds. 24 cores are used for parallel Monte Carlo runs (joblib.Parallel). Rust/Go would be overkill for simulation; they are suited to protocol implementation.

## Frameworks: what is alive in 2025–2026

| Tool | Status | For us |
|---|---|---|
| **Mesa 3** (Python ABM) | Active, JOSS 2025, Python ≥3.12 | Ceiling ~10–50K agents without vectorisation. mesa-frames (Polars backend) — up to 1M |
| **Agents.jl** (Julia) | Active, 3–160× faster than Mesa | Fallback if Python is not enough |
| **PeerSim** (Java) | Dead (last release ~2013) | Do not use |
| **OverSim** (OMNeT++) | Dead (2019) | Do not use |
| **ns-3** | Active, but too low-level | Not our case |
| **SimPy 4** (Python DES) | Active, PyPI | For modelling churn and repair |

**Conclusion:** specialised P2P simulators are dead. Academic groups write their own on numpy/SimPy/MATLAB. This is normal and correct.

## How predecessors approached it

### Samsara (Cox & Noble, SOSP 2003)
- Custom discrete simulation, no named framework
- Focus on adversarial behaviour, not random churn
- Pastiche prototype evaluated against a modified Andrew Benchmark (7.4% overhead)
- Availability set parametrically

### INRIA/Eurecom (Kermarrec group, 2007–2012) — best academic reference
- Primary tool: **Markov chain analytical models** for MTTDL (Mean Time To Data Loss)
- Where simulation was used — NS-2 + custom MATLAB churn generator
- 2009 paper "A Realistic Simulation Model for P2P Storage Systems" — critique of unrealistic models

### EigenTrust (Kamvar et al., WWW 2003) — reference for reputation
- 1000 peers, 100 request cycles, convergence in <10 power-method iterations
- Even with 70% malicious nodes — suppresses fake downloads
- Custom Python/MATLAB

## Churn models

| Model | Description | When used |
|---|---|---|
| **Exponential** | session ~ Exp(λ), memoryless | First pass, analytically convenient |
| **Weibull** (k≈0.34–0.6) | Better fit to Gnutella/BitTorrent empirics | Second pass, Stutzbach & Rejaie 2006 |
| **Empirical traces** | Replay of KaZaA/Gnutella logs | Maximum accuracy, minimum generality |

For backup systems, sessions are longer than in file-sharing (days, not minutes). Calibrate for our use case.

## Modelling data survival

- Storage = per-peer capacity (GB), track used/free
- Data = K+M fragments (erasure coding) across different peers
- Repair trigger: live fragments < threshold
- **Bandwidth is the critical constraint**, not CPU or storage
- Metric: MTTDL (Mean Time To Data Loss), fraction of surviving files
- Markov chain analysis is faster and more informative than simulation for exponential churn

## Modelling reputation (PID)

Nobody has applied PID to P2P storage (this is the project's novelty). Closest analogues:
- EigenTrust — linear algebra (power method)
- TCP congestion control — PI controllers for resources
- General ABM trust approach: agents with true reliability (Beta distribution) → perceived reputation → measure convergence (Kendall's tau)

## Scale on a 24-core Xeon / 64 GB

| Approach | Realistic scale |
|---|---|
| Pure Python Mesa | 10K–50K agents |
| mesa-frames (Polars) | 100K–1M |
| Custom numpy vectorised | 1M+ agents/step |
| SimPy DES | 1M events in seconds |

Bottleneck: N×N trust matrix = O(N²). Sparse trust graph (each peer knows K neighbours) → O(N×K), fine up to 100K.

## Two separate experiments

**A. PID Reputation Convergence** — pure numpy, no network
- N agents, Beta-distributed true reliability
- PID controller per observer
- Metric: Kendall's tau (perceived rank vs true rank) vs time
- 10K agents × 10K steps = seconds

**B. Data Survival Under Churn** — SimPy DES or Markov chain
- N peers, exponential on/off
- Erasure coding k-of-n
- Repair process with bandwidth constraint
- Metric: fraction of files with < k live fragments

To be combined later: reputation influences peer selection for shard placement.

## Sources

- Cox & Noble. "Samsara: Honor Among Thieves in Peer-to-Peer Storage." SOSP 2003
- Stutzbach & Rejaie. "Understanding Churn in Peer-to-Peer Networks." SIGCOMM 2006
- Kamvar et al. "The EigenTrust Algorithm for Reputation Management in P2P Networks." WWW 2003
- INRIA. "P2P Storage Systems: Data Life Time for Different Placement Policies." 2009
- INRIA. "A Realistic Simulation Model for Peer-to-Peer Storage Systems." 2009
- Mesa 3: https://joss.theoj.org/papers/10.21105/joss.07668
- Agents.jl: https://journals.sagepub.com/doi/10.1177/00375497211068820
- SimPy: https://simpy.readthedocs.io/
