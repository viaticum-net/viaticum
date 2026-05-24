# Why Viaticum exists

Viaticum occupies one specific point in the decentralized-storage field: cold backup, no token, owned and restored only by you, with trust earned over time between peers. That point has been empty for years — not for lack of demand, but because nobody built it in a form that survives.

This document maps the field, explains why the projects that tried this exact thing died, and lays out the reasoning behind Viaticum's core choices. For what it is and how it works, see [`overview.md`](overview.md).

## Direct predecessors (this exact idea, tried before)

Three projects tried almost exactly this: peer-to-peer backup where you trade disk space with others, no datacenter. All three proved the demand is real. All three are dead, and all three were proprietary.

| Project | Lifespan | What it was | Why it died |
|---|---|---|---|
| **Wuala** | 2008-2015 | The closest historical implementation. Give X GB, get X GB; erasure coding; client-side encryption | Acquired by LaCie, moved to pure centralized storage in 2011, shut down in 2015. Nothing survived. |
| **CrashPlan (P2P)** | until 2017 | Free encrypted backup to friends' computers | Code42 killed the consumer product in 2017. The business model was the problem, not the technology. |
| **BuddyBackup** | until 2022 | Backup to friends' disks, no central server, free. Conceptually the closest of all | Proprietary, no federation, died with the company. No open-source legacy. |

The pattern is the lesson. Each died for business reasons, not technical ones, and because each was one company's proprietary product, its death took the capability with it. The clearest proof that the market is real is what users did when CrashPlan killed its free P2P backup: they organised a public petition asking Code42 to open-source the code so the capability could survive on its own. Code42 refused, and it was gone. People wanted this enough to fight for it, and the proprietary form is what failed them. The full predecessor study is in [`archive/research/RESEARCH.md`](archive/research/RESEARCH.md).

For a backup tool this is not incidental, it is structural. The whole promise of a backup is that your data outlives accidents, including the accident of a company changing its mind. A proprietary backup breaks that promise the moment its vendor pivots or folds, and Wuala, CrashPlan and BuddyBackup each did exactly that. Only an open protocol, with more than one possible implementation, can promise to outlive any single maker. For this class of problem FOSS is not idealism chosen over pragmatism; it is the only form that can deliver the guarantee at all. Demonstrating that concretely is part of what Viaticum is for.

## Adjacent, alive, but not the same problem

Everything alive today is close in shape but solves a different problem. **Tahoe-LAFS**: encrypted serverless storage, but no reciprocity or earned trust, and now dormant. **Storj, Filecoin, Sia**: decentralized hot, S3-style storage on operator nodes with a token, aimed at always-on access rather than backup. **Autonomi (MaidSafe)**: P2P on home devices like Viaticum, but a permanent, immutable public data layer with a token (think permaweb), not private backup. **Garage**: hot S3 for operators, complementary as a possible cold tier. **Syncthing, Resilio**: sync, not backup, with no erasure coding or point-in-time recovery. **Restic + B2/S3**: a good backup tool that still locks you into a cloud provider. Close, but none of these is decentralized cold backup with trust earned over time.

Put the two groups together and the picture is plain. The projects that tried this exact thing are dead, and every one was proprietary. The projects that are alive are solving adjacent problems. The specific point Viaticum occupies, decentralized cold backup with trust earned over time, no token, owned and restored only by you, is empty. Not for lack of demand: the dead predecessors and the CrashPlan petition prove the demand is real. It is empty because nobody assembled it in the form that survives, an open protocol with no company to fold and no token to crash.

## How these efforts fail, and what Viaticum does instead

Step back and the failures rhyme. A few patterns recur, and the design is largely a list of answers to them.

| Failure mode | Examples | What Viaticum does instead |
|---|---|---|
| Proprietary: the capability died with the company | Wuala, CrashPlan, BuddyBackup | Open protocol, more than one possible implementation, no company to fold |
| Wrong time constant: chased second-scale access, unwinnable on home hardware | most P2P storage | Week-scale cold backup; the competitor is "nothing", not AWS |
| No reciprocity: nothing makes peers actually keep your data | Tahoe-LAFS | Trust earned over time; you have to store to be trusted |
| Retrofitted cores: reputation and churn handling bolted on after launch | many research prototypes | 24 numerical experiments before any production code (see [`archive/experiments/`](archive/experiments/)) |

One failure deserves more than a table cell. The wrong time constant is the most fundamental, and the easiest to miss. Most P2P storage competes with hot cloud (S3, Dropbox) and targets second-scale access: fast reads, fast writes, immediate consistency. That is structurally unwinnable on user-grade hardware, where residential connections, intermittent uptime, NAT and mobile devices all fail at second-scale operations. Projects that need seconds end up requiring always-on infrastructure, which collapses back into operator-controlled clusters, which is centralized providers with extra steps. Viaticum picked a week-scale time constant on purpose: proof-of-storage runs weekly, restore takes days, the network tolerates churn measured in weeks. That single decision is what makes P2P storage on user devices realistic, and it moves the competitive frame: the competitor is the 98% of people with no offsite backup, not AWS.

## On positioning: open source, no token, no money

The decision to keep Viaticum strictly FOSS, with no token and no commercial entity, is deliberate, for several reasons.

No token means no regulatory exposure as securities and no dependence on a token price. It also means no token-holder pressure on protocol decisions.

In a village, no one needs a coin to remember who can be trusted with the harvest, and that trust is not one number (cf. Graeber, *Debt: The First 5000 Years*). Viaticum keeps that texture. The protocol does not mandate one measure of value: an owner weighs how durably a file must survive (its target reliability), how often holders are challenged, how much a peer's online presence counts, and a different implementation could compute trust by an entirely different formula without the network caring. A token would force all of this into one tradeable quantity. Viaticum refuses that flattening, which is the same reason it carries no token at all.

In a village each person also decides for themselves whom to trust, and there is no central registry of reputation. Viaticum works the same way: trust is pairwise, each owner judges each holder through its own proof-of-storage history, with no global score and no authority that grants or revokes standing. A trust system with no center has nothing to attack, capture, or subpoena. And standing is earned only the slow way, over weeks of verified storage, which matters because time is the one input an attacker cannot forge or fast-forward. A Sybil cannot fabricate a history it did not live; the defense against fake identities rests on elapsed time, not on a token.

Beyond all of this there is the artifact itself. Viaticum is a protocol first and an implementation second. The wire format, the proof-of-storage challenge, and the encoding are specified so that anyone can build a compatible client. How a node turns proof history into a trust score is deliberately not specified: that is a model sitting above the protocol, an idea more than a formula, and a different client may compute it differently without the network caring. This Rust codebase is one implementation, not the definition. That strengthens the threat model: a company can be pressured and a single codebase can be abandoned, but an open protocol with more than one possible implementation is far harder to capture. A formal protocol specification is part of the planned work.

No commercial entity means no state attack vector. Tor Project, Signal, Briar all chose this structure for the same reason. A company can be subpoenaed, regulated, acquired, or pressured. An open protocol with distributed maintenance cannot, at least not in the same way.

No money flowing through Viaticum itself means no acquihire target. The project is uninteresting to investors: no users yet, no MRR, no monetization path. That is safety. The "unloved Joe nobody chases" positioning is intentional infrastructure resilience.

There is a wider bet here, worth stating plainly. The reusable part is the trust model, an idea more than a formula or a codebase. Storage is just the first domain demanding enough to prove it, with real data and a real cost when it fails. If reputation-as-credit-limit, earned over time, with no central authority and no token, holds up here, the same idea applies wherever people have to coordinate and judge each other without a center. That is the longer game: P2P arrangements that govern themselves, not because a company or a coin compels them, but because the protocol makes honest behavior the rational choice. Viaticum is one concrete, testable step toward that, not a manifesto about it.
