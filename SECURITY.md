# Security policy

## Reporting a vulnerability

If you find a security issue in Viaticum, please report it privately rather than opening a public issue.

**Preferred:** open a [GitHub security advisory](../../security/advisories/new) on this repository. This gives us a private channel to discuss the issue and coordinate disclosure.

**Alternative:** email the maintainer directly at `[your-email]` with the subject line starting `SECURITY:`.

Please include:
- A description of the issue
- Steps to reproduce, or a proof-of-concept
- Your assessment of the impact
- Any suggested mitigation, if you have one

## What to expect

- An acknowledgment within 7 days
- A response with our assessment of severity and a tentative timeline within 21 days
- Public disclosure coordinated with you, typically after a fix is available

We do not currently run a bug bounty program. If we adopt one, this document will be updated.

## Scope

Viaticum is pre-alpha software. We are actively interested in reports about:

- Protocol-level vulnerabilities (trust protocol, Proof-of-Storage, erasure coding, placement, repair)
- Cryptographic weaknesses (key derivation, encryption, signature schemes, anti-collusion binding)
- Network-level issues (libp2p transport, NAT handling, peer discovery)
- Local attacks against the daemon (privilege escalation, file safety, restore path traversal)

Reports about issues that depend on assuming the attacker already has full control of the local machine or has compromised the user's secret material are usually out of scope, but we will read them and reply.

## Acknowledgments

Researchers who report issues responsibly will be credited in the release notes for the fix, unless they prefer to remain anonymous.
