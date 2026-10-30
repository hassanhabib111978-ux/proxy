# ProxyGuard Android — product readiness and investment gates

**Status as of 2026-10-31:** early local-first diagnostic MVP; not yet an independently validated security product.

## Product promise that can be defended today

ProxyGuard can report selected network facts exposed by Android and compare a user-entered IP address against an imported local CIDR dataset. It can be valuable as a transparent diagnostic utility, but it cannot currently guarantee detection of all proxies, determine global IP reputation offline, or predict a destination site's decision.

The product must preserve three separate concepts:

1. **Observation:** what Android actually exposed at scan time (VPN transport, system-visible proxy, active transport, configured DNS resolvers).
2. **Dataset classification:** what a particular imported source claims about a matching IP range, with source and freshness shown as unverified until authenticated.
3. **Security/abuse assessment:** unavailable until a defined risk target, licensed intelligence sources, validation corpus, and calibrated model exist.

Do not merge these concepts into one generic “risk %”.

## Current engineering baseline (0.3.1 candidate)

- Local-first Android APK; no backend or Internet permission.
- VPN transport and system-visible ProxySelector inspection.
- Configured DNS resolver display, explicitly not a DNS leak test.
- Manual IPv4/IPv6 CIDR lookup against a CSV imported by the user.
- CSV syntax, CIDR, size, record-count, and label validation.
- Unit tests for IP parsing/CIDR matching and evidence-based interpretation.
- No numeric risk score, no calibrated probability, no verified global reputation feed, no signed database update, and no real-device compatibility matrix yet.

## Required work before a paid beta

### Gate A — correctness and measurable accuracy

- Build a test corpus with independently labeled IPv4/IPv6 ranges: residential ISPs, mobile carriers, hosting/cloud, VPN exits, commercial proxies, Tor exits, and ordinary consumer connections.
- Record dataset publisher, license, collection time, scope, label meaning, confidence, and expiry for every sample.
- Use separate development and holdout sets; prevent the same provider/range from leaking between them.
- Report precision, recall, false-positive rate, false-negative rate, coverage, and 95% confidence intervals per class and dataset version.
- Test Android behavior across API levels, common OEMs, Wi-Fi/mobile networks, IPv4/IPv6, VPN apps, system proxy settings, captive portals, and network handovers.
- Define abstention states: unsupported, no coverage, stale feed, ambiguous category, permission/platform limitation, and provider unavailable.
- Never say “near-zero errors” unless a representative test programme produces measured evidence. Even then publish the conditions and measured confidence intervals.

### Gate B — trustworthy threat-intelligence lifecycle

For any future optional update feature:

- Maintain a publisher allowlist and document redistribution/commercial-use rights.
- Define a signed manifest with schema version, publisher key ID, generated-at time, expiry, record count, file size, compression, SHA-256, and license reference.
- Sign a canonical representation with a maintained cryptographic format; verify the signature using a public key pinned in the app.
- Reject unknown keys, invalid signatures, hash mismatch, oversized files, malformed rows, expired feeds, schema downgrade, and replay/rollback attempts.
- Validate and stage the new data before atomic activation; keep a recoverable last-known-good database.
- Display publisher, dataset version, generated time, last successful update, expiry, record count, coverage, and license.
- Keep updates optional and user-controlled. Do not silently upload scan IPs or device/network data.

### Gate C — Android and software assurance

- Add instrumentation/UI tests and real-device test reports for supported OS/device combinations.
- Add static analysis, dependency vulnerability checks, secret scanning, SBOM generation, and build provenance.
- Pin build tools and dependencies; verify the release artifact and publish SHA-256 checksums.
- Use a dedicated, securely backed-up production signing key. Never use a debug key for public release.
- Add a documented support policy, crash/diagnostic consent controls if introduced, and a security vulnerability reporting process.
- Commission an independent mobile application security review before broad public release.

### Gate D — commercial readiness

- Confirm feed licenses explicitly permit commercial display, caching, and redistribution where applicable.
- Publish privacy policy, terms, methodology, known limitations, data sources, retention rules, and support contact.
- Run a closed beta with privacy/security practitioners and ordinary users; collect reproducible false-positive/false-negative reports.
- Measure retention, scan completion, support burden, dataset costs, update frequency, and willingness to pay.
- Only add paid tiers when paid features provide recurring value (for example verified, maintained datasets and transparent update coverage). Keep the core local checks available without an account.

## Investment milestones

| Milestone | Evidence required | Investment decision |
|---|---|---|
| Technical prototype | Successful CI, reliable core tests, clear limits | Continue engineering |
| Validated beta | Independent benchmark, device matrix, feed licensing, security review | Consider a small paid pilot |
| Commercial launch | Stable signed releases, support, privacy/legal readiness, cost model, user demand | Consider external capital |
| Scalable business | Retention, repeat use, positive unit economics, defensible data rights | Consider growth investment |

## Explicit non-goals

- Guarantee that any website will accept an IP or fail to detect a proxy.
- Describe VPN/proxy presence as maliciousness.
- Present provider category labels as independently verified facts.
- Claim DNS leak testing when only resolver configuration is displayed.
- Promise universal or near-zero detection error without measured evidence.
