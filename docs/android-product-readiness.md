# ProxyGuard Android — product readiness and investment gates

**Status as of 2026-10-31:** early local-first diagnostic MVP; not yet an independently validated security product.

## Product promise that can be defended today

ProxyGuard can report selected network facts exposed by Android and compare a user-entered IP address against an imported local CIDR dataset. It can be valuable as a transparent diagnostic utility, but it cannot currently guarantee detection of all proxies, determine global IP reputation offline, or predict a destination site's decision.

The product must preserve three separate concepts:

1. **Observation:** what Android actually exposed at scan time (VPN transport, system-visible proxy, active transport, configured DNS resolvers).
2. **Dataset classification:** what a particular imported source claims about a matching IP range, with source and freshness shown as unverified until authenticated.
3. **Security/abuse assessment:** unavailable until a defined risk target, licensed intelligence sources, validation corpus, and calibrated model exist.

Do not merge these concepts into one generic “risk %”.

## Current engineering baseline (0.4.0 candidate)

- Android APK with local device observations plus an opt-in, user-initiated internet-based proxy endpoint scan; no ProxyGuard-owned backend is required.
- VPN transport and system-visible ProxySelector inspection.
- Configured DNS resolver display, explicitly not a DNS leak test.
- Manual IPv4/IPv6 CIDR lookup against a CSV imported by the user.
- Pre-use HTTP/HTTPS/SOCKS5 tunnel test, exit-IP discovery via an HTTPS echo endpoint, and external IP reputation lookup.
- CSV syntax, CIDR, size, record-count, and label validation.
- Unit tests for IP parsing/CIDR matching and evidence-based interpretation.
- The displayed percentage is an external provider's IP risk score, not a calibrated probability that every destination site will detect or block the proxy. Provider coverage and query limits apply. No independently validated model, signed ProxyGuard intelligence feed, or real-device compatibility matrix yet.

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


## 0.4.0 pre-use scan design and caveats

The app now accepts a proxy host, port, and HTTP/HTTPS/SOCKS5 protocol, verifies an HTTPS tunnel through that endpoint, obtains the observed public exit IP, and queries ProxyCheck.io for an IP risk score and proxy/VPN classification. The app does not change the phone's system proxy configuration. The exit IP is disclosed to the external reputation provider; proxy credentials are not sent to that provider and are not intentionally persisted.

The user-facing 0–100 percentage is a provider-supplied IP risk score presented as a practical risk/detectability indicator. It is not a probability or a promise of how a particular site will classify the connection. A score must be withheld if the proxy tunnel or reputation lookup fails. The agreed display bands are green (0–19), yellow-green (20–39), yellow (40–59), and red (60–100), with deeper red as the score rises.

Before public beta, review ProxyCheck.io terms, privacy and commercial-use permission, its current free quota, response stability, caching/freshness, and whether direct client-to-provider requests are acceptable. Add a second independent intelligence source, provider confidence/freshness display, a benchmark against real proxy endpoints and destination services, tests for authenticated proxies and TLS hostname verification, and an independently validated interpretation model. The score must not be marketed as a universal detection probability.
