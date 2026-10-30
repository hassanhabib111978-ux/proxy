# ProxyGuard — Commercial Product Roadmap

## Product direction

ProxyGuard is a privacy and network-quality diagnostics SaaS. It helps a user assess an IP address or a proxy endpoint they own or are authorized to test, understand reputation and network signals, compare geographic metadata, and diagnose DNS/WebRTC/IPv6 exposure.

It must not promise that a connection will bypass a destination site's geographic, identity, fraud, or access-control checks. Results are indicators with source, timestamp, coverage, and confidence—not guarantees.

## Current repository baseline (2026-10-30)

The current MVP (v0.1.1) analyzes the browser user's current public egress IP:
- ipify public egress IP lookup
- ipapi.is network intelligence (optional server-side key)
- browser WebRTC ICE candidate indicators
- heuristic risk indicator and JSON report
- Arabic/English responsive UI

Not implemented yet:
- arbitrary proxy endpoint testing or proxy-list import
- DNS leak test (correctly marked not tested)
- IPv6 browser diagnostics
- accounts, persistent history, billing, team workspaces, or customer API
- a second IP-intelligence provider

The existing score is heuristic, not a probability and not calibrated against destination-site decisions.

## Target customers

1. Individual privacy-conscious users who want understandable connection diagnostics.
2. QA and software teams validating their own applications from authorized regional test environments.
3. Developers who need an IP intelligence API for their own products.
4. Small businesses that need batch IP reputation review for security and fraud triage.

Avoid positioning the product as a guarantee to defeat geo-blocking, identity checks, fraud controls, or contractual access restrictions.

## Product phases

### Phase 1 — Reliable diagnostic MVP
- Preserve current-connection diagnostics.
- Add IPv4/IPv6 and timezone/geolocation consistency reporting with source and freshness.
- Implement DNS leak testing only after deploying a controlled authoritative DNS zone with unique per-scan tokens, retention limits, and user notice.
- Add provider timeout, quota, degraded-mode, and freshness handling.
- Add integration tests and an independent security review.
- Clearly distinguish "not tested", "no issue observed", and "provider unavailable".

### Phase 2 — Authorized proxy endpoint assessment
- Allow users to submit proxy endpoints they own or are authorized to test.
- Support a narrowly defined protocol set and safe credential handling.
- Test reachability, latency, observed egress IP, geolocation metadata, and consistency.
- Query IP reputation providers for the observed egress IP.
- Do not store proxy credentials; redact secrets from logs and reports.
- Prevent SSRF: block private, loopback, link-local, multicast, and reserved destinations; restrict ports and protocols; enforce outbound egress controls and strict timeouts; never expose internal network access.
- Do not crawl or harvest public proxy lists in the initial commercial release.

### Phase 3 — SaaS foundation
- Authentication, verified email only when required for account recovery/billing, and user consent.
- Per-account quotas, shared rate limiting, abuse controls, audit events, and deletion/export controls.
- Saved scan history with configurable retention.
- Usage metering and provider-cost attribution.
- Billing integration only after provider commercial terms and unit economics are confirmed.

### Phase 4 — Commercial launch
- Private beta with 10–20 testers.
- Measure false positives, coverage, scan completion, provider costs, repeat use, and willingness to pay.
- Publish methodology, limitations, privacy policy, terms, and support contact.
- Launch free tier and paid tiers only after cost controls and payment/tax compliance are ready.

## Pricing hypotheses (validate with customers)

These are experiments, not validated market prices:
- Free: limited single scans and short history.
- Pro: proposed $7–10/month for personal diagnostics and authorized endpoint comparisons.
- Team: proposed $25–40/month for shared projects, batch reports, and team access.
- API: usage-based pricing after provider resale/redistribution rights are confirmed.

Do not copy competitor prices blindly. ProxyCheck's public pricing currently lists a free allowance and paid tiers beginning around $4.99/month; IP2Location's API page lists free, $49, $249, and $499/month plans depending on data coverage. Provider fees, commercial-use rights, and per-query limits must be included in gross-margin calculations.

## Commercial gates

Before taking payment:
- Confirm every upstream provider permits commercial use, caching, display, and resale/derived scoring.
- Model cost per scan, retries, cache behavior, abuse, and free-tier usage.
- Implement secure account isolation and server-side secrets.
- Complete privacy, security, and legal review for target markets.
- Validate product demand through interviews and a small beta.

## First release acceptance criteria

- No fabricated score when provider coverage is missing.
- Every finding shows its source and scan time.
- DNS remains "not tested" until a controlled authoritative test is operational.
- No credentials or full proxy URLs appear in logs.
- No arbitrary URL fetching or access to private/internal IP ranges.
- Rate limits work across multiple service instances.
- Tests cover IPv4, IPv6, malformed inputs, provider failures, timeouts, quotas, and SSRF boundaries.
- Clear Arabic and English explanations and an exportable report.
