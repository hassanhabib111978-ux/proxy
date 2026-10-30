# Architecture and release decisions

ProxyGuard reports observable indicators about the user's current browser connection. It does not promise anonymity or predict every destination website's detection decisions.

## Request flow
1. User explicitly starts a scan.
2. Browser requests public egress IP from ipify.
3. Browser gathers WebRTC ICE candidate types via public STUN. Only candidate types and a boolean public-address mismatch are sent to this app.
4. Server validates the public IP, calls ipapi.is server-side, and normalizes returned indicators.
5. The analyzer returns a transparent heuristic score and findings; reports are not persisted.

## Trust boundaries
- ipify receives the browser's public connection metadata.
- STUN receives ICE connectivity metadata.
- This app receives the public egress IP and minimal WebRTC signals.
- ipapi.is receives the IP for network intelligence.
- Forwarded client IP headers are untrusted unless the exact proxy chain is configured.

## Scoring
Weights in src/analyzer.js are heuristic, not calibrated probabilities. Flags may overlap and are not independent. Never use the score for automated allow/deny decisions.

## DNS
DNS leak testing is intentionally marked not tested. A reliable test requires a controlled authoritative zone, unique per-scan subdomains, query logging, expiry/retention controls and clear user notice.

## Release gates
- Controlled DNS probe and authoritative query pipeline.
- IPv4/IPv6, timeout, provider quota, browser and deployment integration tests.
- Second independent IP intelligence provider with freshness metadata.
- Shared rate limiting for multi-instance production.
- Privacy notice, processor review, HTTPS and independent security review.
- Verify provider commercial terms before monetization.
