# ProxyGuard

ProxyGuard has two separate implementations with different privacy and network behavior:

- **Legacy Web MVP (0.1.1):** browser/server demonstration that uses external IP and STUN services as described below.
- **Android local-first MVP (0.2.0):** native Android app intended to perform its initial diagnostics entirely on-device, without a ProxyGuard backend or internet permission.

Neither edition guarantees anonymity or reproduces every website's proxy-detection systems.

## Legacy Web MVP (0.1.1)

The following sections describe only the original browser/server implementation, not the offline Android app.

## Included checks
- Public egress IP lookup through ipify.
- IP network intelligence through ipapi.is (optional server-side API key).
- WebRTC ICE candidate type and public-address mismatch indicators.
- Transparent heuristic risk indicator, coverage notes, and JSON report export.
- Arabic and English responsive interface.

## Important limitations
- DNS leak testing is **not implemented** and must remain marked "not tested".
- WebRTC differences are indicators, not proof of an IP leak.
- IP intelligence databases can miss residential/mobile proxies and newly deployed endpoints.
- The heuristic score is not a probability and must not be used for automated allow/deny decisions.

## Requirements and run
Node.js 20+. No runtime npm dependencies.

```bash
npm test
npm start
```

Open `http://localhost:3000`. Optional server-side configuration: `IPAPI_IS_KEY`, `PORT`, `HOST`, and `TRUST_PROXY_HOPS` (default 0; only configure for a verified trusted proxy chain).

## Privacy and security
The browser contacts ipify and a public STUN service. The app sends the observed public IP to ipapi.is for network intelligence. These providers may process connection metadata under their own policies. ProxyGuard has no account database or report history and does not intentionally persist scan IPs. Production requires HTTPS, a verified proxy configuration, shared rate limiting for multi-instance deployments, integration tests, provider-terms review, and an independent security review.

## Release gates
1. Implement a controlled authoritative DNS probe before claiming DNS leak coverage.
2. Add IPv4/IPv6, timeout, quota, browser and deployment integration tests.
3. Add a second independent IP intelligence provider and freshness/provenance metadata.
4. Replace in-memory rate limiting for multi-instance production.
5. Review privacy notice, provider retention and commercial terms before monetization.

## Android local-first app

A native Android MVP is now scaffolded in [`android/`](android/). Unlike the original browser/server MVP, this app is designed to perform its initial diagnostics entirely on-device and intentionally has no `INTERNET` permission.

See [Android build and limitations](android/README.md) and the [local-first architecture decision](docs/android-local-first-plan.md). A GitHub Actions workflow builds a debug APK on changes to the Android project; download the APK from the successful workflow run's artifact named `proxyguard-debug-apk`.

The Android MVP currently observes Android-reported VPN transport, network transports, configured DNS resolvers, and a platform-visible proxy, and checks a user-supplied IP against a locally imported CIDR CSV. It does not discover public egress IP offline, perform a DNS leak test, or guarantee detection of every proxy.
