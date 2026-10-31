# ProxyGuard Android local-first implementation

## Product decision
The primary deliverable is a native Android APK that performs diagnostics on-device. It must not require a ProxyGuard backend, account, or subscription to perform local checks.

## What can be checked locally
- Android's active network capabilities, including whether the active network reports VPN transport.
- DNS resolver addresses configured for the active Android network.
- A proxy exposed by the platform ProxySelector.
- User-supplied IP addresses against an imported local IPv4/IPv6 CIDR intelligence database.

## What cannot be truthfully inferred offline
- The public egress IP address, without a network observation endpoint or a user-supplied address.
- Current global IP reputation without an updated intelligence dataset.
- Whether a remote website will classify an IP as proxy/VPN.
- A DNS leak result from merely reading configured DNS resolver addresses.
- All per-app proxy/tunnel state: Android does not expose every app's routing configuration to ordinary applications.

## Privacy requirements
- No INTERNET permission in the initial offline build.
- No analytics, telemetry, account, remote logging, or background network calls.
- Database import is explicit and user initiated.
- Imported data remains in app-private storage.
- Reports must distinguish "not found in imported data" from "safe".

## Database update design
The first version accepts an explicit CSV import. A later opt-in update mechanism may download a signed manifest and compressed feed directly from a documented dataset publisher. Verify signature, hash, size, schema, expiry and license before replacing the previous database. The update should be user initiated and must not require a ProxyGuard-operated server.

## Evidence and result interpretation
The Android app separates local observations, imported CIDR classifications, and an optional external reputation lookup. For pre-use scans it may display the upstream provider's 0–100 IP risk assessment and its separate Proxy/VPN classification. This provider score is not a calibrated probability that a destination site will detect the proxy, and it must never be presented as a universal detection likelihood. An observed VPN is not inherently dangerous. An unmatched IP is not necessarily safe. Hosting/datacenter infrastructure is not proof of a proxy. Missing or failed data must remain unavailable rather than becoming zero risk.

Before introducing any security-risk probability, define the event being predicted (for example, abuse within a specified time window), obtain licensed and sufficiently fresh labeled datasets, establish a representative ground-truth test set, calibrate the model, publish false-positive/false-negative rates and confidence intervals, and continuously monitor drift. Until that work is independently validated, show evidence and limitations instead of a risk percentage.
