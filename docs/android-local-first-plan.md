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

## Scoring and interpretation
The current Android prototype displays two explicitly limited heuristic indices: (1) local device detection strength for Android-visible VPN/system-proxy signals and (2) a manual IP proxy-classification index when a category in the imported CIDR list matches. These are 0–100 indicator weights, not statistical probabilities and not security-risk scores. The UI must separately say that maliciousness/abuse risk is unavailable unless a verified, licensed, sufficiently fresh threat-intelligence dataset is added. Missing data must remain "unavailable", never 0% or "safe".

Before any production security-risk score is considered, define its target (abuse, malware, fraud, or proxy classification), obtain licensed datasets with source, timestamp, coverage and expiry metadata, validate them, and calibrate thresholds against representative labeled data. Do not present heuristic weights as a probability or use them for automated allow/deny decisions.
