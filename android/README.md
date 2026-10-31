# ProxyGuard Android 0.5.0 — pre-use proxy scanner

## Release status

Version **0.5.0** adds ProxyCheck v3 intelligence, including device estimates behind the exit IP and subnet, detection confidence, and attack-history counts. It remains an engineering/test release, not an independently validated commercial security product. It is not yet a production security product, an independently audited release, or a Google Play production-signed build.

## Current behavior

The Android app performs the following checks locally:

- Detects whether the active Android network reports VPN transport.
- Reads active network transport types and configured DNS resolver addresses.
- Attempts to read an HTTP/SOCKS proxy exposed by the platform `ProxySelector`.
- Lets the user enter an IPv4/IPv6 address and compare it with a CSV CIDR database imported explicitly by the user.
- Stores the imported dataset in app-private storage.

The app does not need a ProxyGuard backend or internet permission for these checks.

## How local-only results are interpreted

The local device scan and imported CSV lookup intentionally do **not** produce a 0–100 security score or percentage. The separate live pre-use scan is described below and uses an external provider's score.

- A visible VPN is reported as a VPN observation, not as a security risk.
- A system proxy is reported only when Android exposes one through the platform API.
- No visible signal is reported as “no visible indicators”, not “clean”, “safe”, or “proxy-free”.
- A matching IP range is reported using the category written in the imported CSV.
- Hosting/datacenter classification is not treated as proof of proxy use.
- A Tor/VPN/Proxy category is not treated as proof of abuse or maliciousness.
- An unmatched IP means only “not found in this imported dataset”.

## CSV format

UTF-8 CSV with a header row:

```csv
cidr,category,source
198.51.100.0/24,datacenter,Example feed
2001:db8::/32,hosting,Example feed
```

The example ranges are documentation-only reserved ranges, not real threat intelligence. Use only datasets whose publisher, license, update policy, and intended use you have verified independently.

The current importer validates CSV syntax, CIDR notation, field lengths, control characters, file size, and record count. It does **not** authenticate the publisher, validate the license, verify the data's freshness, or cryptographically verify the file. Imported source labels are untrusted metadata supplied by the CSV.

## What this build cannot establish

- Public egress IP without a network endpoint or user-supplied address.
- Current global IP reputation without a fresh intelligence dataset.
- Whether a website will detect, block, or accept a connection.
- DNS leakage from merely displaying configured DNS resolver addresses.
- Every per-app proxy, tunnel, or routing configuration.
- Whether a detected VPN/proxy is malicious, safe, or trustworthy.

Android's platform APIs do not expose every app's network path to an ordinary application. Absence of a visible setting must never be interpreted as proof that no proxy exists.

## Build and automated tests

Open the `android/` directory in Android Studio with JDK 17 and Android SDK Platform 35, or use the GitHub Actions workflow `.github/workflows/android-build.yml`.

The workflow runs `:app:testDebugUnitTest`, `:app:lintDebug`, and builds a debug APK. The downloadable artifact is named `proxyguard-android-0.5.0-debug`. CI uses a persistent development-only debug signing identity to keep CI test APKs update-compatible. Do not reuse this identity for commercial releases; release builds require a separately protected private signing key. A debug APK is for controlled testing only and is not the production release artifact. Do not bypass Google Play Protect or Android security warnings to install it.

## Privacy

The app requests `ACCESS_NETWORK_STATE` and `INTERNET`. No network scan runs until the user taps the pre-use proxy scan button. The app connects to the entered proxy, opens an HTTPS tunnel to api.ipify.org to discover the exit IP, then sends only that exit IP to ProxyCheck.io over a direct HTTPS connection for reputation data. Proxy username/password are not sent to the reputation provider, are not persisted by the app, and are cleared from the form after the scan. For plain HTTP and SOCKS5 proxies, proxy authentication credentials are not protected by transport encryption; use HTTPS proxy transport or another trusted encrypted channel before entering sensitive credentials. ProxyCheck.io may process the submitted exit IP under its own privacy policy. The no-key service allowance is limited and can change; current published documentation states 100 daily queries for unregistered users. The legacy CSV importer remains available but is not the source of the live risk percentage.

## Production gates — not yet completed

1. **Authenticated intelligence:** define and implement a signed manifest and authenticated dataset delivery. Verify publisher key, signature, SHA-256, schema version, generation/expiry times, record limits, license metadata, and rollback behavior before atomically replacing the active database.
2. **Data provenance:** use only licensed, documented feeds. Keep per-source timestamps, coverage, category semantics, and update history. Reject stale, unsigned, or malformed feeds.
3. **Test evidence:** build a labeled benchmark with independently verified proxy, VPN, Tor, hosting, mobile/residential, and ordinary ISP samples. Report false positives, false negatives, coverage, and confidence intervals by category and provider.
4. **Device coverage:** test supported Android releases, OEM variants, Wi-Fi, mobile data, IPv4/IPv6, active VPNs, system proxy settings, captive portals, and network transitions on physical devices.
5. **Engineering assurance:** add UI/instrumentation tests, static analysis, dependency and supply-chain checks, crash reporting only with clear consent, secure release signing, reproducible build checks, and an independent security assessment.
6. **Commercial readiness:** publish methodology and limitations, privacy notice, terms, support process, data-retention policy, license register, and customer-facing incident/update policy. Validate willingness to pay before introducing billing.

No “near-zero error” or universal detection claim is acceptable until measured against representative, independently labeled test data. Even then, publish the measured rates and test conditions rather than promising zero errors.


## Pre-use proxy scan (0.5.0)

The user can enter an optional local proxy label, paste a proxy IP/host (or host:port), enter the port separately when needed, choose protocol (HTTP, HTTPS, SOCKS5), and provide optional username/password. The label is for local report identification only and is never sent to a provider. The scanner tests the endpoint without changing Android's system proxy configuration. It supports HTTP CONNECT, TLS-to-HTTPS-proxy followed by CONNECT, and SOCKS5 (including username/password authentication). It then requests the public exit IP through the tested tunnel and queries the stable ProxyCheck.io v3 API for IP risk, proxy/VPN classification, network type, estimated devices behind the IP and subnet, detection confidence, and attack-history counts.

The displayed value is the upstream provider's **IP risk score**. Device estimates are shown separately: they are not a verified count of subscribers or active proxy sessions, and high sharing is not automatically treated as abuse. The query requests a seven-day attack-history window, but the provider documents that it may suppress some stale or uncertain anonymous detections (notably on residential, wireless, and CGNAT networks); the displayed history is therefore provider-reported evidence, not a complete forensic log. ProxyCheck.io documents this score as an assessment based on activity it has observed from the IP and whether it appears to be running proxy/VPN infrastructure. It is **not** a calibrated probability that a particular website will detect or block the proxy. Proxy/VPN classification (`proxy`, `type`) is displayed separately from the risk score. Websites use different detection systems and can reach different decisions. If tunnel verification or reputation lookup fails, the app must not display a fabricated 0% score.

Color bands in the Android UI: 0–39 green (very low/low provider risk), 40–74 yellow (medium provider risk), and 75–100 red (high/very high provider risk, with darker red from 90). These are display bands for the provider's IP risk score, not universal website blocking thresholds.

The exit IP is disclosed to ProxyCheck.io for lookup. Proxy host, port, and credentials are not included in that reputation request. The app currently uses the provider's no-key endpoint; availability, query limits, response fields, and terms are controlled by the provider and must be reviewed before commercial launch. No guarantee is made that every proxy type, authentication scheme, DNS leak, WebRTC leak, or website-specific detection method is covered.
