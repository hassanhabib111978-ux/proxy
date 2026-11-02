# ProxyGuard Android 0.6.9 — VPN-aware HTTP/SOCKS5 proxy scanner

## Release status

Version **0.6.9** improves VPN-aware routing diagnostics and distinguishes common SOCKS5 handshake failures (wrong protocol, missing credentials, or rejected authentication methods). Version **0.6.8** added the HTTP/SOCKS5 selector and independent reporting for proxy connectivity and IP reputation; version **0.6.0** added ProxyCheck v3 intelligence. It remains an engineering/test release, not an independently validated commercial security product, independently audited release, or Google Play production-signed build.

## Current behavior

The Android app performs device-configuration checks locally and runs the pre-use proxy scan only after the user starts it. The pre-use scan supports HTTP CONNECT and SOCKS5 (including username/password authentication). A successful tunnel is reported independently from the reputation lookup. When Android denies binding to the physical network while a third-party VPN is active, the scanner no longer silently retries through that VPN; it explains how to exclude ProxyGuard from the VPN or temporarily pause the VPN. SOCKS5 failures identify common HTTP/SOCKS4/TLS protocol mismatches and missing authentication.

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
- Whether a particular website will detect, block, challenge, or accept a connection. A website can use its own IP intelligence, ASN, request/session history, browser signals, TLS fingerprints, and behavioural models.
- DNS leakage from merely displaying configured DNS resolver addresses.
- Every per-app proxy, tunnel, or routing configuration.
- Whether a detected VPN/proxy is malicious, safe, or trustworthy.

Android's platform APIs do not expose every app's network path to an ordinary application. An ordinary app cannot call `VpnService.protect()` on a VPN owned by another app. When a VPN such as Tun2TAP is active, allow ProxyGuard through that VPN's split-tunneling / excluded-app setting (or pause the VPN) before testing a separate proxy. Retrying through the normal app route while the VPN remains active can create a tunnel loop or test the VPN's egress rather than the selected proxy. Absence of a visible setting must never be interpreted as proof that no proxy exists.

## Build and automated tests

Open the `android/` directory in Android Studio with JDK 17 and Android SDK Platform 35, or use the GitHub Actions workflow `.github/workflows/android-build.yml`.

The workflow runs `:app:testDebugUnitTest`, `:app:lintDebug`, and builds a debug APK. The downloadable artifact is named `proxyguard-android-0.6.9-debug`. CI uses a persistent development-only debug signing identity to keep CI test APKs update-compatible. Do not reuse this identity for commercial releases; release builds require a separately protected private signing key. A debug APK is for controlled testing only and is not the production release artifact. Do not bypass Google Play Protect or Android security warnings to install it.

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

The user can enter an optional local proxy label, paste a proxy IP/host (or host:port), enter the port separately when needed, choose HTTP or SOCKS5 using the new quick-selection buttons (SOCKS5 is selected by default), and provide optional username/password. The label is for local report identification only and is never sent to a provider. The scanner tests the endpoint without changing Android's system proxy configuration. It supports HTTP CONNECT, TLS-to-HTTPS-proxy followed by CONNECT, and SOCKS5 (including username/password authentication) and generic SOCKS negotiation: SOCKS5 is attempted first; SOCKS4a is attempted on a fresh connection only when no password credentials are supplied, because SOCKS4a has no password-authentication method.. It then requests the public exit IP through the tested tunnel and queries the stable ProxyCheck.io v3 API for IP risk, proxy/VPN classification, network type, estimated devices behind the IP and subnet, detection confidence, and attack-history counts.

The result has two independent provider indicators, not one ProxyGuard-calibrated probability. The first is the upstream provider's **IP risk score** (recent abuse/reputation and infrastructure classifications; ProxyCheck documents baseline scores before attack history of 33 for Hosting, 50 for VPN, 75 for Scraper/TOR, and 100 for Proxy/Compromised). The second is the provider's **classification confidence**: when ProxyCheck positively classifies the address as anonymous, Proxy, VPN, TOR, Hosting, Scraper, or Compromised, the app displays the provider's detection-confidence score (0–100); when all returned detection flags are negative it displays 0/100 with an explicit note that this only means no positive classification was observed in this provider's current data. If a positive flag is present but the provider supplies no confidence score, the app reports the detection without inventing a percentage. This value is confidence in that provider's classification, not a calibrated probability that an arbitrary website will detect the proxy. Websites may use different IP databases, browser/device signals, session behaviour, DNS/WebRTC observations, or their own history. Device estimates are shown separately: they are not a verified count of subscribers or active proxy sessions, and high sharing is not automatically treated as abuse. The query requests a seven-day attack-history window, but the provider documents that it may suppress some stale or uncertain anonymous detections (notably on residential, wireless, and CGNAT networks); the displayed history is therefore provider-reported evidence, not a complete forensic log. ProxyCheck.io documents this score as an assessment based on activity it has observed from the IP and whether it appears to be running proxy/VPN infrastructure. It is **not** a calibrated probability that a particular website will detect or block the proxy. Proxy/VPN classification (`proxy`, `type`) is displayed separately from the risk score. Websites use different detection systems and can reach different decisions. If the proxy tunnel fails, the connection test is reported as failed. If the tunnel succeeds and an exit IP is obtained but reputation lookup fails or reaches a provider limit, the connection is still reported as successful and the risk score is shown as unavailable, never as a fabricated 0% score.

Color bands in the Android UI: 0–39 green, 40–74 yellow, and 75–100 red (darker red from 90). The provider IP risk score and the source-classification confidence use these display bands independently. The classification card shows the provider's confidence in its positive Proxy/VPN/anonymity/network-category classification; 0/100 means this source returned no positive detection flags at scan time, not that the proxy is impossible to detect. Missing confidence is shown as unavailable, not invented. These are display bands, not universal website blocking thresholds.

The exit IP is disclosed to ProxyCheck.io for lookup. Proxy host, port, and credentials are not included in that reputation request. The app currently uses the provider's no-key endpoint; availability, query limits, response fields, and terms are controlled by the provider and must be reviewed before commercial launch. No guarantee is made that every proxy type, authentication scheme, DNS leak, WebRTC leak, or website-specific detection method is covered.


## IP continuity monitoring (0.6.0)

The user can explicitly start and stop a foreground monitoring session for the entered proxy endpoint. The monitor runs a fresh end-to-end HTTPS tunnel through that same host, port, protocol and authentication pair to api.ipify.org at a user-selected interval of 1, 2, or 5 minutes. It records the first successful exit IP as the baseline. A later, different HTTPS-observed exit IP triggers an Android notification containing the old and new addresses, and is appended to a bounded local history (up to 100 changes). Failed checks do not count as IP changes; the monitor reports the failure and retries at the next interval.

The watcher does not query ProxyCheck on every poll and does not disconnect the proxy or alter Android network routing. Proxy credentials are passed to the in-process foreground service and kept in memory while it runs; they are not written into the watch preferences or the history file. The watcher is START_NOT_STICKY: if Android or the device vendor terminates the service/process, monitoring may stop and must be started again. Notification permission is required on Android 13+ for visible change alerts. The special-use foreground service declaration is for this explicit user-started network continuity task and must be reviewed against Google Play foreground-service policy before any Play distribution.

This measurement confirms a change in the IP observed by api.ipify.org through a new proxy tunnel. It does not guarantee that every destination sees the same egress IP: some providers rotate by destination, per TCP connection, request, sticky-session token, or provider policy. Use the provider's documented sticky-session credentials/token if a stable session is intended. The watcher reuses the same proxy endpoint and credentials, but does not invent or manage vendor-specific session tokens. It provides confirmed-change alerts, not a pre-change prediction. A predicted percentage is intentionally omitted until sufficient independently observed change history exists.
