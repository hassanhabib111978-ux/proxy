# ProxyGuard Android 0.3.1 — local-first diagnostic MVP

## Release status

Version **0.3.1** is an engineering/hardening release candidate for testing. It is not yet a production security product, an independently audited release, or a Google Play production-signed build.

## Current behavior

The Android app performs the following checks locally:

- Detects whether the active Android network reports VPN transport.
- Reads active network transport types and configured DNS resolver addresses.
- Attempts to read an HTTP/SOCKS proxy exposed by the platform `ProxySelector`.
- Lets the user enter an IPv4/IPv6 address and compare it with a CSV CIDR database imported explicitly by the user.
- Stores the imported dataset in app-private storage.

The app does not need a ProxyGuard backend or internet permission for these checks.

## How results are interpreted

The app intentionally does **not** display a 0–100 score or percentage.

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

The workflow runs `:app:testDebugUnitTest` and builds a debug APK. The downloadable artifact is named `proxyguard-android-0.3.1-debug`. A debug APK is for controlled testing only and is not the production release artifact.

## Privacy

The Android build requests `ACCESS_NETWORK_STATE` and intentionally omits `INTERNET`. It has no account, telemetry, analytics, remote logging, or background update service. The user chooses when to import a CSV. The dataset is kept in the app's private files directory.

## Production gates — not yet completed

1. **Authenticated intelligence:** define and implement a signed manifest and authenticated dataset delivery. Verify publisher key, signature, SHA-256, schema version, generation/expiry times, record limits, license metadata, and rollback behavior before atomically replacing the active database.
2. **Data provenance:** use only licensed, documented feeds. Keep per-source timestamps, coverage, category semantics, and update history. Reject stale, unsigned, or malformed feeds.
3. **Test evidence:** build a labeled benchmark with independently verified proxy, VPN, Tor, hosting, mobile/residential, and ordinary ISP samples. Report false positives, false negatives, coverage, and confidence intervals by category and provider.
4. **Device coverage:** test supported Android releases, OEM variants, Wi-Fi, mobile data, IPv4/IPv6, active VPNs, system proxy settings, captive portals, and network transitions on physical devices.
5. **Engineering assurance:** add UI/instrumentation tests, static analysis, dependency and supply-chain checks, crash reporting only with clear consent, secure release signing, reproducible build checks, and an independent security assessment.
6. **Commercial readiness:** publish methodology and limitations, privacy notice, terms, support process, data-retention policy, license register, and customer-facing incident/update policy. Validate willingness to pay before introducing billing.

No “near-zero error” or universal detection claim is acceptable until measured against representative, independently labeled test data. Even then, publish the measured rates and test conditions rather than promising zero errors.
