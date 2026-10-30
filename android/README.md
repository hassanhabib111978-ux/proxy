# ProxyGuard Android — local-first MVP

This is a native Android application scaffold. It does not use a backend, analytics SDK, remote IP API, or network permission.

## Current local checks
- Detects whether Android reports an active VPN transport.
- Reads active network transports and configured DNS resolver addresses.
- Attempts to display an HTTP/SOCKS proxy exposed by the platform ProxySelector.
- Lets the user enter an IPv4/IPv6 address and compare it with an imported local CIDR database.
- Imports CSV files through Android's document picker and stores the parsed database in app-private storage.

## CSV format
UTF-8 CSV with a header row:

```csv
cidr,category,source
198.51.100.0/24,datacenter,Example feed
2001:db8::/32,hosting,Example feed
```

Use real, licensed datasets only. The example ranges above are documentation-only reserved ranges and are not threat intelligence.

## Build
Open the `android/` directory in Android Studio (JDK 17; Android SDK Platform 35), allow Gradle sync, then Build > Build Bundle(s) / APK(s) > Build APK(s).

No server or API key is required to build or run this version. Gradle/Android Gradle Plugin downloads may require internet during the first build.

## Explainable indicators (prototype)

The app displays two distinct kinds of result:

- **Device proxy/tunnel indicator:** based only on an Android-visible active VPN transport and/or a system HTTP/SOCKS proxy exposed through `ProxySelector`. The heuristic display is 75/100 for a visible VPN, 90/100 for a visible system proxy, and 100/100 when both are visible. This measures how strongly the device exposes a proxy/tunnel configuration; it is not a maliciousness or safety score.
- **Manual IP proxy-classification indicator:** only available when the entered IP matches an imported CIDR row with a recognized category. The current prototype maps residential proxy to 95/100, proxy to 90/100, Tor/exit node to 88/100, VPN to 82/100, and hosting/datacenter/cloud to 35/100 (weak infrastructure signal only). Unrecognized categories and no-match results are shown as unavailable rather than 0/100.

These numbers are transparent heuristic indices, **not calibrated probabilities** (for example, 90/100 does not mean a 90% statistical chance of danger). Imported feeds are not authenticated or freshness-checked in this prototype, so source confidence is explicitly limited. A hosting/datacenter classification alone does not prove that an address is a proxy. Absence of a match does not mean safe.

## Deliberate limitations
- No public-egress IP lookup: this would require contacting an external endpoint or running a user-controlled endpoint.
- No remote reputation lookup: the app only compares against the database the user imported.
- No packet interception, traffic redirection, VPN service, or claim to detect every proxy.
- Android may not expose per-app proxy configuration or all tunnel details to ordinary apps.
- DNS resolver addresses are configuration observations, not a DNS leak test.
- An absent local match means "not found in this database", not "safe".

## Next engineering gates
1. Add a robust quoted-CSV parser and signed database manifest with freshness metadata.
2. Verify dataset licensing, provenance, update URL and integrity/signature before bundling any feed.
3. Add unit tests for IPv4/IPv6 CIDR matching and import limits.
4. Add a dedicated UI for database date, source, record count and stale status.
5. Build and test APK on real Android devices and multiple Android versions.
