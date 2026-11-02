package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyEndpointScannerTest {
    private val ip = "203.0.113.10"

    @Test
    fun parsesLegacyV2RiskAndClassificationFields() {
        val result = ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """
            {
              "status": "ok",
              "$ip": {
                "risk": "72",
                "proxy": "yes",
                "type": "VPN",
                "provider": "Example Network",
                "isocode": "US",
                "asn": "AS64500"
              }
            }
            """.trimIndent()
        )

        assertEquals(72, result.riskScore)
        assertTrue(result.proxyDetected)
        assertTrue(result.vpnDetected)
        assertEquals("VPN", result.classificationType)
        assertEquals("Example Network", result.provider)
        assertEquals("US", result.country)
        assertEquals(null, result.region)
        assertEquals(null, result.city)
        assertEquals(null, result.operatorName)
        assertEquals(null, result.operatorPopularity)
        assertEquals(null, result.operatorAnonymity)
        assertEquals(null, result.operatorServices)
        assertEquals("AS64500", result.asn)
    }

    @Test
    fun acceptsWarningStatusAndBooleanProxyValues() {
        val result = ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """
            {
              "status": "warning",
              "$ip": {
                "risk": 18,
                "proxy": false,
                "type": "Residential"
              }
            }
            """.trimIndent()
        )

        assertEquals(18, result.riskScore)
        assertFalse(result.proxyDetected)
        assertFalse(result.vpnDetected)
        assertEquals("Residential", result.classificationType)
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsMissingRiskInsteadOfInventingZero() {
        ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """{"status":"ok","$ip":{"proxy":"no"}}"""
        )
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsOutOfRangeRiskScore() {
        ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """{"status":"ok","$ip":{"risk":"101","proxy":"no"}}"""
        )
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsResponseWithoutRequestedIp() {
        ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """{"status":"ok","198.51.100.2":{"risk":"0","proxy":"no"}}"""
        )
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsProviderErrorStatus() {
        ProxyEndpointScanner.parseProxyCheckV2Response(
            ip,
            """{"status":"denied","message":"quota exceeded"}"""
        )
    }

    @Test
    fun parsesV3DeviceEstimatesConfidenceAndAttackHistory() {
        val result = ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """
            {
              "status": "ok",
              "$ip": {
                "network": {
                  "asn": "AS64500",
                  "provider": "Example Network",
                  "type": "Residential"
                },
                "location": {
                  "country": "United States",
                  "country_code": "US",
                  "region": "New York",
                  "city": "New York"
                },
                "device_estimate": { "address": 143, "subnet": 920 },
                "operator": {
                  "name": "Example Proxy Network",
                  "popularity": "medium",
                  "anonymity": "high",
                  "services": ["residential_proxies", "datacenter_vpns"]
                },
                "detections": {
                  "anonymous": true,
                  "proxy": false,
                  "vpn": true,
                  "tor": false,
                  "hosting": false,
                  "risk": 67,
                  "confidence": 91,
                  "first_seen": "2026-10-25T10:00:00Z",
                  "last_seen": "2026-10-31T08:00:00Z"
                },
                "attack_history": {
                  "login_attempt": 4,
                  "registration_attempt": 3
                },
                "last_updated": "2026-10-31T09:00:00Z"
              }
            }
            """.trimIndent()
        )

        assertEquals(67, result.riskScore)
        assertFalse(result.proxyDetected)
        assertTrue(result.vpnDetected)
        assertEquals("VPN", result.classificationType)
        assertEquals("Residential", result.networkType)
        assertEquals("Example Network", result.provider)
        assertEquals("United States", result.country)
        assertEquals("AS64500", result.asn)
        assertEquals(143, result.estimatedDevicesAtAddress)
        assertEquals(920, result.estimatedDevicesInSubnet)
        assertEquals(91, result.confidenceScore)
        assertEquals(91, result.detectabilityScore)
        assertEquals(true, result.anonymousDetected)
        assertEquals(false, result.hostingDetected)
        assertTrue(result.detectionSignals.orEmpty().contains("VPN"))
        assertTrue(result.detectionSignals.orEmpty().contains("Anonymous / عنوان مصنّف كمجهول"))
        assertEquals(7, result.attackHistoryCount)
        assertEquals("2026-10-25T10:00:00Z", result.firstSeen)
        assertEquals("2026-10-31T08:00:00Z", result.lastSeen)
        assertEquals("2026-10-31T09:00:00Z", result.lastUpdated)
    }

    @Test
    fun leavesUnavailableV3DeviceEstimatesNull() {
        val result = ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """
            {
              "status": "ok",
              "$ip": {
                "network": { "type": "Wireless" },
                "location": { "country_code": "PL" },
                "device_estimate": { "address": null, "subnet": null },
                "detections": {
                  "anonymous": false,
                  "proxy": false,
                  "vpn": false,
                  "tor": false,
                  "hosting": false,
                  "risk": 0,
                  "confidence": null
                },
                "attack_history": null,
                "detection_history": null,
                "last_updated": "2026-10-31T09:00:00Z"
              }
            }
            """.trimIndent()
        )

        assertEquals(0, result.riskScore)
        assertEquals(0, result.detectabilityScore)
        assertEquals(false, result.anonymousDetected)
        assertEquals(emptyList<String>(), result.detectionSignals)
        assertEquals(null, result.estimatedDevicesAtAddress)
        assertEquals(null, result.estimatedDevicesInSubnet)
        assertEquals(null, result.confidenceScore)
        assertEquals(null, result.attackHistoryCount)
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsV3ResponseWithoutRiskInsteadOfInventingZero() {
        ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """{"status":"ok","$ip":{"detections":{"proxy":false,"vpn":false}}}"""
        )
    }

    @Test(expected = IllegalStateException::class)
    fun rejectsV3OutOfRangeRisk() {
        ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """{"status":"ok","$ip":{"detections":{"risk":101}}}"""
        )
    }


    @Test
    fun reportsMissingDetectionFlagsAsUnavailableRatherThanZero() {
        val result = ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """
            {
              "status": "ok",
              "$ip": {
                "network": { "type": "Business" },
                "detections": { "risk": 12 }
              }
            }
            """.trimIndent()
        )

        assertEquals(null, result.detectabilityScore)
        assertEquals(emptyList<String>(), result.detectionSignals)
    }

    @Test
    fun hostingNetworkTypeIsShownAsAClassificationSignal() {
        val result = ProxyEndpointScanner.parseProxyCheckV3Response(
            ip,
            """
            {
              "status": "ok",
              "$ip": {
                "network": { "type": "Hosting" },
                "detections": {
                  "anonymous": false,
                  "proxy": false,
                  "vpn": false,
                  "risk": 33,
                  "confidence": 84
                }
              }
            }
            """.trimIndent()
        )

        assertEquals(84, result.detectabilityScore)
        assertTrue(result.detectionSignals.orEmpty().contains("Hosting / مركز بيانات"))
    }


    @Test
    fun explainsHttpEndpointWhenSocks5WasSelected() {
        assertTrue(
            ProxyEndpointScanner.socks5NegotiationFailure(0x48, 0, false)
                .contains("خادم HTTP")
        )
    }

    @Test
    fun explainsSocks4EndpointWhenSocks5WasSelected() {
        assertTrue(
            ProxyEndpointScanner.socks5NegotiationFailure(0x04, 0, false)
                .contains("SOCKS4")
        )
    }

    @Test
    fun explainsAuthenticationRequiredBySocks5Server() {
        assertTrue(
            ProxyEndpointScanner.socks5NegotiationFailure(5, 2, false)
                .contains("يتطلب اسم مستخدم وكلمة مرور")
        )
    }

    @Test
    fun explainsRejectedSocks5AuthenticationMethods() {
        assertTrue(
            ProxyEndpointScanner.socks5NegotiationFailure(5, 0xFF, false)
                .contains("طرق المصادقة")
        )
    }

}
