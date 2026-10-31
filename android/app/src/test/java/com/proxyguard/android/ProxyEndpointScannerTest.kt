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
}
