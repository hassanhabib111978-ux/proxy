package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ProxyIndicatorScoringTest {
    @Test
    fun deviceSignalScoreRequiresAnObservedSignal() {
        assertNull(ProxyIndicatorScoring.deviceSignalScore(vpn = false, systemProxy = false))
    }

    @Test
    fun deviceSignalScoreDistinguishesVpnAndSystemProxy() {
        assertEquals(75, ProxyIndicatorScoring.deviceSignalScore(vpn = true, systemProxy = false))
        assertEquals(90, ProxyIndicatorScoring.deviceSignalScore(vpn = false, systemProxy = true))
        assertEquals(100, ProxyIndicatorScoring.deviceSignalScore(vpn = true, systemProxy = true))
    }

    @Test
    fun recognizedIpCategoriesReceiveDocumentedIndicatorWeights() {
        assertEquals(95, ProxyIndicatorScoring.scoreForCategory("residential proxy")?.score)
        assertEquals(90, ProxyIndicatorScoring.scoreForCategory("proxy")?.score)
        assertEquals(88, ProxyIndicatorScoring.scoreForCategory("Tor exit")?.score)
        assertEquals(82, ProxyIndicatorScoring.scoreForCategory("VPN")?.score)
        assertEquals(35, ProxyIndicatorScoring.scoreForCategory("datacenter")?.score)
    }

    @Test
    fun datacenterIsOnlyAWeakInfrastructureSignal() {
        val result = ProxyIndicatorScoring.scoreForCategory("hosting")
        assertEquals(35, result?.score)
        assertEquals("ضعيفة", result?.label)
    }

    @Test
    fun unknownCategoriesRemainUnavailable() {
        assertNull(ProxyIndicatorScoring.scoreForCategory("ordinary residential ISP"))
        assertNull(ProxyIndicatorScoring.scoreForCategory("unknown"))
    }

    @Test
    fun indicatorBandsUseExplicitBoundaries() {
        assertEquals("قوية جداً", ProxyIndicatorScoring.indicatorBand(95))
        assertEquals("قوية", ProxyIndicatorScoring.indicatorBand(85))
        assertEquals("واضحة", ProxyIndicatorScoring.indicatorBand(60))
        assertEquals("ضعيفة", ProxyIndicatorScoring.indicatorBand(30))
        assertEquals("ضعيفة جداً", ProxyIndicatorScoring.indicatorBand(29))
    }
}
