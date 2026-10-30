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
        assertEquals(20, ProxyIndicatorScoring.scoreForCategory("datacenter")?.score)
    }

    @Test
    fun datacenterIsOnlyAWeakInfrastructureSignal() {
        val result = ProxyIndicatorScoring.scoreForCategory("hosting")
        assertEquals(20, result?.score)
        assertEquals("ضعيفة", result?.label)
    }

    @Test
    fun unknownCategoriesRemainUnavailable() {
        assertNull(ProxyIndicatorScoring.scoreForCategory("ordinary residential ISP"))
        assertNull(ProxyIndicatorScoring.scoreForCategory("unknown"))
    }

    @Test
    fun indicatorBandsMatchTheRequestedColorThresholds() {
        assertEquals("منخفضة", ProxyIndicatorScoring.indicatorBand(0))
        assertEquals("منخفضة", ProxyIndicatorScoring.indicatorBand(25))
        assertEquals("متوسطة", ProxyIndicatorScoring.indicatorBand(26))
        assertEquals("متوسطة", ProxyIndicatorScoring.indicatorBand(50))
        assertEquals("متوسطة", ProxyIndicatorScoring.indicatorBand(74))
        assertEquals("عالية", ProxyIndicatorScoring.indicatorBand(75))
        assertEquals("عالية", ProxyIndicatorScoring.indicatorBand(89))
        assertEquals("مرتفعة جداً", ProxyIndicatorScoring.indicatorBand(90))
        assertEquals("مرتفعة جداً", ProxyIndicatorScoring.indicatorBand(100))
        assertEquals("غير صالحة", ProxyIndicatorScoring.indicatorBand(-1))
        assertEquals("غير صالحة", ProxyIndicatorScoring.indicatorBand(101))
    }

    @Test
    fun indicatorColorsMatchTheFourRequestedLevels() {
        val green = ProxyIndicatorScoring.indicatorStyle(25)!!
        assertEquals("منخفضة", green.label)
        assertEquals(0xFF16A34A.toInt(), green.foregroundColor)

        val blue = ProxyIndicatorScoring.indicatorStyle(50)!!
        assertEquals("متوسطة", blue.label)
        assertEquals(0xFF2563EB.toInt(), blue.foregroundColor)

        val orange = ProxyIndicatorScoring.indicatorStyle(75)!!
        assertEquals("عالية", orange.label)
        assertEquals(0xFFF97316.toInt(), orange.foregroundColor)

        val red = ProxyIndicatorScoring.indicatorStyle(90)!!
        assertEquals("مرتفعة جداً", red.label)
        assertEquals(0xFFDC2626.toInt(), red.foregroundColor)

        assertNull(ProxyIndicatorScoring.indicatorStyle(-1))
        assertNull(ProxyIndicatorScoring.indicatorStyle(101))
    }
}
