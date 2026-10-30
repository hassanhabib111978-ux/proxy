package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyIndicatorScoringTest {
    @Test
    fun deviceFindingReportsVpnWithoutCallingItRisky() {
        val result = ProxyIndicatorScoring.deviceFinding(vpn = true, systemProxy = false)
        assertEquals("رُصد اتصال VPN", result.label)
        assertTrue(result.detail.contains("ليس خطراً"))
    }

    @Test
    fun deviceFindingDistinguishesSystemProxy() {
        val result = ProxyIndicatorScoring.deviceFinding(vpn = false, systemProxy = true)
        assertEquals("رُصد إعداد Proxy للنظام", result.label)
    }

    @Test
    fun deviceFindingReportsBothObservedSignals() {
        val result = ProxyIndicatorScoring.deviceFinding(vpn = true, systemProxy = true)
        assertEquals("رُصد VPN وإعداد Proxy للنظام", result.label)
    }

    @Test
    fun absenceOfVisibleSignalsIsNotReportedAsProofOfAbsence() {
        val result = ProxyIndicatorScoring.deviceFinding(vpn = false, systemProxy = false)
        assertEquals("لم تُرصد مؤشرات ظاهرة", result.label)
        assertTrue(result.detail.contains("لا يعني ذلك خلو الاتصال"))
    }

    @Test
    fun recognizedIpCategoriesAreClassificationsNotNumericScores() {
        assertEquals("بروكسي سكني", ProxyIndicatorScoring.classifyCategory("residential proxy")?.label)
        assertEquals("Proxy / خادم وسيط", ProxyIndicatorScoring.classifyCategory("proxy")?.label)
        assertEquals("Tor / عقدة خروج", ProxyIndicatorScoring.classifyCategory("Tor exit")?.label)
        assertEquals("VPN", ProxyIndicatorScoring.classifyCategory("VPN")?.label)
        assertEquals("استضافة / مركز بيانات", ProxyIndicatorScoring.classifyCategory("datacenter")?.label)
    }

    @Test
    fun proxyAndVpnCategoriesAcceptCommonSeparatorsAndArabic() {
        assertEquals("Proxy / خادم وسيط", ProxyIndicatorScoring.classifyCategory("http_proxy")?.label)
        assertEquals("VPN", ProxyIndicatorScoring.classifyCategory("vpn-provider")?.label)
        assertEquals("بروكسي سكني", ProxyIndicatorScoring.classifyCategory("بروكسي سكني")?.label)
    }

    @Test
    fun infrastructureAloneDoesNotBecomeAProxyClassification() {
        val result = ProxyIndicatorScoring.classifyCategory("cloud hosting")
        assertEquals("استضافة / مركز بيانات", result?.label)
        assertTrue(result?.detail?.contains("لا تثبت وجود Proxy") == true)
    }

    @Test
    fun unrelatedOrAmbiguousCategoriesRemainUnclassified() {
        assertNull(ProxyIndicatorScoring.classifyCategory("ordinary residential ISP"))
        assertNull(ProxyIndicatorScoring.classifyCategory("tornado"))
        assertNull(ProxyIndicatorScoring.classifyCategory("unknown"))
    }
}
