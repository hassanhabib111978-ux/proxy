package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Test

class ProxyRiskPresentationTest {
    @Test fun thresholdsFollowTheAgreedScale() {
        assertEquals("green", ProxyRiskPresentation.colorBand(0))
        assertEquals("green", ProxyRiskPresentation.colorBand(39))
        assertEquals("yellow", ProxyRiskPresentation.colorBand(40))
        assertEquals("yellow", ProxyRiskPresentation.colorBand(74))
        assertEquals("red", ProxyRiskPresentation.colorBand(75))
        assertEquals("red", ProxyRiskPresentation.colorBand(100))
    }

    @Test fun labelsChangeAtEachThreshold() {
        assertEquals("منخفض جداً", ProxyRiskPresentation.level(19))
        assertEquals("منخفض", ProxyRiskPresentation.level(20))
        assertEquals("متوسط", ProxyRiskPresentation.level(40))
        assertEquals("متوسط", ProxyRiskPresentation.level(74))
        assertEquals("مرتفع", ProxyRiskPresentation.level(75))
        assertEquals("مرتفع جداً", ProxyRiskPresentation.level(90))
    }
}
