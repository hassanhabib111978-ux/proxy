package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Test

class ProxyIpWatchLogicTest {
    @Test
    fun firstSuccessfulObservationEstablishesBaselineWithoutAlert() {
        assertEquals(IpWatchComparison.BASELINE, compareExitIp(null, "198.51.100.10"))
    }

    @Test
    fun identicalExitIpDoesNotTriggerChange() {
        assertEquals(
            IpWatchComparison.UNCHANGED,
            compareExitIp("198.51.100.10", "198.51.100.10")
        )
    }

    @Test
    fun differentExitIpTriggersConfirmedChange() {
        assertEquals(
            IpWatchComparison.CHANGED,
            compareExitIp("198.51.100.10", "203.0.113.25")
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun emptyCurrentIpIsRejected() {
        compareExitIp("198.51.100.10", "")
    }
}
