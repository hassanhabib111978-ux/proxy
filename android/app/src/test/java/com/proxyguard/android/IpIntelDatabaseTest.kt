package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpIntelDatabaseTest {
    private fun ip(value: String) = requireNotNull(IpIntelDatabase.parseIpLiteral(value))

    @Test
    fun ipv4CidrMatchesInsideAndRejectsOutsideAddresses() {
        assertTrue(IpIntelDatabase.cidrContains("192.0.2.0/24", ip("192.0.2.1")))
        assertTrue(IpIntelDatabase.cidrContains("192.0.2.0/24", ip("192.0.2.255")))
        assertFalse(IpIntelDatabase.cidrContains("192.0.2.0/24", ip("192.0.3.1")))
    }

    @Test
    fun ipv4PrefixBoundariesAreHandled() {
        assertTrue(IpIntelDatabase.cidrContains("0.0.0.0/0", ip("203.0.113.9")))
        assertTrue(IpIntelDatabase.cidrContains("203.0.113.9/32", ip("203.0.113.9")))
        assertFalse(IpIntelDatabase.cidrContains("203.0.113.9/32", ip("203.0.113.10")))
    }

    @Test
    fun ipv6CidrMatchesInsideAndOutsideAddresses() {
        assertTrue(IpIntelDatabase.cidrContains("2001:db8:1234::/48", ip("2001:db8:1234:ffff::1")))
        assertFalse(IpIntelDatabase.cidrContains("2001:db8:1234::/48", ip("2001:db8:1235::1")))
        assertTrue(IpIntelDatabase.cidrContains("2001:db8::1/128", ip("2001:db8::1")))
    }

    @Test
    fun ipv4AndIpv6NetworksNeverCrossMatch() {
        assertFalse(IpIntelDatabase.cidrContains("192.0.2.0/24", ip("2001:db8::1")))
        assertFalse(IpIntelDatabase.cidrContains("2001:db8::/32", ip("192.0.2.1")))
    }

    @Test
    fun invalidLiteralsAndCidrsAreRejected() {
        listOf("example.com", "256.1.1.1", "192.0.2", "01.2.3.4", "fe80::1%wlan0", "").forEach {
            assertNull("Expected invalid IP: $it", IpIntelDatabase.parseIpLiteral(it))
        }
        listOf("192.0.2.0/33", "2001:db8::/129", "192.0.2.0/-1", "192.0.2.0/+24",
            "192.0.2.0/024", "example.com/24", "192.0.2.0", "192.0.2.0/24/1").forEach {
            assertFalse("Expected invalid CIDR: $it", IpIntelDatabase.validCidr(it))
        }
    }

    @Test
    fun csvSupportsQuotedCommasAndEscapedQuotes() {
        val entries = IpIntelDatabase.parseCsv(
            "cidr,category,source\r\n" +
                "192.0.2.0/24,proxy,\"Provider, Region 1\"\r\n" +
                "2001:db8::/32,VPN,\"Provider \"\"Alpha\"\"\""
        )
        assertEquals(2, entries.size)
        assertEquals("Provider, Region 1", entries[0].source)
        assertEquals("Provider \"Alpha\"", entries[1].source)
    }

    @Test
    fun csvSupportsBomAndOptionalSourceColumn() {
        val entries = IpIntelDatabase.parseCsv(
            "\uFEFFCIDR,CATEGORY,SOURCE\n192.0.2.1/32,proxy,\n"
        )
        assertEquals(1, entries.size)
        assertEquals("مستورد محلياً", entries[0].source)
    }

    @Test
    fun csvRejectsMalformedQuotesAndWrongHeaders() {
        listOf(
            "cidr,category,source\n192.0.2.0/24,proxy,\"missing",
            "cidr,category,source\n192.0.2.0/24,proxy,\"closed\"junk",
            "address,kind,source\n192.0.2.0/24,proxy,test"
        ).forEach { raw ->
            try {
                IpIntelDatabase.parseCsv(raw)
                throw AssertionError("Expected CSV parsing to fail")
            } catch (_: IllegalArgumentException) {
                // Expected: import is rejected instead of partially accepted.
            }
        }
    }

    @Test
    fun csvRejectsControlCharactersInLabels() {
        val raw = "cidr,category,source\n192.0.2.0/24,proxy,\"source\ncontinued\""
        try {
            IpIntelDatabase.parseCsv(raw)
            throw AssertionError("Expected control character to be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }

    @Test
    fun csvRejectsEmptyDatabaseAndWrongColumnCount() {
        listOf(
            "cidr,category,source\n",
            "cidr,category,source\n192.0.2.0/24,proxy,source,extra"
        ).forEach { raw ->
            try {
                IpIntelDatabase.parseCsv(raw)
                throw AssertionError("Expected invalid database to be rejected")
            } catch (_: IllegalArgumentException) {
                // Expected.
            }
        }
    }
}
