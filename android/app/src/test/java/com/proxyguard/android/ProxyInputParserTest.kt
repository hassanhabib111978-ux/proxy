package com.proxyguard.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ProxyInputParserTest {
    @Test
    fun parsesPlainHostAndPortAsAutoSocks() {
        val endpoint = ProxyInputParser.parse("84.201.5.23:8950")
        assertEquals("84.201.5.23", endpoint.host)
        assertEquals(8950, endpoint.port)
        assertEquals(ProxyProtocol.SOCKS_AUTO, endpoint.protocol)
        assertNull(endpoint.username)
        assertNull(endpoint.password)
    }

    @Test
    fun parsesAuthenticatedSocks5Url() {
        val endpoint = ProxyInputParser.parse("socks5://demo:secret@proxy.example:1080")
        assertEquals("proxy.example", endpoint.host)
        assertEquals(1080, endpoint.port)
        assertEquals(ProxyProtocol.SOCKS5, endpoint.protocol)
        assertEquals("demo", endpoint.username)
        assertEquals("secret", endpoint.password)
    }

    @Test
    fun decodesUrlEncodedCredentials() {
        val endpoint = ProxyInputParser.parse("socks5h://user%40name:p%3Aword@proxy.example:1080")
        assertEquals("user@name", endpoint.username)
        assertEquals("p:word", endpoint.password)
    }

    @Test
    fun recognizesHttpAndHttpsSchemes() {
        assertEquals(ProxyProtocol.HTTP, ProxyInputParser.parse("http://proxy.example:8080").protocol)
        assertEquals(ProxyProtocol.HTTPS, ProxyInputParser.parse("https://proxy.example:443").protocol)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnknownScheme() {
        ProxyInputParser.parse("ftp://proxy.example:21")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMissingPasswordForEmbeddedCredentials() {
        ProxyInputParser.parse("socks5://demo@proxy.example:1080")
    }
}
