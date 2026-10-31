package com.proxyguard.android

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Parses the compact proxy formats accepted by the standalone Risk Auditor.
 * Credentials remain in memory only and are never included in diagnostic text.
 */
internal object ProxyInputParser {
    fun parse(input: String): ProxyEndpoint {
        val normalized = normalizeDigits(input.trim())
        require(normalized.isNotBlank()) { "أدخل عنوان البروكسي أولاً." }
        require(normalized.length <= 1_000) { "بيانات البروكسي أطول من المسموح." }

        val hasScheme = Regex("^[A-Za-z][A-Za-z0-9+.-]*://").containsMatchIn(normalized)
        val uriText = if (hasScheme) normalized else "socks://$normalized"
        val uri = try {
            URI(uriText)
        } catch (error: Exception) {
            throw IllegalArgumentException("صيغة عنوان البروكسي غير صحيحة؛ استخدم host:port أو protocol://host:port.")
        }

        val protocol = when (uri.scheme?.lowercase()) {
            "http" -> ProxyProtocol.HTTP
            "https" -> ProxyProtocol.HTTPS
            "socks5", "socks5h" -> ProxyProtocol.SOCKS5
            "socks" -> ProxyProtocol.SOCKS_AUTO
            else -> throw IllegalArgumentException("الأنواع المدعومة: HTTP وHTTPS وSOCKS وSOCKS5.")
        }

        require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
            "لا تضع مساراً بعد عنوان البروكسي أو المنفذ."
        }
        require(uri.rawQuery == null && uri.rawFragment == null) {
            "لا تدعم صيغة البروكسي معاملات إضافية أو أجزاء URL."
        }

        val host = uri.host
            ?.removePrefix("[")
            ?.removeSuffix("]")
            ?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("تعذر قراءة اسم مضيف البروكسي أو عنوان IP.")
        val port = uri.port
        require(port in 1..65535) { "أدخل منفذاً صحيحاً بين 1 و65535." }

        val username: String?
        val password: String?
        val rawUserInfo = uri.rawUserInfo
        if (rawUserInfo == null) {
            username = null
            password = null
        } else {
            val separator = rawUserInfo.indexOf(':')
            require(separator > 0 && separator < rawUserInfo.lastIndex) {
                "عند تضمين بيانات الدخول داخل العنوان، استخدم user:pass@host:port."
            }
            username = decode(rawUserInfo.substring(0, separator))
            password = decode(rawUserInfo.substring(separator + 1))
            require(username.isNotBlank() && password.isNotBlank()) {
                "اسم المستخدم وكلمة المرور لا يمكن أن يكونا فارغين."
            }
        }

        return ProxyEndpoint(host, port, protocol, username, password)
    }

    private fun decode(value: String): String =
        URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())

    private fun normalizeDigits(value: String): String = buildString {
        value.forEach { character ->
            append(
                when (character) {
                    in '٠'..'٩' -> ('0'.code + (character - '٠')).toChar()
                    in '۰'..'۹' -> ('0'.code + (character - '۰')).toChar()
                    else -> character
                }
            )
        }
    }
}
