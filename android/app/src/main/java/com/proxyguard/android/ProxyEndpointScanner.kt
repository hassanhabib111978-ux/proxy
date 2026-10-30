package com.proxyguard.android

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal enum class ProxyProtocol { HTTP, HTTPS, SOCKS5 }

internal data class ProxyEndpoint(
    val host: String,
    val port: Int,
    val protocol: ProxyProtocol,
    val username: String? = null,
    val password: String? = null
)

internal data class ProxyScanResult(
    val exitIp: String,
    val riskScore: Int,
    val proxyDetected: Boolean,
    val vpnDetected: Boolean,
    val networkType: String?,
    val provider: String?,
    val country: String?,
    val evidence: List<String>
)

internal class ProxyScanException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Tests a user-supplied proxy without changing Android's system proxy settings.
 * Credentials are held only for this call and are never persisted or sent to the
 * reputation provider. Only the observed exit IP is submitted to proxycheck.io.
 */
internal object ProxyEndpointScanner {
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 8_000
    private const val MAX_RESPONSE_BYTES = 32 * 1024
    private const val IP_ECHO_HOST = "api.ipify.org"
    private const val IP_ECHO_PORT = 443

    fun scan(endpoint: ProxyEndpoint): ProxyScanResult {
        validate(endpoint)
        val exitIp = try {
            fetchExitIp(endpoint)
        } catch (e: Exception) {
            throw ProxyScanException(
                "تعذر إكمال الاتصال عبر البروكسي: ${safeMessage(e)}", e
            )
        }
        val intel = try {
            lookupReputation(exitIp)
        } catch (e: Exception) {
            throw ProxyScanException(
                "تم الاتصال بالبروكسي واستخراج عنوان الخروج $exitIp، لكن تعذر التحقق من السمعة: ${safeMessage(e)}", e
            )
        }
        val evidence = buildList {
            add("تم إنشاء نفق اتصال مشفر عبر البروكسي بنجاح.")
            add("عنوان IP الظاهر للخروج: $exitIp")
            if (intel.proxyDetected) add("مصدر السمعة صنّف عنوان الخروج كبروكسي.")
            if (intel.vpnDetected) add("مصدر السمعة صنّف عنوان الخروج كـ VPN.")
            intel.networkType?.let { add("نوع الشبكة المسجل: $it") }
            intel.provider?.let { add("الجهة/المزوّد: $it") }
            if (!intel.proxyDetected && !intel.vpnDetected) {
                add("لم يسجل المصدر تطابقاً إيجابياً مع Proxy أو VPN وقت الفحص؛ هذا لا يضمن عدم اكتشافه لدى كل المواقع.")
            }
        }
        return ProxyScanResult(
            exitIp = exitIp,
            riskScore = intel.riskScore,
            proxyDetected = intel.proxyDetected,
            vpnDetected = intel.vpnDetected,
            networkType = intel.networkType,
            provider = intel.provider,
            country = intel.country,
            evidence = evidence
        )
    }

    private data class Reputation(
        val riskScore: Int,
        val proxyDetected: Boolean,
        val vpnDetected: Boolean,
        val networkType: String?,
        val provider: String?,
        val country: String?
    )

    private fun validate(endpoint: ProxyEndpoint) {
        require(endpoint.host.isNotBlank() && endpoint.host.length <= 253) { "أدخل اسم مضيف أو عنوان IP صحيحاً." }
        require(endpoint.host.none { it.isWhitespace() || it == '/' || it == '@' }) { "صيغة عنوان البروكسي غير صحيحة." }
        require(endpoint.port in 1..65535) { "رقم المنفذ يجب أن يكون بين 1 و65535." }
        require((endpoint.username == null) == (endpoint.password == null)) { "أدخل اسم المستخدم وكلمة المرور معاً أو اتركهما فارغين." }
        require((endpoint.username?.length ?: 0) <= 255 && (endpoint.password?.length ?: 0) <= 255) { "بيانات المصادقة أطول من المسموح." }
    }

    private fun fetchExitIp(endpoint: ProxyEndpoint): String {
        val raw = Socket()
        raw.connect(InetSocketAddress(endpoint.host, endpoint.port), CONNECT_TIMEOUT_MS)
        raw.soTimeout = READ_TIMEOUT_MS
        var proxyTransport: Socket = raw
        try {
            if (endpoint.protocol == ProxyProtocol.HTTPS) {
                proxyTransport = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(raw, endpoint.host, endpoint.port, true) as SSLSocket
                (proxyTransport as SSLSocket).soTimeout = READ_TIMEOUT_MS
                (proxyTransport as SSLSocket).sslParameters = (proxyTransport as SSLSocket).sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                (proxyTransport as SSLSocket).startHandshake()
            }

            when (endpoint.protocol) {
                ProxyProtocol.HTTP, ProxyProtocol.HTTPS -> establishHttpTunnel(proxyTransport, endpoint)
                ProxyProtocol.SOCKS5 -> establishSocksTunnel(proxyTransport, endpoint)
            }

            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(proxyTransport, IP_ECHO_HOST, IP_ECHO_PORT, true) as SSLSocket
            tls.soTimeout = READ_TIMEOUT_MS
            tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            tls.startHandshake()
            tls.getOutputStream().write(
                ("GET / HTTP/1.1\r\nHost: $IP_ECHO_HOST\r\nAccept: text/plain\r\nConnection: close\r\nUser-Agent: ProxyGuard-Android\r\n\r\n")
                    .toByteArray(StandardCharsets.US_ASCII)
            )
            val response = readLimited(tls.getInputStream(), MAX_RESPONSE_BYTES)
            tls.close()
            val body = response.substringAfter("\r\n\r\n", "").trim()
            if (!response.startsWith("HTTP/1.1 200") && !response.startsWith("HTTP/1.0 200")) {
                throw IllegalStateException("خدمة اختبار عنوان الخروج أعادت استجابة غير ناجحة.")
            }
            if (!isIpLiteral(body)) throw IllegalStateException("استجابة عنوان الخروج غير صالحة.")
            return body
        } finally {
            try { proxyTransport.close() } catch (_: Exception) {}
            try { raw.close() } catch (_: Exception) {}
        }
    }

    private fun establishHttpTunnel(socket: Socket, endpoint: ProxyEndpoint) {
        val auth = if (!endpoint.username.isNullOrEmpty()) {
            val token = android.util.Base64.encodeToString(
                "${endpoint.username}:${endpoint.password.orEmpty()}".toByteArray(StandardCharsets.UTF_8),
                android.util.Base64.NO_WRAP
            )
            "Proxy-Authorization: Basic $token\r\n"
        } else ""
        val request = "CONNECT $IP_ECHO_HOST:$IP_ECHO_PORT HTTP/1.1\r\nHost: $IP_ECHO_HOST:$IP_ECHO_PORT\r\n$auth$authConnection: keep-alive\r\n\r\n"
            .replace("$authConnection", "Proxy-Connection")
        socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
        val header = readHeaders(socket.getInputStream())
        val status = header.lineSequence().firstOrNull().orEmpty()
        if (!status.contains(" 200 ")) {
            throw IllegalStateException("رفض البروكسي إنشاء نفق HTTPS (استجابة: ${status.take(80)}).")
        }
    }

    private const val authConnection = "Proxy-Connection"

    private fun establishSocksTunnel(socket: Socket, endpoint: ProxyEndpoint) {
        val out = socket.getOutputStream()
        val input = BufferedInputStream(socket.getInputStream())
        val hasCredentials = !endpoint.username.isNullOrEmpty()
        out.write(if (hasCredentials) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
        val version = input.read()
        val method = input.read()
        if (version != 5 || method == 0xFF || method < 0) throw IllegalStateException("فشل تفاوض SOCKS5.")
        if (method == 0x02) {
            val user = endpoint.username?.toByteArray(StandardCharsets.UTF_8) ?: byteArrayOf()
            val pass = endpoint.password?.toByteArray(StandardCharsets.UTF_8) ?: byteArrayOf()
            require(user.size <= 255 && pass.size <= 255) { "بيانات SOCKS5 أطول من المسموح." }
            out.write(byteArrayOf(0x01, user.size.toByte()))
            out.write(user)
            out.write(pass.size)
            out.write(pass)
            out.flush()
            if (input.read() != 0x01 || input.read() != 0x00) throw IllegalStateException("فشل توثيق SOCKS5.")
        } else if (method != 0x00) {
            throw IllegalStateException("طريقة توثيق SOCKS5 غير مدعومة.")
        } else if (hasCredentials) {
            throw IllegalStateException("البروكسي لم يقبل طريقة التوثيق المطلوبة.")
        }

        val host = IP_ECHO_HOST.toByteArray(StandardCharsets.US_ASCII)
        out.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, host.size.toByte()))
        out.write(host)
        out.write(byteArrayOf((IP_ECHO_PORT shr 8).toByte(), IP_ECHO_PORT.toByte()))
        out.flush()
        val reply = ByteArray(4)
        readFully(input, reply)
        if (reply[0].toInt() != 5 || reply[1].toInt() != 0) {
            throw IllegalStateException("فشل SOCKS5 في فتح الاتصال إلى خدمة اختبار الخروج (رمز ${reply[1].toInt() and 0xff}).")
        }
        val addressLength = when (reply[3].toInt() and 0xff) {
            1 -> 4
            4 -> 16
            3 -> input.read().also { if (it < 0) throw IllegalStateException("استجابة SOCKS5 ناقصة.") }
            else -> throw IllegalStateException("نوع عنوان SOCKS5 غير معروف.")
        }
        val discard = ByteArray(addressLength + 2)
        readFully(input, discard)
    }

    private fun lookupReputation(ip: String): Reputation {
        val url = URL("https://proxycheck.io/v2/$ip?risk=1&vpn=3&asn=1&port=1&seen=1&tag=0")
        val connection = (url.openConnection(Proxy.NO_PROXY) as HttpURLConnection).apply {
            connectTimeout = 7_000
            readTimeout = 7_000
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "ProxyGuard-Android")
        }
        try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val jsonText = stream.use { readLimited(it, MAX_RESPONSE_BYTES) }
            if (code !in 200..299) throw IllegalStateException("مصدر السمعة غير متاح حالياً (HTTP $code).")
            val root = JSONObject(jsonText)
            val status = root.optString("status")
            if (status != "ok" && status != "warning") {
                throw IllegalStateException("مصدر السمعة لم يقبل الطلب: ${root.optString("message", status)}")
            }
            val data = root.optJSONObject(ip) ?: throw IllegalStateException("لم يرجع مصدر السمعة نتيجة لعنوان الخروج.")
            val risk = data.optString("risk").toIntOrNull()
                ?: throw IllegalStateException("مصدر السمعة لم يقدم درجة خطر رقمية؛ لن نخترع نسبة.")
            if (risk !in 0..100) throw IllegalStateException("درجة الخطر الواردة خارج النطاق المتوقع.")
            val proxy = data.optString("proxy").equals("yes", true)
            val type = data.optString("type").takeUnless { it.isBlank() || it == "null" }
            val vpn = type?.contains("vpn", ignoreCase = true) == true
            return Reputation(
                riskScore = risk,
                proxyDetected = proxy,
                vpnDetected = vpn,
                networkType = data.optString("network", "").takeUnless { it.isBlank() || it == "null" },
                provider = data.optString("provider", "").takeUnless { it.isBlank() || it == "null" },
                country = data.optString("isocode", "").takeUnless { it.isBlank() || it == "null" }
            )
        } finally {
            connection.disconnect()
        }
    }

    private fun readHeaders(input: InputStream): String {
        val out = ByteArrayOutputStream()
        var matched = 0
        val end = byteArrayOf(13, 10, 13, 10)
        while (out.size() < 16 * 1024) {
            val b = input.read()
            if (b < 0) break
            out.write(b)
            if (b == end[matched].toInt()) matched++ else matched = if (b == 13) 1 else 0
            if (matched == 4) return out.toString("US-ASCII")
        }
        throw IllegalStateException("استجابة البروكسي غير مكتملة أو أكبر من الحد المسموح.")
    }

    private fun readLimited(input: InputStream, max: Int): String {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (out.size() + count > max) throw IllegalStateException("استجابة الخادم أكبر من الحد المسموح.")
            out.write(buffer, 0, count)
        }
        return out.toString("UTF-8")
    }

    private fun readFully(input: InputStream, target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val count = input.read(target, offset, target.size - offset)
            if (count < 0) throw IllegalStateException("استجابة SOCKS5 ناقصة.")
            offset += count
        }
    }

    private fun isIpLiteral(value: String): Boolean = IpIntelDatabase.parseIpLiteral(value) != null

    private fun safeMessage(error: Exception): String =
        error.message?.take(160) ?: "خطأ اتصال غير محدد"
}
