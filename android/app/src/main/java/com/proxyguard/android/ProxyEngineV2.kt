package com.proxyguard.android

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.IDN
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Inet6Address
import java.net.Socket
import java.nio.charset.StandardCharsets
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Native Android version of the Python toolkit's test/monitor connection logic.
 * Supports HTTP CONNECT and SOCKS5 authentication and tries three independent
 * HTTPS IP endpoints. Credentials are used only in memory and are never logged
 * or persisted by this class.
 *
 * elapsedMs is the complete lookup duration, not a pure network RTT.
 */
internal class ProxyEngineV2 {
    private data class Endpoint(val host: String, val path: String)

    private val endpoints = listOf(
        Endpoint("api.ipify.org", "/"),
        Endpoint("ifconfig.me", "/ip"),
        Endpoint("icanhazip.com", "/")
    )

    fun fetchExitIp(config: ProxyConfig): ProxyResult {
        val started = System.nanoTime()
        if (config.host.isBlank() || config.port !in 1..65535) {
            return ProxyResult(false, elapsedMs = 0L, message = "تحقق من عنوان خادم البروكسي والمنفذ.")
        }
        if (config.username.isNotEmpty() != config.password.isNotEmpty()) {
            return ProxyResult(false, elapsedMs = 0L, message = "أدخل اسم المستخدم وكلمة المرور معاً، أو اتركهما فارغين.")
        }
        val proxyType = config.type.trim().uppercase()
        if (proxyType != "HTTP" && proxyType != "SOCKS5") {
            return ProxyResult(false, elapsedMs = 0L, message = "نوع البروكسي غير مدعوم. اختر HTTP أو SOCKS5.")
        }

        var lastError = "لم تُرجع خدمات فحص IP عنواناً صالحاً."
        for (endpoint in endpoints) {
            try {
                val body = requestThroughProxy(config, proxyType, endpoint)
                val ip = extractIp(body)
                if (ip != null) {
                    val elapsed = (System.nanoTime() - started) / 1_000_000L
                    return ProxyResult(
                        ok = true,
                        ip = ip,
                        elapsedMs = elapsed,
                        message = "تم الفحص عبر " + proxyType + " بنجاح؛ زمن الطلب الكامل " + elapsed + " ms."
                    )
                }
                lastError = "استجاب " + endpoint.host + " بمحتوى لا يحتوي على عنوان IP صالح."
            } catch (e: Exception) {
                lastError = safeReason(e)
            }
        }
        val elapsed = (System.nanoTime() - started) / 1_000_000L
        return ProxyResult(
            ok = false,
            elapsedMs = elapsed,
            message = "تعذر استخراج عنوان IP عبر البروكسي بعد تجربة 3 خدمات مستقلة. آخر سبب: " + lastError
        )
    }

    private fun requestThroughProxy(config: ProxyConfig, proxyType: String, endpoint: Endpoint): String {
        val proxySocket = Socket()
        try {
            proxySocket.connect(java.net.InetSocketAddress(config.host.trim(), config.port), CONNECT_TIMEOUT_MS)
            proxySocket.soTimeout = READ_TIMEOUT_MS
            proxySocket.tcpNoDelay = true

            if (proxyType == "HTTP") establishHttpTunnel(proxySocket, config, endpoint.host)
            else establishSocks5Tunnel(proxySocket, config, endpoint.host)

            val tlsSocket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(proxySocket, endpoint.host, 443, true) as SSLSocket
            tlsSocket.use { secure ->
                secure.soTimeout = READ_TIMEOUT_MS
                val parameters = secure.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                secure.sslParameters = parameters
                secure.startHandshake()

                val request = (
                    "GET " + endpoint.path + " HTTP/1.1\r\n" +
                    "Host: " + endpoint.host + "\r\n" +
                    "Accept: text/plain\r\n" +
                    "Accept-Encoding: identity\r\n" +
                    "Connection: close\r\n\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
                secure.outputStream.write(request)
                secure.outputStream.flush()

                val input = secure.inputStream
                val headerText = String(readHeader(input, MAX_HEADER_BYTES), StandardCharsets.ISO_8859_1)
                val status = headerText.lineSequence().firstOrNull().orEmpty()
                if (!status.contains(" 200 ")) {
                    throw IOException("خدمة IP أعادت استجابة غير ناجحة (" + status + ")")
                }
                val bodyBytes = readLimited(input, MAX_RESPONSE_BYTES)
                val isChunked = headerText.lineSequence().any {
                    it.trim().startsWith("transfer-encoding:", ignoreCase = true) &&
                        it.contains("chunked", ignoreCase = true)
                }
                val decoded = if (isChunked) decodeChunked(bodyBytes) else bodyBytes
                return String(decoded, StandardCharsets.UTF_8).trim()
            }
        } finally {
            runCatching { proxySocket.close() }
        }
    }

    private fun establishHttpTunnel(socket: Socket, config: ProxyConfig, targetHost: String) {
        val output = socket.getOutputStream()
        val request = StringBuilder()
            .append("CONNECT ").append(targetHost).append(":443 HTTP/1.1\r\n")
            .append("Host: ").append(targetHost).append(":443\r\n")
            .append("Proxy-Connection: Keep-Alive\r\n")
        if (config.username.isNotEmpty()) {
            val credentials = config.username + ":" + config.password
            val encoded = Base64.encodeToString(credentials.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
            request.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n")
        }
        request.append("\r\n")
        output.write(request.toString().toByteArray(StandardCharsets.ISO_8859_1))
        output.flush()

        val header = String(readHeader(socket.getInputStream(), MAX_HEADER_BYTES), StandardCharsets.ISO_8859_1)
        val status = header.lineSequence().firstOrNull().orEmpty()
        if (!status.contains(" 200 ")) {
            if (status.contains(" 407 ")) throw IOException("رفض البروكسي بيانات المصادقة (407).")
            throw IOException("تعذر إنشاء نفق HTTPS عبر بروكسي HTTP (" + status + ").")
        }
    }

    private fun establishSocks5Tunnel(socket: Socket, config: ProxyConfig, targetHost: String) {
        val input = socket.getInputStream()
        val output = socket.getOutputStream()
        val hasCredentials = config.username.isNotEmpty()
        output.write(if (hasCredentials) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0))
        output.flush()

        val greeting = readExact(input, 2)
        if (greeting[0].toInt() != 5) throw IOException("استجابة SOCKS غير صالحة.")
        when (greeting[1].toInt() and 0xff) {
            0 -> Unit
            2 -> {
                val user = config.username.toByteArray(StandardCharsets.UTF_8)
                val pass = config.password.toByteArray(StandardCharsets.UTF_8)
                if (user.isEmpty() || pass.isEmpty() || user.size > 255 || pass.size > 255) {
                    throw IOException("بيانات SOCKS5 يجب ألا تتجاوز 255 بايت لكل حقل.")
                }
                output.write(byteArrayOf(1, user.size.toByte()))
                output.write(user)
                output.write(pass.size)
                output.write(pass)
                output.flush()
                val auth = readExact(input, 2)
                if (auth[0].toInt() != 1 || auth[1].toInt() != 0) {
                    throw IOException("رفض خادم SOCKS5 اسم المستخدم أو كلمة المرور.")
                }
            }
            0xff -> throw IOException("خادم SOCKS5 لا يقبل طرق المصادقة المعروضة.")
            else -> throw IOException("طريقة مصادقة SOCKS5 غير مدعومة.")
        }

        val asciiHost = IDN.toASCII(targetHost).toByteArray(StandardCharsets.US_ASCII)
        if (asciiHost.isEmpty() || asciiHost.size > 255) throw IOException("اسم خادم فحص IP غير صالح.")
        output.write(byteArrayOf(5, 1, 0, 3, asciiHost.size.toByte()))
        output.write(asciiHost)
        output.write(byteArrayOf(1, -69))
        output.flush()

        val reply = readExact(input, 4)
        if (reply[0].toInt() != 5) throw IOException("استجابة اتصال SOCKS5 غير صالحة.")
        val code = reply[1].toInt() and 0xff
        val addressType = reply[3].toInt() and 0xff
        when (addressType) {
            1 -> readExact(input, 4)
            4 -> readExact(input, 16)
            3 -> {
                val length = readExact(input, 1)[0].toInt() and 0xff
                readExact(input, length)
            }
            else -> throw IOException("نوع العنوان في رد SOCKS5 غير معروف.")
        }
        readExact(input, 2)
        if (code != 0) throw IOException("رفض خادم SOCKS5 إنشاء الاتصال (رمز " + code + ").")
    }

    private fun readHeader(input: java.io.InputStream, maximum: Int): ByteArray {
        val bytes = ByteArrayOutputStream()
        var matched = 0
        while (bytes.size() < maximum) {
            val value = input.read()
            if (value < 0) throw IOException("انقطع الاتصال قبل اكتمال ترويسة HTTP.")
            bytes.write(value)
            matched = when {
                matched == 0 && value == 13 -> 1
                matched == 1 && value == 10 -> 2
                matched == 2 && value == 13 -> 3
                matched == 3 && value == 10 -> 4
                value == 13 -> 1
                else -> 0
            }
            if (matched == 4) return bytes.toByteArray()
        }
        throw IOException("ترويسة HTTP أكبر من الحد المسموح.")
    }

    private fun readExact(input: java.io.InputStream, count: Int): ByteArray {
        val result = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(result, offset, count - offset)
            if (read < 0) throw IOException("انقطع الاتصال أثناء تفاوض البروكسي.")
            offset += read
        }
        return result
    }

    private fun readLimited(input: java.io.InputStream, maximum: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (output.size() + count > maximum) throw IOException("استجابة خدمة IP تجاوزت الحد المسموح.")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun decodeChunked(raw: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        var position = 0
        while (position < raw.size) {
            val lineEnd = indexOfCrlf(raw, position)
            if (lineEnd < 0) throw IOException("استجابة HTTP مجزأة بصورة غير صالحة.")
            val sizeText = String(raw, position, lineEnd - position, StandardCharsets.US_ASCII)
                .substringBefore(';').trim()
            val size = sizeText.toLongOrNull(16) ?: throw IOException("حجم جزء HTTP غير صالح.")
            position = lineEnd + 2
            if (size == 0L) return output.toByteArray()
            if (size < 0 || size > MAX_RESPONSE_BYTES || position + size + 2 > raw.size) {
                throw IOException("جزء HTTP يتجاوز الحجم المتوقع.")
            }
            output.write(raw, position, size.toInt())
            position += size.toInt()
            if (position + 1 >= raw.size || raw[position] != 13.toByte() || raw[position + 1] != 10.toByte()) {
                throw IOException("فاصل جزء HTTP غير صالح.")
            }
            position += 2
        }
        return output.toByteArray()
    }

    private fun indexOfCrlf(bytes: ByteArray, start: Int): Int {
        for (i in start until bytes.size - 1) {
            if (bytes[i] == 13.toByte() && bytes[i + 1] == 10.toByte()) return i
        }
        return -1
    }

    private fun extractIp(body: String): String? {
        val value = body.trim().lineSequence().firstOrNull()?.trim()?.removePrefix("[")?.removeSuffix("]")
            ?: return null
        if (value.isEmpty() || value.length > 45) return null
        return when {
            value.contains(':') && value.matches(Regex("[0-9a-fA-F:.]+")) -> {
                runCatching { InetAddress.getByName(value) }.getOrNull()
                    ?.takeIf { it is Inet6Address || it.address.size == 16 }
                    ?.hostAddress?.substringBefore('%')
            }
            value.matches(Regex("[0-9.]+")) -> {
                val octets = value.split('.')
                if (octets.size != 4) return null
                val numbers = octets.map { it.toIntOrNull() ?: return null }
                if (numbers.any { it !in 0..255 }) return null
                if (octets.indices.any { octets[it].length > 1 && octets[it].startsWith('0') }) return null
                if (InetAddress.getByAddress(numbers.map { it.toByte() }.toByteArray()) !is Inet4Address) return null
                value
            }
            else -> null
        }
    }

    private fun safeReason(error: Exception): String {
        val message = error.message.orEmpty().replace(Regex("[\\r\\n]+"), " ").take(130)
        return when {
            message.contains("timed out", true) -> "انتهت مهلة الاتصال."
            message.contains("refused", true) -> "رفض خادم البروكسي الاتصال."
            message.isNotBlank() -> message
            else -> "تعذر الوصول إلى خدمة فحص IP."
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 5_000
        const val READ_TIMEOUT_MS = 5_000
        const val MAX_HEADER_BYTES = 16 * 1024
        const val MAX_RESPONSE_BYTES = 32 * 1024
    }
}
