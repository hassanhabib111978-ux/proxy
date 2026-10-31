package com.proxyguard.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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

internal enum class ProxyProtocol { HTTP, HTTPS, SOCKS5, SOCKS_AUTO }

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
    val sourceVersion: String = "v3",
    val proxyDetected: Boolean,
    val vpnDetected: Boolean,
    val classificationType: String?,
    val provider: String?,
    val country: String?,
    val asn: String?,
    val evidence: List<String>,
    val estimatedDevicesAtAddress: Int? = null,
    val estimatedDevicesInSubnet: Int? = null,
    val confidenceScore: Int? = null,
    val attackHistoryCount: Int? = null,
    val firstSeen: String? = null,
    val lastSeen: String? = null,
    val lastUpdated: String? = null,
    val networkType: String? = null,
    val city: String? = null,
    val region: String? = null,
    val operatorName: String? = null,
    val operatorPopularity: String? = null,
    val operatorAnonymity: String? = null,
    val operatorServices: List<String>? = null,
    val anonymousDetected: Boolean? = null,
    val hostingDetected: Boolean? = null,
    val torDetected: Boolean? = null,
    val scraperDetected: Boolean? = null,
    val compromisedDetected: Boolean? = null,
    val detectabilityScore: Int? = null,
    val detectionSignals: List<String>? = null
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
    private val IP_ECHO_HOSTS = listOf("api.ipify.org", "checkip.amazonaws.com", "icanhazip.com")
    private const val IP_ECHO_PORT = 443

    fun scan(context: Context, endpoint: ProxyEndpoint): ProxyScanResult {
        validate(endpoint)
        val directNetwork = selectUnderlyingNetwork(context)
        val exitIp = try {
            fetchExitIp(endpoint, directNetwork)
        } catch (e: Exception) {
            throw ProxyScanException(
                "تعذر إكمال الاتصال عبر البروكسي: ${safeMessage(e)}", e
            )
        }
        val intel = try {
            lookupReputation(exitIp, directNetwork)
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
            if (intel.anonymousDetected == true) add("مصدر السمعة وضع علامة Anonymous على عنوان الخروج.")
            intel.classificationType?.let { add("تصنيف عنوان IP لدى المصدر: $it") }
            intel.provider?.let { add("الجهة/المزوّد: $it") }
            intel.asn?.let { add("رقم النظام المستقل ASN: $it") }
            intel.estimatedDevicesAtAddress?.let { add("تقدير الأجهزة خلف عنوان IP: نحو $it جهازاً") }
            intel.estimatedDevicesInSubnet?.let { add("تقدير الأجهزة خلف الشبكة الفرعية: نحو $it جهازاً") }
            intel.attackHistoryCount?.let { add("أحداث الهجوم المرصودة في سجل المصدر: $it") }
            intel.confidenceScore?.let { add("ثقة تصنيف المصدر: $it/100") }
            if (intel.detectabilityScore == 0 && intel.detectionSignals.orEmpty().isEmpty()) {
                add("لم يرصد المصدر تصنيفاً إيجابياً ضمن إشاراته الحالية؛ هذا لا يضمن عدم تعرف مواقع أو قواعد بيانات أخرى على العنوان.")
            }
        }
        return ProxyScanResult(
            exitIp = exitIp,
            riskScore = intel.riskScore,
            sourceVersion = intel.sourceVersion,
            proxyDetected = intel.proxyDetected,
            vpnDetected = intel.vpnDetected,
            classificationType = intel.classificationType,
            provider = intel.provider,
            country = intel.country,
            asn = intel.asn,
            evidence = evidence,
            estimatedDevicesAtAddress = intel.estimatedDevicesAtAddress,
            estimatedDevicesInSubnet = intel.estimatedDevicesInSubnet,
            confidenceScore = intel.confidenceScore,
            attackHistoryCount = intel.attackHistoryCount,
            firstSeen = intel.firstSeen,
            lastSeen = intel.lastSeen,
            lastUpdated = intel.lastUpdated,
            networkType = intel.networkType,
            city = intel.city,
            region = intel.region,
            operatorName = intel.operatorName,
            operatorPopularity = intel.operatorPopularity,
            operatorAnonymity = intel.operatorAnonymity,
            operatorServices = intel.operatorServices,
            anonymousDetected = intel.anonymousDetected,
            hostingDetected = intel.hostingDetected,
            torDetected = intel.torDetected,
            scraperDetected = intel.scraperDetected,
            compromisedDetected = intel.compromisedDetected,
            detectabilityScore = intel.detectabilityScore,
            detectionSignals = intel.detectionSignals
        )
    }

    internal data class ProxyReputation(
        val riskScore: Int,
        val sourceVersion: String = "v3",
        val proxyDetected: Boolean,
        val vpnDetected: Boolean,
        val classificationType: String?,
        val provider: String?,
        val country: String?,
        val asn: String?,
        val estimatedDevicesAtAddress: Int? = null,
        val estimatedDevicesInSubnet: Int? = null,
        val confidenceScore: Int? = null,
        val attackHistoryCount: Int? = null,
        val firstSeen: String? = null,
        val lastSeen: String? = null,
        val lastUpdated: String? = null,
        val networkType: String? = null,
        val city: String? = null,
        val region: String? = null,
        val operatorName: String? = null,
        val operatorPopularity: String? = null,
        val operatorAnonymity: String? = null,
        val operatorServices: List<String>? = null,
        val anonymousDetected: Boolean? = null,
        val hostingDetected: Boolean? = null,
        val torDetected: Boolean? = null,
        val scraperDetected: Boolean? = null,
        val compromisedDetected: Boolean? = null,
        val detectabilityScore: Int? = null,
        val detectionSignals: List<String>? = null
    )

    /**
     * Parses the documented legacy v2 response. Kept separate from networking so
     * response-field mapping and missing/invalid scores can be unit tested.
     */
    internal fun parseProxyCheckV2Response(ip: String, jsonText: String): ProxyReputation {
        val root = JSONObject(jsonText)
        val status = root.optString("status")
        if (status != "ok" && status != "warning") {
            throw IllegalStateException(
                "مصدر السمعة لم يقبل الطلب: ${root.optString("message", status)}"
            )
        }

        val data = root.optJSONObject(ip)
            ?: throw IllegalStateException("لم يرجع مصدر السمعة نتيجة لعنوان الخروج.")

        val risk = data.opt("risk")?.toString()?.toIntOrNull()
            ?: throw IllegalStateException(
                "مصدر السمعة لم يقدم درجة خطر رقمية؛ لن نخترع نسبة."
            )
        if (risk !in 0..100) {
            throw IllegalStateException("درجة الخطر الواردة خارج النطاق المتوقع.")
        }

        val proxy = when (val raw = data.opt("proxy")) {
            is Boolean -> raw
            null, JSONObject.NULL -> false
            else -> raw.toString().equals("yes", ignoreCase = true)
        }
        fun optionalText(field: String): String? =
            data.optString(field, "").takeUnless { it.isBlank() || it == "null" }

        val classificationType = optionalText("type")
        return ProxyReputation(
            riskScore = risk,
            sourceVersion = "v2",
            proxyDetected = proxy,
            vpnDetected = classificationType?.contains("vpn", ignoreCase = true) == true,
            classificationType = classificationType,
            provider = optionalText("provider"),
            country = optionalText("isocode"),
            asn = optionalText("asn")
        )
    }


    /**
     * Stable ProxyCheck v3 parser. Device counts are estimates of devices behind
     * an IP and subnet, not verified subscriber counts or live session totals.
     */
    internal fun parseProxyCheckV3Response(ip: String, jsonText: String): ProxyReputation {
        val root = JSONObject(jsonText)
        val status = root.optString("status")
        if (status != "ok" && status != "warning") {
            throw IllegalStateException(
                "مصدر السمعة لم يقبل الطلب: ${root.optString("message", status)}"
            )
        }

        val data = root.optJSONObject(ip)
            ?: throw IllegalStateException("لم يرجع مصدر السمعة نتيجة لعنوان الخروج.")
        val detections = data.optJSONObject("detections")
            ?: throw IllegalStateException("استجابة v3 لا تحتوي على بيانات التصنيف.")
        val risk = optionalNonNegativeInt(detections, "risk")
            ?: throw IllegalStateException("مصدر السمعة لم يقدم درجة خطر رقمية؛ لن نخترع 0%.")
        if (risk !in 0..100) {
            throw IllegalStateException("درجة الخطر الواردة خارج النطاق المتوقع.")
        }

        val network = data.optJSONObject("network")
        val location = data.optJSONObject("location")
        val estimate = data.optJSONObject("device_estimate")
        val attackHistory = data.optJSONObject("attack_history")
        val operator = data.optJSONObject("operator")
        fun optionalBoolean(parent: JSONObject?, field: String): Boolean? {
            if (parent == null || !parent.has(field) || parent.isNull(field)) return null
            return parent.optBoolean(field)
        }

        val proxy = optionalBoolean(detections, "proxy") == true
        val vpn = optionalBoolean(detections, "vpn") == true
        val tor = optionalBoolean(detections, "tor")
        val hosting = optionalBoolean(detections, "hosting")
        val scraper = optionalBoolean(detections, "scraper")
        val compromised = optionalBoolean(detections, "compromised")
        val anonymous = optionalBoolean(detections, "anonymous")

        fun optionalText(parent: JSONObject?, field: String): String? {
            if (parent == null || !parent.has(field) || parent.isNull(field)) return null
            return parent.optString(field, "").takeUnless { it.isBlank() || it == "null" }
        }

        val attackCount = attackHistory?.let { history ->
            var total = 0L
            val keys = history.keys()
            while (keys.hasNext()) {
                optionalNonNegativeInt(history, keys.next())?.let { total += it.toLong() }
            }
            total.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        }
        val confidence = optionalNonNegativeInt(detections, "confidence")?.takeIf { it in 0..100 }
        val networkType = optionalText(network, "type")
        val detectionSignals = buildList {
            if (anonymous == true) add("Anonymous / عنوان مصنّف كمجهول")
            if (proxy) add("Proxy")
            if (vpn) add("VPN")
            if (tor == true) add("TOR")
            if (hosting == true || networkType.equals("Hosting", ignoreCase = true)) add("Hosting / مركز بيانات")
            if (scraper == true) add("Scraper")
            if (compromised == true) add("Compromised")
        }.distinct()
        val hasDetectionFields = listOf("anonymous", "proxy", "vpn", "tor", "hosting", "scraper", "compromised")
            .any { detections.has(it) && !detections.isNull(it) }
        val hostingNetwork = networkType.equals("Hosting", ignoreCase = true)
        val hasPositiveDetection = anonymous == true || proxy || vpn || tor == true ||
            hosting == true || hostingNetwork || scraper == true || compromised == true
        // This is the provider's confidence in its positive classification, not a
        // calibrated probability that any particular website will detect the IP.
        val detectabilityScore = when {
            hasPositiveDetection -> confidence
            hasDetectionFields -> 0
            else -> null
        }
        val operatorServices = operator?.optJSONArray("services")?.let { services ->
            (0 until services.length()).mapNotNull { index ->
                services.optString(index).takeIf { it.isNotBlank() && it != "null" }
            }.takeIf { it.isNotEmpty() }
        }
        val classification = when {
            proxy -> "Proxy"
            vpn -> "VPN"
            tor == true -> "TOR"
            hosting == true || hostingNetwork -> "Hosting"
            scraper == true -> "Scraper"
            compromised == true -> "Compromised"
            anonymous == true -> "Anonymous"
            else -> null
        }

        return ProxyReputation(
            riskScore = risk,
            proxyDetected = proxy,
            vpnDetected = vpn,
            classificationType = classification,
            provider = optionalText(network, "provider"),
            country = optionalText(location, "country")
                ?: optionalText(location, "country_name")
                ?: optionalText(location, "country_code"),
            asn = optionalText(network, "asn"),
            estimatedDevicesAtAddress = optionalNonNegativeInt(estimate, "address"),
            estimatedDevicesInSubnet = optionalNonNegativeInt(estimate, "subnet"),
            confidenceScore = confidence,
            attackHistoryCount = attackCount,
            firstSeen = optionalText(detections, "first_seen"),
            lastSeen = optionalText(detections, "last_seen"),
            lastUpdated = optionalText(data, "last_updated"),
            networkType = networkType,
            city = optionalText(location, "city"),
            region = optionalText(location, "region"),
            operatorName = optionalText(operator, "name"),
            operatorPopularity = optionalText(operator, "popularity"),
            operatorAnonymity = optionalText(operator, "anonymity"),
            operatorServices = operatorServices,
            anonymousDetected = anonymous,
            hostingDetected = hosting,
            torDetected = tor,
            scraperDetected = scraper,
            compromisedDetected = compromised,
            detectabilityScore = detectabilityScore,
            detectionSignals = detectionSignals
        )
    }

    private fun optionalNonNegativeInt(parent: JSONObject?, field: String): Int? {
        if (parent == null || !parent.has(field) || parent.isNull(field)) return null
        val raw = parent.opt(field)
        val value = when (raw) {
            is Number -> raw.toString().toDoubleOrNull()
                ?.takeIf { it.isFinite() && it % 1.0 == 0.0 }?.toInt()
            else -> raw?.toString()?.toIntOrNull()
        }
        return value?.takeIf { it >= 0 }
    }

    private fun validate(endpoint: ProxyEndpoint) {
        require(endpoint.host.isNotBlank() && endpoint.host.length <= 253) { "أدخل اسم مضيف أو عنوان IP صحيحاً." }
        require(endpoint.host.none { it.isWhitespace() || it == '/' || it == '@' }) { "صيغة عنوان البروكسي غير صحيحة." }
        require(endpoint.port in 1..65535) { "رقم المنفذ يجب أن يكون بين 1 و65535." }
        require((endpoint.username == null) == (endpoint.password == null)) { "أدخل اسم المستخدم وكلمة المرور معاً أو اتركهما فارغين." }
        require((endpoint.username?.length ?: 0) <= 255 && (endpoint.password?.length ?: 0) <= 255) { "بيانات المصادقة أطول من المسموح." }
    }

    internal fun currentExitIp(context: Context, endpoint: ProxyEndpoint): String {
        validate(endpoint)
        return fetchExitIp(endpoint, selectUnderlyingNetwork(context))
    }

    /**
     * When another VPN app (for example Tun2TAP) is active, ordinary sockets from
     * this app may be routed back into that VPN and create a tunnel loop. Bind the
     * proxy test and reputation requests to the physical non-VPN network instead.
     */
    private fun selectUnderlyingNetwork(context: Context): Network? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val candidates = manager.allNetworks.mapNotNull { network ->
            val caps = manager.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) return@mapNotNull null
            network to caps
        }
        val active = manager.activeNetwork
        val activeCaps = active?.let { manager.getNetworkCapabilities(it) }
        if (activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true && candidates.isEmpty()) {
            throw IllegalStateException(
                "اكتشف ProxyGuard أن VPN نشط، لكن Android لم يوفّر شبكة فعلية مستقلة للاختبار. أوقف Tun2TAP مؤقتاً أو اسمح للتطبيق بالوصول إلى الشبكة الأساسية ثم أعد الفحص."
            )
        }
        if (active != null && activeCaps != null &&
            !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return active
        return candidates.firstOrNull { it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) }?.first
            ?: candidates.firstOrNull()?.first
    }

    private fun fetchExitIp(endpoint: ProxyEndpoint, network: Network?): String {
        val failures = mutableListOf<String>()
        var lastError: Exception? = null
        for (echoHost in IP_ECHO_HOSTS) {
            try {
                return fetchExitIpFromHost(endpoint, network, echoHost)
            } catch (error: Exception) {
                lastError = error
                failures += echoHost + ": " + safeMessage(error)
            }
        }
        throw IllegalStateException(
            "تعذر استخراج عنوان IP عبر جميع خدمات الاختبار. " + failures.joinToString(" | "),
            lastError
        )
    }

    private fun fetchExitIpFromHost(endpoint: ProxyEndpoint, network: Network?, echoHost: String): String {
        fun connect(): Socket {
            val socket = network?.socketFactory?.createSocket() ?: Socket()
            try {
                val address = if (network != null) {
                    val resolved = network.getAllByName(endpoint.host).firstOrNull()
                        ?: throw java.net.UnknownHostException("لم يُرجع DNS أي عنوان لخادم البروكسي.")
                    InetSocketAddress(resolved, endpoint.port)
                } else {
                    InetSocketAddress(endpoint.host, endpoint.port)
                }
                socket.connect(address, CONNECT_TIMEOUT_MS)
                socket.soTimeout = READ_TIMEOUT_MS
                return socket
            } catch (e: Exception) {
                try { socket.close() } catch (_: Exception) {}
                val detail = when (e) {
                    is java.net.UnknownHostException -> "تعذر حل اسم خادم البروكسي؛ تحقق من عنوان الخادم أو DNS."
                    is java.net.SocketTimeoutException -> "انتهت مهلة الوصول إلى خادم البروكسي؛ قد يكون الخادم أو المنفذ غير متاح."
                    is java.net.ConnectException -> "رفض خادم البروكسي الاتصال أو تعذر الوصول إلى المنفذ."
                    else -> "خطأ شبكة من النوع " + e.javaClass.simpleName + "."
                }
                throw IllegalStateException(
                    "فشل الوصول TCP إلى خادم البروكسي " + endpoint.host + ":" + endpoint.port +
                        ". " + detail + " التفاصيل: " + safeMessage(e),
                    e
                )
            }
        }

        var raw = connect()
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
                ProxyProtocol.HTTP, ProxyProtocol.HTTPS -> establishHttpTunnel(proxyTransport, endpoint, echoHost)
                ProxyProtocol.SOCKS5 -> establishSocksTunnel(proxyTransport, endpoint, echoHost)
                ProxyProtocol.SOCKS_AUTO -> {
                    try {
                        establishSocksTunnel(proxyTransport, endpoint, echoHost)
                    } catch (socks5Error: Exception) {
                        try { proxyTransport.close() } catch (_: Exception) {}
                        try { raw.close() } catch (_: Exception) {}
                        if (!endpoint.username.isNullOrEmpty() || !endpoint.password.isNullOrEmpty()) {
                            throw IllegalStateException(
                                "فشل تفاوض SOCKS5. لا يمكن تجربة SOCKS4a عند وجود كلمة مرور؛ تحقق من دعم SOCKS5 والمصادقة.",
                                socks5Error
                            )
                        }
                        raw = connect()
                        proxyTransport = raw
                        try {
                            establishSocks4aTunnel(proxyTransport, endpoint, echoHost)
                        } catch (socks4Error: Exception) {
                            throw IllegalStateException(
                                "تعذر التفاوض مع SOCKS5 أو SOCKS4a. SOCKS5: " +
                                    safeMessage(socks5Error) + "؛ SOCKS4a: " + safeMessage(socks4Error),
                                socks4Error
                            )
                        }
                    }
                }
            }

            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(proxyTransport, echoHost, IP_ECHO_PORT, true) as SSLSocket
            tls.soTimeout = READ_TIMEOUT_MS
            tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            tls.startHandshake()
            tls.getOutputStream().write(
                ("GET / HTTP/1.1\r\nHost: " + echoHost +
                    "\r\nAccept: text/plain\r\nConnection: close\r\nUser-Agent: ProxyGuard-Android\r\n\r\n")
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

    /** SOCKS4a is attempted only when no password credentials were supplied. */
    private fun establishSocks4aTunnel(socket: Socket, endpoint: ProxyEndpoint, echoHost: String) {
        val out = socket.getOutputStream()
        val input = socket.getInputStream()
        val userId = endpoint.username.orEmpty().toByteArray(StandardCharsets.UTF_8)
        require(userId.size <= 255) { "اسم مستخدم SOCKS4a أطول من المسموح." }
        val host = echoHost.toByteArray(StandardCharsets.US_ASCII)
        val request = ByteArrayOutputStream()
        request.write(byteArrayOf(0x04, 0x01, (IP_ECHO_PORT shr 8).toByte(), IP_ECHO_PORT.toByte(), 0, 0, 0, 1))
        request.write(userId)
        request.write(0)
        request.write(host)
        request.write(0)
        out.write(request.toByteArray())
        out.flush()
        val reply = ByteArray(8)
        readFully(input, reply)
        if ((reply[0].toInt() and 0xff) != 0 || (reply[1].toInt() and 0xff) != 90) {
            throw IllegalStateException("رفض خادم SOCKS4a الاتصال (رمز ${reply[1].toInt() and 0xff}).")
        }
    }

    private fun establishHttpTunnel(socket: Socket, endpoint: ProxyEndpoint, echoHost: String) {
        val auth = if (!endpoint.username.isNullOrEmpty()) {
            val token = android.util.Base64.encodeToString(
                "${endpoint.username}:${endpoint.password.orEmpty()}".toByteArray(StandardCharsets.UTF_8),
                android.util.Base64.NO_WRAP
            )
            "Proxy-Authorization: Basic $token\r\n"
        } else ""
        val request = "CONNECT " + echoHost + ":" + IP_ECHO_PORT + " HTTP/1.1\r\nHost: " + echoHost + ":" + IP_ECHO_PORT + "\r\n" + auth + authConnection + ": keep-alive\r\n\r\n"
            .replace("$authConnection", "Proxy-Connection")
        socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
        val header = readHeaders(socket.getInputStream())
        val status = header.lineSequence().firstOrNull().orEmpty()
        if (!status.contains(" 200 ")) {
            throw IllegalStateException("رفض البروكسي إنشاء نفق HTTPS (استجابة: ${status.take(80)}).")
        }
    }

    private const val authConnection = "Proxy-Connection"

    private fun establishSocksTunnel(socket: Socket, endpoint: ProxyEndpoint, echoHost: String) {
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
        }

        val host = echoHost.toByteArray(StandardCharsets.US_ASCII)
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

    private fun lookupReputation(ip: String, network: Network?): ProxyReputation {
        val v3Failure = try {
            return lookupReputationV3(ip, network)
        } catch (e: Exception) {
            e
        }
        return try {
            lookupReputationV2(ip, network)
        } catch (v2Failure: Exception) {
            throw IllegalStateException(
                "تعذر تقييم السمعة عبر v3: ${safeMessage(v3Failure)}. كما تعذر المسار الاحتياطي v2: ${safeMessage(v2Failure)}",
                v2Failure
            )
        }
    }

    private fun lookupReputationV3(ip: String, network: Network?): ProxyReputation {
        val url = URL("https://proxycheck.io/v3/$ip?days=7&tag=0")
        val connection = ((network?.openConnection(url) ?: url.openConnection(Proxy.NO_PROXY)) as HttpURLConnection).apply {
            connectTimeout = 7_000
            readTimeout = 7_000
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "ProxyGuard-Android")
            setRequestProperty("Cache-Control", "no-store")
        }
        try {
            val code = connection.responseCode
            val stream = if (code in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
                    ?: throw IllegalStateException("مصدر السمعة غير متاح حالياً (HTTP $code).")
            }
            val jsonText = stream.use { readLimited(it, MAX_RESPONSE_BYTES) }
            if (code !in 200..299) {
                val providerMessage = runCatching {
                    JSONObject(jsonText).optString("message").takeIf { it.isNotBlank() && it != "null" }
                }.getOrNull()
                val detail = (providerMessage ?: jsonText.trim())
                    .replace(Regex("\\s+"), " ")
                    .take(220)
                val suffix = if (detail.isBlank()) "" else ": $detail"
                throw IllegalStateException("مصدر السمعة غير متاح حالياً (HTTP $code)$suffix")
            }
            return parseProxyCheckV3Response(ip, jsonText)
        } finally {
            connection.disconnect()
        }
    }

    private fun lookupReputationV2(ip: String, network: Network?): ProxyReputation {
        val url = URL("https://proxycheck.io/v2/$ip?risk=1&vpn=1&asn=1&days=7&tag=0")
        val connection = ((network?.openConnection(url) ?: url.openConnection(Proxy.NO_PROXY)) as HttpURLConnection).apply {
            connectTimeout = 7_000
            readTimeout = 7_000
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "ProxyGuard-Android")
            setRequestProperty("Cache-Control", "no-store")
        }
        try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
                ?: throw IllegalStateException("مصدر السمعة v2 غير متاح حالياً (HTTP $code).")
            val jsonText = stream.use { readLimited(it, MAX_RESPONSE_BYTES) }
            if (code !in 200..299) {
                val message = runCatching { JSONObject(jsonText).optString("message") }.getOrNull()
                    ?.takeIf { it.isNotBlank() && it != "null" } ?: jsonText.trim()
                throw IllegalStateException("مصدر السمعة v2 أعاد HTTP $code: ${message.take(180)}")
            }
            return parseProxyCheckV2Response(ip, jsonText)
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
