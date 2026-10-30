package com.proxyguard.android

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

private data class IntelEntry(val cidr: String, val category: String, val source: String)
private data class LocalReport(
    val vpn: Boolean,
    val transports: List<String>,
    val dns: List<String>,
    val systemProxy: String?,
    val databaseCount: Int
)

class MainActivity : Activity() {
    private lateinit var output: TextView
    private lateinit var ipInput: EditText
    private val dbFile by lazy { File(filesDir, "proxyguard-ip-intel.csv") }
    private val entries = mutableListOf<IntelEntry>()
    private var databaseLoadError: String? = null

    companion object {
        private const val REQUEST_DATABASE = 41
        private const val MAX_DATABASE_BYTES = 5 * 1024 * 1024
        private const val MAX_DATABASE_ENTRIES = 100_000
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadDatabase()
        render()
    }

    private fun render() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 42, 36, 32)
            setBackgroundColor(0xFFF4F7FB.toInt())
            // Android 15 enforces edge-to-edge for apps targeting API 35.
            // Keep the content clear of status/navigation bars on older and newer releases.
            setOnApplyWindowInsetsListener { view, insets ->
                view.setPadding(
                    36 + insets.systemWindowInsetLeft,
                    42 + insets.systemWindowInsetTop,
                    36 + insets.systemWindowInsetRight,
                    32 + insets.systemWindowInsetBottom
                )
                insets
            }
        }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val title = TextView(this).apply {
            text = "ProxyGuard"
            textSize = 30f
            setTextColor(0xFF10243A.toInt())
        }
        val subtitle = TextView(this).apply {
            text = "فحص محلي لمؤشرات مخاطر الاتصال"
            textSize = 16f
            setTextColor(0xFF526579.toInt())
        }
        ipInput = EditText(this).apply {
            hint = "أدخل عنوان IP للبروكسي (اختياري)"
            textSize = 16f
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
        }
        val scan = Button(this).apply {
            text = "افحص إعدادات هذا الجهاز"
            setOnClickListener { runLocalScan() }
        }
        val checkIp = Button(this).apply {
            text = "افحص IP مقابل قاعدة البيانات المحلية"
            setOnClickListener { inspectIp(ipInput.text.toString().trim()) }
        }
        val import = Button(this).apply {
            text = "استيراد قاعدة بيانات CSV"
            setOnClickListener { openDatabasePicker() }
        }
        output = TextView(this).apply {
            textSize = 15f
            setTextColor(0xFF1D3045.toInt())
            setPadding(0, 24, 0, 24)
        }
        val privacy = TextView(this).apply {
            text = "الخصوصية: لا يتصل هذا الإصدار بخوادم خارجية ولا يرسل بيانات الفحص. فحص السمعة يعتمد فقط على قاعدة البيانات التي تستوردها. عرض خوادم DNS ليس اختباراً لتسرّب DNS."
            textSize = 13f
            setTextColor(0xFF526579.toInt())
        }
        listOf(title, subtitle, ipInput, scan, checkIp, import, output, privacy).forEach {
            content.addView(it, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                bottomMargin = 18
            })
        }
        scroll.addView(content)
        root.addView(scroll)
        setContentView(root)
        runLocalScan()
    }

    private fun runLocalScan() {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = network?.let { cm.getNetworkCapabilities(it) }
        val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val transports = buildList {
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("Wi‑Fi")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("خلوي")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("Ethernet")
            if (vpn) add("VPN")
        }
        val dns = network?.let { cm.getLinkProperties(it)?.dnsServers?.map(InetAddress::getHostAddress) } ?: emptyList()
        val proxy = try {
            ProxySelector.getDefault()?.select(URI("https://example.invalid"))
                ?.firstOrNull { it.type() == Proxy.Type.HTTP || it.type() == Proxy.Type.SOCKS }
                ?.address()?.toString()
        } catch (_: Exception) { null }
        val report = LocalReport(vpn, transports, dns, proxy, entries.size)
        output.text = buildString {
            appendLine("نتيجة الفحص المحلي")
            appendLine("اتصال نشط: ${if (network == null) "غير متاح" else "نعم"}")
            appendLine("مسار VPN ظاهر للنظام: ${if (report.vpn) "نعم" else "لا"}")
            appendLine("أنواع الاتصال: ${report.transports.ifEmpty { listOf("غير محدد") }.joinToString("، ")}")
            appendLine("خوادم DNS المهيأة: ${report.dns.ifEmpty { listOf("غير متاحة") }.joinToString("، ")}")
            appendLine("بروكسي نظام ظاهر: ${report.systemProxy ?: "لم يُكتشف"}")
            appendLine("سجلات قاعدة البيانات المحلية: ${report.databaseCount}")
            databaseLoadError?.let { appendLine("تنبيه قاعدة البيانات: $it") }
            appendLine()
            appendLine("ملاحظة: غياب إعداد بروكسي ظاهر لا يثبت عدم وجود نفق أو بروكسي على مستوى تطبيق آخر أو الشبكة.")
        }
    }

    private fun inspectIp(raw: String) {
        val ip = parseIpLiteral(raw)
        if (ip == null) {
            output.text = "عنوان IP غير صالح. أدخل عنوان IPv4 أو IPv6 رقمياً دون اسم نطاق."
            return
        }
        val matches = entries.filter { cidrContains(it.cidr, ip) }
        output.text = if (matches.isEmpty()) {
            "لم يُعثر على تطابق في قاعدة البيانات المحلية. هذا لا يعني أن العنوان آمن أو غير مصنف؛ قد تكون القاعدة محدودة أو قديمة."
        } else buildString {
            appendLine("تطابقات محلية: ${matches.size}")
            matches.take(20).forEach { appendLine("• ${it.category} — ${it.source} (${it.cidr})") }
            appendLine()
            append("هذه مؤشرات من قاعدة مستوردة وليست حكماً قطعياً.")
        }
    }

    private fun openDatabasePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/*"
        }
        startActivityForResult(intent, REQUEST_DATABASE)
    }

    @Deprecated("Use Activity Result APIs in a later iteration")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_DATABASE || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val importedText = contentResolver.openInputStream(uri)?.use { readTextLimited(it) }
                ?: error("تعذر فتح الملف")
            val parsed = parseDatabaseCsv(importedText)
            persistDatabase(parsed)
            entries.clear()
            entries.addAll(parsed)
            databaseLoadError = null
            runLocalScan()
            output.append("\nتم استيراد ${parsed.size} سجلاً محلياً بنجاح.")
        } catch (e: Exception) {
            output.text = "تعذر استيراد القاعدة: ${e.message ?: "ملف غير صالح"}"
        }
    }

    private fun loadDatabase() {
        if (!dbFile.exists()) return
        try {
            require(dbFile.length() <= MAX_DATABASE_BYTES) { "حجم القاعدة المحلية يتجاوز الحد المسموح" }
            val text = dbFile.inputStream().use { readTextLimited(it) }
            entries.addAll(parseDatabaseCsv(text))
        } catch (_: Exception) {
            entries.clear()
            databaseLoadError = "تعذرت قراءة القاعدة المحلية؛ يمكنك استيراد ملف جديد."
        }
    }

    private fun readTextLimited(input: InputStream): String {
        val bytes = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            require(total <= MAX_DATABASE_BYTES) { "حجم الملف أكبر من 5MB" }
            bytes.write(buffer, 0, count)
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return decoder.decode(ByteBuffer.wrap(bytes.toByteArray())).toString()
    }

    // This deliberately supports a simple, unquoted CSV schema only:
    // cidr,category,source. Quoted or multiline CSV is rejected, never guessed.
    private fun parseDatabaseCsv(rawText: String): List<IntelEntry> {
        val text = rawText.removePrefix("\uFEFF")
        val lines = text.lineSequence().toList()
        require(lines.firstOrNull()?.trim()?.lowercase() == "cidr,category,source") {
            "صيغة الملف غير صحيحة؛ يجب أن يبدأ بالعناوين cidr,category,source"
        }
        val parsed = ArrayList<IntelEntry>()
        lines.drop(1).forEachIndexed { index, rawLine ->
            val lineNumber = index + 2
            if (rawLine.isBlank()) return@forEachIndexed
            require(!rawLine.contains('"')) { "علامات الاقتباس غير مدعومة في السطر $lineNumber" }
            val columns = rawLine.split(',', limit = 4).map { it.trim() }
            require(columns.size in 2..3) { "عدد الأعمدة غير صحيح في السطر $lineNumber" }
            require(validCidr(columns[0])) { "عنوان CIDR غير صالح في السطر $lineNumber" }
            val category = columns[1]
            val source = columns.getOrElse(2) { "مستورد محلياً" }
            require(isSafeLabel(category, 80)) { "التصنيف فارغ أو طويل أو يحتوي محارف تحكم في السطر $lineNumber" }
            require(isSafeLabel(source, 120)) { "المصدر طويل أو يحتوي محارف تحكم في السطر $lineNumber" }
            parsed.add(IntelEntry(columns[0], category, source))
            require(parsed.size <= MAX_DATABASE_ENTRIES) { "عدد السجلات يتجاوز الحد الأقصى البالغ 100000" }
        }
        require(parsed.isNotEmpty()) { "لا يحتوي الملف على سجلات صالحة" }
        return parsed
    }

    private fun isSafeLabel(value: String, maxLength: Int): Boolean =
        value.isNotBlank() && value.length <= maxLength && value.none { it.isISOControl() }

    private fun persistDatabase(parsed: List<IntelEntry>) {
        val temporary = File(filesDir, "proxyguard-ip-intel.csv.tmp")
        val csv = buildString {
            appendLine("cidr,category,source")
            parsed.forEach { entry ->
                append(entry.cidr).append(',')
                    .append(entry.category).append(',')
                    .append(entry.source).append('\n')
            }
        }
        try {
            temporary.writeText(csv, Charsets.UTF_8)
            try {
                Files.move(
                    temporary.toPath(),
                    dbFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), dbFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    // Parse numeric literals only. Never resolve user/imported hostnames via DNS.
    private fun parseIpLiteral(value: String): InetAddress? {
        if (value.isBlank() || value.contains("%")) return null
        if (value.contains(":")) {
            if (!value.matches(Regex("[0-9a-fA-F:.]+"))) return null
            return runCatching { InetAddress.getByName(value) }.getOrNull()
                ?.takeIf { it.address.size == 16 }
        }
        val octets = value.split(".")
        if (octets.size != 4 || octets.any { it.isEmpty() || it.any { ch -> ch !in '0'..'9' } }) return null
        val numbers = octets.map { it.toIntOrNull() ?: return null }
        if (numbers.any { it !in 0..255 }) return null
        if (octets.indices.any { octets[it].length > 1 && octets[it].startsWith("0") }) return null
        return runCatching { InetAddress.getByAddress(numbers.map { it.toByte() }.toByteArray()) }.getOrNull()
    }

    private fun validCidr(value: String): Boolean {
        val parts = value.split("/")
        if (parts.size != 2) return false
        val address = parseIpLiteral(parts[0]) ?: return false
        val prefix = parts[1].toIntOrNull() ?: return false
        return prefix in 0..(if (address is Inet4Address) 32 else 128)
    }

    private fun cidrContains(cidr: String, candidate: InetAddress): Boolean {
        val parts = cidr.split("/")
        val base = parseIpLiteral(parts[0]) ?: return false
        if (base.address.size != candidate.address.size) return false
        val prefix = parts[1].toIntOrNull() ?: return false
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8
        for (i in 0 until fullBytes) if (base.address[i] != candidate.address[i]) return false
        if (remainingBits > 0) {
            val mask = (0xFF shl (8 - remainingBits)) and 0xFF
            if ((base.address[fullBytes].toInt() and 0xFF and mask) !=
                (candidate.address[fullBytes].toInt() and 0xFF and mask)) return false
        }
        return true
    }
}
