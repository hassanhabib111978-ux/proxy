package com.proxyguard.android

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.URI

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
    private val dbFile by lazy { java.io.File(filesDir, "proxyguard-ip-intel.csv") }
    private val entries = mutableListOf<IntelEntry>()

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
            text = "الخصوصية: لا يتصل هذا الإصدار بخوادم خارجية ولا يرسل بيانات الفحص. فحص السمعة يعتمد فقط على قاعدة البيانات التي تستوردها."
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
            appendLine("خوادم DNS الحالية: ${report.dns.ifEmpty { listOf("غير متاحة") }.joinToString("، ")}")
            appendLine("بروكسي نظام ظاهر: ${report.systemProxy ?: "لم يُكتشف"}")
            appendLine("سجلات قاعدة البيانات المحلية: ${report.databaseCount}")
            appendLine()
            appendLine("ملاحظة: غياب إعداد بروكسي ظاهر لا يثبت عدم وجود نفق أو بروكسي على مستوى تطبيق آخر أو الشبكة.")
        }
    }

    private fun inspectIp(raw: String) {
        val ip = try { InetAddress.getByName(raw) } catch (_: Exception) { null }
        if (ip == null || ip.hostAddress != raw || raw.contains("%")) {
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
        startActivityForResult(intent, 41)
    }

    @Deprecated("Use Activity Result APIs in the next iteration")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 41 || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } ?: ""
            require(text.length <= 5_000_000) { "حجم الملف أكبر من 5MB" }
            val parsed = text.lineSequence().drop(1).mapNotNull { line ->
                val cols = line.split(",", limit = 3).map { it.trim() }
                if (cols.size < 2 || !validCidr(cols[0])) null
                else IntelEntry(cols[0], cols[1].take(80), cols.getOrElse(2) { "مستورد محلياً" }.take(120))
            }.take(100_000).toList()
            dbFile.writeText("cidr,category,source\n" + parsed.joinToString("\n") { "${it.cidr},${it.category},${it.source}" })
            entries.clear()
            entries.addAll(parsed)
            runLocalScan()
            output.append("\nتم استيراد ${parsed.size} سجلاً محلياً.")
        } catch (e: Exception) {
            output.text = "تعذر استيراد القاعدة: ${e.message ?: "ملف غير صالح"}"
        }
    }

    private fun loadDatabase() {
        if (!dbFile.exists()) return
        runCatching {
            dbFile.readLines().drop(1).forEach { line ->
                val cols = line.split(",", limit = 3)
                if (cols.size >= 2 && validCidr(cols[0])) entries.add(IntelEntry(cols[0], cols[1], cols.getOrElse(2) { "محلي" }))
            }
        }
    }

    private fun validCidr(value: String): Boolean {
        val parts = value.split("/")
        if (parts.size != 2) return false
        val address = runCatching { InetAddress.getByName(parts[0]) }.getOrNull() ?: return false
        val prefix = parts[1].toIntOrNull() ?: return false
        return prefix in 0..(if (address is Inet4Address) 32 else 128) &&
            parts[0].all { it.isDigit() || it in ".:" } &&
            !parts[0].contains("%")
    }

    private fun cidrContains(cidr: String, candidate: InetAddress): Boolean {
        val parts = cidr.split("/")
        val base = runCatching { InetAddress.getByName(parts[0]) }.getOrNull() ?: return false
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
