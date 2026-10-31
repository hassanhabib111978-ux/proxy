package com.proxyguard.android

import android.app.Activity
import android.content.Intent
import android.content.ClipboardManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.Proxy
import java.net.ProxySelector
import java.net.InetAddress
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.Executors

internal data class IpIntelEntry(val cidr: String, val category: String, val source: String)
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
    private lateinit var indicatorCard: LinearLayout
    private lateinit var indicatorTitle: TextView
    private lateinit var indicatorValue: TextView
    private lateinit var indicatorLevel: TextView
    private lateinit var detectabilityCard: LinearLayout
    private lateinit var detectabilityTitle: TextView
    private lateinit var detectabilityValue: TextView
    private lateinit var detectabilityLevel: TextView
    private lateinit var proxyNameInput: EditText
    private lateinit var proxyHostInput: EditText
    private lateinit var proxyPortInput: EditText
    private lateinit var proxyProtocolSpinner: Spinner
    private lateinit var proxyUsernameInput: EditText
    private lateinit var proxyPasswordInput: EditText
    private lateinit var proxyScanButton: Button
    private val scanExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val dbFile by lazy { File(filesDir, "proxyguard-ip-intel.csv") }
    private val entries = mutableListOf<IpIntelEntry>()
    private var databaseLoadError: String? = null
    @Volatile private var activityDestroyed = false

    companion object {
        private const val REQUEST_DATABASE = 41
        private const val MAX_DATABASE_BYTES = 5 * 1024 * 1024
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadDatabase()
        render()
    }

    override fun onDestroy() {
        activityDestroyed = true
        scanExecutor.shutdownNow()
        mainHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
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
            text = "فحص مسبق للبروكسي وسمعة IP وكثافة المشاركة"
            textSize = 16f
            setTextColor(0xFF526579.toInt())
        }
        // Optional label for the user's own reference; never sent to providers.
        proxyNameInput = EditText(this).apply {
            hint = "اسم البروكسي (اختياري للتعريف فقط)"
            textSize = 16f
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyHostInput = EditText(this).apply {
            hint = "ألصق عنوان IP أو اسم المضيف (يمكن IP:PORT)"
            textSize = 16f
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyPortInput = EditText(this).apply {
            hint = "المنفذ (مثل 8080 أو 1080) — اختياري إذا أضفته إلى IP:PORT"
            textSize = 14f
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyProtocolSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_item, arrayOf("HTTP", "HTTPS", "SOCKS5")).also {
                it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            }
        }
        proxyUsernameInput = EditText(this).apply {
            hint = "اسم المستخدم / Login (إذا طلبه البروكسي)"
            textSize = 16f
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyPasswordInput = EditText(this).apply {
            hint = "كلمة المرور (إذا طلبها البروكسي)"
            textSize = 16f
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            isSaveEnabled = false
        }
        val pasteProxyButton = Button(this).apply {
            text = "لصق"
            isAllCaps = false
            setOnClickListener {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager
                val pasted = try {
                    clipboard?.primaryClip?.takeIf { it.itemCount > 0 }
                        ?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString()?.trim()
                } catch (_: Exception) { null }
                if (pasted.isNullOrBlank()) {
                    Toast.makeText(this@MainActivity, "لا يوجد نص متاح للصق.", Toast.LENGTH_SHORT).show()
                } else {
                    proxyHostInput.setText(pasted)
                    Toast.makeText(this@MainActivity, "تم لصق العنوان في الحقل.", Toast.LENGTH_SHORT).show()
                }
            }
        }
        proxyScanButton = Button(this).apply {
            text = "افحص البروكسي الآن"
            textSize = 18f
            isAllCaps = false
            minHeight = dp(54)
            setOnClickListener { runProxyScan() }
        }
        val scan = Button(this).apply {
            text = "فحص إعدادات اتصال الجهاز"
            setOnClickListener { runLocalScan() }
        }
        val checkIp = Button(this).apply {
            text = "فحص عنوان مقابل قاعدة CSV المحلية"
            setOnClickListener { inspectIp(ipInput.text.toString().trim()) }
        }
        val import = Button(this).apply {
            text = "استيراد قاعدة بيانات CSV"
            setOnClickListener { openDatabasePicker() }
        }
        ipInput = EditText(this).apply {
            hint = "عنوان IP رقمي لفحص قاعدة CSV فقط"
            textSize = 15f
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
        }
        val formCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(14))
            background = indicatorBackground(Color.WHITE)
        }
        fun fieldLabel(value: String) = TextView(this).apply {
            text = value
            textSize = 13f
            setTextColor(0xFF526579.toInt())
            setPadding(0, dp(5), 0, dp(4))
        }
        val addressRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            addView(proxyHostInput, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(pasteProxyButton, LinearLayout.LayoutParams(dp(76), dp(50)).apply {
                marginStart = dp(8)
            })
        }
        listOf(
            fieldLabel("اسم البروكسي / ملاحظة"),
            proxyNameInput,
            fieldLabel("عنوان البروكسي — IP أو اسم المضيف"),
            addressRow,
            fieldLabel("المنفذ"),
            proxyPortInput,
            fieldLabel("نوع البروكسي"),
            proxyProtocolSpinner,
            fieldLabel("اسم المستخدم (اختياري)"),
            proxyUsernameInput,
            fieldLabel("كلمة المرور (اختيارية)"),
            proxyPasswordInput,
            proxyScanButton
        ).forEach { view ->
            formCard.addView(view, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(7) })
        }
        val diagnosticsTitle = TextView(this).apply {
            text = "أدوات إضافية"
            textSize = 18f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF10243A.toInt())
        }
        indicatorCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = indicatorBackground(0xFFF1F5F9.toInt())
        }
        indicatorTitle = TextView(this).apply {
            text = "نتيجة الفحص"
            textSize = 14f
            setTextColor(0xFF1E293B.toInt())
        }
        indicatorValue = TextView(this).apply {
            text = "بانتظار الفحص"
            textSize = 28f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF64748B.toInt())
        }
        indicatorLevel = TextView(this).apply {
            text = "ستظهر هنا درجة المخاطر ومستوى التصنيف بعد فحص البروكسي."
            textSize = 14f
            setTextColor(0xFF475569.toInt())
        }
        indicatorCard.addView(indicatorTitle)
        indicatorCard.addView(indicatorValue, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(6) })
        indicatorCard.addView(indicatorLevel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(2) })

        detectabilityCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = indicatorBackground(0xFFF1F5F9.toInt())
        }
        detectabilityTitle = TextView(this).apply {
            text = "مؤشر ظهور عنوان IP في قواعد تصنيف البروكسي/VPN"
            textSize = 14f
            setTextColor(0xFF1E293B.toInt())
        }
        detectabilityValue = TextView(this).apply {
            text = "بانتظار الفحص"
            textSize = 26f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF64748B.toInt())
        }
        detectabilityLevel = TextView(this).apply {
            text = "سيظهر هنا ما إذا كان عنوان الخروج مصنّفاً في قاعدة بيانات المصدر."
            textSize = 13f
            setTextColor(0xFF475569.toInt())
        }
        detectabilityCard.addView(detectabilityTitle)
        detectabilityCard.addView(detectabilityValue, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(6) })
        detectabilityCard.addView(detectabilityLevel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(2) })
        output = TextView(this).apply {
            textSize = 15f
            setTextColor(0xFF1D3045.toInt())
            setPadding(0, 24, 0, 24)
        }
        val privacy = TextView(this).apply {
            text = "الخصوصية: يتصل التطبيق بالبروكسي لاستخراج عنوان الخروج، ثم يرسل عنوان الخروج فقط إلى ProxyCheck.io v3 لفحص السمعة وتقدير كثافة الأجهزة وسجل النشاط. لا تُرسل بيانات الاعتماد إلى مزوّد السمعة ولا تُحفظ في التطبيق. تقدير الأجهزة ليس عدد المشتركين أو الجلسات النشطة، وقد يعالج المزوّد عنوان IP وفق سياسته. تنبيه أمني: HTTP وSOCKS5 العاديان لا يشفّران بيانات الاعتماد أثناء النقل؛ استخدم HTTPS Proxy أو قناة موثوقة، ولا تدخل كلمة مرور حساسة عبر بروكسي غير مشفر. عرض DNS ليس اختبار تسريب DNS."
            textSize = 13f
            setTextColor(0xFF526579.toInt())
        }
        listOf(title, subtitle, formCard, indicatorCard, detectabilityCard, output, diagnosticsTitle, ipInput, checkIp, scan, import, privacy).forEach {
            content.addView(it, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                bottomMargin = 18
            })
        }
        output.text = "ألصق عنوان البروكسي، وأدخل المنفذ ونوع الاتصال وبيانات الدخول عند الحاجة، ثم اضغط «افحص البروكسي الآن».\n\nسيظهر هنا بلد عنوان الخروج، ونوع الشبكة، وتقدير الأجهزة المشاركة، ومعلومات السمعة."
        scroll.addView(content)
        root.addView(scroll)
        setContentView(root)
    }

    private fun runProxyScan() {
        val rawAddress = proxyHostInput.text.toString().trim()
        var host = rawAddress
        var port = proxyPortInput.text.toString().trim().toIntOrNull()
        // Prefer an embedded port in a pasted host:port or [IPv6]:port value.
        // Otherwise use the separate port field below the address.
        if (rawAddress.startsWith("[") && rawAddress.contains("]:")) {
            val close = rawAddress.indexOf("]:")
            val embeddedPort = rawAddress.substring(close + 2).toIntOrNull()
            if (embeddedPort != null) {
                host = rawAddress.substring(1, close)
                port = embeddedPort
            }
        } else if (rawAddress.count { it == ':' } == 1) {
            val embeddedPort = rawAddress.substringAfterLast(':').toIntOrNull()
            if (embeddedPort != null) {
                host = rawAddress.substringBeforeLast(':')
                port = embeddedPort
            }
        }
        val proxyLabel = proxyNameInput.text.toString().trim()
        val protocol = when (proxyProtocolSpinner.selectedItem?.toString()) {
            "HTTPS" -> ProxyProtocol.HTTPS
            "SOCKS5" -> ProxyProtocol.SOCKS5
            else -> ProxyProtocol.HTTP
        }
        if (host.isBlank() || port == null || port !in 1..65535) {
            updateIndicator("بيانات البروكسي", "بيانات غير مكتملة", "ألصق عنوان IP أو اسم المضيف، ثم أدخل المنفذ في حقله أو ألصقه بصيغة IP:PORT.")
            return
        }
        val username = proxyUsernameInput.text.toString().takeIf { it.isNotBlank() }
        val password = proxyPasswordInput.text.toString().takeIf { it.isNotBlank() }
        if ((username == null) != (password == null)) {
            updateIndicator("بيانات المصادقة", "بيانات غير مكتملة", "أدخل اسم المستخدم وكلمة المرور معاً أو اتركهما فارغين.")
            return
        }
        val endpoint = ProxyEndpoint(host, port, protocol, username, password)
        proxyScanButton.isEnabled = false
        updateIndicator("فحص البروكسي", "جارٍ الفحص…", "اختبار الاتصال واستخراج عنوان الخروج ثم التحقق من سمعة IP.")
        output.text = "يُجرى الآن اختبار البروكسي. لن تتغير إعدادات اتصال الهاتف."
        scanExecutor.execute {
            try {
                val result = ProxyEndpointScanner.scan(endpoint)
                mainHandler.post {
                    if (activityDestroyed) return@post
                    proxyScanButton.isEnabled = true
                    proxyUsernameInput.text.clear()
                    proxyPasswordInput.text.clear()
                    val level = ProxyRiskPresentation.level(result.riskScore)
                    val color = riskColor(result.riskScore)
                    indicatorTitle.text = "درجة مخاطر IP لدى ProxyCheck.io v3"
                    indicatorValue.text = "${result.riskScore}%"
                    indicatorValue.setTextColor(color)
                    indicatorLevel.text = "$level • ${result.classificationType?.let { "صنّف المصدر العنوان كـ $it" } ?: "لم يصنّف المصدر العنوان كبروكسي أو VPN"}"
                    indicatorLevel.setTextColor(0xFF334155.toInt())
                    indicatorCard.background = indicatorBackground(blendColor(Color.WHITE, color, 0.16f))

                    val detectionScore = result.detectabilityScore
                    val detectedLabels = result.detectionSignals.orEmpty()
                    val detectionColor = detectionScore?.let { riskColor(it) }
                    detectabilityTitle.text = "ثقة مصدر البيانات في تصنيف عنوان IP"
                    when {
                        detectionScore != null -> {
                            detectabilityValue.text = "$detectionScore/100"
                            detectabilityValue.setTextColor(detectionColor ?: 0xFF64748B.toInt())
                            detectabilityCard.background = indicatorBackground(
                                blendColor(Color.WHITE, detectionColor ?: Color.LTGRAY, 0.16f)
                            )
                            detectabilityLevel.text = if (detectionScore == 0 && detectedLabels.isEmpty()) {
                                "لم يرصد ProxyCheck تصنيفاً إيجابياً لهذا العنوان وقت الفحص. هذا لا يعني أن المواقع الأخرى لن تتعرف عليه."
                            } else {
                                "ثقة مصدر البيانات في صحة التصنيف: $detectionScore/100 • ${detectedLabels.joinToString("، ")}. هذه ثقة قاعدة البيانات بتصنيفها وليست احتمالاً عاماً لاكتشافه لدى كل موقع."
                            }
                        }
                        detectedLabels.isNotEmpty() -> {
                            detectabilityValue.text = "رُصد تصنيف"
                            detectabilityValue.setTextColor(0xFFB45309.toInt())
                            detectabilityCard.background = indicatorBackground(0xFFFEF3C7.toInt())
                            detectabilityLevel.text = "${detectedLabels.joinToString("، ")}؛ لكن المصدر لم يقدّم درجة ثقة رقمية لهذا التصنيف."
                        }
                        else -> {
                            detectabilityValue.text = "غير متاح"
                            detectabilityValue.setTextColor(0xFF64748B.toInt())
                            detectabilityCard.background = indicatorBackground(0xFFF1F5F9.toInt())
                            detectabilityLevel.text = "لم تتوفر بيانات كافية لقياس ثقة التصنيف. لا تُفسّر هذه الحالة على أنها 0% أو ضمان لعدم الاكتشاف."
                        }
                    }
                    detectabilityLevel.setTextColor(0xFF334155.toInt())
                    output.text = buildString {
                        appendLine("تقرير فحص البروكسي")
                        if (proxyLabel.isNotBlank()) appendLine("اسم البروكسي: $proxyLabel")
                        appendLine("درجة مخاطر IP لدى ProxyCheck.io: ${result.riskScore}/100")
                        appendLine("ثقة المصدر في تصنيف عنوان IP: ${result.detectabilityScore?.let { "$it/100" } ?: "غير متاح"}")
                        appendLine("إشارات التصنيف المرصودة: ${result.detectionSignals.orEmpty().ifEmpty { listOf("لا توجد إشارات إيجابية لدى هذا المصدر وقت الفحص") }.joinToString("، ")}")
                        appendLine("تنبيه: مؤشر التصنيف وثقة المصدر لا يمثلان احتمال اكتشاف البروكسي لدى كل موقع؛ فالمواقع قد تستخدم إشارات أخرى.")
                        appendLine("عنوان IP الخارج: ${result.exitIp}")
                        appendLine("Proxy مصنّف من المصدر: ${if (result.proxyDetected) "نعم" else "لا"}")
                        appendLine("VPN مصنّف من المصدر: ${if (result.vpnDetected) "نعم" else "لا"}")
                        result.classificationType?.let { appendLine("تصنيف العنوان لدى المصدر: $it") }
                        result.provider?.let { appendLine("المزوّد: $it") }
                        result.country?.let { appendLine("بلد عنوان الخروج: $it") }
                        result.region?.let { appendLine("المنطقة: $it") }
                        result.city?.let { appendLine("المدينة: $it") }
                        result.asn?.let { appendLine("رقم النظام المستقل ASN: $it") }
                        result.networkType?.let { appendLine("نوع الشبكة المسجل: $it") }
                        result.operatorName?.let { appendLine("اسم مشغّل البروكسي/VPN المعروف: $it") }
                        result.operatorPopularity?.let { appendLine("انتشار المشغّل بحسب المصدر: $it") }
                        result.operatorAnonymity?.let { appendLine("مستوى إخفاء الهوية بحسب المصدر: $it") }
                        result.operatorServices?.let { appendLine("الخدمات المعروفة للمشغّل: ${it.joinToString("، ")}") }
                        appendLine()
                        appendLine("مؤشر كثافة المشاركة (تقدير المصدر):")
                        appendLine("تقدير الأجهزة خلف عنوان IP نفسه: ${result.estimatedDevicesAtAddress?.let { "نحو $it جهازاً" } ?: "غير متاح من المصدر"}")
                        appendLine("تقدير الأجهزة خلف الشبكة الفرعية: ${result.estimatedDevicesInSubnet?.let { "نحو $it جهازاً" } ?: "غير متاح من المصدر"}")
                        appendLine("هذا ليس عدداً مؤكداً للمشتركين أو للجلسات المتصلة الآن. معرفة الجلسات الدقيقة تتطلب سجلات مزوّد البروكسي.")
                        appendLine()
                        result.confidenceScore?.let { appendLine("ثقة تصنيف المصدر: $it/100") }
                        result.attackHistoryCount?.let { appendLine("أحداث الهجوم التي أبلغ عنها المصدر ضمن نافذة الأيام السبعة المطلوبة: $it") }
                        appendLine("تنبيه: قد لا تتضمن النافذة بعض الإشارات القديمة أو غير المؤكدة وفق سياسة المصدر؛ هذا ليس سجلاً كاملاً مضموناً لكل النشاطات.")
                        result.firstSeen?.let { appendLine("أول رصد إيجابي: $it") }
                        result.lastSeen?.let { appendLine("آخر رصد إيجابي: $it") }
                        result.lastUpdated?.let { appendLine("آخر تحديث لبيانات المصدر: $it") }
                        appendLine("مصدر السمعة: ProxyCheck.io v3")
                        appendLine()
                        appendLine("الأدلة:")
                        result.evidence.forEach { appendLine("• $it") }
                        appendLine()
                        appendLine("تفسير درجة المخاطر: هذه درجة ProxyCheck.io v3 الخاصة بسمعة/مخاطر عنوان IP، وليست احتمالاً إحصائياً بأن موقعاً معيناً سيكتشف البروكسي أو يحظره.")
                        appendLine("ثقة التصنيف 0–100 تعني مدى ثقة هذا المصدر في تصنيف إيجابي محدد؛ وهي ليست نسبة احتمال الاكتشاف على جميع المواقع.")
                        appendLine("لا يحسب هذا الإصدار بعد درجة موحدة معايرة لجميع إشارات الشبكة والمتصفح والجلسة؛ لذلك لا ينبغي تفسير أي من الرقمين كاحتمال شامل للاكتشاف.")
                        appendLine("تقدير الأجهزة عامل مستقل. لا نرفع درجة الخطر آلياً بسبب كثرة الأجهزة وحدها؛ فقد تكون المشاركة طبيعية في شبكات الهاتف وCGNAT. يصبح المؤشر أكثر إثارة للقلق عند اقترانه بتصنيف Proxy/VPN أو سجل إساءة استخدام حديث.")
                        appendLine("قد يختلف قرار كل موقع؛ ولا يثبت عدم تصنيف العنوان كبروكسي أو VPN أنه غير قابل للاكتشاف.")
                        appendLine("تاريخ الفحص: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.ROOT).format(java.util.Date())}")
                    }
                }
            } catch (e: Exception) {
                mainHandler.post {
                    if (activityDestroyed) return@post
                    proxyScanButton.isEnabled = true
                    proxyUsernameInput.text.clear()
                    proxyPasswordInput.text.clear()
                    updateIndicator("تعذر إكمال الفحص", "لا توجد نسبة موثوقة", e.message ?: "حدث خطأ أثناء فحص البروكسي.")
                    output.text = e.message ?: "تعذر فحص البروكسي. تحقق من البيانات والاتصال ثم أعد المحاولة."
                }
            }
        }
    }

    private fun riskColor(score: Int): Int {
        val green = 0xFF16A34A.toInt()
        val yellow = 0xFFEAB308.toInt()
        val red = 0xFFEF4444.toInt()
        val deepRed = 0xFF991B1B.toInt()
        return when {
            score < 40 -> green
            score < 75 -> yellow
            score < 90 -> red
            else -> blendColor(red, deepRed, (score - 90) / 10f)
        }
    }

    private fun blendColor(start: Int, end: Int, fraction: Float): Int {
        val t = fraction.coerceIn(0f, 1f)
        val a = (Color.alpha(start) + (Color.alpha(end) - Color.alpha(start)) * t).toInt()
        val r = (Color.red(start) + (Color.red(end) - Color.red(start)) * t).toInt()
        val g = (Color.green(start) + (Color.green(end) - Color.green(start)) * t).toInt()
        val b = (Color.blue(start) + (Color.blue(end) - Color.blue(start)) * t).toInt()
        return Color.argb(a, r, g, b)
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
        val dns = network?.let { cm.getLinkProperties(it)?.dnsServers?.mapNotNull { address -> address.hostAddress } } ?: emptyList()
        val proxy = try {
            ProxySelector.getDefault()?.select(URI("https://example.invalid"))
                ?.firstOrNull { it.type() == Proxy.Type.HTTP || it.type() == Proxy.Type.SOCKS }
                ?.address()?.toString()
        } catch (_: Exception) { null }
        val report = LocalReport(vpn, transports, dns, proxy, entries.size)
        val deviceFinding = ProxyIndicatorScoring.deviceFinding(report.vpn, report.systemProxy != null)
        updateIndicator("نتيجة رصد الجهاز", deviceFinding.label, deviceFinding.detail)
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
            appendLine("نتيجة الرصد التقني:")
            appendLine(deviceFinding.label)
            appendLine(deviceFinding.detail)
            appendLine("هذه النتيجة تصف ما أتاحه Android للتطبيق في لحظة الفحص، ولا تمثل حكماً على سلامة الاتصال.")
            appendLine("سمعة IP أو احتمال إساءة الاستخدام: غير متاحين في الفحص المحلي.")
            appendLine()
            appendLine("سمعة عنوان IP: غير متاحة في الفحص المحلي. أدخل عنوان IP وافحصه مقابل قاعدة محلية لتقييم تصنيفه.")
            appendLine("ملاحظة: عدم ظهور إعداد بروكسي لا يثبت عدم وجود وسيط على مستوى تطبيق آخر أو الشبكة.")
        }
    }

    private fun inspectIp(raw: String) {
        val ip = parseIpLiteral(raw)
        if (ip == null) {
            updateIndicator("فحص عنوان IP", "عنوان غير صالح", "أدخل عنوان IPv4 أو IPv6 رقمياً دون اسم نطاق.")
            output.text = "عنوان IP غير صالح. أدخل عنوان IPv4 أو IPv6 رقمياً دون اسم نطاق."
            return
        }
        val matches = entries.filter { cidrContains(it.cidr, ip) }
        if (matches.isEmpty()) {
            updateIndicator("قاعدة IP المحلية", "لا يوجد تطابق", "العنوان غير موجود في السجلات المستوردة؛ لا يمكن استنتاج أنه آمن.")
            output.text = buildString {
                appendLine("فحص عنوان IP: $raw")
                appendLine("لم يُعثر على تطابق في قاعدة البيانات المحلية.")
                appendLine("هذه النتيجة تعني فقط أن العنوان غير موجود ضمن البيانات المستوردة.")
                appendLine("لا تثبت النتيجة أن العنوان آمن أو خالٍ من Proxy/VPN.")
                appendLine("لم يتحقق التطبيق من مصدر القاعدة أو تاريخ تحديثها أو ترخيصها.")
            }
            return
        }

        val classifications = matches.mapNotNull { entry ->
            ProxyIndicatorScoring.classifyCategory(entry.category)?.let { entry to it }
        }
        val distinctLabels = classifications.map { it.second.label }.distinct()
        val status = distinctLabels.takeIf { it.isNotEmpty() }?.joinToString("، ")
            ?: "مطابقة بتصنيف غير معروف"
        val explanation = classifications.map { it.second.detail }.distinct().joinToString(" ")
            .ifBlank { "تم العثور على سجل CIDR، لكن تصنيفه غير مدعوم أو غير واضح." }
        updateIndicator("تصنيف قاعدة IP المحلية", status, explanation)
        output.text = buildString {
            appendLine("فحص عنوان IP: $raw")
            appendLine("تطابقات قاعدة البيانات: ${matches.size}")
            appendLine()
            appendLine("التفسير:")
            if (classifications.isEmpty()) {
                appendLine("وجد تطابق CIDR، لكن فئة التصنيف غير معروفة للتطبيق.")
                appendLine("لا يجوز تحويل تصنيف مجهول إلى حكم أمني أو نسبة.")
            } else {
                classifications.map { it.second.label + ": " + it.second.detail }.distinct()
                    .forEach { appendLine("• $it") }
            }
            appendLine()
            appendLine("السجلات المطابقة:")
            matches.take(20).forEach { appendLine("• ${it.category} — ${it.source} (${it.cidr})") }
            appendLine()
            appendLine("تنبيه: أسماء المصدر والتصنيف مأخوذة من ملف CSV الذي استوردته.")
            appendLine("لم يتحقق التطبيق من هوية الناشر أو ترخيص البيانات أو تاريخ صلاحيتها أو دقتها.")
            appendLine("تصنيف VPN أو Proxy أو Tor لا يثبت أن العنوان ضار أو مسيء.")
            appendLine("والاستضافة/مركز البيانات وحدهما لا يثبتان أن العنوان Proxy.")
        }
    }

    private fun updateIndicator(title: String, value: String, detail: String) {
        indicatorTitle.text = title
        indicatorValue.text = value
        indicatorValue.setTextColor(0xFF1E40AF.toInt())
        indicatorLevel.text = detail
        indicatorLevel.setTextColor(0xFF475569.toInt())
        indicatorCard.background = indicatorBackground(0xFFEFF6FF.toInt())
        detectabilityTitle.text = "ثقة مصدر البيانات في تصنيف عنوان IP"
        detectabilityValue.text = "غير متاح"
        detectabilityValue.setTextColor(0xFF64748B.toInt())
        detectabilityLevel.text = "لا توجد نتيجة تصنيف صالحة من فحص البروكسي الحالي."
        detectabilityLevel.setTextColor(0xFF475569.toInt())
        detectabilityCard.background = indicatorBackground(0xFFF1F5F9.toInt())
    }

    private fun indicatorBackground(color: Int) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(14).toFloat()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

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

    private fun parseDatabaseCsv(rawText: String): List<IpIntelEntry> =
        IpIntelDatabase.parseCsv(rawText)

    private fun csvCell(value: String): String =
        if (value.any { it == ',' || it == '"' || it == '\r' || it == '\n' }) {
            "\"" + value.replace("\"", "\"\"") + "\""
        } else value

    private fun persistDatabase(parsed: List<IpIntelEntry>) {
        val temporary = File(filesDir, "proxyguard-ip-intel.csv.tmp")
        val csv = buildString {
            appendLine("cidr,category,source")
            parsed.forEach { entry ->
                append(csvCell(entry.cidr)).append(',')
                    .append(csvCell(entry.category)).append(',')
                    .append(csvCell(entry.source)).append('\n')
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

    private fun parseIpLiteral(value: String): InetAddress? =
        IpIntelDatabase.parseIpLiteral(value)

    private fun validCidr(value: String): Boolean =
        IpIntelDatabase.validCidr(value)

    private fun cidrContains(cidr: String, candidate: InetAddress): Boolean =
        IpIntelDatabase.cidrContains(cidr, candidate)
}
