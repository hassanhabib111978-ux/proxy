package com.proxyguard.android

import android.app.Activity
import android.app.AlertDialog
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
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
    private lateinit var watchIntervalSpinner: Spinner
    private lateinit var watchStatusText: TextView
    private lateinit var watchStartButton: Button
    private lateinit var watchStopButton: Button
    private lateinit var watchHistoryButton: Button
    private val scanExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val dbFile by lazy { File(filesDir, "proxyguard-ip-intel.csv") }
    private val entries = mutableListOf<IpIntelEntry>()
    private var databaseLoadError: String? = null
    @Volatile private var activityDestroyed = false

    companion object {
        private const val REQUEST_DATABASE = 41
        private const val REQUEST_POST_NOTIFICATIONS = 42
        private const val MAX_DATABASE_BYTES = 5 * 1024 * 1024
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadDatabase()
        render()
    }

    override fun onResume() {
        super.onResume()
        refreshIpWatchStatus()
        mainHandler.post(watchStatusRefresh)
    }

    override fun onPause() {
        mainHandler.removeCallbacks(watchStatusRefresh)
        super.onPause()
    }

    private val watchStatusRefresh = object : Runnable {
        override fun run() {
            if (!activityDestroyed) {
                refreshIpWatchStatus()
                mainHandler.postDelayed(this, 5_000L)
            }
        }
    }

    override fun onDestroy() {
        activityDestroyed = true
        scanExecutor.shutdownNow()
        mainHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun render() {
        val sidePadding = dp(14)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            setPadding(sidePadding, dp(8), sidePadding, dp(8))
            setBackgroundColor(0xFFF4F7FB.toInt())
            setOnApplyWindowInsetsListener { view, insets ->
                view.setPadding(
                    sidePadding + insets.systemWindowInsetLeft,
                    dp(8) + insets.systemWindowInsetTop,
                    sidePadding + insets.systemWindowInsetRight,
                    dp(8) + insets.systemWindowInsetBottom
                )
                insets
            }
        }
        val scroll = ScrollView(this).apply { isFillViewport = true }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            setPadding(0, 0, 0, dp(12))
        }
        val title = TextView(this).apply {
            text = "ProxyGuard"
            textSize = 25f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF10243A.toInt())
        }
        val subtitle = TextView(this).apply {
            text = "افحص البروكسي قبل استخدامه"
            textSize = 12f
            setTextColor(0xFF526579.toInt())
        }

        proxyNameInput = EditText(this).apply {
            hint = "اسم أو ملاحظة للبروكسي (اختياري)"
            textSize = 14f
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyHostInput = EditText(this).apply {
            hint = "عنوان IP أو اسم المضيف"
            textSize = 15f
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyPortInput = EditText(this).apply {
            hint = "منفذ المزوّد"
            textSize = 15f
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyProtocolSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                arrayOf("اختر النوع", "HTTP", "HTTPS", "SOCKS5", "SOCKS (اكتشاف تلقائي)")
            ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            setSelection(0)
        }
        proxyUsernameInput = EditText(this).apply {
            hint = "اسم المستخدم / Login"
            textSize = 14f
            setSingleLine(true)
            isSaveEnabled = false
        }
        proxyPasswordInput = EditText(this).apply {
            hint = "كلمة المرور"
            textSize = 14f
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            isSaveEnabled = false
        }
        val pasteProxyButton = Button(this).apply {
            text = "لصق"
            textSize = 13f
            isAllCaps = false
            minHeight = dp(46)
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
                    Toast.makeText(this@MainActivity, "تم لصق العنوان. راجع المنفذ والنوع.", Toast.LENGTH_SHORT).show()
                }
            }
        }
        proxyScanButton = Button(this).apply {
            text = "افحص البروكسي الآن"
            textSize = 17f
            isAllCaps = false
            minHeight = dp(52)
            setOnClickListener { runProxyScan() }
        }

        watchIntervalSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                arrayOf("كل دقيقة", "كل دقيقتين", "كل 5 دقائق")
            ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            setSelection(1)
        }
        watchStartButton = Button(this).apply {
            text = "ابدأ مراقبة تغيّر IP"
            isAllCaps = false
            setOnClickListener { startIpWatch() }
        }
        watchStopButton = Button(this).apply {
            text = "إيقاف المراقبة"
            isAllCaps = false
            setOnClickListener { stopIpWatch() }
        }
        watchStatusText = TextView(this).apply {
            text = "المراقبة متوقفة."
            textSize = 13f
            setTextColor(0xFF475569.toInt())
        }
        watchHistoryButton = Button(this).apply {
            text = "عرض سجل تغيّرات IP"
            isAllCaps = false
            setOnClickListener { showIpWatchHistory() }
        }
        val localScanButton = Button(this).apply {
            text = "فحص إعدادات اتصال الجهاز"
            isAllCaps = false
            setOnClickListener { runLocalScan() }
        }
        val checkIpButton = Button(this).apply {
            text = "فحص IP مقابل قاعدة CSV المحلية"
            isAllCaps = false
            setOnClickListener { inspectIp(ipInput.text.toString().trim()) }
        }
        val importDatabaseButton = Button(this).apply {
            text = "استيراد قاعدة بيانات CSV"
            isAllCaps = false
            setOnClickListener { openDatabasePicker() }
        }
        ipInput = EditText(this).apply {
            hint = "عنوان IP رقمي للفحص المحلي"
            textSize = 14f
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
        }

        fun fieldLabel(value: String) = TextView(this).apply {
            text = value
            textSize = 12f
            setTextColor(0xFF526579.toInt())
            setPadding(0, dp(3), 0, dp(2))
        }
        fun addGap(target: LinearLayout, height: Int = 5) {
            target.addView(android.view.View(this), LinearLayout.LayoutParams(1, dp(height)))
        }

        val formCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = indicatorBackground(Color.WHITE)
        }
        val addressRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            addView(proxyHostInput, LinearLayout.LayoutParams(0, dp(48), 1f))
            addView(pasteProxyButton, LinearLayout.LayoutParams(dp(68), dp(46)).apply {
                marginStart = dp(6)
            })
        }
        val portColumn = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        portColumn.addView(fieldLabel("المنفذ"))
        portColumn.addView(proxyPortInput)
        val protocolColumn = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        protocolColumn.addView(fieldLabel("نوع البروكسي كما حدده المزوّد"))
        protocolColumn.addView(proxyProtocolSpinner)
        val connectionRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            addView(portColumn, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.42f))
            addView(protocolColumn, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.58f).apply {
                marginStart = dp(8)
            })
        }

        val credentialsBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = android.view.View.GONE
        }
        credentialsBox.addView(fieldLabel("اسم المستخدم"))
        credentialsBox.addView(proxyUsernameInput)
        credentialsBox.addView(fieldLabel("كلمة المرور"))
        credentialsBox.addView(proxyPasswordInput)
        val credentialsToggle = Button(this).apply {
            text = "بيانات الدخول (اختيارية)  +"
            isAllCaps = false
            setOnClickListener {
                val opening = credentialsBox.visibility != android.view.View.VISIBLE
                credentialsBox.visibility = if (opening) android.view.View.VISIBLE else android.view.View.GONE
                text = if (opening) "إخفاء بيانات الدخول  −" else "بيانات الدخول (اختيارية)  +"
            }
        }
        addGap(formCard, 2)
        formCard.addView(fieldLabel("عنوان البروكسي"))
        formCard.addView(addressRow)
        addGap(formCard)
        formCard.addView(connectionRow)
        addGap(formCard, 2)
        formCard.addView(credentialsToggle)
        formCard.addView(credentialsBox)
        addGap(formCard, 4)
        formCard.addView(proxyScanButton)

        indicatorCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), dp(10), dp(10), dp(10))
            background = indicatorBackground(0xFFF1F5F9.toInt())
        }
        indicatorTitle = TextView(this).apply {
            text = "مخاطر عنوان IP"
            textSize = 12f
            setTextColor(0xFF1E293B.toInt())
            maxLines = 2
        }
        indicatorValue = TextView(this).apply {
            text = "—"
            textSize = 25f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF64748B.toInt())
        }
        indicatorLevel = TextView(this).apply {
            text = "تظهر النتيجة بعد الفحص."
            textSize = 11f
            maxLines = 4
            setTextColor(0xFF475569.toInt())
        }
        indicatorCard.addView(indicatorTitle)
        indicatorCard.addView(indicatorValue)
        indicatorCard.addView(indicatorLevel)

        detectabilityCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), dp(10), dp(10), dp(10))
            background = indicatorBackground(0xFFF1F5F9.toInt())
        }
        detectabilityTitle = TextView(this).apply {
            text = "ثقة التصنيف"
            textSize = 12f
            maxLines = 2
            setTextColor(0xFF1E293B.toInt())
        }
        detectabilityValue = TextView(this).apply {
            text = "—"
            textSize = 25f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(0xFF64748B.toInt())
        }
        detectabilityLevel = TextView(this).apply {
            text = "مؤشر منفصل عن درجة المخاطر."
            textSize = 11f
            maxLines = 4
            setTextColor(0xFF475569.toInt())
        }
        detectabilityCard.addView(detectabilityTitle)
        detectabilityCard.addView(detectabilityValue)
        detectabilityCard.addView(detectabilityLevel)

        val scoreRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL
            addView(indicatorCard, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(detectabilityCard, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = dp(8)
            })
        }
        output = TextView(this).apply {
            textSize = 13f
            setTextColor(0xFF1D3045.toInt())
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }
        output.text = "لا يوجد تقرير بعد. أدخل بيانات المزوّد ثم اضغط «افحص البروكسي الآن»."
        val detailsPanel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = android.view.View.GONE
            setPadding(dp(8), dp(4), dp(8), dp(4))
            background = indicatorBackground(Color.WHITE)
            addView(output)
        }
        val detailsToggle = Button(this).apply {
            text = "تفاصيل تقرير الفحص  +"
            isAllCaps = false
            setOnClickListener {
                val opening = detailsPanel.visibility != android.view.View.VISIBLE
                detailsPanel.visibility = if (opening) android.view.View.VISIBLE else android.view.View.GONE
                text = if (opening) "إخفاء تفاصيل التقرير  −" else "تفاصيل تقرير الفحص  +"
            }
        }

        val extrasToggle = Button(this).apply {
            text = "الإضافات والأدوات  +"
            isAllCaps = false
        }
        val extrasPanel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), dp(8), dp(10), dp(8))
            background = indicatorBackground(Color.WHITE)
            visibility = android.view.View.GONE
        }
        extrasToggle.setOnClickListener {
            val opening = extrasPanel.visibility != android.view.View.VISIBLE
            extrasPanel.visibility = if (opening) android.view.View.VISIBLE else android.view.View.GONE
            extrasToggle.text = if (opening) "إخفاء الإضافات  −" else "الإضافات والأدوات  +"
        }
        extrasPanel.addView(fieldLabel("اسم البروكسي / ملاحظة محلية"))
        extrasPanel.addView(proxyNameInput)
        addGap(extrasPanel)
        extrasPanel.addView(fieldLabel("مراقبة تغيّر عنوان الخروج"))
        extrasPanel.addView(fieldLabel("فاصل التحقق الدوري"))
        extrasPanel.addView(watchIntervalSpinner)
        extrasPanel.addView(watchStartButton)
        extrasPanel.addView(watchStopButton)
        extrasPanel.addView(watchStatusText)
        extrasPanel.addView(watchHistoryButton)
        addGap(extrasPanel, 8)
        extrasPanel.addView(fieldLabel("أدوات تشخيص الجهاز وقاعدة البيانات"))
        extrasPanel.addView(localScanButton)
        extrasPanel.addView(fieldLabel("فحص IP مقابل قاعدة محلية مستوردة"))
        extrasPanel.addView(ipInput)
        extrasPanel.addView(checkIpButton)
        extrasPanel.addView(importDatabaseButton)
        val privacy = TextView(this).apply {
            text = "الخصوصية والحدود: يتصل التطبيق بالبروكسي لاستخراج عنوان الخروج، ثم يرسل عنوان الخروج فقط إلى ProxyCheck.io لفحص السمعة، مع مسار v2 احتياطي عند تعذر v3. لا تُرسل بيانات الدخول إلى مزوّد السمعة ولا تُحفظ في التطبيق. تقدير الأجهزة ليس عدد المشتركين أو الجلسات النشطة. HTTP وSOCKS5 وSOCKS4a العاديان لا يشفّران بيانات الاعتماد أثناء النقل؛ لا تدخل كلمة مرور حساسة عبر بروكسي غير موثوق. فحص DNS المعروض ليس اختبار تسريب DNS."
            textSize = 11f
            setTextColor(0xFF526579.toInt())
            setPadding(0, dp(8), 0, dp(4))
        }
        extrasPanel.addView(privacy)

        fun addSection(target: LinearLayout, view: android.view.View, bottom: Int = 7) {
            target.addView(view, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(bottom) })
        }
        addSection(content, title, 0)
        addSection(content, subtitle, 8)
        addSection(content, formCard, 8)
        addSection(content, scoreRow, 4)
        addSection(content, detailsToggle, 2)
        addSection(content, detailsPanel, 6)
        addSection(content, extrasToggle, 2)
        addSection(content, extrasPanel, 4)

        scroll.addView(content)
        root.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        ))
        setContentView(root)
    }

    private fun normalizeDigits(value: String): String = buildString {
        value.forEach { character ->
            val normalized = when (character) {
                in '٠'..'٩' -> ('0'.code + (character - '٠')).toChar()
                in '۰'..'۹' -> ('0'.code + (character - '۰')).toChar()
                else -> character
            }
            append(normalized)
        }
    }

    private fun parseProxyAddressInputs(): Pair<String, Int?> {
        var rawAddress = normalizeDigits(proxyHostInput.text.toString().trim())
        var port = normalizeDigits(proxyPortInput.text.toString().trim()).toIntOrNull()
        listOf("http://", "https://", "socks://", "socks5://", "socks5h://").forEach { scheme ->
            if (rawAddress.startsWith(scheme, ignoreCase = true)) {
                rawAddress = rawAddress.substring(scheme.length)
            }
        }
        var host = rawAddress
        if (rawAddress.startsWith("[") && rawAddress.contains("]:")) {
            val close = rawAddress.indexOf("]:")
            val embeddedPort = rawAddress.substring(close + 2).toIntOrNull()
            if (embeddedPort != null) {
                host = rawAddress.substring(1, close)
                port = embeddedPort
            }
        } else if (rawAddress.startsWith("[") && rawAddress.endsWith("]")) {
            host = rawAddress.substring(1, rawAddress.length - 1)
        } else if (rawAddress.count { it == ':' } == 1) {
            val embeddedPort = rawAddress.substringAfterLast(':').toIntOrNull()
            if (embeddedPort != null) {
                host = rawAddress.substringBeforeLast(':')
                port = embeddedPort
            }
        }
        return host.trim() to port
    }

    private fun selectedProxyProtocol(): ProxyProtocol? =
        when (proxyProtocolSpinner.selectedItem?.toString()) {
            "HTTP" -> ProxyProtocol.HTTP
            "HTTPS" -> ProxyProtocol.HTTPS
            "SOCKS5" -> ProxyProtocol.SOCKS5
            "SOCKS (اكتشاف تلقائي)" -> ProxyProtocol.SOCKS_AUTO
            else -> null
        }

    private fun runProxyScan() {
        val (host, port) = parseProxyAddressInputs()
        if (host.isBlank() || host.contains("/") || host.contains("@") || host.any { it.isWhitespace() }) {
            updateIndicator("عنوان البروكسي", "عنوان غير مكتمل", "أدخل IP أو اسم المضيف فقط، دون مسار أو اسم مستخدم داخل العنوان.")
            return
        }
        if (port == null || port !in 1..65535) {
            updateIndicator("منفذ البروكسي", "منفذ غير صالح", "أدخل المنفذ الذي أعطاك إياه المزوّد، أو الصق العنوان بصيغة host:port. النطاق 1–65535.")
            return
        }
        val protocol = selectedProxyProtocol()
        if (protocol == null) {
            updateIndicator("نوع البروكسي", "اختر النوع أولاً", "اختر HTTP أو HTTPS أو SOCKS5 أو SOCKS (اكتشاف تلقائي) وفقاً لخيار المزوّد.")
            return
        }
        val proxyLabel = proxyNameInput.text.toString().trim()
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
                val result = ProxyEndpointScanner.scan(this@MainActivity, endpoint)
                mainHandler.post {
                    if (activityDestroyed) return@post
                    proxyScanButton.isEnabled = true
                    val level = ProxyRiskPresentation.level(result.riskScore)
                    val color = riskColor(result.riskScore)
                    indicatorTitle.text = "درجة مخاطر IP لدى ProxyCheck.io ${result.sourceVersion}"
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
                        appendLine("مصدر السمعة: ProxyCheck.io ${result.sourceVersion}")
                        appendLine()
                        appendLine("الأدلة:")
                        result.evidence.forEach { appendLine("• $it") }
                        appendLine()
                        appendLine("تفسير درجة المخاطر: هذه درجة ProxyCheck.io ${result.sourceVersion} الخاصة بسمعة/مخاطر عنوان IP، وليست احتمالاً إحصائياً بأن موقعاً معيناً سيكتشف البروكسي أو يحظره.")
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
                    val message = e.message ?: "حدث خطأ أثناء فحص البروكسي."
                    updateIndicator("تعذر إكمال الفحص", "لا توجد نسبة موثوقة", message)
                    output.text = message + "\n\n" + scanFailureAdvice(message) +
                        "\n\nتحقق من العنوان والمنفذ والنوع وبيانات الدخول ثم أعد المحاولة. الفشل ليس درجة خطر."
                }
            }
        }
    }


    private fun startIpWatch() {
        val endpoint = watchEndpointFromInputs() ?: return
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_POST_NOTIFICATIONS
            )
            Toast.makeText(this, "اسمح بالإشعارات حتى تصلك تنبيهات تغيّر عنوان IP.", Toast.LENGTH_LONG).show()
            return
        }
        val interval = when (watchIntervalSpinner.selectedItemPosition) {
            0 -> 1
            2 -> 5
            else -> 2
        }
        try {
            val intent = ProxyIpWatchService.createStartIntent(this, endpoint, interval)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
            watchStatusText.text = "بدأت خدمة المراقبة؛ يجري تسجيل عنوان الخروج الأساسي."
            Toast.makeText(this, "بدأت مراقبة عنوان الخروج.", Toast.LENGTH_SHORT).show()
        } catch (error: Exception) {
            watchStatusText.text = "تعذر بدء المراقبة: " + (error.message ?: "خطأ غير معروف")
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_POST_NOTIFICATIONS) {
            if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
                startIpWatch()
            } else {
                Toast.makeText(this, "لن تصلك تنبيهات تغيّر IP دون السماح بإشعارات التطبيق.", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun watchEndpointFromInputs(): ProxyEndpoint? {
        val (host, port) = parseProxyAddressInputs()
        if (host.isBlank() || host.contains("/") || host.contains("@") || host.any { it.isWhitespace() } ||
            port == null || port !in 1..65535
        ) {
            Toast.makeText(this, "أدخل عنوان البروكسي والمنفذ الصحيحين أولاً.", Toast.LENGTH_LONG).show()
            return null
        }
        val protocol = selectedProxyProtocol()
        if (protocol == null) {
            Toast.makeText(this, "اختر نوع البروكسي كما حدده المزوّد أولاً.", Toast.LENGTH_LONG).show()
            return null
        }
        val username = proxyUsernameInput.text.toString().takeIf { it.isNotBlank() }
        val password = proxyPasswordInput.text.toString().takeIf { it.isNotBlank() }
        if ((username == null) != (password == null)) {
            Toast.makeText(this, "أدخل اسم المستخدم وكلمة المرور معاً أو اتركهما فارغين.", Toast.LENGTH_LONG).show()
            return null
        }
        return ProxyEndpoint(host, port, protocol, username, password)
    }

    private fun scanFailureAdvice(message: String): String = when {
        message.contains("توثيق", ignoreCase = true) || message.contains("authentication", ignoreCase = true) ->
            "تحقق من اسم المستخدم وكلمة المرور وصيغة اسم المستخدم الخاصة بالجلسة أو الدولة."
        message.contains("رفض البروكسي", ignoreCase = true) || message.contains("CONNECT", ignoreCase = true) ->
            "تحقق من نوع البروكسي والمنفذ؛ قد يكون النوع SOCKS5 بينما اخترت HTTP أو العكس، أو قد لا يسمح الخادم بنفق HTTPS."
        message.contains("timeout", ignoreCase = true) || message.contains("timed out", ignoreCase = true) ->
            "انتهت مهلة الاتصال. تحقق من أن البروكسي نشط وأن عنوان الخادم والمنفذ صحيحان، ثم جرب شبكة أخرى."
        message.contains("UnknownHost", ignoreCase = true) || message.contains("resolve", ignoreCase = true) ->
            "تعذر العثور على اسم الخادم. راجع تهجئة اسم المضيف أو استخدم عنوان IP الذي أعطاك المزوّد."
        message.contains("HTTP 4", ignoreCase = true) || message.contains("HTTP 5", ignoreCase = true) ->
            "وصل التطبيق إلى خدمة السمعة لكنها أعادت خطأ؛ قد تكون الحصة اليومية انتهت أو الخدمة غير متاحة مؤقتاً."
        else ->
            "قد يكون السبب عدم تطابق النوع أو المنفذ، توقف الخادم، أو رفضه الاتصال بخدمة اختبار عنوان الخروج. راجع بيانات المزوّد."
    }

    private fun stopIpWatch() {
        stopService(Intent(this, ProxyIpWatchService::class.java))
        refreshIpWatchStatus()
        Toast.makeText(this, "تم طلب إيقاف مراقبة IP.", Toast.LENGTH_SHORT).show()
    }

    private fun refreshIpWatchStatus() {
        if (!::watchStatusText.isInitialized) return
        val prefs = getSharedPreferences(ProxyIpWatchService.PREFS_NAME, MODE_PRIVATE)
        val active = prefs.getBoolean(ProxyIpWatchService.KEY_ACTIVE, false)
        val status = prefs.getString(ProxyIpWatchService.KEY_STATUS, "المراقبة متوقفة").orEmpty()
        val interval = prefs.getInt(ProxyIpWatchService.KEY_INTERVAL_MINUTES, 2)
        val lastIp = prefs.getString(ProxyIpWatchService.KEY_LAST_IP, null)
        val initialIp = prefs.getString(ProxyIpWatchService.KEY_INITIAL_IP, null)
        val changeCount = prefs.getInt(ProxyIpWatchService.KEY_CHANGE_COUNT, 0)
        val lastFrom = prefs.getString(ProxyIpWatchService.KEY_LAST_CHANGE_FROM, null)
        val lastTo = prefs.getString(ProxyIpWatchService.KEY_LAST_CHANGE_TO, null)
        val lastChangeAt = prefs.getLong(ProxyIpWatchService.KEY_LAST_CHANGE_AT, 0L)
        val lastCheckAt = prefs.getLong(ProxyIpWatchService.KEY_LAST_CHECK_AT, 0L)
        val staleAfter = interval * 60_000L * 2L + 45_000L
        val heartbeatStale = active && lastCheckAt > 0L &&
            System.currentTimeMillis() - lastCheckAt > staleAfter
        val displayActive = active && !heartbeatStale
        val builder = StringBuilder()
        builder.append(if (displayActive) "المراقبة نشطة" else if (heartbeatStale) "لا يصل تحديث من خدمة المراقبة" else "المراقبة متوقفة")
        builder.append("\n").append(status)
        if (initialIp != null) builder.append("\nعنوان البداية: ").append(initialIp)
        if (lastIp != null) builder.append("\nعنوان الخروج المرصود حالياً: ").append(lastIp)
        if (displayActive) builder.append("\nفاصل الفحص: كل ").append(interval).append(" دقيقة")
        builder.append("\nعدد تغيّرات IP المسجلة في الجلسة: ").append(changeCount)
        if (lastFrom != null && lastTo != null && lastChangeAt > 0L) {
            val time = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
                .format(java.util.Date(lastChangeAt))
            builder.append("\nآخر تغيير: ").append(lastFrom).append(" ← ").append(lastTo)
            builder.append("\nوقت الرصد: ").append(time)
        }
        if (lastCheckAt > 0L) {
            val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                .format(java.util.Date(lastCheckAt))
            builder.append("\nآخر محاولة فحص: ").append(time)
        }
        watchStatusText.text = builder.toString()
        watchStartButton.isEnabled = !displayActive
        watchStopButton.isEnabled = active
    }

    private fun showIpWatchHistory() {
        val historyFile = File(filesDir, ProxyIpWatchService.HISTORY_FILE)
        val history = if (historyFile.exists()) {
            historyFile.readText(Charsets.UTF_8)
        } else {
            "لم يتم تسجيل أي تغيّر في عنوان IP حتى الآن."
        }
        AlertDialog.Builder(this)
            .setTitle("سجل تغيّرات عنوان IP")
            .setMessage(history.takeLast(12_000))
            .setPositiveButton("إغلاق", null)
            .show()
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
