package com.proxyguard.android

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

class ProxyRiskAuditorActivity : Activity() {
    private lateinit var webView: WebView
    private val scanExecutor = Executors.newSingleThreadExecutor()
    @Volatile private var activityDestroyed = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = android.graphics.Color.rgb(3, 7, 18)
        window.navigationBarColor = android.graphics.Color.rgb(3, 7, 18)

        webView = WebView(this).apply {
            setBackgroundColor(android.graphics.Color.rgb(3, 7, 18))
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = false
            settings.allowFileAccess = true
            settings.allowContentAccess = false
            settings.allowFileAccessFromFileURLs = false
            settings.allowUniversalAccessFromFileURLs = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(
                    view: WebView,
                    request: WebResourceRequest
                ): Boolean {
                    return request.url.scheme != "file"
                }
            }
            addJavascriptInterface(NativeBridge(), "AndroidProxy")
        }
        setContentView(webView)
        webView.loadUrl("file:///android_asset/proxy_risk_auditor.html")
    }

    private inner class NativeBridge {
        @JavascriptInterface
        fun scanProxy(rawInput: String?) {
            val input = rawInput.orEmpty()
            if (input.length > 1_000) {
                publishError("بيانات البروكسي أطول من المسموح.")
                return
            }
            if (activityDestroyed) return

            scanExecutor.execute {
                try {
                    val endpoint = ProxyInputParser.parse(input)
                    val result = ProxyEndpointScanner.scan(this@ProxyRiskAuditorActivity, endpoint)
                    val payload = JSONObject()
                        .put("ok", true)
                        .put("riskScore", result.riskScore)
                        .put("riskLabel", ProxyRiskPresentation.level(result.riskScore))
                        .put("exitIp", result.exitIp)
                        .put("sourceVersion", result.sourceVersion)
                        .put("proxyDetected", result.proxyDetected)
                        .put("vpnDetected", result.vpnDetected)
                        .put("classificationType", result.classificationType ?: JSONObject.NULL)
                        .put("provider", result.provider ?: JSONObject.NULL)
                        .put("networkType", result.networkType ?: JSONObject.NULL)
                        .put("country", result.country ?: JSONObject.NULL)
                        .put("confidenceScore", result.confidenceScore ?: JSONObject.NULL)
                        .put("detectabilityScore", result.detectabilityScore ?: JSONObject.NULL)
                        .put("detectionSignals", JSONArray(result.detectionSignals.orEmpty()))
                        .put("evidence", JSONArray(result.evidence))
                    publish(payload)
                } catch (error: Exception) {
                    publishError(error.message ?: "تعذر إكمال الفحص.")
                }
            }
        }
    }

    private fun publishError(message: String) {
        publish(
            JSONObject()
                .put("ok", false)
                .put("error", message.take(500))
        )
    }

    private fun publish(payload: JSONObject) {
        if (activityDestroyed) return
        val encoded = JSONObject.quote(payload.toString())
        webView.post {
            if (!activityDestroyed && !isFinishing) {
                webView.evaluateJavascript(
                    "window.onNativeResult(JSON.parse(" + encoded + "));",
                    null
                )
            }
        }
    }

    override fun onDestroy() {
        activityDestroyed = true
        scanExecutor.shutdownNow()
        if (::webView.isInitialized) {
            webView.removeJavascriptInterface("AndroidProxy")
            webView.stopLoading()
            webView.destroy()
        }
        super.onDestroy()
    }
}
