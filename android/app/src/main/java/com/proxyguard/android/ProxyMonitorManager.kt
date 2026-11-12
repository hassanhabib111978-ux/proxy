package com.proxyguard.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

internal data class ProxyConfig(
    val host: String,
    val port: Int,
    val type: String,
    val username: String,
    val password: String
)

internal data class ProxyResult(
    val ok: Boolean,
    val ip: String? = null,
    val elapsedMs: Long = 0L,
    val message: String
) {
    fun toJson(): JSONObject = JSONObject()
        .put("ok", ok)
        .put("ip", ip ?: JSONObject.NULL)
        .put("elapsedMs", elapsedMs)
        .put("message", message)
        .put("error", if (ok) JSONObject.NULL else message)
}

internal class ProxyMonitorManager(context: Context) {
    private val appContext = context.applicationContext
    private val engine = ProxyEngine(appContext)
    private val store = ProxyStateStore(appContext)
    private val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "proxyguard-monitor").apply { isDaemon = true }
    }
    @Volatile private var scheduled: ScheduledFuture<*>? = null
    @Volatile private var running = false

    fun checkOnce(config: ProxyConfig, callback: (ProxyResult, JSONObject) -> Unit) {
        executor.execute {
            val result = engine.fetchExitIp(config)
            val state = if (result.ok && result.ip != null) store.record(result.ip) else store.snapshot()
            callback(result, state)
        }
    }

    @Synchronized
    fun start(config: ProxyConfig, intervalSeconds: Int, callback: (ProxyResult, JSONObject) -> Unit) {
        stop()
        running = true
        val safeInterval = intervalSeconds.coerceIn(2, 300)
        scheduled = executor.scheduleWithFixedDelay({
            if (running) {
                val result = engine.fetchExitIp(config)
                val state = if (result.ok && result.ip != null) store.record(result.ip) else store.snapshot()
                if (running) callback(result, state)
            }
        }, 0, safeInterval.toLong(), TimeUnit.SECONDS)
    }

    @Synchronized
    fun stop() {
        running = false
        scheduled?.cancel(false)
        scheduled = null
    }

    fun snapshot(): JSONObject = store.snapshot().put("monitoring", running)

    fun saveMonitorSettings(rotationSeconds: Int, alertSeconds: Int, pollSeconds: Int, soundEnabled: Boolean) {
        store.saveMonitorSettings(rotationSeconds, alertSeconds, pollSeconds, soundEnabled)
    }

    fun monitorSettings(): JSONObject = store.monitorSettings()

    fun resyncRotationTimer(): JSONObject = store.resyncRotationTimer().put("monitoring", running)

    fun clearHistory() = store.clearHistory()

    fun shutdown() {
        stop()
        executor.shutdownNow()
    }
}

private class ProxyStateStore(context: Context) {
    private val prefs = context.getSharedPreferences("proxyguard_ip_state", Context.MODE_PRIVATE)
    private val lock = Any()

    fun record(ip: String): JSONObject = synchronized(lock) {
        val oldIp = prefs.getString("ip", null)
        val oldChangedAt = prefs.getLong("changed_at", 0L)
        val now = System.currentTimeMillis()
        val first = oldIp.isNullOrBlank()
        val changed = !first && oldIp != ip
        val changedAt = if (first || changed) now else oldChangedAt
        val cycleStartAt = if (first || changed) now else prefs.getLong("cycle_started_at", changedAt)
        val events = readHistory()

        if (first || changed) {
            val event = JSONObject()
                .put("ip", ip)
                .put("previousIp", if (first) JSONObject.NULL else oldIp)
                .put("detectedAt", now)
                .put("durationSeconds", if (first || oldChangedAt <= 0L) 0 else ((now - oldChangedAt).coerceAtLeast(0L) / 1000L))
                .put("kind", if (first) "first" else "changed")
            events.put(event)
            while (events.length() > 150) events.remove(0)
            prefs.edit()
                .putString("history", events.toString())
                .putString("ip", ip)
                .putLong("changed_at", changedAt)
                .putLong("cycle_started_at", cycleStartAt)
                .apply()
        } else if (prefs.getLong("cycle_started_at", 0L) <= 0L && cycleStartAt > 0L) {
            prefs.edit().putLong("cycle_started_at", cycleStartAt).apply()
        }
        snapshotLocked(ip, changedAt, cycleStartAt, events, first, changed)
    }

    fun snapshot(): JSONObject = synchronized(lock) {
        val ip = prefs.getString("ip", null)
        val changedAt = prefs.getLong("changed_at", 0L)
        val cycleStartAt = prefs.getLong("cycle_started_at", changedAt)
        snapshotLocked(ip, changedAt, cycleStartAt, readHistory(), false, false)
    }

    fun resyncRotationTimer(): JSONObject = synchronized(lock) {
        val now = System.currentTimeMillis()
        prefs.edit().putLong("cycle_started_at", now).apply()
        snapshot().put("resynced", true)
    }

    fun saveMonitorSettings(rotationSeconds: Int, alertSeconds: Int, pollSeconds: Int, soundEnabled: Boolean) {
        synchronized(lock) {
            prefs.edit()
                .putInt("rotation_seconds", rotationSeconds.coerceIn(10, 86400))
                .putInt("alert_seconds", alertSeconds.coerceIn(1, 120))
                .putInt("poll_seconds", pollSeconds.coerceIn(2, 300))
                .putBoolean("sound_enabled", soundEnabled)
                .apply()
        }
    }

    fun monitorSettings(): JSONObject = synchronized(lock) {
        JSONObject()
            .put("rotationSeconds", prefs.getInt("rotation_seconds", 300))
            .put("alertSeconds", prefs.getInt("alert_seconds", 10))
            .put("pollSeconds", prefs.getInt("poll_seconds", 5))
            .put("soundEnabled", prefs.getBoolean("sound_enabled", true))
    }

    fun clearHistory() = synchronized(lock) {
        prefs.edit().putString("history", "[]").apply()
    }

    private fun readHistory(): JSONArray = try {
        JSONArray(prefs.getString("history", "[]") ?: "[]")
    } catch (_: Exception) {
        JSONArray()
    }

    private fun snapshotLocked(
        ip: String?,
        changedAt: Long,
        cycleStartAt: Long,
        events: JSONArray,
        first: Boolean,
        changed: Boolean
    ): JSONObject = JSONObject()
        .put("currentIp", ip ?: JSONObject.NULL)
        .put("lastChangedAt", if (changedAt > 0L) changedAt else JSONObject.NULL)
        .put("cycleStartAt", if (cycleStartAt > 0L) cycleStartAt else JSONObject.NULL)
        .put("history", events)
        .put("firstSeen", first)
        .put("changed", changed)
}
