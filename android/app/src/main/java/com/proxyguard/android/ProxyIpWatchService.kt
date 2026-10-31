package com.proxyguard.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * User-started foreground monitor. It periodically opens a fresh HTTPS tunnel
 * through the same configured proxy endpoint and observes the public exit IP.
 * Credentials remain in memory only; they are never written to preferences or logs.
 */
class ProxyIpWatchService : Service() {
    @Volatile private var stopping = false
    private var scheduler: ScheduledExecutorService? = null

    private val preferences by lazy {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        val intervalMinutes = intent.getIntExtra(EXTRA_INTERVAL_MINUTES, 2).coerceIn(1, 5)
        createNotificationChannels()
        val initialNotification = buildOngoingNotification("جارٍ بدء مراقبة عنوان الخروج")
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                initialNotification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, initialNotification)
        }

        val endpoint = ProxyEndpoint(
            host = intent.getStringExtra(EXTRA_HOST).orEmpty(),
            port = intent.getIntExtra(EXTRA_PORT, 0),
            protocol = when (intent.getStringExtra(EXTRA_PROTOCOL)) {
                "HTTPS" -> ProxyProtocol.HTTPS
                "SOCKS5" -> ProxyProtocol.SOCKS5
                "SOCKS_AUTO" -> ProxyProtocol.SOCKS_AUTO
                else -> ProxyProtocol.HTTP
            },
            username = intent.getStringExtra(EXTRA_USERNAME),
            password = intent.getStringExtra(EXTRA_PASSWORD)
        )

        stopping = true
        scheduler?.shutdownNow()
        stopping = false
        preferences.edit()
            .putBoolean(KEY_ACTIVE, true)
            .putInt(KEY_INTERVAL_MINUTES, intervalMinutes)
            .putString(KEY_STATUS, "بدأت المراقبة؛ يجري الحصول على عنوان الأساس")
            .remove(KEY_INITIAL_IP)
            .remove(KEY_LAST_IP)
            .remove(KEY_LAST_CHANGE_FROM)
            .remove(KEY_LAST_CHANGE_TO)
            .remove(KEY_LAST_CHANGE_AT)
            .putInt(KEY_CHANGE_COUNT, 0)
            .putLong(KEY_LAST_CHECK_AT, 0L)
            .apply()

        scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "ProxyGuard-IP-Watch").apply { isDaemon = true }
        }.also { executor ->
            executor.scheduleWithFixedDelay(
                { pollExitIp(endpoint) },
                0L,
                intervalMinutes.toLong(),
                TimeUnit.MINUTES
            )
        }
        return START_NOT_STICKY
    }

    private fun pollExitIp(endpoint: ProxyEndpoint) {
        if (stopping) return
        try {
            val observedIp = ProxyEndpointScanner.currentExitIp(this@ProxyIpWatchService, endpoint)
            val previousIp = preferences.getString(KEY_LAST_IP, null)
            val comparison = compareExitIp(previousIp, observedIp)
            val now = System.currentTimeMillis()
            when (comparison) {
                IpWatchComparison.BASELINE -> {
                    preferences.edit()
                        .putString(KEY_INITIAL_IP, observedIp)
                        .putString(KEY_LAST_IP, observedIp)
                        .putString(KEY_STATUS, "تم تسجيل عنوان الأساس؛ المراقبة مستمرة")
                        .putLong(KEY_LAST_CHECK_AT, now)
                        .apply()
                    updateOngoingNotification("عنوان الخروج الحالي: " + observedIp)
                }
                IpWatchComparison.UNCHANGED -> {
                    preferences.edit()
                        .putString(KEY_STATUS, "عنوان الخروج مستقر في آخر فحص")
                        .putLong(KEY_LAST_CHECK_AT, now)
                        .apply()
                    updateOngoingNotification("عنوان الخروج مستقر: " + observedIp)
                }
                IpWatchComparison.CHANGED -> {
                    val oldIp = previousIp.orEmpty()
                    val count = preferences.getInt(KEY_CHANGE_COUNT, 0) + 1
                    preferences.edit()
                        .putString(KEY_LAST_IP, observedIp)
                        .putString(KEY_STATUS, "تم تأكيد تغيّر عنوان IP")
                        .putString(KEY_LAST_CHANGE_FROM, oldIp)
                        .putString(KEY_LAST_CHANGE_TO, observedIp)
                        .putLong(KEY_LAST_CHANGE_AT, now)
                        .putInt(KEY_CHANGE_COUNT, count)
                        .putLong(KEY_LAST_CHECK_AT, now)
                        .apply()
                    appendHistory(now, oldIp, observedIp)
                    notifyIpChanged(oldIp, observedIp, count)
                    updateOngoingNotification("تم رصد تغيّر IP؛ الحالي: " + observedIp)
                }
            }
        } catch (error: Exception) {
            val message = "تعذّر الفحص؛ ستتم إعادة المحاولة: " + safeMessage(error)
            preferences.edit()
                .putString(KEY_STATUS, message)
                .putLong(KEY_LAST_CHECK_AT, System.currentTimeMillis())
                .apply()
            updateOngoingNotification(message)
        }
    }

    private fun appendHistory(timestamp: Long, previousIp: String, currentIp: String) {
        val historyFile = File(filesDir, HISTORY_FILE)
        val existing = if (historyFile.exists()) {
            historyFile.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
        } else {
            listOf("time_utc,previous_ip,new_ip")
        }
        val entry = java.text.SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            java.util.Locale.ROOT
        ).apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(java.util.Date(timestamp)) + "," + previousIp + "," + currentIp
        val updated = (existing + entry).let { rows ->
            if (rows.size > MAX_HISTORY_ROWS + 1) rows.take(1) + rows.takeLast(MAX_HISTORY_ROWS)
            else rows
        }
        historyFile.writeText(updated.joinToString("\n"), Charsets.UTF_8)
    }

    private fun notifyIpChanged(previousIp: String, currentIp: String, count: Int) {
        val text = "العنوان السابق: " + previousIp + " — العنوان الجديد: " + currentIp
        val notification = Notification.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("ProxyGuard: تم تغيّر عنوان IP")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text + "\nعدد التغيّرات في هذه الجلسة: " + count))
            .setContentIntent(openAppPendingIntent())
            .setAutoCancel(true)
            .setShowWhen(true)
            .setWhen(System.currentTimeMillis())
            .build()
        val notificationId = (System.currentTimeMillis() % 100000).toInt() + ALERT_NOTIFICATION_ID
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(notificationId, notification)
    }

    private fun updateOngoingNotification(text: String) {
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIFICATION_ID, buildOngoingNotification(text))
    }

    private fun buildOngoingNotification(text: String): Notification =
        Notification.Builder(this, ONGOING_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("ProxyGuard — مراقبة IP نشطة")
            .setContentText(text)
            .setContentIntent(openAppPendingIntent())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .build()

    private fun openAppPendingIntent(): PendingIntent {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
            ?: Intent(this, MainActivity::class.java)
        return PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                ONGOING_CHANNEL_ID,
                "مراقبة اتصال ProxyGuard",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "إشعار دائم أثناء مراقبة عنوان خروج البروكسي" }
        )
        manager.createNotificationChannel(
            NotificationChannel(
                ALERT_CHANNEL_ID,
                "تنبيهات تغيّر عنوان IP",
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "ينبه عند تأكيد اختلاف عنوان الخروج" }
        )
    }

    private fun safeMessage(error: Exception): String =
        error.message?.take(120) ?: "خطأ اتصال غير محدد"

    override fun onDestroy() {
        stopping = true
        scheduler?.shutdownNow()
        preferences.edit()
            .putBoolean(KEY_ACTIVE, false)
            .putString(KEY_STATUS, "المراقبة متوقفة")
            .apply()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.proxyguard.android.action.START_IP_WATCH"
        const val ACTION_STOP = "com.proxyguard.android.action.STOP_IP_WATCH"
        const val PREFS_NAME = "proxyguard_ip_watch"
        const val KEY_ACTIVE = "active"
        const val KEY_STATUS = "status"
        const val KEY_INTERVAL_MINUTES = "interval_minutes"
        const val KEY_INITIAL_IP = "initial_ip"
        const val KEY_LAST_IP = "last_ip"
        const val KEY_LAST_CHANGE_FROM = "last_change_from"
        const val KEY_LAST_CHANGE_TO = "last_change_to"
        const val KEY_LAST_CHANGE_AT = "last_change_at"
        const val KEY_CHANGE_COUNT = "change_count"
        const val KEY_LAST_CHECK_AT = "last_check_at"
        const val HISTORY_FILE = "proxyguard-ip-watch-history.csv"
        private const val EXTRA_HOST = "host"
        private const val EXTRA_PORT = "port"
        private const val EXTRA_PROTOCOL = "protocol"
        private const val EXTRA_USERNAME = "username"
        private const val EXTRA_PASSWORD = "password"
        private const val EXTRA_INTERVAL_MINUTES = "interval_minutes"
        private const val ONGOING_CHANNEL_ID = "proxyguard_ip_watch"
        private const val ALERT_CHANNEL_ID = "proxyguard_ip_watch_alerts"
        private const val NOTIFICATION_ID = 6201
        private const val ALERT_NOTIFICATION_ID = 6300
        private const val MAX_HISTORY_ROWS = 100

        internal fun createStartIntent(
            context: android.content.Context,
            endpoint: ProxyEndpoint,
            intervalMinutes: Int
        ): Intent = Intent(context, ProxyIpWatchService::class.java).apply {
            action = ACTION_START
            putExtra(EXTRA_HOST, endpoint.host)
            putExtra(EXTRA_PORT, endpoint.port)
            putExtra(EXTRA_PROTOCOL, endpoint.protocol.name)
            putExtra(EXTRA_USERNAME, endpoint.username)
            putExtra(EXTRA_PASSWORD, endpoint.password)
            putExtra(EXTRA_INTERVAL_MINUTES, intervalMinutes.coerceIn(1, 5))
        }
    }
}
