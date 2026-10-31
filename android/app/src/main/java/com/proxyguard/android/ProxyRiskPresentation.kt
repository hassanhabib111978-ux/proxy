package com.proxyguard.android

internal object ProxyRiskPresentation {
    fun level(score: Int): String {
        require(score in 0..100)
        return when {
            score < 20 -> "منخفض جداً"
            score < 40 -> "منخفض"
            score < 75 -> "متوسط"
            score < 90 -> "مرتفع"
            else -> "مرتفع جداً"
        }
    }

    fun colorBand(score: Int): String {
        require(score in 0..100)
        return when {
            score < 40 -> "green"
            score < 75 -> "yellow"
            else -> "red"
        }
    }
}
