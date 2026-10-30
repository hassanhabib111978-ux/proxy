package com.proxyguard.android

internal object ProxyRiskPresentation {
    fun level(score: Int): String {
        require(score in 0..100)
        return when {
            score < 20 -> "منخفض جداً"
            score < 40 -> "منخفض"
            score < 60 -> "متوسط"
            score < 80 -> "مرتفع"
            else -> "مرتفع جداً"
        }
    }

    fun colorBand(score: Int): String {
        require(score in 0..100)
        return when {
            score < 20 -> "green"
            score < 40 -> "yellow-green"
            score < 60 -> "yellow"
            else -> "red"
        }
    }
}
