package com.proxyguard.android

internal data class CategoryScore(
    val score: Int,
    val label: String,
    val reason: String
)

/**
 * Prototype detection weights only. These values are not calibrated probabilities
 * and must never be presented as a security-risk or maliciousness score.
 */
internal object ProxyIndicatorScoring {
    fun deviceSignalScore(vpn: Boolean, systemProxy: Boolean): Int? = when {
        vpn && systemProxy -> 100
        systemProxy -> 90
        vpn -> 75
        else -> null
    }

    fun scoreForCategory(rawCategory: String): CategoryScore? {
        val category = rawCategory.trim().lowercase()
            .replace('_', ' ')
            .replace('-', ' ')
        val hasProxy = category.contains("proxy") ||
            category.contains("بروكسي") ||
            category.contains("وكيل") ||
            category.contains("خادم وسيط")

        return when {
            (category.contains("residential") || category.contains("سكني")) && hasProxy ->
                CategoryScore(95, "قوية جداً", "تصنيف القاعدة يشير صراحةً إلى بروكسي سكني.")
            hasProxy ->
                CategoryScore(90, "قوية", "تصنيف القاعدة يشير صراحةً إلى عنوان بروكسي أو خادم وسيط.")
            (category == "tor" || category.contains("tor exit") || category.contains("tor node") ||
                category.contains("exit node") || category.contains("عقدة خروج") || category.contains("تور")) ->
                CategoryScore(88, "قوية", "تصنيف القاعدة يشير إلى Tor أو عقدة خروج.")
            category.contains("vpn") || category.contains("في بي ان") ->
                CategoryScore(82, "قوية", "تصنيف القاعدة يشير إلى عنوان VPN.")
            category.contains("datacenter") || category.contains("data center") ||
                category.contains("hosting") || category.contains("cloud") ||
                category.contains("مركز بيانات") || category.contains("استضافة") ||
                category.contains("سحابي") ->
                CategoryScore(35, "ضعيفة", "العنوان ضمن بنية استضافة أو مركز بيانات؛ هذا دليل بنية ضعيف ولا يثبت أنه بروكسي.")
            else -> null
        }
    }

    /**
     * Display bands requested for the 0–100 indicator scale:
     * 0–25 low (green), 26–74 moderate (blue), 75–89 high (orange), 90–100 very high (red).
     */
    fun indicatorBand(score: Int): String = when {
        score !in 0..100 -> "غير صالحة"
        score <= 25 -> "منخفضة"
        score < 75 -> "متوسطة"
        score < 90 -> "عالية"
        else -> "مرتفعة جداً"
    }
}
