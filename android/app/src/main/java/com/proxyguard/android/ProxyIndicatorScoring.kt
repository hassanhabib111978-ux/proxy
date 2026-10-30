package com.proxyguard.android

internal data class DeviceFinding(
    val label: String,
    val detail: String
)

internal data class CategoryClassification(
    val label: String,
    val detail: String
)

/**
 * Evidence-first interpretation only.
 *
 * This class deliberately does not assign numeric scores or probabilities.
 * A visible VPN/proxy is a technical observation, not proof of maliciousness.
 * Imported IP categories are unverified claims until their publisher and data
 * provenance have been independently authenticated.
 */
internal object ProxyIndicatorScoring {
    fun deviceFinding(vpn: Boolean, systemProxy: Boolean): DeviceFinding = when {
        vpn && systemProxy -> DeviceFinding(
            "رُصد VPN وإعداد Proxy للنظام",
            "يعرض Android مسار VPN نشطاً، كما يظهر إعداد Proxy للنظام. هذا يثبت ظهور هاتين الإشارتين للنظام فقط، ولا يثبت أن الاتصال ضار أو أن كل التطبيقات تستخدم الإعداد نفسه."
        )
        vpn -> DeviceFinding(
            "رُصد اتصال VPN",
            "يعرض Android مسار VPN نشطاً. وجود VPN ليس خطراً بحد ذاته، ولا يكشف وحده عنوان الخروج أو سمعة مزوّد الخدمة."
        )
        systemProxy -> DeviceFinding(
            "رُصد إعداد Proxy للنظام",
            "أظهر Android إعداد Proxy من خلال واجهة النظام. هذا لا يثبت أن جميع التطبيقات تمر عبره أو أن عنوانه ضار."
        )
        else -> DeviceFinding(
            "لم تُرصد مؤشرات ظاهرة",
            "لم يعرض Android في هذه اللحظة مسار VPN نشطاً أو إعداد Proxy عاماً يمكن للتطبيق قراءته. لا يعني ذلك خلو الاتصال من وسيط مخفي أو إعداد خاص بتطبيق أو بالشبكة."
        )
    }

    fun classifyCategory(rawCategory: String): CategoryClassification? {
        val category = rawCategory.trim().lowercase()
            .replace('_', ' ')
            .replace('-', ' ')
            .replace(Regex("\\s+"), " ")

        val hasProxy = Regex("(^|[^a-z0-9])proxy([^a-z0-9]|$)").containsMatchIn(category) ||
            category.contains("بروكسي") ||
            category.contains("وكيل") ||
            category.contains("خادم وسيط")

        val residential = category.contains("residential") ||
            category.contains("سكني")

        val tor = Regex("(^|[^a-z0-9])tor([^a-z0-9]|$)").containsMatchIn(category) ||
            category.contains("exit node") ||
            category.contains("عقدة خروج") ||
            category == "تور"

        val vpn = Regex("(^|[^a-z0-9])vpn([^a-z0-9]|$)").containsMatchIn(category) ||
            category.contains("في بي ان")

        val hosting = category.contains("datacenter") ||
            category.contains("data center") ||
            category.contains("hosting") ||
            category.contains("cloud") ||
            category.contains("مركز بيانات") ||
            category.contains("استضافة") ||
            category.contains("سحابي")

        return when {
            hasProxy && residential -> CategoryClassification(
                "بروكسي سكني",
                "قاعدة البيانات المستوردة تصنف هذا النطاق كبروكسي سكني. لم يتحقق التطبيق مستقلاً من صحة هذا التصنيف أو حداثته."
            )
            hasProxy -> CategoryClassification(
                "Proxy / خادم وسيط",
                "قاعدة البيانات المستوردة تصنف هذا النطاق كبروكسي. لم يتحقق التطبيق مستقلاً من صحة هذا التصنيف أو حداثته."
            )
            tor -> CategoryClassification(
                "Tor / عقدة خروج",
                "قاعدة البيانات المستوردة تربط هذا النطاق بشبكة Tor أو عقدة خروج. هذا تصنيف تقني وليس حكماً على إساءة الاستخدام."
            )
            vpn -> CategoryClassification(
                "VPN",
                "قاعدة البيانات المستوردة تصنف هذا النطاق كعنوان VPN. وجود VPN لا يعني أن العنوان ضار."
            )
            hosting -> CategoryClassification(
                "استضافة / مركز بيانات",
                "قاعدة البيانات تصنف هذا النطاق كبنية استضافة أو مركز بيانات. هذه المعلومة وحدها لا تثبت وجود Proxy أو VPN."
            )
            else -> null
        }
    }
}
