package com.proxyguard.android

internal enum class IpWatchComparison {
    BASELINE,
    UNCHANGED,
    CHANGED
}

internal fun compareExitIp(previousIp: String?, currentIp: String): IpWatchComparison {
    require(currentIp.isNotBlank()) { "عنوان الخروج الحالي فارغ." }
    return when {
        previousIp.isNullOrBlank() -> IpWatchComparison.BASELINE
        previousIp == currentIp -> IpWatchComparison.UNCHANGED
        else -> IpWatchComparison.CHANGED
    }
}
