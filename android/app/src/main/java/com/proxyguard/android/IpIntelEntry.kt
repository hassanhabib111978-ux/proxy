package com.proxyguard.android

/**
 * One local CIDR classification row imported by the user's CSV database.
 */
internal data class IpIntelEntry(
    val cidr: String,
    val category: String,
    val source: String
)
