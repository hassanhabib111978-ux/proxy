package com.proxyguard.android

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Strict local-only IP/CIDR and CSV parsing.
 * IP literals are parsed numerically; hostnames are rejected so this engine never performs DNS lookups.
 */
internal object IpIntelDatabase {
    const val MAX_DATABASE_BYTES = 5 * 1024 * 1024
    const val MAX_DATABASE_ENTRIES = 100_000

    fun parseCsv(rawText: String): List<IpIntelEntry> {
        require(rawText.toByteArray(Charsets.UTF_8).size <= MAX_DATABASE_BYTES) {
            "حجم القاعدة المحلية يتجاوز 5MB"
        }
        val text = rawText.removePrefix("\uFEFF")
        val rows = parseCsvRows(text)
        val header = rows.firstOrNull()
        require(header?.size == 3 &&
            header[0].trim().equals("cidr", ignoreCase = true) &&
            header[1].trim().equals("category", ignoreCase = true) &&
            header[2].trim().equals("source", ignoreCase = true)
        ) {
            "صيغة الملف غير صحيحة؛ يجب أن يبدأ بالعناوين cidr,category,source"
        }

        val parsed = ArrayList<IpIntelEntry>()
        rows.drop(1).forEachIndexed { index, row ->
            val rowNumber = index + 2
            if (row.all { it.isBlank() }) return@forEachIndexed
            require(row.size in 2..3) {
                "عدد الأعمدة غير صحيح في السطر $rowNumber"
            }
            val cidr = row[0].trim()
            require(validCidr(cidr)) { "عنوان CIDR غير صالح في السطر $rowNumber" }
            val category = row[1].trim()
            val source = row.getOrNull(2)?.trim().takeUnless { it.isNullOrBlank() } ?: "مستورد محلياً"
            require(isSafeLabel(category, 80)) {
                "التصنيف فارغ أو طويل أو يحتوي محارف تحكم في السطر $rowNumber"
            }
            require(isSafeLabel(source, 120)) {
                "المصدر طويل أو يحتوي محارف تحكم في السطر $rowNumber"
            }
            parsed.add(IpIntelEntry(cidr, category, source))
            require(parsed.size <= MAX_DATABASE_ENTRIES) {
                "عدد السجلات يتجاوز الحد الأقصى البالغ 100000"
            }
        }
        require(parsed.isNotEmpty()) { "لا يحتوي الملف على سجلات صالحة" }
        return parsed
    }

    /** RFC-4180-style field quoting, escaped quotes, and CRLF/LF record handling. */
    private fun parseCsvRows(text: String): List<List<String>> {
        val rows = ArrayList<List<String>>()
        var fields = ArrayList<String>()
        val field = StringBuilder()
        var inQuotes = false
        var quoteClosed = false
        var recordHasContent = false
        var index = 0

        fun finishRecord() {
            fields.add(field.toString())
            if (recordHasContent || fields.any { it.isNotBlank() }) {
                rows.add(fields.toList())
                require(rows.size <= MAX_DATABASE_ENTRIES + 1) {
                    "عدد صفوف CSV يتجاوز الحد المسموح"
                }
            }
            fields = ArrayList()
            field.setLength(0)
            quoteClosed = false
            recordHasContent = false
        }

        while (index < text.length) {
            val ch = text[index]
            if (inQuotes) {
                if (ch == '"') {
                    if (index + 1 < text.length && text[index + 1] == '"') {
                        field.append('"')
                        index += 2
                        continue
                    }
                    inQuotes = false
                    quoteClosed = true
                } else {
                    field.append(ch)
                }
            } else {
                when (ch) {
                    '"' -> {
                        require(field.isEmpty() && !quoteClosed) {
                            "علامة اقتباس في موضع غير صالح قرب المحرف $index"
                        }
                        inQuotes = true
                        recordHasContent = true
                    }
                    ',' -> {
                        fields.add(field.toString())
                        field.setLength(0)
                        quoteClosed = false
                        recordHasContent = true
                    }
                    '\n', '\r' -> {
                        finishRecord()
                        if (ch == '\r' && index + 1 < text.length && text[index + 1] == '\n') {
                            index++
                        }
                    }
                    else -> {
                        require(!quoteClosed) {
                            "محتوى غير متوقع بعد إغلاق الاقتباس قرب المحرف $index"
                        }
                        field.append(ch)
                        if (!ch.isWhitespace()) recordHasContent = true
                    }
                }
            }
            index++
        }
        require(!inQuotes) { "ملف CSV يحتوي على علامة اقتباس غير مغلقة" }
        if (field.isNotEmpty() || fields.isNotEmpty() || recordHasContent || quoteClosed) {
            finishRecord()
        }
        return rows
    }

    private fun isSafeLabel(value: String, maxLength: Int): Boolean =
        value.isNotBlank() &&
            value.length <= maxLength &&
            value.none { it.isISOControl() }

    fun parseIpLiteral(value: String): InetAddress? {
        if (value.isBlank() || value != value.trim() || value.contains('%')) return null
        if (value.contains(':')) {
            if (!value.matches(Regex("[0-9a-fA-F:.]+"))) return null
            return runCatching { InetAddress.getByName(value) }.getOrNull()
                ?.takeIf { it.address.size == 16 }
        }
        val octets = value.split('.')
        if (octets.size != 4 || octets.any { it.isEmpty() || it.any { ch -> ch !in '0'..'9' } }) {
            return null
        }
        val numbers = octets.map { it.toIntOrNull() ?: return null }
        if (numbers.any { it !in 0..255 }) return null
        if (octets.indices.any { octets[it].length > 1 && octets[it].startsWith('0') }) return null
        return runCatching {
            InetAddress.getByAddress(numbers.map { it.toByte() }.toByteArray())
        }.getOrNull()
    }

    private fun parseCidr(value: String): Pair<InetAddress, Int>? {
        val parts = value.split('/')
        if (parts.size != 2 || !parts[1].matches(Regex("0|[1-9][0-9]*"))) return null
        val address = parseIpLiteral(parts[0]) ?: return null
        val prefix = parts[1].toIntOrNull() ?: return null
        val maxPrefix = if (address is Inet4Address) 32 else 128
        if (prefix !in 0..maxPrefix) return null
        return address to prefix
    }

    fun validCidr(value: String): Boolean = parseCidr(value) != null

    fun cidrContains(cidr: String, candidate: InetAddress): Boolean {
        val parsed = parseCidr(cidr) ?: return false
        val base = parsed.first.address
        val candidateBytes = candidate.address
        if (base.size != candidateBytes.size) return false
        val prefix = parsed.second
        val fullBytes = prefix / 8
        val remainingBits = prefix % 8
        for (i in 0 until fullBytes) {
            if (base[i] != candidateBytes[i]) return false
        }
        if (remainingBits == 0) return true
        val mask = (0xFF shl (8 - remainingBits)) and 0xFF
        return ((base[fullBytes].toInt() and 0xFF) and mask) ==
            ((candidateBytes[fullBytes].toInt() and 0xFF) and mask)
    }
}
