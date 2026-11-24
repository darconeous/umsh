package com.voria.umsh.features.peers

import com.voria.umsh.core.regionCodeDescription
import com.voria.umsh.models.Octets

/**
 * A region code as a person reads it: its short code (`EUG`), else
 * `0xC0F9`, until the region database names it (Phase 4).
 */
internal fun regionLabel(code: Octets): String {
    val hex = "0x" + code.hex().uppercase()
    val description = try {
        regionCodeDescription(code.toByteArray())
    } catch (_: Exception) {
        null
    }
    return description?.takeIf { !it.equals(hex, ignoreCase = true) } ?: hex
}
