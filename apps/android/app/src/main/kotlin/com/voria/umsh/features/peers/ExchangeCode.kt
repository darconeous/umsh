package com.voria.umsh.features.peers

import java.util.Locale

/**
 * The code both screens show while comparing (`nearby-exchange.svg` 3–4):
 * six digits in two groups of three, as the holders read it aloud. ASCII
 * digits whatever the locale, since the other screen may be in another
 * language; never a resource.
 */
object ExchangeCode {
    /** "123 456"; leading zeros kept. */
    fun grouped(code: Int): String {
        val digits = String.format(Locale.ROOT, "%06d", code.coerceIn(0, 999_999))
        return "${digits.substring(0, 3)} ${digits.substring(3)}"
    }

    /** The digits alone, which TalkBack reads one by one. */
    fun digits(code: Int): String = grouped(code).replace(" ", "")
}
