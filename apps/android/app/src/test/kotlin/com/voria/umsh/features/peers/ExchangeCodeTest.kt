package com.voria.umsh.features.peers

import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test

/** The code both screens show: two groups of three ASCII digits, whatever the locale. */
class ExchangeCodeTest {
    @Test
    fun twoGroupsOfThreeWithLeadingZeros() {
        assertEquals("123 456", ExchangeCode.grouped(123_456))
        assertEquals("000 042", ExchangeCode.grouped(42))
        assertEquals("000 000", ExchangeCode.grouped(0))
        assertEquals("999 999", ExchangeCode.grouped(999_999))
        assertEquals("123456", ExchangeCode.digits(123_456))
    }

    @Test
    fun asciiDigitsInEveryLocale() {
        val before = Locale.getDefault()
        try {
            for (tag in listOf("ar-EG", "fa-IR", "hi-IN-u-nu-deva", "th-TH-u-nu-thai")) {
                Locale.setDefault(Locale.forLanguageTag(tag))
                assertEquals(tag, "012 345", ExchangeCode.grouped(12_345))
            }
        } finally {
            Locale.setDefault(before)
        }
    }
}
