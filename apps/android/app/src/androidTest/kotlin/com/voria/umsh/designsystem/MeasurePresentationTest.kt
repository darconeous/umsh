package com.voria.umsh.designsystem

import android.content.res.Configuration
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Seconds and radio readings through ICU and the string resources (§3.11),
 * in English and under the pseudo-locales: en-XA (accented, longer) and
 * ar-XB (right to left). Connected, since ICU and the resources are the
 * device's; the module has no Robolectric.
 */
class MeasurePresentationTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun resources(locale: Locale) =
        context.createConfigurationContext(Configuration(context.resources.configuration).apply { setLocale(locale) }).resources

    @Test
    fun secondsToATenth() {
        val english = MeasurePresentation.seconds(1_380, Locale.US)
        assertTrue(english, english.startsWith("1.4") && english.trimEnd().endsWith("s") || english.endsWith("sec"))
        assertTrue(MeasurePresentation.seconds(-5, Locale.US).startsWith("0.0"))
        assertTrue(MeasurePresentation.secondsSpoken(1_380, Locale.US).contains("second"))
        // A decimal comma where the locale writes one.
        assertTrue(MeasurePresentation.seconds(1_380, Locale.GERMANY).startsWith("1,4"))
    }

    @Test
    fun aReadingIsOneSentenceInEachLocale() {
        val english = SignalPresentation.readingText(resources(Locale.US), -97, 65, Locale.US)
        assertEquals("-97 dBm · SNR 6.5 dB", english)
        assertEquals("-97 dBm", SignalPresentation.readingText(resources(Locale.US), -97, null, Locale.US))
        assertEquals("SNR 6.5 dB", SignalPresentation.readingText(resources(Locale.US), null, 65, Locale.US))
        assertNull(SignalPresentation.readingText(resources(Locale.US), null, null, Locale.US))
        for (tag in listOf("en-XA", "ar-XB")) {
            val locale = Locale.forLanguageTag(tag)
            val text = SignalPresentation.readingText(resources(locale), -97, 65, locale)!!
            assertNotEquals("$tag is pseudolocalized", english, text)
            assertTrue("$tag keeps its numbers: $text", text.contains("97") && (text.contains("6.5") || text.contains("6٫5") || text.contains("6,5")))
        }
    }

    @Test
    fun barsFollowSignalToNoiseFirst() {
        assertEquals(4, SignalPresentation.bars(-120, 100))
        assertEquals(1, SignalPresentation.bars(-50, -25))
        assertEquals(0, SignalPresentation.bars(null, -80))
        assertEquals(3, SignalPresentation.bars(-95, null))
        assertNull(SignalPresentation.bars(null, null))
    }
}
