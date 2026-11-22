package com.voria.umsh.designsystem

/**
 * Grapheme clusters and emoji, as the channel lettering and title rules
 * need them (`docs/ux/src/apps/channel-badges.md`). Pure Kotlin: `\X` is an
 * extended grapheme cluster in both the JVM's regex engine and Android's
 * (ICU's), so the JVM tests see what a phone sees.
 */
object Graphemes {
    private val cluster = Regex("\\X")

    fun split(text: String): List<String> = cluster.findAll(text).map { it.value }.toList()

    /**
     * Whether [cluster] is drawn as an emoji: anything carrying the emoji
     * variation selector or a keycap, a flag, or a code point whose default
     * presentation is emoji. A text-default symbol such as `©` with no
     * selector is not one.
     */
    fun isEmoji(cluster: String): Boolean {
        if (cluster.isEmpty()) return false
        val first = cluster.codePointAt(0)
        return cluster.contains(VARIATION_EMOJI) ||
            cluster.contains(KEYCAP) ||
            isRegionalIndicator(first) ||
            first == BLACK_FLAG ||
            hasEmojiPresentation(first)
    }

    /**
     * The region a flag cluster names, as channel titles print it: `FR`
     * for a regional-indicator pair, `GB-SCT` for a subdivision tag
     * sequence. Null for anything that is not a flag.
     */
    fun flagRegion(cluster: String): String? {
        val points = cluster.codePoints().toArray()
        if (points.size == 2 && points.all(::isRegionalIndicator)) {
            return points.joinToString("") { (it - REGIONAL_A + 'A'.code).toChar().toString() }
        }
        if (points.size >= 4 && points.first() == BLACK_FLAG && points.last() == CANCEL_TAG) {
            val tags = points.drop(1).dropLast(1)
            if (tags.all { it in TAG_LOWER_A..TAG_LOWER_Z || it in TAG_DIGIT_0..TAG_DIGIT_9 } && tags.size > 2) {
                val text = tags.joinToString("") { (it - TAG_BASE).toChar().toString() }.uppercase()
                return text.substring(0, 2) + "-" + text.substring(2)
            }
        }
        return null
    }

    private fun isRegionalIndicator(point: Int) = point in REGIONAL_A..REGIONAL_Z

    /**
     * Whether [point] is shown as an emoji with no selector: Unicode's
     * Emoji_Presentation property, exact. Pure Kotlin so the JVM tests run
     * it; `android.icu` is not on the JVM.
     */
    private fun hasEmojiPresentation(point: Int): Boolean {
        var low = 0
        var high = EMOJI_PRESENTATION.size / 2 - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            when {
                point < EMOJI_PRESENTATION[2 * mid] -> high = mid - 1
                point > EMOJI_PRESENTATION[2 * mid + 1] -> low = mid + 1
                else -> return true
            }
        }
        return false
    }

    /**
     * Emoji_Presentation as inclusive first/last pairs, ascending. Generated
     * from `Character.isEmojiPresentation` (JDK 27, Unicode 17); regenerate
     * from `emoji-data.txt` when Unicode adds emoji.
     */
    private val EMOJI_PRESENTATION = intArrayOf(
        0x231A, 0x231B, 0x23E9, 0x23EC, 0x23F0, 0x23F0, 0x23F3, 0x23F3, 0x25FD, 0x25FE, 0x2614, 0x2615,
        0x2648, 0x2653, 0x267F, 0x267F, 0x2693, 0x2693, 0x26A1, 0x26A1, 0x26AA, 0x26AB, 0x26BD, 0x26BE,
        0x26C4, 0x26C5, 0x26CE, 0x26CE, 0x26D4, 0x26D4, 0x26EA, 0x26EA, 0x26F2, 0x26F3, 0x26F5, 0x26F5,
        0x26FA, 0x26FA, 0x26FD, 0x26FD, 0x2705, 0x2705, 0x270A, 0x270B, 0x2728, 0x2728, 0x274C, 0x274C,
        0x274E, 0x274E, 0x2753, 0x2755, 0x2757, 0x2757, 0x2795, 0x2797, 0x27B0, 0x27B0, 0x27BF, 0x27BF,
        0x2B1B, 0x2B1C, 0x2B50, 0x2B50, 0x2B55, 0x2B55, 0x1F004, 0x1F004, 0x1F0CF, 0x1F0CF, 0x1F18E, 0x1F18E,
        0x1F191, 0x1F19A, 0x1F1E6, 0x1F1FF, 0x1F201, 0x1F201, 0x1F21A, 0x1F21A, 0x1F22F, 0x1F22F,
        0x1F232, 0x1F236, 0x1F238, 0x1F23A, 0x1F250, 0x1F251, 0x1F300, 0x1F320, 0x1F32D, 0x1F335,
        0x1F337, 0x1F37C, 0x1F37E, 0x1F393, 0x1F3A0, 0x1F3CA, 0x1F3CF, 0x1F3D3, 0x1F3E0, 0x1F3F0,
        0x1F3F4, 0x1F3F4, 0x1F3F8, 0x1F43E, 0x1F440, 0x1F440, 0x1F442, 0x1F4FC, 0x1F4FF, 0x1F53D,
        0x1F54B, 0x1F54E, 0x1F550, 0x1F567, 0x1F57A, 0x1F57A, 0x1F595, 0x1F596, 0x1F5A4, 0x1F5A4,
        0x1F5FB, 0x1F64F, 0x1F680, 0x1F6C5, 0x1F6CC, 0x1F6CC, 0x1F6D0, 0x1F6D2, 0x1F6D5, 0x1F6D8,
        0x1F6DC, 0x1F6DF, 0x1F6EB, 0x1F6EC, 0x1F6F4, 0x1F6FC, 0x1F7E0, 0x1F7EB, 0x1F7F0, 0x1F7F0,
        0x1F90C, 0x1F93A, 0x1F93C, 0x1F945, 0x1F947, 0x1F9FF, 0x1FA70, 0x1FA7C, 0x1FA80, 0x1FA8A,
        0x1FA8E, 0x1FAC6, 0x1FAC8, 0x1FAC8, 0x1FACD, 0x1FADC, 0x1FADF, 0x1FAEA, 0x1FAEF, 0x1FAF8,
    )

    private const val VARIATION_EMOJI = '️'
    private const val KEYCAP = '⃣'
    private const val REGIONAL_A = 0x1F1E6
    private const val REGIONAL_Z = 0x1F1FF
    private const val BLACK_FLAG = 0x1F3F4
    private const val CANCEL_TAG = 0xE007F
    private const val TAG_BASE = 0xE0000
    private const val TAG_LOWER_A = 0xE0061
    private const val TAG_LOWER_Z = 0xE007A
    private const val TAG_DIGIT_0 = 0xE0030
    private const val TAG_DIGIT_9 = 0xE0039
}
