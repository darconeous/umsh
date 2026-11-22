package com.voria.umsh.designsystem

import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/**
 * The colors and lettering an avatar or channel badge is drawn from, apart
 * from any one way of drawing it: a port of iOS `AvatarStyle`. Pure Kotlin,
 * so the JVM tests hold it to `docs/ux/src/apps/avatar-goldens.tsv`, which
 * the iOS tests read too.
 *
 * Colors are `0xRRGGBB` ints.
 */
data class AvatarStyle(
    val fill: Int,
    val whiteText: Boolean,
    /** One or two lines of glyphs, stacked. */
    val lines: List<String>,
    /** Font size as a fraction of the avatar's size. */
    val fontRatio: Float,
    /** Extra leading between the lines, as a fraction of the size; negative is tighter. */
    val lineSpacingRatio: Float,
) {
    companion object {
        /** A hint shorter than three bytes has no color of its own. */
        const val MID_GRAY = 0x808080

        /**
         * A peer's avatar: the hint's three leading bytes as the fill, the
         * core-rendered hint text two over two, and whichever of black or
         * white has the greater APCA contrast against the fill.
         */
        fun peer(hintBytes: ByteArray, hintText: String): AvatarStyle {
            val fill = rgbOf(hintBytes)
            val clusters = Graphemes.split(hintText)
            return AvatarStyle(
                fill = fill,
                whiteText = prefersWhiteText(fill),
                lines = listOf(clusters.take(2).joinToString(""), clusters.drop(2).joinToString("")),
                fontRatio = 0.30f,
                lineSpacingRatio = -0.08f,
            )
        }

        /**
         * A channel's badge. [lettering] comes from [ChannelLettering];
         * [builtinFill] is the fixed color of Public or EMERGENCY, which
         * keep white text; any other channel's fill is derived from [tint].
         */
        fun channel(lettering: List<String>, tint: ByteArray, builtinFill: Int? = null): AvatarStyle {
            val lines = if (lettering.size > 2) {
                listOf(lettering.take(2).joinToString(""), lettering.drop(2).joinToString(""))
            } else {
                listOf(lettering.joinToString(""))
            }
            val fill: Int
            val white: Boolean
            if (builtinFill != null) {
                fill = builtinFill
                white = true
            } else {
                val band = channelBand(rgbOf(tint))
                fill = band.fill
                white = band.whiteText
            }
            return AvatarStyle(
                fill = fill,
                whiteText = white,
                lines = lines,
                // A lone glyph gets the whole square; everything else
                // shares it two to a line, at one size.
                fontRatio = if (lettering.size == 1) 0.76f else 0.42f,
                lineSpacingRatio = -0.06f,
            )
        }

        /** The first three bytes as `0xRRGGBB`, or [MID_GRAY] when there are fewer. */
        fun rgbOf(bytes: ByteArray): Int = if (bytes.size < 3) {
            MID_GRAY
        } else {
            ((bytes[0].toInt() and 0xFF) shl 16) or
                ((bytes[1].toInt() and 0xFF) shl 8) or
                (bytes[2].toInt() and 0xFF)
        }

        /**
         * Whether white text has the greater APCA lightness contrast (SAPC
         * 0.0.98G) against [rgb] than black does. Never a brightness
         * threshold or the WCAG 2 ratio, which overrates black on saturated
         * mid-tones.
         */
        fun prefersWhiteText(rgb: Int): Boolean {
            val background = screenLuminance(red(rgb), green(rgb), blue(rgb))
            val white = screenLuminance(1.0, 1.0, 1.0)
            val black = screenLuminance(0.0, 0.0, 0.0)
            // Each polarity with its own exponents; scaled and offset alike,
            // so the raw magnitudes compare directly.
            val whiteContrast = max(0.0, white.pow(0.62) - background.pow(0.65))
            val blackContrast = max(0.0, background.pow(0.56) - black.pow(0.57))
            return whiteContrast > blackContrast
        }

        private fun screenLuminance(red: Double, green: Double, blue: Double): Double {
            val y = 0.2126729 * red.pow(2.4) + 0.7151522 * green.pow(2.4) + 0.0721750 * blue.pow(2.4)
            // Soft clamp near black, where the display's flare dominates.
            return if (y < 0.022) y + (0.022 - y).pow(1.414) else y
        }

        /**
         * A derived channel color moved out of the middle of the brightness
         * range: the hue kept, brightness and saturation moved into the
         * nearer of a dark band (white text) or a light band (black text),
         * each clearing 4.5:1 against its text. HSB as UIKit computes it.
         */
        fun channelBand(rgb: Int): Band {
            val r = red(rgb)
            val g = green(rgb)
            val b = blue(rgb)
            val maxC = max(r, max(g, b))
            val minC = min(r, min(g, b))
            val delta = maxC - minC
            val brightness = maxC
            val saturation = if (maxC == 0.0) 0.0 else delta / maxC
            val hue = when {
                delta == 0.0 -> 0.0
                maxC == r -> ((g - b) / delta).let { if (it < 0) it + 6 else it } / 6
                maxC == g -> ((b - r) / delta + 2) / 6
                else -> ((r - g) / delta + 4) / 6
            }
            val goesDark = brightness < 0.62
            val fill = hsbToRgb(
                hue,
                if (goesDark) min(saturation, 0.85) else min(saturation, 0.45),
                if (goesDark) 0.42 else 0.90,
            )
            return Band(fill = fill, whiteText = goesDark)
        }

        private fun hsbToRgb(hue: Double, saturation: Double, brightness: Double): Int {
            val h = (hue * 6).let { if (it >= 6) 0.0 else it }
            val sector = h.toInt()
            val f = h - sector
            val p = brightness * (1 - saturation)
            val q = brightness * (1 - saturation * f)
            val t = brightness * (1 - saturation * (1 - f))
            val (r, g, b) = when (sector) {
                0 -> Triple(brightness, t, p)
                1 -> Triple(q, brightness, p)
                2 -> Triple(p, brightness, t)
                3 -> Triple(p, q, brightness)
                4 -> Triple(t, p, brightness)
                else -> Triple(brightness, p, q)
            }
            return (octet(r) shl 16) or (octet(g) shl 8) or octet(b)
        }

        private fun octet(component: Double): Int = Math.round(component * 255).toInt().coerceIn(0, 255)

        private fun red(rgb: Int) = ((rgb shr 16) and 0xFF) / 255.0
        private fun green(rgb: Int) = ((rgb shr 8) and 0xFF) / 255.0
        private fun blue(rgb: Int) = (rgb and 0xFF) / 255.0
    }

    data class Band(val fill: Int, val whiteText: Boolean)
}
