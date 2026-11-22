package com.voria.umsh.designsystem

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.sp

/*
 * Type (`design-language.svg` board 4): the system sans at the Material 3
 * scale, in sp so it follows the font-scale setting. No bundled face.
 *
 *   Headline small  24/32  full-screen states
 *   Title large     22/28  top app bar title
 *   Title medium    16/24  pane and sheet titles
 *   Title small     14/20  banner title
 *   Body large      16/24  list headline, message text
 *   Body medium     14/20  supporting text
 *   Body small      12/16  banner detail
 *   Label large     14/20  buttons
 *   Label medium    12/16  navigation labels
 *   Label small     11/16  badge counts
 *
 * The Material 3 baseline is exactly this scale; it is spelled out so a
 * library default changing cannot move it.
 */
private val Baseline = Typography()

/*
 * Every style takes its paragraph direction from the text it sets, as
 * Android's own views do (first strong character): a message, a name or a
 * draft in one script reads in its own direction whatever the UI's
 * language. Compose's default is the layout's direction instead.
 */
private fun TextStyle.contentDirection() = copy(textDirection = TextDirection.Content)

val UmshTypography = Typography(
    headlineSmall = Baseline.headlineSmall.copy(fontSize = 24.sp, lineHeight = 32.sp).contentDirection(),
    titleLarge = Baseline.titleLarge.copy(fontSize = 22.sp, lineHeight = 28.sp).contentDirection(),
    titleMedium = Baseline.titleMedium.copy(fontSize = 16.sp, lineHeight = 24.sp).contentDirection(),
    titleSmall = Baseline.titleSmall.copy(fontSize = 14.sp, lineHeight = 20.sp).contentDirection(),
    bodyLarge = Baseline.bodyLarge.copy(fontSize = 16.sp, lineHeight = 24.sp).contentDirection(),
    bodyMedium = Baseline.bodyMedium.copy(fontSize = 14.sp, lineHeight = 20.sp).contentDirection(),
    bodySmall = Baseline.bodySmall.copy(fontSize = 12.sp, lineHeight = 16.sp).contentDirection(),
    labelLarge = Baseline.labelLarge.copy(fontSize = 14.sp, lineHeight = 20.sp).contentDirection(),
    labelMedium = Baseline.labelMedium.copy(fontSize = 12.sp, lineHeight = 16.sp).contentDirection(),
    labelSmall = Baseline.labelSmall.copy(fontSize = 11.sp, lineHeight = 16.sp).contentDirection(),
)

/** Addresses, hints and hex: the system monospace, 13/20. Never truncated. */
val IdentifierTextStyle = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontWeight = FontWeight.Normal,
    fontSize = 13.sp,
    lineHeight = 20.sp,
)
