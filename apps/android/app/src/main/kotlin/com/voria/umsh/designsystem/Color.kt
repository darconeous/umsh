package com.voria.umsh.designsystem

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/*
 * The fallback scheme: the communicator palette mapped onto Material 3 roles
 * (`design-language.svg` boards 1 and 2). Chrome normally takes dynamic
 * color; this scheme is for previews, screenshot runs and the drawings.
 *
 * The boards give the surface container lowest, low and high steps for
 * neither appearance; they sit between the steps the boards do give.
 */

val FallbackLightScheme: ColorScheme = lightColorScheme(
    primary = Color(0xFF2A62C9),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD6E6FF),
    onPrimaryContainer = Color(0xFF0B2F66),
    inversePrimary = Color(0xFF4DA3FF),
    secondary = Color(0xFF4A5F80),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD9E5F7),
    onSecondaryContainer = Color(0xFF142A4A),
    tertiary = Color(0xFF7045CC),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFEBE2FF),
    onTertiaryContainer = Color(0xFF2A1270),
    error = Color(0xFFC4291E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFE1DD),
    onErrorContainer = Color(0xFF7A120B),
    background = Color(0xFFF7F9FC),
    onBackground = Color(0xFF14181D),
    surface = Color(0xFFF7F9FC),
    onSurface = Color(0xFF14181D),
    surfaceVariant = Color(0xFFDFE4EA),
    onSurfaceVariant = Color(0xFF4A535E),
    surfaceTint = Color(0xFF2A62C9),
    inverseSurface = Color(0xFF2A2F36),
    inverseOnSurface = Color(0xFFEEF1F5),
    outline = Color(0xFF737D89),
    outlineVariant = Color(0xFFC4CBD4),
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFFF7F9FC),
    surfaceDim = Color(0xFFD7DCE3),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF1F4F8),
    surfaceContainer = Color(0xFFEBEFF4),
    surfaceContainerHigh = Color(0xFFE5E9EF),
    surfaceContainerHighest = Color(0xFFDFE4EA),
)

val FallbackDarkScheme: ColorScheme = darkColorScheme(
    primary = Color(0xFF4DA3FF),
    onPrimary = Color(0xFF00213F),
    primaryContainer = Color(0xFF2A62C9),
    onPrimaryContainer = Color(0xFFE4EDFF),
    inversePrimary = Color(0xFF2A62C9),
    secondary = Color(0xFFA9C2E6),
    onSecondary = Color(0xFF0E2340),
    secondaryContainer = Color(0xFF18304D),
    onSecondaryContainer = Color(0xFFCFE0FF),
    tertiary = Color(0xFFA585FF),
    onTertiary = Color(0xFF240C5C),
    tertiaryContainer = Color(0xFF7045CC),
    onTertiaryContainer = Color(0xFFECE4FF),
    error = Color(0xFFFF6B5E),
    onError = Color(0xFF3D0703),
    errorContainer = Color(0xFF3A1412),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0E1115),
    onBackground = Color(0xFFEEF1F5),
    surface = Color(0xFF0E1115),
    onSurface = Color(0xFFEEF1F5),
    surfaceVariant = Color(0xFF23272E),
    onSurfaceVariant = Color(0xFF9AA3AE),
    surfaceTint = Color(0xFF4DA3FF),
    inverseSurface = Color(0xFFEEF1F5),
    inverseOnSurface = Color(0xFF23272E),
    outline = Color(0xFF7F8995),
    outlineVariant = Color(0xFF2E3540),
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFF2A2F36),
    surfaceDim = Color(0xFF0E1115),
    surfaceContainerLowest = Color(0xFF0A0C10),
    surfaceContainerLow = Color(0xFF12151A),
    surfaceContainer = Color(0xFF161A20),
    surfaceContainerHigh = Color(0xFF1D2127),
    surfaceContainerHighest = Color(0xFF23272E),
)

/**
 * The role Material 3 lacks: a container for attention banners (no radio,
 * disconnected, Bluetooth off, a permission), in the communicator's amber.
 * Fixed for now under dynamic color too; harmonizing it toward the
 * wallpaper comes later (design.md D10).
 */
@Immutable
data class WarningColors(val container: Color, val onContainer: Color)

val WarningLight = WarningColors(container = Color(0xFFFFE9C2), onContainer = Color(0xFF4A3000))
val WarningDark = WarningColors(container = Color(0xFF3A2A0E), onContainer = Color(0xFFFFE2B0))

/**
 * Colors never taken from the theme (`design-language.svg` board 3): the
 * same under dynamic color, and in both appearances apart from the two
 * standard channels, which follow iOS's system blue and red.
 */
@Immutable
data class FixedColors(
    val publicChannel: Color,
    val emergencyChannel: Color,
) {
    /** A sent bubble, the send button and the composer's cursor, by who can read the message. */
    fun sent(security: MessageSecurity): Color = when (security) {
        MessageSecurity.Encrypted -> SentEncrypted
        MessageSecurity.Open -> SentOpen
        MessageSecurity.ForwardSecret -> SentForwardSecret
    }

    /** Text on any of the [sent] colors. */
    val onSent: Color get() = Color.White

    /** The favorite star beside an avatar. */
    val favoriteStar: Color get() = FavoriteStar

    companion object {
        val SentEncrypted = Color(0xFF2A62C9)
        val SentOpen = Color(0xFF1E7B45)
        val SentForwardSecret = Color(0xFF7045CC)
        val FavoriteStar = Color(0xFFF4B400)
    }
}

/** Who can read a message: decides a sent bubble's color. */
enum class MessageSecurity {
    /** A direct message or a private channel. */
    Encrypted,

    /** A channel anyone can read. */
    Open,

    /** Sent under a forward-secret session. */
    ForwardSecret,
}

val FixedLight = FixedColors(publicChannel = Color(0xFF007AFF), emergencyChannel = Color(0xFFFF3B30))
val FixedDark = FixedColors(publicChannel = Color(0xFF0A84FF), emergencyChannel = Color(0xFFFF453A))

val LocalWarningColors = staticCompositionLocalOf { WarningLight }
val LocalFixedColors = staticCompositionLocalOf { FixedLight }
