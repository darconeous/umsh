package com.voria.umsh.designsystem

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalContext

/**
 * The app's theme: Material 3 dynamic color from the wallpaper (every
 * supported device, API 31 and up, has it), the fixed scale for type and
 * shape, the two color sets Material does not carry ([WarningColors],
 * [FixedColors]), and the phone's time formatter ([LocalTimeFormatting]).
 *
 * [fallbackScheme] draws with the communicator palette instead; it is the
 * debug-only `debug.fallbackScheme` switch, for screenshot runs beside the
 * drawings. There is no user-facing color choice.
 */
@Composable
fun UmshTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    fallbackScheme: Boolean = false,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colors = when {
        fallbackScheme -> if (darkTheme) FallbackDarkScheme else FallbackLightScheme
        darkTheme -> dynamicDarkColorScheme(context)
        else -> dynamicLightColorScheme(context)
    }
    CompositionLocalProvider(
        LocalWarningColors provides if (darkTheme) WarningDark else WarningLight,
        LocalFixedColors provides if (darkTheme) FixedDark else FixedLight,
    ) {
        MaterialTheme(
            colorScheme = colors,
            typography = UmshTypography,
            shapes = UmshShapes,
        ) {
            ProvideTimeFormatting(content)
        }
    }
}

/** The app's colors beyond Material's roles. */
object UmshColors {
    val warning: WarningColors
        @Composable get() = LocalWarningColors.current

    val fixed: FixedColors
        @Composable get() = LocalFixedColors.current
}
