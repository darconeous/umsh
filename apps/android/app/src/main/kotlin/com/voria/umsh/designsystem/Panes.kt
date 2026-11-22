package com.voria.umsh.designsystem

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.adaptive.WindowAdaptiveInfo
import androidx.compose.material3.adaptive.currentWindowAdaptiveInfoV2
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.window.core.layout.WindowSizeClass

/**
 * The window the layout is chosen for: the real one, unless a test pins
 * one (a phone, or a tablet) so it runs the same on any display.
 */
val LocalWindowOverride = staticCompositionLocalOf<WindowAdaptiveInfo?> { null }

/** Every layout decision reads the window here: the rail, the panes and the scene strategy alike. */
@Composable
fun windowAdaptiveInfo(): WindowAdaptiveInfo = LocalWindowOverride.current ?: currentWindowAdaptiveInfoV2()

/** The window is wide enough for a rail (600 dp and up). */
@Composable
fun isRailLayout(): Boolean =
    windowAdaptiveInfo().windowSizeClass.isWidthAtLeastBreakpoint(WindowSizeClass.WIDTH_DP_MEDIUM_LOWER_BOUND)

/** The window is wide enough for a list and its detail side by side (840 dp and up). */
@Composable
fun isTwoPaneLayout(): Boolean =
    windowAdaptiveInfo().windowSizeClass.isWidthAtLeastBreakpoint(WindowSizeClass.WIDTH_DP_EXPANDED_LOWER_BOUND)

/**
 * A detail page: beside a list it is a surface-container-low card
 * (`list-detail.svg` board 1); alone it fills the screen.
 */
@Composable
fun DetailPane(content: @Composable () -> Unit) {
    if (!isTwoPaneLayout()) {
        content()
        return
    }
    // The card starts below the status bar; its own top bar then adds none.
    Box(
        Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
            .padding(end = 16.dp, top = 8.dp, bottom = 16.dp),
    ) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerLow,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxSize(),
        ) {
            CompositionLocalProvider(LocalInDetailCard provides true, content = content)
        }
    }
}

/** True inside [DetailPane]'s card: screens draw no background of their own there. */
val LocalInDetailCard = compositionLocalOf { false }

/** The color behind a page's content: the card's beside a list, else the window's. */
@Composable
fun pageColor(): Color =
    if (LocalInDetailCard.current) MaterialTheme.colorScheme.surfaceContainerLow else MaterialTheme.colorScheme.background
