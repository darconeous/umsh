package com.voria.umsh.designsystem

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * How long the UI waits before offering something again: UX timing, kept
 * equal to iOS. Provided so a connected test can shorten it rather than
 * wait it out. The core's own waits (a ping's timeout, Discover's cooldown)
 * are not here and stay real.
 */
@Immutable
data class UiTimings(
    /** How long a ping waits before a new one, replacing it, is offered (iOS `PingSheet.sendAgainAfter`). */
    val pingAgainAfterMs: Long = 8_000L,
)

val LocalUiTimings = staticCompositionLocalOf { UiTimings() }
