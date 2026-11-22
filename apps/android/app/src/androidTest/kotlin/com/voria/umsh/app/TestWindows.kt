package com.voria.umsh.app

import androidx.compose.material3.adaptive.Posture
import androidx.compose.material3.adaptive.WindowAdaptiveInfo
import androidx.window.core.layout.WindowSizeClass

/**
 * Windows a test pins through `LocalWindowOverride`, so a layout test runs
 * the same whatever display, orientation or size the device has.
 */
object TestWindows {
    /** Narrower than 600 dp: the bottom bar, one page at a time. */
    val Phone = WindowAdaptiveInfo(WindowSizeClass(minWidthDp = 0, minHeightDp = 0), Posture())

    /** 840 dp and wider: the rail, and a list beside its detail. */
    val Tablet = WindowAdaptiveInfo(WindowSizeClass(minWidthDp = 840, minHeightDp = 480), Posture())
}
