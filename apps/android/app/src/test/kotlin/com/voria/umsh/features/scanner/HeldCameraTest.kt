package com.voria.umsh.features.scanner

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The scanner's latch for a camera another app holds: CameraX's retries keep it; only opening or failing ends it. */
class HeldCameraTest {
    private fun after(vararg statuses: CameraStatus): Boolean = statuses.fold(false, ::stillHeld)

    @Test
    fun inUseSetsIt() {
        assertTrue(after(CameraStatus.InUse))
    }

    @Test
    fun openingAloneNeverSetsIt() {
        assertFalse(after(CameraStatus.Opening, CameraStatus.Opening))
    }

    @Test
    fun retriesThroughOpeningKeepIt() {
        assertTrue(after(CameraStatus.InUse, CameraStatus.Opening, CameraStatus.InUse, CameraStatus.Opening))
    }

    @Test
    fun openingOrFailingClearsIt() {
        assertFalse(after(CameraStatus.InUse, CameraStatus.Opening, CameraStatus.Open(hasFlash = true)))
        assertFalse(after(CameraStatus.InUse, CameraStatus.Unavailable))
        assertFalse(after(CameraStatus.InUse, CameraStatus.AccessOff))
    }
}
