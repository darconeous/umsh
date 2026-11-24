package com.voria.umsh.designsystem

import android.content.ClipboardManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** A sensitive copy reaches the system clipboard with the sensitive extra; an ordinary one without it. */
class CopierTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private fun copiedAs(text: String, sensitive: Boolean): Pair<String?, Boolean> {
        var read: String? = null
        var marked = false
        compose.runOnUiThread {
            val activity = compose.activity
            Copier(activity) { }.copy(text, R.string.invitation_copied, sensitive)
            val clipboard = activity.getSystemService(ClipboardManager::class.java)
            read = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            marked = clipboard.primaryClipDescription?.extras?.getBoolean(Copier.SENSITIVE_EXTRA) == true
        }
        return read to marked
    }

    @Test
    fun aSensitiveCopyCarriesTheExtra() {
        val (text, marked) = copiedAs("umsh:gk:secret", sensitive = true)
        android.util.Log.i("CopierTest", "sensitive extra=$marked api=${android.os.Build.VERSION.SDK_INT} key=${Copier.SENSITIVE_EXTRA}")
        assertEquals("umsh:gk:secret", text)
        assertTrue(marked)
        assertEquals("android.content.extra.IS_SENSITIVE", Copier.SENSITIVE_EXTRA)
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    @Test
    fun anOrdinaryCopyDoesNot() {
        val (text, marked) = copiedAs("umsh:c:hike-club", sensitive = false)
        assertEquals("umsh:c:hike-club", text)
        assertFalse(marked)
    }
}
