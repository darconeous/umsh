package com.voria.umsh.designsystem

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext

/**
 * Shows a brief notice (a snackbar) after a copy. The shell provides one
 * over its snackbar host; the default does nothing.
 */
fun interface CopyNotice {
    fun show(@StringRes message: Int)
}

val LocalCopyNotice = staticCompositionLocalOf { CopyNotice { } }

/**
 * Copies [text]. Android 13 and later confirm a copy themselves, so the
 * app says nothing there; on 12 and earlier it shows [notice]. A
 * [sensitive] copy (a private channel's invitation, which is its key) is
 * marked so the system's copy preview hides it; 12 has no constant for it,
 * but some keyboards read the same extra.
 */
class Copier(private val context: Context, private val copyNotice: CopyNotice) {
    fun copy(text: String, @StringRes notice: Int, sensitive: Boolean = false) {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
        clipboard.setPrimaryClip(clip(text, sensitive))
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) copyNotice.show(notice)
    }

    companion object {
        /** The clip [copy] sets. */
        fun clip(text: String, sensitive: Boolean): ClipData = ClipData.newPlainText(null, text).apply {
            if (sensitive) description.extras = PersistableBundle().apply { putBoolean(SENSITIVE_EXTRA, true) }
        }

        /** `ClipDescription.EXTRA_IS_SENSITIVE`, which 13 names; the same key on 12. */
        val SENSITIVE_EXTRA: String =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
    }
}

/** One [Copier] per context and notice, so a handler that captures it stays the same across recompositions. */
@Composable
fun rememberCopier(): Copier {
    val context = LocalContext.current
    val notice = LocalCopyNotice.current
    return remember(context, notice) { Copier(context, notice) }
}
