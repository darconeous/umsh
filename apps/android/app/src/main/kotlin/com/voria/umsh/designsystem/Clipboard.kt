package com.voria.umsh.designsystem

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
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
 * app says nothing there; on 12 and earlier it shows [notice].
 */
class Copier(private val context: Context, private val copyNotice: CopyNotice) {
    fun copy(text: String, @StringRes notice: Int) {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
        clipboard.setPrimaryClip(ClipData.newPlainText(null, text))
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) copyNotice.show(notice)
    }
}

@Composable
fun rememberCopier(): Copier = Copier(LocalContext.current, LocalCopyNotice.current)
