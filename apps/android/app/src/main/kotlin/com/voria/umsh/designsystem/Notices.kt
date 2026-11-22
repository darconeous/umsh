package com.voria.umsh.designsystem

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Stable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import kotlinx.coroutines.launch

/** A snackbar host's state, and the notice that shows on it. */
@Stable
class Notices(val snackbars: SnackbarHostState, val notice: CopyNotice)

@Composable
fun rememberNotices(): Notices {
    val snackbars = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val resources = LocalResources.current
    return remember(snackbars, resources) {
        Notices(snackbars, CopyNotice { message -> scope.launch { snackbars.showSnackbar(resources.getString(message)) } })
    }
}

/**
 * Brief notices for a screen outside the shell (onboarding, the
 * unavailable states, Manage space): its own snackbar host, so a copy on
 * Android 12 is still confirmed there.
 */
@Composable
fun NoticeHost(content: @Composable () -> Unit) = NoticeHost(Modifier.fillMaxSize(), content)

/**
 * Brief notices drawn where [content] is, in [modifier]'s bounds: for a
 * sheet, whose window covers the shell's snackbar host.
 */
@Composable
fun NoticeHost(modifier: Modifier, content: @Composable () -> Unit) {
    val notices = rememberNotices()
    CompositionLocalProvider(LocalCopyNotice provides notices.notice) {
        Box(modifier) {
            content()
            SnackbarHost(notices.snackbars, Modifier.align(Alignment.BottomCenter).navigationBarsPadding())
        }
    }
}
