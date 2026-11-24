package com.voria.umsh.designsystem

import androidx.annotation.DrawableRes
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScaffoldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.app.Tags

/** The text action at the end of a full-screen dialog's bar: Save, Done, Add. */
data class DialogAction(
    val label: String,
    val enabled: Boolean,
    val tag: String,
    /** Shown as a spinner, described by [busyDescription], while the action runs. */
    val busy: Boolean = false,
    val busyDescription: String? = null,
    val onClick: () -> Unit,
)

/**
 * A full-screen dialog (Material's, batch 1's full-screen editors): the
 * leading icon closes it ([navigationIcon], Close for the dialog itself,
 * Back for a page inside it), the title, the confirming text action, then
 * the radio control at the very end. The content's padding includes the
 * keyboard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScreenDialogScaffold(
    title: String,
    @DrawableRes navigationIcon: Int,
    navigationDescription: String,
    onNavigate: () -> Unit,
    action: DialogAction?,
    modifier: Modifier = Modifier,
    content: @Composable (PaddingValues) -> Unit,
) {
    val radioControl = LocalTopBarRadioControl.current
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    IconButton(onClick = onNavigate, modifier = Modifier.testTag(Tags.DIALOG_CLOSE)) {
                        Icon(painterResource(navigationIcon), contentDescription = navigationDescription)
                    }
                },
                actions = {
                    if (action != null) {
                        if (action.busy) {
                            Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                                CircularProgressIndicator(
                                    Modifier.size(24.dp).semantics { action.busyDescription?.let { stateDescription = it } },
                                    strokeWidth = 2.dp,
                                )
                            }
                        } else {
                            TextButton(onClick = action.onClick, enabled = action.enabled, modifier = Modifier.testTag(action.tag)) {
                                Text(action.label, style = MaterialTheme.typography.labelLarge)
                            }
                        }
                    }
                    radioControl?.let {
                        it()
                        Spacer(Modifier.width(8.dp))
                    }
                },
                modifier = Modifier.testTag(Tags.TOP_APP_BAR),
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
        // Edge to edge, the keyboard does not resize the window: the content
        // ends above it, so a field's results can scroll into view.
        contentWindowInsets = ScaffoldDefaults.contentWindowInsets.union(WindowInsets.ime),
        content = content,
    )
}
