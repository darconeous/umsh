package com.voria.umsh.features.settings

import android.text.format.Formatter
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.EraseMode
import com.voria.umsh.app.StorageSummary
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.EraseIdentityDialog
import com.voria.umsh.designsystem.EraseFailureDialog
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar

/** Which confirmation is open: Start over asks twice, Cancel the default on both. */
private object Asking {
    const val NONE = 0
    const val ERASE_IDENTITY = 1
    const val START_OVER = 2
    const val START_OVER_AGAIN = 3
}

/**
 * UMSH storage (`manage-space.svg` boards 2–4): the identity at stake, what
 * uses the space, Erase identity and Start over. While staging is on, the
 * erasures are left out (D16).
 */
@Composable
fun ManageSpaceScreen(viewModel: ManageSpaceViewModel, onBack: () -> Unit) {
    val summary by viewModel.summary.collectAsStateWithLifecycle()
    val erasing by viewModel.erasing.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    var asking by rememberSaveable { mutableIntStateOf(Asking.NONE) }

    UmshScaffold(
        topBar = { UmshTopAppBar(stringResource(R.string.manage_space_title), onBack = onBack) },
        modifier = Modifier.testTag(Tags.MANAGE_SPACE),
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            summary?.let { shown ->
                Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState())) {
                    ManageSpaceContent(shown, erasing, onAsk = { asking = it })
                }
            }
        }
    }

    when (asking) {
        Asking.ERASE_IDENTITY -> EraseIdentityDialog(
            onConfirm = {
                asking = Asking.NONE
                viewModel.erase(EraseMode.IdentityOnly)
            },
            onDismiss = { asking = Asking.NONE },
        )
        Asking.START_OVER -> ConfirmDialog(
            title = stringResource(R.string.start_over_title),
            body = stringResource(R.string.start_over_body),
            confirm = stringResource(R.string.start_over_confirm),
            onConfirm = { asking = Asking.START_OVER_AGAIN },
            onDismiss = { asking = Asking.NONE },
        )
        Asking.START_OVER_AGAIN -> ConfirmDialog(
            title = stringResource(R.string.start_over_again_title),
            body = stringResource(R.string.start_over_again_body),
            confirm = stringResource(R.string.start_over_confirm),
            onConfirm = {
                asking = Asking.NONE
                viewModel.erase(EraseMode.Everything)
            },
            onDismiss = { asking = Asking.NONE },
        )
    }
    failure?.let { outcome -> EraseFailureDialog(outcome, onDismiss = viewModel::dismissFailure) }
}

@Composable
private fun ManageSpaceContent(summary: StorageSummary, erasing: Boolean, onAsk: (Int) -> Unit) {
    val context = LocalContext.current
    val transparent = ListItemDefaults.colors(containerColor = Color.Transparent)
    summary.identity?.let { identity ->
        ListItem(
            headlineContent = { Text(identity.name.ifEmpty { stringResource(R.string.your_identity) }) },
            supportingContent = if (identity.name.isNotEmpty()) {
                { Text(stringResource(R.string.your_identity)) }
            } else {
                null
            },
            leadingContent = { PeerAvatar(identity.hint, PeerAvatarShape.Circle, describe = false) },
            colors = transparent,
            modifier = Modifier.testTag(Tags.MANAGE_SPACE_IDENTITY),
        )
    }
    SectionHeader(stringResource(R.string.space_used))
    ListItem(
        headlineContent = { Text(stringResource(R.string.space_messages)) },
        trailingContent = { Text(Formatter.formatShortFileSize(context, summary.contentBytes)) },
        colors = transparent,
        modifier = Modifier.testTag(Tags.MANAGE_SPACE_MESSAGES),
    )
    ListItem(
        headlineContent = { Text(stringResource(R.string.space_keys)) },
        trailingContent = { Text(Formatter.formatShortFileSize(context, summary.keyBytes)) },
        colors = transparent,
        modifier = Modifier.testTag(Tags.MANAGE_SPACE_KEYS),
    )
    if (summary.stagingOn) return
    if (summary.identityStored) {
        DestructiveRow(
            stringResource(R.string.erase_identity),
            stringResource(R.string.erase_identity_detail),
            enabled = !erasing,
            tag = Tags.MANAGE_SPACE_ERASE,
        ) { onAsk(Asking.ERASE_IDENTITY) }
    }
    DestructiveRow(
        stringResource(R.string.start_over),
        stringResource(R.string.start_over_detail),
        enabled = !erasing,
        tag = Tags.MANAGE_SPACE_START_OVER,
    ) { onAsk(Asking.START_OVER) }
}

@Composable
private fun DestructiveRow(title: String, detail: String, enabled: Boolean, tag: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title, color = MaterialTheme.colorScheme.error) },
        supportingContent = { Text(detail) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .padding(top = 8.dp)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .testTag(tag),
    )
}
