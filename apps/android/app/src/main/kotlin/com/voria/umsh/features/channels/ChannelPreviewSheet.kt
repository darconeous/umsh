package com.voria.umsh.features.channels

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.NoticeHost

/**
 * A channel code read over a screen (`qr-scanner.svg` 4): the join preview
 * as a sheet over it, from a root's Scan or Add peer's field. Join channel
 * joins with the alias and opens the new conversation ([onJoined], with
 * its address); dismissing returns, nothing joined. [opening] tells one
 * showing from the next, so the same code read twice starts afresh. After
 * process death the sheet does not reopen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelPreviewSheet(input: String, opening: Long, onDismiss: () -> Unit, onJoined: (String) -> Unit) {
    val viewModel = runtimeViewModel(key = "channel_sheet") { ChannelJoinViewModel(RuntimeChannelJoinHost(it)) }
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val problem by viewModel.problem.collectAsStateWithLifecycle()
    val joining by viewModel.joining.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val joined by rememberUpdatedState(onJoined)
    LaunchedEffect(viewModel) {
        viewModel.joined.collect { channel -> channel.conversationAddress?.let(joined) }
    }
    LaunchedEffect(opening) {
        viewModel.edited()
        viewModel.lookUp(input)
    }
    val alias = rememberAliasDraft(preview, opening)
    // Never saved: a key shown is hidden again once the sheet is recreated.
    var keyShown by remember(opening) { mutableStateOf(false) }

    // Opened whole: a half-open sheet leaves Join channel below a short phone's edge. Held open while joining.
    val busy by rememberUpdatedState(joining)
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { it != SheetValue.Hidden || !busy },
    )
    ModalBottomSheet(
        onDismissRequest = { if (!joining) onDismiss() },
        sheetState = sheetState,
        modifier = Modifier.testTag(Tags.CHANNEL_SHEET),
    ) {
        NoticeHost(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).navigationBarsPadding().padding(bottom = 24.dp)) {
                val shown = preview
                when {
                    shown != null -> {
                        ChannelPreviewDetails(shown, keyShown, onKeyShown = { keyShown = it })
                        AliasField(alias.text, onAlias = alias::type, label = R.string.channel_alias_optional, modifier = Modifier.padding(top = 8.dp))
                        Button(
                            onClick = { viewModel.join(alias.text, openConversation = true) },
                            enabled = !joining,
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(top = 16.dp).heightIn(min = 48.dp).testTag(Tags.CHANNEL_SHEET_JOIN),
                        ) {
                            if (joining) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            } else {
                                Text(stringResource(if (shown.alreadyJoined) R.string.channel_update else R.string.join_channel))
                            }
                        }
                    }
                    problem != null -> Text(
                        stringResource(R.string.channel_input_not_channel),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.CHANNEL_JOIN_PROBLEM),
                    )
                    else -> Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                }
            }
        }
    }

    failure?.let { shownFailure ->
        val title = when (shownFailure) {
            is ChannelJoinFailure.NotLookedUp -> R.string.channel_not_looked_up_title
            is ChannelJoinFailure.NotJoined -> R.string.channel_not_joined_title
        }
        // Nothing was looked up, so there is nothing for the sheet to show: it closes with the dialog.
        FailureDialog(stringResource(title), stringResource(R.string.channel_not_joined_body), shownFailure.error) {
            viewModel.dismissFailure()
            if (shownFailure is ChannelJoinFailure.NotLookedUp) onDismiss()
        }
    }
}
