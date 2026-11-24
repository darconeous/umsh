package com.voria.umsh.features.peers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.features.channels.ChannelKeyText

/**
 * The import preview for an opened link that names no node
 * (product-structure, "Deep links" 2.1): a sheet over whatever was showing,
 * with the link in Add peer's field and what is wrong with it under it, as
 * Add peer reports a bad link (`add-peer.svg` 2). The link can be corrected
 * there; Preview then opens the import preview proper (boards 3–4), with
 * the same rules as Add peer. [link] is the link's text, and null when no
 * sheet shows, and [opening] which opening of it this is: the same link
 * opened again starts over, from the link and what is wrong with it;
 * [onExit] takes a page, a conversation or Your identity, and [onChannel]
 * a link corrected into a channel's; dismissing
 * ([onDismiss]) returns to what was showing, nothing stored.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LinkImportSheet(link: String?, opening: Long, onDismiss: () -> Unit, onExit: (AddPeerExit) -> Unit, onChannel: (String) -> Unit) {
    // The shell's store: the sheet and its preview survive a rotation.
    val viewModel = runtimeViewModel(key = "link_import") { AddPeerViewModel(RuntimeImportHost(it)) }
    val problem by viewModel.problem.collectAsStateWithLifecycle()
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val exit by rememberUpdatedState(onExit)
    val dismiss by rememberUpdatedState(onDismiss)
    val channel by rememberUpdatedState(onChannel)
    LaunchedEffect(viewModel) {
        viewModel.exits.collect {
            exit(it)
            dismiss()
        }
    }
    // Corrected into a channel link: a channel link's own way, Join channel in Settings.
    LaunchedEffect(viewModel) {
        viewModel.channel.collect { opening ->
            if (opening != null) {
                viewModel.closeChannel()
                dismiss()
                channel(opening.input)
            }
        }
    }
    if (link == null) return

    // A correction may be a channel invitation: its key stays out of saved state (§3.8).
    var input by rememberSaveable(opening, stateSaver = ChannelKeyText.FieldSaver) { mutableStateOf(link) }
    // Read once per opening, not again after a rotation: the line describes
    // what the field held when it was last previewed.
    var read by rememberSaveable(opening) { mutableStateOf(false) }
    LaunchedEffect(opening) {
        if (!read) {
            read = true
            viewModel.dismissPreview()
            viewModel.preview(link)
        }
    }
    val keyboard = LocalSoftwareKeyboardController.current
    val runPreview = {
        keyboard?.hide()
        viewModel.preview(input)
    }

    val shown = preview
    if (shown != null) {
        ImportPreviewSheet(shown, viewModel)
        return
    }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.testTag(Tags.LINK_IMPORT_SHEET),
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp)
                .navigationBarsPadding()
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.add_peer),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(horizontal = 24.dp).semantics { heading() },
            )
            IdentityField(
                input = input,
                problem = problem,
                onInput = {
                    input = it
                    viewModel.edited()
                },
                onGo = runPreview,
                onScan = null,
            )
            FilledTonalButton(
                onClick = runPreview,
                enabled = input.isNotBlank(),
                modifier = Modifier.padding(horizontal = 16.dp).testTag(Tags.ADD_PEER_PREVIEW),
            ) {
                Text(stringResource(R.string.add_peer_preview))
            }
        }
    }
}
