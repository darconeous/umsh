package com.voria.umsh.features.scanner

import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.features.channels.ChannelPreviewSheet
import com.voria.umsh.features.peers.AddPeerExit
import com.voria.umsh.features.peers.AddPeerViewModel
import com.voria.umsh.features.peers.ImportPreviewSheet
import com.voria.umsh.features.peers.RuntimeImportHost

/** Whether this phone has a camera to scan with ([LocalCameraPresence]). */
@Composable
fun hasCamera(): Boolean {
    val context = LocalContext.current
    val presence = LocalCameraPresence.current
    return remember(context, presence) { presence.hasCamera(context) }
}

/** Scan in a root's top app bar (`navigation.svg`): the QR scanner. Nothing without a camera (§3.9). */
@Composable
fun ScanAction(onScan: () -> Unit, modifier: Modifier = Modifier) {
    if (!hasCamera()) return
    IconButton(onClick = onScan, modifier = modifier) {
        Icon(painterResource(R.drawable.ic_qr_code), contentDescription = stringResource(R.string.action_scan))
    }
}

/** A code the scanner read for this page: [text], and [onTaken] to say it has been taken, once. */
@Immutable
class ScannedCode(val text: String, val onTaken: () -> Unit)

/**
 * The preview of a code scanned from a root, as a sheet over the root: a
 * node's import preview (`qr-scanner.svg` 3), as Add peer's, or a
 * channel's join preview (board 4). A node already saved, or this phone,
 * opens its page or Your identity instead; [onExit] takes Save peer's page,
 * Message's conversation, a joined channel's conversation, or those.
 * Dismissing returns to the root. After process death the sheet does not
 * reopen.
 */
@Composable
fun ScannedCodePreview(scanned: ScannedCode?, onExit: (AddPeerExit) -> Unit) {
    val viewModel = runtimeViewModel(key = "scanned_code") { AddPeerViewModel(RuntimeImportHost(it)) }
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val exit by rememberUpdatedState(onExit)
    LaunchedEffect(viewModel) { viewModel.exits.collect { exit(it) } }
    val current by rememberUpdatedState(scanned)
    LaunchedEffect(scanned?.text) {
        current?.let { code ->
            code.onTaken()
            viewModel.preview(code.text)
        }
    }
    preview?.let { ImportPreviewSheet(it, viewModel) }
    val channel by viewModel.channel.collectAsStateWithLifecycle()
    channel?.let { opening ->
        ChannelPreviewSheet(
            opening.input,
            opening.opening,
            onDismiss = viewModel::closeChannel,
            onJoined = { address ->
                viewModel.closeChannel()
                exit(AddPeerExit.Conversation(address))
            },
        )
    }
}
