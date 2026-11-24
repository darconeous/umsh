package com.voria.umsh.features.share

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog

/**
 * Share for a peer (`share.svg` 1–2), from its page's top bar and its row's
 * long press: the same sheet as Your identity's code, headed by the node's
 * avatar and [name]. The link is the bare `umsh:n:` address (D4): this
 * phone keeps no node's signed details to pass on.
 */
@Composable
fun PeerShareSheet(peer: PeerSummary, name: String, onDismiss: () -> Unit) {
    val link = remember(peer.address) {
        try {
            nodeUriForAddress(peer.address)
        } catch (error: MobileException) {
            AppLog.w("umsh.share", "no link for a stored address: ${error.javaClass.simpleName}")
            null
        }
    }
    ShareSheet(
        address = peer.address,
        link = link,
        qrDescription = stringResource(R.string.peer_qr_description, userIsolated(name)),
        onDismiss = onDismiss,
        header = {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                PeerAvatar(peer, size = AvatarSize.TopBar, describe = false)
                Text(name, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        },
    )
}
