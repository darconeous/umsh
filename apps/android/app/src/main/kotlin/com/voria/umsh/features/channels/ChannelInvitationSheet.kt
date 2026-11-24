package com.voria.umsh.features.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.features.share.ShareCopy
import com.voria.umsh.features.share.ShareSheet
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary

/**
 * A channel's Share (`channels.svg` 13): a private channel's invitation,
 * which is its key, with its warning first, then the code, Copy
 * invitation (marked sensitive) and Share; a public channel's name link,
 * with no warning. The core makes [link]; the app never keeps it.
 */
@Composable
fun ChannelInvitationSheet(channel: ChannelSummary, link: String, onDismiss: () -> Unit) {
    val title = channelTitle(channel)
    val secret = channel.kind == ChannelKind.PrivateKey
    ShareSheet(
        address = null,
        link = link,
        qrDescription = stringResource(
            if (secret) R.string.channel_invitation_qr_description else R.string.channel_link_qr_description,
            userIsolated(title),
        ),
        onDismiss = onDismiss,
        header = {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.semantics(mergeDescendants = true) {}) {
                Text(title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center, modifier = Modifier.semantics { heading() })
                Text(
                    stringResource(if (secret) R.string.channel_preview_private else R.string.channel_preview_public),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(Tags.CHANNEL_SHARE_KIND),
                )
            }
        },
        copy = if (secret) ShareCopy.Invitation else ShareCopy.Link,
        notice = if (secret) {
            { InvitationWarning(title) }
        } else {
            null
        },
    )
}

/** Anyone holding the invitation is a full member, and can pass it on. */
@Composable
private fun InvitationWarning(title: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.shapes.medium)
            .padding(12.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.CHANNEL_SHARE_WARNING),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            painterResource(R.drawable.ic_warning),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onTertiaryContainer,
            modifier = Modifier.size(20.dp),
        )
        Text(
            stringResource(R.string.channel_invitation_warning, userIsolated(title)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onTertiaryContainer,
        )
    }
}
