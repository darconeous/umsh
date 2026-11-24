package com.voria.umsh.features.channels

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileWellKnownChannel
import com.voria.umsh.core.wellKnownChannel
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.designsystem.wordAndIdentifierStringResource
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary

/** A channel's kind, under its name: Built-in, Public (joined by name) or Private. */
@StringRes
fun kindLabel(channel: ChannelSummary): Int = when (channel.kind) {
    ChannelKind.Builtin -> R.string.channel_kind_builtin
    ChannelKind.Named -> R.string.channel_kind_named
    ChannelKind.PrivateKey -> R.string.channel_kind_private
}

/** "Private · 9c41": the kind, then the identifier. */
@Composable
fun kindAndIdentifier(channel: ChannelSummary): AnnotatedString =
    wordAndIdentifierStringResource(R.string.channel_kind_identifier, stringResource(kindLabel(channel)), channel.channelIdHex)

/**
 * One channel (`channels.svg` 1, `new-channel-chat.svg` 1): its badge,
 * title, kind and identifier, and the bell when it does not notify.
 * Merged for TalkBack; the caller adds the click.
 */
@Composable
fun ChannelRowContent(channel: ChannelSummary, modifier: Modifier = Modifier) {
    ListItem(
        headlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(channelTitle(channel), maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (!channel.notificationsEnabled) {
                    Icon(
                        painterResource(R.drawable.ic_notifications_off),
                        contentDescription = stringResource(R.string.row_muted),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 4.dp).size(16.dp).testTag(Tags.ROW_MUTED),
                    )
                }
            }
        },
        supportingContent = { Text(kindAndIdentifier(channel), maxLines = 1, overflow = TextOverflow.Ellipsis) },
        leadingContent = { ChannelBadge(channel, describe = false) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = modifier,
    )
}

/** How a channel works, where the protocol decides it (`channels.svg` 11); none for other channels. */
@Composable
fun channelStatements(channel: ChannelSummary): List<String> = when (wellKnownChannel(channel.canonicalName)?.channel) {
    MobileWellKnownChannel.PUBLIC -> listOf(
        stringResource(R.string.channel_public_identified),
        stringResource(R.string.channel_public_group_only),
    )
    MobileWellKnownChannel.EMERGENCY -> listOf(
        stringResource(R.string.channel_emergency_unencrypted),
        stringResource(R.string.channel_emergency_signed),
        stringResource(R.string.channel_emergency_priority),
    )
    null -> emptyList()
}

/**
 * Leave "Fire"? (`channels.svg` 12): a private channel's key goes with it;
 * any other can be joined again by its name. Either way its messages go.
 */
@Composable
fun LeaveChannelDialog(channel: ChannelSummary, onConfirm: () -> Unit, onDismiss: () -> Unit) = ConfirmDialog(
    title = stringResource(R.string.leave_channel_title, userIsolated(channelTitle(channel))),
    body = stringResource(
        if (channel.kind == ChannelKind.PrivateKey) R.string.leave_channel_private_body else R.string.leave_channel_named_body,
    ),
    confirm = stringResource(R.string.leave_channel),
    onConfirm = onConfirm,
    onDismiss = onDismiss,
)
