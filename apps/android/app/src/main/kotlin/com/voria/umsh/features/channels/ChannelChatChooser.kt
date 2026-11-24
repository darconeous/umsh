package com.voria.umsh.features.channels

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.models.ChannelSummary

/**
 * New channel chat (`new-channel-chat.svg` 1–3): a sheet of the joined
 * channels that have no conversation yet, drawn as in Settings › Channels;
 * tapping one starts its conversation ([onOpen]). With none left, one line
 * says so. Join a channel… opens Join channel, whose join opens the
 * conversation ([onJoin]). Swiping the sheet down or Back closes it
 * without starting anything. A long list scrolls in the sheet, which grows
 * to full height.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelChatChooser(channels: List<ChannelSummary>, onOpen: (ChannelSummary) -> Unit, onJoin: () -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(Tags.CHANNEL_CHOOSER)) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(bottom = 16.dp)) {
            Text(
                stringResource(R.string.new_channel_chat),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp).semantics { heading() },
            )
            if (channels.isEmpty()) {
                Text(
                    stringResource(R.string.channel_chooser_none),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp).testTag(Tags.CHANNEL_CHOOSER_NONE),
                )
            } else {
                LazyColumn(Modifier.weight(1f, fill = false)) {
                    items(channels, key = { it.id }) { channel ->
                        ChannelRowContent(
                            channel,
                            modifier = Modifier
                                .clickable(role = Role.Button) { onOpen(channel) }
                                .padding(horizontal = 8.dp)
                                .semantics(mergeDescendants = true) {}
                                .testTag(Tags.chooserChannel(channel.id)),
                        )
                    }
                }
            }
            HorizontalDivider(Modifier.padding(horizontal = 24.dp, vertical = 4.dp))
            ListItem(
                headlineContent = { Text(stringResource(R.string.join_a_channel)) },
                // Decorative: the label names the action.
                leadingContent = { Icon(painterResource(R.drawable.ic_add), contentDescription = null) },
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                modifier = Modifier
                    .heightIn(min = 56.dp)
                    .clickable(role = Role.Button, onClick = onJoin)
                    .padding(horizontal = 8.dp)
                    .testTag(Tags.CHANNEL_CHOOSER_JOIN),
            )
        }
    }
}
