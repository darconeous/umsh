package com.voria.umsh.features.conversations

import android.icu.text.NumberFormat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.core.MobileWellKnownChannel
import com.voria.umsh.core.wellKnownChannel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.IdentifierText
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.features.channels.channelStatements
import com.voria.umsh.features.channels.kindLabel
import com.voria.umsh.models.ChannelSummary

/**
 * A channel conversation's page (`conversation-info.svg` 1, 2 and 5), from
 * its thread's title: the channel itself (its page holds the alias,
 * sharing and leaving), Notifications, and on `EMERGENCY` Test messages;
 * the conversation's identifier and message count; Clear all messages;
 * and, for Public and EMERGENCY, how the channel works. The boards'
 * Routing section is gated on several regions per channel (D6) and is not
 * drawn. The shell closes the page once the conversation is gone.
 */
@Composable
fun ConversationInfoScreen(
    address: String,
    onBack: () -> Unit,
    /** The header: the channel's page, on this stack. */
    onOpenChannel: (String) -> Unit,
) {
    val viewModel = runtimeViewModel { ConversationInfoViewModel(it, address) }
    val conversation by viewModel.conversation.collectAsStateWithLifecycle()
    val messageCount by viewModel.messageCount.collectAsStateWithLifecycle()
    val pendingNotifications by viewModel.pendingNotifications.collectAsStateWithLifecycle()
    val testMessages by viewModel.testMessageAlerts.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    // Kept across process death; sends nothing when restored.
    var clearing by rememberSaveable { mutableStateOf(false) }

    val shown = conversation
    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(title = shown?.let { channelTitle(it.channel) }.orEmpty(), onBack = onBack) },
            modifier = Modifier.testTag(Tags.CONVERSATION_INFO),
        ) { padding ->
            if (shown == null) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                return@UmshScaffold
            }
            val channel = shown.channel
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                    ChannelHeader(channel) { onOpenChannel(channel.id) }
                    SwitchRow(
                        R.string.peer_section_notifications,
                        R.string.conversation_info_notifications_footer,
                        pendingNotifications ?: channel.notificationsEnabled,
                        Tags.CONVERSATION_INFO_NOTIFICATIONS,
                        viewModel::setNotifications,
                    )
                    val emergency = wellKnownChannel(channel.canonicalName)?.channel == MobileWellKnownChannel.EMERGENCY
                    if (emergency) {
                        SwitchRow(
                            R.string.conversation_info_test_messages,
                            R.string.conversation_info_test_messages_footer,
                            testMessages == true,
                            Tags.CONVERSATION_INFO_TEST_MESSAGES,
                            viewModel::setTestMessageAlerts,
                        )
                    }
                    SectionHeader(stringResource(R.string.conversation_info_section_conversation))
                    ValueItem(R.string.channel_identifier, Tags.CONVERSATION_INFO_IDENTIFIER) {
                        IdentifierText(channel.channelIdHex, style = valueIdentifierStyle(), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    ValueItem(R.string.conversation_info_messages, Tags.CONVERSATION_INFO_MESSAGES) {
                        // Blank until counted.
                        messageCount?.let { Text(integerText(it), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                    val count = messageCount ?: 0L
                    ClearRow(enabled = count > 0) { clearing = true }
                    val statements = channelStatements(channel)
                    if (statements.isNotEmpty()) {
                        SectionHeader(stringResource(R.string.channel_how_it_works), Modifier.padding(top = 8.dp))
                        Column(Modifier.testTag(Tags.CONVERSATION_INFO_STATEMENTS)) {
                            statements.forEach { statement ->
                                Text(
                                    statement,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    val count = messageCount
    if (clearing && count != null) {
        if (count <= 0L) {
            // Restored over a conversation already empty: nothing to ask about.
            LaunchedEffect(Unit) { clearing = false }
        } else {
            val shownCount = count.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            ConfirmDialog(
                title = stringResource(R.string.clear_messages_title),
                body = stringResource(R.string.clear_channel_messages_body),
                confirm = pluralStringResource(R.plurals.clear_messages_confirm, shownCount, shownCount),
                onConfirm = {
                    clearing = false
                    viewModel.clearMessages()
                },
                onDismiss = { clearing = false },
            )
        }
    }
    failure?.let { shownFailure ->
        val title = when (shownFailure) {
            is ConversationInfoFailure.NotChanged -> R.string.conversation_info_not_changed_title
            is ConversationInfoFailure.NotCleared -> R.string.messages_not_cleared_title
        }
        FailureDialog(stringResource(title), stringResource(R.string.peer_failure_body), shownFailure.error, viewModel::dismissFailure)
    }
}

/** The channel itself: its badge, title and kind, leading to its page; one line under it says what is there. */
@Composable
private fun ChannelHeader(channel: ChannelSummary, onOpen: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = stringResource(R.string.conversation_info_open_channel), onClick = onOpen)
            .padding(bottom = 8.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.CONVERSATION_INFO_CHANNEL),
    ) {
        // A plain row, not a ListItem: a ListItem merges its own texts apart from this one node.
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ChannelBadge(channel, size = AvatarSize.Card, describe = false)
            Column(Modifier.weight(1f)) {
                Text(channelTitle(channel), style = MaterialTheme.typography.titleLarge)
                Text(
                    stringResource(kindLabel(channel)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            stringResource(R.string.conversation_info_channel_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
    }
}

/** A switch with its one-line footer; the row toggles it, and reads as one switch. */
@Composable
private fun SwitchRow(title: Int, footer: Int, checked: Boolean, tag: String, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(title)) },
        supportingContent = { Text(stringResource(footer)) },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.toggleable(value = checked, role = Role.Switch, onValueChange = onChange).testTag(tag),
    )
}

/** A label, with its value at the row's end; one node for TalkBack. */
@Composable
private fun ValueItem(label: Int, tag: String, value: @Composable () -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(label)) },
        trailingContent = value,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(tag),
    )
}

/** Clear all messages, in red with its icon; dimmed with nothing to clear. */
@Composable
private fun ClearRow(enabled: Boolean, onClick: () -> Unit) {
    val color = MaterialTheme.colorScheme.error
    ListItem(
        leadingContent = { Icon(painterResource(R.drawable.ic_delete), contentDescription = null, tint = color) },
        headlineContent = { Text(stringResource(R.string.clear_all_messages), color = color) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .alpha(if (enabled) 1f else DISABLED_ALPHA)
            .testTag(Tags.CONVERSATION_INFO_CLEAR),
    )
}

/** A count in the locale's digits. */
@Composable
private fun integerText(value: Long): String =
    NumberFormat.getIntegerInstance(LocalConfiguration.current.locales[0]).format(value)

private const val DISABLED_ALPHA = 0.38f
