package com.voria.umsh.features.channels

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.IdentifierText
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.LocalTimeFormatting
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.features.peers.RenameDialog
import com.voria.umsh.models.ChannelSummary
import java.time.Instant

/**
 * A channel's page (`channels.svg` 10–13), from Settings › Channels:
 * Conversation and Share lead, as on the peer page; then Name, Identifier,
 * Joined and the Alias, which edits in a dialog; Leave channel; and, for
 * Public and EMERGENCY, how the channel works. Share opens the invitation
 * sheet: a private channel's with its warning, a public one's name link.
 * The page says nothing about the radio. It closes once the channel is
 * left, here or anywhere (the shell's).
 *
 * [onBack] is null beside the Settings list when the page is its only
 * detail page.
 */
@Composable
fun ChannelPageScreen(id: String, onBack: (() -> Unit)?, onConversation: (String) -> Unit) {
    val viewModel = runtimeViewModel { ChannelPageViewModel(it, id) }
    val channel by viewModel.channel.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val invitation by viewModel.invitation.collectAsStateWithLifecycle()
    val opened by rememberUpdatedState(onConversation)
    LaunchedEffect(viewModel) { viewModel.conversationOpened.collect { opened(it) } }
    // Dialogs keep their input across process death and send nothing when restored.
    var aliasing by rememberSaveable { mutableStateOf<String?>(null) }
    var leaving by rememberSaveable { mutableStateOf(false) }

    val shown = channel
    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(title = {}, onBack = onBack) },
            modifier = Modifier.testTag(Tags.CHANNEL_PAGE),
        ) { padding ->
            if (shown == null) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                return@UmshScaffold
            }
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                    Hero(shown)
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    ) {
                        VerbTile(R.drawable.ic_chat, R.string.channel_verb_conversation, Tags.CHANNEL_VERB_CONVERSATION, viewModel::openConversation)
                        VerbTile(R.drawable.ic_share, R.string.action_share, Tags.CHANNEL_VERB_SHARE, viewModel::share)
                    }
                    SectionHeader(stringResource(R.string.channel_section))
                    shown.name?.takeIf { it.isNotBlank() }?.let { name ->
                        ValueItem(R.string.channel_name, Tags.CHANNEL_PAGE_NAME) { Text(name, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                    ValueItem(R.string.channel_identifier, Tags.CHANNEL_PAGE_IDENTIFIER) {
                        IdentifierText(
                            shown.channelIdHex,
                            style = IdentifierTextStyle,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    shown.joinedAtMs?.let { at ->
                        ValueItem(R.string.channel_joined, Tags.CHANNEL_PAGE_JOINED) {
                            Text(joinedText(Instant.ofEpochMilli(at)), color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    val alias = shown.alias?.takeIf { it.isNotBlank() }
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.channel_alias)) },
                        supportingContent = { Text(alias ?: stringResource(R.string.channel_alias_none), modifier = Modifier.testTag(Tags.CHANNEL_PAGE_ALIAS)) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier
                            .clickable(role = Role.Button, onClickLabel = stringResource(R.string.channel_alias_edit)) { aliasing = alias.orEmpty() }
                            .testTag(Tags.CHANNEL_PAGE_ALIAS_ROW),
                    )
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.leave_channel), color = MaterialTheme.colorScheme.error) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier.clickable(role = Role.Button) { leaving = true }.testTag(Tags.CHANNEL_PAGE_LEAVE),
                    )
                    val statements = channelStatements(shown)
                    if (statements.isNotEmpty()) {
                        SectionHeader(stringResource(R.string.channel_how_it_works), Modifier.padding(top = 8.dp))
                        Column(Modifier.testTag(Tags.CHANNEL_PAGE_STATEMENTS)) {
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

    val current = shown
    aliasing?.let { text ->
        if (current == null) return@let
        RenameDialog(
            text = text,
            advertisedName = null,
            onChange = { aliasing = it },
            onSave = {
                viewModel.setAlias(text)
                aliasing = null
            },
            onDismiss = { aliasing = null },
            title = stringResource(R.string.channel_alias),
            label = stringResource(R.string.channel_alias),
            placeholder = current.name?.takeIf { it.isNotBlank() },
        )
    }
    if (leaving && current != null) {
        LeaveChannelDialog(
            current,
            onConfirm = {
                leaving = false
                viewModel.leave()
            },
            onDismiss = { leaving = false },
        )
    }
    val link = invitation
    if (link != null && current != null) ChannelInvitationSheet(current, link, onDismiss = viewModel::closeInvitation)
    failure?.let { shownFailure ->
        val (title, body) = when (shownFailure) {
            is ChannelPageFailure.NotOpened -> R.string.open_failed_title to R.string.open_failed_body
            is ChannelPageFailure.NotLeft -> R.string.channel_not_left_title to R.string.channel_not_left_body
            is ChannelPageFailure.NotChanged -> R.string.channel_not_changed_title to R.string.channel_not_changed_body
            is ChannelPageFailure.NotShared -> R.string.channel_not_shared_title to R.string.channel_not_shared_body
        }
        FailureDialog(stringResource(title), stringResource(body), shownFailure.error, viewModel::dismissFailure)
    }
}

/** The badge, the channel's title, and its kind (Built-in, Public or Private). */
@Composable
private fun Hero(channel: ChannelSummary) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp).semantics(mergeDescendants = true) {},
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ChannelBadge(channel, size = AvatarSize.Page, describe = false)
        Text(
            channelTitle(channel),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() }.testTag(Tags.CHANNEL_PAGE_TITLE),
        )
        Text(
            stringResource(kindLabel(channel)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(Tags.CHANNEL_PAGE_KIND),
        )
    }
}

/** One verb: a tonal circle and its label, as the peer page's. */
@Composable
private fun VerbTile(@DrawableRes icon: Int, @StringRes label: Int, tag: String, onClick: () -> Unit) {
    Column(
        Modifier
            .widthIn(min = 72.dp)
            .clip(MaterialTheme.shapes.medium)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(vertical = 4.dp)
            .testTag(tag),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            Modifier.size(56.dp).background(MaterialTheme.colorScheme.secondaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(painterResource(icon), contentDescription = null, tint = MaterialTheme.colorScheme.onSecondaryContainer)
        }
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium, textAlign = TextAlign.Center)
    }
}

/** A label, with its value at the row's end; one node for TalkBack. */
@Composable
private fun ValueItem(@StringRes label: Int, tag: String, value: @Composable () -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(label)) },
        trailingContent = value,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(tag),
    )
}

/** "Oct 12, 9:14 AM", with the year when it is not this one. */
@Composable
private fun joinedText(at: Instant): String {
    val format = LocalTimeFormatting.current
    val now by LocalAppRuntime.current.now.collectAsStateWithLifecycle()
    val sameYear = at.atZone(format.zone).year == now.atZone(format.zone).year
    return if (sameYear) format.monthDayTime(at) else format.monthDayYearTime(at)
}
