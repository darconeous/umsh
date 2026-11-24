package com.voria.umsh.features.conversations

import android.icu.text.NumberFormat
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Badge
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.annotatedStringResource
import com.voria.umsh.designsystem.identifierStringResource
import com.voria.umsh.designsystem.listTimeText
import com.voria.umsh.designsystem.selectionBackground
import com.voria.umsh.models.PreviewText
import java.time.Instant
import kotlinx.coroutines.launch
import com.voria.umsh.designsystem.userIsolated

/**
 * A conversation row (`conversation-list.svg` board 1): 40 dp avatar or
 * badge, the title (semibold while unread) with a bell-off after it when
 * muted, the preview, the last message's time and the unread count.
 * TalkBack reads it as one item, with its removal in the actions menu.
 */
@Composable
internal fun ConversationRowItem(
    row: ConversationRow,
    now: Instant,
    selected: Boolean,
    onOpen: () -> Unit,
    onRemove: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val unread = row.unreadCount > 0
    val colors = MaterialTheme.colorScheme
    val removeLabel = stringResource(removeLabel(row.removal))
    ListItem(
        headlineContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    row.title,
                    fontWeight = if (unread) FontWeight.SemiBold else null,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false).testTag(Tags.ROW_TITLE),
                )
                if (row.muted) {
                    Icon(
                        painterResource(R.drawable.ic_notifications_off),
                        contentDescription = stringResource(R.string.row_muted),
                        tint = colors.onSurfaceVariant,
                        modifier = Modifier.padding(start = 4.dp).size(16.dp).testTag(Tags.ROW_MUTED),
                    )
                }
            }
        },
        supportingContent = {
            Text(
                previewText(row.preview),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontStyle = if (row.preview == PreviewText.Deleted) FontStyle.Italic else null,
                fontWeight = if (unread) FontWeight.Medium else null,
                color = if (unread) colors.onSurface else colors.onSurfaceVariant,
                modifier = Modifier.testTag(Tags.ROW_PREVIEW),
            )
        },
        leadingContent = { RowAvatarView(row.avatar) },
        trailingContent = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                row.timeMs?.let {
                    Text(
                        listTimeText(Instant.ofEpochMilli(it), now),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = if (unread) FontWeight.SemiBold else null,
                        color = if (unread) colors.primary else colors.onSurfaceVariant,
                        modifier = Modifier.testTag(Tags.ROW_TIME),
                    )
                }
                if (unread) UnreadCount(row.unreadCount)
            }
        },
        // The highlight is drawn behind the row, inset; the content stays where every row has it.
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = modifier
            .selectionBackground(selected, colors.background, colors.secondaryContainer, MaterialTheme.shapes.large)
            .clickable(onClick = onOpen)
            .semantics(mergeDescendants = true) {
                // Beside the open conversation, read as its row, as a Peers row is.
                if (selected) this.selected = true
                if (onRemove != null) {
                    customActions = listOf(CustomAccessibilityAction(removeLabel) { onRemove(); true })
                }
            },
    )
}

/**
 * A row that a swipe toward the start asks to remove (board 7): it reveals
 * Delete or Leave and springs back, whatever the confirmation's answer.
 */
@Composable
internal fun SwipeToRemove(removal: Removal, onRemove: () -> Unit, content: @Composable () -> Unit) {
    val state = rememberSwipeToDismissBoxState()
    val scope = rememberCoroutineScope()
    SwipeToDismissBox(
        state = state,
        backgroundContent = {
            if (state.dismissDirection == SwipeToDismissBoxValue.EndToStart) RemoveBackground(removal)
        },
        enableDismissFromStartToEnd = false,
        onDismiss = {
            onRemove()
            scope.launch { state.reset() }
        },
    ) { content() }
}

@Composable
private fun RemoveBackground(removal: Removal) {
    val colors = MaterialTheme.colorScheme
    Box(
        Modifier.fillMaxSize().background(colors.errorContainer).padding(horizontal = 24.dp).testTag(Tags.SWIPE_REMOVE),
        contentAlignment = Alignment.CenterEnd,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(painterResource(R.drawable.ic_delete), contentDescription = null, tint = colors.onErrorContainer)
            Text(
                stringResource(if (removal is Removal.Delete) R.string.swipe_delete else R.string.swipe_leave),
                style = MaterialTheme.typography.labelLarge,
                color = colors.onErrorContainer,
            )
        }
    }
}

private fun removeLabel(removal: Removal): Int = when (removal) {
    is Removal.Delete -> R.string.action_delete_conversation
    is Removal.Leave -> R.string.action_leave_chat
}

@Composable
internal fun RowAvatarView(avatar: RowAvatar, size: Dp = AvatarSize.List) = when (avatar) {
    is RowAvatar.Peer -> PeerAvatar(avatar.peer, size = size, describe = false)
    is RowAvatar.Channel -> ChannelBadge(avatar.channel, size = size, describe = false)
}

/** The unread count: a filled badge, read by TalkBack as "2 unread messages". */
@Composable
private fun UnreadCount(count: Long) {
    val description = pluralStringResource(R.plurals.row_unread_messages, count.toPluralCount(), count)
    val locale = LocalConfiguration.current.locales[0]
    Badge(
        containerColor = MaterialTheme.colorScheme.primary,
        contentColor = MaterialTheme.colorScheme.onPrimary,
        modifier = Modifier.clearAndSetSemantics { contentDescription = description }.testTag(Tags.ROW_UNREAD),
    ) {
        Text(NumberFormat.getIntegerInstance(locale).format(count))
    }
}

/** A count as plural rules take it. */
private fun Long.toPluralCount(): Int = coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

/** [preview] in the reader's language. */
@Composable
internal fun previewText(preview: PreviewText): AnnotatedString = when (preview) {
    is PreviewText.Draft -> annotatedStringResource(
        R.string.preview_draft,
        AnnotatedString(preview.text),
        styles = mapOf(DRAFT to SpanStyle(color = MaterialTheme.colorScheme.error)),
    )
    PreviewText.Deleted -> AnnotatedString(stringResource(R.string.preview_deleted))
    PreviewText.None -> AnnotatedString(stringResource(R.string.preview_none))
    is PreviewText.Status -> annotatedStringResource(R.string.status_line, userIsolated(senderText(preview.who)), AnnotatedString(userIsolated(preview.body)))
    is PreviewText.Mine -> annotatedStringResource(R.string.preview_mine, AnnotatedString(userIsolated(preview.body)))
    is PreviewText.Member ->
        annotatedStringResource(R.string.preview_channel_sender, userIsolated(senderText(preview.sender)), AnnotatedString(userIsolated(preview.body)))
    is PreviewText.Plain -> AnnotatedString(preview.body)
}

/** Who a line is from, as the thread names them too. */
@Composable
internal fun senderText(sender: PreviewText.Sender): AnnotatedString = when (sender) {
    is PreviewText.Sender.Me -> AnnotatedString(sender.name ?: stringResource(R.string.status_you))
    is PreviewText.Sender.Named -> AnnotatedString(sender.name)
    is PreviewText.Sender.Hint -> identifierStringResource(R.string.member_hint, sender.hint)
    PreviewText.Sender.Unknown -> AnnotatedString(stringResource(R.string.member_unknown))
}

/** The `<annotation type>` that marks the Draft label. */
private const val DRAFT = "draft"
