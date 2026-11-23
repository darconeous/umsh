package com.voria.umsh.features.conversations

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.LocalFixedColors
import com.voria.umsh.designsystem.MessageSecurity
import com.voria.umsh.designsystem.userIsolated

/**
 * The composer (`composer.svg`): a pill field named for the conversation,
 * growing to six lines, with Send beside it once there is something to
 * send. The field is usable in every state, so a draft is never lost to
 * the radio; the cursor and Send take the color the message would land in.
 *
 * Send goes while the radio carries this phone; while it connects Send
 * waits, dimmed, and a tap says why; with no radio a line above the field
 * says so, with Connect radio when there is a radio to open. Replying puts
 * the quote above the field; editing writes in a field of its own under an
 * "Editing message" strip, and Send becomes a check. [focusable] is false
 * while the thread is not the page shown.
 */
@Composable
internal fun Composer(
    draft: TextFieldState,
    editText: TextFieldState,
    title: String,
    state: ComposerState,
    security: MessageSecurity,
    mode: ComposeMode,
    /** Who the message replied to is from, as the strip names them. */
    replyName: String?,
    sending: Boolean,
    onSend: () -> Unit,
    onCancelMode: () -> Unit,
    /** Connect radio's target; null leaves the button out. */
    onConnectRadio: (() -> Unit)?,
    focusRequester: FocusRequester,
    modifier: Modifier = Modifier,
    focusable: Boolean = true,
) {
    val colors = MaterialTheme.colorScheme
    val accent = LocalFixedColors.current.sent(security)
    val editing = mode is ComposeMode.Editing
    val field = if (editing) editText else draft
    Column(modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 12.dp).testTag(Tags.COMPOSER)) {
        if (state == ComposerState.Blocked) {
            Row(
                Modifier.padding(start = 4.dp, bottom = 8.dp).heightIn(min = 36.dp).testTag(Tags.COMPOSER_BLOCKED),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(painterResource(R.drawable.ic_sensors_off), contentDescription = null, tint = colors.onSurfaceVariant, modifier = Modifier.size(20.dp))
                Text(
                    stringResource(R.string.composer_blocked),
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.onSurfaceVariant,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (onConnectRadio != null) {
                    TextButton(onClick = onConnectRadio, modifier = Modifier.testTag(Tags.COMPOSER_CONNECT_RADIO)) {
                        Text(stringResource(R.string.composer_connect_radio))
                    }
                }
            }
        }
        when (mode) {
            ComposeMode.Plain -> Unit
            is ComposeMode.Replying -> Strip(
                heading = stringResource(R.string.replying_to, userIsolated(replyName.orEmpty())),
                line = mode.message.body,
                accent = accent,
                closeLabel = stringResource(R.string.cancel_reply),
                onClose = onCancelMode,
            )
            is ComposeMode.Editing -> Strip(
                heading = stringResource(R.string.editing_message),
                line = mode.message.body,
                accent = accent,
                closeLabel = stringResource(R.string.cancel_edit),
                onClose = onCancelMode,
            )
        }
        Row(verticalAlignment = Alignment.Bottom) {
            val placeholder = stringResource(R.string.composer_placeholder, userIsolated(title))
            val empty = field.text.isEmpty()
            BasicTextField(
                state = field,
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = colors.onSurface),
                cursorBrush = SolidColor(accent),
                lineLimits = TextFieldLineLimits.MultiLine(minHeightInLines = 1, maxHeightInLines = 6),
                modifier = Modifier
                    .weight(1f)
                    .focusRequester(focusRequester)
                    // Only on the page shown: a thread drawn behind a back
                    // preview never takes focus, or the keyboard with it, and
                    // a focused field that stops being shown lets go of both.
                    .focusProperties { canFocus = focusable }
                    // Named while empty only: a description on a field with text
                    // would be read in place of the draft.
                    .semantics { if (empty) contentDescription = placeholder }
                    .testTag(if (editing) Tags.COMPOSER_EDIT_FIELD else Tags.COMPOSER_FIELD),
                decorator = { inner ->
                    Box(
                        Modifier
                            .background(colors.surfaceContainerHigh, RoundedCornerShape(24.dp))
                            .defaultMinSize(minHeight = 48.dp)
                            .padding(horizontal = 18.dp, vertical = 12.dp),
                        contentAlignment = Alignment.CenterStart,
                    ) {
                        if (empty) {
                            // Drawn only: the field itself carries the name.
                            Text(
                                placeholder,
                                style = MaterialTheme.typography.bodyLarge,
                                color = colors.onSurfaceVariant,
                                maxLines = 1,
                                modifier = Modifier.clearAndSetSemantics {},
                            )
                        }
                        inner()
                    }
                },
            )
            Spacer(Modifier.width(8.dp))
            // Absent while there is nothing to send: its arrival says the message is ready.
            Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                if (field.text.isNotBlank()) SendButton(state, accent, editing, sending, onSend)
            }
        }
    }
}

/**
 * Send in the message's color. While the radio connects it is dimmed but
 * still answers a tap, with the alert that says why; with no radio it is
 * inert. Editing, it is a check that saves the new words.
 */
@Composable
private fun SendButton(state: ComposerState, accent: androidx.compose.ui.graphics.Color, editing: Boolean, sending: Boolean, onSend: () -> Unit) {
    val description = when {
        state == ComposerState.Transient -> stringResource(R.string.send_unavailable_connecting)
        editing -> stringResource(R.string.edit_confirm)
        else -> stringResource(R.string.action_send)
    }
    val enabled = state != ComposerState.Blocked && !sending
    FilledIconButton(
        onClick = onSend,
        enabled = enabled,
        colors = IconButtonDefaults.filledIconButtonColors(
            containerColor = accent,
            contentColor = LocalFixedColors.current.onSent,
        ),
        modifier = Modifier
            .size(44.dp)
            .alpha(if (state == ComposerState.Transient) DIMMED_ALPHA else 1f)
            .semantics { contentDescription = description }
            .testTag(Tags.COMPOSER_SEND),
    ) {
        Icon(
            painterResource(if (editing) R.drawable.ic_check else R.drawable.ic_send),
            contentDescription = null,
            modifier = Modifier.size(22.dp),
        )
    }
}

/** The quote of what a reply answers, or the words an edit replaces, above the field. */
@Composable
private fun Strip(heading: String, line: String, accent: androidx.compose.ui.graphics.Color, closeLabel: String, onClose: () -> Unit) {
    Row(
        Modifier
            .padding(start = 4.dp, bottom = 8.dp)
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .testTag(Tags.COMPOSER_STRIP),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.width(3.dp).fillMaxHeight().padding(vertical = 4.dp).background(accent, RoundedCornerShape(1.5.dp)))
        Column(Modifier.weight(1f).padding(start = 10.dp).semantics(mergeDescendants = true) {}) {
            Text(
                heading,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = accent,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                line,
                style = MaterialTheme.typography.bodyMedium,
                fontStyle = FontStyle.Normal,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(onClick = onClose, modifier = Modifier.testTag(Tags.COMPOSER_STRIP_CLOSE)) {
            Icon(painterResource(R.drawable.ic_close), contentDescription = closeLabel)
        }
    }
}

private const val DIMMED_ALPHA = 0.38f
