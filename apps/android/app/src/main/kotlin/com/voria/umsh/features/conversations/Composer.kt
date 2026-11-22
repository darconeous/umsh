package com.voria.umsh.features.conversations

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
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
 * the radio; the cursor takes the color the message would land in.
 *
 * Send is drawn and stays dimmed and inert in every state until sending
 * exists (Phase 2, design D2(b)). With no radio, a line above the field
 * says why (its Connect radio button waits for Radio Detail, D14).
 * [focusable] is false while the thread is not the page shown.
 */
@Composable
internal fun Composer(
    draft: TextFieldState,
    title: String,
    state: ComposerState,
    security: MessageSecurity,
    modifier: Modifier = Modifier,
    focusable: Boolean = true,
) {
    val colors = MaterialTheme.colorScheme
    val accent = LocalFixedColors.current.sent(security)
    Column(modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 12.dp).testTag(Tags.COMPOSER)) {
        if (state == ComposerState.Blocked) {
            Row(
                Modifier.padding(start = 4.dp, bottom = 8.dp).heightIn(min = 36.dp).testTag(Tags.COMPOSER_BLOCKED),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(painterResource(R.drawable.ic_sensors_off), contentDescription = null, tint = colors.onSurfaceVariant, modifier = Modifier.size(20.dp))
                Text(stringResource(R.string.composer_blocked), style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
            }
        }
        Row(verticalAlignment = Alignment.Bottom) {
            val placeholder = stringResource(R.string.composer_placeholder, userIsolated(title))
            val empty = draft.text.isEmpty()
            BasicTextField(
                state = draft,
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = colors.onSurface),
                cursorBrush = SolidColor(accent),
                lineLimits = TextFieldLineLimits.MultiLine(minHeightInLines = 1, maxHeightInLines = 6),
                modifier = Modifier
                    .weight(1f)
                    // Only on the page shown: a thread drawn behind a back
                    // preview never takes focus, or the keyboard with it, and
                    // a focused field that stops being shown lets go of both.
                    .focusProperties { canFocus = focusable }
                    // Named while empty only: a description on a field with text
                    // would be read in place of the draft.
                    .semantics { if (empty) contentDescription = placeholder }
                    .testTag(Tags.COMPOSER_FIELD),
                decorator = { field ->
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
                        field()
                    }
                },
            )
            Spacer(Modifier.width(8.dp))
            // Absent while there is nothing to send: its arrival says the message is ready.
            Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                if (draft.text.isNotBlank()) SendButton(state)
            }
        }
    }
}

/** Inert until Phase 2: TalkBack hears it as unavailable, and while the radio connects, why. */
@Composable
private fun SendButton(state: ComposerState) {
    val description = if (state == ComposerState.Transient) {
        stringResource(R.string.send_unavailable_connecting)
    } else {
        stringResource(R.string.action_send)
    }
    FilledIconButton(
        onClick = {},
        enabled = false,
        modifier = Modifier.size(44.dp).semantics { contentDescription = description }.testTag(Tags.COMPOSER_SEND),
    ) {
        Icon(painterResource(R.drawable.ic_send), contentDescription = null, modifier = Modifier.size(22.dp))
    }
}
