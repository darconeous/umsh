package com.voria.umsh.features.conversations

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.designsystem.LocalFixedColors
import com.voria.umsh.designsystem.failureReasonText
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.models.ResendMode
import com.voria.umsh.services.mobilecore.FailureText

/**
 * Long press (`bubbles.svg` 3): the six reactions, then what the message
 * offers. Copy and Details are always there; the rest only when the core
 * would take them.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MessageMenuSheet(
    message: ChatMessage,
    onReact: (ReactionKind) -> Unit,
    onItem: (MenuItem) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.testTag(Tags.MESSAGE_MENU),
    ) {
        Column(Modifier.navigationBarsPadding().padding(bottom = 8.dp)) {
            if (MessageMenu.reactions(message)) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.MESSAGE_MENU_REACTIONS),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                ) {
                    Glyphs.reactionPalette.forEach { (glyph, kind) ->
                        val drawn = Glyphs.drawable(glyph)
                        val label = stringResource(R.string.react_with, drawn)
                        Box(
                            Modifier
                                .size(48.dp)
                                .clip(CircleShape)
                                .clickable(role = Role.Button) { onReact(kind) }
                                .semantics { contentDescription = label }
                                .testTag(Tags.menuReaction(glyph)),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(drawn, fontSize = 26.sp, color = Color.Unspecified)
                        }
                    }
                }
            }
            MessageMenu.items(message).forEach { item ->
                ListItem(
                    headlineContent = {
                        Text(
                            stringResource(item.label),
                            color = if (item == MenuItem.Delete) MaterialTheme.colorScheme.error else Color.Unspecified,
                        )
                    },
                    leadingContent = {
                        Icon(
                            painterResource(item.icon),
                            contentDescription = null,
                            tint = if (item == MenuItem.Delete) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    modifier = Modifier.clickable(role = Role.Button) { onItem(item) }.testTag(Tags.menuItem(item.name)),
                )
            }
        }
    }
}

private val MenuItem.icon: Int
    get() = when (this) {
        MenuItem.Reply -> R.drawable.ic_reply
        MenuItem.Copy -> R.drawable.ic_content_copy
        MenuItem.ViewOriginal -> R.drawable.ic_history
        MenuItem.TryAgain, MenuItem.Resend -> R.drawable.ic_refresh
        MenuItem.Edit -> R.drawable.ic_edit
        MenuItem.Details -> R.drawable.ic_info
        MenuItem.Delete -> R.drawable.ic_delete
    }

/**
 * `EMERGENCY`'s warning (`threads.svg` 5): red throughout, so it reads as
 * no ordinary confirmation. [sends] words the button for a new message.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun EmergencySheet(sends: Boolean, onCertify: () -> Unit, onCancel: () -> Unit) {
    val red = LocalFixedColors.current.emergencyChannel
    ModalBottomSheet(
        onDismissRequest = onCancel,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = red,
        contentColor = Color.White,
        modifier = Modifier.testTag(Tags.EMERGENCY_SHEET),
    ) {
        Column(
            Modifier.navigationBarsPadding().padding(horizontal = 24.dp).padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(painterResource(R.drawable.ic_warning), contentDescription = null, modifier = Modifier.size(44.dp))
                Text(
                    stringResource(R.string.emergency_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.semantics { heading() },
                )
                Text(stringResource(R.string.emergency_body, EMERGENCY_NAME), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.emergency_body_public), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
            }
            Button(
                onClick = onCertify,
                colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = red),
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag(Tags.EMERGENCY_CERTIFY),
            ) {
                Text(
                    stringResource(if (sends) R.string.emergency_certify_send else R.string.emergency_certify),
                    fontWeight = FontWeight.Bold,
                )
            }
            TextButton(
                onClick = onCancel,
                colors = ButtonDefaults.textButtonColors(contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().testTag(Tags.EMERGENCY_CANCEL),
            ) {
                Text(stringResource(R.string.dialog_cancel), fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

/** The channel's name, which is never translated. */
private const val EMERGENCY_NAME = "EMERGENCY"

/** What the thread tells the person once: why a message did not go, or that it was only kept. */
@Composable
internal fun ThreadAlertDialog(alert: ThreadAlert, onDismiss: () -> Unit) {
    when (alert) {
        ThreadAlert.StillConnecting -> NoticeDialog(
            title = stringResource(R.string.message_not_sent_title),
            body = stringResource(R.string.message_not_sent_connecting),
            onDismiss = onDismiss,
        )
        is ThreadAlert.Submitted -> NoticeDialog(
            title = stringResource(R.string.message_submitted_title),
            body = stringResource(if (alert.recorded) R.string.message_submitted_recorded else R.string.message_submitted_unrecorded),
            onDismiss = onDismiss,
        )
        is ThreadAlert.NotSent -> FailureDialog(
            title = stringResource(R.string.message_not_sent_title),
            body = failureReasonText(FailureText.reason(alert.error)),
            reason = stringResource(R.string.message_text_kept),
            details = FailureText.details(alert.error),
            onDismiss = onDismiss,
        )
        is ThreadAlert.Failed -> FailureDialog(
            title = stringResource(alert.title),
            body = failureReasonText(FailureText.reason(alert.error)),
            reason = null,
            details = FailureText.details(alert.error),
            onDismiss = onDismiss,
        )
    }
}

/** A title, a sentence and OK: nothing to copy, since nothing failed on this phone's side. */
@Composable
private fun NoticeDialog(title: String, body: String, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.THREAD_ALERT),
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.FAILURE_OK)) {
                Text(stringResource(R.string.dialog_ok))
            }
        },
    )
}

/**
 * Sending a failed message again (`bubbles.svg` 5): "Try again" within its
 * window, "Resend" after; one first sent under forward secrecy may go
 * without it. Stacked, since the labels are long.
 */
@Composable
internal fun ResendDialog(prompt: ResendPrompt, onSend: (forwardSecret: Boolean) -> Unit, onDismiss: () -> Unit) {
    val inPlace = prompt.mode == ResendMode.InPlace
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.RESEND_DIALOG),
        title = { Text(stringResource(if (inPlace) R.string.retry_title else R.string.resend_title)) },
        confirmButton = {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.End) {
                TextButton(onClick = { onSend(prompt.message.isForwardSecret) }, modifier = Modifier.testTag(Tags.RESEND_CONFIRM)) {
                    Text(stringResource(if (inPlace) R.string.retry_confirm else R.string.resend_confirm), textAlign = TextAlign.End)
                }
                if (prompt.offersWithoutForwardSecrecy) {
                    TextButton(onClick = { onSend(false) }, modifier = Modifier.testTag(Tags.RESEND_WITHOUT_FORWARD_SECRECY)) {
                        Text(stringResource(R.string.send_without_forward_secrecy), textAlign = TextAlign.End)
                    }
                }
                TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.RESEND_CANCEL)) {
                    Text(stringResource(R.string.dialog_cancel))
                }
            }
        },
    )
}

/** My edited message's original words. */
@Composable
internal fun OriginalDialog(message: ChatMessage, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.ORIGINAL_DIALOG),
        title = { Text(stringResource(R.string.original_message_title)) },
        text = { Text(message.originalBody.orEmpty()) },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.dialog_ok)) }
        },
    )
}
