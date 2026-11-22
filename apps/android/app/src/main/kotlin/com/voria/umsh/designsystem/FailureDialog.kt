package com.voria.umsh.designsystem

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.EraseOutcome
import com.voria.umsh.app.Tags
import com.voria.umsh.services.mobilecore.FailureReason
import com.voria.umsh.services.mobilecore.FailureText
import com.voria.umsh.services.mobilecore.ReasonText

/**
 * The app-wide dialog for a failure that won't fix itself (`onboarding.svg`
 * board 3): what happened, then the reason Android gave. Copy details puts
 * [details] (diagnostic, never translated) on the clipboard; OK closes. It
 * never offers to try again: repeating what just failed would fail the same
 * way. The dialog is a window of its own, over any screen's snackbar host,
 * so its copy notice is drawn inside it.
 */
@Composable
fun FailureDialog(
    title: String,
    body: String,
    reason: String?,
    details: String,
    onDismiss: () -> Unit,
) {
    val notices = rememberNotices()
    val copier = Copier(LocalContext.current, notices.notice)
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.FAILURE_DIALOG),
        icon = {
            Icon(
                painterResource(R.drawable.ic_error),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
            )
        },
        title = { Text(title) },
        text = {
            Box {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(body)
                    if (reason != null) {
                        Text(reason, color = MaterialTheme.colorScheme.onSurface)
                    }
                }
                SnackbarHost(notices.snackbars, Modifier.align(Alignment.BottomCenter))
            }
        },
        dismissButton = {
            TextButton(
                onClick = { copier.copy(details, R.string.details_copied) },
                modifier = Modifier.testTag(Tags.FAILURE_COPY_DETAILS),
            ) {
                Text(stringResource(R.string.copy_details))
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.FAILURE_OK)) {
                Text(stringResource(R.string.dialog_ok))
            }
        },
    )
}

/** [error]'s failure dialog: its reason line and its details, from [FailureText]. */
@Composable
fun FailureDialog(title: String, body: String, error: Throwable, onDismiss: () -> Unit) = FailureDialog(
    title = title,
    body = body,
    reason = failureReasonText(FailureText.reason(error)),
    details = FailureText.details(error),
    onDismiss = onDismiss,
)

/** A reason phrase or sentence, in the reader's language. */
@Composable
fun reasonText(reason: ReasonText): String = stringResource(reason.id, *reason.args.toTypedArray())

@Composable
fun failureReasonText(reason: FailureReason): String = when (reason) {
    is FailureReason.Android -> stringResource(R.string.failure_reason_android, reasonText(reason.phrase))
    is FailureReason.Sentence -> reasonText(reason.text)
}

/**
 * An erase that did not go through, in the app and in Manage space:
 * [EraseOutcome.Failed] (nothing erased) or [EraseOutcome.Incomplete]
 * (the private key went, some keys it used did not). Anything else shows
 * nothing.
 */
@Composable
fun EraseFailureDialog(outcome: EraseOutcome, onDismiss: () -> Unit) {
    when (outcome) {
        is EraseOutcome.Failed -> FailureDialog(
            title = stringResource(R.string.erase_failed_title),
            body = stringResource(R.string.erase_failed_body),
            error = outcome.error,
            onDismiss = onDismiss,
        )
        is EraseOutcome.Incomplete -> FailureDialog(
            title = stringResource(R.string.erase_incomplete_title),
            body = stringResource(R.string.erase_incomplete_body),
            reason = null,
            details = outcome.details,
            onDismiss = onDismiss,
        )
        EraseOutcome.Done, EraseOutcome.Refused -> Unit
    }
}
