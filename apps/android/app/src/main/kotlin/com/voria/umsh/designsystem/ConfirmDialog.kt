package com.voria.umsh.designsystem

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.app.Tags

/**
 * A confirmation before something that cannot be undone: the title says
 * what, the body what goes with it, and the [confirm] button (in the error
 * color when [destructive]) sits beside Cancel, which dismissing also means.
 */
@Composable
fun ConfirmDialog(
    title: String,
    body: String,
    confirm: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    destructive: Boolean = true,
    /** The other button; Cancel unless the dialog names it. */
    dismiss: String? = null,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.CONFIRM_DIALOG),
        title = { Text(title) },
        text = { Text(body) },
        dismissButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.CONFIRM_CANCEL)) {
                Text(dismiss ?: stringResource(R.string.dialog_cancel))
            }
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                colors = if (destructive) ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error) else ButtonDefaults.textButtonColors(),
                modifier = Modifier.testTag(Tags.CONFIRM_ACTION),
            ) {
                Text(confirm)
            }
        },
    )
}

/** Erase this identity? (`identity.svg` board 8), in the app and in Manage space. */
@Composable
fun EraseIdentityDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) = ConfirmDialog(
    title = stringResource(R.string.erase_identity_title),
    body = stringResource(R.string.erase_identity_body),
    confirm = stringResource(R.string.erase_identity),
    onConfirm = onConfirm,
    onDismiss = onDismiss,
)
