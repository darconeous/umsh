package com.voria.umsh.features.peers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.userIsolated

/**
 * Remove a node? (`peers-list.svg` 5), the same from the list and the
 * page. The buttons stack, end-aligned, because the labels are long.
 */
@Composable
fun RemovalDialog(
    name: String,
    choice: RemovalChoice,
    onRemove: () -> Unit,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
) {
    val body = when (choice) {
        is RemovalChoice.WithConversation ->
            if (choice.offersRemove) R.string.remove_peer_body_conversation else R.string.remove_peer_body_delete_conversation
        RemovalChoice.DeleteOnly -> R.string.remove_peer_body_alone
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.REMOVE_PEER_DIALOG),
        title = { Text(stringResource(R.string.remove_peer_title, userIsolated(name))) },
        text = { Text(stringResource(body)) },
        confirmButton = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.Center) {
                if (choice is RemovalChoice.WithConversation && choice.offersRemove) {
                    TextButton(onClick = onRemove, modifier = Modifier.testTag(Tags.REMOVE_PEER_REMOVE)) {
                        Text(stringResource(R.string.remove_peer))
                    }
                }
                TextButton(
                    onClick = onDelete,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.testTag(Tags.REMOVE_PEER_DELETE),
                ) {
                    Text(
                        stringResource(
                            if (choice is RemovalChoice.WithConversation) R.string.delete_peer_and_conversation else R.string.delete_peer,
                        ),
                    )
                }
                TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.CONFIRM_CANCEL)) {
                    Text(stringResource(R.string.dialog_cancel))
                }
            }
        },
    )
}
