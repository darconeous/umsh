package com.voria.umsh.features.peers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.userIsolated

/**
 * Rename (`peer-page.svg` 6): the field starts with the current name; the
 * line under it is what the node calls itself, which an empty name falls
 * back to. Drawn above the keyboard, as Edit name is.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RenameDialog(
    text: String,
    advertisedName: String?,
    onChange: (String) -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    BasicAlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(decorFitsSystemWindows = false),
        modifier = Modifier.safeDrawingPadding().testTag(Tags.RENAME_DIALOG),
    ) {
        Surface(
            shape = AlertDialogDefaults.shape,
            color = AlertDialogDefaults.containerColor,
            tonalElevation = AlertDialogDefaults.TonalElevation,
        ) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp)) {
                Text(
                    stringResource(R.string.rename_title),
                    style = MaterialTheme.typography.headlineSmall,
                    color = AlertDialogDefaults.titleContentColor,
                    modifier = Modifier.padding(bottom = 16.dp).semantics { heading() },
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = onChange,
                    label = { Text(stringResource(R.string.rename_label)) },
                    placeholder = advertisedName?.let { { Text(it) } },
                    supportingText = advertisedName?.let { { Text(stringResource(R.string.rename_calls_itself, userIsolated(it))) } },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Words,
                        autoCorrectEnabled = false,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(onDone = { onSave() }),
                    modifier = Modifier.fillMaxWidth().focusRequester(focus).testTag(Tags.RENAME_FIELD),
                )
                FlowRow(
                    Modifier.fillMaxWidth().padding(top = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(onClick = onDismiss, modifier = Modifier.testTag(Tags.CONFIRM_CANCEL)) {
                        Text(stringResource(R.string.dialog_cancel))
                    }
                    TextButton(onClick = onSave, modifier = Modifier.testTag(Tags.CONFIRM_ACTION)) {
                        Text(stringResource(R.string.action_save))
                    }
                }
            }
        }
    }
}
