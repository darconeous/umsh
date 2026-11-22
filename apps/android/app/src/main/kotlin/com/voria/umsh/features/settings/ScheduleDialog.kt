package com.voria.umsh.features.settings

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags

/** The two announcement schedules, with the intervals iOS offers (seconds; 0 is off). */
enum class ScheduleKind(@param:StringRes val title: Int, val choices: List<Int>) {
    /** A short presence beacon: 20 and 30 minutes, 1 and 4 hours. */
    Beacon(R.string.beacon, listOf(0, 20 * 60, 30 * 60, 3_600, 4 * 3_600)),

    /** The full identity: every 1, 4, 12 or 24 hours. */
    Identity(R.string.identity_schedule, listOf(0, 3_600, 4 * 3_600, 12 * 3_600, 24 * 3_600)),
}

/** "Off", "Every hour", "Every 4 hours", "Every 20 minutes". */
@Composable
fun scheduleText(seconds: Int): String = when {
    seconds <= 0 -> stringResource(R.string.schedule_off)
    seconds % 3_600 == 0 -> (seconds / 3_600).let { pluralStringResource(R.plurals.schedule_every_hours, it, it) }
    else -> (seconds / 60).coerceAtLeast(1).let { pluralStringResource(R.plurals.schedule_every_minutes, it, it) }
}

/** Choosing an interval applies it and closes the dialog. */
@Composable
fun ScheduleDialog(kind: ScheduleKind, current: Int, onChoose: (Int) -> Unit, onDismiss: () -> Unit) {
    // A stored value the list does not offer is still shown, and chosen.
    val choices = if (current in kind.choices) kind.choices else (kind.choices + current).sorted()
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.SCHEDULE_DIALOG),
        title = { Text(stringResource(kind.title)) },
        text = {
            // Scrolls when the dialog is shorter than its choices: landscape at large text.
            Column(Modifier.selectableGroup().verticalScroll(rememberScrollState())) {
                choices.forEach { seconds ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .selectable(selected = seconds == current, role = Role.RadioButton) { onChoose(seconds) }
                            .testTag("${Tags.SCHEDULE_OPTION}_$seconds"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = seconds == current, onClick = null)
                        Text(scheduleText(seconds), Modifier.padding(start = 16.dp))
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.dialog_cancel)) }
        },
    )
}
