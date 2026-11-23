package com.voria.umsh.features.settings

import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.LocationText
import com.voria.umsh.services.location.SharedPrecision

/**
 * Share location and Precision (`identity.svg` 1–2, 6; `permissions.svg`
 * 4–6). [chosen] is the user's precision, null while not sharing; the rows
 * state the area actually disclosed, which approximate location alone
 * makes coarser (§3.8). With no location allowed the switch keeps the
 * choice and a line says nothing is shared.
 */
@Composable
fun ShareLocationRows(
    chosen: UByte?,
    grant: LocationGrant,
    sizes: SharedPrecision,
    onShare: (Boolean) -> Unit,
    onPrecision: () -> Unit,
    onAllow: () -> Unit,
) {
    val sharing = chosen != null
    val effective = sizes.effective(chosen, grant)
    ListItem(
        headlineContent = { Text(stringResource(R.string.share_location)) },
        supportingContent = {
            Text(
                effective?.let { areaText(sizes, it) } ?: stringResource(R.string.share_location_off),
            )
        },
        trailingContent = { Switch(checked = sharing, onCheckedChange = null) },
        colors = rowColors(),
        modifier = Modifier
            .toggleable(value = sharing, role = Role.Switch, onValueChange = onShare)
            .testTag(Tags.IDENTITY_SHARE_LOCATION),
    )
    if (effective == null) return
    if (grant == LocationGrant.None) {
        PermissionLine(R.string.location_off, Tags.IDENTITY_LOCATION_OFF, Tags.IDENTITY_LOCATION_ALLOW, onAllow)
    } else {
        ListItem(
            headlineContent = { Text(stringResource(R.string.precision)) },
            supportingContent = { Text(aboutText(sizes, effective)) },
            colors = rowColors(),
            modifier = Modifier.clickable(role = Role.Button, onClick = onPrecision).testTag(Tags.IDENTITY_PRECISION),
        )
    }
}

/**
 * The seven sizes, named by the area disclosed; choosing one applies it
 * and closes. Under approximate location the finer sizes are off, with a
 * line and Allow ([onAllowPrecise]) to ask for precise.
 */
@Composable
fun PrecisionDialog(
    chosen: UByte,
    grant: LocationGrant,
    sizes: SharedPrecision,
    onChoose: (UByte) -> Unit,
    onAllowPrecise: () -> Unit,
    onDismiss: () -> Unit,
) {
    val selected = sizes.effective(chosen, grant)
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(Tags.PRECISION_DIALOG),
        title = { Text(stringResource(R.string.precision)) },
        text = {
            // Scrolls when the dialog is shorter than its choices: landscape at large text.
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Column(Modifier.selectableGroup()) {
                    sizes.sizes.forEach { size ->
                        val enabled = sizes.allows(size.precision, grant)
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .selectable(
                                    selected = size.precision == selected,
                                    enabled = enabled,
                                    role = Role.RadioButton,
                                ) {
                                    // The clamped size, tapped: the choice stays for when precise is granted.
                                    if (size.precision == selected && selected != chosen) onDismiss() else onChoose(size.precision)
                                }
                                .testTag("${Tags.PRECISION_OPTION}_${size.precision}"),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = size.precision == selected, onClick = null, enabled = enabled)
                            Text(
                                stringResource(R.string.precision_about, LocationText.cellSize(size.meters)),
                                Modifier.padding(start = 16.dp),
                                color = if (enabled) Color.Unspecified else MaterialTheme.colorScheme.onSurface.copy(alpha = DISABLED_ALPHA),
                            )
                        }
                    }
                }
                if (grant == LocationGrant.Approximate) {
                    HorizontalDivider(Modifier.padding(vertical = 8.dp))
                    Row(
                        Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}.testTag(Tags.PRECISION_PRECISE_OFF),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(R.string.precise_location_off),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = onAllowPrecise, modifier = Modifier.testTag(Tags.PRECISION_ALLOW)) {
                            Text(stringResource(R.string.action_allow))
                        }
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

/** A line under a row that says what Android withholds, with Allow. */
@Composable
private fun PermissionLine(@StringRes text: Int, tag: String, allowTag: String, onAllow: () -> Unit) {
    ListItem(
        headlineContent = {
            Text(
                stringResource(text),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        trailingContent = {
            TextButton(onClick = onAllow, modifier = Modifier.testTag(allowTag)) {
                Text(stringResource(R.string.action_allow))
            }
        },
        colors = rowColors(),
        modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(tag),
    )
}

@Composable
private fun areaText(sizes: SharedPrecision, precision: UByte): String =
    stringResource(R.string.share_location_area, cellText(sizes, precision))

@Composable
private fun aboutText(sizes: SharedPrecision, precision: UByte): String =
    stringResource(R.string.precision_about, cellText(sizes, precision))

/** A precision the core cannot size (a stray stored value) reads as its nearest known neighbor's. */
private fun cellText(sizes: SharedPrecision, precision: UByte): String {
    val size = sizes.sizes.lastOrNull { it.precision <= precision } ?: sizes.sizes.first()
    return LocationText.cellSize(size.meters)
}

@Composable
private fun rowColors() = ListItemDefaults.colors(containerColor = Color.Transparent)

private const val DISABLED_ALPHA = 0.38f
