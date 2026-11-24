package com.voria.umsh.features.settings

import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.features.share.shareLink
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalShellViewModelStoreOwner
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.EraseIdentityDialog
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.LocalCopyNotice
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.rememberLocationAskers
import com.voria.umsh.services.preferences.PolicyPreferences
import kotlinx.coroutines.launch

/**
 * Your identity (`identity.svg`): who this phone is (avatar, name and
 * address), four contact-card actions, Announcements (with Share
 * location, §3.8), and Key. [onBack] is null beside the Settings list,
 * where there is no Back. On a tablet, one centered column.
 */
@Composable
fun YourIdentityScreen(onBack: (() -> Unit)?) {
    val host = LocalAppCoreHost.current
    // The shell's store, not the entry's: the same page as placeholder and entry is one ViewModel.
    val viewModel = runtimeViewModel(owner = LocalShellViewModelStoreOwner.current) { YourIdentityViewModel(it, host) }
    val identity by viewModel.identity.collectAsStateWithLifecycle()
    val policy by viewModel.policy.collectAsStateWithLifecycle()
    val canAdvertise by viewModel.canAdvertise.collectAsStateWithLifecycle()
    val dialog by viewModel.dialog.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()
    val grant by viewModel.locationGrant.collectAsStateWithLifecycle()
    val askers = rememberLocationAskers(host.preferences, { viewModel.locationGrant.value }, viewModel::locationAnswered)
    val notice = LocalCopyNotice.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    LaunchedEffect(viewModel) { viewModel.advertised.collect { notice.show(R.string.identity_advertised) } }

    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.your_identity), onBack = onBack) },
            modifier = Modifier.testTag(Tags.YOUR_IDENTITY),
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier
                        .widthIn(max = 600.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(bottom = 24.dp),
                ) {
                    Column(
                        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        PeerAvatar(identity.hint, PeerAvatarShape.Circle, size = AvatarSize.Page)
                        if (identity.advertisedName.isNotEmpty()) {
                            Text(
                                identity.advertisedName,
                                style = MaterialTheme.typography.headlineSmall,
                                textAlign = TextAlign.Center,
                            )
                        }
                        CanonicalAddress(identity.address)
                    }
                    // Flows onto a second row when large text makes the labels
                    // wider than the screen, so a label never crowds or splits.
                    FlowRow(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CardAction(R.drawable.ic_qr_code, stringResource(R.string.identity_qr_code), Tags.IDENTITY_QR) {
                            viewModel.open(IdentityDialog.Qr)
                        }
                        CardAction(R.drawable.ic_share, stringResource(R.string.identity_share), Tags.IDENTITY_SHARE) {
                            scope.launch { viewModel.link()?.let { shareLink(context, it) } }
                        }
                        CardAction(
                            R.drawable.ic_wifi_tethering,
                            stringResource(R.string.identity_advertise),
                            Tags.IDENTITY_ADVERTISE,
                            enabled = canAdvertise,
                            onClick = viewModel::advertise,
                        )
                        CardAction(R.drawable.ic_edit, stringResource(R.string.identity_edit_name), Tags.IDENTITY_EDIT_NAME) {
                            viewModel.open(IdentityDialog.EditName(identity.advertisedName))
                        }
                    }

                    SectionHeader(stringResource(R.string.section_announcements))
                    val discoverable = policy?.discoverable ?: true
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.discoverable)) },
                        supportingContent = { Text(stringResource(R.string.discoverable_detail)) },
                        trailingContent = { Switch(checked = discoverable, onCheckedChange = null) },
                        colors = rowColors(),
                        modifier = Modifier
                            .toggleable(value = discoverable, role = Role.Switch, onValueChange = viewModel::setDiscoverable)
                            .testTag(Tags.IDENTITY_DISCOVERABLE),
                    )
                    val beacon = policy?.beaconIntervalSeconds?.toInt() ?: PolicyPreferences.DEFAULT_BEACON_INTERVAL
                    ValueRow(stringResource(R.string.beacon), scheduleText(beacon), Tags.IDENTITY_BEACON) {
                        viewModel.open(IdentityDialog.Schedule(ScheduleKind.Beacon))
                    }
                    val advert = policy?.advertIntervalSeconds?.toInt() ?: PolicyPreferences.DEFAULT_ADVERT_INTERVAL
                    ValueRow(stringResource(R.string.identity_schedule), scheduleText(advert), Tags.IDENTITY_SCHEDULE) {
                        viewModel.open(IdentityDialog.Schedule(ScheduleKind.Identity))
                    }

                    ShareLocationRows(
                        chosen = policy?.locationPrecision,
                        grant = grant,
                        sizes = viewModel.precisions,
                        onShare = { share ->
                            viewModel.setShareLocation(share)
                            // The choice is written first; Android's dialog only if it will still show it.
                            if (share && grant == LocationGrant.None) askers.location.askIfAskable()
                        },
                        onPrecision = { viewModel.open(IdentityDialog.Precision) },
                        onAllow = askers.location::ask,
                    )

                    SectionHeader(stringResource(R.string.section_key))
                    ValueRow(
                        stringResource(R.string.key_protection),
                        stringResource(protectionText(identity.protection)),
                        Tags.IDENTITY_KEY_PROTECTION,
                        onClick = null,
                    )
                    if (viewModel.canErase) {
                        ListItem(
                            headlineContent = {
                                Text(stringResource(R.string.erase_identity), color = MaterialTheme.colorScheme.error)
                            },
                            colors = rowColors(),
                            modifier = Modifier
                                .clickable(role = Role.Button) { viewModel.open(IdentityDialog.ConfirmErase) }
                                .testTag(Tags.IDENTITY_ERASE),
                        )
                    }
                }
            }
        }
    }

    when (val open = dialog) {
        is IdentityDialog.EditName -> EditNameDialog(
            text = open.text,
            saving = open.saving,
            onChange = viewModel::editName,
            onSave = viewModel::saveName,
            onDismiss = viewModel::dismissDialog,
        )
        IdentityDialog.Qr -> IdentityQrSheet(identity, shareUri, onDismiss = viewModel::dismissDialog)
        is IdentityDialog.Schedule -> ScheduleDialog(
            kind = open.kind,
            current = when (open.kind) {
                ScheduleKind.Beacon -> policy?.beaconIntervalSeconds?.toInt() ?: PolicyPreferences.DEFAULT_BEACON_INTERVAL
                ScheduleKind.Identity -> policy?.advertIntervalSeconds?.toInt() ?: PolicyPreferences.DEFAULT_ADVERT_INTERVAL
            },
            onChoose = { viewModel.setSchedule(open.kind, it) },
            onDismiss = viewModel::dismissDialog,
        )
        IdentityDialog.Precision -> policy?.locationPrecision?.let { chosen ->
            PrecisionDialog(
                chosen = chosen,
                grant = grant,
                sizes = viewModel.precisions,
                onChoose = viewModel::setPrecision,
                onAllowPrecise = askers.precise::ask,
                onDismiss = viewModel::dismissDialog,
            )
        }
        IdentityDialog.ConfirmErase -> EraseIdentityDialog(onConfirm = viewModel::erase, onDismiss = viewModel::dismissDialog)
        null -> Unit
    }

    failure?.let { shown ->
        FailureDialog(
            title = stringResource(
                when (shown) {
                    is IdentityFailure.NameNotSaved -> R.string.name_save_failed_title
                    is IdentityFailure.NotAdvertised -> R.string.advertise_failed_title
                },
            ),
            body = stringResource(
                when (shown) {
                    is IdentityFailure.NameNotSaved -> R.string.name_save_failed_body
                    is IdentityFailure.NotAdvertised -> R.string.advertise_failed_body
                },
            ),
            error = shown.error,
            onDismiss = viewModel::dismissFailure,
        )
    }
}

/** One of the four actions under the header: a tonal circle and its label, as on a contact card. */
@Composable
private fun CardAction(
    @DrawableRes icon: Int,
    label: String,
    tag: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Column(
        Modifier
            .widthIn(min = 72.dp)
            .clip(MaterialTheme.shapes.medium)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .alpha(if (enabled) 1f else DISABLED_ALPHA)
            .padding(vertical = 4.dp)
            .testTag(tag),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            Modifier.size(56.dp).background(MaterialTheme.colorScheme.secondaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(painterResource(icon), contentDescription = null, tint = MaterialTheme.colorScheme.onSecondaryContainer)
        }
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 4.dp),
        )
    }
}

/** A row that states its value; [onClick] null for one that only informs. */
@Composable
private fun ValueRow(title: String, value: String, tag: String, onClick: (() -> Unit)?) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(value) },
        colors = rowColors(),
        modifier = (if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier).testTag(tag),
    )
}

@Composable
private fun rowColors() = ListItemDefaults.colors(containerColor = Color.Transparent)

private fun protectionText(protection: KeyProtection): Int = when (protection) {
    KeyProtection.StrongBox -> R.string.key_protection_strongbox
    KeyProtection.TrustedEnvironment -> R.string.key_protection_tee
    KeyProtection.Software -> R.string.key_protection_software
    KeyProtection.Unknown -> R.string.key_protection_unknown
}

private const val DISABLED_ALPHA = 0.38f
