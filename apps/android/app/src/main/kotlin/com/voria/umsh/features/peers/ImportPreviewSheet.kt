package com.voria.umsh.features.peers

import android.icu.text.NumberFormat
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.core.ulcpLocationCellMeters
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.LocalTimeFormatting
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.listText
import com.voria.umsh.designsystem.rememberCopier
import com.voria.umsh.designsystem.roleLabelForCode
import com.voria.umsh.models.AdvertisedIdentity
import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.ImportPreview
import com.voria.umsh.models.SignatureState
import com.voria.umsh.services.location.LocationText
import java.time.Instant

/**
 * The import preview (`add-peer.svg` 3–4), for typed, pasted and scanned
 * input alike: the node as its link describes it, the node's advertised
 * details (its own claims, signed or not), a local name, and Save peer or
 * Message. A good signature says nothing; a missing one says so; a failed
 * one says so in red. Nothing is saved or sent until a choice is made, and
 * dismissing returns to Add peer. While saving, the sheet stays.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ImportPreviewSheet(preview: ImportPreview, viewModel: AddPeerViewModel) {
    val save by viewModel.save.collectAsStateWithLifecycle()
    val saving by rememberUpdatedState(save is ImportSave.Saving)
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { it != SheetValue.Hidden || !saving },
    )
    ModalBottomSheet(
        onDismissRequest = viewModel::dismissPreview,
        sheetState = sheetState,
        modifier = Modifier.testTag(Tags.IMPORT_SHEET),
    ) {
        // A local name, kept per node across a rotation.
        var name by rememberSaveable(preview.address) { mutableStateOf("") }
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp)
                .navigationBarsPadding()
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Header(preview)
            AddressRow(preview.address)
            preview.identity?.let { identity -> Claims(identity) }
            TextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.import_name)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Done),
                modifier = Modifier.fillMaxWidth().testTag(Tags.IMPORT_NAME),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                val busy = save as? ImportSave.Saving
                TextButton(
                    onClick = { viewModel.importPeer(name, message = false) },
                    enabled = busy == null,
                    modifier = Modifier.weight(1f).testTag(Tags.IMPORT_SAVE),
                ) {
                    Busy(busy?.message == false) { Text(stringResource(R.string.import_save)) }
                }
                Button(
                    onClick = { viewModel.importPeer(name, message = true) },
                    enabled = busy == null,
                    modifier = Modifier.weight(1f).testTag(Tags.IMPORT_MESSAGE),
                ) {
                    Busy(busy?.message == true) { Text(stringResource(R.string.import_message)) }
                }
            }
        }
    }
    (save as? ImportSave.Failed)?.let { failed ->
        // Message's failure leaves no conversation; Save peer's leaves the peer unsaved.
        val message = failed.message
        FailureDialog(
            stringResource(if (message) R.string.open_failed_title else R.string.peer_not_saved_title),
            stringResource(if (message) R.string.open_failed_body else R.string.peer_failure_body),
            failed.error,
            viewModel::dismissFailure,
        )
    }
}

/**
 * "Address" over the full address: one TalkBack stop, and the whole row
 * copies, so the address is not a second stop of its own.
 */
@Composable
private fun AddressRow(address: String) {
    val copier = rememberCopier()
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClickLabel = stringResource(R.string.action_copy_address)) { copier.copy(address, R.string.copied_address) }
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.IMPORT_ADDRESS),
    ) {
        Text(stringResource(R.string.import_address), style = MaterialTheme.typography.bodyMedium)
        CanonicalAddress(address, textAlign = TextAlign.Start, copyable = false)
    }
}

/**
 * The button's label, with a spinner over it while its save runs: the label
 * stays in the tree, unseen, so TalkBack still names the button, and reads
 * it as saving.
 */
@Composable
private fun Busy(busy: Boolean, label: @Composable () -> Unit) {
    if (!busy) {
        label()
        return
    }
    val saving = stringResource(R.string.import_saving)
    Box(Modifier.semantics { stateDescription = saving }, contentAlignment = Alignment.Center) {
        Box(Modifier.alpha(0f)) { label() }
        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = LocalContentColor.current)
    }
}

/** Avatar, name, and what the link carried. */
@Composable
private fun Header(preview: ImportPreview) {
    val identity = preview.identity
    val shape = identity?.let { PeerAvatarShape.of(it.role, Capabilities(it.capabilityBits)) } ?: PeerAvatarShape.Hexagon
    Row(
        Modifier.fillMaxWidth().semantics(mergeDescendants = true) { heading() }.testTag(Tags.IMPORT_HEADER),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        PeerAvatar(preview.hint, shape, size = AvatarSize.Card)
        Column {
            Text(
                identity?.name?.takeIf { it.isNotBlank() } ?: stringResource(R.string.unnamed_node),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                stringResource(if (identity != null) R.string.import_caption_details else R.string.import_caption_key_only),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** The node's advertised details, then whose claims they are, then any signature warning. */
@Composable
private fun Claims(identity: AdvertisedIdentity) {
    DetailRow(R.string.import_role, roleLabelForCode(identity.roleCode), Tags.IMPORT_ROLE)
    val capabilities = Capabilities(identity.capabilityBits)
    val named = capabilities.listText()
    if (named.isNotEmpty()) DetailRow(R.string.peer_capabilities, named, Tags.IMPORT_CAPABILITIES)
    locationText(identity)?.let { DetailRow(R.string.import_location, it, Tags.IMPORT_LOCATION) }
    identity.timestamp?.let { seconds ->
        DetailRow(R.string.import_reported, reportedText(Instant.ofEpochSecond(seconds)), Tags.IMPORT_REPORTED)
    }
    Text(
        stringResource(R.string.import_claims_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.testTag(Tags.IMPORT_CLAIMS),
    )
    SignatureNotice(identity.signature)
}

/** A label at the start, its value at the end; one TalkBack stop. */
@Composable
private fun DetailRow(@StringRes label: Int, value: String, tag: String) {
    Row(
        Modifier.fillMaxWidth().semantics(mergeDescendants = true) {}.testTag(tag),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(stringResource(label), style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * Board 4: unsigned details in the warning container; a signature that
 * fails in red (iOS's warnings). A good signature shows nothing.
 */
@Composable
private fun SignatureNotice(signature: SignatureState) {
    val (text, colors) = when (signature) {
        SignatureState.Valid -> return
        SignatureState.Unsigned -> R.string.identity_unsigned_warning to (UmshColors.warning.container to UmshColors.warning.onContainer)
        SignatureState.Invalid -> R.string.identity_invalid_warning to
            (MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer)
    }
    val (container, content) = colors
    Row(
        Modifier
            .fillMaxWidth()
            .background(container, MaterialTheme.shapes.medium)
            .padding(12.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.IMPORT_SIGNATURE),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            painterResource(R.drawable.ic_warning),
            contentDescription = null,
            tint = if (signature == SignatureState.Unsigned) UmshColors.fixed.caution else content,
            modifier = Modifier.size(20.dp),
        )
        Text(stringResource(text), style = MaterialTheme.typography.bodySmall, color = content)
    }
}

/**
 * "44.0521, -123.0868 · within 38 m": the cell's center to the digits the
 * cell supports, in the reader's numerals, and the cell's width when the
 * node gave a precision. The minus is the locale's own, as everywhere
 * else the app prints a number. Null without a position.
 */
@Composable
private fun locationText(identity: AdvertisedIdentity): String? {
    val latitude = identity.latitude ?: return null
    val longitude = identity.longitude ?: return null
    val cellMeters = identity.locationPrecision?.let { ulcpLocationCellMeters(it.toUByte()) }
    val locale = LocalConfiguration.current.locales[0]
    val digits = CoordinateDigits.of(cellMeters)
    val number = NumberFormat.getInstance(locale).apply {
        minimumFractionDigits = digits
        maximumFractionDigits = digits
        isGroupingUsed = false
    }
    val lat = number.format(latitude)
    val lon = number.format(longitude)
    return if (cellMeters != null) {
        // The size never splits from its unit at a line's end ("38" / "m" on a narrow phone).
        val size = LocationText.cellSize(cellMeters, locale).replace(' ', '\u00A0')
        stringResource(R.string.import_location_within, lat, lon, size)
    } else {
        stringResource(R.string.import_location_value, lat, lon)
    }
}

/** "Oct 28, 3:42 PM", with the year when it is not this one. */
@Composable
private fun reportedText(at: Instant): String {
    val format = LocalTimeFormatting.current
    val now by LocalAppRuntime.current.now.collectAsStateWithLifecycle()
    val sameYear = at.atZone(format.zone).year == now.atZone(format.zone).year
    return if (sameYear) format.monthDayTime(at) else format.monthDayYearTime(at)
}
