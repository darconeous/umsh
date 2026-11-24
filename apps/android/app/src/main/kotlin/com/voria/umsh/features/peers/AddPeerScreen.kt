package com.voria.umsh.features.peers

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.features.channels.ChannelKeyText
import com.voria.umsh.features.channels.ChannelPreviewSheet
import com.voria.umsh.features.scanner.ScannedCode
import com.voria.umsh.features.scanner.hasCamera
import com.voria.umsh.features.settings.IdentityQrSheet
import com.voria.umsh.models.MeetDevice
import com.voria.umsh.models.MeetExchange

/**
 * Add peer (`add-peer.svg` 1–2): Nearby, the contact exchange's devices
 * (`nearby-exchange.svg` 1); the Peer identity field with Preview; and
 * Your identity's Show your code, since swapping codes is the other half
 * of adding someone. Preview opens the import preview over the page
 * (boards 3–4); a node already saved opens its page instead, and a
 * channel link the channel's join preview (`qr-scanner.svg` 4). A device
 * asking to exchange opens its sheet over the page. The field's scan
 * button opens the QR scanner ([onScan]; absent without a camera); the
 * code it reads comes back as [scanned], fills the field and is previewed.
 *
 * [onBack] is null beside the Peers list, where there is no Back.
 * [onExit] takes Add peer's way out: a page, a conversation, or Your
 * identity.
 */
@Composable
fun AddPeerScreen(
    onBack: (() -> Unit)?,
    onExit: (AddPeerExit) -> Unit,
    onScan: (() -> Unit)? = null,
    scanned: ScannedCode? = null,
) {
    val viewModel = runtimeViewModel { AddPeerViewModel(RuntimeImportHost(it)) }
    val problem by viewModel.problem.collectAsStateWithLifecycle()
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val codeShown by viewModel.codeShown.collectAsStateWithLifecycle()
    val exit by rememberUpdatedState(onExit)
    val exchange = checkNotNull(LocalExchangeHost.current) { "Add peer outside the shell" }
    LaunchedEffect(viewModel) { viewModel.exits.collect { exit(it) } }

    // What was typed is restored after process death, but a channel's private key only within this process (§3.8);
    // nothing is read or sent until Preview.
    var input by rememberSaveable(stateSaver = ChannelKeyText.FieldSaver) { mutableStateOf("") }
    val keyboard = LocalSoftwareKeyboardController.current
    val runPreview = {
        keyboard?.hide()
        viewModel.preview(input)
    }
    val currentScan by rememberUpdatedState(scanned)
    LaunchedEffect(scanned?.text) {
        currentScan?.let { code ->
            code.onTaken()
            input = code.text
            viewModel.edited()
            viewModel.preview(code.text)
        }
    }

    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.add_peer), onBack = onBack) },
            modifier = Modifier.testTag(Tags.ADD_PEER),
        ) { padding ->
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .imePadding()
                    .verticalScroll(rememberScrollState())
                    .padding(bottom = 24.dp),
            ) {
                NearbySection(exchange)
                SectionHeader(stringResource(R.string.add_peer_section_identity), Modifier.padding(top = 8.dp))
                IdentityField(
                    input = input,
                    problem = problem,
                    onInput = {
                        input = it
                        viewModel.edited()
                    },
                    onGo = runPreview,
                    onScan = onScan?.takeIf { hasCamera() },
                )
                FilledTonalButton(
                    onClick = runPreview,
                    enabled = input.isNotBlank(),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.ADD_PEER_PREVIEW),
                ) {
                    Text(stringResource(R.string.add_peer_preview))
                }
                SectionHeader(stringResource(R.string.your_identity), Modifier.padding(top = 16.dp))
                ShowCodeRow(onClick = { viewModel.showCode(true) })
            }
        }
    }

    preview?.let { shown -> ImportPreviewSheet(shown, viewModel) }
    val channel by viewModel.channel.collectAsStateWithLifecycle()
    channel?.let { opening ->
        ChannelPreviewSheet(
            opening.input,
            opening.opening,
            onDismiss = viewModel::closeChannel,
            onJoined = { address ->
                viewModel.closeChannel()
                exit(AddPeerExit.Conversation(address))
            },
        )
    }
    val meet by exchange.meet.collectAsStateWithLifecycle()
    (meet?.exchange as? MeetExchange.Asked)?.let { asked -> AskedSheet(asked.device, exchange) }
    if (codeShown) {
        val runtime = LocalAppRuntime.current
        val identity by runtime.identity.collectAsStateWithLifecycle()
        val link by produceState<String?>(null, runtime) { value = runtime.shareUri().await() }
        IdentityQrSheet(identity, link, onDismiss = { viewModel.showCode(false) })
    }
}

/** The field: a link, an address or a key, as typed; never corrected or capitalized. */
@Composable
internal fun IdentityField(input: String, problem: AddPeerProblem?, onInput: (String) -> Unit, onGo: () -> Unit, onScan: (() -> Unit)?) {
    TextField(
        value = input,
        onValueChange = onInput,
        label = { Text(stringResource(R.string.add_peer_field)) },
        trailingIcon = onScan?.let { scan ->
            {
                IconButton(onClick = scan, modifier = Modifier.testTag(Tags.ADD_PEER_SCAN)) {
                    Icon(painterResource(R.drawable.ic_qr_code), contentDescription = stringResource(R.string.action_scan))
                }
            }
        },
        isError = problem != null,
        supportingText = problem?.let { shown ->
            {
                Text(
                    stringResource(
                        when (shown) {
                            AddPeerProblem.NotPeer -> R.string.add_peer_not_peer
                        },
                    ),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.ADD_PEER_PROBLEM),
                )
            }
        },
        // An identifier: monospace and left to right whatever the language.
        textStyle = IdentifierTextStyle.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize, textDirection = TextDirection.Ltr),
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = KeyboardType.Uri,
            imeAction = ImeAction.Go,
        ),
        keyboardActions = KeyboardActions(onGo = { if (input.isNotBlank()) onGo() }),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).testTag(Tags.ADD_PEER_FIELD),
    )
}

/** Show your code: Your identity's QR sheet, over Add peer. */
@Composable
private fun ShowCodeRow(onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp)
            .testTag(Tags.ADD_PEER_SHOW_CODE),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(painterResource(R.drawable.ic_qr_code), contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.show_your_code), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
    }
}

/**
 * Nearby (`nearby-exchange.svg` 1, `add-peer.svg` 2): the devices with Add
 * peer open too, each by its model, its color for this visit and how near
 * it seems; this phone's own color beside You. Tapping one asks it to
 * exchange. Without a radio carrying this phone it is one line.
 */
@Composable
private fun NearbySection(exchange: ExchangeHost) {
    val meet by exchange.meet.collectAsStateWithLifecycle()
    val radioReady by exchange.carriesThisPhone.collectAsStateWithLifecycle(exchange.carriesThisPhoneNow())
    val own = meet?.ownColorRgb.takeIf { radioReady }
    Column(Modifier.testTag(Tags.NEARBY)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionHeader(stringResource(R.string.nearby_section), Modifier.weight(1f))
            if (own != null) {
                Row(
                    Modifier.padding(end = 16.dp, top = 12.dp).semantics(mergeDescendants = true) {}.testTag(Tags.NEARBY_YOU),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(stringResource(R.string.nearby_you), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    MeetGlyph(own, exchange.ownModel, diameter = 22.dp)
                }
            }
        }
        val devices = meet?.devices.orEmpty()
        when {
            !radioReady -> NearbyLine(stringResource(R.string.nearby_no_radio), Tags.NEARBY_NO_RADIO)
            devices.isEmpty() -> NearbyLine(stringResource(R.string.nearby_empty), Tags.NEARBY_EMPTY)
            else -> devices.forEach { device -> NearbyRow(device, onAsk = { exchange.ask(device.id) }) }
        }
    }
}

@Composable
private fun NearbyLine(text: String, tag: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).testTag(tag),
    )
}

/** One device: glyph, model, nearness; the whole row asks. */
@Composable
private fun NearbyRow(device: MeetDevice, onAsk: () -> Unit) {
    val name = meetModelName(device.model)
    val nearness = device.nearness?.let { stringResource(nearnessDescription(it)) }
    val description = nearness?.let { stringResource(R.string.nearby_device_description, name, it) } ?: name
    val askLabel = stringResource(R.string.nearby_ask_action)
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            // Before the semantics below, which replace everything inside them.
            .testTag(Tags.NEARBY_DEVICE)
            .clickable(role = Role.Button, onClickLabel = askLabel, onClick = onAsk)
            .clearAndSetSemantics {
                contentDescription = description
                role = Role.Button
                onClick(label = askLabel) {
                    onAsk()
                    true
                }
            }
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        MeetGlyph(device.colorRgb, device.model)
        Text(name, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        device.nearness?.let { MeetNearness(it) }
    }
}

/**
 * A device asking to exchange (`nearby-exchange.svg` 1): its glyph and
 * model, Exchange contacts?, Not now and Exchange. Not now, or swiping the
 * sheet away, declines. It goes when the answer moves the exchange on.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AskedSheet(device: MeetDevice, exchange: ExchangeHost) {
    ModalBottomSheet(onDismissRequest = { exchange.answer(false) }, modifier = Modifier.testTag(Tags.EXCHANGE_ASKED)) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(start = 24.dp, end = 24.dp, bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            MeetGlyph(device.colorRgb, device.model, diameter = 64.dp)
            Text(
                meetModelName(device.model),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 12.dp),
            )
            Text(
                stringResource(R.string.exchange_asked_title),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(top = 4.dp).semantics { heading() },
            )
            Row(Modifier.fillMaxWidth().padding(top = 24.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = { exchange.answer(false) }, modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(Tags.EXCHANGE_NOT_NOW)) {
                    Text(stringResource(R.string.exchange_not_now))
                }
                Button(onClick = { exchange.answer(true) }, modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(Tags.EXCHANGE_ACCEPT)) {
                    Text(stringResource(R.string.exchange_accept))
                }
            }
        }
    }
}

