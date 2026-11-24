package com.voria.umsh.features.channels

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
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
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.DialogAction
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.FullScreenDialogScaffold
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.features.scanner.ScannedCode
import com.voria.umsh.features.scanner.hasCamera
import com.voria.umsh.models.ChannelPreview
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.JoinedChannel

/**
 * Join channel (`channels.svg` 5–9): a full-screen dialog with one field
 * for a name or an invitation, whose scan button opens the scanner
 * ([onScan]; the code comes back as [scanned]). Look up previews below the
 * field without joining or sending anything; Join (Update for a channel
 * already joined) joins what was looked up, with the alias here, and
 * [onJoined] leaves. Before a lookup, the built-in channels this phone
 * left are suggested; a suggestion joins at once. [input] starts the field
 * (a channel link) and is looked up at once. [forChat]: New channel chat's,
 * whose join opens the channel's conversation and suggests nothing.
 */
@Composable
fun ChannelJoinScreen(
    input: String?,
    forChat: Boolean,
    onClose: () -> Unit,
    onJoined: (JoinedChannel) -> Unit,
    onScan: (() -> Unit)? = null,
    scanned: ScannedCode? = null,
) {
    val viewModel = runtimeViewModel { ChannelJoinViewModel(RuntimeChannelJoinHost(it)) }
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val problem by viewModel.problem.collectAsStateWithLifecycle()
    val joining by viewModel.joining.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val appState by LocalAppRuntime.current.appState.collectAsStateWithLifecycle()
    val suggested = if (forChat) emptyList() else ChannelLists.suggested(appState?.channels.orEmpty())
    val joined by rememberUpdatedState(onJoined)
    LaunchedEffect(viewModel) { viewModel.joined.collect { joined(it) } }

    // What was typed is restored after process death, but a private key only within this process (§3.8);
    // nothing is read or sent until Look up.
    var text by rememberSaveable(stateSaver = ChannelKeyText.FieldSaver) { mutableStateOf(input.orEmpty()) }
    val alias = rememberAliasDraft(preview)
    // Never saved: a key shown is hidden again once the page is recreated.
    var keyShown by remember { mutableStateOf(false) }
    val keyboard = LocalSoftwareKeyboardController.current
    val lookUp = {
        keyboard?.hide()
        keyShown = false
        viewModel.lookUp(text)
    }
    // A link's text is looked up as it opens; again after process death, which keeps no preview.
    LaunchedEffect(viewModel) { if (input != null && viewModel.preview.value == null && text.isNotBlank()) viewModel.lookUp(text) }
    val currentScan by rememberUpdatedState(scanned)
    LaunchedEffect(scanned?.text) {
        currentScan?.let { code ->
            code.onTaken()
            text = code.text
            keyShown = false
            alias.textChanged()
            viewModel.edited()
            viewModel.lookUp(code.text)
        }
    }

    val shown = preview
    FullScreenDialogScaffold(
        title = stringResource(R.string.join_channel),
        navigationIcon = R.drawable.ic_close,
        navigationDescription = stringResource(R.string.action_close),
        onNavigate = onClose,
        action = DialogAction(
            label = stringResource(if (shown?.alreadyJoined == true) R.string.channel_update else R.string.channel_join),
            enabled = shown != null,
            tag = Tags.CHANNEL_JOIN_ACTION,
            busy = joining,
            busyDescription = stringResource(R.string.channel_joining),
            onClick = { viewModel.join(alias.text, openConversation = forChat) },
        ),
        modifier = Modifier.testTag(Tags.CHANNEL_JOIN),
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(bottom = 24.dp),
        ) {
            ChannelInputField(
                text = text,
                problem = problem,
                onText = {
                    text = it
                    keyShown = false
                    alias.textChanged()
                    viewModel.edited()
                },
                onGo = lookUp,
                onScan = onScan?.takeIf { hasCamera() },
            )
            FilledTonalButton(
                onClick = lookUp,
                enabled = text.isNotBlank(),
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.CHANNEL_LOOK_UP),
            ) {
                Text(stringResource(R.string.channel_look_up))
            }
            if (shown == null) {
                Text(
                    stringResource(R.string.join_channel_intro),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
                if (suggested.isNotEmpty()) Suggested(suggested, enabled = !joining, onJoin = { viewModel.rejoin(it.id) })
            } else {
                HorizontalDivider(Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
                ChannelPreviewDetails(shown, keyShown, onKeyShown = { keyShown = it })
                AliasField(alias.text, onAlias = alias::type, label = R.string.channel_alias, modifier = Modifier.padding(top = 8.dp))
            }
        }
    }

    failure?.let { shownFailure ->
        val title = when (shownFailure) {
            is ChannelJoinFailure.NotLookedUp -> R.string.channel_not_looked_up_title
            is ChannelJoinFailure.NotJoined -> R.string.channel_not_joined_title
        }
        FailureDialog(stringResource(title), stringResource(R.string.channel_not_joined_body), shownFailure.error, viewModel::dismissFailure)
    }
}

/** The field: a name or a `umsh:` invitation, as typed; never corrected or capitalized. */
@Composable
private fun ChannelInputField(text: String, problem: ChannelInputProblem?, onText: (String) -> Unit, onGo: () -> Unit, onScan: (() -> Unit)?) {
    TextField(
        value = text,
        onValueChange = onText,
        label = { Text(stringResource(R.string.join_channel_field)) },
        trailingIcon = onScan?.let { scan ->
            {
                IconButton(onClick = scan, modifier = Modifier.testTag(Tags.CHANNEL_JOIN_SCAN)) {
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
                            ChannelInputProblem.NotAscii -> R.string.channel_input_not_ascii
                            ChannelInputProblem.TooLong -> R.string.channel_input_too_long
                            ChannelInputProblem.NotChannel -> R.string.channel_input_not_channel
                        },
                    ),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.CHANNEL_JOIN_PROBLEM),
                )
            }
        },
        textStyle = IdentifierTextStyle.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize, textDirection = TextDirection.Ltr),
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = KeyboardType.Uri,
            imeAction = ImeAction.Go,
        ),
        keyboardActions = KeyboardActions(onGo = { if (text.isNotBlank()) onGo() }),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.CHANNEL_JOIN_FIELD),
    )
}

/**
 * The alias field's draft beside a preview. A held channel's own alias is
 * filled in, once per lookup of it; filled in rather than typed, it goes
 * when the text changes, so it never lands on another channel. Clearing
 * it is kept: Update then clears the channel's alias.
 */
@Stable
internal class AliasDraft(text: String, typed: Boolean, filledFor: String?) {
    var text by mutableStateOf(text)
        private set
    private var typed by mutableStateOf(typed)

    // The held channel whose alias was filled in for the current lookup.
    private var filledFor by mutableStateOf(filledFor)

    /** The user typed in the field. */
    fun type(alias: String) {
        text = alias
        typed = true
    }

    /** The looked-up text changed: the preview, and an alias filled in for it, no longer apply. */
    fun textChanged() {
        if (!typed) text = ""
        filledFor = null
    }

    /** [preview] is shown: its held channel's alias fills an empty field, once. */
    fun previewed(preview: ChannelPreview?) {
        val existing = preview?.existing ?: return
        if (filledFor == existing.id) return
        filledFor = existing.id
        val own = existing.alias
        if (text.isEmpty() && own != null) {
            text = own
            typed = false
        }
    }

    companion object {
        val Saver: Saver<AliasDraft, Any> = listSaver(
            save = { listOf(it.text, it.typed, it.filledFor) },
            restore = { AliasDraft(it[0] as String, it[1] as Boolean, it[2] as String?) },
        )
    }
}

/** An [AliasDraft] kept across a rotation and process death, following [preview]; a new one for new [inputs]. */
@Composable
internal fun rememberAliasDraft(preview: ChannelPreview?, vararg inputs: Any?): AliasDraft {
    val draft = rememberSaveable(*inputs, saver = AliasDraft.Saver) { AliasDraft("", typed = false, filledFor = null) }
    LaunchedEffect(draft, preview) { draft.previewed(preview) }
    return draft
}

/** The alias: stays on this phone, optional. */
@Composable
internal fun AliasField(alias: String, onAlias: (String) -> Unit, label: Int, modifier: Modifier = Modifier) {
    TextField(
        value = alias,
        onValueChange = onAlias,
        label = { Text(stringResource(label)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences, imeAction = ImeAction.Done),
        modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp).testTag(Tags.CHANNEL_ALIAS_FIELD),
    )
}

/** Suggested channels (board 5): built-in channels this phone left; tapping one joins it again. */
@Composable
private fun Suggested(channels: List<ChannelSummary>, enabled: Boolean, onJoin: (ChannelSummary) -> Unit) {
    SectionHeader(stringResource(R.string.suggested_channels), Modifier.padding(top = 8.dp))
    FlowRow(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        channels.forEach { channel ->
            AssistChip(
                onClick = { onJoin(channel) },
                enabled = enabled,
                label = { Text(channelTitle(channel)) },
                leadingIcon = { ChannelBadge(channel, size = 18.dp, describe = false) },
                modifier = Modifier.testTag(Tags.suggestedChannel(channel.id)),
            )
        }
    }
}
