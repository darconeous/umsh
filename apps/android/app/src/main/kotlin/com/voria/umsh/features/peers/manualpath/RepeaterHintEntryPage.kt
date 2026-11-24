package com.voria.umsh.features.peers.manualpath

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.DialogAction
import com.voria.umsh.designsystem.FullScreenDialogScaffold
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.RepeaterHintBadge
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.features.peers.NamedHops
import com.voria.umsh.models.RepeaterHint

/**
 * Type a repeater hint by hand (`manual-path.svg` 4–5): the start of the
 * node's Base58 address, or the hint in hex, the form chosen rather than
 * guessed. The core parses each keystroke; one hint that fits shows what it
 * resolves to, two are offered to pick from. Add stays off until exactly
 * one is chosen and it is not on the path already.
 */
@Composable
fun RepeaterHintEntryPage(draft: ManualPathDraft, onBack: () -> Unit, onAdd: (RepeaterHint) -> Unit) {
    val runtime = LocalAppRuntime.current
    var form by rememberSaveable { mutableStateOf(HintForm.Base58Prefix) }
    var text by rememberSaveable { mutableStateOf("") }
    var pickedHex by rememberSaveable { mutableStateOf<String?>(null) }
    val input = remember(text, form) { RepeaterHints.parse(text, form) }
    LaunchedEffect(text, form) { if (input.candidates.none { it.octets.hex() == pickedHex }) pickedHex = null }
    val namedFlow = remember(input) { runtime.hopNames.peers(input.candidates.map { it.octets }, runtime.appState) }
    val named by namedFlow.collectAsState(NamedHops.NONE)
    val candidateNodes = named.forHints(input.candidates.map { it.octets })
    val chosen = (if (input.candidates.size == 1) input.candidates.first() else input.candidates.firstOrNull { it.octets.hex() == pickedHex })
        ?.takeIf { !draft.contains(it.octets) }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    val names = rememberDisplayNames()

    FullScreenDialogScaffold(
        title = stringResource(R.string.hint_entry_title),
        navigationIcon = R.drawable.ic_arrow_back,
        navigationDescription = stringResource(R.string.action_back),
        onNavigate = onBack,
        action = DialogAction(stringResource(R.string.hint_entry_add), enabled = chosen != null, tag = Tags.HINT_ENTRY_ADD) { chosen?.let(onAdd) },
        modifier = Modifier.testTag(Tags.HINT_ENTRY_PAGE),
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState())) {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                    HintForm.entries.forEachIndexed { index, option ->
                        SegmentedButton(
                            selected = form == option,
                            onClick = { form = option },
                            shape = SegmentedButtonDefaults.itemShape(index, HintForm.entries.size),
                            modifier = Modifier.testTag(if (option == HintForm.Base58Prefix) Tags.HINT_ENTRY_BASE58 else Tags.HINT_ENTRY_HEX),
                        ) {
                            Text(stringResource(if (option == HintForm.Base58Prefix) R.string.hint_entry_base58 else R.string.hint_entry_hex), maxLines = 1)
                        }
                    }
                }
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text(stringResource(R.string.hint_entry_field)) },
                    placeholder = { Text(stringResource(if (form == HintForm.Hex) R.string.hint_entry_hex_example else R.string.hint_entry_base58_example), fontFamily = FontFamily.Monospace) },
                    supportingText = {
                        Text(
                            stringResource(RepeaterHints.footer(form, if (text.isBlank()) null else input.problem)),
                            modifier = Modifier.testTag(Tags.HINT_ENTRY_FOOTER),
                        )
                    },
                    isError = text.isNotBlank() && input.problem != null && input.problem != HintProblem.TooShort,
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Ascii,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(onDone = { chosen?.let(onAdd) }),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).focusRequester(focus).testTag(Tags.HINT_ENTRY_FIELD),
                )
                when {
                    input.candidates.size == 1 -> {
                        val hint = input.candidates.first()
                        val node = candidateNodes.firstOrNull()
                        SectionHeader(stringResource(R.string.hint_entry_hop), Modifier.testTag(Tags.HINT_ENTRY_HOP))
                        ValueRow(stringResource(R.string.hint_entry_row_hint), isolated(hint.text))
                        ValueRow(stringResource(R.string.hint_entry_row_hex), isolated(RepeaterHints.hexText(hint)))
                        ValueRow(stringResource(R.string.hint_entry_row_known), node?.let(names::peer) ?: stringResource(R.string.hint_entry_known_none), Tags.HINT_ENTRY_KNOWN)
                        if (draft.contains(hint.octets)) {
                            Text(
                                stringResource(R.string.hint_entry_in_path),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.HINT_ENTRY_IN_PATH),
                            )
                        }
                    }
                    input.candidates.size > 1 -> {
                        SectionHeader(stringResource(R.string.hint_entry_two_fit), Modifier.testTag(Tags.HINT_ENTRY_TWO_FIT))
                        input.candidates.forEachIndexed { index, hint ->
                            val node = candidateNodes.getOrNull(index)
                            val inPath = draft.contains(hint.octets)
                            val picked = hint.octets.hex() == pickedHex
                            ListItem(
                                headlineContent = { Text(node?.let(names::peer) ?: stringResource(R.string.hint_entry_unknown_node), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                supportingContent = { Text(stringResource(R.string.hint_entry_candidate, isolated(hint.text), isolated(RepeaterHints.hexText(hint)))) },
                                leadingContent = {
                                    if (node != null) {
                                        PeerAvatar(node, describe = false)
                                    } else {
                                        RepeaterHintBadge(hint.octets, hint.text, null)
                                    }
                                },
                                trailingContent = when {
                                    picked -> ({ Icon(painterResource(R.drawable.ic_check), contentDescription = null, tint = MaterialTheme.colorScheme.primary) })
                                    inPath -> ({ Text(stringResource(R.string.add_hop_in_path), color = MaterialTheme.colorScheme.onSurfaceVariant) })
                                    else -> null
                                },
                                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                                modifier = Modifier
                                    .alpha(if (inPath) 0.38f else 1f)
                                    .clickable(enabled = !inPath, role = Role.RadioButton) { pickedHex = hint.octets.hex() }
                                    .semantics(mergeDescendants = true) { selected = picked }
                                    .testTag(Tags.hintCandidate(hint.octets.hex())),
                            )
                        }
                        Text(
                            stringResource(R.string.hint_entry_two_fit_footer),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ValueRow(label: String, value: String, tag: String? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(horizontal = 16.dp)
            .semantics(mergeDescendants = true) {}
            .then(if (tag != null) Modifier.testTag(tag) else Modifier),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
