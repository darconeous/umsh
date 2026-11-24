package com.voria.umsh.features.peers

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.MeasurePresentation
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.label
import com.voria.umsh.designsystem.peerRoleLine
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.DiscoveryVantage
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import java.time.Instant

/** The roles an ask can be narrowed to (iOS `PeerRole.selectable`); none asks every node. */
val DISCOVER_ROLES = listOf(PeerRole.Repeater, PeerRole.Chat, PeerRole.Tracker, PeerRole.Sensor, PeerRole.Bridge)

/**
 * Discover peers (`repeaters-discover.svg` 3–5): where to ask and whom,
 * the ask and its wait, who answered or announced themselves since the
 * page opened (each unsaved one with an add button; a row opens its page
 * through [onOpenPeer]), and Announce my identity behind its confirmation.
 * The overflow clears discovered nodes. Pushed on the stack of the page
 * that opened it (D12); [vantagePeer] is the peer Ask near this node
 * aimed it at.
 */
@Composable
fun DiscoverScreen(
    vantagePeer: String?,
    /** Null beside the Peers list, where the page is the list's detail. */
    onBack: (() -> Unit)?,
    onOpenPeer: (String) -> Unit,
) {
    val runtime = LocalAppRuntime.current
    val viewModel = runtimeViewModel { DiscoverViewModel(it, vantagePeer) }
    val vantage by viewModel.vantage.collectAsStateWithLifecycle()
    val vantageRead by viewModel.vantageRead.collectAsStateWithLifecycle()
    val vantageRow by viewModel.vantagePeerRow.collectAsStateWithLifecycle()
    val heard by viewModel.heard.collectAsStateWithLifecycle()
    val canSend by viewModel.canSend.collectAsStateWithLifecycle()
    val waitMs by viewModel.waitMs.collectAsStateWithLifecycle()
    val askedHere by viewModel.askedHere.collectAsStateWithLifecycle()
    val asking by viewModel.asking.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val identity by runtime.identity.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()

    // Choices and open dialogs survive process death; nothing is sent on restore.
    var nearPeer by rememberSaveable { mutableStateOf(vantagePeer != null) }
    var roleCode by rememberSaveable { mutableStateOf<Int?>(null) }
    var announcing by rememberSaveable { mutableStateOf(false) }
    var clearing by rememberSaveable { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }

    val aimed = vantage?.takeIf { nearPeer }
    // Opened to ask near a peer whose route is still being read: neither
    // choice is settled, so nothing goes until it is.
    val settling = nearPeer && !vantageRead
    val aimedName = vantageRow?.let(names::peer)

    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(stringResource(R.string.discover_title), onBack = onBack) {
                    Box {
                        IconButton(onClick = { menuOpen = true }, modifier = Modifier.testTag(Tags.DISCOVER_MORE)) {
                            Icon(painterResource(R.drawable.ic_more_vert), contentDescription = stringResource(R.string.action_more_options))
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.clear_discovered)) },
                                onClick = {
                                    menuOpen = false
                                    clearing = true
                                },
                                modifier = Modifier.testTag(Tags.DISCOVER_CLEAR),
                            )
                        }
                    }
                }
            },
            modifier = Modifier.testTag(Tags.DISCOVER_PAGE),
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                    SectionHeader(stringResource(R.string.discover_section_ask))
                    WhereToAsk(vantage, aimedName, nearPeer = nearPeer && vantage != null, enabled = !settling, onChoose = { nearPeer = it })
                    RoleChoice(roleCode, onChoose = { roleCode = it })
                    val askLabel = if (aimed != null && aimedName != null) {
                        stringResource(R.string.discover_ask_near, userIsolated(aimedName))
                    } else {
                        stringResource(R.string.discover_ask_nearby)
                    }
                    Button(
                        onClick = { viewModel.ask(roleCode?.let(PeerRole::forCode), aimed) },
                        enabled = canSend && !asking && !settling && waitMs <= 0,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.DISCOVER_ASK),
                    ) {
                        Icon(painterResource(R.drawable.ic_ping), contentDescription = null, modifier = Modifier.size(18.dp))
                        Text(askLabel, modifier = Modifier.padding(start = 8.dp), maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                    AskFooter(waitMs, askedHere, aimed == null)
                    ReadyAnnouncement(askedHere && waitMs <= 0 && canSend)

                    SectionHeader(stringResource(R.string.discover_section_heard))
                    if (heard.isEmpty()) {
                        Text(
                            stringResource(R.string.discover_nothing_heard),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).testTag(Tags.DISCOVER_HEARD_EMPTY),
                        )
                    } else {
                        heard.forEach { peer ->
                            HeardRow(peer, names, now, onOpen = { onOpenPeer(peer.address) }, onSave = { viewModel.save(peer) })
                        }
                    }
                    Footnote(stringResource(R.string.discover_window_footer))

                    SectionHeader(stringResource(R.string.discover_section_announce))
                    OutlinedButton(
                        onClick = { announcing = true },
                        enabled = canSend,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.DISCOVER_ANNOUNCE),
                    ) {
                        Icon(painterResource(R.drawable.ic_wifi_tethering), contentDescription = null, modifier = Modifier.size(18.dp))
                        Text(stringResource(R.string.discover_announce), modifier = Modifier.padding(start = 8.dp))
                    }
                    Footnote(stringResource(R.string.discover_announce_footer))
                }
            }
        }
    }

    if (announcing) {
        val name = identity.advertisedName
        ConfirmDialog(
            title = stringResource(R.string.announce_title),
            body = if (name.isBlank()) {
                stringResource(R.string.announce_body_nameless)
            } else {
                stringResource(R.string.announce_body_named, userIsolated(name))
            },
            confirm = stringResource(R.string.announce_confirm),
            onConfirm = {
                announcing = false
                viewModel.announce()
            },
            onDismiss = { announcing = false },
            destructive = false,
        )
    }
    if (clearing) {
        ConfirmDialog(
            title = stringResource(R.string.clear_discovered_title),
            body = stringResource(R.string.clear_discovered_body),
            confirm = stringResource(R.string.clear_discovered_confirm),
            onConfirm = {
                clearing = false
                viewModel.clearDiscovered()
            },
            onDismiss = { clearing = false },
        )
    }
    failure?.let { shown ->
        val (title, body) = when (shown) {
            is DiscoverFailure.NotAsked -> R.string.discover_not_asked_title to R.string.request_failure_body
            is DiscoverFailure.NotAnnounced -> R.string.announce_failed_title to R.string.request_failure_body
            is DiscoverFailure.NotCleared -> R.string.discovered_not_cleared_title to R.string.peer_failure_body
            is DiscoverFailure.NotSaved -> R.string.peer_not_saved_title to R.string.peer_failure_body
        }
        FailureDialog(stringResource(title), stringResource(body), shown.error, viewModel::dismissFailure)
    }
}

/**
 * Where the ask goes: Nearby—direct, or, with a vantage, the hops to the
 * peer. Always shown, even with one choice, so the default is stated.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WhereToAsk(vantage: DiscoveryVantage?, peerName: String?, nearPeer: Boolean, enabled: Boolean, onChoose: (Boolean) -> Unit) {
    val nearby = stringResource(R.string.discover_where_nearby)
    val near = if (vantage != null && peerName != null) {
        pluralStringResource(R.plurals.discover_where_hops, vantage.repeaters.size, vantage.repeaters.size, userIsolated(peerName))
    } else {
        null
    }
    val options = listOfNotNull(false to nearby, near?.let { true to it })
    Choice(
        label = stringResource(R.string.discover_where),
        value = if (nearPeer && near != null) near else nearby,
        options = options,
        selected = nearPeer && near != null,
        onChoose = onChoose,
        enabled = enabled,
        tag = Tags.DISCOVER_WHERE,
        optionTag = { Tags.discoverWhereOption(if (it) "near" else "nearby") },
        modifier = ChoiceRowModifier,
    )
}

/** A dropdown on its own row, inset as the page's other rows. */
private val ChoiceRowModifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)

/** Whom to ask: All nodes, or one role. */
@Composable
private fun RoleChoice(roleCode: Int?, onChoose: (Int?) -> Unit) {
    val all = stringResource(R.string.discover_role_all)
    val options = listOf<Pair<Int?, String>>(null to all) + DISCOVER_ROLES.map { it.code to it.label() }
    Choice(
        label = stringResource(R.string.discover_role),
        value = options.firstOrNull { it.first == roleCode }?.second ?: all,
        options = options,
        selected = roleCode,
        onChoose = onChoose,
        tag = Tags.DISCOVER_ROLE,
        optionTag = { Tags.discoverRoleOption(it?.toString() ?: "all") },
        modifier = ChoiceRowModifier,
    )
}

/** A labeled field that opens its options, as Material's exposed dropdown. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun <T> Choice(
    label: String,
    value: String,
    options: List<Pair<T, String>>,
    selected: T,
    onChoose: (T) -> Unit,
    tag: String,
    optionTag: (T) -> String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded && enabled,
        onExpandedChange = { expanded = it && enabled },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            singleLine = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            colors = ExposedDropdownMenuDefaults.outlinedTextFieldColors(),
            modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable).testTag(tag),
        )
        ExposedDropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }) {
            options.forEach { (option, text) ->
                DropdownMenuItem(
                    text = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    onClick = {
                        expanded = false
                        onChoose(option)
                    },
                    contentPadding = ExposedDropdownMenuDefaults.ItemContentPadding,
                    modifier = Modifier.semantics { this.selected = option == selected }.testTag(optionTag(option)),
                )
            }
        }
    }
}

/**
 * Under the ask: how long until the next one while the core holds it back
 * ("Asked—replies appear below." when this page sent it), else, for an
 * ask in range of this phone, who answers. Not a live region: it changes
 * every second. [ReadyAnnouncement] says once when Ask is back.
 */
@Composable
private fun AskFooter(waitMs: Long, askedHere: Boolean, nearby: Boolean) {
    val locale = LocalConfiguration.current.locales[0]
    val waiting = if (askedHere) R.string.discover_asked_wait else R.string.discover_wait
    val (text, spoken) = when {
        waitMs > 0 -> stringResource(waiting, MeasurePresentation.wholeSecondsLeft(waitMs, locale)) to
            stringResource(waiting, MeasurePresentation.wholeSecondsLeft(waitMs, locale, spoken = true))
        nearby -> stringResource(R.string.discover_nearby_footer).let { it to it }
        else -> return
    }
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .padding(horizontal = 16.dp)
            .semantics { contentDescription = spoken }
            .testTag(Tags.DISCOVER_ASK_FOOTER),
    )
}

/**
 * TalkBack's one word that Ask is back after this page's ask (§3.10): a
 * polite live region that speaks when it gains its text, and is silent
 * otherwise.
 */
@Composable
private fun ReadyAnnouncement(ready: Boolean) {
    val text = stringResource(R.string.discover_ready_spoken)
    Box(
        Modifier
            .semantics {
                liveRegion = LiveRegionMode.Polite
                if (ready) contentDescription = text
            }
            .testTag(Tags.DISCOVER_READY),
    )
}

/** A node heard since the page opened: tapping opens its page; an unsaved one has an add button. */
@Composable
private fun HeardRow(peer: PeerSummary, names: DisplayNames, now: Instant, onOpen: () -> Unit, onSave: () -> Unit) {
    val role = peerRoleLine(peer)
    val state = if (peer.isSaved) {
        if (role != null) stringResource(R.string.discover_saved_role, role) else stringResource(R.string.discover_saved)
    } else {
        val heardAt = peer.lastHeardAtMs?.let(Instant::ofEpochMilli)
        val age = heardAt?.let { ageText(it, maxOf(now, it)) } ?: stringResource(R.string.age_just_now)
        if (role != null) stringResource(R.string.peer_heard_age_role, age, role) else stringResource(R.string.peer_heard_age, age)
    }
    ListItem(
        headlineContent = { Text(names.peer(peer), maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = { Text(state) },
        leadingContent = { PeerAvatar(peer, favorite = peer.isFavorite, describe = false) },
        trailingContent = if (!peer.isSaved) {
            {
                IconButton(onClick = onSave, modifier = Modifier.testTag(Tags.discoverSave(peer.address))) {
                    Icon(painterResource(R.drawable.ic_person_add), contentDescription = stringResource(R.string.add_to_peers))
                }
            }
        } else {
            null
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable(onClickLabel = stringResource(R.string.open_peer_page), onClick = onOpen)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.discoverRow(peer.address)),
    )
}

@Composable
private fun Footnote(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}
