package com.voria.umsh.features.peers

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.LocalUiTimings
import com.voria.umsh.designsystem.ageSpokenText
import com.voria.umsh.designsystem.identifierAnnotated
import com.voria.umsh.designsystem.label
import com.voria.umsh.designsystem.listText
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.SignatureState
import com.voria.umsh.services.notifications.NotificationPermission
import com.voria.umsh.services.notifications.rememberNotificationsTurnOn
import java.time.Instant

/**
 * A peer's page (`peer-page.svg`): who it is, what can be done, the three
 * facts people check, its notifications, and About. Rendered from the live
 * row by address, so identity replies and route changes land while it is
 * open; the shell closes it once the node is gone. [onBack] is null beside
 * the Peers list. Ping opens its sheet on the ping it sends; the strip's
 * Route opens the Route page. The map card, Manage and Share arrive
 * later (D14).
 */
@Composable
fun PeerPageScreen(
    address: String,
    onBack: (() -> Unit)?,
    /** Message: its conversation, opened; the shell shows it. */
    onConversation: (String) -> Unit,
    /** The strip's Route cell: the Route page, on this page's stack. */
    onOpenRoute: () -> Unit,
    /** The Neighbors verb: the repeater's Neighboring repeaters, on this page's stack. */
    onOpenNeighbors: () -> Unit,
    /** A named repeater on a ping's path: its page, on this page's stack. */
    onOpenPeer: (String) -> Unit,
) {
    val viewModel = runtimeViewModel { PeerPageViewModel(it, address) }
    val timings = LocalUiTimings.current
    val ping = runtimeViewModel { PingViewModel(it, address, timings.pingAgainAfterMs) }
    val pingShown by ping.shown.collectAsStateWithLifecycle()
    val model by viewModel.model.collectAsStateWithLifecycle()
    val route by viewModel.route.collectAsStateWithLifecycle()
    val distance by viewModel.distance.collectAsStateWithLifecycle()
    val messageCount by viewModel.messageCount.collectAsStateWithLifecycle()
    val pendingFavorite by viewModel.pendingFavorite.collectAsStateWithLifecycle()
    val pendingWatch by viewModel.pendingWatch.collectAsStateWithLifecycle()
    val pendingMessages by viewModel.pendingMessages.collectAsStateWithLifecycle()
    val asking by viewModel.asking.collectAsStateWithLifecycle()
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val now by LocalAppRuntime.current.now.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val context = LocalContext.current
    val turnOnNotifications = rememberNotificationsTurnOn(LocalAppCoreHost.current.preferences)
    val opened by rememberUpdatedState(onConversation)
    LaunchedEffect(viewModel) { viewModel.conversationOpened.collect { opened(it) } }

    // Dialogs keep their input across process death and send nothing when restored.
    var renaming by rememberSaveable { mutableStateOf<String?>(null) }
    var removing by rememberSaveable { mutableStateOf(false) }
    var clearing by rememberSaveable { mutableStateOf(false) }

    val shown = model
    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(title = {}, onBack = onBack) {
                    val peer = shown?.peer
                    if (peer != null && peer.isSaved && !peer.isCompanionRadio) {
                        val favorite = pendingFavorite ?: peer.isFavorite
                        IconButton(onClick = { viewModel.setFavorite(!favorite) }, modifier = Modifier.testTag(Tags.PEER_FAVORITE)) {
                            Icon(
                                painterResource(if (favorite) R.drawable.ic_star else R.drawable.ic_star_outline),
                                contentDescription = stringResource(if (favorite) R.string.action_unfavorite else R.string.action_favorite),
                                tint = if (favorite) UmshColors.fixed.favoriteStar else LocalContentColor.current,
                            )
                        }
                    }
                }
            },
            modifier = Modifier.testTag(Tags.PEER_PAGE),
        ) { padding ->
            if (shown == null) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                return@UmshScaffold
            }
            val peer = shown.peer
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp),
                ) {
                    Hero(peer, names, onRename = { renaming = DisplayNames.given(peer).orEmpty() })
                    val verbs = PeerVerbs.offered(peer, PeerVerbs.AVAILABLE)
                    if (verbs.isNotEmpty()) {
                        FlowRow(
                            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            verbs.forEach { verb ->
                                when (verb) {
                                    PeerVerb.Identify -> VerbTile(R.drawable.ic_person_search, R.string.verb_identify, Tags.PEER_VERB_IDENTIFY, !busy && !asking, viewModel::askIdentity)
                                    PeerVerb.Message -> VerbTile(R.drawable.ic_chat, R.string.verb_message, Tags.PEER_VERB_MESSAGE, !busy, viewModel::message)
                                    PeerVerb.Ping -> VerbTile(R.drawable.ic_ping, R.string.verb_ping, Tags.PEER_VERB_PING, true, ping::ping)
                                    PeerVerb.Neighbors -> VerbTile(R.drawable.ic_cell_tower, R.string.verb_neighbors, Tags.PEER_VERB_NEIGHBORS, true, onOpenNeighbors)
                                }
                            }
                        }
                    }
                    if (!peer.isSaved && !peer.isCompanionRadio) {
                        Button(
                            onClick = viewModel::addToPeers,
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.PEER_ADD),
                        ) {
                            Text(stringResource(R.string.add_to_peers))
                        }
                    }
                    PeerGlanceStrip(
                        heard = peer.lastHeardAtMs?.let(Instant::ofEpochMilli),
                        now = now,
                        route = route,
                        distance = distance,
                        onOpenRoute = onOpenRoute,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )

                    val conversation = shown.conversation
                    val offersWatch = !peer.isCompanionRadio
                    if (conversation != null || offersWatch) {
                        SectionHeader(stringResource(R.string.peer_section_notifications))
                        if (conversation != null) {
                            SwitchRow(R.string.peer_notify_messages, pendingMessages ?: conversation.notificationsEnabled, Tags.PEER_NOTIFY_MESSAGES) {
                                viewModel.setMessageNotifications(it)
                            }
                        }
                        if (offersWatch) {
                            SwitchRow(R.string.peer_notify_next_heard, pendingWatch ?: peer.notifyWhenHeard, Tags.PEER_NOTIFY_HEARD) { armed ->
                                // Armed in the core whatever Android allows; then the ask,
                                // or Android's settings once it has stopped asking.
                                viewModel.setNotifyWhenHeard(armed)
                                if (armed && !NotificationPermission.enabled(context)) turnOnNotifications()
                            }
                        }
                    }

                    SectionHeader(stringResource(R.string.peer_section_about))
                    LabeledRow(stringResource(R.string.details_address), stacked = true) {
                        CanonicalAddress(peer.address, textAlign = TextAlign.Start, modifier = Modifier.testTag(Tags.PEER_ADDRESS))
                    }
                    peer.capabilities?.takeIf { it.bits != 0 }?.let { capabilities ->
                        val text = capabilities.listText()
                        if (text.isNotEmpty()) {
                            LabeledRow(stringResource(R.string.peer_capabilities)) {
                                Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag(Tags.PEER_CAPABILITIES))
                            }
                        }
                    }
                    if (!peer.isCompanionRadio) AdvertisedRow(peer, now, asking, busy, viewModel::askIdentity)
                    val advertised = peer.advertised
                    if (advertised != null && !peer.advertisementAttributable) {
                        SignatureWarning(advertised.signature)
                    }

                    if (conversation != null && messageCount > 0) {
                        DestructiveRow(R.string.clear_all_messages, Tags.PEER_CLEAR_MESSAGES) { clearing = true }
                    }
                    if (RemovalChoice.forPage(peer, conversation != null) != null) {
                        DestructiveRow(R.string.remove_peer, Tags.PEER_REMOVE) { removing = true }
                    }
                }
            }
        }
    }

    val peer = shown?.peer
    if (pingShown && peer != null) {
        PingSheet(ping, LocalAppRuntime.current, peer, names, now) { onOpenPeer(it.address) }
    }
    renaming?.let { text ->
        if (peer == null) return@let
        RenameDialog(
            text = text,
            advertisedName = peer.advertisedName?.takeIf { it.isNotBlank() },
            onChange = { renaming = it },
            onSave = {
                // The name it calls itself is no alias: saved as none, so a new advertised name shows.
                val name = text.trim()
                viewModel.rename(if (name == peer.advertisedName) "" else name)
                renaming = null
            },
            onDismiss = { renaming = null },
        )
    }
    if (removing && peer != null) {
        val choice = RemovalChoice.forPage(peer, shown.conversation != null)
        if (choice == null) {
            // Restored over a node that has nothing left to remove: dropped, outside composition.
            LaunchedEffect(Unit) { removing = false }
        } else {
            RemovalDialog(
                name = names.peer(peer),
                choice = choice,
                onRemove = {
                    removing = false
                    viewModel.demote()
                },
                onDelete = {
                    removing = false
                    viewModel.delete(withConversation = choice is RemovalChoice.WithConversation)
                },
                onDismiss = { removing = false },
            )
        }
    }
    if (clearing && peer != null) {
        ClearMessagesDialog(
            name = names.peer(peer),
            count = messageCount,
            onConfirm = {
                clearing = false
                viewModel.clearMessages()
            },
            onDismiss = { clearing = false },
        )
    }
    failure?.let { shownFailure ->
        val (title, body) = when (shownFailure) {
            is PeerPageFailure.NotChanged -> R.string.peer_not_changed_title to R.string.peer_failure_body
            is PeerPageFailure.NotSaved -> R.string.peer_not_saved_title to R.string.peer_failure_body
            is PeerPageFailure.NotRenamed -> R.string.peer_not_renamed_title to R.string.peer_failure_body
            is PeerPageFailure.NotRemoved -> R.string.peer_not_removed_title to R.string.peer_failure_body
            is PeerPageFailure.NotDeleted -> R.string.peer_not_deleted_title to R.string.peer_failure_body
            is PeerPageFailure.NotCleared -> R.string.messages_not_cleared_title to R.string.peer_failure_body
            is PeerPageFailure.NotAsked -> R.string.identity_not_asked_title to R.string.request_failure_body
            is PeerPageFailure.NotOpened -> R.string.open_failed_title to R.string.open_failed_body
        }
        FailureDialog(stringResource(title), stringResource(body), shownFailure.error, viewModel::dismissFailure)
    }
}

/**
 * The page's title: the alias or advertised name, else "Companion radio"
 * for the radio's own, else the node's hint (`peer-page.svg` 4).
 */
@Composable
private fun Hero(peer: PeerSummary, names: DisplayNames, onRename: () -> Unit) {
    val given = DisplayNames.given(peer)
    val renamable = !peer.isCompanionRadio
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        PeerAvatar(peer, size = AvatarSize.Page, favorite = peer.isFavorite)
        val titleStyle = MaterialTheme.typography.headlineSmall
        val renameLabel = stringResource(R.string.peer_rename_action)
        val titleModifier = Modifier
            .clip(MaterialTheme.shapes.small)
            .then(if (renamable) Modifier.clickable(onClickLabel = renameLabel, onClick = onRename) else Modifier)
            .padding(horizontal = 8.dp, vertical = 2.dp)
            .testTag(Tags.PEER_NAME)
        when {
            given != null -> Text(given, style = titleStyle, textAlign = TextAlign.Center, modifier = titleModifier)
            peer.isCompanionRadio -> Text(names.companionRadio, style = titleStyle, textAlign = TextAlign.Center, modifier = titleModifier)
            else -> Text(identifierAnnotated(peer.hint.text, monospace = false), style = titleStyle, textAlign = TextAlign.Center, modifier = titleModifier)
        }
        subtitle(peer)?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag(Tags.PEER_SUBTITLE),
            )
        }
    }
}

/**
 * "Companion radio" for the radio's own, unless that is already its title;
 * else the role, with the advertised name when an alias hides it.
 */
@Composable
private fun subtitle(peer: PeerSummary): String? {
    if (peer.isCompanionRadio) return DisplayNames.given(peer)?.let { stringResource(R.string.companion_radio) }
    val role = peer.role.takeIf { it != PeerRole.Unknown }?.label()
    val hidden = peer.advertisedName?.takeIf { it.isNotBlank() && !peer.alias.isNullOrBlank() && it != peer.alias }
    return when {
        hidden != null && role != null -> stringResource(R.string.peer_subtitle_role_name, role, userIsolated(hidden))
        hidden != null -> stringResource(R.string.peer_subtitle_name, userIsolated(hidden))
        else -> role
    }
}

/** One verb: a tonal circle and its label, as Your identity's actions. */
@Composable
private fun VerbTile(@DrawableRes icon: Int, @StringRes label: Int, tag: String, enabled: Boolean, onClick: () -> Unit) {
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
            stringResource(label),
            style = MaterialTheme.typography.labelMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 4.dp),
        )
    }
}

@Composable
private fun SwitchRow(@StringRes title: Int, checked: Boolean, tag: String, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(title)) },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.toggleable(value = checked, role = Role.Switch, onValueChange = onChange).testTag(tag),
    )
}

/** A label over its value, or beside it ([stacked] false) when it is short. */
@Composable
private fun LabeledRow(label: String, stacked: Boolean = false, value: @Composable () -> Unit) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = { value() },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = if (stacked) Modifier else Modifier.semantics(mergeDescendants = true) {},
    )
}

/** When the node last said who it is, and Ask again, which spins while the ask is out. */
@Composable
private fun AdvertisedRow(peer: PeerSummary, now: Instant, asking: Boolean, busy: Boolean, onAsk: () -> Unit) {
    val received = peer.advertisementReceivedAtMs
    val value = when {
        received != null -> ageSpokenText(Instant.ofEpochMilli(received), now)
        peer.advertised != null -> stringResource(R.string.peer_advertised_imported)
        else -> stringResource(R.string.peer_advertised_never)
    }
    val waiting = stringResource(R.string.waiting_for_reply)
    ListItem(
        headlineContent = { Text(stringResource(R.string.peer_advertised)) },
        supportingContent = { Text(value, modifier = Modifier.testTag(Tags.PEER_ADVERTISED)) },
        trailingContent = {
            if (asking) {
                Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        Modifier.size(24.dp).semantics { stateDescription = waiting }.testTag(Tags.PEER_ASKING),
                        strokeWidth = 2.dp,
                    )
                }
            } else {
                IconButton(onClick = onAsk, enabled = !busy, modifier = Modifier.testTag(Tags.PEER_ASK_AGAIN)) {
                    Icon(painterResource(R.drawable.ic_refresh), contentDescription = stringResource(R.string.peer_ask_again))
                }
            }
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

/** Silent for a valid signature; a quiet line for none; red for one that fails. */
@Composable
private fun SignatureWarning(signature: SignatureState) {
    val (text, color) = when (signature) {
        SignatureState.Valid -> return
        SignatureState.Unsigned -> R.string.identity_unsigned_warning to MaterialTheme.colorScheme.onSurfaceVariant
        SignatureState.Invalid -> R.string.identity_invalid_warning to MaterialTheme.colorScheme.error
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).semantics(mergeDescendants = true) {}.testTag(Tags.PEER_SIGNATURE_WARNING),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(painterResource(R.drawable.ic_warning), contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
        Text(stringResource(text), style = MaterialTheme.typography.bodySmall, color = color)
    }
}

@Composable
private fun DestructiveRow(@StringRes text: Int, tag: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(stringResource(text), color = MaterialTheme.colorScheme.error) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.clickable(role = Role.Button, onClick = onClick).testTag(tag),
    )
}

/** Clear all messages? (as `conversation-info.svg` 5's), with the count on its button. */
@Composable
private fun ClearMessagesDialog(name: String, count: Long, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    val shown = count.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    ConfirmDialog(
        title = stringResource(R.string.clear_messages_title),
        body = stringResource(R.string.clear_messages_body, userIsolated(name)),
        confirm = pluralStringResource(R.plurals.clear_messages_confirm, shown, shown),
        onConfirm = onConfirm,
        onDismiss = onDismiss,
    )
}

private const val DISABLED_ALPHA = 0.38f
