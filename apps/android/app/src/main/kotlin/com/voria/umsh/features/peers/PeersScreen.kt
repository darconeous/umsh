package com.voria.umsh.features.peers

import androidx.annotation.StringRes
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.activity.compose.BackHandler
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ScrollToTopOnReselect
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.FAB_CLEARANCE
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.features.scanner.ScanAction
import com.voria.umsh.features.scanner.ScannedCode
import com.voria.umsh.features.scanner.ScannedCodePreview
import com.voria.umsh.features.share.PeerShareSheet
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.peerRoleLine
import com.voria.umsh.designsystem.rememberListEnvironment
import com.voria.umsh.designsystem.selectionBackground
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import java.time.Instant

/**
 * The Peers root (`peers-list.svg`): Search, the sort and role chips,
 * Favorites, Saved and the companion radio; a row opens the node's page,
 * a long press its actions. [selected] is the peer whose page is beside the
 * list. Discover peers ends the list and is the empty state's one action.
 * The Add peer button opens Add peer ([onAddPeer]); it stands aside for
 * search. Scan opens the QR scanner ([onScan], absent without a camera);
 * a node code it reads comes back as [scanned] and is previewed over the
 * list, as Add peer previews one ([onScannedExit] takes the preview's way out).
 */
@Composable
fun PeersScreen(
    reselects: Int,
    selected: String?,
    onOpen: (String) -> Unit,
    onDiscover: () -> Unit,
    onAddPeer: () -> Unit,
    onScan: (() -> Unit)? = null,
    scanned: ScannedCode? = null,
    onScannedExit: (AddPeerExit) -> Unit = {},
) {
    val environment = rememberListEnvironment()
    val preferences = LocalAppCoreHost.current.preferences
    val viewModel = runtimeViewModel { PeersViewModel(it, environment, preferences.peersSort, preferences::setPeersSort) }
    LaunchedEffect(environment) { viewModel.setEnvironment(environment) }
    val content by viewModel.content.collectAsStateWithLifecycle()
    val sort by viewModel.sort.collectAsStateWithLifecycle()
    val filter by viewModel.filter.collectAsStateWithLifecycle()
    val searching by viewModel.searching.collectAsStateWithLifecycle()
    val query by viewModel.query.collectAsStateWithLifecycle()
    val pendingRemoval by viewModel.pendingRemoval.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val now by LocalAppRuntime.current.now.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    ScrollToTopOnReselect(reselects, list)
    BackHandler(enabled = searching) { viewModel.setSearching(false) }

    UmshScaffold(
        topBar = {
            if (searching) {
                SearchTopBar(query, viewModel::setQuery, onClose = { viewModel.setSearching(false) })
            } else {
                UmshTopAppBar(stringResource(R.string.nav_peers)) {
                    IconButton(onClick = { viewModel.setSearching(true) }, modifier = Modifier.testTag(Tags.PEERS_SEARCH)) {
                        Icon(painterResource(R.drawable.ic_search), contentDescription = stringResource(R.string.action_search))
                    }
                    onScan?.let { ScanAction(it, Modifier.testTag(Tags.PEERS_SCAN)) }
                }
            }
        },
        modifier = Modifier.testTag(Tags.PEERS_ROOT),
        floatingActionButton = {
            if (!searching) {
                ExtendedFloatingActionButton(
                    text = { Text(stringResource(R.string.add_peer)) },
                    // Material hides an icon-and-label FAB's label from TalkBack; the icon speaks it.
                    icon = { Icon(painterResource(R.drawable.ic_person_add), contentDescription = stringResource(R.string.add_peer)) },
                    onClick = onAddPeer,
                    modifier = Modifier.testTag(Tags.PEERS_ADD),
                )
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            // Board 6 draws none: with nothing stored, there is nothing to sort or filter.
            val arrangeable = when (val shown = content) {
                PeersContent.Loading -> false
                is PeersContent.List -> !shown.sections.nothingKnown
                is PeersContent.Search -> true
            }
            if (arrangeable) Chips(sort, filter, onSort = viewModel::setSort, onFilter = viewModel::toggleFilter)
            val names = environment.names
            val rowActions = RowActions(
                onOpen = onOpen,
                onFavorite = viewModel::setFavorite,
                onSave = viewModel::save,
                onRemove = viewModel::askToRemove,
                onShare = viewModel::share,
            )
            when (val shown = content) {
                PeersContent.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(Modifier.testTag(Tags.PEERS_LOADING))
                }
                is PeersContent.List -> if (shown.sections.nothingKnown) {
                    PeersEmpty(onDiscover)
                } else {
                    LazyColumn(
                        state = list,
                        // The last row clears the Add peer button.
                        contentPadding = PaddingValues(bottom = FAB_CLEARANCE),
                        modifier = Modifier.fillMaxSize().testTag(Tags.PEERS_LIST),
                    ) {
                        section(R.string.peers_section_favorites, Tags.PEERS_FAVORITES, shown.sections.favorites, names, selected, now, rowActions)
                        section(R.string.peers_section_saved, Tags.PEERS_SAVED, shown.sections.saved, names, selected, now, rowActions)
                        if (shown.sections.noneSaved) {
                            item(key = "none_saved") {
                                Text(
                                    stringResource(R.string.peers_none_saved),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(16.dp).testTag(Tags.PEERS_NONE_SAVED),
                                )
                            }
                        }
                        section(R.string.peers_section_companion_radio, Tags.PEERS_RADIO, shown.sections.radios, names, selected, now, rowActions)
                        item(key = "discover") { DiscoverRow(onDiscover) }
                    }
                }
                is PeersContent.Search -> LazyColumn(Modifier.fillMaxSize().imePadding().testTag(Tags.PEERS_SEARCH_RESULTS)) {
                    if (shown.results.isEmpty) {
                        item {
                            Text(
                                stringResource(R.string.peers_search_nothing),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(24.dp)
                                    .semantics { liveRegion = LiveRegionMode.Polite }
                                    .testTag(Tags.PEERS_SEARCH_NOTHING),
                            )
                        }
                    }
                    section(R.string.peers_section_saved, Tags.PEERS_SEARCH_SAVED, shown.results.saved, names, selected, now, rowActions)
                    if (shown.results.discovered.isNotEmpty()) {
                        section(
                            R.string.search_section_discovered,
                            Tags.PEERS_SEARCH_DISCOVERED,
                            shown.results.discovered,
                            names,
                            selected,
                            now,
                            rowActions,
                            discovered = true,
                        )
                        item(key = "discovered_footer") {
                            Text(
                                stringResource(R.string.peers_search_discovered_footer),
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

    pendingRemoval?.let { pending ->
        RemovalDialog(
            name = environment.names.peer(pending.peer),
            choice = pending.choice,
            onRemove = viewModel::demote,
            onDelete = viewModel::delete,
            onDismiss = viewModel::cancelRemoval,
        )
    }
    ScannedCodePreview(scanned, onScannedExit)
    val shared by viewModel.shared.collectAsStateWithLifecycle()
    shared?.let { peer -> PeerShareSheet(peer, environment.names.peer(peer), onDismiss = { viewModel.share(null) }) }
    failure?.let { shown ->
        val title = when (shown) {
            is PeersFailure.NotSaved -> R.string.peer_not_saved_title
            is PeersFailure.NotChanged -> R.string.peer_not_changed_title
            is PeersFailure.NotRemoved -> R.string.peer_not_removed_title
            is PeersFailure.NotDeleted -> R.string.peer_not_deleted_title
        }
        FailureDialog(stringResource(title), stringResource(R.string.peer_failure_body), shown.error, viewModel::dismissFailure)
    }
}

/** What a row's tap and long-press menu do. */
private class RowActions(
    val onOpen: (String) -> Unit,
    val onFavorite: (PeerSummary, Boolean) -> Unit,
    val onSave: (PeerSummary) -> Unit,
    val onRemove: (PeerSummary) -> Unit,
    val onShare: (PeerSummary) -> Unit,
)

/** Search in the top bar (`peers-list.svg` 3): Back closes it, the cross empties it. The chips stay beneath. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SearchTopBar(query: String, onQueryChange: (String) -> Unit, onClose: () -> Unit) {
    val focus = remember { FocusRequester() }
    // Saved, so a recreated activity does not raise the keyboard again over results already read.
    var focusedOnce by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (!focusedOnce) {
            focusedOnce = true
            runCatching { focus.requestFocus() }
        }
    }
    TopAppBar(
        navigationIcon = {
            IconButton(onClick = onClose, modifier = Modifier.testTag(Tags.PEERS_SEARCH_CLOSE)) {
                Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.action_back))
            }
        },
        title = {
            TextField(
                value = query,
                onValueChange = onQueryChange,
                placeholder = { Text(stringResource(R.string.search_placeholder), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = Color.Transparent,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent,
                ),
                modifier = Modifier.fillMaxWidth().focusRequester(focus).testTag(Tags.PEERS_SEARCH_FIELD),
            )
        },
        actions = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQueryChange("") }, modifier = Modifier.testTag(Tags.PEERS_SEARCH_CLEAR)) {
                    Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.action_clear_search))
                }
            }
        },
    )
}

/**
 * The sort chip, which opens its menu (`peers-list.svg` 2), and the role
 * filters: one at a time, none shows all. Scrolls sideways when the
 * labels outgrow the screen.
 */
@Composable
private fun Chips(sort: PeerSort, filter: PeerFilter?, onSort: (PeerSort) -> Unit, onFilter: (PeerFilter) -> Unit) {
    var menuOpen by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box {
            val change = stringResource(R.string.peers_sort_change)
            // An assist chip, drawn as the unselected filters beside it: it
            // opens a menu, so it is a button, never a checkbox left unchecked.
            val muted = MaterialTheme.colorScheme.onSurfaceVariant
            AssistChip(
                onClick = { menuOpen = true },
                label = { Text(stringResource(sort.label)) },
                leadingIcon = { Icon(painterResource(R.drawable.ic_sort), contentDescription = null, Modifier.size(18.dp)) },
                trailingIcon = { Icon(painterResource(R.drawable.ic_arrow_drop_down), contentDescription = null, Modifier.size(18.dp)) },
                colors = AssistChipDefaults.assistChipColors(
                    labelColor = muted,
                    leadingIconContentColor = muted,
                    trailingIconContentColor = muted,
                ),
                modifier = Modifier
                    .semantics {
                        onClick(label = change) {
                            menuOpen = true
                            true
                        }
                    }
                    .testTag(Tags.PEERS_SORT),
            )
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                PeerSort.entries.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(stringResource(option.label)) },
                        leadingIcon = {
                            if (option == sort) Icon(painterResource(R.drawable.ic_check), contentDescription = null) else Box(Modifier.size(24.dp))
                        },
                        onClick = {
                            menuOpen = false
                            onSort(option)
                        },
                        modifier = Modifier
                            .semantics { selected = option == sort }
                            .testTag(Tags.peersSortOption(option.name)),
                    )
                }
            }
        }
        PeerFilter.entries.forEach { option ->
            FilterChip(
                selected = option == filter,
                onClick = { onFilter(option) },
                label = { Text(stringResource(option.label)) },
                modifier = Modifier.testTag(Tags.peersFilter(option.name)),
            )
        }
    }
}

@get:StringRes
private val PeerSort.label: Int
    get() = when (this) {
        PeerSort.Alphabetical -> R.string.peers_sort_alphabetical
        PeerSort.RecentlyHeard -> R.string.peers_sort_recently_heard
        PeerSort.LatestMessage -> R.string.peers_sort_latest_message
    }

@get:StringRes
private val PeerFilter.label: Int
    get() = when (this) {
        PeerFilter.People -> R.string.peers_filter_people
        PeerFilter.Sensors -> R.string.peers_filter_sensors
        PeerFilter.Repeaters -> R.string.peers_filter_repeaters
    }

private fun LazyListScope.section(
    @StringRes title: Int,
    tag: String,
    peers: List<PeerSummary>,
    names: DisplayNames,
    selected: String?,
    now: Instant,
    actions: RowActions,
    discovered: Boolean = false,
) {
    if (peers.isEmpty()) return
    item(key = tag) { SectionHeader(stringResource(title), Modifier.testTag(tag)) }
    items(peers, key = { "$tag/${it.address}" }) { peer ->
        PeerRow(peer, names, selected = peer.address == selected, now = now, discovered = discovered, actions = actions)
    }
}

/**
 * One node: tap opens its page, long press its actions (Favorite or
 * Unfavorite, Save for a node not saved, Share, Remove peer); the companion
 * radio's row has no menu. A discovered node shows when it was heard and
 * an add button.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun PeerRow(
    peer: PeerSummary,
    names: DisplayNames,
    selected: Boolean,
    now: Instant,
    discovered: Boolean,
    actions: RowActions,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val role = peerRoleLine(peer)
    val heard = peer.lastHeardAtMs?.takeIf { discovered }?.let { ageText(Instant.ofEpochMilli(it), now) }
    val second = when {
        heard != null && role != null -> stringResource(R.string.peer_heard_age_role, heard, role)
        heard != null -> stringResource(R.string.peer_heard_age, heard)
        else -> role
    }
    val favoriteState = stringResource(R.string.search_favorite_state)
    val colors = MaterialTheme.colorScheme
    Box {
        ListItem(
            headlineContent = { Text(names.peer(peer), maxLines = 1, overflow = TextOverflow.Ellipsis) },
            supportingContent = second?.let { { Text(it) } },
            leadingContent = { PeerAvatar(peer, favorite = peer.isFavorite, describe = false) },
            trailingContent = if (discovered) {
                {
                    IconButton(onClick = { actions.onSave(peer) }, modifier = Modifier.testTag(Tags.peerSave(peer.address))) {
                        Icon(painterResource(R.drawable.ic_person_add), contentDescription = stringResource(R.string.add_to_peers))
                    }
                }
            } else {
                null
            },
            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            modifier = Modifier
                .selectionBackground(selected, Color.Transparent, colors.secondaryContainer, MaterialTheme.shapes.large)
                .combinedClickable(
                    onLongClickLabel = if (peer.isCompanionRadio) null else stringResource(R.string.peer_actions),
                    onLongClick = if (peer.isCompanionRadio) null else ({ menuOpen = true }),
                    onClick = { actions.onOpen(peer.address) },
                )
                .semantics(mergeDescendants = true) {
                    if (peer.isFavorite) stateDescription = favoriteState
                    if (selected) this.selected = true
                }
                .testTag(Tags.peerRow(peer.address)),
        )
        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }, modifier = Modifier.testTag(Tags.PEER_MENU)) {
            if (peer.isSaved) {
                MenuItem(if (peer.isFavorite) R.string.peer_unfavorite else R.string.peer_favorite, Tags.PEER_MENU_FAVORITE) {
                    menuOpen = false
                    actions.onFavorite(peer, !peer.isFavorite)
                }
            } else {
                MenuItem(R.string.peer_save, Tags.PEER_MENU_SAVE) {
                    menuOpen = false
                    actions.onSave(peer)
                }
            }
            MenuItem(R.string.action_share, Tags.PEER_MENU_SHARE) {
                menuOpen = false
                actions.onShare(peer)
            }
            HorizontalDivider()
            DropdownMenuItem(
                text = { Text(stringResource(R.string.remove_peer), color = MaterialTheme.colorScheme.error) },
                onClick = {
                    menuOpen = false
                    actions.onRemove(peer)
                },
                modifier = Modifier.testTag(Tags.PEER_MENU_REMOVE),
            )
        }
    }
}

@Composable
private fun MenuItem(@StringRes text: Int, tag: String, onClick: () -> Unit) {
    DropdownMenuItem(text = { Text(stringResource(text)) }, onClick = onClick, modifier = Modifier.testTag(tag))
}

/** No node known at all (`peers-list.svg` 6): Discover peers is the one action in the body. */
@Composable
private fun PeersEmpty(onDiscover: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 32.dp).testTag(Tags.PEERS_EMPTY),
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.peers_empty_title),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(R.string.peers_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        FilledTonalButton(onClick = onDiscover, modifier = Modifier.padding(top = 8.dp).testTag(Tags.PEERS_EMPTY_DISCOVER)) {
            Icon(painterResource(R.drawable.ic_wifi_tethering), contentDescription = null, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.discover_peers), modifier = Modifier.padding(start = 8.dp))
        }
    }
}

/** The list's last row (`peers-list.svg` 1): Discover peers, in the primary color. */
@Composable
private fun DiscoverRow(onDiscover: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(role = Role.Button, onClick = onDiscover)
            .padding(horizontal = 16.dp)
            .testTag(Tags.PEERS_DISCOVER),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(painterResource(R.drawable.ic_wifi_tethering), contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.discover_peers), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
    }
}

/** The empty detail pane beside the peer list (`list-detail.svg` board 2). */
@Composable
fun NoPeerSelected() {
    DetailPane {
        EmptyState(R.drawable.ic_hub_outlined, stringResource(R.string.no_peer_selected), Modifier.testTag(Tags.EMPTY_DETAIL))
    }
}
