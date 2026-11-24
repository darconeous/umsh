package com.voria.umsh.features.peers.manualpath

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.DialogAction
import com.voria.umsh.designsystem.FullScreenDialogScaffold
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.features.peers.NamedHops
import com.voria.umsh.features.peers.NeighborRow
import com.voria.umsh.features.peers.NeighborSource
import com.voria.umsh.features.peers.PeerSearch
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.models.RepeaterNeighbor
import java.time.Instant

/** Where Add hop's candidates come from. */
enum class HopSource { Neighbors, KnownRepeaters }

/**
 * Add hop (`manual-path.svg` 3): one page for every hop. The trail of the
 * path so far; a filter; Neighbors, what the previous hop reports hearing
 * (the companion radio's own node for the first hop), read only when
 * Refresh is tapped and asked down the path chosen so far; or Known
 * repeaters, what this phone has heard. Neighbors is out of reach when the
 * previous hop is known only by its hint. Tapping a row adds it and the
 * page moves on to the next hop ("Add hop 3"); Done returns. Hops in the
 * path are disabled; the destination, when listed, is pinned at the top
 * with Finish here.
 */
@Composable
fun AddHopPage(
    destination: String,
    draft: ManualPathDraft,
    limits: ManualPathLimits,
    source: NeighborSource,
    onDraft: (ManualPathDraft) -> Unit,
    onDone: () -> Unit,
    onEnterHint: () -> Unit,
) {
    val runtime = LocalAppRuntime.current
    val viewModel = viewModel { AddHopViewModel(source) }
    val listing by viewModel.listing.collectAsStateWithLifecycle()
    val fresh by viewModel.fresh.collectAsStateWithLifecycle()
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val problem by viewModel.problem.collectAsStateWithLifecycle()
    val state by runtime.appState.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val peers = remember(state) { state?.peers.orEmpty() }
    val byAddress = remember(peers) { peers.associateBy { it.address } }
    val hints = draft.hops.map { it.hint.octets }
    val namedFlow = remember(hints) { runtime.hopNames.peers(hints, runtime.appState) }
    val named by namedFlow.collectAsState(NamedHops.NONE)
    val hopNodes = draft.hops.mapIndexed { index, hop -> hop.node?.let(byAddress::get) ?: named.forHints(hints).getOrNull(index) }

    // The node asked for this hop's candidates: the radio's own for the
    // first; else the last hop, when it names a node (a hint is not an
    // address to ask). The ask goes down the hops ahead of it.
    val previous: PeerSummary? = if (draft.hops.isEmpty()) peers.firstOrNull { it.isCompanionRadio } else hopNodes.lastOrNull()
    val pathToPrevious = hints.dropLast(1)
    LaunchedEffect(previous?.address, pathToPrevious) {
        viewModel.ask(previous?.let { Vantage(it.address, pathToPrevious) })
    }
    var chosenSource by rememberSaveable { mutableStateOf(HopSource.Neighbors) }
    val canAskNeighbors = previous != null
    val shownSource = if (canAskNeighbors) chosenSource else HopSource.KnownRepeaters
    var query by rememberSaveable { mutableStateOf("") }

    val add = { hop: DraftHop ->
        onDraft(draft.adding(hop, limits))
        query = ""
        chosenSource = HopSource.Neighbors
    }

    FullScreenDialogScaffold(
        title = stringResource(R.string.add_hop_title, java.text.NumberFormat.getIntegerInstance(LocalConfiguration.current.locales[0]).format(draft.hops.size + 1)),
        navigationIcon = R.drawable.ic_arrow_back,
        navigationDescription = stringResource(R.string.action_back),
        onNavigate = onDone,
        action = DialogAction(stringResource(R.string.add_hop_done), enabled = true, tag = Tags.ADD_HOP_DONE, onClick = onDone),
        modifier = Modifier.testTag(Tags.ADD_HOP_PAGE),
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
            LazyColumn(Modifier.widthIn(max = 600.dp).fillMaxWidth()) {
                item(key = "filter") {
                    // A filled pill (board 3), as the conversation search draws it.
                    TextField(
                        value = query,
                        onValueChange = { query = it },
                        placeholder = { Text(stringResource(R.string.add_hop_filter)) },
                        singleLine = true,
                        leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null) },
                        shape = CircleShape,
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent,
                        ),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.ADD_HOP_FILTER),
                    )
                }
                item(key = "crumb") {
                    Text(
                        crumb(draft, hopNodes, names),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag(Tags.ADD_HOP_CRUMB),
                    )
                }
                item(key = "tabs") {
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                        HopSource.entries.forEachIndexed { index, option ->
                            SegmentedButton(
                                selected = shownSource == option,
                                onClick = { chosenSource = option },
                                // Only Neighbors goes out of reach; Known repeaters, shown then, stays enabled.
                                enabled = option == HopSource.KnownRepeaters || canAskNeighbors,
                                shape = SegmentedButtonDefaults.itemShape(index, HopSource.entries.size),
                                modifier = Modifier.testTag(if (option == HopSource.Neighbors) Tags.ADD_HOP_TAB_NEIGHBORS else Tags.ADD_HOP_TAB_KNOWN),
                            ) {
                                Text(stringResource(if (option == HopSource.Neighbors) R.string.add_hop_neighbors else R.string.add_hop_known), maxLines = 1)
                            }
                        }
                    }
                }
                if (draft.isFull(limits)) {
                    item(key = "full") {
                        Text(
                            pluralStringResource(R.plurals.manual_path_full, limits.maxRouteHints, limits.maxRouteHints),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).testTag(Tags.ADD_HOP_FULL),
                        )
                    }
                    return@LazyColumn
                }
                val reporter = previous
                if (shownSource == HopSource.Neighbors && reporter != null) {
                    neighbors(
                        reporter = reporter,
                        destination = destination,
                        listing = listing,
                        fresh = fresh,
                        busy = busy,
                        problem = problem,
                        query = query,
                        draft = draft,
                        pathToPrevious = pathToPrevious,
                        hopNodes = hopNodes,
                        byAddress = byAddress,
                        names = names,
                        now = now,
                        onRefresh = viewModel::refresh,
                        onLoadMore = viewModel::loadMore,
                        onFinish = onDone,
                        onChoose = { neighbor ->
                            add(DraftHop(RepeaterHints.of(neighbor.hint), node = neighbor.peerAddress, rssiDbm = neighbor.rssiDbm, snrQuarterDb = neighbor.snrQuarterDb))
                        },
                    )
                } else {
                    knownRepeaters(peers, destination, draft, hopNodes, query, names, now) { peer ->
                        add(DraftHop(RepeaterHints.of(peer.hint.octets), node = peer.address))
                    }
                }
                item(key = "enter_hint") {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable(role = Role.Button, onClick = onEnterHint).padding(horizontal = 16.dp).testTag(Tags.ADD_HOP_ENTER_HINT),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(stringResource(R.string.add_hop_enter_hint), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
                    }
                }
            }
        }
    }
}

/** "This phone › Spencer Butte › Skinner Ridge › ?": the path so far, then the hop being chosen. */
@Composable
private fun crumb(draft: ManualPathDraft, hopNodes: List<PeerSummary?>, names: DisplayNames): String {
    var trail = stringResource(R.string.path_this_phone)
    val step = stringResource(R.string.add_hop_crumb_step)
    draft.hops.forEachIndexed { index, hop ->
        val name = hopNodes.getOrNull(index)?.let { userIsolated(names.peer(it)) } ?: isolated(hop.hint.text)
        trail = String.format(step, trail, name)
    }
    return String.format(step, trail, stringResource(R.string.add_hop_crumb_next))
}

/** Whether a node answers Add hop's filter: by name, address prefix or hint, as Peers search; a neighbor by its title or hint too. */
private fun matches(query: String, peer: PeerSummary?, neighbor: RepeaterNeighbor?): Boolean {
    if (query.isBlank()) return true
    if (peer != null) return PeerSearch.matches(peer, query)
    val trimmed = query.trim()
    return neighbor?.name?.contains(trimmed, ignoreCase = true) == true || neighbor?.hintText?.contains(trimmed, ignoreCase = true) == true
}

private fun androidx.compose.foundation.lazy.LazyListScope.neighbors(
    reporter: PeerSummary,
    destination: String,
    listing: RepeaterListing?,
    fresh: Boolean,
    busy: Boolean,
    problem: AddHopProblem?,
    query: String,
    draft: ManualPathDraft,
    pathToPrevious: List<com.voria.umsh.models.Octets>,
    hopNodes: List<PeerSummary?>,
    byAddress: Map<String, PeerSummary>,
    names: DisplayNames,
    now: Instant,
    onRefresh: () -> Unit,
    onLoadMore: () -> Unit,
    onFinish: () -> Unit,
    onChoose: (RepeaterNeighbor) -> Unit,
) {
    val entries = listing?.entries.orEmpty()
    // The destination, when the previous hop hears it: the path can end here.
    entries.firstOrNull { it.peerAddress == destination }?.let { arrived ->
        item(key = "finish") {
            val peer = byAddress[destination]
            ListItem(
                headlineContent = { Text(peer?.let(names::peer) ?: arrived.hintText, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                leadingContent = { peer?.let { PeerAvatar(it, describe = false) } },
                trailingContent = {
                    TextButton(onClick = onFinish, modifier = Modifier.testTag(Tags.ADD_HOP_FINISH)) { Text(stringResource(R.string.add_hop_finish_here)) }
                },
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
        }
    }
    item(key = "neighbors_header") {
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.add_hop_heard_by, userIsolated(names.peer(reporter))),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.weight(1f),
            )
            Box(Modifier.heightIn(min = 48.dp), contentAlignment = Alignment.Center) {
                if (busy) {
                    val asking = stringResource(R.string.neighbors_asking)
                    CircularProgressIndicator(Modifier.size(24.dp).semantics { stateDescription = asking }.testTag(Tags.ADD_HOP_BUSY), strokeWidth = 2.dp)
                } else {
                    TextButton(onClick = onRefresh, modifier = Modifier.testTag(Tags.ADD_HOP_REFRESH)) { Text(stringResource(R.string.neighbors_refresh)) }
                }
            }
        }
    }
    val shown = entries.filter { it.peerAddress != destination }.filter { matches(query, it.peerAddress?.let(byAddress::get), it) }
    items(shown, key = { "neighbor_${it.hint.hex()}" }) { neighbor ->
        val inPath = draft.contains(RepeaterHints.octetsOf(neighbor.hint))
        val known = neighbor.peerAddress?.let(byAddress::get)
        Box(Modifier.testTag(Tags.addHopNeighbor(neighbor.hint.hex()))) {
            NeighborRow(
                neighbor = neighbor,
                known = known,
                reporter = reporter,
                names = names,
                now = now,
                onOpen = if (inPath) null else ({ onChoose(neighbor) }),
                lookUp = null,
                clickLabel = stringResource(R.string.add_hop_choose),
                trailing = if (inPath) ({ InPath() }) else null,
                dimmed = inPath,
            )
        }
    }
    if (shown.isEmpty()) {
        item(key = "neighbors_empty") {
            Text(
                stringResource(if (listing == null) R.string.neighbors_not_read else R.string.neighbors_none),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).testTag(Tags.ADD_HOP_EMPTY),
            )
        }
    }
    problem?.let {
        item(key = "problem") {
            Text(
                stringResource(if (it == AddHopProblem.NoAnswer) R.string.add_hop_no_answer else R.string.add_hop_not_sent),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag(Tags.ADD_HOP_PROBLEM),
            )
        }
    }
    listing?.takeIf { it.nextCursor != null }?.let { more ->
        item(key = "more") {
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp)
                    .clickable(enabled = !busy, role = Role.Button, onClick = onLoadMore)
                    .padding(horizontal = 16.dp)
                    .semantics(mergeDescendants = true) {}
                    .testTag(Tags.ADD_HOP_LOAD_MORE),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.neighbors_load_more),
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (!busy) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
                    modifier = Modifier.weight(1f),
                )
                more.total?.let { total ->
                    Text(stringResource(R.string.neighbors_count, more.entries.size, total), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
    item(key = "neighbors_footer") {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.ADD_HOP_FOOTER)) {
            val reading = when {
                listing == null -> stringResource(R.string.neighbors_nothing_read)
                fresh -> stringResource(R.string.neighbors_read_now)
                else -> {
                    val asOf = Instant.ofEpochMilli(listing.asOfMs)
                    stringResource(R.string.neighbors_last_read, ageText(asOf, maxOf(now, asOf)))
                }
            }
            Text(reading, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (pathToPrevious.isNotEmpty()) {
                val step = stringResource(R.string.add_hop_crumb_step)
                val through = draft.hops.dropLast(1).mapIndexed { index, hop ->
                    hopNodes.getOrNull(index)?.let { userIsolated(names.peer(it)) } ?: isolated(hop.hint.text)
                }.reduce { trail, next -> String.format(step, trail, next) }
                Text(stringResource(R.string.add_hop_asked_through, through), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.knownRepeaters(
    peers: List<PeerSummary>,
    destination: String,
    draft: ManualPathDraft,
    hopNodes: List<PeerSummary?>,
    query: String,
    names: DisplayNames,
    now: Instant,
    onChoose: (PeerSummary) -> Unit,
) {
    val known = peers
        .filter { it.address != destination && !it.isCompanionRadio && it.likelyRepeater }
        .filter { matches(query, it, null) }
        .sortedByDescending { it.lastHeardAtMs ?: Long.MIN_VALUE }
    items(known, key = { "known_${it.address}" }) { peer ->
        val inPath = hopNodes.any { it?.address == peer.address } || draft.contains(RepeaterHints.octetsOf(peer.hint.octets))
        val heard = peer.lastHeardAtMs?.let { Instant.ofEpochMilli(it) }
        ListItem(
            headlineContent = { Text(names.peer(peer), maxLines = 1, overflow = TextOverflow.Ellipsis) },
            supportingContent = heard?.let { { Text(stringResource(R.string.peer_heard_age, ageText(it, maxOf(now, it)))) } },
            leadingContent = { PeerAvatar(peer, favorite = peer.isFavorite, describe = false) },
            trailingContent = if (inPath) ({ InPath() }) else null,
            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            modifier = Modifier
                .alpha(if (inPath) DISABLED_ALPHA else 1f)
                .clickable(enabled = !inPath, onClickLabel = stringResource(R.string.add_hop_choose)) { onChoose(peer) }
                .semantics(mergeDescendants = true) {}
                .testTag(Tags.addHopKnown(peer.address)),
        )
    }
    if (known.isEmpty()) {
        item(key = "known_empty") {
            Text(
                stringResource(R.string.neighbors_none),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).testTag(Tags.ADD_HOP_EMPTY),
            )
        }
    }
}

@Composable
private fun InPath() {
    Text(stringResource(R.string.add_hop_in_path), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

private const val DISABLED_ALPHA = 0.38f
