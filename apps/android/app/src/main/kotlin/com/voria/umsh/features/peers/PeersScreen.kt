package com.voria.umsh.features.peers

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.ScrollToTopOnReselect
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.peerRoleLine
import com.voria.umsh.designsystem.rememberListEnvironment
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary

/**
 * The Peers root (D3, `navigation.svg` board 2, `peers-list.svg` board 1),
 * read-only: Favorites, Saved and the companion radio, each row the
 * avatar, name and role. Sort and filter chips, Search, Scan, Add peer,
 * Discover peers and the rows' pages arrive with the peer pages (Phase 3);
 * until then a row has no action.
 */
@Composable
fun PeersScreen(reselects: Int) {
    val environment = rememberListEnvironment()
    val viewModel = runtimeViewModel { PeersViewModel(it, environment) }
    LaunchedEffect(environment) { viewModel.setEnvironment(environment) }
    val sections by viewModel.sections.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    ScrollToTopOnReselect(reselects, list)
    UmshScaffold(
        topBar = { UmshTopAppBar(stringResource(R.string.nav_peers)) },
        modifier = Modifier.testTag(Tags.PEERS_ROOT),
    ) { padding ->
        val shown = sections
        when {
            shown == null -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            shown.isEmpty -> EmptyState(R.drawable.ic_hub_outlined, text = null, modifier = Modifier.padding(padding))
            else -> LazyColumn(state = list, contentPadding = padding, modifier = Modifier.fillMaxSize().testTag(Tags.PEERS_LIST)) {
                section(R.string.peers_section_favorites, Tags.PEERS_FAVORITES, shown.favorites, environment.names)
                section(R.string.peers_section_saved, Tags.PEERS_SAVED, shown.saved, environment.names)
                section(R.string.peers_section_companion_radio, Tags.PEERS_RADIO, shown.radios, environment.names)
            }
        }
    }
}

private fun LazyListScope.section(@StringRes title: Int, tag: String, peers: List<PeerSummary>, names: DisplayNames) {
    if (peers.isEmpty()) return
    item(key = tag) { SectionHeader(stringResource(title), Modifier.testTag(tag)) }
    items(peers, key = { it.address }) { peer -> PeerRow(peer, names) }
}

/** One peer: no click action or label until its page exists (D14). */
@Composable
private fun PeerRow(peer: PeerSummary, names: DisplayNames) {
    val role = peerRoleLine(peer)
    ListItem(
        headlineContent = { Text(names.peer(peer), maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = role?.let { { Text(it) } },
        leadingContent = { PeerAvatar(peer, favorite = peer.isFavorite, describe = false) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(Tags.peerRow(peer.address)),
    )
}

/** The empty detail pane beside the peer list (`list-detail.svg` board 2). */
@Composable
fun NoPeerSelected() {
    DetailPane {
        EmptyState(R.drawable.ic_hub_outlined, stringResource(R.string.no_peer_selected), Modifier.testTag(Tags.EMPTY_DETAIL))
    }
}
