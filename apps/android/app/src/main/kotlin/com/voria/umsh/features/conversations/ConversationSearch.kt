package com.voria.umsh.features.conversations

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SearchBar
import androidx.compose.material3.SearchBarDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.peerRoleLine
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import java.time.Instant

/**
 * Search over conversations, peers and joined channels (`conversation-list.svg`
 * boards 4–5): Material's full-screen search, opened from the top app bar's
 * Search action. Grouped as iOS groups it; messages are not searched.
 * Tapping a row opens its conversation, starting it the first time.
 *
 * The field takes focus, and the keyboard, as search opens and again when
 * the activity is recreated, but only while the list is [current]: search
 * left open under another destination comes back without raising the
 * keyboard, in a back preview or after.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ConversationSearch(
    current: Boolean,
    query: String,
    results: SearchResults?,
    names: DisplayNames,
    now: Instant,
    onQueryChange: (String) -> Unit,
    onClose: () -> Unit,
    onOpenConversation: (String) -> Unit,
    onOpenPeer: (PeerSummary) -> Unit,
    onOpenChannel: (ChannelSummary) -> Unit,
) {
    val focus = remember { FocusRequester() }
    // Saved, so a recreated activity focuses the field again: Compose does not.
    var holdsFocus by rememberSaveable { mutableStateOf(true) }
    SideEffect { if (!current) holdsFocus = false }
    LaunchedEffect(current) {
        if (current && holdsFocus) focus.requestFocus()
    }
    SearchBar(
        inputField = {
            SearchBarDefaults.InputField(
                query = query,
                onQueryChange = onQueryChange,
                onSearch = {},
                expanded = true,
                onExpandedChange = { if (!it) onClose() },
                placeholder = { Text(stringResource(R.string.search_placeholder)) },
                leadingIcon = {
                    IconButton(onClick = onClose, modifier = Modifier.testTag(Tags.SEARCH_CLOSE)) {
                        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.action_back))
                    }
                },
                trailingIcon = if (query.isNotEmpty()) {
                    {
                        IconButton(onClick = { onQueryChange("") }, modifier = Modifier.testTag(Tags.SEARCH_CLEAR)) {
                            Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.action_clear_search))
                        }
                    }
                } else {
                    null
                },
                modifier = Modifier
                    .focusRequester(focus)
                    .focusProperties { canFocus = current }
                    .testTag(Tags.SEARCH_FIELD),
            )
        },
        expanded = true,
        onExpandedChange = { if (!it) onClose() },
        modifier = Modifier.testTag(Tags.SEARCH_VIEW),
    ) {
        // The results on the list's own background, under the search field's bar (board 4).
        LazyColumn(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).imePadding()) {
            when {
                results == null -> Unit
                results.isEmpty -> item {
                    Text(
                        stringResource(R.string.search_nothing),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        // Announced as the results empty out under a query being typed.
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp)
                            .semantics { liveRegion = LiveRegionMode.Polite }
                            .testTag(Tags.SEARCH_NOTHING),
                    )
                }
                else -> results(results, names, now, onOpenConversation, onOpenPeer, onOpenChannel)
            }
        }
    }
}

private fun LazyListScope.results(
    results: SearchResults,
    names: DisplayNames,
    now: Instant,
    onOpenConversation: (String) -> Unit,
    onOpenPeer: (PeerSummary) -> Unit,
    onOpenChannel: (ChannelSummary) -> Unit,
) {
    if (results.conversations.isNotEmpty()) {
        item { Header(R.string.search_section_conversations, Tags.SEARCH_CONVERSATIONS) }
        items(results.conversations, key = { "c/${it.address}" }) { row ->
            ConversationRowItem(
                row = row,
                now = now,
                selected = false,
                onOpen = { onOpenConversation(row.address) },
                onRemove = null,
                modifier = Modifier.testTag(Tags.searchConversation(row.address)),
            )
        }
    }
    if (results.peers.isNotEmpty()) {
        item { Header(R.string.search_section_peers, Tags.SEARCH_PEERS) }
        items(results.peers, key = { "p/${it.address}" }) { peer -> PeerResult(peer, names, onOpenPeer) }
    }
    if (results.channels.isNotEmpty()) {
        item { Header(R.string.search_section_channels, Tags.SEARCH_CHANNELS) }
        items(results.channels, key = { "h/${it.id}" }) { channel -> ChannelResult(channel, names, onOpenChannel) }
        item { Footer(R.string.search_channels_footer) }
    }
    if (results.discovered.isNotEmpty()) {
        item { Header(R.string.search_section_discovered, Tags.SEARCH_DISCOVERED) }
        items(results.discovered, key = { "d/${it.address}" }) { peer -> PeerResult(peer, names, onOpenPeer) }
        item { Footer(R.string.search_discovered_footer) }
    }
}

@Composable
private fun Header(text: Int, tag: String) = SectionHeader(stringResource(text), Modifier.testTag(tag))

@Composable
private fun Footer(text: Int) {
    Text(
        stringResource(text),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 8.dp),
    )
}

@Composable
private fun PeerResult(peer: PeerSummary, names: DisplayNames, onOpen: (PeerSummary) -> Unit) {
    val role = peerRoleLine(peer)
    // The star is drawn on the avatar; TalkBack hears it here, since search has no Favorites header.
    val favorite = stringResource(R.string.search_favorite_state)
    ListItem(
        headlineContent = { Text(names.peer(peer)) },
        supportingContent = role?.let { { Text(it) } },
        leadingContent = { PeerAvatar(peer, favorite = peer.isFavorite, describe = false) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable { onOpen(peer) }
            .semantics(mergeDescendants = true) { if (peer.isFavorite) stateDescription = favorite }
            .testTag(Tags.searchPeer(peer.address)),
    )
}

@Composable
private fun ChannelResult(channel: ChannelSummary, names: DisplayNames, onOpen: (ChannelSummary) -> Unit) {
    val kind = when (ConversationList.kindLabel(channel)) {
        ConversationList.KindLabel.Builtin -> R.string.channel_kind_builtin
        ConversationList.KindLabel.Named -> R.string.channel_kind_named
        ConversationList.KindLabel.Private -> R.string.channel_kind_private
    }
    ListItem(
        headlineContent = { Text(names.channel(channel)) },
        supportingContent = { Text(stringResource(kind)) },
        leadingContent = { ChannelBadge(channel, describe = false) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable { onOpen(channel) }
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.searchChannel(channel.id)),
    )
}
