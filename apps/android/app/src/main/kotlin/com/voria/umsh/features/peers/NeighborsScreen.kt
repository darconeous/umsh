package com.voria.umsh.features.peers

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.models.RepeaterListing
import java.time.Instant

/**
 * Neighboring repeaters (`repeaters-discover.svg` 1–2): what one repeater
 * reports hearing, a page per Refresh, with Load more; opening the page
 * sends nothing. A known neighbor opens its page through [onOpenPeer]; an
 * unknown hint gets the lookup button when the route to the repeater
 * lands there. Pushed on the stack of the page that opened it (D12).
 */
@Composable
fun NeighborsScreen(
    address: String,
    onBack: () -> Unit,
    onOpenPeer: (String) -> Unit,
) {
    NeighborsContent(address, onBack, onOpenPeer)
}

@Composable
private fun NeighborsContent(address: String, onBack: () -> Unit, onOpenPeer: (String) -> Unit) {
    val runtime = LocalAppRuntime.current
    val source = LocalNeighborSource.current
    val viewModel = runtimeViewModel { NeighborsViewModel(it, address, source ?: it) }
    val reporter by viewModel.reporter.collectAsStateWithLifecycle()
    val listing by viewModel.listing.collectAsStateWithLifecycle()
    val loaded by viewModel.loaded.collectAsStateWithLifecycle()
    val fresh by viewModel.fresh.collectAsStateWithLifecycle()
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val noAnswer by viewModel.noAnswer.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val lookupRoute by viewModel.lookupRoute.collectAsStateWithLifecycle()
    val state by runtime.appState.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val peers = remember(state) { state?.peers.orEmpty().associateBy { it.address } }

    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(
                    title = {
                        Column {
                            Text(stringResource(R.string.neighbors_title), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            reporter?.let {
                                Text(
                                    names.peer(it),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    },
                    onBack = onBack,
                ) {
                    Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                        if (busy) {
                            val asking = stringResource(R.string.neighbors_asking)
                            CircularProgressIndicator(
                                Modifier.size(24.dp).semantics { stateDescription = asking }.testTag(Tags.NEIGHBORS_BUSY),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            IconButton(onClick = viewModel::refresh, modifier = Modifier.testTag(Tags.NEIGHBORS_REFRESH)) {
                                Icon(painterResource(R.drawable.ic_refresh), contentDescription = stringResource(R.string.neighbors_refresh))
                            }
                        }
                    }
                }
            },
            modifier = Modifier.testTag(Tags.NEIGHBORS_PAGE),
        ) { padding ->
            val shown = reporter
            if (shown == null || !loaded) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                return@UmshScaffold
            }
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                LazyColumn(Modifier.widthIn(max = 600.dp).fillMaxWidth().testTag(Tags.NEIGHBORS_LIST)) {
                    item(key = "header") { SectionHeader(stringResource(R.string.neighbors_section)) }
                    val entries = listing?.entries.orEmpty()
                    items(entries, key = { it.hint.hex() }) { neighbor ->
                        val known = neighbor.peerAddress?.let(peers::get)
                        NeighborRow(
                            neighbor = neighbor,
                            known = known,
                            reporter = shown,
                            names = names,
                            now = now,
                            onOpen = known?.let { { onOpenPeer(it.address) } },
                            lookUp = if (known == null && lookupRoute != null) ({ viewModel.lookUp(neighbor.hint) }) else null,
                        )
                    }
                    // This line and the no-answer one say how a Refresh ended, so they are announced.
                    if (entries.isEmpty()) {
                        item(key = "empty") {
                            Text(
                                stringResource(if (listing == null) R.string.neighbors_not_read else R.string.neighbors_none),
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.NEIGHBORS_EMPTY),
                            )
                        }
                    }
                    if (noAnswer) {
                        item(key = "no_answer") {
                            Text(
                                stringResource(R.string.neighbors_no_answer),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.NEIGHBORS_NO_ANSWER),
                            )
                        }
                    }
                    listing?.takeIf { it.nextCursor != null }?.let { more ->
                        item(key = "more") { LoadMoreRow(more, enabled = !busy, onClick = viewModel::loadMore) }
                    }
                    item(key = "footer") { ReadingFooter(listing, fresh, now) }
                }
            }
        }
    }
    failure?.let { error ->
        FailureDialog(stringResource(R.string.neighbors_not_asked_title), stringResource(R.string.request_failure_body), error, viewModel::dismissFailure)
    }
}

/** Load more, with how many of the repeater's neighbors are in hand when it said how many it has: "4 of 9". */
@Composable
private fun LoadMoreRow(listing: RepeaterListing, enabled: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.NEIGHBORS_LOAD_MORE),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.neighbors_load_more),
            style = MaterialTheme.typography.bodyLarge,
            color = if (enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
            modifier = Modifier.weight(1f),
        )
        listing.total?.let { total ->
            Text(
                stringResource(R.string.neighbors_count, listing.entries.size, total),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(Tags.NEIGHBORS_COUNT),
            )
        }
    }
}

/**
 * When the listing was read (iOS `RemoteReadingFooter`, trimmed): just now
 * when answered on this visit, else its age; "Nothing read yet." before
 * any answer.
 */
@Composable
private fun ReadingFooter(listing: RepeaterListing?, fresh: Boolean, now: Instant) {
    val text = when {
        listing == null -> stringResource(R.string.neighbors_nothing_read)
        fresh -> stringResource(R.string.neighbors_read_now)
        else -> {
            val asOf = Instant.ofEpochMilli(listing.asOfMs)
            stringResource(R.string.neighbors_last_read, ageText(asOf, maxOf(now, asOf)))
        }
    }
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.NEIGHBORS_FOOTER),
    )
}
