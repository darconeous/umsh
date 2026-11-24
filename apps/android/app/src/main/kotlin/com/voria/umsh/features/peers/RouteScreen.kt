package com.voria.umsh.features.peers

import android.icu.text.ListFormatter
import androidx.annotation.DrawableRes
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.LocalCopyNotice
import com.voria.umsh.designsystem.LocalTimeFormatting
import com.voria.umsh.designsystem.PathRail
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteState
import com.voria.umsh.models.RouteSummary
import com.voria.umsh.services.format.holdEnd
import java.time.Instant

/**
 * Route (`ping-route.svg` 4–5): how this phone reaches a peer. The path,
 * numbered by leg, with the ambiguity footer when a hop's name was guessed
 * from its hint; Next send; when it was confirmed, or, for a held path,
 * its flood allowance, when the hold ends and the last ack; then Reset
 * route, or Clear manual path for a held one; Ask near this node, when
 * the core has a way to steer an ask there, opens Discover aimed at the
 * peer ([onAskNear]); Edit opens the manual path editor ([onEdit]),
 * seeded from this route. Pushed on the stack of the page that opened it
 * (D12).
 */
@Composable
fun RouteScreen(
    address: String,
    onBack: () -> Unit,
    onOpenPeer: (PeerSummary) -> Unit,
    onAskNear: () -> Unit,
    onEdit: () -> Unit,
) {
    RouteContent(address, onBack, onOpenPeer, onAskNear, onEdit)
}

@Composable
private fun RouteContent(address: String, onBack: () -> Unit, onOpenPeer: (PeerSummary) -> Unit, onAskNear: () -> Unit, onEdit: () -> Unit) {
    val runtime = LocalAppRuntime.current
    val viewModel = runtimeViewModel { RouteViewModel(it, address) }
    val peer by viewModel.peer.collectAsStateWithLifecycle()
    val route by viewModel.route.collectAsStateWithLifecycle()
    val hopNames by viewModel.hopNames.collectAsStateWithLifecycle()
    val busy by viewModel.busy.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val radio by runtime.radio.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val notice = LocalCopyNotice.current
    LaunchedEffect(viewModel) { viewModel.notices.collect { notice.show(it) } }

    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(stringResource(R.string.route_title), onBack = onBack) {
                    // Not offered while there is no session to hold a path in (iOS).
                    if (route is RouteState.Loaded) {
                        IconButton(onClick = onEdit, modifier = Modifier.testTag(Tags.ROUTE_EDIT)) {
                            Icon(painterResource(R.drawable.ic_edit), contentDescription = stringResource(R.string.route_edit))
                        }
                    }
                }
            },
            modifier = Modifier.testTag(Tags.ROUTE_PAGE),
        ) { padding ->
            val shown = peer
            if (shown == null || route == RouteState.Loading) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                return@UmshScaffold
            }
            val loaded = (route as? RouteState.Loaded)?.route
            val layout = RouteLegs.of(route, radio?.name?.takeIf { it.isNotBlank() }).named(hopNames.forHints(loaded?.hints?.map { it.octets }.orEmpty()))
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp),
                ) {
                    PathHeader(loaded)
                    PathRail(
                        stops = layout.stops,
                        legs = layout.legs,
                        peer = shown,
                        names = names,
                        tentative = layout.tentative,
                        onOpen = onOpenPeer,
                        lookUp = { hint, preceding -> runtime.lookUpRepeaterHint(hint, preceding) },
                        modifier = Modifier.padding(horizontal = 16.dp).testTag(Tags.ROUTE_PATH),
                    )
                    if (layout.hasGuessedNames) {
                        Footnote(stringResource(R.string.repeater_hint_footer), Tags.ROUTE_AMBIGUITY)
                    }
                    RouteKindText.nextSend(route)?.let {
                        DetailRow(stringResource(R.string.route_next_send), it.resolve(), Tags.ROUTE_NEXT_SEND)
                    }
                    if (loaded != null) Details(loaded, now)
                    if (loaded != null) {
                        if (loaded.discoveryVantage != null) {
                            ActionRow(R.string.route_ask_near, Tags.ROUTE_ASK_NEAR, enabled = true, icon = R.drawable.ic_ping, destructive = false, onClick = onAskNear)
                        }
                        if (loaded.isHeld) {
                            ActionRow(R.string.clear_manual_path, Tags.ROUTE_CLEAR_MANUAL, enabled = !busy, icon = R.drawable.ic_cancel, onClick = viewModel::clearManualPath)
                        } else {
                            ActionRow(
                                R.string.reset_route,
                                Tags.ROUTE_RESET,
                                enabled = !busy && loaded.kind != RouteKind.Unknown,
                                onClick = viewModel::resetRoute,
                            )
                        }
                        explanation(loaded, shown, names.peer(shown))?.let { Footnote(it, Tags.ROUTE_EXPLANATION) }
                    }
                }
            }
        }
    }
    failure?.let { shownFailure ->
        val title = when (shownFailure) {
            is RouteFailure.NotReset -> R.string.route_not_reset_title
            is RouteFailure.NotCleared -> R.string.manual_path_not_cleared_title
        }
        FailureDialog(stringResource(title), stringResource(R.string.peer_failure_body), shownFailure.error, viewModel::dismissFailure)
    }
}

/** "Path", and the route's length beside it when it has one and is not direct. */
@Composable
private fun PathHeader(route: RouteSummary?) {
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp).semantics(mergeDescendants = true) { heading() },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            stringResource(R.string.route_path),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f),
        )
        val hops = route?.takeIf { !it.isDirect }?.let { it.hopCount ?: it.hints.takeIf { hints -> hints.isNotEmpty() }?.let { hints -> hints.size + 1 } }
        if (hops != null) {
            Text(
                RouteText.Counted(R.plurals.route_hops, hops).resolve(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(Tags.ROUTE_HOPS),
            )
        }
    }
}

/** Confirmed, or for a held path Then flood, Held until and Last ack; Regions when a flood was learned in some. */
@Composable
private fun Details(route: RouteSummary, now: Instant) {
    val dash = DASH
    val confirmed = route.confirmedAtMs?.let { ageText(Instant.ofEpochMilli(it), maxOf(now, Instant.ofEpochMilli(it))) } ?: dash
    if (route.isHeld) {
        val flood = route.holdFloodHops
        if (route.hints.isNotEmpty() && flood != null) {
            DetailRow(stringResource(R.string.route_then_flood), RouteKindText.flood(flood).resolve(), Tags.ROUTE_THEN_FLOOD)
        }
        route.holdUntilMs?.let {
            DetailRow(stringResource(R.string.route_held_until), LocalTimeFormatting.current.holdEnd(Instant.ofEpochMilli(it), now), Tags.ROUTE_HELD_UNTIL)
        }
        DetailRow(stringResource(R.string.route_last_ack), confirmed, Tags.ROUTE_LAST_ACK)
    } else {
        DetailRow(stringResource(R.string.route_confirmed), confirmed, Tags.ROUTE_CONFIRMED)
    }
    if (route.floodRegions.isNotEmpty()) {
        DetailRow(stringResource(R.string.route_regions), ListFormatter.getInstance(LocalConfiguration.current.locales[0]).format(route.floodRegions.map { isolated(regionLabel(it)) }), Tags.ROUTE_REGIONS)
    }
}

/** Where the route came from: a hold that learned paths wait out, or the peer's last reply. */
@Composable
private fun explanation(route: RouteSummary, peer: PeerSummary, name: String): String? = when {
    route.isHeld -> stringResource(R.string.route_held_explanation)
    route.kind == RouteKind.Unknown || peer.isCompanionRadio -> null
    else -> stringResource(R.string.route_learned_from, userIsolated(name))
}

@Composable
private fun DetailRow(label: String, value: String, tag: String) {
    val unknown = value == DASH
    val unknownSpoken = stringResource(R.string.route_value_unknown)
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp)
            .semantics(mergeDescendants = true) { if (unknown) stateDescription = unknownSpoken }
            .testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.End,
            modifier = if (unknown) Modifier.clearAndSetSemantics {} else Modifier,
        )
    }
}

@Composable
private fun ActionRow(text: Int, tag: String, enabled: Boolean, @DrawableRes icon: Int? = null, destructive: Boolean = true, onClick: () -> Unit) {
    val color = if (!enabled) MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f) else if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp)
            .testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (icon != null) Icon(painterResource(icon), contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
        Text(stringResource(text), style = MaterialTheme.typography.bodyLarge, color = color)
    }
}

@Composable
private fun Footnote(text: String, tag: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(tag),
    )
}

/** A value not known, drawn as a dash; TalkBack reads the label, then "Unknown". */
private const val DASH = "—"
