package com.voria.umsh.features.peers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.hideFromAccessibility
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.LocalCopyNotice
import com.voria.umsh.designsystem.MeasurePresentation
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.PathRail
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.reasonText
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.PingReply
import java.time.Instant

/**
 * Ping (`ping-route.svg` 1–3): a bottom sheet over the peer page showing
 * the ping the page's Ping sent. The round trip and hops, Ping again, the
 * path the reply took with how each leg was heard, Reset route, and this
 * visit's earlier pings. A named repeater opens its page ([onOpenPeer],
 * which closes the sheet first); an unmatched hint offers the lookup.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PingSheet(
    viewModel: PingViewModel,
    runtime: AppRuntime,
    peer: PeerSummary,
    names: DisplayNames,
    now: Instant,
    onOpenPeer: (PeerSummary) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = viewModel::dismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(Tags.PING_SHEET),
    ) {
        // The sheet's window covers the shell's snackbar host: Reset route's notices are drawn in it.
        NoticeHost(Modifier.fillMaxWidth()) {
            val notice = LocalCopyNotice.current
            LaunchedEffect(viewModel) { viewModel.notices.collect { notice.show(it) } }
            PingContent(viewModel, runtime, peer, names, now) { opened ->
                viewModel.dismiss()
                onOpenPeer(opened)
            }
        }
    }
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    failure?.let { error ->
        FailureDialog(
            stringResource(R.string.route_not_reset_title),
            stringResource(R.string.peer_failure_body),
            error,
            viewModel::dismissFailure,
        )
    }
}

@Composable
private fun PingContent(
    viewModel: PingViewModel,
    runtime: AppRuntime,
    peer: PeerSummary,
    names: DisplayNames,
    now: Instant,
    onOpenPeer: (PeerSummary) -> Unit,
) {
    val outstanding by viewModel.outstanding.collectAsStateWithLifecycle()
    val latest by viewModel.latest.collectAsStateWithLifecycle()
    val history by viewModel.history.collectAsStateWithLifecycle()
    val canPingAgain by viewModel.canPingAgain.collectAsStateWithLifecycle()
    val resetting by viewModel.resetting.collectAsStateWithLifecycle()
    val replyNames by viewModel.replyNames.collectAsStateWithLifecycle()

    val waiting = outstanding
    val reply = (latest?.outcome as? PingOutcome.Reply)?.reply?.takeIf { waiting == null }
    val layout = when {
        waiting != null -> PingPath.unanswered(broken = false)
        reply != null -> PingPath.of(reply).named(replyNames.forHints(reply.routeHints.map { it.octets }))
        latest?.outcome == PingOutcome.TimedOut -> PingPath.unanswered(broken = true)
        else -> PingPath.unanswered(broken = false)
    }
    // Everything before the result on show.
    val earlier = history.filter { waiting != null || it.id != latest?.id }

    Column(
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 16.dp)
            .navigationBarsPadding(),
    ) {
        ResultRow(waiting, latest, Modifier.padding(horizontal = 24.dp))
        Button(
            onClick = viewModel::pingAgain,
            enabled = canPingAgain,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 12.dp).testTag(Tags.PING_AGAIN),
        ) {
            Text(stringResource(R.string.ping_again))
        }
        if (reply != null) SectionHeader(stringResource(R.string.ping_reply_path))
        PathRail(
            stops = layout.stops,
            legs = layout.legs,
            peer = peer,
            names = names,
            tentative = reply == null,
            onOpen = onOpenPeer,
            lookUp = { hint, preceding -> runtime.lookUpRepeaterHint(hint, preceding) },
            modifier = Modifier.padding(horizontal = 16.dp).testTag(Tags.PING_PATH),
        )
        if (reply != null && layout.hasGuessedNames) {
            Text(
                stringResource(R.string.repeater_hint_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
            )
        }
        TextButton(
            onClick = viewModel::resetRoute,
            enabled = !resetting,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp).testTag(Tags.PING_RESET_ROUTE),
        ) {
            Text(stringResource(R.string.reset_route), color = MaterialTheme.colorScheme.error)
        }
        if (earlier.isNotEmpty()) {
            SectionHeader(stringResource(R.string.ping_earlier))
            earlier.forEach { EarlierRow(it, now) }
        }
    }
}

/**
 * The result: the round trip counting up beside a spinner while waiting;
 * then the round trip and hops, "No reply", or why it could not go. One
 * TalkBack node, a polite live region that reads the result once: while
 * waiting it says only that, so the ticking count is not announced.
 */
@Composable
private fun ResultRow(waiting: OutstandingPing?, latest: PingRecord?, modifier: Modifier = Modifier) {
    val locale = LocalConfiguration.current.locales[0]
    val caution = UmshColors.fixed.caution
    val waitingText = stringResource(R.string.waiting_for_reply)
    val outcome = latest?.outcome
    val reply = (outcome as? PingOutcome.Reply)?.reply
    val spoken = when {
        waiting != null -> waitingText
        reply != null -> replySpoken(reply)
        outcome == PingOutcome.TimedOut -> stringResource(R.string.ping_no_reply)
        outcome is PingOutcome.Unavailable -> reasonText(outcome.reason)
        else -> ""
    }
    Column(
        modifier
            .fillMaxWidth()
            .heightIn(min = 72.dp)
            .testTag(Tags.PING_RESULT)
            .semantics(mergeDescendants = true) {
                contentDescription = spoken
                liveRegion = LiveRegionMode.Polite
            },
        verticalArrangement = Arrangement.Center,
    ) {
        // What is drawn is read as [spoken], once: the ticking count is never read.
        Row(Modifier.semantics { hideFromAccessibility() }, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            when {
                waiting != null -> {
                    CircularProgressIndicator(Modifier.size(32.dp), strokeWidth = 3.dp)
                    var elapsed by remember(waiting.id) { mutableLongStateOf(0L) }
                    LaunchedEffect(waiting.id) {
                        while (true) {
                            withFrameMillis { elapsed = android.os.SystemClock.elapsedRealtime() - waiting.startedAtElapsedMs }
                            kotlinx.coroutines.delay(TICK_MS)
                        }
                    }
                    Text(
                        MeasurePresentation.seconds(elapsed, locale),
                        style = MaterialTheme.typography.displaySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(Tags.PING_ELAPSED),
                    )
                }
                reply != null -> {
                    ReplyMark(reply)
                    reply.roundTripMs?.let {
                        Text(MeasurePresentation.seconds(it, locale), style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Medium)
                    }
                    Spacer(Modifier.weight(1f))
                    RouteKindText.replyHops(reply.hopCount)?.let {
                        Text(it.resolve(), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                outcome == PingOutcome.TimedOut -> {
                    Icon(painterResource(R.drawable.ic_error), contentDescription = null, tint = caution, modifier = Modifier.size(32.dp))
                    Text(stringResource(R.string.ping_no_reply), style = MaterialTheme.typography.headlineMedium, color = caution)
                }
                outcome is PingOutcome.Unavailable -> {
                    Icon(painterResource(R.drawable.ic_warning), contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(32.dp))
                    Text(reasonText(outcome.reason), style = MaterialTheme.typography.titleMedium)
                }
            }
        }
        if (waiting == null && reply?.viaRouteRetry == true) {
            Text(
                stringResource(R.string.ping_answered_on_retry),
                style = MaterialTheme.typography.bodyMedium,
                color = caution,
                modifier = Modifier.padding(start = 48.dp).testTag(Tags.PING_RETRY_LINE).semantics { hideFromAccessibility() },
            )
        }
    }
}

/** A check for a reply; the retry mark, in amber, when only the retry was answered. */
@Composable
private fun ReplyMark(reply: PingReply) {
    if (reply.viaRouteRetry) {
        Icon(painterResource(R.drawable.ic_refresh), contentDescription = null, tint = UmshColors.fixed.caution, modifier = Modifier.size(32.dp))
    } else {
        Icon(painterResource(R.drawable.ic_check_circle), contentDescription = null, tint = UmshColors.fixed.connected, modifier = Modifier.size(32.dp))
    }
}

/** "Reply in 1.4 seconds, 3 hops", and the retry when it was only the retry. */
@Composable
private fun replySpoken(reply: PingReply): String {
    val locale = LocalConfiguration.current.locales[0]
    val time = reply.roundTripMs?.let { MeasurePresentation.secondsSpoken(it, locale) }
    val hops = RouteKindText.replyHops(reply.hopCount)?.resolve()
    val base = when {
        time != null && hops != null -> stringResource(R.string.ping_reply_spoken, time, hops)
        time != null -> stringResource(R.string.ping_reply_spoken_time, time)
        hops != null -> stringResource(R.string.ping_reply_spoken_hops, hops)
        else -> stringResource(R.string.ping_reply_spoken_bare)
    }
    return if (reply.viaRouteRetry) stringResource(R.string.ping_spoken_with_retry, base, stringResource(R.string.ping_answered_on_retry)) else base
}

/** One earlier ping: "1.3 s · 3 hops" or "No reply", and how long ago. */
@Composable
private fun EarlierRow(record: PingRecord, now: Instant) {
    val locale = LocalConfiguration.current.locales[0]
    val (text, color) = when (val outcome = record.outcome) {
        is PingOutcome.Reply -> {
            val time = outcome.reply.roundTripMs?.let { MeasurePresentation.seconds(it, locale) }
            val hops = RouteKindText.replyHops(outcome.reply.hopCount)?.resolve()
            val line = when {
                time != null && hops != null -> stringResource(R.string.ping_earlier_reply, time, hops)
                else -> time ?: hops ?: stringResource(R.string.ping_reply_spoken_bare)
            }
            line to Color.Unspecified
        }
        PingOutcome.TimedOut -> stringResource(R.string.ping_no_reply) to UmshColors.fixed.caution
        is PingOutcome.Unavailable -> reasonText(outcome.reason) to MaterialTheme.colorScheme.onSurfaceVariant
        PingOutcome.Canceled -> return
    }
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(horizontal = 24.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.PING_EARLIER_ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge, color = if (color == Color.Unspecified) MaterialTheme.colorScheme.onSurface else color, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(16.dp))
        Text(ageText(record.sentAt, maxOf(now, record.sentAt)), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private const val TICK_MS = 100L
