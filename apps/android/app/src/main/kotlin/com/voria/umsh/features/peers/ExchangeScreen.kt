package com.voria.umsh.features.peers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.identifierAnnotated
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.MeetDevice
import com.voria.umsh.models.MeetEnd
import com.voria.umsh.models.MeetExchange

/**
 * A contact exchange with a device from Nearby (`nearby-exchange.svg`
 * 2–5): waiting for it, the code both holders compare with Same and
 * Different, and how it ended. Its title is the other device's glyph and
 * model. Back, and Done, leave the attempt for both; Try again starts over
 * under a fresh key, back on Add peer's Nearby. The shell pushes and
 * closes this page as the exchange moves ([com.voria.umsh.app.ShellState.followMeet]).
 */
@Composable
fun ExchangeScreen(onBack: () -> Unit) {
    val exchange = checkNotNull(LocalExchangeHost.current) { "the exchange outside the shell" }
    val meet by exchange.meet.collectAsStateWithLifecycle()
    val state = meet?.exchange
    val device = meet?.device
    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(
                    title = { device?.let { ExchangeTitle(it) } },
                    onBack = onBack,
                )
            },
            modifier = Modifier.testTag(Tags.EXCHANGE),
        ) { padding ->
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 24.dp, vertical = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                when (state) {
                    is MeetExchange.Asking -> Centered { Waiting(state.device, spinner = 36.dp) }
                    is MeetExchange.Accepted -> Centered { Waiting(state.device, spinner = 36.dp) }
                    is MeetExchange.Comparing -> Comparing(state, onSame = { exchange.confirm(true) }, onDifferent = { exchange.confirm(false) })
                    is MeetExchange.Ended -> Ended(state.reason, onDone = onBack, onTryAgain = { exchange.backOut() })
                    // Passing: the page closes, or gives way to the new peer's.
                    else -> Unit
                }
            }
        }
    }
}

@Composable
private fun ExchangeTitle(device: MeetDevice) {
    Row(
        // One stop: the model; the glyph is its color for this visit, said by nothing.
        Modifier.semantics(mergeDescendants = true) {}.testTag(Tags.EXCHANGE_TITLE),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        MeetGlyph(device.colorRgb, device.model, diameter = 32.dp)
        Text(meetModelName(device.model), maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun androidx.compose.foundation.layout.ColumnScope.Centered(content: @Composable () -> Unit) {
    Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) { content() }
}

/**
 * The other device not yet answered: a spinner over the line saying whom
 * the page waits for (boards 2 and 4). The line is the one stop, announced
 * as it appears; the spinner beside it says nothing more.
 */
@Composable
private fun Waiting(device: MeetDevice, spinner: Dp) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(
            Modifier.size(spinner).testTag(Tags.EXCHANGE_WAITING_SPINNER).clearAndSetSemantics {},
            trackColor = MaterialTheme.colorScheme.secondaryContainer,
            strokeWidth = 3.dp,
        )
        Text(
            stringResource(R.string.exchange_waiting, userIsolated(meetModelName(device.model))),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 16.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.EXCHANGE_WAITING),
        )
    }
}

/**
 * The code (boards 3–4). Same sends this phone's identity; nothing
 * identifying goes out before it. Once pressed, a check confirms this side
 * and the page waits for the other. The answers sit at the bottom, in
 * reach of the thumb.
 */
@Composable
private fun androidx.compose.foundation.layout.ColumnScope.Comparing(
    state: MeetExchange.Comparing,
    onSame: () -> Unit,
    onDifferent: () -> Unit,
) {
    Spacer(Modifier.weight(1f))
    Text(
        // ASCII digits, isolated, read one by one; never a resource.
        identifierAnnotated(ExchangeCode.grouped(state.code), monospace = true),
        style = MaterialTheme.typography.displayMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp),
        color = if (state.sent) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.testTag(Tags.EXCHANGE_CODE),
    )
    if (state.sent) {
        Icon(
            painterResource(R.drawable.ic_check_circle),
            contentDescription = stringResource(R.string.exchange_same_pressed),
            tint = UmshColors.fixed.connected,
            modifier = Modifier.padding(top = 24.dp).size(48.dp).testTag(Tags.EXCHANGE_SAME_PRESSED),
        )
        Spacer(Modifier.weight(0.6f))
        Waiting(state.device, spinner = 24.dp)
        Spacer(Modifier.weight(1f))
    } else {
        Text(
            stringResource(R.string.exchange_compare),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            // Announced as Comparing starts: the other person is waiting for an answer.
            modifier = Modifier.padding(top = 16.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.EXCHANGE_COMPARE),
        )
        Spacer(Modifier.weight(1.4f))
        Answers(
            secondary = stringResource(R.string.exchange_different),
            secondaryTag = Tags.EXCHANGE_DIFFERENT,
            onSecondary = onDifferent,
            primary = stringResource(R.string.exchange_same),
            primaryTag = Tags.EXCHANGE_SAME,
            onPrimary = onSame,
        )
    }
}

/**
 * How it ended without contacts crossing (board 5): Different on either
 * side, or a decline, a cancel, a timeout, or the other device lost.
 */
@Composable
private fun androidx.compose.foundation.layout.ColumnScope.Ended(reason: MeetEnd, onDone: () -> Unit, onTryAgain: () -> Unit) {
    Spacer(Modifier.weight(1f))
    Icon(
        painterResource(R.drawable.ic_warning),
        contentDescription = null,
        tint = MaterialTheme.colorScheme.error,
        modifier = Modifier.size(44.dp),
    )
    Text(
        stringResource(if (reason == MeetEnd.Different) R.string.exchange_codes_differ else R.string.exchange_not_exchanged),
        style = MaterialTheme.typography.titleMedium,
        textAlign = TextAlign.Center,
        modifier = Modifier.padding(top = 16.dp).semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.EXCHANGE_ENDED),
    )
    Spacer(Modifier.weight(1.4f))
    Answers(
        secondary = stringResource(R.string.exchange_done),
        secondaryTag = Tags.EXCHANGE_DONE,
        onSecondary = onDone,
        primary = stringResource(R.string.exchange_try_again),
        primaryTag = Tags.EXCHANGE_TRY_AGAIN,
        onPrimary = onTryAgain,
    )
}

/** Two answers side by side, each filling its half, the one that moves on last. */
@Composable
private fun Answers(secondary: String, secondaryTag: String, onSecondary: () -> Unit, primary: String, primaryTag: String, onPrimary: () -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(onClick = onSecondary, modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(secondaryTag)) {
            Text(secondary)
        }
        Button(onClick = onPrimary, modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(primaryTag)) {
            Text(primary)
        }
    }
}
