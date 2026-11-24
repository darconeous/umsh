package com.voria.umsh.designsystem

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.LegSignal
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RepeaterHint
import kotlinx.coroutines.Deferred

/** One node on a drawn path. */
sealed interface RailStop {
    /** The phone the path starts from, with the radio it sends through when that is worth saying. */
    data class Phone(val radioName: String?) : RailStop

    /**
     * A repeater known by its hint: the node it most likely names, if any,
     * and the hops ahead of it in send order, the way an ask to identify it
     * has to go. [enteredByHand] marks a hop of a held path that names no
     * known node: only typing its hint could have put it there.
     */
    data class Repeater(
        val hint: RepeaterHint,
        val preceding: List<Octets>,
        val named: PeerSummary? = null,
        val enteredByHand: Boolean = false,
    ) : RailStop

    /** The node at the far end. */
    data object Peer : RailStop
}

/** What lies between two stops. */
sealed interface RailLeg {
    /** A plain stretch. */
    data object Plain : RailLeg

    /** The leg's place in the path, drawn on the rail (Route's numbering). */
    data class Numbered(val number: Int) : RailLeg

    /** How the far node of the leg was heard; a reading of nothing crossed a bridge. */
    data class Reading(val signal: LegSignal) : RailLeg

    /** Repeaters counted without being named, as a dashed stretch. */
    data class Unnamed(val count: Int) : RailLeg

    /** A stretch nobody traced or counted, dashed. */
    data object Unknown : RailLeg

    /** Nothing known yet: dashed. */
    data object Pending : RailLeg

    /** Nothing came back: dashed, broken by an X. */
    data object Broken : RailLeg
}

/**
 * A path drawn top to bottom, this phone first (iOS `PathRail`): one row
 * per node, joined by a rail, with what is known of each leg between them.
 * A named repeater opens its page through [onOpen]; one that names no
 * known node offers [lookUp] (the hint, and the hops ahead of it). Each
 * stop and each leg is one TalkBack node.
 */
@Composable
fun PathRail(
    stops: List<RailStop>,
    legs: List<RailLeg>,
    peer: PeerSummary,
    names: DisplayNames,
    modifier: Modifier = Modifier,
    /** The whole rail dashed: nothing is known of any of it yet. */
    tentative: Boolean = false,
    onOpen: ((PeerSummary) -> Unit)? = null,
    lookUp: ((Octets, List<Octets>) -> Deferred<Unit>)? = null,
) {
    require(legs.size == (stops.size - 1).coerceAtLeast(0)) { "a leg between each pair of stops" }
    val line = MaterialTheme.colorScheme.outlineVariant
    Column(modifier.fillMaxWidth()) {
        stops.forEachIndexed { index, stop ->
            StopRow(stop, peer, names, top = index > 0, bottom = index < stops.lastIndex, dashed = tentative, line = line, onOpen = onOpen, lookUp = lookUp)
            legs.getOrNull(index)?.let { LegRow(it, tentative, line) }
        }
    }
}

private val COLUMN = 40.dp
private val GAP = 16.dp

@Composable
private fun StopRow(
    stop: RailStop,
    peer: PeerSummary,
    names: DisplayNames,
    top: Boolean,
    bottom: Boolean,
    dashed: Boolean,
    line: Color,
    onOpen: ((PeerSummary) -> Unit)?,
    lookUp: ((Octets, List<Octets>) -> Deferred<Unit>)?,
) {
    val open = (stop as? RailStop.Repeater)?.named?.let { named -> onOpen?.let { { it(named) } } }
    val openLabel = stringResource(R.string.open_peer_page)
    Row(
        Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min)
            .heightIn(min = 48.dp)
            .then(if (open != null) Modifier.clickable(onClickLabel = openLabel, onClick = open) else Modifier)
            .semantics(mergeDescendants = true) {}
            .stopTag(stop),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.width(COLUMN).fillMaxHeight().drawBehind { rail(line, top, bottom, dashed) },
            contentAlignment = Alignment.Center,
        ) {
            when (stop) {
                is RailStop.Phone -> PhoneBadge()
                is RailStop.Repeater -> RepeaterHintBadge(stop.hint.octets, stop.hint.text, stop.named, size = AvatarSize.TopBar)
                RailStop.Peer -> PeerAvatar(peer, size = AvatarSize.TopBar, describe = false)
            }
        }
        Column(Modifier.weight(1f).padding(start = GAP, top = 6.dp, bottom = 6.dp)) {
            val (title, subtitle) = when (stop) {
                is RailStop.Phone -> stringResource(R.string.path_this_phone) to stop.radioName?.let {
                    stringResource(R.string.path_sent_through, userIsolated(it))
                }
                is RailStop.Repeater -> {
                    val hintLine = stringResource(R.string.repeater_hint_row, isolated(stop.hint.text))
                    when {
                        stop.named != null -> names.peer(stop.named) to hintLine
                        stop.enteredByHand -> hintLine to stringResource(R.string.path_entered_by_hand)
                        else -> hintLine to null
                    }
                }
                RailStop.Peer -> names.peer(peer) to null
            }
            Text(title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            subtitle?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (open != null) {
            Icon(
                painterResource(R.drawable.ic_chevron_right),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 12.dp),
            )
        } else if (stop is RailStop.Repeater && stop.named == null && lookUp != null) {
            HintLookupButton({ lookUp(stop.hint.octets, stop.preceding) }, Modifier.testTag(Tags.hintLookup(stop.hint.octets.hex())))
        }
    }
}

private fun Modifier.stopTag(stop: RailStop): Modifier = testTag(
    when (stop) {
        is RailStop.Phone -> Tags.RAIL_PHONE
        is RailStop.Repeater -> Tags.railRepeater(stop.hint.octets.hex())
        RailStop.Peer -> Tags.RAIL_PEER
    },
)

@Composable
internal fun PhoneBadge() {
    Box(
        Modifier
            .size(AvatarSize.TopBar)
            .background(MaterialTheme.colorScheme.surfaceContainerHighest, CircleShape)
            .border(1.5.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painterResource(R.drawable.ic_smartphone),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun LegRow(leg: RailLeg, tentative: Boolean, line: Color) {
    val dashed = when (leg) {
        is RailLeg.Unnamed, RailLeg.Unknown, RailLeg.Pending, RailLeg.Broken -> true
        RailLeg.Plain, is RailLeg.Numbered, is RailLeg.Reading -> tentative
    }
    val minHeight: Dp = when (leg) {
        RailLeg.Plain -> 12.dp
        is RailLeg.Numbered -> 28.dp
        is RailLeg.Reading, is RailLeg.Unnamed, RailLeg.Unknown -> 32.dp
        RailLeg.Pending, RailLeg.Broken -> 44.dp
    }
    val caption = legCaption(leg)
    val noPath = stringResource(R.string.path_no_path)
    // Decoration only (the line, a number) has nothing to read; a caption is read as it stands.
    val semantics = when {
        caption != null -> Modifier.clearAndSetSemantics { contentDescription = caption }
        leg == RailLeg.Broken -> Modifier.clearAndSetSemantics { contentDescription = noPath }
        else -> Modifier.clearAndSetSemantics {}
    }
    Row(
        // The tag first: what follows clearAndSetSemantics is cleared with the children.
        Modifier.fillMaxWidth().height(IntrinsicSize.Min).heightIn(min = minHeight).testTag(Tags.RAIL_LEG).then(semantics),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.width(COLUMN).fillMaxHeight().drawBehind { rail(line, top = true, bottom = true, dashed = dashed) },
            contentAlignment = Alignment.Center,
        ) {
            when (leg) {
                is RailLeg.Numbered -> LegNumber(leg.number)
                RailLeg.Broken -> Icon(
                    painterResource(R.drawable.ic_cancel),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp).background(MaterialTheme.colorScheme.surface, CircleShape),
                )
                else -> Unit
            }
        }
        if (caption != null) {
            Row(
                Modifier.weight(1f).padding(start = GAP),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (leg is RailLeg.Reading) {
                    SignalBars(SignalPresentation.bars(leg.signal.rssiDbm, leg.signal.snrCentibels))
                }
                Text(caption, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/** What a leg says beside the rail: its reading, "Bridged", "2 unnamed repeaters", "Unknown path"; null for none. */
@Composable
private fun legCaption(leg: RailLeg): String? = when (leg) {
    is RailLeg.Reading -> {
        val locale = LocalConfiguration.current.locales[0]
        SignalPresentation.readingText(LocalResources.current, leg.signal.rssiDbm, leg.signal.snrCentibels, locale)
            ?: stringResource(R.string.path_bridged)
    }
    is RailLeg.Unnamed -> pluralStringResource(R.plurals.path_unnamed_repeaters, leg.count, leg.count)
    RailLeg.Unknown -> stringResource(R.string.path_unknown)
    else -> null
}

@Composable
private fun LegNumber(number: Int) {
    val locale = LocalConfiguration.current.locales[0]
    Box(
        Modifier
            .size(20.dp)
            .background(MaterialTheme.colorScheme.surface, CircleShape)
            .border(1.5.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            android.icu.text.NumberFormat.getIntegerInstance(locale).format(number.toLong()),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Zero to four bars, the lit ones in the connected green. */
@Composable
fun SignalBars(bars: Int?, modifier: Modifier = Modifier) {
    val lit = UmshColors.fixed.connected
    val unlit = MaterialTheme.colorScheme.outlineVariant
    Canvas(modifier.size(width = 14.dp, height = 12.dp)) {
        val count = 4
        val gap = size.width / 14f
        val barWidth = (size.width - gap * (count - 1)) / count
        for (index in 0 until count) {
            val height = size.height * (index + 1) / count
            drawRect(
                color = if (bars != null && index < bars) lit else unlit,
                topLeft = Offset(index * (barWidth + gap), size.height - height),
                size = androidx.compose.ui.geometry.Size(barWidth, height),
            )
        }
    }
}

/** The rail through one row's column: above its middle, below it, or both. */
internal fun androidx.compose.ui.graphics.drawscope.DrawScope.rail(color: Color, top: Boolean, bottom: Boolean, dashed: Boolean) {
    val x = size.width / 2
    val start = if (top) 0f else size.height / 2
    val end = if (bottom) size.height else size.height / 2
    if (end <= start) return
    drawLine(
        color = color,
        start = Offset(x, start),
        end = Offset(x, end),
        strokeWidth = 2.dp.toPx(),
        pathEffect = if (dashed) PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 5.dp.toPx())) else null,
    )
}
