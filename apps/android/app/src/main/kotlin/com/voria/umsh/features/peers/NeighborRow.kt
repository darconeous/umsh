package com.voria.umsh.features.peers

import android.icu.text.ListFormatter
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.core.ulcpLocationCellMeters
import com.voria.umsh.designsystem.HintLookupButton
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.SignalPresentation
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rememberCopier
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RepeaterNeighbor
import java.time.Instant
import java.util.Locale
import kotlin.math.ceil
import kotlin.math.log10
import kotlinx.coroutines.Deferred

/**
 * One neighbor a repeater reported (`repeaters-discover.svg` 1): the known
 * node's avatar and name when the core matched it ([known]), else the name
 * the repeater relayed or the hint; how it was heard and when; then its
 * regions and its distance from the [reporter], when there are any. Not
 * heard for six hours, it fades. A known node opens through [onOpen]; an
 * unknown one offers [lookUp]. Long press, on a row with a position: Copy
 * coordinates (Show on map is Phase 4's).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun NeighborRow(
    neighbor: RepeaterNeighbor,
    known: PeerSummary?,
    reporter: PeerSummary,
    names: DisplayNames,
    now: Instant,
    onOpen: (() -> Unit)?,
    lookUp: (() -> Deferred<Unit>)?,
    /** What a tap does, for TalkBack; opening the node's page unless said. */
    clickLabel: String? = null,
    /** In place of the lookup button: Add hop's "In path". */
    trailing: (@Composable () -> Unit)? = null,
    /** Drawn as unavailable (Add hop's hop already in the path). */
    dimmed: Boolean = false,
) {
    val locale = LocalConfiguration.current.locales[0]
    val resources = LocalResources.current
    val copier = rememberCopier()
    var menuOpen by remember { mutableStateOf(false) }
    val stale = neighbor.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, now.toEpochMilli())
    val fade = Modifier.alpha(if (dimmed) DIMMED_ALPHA else if (stale) STALE_ALPHA else 1f)
    val openLabel = clickLabel ?: stringResource(R.string.open_peer_page)

    val title = when {
        known != null -> names.peer(known)
        !neighbor.name.isNullOrBlank() -> neighbor.name
        neighbor.hint.size == 2 -> stringResource(R.string.repeater_hint_row, isolated(neighbor.hintText))
        else -> isolated(neighbor.hintText)
    }
    val signal = SignalPresentation.readingTextQuarterDb(resources, neighbor.rssiDbm, neighbor.snrQuarterDb, locale)
        ?: stringResource(R.string.neighbor_bridged)
    val heardAt = neighbor.lastHeardAtMs?.let(Instant::ofEpochMilli)
    val heard = when {
        heardAt != null -> stringResource(R.string.neighbor_heard, signal, ageText(heardAt, maxOf(now, heardAt)))
        neighbor.lastHeardMinutes != null -> stringResource(R.string.neighbor_heard_long_ago, signal)
        else -> signal
    }
    val detail = detailLine(neighbor, reporter, locale)
    val coordinates = coordinateText(neighbor)
    val actionsLabel = stringResource(R.string.peer_actions)

    Box {
        ListItem(
            headlineContent = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = fade) },
            supportingContent = {
                Text(if (detail != null) "$heard\n$detail" else heard, modifier = fade)
            },
            leadingContent = {
                Box(fade) {
                    if (known != null) {
                        PeerAvatar(known, favorite = known.isFavorite, describe = false)
                    } else {
                        PeerAvatar(NodeHint(neighbor.hint, neighbor.hintText), PeerAvatarShape.Hexagon, describe = false)
                    }
                }
            },
            trailingContent = trailing ?: lookUp?.let { ask ->
                { HintLookupButton(ask, Modifier.testTag(Tags.hintLookup(neighbor.hint.hex()))) }
            },
            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            modifier = Modifier
                .then(
                    when {
                        onOpen != null -> Modifier.combinedClickable(
                            onClickLabel = openLabel,
                            onLongClickLabel = if (coordinates != null) actionsLabel else null,
                            onLongClick = if (coordinates != null) ({ menuOpen = true }) else null,
                            onClick = onOpen,
                        )
                        // Nothing to open: a long press alone, so there is no tap that does nothing.
                        coordinates != null -> Modifier
                            .pointerInput(Unit) { detectTapGestures(onLongPress = { menuOpen = true }) }
                            .semantics {
                                onLongClick(actionsLabel) {
                                    menuOpen = true
                                    true
                                }
                            }
                        else -> Modifier
                    },
                )
                .semantics(mergeDescendants = true) {}
                .testTag(Tags.neighborRow(neighbor.hint.hex())),
        )
        if (coordinates != null) {
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }, modifier = Modifier.testTag(Tags.NEIGHBOR_MENU)) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy_coordinates)) },
                    leadingIcon = { Icon(painterResource(R.drawable.ic_content_copy), contentDescription = null) },
                    onClick = {
                        menuOpen = false
                        copier.copy(coordinates, R.string.coordinates_copied)
                    },
                    modifier = Modifier.testTag(Tags.NEIGHBOR_COPY_COORDINATES),
                )
            }
        }
    }
}

/** The regions, then the distance from the reporting repeater; null when there is neither. */
@Composable
private fun detailLine(neighbor: RepeaterNeighbor, reporter: PeerSummary, locale: Locale): String? {
    val regions = neighbor.regionCodes.takeIf { it.isNotEmpty() }?.let { codes ->
        ListFormatter.getInstance(locale).format(codes.map { isolated(regionLabel(it)) })
    }
    val distance = separation(neighbor, reporter)?.let { separation ->
        val measured = PeerDistance.text(separation.meters, locale)
        if (separation.isUpperBound) stringResource(R.string.distance_under, measured) else measured
    }
    return when {
        regions != null && distance != null -> stringResource(R.string.neighbor_regions_distance, regions, distance)
        else -> regions ?: distance
    }
}

/**
 * How far the neighbor is from the repeater that reported it, which is the
 * distance a neighbor listing is about: the reach of one hop, not how far
 * anything is from this phone. Null when either has no position.
 */
internal fun separation(neighbor: RepeaterNeighbor, reporter: PeerSummary): PeerDistance? {
    val latitude = neighbor.latitude ?: return null
    val longitude = neighbor.longitude ?: return null
    val own = reporter.advertised ?: return null
    val reporterLatitude = own.latitude ?: return null
    val reporterLongitude = own.longitude ?: return null
    val reference = Reference(reporterLatitude, reporterLongitude, own.locationPrecision?.let(::cellMeters))
    return PeerDistance.between(reference, latitude, longitude, neighbor.locationPrecision?.let(::cellMeters))
}

private fun cellMeters(precision: Int): Double? = ulcpLocationCellMeters(precision.toUByte())

/**
 * The pair as it goes on the clipboard, meant to be pasted into a map's
 * search or a message and work there: "44.0521, -123.0868", no label or
 * degree signs, the digits the reported cell supports, and the decimal
 * point whatever the locale. Null without a position.
 */
internal fun coordinateText(neighbor: RepeaterNeighbor): String? {
    val latitude = neighbor.latitude ?: return null
    val longitude = neighbor.longitude ?: return null
    val digits = CoordinateDigits.of(neighbor.locationPrecision?.let(::cellMeters))
    return String.format(Locale.ROOT, "%.${digits}f, %.${digits}f", latitude, longitude)
}

/** How many decimals of a degree a cell of a size supports (iOS `LocationPresentation.coordinateDecimals`). */
internal object CoordinateDigits {
    private const val METERS_PER_DEGREE = 111_320.0

    fun of(cellMeters: Double?): Int {
        cellMeters ?: return 5
        return ceil(log10(METERS_PER_DEGREE / maxOf(cellMeters, 0.01))).toInt().coerceIn(0, 7)
    }
}

/** How far a row that cannot be chosen fades. */
private const val DIMMED_ALPHA = 0.38f

/** How far a neighbor not heard for six hours fades. */
private const val STALE_ALPHA = 0.5f
