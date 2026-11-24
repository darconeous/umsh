package com.voria.umsh.features.peers

import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.ageSpokenText
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.Age
import com.voria.umsh.designsystem.RelativeTimes
import com.voria.umsh.models.RouteState
import java.time.Instant

/**
 * The three facts people check about a node (`peer-page.svg` 1): when it
 * was last heard, how it is reached, and how far away it is and which way.
 * Unknown values show a dash, so the strip keeps its shape. Each cell is
 * one TalkBack node. Route opens the Route page ([onOpenRoute]).
 */
@Composable
fun PeerGlanceStrip(
    heard: Instant?,
    now: Instant,
    route: RouteState,
    distance: PeerDistance?,
    onOpenRoute: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = MaterialTheme.shapes.large,
        modifier = modifier.fillMaxWidth().testTag(Tags.PEER_GLANCE),
    ) {
        Row(Modifier.height(IntrinsicSize.Min)) {
            val unknown = stringResource(R.string.glance_unknown)
            val heardText = heard?.let {
                if (RelativeTimes.age(it, now) == Age.JustNow) stringResource(R.string.glance_just_now) else ageText(it, now)
            }
            val heardSpoken = heard?.let { ageSpokenText(it, now) }
            Cell(R.string.glance_heard, heardText ?: DASH, heardSpoken ?: unknown, Tags.PEER_GLANCE_HEARD)
            Divider()
            val routeText = RouteKindText.brief(route)?.resolve()
            Cell(
                R.string.glance_route,
                routeText ?: DASH,
                routeText ?: unknown,
                Tags.PEER_GLANCE_ROUTE,
                onClick = onOpenRoute,
                onClickLabel = stringResource(R.string.glance_open_route),
            )
            Divider()
            if (distance == null) {
                Cell(R.string.glance_distance, DASH, unknown, Tags.PEER_GLANCE_DISTANCE)
            } else {
                val locale = LocalConfiguration.current.locales[0]
                val measured = PeerDistance.text(distance.meters, locale)
                val text = if (distance.isUpperBound) stringResource(R.string.distance_under, measured) else measured
                val spoken = stringResource(R.string.distance_spoken, text, stringResource(PeerDistance.compassPoint(distance.bearingDegrees)))
                Cell(R.string.glance_distance, text, spoken, Tags.PEER_GLANCE_DISTANCE) {
                    // North-up: the arrow points along the bearing on a map, so it never mirrors.
                    Icon(
                        painterResource(R.drawable.ic_navigation),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(14.dp).rotate(distance.bearingDegrees.toFloat()),
                    )
                }
            }
        }
    }
}

@Composable
private fun RowScope.Divider() {
    VerticalDivider(Modifier.fillMaxHeight().padding(vertical = 12.dp), color = MaterialTheme.colorScheme.outlineVariant)
}

@Composable
private fun RowScope.Cell(
    @StringRes title: Int,
    value: String,
    spoken: String,
    tag: String,
    onClick: (() -> Unit)? = null,
    onClickLabel: String? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val label = stringResource(title)
    val description = stringResource(R.string.glance_spoken, label, spoken)
    Column(
        Modifier
            .weight(1f)
            .then(if (onClick != null) Modifier.clickable(onClickLabel = onClickLabel, role = Role.Button, onClick = onClick) else Modifier)
            .padding(horizontal = 12.dp, vertical = 12.dp)
            // The tag first: what follows clearAndSetSemantics is cleared with the children.
            .testTag(tag)
            .clearAndSetSemantics {
                contentDescription = description
                if (onClick != null) {
                    role = Role.Button
                    onClick(label = onClickLabel) { onClick(); true }
                }
            },
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(value, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
            trailing?.invoke()
        }
    }
}

private const val DASH = "—"
