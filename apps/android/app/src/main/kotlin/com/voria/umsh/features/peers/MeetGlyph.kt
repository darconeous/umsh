package com.voria.umsh.features.peers

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R

/**
 * A device on Nearby, before anything is exchanged (`nearby-exchange.svg`
 * 7): a circle in its color for this visit with the outline of what kind
 * of device it is, never an avatar, since nothing yet says whose it is.
 * Decorative: what it is, is said in words beside it.
 */
@Composable
fun MeetGlyph(colorRgb: Int, model: Int, modifier: Modifier = Modifier, diameter: Dp = 44.dp) {
    val context = LocalContext.current
    val kind = remember(model) { PlatformCatalog.bundled(context).model(model).glyph }
    MeetGlyph(colorRgb, kind, modifier, diameter)
}

/** [MeetGlyph] for a known [kind]: the glyph sheet draws each. */
@Composable
fun MeetGlyph(colorRgb: Int, kind: MeetGlyphKind, modifier: Modifier = Modifier, diameter: Dp = 44.dp) {
    Box(
        modifier
            .size(diameter)
            .background(Color(0xFF000000.toInt() or (colorRgb and 0xFFFFFF)), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painterResource(kind.icon),
            contentDescription = null,
            tint = Color.Black.copy(alpha = 0.78f),
            modifier = Modifier.size(diameter * 0.5f),
        )
    }
}

@get:DrawableRes
private val MeetGlyphKind.icon: Int
    get() = when (this) {
        MeetGlyphKind.Phone -> R.drawable.ic_meet_phone
        MeetGlyphKind.Tablet -> R.drawable.ic_meet_tablet
        MeetGlyphKind.Computer -> R.drawable.ic_meet_computer
        MeetGlyphKind.Board -> R.drawable.ic_meet_radio
    }

/**
 * How near a device seems, 0 (far) to 3 (close): the arcs of a signal lit
 * from the inside out. Decorative; [nearnessDescription] says it in words.
 */
@Composable
fun MeetNearness(nearness: Int, modifier: Modifier = Modifier) {
    val lit = MaterialTheme.colorScheme.onSurfaceVariant
    val unlit = lit.copy(alpha = 0.28f)
    val steps = nearness.coerceIn(0, 3)
    Canvas(modifier.size(24.dp)) {
        val stroke = 2.dp.toPx()
        val center = Offset(size.width / 2, size.height * 0.82f)
        drawCircle(if (steps > 0) lit else unlit, radius = 1.8.dp.toPx(), center = center)
        for (arc in 1..3) {
            val radius = size.width * (0.16f + 0.13f * arc)
            drawArc(
                color = if (arc <= steps) lit else unlit,
                startAngle = 225f,
                sweepAngle = 90f,
                useCenter = false,
                topLeft = Offset(center.x - radius, center.y - radius),
                size = Size(radius * 2, radius * 2),
                style = Stroke(width = stroke, cap = StrokeCap.Round),
            )
        }
    }
}

/** How near a device seems, in words, for TalkBack. */
@StringRes
fun nearnessDescription(nearness: Int): Int = when (nearness.coerceIn(0, 3)) {
    0 -> R.string.meet_nearness_far
    1 -> R.string.meet_nearness_fairly_far
    2 -> R.string.meet_nearness_fairly_close
    else -> R.string.meet_nearness_close
}

/** What Nearby calls a device of [model]: its platform, its board, or "Device". */
@Composable
fun meetModelName(model: Int): String {
    val context = LocalContext.current
    val known = remember(model) { PlatformCatalog.bundled(context).model(model) }
    return known.nameRes?.let { stringResource(it) } ?: known.name ?: stringResource(R.string.meet_device_unknown)
}
