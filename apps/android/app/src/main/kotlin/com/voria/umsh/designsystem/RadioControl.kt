package com.voria.umsh.designsystem

import android.icu.text.ListFormatter
import android.os.Build
import androidx.annotation.DrawableRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioControlState.Extra
import com.voria.umsh.services.radio.RadioControlState.Link
import com.voria.umsh.services.radio.RadioControlState.Power
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant

/** The pill's fixed size: wide enough for its widest state (link, bars and bolt), so it never jumps. */
object RadioControlMetrics {
    val Width = 72.dp
    val Height = 32.dp
    val Glyph = 20.dp
    val ExtraGlyph = 14.dp
    val Ring = 24.dp

    /** A cached reading: drawn, never as live. */
    const val CACHED_ALPHA = 0.38f
}

/**
 * The companion radio at the end of every top app bar, and in the rail's
 * header (`radio-control.svg` board 1): a link glyph, then a power glyph, in
 * a full-radius tonal pill of fixed width. Never the radio's name or the
 * word Connected; TalkBack says those.
 *
 * [onShowDetails] opens the radio's page: Radio Detail with a [radio], Choose
 * a radio with none set up (D20), and the click label says which. Null
 * leaves the control with no click action and no click label: the radio
 * has not been read yet.
 */
@Composable
fun RadioControl(
    radio: RadioSnapshot?,
    now: Instant,
    modifier: Modifier = Modifier,
    known: Boolean = true,
    onShowDetails: (() -> Unit)? = null,
) {
    val state = RadioControlState.from(radio, known)
    val description = radioControlDescription(state, now)
    val clickLabel = stringResource(if (radio != null) R.string.radio_show_details else R.string.radio_choose)
    val sized = modifier
        .minimumInteractiveComponentSize()
        .size(RadioControlMetrics.Width, RadioControlMetrics.Height)
        .testTag(Tags.RADIO_CONTROL)
        .clearAndSetSemantics {
            contentDescription = description
            if (onShowDetails != null) {
                role = Role.Button
                onClick(label = clickLabel) {
                    onShowDetails()
                    true
                }
            }
        }
    val content: @Composable () -> Unit = {
        Row(
            horizontalArrangement = Arrangement.spacedBy(2.dp, Alignment.CenterHorizontally),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            LinkGlyph(state.link)
            state.power?.let { PowerGlyphs(it, Modifier.alpha(if (state.cached) RadioControlMetrics.CACHED_ALPHA else 1f)) }
        }
    }
    val color = MaterialTheme.colorScheme.surfaceContainerHighest
    val contentColor = MaterialTheme.colorScheme.onSurface
    if (onShowDetails != null) {
        Surface(onClick = onShowDetails, shape = FullShape, color = color, contentColor = contentColor, modifier = sized, content = content)
    } else {
        Surface(shape = FullShape, color = color, contentColor = contentColor, modifier = sized, content = content)
    }
}

@Composable
private fun LinkGlyph(link: Link) {
    Box(Modifier.size(RadioControlMetrics.Glyph), contentAlignment = Alignment.Center) {
        when (link) {
            Link.Connected -> Glyph(R.drawable.ic_sensors)
            Link.Connecting, Link.Reconnecting -> {
                Glyph(R.drawable.ic_sensors)
                CircularProgressIndicator(
                    modifier = Modifier.requiredSize(RadioControlMetrics.Ring),
                    strokeWidth = 2.dp,
                    trackColor = MaterialTheme.colorScheme.outlineVariant,
                )
            }
            Link.Waiting, Link.Disconnected, Link.None -> Glyph(R.drawable.ic_sensors_off)
            // Not read yet: the empty pill, for the moment before the first status.
            Link.Unknown -> Unit
            Link.Failed -> Icon(
                painterResource(R.drawable.ic_error),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(RadioControlMetrics.Glyph),
            )
        }
    }
}

@Composable
private fun PowerGlyphs(power: Power, modifier: Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        when (power) {
            is Power.Level -> {
                Glyph(batteryGlyph(power.bars))
                when (power.extra) {
                    Extra.Charging -> Glyph(R.drawable.ic_bolt, Modifier.offset(x = (-3).dp), RadioControlMetrics.ExtraGlyph)
                    Extra.ExternalPower -> Glyph(R.drawable.ic_power, Modifier.offset(x = (-3).dp), RadioControlMetrics.ExtraGlyph)
                    null -> Unit
                }
            }
            is Power.ExternalOnly -> Glyph(if (power.charging) R.drawable.ic_bolt else R.drawable.ic_power)
            Power.Unknown -> Glyph(R.drawable.ic_battery_unknown)
        }
    }
}

@Composable
private fun Glyph(@DrawableRes icon: Int, modifier: Modifier = Modifier, size: Dp = RadioControlMetrics.Glyph) {
    Icon(painterResource(icon), contentDescription = null, modifier = modifier.size(size))
}

@DrawableRes
internal fun batteryGlyph(bars: Int): Int = when (bars) {
    0 -> R.drawable.ic_battery_0_bar
    1 -> R.drawable.ic_battery_1_bar
    2 -> R.drawable.ic_battery_2_bar
    3 -> R.drawable.ic_battery_3_bar
    4 -> R.drawable.ic_battery_4_bar
    5 -> R.drawable.ic_battery_5_bar
    6 -> R.drawable.ic_battery_6_bar
    else -> R.drawable.ic_battery_full
}

/**
 * What TalkBack says for the control: whole clauses ("Companion radio
 * T1000-E", "connected", "battery 78 percent", "charging"), joined as a list
 * in the reader's language.
 */
@Composable
fun radioControlDescription(state: RadioControlState, now: Instant): String {
    when (state.link) {
        Link.Unknown -> return stringResource(R.string.radio_tb_unnamed)
        Link.None -> return stringResource(R.string.radio_tb_not_set_up)
        else -> Unit
    }
    val clauses = buildList {
        add(state.name?.let { stringResource(R.string.radio_tb_name, it) } ?: stringResource(R.string.radio_tb_unnamed))
        add(
            stringResource(
                when (state.link) {
                    Link.Connected -> R.string.radio_tb_connected
                    Link.Connecting -> R.string.radio_tb_connecting
                    Link.Reconnecting -> R.string.radio_tb_reconnecting
                    Link.Waiting -> R.string.radio_tb_waiting
                    Link.Disconnected, Link.None, Link.Unknown -> R.string.radio_tb_disconnected
                    Link.Failed -> R.string.radio_tb_failed
                },
            ),
        )
        when (val power = state.power) {
            is Power.Level -> if (state.cached) {
                add(pluralStringResource(R.plurals.radio_tb_last_battery, power.percent, power.percent))
                state.readAtMs?.let { add(ageSpokenText(Instant.ofEpochMilli(it), now)) }
            } else {
                add(pluralStringResource(R.plurals.radio_tb_battery, power.percent, power.percent))
                when (power.extra) {
                    Extra.Charging -> add(stringResource(R.string.radio_tb_charging))
                    Extra.ExternalPower -> add(stringResource(R.string.radio_tb_external_power))
                    null -> Unit
                }
            }
            is Power.ExternalOnly ->
                add(stringResource(if (power.charging) R.string.radio_tb_charging else R.string.radio_tb_external_power))
            Power.Unknown -> add(stringResource(R.string.radio_tb_battery_unknown))
            null -> Unit
        }
    }
    // A list of clauses, not of things: "a, b, c", never "and". Android 13
    // joins them in the reader's language; before it, the translated
    // two-clause join, applied in turn.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        val locale = LocalConfiguration.current.locales[0]
        return ListFormatter.getInstance(locale, ListFormatter.Type.UNITS, ListFormatter.Width.SHORT).format(clauses)
    }
    val resources = LocalResources.current
    return clauses.reduce { sentence, clause -> resources.getString(R.string.radio_tb_clause_join, sentence, clause) }
}
