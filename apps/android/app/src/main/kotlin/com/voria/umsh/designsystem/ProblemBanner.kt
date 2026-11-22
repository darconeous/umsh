package com.voria.umsh.designsystem

import android.icu.text.NumberFormat
import androidx.annotation.DrawableRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioBanner.RejectReason
import java.time.Instant

/**
 * The app-level problem slot (`radio-control.svg` boards 2–5): an icon, the
 * problem, a detail line, and at most one action. Attention states take the
 * warning container, failures the error container; wording, not tint,
 * tells them apart. It pushes content down and never floats.
 */
@Composable
fun ProblemBanner(
    @DrawableRes icon: Int,
    title: String,
    detail: String?,
    tone: RadioBanner.Tone,
    modifier: Modifier = Modifier,
    action: Pair<String, () -> Unit>? = null,
) {
    val (container, content) = when (tone) {
        RadioBanner.Tone.Warning -> UmshColors.warning.container to UmshColors.warning.onContainer
        RadioBanner.Tone.Error -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
    }
    Surface(color = container, contentColor = content, modifier = modifier.fillMaxWidth()) {
        Row(
            Modifier
                .heightIn(min = 72.dp)
                .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(24.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                // Only the title is a live region: it changes when the problem
                // does. The detail carries an age that ticks each minute, and
                // a live region around it would be read out again each time.
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                detail?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            action?.let { (label, onClick) ->
                TextButton(
                    onClick = onClick,
                    colors = ButtonDefaults.textButtonColors(contentColor = content),
                    modifier = Modifier.testTag(Tags.BANNER_ACTION),
                ) { Text(label) }
            }
        }
    }
}

/**
 * The radio's banner. Its actions (Details, Choose radio, Turn on, Allow)
 * all lead to Phase 2's pages and requests, so none is shown yet.
 */
@Composable
fun RadioProblemBanner(banner: RadioBanner, now: Instant, modifier: Modifier = Modifier) {
    val (icon, title) = when (banner) {
        RadioBanner.NoRadio -> R.drawable.ic_bluetooth to R.string.banner_no_radio_title
        is RadioBanner.Disconnected -> R.drawable.ic_sensors_off to R.string.banner_disconnected_title
        is RadioBanner.BluetoothOff -> R.drawable.ic_bluetooth_disabled to R.string.banner_bluetooth_off_title
        RadioBanner.NearbyDenied -> R.drawable.ic_bluetooth to R.string.banner_nearby_denied_title
        is RadioBanner.Failed -> R.drawable.ic_error to R.string.banner_failed_title
        is RadioBanner.TransmissionRejected -> R.drawable.ic_warning to R.string.banner_tx_rejected_title
    }
    val detail = when (banner) {
        RadioBanner.NoRadio -> stringResource(R.string.banner_detail_choose_radio)
        RadioBanner.NearbyDenied -> stringResource(R.string.banner_detail_needs_permission)
        is RadioBanner.Disconnected -> lastReading(banner.reading, now)
        is RadioBanner.BluetoothOff -> lastReading(banner.reading, now)
        is RadioBanner.Failed -> lastReading(banner.reading, now)
        is RadioBanner.TransmissionRejected -> {
            val reason = rejectReason(banner.reason)
            val name = banner.reading.name
            val percent = banner.reading.percent
            when {
                name != null && percent != null ->
                    stringResource(R.string.banner_detail_reason_battery, reason, name, percentText(percent))
                name != null -> stringResource(R.string.banner_detail_reason_radio, reason, name)
                else -> reason
            }
        }
    }
    ProblemBanner(
        icon = icon,
        title = stringResource(title),
        detail = detail,
        tone = banner.tone,
        modifier = modifier.testTag(Tags.RADIO_BANNER),
    )
}

/** Stored data did not read; stacked above any radio banner. */
@Composable
fun DataLoadBanner(onRetry: () -> Unit, modifier: Modifier = Modifier) {
    ProblemBanner(
        icon = R.drawable.ic_error,
        title = stringResource(R.string.banner_data_load_title),
        detail = stringResource(R.string.banner_detail_data_load),
        tone = RadioBanner.Tone.Error,
        action = stringResource(R.string.banner_retry) to onRetry,
        modifier = modifier.testTag(Tags.DATA_LOAD_BANNER),
    )
}

/** "T1000-E · Last battery 78%, 12 min. ago", or as much of it as is known. */
@Composable
private fun lastReading(reading: RadioBanner.Reading, now: Instant): String? {
    val name = reading.name ?: return null
    val percent = reading.percent
    val readAt = reading.readAtMs
    if (percent == null || readAt == null) return name
    return stringResource(
        R.string.banner_detail_last_battery,
        name,
        percentText(percent),
        ageText(Instant.ofEpochMilli(readAt), now),
    )
}

@Composable
private fun percentText(percent: Int): String =
    NumberFormat.getPercentInstance(LocalConfiguration.current.locales[0]).format(percent / 100.0)

@Composable
private fun rejectReason(reason: RejectReason): String = when (reason) {
    RejectReason.DutyCycle -> stringResource(R.string.banner_reason_duty_cycle)
    RejectReason.ChannelBusy -> stringResource(R.string.banner_reason_channel_busy)
    RejectReason.RadioBusy -> stringResource(R.string.banner_reason_radio_busy)
    RejectReason.QueueFull -> stringResource(R.string.banner_reason_queue_full)
    is RejectReason.Status -> stringResource(R.string.banner_reason_status, isolated(reason.name))
}
