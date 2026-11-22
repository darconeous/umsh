package com.voria.umsh.app.debug

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.designsystem.DataLoadBanner
import com.voria.umsh.designsystem.LocalTopBarRadioControl
import com.voria.umsh.designsystem.RadioControl
import com.voria.umsh.designsystem.RadioProblemBanner
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.radioControlDescription
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant

private val now: Instant = Instant.now()

private fun radio(
    phase: MobileRadioPhase = MobileRadioPhase.ATTACHED,
    percent: Int? = 78,
    charge: UlcpChargeState? = UlcpChargeState.DISCHARGING,
    reportsBattery: Boolean = true,
    cached: Boolean = false,
    minutesAgo: Long = 0,
) = RadioSnapshot(
    phase = phase, name = "T1000-E", linkId = "gallery", host = UlcpHostOwnership.OURS,
    batteryPercent = percent, batteryMillivolts = null, charge = charge,
    batteryReadAtMs = now.toEpochMilli() - minutesAgo * 60_000, problem = null,
    carriesThisPhone = phase == MobileRadioPhase.ATTACHED, reportsBattery = reportsBattery, batteryCached = cached,
)

/** `radio-control.svg` board 1, from the real control over fake radio states. */
@Composable
internal fun RadioStatesBoard() {
    val states = listOf(
        R.string.gallery_radio_connected to radio(),
        R.string.gallery_radio_charging to radio(charge = UlcpChargeState.CHARGING),
        R.string.gallery_radio_external to radio(percent = null, charge = UlcpChargeState.CHARGED),
        R.string.gallery_radio_unknown to radio(percent = null, charge = null),
        R.string.gallery_radio_no_power to radio(percent = null, charge = null, reportsBattery = false),
        R.string.gallery_radio_low to radio(percent = 12),
        R.string.gallery_radio_reconnecting to radio(MobileRadioPhase.RECONNECTING, cached = true, minutesAgo = 2),
        R.string.gallery_radio_disconnected to radio(MobileRadioPhase.WAITING_FOR_RADIO, cached = true, minutesAgo = 12),
        R.string.gallery_radio_failed to radio(MobileRadioPhase.FAILED, cached = true, minutesAgo = 1),
        R.string.gallery_radio_none to null,
    )
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(R.string.gallery_board_radio), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.gallery_radio_subtitle), style = MaterialTheme.typography.bodySmall)
        states.forEach { (label, state) ->
            Column {
                Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
                Surface(shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
                    CompositionLocalProvider(LocalTopBarRadioControl provides { RadioControl(state, now) }) {
                        UmshTopAppBar(stringResource(R.string.nav_conversations))
                    }
                }
                Text(
                    radioControlDescription(RadioControlState.from(state), now),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** `radio-control.svg` boards 2 and 3: every banner row. */
@Composable
internal fun BannersBoard() {
    val minutes = { m: Long -> now.toEpochMilli() - m * 60_000 }
    val rows = listOf(
        RadioBanner.NoRadio,
        RadioBanner.Disconnected(RadioBanner.Reading("T1000-E", 78, minutes(12))),
        RadioBanner.BluetoothOff(RadioBanner.Reading("T1000-E", 78, minutes(3))),
        RadioBanner.NearbyDenied,
        RadioBanner.Failed(RadioBanner.Reading("T1000-E", 64, minutes(1))),
        RadioBanner.TransmissionRejected(RadioBanner.RejectReason.DutyCycle, RadioBanner.Reading("T1000-E", 52, null)),
    )
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(stringResource(R.string.gallery_board_banners), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.gallery_banners_subtitle), style = MaterialTheme.typography.bodySmall)
        rows.forEach { RadioProblemBanner(it, now) }
        DataLoadBanner(onRetry = {})
    }
}
