package com.voria.umsh.app.debug

import androidx.annotation.DrawableRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.voria.umsh.R

/** Every drawable the app ships, in resource-name order. */
private val icons = listOf(
    R.drawable.ic_arrow_back,
    R.drawable.ic_arrow_downward,
    R.drawable.ic_battery_0_bar,
    R.drawable.ic_battery_1_bar,
    R.drawable.ic_battery_2_bar,
    R.drawable.ic_battery_3_bar,
    R.drawable.ic_battery_4_bar,
    R.drawable.ic_battery_5_bar,
    R.drawable.ic_battery_6_bar,
    R.drawable.ic_battery_full,
    R.drawable.ic_battery_unknown,
    R.drawable.ic_bluetooth,
    R.drawable.ic_bluetooth_disabled,
    R.drawable.ic_bolt,
    R.drawable.ic_close,
    R.drawable.ic_delete,
    R.drawable.ic_edit,
    R.drawable.ic_error,
    R.drawable.ic_forum,
    R.drawable.ic_forum_outlined,
    R.drawable.ic_hub,
    R.drawable.ic_hub_outlined,
    R.drawable.ic_map,
    R.drawable.ic_map_outlined,
    R.drawable.ic_notifications_off,
    R.drawable.ic_power,
    R.drawable.ic_qr_code,
    R.drawable.ic_search,
    R.drawable.ic_send,
    R.drawable.ic_sensors,
    R.drawable.ic_sensors_off,
    R.drawable.ic_settings,
    R.drawable.ic_settings_outlined,
    R.drawable.ic_share,
    R.drawable.ic_star,
    R.drawable.ic_vertical_align_bottom,
    R.drawable.ic_warning,
    R.drawable.ic_wifi_tethering,
)

/** The auto-mirrored ones, drawn again right to left. */
private val mirrored = listOf(R.drawable.ic_arrow_back, R.drawable.ic_send, R.drawable.ic_battery_unknown)

/** Every icon at 24 dp with its resource name, then the mirrored ones in RTL. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun IconsBoard() {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.gallery_board_icons), style = MaterialTheme.typography.headlineSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                icons.forEach { IconCell(it) }
            }
            Text(stringResource(R.string.gallery_icons_rtl), style = MaterialTheme.typography.titleSmall)
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    mirrored.forEach { IconCell(it) }
                }
            }
        }
    }
}

@Composable
private fun IconCell(@DrawableRes id: Int) {
    val name = LocalResources.current.getResourceEntryName(id).removePrefix("ic_")
    Column(Modifier.width(76.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(painterResource(id), contentDescription = null, modifier = Modifier.size(24.dp))
        Text(
            name,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}
