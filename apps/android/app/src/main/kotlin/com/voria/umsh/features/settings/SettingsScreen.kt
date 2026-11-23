package com.voria.umsh.features.settings

import android.icu.text.NumberFormat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ScrollToTopOnReselect
import com.voria.umsh.app.Tags
import com.voria.umsh.app.debug.DeveloperSection
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.selectionBackground
import com.voria.umsh.features.radio.RadioDetailModel
import com.voria.umsh.services.radio.RadioSnapshot

/** The Settings rows that open a page beside the list. */
enum class SettingsRow { YourIdentity, CompanionRadio, Notifications }

/**
 * The Settings root (D4, D13): Identity › Your identity, Radios ›
 * Companion radio, This app › Notifications, and in debug builds the
 * Developer section. Channels and the other batch-5 rows arrive with their
 * pages. [selected] is the row whose
 * page is beside the list; null when nothing is beside it.
 */
@Composable
fun SettingsScreen(
    selected: SettingsRow?,
    onOpenIdentity: () -> Unit,
    onOpenRadio: () -> Unit,
    /** Companion radio with none set up: Choose a radio. */
    onChooseRadio: () -> Unit,
    onOpenNotifications: () -> Unit,
    reselects: Int,
) {
    val runtime = LocalAppRuntime.current
    val host = LocalAppCoreHost.current
    val identity by runtime.identity.collectAsStateWithLifecycle()
    val radio by runtime.radio.collectAsStateWithLifecycle()
    val radioKnown by runtime.radioKnown.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    ScrollToTopOnReselect(reselects, list)
    UmshScaffold(
        topBar = { UmshTopAppBar(stringResource(R.string.nav_settings)) },
        modifier = Modifier.testTag(Tags.SETTINGS_ROOT),
    ) { padding ->
        LazyColumn(state = list, contentPadding = padding, modifier = Modifier.testTag(Tags.SETTINGS_LIST)) {
            item { SectionHeader(stringResource(R.string.settings_section_identity)) }
            item {
                val name = identity.advertisedName
                ListItem(
                    headlineContent = { Text(name.ifEmpty { stringResource(R.string.your_identity) }) },
                    supportingContent = if (name.isNotEmpty()) {
                        { Text(stringResource(R.string.your_identity)) }
                    } else {
                        null
                    },
                    leadingContent = {
                        PeerAvatar(identity.hint, PeerAvatarShape.Circle, size = AvatarSize.List, describe = false)
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    // Drawn only, as a selected conversation is: the content
                    // stays where it is when the row is selected.
                    modifier = Modifier
                        .selectionBackground(
                            selected == SettingsRow.YourIdentity,
                            Color.Transparent,
                            MaterialTheme.colorScheme.secondaryContainer,
                            MaterialTheme.shapes.large,
                        )
                        .clickable(onClick = onOpenIdentity)
                        .testTag(Tags.SETTINGS_YOUR_IDENTITY),
                )
            }
            item { SectionHeader(stringResource(R.string.settings_section_radios)) }
            item {
                CompanionRadioRow(
                    radio,
                    radioKnown,
                    selected == SettingsRow.CompanionRadio,
                    onOpen = if (radio != null) onOpenRadio else onChooseRadio,
                )
            }
            item { SectionHeader(stringResource(R.string.settings_section_this_app)) }
            item {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.notifications_title)) },
                    leadingContent = { Icon(painterResource(R.drawable.ic_notifications), contentDescription = null) },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    modifier = Modifier
                        .selectionBackground(
                            selected == SettingsRow.Notifications,
                            Color.Transparent,
                            MaterialTheme.colorScheme.secondaryContainer,
                            MaterialTheme.shapes.large,
                        )
                        .clickable(role = Role.Button, onClick = onOpenNotifications)
                        .testTag(Tags.SETTINGS_NOTIFICATIONS),
                )
            }
            item { DeveloperSection(host, runtime) }
        }
    }
}

/**
 * Radios › Companion radio (`radio-detail.svg` board 6): name, state and
 * live battery. With no radio set up it says so and opens Choose a radio
 * (D20). Until the core has said ([known]), it says nothing and opens
 * nothing: a radio not yet reported is not "none".
 */
@Composable
private fun CompanionRadioRow(radio: RadioSnapshot?, known: Boolean, selected: Boolean, onOpen: () -> Unit) {
    val detail = when {
        radio != null -> companionRadioLine(radio)
        known -> stringResource(R.string.banner_no_radio_title)
        else -> null
    }
    ListItem(
        headlineContent = { Text(stringResource(R.string.radio_detail_title)) },
        supportingContent = detail?.let { { Text(it, maxLines = 1, overflow = TextOverflow.Ellipsis) } },
        leadingContent = {
            Icon(
                painterResource(if (radio == null && known) R.drawable.ic_sensors_off else R.drawable.ic_sensors),
                contentDescription = null,
            )
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .selectionBackground(
                selected,
                Color.Transparent,
                MaterialTheme.colorScheme.secondaryContainer,
                MaterialTheme.shapes.large,
            )
            // Not yet known: no radio to open, and none known to be missing.
            .let { if (radio != null || known) it.clickable(role = Role.Button, onClick = onOpen) else it.semantics(mergeDescendants = true) {} }
            .testTag(Tags.SETTINGS_COMPANION_RADIO),
    )
}

/** "T1000-E 4F2A · Connected · 78%": the battery only while live. */
@Composable
private fun companionRadioLine(radio: RadioSnapshot): String {
    val model = RadioDetailModel.from(radio)
    val name = model.name ?: stringResource(R.string.radio_detail_title)
    val state = stringResource(model.status.label)
    val live = model.battery as? RadioDetailModel.Battery.Live
        ?: return stringResource(R.string.companion_radio_row_no_battery, name, state)
    val percent = NumberFormat.getPercentInstance(LocalConfiguration.current.locales[0]).format(live.percent / 100.0)
    return stringResource(R.string.companion_radio_row, name, state, percent)
}
