package com.voria.umsh.features.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.notifications.NotificationChannels
import com.voria.umsh.services.notifications.NotificationPermission
import com.voria.umsh.services.notifications.rememberNotificationsTurnOn
import kotlinx.coroutines.launch

/**
 * Settings › Notifications (`settings.svg` 5): Hide contents on the lock
 * screen, one row a notification channel opening Android's page for it, and
 * all of the app's notification settings. With notifications off for the
 * app, a card at the top says so, with Turn on. Read again each time the
 * page resumes, since every change is made in Android's settings.
 */
@Composable
fun NotificationsSettingsScreen(onBack: (() -> Unit)?) {
    val context = LocalContext.current
    val preferences = LocalAppCoreHost.current.preferences
    val scope = rememberCoroutineScope()
    val hide by preferences.hideLockScreenContents.collectAsStateWithLifecycle(initialValue = false)
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { resumes++ }
    val enabled = remember(resumes) { NotificationPermission.enabled(context) }
    val importances = remember(resumes) {
        val manager = NotificationManagerCompat.from(context)
        NotificationChannels.categories.associate { it.id to manager.getNotificationChannelCompat(it.id)?.importance }
    }
    val turnOn = rememberNotificationsTurnOn(preferences)

    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.notifications_title), onBack = onBack) },
            modifier = Modifier.testTag(Tags.NOTIFICATIONS_PAGE),
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier
                        .widthIn(max = 600.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(bottom = 24.dp),
                ) {
                    if (!enabled) OffCard(turnOn)
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.hide_lock_screen_contents)) },
                        trailingContent = { Switch(checked = hide, onCheckedChange = null) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier
                            .toggleable(value = hide, role = Role.Switch) { on ->
                                scope.launch {
                                    try {
                                        preferences.setHideLockScreenContents(on)
                                    } catch (error: java.io.IOException) {
                                        AppLog.e(TAG, "lock screen choice not stored: ${error.javaClass.simpleName}")
                                    }
                                }
                            }
                            .testTag(Tags.NOTIFICATIONS_HIDE_LOCK_SCREEN),
                    )
                    SectionHeader(stringResource(R.string.notification_categories))
                    NotificationChannels.categories.forEach { category ->
                        val importance = importances[category.id]
                        val detail = when {
                            importance == null -> null
                            importance == NotificationManagerCompat.IMPORTANCE_NONE -> R.string.notification_category_off
                            importance <= NotificationManagerCompat.IMPORTANCE_LOW -> R.string.notification_category_silent
                            else -> null
                        }
                        ListItem(
                            headlineContent = { Text(stringResource(category.name)) },
                            supportingContent = detail?.let { { Text(stringResource(it)) } },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier
                                .clickable(role = Role.Button) { NotificationPermission.openChannelSettings(context, category.id) }
                                .testTag("${Tags.NOTIFICATIONS_CATEGORY}_${category.id}"),
                        )
                    }
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.all_notification_settings)) },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                        modifier = Modifier
                            .clickable(role = Role.Button) { NotificationPermission.openAppSettings(context) }
                            .testTag(Tags.NOTIFICATIONS_ALL),
                    )
                }
            }
        }
    }
}

/** "Notifications are off", with Turn on: asks, or opens Android's settings once it stops asking. */
@Composable
private fun OffCard(onTurnOn: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        shape = MaterialTheme.shapes.large,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(Tags.NOTIFICATIONS_OFF_CARD),
    ) {
        Row(
            Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(R.drawable.ic_notifications_off), contentDescription = null)
            Text(
                stringResource(R.string.notifications_off),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onTurnOn, modifier = Modifier.testTag(Tags.NOTIFICATIONS_TURN_ON)) {
                Text(stringResource(R.string.notifications_turn_on))
            }
        }
    }
}

private const val TAG = "umsh.settings"
