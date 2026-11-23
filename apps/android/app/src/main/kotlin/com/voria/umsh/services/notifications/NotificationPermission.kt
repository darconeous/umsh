package com.voria.umsh.services.notifications

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.permissions.rememberPermissionAsker
import com.voria.umsh.services.preferences.AppPreferences

/**
 * Notifications (§6.6): `POST_NOTIFICATIONS` from Android 13, asked for once
 * when the first radio connects, never at launch or after Set up later;
 * granted from install below 13.
 */
object NotificationPermission {
    /** The runtime permission exists (Android 13 and later). */
    val asked: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    fun granted(context: Context): Boolean = !asked ||
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /** The app may post at all: the permission, and the app not turned off in Android's settings. */
    fun enabled(context: Context): Boolean = NotificationManagerCompat.from(context).areNotificationsEnabled()

    /** Android's notification settings for the app. */
    fun openAppSettings(context: Context) = open(
        context,
        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
    )

    /** Android's page for one of the app's notification channels. */
    fun openChannelSettings(context: Context, channel: String) = open(
        context,
        Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            .putExtra(Settings.EXTRA_CHANNEL_ID, channel),
    )

    private fun open(context: Context, intent: Intent) {
        try {
            context.startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            AppLog.w(TAG, "no notification settings page")
        }
    }

    private const val TAG = "umsh.permissions"
}

/**
 * The "Notifications are off" card's Turn on: Android's dialog while it will
 * still show it; otherwise, or with the permission granted and the app
 * turned off in Android's settings, those settings.
 */
@Composable
fun rememberNotificationsTurnOn(preferences: AppPreferences): () -> Unit {
    val context = LocalContext.current
    val ask = rememberPermissionAsker(
        permissions = arrayOf(Manifest.permission.POST_NOTIFICATIONS),
        granted = NotificationPermission::granted,
        blocked = preferences.notificationsBlocked,
        setBlocked = preferences::setNotificationsBlocked,
        openSettings = NotificationPermission::openAppSettings,
        name = "notifications",
        // A radio service started before this shows nothing until posted again.
        onGranted = { (context.applicationContext as UmshApplication).radioService.repostNotification() },
    )
    return remember(context, ask) {
        { if (NotificationPermission.granted(context)) NotificationPermission.openAppSettings(context) else ask() }
    }
}
