package com.voria.umsh.services.notifications

import android.content.Context
import androidx.annotation.StringRes
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationManagerCompat
import com.voria.umsh.R

/**
 * The app's notification channels (§6.1), created at process start, the
 * five Settings › Notifications lists. Creating one that exists changes
 * nothing the user set, so this runs every launch; only the name and
 * description follow the language.
 */
object NotificationChannels {
    const val DIRECT = "direct"
    const val CHANNELS = "channels"
    const val EMERGENCY = "emergency"

    /** The radio's foreground service notification: silent, no badge. */
    const val RADIO = "radio"
    const val PROBLEMS = "problems"

    /** One channel, as Settings › Notifications lists it. */
    data class Category(val id: String, @StringRes val name: Int, @StringRes val description: Int)

    /** In the order Settings › Notifications lists them. */
    val categories = listOf(
        Category(DIRECT, R.string.notification_channel_direct, R.string.notification_channel_direct_description),
        Category(CHANNELS, R.string.notification_channel_channels, R.string.notification_channel_channels_description),
        Category(EMERGENCY, R.string.notification_channel_emergency, R.string.notification_channel_emergency_description),
        Category(RADIO, R.string.notification_channel_radio, R.string.notification_channel_radio_description),
        Category(PROBLEMS, R.string.notification_channel_problems, R.string.notification_channel_problems_description),
    )

    fun ensure(context: Context) {
        fun channel(category: Category, importance: Int) =
            NotificationChannelCompat.Builder(category.id, importance)
                .setName(context.getString(category.name))
                .setDescription(context.getString(category.description))
        val (direct, channels, emergency, radio, problems) = categories
        NotificationManagerCompat.from(context).createNotificationChannelsCompat(
            listOf(
                channel(direct, NotificationManagerCompat.IMPORTANCE_HIGH).build(),
                channel(channels, NotificationManagerCompat.IMPORTANCE_DEFAULT).build(),
                channel(emergency, NotificationManagerCompat.IMPORTANCE_HIGH).build(),
                channel(radio, NotificationManagerCompat.IMPORTANCE_LOW)
                    .setShowBadge(false)
                    .setSound(null, null)
                    .setVibrationEnabled(false)
                    .build(),
                channel(problems, NotificationManagerCompat.IMPORTANCE_DEFAULT).build(),
            ),
        )
    }
}
