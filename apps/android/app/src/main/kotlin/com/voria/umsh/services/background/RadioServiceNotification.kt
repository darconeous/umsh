package com.voria.umsh.services.background

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.text.format.DateFormat
import androidx.core.app.NotificationCompat
import com.voria.umsh.R
import com.voria.umsh.app.MainActivity
import com.voria.umsh.designsystem.Age
import com.voria.umsh.designsystem.RelativeTimes
import com.voria.umsh.services.format.AndroidTimeFormatting
import com.voria.umsh.services.notifications.NotificationChannels
import com.voria.umsh.services.radio.RadioControlState
import java.text.NumberFormat
import java.time.Instant
import java.time.ZoneId

/**
 * The radio's one notification (`notifications.svg` 3), changed in place:
 * the radio's name as the header's subtext, the state as the title, the
 * power as the text (live while connected, the last reading with its age
 * while it is away), and Disconnect, or Stop while waiting. A tap opens
 * Radio Detail. Not sensitive.
 */
object RadioServiceNotification {
    const val ID = 1

    /** [run] null: the service has just started and nothing is read yet. */
    fun build(context: Context, run: RadioServiceDecision.Run?, nowMs: Long = System.currentTimeMillis()): Notification {
        val name = run?.radio?.name
        val link = run?.link ?: RadioServiceDecision.Link.Connecting
        val title = when (link) {
            RadioServiceDecision.Link.Connected -> named(context, name, R.string.radio_notif_connected, R.string.radio_notif_connected_unnamed)
            RadioServiceDecision.Link.Connecting -> named(context, name, R.string.radio_notif_connecting, R.string.radio_notif_connecting_unnamed)
            RadioServiceDecision.Link.Reconnecting ->
                named(context, name, R.string.radio_notif_reconnecting, R.string.radio_notif_reconnecting_unnamed)
            RadioServiceDecision.Link.Waiting -> named(context, name, R.string.radio_notif_waiting, R.string.radio_notif_waiting_unnamed)
        }
        val text = when (link) {
            RadioServiceDecision.Link.Connected -> run?.let { batteryLine(context, RadioControlState.from(it.radio).power) }
            RadioServiceDecision.Link.Reconnecting, RadioServiceDecision.Link.Waiting -> run?.let { lastBattery(context, it, nowMs) }
            RadioServiceDecision.Link.Connecting -> null
        }
        // Stop while waiting, Disconnect otherwise: worded as on Radio Detail, and the same act.
        val action = if (link == RadioServiceDecision.Link.Waiting) R.string.radio_notif_stop else R.string.radio_disconnect
        return NotificationCompat.Builder(context, NotificationChannels.RADIO)
            // The link glyph, as the radio control draws it.
            .setSmallIcon(if (link == RadioServiceDecision.Link.Waiting) R.drawable.ic_sensors_off else R.drawable.ic_sensors)
            .setContentTitle(title)
            .setContentText(text)
            .setSubText(name)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openRadioDetail(context))
            .addAction(0, context.getString(action), disconnect(context))
            .build()
    }

    /** Whether [run]'s text carries an age, which moves on by the minute. */
    fun showsAge(run: RadioServiceDecision.Run): Boolean =
        (run.link == RadioServiceDecision.Link.Reconnecting || run.link == RadioServiceDecision.Link.Waiting) &&
            run.radio.batteryPercent != null && run.radio.batteryReadAtMs != null

    private fun named(context: Context, name: String?, withName: Int, without: Int): String =
        if (name != null) context.getString(withName, name) else context.getString(without)

    /** "Last battery 78%, 2 min. ago": the reading kept from before the link went, if any. */
    private fun lastBattery(context: Context, run: RadioServiceDecision.Run, nowMs: Long): String? {
        val percent = run.radio.batteryPercent ?: return null
        val readAt = run.radio.batteryReadAtMs ?: return null
        val locale = context.resources.configuration.locales[0]
        val age = when (val ago = RelativeTimes.age(Instant.ofEpochMilli(readAt), Instant.ofEpochMilli(nowMs))) {
            Age.JustNow -> context.getString(R.string.age_just_now)
            is Age.Ago -> AndroidTimeFormatting(locale, ZoneId.systemDefault(), DateFormat.is24HourFormat(context)).ago(ago.count, ago.unit)
        }
        return context.getString(R.string.radio_notif_last_battery, NumberFormat.getPercentInstance(locale).format(percent / 100.0), age)
    }

    private fun batteryLine(context: Context, power: RadioControlState.Power?): String? {
        val percent = NumberFormat.getPercentInstance()
        return when (power) {
            is RadioControlState.Power.Level -> {
                val level = percent.format(power.percent / 100.0)
                when (power.extra) {
                    RadioControlState.Extra.Charging -> context.getString(R.string.radio_notif_charging, level)
                    RadioControlState.Extra.ExternalPower -> context.getString(R.string.radio_notif_external_power)
                    null -> context.getString(R.string.radio_notif_battery, level)
                }
            }
            is RadioControlState.Power.ExternalOnly -> context.getString(R.string.radio_notif_external_power)
            RadioControlState.Power.Unknown, null -> null
        }
    }

    /** Opens the app at Radio Detail, directly (no trampoline). */
    private fun openRadioDetail(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        MainActivity.radioDetailIntent(context),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun disconnect(context: Context): PendingIntent = PendingIntent.getService(
        context,
        0,
        Intent(context, RadioForegroundService::class.java).setAction(RadioForegroundService.ACTION_DISCONNECT),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}
