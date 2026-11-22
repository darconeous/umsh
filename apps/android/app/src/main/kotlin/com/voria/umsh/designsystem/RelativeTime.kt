package com.voria.umsh.designsystem

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.text.format.DateFormat
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.core.content.ContextCompat
import com.voria.umsh.R
import com.voria.umsh.services.format.AgeUnit
import com.voria.umsh.services.format.AndroidTimeFormatting
import com.voria.umsh.services.format.TimeFormatting
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.temporal.ChronoUnit

/** A list row's trailing time, before its words are resolved. */
sealed interface ListTime {
    data class Text(val text: String) : ListTime
    data object Yesterday : ListTime
}

/** A transcript's date line, before its words are resolved. */
sealed interface DateLine {
    data class Today(val time: String) : DateLine
    data class Yesterday(val time: String) : DateLine
    data class Text(val text: String) : DateLine
}

/** An age: under a minute, or whole units. */
sealed interface Age {
    data object JustNow : Age
    data class Ago(val count: Long, val unit: AgeUnit) : Age
}

/**
 * Which pieces a time is shown with, by calendar day in the formatter's
 * zone. Pure, so the JVM tests cover the choice with a stand-in formatter;
 * the pieces' real text is ICU's, tested on a device.
 */
object RelativeTimes {
    /** "10:21" today, "Yesterday", "Mon" within the week, "Oct 28" this year, else with the year. */
    fun listTime(at: Instant, now: Instant, format: TimeFormatting): ListTime {
        val days = daysBetween(at, now, format.zone)
        val sameYear = at.atZone(format.zone).year == now.atZone(format.zone).year
        return when {
            days <= 0L -> ListTime.Text(format.timeOfDay(at))
            days == 1L -> ListTime.Yesterday
            days < 7L -> ListTime.Text(format.weekday(at))
            sameYear -> ListTime.Text(format.monthDay(at))
            else -> ListTime.Text(format.monthDayYear(at))
        }
    }

    /** Today or Yesterday with a time, else a month and day with a time, with the year if it differs. */
    fun dateLine(at: Instant, now: Instant, format: TimeFormatting): DateLine {
        val days = daysBetween(at, now, format.zone)
        val sameYear = at.atZone(format.zone).year == now.atZone(format.zone).year
        return when {
            days == 0L -> DateLine.Today(format.timeOfDay(at))
            days == 1L -> DateLine.Yesterday(format.timeOfDay(at))
            sameYear -> DateLine.Text(format.monthDayTime(at))
            else -> DateLine.Text(format.monthDayYearTime(at))
        }
    }

    /**
     * How long ago, in the fewest words that stay true: "just now" for the
     * first minute, then whole minutes, hours or days. Never seconds.
     */
    fun age(since: Instant, now: Instant): Age {
        val seconds = Duration.between(since, now).seconds
        return when {
            seconds < 60 -> Age.JustNow
            seconds < 3_600 -> Age.Ago(seconds / 60, AgeUnit.Minutes)
            seconds < 86_400 -> Age.Ago(seconds / 3_600, AgeUnit.Hours)
            else -> Age.Ago(seconds / 86_400, AgeUnit.Days)
        }
    }

    /** Calendar days from [at]'s date to [now]'s; negative for a time ahead of the clock. */
    private fun daysBetween(at: Instant, now: Instant, zone: ZoneId): Long =
        ChronoUnit.DAYS.between(at.atZone(zone).toLocalDate(), now.atZone(zone).toLocalDate())
}

/**
 * The phone's time formatter, one per composition tree ([ProvideTimeFormatting]
 * supplies it). Rows read it rather than building their own, so a list of
 * times shares one set of ICU formatters.
 */
val LocalTimeFormatting = staticCompositionLocalOf<TimeFormatting> {
    error("No TimeFormatting: wrap the content in UmshTheme")
}

/**
 * Supplies [LocalTimeFormatting], rebuilt when the locale, zone or 24-hour
 * setting changes. The 24-hour toggle and a zone change raise no
 * configuration change, only `ACTION_TIME_CHANGED` and
 * `ACTION_TIMEZONE_CHANGED`, so those broadcasts re-read both.
 */
@Composable
fun ProvideTimeFormatting(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val locale = LocalConfiguration.current.locales[0]
    var use24Hour by remember { mutableStateOf(DateFormat.is24HourFormat(context)) }
    var zone by remember { mutableStateOf(ZoneId.systemDefault()) }
    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                use24Hour = DateFormat.is24HourFormat(context)
                zone = ZoneId.systemDefault()
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_TIME_CHANGED)
                addAction(Intent.ACTION_TIMEZONE_CHANGED)
            },
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        // A change while the receiver was not registered (the app in the
        // background) is picked up here, when the tree comes back.
        use24Hour = DateFormat.is24HourFormat(context)
        zone = ZoneId.systemDefault()
        onDispose { context.unregisterReceiver(receiver) }
    }
    val formatting = remember(locale, use24Hour, zone) { AndroidTimeFormatting(locale, zone, use24Hour) }
    CompositionLocalProvider(LocalTimeFormatting provides formatting, content = content)
}

/** [at] as a list row's trailing time; [now] only decides which piece. */
@Composable
fun listTimeText(at: Instant, now: Instant): String =
    when (val time = RelativeTimes.listTime(at, now, LocalTimeFormatting.current)) {
        is ListTime.Text -> time.text
        ListTime.Yesterday -> stringResource(R.string.time_yesterday)
    }

/** [at] as a transcript's date line; [now] only decides which piece. */
@Composable
fun dateLineText(at: Instant, now: Instant): String =
    when (val line = RelativeTimes.dateLine(at, now, LocalTimeFormatting.current)) {
        is DateLine.Today -> stringResource(R.string.date_line_today, line.time)
        is DateLine.Yesterday -> stringResource(R.string.date_line_yesterday, line.time)
        is DateLine.Text -> line.text
    }

/** [at] as a transcript's date line, its day in [dayStyle]: "**Today** 9:40". */
@Composable
fun dateLineText(at: Instant, now: Instant, dayStyle: SpanStyle): AnnotatedString =
    when (val line = RelativeTimes.dateLine(at, now, LocalTimeFormatting.current)) {
        is DateLine.Today -> annotatedStringResource(R.string.date_line_today, AnnotatedString(line.time), styles = mapOf(DAY to dayStyle))
        is DateLine.Yesterday ->
            annotatedStringResource(R.string.date_line_yesterday, AnnotatedString(line.time), styles = mapOf(DAY to dayStyle))
        is DateLine.Text -> AnnotatedString(line.text)
    }

/** The `<annotation type>` that marks a date line's day. */
private const val DAY = "day"

/** How long before [now] [since] was. */
@Composable
fun ageText(since: Instant, now: Instant): String = when (val age = RelativeTimes.age(since, now)) {
    Age.JustNow -> stringResource(R.string.age_just_now)
    is Age.Ago -> LocalTimeFormatting.current.ago(age.count, age.unit)
}

/** [ageText] in full words, for TalkBack: "12 minutes ago". */
@Composable
fun ageSpokenText(since: Instant, now: Instant): String = when (val age = RelativeTimes.age(since, now)) {
    Age.JustNow -> stringResource(R.string.age_just_now)
    is Age.Ago -> LocalTimeFormatting.current.agoSpoken(age.count, age.unit)
}
