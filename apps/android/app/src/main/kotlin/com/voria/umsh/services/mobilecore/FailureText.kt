package com.voria.umsh.services.mobilecore

import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileStoreException
import java.io.IOException

/** The reason line of a failure dialog. */
sealed interface FailureReason {
    /** What Android reported, as a phrase: shown as "Android reported: the disk is full." */
    data class Android(val phrase: ReasonText) : FailureReason

    /** The app's own sentence for a failure Android did not report. */
    data class Sentence(val text: ReasonText) : FailureReason
}

/**
 * The words for a failure that won't fix itself (`onboarding.svg` board 3):
 * a storage failure names what Android reported; anything else gets the
 * core's reason sentence ([CoreErrors]).
 */
object FailureText {
    fun reason(error: Throwable): FailureReason = when (error) {
        is MobileAppException.Store -> storage(error.error)
        is MobileStoreException -> storage(error)
        is IOException -> FailureReason.Android(ReasonText(R.string.android_reason_io))
        else -> FailureReason.Sentence(CoreErrors.reason(error))
    }

    private fun storage(error: MobileStoreException): FailureReason = when (error) {
        is MobileStoreException.OpenFailed -> FailureReason.Android(sqlite(error.code))
        is MobileStoreException.Failed -> FailureReason.Android(sqlite(error.code))
        is MobileStoreException.UnsupportedSchema,
        is MobileStoreException.RecordNotFound,
        is MobileStoreException.InvalidArgument,
        -> FailureReason.Sentence(CoreErrors.reason(error))
    }

    /** SQLite's result code as a phrase; one with no phrase of its own is named. */
    fun sqlite(code: Int): ReasonText = when (code and 0xFF) {
        13 -> ReasonText(R.string.android_reason_full)
        8 -> ReasonText(R.string.android_reason_read_only)
        10 -> ReasonText(R.string.android_reason_io)
        11, 26 -> ReasonText(R.string.android_reason_damaged)
        14 -> ReasonText(R.string.android_reason_cant_open)
        5, 6 -> ReasonText(R.string.android_reason_busy)
        3, 23 -> ReasonText(R.string.android_reason_denied)
        else -> ReasonText(R.string.android_reason_code, listOf(SqliteCodes.name(code)))
    }

    /** The full error, for Copy details: diagnostic, never translated, never shown. */
    fun details(error: Throwable): String = generateSequence(error) { it.cause }
        .take(MAX_CAUSES)
        .joinToString("\ncaused by ") { "${it.javaClass.name}: ${it.message.orEmpty()}" }

    private const val MAX_CAUSES = 4
}
