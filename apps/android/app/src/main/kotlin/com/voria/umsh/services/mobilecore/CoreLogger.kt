package com.voria.umsh.services.mobilecore

import android.util.Log
import com.voria.umsh.core.MobileLogLevel
import com.voria.umsh.core.MobileLogRecord
import com.voria.umsh.core.MobileLogger

/**
 * The core's log lines, into logcat under one tag.
 *
 * A record's private fields (addresses, names, message text) are written
 * only when [includePrivate] is set, which only debug builds do.
 */
class CoreLogger(private val includePrivate: Boolean) : MobileLogger {
    override fun log(record: MobileLogRecord) {
        val priority = when (record.level) {
            MobileLogLevel.ERROR -> Log.ERROR
            MobileLogLevel.WARN -> Log.WARN
            MobileLogLevel.INFO -> Log.INFO
            MobileLogLevel.DEBUG -> Log.DEBUG
            MobileLogLevel.TRACE -> Log.VERBOSE
        }
        val fields = if (includePrivate && record.privateFields.isNotEmpty()) {
            record.privateFields.joinToString(" ", prefix = " ") { "${it.key}=${it.value}" }
        } else {
            ""
        }
        Log.println(priority, TAG, "${record.target}: ${record.message}$fields")
    }

    companion object {
        const val TAG = "umsh.core"
    }
}
