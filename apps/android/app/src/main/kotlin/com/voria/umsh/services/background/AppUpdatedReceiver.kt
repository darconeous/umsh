package com.voria.umsh.services.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.launch

/**
 * The app was just updated (DP-94). An update ends the process, and on
 * API 31–35 nothing brings a radio still in range back: Android reports no
 * new appearance for a radio it still counts as present. This broadcast
 * lets the radio's service start from the background, so it does
 * ([RadioServiceController.startForUpdate]), under the same rules as a
 * presence wake: only a wanted radio that is not still being added, and
 * nothing while the user's stop holds ([UserStop]).
 *
 * API 36 and later rebind the presence service after an update, which
 * starts it there ([RadioPresenceService]); this does nothing on those.
 */
class AppUpdatedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!startsService(Build.VERSION.SDK_INT)) {
            AppLog.i(TAG, "update: left to the presence rebind")
            return
        }
        val application = context.applicationContext as UmshApplication
        val pending = goAsync()
        application.backgroundScope.launch {
            try {
                application.radioService.startForUpdate()
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        private const val TAG = "umsh.service"

        /** Whether the update broadcast is what starts the service at API level [sdk]: below 36. */
        fun startsService(sdk: Int): Boolean = sdk < Build.VERSION_CODES.BAKLAVA
    }
}
