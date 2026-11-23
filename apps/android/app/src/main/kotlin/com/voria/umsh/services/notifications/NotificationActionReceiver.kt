package com.voria.umsh.services.notifications

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.RemoteInput
import com.voria.umsh.app.ReplyOutcome
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * A message notification's Reply and Mark as read (§6.3). Not exported:
 * only the app's own explicit PendingIntents reach it.
 *
 * The broadcast is held (`goAsync`) until the work ends, so the process is
 * not frozen mid-wait. The waits are bounded well inside a background
 * broadcast's limit; a send, once asked for, is waited for, so the notice
 * says what became of the words. A reply first starts the radio's service
 * when a radio is bound and none runs, so the process waits for the link
 * at foreground priority; then the runtime comes up headless (never
 * minting), the radio is waited for, and the reply sends, or its words go
 * to the draft and a notice says so.
 */
class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext as UmshApplication
        val address = intent.getStringExtra(EXTRA_ADDRESS) ?: return
        val action = intent.action ?: return
        val text = if (action == ACTION_REPLY) {
            RemoteInput.getResultsFromIntent(intent)?.getCharSequence(MessageNotifier.KEY_REPLY_TEXT)?.toString()?.trim()
        } else {
            null
        }
        val pending = goAsync()
        app.backgroundScope.launch {
            try {
                when (action) {
                    ACTION_REPLY -> reply(app, address, text.orEmpty())
                    ACTION_MARK_READ -> markRead(app, address)
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.e(TAG, "notification action failed: ${error.javaClass.simpleName}")
            } finally {
                pending.finish()
            }
        }
    }

    private suspend fun reply(app: UmshApplication, address: String, text: String) {
        val notifier = app.notifier
        if (text.isEmpty()) {
            // Nothing typed: the spinner ends, and nothing is sent.
            notifier.endReply(address)
            return
        }
        app.radioService.startForAction()
        val runtime = app.coreHost.runtimeForAction(RUNTIME_WAIT_MS)
        if (runtime == null) {
            AppLog.w(TAG, "reply: no runtime")
            notifier.replyFinished(null, address, text, ReplyOutcome.Failed(savedAsDraft = false))
            return
        }
        val outcome = try {
            runtime.deliverNotificationReply(address, text).await()
        } catch (error: CancellationException) {
            // This work's own end, or the runtime's: an erase, a switch or a
            // lost identity took it down mid-reply. Then the spinner ends
            // (on a notification an erase has not withdrawn), with no notice
            // about a conversation that may be gone.
            currentCoroutineContext().ensureActive()
            AppLog.w(TAG, "reply: the runtime ended")
            notifier.endReply(address)
            return
        } catch (error: Exception) {
            AppLog.e(TAG, "reply failed: ${error.javaClass.simpleName}")
            ReplyOutcome.Failed(savedAsDraft = false)
        }
        AppLog.i(TAG, "reply: $outcome")
        notifier.replyFinished(runtime, address, text, outcome)
    }

    /** The notification goes whatever became of the read: the user is done with it. */
    private suspend fun markRead(app: UmshApplication, address: String) {
        try {
            val runtime = app.coreHost.runtimeForAction(RUNTIME_WAIT_MS)
            if (runtime == null) {
                AppLog.w(TAG, "mark as read: no runtime")
                return
            }
            withTimeoutOrNull(MARK_READ_BUDGET_MS) { runtime.markReadFromNotification(address).await() }
                ?: AppLog.w(TAG, "mark as read: not done in time")
        } finally {
            app.notifier.withdrawConversation(address)
        }
    }

    companion object {
        const val ACTION_REPLY = "com.voria.umsh.action.REPLY"
        const val ACTION_MARK_READ = "com.voria.umsh.action.MARK_READ"
        const val EXTRA_ADDRESS = "umsh.conversation"
        private const val TAG = "umsh.notify"

        /** The store and the identity, as iOS waits for them. */
        private const val RUNTIME_WAIT_MS = 10_000L

        /** The start, then the write, inside a background broadcast's minute. */
        private const val MARK_READ_BUDGET_MS = 40_000L
    }
}
