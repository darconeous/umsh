package com.voria.umsh.services.notifications

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.service.notification.StatusBarNotification
import android.text.SpannableString
import android.text.Spanned
import android.text.style.StyleSpan
import androidx.annotation.VisibleForTesting
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person
import androidx.core.app.RemoteInput
import androidx.core.content.ContextCompat
import androidx.core.content.LocusIdCompat
import androidx.core.os.BundleCompat
import androidx.core.text.BidiFormatter
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.ReplyOutcome
import com.voria.umsh.app.RuntimeNotifications
import com.voria.umsh.core.MobileNotificationEventRecord
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.delay
import kotlinx.coroutines.SupervisorJob

/**
 * Posts what the core asks to be told (§6.2): one MessagingStyle
 * notification a conversation, with its shortcut, Reply and Mark as read;
 * notices for what went wrong. One per process, attached to every runtime
 * the host makes before it starts, and collecting in that runtime's scope:
 * it runs while the radio's service holds the process, with no UI.
 *
 * A message is not posted for the conversation on screen while the app is
 * in front (resumed), and a conversation's notifications go once it is on
 * screen with the app in front, by the same test. A conversation keeps one
 * notice of each kind, the latest, so a run of failures cannot crowd the
 * app's notifications past what Android will show.
 * With Hide contents on the lock screen on, one posted while the phone is
 * locked shows only "New message" until it is unlocked (§6.5).
 *
 * Every post goes through one queue, in turn and spaced, from what is kept
 * here rather than read back from Android: the event loop, a notification's
 * Reply and the unlock all post, and Android neither shows a post at once
 * nor takes updates faster than a few a second.
 */
class MessageNotifier(
    private val context: Context,
    /** The stored Hide contents on the lock screen choice. */
    private val hideOnLockScreen: suspend () -> Boolean,
    /** An activity of the app's is resumed. */
    private val foreground: () -> Boolean = {
        ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
    },
    /** What a tap or a shortcut opens: the app at [address]'s conversation. */
    private val openConversation: (String) -> Intent,
    /** What a Next time heard notice's tap opens: the app at that node (its conversation or its page). */
    private val openPeer: (String) -> Intent,
) : RuntimeNotifications {
    /** The lock screen is up, as the post sees it; instrumented tests answer for it. */
    @VisibleForTesting
    var keyguardLocked: () -> Boolean = {
        context.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == true
    }

    private val manager = NotificationManagerCompat.from(context)
    private val shortcuts = ConversationShortcuts(context, openConversation)

    /** The process has an activity resumed, as [foreground] tells a post; true from ON_RESUME to ON_PAUSE. */
    private val resumed = MutableStateFlow(false)

    /** Watching the lock screen; done once, on the main thread, by [watchProcess]. */
    private var watching = false

    /** Guards what is kept and queued below; held only for quick work, never across a wait. */
    private val lock = Any()

    /** Each conversation's notification as last posted or queued, by address. */
    private val conversations = HashMap<String, Shown>()

    /** Posts waiting their turn, in order; at most one per notification. */
    private val queue = LinkedHashMap<Key, Queued>()

    /** Notifications posted hidden by the lock screen, with the real one each stands for. */
    private val hiddenReal = HashMap<Key, Notification>()

    /** Notifications this process has posted and not withdrawn. */
    private val posted = HashSet<Key>()

    /** When the last post was made ([SystemClock.elapsedRealtime]). */
    private var lastPostAt = Long.MIN_VALUE / 2

    /** One [flush] at a time, so posts keep their spacing. */
    private val turns = Mutex()

    /** Where a reveal's posts are made: the process's, as this notifier is. */
    private val flushing = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Follow the process: reveal what the lock screen hid once the user is
     * present (or the app starts again, should the process have died
     * meanwhile), and say when it is in front. On the main thread, once.
     */
    fun watchProcess() {
        if (watching) return
        watching = true
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) = revealHidden()

                override fun onResume(owner: LifecycleOwner) {
                    resumed.value = true
                }

                override fun onPause(owner: LifecycleOwner) {
                    resumed.value = false
                }
            },
        )
        ContextCompat.registerReceiver(
            context,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = revealHidden()
            },
            IntentFilter(Intent.ACTION_USER_PRESENT),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun attach(runtime: AppRuntime, scope: CoroutineScope) {
        scope.launch(Dispatchers.Default) {
            for (batch in runtime.notificationEvents) {
                for (event in batch) {
                    try {
                        prepare(runtime, event)
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        AppLog.e(TAG, "notification not posted: ${error.javaClass.simpleName}")
                    }
                }
                // One turn for the batch: a conversation's new lines go up together.
                try {
                    flush()
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    AppLog.e(TAG, "notifications not posted: ${error.javaClass.simpleName}")
                }
            }
        }
        // On screen with the app in front: what its notifications announce is shown.
        scope.launch(Dispatchers.Default) {
            combine(runtime.visibleConversation, resumed) { visible, inFront -> visible.takeIf { inFront } }
                .filterNotNull()
                .collect(::withdraw)
        }
        // A conversation removed, here or anywhere: its notifications and shortcut go.
        scope.launch(Dispatchers.Default) {
            var shown: Set<String>? = null
            runtime.appState.filterNotNull().map { state -> state.conversations.mapTo(HashSet()) { it.address } }
                .collect { now ->
                    val gone = shown.orEmpty() - now
                    shown = now
                    if (gone.isNotEmpty()) {
                        gone.forEach(::withdraw)
                        shortcuts.remove(gone)
                    }
                }
        }
    }

    override fun withdrawAll() {
        synchronized(lock) {
            conversations.clear()
            queue.clear()
            hiddenReal.clear()
            posted.forEach { manager.cancel(it.tag, it.id) }
            posted.clear()
            // Tagged ones only: the radio's service notification is not about the identity.
            active().filter { it.tag != null }.forEach { manager.cancel(it.tag, it.id) }
        }
        shortcuts.removeAll()
    }

    /** Every notification about [address]: its conversation's and its notices. */
    fun withdraw(address: String) = withdrawWhere { it.tag == address }

    /** Mark as read: the conversation's notification goes; its notices stay. */
    fun withdrawConversation(address: String) = withdrawWhere { it == Key(address, MESSAGE_ID) }

    /** The notifications [which] picks go, with whatever was kept or queued for them. */
    private fun withdrawWhere(which: (Key) -> Boolean) {
        synchronized(lock) {
            conversations.keys.removeAll { which(Key(it, MESSAGE_ID)) }
            queue.keys.removeAll(which)
            hiddenReal.keys.removeAll(which)
            // Those posted a moment ago may not be in Android's list yet.
            val gone = posted.filter(which)
            posted.removeAll(gone.toSet())
            gone.forEach { manager.cancel(it.tag, it.id) }
            active().filter { it.tag != null && which(Key(it.tag, it.id)) }.forEach { manager.cancel(it.tag, it.id) }
        }
    }

    // region Posting

    /** Say what [event] asks, unless the screen already shows it. */
    suspend fun post(runtime: AppRuntime, event: MobileNotificationEventRecord) {
        prepare(runtime, event)
        flush()
    }

    /** Queue what [event] asks; [flush] posts it. */
    private suspend fun prepare(runtime: AppRuntime, event: MobileNotificationEventRecord) {
        if (NotificationSuppression.suppressed(event, foreground(), runtime.visibleConversation.value)) {
            AppLog.d(TAG, "not posted: its conversation is on screen")
            return
        }
        var directory = NotificationDirectory.of(runtime.appState.value)
        // A conversation the lists have not read yet is named once they have.
        if (directory.misses(event)) {
            runtime.reload(full = true).await()
            directory = NotificationDirectory.of(runtime.appState.value)
        }
        when (val plan = NotificationText.plan(event, directory, names())) {
            is NotificationPlan.Line -> queueLine(plan)
            is NotificationPlan.Notice -> queueNotice(plan)
        }
    }

    /**
     * The end of a reply typed into [address]'s notification: the line it
     * sent is added, or a notice says what became of it. Either way the
     * notification is posted again, which is what ends the reply's spinner.
     */
    suspend fun replyFinished(runtime: AppRuntime?, address: String, text: String, outcome: ReplyOutcome) {
        when (outcome) {
            ReplyOutcome.Sent -> queueRepost(address, mine = text)
            is ReplyOutcome.Failed -> {
                queueRepost(address, mine = null)
                val spec = runtime?.let { specFor(it, address) }
                queueNotice(NotificationText.replyFailed(spec, address, outcome.savedAsDraft))
            }
        }
        flush()
    }

    /** A reply with nothing to send: the notification is posted again, ending its spinner. */
    suspend fun endReply(address: String) {
        queueRepost(address, mine = null)
        flush()
    }

    private suspend fun specFor(runtime: AppRuntime, address: String): ConversationSpec? {
        val state = runtime.appState.value ?: return null
        val conversation = state.conversations.firstOrNull { it.address == address } ?: return null
        val channelId = (conversation as? ChannelConversationSummary)?.channel?.id
        return NotificationText.spec(address, channelId, NotificationDirectory.of(state), names(), null)
    }

    private fun queueLine(plan: NotificationPlan.Line) {
        val spec = plan.spec
        val title = resolve(spec.title)
        val speaker = NotificationPeople.person(plan.speaker.key, resolve(plan.speaker.name), plan.speaker.avatar)
        val body = resolve(plan.body).let { if (plan.status) italic(it) else it }
        shortcuts.push(spec.address, title, if (spec.group) null else speaker, spec.avatar)
        val stored = Stored(spec.address, spec.channel, title, spec.group, spec.offersReply)
        val line = NotificationCompat.MessagingStyle.Message(body, System.currentTimeMillis(), speaker)
        synchronized(lock) {
            val kept = keptFor(stored.address)
            val lines = kept?.lines ?: ArrayDeque()
            lines.addLast(line)
            while (lines.size > MAX_LINES) lines.removeFirst()
            conversations[stored.address] = Shown(stored, lines, kept?.postedAt)
            enqueue(Key(stored.address, MESSAGE_ID), stored.channel, alert = true) { alertOnce -> conversation(stored.address, alertOnce) }
        }
    }

    /** Post [address]'s conversation notification again, with [mine] added; nothing when it is gone. */
    private fun queueRepost(address: String, mine: String?) {
        synchronized(lock) {
            val kept = keptFor(address) ?: return
            mine?.let {
                kept.lines.addLast(NotificationCompat.MessagingStyle.Message(it, System.currentTimeMillis(), null as Person?))
                while (kept.lines.size > MAX_LINES) kept.lines.removeFirst()
            }
            enqueue(Key(address, MESSAGE_ID), kept.stored.channel, alert = false) { alertOnce -> conversation(address, alertOnce) }
        }
    }

    /**
     * Under [lock]: what [address]'s conversation notification shows. Kept
     * here, since Android takes a post a moment after it is made, so a
     * notification read back straight after one may lack its last line.
     * What is kept is dropped once Android no longer shows it (dismissed,
     * or cleared); after a process start the shade's own is read, once.
     */
    private fun keptFor(address: String): Shown? {
        val now = SystemClock.elapsedRealtime()
        conversations[address]?.let { kept ->
            val at = kept.postedAt
            if (at == null || now - at < LANDING_MS || activeConversation(address) != null) return kept
            conversations.remove(address)
            return null
        }
        val active = activeConversation(address) ?: return null
        val real = realOf(active.notification)
        val stored = Stored.from(address, real.extras) ?: return null
        val lines = ArrayDeque(
            NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(real)?.messages.orEmpty().takeLast(MAX_LINES),
        )
        return Shown(stored, lines, now).also { conversations[address] = it }
    }

    private fun activeConversation(address: String): StatusBarNotification? =
        active().firstOrNull { it.tag == address && it.id == MESSAGE_ID }

    /** Under [lock]: [address]'s conversation notification as kept now; null when it has gone. */
    private fun conversation(address: String, alertOnce: Boolean): Notification? {
        val kept = conversations[address] ?: return null
        val style = NotificationCompat.MessagingStyle(me())
        if (kept.stored.group) style.setConversationTitle(kept.stored.title).setGroupConversation(true)
        kept.lines.forEach(style::addMessage)
        return build(kept.stored, style, alertOnce)
    }

    private fun build(stored: Stored, style: NotificationCompat.MessagingStyle, alertOnce: Boolean): Notification {
        val address = stored.address
        return NotificationCompat.Builder(context, stored.channel)
            .setSmallIcon(R.drawable.ic_forum)
            .setStyle(style)
            .setContentTitle(stored.title)
            .setShortcutId(address)
            .setLocusId(LocusIdCompat(address))
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion(stored.channel))
            .setContentIntent(openIntent(address))
            .setAutoCancel(true)
            .setOnlyAlertOnce(alertOnce)
            .setShowWhen(true)
            .apply {
                if (stored.offersReply) addAction(replyAction(address))
                addAction(markReadAction(address))
            }
            .addExtras(stored.extras())
            .build()
    }

    private fun queueNotice(plan: NotificationPlan.Notice) {
        val title = resolve(plan.title)
        val text = resolve(plan.text)
        val avatar = AvatarBitmaps.of(plan.avatar)
        // In place of the conversation's last notice of the kind, alerting again.
        synchronized(lock) {
            enqueue(Key(plan.address, plan.kind.id), plan.channel, alert = true) { alertOnce ->
                NotificationCompat.Builder(context, plan.channel)
                    .setSmallIcon(if (plan.channel == NotificationChannels.PROBLEMS) R.drawable.ic_error else R.drawable.ic_forum)
                    .setContentTitle(title)
                    .setContentText(text)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                    .setLargeIcon(avatar)
                    .setCategory(
                        if (plan.channel == NotificationChannels.PROBLEMS) NotificationCompat.CATEGORY_ERROR else NotificationCompat.CATEGORY_STATUS,
                    )
                    .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                    .setPublicVersion(publicVersion(plan.channel))
                    .setContentIntent(if (plan.kind == NoticeKind.Heard) peerIntent(plan.address) else openIntent(plan.address))
                    .setAutoCancel(true)
                    .setOnlyAlertOnce(alertOnce)
                    .build()
            }
        }
    }

    /**
     * Under [lock]: [key]'s next post, made at its turn by [make] (given
     * whether to alert only once; null: nothing to post). One already
     * waiting is taken over, alerting if either would.
     */
    private fun enqueue(key: Key, channel: String, alert: Boolean, make: (alertOnce: Boolean) -> Notification?) {
        val waiting = queue[key]
        queue[key] = Queued(channel, alert || waiting?.alert == true, make)
    }

    /**
     * Post what is queued, one at a time and spaced: Android drops updates
     * that come faster than a few a second ("Shedding events"), and a
     * burst queued meanwhile is taken over, not posted line by line. Each
     * post is made at its turn from what is kept then, so it carries every
     * line added before it.
     */
    private suspend fun flush() = turns.withLock {
        while (true) {
            val wait = synchronized(lock) {
                if (queue.isEmpty()) return@withLock
                lastPostAt + SPACING_MS - SystemClock.elapsedRealtime()
            }
            if (wait > 0) delay(wait)
            val hide = hideOnLockScreen() && keyguardLocked()
            synchronized(lock) { postNext(hide) }
        }
    }

    /**
     * Under [lock]: post the first queued, or, with Hide contents on and
     * the phone locked ([hide]), its public version in its place: no
     * actions, the real one kept inside it to be revealed on unlock with no
     * second alert.
     */
    @SuppressLint("MissingPermission") // Checked: notifications off post nothing.
    private fun postNext(hide: Boolean) {
        val (key, queued) = queue.entries.firstOrNull()?.toPair() ?: return
        queue.remove(key)
        if (!manager.areNotificationsEnabled()) {
            AppLog.i(TAG, "not posted: notifications are off")
            if (key.id == MESSAGE_ID) conversations.remove(key.tag)
            return
        }
        val notification = if (hide) {
            val real = queued.make(true) ?: return
            hiddenReal[key] = real
            hidden(key, queued.channel, real, alertOnce = !queued.alert)
        } else {
            hiddenReal.remove(key)
            queued.make(!queued.alert) ?: return
        }
        manager.notify(key.tag, key.id, notification)
        posted += key
        lastPostAt = SystemClock.elapsedRealtime()
        if (key.id == MESSAGE_ID) conversations[key.tag]?.postedAt = lastPostAt
    }

    private fun hidden(key: Key, channel: String, real: Notification, alertOnce: Boolean): Notification =
        NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_forum)
            .setContentTitle(context.getString(R.string.notification_public_title))
            .setContentText(context.getString(R.string.notification_public_text))
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(if (key.id == NoticeKind.Heard.id) peerIntent(key.tag) else openIntent(key.tag))
            .setAutoCancel(true)
            .setOnlyAlertOnce(alertOnce)
            .addExtras(Bundle().apply { putParcelable(EXTRA_REAL, real) })
            .build()

    /** Show what the lock screen hid, once the phone is unlocked; no second alert. */
    fun revealHidden() {
        if (keyguardLocked() || !manager.areNotificationsEnabled()) return
        synchronized(lock) {
            // Those posted hidden by this process, and any an earlier one left.
            val reals = HashMap(hiddenReal)
            for (shown in active()) {
                val tag = shown.tag ?: continue
                val real = BundleCompat.getParcelable(shown.notification.extras, EXTRA_REAL, Notification::class.java) ?: continue
                reals.putIfAbsent(Key(tag, shown.id), real)
            }
            hiddenReal.clear()
            for ((key, real) in reals) {
                // One already queued takes its turn as the lock screen then allows.
                if (key in queue) continue
                val make: (Boolean) -> Notification? = if (key.id == MESSAGE_ID && conversations.containsKey(key.tag)) {
                    { alertOnce -> conversation(key.tag, alertOnce) }
                } else {
                    { _ -> real }
                }
                queue[key] = Queued(real.channelId, alert = false, make)
            }
        }
        flushing.launch { flush() }
    }

    private fun publicVersion(channel: String): Notification = NotificationCompat.Builder(context, channel)
        .setSmallIcon(R.drawable.ic_forum)
        .setContentTitle(context.getString(R.string.notification_public_title))
        .setContentText(context.getString(R.string.notification_public_text))
        .setCategory(NotificationCompat.CATEGORY_MESSAGE)
        .build()

    /** What [notification] stands for: the real one a hidden notification carries, or itself. */
    private fun realOf(notification: Notification): Notification =
        BundleCompat.getParcelable(notification.extras, EXTRA_REAL, Notification::class.java) ?: notification

    // endregion

    // region Actions

    private fun replyAction(address: String): NotificationCompat.Action {
        val input = RemoteInput.Builder(KEY_REPLY_TEXT)
            .setLabel(context.getString(R.string.notification_reply_hint))
            .build()
        val intent = actionIntent(NotificationActionReceiver.ACTION_REPLY, address)
        // Mutable: the system fills in what was typed.
        val pending = PendingIntent.getBroadcast(
            context,
            0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Action.Builder(R.drawable.ic_reply, context.getString(R.string.notification_reply), pending)
            .addRemoteInput(input)
            .setAllowGeneratedReplies(false)
            .setSemanticAction(NotificationCompat.Action.SEMANTIC_ACTION_REPLY)
            .setShowsUserInterface(false)
            .build()
    }

    private fun markReadAction(address: String): NotificationCompat.Action {
        val pending = PendingIntent.getBroadcast(
            context,
            0,
            actionIntent(NotificationActionReceiver.ACTION_MARK_READ, address),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Action.Builder(R.drawable.ic_check, context.getString(R.string.notification_mark_read), pending)
            .setSemanticAction(NotificationCompat.Action.SEMANTIC_ACTION_MARK_AS_READ)
            .setShowsUserInterface(false)
            .build()
    }

    /** Explicit, and one per conversation and action: the data tells them apart. */
    private fun actionIntent(action: String, address: String) =
        Intent(context, NotificationActionReceiver::class.java)
            .setAction(action)
            .setData(Uri.Builder().scheme(SCHEME).authority(action).appendPath(address).build())
            .putExtra(NotificationActionReceiver.EXTRA_ADDRESS, address)

    /** Opens the activity itself, no trampoline: one per conversation. */
    private fun openIntent(address: String): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        openConversation(address).setData(Uri.Builder().scheme(SCHEME).authority(OPEN).appendPath(address).build()),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    /** Opens the activity at a node a notice is about: one per node, told apart from its conversation's by the data. */
    private fun peerIntent(address: String): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        openPeer(address).setData(Uri.Builder().scheme(SCHEME).authority(PEER).appendPath(address).build()),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    // endregion

    private fun active(): List<StatusBarNotification> =
        runCatching { context.getSystemService(NotificationManager::class.java).activeNotifications.toList() }
            .getOrDefault(emptyList())

    private fun me(): Person = Person.Builder().setName(context.getString(R.string.notification_you)).build()

    private fun names() = DisplayNames(
        unnamedNode = context.getString(R.string.unnamed_node),
        companionRadio = context.getString(R.string.companion_radio),
        privateChannel = context.getString(R.string.channel_private),
        publicChannel = context.getString(R.string.channel_public),
        emergencyChannel = context.getString(R.string.channel_emergency),
    )

    /** [text] in the reader's language. Names and messages inside a sentence keep their own direction. */
    fun resolve(text: NoteText): CharSequence = when (text) {
        is NoteText.Plain -> text.text
        is NoteText.Res -> context.getString(
            text.id,
            *text.args.map { arg ->
                val resolved = resolve(arg).toString()
                if (arg is NoteText.Plain) BidiFormatter.getInstance().unicodeWrap(resolved) else resolved
            }.toTypedArray(),
        )
        is NoteText.Plural -> context.resources.getQuantityString(text.id, text.count, text.count)
    }

    private fun italic(text: CharSequence): CharSequence = SpannableString(text).apply {
        setSpan(StyleSpan(Typeface.ITALIC), 0, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    /** A notification of the app's: its tag (a conversation's address) and ID. */
    private data class Key(val tag: String, val id: Int)

    /** What a conversation's notification shows. [postedAt]: when it was last posted; null while queued. */
    private class Shown(
        val stored: Stored,
        val lines: ArrayDeque<NotificationCompat.MessagingStyle.Message>,
        var postedAt: Long?,
    )

    /** A post waiting its turn: [make] builds it then, given whether to alert only once. */
    private class Queued(val channel: String, val alert: Boolean, val make: (alertOnce: Boolean) -> Notification?)

    /** What a conversation notification is rebuilt from: kept in its extras. */
    private data class Stored(
        val address: String,
        val channel: String,
        val title: CharSequence,
        val group: Boolean,
        val offersReply: Boolean,
    ) {
        fun extras() = Bundle().apply {
            putString(EXTRA_CHANNEL, channel)
            putCharSequence(EXTRA_TITLE, title)
            putBoolean(EXTRA_GROUP, group)
            putBoolean(EXTRA_OFFERS_REPLY, offersReply)
        }

        companion object {
            fun from(address: String, extras: Bundle): Stored? {
                val channel = extras.getString(EXTRA_CHANNEL) ?: return null
                return Stored(
                    address = address,
                    channel = channel,
                    title = extras.getCharSequence(EXTRA_TITLE) ?: "",
                    group = extras.getBoolean(EXTRA_GROUP),
                    offersReply = extras.getBoolean(EXTRA_OFFERS_REPLY),
                )
            }
        }
    }

    companion object {
        private const val TAG = "umsh.notify"

        /** A conversation's notification, tagged with its address. */
        const val MESSAGE_ID = 10

        /** The lines a conversation's notification keeps. */
        const val MAX_LINES = 7

        /**
         * Between two posts. Android sheds a package's updates above five a
         * second, counting the radio's service notification too.
         */
        private const val SPACING_MS = 300L

        /** How long a post may take to show in Android's list; one missing after that was dismissed. */
        private const val LANDING_MS = 2_000L

        const val KEY_REPLY_TEXT = "umsh.reply"
        private const val SCHEME = "umsh-notification"
        private const val OPEN = "open"
        private const val PEER = "peer"
        const val EXTRA_REAL = "umsh.real"
        private const val EXTRA_CHANNEL = "umsh.channel"
        private const val EXTRA_TITLE = "umsh.title"
        private const val EXTRA_GROUP = "umsh.group"
        private const val EXTRA_OFFERS_REPLY = "umsh.offersReply"
    }
}
