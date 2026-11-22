package com.voria.umsh.features.conversations

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.ConversationSummary
import com.voria.umsh.models.MessageRef
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Where the thread should put the reader next; [id] makes each request new. */
data class ScrollRequest(val id: Long, val target: Target) {
    sealed interface Target {
        /** The newest message, at the bottom. */
        data object Latest : Target

        /** One message, centered: a quote's original. */
        data class Message(val key: String) : Target
    }
}

/** What the thread draws from the window: the rows, and where to scroll. */
data class ThreadTranscript(
    val window: TranscriptWindow = TranscriptWindow(),
    val scroll: ScrollRequest? = null,
    /** A row washed in the conversation's color for a moment: a quote's original, just shown. */
    val highlighted: String? = null,
    val isLoadingOlder: Boolean = false,
    val isLoadingNewer: Boolean = false,
)

/**
 * One conversation's thread: its window on the transcript, kept here and
 * not in a cold flow, so the reading position survives the screen going
 * away for a moment; and the composer's draft.
 *
 * Reads run in this ViewModel's scope (a read nobody waits for is worth
 * nothing); the draft is the runtime's, saved even after this goes.
 */
class ThreadViewModel(private val runtime: AppRuntime, val address: String) : ViewModel() {
    private val _transcript = MutableStateFlow(ThreadTranscript())
    val transcript: StateFlow<ThreadTranscript> = _transcript.asStateFlow()

    /** The conversation as the last state read found it; null once it is gone, or before the first read. */
    val conversation: StateFlow<ConversationSummary?> = runtime.appState
        .map { state -> state?.conversations?.firstOrNull { it.address == address } }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), currentConversation())

    /** What is typed. Seeded once from the stored draft; every change after that is saved. */
    val draft = TextFieldState()

    private val _secretDraft = MutableStateFlow(false)

    /** The draft was begun under forward secrecy, and keeps it until erased even if the session drops. */
    val secretDraft: StateFlow<Boolean> = _secretDraft.asStateFlow()

    /**
     * The reader is at the bottom of the list: new messages slide the window
     * and follow. The screen alone sets it, from where the list actually is.
     */
    @Volatile
    private var following = true

    /** One window change at a time: a page landing on a window replaced under it belongs to nothing. */
    private val windowLock = Mutex()
    private val scrollIds = AtomicLong()

    init {
        viewModelScope.launch { seedDraft() }
        viewModelScope.launch {
            combine(
                snapshotFlow { draft.text.isEmpty() },
                runtime.forwardSecretConversations.map { address in it },
            ) { empty, held -> empty to held }
                .collect { (empty, held) -> _secretDraft.update { settledSecretDraft(it, empty, held) } }
        }
        viewModelScope.launch {
            runtime.transcriptRevisions
                .map { it[address] ?: 0L }
                .distinctUntilChanged()
                .collect { refresh(it) }
        }
    }

    override fun onCleared() {
        // The last keystrokes go to the store now, not after the debounce.
        runtime.flushDrafts()
    }

    /** Whether the reader is at the bottom of a window that reaches the newest message. */
    fun setFollowing(atBottom: Boolean) {
        following = atBottom
    }

    /** A scroll request was carried out. */
    fun scrolled(request: ScrollRequest) {
        _transcript.update { if (it.scroll?.id == request.id) it.copy(scroll = null) else it }
    }

    /** One page of history onto the front, as the reader nears the top. */
    fun loadOlder() {
        val shown = _transcript.value
        if (!shown.window.hasOlder || shown.isLoadingOlder) return
        _transcript.update { it.copy(isLoadingOlder = true) }
        viewModelScope.launch {
            try {
                windowLock.withLock {
                    val window = _transcript.value.window
                    val oldest = window.oldestCursor ?: return@withLock
                    val page = read { runtime.transcriptBefore(address, oldest, TranscriptWindow.PAGE_SIZE) } ?: return@withLock
                    if (page.messages.isEmpty()) {
                        _transcript.update { it.copy(window = it.window.copy(hasOlder = page.hasOlder)) }
                        return@withLock
                    }
                    // Key-anchored: rows landing above the reader, and rows
                    // trimmed far below, leave the rows on screen where they are.
                    _transcript.update { it.copy(window = it.window.prepending(page).trimmedToCapacity()) }
                }
            } finally {
                _transcript.update { it.copy(isLoadingOlder = false) }
            }
        }
    }

    /** One page of newer messages onto the end, as the reader nears the bottom of a window short of the newest. */
    fun loadNewer() {
        val shown = _transcript.value
        if (!shown.window.hasNewer || shown.isLoadingNewer) return
        _transcript.update { it.copy(isLoadingNewer = true) }
        viewModelScope.launch {
            try {
                windowLock.withLock {
                    val newest = _transcript.value.window.newestCursor ?: return@withLock
                    val page = read {
                        runtime.transcriptAfter(address, newest, including = false, limit = TranscriptWindow.PAGE_SIZE)
                    } ?: return@withLock
                    _transcript.update { it.copy(window = it.window.appending(page)) }
                }
            } finally {
                _transcript.update { it.copy(isLoadingNewer = false) }
            }
        }
    }

    /** Back to the newest message from a window that does not reach it. */
    fun jumpToLatest() {
        viewModelScope.launch {
            windowLock.withLock {
                val revision = revision()
                val page = read { runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE) } ?: return@withLock
                _transcript.update { it.copy(window = it.window.replacedBy(page, revision), scroll = request(ScrollRequest.Target.Latest)) }
            }
        }
    }

    /**
     * Show a quote's original: scrolled to where it is in the window, or the
     * window opened around it, and its row washed for a moment.
     */
    fun openQuote(target: MessageRef) {
        viewModelScope.launch {
            val loaded = windowLock.withLock {
                val held = _transcript.value.window.messages.any { it.ref == target }
                if (!held) {
                    val revision = revision()
                    val page = read { runtime.transcriptAround(address, target, TranscriptWindow.FOCUS_RADIUS) }
                        ?: return@launch
                    _transcript.update { it.copy(window = it.window.replacedBy(page, revision)) }
                }
                _transcript.update { it.copy(scroll = request(ScrollRequest.Target.Message(target.key)), highlighted = target.key) }
                held
            }
            // Then the wash fades: the screen animates it out.
            delay(if (loaded) HIGHLIGHT_LOADED_MS else HIGHLIGHT_OPENED_MS)
            _transcript.update { if (it.highlighted == target.key) it.copy(highlighted = null) else it }
        }
    }

    /**
     * Bring the window up to date. Following the live edge, it slides there;
     * reading history, the extent held is re-read in place, so edits,
     * deletions and delivery changes appear without the ground moving.
     */
    private suspend fun refresh(revision: Long) = windowLock.withLock {
        val window = _transcript.value.window
        if (window.loadedRevision == revision && window.hasLoadedOnce) return@withLock
        val oldest = window.oldestCursor
        if (!window.hasLoadedOnce || oldest == null) {
            val page = read { runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE) } ?: return@withLock
            _transcript.update { it.copy(window = it.window.replacedBy(page, revision)) }
            return@withLock
        }
        // Not while a quote's original waits to be scrolled to: the reader is leaving the bottom.
        val showingQuote = _transcript.value.scroll?.target is ScrollRequest.Target.Message
        if (following && !showingQuote && !window.hasNewer) {
            val page = read { runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE) } ?: return@withLock
            _transcript.update { it.copy(window = it.window.replacedBy(page, revision), scroll = request(ScrollRequest.Target.Latest)) }
            return@withLock
        }
        // Exactly what is held, and a little slack at a live bottom edge.
        val slack = if (window.hasNewer) 0 else REFRESH_SLACK
        val limit = minOf(window.messages.size + slack, TranscriptWindow.CAPACITY)
        val page = read { runtime.transcriptAfter(address, oldest, including = true, limit = limit) } ?: return@withLock
        _transcript.update { it.copy(window = it.window.replacedBy(page, revision)) }
    }

    private suspend fun seedDraft() {
        val stored = runtime.appState.filterNotNull().first().conversations.firstOrNull { it.address == address }?.draftText.orEmpty()
        // Whatever was typed before the read stands, and is saved below.
        if (stored.isNotEmpty() && draft.text.isEmpty()) draft.setTextAndPlaceCursorAtEnd(stored)
        var saved = stored
        snapshotFlow { draft.text.toString() }
            .distinctUntilChanged()
            .collect { text ->
                if (text != saved) {
                    saved = text
                    runtime.saveDraft(address, text)
                }
            }
    }

    private fun currentConversation(): ConversationSummary? =
        runtime.appState.value?.conversations?.firstOrNull { it.address == address }

    private fun revision(): Long = runtime.transcriptRevisions.value[address] ?: 0L

    private fun request(target: ScrollRequest.Target) = ScrollRequest(scrollIds.incrementAndGet(), target)

    /** A transcript read; null when it failed, leaving the window as it was. */
    private suspend fun <T> read(query: suspend () -> T): T? = try {
        query()
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        AppLog.w(TAG, "transcript unread: ${error.javaClass.simpleName}")
        null
    }

    private companion object {
        const val TAG = "umsh.thread"
        const val REFRESH_SLACK = 32
        const val HIGHLIGHT_LOADED_MS = 450L
        const val HIGHLIGHT_OPENED_MS = 250L
    }
}
