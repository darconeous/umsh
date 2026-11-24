package com.voria.umsh.features.conversations

import androidx.annotation.VisibleForTesting
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.ResendOutcome
import com.voria.umsh.app.SendOutcome
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.ConversationSummary
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.Octets
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.models.ResendMode
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
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

    /** What Send may do: from the radio alone. */
    val composerState: StateFlow<ComposerState> = combine(runtime.radio, runtime.radioKnown, ComposerState::from)
        .stateIn(viewModelScope, SharingStarted.Eagerly, ComposerState.from(runtime.radio.value, runtime.radioKnown.value))

    private val _composeMode = MutableStateFlow<ComposeMode>(ComposeMode.Plain)

    /** A reply or an edit under way, or neither. */
    val composeMode: StateFlow<ComposeMode> = _composeMode.asStateFlow()

    /** An edit's words, apart from the draft, which an edit leaves alone. */
    val editText = TextFieldState()

    private val _sending = MutableStateFlow(false)

    /** A message from the composer is on its way: Send is single-flight. */
    val sending: StateFlow<Boolean> = _sending.asStateFlow()

    private val _alert = MutableStateFlow<ThreadAlert?>(null)
    val alert: StateFlow<ThreadAlert?> = _alert.asStateFlow()

    private val _emergencyPrompt = MutableStateFlow<EmergencyPrompt?>(null)

    /** `EMERGENCY`'s warning, waiting for an answer. */
    val emergencyPrompt: StateFlow<EmergencyPrompt?> = _emergencyPrompt.asStateFlow()

    /** What waits for the warning; null while that is a new message (or nothing). */
    private var certifiedAction: (() -> Unit)? = null

    /**
     * Agreed in this thread since the core last said it needs it: the
     * conversation is read again afterward, so this bridges the gap.
     */
    private var agreedHere = false

    private val _menuFor = MutableStateFlow<ChatMessage?>(null)

    /** The message whose long-press menu is open. */
    val menuFor: StateFlow<ChatMessage?> = _menuFor.asStateFlow()

    private val _resendPrompt = MutableStateFlow<ResendPrompt?>(null)
    val resendPrompt: StateFlow<ResendPrompt?> = _resendPrompt.asStateFlow()

    private val _deleting = MutableStateFlow<ChatMessage?>(null)

    /** The message whose deletion waits for confirmation. */
    val deleting: StateFlow<ChatMessage?> = _deleting.asStateFlow()

    private val _original = MutableStateFlow<ChatMessage?>(null)

    /** The edited message of mine whose original words are shown. */
    val original: StateFlow<ChatMessage?> = _original.asStateFlow()

    private val _asking = MutableStateFlow<Set<MessageRef>>(emptySet())

    /** Gap placeholders being asked for, until the transcript says so itself. */
    val asking: StateFlow<Set<MessageRef>> = _asking.asStateFlow()

    private val _member = MutableStateFlow<MemberRef?>(null)

    /** The channel member whose sheet is open, from their avatar (`conversation-info.svg` 6). */
    val member: StateFlow<MemberRef?> = _member.asStateFlow()

    private val _memberRequested = MutableStateFlow(false)

    /** Request identity went out from the sheet open now: it reads Identity requested. */
    val memberRequested: StateFlow<Boolean> = _memberRequested.asStateFlow()

    private val leaves = Channel<Unit>(Channel.CONFLATED)

    /** The warning turned down before a send: the thread closes, keeping the draft. */
    val leave = leaves.receiveAsFlow()

    private val focusRequests = Channel<Unit>(Channel.CONFLATED)

    /** The field takes focus: a reply or an edit begun. */
    val focus = focusRequests.receiveAsFlow()

    private var reviseTimer: Job? = null

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
        // The core's word turning back to "needs it" (a lapse, a new owner)
        // undoes an agreement given here, as on iOS.
        viewModelScope.launch {
            conversation
                .map { (it as? ChannelConversationSummary)?.needsEmergencyAgreement }
                .distinctUntilChanged()
                .collect { needs -> if (needs == true) agreedHere = false }
        }
        // A row whose revise window passes offers less: read it again then.
        viewModelScope.launch {
            _transcript.map { it.window.messages }.distinctUntilChanged().collect(::armReviseTimer)
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

    // region Sending

    /** Whether a transmission here waits for `EMERGENCY`'s warning: the core's word, until agreed here. */
    private fun needsCertification(): Boolean =
        (conversation.value as? ChannelConversationSummary)?.needsEmergencyAgreement == true && !agreedHere

    /** Run [action] now, or once the user agrees to `EMERGENCY`'s warning. */
    private fun afterCertified(action: () -> Unit) {
        if (!needsCertification()) {
            action()
            return
        }
        certifiedAction = action
        _emergencyPrompt.value = EmergencyPrompt(sends = false)
    }

    /** The core refused for want of the warning (it lapsed while open): ask again, then retry [action]. */
    private fun askAgain(action: (() -> Unit)?) {
        agreedHere = false
        certifiedAction = action
        _emergencyPrompt.value = EmergencyPrompt(sends = action == null)
    }

    /** Certify and send, or Certify: the core's certification, then what waited for it. */
    fun certify() {
        viewModelScope.launch {
            val action = certifiedAction
            val sends = _emergencyPrompt.value?.sends ?: (action == null)
            certifiedAction = null
            _emergencyPrompt.value = null
            runtime.certifyEmergency().onFailure { error ->
                _alert.value = if (sends) ThreadAlert.NotSent(error) else ThreadAlert.Failed(R.string.request_not_sent_title, error)
                return@launch
            }
            agreedHere = true
            if (action != null) action() else send()
        }
    }

    /** The warning turned down: before a send this leaves the thread, keeping the draft; otherwise only drops what waited. */
    fun declineCertification() {
        val sends = _emergencyPrompt.value?.sends == true
        certifiedAction = null
        _emergencyPrompt.value = null
        if (sends) leaves.trySend(Unit)
    }

    /** The composer forwards under forward secrecy: a session held, or the draft begun under one. Null on a channel. */
    private fun forwardSecret(): Boolean? =
        if (conversation.value is ChannelConversationSummary) null else address in runtime.forwardSecretConversations.value || _secretDraft.value

    /** Send what the composer holds: a new message, a reply, or an edit's words. */
    fun send() {
        // The one gate for both a new message and an edit: the check button is the Send button.
        when (composerState.value) {
            ComposerState.Ready -> Unit
            ComposerState.Transient -> {
                _alert.value = ThreadAlert.StillConnecting
                return
            }
            // Send is not offered; nothing is queued.
            ComposerState.Blocked -> return
        }
        if (_composeMode.value is ComposeMode.Editing) {
            saveEdit()
            return
        }
        if (_sending.value) return
        // Untrimmed, as the draft stores it: the core trims what it sends.
        val text = draft.text.toString()
        if (text.isBlank()) return
        if (needsCertification()) {
            certifiedAction = null
            _emergencyPrompt.value = EmergencyPrompt(sends = true)
            return
        }
        val replying = (_composeMode.value as? ComposeMode.Replying)?.message
        // As the composer shows it as Send is pressed.
        val forwardSecret = forwardSecret()
        _sending.value = true
        viewModelScope.launch {
            try {
                val outcome = if (replying != null) {
                    runtime.reply(address, replying.ref, text, forwardSecret).await()
                } else {
                    runtime.send(address, text, forwardSecret).await()
                }
                when (outcome) {
                    SendOutcome.Sent -> settleSent(text, replying)
                    is SendOutcome.Kept -> {
                        // Kept, marked as not delivered: the transcript holds it
                        // now, with its own retry, so the composer lets it go.
                        settleSent(text, replying)
                        _alert.value = ThreadAlert.Submitted(outcome.recorded)
                    }
                    is SendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                        askAgain(null)
                    } else {
                        _alert.value = ThreadAlert.NotSent(outcome.error)
                    }
                }
            } finally {
                _sending.value = false
            }
        }
    }

    /** The composer after a message it held was kept: emptied, unless more was typed meanwhile, and at the new message. */
    private fun settleSent(text: String, replying: ChatMessage?) {
        val mode = _composeMode.value
        if (replying != null && mode is ComposeMode.Replying && mode.message.ref == replying.ref) {
            _composeMode.value = ComposeMode.Plain
        }
        if (draft.text.toString() == text) draft.clearText()
        followNewMessage()
    }

    /** Carry the reader to a message just added at the bottom, from wherever they were. */
    private fun followNewMessage() {
        if (_transcript.value.window.hasNewer || !following) jumpToLatest()
    }

    /** Reply to [message]: the strip above the field, and the field focused. */
    fun startReply(message: ChatMessage) {
        if (!message.actions.reply) return
        _menuFor.value = null
        _composeMode.value = ComposeMode.Replying(message)
        focusRequests.trySend(Unit)
    }

    /** New words for [message], in their own field under an "Editing message" strip. */
    fun startEdit(message: ChatMessage) {
        if (!message.actions.edit) return
        _menuFor.value = null
        _composeMode.value = ComposeMode.Editing(message)
        editText.setTextAndPlaceCursorAtEnd(message.body)
        focusRequests.trySend(Unit)
    }

    /** Close the reply or edit strip. An edit's words are dropped; the draft stands. */
    fun cancelComposeMode() {
        _composeMode.value = ComposeMode.Plain
        editText.clearText()
    }

    private fun saveEdit() {
        val message = (_composeMode.value as? ComposeMode.Editing)?.message ?: return
        if (_sending.value) return
        val text = editText.text.toString()
        if (text.isBlank()) return
        if (text == message.body) {
            // Nothing changed: the core would refuse it, and there is nothing to send.
            cancelComposeMode()
            return
        }
        afterCertified {
            _sending.value = true
            viewModelScope.launch {
                try {
                    when (val outcome = runtime.edit(address, message.ref, text).await()) {
                        SendOutcome.Sent -> cancelComposeMode()
                        is SendOutcome.Kept -> {
                            cancelComposeMode()
                            _alert.value = ThreadAlert.Submitted(outcome.recorded)
                        }
                        is SendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                            askAgain(::saveEdit)
                        } else {
                            _alert.value = ThreadAlert.Failed(R.string.edit_not_sent_title, outcome.error)
                        }
                    }
                } finally {
                    _sending.value = false
                }
            }
        }
    }

    // endregion

    // region The message menu and its actions

    fun openMenu(message: ChatMessage) {
        if (MessageMenu.hasMenu(message)) _menuFor.value = message
    }

    fun closeMenu() {
        _menuFor.value = null
    }

    fun showOriginal(message: ChatMessage) {
        _menuFor.value = null
        _original.value = message
    }

    fun dismissOriginal() {
        _original.value = null
    }

    /** A reaction picked from the menu: added, or withdrawn if it is already mine (the core decides from the row). */
    fun toggleReaction(message: ChatMessage, kind: ReactionKind) {
        _menuFor.value = null
        afterCertified { reactionCommand { runtime.toggleReaction(address, message.ref, kind).await() } }
    }

    /** A chip tapped: mine withdrawn, another's added as mine. */
    fun tapChip(message: ChatMessage, chip: ReactionChip) {
        if (!message.actions.react) return
        when (chip.style) {
            ReactionChip.Style.Mine, ReactionChip.Style.Failed ->
                afterCertified { reactionCommand { runtime.react(address, message.ref, null).await() } }
            ReactionChip.Style.Theirs -> toggleReaction(message, chip.kind)
        }
    }

    private fun reactionCommand(command: suspend () -> SendOutcome) {
        viewModelScope.launch {
            when (val outcome = command()) {
                SendOutcome.Sent, is SendOutcome.Kept -> Unit
                is SendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                    askAgain { reactionCommand(command) }
                } else {
                    _alert.value = ThreadAlert.Failed(R.string.reaction_not_sent_title, outcome.error)
                }
            }
        }
    }

    fun askDelete(message: ChatMessage) {
        _menuFor.value = null
        if (message.actions.delete) _deleting.value = message
    }

    fun cancelDelete() {
        _deleting.value = null
    }

    /** Delete for everyone, confirmed. */
    fun confirmDelete() {
        val message = _deleting.value ?: return
        _deleting.value = null
        afterCertified { deleteCommand(message) }
    }

    private fun deleteCommand(message: ChatMessage) {
        viewModelScope.launch {
            when (val outcome = runtime.delete(address, message.ref).await()) {
                SendOutcome.Sent, is SendOutcome.Kept -> Unit
                is SendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                    askAgain { deleteCommand(message) }
                } else {
                    _alert.value = ThreadAlert.Failed(R.string.deletion_not_sent_title, outcome.error)
                }
            }
        }
    }

    /** The retry button, or Try again / Resend in the menu: the dialog first. */
    fun askResend(message: ChatMessage) {
        _menuFor.value = null
        val mode = message.actions.resend ?: return
        _resendPrompt.value = ResendPrompt(message, mode)
    }

    fun cancelResend() {
        _resendPrompt.value = null
    }

    /**
     * Send it again, under forward secrecy when [forwardSecret]. The core
     * may still send it as new after the dialog said "Try again".
     */
    fun confirmResend(forwardSecret: Boolean) {
        val message = _resendPrompt.value?.message ?: return
        _resendPrompt.value = null
        afterCertified { resendCommand(message, forwardSecret) }
    }

    private fun resendCommand(message: ChatMessage, forwardSecret: Boolean) {
        viewModelScope.launch {
            when (val outcome = runtime.resend(address, message.ref, forwardSecret).await()) {
                is ResendOutcome.Resent -> if (outcome.mode == ResendMode.AsNew) followNewMessage()
                is ResendOutcome.Kept -> {
                    followNewMessage()
                    _alert.value = ThreadAlert.Submitted(outcome.recorded)
                }
                is ResendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                    askAgain { resendCommand(message, forwardSecret) }
                } else {
                    _alert.value = ThreadAlert.Failed(R.string.resend_not_sent_title, outcome.error)
                }
            }
        }
    }

    /** A gap tapped: ask for its idle placeholders. The core marks those it can never get. */
    fun requestMissing(messages: List<ChatMessage>) {
        val asked = messages.filter { it.actions.requestMissing }.map { it.ref }
        if (asked.isEmpty()) return
        afterCertified { missingCommand(asked) }
    }

    private fun missingCommand(asked: List<MessageRef>) {
        _asking.update { it + asked }
        viewModelScope.launch {
            try {
                when (val outcome = runtime.requestMissing(address, asked).await()) {
                    SendOutcome.Sent, is SendOutcome.Kept -> Unit
                    is SendOutcome.Refused -> if (outcome.needsEmergencyAgreement) {
                        askAgain { missingCommand(asked) }
                    } else {
                        _alert.value = ThreadAlert.Failed(R.string.missing_not_requested_title, outcome.error)
                    }
                }
            } finally {
                _asking.update { it - asked.toSet() }
            }
        }
    }

    // region Members

    /** [message]'s sender's sheet; nothing for a message that claims no hint. */
    fun openMember(message: ChatMessage) {
        val hint = message.senderHint ?: return
        if (conversation.value !is ChannelConversationSummary || message.isOutbound) return
        _memberRequested.value = false
        _member.value = MemberRef(hint, message.senderNodeHint)
    }

    fun closeMember() {
        _member.value = null
        _memberRequested.value = false
    }

    /**
     * Request identity, over the channel. On `EMERGENCY` it waits for the
     * warning, which the sheet steps aside for, as on iOS. Once per
     * opening of the sheet.
     */
    fun requestMemberIdentity() {
        val ref = _member.value ?: return
        if (_memberRequested.value) return
        if (needsCertification()) {
            closeMember()
            afterCertified { memberIdentityCommand(ref.hint) }
            return
        }
        _memberRequested.value = true
        memberIdentityCommand(ref.hint)
    }

    private val _memberAsks = MutableStateFlow<List<SendOutcome?>>(emptyList())

    /** Each ask handed to the runtime, in order: null until its outcome is in. */
    @VisibleForTesting
    internal val memberAsks: StateFlow<List<SendOutcome?>> = _memberAsks.asStateFlow()

    private fun memberIdentityCommand(hint: Octets) {
        val ask = _memberAsks.updateAndGet { it + null }.lastIndex
        viewModelScope.launch {
            val outcome = runtime.requestMemberIdentity(address, hint).await()
            _memberAsks.update { asks -> asks.toMutableList().also { it[ask] = outcome } }
            when (outcome) {
                SendOutcome.Sent, is SendOutcome.Kept -> Unit
                is SendOutcome.Refused -> {
                    if (_member.value?.hint == hint) _memberRequested.value = false
                    if (outcome.needsEmergencyAgreement) {
                        closeMember()
                        askAgain { memberIdentityCommand(hint) }
                    } else {
                        _alert.value = ThreadAlert.Failed(R.string.request_not_sent_title, outcome.error)
                    }
                }
            }
        }
    }

    // endregion

    fun dismissAlert() {
        _alert.value = null
    }

    /** Read the window again once the soonest revise window among its rows has passed. */
    private fun armReviseTimer(messages: List<ChatMessage>) {
        reviseTimer?.cancel()
        val now = System.currentTimeMillis()
        val next = messages.mapNotNull { it.reviseUntilMs }.filter { it >= now }.minOrNull() ?: return
        reviseTimer = viewModelScope.launch {
            delay(next - now + 1)
            refresh(revision(), force = true)
        }
    }

    // endregion

    /**
     * Bring the window up to date. Following the live edge, it slides there;
     * reading history, the extent held is re-read in place, so edits,
     * deletions and delivery changes appear without the ground moving.
     */
    private suspend fun refresh(revision: Long, force: Boolean = false) = windowLock.withLock {
        val window = _transcript.value.window
        if (!force && window.loadedRevision == revision && window.hasLoadedOnce) return@withLock
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
        // Words added to the stored draft from now on, which the next save
        // would otherwise write over: added to what is held, then saved.
        viewModelScope.launch {
            runtime.draftAdditions.filter { it.address == address }.collect { addition ->
                draft.setTextAndPlaceCursorAtEnd(addition.addedTo(draft.text.toString()))
            }
        }
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
