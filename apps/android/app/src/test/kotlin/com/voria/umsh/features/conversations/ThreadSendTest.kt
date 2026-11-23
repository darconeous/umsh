package com.voria.umsh.features.conversations

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.snapshots.Snapshot
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.voria.umsh.app.StagedHost
import com.voria.umsh.app.UmshKey
import com.voria.umsh.models.ChannelConversationSummary
import java.util.concurrent.Executors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The thread's send flow over a live staged core: the composer, the reply strip and `EMERGENCY`'s warning. */
@OptIn(ExperimentalCoroutinesApi::class)
class ThreadSendTest {
    @get:Rule val temp = TemporaryFolder()

    private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private lateinit var staged: StagedHost
    private val models = ViewModelStore()

    @Before
    fun setUp() = Dispatchers.setMain(main)

    @After
    fun tearDown() = runBlocking {
        withContext(main) { models.clear() }
        staged.close()
        Dispatchers.resetMain()
        main.close()
    }

    private suspend fun thread(address: String): ThreadViewModel = withContext(main) {
        val runtime = staged.runtime
        ViewModelProvider.create(models, viewModelFactory { initializer { ThreadViewModel(runtime, address) } })[address, ThreadViewModel::class]
    }

    private suspend fun ThreadViewModel.type(text: String) {
        withContext(main) {
            draft.setTextAndPlaceCursorAtEnd(text)
            Snapshot.sendApplyNotifications()
        }
    }

    private suspend fun ThreadViewModel.typed(): String = withContext(main) { draft.text.toString() }

    private suspend fun <T> eventually(read: suspend () -> T, done: (T) -> Boolean): T = withTimeout(StagedHost.TIMEOUT) {
        while (true) {
            val value = read()
            if (done(value)) return@withTimeout value
            delay(StagedHost.POLL_MS)
        }
        @Suppress("UNREACHABLE_CODE")
        read()
    }

    @Test
    fun emergencyAsksFirstAndCancelLeavesWithTheDraft() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val emergency = staged.emergency()
        val thread = thread(emergency)
        withTimeout(StagedHost.TIMEOUT) {
            thread.conversation.first { (it as? ChannelConversationSummary)?.needsEmergencyAgreement == true }
        }
        withTimeout(StagedHost.TIMEOUT) { thread.composerState.first { it == ComposerState.Ready } }
        thread.type("Rockfall at mile 12")

        withContext(main) { thread.send() }
        assertEquals(EmergencyPrompt(sends = true), thread.emergencyPrompt.value)
        withContext(main) { thread.declineCertification() }
        withTimeout(StagedHost.TIMEOUT) { thread.leave.first() }
        assertNull(thread.emergencyPrompt.value)
        assertEquals("Rockfall at mile 12", thread.typed())
        assertTrue(staged.runtime.transcriptNewest(emergency, 10).messages.isEmpty())

        // Asked again; certified, it sends what the composer holds.
        withContext(main) { thread.send() }
        assertEquals(EmergencyPrompt(sends = true), thread.emergencyPrompt.value)
        withContext(main) { thread.certify() }
        staged.messagesWhere(emergency) { messages -> messages.any { it.isOutbound && it.body == "Rockfall at mile 12" } }
        eventually<String>({ thread.typed() }) { text -> text.isEmpty() }
        assertNull(thread.alert.value)

        // Agreed here: a reaction goes without asking again.
        val mine = staged.messagesWhere(emergency) { messages -> messages.any { it.isOutbound } }.first { it.isOutbound }
        withContext(main) { thread.toggleReaction(mine, com.voria.umsh.models.ReactionKind.Exclaim) }
        assertNull(thread.emergencyPrompt.value)
        staged.messagesWhere(emergency) { messages -> messages.first { it.ref == mine.ref }.reactions.any { it.isMine } }
    }

    @Test
    fun aReplyCarriesItsQuoteAndClosesItsStrip() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val address = staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address
        val thread = thread(address)
        val received = staged.messagesWhere(address) { messages -> messages.any { !it.isOutbound && it.actions.reply } }
            .last { !it.isOutbound && it.actions.reply }
        withTimeout(StagedHost.TIMEOUT) { thread.composerState.first { it == ComposerState.Ready } }
        withContext(main) { thread.startReply(received) }
        assertEquals(ComposeMode.Replying(received), thread.composeMode.value)
        thread.type("On my way")
        withContext(main) { thread.send() }
        val reply = staged.messagesWhere(address) { messages -> messages.any { it.body == "On my way" } }.last { it.body == "On my way" }
        assertTrue(reply.quote != null)
        eventually({ thread.composeMode.value }) { it == ComposeMode.Plain }
        eventually<String>({ thread.typed() }) { text -> text.isEmpty() }
    }

    @Test
    fun anEditWritesApartFromTheDraft() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val address = staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address
        val thread = thread(address)
        withTimeout(StagedHost.TIMEOUT) { thread.composerState.first { it == ComposerState.Ready } }
        thread.type("South gate.")
        withContext(main) { thread.send() }
        val mine = staged.messagesWhere(address) { messages -> messages.any { it.body == "South gate." && it.actions.edit } }
            .last { it.body == "South gate." }
        // Send stays disabled until the first one settles, as the composer shows.
        withTimeout(StagedHost.TIMEOUT) { thread.sending.first { !it } }
        thread.type("half a thought")
        withContext(main) {
            thread.startEdit(mine)
            thread.editText.setTextAndPlaceCursorAtEnd("North gate instead.")
            Snapshot.sendApplyNotifications()
            thread.send()
        }
        staged.messagesWhere(address) { messages -> messages.any { it.ref == mine.ref && it.body == "North gate instead." } }
        eventually({ thread.composeMode.value }) { it == ComposeMode.Plain }
        // The draft was left alone.
        assertEquals("half a thought", thread.typed())
    }

    @Test
    fun detailsReadTheMessageOrSayItIsGone() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val address = staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address
        val stored = staged.messagesWhere(address) { it.isNotEmpty() }.last()
        suspend fun details(key: UmshKey.MessageDetails): DetailsRead = withContext(main) {
            val model = ViewModelProvider.create(models, viewModelFactory { initializer { MessageDetailsViewModel(staged.runtime, key) } })[
                key.toString(), MessageDetailsViewModel::class,
            ]
            withTimeout(StagedHost.TIMEOUT) { model.message.first { it != DetailsRead.Reading } }
        }
        val shown = details(UmshKey.MessageDetails(address, stored.ref.sessionId, stored.ref.handle))
        assertEquals(stored.ref, (shown as DetailsRead.Shown).message.ref)
        assertEquals(DetailsRead.Gone, details(UmshKey.MessageDetails(address, stored.ref.sessionId, stored.ref.handle + 100_000)))
    }

    @Test
    fun anEditWaitsForTheRadioAsASendDoes() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val address = staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address
        val thread = thread(address)
        withTimeout(StagedHost.TIMEOUT) { thread.composerState.first { it == ComposerState.Ready } }
        thread.type("South gate.")
        withContext(main) { thread.send() }
        val mine = staged.messagesWhere(address) { messages -> messages.any { it.body == "South gate." && it.actions.edit } }
            .last { it.body == "South gate." }
        withTimeout(StagedHost.TIMEOUT) { thread.sending.first { !it } }
        withContext(main) {
            thread.startEdit(mine)
            thread.editText.setTextAndPlaceCursorAtEnd("North gate instead.")
            Snapshot.sendApplyNotifications()
        }
        staged.air.setLinkUp(false)
        val state = withTimeout(StagedHost.TIMEOUT) { thread.composerState.first { it != ComposerState.Ready } }
        withContext(main) { thread.send() }
        // Had it gone to the core, its refusal would land before sending settles.
        withTimeout(StagedHost.TIMEOUT) { thread.sending.first { !it } }
        // Transient explains, as a send does; Blocked offers nothing. Neither reaches the core.
        assertEquals(if (state == ComposerState.Transient) ThreadAlert.StillConnecting else null, thread.alert.value)
        assertTrue(thread.composeMode.value is ComposeMode.Editing)
        assertEquals("South gate.", staged.runtime.transcriptNewest(address, 10).messages.first { it.ref == mine.ref }.body)
    }

    @Test
    fun aNotificationReplyKeptAsTheDraftReachesAnOpenThread() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.start()
        val address = staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address
        val thread = thread(address)
        thread.type("Half a thought")
        staged.air.setLinkUp(false)
        staged.carrying(false)
        val outcome = staged.runtime.deliverNotificationReply(address, "On my way", radioWaitMs = 300).await()
        assertEquals(com.voria.umsh.app.ReplyOutcome.Failed(savedAsDraft = true), outcome)
        // The open thread holds the words too, so its next save keeps them.
        eventually<String>({ thread.typed() }) { it == "Half a thought\nOn my way" }
        thread.type("Half a thought\nOn my way!")
        // The thread hands its text on from a collector on the main thread;
        // flushing before that runs would save the earlier text.
        eventually({ staged.runtime.pendingDraft(address) }) { it == "Half a thought\nOn my way!" }
        staged.runtime.flushDrafts().await()
        assertEquals("Half a thought\nOn my way!", staged.storedDraft(address))
    }
}
