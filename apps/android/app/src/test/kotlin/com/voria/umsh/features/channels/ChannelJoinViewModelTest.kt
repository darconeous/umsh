package com.voria.umsh.features.channels

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileException
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelPreview
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.JoinedChannel
import com.voria.umsh.models.Octets
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Join channel's lookup and join, over a fake host. */
@OptIn(ExperimentalCoroutinesApi::class)
class ChannelJoinViewModelTest {
    private class Host : ChannelJoinHost {
        val previews = HashMap<String, CompletableDeferred<ChannelPreview>>()
        val joins = mutableListOf<Triple<String, String?, Boolean>>()
        val clears = mutableListOf<Boolean>()
        var joining = CompletableDeferred<JoinedChannel>()
        val rejoins = mutableListOf<String>()

        fun answer(input: String): CompletableDeferred<ChannelPreview> = previews.getOrPut(input) { CompletableDeferred() }

        override suspend fun preview(input: String): ChannelPreview = answer(input).await()

        override fun join(input: String, alias: String?, clearAlias: Boolean, openConversation: Boolean): Deferred<JoinedChannel> {
            joins += Triple(input, alias, openConversation)
            clears += clearAlias
            return joining
        }

        override fun rejoin(id: String): Deferred<Unit> {
            rejoins += id
            return CompletableDeferred(Unit)
        }
    }

    private fun preview(input: String, existing: ChannelSummary? = null) = ChannelPreview(
        input = input,
        isPrivate = false,
        canonicalName = input.lowercase(),
        displayName = input,
        key = Octets(ByteArray(32)),
        channelIdHex = "a41c",
        tint = Octets(byteArrayOf(0xA4.toByte(), 0x1C, 0x10)),
        existing = existing,
        nameConflict = null,
    )

    private fun stored(joined: Boolean, alias: String? = null) = ChannelSummary(
        id = "ID", kind = ChannelKind.Named, canonicalName = "hike-club", name = "hike-club", alias = alias,
        channelIdHex = "3f9a", tint = Octets(byteArrayOf(1, 2, 3)), regionCode = null, maxFloodHops = null,
        joinedPhone = joined, notificationsEnabled = false, joinedAtMs = null, conversationAddress = null,
    )

    @Before
    fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun theFieldsLineSaysWhyTextNamesNoChannel() {
        assertEquals(ChannelInputProblem.NotAscii, ChannelJoinViewModel.problem(MobileAppException.InvalidInput(MobileException.ChannelNameNotAscii())))
        assertEquals(ChannelInputProblem.TooLong, ChannelJoinViewModel.problem(MobileAppException.InvalidInput(MobileException.ChannelNameTooLong())))
        assertEquals(ChannelInputProblem.NotChannel, ChannelJoinViewModel.problem(MobileAppException.InvalidInput(MobileException.InvalidUri())))
        // Anything else is a failure dialog, not the field's line.
        assertNull(ChannelJoinViewModel.problem(MobileAppException.Busy()))
    }

    @Test
    fun anEditOrANewerLookupOutrunsAnOlderAnswer() {
        val host = Host()
        val model = ChannelJoinViewModel(host)
        model.lookUp("ridge")
        model.lookUp("ridge-runners")
        host.answer("ridge-runners").complete(preview("ridge-runners"))
        host.answer("ridge").complete(preview("ridge"))
        assertEquals("ridge-runners", model.preview.value?.input)

        model.lookUp(" hike-club ")
        model.edited()
        host.answer("hike-club").complete(preview("hike-club"))
        assertNull("the field changed since", model.preview.value)

        model.lookUp("Café")
        host.answer("Café").completeExceptionally(MobileAppException.InvalidInput(MobileException.ChannelNameNotAscii()))
        assertEquals(ChannelInputProblem.NotAscii, model.problem.value)
        assertNull(model.preview.value)
        model.edited()
        assertNull(model.problem.value)

        model.lookUp("x")
        host.answer("x").completeExceptionally(MobileAppException.Busy())
        assertTrue(model.failure.value is ChannelJoinFailure.NotLookedUp)
        assertNull(model.problem.value)
    }

    @Test
    fun joinSendsWhatWasLookedUpOnceAndSaysWhenDone() = runBlocking {
        val host = Host()
        val model = ChannelJoinViewModel(host)
        model.join("ignored", openConversation = false)
        assertTrue("nothing looked up, nothing joined", host.joins.isEmpty())

        model.lookUp("hike-club")
        host.answer("hike-club").complete(preview("hike-club", existing = stored(joined = true)))
        assertTrue(model.preview.value!!.alreadyJoined)
        model.join("  Hikers ", openConversation = true)
        model.join("again", openConversation = true)
        assertEquals("one join at a time", listOf(Triple("hike-club", "Hikers", true)), host.joins)
        assertTrue(model.joining.value)
        host.joining.complete(JoinedChannel("ID", "chat"))
        assertEquals(JoinedChannel("ID", "chat"), withTimeout(1_000) { model.joined.first() })
        assertFalse(model.joining.value)

        host.joining = CompletableDeferred()
        model.join("", openConversation = false)
        assertEquals(Triple("hike-club", null, false), host.joins.last())
        assertEquals("no alias to clear", false, host.clears.last())
        host.joining.completeExceptionally(MobileAppException.ChannelTableFull())
        assertTrue(model.failure.value is ChannelJoinFailure.NotJoined)
        model.dismissFailure()
        assertNull(model.failure.value)

        // A left built-in channel is held, not joined: Join, not Update.
        assertFalse(preview("public", existing = stored(joined = false)).alreadyJoined)

        // Update with the alias field cleared clears the held channel's alias; a typed one sets it.
        model.lookUp("hike")
        host.answer("hike").complete(preview("hike", existing = stored(joined = true, alias = "Hikers")))
        host.joining = CompletableDeferred(JoinedChannel("ID", null))
        model.join(" ", openConversation = false)
        withTimeout(1_000) { model.joined.first() }
        assertEquals(Triple("hike", null, false), host.joins.last())
        assertTrue(host.clears.last())
        model.join("Ridge", openConversation = false)
        withTimeout(1_000) { model.joined.first() }
        assertFalse(host.clears.last())
        model.rejoin("PUBLIC")
        assertEquals(listOf("PUBLIC"), host.rejoins)
        assertEquals(JoinedChannel("PUBLIC", null), withTimeout(1_000) { model.joined.first() })
    }
}
