package com.voria.umsh.features.peers

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.NodeIdentityProfileRecord
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.core.nodeUriWithIdentity
import com.voria.umsh.core.publicIdentityBytes
import com.voria.umsh.core.signNodeIdentityBundle
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.SignatureState
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Add peer's field and preview (`add-peer.svg` 1–4), over the core's own parsers. */
@OptIn(ExperimentalCoroutinesApi::class)
class AddPeerViewModelTest {
    private class Host(override val ownAddress: String) : PeerImportHost {
        val peers = mutableMapOf<String, PeerSummary>()
        val saves = mutableListOf<Triple<String, String?, Boolean>>()
        var next: CompletableDeferred<String> = CompletableDeferred()

        override fun stored(address: String): PeerSummary? = peers[address]

        override fun save(input: String, alias: String?, startConversation: Boolean): Deferred<String> {
            saves += Triple(input, alias, startConversation)
            return next
        }
    }

    @Before
    fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After
    fun tearDown() = Dispatchers.resetMain()

    private val own = ImportFixtures.address(0x01)
    private val host = Host(own)
    private val model = AddPeerViewModel(host)

    @Test
    fun eachInputKindPreviewsOrSaysWhy() {
        val other = ImportFixtures.address(0x02)
        // A bare link, the Base58 address, and the hex key all name the node.
        for (input in listOf(nodeUriForAddress(other), "  $other\n", ImportFixtures.hex(other), "0x" + ImportFixtures.hex(other))) {
            model.preview(input)
            val shown = model.preview.value
            assertNotNull(input, shown)
            assertEquals(other, shown!!.address)
            assertNull(shown.identity)
            assertFalse(shown.hasIdentityData)
            assertEquals(input.trim(), shown.input)
            model.dismissPreview()
        }
        model.preview("umsh:x:Mx4eTq8VbN3k")
        assertEquals(AddPeerProblem.NotPeer, model.problem.value)
        assertNull(model.preview.value)
        model.edited()
        assertNull(model.problem.value)
        // A channel link opens the channel's join preview, each time afresh.
        var last = 0L
        for (channel in listOf("umsh:gs:public", "UMSH:gk:4LrFpcVdqA9LrfxgUz6zE6iUMoWiZVqU2PUVFN5D4y7d", " umsh:cs:public ")) {
            model.preview(channel)
            assertNull(channel, model.problem.value)
            assertNull(model.preview.value)
            val opening = model.channel.value
            assertEquals(channel.trim(), opening?.input)
            assertTrue(opening!!.opening > last)
            last = opening.opening
            model.closeChannel()
            assertNull(model.channel.value)
        }
        // Blank is not previewed at all.
        model.edited()
        model.preview("   ")
        assertNull(model.problem.value)
    }

    @Test
    fun eachSignatureStateReadsAsTheCoreSaysIt() = runBlocking {
        val signed = ImportFixtures.signedLink(0x03)
        model.preview(signed.link)
        val valid = model.preview.value!!.identity!!
        assertEquals(SignatureState.Valid, valid.signature)
        assertEquals("Marmot", valid.name)
        assertEquals(PeerRole.Chat, valid.role)
        assertNotNull(valid.latitude)
        assertEquals(ImportFixtures.REPORTED, valid.timestamp)

        model.preview(ImportFixtures.unsignedLink(0x04))
        assertEquals(SignatureState.Unsigned, model.preview.value!!.identity!!.signature)

        model.preview(ImportFixtures.tamperedLink(0x05))
        assertEquals(SignatureState.Invalid, model.preview.value!!.identity!!.signature)

        // Details that do not parse: the key alone is usable.
        model.preview(ImportFixtures.unreadableLink(0x06))
        val unreadable = model.preview.value!!
        assertTrue(unreadable.hasIdentityData)
        assertNull(unreadable.identity)
    }

    @Test
    fun savedNodesAndThisPhoneOpenTheirPagesInstead() = runBlocking {
        val saved = ImportFixtures.address(0x07)
        host.peers[saved] = peer(saved, saved = true)
        val heard = ImportFixtures.address(0x08)
        host.peers[heard] = peer(heard, saved = false)

        model.preview(nodeUriForAddress(saved))
        assertEquals(AddPeerExit.Page(saved), withTimeout(1_000) { model.exits.first() })
        assertNull(model.preview.value)

        model.preview(own)
        assertEquals(AddPeerExit.OwnIdentity, withTimeout(1_000) { model.exits.first() })

        // Heard over the air but not saved: previewed, so it can be saved.
        model.preview(heard)
        assertEquals(heard, model.preview.value?.address)
    }

    @Test
    fun saveAndMessageLeaveForThePageAndTheConversation() = runBlocking {
        val other = ImportFixtures.address(0x09)
        model.preview(other)
        model.importPeer("  Kestrel ", message = false)
        assertEquals(ImportSave.Saving(message = false), model.save.value)
        // A second tap while saving sends nothing more, and the sheet stays.
        model.importPeer("Kestrel", message = true)
        model.dismissPreview()
        assertEquals(1, host.saves.size)
        assertNotNull(model.preview.value)
        host.next.complete(other)
        assertEquals(AddPeerExit.Page(other), withTimeout(1_000) { model.exits.first() })
        assertEquals(Triple(other, "Kestrel", false), host.saves.single())
        assertNull(model.preview.value)

        host.next = CompletableDeferred()
        model.preview(other)
        model.importPeer("", message = true)
        host.next.complete(other)
        assertEquals(AddPeerExit.Conversation(other), withTimeout(1_000) { model.exits.first() })
        assertEquals(Triple(other, null, true), host.saves.last())
    }

    @Test
    fun aFailedSaveKeepsThePreviewAndSaysWhich() {
        val other = ImportFixtures.address(0x0A)
        model.preview(other)
        model.importPeer("", message = true)
        val refused = MobileAppException.InvalidRequest()
        host.next.completeExceptionally(refused)
        // The error as awaited (coroutines may hand back a recovered copy of it).
        val failed = model.save.value as ImportSave.Failed
        assertTrue(failed.error is MobileAppException.InvalidRequest)
        assertTrue(failed.message)
        assertNotNull(model.preview.value)
        model.dismissFailure()
        assertEquals(ImportSave.Idle, model.save.value)
        assertNotNull(model.preview.value)
    }

    private fun peer(address: String, saved: Boolean) = PeerSummary(
        id = 1,
        address = address,
        hint = NodeHint(Octets(publicIdentityBytes(address).copyOf(3)), "hint"),
        alias = null,
        advertisedName = null,
        isCompanionRadio = false,
        storedRole = PeerRole.Chat,
        advertised = null,
        advertisementAuthenticated = false,
        advertisementReceivedAtMs = null,
        lastHeardAtMs = null,
        isSaved = saved,
        isFavorite = false,
        isOnDeviceIdentity = false,
        notifyWhenHeard = false,
    )
}

/**
 * Node links for import tests, made by the core: a fixed key per [seed],
 * and identity bundles signed by it, unsigned, tampered, or unreadable.
 */
object ImportFixtures {
    // Seeds that are multiples of 0x11 are the staged air's own nodes; these tests use others.
    const val REPORTED = 1_761_666_120L

    fun secret(seed: Int) = ByteArray(32) { seed.toByte() }

    fun address(seed: Int): String = MobileIdentity.unlock(secret(seed)).use { it.publicIdentity().canonicalAddress }

    fun hex(address: String): String = publicIdentityBytes(address).joinToString("") { "%02x".format(it) }

    class Signed(val address: String, val bundle: ByteArray, val link: String)

    fun signedLink(seed: Int, name: String = "Marmot"): Signed = runBlocking {
        val address = address(seed)
        val bundle = signNodeIdentityBundle(
            secret(seed),
            NodeIdentityProfileRecord(
                roleCode = 2u,
                capabilityBits = 0x06u,
                name = name,
                latitude = 44.0521,
                longitude = -123.0868,
                locationPrecision = 5u,
                altitudeM = null,
                timestamp = REPORTED.toUInt(),
            ),
        )
        Signed(address, bundle, nodeUriWithIdentity(address, bundle))
    }

    /** The same claims with the 64-byte signature cut off. */
    fun unsignedLink(seed: Int): String {
        val signed = signedLink(seed)
        return nodeUriWithIdentity(signed.address, signed.bundle.copyOf(signed.bundle.size - 64))
    }

    /** The signed claims with one signature byte changed. */
    fun tamperedLink(seed: Int): String {
        val signed = signedLink(seed)
        val bundle = signed.bundle.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x01).toByte() }
        return nodeUriWithIdentity(signed.address, bundle)
    }

    /** Identity bytes that do not parse. */
    fun unreadableLink(seed: Int): String = nodeUriWithIdentity(address(seed), byteArrayOf(0x7F, 0x7F, 0x7F))
}
