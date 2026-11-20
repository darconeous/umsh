package com.voria.umsh.core

import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The core loads, its sync and async calls cross the boundary, and its
 * worker calls back into Kotlin. Runs on the host JVM and on Android.
 */
class CoreSmokeTest {
    @get:Rule val temp = TemporaryFolder()

    private fun identity(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() })

    @Test
    fun loads() {
        assertTrue(mobileApiVersion() > 0u)
    }

    @Test
    fun identityUnlocks() {
        assertEquals(44, identity(7).publicIdentity().canonicalAddress.length)
    }

    @Test
    fun zoneRules() {
        assertEquals("<-07>7", fixedOffsetRule(-420))
        assertEquals(330.toShort(), ruleOffsetMin("<+0530>-5:30", 0))
        assertNull(zoneRule("../etc/passwd"))
    }

    @Test
    fun applicationStoreOpens() {
        // On Android this is the SQLite compiled into the core.
        val path = temp.newFolder().resolve("application.sqlite").path
        MobileAppStore.open(path).use { it.insertIdentity("alice", "alice-public", 1L) }
        MobileAppStore.open(path).use { store ->
            assertTrue(store.knowsIdentity("alice", "alice-public"))
            store.upsertPeer("alice", "peer", MobilePeerUpsertRecord(alias = null, advertisedName = "Ångström"))
            assertEquals("Ångström", store.listNodes("alice").single().advertisedName)

            // A JVM UUID prints lowercase; the store keeps Foundation's uppercase.
            val channelId = UUID.randomUUID().toString()
            store.insertChannel(
                MobileStoredChannelRecord(
                    id = channelId,
                    ownerIdentityId = "alice",
                    kind = MobileStoredChannelKind.NAMED,
                    canonicalName = "ridge",
                    name = "Ridge",
                    alias = null,
                    channelIdHex = "beef",
                    tint = byteArrayOf(0xBE.toByte(), 0xEF.toByte(), 0x01),
                    regionCode = null,
                    maxFloodHops = null,
                    joinedPhone = true,
                    joinedDevice = false,
                    notificationsEnabled = false,
                    joinedAtMs = null,
                ),
                "digest",
                1L,
            )
            val conversation = store.ensureChannelConversation("alice", channelId, "channel-address", 2L)
            val records = store.applicationRecords("alice")
            assertEquals(channelId.uppercase(), records.channels.single().id)
            assertEquals(conversation, records.channelConversations.single().id)
        }
    }

    @Test
    fun asyncSendCrossesTheBoundary() = runBlocking {
        val own = identity(21)
        val store = MobileAppStore.open(temp.newFolder().resolve("application.sqlite").path)
        store.insertIdentity("me", own.publicIdentity().canonicalAddress, 1L)
        MobileMeshSession.start(own, MobileCounterStore(temp.newFolder().path)).use { session ->
            val peer = identity(22).publicIdentity().canonicalAddress
            session.registerPeers(listOf(MobilePeerRegistrationRecord(peer, false)))
            session.attachChatStore(store, "me", null)
            session.sendChat(peer, MobileChatSendRequest.Text("hello from Kotlin"))
            assertEquals(
                "hello from Kotlin",
                store.chatMessagePageNewest("me", peer, 10u).messages.single().body,
            )
        }
        store.close()
    }

    @Test
    fun workerWakesKotlin() = runBlocking {
        MobileMeshSession.start(identity(65), MobileCounterStore(temp.newFolder().path)).use { session ->
            val woke = CountDownLatch(1)
            session.setWakeListener(
                object : MobileMeshWakeListener {
                    override fun onUpdatePending() = woke.countDown()
                },
            )
            session.ping(identity(66).publicIdentity().canonicalAddress, null)
            assertTrue("listener never fired", woke.await(5, TimeUnit.SECONDS))
            assertTrue(session.pollUpdate().outboundFrames.isNotEmpty())
        }
    }
}
