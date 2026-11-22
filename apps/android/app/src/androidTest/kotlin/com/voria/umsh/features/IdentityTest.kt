package com.voria.umsh.features

import android.content.ClipboardManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.generateIdentitySecret
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.settings.IdentityUnavailableScreen
import com.voria.umsh.services.identity.CoreSecretVault
import com.voria.umsh.services.identity.KeystoreIdentityVault
import com.voria.umsh.services.identity.KeystoreSecretVault
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** Your identity (`identity.svg`), and the identity and storage states that replace the app (D11, `storage-unavailable.svg`). */
class IdentityTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val paths get() = (context.applicationContext as TestUmshApplication).paths!!

    private fun ready(after: Long = 0): AppRuntime = runBlocking {
        val ready = withTimeout(TIMEOUT) {
            fresh.host.state.first { it is HostState.Ready && it.runtime.generation > after }
        } as HostState.Ready
        ready.runtime
    }

    private fun waitFor(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty() }

    private fun clip(): String? =
        context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()

    /** Past Welcome, Settings › Your identity. */
    private fun openYourIdentity(): AppRuntime {
        fresh.host.ensureRuntime(staging = false)
        val runtime = ready()
        runBlocking {
            runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        }
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.NAV_SETTINGS)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        return runtime
    }

    @Test
    fun editNameSavesAndTheHeaderShowsIt() {
        val runtime = openYourIdentity()
        compose.onNodeWithTag(Tags.IDENTITY_EDIT_NAME).performClick()
        compose.onNodeWithTag(Tags.EDIT_NAME_FIELD).performTextClearance()
        compose.onNodeWithTag(Tags.EDIT_NAME_FIELD).performTextInput("Juniper")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(Tags.EDIT_NAME_DIALOG)).fetchSemanticsNodes().isEmpty() }
        compose.onNode(hasText("Juniper")).assertIsDisplayed()
        assertEquals("Juniper", runBlocking { runtime.core.state(true).advertisedName })
    }

    @Test
    fun theQrSheetCopiesThePhonesLink() {
        val runtime = openYourIdentity()
        compose.onNodeWithTag(Tags.IDENTITY_QR).performClick()
        waitFor(Tags.QR_SHEET)
        compose.onNodeWithTag(Tags.QR_IMAGE).assertIsDisplayed()
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        val link = runBlocking { runtime.shareUri().await() }
        // With the core running the link carries freshly signed details, so
        // two reads differ only after the identity.
        val copied = clip().orEmpty()
        assertTrue(copied, copied.startsWith("umsh:"))
        assertEquals(link.substringBeforeLast(':'), copied.substringBeforeLast(':'))
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            // In the sheet's own window: the shell's host is under it.
            compose.onNode(hasText(context.getString(R.string.link_copied))).assertIsDisplayed()
        }
    }

    /** A core that can no longer sign (here stopped; busy erasing is the same) gives the bare link; the sheet never fails. */
    @Test
    fun theQrSheetFallsBackToTheBareLink() {
        val runtime = openYourIdentity()
        runBlocking { runtime.core.stop() }
        compose.onNodeWithTag(Tags.IDENTITY_QR).performClick()
        waitFor(Tags.QR_SHEET)
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.QR_COPY_LINK).assertIsEnabled() }.isSuccess
        }
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        assertEquals(nodeUriForAddress(runtime.ownerAddress), clip())
    }

    /** Without a radio carrying this phone, Advertise is there but off. */
    @Test
    fun advertiseWaitsForARadio() {
        openYourIdentity()
        compose.onNodeWithTag(Tags.IDENTITY_ADVERTISE).assertIsNotEnabled()
    }

    @Test
    fun theAnnouncementRowsChangeThePolicy() {
        val runtime = openYourIdentity()
        compose.onNodeWithTag(Tags.IDENTITY_DISCOVERABLE).performScrollTo().assertIsOn().performClick()
        compose.waitUntil(TIMEOUT) { runBlocking { !runtime.policy.first().discoverable } }
        compose.onNodeWithTag(Tags.IDENTITY_DISCOVERABLE).assertIsOff()

        compose.onNodeWithTag(Tags.IDENTITY_SCHEDULE).performScrollTo().assertTextContains(context.getString(R.string.schedule_off))
        compose.onNodeWithTag(Tags.IDENTITY_SCHEDULE).performClick()
        waitFor(Tags.SCHEDULE_DIALOG)
        compose.onNodeWithTag("${Tags.SCHEDULE_OPTION}_${4 * 3600}").performClick()
        compose.waitUntil(TIMEOUT) { runBlocking { runtime.policy.first().advertIntervalSeconds == 14_400u } }
        val every4 = context.resources.getQuantityString(R.plurals.schedule_every_hours, 4, 4)
        compose.onNodeWithTag(Tags.IDENTITY_SCHEDULE).assertTextContains(every4)

        compose.onNodeWithTag(Tags.IDENTITY_BEACON).performScrollTo().performClick()
        waitFor(Tags.SCHEDULE_DIALOG)
        compose.onNodeWithTag("${Tags.SCHEDULE_OPTION}_${20 * 60}").performClick()
        // The row reads the stored policy: wait for the write, which also checks it was kept.
        compose.waitUntil(TIMEOUT) { runBlocking { runtime.policy.first().beaconIntervalSeconds == 1_200u } }
        val every20 = context.resources.getQuantityString(R.plurals.schedule_every_minutes, 20, 20)
        compose.onNodeWithTag(Tags.IDENTITY_BEACON).assertTextContains(every20)
        compose.onNodeWithTag(Tags.IDENTITY_KEY_PROTECTION).performScrollTo()
            .assertTextContains(context.getString(R.string.key_protection_software))
    }

    /** Board 8: Erase identity confirms, then a new identity at Welcome. */
    @Test
    fun eraseMakesANewIdentityAtWelcome() {
        val before = openYourIdentity()
        compose.onNodeWithTag(Tags.IDENTITY_ERASE).performScrollTo().performClick()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        val after = ready(after = before.generation)
        assertNotEquals(before.ownerAddress, after.ownerAddress)
        waitFor(Tags.WELCOME)
        compose.onNodeWithTag(Tags.SHELL).assertDoesNotExist()
    }

    /** A secret that will not go: the failure dialog, and the phone stays the node it was. */
    @Test
    fun anEraseThatFailsSaysSoAndChangesNothing() {
        val before = openYourIdentity()
        val identityDir = paths.identity
        try {
            assertTrue(identityDir.setWritable(false))
            compose.onNodeWithTag(Tags.IDENTITY_ERASE).performScrollTo().performClick()
            compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
            waitFor(Tags.FAILURE_DIALOG)
            compose.onNode(hasText(context.getString(R.string.erase_failed_title))).assertIsDisplayed()
            compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        } finally {
            identityDir.setWritable(true)
        }
        val after = ready(after = before.generation)
        assertEquals(before.ownerAddress, after.ownerAddress)
    }

    /** Staging never erases the live identity (D16). */
    @Test
    fun stagingLeavesEraseOut() {
        fresh.host.ensureRuntime(staging = true)
        val runtime = ready()
        assertEquals(CoreKind.Staging, runtime.kind)
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.NAV_SETTINGS)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.IDENTITY_KEY_PROTECTION).performScrollTo()
        compose.onNodeWithTag(Tags.IDENTITY_ERASE).assertDoesNotExist()
    }

    /** A planted corrupt database: Storage unavailable, with the real detail line. */
    @Test
    fun aCorruptStoreShowsStorageUnavailable() {
        val store = paths.store(CoreKind.Live).apply { parentFile!!.mkdirs() }
        store.writeBytes(ByteArray(8192) { (it * 31).toByte() })
        fresh.host.ensureRuntime(staging = false)
        val unavailable = runBlocking {
            withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.StoreUnavailable } }
        } as HostState.StoreUnavailable
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.STORAGE_UNAVAILABLE)
        compose.onNodeWithTag(Tags.SHELL).assertDoesNotExist()
        compose.onNodeWithTag(Tags.WELCOME).assertDoesNotExist()
        val detail = unavailable.detail.render()
        assertEquals("app.sqlite: SQLITE_NOTADB (26): file is not a database", detail)
        compose.onNodeWithTag(Tags.UNAVAILABLE_DETAIL).assertTextEquals("⁦$detail⁩")
        compose.onNodeWithTag(Tags.UNAVAILABLE_COPY).performScrollTo().performClick()
        compose.waitForIdle()
        assertEquals(detail, clip())
    }

    /**
     * D11: a stored identity that will never open. Never minted over;
     * Erase identity makes a new node and starts again at Welcome, and
     * what the old one stored stays, as the page says.
     */
    @Test
    fun aLostIdentityOffersErase() {
        val secret = generateIdentitySecret()
        val planted = MobileIdentity.unlock(secret).use { it.publicIdentity().canonicalAddress }
        // Something the old node stored: its name, in the live store.
        withLiveCore(planted) { it.setAdvertisedName("Juniper") }
        val vault = KeystoreIdentityVault(KeystoreSecretVault(paths.identity, paths.identityAlias))
        vault.store(secret)
        paths.identity.listFiles()!!.single().writeBytes(byteArrayOf(1, 2, 3))
        fresh.host.ensureRuntime(staging = false)
        runBlocking { withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.IdentityLost } } }
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.IDENTITY_LOST)
        compose.onNodeWithTag(Tags.UNAVAILABLE_DETAIL).assertIsDisplayed()
        compose.onNodeWithTag(Tags.IDENTITY_LOST_ERASE).performScrollTo().performClick()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        val after = ready()
        waitFor(Tags.WELCOME)
        assertNotEquals(planted, after.ownerAddress)
        assertEquals("", after.identity.value.advertisedName)

        // The old node's rows survived the erase: read with the host's core closed.
        runBlocking { fresh.host.shutdown() }
        assertEquals("Juniper", withLiveCore(planted) { it.state(true).advertisedName })
    }

    /** [work] on a core over the live store with [owner] set, that never starts. */
    private fun <T> withLiveCore(owner: String, work: suspend (MobileAppCore) -> T): T = runBlocking {
        paths.store(CoreKind.Live).parentFile!!.mkdirs()
        MobileAppStore.open(paths.store(CoreKind.Live).path).use { store ->
            val vault = CoreSecretVault(KeystoreSecretVault(File(paths.filesDirectory, "check-keys"), "${paths.keyAliasPrefix}.check"))
            val counters = File(paths.filesDirectory, "check-counters").apply { mkdirs() }
            MobileAppCore(store, vault, MobileAppConfigRecord(counters.path, 65026u)).use { core ->
                core.setOwner(owner)
                try {
                    work(core)
                } finally {
                    core.stop()
                }
            }
        }
    }

    /** D11: Identity unavailable says nothing is lost and offers nothing; the host retries on the next foreground. */
    @Test
    fun anUnavailableIdentityOffersNothing() {
        compose.setContent { UmshTheme(fallbackScheme = true) { IdentityUnavailableScreen() } }
        compose.onNodeWithTag(Tags.IDENTITY_UNAVAILABLE).assertIsDisplayed()
        compose.onNode(hasText(context.getString(R.string.identity_unavailable_title))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.UNAVAILABLE_COPY).assertDoesNotExist()
        compose.onNodeWithTag(Tags.IDENTITY_LOST_ERASE).assertDoesNotExist()
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
