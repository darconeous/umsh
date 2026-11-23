package com.voria.umsh.services.radio

import com.voria.umsh.services.preferences.AppPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The bound radio as the app's preferences keep it. */
class RadioRegistryTest {
    @get:Rule val temp = TemporaryFolder()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @After
    fun tearDown() = scope.cancel()

    private fun preferences() = AppPreferences(temp.root.resolve("preferences.preferences_pb"), scope)

    @Test
    fun aBoundRadioIsRememberedWhole() = runBlocking<Unit> {
        val registry = preferences().radioRegistry
        assertNull(registry.bound())
        val radio = BoundRadio(RadioKind.Ble, "C4:7A:11:00:4F:2A", associationId = "7", modelId = 2, name = "T1000-E 4F2A")
        registry.bind(radio)
        assertEquals(radio, registry.bound())
    }

    @Test
    fun bindingAnotherRadioReplacesEverything() = runBlocking<Unit> {
        val registry = preferences().radioRegistry
        registry.bind(BoundRadio(RadioKind.Ble, "C4:7A:11:00:4F:2A", associationId = "7", modelId = 2, name = "T1000-E"))
        registry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838"))
        assertEquals(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838"), registry.bound())
    }

    /** An attempt under way is remembered as one until its radio attaches. */
    @Test
    fun aPendingBindingEndsWhenItsRadioAttaches() = runBlocking<Unit> {
        val registry = preferences().radioRegistry
        val radio = BoundRadio(RadioKind.Ble, "C4:7A:11:00:4F:2A", associationId = "7", pending = PendingBinding.KnownAssociation)
        registry.bind(radio)
        assertEquals(radio, registry.bound())
        registry.attached("C4:7A:11:00:4F:2B")
        assertEquals(radio, registry.bound())
        registry.setAutoConnect(radio.linkId, false)
        registry.attached(radio.linkId)
        assertEquals(radio.copy(pending = null), registry.bound())
    }

    /** A connection being retired never edits its successor's entry. */
    @Test
    fun writesNameTheirRadio() = runBlocking<Unit> {
        val registry = preferences().radioRegistry
        registry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838"))
        registry.setAutoConnect("10.0.2.2:21839", false)
        registry.setName("10.0.2.2:21839", "Other")
        registry.clear("10.0.2.2:21839")
        assertEquals(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838"), registry.bound())
        registry.setAutoConnect("10.0.2.2:21838", false)
        registry.setName("10.0.2.2:21838", "Bridge")
        assertEquals(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838", name = "Bridge", autoConnect = false), registry.bound())
        registry.clear("10.0.2.2:21838")
        assertNull(registry.bound())
    }

    /** Start over clears the preferences, and the radio with them. */
    @Test
    fun startOverForgetsTheRadio() = runBlocking<Unit> {
        val preferences = preferences()
        preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838"))
        preferences.clear()
        assertNull(preferences.radioRegistry.bound())
    }
}
