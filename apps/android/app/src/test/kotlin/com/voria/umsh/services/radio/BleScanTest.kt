package com.voria.umsh.services.radio

import com.voria.umsh.features.onboarding.FoundRadio
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What a radio's advertising says, and the pairing list built from it (§3.3). */
class BleScanTest {
    /** The ULCP service UUID, little-endian, as advertised. */
    private val serviceLe = "97EC1B1779A0E492CF4C0100156BEB21".chunked(2).map { it.toInt(16).toByte() }

    private fun ad(type: Int, data: List<Byte>) = listOf((data.size + 1).toByte(), type.toByte()) + data

    private fun advertising(pairing: Boolean, model: Int? = 2, name: String? = null): ByteArray {
        val flags = ad(0x01, listOf(if (pairing) 0x06 else 0x04))
        val service = ad(0x07, serviceLe)
        val msd = if (pairing && model != null) ad(0xFF, listOf(0xFF, 0xFF, model shr 8, model and 0xFF).map { it.toByte() }) else emptyList()
        val named = name?.let { ad(0x09, it.encodeToByteArray().toList()) } ?: emptyList()
        return (flags + service + msd + named).toByteArray()
    }

    @Test
    fun aRadioInItsPairingWindow() {
        val parsed = RadioAdvertisement.parse(advertising(pairing = true, name = "T1000-E 4F2A"))
        assertEquals(RadioAdvertisement(discoverable = true, modelId = 2, name = "T1000-E 4F2A", hasService = true), parsed)
        assertTrue(parsed.pairing)
    }

    @Test
    fun aBondedRadioOutsideItsWindowIsNotPairing() {
        val parsed = RadioAdvertisement.parse(advertising(pairing = false))
        assertTrue(parsed.hasService)
        assertNull(parsed.modelId)
        assertFalse(parsed.pairing)
    }

    @Test
    fun anUnassignedModelIsNone() {
        assertNull(RadioAdvertisement.parse(advertising(pairing = true, model = 0)).modelId)
    }

    @Test
    fun anotherServiceIsNotARadio() {
        val bytes = ad(0x01, listOf(0x06)) + ad(0x07, List(16) { 0x11 })
        assertFalse(RadioAdvertisement.parse(bytes.toByteArray()).pairing)
    }

    @Test
    fun aTruncatedStructureEndsTheParse() {
        val bytes = advertising(pairing = true) + byteArrayOf(9, 0x09, 0x41)
        val parsed = RadioAdvertisement.parse(bytes)
        assertEquals(2, parsed.modelId)
        assertNull(parsed.name)
    }

    @Test
    fun theListKeepsFirstHeardOrderAndFillsInNames() {
        val list = PairingRadioList()
        val bare = RadioAdvertisement(discoverable = true, modelId = 2, name = null, hasService = true)
        assertTrue(list.heard("A", bare, 0))
        assertTrue(list.heard("B", bare.copy(modelId = 11), 10))
        assertFalse(list.heard("A", bare, 20))
        // The scan response arrives: the name fills in, the order stays.
        assertTrue(list.heard("B", bare.copy(modelId = 11, name = "T-Deck"), 30))
        assertEquals(listOf(FoundRadio("A", null, 2), FoundRadio("B", "T-Deck", 11)), list.radios)
        // A primary packet alone does not wipe the name.
        assertFalse(list.heard("B", bare.copy(modelId = 11), 40))
    }

    @Test
    fun aRadioOutOfItsWindowIsNotListedAndQuietOnesGo() {
        val list = PairingRadioList()
        val pairing = RadioAdvertisement(discoverable = true, modelId = 2, name = null, hasService = true)
        list.heard("A", pairing, 0)
        // Heard closed: no longer kept alive by it.
        assertFalse(list.heard("A", pairing.copy(discoverable = false, modelId = null), 9_000))
        assertFalse(list.prune(PairingRadioList.PRUNE_MS))
        assertTrue(list.prune(PairingRadioList.PRUNE_MS + 1))
        assertTrue(list.radios.isEmpty())
    }
}
