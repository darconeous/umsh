package com.voria.umsh.features.radio

import com.voria.umsh.R
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.RadioPresetRecord
import com.voria.umsh.core.SavedSnapshotRecord
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.features.radio.RadioDetailModel.Battery
import com.voria.umsh.features.radio.RadioDetailModel.Charge
import com.voria.umsh.features.radio.RadioDetailModel.Primary
import com.voria.umsh.features.radio.RadioDetailModel.Status
import com.voria.umsh.services.radio.RadioProvisioning
import com.voria.umsh.services.radio.RadioSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** `radio-detail.svg` boards 1–4: what Radio Detail shows for each radio state. */
class RadioDetailModelTest {
    private val provisioning = RadioProvisioning(
        deviceModel = "SenseCAP T1000-E",
        frequencyKhz = 910_525,
        transmitPowerDbm = 22,
        bandwidthHz = 62_500,
        spreadingFactor = 7,
        codingRateDenominator = 5,
        dutyCycleNow = 1_376,
        dutyCycleLimit = 6_553,
        saved = SavedSnapshotRecord.CURRENT,
        hasHostFiltering = true,
        filterCount = 12,
        hostChannelCount = 4,
        hostPeerCount = 31,
        queuedFrames = 0,
        droppedFrames = 0,
        autoAck = true,
        supportsDeviceIdentity = true,
        supportsReboot = true,
    )

    private fun radio(
        phase: MobileRadioPhase = MobileRadioPhase.ATTACHED,
        percent: Int? = 78,
        charge: UlcpChargeState? = UlcpChargeState.DISCHARGING,
        cached: Boolean = false,
        problem: MobileRadioProblem? = null,
        provisioning: RadioProvisioning? = this.provisioning,
        deviceKeyHex: String? = "3F2A9C41" + "00".repeat(26) + "E07B",
    ) = RadioSnapshot(
        phase = phase,
        name = "T1000-E 4F2A",
        linkId = "link",
        host = UlcpHostOwnership.OURS,
        batteryPercent = percent,
        batteryMillivolts = null,
        charge = charge,
        batteryReadAtMs = 1_000L,
        problem = problem,
        carriesThisPhone = phase == MobileRadioPhase.ATTACHED,
        reportsBattery = true,
        batteryCached = cached,
        deviceKeyHex = deviceKeyHex,
        provisioning = provisioning,
    )

    @Test
    fun board1Connected() {
        val model = RadioDetailModel.from(radio())
        assertEquals(Status.Connected, model.status)
        assertEquals("SenseCAP T1000-E", model.model)
        assertEquals(Battery.Live(78, Charge.Discharging), model.battery)
        assertEquals(Primary.Disconnect, model.primary)
        assertNull(model.reason)
        assertEquals("3F2A9C41…E07B", model.radioId)
        assertEquals(910_525L, model.mesh?.frequencyKhz)
        assertEquals(12L, model.offline?.receiveFilters)
        assertEquals(true, model.offline?.delegatedAcks)
        assertTrue(model.showsIdentity)
        assertTrue(model.offersMaintenance)
    }

    @Test
    fun liveBatteryStates() {
        assertEquals(Battery.Live(78, Charge.Charging), RadioDetailModel.from(radio(charge = UlcpChargeState.CHARGING)).battery)
        assertEquals(Battery.Live(100, Charge.ExternalPower), RadioDetailModel.from(radio(percent = 100, charge = UlcpChargeState.CHARGED)).battery)
        assertEquals(Battery.Live(78, null), RadioDetailModel.from(radio(charge = null)).battery)
        assertEquals(Battery.ExternalOnly(charging = false), RadioDetailModel.from(radio(percent = null, charge = UlcpChargeState.NOT_CHARGING)).battery)
        assertNull(RadioDetailModel.from(radio(percent = null, charge = null)).battery)
    }

    @Test
    fun board3Waiting() {
        val model = RadioDetailModel.from(
            radio(phase = MobileRadioPhase.WAITING_FOR_RADIO, cached = true, charge = null, provisioning = null, deviceKeyHex = null),
        )
        assertEquals(Status.Waiting, model.status)
        assertEquals(Primary.StopWaiting, model.primary)
        // The last reading with its age, never as live.
        assertEquals(Battery.Last(78, 1_000L), model.battery)
        assertNull(model.mesh)
        assertNull(model.radioId)
        assertFalse(model.showsIdentity)
        // Out of reach the radio can take neither request: no Maintenance.
        assertFalse(model.offersMaintenance)
    }

    @Test
    fun board4FailedCarriesItsReason() {
        val problem = MobileRadioProblem.Transport("com.voria.umsh.radio-transport", 4)
        val model = RadioDetailModel.from(radio(phase = MobileRadioPhase.FAILED, cached = true, problem = problem))
        assertEquals(Status.Failed, model.status)
        assertEquals(Primary.Reconnect, model.primary)
        assertEquals(problem, model.reason)
        assertEquals(Battery.Last(78, 1_000L), model.battery)
        assertFalse(model.offersMaintenance)
    }

    @Test
    fun maintenanceOnlyWhileAttached() {
        MobileRadioPhase.entries.filter { it != MobileRadioPhase.ATTACHED }.forEach { phase ->
            // Even with provisioning still at hand, a radio not attached is offered nothing.
            assertFalse(phase.name, RadioDetailModel.from(radio(phase = phase)).offersMaintenance)
        }
    }

    @Test
    fun aProblemOutsideFailedIsNotAReason() {
        val model = RadioDetailModel.from(radio(problem = MobileRadioProblem.RadioBusy))
        assertNull(model.reason)
    }

    @Test
    fun everyPhaseHasAStateAndAPrimaryAction() {
        val expected = mapOf(
            MobileRadioPhase.ATTACHED to (Status.Connected to Primary.Disconnect),
            MobileRadioPhase.SCANNING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.CONNECTING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.PAIRING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.ATTACHING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.SYNCHRONIZING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.AWAITING_HOST to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.PROVISIONING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.CONFIGURING to (Status.Connecting to Primary.Disconnect),
            MobileRadioPhase.RECONNECTING to (Status.Reconnecting to Primary.Disconnect),
            MobileRadioPhase.WAITING_FOR_RADIO to (Status.Waiting to Primary.StopWaiting),
            MobileRadioPhase.IDLE to (Status.Disconnected to Primary.Connect),
            MobileRadioPhase.UNAVAILABLE to (Status.Disconnected to Primary.Connect),
            MobileRadioPhase.DISCOVERED to (Status.Disconnected to Primary.Connect),
            MobileRadioPhase.DISCONNECTING to (Status.Disconnected to Primary.Connect),
            MobileRadioPhase.FAILED to (Status.Failed to Primary.Reconnect),
        )
        assertEquals(MobileRadioPhase.entries.toSet(), expected.keys)
        expected.forEach { (phase, pair) ->
            val model = RadioDetailModel.from(radio(phase = phase))
            assertEquals(phase.name, pair, model.status to model.primary)
        }
    }

    @Test
    fun offlineAssistanceNeedsHostFiltering() {
        val transparent = provisioning.copy(hasHostFiltering = false)
        assertNull(RadioDetailModel.from(radio(provisioning = transparent)).offline)
    }

    @Test
    fun capabilitiesHideRows() {
        val bare = provisioning.copy(supportsDeviceIdentity = false, supportsReboot = false)
        val model = RadioDetailModel.from(radio(provisioning = bare))
        assertFalse(model.showsIdentity)
        // A radio that cannot restart refuses a factory reset too (UNIMPLEMENTED),
        // and the driver would forget it anyway: neither is offered.
        assertFalse(model.offersMaintenance)
    }

    @Test
    fun shortIdKeepsShortKeysWhole() {
        assertEquals("ABCD", RadioDetailModel.shortId("ABCD"))
        assertEquals("01234567…CDEF", RadioDetailModel.shortId("0123456789ABCDEF0123456789ABCDEF"))
    }

    @Test
    fun presetNamedOnlyOnAnExactMatch() {
        fun preset(id: String, freq: UInt, bw: UInt, sf: UByte) = RadioPresetRecord(
            id = id, name = id, frequencyKhz = freq, bandwidthHz = bw, spreadingFactor = sf, codingRateDenom = 5u,
            transmitPowerDbm = 22, dutyCycleLimit = 0xFFFFu, syncWord = 0x12u, txPreambleSymbols = 32u,
        )
        val presets = listOf(preset("other", 917_500u, 500_000u, 10u), preset("match", 910_525u, 62_500u, 7u))
        val mesh = RadioDetailModel.from(radio()).mesh!!
        assertEquals("match", presets.presetId(mesh))
        assertNull(presets.presetId(mesh.copy(spreadingFactor = 8)))
        assertNull(presets.presetId(mesh.copy(bandwidthHz = null)))
    }

    @Test
    fun presetLabelsByIdOnly() {
        assertEquals(R.string.radio_preset_umsh_us_ca, presetLabel("umsh-us-ca"))
        assertNull(presetLabel("nonesuch"))
    }

    /** Every profile in the shared table has words here; a new one fails this until it does. */
    @Test
    fun everyVettedProfileHasALabel() {
        val table = generateSequence(File("").absoluteFile) { it.parentFile }
            .map { File(it, "crates/umsh-ulcp/src/profiles.rs") }
            .first { it.isFile }
            .readText()
            .substringBefore("#[cfg(test)]")
        val ids = Regex("""\bid: "([^"]+)"""").findAll(table).map { it.groupValues[1] }.toList()
        assertTrue(ids.size > 1)
        ids.forEach { assertNotNull(it, presetLabel(it)) }
    }
}
