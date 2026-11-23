package com.voria.umsh.services.background

import com.voria.umsh.services.background.HeadlessStart.Trigger
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.PendingBinding
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** DP-84 and DP-94: the rules for a presence wake and the update broadcast starting the radio's service. */
class HeadlessStartTest {
    private val ble = BoundRadio(RadioKind.Ble, "C0:FF:EE:00:00:01", associationId = "7")
    private val bridged = BoundRadio(RadioKind.Tcp, "10.0.2.2:21838")

    private fun of(
        trigger: Trigger,
        bound: BoundRadio?,
        stopped: Boolean = false,
        bluetoothOn: Boolean = true,
        running: Boolean = false,
    ) = runBlocking { HeadlessStart.of(trigger, bound, { stopped }, { bluetoothOn }, running) }

    @Test
    fun aWantedRadioStarts() {
        for (trigger in Trigger.entries) {
            assertEquals(HeadlessStart.Start, of(trigger, ble))
            assertEquals(HeadlessStart.Start, of(trigger, bridged))
        }
    }

    @Test
    fun noRadioWantedStartsNothing() {
        for (trigger in Trigger.entries) {
            assertEquals(HeadlessStart.NotWanted, of(trigger, null))
            assertEquals(HeadlessStart.NotWanted, of(trigger, ble.copy(autoConnect = false)))
            // Still being added: the attempt was cut off and is undone, not connected.
            assertEquals(HeadlessStart.NotWanted, of(trigger, ble.copy(pending = PendingBinding.NewAssociation)))
        }
    }

    @Test
    fun theUsersStopHolds() {
        for (trigger in Trigger.entries) {
            assertEquals(HeadlessStart.StoppedByUser, of(trigger, ble, stopped = true))
            assertEquals(HeadlessStart.StoppedByUser, of(trigger, bridged, stopped = true, running = true))
            assertEquals(HeadlessStart.StoppedByUser, of(trigger, ble, stopped = true, bluetoothOn = false))
        }
    }

    @Test
    fun theStopIsNotReadWithNoRadioWanted() = runBlocking {
        var read = false
        HeadlessStart.of(Trigger.Update, null, { read = true; true }, { true }, false)
        assertFalse(read)
    }

    @Test
    fun bluetoothOffHoldsPresenceAndLeavesTheUpdateToIt() {
        assertEquals(HeadlessStart.HoldForBluetooth, of(Trigger.Presence, ble, bluetoothOn = false))
        assertEquals(HeadlessStart.Skip, of(Trigger.Update, ble, bluetoothOn = false))
        // A bridged radio needs no Bluetooth.
        assertEquals(HeadlessStart.Start, of(Trigger.Presence, bridged, bluetoothOn = false))
        assertEquals(HeadlessStart.Start, of(Trigger.Update, bridged, bluetoothOn = false))
    }

    @Test
    fun theUpdateStartsNoServiceAlreadyRunning() {
        assertEquals(HeadlessStart.Skip, of(Trigger.Update, ble, running = true))
        // Presence starts it again: the service seeks the radio it saw.
        assertEquals(HeadlessStart.Start, of(Trigger.Presence, ble, running = true))
    }
}
