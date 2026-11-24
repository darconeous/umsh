package com.voria.umsh.features

import com.voria.umsh.features.peers.ExchangeHost
import com.voria.umsh.models.MeetDevice
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.models.MeetState
import java.util.Collections
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * An exchange a test moves by hand: every state held as long as it likes,
 * including the ones that pass in an instant on the staged air (boards 2
 * and 4). It records what the pages asked of it; only backing out moves
 * it, to Nearby again, as the core does.
 */
class FakeExchangeHost(initial: MeetState? = null) : ExchangeHost {
    override val meet = MutableStateFlow(initial)

    val carries = MutableStateFlow(true)

    override val carriesThisPhone = carries

    override fun carriesThisPhoneNow() = carries.value

    override val ownModel = ANDROID_PHONE

    val calls: MutableList<String> = Collections.synchronizedList(mutableListOf())

    override suspend fun setWanted(wanted: Boolean) {
        calls += "wanted $wanted"
    }

    override fun ask(device: Long) {
        calls += "ask $device"
    }

    override fun answer(accept: Boolean) {
        calls += "answer $accept"
    }

    override fun confirm(same: Boolean) {
        calls += "confirm $same"
    }

    /** As the core does: the attempt is left, and the meet opens again. */
    override fun backOut(): Deferred<Unit> {
        calls += "back out"
        meet.value = meet.value?.copy(exchange = MeetExchange.Idle, device = null)
        return CompletableDeferred(Unit)
    }

    /** Moves the exchange to [exchange], with [device] as the one it is with. */
    fun move(exchange: MeetExchange, device: MeetDevice? = meet.value?.device) {
        meet.value = (meet.value ?: open()).copy(exchange = exchange, device = device)
    }

    companion object {
        const val IPHONE = 0xFE00
        const val ANDROID_PHONE = 0xFE02
        const val PAGER = 9
        const val TDECK = 11

        /** The board's four: an iPhone, the T-LoRa Pager, an Android phone and a T-Deck, nearest first. */
        val devices = listOf(
            MeetDevice(1, IPHONE, 0x6E78C8, 3),
            MeetDevice(2, PAGER, 0x2E9C86, 3),
            MeetDevice(3, ANDROID_PHONE, 0xB08A30, 2),
            MeetDevice(4, TDECK, 0xC0607A, 1),
        )

        val pager = devices[1]

        fun open(devices: List<MeetDevice> = this.devices) =
            MeetState(ownColorRgb = 0x8E7CC3, devices = devices, device = null, exchange = MeetExchange.Idle)
    }
}
