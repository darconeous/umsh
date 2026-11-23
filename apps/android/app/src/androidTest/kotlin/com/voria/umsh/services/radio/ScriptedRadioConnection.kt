package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioTransportPhase
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * A scripted test link: it carries no frames, and reports to the real
 * driver the transport states no other emulator link reaches. The TCP link
 * never waits for its radio, and a real Bluetooth failure needs a radio;
 * this link reports either on its first connect, as a Bluetooth link would
 * after its reconnect window or a failed attachment.
 *
 * Bound like any radio, under a `scripted:` link ID ([ScriptedRadioLinks]):
 * `scripted:waiting` waits, `scripted:failed` fails with
 * [RadioTransportProblem.AttachmentIncomplete], and `scripted:connecting`
 * stays connecting.
 */
class ScriptedRadioConnection(
    linkId: String,
    private val name: String?,
    registry: RadioRegistry,
    events: RadioConnectionEvents,
) : RadioDriverAdapter(RadioKind.Tcp, linkId, registry, events) {
    /** Where the link rests once it is asked to connect. */
    sealed interface Script {
        data object Waiting : Script

        data object Connecting : Script

        data class Failed(val problem: MobileRadioProblem) : Script
    }

    private val script: Script = when {
        linkId.endsWith(":failed") -> Script.Failed(RadioTransportProblem.AttachmentIncomplete.problem)
        linkId.endsWith(":connecting") -> Script.Connecting
        else -> Script.Waiting
    }

    init {
        adopt()
        post { reportTransport(MobileRadioTransportPhase.IDLE, name) }
    }

    override fun startLink(userInitiated: Boolean) {
        connects.getOrPut(linkId) { AtomicInteger() }.incrementAndGet()
        reportTransport(MobileRadioTransportPhase.CONNECTING, name)
        when (val rest = script) {
            Script.Waiting -> reportTransport(MobileRadioTransportPhase.WAITING_FOR_RADIO, name)
            Script.Connecting -> Unit
            is Script.Failed -> reportTransport(MobileRadioTransportPhase.FAILED, name, rest.problem)
        }
    }

    override fun stopLink() {
        reportTransport(MobileRadioTransportPhase.IDLE, name)
    }

    override fun linkSend(frame: ByteArray, rawTransactionId: UByte?) = Unit

    override fun linkResetFraming() = Unit

    override fun linkInvalidate(retrying: Boolean) = stopLink()

    companion object {
        private val connects = ConcurrentHashMap<String, AtomicInteger>()

        /** How often a link under [linkId] has been asked to connect, so a test sees a click reach it. */
        fun connectCount(linkId: String): Int = connects[linkId]?.get() ?: 0
    }
}

/** The app's links ([app]), plus scripted ones under a `scripted:` link ID. */
class ScriptedRadioLinks(private val app: RadioLinkFactory) : RadioLinkFactory {
    override fun make(radio: BoundRadio, registry: RadioRegistry, events: RadioConnectionEvents): RadioConnection? =
        if (radio.linkId.startsWith(PREFIX)) {
            ScriptedRadioConnection(radio.linkId, radio.name, registry, events)
        } else {
            app.make(radio, registry, events)
        }

    companion object {
        const val PREFIX = "scripted:"
    }
}
