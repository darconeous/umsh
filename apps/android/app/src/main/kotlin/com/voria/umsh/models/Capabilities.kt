package com.voria.umsh.models

/**
 * The capability bits a node advertised, in wire order. The core sends
 * bits, never names; a bit this build has no name for survives here and
 * matches nothing.
 */
@JvmInline
value class Capabilities(val bits: Int) {
    fun contains(capability: Int): Boolean = bits and capability == capability

    companion object {
        const val REPEATER = 0x01
        const val MOBILE = 0x02
        const val TEXT_MESSAGES = 0x04
        const val TELEMETRY = 0x08
        const val CHAT_ROOM = 0x10
        const val COAP = 0x20

        /** Every capability this app has a name for, in wire bit order. */
        val NAMED = listOf(REPEATER, MOBILE, TEXT_MESSAGES, TELEMETRY, CHAT_ROOM, COAP)
    }
}
