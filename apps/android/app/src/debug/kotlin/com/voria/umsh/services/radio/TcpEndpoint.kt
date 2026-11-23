package com.voria.umsh.services.radio

/** Where a bridged radio lives, as typed (debug builds). */
data class TcpEndpoint(val host: String, val port: Int) {
    /** `host:port`, an IPv6 literal bracketed: the bridged radio's stable link ID. */
    val text: String get() = if (':' in host) "[$host]:$port" else "$host:$port"

    companion object {
        /** A `umsh-bridge` host interface on the computer running the emulator (`make android-bridge`). */
        const val DEFAULT = "10.0.2.2:21838"

        /**
         * Parse `host:port`, accepting a bracketed IPv6 literal. The port is
         * required: there is no registered one to assume.
         */
        fun parse(input: String): TcpEndpoint? {
            val text = input.trim()
            val host: String
            val port: String
            if (text.startsWith("[")) {
                val close = text.indexOf(']')
                if (close < 0) return null
                host = text.substring(1, close)
                val rest = text.substring(close + 1)
                if (!rest.startsWith(":")) return null
                port = rest.substring(1)
            } else {
                val colon = text.lastIndexOf(':')
                if (colon < 0) return null
                host = text.substring(0, colon)
                port = text.substring(colon + 1)
                // An IPv6 literal needs its brackets, or its last group reads as the port.
                if (':' in host) return null
            }
            // Digits only: no sign, no spaces, no plus.
            if (host.isEmpty() || port.isEmpty() || !port.all { it in '0'..'9' }) return null
            val number = port.toIntOrNull() ?: return null
            if (number !in 1..65535) return null
            return TcpEndpoint(host, number)
        }
    }
}
