package com.voria.umsh.services.radio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Debug builds: the bridged radio's `host:port`. */
class TcpEndpointTest {
    @Test
    fun endpointsParse() {
        assertEquals(TcpEndpoint("10.0.2.2", 21838), TcpEndpoint.parse(TcpEndpoint.DEFAULT))
        assertEquals(TcpEndpoint("localhost", 9000), TcpEndpoint.parse("  localhost:9000 "))
        assertEquals(TcpEndpoint("::1", 21838), TcpEndpoint.parse("[::1]:21838"))
        assertEquals("[::1]:21838", TcpEndpoint("::1", 21838).text)
        assertEquals("10.0.2.2:21838", TcpEndpoint("10.0.2.2", 21838).text)
        listOf("", "host", "host:", ":80", "host:0", "host:65536", "host:+80", "host:8 0", "[::1]", "[::1]80", "[::1:80")
            .forEach { assertNull(it, TcpEndpoint.parse(it)) }
        // An IPv6 address takes brackets: without them its last group would read as the port.
        listOf("fe80::1", "::1:21838", "fe80::1:80").forEach { assertNull(it, TcpEndpoint.parse(it)) }
    }
}
