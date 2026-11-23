package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileHdlcDecoder
import com.voria.umsh.core.MobileRadioPhase
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The bridged radio's link over a loopback socket standing in for a
 * `umsh-bridge` host interface: HDLC frames out, the bridge's close and a
 * refused dial worded as iOS words them, and the two-second redial.
 */
class HdlcTcpLinkTest {
    private val closeables = mutableListOf<AutoCloseable>()
    private val connections = mutableListOf<RadioConnection>()

    @After
    fun tearDown() {
        connections.forEach { it.close() }
        closeables.forEach { runCatching { it.close() } }
    }

    private fun server() = ServerSocket(0, 4, InetAddress.getLoopbackAddress()).apply {
        soTimeout = 10_000
        closeables += this
    }

    private fun connection(port: Int): TcpRadioConnection {
        val endpoint = TcpEndpoint("127.0.0.1", port)
        val registry = MemoryRadioRegistry(BoundRadio(RadioKind.Tcp, endpoint.text))
        return TcpRadioConnection(endpoint, registry, { }).also { connections += it }
    }

    private suspend fun accept(server: ServerSocket): Socket =
        withContext(Dispatchers.IO) { server.accept() }.also { closeables += it }

    /** Read until a whole HDLC frame arrives. */
    private suspend fun firstFrame(socket: Socket): ByteArray = withContext(Dispatchers.IO) {
        socket.soTimeout = 10_000
        val decoder = MobileHdlcDecoder()
        val buffer = ByteArray(1024)
        while (true) {
            val count = socket.getInputStream().read(buffer)
            check(count > 0) { "closed before a frame" }
            decoder.push(buffer.copyOf(count)).firstOrNull()?.let { return@withContext it }
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

    @Test
    fun aBridgedRadioCarriesFramesRedialsAndStopsWhenAsked() = runBlocking<Unit> {
        val server = server()
        val tcp = connection(server.localPort)
        assertEquals(MobileRadioPhase.IDLE, tcp.driver.awaitPhase(MobileRadioPhase.IDLE).phase)

        tcp.connect()
        val first = accept(server)
        // Open is attach: the driver starts its session, and its first frame
        // reaches the bridge HDLC-framed.
        assertTrue(firstFrame(first).isNotEmpty())

        // The bridge closing the socket is a detach: Connecting, and why.
        first.close()
        val closed = tcp.driver.awaitState { it.phase == MobileRadioPhase.CONNECTING && it.problem != null }
        assertEquals(RadioTransportProblem.BridgeClosed, RadioTransportProblem.of(closed.problem!!))
        // Dialed again, without being asked.
        val second = withTimeout(5_000) { accept(server) }
        assertTrue(firstFrame(second).isNotEmpty())

        // Disconnect: nothing redials, and the transport rests idle.
        withTimeout(15_000) { tcp.disconnect() }
        tcp.driver.awaitPhase(MobileRadioPhase.IDLE)
        withContext(Dispatchers.IO) {
            second.soTimeout = 5_000
            val buffer = ByteArray(1024)
            while (second.getInputStream().read(buffer) >= 0) Unit
        }
        server.soTimeout = 3_000
        val redialed = try {
            withContext(Dispatchers.IO) { server.accept() }.also { closeables += it }
            true
        } catch (_: SocketTimeoutException) {
            false
        }
        assertEquals(false, redialed)
    }

    @Test
    fun aRefusedDialSaysTheBridgeIsNotThereYet() = runBlocking<Unit> {
        val port = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
        val tcp = connection(port)
        tcp.autoConnect()
        val waiting = tcp.driver.awaitState { it.phase == MobileRadioPhase.CONNECTING && it.problem != null }
        assertEquals(RadioTransportProblem.BridgeWaiting, RadioTransportProblem.of(waiting.problem!!))
        // Once the bridge listens on that port, the standing attempt finds it.
        val server = ServerSocket(port, 4, InetAddress.getLoopbackAddress()).apply {
            soTimeout = 10_000
            closeables += this
        }
        val socket = accept(server)
        assertTrue(firstFrame(socket).isNotEmpty())
    }
}
