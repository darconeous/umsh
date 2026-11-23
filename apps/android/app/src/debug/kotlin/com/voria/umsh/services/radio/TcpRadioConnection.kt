package com.voria.umsh.services.radio

import android.net.TrafficStats
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileHdlcDecoder
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.core.ulcpHdlcEncode
import com.voria.umsh.services.mobilecore.AppLog
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * A companion radio reached over TCP, framed exactly as a serial one (debug
 * builds; iOS `TcpRadioConnection`). It exists because the emulator has no
 * radio: a `umsh-bridge` host interface (`make android-bridge`) presents a
 * real device session on a socket, and the bytes are the same HDLC-Lite
 * frames a UART carries.
 *
 * There is nothing to discover: the endpoint is the radio. Attach is the
 * socket opening and detach is it closing. While wanted, a dropped or
 * refused socket is dialed again every two seconds, and the transport says
 * Connecting, with the last reason, the whole time; it never reports
 * Waiting or Reconnecting.
 *
 * Every field is confined to the connection's executor. The socket's read
 * loop and its writes run on threads of their own, and post what they find
 * back, tagged with the dial they belong to.
 */
class TcpRadioConnection(
    private val endpoint: TcpEndpoint,
    registry: RadioRegistry,
    events: RadioConnectionEvents,
    /** The registry's name for the radio; the endpoint stands in until there is one. */
    name: String? = null,
) : RadioDriverAdapter(RadioKind.Tcp, endpoint.text, registry, events, name) {
    private val decoder = MobileHdlcDecoder()

    /** False once the user disconnects, so a deliberate teardown does not dial again. */
    private var wantsConnection = false
        set(value) {
            field = value
            if (!value) lastProblem = null
        }

    /**
     * Why the standing attempt has not worked yet, reported with every
     * dial, so the reason stays on screen through the retries rather than
     * flashing away and back every two seconds.
     */
    private var lastProblem: RadioTransportProblem? = null

    /** Which dial a thread's report belongs to; bumped by every teardown. */
    private var dial = 0L

    /** The socket being dialed or carrying frames; null with none. */
    private var socket: Socket? = null

    /** The socket is open and the session has been told. */
    private var open = false

    /** Writes for the open socket, in order, off the executor. */
    private var writer: ExecutorService? = null

    private var redialScheduled = false

    /** What the transport calls the radio: its own name once known, else the endpoint. */
    private val transportName: String get() = radioName ?: endpoint.text

    init {
        adopt()
        post { reportTransport(MobileRadioTransportPhase.IDLE, name = null) }
    }

    override fun startLink(userInitiated: Boolean) {
        if (userInitiated) AppLog.i(TAG, "action: connect to bridged radio")
        wantsConnection = true
        if (socket == null) startDialing()
    }

    override fun stopLink() {
        wantsConnection = false
        teardown(problem = null, reporting = true)
    }

    override fun linkSend(frame: ByteArray, rawTransactionId: UByte?) {
        val writer = writer?.takeIf { open } ?: return
        val wire = try {
            ulcpHdlcEncode(frame)
        } catch (_: MobileException) {
            reportFault(RadioTransportProblem.UnsendableFrame.problem)
            return
        }
        val stream = socket?.getOutputStream() ?: return
        val dial = dial
        try {
            writer.execute {
                try {
                    stream.write(wire)
                    stream.flush()
                } catch (error: IOException) {
                    // A stream has no per-write recovery worth modeling: if
                    // the socket refused a frame, the link is gone, and the
                    // driver fails every outstanding ticket with it.
                    post { if (dial == this.dial) teardown(RadioTransportProblem.BridgeFailed, error) }
                }
            }
        } catch (_: RejectedExecutionException) {
            // The socket is being torn down.
        }
    }

    override fun linkResetFraming() {
        decoder.reset()
    }

    override fun linkInvalidate(retrying: Boolean) {
        // Giving up stops the redial as well, or a fault left standing would
        // reconnect to a radio the driver has just declared unusable, every
        // two seconds, for as long as the app runs.
        if (!retrying) wantsConnection = false
        teardown(problem = null, reporting = true)
    }

    override fun linkAbandonBinding() {
        wantsConnection = false
    }

    override fun linkDidEnterDfu() {
        wantsConnection = false
        teardown(problem = null, reporting = true)
    }

    private fun startDialing() {
        val socket = Socket()
        this.socket = socket
        open = false
        val dial = ++dial
        reportTransport(MobileRadioTransportPhase.CONNECTING, transportName, lastProblem?.problem)
        Thread({ run(socket, dial) }, "umsh-radio-tcp-io").apply { isDaemon = true }.start()
    }

    /** On the socket's own thread: dial, then read until the socket ends. */
    private fun run(socket: Socket, dial: Long) {
        // Attributes the socket's traffic to the bridged radio. The JVM tests'
        // Android stubs have no TrafficStats; tagging is only bookkeeping.
        runCatching { TrafficStats.setThreadStatsTag(TRAFFIC_TAG) }
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(endpoint.host, endpoint.port), CONNECT_TIMEOUT_MS)
        } catch (error: IOException) {
            // Refused is the bridge not started yet, or restarted by hand.
            val problem = if (error is ConnectException) {
                RadioTransportProblem.BridgeWaiting
            } else {
                RadioTransportProblem.BridgeUnreachable
            }
            post { if (dial == this.dial) teardown(problem, error) }
            return
        }
        post { if (dial == this.dial) opened(socket) }
        val buffer = ByteArray(READ_SIZE)
        try {
            val input = socket.getInputStream()
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                val chunk = buffer.copyOf(count)
                // A stream hands over arbitrary chunks: one read may complete
                // none, one or several frames.
                post { if (dial == this.dial) received(chunk) }
            }
            // The bridge closing the socket is a detach.
            post { if (dial == this.dial) teardown(RadioTransportProblem.BridgeClosed) }
        } catch (error: IOException) {
            post { if (dial == this.dial) teardown(RadioTransportProblem.BridgeFailed, error) }
        }
    }

    private fun opened(socket: Socket) {
        if (this.socket !== socket) return
        AppLog.i(TAG, "bridged radio connected")
        open = true
        lastProblem = null
        decoder.reset()
        writer = Executors.newSingleThreadExecutor { Thread(it, "umsh-radio-tcp-write").apply { isDaemon = true } }
        // The endpoint names exactly one radio, so whatever answers is the bound one.
        reportLinkReady(boundRadio = true)
    }

    private fun received(chunk: ByteArray) {
        if (!open) return
        for (frame in decoder.push(chunk)) reportReceived(frame)
    }

    /**
     * Drop the socket, report where that leaves the radio, and dial again
     * unless the user asked to be disconnected. [reporting] reports even
     * with no socket to drop: the driver asked for this teardown and
     * settles its fault on the report.
     */
    private fun teardown(problem: RadioTransportProblem?, error: Exception? = null, reporting: Boolean = false) {
        if (error != null) AppLog.w(TAG, "bridged radio: ${error.javaClass.simpleName}")
        val hadSocket = socket != null
        val wasOpen = open
        dial += 1
        socket?.let { runCatching { it.close() } }
        socket = null
        open = false
        writer?.shutdownNow()
        writer = null
        decoder.reset()
        if (problem != null && wantsConnection) lastProblem = problem

        if (hadSocket || reporting) {
            if (wantsConnection) {
                // The redial is part of the same standing attempt: one steady
                // state, Connecting and why not yet, rather than flapping
                // through disconnected and back on every retry.
                reportTransport(MobileRadioTransportPhase.CONNECTING, transportName, lastProblem?.problem)
            } else {
                reportTransport(MobileRadioTransportPhase.IDLE, transportName, problem?.problem)
            }
        }
        if (wasOpen) linkDropped()

        if (!wantsConnection || redialScheduled) return
        redialScheduled = true
        postDelayed(RETRY_DELAY_MS) {
            redialScheduled = false
            if (wantsConnection && socket == null && !isClosed) startDialing()
        }
    }

    private companion object {
        const val TAG = "umsh.radio"

        /** Short: the usual cause is the bridge being restarted by hand while the app watches. */
        const val RETRY_DELAY_MS = 2_000L
        const val CONNECT_TIMEOUT_MS = 5_000
        const val READ_SIZE = 4_096
        const val TRAFFIC_TAG = 0x554D5348 // "UMSH"
    }
}

/** Debug builds: a bridged radio. */
fun bridgedRadioConnection(radio: BoundRadio, registry: RadioRegistry, events: RadioConnectionEvents): RadioConnection? =
    TcpEndpoint.parse(radio.linkId)?.let { TcpRadioConnection(it, registry, events, radio.name) }
