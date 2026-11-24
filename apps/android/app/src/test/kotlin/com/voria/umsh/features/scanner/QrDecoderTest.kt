package com.voria.umsh.features.scanner

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.features.peers.ImportFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The scanner's decoding and its rules, with no camera: ZXing encodes a
 * code, it is drawn into a camera-like luminance frame, and the decoder and
 * analyzer read it back. The links are the core's own.
 */
class QrDecoderTest {
    private val node = nodeUriForAddress(ImportFixtures.address(0x61))

    @Test
    fun aDrawnCodeReadsBack() {
        assertEquals(node, QrDecoder().decode(QrFrames.of(node)))
    }

    @Test
    fun rowPaddingAndAnOffCenterCodeStillRead() {
        // A row stride past the width (as camera planes have), the code small and off to one side.
        val frame = QrFrames.of(node, width = 640, height = 480, rowStride = 704, codeSize = 260, left = 330, top = 40)
        assertEquals(node, QrDecoder().decode(frame))
    }

    @Test
    fun aFrameWithNoCodeReadsNothing() {
        assertNull(QrDecoder().decode(QrFrames.blank()))
    }

    @Test
    fun onlyUmshNodeCodesAreAccepted() {
        val signed = ImportFixtures.signedLink(0x62).link
        assertEquals(ScanVerdict.Accepted(node), ScanCheck.check(node))
        assertEquals(ScanVerdict.Accepted(signed), ScanCheck.check("  $signed\n"))
        assertEquals(ScanVerdict.Accepted("UMSH:n:${node.removePrefix("umsh:n:")}"), ScanCheck.check("UMSH:n:${node.removePrefix("umsh:n:")}"))
        // A bare address or key is a fine thing to type, but not a UMSH code.
        assertEquals(ScanVerdict.NotUmsh, ScanCheck.check(ImportFixtures.address(0x61)))
        assertEquals(ScanVerdict.NotUmsh, ScanCheck.check(ImportFixtures.hex(ImportFixtures.address(0x61))))
        assertEquals(ScanVerdict.NotUmsh, ScanCheck.check("https://example.org/"))
        assertEquals(ScanVerdict.NotUmsh, ScanCheck.check("umsh:n:not-a-key"))
        // Channel codes are taken when they read as a channel.
        assertEquals(ScanVerdict.Accepted("umsh:gs:ridge-runners"), ScanCheck.check("umsh:gs:ridge-runners"))
        assertEquals(ScanVerdict.NotUmsh, ScanCheck.check("umsh:gk:abc"))
    }

    @Test
    fun theFirstAcceptedCodeIsDeliveredOnce() {
        val analyzer = QrAnalyzer()
        val frame = QrFrames.of(node)
        analyzer.analyze(frame)
        assertEquals(node, analyzer.accepted.value)
        // The same code, and then another, in the frames after: still the first, once.
        val other = nodeUriForAddress(ImportFixtures.address(0x63))
        analyzer.analyze(frame)
        analyzer.analyze(QrFrames.of(other))
        assertEquals(node, analyzer.accepted.value)
        assertNull(analyzer.refusal.value)
    }

    @Test
    fun aRefusedCodeShowsUntilItHasLeftTheFrame() {
        var checks = 0
        val analyzer = QrAnalyzer(
            check = {
                checks++
                ScanCheck.check(it)
            },
            clearAfterFrames = 3,
        )
        val other = QrFrames.of("https://example.org/")
        analyzer.analyze(other)
        analyzer.analyze(other)
        assertEquals(ScanVerdict.NotUmsh, analyzer.refusal.value)
        // Checked once, however many frames hold it.
        assertEquals(1, checks)
        // A blurred frame or two does not clear it.
        analyzer.analyze(QrFrames.blank())
        analyzer.analyze(QrFrames.blank())
        assertEquals(ScanVerdict.NotUmsh, analyzer.refusal.value)
        analyzer.analyze(QrFrames.blank())
        assertNull(analyzer.refusal.value)
        assertNull(analyzer.accepted.value)

        analyzer.analyze(QrFrames.of("umsh:gk:abc"))
        assertEquals(ScanVerdict.NotUmsh, analyzer.refusal.value)
        // A node code after it is taken, and the pill goes.
        analyzer.analyze(QrFrames.of(node))
        assertEquals(node, analyzer.accepted.value)
        assertNull(analyzer.refusal.value)
    }
}

/** Camera-like frames for the scanner's tests: a QR code drawn dark on light into a Y plane. */
object QrFrames {
    fun of(
        text: String,
        width: Int = 480,
        height: Int = 480,
        rowStride: Int = width,
        codeSize: Int = 360,
        left: Int = (width - codeSize) / 2,
        top: Int = (height - codeSize) / 2,
    ): LuminanceFrame {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, codeSize, codeSize, mapOf(EncodeHintType.MARGIN to 2))
        val data = ByteArray(rowStride * height) { LIGHT }
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix[x, y]) data[(top + y) * rowStride + left + x] = DARK
            }
        }
        return LuminanceFrame(data, width, height, rowStride)
    }

    fun blank(width: Int = 480, height: Int = 480): LuminanceFrame = LuminanceFrame(ByteArray(width * height) { LIGHT }, width, height, width)

    private const val LIGHT: Byte = 0xE0.toByte()
    private const val DARK: Byte = 0x20
}
