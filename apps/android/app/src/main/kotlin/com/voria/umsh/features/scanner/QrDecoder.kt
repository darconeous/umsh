package com.voria.umsh.features.scanner

import com.google.zxing.BinaryBitmap
import com.google.zxing.ChecksumException
import com.google.zxing.DecodeHintType
import com.google.zxing.FormatException
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * One camera frame's brightness: the Y plane, [width] × [height] pixels,
 * each row [rowStride] bytes apart (a row may carry padding past [width]).
 */
class LuminanceFrame(val data: ByteArray, val width: Int, val height: Int, val rowStride: Int) {
    init {
        require(rowStride >= width) { "row stride $rowStride under width $width" }
        require(data.size >= rowStride * (height - 1) + width) { "frame data too short" }
    }
}

/**
 * Reads one QR code from a frame with ZXing core (D5). A QR code's finder
 * patterns read in any orientation, so the frame is decoded as the sensor
 * delivers it, never rotated first. Not thread-safe: one per analyzer.
 */
class QrDecoder {
    private val reader = QRCodeReader()

    /** The code's text, or null when the frame holds no readable QR code. */
    fun decode(frame: LuminanceFrame): String? {
        // Rows are [rowStride] apart: the source is told the buffer's real width and crops to the picture.
        val source = PlanarYUVLuminanceSource(
            frame.data,
            frame.rowStride,
            frame.height,
            0,
            0,
            frame.width,
            frame.height,
            false,
        )
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), HINTS).text
        } catch (_: NotFoundException) {
            null
        } catch (_: ChecksumException) {
            null
        } catch (_: FormatException) {
            null
        } finally {
            reader.reset()
        }
    }

    private companion object {
        val HINTS = mapOf(DecodeHintType.TRY_HARDER to true)
    }
}
