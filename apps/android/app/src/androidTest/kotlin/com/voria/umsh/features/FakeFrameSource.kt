package com.voria.umsh.features

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.voria.umsh.features.scanner.CameraStatus
import com.voria.umsh.features.scanner.FrameSource
import com.voria.umsh.features.scanner.LuminanceFrame
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * A camera for the scanner's tests: while the scanner shows it, it hands
 * the scanner's analysis [frame] (a code the test drew, or a blank frame)
 * about every 30 ms on a background thread, as CameraX would, and draws the
 * same frame as the viewfinder's picture. [status] is what it reports; each
 * bind (a new attempt) is counted in [binds].
 */
class FakeFrameSource(private val hasFlash: Boolean = true) : FrameSource {
    val frame = MutableStateFlow<LuminanceFrame?>(null)
    val status = MutableStateFlow<CameraStatus?>(null)
    val binds = AtomicInteger(0)
    val analyzed = AtomicInteger(0)

    /** False draws the frame without handing it to the scanner: a code held still for a picture. */
    @Volatile var feeding = true

    /** The code [text], drawn dark on a pale ground; null shows a blank frame. */
    fun show(text: String?) {
        frame.value = text?.let(::codeFrame) ?: blank()
    }

    @Composable
    override fun Viewfinder(
        torchOn: Boolean,
        attempt: Int,
        onFrame: (LuminanceFrame) -> Unit,
        onStatus: (CameraStatus) -> Unit,
        modifier: Modifier,
    ) {
        val frameNow by rememberUpdatedState(onFrame)
        LaunchedEffect(attempt) {
            binds.incrementAndGet()
            status.collect { onStatus(it ?: CameraStatus.Open(hasFlash)) }
        }
        LaunchedEffect(attempt) {
            withContext(Dispatchers.Default) {
                while (isActive) {
                    frame.value?.takeIf { feeding }?.let {
                        frameNow(it)
                        analyzed.incrementAndGet()
                    }
                    delay(FRAME_MS)
                }
            }
        }
        val shown by frame.collectAsState()
        val picture = remember(shown) { shown?.let(::bitmap)?.asImageBitmap() }
        Box(modifier.background(Color(0xFF3A3530)), contentAlignment = Alignment.Center) {
            picture?.let { Image(it, contentDescription = null, contentScale = ContentScale.Crop, filterQuality = FilterQuality.None) }
        }
    }

    companion object {
        const val FRAME_MS = 30L
        private const val SIDE = 480
        private const val CODE = 300

        /** A 480 × 480 frame with [text]'s QR code in its middle, on a warm pale card, as a phone held up to it. */
        fun codeFrame(text: String): LuminanceFrame {
            val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, CODE, CODE, mapOf(EncodeHintType.MARGIN to 2))
            val data = ByteArray(SIDE * SIDE) { 0x60 }
            val left = (SIDE - CODE) / 2
            for (y in 0 until SIDE) {
                for (x in 0 until SIDE) {
                    val inCard = x in 70 until SIDE - 70 && y in 70 until SIDE - 70
                    if (inCard) data[y * SIDE + x] = 0xE8.toByte()
                }
            }
            for (y in 0 until matrix.height) {
                for (x in 0 until matrix.width) {
                    if (matrix[x, y]) data[(left + y) * SIDE + left + x] = 0x18
                }
            }
            return LuminanceFrame(data, SIDE, SIDE, SIDE)
        }

        fun blank(): LuminanceFrame = LuminanceFrame(ByteArray(SIDE * SIDE) { 0x60 }, SIDE, SIDE, SIDE)

        private fun bitmap(frame: LuminanceFrame): Bitmap {
            val pixels = IntArray(frame.width * frame.height) { index ->
                val y = index / frame.width
                val x = index % frame.width
                val l = frame.data[y * frame.rowStride + x].toInt() and 0xFF
                (0xFF shl 24) or (l shl 16) or (l shl 8) or l
            }
            return Bitmap.createBitmap(pixels, frame.width, frame.height, Bitmap.Config.ARGB_8888)
        }
    }
}
