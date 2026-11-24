package com.voria.umsh.features.scanner

import android.content.Context
import android.content.pm.PackageManager
import androidx.camera.compose.CameraXViewfinder
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.CameraState
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.SurfaceRequest
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.Observer
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.Executors

/** Where the camera stands, as the scanner shows it. */
sealed interface CameraStatus {
    /** Binding, opening, or between CameraX's own retries: the viewfinder stays dark. */
    data object Opening : CameraStatus

    /**
     * Held by another app (or too many cameras open): the viewfinder stays
     * dark until CameraX opens the camera again by itself, once it is free.
     */
    data object InUse : CameraStatus

    /** Frames are coming; [hasFlash] offers the torch. */
    data class Open(val hasFlash: Boolean) : CameraStatus

    /**
     * Camera access is off: turned off in quick settings or disabled by
     * policy. The scanner shows the camera-off page with Allow camera,
     * which binds again and so raises Android's own unblock dialog.
     */
    data object AccessOff : CameraStatus

    /**
     * The camera cannot be used for any other reason: a critical CameraX
     * error other than [AccessOff], or no camera to bind at all. The
     * scanner says so plainly and offers to try again.
     */
    data object Unavailable : CameraStatus
}

/**
 * Where the scanner's frames come from: the camera through CameraX, or,
 * in tests, frames the test makes. [Viewfinder] draws what the camera sees,
 * hands each frame to [onFrame] on a background thread, follows [torchOn],
 * and reports the camera's [CameraStatus]. [attempt] changes to bind again.
 */
interface FrameSource {
    @Composable
    fun Viewfinder(
        torchOn: Boolean,
        attempt: Int,
        onFrame: (LuminanceFrame) -> Unit,
        onStatus: (CameraStatus) -> Unit,
        modifier: Modifier,
    )
}

/** The frame source the scanner uses; tests provide their own. */
val LocalFrameSource = staticCompositionLocalOf<FrameSource> { CameraXFrameSource }

/** Whether this phone has a camera at all; without one Scan is not offered (§3.9). */
fun interface CameraPresence {
    fun hasCamera(context: Context): Boolean
}

/** The scan actions' presence check; tests force it on. */
val LocalCameraPresence = staticCompositionLocalOf {
    CameraPresence { context -> context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
}

/**
 * The camera: a CameraX preview and an image analysis that keeps only the
 * latest frame, on an executor of its own, bound to the page's lifecycle
 * and unbound when the page goes. The back camera when there is one.
 */
object CameraXFrameSource : FrameSource {
    @Composable
    override fun Viewfinder(
        torchOn: Boolean,
        attempt: Int,
        onFrame: (LuminanceFrame) -> Unit,
        onStatus: (CameraStatus) -> Unit,
        modifier: Modifier,
    ) {
        val context = LocalContext.current
        val lifecycleOwner = LocalLifecycleOwner.current
        val frameNow by rememberUpdatedState(onFrame)
        val statusNow by rememberUpdatedState(onStatus)
        var surfaceRequest by remember { mutableStateOf<SurfaceRequest?>(null) }
        var camera by remember { mutableStateOf<Camera?>(null) }

        DisposableEffect(lifecycleOwner, attempt) {
            statusNow(CameraStatus.Opening)
            val executor = Executors.newSingleThreadExecutor()
            val preview = Preview.Builder().build().apply { setSurfaceProvider { request -> surfaceRequest = request } }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setResolutionSelector(
                    ResolutionSelector.Builder().setResolutionStrategy(ANALYSIS_RESOLUTION).build(),
                )
                .build()
            val copier = FrameCopier()
            analysis.setAnalyzer(executor) { image ->
                try {
                    frameNow(copier.frame(image))
                } finally {
                    image.close()
                }
            }
            var provider: ProcessCameraProvider? = null
            var disposed = false
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener(
                {
                    if (disposed) return@addListener
                    try {
                        val cameras = future.get()
                        provider = cameras
                        val selector = if (cameras.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                            CameraSelector.DEFAULT_BACK_CAMERA
                        } else {
                            CameraSelector.DEFAULT_FRONT_CAMERA
                        }
                        camera = cameras.bindToLifecycle(lifecycleOwner, selector, preview, analysis)
                    } catch (error: Exception) {
                        AppLog.w(TAG, "camera not bound: ${error.javaClass.simpleName}")
                        statusNow(CameraStatus.Unavailable)
                    }
                },
                ContextCompat.getMainExecutor(context),
            )
            onDispose {
                disposed = true
                provider?.unbind(preview, analysis)
                analysis.clearAnalyzer()
                executor.shutdown()
                camera = null
                surfaceRequest = null
            }
        }

        camera?.let { bound ->
            // Whether the camera is open now: it closes in the background,
            // and CameraX turns the torch off as it does.
            var opened by remember(bound) { mutableStateOf(false) }
            // The camera's own state. Camera access turned off is its own
            // state, since only that one Allow camera can fix; any other
            // critical error is the unavailable state. Another app holding
            // the camera (or too many open) leaves it bound: CameraX opens
            // it again by itself once it is free. Other recoverable errors
            // are part of opening.
            DisposableEffect(bound, lifecycleOwner) {
                val observer = Observer<CameraState> { state ->
                    val error = state.error
                    if (error != null) AppLog.i(TAG, "camera error ${error.code} (${error.type})")
                    opened = state.type == CameraState.Type.OPEN
                    statusNow(
                        when {
                            error?.code == CameraState.ERROR_CAMERA_DISABLED -> CameraStatus.AccessOff
                            error?.type == CameraState.ErrorType.CRITICAL -> CameraStatus.Unavailable
                            opened -> CameraStatus.Open(bound.cameraInfo.hasFlashUnit())
                            error?.code == CameraState.ERROR_CAMERA_IN_USE ||
                                error?.code == CameraState.ERROR_MAX_CAMERAS_IN_USE -> CameraStatus.InUse
                            else -> CameraStatus.Opening
                        },
                    )
                }
                bound.cameraInfo.cameraState.observe(lifecycleOwner, observer)
                onDispose { bound.cameraInfo.cameraState.removeObserver(observer) }
            }
            // The torch as asked, applied again each time the camera opens:
            // after a return from the background it is lit as the button says.
            LaunchedEffect(bound, torchOn, opened) {
                if (opened && bound.cameraInfo.hasFlashUnit()) bound.cameraControl.enableTorch(torchOn)
            }
        }
        surfaceRequest?.let { CameraXViewfinder(surfaceRequest = it, modifier = modifier) }
    }

    /** Enough for a code at arm's length, little enough to decode every frame. */
    private val ANALYSIS_RESOLUTION = ResolutionStrategy(
        android.util.Size(1280, 720),
        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
    )

    private const val TAG = "umsh.scanner"
}

/**
 * Copies an image's Y plane into a buffer it keeps, so the image can be
 * closed at once; the row stride comes with it. One per analyzer thread.
 */
private class FrameCopier {
    private var buffer = ByteArray(0)

    fun frame(image: ImageProxy): LuminanceFrame {
        val plane = image.planes[0]
        val source = plane.buffer.duplicate().apply { rewind() }
        val size = source.remaining()
        if (buffer.size < size) buffer = ByteArray(size)
        source.get(buffer, 0, size)
        return LuminanceFrame(buffer, image.width, image.height, plane.rowStride)
    }
}
