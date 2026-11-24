package com.voria.umsh.features.scanner

import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.IconToggleButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.Tags

/** The scanner's analysis, kept across a rotation: a code accepted once is never delivered twice. */
class ScannerViewModel : ViewModel() {
    val analyzer = QrAnalyzer()
}

/**
 * The QR scanner (`qr-scanner.svg` 1–2, `permissions.svg` 2–3): a
 * full-bleed viewfinder, Close and the title above it, the torch below
 * when the camera has a flash. Only `umsh:` node codes close it
 * ([onScanned]); any other code is a pill that clears once the code leaves
 * the frame. The camera is asked for the first time the scanner opens; with
 * it refused, or the camera unavailable, the page says so, with Allow
 * camera. Always drawn dark, as a camera page is.
 */
@Composable
fun ScannerScreen(onClose: () -> Unit, onScanned: (String) -> Unit) {
    val context = LocalContext.current
    val viewModel = viewModel { ScannerViewModel() }
    val analyzer = viewModel.analyzer
    val accepted by analyzer.accepted.collectAsStateWithLifecycle()
    val refusal by analyzer.refusal.collectAsStateWithLifecycle()
    val scanned by rememberUpdatedState(onScanned)
    LaunchedEffect(accepted) { accepted?.let { scanned(it) } }

    // Checked again on every start: a one-time grant lapses, and the grant
    // can change in settings while the app is away.
    var granted by remember { mutableStateOf(CameraPermission.granted(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_START) { granted = CameraPermission.granted(context) }
    val asker = rememberCameraAsker(LocalAppCoreHost.current.preferences, onAnswered = { granted = CameraPermission.granted(context) })
    // Asked once, as the scanner first opens; not again on a rotation or a return.
    var askedOnOpen by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (!granted && !askedOnOpen) {
            askedOnOpen = true
            asker.askIfAskable()
        }
    }

    var status by remember { mutableStateOf<CameraStatus>(CameraStatus.Opening) }
    var attempt by remember { mutableIntStateOf(0) }
    var torchOn by rememberSaveable { mutableStateOf(false) }
    val frames = LocalFrameSource.current
    LightSystemBars()
    // A refusal says what is in the frame; with no frames coming (the
    // camera reopening, unavailable or refused) it is forgotten, not left
    // standing over a page it does not belong to.
    val open = (status as? CameraStatus.Open)?.takeIf { granted }
    LaunchedEffect(open != null) { if (open == null) analyzer.forgetRefusal() }

    Box(Modifier.fillMaxSize().background(Color.Black).testTag(Tags.SCANNER)) {
        when {
            granted && status != CameraStatus.Unavailable -> {
                val description = stringResource(R.string.scanner_viewfinder_description)
                frames.Viewfinder(
                    torchOn = torchOn,
                    attempt = attempt,
                    onFrame = analyzer::analyze,
                    onStatus = { status = it },
                    modifier = Modifier.fillMaxSize().semantics { contentDescription = description }.testTag(Tags.SCANNER_VIEWFINDER),
                )
                ScanFrame()
            }
            // Android's dialog is over the page (board 2): nothing beneath it yet.
            !granted && asker.asking -> Unit
            else -> CameraOff(
                onAllow = {
                    if (granted) {
                        // The camera was unavailable: try again, which raises
                        // Android's own unblock dialog when camera access is off.
                        status = CameraStatus.Opening
                        attempt++
                    } else {
                        asker.ask()
                    }
                },
            )
        }
        TopRow(onClose)
        if (open != null && refusal != null) RefusalPill()
        if (open?.hasFlash == true) {
            Torch(
                on = torchOn,
                onChange = { torchOn = it },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .windowInsetsPadding(WindowInsets.safeDrawing)
                    .padding(bottom = 32.dp),
            )
        }
    }
}

/** Close and the title, below the status bar and clear of any cutout; the bottom inset is the torch's. */
@Composable
private fun TopRow(onClose: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(Color.Black.copy(alpha = 0.55f))
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal))
            .heightIn(min = 64.dp)
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(
            onClick = onClose,
            colors = IconButtonDefaults.iconButtonColors(contentColor = Color.White),
            modifier = Modifier.testTag(Tags.SCANNER_CLOSE),
        ) {
            Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.action_close))
        }
        Text(
            stringResource(R.string.scanner_title),
            style = MaterialTheme.typography.titleLarge,
            color = Color.White,
            modifier = Modifier.padding(start = 8.dp).semantics { heading() },
        )
    }
}

/**
 * Where to hold the code: the picture dimmed outside a rounded square, with
 * a light outline around it. It says what to do without text.
 */
@Composable
private fun ScanFrame() {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val side = minOf(maxWidth, maxHeight) * 0.7f
        Canvas(Modifier.fillMaxSize().graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }) {
            val square = side.toPx()
            val topLeft = Offset((size.width - square) / 2, (size.height - square) / 2)
            val corner = CornerRadius(24.dp.toPx())
            drawRect(Color.Black.copy(alpha = 0.5f))
            drawRoundRect(Color.Transparent, topLeft, Size(square, square), corner, blendMode = BlendMode.Clear)
            drawRoundRect(Color.White.copy(alpha = 0.85f), topLeft, Size(square, square), corner, style = Stroke(2.dp.toPx()))
        }
    }
}

/** A code the scanner does not take (board 2), until it leaves the frame. Announced once, politely. */
@Composable
private fun RefusalPill() {
    val text = stringResource(R.string.scanner_not_umsh)
    BoxWithConstraints(Modifier.fillMaxSize()) {
        // Just below the frame's lower edge.
        val below = minOf(maxWidth, maxHeight) * 0.35f + 32.dp
        Surface(
            shape = CircleShape,
            color = Color.Black.copy(alpha = 0.8f),
            contentColor = Color.White,
            modifier = Modifier
                .align(Alignment.Center)
                .offset(y = below)
                .padding(horizontal = 24.dp)
                .semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite }
                .testTag(Tags.SCANNER_PILL),
        ) {
            Text(text, style = MaterialTheme.typography.labelLarge, textAlign = TextAlign.Center, modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp))
        }
    }
}

/** No camera to show (`permissions.svg` 3): why, and Allow camera. Close still leaves. */
@Composable
private fun CameraOff(onAllow: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp).testTag(Tags.SCANNER_CAMERA_OFF),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.scanner_camera_off),
            style = MaterialTheme.typography.bodyLarge,
            color = Color.White,
            textAlign = TextAlign.Center,
        )
        Button(onClick = onAllow, modifier = Modifier.testTag(Tags.SCANNER_ALLOW)) {
            Text(stringResource(R.string.scanner_allow_camera))
        }
    }
}

/** The torch (board 1): a round button that says whether it is on. */
@Composable
private fun Torch(on: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier) {
    val state = stringResource(if (on) R.string.scanner_torch_on else R.string.scanner_torch_off)
    Surface(shape = CircleShape, color = if (on) Color.White else Color.Black.copy(alpha = 0.6f), modifier = modifier.size(64.dp)) {
        IconToggleButton(
            checked = on,
            onCheckedChange = onChange,
            colors = IconButtonDefaults.iconToggleButtonColors(contentColor = Color.White, checkedContentColor = Color.Black),
            modifier = Modifier.fillMaxSize().semantics { stateDescription = state }.testTag(Tags.SCANNER_TORCH),
        ) {
            Icon(painterResource(R.drawable.ic_bolt), contentDescription = stringResource(R.string.scanner_torch))
        }
    }
}

/** Light status and navigation bar icons over the black page, restored when it goes. */
@Composable
private fun LightSystemBars() {
    val view = LocalView.current
    val activity = LocalActivity.current
    DisposableEffect(view, activity) {
        val window = activity?.window ?: return@DisposableEffect onDispose { }
        val controller = WindowCompat.getInsetsController(window, view)
        val status = controller.isAppearanceLightStatusBars
        val navigation = controller.isAppearanceLightNavigationBars
        controller.isAppearanceLightStatusBars = false
        controller.isAppearanceLightNavigationBars = false
        onDispose {
            controller.isAppearanceLightStatusBars = status
            controller.isAppearanceLightNavigationBars = navigation
        }
    }
}
