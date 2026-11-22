package com.voria.umsh.features.settings

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.CanonicalAddress
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.rememberCopier
import com.voria.umsh.models.LocalIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The QR code sheet (`identity.svg` board 3): a large code, always dark on
 * white, the name and the address; Copy link and Share carry the same
 * `umsh:` link, which is never printed.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IdentityQrSheet(identity: LocalIdentity, link: String?, onDismiss: () -> Unit) {
    // Opened whole: a half-open sheet leaves Copy link and Share, and the
    // notice drawn above them, below the screen's edge on a short phone.
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, modifier = Modifier.testTag(Tags.QR_SHEET)) {
        // The sheet's window covers the shell's snackbar host: its copy
        // notices (Copy link, and the address) are drawn in the sheet.
        NoticeHost(Modifier.fillMaxWidth()) { QrSheetContent(identity, link) }
    }
}

@Composable
private fun QrSheetContent(identity: LocalIdentity, link: String?) {
    val copier = rememberCopier()
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
            .padding(bottom = 24.dp)
            .navigationBarsPadding(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        QrCode(link)
        if (identity.advertisedName.isNotEmpty()) {
            Text(identity.advertisedName, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        }
        CanonicalAddress(identity.address)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { link?.let { copier.copy(it, R.string.link_copied) } },
                enabled = link != null,
                modifier = Modifier.testTag(Tags.QR_COPY_LINK),
            ) {
                Text(stringResource(R.string.copy_link))
            }
            FilledTonalButton(
                onClick = { link?.let { shareLink(context, it) } },
                enabled = link != null,
                modifier = Modifier.testTag(Tags.QR_SHARE),
            ) {
                Text(stringResource(R.string.identity_share))
            }
        }
    }
}

/** Level M, dark on white in both appearances, with a quiet zone of four modules. */
@Composable
private fun QrCode(link: String?) {
    val matrix by produceState<BitMatrix?>(null, link) {
        value = link?.let { withContext(Dispatchers.Default) { encode(it) } }
    }
    val description = stringResource(R.string.identity_qr_description)
    Box(
        Modifier
            .size(QR_SIZE)
            .background(Color.White, MaterialTheme.shapes.medium)
            .semantics { contentDescription = description }
            .testTag(Tags.QR_IMAGE),
        contentAlignment = Alignment.Center,
    ) {
        matrix?.let { code ->
            Canvas(Modifier.size(QR_SIZE)) {
                val modules = code.width + QUIET_ZONE * 2
                val cell = size.minDimension / modules
                for (y in 0 until code.height) {
                    for (x in 0 until code.width) {
                        if (code[x, y]) {
                            drawRect(
                                Color.Black,
                                topLeft = Offset((x + QUIET_ZONE) * cell, (y + QUIET_ZONE) * cell),
                                // A hair over one cell, so neighbors never show a seam.
                                size = Size(cell + 0.5f, cell + 0.5f),
                            )
                        }
                    }
                }
            }
        }
    }
}

internal fun encode(link: String): BitMatrix = QRCodeWriter().encode(
    link,
    BarcodeFormat.QR_CODE,
    0,
    0,
    mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 0),
)

/** The Android Sharesheet, with the link as plain text. */
fun shareLink(context: Context, link: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, link)
    }
    context.startActivity(Intent.createChooser(send, null))
}

private val QR_SIZE = 240.dp
private const val QUIET_ZONE = 4
