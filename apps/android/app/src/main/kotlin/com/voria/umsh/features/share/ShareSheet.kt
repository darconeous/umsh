package com.voria.umsh.features.share

import android.content.Context
import android.content.Intent
import androidx.annotation.StringRes
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
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * A link to hand on (`identity.svg` 3, `share.svg` 1, `channels.svg` 13):
 * a large QR code, always dark on white, a node's [address] to compare by
 * eye (none for a channel), and Copy ([copy]) and Share, which carry the
 * same `umsh:` link; the link itself is never printed. [header] is drawn above the code (a peer's avatar and name),
 * [title] under it (this phone's name). [qrDescription] is what TalkBack
 * says of the code. Until [link] is known, the code is blank and the
 * buttons wait.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareSheet(
    address: String?,
    link: String?,
    qrDescription: String,
    onDismiss: () -> Unit,
    header: (@Composable () -> Unit)? = null,
    title: String? = null,
    copy: ShareCopy = ShareCopy.Link,
    /** Drawn above the code: what handing it on means (a private channel's invitation, `channels.svg` 13). */
    notice: (@Composable () -> Unit)? = null,
) {
    // Opened whole: a half-open sheet leaves Copy link and Share, and the
    // notice drawn above them, below the screen's edge on a short phone.
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, modifier = Modifier.testTag(Tags.QR_SHEET)) {
        // The sheet's window covers the shell's snackbar host: its copy
        // notices (Copy link, and the address) are drawn in the sheet.
        NoticeHost(Modifier.fillMaxWidth()) { ShareSheetContent(address, link, qrDescription, header, title, copy, notice) }
    }
}

@Composable
private fun ShareSheetContent(
    address: String?,
    link: String?,
    qrDescription: String,
    header: (@Composable () -> Unit)?,
    title: String?,
    copy: ShareCopy,
    notice: (@Composable () -> Unit)?,
) {
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
        header?.invoke()
        notice?.invoke()
        QrCode(link, qrDescription)
        if (!title.isNullOrEmpty()) {
            Text(title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        }
        address?.let { CanonicalAddress(it) }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { link?.let { copier.copy(it, copy.copied, sensitive = copy.sensitive) } },
                enabled = link != null,
                modifier = Modifier.testTag(Tags.QR_COPY_LINK),
            ) {
                Text(stringResource(copy.label))
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

/** Copy's words, its notice on 12 and earlier, and whether the clip is marked sensitive. */
enum class ShareCopy(@param:StringRes val label: Int, @param:StringRes val copied: Int, val sensitive: Boolean) {
    /** A node's or a public channel's link: Copy link. */
    Link(R.string.copy_link, R.string.link_copied, false),

    /** A private channel's invitation, which is its key: Copy invitation, marked sensitive. */
    Invitation(R.string.copy_invitation, R.string.invitation_copied, true),
}

/** Level M, dark on white in both appearances, with a quiet zone of four modules. */
@Composable
private fun QrCode(link: String?, description: String) {
    val matrix by produceState<BitMatrix?>(null, link) {
        value = link?.let { withContext(Dispatchers.Default) { encode(it) } }
    }
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
