package com.voria.umsh.features.settings

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.features.share.ShareSheet
import com.voria.umsh.models.LocalIdentity

/**
 * The QR code sheet (`identity.svg` board 3, `share.svg` 4): this phone's
 * code, its name and address, Copy link and Share.
 */
@Composable
fun IdentityQrSheet(identity: LocalIdentity, link: String?, onDismiss: () -> Unit) = ShareSheet(
    address = identity.address,
    link = link,
    qrDescription = stringResource(R.string.identity_qr_description),
    onDismiss = onDismiss,
    title = identity.advertisedName,
)
