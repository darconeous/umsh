package com.voria.umsh.features.settings

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.EraseIdentityDialog
import com.voria.umsh.designsystem.UnavailableParagraph
import com.voria.umsh.designsystem.UnavailablePage

/**
 * Identity unavailable (D11): Android's keystore is not ready to hand the
 * identity over. Nothing is lost and nothing is offered; the host tries
 * again the next time the app comes to the foreground.
 */
@Composable
fun IdentityUnavailableScreen() {
    UnavailablePage(
        title = stringResource(R.string.identity_unavailable_title),
        paragraphs = listOf(
            UnavailableParagraph(stringResource(R.string.identity_unavailable_body)),
            UnavailableParagraph(stringResource(R.string.identity_unavailable_intact), emphasized = true),
        ),
        detail = null,
        modifier = Modifier.testTag(Tags.IDENTITY_UNAVAILABLE),
    )
}

/**
 * Identity lost (D11): a secret is stored and can never be opened again.
 * Like Storage unavailable, with [detail] (diagnostic) to copy, and Erase
 * identity, which goes through the host's one erase and comes back at
 * Welcome with a new identity. Never minted over silently. [onErase] is
 * null, and the button left out, while staging is on (D16).
 */
@Composable
fun IdentityLostScreen(detail: String, onErase: (() -> Unit)?) {
    var confirming by rememberSaveable { mutableStateOf(false) }
    UnavailablePage(
        title = stringResource(R.string.identity_lost_title),
        paragraphs = listOf(
            UnavailableParagraph(stringResource(R.string.identity_lost_body)),
            UnavailableParagraph(stringResource(R.string.identity_lost_intact), emphasized = true),
            UnavailableParagraph(stringResource(R.string.identity_lost_advice)),
        ),
        detail = detail,
        modifier = Modifier.testTag(Tags.IDENTITY_LOST),
    ) {
        // Null while staging is on: staging never erases the live identity (D16).
        if (onErase == null) return@UnavailablePage
        OutlinedButton(
            onClick = { confirming = true },
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            modifier = Modifier.padding(top = 8.dp).testTag(Tags.IDENTITY_LOST_ERASE),
        ) {
            Text(stringResource(R.string.erase_identity))
        }
    }
    if (confirming) {
        EraseIdentityDialog(
            onConfirm = {
                confirming = false
                onErase?.invoke()
            },
            onDismiss = { confirming = false },
        )
    }
}
