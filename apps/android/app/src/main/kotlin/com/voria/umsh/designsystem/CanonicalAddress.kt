package com.voria.umsh.designsystem

import androidx.compose.foundation.clickable
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.LineBreak
import androidx.compose.ui.text.style.TextAlign
import com.voria.umsh.R

/**
 * A node's full address, all 44 characters, in groups of four that wrap
 * like words, balanced across the lines (`identity.svg`: six groups and five
 * on a phone held upright).
 * Tapping copies it with no spaces. Never truncated, never abbreviated.
 */
@Composable
fun CanonicalAddress(
    address: String,
    modifier: Modifier = Modifier,
    textAlign: TextAlign = TextAlign.Center,
    color: Color = MaterialTheme.colorScheme.onSurfaceVariant,
) {
    val copier = rememberCopier()
    Text(
        text = identifierAnnotated(AddressGrouping.grouped(address), monospace = false),
        // The minimum size inside the clickable, so the target it reports
        // (and its ripple) is 48 dp even when the address fits two lines.
        modifier = modifier
            .clickable(onClickLabel = stringResource(R.string.action_copy_address)) {
                copier.copy(address, R.string.copied_address)
            }
            .minimumInteractiveComponentSize(),
        // Balanced, so the eleven groups split six and five rather than
        // leaving one group alone on the second line.
        style = IdentifierTextStyle.copy(
            lineBreak = LineBreak(LineBreak.Strategy.Balanced, LineBreak.Strictness.Strict, LineBreak.WordBreak.Default),
        ),
        color = if (color == Color.Unspecified) LocalContentColor.current else color,
        textAlign = textAlign,
    )
}

object AddressGrouping {
    /** [address] in groups of four separated by spaces; the copy carries none. */
    fun grouped(address: String): String = address.chunked(4).joinToString(" ")
}
