package com.voria.umsh.designsystem

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags

/** One paragraph of an unavailable page; [emphasized] reads as the line that matters. */
data class UnavailableParagraph(val text: String, val emphasized: Boolean = false)

/**
 * A page that replaces the whole app (`storage-unavailable.svg`): no
 * navigation, radio control or banner, since anything that looked like the
 * normal app would read as the data being gone. An icon, a title, the
 * paragraphs, then the diagnostic [detail] in a selectable monospace block
 * with Copy details. Scrolls at large font scales.
 */
@Composable
fun UnavailablePage(
    title: String,
    paragraphs: List<UnavailableParagraph>,
    detail: String?,
    modifier: Modifier = Modifier,
    actions: @Composable ColumnScope.() -> Unit = {},
) {
    val copier = rememberCopier()
    Box(
        modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            Modifier
                .widthIn(max = 560.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Spacer(Modifier.height(32.dp))
            Box(
                Modifier
                    .size(72.dp)
                    .background(MaterialTheme.colorScheme.errorContainer, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    painterResource(R.drawable.ic_error),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(32.dp),
                )
            }
            Text(
                title,
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.semantics { heading() }.testTag(Tags.UNAVAILABLE_TITLE),
            )
            paragraphs.forEach { paragraph ->
                Text(
                    paragraph.text,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (paragraph.emphasized) FontWeight.SemiBold else null,
                    color = if (paragraph.emphasized) {
                        MaterialTheme.colorScheme.onSurface
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    textAlign = TextAlign.Center,
                )
            }
            if (detail != null) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                ) {
                    SelectionContainer {
                        Text(
                            identifierAnnotated(detail),
                            style = IdentifierTextStyle,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(12.dp).testTag(Tags.UNAVAILABLE_DETAIL),
                        )
                    }
                }
                TextButton(
                    onClick = { copier.copy(detail, R.string.details_copied) },
                    modifier = Modifier.testTag(Tags.UNAVAILABLE_COPY),
                ) {
                    Text(stringResource(R.string.copy_details))
                }
            }
            actions()
        }
    }
}
