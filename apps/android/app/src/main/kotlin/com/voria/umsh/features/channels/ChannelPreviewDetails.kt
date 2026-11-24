package com.voria.umsh.features.channels

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ChannelBadge
import com.voria.umsh.designsystem.IdentifierText
import com.voria.umsh.designsystem.IdentifierTextStyle
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.channelTitle
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.models.ChannelPreview

/**
 * What a looked-up channel is (`channels.svg` 6–9, `qr-scanner.svg` 4):
 * its badge and name, public or a private invitation, its identifier, a
 * private invitation's key behind the eye, and the one fact a joiner
 * needs; or, instead of that fact, that it is joined already, or that
 * another channel has its name. [keyShown] is the page's own state, never
 * saved: a key revealed is hidden again after the page is recreated.
 */
@Composable
fun ChannelPreviewDetails(preview: ChannelPreview, keyShown: Boolean, onKeyShown: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    val channel = preview.summary
    Column(modifier.fillMaxWidth().testTag(Tags.CHANNEL_PREVIEW)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp).semantics(mergeDescendants = true) {},
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ChannelBadge(channel, size = AvatarSize.List, describe = false)
            Column {
                Text(
                    channelTitle(channel),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.semantics { heading() }.testTag(Tags.CHANNEL_PREVIEW_NAME),
                )
                Text(
                    stringResource(if (preview.isPrivate) R.string.channel_preview_private else R.string.channel_preview_public),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(Tags.CHANNEL_PREVIEW_KIND),
                )
            }
        }
        ValueRow(stringResource(R.string.channel_identifier)) {
            IdentifierText(preview.channelIdHex, style = IdentifierTextStyle, modifier = Modifier.testTag(Tags.CHANNEL_PREVIEW_IDENTIFIER))
        }
        if (preview.isPrivate) KeyRow(preview, keyShown, onKeyShown)
        val conflict = preview.nameConflict
        when {
            preview.alreadyJoined -> AlreadyJoined(channelTitle(checkNotNull(preview.existing)))
            conflict != null -> NameConflict(channelTitle(conflict))
            else -> Text(
                stringResource(if (preview.isPrivate) R.string.channel_preview_private_line else R.string.channel_preview_public_line),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.CHANNEL_PREVIEW_LINE),
            )
        }
    }
}

/** A label, and its value at the end of the row. */
@Composable
private fun ValueRow(label: String, value: @Composable () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 16.dp).semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        value()
    }
}

/**
 * Channel key, dots until the eye shows it. The key is only ever in this
 * page's state: never saved, logged or restored.
 */
@Composable
private fun KeyRow(preview: ChannelPreview, shown: Boolean, onShown: (Boolean) -> Unit) {
    val hiddenState = stringResource(R.string.channel_key_hidden)
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(start = 16.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.channel_key), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            if (!shown) {
                Text(
                    KEY_DOTS,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.semantics { contentDescription = hiddenState }.testTag(Tags.CHANNEL_KEY_DOTS),
                )
            }
            IconButton(onClick = { onShown(!shown) }, modifier = Modifier.testTag(Tags.CHANNEL_KEY_EYE)) {
                Icon(
                    painterResource(if (shown) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                    contentDescription = stringResource(if (shown) R.string.channel_key_hide else R.string.channel_key_show),
                )
            }
        }
        if (shown) {
            IdentifierText(
                preview.key.hex(),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp).padding(bottom = 8.dp).testTag(Tags.CHANNEL_KEY_VALUE),
            )
        }
    }
}

/** Board 8: the same key already held; Join becomes Update. */
@Composable
private fun AlreadyJoined(title: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).semantics(mergeDescendants = true) {}.testTag(Tags.CHANNEL_PREVIEW_JOINED)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(painterResource(R.drawable.ic_check_circle), contentDescription = null, tint = UmshColors.fixed.connected, modifier = Modifier.size(20.dp))
            Text(stringResource(R.string.channel_already_joined, userIsolated(title)), style = MaterialTheme.typography.bodyLarge)
        }
        Text(
            stringResource(R.string.channel_already_joined_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

/** Board 9: a different key under a name already in use; the note only suggests another name. */
@Composable
private fun NameConflict(title: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .background(MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.shapes.medium)
            .padding(16.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.CHANNEL_PREVIEW_CONFLICT),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(
                painterResource(R.drawable.ic_info),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.size(20.dp),
            )
            Column {
                Text(
                    stringResource(R.string.channel_name_conflict, userIsolated(title)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                )
                Text(
                    stringResource(R.string.channel_name_conflict_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

/** Eight dots: the key's length is not told. */
private const val KEY_DOTS = "••••••••"
