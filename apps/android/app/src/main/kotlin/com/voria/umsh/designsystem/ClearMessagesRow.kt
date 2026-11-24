package com.voria.umsh.designsystem

import androidx.compose.foundation.clickable
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import com.voria.umsh.R

/**
 * Clear all messages, in red, on Conversation info and the peer page. One
 * rule for both: a page shows it whenever there is a conversation, and it
 * is dimmed and not clickable with [count] zero, as iOS does, and also
 * while not yet counted (null). [withIcon] draws the delete icon, as
 * Conversation info's board does; the peer page's row is text only.
 */
@Composable
fun ClearMessagesRow(count: Long?, withIcon: Boolean, tag: String, onClick: () -> Unit) {
    val enabled = count != null && count > 0
    val color = MaterialTheme.colorScheme.error
    ListItem(
        leadingContent = if (withIcon) {
            { Icon(painterResource(R.drawable.ic_delete), contentDescription = null, tint = color) }
        } else {
            null
        },
        headlineContent = { Text(stringResource(R.string.clear_all_messages), color = color) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .alpha(if (enabled) 1f else DISABLED_ALPHA)
            .testTag(tag),
    )
}

/** Material's disabled content opacity. */
private const val DISABLED_ALPHA = 0.38f
