package com.voria.umsh.features.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ScrollToTopOnReselect
import com.voria.umsh.app.Tags
import com.voria.umsh.app.debug.DeveloperSection
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.selectionBackground

/**
 * The Settings root (D4): the Identity section's Your identity row, and in
 * debug builds the Developer section. Channels and the batch-5 rows arrive
 * with their pages.
 */
@Composable
fun SettingsScreen(identitySelected: Boolean, onOpenIdentity: () -> Unit, reselects: Int) {
    val runtime = LocalAppRuntime.current
    val host = LocalAppCoreHost.current
    val identity by runtime.identity.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    ScrollToTopOnReselect(reselects, list)
    UmshScaffold(
        topBar = { UmshTopAppBar(stringResource(R.string.nav_settings)) },
        modifier = Modifier.testTag(Tags.SETTINGS_ROOT),
    ) { padding ->
        LazyColumn(state = list, contentPadding = padding, modifier = Modifier.testTag(Tags.SETTINGS_LIST)) {
            item { SectionHeader(stringResource(R.string.settings_section_identity)) }
            item {
                val name = identity.advertisedName
                ListItem(
                    headlineContent = { Text(name.ifEmpty { stringResource(R.string.your_identity) }) },
                    supportingContent = if (name.isNotEmpty()) {
                        { Text(stringResource(R.string.your_identity)) }
                    } else {
                        null
                    },
                    leadingContent = {
                        PeerAvatar(identity.hint, PeerAvatarShape.Circle, size = AvatarSize.List, describe = false)
                    },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    // Drawn only, as a selected conversation is: the content
                    // stays where it is when the row is selected.
                    modifier = Modifier
                        .selectionBackground(
                            identitySelected,
                            Color.Transparent,
                            MaterialTheme.colorScheme.secondaryContainer,
                            MaterialTheme.shapes.large,
                        )
                        .clickable(onClick = onOpenIdentity)
                        .testTag(Tags.SETTINGS_YOUR_IDENTITY),
                )
            }
            item { DeveloperSection(host, runtime) }
        }
    }
}
