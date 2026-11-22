package com.voria.umsh.features.map

import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar

/** The Map root: one full pane at every width. The map itself is Phase 4's. */
@Composable
fun MapScreen() {
    UmshScaffold(
        topBar = { UmshTopAppBar(stringResource(R.string.nav_map)) },
        modifier = Modifier.testTag(Tags.MAP_ROOT),
    ) { padding ->
        EmptyState(R.drawable.ic_map_outlined, text = null, modifier = Modifier.padding(padding))
    }
}
