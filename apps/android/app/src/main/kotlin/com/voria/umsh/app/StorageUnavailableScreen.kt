package com.voria.umsh.app

import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.designsystem.UnavailableParagraph
import com.voria.umsh.designsystem.UnavailablePage

/**
 * Storage unavailable (`storage-unavailable.svg`): the store will not open.
 * Outranks onboarding. [detail] is `StoreDetail`'s diagnostic line, not
 * translated. Android's Clear storage leads to Manage space, not a wipe.
 * [actions]: debug builds' way out of a staging store that will not open.
 */
@Composable
fun StorageUnavailableScreen(detail: String, actions: @Composable ColumnScope.() -> Unit = {}) {
    UnavailablePage(
        title = stringResource(R.string.storage_unavailable_title),
        paragraphs = listOf(
            UnavailableParagraph(stringResource(R.string.storage_unavailable_body)),
            UnavailableParagraph(stringResource(R.string.storage_unavailable_intact), emphasized = true),
            UnavailableParagraph(stringResource(R.string.storage_unavailable_advice)),
        ),
        detail = detail,
        modifier = Modifier.testTag(Tags.STORAGE_UNAVAILABLE),
        actions = actions,
    )
}
