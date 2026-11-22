package com.voria.umsh.designsystem

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.services.format.AndroidCollation
import com.voria.umsh.services.format.Collation

/**
 * The words and the order names are shown in, for a list's ViewModel: from
 * the screen, since a locale change keeps the ViewModel but not the tree.
 */
data class ListEnvironment(val names: DisplayNames, val collation: Collation)

/** This tree's [ListEnvironment]. */
@Composable
fun rememberListEnvironment(): ListEnvironment {
    val names = rememberDisplayNames()
    val collation = rememberCollation()
    return remember(names, collation) { ListEnvironment(names, collation) }
}

/** [DisplayNames] with this tree's words for the fallbacks. */
@Composable
fun rememberDisplayNames(): DisplayNames {
    val unnamed = stringResource(R.string.unnamed_node)
    val radio = stringResource(R.string.companion_radio)
    val private = stringResource(R.string.channel_private)
    val public = stringResource(R.string.channel_public)
    val emergency = stringResource(R.string.channel_emergency)
    return remember(unnamed, radio, private, public, emergency) {
        DisplayNames(unnamed, radio, private, public, emergency)
    }
}

/** How names sort in this tree's locale. */
@Composable
fun rememberCollation(): Collation {
    val locale = LocalConfiguration.current.locales[0]
    return remember(locale) { AndroidCollation(locale) }
}
