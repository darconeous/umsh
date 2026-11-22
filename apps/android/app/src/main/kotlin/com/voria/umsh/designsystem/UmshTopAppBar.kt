package com.voria.umsh.designsystem

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.voria.umsh.R
import com.voria.umsh.app.Tags

/**
 * The radio control as the shell draws it, or null where it is not in top
 * bars: on rail layouts it sits in the rail's header instead.
 */
val LocalTopBarRadioControl = compositionLocalOf<(@Composable () -> Unit)?> { null }

/**
 * The problem banner as the shell draws it, for a screen to place under its
 * top app bar; null on rail layouts, where the shell places it above both
 * panes, and when there is no problem.
 */
val LocalScreenBanner = compositionLocalOf<(@Composable () -> Unit)?> { null }

/**
 * Every in-shell screen's top app bar (`radio-control.svg`): Back on pushed
 * pages, the title, at most two actions, then the radio control at the very
 * end. On rail layouts the radio control is in the rail, not here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UmshTopAppBar(
    title: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {},
) {
    val radioControl = LocalTopBarRadioControl.current
    TopAppBar(
        title = title,
        modifier = modifier.testTag(Tags.TOP_APP_BAR),
        navigationIcon = {
            if (onBack != null) {
                IconButton(onClick = onBack, modifier = Modifier.testTag(Tags.TOP_BAR_BACK)) {
                    Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.action_back))
                }
            }
        },
        actions = {
            actions()
            radioControl?.let {
                it()
                // The pill ends 12 dp from the edge, as the drawn bar does.
                Spacer(Modifier.width(8.dp))
            }
        },
        colors = if (LocalInDetailCard.current) {
            TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent, scrolledContainerColor = Color.Transparent)
        } else {
            TopAppBarDefaults.topAppBarColors()
        },
    )
}

/** A top app bar whose title is one line of text. */
@Composable
fun UmshTopAppBar(
    title: String,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {},
) = UmshTopAppBar(
    title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
    modifier = modifier,
    onBack = onBack,
    actions = actions,
)

/**
 * A screen inside the shell: its top app bar, then (on a phone) the
 * problem banner beneath it, pushing the content down.
 */
@Composable
fun UmshScaffold(
    topBar: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    floatingActionButton: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    val banner = LocalScreenBanner.current
    Scaffold(
        modifier = modifier,
        topBar = {
            Column {
                topBar()
                banner?.invoke()
            }
        },
        floatingActionButton = floatingActionButton,
        containerColor = if (LocalInDetailCard.current) Color.Transparent else MaterialTheme.colorScheme.background,
        content = content,
    )
}
