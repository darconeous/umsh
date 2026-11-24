package com.voria.umsh.features.channels

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FAB_CLEARANCE
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.models.ChannelSummary

/**
 * Settings › Channels (`channels.svg` 1–3): every channel this phone has
 * joined, with its badge, kind and identifier, and the bell when it does
 * not notify. The radio's own channels are not here. A row opens the
 * channel's page ([onOpen]); a long press offers Leave channel. Add
 * channel opens a menu of the two ways in; an empty list offers both.
 *
 * [onBack] is null beside the Settings list, where there is no Back.
 */
@Composable
fun ChannelsScreen(
    onBack: (() -> Unit)?,
    onOpen: (String) -> Unit,
    onJoin: () -> Unit,
    onCreate: () -> Unit,
) {
    val viewModel = runtimeViewModel { ChannelsViewModel(it) }
    val channels by viewModel.channels.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    // The menu and the confirmation are kept across a rotation and process death; nothing is sent until confirmed.
    var menuOpen by rememberSaveable { mutableStateOf(false) }
    var leaving by rememberSaveable { mutableStateOf<String?>(null) }
    // The menu belongs to the Add channel button, drawn only over a list: an emptied list closes it.
    val hasList = !channels.isNullOrEmpty()
    val emptied = channels?.isEmpty() == true
    LaunchedEffect(emptied) { if (emptied) menuOpen = false }
    BackHandler(enabled = menuOpen && hasList) { menuOpen = false }

    DetailPane {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.channels_title), onBack = onBack) },
            modifier = Modifier.testTag(Tags.CHANNELS),
            floatingActionButton = {
                if (hasList) {
                    AddChannelMenu(
                        open = menuOpen,
                        onOpenChange = { menuOpen = it },
                        onJoin = {
                            menuOpen = false
                            onJoin()
                        },
                        onCreate = {
                            menuOpen = false
                            onCreate()
                        },
                    )
                }
            },
        ) { padding ->
            val shown = channels
            when {
                shown == null -> Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(Modifier.testTag(Tags.CHANNELS_LOADING))
                }
                shown.isEmpty() -> Empty(Modifier.padding(padding), onJoin, onCreate)
                else -> LazyColumn(
                    contentPadding = PaddingValues(
                        start = padding.calculateStartPadding(LocalLayoutDirection.current),
                        top = padding.calculateTopPadding(),
                        end = padding.calculateEndPadding(LocalLayoutDirection.current),
                        bottom = padding.calculateBottomPadding() + FAB_CLEARANCE,
                    ),
                    modifier = Modifier.fillMaxSize().testTag(Tags.CHANNELS_LIST),
                ) {
                    items(shown, key = { it.id }) { channel ->
                        ChannelListRow(
                            channel,
                            onOpen = { onOpen(channel.id) },
                            onLeave = {
                                menuOpen = false
                                leaving = channel.id
                            },
                        )
                    }
                }
            }
        }
    }

    leaving?.let { id ->
        val channel = channels?.firstOrNull { it.id == id }
        if (channel == null) {
            // Left already, or restored over a channel no longer joined.
            if (channels != null) leaving = null
        } else {
            LeaveChannelDialog(
                channel,
                onConfirm = {
                    leaving = null
                    viewModel.leave(id)
                },
                onDismiss = { leaving = null },
            )
        }
    }
    failure?.let { error ->
        FailureDialog(
            stringResource(R.string.channel_not_left_title),
            stringResource(R.string.channel_not_left_body),
            error,
            viewModel::dismissFailure,
        )
    }
}

/** A row: tap opens the page; long press offers Leave channel. */
@Composable
private fun ChannelListRow(channel: ChannelSummary, onOpen: () -> Unit, onLeave: () -> Unit) {
    var menuOpen by rememberSaveable(channel.id) { mutableStateOf(false) }
    Box {
        ChannelRowContent(
            channel,
            modifier = Modifier
                .combinedClickable(
                    onLongClickLabel = stringResource(R.string.channel_actions),
                    onLongClick = { menuOpen = true },
                    onClick = onOpen,
                )
                .semantics(mergeDescendants = true) {}
                .testTag(Tags.channelRow(channel.id)),
        )
        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }, modifier = Modifier.testTag(Tags.CHANNEL_MENU)) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.leave_channel), color = MaterialTheme.colorScheme.error) },
                onClick = {
                    menuOpen = false
                    onLeave()
                },
                modifier = Modifier.testTag(Tags.CHANNEL_MENU_LEAVE),
            )
        }
    }
}

/**
 * Add channel (board 2): the button opens the two ways in above it, as
 * iOS's plus menu does; the button then closes them.
 */
@Composable
private fun AddChannelMenu(open: Boolean, onOpenChange: (Boolean) -> Unit, onJoin: () -> Unit, onCreate: () -> Unit) {
    Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (open) {
            Button(onClick = onJoin, modifier = Modifier.testTag(Tags.CHANNELS_MENU_JOIN)) {
                Text(stringResource(R.string.join_channel))
            }
            Button(onClick = onCreate, modifier = Modifier.testTag(Tags.CHANNELS_MENU_CREATE)) {
                Text(stringResource(R.string.new_private_channel))
            }
            FloatingActionButton(onClick = { onOpenChange(false) }, shape = CircleShape, modifier = Modifier.testTag(Tags.CHANNELS_ADD)) {
                Icon(painterResource(R.drawable.ic_close), contentDescription = stringResource(R.string.action_close))
            }
        } else {
            ExtendedFloatingActionButton(
                text = { Text(stringResource(R.string.add_channel)) },
                // Material hides an icon-and-label FAB's label from TalkBack; the icon speaks it.
                icon = { Icon(painterResource(R.drawable.ic_add), contentDescription = stringResource(R.string.add_channel)) },
                onClick = { onOpenChange(true) },
                modifier = Modifier.testTag(Tags.CHANNELS_ADD),
            )
        }
    }
}

/** Board 3: what a channel is, and both ways in. */
@Composable
private fun Empty(modifier: Modifier, onJoin: () -> Unit, onCreate: () -> Unit) {
    Column(
        modifier.fillMaxSize().padding(horizontal = 24.dp).testTag(Tags.CHANNELS_EMPTY),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.channels_empty_title),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(R.string.channels_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        // Flows onto a second row on a narrow screen or with large text, so a label never splits.
        FlowRow(
            Modifier.padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(onClick = onJoin, modifier = Modifier.testTag(Tags.CHANNELS_EMPTY_JOIN)) {
                Text(stringResource(R.string.join_channel))
            }
            FilledTonalButton(onClick = onCreate, modifier = Modifier.testTag(Tags.CHANNELS_EMPTY_CREATE)) {
                Text(stringResource(R.string.new_private_channel))
            }
        }
    }
}
