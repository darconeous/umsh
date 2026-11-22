package com.voria.umsh.features.conversations

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ScrollToTopOnReselect
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.EmptyState
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.rememberListEnvironment
import com.voria.umsh.designsystem.userIsolated

/**
 * The Conversations root (`conversation-list.svg`): every conversation,
 * newest activity first, with Search in the top app bar. A swipe toward
 * the start, or the row's TalkBack action, asks before deleting a direct
 * conversation or leaving a channel's chat. Scan and New chat wait for
 * their pages (D5).
 *
 * [current] is whether the shell has the list as a page shown, not only
 * behind a back preview: only then may search take focus. [selected] is
 * the conversation shown beside the list, highlighted; [onOpen] opens one.
 * A thread showing a removed one is the shell's to close.
 */
@Composable
fun ConversationsScreen(
    current: Boolean,
    selected: String?,
    onOpen: (String) -> Unit,
    reselects: Int,
) {
    val runtime = LocalAppRuntime.current
    val environment = rememberListEnvironment()
    val viewModel = runtimeViewModel { ConversationsViewModel(it, environment) }
    LaunchedEffect(environment) { viewModel.setEnvironment(environment) }
    val content by viewModel.content.collectAsStateWithLifecycle()
    val searching by viewModel.searching.collectAsStateWithLifecycle()
    val query by viewModel.query.collectAsStateWithLifecycle()
    val results by viewModel.results.collectAsStateWithLifecycle()
    val pending by viewModel.pendingRemoval.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()

    val open by rememberUpdatedState(onOpen)
    LaunchedEffect(viewModel) { viewModel.opened.collect { open(it) } }

    val list = rememberLazyListState()
    ScrollToTopOnReselect(reselects, list)

    Box(Modifier.fillMaxSize()) {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(
                    stringResource(R.string.nav_conversations),
                    actions = {
                        IconButton(onClick = { viewModel.setSearching(true) }, modifier = Modifier.testTag(Tags.CONVERSATIONS_SEARCH)) {
                            Icon(painterResource(R.drawable.ic_search), contentDescription = stringResource(R.string.action_search))
                        }
                    },
                )
            },
            modifier = Modifier.testTag(Tags.CONVERSATIONS_ROOT),
        ) { padding ->
            when (val shown = content) {
                ConversationsContent.Loading -> Loading(Modifier.padding(padding))
                ConversationsContent.Empty -> Empty(Modifier.padding(padding))
                is ConversationsContent.Rows -> LazyColumn(
                    state = list,
                    contentPadding = padding,
                    modifier = Modifier.fillMaxSize().testTag(Tags.CONVERSATION_LIST),
                ) {
                    items(shown.rows, key = { it.address }) { row ->
                        SwipeToRemove(row.removal, onRemove = { viewModel.askToRemove(row.removal) }) {
                            ConversationRowItem(
                                row = row,
                                now = now,
                                selected = row.address == selected,
                                onOpen = { onOpen(row.address) },
                                onRemove = { viewModel.askToRemove(row.removal) },
                                modifier = Modifier.testTag(Tags.conversationRow(row.address)),
                            )
                        }
                    }
                }
            }
        }
        if (searching) {
            ConversationSearch(
                current = current,
                query = query,
                results = results,
                names = environment.names,
                now = now,
                onQueryChange = viewModel::setQuery,
                onClose = { viewModel.setSearching(false) },
                onOpenConversation = { address ->
                    viewModel.setSearching(false)
                    onOpen(address)
                },
                onOpenPeer = viewModel::open,
                onOpenChannel = viewModel::open,
            )
        }
    }

    pending?.let { removal -> RemovalDialog(removal, viewModel::confirmRemoval, viewModel::cancelRemoval) }
    failure?.let { shown ->
        val (title, body) = when (shown) {
            is ListFailure.NotRemoved -> when (shown.removal) {
                is Removal.Delete -> R.string.delete_failed_title
                is Removal.Leave -> R.string.leave_failed_title
            } to R.string.remove_failed_body
            is ListFailure.NotOpened -> R.string.open_failed_title to R.string.open_failed_body
        }
        FailureDialog(stringResource(title), stringResource(body), shown.error, viewModel::dismissFailure)
    }
}

/** Board 8 (delete a direct conversation) and board 9 (leave a channel's chat). */
@Composable
private fun RemovalDialog(removal: Removal, onConfirm: () -> Unit, onDismiss: () -> Unit) = when (removal) {
    is Removal.Delete -> ConfirmDialog(
        title = stringResource(R.string.delete_conversation_title),
        body = stringResource(R.string.delete_conversation_body, userIsolated(removal.peerName)),
        confirm = stringResource(R.string.delete_conversation_confirm),
        onConfirm = onConfirm,
        onDismiss = onDismiss,
    )
    is Removal.Leave -> ConfirmDialog(
        title = stringResource(R.string.leave_chat_title, userIsolated(removal.channelTitle)),
        body = stringResource(R.string.leave_chat_body),
        confirm = stringResource(R.string.leave_chat_confirm),
        onConfirm = onConfirm,
        onDismiss = onDismiss,
    )
}

/** Board 3: until the first read, a list that has not been read never claims to be empty. */
@Composable
private fun Loading(modifier: Modifier) {
    Column(
        modifier.fillMaxSize().padding(horizontal = 24.dp).testTag(Tags.CONVERSATIONS_LOADING),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator(Modifier.size(32.dp))
        Text(
            stringResource(R.string.conversations_loading),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

/** Board 2, its body and buttons left out until New chat exists (D5). */
@Composable
private fun Empty(modifier: Modifier) {
    Column(
        modifier.fillMaxSize().padding(horizontal = 24.dp).testTag(Tags.CONVERSATIONS_EMPTY),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            painterResource(R.drawable.ic_forum_outlined),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.outline,
            modifier = Modifier.size(40.dp),
        )
        Text(
            stringResource(R.string.conversations_empty_title),
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() },
        )
    }
}

/** The empty detail pane beside the list (D12). */
@Composable
fun NoConversationSelected() {
    DetailPane {
        EmptyState(R.drawable.ic_forum_outlined, stringResource(R.string.no_conversation_selected), Modifier.testTag(Tags.EMPTY_DETAIL))
    }
}
