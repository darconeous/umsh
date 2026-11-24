package com.voria.umsh.features.conversations

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.rememberCopier
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.features.peers.manualpath.LearnedPathPrompt
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.TranscriptRow
import com.voria.umsh.services.mobilecore.AppLog
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import com.voria.umsh.designsystem.userIsolated

/**
 * A conversation (`threads.svg`): Back, its avatar and title (a direct
 * thread's opens the peer's page; a channel's, its Conversation info), the
 * transcript newest at the bottom, with a channel sender's avatar opening
 * their member sheet, and the composer, which owns the bottom edge and
 * rides above the keyboard. The bar hides under it on a phone; beside the
 * list [onBack] is null, since there is no Back there.
 *
 * [current] is whether the shell has this thread as the page shown: a
 * thread is also drawn when it is not, as the page a predictive back
 * gesture previews, or one leaving. Only the page shown is visible to
 * notifications, marks messages read, and lets the composer take focus.
 */
@Composable
fun ThreadScreen(
    key: UmshKey.Thread,
    current: Boolean,
    onBack: (() -> Unit)?,
    /** Close the thread: `EMERGENCY`'s warning turned down before a send. */
    onLeave: () -> Unit,
    onOpenDetails: (MessageRef) -> Unit,
    /** A direct thread's title, or a saved member's header: the peer's page, by its address. */
    onOpenPeer: (String) -> Unit,
    /** A channel thread's title: its Conversation info (`conversation-info.svg`). */
    onOpenInfo: () -> Unit = {},
    /** The composer's Connect radio with a radio held: its page. */
    onOpenRadio: () -> Unit,
    /** The composer's Connect radio with none set up: Choose a radio (D20). */
    onChooseRadio: () -> Unit,
    /** A `umsh:` link in a message, tapped: opened as another app's link is. */
    onOpenLink: (String) -> Unit = {},
) {
    val runtime = LocalAppRuntime.current
    val viewModel = runtimeViewModel { ThreadViewModel(it, key.address) }
    val conversation by viewModel.conversation.collectAsStateWithLifecycle()
    val appState by runtime.appState.collectAsStateWithLifecycle()
    val identity by runtime.identity.collectAsStateWithLifecycle()
    val forwardSecret by runtime.forwardSecretConversations.collectAsStateWithLifecycle()
    val radio by runtime.radio.collectAsStateWithLifecycle()
    val radioKnown by runtime.radioKnown.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val transcript by viewModel.transcript.collectAsStateWithLifecycle()
    val secretDraft by viewModel.secretDraft.collectAsStateWithLifecycle()
    val names = rememberDisplayNames()
    val context = remember(conversation, appState?.peers, names, identity.advertisedName, forwardSecret, secretDraft) {
        conversation?.let { shown ->
            ThreadContext(
                conversation = shown,
                peers = appState?.peers.orEmpty().associateBy { it.address },
                names = names,
                ownName = identity.advertisedName,
                forwardSecret = shown.address in forwardSecret || secretDraft,
            )
        }
    }
    val list = rememberLazyListState()
    val composerState by viewModel.composerState.collectAsStateWithLifecycle()
    val mode by viewModel.composeMode.collectAsStateWithLifecycle()
    val sending by viewModel.sending.collectAsStateWithLifecycle()
    val alert by viewModel.alert.collectAsStateWithLifecycle()
    val emergencyPrompt by viewModel.emergencyPrompt.collectAsStateWithLifecycle()
    val menuFor by viewModel.menuFor.collectAsStateWithLifecycle()
    val resendPrompt by viewModel.resendPrompt.collectAsStateWithLifecycle()
    val deleting by viewModel.deleting.collectAsStateWithLifecycle()
    val original by viewModel.original.collectAsStateWithLifecycle()
    val asking by viewModel.asking.collectAsStateWithLifecycle()
    val memberRef by viewModel.member.collectAsStateWithLifecycle()
    val memberRequested by viewModel.memberRequested.collectAsStateWithLifecycle()
    val focusRequester = remember { FocusRequester() }
    val copier = rememberCopier()
    val currentLeave by rememberUpdatedState(onLeave)
    LaunchedEffect(viewModel) { viewModel.leave.collect { currentLeave() } }
    LaunchedEffect(viewModel, current) {
        if (current) viewModel.focus.collect { runCatching { focusRequester.requestFocus() } }
    }
    // The caller's lambda may be new on every pass; read it, don't key on it.
    val currentOpenDetails by rememberUpdatedState(onOpenDetails)
    val onItem: (ChatMessage, MenuItem) -> Unit = remember(viewModel, copier) {
        { message, item ->
            viewModel.closeMenu()
            when (item) {
                MenuItem.Reply -> viewModel.startReply(message)
                MenuItem.Copy -> copier.copy(message.body, R.string.message_copied)
                MenuItem.ViewOriginal -> viewModel.showOriginal(message)
                MenuItem.TryAgain, MenuItem.Resend -> viewModel.askResend(message)
                MenuItem.Edit -> viewModel.startEdit(message)
                MenuItem.Details -> currentOpenDetails(message.ref)
                MenuItem.Delete -> viewModel.askDelete(message)
            }
        }
    }
    val currentOpenLink by rememberUpdatedState(onOpenLink)
    val isChannel = conversation is ChannelConversationSummary
    val handlers = remember(viewModel, onItem, isChannel) {
        MessageHandlers(
            onOpenQuote = viewModel::openQuote,
            onMenu = viewModel::openMenu,
            onRetry = viewModel::askResend,
            onReply = viewModel::startReply,
            onChip = viewModel::tapChip,
            onGap = viewModel::requestMissing,
            onMenuItem = onItem,
            onOpenLink = { currentOpenLink(it) },
            onMember = if (isChannel) viewModel::openMember else null,
        )
    }

    // On screen: Phase 2's notifications leave it alone.
    DisposableEffect(key.address, current) {
        if (current) runtime.visibleConversation.value = key.address
        onDispose { runtime.visibleConversation.compareAndSet(key.address, null) }
    }
    MarkRead(key.address, current, conversation?.unreadCount ?: 0, transcript.window, list)

    DetailPane {
        UmshScaffold(
            topBar = {
                UmshTopAppBar(
                    title = {
                        conversation?.let { shown ->
                            val peerLabel = stringResource(R.string.open_peer_page)
                            val infoLabel = stringResource(R.string.conversation_info_open)
                            val (openLabel, open) = when (shown) {
                                is DirectConversationSummary -> peerLabel to { onOpenPeer(shown.peer.address) }
                                is ChannelConversationSummary -> infoLabel to onOpenInfo
                            }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                modifier = Modifier
                                    .clip(MaterialTheme.shapes.small)
                                    .clickable(onClickLabel = openLabel, onClick = open)
                                    .testTag(Tags.THREAD_TITLE),
                            ) {
                                val avatar = when (shown) {
                                    is DirectConversationSummary -> RowAvatar.Peer(shown.peer)
                                    is ChannelConversationSummary -> RowAvatar.Channel(shown.channel)
                                }
                                RowAvatarView(avatar, size = AvatarSize.TopBar)
                                Text(context?.title.orEmpty(), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    },
                    onBack = onBack,
                )
            },
            modifier = Modifier.testTag(Tags.THREAD),
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when {
                        context == null -> if (appState == null) Spinner() else EmptyThread(null)
                        context.conversation.lastMessage == null && transcript.window.messages.isEmpty() -> EmptyThread(context)
                        !transcript.window.hasLoadedOnce -> Spinner()
                        else -> Transcript(viewModel, transcript, context, list, now, handlers, asking)
                    }
                }
                context?.let {
                    val replying = mode as? ComposeMode.Replying
                    Composer(
                        draft = viewModel.draft,
                        editText = viewModel.editText,
                        title = it.title,
                        state = composerState,
                        security = it.composerSecurity,
                        mode = mode,
                        replyName = replying?.let { reply ->
                            when (val sender = it.replyName(reply.message)) {
                                is Sender.Me -> stringResource(R.string.quote_you)
                                else -> senderText(sender).text
                            }
                        },
                        sending = sending,
                        onSend = viewModel::send,
                        onCancelMode = viewModel::cancelComposeMode,
                        // A radio held: its page. None set up: Choose a radio (D20). Not yet known: nothing.
                        onConnectRadio = when {
                            radio != null -> onOpenRadio
                            radioKnown -> onChooseRadio
                            else -> null
                        },
                        focusRequester = focusRequester,
                        focusable = current,
                    )
                }
            }
        }
    }

    menuFor?.let { message ->
        MessageMenuSheet(
            message = message,
            onReact = { kind -> viewModel.toggleReaction(message, kind) },
            onItem = { item -> onItem(message, item) },
            onDismiss = viewModel::closeMenu,
        )
    }
    emergencyPrompt?.let { prompt ->
        EmergencySheet(sends = prompt.sends, onCertify = viewModel::certify, onCancel = viewModel::declineCertification)
    }
    resendPrompt?.let { prompt ->
        ResendDialog(prompt, onSend = viewModel::confirmResend, onDismiss = viewModel::cancelResend)
    }
    deleting?.let {
        ConfirmDialog(
            title = stringResource(R.string.delete_message_title),
            body = if (context?.isChannel != false) {
                stringResource(R.string.delete_message_channel)
            } else {
                stringResource(R.string.delete_message_direct, userIsolated(context.title))
            },
            confirm = stringResource(R.string.delete_message_confirm),
            onConfirm = viewModel::confirmDelete,
            onDismiss = viewModel::cancelDelete,
        )
    }
    original?.let { OriginalDialog(it, onDismiss = viewModel::dismissOriginal) }
    // Read again from the window each time it changes: an identity reply fills the sheet in while it is open.
    val shownMember = memberRef?.let { ref -> context?.let { ChannelMember.of(ref, transcript.window.messages, it) } }
    shownMember?.let { member ->
        MemberSheet(
            member = member,
            requested = memberRequested,
            onRequestIdentity = viewModel::requestMemberIdentity,
            onOpenPeer = { address ->
                viewModel.closeMember()
                onOpenPeer(address)
            },
            onDismiss = viewModel::closeMember,
        )
    }
    alert?.let { ThreadAlertDialog(it, onDismiss = viewModel::dismissAlert) }
    // A held path that keeps missing its acks while the flood is answered (`manual-path.svg` 7).
    if (current && conversation is DirectConversationSummary) LearnedPathPrompt(key.address)
}

/**
 * Mark read while this is the page shown, the app is in front, and the
 * newest messages are on screen: through the newest one shown, which a read
 * never moves back. A preview is not a visit: the activity's lifecycle is
 * the only one, and it is resumed under a back gesture too.
 */
@Composable
private fun MarkRead(address: String, current: Boolean, unread: Long, window: TranscriptWindow, list: LazyListState) {
    val runtime = LocalAppRuntime.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val lifecycleState by lifecycle.currentStateFlow.collectAsStateWithLifecycle()
    val resumed = lifecycleState.isAtLeast(Lifecycle.State.RESUMED)
    val newestShown = if (window.hasLoadedOnce && !window.hasNewer) window.messages.lastOrNull()?.createdAtMs else null
    LaunchedEffect(current, resumed, unread > 0, newestShown, list) {
        if (!current || !resumed || unread <= 0 || newestShown == null) return@LaunchedEffect
        // The newest message's row (index 0, at the bottom) is on screen.
        snapshotFlow { list.layoutInfo.visibleItemsInfo.any { it.index == 0 } }
            .distinctUntilChanged()
            .collectLatest { atLatest ->
                if (!atLatest) return@collectLatest
                try {
                    runtime.markRead(address, newestShown).await()
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    AppLog.w("umsh.thread", "not marked read: ${error.javaClass.simpleName}")
                }
            }
    }
}

/**
 * What the reversed list holds: the rows, and above them the spinner at the
 * older edge. The newer edge has no item: in a reversed list the bottom-most
 * visible item is the one the list keeps in place, and a spinner there would
 * hold its place while a page of newer rows landed above it, carrying the
 * reader's rows up and away (or, as it went, dropping the reader at the
 * newest). Jump to latest covers that edge instead.
 */
private sealed interface TranscriptItem {
    val key: String

    data class Row(val row: TranscriptRow) : TranscriptItem {
        override val key: String get() = row.key
    }

    data object OlderEdge : TranscriptItem {
        override val key: String get() = "edge:older"
    }
}

/**
 * The transcript, newest at the bottom: a reversed list, so it opens there
 * and rows landing above (older pages) or trimmed below stay put under the
 * reader, anchored by key. Following the newest, new messages scroll in.
 */
@Composable
private fun Transcript(
    viewModel: ThreadViewModel,
    transcript: ThreadTranscript,
    context: ThreadContext,
    list: LazyListState,
    now: Instant,
    handlers: MessageHandlers,
    asking: Set<MessageRef>,
) {
    val window = transcript.window
    val items = remember(window) {
        buildList {
            window.rows.asReversed().forEach { add(TranscriptItem.Row(it)) }
            if (window.hasOlder) add(TranscriptItem.OlderEdge)
        }
    }

    val density = LocalDensity.current
    val followSlopPx = with(density) { FOLLOW_SLOP.roundToPx() }
    val centerBiasPx = with(density) { CENTER_BIAS.roundToPx() }
    // Following: at the bottom of the list. The screen alone decides it, so
    // it is never left saying something the list no longer shows.
    LaunchedEffect(list, followSlopPx) {
        snapshotFlow { list.firstVisibleItemIndex == 0 && list.firstVisibleItemScrollOffset <= followSlopPx }
            .distinctUntilChanged()
            .collect(viewModel::setFollowing)
    }
    // Paging: near the top, history; near the bottom of a window short of the newest, newer messages.
    LaunchedEffect(list, items) {
        snapshotFlow {
            val info = list.layoutInfo
            // Not measured yet: near neither edge.
            if (info.totalItemsCount == 0) return@snapshotFlow false to false
            val last = info.visibleItemsInfo.lastOrNull()?.index ?: -1
            val first = info.visibleItemsInfo.firstOrNull()?.index ?: -1
            (last >= info.totalItemsCount - PAGING_DISTANCE) to (first in 0 until PAGING_DISTANCE)
        }
            .distinctUntilChanged()
            .collect { (nearTop, nearBottom) ->
                if (nearTop && window.hasOlder) viewModel.loadOlder()
                if (nearBottom && window.hasNewer) viewModel.loadNewer()
            }
    }
    // Where the view model asked the reader to be, once the rows it named are composed.
    LaunchedEffect(transcript.scroll) {
        val request = transcript.scroll ?: return@LaunchedEffect
        when (val target = request.target) {
            ScrollRequest.Target.Latest -> list.animateScrollToItem(0)
            is ScrollRequest.Target.Message -> {
                val index = items.indexOfFirst { it.key == target.key }
                if (index >= 0) {
                    // Centered: half the viewport below the row's top.
                    val viewport = list.layoutInfo.viewportSize.height
                    list.scrollToItem(index, scrollOffset = -viewport / 2 + centerBiasPx)
                }
            }
        }
        viewModel.scrolled(request)
    }

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val layout = BubbleLayout(
            maxBubbleWidth = (maxWidth - 32.dp) * BUBBLE_WIDTH_FRACTION,
            memberGutter = MEMBER_GUTTER,
        )
        LazyColumn(
            state = list,
            reverseLayout = true,
            // Short of the newest, the last row clears Jump to latest.
            contentPadding = PaddingValues(top = 8.dp, bottom = if (window.hasNewer) JUMP_CLEARANCE else 12.dp),
            modifier = Modifier.fillMaxSize().testTag(Tags.TRANSCRIPT),
        ) {
            items(items, key = { it.key }, contentType = { it::class }) { item ->
                when (item) {
                    TranscriptItem.OlderEdge -> EdgeSpinner(loading = transcript.isLoadingOlder)
                    is TranscriptItem.Row -> TranscriptRowItem(
                        row = item.row,
                        context = context,
                        layout = layout,
                        lastOutboundKey = window.lastOutboundKey,
                        now = now,
                        highlighted = transcript.highlighted == item.key,
                        handlers = handlers,
                        asking = asking,
                    )
                }
            }
        }
        // Only while the loaded window does not reach the newest message.
        if (window.hasNewer) {
            JumpToLatest(viewModel::jumpToLatest, Modifier.align(Alignment.BottomCenter).padding(bottom = 12.dp))
        }
    }
}

/** A fixed-height row at the older edge, spinning while a page of history loads. */
@Composable
private fun EdgeSpinner(loading: Boolean) {
    Box(Modifier.fillMaxWidth().height(44.dp).testTag(Tags.TRANSCRIPT_EDGE), contentAlignment = Alignment.Center) {
        if (loading) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
    }
}

@Composable
private fun JumpToLatest(onClick: () -> Unit, modifier: Modifier) {
    Surface(
        onClick = onClick,
        shape = CircleShape,
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        shadowElevation = 3.dp,
        modifier = modifier.testTag(Tags.JUMP_TO_LATEST),
    ) {
        Row(
            Modifier.heightIn(min = 40.dp).padding(start = 14.dp, end = 20.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(painterResource(R.drawable.ic_vertical_align_bottom), contentDescription = null, modifier = Modifier.size(20.dp))
            Text(stringResource(R.string.jump_to_latest), style = MaterialTheme.typography.labelLarge)
        }
    }
}

/** While the first page loads: a centered spinner only. */
@Composable
private fun Spinner() {
    Box(Modifier.fillMaxSize().testTag(Tags.THREAD_LOADING), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.size(32.dp))
    }
}

/** Board 4: a conversation with no messages; [context] null for one that is gone. */
@Composable
private fun EmptyThread(context: ThreadContext?) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 32.dp).testTag(Tags.THREAD_EMPTY),
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            painterResource(R.drawable.ic_forum_outlined),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(48.dp),
        )
        Text(
            stringResource(R.string.thread_empty_title),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 8.dp).semantics { heading() },
        )
        context?.let {
            Text(
                if (it.isChannel) stringResource(R.string.thread_empty_channel) else stringResource(R.string.thread_empty_direct, userIsolated(it.title)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** A bubble's share of the row; the drawn ones wrap at about this width. */
private const val BUBBLE_WIDTH_FRACTION = 0.82f

/** A channel member's 28 dp avatar and the 8 dp before their bubble. */
private val MEMBER_GUTTER = 36.dp
/** Within this of the bottom still counts as at it. */
private val FOLLOW_SLOP = 32.dp
private const val PAGING_DISTANCE = 5

/** Offsets a quote's original by about half a short row, so the row's middle, not its edge, meets the viewport's. */
private val CENTER_BIAS = 52.dp

/** Jump to latest's 40 dp, the 12 dp under it, and 12 dp above it. */
private val JUMP_CLEARANCE = 64.dp
