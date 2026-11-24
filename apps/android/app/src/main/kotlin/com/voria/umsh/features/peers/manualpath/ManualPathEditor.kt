package com.voria.umsh.features.peers.manualpath

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.designsystem.AvatarSize
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DialogAction
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.FullScreenDialogScaffold
import com.voria.umsh.designsystem.LocalTimeFormatting
import com.voria.umsh.designsystem.MeasurePresentation
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.PhoneBadge
import com.voria.umsh.designsystem.RepeaterHintBadge
import com.voria.umsh.designsystem.SignalPresentation
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.isolated
import com.voria.umsh.designsystem.rail
import com.voria.umsh.designsystem.failureReasonText
import com.voria.umsh.designsystem.reasonText
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.designsystem.userIsolated
import com.voria.umsh.features.peers.Choice
import com.voria.umsh.features.peers.LocalNeighborSource
import com.voria.umsh.features.peers.NamedHops
import com.voria.umsh.features.peers.RouteKindText
import com.voria.umsh.features.peers.resolve
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.services.format.holdEnd
import com.voria.umsh.services.mobilecore.FailureText
import java.time.Instant
import kotlin.math.roundToInt
import kotlinx.serialization.Serializable

/** The pages of the editor's own small stack: the editor, Add hop over it, the hint entry over that. */
@Serializable
sealed interface ManualPathPage : NavKey {
    @Serializable
    data object Editor : ManualPathPage

    @Serializable
    data object AddHop : ManualPathPage

    @Serializable
    data object HintEntry : ManualPathPage
}

/** A draft, or none before it is seeded; saved with the page, so it outlives the process. */
private val OptionalDraftSaver = Saver<ManualPathDraft?, Any>(
    save = { draft -> draft?.let { with(ManualPathDraft.Saver) { save(it) } } ?: NOT_SEEDED },
    restore = { saved -> if (saved == NOT_SEEDED) null else ManualPathDraft.Saver.restore(saved) },
)

private const val NOT_SEEDED = "-"

/**
 * The manual path editor (`manual-path.svg` 1–6), a full-screen dialog
 * above the shell: seeded from the route once, then edited here; Add hop
 * and the hint entry are pages of its own stack. The draft and the draft
 * it started from are the page's saved state, so they outlive the process;
 * Close or Back with changes asks first (board 6). Save holds the path and
 * closes; the Route page beneath reads it then.
 */
@Composable
fun ManualPathScreen(address: String, onClose: () -> Unit) {
    val viewModel = runtimeViewModel { ManualPathViewModel(it, address) }
    val seed by viewModel.seed.collectAsStateWithLifecycle()
    var seeded by rememberSaveable(stateSaver = OptionalDraftSaver) { mutableStateOf<ManualPathDraft?>(null) }
    var draft by rememberSaveable(stateSaver = OptionalDraftSaver) { mutableStateOf<ManualPathDraft?>(null) }
    var discarding by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(seed) {
        val read = seed as? SeedRoute.Read ?: return@LaunchedEffect
        if (seeded == null) {
            val first = ManualPathDraft.seed(read.route, viewModel.limits)
            seeded = first
            draft = first
        }
    }
    val currentClose by rememberUpdatedState(onClose)
    LaunchedEffect(viewModel) { viewModel.saved.collect { currentClose() } }

    val changed = draft != null && draft != seeded
    val close = { if (changed) discarding = true else onClose() }
    val pages = rememberNavBackStack(ManualPathPage.Editor)
    BackHandler(enabled = changed && pages.size == 1) { discarding = true }

    NavDisplay(
        backStack = pages,
        onBack = { if (pages.size > 1) pages.removeAt(pages.lastIndex) },
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator(),
        ),
        entryProvider = entryProvider {
            entry<ManualPathPage.Editor> {
                EditorPage(
                    viewModel = viewModel,
                    seed = seed,
                    draft = draft,
                    onDraft = { draft = it },
                    onClose = close,
                    onAddHop = { pages.add(ManualPathPage.AddHop) },
                )
            }
            entry<ManualPathPage.AddHop> {
                draft?.let { shown ->
                    AddHopPage(
                        destination = viewModel.address,
                        draft = shown,
                        limits = viewModel.limits,
                        source = LocalNeighborSource.current ?: LocalAppRuntime.current,
                        onDraft = { draft = it },
                        onDone = { pages.removeAll { it != ManualPathPage.Editor } },
                        onEnterHint = { pages.add(ManualPathPage.HintEntry) },
                    )
                }
            }
            entry<ManualPathPage.HintEntry> {
                draft?.let { shown ->
                    RepeaterHintEntryPage(
                        draft = shown,
                        onBack = { pages.removeAt(pages.lastIndex) },
                        onAdd = { hint ->
                            draft = shown.adding(DraftHop(hint, typed = true), viewModel.limits)
                            pages.removeAt(pages.lastIndex)
                        },
                    )
                }
            }
        },
    )

    if (discarding) {
        ConfirmDialog(
            title = stringResource(R.string.manual_path_discard_title),
            body = stringResource(R.string.manual_path_discard_body),
            confirm = stringResource(R.string.manual_path_discard),
            dismiss = stringResource(R.string.manual_path_keep_editing),
            destructive = false,
            onConfirm = {
                discarding = false
                onClose()
            },
            onDismiss = { discarding = false },
        )
    }
}

@Composable
private fun EditorPage(
    viewModel: ManualPathViewModel,
    seed: SeedRoute,
    draft: ManualPathDraft?,
    onDraft: (ManualPathDraft) -> Unit,
    onClose: () -> Unit,
    onAddHop: () -> Unit,
) {
    val runtime = LocalAppRuntime.current
    val peer by viewModel.peer.collectAsStateWithLifecycle()
    val ping by viewModel.ping.collectAsStateWithLifecycle()
    val saving by viewModel.saving.collectAsStateWithLifecycle()
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val state by runtime.appState.collectAsStateWithLifecycle()
    val radio by runtime.radio.collectAsStateWithLifecycle()
    val now by runtime.now.collectAsStateWithLifecycle()
    val limits = viewModel.limits

    FullScreenDialogScaffold(
        title = stringResource(R.string.manual_path_title),
        navigationIcon = R.drawable.ic_close,
        navigationDescription = stringResource(R.string.manual_path_close),
        onNavigate = onClose,
        action = DialogAction(
            label = stringResource(R.string.action_save),
            enabled = draft != null,
            tag = Tags.MANUAL_PATH_SAVE,
            busy = saving,
            busyDescription = stringResource(R.string.manual_path_saving),
            onClick = { draft?.let { viewModel.save(it.path, it.holdMs) } },
        ),
        modifier = Modifier.testTag(Tags.MANUAL_PATH_PAGE),
    ) { padding ->
        val shown = peer
        if (shown == null || draft == null) {
            Box(Modifier.padding(padding).fillMaxSize().padding(horizontal = 24.dp), contentAlignment = Alignment.Center) {
                // Unreadable: nothing to seed from, so nothing to save; read again once the core runs.
                if (draft == null && seed is SeedRoute.Unavailable) {
                    Text(
                        failureReasonText(FailureText.reason(seed.error)),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.MANUAL_PATH_UNREAD),
                    )
                } else {
                    CircularProgressIndicator()
                }
            }
            return@FullScreenDialogScaffold
        }
        val hints = draft.hops.map { it.hint.octets }
        val namedFlow = remember(hints) { runtime.hopNames.peers(hints, runtime.appState) }
        val named by namedFlow.collectAsState(NamedHops.NONE)
        val peers = remember(state) { state?.peers.orEmpty().associateBy { it.address } }
        val hopNodes = draft.hops.mapIndexed { index, hop -> hop.node?.let(peers::get) ?: named.forHints(hints).getOrNull(index) }
        Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                PathSection(
                    peer = shown,
                    draft = draft,
                    hopNodes = hopNodes,
                    radioName = radio?.name?.takeIf { it.isNotBlank() },
                    limits = limits,
                    onDraft = onDraft,
                    onAddHop = onAddHop,
                )
                TestSection(
                    ping = ping?.takeIf { it.path == draft.path },
                    onPing = { viewModel.ping(draft.path) },
                )
                HoldSection(draft, limits, now, onDraft)
                if (failure == SaveFailure.Refused) {
                    Text(
                        stringResource(R.string.manual_path_refused),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.MANUAL_PATH_REFUSED),
                    )
                }
            }
        }
    }
    (failure as? SaveFailure.Failed)?.let {
        FailureDialog(stringResource(R.string.manual_path_not_saved_title), stringResource(R.string.peer_failure_body), it.error, viewModel::dismissFailure)
    }
}

/** Where the rail runs and what stands on it: the remove button's column, then the rail's. */
private val ACTION_COLUMN = 48.dp
private val RAIL_COLUMN = 40.dp

/**
 * Path to the peer (boards 1–2): this phone, the hops (each removable,
 * draggable by its handle, and moved by TalkBack's actions), Add hop
 * while there is room, the flood stepper, and the peer.
 */
@Composable
private fun PathSection(
    peer: PeerSummary,
    draft: ManualPathDraft,
    hopNodes: List<PeerSummary?>,
    radioName: String?,
    limits: ManualPathLimits,
    onDraft: (ManualPathDraft) -> Unit,
    onAddHop: () -> Unit,
) {
    val names = rememberDisplayNames()
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp).semantics(mergeDescendants = true) { heading() }.testTag(Tags.MANUAL_PATH_HEADER),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            stringResource(R.string.manual_path_to, userIsolated(names.peer(peer))),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f),
        )
        Text(
            pluralStringResource(R.plurals.route_hops, draft.hops.size + 1, draft.hops.size + 1),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(Tags.MANUAL_PATH_HOPS),
        )
    }
    RailRow(top = false, bottom = true, badge = { PhoneBadge() }) {
        Text(stringResource(R.string.path_this_phone), style = MaterialTheme.typography.bodyLarge)
        radioName?.let {
            Text(stringResource(R.string.path_sent_through, userIsolated(it)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    HopRows(draft, hopNodes, names, onDraft)
    if (!draft.isFull(limits)) {
        RailRow(
            top = true,
            bottom = true,
            modifier = Modifier.clickable(role = Role.Button, onClick = onAddHop).testTag(Tags.MANUAL_PATH_ADD_HOP),
            action = { Icon(painterResource(R.drawable.ic_add_circle), contentDescription = null, tint = MaterialTheme.colorScheme.primary) },
        ) {
            Text(stringResource(R.string.manual_path_add_hop), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
        }
    }
    FloodStepper(draft, limits, onDraft)
    RailRow(top = true, bottom = false, badge = { PeerAvatar(peer, size = AvatarSize.TopBar, describe = false) }, modifier = Modifier.testTag(Tags.MANUAL_PATH_PEER)) {
        Text(names.peer(peer), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

/** One row on the rail: an optional action at the start, the badge on the rail, the words, and an optional end. */
@Composable
private fun RailRow(
    top: Boolean,
    bottom: Boolean,
    modifier: Modifier = Modifier,
    action: (@Composable () -> Unit)? = null,
    badge: (@Composable () -> Unit)? = null,
    end: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    val line = MaterialTheme.colorScheme.outlineVariant
    Row(
        modifier.fillMaxWidth().height(IntrinsicSize.Min).heightIn(min = 56.dp).padding(start = 4.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.width(ACTION_COLUMN), contentAlignment = Alignment.Center) { action?.invoke() }
        Box(
            Modifier.width(RAIL_COLUMN).fillMaxHeight().drawBehind { rail(line, top, bottom, dashed = false) },
            contentAlignment = Alignment.Center,
        ) { badge?.invoke() }
        Column(Modifier.weight(1f).padding(start = 16.dp, top = 6.dp, bottom = 6.dp)) { content() }
        end?.invoke()
    }
}

/**
 * The hops, each dragged by its handle: a row moves past its neighbor once
 * dragged half its height, and lands where it is let go. TalkBack moves
 * them with Move up and Move down instead.
 */
@Composable
private fun HopRows(draft: ManualPathDraft, hopNodes: List<PeerSummary?>, names: com.voria.umsh.models.DisplayNames, onDraft: (ManualPathDraft) -> Unit) {
    val current by rememberUpdatedState(draft)
    val update by rememberUpdatedState(onDraft)
    var dragging by remember { mutableStateOf<Int?>(null) }
    var offset by remember { mutableFloatStateOf(0f) }
    val resources = LocalResources.current
    val locale = LocalConfiguration.current.locales[0]
    val moveUp = stringResource(R.string.manual_path_move_up)
    val moveDown = stringResource(R.string.manual_path_move_down)
    draft.hops.forEachIndexed { index, hop ->
        androidx.compose.runtime.key(hop.hint.octets.hex()) {
            val currentIndex by rememberUpdatedState(index)
            var height by remember { mutableIntStateOf(1) }
            val node = hopNodes.getOrNull(index)
            val hex = RepeaterHints.hexText(hop.hint)
            val title = node?.let(names::peer) ?: stringResource(R.string.repeater_hint_row, isolated(hop.hint.text))
            val subtitle = when {
                node == null && hop.typed -> stringResource(R.string.manual_path_entered_by_hand, isolated(hex))
                hop.rssiDbm != null || hop.snrQuarterDb != null -> SignalPresentation.readingTextQuarterDb(resources, hop.rssiDbm, hop.snrQuarterDb, locale)
                node != null -> stringResource(R.string.repeater_hint_row, isolated(hop.hint.text))
                else -> null
            }
            val lifted = dragging == index
            val actions = buildList {
                if (index > 0) {
                    add(CustomAccessibilityAction(moveUp) { update(current.moving(currentIndex, currentIndex - 1)); true })
                }
                if (index < draft.hops.lastIndex) {
                    add(CustomAccessibilityAction(moveDown) { update(current.moving(currentIndex, currentIndex + 1)); true })
                }
            }
            RailRow(
                top = true,
                bottom = true,
                modifier = Modifier
                    .onSizeChanged { height = it.height.coerceAtLeast(1) }
                    .zIndex(if (lifted) 1f else 0f)
                    .graphicsLayer { translationY = if (lifted) offset else 0f }
                    .then(if (lifted) Modifier.shadow(4.dp) else Modifier)
                    .semantics(mergeDescendants = true) { customActions = actions }
                    .testTag(Tags.manualPathHop(hop.hint.octets.hex())),
                action = {
                    IconButton(
                        onClick = { update(current.removing(currentIndex)) },
                        modifier = Modifier.testTag(Tags.manualPathRemove(hop.hint.octets.hex())),
                    ) {
                        Icon(
                            painterResource(R.drawable.ic_remove_circle),
                            contentDescription = stringResource(R.string.manual_path_remove_hop, title),
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                },
                badge = { RepeaterHintBadge(hop.hint.octets, hop.hint.text, node, size = AvatarSize.TopBar) },
                end = {
                    Box(
                        Modifier
                            .size(48.dp)
                            .testTag(Tags.manualPathHandle(hop.hint.octets.hex()))
                            .clearAndSetSemantics {}
                            .pointerInput(Unit) {
                                detectDragGestures(
                                    onDragStart = {
                                        dragging = currentIndex
                                        offset = 0f
                                    },
                                    onDragEnd = {
                                        dragging = null
                                        offset = 0f
                                    },
                                    onDragCancel = {
                                        dragging = null
                                        offset = 0f
                                    },
                                ) { change, amount ->
                                    change.consume()
                                    val at = dragging ?: return@detectDragGestures
                                    offset += amount.y
                                    val hops = current.hops
                                    if (offset > height / 2f && at < hops.lastIndex) {
                                        update(current.moving(at, at + 1))
                                        dragging = at + 1
                                        offset -= height
                                    } else if (offset < -height / 2f && at > 0) {
                                        update(current.moving(at, at - 1))
                                        dragging = at - 1
                                        offset += height
                                    }
                                }
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(painterResource(R.drawable.ic_drag_handle), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
            ) {
                Column {
                    Text(title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    subtitle?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
    }
}

/**
 * Then flood (Flood with no repeaters, board 2): Off up to the core's most.
 * TalkBack reads its value and adjusts it with Increase and Decrease.
 */
@Composable
private fun FloodStepper(draft: ManualPathDraft, limits: ManualPathLimits, onDraft: (ManualPathDraft) -> Unit) {
    val value = RouteKindText.flood(draft.floodHops).resolve()
    val increase = stringResource(R.string.manual_path_flood_increase)
    val decrease = stringResource(R.string.manual_path_flood_decrease)
    val set = { hops: Int -> onDraft(draft.withFlood(hops, limits)) }
    RailRow(
        top = true,
        bottom = true,
        modifier = Modifier
            .testTag(Tags.MANUAL_PATH_FLOOD)
            .semantics(mergeDescendants = true) {
                stateDescription = value
                progressBarRangeInfo = ProgressBarRangeInfo(draft.floodHops.toFloat(), 0f..limits.maxFloodHops.toFloat(), steps = (limits.maxFloodHops - 1).coerceAtLeast(0))
                setProgress { target ->
                    set(target.roundToInt())
                    true
                }
                customActions = buildList {
                    if (draft.floodHops < limits.maxFloodHops) add(CustomAccessibilityAction(increase) { set(draft.floodHops + 1); true })
                    if (draft.floodHops > 0) add(CustomAccessibilityAction(decrease) { set(draft.floodHops - 1); true })
                }
            },
        end = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    onClick = { set(draft.floodHops - 1) },
                    enabled = draft.floodHops > 0,
                    modifier = Modifier.testTag(Tags.MANUAL_PATH_FLOOD_FEWER).clearAndSetSemantics {},
                ) { Icon(painterResource(R.drawable.ic_remove), contentDescription = null) }
                VerticalDivider(Modifier.height(24.dp))
                IconButton(
                    onClick = { set(draft.floodHops + 1) },
                    enabled = draft.floodHops < limits.maxFloodHops,
                    modifier = Modifier.testTag(Tags.MANUAL_PATH_FLOOD_MORE).clearAndSetSemantics {},
                ) { Icon(painterResource(R.drawable.ic_add), contentDescription = null) }
            }
        },
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(if (draft.hops.isEmpty()) R.string.manual_path_flood else R.string.route_then_flood),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.clearAndSetSemantics {})
            Spacer(Modifier.width(8.dp))
        }
    }
}

/**
 * Test (board 1): Ping along path, and what came back for the path as it
 * stands. The reading is this phone's radio's, of the reply's last leg.
 */
@Composable
private fun TestSection(ping: PathPing?, onPing: () -> Unit) {
    val locale = LocalConfiguration.current.locales[0]
    val resources = LocalResources.current
    SectionTitle(stringResource(R.string.manual_path_test))
    val waiting = ping != null && ping.outcome == null
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(enabled = !waiting, role = Role.Button, onClick = onPing)
            .padding(horizontal = 16.dp)
            .testTag(Tags.MANUAL_PATH_PING),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        val tint = if (waiting) MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f) else MaterialTheme.colorScheme.primary
        Icon(painterResource(R.drawable.ic_ping), contentDescription = null, tint = tint)
        Text(stringResource(R.string.manual_path_ping), style = MaterialTheme.typography.bodyLarge, color = tint)
    }
    when (val outcome = ping?.outcome) {
        null -> if (ping != null) {
            val description = stringResource(R.string.manual_path_pinging)
            Box(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(Tags.MANUAL_PATH_PING_RESULT)) {
                CircularProgressIndicator(Modifier.size(24.dp).semantics { stateDescription = description }, strokeWidth = 2.dp)
            }
        }
        is PingOutcome.Reply -> {
            val reply = outcome.reply
            val time = reply.roundTripMs?.let { stringResource(R.string.manual_path_replied, MeasurePresentation.seconds(it, locale)) }
            val spoken = reply.roundTripMs?.let { stringResource(R.string.manual_path_replied, MeasurePresentation.secondsSpoken(it, locale)) }
            val reading = SignalPresentation.readingText(resources, reply.ownSignal.rssiDbm, reply.ownSignal.snrCentibels, locale)
            ResultRow(
                icon = R.drawable.ic_check_circle,
                tint = UmshColors.fixed.connected,
                title = time ?: stringResource(R.string.ping_reply_spoken_bare),
                detail = reading,
                spoken = listOfNotNull(spoken ?: stringResource(R.string.ping_reply_spoken_bare), reading).joinToString(", "),
            )
        }
        PingOutcome.TimedOut -> ResultRow(R.drawable.ic_error, UmshColors.fixed.caution, stringResource(R.string.ping_no_reply), null, null)
        is PingOutcome.Unavailable -> ResultRow(R.drawable.ic_warning, MaterialTheme.colorScheme.error, reasonText(outcome.reason), null, null)
        PingOutcome.Canceled -> Unit
    }
}

@Composable
private fun ResultRow(icon: Int, tint: androidx.compose.ui.graphics.Color, title: String, detail: String?, spoken: String?) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp)
            .semantics(mergeDescendants = true) {
                spoken?.let { contentDescription = it }
                // Announced once, as the spinner gives way to it (§3.10).
                liveRegion = LiveRegionMode.Polite
            }
            .testTag(Tags.MANUAL_PATH_PING_RESULT),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(painterResource(icon), contentDescription = null, tint = tint)
        Column {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = if (detail == null) tint else MaterialTheme.colorScheme.onSurface)
            detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

/** Hold (board 1): the core's choices, when the hold would end, and what follows it. */
@Composable
private fun HoldSection(draft: ManualPathDraft, limits: ManualPathLimits, now: Instant, onDraft: (ManualPathDraft) -> Unit) {
    val locale = LocalConfiguration.current.locales[0]
    val format = LocalTimeFormatting.current
    SectionTitle(stringResource(R.string.manual_path_hold))
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Choice(
            label = stringResource(R.string.manual_path_hold_for),
            value = MeasurePresentation.span(draft.holdMs, locale),
            options = limits.holdChoicesMs.map { it to MeasurePresentation.span(it, locale) },
            selected = draft.holdMs,
            onChoose = { onDraft(draft.withHold(it, limits)) },
            tag = Tags.MANUAL_PATH_HOLD,
            optionTag = { "${Tags.MANUAL_PATH_HOLD_OPTION}/$it" },
            modifier = Modifier.weight(1f),
        )
        val untilText = format.holdEnd(now.plusMillis(draft.holdMs), now)
        Column(Modifier.weight(1f).padding(start = 16.dp).semantics(mergeDescendants = true) {}.testTag(Tags.MANUAL_PATH_UNTIL)) {
            Text(stringResource(R.string.manual_path_until), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(untilText, style = MaterialTheme.typography.bodyLarge)
        }
    }
    Text(
        stringResource(R.string.manual_path_hold_footer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp).semantics { heading() },
    )
}
