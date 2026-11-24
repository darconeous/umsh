package com.voria.umsh.app

import android.icu.text.NumberFormat
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.Badge
import androidx.compose.material3.Icon
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.layout.calculatePaneScaffoldDirective
import androidx.compose.material3.adaptive.navigation.BackNavigationBehavior
import androidx.compose.material3.adaptive.navigation3.ListDetailSceneStrategy
import androidx.compose.material3.adaptive.navigation3.rememberListDetailSceneStrategy
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteItem
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteType
import androidx.compose.material3.adaptive.navigationsuite.rememberNavigationSuiteScaffoldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusTarget
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.NavEntryDecorator
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberDecoratedNavEntries
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import com.voria.umsh.R
import com.voria.umsh.designsystem.CopyNotice
import com.voria.umsh.designsystem.DataLoadBanner
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.LocalCopyNotice
import com.voria.umsh.designsystem.LocalScreenBanner
import com.voria.umsh.designsystem.LocalTopBarRadioControl
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.RadioBannerAction
import com.voria.umsh.designsystem.RadioControl
import com.voria.umsh.designsystem.RadioProblemBanner
import com.voria.umsh.designsystem.isRailLayout
import com.voria.umsh.designsystem.isTwoPaneLayout
import com.voria.umsh.designsystem.windowAdaptiveInfo
import com.voria.umsh.features.channels.ChannelCreateScreen
import com.voria.umsh.features.channels.ChannelJoinScreen
import com.voria.umsh.features.channels.ChannelKeyText
import com.voria.umsh.features.channels.ChannelPageScreen
import com.voria.umsh.features.conversations.ConversationInfoScreen
import com.voria.umsh.features.channels.ChannelsScreen
import com.voria.umsh.features.conversations.ConversationsScreen
import com.voria.umsh.features.conversations.MessageDetailsScreen
import com.voria.umsh.features.conversations.NoConversationSelected
import com.voria.umsh.features.conversations.ThreadScreen
import com.voria.umsh.features.map.MapScreen
import com.voria.umsh.features.peers.AddPeerExit
import com.voria.umsh.features.peers.AddPeerScreen
import com.voria.umsh.features.peers.ExchangeScreen
import com.voria.umsh.features.peers.LocalExchangeHost
import com.voria.umsh.features.peers.RuntimeExchangeHost
import com.voria.umsh.features.peers.NoPeerSelected
import com.voria.umsh.features.peers.DiscoverScreen
import com.voria.umsh.features.peers.LinkImportSheet
import com.voria.umsh.features.peers.NeighborsScreen
import com.voria.umsh.features.peers.PeerPageScreen
import com.voria.umsh.features.peers.PeersScreen
import com.voria.umsh.features.peers.RouteScreen
import com.voria.umsh.features.peers.manualpath.ManualPathScreen
import com.voria.umsh.features.radio.RadioDetailScreen
import com.voria.umsh.features.scanner.ScannedCode
import com.voria.umsh.features.scanner.ScannerScreen
import com.voria.umsh.features.radio.RadioPickerScreen
import com.voria.umsh.features.settings.NotificationsSettingsScreen
import com.voria.umsh.features.settings.SettingsRow
import com.voria.umsh.features.settings.SettingsScreen
import com.voria.umsh.features.settings.YourIdentityScreen
import com.voria.umsh.services.permissions.rememberBluetoothEnabler
import com.voria.umsh.services.permissions.rememberNearbyDevicesAsker
import com.voria.umsh.services.radio.RadioBanner
import java.time.Instant
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.cancellation.CancellationException
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * The app shell (`navigation.svg`, `list-detail.svg`): the navigation bar
 * below 600 dp, the collapsed wide rail with the radio control in its
 * header from 600 dp, and list beside detail for Conversations, Peers and
 * Settings from 840 dp. One back stack per destination; the problem banner
 * under the top app bar on a phone, above both panes beside the rail.
 *
 * Above it, the app-level stack: pages that belong to no destination, such
 * as Radio Detail from the radio control. They open full width over the
 * shell, never change the selected destination, and Back (with its
 * predictive preview) returns to the shell as it was left.
 */
@Composable
fun UmshShell(shell: ShellState = rememberShellState()) {
    val host = LocalAppCoreHost.current
    val runtime = LocalAppRuntime.current
    val exchange = LocalExchangeHost.current ?: remember(runtime) { RuntimeExchangeHost(runtime) }
    val viewModel = runtimeViewModel {
        val started = ProcessLifecycleOwner.get().lifecycle.currentStateFlow.map { it.isAtLeast(Lifecycle.State.STARTED) }
        ShellViewModel(it, host.bluetooth, host.preferences.radioRegistry.bound, started, exchange)
    }
    // A conversation removed, from its row or anywhere else: its thread
    // closes. A peer removed or erased: every page about it closes, wherever
    // it is. Read from the runtime's state itself, never a copy derived from
    // it or held in composition: a page opened once a command's lists were
    // read (a link's node, a conversation just started) is never closed by
    // an older list arriving after it.
    LaunchedEffect(runtime, shell) {
        runtime.appState.collect { state ->
            if (state == null) return@collect
            shell.closeThreadsNotIn(state.conversations.mapTo(HashSet()) { it.address })
            shell.closePeerPagesNotIn(state.peers.mapTo(HashSet()) { it.address })
            shell.closeChannelPagesNotIn(state.channels.filter { it.joinedPhone }.mapTo(HashSet()) { it.id })
        }
    }
    // The page on screen decides whether the exchange is open (an app-level
    // page over Add peer hides it), and the exchange page comes and goes
    // with the exchange over the Add peer shown: in one pass, so leaving the
    // page backs out before the page is followed again.
    LaunchedEffect(shell, viewModel) {
        combine(viewModel.meetStep, snapshotFlow { shell.shownTop }) { _, top -> top }.collect { top ->
            viewModel.topPageChanged(top)
            shell.followMeet(viewModel.currentMeetStep())
        }
    }
    // A notification's or shortcut's tap (that conversation, above its
    // list, or the radio notification's Radio Detail) and opened links, in
    // the order they arrived. One left unopened by a recreation is opened
    // by the next shell.
    val requests = LocalOpenRequests.current
    val twoPane by rememberUpdatedState(isTwoPaneLayout())
    LaunchedEffect(requests) {
        requests.pending.collect { pending ->
            val request = pending.firstOrNull() ?: return@collect
            when (request) {
                is OpenRequest.Conversation -> shell.openConversation(request.address)
                OpenRequest.RadioDetail -> shell.openRadioDetail()
                is OpenRequest.Peer -> openPeerRequest(runtime, shell, request.address)
                is OpenRequest.Link -> openLink(runtime, shell, viewModel, request) { twoPane }
            }
            requests.done(request)
        }
    }
    val activity = LocalActivity.current
    // Close or Back on an app-level page: back to the shell as it was left,
    // or, for a page another app's link opened, back to that app (D7).
    // Beside that app (split screen, a desktop window) it is already in
    // view: the page closes to the shell, and the app keeps its place.
    val closeAppPage: () -> Unit = remember(shell, activity) {
        {
            val leaving = shell.closingLeavesApp && activity?.isInMultiWindowMode != true
            shell.popAppPage()
            if (leaving) activity?.moveTaskToBack(true)
        }
    }
    // Left by any other way (Home, Recents, another app, the screen off):
    // whatever brings the app back, a link's page no longer leads out of it.
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) {
        if (activity?.isChangingConfigurations != true) {
            shell.appLeft()
            viewModel.appLeft()
        }
    }

    // The radio control for a full-screen dialog above the shell, as the shell's own bars draw it.
    val radioControl: @Composable () -> Unit = remember(viewModel, shell) { { AppStackRadioControl(viewModel, shell) } }

    val snackbars = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val resources = LocalResources.current
    val copyNotice = remember(snackbars, resources) {
        CopyNotice { message -> scope.launch { snackbars.showSnackbar(resources.getString(message)) } }
    }

    CompositionLocalProvider(
        // The store the shell is drawn in: pages drawn in two places share it.
        LocalShellViewModelStoreOwner provides checkNotNull(LocalViewModelStoreOwner.current),
        LocalCopyNotice provides copyNotice,
        LocalExchangeHost provides exchange,
    ) {
        NavDisplay(
            backStack = shell.appStack,
            onBack = closeAppPage,
            entryDecorators = rememberAppStackDecorators(),
            modifier = Modifier.testTag(Tags.APP_NAV_DISPLAY),
            entryProvider = entryProvider {
                entry<UmshKey.Shell> { ShellScaffold(shell, viewModel, snackbars) }
                entry<UmshKey.RadioDetail> {
                    // Full width above the shell: no radio control in its bar
                    // (it is what opened the page), and no banner (the page
                    // states the radio's problem itself).
                    AppPage {
                        RadioDetailScreen(
                            onBack = { shell.popAppPage() },
                            onGone = shell::closeRadioDetail,
                            inPane = false,
                            onChooseRadio = shell::openRadioPicker,
                            onOpenPeer = { shell.openPeer(it, destination = null) },
                        )
                    }
                }
                entry<UmshKey.PeerPage> { key ->
                    // Above the shell, over Radio Detail or opened from a link.
                    // Over Radio Detail, as Radio Detail: no radio control or
                    // banner. A link's page has Close and the radio control
                    // (`peer-page.svg` 5): it may be all of the app shown.
                    AppPage(radioControl.takeIf { key.link != null }) {
                        PeerPageScreen(
                            key.address,
                            onBack = closeAppPage,
                            onConversation = { shell.openConversationFrom(key, it) },
                            onOpenRoute = { shell.openRoute(key) },
                            onOpenNeighbors = { shell.openNeighbors(key) },
                            onOpenPeer = { shell.openPeer(it, destination = null) },
                            closes = key.link != null,
                        )
                    }
                }
                entry<UmshKey.Route> { key ->
                    AppPage {
                        RouteScreen(
                            key.address,
                            onBack = { shell.popAppPage() },
                            onOpenPeer = { shell.openPeer(it.address, destination = null) },
                            onAskNear = { shell.openDiscover(key) },
                            onEdit = { shell.openManualPath(key.address) },
                        )
                    }
                }
                entry<UmshKey.Neighbors> { key ->
                    AppPage {
                        NeighborsScreen(
                            key.address,
                            onBack = { shell.popAppPage() },
                            onOpenPeer = { shell.openPeer(it, destination = null) },
                        )
                    }
                }
                entry<UmshKey.Discover> { key ->
                    AppPage {
                        DiscoverScreen(
                            key.vantagePeer,
                            onBack = { shell.popAppPage() },
                            onOpenPeer = { shell.openPeer(it, destination = null) },
                        )
                    }
                }
                entry<UmshKey.ManualPath> { key ->
                    // A full-screen dialog above the shell: Save and the radio control share its bar; no banner.
                    AppPage(radioControl) {
                        ManualPathScreen(key.address, onClose = { shell.popAppPage() })
                    }
                }
                entry<UmshKey.ChannelJoin> { key ->
                    // A full-screen dialog above the shell: Join and the radio control share its bar; no banner.
                    AppPage(radioControl) {
                        ChannelJoinScreen(
                            input = key.input?.let(ChannelKeyText::open),
                            forChat = key.forChat,
                            onClose = { shell.popAppPage() },
                            onJoined = { shell.leaveChannelJoin(key, it.conversationAddress) },
                            onScan = { shell.openScanner(ScanTarget.JoinChannelField, Destination.Settings) },
                            scanned = shell.scanned(ScanTarget.JoinChannelField, Destination.Settings),
                        )
                    }
                }
                entry<UmshKey.ChannelCreate> {
                    AppPage(radioControl) {
                        ChannelCreateScreen(onClose = { shell.popAppPage() }, onCreated = shell::leaveChannelCreate)
                    }
                }
                entry<UmshKey.Scanner> { key ->
                    // Full screen above the shell; a code it takes goes back to where the scan began.
                    AppPage {
                        ScannerScreen(onClose = { shell.popAppPage() }, onScanned = { shell.deliverScan(key, it) })
                    }
                }
                entry<UmshKey.RadioPicker> {
                    // Full width above the shell and whatever opened it, as Radio Detail.
                    AppPage {
                        RadioPickerScreen(onBack = { shell.popAppPage() }, onChosen = shell::closeRadioPicker)
                    }
                }
            },
        )
        // An opened link that names no node: the import sheet over whatever shows.
        val linkImport by viewModel.linkImport.collectAsStateWithLifecycle()
        LinkImportSheet(
            linkImport?.uri,
            opening = linkImport?.opening ?: 0L,
            onDismiss = viewModel::closeLinkImport,
            onExit = { exit ->
                when (exit) {
                    is AddPeerExit.Page -> shell.openLinkedPeer(exit.address, viewModel.linkImport.value?.origin ?: LinkOrigin.InApp)
                    is AddPeerExit.Conversation -> shell.openConversation(exit.address)
                    AddPeerExit.OwnIdentity -> shell.openOwnIdentity(twoPane)
                }
            },
            onChannel = shell::openChannelLink,
        )
        val linkFailure by viewModel.linkFailure.collectAsStateWithLifecycle()
        linkFailure?.let { error ->
            FailureDialog(
                stringResource(R.string.link_not_opened_title),
                stringResource(R.string.link_not_opened_body),
                error,
                onDismiss = { viewModel.linkFailed(null) },
            )
        }
    }
}

/**
 * An opened `umsh:` link, from another app or a message, by one route
 * (product-structure, "Deep links"): a node opens its page above whatever
 * shows, recorded unsaved when this phone has no row for it; this phone's
 * own link opens Your identity; a link that names no node opens the import
 * sheet with what is wrong with it; a channel link opens Join channel over
 * Settings › Channels.
 */
private suspend fun openLink(runtime: AppRuntime, shell: ShellState, viewModel: ShellViewModel, link: OpenRequest.Link, twoPane: () -> Boolean) {
    viewModel.closeLinkImport()
    when (val target = LinkRoute.target(link.uri, runtime.identity.value.address)) {
        is LinkTarget.Channel -> shell.openChannelLink(target.uri)
        is LinkTarget.Unreadable -> viewModel.showLinkImport(target.uri, link.origin)
        LinkTarget.OwnIdentity -> shell.openOwnIdentity(twoPane())
        is LinkTarget.Node -> try {
            when (val address = runtime.recordLinkPeer(target.uri).await()) {
                null -> shell.openOwnIdentity(twoPane())
                else -> shell.openLinkedPeer(address, link.origin)
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.w("umsh.shell", "link not opened: ${error.javaClass.simpleName}")
            viewModel.linkFailed(error)
        }
    }
}

/**
 * A notification about a node (product-structure, "Notification taps"):
 * one that sends text opens its conversation, started if there is none;
 * any other opens its page on Peers. A node not read yet is waited for
 * briefly; one that never appears (deleted since) opens nothing.
 */
private suspend fun openPeerRequest(runtime: AppRuntime, shell: ShellState, address: String) {
    val peer = withTimeoutOrNull(PEER_REQUEST_WAIT_MS) {
        runtime.appState.mapNotNull { state -> state?.peers?.firstOrNull { it.address == address } }.first()
    }
    when {
        peer == null -> AppLog.w("umsh.shell", "notified peer not stored")
        peer.offersTextMessages -> try {
            shell.openConversation(runtime.startConversation(address).await())
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.w("umsh.shell", "notified peer's conversation not opened: ${error.javaClass.simpleName}")
            shell.showPeer(address)
        }
        else -> shell.showPeer(address)
    }
}

/**
 * A page above the shell: no banner, the radio control only when given
 * (a full-screen dialog's bar), and notices of its own, since the shell's
 * snackbar host is not drawn beneath it.
 */
@Composable
private fun AppPage(radioControl: (@Composable () -> Unit)? = null, content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalTopBarRadioControl provides radioControl, LocalScreenBanner provides null) {
        NoticeHost(content)
    }
}

/** The radio control drawn above the shell: Radio Detail when a radio is held, else Choose a radio. */
@Composable
private fun AppStackRadioControl(viewModel: ShellViewModel, shell: ShellState) {
    val shown by viewModel.radio.collectAsStateWithLifecycle()
    val now by viewModel.now.collectAsStateWithLifecycle()
    val showDetails: (() -> Unit)? = when {
        shown.radio != null -> shell::openRadioDetail
        shown.known -> shell::openRadioPicker
        else -> null
    }
    RadioControl(shown.radio, now, known = shown.known, onShowDetails = showDetails)
}

/** How long a notification tap waits for its node to be read. */
private const val PEER_REQUEST_WAIT_MS = 5_000L

/**
 * What each page above the shell is wrapped in: its saved state, and
 * ViewModels of its own, cleared when it is popped, so two pages of one
 * kind (two peers opened from links) never share one. Pages drawn in two
 * places that must share a ViewModel name the shell's store
 * ([LocalShellViewModelStoreOwner]) themselves.
 */
@Composable
internal fun rememberAppStackDecorators(): List<NavEntryDecorator<NavKey>> = listOf(
    rememberSaveableStateHolderNavEntryDecorator(),
    rememberViewModelStoreNavEntryDecorator(),
)

/** The navigation suite around the destinations, with the radio control and the banners. */
@Composable
private fun ShellScaffold(shell: ShellState, viewModel: ShellViewModel, snackbars: SnackbarHostState) {
    val shown by viewModel.radio.collectAsStateWithLifecycle()
    val now by viewModel.now.collectAsStateWithLifecycle()
    val radioBanner by viewModel.radioBanner.collectAsStateWithLifecycle()
    val dataLoadFailed by viewModel.dataLoadFailed.collectAsStateWithLifecycle()
    val unread by viewModel.unreadConversations.collectAsStateWithLifecycle()

    val rail = isRailLayout()
    // A thread owns the bottom of a phone's screen: its composer, over the IME.
    // A message's details, opened from it, stay in the thread's flow.
    val barHidden = !rail && (shell.top is UmshKey.Thread || shell.top is UmshKey.MessageDetails || shell.top is UmshKey.ConversationInfo)
    val suiteState = rememberNavigationSuiteScaffoldState()
    LaunchedEffect(barHidden) { if (barHidden) suiteState.hide() else suiteState.show() }

    // A radio held: its page. None set up: Choose a radio (D20). Not yet known: nothing.
    val showDetails: (() -> Unit)? = when {
        shown.radio != null -> shell::openRadioDetail
        shown.known -> shell::openRadioPicker
        else -> null
    }
    val radioControl: @Composable () -> Unit = {
        RadioControl(shown.radio, now, known = shown.known, onShowDetails = showDetails)
    }
    val preferences = LocalAppCoreHost.current.preferences
    val allowNearby = rememberNearbyDevicesAsker(preferences)
    val turnOnBluetooth = rememberBluetoothEnabler(preferences)
    val onBannerAction: (RadioBannerAction) -> Unit = { action ->
        when (action) {
            RadioBannerAction.ChooseRadio -> shell.openRadioPicker()
            RadioBannerAction.Details -> shell.openRadioDetail()
            RadioBannerAction.TurnOn -> turnOnBluetooth()
            RadioBannerAction.Allow -> allowNearby()
        }
    }
    val banner: (@Composable () -> Unit)? = if (dataLoadFailed || radioBanner != null) {
        { BannerSlot(dataLoadFailed, radioBanner, now, onRetry = viewModel::retryLoad, onRadioAction = onBannerAction) }
    } else {
        null
    }

    NavigationSuiteScaffold(
        navigationItems = {
            Destination.entries.forEach { destination ->
                val selected = destination == shell.selected
                NavigationSuiteItem(
                    selected = selected,
                    onClick = { shell.select(destination) },
                    icon = {
                        Icon(
                            painterResource(if (selected) destination.selectedIcon else destination.icon),
                            contentDescription = null,
                        )
                    },
                    // One line: four items at 320 dp leave "Conversations" too
                    // little room, and a wrapped label breaks mid-word.
                    label = { Text(stringResource(destination.label), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    badge = if (destination == Destination.Conversations && unread > 0) {
                        { UnreadBadge(unread) }
                    } else {
                        null
                    },
                    modifier = Modifier.testTag(destination.tag),
                )
            }
        },
        navigationSuiteType = if (rail) NavigationSuiteType.WideNavigationRailCollapsed else NavigationSuiteType.NavigationBar,
        state = suiteState,
        primaryActionContent = {
            if (rail) Box(Modifier.testTag(Tags.RAIL_HEADER)) { radioControl() }
        },
        modifier = Modifier.testTag(Tags.SHELL),
    ) {
        CompositionLocalProvider(
            LocalTopBarRadioControl provides if (rail) null else radioControl,
            LocalScreenBanner provides if (rail) null else banner,
        ) {
            Box(Modifier.fillMaxSize()) {
                Column(Modifier.fillMaxSize()) {
                    var below: Modifier = Modifier
                    if (rail && banner != null) {
                        // Beside the rail the banner spans the content area, above
                        // both panes, under the status bar.
                        Box(Modifier.windowInsetsPadding(WindowInsets.statusBars)) { banner() }
                        below = Modifier.consumeWindowInsets(WindowInsets.statusBars)
                    }
                    Box(below.weight(1f)) { Destinations(shell) }
                }
                SnackbarHost(snackbars, Modifier.align(Alignment.BottomCenter))
            }
        }
    }
}

/** The shell's banners: the data-load failure above the radio's problem. */
@Composable
internal fun BannerSlot(
    dataLoadFailed: Boolean,
    radioBanner: RadioBanner?,
    now: Instant,
    onRetry: () -> Unit,
    onRadioAction: ((RadioBannerAction) -> Unit)? = null,
) {
    Column(Modifier.testTag(Tags.BANNER_SLOT)) {
        if (dataLoadFailed) DataLoadBanner(onRetry = onRetry)
        radioBanner?.let { RadioProblemBanner(it, now, onAction = onRadioAction) }
    }
}

@Composable
private fun UnreadBadge(count: Int) {
    val description = pluralStringResource(R.plurals.nav_unread_conversations, count, count)
    val locale = LocalConfiguration.current.locales[0]
    Badge(Modifier.semantics { contentDescription = description }.testTag(Tags.NAV_UNREAD_BADGE)) {
        Text(NumberFormat.getIntegerInstance(locale).format(count.toLong()))
    }
}

/**
 * The shown destination's back stack, with Conversations' beneath it: Back
 * at the root of Peers, Map or Settings is a pop onto Conversations, so the
 * system's predictive gesture previews Conversations as it was left.
 *
 * Every destination's stack is decorated, shown or not, so each keeps its
 * pages' saved state and ViewModels while another is shown; a page popped
 * from its own stack loses them. They all go with the shell.
 */
@OptIn(ExperimentalMaterial3AdaptiveApi::class)
@Composable
private fun Destinations(shell: ShellState) {
    val owner = checkNotNull(LocalViewModelStoreOwner.current)
    val twoPane = isTwoPaneLayout()
    // Back pops one page, as the shell's own back does. The library's default
    // pops until the panes change, which beside a list they never do: Back
    // from a message's details, or a page above them, left the app.
    val strategy = rememberListDetailSceneStrategy<NavKey>(
        backNavigationBehavior = BackNavigationBehavior.PopLatest,
        directive = calculatePaneScaffoldDirective(windowAdaptiveInfo()),
    )
    // Each destination's panes carry its own scene key: list-detail pairs a
    // list with the details after it only within one destination, never a
    // Settings list with a Conversations placeholder beneath it.
    val provider = entryProvider<NavKey> {
        entry<UmshKey.ConversationsRoot>(
            metadata = ListDetailSceneStrategy.listPane(Destination.Conversations) { NoConversationSelected() },
        ) {
            val conversations = shell.stacks.getValue(Destination.Conversations)
            ConversationsScreen(
                current = shell.isShown(Destination.Conversations, UmshKey.ConversationsRoot, twoPane),
                // Beside the list, the open conversation's row is highlighted, under
                // whatever was opened from it too (a message's details, a peer page).
                selected = if (twoPane) {
                    conversations.filterIsInstance<UmshKey.Thread>().lastOrNull()?.address
                } else {
                    null
                },
                onOpen = { address -> shell.openDetail(Destination.Conversations, UmshKey.Thread(address)) },
                onNewMessage = { shell.openAddPeer(Destination.Conversations) },
                reselects = shell.reselectCount(Destination.Conversations),
                onJoinChannel = { shell.openChannelJoin(forChat = true) },
                onScan = { shell.openScanner(ScanTarget.Root, Destination.Conversations) },
                scanned = shell.scanned(ScanTarget.Root, Destination.Conversations),
                onScannedExit = { exit ->
                    when (exit) {
                        // On this stack, as Add peer opened from New message leaves for a page (D11).
                        is AddPeerExit.Page -> shell.openDetail(Destination.Conversations, UmshKey.PeerPage(exit.address, Destination.Conversations))
                        is AddPeerExit.Conversation -> shell.openConversation(exit.address)
                        AddPeerExit.OwnIdentity -> shell.openOwnIdentity(twoPane)
                    }
                },
            )
        }
        entry<UmshKey.Thread>(metadata = ListDetailSceneStrategy.detailPane(Destination.Conversations)) { key ->
            val requests = LocalOpenRequests.current
            ThreadScreen(
                key,
                current = shell.isShown(Destination.Conversations, key, twoPane),
                onBack = if (twoPane) null else ({ shell.pop() }),
                onLeave = { shell.closeThread(key) },
                onOpenDetails = { ref -> shell.push(Destination.Conversations, UmshKey.MessageDetails(key.address, ref.sessionId, ref.handle)) },
                onOpenPeer = { shell.openPeer(it, Destination.Conversations) },
                onOpenInfo = { shell.openConversationInfo(key.address) },
                onOpenRadio = shell::openRadioDetail,
                onChooseRadio = shell::openRadioPicker,
                // A link in a message: by the same route as another app's.
                onOpenLink = { requests.offer(OpenRequest.Link(it, LinkOrigin.InApp)) },
            )
        }
        // Above its thread, in the same pane.
        entry<UmshKey.ConversationInfo>(metadata = ListDetailSceneStrategy.detailPane(Destination.Conversations)) { key ->
            ConversationInfoScreen(key.address, onBack = { shell.pop() }, onOpenChannel = shell::openChannelPageFromInfo)
        }
        entry<UmshKey.MessageDetails>(metadata = ListDetailSceneStrategy.detailPane(Destination.Conversations)) { key ->
            MessageDetailsScreen(key, onBack = { shell.pop() }, onOpenPeer = { shell.openPeer(it, Destination.Conversations) })
        }
        entry<UmshKey.PeersRoot>(
            metadata = ListDetailSceneStrategy.listPane(Destination.Peers) { NoPeerSelected() },
        ) {
            PeersScreen(
                reselects = shell.reselectCount(Destination.Peers),
                // Beside the list, the open peer's row is highlighted.
                // The list's detail page is the one above its root, whatever was opened from it.
                selected = if (twoPane) (shell.stacks.getValue(Destination.Peers).getOrNull(1) as? UmshKey.PeerPage)?.address else null,
                onOpen = shell::openPeerFromList,
                onDiscover = shell::openDiscoverFromList,
                onAddPeer = { shell.openAddPeer(Destination.Peers) },
                onScan = { shell.openScanner(ScanTarget.Root, Destination.Peers) },
                scanned = shell.scanned(ScanTarget.Root, Destination.Peers),
                onScannedExit = { exit ->
                    when (exit) {
                        is AddPeerExit.Page -> shell.openPeerFromList(exit.address)
                        is AddPeerExit.Conversation -> shell.openConversation(exit.address)
                        AddPeerExit.OwnIdentity -> shell.openOwnIdentity(twoPane)
                    }
                },
            )
        }
        // From the Peers list, the list's detail page; from New message, above the conversation list (D11).
        entry<UmshKey.AddPeer>(
            metadata = { key: UmshKey.AddPeer -> ListDetailSceneStrategy.detailPane(key.destination) },
        ) { key ->
            val overDetail = shell.stacks.getValue(key.destination).indexOf(key) > 1
            AddPeerScreen(
                onBack = if (twoPane && !overDetail) null else ({ shell.pop() }),
                onExit = { exit ->
                    when (exit) {
                        is AddPeerExit.Page -> shell.leaveAddPeerForPage(key, exit.address)
                        is AddPeerExit.Conversation -> shell.leaveAddPeerForConversation(key, exit.address)
                        AddPeerExit.OwnIdentity -> shell.leaveAddPeerForIdentity(key, twoPane)
                    }
                },
                onScan = { shell.openScanner(ScanTarget.AddPeerField, key.destination) },
                scanned = shell.scanned(ScanTarget.AddPeerField, key.destination),
            )
        }
        // Over the Add peer it came from, in the same pane; Back leaves the attempt for both.
        entry<UmshKey.Exchange>(
            metadata = { key: UmshKey.Exchange -> ListDetailSceneStrategy.detailPane(key.destination) },
        ) {
            ExchangeScreen(onBack = { shell.pop() })
        }
        // In the detail pane of the destination whose stack it is on.
        entry<UmshKey.PeerPage>(
            metadata = { key: UmshKey.PeerPage -> ListDetailSceneStrategy.detailPane(key.destination ?: Destination.Peers) },
        ) { key ->
            val destination = key.destination ?: Destination.Peers
            // Beside a list there is no Back, unless the page is pushed over another detail page.
            val stack = shell.stacks.getValue(destination)
            val overDetail = stack.indexOf(key) > 1
            PeerPageScreen(
                key.address,
                onBack = if (twoPane && !overDetail) null else ({ shell.pop() }),
                onConversation = { shell.openConversationFrom(key, it) },
                onOpenRoute = { shell.openRoute(key) },
                onOpenNeighbors = { shell.openNeighbors(key) },
                onOpenPeer = { shell.openPeer(it, destination) },
            )
        }
        // Above the page that opened it, in the same pane (D12).
        entry<UmshKey.Route>(
            metadata = { key: UmshKey.Route -> ListDetailSceneStrategy.detailPane(key.destination ?: Destination.Peers) },
        ) { key ->
            val destination = key.destination ?: Destination.Peers
            RouteScreen(
                key.address,
                onBack = { shell.pop() },
                onOpenPeer = { shell.openPeer(it.address, destination) },
                onAskNear = { shell.openDiscover(key) },
                onEdit = { shell.openManualPath(key.address) },
            )
        }
        entry<UmshKey.Neighbors>(
            metadata = { key: UmshKey.Neighbors -> ListDetailSceneStrategy.detailPane(key.destination ?: Destination.Peers) },
        ) { key ->
            val destination = key.destination ?: Destination.Peers
            NeighborsScreen(key.address, onBack = { shell.pop() }, onOpenPeer = { shell.openPeer(it, destination) })
        }
        // From the Peers list, the list's detail page; from Ask near this node, above the Route page that asked.
        entry<UmshKey.Discover>(
            metadata = { key: UmshKey.Discover -> ListDetailSceneStrategy.detailPane(key.destination ?: Destination.Peers) },
        ) { key ->
            val destination = key.destination ?: Destination.Peers
            val overDetail = shell.stacks.getValue(destination).indexOf(key) > 1
            DiscoverScreen(
                key.vantagePeer,
                onBack = if (twoPane && !overDetail) null else ({ shell.pop() }),
                onOpenPeer = { shell.openPeer(it, destination) },
            )
        }
        entry<UmshKey.MapRoot> { MapScreen() }
        entry<UmshKey.SettingsRoot>(
            // Settings opens Your identity beside the list rather than an empty pane.
            metadata = ListDetailSceneStrategy.listPane(Destination.Settings) { YourIdentityScreen(onBack = null) },
        ) {
            val open = shell.stacks.getValue(Destination.Settings).lastOrNull()
            SettingsScreen(
                selected = when {
                    !twoPane -> null
                    open == UmshKey.RadioDetail -> SettingsRow.CompanionRadio
                    open == UmshKey.Notifications -> SettingsRow.Notifications
                    open == UmshKey.Channels || open is UmshKey.ChannelPage -> SettingsRow.Channels
                    // Reached from Companion radio's Radio identity row.
                    open is PeerPageKey -> SettingsRow.CompanionRadio
                    else -> SettingsRow.YourIdentity
                },
                onOpenIdentity = {
                    // Beside the list Your identity is the placeholder: the
                    // root shows it, and pushing it would only give Back a
                    // step that changes nothing.
                    if (twoPane) shell.showRoot(Destination.Settings) else shell.openDetail(UmshKey.YourIdentity)
                },
                onOpenRadio = { shell.openDetail(Destination.Settings, UmshKey.RadioDetail) },
                onChooseRadio = shell::openRadioPicker,
                onOpenNotifications = { shell.openDetail(Destination.Settings, UmshKey.Notifications) },
                onOpenChannels = shell::openChannels,
                reselects = shell.reselectCount(Destination.Settings),
            )
        }
        entry<UmshKey.YourIdentity>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            YourIdentityScreen(onBack = if (twoPane) null else ({ shell.pop() }))
        }
        entry<UmshKey.Notifications>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            NotificationsSettingsScreen(onBack = if (twoPane) null else ({ shell.pop() }))
        }
        entry<UmshKey.Channels>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            ChannelsScreen(
                onBack = if (twoPane) null else ({ shell.pop() }),
                onOpen = shell::openChannelPage,
                onJoin = { shell.openChannelJoin() },
                onCreate = shell::openChannelCreate,
            )
        }
        // Above Channels, or above Conversation info, in the same pane, with Back to it.
        entry<UmshKey.ChannelPage>(
            metadata = { key: UmshKey.ChannelPage -> ListDetailSceneStrategy.detailPane(key.destination) },
        ) { key ->
            ChannelPageScreen(key.id, onBack = { shell.pop() }, onConversation = { shell.openConversationFrom(key, it) })
        }
        entry<UmshKey.RadioDetail>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            // As above the shell: the radio control and the banner would only
            // open this page again, over itself.
            CompositionLocalProvider(LocalTopBarRadioControl provides null, LocalScreenBanner provides null) {
                RadioDetailScreen(
                    onBack = if (twoPane) null else ({ shell.pop() }),
                    onGone = shell::closeRadioDetail,
                    inPane = true,
                    onChooseRadio = shell::openRadioPicker,
                    onOpenPeer = { shell.openPeer(it, Destination.Settings) },
                )
            }
        }
    }
    val paneFocusDecorator = remember { paneFocusDecorator<NavKey>() }
    val decorated = Destination.entries.associateWith { destination ->
        key(destination) {
            rememberDecoratedNavEntries(
                shell.stacks.getValue(destination),
                listOf(
                    rememberSaveableStateHolderNavEntryDecorator<NavKey>(),
                    rememberViewModelStoreNavEntryDecorator<NavKey>(owner),
                    paneFocusDecorator,
                ),
                provider,
            )
        }
    }
    val conversations = decorated.getValue(Destination.Conversations)
    val shown = when (val selected = shell.selected) {
        Destination.Conversations -> conversations
        else -> conversations + decorated.getValue(selected)
    }
    NavDisplay(
        entries = shown,
        sceneStrategies = listOf(strategy),
        modifier = Modifier.testTag(Tags.NAV_DISPLAY),
        onBack = { shell.back() },
    )
}

/** The code waiting for a scan begun at [target] on [destination]'s stack, for its page to take. */
private fun ShellState.scanned(target: ScanTarget, destination: Destination): ScannedCode? =
    pendingScan?.takeIf { it.target == target && it.destination == destination }?.let { waiting ->
        ScannedCode(waiting.text) { takeScan(target, destination) }
    }

/**
 * Makes each page a focus target of its own. The list-detail scaffold moves
 * focus into its current pane whenever the panes change; without a target at
 * the page's root, that focus goes on to the page's first focusable child,
 * which in touch mode is its first text field. In two-pane Settings that was
 * Developer › Bridged radio: the list scrolled to it and the keyboard came up.
 * With this, the pane itself takes the focus and keyboard navigation starts
 * there.
 */
private fun <T : Any> paneFocusDecorator(): NavEntryDecorator<T> =
    NavEntryDecorator { entry ->
        Box(Modifier.focusTarget(), propagateMinConstraints = true) { entry.Content() }
    }
