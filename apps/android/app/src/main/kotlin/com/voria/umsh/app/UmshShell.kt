package com.voria.umsh.app

import android.icu.text.NumberFormat
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
import com.voria.umsh.designsystem.LocalCopyNotice
import com.voria.umsh.designsystem.LocalScreenBanner
import com.voria.umsh.designsystem.LocalTopBarRadioControl
import com.voria.umsh.designsystem.RadioBannerAction
import com.voria.umsh.designsystem.RadioControl
import com.voria.umsh.designsystem.RadioProblemBanner
import com.voria.umsh.designsystem.isRailLayout
import com.voria.umsh.designsystem.isTwoPaneLayout
import com.voria.umsh.designsystem.windowAdaptiveInfo
import com.voria.umsh.features.conversations.ConversationsScreen
import com.voria.umsh.features.conversations.MessageDetailsScreen
import com.voria.umsh.features.conversations.NoConversationSelected
import com.voria.umsh.features.conversations.ThreadScreen
import com.voria.umsh.features.map.MapScreen
import com.voria.umsh.features.peers.NoPeerSelected
import com.voria.umsh.features.peers.PeersScreen
import com.voria.umsh.features.radio.RadioDetailScreen
import com.voria.umsh.features.radio.RadioPickerScreen
import com.voria.umsh.features.settings.NotificationsSettingsScreen
import com.voria.umsh.features.settings.SettingsRow
import com.voria.umsh.features.settings.SettingsScreen
import com.voria.umsh.features.settings.YourIdentityScreen
import com.voria.umsh.services.permissions.rememberBluetoothEnabler
import com.voria.umsh.services.permissions.rememberNearbyDevicesAsker
import com.voria.umsh.services.radio.RadioBanner
import java.time.Instant
import kotlinx.coroutines.flow.filterNotNull
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
    val viewModel = runtimeViewModel { ShellViewModel(it, host.bluetooth, host.preferences.radioRegistry.bound) }
    val conversations by viewModel.conversations.collectAsStateWithLifecycle()
    // A conversation removed, from its row or anywhere else: its thread closes.
    LaunchedEffect(conversations) { conversations?.let(shell::closeThreadsNotIn) }
    // A notification's or shortcut's tap: that conversation, above its
    // list, or the radio notification's Radio Detail.
    val requests = LocalOpenRequests.current
    LaunchedEffect(requests) {
        requests.filterNotNull().collect { request ->
            when (request) {
                is OpenRequest.Conversation -> shell.openConversation(request.address)
                OpenRequest.RadioDetail -> shell.openRadioDetail()
            }
            requests.compareAndSet(request, null)
        }
    }

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
    ) {
        NavDisplay(
            backStack = shell.appStack,
            onBack = { shell.popAppPage() },
            entryDecorators = listOf(rememberSaveableStateHolderNavEntryDecorator()),
            modifier = Modifier.testTag(Tags.APP_NAV_DISPLAY),
            entryProvider = entryProvider {
                entry<UmshKey.Shell> { ShellScaffold(shell, viewModel, snackbars) }
                entry<UmshKey.RadioDetail> {
                    // Full width above the shell: no radio control in its bar
                    // (it is what opened the page), and no banner (the page
                    // states the radio's problem itself).
                    CompositionLocalProvider(LocalTopBarRadioControl provides null, LocalScreenBanner provides null) {
                        RadioDetailScreen(
                            onBack = { shell.popAppPage() },
                            onGone = shell::closeRadioDetail,
                            inPane = false,
                            onChooseRadio = shell::openRadioPicker,
                        )
                    }
                }
                entry<UmshKey.RadioPicker> {
                    // Full width above the shell and whatever opened it, as Radio Detail.
                    CompositionLocalProvider(LocalTopBarRadioControl provides null, LocalScreenBanner provides null) {
                        RadioPickerScreen(onBack = { shell.popAppPage() }, onChosen = shell::closeRadioPicker)
                    }
                }
            },
        )
    }
}

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
    val barHidden = !rail && (shell.top is UmshKey.Thread || shell.top is UmshKey.MessageDetails)
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
    val strategy = rememberListDetailSceneStrategy<NavKey>(directive = calculatePaneScaffoldDirective(windowAdaptiveInfo()))
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
                // Beside the list, the open conversation's row is highlighted, under a message's details too.
                selected = if (twoPane) {
                    when (val shown = conversations.lastOrNull()) {
                        is UmshKey.Thread -> shown.address
                        is UmshKey.MessageDetails -> shown.address
                        else -> null
                    }
                } else {
                    null
                },
                onOpen = { address -> shell.openDetail(Destination.Conversations, UmshKey.Thread(address)) },
                reselects = shell.reselectCount(Destination.Conversations),
            )
        }
        entry<UmshKey.Thread>(metadata = ListDetailSceneStrategy.detailPane(Destination.Conversations)) { key ->
            ThreadScreen(
                key,
                current = shell.isShown(Destination.Conversations, key, twoPane),
                onBack = if (twoPane) null else ({ shell.pop() }),
                onLeave = { shell.closeThread(key) },
                onOpenDetails = { ref -> shell.push(Destination.Conversations, UmshKey.MessageDetails(key.address, ref.sessionId, ref.handle)) },
                onOpenRadio = shell::openRadioDetail,
                onChooseRadio = shell::openRadioPicker,
            )
        }
        entry<UmshKey.MessageDetails>(metadata = ListDetailSceneStrategy.detailPane(Destination.Conversations)) { key ->
            MessageDetailsScreen(key, onBack = { shell.pop() })
        }
        entry<UmshKey.PeersRoot>(
            metadata = ListDetailSceneStrategy.listPane(Destination.Peers) { NoPeerSelected() },
        ) { PeersScreen(reselects = shell.reselectCount(Destination.Peers)) }
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
                reselects = shell.reselectCount(Destination.Settings),
            )
        }
        entry<UmshKey.YourIdentity>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            YourIdentityScreen(onBack = if (twoPane) null else ({ shell.pop() }))
        }
        entry<UmshKey.Notifications>(metadata = ListDetailSceneStrategy.detailPane(Destination.Settings)) {
            NotificationsSettingsScreen(onBack = if (twoPane) null else ({ shell.pop() }))
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
